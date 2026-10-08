//! The concurrency driver of a pull from a remote.
//!
//! A pull holds a fixed number of slots. Each slot is a future that fetches one
//! object and stores it. The loop that owns the slots fills each free slot from
//! the plan. Then it waits for the first slot that finishes.
//!
//! One task reads and writes the plan and the seen-sets, so they need no lock.
//!
//! [`Slots`] is that set of slots. It spawns no task. Its futures borrow the
//! repository, the transaction, and the fetcher, so they need no `'static`
//! bound and no `Arc`. Each pending slot registers the waker of the caller, so
//! a wakeup from a socket or from the blocking pool polls the loop again.
//!
//! Cancellation comes from this ownership. If the loop returns an error, it
//! drops `Slots` and each future that is still in flight. A dropped future
//! closes its connections and releases its permits. No future lives after the
//! call.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// One slot: a boxed future that produces the outcome of one step.
type Slot<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A bounded set of futures in flight that one call polls together.
pub(crate) struct Slots<'a, T> {
    slots: Vec<Slot<'a, T>>,
    limit: usize,
}

impl<'a, T> Slots<'a, T> {
    /// Creates a set that holds at most `limit` futures at a time.
    ///
    /// A limit of zero becomes one, because a set that admits no future never
    /// makes progress.
    pub(crate) fn new(limit: usize) -> Slots<'a, T> {
        let limit = limit.max(1);
        Slots {
            slots: Vec::with_capacity(limit),
            limit,
        }
    }

    /// Returns `true` if one more future fits in the set.
    pub(crate) fn has_room(&self) -> bool {
        self.slots.len() < self.limit
    }

    /// Puts a future into a free slot.
    ///
    /// The caller checks [`has_room`](Slots::has_room) first. If the set is
    /// full, `push` adds the future and the set grows past the limit.
    pub(crate) fn push(&mut self, future: impl Future<Output = T> + Send + 'a) {
        self.slots.push(Box::pin(future));
    }

    /// Returns the number of futures in flight.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.slots.len()
    }

    /// Waits for the first slot to finish, removes it, and returns its output.
    ///
    /// If the set is empty, it returns `None` at once.
    ///
    /// The order is the poll order. If more than one slot is ready, the call
    /// takes the first ready slot in the set. The other ready slots stay ready
    /// for the next call.
    pub(crate) async fn next_ready(&mut self) -> Option<T> {
        if self.slots.is_empty() {
            return None;
        }
        let (index, output) = PollAll(&mut self.slots).await;
        // The last slot moves into the empty position, so the order of the set
        // changes. No code reads a slot by its position between calls, so any
        // order is correct.
        drop(self.slots.swap_remove(index));
        Some(output)
    }
}

/// A future that resolves to the output of the first ready slot and its
/// position in the set.
///
/// It polls each slot in turn, in the order of the set.
struct PollAll<'s, 'a, T>(&'s mut Vec<Slot<'a, T>>);

impl<T> Future for PollAll<'_, '_, T> {
    type Output = (usize, T);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<(usize, T)> {
        for (index, slot) in self.get_mut().0.iter_mut().enumerate() {
            if let Poll::Ready(output) = slot.as_mut().poll(cx) {
                return Poll::Ready((index, output));
            }
        }
        // Each slot that returned `Pending` registered this waker, so progress
        // in any one slot polls the whole set again.
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::poll_once;
    use ostrya_rt::block_on;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A future that resolves when the shared gate reaches its release value.
    /// A test uses it to set the order in which the slots finish.
    struct Gated {
        gate: Arc<AtomicUsize>,
        release: usize,
        value: usize,
    }

    impl Future for Gated {
        type Output = usize;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
            if self.gate.load(Ordering::SeqCst) >= self.release {
                return Poll::Ready(self.value);
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    /// The loop of a pull fills each free slot from the work list. Then it takes
    /// the first slot that finishes. It stops when the list and the set are
    /// both empty.
    #[test]
    fn slots_refill_from_the_plan_up_to_the_limit() {
        block_on(async {
            let mut work: Vec<usize> = (0..7).collect();
            work.reverse();
            let mut slots = Slots::new(3);
            let mut done = Vec::new();
            let mut high_water = 0;
            loop {
                while slots.has_room()
                    && let Some(item) = work.pop()
                {
                    slots.push(async move { item });
                }
                high_water = high_water.max(slots.len());
                let Some(output) = slots.next_ready().await else {
                    break;
                };
                done.push(output);
            }
            // Each item ran, and the number of futures in flight never passed
            // the limit.
            done.sort_unstable();
            assert_eq!(done, (0..7).collect::<Vec<_>>());
            assert_eq!(high_water, 3);
        });
    }

    /// The set returns a ready slot while the other slots stay pending, so the
    /// completion order drives the loop. The push order has no effect on it.
    #[test]
    fn the_first_ready_slot_is_the_one_returned() {
        block_on(async {
            let gate = Arc::new(AtomicUsize::new(0));
            let mut slots = Slots::new(4);
            for (value, release) in [(10usize, 3usize), (11, 1), (12, 2)] {
                slots.push(Gated {
                    gate: gate.clone(),
                    release,
                    value,
                });
            }
            gate.store(1, Ordering::SeqCst);
            assert_eq!(slots.next_ready().await, Some(11));
            gate.store(2, Ordering::SeqCst);
            assert_eq!(slots.next_ready().await, Some(12));
            gate.store(3, Ordering::SeqCst);
            assert_eq!(slots.next_ready().await, Some(10));
            assert_eq!(slots.next_ready().await, None);
        });
    }

    /// If a pull fails, it returns from the loop and drops the set. This drops
    /// each future that is still in flight, with the connections and the
    /// permits that the future holds.
    #[test]
    fn an_error_drops_every_slot_still_in_flight() {
        block_on(async {
            // A future that records its drop. It takes the place of a future
            // that holds a response body and a fetcher permit.
            struct Tracked<'a> {
                dropped: &'a AtomicUsize,
            }

            impl Future for Tracked<'_> {
                type Output = Result<(), &'static str>;

                fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
                    Poll::Pending
                }
            }

            impl Drop for Tracked<'_> {
                fn drop(&mut self) {
                    self.dropped.fetch_add(1, Ordering::SeqCst);
                }
            }

            let dropped = AtomicUsize::new(0);
            let outcome = {
                let mut slots = Slots::new(4);
                for _ in 0..3 {
                    slots.push(Tracked { dropped: &dropped });
                }
                slots.push(async { Err("object not found") });
                let outcome = slots.next_ready().await;
                // The set still holds the three pending slots here.
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
                assert_eq!(slots.len(), 3);
                outcome
            };
            assert_eq!(outcome, Some(Err("object not found")));
            assert_eq!(dropped.load(Ordering::SeqCst), 3);
        });
    }

    /// An empty set resolves at once and gives no output. This result ends the
    /// loop of a pull.
    #[test]
    fn an_empty_set_is_ready_immediately() {
        block_on(async {
            let mut slots: Slots<'_, usize> = Slots::new(2);
            assert_eq!(poll_once(slots.next_ready()).await, Some(None));
            assert!(slots.has_room());
        });
    }
}
