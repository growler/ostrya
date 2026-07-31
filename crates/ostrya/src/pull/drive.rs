//! The concurrency driver an HTTP pull runs its work on.
//!
//! A pull holds a fixed number of slots, each a future that fetches one object
//! and stores it. The loop that owns them refills every free slot from the plan
//! and then waits for whichever slot finishes first, so the plan and the
//! seen-sets are touched by one task and need no lock.
//!
//! [`Slots`] is that set. It is not an executor: nothing is spawned, and the
//! futures it holds borrow the repository, the transaction, and the fetcher, so
//! they need no `'static` bound and no `Arc`. Every pending slot registers the
//! caller's waker, so any socket or blocking-pool wakeup re-polls the loop.
//!
//! Cancellation follows from that ownership: an error returned from the loop
//! drops `Slots`, which drops every future still in flight, which closes their
//! connections and releases their permits. Nothing outlives the call.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// One slot: a boxed future producing a step's outcome.
type Slot<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A bounded set of in-flight futures, polled together.
pub(crate) struct Slots<'a, T> {
    slots: Vec<Slot<'a, T>>,
    limit: usize,
}

impl<'a, T> Slots<'a, T> {
    /// A set holding at most `limit` futures at a time. A limit of zero is
    /// raised to one, since a set that admits nothing never makes progress.
    pub(crate) fn new(limit: usize) -> Slots<'a, T> {
        let limit = limit.max(1);
        Slots {
            slots: Vec::with_capacity(limit),
            limit,
        }
    }

    /// Whether another future fits.
    pub(crate) fn has_room(&self) -> bool {
        self.slots.len() < self.limit
    }

    /// Take a future into a free slot. The caller checks [`has_room`](Slots::has_room)
    /// first; pushing past the limit only grows the set.
    pub(crate) fn push(&mut self, future: impl Future<Output = T> + Send + 'a) {
        self.slots.push(Box::pin(future));
    }

    /// How many futures are in flight.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.slots.len()
    }

    /// Wait for the first slot to finish and remove it, or `None` when the set
    /// is empty.
    ///
    /// The order is the poll order, not the completion order: when several
    /// slots are ready at once the earliest in the set is taken and the rest
    /// stay ready for the next call.
    pub(crate) async fn next_ready(&mut self) -> Option<T> {
        if self.slots.is_empty() {
            return None;
        }
        let (index, output) = PollAll(&mut self.slots).await;
        // The last slot moves into the hole, which reorders the set. Nothing
        // reads a slot by position between calls, so the order is free.
        drop(self.slots.swap_remove(index));
        Some(output)
    }
}

/// Polls every slot in turn and resolves to the first that is ready, with its
/// position in the set.
struct PollAll<'s, 'a, T>(&'s mut Vec<Slot<'a, T>>);

impl<T> Future for PollAll<'_, '_, T> {
    type Output = (usize, T);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<(usize, T)> {
        for (index, slot) in self.get_mut().0.iter_mut().enumerate() {
            if let Poll::Ready(output) = slot.as_mut().poll(cx) {
                return Poll::Ready((index, output));
            }
        }
        // Every slot that answered `Pending` registered this waker, so any one
        // of them making progress re-polls the whole set.
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

    /// A future that resolves once the shared gate reaches its release value,
    /// which lets a test decide the order slots finish in.
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

    /// The loop shape a pull runs: refill every free slot from the work list,
    /// then take whichever finishes first, until both are empty.
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
            // Every item ran, and no more than the limit was ever in flight.
            done.sort_unstable();
            assert_eq!(done, (0..7).collect::<Vec<_>>());
            assert_eq!(high_water, 3);
        });
    }

    /// A slot that is ready is taken while the others stay pending, so the loop
    /// is driven by completion and not by the order work was pushed.
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

    /// A pull that fails returns from the loop, which drops the set and with it
    /// every future still in flight -- the connections they hold and the permits
    /// they took go with them.
    #[test]
    fn an_error_drops_every_slot_still_in_flight() {
        block_on(async {
            // A future that records its drop, standing in for one holding a
            // response body and a fetcher permit.
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
                // The three pending slots are still held here.
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
                assert_eq!(slots.len(), 3);
                outcome
            };
            assert_eq!(outcome, Some(Err("object not found")));
            assert_eq!(dropped.load(Ordering::SeqCst), 3);
        });
    }

    /// An empty set resolves at once rather than waiting for a slot that will
    /// never be pushed, which is what ends the loop.
    #[test]
    fn an_empty_set_is_ready_immediately() {
        block_on(async {
            let mut slots: Slots<'_, usize> = Slots::new(2);
            assert_eq!(poll_once(slots.next_ready()).await, Some(None));
            assert!(slots.has_room());
        });
    }
}
