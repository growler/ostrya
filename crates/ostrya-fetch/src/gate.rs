//! A priority admission gate that bounds concurrent work.
//!
//! A [`Gate`] holds a fixed number of permits. [`Gate::acquire`] returns an
//! [`Acquire`] future, which resolves to a [`Permit`].
//! [`Fetcher`](crate::Fetcher) uses a gate to bound the requests in flight.
//! Other code can use a gate to bound other work, for example the content
//! writes that run at once.
//!
//! If no permit is free, the waiter joins a queue. The queue serves the highest
//! [`Priority`] first, and the waiters of one priority in arrival order. A
//! released permit goes directly to the first waiter and does not raise the
//! free count, so a new waiter cannot take it.
//!
//! The order across priorities is strict. If higher-priority waiters arrive
//! without a pause, a lower-priority waiter stays in the queue. The mix of
//! priorities that the callers use sets the limit of that wait.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use super::Priority;

/// The place of a waiter in the queue: highest priority first, then arrival.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct WaitKey {
    rank: Reverse<Priority>,
    seq: u64,
}

/// The queue and the count of free permits.
struct State {
    free: usize,
    next_seq: u64,
    /// The waiters that have no permit, each with the waker to wake.
    waiting: BTreeMap<WaitKey, Option<Waker>>,
    /// The waiters that got a permit, which the next poll of each takes.
    granted: BTreeSet<WaitKey>,
}

impl State {
    /// Releases one permit. If a waiter is in the queue, the first waiter gets
    /// the permit. If not, the free count increases. Returns the waker that the
    /// caller must wake after it releases the lock.
    fn hand_off(&mut self) -> Option<Waker> {
        match self.waiting.keys().next().copied() {
            Some(key) => {
                let waker = self.waiting.remove(&key).flatten();
                self.granted.insert(key);
                waker
            }
            None => {
                self.free += 1;
                None
            }
        }
    }
}

/// A priority admission gate with a fixed number of permits.
pub struct Gate {
    state: Mutex<State>,
}

impl Gate {
    /// Creates a gate with `limit` permits.
    ///
    /// If `limit` is 0, no [`Acquire`] future resolves.
    pub fn new(limit: usize) -> Gate {
        Gate {
            state: Mutex::new(State {
                free: limit,
                next_seq: 0,
                waiting: BTreeMap::new(),
                granted: BTreeSet::new(),
            }),
        }
    }

    /// Returns a future that waits for a permit at `priority`.
    ///
    /// The future resolves to a [`Permit`]. The [`gate`](crate::gate) module
    /// states the queue order.
    pub fn acquire(self: &Arc<Gate>, priority: Priority) -> Acquire {
        Acquire {
            gate: self.clone(),
            priority,
            key: None,
        }
    }

    /// Releases one permit and wakes the waiter that gets it.
    fn release(&self) {
        let waker = self.state.lock().expect("fetch gate mutex").hand_off();
        // The wake runs outside the lock, so an executor that polls the woken
        // future inline does not lock the mutex a second time.
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// The future that [`Gate::acquire`] returns.
///
/// If a caller drops the future before it resolves, the future leaves the
/// queue. If the gate gave it a permit already, the permit goes to the next
/// waiter.
pub struct Acquire {
    gate: Arc<Gate>,
    priority: Priority,
    /// The place of this waiter in the queue, after it joins the queue.
    key: Option<WaitKey>,
}

impl Future for Acquire {
    type Output = Permit;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Permit> {
        let me = self.get_mut();
        // The mutex is poisoned only if a holder panics under the lock. No
        // caller input can cause that.
        let mut state = me.gate.state.lock().expect("fetch gate mutex");
        match me.key {
            None => {
                if state.free > 0 {
                    state.free -= 1;
                    drop(state);
                    return Poll::Ready(Permit {
                        gate: me.gate.clone(),
                    });
                }
                let seq = state.next_seq;
                state.next_seq += 1;
                let key = WaitKey {
                    rank: Reverse(me.priority),
                    seq,
                };
                state.waiting.insert(key, Some(cx.waker().clone()));
                me.key = Some(key);
                Poll::Pending
            }
            Some(key) => {
                if state.granted.remove(&key) {
                    me.key = None;
                    drop(state);
                    return Poll::Ready(Permit {
                        gate: me.gate.clone(),
                    });
                }
                if let Some(slot) = state.waiting.get_mut(&key) {
                    *slot = Some(cx.waker().clone());
                }
                Poll::Pending
            }
        }
    }
}

impl Drop for Acquire {
    fn drop(&mut self) {
        let Some(key) = self.key else { return };
        let waker = {
            let mut state = self.gate.state.lock().expect("fetch gate mutex");
            state.waiting.remove(&key);
            // If the gate gave this waiter a permit, the permit goes to
            // the next waiter.
            if state.granted.remove(&key) {
                state.hand_off()
            } else {
                None
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// A permit of a [`Gate`], which returns to the gate on drop.
pub struct Permit {
    gate: Arc<Gate>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.gate.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::poll_once;
    use ostrya_rt::block_on;

    #[test]
    fn permits_up_to_the_limit_are_granted_at_once() {
        block_on(async {
            let gate = Arc::new(Gate::new(2));
            let first = gate.acquire(Priority::Normal).await;
            let second = gate.acquire(Priority::Normal).await;
            // The third waits until one is released.
            let mut third = Box::pin(gate.acquire(Priority::Normal));
            assert!(poll_once(&mut third).await.is_none());
            drop(first);
            assert!(poll_once(&mut third).await.is_some());
            drop(second);
        });
    }

    #[test]
    fn a_released_permit_goes_to_the_highest_priority_waiter() {
        block_on(async {
            let gate = Arc::new(Gate::new(1));
            let held = gate.acquire(Priority::Normal).await;
            let mut low = Box::pin(gate.acquire(Priority::Low));
            let mut high = Box::pin(gate.acquire(Priority::High));
            // Queue low first, then high. The later arrival gets the permit,
            // because priority comes first.
            assert!(poll_once(&mut low).await.is_none());
            assert!(poll_once(&mut high).await.is_none());
            drop(held);
            assert!(poll_once(&mut low).await.is_none());
            let permit = poll_once(&mut high).await;
            assert!(permit.is_some());
            // After the high-priority holder releases its permit, the low
            // waiter gets it.
            drop(permit);
            assert!(poll_once(&mut low).await.is_some());
        });
    }

    #[test]
    fn equal_priority_waiters_are_served_in_arrival_order() {
        block_on(async {
            let gate = Arc::new(Gate::new(1));
            let held = gate.acquire(Priority::Normal).await;
            let mut first = Box::pin(gate.acquire(Priority::Normal));
            let mut second = Box::pin(gate.acquire(Priority::Normal));
            assert!(poll_once(&mut first).await.is_none());
            assert!(poll_once(&mut second).await.is_none());
            drop(held);
            assert!(poll_once(&mut second).await.is_none());
            assert!(poll_once(&mut first).await.is_some());
        });
    }

    #[test]
    fn abandoning_a_granted_waiter_passes_the_permit_on() {
        block_on(async {
            let gate = Arc::new(Gate::new(1));
            let held = gate.acquire(Priority::Normal).await;
            let mut leaving = Box::pin(gate.acquire(Priority::High));
            let mut staying = Box::pin(gate.acquire(Priority::Normal));
            assert!(poll_once(&mut leaving).await.is_none());
            assert!(poll_once(&mut staying).await.is_none());
            // The gate gives the permit to the high-priority waiter. The test
            // then drops that waiter before it polls again.
            drop(held);
            drop(leaving);
            assert!(poll_once(&mut staying).await.is_some());
        });
    }

    #[test]
    fn a_dropped_queued_waiter_leaves_no_trace() {
        block_on(async {
            let gate = Arc::new(Gate::new(1));
            let held = gate.acquire(Priority::Normal).await;
            {
                let mut abandoned = Box::pin(gate.acquire(Priority::High));
                assert!(poll_once(&mut abandoned).await.is_none());
            }
            drop(held);
            let state = gate.state.lock().unwrap();
            assert!(state.waiting.is_empty());
            assert!(state.granted.is_empty());
            assert_eq!(state.free, 1);
        });
    }
}
