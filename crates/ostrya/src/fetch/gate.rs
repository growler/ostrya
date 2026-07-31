//! Priority admission control for in-flight fetches.
//!
//! A [`Gate`] holds a fixed number of permits. A waiter that finds none free
//! joins a queue ordered by priority first and arrival second, so a metadata
//! fetch a scan is blocked on overtakes queued bulk content. The guarantee a
//! waiter has is within its own priority: no later arrival of the same priority
//! is served before it. Across priorities the order is strict, so a steady
//! arrival of higher-priority waiters keeps a lower-priority one queued; what
//! bounds that is the caller's mix of priorities, not the gate.
//!
//! A released permit is handed to the best waiter directly rather than returned
//! to a counter, so the woken waiter cannot lose it to a newcomer.
//!
//! Two callers hold one: the fetcher, whose gate bounds requests in flight, and
//! the HTTP pull, whose gate bounds the fetched content objects being written at
//! once.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use super::Priority;

/// A waiter's place in the queue: highest priority first, then arrival order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct WaitKey {
    rank: Reverse<Priority>,
    seq: u64,
}

/// The queue and the free-permit count.
struct State {
    free: usize,
    next_seq: u64,
    /// Waiters that have not been handed a permit, with the waker to notify.
    waiting: BTreeMap<WaitKey, Option<Waker>>,
    /// Waiters a permit has been handed to, which have yet to observe it.
    granted: BTreeSet<WaitKey>,
}

impl State {
    /// Give up a permit: to the best waiter if there is one, otherwise back to
    /// the count. Returns the waker to notify once the lock is released.
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

/// A bounded, priority-ordered admission gate.
pub(crate) struct Gate {
    state: Mutex<State>,
}

impl Gate {
    /// A gate admitting `limit` holders at a time.
    pub(crate) fn new(limit: usize) -> Gate {
        Gate {
            state: Mutex::new(State {
                free: limit,
                next_seq: 0,
                waiting: BTreeMap::new(),
                granted: BTreeSet::new(),
            }),
        }
    }

    /// Wait for a permit at `priority`.
    pub(crate) fn acquire(self: &Arc<Gate>, priority: Priority) -> Acquire {
        Acquire {
            gate: self.clone(),
            priority,
            key: None,
        }
    }

    /// Hand a permit on and notify whoever receives it.
    fn release(&self) {
        let waker = self.state.lock().expect("fetch gate mutex").hand_off();
        // Waking outside the lock keeps an executor that polls inline from
        // re-entering it.
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// The future returned by [`Gate::acquire`].
pub(crate) struct Acquire {
    gate: Arc<Gate>,
    priority: Priority,
    /// This waiter's queue position, once it has queued.
    key: Option<WaitKey>,
}

impl Future for Acquire {
    type Output = Permit;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Permit> {
        let me = self.get_mut();
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
            // A permit handed to a waiter that goes away has to move on.
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

/// Admission to run one fetch, released on drop.
pub(crate) struct Permit {
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
            // Queue low first, then high, so priority and not arrival decides.
            assert!(poll_once(&mut low).await.is_none());
            assert!(poll_once(&mut high).await.is_none());
            drop(held);
            assert!(poll_once(&mut low).await.is_none());
            let permit = poll_once(&mut high).await;
            assert!(permit.is_some());
            // With the high-priority holder done, the low waiter proceeds.
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
            // The permit is handed to the high-priority waiter, which is then
            // dropped without ever observing it.
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
