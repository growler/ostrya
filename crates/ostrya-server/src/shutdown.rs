//! The signal that stops the connections of a server.
//!
//! The connections run as tasks of their own, so dropping the future of
//! [`Server::run`](crate::Server::run) does not reach them. Each connection
//! races a [`Wait`] of the server's [`Shutdown`], and the [`Trigger`] that
//! `run` holds fires the signal when the future drops.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// A signal that fires once and wakes each waiter.
#[derive(Default)]
pub(crate) struct Shutdown {
    /// Set under the lock of `state` when the signal fires, and read with no
    /// lock by a waiter that already holds a waker slot.
    fired: AtomicBool,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    fired: bool,
    next_id: u64,
    /// The waker of each waiter that is pending, by its id.
    waiters: HashMap<u64, Waker>,
    /// How many times a waiter stored a waker, for the test of the reuse.
    #[cfg(test)]
    stores: usize,
}

impl Shutdown {
    /// Fire the signal and wake each waiter.
    pub(crate) fn fire(&self) {
        let waiters = {
            let mut state = self.state.lock().expect("shutdown mutex");
            state.fired = true;
            self.fired.store(true, Ordering::Release);
            std::mem::take(&mut state.waiters)
        };
        for waker in waiters.into_values() {
            waker.wake();
        }
    }

    /// A future that completes when the signal fires.
    pub(crate) fn wait(self: &Arc<Shutdown>) -> Wait {
        Wait {
            shutdown: self.clone(),
            id: None,
            waker: None,
        }
    }
}

/// Fires the signal when it drops.
pub(crate) struct Trigger(pub(crate) Arc<Shutdown>);

impl Drop for Trigger {
    fn drop(&mut self) {
        self.0.fire();
    }
}

/// The future of [`Shutdown::wait`]. It holds one waker slot, so polling it
/// with another waker replaces its waker. A poll with the waker it stored
/// takes no lock.
pub(crate) struct Wait {
    shutdown: Arc<Shutdown>,
    id: Option<u64>,
    /// The waker stored in the slot.
    waker: Option<Waker>,
}

impl Future for Wait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let me = self.get_mut();
        if me.shutdown.fired.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        // The stored waker is woken when the signal fires, and the flag is
        // set before that wake, so the flag read above sees the signal.
        if me.waker.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
            return Poll::Pending;
        }
        let mut state = me.shutdown.state.lock().expect("shutdown mutex");
        if state.fired {
            return Poll::Ready(());
        }
        let id = *me.id.get_or_insert_with(|| {
            let id = state.next_id;
            state.next_id += 1;
            id
        });
        state.waiters.insert(id, cx.waker().clone());
        #[cfg(test)]
        {
            state.stores += 1;
        }
        me.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for Wait {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.shutdown
                .state
                .lock()
                .expect("shutdown mutex")
                .waiters
                .remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::poll_once;
    use ostrya_rt::block_on;

    /// A waiter completes when the trigger drops, and a waiter that drops
    /// leaves no waker behind.
    #[test]
    fn a_dropped_trigger_completes_every_waiter() {
        block_on(async {
            let shutdown = Arc::new(Shutdown::default());
            let trigger = Trigger(shutdown.clone());
            let mut first = shutdown.wait();
            let mut second = shutdown.wait();
            assert!(poll_once(&mut first).await.is_none());
            assert!(poll_once(&mut first).await.is_none());
            assert!(poll_once(&mut second).await.is_none());
            assert_eq!(shutdown.state.lock().unwrap().waiters.len(), 2);
            // A poll with the waker the slot holds stores nothing.
            assert_eq!(shutdown.state.lock().unwrap().stores, 2);
            drop(second);
            assert_eq!(shutdown.state.lock().unwrap().waiters.len(), 1);
            drop(trigger);
            assert!(poll_once(&mut first).await.is_some());
            assert!(poll_once(&mut shutdown.wait()).await.is_some());
        });
    }
}
