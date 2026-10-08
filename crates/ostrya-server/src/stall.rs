//! The deadline on the response bodies of one connection.
//!
//! A response body that streams a file holds its descriptor. A `.filez`
//! built on request also holds a compressor of the view. If a client stops
//! reading, hyper takes no frame of the body, so the body keeps these
//! resources.
//!
//! Each stream body of a connection records the time when hyper last took a
//! frame from it. [`Stall::expired`] completes when one body waited for the
//! whole window. Then the connection ends, and its bodies drop.
//!
//! A body that waits for its own reader, for example for a compressor of the
//! view, does not wait for the client. Its time does not run until it gives
//! its next frame.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ostrya_rt as rt;

/// The stream bodies of one connection and the time each one last gave a
/// frame.
pub(crate) struct Stall {
    window: Duration,
    state: Mutex<State>,
}

struct State {
    next_id: u64,
    /// Each live body, by its id.
    bodies: HashMap<u64, Entry>,
}

/// One live body.
struct Entry {
    /// The time when the body was made, or when it last gave a frame.
    at: Instant,
    /// `true` if the body waits for its own reader.
    reading: bool,
}

impl Stall {
    /// Creates the record of the bodies of a new connection. Each body can
    /// wait for `window` until hyper takes a frame.
    pub(crate) fn new(window: Duration) -> Arc<Stall> {
        Arc::new(Stall {
            window,
            state: Mutex::new(State {
                next_id: 0,
                bodies: HashMap::new(),
            }),
        })
    }

    /// Records a new body, made now.
    pub(crate) fn track(self: &Arc<Stall>) -> Tracker {
        let mut state = self.state.lock().expect("stall mutex");
        let id = state.next_id;
        state.next_id += 1;
        state.bodies.insert(
            id,
            Entry {
                at: Instant::now(),
                reading: false,
            },
        );
        Tracker {
            stall: self.clone(),
            id,
        }
    }

    /// Completes when a live body that does not wait for its reader gives no
    /// frame for the window. The future sleeps until the oldest such body
    /// reaches the window, or for one window if there is no such body. Then
    /// it checks again.
    pub(crate) async fn expired(&self) {
        loop {
            let wait = {
                let state = self.state.lock().expect("stall mutex");
                let oldest = state
                    .bodies
                    .values()
                    .filter(|entry| !entry.reading)
                    .map(|entry| entry.at)
                    .min();
                match oldest {
                    Some(oldest) => match self.window.checked_sub(oldest.elapsed()) {
                        Some(left) if !left.is_zero() => left,
                        _ => return,
                    },
                    None => self.window,
                }
            };
            rt::Timer::after(wait).await;
        }
    }
}

/// The record of one live body. It drops with the body.
pub(crate) struct Tracker {
    stall: Arc<Stall>,
    id: u64,
}

impl Tracker {
    /// Records that hyper took a frame of the body now.
    pub(crate) fn progress(&self) {
        let mut state = self.stall.state.lock().expect("stall mutex");
        if let Some(entry) = state.bodies.get_mut(&self.id) {
            entry.at = Instant::now();
            entry.reading = false;
        }
    }

    /// Records that the body waits for its reader. The time of the body
    /// does not run until its next frame.
    pub(crate) fn reading(&self) {
        let mut state = self.stall.state.lock().expect("stall mutex");
        if let Some(entry) = state.bodies.get_mut(&self.id) {
            entry.reading = true;
        }
    }
}

impl Drop for Tracker {
    fn drop(&mut self) {
        self.stall
            .state
            .lock()
            .expect("stall mutex")
            .bodies
            .remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future;
    use ostrya_rt::block_on;

    /// A body that gives frames keeps the deadline away. A body that waits
    /// for its reader also keeps it away. A body that gives no frame for the
    /// window makes the deadline expire. With no live body, the deadline
    /// never expires.
    #[test]
    fn a_body_with_no_frame_for_the_window_expires() {
        block_on(async {
            let window = Duration::from_millis(200);
            let stall = Stall::new(window);
            let idle = future::or(
                async {
                    stall.expired().await;
                    false
                },
                async {
                    rt::Timer::after(window * 2).await;
                    true
                },
            );
            assert!(idle.await, "no live body, so no expiry");

            let tracker = stall.track();
            let started = Instant::now();
            let fed = future::or(
                async {
                    stall.expired().await;
                    false
                },
                async {
                    for _ in 0..6 {
                        rt::Timer::after(window / 4).await;
                        tracker.progress();
                    }
                    true
                },
            );
            assert!(fed.await, "a body that gives frames does not expire");
            tracker.reading();
            let reading = future::or(
                async {
                    stall.expired().await;
                    false
                },
                async {
                    rt::Timer::after(window * 2).await;
                    true
                },
            );
            assert!(
                reading.await,
                "a body that waits for its reader does not expire"
            );
            tracker.progress();
            stall.expired().await;
            assert!(started.elapsed() >= window * 3 + window * 6 / 4);
            drop(tracker);
            assert!(stall.state.lock().unwrap().bodies.is_empty());
        });
    }
}
