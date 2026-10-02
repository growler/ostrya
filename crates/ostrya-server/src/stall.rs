//! The deadline on the response bodies of one connection.
//!
//! A response body that streams a file holds its descriptor, and a `.filez`
//! built on request also holds a compressor of the view. A client that stops
//! reading keeps hyper from taking frames of the body, and so keeps those
//! resources. Each stream body of a connection records the time hyper last
//! took a frame from it, and [`Stall::expired`] completes when one of them
//! has waited for the whole window. The connection then ends, and its bodies
//! drop. A body that waits for its own reader, for example for a compressor
//! of the view, is not waiting for the client, so its time does not run
//! until it gives its next frame.

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
    /// The time the body was made or last gave a frame.
    at: Instant,
    /// Whether the body waits for its own reader.
    reading: bool,
}

impl Stall {
    /// The bodies of a new connection, which may each wait `window` for
    /// hyper to take a frame.
    pub(crate) fn new(window: Duration) -> Arc<Stall> {
        Arc::new(Stall {
            window,
            state: Mutex::new(State {
                next_id: 0,
                bodies: HashMap::new(),
            }),
        })
    }

    /// Record a new body, made now.
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

    /// Complete when a live body that does not wait for its reader has
    /// given no frame for the window. The future sleeps until the oldest such
    /// body would reach the window, or for one window while there is none,
    /// and checks again.
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
    /// Record that hyper took a frame of the body now.
    pub(crate) fn progress(&self) {
        let mut state = self.stall.state.lock().expect("stall mutex");
        if let Some(entry) = state.bodies.get_mut(&self.id) {
            entry.at = Instant::now();
            entry.reading = false;
        }
    }

    /// Record that the body waits for its reader. The time of the body does
    /// not run until its next frame.
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

    /// A body that gives frames keeps the deadline away, and so does a body
    /// that waits for its reader. A body that gives none for the window
    /// makes it expire. With no body live it never expires.
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
