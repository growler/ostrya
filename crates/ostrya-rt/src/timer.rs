//! Async delays.
//!
//! [`Timer::after`] uses the timer of the backend (`smol::Timer` or
//! `tokio::time::sleep`). The `ostree` command tries a held repository lock
//! again until a timeout. The lock loop of the repository waits on
//! [`Timer::after`] between two attempts, so the wait is an async sleep.
//!
//! [`Deadline`] is the same timer for a `poll_*` method. The work restarts the
//! window when it makes progress, and the poll reports the end of the window.
//! The response body of the fetcher holds one to limit how long a peer can
//! stay silent in a stream. It holds one more to sample the rate for its
//! low-speed rule.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// A one-shot async delay.
pub struct Timer;

impl Timer {
    /// Waits until `duration` elapses.
    #[cfg(feature = "tokio")]
    pub async fn after(duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    /// Waits until `duration` elapses.
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    pub async fn after(duration: Duration) {
        smol::Timer::after(duration).await;
    }
}

/// A restartable time window, polled from inside a `poll_*` method.
///
/// An expiry sticks until the next [`restart`](Deadline::restart). Each poll
/// after the first expiry also reports it.
pub struct Deadline {
    window: Duration,
    expired: bool,
    #[cfg(feature = "tokio")]
    sleep: Pin<Box<tokio::time::Sleep>>,
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    timer: smol::Timer,
}

impl Deadline {
    /// Creates a window of length `window` that starts now.
    ///
    /// With the `tokio` feature, the call must run inside a tokio runtime
    /// context.
    pub fn new(window: Duration) -> Deadline {
        Deadline {
            window,
            expired: false,
            #[cfg(feature = "tokio")]
            sleep: Box::pin(tokio::time::sleep(window)),
            #[cfg(all(feature = "smol", not(feature = "tokio")))]
            timer: smol::Timer::after(window),
        }
    }

    /// Returns the length of the window.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Starts the window again from now.
    pub fn restart(&mut self) {
        self.expired = false;
        // If the end of the window is past the range of the clock, the addition
        // of the window to the clock panics. In that case, the code arms a new
        // sleep, as `new` does.
        #[cfg(feature = "tokio")]
        match tokio::time::Instant::now().checked_add(self.window) {
            Some(end) => self.sleep.as_mut().reset(end),
            None => self.sleep.set(tokio::time::sleep(self.window)),
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        self.timer.set_after(self.window);
    }

    /// Returns `Poll::Ready` if the window ended with no restart.
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.expired {
            return Poll::Ready(());
        }
        #[cfg(feature = "tokio")]
        let polled = self.sleep.as_mut().poll(cx);
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        let polled = Pin::new(&mut self.timer).poll(cx).map(|_| ());
        if polled.is_ready() {
            self.expired = true;
        }
        polled
    }
}

// The streams that hold a `Deadline` move between threads, so it must be
// `Send` and `Sync`.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Deadline>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;
    use std::time::Instant;

    #[test]
    fn after_waits_at_least_the_requested_time() {
        block_on(async {
            let start = Instant::now();
            Timer::after(Duration::from_millis(20)).await;
            assert!(start.elapsed() >= Duration::from_millis(20));
        });
    }

    /// Polls `deadline` once, from inside a task that the backend drives.
    async fn poll_once(deadline: &mut Deadline) -> Poll<()> {
        std::future::poll_fn(|cx| Poll::Ready(deadline.poll_expired(cx))).await
    }

    #[test]
    fn a_restart_moves_the_window_and_expiry_sticks() {
        block_on(async {
            let mut deadline = Deadline::new(Duration::from_millis(100));
            assert!(poll_once(&mut deadline).await.is_pending());

            // Half the window in, a restart moves the end out by a full
            // window. The end of the first window does not expire the deadline.
            Timer::after(Duration::from_millis(50)).await;
            deadline.restart();
            Timer::after(Duration::from_millis(50)).await;
            assert!(poll_once(&mut deadline).await.is_pending());

            Timer::after(Duration::from_millis(150)).await;
            assert!(poll_once(&mut deadline).await.is_ready());
            // The second poll reports the same expiry.
            assert!(poll_once(&mut deadline).await.is_ready());

            // A restart after expiry opens a new window.
            deadline.restart();
            assert!(poll_once(&mut deadline).await.is_pending());
        });
    }

    /// The test uses two windows: one as long as a C `int` of seconds, and one
    /// of the longest duration. Each window arms, restarts, and polls with no
    /// panic on each backend. Both windows stay open.
    #[test]
    fn a_window_of_the_largest_int_seconds_is_armed() {
        block_on(async {
            for window in [Duration::from_secs(i32::MAX as u64), Duration::MAX] {
                let mut deadline = Deadline::new(window);
                assert!(poll_once(&mut deadline).await.is_pending());
                deadline.restart();
                assert!(poll_once(&mut deadline).await.is_pending());
            }
        });
    }
}
