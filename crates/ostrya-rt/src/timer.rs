//! Async delays.
//!
//! [`Timer::after`] resolves once a duration has elapsed, using the compiled
//! backend's timer (`smol::Timer` under smol, `tokio::time::sleep` under
//! tokio). The repository lock-acquisition loop waits on it between contended
//! attempts, turning the tool's retry-until-timeout behavior into an async
//! sleep.
//!
//! [`Deadline`] is the same timer in a form a `poll_*` method can use: a window
//! that is restarted when work makes progress and reports the window running
//! out. The fetcher's response body holds one to bound how long a peer may stay
//! silent mid-stream.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// A one-shot async delay over the compiled runtime backend.
pub struct Timer;

impl Timer {
    /// Complete after `duration` has elapsed.
    #[cfg(feature = "tokio")]
    pub async fn after(duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    /// Complete after `duration` has elapsed.
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    pub async fn after(duration: Duration) {
        smol::Timer::after(duration).await;
    }
}

/// A restartable window, polled from inside a `poll_*` method.
///
/// [`restart`](Deadline::restart) moves the window to one full length from now,
/// and [`poll_expired`](Deadline::poll_expired) reports it running out. Expiry
/// sticks until the next restart, so every poll after the first expiry reports
/// it too, on either backend.
pub struct Deadline {
    window: Duration,
    expired: bool,
    #[cfg(feature = "tokio")]
    sleep: Pin<Box<tokio::time::Sleep>>,
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    timer: smol::Timer,
}

impl Deadline {
    /// A window of `window` starting now.
    ///
    /// Under the tokio backend this must be called from within a runtime
    /// context, as tokio's timer requires.
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

    /// The length of the window.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Start the window again from now.
    pub fn restart(&mut self) {
        self.expired = false;
        #[cfg(feature = "tokio")]
        self.sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + self.window);
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        self.timer.set_after(self.window);
    }

    /// Ready once the window has elapsed without a restart.
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

/// The deadline travels with the streams that hold it.
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

    /// Poll `deadline` once, from inside a task the backend is driving.
    async fn poll_once(deadline: &mut Deadline) -> Poll<()> {
        std::future::poll_fn(|cx| Poll::Ready(deadline.poll_expired(cx))).await
    }

    #[test]
    fn a_restart_moves_the_window_and_expiry_sticks() {
        block_on(async {
            let mut deadline = Deadline::new(Duration::from_millis(100));
            assert!(poll_once(&mut deadline).await.is_pending());

            // Half the window in, a restart pushes expiry out by a full window,
            // so the original window elapsing is not enough.
            Timer::after(Duration::from_millis(50)).await;
            deadline.restart();
            Timer::after(Duration::from_millis(50)).await;
            assert!(poll_once(&mut deadline).await.is_pending());

            Timer::after(Duration::from_millis(150)).await;
            assert!(poll_once(&mut deadline).await.is_ready());
            // The second poll reports the same expiry.
            assert!(poll_once(&mut deadline).await.is_ready());

            // A restart after expiry opens a fresh window.
            deadline.restart();
            assert!(poll_once(&mut deadline).await.is_pending());
        });
    }
}
