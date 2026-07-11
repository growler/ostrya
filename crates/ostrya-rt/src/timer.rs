//! A one-shot async delay.
//!
//! [`Timer::after`] resolves once a duration has elapsed, using the compiled
//! backend's timer (`smol::Timer` under smol, `tokio::time::sleep` under
//! tokio). The repository lock-acquisition loop waits on it between contended
//! attempts, turning the tool's retry-until-timeout behavior into an async
//! sleep.

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
}
