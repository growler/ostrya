//! The blocking-pool entry point and a test-oriented executor driver.
//!
//! [`unblock`] is the single door to the backend's blocking thread pool
//! (`smol::unblock` or `tokio::task::spawn_blocking`); every synchronous
//! syscall offload in the library goes through it. [`block_on`] drives a
//! future to completion on the backend's executor and exists for tests and
//! doctests -- the library's real entry points are `async fn` driven by the
//! caller's runtime.

use std::future::Future;

/// Run a blocking closure on the backend's blocking thread pool, awaiting its
/// result. A panic in the closure propagates to the awaiting task.
#[cfg(feature = "tokio")]
pub async fn unblock<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(value) => value,
        Err(join_error) => std::panic::resume_unwind(join_error.into_panic()),
    }
}

/// Run a blocking closure on the backend's blocking thread pool, awaiting its
/// result. A panic in the closure propagates to the awaiting task.
#[cfg(all(feature = "smol", not(feature = "tokio")))]
pub async fn unblock<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    smol::unblock(f).await
}

/// Drive `future` to completion on the backend's executor. Intended for tests
/// and doctests; production callers await inside their own runtime.
#[cfg(feature = "tokio")]
pub fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()
        .expect("build tokio current-thread runtime")
        .block_on(future)
}

/// Drive `future` to completion on the backend's executor. Intended for tests
/// and doctests; production callers await inside their own runtime.
#[cfg(all(feature = "smol", not(feature = "tokio")))]
pub fn block_on<F: Future>(future: F) -> F::Output {
    smol::block_on(future)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unblock_runs_on_the_pool_and_returns() {
        let sum = block_on(async { unblock(|| (1..=4).sum::<u32>()).await });
        assert_eq!(sum, 10);
    }

    #[test]
    fn unblock_propagates_panics() {
        let result = std::panic::catch_unwind(|| {
            block_on(async { unblock(|| panic!("boom")).await });
        });
        assert!(result.is_err());
    }
}
