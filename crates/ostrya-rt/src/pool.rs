//! The blocking-pool entry points and a test-oriented executor driver.
//!
//! [`unblock`] is the door to the backend's blocking thread pool
//! (`smol::unblock` or `tokio::task::spawn_blocking`) for work whose result is
//! awaited, and [`unblock_detached`] for work that runs detached; every
//! synchronous syscall offload in the library goes through one of the two.
//! [`blocking_threads`] gives the size of that pool. [`block_on`] drives a
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

/// Run a blocking closure on the backend's blocking thread pool as a detached
/// task, with no result to await. The call returns at once.
///
/// Under tokio, a call outside the context of a runtime has no pool to reach,
/// so the closure runs inline on the calling thread before the call returns.
/// A panic in a detached closure is not seen by the caller.
#[cfg(feature = "tokio")]
pub fn unblock_detached<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => drop(handle.spawn_blocking(f)),
        Err(_) => f(),
    }
}

/// Run a blocking closure on the backend's blocking thread pool as a detached
/// task, with no result to await. The call returns at once.
///
/// The pool of `smol` needs no runtime context, so the closure always runs
/// on the pool. A panic in a detached closure is not seen by the caller.
#[cfg(all(feature = "smol", not(feature = "tokio")))]
pub fn unblock_detached<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    smol::unblock(f).detach();
}

/// The most closures the blocking thread pool of the backend runs at the same
/// time.
///
/// The value is the limit of `tokio`'s default runtime, 512. A runtime that the
/// caller builds with another `max_blocking_threads` is not seen.
#[cfg(feature = "tokio")]
pub fn blocking_threads() -> usize {
    512
}

/// The most closures the blocking thread pool of the backend runs at the same
/// time.
///
/// The value follows the rule of the `blocking` crate, which runs the pool of
/// `smol`: `BLOCKING_MAX_THREADS` gives the limit, clamped to 1 through
/// 10,000, and a variable that is absent or is not a number gives 500. The
/// function reads the variable at each call. The pool reads it once, when it
/// first starts a thread.
#[cfg(all(feature = "smol", not(feature = "tokio")))]
pub fn blocking_threads() -> usize {
    parse_max(std::env::var("BLOCKING_MAX_THREADS").ok().as_deref())
}

/// The pool limit that the value of `BLOCKING_MAX_THREADS` gives.
#[cfg(all(feature = "smol", not(feature = "tokio")))]
fn parse_max(value: Option<&str>) -> usize {
    value
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(500, |v| v.clamp(1, 10_000))
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

    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    #[test]
    fn parse_max_follows_the_rule_of_the_pool() {
        assert_eq!(parse_max(None), 500);
        assert_eq!(parse_max(Some("0")), 1);
        assert_eq!(parse_max(Some("20000")), 10_000);
        assert_eq!(parse_max(Some("abc")), 500);
        assert_eq!(parse_max(Some("8")), 8);
    }

    /// The closure runs, and the call does not wait for it.
    #[test]
    fn unblock_detached_runs_the_closure() {
        let (tx, rx) = std::sync::mpsc::channel();
        block_on(async move {
            unblock_detached(move || tx.send(7).unwrap());
            assert_eq!(unblock(move || rx.recv().unwrap()).await, 7);
        });
    }

    /// Under tokio, a call from a thread outside any runtime runs the closure
    /// inline.
    #[cfg(feature = "tokio")]
    #[test]
    fn unblock_detached_with_no_runtime_runs_inline() {
        let ran = std::thread::spawn(|| {
            let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = ran.clone();
            unblock_detached(move || flag.store(true, std::sync::atomic::Ordering::SeqCst));
            ran.load(std::sync::atomic::Ordering::SeqCst)
        })
        .join()
        .unwrap();
        assert!(ran);
    }

    #[test]
    fn unblock_propagates_panics() {
        let result = std::panic::catch_unwind(|| {
            block_on(async { unblock(|| panic!("boom")).await });
        });
        assert!(result.is_err());
    }
}
