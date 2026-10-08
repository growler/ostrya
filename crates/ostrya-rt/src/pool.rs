//! The blocking pool and a driver for tests.
//!
//! [`unblock`] runs a closure on the blocking pool of the backend
//! (`smol::unblock` or `tokio::task::spawn_blocking`) and awaits its result.
//! [`unblock_detached`] runs a closure on the same pool and does not wait.
//! Each synchronous system call that the library moves off its async tasks
//! goes through one of the two. [`blocking_threads`] gives the size of the
//! pool.
//!
//! [`block_on`] exists for tests and doctests. The entry points of the library
//! are `async fn` items that the runtime of the caller drives.

use std::future::Future;

/// Runs a closure on the blocking pool and returns its result.
///
/// # Panics
///
/// - If the closure panics, the awaiting task panics with the same payload.
/// - With the `tokio` feature, if the runtime cancels the closure before the
///   closure starts, for example at a shutdown, the awaiting task panics.
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

/// Runs a closure on the blocking pool and returns its result.
///
/// # Panics
///
/// - If the closure panics, the awaiting task panics with the same payload.
/// - With the `tokio` feature, if the runtime cancels the closure before the
///   closure starts, for example at a shutdown, the awaiting task panics.
#[cfg(all(feature = "smol", not(feature = "tokio")))]
pub async fn unblock<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    smol::unblock(f).await
}

/// Runs a closure on the blocking pool and does not wait for it.
///
/// With the `smol` feature, the closure always runs on the pool, because the
/// pool needs no runtime context. A panic of the closure does not reach the
/// caller.
///
/// With the `tokio` feature, the closure runs on the pool if the call is inside
/// a tokio runtime context. A panic of the closure then does not reach the
/// caller. Outside a runtime context, the closure runs on the calling thread
/// before the function returns, so a panic of the closure reaches the caller.
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

/// Runs a closure on the blocking pool and does not wait for it.
///
/// With the `smol` feature, the closure always runs on the pool, because the
/// pool needs no runtime context. A panic of the closure does not reach the
/// caller.
///
/// With the `tokio` feature, the closure runs on the pool if the call is inside
/// a tokio runtime context. A panic of the closure then does not reach the
/// caller. Outside a runtime context, the closure runs on the calling thread
/// before the function returns, so a panic of the closure reaches the caller.
#[cfg(all(feature = "smol", not(feature = "tokio")))]
pub fn unblock_detached<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    smol::unblock(f).detach();
}

/// Returns how many closures the blocking pool runs at the same time.
///
/// With the `smol` feature, the function reads `BLOCKING_MAX_THREADS` at each
/// call and clamps the value to 1 through 10,000. If the variable is absent or
/// is not a number, the function returns 500.
///
/// With the `tokio` feature, the function returns 512, the limit of the default
/// tokio runtime. It does not read the limit of a runtime that the caller
/// builds with another `max_blocking_threads`.
#[cfg(feature = "tokio")]
pub fn blocking_threads() -> usize {
    512
}

/// Returns how many closures the blocking pool runs at the same time.
///
/// With the `smol` feature, the function reads `BLOCKING_MAX_THREADS` at each
/// call and clamps the value to 1 through 10,000. If the variable is absent or
/// is not a number, the function returns 500.
///
/// With the `tokio` feature, the function returns 512, the limit of the default
/// tokio runtime. It does not read the limit of a runtime that the caller
/// builds with another `max_blocking_threads`.
// The value follows the rule of the `blocking` crate, which runs the pool of
// `smol`. The pool reads the variable once, when it starts its first thread.
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

/// Runs a future to completion on the current thread and returns its output.
///
/// The function serves tests and doctests. A library caller awaits the future
/// in its own runtime. With the `tokio` feature, each call builds a new
/// current-thread runtime with the time and I/O drivers.
///
/// # Panics
///
/// With the `tokio` feature, the function panics in these conditions:
///
/// - The runtime does not build.
/// - The call runs on a thread that drives a tokio runtime, for example
///   inside another `block_on` call or inside a task of
///   [`spawn`](crate::spawn).
#[cfg(feature = "tokio")]
pub fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()
        .expect("build tokio current-thread runtime")
        .block_on(future)
}

/// Runs a future to completion on the current thread and returns its output.
///
/// The function serves tests and doctests. A library caller awaits the future
/// in its own runtime. With the `tokio` feature, each call builds a new
/// current-thread runtime with the time and I/O drivers.
///
/// # Panics
///
/// With the `tokio` feature, the function panics in these conditions:
///
/// - The runtime does not build.
/// - The call runs on a thread that drives a tokio runtime, for example
///   inside another `block_on` call or inside a task of
///   [`spawn`](crate::spawn).
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
