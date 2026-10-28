//! Tasks on the executor of the backend.
//!
//! [`spawn`] gives a future to the executor of the backend (`smol::spawn` or
//! `tokio::spawn`). The task continues when its [`JoinHandle`] drops. The
//! connection drivers of the fetcher need this, because a connection lives
//! longer than the request that opened it.
//!
//! [`unblock_task`] gives a closure to the blocking pool and returns a
//! [`JoinHandle`] of the same kind.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Starts `future` as a task on the executor of the backend.
///
/// The returned [`JoinHandle`] resolves to the output of the task. With the
/// `tokio` feature, the call must run inside a tokio runtime context.
pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    #[cfg(feature = "tokio")]
    {
        JoinHandle {
            inner: tokio::spawn(future),
        }
    }
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    {
        JoinHandle {
            inner: Some(smol::spawn(future)),
        }
    }
}

/// Starts a closure on the blocking pool and returns a handle to its result.
///
/// The pool is the pool of [`unblock`](crate::unblock). The closure starts
/// without a poll of the handle. If the handle drops, the closure continues
/// and runs to completion, also if it has not started yet. So a caller can
/// keep the handle after it drops the future that started the closure, and
/// await the end of the closure later.
///
/// The [`JoinHandle`] states the panics of an await of the handle. With the
/// `tokio` feature, the call must run inside a tokio runtime context.
pub fn unblock_task<T, F>(f: F) -> JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    #[cfg(feature = "tokio")]
    {
        JoinHandle {
            inner: tokio::task::spawn_blocking(f),
        }
    }
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    {
        JoinHandle {
            inner: Some(smol::unblock(f)),
        }
    }
}

/// A handle that resolves to the output of a spawned task, or of a closure
/// that [`unblock_task`] started.
///
/// If the handle drops, the task continues and runs to completion.
///
/// # Panics
///
/// - If the task panics, the task that awaits the handle panics with the same
///   payload.
/// - With the `tokio` feature, if the task is cancelled, the awaiting task
///   panics with a message that starts with `awaited task was cancelled:`. A
///   runtime shutdown is one cause of a cancellation.
pub struct JoinHandle<T> {
    #[cfg(feature = "tokio")]
    inner: tokio::task::JoinHandle<T>,
    /// The `Option` exists for [`Drop`], which moves the task out to call
    /// `detach`, because `detach` consumes the task. Nothing else takes it, so
    /// it holds a task for the whole life of the handle.
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    inner: Option<smol::Task<T>>,
}

#[cfg(all(feature = "smol", not(feature = "tokio")))]
impl<T> Drop for JoinHandle<T> {
    fn drop(&mut self) {
        // Smol cancels a task when its handle drops. The code detaches the
        // task, so the work continues without the handle, as with tokio.
        if let Some(task) = self.inner.take() {
            task.detach();
        }
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        #[cfg(feature = "tokio")]
        {
            match Pin::new(&mut self.get_mut().inner).poll(cx) {
                Poll::Ready(Ok(value)) => Poll::Ready(value),
                Poll::Ready(Err(join_error)) if join_error.is_panic() => {
                    std::panic::resume_unwind(join_error.into_panic())
                }
                // A task that ended with no panic was cancelled, for example by
                // a runtime shutdown. There is no payload to resume and no value
                // to return.
                Poll::Ready(Err(join_error)) => panic!("awaited task was cancelled: {join_error}"),
                Poll::Pending => Poll::Pending,
            }
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            let task = self
                .get_mut()
                .inner
                .as_mut()
                .expect("the task is taken only by Drop, which ends the handle");
            Pin::new(task).poll(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    #[test]
    fn spawned_task_returns_its_output() {
        block_on(async { assert_eq!(spawn(async { 6 * 7 }).await, 42) });
    }

    /// The awaiting side sees the panic payload of the task.
    #[test]
    fn a_panicking_task_propagates_its_panic() {
        let caught = std::panic::catch_unwind(|| {
            block_on(async { spawn(async { panic!("task boom") }).await });
        })
        .unwrap_err();
        let message = caught
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| caught.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        assert_eq!(message, "task boom");
    }

    /// A cancelled task carries no panic payload. The await reports the
    /// cancellation, and the error handling does not fail.
    #[cfg(feature = "tokio")]
    #[test]
    fn an_awaited_cancelled_task_names_the_cancellation() {
        let caught = std::panic::catch_unwind(|| {
            block_on(async {
                let handle = spawn(std::future::pending::<()>());
                handle.inner.abort();
                handle.await;
            });
        })
        .unwrap_err();
        let message = caught.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(message.contains("cancelled"), "{message}");
    }

    #[test]
    fn unblock_task_returns_the_result_of_the_closure() {
        block_on(async { assert_eq!(unblock_task(|| 6 * 7).await, 42) });
    }

    /// The awaiting side sees the panic payload of the closure.
    #[test]
    fn an_unblock_task_propagates_the_panic_of_its_closure() {
        let caught = std::panic::catch_unwind(|| {
            block_on(async { unblock_task(|| panic!("job boom")).await });
        })
        .unwrap_err();
        let message = caught
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| caught.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        assert_eq!(message, "job boom");
    }

    /// The closure runs to its end after its handle drops.
    #[test]
    fn a_dropped_unblock_task_runs_its_closure() {
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<u32>();
        block_on(async move {
            drop(unblock_task(move || {
                go_rx.recv().unwrap();
                done_tx.send(7).unwrap();
            }));
            go_tx.send(()).unwrap();
            let done = crate::unblock(move || done_rx.recv().unwrap()).await;
            assert_eq!(done, 7);
        });
    }

    #[test]
    fn dropped_handle_leaves_the_task_running() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let done = Arc::new(AtomicBool::new(false));
        let flag = done.clone();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        block_on(async move {
            drop(spawn(async move {
                flag.store(true, Ordering::SeqCst);
                let _ = tx.send(());
            }));
            // Wait for the detached task on the blocking pool, so the executor
            // stays free to run it.
            crate::unblock(move || rx.recv().unwrap()).await;
        });
        assert!(done.load(Ordering::SeqCst));
    }
}
