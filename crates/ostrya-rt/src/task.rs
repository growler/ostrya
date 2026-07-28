//! Spawning concurrent tasks on the selected backend.
//!
//! [`spawn`] hands a future to the backend's executor (`smol::spawn` or
//! `tokio::spawn`) and returns a [`JoinHandle`] that resolves to its output.
//! The task keeps running when the handle is dropped, which is what the
//! fetcher's connection drivers need: a connection outlives the request that
//! opened it.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Run `future` concurrently on the backend's executor.
///
/// Under the tokio backend this must be called from within a runtime context,
/// as `tokio::spawn` requires.
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

/// A handle to a spawned task, resolving to the task's output.
///
/// Dropping the handle detaches the task; it runs to completion either way. A
/// panic inside the task propagates to whoever awaits the handle, and a task
/// that was cancelled instead -- which under the tokio backend is what awaiting
/// through a runtime shutdown produces -- panics the awaiting side with a
/// message naming the cancellation.
pub struct JoinHandle<T> {
    #[cfg(feature = "tokio")]
    inner: tokio::task::JoinHandle<T>,
    /// The `Option` exists for [`Drop`], which has to move the task out to call
    /// `detach`, and that consumes it. Nothing else takes it, so it holds a task
    /// for the whole life of the handle.
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    inner: Option<smol::Task<T>>,
}

#[cfg(all(feature = "smol", not(feature = "tokio")))]
impl<T> Drop for JoinHandle<T> {
    fn drop(&mut self) {
        // A smol task is cancelled when its handle drops, so detach it to keep
        // the tokio semantics: the work continues without the handle.
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
                // A task that ended without a panic was cancelled, which the
                // runtime shutting down under it produces. There is no payload
                // to resume, and no value to hand back either.
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

    /// A panic in the task is the payload the awaiting side sees.
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

    /// A cancelled task carries no panic payload, so awaiting it reports the
    /// cancellation rather than failing inside the error handling.
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
