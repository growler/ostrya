//! Owned transaction handles.
//!
//! A [`Transaction`] is created from a [`Repo`](crate::Repo) and owns the
//! repository lock hold and a staging directory for its duration. Multiple
//! transactions may exist at once in one process, each with its own staging
//! directory; the shared repository lock coordinates them and excludes other
//! processes, and the `ostree` tool, per the configured lock kind.
//!
//! At this phase a transaction sets up and tears down its lock and staging area.
//! Object writing, the ref queue, and commit assembly land with the write path.
//! [`commit`](Transaction::commit) and [`abort`](Transaction::abort) both remove
//! the staging directory and release the lock; dropping a transaction that did
//! neither reaps the staging directory and releases the lock as well.

use crate::lock::LockGuard;
use crate::staging::StagingDir;

/// An owned transaction over a repository.
///
/// The handle carries its repository lock hold and staging directory. Dropping
/// it without calling [`commit`](Transaction::commit) or
/// [`abort`](Transaction::abort) reaps the staging directory and releases the
/// lock, so an abandoned transaction leaves no lock held and no staging
/// directory behind.
///
/// End a transaction with [`commit`](Transaction::commit) or
/// [`abort`](Transaction::abort), which remove the staging directory on the
/// blocking pool. Dropping the handle performs that removal synchronously on
/// the thread running the drop, recursing through the staging tree; when the
/// drop lands on an async executor thread it stalls the executor for the
/// duration.
pub struct Transaction {
    // Dropped in declaration order: the staging directory is reaped, then the
    // lock is released.
    staging: Option<StagingDir>,
    /// The repository lock hold, kept for the transaction's lifetime and
    /// released when this field drops. Never read.
    #[allow(dead_code)]
    lock: LockGuard,
}

impl Transaction {
    /// Assemble a transaction from an acquired lock and a staging directory.
    pub(crate) fn new(lock: LockGuard, staging: StagingDir) -> Transaction {
        Transaction {
            staging: Some(staging),
            lock,
        }
    }

    /// Finish the transaction, publishing its staged work.
    ///
    /// At this phase there is no staged work to publish, so this removes the
    /// staging directory and releases the lock. The write path adds object and
    /// ref publication here.
    pub async fn commit(mut self) -> crate::Result<()> {
        self.reap_staging().await;
        Ok(())
    }

    /// Discard the transaction and its staged work, releasing the lock.
    pub async fn abort(mut self) -> crate::Result<()> {
        self.reap_staging().await;
        Ok(())
    }

    /// Remove the staging directory on the blocking pool, if it is still present.
    async fn reap_staging(&mut self) {
        if let Some(staging) = self.staging.take() {
            ostrya_rt::unblock(move || drop(staging)).await;
        }
    }
}

/// A transaction moves freely across tasks and threads.
const _: fn() = || {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<Transaction>();
};
