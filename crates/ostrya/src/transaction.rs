//! Owned transaction handles.
//!
//! A [`Transaction`] is created from a [`Repo`](crate::Repo) and owns the
//! repository lock hold and a staging directory for its duration. Multiple
//! transactions may exist at once in one process, each with its own staging
//! directory; the shared repository lock coordinates them and excludes other
//! processes, and the `ostree` tool, per the configured lock kind.
//!
//! A transaction ingests objects into its staging directory through the write
//! methods (in [`crate::write`]) and publishes them into `objects/` at
//! [`commit`](Transaction::commit). Object identity, dedup, free-space
//! accounting, and the archive size map live in the shared staged state behind
//! a mutex, so concurrent writers may share a `&Transaction`. Dropping a
//! transaction without committing reaps the staging directory (discarding every
//! staged object) and releases the lock.

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Mutex;

use ostrya_core::{Checksum, ObjectType, RepoMode};

use crate::error::{Error, Result};
use crate::lock::LockGuard;
use crate::repo::Repo;
use crate::staging::StagingDir;
use crate::write::{
    StageCtx, StageOutcome, TempKind, publish_blocking, stage_content_blocking,
    stage_metadata_blocking, stage_symlink_blocking,
};

pub use crate::write::{ContentWriter, FileMeta};

/// Statistics accumulated over a transaction, returned by
/// [`commit`](Transaction::commit).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransactionStats {
    /// Metadata objects freshly staged (dirtree, dirmeta, commit, and the
    /// like). A dedup hit does not count.
    pub metadata_written: u32,
    /// Content objects freshly staged. A dedup hit does not count.
    pub content_written: u32,
    /// The total on-disk size of the freshly staged content objects.
    pub content_bytes_written: u64,
    /// Content objects skipped because their (device, inode) was already known.
    /// The devino cache lands with checkout (Phase 8), so this stays 0 here.
    pub devino_cache_hits: u32,
}

/// One object staged in a transaction, awaiting publication.
struct StagedObject {
    /// The flat name the object holds in the staging directory.
    staging_name: String,
    /// The loose path under `objects/` the object publishes to.
    dest: String,
}

/// The archive size record for a content object, the input for `ostree.sizes`
/// in Phase 7d, which is where these fields are first read.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct SizeRecord {
    /// The on-disk (compressed) size of the `.filez`.
    pub(crate) compressed: u64,
    /// The uncompressed payload size.
    pub(crate) unpacked: u64,
}

/// The mutable state shared by concurrent writers on one transaction.
struct Staged {
    /// Objects staged so far, keyed by identity and type for in-transaction
    /// dedup and for publication at commit.
    objects: HashMap<(Checksum, ObjectType), StagedObject>,
    /// Per-content-object size records (archive mode), keyed by checksum.
    sizes: HashMap<Checksum, SizeRecord>,
    /// Remaining write budget in bytes before the configured free-space reserve
    /// is breached.
    free_budget: u64,
    /// Accumulated statistics.
    stats: TransactionStats,
}

/// An owned transaction over a repository.
///
/// The handle carries its repository lock hold, staging directory, and the
/// shared staged state. `&Transaction` is `Send + Sync`: concurrent writers may
/// stage objects through one shared reference. Dropping it without
/// [`commit`](Transaction::commit) or [`abort`](Transaction::abort) reaps the
/// staging directory and releases the lock, so an abandoned transaction leaves
/// nothing behind.
pub struct Transaction {
    repo: Repo,
    // Dropped in declaration order: the staged state and staging directory are
    // released, then the lock.
    staged: Mutex<Staged>,
    staging: Option<StagingDir>,
    /// The repository lock hold, kept for the transaction's lifetime and
    /// released when this field drops. Never read.
    #[allow(dead_code)]
    lock: LockGuard,
}

impl Transaction {
    /// Assemble a transaction from a repository handle, an acquired lock, a
    /// staging directory, and the initial free-space budget.
    pub(crate) fn new(
        repo: Repo,
        lock: LockGuard,
        staging: StagingDir,
        free_budget: u64,
    ) -> Transaction {
        Transaction {
            repo,
            staged: Mutex::new(Staged {
                objects: HashMap::new(),
                sizes: HashMap::new(),
                free_budget,
                stats: TransactionStats::default(),
            }),
            staging: Some(staging),
            lock,
        }
    }

    /// The repository this transaction writes to.
    pub(crate) fn repo(&self) -> &Repo {
        &self.repo
    }

    /// The staging directory descriptor objects are ingested into.
    pub(crate) fn staging_fd(&self) -> BorrowedFd<'_> {
        self.staging
            .as_ref()
            .expect("staging directory present during the transaction")
            .dir_fd()
    }

    /// Stage a regular-file content object whose payload is already written to
    /// `file`. Called by [`ContentWriter::finish`](crate::ContentWriter::finish).
    pub(crate) async fn stage_regular(
        &self,
        checksum: Checksum,
        header: ostrya_core::FileHeader,
        file: std::fs::File,
        temp: TempKind,
        unpacked: u64,
    ) -> Result<Checksum> {
        let mode = self.repo.mode();
        let (fsync, per_object_fsync) = self.fsync_flags()?;
        let objects = self.repo.objects_fd().try_clone_to_owned()?;
        let staging = self.staging_fd().try_clone_to_owned()?;
        let key = checksum;
        let outcome = ostrya_rt::unblock(move || {
            let ctx = StageCtx {
                objects_fd: objects.as_fd(),
                staging_fd: staging.as_fd(),
                mode,
                fsync,
                per_object_fsync,
            };
            stage_content_blocking(&ctx, &key, &header, file, temp, unpacked)
        })
        .await?;
        self.record(checksum, ObjectType::File, mode, outcome)
    }

    /// Stage a symlink content object. Called by
    /// [`write_symlink`](Transaction::write_symlink).
    pub(crate) async fn stage_symlink(
        &self,
        checksum: Checksum,
        header: ostrya_core::FileHeader,
    ) -> Result<Checksum> {
        let mode = self.repo.mode();
        let (fsync, per_object_fsync) = self.fsync_flags()?;
        let objects = self.repo.objects_fd().try_clone_to_owned()?;
        let staging = self.staging_fd().try_clone_to_owned()?;
        let key = checksum;
        let outcome = ostrya_rt::unblock(move || {
            let ctx = StageCtx {
                objects_fd: objects.as_fd(),
                staging_fd: staging.as_fd(),
                mode,
                fsync,
                per_object_fsync,
            };
            stage_symlink_blocking(&ctx, &key, &header)
        })
        .await?;
        self.record(checksum, ObjectType::File, mode, outcome)
    }

    /// Stage a metadata object from its serialized bytes. Called by
    /// [`write_metadata`](Transaction::write_metadata).
    pub(crate) async fn stage_metadata(
        &self,
        checksum: Checksum,
        ty: ObjectType,
        bytes: Vec<u8>,
    ) -> Result<Checksum> {
        let mode = self.repo.mode();
        let (fsync, per_object_fsync) = self.fsync_flags()?;
        let objects = self.repo.objects_fd().try_clone_to_owned()?;
        let staging = self.staging_fd().try_clone_to_owned()?;
        let key = checksum;
        let outcome = ostrya_rt::unblock(move || {
            let ctx = StageCtx {
                objects_fd: objects.as_fd(),
                staging_fd: staging.as_fd(),
                mode,
                fsync,
                per_object_fsync,
            };
            stage_metadata_blocking(&ctx, &key, ty, &bytes)
        })
        .await?;
        self.record(checksum, ty, mode, outcome)
    }

    /// Record a staged object's outcome: debit the free-space budget, insert it
    /// into the staged set, and update the statistics. Idempotent by identity,
    /// so restaging an object already staged in this transaction is a no-op.
    fn record(
        &self,
        checksum: Checksum,
        ty: ObjectType,
        mode: RepoMode,
        outcome: StageOutcome,
    ) -> Result<Checksum> {
        if outcome.deduped {
            return Ok(checksum);
        }
        let mut staged = self.staged.lock().unwrap();
        if staged.objects.contains_key(&(checksum, ty)) {
            // Already staged in this transaction: idempotent no-op.
            return Ok(checksum);
        }
        if outcome.on_disk_size > staged.free_budget {
            return Err(Error::InsufficientFreeSpace {
                shortfall: outcome.on_disk_size - staged.free_budget,
            });
        }
        staged.free_budget -= outcome.on_disk_size;
        staged.objects.insert(
            (checksum, ty),
            StagedObject {
                staging_name: outcome.staging_name,
                dest: outcome.dest,
            },
        );
        if ty == ObjectType::File {
            staged.stats.content_written += 1;
            staged.stats.content_bytes_written += outcome.on_disk_size;
            if mode.is_archive() {
                staged.sizes.insert(
                    checksum,
                    SizeRecord {
                        compressed: outcome.on_disk_size,
                        unpacked: outcome.unpacked,
                    },
                );
            }
        } else {
            staged.stats.metadata_written += 1;
        }
        Ok(checksum)
    }

    /// The `fsync` and `per-object-fsync` settings from the repository config.
    fn fsync_flags(&self) -> Result<(bool, bool)> {
        let config = self.repo.config();
        Ok((config.fsync()?, config.per_object_fsync()?))
    }

    /// Finish the transaction, publishing its staged objects into `objects/`.
    ///
    /// Publication follows the durability contract: with fsync enabled, the
    /// repository is `syncfs`-ed before the staged objects are renamed into
    /// `objects/<xx>/`, and each touched fanout directory and `objects/` is
    /// `fsync`-ed afterward. The staging directory is then reaped and the lock
    /// released.
    pub async fn commit(mut self) -> Result<TransactionStats> {
        self.publish().await?;
        let stats = self.staged.lock().unwrap().stats;
        self.reap_staging().await;
        Ok(stats)
    }

    /// Discard the transaction and its staged objects, releasing the lock.
    pub async fn abort(mut self) -> Result<()> {
        self.reap_staging().await;
        Ok(())
    }

    /// Rename every staged object into `objects/` on the blocking pool.
    async fn publish(&self) -> Result<()> {
        let mode = self.repo.mode();
        let objects: Vec<(String, String)> = {
            let staged = self.staged.lock().unwrap();
            staged
                .objects
                .values()
                .map(|o| (o.staging_name.clone(), o.dest.clone()))
                .collect()
        };
        if objects.is_empty() {
            return Ok(());
        }
        let (fsync, _) = self.fsync_flags()?;
        let repo_fd = self.repo.repo_fd().try_clone_to_owned()?;
        let objects_fd = self.repo.objects_fd().try_clone_to_owned()?;
        let staging_fd = self.staging_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || {
            publish_blocking(
                repo_fd.as_fd(),
                objects_fd.as_fd(),
                staging_fd.as_fd(),
                mode,
                &objects,
                fsync,
            )
        })
        .await
    }

    /// Remove the staging directory on the blocking pool, if still present.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CreateOptions;
    use crate::write::FileMeta;
    use ostrya_rt::block_on;

    /// A throwaway directory removed on drop.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("ostrya-txn-{}-{tag}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The archive size record separates the compressed `.filez` size from the
    /// uncompressed payload size. A highly compressible payload makes the two
    /// diverge, so recording the payload size in the `unpacked` field is the
    /// only value that satisfies the assertions.
    #[test]
    fn archive_size_record_separates_compressed_and_unpacked() {
        let scratch = Scratch::new("sizes");
        let root = scratch.0.join("repo");
        block_on(async {
            let repo = crate::Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let txn = repo.transaction().await.unwrap();
            let payload = vec![b'a'; 8192];
            let checksum = txn
                .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o644), &payload)
                .await
                .unwrap();

            // Read the record out from under the lock so the guard is released
            // before the abort await.
            let (record, content_bytes) = {
                let staged = txn.staged.lock().unwrap();
                let record = staged.sizes.get(&checksum).copied().expect("size record");
                (record, staged.stats.content_bytes_written)
            };
            assert_eq!(
                record.unpacked,
                payload.len() as u64,
                "unpacked is the pre-compression payload size"
            );
            assert_eq!(
                record.compressed, content_bytes,
                "compressed is the on-disk .filez size"
            );
            assert!(
                record.compressed < record.unpacked,
                "a compressible payload stores smaller than it unpacks: \
                 compressed={} unpacked={}",
                record.compressed,
                record.unpacked,
            );
            txn.abort().await.unwrap();
        });
    }
}
