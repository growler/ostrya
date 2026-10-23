//! The push of a local directory to a bucket repository as a new commit.
//!
//! The bucket has no server that makes the commit, so the client makes it.
//! The commit is the commit that the receive side of a tree push makes from
//! the same inputs, with the `config` of the bucket in the role of the
//! server: the tip of the branch in the bucket is the parent, and the
//! namespace gives the collection binding. The push uploads the objects of
//! the tree that the bucket lacks, then the commit object, then the ref file.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Instant;

use ostrya_core::{Checksum, MAX_METADATA_SIZE, ObjectName, ObjectType};

use super::invalid;
use super::s3::{
    BucketState, CompressorPool, Counts, Job, Namespace, Origin, Update, Uploads, fail, read_state,
    write_bucket_refs,
};
use crate::bucket::{
    BucketPushOutcome, BucketRepo, BucketWriteOptions, LockOperation, check_prefixes, object_key,
};
use crate::error::{Error, Result};
use crate::remote::{
    Compression, Encoding, ObjectSource, PushOutcome, PushPhase, PushStats, RefOutcome,
    ScannedTree, TreePushOptions, scan_tree,
};
use crate::server_commit::{clock, commit_bytes};
use crate::summary::OSTREE_METADATA_REF;

/// The work of a tree push before the ref write, and its counts.
struct Uploaded {
    update: Update,
    stats: PushStats,
}

/// Methods that push a local directory to a bucket repository.
impl BucketRepo {
    /// Pushes the directory `root` to the bucket repository as one new
    /// commit on the branch [`onto`](TreePushOptions::onto).
    ///
    /// The push makes the commit on the client: the commit that the receive
    /// side of [`push_tree`](crate::remote::push_tree) makes from the same
    /// inputs, with the `config` of the bucket in the role of the server.
    /// The push needs the features `push` and `s3`, and the bucket
    /// repository needs a `config`, which [`BucketRepo::init`] writes.
    ///
    /// The push writes no `summary` and no `summary.sig`, as
    /// [`Repo::push_to_bucket`](crate::Repo::push_to_bucket) writes none. It
    /// signs no commit. To sign the commit, pull it into a local repository,
    /// sign it there, and push it with `Repo::push_to_bucket`, which then
    /// uploads the `.commitmeta` alone.
    ///
    /// # Steps
    ///
    /// 1. The push refuses [`tags`](TreePushOptions::tags). Then
    ///    [`scan_tree`] checks the other options and walks and hashes the
    ///    tree, with no request.
    /// 2. It takes the writer lock of the bucket repository for
    ///    [`LockOperation::Push`], with
    ///    [`break_lock`](BucketWriteOptions::break_lock).
    /// 3. It reads the `config` and selects the namespace, as
    ///    `Repo::push_to_bucket` does with
    ///    [`collection`](TreePushOptions::collection). Then at the same time
    ///    it reads the ref files of the ref directory of the namespace, lists
    ///    `refs/mirrors/` of the collection id of the bucket, and lists the
    ///    objects. It reads no ref file of another namespace.
    /// 4. It checks the refs: the branch `ostree-metadata` in `refs/heads/`
    ///    of a bucket with a collection id is refused, the ref directory must
    ///    hold no name that is a directory of another name after the push,
    ///    and each ref of the namespace and the parent must name a commit
    ///    that the listing holds.
    /// 5. It makes the commit. The parent is the tip of the branch in the
    ///    bucket, or none for an absent branch or with
    ///    [`orphan`](TreePushOptions::orphan). The collection binding is the
    ///    collection id of the bucket in `refs/heads/`, and the id of the
    ///    namespace in `refs/mirrors/ID/`. With no
    ///    [`timestamp`](TreePushOptions::timestamp), the push takes the clock
    ///    of the system. It reads no environment variable.
    /// 6. It uploads each object of the tree that the listing lacks, at most
    ///    `max_outstanding` uploads at a time.
    /// 7. It uploads the commit object if the listing lacks it.
    /// 8. It checks the writer lock, then writes the ref file of the branch
    ///    if the branch changes.
    /// 9. It releases the writer lock.
    ///
    /// The parent is the tip that the push read under the lock, so each
    /// update is a fast-forward unless `orphan` is set. With `orphan`, the
    /// new commit replaces the tip of a branch that exists, with no check.
    ///
    /// # Objects
    ///
    /// Each object goes up in archive form. A dirtree and a dirmeta object
    /// are the bytes of the scan. A symlink is the framed archive header
    /// alone. A regular file is the framed archive header, then its payload
    /// in raw DEFLATE, read from the file as a stream. The DEFLATE level is
    /// the level of [`compression`](TreePushOptions::compression), else the
    /// `[archive] zlib-level` of the `config` of the bucket, 6 if the
    /// `config` has none, clamped to 1 to 9.
    ///
    /// The push hashes each file again as it reads it. If a file changed
    /// after the hash pass, the read fails at the end of the file, before
    /// the last part of the object goes up. The push then uploads no commit
    /// object and writes no ref, and a multipart upload of the object is
    /// aborted.
    ///
    /// # Progress
    ///
    /// The scan sets the phases `Scanning` and `Hashing`. The push sets the
    /// phase `Uploading` for the uploads of the objects, and `Committing`
    /// for the write of the ref. Each object that it uploads, the commit
    /// object included, counts as needed and as sent. The payload size of a
    /// file counts as content after the upload of its `.filez`.
    ///
    /// # Failure states
    ///
    /// The failure states are those of `Repo::push_to_bucket`. A failure
    /// before the ref write changes no ref, the objects that went up stay,
    /// and a run again uploads only the rest. The push releases the lock
    /// and returns the first error, unless the failure is
    /// [`Error::BucketLockLost`] or [`Error::BucketLocked`]. The holder of a
    /// broken lock is reported on success alone.
    ///
    /// # Result
    ///
    /// [`PushOutcome::commit`] holds the new commit, and the outcome holds
    /// one ref outcome for the branch, also if the branch did not move. The
    /// statistics count the objects of the tree and the commit, the objects
    /// that the push uploaded, and the bytes that it uploaded.
    ///
    /// # Errors
    ///
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if `opts` names
    ///   tags. The push then sends no request.
    /// - The errors of [`scan_tree`], before a request.
    /// - The errors of [`BucketRepo::lock`].
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the bucket
    ///   repository has no `config`, or if the ref directory of the namespace
    ///   holds a name that is a directory of another name after the push.
    /// - [`Error::Remote`] with
    ///   [`RefDenied`](crate::remote::Error::RefDenied) if the branch is
    ///   `ostree-metadata` in `refs/heads/` of a bucket with a collection id.
    /// - [`Error::InvalidFormat`] for a malformed `config`, ref key, or ref
    ///   file, as `Repo::push_to_bucket` states, and if a ref of the
    ///   namespace or the parent names a commit that the bucket does not
    ///   hold. The push then uploads nothing.
    /// - [`Error::Remote`] with
    ///   [`LimitExceeded`](crate::remote::Error::LimitExceeded) if the commit
    ///   object is larger than [`MAX_METADATA_SIZE`]. The push then uploads
    ///   nothing.
    /// - [`Error::Remote`] with
    ///   [`ChecksumMismatch`](crate::remote::Error::ChecksumMismatch) if a
    ///   file changed after the hash pass, and with
    ///   [`Walk`](crate::remote::Error::Walk) if the open or a read of a file
    ///   fails.
    /// - [`Error::BucketLockLost`] if the check of the writer lock fails.
    /// - [`Error::Remote`] for an error of the bucket client, for example
    ///   [`S3`](crate::remote::Error::S3) for an error response.
    pub async fn push_tree(
        &self,
        root: &Path,
        opts: TreePushOptions,
        write: BucketWriteOptions,
    ) -> Result<BucketPushOutcome> {
        if !opts.tags.is_empty() {
            return Err(invalid(
                "a push to an s3:// address creates no tag, and the push names tags",
            ));
        }
        let scanned = scan_tree(root, opts).await?;
        let start = Instant::now();
        let lock = self.lock(LockOperation::Push, write.break_lock).await?;
        let broken_lock = lock.broken().cloned();
        let Uploaded { update, mut stats } = match self.upload_tree(&scanned, write.part_size).await
        {
            Ok(uploaded) => uploaded,
            Err(e) => return Err(fail(lock, e).await),
        };
        if let Some(progress) = &scanned.progress {
            progress.set_phase(PushPhase::Committing);
        }
        let updates = [update];
        if let Err(e) = write_bucket_refs(self, &lock, &[], &updates).await {
            return Err(fail(lock, e).await);
        }
        lock.release().await?;
        stats.elapsed = start.elapsed();
        let [update] = updates;
        Ok(BucketPushOutcome {
            outcome: PushOutcome {
                commit: Some(update.new),
                refs: vec![RefOutcome {
                    name: update.dst,
                    old: update.old,
                    new: Some(update.new),
                }],
                stats,
            },
            broken_lock,
        })
    }

    /// Runs the steps of a tree push from the read of the state of the
    /// bucket to the upload of the commit object.
    async fn upload_tree(&self, scanned: &ScannedTree, part: Option<u64>) -> Result<Uploaded> {
        let ScannedTree {
            model,
            commit: sc,
            collection,
            compression,
            progress,
            ..
        } = scanned;
        let BucketState {
            level,
            ns,
            dir,
            listing,
        } = read_state(self, collection.as_deref()).await?;
        let binding = match &ns {
            Namespace::Local { binding } => binding.as_deref(),
            Namespace::Mirror { id } => Some(id.as_str()),
        };

        // The ref checks, in the directory of the namespace.
        if matches!(ns, Namespace::Local { binding: Some(_) }) && sc.branch == OSTREE_METADATA_REF {
            return Err(Error::Remote(crate::remote::Error::RefDenied(format!(
                "ref '{}' holds the collection anchor commit of a repository with a collection \
                 id, and a tree push writes no anchor commit",
                sc.branch
            ))));
        }
        let tip = dir.get(&sc.branch).copied();
        let parent = if sc.orphan { None } else { tip };
        let mut updated = dir.clone();
        // The new commit is not known yet. Any value serves the prefix check.
        updated.insert(sc.branch.clone(), Checksum::from_bytes([0; 32]));
        check_prefixes(&updated)?;
        let holds = |commit: &Checksum| {
            listing
                .objects
                .contains_key(&ObjectName::new(*commit, ObjectType::Commit))
        };
        if let Some(absent) = dir
            .iter()
            .filter(|(name, _)| **name != sc.branch)
            .map(|(_, commit)| commit)
            .chain(parent.as_ref())
            .find(|commit| !holds(commit))
        {
            return Err(self.malformed(format!(
                "a ref names the commit {absent}, which the bucket does not hold"
            )));
        }

        // The commit.
        let timestamp = match sc.timestamp {
            Some(timestamp) => timestamp,
            None => clock()?,
        };
        let bytes = commit_bytes(sc, tip, timestamp, binding)?;
        if bytes.len() as u64 > MAX_METADATA_SIZE {
            return Err(Error::Remote(crate::remote::Error::LimitExceeded(format!(
                "the commit object is {} bytes, over the limit of {MAX_METADATA_SIZE}",
                bytes.len()
            ))));
        }
        let commit = Checksum::sha256(&bytes);

        // The objects of the tree that the bucket lacks.
        let names = model.object_names();
        let total = names.len() as u64 + 1;
        let upload: Vec<ObjectName> = names
            .into_iter()
            .filter(|name| !listing.objects.contains_key(name))
            .collect();
        let commit_name = ObjectName::new(commit, ObjectType::Commit);
        let send_commit = !listing.objects.contains_key(&commit_name);
        let needed = upload.len() as u64 + u64::from(send_commit);
        let progress = progress.as_ref();
        if let Some(progress) = progress {
            let content = model
                .content_size(&upload, Encoding::Raw)
                .await?
                .unwrap_or(0);
            progress.add_upload(needed, content);
            progress.set_phase(PushPhase::Uploading);
        }
        let level = match compression {
            Compression::Deflate { level } => *level,
            _ => level,
        };
        let counts = Counts::default();
        let compressors = CompressorPool::default();
        let uploads = Uploads {
            bucket: self,
            origin: Origin::Tree {
                model,
                level,
                compressors: &compressors,
            },
            listing: &listing,
            part,
            progress,
            counts: &counts,
        };
        uploads.all(upload.iter().copied().map(Job::Object)).await?;
        drop(upload);
        // The commit object goes up after each object of its tree.
        if send_commit {
            let len = bytes.len() as u64;
            self.bucket().put(&object_key(&commit_name), bytes).await?;
            counts.bytes.fetch_add(len, Ordering::Relaxed);
            counts.objects.fetch_add(1, Ordering::Relaxed);
            if let Some(progress) = progress {
                progress.object_uploaded();
            }
        }

        let sent = counts.objects.load(Ordering::Relaxed);
        let bytes = counts.bytes.load(Ordering::Relaxed);
        Ok(Uploaded {
            update: Update {
                key: ns.key(&sc.branch),
                dst: sc.branch.clone(),
                old: tip,
                new: commit,
            },
            stats: PushStats {
                objects_total: total,
                objects_needed: needed,
                objects_sent: sent,
                bytes_sent: bytes,
                payload_bytes: bytes,
                elapsed: Default::default(),
            },
        })
    }
}
