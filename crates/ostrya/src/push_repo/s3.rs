//! The push of commits from a repository to a bucket repository.
//!
//! The push writes the bucket repository with no session. It reads the
//! objects through the archive view of the local repository, so each local
//! mode gives the bytes of an `archive` repository. The view builds each
//! `.filez` at the `[archive] zlib-level` of the bucket. The `config` of the
//! bucket takes the role of the server of a session push: its collection id
//! and the bindings of the source commits select the namespace of the refs,
//! `refs/heads/` or `refs/mirrors/ID/`.
//!
//! The writes go in this order: the tree objects, the composefs images, and
//! the detached metadata, then the commit objects and the ref files. The push
//! writes no `summary` and no `summary.sig`. A commit object goes up only
//! after each object of its tree, so a commit object in the bucket has its
//! whole tree in the bucket at each point of a run, also of a run that
//! failed. A run again lists the objects and uploads only the rest, and it
//! walks no tree of a commit that the bucket holds.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use futures_io::AsyncRead;
use futures_lite::AsyncReadExt;
use futures_lite::future::zip;
use futures_lite::io::Cursor;
use ostrya_core::{Checksum, DeflateReader, ObjectName, ObjectType, is_ref_name};
use sha2::{Digest, Sha256};

use super::invalid;
use super::negotiate::{Local, Plan, RepoPushOptions, check_bindings, offered_history};
use super::source::RepoSource;
use crate::access::{AuthItem, ClientAccess, ReadAccess};
use crate::archive::{ArchiveAnswer, ArchiveView};
use crate::bucket::{
    BucketPushOutcome, BucketRepo, LockOperation, ObjectListing, WriterLock, check_prefixes,
    object_key,
};
use crate::error::{Error, Result};
use crate::hashing::VerifyingReader;
use crate::pull::drive::Slots;
use crate::remote::s3::{S3Endpoint, part_size};
use crate::remote::tree::TreeModel;
use crate::remote::{
    Compression, Encoding, ObjectData, ObjectSource, PushOutcome, PushPhase, PushProgress,
    PushStats, RefOutcome,
};
use crate::repo::Repo;
use crate::write::archive_level;

/// The namespace of the refs that a push writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Namespace {
    /// `refs/heads/`. `binding` is the collection id of the bucket
    /// repository, the id that a bound commit must name.
    Local { binding: Option<String> },
    /// `refs/mirrors/ID/`.
    Mirror { id: String },
}

impl Namespace {
    /// Returns the ref directory of the namespace, `refs/heads/` or
    /// `refs/mirrors/ID/`.
    pub(super) fn dir(&self) -> String {
        match self {
            Namespace::Local { .. } => "refs/heads/".to_owned(),
            Namespace::Mirror { id } => format!("refs/mirrors/{id}/"),
        }
    }

    /// Returns the bucket key of the ref `name` of the namespace.
    pub(super) fn key(&self, name: &str) -> String {
        format!("{}{name}", self.dir())
    }
}

/// Returns the namespace of a push whose source commits name the collection
/// `collection`, to a bucket repository with the collection id `bucket_id`.
///
/// No collection, or the collection id of the bucket, gives the local refs.
/// Each other collection gives its mirror refs, also in a bucket with no
/// collection id.
fn namespace(collection: Option<&str>, bucket_id: Option<&str>) -> Namespace {
    match collection {
        Some(id) if Some(id) != bucket_id => Namespace::Mirror { id: id.to_owned() },
        _ => Namespace::Local {
            binding: bucket_id.map(str::to_owned),
        },
    }
}

/// The state of a bucket repository that a push reads under the writer
/// lock.
pub(super) struct BucketState {
    /// The DEFLATE level of each `.filez` that the push builds: the
    /// `[archive] zlib-level` of the `config`, 6 if it has none, clamped to 1
    /// to 9.
    pub(super) level: u8,
    /// The namespace of the push.
    pub(super) ns: Namespace,
    /// The refs of the ref directory of the namespace, by name.
    pub(super) dir: BTreeMap<String, Checksum>,
    /// The objects of the bucket.
    pub(super) listing: ObjectListing,
}

/// Reads the state of `bucket` for a push whose commits name the collection
/// `collection`.
///
/// The call reads the `config` and selects the namespace. Then at the same
/// time it reads the ref files of the ref directory of the namespace, lists
/// `refs/mirrors/` of the collection id of the bucket, and lists the
/// objects. It reads no ref file of another namespace.
///
/// # Errors
///
/// - [`Error::Remote`] with
///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the bucket
///   repository has no `config`.
/// - The errors of [`BucketRepo::read_config`], of
///   [`BucketRepo::read_ref_dir`], of [`BucketRepo::refuse_own_mirror_refs`],
///   and of [`BucketRepo::list_objects`].
pub(super) async fn read_state(
    bucket: &BucketRepo,
    collection: Option<&str>,
) -> Result<BucketState> {
    let Some(config) = bucket.read_config().await? else {
        return Err(invalid(format!(
            "the bucket repository {} has no config; init it first",
            bucket.address()
        )));
    };
    let level = archive_level(config.zlib_level()?);
    let bucket_id = config.collection_id();
    let ns = namespace(collection, bucket_id);
    // The push reads the ref directory of its namespace alone, and lists
    // `refs/mirrors/` of the collection id of the bucket.
    let own_mirrors = async {
        match bucket_id {
            Some(own) => bucket.refuse_own_mirror_refs(own).await,
            None => Ok(()),
        }
    };
    let ((dir, own_mirrors), listing) = zip(
        zip(bucket.read_ref_dir(&ns.dir()), own_mirrors),
        bucket.list_objects(),
    )
    .await;
    own_mirrors?;
    Ok(BucketState {
        level,
        ns,
        dir: dir?,
        listing: listing?,
    })
}

/// Refuses the options that a push to a bucket repository cannot carry:
/// tags, a compression, and a delete refspec `:DST`.
fn refuse_options(opts: &RepoPushOptions) -> Result<()> {
    if !opts.tags.is_empty() {
        return Err(invalid(
            "a push to an s3:// address creates no tag, and the push names tags",
        ));
    }
    if opts.compression != Compression::None {
        return Err(invalid(
            "a push to an s3:// address uploads each object in archive form, and the push \
             names a compression",
        ));
    }
    if let Some(spec) = opts.refspecs.iter().find(|spec| {
        spec.rsplit_once(':')
            .is_some_and(|(src, dst)| src.is_empty() && !dst.is_empty())
    }) {
        return Err(invalid(format!(
            "a push to an s3:// address deletes no ref, and the refspec '{spec}' is a delete"
        )));
    }
    Ok(())
}

/// One ref update of a push, after the checks against the bucket.
pub(super) struct Update {
    /// The `DST` of the refspec, or the branch of a tree push.
    pub(super) dst: String,
    /// The bucket key of the ref.
    pub(super) key: String,
    /// The commit of the ref in the bucket before the push.
    pub(super) old: Option<Checksum>,
    /// The commit that the ref takes.
    pub(super) new: Checksum,
}

/// The work of a push before the ref writes, and its counts.
struct Uploaded {
    /// The updates, in the order of the refspecs.
    updates: Vec<Update>,
    stats: PushStats,
}

/// The counts of the uploads of one push.
#[derive(Default)]
pub(super) struct Counts {
    /// The bytes of each object body and detached metadata that the push
    /// read and uploaded.
    pub(super) bytes: AtomicU64,
    /// The objects other than composefs images that the push uploaded.
    pub(super) objects: AtomicU64,
}

/// Methods that push commits to a bucket repository.
impl Repo {
    /// Pushes the commits of `opts.refspecs` to the bucket repository of
    /// `endpoint`.
    ///
    /// [`Repo::push`] with an `Endpoint::S3` calls this method, and drops
    /// [`BucketPushOutcome::broken_lock`]. The push needs the features
    /// `push` and `s3`.
    ///
    /// The bucket repository needs a `config`, which
    /// [`BucketRepo::init`] writes. Each object goes up in archive form: the
    /// stored file of an `archive` repository, and for each other mode a
    /// `.filez` that the push builds at the `[archive] zlib-level` of the
    /// `config` of the bucket, 6 if the `config` has none, clamped to 1 to 9.
    /// The push trusts the listing of the objects of the bucket alone: it
    /// uploads each object of its walk that the listing does not hold.
    ///
    /// The push writes no `summary` and no `summary.sig`. A `summary` and a
    /// `summary.sig` that the bucket holds stay as they are, so they do not
    /// show the refs that the push writes. A pull of a named ref reads the
    /// ref file of the bucket when the summary does not list the ref.
    ///
    /// # Steps
    ///
    /// 1. The push refuses the options that it cannot carry, and runs the
    ///    checks and the commit walk of [`Repo::push_over_stream`] with no
    ///    request: the depth, the collection, the refspecs, the source
    ///    commits, and the bindings. It holds the repository lock shared
    ///    until it returns.
    /// 2. It takes the writer lock of the bucket repository for
    ///    [`LockOperation::Push`], with
    ///    [`break_lock`](RepoPushOptions::break_lock).
    /// 3. It reads the `config` and selects the namespace. Then at the same
    ///    time it reads the ref files of the ref directory of the namespace,
    ///    lists `refs/mirrors/` of the collection id of the bucket, and lists
    ///    the objects. It reads no ref file of another namespace. It checks
    ///    the bindings. For each ref, the tip of the ref in the bucket must
    ///    be an ancestor of the new commit in the local repository, unless
    ///    [`force`](RepoPushOptions::force) is set. A tip that the local
    ///    repository does not hold, or marks partial, is no ancestor.
    /// 4. It walks the commits to offer: each source commit and its history,
    ///    as [`Repo::push_over_stream`] offers them, with the tip of the ref
    ///    in the bucket in the role of the server tip. It walks the tree of
    ///    each offered commit that the listing lacks, and adds the composefs
    ///    image of each source commit and of each walked commit that the
    ///    local repository holds. It walks no tree of a commit that the
    ///    listing holds: each writer uploads a commit object after its tree,
    ///    so a commit object in the bucket has its whole tree in the bucket.
    /// 5. It uploads each tree object and image that the listing lacks, and
    ///    the detached metadata of each commit that the bucket lacks and of
    ///    each source commit, after
    ///    [`detached_metadata_filter`](RepoPushOptions::detached_metadata_filter),
    ///    at most `max_outstanding` uploads at a time. It skips a
    ///    `.commitmeta` that the bucket holds with the same bytes, and a
    ///    commit with no detached metadata after the filter, which leaves the
    ///    bucket copy.
    /// 6. It uploads each commit object that the bucket lacks.
    /// 7. It checks the writer lock, then writes each ref file that changes,
    ///    in the order of the refspecs.
    /// 8. It releases the writer lock.
    ///
    /// # Namespace
    ///
    /// The namespace is [`collection`](RepoPushOptions::collection), else
    /// the `ostree.collection-binding` of the source commits, else none. No
    /// namespace, or the `[core] collection-id` of the bucket, writes
    /// `refs/heads/DST`. Each other collection writes
    /// `refs/mirrors/ID/DST`, also in a bucket with no collection id. A bound
    /// commit must name the id of the namespace, and for `refs/heads/` the
    /// collection id of the bucket. A commit with no binding goes to
    /// `refs/heads/` alone. The fast-forward rule and `force` apply to each
    /// ref in its own namespace.
    ///
    /// # Progress
    ///
    /// The push sets the phase `Scanning` for the checks and the walk,
    /// `Uploading` for the uploads of the objects, and `Committing` for the
    /// writes of the refs. The objects that it
    /// uploads, other than the composefs images, count as needed and as
    /// sent. The content of an `archive` repository counts with the stored
    /// bytes of each `.filez` as the push reads them. In each other mode,
    /// the payload size of a file counts after the upload of its `.filez`.
    /// With a progress handle, a pass over the files to upload gives the
    /// total of the content before the uploads. A failure of that pass
    /// gives no total, and the push goes on.
    ///
    /// # Failure states
    ///
    /// - A failure before the ref writes changes no ref. The objects that
    ///   went up stay, and a run again uploads only the rest. The push releases the lock, and returns the first error. An
    ///   error of the release is dropped: the lock then stays, and the next
    ///   writer names it. When one upload fails, the push starts no new
    ///   upload and waits for the uploads in flight. A failed upload aborts
    ///   its own multipart upload.
    /// - A failure of a ref write leaves some refs moved. A run again finds
    ///   the moved refs at their new commits, and writes the other refs.
    /// - A check of the lock that finds another lock, or no lock, stops the
    ///   push before its next write with
    ///   [`Error::BucketLockLost`], and the push releases no lock.
    /// - A failure of the release, or a crash, leaves the lock. The refs are
    ///   written at that point. The next writer gets
    ///   [`Error::BucketLocked`], and a push with `break_lock` removes the
    ///   lock and names its holder in [`BucketPushOutcome::broken_lock`].
    ///   The holder is reported on success alone: a push that breaks the
    ///   lock and then fails returns its error with no holder.
    /// - A crash during a multipart upload leaves the upload open, and it
    ///   holds storage until a lifecycle rule of the bucket aborts it.
    ///
    /// # Result
    ///
    /// The outcome holds one ref outcome for each refspec, in order, also
    /// for a ref that did not move. The statistics count the commits that
    /// the push offered and the tree objects of its walk, the objects that
    /// it uploaded, and the bytes of each object and detached metadata that
    /// it uploaded. A composefs image counts in the bytes alone.
    ///
    /// # Errors
    ///
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if `opts` names
    ///   tags, a compression, or a delete refspec, or a `DST` that is no ref
    ///   name. The push then sends no request.
    /// - The errors of the checks and of the commit walk of
    ///   [`Repo::push_over_stream`], before a request.
    /// - The errors of [`BucketRepo::lock`].
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the bucket
    ///   repository has no `config`, or if the ref directory of the namespace
    ///   holds a name that is a directory of another name after the push.
    /// - [`Error::InvalidFormat`] if the `config` of the bucket is malformed,
    ///   states a mode other than `archive-z2` and `archive`, holds a
    ///   `tombstone-commits` or `indexed-deltas` that is no boolean, or holds
    ///   a `zlib-level` that is no integer, if a key under the ref directory
    ///   of the namespace is no ref name, if the bucket holds
    ///   `refs/mirrors/ID/` of its own collection id, if a ref file of the
    ///   namespace is malformed, or if a ref of the namespace names a commit
    ///   that the bucket does not hold. The push then uploads
    ///   nothing. The push does not check the keys and the ref files of the
    ///   other namespaces.
    /// - [`Error::Remote`] with
    ///   [`BindingMismatch`](crate::remote::Error::BindingMismatch) if the
    ///   binding of a source commit does not agree with the namespace.
    /// - [`Error::Remote`] with
    ///   [`NonFastForward`](crate::remote::Error::NonFastForward) if a ref
    ///   update is not a fast-forward and `force` is not set.
    /// - [`Error::ObjectNotFound`] if the local repository lacks an object of
    ///   the walk.
    /// - [`Error::BucketLockLost`] if a check of the writer lock fails.
    /// - [`Error::Remote`] for an error of the bucket client, for example
    ///   [`S3`](crate::remote::Error::S3) for an error response.
    /// - [`Error::Io`] and [`Error::Core`] for a failed read of the local
    ///   repository.
    pub async fn push_to_bucket(
        &self,
        endpoint: S3Endpoint,
        opts: RepoPushOptions,
    ) -> Result<BucketPushOutcome> {
        refuse_options(&opts)?;
        let bucket = BucketRepo::open(&endpoint).await?;
        let mut plan = self.plan_push(&opts).await?;
        if let Some(target) = plan.targets.iter().find(|t| !is_ref_name(&t.dst)) {
            return Err(invalid(format!(
                "a push to an s3:// address writes the ref file of each destination, and '{}' \
                 is no ref name",
                target.dst
            )));
        }
        let progress = opts.progress.as_ref();
        if let Some(progress) = progress {
            progress.set_phase(PushPhase::Scanning);
        }
        let start = Instant::now();
        let lock = bucket.lock(LockOperation::Push, opts.break_lock).await?;
        let broken_lock = lock.broken().cloned();
        let Uploaded { updates, mut stats } =
            match self.upload_to_bucket(&bucket, &mut plan, &opts).await {
                Ok(uploaded) => uploaded,
                Err(e) => return Err(fail(lock, e).await),
            };
        if let Some(progress) = progress {
            progress.set_phase(PushPhase::Committing);
        }
        if let Err(e) = write_bucket_refs(&bucket, &lock, &updates).await {
            return Err(fail(lock, e).await);
        }
        lock.release().await?;
        stats.elapsed = start.elapsed();
        let refs = updates
            .into_iter()
            .map(|update| RefOutcome {
                name: update.dst,
                old: update.old,
                new: Some(update.new),
            })
            .collect();
        Ok(BucketPushOutcome {
            outcome: PushOutcome {
                commit: None,
                refs,
                stats,
            },
            broken_lock,
        })
    }

    /// Runs the steps of a push to `bucket` from the read of its state to
    /// the upload of the commit objects.
    async fn upload_to_bucket(
        &self,
        bucket: &BucketRepo,
        plan: &mut Plan,
        opts: &RepoPushOptions,
    ) -> Result<Uploaded> {
        let BucketState {
            level,
            ns,
            dir,
            listing,
        } = read_state(bucket, plan.collection.as_deref()).await?;

        // The bindings.
        match &ns {
            Namespace::Local { binding } => {
                check_bindings(None, binding.as_deref(), &plan.sources)?
            }
            Namespace::Mirror { id } => check_bindings(Some(id), Some(id), &plan.sources)?,
        }

        // The ref checks, in the directory of the namespace.
        let mut updated = dir.clone();
        for target in &plan.targets {
            let commit = target.commit.expect("a push to a bucket refuses a delete");
            updated.insert(target.dst.clone(), commit);
        }
        check_prefixes(&updated)?;
        let mut updates = Vec::with_capacity(plan.targets.len());
        for target in &plan.targets {
            let new = target.commit.expect("a push to a bucket refuses a delete");
            let old = dir.get(&target.dst).copied();
            let key = ns.key(&target.dst);
            if let Some(tip) = old
                && tip != new
                && !opts.force
                && !self.fast_forward(new, tip, &mut plan.commits).await?
            {
                return Err(Error::Remote(crate::remote::Error::NonFastForward(
                    format!(
                        "ref '{key}' is at {tip}, which is not an ancestor of {new} in the \
                         local repository"
                    ),
                )));
            }
            updates.push(Update {
                dst: target.dst.clone(),
                key,
                old,
                new,
            });
        }

        let walk = self.bucket_walk(plan, &updates, &listing, opts).await?;
        // The walk is the last reader of the commits of the plan.
        drop(std::mem::take(&mut plan.commits));
        // Each ref of the new ref set of the namespace names a commit that
        // the bucket holds or that the push uploads, so a ref of the
        // namespace that names an absent commit refuses the push before its
        // first upload.
        if let Some(absent) = updated.values().find(|commit| {
            !walk.missing.contains(commit)
                && !listing
                    .objects
                    .contains_key(&ObjectName::new(**commit, ObjectType::Commit))
        }) {
            return Err(bucket.malformed(format!(
                "a ref names the commit {absent}, which the bucket does not hold"
            )));
        }
        let counts = Counts::default();
        let progress = opts.progress.as_ref();
        let (sizes, content) = self.content_sizes(&walk.upload, opts).await;
        let counted = |names: &[ObjectName]| -> u64 {
            names
                .iter()
                .filter(|name| name.ty != ObjectType::ComposefsImage)
                .count() as u64
        };
        let needed = counted(&walk.upload) + walk.missing_commits.len() as u64;
        if let Some(progress) = progress {
            progress.add_upload(needed, content);
            progress.set_phase(PushPhase::Uploading);
        }

        let view = ArchiveView::with_zlib_level(self.clone(), level);
        let access = ReadAccess::new(
            Arc::new(ClientAccess::implicit(self.config().collection_id())),
            AuthItem::Anonymous,
            None,
        );
        let source = RepoSource::new(self.clone(), opts.detached_metadata_filter.clone());
        let uploads = Uploads {
            bucket,
            origin: Origin::Repo {
                repo: self,
                view: &view,
                access: &access,
                source: &source,
                sizes: &sizes,
            },
            listing: &listing,
            part: opts.part_size,
            progress,
            counts: &counts,
        };
        // The tree objects, the images, and the detached metadata share one
        // pool of uploads. Each commit object goes up after the pool ends.
        uploads
            .all(
                walk.upload
                    .iter()
                    .copied()
                    .map(Job::Object)
                    .chain(walk.metadata.iter().copied().map(Job::Metadata)),
            )
            .await?;
        uploads
            .all(
                walk.missing_commits
                    .iter()
                    .map(|commit| Job::Object(ObjectName::new(*commit, ObjectType::Commit))),
            )
            .await?;

        let sent = counts.objects.load(Ordering::Relaxed);
        let bytes = counts.bytes.load(Ordering::Relaxed);
        Ok(Uploaded {
            updates,
            stats: PushStats {
                objects_total: walk.offered as u64 + walk.tree_objects as u64,
                objects_needed: needed,
                objects_sent: sent,
                bytes_sent: bytes,
                payload_bytes: bytes,
                elapsed: Default::default(),
            },
        })
    }

    /// Returns the payload size of each file of `upload` whose `.filez` the
    /// push builds, and the total of the content for the progress.
    ///
    /// A `.filez` that the push builds takes its part size from the size of
    /// its payload, so the pass reads the size of each file of a repository
    /// of a mode other than `archive`, unless the caller sets the part size.
    /// The total needs a progress handle. In an `archive` repository it is
    /// the sum of the stored sizes. A failure of the pass gives no sizes and
    /// a total of zero, and the push goes on: each upload reads the size of
    /// its own payload, and an upload of an absent object fails.
    async fn content_sizes(
        &self,
        upload: &[ObjectName],
        opts: &RepoPushOptions,
    ) -> (HashMap<Checksum, u64>, u64) {
        let archive = self.mode().is_archive();
        let builds = !archive && opts.part_size.is_none();
        if opts.progress.is_none() && !builds {
            return (HashMap::new(), 0);
        }
        let files: Vec<Checksum> = upload
            .iter()
            .filter(|name| name.ty == ObjectType::File)
            .map(|name| name.checksum)
            .collect();
        let repo = self.clone();
        if archive {
            let total = ostrya_rt::unblock(move || repo.content_size_blocking(&files, true)).await;
            return (HashMap::new(), total.unwrap_or(0));
        }
        let sizes = ostrya_rt::unblock(move || -> Result<HashMap<Checksum, u64>> {
            files
                .iter()
                .map(|file| Ok((*file, repo.object_content_size_blocking(file, false)?)))
                .collect()
        })
        .await
        .unwrap_or_default();
        let total = sizes
            .values()
            .fold(0u64, |sum, size| sum.saturating_add(*size));
        (sizes, total)
    }

    /// Returns the commits and the objects of a push to a bucket repository
    /// whose listing is `listing`.
    ///
    /// The walk reads the tree of each offered commit that the listing
    /// lacks. A commit object in the bucket has its whole tree in the
    /// bucket, so the walk reads no tree of a commit that the listing holds.
    async fn bucket_walk(
        &self,
        plan: &mut Plan,
        updates: &[Update],
        listing: &ObjectListing,
        opts: &RepoPushOptions,
    ) -> Result<Walk> {
        let holds = |checksum: &Checksum, ty: ObjectType| {
            listing
                .objects
                .contains_key(&ObjectName::new(*checksum, ty))
        };
        // The commits to offer: each source commit and its history, cut at
        // the tip of the ref in the bucket.
        let chains = std::mem::take(&mut plan.chains);
        let mut offered: Vec<Checksum> = Vec::new();
        let mut seen = HashSet::new();
        for ((target, chain), update) in plan.targets.iter().zip(&chains).zip(updates) {
            let source = target.commit.expect("a push to a bucket refuses a delete");
            let history = offered_history(opts.depth, update.old, chain);
            for commit in std::iter::once(&source).chain(history) {
                if seen.insert(*commit) {
                    offered.push(*commit);
                }
            }
        }
        drop(chains);
        let missing_commits: Vec<Checksum> = offered
            .iter()
            .filter(|commit| !holds(commit, ObjectType::Commit))
            .copied()
            .collect();
        let missing: HashSet<Checksum> = missing_commits.iter().copied().collect();
        let mut seen = HashSet::new();
        let mut tree_names = Vec::new();
        for commit in &missing_commits {
            let Local::Held(link) = plan.commits[commit] else {
                unreachable!("an offered commit is held");
            };
            self.collect_tree_strict(
                link.root_dirtree,
                link.root_dirmeta,
                &mut seen,
                &mut tree_names,
            )
            .await?;
        }
        drop(seen);
        let tree_objects = tree_names.len();
        // The composefs image of each walked commit and of each source
        // commit. A source commit that the bucket holds can have an image
        // that the local repository made after the commit went up.
        let repo = self.clone();
        let images_of: Vec<Checksum> = missing_commits
            .iter()
            .copied()
            .chain(
                plan.sources
                    .iter()
                    .map(|(c, _)| *c)
                    .filter(|c| !missing.contains(c)),
            )
            .collect();
        let images = ostrya_rt::unblock(move || -> Result<Vec<ObjectName>> {
            let mut images = Vec::new();
            for commit in images_of {
                if repo.has_object_blocking(ObjectType::ComposefsImage, &commit)? {
                    images.push(ObjectName::new(commit, ObjectType::ComposefsImage));
                }
            }
            Ok(images)
        })
        .await?;
        tree_names.extend(images);
        let upload = tree_names
            .into_iter()
            .filter(|name| !listing.objects.contains_key(name))
            .collect();
        // The detached metadata of each commit that the push uploads, then of
        // each source commit, each once.
        let mut metadata = missing_commits.clone();
        metadata.extend(
            plan.sources
                .iter()
                .map(|(c, _)| *c)
                .filter(|c| !missing.contains(c)),
        );
        Ok(Walk {
            offered: offered.len(),
            missing_commits,
            missing,
            tree_objects,
            upload,
            metadata,
        })
    }

    /// Returns `true` if the local repository holds `tip` on the parent
    /// chain of `new`.
    ///
    /// The walk reads the chain with no depth limit. It stops with `false`
    /// at a commit that the local repository does not hold or marks
    /// partial, and at the root.
    async fn fast_forward(
        &self,
        new: Checksum,
        tip: Checksum,
        commits: &mut HashMap<Checksum, Local>,
    ) -> Result<bool> {
        let mut next = new;
        loop {
            let Local::Held(link) = self.history_commit(&next, commits).await? else {
                return Ok(false);
            };
            if next == tip {
                return Ok(true);
            }
            match link.parent {
                Some(parent) => next = parent,
                None => return Ok(false),
            }
        }
    }
}

/// The commits and the objects of a push to a bucket repository.
struct Walk {
    /// The number of commits that the push offered.
    offered: usize,
    /// The offered commits that the listing lacks, in the order of the
    /// offer.
    missing_commits: Vec<Checksum>,
    /// The commits of `missing_commits`, for a lookup.
    missing: HashSet<Checksum>,
    /// The number of tree objects of the walk.
    tree_objects: usize,
    /// The tree objects and the composefs images that the listing lacks.
    upload: Vec<ObjectName>,
    /// The commits whose detached metadata the push uploads: each missing
    /// commit, then each source commit, each once.
    metadata: Vec<Checksum>,
}

/// Checks the writer lock, then writes the ref file of each update that
/// changes a ref, in order.
pub(super) async fn write_bucket_refs(
    bucket: &BucketRepo,
    lock: &WriterLock<'_>,
    updates: &[Update],
) -> Result<()> {
    lock.check().await?;
    for update in updates {
        if update.old == Some(update.new) {
            continue;
        }
        bucket
            .bucket()
            .put(
                &update.key,
                format!("{}\n", update.new.to_hex()).into_bytes(),
            )
            .await?;
    }
    Ok(())
}

/// Returns the error of a push that failed while it held `lock`.
///
/// The call releases the lock and drops an error of the release, unless the
/// failure is a lost lock or a lock of another writer.
pub(super) async fn fail(lock: WriterLock<'_>, e: Error) -> Error {
    if !matches!(e, Error::BucketLockLost { .. } | Error::BucketLocked { .. }) {
        let _ = lock.release().await;
    }
    e
}

/// One upload of a push.
#[derive(Clone, Copy)]
pub(super) enum Job {
    /// An object, as a stream.
    Object(ObjectName),
    /// The detached metadata of a commit.
    Metadata(Checksum),
}

/// The uploads of the objects of one push.
pub(super) struct Uploads<'a> {
    pub(super) bucket: &'a BucketRepo,
    /// The source of the objects.
    pub(super) origin: Origin<'a>,
    /// The listing of the objects of the bucket before the uploads.
    pub(super) listing: &'a ObjectListing,
    /// The part size of the caller, or `None` for the part size rule.
    pub(super) part: Option<u64>,
    pub(super) progress: Option<&'a PushProgress>,
    pub(super) counts: &'a Counts,
}

/// The source of the objects of a push to a bucket repository.
pub(super) enum Origin<'a> {
    /// A local repository, through its archive view.
    Repo {
        repo: &'a Repo,
        view: &'a ArchiveView,
        access: &'a ReadAccess,
        /// The source of the detached metadata, with the filter of the push.
        source: &'a RepoSource,
        /// The payload size of each file whose `.filez` the push builds, if
        /// the pass over the files read it.
        sizes: &'a HashMap<Checksum, u64>,
    },
    /// The model of a local directory, whose `.filez` objects the push
    /// builds at `level` with the compressors of `compressors`.
    Tree {
        model: &'a TreeModel,
        level: u8,
        compressors: &'a CompressorPool,
    },
}

/// The body of one object upload.
struct Body<'a> {
    /// The number of bytes of the body, if it is known.
    len: Option<u64>,
    body: BodyData<'a>,
    /// The payload size of a file whose `.filez` the push builds, which
    /// counts as content after the upload, if it is known.
    payload: Option<u64>,
    /// `true` if the bytes of the body count as content as the push reads
    /// them: the stored `.filez` of an `archive` repository.
    stored_content: bool,
}

/// The bytes of one object upload.
enum BodyData<'a> {
    /// A stream.
    Stream(Box<dyn AsyncRead + Unpin + Send + 'a>),
    /// Bytes in memory: a dirtree or a dirmeta object of a tree push.
    Bytes(Vec<u8>),
}

/// The raw-DEFLATE compressor of the payload of one file of a tree push.
type FileDeflate = DeflateReader<Box<dyn AsyncRead + Unpin + Send>>;

/// The compressors of a tree push that no upload body holds.
///
/// A body leases one compressor, and gives it back when the body drops. At
/// most `max_outstanding` bodies exist at a time, so the pool holds at most
/// that many compressors.
#[derive(Default)]
pub(super) struct CompressorPool {
    idle: Mutex<Vec<FileDeflate>>,
}

impl CompressorPool {
    /// Leases a compressor over `source` at `level`.
    ///
    /// The lease reuses an idle compressor if one is there.
    fn lease(&self, source: Box<dyn AsyncRead + Unpin + Send>, level: u8) -> Leased<'_> {
        let idle = self.idle.lock().expect("tree push compressor mutex").pop();
        let reader = match idle {
            Some(mut reader) => {
                reader.reset(source, level);
                reader
            }
            None => DeflateReader::new(source, level),
        };
        Leased {
            reader: Some(reader),
            pool: self,
        }
    }
}

/// A compressor that one upload body holds.
struct Leased<'a> {
    reader: Option<FileDeflate>,
    pool: &'a CompressorPool,
}

impl AsyncRead for Leased<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let reader = self.reader.as_mut().expect("a lease holds its compressor");
        Pin::new(reader).poll_read(cx, buf)
    }
}

impl Drop for Leased<'_> {
    fn drop(&mut self) {
        if let Some(mut reader) = self.reader.take() {
            // The file closes now. The compressor and its buffers stay for
            // the next body.
            *reader.get_mut() = Box::new(futures_lite::io::empty());
            self.pool
                .idle
                .lock()
                .expect("tree push compressor mutex")
                .push(reader);
        }
    }
}

impl Uploads<'_> {
    /// Runs each upload of `jobs`, at most `max_outstanding` at a time.
    ///
    /// After the first failure, the call starts no new upload, waits for
    /// the uploads in flight, and returns the first error.
    pub(super) async fn all(&self, jobs: impl Iterator<Item = Job>) -> Result<()> {
        let mut slots = Slots::new(self.bucket.max_outstanding());
        let mut pending = jobs;
        let mut first = None;
        loop {
            while first.is_none()
                && slots.has_room()
                && let Some(job) = pending.next()
            {
                match job {
                    Job::Object(name) => slots.push(self.one(name)),
                    Job::Metadata(commit) => slots.push(self.metadata(commit)),
                }
            }
            match slots.next_ready().await {
                None => break,
                Some(Ok(())) => {}
                Some(Err(e)) => {
                    first.get_or_insert(e);
                }
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// Uploads the object `name` as a stream.
    async fn one(&self, name: ObjectName) -> Result<()> {
        let key = object_key(&name);
        let file = name.ty == ObjectType::File;
        let Body {
            len,
            body,
            payload,
            stored_content,
        } = match self.origin {
            Origin::Repo {
                repo,
                view,
                access,
                sizes,
                ..
            } => {
                self.repo_body(repo, view, access, sizes, &key, &name)
                    .await?
            }
            Origin::Tree {
                model,
                level,
                compressors,
            } => tree_body(model, level, compressors, &name).await?,
        };
        let part = match self.part {
            Some(part) => part,
            None => part_size(len.or(payload).unwrap_or(0))?,
        };
        let read = AtomicU64::new(0);
        let body = match body {
            // Bytes of at most one part go in one `PUT`, with no copy.
            BodyData::Bytes(bytes) if bytes.len() as u64 <= part => {
                let len = bytes.len() as u64;
                self.bucket.bucket().put(&key, bytes).await?;
                read.store(len, Ordering::Relaxed);
                None
            }
            BodyData::Bytes(bytes) => Some(Box::new(Cursor::new(bytes)) as Box<_>),
            BodyData::Stream(body) => Some(body),
        };
        if let Some(body) = body {
            let counted = Counted {
                inner: body,
                read: &read,
                progress: self.progress.filter(|_| file && stored_content),
            };
            let put = self.bucket.bucket().put_stream(&key, counted, part).await;
            if let (Err(e), Origin::Tree { model, .. }) = (&put, &self.origin)
                && let Some(e) = changed_file(model, &name, e)
            {
                return Err(e);
            }
            put?;
        }
        self.counts
            .bytes
            .fetch_add(read.load(Ordering::Relaxed), Ordering::Relaxed);
        if name.ty != ObjectType::ComposefsImage {
            self.counts.objects.fetch_add(1, Ordering::Relaxed);
            if let Some(progress) = self.progress {
                if let Some(payload) = payload.filter(|_| file) {
                    progress.add_content(payload);
                }
                progress.object_uploaded();
            }
        }
        Ok(())
    }

    /// Returns the body of the object `name` of a local repository, at the
    /// key `key`, from the archive view.
    async fn repo_body(
        &self,
        repo: &Repo,
        view: &ArchiveView,
        access: &ReadAccess,
        sizes: &HashMap<Checksum, u64>,
        key: &str,
        name: &ObjectName,
    ) -> Result<Body<'static>> {
        let missing = || Error::ObjectNotFound {
            checksum: name.checksum,
            ty: name.ty,
        };
        let (len, body) = match view.get(key, access).await? {
            ArchiveAnswer::Stream { len, body } => (len, body),
            ArchiveAnswer::NotFound | ArchiveAnswer::Refused => return Err(missing()),
            other => {
                return Err(Error::InvalidFormat(format!(
                    "the archive view gave {other:?} for the object {key}"
                )));
            }
        };
        // The view builds a `.filez` with no length. The payload size of the
        // file bounds the size of the `.filez`, and counts as content after
        // the upload.
        let built = len.is_none();
        let payload = match sizes.get(&name.checksum) {
            _ if !built => None,
            Some(size) => Some(*size),
            None if self.part.is_some() && self.progress.is_none() => None,
            None => {
                let repo = repo.clone();
                let checksum = name.checksum;
                Some(
                    ostrya_rt::unblock(move || repo.object_content_size_blocking(&checksum, false))
                        .await?,
                )
            }
        };
        Ok(Body {
            len,
            body: BodyData::Stream(body),
            payload,
            stored_content: !built,
        })
    }

    /// Uploads the detached metadata of `commit` if the bucket does not hold
    /// it with the same bytes.
    ///
    /// The bytes are the stored `.commitmeta` after the filter of the push.
    /// A commit with no detached metadata after the filter uploads nothing,
    /// and the bucket keeps its copy. The bytes go up when the listing does
    /// not hold the key, when the size in the listing differs, or when a
    /// read of the key gives other bytes.
    async fn metadata(&self, commit: Checksum) -> Result<()> {
        let Origin::Repo { source, .. } = self.origin else {
            unreachable!("a tree push uploads no detached metadata");
        };
        let Some(bytes) = source.detached_bytes(&commit).await? else {
            return Ok(());
        };
        let name = ObjectName::new(commit, ObjectType::CommitMeta);
        let key = object_key(&name);
        let len = bytes.len() as u64;
        let current = match self.listing.objects.get(&name) {
            Some(size) if *size == len => match self.bucket.bucket().get(&key, len).await {
                Ok(object) => object.map(|object| object.bytes),
                // A larger object holds other bytes.
                Err(crate::remote::Error::LimitExceeded(_)) => None,
                Err(e) => return Err(e.into()),
            },
            _ => None,
        };
        if current.as_deref() == Some(&bytes[..]) {
            return Ok(());
        }
        self.bucket.bucket().put(&key, bytes).await?;
        self.counts.bytes.fetch_add(len, Ordering::Relaxed);
        Ok(())
    }
}

/// Returns the body of the object `name` of the tree `model`.
///
/// A dirtree or a dirmeta object is its serialized bytes, in memory. A
/// symlink is the framed archive header alone. A regular file is the framed
/// archive header, then its payload in raw DEFLATE at `level`, through a
/// compressor of `compressors`. The payload goes through a reader that hashes
/// the header and the payload, and fails at the end of the payload if the
/// checksum is not that of `name`. So a file that changed after the hash pass
/// fails the upload before its last part goes up.
async fn tree_body<'a>(
    model: &TreeModel,
    level: u8,
    compressors: &'a CompressorPool,
    name: &ObjectName,
) -> Result<Body<'a>> {
    let data = model.open(name, Encoding::Raw).await?;
    let (header, size, payload) = match data {
        ObjectData::Content {
            header,
            size,
            payload,
        } => (header, size, payload),
        ObjectData::Encoded { mut reader, .. } => {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await?;
            return Ok(Body {
                len: Some(bytes.len() as u64),
                body: BodyData::Bytes(bytes),
                payload: None,
                stored_content: false,
            });
        }
    };
    let mut framed = Vec::new();
    header.write_framed_archive(size, &mut framed)?;
    let body: Box<dyn AsyncRead + Unpin + Send + 'a> = match payload {
        // A symlink is the archive header alone.
        None => Box::new(Cursor::new(framed)),
        Some(payload) => {
            let mut prefix = Vec::new();
            header.write_framed(&mut prefix)?;
            let mut hasher = Sha256::new();
            hasher.update(&prefix);
            drop(prefix);
            let verified = VerifyingReader::new(name.checksum, hasher, payload);
            Box::new(Cursor::new(framed).chain(compressors.lease(Box::new(verified), level)))
        }
    };
    Ok(Body {
        len: None,
        body: BodyData::Stream(body),
        payload: Some(size),
        stored_content: false,
    })
}

/// Returns the error of a failed upload of the file `name` of the tree
/// `model` when the failure is a read of the file, or `None` for another
/// failure.
///
/// A read that finds other bytes than the hash pass gives
/// [`ChecksumMismatch`](crate::remote::Error::ChecksumMismatch), and each
/// other failed read gives [`Walk`](crate::remote::Error::Walk). Each names
/// the path of the file.
fn changed_file(model: &TreeModel, name: &ObjectName, e: &crate::remote::Error) -> Option<Error> {
    let crate::remote::Error::Io(io) = e else {
        return None;
    };
    if name.ty != ObjectType::File {
        return None;
    }
    let path = model.source_path(name)?;
    let error = if io.kind() == std::io::ErrorKind::InvalidData {
        crate::remote::Error::ChecksumMismatch(format!(
            "the file {} changed after the hash pass: {io}",
            path.display()
        ))
    } else {
        crate::remote::Error::Walk {
            path,
            source: std::io::Error::new(io.kind(), io.to_string()),
        }
    };
    Some(Error::Remote(error))
}

/// A body that counts the bytes that it gives, and gives them to a progress
/// handle as content bytes.
struct Counted<'a> {
    inner: Box<dyn AsyncRead + Unpin + Send + 'a>,
    read: &'a AtomicU64,
    progress: Option<&'a PushProgress>,
}

impl AsyncRead for Counted<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = polled {
            self.read.fetch_add(n as u64, Ordering::Relaxed);
            if let Some(progress) = self.progress {
                progress.add_content(n as u64);
            }
        }
        polled
    }
}

#[cfg(test)]
mod tests {
    use ostrya_core::RepoMode;

    use super::super::test_repo::{Scratch, commit_tree};
    use super::*;

    #[test]
    fn the_namespace_comes_from_the_collection_and_the_bucket_id() {
        let a = Some("org.example.A");
        let b = Some("org.example.B");
        assert_eq!(namespace(None, None), Namespace::Local { binding: None });
        assert_eq!(
            namespace(None, a),
            Namespace::Local {
                binding: a.map(str::to_owned)
            }
        );
        assert_eq!(
            namespace(a, a),
            Namespace::Local {
                binding: a.map(str::to_owned)
            }
        );
        assert_eq!(
            namespace(b, a),
            Namespace::Mirror {
                id: "org.example.B".into()
            }
        );
        assert_eq!(
            namespace(b, None),
            Namespace::Mirror {
                id: "org.example.B".into()
            }
        );
        assert_eq!(namespace(None, None).key("a/b"), "refs/heads/a/b");
        assert_eq!(
            namespace(b, a).key("main"),
            "refs/mirrors/org.example.B/main"
        );
    }

    #[test]
    fn the_options_of_a_session_push_are_refused() {
        refuse_options(&RepoPushOptions {
            refspecs: vec!["main".into(), "origin:main:dst".into(), "a:b".into()],
            ..RepoPushOptions::default()
        })
        .unwrap();
        for (opts, needle) in [
            (
                RepoPushOptions {
                    tags: vec!["v1".into()],
                    ..RepoPushOptions::default()
                },
                "tags",
            ),
            (
                RepoPushOptions {
                    compression: Compression::Deflate { level: 6 },
                    ..RepoPushOptions::default()
                },
                "compression",
            ),
            (
                RepoPushOptions {
                    refspecs: vec!["main".into(), ":old".into()],
                    ..RepoPushOptions::default()
                },
                "':old' is a delete",
            ),
        ] {
            match refuse_options(&opts) {
                Err(Error::Remote(crate::remote::Error::InvalidInput(message))) => {
                    assert!(message.contains(needle), "{message}")
                }
                other => panic!("{needle}: {other:?}"),
            }
        }
    }

    /// The walk finds a tip on the parent chain, and stops at a partial
    /// commit, at an absent commit, and at the root.
    #[test]
    fn a_fast_forward_needs_the_tip_on_the_local_chain() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("bucket-ff");
            let repo = scratch.create(RepoMode::Archive).await;
            let c1 = commit_tree(&repo, &scratch, "main", None, b"1").await;
            let c2 = commit_tree(&repo, &scratch, "main", Some(c1), b"2").await;
            let c3 = commit_tree(&repo, &scratch, "main", Some(c2), b"3").await;
            let other = commit_tree(&repo, &scratch, "other", None, b"x").await;
            let mut commits = HashMap::new();
            assert!(repo.fast_forward(c3, c1, &mut commits).await.unwrap());
            assert!(repo.fast_forward(c3, c2, &mut commits).await.unwrap());
            assert!(!repo.fast_forward(c3, other, &mut commits).await.unwrap());
            assert!(!repo.fast_forward(c1, c3, &mut commits).await.unwrap());
            // A tip beyond a partial commit is no ancestor.
            std::fs::write(
                repo.path()
                    .join("state")
                    .join(format!("{}.commitpartial", c2.to_hex())),
                b"",
            )
            .unwrap();
            let mut commits = HashMap::new();
            assert!(!repo.fast_forward(c3, c1, &mut commits).await.unwrap());
            // A tip that the repository does not hold is no ancestor.
            let mut commits = HashMap::new();
            let absent = Checksum::from_bytes([9; 32]);
            assert!(!repo.fast_forward(c3, absent, &mut commits).await.unwrap());
        });
    }

    #[test]
    fn the_object_key_is_the_archive_path() {
        let name = ObjectName::new(Checksum::from_bytes([0xab; 32]), ObjectType::File);
        assert_eq!(
            object_key(&name),
            format!("objects/ab/{}.filez", "ab".repeat(31))
        );
    }
}
