//! The fsck of a bucket repository.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use futures_io::AsyncRead;
use futures_lite::AsyncReadExt;
use futures_lite::future::zip;
use ostrya_composefs::FsVerityHasher;
use ostrya_core::{
    Checksum, Commit, ContentHasher, DirMetaRef, DirTree, DirTreeRef, ObjectName, ObjectType,
};

use self::BucketFindingKind::{
    Config, Corrupt, Lock, Marker, Mismatch, Missing, Ref, Stray, Upload,
};
use super::listing::is_fanout_prefix;
use super::lock::{LOCK_KEY, LockHolder, LockOperation, WriterLock};
use super::state::{BucketRefs, PARTIAL_STATE_BYTE, RefKey, RefRead, marker_key, ref_key};
use super::summary::SuperblockKey;
use super::{BucketRepo, ObjectListing, each_slot, object_key, release_on_error};
use crate::deltagen::delta_name;
use crate::error::{Error, Result};
use crate::object::MAX_METADATA_SIZE;
use crate::pull::drive::Slots;
use crate::pull::http::{
    BoundedInput, check_stream_end, compressed_bound, payload_refusal, read_archive_header,
};
use crate::summary::{SUMMARY_READ_CAP, Summary};
use crate::verify::TrustedKeys;
use crate::write::{COPY_CHUNK, check_archive_payload};

/// The size of the chunks in which the run reads a composefs image: 64 KiB.
const IMAGE_CHUNK: usize = 64 * 1024;

/// The most ref keys that one summary note names. The note gives the count
/// of the others.
const MAX_NAMED_DIFFERENCES: usize = 10;

/// The size above which the run hashes and parses a metadata object on the
/// blocking pool: 1 MiB. A smaller object takes less time than a switch of
/// thread.
const UNBLOCK_SIZE: usize = 1024 * 1024;

/// The detail of a `Missing` finding on an object that the listing does not
/// hold.
const UNLISTED: &str = "the listing does not hold the object";

/// The options of [`BucketRepo::fsck`].
///
/// A caller sets the fields of [`default`](Default::default), because the
/// struct is `#[non_exhaustive]`. The default run reads the repository and
/// changes nothing.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct BucketFsckOptions {
    /// Repair the repository. This makes the run a writer, under the writer
    /// lock with the operation [`LockOperation::Fsck`].
    ///
    /// The run writes a partial-commit marker for each commit that reaches a
    /// tree object of a `Missing`, a `Mismatch`, or a `Corrupt` finding,
    /// deletes the marker of each commit whose tree it finds whole, and then
    /// deletes the object of each `Mismatch` and `Corrupt` finding.
    /// [`BucketRepo::fsck`] states the order. A bucket repository with no
    /// `config`, or with a `config` that breaks a rule, refuses the repair:
    /// the run then reads the repository and changes nothing.
    pub delete: bool,
    /// With [`delete`](BucketFsckOptions::delete) alone: remove the writer
    /// lock of another writer before the run takes its own, as
    /// [`BucketRepo::lock`] states.
    pub break_lock: bool,
    /// The keys that the signature of the summary must verify against, or
    /// `None` for a run that verifies no signature.
    ///
    /// [`PullTrust::summary_keys`](crate::verify::PullTrust::summary_keys)
    /// gives the keys of a remote, as a pull from the remote takes them.
    pub summary_keys: Option<TrustedKeys>,
}

/// The result of [`BucketRepo::fsck`].
///
/// A corrupt repository does not fail the call. The report holds each
/// finding, and [`has_errors`](BucketFsckReport::has_errors) tells if a
/// finding is an error.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BucketFsckReport {
    /// The number of objects in the listing of the 256 fan-out prefixes.
    pub objects_listed: u64,
    /// The number of commit objects that the run read and checked.
    pub commits_checked: u64,
    /// The number of tree objects and composefs images that the run read and
    /// checked, each one time.
    pub objects_checked: u64,
    /// The bytes of the object reads of the checks. A read again of an
    /// object after a failure in transit counts too.
    pub bytes_read: u64,
    /// The number of objects of the listing that no commit of the listing
    /// reaches. The run does not read them. A `.commitmeta` and a `.cfs` of a
    /// commit of the listing count as reached.
    pub objects_unreached: u64,
    /// The composefs images whose commit object is not in the listing, or
    /// whose commit object the repair deletes, sorted. The run does not
    /// check such an image, and it is not a finding.
    pub orphan_images: Vec<Checksum>,
    /// The commits that have a partial-commit marker
    /// `state/<checksum>.commitpartial` at the start of the run, sorted.
    pub commits_partial: Vec<Checksum>,
    /// The findings, sorted by key, then by kind.
    pub findings: Vec<BucketFinding>,
    /// The key of each object that the run deleted: the commit objects, then
    /// the tree objects, then the composefs images. The keys of each of the
    /// three groups are sorted.
    pub deleted: Vec<String>,
    /// Each commit object that the run deleted and that a ref names, with
    /// the key of each ref that names it, sorted by commit.
    ///
    /// Such a ref names a commit that the bucket does not hold. A push of the
    /// ref uploads the commit again.
    pub deleted_ref_targets: Vec<(Checksum, Vec<String>)>,
    /// Each commit for which the run wrote a partial-commit marker, with the
    /// key of each ref that names the commit, sorted by commit.
    pub marked_partial: Vec<(Checksum, Vec<String>)>,
    /// Each commit whose partial-commit marker the run deleted, because the
    /// run found its tree whole, sorted.
    pub cleared_partial: Vec<Checksum>,
    /// The holder of the lock that the break of the lock deleted, or `None`
    /// if the run deleted no lock.
    pub broken_lock: Option<LockHolder>,
}

impl BucketFsckReport {
    /// Returns `true` if a finding of the report is an error.
    ///
    /// A report with notes alone has no error.
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|finding| finding.error)
    }
}

/// One finding of [`BucketRepo::fsck`].
///
/// The [`Display`](std::fmt::Display) output is one line: the kind, the
/// key, and the detail, then `; in commits` and the commits, if the finding
/// names commits.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BucketFinding {
    /// The kind of the finding.
    pub kind: BucketFindingKind,
    /// `true` for an error, and `false` for a note.
    ///
    /// A `Summary` finding is an error if the summary does not parse, fails
    /// the check of its signature, or names a commit or a delta that the
    /// bucket does not hold. Each other `Summary` finding is a note. A
    /// `Missing` finding of a run without
    /// [`delete`](BucketFsckOptions::delete) is a note if the listing does
    /// not hold the object and a read after the listing finds it. A `Marker`,
    /// an `Upload`, and a `Lock` finding are notes. Each other finding is an
    /// error.
    pub error: bool,
    /// The key of the finding, relative to the prefix of the repository:
    /// `config`, a ref key, `summary`, `summary.sig`, a stray key, the key of
    /// an object, the key of a partial-commit marker, the key of an upload,
    /// or the key of the writer lock.
    pub key: String,
    /// The object of a `Missing`, a `Mismatch`, or a `Corrupt` finding.
    pub object: Option<ObjectName>,
    /// The commits of the listing that reach the object of a `Missing`, a
    /// `Mismatch`, or a `Corrupt` finding, sorted.
    ///
    /// The list is empty for a commit object. For a composefs image, it
    /// holds the commit of the image.
    pub commits: Vec<Checksum>,
    /// The reason, in words.
    pub detail: String,
}

impl std::fmt::Display for BucketFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.kind.as_str(),
            self.key.escape_debug(),
            self.detail
        )?;
        if !self.commits.is_empty() {
            let commits: Vec<String> = self.commits.iter().map(Checksum::to_hex).collect();
            write!(f, "; in commits {}", commits.join(", "))?;
        }
        Ok(())
    }
}

/// The kind of a [`BucketFinding`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum BucketFindingKind {
    /// The `config` is absent, or breaks a rule of a bucket repository.
    Config,
    /// A key under `refs/` that is no ref key, a ref file that does not
    /// parse or is gone at its read, a ref under `refs/mirrors/` of the own
    /// collection id, or a ref that names a commit that the bucket does not
    /// hold.
    Ref,
    /// The summary does not parse, fails the check of its signature, or
    /// differs from the ref files or the deltas of the bucket. Also a delta
    /// map of the bucket that the run cannot build, when the bucket holds a
    /// summary.
    Summary,
    /// A key under `objects/` that is no object key.
    Stray,
    /// An object of the tree of a commit is not in the listing, or is gone at
    /// its read.
    Missing,
    /// The bytes of an object do not have the checksum of its name, or the
    /// fs-verity digest of a composefs image is not the digest that its
    /// commit records.
    Mismatch,
    /// An object that does not parse, a `.filez` that does not inflate to
    /// its declared size, or a composefs image whose commit records no
    /// digest that the run can read.
    Corrupt,
    /// A partial-commit marker of a commit whose tree the run finds whole. A
    /// run with [`delete`](BucketFsckOptions::delete) deletes such a marker.
    Marker,
    /// An incomplete multipart upload.
    Upload,
    /// A writer lock that the run found.
    Lock,
}

impl BucketFindingKind {
    /// Returns the name of the kind: `config`, `ref`, `summary`, `stray`,
    /// `missing`, `mismatch`, `corrupt`, `marker`, `upload`, or `lock`.
    pub fn as_str(self) -> &'static str {
        match self {
            BucketFindingKind::Config => "config",
            BucketFindingKind::Ref => "ref",
            BucketFindingKind::Summary => "summary",
            BucketFindingKind::Stray => "stray",
            BucketFindingKind::Missing => "missing",
            BucketFindingKind::Mismatch => "mismatch",
            BucketFindingKind::Corrupt => "corrupt",
            BucketFindingKind::Marker => "marker",
            BucketFindingKind::Upload => "upload",
            BucketFindingKind::Lock => "lock",
        }
    }
}

impl std::fmt::Display for BucketFindingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The state of one run.
#[derive(Default)]
struct Run {
    report: BucketFsckReport,
    findings: Vec<BucketFinding>,
    /// The objects of the `Missing` findings that the listing does not hold.
    unlisted: HashSet<ObjectName>,
    /// `true` after the check of the lock before the first write of the
    /// repair.
    changed: bool,
}

impl Run {
    /// Records a finding with no object.
    fn add(&mut self, kind: BucketFindingKind, error: bool, key: &str, detail: String) {
        self.findings.push(BucketFinding {
            kind,
            error,
            key: key.to_owned(),
            object: None,
            commits: Vec::new(),
            detail,
        });
    }

    /// Records an error on the object `name`.
    fn object(&mut self, kind: BucketFindingKind, name: ObjectName, detail: String) {
        self.findings.push(BucketFinding {
            kind,
            error: true,
            key: object_key(&name),
            object: Some(name),
            commits: Vec::new(),
            detail,
        });
    }

    /// Records a `Missing` finding on the object `name`, which the listing
    /// does not hold.
    fn unlisted(&mut self, name: ObjectName) {
        self.object(Missing, name, UNLISTED.to_owned());
        self.unlisted.insert(name);
    }

    /// Records the finding on the metadata object `name`, whose bytes have
    /// the checksum `actual` and parse as the type of the name unless
    /// `parsed` gives the parse error.
    fn check_metadata<T, E: std::fmt::Display>(
        &mut self,
        name: ObjectName,
        actual: Checksum,
        parsed: &std::result::Result<T, E>,
    ) {
        let what = match name.ty {
            ObjectType::Commit => "a commit",
            ObjectType::DirTree => "a dirtree",
            _ => "a dirmeta",
        };
        match (actual == name.checksum, parsed) {
            (true, Ok(_)) => {}
            (true, Err(e)) => self.object(Corrupt, name, format!("does not parse as {what}: {e}")),
            (false, Ok(_)) => self.object(
                Mismatch,
                name,
                format!("the bytes have the checksum {actual}"),
            ),
            (false, Err(e)) => self.object(
                Mismatch,
                name,
                format!("the bytes have the checksum {actual}, and do not parse as {what}: {e}"),
            ),
        }
    }

    /// Returns the report, with the findings sorted.
    fn finish(self) -> BucketFsckReport {
        let Run {
            mut report,
            mut findings,
            ..
        } = self;
        findings.sort_by(|a, b| a.key.cmp(&b.key).then(a.kind.cmp(&b.kind)));
        report.findings = findings;
        report
    }
}

/// A commit that the run walks: the commit, its root dirtree, and its root
/// dirmeta.
#[derive(Clone, Copy)]
struct Root {
    commit: Checksum,
    dirtree: Checksum,
    dirmeta: Checksum,
}

/// The result of the read of one metadata object.
enum Read {
    /// The key holds no object at the read.
    Gone,
    /// The object is larger than [`MAX_METADATA_SIZE`].
    TooLarge,
    /// The bytes of the object.
    Bytes(Vec<u8>),
}

/// The result of the read and the check of one metadata object.
enum Metadata<T> {
    /// The key holds no object at the read.
    Gone,
    /// The object is larger than [`MAX_METADATA_SIZE`].
    TooLarge,
    /// The object has `len` bytes, whose checksum is `actual`, and which
    /// parse to `parsed`.
    Checked {
        len: u64,
        actual: Checksum,
        parsed: std::result::Result<T, String>,
    },
}

/// The objects that a dirtree names: its files, and the dirtree and the
/// dirmeta of each directory.
type Children = (Vec<Checksum>, Vec<(Checksum, Checksum)>);

/// The result of a whole read of `summary` or `summary.sig`.
enum Whole {
    /// The key holds no object.
    Absent,
    /// The object is larger than [`SUMMARY_READ_CAP`].
    TooLarge,
    /// The bytes of the object.
    Bytes(Vec<u8>),
}

/// The result of one check read of a content object or of a composefs
/// image.
enum Checked<T> {
    /// The key holds no object at the read.
    Gone,
    /// The body failed in transit, after the given number of bytes.
    Transit(std::io::Error, u64),
    /// The check read the object to its result, with the given number of
    /// bytes.
    Done(T, u64),
}

/// The verdict of the check of a content object.
enum Verdict {
    /// The object is valid.
    Good,
    /// The object has the given checksum.
    Mismatch(Checksum),
    /// The object does not read as a `.filez`, for the given reason.
    Corrupt(String),
}

/// The objects that `--delete` acts on, in the order of the run.
#[derive(Debug, Default, PartialEq, Eq)]
struct DeletePlan {
    /// The commits that get a partial-commit marker, sorted.
    markers: Vec<Checksum>,
    /// The commit objects to delete, sorted.
    commits: Vec<ObjectName>,
    /// The tree objects to delete, sorted.
    tree: Vec<ObjectName>,
    /// The composefs images to delete, sorted.
    images: Vec<ObjectName>,
}

impl BucketRepo {
    /// Checks the bucket repository, and with
    /// [`delete`](BucketFsckOptions::delete) repairs it.
    ///
    /// The run reads each commit, each object of the tree of each commit,
    /// and each composefs image of a commit, and checks each one against its
    /// name. Its cost is the download of the reachable objects of the
    /// repository. At most `max_outstanding` reads run at a time, as
    /// [`new`](BucketRepo::new) states, and each read of a `.filez`, of a
    /// `.cfs`, or of a superblock is a stream that the run reads in chunks of
    /// 64 KiB. Each read of the `config`, of a ref file, of the summary, of a
    /// superblock, and of an object takes the strict rule of an absent key of
    /// [`get_strict`](crate::remote::s3::Bucket::get_strict). The bucket
    /// repository module states the checks under "The fsck".
    ///
    /// # Steps
    ///
    /// 1. With `delete`, the run reads the `config` first. A `config` that is
    ///    absent or breaks a rule refuses the repair, and the run goes on
    ///    with no change. Else it takes the writer lock for
    ///    [`LockOperation::Fsck`], with
    ///    [`break_lock`](BucketFsckOptions::break_lock). Without `delete`,
    ///    the run reads the lock, and a lock gives a `Lock` note.
    /// 2. The `config`.
    /// 3. At the same time: the ref files under `refs/`, the listing of the
    ///    objects, the strays under `objects/`, the partial-commit markers
    ///    under `state/`, and the list of the incomplete multipart uploads.
    /// 4. The summary, and at the same time its signature with
    ///    [`summary_keys`](BucketFsckOptions::summary_keys).
    /// 5. The commits, then the dirtrees and the dirmetas, then the
    ///    `.filez` objects, then the composefs images. A phase starts after
    ///    the phase before it ends.
    /// 6. The count of the objects that no commit reaches.
    /// 7. Without `delete`, a read again of each object that the listing
    ///    does not hold and that a `Missing` finding names, because a writer
    ///    can change the bucket during the run. If the key holds an object,
    ///    the finding is a note. Else the run reads each commit of the
    ///    finding again, and drops the commits that are gone. If no commit
    ///    stays, the run records no finding.
    /// 8. With `delete`: a check of the lock, a marker
    ///    `state/<checksum>.commitpartial` for each commit that reaches a
    ///    tree object of a `Missing`, a `Mismatch`, or a `Corrupt` finding,
    ///    the delete of the marker of each commit whose tree the run finds
    ///    whole, a check of the lock, and the delete of each object of a
    ///    `Mismatch` and a `Corrupt` finding: the commit objects, then the
    ///    tree objects, then the composefs images. A commit that holds a
    ///    marker gets no new one, and a commit whose own object the run
    ///    deletes gets none. The run deletes no commit because of a bad tree
    ///    object. Then the release of the lock. Without `delete`, a marker of
    ///    a commit whose tree the run finds whole gives a `Marker` note, and
    ///    the run reads the lock again: a new lock gives a `Lock` note.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `break_lock` is set without `delete`. The
    ///   run then sends no request.
    /// - The errors of [`lock`](BucketRepo::lock). A lock of another writer
    ///   fails a run with `delete` before it reads an object.
    /// - [`Error::BucketLockLost`] if a check of the lock fails before the
    ///   first write of the repair. The run then writes and deletes nothing,
    ///   and releases no lock. A lock that is gone at the release gives a
    ///   `Lock` note.
    /// - [`Error::BucketRepairIncomplete`] if a step of the repair fails
    ///   after the check of the lock before its first write. The error holds
    ///   the report, with each marker write and each delete that completed,
    ///   and the failure. The bucket can then hold the marker of a commit
    ///   whose bad objects are still in the bucket, and a push of that commit
    ///   uploads no object for them and deletes the marker. Run the fsck with
    ///   `delete` again before a push.
    /// - [`Error::Remote`] for an error of the bucket client, also for a 404
    ///   without the code `NoSuchKey`, and [`Error::Io`] for a read that
    ///   fails in transit two times. A run with `delete` then releases its
    ///   lock and drops an error of that release.
    pub async fn fsck(&self, opts: &BucketFsckOptions) -> Result<BucketFsckReport> {
        if opts.break_lock && !opts.delete {
            return Err(Error::InvalidInput(
                "the fsck of a bucket repository breaks the writer lock only with delete; a run \
                 with no delete takes no lock"
                    .to_owned(),
            ));
        }
        let mut run = Run::default();
        let config = self.fsck_config(&mut run, opts.delete).await?;
        let own = config
            .as_ref()
            .and_then(|c| c.collection_id().map(str::to_owned));
        if opts.delete && config.is_some() {
            let lock = self.lock(LockOperation::Fsck, opts.break_lock).await?;
            run.report.broken_lock = lock.broken().cloned();
            if let Err(e) = self
                .fsck_run(&mut run, opts, own.as_deref(), Some(&lock))
                .await
            {
                let e = release_on_error(lock, e).await;
                if run.changed {
                    return Err(Error::BucketRepairIncomplete {
                        address: self.address().to_string(),
                        report: Box::new(run.finish()),
                        error: Box::new(e),
                    });
                }
                return Err(e);
            }
            match lock.release().await {
                Ok(()) => {}
                Err(Error::BucketLockLost { holder, .. }) => run.add(
                    Lock,
                    false,
                    LOCK_KEY,
                    format!(
                        "the lock of the run was gone at its release: {}",
                        super::describe_lost(holder.as_deref())
                    ),
                ),
                Err(e) => return Err(e),
            }
        } else {
            let start = self.lock_holder().await?;
            if let Some(holder) = &start {
                run.add(
                    Lock,
                    false,
                    LOCK_KEY,
                    format!("a writer held the lock at the start of the run: {holder}"),
                );
            }
            self.fsck_run(&mut run, opts, own.as_deref(), None).await?;
            if let Some(holder) = self.lock_holder().await?
                && start.as_ref().is_none_or(|start| start.id != holder.id)
            {
                run.add(
                    Lock,
                    false,
                    LOCK_KEY,
                    format!("a writer held the lock at the end of the run: {holder}"),
                );
            }
        }
        Ok(run.finish())
    }

    /// Reads the `config` by the strict rule of an absent key, records a
    /// `Config` finding for a `config` that is absent or breaks a rule, and
    /// returns the valid `config`.
    async fn fsck_config(
        &self,
        run: &mut Run,
        delete: bool,
    ) -> Result<Option<crate::config::RepoConfig>> {
        let refused = if delete {
            "; the run refuses the repair, and changes nothing"
        } else {
            ""
        };
        match self.read_config_strict().await {
            Ok(Some(config)) => Ok(Some(config)),
            Ok(None) => {
                run.add(
                    Config,
                    true,
                    "config",
                    format!("the bucket repository has no config{refused}"),
                );
                Ok(None)
            }
            Err(Error::InvalidFormat(message)) => {
                let lead = format!("the bucket repository {}: ", self.address());
                let reason = message.strip_prefix(&lead).unwrap_or(&message);
                run.add(Config, true, "config", format!("{reason}{refused}"));
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Runs the steps of the fsck after the take of the lock.
    async fn fsck_run(
        &self,
        run: &mut Run,
        opts: &BucketFsckOptions,
        own: Option<&str>,
        lock: Option<&WriterLock<'_>>,
    ) -> Result<()> {
        // A list of the uploads needs a permission of its own, so it runs
        // with the other lists, before the first object read.
        let (refs, (listing, (delimited, (state, uploads)))) = zip(
            self.fsck_refs(run, own),
            zip(
                self.list_objects(),
                zip(
                    self.bucket.list_delimited("objects/"),
                    zip(self.partial_commits(), self.bucket.list_uploads()),
                ),
            ),
        )
        .await;
        let refs = refs?;
        let listing = listing?;
        let (delimited, partial, uploads) = (delimited?, state?, uploads?);
        run.report.objects_listed = listing.objects.len() as u64;
        self.fsck_strays(run, &listing, delimited).await?;
        run.report.commits_partial = partial.iter().copied().collect();
        for upload in uploads {
            run.add(
                Upload,
                false,
                &upload.key,
                format!(
                    "an incomplete multipart upload, with the upload id {} and the Initiated \
                     time {}",
                    upload.upload_id.escape_debug(),
                    upload.initiated.escape_debug()
                ),
            );
        }
        let holds = |name: ObjectName| listing.objects.contains_key(&name);
        for (key, commit) in ref_entries(&refs) {
            if !holds(ObjectName::new(commit, ObjectType::Commit)) {
                run.add(
                    Ref,
                    true,
                    &key,
                    format!("names the commit {commit}, which the bucket does not hold"),
                );
            }
        }
        self.fsck_summary(run, opts.summary_keys.as_ref(), &refs, &listing)
            .await?;
        let (roots, digests) = self.fsck_commits(run, &listing).await?;
        let (seen, files) = self.fsck_trees(run, &listing, &roots).await?;
        self.fsck_contents(run, &listing, &files).await?;
        self.fsck_images(run, &listing, &digests, lock.is_some())
            .await?;
        run.report.objects_unreached = listing
            .objects
            .keys()
            .filter(|name| !is_reached(name, &seen, &files, &listing))
            .count() as u64;
        drop(seen);
        drop(files);
        self.fsck_attribute(run, &listing, &roots).await?;
        if lock.is_none() {
            self.fsck_recheck(run).await?;
        }
        let whole = whole_marked(&run.findings, &roots, &partial);
        match lock {
            Some(lock) => self.fsck_repair(run, &refs, &partial, &whole, lock).await,
            None => {
                for commit in whole {
                    run.add(
                        Marker,
                        false,
                        &marker_key(&commit),
                        format!(
                            "the commit {commit} has a partial-commit marker, and the run finds \
                             its tree whole; a run with delete deletes the marker"
                        ),
                    );
                }
                Ok(())
            }
        }
    }

    /// Reads the ref files by the strict rule of an absent key, records each
    /// `Ref` finding, and returns the refs that pass.
    async fn fsck_refs(&self, run: &mut Run, own: Option<&str>) -> Result<BucketRefs> {
        let listing = self.bucket.list("refs/").await?;
        let mut keys = Vec::with_capacity(listing.objects.len());
        for listed in &listing.objects {
            let key = listed.key.as_str();
            match ref_key(key) {
                Some(RefKey::Mirror(id, _)) if Some(id) == own => run.add(
                    Ref,
                    true,
                    key,
                    "is a ref under refs/mirrors/ of the own collection id; a bucket repository \
                     holds the refs of its own collection under refs/heads/"
                        .to_owned(),
                ),
                Some(_) => keys.push(key),
                None => run.add(
                    Ref,
                    true,
                    key,
                    "is no ref of refs/heads/ or of refs/mirrors/ID/".to_owned(),
                ),
            }
        }
        let mut refs = BucketRefs::default();
        let mut reads = Slots::new(self.max_outstanding);
        let mut pending = keys.into_iter();
        loop {
            while reads.has_room()
                && let Some(key) = pending.next()
            {
                reads.push(async move { (key, self.read_ref_file_strict(key).await) });
            }
            let Some((key, read)) = reads.next_ready().await else {
                break;
            };
            match read? {
                RefRead::Commit(commit) => match ref_key(key) {
                    Some(RefKey::Head(name)) => {
                        refs.heads.insert(name.to_owned(), commit);
                    }
                    Some(RefKey::Mirror(id, name)) => {
                        refs.mirrors
                            .entry(id.to_owned())
                            .or_default()
                            .insert(name.to_owned(), commit);
                    }
                    None => unreachable!("each key passed the rule"),
                },
                RefRead::Gone => run.add(
                    Ref,
                    true,
                    key,
                    "was in the listing and is gone at its read".to_owned(),
                ),
                RefRead::Malformed(why) => run.add(Ref, true, key, why),
            }
        }
        Ok(refs)
    }

    /// Records a `Stray` finding for each key under `objects/` that is no
    /// object key.
    ///
    /// The strays of the 256 fan-out prefixes are in `listing`. `delimited`
    /// is the list of `objects/` with the delimiter `/`: each key in it is a
    /// stray, and each common prefix other than a fan-out prefix is listed in
    /// full.
    async fn fsck_strays(
        &self,
        run: &mut Run,
        listing: &ObjectListing,
        delimited: crate::remote::s3::Listing,
    ) -> Result<()> {
        let stray = |run: &mut Run, key: &str, size: u64| {
            run.add(
                Stray,
                true,
                key,
                format!("is no object key, with {size} bytes"),
            )
        };
        for listed in listing.strays.iter().chain(&delimited.objects) {
            stray(run, &listed.key, listed.size);
        }
        for prefix in &delimited.common_prefixes {
            if is_fanout_prefix(prefix) {
                continue;
            }
            match self.bucket.list(prefix).await {
                Ok(list) => {
                    for listed in &list.objects {
                        stray(run, &listed.key, listed.size);
                    }
                }
                Err(crate::remote::Error::InvalidInput(why)) => run.add(
                    Stray,
                    true,
                    prefix,
                    format!(
                        "is a prefix of keys that are no object keys, and cannot be listed: {why}"
                    ),
                ),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Checks the summary and its signature, and compares the summary with
    /// the refs and the deltas of the bucket.
    async fn fsck_summary(
        &self,
        run: &mut Run,
        keys: Option<&TrustedKeys>,
        refs: &BucketRefs,
        listing: &ObjectListing,
    ) -> Result<()> {
        let (summary, signature) = match keys {
            Some(_) => {
                let (summary, signature) =
                    zip(self.read_whole("summary"), self.read_whole("summary.sig")).await;
                (summary?, Some(signature?))
            }
            None => (self.read_whole("summary").await?, None),
        };
        let summary = match summary {
            Whole::Bytes(bytes) => bytes,
            Whole::TooLarge => {
                too_large_summary(run, "summary");
                return Ok(());
            }
            Whole::Absent => {
                match keys {
                    Some(_) => summary_error(
                        run,
                        "the run verifies the signature of the summary, and the bucket holds no \
                         summary"
                            .to_owned(),
                    ),
                    None => run.add(
                        BucketFindingKind::Summary,
                        false,
                        "summary",
                        "the bucket holds no summary".to_owned(),
                    ),
                }
                return Ok(());
            }
        };
        if let (Some(keys), Some(signature)) = (keys, signature) {
            self.fsck_signature(run, keys, &summary, signature).await?;
        }
        // A summary can be as large as `SUMMARY_READ_CAP`, so the parse runs
        // on the blocking pool, as the parse of a pull does.
        let parsed = ostrya_rt::unblock(move || -> Result<_> {
            let parsed = Summary::parse(&summary)?;
            let collections = parsed.collection_map()?;
            let deltas = parsed.static_deltas()?;
            Ok((parsed, collections, deltas))
        })
        .await;
        let (parsed, collections, advertised) = match parsed {
            Ok(parsed) => parsed,
            Err(e) => {
                summary_error(run, format!("does not parse: {e}"));
                return Ok(());
            }
        };
        let holds = |commit: &Checksum| {
            listing
                .objects
                .contains_key(&ObjectName::new(*commit, ObjectType::Commit))
        };
        let mut listed: BTreeMap<String, Checksum> = BTreeMap::new();
        for entry in &parsed.refs {
            listed.insert(format!("refs/heads/{}", entry.name), entry.commit);
        }
        for (id, entries) in &collections {
            for entry in entries {
                listed.insert(format!("refs/mirrors/{id}/{}", entry.name), entry.commit);
            }
        }
        drop(parsed);
        drop(collections);
        let files: BTreeMap<String, Checksum> = ref_entries(refs).collect();
        let mut stale = Vec::new();
        for (key, commit) in &listed {
            if !holds(commit) {
                summary_error(
                    run,
                    format!(
                        "names the ref {} at the commit {commit}, which the bucket does not hold",
                        key.escape_debug()
                    ),
                );
            } else if files.get(key) != Some(commit) {
                stale.push(key.clone());
            }
        }
        stale.extend(
            files
                .keys()
                .filter(|key| !listed.contains_key(*key))
                .cloned(),
        );
        stale.sort();
        let deltas_stale = match self.fsck_deltas(run, &advertised).await {
            Ok(stale) => stale,
            Err(Error::InvalidFormat(message)) => {
                let lead = format!("the bucket repository {}: ", self.address());
                let reason = message.strip_prefix(&lead).unwrap_or(&message);
                summary_error(
                    run,
                    format!("the delta map of the bucket cannot be built: {reason}"),
                );
                Vec::new()
            }
            Err(e) => return Err(e),
        };
        if !stale.is_empty() || !deltas_stale.is_empty() {
            let mut parts = Vec::new();
            if !stale.is_empty() {
                parts.push(format!(
                    "{} ref(s) differ from the ref files: {}",
                    stale.len(),
                    named_list(&stale)
                ));
            }
            if !deltas_stale.is_empty() {
                parts.push(format!(
                    "{} delta(s) of the bucket are not in it: {}",
                    deltas_stale.len(),
                    named_list(&deltas_stale)
                ));
            }
            run.add(
                BucketFindingKind::Summary,
                false,
                "summary",
                format!(
                    "the summary is older than the refs or the deltas: {}",
                    parts.join("; ")
                ),
            );
        }
        Ok(())
    }

    /// Compares the deltas `advertised` of the summary with the superblocks
    /// of the bucket, records each `Summary` error, and returns the names of
    /// the deltas of the bucket that the summary does not advertise, sorted.
    ///
    /// The run lists `deltas/`, and reads the superblocks of the advertised
    /// deltas alone, by the strict rule of an absent key.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] if the delta map of the bucket cannot be
    /// built: a superblock key that names no delta, or a superblock that is
    /// larger than its cap. The errors of the reads.
    async fn fsck_deltas(
        &self,
        run: &mut Run,
        advertised: &[crate::summary::AdvertisedDelta],
    ) -> Result<Vec<String>> {
        let mut held: BTreeMap<String, SuperblockKey> = self
            .superblock_keys()
            .await?
            .into_iter()
            .map(|key| (key.name.clone(), key))
            .collect();
        let mut named = Vec::new();
        let mut read = Vec::new();
        let mut seen = HashSet::new();
        for delta in advertised {
            let name = delta_name(delta.from.as_ref(), &delta.to);
            if !seen.insert(name.clone()) {
                continue;
            }
            if let Some(key) = held.remove(&name) {
                read.push(key);
            }
            named.push((name, delta.superblock));
        }
        let digests: HashMap<String, Checksum> = self
            .superblock_digests(read)
            .await?
            .into_iter()
            .map(|delta| (delta.name, delta.digest))
            .collect();
        for (name, expected) in named {
            match digests.get(&name) {
                None => summary_error(
                    run,
                    format!("names the delta {name}, whose superblock the bucket does not hold"),
                ),
                Some(digest) if *digest != expected => summary_error(
                    run,
                    format!(
                        "names the delta {name} with the superblock digest {expected}, and the \
                         superblock of the bucket has the digest {digest}"
                    ),
                ),
                Some(_) => {}
            }
        }
        Ok(held.into_keys().collect())
    }

    /// Verifies the signature `signature` of the summary `summary` against
    /// `keys`, as a pull that verifies the summary does.
    async fn fsck_signature(
        &self,
        run: &mut Run,
        keys: &TrustedKeys,
        summary: &[u8],
        signature: Whole,
    ) -> Result<()> {
        let signature = match signature {
            Whole::Bytes(bytes) => bytes,
            Whole::TooLarge => {
                too_large_summary(run, "summary.sig");
                return Ok(());
            }
            Whole::Absent => {
                run.add(
                    BucketFindingKind::Summary,
                    true,
                    "summary.sig",
                    "the run verifies the signature of the summary, and the bucket holds no \
                     summary.sig"
                        .to_owned(),
                );
                return Ok(());
            }
        };
        let dict =
            ostrya_rt::unblock(move || crate::summary::parse_signature_dict(&signature)).await;
        let dict = match dict {
            Ok(dict) => dict,
            Err(e) => {
                run.add(
                    BucketFindingKind::Summary,
                    true,
                    "summary.sig",
                    format!("does not parse: {e}"),
                );
                return Ok(());
            }
        };
        match keys
            .policy()
            .check("the summary", summary, dict.as_ref())
            .await
        {
            Ok(()) => Ok(()),
            Err(Error::Signature(message)) => {
                run.add(BucketFindingKind::Summary, true, "summary.sig", message);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Reads `summary` or `summary.sig` whole, by the strict rule of an
    /// absent key, up to the read cap of a summary.
    async fn read_whole(&self, key: &str) -> Result<Whole> {
        match self.bucket.get_strict(key, SUMMARY_READ_CAP).await {
            Ok(Some(object)) => Ok(Whole::Bytes(object.bytes)),
            Ok(None) => Ok(Whole::Absent),
            Err(crate::remote::Error::LimitExceeded(_)) => Ok(Whole::TooLarge),
            Err(e) => Err(e.into()),
        }
    }

    /// Reads and checks each commit object of the listing.
    ///
    /// Returns the root of each commit that parses, also of a commit whose
    /// bytes do not match its name, and the digest that each commit with a
    /// composefs image in the listing records, or the reason that the digest
    /// does not read.
    #[allow(clippy::type_complexity)]
    async fn fsck_commits(
        &self,
        run: &mut Run,
        listing: &ObjectListing,
    ) -> Result<(
        Vec<Root>,
        HashMap<Checksum, std::result::Result<Option<[u8; 32]>, String>>,
    )> {
        let mut commits: Vec<(ObjectName, u64)> = listing
            .objects
            .iter()
            .filter(|(name, _)| name.ty == ObjectType::Commit)
            .map(|(name, size)| (*name, *size))
            .collect();
        commits.sort_by_key(|(name, _)| name.checksum);
        let mut roots = Vec::new();
        let mut digests = HashMap::new();
        let mut reads = Slots::new(self.max_outstanding);
        let mut pending = commits.into_iter();
        loop {
            while reads.has_room()
                && let Some((name, size)) = pending.next()
            {
                reads.push(async move {
                    let read = self.read_checked(name, size, parse_commit).await;
                    (name, read)
                });
            }
            let Some((name, read)) = reads.next_ready().await else {
                break;
            };
            let has_image = listing
                .objects
                .contains_key(&ObjectName::new(name.checksum, ObjectType::ComposefsImage));
            let (len, actual, parsed) = match read? {
                // A writer removed the commit after the listing.
                Metadata::Gone => continue,
                Metadata::TooLarge => {
                    run.object(Corrupt, name, too_large());
                    if has_image {
                        digests.insert(
                            name.checksum,
                            Err("the commit object is larger than the cap".to_owned()),
                        );
                    }
                    continue;
                }
                Metadata::Checked {
                    len,
                    actual,
                    parsed,
                } => (len, actual, parsed),
            };
            run.report.commits_checked += 1;
            run.report.bytes_read += len;
            run.check_metadata(name, actual, &parsed);
            match parsed {
                Ok(commit) => {
                    roots.push(Root {
                        commit: name.checksum,
                        dirtree: commit.root_dirtree,
                        dirmeta: commit.root_dirmeta,
                    });
                    if has_image {
                        digests.insert(
                            name.checksum,
                            crate::composefs::recorded_digest(&commit).map_err(|e| e.to_string()),
                        );
                    }
                }
                Err(e) if has_image => {
                    digests.insert(
                        name.checksum,
                        Err(format!("the commit does not parse: {e}")),
                    );
                }
                Err(_) => {}
            }
        }
        roots.sort_by_key(|root| root.commit);
        Ok((roots, digests))
    }

    /// Reads the metadata object `name` whole, by the strict rule of an
    /// absent key. `listed` is its size in the listing, and caps the read.
    ///
    /// An object that is larger than its listed size, for example after a
    /// writer replaced it, is read again with the cap
    /// [`MAX_METADATA_SIZE`].
    async fn read_metadata(&self, name: ObjectName, listed: u64) -> Result<Read> {
        if listed > MAX_METADATA_SIZE {
            return Ok(Read::TooLarge);
        }
        let key = object_key(&name);
        let read = match self.bucket.get_strict(&key, listed).await {
            Err(crate::remote::Error::LimitExceeded(_)) if listed < MAX_METADATA_SIZE => {
                self.bucket.get_strict(&key, MAX_METADATA_SIZE).await
            }
            read => read,
        };
        match read {
            Ok(Some(object)) => Ok(Read::Bytes(object.bytes)),
            Ok(None) => Ok(Read::Gone),
            Err(crate::remote::Error::LimitExceeded(_)) => Ok(Read::TooLarge),
            Err(e) => Err(e.into()),
        }
    }

    /// Reads the metadata object `name` as [`read_metadata`] does, and takes
    /// the SHA-256 of its bytes and their parse with `parse`.
    ///
    /// The hash and the parse of an object larger than [`UNBLOCK_SIZE`] run
    /// on the blocking pool, so the other reads in flight go on.
    ///
    /// [`read_metadata`]: BucketRepo::read_metadata
    async fn read_checked<T: Send + 'static>(
        &self,
        name: ObjectName,
        listed: u64,
        parse: fn(&[u8]) -> std::result::Result<T, String>,
    ) -> Result<Metadata<T>> {
        let bytes = match self.read_metadata(name, listed).await? {
            Read::Gone => return Ok(Metadata::Gone),
            Read::TooLarge => return Ok(Metadata::TooLarge),
            Read::Bytes(bytes) => bytes,
        };
        let len = bytes.len() as u64;
        let check = move || (Checksum::sha256(&bytes), parse(&bytes));
        let (actual, parsed) = if len > UNBLOCK_SIZE as u64 {
            ostrya_rt::unblock(check).await
        } else {
            check()
        };
        Ok(Metadata::Checked {
            len,
            actual,
            parsed,
        })
    }

    /// Walks the trees of `roots`, and reads and checks each dirtree and each
    /// dirmeta once.
    ///
    /// Returns the dirtrees and the dirmetas that the walk reached, and the
    /// content objects of the dirtrees that parse.
    async fn fsck_trees(
        &self,
        run: &mut Run,
        listing: &ObjectListing,
        roots: &[Root],
    ) -> Result<(HashSet<ObjectName>, HashSet<Checksum>)> {
        let mut seen: HashSet<ObjectName> = HashSet::new();
        let mut queue: Vec<ObjectName> = Vec::new();
        for root in roots {
            for name in [
                ObjectName::new(root.dirtree, ObjectType::DirTree),
                ObjectName::new(root.dirmeta, ObjectType::DirMeta),
            ] {
                if seen.insert(name) {
                    queue.push(name);
                }
            }
        }
        let mut files: HashSet<Checksum> = HashSet::new();
        let mut reads = Slots::new(self.max_outstanding);
        loop {
            while reads.has_room()
                && let Some(name) = queue.pop()
            {
                let Some(size) = listing.objects.get(&name).copied() else {
                    run.unlisted(name);
                    continue;
                };
                let parse = match name.ty {
                    ObjectType::DirMeta => parse_dirmeta,
                    _ => parse_dirtree,
                };
                reads.push(async move { (name, self.read_checked(name, size, parse).await) });
            }
            let Some((name, read)) = reads.next_ready().await else {
                if queue.is_empty() {
                    break;
                }
                continue;
            };
            let (len, actual, parsed) = match read? {
                Metadata::Gone => {
                    run.object(
                        Missing,
                        name,
                        "the object was in the listing and is gone at its read".to_owned(),
                    );
                    continue;
                }
                Metadata::TooLarge => {
                    run.object(Corrupt, name, too_large());
                    continue;
                }
                Metadata::Checked {
                    len,
                    actual,
                    parsed,
                } => (len, actual, parsed),
            };
            run.report.objects_checked += 1;
            run.report.bytes_read += len;
            run.check_metadata(name, actual, &parsed);
            // A dirtree that does not parse ends its subtree. A dirmeta names
            // no object.
            let Ok((tree_files, dirs)) = parsed else {
                continue;
            };
            files.extend(tree_files);
            for (subtree, submeta) in dirs {
                for child in [
                    ObjectName::new(subtree, ObjectType::DirTree),
                    ObjectName::new(submeta, ObjectType::DirMeta),
                ] {
                    if seen.insert(child) {
                        queue.push(child);
                    }
                }
            }
        }
        Ok((seen, files))
    }

    /// Reads and checks each content object of `files`, at most
    /// `max_outstanding` at a time, each with one read buffer.
    async fn fsck_contents(
        &self,
        run: &mut Run,
        listing: &ObjectListing,
        files: &HashSet<Checksum>,
    ) -> Result<()> {
        let mut buffers: Vec<Vec<u8>> = Vec::new();
        let mut reads = Slots::new(self.max_outstanding);
        let mut pending = files.iter();
        loop {
            while reads.has_room()
                && let Some(file) = pending.next()
            {
                let name = ObjectName::new(*file, ObjectType::File);
                if !listing.objects.contains_key(&name) {
                    run.unlisted(name);
                    continue;
                }
                let mut buf = buffers.pop().unwrap_or_default();
                reads.push(async move {
                    let checked = self
                        .read_twice(name, |buf| self.check_content(name.checksum, buf), &mut buf)
                        .await;
                    (name, checked, buf)
                });
            }
            let Some((name, checked, buf)) = reads.next_ready().await else {
                break;
            };
            buffers.push(buf);
            let (verdict, bytes) = match checked? {
                (Some(verdict), bytes) => (verdict, bytes),
                (None, bytes) => {
                    run.report.bytes_read += bytes;
                    run.object(
                        Missing,
                        name,
                        "the object was in the listing and is gone at its read".to_owned(),
                    );
                    continue;
                }
            };
            run.report.objects_checked += 1;
            run.report.bytes_read += bytes;
            match verdict {
                Verdict::Good => {}
                Verdict::Mismatch(actual) => run.object(
                    Mismatch,
                    name,
                    format!("the object has the checksum {actual}"),
                ),
                Verdict::Corrupt(why) => run.object(Corrupt, name, why),
            }
        }
        Ok(())
    }

    /// Runs the check read `check` of the object `name`, and runs it once
    /// more from the start of the object if its body fails in transit.
    ///
    /// Returns the result of the check, or `None` if the key holds no object
    /// at the read, with the bytes of the reads.
    async fn read_twice<'b, T, F, Fut>(
        &self,
        name: ObjectName,
        check: F,
        buf: &'b mut Vec<u8>,
    ) -> Result<(Option<T>, u64)>
    where
        F: Fn(&'b mut Vec<u8>) -> Fut,
        Fut: Future<Output = Result<(Checked<T>, &'b mut Vec<u8>)>>,
    {
        let (first, buf) = check(buf).await?;
        let mut bytes = 0;
        match first {
            Checked::Gone => return Ok((None, 0)),
            Checked::Done(verdict, read) => return Ok((Some(verdict), read)),
            Checked::Transit(_, read) => bytes += read,
        }
        let (second, _) = check(buf).await?;
        match second {
            Checked::Gone => Ok((None, bytes)),
            Checked::Done(verdict, read) => Ok((Some(verdict), bytes + read)),
            Checked::Transit(e, _) => Err(Error::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "the read of {} failed in transit two times: {e}",
                    object_key(&name)
                ),
            ))),
        }
    }

    /// Reads the content object `checksum` as a stream, and checks it.
    async fn check_content<'b>(
        &self,
        checksum: Checksum,
        buf: &'b mut Vec<u8>,
    ) -> Result<(Checked<Verdict>, &'b mut Vec<u8>)> {
        let key = object_key(&ObjectName::new(checksum, ObjectType::File));
        let Some(stream) = self.bucket.get_stream_strict(&key).await? else {
            return Ok((Checked::Gone, buf));
        };
        let mut transit = Transit::new(stream);
        let verdict = content_verdict(&checksum, &mut transit, buf).await;
        Ok((transit.finish(verdict), buf))
    }

    /// Checks each composefs image of the listing against the digest that
    /// its commit records.
    ///
    /// With `deleting`, the run is a repair: the image of a commit whose own
    /// object has a `Mismatch` or a `Corrupt` finding is an orphan, because
    /// the repair deletes the commit, and the run does not check it.
    async fn fsck_images(
        &self,
        run: &mut Run,
        listing: &ObjectListing,
        digests: &HashMap<Checksum, std::result::Result<Option<[u8; 32]>, String>>,
        deleting: bool,
    ) -> Result<()> {
        let doomed: HashSet<Checksum> = if deleting {
            run.findings
                .iter()
                .filter(|finding| matches!(finding.kind, Mismatch | Corrupt))
                .filter_map(|finding| finding.object)
                .filter(|name| name.ty == ObjectType::Commit)
                .map(|name| name.checksum)
                .collect()
        } else {
            HashSet::new()
        };
        let mut images: Vec<Checksum> = listing
            .objects
            .keys()
            .filter(|name| name.ty == ObjectType::ComposefsImage)
            .map(|name| name.checksum)
            .collect();
        images.sort();
        let mut checks = Vec::new();
        for commit in images {
            let name = ObjectName::new(commit, ObjectType::ComposefsImage);
            if doomed.contains(&commit) {
                run.report.orphan_images.push(commit);
                continue;
            }
            match digests.get(&commit) {
                // The commit is not in the listing, or a writer removed it
                // after the listing.
                None => run.report.orphan_images.push(commit),
                Some(Err(why)) => {
                    let mut finding = image_finding(Corrupt, name, why.clone());
                    finding.commits.push(commit);
                    run.findings.push(finding);
                }
                Some(Ok(None)) => {
                    let mut finding = image_finding(
                        Corrupt,
                        name,
                        "the commit does not carry ostree.composefs.digest.v0".to_owned(),
                    );
                    finding.commits.push(commit);
                    run.findings.push(finding);
                }
                Some(Ok(Some(expected))) => checks.push((name, *expected)),
            }
        }
        let mut buffers: Vec<Vec<u8>> = Vec::new();
        let mut reads = Slots::new(self.max_outstanding);
        let mut pending = checks.into_iter();
        loop {
            while reads.has_room()
                && let Some((name, expected)) = pending.next()
            {
                let mut buf = buffers.pop().unwrap_or_default();
                reads.push(async move {
                    let checked = self
                        .read_twice(name, |buf| self.image_digest(name.checksum, buf), &mut buf)
                        .await;
                    (name, expected, checked, buf)
                });
            }
            let Some((name, expected, checked, buf)) = reads.next_ready().await else {
                break;
            };
            buffers.push(buf);
            let (checked, bytes) = checked?;
            run.report.bytes_read += bytes;
            // A writer removed the image after the listing.
            let Some(actual) = checked else {
                continue;
            };
            run.report.objects_checked += 1;
            if actual != expected {
                let mut finding = image_finding(
                    Mismatch,
                    name,
                    format!(
                        "the commit records the digest {}, and the image has the digest {}",
                        crate::composefs::digest_hex(&expected),
                        crate::composefs::digest_hex(&actual)
                    ),
                );
                finding.commits.push(name.checksum);
                run.findings.push(finding);
            }
        }
        Ok(())
    }

    /// Reads the composefs image of `commit` as a stream, and returns its
    /// fs-verity digest.
    async fn image_digest<'b>(
        &self,
        commit: Checksum,
        buf: &'b mut Vec<u8>,
    ) -> Result<(Checked<[u8; 32]>, &'b mut Vec<u8>)> {
        let key = object_key(&ObjectName::new(commit, ObjectType::ComposefsImage));
        let Some(stream) = self.bucket.get_stream_strict(&key).await? else {
            return Ok((Checked::Gone, buf));
        };
        if buf.len() < IMAGE_CHUNK {
            buf.resize(IMAGE_CHUNK, 0);
        }
        let mut transit = Transit::new(stream);
        let mut hasher = FsVerityHasher::new();
        loop {
            match transit.read(&mut buf[..]).await {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(_) => break,
            }
        }
        Ok((transit.finish(hasher.finalize()), buf))
    }

    /// Names the commits that reach each tree object of a `Missing`, a
    /// `Mismatch`, or a `Corrupt` finding.
    ///
    /// The pass runs only if such a finding exists. It reads each dirtree of
    /// the listing that the commits reach once more. It gives each dirtree a
    /// number, keeps each edge from a dirtree to its parent as two numbers in
    /// one sorted list, and keeps the holders of each faulty object. It keeps
    /// no list of the files of a dirtree.
    async fn fsck_attribute(
        &self,
        run: &mut Run,
        listing: &ObjectListing,
        roots: &[Root],
    ) -> Result<()> {
        let faulty: HashSet<ObjectName> = run
            .findings
            .iter()
            .filter(|finding| matches!(finding.kind, Missing | Mismatch | Corrupt))
            .filter_map(|finding| finding.object)
            .filter(|name| is_tree_object(name.ty))
            .collect();
        if faulty.is_empty() {
            return Ok(());
        }
        // The number of each dirtree that the pass reaches.
        let mut index: HashMap<Checksum, u32> = HashMap::new();
        // Each edge from a dirtree to its parent: (child, parent).
        let mut edges: Vec<(u32, u32)> = Vec::new();
        let mut tops: HashMap<u32, Vec<Checksum>> = HashMap::new();
        let mut holders: HashMap<ObjectName, Vec<u32>> = HashMap::new();
        let mut direct: HashMap<ObjectName, BTreeSet<Checksum>> = HashMap::new();
        let mut queue: Vec<Checksum> = Vec::new();
        for root in roots {
            let top = intern(&mut index, &mut queue, root.dirtree);
            tops.entry(top).or_default().push(root.commit);
            let meta = ObjectName::new(root.dirmeta, ObjectType::DirMeta);
            if faulty.contains(&meta) {
                direct.entry(meta).or_default().insert(root.commit);
            }
        }
        let mut reads = Slots::new(self.max_outstanding);
        loop {
            while reads.has_room()
                && let Some(dirtree) = queue.pop()
            {
                let name = ObjectName::new(dirtree, ObjectType::DirTree);
                let Some(size) = listing.objects.get(&name).copied() else {
                    continue;
                };
                reads.push(async move { (dirtree, self.read_metadata(name, size).await) });
            }
            let Some((dirtree, read)) = reads.next_ready().await else {
                if queue.is_empty() {
                    break;
                }
                continue;
            };
            let Read::Bytes(bytes) = read? else {
                continue;
            };
            let Ok(view) = DirTreeRef::parse(&bytes) else {
                continue;
            };
            let parent = index[&dirtree];
            for item in view.files() {
                let Ok((_, file)) = item else {
                    break;
                };
                let name = ObjectName::new(file, ObjectType::File);
                if faulty.contains(&name) {
                    holders.entry(name).or_default().push(parent);
                }
            }
            for item in view.dirs() {
                let Ok((_, subtree, submeta)) = item else {
                    break;
                };
                let child = intern(&mut index, &mut queue, subtree);
                edges.push((child, parent));
                let meta = ObjectName::new(submeta, ObjectType::DirMeta);
                if faulty.contains(&meta) {
                    holders.entry(meta).or_default().push(parent);
                }
            }
        }
        edges.sort_unstable();
        edges.dedup();
        let mut visited: HashSet<u32> = HashSet::new();
        let mut stack: Vec<u32> = Vec::new();
        for finding in &mut run.findings {
            let Some(name) = finding.object else {
                continue;
            };
            if !faulty.contains(&name) {
                continue;
            }
            let mut commits = direct.remove(&name).unwrap_or_default();
            visited.clear();
            stack.clear();
            match name.ty {
                ObjectType::DirTree => stack.extend(index.get(&name.checksum)),
                _ => stack.extend(holders.get(&name).into_iter().flatten()),
            }
            while let Some(dirtree) = stack.pop() {
                if !visited.insert(dirtree) {
                    continue;
                }
                if let Some(top) = tops.get(&dirtree) {
                    commits.extend(top.iter().copied());
                }
                let from = edges.partition_point(|(child, _)| *child < dirtree);
                stack.extend(
                    edges[from..]
                        .iter()
                        .take_while(|(child, _)| *child == dirtree)
                        .map(|(_, parent)| *parent),
                );
            }
            finding.commits = commits.into_iter().collect();
        }
        Ok(())
    }

    /// Reads again each object that a `Missing` finding names and that the
    /// listing does not hold, and then the commits of each such object that
    /// is still absent.
    ///
    /// A run with no lock does not stop a writer, and the listing of the 256
    /// fan-out prefixes is no snapshot. An object that a read finds now
    /// makes its finding a note. A finding whose commits are all gone is
    /// dropped. Each read opens the object as a stream, and reads none of
    /// its body.
    async fn fsck_recheck(&self, run: &mut Run) -> Result<()> {
        if run.unlisted.is_empty() {
            return Ok(());
        }
        let mut names: Vec<ObjectName> = run.unlisted.iter().copied().collect();
        names.sort_by_cached_key(object_key);
        let present = self.held_objects(names).await?;
        let mut commits: BTreeSet<Checksum> = BTreeSet::new();
        for finding in &run.findings {
            if let Some(name) = finding.object
                && finding.kind == Missing
                && run.unlisted.contains(&name)
                && !present.contains(&name)
            {
                commits.extend(finding.commits.iter().copied());
            }
        }
        let held = self
            .held_objects(
                commits
                    .into_iter()
                    .map(|commit| ObjectName::new(commit, ObjectType::Commit))
                    .collect(),
            )
            .await?;
        let unlisted = &run.unlisted;
        run.findings.retain_mut(|finding| {
            let Some(name) = finding.object else {
                return true;
            };
            if finding.kind != Missing || !unlisted.contains(&name) {
                return true;
            }
            if present.contains(&name) {
                finding.error = false;
                finding.detail = "the listing does not hold the object, and a read after the \
                                  listing finds it: a writer changed the bucket during the run"
                    .to_owned();
                return true;
            }
            if finding.commits.is_empty() {
                return true;
            }
            finding
                .commits
                .retain(|commit| held.contains(&ObjectName::new(*commit, ObjectType::Commit)));
            !finding.commits.is_empty()
        });
        Ok(())
    }

    /// Returns each object of `names` whose key holds an object now, by the
    /// strict rule of an absent key, at most `max_outstanding` reads at a
    /// time.
    ///
    /// Each read opens the object as a stream and drops it, so the read
    /// takes none of its body.
    async fn held_objects(&self, names: Vec<ObjectName>) -> Result<HashSet<ObjectName>> {
        let mut held = HashSet::new();
        let bucket = &self.bucket;
        each_slot(
            self.max_outstanding,
            names.into_iter().map(|name| async move {
                let stream = bucket.get_stream_strict(&object_key(&name)).await?;
                Ok((name, stream.is_some()))
            }),
            |(name, present)| {
                if present {
                    held.insert(name);
                }
            },
        )
        .await?;
        Ok(held)
    }

    /// Writes and deletes the partial-commit markers, and deletes the bad
    /// objects, under `lock`. `whole` holds the commits whose marker the run
    /// deletes.
    async fn fsck_repair(
        &self,
        run: &mut Run,
        refs: &BucketRefs,
        partial: &BTreeSet<Checksum>,
        whole: &[Checksum],
        lock: &WriterLock<'_>,
    ) -> Result<()> {
        let plan = delete_plan(&run.findings, partial);
        if plan == DeletePlan::default() && whole.is_empty() {
            return Ok(());
        }
        let mut named: HashMap<Checksum, Vec<String>> = HashMap::new();
        for (key, commit) in ref_entries(refs) {
            named.entry(commit).or_default().push(key);
        }
        for keys in named.values_mut() {
            keys.sort();
        }
        lock.check().await?;
        run.changed = true;
        let bucket = &self.bucket;
        let max = self.max_outstanding;
        let report = &mut run.report;
        let marked = each_slot(
            max,
            plan.markers.iter().map(|commit| async move {
                bucket
                    .put(&marker_key(commit), vec![PARTIAL_STATE_BYTE])
                    .await?;
                Ok(*commit)
            }),
            |commit| {
                let keys = named.get(&commit).cloned().unwrap_or_default();
                report.marked_partial.push((commit, keys));
            },
        )
        .await;
        report.marked_partial.sort();
        marked?;
        let cleared = each_slot(
            max,
            whole.iter().map(|commit| async move {
                bucket.delete(&marker_key(commit)).await?;
                Ok(*commit)
            }),
            |commit| report.cleared_partial.push(commit),
        )
        .await;
        report.cleared_partial.sort();
        cleared?;
        if plan.commits.is_empty() && plan.tree.is_empty() && plan.images.is_empty() {
            return Ok(());
        }
        lock.check().await?;
        for group in [&plan.commits, &plan.tree, &plan.images] {
            let start = report.deleted.len();
            let deleted = each_slot(
                max,
                group.iter().map(|name| async move {
                    bucket.delete(&object_key(name)).await?;
                    Ok(*name)
                }),
                |name| {
                    report.deleted.push(object_key(&name));
                    if name.ty == ObjectType::Commit
                        && let Some(keys) = named.get(&name.checksum)
                    {
                        report
                            .deleted_ref_targets
                            .push((name.checksum, keys.clone()));
                    }
                },
            )
            .await;
            report.deleted[start..].sort();
            report.deleted_ref_targets.sort();
            deleted?;
        }
        Ok(())
    }
}

/// Returns the number of the dirtree `tree` in `index`, and gives a new
/// dirtree the next number and puts it in `queue`.
fn intern(index: &mut HashMap<Checksum, u32>, queue: &mut Vec<Checksum>, tree: Checksum) -> u32 {
    let next = u32::try_from(index.len()).expect("fewer than 2^32 dirtrees");
    *index.entry(tree).or_insert_with(|| {
        queue.push(tree);
        next
    })
}

/// Returns the parse of the commit object `bytes`.
fn parse_commit(bytes: &[u8]) -> std::result::Result<Commit, String> {
    Commit::parse(bytes).map_err(|e| e.to_string())
}

/// Returns the objects that the dirtree object `bytes` names.
fn parse_dirtree(bytes: &[u8]) -> std::result::Result<Children, String> {
    let tree = DirTree::parse(bytes).map_err(|e| e.to_string())?;
    Ok((
        tree.files.into_iter().map(|(_, file)| file).collect(),
        tree.dirs
            .into_iter()
            .map(|(_, subtree, submeta)| (subtree, submeta))
            .collect(),
    ))
}

/// Checks the parse of the dirmeta object `bytes`. A dirmeta names no
/// object.
fn parse_dirmeta(bytes: &[u8]) -> std::result::Result<Children, String> {
    DirMetaRef::parse(bytes)
        .map(|_| (Vec::new(), Vec::new()))
        .map_err(|e| e.to_string())
}

/// Returns the plan of `--delete` for `findings`, with the commits of
/// `partial`, which hold a marker.
///
/// The bad objects are the objects of the `Mismatch` and the `Corrupt`
/// findings. Each commit that reaches a tree object of a `Missing`, a
/// `Mismatch`, or a `Corrupt` finding gets a marker, unless it holds one or
/// its own object is bad.
fn delete_plan(findings: &[BucketFinding], partial: &BTreeSet<Checksum>) -> DeletePlan {
    let mut plan = DeletePlan::default();
    let mut markers = BTreeSet::new();
    for finding in findings {
        let Some(name) = finding.object else {
            continue;
        };
        if !matches!(finding.kind, Missing | Mismatch | Corrupt) {
            continue;
        }
        if is_tree_object(name.ty) {
            markers.extend(finding.commits.iter().copied());
        }
        if finding.kind == Missing {
            continue;
        }
        match name.ty {
            ObjectType::Commit => plan.commits.push(name),
            ObjectType::ComposefsImage => plan.images.push(name),
            ty if is_tree_object(ty) => plan.tree.push(name),
            _ => {}
        }
    }
    for list in [&mut plan.commits, &mut plan.tree, &mut plan.images] {
        list.sort_by_cached_key(object_key);
        list.dedup();
    }
    // Each name of `plan.commits` is a commit, so the order of the keys is
    // the order of the checksums.
    plan.markers = markers
        .into_iter()
        .filter(|commit| {
            !partial.contains(commit)
                && plan
                    .commits
                    .binary_search_by_key(commit, |name| name.checksum)
                    .is_err()
        })
        .collect();
    plan
}

/// Returns each commit of `roots` with a marker in `partial` whose tree has
/// no `Missing`, no `Mismatch`, and no `Corrupt` finding in `findings`, and
/// whose own object has none, sorted.
///
/// A finding on a tree object that names no commit leaves each marker, as
/// the run cannot tell its commits.
fn whole_marked(
    findings: &[BucketFinding],
    roots: &[Root],
    partial: &BTreeSet<Checksum>,
) -> Vec<Checksum> {
    let mut faulty: HashSet<Checksum> = HashSet::new();
    for finding in findings {
        let Some(name) = finding.object else {
            continue;
        };
        if !matches!(finding.kind, Missing | Mismatch | Corrupt) {
            continue;
        }
        if name.ty == ObjectType::Commit {
            faulty.insert(name.checksum);
        } else if is_tree_object(name.ty) {
            if finding.commits.is_empty() {
                return Vec::new();
            }
            faulty.extend(finding.commits.iter().copied());
        }
    }
    roots
        .iter()
        .map(|root| root.commit)
        .filter(|commit| partial.contains(commit) && !faulty.contains(commit))
        .collect()
}

/// Returns `true` for the type of an object of the tree of a commit.
fn is_tree_object(ty: ObjectType) -> bool {
    matches!(
        ty,
        ObjectType::DirTree | ObjectType::DirMeta | ObjectType::File
    )
}

/// Returns `true` if a commit of the listing reaches the object `name`.
fn is_reached(
    name: &ObjectName,
    seen: &HashSet<ObjectName>,
    files: &HashSet<Checksum>,
    listing: &ObjectListing,
) -> bool {
    match name.ty {
        ObjectType::Commit => true,
        ObjectType::DirTree | ObjectType::DirMeta => seen.contains(name),
        ObjectType::File => files.contains(&name.checksum),
        ObjectType::CommitMeta | ObjectType::ComposefsImage => listing
            .objects
            .contains_key(&ObjectName::new(name.checksum, ObjectType::Commit)),
        _ => false,
    }
}

/// Returns each ref of `refs` as its key and its commit.
fn ref_entries(refs: &BucketRefs) -> impl Iterator<Item = (String, Checksum)> + '_ {
    refs.heads
        .iter()
        .map(|(name, commit)| (format!("refs/heads/{name}"), *commit))
        .chain(refs.mirrors.iter().flat_map(|(id, dir)| {
            dir.iter()
                .map(move |(name, commit)| (format!("refs/mirrors/{id}/{name}"), *commit))
        }))
}

/// Returns the detail of an object over [`MAX_METADATA_SIZE`].
fn too_large() -> String {
    format!("the object is larger than {MAX_METADATA_SIZE} bytes")
}

/// Records a `Summary` error.
fn summary_error(run: &mut Run, detail: String) {
    run.add(BucketFindingKind::Summary, true, "summary", detail);
}

/// Records the `Summary` error of `summary` or `summary.sig` at `key` that is
/// larger than the read cap of a summary.
fn too_large_summary(run: &mut Run, key: &str) {
    run.add(
        BucketFindingKind::Summary,
        true,
        key,
        format!("is larger than {SUMMARY_READ_CAP} bytes"),
    );
}

/// Returns the first names of `names`, joined, and the count of the others.
fn named_list(names: &[String]) -> String {
    let shown: Vec<String> = names
        .iter()
        .take(MAX_NAMED_DIFFERENCES)
        .map(|name| name.escape_debug().to_string())
        .collect();
    let mut text = shown.join(", ");
    if names.len() > MAX_NAMED_DIFFERENCES {
        text.push_str(&format!(
            ", and {} more",
            names.len() - MAX_NAMED_DIFFERENCES
        ));
    }
    text
}

/// Returns an error on the composefs image `name`.
fn image_finding(kind: BucketFindingKind, name: ObjectName, detail: String) -> BucketFinding {
    BucketFinding {
        kind,
        error: true,
        key: object_key(&name),
        object: Some(name),
        commits: Vec::new(),
        detail,
    }
}

/// Checks the content object `checksum` from its stream `stream`.
async fn content_verdict<R: AsyncRead + Unpin>(
    checksum: &Checksum,
    stream: R,
    buf: &mut Vec<u8>,
) -> Verdict {
    let (header, declared, _, stream) = match read_archive_header(stream).await {
        Ok(read) => read,
        Err(e) => return Verdict::Corrupt(format!("the archive header does not read: {e}")),
    };
    if header.is_symlink() {
        if declared != 0 {
            return Verdict::Corrupt(format!("a symlink declares a payload of {declared} bytes"));
        }
        if let Err(e) = check_stream_end(checksum, "symlink header", stream).await {
            return Verdict::Corrupt(e.to_string());
        }
        return match ContentHasher::new(&header) {
            Ok(hasher) => match hasher.finish() {
                actual if actual == *checksum => Verdict::Good,
                actual => Verdict::Mismatch(actual),
            },
            Err(e) => Verdict::Corrupt(e.to_string()),
        };
    }
    if buf.len() < COPY_CHUNK {
        buf.resize(COPY_CHUNK, 0);
    }
    let source = BoundedInput::new(stream, *checksum, compressed_bound(declared));
    match check_archive_payload(checksum, &header, declared, source, buf)
        .await
        .map_err(payload_refusal)
    {
        Ok(()) => Verdict::Good,
        Err(Error::ChecksumMismatch { actual, .. }) => Verdict::Mismatch(actual),
        Err(e) => Verdict::Corrupt(e.to_string()),
    }
}

/// The body of an object, with a count of its bytes and the first failure
/// of the body in transit.
///
/// A check reads the body through this reader, so the run tells a body that
/// failed in transit from an object whose bytes are bad.
struct Transit<R> {
    inner: R,
    /// The bytes that the body gave.
    bytes: u64,
    /// The first error of the body.
    failure: Option<std::io::Error>,
}

impl<R> Transit<R> {
    fn new(inner: R) -> Transit<R> {
        Transit {
            inner,
            bytes: 0,
            failure: None,
        }
    }

    /// Returns the result of a check whose verdict is `verdict`: the failure
    /// in transit if the body failed, else the verdict.
    fn finish<T>(self, verdict: T) -> Checked<T> {
        match self.failure {
            Some(e) => Checked::Transit(e, self.bytes),
            None => Checked::Done(verdict, self.bytes),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Transit<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        match ready!(Pin::new(&mut me.inner).poll_read(cx, buf)) {
            Ok(n) => {
                me.bytes += n as u64;
                Poll::Ready(Ok(n))
            }
            Err(e) => {
                let copy = std::io::Error::new(e.kind(), e.to_string());
                me.failure.get_or_insert(e);
                Poll::Ready(Err(copy))
            }
        }
    }
}

/// A compile-time check that the future of a run is `Send`.
const _: fn() = || {
    fn assert_send<T: Send>(_: &T) {}
    let _ = |repo: &BucketRepo, opts: &BucketFsckOptions| assert_send(&repo.fsck(opts));
};

#[cfg(test)]
mod tests {
    use super::*;

    fn csum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    fn found(kind: BucketFindingKind, ty: ObjectType, object: u8, commits: &[u8]) -> BucketFinding {
        let name = ObjectName::new(csum(object), ty);
        BucketFinding {
            kind,
            error: true,
            key: object_key(&name),
            object: Some(name),
            commits: commits.iter().map(|byte| csum(*byte)).collect(),
            detail: String::new(),
        }
    }

    #[test]
    fn the_repair_marks_the_commits_of_bad_tree_objects_and_deletes_the_bad_objects() {
        let findings = [
            found(Missing, ObjectType::File, 10, &[1, 2]),
            found(Mismatch, ObjectType::DirTree, 11, &[3]),
            found(Corrupt, ObjectType::File, 12, &[4]),
            found(Mismatch, ObjectType::Commit, 2, &[]),
            found(Corrupt, ObjectType::Commit, 5, &[]),
            found(Mismatch, ObjectType::ComposefsImage, 6, &[6]),
            found(Missing, ObjectType::DirMeta, 13, &[1, 7]),
            BucketFinding {
                kind: Stray,
                error: true,
                key: "objects/abc".into(),
                object: None,
                commits: Vec::new(),
                detail: String::new(),
            },
        ];
        let partial: BTreeSet<Checksum> = [csum(7)].into();
        let plan = delete_plan(&findings, &partial);
        // `2` is a bad commit object, and `7` has a marker. The commit of an
        // image gets no marker.
        assert_eq!(plan.markers, [csum(1), csum(3), csum(4)]);
        assert_eq!(
            plan.commits,
            [
                ObjectName::new(csum(2), ObjectType::Commit),
                ObjectName::new(csum(5), ObjectType::Commit),
            ]
        );
        assert_eq!(
            plan.tree,
            [
                ObjectName::new(csum(11), ObjectType::DirTree),
                ObjectName::new(csum(12), ObjectType::File),
            ]
        );
        assert_eq!(
            plan.images,
            [ObjectName::new(csum(6), ObjectType::ComposefsImage)]
        );
        assert_eq!(delete_plan(&[], &partial), DeletePlan::default());
    }

    #[test]
    fn a_marker_goes_only_for_a_walked_commit_with_no_finding_in_its_tree() {
        let root = |commit: u8| Root {
            commit: csum(commit),
            dirtree: csum(100 + commit),
            dirmeta: csum(200),
        };
        let roots = [root(1), root(2), root(3), root(4), root(5)];
        // `6` has a marker and is not walked.
        let partial: BTreeSet<Checksum> = [1, 2, 3, 4, 6].map(csum).into();
        let findings = [
            found(Missing, ObjectType::File, 10, &[2]),
            found(Mismatch, ObjectType::Commit, 3, &[]),
            found(Mismatch, ObjectType::ComposefsImage, 4, &[4]),
        ];
        // The image of `4` is no object of its tree.
        assert_eq!(
            whole_marked(&findings, &roots, &partial),
            [csum(1), csum(4)]
        );
        assert_eq!(whole_marked(&[], &roots, &partial), [1, 2, 3, 4].map(csum));
        // A tree finding with no commit leaves each marker.
        let unknown = [found(Corrupt, ObjectType::DirTree, 11, &[])];
        assert!(whole_marked(&unknown, &roots, &partial).is_empty());
    }

    #[test]
    fn a_finding_is_one_line_with_its_commits() {
        let mut finding = found(Missing, ObjectType::File, 10, &[1, 2]);
        finding.detail = "the listing does not hold the object".into();
        assert_eq!(
            finding.to_string(),
            format!(
                "missing {}: the listing does not hold the object; in commits {}, {}",
                finding.key,
                csum(1),
                csum(2)
            )
        );
        let note = BucketFinding {
            kind: Upload,
            error: false,
            key: "objects/ab/c\n".into(),
            object: None,
            commits: Vec::new(),
            detail: "an incomplete multipart upload".into(),
        };
        assert_eq!(
            note.to_string(),
            "upload objects/ab/c\\n: an incomplete multipart upload"
        );
    }

    #[test]
    fn each_kind_has_a_name_and_the_kinds_sort_in_the_order_of_the_checks() {
        let kinds = [
            (Config, "config"),
            (Ref, "ref"),
            (BucketFindingKind::Summary, "summary"),
            (Stray, "stray"),
            (Missing, "missing"),
            (Mismatch, "mismatch"),
            (Corrupt, "corrupt"),
            (Marker, "marker"),
            (Upload, "upload"),
            (Lock, "lock"),
        ];
        for pair in kinds.windows(2) {
            assert!(pair[0].0 < pair[1].0);
        }
        for (kind, name) in kinds {
            assert_eq!(kind.as_str(), name);
            assert_eq!(kind.to_string(), name);
        }
    }

    #[test]
    fn a_report_has_errors_only_with_an_error_finding() {
        let mut report = BucketFsckReport::default();
        assert!(!report.has_errors());
        let mut note = found(Missing, ObjectType::File, 1, &[]);
        note.error = false;
        report.findings.push(note);
        assert!(!report.has_errors());
        report
            .findings
            .push(found(Missing, ObjectType::File, 2, &[]));
        assert!(report.has_errors());
    }

    #[test]
    fn a_long_list_of_names_gives_the_count_of_the_others() {
        let names: Vec<String> = (0..12).map(|n| format!("refs/heads/r{n:02}")).collect();
        let text = named_list(&names);
        assert!(text.starts_with("refs/heads/r00, refs/heads/r01"), "{text}");
        assert!(text.ends_with("refs/heads/r09, and 2 more"), "{text}");
        assert_eq!(named_list(&names[..1]), "refs/heads/r00");
    }
}
