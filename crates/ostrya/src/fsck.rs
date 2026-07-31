//! Object-integrity and completeness checking.
//!
//! [`Repo::fsck`] enumerates every commit in the store and walks the objects
//! reachable from each, verifying two things (the checks the `ostree fsck` tool
//! performs, recovered by black-box observation):
//!
//! - Integrity: each object's recomputed checksum equals its name. A metadata
//!   object is hashed over its serialized bytes; a content object is hashed over
//!   its framed uncompressed header and uncompressed payload, so a corrupt
//!   `.filez` or a tampered `.file` is caught in every mode.
//! - Completeness: every referenced object is present. A referenced object that
//!   is absent is reported, and the commit that referenced it is marked partial
//!   by writing its `state/<commit>.commitpartial` marker, matching the tool.
//!
//! The result is a [`FsckReport`]; a corrupt repository does not fail the call,
//! it populates [`errors`](FsckReport::errors). A caller (or the CLI) turns a
//! non-empty report into a failure.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::Write;
use std::os::fd::BorrowedFd;
use std::pin::Pin;

use futures_lite::AsyncReadExt;
use ostrya_core::{Checksum, Commit, ContentHasher, DirTree, ObjectName, ObjectType};
use rustix::fs::{Mode, OFlags};

use crate::error::{Error, Result};
use crate::repo::Repo;

/// The single byte the tool writes into a `.commitpartial` marker when fsck
/// finds a commit incomplete (recovered by observation).
const PARTIAL_STATE_BYTE: u8 = 0x66;

/// The chunk size for streaming a content object's payload through the hasher.
const READ_CHUNK: usize = 128 * 1024;

/// Options controlling [`Repo::fsck`].
#[derive(Debug, Clone)]
pub struct FsckOptions {
    /// Write a `state/<commit>.commitpartial` marker for any commit found to be
    /// missing a referenced object, matching the tool. Enabled by default.
    pub mark_partial: bool,
}

impl Default for FsckOptions {
    fn default() -> Self {
        FsckOptions { mark_partial: true }
    }
}

impl FsckOptions {
    /// The default options (partial-marking enabled).
    pub fn new() -> FsckOptions {
        FsckOptions::default()
    }
}

/// Why one object failed fsck.
#[derive(Debug, Clone)]
pub enum FsckErrorKind {
    /// The object is referenced but absent from the store.
    Missing,
    /// The object is present but its recomputed checksum differs from its name.
    ChecksumMismatch {
        /// The checksum the object's bytes actually hash to.
        actual: Checksum,
    },
    /// The object is present but could not be parsed or read.
    Corrupt(String),
}

/// One fsck finding: the object at fault and why.
#[derive(Debug, Clone)]
pub struct FsckError {
    /// The object the finding concerns.
    pub object: ObjectName,
    /// The nature of the fault.
    pub kind: FsckErrorKind,
}

impl std::fmt::Display for FsckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            FsckErrorKind::Missing => write!(f, "missing object {}", self.object),
            FsckErrorKind::ChecksumMismatch { actual } => write!(
                f,
                "corrupted object {}: checksum expected {}, computed {}",
                self.object, self.object.checksum, actual
            ),
            FsckErrorKind::Corrupt(detail) => {
                write!(f, "corrupted object {}: {detail}", self.object)
            }
        }
    }
}

/// The outcome of a [`Repo::fsck`] run.
#[derive(Debug, Clone)]
pub struct FsckReport {
    /// The number of commit objects walked.
    pub commits_checked: usize,
    /// The number of distinct objects examined.
    pub objects_checked: usize,
    /// The findings, one per faulty object.
    pub errors: Vec<FsckError>,
}

impl FsckReport {
    /// Whether the repository passed with no findings.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// The mutable state threaded through one fsck run.
#[derive(Default)]
struct Ctx {
    /// Every referenced object, present or not (the examined-object count).
    seen: HashSet<ObjectName>,
    /// Metadata objects whose checksum was recomputed and matched, so they are
    /// not re-hashed when reached again from another commit.
    checked_ok: HashSet<ObjectName>,
    /// Memoized per content object: whether it is missing. A content object
    /// reached again from another commit returns its cached outcome instead of
    /// being re-read and re-hashed, whether it passed, failed, or was absent.
    content_examined: HashMap<Checksum, bool>,
    /// Memoized per dirtree: whether its subtree (the dirtree, its dirmetas,
    /// files, and nested subtrees) references any missing object. A subtree
    /// shared between commits is walked once but still contributes its missing
    /// state to every commit that reaches it.
    dirtree_missing: HashMap<Checksum, bool>,
    /// Objects a finding has already been recorded for, to report each once.
    reported: HashSet<ObjectName>,
    /// The findings.
    errors: Vec<FsckError>,
}

/// The result of verifying one metadata object during the walk.
enum VerifyMeta {
    /// The object is present; its serialized bytes are returned for parsing. Its
    /// checksum has been verified (a mismatch is already recorded).
    Present(Vec<u8>),
    /// The object is referenced but absent, which makes the referencing commit
    /// partial.
    Missing,
    /// The object is present but could not be read; recorded as corruption,
    /// which does not make the commit partial.
    Unreadable,
}

impl Ctx {
    /// Record one finding, at most once per object.
    fn record(&mut self, object: ObjectName, kind: FsckErrorKind) {
        if self.reported.insert(object) {
            self.errors.push(FsckError { object, kind });
        }
    }
}

impl Repo {
    /// Verify object integrity and completeness across every commit in the
    /// store.
    pub async fn fsck(&self, opts: &FsckOptions) -> Result<FsckReport> {
        let all = self.list_objects().await?;
        let mut ctx = Ctx::default();

        // Validate refs: a ref pointing at an absent commit is a finding.
        for target in self.list_all_ref_targets().await? {
            let name = ObjectName::new(target, ObjectType::Commit);
            if !all.contains(&name) {
                ctx.seen.insert(name);
                ctx.record(name, FsckErrorKind::Missing);
            }
        }

        // The roots are every commit object present, walked in a deterministic
        // order.
        let mut commit_roots: Vec<Checksum> = all
            .iter()
            .filter(|o| o.ty == ObjectType::Commit)
            .map(|o| o.checksum)
            .collect();
        commit_roots.sort();

        let commits_checked = commit_roots.len();
        for commit in commit_roots {
            self.fsck_walk_commit(commit, opts, &mut ctx).await?;
        }

        Ok(FsckReport {
            commits_checked,
            objects_checked: ctx.seen.len(),
            errors: ctx.errors,
        })
    }

    /// Walk one commit's reachable objects, verifying each. A commit that turns
    /// out to be missing a referenced object is marked partial when the option
    /// is set.
    async fn fsck_walk_commit(
        &self,
        commit: Checksum,
        opts: &FsckOptions,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let mut had_missing = false;
        let commit_name = ObjectName::new(commit, ObjectType::Commit);

        match self.fsck_verify_metadata(commit_name, ctx).await? {
            VerifyMeta::Present(bytes) => match Commit::parse(&bytes) {
                Ok(parsed) => {
                    let root_dirmeta = ObjectName::new(parsed.root_dirmeta, ObjectType::DirMeta);
                    if matches!(
                        self.fsck_verify_metadata(root_dirmeta, ctx).await?,
                        VerifyMeta::Missing
                    ) {
                        had_missing = true;
                    }
                    if fsck_walk_subtree(self, parsed.root_dirtree, ctx).await? {
                        had_missing = true;
                    }
                }
                Err(e) => ctx.record(commit_name, FsckErrorKind::Corrupt(e.to_string())),
            },
            VerifyMeta::Missing => had_missing = true,
            VerifyMeta::Unreadable => {}
        }

        if had_missing && opts.mark_partial {
            self.mark_commit_partial(&commit).await?;
        }
        Ok(())
    }

    /// Verify one metadata object's checksum, reporting a mismatch, a missing
    /// object, or an unreadable one.
    async fn fsck_verify_metadata(&self, name: ObjectName, ctx: &mut Ctx) -> Result<VerifyMeta> {
        ctx.seen.insert(name);
        match self.load_object_bytes(name.ty, &name.checksum).await {
            Ok(bytes) => {
                if !ctx.checked_ok.contains(&name) {
                    let actual = Checksum::sha256(&bytes);
                    if actual == name.checksum {
                        ctx.checked_ok.insert(name);
                    } else {
                        ctx.record(name, FsckErrorKind::ChecksumMismatch { actual });
                    }
                }
                Ok(VerifyMeta::Present(bytes))
            }
            Err(Error::ObjectNotFound { .. }) => {
                ctx.record(name, FsckErrorKind::Missing);
                Ok(VerifyMeta::Missing)
            }
            // A read failure is reported as corruption rather than aborting the
            // whole check.
            Err(Error::Io(e)) => {
                ctx.record(name, FsckErrorKind::Corrupt(e.to_string()));
                Ok(VerifyMeta::Unreadable)
            }
            Err(e) => Err(e),
        }
    }

    /// Verify one content object, returning whether it is missing (which makes
    /// the referencing commit partial). The outcome is memoized, so a content
    /// object reached again from another commit is not re-read and re-hashed.
    async fn fsck_verify_content(&self, checksum: Checksum, ctx: &mut Ctx) -> Result<bool> {
        let name = ObjectName::new(checksum, ObjectType::File);
        ctx.seen.insert(name);
        if let Some(&missing) = ctx.content_examined.get(&checksum) {
            return Ok(missing);
        }
        let missing = self.fsck_hash_content(name, ctx).await?;
        ctx.content_examined.insert(checksum, missing);
        Ok(missing)
    }

    /// Load a content object, hash its framed header and streamed payload, and
    /// compare with its name, recording any fault. Returns whether the object is
    /// missing.
    async fn fsck_hash_content(&self, name: ObjectName, ctx: &mut Ctx) -> Result<bool> {
        let checksum = name.checksum;
        let file = match self.load_file(&checksum).await {
            Ok(file) => file,
            Err(Error::ObjectNotFound { .. }) => {
                ctx.record(name, FsckErrorKind::Missing);
                return Ok(true);
            }
            Err(Error::Io(e)) => {
                ctx.record(name, FsckErrorKind::Corrupt(e.to_string()));
                return Ok(false);
            }
            Err(Error::InvalidFormat(m)) => {
                ctx.record(name, FsckErrorKind::Corrupt(m));
                return Ok(false);
            }
            Err(Error::Core(e)) => {
                ctx.record(name, FsckErrorKind::Corrupt(e.to_string()));
                return Ok(false);
            }
            Err(e) => return Err(e),
        };

        let mut hasher = ContentHasher::new(&file.header())?;

        let mut reader = file.reader().await?;
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(e) => {
                    ctx.record(
                        name,
                        FsckErrorKind::Corrupt(format!("payload read failed: {e}")),
                    );
                    return Ok(false);
                }
            }
        }

        let actual = hasher.finish();
        if actual != checksum {
            ctx.record(name, FsckErrorKind::ChecksumMismatch { actual });
        }
        Ok(false)
    }

    /// Write a commit's `state/<commit>.commitpartial` marker.
    async fn mark_commit_partial(&self, commit: &Checksum) -> Result<()> {
        let path = crate::pull::partial_path(commit);
        let repo = self.clone();
        ostrya_rt::unblock(move || write_partial_marker(repo.repo_fd(), &path)).await
    }
}

/// The boxed future type for the recursive subtree walk. Async recursion needs
/// indirection, so each level returns a boxed future.
type SubtreeFuture<'a> = Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>>;

/// Verify a dirtree and everything beneath it, returning whether the subtree
/// references any missing object. Each dirtree's result is memoized so a subtree
/// shared between commits is verified once, yet its missing state still reaches
/// every commit that references it. A missing dirtree makes its subtree missing;
/// a present-but-corrupt one is recorded and its subtree treated as complete,
/// since its children cannot be enumerated.
fn fsck_walk_subtree<'a>(repo: &'a Repo, dt: Checksum, ctx: &'a mut Ctx) -> SubtreeFuture<'a> {
    Box::pin(async move {
        if let Some(&missing) = ctx.dirtree_missing.get(&dt) {
            return Ok(missing);
        }
        let name = ObjectName::new(dt, ObjectType::DirTree);
        let missing = match repo.fsck_verify_metadata(name, ctx).await? {
            VerifyMeta::Missing => true,
            VerifyMeta::Unreadable => false,
            VerifyMeta::Present(bytes) => match DirTree::parse(&bytes) {
                Ok(dirtree) => {
                    let mut missing = false;
                    for (_, file) in dirtree.files {
                        missing |= repo.fsck_verify_content(file, ctx).await?;
                    }
                    for (_, subtree, submeta) in dirtree.dirs {
                        let sub_meta = ObjectName::new(submeta, ObjectType::DirMeta);
                        if matches!(
                            repo.fsck_verify_metadata(sub_meta, ctx).await?,
                            VerifyMeta::Missing
                        ) {
                            missing = true;
                        }
                        missing |= fsck_walk_subtree(repo, subtree, ctx).await?;
                    }
                    missing
                }
                Err(e) => {
                    ctx.record(name, FsckErrorKind::Corrupt(e.to_string()));
                    false
                }
            },
        };
        ctx.dirtree_missing.insert(dt, missing);
        Ok(missing)
    })
}

/// Create or truncate a `.commitpartial` marker holding the single state byte
/// the tool writes.
fn write_partial_marker(repo_fd: BorrowedFd<'_>, path: &str) -> Result<()> {
    let fd = rustix::fs::openat(
        repo_fd,
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )?;
    std::fs::File::from(fd)
        .write_all(&[PARTIAL_STATE_BYTE])
        .map_err(Error::Io)
}
