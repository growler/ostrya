//! Object-integrity and completeness checking.
//!
//! [`Repo::fsck`] runs the four phases the `ostree fsck` tool runs, recovered by
//! black-box observation and recorded in `docs/format-reference.md`, "CLI output
//! formats", `fsck`:
//!
//! 1. Validate refs. Every ref under `refs/heads` and `refs/remotes` names a
//!    commit object, which is loaded and checksummed. Under
//!    [`verify_bindings`](FsckOptions::verify_bindings) the commit must carry
//!    that ref's name in its `ostree.ref-binding`.
//! 2. Validate refs in collections. Under
//!    [`verify_bindings`](FsckOptions::verify_bindings) every
//!    collection-qualified ref's commit must carry that collection id in its
//!    `ostree.collection-binding`.
//! 3. Enumerate commits. Every commit object in the store is listed, and the
//!    ones already carrying a `state/<commit>.commitpartial` marker are skipped.
//!    Under [`verify_back_refs`](FsckOptions::verify_back_refs) every name in a
//!    commit's `ostree.ref-binding` must name a ref that resolves to that
//!    commit.
//! 4. Verify content integrity. Every object the verified commits reference is
//!    examined once:
//!
//!    - Integrity: each object's recomputed checksum equals its name. A metadata
//!      object is hashed over its serialized bytes; a content object is hashed
//!      over its framed uncompressed header and uncompressed payload, so a
//!      corrupt `.filez` or a tampered `.file` is caught in every mode.
//!    - Completeness: every referenced object is present. A referenced object
//!      that is absent is reported, and every commit that reaches it is marked
//!      partial by writing its `state/<commit>.commitpartial` marker.
//!
//! A run ends early at three conditions. A ref over a commit object the store
//! does not hold and a dirtree that is absent each leave the run unable to read
//! what it must read next. A binding check that fails states a fact about the
//! ref graph rather than about an object, and marks nothing. Every other fault
//! is recorded and the run goes on, so one run reports every fault it can reach
//! (`docs/conformance/cli-surface.md`, "fsck").
//!
//! One step follows the four phases. Under
//! [`add_tombstones`](FsckOptions::add_tombstones) every commit object whose
//! parent commit object is absent is deleted and a `.tombstone-commit` naming
//! it is written. The step writes to the repository, so it acts after a walk
//! that found a corrupt object only under [`all`](FsckOptions::all) or
//! [`delete`](FsckOptions::delete). A walk whose findings are absent objects
//! alone, and a walk with no finding, reach the step on their own.
//!
//! The result is a [`FsckReport`]; a corrupt repository does not fail the call,
//! it populates [`errors`](FsckReport::errors) and
//! [`failure`](FsckReport::failure). A caller (or the CLI) turns a non-empty
//! report into a failure.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::Write;
use std::os::fd::BorrowedFd;
use std::pin::Pin;

use futures_lite::AsyncReadExt;
use ostrya_core::{
    Checksum, Commit, ContentHasher, DirMetaRef, DirTree, DirTreeRef, ObjectName, ObjectType,
    RepoMode,
};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::perm;
use crate::refs::CollectionRefEntry;
use crate::repo::Repo;
use crate::tombstone::write_tombstone;
use crate::write::COPY_CHUNK;

/// The single byte the tool writes into a `.commitpartial` marker when fsck
/// finds a commit incomplete (recovered by observation).
const PARTIAL_STATE_BYTE: u8 = 0x66;

/// Options controlling [`Repo::fsck`].
#[derive(Debug, Clone)]
pub struct FsckOptions {
    /// Write a `state/<commit>.commitpartial` marker for any commit that
    /// reaches an object the run found missing or deleted, matching the tool.
    /// Enabled by default. Clearing it is a port extension, which the CLI
    /// spells `--no-mark-partial`.
    pub mark_partial: bool,
    /// Unlink every object whose recomputed checksum differs from its name,
    /// and mark every commit that reaches one partial
    /// (`ostree fsck --delete`).
    pub delete: bool,
    /// Let the [`add_tombstones`](FsckOptions::add_tombstones) phase run on a
    /// walk that found a corrupt object (`ostree fsck -a`).
    ///
    /// The object walk runs to its end whatever this field carries. The field
    /// selects one thing: whether the destructive tombstone phase is allowed
    /// to act after a walk that found an object whose bytes do not match its
    /// name. `delete` carries the same permission on its own, and a walk whose
    /// findings are absent objects alone needs neither.
    pub all: bool,
    /// Delete every commit object whose parent commit object is absent and
    /// write a `.tombstone-commit` naming it
    /// (`ostree fsck --add-tombstones`).
    pub add_tombstones: bool,
    /// Check that every ref's commit carries that ref in its
    /// `ostree.ref-binding`, and that every collection ref's commit carries
    /// the collection id in its `ostree.collection-binding`
    /// (`ostree fsck --verify-bindings`).
    pub verify_bindings: bool,
    /// Check that every name in a commit's `ostree.ref-binding` names a ref
    /// that resolves to that commit, and that a commit carrying an
    /// `ostree.collection-binding` is named by that collection ref
    /// (`ostree fsck --verify-back-refs`). The check is independent of
    /// `verify_bindings`; naming one runs one.
    pub verify_back_refs: bool,
}

impl Default for FsckOptions {
    fn default() -> Self {
        FsckOptions {
            mark_partial: true,
            delete: false,
            all: false,
            add_tombstones: false,
            verify_bindings: false,
            verify_back_refs: false,
        }
    }
}

impl FsckOptions {
    /// The default options: partial-marking enabled, every other check off.
    pub fn new() -> FsckOptions {
        FsckOptions::default()
    }
}

/// The phases a run passes through, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FsckPhase {
    /// Loading and checksumming each ref's commit object.
    ValidateRefs,
    /// Reading the collection-qualified refs.
    ValidateCollectionRefs,
    /// Listing the commit objects and separating the ones already partial.
    EnumerateCommits,
    /// Walking and verifying the objects the verified commits reference.
    VerifyObjects,
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

/// One fsck finding: the object at fault, why, and which commits reach it.
#[derive(Debug, Clone)]
pub struct FsckError {
    /// The object the finding concerns.
    pub object: ObjectName,
    /// The nature of the fault.
    pub kind: FsckErrorKind,
    /// The verified commits that reach the object, sorted. Empty on a finding
    /// the ref phase made, which reads a commit object a ref names and reaches
    /// no commit through it.
    pub in_commits: Vec<Checksum>,
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

/// A ref-binding or back-reference finding. One of these ends the run at the
/// phase that made it.
#[derive(Debug, Clone)]
pub struct FsckBindingError {
    /// The commit the finding concerns.
    pub commit: Checksum,
    /// What failed.
    pub kind: FsckBindingErrorKind,
}

/// Which binding check failed.
#[derive(Debug, Clone)]
pub enum FsckBindingErrorKind {
    /// The ref phase: the ref is not named in the commit's
    /// `ostree.ref-binding`. `bindings` holds what the commit does carry, in
    /// stored order.
    RefNotBound {
        /// The ref the commit was reached through, by its bare name.
        ref_name: String,
        /// The names the commit's `ostree.ref-binding` carries.
        bindings: Vec<String>,
    },
    /// The collection phase: the commit's `ostree.collection-binding` is not
    /// the collection id the ref was found under.
    CollectionMismatch {
        /// The id the commit's `ostree.collection-binding` carries.
        bound: String,
        /// The collection id the ref was found under.
        found_under: String,
    },
    /// The back-reference check: a bound ref name that names no ref.
    BackRefMissing {
        /// The bound name.
        ref_name: String,
    },
    /// The back-reference check: a bound ref name that names another commit.
    BackRefMismatch {
        /// The bound name.
        ref_name: String,
    },
    /// The back-reference check: a bound collection ref that does not exist.
    BackCollectionRefMissing {
        /// The commit's `ostree.collection-binding`.
        collection_id: String,
        /// The bound name.
        ref_name: String,
    },
    /// The back-reference check: a bound collection ref that names another
    /// commit.
    BackCollectionRefMismatch {
        /// The commit's `ostree.collection-binding`.
        collection_id: String,
        /// The bound name.
        ref_name: String,
    },
}

/// The condition that ended a run before its last phase finished.
#[derive(Debug, Clone)]
pub enum FsckFailure {
    /// A ref names a commit object the store cannot supply.
    RefTarget {
        /// The ref, by its bare name: a remote ref carries no remote prefix
        /// here, matching the tool's own message.
        ref_name: String,
        /// The commit the ref names.
        commit: Checksum,
        /// Whether the run itself removed the object, which `delete` does for
        /// a ref target whose checksum does not match.
        removed: bool,
    },
    /// A dirtree the walk must enumerate is absent, so the subtree beneath it
    /// cannot be read.
    MissingDirTree(Checksum),
    /// A ref-binding or back-reference check failed.
    Binding(FsckBindingError),
}

/// The outcome of a [`Repo::fsck`] run.
#[derive(Debug, Clone)]
pub struct FsckReport {
    /// The last phase the run entered.
    pub reached: FsckPhase,
    /// The commit objects the run verified: every commit in the store that
    /// carried no `.commitpartial` marker when the run started.
    pub commits_checked: usize,
    /// The commit objects the run skipped because they were already marked
    /// partial.
    pub commits_partial: usize,
    /// The distinct objects the verified commits reference, present or absent.
    /// Detached commit metadata is outside the count.
    pub objects_checked: usize,
    /// The findings, one per faulty object, sorted by object checksum.
    pub errors: Vec<FsckError>,
    /// The commits this run marked partial, sorted.
    pub marked_partial: Vec<Checksum>,
    /// The objects this run unlinked under `delete`, sorted.
    pub deleted: Vec<ObjectName>,
    /// The commits this run tombstoned under `add_tombstones`, sorted.
    pub tombstoned: Vec<Checksum>,
    /// The condition that ended the run early, where one did.
    pub failure: Option<FsckFailure>,
}

impl FsckReport {
    /// Whether the repository passed with no findings: no faulty object, no
    /// condition that ended the run, and no commit skipped as already partial.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty() && self.failure.is_none() && self.commits_partial == 0
    }
}

/// The mutable state threaded through one fsck run.
#[derive(Default)]
struct Ctx {
    /// The findings, in the order they were made.
    errors: Vec<FsckError>,
    /// The objects a finding names whose bytes do not parse as the type their
    /// name gives them. The run reports each and acts on none.
    unparsable: HashSet<ObjectName>,
    /// The commits marked partial by this run.
    marked_partial: Vec<Checksum>,
    /// The objects unlinked by this run.
    deleted: HashSet<ObjectName>,
    /// The commits tombstoned by this run.
    tombstoned: Vec<Checksum>,
    /// How many leading entries of `errors` the ref phase made. Those keep an
    /// empty `in_commits`: the ref phase reaches no commit through the object
    /// it read.
    ref_findings: usize,
    /// The commit objects the run verifies, sorted.
    verified: Vec<Checksum>,
    /// The commit objects skipped as already partial.
    commits_partial: usize,
}

impl Ctx {
    /// Record one finding. The commits that reach the object are attributed
    /// after the walk, so the finding starts with none.
    fn record(&mut self, object: ObjectName, kind: FsckErrorKind) {
        self.errors.push(FsckError {
            object,
            kind,
            in_commits: Vec::new(),
        });
    }

    /// Assemble the report.
    fn finish(
        mut self,
        reached: FsckPhase,
        objects_checked: usize,
        failure: Option<FsckFailure>,
    ) -> FsckReport {
        self.errors.sort_by_key(|e| {
            (
                e.object.checksum,
                e.object.ty as u32,
                e.in_commits.is_empty(),
            )
        });
        self.marked_partial.sort();
        let mut deleted: Vec<ObjectName> = self.deleted.into_iter().collect();
        deleted.sort_by_key(|name| (name.checksum, name.ty as u32));
        self.tombstoned.sort();
        FsckReport {
            reached,
            commits_checked: self.verified.len(),
            commits_partial: self.commits_partial,
            objects_checked,
            errors: self.errors,
            marked_partial: self.marked_partial,
            deleted,
            tombstoned: self.tombstoned,
            failure,
        }
    }
}

impl Repo {
    /// Verify object integrity and completeness across every commit in the
    /// store.
    pub async fn fsck(&self, opts: &FsckOptions) -> Result<FsckReport> {
        let mut ctx = Ctx::default();
        // Every phase that reads a ref reads this one listing.
        let (ref_targets, collection_refs) = self.fsck_read_refs().await?;

        // Phase 1: the refs.
        if let Some(failure) = self
            .fsck_validate_refs(&ref_targets, opts, &mut ctx)
            .await?
        {
            return Ok(ctx.finish(FsckPhase::ValidateRefs, 0, Some(failure)));
        }
        ctx.ref_findings = ctx.errors.len();

        // Phase 2: the collection refs.
        if let Some(failure) = self
            .fsck_validate_collection_refs(&collection_refs, opts, &mut ctx)
            .await?
        {
            return Ok(ctx.finish(FsckPhase::ValidateCollectionRefs, 0, Some(failure)));
        }
        ctx.ref_findings = ctx.errors.len();

        // Phase 3: the commit objects.
        let commits = self.list_objects_of_type(ObjectType::Commit).await?;
        if let Some(failure) = self
            .fsck_enumerate_commits(&commits, &ref_targets, &collection_refs, opts, &mut ctx)
            .await?
        {
            return Ok(ctx.finish(
                FsckPhase::EnumerateCommits,
                0,
                Some(FsckFailure::Binding(failure)),
            ));
        }

        // Phase 4: collect the object set the verified commits reference, then
        // verify each object in it.
        let order = match self.fsck_collect_objects(&ctx.verified).await? {
            Ok(order) => order,
            Err(failure) => return Ok(ctx.finish(FsckPhase::VerifyObjects, 0, Some(failure))),
        };
        let objects_checked = order.len();
        self.fsck_verify_objects(&order, &mut ctx).await?;

        // Attribute each finding to the commits that reach it, and act on the
        // findings: unlink under `delete`, and mark partial. The attribution
        // reads the dirtrees again, so it runs before anything is unlinked.
        if !ctx.errors.is_empty() {
            self.fsck_attribute_findings(&mut ctx).await?;
            self.fsck_apply_findings(opts, &mut ctx).await?;
        }

        // The tombstone phase acts on a repository, so it is held to the
        // condition the tool holds it to: a walk that reached its end. A
        // corrupt object ends the tool's walk unless `all` or `delete` carries
        // it on; an absent object never does
        // (`docs/conformance/cli-surface.md`, "fsck").
        let corrupt = ctx
            .errors
            .iter()
            .any(|error| !matches!(error.kind, FsckErrorKind::Missing));
        if opts.add_tombstones && (opts.all || opts.delete || !corrupt) {
            self.fsck_add_tombstones(&commits, &mut ctx).await?;
        }

        Ok(ctx.finish(FsckPhase::VerifyObjects, objects_checked, None))
    }

    /// Read the refs the run needs, once: every ref under `refs/heads` and
    /// `refs/remotes` by the bare name a message gives it, and every
    /// collection-qualified ref.
    ///
    /// A remote ref's refspec carries the remote name ahead of a `:`, which the
    /// tool's own message drops, so the tail alone is kept.
    async fn fsck_read_refs(&self) -> Result<(Vec<(String, Checksum)>, Vec<CollectionRefEntry>)> {
        let heads = self.list_refs(None).await?;
        let collection_refs = self.collection_refs_over(&heads).await?;
        let mut targets = heads;
        for (refspec, commit) in self.list_remote_refs().await? {
            let name = match refspec.split_once(':') {
                Some((_, name)) => name.to_owned(),
                None => refspec,
            };
            targets.push((name, commit));
        }
        Ok((targets, collection_refs))
    }

    /// Phase 1: load and checksum the commit each ref under `refs/heads` and
    /// `refs/remotes` names, and under `verify_bindings` hold each commit to
    /// the ref it was reached through.
    async fn fsck_validate_refs(
        &self,
        targets: &[(String, Checksum)],
        opts: &FsckOptions,
        ctx: &mut Ctx,
    ) -> Result<Option<FsckFailure>> {
        for (name, commit) in targets {
            let commit = *commit;
            let bytes = match self.fsck_check_ref_target(name, commit, opts, ctx).await? {
                Err(failure) => return Ok(Some(failure)),
                Ok(bytes) => bytes,
            };
            if opts.verify_bindings
                && let Some(bytes) = bytes
                && let Ok(parsed) = Commit::parse(&bytes)
                && let Some(kind) = check_ref_binding(&parsed, name)
            {
                return Ok(Some(FsckFailure::Binding(FsckBindingError {
                    commit,
                    kind,
                })));
            }
        }
        Ok(None)
    }

    /// Load and checksum the commit object one ref names.
    ///
    /// `Err` ends the run. `Ok(None)` records a finding and leaves the commit
    /// unread; whether the run continues past it is the caller's check.
    /// `display` is the ref as a message names it.
    async fn fsck_check_ref_target(
        &self,
        display: &str,
        commit: Checksum,
        opts: &FsckOptions,
        ctx: &mut Ctx,
    ) -> Result<std::result::Result<Option<Vec<u8>>, FsckFailure>> {
        let bytes = match self.load_object_bytes(ObjectType::Commit, &commit).await {
            Ok(bytes) => bytes,
            Err(Error::ObjectNotFound { .. }) => {
                return Ok(Err(FsckFailure::RefTarget {
                    ref_name: display.to_owned(),
                    commit,
                    removed: false,
                }));
            }
            Err(e) => return Err(e),
        };
        let actual = Checksum::sha256(&bytes);
        if actual == commit {
            return Ok(Ok(Some(bytes)));
        }
        let object = ObjectName::new(commit, ObjectType::Commit);
        ctx.record(object, FsckErrorKind::ChecksumMismatch { actual });
        if opts.delete {
            self.fsck_unlink_object(object).await?;
            ctx.deleted.insert(object);
            return Ok(Err(FsckFailure::RefTarget {
                ref_name: display.to_owned(),
                commit,
                removed: true,
            }));
        }
        Ok(Ok(None))
    }

    /// Phase 2: load and checksum the commit each collection-qualified ref
    /// names, and under `verify_bindings` hold each commit to the collection id
    /// the ref was found under.
    ///
    /// A local ref qualified by the repository's own collection id was already
    /// read by phase 1, so this phase reads it for its binding alone.
    async fn fsck_validate_collection_refs(
        &self,
        entries: &[CollectionRefEntry],
        opts: &FsckOptions,
        ctx: &mut Ctx,
    ) -> Result<Option<FsckFailure>> {
        for entry in entries {
            let bytes = if entry.local {
                self.load_object_bytes(ObjectType::Commit, &entry.commit)
                    .await
                    .ok()
            } else {
                let display = format!("({}, {})", entry.collection, entry.name);
                match self
                    .fsck_check_ref_target(&display, entry.commit, opts, ctx)
                    .await?
                {
                    Err(failure) => return Ok(Some(failure)),
                    Ok(bytes) => bytes,
                }
            };
            if opts.verify_bindings
                && let Some(bytes) = bytes
                && let Ok(parsed) = Commit::parse(&bytes)
                && let Some(bound) = parsed.collection_binding()
                && bound != entry.collection
            {
                return Ok(Some(FsckFailure::Binding(FsckBindingError {
                    commit: entry.commit,
                    kind: FsckBindingErrorKind::CollectionMismatch {
                        bound: bound.to_owned(),
                        found_under: entry.collection.clone(),
                    },
                })));
            }
        }
        Ok(None)
    }

    /// Phase 3: separate the commit objects the run verifies from the ones
    /// already marked partial, and under `verify_back_refs` hold every commit
    /// in the store to the refs its own bindings name.
    async fn fsck_enumerate_commits(
        &self,
        commits: &[Checksum],
        targets: &[(String, Checksum)],
        collection_refs: &[CollectionRefEntry],
        opts: &FsckOptions,
        ctx: &mut Ctx,
    ) -> Result<Option<FsckBindingError>> {
        for commit in commits {
            if self.commit_state(commit).await? == crate::read::CommitState::Partial {
                ctx.commits_partial += 1;
            } else {
                ctx.verified.push(*commit);
            }
        }

        if !opts.verify_back_refs {
            return Ok(None);
        }
        let by_name = index_first(
            targets
                .iter()
                .map(|(name, commit)| (name.as_str(), *commit)),
        );
        let by_pair = index_first(collection_refs.iter().map(|entry| {
            (
                (entry.collection.as_str(), entry.name.as_str()),
                entry.commit,
            )
        }));
        for commit in commits {
            let Ok(bytes) = self.load_object_bytes(ObjectType::Commit, commit).await else {
                continue;
            };
            let Ok(parsed) = Commit::parse(&bytes) else {
                continue;
            };
            if let Some(kind) = check_back_refs(&parsed, commit, &by_name, &by_pair) {
                return Ok(Some(FsckBindingError {
                    commit: *commit,
                    kind,
                }));
            }
        }
        Ok(None)
    }

    /// Phase 4, first half: the distinct objects the verified commits
    /// reference, in the order the walk discovers them. A dirtree that is
    /// absent ends the run, the subtree beneath it being unreadable; a dirmeta
    /// or a content object that is absent is in the set and is reported by the
    /// verification half.
    async fn fsck_collect_objects(
        &self,
        commits: &[Checksum],
    ) -> Result<std::result::Result<Vec<ObjectName>, FsckFailure>> {
        let mut order = Vec::new();
        let mut seen = HashSet::new();
        let mut walked = HashSet::new();
        for commit in commits {
            let name = ObjectName::new(*commit, ObjectType::Commit);
            push_object(&mut order, &mut seen, name);
            let Ok(bytes) = self.load_object_bytes(ObjectType::Commit, commit).await else {
                continue;
            };
            let Ok(parsed) = Commit::parse(&bytes) else {
                continue;
            };
            push_object(
                &mut order,
                &mut seen,
                ObjectName::new(parsed.root_dirmeta, ObjectType::DirMeta),
            );
            let mut sink = CollectSink {
                order: &mut order,
                seen: &mut seen,
            };
            if let Err(absent) =
                walk_subtree(self, parsed.root_dirtree, &mut walked, &mut sink).await?
            {
                return Ok(Err(FsckFailure::MissingDirTree(absent)));
            }
        }
        Ok(Ok(order))
    }

    /// Phase 4, second half: examine each object in the set once, reporting a
    /// checksum mismatch, an unreadable object, or an absent one. Every object
    /// in the set is examined, whatever the findings before it.
    ///
    /// One read buffer serves every content object in the set, so a store of
    /// many small objects allocates once.
    async fn fsck_verify_objects(&self, order: &[ObjectName], ctx: &mut Ctx) -> Result<()> {
        let mut buf: Vec<u8> = Vec::new();
        for name in order {
            if name.ty == ObjectType::File {
                if buf.len() < COPY_CHUNK {
                    buf.resize(COPY_CHUNK, 0);
                }
                self.fsck_hash_content(*name, &mut buf, ctx).await?;
            } else {
                self.fsck_hash_metadata(*name, ctx).await?;
            }
        }
        Ok(())
    }

    /// Hash one metadata object's bytes and compare with its name.
    ///
    /// An object whose checksum does not match is read at its own type as
    /// well. One whose bytes do not parse there is reported and left alone:
    /// `delete` does not unlink it and no commit is marked partial over it.
    async fn fsck_hash_metadata(&self, name: ObjectName, ctx: &mut Ctx) -> Result<()> {
        match self.load_object_bytes(name.ty, &name.checksum).await {
            Ok(bytes) => {
                let actual = Checksum::sha256(&bytes);
                if actual != name.checksum {
                    ctx.record(name, FsckErrorKind::ChecksumMismatch { actual });
                    if !parses_as(name.ty, &bytes) {
                        ctx.unparsable.insert(name);
                    }
                }
            }
            Err(Error::ObjectNotFound { .. }) => ctx.record(name, FsckErrorKind::Missing),
            // A read failure is reported as corruption rather than ending the
            // whole check.
            Err(Error::Io(e)) => ctx.record(name, FsckErrorKind::Corrupt(e.to_string())),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Load a content object, hash its framed header and streamed payload, and
    /// compare with its name, recording any fault.
    async fn fsck_hash_content(
        &self,
        name: ObjectName,
        buf: &mut [u8],
        ctx: &mut Ctx,
    ) -> Result<()> {
        let checksum = name.checksum;
        let file = match self.load_file(&checksum).await {
            Ok(file) => file,
            Err(Error::ObjectNotFound { .. }) => {
                ctx.record(name, FsckErrorKind::Missing);
                return Ok(());
            }
            Err(Error::Io(e)) => {
                ctx.record(name, FsckErrorKind::Corrupt(e.to_string()));
                return Ok(());
            }
            Err(Error::InvalidFormat(m)) => {
                ctx.record(name, FsckErrorKind::Corrupt(m));
                return Ok(());
            }
            Err(Error::Core(e)) => {
                ctx.record(name, FsckErrorKind::Corrupt(e.to_string()));
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        let mut hasher = ContentHasher::new(&file.header())?;

        let mut reader = file.reader().await?;
        loop {
            match reader.read(buf).await {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(e) => {
                    ctx.record(
                        name,
                        FsckErrorKind::Corrupt(format!("payload read failed: {e}")),
                    );
                    return Ok(());
                }
            }
        }

        let actual = hasher.finish();
        if actual != checksum {
            ctx.record(name, FsckErrorKind::ChecksumMismatch { actual });
        }
        Ok(())
    }

    /// Name the verified commits that reach each faulty object.
    ///
    /// The walk reads the dirtrees a second time, once per verified commit, so
    /// it runs before `delete` unlinks anything. A finding the ref phase made
    /// keeps its empty list: the ref phase reaches no commit through the object
    /// it read.
    async fn fsck_attribute_findings(&self, ctx: &mut Ctx) -> Result<()> {
        let faulty: HashSet<ObjectName> = ctx.errors[ctx.ref_findings..]
            .iter()
            .map(|e| e.object)
            .collect();
        if faulty.is_empty() {
            return Ok(());
        }
        // The walk records the objects it reaches that are faulty and no
        // other, so the memory one commit costs follows the count of findings
        // and not the size of its tree.
        let mut found: HashMap<ObjectName, Vec<Checksum>> = HashMap::new();
        for commit in &ctx.verified {
            let mut sink = ReachSink {
                faulty: &faulty,
                commit: *commit,
                found: &mut found,
            };
            sink.take(ObjectName::new(*commit, ObjectType::Commit));
            if let Ok(bytes) = self.load_object_bytes(ObjectType::Commit, commit).await
                && let Ok(parsed) = Commit::parse(&bytes)
            {
                sink.take(ObjectName::new(parsed.root_dirmeta, ObjectType::DirMeta));
                let mut walked = HashSet::new();
                walk_subtree(self, parsed.root_dirtree, &mut walked, &mut sink)
                    .await?
                    .ok();
            }
        }
        // `ctx.verified` is sorted, so each list came out sorted.
        let ref_findings = ctx.ref_findings;
        for error in &mut ctx.errors[ref_findings..] {
            if let Some(commits) = found.remove(&error.object) {
                error.in_commits = commits;
            }
        }
        Ok(())
    }

    /// Act on the findings: unlink each faulty object under `delete`, and mark
    /// every commit that reaches a deleted or an absent object partial.
    ///
    /// A checksum mismatch alone marks nothing, which is what the tool does: an
    /// object that is present and wrong leaves its commits complete until the
    /// object is removed.
    async fn fsck_apply_findings(&self, opts: &FsckOptions, ctx: &mut Ctx) -> Result<()> {
        let mut doomed = Vec::new();
        let mut seen: HashSet<Checksum> = HashSet::new();
        let mut incomplete: Vec<Checksum> = Vec::new();
        for error in &ctx.errors {
            let absent = matches!(error.kind, FsckErrorKind::Missing);
            if (!absent && !opts.delete) || ctx.unparsable.contains(&error.object) {
                continue;
            }
            if !absent {
                doomed.push(error.object);
            }
            for commit in &error.in_commits {
                if seen.insert(*commit) {
                    incomplete.push(*commit);
                }
            }
        }
        for object in doomed {
            if !ctx.deleted.insert(object) {
                continue;
            }
            self.fsck_unlink_object(object).await?;
        }
        if opts.mark_partial {
            for commit in incomplete {
                self.mark_commit_partial(&commit).await?;
                ctx.marked_partial.push(commit);
            }
        }
        Ok(())
    }

    /// Delete every commit object whose parent commit object is absent from the
    /// store, writing a `.tombstone-commit` naming the deleted commit.
    ///
    /// The absence is read against the listing the run took at its start, so
    /// one run removes one generation: a commit whose parent this same run
    /// removed is reached by the next run.
    async fn fsck_add_tombstones(&self, all: &[Checksum], ctx: &mut Ctx) -> Result<()> {
        let present: HashSet<Checksum> = all.iter().copied().collect();
        let fsync = self.config().fsync()?;
        for commit in all.iter().copied() {
            let Ok(bytes) = self.load_object_bytes(ObjectType::Commit, &commit).await else {
                continue;
            };
            let Ok(parsed) = Commit::parse(&bytes) else {
                continue;
            };
            let Some(parent) = parsed.parent else {
                continue;
            };
            if present.contains(&parent) {
                continue;
            }
            let mode = self.mode();
            let repo = self.clone();
            ostrya_rt::unblock(move || write_tombstone(repo.objects_fd(), &commit, mode, fsync))
                .await?;
            self.fsck_unlink_object(ObjectName::new(commit, ObjectType::Commit))
                .await?;
            ctx.tombstoned.push(commit);
        }
        Ok(())
    }

    /// Unlink one loose object, treating an already-absent file as success.
    async fn fsck_unlink_object(&self, name: ObjectName) -> Result<()> {
        let repo = self.clone();
        let path = name.loose_path(repo.mode());
        ostrya_rt::unblock(move || {
            match rustix::fs::unlinkat(repo.objects_fd(), path.as_str(), AtFlags::empty()) {
                Ok(()) | Err(Errno::NOENT) => Ok(()),
                Err(e) => Err(Error::Io(e.into())),
            }
        })
        .await
    }

    /// Write a commit's `state/<commit>.commitpartial` marker.
    async fn mark_commit_partial(&self, commit: &Checksum) -> Result<()> {
        let path = crate::pull::partial_path(commit);
        let repo = self.clone();
        ostrya_rt::unblock(move || write_partial_marker(repo.repo_fd(), &path, repo.mode())).await
    }
}

/// Whether the ref phase's binding check refuses this commit under this ref.
///
/// A commit carrying no `ostree.ref-binding` key at all predates the convention
/// and passes, which is what the tool does; one carrying a binding list that
/// omits the ref fails.
fn check_ref_binding(commit: &Commit, ref_name: &str) -> Option<FsckBindingErrorKind> {
    commit.metadata_value("ostree.ref-binding")?;
    let bindings = commit.ref_bindings();
    if bindings.contains(&ref_name) {
        return None;
    }
    Some(FsckBindingErrorKind::RefNotBound {
        ref_name: ref_name.to_owned(),
        bindings: bindings.into_iter().map(str::to_owned).collect(),
    })
}

/// Whether the back-reference check refuses this commit.
///
/// Each name in the commit's `ostree.ref-binding` must name a ref that resolves
/// to the commit, the refs under `refs/remotes` counting by their bare names.
/// Where the commit carries an `ostree.collection-binding`, the collection ref
/// `(binding, name)` must exist and resolve to it as well. The names are walked
/// in stored order and the first failure is the one reported.
fn check_back_refs(
    commit: &Commit,
    checksum: &Checksum,
    by_name: &HashMap<&str, Checksum>,
    by_pair: &HashMap<(&str, &str), Checksum>,
) -> Option<FsckBindingErrorKind> {
    let collection = commit.collection_binding();
    for name in commit.ref_bindings() {
        match by_name.get(name) {
            None => {
                return Some(FsckBindingErrorKind::BackRefMissing {
                    ref_name: name.to_owned(),
                });
            }
            Some(target) if target != checksum => {
                return Some(FsckBindingErrorKind::BackRefMismatch {
                    ref_name: name.to_owned(),
                });
            }
            Some(_) => {}
        }
        let Some(collection) = collection else {
            continue;
        };
        match by_pair.get(&(collection, name)) {
            None => {
                return Some(FsckBindingErrorKind::BackCollectionRefMissing {
                    collection_id: collection.to_owned(),
                    ref_name: name.to_owned(),
                });
            }
            Some(target) if target != checksum => {
                return Some(FsckBindingErrorKind::BackCollectionRefMismatch {
                    collection_id: collection.to_owned(),
                    ref_name: name.to_owned(),
                });
            }
            Some(_) => {}
        }
    }
    None
}

/// Index `entries` by key, keeping the first value each key carries, which is
/// the one a linear scan over the same order would find.
fn index_first<K: std::hash::Hash + Eq, V>(entries: impl Iterator<Item = (K, V)>) -> HashMap<K, V> {
    let mut map = HashMap::new();
    for (key, value) in entries {
        map.entry(key).or_insert(value);
    }
    map
}

/// Whether `bytes` read as the type `ty` names. A metadata object whose
/// checksum does not match is held to this before the run acts on it.
fn parses_as(ty: ObjectType, bytes: &[u8]) -> bool {
    match ty {
        ObjectType::Commit => Commit::parse(bytes).is_ok(),
        ObjectType::DirTree => DirTreeRef::parse(bytes).is_ok(),
        ObjectType::DirMeta => DirMetaRef::parse(bytes).is_ok(),
        _ => true,
    }
}

/// What one subtree walk does with each object it reaches.
trait WalkSink {
    /// Take one object the walk reached.
    fn take(&mut self, object: ObjectName);
}

/// The collecting sink: the distinct objects in discovery order.
struct CollectSink<'a> {
    order: &'a mut Vec<ObjectName>,
    seen: &'a mut HashSet<ObjectName>,
}

impl WalkSink for CollectSink<'_> {
    fn take(&mut self, object: ObjectName) {
        push_object(self.order, self.seen, object);
    }
}

/// The attributing sink: the faulty objects one commit reaches, named against
/// that commit. An object the walk reaches more than once under one commit is
/// recorded once: the commit is appended only where it is not already the last
/// name on the object's list.
struct ReachSink<'a> {
    faulty: &'a HashSet<ObjectName>,
    commit: Checksum,
    found: &'a mut HashMap<ObjectName, Vec<Checksum>>,
}

impl WalkSink for ReachSink<'_> {
    fn take(&mut self, object: ObjectName) {
        if !self.faulty.contains(&object) {
            return;
        }
        let commits = self.found.entry(object).or_default();
        if commits.last() != Some(&self.commit) {
            commits.push(self.commit);
        }
    }
}

/// Append one object where the walk has not already taken it.
fn push_object(order: &mut Vec<ObjectName>, seen: &mut HashSet<ObjectName>, object: ObjectName) {
    if seen.insert(object) {
        order.push(object);
    }
}

/// The boxed future type for the recursive subtree walk. Async recursion needs
/// indirection, so each level returns a boxed future.
type SubtreeFuture<'a> = Pin<Box<dyn Future<Output = Result<WalkOutcome>> + Send + 'a>>;

/// A subtree walk either reaches every dirtree beneath it or names the first
/// one that is absent.
type WalkOutcome = std::result::Result<(), Checksum>;

/// Walk a dirtree and everything beneath it, handing every object to `sink`.
///
/// A dirtree already walked in this pass is not descended into again, so a
/// subtree two directories share is read once. A dirtree that is absent ends
/// the walk and is named; one that is present but cannot be parsed contributes
/// itself and no child, the verification pass reporting its checksum.
fn walk_subtree<'a, S: WalkSink + Send>(
    repo: &'a Repo,
    dirtree: Checksum,
    walked: &'a mut HashSet<Checksum>,
    sink: &'a mut S,
) -> SubtreeFuture<'a> {
    Box::pin(async move {
        let name = ObjectName::new(dirtree, ObjectType::DirTree);
        sink.take(name);
        if !walked.insert(dirtree) {
            return Ok(Ok(()));
        }
        let bytes = match repo.load_object_bytes(ObjectType::DirTree, &dirtree).await {
            Ok(bytes) => bytes,
            Err(Error::ObjectNotFound { .. }) => return Ok(Err(dirtree)),
            Err(e) => return Err(e),
        };
        let Ok(parsed) = DirTree::parse(&bytes) else {
            return Ok(Ok(()));
        };
        for (_, file) in parsed.files {
            sink.take(ObjectName::new(file, ObjectType::File));
        }
        for (_, subtree, submeta) in parsed.dirs {
            sink.take(ObjectName::new(submeta, ObjectType::DirMeta));
            if let Err(absent) = walk_subtree(repo, subtree, walked, sink).await? {
                return Ok(Err(absent));
            }
        }
        Ok(Ok(()))
    })
}

/// Create or truncate a `.commitpartial` marker holding the single state byte
/// the tool writes.
///
/// A marker this call creates in a `bare-user-shared` repository is forced to
/// [`perm::SHARED_FILE_MODE`]. The create attempt therefore carries `O_EXCL`,
/// which separates the arm that made the file from the arm that found one: a
/// marker another member of the repository group owns keeps the mode it has and
/// is truncated in place. The second open carries `O_CREAT` as well, because a
/// concurrent pull or prune removes the marker of a commit it completes or
/// deletes, and the name is free again by the time this call reaches it.
fn write_partial_marker(repo_fd: BorrowedFd<'_>, path: &str, repo_mode: RepoMode) -> Result<()> {
    let mode = Mode::from_raw_mode(crate::pull::PARTIAL_MARKER_MODE);
    let fd = match rustix::fs::openat(
        repo_fd,
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        mode,
    ) {
        Ok(fd) => {
            perm::force_created_mode(&fd, repo_mode, perm::SHARED_FILE_MODE)?;
            fd
        }
        Err(Errno::EXIST) => rustix::fs::openat(
            repo_fd,
            path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
            mode,
        )?,
        Err(e) => return Err(e.into()),
    };
    std::fs::File::from(fd)
        .write_all(&[PARTIAL_STATE_BYTE])
        .map_err(Error::Io)
}
