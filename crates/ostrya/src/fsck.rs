//! Checks of the integrity and the completeness of a repository.
//!
//! [`Repo::fsck`] runs the checks. [`FsckOptions`] selects the optional checks
//! and the actions on the findings. [`FsckReport`] holds the result.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd};
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

/// The one byte that the `ostree` command writes into a `.commitpartial`
/// marker when its fsck finds a commit incomplete (observed).
const PARTIAL_STATE_BYTE: u8 = 0x66;

/// The options of a [`Repo::fsck`] run.
#[derive(Debug, Clone)]
pub struct FsckOptions {
    /// The switch that marks each commit that reaches an absent or a deleted
    /// object as partial.
    ///
    /// The mark is the `state/<commit>.commitpartial` marker of the commit, as
    /// the `ostree` command writes it. The default is `true`. The value `false`
    /// is an ostrya extension, which the `ostrya fsck` command spells
    /// `--no-mark-partial`.
    pub mark_partial: bool,
    /// The switch that unlinks each object whose checksum differs from its name.
    ///
    /// The option of the `ostree fsck` command is `--delete`.
    ///
    /// The run also marks each commit that reaches a deleted object as
    /// partial. If the bytes of a metadata object do not parse as the type of
    /// its name, the run reports the object and does not unlink it. Such an
    /// object marks no commit as partial.
    ///
    /// If this field is `false`, a checksum mismatch marks no commit, as with
    /// the `ostree` command. A commit stays complete while the wrong object is
    /// present.
    pub delete: bool,
    /// The switch that lets the tombstone step run after a walk with a corrupt
    /// object.
    ///
    /// The option of the `ostree fsck` command is `-a`.
    ///
    /// The object walk runs to its end with each value of this field. The
    /// field has one effect: it lets the
    /// [`add_tombstones`](FsckOptions::add_tombstones) step act after a walk
    /// that found an object whose bytes do not match its name.
    /// [`delete`](FsckOptions::delete) gives the same permission. A walk that
    /// found only absent objects needs neither field.
    pub all: bool,
    /// The switch that deletes each commit whose parent commit is absent.
    ///
    /// The option of the `ostree fsck` command is `--add-tombstones`.
    ///
    /// The step writes a `.tombstone-commit` object that names each deleted
    /// commit. [`Repo::fsck`] states when the step runs.
    pub add_tombstones: bool,
    /// The switch that checks that the commit of each ref is bound to the ref.
    ///
    /// The option of the `ostree fsck` command is `--verify-bindings`.
    ///
    /// The `ostree.ref-binding` of the commit of each ref must hold the name
    /// of the ref. A commit with no `ostree.ref-binding` key passes this
    /// check, as with the `ostree` command.
    ///
    /// The `ostree.collection-binding` of the commit of each collection ref
    /// must be the collection id of the ref. A commit with no
    /// `ostree.collection-binding` key passes this check.
    pub verify_bindings: bool,
    /// The switch that checks that the ref bindings of each commit resolve to it.
    ///
    /// The option of the `ostree fsck` command is `--verify-back-refs`.
    ///
    /// The check reads each commit object in the object store. Each name in
    /// the `ostree.ref-binding` of a commit must name a ref that resolves to
    /// the commit. A ref under `refs/remotes` counts by its bare name. If the
    /// commit has an `ostree.collection-binding`, the collection ref with that
    /// id and that name must also resolve to the commit.
    ///
    /// This check and [`verify_bindings`](FsckOptions::verify_bindings) are
    /// independent. Each field runs its own check only.
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
    /// Creates the default options.
    ///
    /// [`mark_partial`](FsckOptions::mark_partial) is `true`, and each other
    /// field is `false`.
    pub fn new() -> FsckOptions {
        FsckOptions::default()
    }
}

/// The phases of a [`Repo::fsck`] run, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FsckPhase {
    /// The phase that loads the commit of each ref and verifies its checksum.
    ValidateRefs,
    /// The phase that reads the collection-qualified refs.
    ValidateCollectionRefs,
    /// The phase that lists the commit objects and separates the partial ones.
    EnumerateCommits,
    /// The phase that walks and verifies the objects of the verified commits.
    VerifyObjects,
}

/// The cause of a finding on one object.
#[derive(Debug, Clone)]
pub enum FsckErrorKind {
    /// The object is referenced and absent from the object store.
    Missing,
    /// The object is present, and its checksum differs from its name.
    ChecksumMismatch {
        /// The checksum of the bytes of the object.
        actual: Checksum,
    },
    /// The object is present, and a read or a parse of it failed.
    Corrupt(String),
}

/// One finding of a run: the object, the cause, and the commits that reach it.
#[derive(Debug, Clone)]
pub struct FsckError {
    /// The object of the finding.
    pub object: ObjectName,
    /// The cause of the finding.
    pub kind: FsckErrorKind,
    /// The verified commits that reach the object, sorted.
    ///
    /// The list is empty for a finding of the ref phase. That phase reads the
    /// commit object that a ref names, and it reaches no commit through it.
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

/// A failed binding check or back-reference check.
///
/// A finding of this type ends the run in the phase that made it.
#[derive(Debug, Clone)]
pub struct FsckBindingError {
    /// The commit of the finding.
    pub commit: Checksum,
    /// The check that failed.
    pub kind: FsckBindingErrorKind,
}

/// The binding check that failed.
#[derive(Debug, Clone)]
pub enum FsckBindingErrorKind {
    /// The `ostree.ref-binding` of the commit does not hold the ref (ref
    /// phase).
    RefNotBound {
        /// The bare name of the ref through which the run reached the commit.
        ref_name: String,
        /// The names in the `ostree.ref-binding` of the commit, in stored
        /// order.
        bindings: Vec<String>,
    },
    /// The `ostree.collection-binding` of the commit is not the collection id
    /// of the ref.
    ///
    /// The collection phase makes this finding.
    CollectionMismatch {
        /// The id in the `ostree.collection-binding` of the commit.
        bound: String,
        /// The collection id of the ref.
        found_under: String,
    },
    /// A bound ref name that names no ref (back-reference check).
    BackRefMissing {
        /// The bound name.
        ref_name: String,
    },
    /// A bound ref name that names another commit (back-reference check).
    BackRefMismatch {
        /// The bound name.
        ref_name: String,
    },
    /// A bound collection ref that does not exist (back-reference check).
    BackCollectionRefMissing {
        /// The `ostree.collection-binding` of the commit.
        collection_id: String,
        /// The bound name.
        ref_name: String,
    },
    /// A bound collection ref that names another commit (back-reference
    /// check).
    BackCollectionRefMismatch {
        /// The `ostree.collection-binding` of the commit.
        collection_id: String,
        /// The bound name.
        ref_name: String,
    },
}

/// The condition that ended a run before the end of its last phase.
#[derive(Debug, Clone)]
pub enum FsckFailure {
    /// A ref names a commit object that the object store does not hold.
    RefTarget {
        /// The name of the ref, as a message gives it.
        ///
        /// A remote ref has its bare name, with no remote prefix, as in the
        /// message of the `ostree` command. A mirror ref has the form
        /// `(collection, name)`.
        ref_name: String,
        /// The commit that the ref names.
        commit: Checksum,
        /// `true` if the run removed the object itself.
        ///
        /// [`delete`](FsckOptions::delete) removes a ref target whose checksum
        /// does not match.
        removed: bool,
    },
    /// An absent dirtree that the walk must read.
    ///
    /// The run cannot read the subtree of this dirtree.
    MissingDirTree(Checksum),
    /// A failed binding check or back-reference check.
    Binding(FsckBindingError),
}

/// The result of a [`Repo::fsck`] run.
///
/// A corrupt repository does not fail the call. The report holds each faulty
/// object in [`errors`](FsckReport::errors), and the condition that ended the
/// run in [`failure`](FsckReport::failure). A caller, for example the
/// `ostrya fsck` command, turns a report with findings into a failure.
#[derive(Debug, Clone)]
pub struct FsckReport {
    /// The last phase that the run entered.
    pub reached: FsckPhase,
    /// The number of commit objects that the run verified.
    ///
    /// These are the commits in the object store that had no `.commitpartial`
    /// marker at the start of the run.
    pub commits_checked: usize,
    /// The number of commit objects that the run skipped as already partial.
    pub commits_partial: usize,
    /// The number of distinct objects that the verified commits reference.
    ///
    /// The count includes the present objects and the absent objects. It does
    /// not include detached commit metadata. If the run ended early, the count
    /// is `0`.
    pub objects_checked: usize,
    /// The findings, sorted by object checksum.
    ///
    /// A commit object that a ref names can have two findings: one from the
    /// ref phase and one from the object walk.
    pub errors: Vec<FsckError>,
    /// The commits that the run marked as partial, sorted.
    pub marked_partial: Vec<Checksum>,
    /// The objects that the run unlinked for [`delete`](FsckOptions::delete),
    /// sorted.
    pub deleted: Vec<ObjectName>,
    /// The commits that the run deleted for
    /// [`add_tombstones`](FsckOptions::add_tombstones), sorted.
    pub tombstoned: Vec<Checksum>,
    /// The condition that ended the run early, if one did.
    pub failure: Option<FsckFailure>,
}

impl FsckReport {
    /// Returns `true` if the repository passed with no finding.
    ///
    /// A pass has no faulty object, no condition that ended the run, and no
    /// commit that the run skipped as already partial.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty() && self.failure.is_none() && self.commits_partial == 0
    }
}

/// The mutable state of one fsck run.
#[derive(Default)]
struct Ctx {
    /// The findings, in the order of the run.
    errors: Vec<FsckError>,
    /// The objects of findings whose bytes do not parse as the type of their
    /// name. The run reports each one and acts on none.
    unparsable: HashSet<ObjectName>,
    /// The commits that this run marked as partial.
    marked_partial: Vec<Checksum>,
    /// The objects that this run unlinked.
    deleted: HashSet<ObjectName>,
    /// The commits that this run tombstoned.
    tombstoned: Vec<Checksum>,
    /// The number of leading entries of `errors` that the ref phase made.
    /// These keep an empty `in_commits`, because the ref phase reaches no
    /// commit through the object that it read.
    ref_findings: usize,
    /// The commit objects that the run verifies, sorted.
    verified: Vec<Checksum>,
    /// The number of commit objects skipped as already partial.
    commits_partial: usize,
}

impl Ctx {
    /// Records one finding. The run names the commits that reach the object
    /// after the walk, so the finding starts with no commit.
    fn record(&mut self, object: ObjectName, kind: FsckErrorKind) {
        self.errors.push(FsckError {
            object,
            kind,
            in_commits: Vec::new(),
        });
    }

    /// Builds the report.
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

/// Methods that check the objects and the refs of a repository.
impl Repo {
    /// Checks the integrity and the completeness of the commits in a repository.
    ///
    /// The run has the four phases of the `ostree fsck` command, in the same
    /// order. A corrupt repository does not fail the call: the [`FsckReport`]
    /// holds the findings. [`FsckOptions`] selects the optional checks.
    ///
    /// # Phases
    ///
    /// 1. Validate refs ([`FsckPhase::ValidateRefs`]). The run loads the
    ///    commit object that each ref under `refs/heads` and `refs/remotes`
    ///    names, and verifies its checksum. If
    ///    [`verify_bindings`](FsckOptions::verify_bindings) is set, the
    ///    `ostree.ref-binding` of the commit must hold the name of the ref.
    /// 2. Validate refs in collections
    ///    ([`FsckPhase::ValidateCollectionRefs`]). The run loads the commit of
    ///    each mirror ref and verifies its checksum. If `verify_bindings` is
    ///    set, the `ostree.collection-binding` of the commit of each
    ///    collection-qualified ref must be the collection id of the ref.
    /// 3. Enumerate commits ([`FsckPhase::EnumerateCommits`]). The run lists
    ///    each commit object in the object store. It skips each commit that
    ///    has a `state/<commit>.commitpartial` marker at the start of the run.
    ///    If [`verify_back_refs`](FsckOptions::verify_back_refs) is set, each
    ///    name in the `ostree.ref-binding` of a commit must name a ref that
    ///    resolves to that commit.
    /// 4. Verify objects ([`FsckPhase::VerifyObjects`]). The run reads each
    ///    object that the verified commits reference, once:
    ///
    ///    - Integrity: the checksum of each object must equal its name. The
    ///      hash of a metadata object covers its serialized bytes. The hash of
    ///      a content object covers its framed uncompressed header and its
    ///      uncompressed payload. Because of this, the run finds a corrupt
    ///      `.filez` or a changed `.file` in each repository mode.
    ///    - Completeness: each referenced object must be present. The run
    ///      reports each absent object. It marks each commit that reaches the
    ///      object as partial: it writes the `state/<commit>.commitpartial`
    ///      marker of the commit.
    ///
    /// [`mark_partial`](FsckOptions::mark_partial) and
    /// [`delete`](FsckOptions::delete) state the actions on a finding.
    ///
    /// # Early end
    ///
    /// A run ends early at three conditions:
    ///
    /// - A ref names a commit object that the object store does not hold
    ///   ([`FsckFailure::RefTarget`]).
    /// - A dirtree that the walk must read is absent
    ///   ([`FsckFailure::MissingDirTree`]).
    /// - A binding check fails ([`FsckFailure::Binding`]).
    ///
    /// After the first two conditions, the run cannot read the next object
    /// that it must read. A failed binding check states a fact about the refs
    /// and marks nothing. The run records each other fault and continues, so
    /// one run reports each fault that it can reach.
    ///
    /// [`FsckReport::failure`] holds the condition, and
    /// [`FsckReport::reached`] holds the phase.
    ///
    /// # Tombstones
    ///
    /// If [`add_tombstones`](FsckOptions::add_tombstones) is set, one step
    /// follows the four phases. The step deletes each commit object whose
    /// parent commit object is absent. It writes a `.tombstone-commit` object
    /// that names each deleted commit.
    ///
    /// The step writes to the repository. After a walk that found a corrupt
    /// object, the step runs only if [`all`](FsckOptions::all) or
    /// [`delete`](FsckOptions::delete) is set. After a walk that found only
    /// absent objects, or no fault, the step runs without `all` and `delete`.
    /// A run that ends early does not reach the step.
    ///
    /// The step reads the parent of each commit against the commit list of
    /// the start of the run. As a result, one run removes one generation. If
    /// the run removes the parent of a commit, the next run removes that
    /// commit.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8.
    /// - [`Error::Core`] if a ref file holds no checksum, if the header of a
    ///   content object does not serialize, or if `[core] fsync` is not a
    ///   boolean.
    /// - [`Error::Io`] if a read or a write on the file system fails. These
    ///   are the listing of the refs and of the objects, the read of a commit
    ///   that a ref names or of a dirtree, the check for a `.commitpartial`
    ///   marker, the unlink of an object, and the write of a marker or a
    ///   tombstone. A commit that a ref names, or a dirtree, larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) also gives this
    ///   error.
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

        // Name the commits that reach each finding, and act on the findings:
        // unlink if `delete` is set, and mark as partial. The naming step
        // reads the dirtrees again, so it runs before the first unlink.
        if !ctx.errors.is_empty() {
            self.fsck_attribute_findings(&mut ctx).await?;
            self.fsck_apply_findings(opts, &mut ctx).await?;
        }

        // The tombstone step writes to the repository, so it has the
        // condition of the `ostree` command: a walk that reached its end. A
        // corrupt object ends the walk of the `ostree` command unless `all` or
        // `delete` is set. An absent object never ends it.
        let corrupt = ctx
            .errors
            .iter()
            .any(|error| !matches!(error.kind, FsckErrorKind::Missing));
        if opts.add_tombstones && (opts.all || opts.delete || !corrupt) {
            self.fsck_add_tombstones(&commits, &mut ctx).await?;
        }

        Ok(ctx.finish(FsckPhase::VerifyObjects, objects_checked, None))
    }

    /// Reads the refs of the run, once.
    ///
    /// The result holds each ref under `refs/heads` and `refs/remotes`, by the
    /// bare name that a message gives it, and each collection-qualified ref.
    /// The refspec of a remote ref has the remote name before a `:`. The
    /// message of the `ostree` command drops it, so the function keeps the
    /// tail only.
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

    /// Runs phase 1: loads and verifies the commit that each ref under
    /// `refs/heads` and `refs/remotes` names. If `verify_bindings` is set, it
    /// checks each commit against the ref through which the run reached it.
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

    /// Loads the commit object that one ref names and verifies its checksum.
    ///
    /// `Err` ends the run. `Ok(None)` records a finding and leaves the commit
    /// unread. The caller decides if the run continues after it. `display` is
    /// the ref as a message names it.
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

    /// Runs phase 2: loads and verifies the commit that each
    /// collection-qualified ref names. If `verify_bindings` is set, it checks
    /// each commit against the collection id of the ref.
    ///
    /// Phase 1 already read each local ref that the collection id of the
    /// repository qualifies. This phase reads such a ref for its binding only.
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

    /// Runs phase 3: separates the commit objects that the run verifies from
    /// the commits already marked as partial. If `verify_back_refs` is set, it
    /// checks each commit in the store against the refs that its bindings name.
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

    /// Runs the first half of phase 4: returns the distinct objects that the
    /// verified commits reference, in the order of the walk.
    ///
    /// An absent dirtree ends the run, because its subtree is unreadable. An
    /// absent dirmeta or content object is in the set, and the second half
    /// reports it.
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

    /// Runs the second half of phase 4: reads each object in the set once.
    ///
    /// The function records a checksum mismatch, an unreadable object, or an
    /// absent object. It reads each object in the set, whatever the findings
    /// before it. One read buffer serves each content object in the set, so a
    /// store of many small objects allocates once.
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

    /// Verifies the checksum of the bytes of one metadata object.
    ///
    /// If the checksum does not match, the function also parses the bytes as
    /// the type of the object. If the parse fails, the run reports the object
    /// and does not act on it. `delete` does not unlink it, and no commit is
    /// marked as partial because of it.
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
            // The run records a read failure as corruption and continues.
            Err(Error::Io(e)) => ctx.record(name, FsckErrorKind::Corrupt(e.to_string())),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Verifies the checksum of a content object over its framed header and
    /// its streamed payload, and records each fault.
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

    /// Names the verified commits that reach each faulty object.
    ///
    /// The walk reads the dirtrees a second time, once for each verified
    /// commit, so it runs before `delete` unlinks an object. A finding of the
    /// ref phase keeps its empty list, because the ref phase reaches no commit
    /// through the object that it read.
    async fn fsck_attribute_findings(&self, ctx: &mut Ctx) -> Result<()> {
        let faulty: HashSet<ObjectName> = ctx.errors[ctx.ref_findings..]
            .iter()
            .map(|e| e.object)
            .collect();
        if faulty.is_empty() {
            return Ok(());
        }
        // The walk records only the faulty objects that it reaches, so the
        // memory of one commit grows with the count of findings. The size of
        // its tree does not change it.
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
        // `ctx.verified` is sorted, so each list is sorted.
        let ref_findings = ctx.ref_findings;
        for error in &mut ctx.errors[ref_findings..] {
            if let Some(commits) = found.remove(&error.object) {
                error.in_commits = commits;
            }
        }
        Ok(())
    }

    /// Acts on the findings. If `delete` is set, the function unlinks each
    /// faulty object. It marks each commit that reaches a deleted or an
    /// absent object as partial.
    ///
    /// A checksum mismatch alone marks no commit, as with the `ostree`
    /// command. The commits of an object that is present and wrong stay
    /// complete until the object is removed.
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

    /// Deletes each commit object whose parent commit object is absent from
    /// the store, and writes a `.tombstone-commit` that names it.
    ///
    /// The function reads the absence against the listing of the start of the
    /// run, so one run removes one generation. If this run removed the parent
    /// of a commit, the next run removes the commit.
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
            ostrya_rt::unblock(move || {
                let tmp_fd = crate::staging::open_tmp_dir(repo.repo_fd(), mode)?;
                write_tombstone(tmp_fd.as_fd(), repo.objects_fd(), &commit, mode, fsync)
            })
            .await?;
            self.fsck_unlink_object(ObjectName::new(commit, ObjectType::Commit))
                .await?;
            ctx.tombstoned.push(commit);
        }
        Ok(())
    }

    /// Unlinks one loose object. An absent file counts as a success.
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

    /// Writes the `state/<commit>.commitpartial` marker of a commit.
    async fn mark_commit_partial(&self, commit: &Checksum) -> Result<()> {
        let path = crate::pull::partial_path(commit);
        let repo = self.clone();
        ostrya_rt::unblock(move || write_partial_marker(repo.repo_fd(), &path, repo.mode())).await
    }
}

/// Returns the failure if the binding check of the ref phase refuses this
/// commit under this ref.
///
/// A commit with no `ostree.ref-binding` key is older than the convention and
/// passes, as with the `ostree` command. A commit with a binding list that
/// does not hold the ref fails.
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

/// Returns the failure if the back-reference check refuses this commit.
///
/// Each name in the `ostree.ref-binding` of the commit must name a ref that
/// resolves to the commit. A ref under `refs/remotes` counts by its bare name.
/// If the commit has an `ostree.collection-binding`, the collection ref
/// `(binding, name)` must also exist and resolve to it. The function reads the
/// names in stored order and returns the first failure.
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

/// Indexes `entries` by key and keeps the first value of each key. A linear
/// scan in the same order finds the same value.
fn index_first<K: std::hash::Hash + Eq, V>(entries: impl Iterator<Item = (K, V)>) -> HashMap<K, V> {
    let mut map = HashMap::new();
    for (key, value) in entries {
        map.entry(key).or_insert(value);
    }
    map
}

/// Returns `true` if `bytes` parse as the type `ty`. The run acts on a
/// metadata object with a wrong checksum only if this check passes.
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
    /// Takes one object that the walk reached.
    fn take(&mut self, object: ObjectName);
}

/// The sink that collects the distinct objects in the order of the walk.
struct CollectSink<'a> {
    order: &'a mut Vec<ObjectName>,
    seen: &'a mut HashSet<ObjectName>,
}

impl WalkSink for CollectSink<'_> {
    fn take(&mut self, object: ObjectName) {
        push_object(self.order, self.seen, object);
    }
}

/// The sink that names one commit against each faulty object it reaches.
///
/// If the walk reaches an object more than once under one commit, the sink
/// records it once. It appends the commit only if the commit is not already
/// the last name on the list of the object.
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

/// Appends one object if the walk did not take it before.
fn push_object(order: &mut Vec<ObjectName>, seen: &mut HashSet<ObjectName>, object: ObjectName) {
    if seen.insert(object) {
        order.push(object);
    }
}

/// The boxed future of the recursive subtree walk. Async recursion needs
/// indirection, so each level returns a boxed future.
type SubtreeFuture<'a> = Pin<Box<dyn Future<Output = Result<WalkOutcome>> + Send + 'a>>;

/// The result of a subtree walk: `Ok` if the walk reached each dirtree in the
/// subtree, or the first absent dirtree.
type WalkOutcome = std::result::Result<(), Checksum>;

/// Walks a dirtree and its full subtree, and gives each object to `sink`.
///
/// The walk enters each dirtree once in a pass, so it reads a subtree that two
/// directories share once. An absent dirtree ends the walk, and the result
/// names it. A present dirtree that does not parse gives itself and no child.
/// The verification pass then reports its checksum.
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

/// Creates or truncates a `.commitpartial` marker that holds the one state
/// byte of the `ostree` command.
///
/// In a `bare-user-shared` repository, a marker that this call creates gets
/// the mode [`perm::SHARED_FILE_MODE`]. For this reason the create attempt
/// has `O_EXCL`, which separates the arm that made the file from the arm that
/// found one. A marker that another member of the repository group owns keeps
/// its mode, and the call truncates it in place.
///
/// The second open also has `O_CREAT`. A concurrent pull or prune removes the
/// marker of a commit that it completes or deletes, and the name can be free
/// again when this call reaches it.
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
