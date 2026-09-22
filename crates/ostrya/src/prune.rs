//! Pruning unreachable objects.
//!
//! [`Repo::prune`] computes the set of objects reachable from a chosen set of
//! roots and deletes every loose object not in it. The behavior reproduces the
//! `ostree prune` tool (recovered by black-box observation):
//!
//! - The roots are always the commits every ref resolves to. With
//!   [`refs_only`](PruneOptions::refs_only) unset, every commit object present
//!   in the store is also a root, so an unreferenced commit and its objects are
//!   kept; with it set, only commits reachable from a ref survive.
//!   [`keep_younger_than`](PruneOptions::keep_younger_than), a non-empty
//!   [`only_branch`](PruneOptions::only_branch), and a non-empty
//!   [`retain_branch_depth`](PruneOptions::retain_branch_depth) each root the
//!   walk on the refs alone the way [`refs_only`](PruneOptions::refs_only)
//!   does.
//! - [`depth`](PruneOptions::depth) bounds how far back each ref's history is
//!   kept: `-1` (the default) keeps the whole ancestry, `0` keeps only each
//!   ref's head commit, `N` keeps `N` parents. `-1` is the one negative value
//!   that keeps the whole ancestry; every other negative value keeps the head
//!   alone.
//! - [`retain_branch_depth`](PruneOptions::retain_branch_depth) states a depth
//!   for one branch, in place of [`depth`](PruneOptions::depth) for it.
//! - A bound belongs to the commit a ref names and not to the path the walk
//!   took to reach it. The walk that arrives at a ref's target over a `parent`
//!   edge drops the bound it carried and continues under that ref's own bound,
//!   so a branch cut short cuts every history that runs through its head.
//!   Where two refs name one commit, the commit is walked under each of the two
//!   bounds and keeps what either of them reaches.
//! - [`keep_younger_than`](PruneOptions::keep_younger_than) bounds each ref's
//!   history by time instead of by depth: a commit reached over the `parent`
//!   edge is kept while its own timestamp is at or after the bound. A ref's own
//!   target is kept whatever its timestamp.
//! - [`commit_only`](PruneOptions::commit_only) deletes commit objects alone
//!   and leaves the trees they reached where they stand.
//! - A kept commit's detached metadata (`.commitmeta`) is kept with it; a
//!   pruned commit's detached metadata and its `state/<commit>.commitpartial`
//!   marker are removed alongside it. Tombstone-commit markers are never pruned.
//! - [`no_prune`](PruneOptions::no_prune) computes the statistics without
//!   deleting anything.
//! - [`delete_commit`](PruneOptions::delete_commit) removes a specific,
//!   unreferenced commit object, then sweeps what it orphaned. The walk treats
//!   that commit as already absent, so what only it reached is swept, and the
//!   object itself is unlinked once the walk has succeeded. The reported counts
//!   cover the swept objects, matching the tool. Under
//!   [`no_prune`](PruneOptions::no_prune) the commit stays and the counts
//!   report the sweep its removal would cause. The `ostree` tool refuses the
//!   two options together, and so does the `ostrya` CLI.
//! - [`static_deltas_only`](PruneOptions::static_deltas_only) narrows the run
//!   to the static deltas [`delete_commit`](PruneOptions::delete_commit) names
//!   and leaves every loose object where it stands.
//! - Every run removes the static delta of each commit it deleted, the delta
//!   directory whole and its fanout parent in place. A delta whose source
//!   commit the run deleted is kept.
//! - A run writes a `.tombstone-commit` for every commit it removes where
//!   [`delete_commit`](PruneOptions::delete_commit) is given or the repository
//!   config sets `[core] tombstone-commits`.
//!
//! Two options carry reachability the tool has no counterpart for, so a prune
//! that leaves them at their defaults is the tool's:
//! [`gc_root_metadata_keys`](PruneOptions::gc_root_metadata_keys) names metadata
//! keys whose value names further commits to keep, and
//! [`traverse_parent`](PruneOptions::traverse_parent) decides whether a commit's
//! `parent` is reachable from it at all.
//!
//! The `ostrya` CLI fills the first of the two from the repository config key
//! `[ex-ostrya] gc-root-metadata-keys`
//! ([`RepoConfig::gc_root_metadata_keys`](crate::RepoConfig::gc_root_metadata_keys)).
//! The library reads one config key of its own, `[core] tombstone-commits`; the
//! rest of a prune acts on the options it is given.

use std::collections::HashSet;
use std::os::fd::BorrowedFd;

use ostrya_core::{Checksum, ObjectName, ObjectType, RepoMode, loose_path};
use rustix::fs::AtFlags;
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::tombstone::write_tombstone;
use crate::traverse::ParentBound;

/// Options controlling [`Repo::prune`].
#[derive(Debug, Clone)]
pub struct PruneOptions {
    /// Keep only objects reachable from refs. When false, every commit object
    /// present in the store is also treated as a root, so unreferenced commits
    /// survive.
    pub refs_only: bool,
    /// How many parent commits of each ref to keep: `-1` for the whole
    /// ancestry, `0` for only the head, `N` for `N` parents. `-1` is the one
    /// negative value that keeps the whole ancestry; every other negative value
    /// keeps the head alone.
    pub depth: i32,
    /// Compute the statistics without deleting anything, including the commit
    /// [`delete_commit`](PruneOptions::delete_commit) names.
    pub no_prune: bool,
    /// Remove this specific commit object before sweeping. It must not be the
    /// target of any ref. Under [`no_prune`](PruneOptions::no_prune) it stays,
    /// and the statistics cover the sweep its removal would cause.
    pub delete_commit: Option<Checksum>,
    /// Keep no commit older than this count of seconds since the Unix epoch.
    ///
    /// `Some` roots the walk on the refs alone, the way
    /// [`refs_only`](PruneOptions::refs_only) does, and bounds the `parent`
    /// edge by time in place of by [`depth`](PruneOptions::depth), which is
    /// then read for no branch that
    /// [`retain_branch_depth`](PruneOptions::retain_branch_depth) leaves at the
    /// global value. A ref's own target is kept whatever its timestamp.
    pub keep_younger_than: Option<u64>,
    /// The branches the run prunes, each named as
    /// [`Repo::list_refs`](crate::Repo::list_refs) and
    /// [`Repo::list_remote_refs`](crate::Repo::list_remote_refs) name one.
    ///
    /// Empty prunes every branch. A non-empty list roots the walk on the refs
    /// alone and retains in full every branch it does not name and
    /// [`retain_branch_depth`](PruneOptions::retain_branch_depth) does not name
    /// either. Every value is resolved as a revision, so one naming nothing
    /// fails the prune before any object is removed; a value that resolves and
    /// matches no ref name selects no branch, which leaves every branch
    /// retained in full.
    pub only_branch: Vec<String>,
    /// A depth for one branch, in place of [`depth`](PruneOptions::depth) for
    /// it. A branch named here is never retained in full by
    /// [`only_branch`](PruneOptions::only_branch).
    ///
    /// A non-empty list roots the walk on the refs alone, the way
    /// [`refs_only`](PruneOptions::refs_only) does. The entries are read in
    /// order and the last one naming a branch decides it. An entry whose depth
    /// is `0` leaves the branch at the global [`depth`](PruneOptions::depth)
    /// and still counts as naming it.
    pub retain_branch_depth: Vec<(String, i32)>,
    /// Delete commit objects alone. The objects a deleted commit reached are
    /// left where they stand, and the statistics count commit objects alone.
    pub commit_only: bool,
    /// Delete the static deltas [`delete_commit`](PruneOptions::delete_commit)
    /// targets and nothing else. Requires
    /// [`delete_commit`](PruneOptions::delete_commit); without it the prune
    /// fails with [`Error::InvalidFormat`].
    pub static_deltas_only: bool,
    /// Metadata keys that name further reachable commits.
    ///
    /// Each name is looked up in every reached commit's own metadata and in its
    /// detached metadata. A key that is present holds an `aay` whose elements
    /// are commit checksums, and each of those commits is walked as a root of
    /// its own, so what it reaches is kept too. A key that holds anything else
    /// fails the prune with [`Error::InvalidGcRoot`].
    ///
    /// The list is empty by default, which reads no metadata at all. A
    /// non-empty list adds no reachability under
    /// [`refs_only`](PruneOptions::refs_only) unset, since a prune that is not
    /// restricted to refs already roots every commit in the store. It is still
    /// read there: every commit's metadata and detached metadata is looked up,
    /// and a key of the wrong type fails the prune under either setting.
    pub gc_root_metadata_keys: Vec<String>,
    /// Whether a commit's `parent` is reachable from it.
    ///
    /// True by default, which is what the tool does and what
    /// [`depth`](PruneOptions::depth) bounds. False keeps a commit's ancestry
    /// only where something else names it, which is the setting an application
    /// tracking its own roots through
    /// [`gc_root_metadata_keys`](PruneOptions::gc_root_metadata_keys) uses.
    ///
    /// The repository config carries no counterpart for this field, so a prune
    /// the `ostrya` CLI runs always follows the `parent` edge. A configured
    /// CLI prune adds roots and takes none away, so it keeps at least what the
    /// tool keeps.
    pub traverse_parent: bool,
}

impl Default for PruneOptions {
    fn default() -> Self {
        PruneOptions {
            refs_only: false,
            depth: -1,
            no_prune: false,
            delete_commit: None,
            keep_younger_than: None,
            only_branch: Vec::new(),
            retain_branch_depth: Vec::new(),
            commit_only: false,
            static_deltas_only: false,
            gc_root_metadata_keys: Vec::new(),
            traverse_parent: true,
        }
    }
}

impl PruneOptions {
    /// The default options: keep everything reachable from any commit in the
    /// store (nothing is pruned in a healthy repository).
    pub fn new() -> PruneOptions {
        PruneOptions::default()
    }

    /// Prune against the named metadata keys as the extra roots, over refs
    /// alone and without the `parent` edge: an application that records its own
    /// reachability in commit metadata says what is kept, and a commit's
    /// ancestry is not kept for being an ancestry.
    ///
    /// The caller sets [`traverse_parent`](PruneOptions::traverse_parent) back
    /// to true on the result to have both edge kinds.
    pub fn gc_roots<I, S>(keys: I) -> PruneOptions
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        PruneOptions {
            refs_only: true,
            gc_root_metadata_keys: keys.into_iter().map(Into::into).collect(),
            traverse_parent: false,
            ..PruneOptions::default()
        }
    }

    /// The bound the walk puts on a branch no `retain_branch_depth` entry
    /// names and `only_branch` leaves at the global setting.
    fn global_bound(&self) -> ParentBound {
        match self.keep_younger_than {
            Some(since) => ParentBound::Since(since),
            None => ParentBound::depth(self.depth),
        }
    }

    /// Whether the roots are the refs alone. A time bound, a branch selection,
    /// and a per-branch depth each imply it, as `refs_only` states it.
    fn roots_on_refs_alone(&self) -> bool {
        self.refs_only
            || self.keep_younger_than.is_some()
            || !self.only_branch.is_empty()
            || !self.retain_branch_depth.is_empty()
    }

    /// The bound one enumerated ref's history takes.
    ///
    /// The last `retain_branch_depth` entry naming the ref decides it, unless
    /// that entry's depth is `0`, which leaves the ref at the global bound. A
    /// ref no entry names takes the global bound where `only_branch` is empty
    /// or names it, and is retained in full otherwise.
    ///
    /// Both lists carry the value the caller gave, so a ref is selected by its
    /// name and not by the commit the value resolves to.
    fn ref_bound(&self, name: &str) -> ParentBound {
        let entry = self
            .retain_branch_depth
            .iter()
            .rev()
            .find(|(branch, _)| branch == name)
            .map(|(_, depth)| *depth);
        match entry {
            Some(depth) if depth != 0 => ParentBound::depth(depth),
            entry => {
                let named = entry.is_some() || self.only_branch.iter().any(|value| value == name);
                if self.only_branch.is_empty() || named {
                    self.global_bound()
                } else {
                    ParentBound::Depth(-1)
                }
            }
        }
    }
}

/// Whether an object of this type is in the counts a run reports.
///
/// Detached commit metadata and tombstone markers are outside both counts, and
/// `commit_only` narrows them to commit objects, which is what the `ostree`
/// tool reports. Static deltas are outside both counts by not being loose
/// objects.
fn counted(ty: ObjectType, commit_only: bool) -> bool {
    if commit_only {
        ty == ObjectType::Commit
    } else {
        !matches!(ty, ObjectType::CommitMeta | ObjectType::TombstoneCommit)
    }
}

/// The outcome of a [`Repo::prune`] run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneStats {
    /// The number of loose objects considered: the store's total after any
    /// `delete_commit` removal, with detached commit metadata and tombstone
    /// markers left out and static deltas outside it. Under `commit_only` it
    /// counts commit objects alone.
    pub total_objects: usize,
    /// The number of objects deleted (or, under `no_prune`, that would be), on
    /// the terms `total_objects` states: a `.commitmeta` removed alongside its
    /// commit is not in the number, and neither is a static delta.
    pub pruned_objects: usize,
    /// The on-disk bytes freed by the objects `pruned_objects` counts (or that
    /// would be).
    pub freed_bytes: u64,
}

/// What the blocking half of a prune does with each doomed object.
#[derive(Debug, Clone, Copy)]
struct Sweep {
    /// The repository mode, which names each object's loose path.
    mode: RepoMode,
    /// Delete nothing and report what the deletion would free.
    no_prune: bool,
    /// Write a `.tombstone-commit` for each commit removed.
    tombstones: bool,
    /// Place each tombstone on stable storage before it is linked into place.
    fsync: bool,
    /// Count commit objects alone.
    commit_only: bool,
}

impl Repo {
    /// Prune unreachable objects, returning the run's statistics.
    pub async fn prune(&self, opts: &PruneOptions) -> Result<PruneStats> {
        let mode = self.mode();

        // The delta-only run needs the commit it keys on, so refuse the pair
        // before anything is read.
        let Some(delta_target) = opts.delete_commit else {
            if opts.static_deltas_only {
                return Err(Error::InvalidFormat(
                    "static_deltas_only requires delete_commit".into(),
                ));
            }
            return self.prune_objects(opts, mode).await;
        };
        if opts.static_deltas_only {
            // The run removes the named commit's deltas and nothing else, so
            // the counts report the store as it stands and the ref check that
            // guards a commit deletion does not apply.
            let commit_only = opts.commit_only;
            let total_objects = self
                .count_objects(move |ty| counted(ty, commit_only))
                .await?;
            if !opts.no_prune {
                self.sweep_static_deltas(&HashSet::from([delta_target]))
                    .await?;
            }
            return Ok(PruneStats {
                total_objects,
                pruned_objects: 0,
                freed_bytes: 0,
            });
        }
        self.prune_objects(opts, mode).await
    }

    /// The object sweep: the walk, the deletions, and the static deltas the
    /// deletions stranded.
    async fn prune_objects(&self, opts: &PruneOptions, mode: RepoMode) -> Result<PruneStats> {
        // A commit a ref points at is not deletable. Refuse it here, so a prune
        // that cannot succeed fails before the traversal. The unlink checks
        // again, because a ref naming the commit can appear while the walk
        // runs.
        if let Some(commit) = opts.delete_commit {
            self.refuse_referenced_commit(&commit).await?;
        }

        // Assemble the roots: every ref's target under the bound its branch
        // takes, plus every commit in the store unless the caller restricted to
        // refs. A commit named for deletion is dropped from the store's view
        // here and unlinked once the walk has succeeded, so it roots nothing and
        // the sweep, which runs over this same view, does not name it a second
        // time.
        let named_refs = self.list_all_refs().await?;
        // Every branch selection is resolved as a revision, so a value naming
        // nothing fails the prune before any object is removed. The commit it
        // resolves to is not read: the value selects a branch by matching a ref
        // name.
        for value in &opts.only_branch {
            self.resolve_rev(value, false).await?;
        }
        let mut roots: Vec<(Checksum, ParentBound)> = named_refs
            .iter()
            .map(|(name, checksum)| (*checksum, opts.ref_bound(name)))
            .collect();
        // A ref's bound belongs to the commit it names, not to the path the
        // walk took to reach it, so the walk replaces an inherited bound at
        // every ref target it arrives at. Where two refs name one commit, both
        // roots stand and the commit is expanded under each of the two bounds.
        let ref_targets: HashSet<Checksum> =
            named_refs.iter().map(|(_, checksum)| *checksum).collect();

        let mut all_objects = self.list_objects().await?;
        if let Some(commit) = opts.delete_commit {
            all_objects.remove(&ObjectName::new(commit, ObjectType::Commit));
            all_objects.remove(&ObjectName::new(commit, ObjectType::CommitMeta));
        }
        let global_bound = opts.global_bound();
        if !opts.roots_on_refs_alone() {
            roots.extend(
                all_objects
                    .iter()
                    .filter(|o| o.ty == ObjectType::Commit)
                    .map(|o| (o.checksum, global_bound)),
            );
        }

        let gc = crate::traverse::GcRoots {
            metadata_keys: opts.gc_root_metadata_keys.clone(),
            traverse_parent: opts.traverse_parent,
            // A `commit_only` run consults the reachable set for commit names
            // alone, so the trees are neither read nor collected.
            traverse_tree: !opts.commit_only,
        };
        let mut keep = self
            .traverse_reachable_gc(roots, global_bound, &gc, &ref_targets, opts.delete_commit)
            .await?;
        // A kept commit keeps its detached metadata.
        let kept_commits: Vec<Checksum> = keep
            .iter()
            .filter(|name| name.ty == ObjectType::Commit)
            .map(|name| name.checksum)
            .collect();
        for checksum in kept_commits {
            keep.insert(ObjectName::new(checksum, ObjectType::CommitMeta));
        }

        // Everything present but unreachable is a prune candidate, except
        // tombstone markers, which the tool never prunes. `commit_only` narrows
        // the candidates to commit objects and the detached metadata removed
        // alongside one.
        // The store's objects less the reachable ones is the largest the list
        // can grow to, so one allocation holds it.
        let mut doomed: Vec<ObjectName> =
            Vec::with_capacity(all_objects.len().saturating_sub(keep.len()));
        doomed.extend(
            all_objects
                .iter()
                .filter(|o| o.ty != ObjectType::TombstoneCommit && !keep.contains(o))
                .filter(|o| {
                    !opts.commit_only || matches!(o.ty, ObjectType::Commit | ObjectType::CommitMeta)
                })
                .copied(),
        );

        let total_objects = all_objects
            .iter()
            .filter(|o| counted(o.ty, opts.commit_only))
            .count();

        let sweep = Sweep {
            mode,
            no_prune: opts.no_prune,
            // `delete_commit` turns tombstone writing on for the whole run, as
            // the config key does for a run that names no commit.
            tombstones: opts.delete_commit.is_some() || self.config().tombstone_commits()?,
            fsync: self.config().fsync()?,
            commit_only: opts.commit_only,
        };

        // The walk succeeded, so no data the prune reads can refuse it now:
        // remove the named commit, then sweep what it orphaned. A dry run keeps
        // the commit and reports the sweep its removal would cause.
        if !opts.no_prune
            && let Some(commit) = opts.delete_commit
        {
            self.delete_commit_object(&commit, &sweep).await?;
        }

        let repo = self.clone();
        let doomed_deltas: HashSet<Checksum> = doomed
            .iter()
            .filter(|o| o.ty == ObjectType::Commit)
            .map(|o| o.checksum)
            .chain(opts.delete_commit)
            .collect();
        let (pruned_objects, freed_bytes) =
            ostrya_rt::unblock(move || sweep_blocking(&repo, &sweep, &doomed)).await?;

        if !opts.no_prune {
            self.sweep_static_deltas(&doomed_deltas).await?;
        }

        Ok(PruneStats {
            total_objects,
            pruned_objects,
            freed_bytes,
        })
    }

    /// Refuse a commit any ref points at, so pruning cannot leave a dangling
    /// ref.
    async fn refuse_referenced_commit(&self, commit: &Checksum) -> Result<()> {
        let referenced = self.list_all_ref_targets().await?;
        if referenced.contains(commit) {
            return Err(Error::InvalidFormat(format!(
                "cannot delete commit {commit}: it is the target of a ref"
            )));
        }
        Ok(())
    }

    /// Remove a named commit's object, its detached metadata, and its partial
    /// marker, writing its tombstone first where the run writes tombstones.
    ///
    /// The ref check runs again next to the unlink, so a ref published while
    /// the prune walked the store still refuses the deletion.
    async fn delete_commit_object(&self, commit: &Checksum, sweep: &Sweep) -> Result<()> {
        self.refuse_referenced_commit(commit).await?;
        let mode = self.mode();
        let commit = *commit;
        let sweep = *sweep;
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            if sweep.tombstones {
                write_tombstone(repo.objects_fd(), &commit, sweep.mode, sweep.fsync)?;
            }
            let commit_path = loose_path(&commit, ObjectType::Commit, mode);
            unlink_optional(repo.objects_fd(), &commit_path)?;
            let meta_path = loose_path(&commit, ObjectType::CommitMeta, mode);
            unlink_optional(repo.objects_fd(), &meta_path)?;
            let partial = crate::pull::partial_path(&commit);
            unlink_optional(repo.repo_fd(), &partial)?;
            Ok(())
        })
        .await
    }

    /// Remove the static delta of every commit in `targets`.
    ///
    /// A delta is keyed by the commit it produces, so a delta whose source
    /// commit the run deleted is left where it stands. The `delta-indexes/`
    /// cache is not touched, which is what the `ostree` tool's prune leaves.
    async fn sweep_static_deltas(&self, targets: &HashSet<Checksum>) -> Result<()> {
        if targets.is_empty() {
            return Ok(());
        }
        let targets = targets.clone();
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            let repo_fd = repo.repo_fd();
            for dir in crate::delta::list_delta_dirs(repo_fd)? {
                if targets.contains(&dir.to) {
                    crate::delta::remove_delta_dir(repo_fd, &dir)?;
                }
            }
            Ok(())
        })
        .await
    }
}

/// Stat and (unless `no_prune`) unlink each doomed object, summing the bytes
/// freed. A pruned commit also loses its `state/<commit>.commitpartial` marker
/// and, where the run writes tombstones, gains a `.tombstone-commit` written
/// before the unlink.
fn sweep_blocking(repo: &Repo, sweep: &Sweep, doomed: &[ObjectName]) -> Result<(usize, u64)> {
    let objects_fd = repo.objects_fd();
    let mut count = 0usize;
    let mut freed = 0u64;
    for name in doomed {
        let path = name.loose_path(sweep.mode);
        let size = match rustix::fs::statat(objects_fd, path.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat.st_size.max(0) as u64,
            // Raced away already, or never present; nothing to free.
            Err(Errno::NOENT) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        };
        if !sweep.no_prune {
            if sweep.tombstones && name.ty == ObjectType::Commit {
                write_tombstone(objects_fd, &name.checksum, sweep.mode, sweep.fsync)?;
            }
            unlink_optional(objects_fd, &path)?;
            if name.ty == ObjectType::Commit {
                let partial = crate::pull::partial_path(&name.checksum);
                unlink_optional(repo.repo_fd(), &partial)?;
            }
        }
        if !counted(name.ty, sweep.commit_only) {
            continue;
        }
        count += 1;
        freed += size;
    }
    Ok((count, freed))
}

/// Unlink a path relative to `dir`, treating an already-absent file as success.
fn unlink_optional(dir: BorrowedFd<'_>, path: &str) -> Result<()> {
    match rustix::fs::unlinkat(dir, path, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(Error::Io(e.into())),
    }
}
