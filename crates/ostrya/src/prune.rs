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
//! - [`depth`](PruneOptions::depth) bounds how far back each ref's history is
//!   kept: `-1` (the default) keeps the whole ancestry, `0` keeps only each
//!   ref's head commit, `N` keeps `N` parents.
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
//!
//! Two options carry reachability the tool has no counterpart for, so a prune
//! that leaves them at their defaults is the tool's:
//! [`gc_root_properties`](PruneOptions::gc_root_properties) names metadata
//! properties whose value names further commits to keep, and
//! [`traverse_parent`](PruneOptions::traverse_parent) decides whether a commit's
//! `parent` is reachable from it at all.

use std::os::fd::BorrowedFd;

use ostrya_core::{Checksum, ObjectName, ObjectType, RepoMode, loose_path};
use rustix::fs::AtFlags;
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::repo::Repo;

/// Options controlling [`Repo::prune`].
#[derive(Debug, Clone)]
pub struct PruneOptions {
    /// Keep only objects reachable from refs. When false, every commit object
    /// present in the store is also treated as a root, so unreferenced commits
    /// survive.
    pub refs_only: bool,
    /// How many parent commits of each ref to keep: `-1` for the whole
    /// ancestry, `0` for only the head, `N` for `N` parents.
    pub depth: i32,
    /// Compute the statistics without deleting anything, including the commit
    /// [`delete_commit`](PruneOptions::delete_commit) names.
    pub no_prune: bool,
    /// Remove this specific commit object before sweeping. It must not be the
    /// target of any ref. Under [`no_prune`](PruneOptions::no_prune) it stays,
    /// and the statistics cover the sweep its removal would cause.
    pub delete_commit: Option<Checksum>,
    /// Metadata property names that name further reachable commits.
    ///
    /// Each name is looked up in every reached commit's own metadata and in its
    /// detached metadata. A property that is present holds an `aay` whose
    /// elements are commit checksums, and each of those commits is walked as a
    /// root of its own, so what it reaches is kept too. A property that holds
    /// anything else fails the prune with [`Error::InvalidGcRoot`].
    ///
    /// The list is empty by default, which reads no metadata at all. A
    /// non-empty list adds no reachability under
    /// [`refs_only`](PruneOptions::refs_only) unset, since a prune that is not
    /// restricted to refs already roots every commit in the store. It is still
    /// read there: every commit's metadata and detached metadata is looked up,
    /// and a property of the wrong type fails the prune under either setting.
    pub gc_root_properties: Vec<String>,
    /// Whether a commit's `parent` is reachable from it.
    ///
    /// True by default, which is what the tool does and what
    /// [`depth`](PruneOptions::depth) bounds. False keeps a commit's ancestry
    /// only where something else names it, which is the setting an application
    /// tracking its own roots through
    /// [`gc_root_properties`](PruneOptions::gc_root_properties) uses.
    pub traverse_parent: bool,
}

impl Default for PruneOptions {
    fn default() -> Self {
        PruneOptions {
            refs_only: false,
            depth: -1,
            no_prune: false,
            delete_commit: None,
            gc_root_properties: Vec::new(),
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

    /// Prune against the named properties as the extra roots, over refs alone
    /// and without the `parent` edge: an application that records its own
    /// reachability in commit metadata says what is kept, and a commit's
    /// ancestry is not kept for being an ancestry.
    ///
    /// The caller sets [`traverse_parent`](PruneOptions::traverse_parent) back
    /// to true on the result to have both edge kinds.
    pub fn gc_roots<I, S>(properties: I) -> PruneOptions
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        PruneOptions {
            refs_only: true,
            gc_root_properties: properties.into_iter().map(Into::into).collect(),
            traverse_parent: false,
            ..PruneOptions::default()
        }
    }
}

/// The outcome of a [`Repo::prune`] run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneStats {
    /// The number of loose objects considered (the store's total after any
    /// `delete_commit` removal).
    pub total_objects: usize,
    /// The number of objects deleted (or, under `no_prune`, that would be).
    pub pruned_objects: usize,
    /// The on-disk bytes freed by the deleted objects (or that would be).
    pub freed_bytes: u64,
}

impl Repo {
    /// Prune unreachable objects, returning the run's statistics.
    pub async fn prune(&self, opts: &PruneOptions) -> Result<PruneStats> {
        let mode = self.mode();

        // A commit a ref points at is not deletable. Refuse it here, so a prune
        // that cannot succeed fails before the traversal. The unlink checks
        // again, because a ref naming the commit can appear while the walk
        // runs.
        if let Some(commit) = opts.delete_commit {
            self.refuse_referenced_commit(&commit).await?;
        }

        // Assemble the roots: every ref's target, plus every commit in the
        // store unless the caller restricted to refs. A commit named for
        // deletion is dropped from the store's view here and unlinked once the
        // walk has succeeded, so it roots nothing and the sweep, which runs
        // over this same view, does not name it a second time.
        let mut roots: Vec<Checksum> = self.list_all_ref_targets().await?;
        let mut all_objects = self.list_objects().await?;
        if let Some(commit) = opts.delete_commit {
            all_objects.remove(&ObjectName::new(commit, ObjectType::Commit));
            all_objects.remove(&ObjectName::new(commit, ObjectType::CommitMeta));
        }
        if !opts.refs_only {
            roots.extend(
                all_objects
                    .iter()
                    .filter(|o| o.ty == ObjectType::Commit)
                    .map(|o| o.checksum),
            );
        }

        let gc = crate::traverse::GcRoots {
            properties: opts.gc_root_properties.clone(),
            traverse_parent: opts.traverse_parent,
        };
        let mut keep = self
            .traverse_reachable_gc(roots, opts.depth, &gc, opts.delete_commit)
            .await?;
        // A kept commit keeps its detached metadata.
        for name in keep.clone() {
            if name.ty == ObjectType::Commit {
                keep.insert(ObjectName::new(name.checksum, ObjectType::CommitMeta));
            }
        }

        // Everything present but unreachable is a prune candidate, except
        // tombstone markers, which the tool never prunes.
        let doomed: Vec<ObjectName> = all_objects
            .iter()
            .filter(|o| o.ty != ObjectType::TombstoneCommit && !keep.contains(o))
            .copied()
            .collect();

        let total_objects = all_objects.len();

        // The walk succeeded, so no data the prune reads can refuse it now:
        // remove the named commit, then sweep what it orphaned. A dry run keeps
        // the commit and reports the sweep its removal would cause.
        if !opts.no_prune
            && let Some(commit) = opts.delete_commit
        {
            self.delete_commit_object(&commit).await?;
        }

        let no_prune = opts.no_prune;
        let repo = self.clone();
        let (pruned_objects, freed_bytes) =
            ostrya_rt::unblock(move || sweep_blocking(&repo, mode, &doomed, no_prune)).await?;

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
    /// marker.
    ///
    /// The ref check runs again next to the unlink, so a ref published while
    /// the prune walked the store still refuses the deletion.
    async fn delete_commit_object(&self, commit: &Checksum) -> Result<()> {
        self.refuse_referenced_commit(commit).await?;
        let mode = self.mode();
        let commit = *commit;
        let repo = self.clone();
        ostrya_rt::unblock(move || {
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
}

/// Stat and (unless `no_prune`) unlink each doomed object, summing the bytes
/// freed. A pruned commit also loses its `state/<commit>.commitpartial` marker.
fn sweep_blocking(
    repo: &Repo,
    mode: RepoMode,
    doomed: &[ObjectName],
    no_prune: bool,
) -> Result<(usize, u64)> {
    let objects_fd = repo.objects_fd();
    let mut count = 0usize;
    let mut freed = 0u64;
    for name in doomed {
        let path = name.loose_path(mode);
        let size = match rustix::fs::statat(objects_fd, path.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat.st_size.max(0) as u64,
            // Raced away already, or never present; nothing to free.
            Err(Errno::NOENT) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        };
        if !no_prune {
            unlink_optional(objects_fd, &path)?;
            if name.ty == ObjectType::Commit {
                let partial = crate::pull::partial_path(&name.checksum);
                unlink_optional(repo.repo_fd(), &partial)?;
            }
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
