//! Removal of unreachable objects.
//!
//! [`Repo::prune`] walks from a set of roots and removes each loose object
//! that the walk does not reach. If the three ostrya extensions of
//! [`PruneOptions`] keep their defaults, a run does the same work as the
//! `ostree prune` command, as observed.
//!
//! - [`PruneOptions`] sets the roots, the bounds, and the dry run.
//! - [`PruneStats`] holds the counts of a run and the refs that it deleted.
//! - [`WeakRefFilter`] marks refs weak, so that a run can delete them.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

use ostrya_core::{Checksum, ObjectName, ObjectType, RepoMode, loose_path};
use rustix::fs::AtFlags;
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::lock::LockKind;
use crate::repo::Repo;
use crate::tombstone::write_tombstone;
use crate::traverse::{ListedRef, ParentBound, RefSpace, WeakBounds};

/// The callback of a [`WeakRefFilter`]: a verdict on one ref.
///
/// The arguments are the name of the ref and the commit that it resolves to.
/// If the callback returns `true`, the ref is strong: it roots the walk under
/// the bound of its name. If the callback returns `false`, the ref is weak and
/// roots nothing. A weak ref survives if the walk reaches its commit over some
/// other edge. Otherwise the run deletes it.
pub type WeakRefFilterFn = Arc<dyn Fn(&str, &Checksum) -> bool + Send + Sync>;

/// The ref classifier of a prune, unset by default.
///
/// An unset filter marks every ref strong, so a prune with no filter deletes no
/// ref. [`PruneOptions::weak_ref_filter`] states how a run uses the verdicts.
///
/// The callback is in an [`Arc`], so a caller can share one classifier across
/// more than one [`PruneOptions`]. A classifier that keeps state must supply
/// its own interior mutability.
///
/// # Callback rules
///
/// The callback runs on the executor thread while the run holds the repository
/// lock exclusive, so it must call no [`Repo`] method:
///
/// - A call to [`Repo::transaction`] inside it waits until `[core]
///   lock-timeout-secs` passes and then fails. If the value is `-1`, the wait
///   has no end.
/// - A `block_on` call into the async runtime inside it re-enters the runtime.
///
/// The result of the callback must depend only on its two arguments and on the
/// state that the caller captured before the call.
///
/// If a classifier moves a ref as a side effect of its call, the hazard belongs
/// to the caller. The compare-and-delete guard stops the run from unlinking a
/// ref that moved. The run walks once, so the objects under the new commit of
/// that ref can still go.
#[derive(Clone, Default)]
pub struct WeakRefFilter(Option<WeakRefFilterFn>);

impl WeakRefFilter {
    /// Creates a filter that calls `f` for each ref that it classifies.
    pub fn new<F>(f: F) -> WeakRefFilter
    where
        F: Fn(&str, &Checksum) -> bool + Send + Sync + 'static,
    {
        WeakRefFilter(Some(Arc::new(f)))
    }

    /// Creates a filter from a callback that the caller already holds.
    ///
    /// The caller can share the callback with another [`PruneOptions`].
    pub fn from_fn(f: WeakRefFilterFn) -> WeakRefFilter {
        WeakRefFilter(Some(f))
    }

    /// Returns `true` if the filter holds a callback.
    pub(crate) fn is_set(&self) -> bool {
        self.0.is_some()
    }

    /// Returns `true` if the ref is strong. An unset filter returns `true` for
    /// each ref.
    pub(crate) fn is_strong(&self, name: &str, target: &Checksum) -> bool {
        match &self.0 {
            Some(f) => f(name, target),
            None => true,
        }
    }
}

impl std::fmt::Debug for WeakRefFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(_) => f.write_str("WeakRefFilter(set)"),
            None => f.write_str("WeakRefFilter(unset)"),
        }
    }
}

/// The options of [`Repo::prune`].
///
/// [`PruneOptions::default`] gives a run that keeps each object that a commit
/// in the store reaches. [`Repo::prune`] states how the options set the roots
/// and the bounds of the walk.
///
/// # Extensions
///
/// Three options are ostrya extensions. The `ostree` command has no
/// counterpart for them:
///
/// - [`gc_root_metadata_keys`](PruneOptions::gc_root_metadata_keys): metadata
///   keys whose values name more commits to keep.
/// - [`traverse_parent`](PruneOptions::traverse_parent): the switch that makes
///   the `parent` of a commit reachable from it.
/// - [`weak_ref_filter`](PruneOptions::weak_ref_filter): the classifier that
///   marks each ref strong or weak.
///
/// The default of each one is the behavior without the option. A prune that
/// keeps all three at their defaults does the same work as the `ostree`
/// command.
#[derive(Debug, Clone)]
pub struct PruneOptions {
    /// The switch that roots the walk on the refs alone.
    ///
    /// If it is `false` (the default), each commit object in the store is also
    /// a root. A commit that no ref names then survives with its objects. If
    /// it is `true`, only the commits that a ref reaches survive.
    pub refs_only: bool,
    /// The number of parent commits that the run keeps for each ref.
    ///
    /// - `-1` (the default) keeps the whole ancestry.
    /// - `0` keeps only the commit that the ref names.
    /// - `N` keeps `N` parents.
    /// - Each other negative value keeps only the commit that the ref names.
    pub depth: i32,
    /// The switch for a dry run that computes the statistics and deletes
    /// nothing.
    ///
    /// The run also keeps the commit that
    /// [`delete_commit`](PruneOptions::delete_commit) names.
    pub no_prune: bool,
    /// A commit object that the run removes before the sweep.
    ///
    /// No ref can name the commit. The walk reads the commit as absent, so the
    /// sweep removes each object that only this commit reached. The run unlinks
    /// the commit object after the walk succeeds. The counts cover only the
    /// swept objects, as the counts of the `ostree` command do.
    ///
    /// If [`no_prune`](PruneOptions::no_prune) is set, the commit stays, and
    /// the statistics report the sweep that its removal causes. The
    /// `ostree` command refuses the two options together, and so does the
    /// `ostrya` CLI.
    pub delete_commit: Option<Checksum>,
    /// The oldest commit time that the run keeps, in seconds since the Unix
    /// epoch.
    ///
    /// If it is `Some`, the run roots the walk on the refs alone, as
    /// [`refs_only`](PruneOptions::refs_only) does. A commit that the walk
    /// reaches over a `parent` edge survives if its own timestamp is at or
    /// after the bound. The commit that a ref names survives whatever its
    /// timestamp.
    ///
    /// The time bound replaces [`depth`](PruneOptions::depth) for each branch
    /// that [`retain_branch_depth`](PruneOptions::retain_branch_depth) leaves
    /// at the global value. A ref that
    /// [`weak_ref_filter`](PruneOptions::weak_ref_filter) marks weak gets no
    /// guarantee, because it roots the walk under no bound.
    pub keep_younger_than: Option<u64>,
    /// The branches that the run prunes.
    ///
    /// Each value names a branch as [`Repo::list_refs`](crate::Repo::list_refs)
    /// and [`Repo::list_remote_refs`](crate::Repo::list_remote_refs) name one.
    /// An empty list prunes every branch.
    ///
    /// A non-empty list roots the walk on the refs alone. The run keeps in full
    /// each branch that neither this list nor
    /// [`retain_branch_depth`](PruneOptions::retain_branch_depth) names.
    ///
    /// The run resolves each value as a revision, so a value that names nothing
    /// fails the prune before the run removes an object. A value that resolves
    /// and matches no ref name selects no branch. If no value selects a branch,
    /// the run keeps every branch in full.
    ///
    /// A ref that [`weak_ref_filter`](PruneOptions::weak_ref_filter) marks weak
    /// gets no retention from this list, because it roots the walk under no
    /// bound.
    pub only_branch: Vec<String>,
    /// Depths for single branches, each in place of
    /// [`depth`](PruneOptions::depth) for its branch.
    ///
    /// A non-empty list roots the walk on the refs alone, as
    /// [`refs_only`](PruneOptions::refs_only) does. The run reads the entries
    /// in order, and the last entry that names a branch decides its depth. An
    /// entry with the depth `0` leaves the branch at the global
    /// [`depth`](PruneOptions::depth) and still counts as a name.
    ///
    /// [`only_branch`](PruneOptions::only_branch) never keeps in full a branch
    /// that this list names.
    pub retain_branch_depth: Vec<(String, i32)>,
    /// The switch that deletes commit objects alone.
    ///
    /// The objects that a deleted commit reached stay in place, and the
    /// statistics count commit objects alone.
    pub commit_only: bool,
    /// The switch that deletes only the static deltas that target
    /// [`delete_commit`](PruneOptions::delete_commit).
    ///
    /// The run leaves every loose object in place. The switch needs
    /// [`delete_commit`](PruneOptions::delete_commit). If `delete_commit` is
    /// `None`, the prune fails with [`Error::InvalidFormat`].
    pub static_deltas_only: bool,
    /// Metadata keys whose values name more commits to keep.
    ///
    /// The run looks up each key in the metadata of each reached commit and in
    /// its detached metadata. A key that is present holds an `aay` whose
    /// elements are commit checksums. The run walks each of those commits as a
    /// root of its own, so it also keeps what that commit reaches. Such a
    /// commit gets the full depth of the walk, because the depth counts parent
    /// hops.
    ///
    /// If a key holds a value of another type, the prune fails with
    /// [`Error::InvalidGcRoot`].
    ///
    /// The list is empty by default, and an empty list reads no metadata. If
    /// [`refs_only`](PruneOptions::refs_only) is `false`, a non-empty list adds
    /// no reachability, because each commit in the store is already a root.
    /// The run still reads the metadata and the detached metadata of each
    /// commit. A key of the wrong type fails the prune with either value of
    /// `refs_only`.
    ///
    /// This field is an ostrya extension. The `ostrya` CLI fills it from the
    /// repository config key `[ex-ostrya] gc-root-metadata-keys`
    /// ([`RepoConfig::gc_root_metadata_keys`](crate::RepoConfig::gc_root_metadata_keys)).
    pub gc_root_metadata_keys: Vec<String>,
    /// The switch that makes the `parent` of a commit reachable from it.
    ///
    /// The default is `true`, which is the behavior of the `ostree` command.
    /// [`depth`](PruneOptions::depth) bounds the edge. If it is `false`, the
    /// ancestry of a commit survives only where something else names it. An
    /// application that tracks its own roots through
    /// [`gc_root_metadata_keys`](PruneOptions::gc_root_metadata_keys) uses this
    /// setting.
    ///
    /// This field is an ostrya extension. The repository config has no key for
    /// it, so a prune that the `ostrya` CLI runs always follows the `parent`
    /// edge. A CLI prune with configured metadata keys adds roots and removes
    /// none, so it keeps at least what the `ostree` command keeps.
    pub traverse_parent: bool,
    /// The classifier that marks each ref strong or weak.
    ///
    /// The default is unset, which marks every ref strong and deletes no ref.
    /// A set filter needs [`refs_only`](PruneOptions::refs_only). If
    /// `refs_only` is `false`, the prune fails with [`Error::InvalidFormat`]
    /// before the run reads anything. This field is an ostrya extension.
    ///
    /// The filter sees these names:
    ///
    /// - For a ref under `refs/heads`, its path in that directory.
    /// - For a ref under `refs/remotes`, its `<remote>:<name>` refspec.
    ///
    /// A ref under `refs/mirrors` is strong and never reaches the filter. A ref
    /// whose listed name maps to a different file through the refspec rule is
    /// also strong, and the filter never sees it:
    ///
    /// - A local name maps to its own file if the name holds no `:`.
    /// - A remote refspec maps to its own file if the first `/` of the path
    ///   in `refs/remotes` is the first `:` of the name.
    ///
    /// A classifier that tests a prefix of the name keeps its meaning if the
    /// prefix holds a `/` before any `:`. Such a prefix matches only a local
    /// name. A prefix that is a bare segment also matches a remote refspec, and
    /// so does a substring test. For example, the prefix `pool` matches
    /// `poolcache:main`, the refspec of a ref of the remote `poolcache`.
    ///
    /// A strong ref roots the walk under the bound that
    /// [`retain_branch_depth`](PruneOptions::retain_branch_depth),
    /// [`only_branch`](PruneOptions::only_branch), and
    /// [`depth`](PruneOptions::depth) give its name. A weak ref roots nothing.
    /// It survives if the walk reaches its commit over some other edge:
    ///
    /// - An arrival over a `parent` edge gives the commit the bound of the name
    ///   of the weak ref. That bound replaces the bound that the edge left. The
    ///   target of a strong ref gets the same rule.
    /// - An arrival over another edge carries a bound of its own. The commit
    ///   expands under that bound and under the bound of the weak ref.
    ///
    /// The run deletes each weak ref that the walk did not reach and names it
    /// in [`PruneStats::deleted_refs`].
    ///
    /// The branch selection has nothing to select for a weak ref, because a
    /// weak ref roots nothing. The filter also classifies a weak ref outside an
    /// [`only_branch`](PruneOptions::only_branch) selection. If the walk does
    /// not reach its commit, the run deletes the ref and sweeps its objects.
    /// [`keep_younger_than`](PruneOptions::keep_younger_than) keeps only the
    /// target of a strong ref. The run deletes a weak ref that the walk does
    /// not reach, whatever the timestamp of its commit.
    pub weak_ref_filter: WeakRefFilter,
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
            weak_ref_filter: WeakRefFilter::default(),
        }
    }
}

impl PruneOptions {
    /// Creates the default options.
    ///
    /// A run with these options keeps each object that a commit in the store
    /// reaches. In a repository with no unreachable objects, it removes
    /// nothing.
    pub fn new() -> PruneOptions {
        PruneOptions::default()
    }

    /// Creates options for a walk over refs and metadata keys with no `parent` edge.
    ///
    /// The options set [`refs_only`](PruneOptions::refs_only) to `true`,
    /// [`gc_root_metadata_keys`](PruneOptions::gc_root_metadata_keys) to
    /// `keys`, and [`traverse_parent`](PruneOptions::traverse_parent) to
    /// `false`. The other fields keep their defaults.
    ///
    /// With these options, an application that records its own reachability in
    /// commit metadata decides what the run keeps. The ancestry of a commit
    /// survives only where something else names it. A caller that wants both
    /// edge kinds sets `traverse_parent` back to `true` on the result.
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

    /// Returns the bound of a branch that no `retain_branch_depth` entry names
    /// and that `only_branch` leaves at the global setting.
    fn global_bound(&self) -> ParentBound {
        match self.keep_younger_than {
            Some(since) => ParentBound::Since(since),
            None => ParentBound::depth(self.depth),
        }
    }

    /// Returns `true` if the roots are the refs alone.
    ///
    /// A time bound, a branch selection, and a depth for one branch each have
    /// the same effect as `refs_only`.
    fn roots_on_refs_alone(&self) -> bool {
        self.refs_only
            || self.keep_younger_than.is_some()
            || !self.only_branch.is_empty()
            || !self.retain_branch_depth.is_empty()
    }

    /// Returns the bound of the history of one listed ref.
    ///
    /// The last `retain_branch_depth` entry that names the ref decides the
    /// bound. If the depth of that entry is `0`, the ref takes the global
    /// bound. A ref that no entry names takes the global bound if
    /// `only_branch` is empty or names it. Otherwise the run keeps the ref in
    /// full.
    ///
    /// Both lists hold the values that the caller gave, so the run selects a
    /// ref by its name. The commit that a value resolves to has no effect on
    /// the selection.
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

/// Returns `true` if an object of this type is in the counts of a run.
///
/// Detached commit metadata and tombstone markers are outside both counts.
/// `commit_only` narrows the counts to commit objects, which is what the
/// `ostree` command reports. Static deltas are not loose objects, so they are
/// outside both counts.
fn counted(ty: ObjectType, commit_only: bool) -> bool {
    if commit_only {
        ty == ObjectType::Commit
    } else {
        !matches!(ty, ObjectType::CommitMeta | ObjectType::TombstoneCommit)
    }
}

/// The statistics of a [`Repo::prune`] run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneStats {
    /// The number of loose objects that the run considered.
    ///
    /// It is the total of the store after a
    /// [`delete_commit`](PruneOptions::delete_commit) removal. It leaves out
    /// detached commit metadata and tombstone markers. Static deltas are not
    /// loose objects, so they are outside it. If
    /// [`commit_only`](PruneOptions::commit_only) is set, it counts commit
    /// objects alone.
    pub total_objects: usize,
    /// The number of objects that the run deleted.
    ///
    /// If [`no_prune`](PruneOptions::no_prune) is set, it is the number that
    /// the run deletes without `no_prune`. It counts on the terms of
    /// [`total_objects`](PruneStats::total_objects). A `.commitmeta` removed
    /// with its commit is not in the number, and a static delta is not in it.
    pub pruned_objects: usize,
    /// The on-disk bytes of the objects that
    /// [`pruned_objects`](PruneStats::pruned_objects) counts.
    ///
    /// If [`no_prune`](PruneOptions::no_prune) is set, it is the number of
    /// bytes that the run frees without `no_prune`.
    pub freed_bytes: u64,
    /// The weak refs that the run deleted, sorted by name in byte order.
    ///
    /// If [`no_prune`](PruneOptions::no_prune) is set, the list names the refs
    /// that the run deletes without `no_prune`, and the run removes no ref. The
    /// list does not name a ref that the compare-and-delete guard skipped,
    /// because the run left that ref in place.
    ///
    /// A [`static_deltas_only`](PruneOptions::static_deltas_only) run returns
    /// before it reads the refs, so it classifies no ref. The list is then
    /// empty, whatever [`weak_ref_filter`](PruneOptions::weak_ref_filter)
    /// holds.
    ///
    /// If the run fails part way through the deletions, the refs that it
    /// already removed stay removed. The caller gets the error and no list.
    pub deleted_refs: Vec<String>,
}

/// The settings that the blocking half of a prune applies to each object that
/// it removes.
#[derive(Debug, Clone, Copy)]
struct Sweep {
    /// The repository mode, which sets the loose path of each object.
    mode: RepoMode,
    /// The switch for a dry run: delete nothing and report what a real run
    /// frees.
    no_prune: bool,
    /// The switch that writes a `.tombstone-commit` for each removed commit.
    tombstones: bool,
    /// The switch that syncs each tombstone before its link into place. It
    /// also syncs the directories that the commit removals changed before the
    /// first content object goes.
    fsync: bool,
    /// The switch that counts commit objects alone.
    commit_only: bool,
}

/// Methods that remove unreachable objects.
impl Repo {
    /// Removes the objects that no root reaches and returns the statistics.
    ///
    /// The run walks from the roots, keeps each object that the walk reaches,
    /// and removes each other loose object. A kept commit keeps its detached
    /// metadata (`.commitmeta`). The run removes the detached metadata of each
    /// commit that it removes. [`PruneOptions`] sets the roots, the bounds, and
    /// the dry run.
    ///
    /// The run reads four `[core]` keys of the repository config: `locking`
    /// and `lock-timeout-secs` when it takes the repository lock, and
    /// `tombstone-commits` and `fsync` during the run. The options decide all
    /// other behavior.
    ///
    /// # Roots
    ///
    /// The commits that the refs name are always roots.
    /// [`refs_only`](PruneOptions::refs_only) states when each other commit in
    /// the store is also a root. Each of these options roots the walk on the
    /// refs alone, as `refs_only` does:
    ///
    /// - [`keep_younger_than`](PruneOptions::keep_younger_than) if it is
    ///   `Some`.
    /// - [`only_branch`](PruneOptions::only_branch) if it is not empty.
    /// - [`retain_branch_depth`](PruneOptions::retain_branch_depth) if it is
    ///   not empty.
    ///
    /// # Bounds
    ///
    /// [`depth`](PruneOptions::depth),
    /// [`retain_branch_depth`](PruneOptions::retain_branch_depth), and
    /// [`keep_younger_than`](PruneOptions::keep_younger_than) bound the history
    /// of each ref. A bound belongs to the commit that a ref names, whatever
    /// path the walk took to that commit.
    ///
    /// The walk can arrive at the target of a ref over a `parent` edge. Then
    /// the walk drops the bound that it carried and continues under the bound
    /// of that ref. As a result, a branch cut short also cuts each history that
    /// runs through its head. If two refs name one commit, the walk expands the
    /// commit under each of the two bounds, and the commit keeps what either
    /// bound reaches.
    ///
    /// # Static deltas and markers
    ///
    /// A run removes each static delta whose target commit it deleted. It
    /// removes the whole delta directory and leaves the fanout parent
    /// directory in place. A delta whose source commit the run deleted stays.
    ///
    /// After the sweep, a run that is neither a
    /// [`no_prune`](PruneOptions::no_prune) dry run nor a
    /// [`static_deltas_only`](PruneOptions::static_deltas_only) run also
    /// removes these entries:
    ///
    /// - each static delta whose target commit is absent from the store.
    /// - each `state/<commit>.commitpartial` marker whose commit is absent.
    ///
    /// This pass removes the marker of each commit that the run removes. If a
    /// run stops part way through, it leaves these entries behind, and the
    /// next run removes them. The run holds the repository lock exclusive, so
    /// no pull stands between the write of a marker and the store of its
    /// commit. This pass is ostrya behavior: the behavior of the `ostree`
    /// command for these entries is not observed.
    ///
    /// Each delta sweep skips a delta name that does not decode and leaves that
    /// entry in place. This includes the sweep of a `static_deltas_only` run.
    ///
    /// # Sweep order
    ///
    /// The sweep removes the commits first and their content after them. For
    /// each commit, it writes the tombstone, unlinks the commit object, and
    /// then unlinks its detached metadata. Next, it removes each detached
    /// metadata whose commit is absent.
    ///
    /// If `[core] fsync` is `true`, the run syncs the `objects/` directories
    /// that these removals changed before it removes the first dirtree,
    /// dirmeta, or file object. As a result, a run that stops at an error or a
    /// crash leaves no commit object whose tree it started to remove. If
    /// `[core] fsync` is `false`, a crash gives no guarantee of the order in
    /// which the removals reach the disk.
    ///
    /// A [`delete_commit`](PruneOptions::delete_commit) run removes and syncs
    /// the named commit in the same way before the sweep.
    ///
    /// # Tombstones
    ///
    /// If [`delete_commit`](PruneOptions::delete_commit) is set or the
    /// repository config sets `[core] tombstone-commits`, the run writes a
    /// `.tombstone-commit` for each commit that it removes. The run never
    /// removes a tombstone-commit marker.
    ///
    /// # Lock
    ///
    /// The run holds the repository lock exclusive
    /// ([`LockKind`]) from start to end. This includes a
    /// [`no_prune`](PruneOptions::no_prune) dry run and a
    /// [`static_deltas_only`](PruneOptions::static_deltas_only) run. The run
    /// waits for each other holder, a held
    /// [`UpdateGuard`](crate::UpdateGuard) included. If the caller holds its
    /// own transaction open across the call, the run waits until `[core]
    /// lock-timeout-secs` passes and then fails.
    ///
    /// If the repository config sets `[core] locking` to `false`, no lock
    /// excludes a concurrent writer. Another writer can store a commit after
    /// the run lists the store. The run reads that commit as absent, so it can
    /// remove the marker and the static delta of that commit.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if
    ///   [`static_deltas_only`](PruneOptions::static_deltas_only) is set and
    ///   [`delete_commit`](PruneOptions::delete_commit) is `None`.
    /// - [`Error::InvalidFormat`] if
    ///   [`weak_ref_filter`](PruneOptions::weak_ref_filter) is set and
    ///   [`refs_only`](PruneOptions::refs_only) is `false`.
    /// - [`Error::InvalidFormat`] if a ref names the commit that
    ///   [`delete_commit`](PruneOptions::delete_commit) names. The run checks
    ///   this before the walk and again before the unlink.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is less than `-1`,
    ///   or if a ref file holds bytes that are not UTF-8.
    /// - [`Error::Core`] if a `[core]` key that the run reads holds a value of
    ///   the wrong type.
    /// - [`Error::Core`] if a ref file holds no valid checksum.
    /// - [`Error::Core`] if a commit object or its detached metadata does not
    ///   parse.
    /// - [`Error::Core`] if a dirtree that the walk reads does not parse. A
    ///   run with [`commit_only`](PruneOptions::commit_only) reads no dirtree.
    /// - [`Error::LockTimeout`] if the wait for the lock passes `[core]
    ///   lock-timeout-secs`.
    /// - An error of [`resolve_rev`](Repo::resolve_rev), for example
    ///   [`Error::RefNotFound`], if a value of
    ///   [`only_branch`](PruneOptions::only_branch) does not resolve.
    /// - [`Error::InvalidGcRoot`] if a key of
    ///   [`gc_root_metadata_keys`](PruneOptions::gc_root_metadata_keys) holds a
    ///   value that is not an `aay` of commit checksums.
    /// - [`Error::Io`] if a read, a write, or a removal on the file system
    ///   fails.
    /// - [`Error::Io`] if a metadata object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> ostrya::Result<()> {
    /// use ostrya::{PruneOptions, Repo};
    ///
    /// let repo = Repo::open("/srv/repo".as_ref()).await?;
    /// let stats = repo.prune(&PruneOptions::default()).await?;
    /// println!(
    ///     "removed {} of {} objects, {} bytes",
    ///     stats.pruned_objects, stats.total_objects, stats.freed_bytes
    /// );
    /// # Ok(()) }
    /// ```
    pub async fn prune(&self, opts: &PruneOptions) -> Result<PruneStats> {
        let mode = self.mode();

        // The delta-only run needs the commit that it keys on. The run refuses
        // the pair before the lock, so a contended repository gives the same
        // refusal as a free one.
        if opts.static_deltas_only && opts.delete_commit.is_none() {
            return Err(Error::InvalidFormat(
                "static_deltas_only requires delete_commit".into(),
            ));
        }

        // The classifier decides which refs the run deletes, and a run that
        // roots every commit in the store deletes none of them. The run refuses
        // the pair before the lock, so a contended repository gives the same
        // refusal as a free one. The refusal also comes before every read, so
        // the run never calls the classifier.
        if opts.weak_ref_filter.is_set() && !opts.refs_only {
            return Err(Error::InvalidFormat(
                "weak_ref_filter requires refs_only".into(),
            ));
        }

        let _lock = self.lock_repo(LockKind::Exclusive).await?;

        let Some(delta_target) = opts.delete_commit else {
            return self.prune_objects(opts, mode).await;
        };
        if opts.static_deltas_only {
            // The run removes the deltas of the named commit and nothing else.
            // So the counts report the store as it is, and the ref check that
            // guards a commit deletion does not apply.
            let commit_only = opts.commit_only;
            let total_objects = self
                .count_objects(move |ty| counted(ty, commit_only))
                .await?;
            if !opts.no_prune {
                let repo = self.clone();
                ostrya_rt::unblock(move || {
                    crate::delta::prune_delta_dirs(repo.repo_fd(), |to| *to == delta_target)
                })
                .await?;
            }
            return Ok(PruneStats {
                total_objects,
                pruned_objects: 0,
                freed_bytes: 0,
                // A delta-only run reads no ref, so it deletes none.
                deleted_refs: Vec::new(),
            });
        }
        self.prune_objects(opts, mode).await
    }

    /// Runs the object sweep: the walk, the deletions, and the removal of the
    /// static deltas that the deletions left with no target.
    async fn prune_objects(&self, opts: &PruneOptions, mode: RepoMode) -> Result<PruneStats> {
        // The run cannot delete a commit that a ref names. Refuse it here, so a
        // prune that cannot succeed fails before the walk. The unlink checks
        // again, because a writer that takes no repository lock can publish a
        // ref that names the commit while the walk runs.
        if let Some(commit) = opts.delete_commit {
            self.refuse_referenced_commit(&commit).await?;
        }

        // Assemble the roots: the target of each ref under the bound of its
        // branch. Unless the roots are the refs alone, each commit in the store
        // is also a root. The view of the store drops a commit named for
        // deletion here, and the run unlinks it after the walk succeeds. So it
        // roots nothing, and the sweep, which runs over this same view, does
        // not name it a second time.
        let named_refs = self.list_all_refs().await?;
        // The run resolves each branch selection as a revision, so a value
        // that names nothing fails the prune before the run removes an object.
        // The run does not read the commit that the value resolves to. The
        // value selects a branch by a match with a ref name.
        for value in &opts.only_branch {
            self.resolve_rev(value, false).await?;
        }
        // Classify the ref space in one pass, so the strong roots and the weak
        // targets cannot disagree. A ref is weak if all three hold:
        //
        // - it is in `refs/heads` or `refs/remotes`.
        // - its listed name addresses the file that it was listed from.
        // - the classifier returns false for it.
        //
        // Every other ref is strong. A ref in `refs/mirrors` is always strong
        // and never reaches the classifier. The space test states this, and
        // the addressability test holds it a second time, because no refspec
        // maps to a path in `refs/mirrors`.
        //
        // A weak target stays out of `ref_targets`: the walk needs a seed for
        // every checksum that set names, and a weak ref supplies none. The weak
        // targets go in `GcRoots::weak_roots`, and the walk seeds one on the
        // arrival that reaches it.
        //
        // If a strong ref and a weak ref name one commit, the commit enters
        // through the strong ref. So the commit is reachable, and the weak ref
        // survives.
        //
        // An unset classifier makes every ref strong, so the unset case tests
        // one boolean for each ref.
        let filtering = opts.weak_ref_filter.is_set();
        let mut roots: Vec<(Checksum, ParentBound)> = Vec::new();
        let mut ref_targets: HashSet<Checksum> = HashSet::new();
        let mut weak_refs: Vec<(String, Checksum)> = Vec::new();
        let mut weak_roots: HashMap<Checksum, WeakBounds> = HashMap::new();
        for ListedRef {
            space,
            name,
            addressable,
            checksum,
        } in named_refs
        {
            let bound = opts.ref_bound(&name);
            let weak = filtering
                && matches!(space, RefSpace::Heads | RefSpace::Remotes)
                && addressable
                && !opts.weak_ref_filter.is_strong(&name, &checksum);
            if weak {
                weak_roots.entry(checksum).or_default().add(bound);
                weak_refs.push((name, checksum));
                continue;
            }
            // The bound of a ref belongs to the commit that it names, whatever
            // path the walk took to that commit. So the walk replaces an
            // inherited bound at each ref target that it arrives at. If two refs
            // name one commit, both roots stand, and the walk expands the commit
            // under each of the two bounds.
            roots.push((checksum, bound));
            ref_targets.insert(checksum);
        }

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
            // A `commit_only` run reads only the commit names of the reachable
            // set, so the walk neither reads nor collects the trees.
            traverse_tree: !opts.commit_only,
            weak_roots,
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

        // Each present object that the walk did not reach is a candidate,
        // except tombstone markers, which the `ostree` command never prunes.
        // `commit_only` narrows the candidates to commit objects and the
        // detached metadata removed with one.
        // The objects of the store less the reachable ones is the largest size
        // of the list, so one allocation holds it.
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

        // Delete each weak ref that the walk did not reach. This pass runs
        // after the walk, because a walk that fails must leave the repository
        // as it was. It runs before the commit deletion and the sweep.
        // `refuse_referenced_commit` ran over the whole ref listing and refused
        // a `delete_commit` that a weak ref names, so the two cannot meet.
        //
        // The pass unlinks ref files alone and takes no lock of its own, so it
        // cannot deadlock against the hold of the run. An emptied parent
        // directory in `refs/heads` stays in place, because an rmdir walk races
        // a writer that creates a sibling ref.
        //
        // The whole pass runs in one blocking hop, as the object sweep does.
        // The pass reads each name immediately before its unlink, and it calls
        // `fsync` once at the end on the directories that held a removed ref.
        // The doomed list is the weak list less the refs that the walk reached,
        // in the order of the listing. So the code narrows the weak list in
        // place.
        let mut doomed_refs = weak_refs;
        doomed_refs
            .retain(|(_, target)| !keep.contains(&ObjectName::new(*target, ObjectType::Commit)));
        // A dry run reports what the walk decided and touches nothing, so it
        // reads no ref a second time.
        let mut deleted_refs: Vec<String> = if opts.no_prune {
            doomed_refs.into_iter().map(|(name, _)| name).collect()
        } else {
            let repo = self.clone();
            let fsync = sweep.fsync;
            ostrya_rt::unblock(move || {
                crate::refs::delete_matching_refs_blocking(repo.repo_fd(), doomed_refs, fsync)
            })
            .await?
        };
        deleted_refs.sort();

        // The walk succeeded, so no data that the prune reads can refuse it
        // now. Remove the named commit, then sweep what it orphaned. A dry run
        // keeps the commit and reports the sweep that its removal causes.
        if !opts.no_prune
            && let Some(commit) = opts.delete_commit
        {
            self.delete_commit_object(&commit, &sweep).await?;
        }

        // The commits that the store holds after the sweep are the listed ones
        // that the walk kept. Each listed commit that the walk did not keep is
        // doomed. The listing already leaves out the commit that
        // `delete_commit` names. The set comes from the listing in memory, so
        // the leftover sweep reads no object to learn it.
        let present_commits: HashSet<Checksum> = if opts.no_prune {
            HashSet::new()
        } else {
            all_objects
                .iter()
                .filter(|o| o.ty == ObjectType::Commit && keep.contains(o))
                .map(|o| o.checksum)
                .collect()
        };
        drop(all_objects);
        drop(keep);

        let repo = self.clone();
        let (pruned_objects, freed_bytes) =
            ostrya_rt::unblock(move || sweep_blocking(&repo, &sweep, &doomed)).await?;

        // Remove what refers to an absent commit: each static delta whose
        // target commit is absent and each `.commitpartial` marker whose commit
        // is absent. This covers the commits that this run removed, whose
        // markers the object sweep leaves for this pass. It also covers the
        // commits that a run that stopped part way through removed, which no
        // later walk finds. The run holds the repository lock exclusive, so no
        // pull stands between the write of a marker and the store of its
        // commit.
        if !opts.no_prune {
            let repo = self.clone();
            ostrya_rt::unblock(move || {
                let repo_fd = repo.repo_fd();
                crate::delta::prune_delta_dirs(repo_fd, |to| !present_commits.contains(to))?;
                sweep_orphan_markers_blocking(repo_fd, &present_commits)
            })
            .await?;
        }

        Ok(PruneStats {
            total_objects,
            pruned_objects,
            freed_bytes,
            deleted_refs,
        })
    }

    /// Refuses a commit that a ref names, so that a prune cannot leave a
    /// dangling ref.
    async fn refuse_referenced_commit(&self, commit: &Checksum) -> Result<()> {
        let referenced = self.list_all_ref_targets().await?;
        if referenced.contains(commit) {
            return Err(Error::InvalidFormat(format!(
                "cannot delete commit {commit}: it is the target of a ref"
            )));
        }
        Ok(())
    }

    /// Removes the object and the detached metadata of a named commit. If the
    /// run writes tombstones, the tombstone comes first.
    ///
    /// The ref check runs again next to the unlink, so a ref published while
    /// the prune walked the store still refuses the deletion. If the run
    /// syncs, the call syncs the directory that held the removed entries before
    /// it returns. The removal is then durable before the sweep removes an
    /// object that the commit reached. The partial marker of the commit stays.
    /// The run removes it with the orphan markers after the sweep, because the
    /// commit is absent from the listing that this pass reads.
    async fn delete_commit_object(&self, commit: &Checksum, sweep: &Sweep) -> Result<()> {
        self.refuse_referenced_commit(commit).await?;
        let commit = *commit;
        let sweep = *sweep;
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            let objects_fd = repo.objects_fd();
            let tmp = tombstone_tmp(&repo, &sweep)?;
            let mut touched = BTreeSet::new();
            remove_commit(
                tmp.as_ref().map(AsFd::as_fd),
                objects_fd,
                &sweep,
                &commit,
                true,
                &mut touched,
            )?;
            if sweep.fsync {
                sync_dirs(objects_fd, &touched)?;
            }
            Ok(())
        })
        .await
    }
}

/// Removes each `state/<commit>.commitpartial` marker whose commit is not in
/// `present`.
///
/// The function leaves in place a name that is not a marker name in lowercase
/// hex, and also a directory. A repository with no `state/` has nothing to
/// remove.
fn sweep_orphan_markers_blocking(
    repo_fd: BorrowedFd<'_>,
    present: &HashSet<Checksum>,
) -> Result<()> {
    use rustix::fs::{Dir, Mode, OFlags, openat};

    let io_err = |e: Errno| Error::Io(e.into());
    let state = match openat(
        repo_fd,
        "state",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(()),
        Err(e) => return Err(io_err(e)),
    };
    let mut orphans = Vec::new();
    for entry in Dir::new(state).map_err(io_err)? {
        let entry = entry.map_err(io_err)?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        let Some(hex) = name.strip_suffix(".commitpartial") else {
            continue;
        };
        let Ok(commit) = Checksum::from_hex_lower(hex) else {
            continue;
        };
        if !present.contains(&commit) {
            orphans.push(commit);
        }
    }
    for commit in orphans {
        let partial = crate::pull::partial_path(&commit);
        match rustix::fs::unlinkat(repo_fd, partial.as_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT | Errno::ISDIR) => {}
            Err(e) => return Err(io_err(e)),
        }
    }
    Ok(())
}

/// Opens the `tmp/` of the repository if the run writes tombstones. Each
/// tombstone write puts its temp file there. A run that writes no tombstone
/// does not open `tmp/` and does not create it.
fn tombstone_tmp(repo: &Repo, sweep: &Sweep) -> Result<Option<OwnedFd>> {
    if !sweep.tombstones {
        return Ok(None);
    }
    Ok(Some(crate::staging::open_tmp_dir(
        repo.repo_fd(),
        sweep.mode,
    )?))
}

/// Removes one commit, in this order:
///
/// 1. If `tmp_fd`, the open `tmp/` of the repository, is given, writes the
///    tombstone of the commit.
/// 2. Unlinks the commit object.
/// 3. If `meta` is true, unlinks its detached metadata.
///
/// The function adds to `touched` each `objects/` fanout directory in which it
/// unlinked an entry, named relative to `objects/`.
///
/// The `state/<commit>.commitpartial` marker of the commit stays. The commit
/// can already be partial. If a crash makes the marker unlink durable and
/// leaves the commit unlink not durable, a partial commit looks complete. The
/// run removes the marker after the object sweep, with the markers whose
/// commit is absent. The next run removes a marker that a failed or crashed
/// run leaves.
///
/// The commit goes before its detached metadata. Detached metadata with no
/// commit is unreachable, and the next prune removes it. The reverse order
/// leaves a commit with no signatures.
fn remove_commit(
    tmp_fd: Option<BorrowedFd<'_>>,
    objects_fd: BorrowedFd<'_>,
    sweep: &Sweep,
    commit: &Checksum,
    meta: bool,
    touched: &mut BTreeSet<String>,
) -> Result<()> {
    if let Some(tmp_fd) = tmp_fd {
        write_tombstone(tmp_fd, objects_fd, commit, sweep.mode, sweep.fsync)?;
    }
    let commit_path = loose_path(commit, ObjectType::Commit, sweep.mode);
    let mut unlinked = unlink_optional(objects_fd, &commit_path)?;
    if meta {
        let meta_path = loose_path(commit, ObjectType::CommitMeta, sweep.mode);
        unlinked |= unlink_optional(objects_fd, &meta_path)?;
    }
    if unlinked {
        touched.insert(objects_fanout(commit));
    }
    Ok(())
}

/// Returns the name of the `objects/` fanout directory of an object.
fn objects_fanout(checksum: &Checksum) -> String {
    checksum.to_hex()[..2].to_owned()
}

/// Calls `fsync` on each directory in `dirs`, each named relative to
/// `objects_fd`.
fn sync_dirs(objects_fd: BorrowedFd<'_>, dirs: &BTreeSet<String>) -> Result<()> {
    for dir in dirs {
        crate::refs::sync_dir(objects_fd, dir)?;
    }
    Ok(())
}

/// Returns the on-disk size of a loose object, or `None` if it is absent.
fn object_size(objects_fd: BorrowedFd<'_>, path: &str) -> Result<Option<u64>> {
    match rustix::fs::statat(objects_fd, path, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat.st_size.max(0) as u64)),
        // A concurrent removal took it, or it was never present. Nothing to
        // free.
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Stats each doomed object, unlinks it unless `no_prune` is set, and returns
/// the count and the sum of the freed bytes.
///
/// The sweep runs in two phases:
///
/// 1. The commit phase removes each doomed commit with [`remove_commit`],
///    together with its detached metadata if that is doomed too. Then it
///    removes each doomed detached metadata whose commit the phase did not
///    remove.
/// 2. The content phase removes every other doomed object, in any order.
///
/// If the run syncs, the sweep syncs the `objects/` directories that the
/// commit phase changed between the two phases. A sweep that stops at an error
/// or a crash then leaves no commit object whose tree it started to remove. If
/// the run does not sync, a crash gives no guarantee of which removals reached
/// the disk, in which order. The sweep removes no `.commitpartial` marker.
///
/// The sweep stats each doomed object before its unlink. The detached metadata
/// that the commit phase removes with its commit is the exception, and neither
/// number counts it. The sweep skips an object that is already absent at its
/// stat and counts it in neither number.
fn sweep_blocking(repo: &Repo, sweep: &Sweep, doomed: &[ObjectName]) -> Result<(usize, u64)> {
    let objects_fd = repo.objects_fd();
    let mut count = 0usize;
    let mut freed = 0u64;
    let mut tally = |ty: ObjectType, size: u64| {
        if counted(ty, sweep.commit_only) {
            count += 1;
            freed += size;
        }
    };

    // The commit phase.
    let doomed_meta: HashSet<Checksum> = doomed
        .iter()
        .filter(|o| o.ty == ObjectType::CommitMeta)
        .map(|o| o.checksum)
        .collect();
    let mut touched = BTreeSet::new();
    let mut removed_commits = HashSet::new();
    let tmp = if sweep.no_prune || !doomed.iter().any(|o| o.ty == ObjectType::Commit) {
        None
    } else {
        tombstone_tmp(repo, sweep)?
    };
    for name in doomed.iter().filter(|o| o.ty == ObjectType::Commit) {
        let Some(size) = object_size(objects_fd, &name.loose_path(sweep.mode))? else {
            continue;
        };
        if !sweep.no_prune {
            let meta = doomed_meta.contains(&name.checksum);
            remove_commit(
                tmp.as_ref().map(AsFd::as_fd),
                objects_fd,
                sweep,
                &name.checksum,
                meta,
                &mut touched,
            )?;
        }
        removed_commits.insert(name.checksum);
        tally(name.ty, size);
    }
    // Detached metadata whose commit is absent, which no commit removal took
    // with it.
    for name in doomed
        .iter()
        .filter(|o| o.ty == ObjectType::CommitMeta && !removed_commits.contains(&o.checksum))
    {
        let path = name.loose_path(sweep.mode);
        let Some(size) = object_size(objects_fd, &path)? else {
            continue;
        };
        if !sweep.no_prune && unlink_optional(objects_fd, &path)? {
            touched.insert(objects_fanout(&name.checksum));
        }
        tally(name.ty, size);
    }

    // The barrier: the commit removals are durable before any content goes.
    if sweep.fsync && !sweep.no_prune {
        sync_dirs(objects_fd, &touched)?;
    }

    // The content phase.
    for name in doomed
        .iter()
        .filter(|o| !matches!(o.ty, ObjectType::Commit | ObjectType::CommitMeta))
    {
        let path = name.loose_path(sweep.mode);
        let Some(size) = object_size(objects_fd, &path)? else {
            continue;
        };
        if !sweep.no_prune {
            unlink_optional(objects_fd, &path)?;
        }
        tally(name.ty, size);
    }
    Ok((count, freed))
}

/// Unlinks a path relative to `dir`. An absent file counts as success.
///
/// Returns `true` if the call unlinked an entry.
fn unlink_optional(dir: BorrowedFd<'_>, path: &str) -> Result<bool> {
    match rustix::fs::unlinkat(dir, path, AtFlags::empty()) {
        Ok(()) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(e) => Err(Error::Io(e.into())),
    }
}
