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
//! - A run holds the repository lock exclusive from end to end, a
//!   [`no_prune`](PruneOptions::no_prune) dry run and a
//!   [`static_deltas_only`](PruneOptions::static_deltas_only) run included. It
//!   reads `[core] locking` and `[core] lock-timeout-secs`, and it fails with
//!   [`Error::LockTimeout`] where another holder keeps the lock past the
//!   timeout. The hold excludes every other writer, in this process and in
//!   another: a caller that holds a transaction of its own open across the call
//!   waits out the timeout and then fails, and a transaction the process opens
//!   while the run stands waits for the run to finish.
//!
//! A third option carries a behavior the tool has no counterpart for:
//! [`weak_ref_filter`](PruneOptions::weak_ref_filter) classifies each ref under
//! `refs/heads` as strong or weak. A strong ref roots the walk as every ref
//! does. A weak ref roots nothing: it survives where the walk reaches its
//! commit over some other edge, and the run unlinks it otherwise and names it
//! in [`PruneStats::deleted_refs`]. Where the walk arrives at a weak ref's
//! commit over a `parent` edge, that commit takes the bound the weak ref's own
//! name carries in place of the bound the edge had left, which is the rule a
//! strong ref's target already gets. An arrival over any other edge carries a
//! bound of its own, and the commit expands under that bound and under the weak
//! ref's bound alike. A set filter requires
//! [`refs_only`](PruneOptions::refs_only).
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

use std::collections::{HashMap, HashSet};
use std::os::fd::BorrowedFd;
use std::sync::Arc;

use ostrya_core::{Checksum, ObjectName, ObjectType, RepoMode, loose_path};
use rustix::fs::AtFlags;
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::lock::LockKind;
use crate::repo::Repo;
use crate::tombstone::write_tombstone;
use crate::traverse::{ParentBound, RefSpace, WeakBounds};

/// A verdict on one ref, taken as a prune classifies the ref space.
///
/// The arguments are the ref's name and the commit it resolves to. True
/// classifies the ref strong, so it roots the walk under the bound its name
/// carries. False classifies it weak, so it is no root: a weak ref survives
/// where the walk reaches its commit over some other edge, and the run deletes
/// it otherwise.
pub type WeakRefFilterFn = Arc<dyn Fn(&str, &Checksum) -> bool + Send + Sync>;

/// The ref classifier a prune applies, unset by default.
///
/// An unset filter classifies every ref strong, so a prune that leaves it unset
/// deletes no ref.
///
/// The callback runs on the executor thread while the run holds the repository
/// lock exclusive, so it must call no [`Repo`] method. [`Repo::transaction`]
/// from inside it waits out `[core] lock-timeout-secs` and then fails, and
/// `ostrya_rt::block_on` inside it re-enters the runtime. The callback must be
/// pure over its two arguments and over the state the caller captured before
/// the call.
///
/// A classifier that repoints a ref as a side effect of its own call is the
/// caller's own hazard. The compare-and-delete guard keeps the run from
/// unlinking a ref that moved, and the run walks once, so the objects under the
/// commit the ref now names can still go.
///
/// The callback is shared rather than exclusive, so a caller holds one
/// classifier across several [`PruneOptions`]. A classifier that accumulates
/// state carries its own interior mutability.
#[derive(Clone, Default)]
pub struct WeakRefFilter(Option<WeakRefFilterFn>);

impl WeakRefFilter {
    /// A filter that calls `f` for every ref it classifies.
    pub fn new<F>(f: F) -> WeakRefFilter
    where
        F: Fn(&str, &Checksum) -> bool + Send + Sync + 'static,
    {
        WeakRefFilter(Some(Arc::new(f)))
    }

    /// A filter over a callback the caller already holds, for a callback shared
    /// with another [`PruneOptions`].
    pub fn from_fn(f: WeakRefFilterFn) -> WeakRefFilter {
        WeakRefFilter(Some(f))
    }

    /// Whether a callback stands.
    pub(crate) fn is_set(&self) -> bool {
        self.0.is_some()
    }

    /// Whether the ref is strong. An unset filter answers true for every ref.
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
    /// global value. A ref's own target is kept whatever its timestamp. A ref
    /// [`weak_ref_filter`](PruneOptions::weak_ref_filter) calls weak is outside
    /// that, because it roots the walk under no bound.
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
    ///
    /// A ref [`weak_ref_filter`](PruneOptions::weak_ref_filter) calls weak is
    /// outside the retention this states, because it roots the walk under no
    /// bound.
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
    /// The classifier that splits the ref space into strong refs and weak refs.
    ///
    /// Unset by default, which classifies every ref strong and deletes no ref.
    /// A set filter requires [`refs_only`](PruneOptions::refs_only); the two
    /// apart fail the prune with [`Error::InvalidFormat`] before the run reads
    /// anything.
    ///
    /// The filter sees each ref under `refs/heads` by its path below that
    /// directory. A ref under `refs/remotes` and a ref under `refs/mirrors` is
    /// strong and never reaches the filter. A name below `refs/heads` holding a
    /// `:` maps to a path under `refs/remotes` through the refspec rule, so it
    /// is strong as well and the filter never learns it exists.
    ///
    /// A strong ref roots the walk under the bound
    /// [`retain_branch_depth`](PruneOptions::retain_branch_depth),
    /// [`only_branch`](PruneOptions::only_branch), and
    /// [`depth`](PruneOptions::depth) give its name. A weak ref roots nothing.
    /// It survives where the walk reaches its commit over some other edge. An
    /// arrival over a `parent` edge gives the commit the bound that weak ref's
    /// own name carries in place of the bound the edge had left; an arrival
    /// over any other edge carries a bound of its own, and the commit expands
    /// under that bound and under the weak ref's bound alike. The run deletes
    /// each weak ref the walk did not reach and names it in
    /// [`PruneStats::deleted_refs`].
    ///
    /// A weak ref roots nothing, so the branch selection has nothing to select
    /// for it: a weak ref outside an
    /// [`only_branch`](PruneOptions::only_branch) selection is classified all
    /// the same, and the run deletes it and sweeps its objects where the walk
    /// does not reach its commit.
    /// [`keep_younger_than`](PruneOptions::keep_younger_than) holds its
    /// guarantee for a strong ref's own target: the run deletes a weak ref the
    /// walk does not reach whatever the timestamp of the commit it names.
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The weak refs the run deleted, sorted by name in byte order.
    ///
    /// Under [`no_prune`](PruneOptions::no_prune) it names the refs the run
    /// would have deleted, and the run removes no ref. A ref the
    /// compare-and-delete guard skipped is in neither, because the run left it
    /// where it stood.
    ///
    /// A [`static_deltas_only`](PruneOptions::static_deltas_only) run returns
    /// before it reads the ref space, so it classifies no ref and the list is
    /// empty whatever
    /// [`weak_ref_filter`](PruneOptions::weak_ref_filter) holds.
    ///
    /// Where the run fails part way through the deletions, the refs it already
    /// removed stay removed, and this list goes with the error the caller gets
    /// in place of the statistics.
    pub deleted_refs: Vec<String>,
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
    ///
    /// The run holds the repository lock exclusive from end to end, a
    /// [`no_prune`](PruneOptions::no_prune) dry run and a
    /// [`static_deltas_only`](PruneOptions::static_deltas_only) run included.
    /// It reads `[core] locking` and `[core] lock-timeout-secs`, and it fails
    /// with [`Error::LockTimeout`] where another holder keeps the lock past the
    /// timeout. The hold excludes every other writer, in this process and in
    /// another: a caller that holds a transaction of its own open across the
    /// call waits out the timeout and then fails, and a transaction the process
    /// opens while the run stands waits for the run to finish.
    pub async fn prune(&self, opts: &PruneOptions) -> Result<PruneStats> {
        let mode = self.mode();

        // The delta-only run needs the commit it keys on. The pair is refused
        // ahead of the lock, so a contended repository gives the same refusal
        // as a free one.
        if opts.static_deltas_only && opts.delete_commit.is_none() {
            return Err(Error::InvalidFormat(
                "static_deltas_only requires delete_commit".into(),
            ));
        }

        // The classifier decides which refs the run deletes, and a run that
        // roots every commit in the store deletes none of them. The pair is
        // refused ahead of the lock, so a contended repository gives the same
        // refusal as a free one, and ahead of every read, so the classifier is
        // never called.
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
                // A delta-only run reads no ref, so it deletes none.
                deleted_refs: Vec::new(),
            });
        }
        self.prune_objects(opts, mode).await
    }

    /// The object sweep: the walk, the deletions, and the static deltas the
    /// deletions stranded.
    async fn prune_objects(&self, opts: &PruneOptions, mode: RepoMode) -> Result<PruneStats> {
        // A commit a ref points at is not deletable. Refuse it here, so a prune
        // that cannot succeed fails before the traversal. The unlink checks
        // again, because a writer that takes no repository lock can publish a
        // ref naming the commit while the walk runs.
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
        // Classify the ref space in one pass, so the strong roots and the weak
        // targets cannot disagree. A ref is weak where it lives below
        // `refs/heads`, the classifier answers false for it, and its name
        // round-trips through the refspec mapping. Every other ref is strong.
        //
        // A weak target stays out of `ref_targets`: the walk needs a seed for
        // every checksum that set names, and a weak ref supplies none. The weak
        // targets ride on `GcRoots::weak_roots` instead, where the walk seeds
        // one on the arrival that reaches it.
        //
        // A commit a strong ref and a weak ref both name enters through the
        // strong ref, so the commit is reachable and the weak ref survives.
        //
        // An unset classifier makes every ref strong, so the unset case tests
        // one boolean for each ref.
        let filtering = opts.weak_ref_filter.is_set();
        let mut roots: Vec<(Checksum, ParentBound)> = Vec::new();
        let mut ref_targets: HashSet<Checksum> = HashSet::new();
        let mut weak_refs: Vec<(String, Checksum)> = Vec::new();
        let mut weak_roots: HashMap<Checksum, WeakBounds> = HashMap::new();
        for (space, name, checksum) in named_refs {
            let bound = opts.ref_bound(&name);
            let weak = filtering
                && space == RefSpace::Heads
                && crate::refs::heads_name_round_trips(&name)
                && !opts.weak_ref_filter.is_strong(&name, &checksum);
            if weak {
                weak_roots.entry(checksum).or_default().add(bound);
                weak_refs.push((name, checksum));
                continue;
            }
            // A ref's bound belongs to the commit it names, not to the path the
            // walk took to reach it, so the walk replaces an inherited bound at
            // every ref target it arrives at. Where two refs name one commit,
            // both roots stand and the commit is expanded under each of the two
            // bounds.
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
            // A `commit_only` run consults the reachable set for commit names
            // alone, so the trees are neither read nor collected.
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

        // Delete each weak ref the walk did not reach. This runs after the
        // walk, because a walk that fails must leave the repository as it
        // stood, and before the commit deletion and the sweep:
        // `refuse_referenced_commit` ran over the whole ref listing and would
        // have refused a `delete_commit` any weak ref names, so the two cannot
        // meet.
        //
        // The pass unlinks ref files alone and takes no lock of its own, so it
        // cannot deadlock against the hold the run keeps. An emptied parent
        // directory below `refs/heads` stays where it is, because an rmdir walk
        // races a writer creating a sibling ref.
        //
        // The whole pass runs in one blocking hop, the way the object sweep
        // does. Each name is read immediately ahead of its own unlink, and the
        // directories that held a removed ref are `fsync`-ed once at the end.
        let mut doomed_refs: Vec<(String, Checksum)> = Vec::with_capacity(weak_refs.len());
        for (name, target) in weak_refs {
            if !keep.contains(&ObjectName::new(target, ObjectType::Commit)) {
                doomed_refs.push((name, target));
            }
        }
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
            deleted_refs,
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
