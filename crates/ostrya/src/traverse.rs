//! Reachability traversal and loose-object enumeration.
//!
//! [`Repo::list_objects`] enumerates every loose object present under
//! `objects/`. [`Repo::traverse_commit`] and [`Repo::traverse_reachable`] walk
//! the Merkle DAG from one or more commits, collecting the [`ObjectName`] of
//! every object reachable from them: the commit object, its root dirmeta, and
//! recursively each dirtree, subdirectory dirmeta, and file object, following
//! parent commits up to a caller-supplied depth. These are the primitives prune
//! and fsck build on.
//!
//! Depth follows the tool's observed semantics (recovered by running
//! `ostree prune --refs-only --depth=N`): `depth` is the number of parent
//! commits to follow. `depth = 0` keeps only the named commit; `depth = 1`
//! keeps it and its immediate parent; `depth = -1` follows the whole ancestry.
//! `-1` is the one negative value that follows the whole ancestry: every other
//! negative depth keeps the named commit alone, which `ostree prune
//! --refs-only --depth=-2` and `--depth=-3` show.
//!
//! A walk bounds the `parent` chain by depth or by time. [`ParentBound::Since`]
//! follows the chain while each parent commit's own timestamp is at or after a
//! chosen second count, which is what `ostree prune --keep-younger-than=DATE`
//! does. A commit a root names is kept whatever its timestamp; the bound acts
//! on the `parent` edge alone.
//!
//! Traversal is lenient about objects that are referenced but absent: a missing
//! object's name is still collected (it is a reachable reference), but a missing
//! or unparseable commit or dirtree cannot be descended into, so its children
//! are not enumerated. [`traverse_commit`](Repo::traverse_commit) is the one
//! exception: the commit the caller names must exist, else
//! [`Error::ObjectNotFound`] is returned.
//!
//! A walk follows two further edges under `GcRoots`, which
//! [`PruneOptions`](crate::PruneOptions) exposes. The commit `parent` edge is
//! optional, and any number of metadata keys name further commits: the value of
//! each configured key, in a commit's own metadata and in its detached
//! metadata, is an `aay` whose elements are commit checksums. Each such commit
//! is walked in turn, so a metadata-key edge reaches everything the commit it
//! names reaches. A commit arrived at this way is a root in its own right and
//! is given the walk's full depth, since depth counts parent hops.

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd, BorrowedFd};

use ostrya_core::{Checksum, Commit, ObjectName, ObjectType, Value};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::refs::walk_ref_dir;
use crate::repo::Repo;

/// The GVariant type a garbage-collection root metadata key holds: an array of
/// commit checksums in their 32-byte binary form.
const GC_ROOT_SIGNATURE: &str = "aay";

/// The bound a walk puts on one root's `parent` chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParentBound {
    /// Follow this many more `parent` hops. `-1` is the whole ancestry and is
    /// the one negative value the bound carries.
    Depth(i32),
    /// Follow the `parent` chain while each parent commit's own timestamp is at
    /// or after this count of seconds since the Unix epoch.
    Since(u64),
}

impl ParentBound {
    /// The depth bound `depth` names: `-1` is the whole ancestry, and every
    /// other negative value is the named commit alone.
    pub(crate) fn depth(depth: i32) -> ParentBound {
        ParentBound::Depth(if depth == -1 { -1 } else { depth.max(0) })
    }
}

/// The bounds one commit takes from the weak refs that name it.
///
/// At most one bound of each kind is held: the depth bound that follows the
/// furthest and the earliest timestamp bound. A further bound of the same kind
/// is dropped where a held bound already reaches at least as far, because
/// [`Expanded::covers`] skips the expansion that bound asks for. The two kinds
/// are held apart, because `covers` compares a depth with a depth and a
/// timestamp with a timestamp.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WeakBounds {
    /// The furthest reaching depth bound, `-1` for the whole ancestry.
    depth: Option<i32>,
    /// The earliest timestamp bound.
    since: Option<u64>,
}

impl WeakBounds {
    /// Fold one more bound in.
    pub(crate) fn add(&mut self, bound: ParentBound) {
        match bound {
            ParentBound::Depth(depth) => {
                if !self.depth.is_some_and(|prev| reaches_at_least(prev, depth)) {
                    self.depth = Some(depth);
                }
            }
            ParentBound::Since(since) => {
                if self.since.is_none_or(|prev| prev > since) {
                    self.since = Some(since);
                }
            }
        }
    }

    /// The bounds to seed, at most one of each kind.
    fn seeds(self) -> impl Iterator<Item = ParentBound> {
        self.depth
            .map(ParentBound::Depth)
            .into_iter()
            .chain(self.since.map(ParentBound::Since))
    }
}

/// The directory of `refs/` one ref lives under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefSpace {
    /// A local ref, below `refs/heads`.
    Heads,
    /// A remote ref, below `refs/remotes`.
    Remotes,
    /// A mirror ref, below `refs/mirrors`.
    Mirrors,
}

/// One ref a listing found, as [`Repo::list_all_refs`] reports it.
#[derive(Debug)]
pub(crate) struct ListedRef {
    /// The directory of `refs/` the ref file lives under.
    pub(crate) space: RefSpace,
    /// The name the listing gave the ref.
    pub(crate) name: String,
    /// Whether that name addresses the file it was listed from, by
    /// [`crate::refs::listed_name_addresses_it`].
    pub(crate) addressable: bool,
    /// The commit the ref resolves to.
    pub(crate) checksum: Checksum,
}

/// How the walk arrived at a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arrival {
    /// The commit is a root: a caller-supplied seed or a commit a metadata-key
    /// edge names. The bound the arrival carries is the commit's own.
    Root,
    /// The commit was reached over a depth-bounded `parent` edge, so the bound
    /// it carries is the one the child had left.
    Parent,
    /// The commit was reached over a [`ParentBound::Since`] `parent` edge, so
    /// it is kept only while its own timestamp is at or after the bound.
    TimedParent,
}

impl Arrival {
    /// Whether the bound the arrival carries came down a `parent` edge.
    fn inherited(self) -> bool {
        self != Arrival::Root
    }
}

/// What the expansions of one commit have reached so far.
///
/// A commit is expanded again only under a bound that follows further than
/// every bound it was expanded under, so each expansion strictly improves one
/// of the first two fields and the walk terminates.
#[derive(Debug, Clone, Copy, Default)]
struct Expanded {
    /// The most reaching depth bound an expansion carried.
    depth: Option<i32>,
    /// The earliest timestamp bound an expansion carried.
    since: Option<u64>,
    /// The earliest timestamp bound a conditional arrival was rejected under.
    /// The commit's own timestamp is below it, so every conditional arrival at
    /// or above it is rejected too and needs no second read of the commit.
    rejected_since: Option<u64>,
}

impl Expanded {
    /// Whether an expansion already made follows at least as far as `bound`
    /// would.
    fn covers(&self, bound: ParentBound) -> bool {
        if self.depth == Some(-1) {
            return true;
        }
        match bound {
            ParentBound::Depth(depth) => {
                self.depth.is_some_and(|prev| reaches_at_least(prev, depth))
            }
            ParentBound::Since(since) => self.since.is_some_and(|prev| prev <= since),
        }
    }

    /// Whether a conditional arrival under `bound` is already known to fall
    /// below the commit's own timestamp.
    fn rejects(&self, bound: ParentBound) -> bool {
        match bound {
            ParentBound::Since(since) => self.rejected_since.is_some_and(|prev| since >= prev),
            ParentBound::Depth(_) => false,
        }
    }

    /// Record an expansion under `bound`.
    fn record(&mut self, bound: ParentBound) {
        match bound {
            ParentBound::Depth(depth) => {
                if !self.depth.is_some_and(|prev| reaches_at_least(prev, depth)) {
                    self.depth = Some(depth);
                }
            }
            ParentBound::Since(since) => {
                if self.since.is_none_or(|prev| prev > since) {
                    self.since = Some(since);
                }
            }
        }
    }

    /// Record that a conditional arrival under `since` fell below the commit's
    /// own timestamp.
    fn reject(&mut self, since: u64) {
        if self.rejected_since.is_none_or(|prev| prev > since) {
            self.rejected_since = Some(since);
        }
    }
}

/// The edges a reachability walk follows out of a commit, beyond the objects its
/// tree names.
#[derive(Debug, Clone)]
pub(crate) struct GcRoots {
    /// Metadata keys whose value names further reachable commits. Empty
    /// configures the walk to read no metadata at all.
    pub metadata_keys: Vec<String>,
    /// Whether the commit `parent` edge is followed.
    pub traverse_parent: bool,
    /// Whether the objects a commit's tree names are reachable. False collects
    /// commit names alone and reads no dirtree, which is the set
    /// `prune --commit-only` consults.
    pub traverse_tree: bool,
    /// The commits weak refs name, each with the bounds those refs' own names
    /// carry.
    ///
    /// A weak ref is no seed, so an arrival at one of these commits is replaced
    /// by a seed at the bounds recorded here. A commit several weak refs name
    /// takes the bounds [`WeakBounds`] holds: the depth bound that follows the
    /// furthest and the earliest timestamp bound.
    pub weak_roots: HashMap<Checksum, WeakBounds>,
}

impl GcRoots {
    /// The plain ostree walk: the `parent` edge, the trees, and no
    /// metadata-key edges.
    fn parents_only() -> GcRoots {
        GcRoots {
            metadata_keys: Vec::new(),
            traverse_parent: true,
            traverse_tree: true,
            weak_roots: HashMap::new(),
        }
    }
}

impl Repo {
    /// Enumerate every loose object present under `objects/`.
    ///
    /// The `objects/<xx>/` fanout directories are scanned and each
    /// `<62hex>.<ext>` entry is parsed into an [`ObjectName`]. Entries whose
    /// name is not a valid loose object (a leftover `.tmp-` temporary, say) are
    /// skipped.
    pub async fn list_objects(&self) -> Result<HashSet<ObjectName>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || list_objects_blocking(repo.objects_fd())).await
    }

    /// List the checksums of the loose objects of one type, sorted.
    ///
    /// The enumeration is the one [`list_objects`](Repo::list_objects) makes,
    /// with the type read off the entry's extension before its name is parsed,
    /// so a caller after one type pays for no other type's name.
    pub(crate) async fn list_objects_of_type(&self, ty: ObjectType) -> Result<Vec<Checksum>> {
        let repo = self.clone();
        let mut names = ostrya_rt::unblock(move || -> Result<Vec<Checksum>> {
            let mut out = Vec::new();
            for_each_object(
                repo.objects_fd(),
                |candidate| candidate == ty,
                |name| out.push(name.checksum),
            )?;
            Ok(out)
        })
        .await?;
        names.sort();
        Ok(names)
    }

    /// Count the loose objects under `objects/` whose type `keep` admits.
    ///
    /// The enumeration is the one [`list_objects`](Repo::list_objects) makes
    /// and holds no name, so a caller that needs a total alone pays for no set.
    pub(crate) async fn count_objects<F>(&self, keep: F) -> Result<usize>
    where
        F: Fn(ObjectType) -> bool + Send + 'static,
    {
        let repo = self.clone();
        ostrya_rt::unblock(move || count_objects_blocking(repo.objects_fd(), keep)).await
    }

    /// Collect every object reachable from `commit`, following parent commits up
    /// to `max_depth` (`-1` for the whole ancestry). The named commit must
    /// exist; a parent that is absent stops that chain without error.
    pub async fn traverse_commit(
        &self,
        commit: &Checksum,
        max_depth: i32,
    ) -> Result<HashSet<ObjectName>> {
        if !self.has_object(ObjectType::Commit, commit).await? {
            return Err(Error::ObjectNotFound {
                checksum: *commit,
                ty: ObjectType::Commit,
            });
        }
        let bound = ParentBound::depth(max_depth);
        let mut reachable = HashSet::new();
        self.collect_reachable(
            vec![(*commit, bound, Arrival::Root)],
            bound,
            &GcRoots::parents_only(),
            &HashSet::new(),
            None,
            &mut reachable,
        )
        .await?;
        Ok(reachable)
    }

    /// Collect every object reachable from any of `roots`, each followed to
    /// `max_depth` parents. Roots that are absent are skipped, so a dangling ref
    /// does not fail the walk.
    pub async fn traverse_reachable(
        &self,
        roots: impl IntoIterator<Item = Checksum>,
        max_depth: i32,
    ) -> Result<HashSet<ObjectName>> {
        let bound = ParentBound::depth(max_depth);
        self.traverse_reachable_gc(
            roots.into_iter().map(|c| (c, bound)),
            bound,
            &GcRoots::parents_only(),
            &HashSet::new(),
            None,
        )
        .await
    }

    /// Collect every object reachable from any of `roots` under the edges `gc`
    /// names. This is [`traverse_reachable`](Repo::traverse_reachable) with the
    /// `parent` edge made optional and the metadata-key edges added.
    ///
    /// Each root carries its own bound, so one walk holds a branch cut to a
    /// depth beside a branch kept in full. `root_bound` is the bound every
    /// commit a metadata-key edge names is seeded at.
    ///
    /// `bounded_roots` names the commits whose bound is a property of the
    /// commit and not of the path that reached it: the walk drops every
    /// `parent`-edge arrival at one of them and leaves the expansion to the
    /// seed, so the bound the arrival inherited is replaced rather than
    /// narrowed. Every checksum in it must also be a seed in `roots`.
    ///
    /// `pending_delete` names a commit the walk reads as absent. Prune unlinks
    /// the commit it deletes only once the walk has succeeded, and this keeps
    /// the walk's result the same as one run against the store the unlink
    /// leaves: the commit's own name is reachable, and nothing under it is.
    pub(crate) async fn traverse_reachable_gc(
        &self,
        roots: impl IntoIterator<Item = (Checksum, ParentBound)>,
        root_bound: ParentBound,
        gc: &GcRoots,
        bounded_roots: &HashSet<Checksum>,
        pending_delete: Option<Checksum>,
    ) -> Result<HashSet<ObjectName>> {
        let seeds = roots
            .into_iter()
            .map(|(c, bound)| (c, bound, Arrival::Root))
            .collect();
        let mut reachable = HashSet::new();
        self.collect_reachable(
            seeds,
            root_bound,
            gc,
            bounded_roots,
            pending_delete,
            &mut reachable,
        )
        .await?;
        Ok(reachable)
    }

    /// The shared reachability walk. `seeds` pairs each root commit with the
    /// bound its `parent` chain follows and with the kind of arrival it is.
    /// Names are added for every referenced object; recursion into a commit or
    /// dirtree needs the object to load, so an absent or corrupt one
    /// contributes its own name but none beneath it.
    ///
    /// A commit reached from more than one root is expanded under the furthest
    /// reaching bound any root gives it, so the reachable set does not depend on
    /// the order roots are supplied in: a commit already expanded under a bound
    /// that follows at least as far is skipped, otherwise it is expanded again
    /// to push its parent further back.
    ///
    /// A commit `bounded_roots` names carries its own bound. Every
    /// `parent`-edge arrival at one is dropped, so the seed's bound stands in
    /// place of the bound the arrival inherited.
    ///
    /// A commit `gc.weak_roots` names carries its own bounds as well, and
    /// enters the walk through no seed of the caller's. The first arrival at
    /// one pushes a seed for each bound the map records, at most one of each
    /// kind. A `parent`-edge arrival
    /// is then dropped the way a `bounded_roots` arrival is, so the pushed
    /// seeds stand in place of the bound the arrival inherited. An arrival that
    /// is a root in its own right stands, and the commit expands under the
    /// arrival's bound and under the pushed seeds alike. The pushed seeds go
    /// through the same memoization as every other entry: a commit already
    /// expanded under a bound that reaches at least as far is skipped, and one
    /// reached under a longer bound is expanded again. A commit takes its weak
    /// seeds once, and each extra entry is either skipped or strictly improves
    /// the recorded depth or timestamp, so the walk terminates.
    ///
    /// A conditional arrival is one a [`ParentBound::Since`] parent edge made.
    /// It contributes nothing at all where the commit's own timestamp is below
    /// the bound, and no expansion is recorded for it, so a root naming that
    /// same commit still keeps it. The rejection itself is memoized, so a
    /// second child arriving under the same bound reads no commit.
    ///
    /// `root_bound` is the bound every commit a metadata-key edge names is
    /// seeded at. `pending_delete` names a commit that is read as absent.
    async fn collect_reachable(
        &self,
        seeds: Vec<(Checksum, ParentBound, Arrival)>,
        root_bound: ParentBound,
        gc: &GcRoots,
        bounded_roots: &HashSet<Checksum>,
        pending_delete: Option<Checksum>,
        reachable: &mut HashSet<ObjectName>,
    ) -> Result<()> {
        let mut commit_stack = seeds;
        let mut seen_commits: HashMap<Checksum, Expanded> = HashMap::new();
        let mut seen_dirtrees: HashSet<Checksum> = HashSet::new();
        // The commits a weak-ref seed was pushed for. A pushed seed matches
        // `weak_roots` again on its own pop, so the set is what stops the walk
        // from pushing it a second time.
        let mut weak_seeded: HashSet<Checksum> = HashSet::new();

        while let Some((commit_checksum, bound, arrival)) = commit_stack.pop() {
            // A weak ref's commit takes the bound that ref's own name carries,
            // the moment the walk reaches it over any edge. The seed is a
            // `Root` arrival, so the bound is the commit's own and the commit
            // is kept whatever its timestamp under a `Since` bound, which is
            // what a strong ref's target already gets.
            //
            // The test stands ahead of the `inherited` drop below and covers
            // every arrival kind. A metadata-key edge pushes a `Root` arrival
            // at the run's global bound, so a rule keyed on `inherited` alone
            // would let that arrival expand the commit at the global bound
            // while the weak ref's own bound reaches further, and the sweep
            // would then take the ancestry of a ref that still stands.
            if let Some(bounds) = gc.weak_roots.get(&commit_checksum)
                && weak_seeded.insert(commit_checksum)
            {
                for weak_bound in bounds.seeds() {
                    commit_stack.push((commit_checksum, weak_bound, Arrival::Root));
                }
            }

            // A commit that carries its own bound takes it whatever the
            // `parent` edge that reached it had left. The seed holds that
            // bound, so the arrival is dropped here and the seed's expansion
            // stands for it. A weak ref's commit is dropped on the same terms:
            // the seed pushed above holds its bound.
            if arrival.inherited()
                && (bounded_roots.contains(&commit_checksum)
                    || gc.weak_roots.contains_key(&commit_checksum))
            {
                continue;
            }

            let seen = seen_commits
                .get(&commit_checksum)
                .copied()
                .unwrap_or_default();
            if seen.covers(bound) {
                continue;
            }
            if arrival == Arrival::TimedParent && seen.rejects(bound) {
                continue;
            }

            let loaded = if pending_delete == Some(commit_checksum) {
                None
            } else {
                self.try_load_commit(&commit_checksum).await?
            };

            // A commit the timestamp bound rules out is not kept and no
            // expansion is recorded for it, so a ref naming it still reaches
            // it. The rejection is recorded, so a second child under the same
            // bound does not read the commit again.
            if arrival == Arrival::TimedParent
                && let ParentBound::Since(since) = bound
                && let Some(commit) = &loaded
                && commit.timestamp < since
            {
                seen_commits
                    .entry(commit_checksum)
                    .or_default()
                    .reject(since);
                continue;
            }

            seen_commits
                .entry(commit_checksum)
                .or_default()
                .record(bound);
            reachable.insert(ObjectName::new(commit_checksum, ObjectType::Commit));

            let Some(commit) = loaded else {
                continue;
            };

            if gc.traverse_tree {
                reachable.insert(ObjectName::new(commit.root_dirmeta, ObjectType::DirMeta));
                self.walk_tree(commit.root_dirtree, &mut seen_dirtrees, reachable)
                    .await?;
            }

            if !gc.metadata_keys.is_empty() {
                self.push_metadata_key_edges(
                    &commit_checksum,
                    &commit.metadata,
                    gc,
                    root_bound,
                    &mut commit_stack,
                )
                .await?;
            }

            if gc.traverse_parent
                && let Some(parent) = commit.parent
            {
                match bound {
                    ParentBound::Depth(0) => {}
                    ParentBound::Depth(depth) => {
                        let next = if depth < 0 { -1 } else { depth - 1 };
                        commit_stack.push((parent, ParentBound::Depth(next), Arrival::Parent));
                    }
                    ParentBound::Since(since) => {
                        commit_stack.push((
                            parent,
                            ParentBound::Since(since),
                            Arrival::TimedParent,
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Walk a dirtree subtree, collecting the name of every dirtree, dirmeta,
    /// and file reachable from it. A dirtree that cannot be loaded contributes
    /// its own name only.
    async fn walk_tree(
        &self,
        root_dirtree: Checksum,
        seen_dirtrees: &mut HashSet<Checksum>,
        reachable: &mut HashSet<ObjectName>,
    ) -> Result<()> {
        let mut stack = vec![root_dirtree];
        while let Some(dirtree_checksum) = stack.pop() {
            if !seen_dirtrees.insert(dirtree_checksum) {
                continue;
            }
            reachable.insert(ObjectName::new(dirtree_checksum, ObjectType::DirTree));

            let Some(dirtree) = self.try_load_dirtree(&dirtree_checksum).await? else {
                continue;
            };
            for (_, file_checksum) in dirtree.files {
                reachable.insert(ObjectName::new(file_checksum, ObjectType::File));
            }
            for (_, subtree, submeta) in dirtree.dirs {
                reachable.insert(ObjectName::new(submeta, ObjectType::DirMeta));
                stack.push(subtree);
            }
        }
        Ok(())
    }

    /// Push every commit the configured metadata keys name onto the walk.
    ///
    /// Each key is read from `metadata`, the commit's own, and then from its
    /// detached metadata, so one key name carries edges from both. A key no
    /// dict holds contributes nothing. A key that is present and does not hold
    /// an `aay` of 32-byte checksums fails the walk with
    /// [`Error::InvalidGcRoot`], because a value the walk cannot read is an
    /// edge it cannot follow, and objects would be deleted for it.
    ///
    /// The detached metadata is read once per expansion of a commit, and only
    /// for a walk that has metadata keys configured. A commit reached again at
    /// a depth that follows more parents is expanded a second time and read
    /// again.
    async fn push_metadata_key_edges(
        &self,
        commit: &Checksum,
        metadata: &Value,
        gc: &GcRoots,
        root_bound: ParentBound,
        stack: &mut Vec<(Checksum, ParentBound, Arrival)>,
    ) -> Result<()> {
        let detached = self.read_commit_detached_metadata(commit).await?;
        for key in &gc.metadata_keys {
            for source in [Some(metadata), detached.as_ref()].into_iter().flatten() {
                let Some(value) = source.dict_get(key) else {
                    continue;
                };
                for target in metadata_key_targets(commit, key, value)? {
                    stack.push((target, root_bound, Arrival::Root));
                }
            }
        }
        Ok(())
    }

    /// Load and parse a commit, treating an absent object as `None` rather than
    /// an error, for the lenient traversal walk.
    async fn try_load_commit(&self, checksum: &Checksum) -> Result<Option<Commit>> {
        match self.load_object_bytes(ObjectType::Commit, checksum).await {
            Ok(bytes) => Ok(Some(Commit::parse(&bytes)?)),
            Err(Error::ObjectNotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Load and parse a dirtree, treating an absent object as `None`.
    async fn try_load_dirtree(&self, checksum: &Checksum) -> Result<Option<ostrya_core::DirTree>> {
        match self.load_dirtree(checksum).await {
            Ok(dirtree) => Ok(Some(dirtree)),
            Err(Error::ObjectNotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Collect the commit checksum every ref resolves to, across
    /// `refs/heads`, `refs/remotes`, and `refs/mirrors`. Used to seed prune and
    /// fsck with the set of refs' targets.
    pub(crate) async fn list_all_ref_targets(&self) -> Result<Vec<Checksum>> {
        Ok(self
            .list_all_refs()
            .await?
            .into_iter()
            .map(|listed| listed.checksum)
            .collect())
    }

    /// Collect every ref across `refs/heads`, `refs/remotes`, and
    /// `refs/mirrors`.
    ///
    /// A local ref is named by its path under `refs/heads`, so a nested name
    /// keeps its `/`. A remote ref is named by its `<remote>:<name>` refspec. A
    /// mirror ref is named by its path under `refs/mirrors`, which is the
    /// collection id and the ref name below it. Each ref also reports whether
    /// the name it was given addresses the file it was listed from, which is
    /// the test a caller that reads or unlinks a ref by its name needs. Prune
    /// reads the names to decide which branch a depth applies to, and reads the
    /// [`RefSpace`] and the addressability to decide which refs its classifier
    /// sees.
    pub(crate) async fn list_all_refs(&self) -> Result<Vec<ListedRef>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            let mut out = Vec::new();
            for (space, top) in [
                (RefSpace::Heads, "refs/heads"),
                (RefSpace::Remotes, "refs/remotes"),
                (RefSpace::Mirrors, "refs/mirrors"),
            ] {
                collect_named_refs(repo.repo_fd(), space, top, &mut out)?;
            }
            Ok(out)
        })
        .await
    }
}

/// Read one metadata key's value as the list of commits it names.
///
/// The value is the variant an `a{sv}` entry holds. It has to carry an `aay`
/// whose every element is a 32-byte commit checksum; anything else is an
/// [`Error::InvalidGcRoot`] naming the commit the value came from.
fn metadata_key_targets(commit: &Checksum, key: &str, value: &Value) -> Result<Vec<Checksum>> {
    let invalid = |reason: String| Error::InvalidGcRoot {
        commit: *commit,
        metadata_key: key.to_owned(),
        reason,
    };
    let Some((ty, elements)) = value.as_variant() else {
        return Err(invalid("value is not a variant".into()));
    };
    let signature = ty.signature();
    if signature != GC_ROOT_SIGNATURE {
        return Err(invalid(format!(
            "type is `{signature}`, not `{GC_ROOT_SIGNATURE}`"
        )));
    }
    let Some(elements) = elements.as_array() else {
        return Err(invalid("value is not an array".into()));
    };
    let mut targets = Vec::with_capacity(elements.len());
    for (index, element) in elements.iter().enumerate() {
        let Some(bytes) = element.as_bytes() else {
            return Err(invalid(format!("element {index} is not a byte array")));
        };
        let checksum = Checksum::from_ay(bytes)
            .map_err(|_| invalid(format!("element {index} is {} bytes, not 32", bytes.len())))?;
        targets.push(checksum);
    }
    Ok(targets)
}

/// Whether a commit already expanded at remaining depth `prev` follows at least
/// as many parents as a fresh arrival at remaining depth `depth`. A negative
/// depth is unbounded and dominates any finite depth.
pub(crate) fn reaches_at_least(prev: i32, depth: i32) -> bool {
    if prev < 0 {
        true
    } else if depth < 0 {
        false
    } else {
        prev >= depth
    }
}

/// Call `f` with the [`ObjectName`] of each loose object under an `objects/`
/// directory fd.
///
/// `keep` is read off the entry's extension, before its checksum is parsed, so
/// a caller after one type pays for no other type's hexadecimal.
///
/// The enumeration holds one directory open at a time and borrows each entry
/// name from the reader, so it allocates nothing per object.
fn for_each_object(
    objects_fd: BorrowedFd<'_>,
    keep: impl Fn(ObjectType) -> bool,
    mut f: impl FnMut(ObjectName),
) -> Result<()> {
    for_each_dir_name(objects_fd, |fanout| {
        // Object fanout directories are exactly two hex characters; anything
        // else under `objects/` (a stray file, a cache directory) is not a
        // loose-object fanout.
        if fanout.len() != 2 || !fanout.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(());
        }
        let dir = match rustix::fs::openat(
            objects_fd,
            fanout,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(()),
            Err(e) => return Err(Error::Io(e.into())),
        };
        for_each_dir_name(dir.as_fd(), |entry| {
            if let Some(name) = parse_object_entry(fanout, entry, &keep) {
                f(name);
            }
            Ok(())
        })
    })
}

/// Enumerate loose objects under an `objects/` directory fd.
fn list_objects_blocking(objects_fd: BorrowedFd<'_>) -> Result<HashSet<ObjectName>> {
    let mut out = HashSet::new();
    for_each_object(
        objects_fd,
        |_| true,
        |name| {
            out.insert(name);
        },
    )?;
    Ok(out)
}

/// Count the loose objects under an `objects/` directory fd whose type `keep`
/// admits, holding no name.
fn count_objects_blocking(
    objects_fd: BorrowedFd<'_>,
    keep: impl Fn(ObjectType) -> bool,
) -> Result<usize> {
    let mut count = 0usize;
    for_each_object(objects_fd, keep, |_| {
        count += 1;
    })?;
    Ok(count)
}

/// Parse one `objects/<fanout>/<rest>.<ext>` entry into an [`ObjectName`], or
/// `None` when the name is not a valid loose object or `keep` refuses its
/// type.
fn parse_object_entry(
    fanout: &str,
    entry: &str,
    keep: &impl Fn(ObjectType) -> bool,
) -> Option<ObjectName> {
    let (rest, ext) = entry.rsplit_once('.')?;
    if fanout.len() != 2 || rest.len() != 62 {
        return None;
    }
    let ty = ObjectType::from_extension(ext)?;
    if !keep(ty) {
        return None;
    }
    let mut hex = [0u8; 64];
    hex[..2].copy_from_slice(fanout.as_bytes());
    hex[2..].copy_from_slice(rest.as_bytes());
    let checksum = Checksum::from_hex(std::str::from_utf8(&hex).ok()?).ok()?;
    Some(ObjectName::new(checksum, ty))
}

/// Call `f` with the name of each entry of an open directory, skipping `.` and
/// `..`. The name borrows the reader's own buffer.
fn for_each_dir_name(dir: BorrowedFd<'_>, mut f: impl FnMut(&str) -> Result<()>) -> Result<()> {
    let reader = rustix::fs::Dir::read_from(dir).map_err(|e| Error::Io(e.into()))?;
    for entry in reader {
        let entry = entry.map_err(|e| Error::Io(e.into()))?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        // Object and fanout names are ASCII and a ref name is UTF-8; anything
        // else is neither a loose object nor a ref.
        if let Ok(name) = std::str::from_utf8(bytes) {
            f(name)?;
        }
    }
    Ok(())
}

/// Read the entry names of an open directory, skipping `.` and `..`.
pub(crate) fn read_dir_names(dir: BorrowedFd<'_>) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for_each_dir_name(dir, |name| {
        names.push(name.to_owned());
        Ok(())
    })?;
    Ok(names)
}

/// Recursively collect each ref file under `top`, following the `refs/`
/// subtree. Alias symlinks are followed; a dangling one is skipped. A ref under
/// `refs/remotes` takes its `<remote>:<name>` refspec, and a ref under either
/// of the other two takes its path below `top`.
fn collect_named_refs(
    repo_fd: BorrowedFd<'_>,
    space: RefSpace,
    top: &str,
    out: &mut Vec<ListedRef>,
) -> Result<()> {
    let dir = match rustix::fs::openat(
        repo_fd,
        top,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(()),
        Err(e) => return Err(Error::Io(e.into())),
    };
    walk_ref_dir(dir.as_fd(), "", &mut |entry| {
        if let Some(checksum) = read_ref_target(entry.dir, entry.name)? {
            let name = match space {
                RefSpace::Remotes => entry.path.replacen('/', ":", 1),
                RefSpace::Heads | RefSpace::Mirrors => entry.path.to_owned(),
            };
            // A mirror entry answers false by construction: no refspec maps to
            // a path below `refs/mirrors`.
            let addressable = crate::refs::listed_name_addresses_it(&name, top, entry.path);
            out.push(ListedRef {
                space,
                name,
                addressable,
                checksum,
            });
        }
        Ok(())
    })
}

/// The largest ref file the reader will load; a ref is 65 bytes.
const REF_READ_CAP: u64 = 4096;

/// Read a ref file's target checksum relative to `dir`, following alias
/// symlinks; `None` when the file is absent.
fn read_ref_target(dir: BorrowedFd<'_>, name: &str) -> Result<Option<Checksum>> {
    use std::io::Read;
    let fd = match rustix::fs::openat(dir, name, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(Error::Io(e.into())),
    };
    let mut buf = Vec::new();
    std::fs::File::from(fd)
        .take(REF_READ_CAP)
        .read_to_end(&mut buf)
        .map_err(Error::Io)?;
    let text = std::str::from_utf8(&buf)
        .map_err(|_| Error::InvalidFormat("ref content is not valid UTF-8".into()))?;
    Ok(Some(Checksum::from_hex(text.trim())?))
}
