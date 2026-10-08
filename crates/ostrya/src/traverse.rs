//! Walks of the objects that commits reach, and listings of loose objects.
//!
//! - [`Repo::list_objects`] lists each loose object in `objects/`.
//! - [`Repo::traverse_commit`] walks the objects that one commit and its
//!   parents reach.
//! - [`Repo::traverse_reachable`] walks the objects that a set of commits and
//!   their parents reach.
//!
//! [`Repo::prune`](crate::Repo::prune) and [`Repo::fsck`](crate::Repo::fsck)
//! use these listings and walks.

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd, BorrowedFd};

use ostrya_core::{Checksum, Commit, ObjectName, ObjectType, Value};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::refs::walk_ref_dir;
use crate::repo::Repo;

/// The GVariant type of the value of a GC-root metadata key.
///
/// The value is an array of commit checksums, each in its 32-byte binary form.
const GC_ROOT_SIGNATURE: &str = "aay";

/// The bound that a walk puts on the `parent` chain of one root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParentBound {
    /// The number of `parent` hops that the walk can still follow.
    ///
    /// `-1` is the whole ancestry. It is the one negative value that the bound
    /// holds.
    Depth(i32),
    /// A time in seconds since the Unix epoch.
    ///
    /// The walk follows the `parent` chain while the timestamp of each parent
    /// commit is at or after this time. This is the bound of
    /// `ostree prune --keep-younger-than=DATE`. A commit that a root names is
    /// kept whatever its timestamp, because the bound acts on the `parent` edge
    /// alone.
    Since(u64),
}

impl ParentBound {
    /// Returns the depth bound for `depth`.
    ///
    /// `-1` is the whole ancestry. Each other negative value is the named
    /// commit alone.
    pub(crate) fn depth(depth: i32) -> ParentBound {
        ParentBound::Depth(if depth == -1 { -1 } else { depth.max(0) })
    }
}

/// The bounds that one commit takes from the weak refs that name it.
///
/// The struct holds at most one bound of each kind: the depth bound that
/// reaches furthest, and the earliest timestamp bound. If a held bound reaches
/// at least as far as a new bound of the same kind, the new bound is dropped.
/// [`Expanded::covers`] skips the expansion of that new bound in any case.
///
/// The two kinds are held apart, because `covers` compares a depth with a
/// depth and a timestamp with a timestamp.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WeakBounds {
    /// The depth bound that reaches furthest, `-1` for the whole ancestry.
    depth: Option<i32>,
    /// The earliest timestamp bound.
    since: Option<u64>,
}

impl WeakBounds {
    /// Adds one more bound.
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

    /// Returns the bounds to seed, at most one of each kind.
    fn seeds(self) -> impl Iterator<Item = ParentBound> {
        self.depth
            .map(ParentBound::Depth)
            .into_iter()
            .chain(self.since.map(ParentBound::Since))
    }
}

/// The directory under `refs/` that holds one ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefSpace {
    /// A local ref, under `refs/heads`.
    Heads,
    /// A remote ref, under `refs/remotes`.
    Remotes,
    /// A mirror ref, under `refs/mirrors`.
    Mirrors,
}

/// One ref that [`Repo::list_all_refs`] found.
#[derive(Debug)]
pub(crate) struct ListedRef {
    /// The directory under `refs/` that holds the ref file.
    pub(crate) space: RefSpace,
    /// The name that the listing gave the ref.
    pub(crate) name: String,
    /// `true` if that name addresses the file that the listing read, by the
    /// rule of [`listed_name_addresses_it`](crate::refs::listed_name_addresses_it).
    pub(crate) addressable: bool,
    /// The commit that the ref resolves to.
    pub(crate) checksum: Checksum,
}

/// The kind of edge over which the walk arrived at a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arrival {
    /// An arrival at a root: a seed of the caller, or a commit that a
    /// metadata-key edge names. The bound of the arrival is the bound of the
    /// commit itself.
    Root,
    /// An arrival over a `parent` edge with a depth bound. The bound of the
    /// arrival is the bound that the child had left.
    Parent,
    /// An arrival over a `parent` edge with a [`ParentBound::Since`] bound. The
    /// walk keeps the commit only while its timestamp is at or after the bound.
    TimedParent,
}

impl Arrival {
    /// Returns `true` if the bound of the arrival came over a `parent` edge.
    fn inherited(self) -> bool {
        self != Arrival::Root
    }
}

/// The furthest bounds under which the walk expanded one commit.
///
/// The walk expands a commit again only under a bound that reaches further
/// than each earlier bound of that commit. So each expansion strictly extends
/// `depth` or `since`, and the walk ends.
#[derive(Debug, Clone, Copy, Default)]
struct Expanded {
    /// The depth bound of an expansion that reaches furthest.
    depth: Option<i32>,
    /// The earliest timestamp bound of an expansion.
    since: Option<u64>,
    /// The earliest timestamp bound under which the walk rejected a
    /// conditional arrival.
    ///
    /// The timestamp of the commit is below this bound. So the walk also
    /// rejects each conditional arrival at or after this bound, and reads the
    /// commit no second time.
    rejected_since: Option<u64>,
}

impl Expanded {
    /// Returns `true` if an earlier expansion reaches at least as far as
    /// `bound`.
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

    /// Returns `true` if the walk already knows that the timestamp of the
    /// commit is below `bound`, the bound of a conditional arrival.
    fn rejects(&self, bound: ParentBound) -> bool {
        match bound {
            ParentBound::Since(since) => self.rejected_since.is_some_and(|prev| since >= prev),
            ParentBound::Depth(_) => false,
        }
    }

    /// Records an expansion under `bound`.
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

    /// Records that the timestamp of the commit is below `since`, the bound of
    /// a conditional arrival.
    fn reject(&mut self, since: u64) {
        if self.rejected_since.is_none_or(|prev| prev > since) {
            self.rejected_since = Some(since);
        }
    }
}

/// The edges that a walk follows out of a commit, in addition to the objects
/// of its tree.
#[derive(Debug, Clone)]
pub(crate) struct GcRoots {
    /// The metadata keys whose values name more reachable commits.
    ///
    /// If the list is empty, the walk reads no metadata.
    pub metadata_keys: Vec<String>,
    /// `true` if the walk follows the `parent` edge of a commit.
    pub traverse_parent: bool,
    /// `true` if the objects of the tree of a commit are reachable.
    ///
    /// If `false`, the walk collects commit names alone and reads no dirtree.
    /// `prune --commit-only` sets it to `false`.
    pub traverse_tree: bool,
    /// The commits that weak refs name, each with the bounds of the names of
    /// those refs.
    ///
    /// A weak ref is no seed. So the walk replaces an arrival at one of these
    /// commits with a seed at the bounds recorded here. If several weak refs
    /// name one commit, the commit takes the bounds that [`WeakBounds`] holds.
    /// These are the depth bound that reaches furthest and the earliest
    /// timestamp bound.
    pub weak_roots: HashMap<Checksum, WeakBounds>,
}

impl GcRoots {
    /// Returns the edges of the walk of the `ostree` command: the `parent`
    /// edge, the trees, and no metadata-key edges.
    fn parents_only() -> GcRoots {
        GcRoots {
            metadata_keys: Vec::new(),
            traverse_parent: true,
            traverse_tree: true,
            weak_roots: HashMap::new(),
        }
    }
}

/// Methods that list objects and walk the objects that commits reach.
impl Repo {
    /// Returns the name of each loose object in `objects/`.
    ///
    /// The method reads each `objects/<xx>/` fanout directory and parses each
    /// `<62hex>.<ext>` entry into an [`ObjectName`]. It skips an entry whose
    /// name is not a loose object name, for example a leftover `.tmp-` file.
    /// It also skips each entry of `objects/` that is not two hexadecimal
    /// characters, and each name that is not UTF-8.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the read of `objects/` or of a fanout directory
    ///   fails. A fanout directory that is removed during the listing is
    ///   skipped.
    pub async fn list_objects(&self) -> Result<HashSet<ObjectName>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || list_objects_blocking(repo.objects_fd())).await
    }

    /// Returns the checksums of the loose objects of one type, in sorted order.
    ///
    /// The listing is the listing of [`list_objects`](Repo::list_objects). It
    /// reads the type from the extension of an entry before it parses the
    /// name. So the method parses no name of another type.
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

    /// Returns the number of loose objects in `objects/` whose type `keep`
    /// accepts.
    ///
    /// The listing is the listing of [`list_objects`](Repo::list_objects). It
    /// keeps no name, so a caller that needs only the total builds no set.
    pub(crate) async fn count_objects<F>(&self, keep: F) -> Result<usize>
    where
        F: Fn(ObjectType) -> bool + Send + 'static,
    {
        let repo = self.clone();
        ostrya_rt::unblock(move || count_objects_blocking(repo.objects_fd(), keep)).await
    }

    /// Returns the name of each object that `commit` and its parents reach.
    ///
    /// The set holds the commit, its root dirmeta, and each dirtree, dirmeta,
    /// and file object of its tree. It holds the same objects for each parent
    /// commit that the walk follows. The repository must hold `commit`.
    ///
    /// If a parent commit is absent, the set holds its name, and the walk of
    /// that chain stops without an error. Other absent objects follow the rules
    /// of [`traverse_reachable`](Repo::traverse_reachable).
    ///
    /// # Depth
    ///
    /// `max_depth` is the number of parent commits that the walk follows:
    ///
    /// - `0`: the named commit alone.
    /// - `1`: the named commit and its parent.
    /// - `N`: the named commit and `N` parents.
    /// - `-1`: the whole ancestry.
    /// - Each other negative value: the named commit alone.
    ///
    /// The `ostree` command uses the same depths, as
    /// `ostree prune --refs-only --depth=N` shows. `--depth=-2` and
    /// `--depth=-3` keep the named commit alone.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the repository does not hold `commit`.
    /// - [`Error::Core`] if a commit or a dirtree that the walk reads does not
    ///   parse.
    /// - [`Error::Io`] if a read of the object store fails. This includes a
    ///   commit or a dirtree that is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or that is not a
    ///   regular file.
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

    /// Returns the name of each object that one of `roots` and its parents
    /// reach.
    ///
    /// For each root, the set holds the objects that
    /// [`traverse_commit`](Repo::traverse_commit) collects. If two roots reach
    /// one commit, the walk follows its parents under the depth that reaches
    /// further. So the result does not depend on the order of `roots`.
    ///
    /// # Depth
    ///
    /// `max_depth` applies to each root. `0` is the root alone, `N` is the root
    /// and `N` parents, and `-1` is the whole ancestry. Each other negative
    /// value is the root alone.
    ///
    /// # Missing objects
    ///
    /// - The set holds the name of each object that a reached object refers
    ///   to, also if the repository does not hold that object.
    /// - If a commit or a dirtree is absent, the walk cannot read its children.
    ///   So the set holds no object below it.
    /// - An absent root causes no error, so a ref to an absent commit does not
    ///   stop the walk.
    /// - The walk does not look up dirmeta objects and file objects.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if a commit or a dirtree that the walk reads does not
    ///   parse.
    /// - [`Error::Io`] if a read of the object store fails. This includes a
    ///   commit or a dirtree that is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or that is not a
    ///   regular file.
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

    /// Returns the name of each object that one of `roots` reaches over the
    /// edges of `gc`.
    ///
    /// The walk is the walk of
    /// [`traverse_reachable`](Repo::traverse_reachable), with an optional
    /// `parent` edge and with the metadata-key edges.
    ///
    /// Each root has its own bound. So one walk can cut one branch to a depth
    /// and keep another branch in full. The walk seeds each commit that a
    /// metadata-key edge names at `root_bound`.
    ///
    /// `bounded_roots` names the commits whose bound belongs to the commit,
    /// and not to the path that reached it. The walk drops each `parent`-edge
    /// arrival at one of these commits, and the seed does the expansion. So the
    /// seed replaces the inherited bound. Each checksum in `bounded_roots` must
    /// also be a seed in `roots`.
    ///
    /// `pending_delete` names a commit that the walk reads as absent. Prune
    /// unlinks the commit that it deletes only after the walk succeeds. With
    /// `pending_delete`, the result is the result of a walk of the store after
    /// the unlink. The name of the commit is reachable, and nothing below it
    /// is.
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

    /// Adds to `reachable` the name of each object that `seeds` reach.
    ///
    /// `seeds` pairs each root commit with the bound of its `parent` chain and
    /// with the kind of its arrival. The walk adds the name of each object that
    /// a reached object refers to. To read the children of a commit or a
    /// dirtree, the walk must load it. So an absent commit or dirtree adds its
    /// own name and no name below it. A commit or a dirtree that does not
    /// parse stops the walk with an error.
    ///
    /// If more than one root reaches a commit, the walk expands the commit
    /// under the bound that reaches furthest. So the reachable set does not
    /// depend on the order of the roots. If an earlier expansion of the commit
    /// reaches at least as far, the walk skips the arrival. Otherwise it
    /// expands the commit again, to follow its parents further.
    ///
    /// A commit that `bounded_roots` names has its own bound. The walk drops
    /// each `parent`-edge arrival at such a commit. So the bound of the seed
    /// replaces the bound that the arrival inherited.
    ///
    /// A commit that `gc.weak_roots` names also has its own bounds, and no
    /// seed of the caller adds it to the walk. The first arrival at such a
    /// commit pushes one seed for each bound that the map records, at most
    /// one of each kind. Then the walk drops a `parent`-edge arrival as it
    /// drops one for `bounded_roots`, so the pushed seeds replace the
    /// inherited bound.
    ///
    /// An arrival at a weak-ref commit that is a root itself stays. The commit
    /// expands under the bound of the arrival and under the pushed seeds. The
    /// pushed seeds go through the same memoization as each other entry. The
    /// walk skips a commit that an earlier expansion covers, and expands again
    /// a commit that a further bound reaches.
    ///
    /// A commit takes its weak seeds once. Each extra entry is either skipped
    /// or strictly extends the recorded depth or timestamp. So the walk ends.
    ///
    /// A conditional arrival is an arrival over a [`ParentBound::Since`]
    /// `parent` edge. If the timestamp of the commit is below the bound, the
    /// arrival adds nothing and records no expansion. So a root that names the
    /// same commit still keeps it. The walk memoizes the rejection, so a second
    /// child that arrives under the same bound reads no commit.
    ///
    /// The walk seeds each commit that a metadata-key edge names at
    /// `root_bound`. The walk reads the commit `pending_delete` names as
    /// absent.
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
        // The commits for which the walk pushed a weak-ref seed. A pushed seed
        // matches `weak_roots` again when the walk pops it. This set stops the
        // walk from a second push of the seed.
        let mut weak_seeded: HashSet<Checksum> = HashSet::new();

        while let Some((commit_checksum, bound, arrival)) = commit_stack.pop() {
            // When the walk reaches the commit of a weak ref over any edge,
            // the commit takes the bound of the name of that ref. The seed is
            // a `Root` arrival, so the bound belongs to the commit. Under a
            // `Since` bound, the walk keeps the commit whatever its timestamp,
            // as it keeps the target of a strong ref.
            //
            // This test comes before the `inherited` drop and applies to each
            // kind of arrival. A metadata-key edge pushes a `Root` arrival at
            // the global bound of the run. If the rule tested `inherited`
            // alone, that arrival can expand the commit at the global bound
            // while the bound of the weak ref reaches further. Then the sweep
            // deletes the ancestry of a ref that stays.
            if let Some(bounds) = gc.weak_roots.get(&commit_checksum)
                && weak_seeded.insert(commit_checksum)
            {
                for weak_bound in bounds.seeds() {
                    commit_stack.push((commit_checksum, weak_bound, Arrival::Root));
                }
            }

            // A commit with its own bound takes that bound, whatever bound the
            // `parent` edge had left. The seed holds that bound. So the walk
            // drops the arrival here, and the expansion of the seed replaces
            // it. The walk drops an arrival at the commit of a weak ref in the
            // same way, because the pushed weak-ref seed holds its bound.
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

            // The walk does not keep a commit that the timestamp bound rejects,
            // and records no expansion for it. So a ref that names the commit
            // still reaches it. The walk records the rejection, so a second
            // child under the same bound does not read the commit again.
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

    /// Adds to `reachable` the name of each dirtree, dirmeta, and file object
    /// that `root_dirtree` reaches.
    ///
    /// An absent dirtree adds its own name only. A dirtree that does not parse
    /// stops the walk with an error.
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

    /// Adds the names of one tree to `seen` and `out`.
    ///
    /// The names are the root dirmeta, the root dirtree, and each dirtree,
    /// dirmeta, and file object that they reach. The walk skips a name that
    /// `seen` holds, and the subtree below a dirtree that `seen` holds. So
    /// several trees share one walk. Each new name goes into `seen` and onto
    /// the end of `out`.
    ///
    /// The walk is strict: a dirtree or a dirmeta that the repository does
    /// not hold is [`Error::ObjectNotFound`]. The walk does not look up file
    /// objects.
    ///
    /// The walk loads up to [`STRICT_TREE_LOADS`] dirtrees at the same time.
    /// It takes them from its stack in order, and it reads their entries in
    /// the same order. So the order of `out` does not depend on the loads.
    #[cfg(feature = "push")]
    pub(crate) async fn collect_tree_strict(
        &self,
        root_dirtree: Checksum,
        root_dirmeta: Checksum,
        seen: &mut HashSet<ObjectName>,
        out: &mut Vec<ObjectName>,
    ) -> Result<()> {
        self.collect_dirmeta_strict(root_dirmeta, seen, out).await?;
        let mut stack = vec![root_dirtree];
        let mut batch = Vec::with_capacity(STRICT_TREE_LOADS);
        while !stack.is_empty() {
            batch.clear();
            while batch.len() < STRICT_TREE_LOADS
                && let Some(dirtree_checksum) = stack.pop()
            {
                let name = ObjectName::new(dirtree_checksum, ObjectType::DirTree);
                if seen.insert(name) {
                    out.push(name);
                    batch.push(dirtree_checksum);
                }
            }
            let dirtrees = join_all(batch.iter().map(|c| self.load_dirtree(c))).await;
            for dirtree in dirtrees {
                let dirtree = dirtree?;
                for (_, file_checksum) in dirtree.files {
                    let name = ObjectName::new(file_checksum, ObjectType::File);
                    if seen.insert(name) {
                        out.push(name);
                    }
                }
                for (_, subtree, submeta) in dirtree.dirs {
                    self.collect_dirmeta_strict(submeta, seen, out).await?;
                    stack.push(subtree);
                }
            }
        }
        Ok(())
    }

    /// Adds the dirmeta `checksum` to `seen` and `out` if `seen` does not
    /// hold it.
    ///
    /// A dirmeta that the repository does not hold is
    /// [`Error::ObjectNotFound`].
    #[cfg(feature = "push")]
    async fn collect_dirmeta_strict(
        &self,
        checksum: Checksum,
        seen: &mut HashSet<ObjectName>,
        out: &mut Vec<ObjectName>,
    ) -> Result<()> {
        let name = ObjectName::new(checksum, ObjectType::DirMeta);
        if !seen.insert(name) {
            return Ok(());
        }
        if !self.has_object(ObjectType::DirMeta, &checksum).await? {
            return Err(Error::ObjectNotFound {
                checksum,
                ty: ObjectType::DirMeta,
            });
        }
        out.push(name);
        Ok(())
    }

    /// Pushes onto the walk each commit that the configured metadata keys
    /// name.
    ///
    /// The method reads each key from `metadata`, the metadata of the commit,
    /// and then from its detached metadata. So one key name gives edges from
    /// both. A key that no dict holds adds nothing.
    ///
    /// If a key is present and does not hold an `aay` of 32-byte checksums,
    /// the walk fails with [`Error::InvalidGcRoot`]. If the walk does not
    /// follow an edge, a sweep deletes the objects of that edge. So a value
    /// that the walk cannot read stops the walk.
    ///
    /// The method reads the detached metadata once for each expansion of a
    /// commit, and only if the walk has metadata keys. The walk can reach a
    /// commit again at a depth that follows more parents. It then expands the
    /// commit a second time and reads the detached metadata again.
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

    /// Loads and parses a commit for the lenient walk.
    ///
    /// Returns `None` if the repository does not hold the commit.
    async fn try_load_commit(&self, checksum: &Checksum) -> Result<Option<Commit>> {
        match self.load_object_bytes(ObjectType::Commit, checksum).await {
            Ok(bytes) => Ok(Some(Commit::parse(&bytes)?)),
            Err(Error::ObjectNotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Loads and parses a dirtree, or returns `None` if it is absent.
    async fn try_load_dirtree(&self, checksum: &Checksum) -> Result<Option<ostrya_core::DirTree>> {
        match self.load_dirtree(checksum).await {
            Ok(dirtree) => Ok(Some(dirtree)),
            Err(Error::ObjectNotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Returns the commit checksum of each ref in `refs/heads`,
    /// `refs/remotes`, and `refs/mirrors`.
    ///
    /// Prune and fsck seed their walks with these targets.
    pub(crate) async fn list_all_ref_targets(&self) -> Result<Vec<Checksum>> {
        Ok(self
            .list_all_refs()
            .await?
            .into_iter()
            .map(|listed| listed.checksum)
            .collect())
    }

    /// Returns each ref in `refs/heads`, `refs/remotes`, and `refs/mirrors`.
    ///
    /// The name of each kind of ref:
    ///
    /// - A local ref: its path under `refs/heads`. A nested name keeps its `/`.
    /// - A remote ref: its `<remote>:<name>` refspec.
    /// - A mirror ref: its path under `refs/mirrors`, that is the collection id
    ///   and the ref name below it.
    ///
    /// Each ref also tells if its name addresses the file that the listing
    /// read. A caller that reads or unlinks a ref by its name needs this check.
    /// Prune reads the names to find the branch that a depth applies to. It
    /// reads the [`RefSpace`] and the addressability to find the refs that its
    /// classifier sees.
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

/// The maximum number of dirtrees that [`Repo::collect_tree_strict`] loads at
/// the same time.
///
/// Each load holds one dirtree object, and the format caps its size. So the
/// loads hold at most this many objects in memory.
#[cfg(feature = "push")]
const STRICT_TREE_LOADS: usize = 8;

/// Runs `futures` at the same time and returns their outputs in the order of
/// `futures`.
#[cfg(feature = "push")]
async fn join_all<F: Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let mut futures: Vec<_> = futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let mut outputs: Vec<Option<F::Output>> = futures.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (future, output) in futures.iter_mut().zip(outputs.iter_mut()) {
            if let Some(running) = future {
                match running.as_mut().poll(cx) {
                    std::task::Poll::Ready(value) => {
                        *output = Some(value);
                        *future = None;
                    }
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    outputs
        .into_iter()
        .map(|output| output.expect("each future is ready"))
        .collect()
}

/// Returns the commits that the value of one metadata key names.
///
/// The value is the variant that an `a{sv}` entry holds. It must hold an `aay`
/// in which each element is a 32-byte commit checksum. Any other value is an
/// [`Error::InvalidGcRoot`] that names the commit of the value.
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

/// Returns `true` if an expansion at remaining depth `prev` follows at least
/// as many parents as a new arrival at remaining depth `depth`.
///
/// A negative depth has no bound, so it reaches further than each finite
/// depth.
pub(crate) fn reaches_at_least(prev: i32, depth: i32) -> bool {
    if prev < 0 {
        true
    } else if depth < 0 {
        false
    } else {
        prev >= depth
    }
}

/// Calls `f` with the [`ObjectName`] of each loose object under the
/// `objects/` directory `objects_fd`.
///
/// The function calls `keep` with the type from the extension of the entry,
/// before it parses the checksum. So it parses no hexadecimal name of another
/// type.
///
/// The listing holds one directory open at a time and borrows each entry name
/// from the reader. So it makes no allocation for each object.
fn for_each_object(
    objects_fd: BorrowedFd<'_>,
    keep: impl Fn(ObjectType) -> bool,
    mut f: impl FnMut(ObjectName),
) -> Result<()> {
    for_each_dir_name(objects_fd, |fanout| {
        // The name of a fanout directory is two hexadecimal characters. Any
        // other entry of `objects/` (a stray file, a cache directory) is not
        // a fanout directory.
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

/// Returns the name of each loose object under the `objects/` directory
/// `objects_fd`.
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

/// Returns the number of loose objects under the `objects/` directory
/// `objects_fd` whose type `keep` accepts.
///
/// The count keeps no name.
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

/// Parses one `objects/<fanout>/<rest>.<ext>` entry into an [`ObjectName`].
///
/// Returns `None` if the name is not a loose object name, or if `keep` refuses
/// its type.
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

/// Calls `f` with the name of each entry of an open directory, except `.` and
/// `..`.
///
/// The name borrows the buffer of the reader.
fn for_each_dir_name(dir: BorrowedFd<'_>, mut f: impl FnMut(&str) -> Result<()>) -> Result<()> {
    let reader = rustix::fs::Dir::read_from(dir).map_err(|e| Error::Io(e.into()))?;
    for entry in reader {
        let entry = entry.map_err(|e| Error::Io(e.into()))?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        // Object names and fanout names are ASCII, and a ref name is UTF-8.
        // Any other name is not a loose object and not a ref.
        if let Ok(name) = std::str::from_utf8(bytes) {
            f(name)?;
        }
    }
    Ok(())
}

/// Returns the entry names of an open directory, except `.` and `..`.
pub(crate) fn read_dir_names(dir: BorrowedFd<'_>) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for_each_dir_name(dir, |name| {
        names.push(name.to_owned());
        Ok(())
    })?;
    Ok(names)
}

/// Adds to `out` each ref file in the tree under `top`.
///
/// The walk follows alias symlinks and skips a dangling symlink. A ref under
/// `refs/remotes` takes its `<remote>:<name>` refspec as its name. A ref under
/// `refs/heads` or `refs/mirrors` takes its path below `top`.
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
            // A mirror entry always gives `false`, because no refspec maps to
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

/// The largest ref file that the reader loads, in bytes.
///
/// A ref file is 65 bytes.
const REF_READ_CAP: u64 = 4096;

/// Returns the target checksum of the ref file `name` in `dir`.
///
/// The read follows alias symlinks. Returns `None` if the file is absent.
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
