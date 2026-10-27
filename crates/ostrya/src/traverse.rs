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
use crate::pull::drive::Slots;
use crate::refs::walk_ref_dir;
use crate::related::{self, RelatedField, RelatedWarning};
use crate::repo::Repo;

/// The bound that a walk puts on the `parent` chain of one root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParentBound {
    /// The number of `parent` edges that the walk can still follow.
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
    /// A name that fails the ref-name rule gives `false`.
    pub(crate) addressable: bool,
    /// The commit that the ref resolves to.
    pub(crate) checksum: Checksum,
}

/// The kind of edge over which the walk arrived at a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arrival {
    /// An arrival at a root: a seed of the caller, or a commit that a related
    /// edge names. The bound of the arrival is the bound of the commit itself.
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

/// What the walk read of one commit.
#[derive(Debug, Clone, Copy, Default)]
enum Read {
    /// The walk did not read the commit.
    #[default]
    Unread,
    /// The store does not hold the commit.
    Absent,
    /// The store holds the commit, with this parent and this timestamp.
    Present {
        parent: Option<Checksum>,
        timestamp: u64,
    },
}

/// The furthest bounds under which the walk expanded one commit, and the
/// parent and the timestamp of the commit.
///
/// The walk expands a commit again only under a bound that reaches further
/// than each earlier bound of that commit. So each expansion strictly extends
/// `depth` or `since`, and the walk ends. A second expansion follows the
/// parent that `read` holds, and reads the commit no second time.
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
    /// What the walk read of the commit.
    read: Read,
}

impl Expanded {
    /// Returns `true` if the walk expanded the commit under one bound or
    /// more.
    fn expanded(&self) -> bool {
        self.depth.is_some() || self.since.is_some()
    }

    /// Returns `true` if an earlier expansion reaches at least as far as
    /// `bound`.
    fn covers(&self, bound: ParentBound) -> bool {
        if self.depth == Some(-1) {
            return true;
        }
        match bound {
            // Each expansion reads the commit, its tree, and its edges other
            // than `parent`. An expansion under `Depth(0)` follows no parent,
            // so each earlier expansion covers it.
            ParentBound::Depth(0) => self.expanded(),
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
    /// `true` if the walk follows field 2 of a commit: the dependencies.
    pub dependencies: bool,
    /// `true` if the walk follows the `ostrya.related` entry of the detached
    /// metadata of a commit: the build sources.
    ///
    /// The walk reads the detached metadata of a commit only if this is
    /// `true`.
    pub build_sources: bool,
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
    /// edge, the trees, and no related edges.
    fn parents_only() -> GcRoots {
        GcRoots {
            dependencies: false,
            build_sources: false,
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
    /// The listing holds the sidecars of the commits too: each `.commitmeta`
    /// object and each `.cfs` composefs image, of type
    /// [`ObjectType::ComposefsImage`]. The checksum of a sidecar is the
    /// checksum of its commit.
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

    /// Returns the checksums of the commit objects and of the composefs image
    /// objects, each in sorted order.
    ///
    /// One listing pass of [`list_objects`](Repo::list_objects) gives both
    /// lists. The pass reads the type from the extension of an entry before
    /// it parses the name, so it parses no name of another type. A store with
    /// no image gives an empty second list.
    pub(crate) async fn list_commits_and_images(&self) -> Result<(Vec<Checksum>, Vec<Checksum>)> {
        let repo = self.clone();
        let (mut commits, mut images) = ostrya_rt::unblock(move || -> Result<_> {
            let mut commits = Vec::new();
            let mut images = Vec::new();
            for_each_object(
                repo.objects_fd(),
                |ty| matches!(ty, ObjectType::Commit | ObjectType::ComposefsImage),
                |name| match name.ty {
                    ObjectType::Commit => commits.push(name.checksum),
                    _ => images.push(name.checksum),
                },
            )?;
            Ok((commits, images))
        })
        .await?;
        commits.sort();
        images.sort();
        Ok((commits, images))
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
        // The walk follows no related edge, so it gives no warning.
        let mut warnings = Vec::new();
        collect_reachable(
            self,
            vec![(*commit, bound, Arrival::Root)],
            bound,
            &GcRoots::parents_only(),
            &HashSet::new(),
            None,
            &mut reachable,
            &mut warnings,
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
        walk_reachable(self, roots, max_depth).await
    }

    /// Returns the name of each object that one of `roots` reaches over the
    /// edges of `gc`, and the warnings of the defective related values that
    /// the walk read.
    ///
    /// The walk is the walk of
    /// [`traverse_reachable`](Repo::traverse_reachable), with an optional
    /// `parent` edge and with the related edges.
    ///
    /// Each root has its own bound. So one walk can cut one branch to a depth
    /// and keep another branch in full. The walk seeds each commit that a
    /// related edge names at `root_bound`.
    ///
    /// The warnings are sorted by commit and then by field, dependencies
    /// first. The warnings of one field keep the order of its entries.
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
    ///
    /// `listing` is the listing of the loose objects that the caller took
    /// under the exclusive repository lock, and the caller holds that lock
    /// during the walk. The walk reads the `.commitmeta` of a commit only if
    /// `listing` holds it.
    pub(crate) async fn traverse_reachable_gc(
        &self,
        roots: impl IntoIterator<Item = (Checksum, ParentBound)>,
        root_bound: ParentBound,
        gc: &GcRoots,
        bounded_roots: &HashSet<Checksum>,
        pending_delete: Option<Checksum>,
        listing: &HashSet<ObjectName>,
    ) -> Result<(HashSet<ObjectName>, Vec<RelatedWarning>)> {
        let store = ListedLoose {
            repo: self,
            listing,
        };
        walk_reachable_gc(&store, roots, root_bound, gc, bounded_roots, pending_delete).await
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

/// A store of metadata objects that the reachability walk reads.
///
/// [`Repo`] reads its loose objects, and a bucket repository reads the keys
/// of its objects. The walk parses the bytes itself, so each store gives the
/// same result for the same objects.
pub(crate) trait MetadataSource: Sync {
    /// Returns the bytes of the metadata object of `ty` and `checksum`, or
    /// `None` if the store does not hold the object.
    ///
    /// `None` must mean that the object is absent. The walk adds no name
    /// below an absent commit or dirtree. So a failed read that gives `None`
    /// hides a subtree from the walk, and each other failure is an error. A
    /// bucket repository gives `None` only for a 404 with the code
    /// `NoSuchKey`.
    fn load_metadata(
        &self,
        ty: ObjectType,
        checksum: Checksum,
    ) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    /// Returns the number of dirtree reads that the walk of one tree can
    /// have in flight at a time.
    ///
    /// The default is one, and zero is one. [`Repo`] keeps the default.
    fn max_reads(&self) -> usize {
        1
    }

    /// Returns the detached metadata dict of the commit `commit`, or `None`
    /// if the store holds no `.commitmeta` for it or holds the zero-length
    /// marker.
    ///
    /// The default reads the object with
    /// [`load_metadata`](MetadataSource::load_metadata) and parses it on the
    /// blocking pool. [`Repo`] reads and parses the file in one trip to the
    /// blocking pool.
    fn load_detached(
        &self,
        commit: Checksum,
    ) -> impl Future<Output = Result<Option<Value>>> + Send {
        async move {
            match self.load_metadata(ObjectType::CommitMeta, commit).await? {
                Some(bytes) => {
                    ostrya_rt::unblock(move || crate::commit::parse_detached_metadata(&bytes)).await
                }
                None => Ok(None),
            }
        }
    }

    /// Returns the bytes of the commit object `commit` and its detached
    /// metadata dict, or `None` if the store does not hold the commit.
    ///
    /// The detached metadata is the value that
    /// [`load_detached`](MetadataSource::load_detached) gives. The default
    /// calls [`load_metadata`](MetadataSource::load_metadata) and then
    /// `load_detached`. [`Repo`] reads the two files and parses the detached
    /// metadata in one trip to the blocking pool.
    fn load_commit_with_detached(
        &self,
        commit: Checksum,
    ) -> impl Future<Output = Result<Option<(Vec<u8>, Option<Value>)>>> + Send {
        async move {
            let Some(bytes) = self.load_metadata(ObjectType::Commit, commit).await? else {
                return Ok(None);
            };
            Ok(Some((bytes, self.load_detached(commit).await?)))
        }
    }
}

impl MetadataSource for Repo {
    async fn load_metadata(&self, ty: ObjectType, checksum: Checksum) -> Result<Option<Vec<u8>>> {
        match self.load_object_bytes(ty, &checksum).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(Error::ObjectNotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn load_detached(&self, commit: Checksum) -> Result<Option<Value>> {
        self.read_commit_detached_metadata(&commit).await
    }

    async fn load_commit_with_detached(
        &self,
        commit: Checksum,
    ) -> Result<Option<(Vec<u8>, Option<Value>)>> {
        match self.load_commit_and_detached(&commit).await {
            Ok(loaded) => Ok(Some(loaded)),
            Err(Error::ObjectNotFound {
                ty: ObjectType::Commit,
                ..
            }) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// The loose objects of a [`Repo`], with the listing of the objects that the
/// caller of the walk took.
///
/// A prune takes the listing under the exclusive repository lock and holds
/// that lock during the walk. Each writer of a `.commitmeta` file takes the
/// shared repository lock. So a `.commitmeta` that the listing does not hold
/// is absent, and the source opens no file for it. Each other read goes to
/// the [`Repo`]. If `[core] locking` is false, no lock orders the walk and a
/// writer, as for each other object of the prune.
struct ListedLoose<'a> {
    repo: &'a Repo,
    listing: &'a HashSet<ObjectName>,
}

impl ListedLoose<'_> {
    /// Returns `true` if the listing holds the `.commitmeta` of `commit`.
    fn has_detached(&self, commit: Checksum) -> bool {
        self.listing
            .contains(&ObjectName::new(commit, ObjectType::CommitMeta))
    }
}

impl MetadataSource for ListedLoose<'_> {
    async fn load_metadata(&self, ty: ObjectType, checksum: Checksum) -> Result<Option<Vec<u8>>> {
        if ty == ObjectType::CommitMeta && !self.has_detached(checksum) {
            return Ok(None);
        }
        self.repo.load_metadata(ty, checksum).await
    }

    async fn load_detached(&self, commit: Checksum) -> Result<Option<Value>> {
        if !self.has_detached(commit) {
            return Ok(None);
        }
        self.repo.load_detached(commit).await
    }

    async fn load_commit_with_detached(
        &self,
        commit: Checksum,
    ) -> Result<Option<(Vec<u8>, Option<Value>)>> {
        if !self.has_detached(commit) {
            let bytes = self.repo.load_metadata(ObjectType::Commit, commit).await?;
            return Ok(bytes.map(|bytes| (bytes, None)));
        }
        self.repo.load_commit_with_detached(commit).await
    }
}

/// Returns the name of each object of `store` that one of `roots` and its
/// parents reach.
///
/// The walk is the walk of [`Repo::traverse_reachable`], and `max_depth`
/// has the same meaning.
pub(crate) async fn walk_reachable<S: MetadataSource>(
    store: &S,
    roots: impl IntoIterator<Item = Checksum>,
    max_depth: i32,
) -> Result<HashSet<ObjectName>> {
    let bound = ParentBound::depth(max_depth);
    // The walk follows no related edge, so it gives no warning.
    let (reachable, _) = walk_reachable_gc(
        store,
        roots.into_iter().map(|c| (c, bound)),
        bound,
        &GcRoots::parents_only(),
        &HashSet::new(),
        None,
    )
    .await?;
    Ok(reachable)
}

/// Returns the name of each object of `store` that one of `roots` reaches
/// over the edges of `gc`, and the warnings of the defective related values
/// that the walk read.
///
/// The walk is the walk of [`Repo::traverse_reachable_gc`], and the
/// arguments and the result have the same meaning.
pub(crate) async fn walk_reachable_gc<S: MetadataSource>(
    store: &S,
    roots: impl IntoIterator<Item = (Checksum, ParentBound)>,
    root_bound: ParentBound,
    gc: &GcRoots,
    bounded_roots: &HashSet<Checksum>,
    pending_delete: Option<Checksum>,
) -> Result<(HashSet<ObjectName>, Vec<RelatedWarning>)> {
    let seeds = roots
        .into_iter()
        .map(|(c, bound)| (c, bound, Arrival::Root))
        .collect();
    let mut reachable = HashSet::new();
    let mut warnings = Vec::new();
    collect_reachable(
        store,
        seeds,
        root_bound,
        gc,
        bounded_roots,
        pending_delete,
        &mut reachable,
        &mut warnings,
    )
    .await?;
    // The walk reads the commits in an order that depends on the order of
    // the roots. The sort is stable, so the warnings of one field keep the
    // order of its entries.
    warnings.sort_by_key(|w| (w.commit, w.field == RelatedField::BuildSources));
    Ok((reachable, warnings))
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
/// expands the commit again, to follow its parents further. Each expansion
/// reaches the tree and the edges other than `parent`, so each earlier
/// expansion covers an arrival under `Depth(0)`. The walk keeps the parent
/// and the timestamp of each commit that it reads, so a second expansion
/// reads no commit.
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
/// same commit still keeps it. The walk memoizes the rejection and the
/// timestamp, so a second conditional arrival reads no commit. An arrival
/// that expands the commit after a rejection reads the commit again, for
/// its tree and its edges other than `parent`.
///
/// The walk seeds each commit that a related edge names at `root_bound`.
/// Each such seed is the same entry, so the walk pushes it at the first edge
/// alone. One set of seeded commits serves the two related fields. The walk
/// reads the commit `pending_delete` names as absent.
///
/// The walk reads the edges other than `parent` one time for each commit, at
/// its first expansion. A later expansion follows more parents, and the
/// seeds of the edges are the same. The related edges are:
///
/// - With `gc.dependencies`, the entries of field 2. The walk reads field 2
///   of each commit that it reaches, a dependency included.
/// - With `gc.build_sources`, the entries of the first `ostrya.related` entry
///   of the detached metadata. The walk reads it for each commit that it
///   reaches, a build source included.
///
/// A defective related value or entry adds one warning to `warnings` and
/// seeds nothing. The other entries of the field seed as usual. A related
/// entry that names a commit that the store does not hold seeds a commit
/// that adds its own name alone. Unless the arrival is over a `parent` edge
/// under a timestamp bound, the walk reads the detached metadata with the
/// commit in one call of
/// [`load_commit_with_detached`](MetadataSource::load_commit_with_detached).
/// A `.commitmeta` that does not parse stops the walk with an error.
///
/// The walk reads the commits one at a time. It walks the tree of a commit
/// with [`walk_tree`] before it reads the next commit.
#[allow(clippy::too_many_arguments)]
async fn collect_reachable<S: MetadataSource>(
    store: &S,
    seeds: Vec<(Checksum, ParentBound, Arrival)>,
    root_bound: ParentBound,
    gc: &GcRoots,
    bounded_roots: &HashSet<Checksum>,
    pending_delete: Option<Checksum>,
    reachable: &mut HashSet<ObjectName>,
    warnings: &mut Vec<RelatedWarning>,
) -> Result<()> {
    let mut commit_stack = seeds;
    let mut seen_commits: HashMap<Checksum, Expanded> = HashMap::new();
    let mut seen_dirtrees: HashSet<Checksum> = HashSet::new();
    // The commits for which the walk pushed a weak-ref seed. A pushed seed
    // matches `weak_roots` again when the walk pops it. This set stops the
    // walk from a second push of the seed.
    let mut weak_seeded: HashSet<Checksum> = HashSet::new();
    // The commits for which a related edge pushed a seed. A second edge to
    // the same commit pushes the same entry, which adds nothing.
    let mut seeded: HashSet<Checksum> = HashSet::new();
    // The commits whose edges other than `parent` the walk read. The walk
    // adds a commit when it reads them, so an arrival that the timestamp
    // bound rejects reads nothing and adds nothing.
    let mut edges_read: HashSet<Checksum> = HashSet::new();
    let reads_edges = gc.dependencies || gc.build_sources;

    while let Some((commit_checksum, bound, arrival)) = commit_stack.pop() {
        // When the walk reaches the commit of a weak ref over any edge,
        // the commit takes the bound of the name of that ref. The seed is
        // a `Root` arrival, so the bound belongs to the commit. Under a
        // `Since` bound, the walk keeps the commit whatever its timestamp,
        // as it keeps the target of a strong ref.
        //
        // This test comes before the `inherited` drop and applies to each
        // kind of arrival. A related edge pushes a `Root` arrival at the
        // global bound of the run. If the rule tested `inherited` alone, that
        // arrival can expand the commit at the global bound while the bound
        // of the weak ref reaches further. Then the sweep deletes the
        // ancestry of a ref that stays.
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

        // The timestamp that the entry holds decides a conditional arrival
        // with no second read of the commit.
        if arrival == Arrival::TimedParent
            && let ParentBound::Since(since) = bound
            && let Read::Present { timestamp, .. } = seen.read
            && timestamp < since
        {
            seen_commits
                .entry(commit_checksum)
                .or_default()
                .reject(since);
            continue;
        }
        // An earlier expansion read the commit, walked its tree, and read
        // its edges other than `parent`. So a further expansion follows the
        // parent alone.
        if seen.expanded() {
            seen_commits
                .entry(commit_checksum)
                .or_default()
                .record(bound);
            if gc.traverse_parent
                && let Read::Present {
                    parent: Some(parent),
                    ..
                } = seen.read
            {
                push_parent(&mut commit_stack, parent, bound);
            }
            continue;
        }

        // At the first expansion of a commit, the walk reads the detached
        // metadata with the commit, in one read of the store. A `TimedParent`
        // arrival can be rejected, so it reads the commit alone, and the
        // walk reads the detached metadata after the bound accepts it.
        let mut prefetched: Option<Option<Value>> = None;
        let loaded = if pending_delete == Some(commit_checksum) {
            None
        } else if gc.build_sources
            && arrival != Arrival::TimedParent
            && !edges_read.contains(&commit_checksum)
        {
            match store.load_commit_with_detached(commit_checksum).await? {
                Some((bytes, detached)) => {
                    prefetched = Some(detached);
                    Some(Commit::parse(&bytes)?)
                }
                None => None,
            }
        } else {
            try_load_commit(store, &commit_checksum).await?
        };
        let entry = seen_commits.entry(commit_checksum).or_default();
        entry.read = match &loaded {
            Some(commit) => Read::Present {
                parent: commit.parent,
                timestamp: commit.timestamp,
            },
            None => Read::Absent,
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
            entry.reject(since);
            continue;
        }

        entry.record(bound);
        reachable.insert(ObjectName::new(commit_checksum, ObjectType::Commit));

        let Some(commit) = loaded else {
            continue;
        };

        if gc.traverse_tree {
            reachable.insert(ObjectName::new(commit.root_dirmeta, ObjectType::DirMeta));
            walk_tree(store, commit.root_dirtree, &mut seen_dirtrees, reachable).await?;
        }

        if reads_edges && edges_read.insert(commit_checksum) {
            let mut push = |target: Checksum| {
                if seeded.insert(target) {
                    commit_stack.push((target, root_bound, Arrival::Root));
                }
            };
            if gc.dependencies {
                let (targets, defects) =
                    related::split_entries(related::entries_of(&commit.related));
                warnings.extend(defects.into_iter().map(|reason| RelatedWarning {
                    commit: commit_checksum,
                    field: RelatedField::Dependencies,
                    reason,
                }));
                targets.into_iter().for_each(&mut push);
            }
            if gc.build_sources {
                let detached = match prefetched {
                    Some(detached) => detached,
                    None => store.load_detached(commit_checksum).await?,
                };
                let (targets, defects) = match related::build_sources(detached.as_ref()) {
                    Ok(entries) => related::split_entries(entries.unwrap_or_default()),
                    Err(reason) => (Vec::new(), vec![reason]),
                };
                warnings.extend(defects.into_iter().map(|reason| RelatedWarning {
                    commit: commit_checksum,
                    field: RelatedField::BuildSources,
                    reason,
                }));
                targets.into_iter().for_each(&mut push);
            }
        }

        if gc.traverse_parent
            && let Some(parent) = commit.parent
        {
            push_parent(&mut commit_stack, parent, bound);
        }
    }
    Ok(())
}

/// Pushes the arrival at `parent` over the `parent` edge of a commit that
/// the walk expands under `bound`.
///
/// Under `Depth(0)`, the walk follows no parent and pushes nothing.
fn push_parent(
    commit_stack: &mut Vec<(Checksum, ParentBound, Arrival)>,
    parent: Checksum,
    bound: ParentBound,
) {
    match bound {
        ParentBound::Depth(0) => {}
        ParentBound::Depth(depth) => {
            let next = if depth < 0 { -1 } else { depth - 1 };
            commit_stack.push((parent, ParentBound::Depth(next), Arrival::Parent));
        }
        ParentBound::Since(since) => {
            commit_stack.push((parent, ParentBound::Since(since), Arrival::TimedParent));
        }
    }
}

/// Adds to `reachable` the name of each dirtree, dirmeta, and file object
/// that `root_dirtree` reaches.
///
/// An absent dirtree adds its own name only. A dirtree that does not parse
/// stops the walk with an error.
///
/// The walk reads at most [`max_reads`](MetadataSource::max_reads) dirtrees
/// at a time. It adds the name of a dirtree when it starts the read, so it
/// reads each dirtree once. With a limit of one, the walk reads the
/// dirtrees in depth-first order, and starts each read after the read
/// before it ends. With a higher limit, the first read that fails in time
/// gives the error, and the walk drops the other reads in flight. If no
/// read fails, the set does not depend on the limit.
async fn walk_tree<S: MetadataSource>(
    store: &S,
    root_dirtree: Checksum,
    seen_dirtrees: &mut HashSet<Checksum>,
    reachable: &mut HashSet<ObjectName>,
) -> Result<()> {
    let mut stack = vec![root_dirtree];
    let mut reads = Slots::new(store.max_reads());
    loop {
        while reads.has_room()
            && let Some(dirtree_checksum) = stack.pop()
        {
            if !seen_dirtrees.insert(dirtree_checksum) {
                continue;
            }
            reachable.insert(ObjectName::new(dirtree_checksum, ObjectType::DirTree));
            reads.push(async move { try_load_dirtree(store, &dirtree_checksum).await });
        }
        // The loop above stops on an empty stack or on a full set. So an
        // empty set means that the stack is empty too.
        let Some(loaded) = reads.next_ready().await else {
            break;
        };
        let Some(dirtree) = loaded? else {
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

/// Loads and parses a commit for the lenient walk.
///
/// Returns `None` if the store does not hold the commit.
async fn try_load_commit<S: MetadataSource>(
    store: &S,
    checksum: &Checksum,
) -> Result<Option<Commit>> {
    match store.load_metadata(ObjectType::Commit, *checksum).await? {
        Some(bytes) => Ok(Some(Commit::parse(&bytes)?)),
        None => Ok(None),
    }
}

/// Loads and parses a dirtree, or returns `None` if it is absent.
async fn try_load_dirtree<S: MetadataSource>(
    store: &S,
    checksum: &Checksum,
) -> Result<Option<ostrya_core::DirTree>> {
    match store.load_metadata(ObjectType::DirTree, *checksum).await? {
        Some(bytes) => Ok(Some(ostrya_core::DirTree::parse(&bytes)?)),
        None => Ok(None),
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A `.cfs` entry parses as the composefs image of the commit that has
    /// the same checksum, and the `keep` filter applies to it.
    #[test]
    fn a_cfs_entry_parses_as_a_composefs_image() {
        let hex = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";
        let checksum = Checksum::from_hex(hex).unwrap();
        let entry = format!("{}.cfs", &hex[2..]);
        assert_eq!(
            parse_object_entry(&hex[..2], &entry, &|_| true),
            Some(ObjectName::new(checksum, ObjectType::ComposefsImage))
        );
        assert_eq!(
            parse_object_entry(&hex[..2], &entry, &|ty| ty != ObjectType::ComposefsImage),
            None
        );
        let type_str = format!("{}.composefs-image", &hex[2..]);
        assert_eq!(parse_object_entry(&hex[..2], &type_str, &|_| true), None);
    }

    /// A store in memory that records its reads in order and counts the
    /// reads in flight. Each read yields once before it ends, so the reads
    /// of a walk overlap.
    struct Counted {
        objects: HashMap<ObjectName, Vec<u8>>,
        limit: usize,
        reads: std::sync::Mutex<Vec<ObjectName>>,
        in_flight: AtomicUsize,
        high_water: AtomicUsize,
    }

    impl Counted {
        fn new(objects: HashMap<ObjectName, Vec<u8>>, limit: usize) -> Counted {
            Counted {
                objects,
                limit,
                reads: Default::default(),
                in_flight: AtomicUsize::new(0),
                high_water: AtomicUsize::new(0),
            }
        }
    }

    impl MetadataSource for Counted {
        async fn load_metadata(
            &self,
            ty: ObjectType,
            checksum: Checksum,
        ) -> Result<Option<Vec<u8>>> {
            let name = ObjectName::new(checksum, ty);
            self.reads.lock().unwrap().push(name);
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.high_water.fetch_max(now, Ordering::SeqCst);
            futures_lite::future::yield_now().await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(self.objects.get(&name).cloned())
        }

        fn max_reads(&self) -> usize {
            self.limit
        }
    }

    /// Adds the dirtree of `tree` to `objects` and `expected`, and returns
    /// its checksum.
    fn put_dirtree(
        objects: &mut HashMap<ObjectName, Vec<u8>>,
        expected: &mut HashSet<ObjectName>,
        tree: &ostrya_core::DirTree,
    ) -> Checksum {
        let bytes = tree.serialize().unwrap();
        let checksum = Checksum::sha256(&bytes);
        let name = ObjectName::new(checksum, ObjectType::DirTree);
        objects.insert(name, bytes);
        expected.insert(name);
        checksum
    }

    /// Returns the objects of one commit, the commit, and the names that
    /// the commit reaches. The root directory holds 12 directories, and each
    /// of these holds 3 directories with one file of its own. So the tree
    /// holds 49 dirtrees.
    fn wide_tree() -> (HashMap<ObjectName, Vec<u8>>, Checksum, HashSet<ObjectName>) {
        let mut objects = HashMap::new();
        let mut expected = HashSet::new();
        let dirmeta = Checksum::sha256(b"dirmeta");
        expected.insert(ObjectName::new(dirmeta, ObjectType::DirMeta));
        let mut root = ostrya_core::DirTree::default();
        for outer in 0..12 {
            let mut middle = ostrya_core::DirTree::default();
            for inner in 0..3 {
                let file = Checksum::sha256(format!("file {outer} {inner}").as_bytes());
                expected.insert(ObjectName::new(file, ObjectType::File));
                let leaf = ostrya_core::DirTree {
                    files: vec![("f".to_owned(), file)],
                    dirs: Vec::new(),
                };
                let leaf = put_dirtree(&mut objects, &mut expected, &leaf);
                middle.dirs.push((format!("e{inner}"), leaf, dirmeta));
            }
            let middle = put_dirtree(&mut objects, &mut expected, &middle);
            root.dirs.push((format!("d{outer:02}"), middle, dirmeta));
        }
        let root = put_dirtree(&mut objects, &mut expected, &root);
        let commit = Commit {
            metadata: Value::Array(Vec::new()),
            parent: None,
            related: Vec::new(),
            subject: String::new(),
            body: String::new(),
            timestamp: 0,
            root_dirtree: root,
            root_dirmeta: dirmeta,
        };
        let bytes = commit.serialize().unwrap();
        let checksum = Checksum::sha256(&bytes);
        let name = ObjectName::new(checksum, ObjectType::Commit);
        objects.insert(name, bytes);
        expected.insert(name);
        (objects, checksum, expected)
    }

    /// The walk of one tree has at most the limit of the store in flight,
    /// and the reads overlap when the limit allows it. Each limit gives the
    /// same set and reads each object once. With a limit of one, the walk
    /// reads the dirtrees in depth-first order.
    #[test]
    fn a_tree_walk_runs_at_most_the_limit_of_reads_at_a_time() {
        let (objects, commit, expected) = wide_tree();
        let commit_name = ObjectName::new(commit, ObjectType::Commit);
        let mut depth_first = vec![commit_name];
        let mut stack = vec![Commit::parse(&objects[&commit_name]).unwrap().root_dirtree];
        while let Some(dirtree) = stack.pop() {
            let name = ObjectName::new(dirtree, ObjectType::DirTree);
            depth_first.push(name);
            let parsed = ostrya_core::DirTree::parse(&objects[&name]).unwrap();
            stack.extend(parsed.dirs.iter().map(|(_, subtree, _)| *subtree));
        }
        for limit in [1, 4, 8] {
            let store = Counted::new(objects.clone(), limit);
            let reached = ostrya_rt::block_on(walk_reachable(&store, [commit], 0)).unwrap();
            assert_eq!(reached, expected, "limit {limit}");
            let reads = store.reads.lock().unwrap();
            let once: HashSet<ObjectName> = reads.iter().copied().collect();
            assert_eq!(reads.len(), objects.len(), "limit {limit}");
            assert_eq!(once.len(), objects.len(), "limit {limit}");
            let high_water = store.high_water.load(Ordering::SeqCst);
            if limit == 1 {
                assert_eq!(*reads, depth_first);
                assert_eq!(high_water, 1);
            } else {
                assert!(
                    high_water > 1 && high_water <= limit,
                    "limit {limit}: {high_water}"
                );
            }
        }
    }

    /// A dirtree that does not parse gives the same error at each limit.
    #[test]
    fn a_dirtree_that_does_not_parse_fails_the_walk_at_each_limit() {
        let (mut objects, commit, _) = wide_tree();
        let root = Commit::parse(&objects[&ObjectName::new(commit, ObjectType::Commit)])
            .unwrap()
            .root_dirtree;
        let root =
            ostrya_core::DirTree::parse(&objects[&ObjectName::new(root, ObjectType::DirTree)])
                .unwrap();
        let (_, sibling, _) = root.dirs[5];
        objects.insert(
            ObjectName::new(sibling, ObjectType::DirTree),
            b"not a dirtree".to_vec(),
        );
        let errors: Vec<String> = [1, 4]
            .into_iter()
            .map(|limit| {
                let store = Counted::new(objects.clone(), limit);
                let err = ostrya_rt::block_on(walk_reachable(&store, [commit], 0)).unwrap_err();
                assert!(matches!(err, Error::Core(_)), "limit {limit}: {err}");
                err.to_string()
            })
            .collect();
        assert_eq!(errors[0], errors[1]);
    }
}
