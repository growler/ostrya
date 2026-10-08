//! Directory trees built in memory and written as dirtree objects.
//!
//! A [`MutableTree`] holds the entries of one directory and its nested
//! subdirectories. [`MutableTree::new`] creates an empty tree.
//! [`MutableTree::from_commit`] creates a tree from the root of a commit.
//!
//! [`Transaction::write_mtree`] writes the changed subtrees as dirtree
//! objects, stages them, and returns the root as a [`RepoTree`].

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use ostrya_core::{Checksum, DirTree, ObjectType};

use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::transaction::Transaction;
use crate::tree::RepoTree;

/// A directory that a caller builds in memory.
///
/// A tree holds these items:
///
/// - files, each a name and a content checksum. A symlink is a file entry.
/// - subdirectories, each a name and a nested tree.
/// - the dirmeta checksum of the directory itself.
///
/// A name is a file or a subdirectory, never both. The methods that insert an
/// entry check that each name is not empty, is not `.` or `..`, and holds no
/// `/`. They do not check for a NUL byte. [`write_mtree`](Transaction::write_mtree)
/// checks each name against the [rules](crate::DirTree#rules) of a dirtree
/// object.
///
/// # Lazy hydration
///
/// [`from_commit`](MutableTree::from_commit) reads only the root dirtree. It
/// records the dirtree and dirmeta checksums of each subdirectory. The tree
/// reads a subdirectory when [`ensure_dir`](MutableTree::ensure_dir) or
/// [`subtree`](MutableTree::subtree) first descends into it. A walk to one
/// path in a large commit reads only the directories on that path.
///
/// A descent is `async` because it can read a dirtree. The other methods
/// change entries that the tree holds already, and they are synchronous.
///
/// # Dirty tracking
///
/// A subtree that matches a committed dirtree and has no change keeps the
/// checksum of that dirtree. [`write_mtree`](Transaction::write_mtree) reuses
/// this checksum. It serializes and stages nothing for that subtree or for
/// the entries under it.
///
/// `write_mtree` writes a new dirtree for a subtree in these cases:
///
/// - The subtree has a change.
/// - A child of the subtree is loaded, because a descent read it.
///
/// If the new bytes are equal to a dirtree in the object store, the new
/// dirtree has the same checksum. The store keeps one copy.
#[derive(Debug)]
pub struct MutableTree {
    /// The dirmeta checksum of this directory, set with
    /// [`set_metadata_checksum`](MutableTree::set_metadata_checksum).
    /// [`write_mtree`](Transaction::write_mtree) requires it on each directory
    /// that it writes.
    metadata_checksum: Option<Checksum>,
    /// The files by name, in byte-wise name order (the `BTreeMap` key order).
    files: BTreeMap<String, Checksum>,
    /// The subdirectories by name, in byte-wise name order.
    dirs: BTreeMap<String, Child>,
    /// The committed dirtree checksum while this directory has no change since
    /// the load. `None` for a new or a changed directory. A change clears it,
    /// and a write of the directory sets it again.
    clean: Option<Checksum>,
    /// The repository that lazy children are read from. `None` for a tree
    /// that `new` created, which has no lazy children.
    repo: Option<Repo>,
}

/// A subdirectory entry: a committed dirtree that is not read yet, or a loaded
/// tree.
#[derive(Debug)]
enum Child {
    /// A committed subdirectory whose contents are not read yet. The checksums
    /// name its dirtree and dirmeta objects.
    Lazy {
        dirtree: Checksum,
        dirmeta: Checksum,
    },
    /// A loaded subtree.
    Loaded(MutableTree),
}

/// The entry that a directory holds at a name, for the path walker of the
/// staging tree.
pub(crate) enum ChildKind {
    /// No entry with that name.
    Absent,
    /// A file or a symlink, named by its content checksum.
    File(Checksum),
    /// A loaded subdirectory.
    Dir,
    /// A committed subdirectory that is not read yet. The walker hydrates it
    /// before a descent.
    LazyDir {
        /// The dirtree checksum of the subdirectory.
        dirtree: Checksum,
        /// The dirmeta checksum of the subdirectory.
        dirmeta: Checksum,
    },
}

/// A borrowed view of a subdirectory entry, for a read of a tree with no change
/// to it (the right side of a [`merge`](crate::StagingTree::merge)).
pub(crate) enum ChildRef<'a> {
    /// A loaded subtree, borrowed in place.
    Loaded(&'a MutableTree),
    /// A committed subtree named by its dirtree and dirmeta checksums.
    Lazy {
        /// The dirtree checksum of the subdirectory.
        dirtree: Checksum,
        /// The dirmeta checksum of the subdirectory.
        dirmeta: Checksum,
    },
}

/// An entry that [`take_child`](MutableTree::take_child) took out of one
/// directory, for [`insert_child`](MutableTree::insert_child) to put under
/// another name. The node does not change, so a lazy subdirectory stays lazy.
pub(crate) struct TakenEntry {
    inner: TakenInner,
}

/// The taken node: the checksum of a file entry, or a subdirectory.
enum TakenInner {
    File(Checksum),
    Dir(Child),
}

/// The mode of a descent. It selects the result for a name that the directory
/// does not hold, and the variant for a file of that name.
enum Absent {
    /// Insert an empty subdirectory of that name and return it. A file of that
    /// name gives [`Error::ReplaceFileWithDir`].
    Create,
    /// Refuse that name with [`Error::PathNotFound`]. A file of that name
    /// gives [`Error::NotADirectory`].
    Refuse,
}

/// The checksums that a written directory gives to the dirtree entry of its
/// parent.
struct Emitted {
    dirtree: Checksum,
    dirmeta: Checksum,
}

/// Checks that one entry name is a single path component.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::MutableTree("entry name is empty".into()));
    }
    if name == "." || name == ".." {
        return Err(Error::MutableTree(format!(
            "entry name {name:?} is a directory traversal"
        )));
    }
    if name.contains('/') {
        return Err(Error::MutableTree(format!(
            "entry name {name:?} contains a slash"
        )));
    }
    Ok(())
}

impl MutableTree {
    /// Creates an empty tree with no dirmeta checksum.
    pub fn new() -> MutableTree {
        MutableTree {
            metadata_checksum: None,
            files: BTreeMap::new(),
            dirs: BTreeMap::new(),
            clean: None,
            repo: None,
        }
    }

    /// Creates a tree from the root of a commit and reads only the root dirtree.
    ///
    /// `rev` is a revision in the syntax of
    /// [`Repo::resolve_rev`](crate::Repo::resolve_rev). The root of the tree
    /// takes the dirmeta checksum of the commit root. The tree reads each
    /// subdirectory on the first descent, as
    /// [`MutableTree`](MutableTree#lazy-hydration) states.
    ///
    /// # Errors
    ///
    /// - [`Error::RefNotFound`] if `rev` names no ref and no commit.
    /// - [`Error::InvalidRefspec`] if `rev` is not a checksum and not a valid
    ///   refspec.
    /// - [`Error::AmbiguousRefspec`] if more than one commit checksum starts
    ///   with the abbreviated checksum in `rev`.
    /// - [`Error::NoParentCommit`] if a `^` in `rev` steps back from a commit
    ///   with no parent.
    /// - [`Error::ObjectNotFound`] if the commit, a commit that a `^` step
    ///   reads, or the root dirtree is not in the repository.
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8.
    /// - [`Error::Core`] if a ref file holds no checksum, or if the commit or
    ///   the root dirtree does not parse.
    /// - [`Error::Io`] if a read from the file system fails, or if an object is
    ///   larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    pub async fn from_commit(repo: &Repo, rev: &str) -> Result<MutableTree> {
        let checksum = repo
            .resolve_rev(rev, true)
            .await?
            .ok_or_else(|| Error::RefNotFound(rev.to_owned()))?;
        let (commit, _) = repo.load_commit(&checksum).await?;
        MutableTree::hydrate(repo, commit.root_dirtree, commit.root_dirmeta).await
    }

    /// Reads one committed dirtree into a loaded tree. Its subdirectories
    /// become lazy children that hold the same repository handle.
    pub(crate) async fn hydrate(
        repo: &Repo,
        dirtree: Checksum,
        dirmeta: Checksum,
    ) -> Result<MutableTree> {
        let loaded = repo.load_dirtree(&dirtree).await?;
        let mut files = BTreeMap::new();
        for (name, csum) in loaded.files {
            files.insert(name, csum);
        }
        let mut dirs = BTreeMap::new();
        for (name, child_dirtree, child_dirmeta) in loaded.dirs {
            dirs.insert(
                name,
                Child::Lazy {
                    dirtree: child_dirtree,
                    dirmeta: child_dirmeta,
                },
            );
        }
        Ok(MutableTree {
            metadata_checksum: Some(dirmeta),
            files,
            dirs,
            clean: Some(dirtree),
            repo: Some(repo.clone()),
        })
    }

    /// Sets the dirmeta checksum of this directory.
    ///
    /// The dirtree of a directory does not hold its own dirmeta checksum, so
    /// this call does not count as a change of the directory. The dirtree of
    /// the parent holds it. [`write_mtree`](Transaction::write_mtree) writes
    /// the new value into the parent when it writes the parent.
    pub fn set_metadata_checksum(&mut self, checksum: Checksum) {
        self.metadata_checksum = Some(checksum);
    }

    /// Returns the subdirectory `name`, and creates an empty one if it is
    /// absent.
    ///
    /// If the subdirectory is a committed child that is not read yet, the call
    /// reads its dirtree first. A new subdirectory has no dirmeta checksum, and
    /// it counts as a change of this directory.
    ///
    /// # Errors
    ///
    /// - [`Error::MutableTree`] if `name` is empty, is `.` or `..`, or holds a
    ///   `/`.
    /// - [`Error::ReplaceFileWithDir`] if a file of that name exists. The
    ///   payload is `name`.
    /// - [`Error::ObjectNotFound`] if the dirtree of the committed child is not
    ///   in the repository.
    /// - [`Error::Core`] if the dirtree of the committed child does not parse.
    /// - [`Error::Io`] if the read of that dirtree fails, or if the dirtree is
    ///   larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    pub async fn ensure_dir(&mut self, name: &str) -> Result<&mut MutableTree> {
        self.descend(name, Absent::Create).await
    }

    /// Returns the existing subdirectory `name`, and creates nothing.
    ///
    /// If the subdirectory is a committed child that is not read yet, the call
    /// reads its dirtree first.
    ///
    /// A symlink is a file entry in this tree. A symlink to a directory gives
    /// [`Error::NotADirectory`] too, because the call resolves one name in one
    /// directory and reads no symlink target.
    ///
    /// The payload of [`Error::NotADirectory`] and of [`Error::PathNotFound`]
    /// is `name` alone, because a tree holds no path. The staging tree puts one
    /// entry name in [`Error::ReplaceDirWithFile`] in the same way.
    ///
    /// # Errors
    ///
    /// - [`Error::MutableTree`] if `name` is empty, is `.` or `..`, or holds a
    ///   `/`.
    /// - [`Error::NotADirectory`] if a file or a symlink of that name exists.
    /// - [`Error::PathNotFound`] if no entry of that name exists.
    /// - [`Error::ObjectNotFound`] if the dirtree of the committed child is not
    ///   in the repository.
    /// - [`Error::Core`] if the dirtree of the committed child does not parse.
    /// - [`Error::Io`] if the read of that dirtree fails, or if the dirtree is
    ///   larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    pub async fn subtree(&mut self, name: &str) -> Result<&mut MutableTree> {
        self.descend(name, Absent::Refuse).await
    }

    /// Returns the subdirectory `name`, and reads a committed child that is not
    /// read yet in place. `absent` selects the result for an absent name, and
    /// the variant for a file of that name.
    async fn descend(&mut self, name: &str, absent: Absent) -> Result<&mut MutableTree> {
        validate_name(name)?;
        if self.files.contains_key(name) {
            return Err(match absent {
                Absent::Create => Error::ReplaceFileWithDir(name.to_owned()),
                Absent::Refuse => Error::NotADirectory {
                    path: name.to_owned(),
                },
            });
        }
        match self.dirs.get(name) {
            None => {
                if matches!(absent, Absent::Refuse) {
                    return Err(Error::PathNotFound {
                        path: name.to_owned(),
                    });
                }
                let child = MutableTree {
                    metadata_checksum: None,
                    files: BTreeMap::new(),
                    dirs: BTreeMap::new(),
                    clean: None,
                    repo: self.repo.clone(),
                };
                self.dirs.insert(name.to_owned(), Child::Loaded(child));
                // A new subdirectory changes the dirtree of this directory.
                self.clean = None;
            }
            Some(Child::Lazy { dirtree, dirmeta }) => {
                let (dirtree, dirmeta) = (*dirtree, *dirmeta);
                let repo = self.repo.clone().ok_or_else(|| {
                    Error::MutableTree(format!(
                        "cannot read subdirectory {name:?}: no repository to hydrate from"
                    ))
                })?;
                let loaded = MutableTree::hydrate(&repo, dirtree, dirmeta).await?;
                self.dirs.insert(name.to_owned(), Child::Loaded(loaded));
                // A descent does not change the dirtree of this directory, so
                // `clean` stays as it was.
            }
            Some(Child::Loaded(_)) => {}
        }
        match self.dirs.get_mut(name) {
            Some(Child::Loaded(tree)) => Ok(tree),
            _ => Err(Error::MutableTree(format!(
                "subdirectory {name:?} was not materialized"
            ))),
        }
    }

    /// Sets the file `name` to a content checksum.
    ///
    /// If a file of that name exists, the call replaces it. The call counts as
    /// a change of this directory.
    ///
    /// # Errors
    ///
    /// - [`Error::MutableTree`] if `name` is empty, is `.` or `..`, or holds a
    ///   `/`.
    /// - [`Error::ReplaceDirWithFile`] if a subdirectory of that name exists.
    ///   The payload is `name`.
    pub fn replace_file(&mut self, name: &str, checksum: Checksum) -> Result<()> {
        validate_name(name)?;
        if self.dirs.contains_key(name) {
            return Err(Error::ReplaceDirWithFile(name.to_owned()));
        }
        self.files.insert(name.to_owned(), checksum);
        self.clean = None;
        Ok(())
    }

    /// Returns the content checksum of the file or symlink entry `name`, if one
    /// is present. A directory entry of that name gives `None`. The overlay
    /// merge uses it to find a base leaf that an upper directory must replace.
    pub(crate) fn file_checksum(&self, name: &str) -> Option<Checksum> {
        self.files.get(name).copied()
    }

    /// Removes every file and subdirectory, and marks the directory dirty. The
    /// overlay merge uses it to clear an opaque directory before it reads the
    /// upper entries.
    pub(crate) fn clear_children(&mut self) {
        if !self.files.is_empty() || !self.dirs.is_empty() {
            self.files.clear();
            self.dirs.clear();
            self.clean = None;
        }
    }

    /// Takes the file or subdirectory `name` out of this directory, for
    /// [`insert_child`](MutableTree::insert_child) to put under another name.
    ///
    /// The call marks this directory dirty. The taken node does not change, so
    /// a moved subtree keeps its own `clean` state and a lazy child stays lazy.
    /// An absent name gives `None`.
    pub(crate) fn take_child(&mut self, name: &str) -> Option<TakenEntry> {
        let inner = if let Some(checksum) = self.files.remove(name) {
            TakenInner::File(checksum)
        } else if let Some(child) = self.dirs.remove(name) {
            TakenInner::Dir(child)
        } else {
            return None;
        };
        self.clean = None;
        Some(TakenEntry { inner })
    }

    /// Inserts a taken entry under `name`, and marks this directory dirty.
    ///
    /// The call refuses a name that an entry holds already. This keeps the
    /// rule of one entry for each name that every other mutator keeps.
    ///
    /// A moved lazy child reads its dirtree through the repository handle of
    /// this directory. Every directory takes that handle from its parent. A
    /// lazy child exists only under a tree that
    /// [`hydrate`](MutableTree::hydrate) built, so a directory that can
    /// receive one always holds a handle.
    pub(crate) fn insert_child(&mut self, name: &str, entry: TakenEntry) -> Result<()> {
        validate_name(name)?;
        if self.files.contains_key(name) || self.dirs.contains_key(name) {
            return Err(Error::MutableTree(format!(
                "an entry named {name:?} already exists"
            )));
        }
        match entry.inner {
            TakenInner::File(checksum) => {
                self.files.insert(name.to_owned(), checksum);
            }
            TakenInner::Dir(child) => {
                self.dirs.insert(name.to_owned(), child);
            }
        }
        self.clean = None;
        Ok(())
    }

    /// Removes the file or the subdirectory `name`.
    ///
    /// If `allow_noent` is `true`, an absent entry is not an error. The call
    /// does not check the form of `name`, so an invalid name matches no entry.
    /// A removal counts as a change of this directory.
    ///
    /// # Errors
    ///
    /// [`Error::MutableTree`] if no entry of that name exists and
    /// `allow_noent` is `false`.
    pub fn remove(&mut self, name: &str, allow_noent: bool) -> Result<()> {
        let removed = self.files.remove(name).is_some() || self.dirs.remove(name).is_some();
        if removed {
            self.clean = None;
        } else if !allow_noent {
            return Err(Error::MutableTree(format!(
                "no entry named {name:?} to remove"
            )));
        }
        Ok(())
    }

    /// Returns the dirmeta checksum of this directory, if it is set.
    ///
    /// [`write_mtree`](Transaction::write_mtree) cannot write a root with no
    /// dirmeta checksum. A caller can call this method before `write_mtree` to
    /// find a tree whose sources set no root dirmeta.
    pub fn metadata_checksum(&self) -> Option<Checksum> {
        self.metadata_checksum
    }

    /// Records a committed subdirectory at `name` and does not read it.
    ///
    /// The overlay reads only the paths that a later source names. If a later
    /// source descends into the child, the tree reads the child from `repo`.
    ///
    /// The call refuses a name that this tree holds as a file, as every other
    /// mutator does.
    pub(crate) fn insert_lazy_dir(
        &mut self,
        name: &str,
        dirtree: Checksum,
        dirmeta: Checksum,
        repo: &Repo,
    ) -> Result<()> {
        validate_name(name)?;
        if self.files.contains_key(name) {
            return Err(Error::ReplaceFileWithDir(name.to_owned()));
        }
        if self.repo.is_none() {
            self.repo = Some(repo.clone());
        }
        self.dirs
            .insert(name.to_owned(), Child::Lazy { dirtree, dirmeta });
        self.clean = None;
        Ok(())
    }

    /// Returns the repository that this tree reads lazy children from, if any.
    pub(crate) fn repo(&self) -> Option<Repo> {
        self.repo.clone()
    }

    /// Returns the entry that this directory holds at `name`, for the path
    /// walker of the staging tree.
    pub(crate) fn child_kind(&self, name: &str) -> ChildKind {
        if let Some(checksum) = self.files.get(name) {
            return ChildKind::File(*checksum);
        }
        match self.dirs.get(name) {
            Some(Child::Loaded(_)) => ChildKind::Dir,
            Some(Child::Lazy { dirtree, dirmeta }) => ChildKind::LazyDir {
                dirtree: *dirtree,
                dirmeta: *dirmeta,
            },
            None => ChildKind::Absent,
        }
    }

    /// Returns the loaded directory at the literal components of `path`.
    ///
    /// The result is `None` if a component is absent or is not a loaded
    /// directory. The caller must hydrate lazy children before this walk can
    /// pass through them.
    pub(crate) fn dir_at(&self, path: &[String]) -> Option<&MutableTree> {
        let mut cur = self;
        for name in path {
            match cur.dirs.get(name) {
                Some(Child::Loaded(child)) => cur = child,
                _ => return None,
            }
        }
        Some(cur)
    }

    /// Returns the loaded directory at `path` for a change, as
    /// [`dir_at`](MutableTree::dir_at) does for a read.
    pub(crate) fn dir_at_mut(&mut self, path: &[String]) -> Option<&mut MutableTree> {
        let mut cur = self;
        for name in path {
            match cur.dirs.get_mut(name) {
                Some(Child::Loaded(child)) => cur = child,
                _ => return None,
            }
        }
        Some(cur)
    }

    /// Replaces the lazy child `name` with its hydrated subtree. The dirtree of
    /// this directory does not change, so `clean` stays as it was.
    pub(crate) fn install_hydrated_child(&mut self, name: &str, loaded: MutableTree) {
        self.dirs.insert(name.to_owned(), Child::Loaded(loaded));
    }

    /// Sets the dirmeta checksum of the subdirectory `name`, and does not
    /// hydrate a lazy child.
    ///
    /// A loaded child takes the checksum as its own dirmeta checksum. The call
    /// changes the entry of a lazy child in place and keeps its dirtree,
    /// because the contents of the child do not change.
    ///
    /// The dirtree of this directory holds the dirmeta checksum of the child,
    /// so a changed lazy entry marks this directory dirty. A loaded child
    /// already causes a new dirtree for its parent.
    pub(crate) fn set_child_dirmeta(&mut self, name: &str, dirmeta: Checksum) -> Result<()> {
        match self.dirs.get_mut(name) {
            Some(Child::Loaded(child)) => {
                child.metadata_checksum = Some(dirmeta);
                Ok(())
            }
            Some(Child::Lazy { dirmeta: dm, .. }) => {
                if *dm != dirmeta {
                    *dm = dirmeta;
                    self.clean = None;
                }
                Ok(())
            }
            None => Err(Error::MutableTree(format!(
                "no subdirectory named {name:?}"
            ))),
        }
    }

    /// Inserts a new empty loaded subdirectory `name` with the given dirmeta
    /// checksum.
    ///
    /// The call replaces an existing entry of that name, and marks this
    /// directory dirty.
    pub(crate) fn insert_empty_dir(&mut self, name: &str, dirmeta: Option<Checksum>) {
        let child = MutableTree {
            metadata_checksum: dirmeta,
            files: BTreeMap::new(),
            dirs: BTreeMap::new(),
            clean: None,
            repo: self.repo.clone(),
        };
        self.files.remove(name);
        self.dirs.insert(name.to_owned(), Child::Loaded(child));
        self.clean = None;
    }

    /// Returns the file entries of this directory, in byte-wise name order.
    pub(crate) fn file_entries(&self) -> impl Iterator<Item = (&str, Checksum)> {
        self.files
            .iter()
            .map(|(name, checksum)| (name.as_str(), *checksum))
    }

    /// Returns the subdirectory entries of this directory as borrowed views, in
    /// byte-wise name order.
    pub(crate) fn dir_entries(&self) -> impl Iterator<Item = (&str, ChildRef<'_>)> {
        self.dirs.iter().map(|(name, child)| {
            let view = match child {
                Child::Loaded(tree) => ChildRef::Loaded(tree),
                Child::Lazy { dirtree, dirmeta } => ChildRef::Lazy {
                    dirtree: *dirtree,
                    dirmeta: *dirmeta,
                },
            };
            (name.as_str(), view)
        })
    }
}

impl Default for MutableTree {
    fn default() -> MutableTree {
        MutableTree::new()
    }
}

/// Methods that write a mutable tree as dirtree objects.
impl Transaction {
    /// Writes the changed subtrees of `mtree` as dirtree objects.
    ///
    /// The call stages each new dirtree as an object of GVariant type
    /// `(a(say)a(sayay))`, and returns the root as a [`RepoTree`]. The walk is
    /// post-order: it writes the children of a directory before the directory.
    /// A subtree with no change keeps its committed dirtree checksum, and the
    /// call does not serialize or stage it again, as
    /// [`MutableTree`](MutableTree#dirty-tracking) states.
    ///
    /// Each directory that the call writes must have a dirmeta checksum.
    ///
    /// The returned root reads back through this transaction alone, as
    /// [`read_dir`](Transaction::read_dir) states. Before the
    /// transaction commit, [`RepoTree::read_dir`](crate::RepoTree::read_dir)
    /// on a dirtree that this call staged fails with
    /// [`Error::ObjectNotFound`].
    ///
    /// # Errors
    ///
    /// - [`Error::MutableTree`] if a directory that the call writes has no
    ///   dirmeta checksum. The message names the path of the directory, with
    ///   `/` for the root.
    /// - [`Error::Core`] if an entry name holds a NUL byte, or if
    ///   `[core] fsync` or `[core] per-object-fsync` in the repository config
    ///   is malformed.
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`,
    ///   or if `[ex-integrity] fsverity` is `yes` and the fs-verity seal fails.
    /// - [`Error::InsufficientFreeSpace`] if a dirtree needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn write_mtree(&self, mtree: &mut MutableTree) -> Result<RepoTree> {
        let emitted = write_node(self, mtree, "/".to_owned()).await?;
        Ok(RepoTree::from_parts(
            self.repo().clone(),
            emitted.dirtree,
            emitted.dirmeta,
        ))
    }
}

/// The boxed future type of the recursive post-order walk. Async recursion
/// needs indirection, so each level returns a boxed future.
type NodeFuture<'a> = Pin<Box<dyn Future<Output = Result<Emitted>> + Send + 'a>>;

/// Writes one directory node. If the node is clean, the function reuses its
/// dirtree checksum. If not, it builds and stages a dirtree from the files and
/// children of the node.
fn write_node<'a>(txn: &'a Transaction, node: &'a mut MutableTree, path: String) -> NodeFuture<'a> {
    Box::pin(async move {
        let dirmeta = node.metadata_checksum.ok_or_else(|| {
            Error::MutableTree(format!("directory {path} has no dirmeta checksum set"))
        })?;

        // A directory with no loaded children and an intact committed
        // checksum keeps that checksum. The walk reads and stages nothing
        // under it.
        let has_loaded_child = node
            .dirs
            .values()
            .any(|child| matches!(child, Child::Loaded(_)));
        if let Some(dirtree) = node.clean
            && !has_loaded_child
        {
            return Ok(Emitted { dirtree, dirmeta });
        }

        let mut tree = DirTree::default();
        for (name, checksum) in &node.files {
            tree.files.push((name.clone(), *checksum));
        }
        for (name, child) in node.dirs.iter_mut() {
            let emitted = match child {
                Child::Lazy { dirtree, dirmeta } => Emitted {
                    dirtree: *dirtree,
                    dirmeta: *dirmeta,
                },
                Child::Loaded(subtree) => write_node(txn, subtree, join_path(&path, name)).await?,
            };
            tree.dirs
                .push((name.clone(), emitted.dirtree, emitted.dirmeta));
        }

        let bytes = tree.serialize()?;
        let dirtree = txn
            .write_metadata(ObjectType::DirTree, None, &bytes)
            .await?;
        node.clean = Some(dirtree);
        Ok(Emitted { dirtree, dirmeta })
    })
}

/// Joins a parent path and a child name for error messages.
fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// A compile-time check that a mutable tree is `Send + Sync`, so it can move
/// across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MutableTree>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CreateOptions;
    use ostrya_core::RepoMode;
    use ostrya_rt::block_on;

    /// A throwaway directory removed on drop.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("ostrya-mtree-{}-{tag}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `insert_lazy_dir` refuses the names that `replace_file` and
    /// `ensure_dir` refuse, and records nothing for a refused name.
    #[test]
    fn insert_lazy_dir_rejects_invalid_names() {
        let scratch = Scratch::new("lazy-names");
        block_on(async {
            let repo = Repo::create(
                &scratch.0.join("repo"),
                CreateOptions::new(RepoMode::BareUser),
            )
            .await
            .unwrap();
            let some = Checksum::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();

            let mut mtree = MutableTree::new();
            for name in ["", ".", "..", "a/b"] {
                assert!(
                    matches!(
                        mtree.insert_lazy_dir(name, some, some, &repo),
                        Err(Error::MutableTree(_))
                    ),
                    "insert_lazy_dir rejects {name:?}"
                );
            }
            assert!(mtree.dirs.is_empty(), "a refused name records no child");
            assert!(
                mtree.repo.is_none(),
                "a refused name adopts no repository handle"
            );
        });
    }
}
