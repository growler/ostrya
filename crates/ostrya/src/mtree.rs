//! In-memory mutable trees and their serialization to dirtree objects.
//!
//! A [`MutableTree`] is a directory under construction: a name-keyed set of
//! files (each a content checksum) and subdirectories (each a nested tree),
//! plus the dirmeta checksum for the directory itself. Building a tree in
//! memory and then calling [`Transaction::write_mtree`] serializes the dirty
//! subtrees into `(a(say)a(sayay))` dirtree objects and stages them, yielding
//! the root as a [`RepoTree`].
//!
//! Lazy hydration. [`MutableTree::from_commit`] reads only the root dirtree and
//! records the checksums of each subdirectory. A subdirectory's contents are
//! read when [`ensure_dir`](MutableTree::ensure_dir) first descends into it,
//! so editing one path in a large commit reads only the directories along that
//! path. Descending is `async` because it may read a dirtree; the other
//! mutators operate on already-hydrated contents and stay synchronous.
//!
//! Dirty tracking. A subtree that matches a committed dirtree and has not been
//! mutated keeps that dirtree checksum, and [`write_mtree`](Transaction::write_mtree)
//! reuses it without re-serializing or re-staging anything beneath it. A
//! subtree that has been mutated, or that has a descended (loaded) child, is
//! reassembled; identical reassembled bytes deduplicate against the store.
//!
//! Names are validated on insertion (non-empty, not `.` or `..`, no `/`) and
//! one name cannot be both a file and a directory, matching the owned-parse
//! rule the dirtree object model enforces.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use ostrya_core::{Checksum, DirTree, ObjectType};

use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::transaction::Transaction;
use crate::tree::RepoTree;

/// A directory being assembled in memory.
///
/// Files map a name to a content checksum; subdirectories map a name to a
/// [`Child`], which is either a lazy reference to a committed dirtree or a
/// materialized nested tree. `clean` holds the committed dirtree checksum while
/// this directory exactly matches a committed dirtree and has not been mutated;
/// it is cleared on mutation and set again once the directory is written.
#[derive(Debug)]
pub struct MutableTree {
    /// The dirmeta checksum for this directory, set with
    /// [`set_metadata_checksum`](MutableTree::set_metadata_checksum). Required
    /// by [`write_mtree`](Transaction::write_mtree) for every directory it
    /// emits.
    metadata_checksum: Option<Checksum>,
    /// Files by name, in byte-wise name order (the `BTreeMap` key order).
    files: BTreeMap<String, Checksum>,
    /// Subdirectories by name, in byte-wise name order.
    dirs: BTreeMap<String, Child>,
    /// The committed dirtree checksum when this directory is unmutated since
    /// load; `None` for a from-scratch or mutated directory.
    clean: Option<Checksum>,
    /// The repository lazy children are hydrated from; `None` for a
    /// from-scratch tree, which has no lazy children.
    repo: Option<Repo>,
}

/// A subdirectory entry: a committed dirtree not yet read, or a loaded tree.
#[derive(Debug)]
enum Child {
    /// A committed subdirectory whose contents have not been read. The
    /// checksums name its dirtree and dirmeta objects.
    Lazy {
        dirtree: Checksum,
        dirmeta: Checksum,
    },
    /// A materialized subtree.
    Loaded(MutableTree),
}

/// What a directory holds at a given name, for the staging-tree path walker.
pub(crate) enum ChildKind {
    /// No entry with that name.
    Absent,
    /// A file or symlink, named by its content checksum.
    File(Checksum),
    /// A materialized (loaded) subdirectory.
    Dir,
    /// A committed subdirectory not yet read; hydrate before descending.
    LazyDir {
        /// The subdirectory's dirtree checksum.
        dirtree: Checksum,
        /// The subdirectory's dirmeta checksum.
        dirmeta: Checksum,
    },
}

/// A borrowed view of a subdirectory entry, for reading a tree without mutating
/// it (the right side of a [`merge`](crate::StagingTree::merge)).
pub(crate) enum ChildRef<'a> {
    /// A materialized subtree, borrowed in place.
    Loaded(&'a MutableTree),
    /// A committed subtree named by its dirtree and dirmeta checksums.
    Lazy {
        /// The subdirectory's dirtree checksum.
        dirtree: Checksum,
        /// The subdirectory's dirmeta checksum.
        dirmeta: Checksum,
    },
}

/// The checksums a written directory contributes to its parent's dirtree entry.
struct Emitted {
    dirtree: Checksum,
    dirmeta: Checksum,
}

/// Validate one entry name as a single path component.
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
    /// An empty tree with no dirmeta checksum set.
    pub fn new() -> MutableTree {
        MutableTree {
            metadata_checksum: None,
            files: BTreeMap::new(),
            dirs: BTreeMap::new(),
            clean: None,
            repo: None,
        }
    }

    /// Build a tree from a committed revision, reading only the root dirtree.
    /// Subdirectories are recorded lazily and read on first descent.
    pub async fn from_commit(repo: &Repo, rev: &str) -> Result<MutableTree> {
        let checksum = repo
            .resolve_rev(rev, true)
            .await?
            .ok_or_else(|| Error::RefNotFound(rev.to_owned()))?;
        let (commit, _) = repo.load_commit(&checksum).await?;
        MutableTree::hydrate(repo, commit.root_dirtree, commit.root_dirmeta).await
    }

    /// Read one committed dirtree into a loaded tree; its subdirectories become
    /// lazy children carrying the same repository handle.
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

    /// Set this directory's dirmeta checksum. The directory's own dirtree does
    /// not include its dirmeta, so `clean` stays valid; the parent picks up the
    /// new dirmeta when it reassembles.
    pub fn set_metadata_checksum(&mut self, checksum: Checksum) {
        self.metadata_checksum = Some(checksum);
    }

    /// Ensure a subdirectory named `name` exists and return it, creating an
    /// empty one if absent or hydrating a lazy committed one. Fails if a file
    /// with that name exists.
    pub async fn ensure_dir(&mut self, name: &str) -> Result<&mut MutableTree> {
        validate_name(name)?;
        if self.files.contains_key(name) {
            return Err(Error::MutableTree(format!(
                "cannot create directory {name:?}: a file with that name exists"
            )));
        }
        match self.dirs.get(name) {
            None => {
                let child = MutableTree {
                    metadata_checksum: None,
                    files: BTreeMap::new(),
                    dirs: BTreeMap::new(),
                    clean: None,
                    repo: self.repo.clone(),
                };
                self.dirs.insert(name.to_owned(), Child::Loaded(child));
                // Adding a subdirectory changes this directory's dirtree.
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
                // Descending does not change this directory's dirtree, so
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

    /// Set the file named `name` to the given content checksum, replacing any
    /// existing file of that name. Fails if a directory with that name exists.
    pub fn replace_file(&mut self, name: &str, checksum: Checksum) -> Result<()> {
        validate_name(name)?;
        if self.dirs.contains_key(name) {
            return Err(Error::MutableTree(format!(
                "cannot set file {name:?}: a directory with that name exists"
            )));
        }
        self.files.insert(name.to_owned(), checksum);
        self.clean = None;
        Ok(())
    }

    /// The content checksum recorded for the file (or symlink) entry `name`, if
    /// one is present. A directory entry of that name yields `None`. Used by the
    /// overlay merge to detect a base leaf an upper directory must replace.
    pub(crate) fn file_checksum(&self, name: &str) -> Option<Checksum> {
        self.files.get(name).copied()
    }

    /// Remove every file and subdirectory, marking the directory dirty. Used by
    /// the overlay merge to clear an opaque directory before ingesting the
    /// upper entries fresh.
    pub(crate) fn clear_children(&mut self) {
        if !self.files.is_empty() || !self.dirs.is_empty() {
            self.files.clear();
            self.dirs.clear();
            self.clean = None;
        }
    }

    /// Remove the file or subdirectory named `name`. With `allow_noent`, an
    /// absent entry is not an error.
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

    /// This directory's dirmeta checksum, if set.
    pub(crate) fn metadata_checksum(&self) -> Option<Checksum> {
        self.metadata_checksum
    }

    /// The repository this tree hydrates lazy children from, if any.
    pub(crate) fn repo(&self) -> Option<Repo> {
        self.repo.clone()
    }

    /// What this directory holds at `name`, for the staging-tree path walker.
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

    /// Navigate to the loaded directory at the literal component `path`, or
    /// `None` if any component is missing or is not a loaded directory. Lazy
    /// children must be hydrated by the caller before they can be traversed.
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

    /// The mutable counterpart of [`dir_at`](MutableTree::dir_at).
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

    /// Replace a lazy child `name` with its hydrated subtree. The directory's
    /// own dirtree is unchanged, so `clean` stays as it was.
    pub(crate) fn install_hydrated_child(&mut self, name: &str, loaded: MutableTree) {
        self.dirs.insert(name.to_owned(), Child::Loaded(loaded));
    }

    /// Insert a fresh empty loaded subdirectory named `name` with the given
    /// dirmeta checksum, replacing any existing entry of that name. Marks this
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

    /// The file entries of this directory, byte-wise name-sorted.
    pub(crate) fn file_entries(&self) -> impl Iterator<Item = (&str, Checksum)> {
        self.files
            .iter()
            .map(|(name, checksum)| (name.as_str(), *checksum))
    }

    /// The subdirectory entries of this directory as borrowed views, byte-wise
    /// name-sorted.
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

impl Transaction {
    /// Serialize the dirty subtrees of `mtree` into dirtree objects, stage
    /// them, and return the root as a [`RepoTree`].
    ///
    /// The walk is post-order over dirty subtrees. An unmutated subtree keeps
    /// its committed dirtree checksum and is neither re-serialized nor
    /// re-staged. Each written directory requires its dirmeta checksum set;
    /// an unset checksum is an error naming the directory's path.
    pub async fn write_mtree(&self, mtree: &mut MutableTree) -> Result<RepoTree> {
        let emitted = write_node(self, mtree, "/".to_owned()).await?;
        Ok(RepoTree::from_parts(
            self.repo().clone(),
            emitted.dirtree,
            emitted.dirmeta,
        ))
    }
}

/// The boxed future type for the recursive post-order walk. Async recursion
/// needs indirection, so each level returns a boxed future.
type NodeFuture<'a> = Pin<Box<dyn Future<Output = Result<Emitted>> + Send + 'a>>;

/// Resolve one directory node: reuse its dirtree checksum when clean, otherwise
/// assemble and stage a dirtree from its files and children.
fn write_node<'a>(txn: &'a Transaction, node: &'a mut MutableTree, path: String) -> NodeFuture<'a> {
    Box::pin(async move {
        let dirmeta = node.metadata_checksum.ok_or_else(|| {
            Error::MutableTree(format!("directory {path} has no dirmeta checksum set"))
        })?;

        // A directory with no descended children and an intact committed
        // checksum is reused untouched; nothing beneath it is read or staged.
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

/// Join a parent path and a child name for error messages.
fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// A mutable tree moves freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MutableTree>();
};
