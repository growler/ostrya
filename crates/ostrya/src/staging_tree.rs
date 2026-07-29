//! Path-addressed tree construction over a transaction (Phase 7f).
//!
//! A [`StagingTree`] builds a directory tree by path rather than by hand-walking
//! a [`MutableTree`](crate::MutableTree). It borrows the transaction it stages
//! into, so `close`, [`write_mtree`](crate::Transaction::write_mtree), commit is
//! the only ordering that compiles. It is a port extension with no `ostree` tool
//! counterpart and no on-disk format impact: every file, symlink, and directory
//! it records flows through the 7a object writers and produces an ordinary 7b
//! tree.
//!
//! Concurrency. The tree sits behind a synchronous mutex held only across the
//! brief map operations that read or mutate its structure. File writes stream
//! outside that lock, so many [`write_file`](StagingTree::write_file) streams
//! progress concurrently through one shared `&StagingTree`; each records its
//! entry under the lock only at [`finish`](StagedFileWriter::finish). The async
//! parts -- hydrating a lazily-loaded committed subdirectory, loading a symlink
//! object during resolution, streaming payloads -- run between lock acquisitions,
//! never across one. [`close`](StagingTree::close) hands back the assembled
//! [`MutableTree`](crate::MutableTree) and fails while any file writer is still
//! outstanding, counted on the tree.
//!
//! Path semantics. Intermediate path components resolve through symlinks; the
//! final component never follows for a write. A relative symlink target resolves
//! from the symlink's parent, an absolute target from the tree root, `..` clamps
//! at the root, chains are capped, and a dangling target is an error. Reads
//! ([`read_file`](StagingTree::read_file), [`read_dir`](StagingTree::read_dir))
//! and [`merge`](StagingTree::merge) take a `follow_symlinks` flag governing the
//! final component; objects load from the transaction's staged set before
//! `objects/`, so content staged in the current transaction is visible before it
//! publishes.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::path::{Component, Path};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures_io::AsyncWrite;
use ostrya_core::{Checksum, Commit, DirMeta};

use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject};
use crate::mtree::{ChildKind, ChildRef, MutableTree};
use crate::transaction::Transaction;
use crate::write::{ContentWriter, FileMeta};

/// The maximum number of symlinks a single path resolution follows before it is
/// treated as a loop.
const MAX_SYMLINK_DEPTH: usize = 40;

/// One meaningful path component: a name, or a parent-directory hop.
#[derive(Clone)]
enum Comp {
    Normal(String),
    Parent,
}

/// Where a path resolution ended.
enum WalkEnd {
    /// A directory at the given literal component path (all loaded directories).
    Dir(Vec<String>),
    /// A file or symlink leaf, with its entry name and content checksum.
    Leaf { name: String, checksum: Checksum },
}

/// Options for [`StagingTree::merge`].
#[derive(Debug, Clone, Copy, Default)]
pub struct MergeOptions {
    /// Take the right side's version on a conflict instead of failing.
    pub allow_overwrite: bool,
    /// Follow left-side symlinks during the merge: a right-side directory over a
    /// left-side symlink merges into the symlink's target directory.
    pub follow_symlinks: bool,
}

/// One entry in a [`read_dir`](StagingTree::read_dir) listing. A directory under
/// construction has no committed checksum, so it carries only its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagingEntry {
    /// A file or symlink, named by its content checksum.
    File {
        /// The entry name.
        name: String,
        /// The content object checksum.
        checksum: Checksum,
    },
    /// A subdirectory; no checksum until it is written.
    Dir {
        /// The entry name.
        name: String,
    },
}

/// Path-addressed construction over a transaction.
///
/// Constructed with [`Transaction::staging_tree`] or
/// [`Transaction::staging_tree_from_mutable_tree`]. `&StagingTree` is
/// `Send + Sync`, so file writes may run concurrently.
///
/// The tree and the outstanding-writer count are `Arc`-shared with the
/// [`StagedFileWriter`]s handed out by [`write_file`](StagingTree::write_file),
/// so a writer does not borrow the tree: [`close`](StagingTree::close) can be
/// called with a writer still live and fails on the count rather than being
/// rejected at compile time.
pub struct StagingTree<'txn> {
    txn: &'txn Transaction,
    tree: Arc<Mutex<MutableTree>>,
    /// Outstanding [`StagedFileWriter`] count; [`close`](StagingTree::close)
    /// fails while it is nonzero.
    writers: Arc<AtomicUsize>,
}

impl Transaction {
    /// A staging tree over this transaction, empty or lazily hydrated from a
    /// commit's root. Hydrating reads the commit's root dirtree, so this departs
    /// from the synchronous API sketch (which is explicitly not final code) the
    /// same way [`MutableTree::ensure_dir`](crate::MutableTree::ensure_dir) does.
    pub async fn staging_tree(&self, source: Option<&Commit>) -> Result<StagingTree<'_>> {
        let tree = match source {
            None => MutableTree::new(),
            Some(commit) => {
                MutableTree::hydrate(self.repo(), commit.root_dirtree, commit.root_dirmeta).await?
            }
        };
        Ok(StagingTree::from_tree(self, tree))
    }

    /// A staging tree over this transaction wrapping an existing mutable tree.
    pub fn staging_tree_from_mutable_tree(&self, source: MutableTree) -> StagingTree<'_> {
        StagingTree::from_tree(self, source)
    }
}

impl<'txn> StagingTree<'txn> {
    fn from_tree(txn: &'txn Transaction, tree: MutableTree) -> StagingTree<'txn> {
        StagingTree {
            txn,
            tree: Arc::new(Mutex::new(tree)),
            writers: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Hand the assembled tree to the caller, for
    /// [`write_mtree`](crate::Transaction::write_mtree). Fails while any
    /// [`write_file`](StagingTree::write_file) writer is still outstanding.
    pub fn close(self) -> Result<MutableTree> {
        let outstanding = self.writers.load(Ordering::Acquire);
        if outstanding != 0 {
            return Err(Error::Staging(format!(
                "cannot close the staging tree: {outstanding} file writer(s) still outstanding"
            )));
        }
        // The counter is authoritative: at zero, every writer has recorded its
        // entry (finish takes the tree lock before it decrements) or was
        // abandoned. A finishing writer may still hold a tree Arc clone for the
        // moment between its decrement and its drop, so take the tree out through
        // the mutex rather than requiring sole Arc ownership. The Acquire load
        // above pairs with the AcqRel decrement in finish, so that writer's
        // replace_file is visible here. mem::take leaves an empty tree behind
        // that is never observed, since the counter guarantees no writer records
        // again.
        let mut guard = self.tree.lock().unwrap();
        Ok(std::mem::take(&mut *guard))
    }

    // --- write operations ---

    /// A streaming writer for one regular-file payload at `path`. The parent
    /// directory must exist (intermediate components resolve through symlinks);
    /// the final component never follows a symlink. Replaces an existing file or
    /// symlink; fails on a directory.
    pub async fn write_file(&self, path: &Path, meta: &FileMeta) -> Result<StagedFileWriter<'txn>> {
        let (parent, name) = self.resolve_parent(path).await?;
        self.check_writable_leaf(path, &parent, &name)?;
        let writer = self.txn.content_writer(None, meta).await?;
        self.writers.fetch_add(1, Ordering::AcqRel);
        Ok(StagedFileWriter {
            tree: self.tree.clone(),
            writers: self.writers.clone(),
            writer: Some(writer),
            parent,
            name,
        })
    }

    /// Write a regular file at `path` whose content the caller already holds.
    pub async fn write_file_content(
        &self,
        path: &Path,
        meta: &FileMeta,
        content: &[u8],
    ) -> Result<()> {
        let (parent, name) = self.resolve_parent(path).await?;
        self.check_writable_leaf(path, &parent, &name)?;
        let checksum = self.txn.write_regfile_inline(None, meta, content).await?;
        self.with_dir_mut(&parent, |dir| dir.replace_file(&name, checksum))
    }

    /// Create the directory `path`, whose parent must exist. Fails on any
    /// existing entry.
    pub async fn make_dir(&self, path: &Path, meta: &DirMeta) -> Result<()> {
        let (parent, name) = self.resolve_parent(path).await?;
        if !matches!(self.peek(&parent, &name)?, ChildKind::Absent) {
            return Err(Error::Staging(format!(
                "cannot create directory {}: an entry already exists there",
                path.display()
            )));
        }
        let dirmeta = self.stage_dirmeta(meta).await?;
        self.with_dir_mut(&parent, |dir| {
            if !matches!(dir.child_kind(&name), ChildKind::Absent) {
                return Err(Error::Staging(format!(
                    "cannot create directory {}: an entry already exists there",
                    path.display()
                )));
            }
            dir.insert_empty_dir(&name, Some(dirmeta));
            Ok(())
        })
    }

    /// Create `path` and any missing ancestors, applying `meta` to the
    /// directories it creates and leaving existing ones untouched.
    pub async fn make_dir_all(&self, path: &Path, meta: &DirMeta) -> Result<()> {
        let comps = components_of(path)?;
        // Stage `meta` at most once, and only when a directory is actually
        // created. A `make_dir_all` whose every component already exists creates
        // nothing and must not materialize an orphan dirmeta into `objects/`.
        let mut dirmeta: Option<Checksum> = None;
        let mut cur: Vec<String> = Vec::new();
        for comp in comps {
            let name = match comp {
                Comp::Parent => {
                    cur.pop();
                    continue;
                }
                Comp::Normal(name) => name,
            };
            match self.peek(&cur, &name)? {
                ChildKind::Dir | ChildKind::LazyDir { .. } => {
                    self.ensure_child_dir(&cur, &name).await?;
                    cur.push(name);
                }
                ChildKind::Absent => {
                    let dm = match dirmeta {
                        Some(dm) => dm,
                        None => {
                            let dm = self.stage_dirmeta(meta).await?;
                            dirmeta = Some(dm);
                            dm
                        }
                    };
                    self.with_dir_mut(&cur, |dir| {
                        match dir.child_kind(&name) {
                            // A concurrent op may have created it; only create if
                            // still absent, and reject a non-directory in the way.
                            ChildKind::Absent => dir.insert_empty_dir(&name, Some(dm)),
                            ChildKind::File(_) => {
                                return Err(Error::Staging(format!(
                                    "cannot create directory {}: {name:?} is a file",
                                    path.display()
                                )));
                            }
                            ChildKind::Dir | ChildKind::LazyDir { .. } => {}
                        }
                        Ok(())
                    })?;
                    self.ensure_child_dir(&cur, &name).await?;
                    cur.push(name);
                }
                ChildKind::File(checksum) => {
                    // Follow a symlink to a directory; a regular file is an error.
                    let obj = self.txn.load_file_staged_first(&checksum).await?;
                    match obj.kind {
                        FileKind::Symlink { target } => {
                            cur = self.resolve_symlink_dir(&cur, &target).await?;
                        }
                        FileKind::Regular { .. } => {
                            return Err(Error::Staging(format!(
                                "cannot create directory {}: {name:?} is a file",
                                path.display()
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Create a symlink at `path` pointing at `target`. The mode is fixed by the
    /// object model, so only `meta`'s owner and xattrs are used. Fails on any
    /// existing entry.
    pub async fn symlink(&self, path: &Path, target: &Path, meta: &FileMeta) -> Result<()> {
        let (parent, name) = self.resolve_parent(path).await?;
        if !matches!(self.peek(&parent, &name)?, ChildKind::Absent) {
            return Err(Error::Staging(format!(
                "cannot create symlink {}: an entry already exists there",
                path.display()
            )));
        }
        let target = target
            .to_str()
            .ok_or_else(|| Error::Staging("symlink target is not valid UTF-8".into()))?;
        let checksum = self.txn.write_symlink(target, meta, None).await?;
        self.with_dir_mut(&parent, |dir| {
            if !matches!(dir.child_kind(&name), ChildKind::Absent) {
                return Err(Error::Staging(format!(
                    "cannot create symlink {}: an entry already exists there",
                    path.display()
                )));
            }
            dir.replace_file(&name, checksum)
        })
    }

    /// Record a second tree entry at `path` for the content object found at
    /// `target`. The object carries all metadata, so none is taken. The final
    /// component of `target` is not followed, so a symlink is hardlinked as the
    /// symlink object. Fails on any existing entry at `path`.
    pub async fn hardlink(&self, path: &Path, target: &Path) -> Result<()> {
        let checksum = match self
            .walk_from(Vec::new(), components_of(target)?, false)
            .await?
        {
            WalkEnd::Leaf { checksum, .. } => checksum,
            WalkEnd::Dir(_) => {
                return Err(Error::Staging(format!(
                    "cannot hardlink from {}: the target is a directory",
                    target.display()
                )));
            }
        };
        let (parent, name) = self.resolve_parent(path).await?;
        self.with_dir_mut(&parent, |dir| {
            if !matches!(dir.child_kind(&name), ChildKind::Absent) {
                return Err(Error::Staging(format!(
                    "cannot hardlink {}: an entry already exists there",
                    path.display()
                )));
            }
            dir.replace_file(&name, checksum)
        })
    }

    // --- reads (staged-first) ---

    /// Read the file object at `path`, resolving through the staged tree and
    /// loading its bytes from the transaction's staged set before `objects/`.
    /// With `follow_symlinks`, a final symlink is resolved to its target.
    pub async fn read_file(&self, path: &Path, follow_symlinks: bool) -> Result<FileObject> {
        match self
            .walk_from(Vec::new(), components_of(path)?, follow_symlinks)
            .await?
        {
            WalkEnd::Leaf { checksum, .. } => self.txn.load_file_staged_first(&checksum).await,
            WalkEnd::Dir(_) => Err(Error::Staging(format!(
                "{} is a directory, not a file",
                path.display()
            ))),
        }
    }

    /// List the entries of the directory at `path`, files first then
    /// subdirectories, each group name-sorted. With `follow_symlinks`, a final
    /// symlink is resolved to its target directory.
    pub async fn read_dir(&self, path: &Path, follow_symlinks: bool) -> Result<Vec<StagingEntry>> {
        let dir_path = match self
            .walk_from(Vec::new(), components_of(path)?, follow_symlinks)
            .await?
        {
            WalkEnd::Dir(p) => p,
            WalkEnd::Leaf { name, .. } => {
                return Err(Error::Staging(format!("{name:?} is not a directory")));
            }
        };
        self.with_dir(&dir_path, |dir| {
            let mut entries = Vec::new();
            for (name, checksum) in dir.file_entries() {
                entries.push(StagingEntry::File {
                    name: name.to_owned(),
                    checksum,
                });
            }
            for (name, _child) in dir.dir_entries() {
                entries.push(StagingEntry::Dir {
                    name: name.to_owned(),
                });
            }
            entries
        })
    }

    /// Merge `other` into this tree per `opts`. Equal entries merge silently;
    /// differing files, file-versus-directory clashes, and differing directory
    /// metadata are conflicts without `allow_overwrite` and take the right side
    /// with it. With `follow_symlinks`, a right-side directory over a left-side
    /// symlink merges into the symlink's target directory; right-side files and
    /// symlinks replace the left entry and never write through.
    pub async fn merge(&self, other: &MutableTree, opts: MergeOptions) -> Result<()> {
        merge_into(self, Vec::new(), RightDir::Mutable(other), &opts).await
    }

    // --- internal helpers ---

    /// Stage a directory-metadata object and return its checksum.
    async fn stage_dirmeta(&self, meta: &DirMeta) -> Result<Checksum> {
        self.txn.write_dirmeta(meta).await
    }

    /// Fail if a write to a leaf at `parent/name` would clobber a directory. A
    /// file or symlink is replaced; an absent entry is created.
    fn check_writable_leaf(&self, path: &Path, parent: &[String], name: &str) -> Result<()> {
        match self.peek(parent, name)? {
            ChildKind::Dir | ChildKind::LazyDir { .. } => Err(Error::Staging(format!(
                "cannot write file {}: a directory exists at that path",
                path.display()
            ))),
            _ => Ok(()),
        }
    }

    /// Resolve a path's parent directory (following symlinks on intermediate
    /// components) and return its literal component path plus the final name.
    async fn resolve_parent(&self, path: &Path) -> Result<(Vec<String>, String)> {
        let comps = components_of(path)?;
        let (last, init) = comps
            .split_last()
            .ok_or_else(|| Error::Staging(format!("{} has no final component", path.display())))?;
        let name = match last {
            Comp::Normal(name) => name.clone(),
            Comp::Parent => {
                return Err(Error::Staging(format!("{} ends in `..`", path.display())));
            }
        };
        let parent = match self.walk_from(Vec::new(), init.to_vec(), true).await? {
            WalkEnd::Dir(dir) => dir,
            WalkEnd::Leaf { .. } => {
                return Err(Error::Staging(format!(
                    "cannot resolve {}: a parent component is not a directory",
                    path.display()
                )));
            }
        };
        Ok((parent, name))
    }

    /// Resolve a symlink `target` found in directory `base` to a directory.
    async fn resolve_symlink_dir(&self, base: &[String], target: &str) -> Result<Vec<String>> {
        let (absolute, comps) = split_target(target)?;
        let start = if absolute { Vec::new() } else { base.to_vec() };
        match self.walk_from(start, comps, true).await? {
            WalkEnd::Dir(dir) => Ok(dir),
            WalkEnd::Leaf { name, .. } => Err(Error::Staging(format!(
                "symlink target {target:?} resolves to the file {name:?}, not a directory"
            ))),
        }
    }

    /// Walk `comps` from the loaded directory `start`, resolving symlinks. With
    /// `follow_final`, a final symlink is followed too. Returns the directory or
    /// leaf the path names.
    async fn walk_from(
        &self,
        start: Vec<String>,
        comps: Vec<Comp>,
        follow_final: bool,
    ) -> Result<WalkEnd> {
        let mut cur = start;
        let mut pending: VecDeque<Comp> = comps.into();
        let mut symlink_depth = 0usize;
        let mut last_symlink: Option<(String, String)> = None;

        while let Some(comp) = pending.pop_front() {
            let is_final = pending.is_empty();
            let name = match comp {
                Comp::Parent => {
                    cur.pop();
                    continue;
                }
                Comp::Normal(name) => name,
            };

            match self.peek(&cur, &name)? {
                ChildKind::Absent => {
                    return Err(match &last_symlink {
                        Some((symlink, target)) => Error::Staging(format!(
                            "dangling symlink {symlink} -> {target}: no entry {name:?} under /{}",
                            cur.join("/")
                        )),
                        None => Error::Staging(format!(
                            "path not found: no entry {name:?} under /{}",
                            cur.join("/")
                        )),
                    });
                }
                ChildKind::Dir | ChildKind::LazyDir { .. } => {
                    self.ensure_child_dir(&cur, &name).await?;
                    cur.push(name);
                }
                ChildKind::File(checksum) => {
                    if is_final && !follow_final {
                        return Ok(WalkEnd::Leaf { name, checksum });
                    }
                    let obj = self.txn.load_file_staged_first(&checksum).await?;
                    match obj.kind {
                        FileKind::Symlink { target } => {
                            symlink_depth += 1;
                            if symlink_depth > MAX_SYMLINK_DEPTH {
                                return Err(Error::Staging(format!(
                                    "symlink chain too deep (possible loop) resolving {name:?} \
                                     under /{}",
                                    cur.join("/")
                                )));
                            }
                            last_symlink = Some((join(&cur, &name), target.clone()));
                            let (absolute, target_comps) = split_target(&target)?;
                            if absolute {
                                cur.clear();
                            }
                            for comp in target_comps.into_iter().rev() {
                                pending.push_front(comp);
                            }
                        }
                        FileKind::Regular { .. } => {
                            if is_final {
                                return Ok(WalkEnd::Leaf { name, checksum });
                            }
                            return Err(Error::Staging(format!(
                                "not a directory: {name:?} under /{} is a regular file",
                                cur.join("/")
                            )));
                        }
                    }
                }
            }
        }
        Ok(WalkEnd::Dir(cur))
    }

    /// Ensure the child `name` under the loaded directory `path` is a loaded
    /// directory, hydrating a lazily-loaded committed subdirectory. Errors if
    /// the child is absent or is not a directory.
    async fn ensure_child_dir(&self, path: &[String], name: &str) -> Result<()> {
        loop {
            let (kind, repo) = {
                let tree = self.tree.lock().unwrap();
                let dir = tree
                    .dir_at(path)
                    .ok_or_else(|| Error::Staging(dir_gone(path)))?;
                (dir.child_kind(name), dir.repo())
            };
            match kind {
                ChildKind::Dir => return Ok(()),
                ChildKind::LazyDir { dirtree, dirmeta } => {
                    let repo = repo.ok_or_else(|| {
                        Error::Staging(format!("cannot hydrate {name:?}: no repository handle"))
                    })?;
                    let loaded = MutableTree::hydrate(&repo, dirtree, dirmeta).await?;
                    let mut tree = self.tree.lock().unwrap();
                    if let Some(dir) = tree.dir_at_mut(path)
                        && matches!(dir.child_kind(name), ChildKind::LazyDir { .. })
                    {
                        dir.install_hydrated_child(name, loaded);
                    }
                    // Loop to re-read; the child is a loaded directory now.
                }
                ChildKind::File(_) => {
                    return Err(Error::Staging(format!(
                        "not a directory: {name:?} under /{}",
                        path.join("/")
                    )));
                }
                ChildKind::Absent => {
                    return Err(Error::Staging(format!(
                        "path not found: no entry {name:?} under /{}",
                        path.join("/")
                    )));
                }
            }
        }
    }

    /// The kind of `name` under the loaded directory `path`, under the lock.
    fn peek(&self, path: &[String], name: &str) -> Result<ChildKind> {
        let tree = self.tree.lock().unwrap();
        let dir = tree
            .dir_at(path)
            .ok_or_else(|| Error::Staging(dir_gone(path)))?;
        Ok(dir.child_kind(name))
    }

    /// Run `f` against the loaded directory at `path` under the lock.
    fn with_dir<R>(&self, path: &[String], f: impl FnOnce(&MutableTree) -> R) -> Result<R> {
        let tree = self.tree.lock().unwrap();
        let dir = tree
            .dir_at(path)
            .ok_or_else(|| Error::Staging(dir_gone(path)))?;
        Ok(f(dir))
    }

    /// Run `f` against the mutable loaded directory at `path` under the lock.
    fn with_dir_mut<R>(
        &self,
        path: &[String],
        f: impl FnOnce(&mut MutableTree) -> Result<R>,
    ) -> Result<R> {
        let mut tree = self.tree.lock().unwrap();
        let dir = tree
            .dir_at_mut(path)
            .ok_or_else(|| Error::Staging(dir_gone(path)))?;
        f(dir)
    }
}

/// A read-only directory view for the right side of a merge: an in-memory
/// mutable tree node, or a committed subtree loaded through the transaction on
/// demand. A committed subtree resolves staged-first, so a dirtree staged in
/// the current transaction is visible before it publishes, matching the left.
enum RightDir<'a> {
    Mutable(&'a MutableTree),
    Committed {
        txn: &'a Transaction,
        dirtree: Checksum,
        dirmeta: Checksum,
    },
}

impl<'a> RightDir<'a> {
    /// This directory's dirmeta checksum, if it has one.
    fn dirmeta(&self) -> Option<Checksum> {
        match self {
            RightDir::Mutable(tree) => tree.metadata_checksum(),
            RightDir::Committed { dirmeta, .. } => Some(*dirmeta),
        }
    }

    /// This directory's files and subdirectories. A committed directory is read
    /// through `txn` (staged-first); an in-memory node is read directly. The
    /// `txn` supplies the transaction a lazy child's committed view resolves
    /// through.
    async fn entries(
        &self,
        txn: &'a Transaction,
    ) -> Result<(Vec<(String, Checksum)>, Vec<(String, RightDir<'a>)>)> {
        match self {
            RightDir::Mutable(tree) => {
                let tree: &'a MutableTree = tree;
                let files = tree
                    .file_entries()
                    .map(|(name, checksum)| (name.to_owned(), checksum))
                    .collect();
                let dirs = tree
                    .dir_entries()
                    .map(|(name, child)| {
                        let view = match child {
                            ChildRef::Loaded(sub) => RightDir::Mutable(sub),
                            ChildRef::Lazy { dirtree, dirmeta } => RightDir::Committed {
                                txn,
                                dirtree,
                                dirmeta,
                            },
                        };
                        (name.to_owned(), view)
                    })
                    .collect();
                Ok((files, dirs))
            }
            RightDir::Committed { txn, dirtree, .. } => {
                let txn: &'a Transaction = txn;
                let dt = txn.load_dirtree_staged_first(dirtree).await?;
                let files = dt.files.into_iter().collect();
                let dirs = dt
                    .dirs
                    .into_iter()
                    .map(|(name, child_dirtree, child_dirmeta)| {
                        (
                            name,
                            RightDir::Committed {
                                txn,
                                dirtree: child_dirtree,
                                dirmeta: child_dirmeta,
                            },
                        )
                    })
                    .collect();
                Ok((files, dirs))
            }
        }
    }
}

/// The boxed future for the recursive merge; async recursion needs indirection.
type MergeFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Merge the right-side directory `right` into the left staging tree at
/// `left_path`.
fn merge_into<'a>(
    st: &'a StagingTree<'_>,
    left_path: Vec<String>,
    right: RightDir<'a>,
    opts: &'a MergeOptions,
) -> MergeFuture<'a> {
    Box::pin(async move {
        // Reconcile this directory's own metadata. A right dirmeta that is unset
        // makes no change; one that equals the left is silent; a differing one is
        // a conflict without `allow_overwrite`, and is taken with it.
        if let Some(right_dm) = right.dirmeta() {
            let left_dm = {
                let tree = st.tree.lock().unwrap();
                match tree.dir_at(&left_path) {
                    Some(dir) => dir.metadata_checksum(),
                    None => return Err(Error::Staging(dir_gone(&left_path))),
                }
            };
            match left_dm {
                Some(left) if left == right_dm => {}
                Some(_) if !opts.allow_overwrite => {
                    return Err(Error::MergeConflict(format!(
                        "directory metadata differs at /{}",
                        left_path.join("/")
                    )));
                }
                _ => {
                    st.with_dir_mut(&left_path, |dir| {
                        dir.set_metadata_checksum(right_dm);
                        Ok(())
                    })?;
                }
            }
        }

        let (rfiles, rdirs) = right.entries(st.txn).await?;

        for (name, right_csum) in rfiles {
            match st.peek(&left_path, &name)? {
                ChildKind::Absent => {
                    st.with_dir_mut(&left_path, |dir| dir.replace_file(&name, right_csum))?;
                }
                ChildKind::File(left_csum) if left_csum == right_csum => {}
                ChildKind::File(_) => {
                    if !opts.allow_overwrite {
                        return Err(Error::MergeConflict(format!(
                            "file differs at /{}",
                            join(&left_path, &name)
                        )));
                    }
                    st.with_dir_mut(&left_path, |dir| dir.replace_file(&name, right_csum))?;
                }
                ChildKind::Dir | ChildKind::LazyDir { .. } => {
                    if !opts.allow_overwrite {
                        return Err(Error::MergeConflict(format!(
                            "a file cannot overwrite the directory at /{}",
                            join(&left_path, &name)
                        )));
                    }
                    st.with_dir_mut(&left_path, |dir| {
                        dir.remove(&name, true)?;
                        dir.replace_file(&name, right_csum)
                    })?;
                }
            }
        }

        for (name, right_child) in rdirs {
            match st.peek(&left_path, &name)? {
                ChildKind::Absent => {
                    st.with_dir_mut(&left_path, |dir| {
                        dir.insert_empty_dir(&name, right_child.dirmeta());
                        Ok(())
                    })?;
                    let mut child_path = left_path.clone();
                    child_path.push(name);
                    merge_into(st, child_path, right_child, opts).await?;
                }
                ChildKind::Dir | ChildKind::LazyDir { .. } => {
                    st.ensure_child_dir(&left_path, &name).await?;
                    let mut child_path = left_path.clone();
                    child_path.push(name);
                    merge_into(st, child_path, right_child, opts).await?;
                }
                ChildKind::File(left_csum) => {
                    if opts.follow_symlinks {
                        let obj = st.txn.load_file_staged_first(&left_csum).await?;
                        if let FileKind::Symlink { target } = obj.kind {
                            let target_dir = st.resolve_symlink_dir(&left_path, &target).await?;
                            merge_into(st, target_dir, right_child, opts).await?;
                            continue;
                        }
                    }
                    if !opts.allow_overwrite {
                        return Err(Error::MergeConflict(format!(
                            "a directory cannot overwrite the file at /{}",
                            join(&left_path, &name)
                        )));
                    }
                    st.with_dir_mut(&left_path, |dir| {
                        dir.remove(&name, true)?;
                        dir.insert_empty_dir(&name, right_child.dirmeta());
                        Ok(())
                    })?;
                    let mut child_path = left_path.clone();
                    child_path.push(name);
                    merge_into(st, child_path, right_child, opts).await?;
                }
            }
        }
        Ok(())
    })
}

/// A streaming writer for one regular-file payload recorded into a staging tree
/// at [`finish`](StagedFileWriter::finish). It shares the tree and writer count
/// with its [`StagingTree`] through `Arc`, so it does not borrow the tree.
/// Implements [`futures_io::AsyncWrite`] unconditionally and the tokio
/// `AsyncWrite` under the `tokio` feature. Dropping it without `finish` abandons
/// the staged temporary (reaped by the transaction) and releases its writer
/// slot.
pub struct StagedFileWriter<'txn> {
    tree: Arc<Mutex<MutableTree>>,
    writers: Arc<AtomicUsize>,
    writer: Option<ContentWriter<'txn>>,
    parent: Vec<String>,
    name: String,
}

impl StagedFileWriter<'_> {
    /// Complete the content object and record it at the path. Releases the
    /// writer slot on every path.
    pub async fn finish(mut self) -> Result<()> {
        let writer = self.writer.take().expect("writer present until finish");
        let outcome = match writer.finish().await {
            Ok(checksum) => {
                let mut tree = self.tree.lock().unwrap();
                match tree.dir_at_mut(&self.parent) {
                    Some(dir) => dir.replace_file(&self.name, checksum),
                    None => Err(Error::Staging(dir_gone(&self.parent))),
                }
            }
            Err(e) => Err(e),
        };
        self.writers.fetch_sub(1, Ordering::AcqRel);
        outcome
    }
}

impl Drop for StagedFileWriter<'_> {
    fn drop(&mut self) {
        // An abandoned writer (dropped without `finish`) still releases its slot,
        // so `close` is never wedged; its staged temporary is reaped by the
        // transaction.
        if self.writer.is_some() {
            self.writers.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl AsyncWrite for StagedFileWriter<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().writer {
            Some(writer) => Pin::new(writer).poll_write(cx, buf),
            None => Poll::Ready(Ok(0)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().writer {
            Some(writer) => Pin::new(writer).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[cfg(feature = "tokio")]
impl ostrya_rt::tokio_io::AsyncWrite for StagedFileWriter<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_close(self, cx)
    }
}

/// The meaningful components of a path: names and parent-directory hops, with the
/// root, current-directory, and prefix components dropped. A non-UTF-8 component
/// is rejected, since the tree is `String`-keyed and a lossy conversion would
/// silently address the wrong name.
fn components_of(path: &Path) -> Result<Vec<Comp>> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(
                part.to_str()
                    .map(|s| Comp::Normal(s.to_owned()))
                    .ok_or_else(|| {
                        Error::Staging(format!(
                            "path component is not valid UTF-8: {}",
                            path.display()
                        ))
                    }),
            ),
            Component::ParentDir => Some(Ok(Comp::Parent)),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
        .collect()
}

/// Split a symlink target into an absolute flag and its meaningful components.
/// The target is already validated UTF-8, so component decoding never fails.
fn split_target(target: &str) -> Result<(bool, Vec<Comp>)> {
    Ok((target.starts_with('/'), components_of(Path::new(target))?))
}

/// A `parent/name` display path for messages.
fn join(path: &[String], name: &str) -> String {
    if path.is_empty() {
        name.to_owned()
    } else {
        format!("{}/{}", path.join("/"), name)
    }
}

/// The message for a directory that is no longer present under the lock.
fn dir_gone(path: &[String]) -> String {
    format!("directory /{} is no longer present", path.join("/"))
}

/// The new staging-tree types move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<StagingTree<'static>>();
    assert_send_sync::<StagedFileWriter<'static>>();
    assert_send_sync::<StagingEntry>();
    assert_send_sync::<MergeOptions>();
};

#[cfg(feature = "tokio")]
const _: fn() = || {
    fn assert_tokio_write<T: ostrya_rt::tokio_io::AsyncWrite>() {}
    assert_tokio_write::<StagedFileWriter<'static>>();
};
