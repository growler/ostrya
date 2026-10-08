//! Construction of a tree by path inside a transaction.
//!
//! A [`StagingTree`] builds a directory tree by path, over a [`MutableTree`].
//! Each file, symlink, and directory goes through the object writers of the
//! [`Transaction`], so the result is an ordinary tree.
//!
//! - [`Transaction::staging_tree`] creates a staging tree.
//! - [`StagedFileWriter`] streams one regular file into the tree.
//! - [`MergeOptions`] and [`RootDirmeta`] control a merge.
//! - [`StagingEntry`] and [`StagingLookup`] tell what the tree holds at a path.

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

/// The maximum number of symlinks that one path resolution follows. The next
/// symlink is a loop.
const MAX_SYMLINK_DEPTH: usize = 40;

/// One meaningful path component: a name, or a parent-directory hop.
#[derive(Clone)]
enum Comp {
    Normal(String),
    Parent,
}

/// Where a path resolution ended.
enum WalkEnd {
    /// A directory at the given literal component path. Each directory on the
    /// path is loaded.
    Dir(Vec<String>),
    /// A file or symlink leaf, with the literal component path of its parent,
    /// its entry name, and its content checksum. A refusal names the parent
    /// path and the name, so a message reports the place where resolution
    /// ended.
    Leaf {
        parent: Vec<String>,
        name: String,
        checksum: Checksum,
    },
}

/// The dirmeta policy for one directory of a merge.
///
/// The policy applies to the merge root
/// ([`root_dirmeta`](MergeOptions::root_dirmeta)) and to a directory that a
/// followed left-side symlink lands in
/// ([`symlink_target_dirmeta`](MergeOptions::symlink_target_dirmeta)). Each
/// other directory that the merge reaches reconciles under both settings.
#[derive(Debug, Clone, Copy, Default)]
pub enum RootDirmeta {
    /// The same reconciliation as each other directory of the merge.
    ///
    /// An equal dirmeta makes no change. A differing dirmeta is a conflict
    /// without `allow_overwrite`. With `allow_overwrite`, the directory takes
    /// the dirmeta of the right side.
    #[default]
    Reconcile,
    /// The dirmeta of the left side, whatever the right side carries.
    ///
    /// A left directory with no dirmeta keeps none.
    /// [`write_mtree`](crate::Transaction::write_mtree) refuses a tree that
    /// holds a directory with no dirmeta. Under
    /// [`Reconcile`](RootDirmeta::Reconcile), such a directory takes the
    /// dirmeta that the right side carries for it, if the right side carries
    /// one.
    KeepLeft,
}

/// The options of [`StagingTree::merge`] and [`StagingTree::merge_at`].
#[derive(Debug, Clone, Copy, Default)]
pub struct MergeOptions {
    /// Lets the right side win a conflict.
    ///
    /// If `false`, a conflict fails the merge with [`Error::MergeConflict`].
    pub allow_overwrite: bool,
    /// Follows left-side symlinks during the merge.
    ///
    /// A right-side directory over a left-side symlink then merges into the
    /// target directory of the symlink.
    pub follow_symlinks: bool,
    /// The dirmeta policy of the merge root alone.
    pub root_dirmeta: RootDirmeta,
    /// The dirmeta policy of each directory that a followed left-side symlink
    /// lands in.
    ///
    /// The policy applies at each such landing that the recursive merge
    /// reaches, and it does not depend on `root_dirmeta`. A
    /// [`merge_at`](StagingTree::merge_at) base that is a symlink is the merge
    /// root, so `root_dirmeta` applies to it.
    pub symlink_target_dirmeta: RootDirmeta,
}

/// One entry of a [`read_dir`](StagingTree::read_dir) listing.
///
/// A directory in construction has no checksum yet, so a
/// [`Dir`](StagingEntry::Dir) entry carries its name alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagingEntry {
    /// A file or symlink, named by its content checksum.
    File {
        /// The entry name.
        name: String,
        /// The content object checksum.
        checksum: Checksum,
    },
    /// A subdirectory.
    ///
    /// It has no checksum until
    /// [`write_mtree`](crate::Transaction::write_mtree) writes it.
    Dir {
        /// The entry name.
        name: String,
    },
}

/// The result of a [`lookup`](StagingTree::lookup) at a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingLookup {
    /// No entry, because a component on the path is absent.
    Absent,
    /// A regular file or symlink, named by its content checksum.
    ///
    /// The tree does not record the kind, so only a load of the object tells
    /// the two apart. [`read_file`](StagingTree::read_file) loads it.
    File {
        /// The content object checksum.
        checksum: Checksum,
    },
    /// A directory.
    Dir,
}

/// A tree of a transaction that is built by path.
///
/// [`Transaction::staging_tree`] and
/// [`Transaction::staging_tree_from_mutable_tree`] create a staging tree. It
/// borrows the transaction, so the order [`close`](StagingTree::close),
/// [`write_mtree`](crate::Transaction::write_mtree), and
/// [`commit`](crate::Transaction::commit) is the only order that compiles.
///
/// The staging tree is an ostrya extension, with no equivalent in the
/// `ostree` command. It does not change the on-disk format. Each file,
/// symlink, and directory goes through the object writers of the
/// transaction, and the result is an ordinary tree.
///
/// # Concurrency
///
/// `&StagingTree` is `Send + Sync`. A synchronous mutex guards the tree. An
/// operation holds the mutex only for the short map operations that read or
/// change the structure of the tree. These async steps run between two
/// acquisitions of the mutex, and never hold it:
///
/// - the load of a committed subdirectory that is not loaded yet
/// - the load of a symlink object during path resolution
/// - the stream of a file payload
///
/// Many [`write_file`](StagingTree::write_file) streams can run at the same
/// time through one shared `&StagingTree`. A file write streams outside the
/// mutex. Each writer records its entry under the mutex, at
/// [`finish`](StagedFileWriter::finish) only.
///
/// The tree counts its outstanding writers. Each [`StagedFileWriter`] shares
/// the tree and the count through `Arc`, so a writer does not borrow the
/// tree. A call to [`close`](StagingTree::close) with a live writer compiles,
/// and fails at run time on the count.
///
/// While any file writer is outstanding, at any place in the tree, these
/// operations fail with [`Staging`](Error::Staging):
///
/// - a [`merge_at`](StagingTree::merge_at) that drops a directory
/// - a [`remove`](StagingTree::remove) that takes an entry out
/// - a [`clear_dir`](StagingTree::clear_dir) that reaches a directory
/// - a [`rename`](StagingTree::rename)
///
/// A writer records its entry under the component path that it captured
/// when it started. If an entry on that path is dropped before
/// [`finish`](StagedFileWriter::finish), the path becomes stale.
///
/// # Paths
///
/// - Each intermediate component resolves through symlinks. A write never
///   follows a symlink at the final component.
/// - A relative symlink target resolves from the parent of the symlink. An
///   absolute target resolves from the tree root.
/// - A `..` at the tree root stays at the root.
/// - One resolution follows at most 40 symlinks. The next one gives
///   [`SymlinkLoop`](Error::SymlinkLoop).
/// - A dangling symlink target is an error.
/// - A path with no components (`.`, `/`, and the empty path) names the tree
///   root. [`ensure_dir`](StagingTree::ensure_dir) stamps the root, and
///   [`merge_at`](StagingTree::merge_at) merges into it.
///
/// The parent directory of a write must exist. If an implied dirmeta is set
/// ([`with_implied_dirmeta`](StagingTree::with_implied_dirmeta)), the write
/// creates its missing ancestors as directories with that dirmeta. A
/// [`merge_at`](StagingTree::merge_at) creates its whole base in the same way.
/// Path resolution for a read never creates a directory.
///
/// [`make_dir_all`](StagingTree::make_dir_all) refuses a symlink at the last
/// component of its path, because that component is the directory that the
/// call creates. It follows a symlink at each earlier component.
///
/// The reads [`read_file`](StagingTree::read_file),
/// [`read_dir`](StagingTree::read_dir), and [`lookup`](StagingTree::lookup)
/// take a `follow_symlinks` flag for the final component. The
/// [`follow_symlinks`](MergeOptions::follow_symlinks) option of a merge
/// controls the left-side entry names that the merge reaches. The final
/// component of the merge base follows in both settings.
///
/// Objects load from the staged set of the transaction before `objects/`, so
/// content that the current transaction stages is visible before the
/// transaction publishes it.
///
/// # Error paths
///
/// Each refusal has its own [`Error`] variant, so a caller can branch on the
/// variant:
///
/// - [`PathNotFound`](Error::PathNotFound)
/// - [`NotADirectory`](Error::NotADirectory)
/// - [`DanglingSymlink`](Error::DanglingSymlink)
/// - [`SymlinkLoop`](Error::SymlinkLoop)
/// - [`EntryExists`](Error::EntryExists)
///
/// [`Staging`](Error::Staging) carries each condition that these variants do
/// not name.
///
/// Each typed refusal of the staging tree reports one path form: the resolved
/// literal component path, with no leading `/`. The tree root is spelled `.`.
///
/// - A path that crosses a symlink reports the components of the target. A
///   write under `opt -> usr/opt` reports `usr/opt`.
/// - If a component is absent while components of a symlink target are still
///   queued, the error is [`DanglingSymlink`](Error::DanglingSymlink) for the
///   innermost such symlink. After the target is spent, an absent component
///   gives [`PathNotFound`](Error::PathNotFound).
/// - A [`Staging`](Error::Staging) condition before resolution starts reports
///   the path as the caller gave it, because no resolved form exists. These
///   conditions are a path with no final component, a path that ends in `..`,
///   and a path component that is not UTF-8.
/// - A symlink target that is not UTF-8 names no path.
/// - A directory in the way of a write gives
///   [`ReplaceDirWithFile`](Error::ReplaceDirWithFile), at whichever moment
///   the directory appeared. This variant names the entry alone, because the
///   mutable-tree layer raises it. It is the one exception to the path form.
///
/// # Examples
///
/// Write one file by path, then write the tree and commit it.
///
/// ```no_run
/// # async fn run() -> ostrya::Result<()> {
/// use std::path::Path;
///
/// use ostrya::{CommitOptions, DirMeta, FileMeta, Repo, Xattrs};
///
/// let repo = Repo::open("/srv/repo".as_ref()).await?;
/// let txn = repo.transaction().await?;
/// let dir = DirMeta { uid: 0, gid: 0, mode: 0o40755, xattrs: Xattrs::empty() };
/// let st = txn.staging_tree(None).await?.with_implied_dirmeta(dir.clone());
/// st.ensure_dir(Path::new("."), &dir).await?;
/// let file = FileMeta::regular(0, 0, 0o644);
/// st.write_file_content(Path::new("etc/hostname"), &file, b"example\n").await?;
/// let mut tree = st.close()?;
/// let root = txn.write_mtree(&mut tree).await?;
/// let commit = txn.write_commit(CommitOptions::default(), &root).await?;
/// txn.set_ref("exampleos/stable", Some(&commit));
/// txn.commit().await?;
/// # Ok(()) }
/// ```
pub struct StagingTree<'txn> {
    txn: &'txn Transaction,
    tree: Arc<Mutex<MutableTree>>,
    /// The count of outstanding [`StagedFileWriter`]s.
    /// [`close`](StagingTree::close) and a [`merge_at`](StagingTree::merge_at)
    /// that drops a directory fail while it is not zero.
    /// [`write_file`](StagingTree::write_file) increments it under the tree
    /// lock, and the merge check reads it under the same lock. A registration
    /// and a directory drop cannot miss each other.
    writers: Arc<AtomicUsize>,
    /// The dirmeta of the ancestors that a write creates. `None` keeps a
    /// missing parent an error.
    implied_dirmeta: Option<DirMeta>,
}

/// Methods that create a staging tree.
impl Transaction {
    /// Creates a staging tree over this transaction, empty or from a commit.
    ///
    /// With a `source` commit, the call reads the root dirtree of the commit,
    /// and the tree loads each subdirectory when an operation first reaches
    /// it. With `None`, the tree is empty and its root has no dirmeta.
    /// [`write_mtree`](Transaction::write_mtree) refuses a root with no
    /// dirmeta, so [`ensure_dir`](StagingTree::ensure_dir) on the path `.`
    /// sets one.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the root dirtree of `source` is not in
    ///   the repository.
    /// - [`Error::Core`] if the root dirtree is malformed.
    /// - [`Error::Io`] if the read of the root dirtree fails.
    pub async fn staging_tree(&self, source: Option<&Commit>) -> Result<StagingTree<'_>> {
        let tree = match source {
            None => MutableTree::new(),
            Some(commit) => {
                MutableTree::hydrate(self.repo(), commit.root_dirtree, commit.root_dirmeta).await?
            }
        };
        Ok(StagingTree::from_tree(self, tree))
    }

    /// Creates a staging tree over this transaction from an existing mutable
    /// tree.
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
            implied_dirmeta: None,
        }
    }

    /// Returns this tree with `meta` as the dirmeta of the ancestors that writes create.
    ///
    /// The dirmeta is set once, at construction. The method consumes the tree, so
    /// the type needs no interior mutability. If no implied dirmeta is set, a
    /// missing parent is an error.
    ///
    /// These operations create missing ancestors with this dirmeta:
    ///
    /// - [`write_file`](StagingTree::write_file)
    /// - [`write_file_content`](StagingTree::write_file_content)
    /// - [`symlink`](StagingTree::symlink)
    /// - the destination side of a [`hardlink`](StagingTree::hardlink)
    /// - [`place_object`](StagingTree::place_object)
    /// - [`ensure_dir`](StagingTree::ensure_dir)
    /// - the destination side of a [`rename`](StagingTree::rename)
    ///
    /// The leaf takes the metadata that the operation itself supplies. A
    /// [`merge_at`](StagingTree::merge_at) base is created under the same policy,
    /// its own final component included, because the base names a directory.
    ///
    /// These steps never create a directory and never stage a dirmeta object:
    ///
    /// - path resolution for a read
    /// - a [`lookup`](StagingTree::lookup)
    /// - a [`remove`](StagingTree::remove)
    /// - a [`clear_dir`](StagingTree::clear_dir)
    /// - the source side of a [`hardlink`](StagingTree::hardlink)
    /// - the `from` side of a [`rename`](StagingTree::rename)
    ///
    /// [`make_dir`](StagingTree::make_dir) and
    /// [`make_dir_all`](StagingTree::make_dir_all) keep their own rules.
    ///
    /// Ancestors that a call creates before a refused leaf stay in the tree. A
    /// component that a later `..` steps back out of is created like any other
    /// ancestor.
    pub fn with_implied_dirmeta(mut self, meta: DirMeta) -> StagingTree<'txn> {
        self.implied_dirmeta = Some(meta);
        self
    }

    /// Returns the assembled tree, for [`write_mtree`](crate::Transaction::write_mtree).
    ///
    /// # Errors
    ///
    /// - [`Error::Staging`] if a writer from [`write_file`](StagingTree::write_file)
    ///   is still outstanding.
    pub fn close(self) -> Result<MutableTree> {
        let outstanding = self.writers.load(Ordering::Acquire);
        if outstanding != 0 {
            return Err(Error::Staging(format!(
                "cannot close the staging tree: {outstanding} file writer(s) still outstanding"
            )));
        }
        // The counter is authoritative. At zero, each writer recorded its
        // entry (finish takes the tree lock before it decrements) or was
        // dropped. A finishing writer can still hold a clone of the tree Arc
        // between its decrement and its drop. So the tree comes out through
        // the mutex, and sole Arc ownership is not necessary. The Acquire load
        // above pairs with the AcqRel decrement in finish, so the replace_file
        // of that writer is visible here. mem::take leaves an empty tree
        // behind. Nothing reads it, because the counter guarantees that no
        // writer records again.
        let mut guard = self.tree.lock().unwrap();
        Ok(std::mem::take(&mut *guard))
    }

    // --- write operations ---

    /// Returns a streaming writer for one regular-file payload at `path`.
    ///
    /// The parent directory must exist, unless an implied dirmeta is set
    /// ([`with_implied_dirmeta`](StagingTree::with_implied_dirmeta)). Intermediate
    /// components resolve through symlinks, and the final component never follows a
    /// symlink. At [`finish`](StagedFileWriter::finish), the file replaces an
    /// existing file or symlink at `path`.
    ///
    /// # Errors
    ///
    /// - [`Error::ReplaceDirWithFile`] if a directory is at `path`.
    /// - [`Error::Staging`] if a concurrent operation drops the parent directory
    ///   between path resolution and the registration of the writer. The writer is
    ///   not counted in that window, so the writer guard holds off no concurrent
    ///   operation. The check at registration finds the drop.
    /// - [`Error::PathNotFound`], [`Error::NotADirectory`], [`Error::DanglingSymlink`],
    ///   or [`Error::SymlinkLoop`] if the path does not resolve.
    ///   [`StagingTree`](StagingTree#error-paths) states the path that each one
    ///   names.
    /// - [`Error::Staging`] if `path` has no final component, ends in `..`, or has
    ///   a component that is not UTF-8.
    /// - [`Error::Core`] if the mode in `meta` is not a regular-file mode or a
    ///   symlink mode.
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`, or
    ///   if `[ex-integrity] fsverity` is `yes` and the fs-verity seal of a staged
    ///   dirmeta object fails.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::InsufficientFreeSpace`] if a staged dirmeta object needs more
    ///   space than the free-space budget of the transaction holds.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a `[core]`, `[archive]`, or
    ///   `[ex-integrity]` value in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn write_file(&self, path: &Path, meta: &FileMeta) -> Result<StagedFileWriter<'txn>> {
        let (parent, name) = self.resolve_write_parent(path).await?;
        self.check_writable_leaf(&parent, &name)?;
        let writer = self.txn.content_writer(None, meta).await?;
        {
            // Register under the tree lock, and check the parent again. Each
            // merge arm that drops a directory reads a zero count under this
            // same lock before it drops. So a writer registered against a
            // parent that still exists keeps its captured path valid for its
            // whole life. A parent that a concurrent merge already dropped
            // fails here, before finish.
            let tree = self.tree.lock().unwrap();
            if tree.dir_at(&parent).is_none() {
                return Err(Error::Staging(dir_gone(&parent)));
            }
            self.writers.fetch_add(1, Ordering::AcqRel);
        }
        Ok(StagedFileWriter {
            tree: self.tree.clone(),
            writers: self.writers.clone(),
            writer: Some(writer),
            parent,
            name,
        })
    }

    /// Writes a regular file at `path` from content that the caller holds.
    ///
    /// The file replaces an existing file or symlink at `path`. The path rules of
    /// [`write_file`](StagingTree::write_file) apply.
    ///
    /// # Errors
    ///
    /// - [`Error::ReplaceDirWithFile`] if a directory is at `path`.
    /// - [`Error::PathNotFound`], [`Error::NotADirectory`], [`Error::DanglingSymlink`],
    ///   or [`Error::SymlinkLoop`] if the path does not resolve.
    ///   [`StagingTree`](StagingTree#error-paths) states the path that each one
    ///   names.
    /// - [`Error::Staging`] if `path` has no final component, ends in `..`, or has
    ///   a component that is not UTF-8.
    /// - [`Error::Core`] if the mode in `meta` is not a regular-file mode or a
    ///   symlink mode.
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`, or
    ///   if `[ex-integrity] fsverity` is `yes` and the fs-verity seal of the
    ///   object fails.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::InsufficientFreeSpace`] if a staged object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a `[core]`, `[archive]`, or
    ///   `[ex-integrity]` value in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn write_file_content(
        &self,
        path: &Path,
        meta: &FileMeta,
        content: &[u8],
    ) -> Result<()> {
        let (parent, name) = self.resolve_write_parent(path).await?;
        self.check_writable_leaf(&parent, &name)?;
        let checksum = self.txn.write_regfile_inline(None, meta, content).await?;
        self.with_dir_mut(&parent, |dir| dir.replace_file(&name, checksum))
    }

    /// Creates the directory `path`, whose parent must exist.
    ///
    /// The call never creates a parent, also when an implied dirmeta is set.
    ///
    /// # Errors
    ///
    /// - [`Error::EntryExists`] if an entry of any kind is at `path`.
    /// - [`Error::PathNotFound`], [`Error::NotADirectory`], [`Error::DanglingSymlink`],
    ///   or [`Error::SymlinkLoop`] if the path does not resolve.
    ///   [`StagingTree`](StagingTree#error-paths) states the path that each one
    ///   names.
    /// - [`Error::Staging`] if `path` has no final component, ends in `..`, or has
    ///   a component that is not UTF-8.
    /// - [`Error::Core`] if `meta` does not hold a directory mode.
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`, or
    ///   if `[ex-integrity] fsverity` is `yes` and the fs-verity seal of a staged
    ///   object fails.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::InsufficientFreeSpace`] if a staged object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a `[core]`, `[archive]`, or
    ///   `[ex-integrity]` value in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn make_dir(&self, path: &Path, meta: &DirMeta) -> Result<()> {
        let (parent, name) = self.resolve_parent(path).await?;
        if !matches!(self.peek(&parent, &name)?, ChildKind::Absent) {
            return Err(entry_exists(&parent, &name));
        }
        let dirmeta = self.stage_dirmeta(meta).await?;
        self.with_dir_mut(&parent, |dir| {
            if !matches!(dir.child_kind(&name), ChildKind::Absent) {
                return Err(entry_exists(&parent, &name));
            }
            dir.insert_empty_dir(&name, Some(dirmeta));
            Ok(())
        })
    }

    /// Creates `path` and its missing ancestors, with `meta` on each new directory.
    ///
    /// The call does not change an existing directory.
    ///
    /// # Symlinks
    ///
    /// A symlink at the last component of `path` gives
    /// [`EntryExists`](Error::EntryExists), because that component is the directory
    /// that the call creates. A base root file system can ship `/var` or
    /// `/usr/etc` as a symlink to another directory. The refusal reports that alias
    /// to the caller, and the caller decides where the content goes.
    ///
    /// The refusal comes before the target resolves, and it does not depend on the
    /// target. A dangling symlink at that component also gives
    /// [`EntryExists`](Error::EntryExists). A regular file at that component gives
    /// [`NotADirectory`](Error::NotADirectory). `mkdir -p` accepts a symlink to a
    /// directory there and exits with status zero.
    ///
    /// A symlink at an earlier component resolves to its target directory, and the
    /// call creates the next components under that target. A `..` after a symlink
    /// makes that symlink an earlier component. For example,
    /// `make_dir_all("var/lock/..")`
    /// follows a `var/lock` alias, goes up to the parent of the target, and creates
    /// nothing at the alias.
    ///
    /// # Partial results
    ///
    /// The directories that the walk creates before a refusal stay in the tree. A
    /// directory that a later `..` steps back out of is created like any other
    /// ancestor. The implied-dirmeta policy follows the same rule
    /// ([`with_implied_dirmeta`](StagingTree::with_implied_dirmeta)).
    ///
    /// # Errors
    ///
    /// - [`Error::EntryExists`] if a symlink is at the last component of `path`.
    /// - [`Error::NotADirectory`] if a file is at a component of `path`, or if a
    ///   symlink on the path resolves to a file.
    /// - [`Error::DanglingSymlink`] or [`Error::SymlinkLoop`] if a symlink on the
    ///   path does not resolve.
    /// - [`Error::Staging`] if a component of `path` is not UTF-8.
    /// - [`Error::Core`] if `meta` does not hold a directory mode.
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`, or
    ///   if `[ex-integrity] fsverity` is `yes` and the fs-verity seal of a staged
    ///   object fails.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::InsufficientFreeSpace`] if a staged object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a `[core]`, `[archive]`, or
    ///   `[ex-integrity]` value in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn make_dir_all(&self, path: &Path, meta: &DirMeta) -> Result<()> {
        self.walk_creating(components_of(path)?, meta, true).await?;
        Ok(())
    }

    /// Walks `comps` from the tree root and returns the literal component
    /// path that the walk reached. The walk creates each absent component as
    /// a directory with `meta`, and follows symlinks to directories.
    ///
    /// With `refuse_final_symlink`, a symlink at the last element of `comps` is
    /// [`EntryExists`](Error::EntryExists). Without it, the walk follows that
    /// symlink to its target directory. Each earlier element follows such a
    /// symlink under both settings. A last element that is a `Comp::Parent`
    /// hop pops the resolved path and ends the walk. The flag applies to no
    /// element of a `comps` that ends in `..`.
    /// [`make_dir_all`](StagingTree::make_dir_all) sets it, because that
    /// element is the directory that the call creates. The two resolution
    /// walks clear it. For them, the last element of `comps` is a parent
    /// directory that must follow a symlink. These are the parent of a write under an
    /// implied dirmeta
    /// ([`resolve_write_parent`](StagingTree::resolve_write_parent)) and the
    /// base of a [`merge_at`](StagingTree::merge_at)
    /// ([`resolve_merge_base`](StagingTree::resolve_merge_base)).
    async fn walk_creating(
        &self,
        comps: Vec<Comp>,
        meta: &DirMeta,
        refuse_final_symlink: bool,
    ) -> Result<Vec<String>> {
        // Stage `meta` at most once, and only when a directory is actually
        // created. A walk whose every component already exists creates
        // nothing and must not materialize an orphan dirmeta into `objects/`.
        let mut dirmeta: Option<Checksum> = None;
        let mut cur: Vec<String> = Vec::new();
        let total = comps.len();
        for (idx, comp) in comps.into_iter().enumerate() {
            let is_final = idx + 1 == total;
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
                            // A concurrent op can have created it. Create it
                            // only if it is still absent, and reject a
                            // non-directory in the way.
                            ChildKind::Absent => dir.insert_empty_dir(&name, Some(dm)),
                            ChildKind::File(_) => {
                                return Err(Error::NotADirectory {
                                    path: join(&cur, &name),
                                });
                            }
                            ChildKind::Dir | ChildKind::LazyDir { .. } => {}
                        }
                        Ok(())
                    })?;
                    self.ensure_child_dir(&cur, &name).await?;
                    cur.push(name);
                }
                ChildKind::File(checksum) => {
                    // Follow a symlink to a directory. A regular file is an error.
                    let obj = self.txn.load_file_staged_first(&checksum).await?;
                    match obj.kind {
                        FileKind::Symlink { target } => {
                            // The caller that creates the last component takes
                            // a symlink there as an entry already present. The
                            // check comes before the target walk, so the
                            // refusal does not depend on the symlink target.
                            if refuse_final_symlink && is_final {
                                return Err(entry_exists(&cur, &name));
                            }
                            // An absent component that the target walk reaches
                            // belongs to this symlink. The walk consumes the
                            // target alone, so its `PathNotFound` is never one
                            // of the components of the caller. The dangling
                            // report of an inner symlink passes through, so
                            // the error names the innermost open symlink, the
                            // same as `walk_from`.
                            let link = join(&cur, &name);
                            cur = match self.resolve_symlink_dir(&cur, &target).await {
                                Ok(dir) => dir,
                                Err(Error::PathNotFound { .. }) => {
                                    return Err(Error::DanglingSymlink { path: link, target });
                                }
                                Err(e) => return Err(e),
                            };
                        }
                        FileKind::Regular { .. } => {
                            return Err(Error::NotADirectory {
                                path: join(&cur, &name),
                            });
                        }
                    }
                }
            }
        }
        Ok(cur)
    }

    /// Creates the directory at `path`, or sets `meta` on an existing one.
    ///
    /// A file or symlink at `path` gives [`NotADirectory`](Error::NotADirectory).
    /// The call stages the dirmeta object only for a new directory or for a
    /// differing recorded dirmeta. A call with no change stages no object.
    ///
    /// The call never loads a committed directory that is not loaded yet. It
    /// compares the recorded dirmeta, and it rewrites a differing one in place,
    /// because the content of the directory does not change.
    ///
    /// A `path` with no components (`.`, `/`, and the empty path) names the tree
    /// root, which takes the same comparison and the same stamp. No parent directory
    /// holds the root, so the root is a directory in every call.
    /// [`close`](StagingTree::close) returns a tree whose root has the stamped
    /// dirmeta, and [`write_mtree`](crate::Transaction::write_mtree) records it as
    /// the root dirmeta of the tree that it returns.
    ///
    /// # Errors
    ///
    /// - [`Error::NotADirectory`] if a file or a symlink is at `path`.
    /// - [`Error::PathNotFound`], [`Error::NotADirectory`], [`Error::DanglingSymlink`],
    ///   or [`Error::SymlinkLoop`] if the path does not resolve.
    ///   [`StagingTree`](StagingTree#error-paths) states the path that each one
    ///   names.
    /// - [`Error::Staging`] if `path` ends in `..` or has a component that is not
    ///   UTF-8.
    /// - [`Error::Core`] if `meta` does not hold a directory mode.
    /// - [`Error::Unsupported`] if the call stages a dirmeta object in a
    ///   `bare-split-xattrs` repository, or if its fs-verity seal fails under
    ///   `[ex-integrity] fsverity` = `yes`.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::InsufficientFreeSpace`] if a staged object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a `[core]`, `[archive]`, or
    ///   `[ex-integrity]` value in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn ensure_dir(&self, path: &Path, meta: &DirMeta) -> Result<()> {
        if components_of(path)?.is_empty() {
            // The tree root, which no parent directory holds. The comparison
            // reads the recorded dirmeta of the root, and the stamp sets it
            // there. Staging is async and runs outside the lock. The root is a
            // directory in every acquisition, so the mutating acquisition
            // repeats no decision: it stamps what the comparison read. Of two
            // stamps with differing dirmetas, the last one stays recorded.
            // This is the last-writer-wins rule of a raced staging write.
            let new_dirmeta = self.txn.dirmeta_checksum(meta)?;
            if self.with_dir(&[], |dir| dir.metadata_checksum())? == Some(new_dirmeta) {
                return Ok(());
            }
            let dirmeta = self.stage_dirmeta(meta).await?;
            return self.with_dir_mut(&[], |dir| {
                dir.set_metadata_checksum(dirmeta);
                Ok(())
            });
        }
        let (parent, name) = self.resolve_write_parent(path).await?;
        let new_dirmeta = self.txn.dirmeta_checksum(meta)?;
        let unchanged = match self.peek(&parent, &name)? {
            ChildKind::File(_) => {
                return Err(Error::NotADirectory {
                    path: join(&parent, &name),
                });
            }
            ChildKind::Absent => false,
            ChildKind::LazyDir { dirmeta, .. } => dirmeta == new_dirmeta,
            ChildKind::Dir => {
                let mut child = parent.clone();
                child.push(name.clone());
                self.with_dir(&child, |dir| dir.metadata_checksum())? == Some(new_dirmeta)
            }
        };
        if unchanged {
            return Ok(());
        }
        // Staging is async and runs outside the lock, so the mutating
        // acquisition repeats the decision. An entry that is still absent is
        // inserted, a directory takes the new dirmeta, and a file that
        // appeared in the way is rejected.
        let dirmeta = self.stage_dirmeta(meta).await?;
        self.with_dir_mut(&parent, |dir| match dir.child_kind(&name) {
            ChildKind::Absent => {
                dir.insert_empty_dir(&name, Some(dirmeta));
                Ok(())
            }
            ChildKind::Dir | ChildKind::LazyDir { .. } => dir.set_child_dirmeta(&name, dirmeta),
            ChildKind::File(_) => Err(Error::NotADirectory {
                path: join(&parent, &name),
            }),
        })
    }

    /// Creates a symlink at `path` that points at `target`.
    ///
    /// The object model fixes the mode of a symlink, so the call uses only the owner
    /// and the xattrs of `meta`. The symlink replaces an existing file or symlink at
    /// `path`. The path rules of [`write_file`](StagingTree::write_file) apply.
    ///
    /// # Errors
    ///
    /// - [`Error::ReplaceDirWithFile`] if a directory is at `path`.
    /// - [`Error::Staging`] if `target` is not UTF-8.
    /// - [`Error::PathNotFound`], [`Error::NotADirectory`], [`Error::DanglingSymlink`],
    ///   or [`Error::SymlinkLoop`] if the path does not resolve.
    ///   [`StagingTree`](StagingTree#error-paths) states the path that each one
    ///   names.
    /// - [`Error::Staging`] if `path` has no final component, ends in `..`, or has
    ///   a component that is not UTF-8.
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`, or
    ///   if `[ex-integrity] fsverity` is `yes` and the fs-verity seal of a staged
    ///   object fails.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::InsufficientFreeSpace`] if a staged object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a `[core]`, `[archive]`, or
    ///   `[ex-integrity]` value in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn symlink(&self, path: &Path, target: &Path, meta: &FileMeta) -> Result<()> {
        let (parent, name) = self.resolve_write_parent(path).await?;
        self.check_writable_leaf(&parent, &name)?;
        let target = target
            .to_str()
            .ok_or_else(|| Error::Staging("symlink target is not valid UTF-8".into()))?;
        let checksum = self.txn.write_symlink(target, meta, None).await?;
        self.with_dir_mut(&parent, |dir| dir.replace_file(&name, checksum))
    }

    /// Records a second tree entry at `path` for the content object at `target`.
    ///
    /// The object carries all the metadata, so the call takes none. The call does not
    /// follow the final component of `target`, so a symlink is hardlinked as the
    /// symlink object. The new entry replaces an existing file or symlink at
    /// `path`.
    ///
    /// # Errors
    ///
    /// - [`Error::ReplaceDirWithFile`] if a directory is at `path`.
    /// - [`Error::Staging`] if `target` names a directory.
    /// - [`Error::PathNotFound`], [`Error::NotADirectory`], [`Error::DanglingSymlink`],
    ///   or [`Error::SymlinkLoop`] if `target` or the parent of `path` does not
    ///   resolve. [`StagingTree`](StagingTree#error-paths) states the path that each
    ///   one names.
    /// - [`Error::Staging`] if `path` has no final component, ends in `..`, or has
    ///   a component that is not UTF-8.
    /// - [`Error::Staging`] if a component of `target` is not UTF-8.
    /// - [`Error::Unsupported`] if the call stages a dirmeta object in a
    ///   `bare-split-xattrs` repository, or if its fs-verity seal fails under
    ///   `[ex-integrity] fsverity` = `yes`.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::InsufficientFreeSpace`] if a staged object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a `[core]`, `[archive]`, or
    ///   `[ex-integrity]` value in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn hardlink(&self, path: &Path, target: &Path) -> Result<()> {
        let checksum = match self
            .walk_from(Vec::new(), components_of(target)?, false)
            .await?
        {
            WalkEnd::Leaf { checksum, .. } => checksum,
            WalkEnd::Dir(dir) => {
                return Err(Error::Staging(format!(
                    "cannot hardlink from {}: the source is a directory",
                    spell_path(&dir)
                )));
            }
        };
        let (parent, name) = self.resolve_write_parent(path).await?;
        self.check_writable_leaf(&parent, &name)?;
        self.with_dir_mut(&parent, |dir| dir.replace_file(&name, checksum))
    }

    /// Records `checksum` as the file entry at `path`.
    ///
    /// The same checksum at `path` makes no change. The call decides and applies
    /// this rule under one lock acquisition. If concurrent calls place differing
    /// checksums at one path, one of them is recorded and each other call gets a
    /// conflict. No call overwrites another call without an error. The call does not
    /// check that the object is in the store, the same as
    /// [`write_mtree`](crate::Transaction::write_mtree).
    ///
    /// # Errors
    ///
    /// - [`Error::MergeConflict`] if a differing file entry or a directory is at
    ///   `path`.
    /// - [`Error::PathNotFound`], [`Error::NotADirectory`], [`Error::DanglingSymlink`],
    ///   or [`Error::SymlinkLoop`] if the path does not resolve.
    ///   [`StagingTree`](StagingTree#error-paths) states the path that each one
    ///   names.
    /// - [`Error::Staging`] if `path` has no final component, ends in `..`, or has
    ///   a component that is not UTF-8.
    /// - [`Error::Unsupported`] if the call stages a dirmeta object in a
    ///   `bare-split-xattrs` repository, or if its fs-verity seal fails under
    ///   `[ex-integrity] fsverity` = `yes`.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::InsufficientFreeSpace`] if a staged object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a `[core]`, `[archive]`, or
    ///   `[ex-integrity]` value in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn place_object(&self, path: &Path, checksum: &Checksum) -> Result<()> {
        let (parent, name) = self.resolve_write_parent(path).await?;
        self.with_dir_mut(&parent, |dir| match dir.child_kind(&name) {
            ChildKind::Absent => dir.replace_file(&name, *checksum),
            ChildKind::File(existing) if existing == *checksum => Ok(()),
            ChildKind::File(_) => Err(Error::MergeConflict(format!(
                "placed object differs at {}",
                join(&parent, &name)
            ))),
            ChildKind::Dir | ChildKind::LazyDir { .. } => Err(Error::MergeConflict(format!(
                "an object cannot overwrite the directory at {}",
                join(&parent, &name)
            ))),
        })
    }

    /// Removes the entry at `path`, with its whole subtree.
    ///
    /// The call never follows the final component, so the removal of a symlink
    /// removes the symlink. With `allow_noent`, the call returns `Ok` for an
    /// absent entry, an absent ancestor, and a dangling intermediate symlink.
    ///
    /// # Errors
    ///
    /// - [`Error::PathNotFound`] if no entry is at `path` and `allow_noent` is
    ///   `false`.
    /// - [`Error::Staging`] if the call takes an entry out while any writer from
    ///   [`write_file`](StagingTree::write_file) is outstanding, at any place in
    ///   the tree. A call that removes nothing does not check the writers.
    /// - [`Error::PathNotFound`] or [`Error::DanglingSymlink`] if an ancestor does
    ///   not resolve and `allow_noent` is `false`.
    /// - [`Error::NotADirectory`] or [`Error::SymlinkLoop`] if an ancestor does
    ///   not resolve, also with `allow_noent`.
    /// - [`Error::Staging`] if `path` has no final component, ends in `..`, or has
    ///   a component that is not UTF-8.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn remove(&self, path: &Path, allow_noent: bool) -> Result<()> {
        let (parent, name) = match self.resolve_parent(path).await {
            Ok(resolved) => resolved,
            Err(Error::PathNotFound { .. } | Error::DanglingSymlink { .. }) if allow_noent => {
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        // The absent-entry outcome is decided under the same acquisition that
        // removes the entry, so the call cannot miss an entry that appears in
        // between. A caller never sees the mutable-tree refusal. A call that
        // removes nothing reads no writer guard. The merge arms do the same:
        // they read the guard only where they are about to drop.
        self.with_dir_mut(&parent, |dir| match dir.child_kind(&name) {
            ChildKind::Absent if allow_noent => Ok(()),
            ChildKind::Absent => Err(Error::PathNotFound {
                path: join(&parent, &name),
            }),
            _ => {
                self.check_no_live_writers(&format!("remove {}", join(&parent, &name)))?;
                dir.remove(&name, true)
            }
        })
    }

    /// Removes each entry under `path`, and keeps the directory and its dirmeta.
    ///
    /// The call never follows the final component. A file at `path` gives
    /// [`NotADirectory`](Error::NotADirectory), and a symlink there gives the same
    /// error, also a symlink to a directory. `path` names a directory below the
    /// root, so the call cannot clear the root itself. With `allow_noent`, an
    /// absent directory gives `Ok`, also for an absent ancestor and a dangling
    /// intermediate symlink.
    ///
    /// The call never loads a committed directory that is not loaded yet. It
    /// replaces the entry with an empty loaded directory that keeps the recorded
    /// dirmeta checksum, so it reads no dirtree.
    ///
    /// # Errors
    ///
    /// - [`Error::NotADirectory`] if a file or a symlink is at `path`.
    /// - [`Error::PathNotFound`] if no entry is at `path` and `allow_noent` is
    ///   `false`.
    /// - [`Error::Staging`] if the call reaches a directory while any writer from
    ///   [`write_file`](StagingTree::write_file) is outstanding, at any place in
    ///   the tree. This applies also to an empty directory. A call over an absent
    ///   directory under `allow_noent` does not check the writers.
    /// - [`Error::Staging`] if `path` has no final component (the tree root),
    ///   ends in `..`, or has a component that is not UTF-8.
    /// - [`Error::PathNotFound`] or [`Error::DanglingSymlink`] if an ancestor does
    ///   not resolve and `allow_noent` is `false`.
    /// - [`Error::NotADirectory`] or [`Error::SymlinkLoop`] if an ancestor does
    ///   not resolve, also with `allow_noent`.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn clear_dir(&self, path: &Path, allow_noent: bool) -> Result<()> {
        let (parent, name) = match self.resolve_parent(path).await {
            Ok(resolved) => resolved,
            Err(Error::PathNotFound { .. } | Error::DanglingSymlink { .. }) if allow_noent => {
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        self.with_dir_mut(&parent, |dir| match dir.child_kind(&name) {
            ChildKind::Absent if allow_noent => Ok(()),
            ChildKind::Absent => Err(Error::PathNotFound {
                path: join(&parent, &name),
            }),
            ChildKind::File(_) => Err(Error::NotADirectory {
                path: join(&parent, &name),
            }),
            ChildKind::Dir => {
                self.check_no_live_writers(&format!(
                    "clear the directory at {}",
                    join(&parent, &name)
                ))?;
                let child = dir
                    .dir_at_mut(std::slice::from_ref(&name))
                    .expect("a loaded child under the same lock acquisition");
                child.clear_children();
                Ok(())
            }
            ChildKind::LazyDir { dirmeta, .. } => {
                self.check_no_live_writers(&format!(
                    "clear the directory at {}",
                    join(&parent, &name)
                ))?;
                dir.insert_empty_dir(&name, Some(dirmeta));
                Ok(())
            }
        })
    }

    /// Moves the entry at `from` to `to`, with its subtree and its dirmeta.
    ///
    /// The call follows neither final component, so the rename of a symlink moves
    /// the symlink. If an implied dirmeta is set
    /// ([`with_implied_dirmeta`](StagingTree::with_implied_dirmeta)), a missing
    /// destination parent is created. If no implied dirmeta is set, a missing
    /// destination parent is an error. The `from` side never creates a directory.
    ///
    /// The call moves the node as it is. A committed directory that is not loaded
    /// yet stays that way, and the call reads no dirtree for the moved subtree.
    ///
    /// The destination resolves before the call decides on a refusal, so a refused
    /// call keeps the ancestors that the implied-dirmeta policy created for it. Each
    /// write follows this rule. If the destination is under the moved entry,
    /// those ancestors are inside that entry. The call then loads a committed source
    /// directory to reach them, and the refusal reports any error of that
    /// resolution.
    ///
    /// # Errors
    ///
    /// - [`Error::EntryExists`] if an entry is at `to`.
    /// - [`Error::Staging`] if `to` is at or under the moved entry, because the
    ///   move detaches the directory that must receive the entry.
    /// - [`Error::Staging`] if any writer from
    ///   [`write_file`](StagingTree::write_file) is outstanding, at any place in
    ///   the tree.
    /// - [`Error::PathNotFound`] if no entry is at `from`.
    /// - [`Error::PathNotFound`], [`Error::NotADirectory`], [`Error::DanglingSymlink`],
    ///   or [`Error::SymlinkLoop`] if the path does not resolve.
    ///   [`StagingTree`](StagingTree#error-paths) states the path that each one
    ///   names.
    /// - [`Error::Staging`] if `from` or `to` has no final component, ends in
    ///   `..`, or has a component that is not UTF-8.
    /// - [`Error::Unsupported`] if the call stages a dirmeta object in a
    ///   `bare-split-xattrs` repository, or if its fs-verity seal fails under
    ///   `[ex-integrity] fsverity` = `yes`.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::InsufficientFreeSpace`] if a staged object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a `[core]`, `[archive]`, or
    ///   `[ex-integrity]` value in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let (from_parent, from_name) = self.resolve_parent(from).await?;
        let (to_parent, to_name) = self.resolve_write_parent(to).await?;
        let mut from_path = from_parent.clone();
        from_path.push(from_name.clone());
        // Both sides are resolved literal component paths, so the prefix
        // comparison is exact. The take detaches a destination parent at or
        // under the moved entry, and that parent cannot receive the entry.
        if to_parent.starts_with(&from_path) {
            return Err(Error::Staging(format!(
                "cannot rename {} to {}: the destination is under the moved entry",
                spell_path(&from_path),
                join(&to_parent, &to_name)
            )));
        }
        // Decide and move under one lock acquisition. The destination and
        // the source are read again, and the writer guard is read where the
        // entry is about to move. So no concurrent operation gets in between
        // the checks and the two mutations.
        let mut tree = self.tree.lock().unwrap();
        let to_dir = tree
            .dir_at(&to_parent)
            .ok_or_else(|| Error::Staging(dir_gone(&to_parent)))?;
        if !matches!(to_dir.child_kind(&to_name), ChildKind::Absent) {
            return Err(entry_exists(&to_parent, &to_name));
        }
        let from_dir = tree
            .dir_at_mut(&from_parent)
            .ok_or_else(|| Error::Staging(dir_gone(&from_parent)))?;
        if matches!(from_dir.child_kind(&from_name), ChildKind::Absent) {
            return Err(Error::PathNotFound {
                path: join(&from_parent, &from_name),
            });
        }
        self.check_no_live_writers(&format!(
            "rename {} to {}",
            join(&from_parent, &from_name),
            join(&to_parent, &to_name)
        ))?;
        let entry = from_dir
            .take_child(&from_name)
            .expect("an entry present under the same lock acquisition");
        // The entry is out of the tree here, so a failed insertion drops it.
        // Neither of the two refusals can occur. The name comes from a
        // `Component::Normal`, which `validate_name` accepts, and the
        // destination was read absent under this same acquisition.
        tree.dir_at_mut(&to_parent)
            .expect("a destination parent present under the same lock acquisition")
            .insert_child(&to_name, entry)
            .expect("a fresh name in a present directory under the same lock acquisition");
        Ok(())
    }

    // --- reads (staged-first) ---

    /// Returns the kind of entry at `path`.
    ///
    /// Intermediate components follow symlinks. The final component follows a
    /// symlink only with `follow_symlinks`. An absent component at any place on the
    /// path gives [`StagingLookup::Absent`], so a probe of a path with absent
    /// ancestors is not an error.
    ///
    /// # Errors
    ///
    /// - [`Error::NotADirectory`] if an intermediate component is not a directory.
    /// - [`Error::DanglingSymlink`] or [`Error::SymlinkLoop`] if a symlink on the
    ///   path does not resolve.
    /// - [`Error::Staging`] if a component of `path` is not UTF-8.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn lookup(&self, path: &Path, follow_symlinks: bool) -> Result<StagingLookup> {
        match self
            .walk_from(Vec::new(), components_of(path)?, follow_symlinks)
            .await
        {
            Ok(WalkEnd::Dir(_)) => Ok(StagingLookup::Dir),
            Ok(WalkEnd::Leaf { checksum, .. }) => Ok(StagingLookup::File { checksum }),
            Err(Error::PathNotFound { .. }) => Ok(StagingLookup::Absent),
            Err(e) => Err(e),
        }
    }

    /// Returns the file object at `path`.
    ///
    /// The path resolves through the staging tree. The bytes load from the staged
    /// set of the transaction before `objects/`. With `follow_symlinks`, a symlink
    /// at the final component resolves to its target.
    ///
    /// # Errors
    ///
    /// - [`Error::Staging`] if `path` names a directory.
    /// - [`Error::PathNotFound`], [`Error::NotADirectory`], [`Error::DanglingSymlink`],
    ///   or [`Error::SymlinkLoop`] if the path does not resolve.
    ///   [`StagingTree`](StagingTree#error-paths) states the path that each one
    ///   names.
    /// - [`Error::Staging`] if a component of `path` is not UTF-8.
    /// - [`Error::ObjectNotFound`] if the file object, a symlink object, or a
    ///   committed dirtree that the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn read_file(&self, path: &Path, follow_symlinks: bool) -> Result<FileObject> {
        match self
            .walk_from(Vec::new(), components_of(path)?, follow_symlinks)
            .await?
        {
            WalkEnd::Leaf { checksum, .. } => self.txn.load_file_staged_first(&checksum).await,
            WalkEnd::Dir(dir) => Err(Error::Staging(format!(
                "{} is a directory, not a file",
                spell_path(&dir)
            ))),
        }
    }

    /// Returns the entries of the directory at `path`.
    ///
    /// The files come first, then the subdirectories. Each group is sorted by name.
    /// With `follow_symlinks`, a symlink at the final component resolves to its
    /// target directory.
    ///
    /// # Errors
    ///
    /// - [`Error::NotADirectory`] if a file or a symlink that the call does not
    ///   follow is at `path`.
    /// - [`Error::PathNotFound`], [`Error::NotADirectory`], [`Error::DanglingSymlink`],
    ///   or [`Error::SymlinkLoop`] if the path does not resolve.
    ///   [`StagingTree`](StagingTree#error-paths) states the path that each one
    ///   names.
    /// - [`Error::Staging`] if a component of `path` is not UTF-8.
    /// - [`Error::ObjectNotFound`] if a symlink object or a committed dirtree that
    ///   the walk loads is not in the repository.
    /// - [`Error::Staging`] if a concurrent operation removes a directory on the
    ///   path while the call uses it.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn read_dir(&self, path: &Path, follow_symlinks: bool) -> Result<Vec<StagingEntry>> {
        let dir_path = match self
            .walk_from(Vec::new(), components_of(path)?, follow_symlinks)
            .await?
        {
            WalkEnd::Dir(p) => p,
            WalkEnd::Leaf {
                parent: dir, name, ..
            } => {
                return Err(Error::NotADirectory {
                    path: join(&dir, &name),
                });
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

    /// Merges `other` into the root of this tree.
    ///
    /// The call is [`merge_at`](StagingTree::merge_at) with the base `.`.
    ///
    /// # Errors
    ///
    /// The errors of [`merge_at`](StagingTree::merge_at).
    pub async fn merge(&self, other: &MutableTree, opts: MergeOptions) -> Result<()> {
        self.merge_at(Path::new("."), other, opts).await
    }

    /// Merges `other` into the directory at `base`, as `opts` sets.
    ///
    /// An equal entry makes no change. These differences are conflicts without
    /// `allow_overwrite`, and the right side wins them with it:
    ///
    /// - differing files
    /// - a file against a directory
    /// - differing directory metadata
    ///
    /// A merge that fails keeps the entries that it applied before the failure.
    ///
    /// # Symlinks
    ///
    /// With `follow_symlinks`, a right-side directory over a left-side symlink
    /// merges into the target directory of the symlink. A right-side file or
    /// symlink replaces the left entry and never writes through it.
    ///
    /// # Directory metadata
    ///
    /// [`root_dirmeta`](MergeOptions::root_dirmeta) controls the merge root alone.
    /// Under [`Reconcile`](RootDirmeta::Reconcile), the directory at `base`
    /// reconciles its own dirmeta against the dirmeta of the right root. Under
    /// [`KeepLeft`](RootDirmeta::KeepLeft), it keeps the dirmeta that it has.
    ///
    /// [`symlink_target_dirmeta`](MergeOptions::symlink_target_dirmeta) controls
    /// each directory that a followed left-side symlink lands in. Under
    /// [`KeepLeft`](RootDirmeta::KeepLeft), the target keeps its own dirmeta. Under
    /// [`Reconcile`](RootDirmeta::Reconcile), it reconciles against the dirmeta that
    /// the right side carries for the name of the symlink.
    ///
    /// [`RootDirmeta`] states the rules for each other directory and for a
    /// directory with no dirmeta.
    ///
    /// # Base
    ///
    /// If an implied dirmeta is set
    /// ([`with_implied_dirmeta`](StagingTree::with_implied_dirmeta)), a missing
    /// `base` is created with it. If no implied dirmeta is set, a missing `base` is
    /// an error of the walk. `base` resolves through symlinks before the merge
    /// starts, its final component included. If `base` is a symlink, its target
    /// directory is the merge root and takes `root_dirmeta`. A file at `base` and
    /// a symlink to a file there both give [`NotADirectory`](Error::NotADirectory).
    ///
    /// # Concurrency
    ///
    /// While any writer from [`write_file`](StagingTree::write_file) is
    /// outstanding, at any place in the tree, a merge that drops a directory fails.
    /// That directory and its subtree stay in place. Two cases drop a directory:
    ///
    /// - an overwrite that replaces a directory with a file
    /// - a right-side directory that arrives at a name where a concurrent operation
    ///   put a directory after the merge read the name
    ///
    /// Without `allow_overwrite`, each of these cases is a conflict, and the merge
    /// drops no directory.
    ///
    /// If a concurrent operation puts a leaf at a name that the merge already read,
    /// the merge overwrites the leaf, whatever `allow_overwrite` says. The other
    /// staging writes follow the same last-writer-wins rule on a raced name. The
    /// merge reads a name again only for a raced directory, because the drop of a
    /// directory loses a subtree.
    ///
    /// # Errors
    ///
    /// - [`Error::MergeConflict`] for a conflict without `allow_overwrite`.
    /// - [`Error::Staging`] if the merge drops a directory while any writer from
    ///   [`write_file`](StagingTree::write_file) is outstanding.
    /// - [`Error::NotADirectory`] if `base`, a component on its path, or the target
    ///   of a followed left-side symlink is a file or a symlink to a file.
    /// - [`Error::PathNotFound`], [`Error::DanglingSymlink`], or
    ///   [`Error::SymlinkLoop`] if `base` or a followed left-side symlink does not
    ///   resolve. [`StagingTree`](StagingTree#error-paths) states the path that each
    ///   one names.
    /// - [`Error::ReplaceDirWithFile`] if a concurrent operation puts a directory at
    ///   a name where the merge records a file.
    /// - [`Error::Staging`] if a component of `base` is not UTF-8.
    /// - [`Error::Unsupported`] if the call stages a dirmeta object in a
    ///   `bare-split-xattrs` repository, or if its fs-verity seal fails under
    ///   `[ex-integrity] fsverity` = `yes`.
    /// - [`Error::ObjectNotFound`] if a symlink object or a dirtree that the
    ///   merge loads on either side is not in the repository.
    /// - [`Error::Core`] if a dirtree that the merge loads is malformed.
    /// - [`Error::Staging`] if a concurrent operation removes a directory that the
    ///   merge uses.
    /// - [`Error::InsufficientFreeSpace`] if a staged object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a `[core]`, `[archive]`, or
    ///   `[ex-integrity]` value in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn merge_at(
        &self,
        base: &Path,
        other: &MutableTree,
        opts: MergeOptions,
    ) -> Result<()> {
        let base_path = self.resolve_merge_base(base).await?;
        merge_into(
            self,
            base_path,
            RightDir::Mutable(other),
            &opts,
            opts.root_dirmeta,
        )
        .await
    }

    // --- internal helpers ---

    /// Stages a directory-metadata object and returns its checksum.
    async fn stage_dirmeta(&self, meta: &DirMeta) -> Result<Checksum> {
        self.txn.write_dirmeta(meta).await
    }

    /// Refuses a structural change while any file writer is live.
    ///
    /// A structural change is a directory drop, an entry removal, a clear of
    /// the children of a directory, or an entry move. A writer records its entry at
    /// [`finish`](StagedFileWriter::finish) under the component path that it
    /// captured. A directory dropped in between makes that path stale, or
    /// makes it point at a different directory created there later. A removed
    /// file entry cannot make a captured path stale. The guard refuses it
    /// because the guard is the whole-tree form, which reads a count and no
    /// paths.
    ///
    /// `action` spells the refused change and the path that it targets. Call
    /// this under the tree lock, where
    /// [`write_file`](StagingTree::write_file) registers its writers, so the
    /// count read here cannot race a registration. The check also sees each
    /// deregistration: [`finish`](StagedFileWriter::finish) records its entry
    /// under this same lock before it decrements. So a zero count read here
    /// means that each departed writer recorded its entry. The comment in
    /// [`close`](StagingTree::close) states the full argument.
    fn check_no_live_writers(&self, action: &str) -> Result<()> {
        let outstanding = self.writers.load(Ordering::Acquire);
        if outstanding != 0 {
            return Err(Error::Staging(format!(
                "cannot {action}: {outstanding} file writer(s) still outstanding"
            )));
        }
        Ok(())
    }

    /// Fails if a write to a leaf at `parent/name` replaces a directory. The
    /// write replaces a file or symlink, and creates an absent entry.
    fn check_writable_leaf(&self, parent: &[String], name: &str) -> Result<()> {
        match self.peek(parent, name)? {
            ChildKind::Dir | ChildKind::LazyDir { .. } => {
                Err(Error::ReplaceDirWithFile(name.to_owned()))
            }
            _ => Ok(()),
        }
    }

    /// Resolves a merge base to its literal component path.
    ///
    /// With an implied dirmeta set, absent components become directories with
    /// that dirmeta. Without one, an absent component is the error that the
    /// walk types. Both walks follow symlinks to directories, the final
    /// component included. Both report a file in the way as
    /// [`NotADirectory`](Error::NotADirectory), and an absent component inside
    /// a symlink target as [`DanglingSymlink`](Error::DanglingSymlink).
    async fn resolve_merge_base(&self, base: &Path) -> Result<Vec<String>> {
        let comps = components_of(base)?;
        let Some(meta) = &self.implied_dirmeta else {
            return match self.walk_from(Vec::new(), comps, true).await? {
                WalkEnd::Dir(dir) => Ok(dir),
                WalkEnd::Leaf { parent, name, .. } => Err(Error::NotADirectory {
                    path: join(&parent, &name),
                }),
            };
        };
        self.walk_creating(comps, meta, false).await
    }

    /// Puts a fresh empty directory with `dirmeta` at `parent/name` for a
    /// merge.
    ///
    /// The merge read the entry in an earlier acquisition, so the mutating
    /// acquisition reads it again. Otherwise a directory that a concurrent
    /// operation put there since then is dropped with its subtree. That branch
    /// gives the two answers of a directory clash at each place in the merge.
    /// The order is the order of the merge: a conflict without
    /// `allow_overwrite`, and the writer guard with it.
    ///
    /// A file that the second read finds is overwritten, whatever
    /// `allow_overwrite` says. The second read exists to keep a subtree. A
    /// raced leaf follows the last-writer-wins rule that the other arms of the
    /// merge follow on a name that they already read.
    fn insert_merged_dir(
        &self,
        parent: &[String],
        name: &str,
        dirmeta: Option<Checksum>,
        allow_overwrite: bool,
    ) -> Result<()> {
        self.with_dir_mut(parent, |dir| {
            if matches!(
                dir.child_kind(name),
                ChildKind::Dir | ChildKind::LazyDir { .. }
            ) {
                if !allow_overwrite {
                    return Err(Error::MergeConflict(format!(
                        "a directory appeared at {} after the merge read the name",
                        join(parent, name)
                    )));
                }
                self.check_no_live_writers(&format!(
                    "drop the directory at {}",
                    join(parent, name)
                ))?;
            }
            dir.insert_empty_dir(name, dirmeta);
            Ok(())
        })
    }

    /// Resolves the parent directory of a path for a write. With an implied
    /// dirmeta set, absent ancestors become directories with that dirmeta.
    /// Without one, an absent ancestor is the error that the walk types.
    async fn resolve_write_parent(&self, path: &Path) -> Result<(Vec<String>, String)> {
        let Some(meta) = &self.implied_dirmeta else {
            return self.resolve_parent(path).await;
        };
        let (init, name) = split_final(path)?;
        let parent = self.walk_creating(init, meta, false).await?;
        Ok((parent, name))
    }

    /// Resolves the parent directory of a path, and returns its literal
    /// component path and the final name. Intermediate components follow
    /// symlinks.
    async fn resolve_parent(&self, path: &Path) -> Result<(Vec<String>, String)> {
        let (init, name) = split_final(path)?;
        let parent = match self.walk_from(Vec::new(), init, true).await? {
            WalkEnd::Dir(dir) => dir,
            WalkEnd::Leaf {
                parent: dir, name, ..
            } => {
                return Err(Error::NotADirectory {
                    path: join(&dir, &name),
                });
            }
        };
        Ok((parent, name))
    }

    /// Resolves a symlink `target` found in the directory `base` to a
    /// directory.
    async fn resolve_symlink_dir(&self, base: &[String], target: &str) -> Result<Vec<String>> {
        let (absolute, comps) = split_target(target)?;
        let start = if absolute { Vec::new() } else { base.to_vec() };
        match self.walk_from(start, comps, true).await? {
            WalkEnd::Dir(dir) => Ok(dir),
            WalkEnd::Leaf {
                parent: dir, name, ..
            } => Err(Error::NotADirectory {
                path: join(&dir, &name),
            }),
        }
    }

    /// Walks `comps` from the loaded directory `start` through symlinks, and
    /// returns the directory or the leaf that the path names. With
    /// `follow_final`, the walk also follows a final symlink.
    async fn walk_from(
        &self,
        start: Vec<String>,
        comps: Vec<Comp>,
        follow_final: bool,
    ) -> Result<WalkEnd> {
        let mut cur = start;
        let mut pending: VecDeque<Comp> = comps.into();
        let mut symlink_depth = 0usize;
        // Each entry is a symlink whose target components the walk still
        // consumes. An entry holds its path, its target, and the pending length
        // to return to after the target is spent. A failure belongs to the
        // innermost open entry.
        let mut open_symlinks: Vec<(String, String, usize)> = Vec::new();

        while let Some(comp) = pending.pop_front() {
            // Drop each symlink whose target is spent. The walk is back on the
            // components of the caller, so an absent entry is not a dangling
            // target.
            while open_symlinks
                .last()
                .is_some_and(|(_, _, mark)| pending.len() < *mark)
            {
                open_symlinks.pop();
            }
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
                    return Err(match open_symlinks.last() {
                        Some((path, target, _)) => Error::DanglingSymlink {
                            path: path.clone(),
                            target: target.clone(),
                        },
                        None => Error::PathNotFound {
                            path: join(&cur, &name),
                        },
                    });
                }
                ChildKind::Dir | ChildKind::LazyDir { .. } => {
                    self.ensure_child_dir(&cur, &name).await?;
                    cur.push(name);
                }
                ChildKind::File(checksum) => {
                    if is_final && !follow_final {
                        return Ok(WalkEnd::Leaf {
                            parent: cur,
                            name,
                            checksum,
                        });
                    }
                    let obj = self.txn.load_file_staged_first(&checksum).await?;
                    match obj.kind {
                        FileKind::Symlink { target } => {
                            symlink_depth += 1;
                            if symlink_depth > MAX_SYMLINK_DEPTH {
                                return Err(Error::SymlinkLoop {
                                    path: join(&cur, &name),
                                });
                            }
                            let (absolute, target_comps) = split_target(&target)?;
                            // The mark is the count of the components queued
                            // behind this target: the components of the
                            // caller, plus the target remainder of any outer
                            // symlink.
                            let mark = pending.len();
                            open_symlinks.push((join(&cur, &name), target.clone(), mark));
                            if absolute {
                                cur.clear();
                            }
                            for comp in target_comps.into_iter().rev() {
                                pending.push_front(comp);
                            }
                        }
                        FileKind::Regular { .. } => {
                            if is_final {
                                return Ok(WalkEnd::Leaf {
                                    parent: cur,
                                    name,
                                    checksum,
                                });
                            }
                            return Err(Error::NotADirectory {
                                path: join(&cur, &name),
                            });
                        }
                    }
                }
            }
        }
        Ok(WalkEnd::Dir(cur))
    }

    /// Makes sure that the child `name` under the loaded directory `path` is
    /// a loaded directory. The call loads a committed subdirectory that is
    /// not loaded yet. It fails if the child is absent or is not a directory.
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
                        Error::Staging(format!(
                            "cannot hydrate {}: no repository handle",
                            join(path, name)
                        ))
                    })?;
                    let loaded = MutableTree::hydrate(&repo, dirtree, dirmeta).await?;
                    let mut tree = self.tree.lock().unwrap();
                    if let Some(dir) = tree.dir_at_mut(path)
                        && matches!(dir.child_kind(name), ChildKind::LazyDir { .. })
                    {
                        dir.install_hydrated_child(name, loaded);
                    }
                    // Loop to read again. The child is a loaded directory now.
                }
                ChildKind::File(_) => {
                    return Err(Error::NotADirectory {
                        path: join(path, name),
                    });
                }
                ChildKind::Absent => {
                    return Err(Error::PathNotFound {
                        path: join(path, name),
                    });
                }
            }
        }
    }

    /// Returns the kind of `name` under the loaded directory `path`, under the
    /// lock.
    fn peek(&self, path: &[String], name: &str) -> Result<ChildKind> {
        let tree = self.tree.lock().unwrap();
        let dir = tree
            .dir_at(path)
            .ok_or_else(|| Error::Staging(dir_gone(path)))?;
        Ok(dir.child_kind(name))
    }

    /// Runs `f` against the loaded directory at `path` under the lock.
    fn with_dir<R>(&self, path: &[String], f: impl FnOnce(&MutableTree) -> R) -> Result<R> {
        let tree = self.tree.lock().unwrap();
        let dir = tree
            .dir_at(path)
            .ok_or_else(|| Error::Staging(dir_gone(path)))?;
        Ok(f(dir))
    }

    /// Runs `f` against the mutable loaded directory at `path` under the lock.
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

/// A read-only directory view for the right side of a merge. It is an
/// in-memory mutable tree node, or a committed subtree that loads through the
/// transaction on demand. A committed subtree resolves staged-first, so a
/// dirtree staged in the current transaction is visible before it publishes.
/// The left side follows the same rule.
enum RightDir<'a> {
    Mutable(&'a MutableTree),
    Committed {
        txn: &'a Transaction,
        dirtree: Checksum,
        dirmeta: Checksum,
    },
}

impl<'a> RightDir<'a> {
    /// Returns the dirmeta checksum of this directory, if it has one.
    fn dirmeta(&self) -> Option<Checksum> {
        match self {
            RightDir::Mutable(tree) => tree.metadata_checksum(),
            RightDir::Committed { dirmeta, .. } => Some(*dirmeta),
        }
    }

    /// Returns the files and the subdirectories of this directory. A
    /// committed directory is read through `txn` (staged-first). An in-memory
    /// node is read directly. `txn` is the transaction that the committed
    /// view of a lazy child resolves through.
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

/// The boxed future for the recursive merge. Async recursion needs
/// indirection.
type MergeFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Merges the right-side directory `right` into the left staging tree at
/// `left_path`.
///
/// `root_dirmeta` is the policy for the metadata of `left_path` itself. The
/// merge root takes [`MergeOptions::root_dirmeta`]. The directory that a
/// followed left-side symlink lands in takes
/// [`MergeOptions::symlink_target_dirmeta`]. Each other descendant
/// reconciles, so the recursion passes [`RootDirmeta::Reconcile`] for it.
fn merge_into<'a>(
    st: &'a StagingTree<'_>,
    left_path: Vec<String>,
    right: RightDir<'a>,
    opts: &'a MergeOptions,
    root_dirmeta: RootDirmeta,
) -> MergeFuture<'a> {
    Box::pin(async move {
        // Reconcile the metadata of this directory. A right dirmeta that is
        // unset makes no change, and one that equals the left makes no change.
        // A differing one is a conflict without `allow_overwrite`, and the
        // directory takes it with `allow_overwrite`. Under `KeepLeft` this
        // directory skips the step and keeps the dirmeta that it has.
        if matches!(root_dirmeta, RootDirmeta::Reconcile)
            && let Some(right_dm) = right.dirmeta()
        {
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
                        "directory metadata differs at {}",
                        spell_path(&left_path)
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
                            "file differs at {}",
                            join(&left_path, &name)
                        )));
                    }
                    st.with_dir_mut(&left_path, |dir| dir.replace_file(&name, right_csum))?;
                }
                ChildKind::Dir | ChildKind::LazyDir { .. } => {
                    if !opts.allow_overwrite {
                        return Err(Error::MergeConflict(format!(
                            "a file cannot overwrite the directory at {}",
                            join(&left_path, &name)
                        )));
                    }
                    st.with_dir_mut(&left_path, |dir| {
                        st.check_no_live_writers(&format!(
                            "drop the directory at {}",
                            join(&left_path, &name)
                        ))?;
                        dir.remove(&name, true)?;
                        dir.replace_file(&name, right_csum)
                    })?;
                }
            }
        }

        for (name, right_child) in rdirs {
            match st.peek(&left_path, &name)? {
                ChildKind::Absent => {
                    st.insert_merged_dir(
                        &left_path,
                        &name,
                        right_child.dirmeta(),
                        opts.allow_overwrite,
                    )?;
                    let mut child_path = left_path.clone();
                    child_path.push(name);
                    merge_into(st, child_path, right_child, opts, RootDirmeta::Reconcile).await?;
                }
                ChildKind::Dir | ChildKind::LazyDir { .. } => {
                    st.ensure_child_dir(&left_path, &name).await?;
                    let mut child_path = left_path.clone();
                    child_path.push(name);
                    merge_into(st, child_path, right_child, opts, RootDirmeta::Reconcile).await?;
                }
                ChildKind::File(left_csum) => {
                    if opts.follow_symlinks {
                        let obj = st.txn.load_file_staged_first(&left_csum).await?;
                        if let FileKind::Symlink { target } = obj.kind {
                            let target_dir = st.resolve_symlink_dir(&left_path, &target).await?;
                            merge_into(
                                st,
                                target_dir,
                                right_child,
                                opts,
                                opts.symlink_target_dirmeta,
                            )
                            .await?;
                            continue;
                        }
                    }
                    if !opts.allow_overwrite {
                        return Err(Error::MergeConflict(format!(
                            "a directory cannot overwrite the file at {}",
                            join(&left_path, &name)
                        )));
                    }
                    st.insert_merged_dir(
                        &left_path,
                        &name,
                        right_child.dirmeta(),
                        opts.allow_overwrite,
                    )?;
                    let mut child_path = left_path.clone();
                    child_path.push(name);
                    merge_into(st, child_path, right_child, opts, RootDirmeta::Reconcile).await?;
                }
            }
        }
        Ok(())
    })
}

/// A streaming writer for one regular-file payload of a staging tree.
///
/// [`finish`](StagedFileWriter::finish) records the file in the tree. The writer
/// shares the tree and the writer count with its [`StagingTree`] through `Arc`,
/// so it does not borrow the tree. It implements `futures_io::AsyncWrite`
/// always, and the tokio `AsyncWrite` under the `tokio` feature. If the writer
/// is dropped without `finish`, it removes the staged temporary file and
/// releases its writer slot.
pub struct StagedFileWriter<'txn> {
    tree: Arc<Mutex<MutableTree>>,
    writers: Arc<AtomicUsize>,
    writer: Option<ContentWriter<'txn>>,
    parent: Vec<String>,
    name: String,
}

impl StagedFileWriter<'_> {
    /// Completes the content object and records it at the path of the writer.
    ///
    /// The call releases the writer slot on every return.
    ///
    /// # Errors
    ///
    /// - [`Error::ReplaceDirWithFile`] if a directory is at the path.
    /// - [`Error::Staging`] if a concurrent operation removed the parent directory.
    /// - [`Error::Unsupported`] if `[ex-integrity] fsverity` is `yes` and the
    ///   fs-verity seal of the object fails.
    /// - [`Error::InsufficientFreeSpace`] if a staged object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a `[core]`, `[archive]`, or
    ///   `[ex-integrity]` value in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
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
        // An abandoned writer (dropped without `finish`) still releases its
        // slot, so it never makes `close` fail. The content writer removes its
        // staged temporary file when it drops.
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

/// Returns the meaningful components of a path: names and parent-directory
/// hops. The root, current-directory, and prefix components are dropped. A
/// non-UTF-8 component is rejected, because the tree is `String`-keyed and a
/// lossy conversion addresses the wrong name with no error.
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

/// Splits a path into its parent components and its final name. The call
/// refuses a path with no final component and a path that ends in `..`. The
/// refusal comes before resolution, so it reports the path as the caller gave
/// it.
fn split_final(path: &Path) -> Result<(Vec<Comp>, String)> {
    let mut comps = components_of(path)?;
    let name = match comps.pop() {
        Some(Comp::Normal(name)) => name,
        Some(Comp::Parent) => {
            return Err(Error::Staging(format!("{} ends in `..`", path.display())));
        }
        None => {
            return Err(Error::Staging(format!(
                "{} has no final component",
                path.display()
            )));
        }
    };
    Ok((comps, name))
}

/// Splits a symlink target into an absolute flag and its meaningful
/// components. The target is UTF-8 already, so the decode of a component
/// never fails.
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

/// A whole component path spelled for a message. The tree root has no
/// components, so it spells as `.`.
fn spell_path(path: &[String]) -> String {
    if path.is_empty() {
        ".".to_owned()
    } else {
        path.join("/")
    }
}

/// The message for a directory that is no longer present under the lock.
fn dir_gone(path: &[String]) -> String {
    format!("directory {} is no longer present", spell_path(path))
}

/// The refusal for an operation that requires a fresh entry at `parent/name`.
fn entry_exists(parent: &[String], name: &str) -> Error {
    Error::EntryExists {
        path: join(parent, name),
    }
}

/// The staging-tree types move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<StagingTree<'static>>();
    assert_send_sync::<StagedFileWriter<'static>>();
    assert_send_sync::<StagingEntry>();
    assert_send_sync::<StagingLookup>();
    assert_send_sync::<MergeOptions>();
    assert_send_sync::<RootDirmeta>();
};

#[cfg(feature = "tokio")]
const _: fn() = || {
    fn assert_tokio_write<T: ostrya_rt::tokio_io::AsyncWrite>() {}
    assert_tokio_write::<StagedFileWriter<'static>>();
};
