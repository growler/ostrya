//! Export of a commit as a composefs EROFS image.
//!
//! - [`Repo::export_composefs`] builds the image in memory and returns its
//!   bytes and its fs-verity digest.
//! - [`Repo::export_composefs_to`] writes the image through a file
//!   descriptor.
//! - [`Repo::commit_add_composefs_metadata`] stages a new commit that records
//!   the image digest under `ostree.composefs.digest.v0`.
//! - [`Transaction::composefs_digest`] returns the image digest of a staged
//!   tree.
//! - [`Transaction::write_composefs_content`] stages the image of a staged
//!   tree as a regular content object.
//! - [`Transaction::write_composefs_commit`] stages the composefs image commit
//!   of a staged tree, and [`Repo::open_composefs_image`] opens the image of
//!   the image commit that a commit names.
//! - [`Repo::objects_dir`] gives the descriptor of the object store. A
//!   composefs mount reads the backing objects of the image through it.
//!
//! [`ComposefsOptions`] and [`VerityPolicy`] select the verity form of the
//! image.

use std::collections::{HashMap, btree_map};
use std::future::Future;
use std::io::{BufWriter, Seek, SeekFrom};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use ostrya_composefs::{
    Content, Directory, Error as WriterError, FsVerityHasher, Image, Metadata, Node, Regular,
    Symlink, build_image, write_image_to, write_image_unhashed_to,
};
use ostrya_core::{
    Checksum, Commit, DirMeta, DirTree, ObjectType, RepoMode, Type, Value, Xattrs, loose_path,
};
use ostrya_rt::FileReader;

use crate::commit::append_dict_entry;
use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject};
use crate::related::{self, RelationField};
use crate::repo::Repo;
use crate::repo_fs::{RepoDir, TempFile};
use crate::transaction::Transaction;
use crate::tree::RepoTree;
use crate::write::FileMeta;

/// The empty top-level directories that the `ostree` command adds to each
/// exported image.
const INJECTED_DIRS: [&str; 5] = ["boot", "etc", "sysroot", "usr", "var"];
/// The mode that the `ostree` command gives each added top-level directory
/// (`040755`).
const INJECTED_DIR_MODE: u32 = 0o040755;
/// The commit metadata key that holds the fs-verity digest of the image.
pub const COMPOSEFS_DIGEST_KEY: &str = "ostree.composefs.digest.v0";
/// The GVariant type of the digest value, a 32-byte `ay`.
const DIGEST_SIGNATURE: &str = "ay";
/// The size of each chunk that the hasher reads from a backing object.
pub(crate) const DIGEST_CHUNK: usize = 128 * 1024;
/// The bytes that one xattr spends from the composefs xattr budget of an
/// inode, in addition to its name and its value.
const XATTR_ENTRY_COST: usize = 7;
/// The composefs xattr budget of one inode, in bytes.
const MAX_XATTR_TOTAL: usize = 32755;
/// The longest xattr name that the length field of an EROFS entry can state.
/// The entry stores the name without its prefix, and this suffix is not longer
/// than the full name. The check holds the full name to this bound, so the
/// prefix table stays in the writer.
const MAX_XATTR_NAME: usize = u8::MAX as usize;
/// The repository mode of the loose path that each backing redirect names. The
/// image points at the `.file` objects of a composefs backing store, whatever
/// the mode of the repository that the image comes from.
const BACKING_MODE: RepoMode = RepoMode::BareUser;

/// A boxed `Send` future for the recursive tree walk. Async recursion needs
/// this indirection.
type TreeFuture<'a> = Pin<Box<dyn Future<Output = Result<Directory>> + Send + 'a>>;

/// The place where the composefs walk reads the objects of the tree.
#[derive(Clone, Copy)]
enum ObjectSource<'a> {
    /// A published repository: each object is a loose object under `objects/`.
    Repo(&'a Repo),
    /// A transaction: an object that it staged comes from the staging
    /// directory. An object that deduplicated comes from `objects/`.
    Staged(&'a Transaction),
}

impl ObjectSource<'_> {
    async fn dirtree(&self, checksum: &Checksum) -> Result<DirTree> {
        match self {
            ObjectSource::Repo(repo) => repo.load_dirtree(checksum).await,
            ObjectSource::Staged(txn) => txn.load_dirtree_staged_first(checksum).await,
        }
    }

    async fn dirmeta(&self, checksum: &Checksum) -> Result<DirMeta> {
        match self {
            ObjectSource::Repo(repo) => repo.load_dirmeta(checksum).await,
            ObjectSource::Staged(txn) => txn.load_dirmeta_staged_first(checksum).await,
        }
    }

    /// Loads a file object. If `measure` is set, the same load also reads the
    /// fs-verity digest that the kernel holds for a sealed raw-payload object.
    async fn file(&self, checksum: &Checksum, measure: bool) -> Result<FileObject> {
        match self {
            ObjectSource::Repo(repo) => repo.load_file_with(checksum, measure).await,
            ObjectSource::Staged(txn) => txn.load_file_staged_first_with(checksum, measure).await,
        }
    }
}

/// The verity form of an exported composefs image.
///
/// The policy selects if each backed file carries the fs-verity digest of its
/// content. The export opens each backing object under both policies. The
/// mode, the owner, the size, and the xattrs of the inode come from the file
/// object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerityPolicy {
    /// Each backed file carries the 36-byte metacopy record with the fs-verity
    /// digest of its content.
    ///
    /// This policy is the default.
    ///
    /// If a backing object is sealed with the parameters that
    /// [`Repo::export_composefs`] states, the export reads the digest from the
    /// kernel. For each other backing object, the export streams the payload
    /// to compute the digest.
    #[default]
    Computed,
    /// Each backed file carries the metacopy xattr with an empty value.
    ///
    /// The export reads no payload.
    ///
    /// The image has its own fs-verity digest. This digest is different from
    /// the value that a commit records under `ostree.composefs.digest.v0`.
    /// The recorded value is the digest of the image with verity digests.
    /// [`ComposefsOptions::RECORDED`] gives the options of that image.
    Disabled,
}

/// The options of a composefs export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ComposefsOptions {
    /// The verity policy of the image.
    ///
    /// The default is [`VerityPolicy::Computed`].
    pub verity: VerityPolicy,
}

impl ComposefsOptions {
    /// The options of the image whose fs-verity digest a commit records.
    ///
    /// `ostree.composefs.digest.v0` holds the fs-verity digest of the image
    /// that [`Repo::export_composefs`] and [`Repo::export_composefs_to`] write
    /// with these options and no hook. A target machine computes the same
    /// digest at boot.
    ///
    /// The policy is [`VerityPolicy::Computed`]. Each backed file in the image
    /// carries the fs-verity digest of its content, so the image digest covers
    /// the content of each backed file.
    /// [`Repo::commit_add_composefs_metadata`] and
    /// [`Transaction::composefs_digest`] use these options, so a change of the
    /// default does not change the recorded digest.
    pub const RECORDED: ComposefsOptions = ComposefsOptions {
        verity: VerityPolicy::Computed,
    };
}

/// The kind of an inode of a composefs image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// A directory.
    Directory,
    /// A regular file.
    Regular,
    /// A symbolic link.
    Symlink,
}

/// A hook that a composefs export calls for each node of the tree.
///
/// The export calls the hook one time for each node of the tree, and for each
/// top-level directory that the export adds. The whiteout stubs of the image
/// get no call. The hook gets the absolute path of the node in the image, the
/// kind of the node, and its [`Metadata`]. It can change the mode, the owner, the mtime,
/// and the xattrs. If the hook returns an error, the export stops and returns
/// that error.
pub type ComposefsEntryFn<'a> = &'a (dyn Fn(&Path, EntryKind, &mut Metadata) -> Result<()> + Sync);

/// The inputs of one walk of a tree that are the same for each node.
#[derive(Clone, Copy)]
struct Walk<'a> {
    /// The place where the walk reads the objects of the tree.
    source: ObjectSource<'a>,
    /// The way the walk gets the fs-verity digest of each backed file.
    digests: Digests,
    /// The hook of the caller, if it gave one.
    filter: Option<ComposefsEntryFn<'a>>,
}

impl Walk<'_> {
    /// Gives `meta` of the node at `path` to the hook, if the walk has one,
    /// and then checks the xattrs of the result. An error of the hook goes
    /// back unchanged.
    fn entry(&self, path: &Path, kind: EntryKind, meta: &mut Metadata) -> Result<()> {
        if let Some(filter) = self.filter {
            filter(path, kind, meta)?;
        }
        check_xattrs(&meta.xattrs)
    }
}

/// The way the export gets the fs-verity digest of each backed file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Digests {
    /// The digest that the kernel holds for a sealed object, or else the
    /// digest of the streamed payload. [`VerityPolicy::Computed`] gives it.
    Computed,
    /// The digest that the kernel holds for a sealed object. An object with
    /// no seal is refused, and no payload is read.
    Sealed,
    /// No digest. [`VerityPolicy::Disabled`] gives it.
    Disabled,
}

/// The fs-verity digests that one walk of a tree computed for one image
/// model, keyed by the checksum of the file object.
///
/// When several paths of the tree name one object, the walk reads and hashes
/// the object one time. A digest that the kernel gives for a sealed object
/// does not go into the cache, because the load of the object reads it at no
/// cost.
#[derive(Default)]
struct VerityCache {
    digests: HashMap<Checksum, [u8; 32]>,
    /// The number of objects that the cache read and hashed.
    #[cfg(test)]
    hashed: usize,
}

impl From<VerityPolicy> for Digests {
    fn from(policy: VerityPolicy) -> Digests {
        match policy {
            VerityPolicy::Computed => Digests::Computed,
            VerityPolicy::Disabled => Digests::Disabled,
        }
    }
}

/// Methods that compute the composefs digest of a staged tree and stage its
/// image as a content object.
impl Transaction {
    /// Returns the composefs image digest of a tree that this transaction
    /// staged.
    ///
    /// The value is the one that `ostree.composefs.digest.v0` holds: the
    /// fs-verity digest of the image that an export with
    /// [`ComposefsOptions::RECORDED`] and no hook writes for the same tree.
    /// [`Repo::export_composefs`] describes the image.
    ///
    /// The call reads each object that this transaction staged from the
    /// staging directory, and each other object from `objects/`. The digest is
    /// available before the transaction commit, so it can go into the metadata
    /// of the commit that the tree belongs to. The value depends on the tree
    /// alone, so a repository of any mode that holds the tree gives the same
    /// digest.
    ///
    /// The image goes to [`std::io::sink`], so the digest needs no image-sized
    /// buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if a dirtree, dirmeta, or file object of the
    ///   tree is in neither the staging directory nor the object store.
    /// - [`Error::Core`] if a dirtree object, a dirmeta object, or the header
    ///   of a file object does not parse.
    /// - [`Error::InvalidFormat`] if a file object does not have the form of
    ///   the repository mode. [`Repo::load_file`] lists the cases.
    /// - [`Error::Unsupported`] if the tree does not fit a limit of the image.
    ///   [`Repo::export_composefs`] lists the limits.
    /// - [`Error::InvalidFormat`] if a metadata object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or is not a regular
    ///   file, or if a symlink is on its path.
    /// - [`Error::Io`] if a file system operation fails, or if an `archive`
    ///   payload does not inflate.
    pub async fn composefs_digest(&self, root: &RepoTree) -> Result<[u8; 32]> {
        let walk = Walk {
            source: ObjectSource::Staged(self),
            digests: ComposefsOptions::RECORDED.verity.into(),
            filter: None,
        };
        let dir = composefs_model(walk, root, &mut VerityCache::default()).await?;
        image_digest(dir).await
    }

    /// Writes the composefs image of a tree that this transaction staged as a
    /// regular content object.
    ///
    /// The call returns the checksum of the content object and the fs-verity
    /// digest of the image. The image is the image that an export with `opts`
    /// and the hook `filter` writes for the same tree
    /// ([`Repo::export_composefs`]). The call reads the objects of the tree as
    /// [`composefs_digest`](Transaction::composefs_digest) reads them.
    ///
    /// `filter` is a hook, as in [`Repo::export_composefs`]. The hook gets one
    /// call for each node of the tree, and for each top-level directory that
    /// the call adds to the image. The whiteout stubs of the image get no
    /// call. With `None`, the call uses no hook.
    ///
    /// `meta` is the owner, the mode, and the xattrs of the content object.
    /// The caller sets them.
    ///
    /// The call writes the image in two steps, and each step holds no
    /// image-sized buffer:
    ///
    /// 1. On the blocking pool, the writer writes the image to an unnamed temp
    ///    file of the staging directory and computes the fs-verity digest as
    ///    it writes. The call does not seal and does not sync this file.
    /// 2. The call streams the temp file into a content object with
    ///    [`write_content`](Transaction::write_content). The content writer
    ///    applies the form of the repository mode, the fs-verity seal, and
    ///    the sync of the transaction, and counts the object in the
    ///    free-space budget.
    ///
    /// The image therefore goes to disk two times. The temp file goes away
    /// when the call returns. In an `archive` repository, the content object
    /// is a `.filez` object.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`.
    ///   The call refuses this mode before it reads the tree.
    /// - The errors of [`composefs_digest`](Transaction::composefs_digest).
    /// - [`Error::Unsupported`] if the xattrs of an inode after `filter` do
    ///   not fit a limit of the image, or if they hold an empty name, a name
    ///   with a NUL byte, or one name two times.
    /// - The error that `filter` returns.
    /// - The errors of [`write_content`](Transaction::write_content).
    /// - [`Error::Io`] if the create of the temp file, a write to it, or a
    ///   read from it fails.
    pub async fn write_composefs_content(
        &self,
        root: &RepoTree,
        opts: &ComposefsOptions,
        filter: Option<ComposefsEntryFn<'_>>,
        meta: &FileMeta,
    ) -> Result<(Checksum, [u8; 32])> {
        if self.repo().mode() == RepoMode::BareSplitXattrs {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
        let walk = Walk {
            source: ObjectSource::Staged(self),
            digests: opts.verity.into(),
            filter,
        };
        let dir = composefs_model(walk, root, &mut VerityCache::default()).await?;
        let staging = self.staging_dir().clone();
        let (file, size, digest) = self
            .unblock(move || write_scratch_image_blocking(&staging, &dir))
            .await?;
        let checksum = self
            .write_content(None, meta, FileReader::with_len_hint(file, size))
            .await?;
        Ok((checksum, digest))
    }
}

/// Methods that export a commit as a composefs image.
impl Repo {
    /// Builds the composefs EROFS image of `commit` in memory.
    ///
    /// The returned [`Image`] holds the bytes of the image and its fs-verity
    /// digest. With [`ComposefsOptions::RECORDED`] and no hook (`filter` is
    /// `None`), the digest is the value that
    /// [`commit_add_composefs_metadata`](Repo::commit_add_composefs_metadata)
    /// records for the tree of the commit. Under [`VerityPolicy::Disabled`],
    /// the digest is different from that value. The image assembly runs on the
    /// blocking pool.
    ///
    /// `filter` is a hook that the export calls one time for each node of the
    /// tree, and for each top-level directory that the export adds. The
    /// whiteout stubs of the image get no call. With `None`, the export calls
    /// no hook.
    ///
    /// # Tree model
    ///
    /// The export reads the root tree of the commit. It turns each entry into
    /// a node of the image:
    ///
    /// - A directory gets the mode, the owner, and the xattrs of its dirmeta
    ///   object.
    /// - A symlink stores its target inline.
    /// - An empty regular file has no backing.
    /// - A regular file with content redirects to the loose path of its
    ///   `.file` object, with a leading `/`. Under
    ///   [`VerityPolicy::Computed`], it also carries the fs-verity digest of
    ///   its content.
    ///
    /// The export sets the mtime of each inode to 0, as the `ostree` command
    /// does. It adds the five empty top-level directories that the `ostree`
    /// command adds: `boot`, `etc`, `sysroot`, `usr`, and `var`. Each one has
    /// the mode `040755` and the uid and gid 0. If the root of the commit
    /// already holds one of these names, the entry of the commit stays.
    ///
    /// # Verity digests
    ///
    /// Under [`VerityPolicy::Computed`], the export gets the fs-verity digest
    /// of each backed file in one of two ways:
    ///
    /// - If the object file is the raw payload and `statx` reports its inode
    ///   as sealed, the export reads the digest from the kernel. The seal must
    ///   name SHA-256, 4096-byte blocks, no salt, and the payload size. A
    ///   repository with `[ex-integrity] fsverity` seals with these parameters.
    ///   The read occurs in the blocking-pool call that loads the metadata of
    ///   the object.
    /// - In all other cases, and if the kernel read fails, the export streams
    ///   the payload through the fs-verity hasher in chunks of 128 KiB. It
    ///   buffers no unconstrained blob.
    ///
    /// The export never reads the digest of an `archive` object from the
    /// kernel. The digest of a `.filez` file covers the stored form of the
    /// object, and the image needs the digest of the content.
    ///
    /// The kernel read takes no payload byte, so it does not find damage to
    /// the data or the verity metadata of a sealed object. [`Repo::fsck`] is
    /// the check for object integrity.
    ///
    /// # Repository modes
    ///
    /// The export runs in every repository mode. The EROFS metadata of each
    /// file comes from the file object, as [`Repo::load_file`] reads it in the
    /// mode of the repository. The image stores the logical uid and gid of
    /// each file, whoever runs the export. composefs presents the ownership
    /// through uid mapping at mount.
    ///
    /// The image depends on the committed tree alone. Each regular file
    /// redirects to its `.file` loose path, the form that a composefs backing
    /// store holds. Each digest covers the content of the file, so a
    /// repository of any mode that holds the tree gives the same image and
    /// digest.
    ///
    /// An `archive` repository holds its content objects in `.filez` form. An
    /// image exported from it mounts over a store that holds the same objects
    /// in `.file` form. A `bare-user` repository that pulls the tree is an
    /// example.
    ///
    /// # Limits
    ///
    /// The image cannot hold some trees. The export refuses each of these trees
    /// with [`Error::Unsupported`]:
    ///
    /// - An inode with too many bytes of extended attributes. Each attribute
    ///   spends its name, its value, and 7 bytes from a budget of 32755 bytes
    ///   for the inode. The `ostree` command refuses a tree that spends more.
    ///   At boot, the `ostree` command cannot reproduce a composefs digest of
    ///   such a tree.
    ///   The budget is less than the 65535 bytes that the value-length field
    ///   of an EROFS xattr entry can state, so that field never limits first.
    /// - An xattr name longer than 255 bytes, the limit of the name-length
    ///   field of an EROFS xattr entry. The budget alone does not hold a name
    ///   to this length.
    /// - A symlink target that does not fit in the block of its inode. The
    ///   image stores the target inline, next to the inode header and the
    ///   xattrs of the inode. For a symlink with no xattrs, the limit is 4063
    ///   bytes. The `ostree` command aborts on the same trees. `PATH_MAX` keeps
    ///   a target this long out of a tree that a checkout produces. A tar
    ///   import can produce one.
    /// - A child name longer than 255 bytes. The `ostree` command refuses the
    ///   same trees with `File name too long`. A file system holds no name
    ///   this long. A tar import can produce one.
    /// - A child name that is empty, is `.` or `..`, or holds `/`.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the commit object, or a dirtree,
    ///   dirmeta, or file object of its tree, is not in the object store.
    /// - [`Error::Core`] if the commit object, a dirtree object, a dirmeta
    ///   object, or the header of a file object does not parse.
    /// - [`Error::InvalidFormat`] if a file object does not have the form of
    ///   the repository mode. [`Repo::load_file`] lists the cases.
    /// - [`Error::Unsupported`] if the tree does not fit a limit of the image.
    /// - [`Error::Unsupported`] if the xattrs of an inode after `filter` do
    ///   not fit a limit of the image, or if they hold an empty name, a name
    ///   with a NUL byte, or one name two times.
    /// - The error that `filter` returns.
    /// - [`Error::InvalidFormat`] if a metadata object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or is not a regular
    ///   file, or if a symlink is on its path.
    /// - [`Error::Io`] if a file system operation fails, or if an `archive`
    ///   payload does not inflate.
    pub async fn export_composefs(
        &self,
        commit: &Checksum,
        opts: &ComposefsOptions,
        filter: Option<ComposefsEntryFn<'_>>,
    ) -> Result<Image> {
        let dir = self
            .composefs_export_model(commit, opts.verity.into(), filter)
            .await?;
        ostrya_rt::unblock(move || build_image(&dir))
            .await
            .map_err(writer_error)
    }

    /// Writes the composefs image of `commit` to `out` and returns its digest.
    ///
    /// The image and its fs-verity digest are the same as those of
    /// [`export_composefs`](Repo::export_composefs), with the same options,
    /// the same hook `filter`, the same repository modes, and the same limits.
    ///
    /// The call writes the image to the file descriptor as it serializes it.
    /// The output is append-only, so the call holds no image-sized buffer. It
    /// writes `out` from its current offset and never seeks it. If the call
    /// fails, the bytes that it already wrote stay in `out`.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the commit object, or a dirtree,
    ///   dirmeta, or file object of its tree, is not in the object store.
    /// - [`Error::Core`] if the commit object, a dirtree object, a dirmeta
    ///   object, or the header of a file object does not parse.
    /// - [`Error::InvalidFormat`] if a file object does not have the form of
    ///   the repository mode. [`Repo::load_file`] lists the cases.
    /// - [`Error::Unsupported`] if the tree does not fit a limit of the image.
    ///   [`export_composefs`](Repo::export_composefs) lists the limits.
    /// - [`Error::Unsupported`] if the xattrs of an inode after `filter` do
    ///   not fit a limit of the image, or if they hold an empty name, a name
    ///   with a NUL byte, or one name two times.
    /// - The error that `filter` returns.
    /// - [`Error::Io`] if the duplicate of `out` fails, or if a write to `out`
    ///   or its flush fails.
    /// - [`Error::InvalidFormat`] if a metadata object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or is not a regular
    ///   file, or if a symlink is on its path.
    /// - [`Error::Io`] if another file system operation fails, or if an
    ///   `archive` payload does not inflate.
    pub async fn export_composefs_to(
        &self,
        commit: &Checksum,
        opts: &ComposefsOptions,
        filter: Option<ComposefsEntryFn<'_>>,
        out: BorrowedFd<'_>,
    ) -> Result<[u8; 32]> {
        let dir = self
            .composefs_export_model(commit, opts.verity.into(), filter)
            .await?;
        // The blocking pool needs an owned handle, so the call duplicates the
        // descriptor of the caller for the closure to move.
        let fd = out.try_clone_to_owned()?;
        ostrya_rt::unblock(move || write_image_to_fd(&dir, fd))
            .await
            .map_err(writer_error)
    }

    /// Writes the composefs image of `commit` to `out` for a mount, and
    /// returns the size of the image in bytes.
    ///
    /// The image is the image of
    /// [`export_composefs_to`](Repo::export_composefs_to) with `verity` and
    /// no hook, with these changes:
    ///
    /// - Under [`VerityPolicy::Computed`], the call takes the fs-verity digest
    ///   of each backed file from the kernel alone, and reads no payload. An
    ///   object with no seal, or with a seal of other parameters, fails the
    ///   call. An overlay with `verity=require` cannot open such an object.
    /// - The call computes no fs-verity digest of the image.
    /// - The call computes the size of the image before it writes, and
    ///   refuses an image larger than `max_size` bytes with no write.
    ///
    /// The function is not a stable API.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if a backed file has no seal under
    ///   [`VerityPolicy::Computed`], or if the image is larger than
    ///   `max_size` bytes.
    /// - The errors of [`export_composefs_to`](Repo::export_composefs_to).
    #[doc(hidden)]
    pub async fn export_composefs_for_mount(
        &self,
        commit: &Checksum,
        verity: VerityPolicy,
        out: BorrowedFd<'_>,
        max_size: u64,
    ) -> Result<u64> {
        let digests = match verity {
            VerityPolicy::Computed => Digests::Sealed,
            VerityPolicy::Disabled => Digests::Disabled,
        };
        let dir = self.composefs_export_model(commit, digests, None).await?;
        let fd = out.try_clone_to_owned()?;
        ostrya_rt::unblock(move || {
            let mut out = BufWriter::with_capacity(DIGEST_CHUNK, std::fs::File::from(fd));
            write_image_unhashed_to(&dir, &mut out, max_size)
        })
        .await
        .map_err(writer_error)
    }

    /// Returns the composefs tree model of the root of `commit`. The two
    /// export entry points share this step.
    async fn composefs_export_model(
        &self,
        commit: &Checksum,
        digests: Digests,
        filter: Option<ComposefsEntryFn<'_>>,
    ) -> Result<Directory> {
        let (commit_obj, _) = self.load_commit(commit).await?;
        self.composefs_commit_model(&commit_obj, digests, filter)
            .await
    }

    /// Returns the composefs tree model of the root of a loaded commit.
    async fn composefs_commit_model(
        &self,
        commit_obj: &Commit,
        digests: Digests,
        filter: Option<ComposefsEntryFn<'_>>,
    ) -> Result<Directory> {
        let tree = RepoTree::from_parts(
            self.clone(),
            commit_obj.root_dirtree,
            commit_obj.root_dirmeta,
        );
        let walk = Walk {
            source: ObjectSource::Repo(self),
            digests,
            filter,
        };
        composefs_model(walk, &tree, &mut VerityCache::default()).await
    }

    /// Stages a new commit that records the composefs image digest of
    /// `commit`.
    ///
    /// The digest is the fs-verity digest of the image that
    /// [`export_composefs`](Repo::export_composefs) writes with
    /// [`ComposefsOptions::RECORDED`] and no hook. The `ostree` command stores
    /// this value and verifies it at boot.
    ///
    /// The call appends the key `ostree.composefs.digest.v0` to the metadata
    /// dict of `commit`, with the 32-byte digest as an `ay` value. The other
    /// fields of the commit stay the same. The call stages the new commit in
    /// `txn` and returns its checksum. The new commit publishes when `txn`
    /// commits.
    ///
    /// The new commit keeps field 2 of `commit`, the attachments, with no
    /// change. Before the call builds the image, it checks field 2 with the
    /// rules of [`write_commit`](Transaction::write_commit): each entry has a
    /// name that is not empty and a checksum of 32 bytes, the entries are
    /// sorted by name in byte order with no name two times, and each
    /// attachment is complete in the repository or in `txn`. The check reads
    /// no attachment of an attachment.
    ///
    /// The image depends on the tree of the commit alone, so the metadata of
    /// the commit and the repository mode do not change the digest. The image
    /// goes to [`std::io::sink`], so the digest needs no image-sized buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `commit` already carries
    ///   `ostree.composefs.digest.v0`.
    /// - [`Error::InvalidRelations`] with `commit` if field 2 of `commit` is
    ///   defective, if its entries are not sorted or have a name two times,
    ///   or if an attachment is absent or partial.
    /// - [`Error::Core`] if the commit tuple of an attachment does not frame,
    ///   or if its field 2 does not decode.
    /// - [`Error::ObjectNotFound`] if the commit object, or a dirtree,
    ///   dirmeta, or file object of its tree, is not in the object store.
    /// - [`Error::Core`] if the commit object, a dirtree object, a dirmeta
    ///   object, or the header of a file object does not parse.
    /// - [`Error::InvalidFormat`] if a file object does not have the form of
    ///   the repository mode. [`Repo::load_file`] lists the cases.
    /// - [`Error::Unsupported`] if the tree does not fit a limit of the image.
    ///   [`export_composefs`](Repo::export_composefs) lists the limits.
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`,
    ///   or if `[ex-integrity] fsverity` is `yes` and the fs-verity seal of
    ///   the new commit object fails.
    /// - [`Error::InsufficientFreeSpace`] if the new commit object needs more
    ///   space than the free-space budget of the transaction holds.
    /// - [`Error::Core`] if `[core] fsync` or `[core] per-object-fsync` in the
    ///   repository config is malformed.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::InvalidFormat`] if a metadata object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or is not a regular
    ///   file, or if a symlink is on its path.
    /// - [`Error::Io`] if a file system operation fails, or if an `archive`
    ///   payload does not inflate.
    pub async fn commit_add_composefs_metadata(
        &self,
        txn: &Transaction,
        commit: &Checksum,
    ) -> Result<Checksum> {
        let (mut commit_obj, _) = self.load_commit(commit).await?;
        if commit_obj.metadata.dict_get(COMPOSEFS_DIGEST_KEY).is_some() {
            return Err(Error::InvalidFormat(format!(
                "commit already carries {COMPOSEFS_DIGEST_KEY}"
            )));
        }
        let atts = related::checked_entries(
            RelationField::Attachments,
            Some(*commit),
            related::entries_of(&commit_obj.related),
        )?;
        related::check_order(Some(*commit), atts.iter().map(|(name, _)| name.as_str()))?;
        related::check_attachments(txn, Some(*commit), &atts).await?;
        let dir = self
            .composefs_commit_model(&commit_obj, ComposefsOptions::RECORDED.verity.into(), None)
            .await?;
        let fs_verity = image_digest(dir).await?;
        let digest_type = Type::parse(DIGEST_SIGNATURE).map_err(ostrya_core::Error::from)?;
        let value = Value::variant(digest_type, Value::Bytes(fs_verity.to_vec()));
        append_dict_entry(&mut commit_obj.metadata, COMPOSEFS_DIGEST_KEY, value)?;
        let bytes = commit_obj.serialize()?;
        txn.write_metadata(ObjectType::Commit, None, &bytes).await
    }
}

/// Returns the fs-verity digest of the bytes of `file` from its current
/// offset to its end.
///
/// The function reads the file in chunks of 128 KiB and feeds each chunk to
/// the fs-verity hasher, so it holds no image-sized buffer.
pub(crate) fn image_file_digest(file: &mut std::fs::File) -> std::io::Result<[u8; 32]> {
    use std::io::Read;

    let mut hasher = FsVerityHasher::new();
    let mut buf = vec![0u8; DIGEST_CHUNK];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(hasher.finalize())
}

/// Returns the digest that `commit` records under
/// `ostree.composefs.digest.v0`, or `None` if the commit does not carry the
/// key.
///
/// The value is the first entry of the key. It must be a variant of type `ay`
/// with 32 bytes, or the call fails with [`Error::InvalidFormat`].
pub(crate) fn recorded_digest(commit: &Commit) -> Result<Option<[u8; 32]>> {
    let Some(entry) = commit.metadata.dict_get(COMPOSEFS_DIGEST_KEY) else {
        return Ok(None);
    };
    entry_digest(entry).map(Some)
}

/// Returns the digest that `entry`, the value of an entry under
/// `ostree.composefs.digest.v0`, holds: a variant of type `ay` with 32 bytes.
/// Each other value fails with [`Error::InvalidFormat`].
fn entry_digest(entry: &Value) -> Result<[u8; 32]> {
    entry
        .as_variant()
        .filter(|(ty, _)| ty.signature() == DIGEST_SIGNATURE)
        .and_then(|(_, value)| value.as_bytes())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            Error::InvalidFormat(format!(
                "the value of {COMPOSEFS_DIGEST_KEY} is not a variant of type \
                 {DIGEST_SIGNATURE} with 32 bytes"
            ))
        })
}

/// Returns the lowercase hex form of a 32-byte digest.
pub(crate) fn digest_hex(digest: &[u8; 32]) -> String {
    use std::fmt::Write;

    digest
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Builds the composefs tree model of `root` from the objects in `source`.
/// The model holds the metadata and the backing redirect of each file, and no
/// file content, so the shape of the tree bounds its size. The walk takes the
/// fs-verity digest of each object with no seal from `cache` if it holds one.
/// The walk gives each node to the hook of `walk`, if it has one, and checks
/// the xattrs of the node after the hook.
async fn composefs_model(
    walk: Walk<'_>,
    root: &RepoTree,
    cache: &mut VerityCache,
) -> Result<Directory> {
    let mut path = PathBuf::from("/");
    let mut dir = build_directory(
        walk,
        &mut path,
        *root.dirtree_checksum(),
        *root.dirmeta_checksum(),
        cache,
    )
    .await?;
    inject_top_level_dirs(&mut dir, walk)?;
    Ok(dir)
}

/// Serializes `dir` through `fd` and returns the fs-verity digest of the
/// image. A buffer wraps the descriptor, because the writer emits the image in
/// many small writes.
fn write_image_to_fd(dir: &Directory, fd: OwnedFd) -> std::result::Result<[u8; 32], WriterError> {
    let mut out = BufWriter::with_capacity(DIGEST_CHUNK, std::fs::File::from(fd));
    write_image_to(dir, &mut out)
}

/// Writes the image of `dir` to an unnamed temp file of the staging directory
/// `staging`, and returns the file at offset 0, its size in bytes, and the
/// fs-verity digest of the image.
///
/// The writer computes the digest as it writes through a buffer of 128 KiB,
/// so no step holds the whole image. The function sets no mode, does not sync
/// the file, and does not seal it. The file goes away when it closes.
fn write_scratch_image_blocking(
    staging: &RepoDir,
    dir: &Directory,
) -> Result<(std::fs::File, u64, [u8; 32])> {
    let mut file = TempFile::create(staging)?.into_file()?;
    let mut out = BufWriter::with_capacity(DIGEST_CHUNK, &mut file);
    let digest = write_image_to(dir, &mut out).map_err(writer_error)?;
    out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    let size = crate::repo_fs::stat_fd(file.as_fd())?.size;
    file.seek(SeekFrom::Start(0))?;
    Ok((file, size, digest))
}

/// Returns the fs-verity digest of the image of `dir`, for a caller that needs
/// the digest alone. The image goes to [`std::io::sink`], so the call never
/// holds it.
async fn image_digest(dir: Directory) -> Result<[u8; 32]> {
    ostrya_rt::unblock(move || write_image_to(&dir, &mut std::io::sink()))
        .await
        .map_err(writer_error)
}

/// Returns the library error for an error of the writer. The writer holds the
/// bounds that the image format states. The tree reaches these bounds, so a
/// refusal of the writer is a refusal of the tree.
pub(crate) fn writer_error(err: WriterError) -> Error {
    match err {
        WriterError::Unsupported(msg) => Error::Unsupported(msg),
        WriterError::Io(err) => Error::Io(err),
    }
}

/// Builds the composefs [`Directory`] model of one directory of a committed
/// tree, and recurses into its subdirectories. `path` is the absolute path of
/// the directory in the image. The call gives the directory to the hook before
/// its children. The future is boxed because the recursion is async.
fn build_directory<'a>(
    walk: Walk<'a>,
    path: &'a mut PathBuf,
    dirtree: Checksum,
    dirmeta: Checksum,
    cache: &'a mut VerityCache,
) -> TreeFuture<'a> {
    Box::pin(async move {
        let object = walk.source.dirmeta(&dirmeta).await?;
        let mut meta = dirmeta_to_metadata(&object);
        walk.entry(path, EntryKind::Directory, &mut meta)?;
        let mut dir = Directory::new(meta);
        let tree = walk.source.dirtree(&dirtree).await?;
        for (name, checksum) in tree.files {
            path.push(&name);
            let node = file_node(walk, path, &checksum, &mut *cache).await?;
            path.pop();
            dir.children.insert(name.into_bytes(), node);
        }
        for (name, subtree, submeta) in tree.dirs {
            path.push(&name);
            let sub = build_directory(walk, &mut *path, subtree, submeta, &mut *cache).await?;
            path.pop();
            dir.children.insert(name.into_bytes(), Node::Directory(sub));
        }
        Ok(dir)
    })
}

/// Builds the composefs [`Node`] of a file object.
///
/// - A symlink stores its target inline.
/// - An empty regular file has no backing.
/// - A regular file with content redirects to its `.file` loose path. Under
///   [`Digests::Computed`] and [`Digests::Sealed`], it carries the fs-verity
///   digest of its content.
///
/// The call reads the file object in each mode, because the metadata of the
/// inode comes from it. Under [`Digests::Computed`], it takes the digest of an
/// object with no seal from `cache` if it holds one. `path` is the absolute
/// path of the file in the image. The call gives the file to the hook before
/// it gets the digest of the content.
async fn file_node(
    walk: Walk<'_>,
    path: &Path,
    checksum: &Checksum,
    cache: &mut VerityCache,
) -> Result<Node> {
    let digests = walk.digests;
    let file = walk
        .source
        .file(checksum, digests != Digests::Disabled)
        .await?;
    let mut meta = file_to_metadata(&file);
    let kind = match &file.kind {
        FileKind::Symlink { .. } => EntryKind::Symlink,
        FileKind::Regular { .. } => EntryKind::Regular,
    };
    walk.entry(path, kind, &mut meta)?;
    match &file.kind {
        FileKind::Symlink { target } => Ok(Node::Symlink(Symlink {
            meta,
            target: target.clone().into_bytes(),
        })),
        FileKind::Regular { size } => {
            let content = if *size == 0 {
                Content::Empty
            } else {
                let digest = match digests {
                    Digests::Computed => Some(content_fs_verity(&file, cache).await?),
                    Digests::Sealed => Some(file.kernel_fs_verity().ok_or_else(|| {
                        Error::Unsupported(format!(
                            "the file object {checksum} has no fs-verity seal with SHA-256, \
                             4096-byte blocks, and no salt"
                        ))
                    })?),
                    Digests::Disabled => None,
                };
                Content::Backed {
                    size: *size,
                    redirect: format!("/{}", loose_path(checksum, ObjectType::File, BACKING_MODE)),
                    verity: digest,
                }
            };
            Ok(Node::Regular(Regular { meta, content }))
        }
    }
}

/// Returns the fs-verity digest of the content of a regular file.
///
/// If the object file is a sealed raw payload, the value is the digest that
/// the kernel gave at load. The call then reads no payload byte, and it does
/// not put the digest in `cache`. The seal must name SHA-256, 4096-byte
/// blocks, no salt, and the payload size.
///
/// In all other cases, the call looks for the checksum of the file object in
/// `cache`, and gives the digest that the cache holds. If the cache holds no
/// digest of the object, the call streams the payload of the object through
/// the hasher in bounded chunks, and puts the digest in `cache`. The checksum
/// of the file object covers the content, so it is a key of the digest. The
/// digest covers the content, so a repository that stores the object
/// compressed gives the same value as one that stores it raw.
async fn content_fs_verity(file: &FileObject, cache: &mut VerityCache) -> Result<[u8; 32]> {
    use futures_lite::AsyncReadExt;

    if let Some(digest) = file.kernel_fs_verity() {
        return Ok(digest);
    }
    if let Some(digest) = cache.digests.get(file.checksum()) {
        return Ok(*digest);
    }
    let mut reader = file.reader().await?;
    let mut hasher = FsVerityHasher::new();
    let mut buf = vec![0u8; DIGEST_CHUNK];
    loop {
        let n = reader.read(&mut buf).await.map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    cache.digests.insert(*file.checksum(), digest);
    #[cfg(test)]
    {
        cache.hashed += 1;
    }
    Ok(digest)
}

/// Inserts the five top-level directories that the `ostree` command adds. If
/// the root of the commit already holds one of these names, its entry stays,
/// and the call does not give the name to the hook a second time.
fn inject_top_level_dirs(root: &mut Directory, walk: Walk<'_>) -> Result<()> {
    for name in INJECTED_DIRS {
        let key = name.as_bytes().to_vec();
        if let btree_map::Entry::Vacant(slot) = root.children.entry(key) {
            let mut meta = Metadata {
                mode: INJECTED_DIR_MODE,
                uid: 0,
                gid: 0,
                mtime: (0, 0),
                xattrs: Vec::new(),
            };
            walk.entry(&Path::new("/").join(name), EntryKind::Directory, &mut meta)?;
            slot.insert(Node::Directory(Directory::new(meta)));
        }
    }
    Ok(())
}

/// Returns the composefs [`Metadata`] of a directory. The `ostree` command
/// sets the mtime of each exported inode to 0.
fn dirmeta_to_metadata(dirmeta: &DirMeta) -> Metadata {
    Metadata {
        mode: dirmeta.mode,
        uid: dirmeta.uid,
        gid: dirmeta.gid,
        mtime: (0, 0),
        xattrs: xattrs_to_model(&dirmeta.xattrs),
    }
}

/// Returns the composefs [`Metadata`] of a file object. The `ostree` command
/// sets the mtime of each exported inode to 0.
fn file_to_metadata(file: &FileObject) -> Metadata {
    Metadata {
        mode: file.mode,
        uid: file.uid,
        gid: file.gid,
        mtime: (0, 0),
        xattrs: xattrs_to_model(&file.xattrs),
    }
}

/// Converts an [`Xattrs`] set to the `(name, value)` pairs of the writer. A
/// stored name ends in a NUL byte. The writer indexes raw names, so the call
/// drops the NUL.
fn xattrs_to_model(xattrs: &Xattrs) -> Vec<(Vec<u8>, Vec<u8>)> {
    xattrs
        .iter()
        .map(|(name, value)| {
            let name = name.strip_suffix(&[0]).unwrap_or(name);
            (name.to_vec(), value.to_vec())
        })
        .collect()
}

/// Checks the final xattrs of one inode of the image model.
///
/// Each attribute spends its name, its value, and [`XATTR_ENTRY_COST`] bytes
/// from the budget of [`MAX_XATTR_TOTAL`] bytes of the inode. The call refuses
/// an inode that spends more. It holds each name to [`MAX_XATTR_NAME`] bytes,
/// the one EROFS length field that the budget does not bind. It also refuses
/// an empty name, a name that holds a NUL byte, and a name that occurs two
/// times. A stored [`Xattrs`] set holds none of these three, so only a hook
/// can give one. The writer panics on a value or an area above its limits, so
/// the walk runs this check on each node after the hook.
fn check_xattrs(xattrs: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
    let mut spent = 0usize;
    for (name, value) in xattrs {
        if name.is_empty() {
            return Err(Error::Unsupported("an xattr name is empty".into()));
        }
        if name.contains(&0) {
            return Err(Error::Unsupported(format!(
                "xattr {} holds a NUL byte",
                name.escape_ascii(),
            )));
        }
        if name.len() > MAX_XATTR_NAME {
            return Err(Error::Unsupported(format!(
                "xattr {} is {} bytes long, above the {MAX_XATTR_NAME} \
                 bytes a composefs image states a name in",
                String::from_utf8_lossy(name),
                name.len(),
            )));
        }
        spent += XATTR_ENTRY_COST + name.len() + value.len();
        if spent > MAX_XATTR_TOTAL {
            return Err(Error::Unsupported(format!(
                "xattr {} takes the inode to {spent} bytes of extended \
                 attributes, above the {MAX_XATTR_TOTAL} bytes a composefs \
                 image holds",
                String::from_utf8_lossy(name),
            )));
        }
    }
    // A stored set holds its names in strictly increasing order, so with no
    // hook the check needs no sorted copy.
    if !xattrs.windows(2).all(|pair| pair[0].0 < pair[1].0) {
        let mut names: Vec<&[u8]> = xattrs.iter().map(|(name, _)| name.as_slice()).collect();
        names.sort_unstable();
        if let Some(pair) = names.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(Error::Unsupported(format!(
                "xattr {} is on the inode two times",
                String::from_utf8_lossy(pair[0]),
            )));
        }
    }
    Ok(())
}

/// Compile-time checks that the futures of the exports with a hook are
/// `Send`.
const _: fn() = || {
    fn assert_send<T: Send>(_: &T) {}
    let _ = |repo: &Repo, commit: &Checksum, filter: ComposefsEntryFn<'_>| {
        assert_send(&repo.export_composefs(commit, &ComposefsOptions::RECORDED, Some(filter)));
    };
    let _ = |repo: &Repo, commit: &Checksum, filter: ComposefsEntryFn<'_>, out: BorrowedFd<'_>| {
        assert_send(&repo.export_composefs_to(
            commit,
            &ComposefsOptions::RECORDED,
            Some(filter),
            out,
        ));
    };
};

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use std::sync::Mutex;

    use ostrya_composefs::{Metadata, Node};
    use ostrya_core::{DirMeta, ObjectType, RepoMode, Xattrs};
    use ostrya_rt::block_on;

    use super::{
        ComposefsEntryFn, Digests, EntryKind, ObjectSource, VerityCache, Walk, composefs_model,
    };
    use crate::{CreateOptions, FileMeta, MutableTree, Repo, Transaction};

    /// A scratch directory that the drop removes.
    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let path = std::env::temp_dir().join(format!(
                "ostrya-composefs-{tag}-{}-{}",
                std::process::id(),
                crate::write::unique()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Scratch { path }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Writes the regular file `name` under `dir` with `bytes` and the mode
    /// 0644.
    fn write_file(dir: &Path, name: &str, bytes: &[u8]) {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// One tree walk reads and hashes each object with no seal one time. Two
    /// paths of the tree name one object. An empty file has no backing, so
    /// the walk hashes no empty object.
    #[test]
    fn one_tree_walk_hashes_each_unsealed_object_one_time() {
        let scratch = Scratch::new("verity-cache");
        let root = scratch.path.join("repo");
        block_on(async {
            drop(
                Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
                    .await
                    .unwrap(),
            );
            let cfg = root.join("config");
            let mut text = std::fs::read_to_string(&cfg).unwrap();
            text.push_str("[ex-integrity]\nfsverity=no\n");
            std::fs::write(&cfg, text).unwrap();
            let repo = Repo::open(&root).await.unwrap();

            let src = scratch.path.join("tree").join("src");
            std::fs::create_dir_all(&src).unwrap();
            write_file(&src, "a", b"shared bytes\n");
            write_file(&src, "b", b"shared bytes\n");
            write_file(&src, "empty", b"");

            let txn = repo.transaction().await.unwrap();
            let mut mtree = MutableTree::new();
            let dfd = std::fs::File::open(scratch.path.join("tree")).unwrap();
            txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
                .await
                .unwrap();
            let tree = txn.write_mtree(&mut mtree).await.unwrap();
            let mut cache = VerityCache::default();
            let walk = Walk {
                source: ObjectSource::Staged(&txn),
                digests: Digests::Computed,
                filter: None,
            };
            composefs_model(walk, &tree, &mut cache).await.unwrap();
            assert_eq!(cache.hashed, 1);
        });
    }

    /// The stored xattrs of the test tree: `security.selinux` with `label`.
    /// A stored name ends in a NUL byte.
    fn selinux(label: &[u8]) -> Xattrs {
        Xattrs::new([(b"security.selinux\0".to_vec(), label.to_vec())]).unwrap()
    }

    /// Stages a dirmeta with the mode 040755, the owner 0:0, and `xattrs`.
    async fn stage_dirmeta(txn: &Transaction, xattrs: Xattrs) -> ostrya_core::Checksum {
        let bytes = DirMeta {
            uid: 0,
            gid: 0,
            mode: 0o040755,
            xattrs,
        }
        .serialize()
        .unwrap();
        txn.write_metadata(ObjectType::DirMeta, None, &bytes)
            .await
            .unwrap()
    }

    /// One call of the hook: the path, the kind, the mtime, and the xattr
    /// names that the hook got.
    type Call = (PathBuf, EntryKind, (u64, u32), Vec<Vec<u8>>);

    /// The walk gives each node of the tree to the hook one time, before the
    /// children of a directory. The hook gets the mtime 0 and the xattr names
    /// with no NUL byte. A change of the hook is in the model. A top-level
    /// name that the tree holds gets one call with the kind of the tree
    /// entry, and the walk adds no directory in its place.
    #[test]
    fn the_walk_gives_each_node_to_the_hook() {
        let scratch = Scratch::new("hook-model");
        let calls: Mutex<Vec<Call>> = Mutex::new(Vec::new());
        let hook: ComposefsEntryFn<'_> = &|path, kind, meta: &mut Metadata| {
            let names = meta.xattrs.iter().map(|(name, _)| name.clone()).collect();
            calls
                .lock()
                .unwrap()
                .push((path.to_path_buf(), kind, meta.mtime, names));
            if path == Path::new("/sub/f") {
                meta.mode = 0o100600;
                meta.uid = 7;
                meta.gid = 8;
                meta.mtime = (5, 6);
            }
            Ok(())
        };
        let model = block_on(async {
            let repo = Repo::create(
                &scratch.path.join("repo"),
                CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let txn = repo.transaction().await.unwrap();
            let file = |xattrs: Xattrs| FileMeta {
                uid: 0,
                gid: 0,
                mode: 0o100644,
                xattrs,
            };
            let etc = txn
                .write_regfile_inline(None, &file(selinux(b"etc_t\0")), b"a file\n")
                .await
                .unwrap();
            let f = txn
                .write_regfile_inline(None, &file(Xattrs::empty()), b"")
                .await
                .unwrap();
            let mut mtree = MutableTree::new();
            mtree.replace_file("etc", etc).unwrap();
            let sub = mtree.ensure_dir("sub").await.unwrap();
            sub.replace_file("f", f).unwrap();
            sub.set_metadata_checksum(stage_dirmeta(&txn, Xattrs::empty()).await);
            mtree.set_metadata_checksum(stage_dirmeta(&txn, selinux(b"root_t\0")).await);
            let tree = txn.write_mtree(&mut mtree).await.unwrap();
            let walk = Walk {
                source: ObjectSource::Staged(&txn),
                digests: Digests::Disabled,
                filter: Some(hook),
            };
            composefs_model(walk, &tree, &mut VerityCache::default())
                .await
                .unwrap()
        });

        let calls = calls.into_inner().unwrap();
        let paths: Vec<&Path> = calls.iter().map(|call| call.0.as_path()).collect();
        let at = |path: &str| {
            paths
                .iter()
                .position(|seen| *seen == Path::new(path))
                .unwrap()
        };
        for want in [
            "/", "/etc", "/sub", "/sub/f", "/boot", "/sysroot", "/usr", "/var",
        ] {
            let count = paths
                .iter()
                .filter(|seen| **seen == Path::new(want))
                .count();
            assert_eq!(count, 1, "{want} gets one call: {paths:?}");
        }
        assert_eq!(
            paths.len(),
            8,
            "the hook gets one call for each node: {paths:?}"
        );
        assert!(at("/") < at("/etc") && at("/") < at("/sub") && at("/sub") < at("/sub/f"));

        let selinux_name = [b"security.selinux".to_vec()];
        for (path, kind, mtime, names) in &calls {
            assert_eq!(*mtime, (0, 0), "the mtime of {}", path.display());
            let want: &[Vec<u8>] = match path.to_str().unwrap() {
                "/" | "/etc" => &selinux_name,
                _ => &[],
            };
            assert_eq!(names, want, "the xattr names of {}", path.display());
            let want_kind = match path.to_str().unwrap() {
                "/etc" | "/sub/f" => EntryKind::Regular,
                _ => EntryKind::Directory,
            };
            assert_eq!(*kind, want_kind, "the kind of {}", path.display());
        }

        assert!(matches!(
            model.children.get(&b"etc"[..]),
            Some(Node::Regular(_))
        ));
        let Some(Node::Directory(sub)) = model.children.get(&b"sub"[..]) else {
            panic!("the model holds the directory sub");
        };
        let Some(Node::Regular(f)) = sub.children.get(&b"f"[..]) else {
            panic!("the model holds the file sub/f");
        };
        assert_eq!(
            (f.meta.mode, f.meta.uid, f.meta.gid, f.meta.mtime),
            (0o100600, 7, 8, (5, 6)),
        );
    }
}
