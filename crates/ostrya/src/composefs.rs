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
//!
//! [`ComposefsOptions`] and [`VerityPolicy`] select the verity form of the
//! image.
//!
//! # The image object
//!
//! A repository can store the image of a commit as an object of the type
//! [`ObjectType::ComposefsImage`], at `objects/<xx>/<commit>.cfs`. The object
//! is a sidecar of the commit, as the detached metadata is. Its name is the
//! checksum of the commit, and its bytes are the image that an export with
//! [`ComposefsOptions::RECORDED`] writes. So its fs-verity digest is the value
//! of the `ostree.composefs.digest.v0` key of the commit.
//!
//! - [`Transaction::build_composefs_image`] writes the image of a tree to the
//!   staging directory, and [`Transaction::attach_composefs_image`] stages it
//!   as the image of a commit.
//! - [`Transaction::write_composefs_image`] stages the image of a commit in
//!   one call.
//! - [`Repo::add_composefs_image`] stores the image of a commit in its own
//!   transaction.
//! - [`Repo::check_composefs_image`] compares a stored image with the key of
//!   its commit, and [`Repo::composefs_image_path`] gives its path.
//!
//! Each write refuses a commit without the key and an image whose digest is
//! not the key. A write never holds the whole image in memory.
//!
//! A pull ([`Repo::pull`], [`Repo::pull_local`]), a push, and a one-way stream
//! carry the image with its commit. Each of them computes the digest of the
//! bytes that it writes, and installs the image only when the digest is the
//! key.

use std::future::Future;
use std::io::BufWriter;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::pin::Pin;

use futures_io::AsyncRead;
use ostrya_composefs::{
    Content, Directory, Error as WriterError, FsVerityHasher, Image, Metadata, Node, Regular,
    Symlink, build_image, write_image_to,
};
use ostrya_core::{
    Checksum, Commit, DirMeta, DirTree, ObjectType, RepoMode, Type, Value, Xattrs, loose_path,
};

use crate::commit::{append_dict_entry, check_gc_anchors};
use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject};
use crate::repo::Repo;
use crate::transaction::Transaction;
use crate::tree::RepoTree;
use crate::write::{
    ImageTemp, clone_image_temp_blocking, discard_image_temp, link_image_blocking,
    write_image_stream_temp, write_image_temp_blocking,
};

/// The empty top-level directories that the `ostree` command adds to each
/// exported image.
const INJECTED_DIRS: [&str; 5] = ["boot", "etc", "sysroot", "usr", "var"];
/// The mode that the `ostree` command gives each added top-level directory
/// (`040755`).
const INJECTED_DIR_MODE: u32 = 0o040755;
/// The commit metadata key that holds the fs-verity digest of the image.
const COMPOSEFS_DIGEST_KEY: &str = "ostree.composefs.digest.v0";
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
    /// with these options. A target machine computes the same digest at boot.
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

/// The result of a write of the composefs image of a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposefsImageAdd {
    /// The repository holds no image of the commit. The write adds one.
    Added,
    /// The repository holds an image of the commit, and its digest is the key
    /// of the commit. The write changes nothing.
    ///
    /// An image that the same transaction staged before gives this result
    /// too.
    AlreadyValid,
    /// The repository holds an image of the commit, and its digest is not the
    /// key of the commit or the image does not read. The write replaces it.
    Replaced,
}

/// The state of the stored composefs image of a commit, as
/// [`Repo::check_composefs_image`] gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposefsImageState {
    /// The image is present, and its fs-verity digest is the key of the
    /// commit.
    Valid,
    /// The commit carries the key, and the repository holds no image of it.
    Absent,
    /// The commit does not carry `ostree.composefs.digest.v0`.
    ///
    /// The call does not look for an image in this state.
    NoKey,
    /// The image is present, and its fs-verity digest is not the key of the
    /// commit.
    Mismatch {
        /// The digest that the commit records.
        expected: [u8; 32],
        /// The fs-verity digest of the stored image.
        actual: [u8; 32],
    },
}

/// A composefs image that a transaction wrote to its staging directory and
/// that is not the image of a commit yet.
///
/// [`Transaction::build_composefs_image`] gives it, and
/// [`Transaction::attach_composefs_image`] takes it. A drop removes the image
/// file.
pub struct StagedComposefsImage<'txn> {
    txn: &'txn Transaction,
    /// The image file. `None` after the attach took it.
    image: Option<ImageTemp>,
    digest: [u8; 32],
}

impl StagedComposefsImage<'_> {
    /// Returns the fs-verity digest of the image.
    ///
    /// The value is the one that `ostree.composefs.digest.v0` holds for a
    /// commit of the tree.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl StagedComposefsImage<'_> {
    /// Removes the image file on the blocking pool.
    ///
    /// If the call cannot hand the staging directory to the blocking pool, it
    /// keeps the image file, and the drop removes it.
    async fn discard(mut self) {
        let Some(image) = self.image.take() else {
            return;
        };
        match self.txn.staging_fd().try_clone_to_owned() {
            Ok(staging) => {
                ostrya_rt::unblock(move || discard_image_temp(staging.as_fd(), &image.temp)).await;
            }
            Err(_) => self.image = Some(image),
        }
    }
}

impl std::fmt::Debug for StagedComposefsImage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedComposefsImage")
            .field("digest", &digest_hex(&self.digest))
            .finish_non_exhaustive()
    }
}

impl Drop for StagedComposefsImage<'_> {
    fn drop(&mut self) {
        if let Some(image) = self.image.take() {
            discard_image_temp(self.txn.staging_fd(), &image.temp);
        }
    }
}

/// Methods that compute the composefs digest of a staged tree and stage the
/// composefs image of a commit.
impl Transaction {
    /// Returns the composefs image digest of a tree that this transaction
    /// staged.
    ///
    /// The value is the one that `ostree.composefs.digest.v0` holds: the
    /// fs-verity digest of the image that an export with
    /// [`ComposefsOptions::RECORDED`] writes for the same tree.
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
    /// - [`Error::Io`] if a file system operation fails, if a metadata object
    ///   is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), or if
    ///   an `archive` payload does not inflate.
    pub async fn composefs_digest(&self, root: &RepoTree) -> Result<[u8; 32]> {
        let dir = composefs_model(
            ObjectSource::Staged(self),
            root,
            &ComposefsOptions::RECORDED,
        )
        .await?;
        image_digest(dir).await
    }

    /// Writes the composefs image of a tree to the staging directory of this
    /// transaction.
    ///
    /// The image is the image that an export with
    /// [`ComposefsOptions::RECORDED`] writes for the same tree, so
    /// [`StagedComposefsImage::digest`] is the value of
    /// [`composefs_digest`](Transaction::composefs_digest). The call reads the
    /// objects of the tree as `composefs_digest` reads them. A caller that
    /// writes a new commit takes the digest for the key
    /// `ostree.composefs.digest.v0` of the commit, writes the commit, and then
    /// gives the image to [`attach_composefs_image`](Transaction::attach_composefs_image).
    /// The tree is then read one time.
    ///
    /// The writer computes the fs-verity digest as it writes the image, and
    /// it holds no image-sized buffer. The image file has the mode 0644. If
    /// `[ex-integrity] fsverity` is not `no`, the call seals the file and
    /// compares the digest that the kernel reads with the digest of the
    /// writer. If the `fsync` and `per-object-fsync` values of the
    /// transaction are both on, the call syncs the file. Each value comes from
    /// [`set_fsync`](Transaction::set_fsync) or
    /// [`set_per_object_fsync`](Transaction::set_per_object_fsync) if the
    /// transaction has an override, and else from `[core] fsync` or
    /// `[core] per-object-fsync`.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`.
    /// - The errors of [`composefs_digest`](Transaction::composefs_digest).
    /// - [`Error::Unsupported`] if `[ex-integrity] fsverity` is `yes` and the
    ///   seal fails.
    /// - [`Error::InvalidFormat`] if the digest that the kernel reads for the
    ///   sealed file is not the digest of the writer.
    /// - [`Error::Core`] if `[core] fsync` or `[core] per-object-fsync` in the
    ///   repository config is malformed.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` in the
    ///   repository config is malformed.
    /// - [`Error::Io`] if a write to the image file or another file system
    ///   operation fails.
    pub async fn build_composefs_image(&self, root: &RepoTree) -> Result<StagedComposefsImage<'_>> {
        if self.repo().mode() == RepoMode::BareSplitXattrs {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
        let (fsync, per_object_fsync) = self.fsync_flags()?;
        let verity = self.repo().config().fsverity()?;
        let dir = composefs_model(
            ObjectSource::Staged(self),
            root,
            &ComposefsOptions::RECORDED,
        )
        .await?;
        let staging = self.staging_fd().try_clone_to_owned()?;
        let image = ostrya_rt::unblock(move || {
            write_image_temp_blocking(staging.as_fd(), &dir, fsync && per_object_fsync, verity)
        })
        .await?;
        Ok(StagedComposefsImage {
            txn: self,
            digest: image.digest,
            image: Some(image),
        })
    }

    /// Stages `image` as the composefs image of `commit`.
    ///
    /// The commit comes from the staged set of this transaction, or else from
    /// `objects/`. The call checks the digest of the image against the key
    /// `ostree.composefs.digest.v0` of the commit, and refuses a mismatch. It
    /// then compares the stored image of the commit with the key, if the
    /// repository holds one. The call streams the stored image through the
    /// fs-verity hasher.
    ///
    /// - With no stored image, the call stages the image and returns
    ///   [`ComposefsImageAdd::Added`].
    /// - With a stored image whose digest is the key, the call drops the image
    ///   and returns [`ComposefsImageAdd::AlreadyValid`].
    /// - With a stored image whose digest is not the key, or a stored image
    ///   that does not read, the call stages the image and returns
    ///   [`ComposefsImageAdd::Replaced`].
    ///
    /// If the call does not stage the image, it removes the image file.
    ///
    /// [`commit`](Transaction::commit) publishes a staged image after all the
    /// other objects of the transaction. Its rename replaces the stored image
    /// in one step. The image is a sidecar of the commit, so no field of
    /// [`TransactionStats`](crate::TransactionStats) counts it, and
    /// `ostree.sizes` has no entry for it. The image takes its size from the
    /// free-space budget of the transaction.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `image` comes from another transaction.
    /// - [`Error::InvalidInput`] if the commit does not carry
    ///   `ostree.composefs.digest.v0`.
    /// - [`Error::InvalidFormat`] if the first entry of that key is not a
    ///   variant of type `ay` with 32 bytes.
    /// - [`Error::ComposefsDigestMismatch`] if the digest of the image is not
    ///   the value of the key.
    /// - [`Error::ObjectNotFound`] if the commit object is not staged and not
    ///   in the object store.
    /// - [`Error::Core`] if the commit object does not parse.
    /// - [`Error::InsufficientFreeSpace`] if the image needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Io`] if a file system operation fails, or if the commit
    ///   object is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    pub async fn attach_composefs_image(
        &self,
        commit: &Checksum,
        image: StagedComposefsImage<'_>,
    ) -> Result<ComposefsImageAdd> {
        if !std::ptr::eq(image.txn, self) {
            image.discard().await;
            return Err(Error::InvalidInput(
                "the composefs image comes from another transaction".into(),
            ));
        }
        let checked = async {
            let commit_obj = self.load_commit_staged_first(commit).await?;
            let key = require_recorded_digest(&commit_obj, commit)?;
            check_image_digest(commit, &key, &image)?;
            self.image_state(commit, &key).await
        }
        .await;
        self.finish_attach(commit, checked, image).await
    }

    /// Builds and stages the composefs image of `commit`.
    ///
    /// The call runs [`build_composefs_image`](Transaction::build_composefs_image)
    /// over the root of the commit and
    /// [`attach_composefs_image`](Transaction::attach_composefs_image) with
    /// the result. If the repository holds a valid image of the commit
    /// already, the call builds nothing and returns
    /// [`ComposefsImageAdd::AlreadyValid`].
    ///
    /// The call does not refuse a partial commit. If an object of the tree is
    /// absent, the build fails.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if the commit does not carry
    ///   `ostree.composefs.digest.v0`.
    /// - [`Error::ComposefsDigestMismatch`] if the image of the tree does not
    ///   have the digest that the commit records.
    /// - The errors of
    ///   [`build_composefs_image`](Transaction::build_composefs_image) and of
    ///   [`attach_composefs_image`](Transaction::attach_composefs_image).
    pub async fn write_composefs_image(&self, commit: &Checksum) -> Result<ComposefsImageAdd> {
        let commit_obj = self.load_commit_staged_first(commit).await?;
        let key = require_recorded_digest(&commit_obj, commit)?;
        let Some(result) = self.image_state(commit, &key).await? else {
            return Ok(ComposefsImageAdd::AlreadyValid);
        };
        let tree = RepoTree::from_parts(
            self.repo().clone(),
            commit_obj.root_dirtree,
            commit_obj.root_dirmeta,
        );
        let image = self.build_composefs_image(&tree).await?;
        let checked = check_image_digest(commit, &key, &image).map(|()| Some(result));
        self.finish_attach(commit, checked, image).await
    }

    /// Stages `image` as the composefs image of `commit` after the checks of
    /// [`attach_composefs_image`](Transaction::attach_composefs_image).
    ///
    /// `checked` is the result of the checks, as
    /// [`image_state`](Transaction::image_state) gives it. On `Ok(Some(_))`,
    /// the call links the image into the staging directory and returns the
    /// result. On `Ok(None)` or `Err`, it removes the image file and returns
    /// [`ComposefsImageAdd::AlreadyValid`] or the error.
    async fn finish_attach(
        &self,
        commit: &Checksum,
        checked: Result<Option<ComposefsImageAdd>>,
        mut image: StagedComposefsImage<'_>,
    ) -> Result<ComposefsImageAdd> {
        let result = match checked {
            Ok(Some(result)) => result,
            Ok(None) => {
                image.discard().await;
                return Ok(ComposefsImageAdd::AlreadyValid);
            }
            Err(e) => {
                image.discard().await;
                return Err(e);
            }
        };
        let staging = self.staging_fd().try_clone_to_owned()?;
        let temp = image
            .image
            .take()
            .expect("a staged composefs image holds its file until attached");
        let mode = self.repo().mode();
        let key = *commit;
        let outcome =
            ostrya_rt::unblock(move || link_image_blocking(staging.as_fd(), temp, &key, mode))
                .await?;
        self.record_image(*commit, outcome)?;
        Ok(result)
    }

    /// Returns the result that a write of a valid image of `commit` gives:
    /// `None` if the transaction staged an image of the commit or the
    /// repository holds a valid one, so the write changes nothing.
    ///
    /// A stored image that does not read gives
    /// [`ComposefsImageAdd::Replaced`], so the rename of the publish replaces
    /// it.
    async fn image_state(
        &self,
        commit: &Checksum,
        key: &[u8; 32],
    ) -> Result<Option<ComposefsImageAdd>> {
        if self.is_staged(commit, ObjectType::ComposefsImage) {
            return Ok(None);
        }
        Ok(match self.repo().stored_image_digest(commit).await {
            Ok(None) => Some(ComposefsImageAdd::Added),
            Ok(Some(digest)) if digest == *key => None,
            Ok(Some(_)) | Err(Error::Io(_)) => Some(ComposefsImageAdd::Replaced),
            Err(e) => return Err(e),
        })
    }

    /// Stages the stored composefs image of `commit` in `src` as the image of
    /// `commit` in this transaction.
    ///
    /// The call copies the image with a `FICLONE` reflink if the file system
    /// supports one, and with a byte copy in the kernel otherwise. It never
    /// shares the inode of the source. It seals the copy as
    /// [`build_composefs_image`](Transaction::build_composefs_image) seals a
    /// new image. The fs-verity digest of the copy is the kernel digest of
    /// the seal. If the call does not seal the copy, it reads the copy to
    /// compute the digest. Then
    /// [`attach_composefs_image`](Transaction::attach_composefs_image) checks
    /// the digest against the key of the commit and stages the copy.
    ///
    /// Returns the size of the image in bytes, or `None` if `src` holds no
    /// image of `commit`.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`.
    /// - [`Error::ComposefsDigestMismatch`] if the digest of the image is not
    ///   the key of the commit.
    /// - The errors of [`attach_composefs_image`](Transaction::attach_composefs_image).
    pub(crate) async fn import_composefs_image(
        &self,
        src: &Repo,
        commit: &Checksum,
    ) -> Result<Option<u64>> {
        if self.repo().mode() == RepoMode::BareSplitXattrs {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
        let (fsync, per_object_fsync) = self.fsync_flags()?;
        let verity = self.repo().config().fsverity()?;
        let staging = self.staging_fd().try_clone_to_owned()?;
        let src = src.clone();
        let key = *commit;
        let image = ostrya_rt::unblock(move || {
            clone_image_temp_blocking(
                staging.as_fd(),
                src.objects_fd(),
                src.mode(),
                &key,
                fsync && per_object_fsync,
                verity,
            )
        })
        .await?;
        let Some(image) = image else {
            return Ok(None);
        };
        let size = image.size;
        let staged = StagedComposefsImage {
            txn: self,
            digest: image.digest,
            image: Some(image),
        };
        self.attach_composefs_image(commit, staged).await?;
        Ok(Some(size))
    }

    /// Streams a composefs image from `reader` and stages it as the image of
    /// `commit`.
    ///
    /// The bytes go through `buf`, so no step holds the whole image. The call
    /// computes the fs-verity digest as it writes the image, and seals the
    /// image as [`build_composefs_image`](Transaction::build_composefs_image)
    /// seals a new image. Then
    /// [`attach_composefs_image`](Transaction::attach_composefs_image) checks
    /// the digest against the key of the commit and stages the image.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`.
    /// - [`Error::Io`] if a read from `reader` fails, or if a file system
    ///   operation fails.
    /// - [`Error::ComposefsDigestMismatch`] if the digest of the image is not
    ///   the key of the commit.
    /// - The errors of [`attach_composefs_image`](Transaction::attach_composefs_image).
    pub(crate) async fn stage_composefs_image_from<R: AsyncRead + Unpin>(
        &self,
        commit: &Checksum,
        reader: R,
        buf: &mut Vec<u8>,
    ) -> Result<ComposefsImageAdd> {
        let image = write_image_stream_temp(self, reader, buf).await?;
        let staged = StagedComposefsImage {
            txn: self,
            digest: image.digest,
            image: Some(image),
        };
        self.attach_composefs_image(commit, staged).await
    }

    /// Streams a composefs image from `reader` and stages it as the image of
    /// `commit`, with no check against the key of the commit.
    ///
    /// The call writes and seals the image as
    /// [`stage_composefs_image_from`](Transaction::stage_composefs_image_from)
    /// does, and returns its fs-verity digest. The commit need not be staged
    /// or stored yet. The caller compares the digest with the key of the
    /// commit before the transaction commits, and drops the transaction on a
    /// mismatch.
    #[cfg(feature = "receive")]
    pub(crate) async fn stage_composefs_image_unchecked<R: AsyncRead + Unpin>(
        &self,
        commit: &Checksum,
        reader: R,
        buf: &mut Vec<u8>,
    ) -> Result<[u8; 32]> {
        let image = write_image_stream_temp(self, reader, buf).await?;
        let digest = image.digest;
        let staging = self.staging_fd().try_clone_to_owned()?;
        let mode = self.repo().mode();
        let key = *commit;
        let outcome =
            ostrya_rt::unblock(move || link_image_blocking(staging.as_fd(), image, &key, mode))
                .await?;
        self.record_image(*commit, outcome)?;
        Ok(digest)
    }
}

/// Methods that export a commit as a composefs image.
impl Repo {
    /// Builds the composefs EROFS image of `commit` in memory.
    ///
    /// The returned [`Image`] holds the bytes of the image and its fs-verity
    /// digest. With [`ComposefsOptions::RECORDED`], the digest is the value
    /// that [`commit_add_composefs_metadata`](Repo::commit_add_composefs_metadata)
    /// records for the tree of the commit. Under [`VerityPolicy::Disabled`],
    /// the digest is different from that value. The image assembly runs on the
    /// blocking pool.
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
    /// - [`Error::Io`] if a file system operation fails, if a metadata object
    ///   is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), or if
    ///   an `archive` payload does not inflate.
    pub async fn export_composefs(
        &self,
        commit: &Checksum,
        opts: &ComposefsOptions,
    ) -> Result<Image> {
        let dir = self.composefs_export_model(commit, opts).await?;
        ostrya_rt::unblock(move || build_image(&dir))
            .await
            .map_err(writer_error)
    }

    /// Writes the composefs image of `commit` to `out` and returns its digest.
    ///
    /// The image and its fs-verity digest are the same as those of
    /// [`export_composefs`](Repo::export_composefs), with the same options,
    /// the same repository modes, and the same limits.
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
    /// - [`Error::Io`] if the duplicate of `out` fails, or if a write to `out`
    ///   or its flush fails.
    /// - [`Error::Io`] if another file system operation fails, if a metadata
    ///   object is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE),
    ///   or if an `archive` payload does not inflate.
    pub async fn export_composefs_to(
        &self,
        commit: &Checksum,
        opts: &ComposefsOptions,
        out: BorrowedFd<'_>,
    ) -> Result<[u8; 32]> {
        let dir = self.composefs_export_model(commit, opts).await?;
        // The blocking pool needs an owned handle, so the call duplicates the
        // descriptor of the caller for the closure to move.
        let fd = out.try_clone_to_owned()?;
        ostrya_rt::unblock(move || write_image_to_fd(&dir, fd))
            .await
            .map_err(writer_error)
    }

    /// Returns the composefs tree model of the root of `commit`. The two
    /// export entry points share this step.
    async fn composefs_export_model(
        &self,
        commit: &Checksum,
        opts: &ComposefsOptions,
    ) -> Result<Directory> {
        let (commit_obj, _) = self.load_commit(commit).await?;
        self.composefs_commit_model(&commit_obj, opts).await
    }

    /// Returns the composefs tree model of the root of a loaded commit.
    async fn composefs_commit_model(
        &self,
        commit_obj: &Commit,
        opts: &ComposefsOptions,
    ) -> Result<Directory> {
        let tree = RepoTree::from_parts(
            self.clone(),
            commit_obj.root_dirtree,
            commit_obj.root_dirmeta,
        );
        composefs_model(ObjectSource::Repo(self), &tree, opts).await
    }

    /// Stages a new commit that records the composefs image digest of
    /// `commit`.
    ///
    /// The digest is the fs-verity digest of the image that
    /// [`export_composefs`](Repo::export_composefs) writes with
    /// [`ComposefsOptions::RECORDED`]. The `ostree` command stores this value
    /// and verifies it at boot.
    ///
    /// The call appends the key `ostree.composefs.digest.v0` to the metadata
    /// dict of `commit`, with the 32-byte digest as an `ay` value. The other
    /// fields of the commit stay the same. The call stages the new commit in
    /// `txn` and returns its checksum. The new commit publishes when `txn`
    /// commits.
    ///
    /// The call checks the values of the GC anchor keys in the new metadata
    /// dict, as [`write_commit`](Transaction::write_commit) does. The check
    /// includes the entries that the call copies from `commit`. On a refusal,
    /// the call stages nothing.
    ///
    /// The image depends on the tree of the commit alone, so the metadata of
    /// the commit and the repository mode do not change the digest. The image
    /// goes to [`std::io::sink`], so the digest needs no image-sized buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `commit` already carries
    ///   `ostree.composefs.digest.v0`.
    /// - [`Error::InvalidGcAnchor`] if an entry of the new metadata gives a
    ///   key of `[ex-ostrya] gc-root-metadata-keys` a value that a prune
    ///   refuses.
    /// - [`Error::Core`] if `[ex-ostrya] gc-root-metadata-keys` holds a
    ///   malformed escape sequence.
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
    /// - [`Error::Io`] if a file system operation fails, if a metadata object
    ///   is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), or if
    ///   an `archive` payload does not inflate.
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
        let dir = self
            .composefs_commit_model(&commit_obj, &ComposefsOptions::RECORDED)
            .await?;
        let fs_verity = image_digest(dir).await?;
        let digest_type = Type::parse(DIGEST_SIGNATURE).map_err(ostrya_core::Error::from)?;
        let value = Value::variant(digest_type, Value::Bytes(fs_verity.to_vec()));
        append_dict_entry(&mut commit_obj.metadata, COMPOSEFS_DIGEST_KEY, value)?;
        check_gc_anchors(self.config(), [&commit_obj.metadata])?;
        let bytes = commit_obj.serialize()?;
        txn.write_metadata(ObjectType::Commit, None, &bytes).await
    }

    /// Builds and stores the composefs image of `commit`.
    ///
    /// The call begins a transaction before it reads the commit, runs
    /// [`Transaction::write_composefs_image`], and commits the transaction.
    /// The transaction holds the repository lock shared, so a prune cannot
    /// remove the commit or its objects during the build. The transaction
    /// applies the fsync policy, the fs-verity seal, and the free-space budget
    /// of the repository. If the call fails, it stores nothing.
    ///
    /// The commit must carry `ostree.composefs.digest.v0`.
    /// [`commit_add_composefs_metadata`](Repo::commit_add_composefs_metadata)
    /// writes a commit with the key and does not store the image.
    ///
    /// # Errors
    ///
    /// - The errors of [`Repo::transaction`].
    /// - The errors of [`Transaction::write_composefs_image`].
    /// - The errors of [`Transaction::commit`].
    pub async fn add_composefs_image(&self, commit: &Checksum) -> Result<ComposefsImageAdd> {
        let txn = self.transaction().await?;
        let result = txn.write_composefs_image(commit).await?;
        txn.commit().await?;
        Ok(result)
    }

    /// Returns the path of the composefs image object of `commit`.
    ///
    /// The path is [`path`](Repo::path) joined with
    /// `objects/<xx>/<rest>.cfs`. The call does no I/O, so the image need not
    /// exist. A relative [`path`](Repo::path) gives a relative result.
    pub fn composefs_image_path(&self, commit: &Checksum) -> PathBuf {
        self.path().join("objects").join(loose_path(
            commit,
            ObjectType::ComposefsImage,
            self.mode(),
        ))
    }

    /// Compares the stored composefs image of `commit` with the key
    /// `ostree.composefs.digest.v0` of the commit.
    ///
    /// The call streams the image through the fs-verity hasher in chunks of
    /// 128 KiB. It does not read the digest of a sealed image from the kernel.
    /// [`ComposefsImageState`] lists the results.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the commit object is not in the object
    ///   store.
    /// - [`Error::Core`] if the commit object does not parse.
    /// - [`Error::InvalidFormat`] if the first entry of
    ///   `ostree.composefs.digest.v0` is not a variant of type `ay` with 32
    ///   bytes.
    /// - [`Error::Io`] if a read of the image or another file system operation
    ///   fails, or if the commit object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    pub async fn check_composefs_image(&self, commit: &Checksum) -> Result<ComposefsImageState> {
        let bytes = self.load_object_bytes(ObjectType::Commit, commit).await?;
        let commit_obj = Commit::parse(&bytes)?;
        let Some(expected) = recorded_digest(&commit_obj)? else {
            return Ok(ComposefsImageState::NoKey);
        };
        Ok(match self.stored_image_digest(commit).await? {
            None => ComposefsImageState::Absent,
            Some(actual) if actual == expected => ComposefsImageState::Valid,
            Some(actual) => ComposefsImageState::Mismatch { expected, actual },
        })
    }

    /// Returns the fs-verity digest of the stored composefs image of
    /// `commit`, or `None` if the repository holds no image of it.
    ///
    /// The call streams the image on the blocking pool, as
    /// [`stored_image_digest_blocking`] does.
    pub(crate) async fn stored_image_digest(&self, commit: &Checksum) -> Result<Option<[u8; 32]>> {
        let repo = self.clone();
        let commit = *commit;
        ostrya_rt::unblock(move || {
            stored_image_digest_blocking(repo.objects_fd(), &commit, repo.mode())
        })
        .await
    }
}

/// Returns the fs-verity digest of the stored composefs image of `commit`
/// under `objects_fd`, or `None` if the image is absent.
///
/// The function reads the image in chunks of 128 KiB and feeds each chunk to
/// the fs-verity hasher, so it holds no image-sized buffer.
pub(crate) fn stored_image_digest_blocking(
    objects_fd: BorrowedFd<'_>,
    commit: &Checksum,
    mode: RepoMode,
) -> Result<Option<[u8; 32]>> {
    let path = loose_path(commit, ObjectType::ComposefsImage, mode);
    let fd = match rustix::fs::openat(
        objects_fd,
        path.as_str(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut file = std::fs::File::from(fd);
    Ok(Some(image_file_digest(&mut file)?))
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
    entry
        .as_variant()
        .filter(|(ty, _)| ty.signature() == DIGEST_SIGNATURE)
        .and_then(|(_, value)| value.as_bytes())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(Some)
        .ok_or_else(|| {
            Error::InvalidFormat(format!(
                "the value of {COMPOSEFS_DIGEST_KEY} is not a variant of type \
                 {DIGEST_SIGNATURE} with 32 bytes"
            ))
        })
}

/// Returns the digest that `commit_obj` records, as [`recorded_digest`] does.
/// A commit without the key is refused with [`Error::InvalidInput`].
fn require_recorded_digest(commit_obj: &Commit, commit: &Checksum) -> Result<[u8; 32]> {
    recorded_digest(commit_obj)?.ok_or_else(|| {
        Error::InvalidInput(format!(
            "commit {commit} does not carry {COMPOSEFS_DIGEST_KEY}, so it has no composefs image"
        ))
    })
}

/// Refuses `image` with [`Error::ComposefsDigestMismatch`] if its digest is
/// not `key`, the digest that `commit` records.
fn check_image_digest(
    commit: &Checksum,
    key: &[u8; 32],
    image: &StagedComposefsImage<'_>,
) -> Result<()> {
    if image.digest != *key {
        return Err(Error::ComposefsDigestMismatch {
            commit: *commit,
            expected: *key,
            actual: image.digest,
        });
    }
    Ok(())
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
/// file content, so the shape of the tree bounds its size.
async fn composefs_model(
    source: ObjectSource<'_>,
    root: &RepoTree,
    opts: &ComposefsOptions,
) -> Result<Directory> {
    let mut dir = build_directory(
        source,
        *root.dirtree_checksum(),
        *root.dirmeta_checksum(),
        opts.verity,
    )
    .await?;
    inject_top_level_dirs(&mut dir);
    Ok(dir)
}

/// Serializes `dir` through `fd` and returns the fs-verity digest of the
/// image. A buffer wraps the descriptor, because the writer emits the image in
/// many small writes.
fn write_image_to_fd(dir: &Directory, fd: OwnedFd) -> std::result::Result<[u8; 32], WriterError> {
    let mut out = BufWriter::new(std::fs::File::from(fd));
    write_image_to(dir, &mut out)
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
/// tree, and recurses into its subdirectories. The future is boxed because the
/// recursion is async.
fn build_directory(
    source: ObjectSource<'_>,
    dirtree: Checksum,
    dirmeta: Checksum,
    verity: VerityPolicy,
) -> TreeFuture<'_> {
    Box::pin(async move {
        let meta = source.dirmeta(&dirmeta).await?;
        let mut dir = Directory::new(dirmeta_to_metadata(&meta)?);
        let tree = source.dirtree(&dirtree).await?;
        for (name, checksum) in tree.files {
            let node = file_node(source, &checksum, verity).await?;
            dir.children.insert(name.into_bytes(), node);
        }
        for (name, subtree, submeta) in tree.dirs {
            let sub = build_directory(source, subtree, submeta, verity).await?;
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
///   [`VerityPolicy::Computed`], it carries the fs-verity digest of its
///   content.
///
/// The call reads the file object under both policies, because the metadata
/// of the inode comes from it.
async fn file_node(
    source: ObjectSource<'_>,
    checksum: &Checksum,
    verity: VerityPolicy,
) -> Result<Node> {
    let file = source
        .file(checksum, verity == VerityPolicy::Computed)
        .await?;
    let meta = file_to_metadata(&file)?;
    match &file.kind {
        FileKind::Symlink { target } => Ok(Node::Symlink(Symlink {
            meta,
            target: target.clone().into_bytes(),
        })),
        FileKind::Regular { size } => {
            let content = if *size == 0 {
                Content::Empty
            } else {
                let digest = match verity {
                    VerityPolicy::Computed => Some(content_fs_verity(&file).await?),
                    VerityPolicy::Disabled => None,
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
/// the kernel gave at load. The call then reads no payload byte. The seal must
/// name SHA-256, 4096-byte blocks, no salt, and the payload size. In all other
/// cases, the call streams the payload of the object through the hasher in
/// bounded chunks. The digest
/// covers the content, so a repository that stores the object compressed gives
/// the same value as one that stores it raw.
async fn content_fs_verity(file: &FileObject) -> Result<[u8; 32]> {
    use futures_lite::AsyncReadExt;

    if let Some(digest) = file.kernel_fs_verity() {
        return Ok(digest);
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
    Ok(hasher.finalize())
}

/// Inserts the five top-level directories that the `ostree` command adds. If
/// the root of the commit already holds one of these names, its entry stays.
fn inject_top_level_dirs(root: &mut Directory) {
    for name in INJECTED_DIRS {
        let key = name.as_bytes().to_vec();
        root.children.entry(key).or_insert_with(|| {
            Node::Directory(Directory::new(Metadata {
                mode: INJECTED_DIR_MODE,
                uid: 0,
                gid: 0,
                mtime: (0, 0),
                xattrs: Vec::new(),
            }))
        });
    }
}

/// Returns the composefs [`Metadata`] of a directory. The `ostree` command
/// sets the mtime of each exported inode to 0.
fn dirmeta_to_metadata(dirmeta: &DirMeta) -> Result<Metadata> {
    Ok(Metadata {
        mode: dirmeta.mode,
        uid: dirmeta.uid,
        gid: dirmeta.gid,
        mtime: (0, 0),
        xattrs: xattrs_to_model(&dirmeta.xattrs)?,
    })
}

/// Returns the composefs [`Metadata`] of a file object. The `ostree` command
/// sets the mtime of each exported inode to 0.
fn file_to_metadata(file: &FileObject) -> Result<Metadata> {
    Ok(Metadata {
        mode: file.mode,
        uid: file.uid,
        gid: file.gid,
        mtime: (0, 0),
        xattrs: xattrs_to_model(&file.xattrs)?,
    })
}

/// Converts an [`Xattrs`] set to the `(name, value)` pairs of the writer. A
/// stored name ends in a NUL byte. The writer indexes raw names, so the call
/// drops the NUL.
///
/// Each attribute spends its name, its value, and [`XATTR_ENTRY_COST`] bytes
/// from the budget of [`MAX_XATTR_TOTAL`] bytes of the inode. The call refuses
/// an inode that spends more. It holds each name to [`MAX_XATTR_NAME`] bytes,
/// the one EROFS length field that the budget does not bind. The bytes of the
/// tree enter the image model here, so the refusals are here.
fn xattrs_to_model(xattrs: &Xattrs) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut spent = 0usize;
    xattrs
        .iter()
        .map(|(name, value)| {
            let name = name.strip_suffix(&[0]).unwrap_or(name).to_vec();
            if name.len() > MAX_XATTR_NAME {
                return Err(Error::Unsupported(format!(
                    "xattr {} is {} bytes long, above the {MAX_XATTR_NAME} \
                     bytes a composefs image states a name in",
                    String::from_utf8_lossy(&name),
                    name.len(),
                )));
            }
            spent += XATTR_ENTRY_COST + name.len() + value.len();
            if spent > MAX_XATTR_TOTAL {
                return Err(Error::Unsupported(format!(
                    "xattr {} takes the inode to {spent} bytes of extended \
                     attributes, above the {MAX_XATTR_TOTAL} bytes a composefs \
                     image holds",
                    String::from_utf8_lossy(&name),
                )));
            }
            Ok((name, value.to_vec()))
        })
        .collect()
}
