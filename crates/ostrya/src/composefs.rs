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

use std::future::Future;
use std::io::BufWriter;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::pin::Pin;

use ostrya_composefs::{
    Content, Directory, Error as WriterError, FsVerityHasher, Image, Metadata, Node, Regular,
    Symlink, build_image, write_image_to,
};
use ostrya_core::{
    Checksum, Commit, DirMeta, DirTree, ObjectType, RepoMode, Type, Value, Xattrs, loose_path,
};

use crate::commit::append_dict_entry;
use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject};
use crate::repo::Repo;
use crate::transaction::Transaction;
use crate::tree::RepoTree;

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
const DIGEST_CHUNK: usize = 128 * 1024;
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

/// Methods that compute the composefs digest of a staged tree.
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
    /// The image depends on the tree of the commit alone, so the metadata of
    /// the commit and the repository mode do not change the digest. The image
    /// goes to [`std::io::sink`], so the digest needs no image-sized buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `commit` already carries
    ///   `ostree.composefs.digest.v0`.
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
        let bytes = commit_obj.serialize()?;
        txn.write_metadata(ObjectType::Commit, None, &bytes).await
    }
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
fn writer_error(err: WriterError) -> Error {
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
