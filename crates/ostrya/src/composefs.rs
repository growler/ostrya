//! composefs / EROFS image export.
//!
//! [`Repo::export_composefs`] builds the composefs EROFS image for a commit's
//! tree. It reads the commit's [`RepoTree`], turns each directory, symlink, and
//! regular file into the tree model the [`ostrya_composefs`] writer consumes,
//! injects the five top-level directories the tool adds (`boot`, `etc`,
//! `sysroot`, `usr`, `var`), and drives the writer. Each regular file with
//! content redirects to its `.file` loose path and, under the default verity
//! policy, carries the fs-verity digest of that content; the digest is computed
//! by streaming the object's payload through the fs-verity primitive in bounded
//! chunks, so no unconstrained blob is buffered. The synchronous image
//! assembly runs on the blocking pool.
//!
//! [`Repo::export_composefs_to`] writes the same image through a file
//! descriptor and returns its fs-verity digest. Emission is append-only, so
//! the image reaches the descriptor as it is serialized and no image-sized
//! buffer is held. [`Repo::export_composefs`] returns the bytes for a caller
//! that wants them in memory.
//!
//! [`ComposefsOptions`] carries the verity policy. Under
//! [`VerityPolicy::Computed`], the default, each backed file carries the
//! 36-byte metacopy record holding its content's fs-verity digest. Under
//! [`VerityPolicy::Disabled`] the metacopy xattr is present with an empty
//! value, no payload is streamed, and the image the export writes has its own
//! fs-verity digest, distinct from the value a commit records under
//! `ostree.composefs.digest.v0`. The recorded value is the digest of the
//! verity-form image, which is what a target machine reproduces at boot, so
//! the two are not compared. Every backing object is still opened under both
//! policies, because the inode's mode, ownership, size, and xattrs come from
//! the file object.
//!
//! [`Repo::commit_add_composefs_metadata`] computes the image digest for an
//! existing commit and writes a new commit whose metadata dict carries
//! `ostree.composefs.digest.v0`, the value the tool stores and verifies at boot.
//! [`Transaction::composefs_digest`] computes the same digest over a tree the
//! transaction has staged and not yet published, which is what a commit
//! carrying the key in its own metadata needs. Both write the image through
//! [`std::io::sink`], so neither holds an image.
//!
//! The image derives from the committed tree alone. Each regular file redirects
//! to the `.file` loose path, the form the composefs backing modes store, and
//! carries the fs-verity digest of the file's content, so a repository holding
//! the same tree produces the same image and the same digest whatever its mode.
//!
//! The export applies to the composefs backing modes, `bare-user` and
//! `bare-user-shared`: the EROFS metadata comes from the logical
//! `user.ostreemeta` attributes and each regular file redirects to its `.file`
//! loose object. Ownership is presented through composefs uid mapping at mount,
//! so the stored uid/gid are the logical owners regardless of who runs the
//! export. Other modes are rejected. The two digest-only paths,
//! [`Repo::commit_add_composefs_metadata`] and
//! [`Transaction::composefs_digest`], build no image and run in every mode,
//! since the value is a fact about the tree.
//!
//! One tree fact has no place in the image: an inode that spends too much on
//! extended attributes. Each attribute spends its name, its value, and 7 bytes
//! from a budget of 32755 bytes for the inode. The tool refuses a tree that
//! spends more, so every path here refuses it with [`Error::Unsupported`] where
//! the tree's bytes enter the image model. A commit past the budget would carry
//! a composefs digest no `ostree` reproduces at boot. The budget sits under the
//! 65535 bytes an EROFS xattr entry states its value length in, so that field
//! never binds first. A name is held there as well, at the 255 bytes the
//! entry's name-length field states, which the budget leaves unbound.
//! `docs/format-reference.md`, "composefs", records the observation the budget
//! comes from and the width of each field.
//!
//! A symlink target that fills its inode's block has no place there either. The
//! image states a target inline, beside the inode header and the inode's
//! extended attributes, so the writer refuses a target above what those two
//! leave in a block: 4063 bytes for a symlink carrying no attributes. Every
//! path here reports that refusal as [`Error::Unsupported`]. The tool aborts on
//! the same trees, which `docs/format-reference.md`, "composefs", records.
//! `PATH_MAX` keeps a target that long out of a tree a checkout produces; a tar
//! import reaches it.

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

/// The empty top-level directories the tool injects into every exported image.
const INJECTED_DIRS: [&str; 5] = ["boot", "etc", "sysroot", "usr", "var"];
/// The mode the tool gives each injected top-level directory (`040755`).
const INJECTED_DIR_MODE: u32 = 0o040755;
/// The commit metadata key holding the image's fs-verity digest.
const COMPOSEFS_DIGEST_KEY: &str = "ostree.composefs.digest.v0";
/// The GVariant type of the digest value, a 32-byte `ay`.
const DIGEST_SIGNATURE: &str = "ay";
/// The chunk size used to stream a backing object through the digester.
const DIGEST_CHUNK: usize = 128 * 1024;
/// The bytes one xattr spends from an inode's composefs xattr budget, on top of
/// its name and its value.
const XATTR_ENTRY_COST: usize = 7;
/// The composefs xattr budget of one inode, in bytes.
const MAX_XATTR_TOTAL: usize = 32755;
/// The longest xattr name an EROFS entry states its length in. The stored name
/// is the prefix-stripped suffix, which is no longer than the full name, so the
/// full name is held to this bound and the prefix table stays in the writer.
const MAX_XATTR_NAME: usize = u8::MAX as usize;
/// The repository mode whose loose-path form each backing redirect names. The
/// image points at the `.file` objects a composefs backing store holds, whatever
/// mode the repository the image was built from uses.
const BACKING_MODE: RepoMode = RepoMode::BareUser;

/// A boxed, `Send` future, used for the recursive tree walk (async recursion
/// needs indirection).
type TreeFuture<'a> = Pin<Box<dyn Future<Output = Result<Directory>> + Send + 'a>>;

/// Where the composefs walk reads the tree's objects.
#[derive(Clone, Copy)]
enum ObjectSource<'a> {
    /// A published repository: every object is a loose object under `objects/`.
    Repo(&'a Repo),
    /// A transaction: an object it staged is read from the staging directory,
    /// and one that deduplicated from `objects/`.
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

    async fn file(&self, checksum: &Checksum) -> Result<FileObject> {
        match self {
            ObjectSource::Repo(repo) => repo.load_file(checksum).await,
            ObjectSource::Staged(txn) => txn.load_file_staged_first(checksum).await,
        }
    }
}

/// Whether an exported image carries the backing objects' fs-verity digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerityPolicy {
    /// Each backed file carries the 36-byte metacopy record holding the
    /// fs-verity digest of its content. The payload of every backing object is
    /// streamed to compute it.
    #[default]
    Computed,
    /// Each backed file carries the metacopy xattr with an empty value. No
    /// payload is read.
    Disabled,
}

/// Options for a composefs export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ComposefsOptions {
    /// The verity policy the image is written under.
    pub verity: VerityPolicy,
}

/// The policy the recorded digest is taken under. `ostree.composefs.digest.v0`
/// holds the digest of the verity-form image, the artifact a target machine
/// reproduces at boot, so the two sites that compute the recorded value name
/// [`VerityPolicy::Computed`] rather than take it from the default.
const RECORDED_POLICY: ComposefsOptions = ComposefsOptions {
    verity: VerityPolicy::Computed,
};

impl Transaction {
    /// The fs-verity digest of the composefs image for a tree this transaction
    /// has staged, the value `ostree.composefs.digest.v0` holds.
    ///
    /// The image is built from the staged objects, so the digest is available
    /// before the transaction publishes and can go into the metadata of the
    /// commit the tree belongs to. The value depends on the tree alone, so a
    /// repository of any mode holding that tree reaches the same digest.
    /// The image is written through [`std::io::sink`], so the digest costs no
    /// image-sized buffer.
    pub async fn composefs_digest(&self, root: &RepoTree) -> Result<[u8; 32]> {
        let dir = composefs_model(ObjectSource::Staged(self), root, &RECORDED_POLICY).await?;
        image_digest(dir).await
    }
}

impl Repo {
    /// Build the composefs EROFS image for `commit` and return its bytes and
    /// fs-verity digest.
    ///
    /// The repository must be a composefs backing mode (`bare-user` or
    /// `bare-user-shared`); any other mode is [`Error::Unsupported`].
    ///
    /// `opts.verity` decides whether each backed file carries the fs-verity
    /// digest of its content. Under [`VerityPolicy::Disabled`] the image's own
    /// digest differs from the value a commit records under
    /// `ostree.composefs.digest.v0`.
    pub async fn export_composefs(
        &self,
        commit: &Checksum,
        opts: &ComposefsOptions,
    ) -> Result<Image> {
        self.ensure_composefs_backing_mode()?;
        let dir = self.composefs_export_model(commit, opts).await?;
        ostrya_rt::unblock(move || build_image(&dir))
            .await
            .map_err(writer_error)
    }

    /// Write the composefs EROFS image for `commit` through `out` and return the
    /// image's fs-verity digest.
    ///
    /// The image goes to the file descriptor as it is serialized, so no
    /// image-sized buffer is held. `out` is written from its current offset
    /// onward and is never seeked, and a call that fails leaves the prefix it
    /// had already written. The mode rule and `opts.verity` are those of
    /// [`Repo::export_composefs`].
    pub async fn export_composefs_to(
        &self,
        commit: &Checksum,
        opts: &ComposefsOptions,
        out: BorrowedFd<'_>,
    ) -> Result<[u8; 32]> {
        self.ensure_composefs_backing_mode()?;
        let dir = self.composefs_export_model(commit, opts).await?;
        // The blocking pool needs an owned handle, so the caller's descriptor is
        // duplicated for the closure to move.
        let fd = out.try_clone_to_owned()?;
        ostrya_rt::unblock(move || write_image_to_fd(&dir, fd))
            .await
            .map_err(writer_error)
    }

    /// The composefs tree model for `commit`'s root, the step the two export
    /// entry points share. Every mode reaches the same model, so the mode check
    /// belongs to the two entry points that write an image and not here.
    async fn composefs_export_model(
        &self,
        commit: &Checksum,
        opts: &ComposefsOptions,
    ) -> Result<Directory> {
        let (commit_obj, _) = self.load_commit(commit).await?;
        self.composefs_commit_model(&commit_obj, opts).await
    }

    /// The composefs tree model for the root of a commit already loaded.
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

    /// Compute the composefs image digest for `commit` and stage a new commit
    /// whose metadata carries `ostree.composefs.digest.v0`, returning the new
    /// commit's checksum. The new commit is published when `txn` commits.
    ///
    /// The image derives from the commit's tree alone, so the digest is
    /// independent of the metadata it is stored in and of the repository's mode;
    /// every mode holding that tree reaches the same value. The digest key is
    /// appended to the commit's existing metadata dict; a commit that already
    /// carries it is [`Error::InvalidFormat`]. The image is written through
    /// [`std::io::sink`], so the digest costs no image-sized buffer.
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
            .composefs_commit_model(&commit_obj, &RECORDED_POLICY)
            .await?;
        let fs_verity = image_digest(dir).await?;
        let digest_type = Type::parse(DIGEST_SIGNATURE).map_err(ostrya_core::Error::from)?;
        let value = Value::variant(digest_type, Value::Bytes(fs_verity.to_vec()));
        append_dict_entry(&mut commit_obj.metadata, COMPOSEFS_DIGEST_KEY, value)?;
        let bytes = commit_obj.serialize()?;
        txn.write_metadata(ObjectType::Commit, None, &bytes).await
    }

    /// Reject a repository whose mode is not a composefs backing mode.
    fn ensure_composefs_backing_mode(&self) -> Result<()> {
        match self.mode() {
            RepoMode::BareUser | RepoMode::BareUserShared => Ok(()),
            other => Err(Error::Unsupported(format!(
                "composefs export requires a bare-user or bare-user-shared \
                 repository, not {other:?}"
            ))),
        }
    }
}

/// Build the composefs tree model for `root`, reading the tree's objects from
/// `source`. The model holds each file's metadata and its backing redirect, and
/// no file content, so it is bounded by the tree's shape.
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

/// Serialize `dir` through `fd` and return the image's fs-verity digest. The
/// descriptor is buffered, because the writer emits the image in many small
/// writes.
fn write_image_to_fd(dir: &Directory, fd: OwnedFd) -> std::result::Result<[u8; 32], WriterError> {
    let mut out = BufWriter::new(std::fs::File::from(fd));
    write_image_to(dir, &mut out)
}

/// The fs-verity digest of the image for `dir`, for a caller that wants the
/// digest and not the image. The image goes through [`std::io::sink`], so it is
/// never held.
async fn image_digest(dir: Directory) -> Result<[u8; 32]> {
    ostrya_rt::unblock(move || write_image_to(&dir, &mut std::io::sink()))
        .await
        .map_err(writer_error)
}

/// The library error for a writer refusal. The writer holds the bounds the
/// image itself states, which the tree reaches, so its refusal is the tree's.
fn writer_error(err: WriterError) -> Error {
    match err {
        WriterError::Unsupported(msg) => Error::Unsupported(msg),
        WriterError::Io(err) => Error::Io(err),
    }
}

/// Build the composefs [`Directory`] model for one directory of a committed
/// tree, recursing into subdirectories. Boxed because the recursion is async.
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

/// Build the composefs [`Node`] for a file object: a symlink stores its target
/// inline, an empty regular file has no backing, and a regular file with
/// content redirects to its `.file` loose path and carries the fs-verity digest
/// of its content under [`VerityPolicy::Computed`]. The file object is read
/// under either policy, because the inode's metadata comes from it.
async fn file_node(
    source: ObjectSource<'_>,
    checksum: &Checksum,
    verity: VerityPolicy,
) -> Result<Node> {
    let file = source.file(checksum).await?;
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

/// Compute the fs-verity digest of a regular file's content by streaming the
/// object's payload through the digester in bounded chunks. The content is what
/// the digest covers, so a repository storing the object compressed reaches the
/// same value as one storing it raw.
async fn content_fs_verity(file: &FileObject) -> Result<[u8; 32]> {
    use futures_lite::AsyncReadExt;

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

/// Insert the five top-level directories the tool injects, skipping any name the
/// commit's own root already holds.
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

/// The composefs [`Metadata`] for a directory. The tool sets every exported
/// inode's mtime to 0.
fn dirmeta_to_metadata(dirmeta: &DirMeta) -> Result<Metadata> {
    Ok(Metadata {
        mode: dirmeta.mode,
        uid: dirmeta.uid,
        gid: dirmeta.gid,
        mtime: (0, 0),
        xattrs: xattrs_to_model(&dirmeta.xattrs)?,
    })
}

/// The composefs [`Metadata`] for a file object. The tool sets every exported
/// inode's mtime to 0.
fn file_to_metadata(file: &FileObject) -> Result<Metadata> {
    Ok(Metadata {
        mode: file.mode,
        uid: file.uid,
        gid: file.gid,
        mtime: (0, 0),
        xattrs: xattrs_to_model(&file.xattrs)?,
    })
}

/// Convert an [`Xattrs`] set to the writer's `(name, value)` pairs. Stored
/// names carry a terminating NUL; the writer indexes raw names, so the NUL is
/// dropped.
///
/// Each attribute spends its name, its value, and [`XATTR_ENTRY_COST`] bytes
/// from the inode's budget of [`MAX_XATTR_TOTAL`] bytes, and an inode that
/// spends more is refused. Each name is held to [`MAX_XATTR_NAME`] bytes, the
/// one EROFS length field the budget does not bind. This is where the tree's
/// own bytes enter the image model, so the refusals belong here.
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
