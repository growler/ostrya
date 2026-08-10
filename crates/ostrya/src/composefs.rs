//! composefs / EROFS image export.
//!
//! [`Repo::export_composefs`] builds the composefs EROFS image for a commit's
//! tree. It reads the commit's [`RepoTree`], turns each directory, symlink, and
//! regular file into the tree model the [`ostrya_composefs`] writer consumes,
//! injects the five top-level directories the tool adds (`boot`, `etc`,
//! `sysroot`, `usr`, `var`), and drives the writer. Each regular file with
//! content redirects to its `.file` loose path and carries the fs-verity digest
//! of that content; the digest is computed by streaming the object's payload
//! through the fs-verity primitive in bounded chunks, so no unconstrained blob
//! is buffered. The synchronous image assembly runs on the blocking pool.
//!
//! [`Repo::commit_add_composefs_metadata`] computes the image digest for an
//! existing commit and writes a new commit whose metadata dict carries
//! `ostree.composefs.digest.v0`, the value the tool stores and verifies at boot.
//! [`Transaction::composefs_digest`] computes the same digest over a tree the
//! transaction has staged and not yet published, which is what a commit
//! carrying the key in its own metadata needs.
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
//! export. Other modes are rejected. The digest a commit stores is computed in
//! every mode, since the value is a fact about the tree.

use std::future::Future;
use std::pin::Pin;

use ostrya_composefs::{
    Content, Directory, FsVerityHasher, Image, Metadata, Node, Regular, Symlink, build_image,
};
use ostrya_core::{
    Checksum, DirMeta, DirTree, ObjectType, RepoMode, Type, Value, Xattrs, loose_path,
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

impl Transaction {
    /// The fs-verity digest of the composefs image for a tree this transaction
    /// has staged, the value `ostree.composefs.digest.v0` holds.
    ///
    /// The image is built from the staged objects, so the digest is available
    /// before the transaction publishes and can go into the metadata of the
    /// commit the tree belongs to. The value depends on the tree alone, so a
    /// repository of any mode holding that tree reaches the same digest.
    pub async fn composefs_digest(&self, root: &RepoTree) -> Result<[u8; 32]> {
        let image = build_composefs_image(ObjectSource::Staged(self), root).await?;
        Ok(image.fs_verity)
    }
}

impl Repo {
    /// Build the composefs EROFS image for `commit` and return its bytes and
    /// fs-verity digest.
    ///
    /// The repository must be a composefs backing mode (`bare-user` or
    /// `bare-user-shared`); any other mode is [`Error::Unsupported`].
    pub async fn export_composefs(&self, commit: &Checksum) -> Result<Image> {
        self.ensure_composefs_backing_mode()?;
        let (commit_obj, _) = self.load_commit(commit).await?;
        let tree = RepoTree::from_parts(
            self.clone(),
            commit_obj.root_dirtree,
            commit_obj.root_dirmeta,
        );
        build_composefs_image(ObjectSource::Repo(self), &tree).await
    }

    /// Compute the composefs image digest for `commit` and stage a new commit
    /// whose metadata carries `ostree.composefs.digest.v0`, returning the new
    /// commit's checksum. The new commit is published when `txn` commits.
    ///
    /// The image derives from the commit's tree alone, so the digest is
    /// independent of the metadata it is stored in. The digest key is appended
    /// to the commit's existing metadata dict; a commit that already carries it
    /// is [`Error::InvalidFormat`].
    pub async fn commit_add_composefs_metadata(
        &self,
        txn: &Transaction,
        commit: &Checksum,
    ) -> Result<Checksum> {
        let image = self.export_composefs(commit).await?;
        let (mut commit_obj, _) = self.load_commit(commit).await?;
        if commit_obj.metadata.dict_get(COMPOSEFS_DIGEST_KEY).is_some() {
            return Err(Error::InvalidFormat(format!(
                "commit already carries {COMPOSEFS_DIGEST_KEY}"
            )));
        }
        let digest_type = Type::parse(DIGEST_SIGNATURE).map_err(ostrya_core::Error::from)?;
        let value = Value::variant(digest_type, Value::Bytes(image.fs_verity.to_vec()));
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

/// Build the composefs EROFS image for `root`, reading the tree's objects from
/// `source`, and return its bytes and fs-verity digest.
async fn build_composefs_image(source: ObjectSource<'_>, root: &RepoTree) -> Result<Image> {
    let mut dir =
        build_directory(source, *root.dirtree_checksum(), *root.dirmeta_checksum()).await?;
    inject_top_level_dirs(&mut dir);
    Ok(ostrya_rt::unblock(move || build_image(&dir)).await)
}

/// Build the composefs [`Directory`] model for one directory of a committed
/// tree, recursing into subdirectories. Boxed because the recursion is async.
fn build_directory(
    source: ObjectSource<'_>,
    dirtree: Checksum,
    dirmeta: Checksum,
) -> TreeFuture<'_> {
    Box::pin(async move {
        let meta = source.dirmeta(&dirmeta).await?;
        let mut dir = Directory::new(dirmeta_to_metadata(&meta));
        let tree = source.dirtree(&dirtree).await?;
        for (name, checksum) in tree.files {
            let node = file_node(source, &checksum).await?;
            dir.children.insert(name.into_bytes(), node);
        }
        for (name, subtree, submeta) in tree.dirs {
            let sub = build_directory(source, subtree, submeta).await?;
            dir.children.insert(name.into_bytes(), Node::Directory(sub));
        }
        Ok(dir)
    })
}

/// Build the composefs [`Node`] for a file object: a symlink stores its target
/// inline, an empty regular file has no backing, and a regular file with
/// content redirects to its `.file` loose path and carries the fs-verity digest
/// of its content.
async fn file_node(source: ObjectSource<'_>, checksum: &Checksum) -> Result<Node> {
    let file = source.file(checksum).await?;
    let meta = file_to_metadata(&file);
    match &file.kind {
        FileKind::Symlink { target } => Ok(Node::Symlink(Symlink {
            meta,
            target: target.clone().into_bytes(),
        })),
        FileKind::Regular { size } => {
            let content = if *size == 0 {
                Content::Empty
            } else {
                Content::Backed {
                    size: *size,
                    redirect: format!("/{}", loose_path(checksum, ObjectType::File, BACKING_MODE)),
                    verity: content_fs_verity(&file).await?,
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
fn dirmeta_to_metadata(dirmeta: &DirMeta) -> Metadata {
    Metadata {
        mode: dirmeta.mode,
        uid: dirmeta.uid,
        gid: dirmeta.gid,
        mtime: (0, 0),
        xattrs: xattrs_to_model(&dirmeta.xattrs),
    }
}

/// The composefs [`Metadata`] for a file object. The tool sets every exported
/// inode's mtime to 0.
fn file_to_metadata(file: &FileObject) -> Metadata {
    Metadata {
        mode: file.mode,
        uid: file.uid,
        gid: file.gid,
        mtime: (0, 0),
        xattrs: xattrs_to_model(&file.xattrs),
    }
}

/// Convert an [`Xattrs`] set to the writer's `(name, value)` pairs. Stored
/// names carry a terminating NUL; the writer indexes raw names, so the NUL is
/// dropped.
fn xattrs_to_model(xattrs: &Xattrs) -> Vec<(Vec<u8>, Vec<u8>)> {
    xattrs
        .iter()
        .map(|(name, value)| {
            let name = name.strip_suffix(&[0]).unwrap_or(name).to_vec();
            (name, value.to_vec())
        })
        .collect()
}
