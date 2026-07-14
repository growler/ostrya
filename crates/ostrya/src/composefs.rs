//! composefs / EROFS image export.
//!
//! [`Repo::export_composefs`] builds the composefs EROFS image for a commit's
//! tree. It reads the commit's [`RepoTree`], turns each directory, symlink, and
//! regular file into the tree model the [`ostrya_composefs`] writer consumes,
//! injects the five top-level directories the tool adds (`boot`, `etc`,
//! `sysroot`, `usr`, `var`), and drives the writer. Each regular file with
//! content redirects to its `.file` loose path and carries the fs-verity digest
//! of that backing object; the digest is computed by streaming the loose object
//! through the fs-verity primitive on the blocking pool, so no unconstrained
//! blob is buffered. The synchronous image assembly runs on the blocking pool
//! too.
//!
//! [`Repo::commit_add_composefs_metadata`] computes the image digest for an
//! existing commit and writes a new commit whose metadata dict carries
//! `ostree.composefs.digest.v0`, the value the tool stores and verifies at boot.
//!
//! The export applies to the composefs backing modes, `bare-user` and
//! `bare-user-shared`: the EROFS metadata comes from the logical
//! `user.ostreemeta` attributes and each regular file redirects to its `.file`
//! loose object. Ownership is presented through composefs uid mapping at mount,
//! so the stored uid/gid are the logical owners regardless of who runs the
//! export. Other modes are rejected.

use std::future::Future;
use std::os::fd::{AsFd, BorrowedFd};
use std::pin::Pin;

use ostrya_composefs::{
    Content, Directory, FsVerityHasher, Image, Metadata, Node, Regular, Symlink, build_image,
};
use ostrya_core::{Checksum, DirMeta, ObjectType, RepoMode, Type, Value, Xattrs, loose_path};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::commit::append_dict_entry;
use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject};
use crate::repo::Repo;
use crate::transaction::Transaction;
use crate::tree::{RepoTree, TreeEntry};

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

/// A boxed, `Send` future, used for the recursive tree walk (async recursion
/// needs indirection).
type TreeFuture<'a> = Pin<Box<dyn Future<Output = Result<Directory>> + Send + 'a>>;

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
        let mut root = self.build_directory(tree).await?;
        inject_top_level_dirs(&mut root);
        Ok(ostrya_rt::unblock(move || build_image(&root)).await)
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

    /// Build the composefs [`Directory`] model for one committed directory,
    /// recursing into subdirectories. Boxed because the recursion is async.
    fn build_directory(&self, tree: RepoTree) -> TreeFuture<'_> {
        Box::pin(async move {
            let dirmeta = self.load_dirmeta(tree.dirmeta_checksum()).await?;
            let mut dir = Directory::new(dirmeta_to_metadata(&dirmeta));
            for entry in tree.read_dir().await? {
                match entry {
                    TreeEntry::File { name, checksum } => {
                        let node = self.file_node(&checksum).await?;
                        dir.children.insert(name.into_bytes(), node);
                    }
                    TreeEntry::Dir { name, tree } => {
                        let sub = self.build_directory(tree).await?;
                        dir.children.insert(name.into_bytes(), Node::Directory(sub));
                    }
                }
            }
            Ok(dir)
        })
    }

    /// Build the composefs [`Node`] for a file object: a symlink stores its
    /// target inline, an empty regular file has no backing, and a regular file
    /// with content redirects to its `.file` loose path and carries that
    /// object's fs-verity digest.
    async fn file_node(&self, checksum: &Checksum) -> Result<Node> {
        let file = self.load_file(checksum).await?;
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
                        redirect: format!(
                            "/{}",
                            loose_path(checksum, ObjectType::File, self.mode())
                        ),
                        verity: self.backing_object_fs_verity(checksum).await?,
                    }
                };
                Ok(Node::Regular(Regular { meta, content }))
            }
        }
    }

    /// Compute the fs-verity digest of a regular file's backing `.file` loose
    /// object by streaming its bytes through the digester on the blocking pool.
    async fn backing_object_fs_verity(&self, checksum: &Checksum) -> Result<[u8; 32]> {
        let path = loose_path(checksum, ObjectType::File, self.mode());
        let objects_fd = self.objects_fd().try_clone_to_owned()?;
        let key = *checksum;
        ostrya_rt::unblock(move || fs_verity_of_object(objects_fd.as_fd(), &path, &key)).await
    }
}

/// Stream a loose object at `path` through the fs-verity digester in bounded
/// chunks, mapping a missing object to [`Error::ObjectNotFound`].
fn fs_verity_of_object(
    objects_fd: BorrowedFd<'_>,
    path: &str,
    checksum: &Checksum,
) -> Result<[u8; 32]> {
    use std::io::Read;

    let fd = rustix::fs::openat(
        objects_fd,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        if e == Errno::NOENT {
            Error::ObjectNotFound {
                checksum: *checksum,
                ty: ObjectType::File,
            }
        } else {
            Error::Io(e.into())
        }
    })?;
    let mut file = std::fs::File::from(fd);
    let mut hasher = FsVerityHasher::new();
    let mut buf = vec![0u8; DIGEST_CHUNK];
    loop {
        let n = file.read(&mut buf)?;
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
