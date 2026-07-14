//! The checkout path: materializing a committed tree onto a filesystem.
//!
//! [`Repo::checkout_at`] writes the tree of a commit into a destination
//! directory, reproducing the metadata the repository mode records. A
//! [`CheckoutOptions`] shapes it: the checkout mode ([`None`](CheckoutMode::None)
//! or [`User`](CheckoutMode::User)), the overwrite policy over an existing
//! destination, an optional subpath, whether to fsync, whether to force a copy
//! over a hardlink, whether to process Docker-style whiteouts, an optional
//! [`DevInoCache`] to populate, and an optional filter.
//!
//! For each regular file the checkout hardlinks the loose object into place when
//! the object's stored inode is already byte-identical to what the checkout
//! would otherwise write, and copies otherwise. The copy path streams the
//! payload through [`FileObject::reader`], attempting a `FICLONE` reflink on a
//! non-archive object before falling back to a byte copy. Directories are always
//! created fresh and receive their full logical mode after their children are
//! materialized, so a restrictive mode does not block writing them. The
//! recovered facts these rules reproduce are recorded in `format-reference.md`,
//! "Checkout".
//!
//! The per-directory traversal is async (dirtree and dirmeta load through the
//! blocking pool); per-file materialization -- metadata application, reflink,
//! hardlink, rename -- runs on the blocking pool through [`ostrya_rt::unblock`];
//! the copy path streams payload bytes through an `rt::File` in bounded chunks,
//! so no whole object is buffered.

use std::future::Future;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use ostrya_core::{Checksum, Commit, DirMeta, ObjectType, RepoMode, Xattrs, loose_path};
use ostrya_rt::File as RtFile;
use rustix::fs::{AtFlags, CWD, Dir, FileType, Gid, Mode, OFlags, RenameFlags, Uid};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject};
use crate::ingest::join_path;
use crate::modifier::{DevInoCache, FilterResult};
use crate::read::CommitState;
use crate::repo::Repo;
use crate::tree::{RepoTree, TreeEntry};
use crate::write::{FileMeta, TempKind};

/// The permission-and-special-bit mask of an `st_mode` (`perm & 0o7777`).
const PERM_MASK: u32 = 0o7777;
/// The permission mask a [`User`](CheckoutMode::User) checkout applies to a
/// regular file (`perm & 0o777`): the setuid, setgid, and sticky bits are
/// dropped, the rwx bits including group- and other-write are kept.
const USER_PERM_MASK: u32 = 0o777;
/// The transient mode a directory is created with so its children can be
/// written; the final logical mode is applied after they are materialized.
const TRANSIENT_DIR_MODE: u32 = 0o700;
/// The overlayfs opaque-directory marker, an entry that clears the destination
/// directory's pre-existing content before the committed entries are written.
const OPAQUE_MARKER: &str = ".wh..wh..opq";
/// The Docker-style whiteout name prefix; `.wh.<name>` removes `<name>` from the
/// destination directory.
const WHITEOUT_PREFIX: &str = ".wh.";

/// How checkout applies ownership, permissions, and xattrs to materialized
/// files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CheckoutMode {
    /// The faithful checkout (`ostree checkout`): chown to the logical uid/gid,
    /// chmod to the full logical permission bits, and apply the logical xattrs.
    #[default]
    None,
    /// The unprivileged checkout (`ostree checkout -U`): no chown, no xattrs; a
    /// regular file's mode drops the setuid/setgid/sticky bits, a directory's
    /// mode keeps them.
    User,
}

/// How checkout treats a pre-existing destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverwriteMode {
    /// The destination must be created fresh; any collision is an error
    /// (`ostree checkout`).
    #[default]
    None,
    /// Keep existing directories, overwrite existing files, add new entries, and
    /// leave untouched existing entries in place (`ostree checkout --union`).
    UnionFiles,
    /// Keep existing files and directories, only add entries that do not already
    /// exist (`ostree checkout --union-add`).
    AddFiles,
    /// Add new entries; an existing entry identical (by inode) to the object it
    /// would receive is left in place, and a differing existing entry is an
    /// error (`ostree checkout --union-identical`).
    UnionIdentical,
}

/// A synchronous filter over checked-out paths. A [`Skip`](FilterResult::Skip)
/// on a directory prunes its whole subtree.
pub type CheckoutFilterFn = Box<dyn FnMut(&Path, &FileMeta) -> FilterResult + Send>;

/// Options for [`Repo::checkout_at`].
///
/// Construct with [`new`](CheckoutOptions::new) or [`Default`] and set the
/// fields directly. `checkout_at` takes the options by `&mut`, so the filter
/// callback runs through an exclusive borrow and the devino cache is populated in
/// place.
pub struct CheckoutOptions {
    /// The checkout mode.
    pub mode: CheckoutMode,
    /// The overwrite policy over an existing destination.
    pub overwrite: OverwriteMode,
    /// A path within the commit tree to check out as the destination root,
    /// instead of the whole tree.
    pub subpath: Option<PathBuf>,
    /// Whether to fsync written files and directories. Defaults false, matching
    /// the tool.
    pub enable_fsync: bool,
    /// Force a copy for every object, suppressing every hardlink. The copy path
    /// still attempts a reflink.
    pub force_copy: bool,
    /// Process Docker-style whiteouts (`.wh.<name>` and `.wh..wh..opq`) instead
    /// of materializing them as ordinary files.
    pub process_whiteouts: bool,
    /// A devino cache to populate: each regular file's destination
    /// `(st_dev, st_ino)` is recorded against its checksum as it is written or
    /// linked.
    pub devino_cache: Option<DevInoCache>,
    /// A filter called per path to include or prune entries.
    pub filter: Option<CheckoutFilterFn>,
}

impl Default for CheckoutOptions {
    fn default() -> CheckoutOptions {
        CheckoutOptions {
            mode: CheckoutMode::None,
            overwrite: OverwriteMode::None,
            subpath: None,
            enable_fsync: false,
            force_copy: false,
            process_whiteouts: false,
            devino_cache: None,
            filter: None,
        }
    }
}

impl CheckoutOptions {
    /// Options for the given checkout mode with every other field at its default.
    pub fn new(mode: CheckoutMode) -> CheckoutOptions {
        CheckoutOptions {
            mode,
            ..CheckoutOptions::default()
        }
    }
}

impl Repo {
    /// Check the tree of `commit` out into `dest_path`, relative to `dest_dir`,
    /// shaped by `opts`.
    ///
    /// With no subpath the whole commit tree is written and the destination root
    /// receives the tree root's dirmeta. With a subpath naming a directory, that
    /// subtree is written and its dirmeta becomes the destination root's; with a
    /// subpath naming a file or symlink, the destination directory is created and
    /// the single object is placed inside it under its name.
    ///
    /// `dest_path` names the destination root relative to `dest_dir`; its parent
    /// components must already exist. A `.` or empty `dest_path` checks out into
    /// `dest_dir` itself without creating or re-stamping a root directory.
    pub async fn checkout_at(
        &self,
        opts: &mut CheckoutOptions,
        dest_dir: BorrowedFd<'_>,
        dest_path: &Path,
        commit: &Checksum,
    ) -> Result<()> {
        let policy = Policy::new(self.mode(), opts);
        // union-identical establishes identity by the object inode, so it is
        // meaningful only for a hardlink checkout. Reject it before any I/O when
        // the repository mode and checkout mode (or force_copy) produce copies,
        // matching the tool's refusal to run `--union-identical` without
        // `--require-hardlinks`.
        if policy.overwrite == OverwriteMode::UnionIdentical && !hardlink_regular(policy) {
            return Err(Error::Checkout(
                "union-identical requires a hardlink checkout, but this repository \
                 mode and checkout mode (or force_copy) produce copies"
                    .into(),
            ));
        }
        let (commit_obj, state) = self.load_commit(commit).await?;
        if state == CommitState::Partial {
            return Err(Error::Checkout(format!(
                "commit {} is partial; checkout needs a complete commit",
                commit.to_hex()
            )));
        }
        let target = resolve_target(self, &commit_obj, opts.subpath.as_deref()).await?;
        let (parent_fd, name) = open_dest_parent(dest_dir, dest_path)?;

        match target {
            Target::Dir { dirtree, dirmeta } => {
                let dm = self.load_dirmeta(&dirmeta).await?;
                let (dir_fd, fresh) = match &name {
                    Some(n) => create_dest_dir(parent_fd.as_fd(), n, policy.overwrite)?,
                    None => (parent_fd.as_fd().try_clone_to_owned()?, false),
                };
                checkout_dir(
                    self,
                    opts,
                    policy,
                    DirNode {
                        dir_fd,
                        dirtree,
                        dirmeta: dm,
                        fresh,
                        base_path: "/".to_owned(),
                    },
                )
                .await?;
            }
            Target::File {
                name: entry_name,
                checksum,
            } => {
                let dir_name = name.ok_or_else(|| {
                    Error::Checkout("a file subpath needs a named destination directory".into())
                })?;
                let (dir_fd, _fresh) =
                    create_dest_dir(parent_fd.as_fd(), &dir_name, policy.overwrite)?;
                checkout_file(
                    self,
                    opts,
                    policy,
                    dir_fd.as_fd(),
                    &entry_name,
                    &checksum,
                    "/",
                )
                .await?;
                if policy.enable_fsync {
                    fsync_dir(dir_fd).await?;
                }
            }
        }
        Ok(())
    }
}

/// The resolved node a checkout materializes as its destination root.
enum Target {
    /// A directory subtree: its dirtree and dirmeta checksums.
    Dir {
        dirtree: Checksum,
        dirmeta: Checksum,
    },
    /// A single file or symlink: its name in the tree and content checksum.
    File { name: String, checksum: Checksum },
}

/// Resolve the checkout target within a commit tree, honoring an optional
/// subpath. An absent or root subpath selects the whole tree; a subpath is
/// resolved through the tree and a missing one is an error.
async fn resolve_target(repo: &Repo, commit: &Commit, subpath: Option<&Path>) -> Result<Target> {
    let root = Target::Dir {
        dirtree: commit.root_dirtree,
        dirmeta: commit.root_dirmeta,
    };
    let Some(sub) = subpath else {
        return Ok(root);
    };
    if is_root_path(sub) {
        return Ok(root);
    }
    let tree = RepoTree::from_parts(repo.clone(), commit.root_dirtree, commit.root_dirmeta);
    match tree.lookup(sub).await? {
        Some(TreeEntry::Dir { tree, .. }) => Ok(Target::Dir {
            dirtree: *tree.dirtree_checksum(),
            dirmeta: *tree.dirmeta_checksum(),
        }),
        Some(TreeEntry::File { name, checksum }) => Ok(Target::File { name, checksum }),
        None => Err(Error::Checkout(format!(
            "subpath not found: {}",
            sub.display()
        ))),
    }
}

/// Whether a path has no meaningful component, so it names the tree root.
fn is_root_path(p: &Path) -> bool {
    use std::path::Component;
    !p.components().any(|c| matches!(c, Component::Normal(_)))
}

/// Open the parent directory of `dest_path` relative to `dest_dir` and return it
/// with the final component's name. A `.` or empty `dest_path` has no final
/// component, so `dest_dir` itself is returned with no name.
fn open_dest_parent(
    dest_dir: BorrowedFd<'_>,
    dest_path: &Path,
) -> Result<(OwnedFd, Option<String>)> {
    match dest_path.file_name() {
        Some(name) => {
            let name = name
                .to_str()
                .ok_or_else(|| Error::Checkout("destination name is not valid UTF-8".into()))?
                .to_owned();
            let parent_fd = match dest_path.parent() {
                Some(p) if !p.as_os_str().is_empty() => rustix::fs::openat(
                    dest_dir,
                    p,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?,
                _ => dest_dir.try_clone_to_owned()?,
            };
            Ok((parent_fd, Some(name)))
        }
        None => Ok((dest_dir.try_clone_to_owned()?, None)),
    }
}

/// The boxed future for the recursive directory walk; async recursion needs
/// indirection, so each level returns a boxed future.
type CheckoutFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// A destination directory to materialize into: its already-created fd, the
/// commit dirtree and dirmeta to write, whether it was freshly created (so its
/// metadata is applied) or reused (so its metadata is left untouched), and the
/// path for filter callbacks.
struct DirNode {
    dir_fd: OwnedFd,
    dirtree: Checksum,
    dirmeta: DirMeta,
    fresh: bool,
    base_path: String,
}

/// Materialize one directory: its files, then its subdirectories, then its own
/// metadata.
fn checkout_dir<'a>(
    repo: &'a Repo,
    opts: &'a mut CheckoutOptions,
    policy: Policy,
    node: DirNode,
) -> CheckoutFuture<'a> {
    Box::pin(async move {
        let DirNode {
            dir_fd,
            dirtree: dirtree_csum,
            dirmeta,
            fresh,
            base_path,
        } = node;
        let dirtree = repo.load_dirtree(&dirtree_csum).await?;

        // An opaque marker clears the destination directory before the committed
        // entries are written. Over a fresh (empty) destination this is a no-op.
        if policy.process_whiteouts && dirtree.files.iter().any(|(n, _)| n == OPAQUE_MARKER) {
            let d = dir_fd.as_fd().try_clone_to_owned()?;
            ostrya_rt::unblock(move || clear_dir(d.as_fd())).await?;
        }

        for (name, checksum) in &dirtree.files {
            if policy.process_whiteouts {
                if name == OPAQUE_MARKER {
                    continue;
                }
                if let Some(target) = name.strip_prefix(WHITEOUT_PREFIX) {
                    let d = dir_fd.as_fd().try_clone_to_owned()?;
                    let target = target.to_owned();
                    ostrya_rt::unblock(move || remove_dir_entry(d.as_fd(), &target)).await?;
                    continue;
                }
            }
            checkout_file(
                repo,
                &mut *opts,
                policy,
                dir_fd.as_fd(),
                name,
                checksum,
                &base_path,
            )
            .await?;
        }

        for (name, sub_dirtree, sub_dirmeta) in &dirtree.dirs {
            let dm = repo.load_dirmeta(sub_dirmeta).await?;
            let cb_path = join_path(&base_path, name);
            if let Some(filter) = &mut opts.filter {
                let fm = FileMeta {
                    uid: dm.uid,
                    gid: dm.gid,
                    mode: dm.mode,
                    xattrs: dm.xattrs.clone(),
                };
                if filter(Path::new(&cb_path), &fm) == FilterResult::Skip {
                    continue;
                }
            }
            let (child_fd, child_fresh) = create_dest_dir(dir_fd.as_fd(), name, policy.overwrite)?;
            checkout_dir(
                repo,
                &mut *opts,
                policy,
                DirNode {
                    dir_fd: child_fd,
                    dirtree: *sub_dirtree,
                    dirmeta: dm,
                    fresh: child_fresh,
                    base_path: cb_path,
                },
            )
            .await?;
        }

        // The directory's final metadata is applied after its children so a
        // restrictive mode does not block writing them. A reused directory keeps
        // its existing metadata.
        if fresh {
            let d = dir_fd.as_fd().try_clone_to_owned()?;
            let effective = policy.effective;
            ostrya_rt::unblock(move || apply_dir_metadata(d.as_fd(), effective, &dirmeta)).await?;
        }
        if policy.enable_fsync {
            fsync_dir(dir_fd).await?;
        }
        Ok(())
    })
}

/// Materialize one file or symlink entry, after the filter.
async fn checkout_file(
    repo: &Repo,
    opts: &mut CheckoutOptions,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    checksum: &Checksum,
    base_path: &str,
) -> Result<()> {
    let obj = repo.load_file(checksum).await?;
    if let Some(filter) = &mut opts.filter {
        let cb_path = join_path(base_path, name);
        let fm = FileMeta {
            uid: obj.uid,
            gid: obj.gid,
            mode: obj.mode,
            xattrs: obj.xattrs.clone(),
        };
        if filter(Path::new(&cb_path), &fm) == FilterResult::Skip {
            return Ok(());
        }
    }
    match &obj.kind {
        FileKind::Symlink { target } => {
            place_symlink(repo, policy, dir_fd, name, &obj, target).await
        }
        FileKind::Regular { .. } => place_regular(repo, opts, policy, dir_fd, name, &obj).await,
    }
}

/// Materialize a regular file: hardlink the loose object where the object inode
/// is already the target inode, else copy (reflink where possible).
async fn place_regular(
    repo: &Repo,
    opts: &mut CheckoutOptions,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    obj: &FileObject,
) -> Result<()> {
    let checksum = obj.checksum();
    let obj_devino = if policy.overwrite == OverwriteMode::UnionIdentical {
        Some(loose_object_devino(repo, policy.repo_mode, checksum)?)
    } else {
        None
    };
    let remove_existing = match pre_check(dir_fd, name, policy.overwrite, obj_devino)? {
        Disposition::Skip => return Ok(()),
        Disposition::Error => return Err(collision(name)),
        Disposition::Place => false,
        Disposition::Overwrite => true,
    };

    // A cross-filesystem link (EXDEV) yields None and falls back to the copy
    // path below.
    if hardlink_regular(policy)
        && let Some((dev, ino)) =
            try_link_object(repo, policy, dir_fd, name, checksum, remove_existing).await?
    {
        record_devino(opts, dev, ino, checksum);
        return Ok(());
    }

    let (temp, kind) = crate::write::open_temp(dir_fd)?;
    copy_object(repo, obj, &temp, policy).await?;
    let plan = FinishCopy {
        dir: dir_fd.try_clone_to_owned()?,
        name: name.to_owned(),
        temp,
        kind,
        effective: policy.effective,
        uid: obj.uid,
        gid: obj.gid,
        mode: obj.mode,
        xattrs: obj.xattrs.clone(),
        enable_fsync: policy.enable_fsync,
        remove_existing,
    };
    let (dev, ino) = ostrya_rt::unblock(move || finish_copy_blocking(plan)).await?;
    record_devino(opts, dev, ino, checksum);
    Ok(())
}

/// Materialize a symlink: hardlink the loose object only under `bare` +
/// [`None`](CheckoutMode::None), else recreate the link fresh.
async fn place_symlink(
    repo: &Repo,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    obj: &FileObject,
    target: &str,
) -> Result<()> {
    let checksum = obj.checksum();
    let obj_devino = if policy.overwrite == OverwriteMode::UnionIdentical {
        Some(loose_object_devino(repo, policy.repo_mode, checksum)?)
    } else {
        None
    };
    let remove_existing = match pre_check(dir_fd, name, policy.overwrite, obj_devino)? {
        Disposition::Skip => return Ok(()),
        Disposition::Error => return Err(collision(name)),
        Disposition::Place => false,
        Disposition::Overwrite => true,
    };

    if hardlink_symlink(policy)
        && try_link_object(repo, policy, dir_fd, name, checksum, remove_existing)
            .await?
            .is_some()
    {
        return Ok(());
    }

    let plan = RecreateSymlink {
        dir: dir_fd.try_clone_to_owned()?,
        name: name.to_owned(),
        target: target.to_owned(),
        effective: policy.effective,
        uid: obj.uid,
        gid: obj.gid,
        xattrs: obj.xattrs.clone(),
        remove_existing,
    };
    ostrya_rt::unblock(move || recreate_symlink_blocking(plan)).await
}

/// Record a written regular file's destination inode against its checksum, for
/// a later ingest under `DEVINO_CANONICAL`.
fn record_devino(opts: &mut CheckoutOptions, dev: u64, ino: u64, checksum: &Checksum) {
    if let Some(cache) = &mut opts.devino_cache {
        cache.insert(dev, ino, *checksum);
    }
}

/// The overwrite verdict for one destination entry.
enum Disposition {
    /// The entry is absent; write it.
    Place,
    /// The entry exists and must be removed before writing.
    Overwrite,
    /// The entry exists and is left in place.
    Skip,
    /// The entry exists and its presence is a conflict.
    Error,
}

/// Decide how to treat a destination entry given the overwrite mode. For
/// [`UnionIdentical`](OverwriteMode::UnionIdentical), `obj_devino` is the
/// `(dev, ino)` of the loose object the entry would receive; an existing entry
/// that already shares it is identical.
fn pre_check(
    dir_fd: BorrowedFd<'_>,
    name: &str,
    overwrite: OverwriteMode,
    obj_devino: Option<(u64, u64)>,
) -> Result<Disposition> {
    let st = match rustix::fs::statat(dir_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::NOENT) => return Ok(Disposition::Place),
        Err(e) => return Err(e.into()),
    };
    Ok(match overwrite {
        OverwriteMode::None => Disposition::Error,
        OverwriteMode::UnionFiles => {
            // The tool overwrites an existing non-directory in place (a rename
            // over the name) but cannot rename a file or symlink over a
            // directory: a directory where the commit carries a non-directory is
            // a conflict it errors on (`renameat(...): Is a directory`), not a
            // subtree to remove.
            if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
                Disposition::Error
            } else {
                Disposition::Overwrite
            }
        }
        OverwriteMode::AddFiles => Disposition::Skip,
        OverwriteMode::UnionIdentical => match obj_devino {
            Some((dev, ino)) if st.st_dev == dev && st.st_ino == ino => Disposition::Skip,
            _ => Disposition::Error,
        },
    })
}

/// The `(st_dev, st_ino)` of a loose content object, for identity comparison.
fn loose_object_devino(repo: &Repo, mode: RepoMode, checksum: &Checksum) -> Result<(u64, u64)> {
    let path = loose_path(checksum, ObjectType::File, mode);
    let st =
        rustix::fs::statat(repo.objects_fd(), &path, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
            if e == Errno::NOENT {
                Error::ObjectNotFound {
                    checksum: *checksum,
                    ty: ObjectType::File,
                }
            } else {
                e.into()
            }
        })?;
    Ok((st.st_dev, st.st_ino))
}

/// Create the destination directory `name` under `parent`, returning its fd and
/// whether it was freshly created. A fresh directory is opened writable so its
/// children can be materialized. An existing directory is an error under
/// [`OverwriteMode::None`] and reused otherwise.
fn create_dest_dir(
    parent: BorrowedFd<'_>,
    name: &str,
    overwrite: OverwriteMode,
) -> Result<(OwnedFd, bool)> {
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(TRANSIENT_DIR_MODE)) {
        Ok(()) => {
            let fd = open_dir(parent, name)?;
            // Override the umask so the directory is writable while populated.
            rustix::fs::fchmod(&fd, Mode::from_raw_mode(TRANSIENT_DIR_MODE))?;
            Ok((fd, true))
        }
        Err(Errno::EXIST) => {
            // The name is taken. The tool reuses a like-typed directory,
            // merging its subtree, but never changes an entry's type: a name
            // held by a non-directory when the commit carries a directory is a
            // conflict it errors on in every mode. Match that with a checkout
            // error rather than letting the directory open below surface a raw
            // ENOTDIR (or ELOOP for a symlink).
            let st = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
                return Err(Error::Checkout(format!(
                    "{name}: destination entry exists and is not a directory"
                )));
            }
            match overwrite {
                OverwriteMode::None => Err(Error::Checkout(format!(
                    "{name}: destination directory already exists"
                ))),
                _ => Ok((open_dir(parent, name)?, false)),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// Open an existing directory `name` under `parent`, no-follow.
fn open_dir(parent: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    Ok(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Attempt to hardlink a loose object into place. Returns the destination
/// `(dev, ino)` on success, or `None` when the link crossed a filesystem
/// (`EXDEV`) and the caller must fall back to a copy.
async fn try_link_object(
    repo: &Repo,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    checksum: &Checksum,
    remove_existing: bool,
) -> Result<Option<(u64, u64)>> {
    let objects = repo.objects_fd().try_clone_to_owned()?;
    let dir = dir_fd.try_clone_to_owned()?;
    let loose = loose_path(checksum, ObjectType::File, policy.repo_mode);
    let name = name.to_owned();
    ostrya_rt::unblock(move || {
        if remove_existing {
            remove_dir_entry(dir.as_fd(), &name)?;
        }
        match rustix::fs::linkat(
            objects.as_fd(),
            &loose,
            dir.as_fd(),
            &name,
            AtFlags::empty(),
        ) {
            Ok(()) => {
                let st = rustix::fs::statat(dir.as_fd(), &name, AtFlags::SYMLINK_NOFOLLOW)?;
                Ok(Some((st.st_dev, st.st_ino)))
            }
            Err(Errno::XDEV) => Ok(None),
            Err(Errno::EXIST) => Err(collision(&name)),
            Err(e) => Err(e.into()),
        }
    })
    .await
}

/// Fill the destination temp file with the object's payload: a `FICLONE` reflink
/// of the loose object where it holds the raw payload (the bare family), else a
/// streamed byte copy through [`FileObject::reader`] (which inflates archive
/// objects on the fly). No whole payload is buffered.
async fn copy_object(repo: &Repo, obj: &FileObject, temp: &OwnedFd, policy: Policy) -> Result<()> {
    if policy.repo_mode != RepoMode::Archive {
        let objects = repo.objects_fd().try_clone_to_owned()?;
        let loose = loose_path(obj.checksum(), ObjectType::File, policy.repo_mode);
        let dst = temp.as_fd().try_clone_to_owned()?;
        let cloned =
            ostrya_rt::unblock(move || reflink_object(objects.as_fd(), &loose, dst.as_fd())).await;
        if cloned {
            return Ok(());
        }
    }
    let reader = obj.reader().await?;
    let mut writer = RtFile::from(temp.as_fd().try_clone_to_owned()?);
    crate::write::copy_stream(reader, &mut writer)
        .await
        .map_err(Error::Io)?;
    crate::write::flush(&mut writer).await.map_err(Error::Io)?;
    Ok(())
}

/// Try to clone a loose object's extents into `dst` with `FICLONE`. Any failure
/// (a filesystem without reflink, a cross-filesystem destination, a missing
/// object) returns `false`, and the caller streams the payload instead. On
/// failure `FICLONE` writes nothing, so `dst` stays empty for the fallback.
fn reflink_object(objects: BorrowedFd<'_>, loose: &str, dst: BorrowedFd<'_>) -> bool {
    match rustix::fs::openat(
        objects,
        loose,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(src) => rustix::fs::ioctl_ficlone(dst, &src).is_ok(),
        Err(_) => false,
    }
}

/// The materials for finishing a copied regular file, moved into the blocking
/// pool.
struct FinishCopy {
    dir: OwnedFd,
    name: String,
    temp: OwnedFd,
    kind: TempKind,
    effective: CheckoutMode,
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: Xattrs,
    enable_fsync: bool,
    remove_existing: bool,
}

/// Apply metadata to a copied regular file's temp inode, optionally fsync it,
/// then materialize it under its destination name, returning the destination
/// `(dev, ino)`.
fn finish_copy_blocking(plan: FinishCopy) -> Result<(u64, u64)> {
    apply_regular_metadata(
        plan.temp.as_fd(),
        plan.effective,
        plan.uid,
        plan.gid,
        plan.mode,
        &plan.xattrs,
    )?;
    if plan.enable_fsync {
        rustix::fs::fsync(plan.temp.as_fd())?;
    }
    if plan.remove_existing {
        remove_dir_entry(plan.dir.as_fd(), &plan.name)?;
    }
    match &plan.kind {
        TempKind::Anonymous => {
            let proc = format!("/proc/self/fd/{}", plan.temp.as_raw_fd());
            match rustix::fs::linkat(
                CWD,
                proc.as_str(),
                plan.dir.as_fd(),
                &plan.name,
                AtFlags::SYMLINK_FOLLOW,
            ) {
                Ok(()) => {}
                Err(Errno::EXIST) => return Err(collision(&plan.name)),
                Err(e) => return Err(e.into()),
            }
        }
        TempKind::Named(tmp) => {
            // When the copy does not remove an existing entry first, a colliding
            // destination name is a collision: the anonymous (linkat) path
            // rejects it with EEXIST. A plain renameat would instead replace the
            // name in place, silently overwriting an entry that raced in after
            // pre_check, so rename with RENAME_NOREPLACE to surface the same
            // collision the anonymous path does.
            let result = if !plan.remove_existing {
                match rustix::fs::renameat_with(
                    plan.dir.as_fd(),
                    tmp.as_str(),
                    plan.dir.as_fd(),
                    &plan.name,
                    RenameFlags::NOREPLACE,
                ) {
                    // A kernel or filesystem without RENAME_NOREPLACE support
                    // falls back to a plain rename, which cannot enforce the
                    // guard against a concurrent writer.
                    Err(Errno::INVAL | Errno::NOSYS) => rustix::fs::renameat(
                        plan.dir.as_fd(),
                        tmp.as_str(),
                        plan.dir.as_fd(),
                        &plan.name,
                    ),
                    other => other,
                }
            } else {
                rustix::fs::renameat(plan.dir.as_fd(), tmp.as_str(), plan.dir.as_fd(), &plan.name)
            };
            if let Err(e) = result {
                let _ = rustix::fs::unlinkat(plan.dir.as_fd(), tmp.as_str(), AtFlags::empty());
                return Err(if e == Errno::EXIST {
                    collision(&plan.name)
                } else {
                    e.into()
                });
            }
        }
    }
    let st = rustix::fs::statat(plan.dir.as_fd(), &plan.name, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok((st.st_dev, st.st_ino))
}

/// Apply a regular file's checkout-mode metadata to its inode fd.
fn apply_regular_metadata(
    fd: BorrowedFd<'_>,
    effective: CheckoutMode,
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: &Xattrs,
) -> Result<()> {
    match effective {
        CheckoutMode::None => {
            rustix::fs::fchown(fd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
            rustix::fs::fchmod(fd, Mode::from_raw_mode(mode & PERM_MASK))?;
            for (name, value) in xattrs.iter() {
                crate::write::set_inode_xattr(fd, name, value)?;
            }
        }
        CheckoutMode::User => {
            rustix::fs::fchmod(fd, Mode::from_raw_mode(mode & USER_PERM_MASK))?;
        }
    }
    Ok(())
}

/// Apply a directory's checkout-mode metadata to its fd. The full logical mode
/// (`mode & 0o7777`, special bits kept) is applied under both checkout modes;
/// only the chown and xattrs differ.
fn apply_dir_metadata(fd: BorrowedFd<'_>, effective: CheckoutMode, dm: &DirMeta) -> Result<()> {
    if effective == CheckoutMode::None {
        rustix::fs::fchown(fd, Some(Uid::from_raw(dm.uid)), Some(Gid::from_raw(dm.gid)))?;
    }
    rustix::fs::fchmod(fd, Mode::from_raw_mode(dm.mode & PERM_MASK))?;
    if effective == CheckoutMode::None {
        for (name, value) in dm.xattrs.iter() {
            crate::write::set_inode_xattr(fd, name, value)?;
        }
    }
    Ok(())
}

/// The materials for recreating a symlink, moved into the blocking pool.
struct RecreateSymlink {
    dir: OwnedFd,
    name: String,
    target: String,
    effective: CheckoutMode,
    uid: u32,
    gid: u32,
    xattrs: Xattrs,
    remove_existing: bool,
}

/// Recreate a symlink fresh and apply its checkout-mode metadata.
fn recreate_symlink_blocking(plan: RecreateSymlink) -> Result<()> {
    if plan.remove_existing {
        remove_dir_entry(plan.dir.as_fd(), &plan.name)?;
    }
    match rustix::fs::symlinkat(plan.target.as_str(), plan.dir.as_fd(), &plan.name) {
        Ok(()) => {}
        Err(Errno::EXIST) => return Err(collision(&plan.name)),
        Err(e) => return Err(e.into()),
    }
    if plan.effective == CheckoutMode::None {
        rustix::fs::chownat(
            plan.dir.as_fd(),
            plan.name.as_str(),
            Some(Uid::from_raw(plan.uid)),
            Some(Gid::from_raw(plan.gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        for (name, value) in plan.xattrs.iter() {
            crate::write::set_link_xattr(plan.dir.as_fd(), &plan.name, name, value)?;
        }
    }
    Ok(())
}

/// Remove a destination entry, recursing into a directory. A missing entry is
/// not an error.
fn remove_dir_entry(dir: BorrowedFd<'_>, name: &str) -> Result<()> {
    let st = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::NOENT) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
        let child = open_dir(dir, name)?;
        clear_dir(child.as_fd())?;
        drop(child);
        rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR)?;
    } else {
        rustix::fs::unlinkat(dir, name, AtFlags::empty())?;
    }
    Ok(())
}

/// Remove every entry of a directory, recursing into subdirectories. Names are
/// collected before removal so the iteration is not disturbed by the unlinks.
fn clear_dir(dir: BorrowedFd<'_>) -> Result<()> {
    let mut names = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let name = name
            .to_str()
            .map_err(|_| Error::InvalidFormat("directory entry name is not valid UTF-8".into()))?
            .to_owned();
        names.push(name);
    }
    for name in &names {
        remove_dir_entry(dir, name)?;
    }
    Ok(())
}

/// Fsync a directory on the blocking pool.
async fn fsync_dir(dir: OwnedFd) -> Result<()> {
    ostrya_rt::unblock(move || rustix::fs::fsync(dir.as_fd()).map_err(Error::from)).await
}

/// The error for a destination collision.
fn collision(name: &str) -> Error {
    Error::Checkout(format!("{name}: destination entry already exists"))
}

/// The checkout decisions derived from the options and repository mode.
#[derive(Debug, Clone, Copy)]
struct Policy {
    /// The repository storage mode.
    repo_mode: RepoMode,
    /// The checkout mode the caller requested.
    requested: CheckoutMode,
    /// The checkout mode actually applied: `bare-user-only` forces
    /// [`User`](CheckoutMode::User) regardless of the request, since its objects
    /// carry no ownership or xattrs and the canonical mode is already on the
    /// inode.
    effective: CheckoutMode,
    force_copy: bool,
    overwrite: OverwriteMode,
    enable_fsync: bool,
    process_whiteouts: bool,
}

impl Policy {
    fn new(repo_mode: RepoMode, opts: &CheckoutOptions) -> Policy {
        let effective = if repo_mode == RepoMode::BareUserOnly {
            CheckoutMode::User
        } else {
            opts.mode
        };
        Policy {
            repo_mode,
            requested: opts.mode,
            effective,
            force_copy: opts.force_copy,
            overwrite: opts.overwrite,
            enable_fsync: opts.enable_fsync,
            process_whiteouts: opts.process_whiteouts,
        }
    }
}

/// Whether a regular file's loose object may be hardlinked into place: only when
/// its stored inode already matches what the checkout would write, and never
/// under `force_copy`.
fn hardlink_regular(policy: Policy) -> bool {
    if policy.force_copy {
        return false;
    }
    matches!(
        (policy.repo_mode, policy.requested),
        (RepoMode::Bare, CheckoutMode::None)
            | (RepoMode::BareUser, CheckoutMode::User)
            | (RepoMode::BareUserOnly, _)
    )
}

/// Whether a symlink's loose object may be hardlinked into place: only under
/// `bare` + [`None`](CheckoutMode::None), where the object is a real symlink
/// carrying the logical ownership and xattrs.
fn hardlink_symlink(policy: Policy) -> bool {
    !policy.force_copy
        && policy.repo_mode == RepoMode::Bare
        && policy.requested == CheckoutMode::None
}

/// `CheckoutOptions` moves freely across tasks and threads, so the recursive
/// checkout future stays `Send`.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<CheckoutOptions>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(repo_mode: RepoMode, mode: CheckoutMode, force_copy: bool) -> Policy {
        Policy::new(
            repo_mode,
            &CheckoutOptions {
                mode,
                force_copy,
                ..CheckoutOptions::default()
            },
        )
    }

    /// The hardlink-eligibility matrix from `format-reference.md`, "Checkout":
    /// a regular file is hardlinked exactly when the object inode is already the
    /// target inode.
    #[test]
    fn hardlink_regular_matrix() {
        use CheckoutMode::{None, User};
        use RepoMode::{Archive, Bare, BareUser, BareUserOnly, BareUserShared};

        assert!(hardlink_regular(policy(Bare, None, false)));
        assert!(!hardlink_regular(policy(Bare, User, false)));
        assert!(!hardlink_regular(policy(BareUser, None, false)));
        assert!(hardlink_regular(policy(BareUser, User, false)));
        assert!(hardlink_regular(policy(BareUserOnly, None, false)));
        assert!(hardlink_regular(policy(BareUserOnly, User, false)));
        assert!(!hardlink_regular(policy(BareUserShared, None, false)));
        assert!(!hardlink_regular(policy(BareUserShared, User, false)));
        assert!(!hardlink_regular(policy(Archive, None, false)));
        assert!(!hardlink_regular(policy(Archive, User, false)));

        // force_copy suppresses every hardlink.
        assert!(!hardlink_regular(policy(Bare, None, true)));
        assert!(!hardlink_regular(policy(BareUserOnly, None, true)));
    }

    /// Symlinks are hardlinked only under `bare` + `None`; everywhere else they
    /// are recreated.
    #[test]
    fn hardlink_symlink_matrix() {
        use CheckoutMode::{None, User};
        use RepoMode::{Archive, Bare, BareUser, BareUserOnly};

        assert!(hardlink_symlink(policy(Bare, None, false)));
        assert!(!hardlink_symlink(policy(Bare, User, false)));
        assert!(!hardlink_symlink(policy(Bare, None, true)));
        assert!(!hardlink_symlink(policy(BareUser, None, false)));
        assert!(!hardlink_symlink(policy(BareUserOnly, None, false)));
        assert!(!hardlink_symlink(policy(Archive, None, false)));
    }

    /// `bare-user-only` forces `User` semantics regardless of the requested
    /// mode, so a `None` request never attempts a doomed chown to 0:0.
    #[test]
    fn bare_user_only_forces_user_semantics() {
        assert_eq!(
            policy(RepoMode::BareUserOnly, CheckoutMode::None, false).effective,
            CheckoutMode::User
        );
        assert_eq!(
            policy(RepoMode::Bare, CheckoutMode::None, false).effective,
            CheckoutMode::None
        );
    }

    /// A scratch directory removed on drop, for the named-temp copy-path tests.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("ostrya-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A named-temp `FinishCopy` that removes nothing first (`remove_existing ==
    /// false`), staging `b"NEW"` as `.ostrya-test-tmp` and targeting `dest` in
    /// `scratch`.
    fn named_none_plan(scratch: &Scratch) -> FinishCopy {
        use std::io::Write as _;

        let dir_fd: OwnedFd = std::fs::File::open(scratch.path()).unwrap().into();
        let tmp_name = ".ostrya-test-tmp".to_owned();
        let mut tmp = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(scratch.path().join(&tmp_name))
            .unwrap();
        tmp.write_all(b"NEW").unwrap();
        FinishCopy {
            dir: dir_fd,
            name: "dest".to_owned(),
            temp: tmp.into(),
            kind: TempKind::Named(tmp_name),
            effective: CheckoutMode::User,
            uid: 0,
            gid: 0,
            mode: 0o644,
            xattrs: Xattrs::empty(),
            enable_fsync: false,
            remove_existing: false,
        }
    }

    /// The named-temp fallback honors `OverwriteMode::None`: a destination name
    /// that appears before the rename is a collision, and the existing entry is
    /// left untouched rather than replaced in place. (Requires a filesystem with
    /// `RENAME_NOREPLACE`, which every filesystem since Linux 3.15 provides.)
    #[test]
    fn named_temp_none_rejects_a_racing_collision() {
        let scratch = Scratch::new("co-named-collide");
        std::fs::write(scratch.path().join("dest"), b"OLD").unwrap();

        let err = finish_copy_blocking(named_none_plan(&scratch));
        assert!(
            matches!(err, Err(Error::Checkout(_))),
            "a colliding destination is a checkout error, got {err:?}"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("dest")).unwrap(),
            b"OLD",
            "the existing entry is not overwritten"
        );
    }

    /// The same named-temp `OverwriteMode::None` path materializes normally when
    /// no destination entry exists.
    #[test]
    fn named_temp_none_places_when_absent() {
        let scratch = Scratch::new("co-named-fresh");

        finish_copy_blocking(named_none_plan(&scratch)).unwrap();
        assert_eq!(std::fs::read(scratch.path().join("dest")).unwrap(), b"NEW");
    }
}
