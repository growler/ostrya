//! The checkout path: materializing a committed tree onto a filesystem.
//!
//! [`Repo::checkout_at`] writes the tree of a commit into a destination
//! directory, reproducing the metadata the repository mode records. A
//! [`CheckoutOptions`] shapes it: the checkout mode ([`None`](CheckoutMode::None)
//! or [`User`](CheckoutMode::User)), the overwrite policy over an existing
//! destination, an optional subpath, whether to fsync, whether to force a copy
//! over a hardlink, whether to process Docker-style whiteouts, whether to
//! process overlayfs passthrough whiteouts, an optional [`DevInoCache`] to
//! populate, and an optional filter.
//!
//! For each regular file the checkout hardlinks the loose object into place when
//! the object's stored inode carries the metadata the destination needs, and
//! copies otherwise. A hardlink adopts the object inode's mode as it stands, so
//! a `bare-user` object under [`User`](CheckoutMode::User) arrives without the
//! sticky bit a copy would keep; that is the tool's own outcome for the same
//! commit. The copy path streams the
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

use futures_lite::AsyncReadExt;
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
use crate::tree::{Comp, RepoTree, TreeEntry};
use crate::write::{FileMeta, TempKind};

/// The permission-and-special-bit mask of an `st_mode` (`perm & 0o7777`).
const PERM_MASK: u32 = 0o7777;
/// The permission mask a [`User`](CheckoutMode::User) checkout applies to a
/// regular file it writes (`perm & 0o1777`): the setuid and setgid bits are
/// dropped, the sticky bit and the rwx bits including group- and other-write
/// are kept. Recovered by checking a tree of assorted special-bit modes out
/// with `ostree checkout -U --force-copy` in each mode
/// (`format-reference.md`, "Checkout").
const USER_PERM_MASK: u32 = 0o1777;
/// The chunk size the identity comparison streams a destination file in, so no
/// whole file is buffered.
const HASH_CHUNK: usize = 64 * 1024;
/// The transient mode a directory is created with so its children can be
/// written; the final logical mode is applied after they are materialized.
const TRANSIENT_DIR_MODE: u32 = 0o700;
/// The overlayfs opaque-directory marker, an entry that clears the destination
/// directory's pre-existing content before the committed entries are written.
const OPAQUE_MARKER: &str = ".wh..wh..opq";
/// The Docker-style whiteout name prefix; `.wh.<name>` removes `<name>` from the
/// destination directory.
const WHITEOUT_PREFIX: &str = ".wh.";
/// The overlayfs passthrough whiteout name prefix; `.ostree-wh.<name>` becomes a
/// character device 0:0 at `<name>`.
const PASSTHROUGH_PREFIX: &str = ".ostree-wh.";

/// How checkout applies ownership, permissions, and xattrs to materialized
/// files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CheckoutMode {
    /// The faithful checkout (`ostree checkout`): chown to the logical uid/gid,
    /// chmod to the full logical permission bits, and apply the logical xattrs.
    #[default]
    None,
    /// The unprivileged checkout (`ostree checkout -U`): no chown, no xattrs; a
    /// regular file the checkout writes drops the setuid and setgid bits and
    /// keeps the sticky bit, and a directory's mode keeps all three. A regular
    /// file the checkout hardlinks instead carries the object inode's own mode,
    /// which in `bare-user` holds no special bit at all.
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
    /// Add new entries; an existing entry that is what this checkout would put
    /// there is left in place, and a differing existing entry is an error
    /// (`ostree checkout --union-identical`). A regular file is what the
    /// checkout would put there when it is already the loose object's inode, or
    /// when its file-object checksum equals the object's and its permission bits
    /// equal the loose object inode's. A symlink is compared by its target. A
    /// directory is reused with no comparison, as under the other union modes.
    /// See `format-reference.md`, "Checkout".
    UnionIdentical,
}

/// A synchronous filter over checked-out paths.
///
/// The path is rooted at the checkout root, carries a leading slash, and
/// carries no trailing slash; the root itself is `/`. The [`FileMeta`] carries
/// the entry's own recorded metadata: a directory's dirmeta, and a file's or a
/// symlink's file object, so `mode` names the entry's type. That metadata
/// object is loaded before the filter is called, so a pruned entry still costs
/// the load of its own metadata.
///
/// The filter decides the checkout root, every directory entry, and every file
/// and symlink entry of a walked tree. A [`Skip`](FilterResult::Skip) on the
/// root writes nothing and creates no destination, and a
/// [`Skip`](FilterResult::Skip) on a directory prunes its whole subtree.
///
/// Two sites stand outside it: the single object a file or symlink
/// [`subpath`](CheckoutOptions::subpath) names, which is written without a
/// filter call; and the opaque whiteout marker's clear, which is the directory
/// walk's own pre-pass over the destination's names. A file entry is decided
/// ahead of the whiteout verdict, so a [`Skip`](FilterResult::Skip) on a marker
/// entry's own path performs no removal and writes no device.
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
    /// instead of the whole tree. A path with no name component names the
    /// whole tree. A path that carries a name component and a `..` component
    /// names nothing, since no directory holds a `..` entry. Such a path is
    /// refused with [`Error::SubpathNotFound`]. Where a component before the
    /// first `..` names a file or a symlink, the refusal is
    /// [`Error::SubpathNotADirectory`].
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
    /// Process overlayfs passthrough whiteouts: a regular-file entry named
    /// `.ostree-wh.<name>` becomes a character device 0:0 at `<name>` instead of
    /// an ordinary file under its own name.
    pub process_passthrough_whiteouts: bool,
    /// A devino cache to populate: each regular file's destination
    /// `(st_dev, st_ino)` is recorded against its checksum as it is written or
    /// linked.
    pub devino_cache: Option<DevInoCache>,
    /// A filter called per path to include or prune entries. The paths it sees
    /// and the sites it does not reach are stated on [`CheckoutFilterFn`].
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
            process_passthrough_whiteouts: false,
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
        // The tool takes `--union-identical` only together with
        // `--require-hardlinks`, so the checkout that runs under it is a
        // hardlinking one. Reject the mode before any I/O where the repository
        // mode and checkout mode (or force_copy) produce copies, which is the
        // same set the tool's `-H` gate refuses.
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

        match target {
            Target::Dir { dirtree, dirmeta } => {
                let dm = self.load_dirmeta(&dirmeta).await?;
                // The root is decided before the destination path is touched,
                // so a pruned root writes nothing, creates no destination, and
                // reads nothing of the destination's own parent.
                if let Some(filter) = &mut opts.filter {
                    let fm = FileMeta {
                        uid: dm.uid,
                        gid: dm.gid,
                        mode: dm.mode,
                        xattrs: dm.xattrs.clone(),
                    };
                    if filter(Path::new("/"), &fm) == FilterResult::Skip {
                        return Ok(());
                    }
                }
                let (parent_fd, name) = open_dest_parent(dest_dir, dest_path)?;
                let (dir_fd, fresh) = match &name {
                    Some(n) => create_dest_dir(
                        parent_fd.as_fd(),
                        n,
                        policy.overwrite,
                        widens_type_conflict(policy),
                    )?,
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
                let (parent_fd, name) = open_dest_parent(dest_dir, dest_path)?;
                let dir_name = name.ok_or_else(|| {
                    Error::Checkout("a file subpath needs a named destination directory".into())
                })?;
                // The destination directory a file target needs is outside the
                // reach of the whiteout switch's widening.
                let (dir_fd, _fresh) =
                    create_dest_dir(parent_fd.as_fd(), &dir_name, policy.overwrite, false)?;
                let obj = self.load_file(&checksum).await?;
                checkout_entry(self, opts, policy, dir_fd.as_fd(), &entry_name, &obj).await?;
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
/// resolved through the tree and one that does not resolve is an error. The two
/// refusals are told apart: a value naming no entry is
/// [`Error::SubpathNotFound`] and one running through an entry that is not a
/// directory is [`Error::SubpathNotADirectory`], the split the tool also makes
/// and the split `ostrya checkout --allow-noent` acts on.
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
        None => Err(unresolved_subpath(&tree, sub).await),
    }
}

/// Which refusal a subpath that resolved to nothing carries. The walk descends
/// the value's leading components one at a time: a component naming an entry
/// that is not a directory makes the value run through a non-directory, and
/// every other outcome makes the value name nothing. The components are read
/// through the same split [`RepoTree::lookup`](crate::RepoTree::lookup) reads,
/// so the walk stops where the lookup stopped.
async fn unresolved_subpath(tree: &RepoTree, sub: &Path) -> Error {
    let not_found = || Error::SubpathNotFound(sub.to_path_buf());
    let components = crate::tree::normalize(sub);
    let Some(leading) = components.len().checked_sub(1) else {
        return not_found();
    };
    let mut current = tree.clone();
    for component in &components[..leading] {
        let Comp::Normal(component) = component else {
            // A `..` component. No directory holds an entry of this name, so
            // the value names nothing, whatever follows it.
            return not_found();
        };
        match current.lookup(Path::new(component)).await {
            Ok(Some(TreeEntry::Dir { tree, .. })) => current = tree,
            Ok(Some(TreeEntry::File { .. })) => {
                return Error::SubpathNotADirectory(sub.to_path_buf());
            }
            Ok(None) => return not_found(),
            // A failed lookup keeps its own error. Reporting it as an absent
            // subpath would let `ostrya checkout --allow-noent` turn a read or
            // decode failure into exit 0.
            Err(e) => return e,
        }
    }
    not_found()
}

/// Whether a path has no meaningful component, so it names the tree root.
pub(crate) fn is_root_path(p: &Path) -> bool {
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
        // entries are written. A fresh directory was just created and holds
        // nothing, so the clear has nothing to do there.
        if !fresh
            && policy.process_whiteouts
            && dirtree.files.iter().any(|(n, _)| n == OPAQUE_MARKER)
        {
            let d = dir_fd.as_fd().try_clone_to_owned()?;
            ostrya_rt::unblock(move || clear_dir(d.as_fd())).await?;
        }

        for (name, checksum) in &dirtree.files {
            let obj = repo.load_file(checksum).await?;
            // The filter decides the entry ahead of the whiteout verdict, so a
            // pruned marker removes nothing and writes no device.
            if let Some(filter) = &mut opts.filter {
                let cb_path = join_path(&base_path, name);
                let fm = FileMeta {
                    uid: obj.uid,
                    gid: obj.gid,
                    mode: obj.mode,
                    xattrs: obj.xattrs.clone(),
                };
                if filter(Path::new(&cb_path), &fm) == FilterResult::Skip {
                    continue;
                }
            }
            checkout_entry(repo, &mut *opts, policy, dir_fd.as_fd(), name, &obj).await?;
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
            let (child_fd, child_fresh) = create_dest_dir(
                dir_fd.as_fd(),
                name,
                policy.overwrite,
                widens_type_conflict(policy),
            )?;
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

/// Act on one file entry of a tree: the whiteout verdict where a switch claims
/// the name, and the plain materialization otherwise.
///
/// A `--subpath` naming a marker file reaches the same decision, so a marker is
/// never materialized under its own name because a subpath selected it. The
/// opaque marker's clear is the directory walk's own pre-pass, so a subpath
/// naming `.wh..wh..opq` drops the entry and clears nothing, which is the tool's
/// own outcome (`format-reference.md`, "Checkout").
async fn checkout_entry(
    repo: &Repo,
    opts: &mut CheckoutOptions,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    obj: &FileObject,
) -> Result<()> {
    match whiteout_verdict(policy, name, obj)? {
        Some(Whiteout::Drop) => Ok(()),
        Some(Whiteout::Remove(target)) => {
            let d = dir_fd.try_clone_to_owned()?;
            ostrya_rt::unblock(move || remove_dir_entry(d.as_fd(), &target)).await
        }
        Some(Whiteout::Device(target)) => place_whiteout_device(policy, dir_fd, &target, obj).await,
        None => checkout_file(repo, opts, policy, dir_fd, name, obj).await,
    }
}

/// Materialize one file or symlink entry.
async fn checkout_file(
    repo: &Repo,
    opts: &mut CheckoutOptions,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    obj: &FileObject,
) -> Result<()> {
    match &obj.kind {
        FileKind::Symlink { target } => {
            place_symlink(repo, policy, dir_fd, name, obj, target).await
        }
        FileKind::Regular { .. } => place_regular(repo, opts, policy, dir_fd, name, obj).await,
    }
}

/// What the whiteout options make of one file entry.
///
/// Both marker sets act on a regular-file entry alone: an entry of any other
/// type carrying a marker name is materialized verbatim, which is the tool's
/// own outcome (`format-reference.md`, "Checkout"). The opaque marker's clear
/// is decided separately, by name over the whole file-entry list, so a symlink
/// so named clears the directory and is then materialized.
enum Whiteout {
    /// The opaque marker, whose clear has already run: suppress it.
    Drop,
    /// A per-name marker: remove this name from the destination directory and
    /// materialize nothing.
    Remove(String),
    /// A passthrough marker: write a character device 0:0 under this name.
    Device(String),
}

/// The whiteout verdict for one file entry, or `None` where the entry is
/// materialized as it stands. A marker naming nothing is refused.
fn whiteout_verdict(policy: Policy, name: &str, obj: &FileObject) -> Result<Option<Whiteout>> {
    if !matches!(obj.kind, FileKind::Regular { .. }) {
        return Ok(None);
    }
    if policy.process_whiteouts {
        if name == OPAQUE_MARKER {
            return Ok(Some(Whiteout::Drop));
        }
        if let Some(target) = name.strip_prefix(WHITEOUT_PREFIX) {
            if target.is_empty() {
                return Err(Error::Checkout(format!(
                    "{WHITEOUT_PREFIX}: the whiteout names no entry"
                )));
            }
            return Ok(Some(Whiteout::Remove(target.to_owned())));
        }
    }
    if policy.process_passthrough_whiteouts
        && let Some(target) = name.strip_prefix(PASSTHROUGH_PREFIX)
    {
        if target.is_empty() {
            return Err(Error::Checkout(format!(
                "{PASSTHROUGH_PREFIX}: the overlayfs whiteout names no entry"
            )));
        }
        return Ok(Some(Whiteout::Device(target.to_owned())));
    }
    Ok(None)
}

/// Materialize an overlayfs passthrough whiteout: a character device 0:0 under
/// the marker's target name.
///
/// The device takes the marker's permission bits, and under
/// [`None`](CheckoutMode::None) its ownership and its extended attributes as
/// well. The bits reach `mknodat`, so the process umask reduces them exactly as
/// it reduces the tool's; [`None`](CheckoutMode::None) then applies the recorded
/// mode in full, so the umask stands under [`User`](CheckoutMode::User) alone.
///
/// [`UnionIdentical`](OverwriteMode::UnionIdentical) keeps an existing entry of
/// any type here, with no comparison, which is the one place the identity rule
/// does not run. Recovered by checking a passthrough marker out over a
/// destination holding a regular file, a symlink, a directory, and a device
/// (`format-reference.md`, "Checkout").
async fn place_whiteout_device(
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    obj: &FileObject,
) -> Result<()> {
    // The whiteout device keeps its refusal over a destination directory under
    // either switch, so the widening does not reach it.
    let remove_existing = match pre_check(dir_fd, name, policy.overwrite, false)? {
        Disposition::Skip | Disposition::Check(_) => return Ok(()),
        Disposition::Error => return Err(collision(name)),
        Disposition::Place => false,
        Disposition::Overwrite => true,
    };

    let plan = PlaceWhiteoutDevice {
        dir: dir_fd.try_clone_to_owned()?,
        name: name.to_owned(),
        effective: policy.effective,
        uid: obj.uid,
        gid: obj.gid,
        mode: obj.mode & PERM_MASK,
        xattrs: obj.xattrs.clone(),
        remove_existing,
    };
    ostrya_rt::unblock(move || place_whiteout_device_blocking(plan)).await
}

/// The blocking half of [`place_whiteout_device`].
struct PlaceWhiteoutDevice {
    dir: OwnedFd,
    name: String,
    effective: CheckoutMode,
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: Xattrs,
    remove_existing: bool,
}

/// Create the whiteout device and apply its checkout-mode metadata.
fn place_whiteout_device_blocking(plan: PlaceWhiteoutDevice) -> Result<()> {
    if plan.remove_existing {
        remove_dir_entry(plan.dir.as_fd(), &plan.name)?;
    }
    match rustix::fs::mknodat(
        plan.dir.as_fd(),
        plan.name.as_str(),
        FileType::CharacterDevice,
        Mode::from_raw_mode(plan.mode),
        rustix::fs::makedev(0, 0),
    ) {
        Ok(()) => {}
        Err(Errno::EXIST) => return Err(collision(&plan.name)),
        Err(e) => return Err(e.into()),
    }
    if plan.effective == CheckoutMode::None {
        // The order is the one `apply_regular_metadata` takes, and the tool's:
        // the attributes, then the ownership, then the mode. `chown` on a device
        // node clears the setuid and setgid bits for an unprivileged caller even
        // where the ids do not change, so the recorded mode is applied after the
        // ownership. The attributes come first, so a marker whose attribute the
        // kernel refuses leaves the device at the mode `mknod` gave it, which is
        // the tool's own outcome (`format-reference.md`, "Checkout").
        for (name, value) in plan.xattrs.iter() {
            crate::write::set_link_xattr(plan.dir.as_fd(), &plan.name, name, value).map_err(
                |err| {
                    Error::Checkout(format!(
                        "{}: setting the extended attribute {}: {}",
                        plan.name,
                        xattr_name(name),
                        reason(err),
                    ))
                },
            )?;
        }
        rustix::fs::chownat(
            plan.dir.as_fd(),
            plan.name.as_str(),
            Some(Uid::from_raw(plan.uid)),
            Some(Gid::from_raw(plan.gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        rustix::fs::chmodat(
            plan.dir.as_fd(),
            plan.name.as_str(),
            Mode::from_raw_mode(plan.mode),
            AtFlags::empty(),
        )?;
    }
    Ok(())
}

/// An extended attribute's name for a message: the stored name without its
/// terminating NUL, and lossily where it is not UTF-8.
fn xattr_name(name: &[u8]) -> String {
    String::from_utf8_lossy(name.strip_suffix(&[0]).unwrap_or(name)).into_owned()
}

/// An error's own words for a message a caller wraps, with the numeric tail an
/// I/O error carries left off.
fn reason(err: Error) -> String {
    let text = match &err {
        Error::Io(io) => io.to_string(),
        other => other.to_string(),
    };
    match text.find(" (os error ") {
        Some(cut) => text[..cut].to_owned(),
        None => text,
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
    let remove_existing =
        match pre_check(dir_fd, name, policy.overwrite, widens_type_conflict(policy))? {
            Disposition::Skip => return Ok(()),
            Disposition::Error => return Err(collision(name)),
            Disposition::Place => false,
            Disposition::Overwrite => true,
            Disposition::Check(st) => {
                if destination_is_identical(repo, policy, dir_fd, name, &st, obj).await? {
                    return Ok(());
                }
                return Err(collision(name));
            }
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
    let remove_existing =
        match pre_check(dir_fd, name, policy.overwrite, widens_type_conflict(policy))? {
            Disposition::Skip => return Ok(()),
            Disposition::Error => return Err(collision(name)),
            Disposition::Place => false,
            Disposition::Overwrite => true,
            Disposition::Check(st) => {
                if destination_is_identical(repo, policy, dir_fd, name, &st, obj).await? {
                    return Ok(());
                }
                return Err(collision(name));
            }
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
    /// The entry exists and must be compared against the object it would
    /// receive, carrying the stat the comparison reads.
    Check(rustix::fs::Stat),
    /// The entry exists and its presence is a conflict.
    Error,
}

/// Decide how to treat a destination entry given the overwrite mode.
/// [`UnionIdentical`](OverwriteMode::UnionIdentical) defers to
/// [`destination_is_identical`], which the caller runs over the returned stat.
///
/// `widen_type_conflict` carries [`widens_type_conflict`] for the entry sites
/// the switch reaches. The whiteout device is not one of them, so it passes
/// `false` and keeps its refusal over a destination directory.
fn pre_check(
    dir_fd: BorrowedFd<'_>,
    name: &str,
    overwrite: OverwriteMode,
    widen_type_conflict: bool,
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
            // subtree to remove. `--whiteouts` widens the disposition, and the
            // directory and its whole subtree are then removed.
            if FileType::from_raw_mode(st.st_mode) == FileType::Directory && !widen_type_conflict {
                Disposition::Error
            } else {
                Disposition::Overwrite
            }
        }
        OverwriteMode::AddFiles => Disposition::Skip,
        OverwriteMode::UnionIdentical => Disposition::Check(st),
    })
}

/// The `(st_dev, st_ino)` and the permission bits of a loose content object's
/// own inode, for identity comparison.
fn loose_object_stat(repo: &Repo, mode: RepoMode, checksum: &Checksum) -> Result<(u64, u64, u32)> {
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
    Ok((st.st_dev, st.st_ino, st.st_mode & PERM_MASK))
}

/// Whether an existing destination entry is what this checkout would put there,
/// deciding [`OverwriteMode::UnionIdentical`].
///
/// The rule is the tool's, recovered by black-box observation and recorded in
/// `format-reference.md`, "Checkout". A regular file matches when it is already
/// the loose object's inode, or when the file-object checksum computed from it
/// equals the object's and its permission bits equal the loose object inode's.
/// The checksum reduces the destination's metadata the way the repository mode
/// reduces an ingested entry, so `bare-user-only` drops ownership and extended
/// attributes and masks the permission bits. A symlink matches on its target
/// alone. Neither the modification time nor the link count is read. An entry
/// whose type differs from the object's matches nothing.
///
/// The checksum covers the framed header followed by the payload, so a
/// destination of a different size, or one whose canonical header differs,
/// carries a different checksum whatever its bytes hold. Both are decided from
/// the stat and the extended attributes alone, so the payload is read only
/// where a match is still possible.
async fn destination_is_identical(
    repo: &Repo,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    st: &rustix::fs::Stat,
    obj: &FileObject,
) -> Result<bool> {
    match &obj.kind {
        FileKind::Symlink { target } => {
            if FileType::from_raw_mode(st.st_mode) != FileType::Symlink {
                return Ok(false);
            }
            let link = rustix::fs::readlinkat(dir_fd, name, Vec::new())?;
            Ok(link.as_bytes() == target.as_bytes())
        }
        FileKind::Regular { size } => {
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                return Ok(false);
            }
            let (dev, ino, obj_perm) = loose_object_stat(repo, policy.repo_mode, obj.checksum())?;
            if st.st_dev == dev && st.st_ino == ino {
                return Ok(true);
            }
            if u64::try_from(st.st_size).ok() != Some(*size) {
                return Ok(false);
            }
            if st.st_mode & PERM_MASK != obj_perm {
                return Ok(false);
            }
            let fd = rustix::fs::openat(
                dir_fd,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let meta = FileMeta {
                uid: st.st_uid,
                gid: st.st_gid,
                mode: st.st_mode,
                xattrs: crate::object::read_all_xattrs(fd.as_fd())?,
            };
            let header = crate::write::canonical_header(policy.repo_mode, meta.regular_header());
            if header != crate::write::canonical_header(policy.repo_mode, obj.header()) {
                return Ok(false);
            }
            let checksum = hash_destination_file(fd, &header, *size).await?;
            Ok(checksum == *obj.checksum())
        }
    }
}

/// The file-object checksum a destination regular file of `size` bytes, opened
/// as `fd` and carrying `header`, would ingest as. The payload streams in
/// bounded chunks, so no whole file is buffered.
async fn hash_destination_file(
    fd: OwnedFd,
    header: &ostrya_core::FileHeader,
    size: u64,
) -> Result<Checksum> {
    let mut hasher = ostrya_core::ContentHasher::new(header)?;
    let mut file = RtFile::from(fd);
    let mut buf = vec![
        0u8;
        usize::try_from(size)
            .unwrap_or(HASH_CHUNK)
            .clamp(1, HASH_CHUNK)
    ];
    loop {
        let n = file.read(&mut buf).await.map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finish())
}

/// Create the destination directory `name` under `parent`, returning its fd and
/// whether it was freshly created. A fresh directory is opened writable so its
/// children can be materialized. An existing directory is an error under
/// [`OverwriteMode::None`] and reused otherwise.
///
/// A union mode follows a symlink standing at any directory name, the
/// checkout's own destination included, and writes into the directory the link
/// resolves to. The link is followed wherever it points, so a checkout writes
/// outside the destination tree where the destination's own symlinks lead
/// there, which is the tool's outcome. A link resolving to nothing, to a
/// non-directory, or to itself carries the open's own error. See
/// `format-reference.md`, "Checkout".
///
/// `widen_type_conflict` carries [`widens_type_conflict`] for the directory
/// sites the switch reaches: the destination root of a directory target and
/// every directory of the walk below it. The entry standing there is removed
/// and a directory is created in its place, so a symlink loses the link alone
/// and the directory it resolved to stays as it stands. The destination
/// directory a file target needs is not one of the sites, so it passes `false`
/// and keeps the symlink-following rule above.
fn create_dest_dir(
    parent: BorrowedFd<'_>,
    name: &str,
    overwrite: OverwriteMode,
    widen_type_conflict: bool,
) -> Result<(OwnedFd, bool)> {
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(TRANSIENT_DIR_MODE)) {
        Ok(()) => Ok((open_fresh_dir(parent, name)?, true)),
        Err(Errno::EXIST) => {
            // The name is taken. The tool reuses a like-typed directory,
            // merging its subtree, but never changes an entry's type: a name
            // held by a non-directory when the commit carries a directory is a
            // conflict it errors on in every mode. Match that with a checkout
            // error rather than letting the directory open below surface a raw
            // ENOTDIR (or ELOOP for a symlink).
            let st = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(st.st_mode) != FileType::Directory && widen_type_conflict {
                unlink_entry(parent, name, false)?;
                rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(TRANSIENT_DIR_MODE))?;
                return Ok((open_fresh_dir(parent, name)?, true));
            }
            if overwrite != OverwriteMode::None && is_symlink(st.st_mode) {
                return Ok((open_dir_following(parent, name)?, false));
            }
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

/// Open a directory just created under `parent`, overriding the umask so it is
/// writable while its children are materialized.
fn open_fresh_dir(parent: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    let fd = open_dir(parent, name)?;
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(TRANSIENT_DIR_MODE))?;
    Ok(fd)
}

/// Whether an `st_mode` names a symlink.
fn is_symlink(mode: u32) -> bool {
    FileType::from_raw_mode(mode) == FileType::Symlink
}

/// Open the directory `name` under `parent` resolves to, following a symlink at
/// the final component.
fn open_dir_following(parent: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    Ok(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
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
            // The xattrs go on before the mode: the kernel checks a `user.*`
            // xattr against the inode's write permission, which a logical mode
            // without an owner-write bit (0444, 0555) does not grant.
            for (name, value) in xattrs.iter() {
                crate::write::set_inode_xattr(fd, name, value)?;
            }
            rustix::fs::fchown(fd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
            rustix::fs::fchmod(fd, Mode::from_raw_mode(mode & PERM_MASK))?;
        }
        CheckoutMode::User => {
            rustix::fs::fchmod(fd, Mode::from_raw_mode(mode & USER_PERM_MASK))?;
        }
    }
    Ok(())
}

/// Apply a directory's checkout-mode metadata to its fd. The full logical mode
/// (`mode & 0o7777`, special bits kept) is applied under both checkout modes;
/// only the chown and xattrs differ. The mode is applied last, since a `user.*`
/// xattr needs write permission on the inode.
fn apply_dir_metadata(fd: BorrowedFd<'_>, effective: CheckoutMode, dm: &DirMeta) -> Result<()> {
    if effective == CheckoutMode::None {
        for (name, value) in dm.xattrs.iter() {
            crate::write::set_inode_xattr(fd, name, value)?;
        }
        rustix::fs::fchown(fd, Some(Uid::from_raw(dm.uid)), Some(Gid::from_raw(dm.gid)))?;
    }
    rustix::fs::fchmod(fd, Mode::from_raw_mode(dm.mode & PERM_MASK))?;
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
    match entry_is_dir(dir, name)? {
        None => Ok(()),
        Some(false) => unlink_entry(dir, name, false),
        Some(true) => remove_subtree(dir, name),
    }
}

/// Whether `name` under `dir` is a directory, or `None` where the name is not
/// taken.
fn entry_is_dir(dir: BorrowedFd<'_>, name: &str) -> Result<Option<bool>> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(
            FileType::from_raw_mode(st.st_mode) == FileType::Directory,
        )),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Unlink `name` under `dir`. A name that is already gone is not an error.
fn unlink_entry(dir: BorrowedFd<'_>, name: &str, is_dir: bool) -> Result<()> {
    let flags = if is_dir {
        AtFlags::REMOVEDIR
    } else {
        AtFlags::empty()
    };
    match rustix::fs::unlinkat(dir, name, flags) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Remove `name` under `dir` and everything below it.
///
/// The removal is a loop over an explicit stack of levels, and one directory
/// descriptor stands open at a time: descending replaces the level's descriptor
/// with the child's, and ascending replaces it with the one `..` opens, which
/// names the parent while the emptied level is still linked where it was
/// opened. Depth costs a name and an entry list on the heap, so a destination
/// subtree deeper than the process descriptor limit or than the thread stack
/// holds is removed whole.
fn remove_subtree(dir: BorrowedFd<'_>, name: &str) -> Result<()> {
    let mut level = match open_dir(dir, name) {
        Ok(fd) => fd,
        // The subtree is gone, which the removal wanted anyway. The type comes
        // from `getdents64` or from a caller's own `statat`, so the name can be
        // unlinked between the two calls.
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    // One entry per level on the path from `name` down to the level in hand:
    // the level's own name, and what is left to remove within it.
    let mut levels = vec![(name.to_owned(), read_level(level.as_fd())?)];

    while let Some((_, entries)) = levels.last_mut() {
        match entries.pop() {
            Some((child, false)) => unlink_entry(level.as_fd(), &child, false)?,
            Some((child, true)) => {
                let child_fd = match open_dir(level.as_fd(), &child) {
                    Ok(fd) => fd,
                    // The child is gone, which the removal wanted anyway.
                    Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                let child_entries = read_level(child_fd.as_fd())?;
                level = child_fd;
                levels.push((child, child_entries));
            }
            None => {
                let (cleared, _) = levels.pop().expect("a level is in hand within the loop");
                if levels.is_empty() {
                    drop(level);
                    return unlink_entry(dir, &cleared, true);
                }
                level = open_dir(level.as_fd(), "..")?;
                unlink_entry(level.as_fd(), &cleared, true)?;
            }
        }
    }
    Ok(())
}

/// Remove every entry of a directory, recursing into subdirectories. The names
/// are collected before the removal so the iteration is not disturbed by the
/// unlinks.
fn clear_dir(dir: BorrowedFd<'_>) -> Result<()> {
    for (name, is_dir) in read_level(dir)? {
        if is_dir {
            remove_subtree(dir, &name)?;
        } else {
            unlink_entry(dir, &name, false)?;
        }
    }
    Ok(())
}

/// The entries of one directory, each with whether it is a directory.
///
/// `getdents64` already carries the type, so the type is read off the entry and
/// no call per name is made. A filesystem that reports [`FileType::Unknown`]
/// leaves the type to one `statat` for that name alone; a name that is gone by
/// the time that call runs is left out.
fn read_level(level: BorrowedFd<'_>) -> Result<Vec<(String, bool)>> {
    let mut entries = Vec::new();
    for entry in Dir::read_from(level)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let name = name
            .to_str()
            .map_err(|_| Error::InvalidFormat("directory entry name is not valid UTF-8".into()))?
            .to_owned();
        let is_dir = match entry.file_type() {
            FileType::Directory => true,
            FileType::Unknown => match entry_is_dir(level, &name)? {
                Some(is_dir) => is_dir,
                None => continue,
            },
            _ => false,
        };
        entries.push((name, is_dir));
    }
    Ok(entries)
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
    process_passthrough_whiteouts: bool,
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
            process_passthrough_whiteouts: opts.process_passthrough_whiteouts,
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

/// Whether the whiteout switch widens the union-files disposition over a type
/// conflict, so a destination entry whose type is not the type the tree carries
/// is removed rather than refused. `process_whiteouts` widens
/// [`UnionFiles`](OverwriteMode::UnionFiles) alone, and
/// `process_passthrough_whiteouts` widens nothing. See `format-reference.md`,
/// "Checkout".
fn widens_type_conflict(policy: Policy) -> bool {
    policy.process_whiteouts && policy.overwrite == OverwriteMode::UnionFiles
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
