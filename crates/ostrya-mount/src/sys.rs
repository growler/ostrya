//! The blocking mount steps: the loop device, the EROFS mount, the overlays,
//! and the unmount.
//!
//! Each function blocks the calling thread. The callers run them on the
//! blocking pool of the runtime.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ostrya_sys::{LoopConfig, LoopDevice};
use rustix::fs::{AtFlags, CWD, Mode, OFlags, StatxAttributes, StatxFlags, openat};
use rustix::io::Errno;
use rustix::mount::{
    FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags, UnmountFlags, fsconfig_create,
    fsconfig_set_fd, fsconfig_set_flag, fsconfig_set_string, fsmount, fsopen, move_mount, unmount,
};

use crate::error::{ATTACH_STEP, Error, Result};
use crate::options::{Access, OverlayVerity};

/// The block size of the loop device, in bytes. EROFS uses blocks of this
/// size, and a loop device with the same block size reads each block in one
/// request.
pub(crate) const IMAGE_BLOCK: u64 = 4096;

/// The `f_type` that `statfs` reports for overlayfs.
pub(crate) const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;

/// The number of names that [`TempDir::new`] tries before it fails.
const TEMP_ATTEMPTS: u32 = 100;

/// The settings of one mount.
#[derive(Debug)]
pub(crate) struct Plan {
    /// The `verity` option of the composefs overlay.
    pub(crate) verity: OverlayVerity,
    /// Read-only, or read-write with an upper directory.
    pub(crate) access: Access,
    /// The source label of the mount.
    pub(crate) source: String,
    /// The attribute flags that each mount of the tree adds, for example
    /// `MOUNT_ATTR_NOSUID`.
    pub(crate) attrs: MountAttrFlags,
    /// The user namespace whose mapping the EROFS mount takes, or `None` for
    /// a mount with no ID mapping.
    pub(crate) idmap: Option<OwnedFd>,
}

/// The upper and the work directory of a read-write mount.
#[derive(Debug)]
pub(crate) struct Layout {
    /// The upper directory, `<target>/overlay`.
    pub(crate) upper: OwnedFd,
    /// The work directory, `<target>/work`.
    pub(crate) work: OwnedFd,
}

impl Layout {
    /// Creates `overlay` and `work` under the target `target_fd` if they are
    /// absent, and opens them.
    pub(crate) fn ensure(target_fd: BorrowedFd<'_>) -> Result<Layout> {
        Ok(Layout {
            upper: ensure_layout_dir(target_fd, "overlay")?,
            work: ensure_layout_dir(target_fd, "work")?,
        })
    }
}

/// The options of the overlay on the composefs mount.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UpperOptions {
    /// Keeps the overlay xattrs in the `user.overlay.` namespace. An overlay
    /// that a process mounts inside a user namespace needs it.
    pub(crate) userxattr: bool,
    /// The attribute flags that the mount adds to `MOUNT_ATTR_NOATIME`.
    pub(crate) attrs: MountAttrFlags,
    /// The way the overlay takes each layer.
    pub(crate) layers: LayerRef,
}

/// The way an overlay takes a layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayerRef {
    /// The `/proc/self/fd/N` path of the descriptor of the layer. The kernel
    /// resolves the path in the mount namespace of the process.
    Path,
    /// The descriptor of the layer itself, with `FSCONFIG_SET_FD`. This form
    /// needs no `/proc` in the mount namespace of the process.
    #[cfg_attr(not(feature = "server"), allow(dead_code))]
    Fd,
}

/// Mounts the EROFS image `image` over the backing objects in `objects` at
/// `target`, and returns a descriptor of the root of the new mount.
///
/// The function attaches the image to a loop device, mounts the device as
/// EROFS, and stacks the composefs overlay on it. For [`Access::ReadWrite`]
/// it stacks a second overlay with an upper directory. overlayfs takes each
/// layer by the `/proc/self/fd/N` path of its detached mount. The composefs
/// layer of a read-write mount is attached at a temp directory while the
/// upper overlay takes it. The new mount goes onto `target` as the last step,
/// so a failure leaves `target` unchanged, except for the upper and the work
/// directory of a read-write mount.
pub(crate) fn mount_tree(
    image: OwnedFd,
    objects: BorrowedFd<'_>,
    target: &Path,
    plan: &Plan,
) -> Result<OwnedFd> {
    let target_fd = open_dir(CWD, target).map_err(|e| Error::sys("open target", e))?;
    let layout = match plan.access {
        Access::ReadOnly => None,
        Access::ReadWrite => Some(Layout::ensure(target_fd.as_fd())?),
    };

    let composefs = build_composefs(image, objects, plan)?;
    let top = match layout {
        None => composefs,
        Some(layout) => {
            let lower = TempMount::attach(composefs)?;
            let opts = UpperOptions {
                userxattr: false,
                attrs: plan.attrs,
                layers: LayerRef::Path,
            };
            top_overlay(lower.as_fd(), Some(&layout), &plan.source, opts)?
        }
    };
    // The descriptor of the root stays valid when the mount moves, so it is
    // opened before the move, and no step can fail after it.
    let root = open_dir(&top, ".").map_err(|e| Error::sys("open mount root", e))?;
    move_onto(top, target_fd.as_fd())?;
    Ok(root)
}

/// Mounts the EROFS image `image` and stacks the read-only composefs overlay
/// on it, with the backing objects in `objects`. Returns the detached
/// overlay mount.
///
/// With [`Plan::idmap`], the EROFS mount takes the ID mapping of that user
/// namespace before the overlay takes it. The overlay takes the detached
/// EROFS mount as its layer.
pub(crate) fn build_composefs(
    image: OwnedFd,
    objects: BorrowedFd<'_>,
    plan: &Plan,
) -> Result<OwnedFd> {
    let erofs = erofs_mount(image.as_fd(), plan.attrs)?;
    // The loop device holds its own reference to the image.
    drop(image);
    if let Some(userns) = &plan.idmap {
        ostrya_sys::mount_setattr_idmap(&erofs, userns)
            .map_err(|e| Error::sys("mount_setattr idmap", e))?;
    }
    let composefs = composefs_overlay(erofs.as_fd(), objects, plan)?;
    // The overlay holds its own reference to each layer.
    drop(erofs);
    Ok(composefs)
}

/// Moves the detached mount `top` onto the directory `target_fd`.
pub(crate) fn move_onto(top: OwnedFd, target_fd: BorrowedFd<'_>) -> Result<()> {
    move_mount(
        &top,
        "",
        target_fd,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .map_err(|e| Error::sys("move_mount to target", e))
}

/// Unmounts the overlay mount at `target`.
///
/// The function refuses a target that is not the root of an overlay mount,
/// so a wrong path cannot unmount another file system. The unmount is not
/// lazy: a mount that a process still uses gives `EBUSY`. After the unmount,
/// the kernel releases the layers, and the loop device detaches.
pub(crate) fn unmount_overlay(target: &Path) -> Result<()> {
    let stat = rustix::fs::statfs(target).map_err(|e| Error::sys("statfs target", e))?;
    let is_overlay = u64::try_from(stat.f_type).is_ok_and(|t| t == OVERLAYFS_SUPER_MAGIC);
    let stx = rustix::fs::statx(CWD, target, AtFlags::empty(), StatxFlags::BASIC_STATS)
        .map_err(|e| Error::sys("statx target", e))?;
    let is_root = stx.stx_attributes.contains(StatxAttributes::MOUNT_ROOT);
    if !is_overlay || !is_root {
        return Err(Error::NotOverlayMount(target.to_owned()));
    }
    unmount(target, UnmountFlags::empty()).map_err(|e| Error::sys("unmount", e))
}

/// Opens the directory at `path` under `dir` read-only.
pub(crate) fn open_dir(
    dir: impl AsFd,
    path: impl rustix::path::Arg,
) -> rustix::io::Result<OwnedFd> {
    openat(
        dir,
        path,
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Returns the `/proc/self/fd/N` path of `fd`, the form in which overlayfs
/// and EROFS take a layer or a device.
pub(crate) fn fd_path(fd: BorrowedFd<'_>) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

/// Attaches `image` to a read-only, auto-clearing loop device with
/// [`IMAGE_BLOCK`]-byte blocks. The device reads with direct I/O where the
/// kernel accepts it.
fn attach_loop(image: BorrowedFd<'_>) -> Result<LoopDevice> {
    let cfg = LoopConfig {
        block_size: IMAGE_BLOCK as u32,
        read_only: true,
        autoclear: true,
        direct_io: true,
    };
    LoopDevice::attach(image, &cfg).map_err(|e| Error::sys(ATTACH_STEP, e))
}

/// Mounts `image` as EROFS through a loop device, with the attribute flags
/// `attrs` added, and returns the detached mount.
///
/// The mount holds the loop device open. The device is auto-clearing, so it
/// detaches when the last mount of it goes away.
fn erofs_mount(image: BorrowedFd<'_>, attrs: MountAttrFlags) -> Result<OwnedFd> {
    let dev = attach_loop(image)?;
    let fs =
        fsopen("erofs", FsOpenFlags::FSOPEN_CLOEXEC).map_err(|e| Error::sys("fsopen erofs", e))?;
    configure(&fs, "fsconfig erofs", |fs| {
        fsconfig_set_flag(fs, "ro")?;
        fsconfig_set_string(fs, "source", fd_path(dev.as_fd()))?;
        fsconfig_create(fs)
    })?;
    let mount = fsmount(
        &fs,
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_RDONLY | MountAttrFlags::MOUNT_ATTR_NOATIME | attrs,
    )
    .map_err(|e| Error::sys("fsmount erofs", e))?;
    Ok(mount)
}

/// Stacks the read-only composefs overlay: the EROFS mount `erofs` as the
/// metadata layer, and the object store `objects` as the data layer. The
/// mount adds the attribute flags of `plan`. Returns the detached mount.
fn composefs_overlay(
    erofs: BorrowedFd<'_>,
    objects: BorrowedFd<'_>,
    plan: &Plan,
) -> Result<OwnedFd> {
    let fs = fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC)
        .map_err(|e| Error::sys("fsopen overlay", e))?;
    configure(&fs, "fsconfig composefs overlay", |fs| {
        fsconfig_set_string(fs, "source", plan.source.as_str())?;
        // A data-only layer needs both options: each file of the image is a
        // metacopy inode with a redirect to its backing object.
        fsconfig_set_string(fs, "metacopy", "on")?;
        fsconfig_set_string(fs, "redirect_dir", "on")?;
        fsconfig_set_string(fs, "verity", plan.verity.option())?;
        fsconfig_set_string(fs, "lowerdir+", fd_path(erofs))?;
        fsconfig_set_string(fs, "datadir+", fd_path(objects))?;
        fsconfig_create(fs)
    })?;
    fsmount(
        &fs,
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_RDONLY | MountAttrFlags::MOUNT_ATTR_NOATIME | plan.attrs,
    )
    .map_err(|e| Error::sys("fsmount composefs overlay", e))
}

/// Stacks an overlay on the composefs mount `lower` and returns the detached
/// mount.
///
/// With `layout`, the overlay is writable, with the upper and the work
/// directory of `layout`. With no `layout`, the overlay is read-only. Its
/// layers are `lower` and, below it, an empty read-only tmpfs, because
/// overlayfs refuses one lower layer with no upper directory. The tmpfs adds
/// no entry to the tree.
///
/// `lower` names the root of a mount. overlayfs takes each layer in the form
/// of [`UpperOptions::layers`].
pub(crate) fn top_overlay(
    lower: BorrowedFd<'_>,
    layout: Option<&Layout>,
    source: &str,
    opts: UpperOptions,
) -> Result<OwnedFd> {
    let fs = fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC)
        .map_err(|e| Error::sys("fsopen overlay", e))?;
    let empty = match layout {
        Some(_) => None,
        None => Some(empty_layer()?),
    };
    let layer = |fs: &OwnedFd, key: &str, fd: BorrowedFd<'_>| match opts.layers {
        LayerRef::Path => fsconfig_set_string(fs, key, fd_path(fd)),
        LayerRef::Fd => fsconfig_set_fd(fs, key, fd),
    };
    configure(&fs, "fsconfig top overlay", |fs| {
        fsconfig_set_string(fs, "source", source)?;
        if opts.userxattr {
            fsconfig_set_flag(fs, "userxattr")?;
        }
        // The module parameters of the host give the defaults of `metacopy`
        // and `redirect_dir`. The mount sets both, so the upper directory has
        // the same form on each host: a file that the mount copies up holds
        // its data, and no directory is a redirect. `nofollow` keeps this also
        // on a host that sets `redirect_always_follow`, where `userxattr`
        // with `follow` fails. A `rename(2)` of a lower directory that is not
        // copied up then gives `EXDEV`. The lower layer is the composefs
        // overlay, which does not show its own `trusted.overlay.*` xattrs, so
        // no redirect of that layer is lost.
        fsconfig_set_string(fs, "metacopy", "off")?;
        fsconfig_set_string(fs, "redirect_dir", "nofollow")?;
        layer(fs, "lowerdir+", lower)?;
        if let Some(empty) = &empty {
            layer(fs, "lowerdir+", empty.as_fd())?;
        }
        if let Some(layout) = layout {
            layer(fs, "upperdir", layout.upper.as_fd())?;
            layer(fs, "workdir", layout.work.as_fd())?;
        }
        fsconfig_create(fs)
    })?;
    let rdonly = match layout {
        Some(_) => MountAttrFlags::empty(),
        None => MountAttrFlags::MOUNT_ATTR_RDONLY,
    };
    fsmount(
        &fs,
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_NOATIME | rdonly | opts.attrs,
    )
    .map_err(|e| Error::sys("fsmount top overlay", e))
}

/// Mounts an empty, read-only tmpfs and returns the detached mount.
fn empty_layer() -> Result<OwnedFd> {
    let fs =
        fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC).map_err(|e| Error::sys("fsopen tmpfs", e))?;
    configure(&fs, "fsconfig tmpfs", |fs| {
        fsconfig_set_string(fs, "mode", "0755")?;
        fsconfig_set_flag(fs, "ro")?;
        fsconfig_create(fs)
    })?;
    fsmount(
        &fs,
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_RDONLY
            | MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NODEV
            | MountAttrFlags::MOUNT_ATTR_NOEXEC,
    )
    .map_err(|e| Error::sys("fsmount tmpfs", e))
}

/// Runs the `fsconfig` calls of `steps` on the file system context `fs`. On
/// a failure, the error carries the messages that the kernel logged in the
/// context.
fn configure(
    fs: &OwnedFd,
    op: &'static str,
    steps: impl FnOnce(&OwnedFd) -> rustix::io::Result<()>,
) -> Result<()> {
    steps(fs).map_err(|errno| Error::Sys {
        op,
        errno,
        log: context_log(fs),
    })
}

/// Reads the messages that the kernel logged in the file system context
/// `fs`, joined with `; `. Returns `None` if the context holds no message.
///
/// Each read returns one message. A read of an empty log gives `ENODATA`.
fn context_log(fs: &OwnedFd) -> Option<String> {
    let mut lines = Vec::new();
    let mut buf = [0u8; 1024];
    // The kernel keeps at most 8 messages in a context.
    for _ in 0..8 {
        match rustix::io::read(fs, &mut buf) {
            Ok(n) if n > 0 => lines.push(String::from_utf8_lossy(&buf[..n]).trim_end().to_owned()),
            _ => break,
        }
    }
    (!lines.is_empty()).then(|| lines.join("; "))
}

/// Creates the directory `name` under `dirfd` with the mode 0755 if it is
/// absent, and opens it.
///
/// The function sets the mode with `fchmod` after the create, so the umask
/// of the process does not change it. An existing directory keeps its mode.
/// Only a directory is accepted: a regular file or a symlink fails the open
/// with `ENOTDIR`.
pub(crate) fn ensure_layout_dir(dirfd: BorrowedFd<'_>, name: &'static str) -> Result<OwnedFd> {
    let created = match rustix::fs::mkdirat(dirfd, name, Mode::from_bits_truncate(0o755)) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(e) => return Err(Error::sys(name, e)),
    };
    let fd = openat(
        dirfd,
        name,
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| Error::sys(name, e))?;
    if created {
        rustix::fs::fchmod(&fd, Mode::from_bits_truncate(0o755))
            .map_err(|e| Error::sys(name, e))?;
    }
    Ok(fd)
}

/// A new, empty directory in the temp directory of the process. The value
/// removes the directory when it drops.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates `.ostrya-mount-<pid>-<n>` with the mode 0700 in
    /// [`std::env::temp_dir`]. `n` is a counter of the process. If the name
    /// exists, the function tries the next value of the counter.
    fn new() -> Result<TempDir> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        for _ in 0..TEMP_ATTEMPTS {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!(".ostrya-mount-{}-{n}", std::process::id()));
            match builder.create(&path) {
                Ok(()) => return Ok(TempDir { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(Error::io("create temp mount directory", &e)),
            }
        }
        Err(Error::sys("create temp mount directory", Errno::EXIST))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

/// A detached mount, attached at a [`TempDir`] while a later layer takes it.
///
/// The value holds the descriptor of the root of the mount. When it drops, it
/// detaches the mount from the directory and removes the directory. A layer
/// that a later mount took stays in that mount.
struct TempMount {
    fd: OwnedFd,
    dir: TempDir,
}

impl TempMount {
    /// Attaches the detached mount `mount` at a new temp directory. The
    /// descriptor `mount` then names the root of the attached mount.
    fn attach(mount: OwnedFd) -> Result<TempMount> {
        let dir = TempDir::new()?;
        move_mount(
            &mount,
            "",
            CWD,
            &dir.path,
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )
        .map_err(|e| Error::sys("move_mount to temp directory", e))?;
        Ok(TempMount { fd: mount, dir })
    }
}

impl AsFd for TempMount {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Drop for TempMount {
    fn drop(&mut self) {
        // The unmount follows no symlink at the temp path, so it can only
        // detach a mount at the directory itself.
        let _ = unmount(
            &self.dir.path,
            UnmountFlags::DETACH | UnmountFlags::NOFOLLOW,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_temp_dir_is_private_and_goes_away() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path.clone();
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o7777, 0o700);
        let other = TempDir::new().unwrap();
        assert_ne!(other.path, path);
        drop(dir);
        assert!(!path.exists());
    }
}
