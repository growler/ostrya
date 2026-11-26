//! The direct mounter, for a root caller in the initial user namespace.

use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;

use crate::error::{Error, Result};
use crate::options::{MountOptions, Verity};
use crate::sys::{IMAGE_BLOCK, Plan, mount_tree, unmount_overlay};

/// The source label of a mount, if the options give none.
const IMAGE_SOURCE: &str = "composefs";

/// The mounter that makes each mount in the process itself.
///
/// The process needs `CAP_SYS_ADMIN` in the initial user namespace, because
/// the kernel makes the EROFS and the overlayfs mounts only with that
/// privilege. It also needs access to `/dev/loop-control` and to the loop
/// devices. The mounter does no check of its own: a call without the
/// privilege or the access fails with [`Error::Sys`] and `EPERM` or
/// `EACCES`.
///
/// The mounter opens no repository. The caller opens the image and the
/// `objects` directory, and gives their descriptors to the call. Each call
/// blocks the calling thread until its system calls complete. A caller on an
/// async runtime runs the call on its blocking pool.
#[derive(Debug, Clone, Copy, Default)]
pub struct Direct {
    _private: (),
}

impl Direct {
    /// Returns the direct mounter.
    pub fn new() -> Direct {
        Direct { _private: () }
    }

    /// Mounts the composefs image that `image` holds at `target`, with the
    /// backing objects in the directory `objects`.
    ///
    /// The call checks no digest of the image. The loop device reads the
    /// image from offset 0, whatever the offset of the descriptor. The image
    /// must not change while it is mounted. A sealed image, for example a
    /// sealed memory file or a file sealed with fs-verity, gives this
    /// guarantee.
    ///
    /// `objects` is the `objects` directory of a repository of the mode
    /// `bare`, `bare-user`, `bare-user-only`, `bare-split-xattrs`,
    /// `bare-user-shared`, or `bare-user-private`. The call does not read the
    /// mode of the repository. An `archive` repository stores compressed
    /// `.filez` objects, so over its `objects` directory each regular file
    /// with content fails to open.
    ///
    /// `verity` is the `verity` option of the composefs overlay. The call
    /// does not read the config of the repository. Give [`Verity::Require`]
    /// if `[ex-integrity] fsverity` of the repository is `yes`, and
    /// [`Verity::Off`] for each other value. With [`Verity::Require`], the
    /// kernel compares the fs-verity digest of each backing object with the
    /// digest in the image when the file opens, and each backed file of the
    /// image must carry a digest.
    ///
    /// Each mount of the tree adds the attribute flags of
    /// [`MountOptions::flags`].
    ///
    /// The mount steps are:
    ///
    /// 1. The open of `target`. For [`Access::ReadWrite`](crate::Access),
    ///    the create of `<target>/overlay` and `<target>/work`.
    /// 2. The attach of the image to a read-only loop device with 4096-byte
    ///    blocks. The device uses direct I/O where the kernel accepts it.
    /// 3. The EROFS mount of the device.
    /// 4. The composefs overlay, with the EROFS mount as the metadata layer
    ///    and `objects` as the data layer.
    /// 5. For [`Access::ReadWrite`](crate::Access), the overlay with the
    ///    upper directory.
    /// 6. The move of the new mount onto `target`.
    ///
    /// The new mount goes onto `target` as the last step.
    ///
    /// Returns a descriptor of the root of the new mount. The descriptor
    /// keeps the mount in use, so close it before [`Direct::unmount`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidImage`] if the image is empty, or if its size is not
    ///   a multiple of 4096 bytes.
    /// - [`Error::Sys`] if the `fstat` or the duplicate of `image` fails, or
    ///   if a step fails. The error names the step. For a refused file
    ///   system option, it carries the message of the kernel.
    pub fn mount_image(
        &self,
        image: BorrowedFd<'_>,
        objects: BorrowedFd<'_>,
        verity: Verity,
        target: &Path,
        opts: &MountOptions,
    ) -> Result<OwnedFd> {
        check_image_size(image)?;
        let image = image
            .try_clone_to_owned()
            .map_err(|e| Error::io("dup image", &e))?;
        let plan = Plan {
            verity,
            access: opts.access,
            source: opts
                .source
                .clone()
                .unwrap_or_else(|| IMAGE_SOURCE.to_owned()),
            attrs: opts.flags.attrs(),
            idmap: None,
        };
        mount_tree(image, objects, target, &plan)
    }

    /// Unmounts the composefs mount at `target`.
    ///
    /// The call refuses a target that is not the root of an overlay mount.
    /// The unmount is not lazy, so each open descriptor in the mount blocks
    /// it, the descriptor that the mount call returned included. After it,
    /// the kernel releases the layers and detaches the loop device. For an
    /// image in a memory file, the kernel then frees the memory of the image
    /// when no descriptor of the file is open.
    ///
    /// For a read-write mount, the upper directory `<target>/overlay` keeps
    /// the changes after the unmount.
    ///
    /// # Errors
    ///
    /// - [`Error::NotOverlayMount`] if `target` is not the root of an overlay
    ///   mount.
    /// - [`Error::Sys`] with `EBUSY` if a process still uses the mount, and
    ///   [`Error::Sys`] if another call fails.
    pub fn unmount(&self, target: &Path) -> Result<()> {
        unmount_overlay(target)
    }
}

/// Refuses an image of the caller that a loop device cannot carry whole: an
/// empty file, or a size that is not a multiple of [`IMAGE_BLOCK`].
fn check_image_size(image: BorrowedFd<'_>) -> Result<()> {
    let size = rustix::fs::fstat(image)
        .map_err(|e| Error::sys("fstat image", e))?
        .st_size;
    if !u64::try_from(size).is_ok_and(|n| n > 0 && n.is_multiple_of(IMAGE_BLOCK)) {
        return Err(Error::InvalidImage(format!(
            "the size {size} is not a positive multiple of {IMAGE_BLOCK} bytes"
        )));
    }
    Ok(())
}
