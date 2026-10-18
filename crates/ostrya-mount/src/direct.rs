//! The direct mounter, for a root caller in the initial user namespace.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use ostrya::{Checksum, ComposefsOptions, Repo};

use crate::error::{Error, Result};
use crate::options::{MountOptions, OverlayVerity, check_mode, verity_for};
use crate::sys::{IMAGE_BLOCK, Plan, mount_tree, unmount_overlay};

/// The source label of a mount of an image of the caller, if the options
/// give none.
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
/// Each mount call checks the repository first and then runs the system
/// calls on the blocking pool of the runtime. The new mount goes onto the
/// target as the last step. If the caller drops the future of a call after
/// the system calls start, the mount still completes.
#[derive(Debug, Clone, Copy, Default)]
pub struct Direct {
    _private: (),
}

/// The values that each mount of a repository takes from it.
struct RepoPlan {
    /// The `verity` option of the composefs overlay.
    verity: OverlayVerity,
    /// The options of a built image.
    build: ComposefsOptions,
}

impl RepoPlan {
    /// Refuses a repository that cannot be mounted, and reads the verity
    /// choice from its config.
    fn new(repo: &Repo) -> Result<RepoPlan> {
        check_mode(repo.mode())?;
        let (verity, policy) = verity_for(repo.config().fsverity()?);
        Ok(RepoPlan {
            verity,
            build: ComposefsOptions { verity: policy },
        })
    }

    /// Returns the settings of a mount with `opts`, with `source` as the
    /// label if `opts` gives none.
    fn plan(&self, opts: &MountOptions, source: impl FnOnce() -> String) -> Plan {
        Plan {
            verity: self.verity,
            access: opts.access,
            source: opts.source.clone().unwrap_or_else(source),
        }
    }
}

impl Direct {
    /// Returns the direct mounter.
    pub fn new() -> Direct {
        Direct { _private: () }
    }

    /// Mounts the stored composefs image of `commit` at `target`.
    ///
    /// The call opens the image through
    /// [`Repo::open_composefs_image_checked`], which compares its digest with
    /// the key `ostree.composefs.digest.v0` of the commit. The loop device
    /// takes the descriptor that the call checked.
    ///
    /// With `[ex-integrity] fsverity=yes`, the overlay mounts with
    /// `verity=require`. The kernel then compares the fs-verity digest of each
    /// backing object with the digest in the image when the file opens. With
    /// another value, the overlay mounts with `verity=off`.
    ///
    /// Returns a descriptor of the root of the new mount. The descriptor
    /// keeps the mount in use, so close it before [`Direct::unmount`].
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedMode`] for an `archive` repository.
    /// - [`Error::Repo`] with the errors of
    ///   [`Repo::open_composefs_image_checked`], and if `[ex-integrity]
    ///   fsverity` in the config is malformed.
    /// - [`Error::Sys`] if a system call fails. [`Direct::mount_image`] lists
    ///   the steps.
    pub async fn mount_stored(
        &self,
        repo: &Repo,
        commit: &Checksum,
        target: &Path,
        opts: &MountOptions,
    ) -> Result<OwnedFd> {
        let repo_plan = RepoPlan::new(repo)?;
        let (image, _) = repo.open_composefs_image_checked(commit).await?;
        let plan = repo_plan.plan(opts, || commit.to_hex());
        run(image.into(), repo, target, plan).await
    }

    /// Builds the composefs image of `commit` in memory and mounts it at
    /// `target`.
    ///
    /// The call needs no stored image and no key in the commit. It writes the
    /// image to a memory file as it serializes it, seals the file against
    /// each change, and attaches it to the loop device. The memory of the
    /// file counts against the memory cgroup of the process until the
    /// unmount, and the kernel frees it when the loop device detaches.
    ///
    /// With `[ex-integrity] fsverity=yes`, the image carries the fs-verity
    /// digest of each backing object, and the overlay mounts with
    /// `verity=require`. With another value, the image carries no digest, and
    /// the overlay mounts with `verity=off`.
    ///
    /// Returns a descriptor of the root of the new mount. The descriptor
    /// keeps the mount in use, so close it before [`Direct::unmount`].
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedMode`] for an `archive` repository.
    /// - [`Error::Repo`] with the errors of [`Repo::export_composefs_to`],
    ///   and if `[ex-integrity] fsverity` in the config is malformed.
    /// - [`Error::Sys`] if the memory file cannot be created or sealed, or if
    ///   a system call of the mount fails. [`Direct::mount_image`] lists the
    ///   steps.
    pub async fn mount_built(
        &self,
        repo: &Repo,
        commit: &Checksum,
        target: &Path,
        opts: &MountOptions,
    ) -> Result<OwnedFd> {
        let repo_plan = RepoPlan::new(repo)?;
        let image = ostrya_sys::sealable_memfd(&format!("ostrya-cfs-{commit}"))
            .map_err(|e| Error::sys("memfd_create", e))?;
        repo.export_composefs_to(commit, &repo_plan.build, image.as_fd())
            .await?;
        ostrya_sys::seal_contents(&image).map_err(|e| Error::sys("seal memfd", e))?;
        let plan = repo_plan.plan(opts, || commit.to_hex());
        run(image, repo, target, plan).await
    }

    /// Mounts the composefs image that `image` holds at `target`, with the
    /// backing objects of `repo`.
    ///
    /// The call checks no digest of the image. The loop device reads the
    /// image from offset 0, whatever the offset of the descriptor. The image
    /// must not change while it is mounted. A sealed image, for example a
    /// sealed memory file or a file sealed with fs-verity, gives this
    /// guarantee.
    ///
    /// The `verity` option of the overlay follows `[ex-integrity] fsverity`,
    /// as for [`Direct::mount_stored`]. With `verity=require`, each backed
    /// file of the image must carry a digest.
    ///
    /// The mount steps are:
    ///
    /// 1. The open of `target`. For [`Access::ReadWrite`](crate::Access),
    ///    the create of `<target>/overlay` and `<target>/work`.
    /// 2. The attach of the image to a read-only loop device with 4096-byte
    ///    blocks. The device uses direct I/O where the kernel accepts it.
    /// 3. The EROFS mount of the device.
    /// 4. The composefs overlay, with the EROFS mount as the metadata layer
    ///    and `objects/` as the data layer.
    /// 5. For [`Access::ReadWrite`](crate::Access), the overlay with the
    ///    upper directory.
    /// 6. The move of the new mount onto `target`.
    ///
    /// Returns a descriptor of the root of the new mount. The descriptor
    /// keeps the mount in use, so close it before [`Direct::unmount`].
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedMode`] for an `archive` repository.
    /// - [`Error::InvalidImage`] if the image is empty, or if its size is not
    ///   a multiple of 4096 bytes.
    /// - [`Error::Repo`] if `[ex-integrity] fsverity` in the config is
    ///   malformed.
    /// - [`Error::Sys`] if the duplicate or the `fstat` of `image` fails, or
    ///   if a step fails. The error names the step. For a refused file
    ///   system option, it carries the message of the kernel.
    pub async fn mount_image(
        &self,
        image: BorrowedFd<'_>,
        repo: &Repo,
        target: &Path,
        opts: &MountOptions,
    ) -> Result<OwnedFd> {
        let repo_plan = RepoPlan::new(repo)?;
        let image = image
            .try_clone_to_owned()
            .map_err(|e| Error::io("dup image", &e))?;
        let plan = repo_plan.plan(opts, || IMAGE_SOURCE.to_owned());
        let repo = repo.clone();
        let target = target.to_owned();
        ostrya_rt::unblock(move || {
            check_image_size(image.as_fd())?;
            mount_tree(image, repo.objects_dir(), &target, &plan)
        })
        .await
    }

    /// Unmounts the composefs mount at `target`.
    ///
    /// The call refuses a target that is not the root of an overlay mount.
    /// The unmount is not lazy, so each open descriptor in the mount blocks
    /// it, the descriptor that the mount call returned included. After it,
    /// the kernel releases the layers and detaches the loop device. For a
    /// built image, the kernel then frees the memory of the image.
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
    pub async fn unmount(&self, target: &Path) -> Result<()> {
        let target = target.to_owned();
        ostrya_rt::unblock(move || unmount_overlay(&target)).await
    }
}

/// Runs the blocking mount steps on the blocking pool.
async fn run(image: OwnedFd, repo: &Repo, target: &Path, plan: Plan) -> Result<OwnedFd> {
    let repo = repo.clone();
    let target = target.to_owned();
    ostrya_rt::unblock(move || mount_tree(image, repo.objects_dir(), &target, &plan)).await
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
