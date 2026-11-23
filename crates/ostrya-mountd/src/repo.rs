//! The reads of a repository that a mount needs: the check of the mode, the
//! verity choice of the config, the open of the image of an image commit, and
//! the build of an image in memory. The daemon and the mount helper share
//! them.

use std::os::fd::{AsFd, OwnedFd};

use ostrya::{Checksum, ComposefsImageSource, Repo, RepoMode, Tristate, VerityPolicy};
use ostrya_mount::Verity;
use rustix::io::Errno;

/// The block size of the loop device that carries the image. The size of
/// an image must be a positive multiple of it.
const IMAGE_BLOCK: u64 = 4096;

/// The default largest size of a built image, in bytes: 100 MiB.
pub(crate) const DEFAULT_MAX_IMAGE_SIZE: u64 = 100 * 1024 * 1024;

/// The error of a read of the repository.
#[derive(Debug)]
pub(crate) enum Error {
    /// An error of the repository: a failed open, an image commit with a
    /// defect, a failed export, or a malformed config value.
    Repo(ostrya::Error),
    /// A repository whose mode a composefs mount cannot read. Only `archive`
    /// gives this error.
    UnsupportedMode(RepoMode),
    /// A commit that names no image commit as the attachment or the
    /// supplement `composefs`.
    NoImage {
        /// The commit of the request.
        commit: Checksum,
    },
    /// The image of an image commit, whose size a loop device cannot carry
    /// whole: 0, or not a multiple of 4096 bytes.
    ImageSize {
        /// The checksum of the image commit.
        image: Checksum,
        /// The size of the image in bytes.
        size: u64,
    },
    /// A system call of the memory file that failed.
    Sys {
        /// The call that failed.
        op: &'static str,
        /// The error number of the call.
        errno: Errno,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Repo(e) => e.fmt(f),
            Error::UnsupportedMode(mode) => write!(
                f,
                "a repository of the mode {} cannot be mounted",
                mode.as_mode_str()
            ),
            Error::NoImage { commit } => write!(
                f,
                "commit {commit} has no attachment or supplement {}",
                ostrya::COMPOSEFS_RELATION
            ),
            Error::ImageSize { image, size } => write!(
                f,
                "the image of commit {image} has the size {size}, which is not a positive \
                 multiple of {IMAGE_BLOCK} bytes"
            ),
            Error::Sys { op, errno } => write!(f, "{op}: {errno}"),
        }
    }
}

impl From<ostrya::Error> for Error {
    fn from(e: ostrya::Error) -> Error {
        Error::Repo(e)
    }
}

/// The values that each mount of a repository takes from it.
pub(crate) struct RepoPlan {
    /// The `verity` option of the composefs overlay.
    pub(crate) verity: Verity,
    /// The verity policy of a built image.
    pub(crate) build: VerityPolicy,
}

impl RepoPlan {
    /// Refuses a repository that cannot be mounted, and reads the verity
    /// choice from its config.
    pub(crate) fn new(repo: &Repo) -> Result<RepoPlan, Error> {
        check_mode(repo.mode())?;
        let (verity, build) = verity_for(repo.config().fsverity()?);
        Ok(RepoPlan { verity, build })
    }
}

/// Returns the overlay verity mode and the verity policy of a built image for
/// the value of `[ex-integrity] fsverity`.
///
/// Only `yes` seals each object, so only `yes` requires verity. With `maybe`,
/// an object on a file system without fs-verity has no seal, and the overlay
/// must not require one.
fn verity_for(fsverity: Tristate) -> (Verity, VerityPolicy) {
    match fsverity {
        Tristate::Yes => (Verity::Require, VerityPolicy::Computed),
        Tristate::No | Tristate::Maybe => (Verity::Off, VerityPolicy::Disabled),
    }
}

/// Refuses a repository mode whose objects a composefs mount cannot read.
///
/// The image names each backing object by its loose path,
/// `<xx>/<rest>.file`. Each mode except `archive` stores the raw content of a
/// regular file at that path. `archive` stores compressed `.filez` objects.
fn check_mode(mode: RepoMode) -> Result<(), Error> {
    match mode {
        RepoMode::Archive => Err(Error::UnsupportedMode(mode)),
        RepoMode::Bare
        | RepoMode::BareUser
        | RepoMode::BareUserOnly
        | RepoMode::BareSplitXattrs
        | RepoMode::BareUserShared => Ok(()),
    }
}

/// Opens the image of the image commit that `commit` names as the
/// attachment or the supplement `composefs`.
///
/// The lookup and its checks are those of [`Repo::open_composefs_image`]. The
/// call then refuses an image whose size is 0 or not a multiple of 4096
/// bytes, because the loop device reads the image in blocks of 4096 bytes.
/// The call does not copy the image. Under `[ex-integrity] fsverity=yes`, the
/// lookup requires that the loose object of the image is sealed with
/// fs-verity. Under another value, the object can have no seal, and a process
/// that can write the file can then change it while it is mounted.
///
/// Returns the descriptor of the image, the field that names the image
/// commit, and the checksum of the image commit, or `None` if the commit
/// names no image commit.
pub(crate) async fn find_image(
    repo: &Repo,
    commit: &Checksum,
) -> Result<Option<(OwnedFd, ComposefsImageSource, Checksum)>, Error> {
    let Some(image) = repo.open_composefs_image(commit).await? else {
        return Ok(None);
    };
    if image.size == 0 || !image.size.is_multiple_of(IMAGE_BLOCK) {
        return Err(Error::ImageSize {
            image: image.commit,
            size: image.size,
        });
    }
    Ok(Some((image.file.into(), image.source, image.commit)))
}

/// Opens the image of the image commit that `commit` names, as
/// [`find_image`] does, and refuses a commit that names no image commit.
pub(crate) async fn open_named_image(repo: &Repo, commit: &Checksum) -> Result<OwnedFd, Error> {
    match find_image(repo, commit).await? {
        Some((image, _, _)) => Ok(image),
        None => Err(Error::NoImage { commit: *commit }),
    }
}

/// Builds the composefs image of `commit` into a sealed memory file.
///
/// The build refuses an image larger than `max_size` bytes before it writes
/// a byte. Under [`VerityPolicy::Computed`], it takes the digest of each
/// backing object from the kernel, and refuses an object with no seal.
pub(crate) async fn build_image(
    repo: &Repo,
    commit: &Checksum,
    repo_plan: &RepoPlan,
    max_size: u64,
) -> Result<OwnedFd, Error> {
    let image = ostrya_sys::sealable_memfd(&format!("ostrya-cfs-{commit}")).map_err(|errno| {
        Error::Sys {
            op: "memfd_create",
            errno,
        }
    })?;
    repo.export_composefs_for_mount(commit, repo_plan.build, image.as_fd(), max_size)
        .await?;
    ostrya_sys::seal_contents(&image).map_err(|errno| Error::Sys {
        op: "seal memfd",
        errno,
    })?;
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_yes_requires_verity() {
        assert_eq!(
            verity_for(Tristate::Yes),
            (Verity::Require, VerityPolicy::Computed)
        );
        assert_eq!(
            verity_for(Tristate::Maybe),
            (Verity::Off, VerityPolicy::Disabled)
        );
        assert_eq!(
            verity_for(Tristate::No),
            (Verity::Off, VerityPolicy::Disabled)
        );
    }

    #[test]
    fn only_archive_is_refused() {
        for mode in [
            RepoMode::Bare,
            RepoMode::BareUser,
            RepoMode::BareUserOnly,
            RepoMode::BareSplitXattrs,
            RepoMode::BareUserShared,
        ] {
            check_mode(mode).unwrap();
        }
        assert!(matches!(
            check_mode(RepoMode::Archive),
            Err(Error::UnsupportedMode(RepoMode::Archive))
        ));
    }
}
