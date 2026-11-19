//! The reads of a repository that a mount needs: the check of the mode, the
//! verity choice of the config, and the build of an image in memory.

use std::os::fd::{AsFd, OwnedFd};

use ostrya::{Checksum, Repo, RepoMode, Tristate, VerityPolicy};
use ostrya_mount::Verity;
use rustix::io::Errno;

/// The error of a read of the repository.
#[derive(Debug)]
pub(crate) enum Error {
    /// An error of the repository: a failed open, an absent image, an image
    /// whose digest is not the key of its commit, a failed export, or a
    /// malformed config value.
    Repo(ostrya::Error),
    /// A repository whose mode a composefs mount cannot read. Only `archive`
    /// gives this error.
    UnsupportedMode(RepoMode),
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
