//! The options of a mount, and the choices that the repository config makes.

use ostrya::{RepoMode, Tristate, VerityPolicy};

use crate::error::{Error, Result};

/// The access that a mount gives to the tree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Access {
    /// The mount is read-only.
    ///
    /// This value is the default.
    #[default]
    ReadOnly,
    /// The mount accepts changes. An overlay with an upper directory holds
    /// each change, and the repository does not change.
    ///
    /// The upper directory is `<target>/overlay`, and the work directory of
    /// the overlay is `<target>/work`. The mount creates each of them with
    /// the mode 0755 if it is absent, and keeps the content of an existing
    /// one. The mount hides both directories while it is in place.
    ReadWrite,
}

/// The options of a mount.
///
/// Create the options with [`MountOptions::default`], then set the fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MountOptions {
    /// The access that the mount gives. The default is [`Access::ReadOnly`].
    pub access: Access,
    /// The source label of the mount, which `/proc/self/mountinfo` shows.
    ///
    /// If the value is `None`, a mount of a commit takes the checksum of the
    /// commit, and a mount of an image of the caller takes `composefs`. The
    /// kernel takes a label of at most 255 bytes, and
    /// [`Helper`](crate::Helper) refuses a longer one before it connects.
    pub source: Option<String>,
}

/// The `verity` option of the composefs overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverlayVerity {
    /// The overlay reads no fs-verity digest.
    Off,
    /// The overlay compares the fs-verity digest of each backing object with
    /// the digest in the image, and refuses a file without a digest.
    Require,
}

impl OverlayVerity {
    /// Returns the value of the `verity` option of overlayfs.
    pub(crate) fn option(self) -> &'static str {
        match self {
            OverlayVerity::Off => "off",
            OverlayVerity::Require => "require",
        }
    }
}

/// Returns the overlay verity mode and the verity policy of a built image for
/// the value of `[ex-integrity] fsverity`.
///
/// Only `yes` seals each object, so only `yes` requires verity. With `maybe`,
/// an object on a file system without fs-verity has no seal, and the overlay
/// must not require one.
pub(crate) fn verity_for(fsverity: Tristate) -> (OverlayVerity, VerityPolicy) {
    match fsverity {
        Tristate::Yes => (OverlayVerity::Require, VerityPolicy::Computed),
        Tristate::No | Tristate::Maybe => (OverlayVerity::Off, VerityPolicy::Disabled),
    }
}

/// Refuses a repository mode whose objects a composefs mount cannot read.
///
/// The image names each backing object by its loose path,
/// `<xx>/<rest>.file`. Each mode except `archive` stores the raw content of a
/// regular file at that path. `archive` stores compressed `.filez` objects.
pub(crate) fn check_mode(mode: RepoMode) -> Result<()> {
    match mode {
        RepoMode::Archive => Err(Error::UnsupportedMode(mode)),
        RepoMode::Bare
        | RepoMode::BareUser
        | RepoMode::BareUserOnly
        | RepoMode::BareSplitXattrs
        | RepoMode::BareUserShared => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_yes_requires_verity() {
        assert_eq!(
            verity_for(Tristate::Yes),
            (OverlayVerity::Require, VerityPolicy::Computed)
        );
        assert_eq!(
            verity_for(Tristate::Maybe),
            (OverlayVerity::Off, VerityPolicy::Disabled)
        );
        assert_eq!(
            verity_for(Tristate::No),
            (OverlayVerity::Off, VerityPolicy::Disabled)
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

    #[test]
    fn the_default_is_read_only_with_no_source() {
        let opts = MountOptions::default();
        assert_eq!(opts.access, Access::ReadOnly);
        assert_eq!(opts.source, None);
    }
}
