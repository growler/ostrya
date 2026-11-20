//! The options of a mount.

use rustix::mount::MountAttrFlags;

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
    /// The attribute flags of the mount. The default sets no flag.
    pub flags: MountFlags,
}

/// The attribute flags that a mount adds.
///
/// [`Direct::mount_image`](crate::Direct::mount_image) adds each flag that
/// is `true` to each mount of the tree. The mount daemon sets `nosuid` and
/// `nodev` on each mount, with or without the flags. It cannot set `noexec`,
/// so [`Helper`](crate::Helper) refuses `noexec` before it connects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MountFlags {
    /// The mount ignores the set-user-ID bit, the set-group-ID bit, and the
    /// file capabilities of each file: `MOUNT_ATTR_NOSUID`.
    pub nosuid: bool,
    /// The mount opens no device node: `MOUNT_ATTR_NODEV`.
    pub nodev: bool,
    /// The mount runs no program: `MOUNT_ATTR_NOEXEC`.
    pub noexec: bool,
}

impl MountFlags {
    /// Returns the flags as mount attributes of the kernel.
    pub(crate) fn attrs(self) -> MountAttrFlags {
        let mut attrs = MountAttrFlags::empty();
        if self.nosuid {
            attrs |= MountAttrFlags::MOUNT_ATTR_NOSUID;
        }
        if self.nodev {
            attrs |= MountAttrFlags::MOUNT_ATTR_NODEV;
        }
        if self.noexec {
            attrs |= MountAttrFlags::MOUNT_ATTR_NOEXEC;
        }
        attrs
    }
}

/// The `verity` option of the composefs overlay.
///
/// [`Plan::verity`](crate::sys::Plan::verity) takes the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verity {
    /// The overlay reads no fs-verity digest.
    Off,
    /// The overlay compares the fs-verity digest of each backing object with
    /// the digest in the image, and refuses a file without a digest.
    Require,
}

impl Verity {
    /// Returns the value of the `verity` option of overlayfs.
    pub(crate) fn option(self) -> &'static str {
        match self {
            Verity::Off => "off",
            Verity::Require => "require",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_read_only_with_no_source_and_no_flag() {
        let opts = MountOptions::default();
        assert_eq!(opts.access, Access::ReadOnly);
        assert_eq!(opts.source, None);
        assert_eq!(opts.flags, MountFlags::default());
        assert_eq!(opts.flags.attrs(), MountAttrFlags::empty());
    }

    #[test]
    fn each_flag_gives_its_mount_attribute() {
        let flags = MountFlags {
            nosuid: true,
            nodev: false,
            noexec: true,
        };
        assert_eq!(
            flags.attrs(),
            MountAttrFlags::MOUNT_ATTR_NOSUID | MountAttrFlags::MOUNT_ATTR_NOEXEC
        );
        let flags = MountFlags {
            nodev: true,
            ..MountFlags::default()
        };
        assert_eq!(flags.attrs(), MountAttrFlags::MOUNT_ATTR_NODEV);
    }
}
