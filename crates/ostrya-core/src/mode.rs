//! Repository storage modes.

/// The on-disk storage mode of a repository.
///
/// The mode decides how a repository stores a [`File`] object and which
/// loose-path extension the object gets. The mode strings are the tokens of
/// `[core] mode=` in `config`. The `ostree` command writes each of them except
/// `bare-user-shared` and `bare-user-private`, the ostrya extensions.
///
/// [`File`]: crate::ObjectType::File
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RepoMode {
    /// Real files, with the uid, gid, mode, and xattrs on the inode.
    Bare,
    /// Files with the metadata in the `user.ostreemeta` xattr.
    ///
    /// A process with no privileges can write a repository of this mode.
    BareUser,
    /// Files with no xattr metadata.
    ///
    /// This mode drops the uid and the gid. The inode holds the canonical mode.
    BareUserOnly,
    /// Storage as in [`Bare`](Self::Bare), with the xattrs in separate
    /// `.file-xattrs` objects and none on the inode.
    BareSplitXattrs,
    /// File content in `.filez` objects, compressed with raw DEFLATE.
    ///
    /// An HTTP server can serve a repository of this mode.
    Archive,
    /// Storage as in [`BareUser`](Self::BareUser), for a repository that a
    /// group shares.
    ///
    /// This mode never applies the logical mode to the inode. It is an ostrya
    /// extension for development only.
    BareUserShared,
    /// Storage as in [`BareUser`](Self::BareUser), with the inode mode 0400 on
    /// each content object. Metadata objects keep 0644.
    ///
    /// The bytes of an object, its `user.ostreemeta` xattr, and each checksum
    /// are the same as in [`BareUser`](Self::BareUser). A symlink object is a
    /// regular file, and it also gets the inode mode 0400. A process that reads
    /// a content object must be the owner of the object or have privilege. A
    /// checkout copies or reflinks each regular file.
    ///
    /// This mode is an ostrya extension, for a host that mounts its
    /// deployments with composefs. The `ostree` command refuses to open a
    /// repository of this mode.
    BareUserPrivate,
}

impl RepoMode {
    /// Parses a `[core] mode=` string.
    ///
    /// Returns `None` for an unknown string. `archive` is an accepted alias
    /// for `archive-z2`.
    pub fn from_mode_str(s: &str) -> Option<RepoMode> {
        Some(match s {
            "bare" => RepoMode::Bare,
            "bare-user" => RepoMode::BareUser,
            "bare-user-only" => RepoMode::BareUserOnly,
            "bare-split-xattrs" => RepoMode::BareSplitXattrs,
            "archive-z2" | "archive" => RepoMode::Archive,
            "bare-user-shared" => RepoMode::BareUserShared,
            "bare-user-private" => RepoMode::BareUserPrivate,
            _ => return None,
        })
    }

    /// Returns the canonical `[core] mode=` string.
    ///
    /// [`Archive`](Self::Archive) always gives `archive-z2`.
    pub fn as_mode_str(self) -> &'static str {
        match self {
            RepoMode::Bare => "bare",
            RepoMode::BareUser => "bare-user",
            RepoMode::BareUserOnly => "bare-user-only",
            RepoMode::BareSplitXattrs => "bare-split-xattrs",
            RepoMode::Archive => "archive-z2",
            RepoMode::BareUserShared => "bare-user-shared",
            RepoMode::BareUserPrivate => "bare-user-private",
        }
    }

    /// Returns `true` if the mode stores [`File`] content objects compressed.
    ///
    /// The `z` loose-path suffix applies only to a [`File`] content object in
    /// this mode. The auxiliary non-meta objects carry no suffix.
    /// [`ObjectType::extension`] gives each extension.
    ///
    /// [`File`]: crate::ObjectType::File
    /// [`ObjectType::extension`]: crate::ObjectType::extension
    pub fn is_archive(self) -> bool {
        matches!(self, RepoMode::Archive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_alias_parses_and_canonicalizes() {
        assert_eq!(RepoMode::from_mode_str("archive"), Some(RepoMode::Archive));
        assert_eq!(
            RepoMode::from_mode_str("archive-z2"),
            Some(RepoMode::Archive)
        );
        assert_eq!(RepoMode::Archive.as_mode_str(), "archive-z2");
    }

    #[test]
    fn every_mode_round_trips_through_its_canonical_string() {
        for mode in [
            RepoMode::Bare,
            RepoMode::BareUser,
            RepoMode::BareUserOnly,
            RepoMode::BareSplitXattrs,
            RepoMode::Archive,
            RepoMode::BareUserShared,
            RepoMode::BareUserPrivate,
        ] {
            assert_eq!(RepoMode::from_mode_str(mode.as_mode_str()), Some(mode));
        }
    }

    #[test]
    fn unknown_mode_is_none() {
        assert_eq!(RepoMode::from_mode_str("bogus"), None);
    }
}
