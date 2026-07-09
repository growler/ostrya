//! Repository storage modes.
//!
//! The mode determines how a `File` object is materialized on disk and how the
//! loose-path extension is chosen. The mode strings here are the exact tokens
//! the `ostree` tool writes to `config` under `[core] mode=`.

/// The on-disk storage mode of a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RepoMode {
    /// Real files with real uid/gid/mode/xattrs on the inode.
    Bare,
    /// Metadata carried in the `user.ostreemeta` xattr; unprivileged-writable.
    BareUser,
    /// No xattr metadata; uid/gid discarded, canonical mode on the inode.
    BareUserOnly,
    /// Like bare-user, but xattrs live in separate `.file-xattrs` objects.
    BareSplitXattrs,
    /// Content zlib-RAW-compressed as `.filez`; HTTP-servable.
    Archive,
    /// Port extension (development-only): `File` split into `.filea`
    /// (attributes plus a blob reference) and `.fileb` (raw payload).
    BareUserSplitAttrs,
}

impl RepoMode {
    /// Parse a `[core] mode=` string. `archive` is an accepted alias for
    /// `archive-z2`.
    pub fn from_mode_str(s: &str) -> Option<RepoMode> {
        Some(match s {
            "bare" => RepoMode::Bare,
            "bare-user" => RepoMode::BareUser,
            "bare-user-only" => RepoMode::BareUserOnly,
            "bare-split-xattrs" => RepoMode::BareSplitXattrs,
            "archive-z2" | "archive" => RepoMode::Archive,
            "bare-user-split-attrs" => RepoMode::BareUserSplitAttrs,
            _ => return None,
        })
    }

    /// The canonical `[core] mode=` string. Archive always serializes back as
    /// `archive-z2`.
    pub fn as_mode_str(self) -> &'static str {
        match self {
            RepoMode::Bare => "bare",
            RepoMode::BareUser => "bare-user",
            RepoMode::BareUserOnly => "bare-user-only",
            RepoMode::BareSplitXattrs => "bare-split-xattrs",
            RepoMode::Archive => "archive-z2",
            RepoMode::BareUserSplitAttrs => "bare-user-split-attrs",
        }
    }

    /// Whether `File` content objects are stored compressed. The `z`
    /// loose-path suffix applies only to a `File` content object in this mode;
    /// the auxiliary non-meta objects carry no suffix.
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
            RepoMode::BareUserSplitAttrs,
        ] {
            assert_eq!(RepoMode::from_mode_str(mode.as_mode_str()), Some(mode));
        }
    }

    #[test]
    fn unknown_mode_is_none() {
        assert_eq!(RepoMode::from_mode_str("bogus"), None);
    }
}
