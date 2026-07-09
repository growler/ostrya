//! Object types.
//!
//! The numeric values are wire-significant: they appear in the `(su)`
//! object-name serialization and in the `ostree.sizes` packed entries. The
//! `is-meta` predicate (types 2..=6) drives the checksum rules. The `z`
//! loose-path suffix applies only to a `File` object in archive mode
//! (`.filez`); the auxiliary non-meta objects (`payload-link`, `file-xattrs`,
//! `file-xattrs-link`) are stored uncompressed and carry no suffix.

use crate::error::{Error, Result};
use crate::mode::RepoMode;

/// A repository object type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ObjectType {
    /// Content: a file header plus payload (`.file` / `.filez`).
    File = 1,
    /// Sorted lists of child files and subdirs (`.dirtree`).
    DirTree = 2,
    /// Directory uid/gid/mode/xattrs (`.dirmeta`).
    DirMeta = 3,
    /// Commit metadata plus root tree/meta references (`.commit`).
    Commit = 4,
    /// Marks a deleted commit (`.tombstone-commit`).
    TombstoneCommit = 5,
    /// Detached, mutable commit metadata (`.commitmeta`).
    CommitMeta = 6,
    /// Symlink to a `.file`, keyed by payload-only checksum (`.payload-link`).
    PayloadLink = 7,
    /// Detached xattrs blob (`.file-xattrs`).
    FileXattrs = 8,
    /// Hardlink to a `.file-xattrs`, keyed by the `.file` checksum
    /// (`.file-xattrs-link`).
    FileXattrsLink = 9,
    /// Port extension: raw file payload, keyed by `SHA256(payload)`
    /// (`.fileb`), used in bare-user-split-attrs mode.
    FileBlob = 10,
}

impl ObjectType {
    /// The wire-significant numeric tag.
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// Recover the type from its numeric tag.
    pub fn from_u32(v: u32) -> Result<ObjectType> {
        Ok(match v {
            1 => ObjectType::File,
            2 => ObjectType::DirTree,
            3 => ObjectType::DirMeta,
            4 => ObjectType::Commit,
            5 => ObjectType::TombstoneCommit,
            6 => ObjectType::CommitMeta,
            7 => ObjectType::PayloadLink,
            8 => ObjectType::FileXattrs,
            9 => ObjectType::FileXattrsLink,
            10 => ObjectType::FileBlob,
            _ => return Err(Error::InvalidObjectType(v)),
        })
    }

    /// The is-meta predicate: types 2..=6. Metadata objects are stored
    /// uncompressed and never carry the `z` suffix.
    pub fn is_meta(self) -> bool {
        matches!(
            self,
            ObjectType::DirTree
                | ObjectType::DirMeta
                | ObjectType::Commit
                | ObjectType::TombstoneCommit
                | ObjectType::CommitMeta
        )
    }

    /// The loose-path extension (without the leading dot) for this type in the
    /// given mode. Mode-aware for `File`: `file` (bare family), `filez`
    /// (archive), or `filea` (bare-user-split-attrs).
    pub fn extension(self, mode: RepoMode) -> &'static str {
        match self {
            ObjectType::File => match mode {
                RepoMode::Archive => "filez",
                RepoMode::BareUserSplitAttrs => "filea",
                RepoMode::Bare
                | RepoMode::BareUser
                | RepoMode::BareUserOnly
                | RepoMode::BareSplitXattrs => "file",
            },
            ObjectType::DirTree => "dirtree",
            ObjectType::DirMeta => "dirmeta",
            ObjectType::Commit => "commit",
            ObjectType::TombstoneCommit => "tombstone-commit",
            ObjectType::CommitMeta => "commitmeta",
            ObjectType::PayloadLink => "payload-link",
            ObjectType::FileXattrs => "file-xattrs",
            ObjectType::FileXattrsLink => "file-xattrs-link",
            ObjectType::FileBlob => "fileb",
        }
    }

    /// Recover the type from a loose-path extension (without the leading dot),
    /// or `None` for an unrecognized extension. The inverse of
    /// [`extension`](Self::extension): the three mode-specific `File`
    /// spellings (`file`, `filez`, `filea`) all map back to `File`.
    pub fn from_extension(ext: &str) -> Option<ObjectType> {
        Some(match ext {
            "file" | "filez" | "filea" => ObjectType::File,
            "dirtree" => ObjectType::DirTree,
            "dirmeta" => ObjectType::DirMeta,
            "commit" => ObjectType::Commit,
            "tombstone-commit" => ObjectType::TombstoneCommit,
            "commitmeta" => ObjectType::CommitMeta,
            "payload-link" => ObjectType::PayloadLink,
            "file-xattrs" => ObjectType::FileXattrs,
            "file-xattrs-link" => ObjectType::FileXattrsLink,
            "fileb" => ObjectType::FileBlob,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_tags_round_trip() {
        for v in 1..=10u32 {
            assert_eq!(ObjectType::from_u32(v).unwrap().as_u32(), v);
        }
        assert!(matches!(
            ObjectType::from_u32(0),
            Err(Error::InvalidObjectType(0))
        ));
        assert!(matches!(
            ObjectType::from_u32(11),
            Err(Error::InvalidObjectType(11))
        ));
    }

    #[test]
    fn is_meta_covers_two_through_six() {
        for v in 1..=10u32 {
            let ty = ObjectType::from_u32(v).unwrap();
            assert_eq!(ty.is_meta(), (2..=6).contains(&v), "type {v}");
        }
    }

    #[test]
    fn file_extension_is_mode_aware() {
        assert_eq!(ObjectType::File.extension(RepoMode::Bare), "file");
        assert_eq!(ObjectType::File.extension(RepoMode::BareUser), "file");
        assert_eq!(ObjectType::File.extension(RepoMode::Archive), "filez");
        assert_eq!(
            ObjectType::File.extension(RepoMode::BareUserSplitAttrs),
            "filea"
        );
    }

    #[test]
    fn metadata_extension_is_mode_independent() {
        for mode in [RepoMode::Bare, RepoMode::Archive] {
            assert_eq!(ObjectType::DirTree.extension(mode), "dirtree");
            assert_eq!(ObjectType::Commit.extension(mode), "commit");
        }
    }

    #[test]
    fn from_extension_inverts_extension() {
        let modes = [
            RepoMode::Bare,
            RepoMode::BareUser,
            RepoMode::BareUserOnly,
            RepoMode::BareSplitXattrs,
            RepoMode::Archive,
            RepoMode::BareUserSplitAttrs,
        ];
        for v in 1..=10u32 {
            let ty = ObjectType::from_u32(v).unwrap();
            for mode in modes {
                assert_eq!(ObjectType::from_extension(ty.extension(mode)), Some(ty));
            }
        }
        // The mode-specific File spellings all recover File.
        assert_eq!(ObjectType::from_extension("filea"), Some(ObjectType::File));
        assert_eq!(ObjectType::from_extension("filez"), Some(ObjectType::File));
        assert_eq!(ObjectType::from_extension("unknown"), None);
        assert_eq!(ObjectType::from_extension(""), None);
    }
}
