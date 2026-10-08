//! Object types and their loose-path extensions.

use crate::error::{Error, Result};
use crate::mode::RepoMode;

/// A repository object type.
///
/// The numeric value of each variant is part of the wire format. It is the
/// `u` member of the `(su)` serialization of an object name and the type byte
/// of an `ostree.sizes` entry ([`SizeEntry`](crate::sizes::SizeEntry)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ObjectType {
    /// A content object: a file header and the payload (`.file` or `.filez`).
    File = 1,
    /// The sorted lists of the files and subdirectories of a directory
    /// (`.dirtree`).
    DirTree = 2,
    /// The uid, gid, mode, and xattrs of a directory (`.dirmeta`).
    DirMeta = 3,
    /// A commit: the metadata and the root checksums (`.commit`).
    ///
    /// The root checksums name the root dirtree and the root dirmeta.
    Commit = 4,
    /// A marker of a deleted commit (`.tombstone-commit`).
    TombstoneCommit = 5,
    /// The detached metadata of a commit (`.commitmeta`).
    ///
    /// It can change after the commit.
    CommitMeta = 6,
    /// A symlink to a `.file` object (`.payload-link`).
    ///
    /// Its name is the checksum of the payload only.
    PayloadLink = 7,
    /// A detached xattrs blob (`.file-xattrs`).
    FileXattrs = 8,
    /// A hardlink to a `.file-xattrs` object (`.file-xattrs-link`).
    ///
    /// Its name is the checksum of the `.file` object.
    FileXattrsLink = 9,
}

impl ObjectType {
    /// Returns the numeric value of the type, as the wire format writes it.
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// Returns the type of a numeric value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidObjectType`] if `v` is not in the range 1 to 9.
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
            _ => return Err(Error::InvalidObjectType(v)),
        })
    }

    /// Returns `true` if the type is a metadata type.
    ///
    /// The metadata types are [`DirTree`](Self::DirTree),
    /// [`DirMeta`](Self::DirMeta), [`Commit`](Self::Commit),
    /// [`TombstoneCommit`](Self::TombstoneCommit), and
    /// [`CommitMeta`](Self::CommitMeta), with the numeric values `2..=6`. The
    /// checksum rules of an object depend on this property. A metadata object
    /// is stored uncompressed, and its loose path never has the `z` suffix.
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

    /// Returns the loose-path extension of the type in `mode`.
    ///
    /// The extension has no leading dot. The extension of a
    /// [`File`](Self::File) object depends on the mode. It is `filez` in
    /// archive mode and `file` in each bare mode. The `z` suffix occurs only
    /// on a `File` object in archive mode.
    ///
    /// The extensions of the other types do not depend on the mode. The
    /// non-metadata types `payload-link`, `file-xattrs`, and
    /// `file-xattrs-link` are stored uncompressed and have no `z` suffix.
    pub fn extension(self, mode: RepoMode) -> &'static str {
        match self {
            ObjectType::File => match mode {
                RepoMode::Archive => "filez",
                RepoMode::Bare
                | RepoMode::BareUser
                | RepoMode::BareUserOnly
                | RepoMode::BareSplitXattrs
                | RepoMode::BareUserShared => "file",
            },
            ObjectType::DirTree => "dirtree",
            ObjectType::DirMeta => "dirmeta",
            ObjectType::Commit => "commit",
            ObjectType::TombstoneCommit => "tombstone-commit",
            ObjectType::CommitMeta => "commitmeta",
            ObjectType::PayloadLink => "payload-link",
            ObjectType::FileXattrs => "file-xattrs",
            ObjectType::FileXattrsLink => "file-xattrs-link",
        }
    }

    /// Returns the type string, as the string form of an object name uses it.
    ///
    /// The string form is `<hexchecksum>.<typestr>`. The type string does not
    /// depend on the mode. A `File` object has the type string `file`, also in
    /// archive mode, where its loose path has the `z` suffix. The `ostree`
    /// command prints the form with no `z` in its object references.
    pub fn type_str(self) -> &'static str {
        // Every extension but the archive `File` suffix is mode-independent,
        // so the bare-mode extension is the canonical type string.
        self.extension(RepoMode::Bare)
    }

    /// Returns the type of a loose-path extension.
    ///
    /// The extension has no leading dot. This function is the inverse of
    /// [`extension`](Self::extension), so both `file` and `filez` give
    /// [`File`](Self::File). If the extension is not known, the function
    /// returns `None`.
    pub fn from_extension(ext: &str) -> Option<ObjectType> {
        Some(match ext {
            "file" | "filez" => ObjectType::File,
            "dirtree" => ObjectType::DirTree,
            "dirmeta" => ObjectType::DirMeta,
            "commit" => ObjectType::Commit,
            "tombstone-commit" => ObjectType::TombstoneCommit,
            "commitmeta" => ObjectType::CommitMeta,
            "payload-link" => ObjectType::PayloadLink,
            "file-xattrs" => ObjectType::FileXattrs,
            "file-xattrs-link" => ObjectType::FileXattrsLink,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_tags_round_trip() {
        for v in 1..=9u32 {
            assert_eq!(ObjectType::from_u32(v).unwrap().as_u32(), v);
        }
        assert!(matches!(
            ObjectType::from_u32(0),
            Err(Error::InvalidObjectType(0))
        ));
        assert!(matches!(
            ObjectType::from_u32(10),
            Err(Error::InvalidObjectType(10))
        ));
    }

    #[test]
    fn is_meta_covers_two_through_six() {
        for v in 1..=9u32 {
            let ty = ObjectType::from_u32(v).unwrap();
            assert_eq!(ty.is_meta(), (2..=6).contains(&v), "type {v}");
        }
    }

    #[test]
    fn file_extension_is_mode_aware() {
        assert_eq!(ObjectType::File.extension(RepoMode::Bare), "file");
        assert_eq!(ObjectType::File.extension(RepoMode::BareUser), "file");
        assert_eq!(ObjectType::File.extension(RepoMode::BareUserShared), "file");
        assert_eq!(ObjectType::File.extension(RepoMode::Archive), "filez");
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
            RepoMode::BareUserShared,
        ];
        for v in 1..=9u32 {
            let ty = ObjectType::from_u32(v).unwrap();
            for mode in modes {
                assert_eq!(ObjectType::from_extension(ty.extension(mode)), Some(ty));
            }
        }
        // Both mode-specific File spellings recover File.
        assert_eq!(ObjectType::from_extension("filez"), Some(ObjectType::File));
        assert_eq!(ObjectType::from_extension("unknown"), None);
        assert_eq!(ObjectType::from_extension(""), None);
    }
}
