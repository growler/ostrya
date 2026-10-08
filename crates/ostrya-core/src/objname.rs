//! The name of an object: a checksum and an object type.
//!
//! Traversal, prune, and fsck use sets of object names, so the checksum and the
//! type of a loose object stay together.

use crate::checksum::Checksum;
use crate::loosepath::loose_path;
use crate::mode::RepoMode;
use crate::objtype::ObjectType;

/// A checksum and the type of the object that it identifies.
///
/// The [`Display`](std::fmt::Display) form is `<hexchecksum>.<typestr>`. The
/// `ostree` command prints an object reference in this form. The type string
/// comes from [`ObjectType::type_str`] and does not depend on the repository
/// mode. In archive mode, a content object is also `file`, and its loose path
/// has the `z` suffix that [`ObjectType::extension`] adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectName {
    /// The SHA-256 checksum of the object.
    pub checksum: Checksum,
    /// The object type.
    pub ty: ObjectType,
}

impl ObjectName {
    /// Creates an object name from a checksum and an object type.
    pub fn new(checksum: Checksum, ty: ObjectType) -> ObjectName {
        ObjectName { checksum, ty }
    }

    /// Returns the loose path of this object for a repository mode.
    ///
    /// The path is relative to the `objects/` directory and has the layout of
    /// [`loose_path`].
    pub fn loose_path(&self, mode: RepoMode) -> String {
        loose_path(&self.checksum, self.ty, mode)
    }
}

impl std::fmt::Display for ObjectName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.checksum.to_hex(), self.ty.type_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_form_uses_the_mode_independent_type() {
        let c =
            Checksum::from_hex("b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89")
                .unwrap();
        // A content object is `.file` in the string form regardless of mode.
        assert_eq!(
            ObjectName::new(c, ObjectType::File).to_string(),
            "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89.file"
        );
        assert_eq!(
            ObjectName::new(c, ObjectType::DirTree).to_string(),
            "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89.dirtree"
        );
        // The loose path is mode-aware: archive content carries the z suffix.
        assert_eq!(
            ObjectName::new(c, ObjectType::File).loose_path(RepoMode::Archive),
            "b3/c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89.filez"
        );
    }
}
