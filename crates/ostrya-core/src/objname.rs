//! An object name: a checksum paired with its object type.
//!
//! Reachability traversal, prune, and fsck work over sets of object names, so
//! the two coordinates that identify a loose object travel together. The string
//! form is `<hexchecksum>.<typestr>` (the tool's object reference), where the
//! type string is mode-independent -- a content object is `file` even in
//! archive mode, where its loose path carries the `z` suffix.

use crate::checksum::Checksum;
use crate::loosepath::loose_path;
use crate::mode::RepoMode;
use crate::objtype::ObjectType;

/// A checksum together with the object type it identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectName {
    /// The object's SHA-256 identity.
    pub checksum: Checksum,
    /// The object type.
    pub ty: ObjectType,
}

impl ObjectName {
    /// Pair a checksum with its type.
    pub fn new(checksum: Checksum, ty: ObjectType) -> ObjectName {
        ObjectName { checksum, ty }
    }

    /// The loose path of this object relative to `objects/`, for the given
    /// repository mode.
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
