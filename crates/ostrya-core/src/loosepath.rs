//! Loose object path derivation.
//!
//! A loose object lives at `<first 2 hex>/<remaining 62 hex>.<ext>` relative to
//! the repository `objects/` directory. The extension comes from the object
//! type and mode (see [`ObjectType::extension`]); metadata objects never carry
//! the compression suffix.

use crate::checksum::Checksum;
use crate::mode::RepoMode;
use crate::objtype::ObjectType;

/// The loose path of an object relative to the `objects/` directory, for
/// example `10/7500...c7983.dirtree`.
pub fn loose_path(checksum: &Checksum, ty: ObjectType, mode: RepoMode) -> String {
    let hex = checksum.to_hex();
    format!("{}/{}.{}", &hex[..2], &hex[2..], ty.extension(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_fanout_and_selects_extension() {
        let c =
            Checksum::from_hex("b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89")
                .unwrap();
        assert_eq!(
            loose_path(&c, ObjectType::Commit, RepoMode::Archive),
            "b3/c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89.commit"
        );
        // Archive content objects carry the z suffix; bare do not.
        assert_eq!(
            loose_path(&c, ObjectType::File, RepoMode::Archive),
            "b3/c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89.filez"
        );
        assert_eq!(
            loose_path(&c, ObjectType::File, RepoMode::BareUser),
            "b3/c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89.file"
        );
    }
}
