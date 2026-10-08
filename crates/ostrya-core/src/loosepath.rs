//! The loose path of an object.

use crate::checksum::Checksum;
use crate::mode::RepoMode;
use crate::objtype::ObjectType;

/// Returns the loose path of an object for a repository mode.
///
/// The path is relative to the `objects/` directory of the repository. Its
/// layout is `<first 2 hex>/<remaining 62 hex>.<ext>`, for example
/// `10/7500...c7983.dirtree`.
///
/// [`ObjectType::extension`] gives the extension for the object type and the
/// mode. A metadata object never has the compression suffix `z`.
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
        // A content object has the z suffix in archive mode. In a bare mode it
        // has no suffix.
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
