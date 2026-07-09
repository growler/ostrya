#![forbid(unsafe_code)]

//! ostree object model, checksums, and on-disk format primitives.
//!
//! Builds on the ostrya-gvariant codec to serialize and parse commits,
//! dirtrees, dirmeta, and file headers, and provides the checksum type, LEB128
//! varint, loose-path derivation, `ostree.sizes` packing, and xattr
//! canonicalization.
//!
//! This crate covers phases 2 and 3 of the port plan (see
//! `docs/port-plan.md`): the format primitives (checksum, varint, loose
//! paths, sizes, xattrs, keyfile) and the typed object structs (commit,
//! dirtree, dirmeta, file headers) with their borrowed read-path views.

mod be;
mod checksum;
mod commit;
mod dirmeta;
mod dirtree;
mod error;
pub mod filehdr;
mod keyfile;
mod loosepath;
mod mode;
mod objtype;
pub mod sizes;
mod valiter;
pub mod varint;
mod xattr;

pub use checksum::Checksum;
pub use commit::Commit;
pub use dirmeta::{DirMeta, DirMetaRef};
pub use dirtree::{DirTree, DirTreeRef};
pub use error::{Error, Result};
pub use filehdr::{ContentHasher, FileHeader};
pub use keyfile::KeyFile;
pub use loosepath::loose_path;
pub use mode::RepoMode;
pub use objtype::ObjectType;
pub use xattr::{Xattrs, XattrsRef};

#[cfg(test)]
mod tests {
    use ostrya_gvariant::{GvType, Type};

    use crate::{Checksum, Commit, DirMeta, DirTree, FileHeader};

    /// The hand-stated `ALIGNMENT`/`FIXED_SIZE` of an object type must equal
    /// what its signature implies, so the two cannot silently drift.
    fn assert_pinned<T: GvType>() {
        let ty = Type::parse(T::SIGNATURE).unwrap();
        assert_eq!(
            T::ALIGNMENT,
            ty.alignment(),
            "alignment for {}",
            T::SIGNATURE
        );
        assert_eq!(
            T::FIXED_SIZE,
            ty.fixed_size(),
            "fixed size for {}",
            T::SIGNATURE
        );
    }

    #[test]
    fn object_constants_match_their_signatures() {
        assert_pinned::<Checksum>();
        assert_pinned::<FileHeader>();
        assert_pinned::<DirMeta>();
        assert_pinned::<DirTree>();
        assert_pinned::<Commit>();
    }
}
