#![forbid(unsafe_code)]

//! The object model and the on-disk format primitives of ostree.
//!
//! A caller reads and writes the objects of an ostree repository as bytes in
//! the on-disk format and computes their checksums. The crate also holds the
//! format rules for loose paths, ref names, and new commits. It re-exports the
//! GVariant codec of `ostrya-gvariant` for the metadata of a commit. The crate
//! compiles on Linux, macOS, and Windows.
//!
//! # Entry points
//!
//! - [`Checksum`] is the SHA-256 id of an object.
//! - [`Commit`] reads and writes a commit object.
//! - [`DirTree`] and [`DirMeta`] read and write the objects of a directory.
//! - [`FileHeader`] is the header of a content object.
//! - [`Xattrs`] is a sorted set of extended attributes.
//! - [`ObjectType`] and [`RepoMode`] select the [`loose_path`] of an object.
//! - [`DeflateSink`] compresses the payload of an archive-mode content object.
//! - [`KeyFile`] reads and writes the repository `config` file.
//!
//! # Modules
//!
//! - [`base64`]: standard base64 for byte strings of any length.
//! - [`filehdr`]: the content-object header, its framing, and its checksum.
//! - [`sizes`]: the packed entries of the `ostree.sizes` commit metadata.
//! - [`varint`]: the LEB128 varints of the format.
//!
//! # Examples
//!
//! ```
//! use ostrya_core::{Checksum, DirMeta, ObjectType, RepoMode, Xattrs, loose_path};
//!
//! // The root directory of a commit: uid 0, gid 0, mode 0755, no xattrs.
//! let meta = DirMeta { uid: 0, gid: 0, mode: 0o040755, xattrs: Xattrs::empty() };
//! let checksum = Checksum::sha256(&meta.serialize()?);
//! let hex = "446a0ef11b7cc167f3b603e585c7eeeeb675faa412d5ec73f62988eb0b6c5488";
//! assert_eq!(checksum.to_hex(), hex);
//! let path = loose_path(&checksum, ObjectType::DirMeta, RepoMode::Bare);
//! assert_eq!(path, format!("44/{}.dirmeta", &hex[2..]));
//! # Ok::<(), ostrya_core::Error>(())
//! ```

pub mod base64;
mod be;
mod checksum;
mod commit;
mod deflate;
mod dirmeta;
mod dirtree;
mod error;
pub mod filehdr;
mod keyfile;
mod loosepath;
mod mode;
mod objname;
mod objtype;
mod refname;
pub mod sizes;
mod valiter;
pub mod varint;
mod xattr;

pub use checksum::Checksum;
pub use commit::{
    Commit, CommitLink, TimestampError, commit_metadata, commit_timestamp, ref_binding,
};
pub use deflate::{DeflateReader, DeflateSink};
pub use dirmeta::{DirMeta, DirMetaRef};
pub use dirtree::{DirTree, DirTreeRef};
pub use error::{Error, Result};
#[doc(hidden)]
pub use filehdr::{ContentHasher, FileHeader};
pub use keyfile::KeyFile;
pub use loosepath::loose_path;
pub use mode::RepoMode;
pub use objname::ObjectName;
pub use objtype::ObjectType;
pub use refname::{is_checksum_shaped, is_ref_component, is_ref_name, is_refspec};
pub use xattr::{Xattrs, XattrsRef};

// The dynamic GVariant value tree and the codec functions. `Commit::metadata`
// is a `Value`. With these re-exports, a dependent crate can read and write
// any metadata dict with no direct dependency on `ostrya-gvariant`.
#[doc(no_inline)]
pub use ostrya_gvariant::{
    ArrayIter, DictBuilder, GvDecode, GvEncode, GvType, Span, TextError, Type, Value, VariantBytes,
    choose_offset_size, from_bytes, from_text, offset_size_for, to_bytes, to_text,
    to_text_unannotated, tuple_field_from_bytes, validate, write_array, write_offset,
};

/// The size limit of a metadata object: 128 MiB.
///
/// The format sets this limit. A reader loads a metadata object whole, so it
/// must refuse a larger object.
pub const MAX_METADATA_SIZE: u64 = 128 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use ostrya_gvariant::{GvType, Type};

    use crate::{Checksum, Commit, DirMeta, DirTree, FileHeader};

    /// Checks that the `ALIGNMENT` and `FIXED_SIZE` constants of an object
    /// type match the values that its signature gives.
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
