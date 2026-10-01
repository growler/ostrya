#![forbid(unsafe_code)]

//! ostree object model, checksums, and on-disk format primitives.
//!
//! Builds on the ostrya-gvariant codec to serialize and parse commits,
//! dirtrees, dirmeta, and file headers, and provides the checksum type, LEB128
//! varint, loose-path derivation, `ostree.sizes` packing, and xattr
//! canonicalization.
//!
//! The crate also holds the rules a new commit is built by: the raw-DEFLATE
//! encoder of archive-mode content objects ([`DeflateSink`], and
//! [`DeflateReader`] over a source), the commit metadata rule
//! ([`commit_metadata`]), the commit timestamp rule ([`commit_timestamp`]),
//! the ref-name rule ([`is_refspec`]), and the metadata size cap
//! ([`MAX_METADATA_SIZE`]).
//! It compiles on Linux, macOS, and Windows.
//!
//! This crate covers phases 2 and 3 of the port plan (see
//! `docs/port-plan.md`): the format primitives (checksum, varint, loose
//! paths, sizes, xattrs, keyfile) and the typed object structs (commit,
//! dirtree, dirmeta, file headers) with their borrowed read-path views.

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
pub use filehdr::{ContentHasher, FileHeader};
pub use keyfile::KeyFile;
pub use loosepath::loose_path;
pub use mode::RepoMode;
pub use objname::ObjectName;
pub use objtype::ObjectType;
pub use refname::{is_ref_component, is_ref_name, is_refspec};
pub use xattr::{Xattrs, XattrsRef};

// The dynamic GVariant value tree and its codec entry points. `Commit::metadata`
// is a `Value`, so consuming crates need these to inspect, load, and serialize
// arbitrary metadata dicts without depending on `ostrya-gvariant` directly.
pub use ostrya_gvariant::{
    ArrayIter, DictBuilder, GvDecode, GvType, Span, TextError, Type, Value, VariantBytes,
    choose_offset_size, from_bytes, from_text, offset_size_for, to_bytes, to_text,
    to_text_unannotated, tuple_field_from_bytes, validate, write_offset,
};

/// The largest metadata object the port loads: 128 MiB, the metadata cap of
/// the format. A metadata object is read whole, so every reader of one holds
/// this bound.
pub const MAX_METADATA_SIZE: u64 = 128 * 1024 * 1024;

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
