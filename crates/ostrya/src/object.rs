//! The size caps of loose objects.
//!
//! A metadata read stops at the metadata cap of the format, 128 MiB
//! ([`MAX_METADATA_SIZE`]), so a malformed object cannot use all memory.

pub use ostrya_core::MAX_METADATA_SIZE;

/// The maximum size of the framed file header of a content object.
///
/// A reader loads a header up to this size. The limit applies to the archive
/// form on disk and to the same framing that arrives over HTTP.
///
/// A header holds the uid, the gid, the mode, the rdev, a symlink target, and
/// the xattr array. A typical header is a few hundred bytes. A header with
/// large xattrs is a few kilobytes. Linux limits one xattr value to 64 KiB, so
/// 1 MiB holds a header with many of them.
///
/// The limit is much less than [`MAX_METADATA_SIZE`] (128 MiB) for two reasons:
///
/// - The header length comes from the object stream.
/// - The receive path holds one header buffer for each fetch in flight.
pub(crate) const MAX_FILE_HEADER_SIZE: u64 = 1024 * 1024;
