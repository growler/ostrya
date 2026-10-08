//! The error type of the format primitives.
//!
//! This module implements `Display` and `std::error::Error` by hand, as
//! `ostrya-gvariant` does, so this crate needs no derive dependency. The
//! `ostrya` crate wraps this type in its own error, which uses `thiserror`.

use std::fmt;

/// An error of the format primitives.
///
/// Each fallible function of this crate returns it, except
/// [`commit_timestamp`](crate::commit_timestamp). The I/O trait methods of
/// [`DeflateSink`](crate::DeflateSink) and
/// [`DeflateReader`](crate::DeflateReader) return [`std::io::Error`]. Most
/// variants hold a fixed message that names the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// An encode or decode error of the GVariant codec.
    Gvariant(ostrya_gvariant::Error),
    /// A checksum in hex, base64, or byte form that is not valid.
    InvalidChecksum(&'static str),
    /// A base64 string with an invalid character or a truncated group.
    InvalidBase64(&'static str),
    /// An object-type number that names no known type.
    InvalidObjectType(u32),
    /// A LEB128 varint that is truncated, overflows 64 bits, or is not minimal.
    InvalidVarint(&'static str),
    /// An xattr set with a name that is not valid.
    ///
    /// The name is empty, a duplicate, out of sort order, or has a missing
    /// terminating NUL or an interior NUL.
    InvalidXattrs(&'static str),
    /// An `ostree.sizes` entry that is too short or has trailing bytes.
    InvalidSizeEntry(&'static str),
    /// A key file error.
    ///
    /// These are the causes:
    ///
    /// - The text does not parse.
    /// - A value does not convert to the requested type.
    /// - A set refuses a group name, a key, or a value.
    KeyFile(String),
    /// A commit object with a parent or root checksum of an invalid length.
    InvalidCommit(&'static str),
    /// A dirtree object that breaks an entry rule.
    ///
    /// These are the causes:
    ///
    /// - An entry name is not valid.
    /// - An entry checksum is not 32 bytes.
    /// - The names are not sorted.
    /// - A name is in both the file and directory lists.
    InvalidDirTree(&'static str),
    /// A dirmeta object with a mode that is not a directory mode.
    InvalidDirMeta(&'static str),
    /// A file header or a framed content stream that is not valid.
    ///
    /// The header has a nonzero rdev, a mode that is not a regular file or a
    /// symlink, or a regular file with a symlink target. The framed stream is
    /// too short, has nonzero padding, or has a header length out of bounds.
    /// A header that is longer than the framing length limit also gives this
    /// error.
    InvalidFileHeader(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Gvariant(e) => write!(f, "gvariant: {e}"),
            Error::InvalidChecksum(reason) => write!(f, "invalid checksum: {reason}"),
            Error::InvalidBase64(reason) => write!(f, "invalid base64: {reason}"),
            Error::InvalidObjectType(v) => write!(f, "invalid object type tag {v}"),
            Error::InvalidVarint(reason) => write!(f, "invalid varint: {reason}"),
            Error::InvalidXattrs(reason) => write!(f, "invalid xattrs: {reason}"),
            Error::InvalidSizeEntry(reason) => write!(f, "invalid ostree.sizes entry: {reason}"),
            Error::KeyFile(reason) => write!(f, "keyfile: {reason}"),
            Error::InvalidCommit(reason) => write!(f, "invalid commit: {reason}"),
            Error::InvalidDirTree(reason) => write!(f, "invalid dirtree: {reason}"),
            Error::InvalidDirMeta(reason) => write!(f, "invalid dirmeta: {reason}"),
            Error::InvalidFileHeader(reason) => write!(f, "invalid file header: {reason}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Gvariant(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ostrya_gvariant::Error> for Error {
    fn from(e: ostrya_gvariant::Error) -> Self {
        Error::Gvariant(e)
    }
}

/// The result type of the format primitives.
pub type Result<T> = std::result::Result<T, Error>;
