//! The error type for the format-primitive layer.
//!
//! Hand-rolled with a manual [`Display`] and [`std::error::Error`] impl, the
//! same style as the sibling `ostrya-gvariant` crate, so this crate pulls in
//! no derive dependency. The higher-level `ostrya` crate wraps these in its
//! own `thiserror`-based error.

use std::fmt;

/// Errors produced by the core format primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A GVariant (de)serialization error from the codec layer.
    Gvariant(ostrya_gvariant::Error),
    /// A checksum string or byte sequence was malformed.
    InvalidChecksum(&'static str),
    /// An object-type numeric tag did not name a known type.
    InvalidObjectType(u32),
    /// A LEB128 varint was truncated or overflowed 64 bits.
    InvalidVarint(&'static str),
    /// An xattr set failed validation (empty, duplicate, or unsorted name).
    InvalidXattrs(&'static str),
    /// An `ostree.sizes` entry was malformed.
    InvalidSizeEntry(&'static str),
    /// A GKeyFile/INI document or a typed lookup was malformed.
    KeyFile(String),
    /// A commit object violated a value-level convention.
    InvalidCommit(&'static str),
    /// A dirtree object violated a value-level convention (bad file name,
    /// checksum length, or sort order).
    InvalidDirTree(&'static str),
    /// A dirmeta object violated a value-level convention.
    InvalidDirMeta(&'static str),
    /// A file content-object header violated a value-level convention
    /// (nonzero rdev, non-REG/non-LNK mode, or a malformed blob reference).
    InvalidFileHeader(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Gvariant(e) => write!(f, "gvariant: {e}"),
            Error::InvalidChecksum(reason) => write!(f, "invalid checksum: {reason}"),
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

/// Result alias for the core format primitives.
pub type Result<T> = std::result::Result<T, Error>;
