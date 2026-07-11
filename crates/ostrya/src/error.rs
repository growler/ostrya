//! The library error type.
//!
//! One `Error` enum for the whole crate, deriving `Display` and
//! `std::error::Error` via `thiserror`. The enum is `#[non_exhaustive]` because
//! later phases add variants (object not-found, checksum mismatch, signature,
//! lock, and so on).

use ostrya_core::{Checksum, ObjectType};
use thiserror::Error;

/// Result alias used throughout the `ostrya` crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The single error type for the library.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An underlying I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// An error from the core format-primitive layer (checksums, keyfile
    /// parsing, object model).
    #[error(transparent)]
    Core(#[from] ostrya_core::Error),
    /// A referenced object is not present in the store.
    #[error("object not found: {ty:?} {checksum}")]
    ObjectNotFound {
        /// The object identity that was looked up.
        checksum: Checksum,
        /// The object type that was looked up.
        ty: ObjectType,
    },
    /// A refspec did not resolve to a commit.
    #[error("ref not found: {0}")]
    RefNotFound(String),
    /// On-disk data did not match the expected format.
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    /// A requested operation or repository feature is not supported.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Acquiring the repository lock timed out under contention.
    #[error("timed out acquiring repository lock after {secs}s")]
    LockTimeout {
        /// The configured lock-acquisition timeout, in seconds.
        secs: i64,
    },
    /// A written object's computed checksum did not match the caller's
    /// expected value.
    #[error("checksum mismatch: expected {expected}, computed {actual}")]
    ChecksumMismatch {
        /// The checksum the caller asserted the object would have.
        expected: Checksum,
        /// The checksum the write path actually computed.
        actual: Checksum,
    },
    /// Staging an object would drop free space below the configured
    /// `min-free-space-percent` / `min-free-space-size` reserve.
    #[error("insufficient free space: short by {shortfall} bytes")]
    InsufficientFreeSpace {
        /// How many more bytes of free space the write would have needed.
        shortfall: u64,
    },
}

impl From<rustix::io::Errno> for Error {
    fn from(errno: rustix::io::Errno) -> Error {
        Error::Io(errno.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_converts_displays_and_chains() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err: Error = io.into();
        assert!(matches!(err, Error::Io(_)));
        assert!(err.to_string().contains("i/o error"));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn format_and_unsupported_have_no_source() {
        let err = Error::InvalidFormat("bad header".into());
        assert!(err.to_string().contains("invalid format"));
        assert!(std::error::Error::source(&err).is_none());

        let err = Error::Unsupported("mode".into());
        assert!(err.to_string().contains("unsupported"));
        assert!(std::error::Error::source(&err).is_none());
    }
}
