//! The library error type.
//!
//! One `Error` enum for the whole crate, deriving `Display` and
//! `std::error::Error` via `thiserror`. The enum is `#[non_exhaustive]` because
//! later phases add variants (object not-found, checksum mismatch, signature,
//! lock, and so on).

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
    /// On-disk data did not match the expected format.
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    /// A requested operation or repository feature is not supported.
    #[error("unsupported: {0}")]
    Unsupported(String),
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
