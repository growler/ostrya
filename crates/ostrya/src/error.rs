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
    /// An in-memory tree could not be built or serialized: an invalid entry
    /// name, a file/directory name collision, a directory missing its dirmeta
    /// checksum, or removing an absent entry.
    #[error("mutable tree: {0}")]
    MutableTree(String),
    /// An overlayfs upperdir uses a feature the merge cannot honor because the
    /// entry is not self-contained (`overlay.metacopy` or `overlay.redirect`);
    /// the overlay must be mounted with that feature disabled.
    #[error("unsupported overlay feature: {0}")]
    UnsupportedOverlayFeature(String),
    /// A staging-tree path could not be resolved: a missing component, a
    /// non-directory where a directory was expected, an existing entry where a
    /// fresh one was required, or a dangling or looping symlink.
    #[error("staging tree: {0}")]
    Staging(String),
    /// A staging-tree merge hit a conflict the [`MergeOptions`](crate::MergeOptions)
    /// did not permit: differing files, a file-versus-directory clash, or
    /// differing directory metadata, without `allow_overwrite`.
    #[error("merge conflict: {0}")]
    MergeConflict(String),
    /// A checkout could not proceed: a collision under
    /// [`OverwriteMode::None`](crate::OverwriteMode::None), a
    /// [`UnionIdentical`](crate::OverwriteMode::UnionIdentical) mismatch, a
    /// missing subpath, or an unsupported combination of options.
    #[error("checkout: {0}")]
    Checkout(String),
    /// A tar import or export could not proceed: an entry type ostree cannot
    /// store (a device node or FIFO), a path with a `..` component, a hardlink
    /// with no target in the archive, or a non-UTF-8 xattr name.
    #[error("tar: {0}")]
    Tar(String),
    /// A signing engine rejected its key material or a signature blob: a
    /// wrong-length key, a public key that is not a valid curve point, or a
    /// malformed secret key.
    #[error("signature: {0}")]
    Signature(String),
    /// A fetch could not be set up or carried out: an unusable mirror URL,
    /// header, or TLS configuration, or a transport failure that outlived its
    /// retries.
    #[error("fetch: {0}")]
    Fetch(String),
    /// Every mirror answered the request with an unsuccessful HTTP status. A
    /// 404 here means the object is absent from the remote, which pull treats
    /// as a normal answer for optional objects.
    ///
    /// One mirror's answer is reported: the first status received that is not
    /// retried, from whichever round it came, unless the rounds ran out with a
    /// retryable status outstanding, in which case the last mirror to give one.
    #[error("http status {status} for {url}")]
    HttpStatus {
        /// The status that mirror returned.
        status: u16,
        /// The URL requested of it.
        url: String,
    },
    /// A response declared more bytes than the caller's cap allows. A body that
    /// outgrows the cap while streaming fails the read with
    /// [`FileTooLarge`](std::io::ErrorKind::FileTooLarge) instead.
    #[error("fetched object exceeds the {limit}-byte cap")]
    FetchTooLarge {
        /// The cap the caller set on the request.
        limit: u64,
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
