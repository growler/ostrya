//! The error type of the signing engines.

/// Result alias used throughout the `ostrya-sign` crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The error a signing or verifying engine fails with.
///
/// The enum is `#[non_exhaustive]`, so a match outside the crate needs a
/// wildcard arm. Each variant stays constructible outside the crate, so a
/// `Signer` or a `Verifier` of another crate can return
/// [`Error::Signature`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A signing engine rejected its key material or a signature blob: a
    /// wrong-length key, a public key that is not a valid curve point, or a
    /// malformed secret key. A key source that cannot be read, and a signer
    /// or a verifier that fails, report here as well.
    #[error("signature: {0}")]
    Signature(String),
    /// The detached metadata given to [`append_signature`](crate::append_signature)
    /// is not an `a{sv}` dict, or the signature value of the engine in it is
    /// not an array.
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    /// An error from the core format-primitive layer, for example from a
    /// base64 decode.
    #[error(transparent)]
    Core(#[from] ostrya_core::Error),
}
