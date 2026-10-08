//! The error type of the signing engines.

/// The result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The error of a signing engine or a verifying engine.
///
/// Code outside this crate can make each variant. As a result, a [`Signer`]
/// or a [`Verifier`] of another crate can return [`Error::Signature`].
///
/// [`Signer`]: crate::Signer
/// [`Verifier`]: crate::Verifier
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A failure of key material, of a key source, or of an engine.
    ///
    /// The variant covers these conditions:
    ///
    /// - An engine refuses a key or a signature blob. Examples are a key of
    ///   the wrong length, a public key that is not a valid curve point, and a
    ///   malformed secret key.
    /// - A key source cannot be read, or a key reader of this crate refuses
    ///   it.
    /// - A signer or a verifier fails.
    #[error("signature: {0}")]
    Signature(String),
    /// A detached-metadata dict that [`append_signature`] cannot change.
    ///
    /// The value is not an `a{sv}` dict, or the signature value of the engine
    /// in it is not an array.
    ///
    /// [`append_signature`]: crate::append_signature
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    /// An [`ostrya_core::Error`], for example from a base64 decode.
    #[error(transparent)]
    Core(#[from] ostrya_core::Error),
}
