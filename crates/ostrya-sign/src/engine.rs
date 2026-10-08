//! The engine-agnostic signing surface.

use std::future::Future;
use std::pin::Pin;

use crate::Result;

/// The boxed future that [`Signer::sign`] returns.
///
/// The future is boxed so that `Signer` stays dyn-compatible. As a result,
/// `Repo::sign_commit` of the `ostrya` crate can take `&dyn Signer`. Each
/// engine decides internally if it moves heavy work to the blocking pool.
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;

/// The boxed future that [`Verifier::verify`] returns.
///
/// The future is boxed so that `Verifier` stays dyn-compatible. As a result,
/// `Repo::verify_commit` of the `ostrya` crate can take `&dyn Verifier`. The
/// verifiers of this crate return a future that is ready at once.
pub type VerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<VerifyOutcome>> + Send + 'a>>;

/// An engine that produces a detached signature over an opaque payload.
pub trait Signer: Send + Sync {
    /// Returns the short name of the engine.
    ///
    /// The engines of this crate use the names `"ed25519"`, `"spki"`,
    /// `"gpg"`, and `"dummy"`.
    fn name(&self) -> &str;

    /// Returns the key of the engine in the detached-metadata dict.
    ///
    /// The signatures of the engine go under this key, for example
    /// `"ostree.sign.dummy"`. A caller passes the key to [`append_signature`].
    ///
    /// [`append_signature`]: crate::append_signature
    fn metadata_key(&self) -> &str;

    /// Signs `data` and returns one signature blob.
    ///
    /// For a commit, `data` is the serialized commit object. These bytes are
    /// the normal-form GVariant bytes that give the commit checksum.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if the engine cannot make a signature.
    ///
    /// The dummy, ed25519, and spki engines never return an error. The
    /// `GpgSigner` type states its failure conditions.
    ///
    /// [`Error::Signature`]: crate::Error::Signature
    fn sign<'a>(&'a self, data: &'a [u8]) -> SignFuture<'a>;
}

/// An engine that checks detached signatures over an opaque payload.
pub trait Verifier: Send + Sync {
    /// Returns the key in the detached-metadata dict that holds the signatures.
    ///
    /// The value of this key is an `aay`, and each `ay` element is one
    /// signature blob for this verifier.
    fn metadata_key(&self) -> &str;

    /// Verifies the blobs in `signatures` against `data`.
    ///
    /// The outcome is valid if at least one blob verifies. The outcome holds
    /// one [`SignatureInfo`] for each blob in [`VerifyOutcome::signatures`].
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if the engine cannot do the verification.
    ///
    /// The dummy, ed25519, and spki engines never return an error. A blob that
    /// does not verify is an entry with `valid` set to `false` in the outcome.
    ///
    /// [`Error::Signature`]: crate::Error::Signature
    fn verify<'a>(&'a self, data: &'a [u8], signatures: &'a [Vec<u8>]) -> VerifyFuture<'a>;
}

/// The result of the verification of a payload.
#[derive(Debug, Clone, Default)]
pub struct VerifyOutcome {
    /// `true` if at least one signature verified.
    ///
    /// [`Verifier::verify`] states the rule.
    pub valid: bool,
    /// One entry for each signature blob, in the order of the blobs.
    pub signatures: Vec<SignatureInfo>,
}

/// The result of the verification of one signature.
///
/// The fields mirror the documented GPG verify result. If an engine has no
/// value for a field, it leaves the field unset.
#[derive(Debug, Clone, Default)]
pub struct SignatureInfo {
    /// `true` if this signature verified.
    pub valid: bool,
    /// The fingerprint of the signing key, if the engine gives one.
    pub fingerprint: Option<String>,
    /// The fingerprint of the primary key of the certificate of the signer.
    ///
    /// If a subkey made the signature (GPG), this is the fingerprint of the
    /// primary key of the subkey. If the primary key made the signature, this
    /// value is equal to [`fingerprint`](Self::fingerprint).
    pub primary_fingerprint: Option<String>,
    /// The creation time of the signature in seconds since the Unix epoch.
    ///
    /// The value is `None` if the engine does not know the time.
    pub created: Option<u64>,
    /// The expiry time of the signature in seconds since the Unix epoch.
    ///
    /// The value is `None` if the signature has no expiry time.
    pub expires: Option<u64>,
    /// The expiry time of the signing key in seconds since the Unix epoch.
    ///
    /// An engine sets the value only if the key has an expiry time and this time
    /// is in the past.
    pub key_expires: Option<u64>,
    /// `true` if the signing key is expired.
    pub expired: bool,
    /// `true` if the signing key is revoked.
    pub revoked: bool,
    /// `true` if the signing key is not in the trusted set.
    ///
    /// The dummy, ed25519, and spki verifiers set this field to the opposite
    /// of [`valid`](Self::valid) for each blob. This also applies to a
    /// malformed blob.
    pub key_missing: bool,
    /// The name of the public-key algorithm, if the engine gives one (GPG).
    pub pubkey_algorithm: Option<String>,
    /// The name of the digest algorithm, if the engine gives one (GPG).
    pub hash_algorithm: Option<String>,
    /// The user name of the signer, if the engine gives one.
    pub user_name: Option<String>,
    /// The email address of the signer, if the engine gives one.
    pub user_email: Option<String>,
}
