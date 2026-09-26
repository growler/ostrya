//! The engine-agnostic signing surface.

use std::future::Future;
use std::pin::Pin;

use crate::Result;

/// The future returned by [`Signer::sign`]. A boxed future keeps `Signer`
/// dyn-compatible, so `Repo::sign_commit` can take `&dyn Signer`; each engine
/// decides internally whether to offload heavy work to the blocking pool.
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;

/// The future returned by [`Verifier::verify`]. A boxed future keeps `Verifier`
/// dyn-compatible, so `Repo::verify_commit` can take `&dyn Verifier`; an
/// engine that delegates to an external helper awaits it internally, while the
/// in-process engines resolve immediately.
pub type VerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<VerifyOutcome>> + Send + 'a>>;

/// An engine that produces a detached signature over an opaque payload.
pub trait Signer: Send + Sync {
    /// The engine's short name (`"ed25519"`, `"spki"`, `"gpg"`, `"dummy"`).
    fn name(&self) -> &str;

    /// The detached-metadata dict key the engine's signatures accumulate under
    /// (for example `"ostree.sign.dummy"`).
    fn metadata_key(&self) -> &str;

    /// Sign `data`, yielding one signature blob.
    fn sign<'a>(&'a self, data: &'a [u8]) -> SignFuture<'a>;
}

/// An engine that checks detached signatures over an opaque payload.
pub trait Verifier: Send + Sync {
    /// The detached-metadata dict key whose `aay` value holds the blobs this
    /// verifier consumes.
    fn metadata_key(&self) -> &str;

    /// Verify `signatures` against `data`. The outcome is valid when at least
    /// one blob verifies; the per-signature detail is reported in
    /// [`VerifyOutcome::signatures`].
    fn verify<'a>(&'a self, data: &'a [u8], signatures: &'a [Vec<u8>]) -> VerifyFuture<'a>;
}

/// The result of verifying a payload against one or more engines.
#[derive(Debug, Clone, Default)]
pub struct VerifyOutcome {
    /// Whether at least one signature verified.
    pub valid: bool,
    /// One entry per signature blob examined, in the order examined.
    pub signatures: Vec<SignatureInfo>,
}

/// Per-signature detail. The fields mirror the documented GPG verify result;
/// engines without a notion of a field leave it unset.
#[derive(Debug, Clone, Default)]
pub struct SignatureInfo {
    /// Whether this signature verified.
    pub valid: bool,
    /// The signing key fingerprint, when the engine exposes one.
    pub fingerprint: Option<String>,
    /// The primary-key fingerprint of the signer's certificate, when the
    /// signing key is a subkey (GPG). Equal to [`fingerprint`](Self::fingerprint)
    /// when the primary key signed.
    pub primary_fingerprint: Option<String>,
    /// The signature creation time (seconds since the Unix epoch), when known.
    pub created: Option<u64>,
    /// The signature expiry time (seconds since the Unix epoch), when the
    /// signature carries one.
    pub expires: Option<u64>,
    /// The signing key's expiry time (seconds since the Unix epoch), when the
    /// key carries one and it has passed.
    pub key_expires: Option<u64>,
    /// Whether the signing key had expired.
    pub expired: bool,
    /// Whether the signing key was revoked.
    pub revoked: bool,
    /// Whether the signing key was absent from the trusted set.
    pub key_missing: bool,
    /// The public-key algorithm name, when the engine exposes one (GPG).
    pub pubkey_algorithm: Option<String>,
    /// The digest algorithm name, when the engine exposes one (GPG).
    pub hash_algorithm: Option<String>,
    /// The signer's user name, when the engine exposes one.
    pub user_name: Option<String>,
    /// The signer's user email, when the engine exposes one.
    pub user_email: Option<String>,
}
