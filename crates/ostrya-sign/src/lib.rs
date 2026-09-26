#![forbid(unsafe_code)]

//! Commit signing framework and the signing engines of ostrya.
//!
//! [`Signer`] and [`Verifier`] are the engine-agnostic surface: a signer names
//! its engine and its detached-metadata key and signs an opaque byte payload; a
//! verifier checks a set of signature blobs against a payload and reports a
//! [`VerifyOutcome`]. Both operate on opaque bytes, so the commit path and the
//! summary path share one surface.
//!
//! The signed payload for a commit is the canonical serialized commit GVariant
//! bytes -- the same normal-form bytes that hash to the commit checksum
//! (`format-reference.md`, "Signing details").
//!
//! Signatures live in the commit's detached metadata (`.commitmeta`), a bare
//! `a{sv}` dict. Each engine owns one key whose value is an `aay` (an array of
//! signature blobs); signing appends one `ay` element, creating the array when
//! absent and leaving other engines' arrays untouched. [`append_signature`]
//! makes that append on a dict in memory. `Repo::sign_commit` and
//! `Repo::verify_commit` in `ostrya` tie the engine to the detached-metadata
//! I/O.
//!
//! The dummy engine ([`DummySigner`] / [`DummyVerifier`]) carries no crypto: a
//! signature is the raw bytes of its key identifier, and verification matches a
//! stored blob against a trusted key byte string. It exercises the framework
//! and cross-checks against the tool's `ostree.sign.dummy` engine.
//!
//! The ed25519 engine ([`Ed25519Signer`] / [`Ed25519Verifier`]) is the first
//! real engine: a 32-byte public key, a 64-byte signature, and a 64-byte secret
//! key (32-byte seed followed by the 32-byte public key), all per
//! `format-reference.md`. ed25519 is deterministic, so signing needs no RNG and
//! the same key over the same commit yields byte-identical detached metadata.
//! [`SignKeys`] holds the trusted and revoked sets of a sign-api key store, and
//! a verifier trusts the loaded set minus the revoked set.
//! [`Ed25519Verifier::from_sign_keys`] takes a loaded key set, and the
//! `FromSystemKeys` trait of `ostrya` loads it from the system store.
//!
//! Under the `sign-spki` feature the crate holds the spki engine
//! (`SpkiSigner` / `SpkiVerifier`), ECDSA over NIST P-256 with SHA-256.
//! Under the `sign-gpg` feature it holds `GpgSigner`, which runs
//! `gpg --detach-sign` through `ostrya-rt`. The `smol` and `tokio` features
//! select the backend of `ostrya-rt` for that run, and a build without
//! `sign-gpg` holds no runtime. The GPG verifier is part of `ostrya`.
//!
//! [`read_key_file`] and [`read_key_source`] read a key source over `std::fs`,
//! only a regular file and only up to a ceiling such as [`MAX_KEY_FILE`], and
//! [`key_text`] reads the result as text.
//!
//! The crate compiles on Linux, macOS, and Windows.

mod dummy;
mod ed25519;
mod engine;
mod error;
#[cfg(feature = "sign-gpg")]
mod gpg;
mod keys;
mod metadata;
#[cfg(feature = "sign-spki")]
mod spki;

pub use dummy::{DummySigner, DummyVerifier};
pub use ed25519::{Ed25519Signer, Ed25519Verifier};
pub use engine::{SignFuture, SignatureInfo, Signer, Verifier, VerifyFuture, VerifyOutcome};
pub use error::{Error, Result};
#[cfg(feature = "sign-gpg")]
pub use gpg::GpgSigner;
pub use keys::{MAX_KEY_FILE, SignKeys, key_text, read_key_file, read_key_source};
pub use metadata::append_signature;
#[cfg(feature = "sign-spki")]
pub use spki::{SpkiSigner, SpkiVerifier};

/// The signing public types move freely across tasks and threads. The trait
/// objects `Repo::sign_commit` and `Repo::verify_commit` accept are
/// `Send + Sync` through the supertrait bounds; their dyn-compatibility is
/// enforced by the `&dyn Signer` and `&dyn Verifier` arguments of those two
/// methods.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DummySigner>();
    assert_send_sync::<DummyVerifier>();
    assert_send_sync::<Ed25519Signer>();
    assert_send_sync::<Ed25519Verifier>();
    assert_send_sync::<VerifyOutcome>();
    assert_send_sync::<SignatureInfo>();
    assert_send_sync::<SignKeys>();
    assert_send_sync::<Error>();
    #[cfg(feature = "sign-spki")]
    assert_send_sync::<SpkiSigner>();
    #[cfg(feature = "sign-spki")]
    assert_send_sync::<SpkiVerifier>();
    #[cfg(feature = "sign-gpg")]
    assert_send_sync::<GpgSigner>();
};
