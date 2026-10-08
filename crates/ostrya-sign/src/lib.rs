#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! The engines that sign and verify ostree commits and summaries.
//!
//! A caller signs a commit or a summary with a [`Signer`] and verifies it with
//! a [`Verifier`]. Each engine stores its signatures under its own key in the
//! detached metadata. The `ostrya` crate reads and writes this metadata and
//! loads the system key store. The crate compiles on Linux, macOS, and Windows.
//!
//! # Entry points
//!
//! - [`Signer`] and [`Verifier`] are the traits of an engine.
//! - [`Ed25519Signer`] and [`Ed25519Verifier`] are the ed25519 engine.
//! - [`DummySigner`] and [`DummyVerifier`] are the dummy engine for tests.
//! - [`append_signature`] adds a signature to a detached-metadata dict.
//! - [`read_key_file`] reads a key file, and [`SignKeys`] holds the keys.
//!
//! # Features
//!
//! - `smol` (default): with `sign-gpg`, `GpgSigner` runs `gpg` on `smol`.
//! - `tokio`: with `sign-gpg`, `GpgSigner` runs `gpg` on `tokio`.
//! - `sign-spki`: the spki engine, `SpkiSigner` and `SpkiVerifier`.
//! - `sign-gpg`: `GpgSigner`, which signs with the `gpg` command.
//!
//! # Examples
//!
//! ```
//! use futures_lite::future::block_on;
//! use ostrya_sign::{Ed25519Signer, Ed25519Verifier, Signer, Verifier};
//!
//! // The key of test 1 in RFC 8032: the 32-byte seed, then the public key.
//! let secret = ostrya_core::base64::decode(concat!(
//!     "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2DXWpgBgrEKt9VL/tPJZAc6",
//!     "DuFy89qmIyWvAhpo9wdRGg==",
//! ))?;
//! let signer = Ed25519Signer::from_secret_key(&secret)?;
//! let signature = block_on(signer.sign(b"commit bytes"))?;
//! let verifier = Ed25519Verifier::new([&secret[32..]], Vec::<&[u8]>::new())?;
//! let outcome = block_on(verifier.verify(b"commit bytes", &[signature]))?;
//! assert!(outcome.valid);
//! # Ok::<(), ostrya_sign::Error>(())
//! ```

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

// The public types of this crate are `Send + Sync`, so they can move across
// tasks and threads. The trait objects that `Repo::sign_commit` and
// `Repo::verify_commit` take are `Send + Sync` through the supertrait bounds.
// The `&dyn Signer` and `&dyn Verifier` arguments of these two methods make
// sure that the traits stay dyn-compatible.
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
