#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! The engines that sign and verify ostree commits and summaries.
//!
//! A caller signs a commit or a summary with a [`Signer`] and verifies it with
//! a [`Verifier`]. Each engine stores its signatures under its own key in the
//! detached metadata. The `ostrya` crate reads and writes this metadata, loads
//! the system key store, and reads the GPG keyrings of the ostree paths. The
//! crate compiles on Linux, macOS, and Windows.
//!
//! A [`Verifier`] verifies in the call to [`Verifier::verify`], so a program
//! with no async runtime can verify. A [`Signer`] returns a future.
//!
//! # Entry points
//!
//! - [`Signer`] and [`Verifier`] are the traits of an engine.
//! - [`Ed25519Signer`] and [`Ed25519Verifier`] are the ed25519 engine.
//! - [`DummySigner`] and [`DummyVerifier`] are the dummy engine for tests.
//! - [`append_signature`] adds a signature to a detached-metadata dict.
//! - [`read_key_file`] reads a key file, and [`SignKeys`] holds the keys.
//! - `X509Signer`, with the feature `sign-x509`, is the trait of a signer
//!   with an X.509 certificate chain, for a CMS signature.
//! - `GpgVerifier`, with the feature `gpg`, is the GPG verifier.
//!   `gpg_keyring_keys` lists the keys of a keyring, and `gpg_offered_keys`
//!   and `gpg_merge_keyring` merge a keyring into another.
//!
//! # Features
//!
//! - `smol` (default): with `sign-gpg`, `GpgSigner` runs `gpg` on `smol`.
//! - `tokio`: with `sign-gpg`, `GpgSigner` runs `gpg` on `tokio`.
//! - `sign-spki`: the spki engine with each of its key types. It turns on
//!   `sign-spki-p256`, `sign-spki-p384`, `sign-spki-ed25519`, and
//!   `sign-spki-rsa`.
//! - `sign-spki-p256`: the spki engine with the ECDSA P-256 key type. The
//!   engine is `SpkiSigner` and `SpkiVerifier`, `spki_public_keys`, which
//!   reads the keys of a public key file, `spki_secret_keys`, which reads the
//!   signers of a PEM secret key file, and `spki_secret_key_lines`, which
//!   reads the signers of a file of base64 key lines.
//! - `sign-spki-p384`: the spki engine with the ECDSA P-384 key type, ECDSA
//!   signatures with SHA-256. The engine has the items of `sign-spki-p256`.
//! - `sign-spki-ed25519`: the spki engine with the Ed25519 key type, pure
//!   Ed25519 signatures of RFC 8032. The engine has the items of
//!   `sign-spki-p256`. The ed25519 engine needs no feature.
//! - `sign-spki-rsa`: the spki engine with the RSA key type, PKCS#1 v1.5
//!   signatures with SHA-256. The engine has the items of `sign-spki-p256`.
//!   A build without one of the four key features refuses a key of that
//!   type, with a message that names its feature.
//! - `gpg`: `GpgVerifier`, which verifies GPG signatures in the process
//!   with rPGP, and the keyring functions `gpg_keyring_keys`,
//!   `gpg_offered_keys`, and `gpg_merge_keyring`, with `GpgKey`,
//!   `GpgOfferedKeys`, and `MAX_KEYRING`. The feature holds no runtime.
//! - `sign-gpg`: `GpgSigner`, which signs with the `gpg` command. It does
//!   not turn on `gpg`.
//! - `sign-x509`: the trait `X509Signer`. With `sign-spki-p256`,
//!   `sign-spki-p384`, or `sign-spki-rsa`, also `X509SpkiSigner`, the spki
//!   signer with an X.509 certificate chain, which
//!   `SpkiSigner::with_certificates` makes. With one of the four key
//!   features, also `SpkiVerifier::from_certificates`, which trusts the keys
//!   of X.509 certificates. The feature validates no certificate chain.
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
//! let outcome = verifier.verify(b"commit bytes", &[signature])?;
//! assert!(outcome.valid);
//! # Ok::<(), ostrya_sign::Error>(())
//! ```

mod dummy;
mod ed25519;
mod engine;
mod error;
#[cfg(any(feature = "gpg", feature = "sign-gpg"))]
mod gpg;
mod keys;
mod metadata;
#[cfg(any(
    feature = "sign-spki-p256",
    feature = "sign-spki-p384",
    feature = "sign-spki-ed25519",
    feature = "sign-spki-rsa"
))]
mod pem;
#[cfg(any(
    feature = "sign-spki-p256",
    feature = "sign-spki-p384",
    feature = "sign-spki-ed25519",
    feature = "sign-spki-rsa"
))]
mod spki;
#[cfg(feature = "sign-x509")]
mod x509;

#[cfg(all(
    feature = "sign-x509",
    any(
        feature = "sign-spki-p256",
        feature = "sign-spki-p384",
        feature = "sign-spki-rsa"
    )
))]
pub use self::spki::X509SpkiSigner;
#[cfg(any(
    feature = "sign-spki-p256",
    feature = "sign-spki-p384",
    feature = "sign-spki-ed25519",
    feature = "sign-spki-rsa"
))]
pub use self::spki::{
    SpkiSigner, SpkiVerifier, spki_public_keys, spki_secret_key_lines, spki_secret_keys,
};
pub use dummy::{DummySigner, DummyVerifier};
pub use ed25519::{Ed25519Signer, Ed25519Verifier};
pub use engine::{SignFuture, SignatureInfo, Signer, Verifier, VerifyOutcome};
pub use error::{Error, Result};
#[cfg(feature = "sign-gpg")]
pub use gpg::GpgSigner;
#[cfg(feature = "gpg")]
pub use gpg::{
    GpgKey, GpgOfferedKeys, GpgVerifier, MAX_KEYRING, gpg_keyring_keys, gpg_merge_keyring,
    gpg_offered_keys,
};
pub use keys::{MAX_KEY_FILE, SignKeys, key_text, read_key_file, read_key_source};
pub use metadata::append_signature;
#[cfg(feature = "sign-x509")]
pub use x509::X509Signer;

// The public types of this crate are `Send + Sync`, so they can move across
// tasks and threads. The trait objects that `Repo::sign_commit` and
// `Repo::verify_commit` take are `Send + Sync` through the supertrait bounds.
// The `&dyn Signer` argument of `Repo::sign_commit` and the
// `Arc<dyn Verifier>` arguments of `Repo::verify_commit` make sure that the
// traits stay dyn-compatible. The `&dyn X509Signer` below does the same for
// `X509Signer`.
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
    #[cfg(any(
        feature = "sign-spki-p256",
        feature = "sign-spki-p384",
        feature = "sign-spki-ed25519",
        feature = "sign-spki-rsa"
    ))]
    assert_send_sync::<SpkiSigner>();
    #[cfg(any(
        feature = "sign-spki-p256",
        feature = "sign-spki-p384",
        feature = "sign-spki-ed25519",
        feature = "sign-spki-rsa"
    ))]
    assert_send_sync::<SpkiVerifier>();
    #[cfg(all(
        feature = "sign-x509",
        any(
            feature = "sign-spki-p256",
            feature = "sign-spki-p384",
            feature = "sign-spki-rsa"
        )
    ))]
    assert_send_sync::<X509SpkiSigner>();
    #[cfg(feature = "sign-gpg")]
    assert_send_sync::<GpgSigner>();
    #[cfg(feature = "gpg")]
    assert_send_sync::<GpgVerifier>();
    #[cfg(feature = "gpg")]
    assert_send_sync::<GpgKey>();
    #[cfg(feature = "gpg")]
    assert_send_sync::<GpgOfferedKeys>();
    #[cfg(feature = "sign-x509")]
    let _: Option<&dyn X509Signer> = None;
};
