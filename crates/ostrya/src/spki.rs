//! spki (ECDSA over SubjectPublicKeyInfo) commit-signing engine (Phase 13c).
//!
//! Behind the `sign-spki` feature. The engine signs and verifies through the
//! shared [`Signer`]/[`Verifier`] framework: [`SpkiSigner`] produces a detached
//! signature over the commit's canonical bytes and [`SpkiVerifier`] checks the
//! blobs stored under `ostree.sign.spki` in the commit's detached metadata.
//!
//! Format (NIST P-256 with SHA-256, per `format-reference.md`, "Signing details
//! -- spki"):
//!
//! - Signatures are ECDSA over P-256 with SHA-256, DER-encoded (an ASN.1
//!   `SEQUENCE` of the two integers `r` and `s`). Verification also accepts the
//!   fixed-width `r || s` form.
//! - Public keys are the SubjectPublicKeyInfo DER (the base64 body of a PEM
//!   `PUBLIC KEY` block); a bare SEC1 point is accepted as a fallback.
//! - Secret keys are base64; the decoded bytes are a PKCS#8 `PrivateKeyInfo`
//!   DER, a SEC1 `ECPrivateKey` DER, or a raw 32-byte P-256 scalar.
//!
//! The key store is the sign-api store shared with ed25519: [`SpkiVerifier`]
//! loads `trusted.spki` and `revoked.spki` and their `.d` directories through
//! [`load_sign_keys`], each line the base64 of a SubjectPublicKeyInfo, and
//! trusts the loaded set minus the revoked set.
//!
//! Signing uses deterministic ECDSA (RFC 6979), so it needs no RNG and completes
//! in-task. The tool signs with a random nonce, so spki `.commitmeta` bytes are
//! not byte-identical across signers; the correctness gate is cross-verification,
//! not byte-identity.

use ostrya_core::base64;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use p256::{EncodedPoint, SecretKey};

use crate::error::{Error, Result};
use crate::sign::{
    SignFuture, SignKeys, SignatureInfo, Signer, Verifier, VerifyFuture, VerifyOutcome,
    load_sign_keys,
};

/// The spki sign-type name, used both as the engine name and as the base name of
/// its key-store files (`trusted.spki`, `revoked.spki`).
const SPKI_SIGN_TYPE: &str = "spki";
/// The spki engine's detached-metadata dict key.
const SPKI_METADATA_KEY: &str = "ostree.sign.spki";
/// The byte length of a raw P-256 scalar (a bare secret key).
const P256_SCALAR_LEN: usize = 32;

/// The spki commit-signing engine: deterministic ECDSA over NIST P-256 with
/// SHA-256, producing DER-encoded signatures.
#[derive(Clone)]
pub struct SpkiSigner {
    signing_key: SigningKey,
}

impl SpkiSigner {
    /// Build a signer from a base64-encoded secret key. The decoded bytes are a
    /// PKCS#8 `PrivateKeyInfo` DER, a SEC1 `ECPrivateKey` DER, or a raw 32-byte
    /// scalar. Surrounding whitespace (a trailing newline from a key file) is
    /// ignored.
    pub fn from_base64(secret_b64: &str) -> Result<SpkiSigner> {
        SpkiSigner::from_secret_key(&base64::decode(secret_b64.trim())?)
    }

    /// Build a signer from raw secret-key bytes: a PKCS#8 `PrivateKeyInfo` DER,
    /// a SEC1 `ECPrivateKey` DER, or a raw 32-byte P-256 scalar.
    pub fn from_secret_key(bytes: &[u8]) -> Result<SpkiSigner> {
        Ok(SpkiSigner {
            signing_key: decode_signing_key(bytes)?,
        })
    }

    /// Build a signer from a PKCS#8 PEM secret key
    /// (`-----BEGIN PRIVATE KEY-----`).
    pub fn from_pkcs8_pem(pem: &str) -> Result<SpkiSigner> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| Error::Signature(format!("spki secret key: {e}")))?;
        Ok(SpkiSigner { signing_key })
    }

    /// The SubjectPublicKeyInfo DER of this signer's public key, the bytes a
    /// verifier trusts (the base64 body of a PEM `PUBLIC KEY` block).
    pub fn public_key_der(&self) -> Vec<u8> {
        self.signing_key
            .verifying_key()
            .to_public_key_der()
            .expect("P-256 public key always encodes to SPKI DER")
            .as_bytes()
            .to_vec()
    }
}

impl Signer for SpkiSigner {
    fn name(&self) -> &str {
        SPKI_SIGN_TYPE
    }

    fn metadata_key(&self) -> &str {
        SPKI_METADATA_KEY
    }

    fn sign<'a>(&'a self, data: &'a [u8]) -> SignFuture<'a> {
        let sig: Signature = self.signing_key.sign(data);
        let der = sig.to_der().to_bytes().to_vec();
        Box::pin(async move { Ok(der) })
    }
}

/// The spki commit-verifying engine, holding the effective trusted key set.
///
/// A signature verifies when any trusted key accepts it.
#[derive(Clone)]
pub struct SpkiVerifier {
    trusted: Vec<VerifyingKey>,
}

impl SpkiVerifier {
    /// Build a verifier trusting each key in `trusted` except those also in
    /// `revoked`. Keys are SubjectPublicKeyInfo DER (or a bare SEC1 point);
    /// keys are matched by their uncompressed point, so encodings differing only
    /// in point compression still match. A key in either set that does not parse
    /// is an error, so a malformed revocation fails closed rather than being
    /// silently ignored.
    pub fn new<T, R>(trusted: T, revoked: R) -> Result<SpkiVerifier>
    where
        T: IntoIterator,
        T::Item: AsRef<[u8]>,
        R: IntoIterator,
        R::Item: AsRef<[u8]>,
    {
        let revoked: Vec<EncodedPoint> = revoked
            .into_iter()
            .map(|k| decode_verifying_key(k.as_ref()).map(|vk| vk.to_encoded_point(false)))
            .collect::<Result<_>>()?;
        let mut keys = Vec::new();
        for key in trusted {
            let vk = decode_verifying_key(key.as_ref())?;
            if revoked.contains(&vk.to_encoded_point(false)) {
                continue;
            }
            keys.push(vk);
        }
        Ok(SpkiVerifier { trusted: keys })
    }

    /// Build a verifier from a loaded [`SignKeys`] set (trusted minus revoked).
    pub fn from_sign_keys(keys: SignKeys) -> Result<SpkiVerifier> {
        SpkiVerifier::new(keys.trusted, keys.revoked)
    }

    /// Build a verifier from the system sign-api key store: `trusted.spki` and
    /// `revoked.spki` and their `.d` directories under the system search path
    /// (see [`load_sign_keys`]).
    pub fn from_system_keys() -> Result<SpkiVerifier> {
        SpkiVerifier::from_sign_keys(load_sign_keys(SPKI_SIGN_TYPE)?)
    }

    /// Build a verifier trusting a single PEM `PUBLIC KEY`
    /// (`-----BEGIN PUBLIC KEY-----`).
    pub fn from_pem(pem: &str) -> Result<SpkiVerifier> {
        let vk = VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| Error::Signature(format!("spki public key: {e}")))?;
        Ok(SpkiVerifier { trusted: vec![vk] })
    }

    /// Whether the effective trusted set is empty: no key was given, or the
    /// revoked set removed every one. Such a verifier refuses every signature.
    pub(crate) fn is_empty(&self) -> bool {
        self.trusted.is_empty()
    }
}

impl Verifier for SpkiVerifier {
    fn metadata_key(&self) -> &str {
        SPKI_METADATA_KEY
    }

    fn verify<'a>(&'a self, data: &'a [u8], signatures: &'a [Vec<u8>]) -> VerifyFuture<'a> {
        let mut outcome = VerifyOutcome::default();
        for blob in signatures {
            // Accept a DER-encoded signature (the tool's and this engine's form)
            // or the fixed-width r || s form.
            let sig = Signature::from_der(blob).or_else(|_| Signature::from_slice(blob));
            let valid = match sig {
                Ok(sig) => self.trusted.iter().any(|k| k.verify(data, &sig).is_ok()),
                Err(_) => false,
            };
            outcome.valid |= valid;
            outcome.signatures.push(SignatureInfo {
                valid,
                key_missing: !valid,
                ..SignatureInfo::default()
            });
        }
        Box::pin(async move { Ok(outcome) })
    }
}

/// Decode secret-key bytes into a [`SigningKey`], accepting a PKCS#8
/// `PrivateKeyInfo` DER, a SEC1 `ECPrivateKey` DER, or a raw 32-byte scalar.
fn decode_signing_key(bytes: &[u8]) -> Result<SigningKey> {
    if let Ok(key) = SigningKey::from_pkcs8_der(bytes) {
        return Ok(key);
    }
    if let Ok(secret) = SecretKey::from_sec1_der(bytes) {
        return Ok(SigningKey::from(&secret));
    }
    if bytes.len() == P256_SCALAR_LEN
        && let Ok(key) = SigningKey::from_slice(bytes)
    {
        return Ok(key);
    }
    Err(Error::Signature(
        "spki secret key: expected PKCS#8 DER, SEC1 DER, or a 32-byte P-256 scalar".into(),
    ))
}

/// Decode public-key bytes into a [`VerifyingKey`], accepting a
/// SubjectPublicKeyInfo DER or a bare SEC1 point.
fn decode_verifying_key(bytes: &[u8]) -> Result<VerifyingKey> {
    if let Ok(vk) = VerifyingKey::from_public_key_der(bytes) {
        return Ok(vk);
    }
    if let Ok(vk) = VerifyingKey::from_sec1_bytes(bytes) {
        return Ok(vk);
    }
    Err(Error::Signature(
        "spki public key: expected SubjectPublicKeyInfo DER or a SEC1 point".into(),
    ))
}

/// The spki public types move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SpkiSigner>();
    assert_send_sync::<SpkiVerifier>();
};
