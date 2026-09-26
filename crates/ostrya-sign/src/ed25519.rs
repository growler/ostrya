//! The ed25519 engine.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use ostrya_core::base64;

use crate::{
    Error, Result, SignFuture, SignKeys, SignatureInfo, Signer, Verifier, VerifyFuture,
    VerifyOutcome,
};

/// The ed25519 sign-type name, used both as the engine name and as the base
/// name of its key-store files (`trusted.ed25519`, `revoked.ed25519`).
const ED25519_SIGN_TYPE: &str = "ed25519";
/// The ed25519 engine's detached-metadata dict key.
const ED25519_METADATA_KEY: &str = "ostree.sign.ed25519";
/// The raw byte length of an ed25519 public key.
const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// The raw byte length of an ed25519 secret key (seed followed by public key).
const ED25519_SECRET_KEY_LEN: usize = 64;

/// The ed25519 commit-signing engine.
///
/// The secret key is the 64-byte seed-plus-public-key form the tool uses;
/// [`from_keypair_bytes`](SigningKey::from_keypair_bytes) checks that the stored
/// public half matches the seed. Signing is deterministic (RFC 8032), so it
/// needs no RNG and completes in-task without offloading to the blocking pool.
#[derive(Debug, Clone)]
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Build a signer from a 64-byte secret key (32-byte seed followed by the
    /// 32-byte public key). Accepts the raw bytes or an `ay` payload.
    pub fn from_secret_key(secret: &[u8]) -> Result<Ed25519Signer> {
        let bytes: [u8; ED25519_SECRET_KEY_LEN] = secret.try_into().map_err(|_| {
            Error::Signature(format!(
                "ed25519 secret key must be {ED25519_SECRET_KEY_LEN} bytes, got {}",
                secret.len()
            ))
        })?;
        let signing_key = SigningKey::from_keypair_bytes(&bytes)
            .map_err(|e| Error::Signature(format!("ed25519 secret key: {e}")))?;
        Ok(Ed25519Signer { signing_key })
    }

    /// Build a signer from a base64-encoded 64-byte secret key. Surrounding
    /// whitespace (a trailing newline from a key file) is ignored.
    pub fn from_base64(secret_b64: &str) -> Result<Ed25519Signer> {
        Ed25519Signer::from_secret_key(&base64::decode(secret_b64.trim())?)
    }
}

impl Signer for Ed25519Signer {
    fn name(&self) -> &str {
        ED25519_SIGN_TYPE
    }

    fn metadata_key(&self) -> &str {
        ED25519_METADATA_KEY
    }

    fn sign<'a>(&'a self, data: &'a [u8]) -> SignFuture<'a> {
        let signature = self.signing_key.sign(data).to_bytes().to_vec();
        Box::pin(async move { Ok(signature) })
    }
}

/// The ed25519 commit-verifying engine, holding the effective trusted key set.
///
/// A signature verifies when any trusted key accepts it. Verification uses the
/// lenient (cofactored) equation, matching the acceptance the tool's libsodium
/// backend applies, so a valid signature written by either side verifies on the
/// other.
#[derive(Debug, Clone)]
pub struct Ed25519Verifier {
    trusted: Vec<VerifyingKey>,
}

impl Ed25519Verifier {
    /// Build a verifier trusting each key in `trusted` except those also in
    /// `revoked`. Keys are 32-byte public keys, as raw bytes or `ay` payloads.
    /// A trusted key that is not a valid curve point is an error; a revoked key
    /// need only match by bytes and is not validated as a point.
    pub fn new<T, R>(trusted: T, revoked: R) -> Result<Ed25519Verifier>
    where
        T: IntoIterator,
        T::Item: AsRef<[u8]>,
        R: IntoIterator,
        R::Item: AsRef<[u8]>,
    {
        let revoked: HashSet<[u8; ED25519_PUBLIC_KEY_LEN]> = revoked
            .into_iter()
            .map(|k| ed25519_public_bytes(k.as_ref()))
            .collect::<Result<_>>()?;
        let mut keys = Vec::new();
        for key in trusted {
            let raw = ed25519_public_bytes(key.as_ref())?;
            if revoked.contains(&raw) {
                continue;
            }
            let vk = VerifyingKey::from_bytes(&raw)
                .map_err(|e| Error::Signature(format!("ed25519 public key: {e}")))?;
            keys.push(vk);
        }
        Ok(Ed25519Verifier { trusted: keys })
    }

    /// Build a verifier from a loaded [`SignKeys`] set (trusted minus revoked).
    pub fn from_sign_keys(keys: SignKeys) -> Result<Ed25519Verifier> {
        Ed25519Verifier::new(keys.trusted, keys.revoked)
    }

    /// Whether the effective trusted set is empty: no key was given, or the
    /// revoked set removed every one. Such a verifier refuses every signature.
    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty()
    }
}

impl Verifier for Ed25519Verifier {
    fn metadata_key(&self) -> &str {
        ED25519_METADATA_KEY
    }

    fn verify<'a>(&'a self, data: &'a [u8], signatures: &'a [Vec<u8>]) -> VerifyFuture<'a> {
        let mut outcome = VerifyOutcome::default();
        for blob in signatures {
            let valid = match <[u8; 64]>::try_from(blob.as_slice()) {
                Ok(sig_bytes) => {
                    let sig = Signature::from_bytes(&sig_bytes);
                    self.trusted.iter().any(|k| k.verify(data, &sig).is_ok())
                }
                // A blob that is not 64 bytes cannot be an ed25519 signature.
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

/// Interpret a byte slice as a 32-byte ed25519 public key.
fn ed25519_public_bytes(key: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_LEN]> {
    key.try_into().map_err(|_| {
        Error::Signature(format!(
            "ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
            key.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_key_of_another_length_is_refused() {
        let err = Ed25519Signer::from_secret_key(&[0u8; ED25519_SECRET_KEY_LEN - 1]).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("must be 64 bytes, got 63")),
            "{err}"
        );
    }

    #[test]
    fn a_signature_verifies_under_the_key_that_made_it() {
        let mut secret = [0u8; ED25519_SECRET_KEY_LEN];
        secret[..32].copy_from_slice(&[7u8; 32]);
        let public = SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        secret[32..].copy_from_slice(&public);
        let signer = Ed25519Signer::from_secret_key(&secret).unwrap();
        let signature = futures_lite::future::block_on(signer.sign(b"payload")).unwrap();
        let verifier = Ed25519Verifier::new([public], Vec::<Vec<u8>>::new()).unwrap();
        let outcome =
            futures_lite::future::block_on(verifier.verify(b"payload", &[signature])).unwrap();
        assert!(outcome.valid);
    }
}
