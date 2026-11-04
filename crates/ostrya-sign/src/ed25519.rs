//! The ed25519 engine.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use ostrya_core::{Checksum, base64};

use crate::{Error, Result, SignFuture, SignKeys, SignatureInfo, Signer, Verifier, VerifyOutcome};

/// The ed25519 sign type. It is the engine name and the base name of the
/// key-store files (`trusted.ed25519`, `revoked.ed25519`).
const ED25519_SIGN_TYPE: &str = "ed25519";
/// The key of the ed25519 engine in the detached-metadata dict.
const ED25519_METADATA_KEY: &str = "ostree.sign.ed25519";
/// The raw byte length of an ed25519 public key.
const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// The raw byte length of an ed25519 secret key (seed followed by public key).
const ED25519_SECRET_KEY_LEN: usize = 64;
/// The SubjectPublicKeyInfo DER of an ed25519 public key before the 32 bytes
/// of the key (RFC 8410): the outer `SEQUENCE`, the `AlgorithmIdentifier`
/// `id-Ed25519` with no parameters, and the header of the `BIT STRING`.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The signer of the ed25519 engine.
///
/// The engine name is `ed25519`. The key of the engine in the detached
/// metadata is `ostree.sign.ed25519`. A signature is 64 bytes.
///
/// The secret key is 64 bytes: the 32-byte seed, then the 32-byte public key.
/// The `ostree` command uses the same form. The signer refuses a secret key
/// whose public half does not match the seed.
///
/// Signing is deterministic (RFC 8032), so it needs no random number
/// generator. The signer signs in the call to [`Signer::sign`] and does not
/// use the blocking pool. The same key over the same commit gives
/// byte-identical detached metadata.
#[derive(Debug, Clone)]
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Creates a signer from a 64-byte secret key.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] with the message
    ///   `ed25519 secret key must be 64 bytes, got <n>` if `secret` is not 64
    ///   bytes long.
    /// - [`Error::Signature`] with a message that starts with
    ///   `ed25519 secret key:` if the public half does not match the seed.
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

    /// Creates a signer from a base64-encoded 64-byte secret key.
    ///
    /// The function first removes the leading and trailing white space of
    /// `secret_b64`, for example the newline at the end of a key file.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if the text is not valid base64.
    /// - The errors of [`from_secret_key`](Self::from_secret_key) for the
    ///   decoded bytes.
    pub fn from_base64(secret_b64: &str) -> Result<Ed25519Signer> {
        Ed25519Signer::from_secret_key(&base64::decode(secret_b64.trim())?)
    }

    /// Returns the 32 bytes of the public key.
    ///
    /// The value is the second half of the secret key that
    /// [`from_secret_key`](Self::from_secret_key) takes. Give this value to
    /// [`Ed25519Verifier::new`] as a trusted key to verify the signatures of
    /// this signer.
    pub fn public_key(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.signing_key.verifying_key().to_bytes()
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

/// The verifier of the ed25519 engine, with its set of trusted keys.
///
/// The verifier reads the signatures under the key `ostree.sign.ed25519` of
/// the detached metadata. A signature verifies if a trusted key accepts it. A
/// blob that is not 64 bytes does not verify.
///
/// For a valid blob, the [`SignatureInfo`] gives the `fingerprint` of the
/// first trusted key that verifies it. The fingerprint is the SHA-256 of the
/// SubjectPublicKeyInfo DER of the key (RFC 8410), in lowercase hex. This DER
/// holds the 32 bytes of the key as they were given. The spki engine gives
/// the same fingerprint for the same Ed25519 key. For a blob that is not
/// valid, the `fingerprint` is `None`.
///
/// The `ostree` command verifies the signatures of [`Ed25519Signer`]. This
/// verifier verifies the signatures that the `ostree` command writes.
#[derive(Debug, Clone)]
pub struct Ed25519Verifier {
    trusted: Vec<TrustedKey>,
}

impl Ed25519Verifier {
    /// Creates a verifier that trusts each key in `trusted` that is not in
    /// `revoked`.
    ///
    /// Each key in the two sets must be a 32-byte public key. A key in
    /// `revoked` matches a trusted key by its bytes, and `new` does not check
    /// it as a curve point. `new` skips a trusted key that is also in
    /// `revoked` before the point check. Each other trusted key must be a
    /// valid curve point.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] with the message
    ///   `ed25519 public key must be 32 bytes, got <n>` if a key in `trusted`
    ///   or in `revoked` is not 32 bytes long.
    /// - [`Error::Signature`] with a message that starts with
    ///   `ed25519 public key:` if a trusted key that is not revoked is not a
    ///   valid curve point.
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
            keys.push(TrustedKey::new(vk, &raw));
        }
        Ok(Ed25519Verifier { trusted: keys })
    }

    /// Creates a verifier from a loaded [`SignKeys`] set.
    ///
    /// The function gives `keys.trusted` and `keys.revoked` to
    /// [`new`](Self::new), which states the rules for the keys.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] for a key that [`new`](Self::new) refuses.
    pub fn from_sign_keys(keys: SignKeys) -> Result<Ed25519Verifier> {
        Ed25519Verifier::new(keys.trusted, keys.revoked)
    }

    /// Returns `true` if the set of trusted keys is empty.
    ///
    /// The set is empty if no trusted key was given, or if the revoked set
    /// removed each trusted key. An empty verifier refuses every signature.
    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty()
    }
}

impl Verifier for Ed25519Verifier {
    fn metadata_key(&self) -> &str {
        ED25519_METADATA_KEY
    }

    fn verify(&self, data: &[u8], signatures: &[Vec<u8>]) -> Result<VerifyOutcome> {
        let mut outcome = VerifyOutcome::default();
        for blob in signatures {
            let trusted = match <[u8; 64]>::try_from(blob.as_slice()) {
                Ok(sig_bytes) => {
                    let sig = Signature::from_bytes(&sig_bytes);
                    self.trusted
                        .iter()
                        .find(|t| t.key.verify(data, &sig).is_ok())
                }
                // A blob that is not 64 bytes cannot be an ed25519 signature.
                Err(_) => None,
            };
            let valid = trusted.is_some();
            outcome.valid |= valid;
            outcome.signatures.push(SignatureInfo {
                valid,
                fingerprint: trusted.map(|t| t.fingerprint.clone()),
                key_missing: !valid,
                ..SignatureInfo::default()
            });
        }
        Ok(outcome)
    }
}

/// A trusted key of a verifier.
#[derive(Debug, Clone)]
struct TrustedKey {
    /// The key.
    key: VerifyingKey,
    /// The lowercase hex SHA-256 of the SubjectPublicKeyInfo DER of the key.
    fingerprint: String,
}

impl TrustedKey {
    /// Returns the trusted key of `key`, whose 32 bytes as they were given
    /// are `raw`.
    fn new(key: VerifyingKey, raw: &[u8; ED25519_PUBLIC_KEY_LEN]) -> TrustedKey {
        let mut der = [0u8; ED25519_SPKI_PREFIX.len() + ED25519_PUBLIC_KEY_LEN];
        der[..ED25519_SPKI_PREFIX.len()].copy_from_slice(&ED25519_SPKI_PREFIX);
        der[ED25519_SPKI_PREFIX.len()..].copy_from_slice(raw);
        TrustedKey {
            key,
            fingerprint: Checksum::sha256(&der).to_hex(),
        }
    }
}

/// Reads a byte slice as a 32-byte ed25519 public key.
fn ed25519_public_bytes(key: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_LEN]> {
    key.try_into().map_err(|_| {
        Error::Signature(format!(
            "ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
            key.len()
        ))
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // The key of test 1 in RFC 8032, section 7.1.

    /// The seed of the key, in hex. The spki ed25519 tests use it too.
    pub(crate) const SEED_HEX: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    /// The public key, in hex. The spki ed25519 tests use it too.
    pub(crate) const PUBLIC_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    /// The lowercase hex SHA-256 of the SubjectPublicKeyInfo DER of the key.
    /// The spki ed25519 tests use it too.
    pub(crate) const FINGERPRINT: &str =
        "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

    /// Returns the bytes of the hex text `hex`. The spki ed25519 tests use it
    /// too.
    pub(crate) fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Returns the signer of the 32-byte seed `seed`.
    fn signer_of(seed: &[u8; 32]) -> Ed25519Signer {
        let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        Ed25519Signer::from_secret_key(&[&seed[..], &public].concat()).unwrap()
    }

    /// Returns the seed of the key.
    fn rfc_seed() -> [u8; 32] {
        from_hex(SEED_HEX).try_into().unwrap()
    }

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
        let outcome = verifier.verify(b"payload", &[signature]).unwrap();
        assert!(outcome.valid);
    }

    #[test]
    fn the_public_key_is_the_second_half_of_the_secret_key() {
        let mut secret = [0u8; ED25519_SECRET_KEY_LEN];
        secret[..32].copy_from_slice(&[7u8; 32]);
        let public = SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        secret[32..].copy_from_slice(&public);
        let signer = Ed25519Signer::from_secret_key(&secret).unwrap();
        assert_eq!(signer.public_key(), secret[32..]);
        let signature = futures_lite::future::block_on(signer.sign(b"payload")).unwrap();
        let verifier = Ed25519Verifier::new([signer.public_key()], Vec::<Vec<u8>>::new()).unwrap();
        let outcome = verifier.verify(b"payload", &[signature]).unwrap();
        assert!(outcome.valid);
    }

    #[test]
    fn a_valid_signature_names_the_fingerprint_of_its_key() {
        let signer = signer_of(&rfc_seed());
        assert_eq!(signer.public_key()[..], from_hex(PUBLIC_HEX));
        let signature = futures_lite::future::block_on(signer.sign(b"payload")).unwrap();
        let verifier = Ed25519Verifier::new([from_hex(PUBLIC_HEX)], Vec::<Vec<u8>>::new()).unwrap();
        let outcome = verifier.verify(b"payload", &[signature]).unwrap();
        assert!(outcome.valid);
        let [info] = outcome.signatures.as_slice() else {
            panic!("one blob gives one entry");
        };
        assert!(info.valid);
        assert!(!info.key_missing);
        assert_eq!(info.fingerprint.as_deref(), Some(FINGERPRINT));
        assert_eq!(info.pubkey_algorithm, None);
    }

    #[test]
    fn a_signature_names_the_trusted_key_that_verifies_it() {
        let first = signer_of(&rfc_seed());
        let second = signer_of(&[7u8; 32]);
        let verifier = Ed25519Verifier::new(
            [first.public_key(), second.public_key()],
            Vec::<Vec<u8>>::new(),
        )
        .unwrap();
        let signature = futures_lite::future::block_on(second.sign(b"payload")).unwrap();
        let outcome = verifier.verify(b"payload", &[signature]).unwrap();
        assert!(outcome.valid);
        let der = [&ED25519_SPKI_PREFIX[..], &second.public_key()].concat();
        let want = Checksum::sha256(&der).to_hex();
        assert_ne!(want, FINGERPRINT);
        assert_eq!(outcome.signatures[0].fingerprint, Some(want));
    }

    #[test]
    fn a_blob_that_does_not_verify_names_no_key() {
        let verifier = Ed25519Verifier::new([from_hex(PUBLIC_HEX)], Vec::<Vec<u8>>::new()).unwrap();
        let untrusted =
            futures_lite::future::block_on(signer_of(&[7u8; 32]).sign(b"payload")).unwrap();
        let blobs = [untrusted, vec![0u8; 63], vec![0u8; 65], Vec::new()];
        let outcome = verifier.verify(b"payload", &blobs).unwrap();
        assert!(!outcome.valid);
        assert_eq!(outcome.signatures.len(), blobs.len());
        for info in &outcome.signatures {
            assert!(!info.valid);
            assert!(info.key_missing);
            assert_eq!(info.fingerprint, None);
        }
    }

    #[test]
    fn a_non_canonical_key_encoding_gives_a_fingerprint_of_its_own() {
        // The identity point with the sign bit of x set.
        let mut key = [0u8; 32];
        key[0] = 1;
        key[31] = 0x80;
        let mut canonical = [0u8; 32];
        canonical[0] = 1;
        // R is the canonical encoding of the identity point, and S is 0.
        let blob = [&canonical[..], &[0u8; 32]].concat();
        let verifier = Ed25519Verifier::new([key], Vec::<Vec<u8>>::new()).unwrap();
        let outcome = verifier.verify(b"payload", &[blob]).unwrap();
        assert!(outcome.valid);
        let want = Checksum::sha256(&[&ED25519_SPKI_PREFIX[..], &key].concat()).to_hex();
        let other = Checksum::sha256(&[&ED25519_SPKI_PREFIX[..], &canonical].concat()).to_hex();
        assert_ne!(want, other);
        assert_eq!(outcome.signatures[0].fingerprint, Some(want));
    }
}
