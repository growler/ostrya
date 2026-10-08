//! The spki engine: ECDSA over NIST P-256 with SHA-256.
//!
//! The docs of `SpkiSigner` and `SpkiVerifier` hold the signature and key
//! formats.

use ostrya_core::base64;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use p256::{EncodedPoint, SecretKey};

use crate::{
    Error, Result, SignFuture, SignKeys, SignatureInfo, Signer, Verifier, VerifyFuture,
    VerifyOutcome,
};

/// The name of the spki sign type. It is the engine name and the base name of
/// the key-store files (`trusted.spki`, `revoked.spki`).
const SPKI_SIGN_TYPE: &str = "spki";
/// The key of the spki engine in the detached-metadata dict.
const SPKI_METADATA_KEY: &str = "ostree.sign.spki";
/// The byte length of a raw P-256 scalar (a bare secret key).
const P256_SCALAR_LEN: usize = 32;

/// The signer of the spki engine.
///
/// The engine name is `spki`. The signer stores its signatures under the key
/// `ostree.sign.spki` in the detached metadata.
///
/// # Signature format
///
/// A signature is ECDSA over NIST P-256 with SHA-256. The signer writes it in
/// DER, an ASN.1 `SEQUENCE` of the two integers `r` and `s`.
///
/// The signer uses deterministic ECDSA (RFC 6979), so it needs no random
/// number generator. It signs in the call to [`Signer::sign`], so the future
/// that this call returns is ready at once. Signing never returns an error.
#[derive(Clone)]
pub struct SpkiSigner {
    signing_key: SigningKey,
}

impl SpkiSigner {
    /// Creates a signer from a base64 secret key.
    ///
    /// The function removes the leading and trailing white space of
    /// `secret_b64`, for example the newline at the end of a key file. Then it
    /// decodes the base64 text and reads the bytes as
    /// [`from_secret_key`](Self::from_secret_key) does.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if `secret_b64` is not valid base64 text.
    /// - [`Error::Signature`] if the decoded bytes are in no secret-key form
    ///   that [`from_secret_key`](Self::from_secret_key) accepts.
    pub fn from_base64(secret_b64: &str) -> Result<SpkiSigner> {
        SpkiSigner::from_secret_key(&base64::decode(secret_b64.trim())?)
    }

    /// Creates a signer from the bytes of a secret key.
    ///
    /// The function accepts these forms of `bytes`:
    ///
    /// - a PKCS#8 `PrivateKeyInfo` DER
    /// - a SEC1 `ECPrivateKey` DER
    /// - a raw 32-byte P-256 scalar
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if the function cannot read `bytes` in one of
    ///   these forms. The message is `spki secret key: expected PKCS#8 DER,
    ///   SEC1 DER, or a 32-byte P-256 scalar`.
    pub fn from_secret_key(bytes: &[u8]) -> Result<SpkiSigner> {
        Ok(SpkiSigner {
            signing_key: decode_signing_key(bytes)?,
        })
    }

    /// Creates a signer from a PKCS#8 PEM secret key.
    ///
    /// The PEM block starts with `-----BEGIN PRIVATE KEY-----`.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if `pem` is not a PKCS#8 PEM P-256 secret key.
    ///   The message starts with `spki secret key: `.
    pub fn from_pkcs8_pem(pem: &str) -> Result<SpkiSigner> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| Error::Signature(format!("spki secret key: {e}")))?;
        Ok(SpkiSigner { signing_key })
    }

    /// Returns the SubjectPublicKeyInfo DER of the public key of this signer.
    ///
    /// A [`SpkiVerifier`] trusts these bytes. The base64 body of a PEM
    /// `PUBLIC KEY` block decodes to the same bytes.
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

/// The verifier of the spki engine.
///
/// The verifier holds the effective set of trusted keys. It reads the
/// signatures under the key `ostree.sign.spki` in the detached metadata. A
/// signature verifies if one of the trusted keys accepts it.
///
/// # Formats
///
/// A signature is in DER form, the form that [`SpkiSigner`] writes. The
/// verifier also accepts the fixed-width 64-byte `r || s` form.
/// A blob in neither form does not verify.
///
/// A public key is a SubjectPublicKeyInfo DER, which is the base64 body of a
/// PEM `PUBLIC KEY` block. The verifier also accepts a bare SEC1 point. In the
/// system key store, each line of the `trusted.spki` and `revoked.spki` files
/// is the base64 of a SubjectPublicKeyInfo DER.
///
/// # Examples
///
/// ```
/// use futures_lite::future::block_on;
/// use ostrya_sign::{Signer, SpkiSigner, SpkiVerifier, Verifier};
///
/// let signer = SpkiSigner::from_secret_key(&[7u8; 32])?;
/// let der = signer.public_key_der();
/// let verifier = SpkiVerifier::new([der], Vec::<&[u8]>::new())?;
/// let signature = block_on(signer.sign(b"commit bytes"))?;
/// // A DER signature starts with the tag of an ASN.1 `SEQUENCE`.
/// assert_eq!(signature[0], 0x30);
/// let outcome = block_on(verifier.verify(b"commit bytes", &[signature]))?;
/// assert!(outcome.valid);
/// # Ok::<(), ostrya_sign::Error>(())
/// ```
#[derive(Clone)]
pub struct SpkiVerifier {
    trusted: Vec<VerifyingKey>,
}

impl SpkiVerifier {
    /// Creates a verifier that trusts each key in `trusted` that is not in `revoked`.
    ///
    /// Each key is in one of the [public-key forms](SpkiVerifier#formats) of
    /// the verifier. The function matches the keys by their uncompressed
    /// point, so two encodings that differ only in point compression match.
    ///
    /// The function returns an error for a key in either set that does not
    /// parse, so a malformed revocation fails closed.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if a key in `trusted` or `revoked` is neither a
    ///   SubjectPublicKeyInfo DER nor a SEC1 point. The message is
    ///   `spki public key: expected SubjectPublicKeyInfo DER or a SEC1 point`.
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

    /// Creates a verifier from a loaded [`SignKeys`] set.
    ///
    /// The function gives `keys.trusted` and `keys.revoked` to
    /// [`new`](Self::new), which states the rules for the keys. The
    /// `FromSystemKeys` trait of the `ostrya` crate loads this set from the
    /// system key store.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if a key in either set does not parse, as for
    ///   [`new`](Self::new).
    pub fn from_sign_keys(keys: SignKeys) -> Result<SpkiVerifier> {
        SpkiVerifier::new(keys.trusted, keys.revoked)
    }

    /// Creates a verifier that trusts one PEM public key.
    ///
    /// The PEM block starts with `-----BEGIN PUBLIC KEY-----` and holds a
    /// SubjectPublicKeyInfo.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if `pem` is not a PEM P-256 public key. The
    ///   message starts with `spki public key: `.
    pub fn from_pem(pem: &str) -> Result<SpkiVerifier> {
        let vk = VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| Error::Signature(format!("spki public key: {e}")))?;
        Ok(SpkiVerifier { trusted: vec![vk] })
    }

    /// Returns `true` if the verifier trusts no key.
    ///
    /// The set is empty if `trusted` is empty, or if `revoked` holds each key
    /// of `trusted`. An empty verifier refuses each signature.
    pub fn is_empty(&self) -> bool {
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
            // The verifier accepts a DER signature (the form of this engine)
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

/// Decodes secret-key bytes into a [`SigningKey`]. The bytes are a PKCS#8
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

/// Decodes public-key bytes into a [`VerifyingKey`]. The bytes are a
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
