//! The spki engine: ECDSA over NIST P-256 and P-384 with SHA-256, and RSA
//! PKCS#1 v1.5 with SHA-256.
//!
//! The algorithm OID of a key selects its key type. The docs of `SpkiSigner`
//! and `SpkiVerifier` hold the signature and key formats.

#[cfg(feature = "sign-spki-p384")]
mod p384;
#[cfg(feature = "sign-spki-rsa")]
mod rsa;

use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::HashSet;

use der::asn1::{AnyRef, ContextSpecific, ObjectIdentifier, OctetStringRef, UintRef};
use der::zeroize::Zeroizing;
use der::{Decode, Reader, SliceReader, Tag, TagNumber, Tagged};
use ostrya_core::{Checksum, base64};
use pkcs8::PrivateKeyInfo;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

#[cfg(feature = "sign-spki-p256")]
use p256::ecdsa::signature::{Signer as _, hazmat::PrehashVerifier as _};
#[cfg(feature = "sign-spki-p256")]
use p256::pkcs8::EncodePublicKey;

use crate::pem;
use crate::{
    Error, Result, SignFuture, SignKeys, SignatureInfo, Signer, Verifier, VerifyFuture,
    VerifyOutcome,
};

/// The name of the spki sign type. It is the engine name and the base name of
/// the key-store files (`trusted.spki`, `revoked.spki`).
const SPKI_SIGN_TYPE: &str = "spki";
/// The key of the spki engine in the detached-metadata dict.
const SPKI_METADATA_KEY: &str = "ostree.sign.spki";
/// The label of the PEM blocks of a public key file.
const PUBLIC_KEY_LABEL: &[u8] = b"PUBLIC KEY";
/// The label of the PEM blocks of a secret key file.
const PRIVATE_KEY_LABEL: &[u8] = b"PRIVATE KEY";

/// The algorithm OID of an elliptic-curve key, `id-ecPublicKey`.
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// The OID of the NIST P-256 curve, `prime256v1`.
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// The OID of the NIST P-384 curve, `secp384r1`.
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// The algorithm OID of an RSA key, `rsaEncryption`.
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// The names of the key types and curves that a refusal message gives. A
/// message gives the dotted OID of a key type or a curve with no name here.
const OID_NAMES: &[(ObjectIdentifier, &str)] = &[
    (RSA_ENCRYPTION, "RSA"),
    (
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
        "RSASSA-PSS",
    ),
    (ObjectIdentifier::new_unwrap("1.2.840.10040.4.1"), "DSA"),
    (ObjectIdentifier::new_unwrap("1.3.101.110"), "X25519"),
    (ObjectIdentifier::new_unwrap("1.3.101.111"), "X448"),
    (ObjectIdentifier::new_unwrap("1.3.101.112"), "Ed25519"),
    (ObjectIdentifier::new_unwrap("1.3.101.113"), "Ed448"),
    (SECP384R1, "P-384"),
    (ObjectIdentifier::new_unwrap("1.3.132.0.35"), "P-521"),
    (ObjectIdentifier::new_unwrap("1.3.132.0.10"), "secp256k1"),
    (ObjectIdentifier::new_unwrap("1.2.156.10197.1.301"), "SM2"),
];

/// The reason of a refusal of an EC key with explicit curve parameters.
const EXPLICIT_PARAMETERS: &str = "the EC key has explicit curve parameters";

/// The signer of the spki engine.
///
/// The engine name is `spki`. The signer stores its signatures under the key
/// `ostree.sign.spki` in the detached metadata.
///
/// # Signature format
///
/// The key type of the signer selects the signature format:
///
/// - P-256: ECDSA over NIST P-256 with SHA-256. The signer writes the
///   signature in DER, an ASN.1 `SEQUENCE` of the two integers `r` and `s`.
///   The signer uses deterministic ECDSA (RFC 6979).
/// - P-384: ECDSA over NIST P-384 with SHA-256, in DER as for P-256. The
///   signer signs the SHA-256 of the data. It makes the nonce of RFC 6979
///   from this hash with HMAC-SHA-384, so its signatures differ from the
///   RFC 6979 test vectors for P-384 with SHA-256, which use HMAC-SHA-256.
///   The verify of a signature does not depend on its nonce.
/// - RSA: RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017). The signature is the
///   raw signature, with the length of the modulus in bytes. The signer
///   blinds each private-key operation with a random value from the
///   operating system. The blinding does not change the signature.
///
/// The signer gives the same bytes for the same key and the same data. It
/// signs in the call to [`Signer::sign`], so the future that this call
/// returns is ready at once, and the call blocks for the CPU time of the
/// signature. The time of an RSA signature increases with the size of the
/// modulus: with a 16384-bit key, a signature takes about 0.5 seconds on an
/// x86-64 host. A caller on an async runtime can run the call on a thread
/// for blocking work.
///
/// A P-256 or a P-384 signature never returns an error. An RSA signature
/// returns [`Error::Signature`] if the check of the private-key operation
/// fails.
///
/// # Secret keys
///
/// The algorithm OID of a PKCS#8 key selects the key type, and the curve OID
/// in its `parameters` field selects the curve. The signer takes these key
/// types:
///
/// - `id-ecPublicKey` (1.2.840.10045.2.1) on the curve `prime256v1`
///   (1.2.840.10045.3.1.7), with the feature `sign-spki-p256`.
/// - `id-ecPublicKey` on the curve `secp384r1` (1.3.132.0.34), with the
///   feature `sign-spki-p384`.
/// - `rsaEncryption` (1.2.840.113549.1.1.1) with `NULL` parameters, with the
///   feature `sign-spki-rsa`. The modulus has 2048 to 16384 bits, and the
///   key has two primes.
///
/// The signer refuses each other key type and curve, an EC key with
/// explicit curve parameters, and a key of a type that the build has no code
/// for. An `id-RSASSA-PSS` key (1.2.840.113549.1.1.10) is of another key
/// type.
///
/// A secret key file holds PEM `PRIVATE KEY` blocks, and
/// [`spki_secret_keys`] reads it. Each block gives one signer.
#[derive(Clone)]
pub struct SpkiSigner {
    key: Secret,
}

impl SpkiSigner {
    /// Creates a signer from a base64 secret key.
    ///
    /// The function removes each white space character of `secret_b64`, at
    /// any position. White space is space, horizontal tab, LF, form feed, and
    /// CR. So the text can hold the line breaks of a PEM body, LF or CRLF.
    /// Then the function decodes the base64 text and reads the bytes as
    /// [`from_secret_key`](Self::from_secret_key) does.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if the text is not valid base64 after the white space
    ///   is removed. A character outside the base64 alphabet is not valid.
    /// - [`Error::Signature`] if [`from_secret_key`](Self::from_secret_key)
    ///   refuses the decoded bytes.
    pub fn from_base64(secret_b64: &str) -> Result<SpkiSigner> {
        let der = match without_white_space(secret_b64) {
            Cow::Borrowed(text) => base64::decode(text),
            Cow::Owned(text) => base64::decode(&Zeroizing::new(text)),
        };
        SpkiSigner::from_secret_key(&Zeroizing::new(der?))
    }

    /// Creates a signer from the bytes of a secret key.
    ///
    /// The function accepts these forms of `bytes`:
    ///
    /// - a PKCS#8 `PrivateKeyInfo` DER
    /// - a SEC1 `ECPrivateKey` DER with a `parameters` field that names the
    ///   P-256 or the P-384 curve
    /// - a PKCS#1 `RSAPrivateKey` DER
    ///
    /// The function tells the three forms apart by their ASN.1 structure.
    /// After its version, a PKCS#8 key holds an `AlgorithmIdentifier`, a
    /// PKCS#1 key holds the modulus, and a SEC1 key holds the secret scalar in
    /// an `OCTET STRING`. A PKCS#1 key holds the fields of an `RSAPrivateKey`
    /// and no other field. The `ECPrivateKey` in a PKCS#8 key can have no
    /// `parameters` field. If it has one, the field names the curve of the
    /// PKCS#8 key.
    ///
    /// The scalar of an EC key can be shorter than the field size of the
    /// curve, 32 bytes for P-256 and 48 bytes for P-384. The function reads
    /// a scalar of 24 bytes up to the field size, with zero bytes on the
    /// left. The `publicKey` field of the `ECPrivateKey` can be absent.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] in these conditions. Each message starts with
    /// `spki secret key: `.
    ///
    /// - The key type of a PKCS#8 key is not `id-ecPublicKey` or
    ///   `rsaEncryption`. The message is
    ///   `spki secret key: the key type <name> is not supported`. `<name>` is
    ///   a name such as `RSASSA-PSS` or `Ed25519`, or the dotted OID.
    /// - The build has no code for the key type or the curve of the key. The
    ///   message is `spki secret key: this build has no code for <the key
    ///   type RSA | the curve P-256 | the curve P-384>; build with the
    ///   <feature> feature`. `<feature>` is `sign-spki-rsa`, `sign-spki-p256`,
    ///   or `sign-spki-p384`.
    /// - The parameters of the `rsaEncryption` `AlgorithmIdentifier` of a
    ///   PKCS#8 key are not `NULL`. The message is
    ///   `spki secret key: the rsaEncryption parameters are not NULL`.
    /// - The modulus of an RSA key has fewer than 2048 bits or more than
    ///   16384 bits. The message is `spki secret key: the RSA modulus has
    ///   <bits> bits; the engine takes 2048 to 16384 bits`.
    /// - An RSA key has more than two primes. The message is
    ///   `spki secret key: the RSA key has more than two primes`.
    /// - The integers of an RSA key do not make a valid key. The message
    ///   starts with `spki secret key: the RSA key is not valid: `.
    /// - A PKCS#8 key or a SEC1 key names a curve other than P-256 and P-384.
    ///   The message is `spki secret key: the curve <name> is not supported`.
    /// - An EC key has explicit curve parameters, in the PKCS#8
    ///   `AlgorithmIdentifier`, in the `ECPrivateKey` of a PKCS#8 key, or in
    ///   a SEC1 key. The message is
    ///   `spki secret key: the EC key has explicit curve parameters`.
    /// - A PKCS#8 key has no curve in its `AlgorithmIdentifier`. The message
    ///   is `spki secret key: the EC key does not name its curve`.
    /// - The `parameters` field of the `ECPrivateKey` of a PKCS#8 key names
    ///   another curve, or holds a value that is not a curve, such as a
    ///   `NULL`. The message is `spki secret key: the ECPrivateKey names a
    ///   curve other than the curve of the PKCS#8 key`.
    /// - A SEC1 key has no `parameters` field, or the field holds a value that
    ///   is not a curve. The message is
    ///   `spki secret key: the SEC1 key does not name its curve`.
    /// - The function cannot read `bytes` in one of the forms. The message is
    ///   `spki secret key: expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER`. A
    ///   raw 32-byte scalar is in no accepted form.
    pub fn from_secret_key(bytes: &[u8]) -> Result<SpkiSigner> {
        let key = decode_secret_key(bytes).map_err(|refusal| {
            refusal.into_error(
                "spki secret key",
                "expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER",
            )
        })?;
        Ok(SpkiSigner { key })
    }

    /// Creates a signer from a PKCS#8 PEM secret key.
    ///
    /// `pem` holds one PEM block in the form of RFC 7468, and the block
    /// starts with `-----BEGIN PRIVATE KEY-----`. The block holds a PKCS#8
    /// `PrivateKeyInfo` DER.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] in these conditions. Each message starts with
    /// `spki secret key: `.
    ///
    /// - `pem` is not one PEM block.
    /// - The label of the block is not `PRIVATE KEY`.
    /// - The block does not hold a PKCS#8 `PrivateKeyInfo` DER. The message
    ///   is `spki secret key: expected PKCS#8 DER`.
    /// - [`from_secret_key`](Self::from_secret_key) refuses the key type, the
    ///   curve, the parameters, the modulus, or the primes of the key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<SpkiSigner> {
        let fail = |what: String| Error::Signature(format!("spki secret key: {what}"));
        let mut decoder =
            pem_rfc7468::Decoder::new(pem.as_bytes()).map_err(|e| fail(e.to_string()))?;
        let label = decoder.type_label();
        if label.as_bytes() != PRIVATE_KEY_LABEL {
            return Err(fail(format!("unexpected label \"{label}\"")));
        }
        let mut der = Zeroizing::new(Vec::new());
        decoder
            .decode_to_end(&mut der)
            .map_err(|e| fail(e.to_string()))?;
        let key = decode_pkcs8_key(&der)
            .map_err(|refusal| refusal.into_error("spki secret key", "expected PKCS#8 DER"))?;
        Ok(SpkiSigner { key })
    }

    /// Returns the SubjectPublicKeyInfo DER of the public key of this signer.
    ///
    /// The DER of an EC key holds the uncompressed point of the key. The DER
    /// of an RSA key holds the algorithm `rsaEncryption` with `NULL`
    /// parameters, and the modulus and the exponent. A [`SpkiVerifier`]
    /// trusts these bytes. The base64 body of a PEM `PUBLIC KEY` block
    /// decodes to the same bytes.
    pub fn public_key_der(&self) -> Vec<u8> {
        self.key.public_key().canonical_der()
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
        let signature = self.key.sign(data);
        Box::pin(async move { signature })
    }
}

/// The verifier of the spki engine.
///
/// The verifier holds the effective set of trusted keys. It reads the
/// signatures under the key `ostree.sign.spki` in the detached metadata.
///
/// # Formats
///
/// A signature is in the form that [`SpkiSigner`] writes for the key type: a
/// DER ECDSA signature for a P-256 or a P-384 key, and a raw PKCS#1 v1.5
/// signature with the length of the modulus for an RSA key. A blob in another
/// form does not verify. The fixed-width `r || s` form of an ECDSA signature,
/// 64 bytes for P-256 and 96 bytes for P-384, is such a blob.
///
/// A public key is a SubjectPublicKeyInfo DER, which is the base64 body of a
/// PEM `PUBLIC KEY` block. The algorithm OID of the key selects its key type,
/// and the curve OID selects the curve. The verifier takes these key types:
///
/// - `id-ecPublicKey` on the curve `prime256v1`, with a compressed or an
///   uncompressed point, with the feature `sign-spki-p256`.
/// - `id-ecPublicKey` on the curve `secp384r1`, with a compressed or an
///   uncompressed point, with the feature `sign-spki-p384`.
/// - `rsaEncryption` with `NULL` parameters and a modulus of 2048 to 16384
///   bits, with the feature `sign-spki-rsa`. The public key of a multi-prime
///   key is a modulus and an exponent, and the verifier takes it.
///
/// The verifier refuses each other key type and curve, an EC key with
/// explicit curve parameters, and a key of a type that the build has no code
/// for. A bare SEC1 point is not a public key of the verifier. A public key
/// file holds PEM `PUBLIC KEY` blocks, and [`spki_public_keys`] reads it. The
/// `trusted.spki` and `revoked.spki` files of the system key store are public
/// key files.
///
/// # Verification
///
/// A trusted key tries a blob only when the blob has the signature form of
/// the key type. For a P-256 or a P-384 key, that is a strict DER parse of a
/// signature on the curve of the key. The two integers of a P-256 signature
/// also fit the field of P-384, so each P-384 key also tries each DER blob of
/// a P-256 key. This verify fails, and the result does not change. For an RSA
/// key, the length of the blob is the length of the modulus. A blob is valid
/// only when a trusted key verifies it. A blob that no trusted key verifies
/// is not valid, and it is not an error. A store can hold keys of each type
/// together.
///
/// For a valid blob, the [`SignatureInfo`] gives these fields of the first
/// trusted key that verifies it:
///
/// - `pubkey_algorithm`: `p256`, `p384`, or `rsa`.
/// - `fingerprint`: the SHA-256 of the SubjectPublicKeyInfo DER of the key,
///   in lowercase hex. The verifier encodes this DER again from the decoded
///   key: with an uncompressed point for an EC key, and with `NULL`
///   parameters for an RSA key. So two encodings of one key give one
///   fingerprint.
///
/// The verifier verifies in the call to [`Verifier::verify`], so the future
/// that this call returns is ready at once. Each key type signs the SHA-256
/// of the data. The verifier computes this hash one time for each call, when
/// the first trusted key tries a blob.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "sign-spki-p256")]
/// # {
/// use futures_lite::future::block_on;
/// use ostrya_sign::{Signer, SpkiSigner, SpkiVerifier, Verifier};
///
/// // The base64 of a PKCS#8 DER P-256 secret key.
/// let signer = SpkiSigner::from_base64(concat!(
///     "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
///     "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
///     "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
/// ))?;
/// let der = signer.public_key_der();
/// let verifier = SpkiVerifier::new([der], Vec::<&[u8]>::new())?;
/// let signature = block_on(signer.sign(b"commit bytes"))?;
/// // A DER signature starts with the tag of an ASN.1 `SEQUENCE`.
/// assert_eq!(signature[0], 0x30);
/// let outcome = block_on(verifier.verify(b"commit bytes", &[signature]))?;
/// assert!(outcome.valid);
/// assert_eq!(outcome.signatures[0].pubkey_algorithm.as_deref(), Some("p256"));
/// # }
/// # Ok::<(), ostrya_sign::Error>(())
/// ```
#[derive(Clone)]
pub struct SpkiVerifier {
    trusted: Vec<TrustedKey>,
}

impl SpkiVerifier {
    /// Creates a verifier that trusts each key in `trusted` that is not in `revoked`.
    ///
    /// Each key is in one of the [public-key forms](SpkiVerifier#formats) of
    /// the verifier. The function matches the keys by their decoded value: it
    /// encodes the SubjectPublicKeyInfo DER of each key again, with an
    /// uncompressed point for an EC key, and compares these bytes. So two
    /// encodings that differ only in point compression match. Two RSA keys
    /// match when their modulus and exponent are equal.
    ///
    /// The function returns an error for a key in either set that it refuses,
    /// so a revocation that the verifier cannot read fails closed.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if a key in `trusted` or `revoked` is refused.
    /// Each message starts with `spki public key: `.
    ///
    /// - The key type is not `id-ecPublicKey` or `rsaEncryption`. The message
    ///   is `spki public key: the key type <name> is not supported`. `<name>`
    ///   is a name such as `RSASSA-PSS` or `Ed25519`, or the dotted OID.
    /// - The build has no code for the key type or the curve of the key. The
    ///   message is `spki public key: this build has no code for <the key
    ///   type RSA | the curve P-256 | the curve P-384>; build with the
    ///   <feature> feature`.
    /// - The parameters of an `rsaEncryption` key are not `NULL`. The message
    ///   is `spki public key: the rsaEncryption parameters are not NULL`.
    /// - The modulus of an RSA key has fewer than 2048 bits or more than
    ///   16384 bits. The message is `spki public key: the RSA modulus has
    ///   <bits> bits; the engine takes 2048 to 16384 bits`.
    /// - The modulus and the exponent of an RSA key do not make a valid key,
    ///   for example an even modulus. The message starts with
    ///   `spki public key: the RSA key is not valid: `.
    /// - The key names a curve other than P-256 and P-384. The message is
    ///   `spki public key: the curve <name> is not supported`.
    /// - The key has explicit curve parameters. The message is
    ///   `spki public key: the EC key has explicit curve parameters`.
    /// - The key has no curve. The message is
    ///   `spki public key: the EC key does not name its curve`.
    /// - The key is not a SubjectPublicKeyInfo DER, its point is not in the
    ///   compressed or the uncompressed form, its point is not on the curve,
    ///   or its RSA key is not an `RSAPublicKey` DER. The message is
    ///   `spki public key: expected SubjectPublicKeyInfo DER`.
    pub fn new<T, R>(trusted: T, revoked: R) -> Result<SpkiVerifier>
    where
        T: IntoIterator,
        T::Item: AsRef<[u8]>,
        R: IntoIterator,
        R::Item: AsRef<[u8]>,
    {
        let revoked: HashSet<Vec<u8>> = revoked
            .into_iter()
            .map(|k| public_key(k.as_ref()).map(|key| key.canonical_der()))
            .collect::<Result<_>>()?;
        let mut keys = Vec::new();
        for key in trusted {
            let key = public_key(key.as_ref())?;
            let der = key.canonical_der();
            if revoked.contains(&der) {
                continue;
            }
            keys.push(TrustedKey::new(key, &der));
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
    /// - [`Error::Signature`] if a key in either set is refused, as for
    ///   [`new`](Self::new).
    pub fn from_sign_keys(keys: SignKeys) -> Result<SpkiVerifier> {
        SpkiVerifier::new(keys.trusted, keys.revoked)
    }

    /// Creates a verifier that trusts each key of the PEM text `pem`.
    ///
    /// The function reads `pem` as [`spki_public_keys`] reads a public key
    /// file. Each `PUBLIC KEY` block of the text holds one key. An empty text,
    /// or a text of white space only, gives a verifier that trusts no key.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if [`spki_public_keys`] refuses the text. The
    ///   message starts with `the spki public key text`.
    pub fn from_pem(pem: impl AsRef<[u8]>) -> Result<SpkiVerifier> {
        let keys = public_keys(pem.as_ref(), "the spki public key text")?;
        Ok(SpkiVerifier {
            trusted: keys
                .into_iter()
                .map(|(_, key)| {
                    let der = key.canonical_der();
                    TrustedKey::new(key, &der)
                })
                .collect(),
        })
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
        let prehash = Prehash::new(data);
        for blob in signatures {
            let forms = SignatureForms::parse(blob);
            let info = match self
                .trusted
                .iter()
                .find(|t| t.key.verifies(&prehash, &forms))
            {
                Some(trusted) => SignatureInfo {
                    valid: true,
                    fingerprint: Some(trusted.fingerprint.clone()),
                    pubkey_algorithm: Some(trusted.key.algorithm().into()),
                    ..SignatureInfo::default()
                },
                None => SignatureInfo {
                    key_missing: true,
                    ..SignatureInfo::default()
                },
            };
            outcome.valid |= info.valid;
            outcome.signatures.push(info);
        }
        Box::pin(async move { Ok(outcome) })
    }
}

/// Reads the public keys of a public key file of the spki engine.
///
/// `text` is the content of the file. The file holds PEM `PUBLIC KEY` blocks,
/// and each block holds one key. The function returns the
/// SubjectPublicKeyInfo DER of each block as the file holds it, in the order
/// of the file. Each error message names the file with `subject`.
///
/// # Rules
///
/// - A line ends at LF, and one CR at the end of a line is removed. A CR at
///   another position is a byte of the line. The text can hold any byte
///   outside the blocks.
/// - Leading and trailing spaces and tabs of a line are removed before the
///   line is compared with a boundary. A block starts at the line
///   `-----BEGIN LABEL-----` and stops at the line `-----END LABEL-----`. A
///   line with other text is not a boundary line.
/// - Text outside the blocks is ignored. A line of base64 text outside a
///   block is also ignored.
/// - A body line is not empty and holds no CR. `pem-rfc7468` decodes the
///   body in the form of RFC 7468: lines of 64 base64 characters, the last
///   line shorter or equal, and no headers.
/// - An empty text, or a text of white space only, holds no key. White space
///   is space, horizontal tab, LF, form feed, and CR. The function returns an
///   empty list.
///
/// # Errors
///
/// [`Error::Signature`] if the function refuses the file. The function
/// refuses the whole file, also when other blocks of the file are valid. A
/// message names the line of the block where it can. The function refuses
/// the file in these conditions:
///
/// - A block has no END line, or its END label is not its BEGIN label.
/// - A BEGIN line is in a block.
/// - A block has a label other than `PUBLIC KEY`. The message is
///   `<subject>, line <n>: unexpected label "<label>"`.
/// - A `PUBLIC KEY` block does not decode. The message starts with
///   `<subject>, line <n>: the PUBLIC KEY block does not decode: `.
/// - A `PUBLIC KEY` block holds a key that [`SpkiVerifier::new`] refuses for
///   its key type, its curve, its parameters, or its modulus. The message is
///   `<subject>, line <n>: <reason>`, with the reason of
///   [`SpkiVerifier::new`], for example `the key type Ed25519 is not
///   supported`.
/// - A `PUBLIC KEY` block holds no other public key that
///   [`SpkiVerifier::new`] accepts. The message is
///   `<subject>, line <n>: the PUBLIC KEY block holds no valid public key`.
/// - The text is not empty or white space, and holds no block. The message is
///   `<subject> holds no PEM PUBLIC KEY block`.
pub fn spki_public_keys(text: &[u8], subject: &str) -> Result<Vec<Vec<u8>>> {
    let keys = public_keys(text, subject)?;
    Ok(keys.into_iter().map(|(der, _)| der).collect())
}

/// Reads the public keys of a public key file as [`spki_public_keys`] does,
/// and returns the DER and the decoded key of each block.
fn public_keys(text: &[u8], subject: &str) -> Result<Vec<(Vec<u8>, Public)>> {
    if text.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let blocks = labeled_blocks(text, subject, PUBLIC_KEY_LABEL)?;
    let mut keys = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let mut der = block.decode().map_err(|e| {
            refuse(
                subject,
                format!(
                    "line {}: the PUBLIC KEY block does not decode: {e}",
                    block.line
                ),
            )
        })?;
        let key = decode_public_key(&der).map_err(|refusal| {
            let reason = match refusal {
                Refusal::Form => "the PUBLIC KEY block holds no valid public key".into(),
                Refusal::Key(reason) => reason,
            };
            refuse(subject, format!("line {}: {reason}", block.line))
        })?;
        keys.push((std::mem::take(&mut *der), key));
    }
    Ok(keys)
}

/// Reads the signers of a secret key file of the spki engine.
///
/// `text` is the content of the file. The file holds PEM `PRIVATE KEY`
/// blocks, and each block holds one PKCS#8 `PrivateKeyInfo` DER of a P-256,
/// a P-384, or an RSA key. The function returns one signer for each block, in
/// the order of the file. Each error message names the file with `subject`.
///
/// The function takes `text` by value and wipes it before it returns. It also
/// wipes the DER of each block.
///
/// # Rules
///
/// The rules of [`spki_public_keys`] for lines, boundary lines, text outside
/// the blocks, and block bodies apply. An empty text, or a text of white space
/// only, holds no block, and the function refuses it.
///
/// # Errors
///
/// [`Error::Signature`] if the function refuses the file. The function
/// refuses the whole file, also when other blocks of the file are valid. A
/// message names the line of the block where it can. The function refuses
/// the file in these conditions:
///
/// - A block has no END line, or its END label is not its BEGIN label.
/// - A BEGIN line is in a block.
/// - A block has a label other than `PRIVATE KEY`. The message is
///   `<subject>, line <n>: unexpected label "<label>"`.
/// - A `PRIVATE KEY` block does not decode. The message starts with
///   `<subject>, line <n>: the PRIVATE KEY block does not decode: `.
/// - A `PRIVATE KEY` block holds a PKCS#8 key that
///   [`SpkiSigner::from_secret_key`] refuses for its key type, its curve, its
///   parameters, its modulus, or its primes. The message is
///   `<subject>, line <n>: <reason>`, with the reason of
///   [`SpkiSigner::from_secret_key`], for example
///   `the key type Ed25519 is not supported`.
/// - A `PRIVATE KEY` block holds no other PKCS#8 key that
///   [`SpkiSigner::from_secret_key`] accepts. The message is
///   `<subject>, line <n>: the PRIVATE KEY block holds no valid PKCS#8 key`.
/// - The text holds no block. The message is
///   `<subject> holds no PEM PRIVATE KEY block`.
pub fn spki_secret_keys(text: Vec<u8>, subject: &str) -> Result<Vec<SpkiSigner>> {
    let text = Zeroizing::new(text);
    let blocks = labeled_blocks(&text, subject, PRIVATE_KEY_LABEL)?;
    let mut signers = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let der = block.decode().map_err(|e| {
            refuse(
                subject,
                format!(
                    "line {}: the PRIVATE KEY block does not decode: {e}",
                    block.line
                ),
            )
        })?;
        let key = decode_pkcs8_key(&der).map_err(|refusal| {
            let reason = match refusal {
                Refusal::Form => "the PRIVATE KEY block holds no valid PKCS#8 key".into(),
                Refusal::Key(reason) => reason,
            };
            refuse(subject, format!("line {}: {reason}", block.line))
        })?;
        signers.push(SpkiSigner { key });
    }
    Ok(signers)
}

/// Reads the signers of a line file of secret keys of the spki engine.
///
/// `text` is the content of the file. Each line holds the base64 of one
/// secret key, in a form that [`SpkiSigner::from_secret_key`] accepts: a
/// PKCS#8, a SEC1, or a PKCS#1 DER. The function returns one signer for each
/// line, in the order of the file. Each error message names the file with
/// `subject`.
///
/// A line ends at LF, and the function removes one CR at the end of each
/// line. The last line can have no line end.
///
/// The function takes `text` by value and wipes it before it returns. It also
/// wipes the decoded DER of each key.
///
/// # Errors
///
/// [`Error::Signature`] if the function refuses the file. The function
/// refuses the whole file, also when other lines of the file are valid:
///
/// - The text is empty. The message is `<subject> holds no key`.
/// - A line is empty. The message is `<subject>, line <n> is empty`.
/// - A line holds white space. The message is
///   `<subject>, line <n> holds white space`.
/// - A line is not the base64 of a secret key that
///   [`SpkiSigner::from_secret_key`] accepts. The message is
///   `<subject>, line <n>: <reason>`.
pub fn spki_secret_key_lines(text: Vec<u8>, subject: &str) -> Result<Vec<SpkiSigner>> {
    let text = Zeroizing::new(text);
    if text.is_empty() {
        return Err(Error::Signature(format!("{subject} holds no key")));
    }
    let body = text.strip_suffix(b"\n").unwrap_or(&text);
    let mut signers = Vec::new();
    for (index, line) in body.split(|&byte| byte == b'\n').enumerate() {
        let number = index + 1;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return Err(Error::Signature(format!(
                "{subject}, line {number} is empty"
            )));
        }
        if line.iter().any(u8::is_ascii_whitespace) {
            return Err(Error::Signature(format!(
                "{subject}, line {number} holds white space"
            )));
        }
        let line = std::str::from_utf8(line)
            .map_err(|_| refuse(subject, format!("line {number}: the line is not base64")))?;
        // With no white space in the line, the decode of `from_base64` is the
        // strict decode, and the decoded key is wiped.
        let signer = SpkiSigner::from_base64(line).map_err(|e| {
            let reason = match e {
                Error::Signature(reason) => reason,
                other => other.to_string(),
            };
            refuse(subject, format!("line {number}: {reason}"))
        })?;
        signers.push(signer);
    }
    Ok(signers)
}

/// Splits `text` into its PEM blocks, and refuses the text if a block has a
/// label other than `label` or if the text holds no block.
fn labeled_blocks<'a>(text: &'a [u8], subject: &str, label: &[u8]) -> Result<Vec<pem::Block<'a>>> {
    let blocks = pem::split(text).map_err(|e| refuse(subject, e))?;
    if let Some(other) = blocks.iter().find(|b| b.label != label) {
        return Err(refuse(
            subject,
            format!(
                "line {}: unexpected label \"{}\"",
                other.line,
                other.label_text()
            ),
        ));
    }
    if blocks.is_empty() {
        return Err(Error::Signature(format!(
            "{subject} holds no PEM {} block",
            String::from_utf8_lossy(label)
        )));
    }
    Ok(blocks)
}

/// Returns the error that refuses the key file `subject` for `what`.
fn refuse(subject: &str, what: String) -> Error {
    Error::Signature(format!("{subject}, {what}"))
}

/// Returns `text` with each ASCII white space character removed.
///
/// The function copies `text` only if it holds white space.
fn without_white_space(text: &str) -> Cow<'_, str> {
    if !text.bytes().any(|b| b.is_ascii_whitespace()) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    out.extend(text.chars().filter(|c| !c.is_ascii_whitespace()));
    Cow::Owned(out)
}

/// The secret key of a signer, for each key type.
#[derive(Clone)]
enum Secret {
    /// An ECDSA P-256 key.
    #[cfg(feature = "sign-spki-p256")]
    P256(p256::ecdsa::SigningKey),
    /// An ECDSA P-384 key that signs the SHA-256 of the data.
    #[cfg(feature = "sign-spki-p384")]
    P384(::p384::ecdsa::SigningKey),
    /// An RSA key that signs with PKCS#1 v1.5 and SHA-256.
    #[cfg(feature = "sign-spki-rsa")]
    Rsa(Box<::rsa::pkcs1v15::SigningKey<::rsa::sha2::Sha256>>),
}

impl Secret {
    /// Returns the public key of this secret key.
    fn public_key(&self) -> Public {
        match self {
            #[cfg(feature = "sign-spki-p256")]
            Secret::P256(key) => Public::P256(*key.verifying_key()),
            #[cfg(feature = "sign-spki-p384")]
            Secret::P384(key) => Public::P384(*key.verifying_key()),
            #[cfg(feature = "sign-spki-rsa")]
            Secret::Rsa(key) => Public::Rsa(rsa::public_of(key)),
        }
    }

    /// Signs `data` and returns the signature in the form of the key type.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            #[cfg(feature = "sign-spki-p256")]
            Secret::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(data);
                Ok(signature.to_der().to_bytes().into_vec())
            }
            #[cfg(feature = "sign-spki-p384")]
            Secret::P384(key) => Ok(p384::sign(key, data)),
            #[cfg(feature = "sign-spki-rsa")]
            Secret::Rsa(key) => rsa::sign(key, data),
        }
    }
}

/// A public key, for each key type.
#[derive(Clone)]
enum Public {
    /// An ECDSA P-256 key.
    #[cfg(feature = "sign-spki-p256")]
    P256(p256::ecdsa::VerifyingKey),
    /// An ECDSA P-384 key that verifies a signature of the SHA-256 of the
    /// data.
    #[cfg(feature = "sign-spki-p384")]
    P384(::p384::ecdsa::VerifyingKey),
    /// An RSA key that verifies PKCS#1 v1.5 with SHA-256.
    #[cfg(feature = "sign-spki-rsa")]
    Rsa(::rsa::pkcs1v15::VerifyingKey<::rsa::sha2::Sha256>),
}

impl Public {
    /// Returns the name of the key type, the value of
    /// [`SignatureInfo::pubkey_algorithm`].
    fn algorithm(&self) -> &'static str {
        match self {
            #[cfg(feature = "sign-spki-p256")]
            Public::P256(_) => "p256",
            #[cfg(feature = "sign-spki-p384")]
            Public::P384(_) => "p384",
            #[cfg(feature = "sign-spki-rsa")]
            Public::Rsa(_) => "rsa",
        }
    }

    /// Returns the SubjectPublicKeyInfo DER of the key, encoded again from the
    /// decoded key: an uncompressed EC point, or `rsaEncryption` with `NULL`
    /// parameters and the `RSAPublicKey` of the modulus and the exponent.
    fn canonical_der(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "sign-spki-p256")]
            Public::P256(key) => p256::PublicKey::from(key)
                .to_public_key_der()
                .expect("P-256 public key always encodes to SPKI DER")
                .into_vec(),
            #[cfg(feature = "sign-spki-p384")]
            Public::P384(key) => p384::canonical_der(key),
            #[cfg(feature = "sign-spki-rsa")]
            Public::Rsa(key) => ::rsa::pkcs8::EncodePublicKey::to_public_key_der(key)
                .expect("RSA public key always encodes to SPKI DER")
                .into_vec(),
        }
    }

    /// Returns `true` if this key verifies the signature in `forms` of the
    /// data of `prehash`. The key tries only the form of its key type.
    fn verifies(&self, prehash: &Prehash<'_>, forms: &SignatureForms<'_>) -> bool {
        match self {
            #[cfg(feature = "sign-spki-p256")]
            Public::P256(key) => forms
                .p256
                .as_ref()
                .is_some_and(|signature| key.verify_prehash(prehash.get(), signature).is_ok()),
            #[cfg(feature = "sign-spki-p384")]
            Public::P384(key) => p384::verifies(key, prehash, forms.p384.as_ref()),
            #[cfg(feature = "sign-spki-rsa")]
            Public::Rsa(key) => rsa::verifies(key, prehash, forms.blob),
        }
    }
}

/// The SHA-256 of the data of a verify call.
///
/// Each key type of the engine signs the SHA-256 of the data. The verifier
/// computes the hash one time for each call, when the first key tries a
/// blob, and each key verifies with this hash.
struct Prehash<'a> {
    /// The data.
    data: &'a [u8],
    /// The SHA-256 of `data`, after the first call to [`Prehash::get`].
    digest: OnceCell<Checksum>,
}

impl Prehash<'_> {
    /// Returns the prehash of `data`. The hash is not computed yet.
    fn new(data: &[u8]) -> Prehash<'_> {
        Prehash {
            data,
            digest: OnceCell::new(),
        }
    }

    /// Returns the SHA-256 of the data. The first call computes it.
    fn get(&self) -> &[u8] {
        self.digest
            .get_or_init(|| Checksum::sha256(self.data))
            .as_bytes()
    }
}

/// A trusted key of a verifier.
#[derive(Clone)]
struct TrustedKey {
    /// The key.
    key: Public,
    /// The lowercase hex SHA-256 of the canonical DER of the key.
    fingerprint: String,
}

impl TrustedKey {
    /// Returns the trusted key of `key`, whose canonical DER is `der`.
    fn new(key: Public, der: &[u8]) -> TrustedKey {
        TrustedKey {
            key,
            fingerprint: Checksum::sha256(der).to_hex(),
        }
    }
}

/// A signature blob, parsed in the signature form of each key type.
struct SignatureForms<'a> {
    /// The blob. An RSA key reads it as it is, because the form of an RSA
    /// signature depends on the size of the key.
    #[cfg_attr(not(feature = "sign-spki-rsa"), allow(dead_code))]
    blob: &'a [u8],
    /// The blob as a DER ECDSA P-256 signature, if it parses as one.
    #[cfg(feature = "sign-spki-p256")]
    p256: Option<p256::ecdsa::Signature>,
    /// The blob as a DER ECDSA P-384 signature, if it parses as one.
    #[cfg(feature = "sign-spki-p384")]
    p384: Option<::p384::ecdsa::Signature>,
}

impl SignatureForms<'_> {
    /// Parses `blob` in the signature form of each key type.
    fn parse(blob: &[u8]) -> SignatureForms<'_> {
        SignatureForms {
            blob,
            #[cfg(feature = "sign-spki-p256")]
            p256: p256::ecdsa::Signature::from_der(blob).ok(),
            #[cfg(feature = "sign-spki-p384")]
            p384: ::p384::ecdsa::Signature::from_der(blob).ok(),
        }
    }
}

/// The key types of the engine.
enum KeyType {
    /// ECDSA on the P-256 curve.
    #[cfg(feature = "sign-spki-p256")]
    P256,
    /// ECDSA on the P-384 curve.
    #[cfg(feature = "sign-spki-p384")]
    P384,
    /// RSA, key type `rsaEncryption`.
    #[cfg(feature = "sign-spki-rsa")]
    Rsa,
}

/// Why a key decoder refuses its bytes.
enum Refusal {
    /// The bytes are not in a form that the decoder reads.
    Form,
    /// The bytes hold a key that the engine does not take. The value is the
    /// reason.
    Key(String),
}

impl Refusal {
    /// Returns the error of this refusal. The message starts with `what`. A
    /// [`Refusal::Form`] gives the reason `form`.
    fn into_error(self, what: &str, form: &str) -> Error {
        match self {
            Refusal::Form => Error::Signature(format!("{what}: {form}")),
            Refusal::Key(reason) => Error::Signature(format!("{what}: {reason}")),
        }
    }
}

/// Returns the name of the key type or curve `oid`, or its dotted form.
fn oid_name(oid: ObjectIdentifier) -> String {
    OID_NAMES
        .iter()
        .find(|(known, _)| *known == oid)
        .map_or_else(|| oid.to_string(), |(_, name)| (*name).to_owned())
}

/// Returns the refusal of a key of a type or on a curve that the build has no
/// code for. `what` names the key type or the curve, and `feature` names the
/// feature that adds the code.
#[cfg(not(all(
    feature = "sign-spki-p256",
    feature = "sign-spki-p384",
    feature = "sign-spki-rsa"
)))]
fn missing_feature(what: &str, feature: &str) -> Refusal {
    Refusal::Key(format!(
        "this build has no code for {what}; build with the {feature} feature"
    ))
}

/// Selects the key type from the `AlgorithmIdentifier` of a key.
fn key_type(algorithm: &AlgorithmIdentifierRef<'_>) -> std::result::Result<KeyType, Refusal> {
    match algorithm.oid {
        oid if oid == ID_EC_PUBLIC_KEY => match ec_curve(algorithm.parameters)? {
            #[cfg(feature = "sign-spki-p256")]
            curve if curve == SECP256R1 => Ok(KeyType::P256),
            #[cfg(not(feature = "sign-spki-p256"))]
            curve if curve == SECP256R1 => {
                Err(missing_feature("the curve P-256", "sign-spki-p256"))
            }
            #[cfg(feature = "sign-spki-p384")]
            curve if curve == SECP384R1 => Ok(KeyType::P384),
            #[cfg(not(feature = "sign-spki-p384"))]
            curve if curve == SECP384R1 => {
                Err(missing_feature("the curve P-384", "sign-spki-p384"))
            }
            curve => Err(unsupported_curve(curve)),
        },
        #[cfg(feature = "sign-spki-rsa")]
        oid if oid == RSA_ENCRYPTION => rsa_parameters(algorithm).map(|()| KeyType::Rsa),
        #[cfg(not(feature = "sign-spki-rsa"))]
        oid if oid == RSA_ENCRYPTION => rsa_parameters(algorithm)
            .and_then(|()| Err(missing_feature("the key type RSA", "sign-spki-rsa"))),
        oid => Err(Refusal::Key(format!(
            "the key type {} is not supported",
            oid_name(oid)
        ))),
    }
}

/// Returns the refusal of a key on the curve `curve`, which is outside the
/// key types of the engine.
fn unsupported_curve(curve: ObjectIdentifier) -> Refusal {
    Refusal::Key(format!("the curve {} is not supported", oid_name(curve)))
}

/// Checks that the parameters of an `rsaEncryption` `AlgorithmIdentifier`
/// are `NULL`.
fn rsa_parameters(algorithm: &AlgorithmIdentifierRef<'_>) -> std::result::Result<(), Refusal> {
    if algorithm.parameters == Some(AnyRef::NULL) {
        return Ok(());
    }
    Err(Refusal::Key(
        "the rsaEncryption parameters are not NULL".into(),
    ))
}

/// Returns the curve OID of the `parameters` of an EC key, or `None` if the
/// value names no curve.
///
/// The parameters are a curve OID, or a `SEQUENCE` of explicit curve
/// parameters, which the engine refuses.
fn named_curve(parameters: AnyRef<'_>) -> std::result::Result<Option<ObjectIdentifier>, Refusal> {
    match parameters.tag() {
        Tag::ObjectIdentifier => parameters.decode_as().map(Some).map_err(|_| Refusal::Form),
        Tag::Sequence => Err(Refusal::Key(EXPLICIT_PARAMETERS.into())),
        _ => Ok(None),
    }
}

/// Returns the named curve of the `parameters` of the `AlgorithmIdentifier`
/// of an EC key.
fn ec_curve(parameters: Option<AnyRef<'_>>) -> std::result::Result<ObjectIdentifier, Refusal> {
    match parameters.map(named_curve).transpose()?.flatten() {
        Some(curve) => Ok(curve),
        None => Err(Refusal::Key("the EC key does not name its curve".into())),
    }
}

/// Decodes a SubjectPublicKeyInfo DER into a public key.
fn decode_public_key(der: &[u8]) -> std::result::Result<Public, Refusal> {
    let info = SubjectPublicKeyInfoRef::from_der(der).map_err(|_| Refusal::Form)?;
    match key_type(&info.algorithm)? {
        #[cfg(feature = "sign-spki-p256")]
        KeyType::P256 => {
            ec_point_form(&info)?;
            p256::ecdsa::VerifyingKey::try_from(info)
                .map(Public::P256)
                .map_err(|_| Refusal::Form)
        }
        #[cfg(feature = "sign-spki-p384")]
        KeyType::P384 => p384::public_key(info).map(Public::P384),
        #[cfg(feature = "sign-spki-rsa")]
        KeyType::Rsa => rsa::public_key(&info).map(Public::Rsa),
    }
}

/// Checks that the point of an EC SubjectPublicKeyInfo is compressed (0x02,
/// 0x03) or uncompressed (0x04). The compact form (0x05) leaves the choice of
/// y to the decoder, so the engine refuses it.
#[cfg(any(feature = "sign-spki-p256", feature = "sign-spki-p384"))]
fn ec_point_form(info: &SubjectPublicKeyInfoRef<'_>) -> std::result::Result<(), Refusal> {
    match info.subject_public_key.as_bytes().and_then(<[u8]>::first) {
        Some(0x02..=0x04) => Ok(()),
        _ => Err(Refusal::Form),
    }
}

/// Decodes a SubjectPublicKeyInfo DER into a public key, with the error of
/// [`SpkiVerifier::new`].
fn public_key(der: &[u8]) -> Result<Public> {
    decode_public_key(der).map_err(|refusal| {
        refusal.into_error("spki public key", "expected SubjectPublicKeyInfo DER")
    })
}

/// Decodes secret-key bytes. The bytes are a PKCS#8 `PrivateKeyInfo` DER, a
/// PKCS#1 `RSAPrivateKey` DER, or a SEC1 `ECPrivateKey` DER that names its
/// curve.
///
/// After its version, a PKCS#8 `PrivateKeyInfo` holds an
/// `AlgorithmIdentifier`, a PKCS#1 `RSAPrivateKey` holds an `INTEGER`, and a
/// SEC1 `ECPrivateKey` holds an `OCTET STRING`. So at most one of the three
/// structures reads the bytes.
fn decode_secret_key(bytes: &[u8]) -> std::result::Result<Secret, Refusal> {
    if let Ok(info) = PrivateKeyInfo::from_der(bytes) {
        return decode_pkcs8(info);
    }
    if is_pkcs1_private_key(bytes) {
        #[cfg(feature = "sign-spki-rsa")]
        return rsa::secret_key(bytes).map(|key| Secret::Rsa(Box::new(key)));
        #[cfg(not(feature = "sign-spki-rsa"))]
        return Err(missing_feature("the key type RSA", "sign-spki-rsa"));
    }
    let parameters = sec1_parameters(bytes).map_err(|_| Refusal::Form)?;
    match parameters.map(named_curve).transpose()?.flatten() {
        None => Err(Refusal::Key("the SEC1 key does not name its curve".into())),
        #[cfg(feature = "sign-spki-p256")]
        Some(curve) if curve == SECP256R1 => p256::SecretKey::from_sec1_der(bytes)
            .map(|secret| Secret::P256((&secret).into()))
            .map_err(|_| Refusal::Form),
        #[cfg(not(feature = "sign-spki-p256"))]
        Some(curve) if curve == SECP256R1 => {
            Err(missing_feature("the curve P-256", "sign-spki-p256"))
        }
        #[cfg(feature = "sign-spki-p384")]
        Some(curve) if curve == SECP384R1 => p384::sec1_secret_key(bytes).map(Secret::P384),
        #[cfg(not(feature = "sign-spki-p384"))]
        Some(curve) if curve == SECP384R1 => {
            Err(missing_feature("the curve P-384", "sign-spki-p384"))
        }
        Some(curve) => Err(unsupported_curve(curve)),
    }
}

/// Returns `true` if `bytes` hold the fields of a PKCS#1 `RSAPrivateKey` DER:
/// a `SEQUENCE` of the version 0 or 1, then eight unsigned `INTEGER`s. With
/// the version 1, the `otherPrimeInfos` field follows: a `SEQUENCE` of
/// `SEQUENCE`s of three unsigned `INTEGER`s. No field follows.
///
/// A two-prime key has the version 0, and a multi-prime key the version 1.
/// The function does not check the values of the integers.
fn is_pkcs1_private_key(bytes: &[u8]) -> bool {
    let read = || -> der::Result<()> {
        let mut reader = SliceReader::new(bytes)?;
        reader.sequence(|seq| {
            let version = u8::decode(seq)?;
            if version > 1 {
                return Err(Tag::Integer.value_error());
            }
            for _ in 0..8 {
                UintRef::decode(seq)?;
            }
            if version == 1 {
                seq.sequence(|infos| {
                    while !infos.is_finished() {
                        infos.sequence(|info| {
                            for _ in 0..3 {
                                UintRef::decode(info)?;
                            }
                            Ok(())
                        })?;
                    }
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        reader.finish(())
    };
    read().is_ok()
}

/// Decodes a PKCS#8 `PrivateKeyInfo` DER.
fn decode_pkcs8_key(der: &[u8]) -> std::result::Result<Secret, Refusal> {
    decode_pkcs8(PrivateKeyInfo::from_der(der).map_err(|_| Refusal::Form)?)
}

/// Decodes the secret key of a PKCS#8 `PrivateKeyInfo`.
fn decode_pkcs8(info: PrivateKeyInfo<'_>) -> std::result::Result<Secret, Refusal> {
    match key_type(&info.algorithm)? {
        #[cfg(feature = "sign-spki-p256")]
        KeyType::P256 => {
            inner_curve_is(info.private_key, SECP256R1)?;
            p256::SecretKey::try_from(info)
                .map(|secret| Secret::P256((&secret).into()))
                .map_err(|_| Refusal::Form)
        }
        #[cfg(feature = "sign-spki-p384")]
        KeyType::P384 => p384::pkcs8_secret_key(info).map(Secret::P384),
        #[cfg(feature = "sign-spki-rsa")]
        KeyType::Rsa => rsa::secret_key(info.private_key).map(|key| Secret::Rsa(Box::new(key))),
    }
}

/// Checks the `parameters` field of the `ECPrivateKey` DER `der` of a PKCS#8
/// EC key whose `AlgorithmIdentifier` names `curve`.
///
/// The field can be absent. If it is present, it names `curve`. A field that
/// names no curve, such as a `NULL`, is refused as another curve.
#[cfg(any(feature = "sign-spki-p256", feature = "sign-spki-p384"))]
fn inner_curve_is(der: &[u8], curve: ObjectIdentifier) -> std::result::Result<(), Refusal> {
    let Some(parameters) = sec1_parameters(der).map_err(|_| Refusal::Form)? else {
        return Ok(());
    };
    match named_curve(parameters)? {
        Some(named) if named == curve => Ok(()),
        _ => Err(Refusal::Key(
            "the ECPrivateKey names a curve other than the curve of the PKCS#8 key".into(),
        )),
    }
}

/// Returns the `parameters` field of a SEC1 `ECPrivateKey` DER, or `None` if
/// the key has no `parameters` field.
///
/// The structure is `SEQUENCE { version INTEGER, privateKey OCTET STRING,
/// parameters [0] ECParameters OPTIONAL, publicKey [1] BIT STRING OPTIONAL }`.
/// The version is 1. The function reads the structure up to the `parameters`
/// field, and does not check the value of the field.
fn sec1_parameters(bytes: &[u8]) -> der::Result<Option<AnyRef<'_>>> {
    let mut reader = SliceReader::new(bytes)?;
    let parameters = reader.sequence(|seq| {
        if u8::decode(seq)? != 1 {
            return Err(Tag::Integer.value_error());
        }
        OctetStringRef::decode(seq)?;
        let parameters = ContextSpecific::<AnyRef<'_>>::decode_explicit(seq, TagNumber::N0)?;
        seq.read_slice(seq.remaining_len())?;
        Ok(parameters.map(|field| field.value))
    })?;
    reader.finish(parameters)
}

#[cfg(all(test, feature = "sign-spki-p256"))]
mod tests {
    use std::task::{Context, Poll, Waker};

    use futures_lite::future::block_on;
    use p256::SecretKey;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

    use super::*;

    /// The subject of the reader in the tests.
    const SUBJECT: &str = "the key file 'k'";

    /// Returns a signer of the scalar `[byte; 32]`.
    fn signer(byte: u8) -> SpkiSigner {
        SpkiSigner {
            key: Secret::P256(SigningKey::from_slice(&[byte; 32]).unwrap()),
        }
    }

    /// Returns the P-256 signing key of `signer`.
    fn signing_key(signer: &SpkiSigner) -> &SigningKey {
        match &signer.key {
            Secret::P256(key) => key,
            #[cfg(feature = "sign-spki-p384")]
            Secret::P384(_) => panic!("the signer holds a P-384 key"),
            #[cfg(feature = "sign-spki-rsa")]
            Secret::Rsa(_) => panic!("the signer holds an RSA key"),
        }
    }

    /// Returns the P-256 public key of `signer`.
    fn verifying_key(signer: &SpkiSigner) -> VerifyingKey {
        *signing_key(signer).verifying_key()
    }

    /// Returns the curve OID of the `parameters` field of a SEC1 key DER.
    fn sec1_curve(der: &[u8]) -> Option<ObjectIdentifier> {
        sec1_parameters(der)
            .unwrap()
            .map(|parameters| parameters.decode_as().unwrap())
    }

    /// Returns a PEM block of `label` around `der`, with 64-column lines.
    fn pem_block(label: &str, der: &[u8]) -> String {
        let b64 = base64::encode(der);
        let mut text = format!("-----BEGIN {label}-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            text.push_str(std::str::from_utf8(chunk).unwrap());
            text.push('\n');
        }
        text.push_str(&format!("-----END {label}-----\n"));
        text
    }

    /// Returns the message of a refusal of the reader.
    fn refusal(text: &str) -> String {
        match spki_public_keys(text.as_bytes(), SUBJECT).unwrap_err() {
            Error::Signature(m) => m,
            other => panic!("not a signature error: {other}"),
        }
    }

    #[test]
    fn one_block_gives_its_key() {
        let der = signer(7).public_key_der();
        let text = pem_block("PUBLIC KEY", &der);
        assert_eq!(spki_public_keys(text.as_bytes(), SUBJECT).unwrap(), [der]);
    }

    #[test]
    fn two_blocks_give_two_keys_in_order() {
        let (a, b) = (signer(7).public_key_der(), signer(9).public_key_der());
        let text = format!(
            "first\n{}between\n{}after\n",
            pem_block("PUBLIC KEY", &a),
            pem_block("PUBLIC KEY", &b)
        );
        assert_eq!(spki_public_keys(text.as_bytes(), SUBJECT).unwrap(), [a, b]);
    }

    #[test]
    fn empty_and_white_space_text_give_no_keys() {
        for text in ["", "\n", " \t\r\n\n"] {
            assert!(
                spki_public_keys(text.as_bytes(), SUBJECT)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn base64_lines_are_refused() {
        let line = base64::encode(&signer(7).public_key_der());
        assert_eq!(
            refusal(&format!("{line}\n")),
            "the key file 'k' holds no PEM PUBLIC KEY block"
        );
    }

    #[test]
    fn another_label_refuses_the_file() {
        let key = pem_block("PUBLIC KEY", &signer(7).public_key_der());
        for label in ["CERTIFICATE", "PRIVATE KEY", "public key"] {
            let other = pem_block(label, &signer(9).public_key_der());
            assert_eq!(
                refusal(&format!("{key}{other}")),
                format!("the key file 'k', line 5: unexpected label \"{label}\""),
            );
        }
    }

    #[test]
    fn a_block_that_is_not_a_key_refuses_the_file() {
        let key = pem_block("PUBLIC KEY", &signer(7).public_key_der());
        let not_a_key = pem_block("PUBLIC KEY", b"not a key");
        assert_eq!(
            refusal(&format!("{key}{not_a_key}")),
            "the key file 'k', line 5: the PUBLIC KEY block holds no valid public key"
        );
        let blank = "-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----\n";
        assert!(
            refusal(blank)
                .starts_with("the key file 'k', line 1: the PUBLIC KEY block does not decode: ")
        );
    }

    #[test]
    fn cr_line_ends_are_refused() {
        let text = pem_block("PUBLIC KEY", &signer(7).public_key_der()).replace('\n', "\r");
        assert!(refusal(&text).ends_with("has no END line"));
    }

    #[test]
    fn a_split_error_names_the_file() {
        assert_eq!(
            refusal("-----BEGIN PUBLIC KEY-----\n"),
            "the key file 'k', line 1: the block \"PUBLIC KEY\" has no END line"
        );
    }

    #[test]
    fn from_pem_trusts_each_block() {
        let (a, b) = (signer(7), signer(9));
        let text = format!(
            "{}{}",
            pem_block("PUBLIC KEY", &a.public_key_der()),
            pem_block("PUBLIC KEY", &b.public_key_der())
        );
        let verifier = SpkiVerifier::from_pem(&text).unwrap();
        let signature = block_on(b.sign(b"data")).unwrap();
        assert!(
            block_on(verifier.verify(b"data", &[signature]))
                .unwrap()
                .valid
        );
        assert!(SpkiVerifier::from_pem("").unwrap().is_empty());
        assert!(SpkiVerifier::from_pem(base64::encode(&a.public_key_der())).is_err());
    }

    /// The SubjectPublicKeyInfo DER of the fixture key, in base64.
    const PUBLIC_SPKI_B64: &str = concat!(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8X83xylD3ibci0xjFKMR4bwUtTU/",
        "YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDnRAG1Ua8eR8SKbLQ==",
    );
    /// The secret key of the fixture, base64 of the PKCS#8 DER.
    const SECRET_PKCS8_B64: &str = concat!(
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
        "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
        "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
    );
    /// The secret key of the fixture, base64 of the SEC1 DER with the curve
    /// in its `parameters` field.
    const SECRET_SEC1_B64: &str = concat!(
        "MHcCAQEEINi+9PBLJ58xxEdEmGrDDSFHBr+t0GqQv95FbKD3q8yhoAoGCCqGSM49AwEHoUQD",
        "QgAE8X83xylD3ibci0xjFKMR4bwUtTU/YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDn",
        "RAG1Ua8eR8SKbLQ==",
    );

    /// Returns `b64` with a line break after each 64 characters.
    fn wrapped(b64: &str, line_end: &str) -> String {
        b64.as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(line_end)
    }

    /// Returns the message of a signature error.
    fn message<T>(result: Result<T>) -> String {
        match result {
            Err(Error::Signature(m)) => m,
            Err(other) => panic!("not a signature error: {other}"),
            Ok(_) => panic!("the call has to fail"),
        }
    }

    #[test]
    fn inline_secret_keys_in_pkcs8_and_sec1_are_accepted() {
        let want = base64::decode(PUBLIC_SPKI_B64).unwrap();
        for b64 in [SECRET_PKCS8_B64, SECRET_SEC1_B64] {
            for text in [
                b64.to_owned(),
                wrapped(b64, "\n"),
                wrapped(b64, "\r\n"),
                format!(" \t{}\n", wrapped(b64, "\n\x0c")),
            ] {
                let signer = SpkiSigner::from_base64(&text).unwrap();
                assert_eq!(signer.public_key_der(), want, "{text:?}");
            }
        }
    }

    #[test]
    fn a_raw_scalar_is_refused() {
        let scalar = [7u8; 32];
        let refused = "spki secret key: expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER";
        assert_eq!(message(SpkiSigner::from_secret_key(&scalar)), refused);
        assert_eq!(
            message(SpkiSigner::from_base64(&base64::encode(&scalar))),
            refused
        );
    }

    #[test]
    fn a_sec1_key_with_no_curve_is_refused() {
        let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
        // This encoder writes no `parameters` field.
        let der = secret.to_sec1_der().unwrap();
        assert_eq!(sec1_curve(&der), None);
        assert_eq!(
            message(SpkiSigner::from_secret_key(&der)),
            "spki secret key: the SEC1 key does not name its curve"
        );
        let named = base64::decode(SECRET_SEC1_B64).unwrap();
        assert_eq!(
            sec1_curve(&named),
            Some(ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"))
        );
    }

    #[test]
    fn a_sec1_key_of_another_curve_is_refused() {
        // The SEC1 key of the fixture, with secp521r1 in its `parameters`
        // field.
        let der = base64::decode(concat!(
            "MHQCAQEEINi+9PBLJ58xxEdEmGrDDSFHBr+t0GqQv95FbKD3q8yhoAcGBSuBBAAjoUQD",
            "QgAE8X83xylD3ibci0xjFKMR4bwUtTU/YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDn",
            "RAG1Ua8eR8SKbLQ==",
        ))
        .unwrap();
        assert_eq!(
            sec1_curve(&der),
            Some(ObjectIdentifier::new_unwrap("1.3.132.0.35"))
        );
        assert_eq!(
            message(SpkiSigner::from_secret_key(&der)),
            "spki secret key: the curve P-521 is not supported"
        );
    }

    #[test]
    fn other_inline_secret_forms_are_refused() {
        let pem_text = pem_block("PRIVATE KEY", &base64::decode(SECRET_PKCS8_B64).unwrap());
        assert_eq!(
            message(SpkiSigner::from_base64(&base64::encode(
                pem_text.as_bytes()
            ))),
            "spki secret key: expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER"
        );
        assert!(SpkiSigner::from_base64(&pem_text).is_err());
        for junk in [
            format!("{SECRET_PKCS8_B64}!"),
            format!("{}!{}", &SECRET_PKCS8_B64[..20], &SECRET_PKCS8_B64[20..]),
            format!("{}\x0b{}", &SECRET_PKCS8_B64[..20], &SECRET_PKCS8_B64[20..]),
        ] {
            assert!(
                matches!(SpkiSigner::from_base64(&junk), Err(Error::Core(_))),
                "{junk:?}"
            );
        }
    }

    #[test]
    fn a_public_key_is_a_subject_public_key_info() {
        let key = verifying_key(&signer(7));
        let uncompressed = signer(7).public_key_der();
        // The SubjectPublicKeyInfo of the compressed point: the header of the
        // P-256 key, then a BIT STRING of 34 bytes.
        let mut compressed = base64::decode("MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgA=").unwrap();
        compressed.extend_from_slice(key.to_encoded_point(true).as_bytes());
        for der in [&uncompressed, &compressed] {
            assert!(
                !SpkiVerifier::new([der], Vec::<&[u8]>::new())
                    .unwrap()
                    .is_empty()
            );
        }

        let refused = "spki public key: expected SubjectPublicKeyInfo DER";
        let point = key.to_encoded_point(false);
        let point_compressed = key.to_encoded_point(true);
        let pkcs8 = base64::decode(SECRET_PKCS8_B64).unwrap();
        let pem_text = pem_block("PUBLIC KEY", &uncompressed);
        for bytes in [
            point.as_bytes(),
            point_compressed.as_bytes(),
            &pkcs8,
            pem_text.as_bytes(),
        ] {
            assert_eq!(
                message(SpkiVerifier::new([bytes], Vec::<&[u8]>::new())),
                refused
            );
            assert_eq!(
                message(SpkiVerifier::new([&uncompressed[..]], [bytes])),
                refused
            );
        }
    }

    #[test]
    fn a_pem_block_with_a_sec1_point_is_refused() {
        let point = verifying_key(&signer(7)).to_encoded_point(false);
        let text = pem_block("PUBLIC KEY", point.as_bytes());
        assert_eq!(
            message(SpkiVerifier::from_pem(&text)),
            "the spki public key text, line 1: the PUBLIC KEY block holds no valid public key"
        );
    }

    /// Returns the PKCS#8 DER of the secret key of `signer(byte)`.
    fn pkcs8(byte: u8) -> Vec<u8> {
        use p256::pkcs8::EncodePrivateKey;
        SecretKey::from(signing_key(&signer(byte)))
            .to_pkcs8_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// Returns the public keys of the signers that `spki_secret_keys` reads
    /// from `text`.
    fn secret_keys(text: &str) -> Result<Vec<Vec<u8>>> {
        let signers = spki_secret_keys(text.as_bytes().to_vec(), SUBJECT)?;
        Ok(signers.iter().map(SpkiSigner::public_key_der).collect())
    }

    #[test]
    fn each_private_key_block_gives_a_signer_in_order() {
        let text = format!(
            "first\n{}between -----\n{}after\n",
            pem_block("PRIVATE KEY", &pkcs8(7)),
            pem_block("PRIVATE KEY", &pkcs8(9))
        );
        let want = [signer(7).public_key_der(), signer(9).public_key_der()];
        assert_eq!(secret_keys(&text).unwrap(), want);
        let crlf = text.replace('\n', "\r\n");
        assert_eq!(secret_keys(&crlf).unwrap(), want);
        let blank_boundaries = text
            .replace("-----BEGIN", " \t-----BEGIN")
            .replace("KEY-----\n", "KEY----- \n");
        assert_eq!(secret_keys(&blank_boundaries).unwrap(), want);
        let no_final_line_end = text.trim_end_matches("after\n").trim_end();
        assert_eq!(secret_keys(no_final_line_end).unwrap(), want);
    }

    #[test]
    fn a_secret_key_file_with_no_block_is_refused() {
        let line = base64::encode(&pkcs8(7));
        for text in ["", "\n", " \t\r\n\n", &format!("{line}\n")] {
            assert_eq!(
                message(secret_keys(text)),
                "the key file 'k' holds no PEM PRIVATE KEY block",
                "{text:?}"
            );
        }
    }

    #[test]
    fn another_label_refuses_the_secret_key_file() {
        let key = pem_block("PRIVATE KEY", &pkcs8(7));
        for label in [
            "EC PRIVATE KEY",
            "RSA PRIVATE KEY",
            "PUBLIC KEY",
            "ENCRYPTED PRIVATE KEY",
            "private key",
        ] {
            let other = pem_block(label, &pkcs8(9));
            assert_eq!(
                message(secret_keys(&format!("{key}{other}"))),
                format!("the key file 'k', line 6: unexpected label \"{label}\""),
            );
            assert_eq!(
                message(secret_keys(&other)),
                format!("the key file 'k', line 1: unexpected label \"{label}\""),
            );
        }
    }

    #[test]
    fn a_private_key_block_that_is_not_a_p256_pkcs8_key_refuses_the_file() {
        let key = pem_block("PRIVATE KEY", &pkcs8(7));
        let sec1 = base64::decode(SECRET_SEC1_B64).unwrap();
        for der in [
            signer(9).public_key_der(),
            vec![7u8; 32],
            sec1,
            b"not a key".to_vec(),
        ] {
            let text = format!("{key}{}", pem_block("PRIVATE KEY", &der));
            assert_eq!(
                message(secret_keys(&text)),
                "the key file 'k', line 6: the PRIVATE KEY block holds no valid PKCS#8 key"
            );
        }
    }

    #[test]
    fn a_private_key_block_that_does_not_decode_refuses_the_file() {
        let key = pem_block("PRIVATE KEY", &pkcs8(7));
        let b64 = base64::encode(&pkcs8(9));
        let wrapped = format!("{}\n{}\n{}", &b64[..64], &b64[64..128], &b64[128..]);
        for (body, reason) in [
            (
                format!("{}\n\n{}", &b64[..64], &b64[64..]),
                "line 8 is empty",
            ),
            (b64.clone(), "PEM Base64 error: invalid Base64 encoding"),
            (
                format!("Proc-Type: 4,ENCRYPTED\n{wrapped}"),
                "PEM headers disallowed by RFC7468",
            ),
            (
                format!("{}!\n{}", &b64[..60], &b64[64..]),
                "PEM Base64 error: invalid Base64 encoding",
            ),
        ] {
            let text =
                format!("{key}-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n");
            assert_eq!(
                message(secret_keys(&text)),
                format!(
                    "the key file 'k', line 6: the PRIVATE KEY block does not decode: {reason}"
                ),
                "{body:?}"
            );
        }
        for text in [
            "-----BEGIN PRIVATE KEY-----\n".to_owned(),
            format!("{key}-----BEGIN PRIVATE KEY-----\n{key}"),
            key.replace("-----END PRIVATE KEY-----", "-----END PUBLIC KEY-----"),
        ] {
            assert!(
                message(secret_keys(&text)).starts_with("the key file 'k', line "),
                "{text:?}"
            );
        }
    }

    /// Returns the public keys of the signers that `spki_secret_key_lines`
    /// reads from `text`.
    fn secret_key_lines(text: &str) -> Result<Vec<Vec<u8>>> {
        let signers = spki_secret_key_lines(text.as_bytes().to_vec(), SUBJECT)?;
        Ok(signers.iter().map(SpkiSigner::public_key_der).collect())
    }

    #[test]
    fn each_secret_key_line_gives_a_signer_in_order() {
        let (a, b) = (base64::encode(&pkcs8(7)), base64::encode(&pkcs8(9)));
        let want = [signer(7).public_key_der(), signer(9).public_key_der()];
        for text in [
            format!("{a}\n{b}\n"),
            format!("{a}\r\n{b}\r\n"),
            format!("{a}\n{b}"),
        ] {
            assert_eq!(secret_key_lines(&text).unwrap(), want, "{text:?}");
        }
        let sec1 = format!("{SECRET_SEC1_B64}\n");
        assert_eq!(secret_key_lines(&sec1).unwrap().len(), 1);
    }

    #[test]
    fn a_bad_secret_key_line_refuses_the_file() {
        let (a, b) = (base64::encode(&pkcs8(7)), base64::encode(&pkcs8(9)));
        let public = base64::encode(&signer(9).public_key_der());
        for (text, tail) in [
            (String::new(), " holds no key"),
            (format!("{a}\n\n{b}\n"), ", line 2 is empty"),
            (format!("\n{a}\n"), ", line 1 is empty"),
            (format!("{a}\n\n"), ", line 2 is empty"),
            (format!("{a} {b}\n"), ", line 1 holds white space"),
            (format!("{a}\n \n"), ", line 2 holds white space"),
            (format!("{a}\r\r\n"), ", line 1 holds white space"),
            (
                format!("{a}\n{public}\n"),
                ", line 2: spki secret key: expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER",
            ),
        ] {
            assert_eq!(
                message(secret_key_lines(&text)),
                format!("{SUBJECT}{tail}"),
                "{text:?}"
            );
        }
        let refused = message(secret_key_lines("not!base64\n"));
        assert!(
            refused.starts_with("the key file 'k', line 1: "),
            "{refused}"
        );
        let not_utf8 = spki_secret_key_lines(b"\xff\n".to_vec(), SUBJECT);
        assert_eq!(
            message(not_utf8),
            "the key file 'k', line 1: the line is not base64"
        );
    }

    #[test]
    fn a_fixed_width_signature_does_not_verify() {
        let signer = signer(7);
        let verifier = SpkiVerifier::new([signer.public_key_der()], Vec::<&[u8]>::new()).unwrap();
        let der = block_on(signer.sign(b"data")).unwrap();
        let fixed = Signature::from_der(&der).unwrap().to_bytes().to_vec();
        assert_eq!(fixed.len(), 64);
        let outcome = block_on(verifier.verify(b"data", &[fixed])).unwrap();
        assert!(!outcome.valid);
        assert!(outcome.signatures[0].key_missing);
        assert!(block_on(verifier.verify(b"data", &[der])).unwrap().valid);
    }

    /// The PKCS#8 DER of an Ed25519 key, the key of test 1 in RFC 8032.
    const ED25519_PKCS8_B64: &str =
        "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMRESeVpezJpGXA7rAMcrn9g";

    // A P-256 key with explicit curve parameters, in three forms. The command
    // `openssl ecparam -name prime256v1 -param_enc explicit -genkey -noout`
    // (LibreSSL 4.2.1) made the SEC1 key. `openssl pkcs8 -topk8 -nocrypt`
    // made the PKCS#8 key, and `openssl ec -pubout` the SubjectPublicKeyInfo.

    /// The SubjectPublicKeyInfo DER of the explicit-parameter key, in base64.
    const EXPLICIT_SPKI_B64: &str = concat!(
        "MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA",
        "////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT",
        "57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEs",
        "Qkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R",
        "9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABGnMj3ISe4sJtUCw6z4y",
        "6Wk8pa1SPPx4SCyArVcCGMUmIY1N8pQiewxLrt7nYCARZr/CieWlZSg2/1kxKlOhc/A=",
    );
    /// The PKCS#8 DER of the explicit-parameter key, in base64.
    const EXPLICIT_PKCS8_B64: &str = concat!(
        "MIIBeQIBADCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAA",
        "AAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXY",
        "qjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR",
        "8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBo",
        "N79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBG0wawIBAQQg58wZgvcv",
        "Ek9rRN7KnqKIiOtPfqdDIthOJfNjSXgCJcShRANCAARpzI9yEnuLCbVAsOs+MulpPKWtUjz8eEgs",
        "gK1XAhjFJiGNTfKUInsMS67e52AgEWa/wonlpWUoNv9ZMSpToXPw",
    );
    /// The SEC1 DER of the explicit-parameter key, in base64.
    const EXPLICIT_SEC1_B64: &str = concat!(
        "MIIBaAIBAQQg58wZgvcvEk9rRN7KnqKIiOtPfqdDIthOJfNjSXgCJcSggfowgfcCAQEwLAYHKoZI",
        "zj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAA",
        "AAAAAAAA///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSd",
        "NgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li",
        "/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5",
        "ysL8YyVRAgEBoUQDQgAEacyPchJ7iwm1QLDrPjLpaTylrVI8/HhILICtVwIYxSYhjU3ylCJ7DEuu",
        "3udgIBFmv8KJ5aVlKDb/WTEqU6Fz8A==",
    );

    /// Returns the DER of a TLV with the tag `tag` and the content `content`.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            len @ 0..=0x7f => out.push(len as u8),
            len @ 0x80..=0xff => out.extend([0x81, len as u8]),
            len => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    /// Returns the DER of the OID `dotted`.
    fn oid(dotted: &str) -> Vec<u8> {
        tlv(0x06, ObjectIdentifier::new_unwrap(dotted).as_bytes())
    }

    /// Returns the DER of an `AlgorithmIdentifier` of the OID `dotted` and the
    /// DER `parameters`.
    fn algorithm(dotted: &str, parameters: &[u8]) -> Vec<u8> {
        tlv(0x30, &[oid(dotted), parameters.to_vec()].concat())
    }

    /// Returns the DER of a SubjectPublicKeyInfo of the `AlgorithmIdentifier`
    /// DER `algorithm` and the key bytes `key`.
    fn spki_of(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
        let bits = tlv(0x03, &[&[0u8][..], key].concat());
        tlv(0x30, &[algorithm, &bits].concat())
    }

    /// Returns the DER of a PKCS#8 `PrivateKeyInfo` of the
    /// `AlgorithmIdentifier` DER `algorithm` and the key bytes `key`.
    fn pkcs8_of(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
        tlv(
            0x30,
            &[tlv(0x02, &[0]), algorithm.to_vec(), tlv(0x04, key)].concat(),
        )
    }

    /// The `AlgorithmIdentifier` DER of a P-256 key.
    fn p256_algorithm() -> Vec<u8> {
        algorithm("1.2.840.10045.2.1", &oid("1.2.840.10045.3.1.7"))
    }

    /// Returns the message of the refusal of the public key `der`.
    fn public_refusal(der: &[u8]) -> String {
        message(SpkiVerifier::new([der], Vec::<&[u8]>::new()))
    }

    /// Returns the message of the refusal of the secret key `der`.
    fn secret_refusal(der: &[u8]) -> String {
        message(SpkiSigner::from_secret_key(der))
    }

    #[test]
    fn a_secret_scalar_shorter_than_the_field_size_is_accepted() {
        let short = [0x5au8; 24];
        let padded = [&[0u8; 8][..], &short].concat();
        let want =
            Public::P256(*SigningKey::from_slice(&padded).unwrap().verifying_key()).canonical_der();
        let curve = tlv(0xa0, &oid("1.2.840.10045.3.1.7"));
        for octets in [&short[..], &padded[..]] {
            // A SEC1 key with no public key, and the same key in PKCS#8.
            let sec1 = tlv(
                0x30,
                &[tlv(0x02, &[1]), tlv(0x04, octets), curve.clone()].concat(),
            );
            let pkcs8 = pkcs8_of(&p256_algorithm(), &sec1);
            for der in [sec1, pkcs8] {
                let signer = SpkiSigner::from_secret_key(&der).unwrap();
                assert_eq!(signer.public_key_der(), want, "{der:02x?}");
            }
        }
    }

    #[test]
    fn a_key_with_explicit_curve_parameters_is_refused() {
        let explicit = "the EC key has explicit curve parameters";
        let spki = base64::decode(EXPLICIT_SPKI_B64).unwrap();
        let outer = base64::decode(EXPLICIT_PKCS8_B64).unwrap();
        let sec1 = base64::decode(EXPLICIT_SEC1_B64).unwrap();
        assert_eq!(
            public_refusal(&spki),
            format!("spki public key: {explicit}")
        );
        let valid = signer(7).public_key_der();
        assert_eq!(
            message(SpkiVerifier::new([&valid[..]], [&spki[..]])),
            format!("spki public key: {explicit}")
        );
        let text = format!(
            "{}{}",
            pem_block("PUBLIC KEY", &valid),
            pem_block("PUBLIC KEY", &spki)
        );
        assert_eq!(
            refusal(&text),
            format!("the key file 'k', line 5: {explicit}")
        );

        // The explicit parameters in the PKCS#8 `AlgorithmIdentifier`, in the
        // `ECPrivateKey` of a PKCS#8 key, and in a bare SEC1 key.
        let inner = pkcs8_of(&p256_algorithm(), &sec1);
        for der in [&outer, &inner, &sec1] {
            assert_eq!(secret_refusal(der), format!("spki secret key: {explicit}"));
        }
        for der in [&outer, &inner] {
            let text = format!(
                "{}{}",
                pem_block("PRIVATE KEY", &pkcs8(7)),
                pem_block("PRIVATE KEY", der)
            );
            assert_eq!(
                message(secret_keys(&text)),
                format!("the key file 'k', line 6: {explicit}")
            );
        }
    }

    #[test]
    fn a_pkcs8_key_whose_inner_curve_differs_is_refused() {
        // The SEC1 key of the fixture, with secp521r1 in its `parameters`
        // field, in a PKCS#8 key of the P-256 curve.
        let sec1 = base64::decode(concat!(
            "MHQCAQEEINi+9PBLJ58xxEdEmGrDDSFHBr+t0GqQv95FbKD3q8yhoAcGBSuBBAAjoUQD",
            "QgAE8X83xylD3ibci0xjFKMR4bwUtTU/YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDn",
            "RAG1Ua8eR8SKbLQ==",
        ))
        .unwrap();
        assert_eq!(
            secret_refusal(&pkcs8_of(&p256_algorithm(), &sec1)),
            "spki secret key: the ECPrivateKey names a curve other than the curve of the \
             PKCS#8 key"
        );
        // The SEC1 key of the fixture names P-256, and a PKCS#8 key with it
        // gives the key of the fixture.
        let named = base64::decode(SECRET_SEC1_B64).unwrap();
        let signer = SpkiSigner::from_secret_key(&pkcs8_of(&p256_algorithm(), &named)).unwrap();
        assert_eq!(
            signer.public_key_der(),
            base64::decode(PUBLIC_SPKI_B64).unwrap()
        );
    }

    #[test]
    fn a_compact_point_is_refused() {
        // The compact form gives the x coordinate alone, after the byte 0x05.
        let point = verifying_key(&signer(7)).to_encoded_point(false);
        let compact = [&[0x05][..], point.x().unwrap().as_slice()].concat();
        let spki = spki_of(&p256_algorithm(), &compact);
        assert_eq!(
            public_refusal(&spki),
            "spki public key: expected SubjectPublicKeyInfo DER"
        );
    }

    #[test]
    fn a_structure_that_is_not_a_sec1_key_is_in_no_form() {
        let form = "spki secret key: expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER";
        let scalar = tlv(0x04, &[7; 32]);
        for version in [0u8, 2] {
            let der = tlv(0x30, &[tlv(0x02, &[version]), scalar.clone()].concat());
            assert_eq!(secret_refusal(&der), form);
        }
        let short = [0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0x78];
        assert_eq!(secret_refusal(&short), form);
    }

    #[test]
    fn a_parameters_field_that_is_not_a_curve_is_refused() {
        // A SEC1 key whose `parameters` field holds a NULL.
        let sec1 = tlv(
            0x30,
            &[
                tlv(0x02, &[1]),
                tlv(0x04, &[7; 32]),
                tlv(0xa0, &[0x05, 0x00]),
            ]
            .concat(),
        );
        assert_eq!(
            secret_refusal(&sec1),
            "spki secret key: the SEC1 key does not name its curve"
        );
        assert_eq!(
            secret_refusal(&pkcs8_of(&p256_algorithm(), &sec1)),
            "spki secret key: the ECPrivateKey names a curve other than the curve of the \
             PKCS#8 key"
        );
    }

    #[test]
    fn a_key_of_another_type_or_curve_is_refused() {
        let ec = "1.2.840.10045.2.1";
        let null = [0x05, 0x00];
        for (algorithm, reason) in [
            (
                algorithm(ec, &oid("1.3.132.0.35")),
                "the curve P-521 is not supported",
            ),
            (
                algorithm(ec, &oid("1.3.132.0.10")),
                "the curve secp256k1 is not supported",
            ),
            (
                algorithm(ec, &oid("1.2.3.4")),
                "the curve 1.2.3.4 is not supported",
            ),
            (algorithm(ec, &[]), "the EC key does not name its curve"),
            (algorithm(ec, &null), "the EC key does not name its curve"),
            (
                algorithm("1.3.101.112", &[]),
                "the key type Ed25519 is not supported",
            ),
            (
                algorithm("1.2.840.113549.1.1.10", &[]),
                "the key type RSASSA-PSS is not supported",
            ),
            (
                algorithm("1.2.3.4", &[]),
                "the key type 1.2.3.4 is not supported",
            ),
        ] {
            let spki = spki_of(&algorithm, &[4; 65]);
            assert_eq!(public_refusal(&spki), format!("spki public key: {reason}"));
            let secret = pkcs8_of(&algorithm, &[7; 32]);
            assert_eq!(
                secret_refusal(&secret),
                format!("spki secret key: {reason}")
            );

            // One such key refuses the whole file.
            let text = format!(
                "{}{}",
                pem_block("PUBLIC KEY", &signer(7).public_key_der()),
                pem_block("PUBLIC KEY", &spki)
            );
            assert_eq!(
                refusal(&text),
                format!("the key file 'k', line 5: {reason}")
            );
            let text = format!(
                "{}{}",
                pem_block("PRIVATE KEY", &pkcs8(7)),
                pem_block("PRIVATE KEY", &secret)
            );
            assert_eq!(
                message(secret_keys(&text)),
                format!("the key file 'k', line 6: {reason}")
            );
        }
        let ed25519 = base64::decode(ED25519_PKCS8_B64).unwrap();
        assert_eq!(
            secret_refusal(&ed25519),
            "spki secret key: the key type Ed25519 is not supported"
        );
    }

    #[test]
    fn a_pkcs8_pem_key_is_read_by_its_label() {
        let der = base64::decode(SECRET_PKCS8_B64).unwrap();
        let signer = SpkiSigner::from_pkcs8_pem(&pem_block("PRIVATE KEY", &der)).unwrap();
        assert_eq!(
            signer.public_key_der(),
            base64::decode(PUBLIC_SPKI_B64).unwrap()
        );
        assert_eq!(
            message(SpkiSigner::from_pkcs8_pem(&pem_block(
                "EC PRIVATE KEY",
                &der
            ))),
            "spki secret key: unexpected label \"EC PRIVATE KEY\""
        );
        let sec1 = base64::decode(SECRET_SEC1_B64).unwrap();
        assert_eq!(
            message(SpkiSigner::from_pkcs8_pem(&pem_block("PRIVATE KEY", &sec1))),
            "spki secret key: expected PKCS#8 DER"
        );
        let ed25519 = base64::decode(ED25519_PKCS8_B64).unwrap();
        assert_eq!(
            message(SpkiSigner::from_pkcs8_pem(&pem_block(
                "PRIVATE KEY",
                &ed25519
            ))),
            "spki secret key: the key type Ed25519 is not supported"
        );
        assert!(SpkiSigner::from_pkcs8_pem("not PEM").is_err());
    }

    /// Returns a signature of `data` by the Ed25519 key of test 1 in RFC 8032.
    fn ed25519_signature(data: &[u8]) -> Vec<u8> {
        let secret = base64::decode(concat!(
            "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2DXWpgBgrEKt9VL/tPJZAc6",
            "DuFy89qmIyWvAhpo9wdRGg==",
        ))
        .unwrap();
        let signer = crate::Ed25519Signer::from_secret_key(&secret).unwrap();
        block_on(signer.sign(data)).unwrap()
    }

    #[test]
    fn a_blob_that_no_trusted_key_verifies_is_not_valid() {
        let signer = signer(7);
        let verifier = SpkiVerifier::new([signer.public_key_der()], Vec::<&[u8]>::new()).unwrap();
        let der = block_on(signer.sign(b"data")).unwrap();
        let mut trailing = der.clone();
        trailing.push(0);
        // The second INTEGER claims one byte more than the SEQUENCE holds.
        let mut malformed = der.clone();
        let at = 4 + usize::from(malformed[3]);
        malformed[at + 1] += 1;
        let fixed = Signature::from_der(&der).unwrap().to_bytes().to_vec();
        let ed25519 = ed25519_signature(b"data");
        assert_eq!(ed25519.len(), 64);
        let random: Vec<u8> = (0u8..64)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect();
        for blob in [random, vec![0x5a], trailing, malformed, fixed, ed25519] {
            let outcome = block_on(verifier.verify(b"data", std::slice::from_ref(&blob))).unwrap();
            assert!(!outcome.valid, "{blob:02x?}");
            let info = &outcome.signatures[0];
            assert!(!info.valid && info.key_missing, "{blob:02x?}");
            assert_eq!(info.fingerprint, None);
            assert_eq!(info.pubkey_algorithm, None);
        }
    }

    #[test]
    fn a_signature_of_another_key_type_beside_a_valid_one_keeps_the_outcome_valid() {
        let signer = signer(7);
        let verifier = SpkiVerifier::new([signer.public_key_der()], Vec::<&[u8]>::new()).unwrap();
        let blobs = [
            ed25519_signature(b"data"),
            block_on(signer.sign(b"data")).unwrap(),
        ];
        let outcome = block_on(verifier.verify(b"data", &blobs)).unwrap();
        assert!(outcome.valid);
        assert!(!outcome.signatures[0].valid && outcome.signatures[0].key_missing);
        assert!(outcome.signatures[1].valid && !outcome.signatures[1].key_missing);
    }

    /// The lowercase hex SHA-256 of the SubjectPublicKeyInfo DER of the
    /// fixture key, with an uncompressed point.
    const FIXTURE_FINGERPRINT: &str =
        "644cc120ac214d21a60770c087fbeed2ca25eab2b4536ec33fb1a133763aa7b7";

    /// Returns the SubjectPublicKeyInfo DER of the fixture key with a
    /// compressed point.
    fn compressed_fixture_spki() -> Vec<u8> {
        let uncompressed = base64::decode(PUBLIC_SPKI_B64).unwrap();
        let key = VerifyingKey::from_sec1_bytes(&uncompressed[26..]).unwrap();
        spki_of(&p256_algorithm(), key.to_encoded_point(true).as_bytes())
    }

    #[test]
    fn a_valid_signature_names_the_algorithm_and_the_fingerprint() {
        let uncompressed = base64::decode(PUBLIC_SPKI_B64).unwrap();
        assert_eq!(
            Checksum::sha256(&uncompressed).to_hex(),
            FIXTURE_FINGERPRINT
        );
        let signer = SpkiSigner::from_base64(SECRET_PKCS8_B64).unwrap();
        let signature = block_on(signer.sign(b"data")).unwrap();
        let pem_text = pem_block("PUBLIC KEY", &compressed_fixture_spki());
        for verifier in [
            SpkiVerifier::new([&uncompressed], Vec::<&[u8]>::new()).unwrap(),
            SpkiVerifier::new([compressed_fixture_spki()], Vec::<&[u8]>::new()).unwrap(),
            SpkiVerifier::from_pem(&pem_text).unwrap(),
        ] {
            let outcome =
                block_on(verifier.verify(b"data", std::slice::from_ref(&signature))).unwrap();
            let info = &outcome.signatures[0];
            assert!(info.valid);
            assert_eq!(info.pubkey_algorithm.as_deref(), Some("p256"));
            assert_eq!(info.fingerprint.as_deref(), Some(FIXTURE_FINGERPRINT));
        }
    }

    #[test]
    fn revocation_matches_two_encodings_of_one_key() {
        let uncompressed = base64::decode(PUBLIC_SPKI_B64).unwrap();
        let compressed = compressed_fixture_spki();
        assert_ne!(uncompressed, compressed);
        for (trusted, revoked) in [(&uncompressed, &compressed), (&compressed, &uncompressed)] {
            assert!(SpkiVerifier::new([trusted], [revoked]).unwrap().is_empty());
        }
        let other = signer(9).public_key_der();
        assert!(
            !SpkiVerifier::new([&uncompressed], [&other])
                .unwrap()
                .is_empty()
        );
    }

    /// The DER signature of `b"commit bytes"` by the fixture key. ECDSA with
    /// RFC 6979 nonces gives these bytes for each signature.
    const FIXTURE_SIGNATURE_B64: &str = concat!(
        "MEUCIBOCcWASREvwxjPttodffAVDX1iT+7TJRnpkW//JwlMDAiEA03+9SS49ape5mdla7aeMj9Vb",
        "Vv2kCGVGWhSW2KOFbP8=",
    );

    #[test]
    fn signing_is_deterministic() {
        let pkcs8 = SpkiSigner::from_base64(SECRET_PKCS8_B64).unwrap();
        let sec1 = SpkiSigner::from_base64(SECRET_SEC1_B64).unwrap();
        let first = block_on(pkcs8.sign(b"commit bytes")).unwrap();
        assert_eq!(block_on(pkcs8.sign(b"commit bytes")).unwrap(), first);
        assert_eq!(block_on(sec1.sign(b"commit bytes")).unwrap(), first);
        assert_eq!(base64::encode(&first), FIXTURE_SIGNATURE_B64);
    }

    #[test]
    fn the_sign_and_verify_futures_are_ready_at_once() {
        let signer = signer(7);
        let verifier = SpkiVerifier::new([signer.public_key_der()], Vec::<&[u8]>::new()).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let signature = match signer.sign(b"data").as_mut().poll(&mut context) {
            Poll::Ready(signature) => signature.unwrap(),
            Poll::Pending => panic!("the sign future is pending"),
        };
        let signatures = [signature];
        match verifier
            .verify(b"data", &signatures)
            .as_mut()
            .poll(&mut context)
        {
            Poll::Ready(outcome) => assert!(outcome.unwrap().valid),
            Poll::Pending => panic!("the verify future is pending"),
        }
    }

    #[test]
    fn a_key_computes_the_prehash_when_it_tries_a_blob() {
        let signer = signer(7);
        let key = Public::P256(verifying_key(&signer));
        let prehash = Prehash::new(b"data");
        assert!(!key.verifies(&prehash, &SignatureForms::parse(&[0x5a])));
        assert!(prehash.digest.get().is_none());
        let der = block_on(signer.sign(b"data")).unwrap();
        assert!(key.verifies(&prehash, &SignatureForms::parse(&der)));
        assert_eq!(
            prehash.digest.get().map(Checksum::to_hex),
            Some(Checksum::sha256(b"data").to_hex())
        );
    }

    #[test]
    fn the_prehash_verify_agrees_with_the_verify_of_the_data() {
        use p256::ecdsa::signature::Verifier as _;

        let signer = signer(7);
        let verifying = verifying_key(&signer);
        let key = Public::P256(verifying);
        let valid = block_on(signer.sign(b"data")).unwrap();
        let other = block_on(self::signer(9).sign(b"data")).unwrap();
        for data in [&b"data"[..], b"other data", b""] {
            for blob in [&valid, &other] {
                let signature = Signature::from_der(blob).unwrap();
                assert_eq!(
                    key.verifies(&Prehash::new(data), &SignatureForms::parse(blob)),
                    verifying.verify(data, &signature).is_ok(),
                    "{data:?}"
                );
            }
        }
    }
}

#[cfg(all(
    test,
    any(feature = "sign-spki-p256", feature = "sign-spki-p384"),
    not(feature = "sign-spki-rsa")
))]
mod without_rsa_tests {
    use super::*;

    /// Returns the DER of the one PEM block of the key fixture file `$name`.
    macro_rules! key_der {
        ($name:literal) => {
            pem_rfc7468::decode_vec(
                include_bytes!(concat!("../../../tests/fixtures/spki/keys/", $name)).as_slice(),
            )
            .unwrap()
            .1
        };
    }

    #[test]
    fn an_rsa_key_names_the_feature_of_the_key_type() {
        let reason = "this build has no code for the key type RSA; build with the sign-spki-rsa \
                      feature";
        let public = key_der!("rsa-2048.pub.pem");
        match SpkiVerifier::new([public], Vec::<&[u8]>::new()) {
            Err(Error::Signature(m)) => assert_eq!(m, format!("spki public key: {reason}")),
            _ => panic!("the RSA public key has to be refused"),
        }
        for secret in [
            key_der!("rsa-2048.pem"),
            key_der!("rsa-2048.pkcs1.pem"),
            key_der!("rsa-3prime.pkcs1.pem"),
        ] {
            match SpkiSigner::from_secret_key(&secret) {
                Err(Error::Signature(m)) => assert_eq!(m, format!("spki secret key: {reason}")),
                _ => panic!("the RSA secret key has to be refused"),
            }
        }
    }

    /// Returns the DER of a TLV with the tag `tag` and the content `content`.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            len @ 0..=0x7f => out.push(len as u8),
            len => out.extend([0x81, len as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    /// Returns the DER of one `INTEGER` for each value of `values`.
    fn integers(values: &[u8]) -> Vec<u8> {
        values.iter().flat_map(|&v| tlv(0x02, &[v])).collect()
    }

    #[test]
    fn a_sequence_of_integers_that_is_no_rsa_key_is_in_no_form() {
        let form = "spki secret key: expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER";
        let two_prime = integers(&[0, 5, 5, 5, 5, 5, 5, 5, 5]);
        let multi_prime = integers(&[1, 5, 5, 5, 5, 5, 5, 5, 5]);
        // An `otherPrimeInfos` field of one `OtherPrimeInfo`.
        let other_primes = tlv(0x30, &tlv(0x30, &integers(&[5, 5, 5])));
        let null = [0x05, 0x00];
        for fields in [
            // A traditional DSA key: version 0, then p, q, g, y, and x.
            integers(&[0, 23, 11, 4, 9, 7]),
            // The version and one integer.
            integers(&[0, 5]),
            // One integer too many.
            integers(&[0, 5, 5, 5, 5, 5, 5, 5, 5, 5]),
            // A field after the integers of a two-prime key.
            [&two_prime[..], &null].concat(),
            [&two_prime[..], &other_primes].concat(),
            // Version 1 with no `otherPrimeInfos` field, or with a field that
            // is not one.
            multi_prime.clone(),
            [&multi_prime[..], &null].concat(),
            // A field after the `otherPrimeInfos` field.
            [&multi_prime[..], &other_primes, &null].concat(),
        ] {
            let der = tlv(0x30, &fields);
            match SpkiSigner::from_secret_key(&der) {
                Err(Error::Signature(m)) => assert_eq!(m, form, "{der:02x?}"),
                _ => panic!("the sequence has to be refused: {der:02x?}"),
            }
        }

        // The fields of an `RSAPrivateKey`, with integers that make no valid
        // key, name the feature of the key type.
        let reason = "spki secret key: this build has no code for the key type RSA; build with \
                      the sign-spki-rsa feature";
        for fields in [two_prime, [&multi_prime[..], &other_primes].concat()] {
            let der = tlv(0x30, &fields);
            match SpkiSigner::from_secret_key(&der) {
                Err(Error::Signature(m)) => assert_eq!(m, reason, "{der:02x?}"),
                _ => panic!("the sequence has to be refused: {der:02x?}"),
            }
        }
    }
}

#[cfg(all(
    test,
    any(feature = "sign-spki-p384", feature = "sign-spki-rsa"),
    not(feature = "sign-spki-p256")
))]
mod without_p256_tests {
    use ostrya_core::base64;

    use super::*;

    #[test]
    fn a_p256_key_names_the_feature_of_the_curve() {
        let reason = "this build has no code for the curve P-256; build with the sign-spki-p256 \
                      feature";
        // A P-256 key: the SubjectPublicKeyInfo DER, the PKCS#8 DER, and the
        // SEC1 DER with the curve in its `parameters` field, in base64.
        let public = base64::decode(concat!(
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8X83xylD3ibci0xjFKMR4bwUtTU/",
            "YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDnRAG1Ua8eR8SKbLQ==",
        ))
        .unwrap();
        let pkcs8 = base64::decode(concat!(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
            "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
            "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
        ))
        .unwrap();
        let sec1 = base64::decode(concat!(
            "MHcCAQEEINi+9PBLJ58xxEdEmGrDDSFHBr+t0GqQv95FbKD3q8yhoAoGCCqGSM49AwEHoUQD",
            "QgAE8X83xylD3ibci0xjFKMR4bwUtTU/YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDn",
            "RAG1Ua8eR8SKbLQ==",
        ))
        .unwrap();
        match SpkiVerifier::new([public], Vec::<&[u8]>::new()) {
            Err(Error::Signature(m)) => assert_eq!(m, format!("spki public key: {reason}")),
            _ => panic!("the P-256 public key has to be refused"),
        }
        for secret in [pkcs8, sec1] {
            match SpkiSigner::from_secret_key(&secret) {
                Err(Error::Signature(m)) => assert_eq!(m, format!("spki secret key: {reason}")),
                _ => panic!("the P-256 secret key has to be refused"),
            }
        }
    }
}

#[cfg(all(
    test,
    any(feature = "sign-spki-p256", feature = "sign-spki-rsa"),
    not(feature = "sign-spki-p384")
))]
mod without_p384_tests {
    use ostrya_core::base64;

    use super::*;

    #[test]
    fn a_p384_key_names_the_feature_of_the_curve() {
        let reason = "this build has no code for the curve P-384; build with the sign-spki-p384 \
                      feature";
        // The P-384 key of RFC 6979, appendix A.2.6: the SubjectPublicKeyInfo
        // DER, the PKCS#8 DER, and the SEC1 DER with the curve in its
        // `parameters` field, in base64.
        let public = base64::decode(concat!(
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7DpOQVtOGaRWhhgCn0J/pdqai8SukuAuBqrlKGswDGTe",
            "+PDqkFWGYGSiVFFUgLwTgBXZty19VyROqO+awMYhiWcIpZNn+d+59UyoSz8cnbEoiyMcOuDU/nNE",
            "/SUzJkcg",
        ))
        .unwrap();
        let pkcs8 = base64::decode(concat!(
            "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBrnT2tLhuMHAWxmHW2ZZ9N4jw7Znvy",
            "l7qapHdAeHE32JbVck5McKgl+HLJ6mDS7fWhZANiAATsOk5BW04ZpFaGGAKfQn+l2pqLxK6S4C4G",
            "quUoazAMZN748OqQVYZgZKJUUVSAvBOAFdm3LX1XJE6o75rAxiGJZwilk2f537n1TKhLPxydsSiL",
            "Ixw64NT+c0T9JTMmRyA=",
        ))
        .unwrap();
        let sec1 = base64::decode(concat!(
            "MIGkAgEBBDBrnT2tLhuMHAWxmHW2ZZ9N4jw7Znvyl7qapHdAeHE32JbVck5McKgl+HLJ6mDS7fWg",
            "BwYFK4EEACKhZANiAATsOk5BW04ZpFaGGAKfQn+l2pqLxK6S4C4GquUoazAMZN748OqQVYZgZKJU",
            "UVSAvBOAFdm3LX1XJE6o75rAxiGJZwilk2f537n1TKhLPxydsSiLIxw64NT+c0T9JTMmRyA=",
        ))
        .unwrap();
        match SpkiVerifier::new([public], Vec::<&[u8]>::new()) {
            Err(Error::Signature(m)) => assert_eq!(m, format!("spki public key: {reason}")),
            _ => panic!("the P-384 public key has to be refused"),
        }
        for secret in [pkcs8, sec1] {
            match SpkiSigner::from_secret_key(&secret) {
                Err(Error::Signature(m)) => assert_eq!(m, format!("spki secret key: {reason}")),
                _ => panic!("the P-384 secret key has to be refused"),
            }
        }
    }
}
