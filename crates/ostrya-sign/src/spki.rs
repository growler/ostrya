//! The spki engine: ECDSA over NIST P-256 with SHA-256.
//!
//! The docs of `SpkiSigner` and `SpkiVerifier` hold the signature and key
//! formats.

use std::borrow::Cow;

use ostrya_core::base64;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::zeroize::Zeroizing;
use p256::pkcs8::der::asn1::{ContextSpecific, ObjectIdentifier, OctetStringRef};
use p256::pkcs8::der::{self, Decode, Reader, SliceReader, TagNumber};
use p256::pkcs8::{AssociatedOid, DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use p256::{EncodedPoint, NistP256, SecretKey};

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
    /// - [`Error::Signature`] if the decoded bytes are in no secret-key form
    ///   that [`from_secret_key`](Self::from_secret_key) accepts.
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
    ///   P-256 curve
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if `bytes` is a SEC1 `ECPrivateKey` DER with no
    ///   `parameters` field. The message is `spki secret key: the SEC1 key
    ///   does not name its curve`.
    /// - [`Error::Signature`] if `bytes` is a SEC1 `ECPrivateKey` DER with a
    ///   `parameters` field that names a curve other than P-256. The message
    ///   is `spki secret key: the SEC1 key names a curve other than P-256`.
    /// - [`Error::Signature`] if the function cannot read `bytes` in one of
    ///   these forms. The message is `spki secret key: expected PKCS#8 DER or
    ///   SEC1 DER`. A raw 32-byte scalar is in no accepted form.
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
/// A signature is in DER form, the form that [`SpkiSigner`] writes. A blob
/// in another form does not verify. The fixed-width 64-byte `r || s` form is
/// such a blob.
///
/// A public key is a SubjectPublicKeyInfo DER, which is the base64 body of a
/// PEM `PUBLIC KEY` block. A bare SEC1 point is not a public key of the
/// verifier. A public key file holds PEM `PUBLIC KEY` blocks, and
/// [`spki_public_keys`] reads it. The `trusted.spki` and `revoked.spki` files
/// of the system key store are public key files.
///
/// # Examples
///
/// ```
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
    /// - [`Error::Signature`] if a key in `trusted` or `revoked` is not a
    ///   SubjectPublicKeyInfo DER. The message is
    ///   `spki public key: expected SubjectPublicKeyInfo DER`.
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
            trusted: keys.into_iter().map(|(_, vk)| vk).collect(),
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
        for blob in signatures {
            // The verifier reads a DER signature alone, the form of this
            // engine. A blob in another form does not verify.
            let sig = Signature::from_der(blob);
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

/// Reads the public keys of a public key file of the spki engine.
///
/// `text` is the content of the file. The file holds PEM `PUBLIC KEY` blocks,
/// and each block holds one key. The function returns the
/// SubjectPublicKeyInfo DER of each block, in the order of the file. Each
/// error message names the file with `subject`.
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
/// - A `PUBLIC KEY` block does not decode, or does not hold a public key
///   that [`SpkiVerifier::new`] accepts.
/// - The text is not empty or white space, and holds no block. The message is
///   `<subject> holds no PEM PUBLIC KEY block`.
pub fn spki_public_keys(text: &[u8], subject: &str) -> Result<Vec<Vec<u8>>> {
    let keys = public_keys(text, subject)?;
    Ok(keys.into_iter().map(|(der, _)| der).collect())
}

/// Reads the public keys of a public key file as [`spki_public_keys`] does,
/// and returns the DER and the decoded key of each block.
fn public_keys(text: &[u8], subject: &str) -> Result<Vec<(Vec<u8>, VerifyingKey)>> {
    if text.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let refuse = |what: String| Error::Signature(format!("{subject}, {what}"));
    let blocks = pem::split(text).map_err(refuse)?;
    if let Some(other) = blocks.iter().find(|b| b.label != PUBLIC_KEY_LABEL) {
        return Err(refuse(format!(
            "line {}: unexpected label \"{}\"",
            other.line,
            other.label_text()
        )));
    }
    if blocks.is_empty() {
        return Err(Error::Signature(format!(
            "{subject} holds no PEM PUBLIC KEY block"
        )));
    }
    let mut keys = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let der = block.decode().map_err(|e| {
            refuse(format!(
                "line {}: the PUBLIC KEY block does not decode: {e}",
                block.line
            ))
        })?;
        let vk = decode_verifying_key(&der).map_err(|_| {
            refuse(format!(
                "line {}: the PUBLIC KEY block holds no P-256 public key",
                block.line
            ))
        })?;
        keys.push((der, vk));
    }
    Ok(keys)
}

/// Decodes secret-key bytes into a [`SigningKey`]. The bytes are a PKCS#8
/// `PrivateKeyInfo` DER, or a SEC1 `ECPrivateKey` DER that names the P-256
/// curve.
///
/// The check of the curve applies to a bare SEC1 key alone. The
/// `ECPrivateKey` in a PKCS#8 key can have no `parameters` field, because the
/// `AlgorithmIdentifier` of the PKCS#8 key names the curve.
fn decode_signing_key(bytes: &[u8]) -> Result<SigningKey> {
    if let Ok(key) = SigningKey::from_pkcs8_der(bytes) {
        return Ok(key);
    }
    if let Ok(secret) = SecretKey::from_sec1_der(bytes) {
        return match sec1_curve(bytes) {
            Ok(Some(curve)) if curve == NistP256::OID => Ok(SigningKey::from(&secret)),
            Ok(Some(_)) => Err(Error::Signature(
                "spki secret key: the SEC1 key names a curve other than P-256".into(),
            )),
            Ok(None) => Err(Error::Signature(
                "spki secret key: the SEC1 key does not name its curve".into(),
            )),
            Err(_) => Err(not_a_secret_key()),
        };
    }
    Err(not_a_secret_key())
}

/// Returns the error for secret-key bytes in no accepted form.
fn not_a_secret_key() -> Error {
    Error::Signature("spki secret key: expected PKCS#8 DER or SEC1 DER".into())
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

/// Returns the curve OID of the `parameters` field of a SEC1 `ECPrivateKey`
/// DER, or `None` if the key has no `parameters` field.
///
/// The structure is `SEQUENCE { version INTEGER, privateKey OCTET STRING,
/// parameters [0] ECParameters OPTIONAL, publicKey [1] BIT STRING OPTIONAL }`.
/// The function reads a named curve alone. Other `ECParameters` give an
/// error.
fn sec1_curve(bytes: &[u8]) -> der::Result<Option<ObjectIdentifier>> {
    let mut reader = SliceReader::new(bytes)?;
    let curve = reader.sequence(|seq| {
        u8::decode(seq)?;
        OctetStringRef::decode(seq)?;
        let parameters = ContextSpecific::<ObjectIdentifier>::decode_explicit(seq, TagNumber::N0)?;
        seq.read_slice(seq.remaining_len())?;
        Ok(parameters.map(|field| field.value))
    })?;
    reader.finish(curve)
}

/// Decodes public-key bytes into a [`VerifyingKey`]. The bytes are a
/// SubjectPublicKeyInfo DER.
fn decode_verifying_key(bytes: &[u8]) -> Result<VerifyingKey> {
    VerifyingKey::from_public_key_der(bytes)
        .map_err(|_| Error::Signature("spki public key: expected SubjectPublicKeyInfo DER".into()))
}

#[cfg(test)]
mod tests {
    use futures_lite::future::block_on;

    use super::*;

    /// The subject of the reader in the tests.
    const SUBJECT: &str = "the key file 'k'";

    /// Returns a signer of the scalar `[byte; 32]`.
    fn signer(byte: u8) -> SpkiSigner {
        SpkiSigner {
            signing_key: SigningKey::from_slice(&[byte; 32]).unwrap(),
        }
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
            "the key file 'k', line 5: the PUBLIC KEY block holds no P-256 public key"
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
        let refused = "spki secret key: expected PKCS#8 DER or SEC1 DER";
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
        assert_eq!(sec1_curve(&der).unwrap(), None);
        assert_eq!(
            message(SpkiSigner::from_secret_key(&der)),
            "spki secret key: the SEC1 key does not name its curve"
        );
        let named = base64::decode(SECRET_SEC1_B64).unwrap();
        assert_eq!(
            sec1_curve(&named).unwrap(),
            Some(ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"))
        );
    }

    #[test]
    fn a_sec1_key_of_another_curve_is_refused() {
        // The SEC1 key of the fixture, with secp384r1 in its `parameters`
        // field.
        let der = base64::decode(concat!(
            "MHQCAQEEINi+9PBLJ58xxEdEmGrDDSFHBr+t0GqQv95FbKD3q8yhoAcGBSuBBAAioUQD",
            "QgAE8X83xylD3ibci0xjFKMR4bwUtTU/YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDn",
            "RAG1Ua8eR8SKbLQ==",
        ))
        .unwrap();
        assert_eq!(
            sec1_curve(&der).unwrap(),
            Some(ObjectIdentifier::new_unwrap("1.3.132.0.34"))
        );
        assert_eq!(
            message(SpkiSigner::from_secret_key(&der)),
            "spki secret key: the SEC1 key names a curve other than P-256"
        );
    }

    #[test]
    fn other_inline_secret_forms_are_refused() {
        let pem_text = pem_block("PRIVATE KEY", &base64::decode(SECRET_PKCS8_B64).unwrap());
        assert_eq!(
            message(SpkiSigner::from_base64(&base64::encode(
                pem_text.as_bytes()
            ))),
            "spki secret key: expected PKCS#8 DER or SEC1 DER"
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
        let key = signer(7).signing_key.verifying_key().to_owned();
        let uncompressed = key.to_public_key_der().unwrap().as_bytes().to_vec();
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
        let point = signer(7)
            .signing_key
            .verifying_key()
            .to_encoded_point(false);
        let text = pem_block("PUBLIC KEY", point.as_bytes());
        assert_eq!(
            message(SpkiVerifier::from_pem(&text)),
            "the spki public key text, line 1: the PUBLIC KEY block holds no P-256 public key"
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
}
