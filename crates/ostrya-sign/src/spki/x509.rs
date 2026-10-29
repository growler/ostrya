//! The X.509 certificates of the spki engine: the signer with a certificate
//! chain, and the verifier that trusts the keys of certificates.
//!
//! The module decodes each certificate with `x509-cert`, a strict DER
//! decode. It validates no chain, no signature of a certificate, and no
//! validity period.

use der::Decode;
use der::referenced::OwnedToRef;
use x509_cert::Certificate;

use super::{
    Public, Secret, SpkiSigner, SpkiVerifier, TrustedKey, decode_public_key_info, labeled_blocks,
    refuse,
};
use crate::{Error, Result, SignFuture, Signer, X509Signer};

/// The label of the PEM blocks of a certificate.
const CERTIFICATE_LABEL: &[u8] = b"CERTIFICATE";

/// The `AlgorithmIdentifier` DER of an RSA signature: `rsaEncryption`
/// (1.2.840.113549.1.1.1) with `NULL` parameters.
const RSA_SIGNATURE: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];
/// The `AlgorithmIdentifier` DER of an ECDSA signature: `ecdsa-with-SHA256`
/// (1.2.840.10045.4.3.2) with no parameters.
const ECDSA_SIGNATURE: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];
/// The `AlgorithmIdentifier` DER of the digest: SHA-256
/// (2.16.840.1.101.3.4.2.1) with `NULL` parameters.
const SHA256_DIGEST: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
];

/// A signer of the spki engine with an X.509 certificate chain.
///
/// [`SpkiSigner::with_certificates`] makes this signer. The certificate of
/// the signer holds the key of the signer. The signer signs as its
/// [`SpkiSigner`] signs, with the engine name `spki` and the metadata key
/// `ostree.sign.spki`.
///
/// # Algorithms
///
/// The signer hashes the data with SHA-256 and signs the hash. The
/// [`X509Signer`] methods give these DER `AlgorithmIdentifier` values:
///
/// - [`signature_algorithm`](X509Signer::signature_algorithm) of an RSA key:
///   `rsaEncryption` (1.2.840.113549.1.1.1) with `NULL` parameters, the bytes
///   `30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00`.
/// - [`signature_algorithm`](X509Signer::signature_algorithm) of a P-256 or a
///   P-384 key: `ecdsa-with-SHA256` (1.2.840.10045.4.3.2) with no
///   parameters, the bytes `30 0a 06 08 2a 86 48 ce 3d 04 03 02`.
/// - [`digest_algorithm`](X509Signer::digest_algorithm): SHA-256
///   (2.16.840.1.101.3.4.2.1) with `NULL` parameters, the bytes
///   `30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00`.
///
/// The signature of an RSA key is the raw PKCS#1 v1.5 signature, and the
/// signature of an ECDSA key is a DER `SEQUENCE` of `r` and `s`.
#[derive(Clone)]
pub struct X509SpkiSigner {
    signer: SpkiSigner,
    certificates: Vec<Vec<u8>>,
    signature_algorithm: &'static [u8],
}

impl X509SpkiSigner {
    /// Returns the SubjectPublicKeyInfo DER of the public key of this signer.
    ///
    /// [`SpkiSigner::public_key_der`] states the form of the DER.
    pub fn public_key_der(&self) -> Vec<u8> {
        self.signer.public_key_der()
    }
}

impl Signer for X509SpkiSigner {
    fn name(&self) -> &str {
        self.signer.name()
    }

    fn metadata_key(&self) -> &str {
        self.signer.metadata_key()
    }

    fn sign<'a>(&'a self, data: &'a [u8]) -> SignFuture<'a> {
        self.signer.sign(data)
    }
}

impl X509Signer for X509SpkiSigner {
    fn certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }

    fn signature_algorithm(&self) -> &[u8] {
        self.signature_algorithm
    }

    fn digest_algorithm(&self) -> &[u8] {
        SHA256_DIGEST
    }
}

impl SpkiSigner {
    /// Gives this signer an X.509 certificate chain.
    ///
    /// The first certificate of `certificates` is the certificate of the
    /// signer. The intermediate certificates follow in chain order. Each item
    /// of `certificates` is one DER certificate, or PEM text of one or more
    /// `CERTIFICATE` blocks, as [`SpkiVerifier::from_certificates`] reads it.
    /// [`X509Signer::certificates`] gives the DER of each certificate, in
    /// order.
    ///
    /// The function compares the SubjectPublicKeyInfo of the first
    /// certificate with the key of the signer by the rule of the revocation
    /// compare of [`SpkiVerifier::new`]. It decodes each other certificate,
    /// and does not read its key. It validates no chain.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] in these conditions. Each message starts with
    /// `spki certificate`.
    ///
    /// - The key of the signer is an Ed25519 key. The message is
    ///   `spki certificate: an Ed25519 key takes no X.509 signer`.
    /// - [`SpkiVerifier::from_certificates`] refuses an item for its form.
    /// - `certificates` holds no certificate. The message is
    ///   `spki certificate: the list of certificates is empty`.
    /// - [`SpkiVerifier::new`] refuses the key of the first certificate. The
    ///   message is `spki certificate 1: <reason>`.
    /// - The key of the first certificate is not the key of the signer. The
    ///   message is
    ///   `spki certificate 1: the key of the certificate is not the key of the
    ///   signer`.
    pub fn with_certificates<I>(self, certificates: I) -> Result<X509SpkiSigner>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let signature_algorithm = match self.key {
            Secret::P256(_) => ECDSA_SIGNATURE,
            Secret::P384(_) => ECDSA_SIGNATURE,
            Secret::Rsa(_) => RSA_SIGNATURE,
            Secret::Ed25519(_) => {
                return Err(Error::Signature(
                    "spki certificate: an Ed25519 key takes no X.509 signer".into(),
                ));
            }
        };
        let certificates = read_certificates(certificates)?;
        let Some((_, first)) = certificates.first() else {
            return Err(Error::Signature(
                "spki certificate: the list of certificates is empty".into(),
            ));
        };
        if certificate_key(1, first)?.canonical_der() != self.public_key_der() {
            return Err(Error::Signature(
                "spki certificate 1: the key of the certificate is not the key of the signer"
                    .into(),
            ));
        }
        Ok(X509SpkiSigner {
            signer: self,
            certificates: certificates.into_iter().map(|(der, _)| der).collect(),
            signature_algorithm,
        })
    }
}

impl SpkiVerifier {
    /// Creates a verifier that trusts the key of each X.509 certificate of
    /// `certificates`.
    ///
    /// Each item of `certificates` is one of these forms:
    ///
    /// - One DER certificate. The item starts with the byte 0x30, the tag of
    ///   an ASN.1 `SEQUENCE`.
    /// - PEM text of one or more `CERTIFICATE` blocks. Each other item is read
    ///   as PEM text, so a PEM text that starts with the character `0` is
    ///   read as DER. The PEM rules of
    ///   [`spki_public_keys`](super::spki_public_keys) apply, but the
    ///   function refuses an empty item, an item of white space only, and an
    ///   item with no `CERTIFICATE` block.
    ///
    /// The items can be of the two forms together. The function counts the
    /// certificates of all items from 1, in order.
    ///
    /// The function trusts the SubjectPublicKeyInfo of each certificate, as
    /// [`new`](Self::new) trusts a key. A key from a certificate, from a PEM
    /// `PUBLIC KEY` block, and from a SubjectPublicKeyInfo DER is one trusted
    /// key, with one fingerprint. The function validates no chain, no
    /// signature of a certificate, and no validity period. An empty
    /// `certificates` gives a verifier that trusts no key.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] in these conditions. The function refuses the
    /// whole input, also when other certificates are valid. Each message
    /// starts with `spki certificate`. `<i>` is the number of the item in
    /// `certificates`, from 1.
    ///
    /// - An item is empty. The message is `spki certificate item <i> is
    ///   empty`.
    /// - A PEM text has a block with a label other than `CERTIFICATE`. The
    ///   message is
    ///   `spki certificate item <i>, line <n>: unexpected label "<label>"`.
    /// - A PEM text has a block with no END line, or another error of the
    ///   boundary lines. The message starts with
    ///   `spki certificate item <i>, line <n>: `.
    /// - A `CERTIFICATE` block does not decode. The message starts with
    ///   `spki certificate item <i>, line <n>: the CERTIFICATE block does not
    ///   decode: `.
    /// - A PEM text holds no block. The message is
    ///   `spki certificate item <i> holds no PEM CERTIFICATE block`.
    /// - A DER item or the body of a block is not an X.509 certificate DER.
    ///   The message is
    ///   `spki certificate <n>: expected X.509 certificate DER`.
    /// - [`new`](Self::new) refuses the key of a certificate, for example for
    ///   its key type. The message is `spki certificate <n>: <reason>`, with
    ///   the reason of [`new`](Self::new). The message of a key that
    ///   [`new`](Self::new) refuses for its form is
    ///   `spki certificate <n>: the certificate holds no valid public key`.
    pub fn from_certificates<I>(certificates: I) -> Result<SpkiVerifier>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut trusted = Vec::new();
        for (index, (_, certificate)) in read_certificates(certificates)?.iter().enumerate() {
            let key = certificate_key(index + 1, certificate)?;
            let der = key.canonical_der();
            trusted.push(TrustedKey::new(key, &der));
        }
        Ok(SpkiVerifier { trusted })
    }
}

/// Reads the certificates of `items` in order, by the rules of
/// [`SpkiVerifier::from_certificates`]. Returns the DER of each certificate
/// and the decoded certificate.
fn read_certificates<I>(items: I) -> Result<Vec<(Vec<u8>, Certificate)>>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let mut ders = Vec::new();
    for (index, item) in items.into_iter().enumerate() {
        let item = item.as_ref();
        let subject = format!("spki certificate item {}", index + 1);
        match item.first() {
            None => return Err(Error::Signature(format!("{subject} is empty"))),
            Some(0x30) => ders.push(item.to_vec()),
            Some(_) => {
                for block in labeled_blocks(item, &subject, CERTIFICATE_LABEL)? {
                    let mut der = block.decode().map_err(|e| {
                        refuse(
                            &subject,
                            format!(
                                "line {}: the CERTIFICATE block does not decode: {e}",
                                block.line
                            ),
                        )
                    })?;
                    ders.push(std::mem::take(&mut *der));
                }
            }
        }
    }
    let mut certificates = Vec::with_capacity(ders.len());
    for (index, der) in ders.into_iter().enumerate() {
        let certificate = Certificate::from_der(&der).map_err(|_| {
            Error::Signature(format!(
                "spki certificate {}: expected X.509 certificate DER",
                index + 1
            ))
        })?;
        certificates.push((der, certificate));
    }
    Ok(certificates)
}

/// Decodes the SubjectPublicKeyInfo of `certificate`, the certificate
/// `number`.
fn certificate_key(number: usize, certificate: &Certificate) -> Result<Public> {
    let info = certificate
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();
    decode_public_key_info(info).map_err(|refusal| {
        refusal.into_error(
            &format!("spki certificate {number}"),
            "the certificate holds no valid public key",
        )
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use der::Encode;
    use der::asn1::{BitString, GeneralizedTime, ObjectIdentifier, UtcTime};
    use futures_lite::future::block_on;
    use pem_rfc7468::LineEnding;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};
    use x509_cert::{TbsCertificate, Version};

    use super::*;
    use crate::spki::SpkiSigner;
    use crate::{SignatureInfo, Signer, Verifier};

    /// Returns the text of the TLS fixture file `$name`.
    macro_rules! tls {
        ($name:literal) => {
            include_str!(concat!("../../../../tests/fixtures/tls/", $name))
        };
    }

    /// Returns the DER of the one PEM block of `pem`.
    fn der_of(pem: &str) -> Vec<u8> {
        pem_rfc7468::decode_vec(pem.as_bytes()).unwrap().1
    }

    /// Returns the message of a signature error.
    fn message<T>(result: Result<T>) -> String {
        match result {
            Err(Error::Signature(m)) => m,
            Err(other) => panic!("not a signature error: {other}"),
            Ok(_) => panic!("the call has to fail"),
        }
    }

    /// Returns the result of `verifier` for the one blob `blob` over `data`.
    fn outcome(verifier: &SpkiVerifier, data: &[u8], blob: &[u8]) -> SignatureInfo {
        let mut outcome = verifier.verify(data, &[blob.to_vec()]).unwrap();
        outcome.signatures.remove(0)
    }

    /// Returns a certificate of the key of `signer`, valid from 2000 to 2100.
    /// `signer` signs it with the signature algorithm `oid`, with no
    /// parameters.
    fn certificate(signer: &SpkiSigner, oid: &str) -> Vec<u8> {
        let algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap(oid),
            parameters: None,
        };
        let name: Name = "CN=ostrya-sign test".parse().unwrap();
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[1]).unwrap(),
            signature: algorithm.clone(),
            issuer: name.clone(),
            validity: Validity {
                not_before: Time::UtcTime(
                    UtcTime::from_unix_duration(Duration::from_secs(946_684_800)).unwrap(),
                ),
                not_after: Time::GeneralTime(
                    GeneralizedTime::from_unix_duration(Duration::from_secs(4_102_444_800))
                        .unwrap(),
                ),
            },
            subject: name,
            subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(&signer.public_key_der())
                .unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };
        let signature = block_on(signer.sign(&tbs.to_der().unwrap())).unwrap();
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(&signature).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    #[test]
    fn an_item_that_is_not_a_certificate_is_refused() {
        let not_a_certificate = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(
            message(SpkiVerifier::from_certificates([
                der_of(tls!("server.pem")),
                not_a_certificate.clone()
            ])),
            "spki certificate 2: expected X.509 certificate DER"
        );
        let block =
            pem_rfc7468::encode_string("CERTIFICATE", LineEnding::LF, &not_a_certificate).unwrap();
        assert_eq!(
            message(SpkiVerifier::from_certificates([block])),
            "spki certificate 1: expected X.509 certificate DER"
        );
        assert_eq!(
            message(SpkiVerifier::from_certificates([tls!("ca.pem"), ""])),
            "spki certificate item 2 is empty"
        );
        let key = pem_rfc7468::encode_string("PUBLIC KEY", LineEnding::LF, b"key").unwrap();
        assert_eq!(
            message(SpkiVerifier::from_certificates([key])),
            "spki certificate item 1, line 1: unexpected label \"PUBLIC KEY\""
        );
        assert_eq!(
            message(SpkiVerifier::from_certificates([" \n"])),
            "spki certificate item 1 holds no PEM CERTIFICATE block"
        );
        assert!(
            SpkiVerifier::from_certificates(Vec::<&[u8]>::new())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_certificate_of_a_refused_key_refuses_the_input() {
        // Returns `server.pem` with the SubjectPublicKeyInfo of the algorithm
        // `oid`, with no parameters, and the public key `key`.
        let with_key = |oid: &str, key: &[u8]| -> Vec<u8> {
            let mut certificate = Certificate::from_der(&der_of(tls!("server.pem"))).unwrap();
            certificate.tbs_certificate.subject_public_key_info = SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: ObjectIdentifier::new_unwrap(oid),
                    parameters: None,
                },
                subject_public_key: BitString::from_bytes(key).unwrap(),
            };
            certificate.to_der().unwrap()
        };
        let ed448 = with_key("1.3.101.113", &[7; 57]);
        assert_eq!(
            message(SpkiVerifier::from_certificates([
                der_of(tls!("server.pem")),
                ed448.clone()
            ])),
            "spki certificate 2: the key type Ed448 is not supported"
        );
        assert_eq!(
            message(SpkiVerifier::from_certificates([
                ed448,
                der_of(tls!("server.pem"))
            ])),
            "spki certificate 1: the key type Ed448 is not supported"
        );
        // An Ed25519 key of 31 bytes is not in the form of the key type.
        assert_eq!(
            message(SpkiVerifier::from_certificates([
                der_of(tls!("ca.pem")),
                with_key("1.3.101.112", &[7; 31])
            ])),
            "spki certificate 2: the certificate holds no valid public key"
        );
    }

    #[test]
    fn a_signer_takes_its_certificate_chain_in_order() {
        let signer = crate::spki_secret_keys(tls!("server.key.pem").as_bytes().to_vec(), "k")
            .unwrap()
            .remove(0);
        let (server, ca) = (tls!("server.pem"), tls!("ca.pem"));
        let want = [der_of(server), der_of(ca)];
        for items in [
            vec![server.as_bytes().to_vec(), ca.as_bytes().to_vec()],
            vec![format!("{server}{ca}").into_bytes()],
            vec![der_of(server), ca.as_bytes().to_vec()],
        ] {
            let x509 = signer.clone().with_certificates(items).unwrap();
            assert_eq!(x509.certificates(), want);
            assert_eq!(x509.signature_algorithm(), ECDSA_SIGNATURE);
            assert_eq!(x509.digest_algorithm(), SHA256_DIGEST);
            assert_eq!(x509.public_key_der(), signer.public_key_der());
        }
        // The function does not compare the key of an intermediate
        // certificate.
        let x509 = signer
            .with_certificates([server, tls!("client.pem")])
            .unwrap();
        assert_eq!(x509.certificates().len(), 2);
    }

    #[test]
    fn a_signer_compares_the_decoded_key_of_its_certificate() {
        let signer = crate::spki_secret_keys(tls!("server.key.pem").as_bytes().to_vec(), "k")
            .unwrap()
            .remove(0);
        // The certificate holds the key of the signer as a compressed point,
        // so its SubjectPublicKeyInfo DER is not the DER of the signer.
        let mut certificate = Certificate::from_der(&der_of(tls!("server.pem"))).unwrap();
        let info = &mut certificate.tbs_certificate.subject_public_key_info;
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(info.subject_public_key.raw_bytes())
            .unwrap();
        let point = key.to_encoded_point(true);
        assert!(matches!(point.as_bytes().first(), Some(0x02 | 0x03)));
        info.subject_public_key = BitString::from_bytes(point.as_bytes()).unwrap();
        assert_ne!(info.to_der().unwrap(), signer.public_key_der());
        let compressed = certificate.to_der().unwrap();
        let x509 = signer.with_certificates([&compressed]).unwrap();
        assert_eq!(x509.certificates(), [compressed]);
    }

    #[test]
    fn a_signer_refuses_a_certificate_of_another_key() {
        let signer = crate::spki_secret_keys(tls!("server.key.pem").as_bytes().to_vec(), "k")
            .unwrap()
            .remove(0);
        let other = SpkiSigner {
            key: crate::spki::Secret::P256(p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap()),
        };
        let other = certificate(&other, "1.2.840.10045.4.3.2");
        for items in [
            vec![tls!("client.pem").as_bytes().to_vec()],
            vec![other, tls!("server.pem").as_bytes().to_vec()],
        ] {
            assert_eq!(
                message(signer.clone().with_certificates(items)),
                "spki certificate 1: the key of the certificate is not the key of the signer"
            );
        }
        assert_eq!(
            message(signer.clone().with_certificates(Vec::<&[u8]>::new())),
            "spki certificate: the list of certificates is empty"
        );
        assert_eq!(
            message(signer.with_certificates([tls!("server.pem").as_bytes(), &[0x30, 0x00]])),
            "spki certificate 2: expected X.509 certificate DER"
        );
    }

    #[test]
    fn the_key_of_a_certificate_is_the_trusted_key() {
        let signer = crate::spki_secret_keys(tls!("server.key.pem").as_bytes().to_vec(), "k")
            .unwrap()
            .remove(0);
        let signature = block_on(signer.sign(b"data")).unwrap();
        let der = signer.public_key_der();
        let block = pem_rfc7468::encode_string("PUBLIC KEY", LineEnding::LF, &der).unwrap();
        let want = outcome(
            &SpkiVerifier::new([&der], Vec::<&[u8]>::new()).unwrap(),
            b"data",
            &signature,
        );
        assert!(want.valid);
        assert_eq!(want.pubkey_algorithm.as_deref(), Some("p256"));
        for verifier in [
            SpkiVerifier::from_certificates([tls!("server.pem")]).unwrap(),
            SpkiVerifier::from_certificates([der_of(tls!("server.pem"))]).unwrap(),
            SpkiVerifier::from_certificates([tls!("ca.pem"), tls!("server.pem")]).unwrap(),
            SpkiVerifier::from_pem(&block).unwrap(),
        ] {
            let info = outcome(&verifier, b"data", &signature);
            assert!(info.valid);
            assert_eq!(info.fingerprint, want.fingerprint);
            assert_eq!(info.pubkey_algorithm, want.pubkey_algorithm);
        }
        let ca = SpkiVerifier::from_certificates([tls!("ca.pem")]).unwrap();
        assert!(!outcome(&ca, b"data", &signature).valid);
    }

    #[test]
    fn the_digest_algorithm_is_sha256_with_null_parameters() {
        let algorithm = x509_cert::spki::AlgorithmIdentifierRef::from_der(SHA256_DIGEST).unwrap();
        assert_eq!(
            algorithm.oid,
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1")
        );
        assert_eq!(algorithm.parameters, Some(der::asn1::AnyRef::NULL));
    }

    #[test]
    fn a_p384_signer_gives_the_ecdsa_with_sha256_identifier() {
        let signer = SpkiSigner {
            key: crate::spki::Secret::P384(
                ::p384::ecdsa::SigningKey::from_slice(&[7; 48]).unwrap(),
            ),
        };
        let certificate = certificate(&signer, "1.2.840.10045.4.3.2");
        let x509 = signer.with_certificates([&certificate]).unwrap();
        assert_eq!(
            x509.signature_algorithm(),
            [
                0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
            ]
        );
        let algorithm =
            x509_cert::spki::AlgorithmIdentifierRef::from_der(x509.signature_algorithm()).unwrap();
        assert_eq!(
            algorithm.oid,
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2")
        );
        assert_eq!(algorithm.parameters, None);
        assert_eq!(
            x509.digest_algorithm(),
            [
                0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00
            ]
        );
        let signature = block_on(x509.sign(b"data")).unwrap();
        let verifier = SpkiVerifier::from_certificates([&certificate]).unwrap();
        let info = outcome(&verifier, b"data", &signature);
        assert!(info.valid);
        assert_eq!(info.pubkey_algorithm.as_deref(), Some("p384"));
    }

    #[test]
    fn an_rsa_signer_signs_the_test_vector() {
        let data = include_bytes!("../../../../tests/fixtures/spki/keys/vector.data");
        let vector = include_bytes!("../../../../tests/fixtures/spki/keys/rsa-2048.vector.sig");
        let pem = include_str!("../../../../tests/fixtures/spki/keys/rsa-2048.pem");
        let signer = crate::spki_secret_keys(pem.as_bytes().to_vec(), "k")
            .unwrap()
            .remove(0);
        let certificate = certificate(&signer, "1.2.840.113549.1.1.11");
        let x509 = signer.with_certificates([&certificate]).unwrap();
        let x509: &dyn X509Signer = &x509;
        assert_eq!(x509.name(), "spki");
        assert_eq!(x509.metadata_key(), "ostree.sign.spki");
        assert_eq!(x509.certificates(), std::slice::from_ref(&certificate));
        assert_eq!(
            x509.signature_algorithm(),
            [
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
                0x00
            ]
        );
        let algorithm =
            x509_cert::spki::AlgorithmIdentifierRef::from_der(x509.signature_algorithm()).unwrap();
        assert_eq!(algorithm.oid, crate::spki::RSA_ENCRYPTION);
        assert_eq!(algorithm.parameters, Some(der::asn1::AnyRef::NULL));
        assert_eq!(x509.digest_algorithm(), SHA256_DIGEST);
        assert_eq!(block_on(x509.sign(data)).unwrap(), vector);
        let verifier = SpkiVerifier::from_certificates([&certificate]).unwrap();
        let info = outcome(&verifier, data, vector);
        assert!(info.valid);
        assert_eq!(info.pubkey_algorithm.as_deref(), Some("rsa"));
    }

    #[test]
    fn an_ed25519_certificate_is_trusted() {
        let signer = SpkiSigner {
            key: crate::spki::Secret::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(
                &[7; 32],
            ))),
        };
        let certificate = certificate(&signer, "1.3.101.112");
        let signature = block_on(signer.sign(b"data")).unwrap();
        let want = outcome(
            &SpkiVerifier::new([signer.public_key_der()], Vec::<&[u8]>::new()).unwrap(),
            b"data",
            &signature,
        );
        let info = outcome(
            &SpkiVerifier::from_certificates([&certificate]).unwrap(),
            b"data",
            &signature,
        );
        assert!(info.valid);
        assert_eq!(info.pubkey_algorithm.as_deref(), Some("ed25519"));
        assert_eq!(info.fingerprint, want.fingerprint);
        assert_eq!(
            message(signer.with_certificates([&certificate])),
            "spki certificate: an Ed25519 key takes no X.509 signer"
        );
    }
}
