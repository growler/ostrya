//! A test CA that signs client certificates with chosen URI SANs.
//!
//! The CA has an Ed25519 key, the key of test 1 of RFC 8032. Each
//! certificate is valid from 2000 to 2100 and has the extended key usage
//! `clientAuth`. The unit tests and the integration tests of the crate use
//! this module, so it names no item of the crate.

#![allow(dead_code)]

use std::time::Duration;

use ostrya::{Ed25519Signer, Signer};
use x509_cert::Certificate;
use x509_cert::TbsCertificate;
use x509_cert::Version;
use x509_cert::der::asn1::{BitString, GeneralizedTime, Ia5String, OctetString, UtcTime};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::oid::db::rfc5280::ID_KP_CLIENT_AUTH;
use x509_cert::der::oid::db::rfc8410::ID_ED_25519;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, SubjectAltName};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

/// The seed and the public key of test 1 of RFC 8032.
const SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\
                      d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// The test CA.
pub(crate) struct TestCa {
    signer: Ed25519Signer,
    name: Name,
    /// The PEM certificate of the CA.
    pub(crate) pem: String,
}

fn ed25519() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_ED_25519,
        parameters: None,
    }
}

fn extension<T: AssociatedOid + Encode>(value: &T, critical: bool) -> Extension {
    Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(value.to_der().unwrap()).unwrap(),
    }
}

/// The SubjectAltName extension value with the URI SANs `uris`.
pub(crate) fn uri_sans(uris: &[&str]) -> Vec<u8> {
    let names = uris
        .iter()
        .map(|uri| GeneralName::UniformResourceIdentifier(Ia5String::new(uri).unwrap()))
        .collect();
    SubjectAltName(names).to_der().unwrap()
}

/// `der` as a PEM certificate.
pub(crate) fn pem(der: &[u8]) -> String {
    let base64 = ostrya::base64::encode(der);
    let mut text = "-----BEGIN CERTIFICATE-----\n".to_owned();
    for line in base64.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(line).unwrap());
        text.push('\n');
    }
    text.push_str("-----END CERTIFICATE-----\n");
    text
}

/// The SPKI of the one certificate of the PEM text `cert_pem`.
pub(crate) fn spki_of(cert_pem: &str) -> SubjectPublicKeyInfoOwned {
    let base64: String = cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = ostrya::base64::decode(&base64).unwrap();
    Certificate::from_der(&der)
        .unwrap()
        .tbs_certificate
        .subject_public_key_info
}

impl TestCa {
    pub(crate) fn new() -> TestCa {
        let secret: Vec<u8> = (0..SECRET.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&SECRET[i..i + 2], 16).unwrap())
            .collect();
        let signer = Ed25519Signer::from_secret_key(&secret).unwrap();
        let name: Name = "CN=ostrya claims test CA".parse().unwrap();
        let mut ca = TestCa {
            signer,
            name: name.clone(),
            pem: String::new(),
        };
        let spki = ca.own_spki(&secret[32..]);
        let constraints = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        let der = ca.sign(1, name, spki, vec![extension(&constraints, true)]);
        ca.pem = pem(&der);
        ca
    }

    fn own_spki(&self, public: &[u8]) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: ed25519(),
            subject_public_key: BitString::from_bytes(public).unwrap(),
        }
    }

    /// The DER bytes of a client certificate with the subject CN `cn` and
    /// the URI SANs `uris`. Its key is the key of the CA.
    pub(crate) fn leaf(&self, cn: &str, uris: &[&str]) -> Vec<u8> {
        if uris.is_empty() {
            self.leaf_with(cn, None, &[])
        } else {
            self.leaf_with(cn, None, &[uri_sans(uris)])
        }
    }

    /// The DER bytes of a client certificate with the subject CN `cn`, the
    /// key `spki` (else the key of the CA), and one SubjectAltName extension
    /// for each value of `sans`.
    pub(crate) fn leaf_with(
        &self,
        cn: &str,
        spki: Option<SubjectPublicKeyInfoOwned>,
        sans: &[Vec<u8>],
    ) -> Vec<u8> {
        let spki = spki.unwrap_or_else(|| spki_of(&self.pem));
        let mut extensions = vec![extension(&ExtendedKeyUsage(vec![ID_KP_CLIENT_AUTH]), false)];
        for san in sans {
            extensions.push(Extension {
                extn_id: SubjectAltName::OID,
                critical: false,
                extn_value: OctetString::new(san.clone()).unwrap(),
            });
        }
        let subject: Name = format!("CN={cn}").parse().unwrap();
        self.sign(2, subject, spki, extensions)
    }

    fn sign(
        &self,
        serial: u8,
        subject: Name,
        spki: SubjectPublicKeyInfoOwned,
        extensions: Vec<Extension>,
    ) -> Vec<u8> {
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[serial]).unwrap(),
            signature: ed25519(),
            issuer: self.name.clone(),
            validity: Validity {
                not_before: Time::UtcTime(
                    UtcTime::from_unix_duration(Duration::from_secs(946_684_800)).unwrap(),
                ),
                not_after: Time::GeneralTime(
                    GeneralizedTime::from_unix_duration(Duration::from_secs(4_102_444_800))
                        .unwrap(),
                ),
            },
            subject,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };
        let signature =
            futures_lite::future::block_on(self.signer.sign(&tbs.to_der().unwrap())).unwrap();
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: ed25519(),
            signature: BitString::from_bytes(&signature).unwrap(),
        }
        .to_der()
        .unwrap()
    }
}
