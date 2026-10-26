//! The P-384 key type of the spki engine: ECDSA over NIST P-384 with SHA-256.
//!
//! The default `Signer` and `Verifier` of `p384` hash the data with SHA-384.
//! The engine hashes the data with SHA-256, as for each ECDSA and RSA key
//! type, and signs and verifies this hash as a prehash. `ecdsa` makes the
//! RFC 6979 nonce of a prehash with HMAC-SHA-384, so the signer gives the
//! same bytes for the same key and the same data.

use ::p384::ecdsa::signature::hazmat::{PrehashSigner as _, PrehashVerifier as _};
use ::p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use ::p384::pkcs8::EncodePublicKey as _;
use ostrya_core::Checksum;
use pkcs8::PrivateKeyInfo;
use spki::SubjectPublicKeyInfoRef;

use super::{Prehash, Refusal, SECP384R1, ec_point_form, inner_curve_is};

/// Decodes the public key of a P-384 SubjectPublicKeyInfo. The caller checks
/// the algorithm and the curve.
pub(super) fn public_key(
    info: SubjectPublicKeyInfoRef<'_>,
) -> std::result::Result<VerifyingKey, Refusal> {
    ec_point_form(&info)?;
    VerifyingKey::try_from(info).map_err(|_| Refusal::Form)
}

/// Decodes the secret key of a P-384 PKCS#8 key. The caller checks the
/// algorithm and the curve.
pub(super) fn pkcs8_secret_key(
    info: PrivateKeyInfo<'_>,
) -> std::result::Result<SigningKey, Refusal> {
    inner_curve_is(info.private_key, SECP384R1)?;
    ::p384::SecretKey::try_from(info)
        .map(|secret| (&secret).into())
        .map_err(|_| Refusal::Form)
}

/// Decodes a SEC1 `ECPrivateKey` DER whose `parameters` field names P-384.
pub(super) fn sec1_secret_key(der: &[u8]) -> std::result::Result<SigningKey, Refusal> {
    ::p384::SecretKey::from_sec1_der(der)
        .map(|secret| (&secret).into())
        .map_err(|_| Refusal::Form)
}

/// Returns the SubjectPublicKeyInfo DER of `key`, with an uncompressed point.
pub(super) fn canonical_der(key: &VerifyingKey) -> Vec<u8> {
    ::p384::PublicKey::from(key)
        .to_public_key_der()
        .expect("P-384 public key always encodes to SPKI DER")
        .into_vec()
}

/// Signs the SHA-256 of `data` with `key`, and returns the DER signature.
pub(super) fn sign(key: &SigningKey, data: &[u8]) -> Vec<u8> {
    let signature: Signature = key
        .sign_prehash(Checksum::sha256(data).as_bytes())
        .expect("a 32-byte prehash always signs on P-384");
    signature.to_der().to_bytes().into_vec()
}

/// Returns `true` if `key` verifies `signature`, the blob as a DER P-384
/// signature, over the data of `prehash`. A blob that does not parse as one
/// is not tried.
pub(super) fn verifies(
    key: &VerifyingKey,
    prehash: &Prehash<'_>,
    signature: Option<&Signature>,
) -> bool {
    signature.is_some_and(|signature| key.verify_prehash(prehash.get(), signature).is_ok())
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll, Waker};

    use futures_lite::future::block_on;
    use ostrya_core::base64;

    use super::*;
    use crate::{
        Error, Result, Signer, SpkiSigner, SpkiVerifier, Verifier, spki_public_keys,
        spki_secret_key_lines, spki_secret_keys,
    };

    // The P-384 key of RFC 6979, appendix A.2.6, in four forms. `openssl pkey`
    // of OpenSSL 3.6.4 wrote the PKCS#8 key and the two SubjectPublicKeyInfo
    // forms from the SEC1 key.

    /// The secret key, base64 of the PKCS#8 DER.
    const SECRET_PKCS8_B64: &str = concat!(
        "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBrnT2tLhuMHAWxmHW2ZZ9N4jw7Znvy",
        "l7qapHdAeHE32JbVck5McKgl+HLJ6mDS7fWhZANiAATsOk5BW04ZpFaGGAKfQn+l2pqLxK6S4C4G",
        "quUoazAMZN748OqQVYZgZKJUUVSAvBOAFdm3LX1XJE6o75rAxiGJZwilk2f537n1TKhLPxydsSiL",
        "Ixw64NT+c0T9JTMmRyA=",
    );
    /// The secret key, base64 of the SEC1 DER with the curve in its
    /// `parameters` field.
    const SECRET_SEC1_B64: &str = concat!(
        "MIGkAgEBBDBrnT2tLhuMHAWxmHW2ZZ9N4jw7Znvyl7qapHdAeHE32JbVck5McKgl+HLJ6mDS7fWg",
        "BwYFK4EEACKhZANiAATsOk5BW04ZpFaGGAKfQn+l2pqLxK6S4C4GquUoazAMZN748OqQVYZgZKJU",
        "UVSAvBOAFdm3LX1XJE6o75rAxiGJZwilk2f537n1TKhLPxydsSiLIxw64NT+c0T9JTMmRyA=",
    );
    /// The SubjectPublicKeyInfo DER with an uncompressed point, in base64.
    const PUBLIC_SPKI_B64: &str = concat!(
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7DpOQVtOGaRWhhgCn0J/pdqai8SukuAuBqrlKGswDGTe",
        "+PDqkFWGYGSiVFFUgLwTgBXZty19VyROqO+awMYhiWcIpZNn+d+59UyoSz8cnbEoiyMcOuDU/nNE",
        "/SUzJkcg",
    );
    /// The SubjectPublicKeyInfo DER with a compressed point, in base64.
    const PUBLIC_SPKI_COMPRESSED_B64: &str = concat!(
        "MEYwEAYHKoZIzj0CAQYFK4EEACIDMgAC7DpOQVtOGaRWhhgCn0J/pdqai8SukuAuBqrlKGswDGTe",
        "+PDqkFWGYGSiVFFUgLwT",
    );
    /// The lowercase hex SHA-256 of the DER of [`PUBLIC_SPKI_B64`].
    const FINGERPRINT: &str = "2f95601fa82060b909bfc6b979dbd303d34d34e0afb27ea496beac362f242a4b";

    /// The secret scalar `x` of the key, in hex.
    const SCALAR_HEX: &str = concat!(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8",
        "96D5724E4C70A825F872C9EA60D2EDF5",
    );
    /// The `r` of the signature of RFC 6979, appendix A.2.6, "With SHA-256,
    /// message = "sample"", in hex.
    const RFC_SAMPLE_R_HEX: &str = concat!(
        "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33",
        "BDE1E888E63355D92FA2B3C36D8FB2CD",
    );
    /// The `s` of the same signature, in hex.
    const RFC_SAMPLE_S_HEX: &str = concat!(
        "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEB",
        "EFDC63ECCD1AC42EC0CB8668A4FA0AB0",
    );

    /// The DER signature of `b"commit bytes"` by the key. The signer gives
    /// these bytes for each signature.
    const SIGNATURE_B64: &str = concat!(
        "MGYCMQDPI5yWt1xtbXOxCzjybwPUy9mo2onrUADSuMXAkZfdZpBgdo8YV/xINMYUP4H7YuQCMQCITkn2",
        "u7JiAd4zO5hAkCVjmBFKourpi+o1D51UUkM6xEdWlfR230BosyWE6NnLZ7E=",
    );

    /// The subject of the key file readers in the tests.
    const SUBJECT: &str = "the key file 'k'";

    /// Returns the bytes of the hex text `hex`.
    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Returns the bytes of the base64 text `b64`.
    fn der(b64: &str) -> Vec<u8> {
        base64::decode(b64).unwrap()
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

    /// Returns the DER of the OID `dotted`.
    fn oid(dotted: &str) -> Vec<u8> {
        tlv(
            0x06,
            der::asn1::ObjectIdentifier::new_unwrap(dotted).as_bytes(),
        )
    }

    /// Returns the SEC1 DER of the key, with the DER `parameters` between the
    /// secret scalar and the public key.
    fn sec1_of(parameters: &[u8]) -> Vec<u8> {
        let point = &der(PUBLIC_SPKI_B64)[23..];
        let public = tlv(0xa1, &tlv(0x03, &[&[0u8][..], point].concat()));
        let fields = [
            tlv(0x02, &[1]),
            tlv(0x04, &from_hex(SCALAR_HEX)),
            parameters.to_vec(),
            public,
        ];
        tlv(0x30, &fields.concat())
    }

    /// Returns the DER of an EC `AlgorithmIdentifier` of the curve `dotted`.
    fn ec_algorithm(dotted: &str) -> Vec<u8> {
        tlv(0x30, &[oid("1.2.840.10045.2.1"), oid(dotted)].concat())
    }

    /// Returns a PEM block of `label` around `der`, with 64-column lines.
    fn pem_block(label: &str, der: &[u8]) -> String {
        pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::LF, der).unwrap()
    }

    /// Returns the message of a signature error.
    fn message<T>(result: Result<T>) -> String {
        match result {
            Err(Error::Signature(m)) => m,
            Err(other) => panic!("not a signature error: {other}"),
            Ok(_) => panic!("the call has to fail"),
        }
    }

    /// Returns the signer of the key.
    fn signer() -> SpkiSigner {
        SpkiSigner::from_base64(SECRET_PKCS8_B64).unwrap()
    }

    /// Returns the P-384 signing key of the signer.
    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&from_hex(SCALAR_HEX)).unwrap()
    }

    /// Returns the verifier that trusts the key.
    fn verifier() -> SpkiVerifier {
        SpkiVerifier::new([der(PUBLIC_SPKI_B64)], Vec::<&[u8]>::new()).unwrap()
    }

    /// Returns the outcome of `verifier` for the one blob `blob` over `data`.
    fn outcome(verifier: &SpkiVerifier, data: &[u8], blob: &[u8]) -> crate::VerifyOutcome {
        block_on(verifier.verify(data, &[blob.to_vec()])).unwrap()
    }

    #[test]
    fn a_p384_key_signs_and_verifies() {
        let signature = block_on(signer().sign(b"data")).unwrap();
        // A DER signature starts with the tag of an ASN.1 `SEQUENCE`.
        assert_eq!(signature[0], 0x30);
        let verifier = verifier();
        assert!(outcome(&verifier, b"data", &signature).valid);
        assert!(!outcome(&verifier, b"other data", &signature).valid);
        let pem = SpkiVerifier::from_pem(pem_block("PUBLIC KEY", &der(PUBLIC_SPKI_B64))).unwrap();
        assert!(outcome(&pem, b"data", &signature).valid);
    }

    #[test]
    fn each_secret_key_form_gives_one_public_key() {
        let want = der(PUBLIC_SPKI_B64);
        assert_eq!(
            sec1_of(&tlv(0xa0, &oid("1.3.132.0.34"))),
            der(SECRET_SEC1_B64)
        );
        let wrapped = |b64: &str, line_end: &str| {
            b64.as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join(line_end)
        };
        let pkcs8_pem = pem_block("PRIVATE KEY", &der(SECRET_PKCS8_B64));
        let mut signers = vec![
            SpkiSigner::from_secret_key(&der(SECRET_PKCS8_B64)).unwrap(),
            SpkiSigner::from_secret_key(&der(SECRET_SEC1_B64)).unwrap(),
            SpkiSigner::from_pkcs8_pem(&pkcs8_pem).unwrap(),
        ];
        for b64 in [SECRET_PKCS8_B64, SECRET_SEC1_B64] {
            for text in [wrapped(b64, "\n"), wrapped(b64, "\r\n")] {
                signers.push(SpkiSigner::from_base64(&text).unwrap());
            }
        }
        signers.extend(spki_secret_keys(pkcs8_pem.into_bytes(), SUBJECT).unwrap());
        let lines = format!("{SECRET_PKCS8_B64}\n{SECRET_SEC1_B64}\r\n");
        signers.extend(spki_secret_key_lines(lines.into_bytes(), SUBJECT).unwrap());
        assert_eq!(signers.len(), 10);
        for signer in signers {
            assert_eq!(signer.public_key_der(), want);
        }
    }

    #[test]
    fn signing_is_deterministic() {
        let pkcs8 = signer();
        let sec1 = SpkiSigner::from_base64(SECRET_SEC1_B64).unwrap();
        let first = block_on(pkcs8.sign(b"commit bytes")).unwrap();
        assert_eq!(block_on(pkcs8.sign(b"commit bytes")).unwrap(), first);
        assert_eq!(block_on(sec1.sign(b"commit bytes")).unwrap(), first);
        assert_eq!(base64::encode(&first), SIGNATURE_B64);
    }

    #[test]
    fn the_rfc_6979_signature_with_sha256_verifies() {
        let rs = [from_hex(RFC_SAMPLE_R_HEX), from_hex(RFC_SAMPLE_S_HEX)].concat();
        let signature = Signature::from_slice(&rs).unwrap();
        let blob = signature.to_der().to_bytes().into_vec();
        let verifier = verifier();
        assert!(outcome(&verifier, b"sample", &blob).valid);
        assert!(!outcome(&verifier, b"test", &blob).valid);
        // The signer signs the same hash with another nonce.
        let own = block_on(signer().sign(b"sample")).unwrap();
        assert_ne!(own, blob);
        assert!(outcome(&verifier, b"sample", &own).valid);
    }

    #[test]
    fn a_signature_of_the_sha384_of_the_data_does_not_verify() {
        use ::p384::ecdsa::signature::{Signer as _, Verifier as _};

        let key = signing_key();
        let signature: Signature = key.sign(b"data");
        assert!(key.verifying_key().verify(b"data", &signature).is_ok());
        let blob = signature.to_der().to_bytes().into_vec();
        let outcome = outcome(&verifier(), b"data", &blob);
        assert!(!outcome.valid);
        assert!(outcome.signatures[0].key_missing);
    }

    #[test]
    fn a_blob_that_no_trusted_key_verifies_is_not_valid() {
        let verifier = verifier();
        let der = block_on(signer().sign(b"data")).unwrap();
        assert!(outcome(&verifier, b"data", &der).valid);
        let mut trailing = der.clone();
        trailing.push(0);
        // The second INTEGER claims one byte more than the SEQUENCE holds.
        let mut malformed = der.clone();
        let at = 4 + usize::from(malformed[3]);
        malformed[at + 1] += 1;
        let fixed = Signature::from_der(&der).unwrap().to_bytes().to_vec();
        assert_eq!(fixed.len(), 96);
        let random: Vec<u8> = (0u8..96)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect();
        // A signature of the same hash by another P-384 key.
        let other: Signature = SigningKey::from_slice(&[7; 48])
            .unwrap()
            .sign_prehash(Checksum::sha256(b"data").as_bytes())
            .unwrap();
        for blob in [
            random,
            vec![0x5a],
            trailing,
            malformed,
            fixed,
            other.to_der().to_bytes().into_vec(),
        ] {
            let outcome = outcome(&verifier, b"data", &blob);
            assert!(!outcome.valid, "{blob:02x?}");
            let info = &outcome.signatures[0];
            assert!(!info.valid && info.key_missing, "{blob:02x?}");
            assert_eq!(info.fingerprint, None);
            assert_eq!(info.pubkey_algorithm, None);
        }
    }

    /// The order `n` of the group of P-384, in hex.
    const ORDER_HEX: &str = concat!(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF",
        "581A0DB248B0A77AECEC196ACCC52973",
    );

    /// Returns the minimal DER INTEGER of the unsigned big-endian value
    /// `value`.
    fn uint(value: &[u8]) -> Vec<u8> {
        let start = value
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(value.len() - 1);
        let value = &value[start..];
        if value[0] & 0x80 == 0 {
            tlv(0x02, value)
        } else {
            tlv(0x02, &[&[0u8][..], value].concat())
        }
    }

    /// Returns the big-endian sum of the 48-byte values `a` and `b`, in 49
    /// bytes.
    fn add(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 49];
        let mut carry = 0u16;
        for i in (0..48).rev() {
            let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
            out[i + 1] = sum as u8;
            carry = sum >> 8;
        }
        out[0] = carry as u8;
        out
    }

    #[test]
    fn a_blob_that_breaks_the_der_or_the_range_rules_is_not_valid() {
        let verifier = verifier();
        let blob = block_on(signer().sign(b"data")).unwrap();
        let signature = Signature::from_der(&blob).unwrap();
        let r = signature.r().to_bytes().to_vec();
        let s = signature.s().to_bytes().to_vec();
        let n = from_hex(ORDER_HEX);
        let pair = |r: Vec<u8>, s: Vec<u8>| tlv(0x30, &[r, s].concat());
        assert_eq!(pair(uint(&r), uint(&s)), blob);
        // The same signature with `n - s` in place of `s` verifies too.
        let high_s = pair(uint(&r), uint(&(-*signature.s()).to_bytes()));
        assert_ne!(high_s, blob);
        for good in [&blob, &high_s] {
            assert!(outcome(&verifier, b"data", good).valid, "{good:02x?}");
        }

        // `s` as a negative INTEGER: the minimal two's complement form of a
        // value with its top bit set.
        let negative_s = if s[0] & 0x80 == 0 {
            tlv(0x02, &[&[0xffu8][..], &s].concat())
        } else {
            tlv(0x02, &s)
        };
        // `r` with one more leading zero byte than the minimal form holds.
        let padded_r = {
            let minimal = uint(&r);
            tlv(0x02, &[&[0u8][..], &minimal[2..]].concat())
        };
        let content = &blob[2..];
        let long_length = [&[0x30u8, 0x81, blob[1]][..], content].concat();
        let indefinite = [&[0x30u8, 0x80][..], content, &[0, 0]].concat();
        for bad in [
            pair(uint(&[0]), uint(&s)),
            pair(uint(&r), uint(&[0])),
            pair(uint(&n), uint(&s)),
            pair(uint(&add(&r, &n)), uint(&s)),
            pair(uint(&r), negative_s),
            pair(padded_r, uint(&s)),
            long_length,
            indefinite,
        ] {
            let outcome = outcome(&verifier, b"data", &bad);
            assert!(!outcome.valid, "{bad:02x?}");
            let info = &outcome.signatures[0];
            assert!(!info.valid && info.key_missing, "{bad:02x?}");
            assert_eq!(info.fingerprint, None);
            assert_eq!(info.pubkey_algorithm, None);
        }
    }

    #[test]
    fn a_valid_signature_names_the_algorithm_and_the_fingerprint() {
        assert_eq!(
            Checksum::sha256(&der(PUBLIC_SPKI_B64)).to_hex(),
            FINGERPRINT
        );
        let signature = block_on(signer().sign(b"data")).unwrap();
        let compressed = der(PUBLIC_SPKI_COMPRESSED_B64);
        for verifier in [
            verifier(),
            SpkiVerifier::new([&compressed], Vec::<&[u8]>::new()).unwrap(),
            SpkiVerifier::from_pem(pem_block("PUBLIC KEY", &compressed)).unwrap(),
        ] {
            let outcome = outcome(&verifier, b"data", &signature);
            let info = &outcome.signatures[0];
            assert!(info.valid);
            assert_eq!(info.pubkey_algorithm.as_deref(), Some("p384"));
            assert_eq!(info.fingerprint.as_deref(), Some(FINGERPRINT));
        }
    }

    #[test]
    fn revocation_matches_two_encodings_of_one_key() {
        let uncompressed = der(PUBLIC_SPKI_B64);
        let compressed = der(PUBLIC_SPKI_COMPRESSED_B64);
        for (trusted, revoked) in [(&uncompressed, &compressed), (&compressed, &uncompressed)] {
            assert!(SpkiVerifier::new([trusted], [revoked]).unwrap().is_empty());
        }
        let other = canonical_der(&VerifyingKey::from(
            &SigningKey::from_slice(&[7; 48]).unwrap(),
        ));
        assert!(
            !SpkiVerifier::new([&uncompressed], [&other])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_sign_and_verify_futures_are_ready_at_once() {
        let signer = signer();
        let verifier = verifier();
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
    fn a_secret_scalar_shorter_than_the_field_size_is_accepted() {
        // The 32 low bytes of the scalar of the key, as a scalar of their own.
        let short = &from_hex(SCALAR_HEX)[16..];
        let padded = [&[0u8; 16][..], short].concat();
        let want = canonical_der(SigningKey::from_slice(&padded).unwrap().verifying_key());
        let curve = tlv(0xa0, &oid("1.3.132.0.34"));
        for octets in [short, &padded[..]] {
            // A SEC1 key with no public key, and the same key in PKCS#8.
            let sec1 = tlv(
                0x30,
                &[tlv(0x02, &[1]), tlv(0x04, octets), curve.clone()].concat(),
            );
            let pkcs8 = tlv(
                0x30,
                &[
                    tlv(0x02, &[0]),
                    ec_algorithm("1.3.132.0.34"),
                    tlv(0x04, &sec1),
                ]
                .concat(),
            );
            for der in [sec1, pkcs8] {
                let signer = SpkiSigner::from_secret_key(&der).unwrap();
                assert_eq!(signer.public_key_der(), want, "{der:02x?}");
            }
        }
    }

    #[test]
    fn a_sec1_key_with_no_curve_is_refused() {
        assert_eq!(
            message(SpkiSigner::from_secret_key(&sec1_of(&[]))),
            "spki secret key: the SEC1 key does not name its curve"
        );
    }

    #[test]
    fn a_pkcs8_key_whose_inner_curve_differs_is_refused() {
        let sec1 = sec1_of(&tlv(0xa0, &oid("1.2.840.10045.3.1.7")));
        let pkcs8 = tlv(
            0x30,
            &[
                tlv(0x02, &[0]),
                ec_algorithm("1.3.132.0.34"),
                tlv(0x04, &sec1),
            ]
            .concat(),
        );
        assert_eq!(
            message(SpkiSigner::from_secret_key(&pkcs8)),
            "spki secret key: the ECPrivateKey names a curve other than the curve of the \
             PKCS#8 key"
        );
    }

    #[test]
    fn a_p521_key_and_a_key_of_another_type_are_refused() {
        let p521 = "the curve P-521 is not supported";
        // The key of the tests with the OID of P-521 in place of the OID of
        // P-384.
        let spki = {
            let mut spki = der(PUBLIC_SPKI_B64);
            assert_eq!(spki[15..20], from_hex("2B81040022"));
            spki[19] = 0x23;
            spki
        };
        assert_eq!(
            message(SpkiVerifier::new([&spki], Vec::<&[u8]>::new())),
            format!("spki public key: {p521}")
        );
        assert_eq!(
            message(spki_public_keys(
                pem_block("PUBLIC KEY", &spki).as_bytes(),
                SUBJECT
            )),
            format!("{SUBJECT}, line 1: {p521}")
        );
        let pkcs8 = tlv(
            0x30,
            &[
                tlv(0x02, &[0]),
                ec_algorithm("1.3.132.0.35"),
                tlv(0x04, &sec1_of(&[])),
            ]
            .concat(),
        );
        let sec1 = sec1_of(&tlv(0xa0, &oid("1.3.132.0.35")));
        for secret in [&pkcs8, &sec1] {
            assert_eq!(
                message(SpkiSigner::from_secret_key(secret)),
                format!("spki secret key: {p521}")
            );
        }

        // The PKCS#8 DER of an Ed448 key, with a 57-byte secret key.
        let ed448 = tlv(
            0x30,
            &[
                tlv(0x02, &[0]),
                tlv(0x30, &oid("1.3.101.113")),
                tlv(0x04, &tlv(0x04, &[7; 57])),
            ]
            .concat(),
        );
        assert_eq!(
            message(SpkiSigner::from_secret_key(&ed448)),
            "spki secret key: the key type Ed448 is not supported"
        );
    }

    #[cfg(all(feature = "sign-spki-p256", feature = "sign-spki-rsa"))]
    #[test]
    fn a_store_of_p256_p384_and_rsa_keys_verifies_a_signature_of_each() {
        // A P-256 key, base64 of the PKCS#8 DER.
        let p256 = SpkiSigner::from_base64(concat!(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
            "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
            "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
        ))
        .unwrap();
        let rsa_pem = include_str!("../../../../tests/fixtures/spki/keys/rsa-2048.pem");
        let rsa = spki_secret_keys(rsa_pem.as_bytes().to_vec(), SUBJECT)
            .unwrap()
            .remove(0);
        let p384 = signer();
        let text: String = [&p256, &p384, &rsa]
            .iter()
            .map(|signer| pem_block("PUBLIC KEY", &signer.public_key_der()))
            .collect();
        let verifier = SpkiVerifier::from_pem(&text).unwrap();
        for (signer, algorithm) in [(&p256, "p256"), (&p384, "p384"), (&rsa, "rsa")] {
            let signature = block_on(signer.sign(b"data")).unwrap();
            let outcome = outcome(&verifier, b"data", &signature);
            assert!(outcome.valid, "{algorithm}");
            assert_eq!(
                outcome.signatures[0].pubkey_algorithm.as_deref(),
                Some(algorithm)
            );
        }
    }
}
