//! The RSA key type of the spki engine: PKCS#1 v1.5 signatures with SHA-256.
//!
//! The module reads the `RSAPublicKey` and `RSAPrivateKey` structures with
//! the `pkcs1` crate that `rsa` exports, and does not use the key decoders of
//! `rsa`. The SubjectPublicKeyInfo decoder of `rsa` caps the modulus at 4096
//! bits. The private-key decoders of `rsa` apply no cap, and give general
//! errors, such as `KeyMalformed`, that do not state the reason.
//! `RsaPrivateKey::from_components` takes more than two primes. So the
//! module checks the size of the modulus and the number of primes itself,
//! before it computes with the key, and gives a message for each refusal.

use ::rsa::pkcs1::{self, Version};
use ::rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use ::rsa::rand_core::OsRng;
use ::rsa::sha2::Sha256;
use ::rsa::signature::hazmat::PrehashVerifier as _;
use ::rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};
use ::rsa::traits::PublicKeyParts as _;
use ::rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use der::Decode;
use der::asn1::UintRef;
use der::zeroize::Zeroizing;
use spki::SubjectPublicKeyInfoRef;

use super::{Prehash, Refusal};
use crate::{Error, Result};

/// The smallest modulus, in bits, that the engine takes.
const MIN_BITS: usize = 2048;
/// The largest modulus, in bits, that the engine takes.
const MAX_BITS: usize = 16384;

/// Returns the number of bits of the unsigned big-endian integer `be`.
fn bits(be: &[u8]) -> usize {
    match be.iter().position(|&byte| byte != 0) {
        Some(first) => (be.len() - first) * 8 - be[first].leading_zeros() as usize,
        None => 0,
    }
}

/// Refuses a modulus outside the range of the engine.
fn check_size(modulus: &[u8]) -> std::result::Result<(), Refusal> {
    let bits = bits(modulus);
    if (MIN_BITS..=MAX_BITS).contains(&bits) {
        return Ok(());
    }
    Err(Refusal::Key(format!(
        "the RSA modulus has {bits} bits; the engine takes {MIN_BITS} to {MAX_BITS} bits"
    )))
}

/// Returns the refusal of a key that `rsa` refuses for the reason `error`.
fn not_valid(error: ::rsa::Error) -> Refusal {
    Refusal::Key(format!("the RSA key is not valid: {error}"))
}

/// Returns the integer of the DER `INTEGER` `value`.
fn uint(value: UintRef<'_>) -> BigUint {
    BigUint::from_bytes_be(value.as_bytes())
}

/// Returns the integer of the DER `INTEGER` `value` of a secret key.
///
/// `BigUint::from_bytes_be` reverses a copy of the bytes that it does not
/// wipe. This function reverses a copy that it wipes, and gives the copy to
/// `BigUint::from_bytes_le`, which reads the bytes into the integer with no
/// other copy.
fn secret_uint(value: UintRef<'_>) -> BigUint {
    let mut le = Zeroizing::new(value.as_bytes().to_vec());
    le.reverse();
    BigUint::from_bytes_le(&le)
}

/// Decodes the public key of an `rsaEncryption` SubjectPublicKeyInfo. The
/// caller checks the algorithm and its parameters.
pub(super) fn public_key(
    info: &SubjectPublicKeyInfoRef<'_>,
) -> std::result::Result<VerifyingKey<Sha256>, Refusal> {
    let der = info.subject_public_key.as_bytes().ok_or(Refusal::Form)?;
    let key = pkcs1::RsaPublicKey::from_der(der).map_err(|_| Refusal::Form)?;
    check_size(key.modulus.as_bytes())?;
    let key =
        RsaPublicKey::new_with_max_size(uint(key.modulus), uint(key.public_exponent), MAX_BITS)
            .map_err(not_valid)?;
    Ok(VerifyingKey::new(key))
}

/// Decodes a PKCS#1 `RSAPrivateKey` DER. The key has two primes.
pub(super) fn secret_key(der: &[u8]) -> std::result::Result<SigningKey<Sha256>, Refusal> {
    let key = pkcs1::RsaPrivateKey::from_der(der).map_err(|_| Refusal::Form)?;
    if key.version() != Version::TwoPrime {
        return Err(Refusal::Key("the RSA key has more than two primes".into()));
    }
    check_size(key.modulus.as_bytes())?;
    // The function computes the CRT values from the primes, and does not read
    // them from the DER. `RsaPrivateKey` wipes its integers when it drops.
    let key = RsaPrivateKey::from_components(
        uint(key.modulus),
        uint(key.public_exponent),
        secret_uint(key.private_exponent),
        vec![secret_uint(key.prime1), secret_uint(key.prime2)],
    )
    .map_err(not_valid)?;
    Ok(SigningKey::new(key))
}

/// Returns the public key of `key`.
pub(super) fn public_of(key: &SigningKey<Sha256>) -> VerifyingKey<Sha256> {
    VerifyingKey::new(key.as_ref().to_public_key())
}

/// Signs `data` with `key`. The signature has the length of the modulus.
///
/// The operation is blinded with a random value from the operating system.
/// The blinding does not change the signature, so the function gives the
/// same bytes for the same key and the same data.
pub(super) fn sign(key: &SigningKey<Sha256>, data: &[u8]) -> Result<Vec<u8>> {
    key.try_sign_with_rng(&mut OsRng, data)
        .map(|signature| signature.to_vec())
        .map_err(|e| Error::Signature(format!("spki: the RSA signature failed: {e}")))
}

/// Returns `true` if `key` verifies `blob` as the signature of the data of
/// `prehash`. The key tries a blob of the length of its modulus alone.
///
/// The key puts the `DigestInfo` prefix of SHA-256 before the hash, as a
/// verify of the data does.
pub(super) fn verifies(key: &VerifyingKey<Sha256>, prehash: &Prehash<'_>, blob: &[u8]) -> bool {
    blob.len() == key.as_ref().size()
        && Signature::try_from(blob)
            .is_ok_and(|signature| key.verify_prehash(prehash.get(), &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll, Waker};

    use futures_lite::future::block_on;
    use ostrya_core::{Checksum, base64};
    use pkcs8::PrivateKeyInfo;

    use super::*;
    use crate::{
        Signer, SpkiSigner, SpkiVerifier, Verifier, spki_public_keys, spki_secret_key_lines,
        spki_secret_keys,
    };

    /// Returns the text of the key fixture file `$name`.
    macro_rules! key {
        ($name:literal) => {
            include_str!(concat!("../../../../tests/fixtures/spki/keys/", $name))
        };
    }

    /// The subject of the key file readers in the tests.
    const SUBJECT: &str = "the key file 'k'";
    /// The lowercase hex SHA-256 of the SubjectPublicKeyInfo DER of
    /// `rsa-2048.pub.pem`.
    const FINGERPRINT_2048: &str =
        "e2d83e58fabfb0e5acba74cccf136b03d71794c9fd3921786461435680833875";

    /// Returns the DER of the one PEM block of `pem`.
    fn der_of(pem: &str) -> Vec<u8> {
        pem_rfc7468::decode_vec(pem.as_bytes()).unwrap().1
    }

    /// Returns the PKCS#1 `RSAPrivateKey` DER in the PKCS#8 key of `pem`.
    fn pkcs1_of(pem: &str) -> Vec<u8> {
        let der = der_of(pem);
        PrivateKeyInfo::from_der(&der).unwrap().private_key.to_vec()
    }

    /// Returns the message of a signature error.
    fn message<T>(result: Result<T>) -> String {
        match result {
            Err(Error::Signature(m)) => m,
            Err(other) => panic!("not a signature error: {other}"),
            Ok(_) => panic!("the call has to fail"),
        }
    }

    /// Returns the signer of the PEM `PRIVATE KEY` block `pem`.
    fn signer(pem: &str) -> SpkiSigner {
        let mut signers = spki_secret_keys(pem.as_bytes().to_vec(), SUBJECT).unwrap();
        assert_eq!(signers.len(), 1);
        signers.remove(0)
    }

    /// Returns the outcome of `verifier` for the one blob `blob` over `data`.
    fn outcome(verifier: &SpkiVerifier, data: &[u8], blob: &[u8]) -> crate::VerifyOutcome {
        verifier.verify(data, &[blob.to_vec()]).unwrap()
    }

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

    /// Returns the DER `INTEGER` of the unsigned big-endian integer `be`.
    fn integer(be: &[u8]) -> Vec<u8> {
        if be[0] & 0x80 != 0 {
            return tlv(0x02, &[&[0u8][..], be].concat());
        }
        tlv(0x02, be)
    }

    /// The DER of the OID `rsaEncryption`.
    const RSA_OID: [u8; 11] = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];

    /// Returns the DER of an `rsaEncryption` SubjectPublicKeyInfo of the
    /// `RSAPublicKey` DER `key`, with the DER `parameters` after the OID.
    fn rsa_spki(parameters: &[u8], key: &[u8]) -> Vec<u8> {
        let algorithm = tlv(0x30, &[&RSA_OID[..], parameters].concat());
        let bits = tlv(0x03, &[&[0u8][..], key].concat());
        tlv(0x30, &[algorithm, bits].concat())
    }

    /// Returns the `RSAPublicKey` DER of the SubjectPublicKeyInfo DER `spki`.
    fn rsa_public_key(spki: &[u8]) -> Vec<u8> {
        let info = SubjectPublicKeyInfoRef::from_der(spki).unwrap();
        info.subject_public_key.as_bytes().unwrap().to_vec()
    }

    /// Returns a 16385-bit modulus: 2^16384 + 1.
    fn modulus_16385() -> Vec<u8> {
        let mut n = vec![0u8; 2049];
        n[0] = 1;
        n[2048] = 1;
        n
    }

    #[test]
    fn keys_of_2048_8192_and_16384_bits_sign_and_verify() {
        for (secret, public, bits) in [
            (key!("rsa-2048.pem"), key!("rsa-2048.pub.pem"), 2048),
            (key!("rsa-8192.pem"), key!("rsa-8192.pub.pem"), 8192),
            (key!("rsa-16384.pem"), key!("rsa-16384.pub.pem"), 16384),
        ] {
            let signer = signer(secret);
            assert_eq!(signer.public_key_der(), der_of(public));
            let signature = block_on(signer.sign(b"data")).unwrap();
            assert_eq!(signature.len(), bits / 8);
            let verifier = SpkiVerifier::from_pem(public).unwrap();
            assert!(outcome(&verifier, b"data", &signature).valid, "{bits}");
            assert!(
                !outcome(&verifier, b"other data", &signature).valid,
                "{bits}"
            );
        }
    }

    #[test]
    fn each_secret_key_form_gives_one_public_key() {
        let want = der_of(key!("rsa-2048.pub.pem"));
        let pkcs8 = der_of(key!("rsa-2048.pem"));
        let pkcs1 = der_of(key!("rsa-2048.pkcs1.pem"));
        assert_eq!(pkcs1, pkcs1_of(key!("rsa-2048.pem")));
        let b64 = base64::encode(&pkcs1);
        let wrapped = |line_end: &str| {
            b64.as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join(line_end)
        };
        for signer in [
            SpkiSigner::from_secret_key(&pkcs8).unwrap(),
            SpkiSigner::from_secret_key(&pkcs1).unwrap(),
            SpkiSigner::from_base64(&b64).unwrap(),
            SpkiSigner::from_base64(&wrapped("\n")).unwrap(),
            SpkiSigner::from_base64(&wrapped("\r\n")).unwrap(),
            SpkiSigner::from_pkcs8_pem(key!("rsa-2048.pem")).unwrap(),
            signer(key!("rsa-2048.pem")),
        ] {
            assert_eq!(signer.public_key_der(), want);
        }
        let lines = format!("{}\n{b64}\r\n", base64::encode(&pkcs8));
        let signers = spki_secret_key_lines(lines.into_bytes(), SUBJECT).unwrap();
        assert_eq!(signers.len(), 2);
        for signer in signers {
            assert_eq!(signer.public_key_der(), want);
        }
    }

    #[test]
    fn signing_is_deterministic() {
        let pkcs8 = signer(key!("rsa-2048.pem"));
        let pkcs1 = SpkiSigner::from_secret_key(&der_of(key!("rsa-2048.pkcs1.pem"))).unwrap();
        let first = block_on(pkcs8.sign(b"commit bytes")).unwrap();
        assert_eq!(block_on(pkcs8.sign(b"commit bytes")).unwrap(), first);
        assert_eq!(block_on(pkcs1.sign(b"commit bytes")).unwrap(), first);
    }

    #[test]
    fn the_test_vector_of_openssl_signs_and_verifies() {
        let data = include_bytes!("../../../../tests/fixtures/spki/keys/vector.data");
        let vector = include_bytes!("../../../../tests/fixtures/spki/keys/rsa-2048.vector.sig");
        let signature = block_on(signer(key!("rsa-2048.pem")).sign(data)).unwrap();
        assert_eq!(signature, vector);
        let verifier = SpkiVerifier::from_pem(key!("rsa-2048.pub.pem")).unwrap();
        assert!(outcome(&verifier, data, vector).valid);
        let mut changed = data.to_vec();
        changed[0] ^= 1;
        assert!(!outcome(&verifier, &changed, vector).valid);
    }

    #[test]
    fn a_modulus_outside_2048_to_16384_bits_is_refused() {
        for (secret, public, bits) in [
            (key!("rsa-1024.pem"), key!("rsa-1024.pub.pem"), 1024),
            (key!("rsa-2047.pem"), key!("rsa-2047.pub.pem"), 2047),
            (key!("rsa-16386.pem"), key!("rsa-16386.pub.pem"), 16386),
        ] {
            let reason =
                format!("the RSA modulus has {bits} bits; the engine takes 2048 to 16384 bits");
            assert_eq!(
                message(SpkiVerifier::new([der_of(public)], Vec::<&[u8]>::new())),
                format!("spki public key: {reason}")
            );
            assert_eq!(
                message(SpkiSigner::from_secret_key(&der_of(secret))),
                format!("spki secret key: {reason}")
            );
            assert_eq!(
                message(SpkiSigner::from_secret_key(&pkcs1_of(secret))),
                format!("spki secret key: {reason}")
            );
            assert_eq!(
                message(spki_public_keys(public.as_bytes(), SUBJECT)),
                format!("{SUBJECT}, line 1: {reason}")
            );
            assert_eq!(
                message(spki_secret_keys(secret.as_bytes().to_vec(), SUBJECT)),
                format!("{SUBJECT}, line 1: {reason}")
            );
        }

        // A 16385-bit modulus, one bit above the range. The engine checks the
        // size before it computes with the key, so the other integers of the
        // secret key are not read.
        let reason = "the RSA modulus has 16385 bits; the engine takes 2048 to 16384 bits";
        let public = tlv(
            0x30,
            &[integer(&modulus_16385()), integer(&[1, 0, 1])].concat(),
        );
        assert_eq!(
            message(SpkiVerifier::new(
                [rsa_spki(&[0x05, 0x00], &public)],
                Vec::<&[u8]>::new()
            )),
            format!("spki public key: {reason}")
        );
        let mut fields = vec![integer(&[0]), integer(&modulus_16385())];
        fields.extend(std::iter::repeat_n(integer(&[1]), 7));
        let secret = tlv(0x30, &fields.concat());
        assert_eq!(
            message(SpkiSigner::from_secret_key(&secret)),
            format!("spki secret key: {reason}")
        );
    }

    #[test]
    fn a_multi_prime_secret_key_is_refused() {
        let reason = "the RSA key has more than two primes";
        for der in [
            der_of(key!("rsa-3prime.pem")),
            der_of(key!("rsa-3prime.pkcs1.pem")),
        ] {
            assert_eq!(
                message(SpkiSigner::from_secret_key(&der)),
                format!("spki secret key: {reason}")
            );
        }
        assert_eq!(
            message(spki_secret_keys(
                key!("rsa-3prime.pem").as_bytes().to_vec(),
                SUBJECT
            )),
            format!("{SUBJECT}, line 1: {reason}")
        );
        // The public key of a multi-prime key is a modulus and an exponent.
        assert!(
            !SpkiVerifier::from_pem(key!("rsa-3prime.pub.pem"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_sequence_of_integers_that_is_no_rsa_key_is_in_no_form() {
        let form = "spki secret key: expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER";
        let integers =
            |values: &[u8]| -> Vec<u8> { values.iter().flat_map(|&v| integer(&[v])).collect() };
        // A traditional DSA key, and version 1 with no `otherPrimeInfos` field.
        for fields in [
            integers(&[0, 23, 11, 4, 9, 7]),
            integers(&[1, 5, 5, 5, 5, 5, 5, 5, 5]),
        ] {
            assert_eq!(
                message(SpkiSigner::from_secret_key(&tlv(0x30, &fields))),
                form
            );
        }
    }

    #[test]
    fn an_rsa_pss_key_is_refused() {
        let reason = "the key type RSASSA-PSS is not supported";
        assert_eq!(
            message(SpkiVerifier::from_pem(key!("rsa-pss.pub.pem"))),
            format!("the spki public key text, line 1: {reason}")
        );
        assert_eq!(
            message(SpkiSigner::from_secret_key(&der_of(key!("rsa-pss.pem")))),
            format!("spki secret key: {reason}")
        );
    }

    #[test]
    fn rsa_encryption_parameters_other_than_null_are_refused() {
        let reason = "spki public key: the rsaEncryption parameters are not NULL";
        let key = rsa_public_key(&der_of(key!("rsa-2048.pub.pem")));
        assert_eq!(
            rsa_spki(&[0x05, 0x00], &key),
            der_of(key!("rsa-2048.pub.pem"))
        );
        let oid = [0x06, 0x03, 0x2a, 0x03, 0x04];
        for parameters in [&[][..], &oid[..]] {
            let spki = rsa_spki(parameters, &key);
            assert_eq!(
                message(SpkiVerifier::new([spki], Vec::<&[u8]>::new())),
                reason
            );
        }

        // The same parameters in a PKCS#8 key.
        let pkcs1 = pkcs1_of(key!("rsa-2048.pem"));
        for parameters in [&[][..], &oid[..]] {
            let algorithm = tlv(0x30, &[&RSA_OID[..], parameters].concat());
            let pkcs8 = tlv(
                0x30,
                &[integer(&[0]), algorithm, tlv(0x04, &pkcs1)].concat(),
            );
            assert_eq!(
                message(SpkiSigner::from_secret_key(&pkcs8)),
                "spki secret key: the rsaEncryption parameters are not NULL"
            );
        }
    }

    /// Returns a 2048-bit signer of the three primes of `rsa-3prime.pem`. The
    /// engine refuses the key, so the test builds it with `rsa`.
    fn three_prime_signer() -> SigningKey<Sha256> {
        let der = der_of(key!("rsa-3prime.pkcs1.pem"));
        let key = pkcs1::RsaPrivateKey::from_der(&der).unwrap();
        let mut primes = vec![uint(key.prime1), uint(key.prime2)];
        primes.extend(
            key.other_prime_infos
                .unwrap()
                .iter()
                .map(|info| uint(info.prime)),
        );
        let n = uint(key.modulus);
        let (e, d) = (uint(key.public_exponent), uint(key.private_exponent));
        SigningKey::new(RsaPrivateKey::from_components(n, e, d, primes).unwrap())
    }

    #[test]
    fn a_blob_that_no_trusted_key_verifies_is_not_valid() {
        let verifier = SpkiVerifier::from_pem(key!("rsa-2048.pub.pem")).unwrap();
        let valid = block_on(signer(key!("rsa-2048.pem")).sign(b"data")).unwrap();
        assert!(outcome(&verifier, b"data", &valid).valid);
        let longer = [&valid[..], &[0]].concat();
        let shorter = valid[..valid.len() - 1].to_vec();
        let leading_zero = [&[0][..], &valid].concat();
        let fixed: Vec<u8> = (0..=255u8)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect();
        let other_key = sign(&three_prime_signer(), b"data").unwrap();
        assert_eq!(other_key.len(), 256);
        #[cfg_attr(not(feature = "sign-spki-p256"), allow(unused_mut))]
        let mut blobs = vec![longer, shorter, leading_zero, fixed, other_key];
        // A DER ECDSA signature over the same data.
        #[cfg(feature = "sign-spki-p256")]
        blobs.push(block_on(p256_signer().sign(b"data")).unwrap());
        for blob in blobs {
            let outcome = outcome(&verifier, b"data", &blob);
            assert!(!outcome.valid, "{blob:02x?}");
            let info = &outcome.signatures[0];
            assert!(!info.valid && info.key_missing, "{blob:02x?}");
            assert_eq!(info.fingerprint, None);
            assert_eq!(info.pubkey_algorithm, None);
        }
    }

    #[test]
    fn the_prehash_verify_agrees_with_the_verify_of_the_data() {
        use ::rsa::signature::Verifier as _;

        let info = der_of(key!("rsa-2048.pub.pem"));
        let Ok(key) = public_key(&SubjectPublicKeyInfoRef::from_der(&info).unwrap()) else {
            panic!("the fixture key decodes");
        };
        let valid = block_on(signer(key!("rsa-2048.pem")).sign(b"data")).unwrap();
        let other = sign(&three_prime_signer(), b"data").unwrap();
        let wrong_length = valid[1..].to_vec();
        for data in [&b"data"[..], b"other data", b""] {
            for blob in [&valid, &other, &wrong_length] {
                let prehash = Prehash::new(data);
                let want = blob.len() == key.as_ref().size()
                    && key
                        .verify(data, &Signature::try_from(blob.as_slice()).unwrap())
                        .is_ok();
                assert_eq!(verifies(&key, &prehash, blob), want, "{data:?}");
                // A blob of another length leaves the hash not computed.
                assert_eq!(prehash.digest.get().is_some(), blob.len() == 256);
            }
        }
    }

    #[test]
    fn a_valid_signature_names_the_algorithm_and_the_fingerprint() {
        let public = der_of(key!("rsa-2048.pub.pem"));
        assert_eq!(Checksum::sha256(&public).to_hex(), FINGERPRINT_2048);
        let signature = block_on(signer(key!("rsa-2048.pem")).sign(b"data")).unwrap();
        for verifier in [
            SpkiVerifier::new([&public], Vec::<&[u8]>::new()).unwrap(),
            SpkiVerifier::from_pem(key!("rsa-2048.pub.pem")).unwrap(),
        ] {
            let outcome = outcome(&verifier, b"data", &signature);
            let info = &outcome.signatures[0];
            assert!(info.valid);
            assert_eq!(info.pubkey_algorithm.as_deref(), Some("rsa"));
            assert_eq!(info.fingerprint.as_deref(), Some(FINGERPRINT_2048));
        }
    }

    #[test]
    fn the_public_key_of_a_pkcs1_signer_revokes_the_key_of_the_file() {
        let pkcs1 = SpkiSigner::from_secret_key(&der_of(key!("rsa-2048.pkcs1.pem"))).unwrap();
        let trusted = der_of(key!("rsa-2048.pub.pem"));
        assert!(
            SpkiVerifier::new([&trusted], [pkcs1.public_key_der()])
                .unwrap()
                .is_empty()
        );
        let other = der_of(key!("rsa-8192.pub.pem"));
        assert!(!SpkiVerifier::new([&trusted], [&other]).unwrap().is_empty());
    }

    #[test]
    fn the_sign_future_is_ready_at_once() {
        let signer = signer(key!("rsa-2048.pem"));
        let verifier = SpkiVerifier::from_pem(key!("rsa-2048.pub.pem")).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let signature = match signer.sign(b"data").as_mut().poll(&mut context) {
            Poll::Ready(signature) => signature.unwrap(),
            Poll::Pending => panic!("the sign future is pending"),
        };
        assert!(verifier.verify(b"data", &[signature]).unwrap().valid);
    }

    /// Returns a signer of a P-256 key, from the base64 of its PKCS#8 DER.
    #[cfg(feature = "sign-spki-p256")]
    fn p256_signer() -> SpkiSigner {
        SpkiSigner::from_base64(concat!(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
            "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
            "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
        ))
        .unwrap()
    }

    #[cfg(feature = "sign-spki-p256")]
    #[test]
    fn a_store_of_a_p256_key_and_an_rsa_key_verifies_a_signature_of_each() {
        let p256 = p256_signer();
        let rsa = signer(key!("rsa-2048.pem"));
        let block = pem_rfc7468::encode_string(
            "PUBLIC KEY",
            pem_rfc7468::LineEnding::LF,
            &p256.public_key_der(),
        )
        .unwrap();
        let text = format!("{block}{}", key!("rsa-2048.pub.pem"));
        let verifier = SpkiVerifier::from_pem(&text).unwrap();
        for (signer, algorithm) in [(&p256, "p256"), (&rsa, "rsa")] {
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
