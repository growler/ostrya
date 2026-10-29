//! The Ed25519 key type of the spki engine: pure Ed25519 of RFC 8032.
//!
//! The signer signs the data itself, with no prehash and no context, and the
//! verifier verifies the data itself. The signature is 64 bytes, `R || S`.
//! Ed25519 is deterministic, so the signer gives the same bytes for the same
//! key and the same data.
//!
//! The verify is [`VerifyingKey::verify`] of `ed25519-dalek`, the verify of
//! the ed25519 engine. It checks the equation `[S]B = R + [k]A` with no
//! cofactor, which RFC 8032 permits, and it refuses an `S` that is not below
//! the group order. It accepts a public key of small order. The two engines
//! share no code.

use der::zeroize::Zeroizing;
use ed25519_dalek::pkcs8::EncodePublicKey as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use pkcs8::PrivateKeyInfo;
use spki::SubjectPublicKeyInfoRef;

use super::{Prehash, Refusal};

/// The reason of a refusal of a PKCS#8 key whose public key is not the key of
/// its seed.
const OTHER_PUBLIC_KEY: &str = "the public key of the PKCS#8 key is not the key of its secret key";

/// Decodes the public key of an Ed25519 SubjectPublicKeyInfo. The caller
/// checks the algorithm and the parameters.
///
/// The key is the 32 bytes of the `subjectPublicKey` field. The bytes must
/// decode to a point on the curve. The decode also accepts the encodings
/// that RFC 8032 refuses: a y coordinate that is not below p, and x = 0 with
/// the sign bit set. The key keeps these bytes as they are given.
pub(super) fn public_key(
    info: SubjectPublicKeyInfoRef<'_>,
) -> std::result::Result<VerifyingKey, Refusal> {
    VerifyingKey::try_from(info).map_err(|_| Refusal::Form)
}

/// Decodes the secret key of an Ed25519 PKCS#8 key. The caller checks the
/// algorithm and the parameters.
///
/// The `privateKey` field holds an `OCTET STRING` of the 32-byte seed. If the
/// key has a `publicKey` field, the field holds the public key of the seed.
///
/// The function reads the fields itself, and not with the `KeypairBytes` of
/// `ed25519`. `KeypairBytes` wipes its copy of the seed only with the feature
/// `zeroize` of `ed25519`, and the build does not turn it on.
pub(super) fn pkcs8_secret_key(
    info: PrivateKeyInfo<'_>,
) -> std::result::Result<SigningKey, Refusal> {
    let [0x04, 0x20, seed @ ..] = info.private_key else {
        return Err(Refusal::Form);
    };
    let seed = Zeroizing::new(<[u8; 32]>::try_from(seed).map_err(|_| Refusal::Form)?);
    let key = SigningKey::from_bytes(&seed);
    if info
        .public_key
        .is_some_and(|public| public != key.verifying_key().as_bytes())
    {
        return Err(Refusal::Key(OTHER_PUBLIC_KEY.into()));
    }
    Ok(key)
}

/// Returns the SubjectPublicKeyInfo DER of `key`: the algorithm `id-Ed25519`
/// with no parameters, and the 32 bytes of the key as they were given.
pub(super) fn canonical_der(key: &VerifyingKey) -> Vec<u8> {
    key.to_public_key_der()
        .expect("Ed25519 public key always encodes to SPKI DER")
        .into_vec()
}

/// Signs `data` with `key`, and returns the 64-byte signature.
pub(super) fn sign(key: &SigningKey, data: &[u8]) -> Vec<u8> {
    key.sign(data).to_bytes().to_vec()
}

/// Returns `true` if `key` verifies `signature`, the blob as an Ed25519
/// signature, over the data of `prehash`. A blob that is not 64 bytes is not
/// tried. The key verifies the data, so it does not compute the hash of
/// `prehash`.
pub(super) fn verifies(
    key: &VerifyingKey,
    prehash: &Prehash<'_>,
    signature: Option<&Signature>,
) -> bool {
    signature.is_some_and(|signature| key.verify(prehash.data, signature).is_ok())
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll, Waker};

    use futures_lite::future::block_on;
    use ostrya_core::{Checksum, base64};

    use super::*;
    use crate::{
        Ed25519Signer, Error, Result, Signer, SpkiSigner, SpkiVerifier, Verifier, spki_public_keys,
        spki_secret_key_lines, spki_secret_keys,
    };

    // The key of test 1 in RFC 8032, section 7.1.

    /// The seed of the key, in hex.
    const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    /// The public key, in hex.
    const PUBLIC_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    /// The signature of the empty message, in hex.
    const RFC_SIGNATURE_HEX: &str = concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    /// The lowercase hex SHA-256 of the SubjectPublicKeyInfo DER of the key.
    const FINGERPRINT: &str = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

    /// The `AlgorithmIdentifier` DER of `id-Ed25519`, with no parameters.
    const ALGORITHM: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

    /// The subject of the key file readers in the tests.
    const SUBJECT: &str = "the key file 'k'";

    /// Returns the bytes of the hex text `hex`.
    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
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

    /// Returns the SubjectPublicKeyInfo DER of the `AlgorithmIdentifier` DER
    /// `algorithm` and the key bytes `key`.
    fn spki_of(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
        let bits = tlv(0x03, &[&[0u8][..], key].concat());
        tlv(0x30, &[algorithm, &bits].concat())
    }

    /// Returns the PKCS#8 DER of the version `version`, the
    /// `AlgorithmIdentifier` DER `algorithm`, the `privateKey` content
    /// `private`, and the `publicKey` bytes `public` if they are given.
    fn pkcs8_of(version: u8, algorithm: &[u8], private: &[u8], public: Option<&[u8]>) -> Vec<u8> {
        let mut fields = [
            tlv(0x02, &[version]),
            algorithm.to_vec(),
            tlv(0x04, private),
        ]
        .concat();
        if let Some(public) = public {
            fields.extend(tlv(0x81, &[&[0u8][..], public].concat()));
        }
        tlv(0x30, &fields)
    }

    /// Returns the PKCS#8 DER of the seed `seed`, with the `version` 0
    /// (version 1) and no public key.
    fn pkcs8_v1(seed: &[u8]) -> Vec<u8> {
        pkcs8_of(0, &ALGORITHM, &tlv(0x04, seed), None)
    }

    /// Returns the SubjectPublicKeyInfo DER of the key bytes `key`.
    fn public_der(key: &[u8]) -> Vec<u8> {
        spki_of(&ALGORITHM, key)
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
        SpkiSigner::from_secret_key(&pkcs8_v1(&from_hex(SEED_HEX))).unwrap()
    }

    /// Returns the verifier that trusts the public key `key`.
    fn verifier_of(key: &[u8]) -> SpkiVerifier {
        SpkiVerifier::new([public_der(key)], Vec::<&[u8]>::new()).unwrap()
    }

    /// Returns the verifier that trusts the key.
    fn verifier() -> SpkiVerifier {
        verifier_of(&from_hex(PUBLIC_HEX))
    }

    /// Returns the outcome of `verifier` for the one blob `blob` over `data`.
    fn outcome(verifier: &SpkiVerifier, data: &[u8], blob: &[u8]) -> crate::VerifyOutcome {
        verifier.verify(data, &[blob.to_vec()]).unwrap()
    }

    #[test]
    fn the_rfc_8032_test_1_signature_is_signed_and_verified() {
        let signer = signer();
        assert_eq!(signer.public_key_der(), public_der(&from_hex(PUBLIC_HEX)));
        let signature = block_on(signer.sign(b"")).unwrap();
        assert_eq!(signature, from_hex(RFC_SIGNATURE_HEX));
        let verifier = verifier();
        assert!(outcome(&verifier, b"", &signature).valid);
        assert!(!outcome(&verifier, b"data", &signature).valid);
    }

    #[test]
    fn an_ed25519_key_signs_and_verifies() {
        let signature = block_on(signer().sign(b"data")).unwrap();
        assert_eq!(signature.len(), 64);
        let verifier = verifier();
        assert!(outcome(&verifier, b"data", &signature).valid);
        assert!(!outcome(&verifier, b"other data", &signature).valid);
        let text = pem_block("PUBLIC KEY", &public_der(&from_hex(PUBLIC_HEX)));
        let pem = SpkiVerifier::from_pem(&text).unwrap();
        assert!(outcome(&pem, b"data", &signature).valid);
    }

    #[test]
    fn signing_is_deterministic() {
        let signer = signer();
        let first = block_on(signer.sign(b"commit bytes")).unwrap();
        assert_eq!(block_on(signer.sign(b"commit bytes")).unwrap(), first);
    }

    #[test]
    fn the_ed25519_engine_and_the_spki_engine_write_the_same_bytes() {
        let keypair = [from_hex(SEED_HEX), from_hex(PUBLIC_HEX)].concat();
        let ed25519 = Ed25519Signer::from_secret_key(&keypair).unwrap();
        let spki = signer();
        assert_ne!(ed25519.metadata_key(), spki.metadata_key());
        for data in [&b""[..], b"commit bytes"] {
            assert_eq!(
                block_on(ed25519.sign(data)).unwrap(),
                block_on(spki.sign(data)).unwrap()
            );
        }
    }

    #[test]
    fn each_secret_key_form_gives_one_public_key() {
        let want = public_der(&from_hex(PUBLIC_HEX));
        let seed = from_hex(SEED_HEX);
        let v1 = pkcs8_v1(&seed);
        let v2 = pkcs8_of(
            1,
            &ALGORITHM,
            &tlv(0x04, &seed),
            Some(&from_hex(PUBLIC_HEX)),
        );
        let v1_b64 = base64::encode(&v1);
        let v2_b64 = base64::encode(&v2);
        let v1_pem = pem_block("PRIVATE KEY", &v1);
        let mut signers = vec![
            SpkiSigner::from_secret_key(&v1).unwrap(),
            SpkiSigner::from_secret_key(&v2).unwrap(),
            SpkiSigner::from_base64(&v1_b64).unwrap(),
            SpkiSigner::from_pkcs8_pem(&v1_pem).unwrap(),
            SpkiSigner::from_pkcs8_pem(&pem_block("PRIVATE KEY", &v2)).unwrap(),
        ];
        signers.extend(spki_secret_keys(v1_pem.into_bytes(), SUBJECT).unwrap());
        let lines = format!("{v1_b64}\n{v2_b64}\r\n");
        signers.extend(spki_secret_key_lines(lines.into_bytes(), SUBJECT).unwrap());
        assert_eq!(signers.len(), 8);
        let first = block_on(signers[0].sign(b"data")).unwrap();
        for signer in signers {
            assert_eq!(signer.public_key_der(), want);
            assert_eq!(block_on(signer.sign(b"data")).unwrap(), first);
        }
    }

    #[test]
    fn a_pkcs8_key_whose_public_key_is_another_key_is_refused() {
        let seed = from_hex(SEED_HEX);
        let other = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let short = &from_hex(PUBLIC_HEX)[..31];
        for public in [&other[..], short] {
            let der = pkcs8_of(1, &ALGORITHM, &tlv(0x04, &seed), Some(public));
            assert_eq!(
                message(SpkiSigner::from_secret_key(&der)),
                format!("spki secret key: {OTHER_PUBLIC_KEY}")
            );
            let text = pem_block("PRIVATE KEY", &der);
            assert_eq!(
                message(spki_secret_keys(text.into_bytes(), SUBJECT)),
                format!("{SUBJECT}, line 1: {OTHER_PUBLIC_KEY}")
            );
        }
    }

    #[test]
    fn other_secret_key_forms_are_refused() {
        let form = "spki secret key: expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER";
        let seed = from_hex(SEED_HEX);
        let public = from_hex(PUBLIC_HEX);
        for der in [
            // The `version` 1 (version 2) with no public key.
            pkcs8_of(1, &ALGORITHM, &tlv(0x04, &seed), None),
            // The `version` 0 (version 1) with a public key.
            pkcs8_of(0, &ALGORITHM, &tlv(0x04, &seed), Some(&public)),
            // The seed in the `privateKey` field with no inner OCTET STRING.
            pkcs8_of(0, &ALGORITHM, &seed, None),
            // A seed of 31 bytes and of 33 bytes.
            pkcs8_v1(&seed[..31]),
            pkcs8_v1(&[&seed[..], &[0]].concat()),
            // The inner OCTET STRING alone, the seed alone, and the seed and
            // the public key.
            tlv(0x04, &seed),
            seed.clone(),
            [&seed[..], &public].concat(),
        ] {
            assert_eq!(
                message(SpkiSigner::from_secret_key(&der)),
                form,
                "{der:02x?}"
            );
        }
    }

    #[test]
    fn parameters_of_an_ed25519_key_are_refused() {
        let reason = "the Ed25519 parameters are not absent";
        let seed = from_hex(SEED_HEX);
        let public = from_hex(PUBLIC_HEX);
        let oid = [0x06, 0x03, 0x2b, 0x65, 0x70];
        for parameters in [&[0x05, 0x00][..], &oid] {
            let algorithm = tlv(0x30, &[&oid[..], parameters].concat());
            assert_eq!(
                message(SpkiVerifier::new(
                    [spki_of(&algorithm, &public)],
                    Vec::<&[u8]>::new()
                )),
                format!("spki public key: {reason}")
            );
            assert_eq!(
                message(spki_public_keys(
                    pem_block("PUBLIC KEY", &spki_of(&algorithm, &public)).as_bytes(),
                    SUBJECT
                )),
                format!("{SUBJECT}, line 1: {reason}")
            );
            let secret = pkcs8_of(0, &algorithm, &tlv(0x04, &seed), None);
            assert_eq!(
                message(SpkiSigner::from_secret_key(&secret)),
                format!("spki secret key: {reason}")
            );
        }
    }

    #[test]
    fn a_public_key_that_is_not_a_point_of_32_bytes_is_refused() {
        let form = "spki public key: expected SubjectPublicKeyInfo DER";
        let public = from_hex(PUBLIC_HEX);
        // y = 2 is not the y of a point on the curve.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        // A BIT STRING with unused bits.
        let mut unused_bits = public_der(&public);
        unused_bits[11] = 1;
        for der in [
            public_der(&public[..31]),
            public_der(&[&public[..], &[0]].concat()),
            public_der(&not_a_point),
            unused_bits,
        ] {
            assert_eq!(
                message(SpkiVerifier::new([&der], Vec::<&[u8]>::new())),
                form,
                "{der:02x?}"
            );
        }
    }

    #[test]
    fn a_blob_that_no_trusted_key_verifies_is_not_valid() {
        let verifier = verifier();
        let signature = block_on(signer().sign(b"data")).unwrap();
        let mut longer = signature.clone();
        longer.push(0);
        let shorter = signature[..63].to_vec();
        // The key tries no blob of another length than 64 bytes. It tries a
        // signature of the same data by another key, which fails.
        let other = SigningKey::from_bytes(&[7; 32])
            .sign(b"data")
            .to_bytes()
            .to_vec();
        for blob in [longer, shorter, Vec::new(), other] {
            let outcome = outcome(&verifier, b"data", &blob);
            assert!(!outcome.valid, "{blob:02x?}");
            let info = &outcome.signatures[0];
            assert!(!info.valid && info.key_missing, "{blob:02x?}");
            assert_eq!(info.fingerprint, None);
            assert_eq!(info.pubkey_algorithm, None);
        }
    }

    #[test]
    fn a_key_does_not_compute_the_prehash() {
        let key = signer().key.public_key();
        let prehash = Prehash::new(b"data");
        let signature = block_on(signer().sign(b"data")).unwrap();
        let parse = super::super::SignatureForms::parse;
        assert!(key.verifies(&prehash, &parse(&signature)));
        assert!(!key.verifies(&prehash, &parse(&[0x5a])));
        assert!(prehash.digest.get().is_none());
    }

    #[test]
    fn a_valid_signature_names_the_algorithm_and_the_fingerprint() {
        let der = public_der(&from_hex(PUBLIC_HEX));
        assert_eq!(Checksum::sha256(&der).to_hex(), FINGERPRINT);
        let signature = block_on(signer().sign(b"data")).unwrap();
        for verifier in [
            verifier(),
            SpkiVerifier::from_pem(pem_block("PUBLIC KEY", &der)).unwrap(),
        ] {
            let outcome = outcome(&verifier, b"data", &signature);
            let info = &outcome.signatures[0];
            assert!(info.valid);
            assert_eq!(info.pubkey_algorithm.as_deref(), Some("ed25519"));
            assert_eq!(info.fingerprint.as_deref(), Some(FINGERPRINT));
        }
    }

    #[test]
    fn revocation_matches_the_key_bytes() {
        let public = from_hex(PUBLIC_HEX);
        assert!(
            SpkiVerifier::new([public_der(&public)], [public_der(&public)])
                .unwrap()
                .is_empty()
        );
        let other = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        assert!(
            !SpkiVerifier::new([public_der(&public)], [public_der(&other)])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_non_canonical_key_encoding_is_kept_as_given() {
        // The identity point, y = 1, the same point with y = p + 1, and the
        // same point with x = 0 and the sign bit set. RFC 8032 refuses the
        // last two encodings. The three encodings decode to one point. The
        // `ostree` command also verifies the blob below with each of the
        // three keys.
        let canonical =
            from_hex("0100000000000000000000000000000000000000000000000000000000000000");
        let non_canonical =
            from_hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let sign_bit = from_hex("0100000000000000000000000000000000000000000000000000000000000080");
        for key in [&canonical, &non_canonical, &sign_bit] {
            let der = public_der(key);
            let verifier = verifier_of(key);
            let blob = [canonical.clone(), vec![0; 32]].concat();
            let info = &outcome(&verifier, b"data", &blob).signatures[0];
            assert!(info.valid, "{key:02x?}");
            assert_eq!(
                info.fingerprint.as_deref(),
                Some(Checksum::sha256(&der).to_hex().as_str())
            );
        }
        // A blob whose `R` has the sign bit set does not verify. The
        // `ostree` command also refuses it.
        let blob = [sign_bit.clone(), vec![0; 32]].concat();
        assert!(!outcome(&verifier_of(&sign_bit), b"data", &blob).valid);
        // The revocation of one encoding does not remove the other.
        assert!(
            !SpkiVerifier::new([public_der(&non_canonical)], [public_der(&canonical)])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_sign_future_is_ready_at_once() {
        let signer = signer();
        let verifier = verifier();
        let mut context = Context::from_waker(Waker::noop());
        let signature = match signer.sign(b"data").as_mut().poll(&mut context) {
            Poll::Ready(signature) => signature.unwrap(),
            Poll::Pending => panic!("the sign future is pending"),
        };
        assert!(verifier.verify(b"data", &[signature]).unwrap().valid);
    }

    // The three tests below hold the agreement of the verify with the
    // `ostree` command, which gives the same result for each case.

    /// The order `L` of the group of Ed25519, little-endian.
    const ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    #[test]
    fn a_small_order_key_verifies_the_identity_signature_for_each_message() {
        // The identity point as the public key, and the signature with `R` the
        // identity point and `S` zero.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let verifier = verifier_of(&identity);
        let blob = [&identity[..], &[0u8; 32]].concat();
        for data in [&b""[..], b"data", b"other data"] {
            assert!(outcome(&verifier, data, &blob).valid, "{data:?}");
        }
    }

    // A key with the secret scalar `a`, and two signatures of `b"data"` with
    // the nonce `r`. The values come from the formulas of RFC 8032, computed
    // outside the port. The first signature is `R = [r]B` and
    // `S = r + H(R || A || M) a`. The second signature is `R' = [r]B + T`, with
    // `T` the point of order 2, and `S' = r + H(R' || A || M) a`. The second
    // signature satisfies the cofactored equation `[8][S']B = [8]R' + [8][k]A`
    // and not the equation with no cofactor.

    /// The public key `A`, in hex.
    const COFACTOR_PUBLIC_HEX: &str =
        "36625933c6007dfa76dc46d8f7b66230d95daf512753a55e6a389fa2c5bdfa31";
    /// The signature with `R = [r]B`, in hex.
    const COFACTOR_HONEST_HEX: &str = concat!(
        "1373153f9b3c39a4530d70b40a7a97feee5284f4cdc74507cfe316c0d1767198",
        "5a694e77eaf50c0a65b5422439928c03eab64be610656ef5b036e08416b8a500",
    );
    /// The signature with `R' = [r]B + T`, in hex.
    const COFACTOR_TORSION_HEX: &str = concat!(
        "da8ceac064c3c65bacf28f4bf585680111ad7b0b3238baf8301ce93f2e898e67",
        "893d5d7981e96653b47f9da9b270a4bf6296de16387a8e645397d64cf530200e",
    );

    #[test]
    fn a_signature_that_passes_only_a_cofactored_check_does_not_verify() {
        let verifier = verifier_of(&from_hex(COFACTOR_PUBLIC_HEX));
        let honest = from_hex(COFACTOR_HONEST_HEX);
        assert!(outcome(&verifier, b"data", &honest).valid);
        let torsion = from_hex(COFACTOR_TORSION_HEX);
        // `R'` differs from `R` and `S'` differs from `S`.
        assert_ne!(torsion[..32], honest[..32]);
        assert_ne!(torsion[32..], honest[32..]);
        let outcome = outcome(&verifier, b"data", &torsion);
        assert!(!outcome.valid);
        assert!(outcome.signatures[0].key_missing);
    }

    #[test]
    fn a_signature_whose_s_is_not_reduced_does_not_verify() {
        let verifier = verifier();
        let signature = block_on(signer().sign(b"data")).unwrap();
        assert!(outcome(&verifier, b"data", &signature).valid);
        // S + L, little-endian. `S` is below `L`, so the sum fits in 32 bytes.
        let mut s_plus_l = [0u8; 32];
        let mut carry = 0u16;
        for (i, byte) in s_plus_l.iter_mut().enumerate() {
            let sum = u16::from(signature[32 + i]) + u16::from(ORDER[i]) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        let blob = [&signature[..32], &s_plus_l].concat();
        let outcome = outcome(&verifier, b"data", &blob);
        assert!(!outcome.valid);
        assert!(outcome.signatures[0].key_missing);
    }

    #[test]
    fn a_store_of_the_four_key_types_verifies_a_signature_of_each() {
        // A P-256 key and a P-384 key, base64 of the PKCS#8 DER.
        let p256 = SpkiSigner::from_base64(concat!(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
            "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
            "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
        ))
        .unwrap();
        let p384 = SpkiSigner::from_base64(concat!(
            "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBrnT2tLhuMHAWxmHW2ZZ9N4jw7Znvy",
            "l7qapHdAeHE32JbVck5McKgl+HLJ6mDS7fWhZANiAATsOk5BW04ZpFaGGAKfQn+l2pqLxK6S4C4G",
            "quUoazAMZN748OqQVYZgZKJUUVSAvBOAFdm3LX1XJE6o75rAxiGJZwilk2f537n1TKhLPxydsSiL",
            "Ixw64NT+c0T9JTMmRyA=",
        ))
        .unwrap();
        let rsa_pem = include_str!("../../../../tests/fixtures/spki/keys/rsa-2048.pem");
        let rsa = spki_secret_keys(rsa_pem.as_bytes().to_vec(), SUBJECT)
            .unwrap()
            .remove(0);
        let ed25519 = signer();
        let text: String = [&p256, &p384, &ed25519, &rsa]
            .iter()
            .map(|signer| pem_block("PUBLIC KEY", &signer.public_key_der()))
            .collect();
        let verifier = SpkiVerifier::from_pem(&text).unwrap();
        for (signer, algorithm) in [
            (&p256, "p256"),
            (&p384, "p384"),
            (&ed25519, "ed25519"),
            (&rsa, "rsa"),
        ] {
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
