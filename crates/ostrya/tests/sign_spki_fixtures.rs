//! Integration tests that verify spki signatures that the `ostree` tool wrote.
//!
//! The fixtures are in `tests/fixtures/spki/<key type>/`. Each fixture holds a
//! key pair and a copy of the `archive` fixture repository. The `ostree` tool
//! signed the commit of the repository two times, and wrote a signed static
//! delta and a signed summary. The script `tests/fixtures/spki/generate.sh`
//! wrote the fixtures.
//!
//! The tests do not make the fixtures again. Each run of the script makes a
//! new key, and ECDSA takes a random nonce for each signature, so a run gives
//! new bytes. The fixtures are committed, and the script runs only to replace
//! them.

#![cfg(feature = "sign-spki-p256")]

mod common;

use std::path::PathBuf;

use common::fixture_root;
use ostrya::{
    Checksum, Repo, SpkiVerifier, base64, spki_public_keys, spki_secret_keys,
    static_delta_relative_dir,
};
use ostrya_rt::block_on;

/// The commit of the `archive` fixture, which the spki fixtures sign.
const COMMIT: &str = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";

/// The key in the detached metadata that holds the spki signatures.
const SPKI_KEY: &str = "ostree.sign.spki";

/// The order n of P-256 divided by 2 and rounded down, big-endian. A
/// signature with an s above this value has a high s.
const P256_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// A P-256 public key (SubjectPublicKeyInfo DER) in base64 that signed no
/// fixture.
const OTHER_SPKI_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECmz6W9QPu0HuggzW4vGvsnvQIl4J\
yl/b9kVl8fm/qw/xJSQfCEzhnGMQzmyj2quUo96zvuxlCllcTkzsOhwEAg==";

/// The message of a failed fixture check that the fixture causes.
const REGENERATE: &str = "the fixture does not hold the signatures that the generator writes: \
run tests/fixtures/spki/generate.sh p256 again";

/// Returns the directory of the P-256 fixture.
fn p256_dir() -> PathBuf {
    fixture_root().join("../spki/p256")
}

/// Returns the commit that the fixtures sign.
fn commit() -> Checksum {
    Checksum::from_hex(COMMIT).unwrap()
}

/// Returns a verifier that trusts the public key of the P-256 fixture.
fn p256_verifier() -> SpkiVerifier {
    SpkiVerifier::from_pem(std::fs::read(p256_dir().join("public.pem")).unwrap()).unwrap()
}

/// Returns a verifier that trusts a key that signed no fixture.
fn stranger_verifier() -> SpkiVerifier {
    SpkiVerifier::new(
        [base64::decode(OTHER_SPKI_B64).unwrap()],
        Vec::<Vec<u8>>::new(),
    )
    .unwrap()
}

/// Returns `true` if the s of the DER ECDSA-Sig-Value `der` over P-256 is
/// greater than n/2.
///
/// The function reads one SEQUENCE with a short-form length, two INTEGERs with
/// short-form lengths in it, and no byte after them. It removes one leading
/// 0x00 from the value of s and reads the remaining bytes, at most 32, as an
/// unsigned big-endian number. It accepts a negative INTEGER and an INTEGER
/// that is not minimal. The strict DER parse is the verify of the port. The
/// test that calls this function also verifies each blob with the port.
fn has_high_s(der: &[u8]) -> bool {
    assert!(
        der.first() == Some(&0x30)
            && der.get(1).map(|&len| usize::from(len)) == Some(der.len() - 2),
        "the signature is not one DER SEQUENCE"
    );
    let mut at = 2;
    let mut integers = Vec::with_capacity(2);
    for _ in 0..2 {
        assert_eq!(der.get(at), Some(&0x02), "the signature holds no INTEGER");
        let len = usize::from(*der.get(at + 1).expect("the INTEGER has no length"));
        assert!(len < 0x80, "the INTEGER length is not short form");
        let value = der
            .get(at + 2..at + 2 + len)
            .expect("the INTEGER goes past the SEQUENCE");
        integers.push(value);
        at += 2 + len;
    }
    assert_eq!(at, der.len(), "bytes follow the two INTEGERs");
    let s = integers[1];
    let s = s.strip_prefix(&[0]).unwrap_or(s);
    assert!(s.len() <= 32, "s is longer than 32 bytes");
    let mut padded = [0u8; 32];
    padded[32 - s.len()..].copy_from_slice(s);
    padded > P256_HALF_ORDER
}

#[test]
fn p256_fixture_keys_are_one_pair() {
    let dir = p256_dir();
    let secret = std::fs::read(dir.join("secret.pem")).unwrap();
    let signers = spki_secret_keys(secret, "secret.pem").unwrap();
    assert_eq!(signers.len(), 1);
    let public = spki_public_keys(
        &std::fs::read(dir.join("public.pem")).unwrap(),
        "public.pem",
    )
    .unwrap();
    assert_eq!(public.len(), 1);
    assert_eq!(signers[0].public_key_der(), public[0]);
}

/// The tool signed the commit of the P-256 fixture two times. The first
/// signature has a low s, and the second has a high s.
///
/// OpenSSL does not make s low, so the tool writes signatures with a high s.
/// The port accepts a high s. A verify that refuses a high s refuses
/// signatures that the tool writes. Thus the test asserts the s class of each
/// blob, and that each blob verifies.
#[test]
fn p256_tool_commit_verifies_low_and_high_s() {
    block_on(async {
        let repo = Repo::open(&p256_dir().join("repo")).await.unwrap();
        let dict = repo
            .read_commit_detached_metadata(&commit())
            .await
            .unwrap()
            .expect("the commit has detached metadata");
        let value = dict.dict_get(SPKI_KEY).expect("the dict holds spki blobs");
        let array = value.as_variant().map_or(value, |(_, inner)| inner);
        let blobs: Vec<Vec<u8>> = array
            .as_array()
            .expect("the spki value is an array")
            .iter()
            .map(|blob| blob.as_bytes().expect("a blob is a byte string").to_vec())
            .collect();
        assert_eq!(blobs.len(), 2, "{REGENERATE}");
        assert!(!has_high_s(&blobs[0]), "{REGENERATE}");
        assert!(has_high_s(&blobs[1]), "{REGENERATE}");

        let outcome = repo
            .verify_commit(&commit(), &[&p256_verifier()])
            .await
            .unwrap();
        assert!(outcome.valid);
        assert_eq!(outcome.signatures.len(), 2, "{REGENERATE}");
        // Each blob verifies. The second blob has a high s.
        for info in &outcome.signatures {
            assert!(info.valid);
            assert_eq!(info.pubkey_algorithm.as_deref(), Some("p256"));
        }

        let outcome = repo
            .verify_commit(&commit(), &[&stranger_verifier()])
            .await
            .unwrap();
        assert!(
            !outcome.valid,
            "a key that signed no fixture must not verify"
        );
        assert_eq!(outcome.signatures.len(), 2);
        assert!(
            outcome
                .signatures
                .iter()
                .all(|info| info.key_missing && !info.valid)
        );
    });
}

#[test]
fn p256_tool_summary_verifies() {
    block_on(async {
        let repo = Repo::open(&p256_dir().join("repo")).await.unwrap();
        let outcome = repo.verify_summary(&[&p256_verifier()]).await.unwrap();
        assert!(outcome.valid);
        assert!(outcome.signatures.iter().all(|info| info.valid));

        let outcome = repo.verify_summary(&[&stranger_verifier()]).await.unwrap();
        assert!(
            !outcome.valid,
            "a key that signed no fixture must not verify"
        );
        assert_eq!(outcome.signatures.len(), 1);
        assert!(!outcome.signatures[0].valid);
    });
}

#[test]
fn p256_tool_delta_verifies() {
    block_on(async {
        let root = p256_dir().join("repo");
        let repo = Repo::open(&root).await.unwrap();
        let dir = root.join(static_delta_relative_dir(None, &commit()));
        let outcome = repo
            .verify_static_delta(&dir, &[&p256_verifier()])
            .await
            .unwrap();
        assert!(outcome.valid);
        assert!(outcome.signatures.iter().all(|info| info.valid));

        let outcome = repo
            .verify_static_delta(&dir, &[&stranger_verifier()])
            .await
            .unwrap();
        assert!(
            !outcome.valid,
            "a key that signed no fixture must not verify"
        );
        assert_eq!(outcome.signatures.len(), 1);
        assert!(!outcome.signatures[0].valid);
    });
}
