//! Integration tests that verify spki signatures that the `ostree` tool wrote.
//!
//! The fixtures are in `tests/fixtures/spki/<key type>/`, where the key type is
//! `p256` or `rsa`. Each fixture holds a key pair and a copy of the `archive`
//! fixture repository. The `ostree` tool signed the commit of the repository,
//! and wrote a signed static delta and a signed summary. The script
//! `tests/fixtures/spki/generate.sh` wrote the fixtures.
//!
//! The tests of each key type are in one module, under the `cfg` of its key
//! feature:
//!
//! - `p256`: the tool signed the commit two times. The first signature has a
//!   low s, and the second has a high s. The tests verify each signature.
//! - `rsa`: the tool signed the commit one time. RSA PKCS#1 v1.5 is
//!   deterministic. Thus the tests also sign the commit, the summary, and the
//!   superblock with the port, and compare the bytes with the signatures of
//!   the tool.
//!
//! The tests do not make the fixtures again. Each run of the script makes a
//! new key, so a run gives new bytes. The fixtures are committed, and the
//! script runs only to replace them.

#![cfg(any(feature = "sign-spki-p256", feature = "sign-spki-rsa"))]

mod common;

use std::path::PathBuf;

use common::fixture_root;
use ostrya::{
    Checksum, Repo, SpkiSigner, SpkiVerifier, Value, spki_public_keys, spki_secret_keys,
    static_delta_relative_dir,
};
use ostrya_rt::block_on;

/// The commit of the `archive` fixture, which the spki fixtures sign.
const COMMIT: &str = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";

/// The key in the detached metadata that holds the spki signatures.
const SPKI_KEY: &str = "ostree.sign.spki";

/// Returns the directory of the fixture of the key type `ty`.
fn fixture_dir(ty: &str) -> PathBuf {
    fixture_root().join("../spki").join(ty)
}

/// Returns the message of a failed fixture check that the fixture of the key
/// type `ty` causes.
fn regenerate(ty: &str) -> String {
    format!(
        "the fixture does not hold the signatures that the generator writes: \
         run tests/fixtures/spki/generate.sh {ty} again as CONTRIBUTING.md states"
    )
}

/// Returns the commit that the fixtures sign.
fn commit() -> Checksum {
    Checksum::from_hex(COMMIT).unwrap()
}

/// Returns the signer of the secret key of the fixture of the key type `ty`.
fn fixture_signer(ty: &str) -> SpkiSigner {
    let secret = std::fs::read(fixture_dir(ty).join("secret.pem")).unwrap();
    let mut signers = spki_secret_keys(secret, "secret.pem").unwrap();
    assert_eq!(signers.len(), 1);
    signers.remove(0)
}

/// Returns a verifier that trusts the public key of the fixture of the key
/// type `ty`.
fn fixture_verifier(ty: &str) -> SpkiVerifier {
    SpkiVerifier::from_pem(std::fs::read(fixture_dir(ty).join("public.pem")).unwrap()).unwrap()
}

/// Asserts that the secret key and the public key of the fixture of the key
/// type `ty` are one key pair.
fn assert_fixture_keys_are_one_pair(ty: &str) {
    let signer = fixture_signer(ty);
    let public = spki_public_keys(
        &std::fs::read(fixture_dir(ty).join("public.pem")).unwrap(),
        "public.pem",
    )
    .unwrap();
    assert_eq!(public.len(), 1);
    assert_eq!(signer.public_key_der(), public[0]);
}

/// Returns the spki blobs of the `a{sv}` dict `dict`, in blob order.
fn spki_blobs(dict: &Value) -> Vec<Vec<u8>> {
    let value = dict.dict_get(SPKI_KEY).expect("the dict holds spki blobs");
    let array = value.as_variant().map_or(value, |(_, inner)| inner);
    array
        .as_array()
        .expect("the spki value is an array")
        .iter()
        .map(|blob| blob.as_bytes().expect("a blob is a byte string").to_vec())
        .collect()
}

#[cfg(feature = "sign-spki-p256")]
mod p256 {
    use super::*;
    use ostrya::base64;

    /// The key type of the fixture.
    const TYPE: &str = "p256";

    /// The order n of P-256 divided by 2 and rounded down, big-endian. A
    /// signature with an s above this value has a high s.
    const P256_HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];

    /// A P-256 public key (SubjectPublicKeyInfo DER) in base64 that signed no
    /// fixture.
    const OTHER_SPKI_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECmz6W9QPu0HuggzW4vGvsnvQIl4J\
    yl/b9kVl8fm/qw/xJSQfCEzhnGMQzmyj2quUo96zvuxlCllcTkzsOhwEAg==";

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
    /// The function reads one SEQUENCE with a short-form length, two INTEGERs
    /// with short-form lengths in it, and no byte after them. It removes one
    /// leading 0x00 from the value of s and reads the remaining bytes, at most
    /// 32, as an unsigned big-endian number. It accepts a negative INTEGER and
    /// an INTEGER that is not minimal. The strict DER parse is the verify of
    /// the port. The test that calls this function also verifies each blob
    /// with the port.
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
        assert_fixture_keys_are_one_pair(TYPE);
    }

    /// The tool signed the commit of the P-256 fixture two times. The first
    /// signature has a low s, and the second has a high s.
    ///
    /// OpenSSL does not make s low, so the tool writes signatures with a high
    /// s. The port accepts a high s. A verify that refuses a high s refuses
    /// signatures that the tool writes. Thus the test asserts the s class of
    /// each blob, and that each blob verifies.
    #[test]
    fn p256_tool_commit_verifies_low_and_high_s() {
        block_on(async {
            let repo = Repo::open(&fixture_dir(TYPE).join("repo")).await.unwrap();
            let dict = repo
                .read_commit_detached_metadata(&commit())
                .await
                .unwrap()
                .expect("the commit has detached metadata");
            let blobs = spki_blobs(&dict);
            assert_eq!(blobs.len(), 2, "{}", regenerate(TYPE));
            assert!(!has_high_s(&blobs[0]), "{}", regenerate(TYPE));
            assert!(has_high_s(&blobs[1]), "{}", regenerate(TYPE));

            let outcome = repo
                .verify_commit(&commit(), &[&fixture_verifier(TYPE)])
                .await
                .unwrap();
            assert!(outcome.valid);
            assert_eq!(outcome.signatures.len(), 2, "{}", regenerate(TYPE));
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
            let repo = Repo::open(&fixture_dir(TYPE).join("repo")).await.unwrap();
            let outcome = repo
                .verify_summary(&[&fixture_verifier(TYPE)])
                .await
                .unwrap();
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
            let root = fixture_dir(TYPE).join("repo");
            let repo = Repo::open(&root).await.unwrap();
            let dir = root.join(static_delta_relative_dir(None, &commit()));
            let outcome = repo
                .verify_static_delta(&dir, &[&fixture_verifier(TYPE)])
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
}

#[cfg(feature = "sign-spki-rsa")]
mod rsa {
    use std::path::Path;
    use std::process::Command;

    use super::*;
    use common::TmpDir;
    use ostrya::{Signer, Type, from_bytes};

    /// The key type of the fixture.
    const TYPE: &str = "rsa";

    /// The length in bytes of a signature of the 2048-bit fixture key.
    const SIGNATURE_LEN: usize = 256;

    /// Returns a verifier that trusts an RSA key that signed no fixture.
    ///
    /// The key is `rsa-2048.pub.pem` of the key fixtures in
    /// `tests/fixtures/spki/keys/`.
    fn stranger_verifier() -> SpkiVerifier {
        let pem = std::fs::read(fixture_root().join("../spki/keys/rsa-2048.pub.pem")).unwrap();
        SpkiVerifier::from_pem(pem).unwrap()
    }

    /// Returns the path of the `.commitmeta` of the fixture commit, relative to
    /// the repository.
    fn commitmeta_path() -> String {
        format!("objects/{}/{}.commitmeta", &COMMIT[..2], &COMMIT[2..])
    }

    /// Reads the signed superblock of the delta in the repository `root`.
    /// Returns the superblock bytes that the signatures sign, and the spki
    /// blobs.
    fn read_signed_superblock(root: &Path) -> (Vec<u8>, Vec<Vec<u8>>) {
        let path = root
            .join(static_delta_relative_dir(None, &commit()))
            .join("superblock");
        let bytes = std::fs::read(path).unwrap();
        let value = from_bytes(&Type::parse("(taya{sv})").unwrap(), &bytes).unwrap();
        let fields = value.as_tuple().expect("the superblock is a tuple");
        let payload = fields[1]
            .as_bytes()
            .expect("the signed superblock is a byte string")
            .to_vec();
        (payload, spki_blobs(&fields[2]))
    }

    /// Copies a directory tree with its attributes (`cp -a`).
    fn copy_tree(from: &Path, to: &Path) {
        let status = Command::new("cp")
            .args(["-a"])
            .arg(from)
            .arg(to)
            .status()
            .expect("run cp");
        assert!(status.success(), "cp -a {from:?} {to:?} failed");
    }

    #[test]
    fn rsa_fixture_keys_are_one_pair() {
        assert_fixture_keys_are_one_pair(TYPE);
    }

    #[test]
    fn rsa_tool_commit_verifies() {
        block_on(async {
            let repo = Repo::open(&fixture_dir(TYPE).join("repo")).await.unwrap();
            let dict = repo
                .read_commit_detached_metadata(&commit())
                .await
                .unwrap()
                .expect("the commit has detached metadata");
            let blobs = spki_blobs(&dict);
            assert_eq!(blobs.len(), 1, "{}", regenerate(TYPE));
            assert_eq!(blobs[0].len(), SIGNATURE_LEN, "{}", regenerate(TYPE));

            let fingerprint = Checksum::sha256(&fixture_signer(TYPE).public_key_der()).to_hex();
            let outcome = repo
                .verify_commit(&commit(), &[&fixture_verifier(TYPE)])
                .await
                .unwrap();
            assert!(outcome.valid);
            assert_eq!(outcome.signatures.len(), 1);
            let info = &outcome.signatures[0];
            assert!(info.valid);
            assert_eq!(info.pubkey_algorithm.as_deref(), Some("rsa"));
            assert_eq!(info.fingerprint.as_deref(), Some(fingerprint.as_str()));

            let outcome = repo
                .verify_commit(&commit(), &[&stranger_verifier()])
                .await
                .unwrap();
            assert!(
                !outcome.valid,
                "a key that signed no fixture must not verify"
            );
            assert_eq!(outcome.signatures.len(), 1);
            assert!(outcome.signatures[0].key_missing);
            assert!(!outcome.signatures[0].valid);
        });
    }

    #[test]
    fn rsa_tool_summary_verifies() {
        block_on(async {
            let repo = Repo::open(&fixture_dir(TYPE).join("repo")).await.unwrap();
            let outcome = repo
                .verify_summary(&[&fixture_verifier(TYPE)])
                .await
                .unwrap();
            assert!(outcome.valid);
            assert_eq!(outcome.signatures.len(), 1, "{}", regenerate(TYPE));
            assert!(outcome.signatures[0].valid);

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
    fn rsa_tool_delta_verifies() {
        block_on(async {
            let root = fixture_dir(TYPE).join("repo");
            let repo = Repo::open(&root).await.unwrap();
            let dir = root.join(static_delta_relative_dir(None, &commit()));
            let outcome = repo
                .verify_static_delta(&dir, &[&fixture_verifier(TYPE)])
                .await
                .unwrap();
            assert!(outcome.valid);
            assert_eq!(outcome.signatures.len(), 1, "{}", regenerate(TYPE));
            assert!(outcome.signatures[0].valid);

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

    /// The port signs the commit of a copy of the fixture with the fixture
    /// key. RSA PKCS#1 v1.5 is deterministic, so the signature and the whole
    /// `.commitmeta` file are the same bytes as the ones that the tool wrote.
    #[test]
    fn rsa_port_commit_signature_is_the_tool_signature() {
        let tmp = TmpDir::new("spki-rsa-commit");
        let root = tmp.path().join("repo");
        let fixture = fixture_dir(TYPE).join("repo");
        copy_tree(&fixture, &root);
        let tool_meta = std::fs::read(fixture.join(commitmeta_path())).unwrap();
        let tool_dict = from_bytes(&Type::parse("a{sv}").unwrap(), &tool_meta).unwrap();
        let tool_blobs = spki_blobs(&tool_dict);
        assert_eq!(tool_blobs.len(), 1, "{}", regenerate(TYPE));
        std::fs::remove_file(root.join(commitmeta_path())).unwrap();

        block_on(async {
            let repo = Repo::open(&root).await.unwrap();
            repo.sign_commit(&commit(), &fixture_signer(TYPE))
                .await
                .unwrap();
            let dict = repo
                .read_commit_detached_metadata(&commit())
                .await
                .unwrap()
                .expect("the commit has detached metadata");
            assert_eq!(spki_blobs(&dict), tool_blobs);
        });
        let port_meta = std::fs::read(root.join(commitmeta_path())).unwrap();
        assert_eq!(
            port_meta, tool_meta,
            "the port and the tool write the same .commitmeta bytes"
        );
    }

    /// The port signs the `summary` file and the signed superblock bytes of
    /// the fixture with the fixture key. Each signature is the same bytes as
    /// the signature that the tool wrote.
    #[test]
    fn rsa_port_summary_and_delta_signatures_are_the_tool_signatures() {
        block_on(async {
            let root = fixture_dir(TYPE).join("repo");
            let repo = Repo::open(&root).await.unwrap();
            let signer = fixture_signer(TYPE);

            let summary = repo
                .read_summary()
                .await
                .unwrap()
                .expect("the fixture has a summary");
            let signatures = repo
                .read_summary_signature()
                .await
                .unwrap()
                .expect("the fixture has a summary.sig");
            let tool = spki_blobs(&signatures);
            assert_eq!(tool.len(), 1, "{}", regenerate(TYPE));
            assert_eq!(signer.sign(&summary).await.unwrap(), tool[0]);

            let (payload, tool) = read_signed_superblock(&root);
            assert_eq!(tool.len(), 1, "{}", regenerate(TYPE));
            assert_eq!(signer.sign(&payload).await.unwrap(), tool[0]);
        });
    }
}
