//! Integration tests that compare the spki engine with the `ostree` tool in
//! both directions.
//!
//! The fixtures are in `tests/fixtures/spki/<key type>/`, where the key type is
//! `p256`, `p384`, `ed25519`, or `rsa`. Each fixture holds a key pair and a copy of the `archive`
//! fixture repository. The `ostree` tool signed the commit of the repository,
//! and wrote a signed static delta and a signed summary. The script
//! `tests/fixtures/spki/generate.sh` wrote the fixtures.
//!
//! The tests of each key type are in one module, under the `cfg` of its key
//! feature:
//!
//! - `p256` and `p384`: the tool signed the commit two times. The first
//!   signature has a low s, and the second has a high s. The tests verify
//!   each signature.
//! - `ed25519` and `rsa`: the tool signed the commit one time. Ed25519 and
//!   RSA PKCS#1 v1.5 are deterministic. Thus the tests also sign the commit,
//!   the summary, and the superblock with the port, and compare the bytes with
//!   the signatures of the tool.
//!
//! The tests do not make the fixtures again. Each run of the script makes a
//! new key, so a run gives new bytes. The fixtures are committed, and the
//! script runs only to replace them.
//!
//! In the other direction, the test `<key type>_tool_verifies_port_signatures`
//! of each module signs a copy of the `archive` fixture repository with the
//! fixture key. The port signs the commit, a static delta, and the summary.
//! The tool then verifies each signature with the public key of the fixture,
//! and refuses each signature with a key of the same type that signed nothing.
//! This part needs a build of the tool with the features `openssl` and
//! `sign-spki` in `ostree --version`. Without such a build the part skips, and
//! `OSTRYA_REQUIRE_OSTREE_SPKI` turns the skip into a failure.

#![cfg(any(
    feature = "sign-spki-p256",
    feature = "sign-spki-p384",
    feature = "sign-spki-ed25519",
    feature = "sign-spki-rsa"
))]

mod common;

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;

use common::{TmpDir, fixture_repo, fixture_root, ostree_supports_spki};
use ostrya::{
    Checksum, DeltaOptions, Repo, Signer, SpkiSigner, SpkiVerifier, SummaryOptions, Value,
    spki_public_keys, spki_secret_keys, static_delta_relative_dir,
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

/// Returns the path of the `.commitmeta` of the fixture commit, relative to
/// the repository.
#[cfg(any(feature = "sign-spki-ed25519", feature = "sign-spki-rsa"))]
fn commitmeta_path() -> String {
    format!("objects/{}/{}.commitmeta", &COMMIT[..2], &COMMIT[2..])
}

/// Reads the signed superblock of the delta in the repository `root`.
/// Returns the superblock bytes that the signatures sign, and the spki
/// blobs.
#[cfg(any(feature = "sign-spki-ed25519", feature = "sign-spki-rsa"))]
fn read_signed_superblock(root: &std::path::Path) -> (Vec<u8>, Vec<Vec<u8>>) {
    let path = root
        .join(static_delta_relative_dir(None, &commit()))
        .join("superblock");
    let bytes = std::fs::read(path).unwrap();
    let value = ostrya::from_bytes(&ostrya::Type::parse("(taya{sv})").unwrap(), &bytes).unwrap();
    let fields = value.as_tuple().expect("the superblock is a tuple");
    let payload = fields[1]
        .as_bytes()
        .expect("the signed superblock is a byte string")
        .to_vec();
    (payload, spki_blobs(&fields[2]))
}

/// Copies a directory tree with its attributes (`cp -a`).
fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    let status = std::process::Command::new("cp")
        .args(["-a"])
        .arg(from)
        .arg(to)
        .status()
        .expect("run cp");
    assert!(status.success(), "cp -a {from:?} {to:?} failed");
}

/// Returns `true` if the s of the DER ECDSA-Sig-Value `der` is greater than
/// `half_order`, the order n of the curve divided by 2 and rounded down,
/// big-endian.
///
/// The function reads one SEQUENCE with a short-form length, two INTEGERs
/// with short-form lengths in it, and no byte after them. It removes one
/// leading 0x00 from the value of s and reads the remaining bytes, at most the
/// length of `half_order`, as an unsigned big-endian number. It accepts a
/// negative INTEGER and an INTEGER that is not minimal. The strict DER parse
/// is the verify of the port. The test that calls this function also verifies
/// each blob with the port.
#[cfg(any(feature = "sign-spki-p256", feature = "sign-spki-p384"))]
fn has_high_s(der: &[u8], half_order: &[u8]) -> bool {
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
    let width = half_order.len();
    assert!(s.len() <= width, "s is longer than {width} bytes");
    let mut padded = vec![0u8; width];
    padded[width - s.len()..].copy_from_slice(s);
    padded.as_slice() > half_order
}

/// Runs the `ostree` command with `args`, and returns its output with no check
/// of the exit status.
fn tool(args: &[&str]) -> Output {
    Command::new("ostree")
        .args(args)
        .output()
        .expect("run ostree")
}

/// The port signs a copy of the `archive` fixture with the secret key of the
/// fixture of the key type `ty`: the commit, a static delta from scratch to
/// the commit, and the summary. The port verifies the signatures of the delta
/// and of the summary first.
///
/// The tool then verifies each signature with `public.pem` of the fixture,
/// and refuses each signature with `stranger_pem`, a PEM `PUBLIC KEY` of the
/// same key type that signed nothing. The tool verifies the summary through a
/// client repository with one `file://` remote for each key. Each refusal must
/// give the reason of a signature that does not verify, so a key that the tool
/// cannot load does not satisfy the test.
fn assert_tool_verifies_port_signatures(ty: &str, stranger_pem: &str) {
    let tmp = TmpDir::new(&format!("spki-{ty}-tool-verifies"));
    let root = tmp.path().join("repo");
    copy_tree(&fixture_repo("archive"), &root);
    block_on(async {
        let repo = Repo::open(&root).await.unwrap();
        let signer: Arc<dyn Signer> = Arc::new(fixture_signer(ty));
        repo.sign_commit(&commit(), &*signer).await.unwrap();
        let opts = DeltaOptions {
            signers: vec![signer.clone()],
            ..Default::default()
        };
        repo.generate_static_delta(None, &commit(), &opts)
            .await
            .unwrap();
        repo.regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        repo.sign_summary(&*signer).await.unwrap();

        let verifier = fixture_verifier(ty);
        let dir = root.join(static_delta_relative_dir(None, &commit()));
        let outcome = repo.verify_static_delta(&dir, &[&verifier]).await.unwrap();
        assert!(
            outcome.valid,
            "the port does not verify its delta signature"
        );
        let outcome = repo.verify_summary(&[&verifier]).await.unwrap();
        assert!(
            outcome.valid,
            "the port does not verify its summary signature"
        );
    });

    if !ostree_supports_spki() {
        eprintln!("skipping: the installed `ostree` carries no spki engine");
        return;
    }
    let stranger = tmp.path().join("stranger.pem");
    std::fs::write(&stranger, stranger_pem).unwrap();
    let public = fixture_dir(ty).join("public.pem");
    let repo_arg = format!("--repo={}", root.display());
    let refused = "spki: Signature couldn't be verified with:";
    let client_arg = format!("--repo={}", tmp.path().join("client").display());
    let init = tool(&[&client_arg, "init", "--mode=archive"]);
    assert!(init.status.success(), "ostree init: {init:?}");
    for (keys, trusted) in [(&public, true), (&stranger, false)] {
        let keys_arg = format!("--keys-file={}", keys.display());
        let label = format!("{ty} under {}", keys.display());

        let out = tool(&[
            &repo_arg, "sign", "--verify", "-s", "spki", &keys_arg, COMMIT,
        ]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(if trusted { 0 } else { 1 }),
            "ostree sign --verify, {label}: {stdout}{stderr}"
        );
        if trusted {
            assert!(
                stdout.starts_with("spki: Signature verified successfully with key '"),
                "ostree sign --verify, {label}: {stdout}"
            );
        } else {
            assert!(
                stderr.contains(refused),
                "ostree sign --verify, {label}: {stderr}"
            );
        }

        let out = tool(&[
            &repo_arg,
            "static-delta",
            "verify",
            "--sign-type=spki",
            &keys_arg,
            COMMIT,
        ]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(if trusted { 0 } else { 1 }),
            "ostree static-delta verify, {label}: {stdout}{stderr}"
        );
        if trusted {
            assert_eq!(
                stdout, "Verification OK\n",
                "ostree static-delta verify, {label}"
            );
        } else {
            assert_eq!(
                stdout, "Verification fails\n",
                "ostree static-delta verify, {label}"
            );
            assert!(
                stderr.contains(refused),
                "ostree static-delta verify, {label}: {stderr}"
            );
        }

        let remote = if trusted { "trusted" } else { "stranger" };
        let add = tool(&[
            &client_arg,
            "remote",
            "add",
            "--set=gpg-verify=false",
            "--set=gpg-verify-summary=false",
            "--set=sign-verify-summary=true",
            &format!("--set=verification-spki-file={}", keys.display()),
            remote,
            &format!("file://{}", root.display()),
        ]);
        assert!(add.status.success(), "ostree remote add: {add:?}");
        let out = tool(&[&client_arg, "remote", "summary", remote]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(if trusted { 0 } else { 1 }),
            "ostree remote summary, {label}: {stderr}"
        );
        if !trusted {
            assert!(
                stderr.contains(refused),
                "ostree remote summary, {label}: {stderr}"
            );
        }
    }
}

#[cfg(feature = "sign-spki-p256")]
mod p256 {
    use super::*;
    use common::wrap_pem;
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

    #[test]
    fn p256_fixture_keys_are_one_pair() {
        assert_fixture_keys_are_one_pair(TYPE);
    }

    #[test]
    fn p256_tool_verifies_port_signatures() {
        assert_tool_verifies_port_signatures(TYPE, &wrap_pem("PUBLIC KEY", OTHER_SPKI_B64));
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
            assert!(
                !has_high_s(&blobs[0], &P256_HALF_ORDER),
                "{}",
                regenerate(TYPE)
            );
            assert!(
                has_high_s(&blobs[1], &P256_HALF_ORDER),
                "{}",
                regenerate(TYPE)
            );

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

#[cfg(feature = "sign-spki-p384")]
mod p384 {
    use super::*;
    use common::wrap_pem;
    use ostrya::base64;

    /// The key type of the fixture.
    const TYPE: &str = "p384";

    /// The order n of P-384 divided by 2 and rounded down, big-endian. A
    /// signature with an s above this value has a high s.
    const P384_HALF_ORDER: [u8; 48] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe3, 0xb1, 0xa6, 0xc0, 0xfa, 0x1b,
        0x96, 0xef, 0xac, 0x0d, 0x06, 0xd9, 0x24, 0x58, 0x53, 0xbd, 0x76, 0x76, 0x0c, 0xb5, 0x66,
        0x62, 0x94, 0xb9,
    ];

    /// A P-384 public key (SubjectPublicKeyInfo DER) in base64 that signed no
    /// fixture: the key of RFC 6979, appendix A.2.6.
    const OTHER_SPKI_B64: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7DpOQVtOGaRWhhgCn0J/pdqai8SukuAu\
    BqrlKGswDGTe+PDqkFWGYGSiVFFUgLwTgBXZty19VyROqO+awMYhiWcIpZNn+d+59UyoSz8cnbEoiyMcOuDU/nNE/SUzJkcg";

    /// Returns a verifier that trusts a key that signed no fixture.
    fn stranger_verifier() -> SpkiVerifier {
        SpkiVerifier::new(
            [base64::decode(OTHER_SPKI_B64).unwrap()],
            Vec::<Vec<u8>>::new(),
        )
        .unwrap()
    }

    #[test]
    fn p384_fixture_keys_are_one_pair() {
        assert_fixture_keys_are_one_pair(TYPE);
    }

    #[test]
    fn p384_tool_verifies_port_signatures() {
        assert_tool_verifies_port_signatures(TYPE, &wrap_pem("PUBLIC KEY", OTHER_SPKI_B64));
    }

    /// The tool signed the commit of the P-384 fixture two times. The first
    /// signature has a low s, and the second has a high s.
    ///
    /// The port verifies a P-384 signature over the SHA-256 of the data, so a
    /// valid blob shows that the tool signs this hash. The port accepts a high
    /// s, as for P-256.
    #[test]
    fn p384_tool_commit_verifies_low_and_high_s() {
        block_on(async {
            let repo = Repo::open(&fixture_dir(TYPE).join("repo")).await.unwrap();
            let dict = repo
                .read_commit_detached_metadata(&commit())
                .await
                .unwrap()
                .expect("the commit has detached metadata");
            let blobs = spki_blobs(&dict);
            assert_eq!(blobs.len(), 2, "{}", regenerate(TYPE));
            assert!(
                !has_high_s(&blobs[0], &P384_HALF_ORDER),
                "{}",
                regenerate(TYPE)
            );
            assert!(
                has_high_s(&blobs[1], &P384_HALF_ORDER),
                "{}",
                regenerate(TYPE)
            );

            let fingerprint = Checksum::sha256(&fixture_signer(TYPE).public_key_der()).to_hex();
            let outcome = repo
                .verify_commit(&commit(), &[&fixture_verifier(TYPE)])
                .await
                .unwrap();
            assert!(outcome.valid);
            assert_eq!(outcome.signatures.len(), 2, "{}", regenerate(TYPE));
            // Each blob verifies. The second blob has a high s.
            for info in &outcome.signatures {
                assert!(info.valid);
                assert_eq!(info.pubkey_algorithm.as_deref(), Some("p384"));
                assert_eq!(info.fingerprint.as_deref(), Some(fingerprint.as_str()));
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
    fn p384_tool_summary_verifies() {
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
    fn p384_tool_delta_verifies() {
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
}

#[cfg(feature = "sign-spki-ed25519")]
mod ed25519 {
    use super::*;
    use common::wrap_pem;
    use ostrya::{Signer, Type, from_bytes};

    /// The key type of the fixture.
    const TYPE: &str = "ed25519";

    /// The length in bytes of an Ed25519 signature.
    const SIGNATURE_LEN: usize = 64;

    /// The SubjectPublicKeyInfo DER of an Ed25519 key before its 32 key bytes:
    /// the algorithm `id-Ed25519` with no parameters.
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    /// An Ed25519 public key that signed no fixture: the key of test 1 in
    /// RFC 8032.
    const OTHER_PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    /// Returns a verifier that trusts a key that signed no fixture.
    fn stranger_verifier() -> SpkiVerifier {
        SpkiVerifier::new(
            [[&SPKI_PREFIX[..], &OTHER_PUBLIC_KEY].concat()],
            Vec::<Vec<u8>>::new(),
        )
        .unwrap()
    }

    #[test]
    fn ed25519_fixture_keys_are_one_pair() {
        assert_fixture_keys_are_one_pair(TYPE);
    }

    #[test]
    fn ed25519_tool_verifies_port_signatures() {
        let spki = ostrya::base64::encode(&[&SPKI_PREFIX[..], &OTHER_PUBLIC_KEY].concat());
        assert_tool_verifies_port_signatures(TYPE, &wrap_pem("PUBLIC KEY", &spki));
    }

    #[test]
    fn ed25519_tool_commit_verifies() {
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
            assert_eq!(info.pubkey_algorithm.as_deref(), Some("ed25519"));
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
    fn ed25519_tool_summary_verifies() {
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
    fn ed25519_tool_delta_verifies() {
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
    /// key. Ed25519 is deterministic, so the signature and the whole
    /// `.commitmeta` file are the same bytes as the ones that the tool wrote.
    #[test]
    fn ed25519_port_commit_signature_is_the_tool_signature() {
        let tmp = TmpDir::new("spki-ed25519-commit");
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
    fn ed25519_port_summary_and_delta_signatures_are_the_tool_signatures() {
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

#[cfg(feature = "sign-spki-rsa")]
mod rsa {
    use super::*;
    use ostrya::{Signer, Type, from_bytes};

    /// The key type of the fixture.
    const TYPE: &str = "rsa";

    /// The length in bytes of a signature of the 2048-bit fixture key.
    const SIGNATURE_LEN: usize = 256;

    /// Returns the PEM text of an RSA public key that signed no fixture.
    ///
    /// The key is `rsa-2048.pub.pem` of the key fixtures in
    /// `tests/fixtures/spki/keys/`.
    fn stranger_pem() -> String {
        std::fs::read_to_string(fixture_root().join("../spki/keys/rsa-2048.pub.pem")).unwrap()
    }

    /// Returns a verifier that trusts an RSA key that signed no fixture.
    fn stranger_verifier() -> SpkiVerifier {
        SpkiVerifier::from_pem(stranger_pem()).unwrap()
    }

    #[test]
    fn rsa_fixture_keys_are_one_pair() {
        assert_fixture_keys_are_one_pair(TYPE);
    }

    #[test]
    fn rsa_tool_verifies_port_signatures() {
        assert_tool_verifies_port_signatures(TYPE, &stranger_pem());
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
