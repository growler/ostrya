//! Integration tests for commit signing with the spki engine (ECDSA and SPKI).
//!
//! These tests use [`SpkiSigner`], [`SpkiVerifier`], and the key store of the
//! sign API.
//!
//! The tests in `sign_spki_fixtures.rs` compare the engine with the `ostree`
//! command in both directions for each key type. The tests in which the
//! command verifies the signatures of the engine need a build of the command
//! with the features `openssl` and `sign-spki`.
//!
//! [`spki_openssl_interop`] runs the `openssl` command as a black box. It
//! checks the standard formats in both directions, over the same P-256 key and
//! SHA-256 digest:
//!
//! - `openssl` verifies a signature that ostrya wrote.
//! - ostrya verifies a signature that `openssl` wrote.
//!
//! The embedded keys are a fixed P-256 pair. The command `openssl genpkey
//! -algorithm EC -pkeyopt ec_paramgen_curve:P-256` made them.

#![cfg(feature = "sign-spki")]

mod common;

use std::os::fd::AsFd;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use common::{TmpDir, openssl_available, wrap_pem};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Ed25519Signer,
    MutableTree, Repo, RepoMode, Signer, SpkiSigner, SpkiVerifier, Verifier, base64,
    load_sign_keys_from,
};
use ostrya_rt::block_on;

/// The SubjectPublicKeyInfo DER of the embedded key in base64.
const PUBLIC_SPKI_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8X83xylD3ibci0xjFKMR4bwUtTU/\
YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDnRAG1Ua8eR8SKbLQ==";
/// The PEM `PUBLIC KEY` form of the same key.
const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8X83xylD3ibci0xjFKMR4bwUtTU/\n\
YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDnRAG1Ua8eR8SKbLQ==\n\
-----END PUBLIC KEY-----\n";
/// The matching secret key as base64 of the PKCS#8 `PrivateKeyInfo` DER.
const SECRET_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG\
v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3\
csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst";
/// The matching secret key as base64 of the SEC1 `ECPrivateKey` DER.
const SECRET_SEC1_B64: &str = "MHcCAQEEINi+9PBLJ58xxEdEmGrDDSFHBr+t0GqQv95FbKD3q8yhoAoGCCqGSM49AwEHoUQD\
QgAE8X83xylD3ibci0xjFKMR4bwUtTU/YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDn\
RAG1Ua8eR8SKbLQ==";
/// The matching secret key as the raw 32-byte P-256 scalar (hex). It is not
/// a secret key form of the engine.
const SECRET_SCALAR_HEX: &str = "D8BEF4F04B279F31C44744986AC30D214706BFADD06A90BFDE456CA0F7ABCCA1";

/// Decodes a hex string into bytes.
fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// The raw SubjectPublicKeyInfo DER of the embedded key.
fn public_spki_der() -> Vec<u8> {
    base64::decode(PUBLIC_SPKI_B64).unwrap()
}

/// Builds a small source tree under `base/src`.
fn build_source(base: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostrya\n").unwrap();
    std::fs::set_permissions(
        src.join("hello.txt"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Creates an archive repository and commits `base/src` on `test/main`. The
/// ingest uses canonical permissions and owner 0:0. Returns the repository and
/// the commit.
async fn build_committed_repo(base: &Path) -> (Repo, Checksum) {
    build_source(base);
    let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    );
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new("src"),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let opts = CommitOptions {
        subject: Some("spki sign fixture".to_owned()),
        timestamp: Some(1_700_000_000),
        ..CommitOptions::default()
    };
    let commit = txn.write_commit(opts, &root).await.unwrap();
    txn.set_ref("test/main", Some(&commit));
    txn.commit().await.unwrap();
    (repo, commit)
}

/// Returns the canonical commit bytes (the signed payload) of `commit` under
/// `base`.
fn commit_bytes(base: &Path, commit: &Checksum) -> Vec<u8> {
    let hex = commit.to_hex();
    let (a, b) = hex.split_at(2);
    std::fs::read(
        base.join("repo/objects")
            .join(a)
            .join(format!("{b}.commit")),
    )
    .unwrap()
}

#[test]
fn spki_round_trip_within_the_port() {
    let tmp = TmpDir::new("spki-roundtrip");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &SpkiSigner::from_base64(SECRET_SEC1_B64).unwrap())
            .await
            .unwrap();

        // The signature verifies with the key in SubjectPublicKeyInfo DER
        // form and in PEM form.
        let by_der = SpkiVerifier::new([public_spki_der()], Vec::<Vec<u8>>::new()).unwrap();
        assert!(
            repo.verify_commit(&commit, &[Arc::new(by_der)])
                .await
                .unwrap()
                .valid
        );
        let by_pem = SpkiVerifier::from_pem(PUBLIC_PEM).unwrap();
        assert!(
            repo.verify_commit(&commit, &[Arc::new(by_pem)])
                .await
                .unwrap()
                .valid
        );

        // The signature does not verify with an unrelated well-formed key.
        let stranger = spki_stranger_verifier();
        let outcome = repo
            .verify_commit(&commit, &[Arc::new(stranger)])
            .await
            .unwrap();
        assert!(!outcome.valid, "an untrusted key must not verify");
        assert!(outcome.signatures[0].key_missing);
    });
}

/// A different well-formed P-256 public key (SubjectPublicKeyInfo DER) in
/// base64.
const OTHER_SPKI_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECmz6W9QPu0HuggzW4vGvsnvQIl4J\
yl/b9kVl8fm/qw/xJSQfCEzhnGMQzmyj2quUo96zvuxlCllcTkzsOhwEAg==";

/// Returns a verifier that trusts a key unrelated to the embedded pair.
fn spki_stranger_verifier() -> SpkiVerifier {
    SpkiVerifier::new(
        [base64::decode(OTHER_SPKI_B64).unwrap()],
        Vec::<Vec<u8>>::new(),
    )
    .unwrap()
}

/// Returns `b64` with `line_end` after each 64 characters, as in a PEM body.
fn with_line_breaks(b64: &str, line_end: &str) -> String {
    b64.as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(line_end)
}

/// Returns the SEC1 DER of the embedded key with no `parameters` field.
///
/// The function removes the `[0]` element that names the curve from
/// [`SECRET_SEC1_B64`] and sets the outer length again.
fn sec1_without_parameters() -> Vec<u8> {
    let mut der = base64::decode(SECRET_SEC1_B64).unwrap();
    assert_eq!(der[..2], [0x30, 0x77]);
    assert_eq!(der[39..51], from_hex("A00A06082A8648CE3D030107"));
    der.drain(39..51);
    der[1] = 0x6b;
    der
}

/// Returns the SEC1 DER of the embedded key with a `parameters` field that
/// names secp521r1.
///
/// The function replaces the `[0]` element of [`SECRET_SEC1_B64`] and sets the
/// outer length again.
fn sec1_of_another_curve() -> Vec<u8> {
    let mut der = base64::decode(SECRET_SEC1_B64).unwrap();
    assert_eq!(der[39..51], from_hex("A00A06082A8648CE3D030107"));
    der.splice(39..51, from_hex("A00706052B81040023"));
    der[1] = 0x74;
    der
}

#[test]
fn spki_secret_key_encodings_agree() {
    // The same key decodes from base64 of PKCS#8 DER and of SEC1 DER, also
    // with the LF or CRLF line breaks of a PEM body. Each form gives the
    // embedded public key.
    let want = public_spki_der();
    for secret in [SECRET_PKCS8_B64, SECRET_SEC1_B64] {
        for text in [
            secret.to_owned(),
            with_line_breaks(secret, "\n"),
            format!("{}\r\n", with_line_breaks(secret, "\r\n")),
        ] {
            let signer = SpkiSigner::from_base64(&text).unwrap();
            assert_eq!(signer.public_key_der(), want, "secret form {text:?}");
        }
    }
    // The PKCS#8 PEM constructor gives the same public key.
    let pkcs8_pem = wrap_pem("PRIVATE KEY", SECRET_PKCS8_B64);
    assert_eq!(
        SpkiSigner::from_pkcs8_pem(&pkcs8_pem)
            .unwrap()
            .public_key_der(),
        want
    );
    // A malformed secret returns a signature error. The constructor does not
    // panic.
    assert!(SpkiSigner::from_base64("bm90LWEta2V5").is_err());
}

/// Returns the message of a signature error of the spki secret key reader.
fn secret_refusal(b64: &str) -> String {
    match SpkiSigner::from_base64(b64) {
        Err(ostrya::sign::Error::Signature(m)) => m,
        Err(other) => panic!("not a signature error: {other}"),
        Ok(_) => panic!("the secret key {b64:?} has to be refused"),
    }
}

#[test]
fn spki_secret_key_refused_forms() {
    // The raw 32-byte scalar of the embedded key.
    let scalar_b64 = base64::encode(&from_hex(SECRET_SCALAR_HEX));
    assert_eq!(
        secret_refusal(&scalar_b64),
        "spki secret key: expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER"
    );
    // A SEC1 key with no `parameters` field.
    assert_eq!(
        secret_refusal(&base64::encode(&sec1_without_parameters())),
        "spki secret key: the SEC1 key does not name its curve"
    );
    // A SEC1 key whose `parameters` field names secp521r1.
    assert_eq!(
        secret_refusal(&base64::encode(&sec1_of_another_curve())),
        "spki secret key: the curve P-521 is not supported"
    );
    // The base64 of the full PEM text.
    let pem = wrap_pem("PRIVATE KEY", SECRET_PKCS8_B64);
    assert_eq!(
        secret_refusal(&base64::encode(pem.as_bytes())),
        "spki secret key: expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER"
    );
    // A character outside the base64 alphabet, also at the end.
    assert!(SpkiSigner::from_base64(&format!("{SECRET_PKCS8_B64}!")).is_err());
}

/// Returns the fixed-width `r || s` form of a DER ECDSA signature over P-256.
fn fixed_width(der: &[u8]) -> Vec<u8> {
    // SEQUENCE { INTEGER r, INTEGER s }, each with a short-form length.
    assert_eq!(der[0], 0x30);
    let mut out = Vec::with_capacity(64);
    let mut at = 2;
    for _ in 0..2 {
        assert_eq!(der[at], 0x02);
        let len = usize::from(der[at + 1]);
        let int = &der[at + 2..at + 2 + len];
        let int = &int[int.len().saturating_sub(32)..];
        out.extend(std::iter::repeat_n(0u8, 32 - int.len()));
        out.extend_from_slice(int);
        at += 2 + len;
    }
    out
}

/// A commit whose only spki signature is the fixed-width `r || s` form of a
/// valid signature does not verify. The DER form of the same signature
/// verifies.
#[test]
fn spki_fixed_width_signature_does_not_verify() {
    let tmp = TmpDir::new("spki-fixed-width");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        let signer = SpkiSigner::from_base64(SECRET_PKCS8_B64).unwrap();
        let der = signer.sign(&commit_bytes(base, &commit)).await.unwrap();
        let verifier: Arc<dyn Verifier> =
            Arc::new(SpkiVerifier::new([public_spki_der()], Vec::<Vec<u8>>::new()).unwrap());

        for (blob, valid) in [(fixed_width(&der), false), (der, true)] {
            let mut dict = ostrya::Value::Array(Vec::new());
            ostrya::sign::append_signature(&mut dict, signer.metadata_key(), blob).unwrap();
            repo.write_commit_detached_metadata(&commit, Some(&dict))
                .await
                .unwrap();
            let outcome = repo
                .verify_commit(&commit, std::slice::from_ref(&verifier))
                .await
                .unwrap();
            assert_eq!(outcome.valid, valid);
            assert_eq!(outcome.signatures.len(), 1);
        }
    });
}

/// A commit whose only spki signature is a blob that the trusted key does not
/// verify does not verify. A signature of another key type beside a valid
/// signature leaves the commit valid.
#[test]
fn spki_blobs_that_no_trusted_key_verifies() {
    let tmp = TmpDir::new("spki-strict");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        let data = commit_bytes(base, &commit);
        let signer = SpkiSigner::from_base64(SECRET_PKCS8_B64).unwrap();
        let der = signer.sign(&data).await.unwrap();
        let verifier: Arc<dyn Verifier> =
            Arc::new(SpkiVerifier::new([public_spki_der()], Vec::<Vec<u8>>::new()).unwrap());
        // The ed25519 key of test 1 in RFC 8032: the seed, then the public key.
        let ed25519 = Ed25519Signer::from_secret_key(
            &base64::decode(concat!(
                "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2DXWpgBgrEKt9VL/tPJZAc6",
                "DuFy89qmIyWvAhpo9wdRGg==",
            ))
            .unwrap(),
        )
        .unwrap()
        .sign(&data)
        .await
        .unwrap();
        let mut trailing = der.clone();
        trailing.push(0);
        // The second INTEGER claims one byte more than the SEQUENCE holds.
        let mut malformed = der.clone();
        let at = 4 + usize::from(malformed[3]);
        malformed[at + 1] += 1;
        let random: Vec<u8> = (0u8..64)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect();

        let cases = [
            (vec![random], false),
            (vec![vec![0x5a]], false),
            (vec![trailing], false),
            (vec![malformed], false),
            (vec![ed25519.clone()], false),
            (vec![ed25519, der], true),
        ];
        for (blobs, valid) in cases {
            let mut dict = ostrya::Value::Array(Vec::new());
            for blob in &blobs {
                ostrya::sign::append_signature(&mut dict, signer.metadata_key(), blob.clone())
                    .unwrap();
            }
            repo.write_commit_detached_metadata(&commit, Some(&dict))
                .await
                .unwrap();
            let outcome = repo
                .verify_commit(&commit, std::slice::from_ref(&verifier))
                .await
                .unwrap();
            assert_eq!(outcome.valid, valid, "{blobs:02x?}");
            assert_eq!(outcome.signatures.len(), blobs.len());
            assert!(!outcome.signatures[0].valid && outcome.signatures[0].key_missing);
        }
    });
}

#[test]
fn spki_trusted_revoked_directory_convention() {
    let tmp = TmpDir::new("spki-keydir");
    let base = tmp.path();
    let keys_dir = base.join("keys");
    let trusted_d = keys_dir.join("trusted.spki.d");
    std::fs::create_dir_all(&trusted_d).unwrap();
    std::fs::write(trusted_d.join("mykey"), PUBLIC_PEM).unwrap();

    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &SpkiSigner::from_base64(SECRET_SEC1_B64).unwrap())
            .await
            .unwrap();

        // The loader resolves the trusted key, and the signature verifies.
        let keys = load_sign_keys_from(&[keys_dir.as_path()], "spki").unwrap();
        assert_eq!(keys.trusted.len(), 1);
        assert!(keys.revoked.is_empty());
        let verifier = SpkiVerifier::from_sign_keys(keys).unwrap();
        assert!(
            repo.verify_commit(&commit, &[Arc::new(verifier)])
                .await
                .unwrap()
                .valid,
            "loaded trusted key should verify"
        );

        // If the key is revoked, the effective trusted set does not hold it.
        let revoked_d = keys_dir.join("revoked.spki.d");
        std::fs::create_dir_all(&revoked_d).unwrap();
        std::fs::write(revoked_d.join("bad"), PUBLIC_PEM).unwrap();
        let keys = load_sign_keys_from(&[keys_dir.as_path()], "spki").unwrap();
        assert_eq!(keys.revoked.len(), 1);
        let verifier = SpkiVerifier::from_sign_keys(keys).unwrap();
        assert!(
            !repo
                .verify_commit(&commit, &[Arc::new(verifier)])
                .await
                .unwrap()
                .valid,
            "a revoked key must not verify"
        );
    });
}

/// Returns whether the keys of the store at `keys_dir` verify the signed
/// `commit` of `repo`.
async fn store_verifies(repo: &Repo, commit: &Checksum, keys_dir: &Path) -> bool {
    let keys = load_sign_keys_from(&[keys_dir], "spki").unwrap();
    let verifier = SpkiVerifier::from_sign_keys(keys).unwrap();
    repo.verify_commit(commit, &[Arc::new(verifier)])
        .await
        .unwrap()
        .valid
}

/// Returns the message of the refusal of the store at `keys_dir`.
fn store_refusal(keys_dir: &Path) -> String {
    match load_sign_keys_from(&[keys_dir], "spki").unwrap_err() {
        ostrya::Error::Signature(m) => m,
        other => panic!("not a signature error: {other}"),
    }
}

/// The files of the key store hold PEM `PUBLIC KEY` blocks. A file of base64
/// lines, or a file with a block of another label, refuses the load, also in
/// a `.d` directory and for the revoked set. The refusal names the file. An
/// empty file adds no keys.
#[test]
fn spki_key_store_files_hold_pem_blocks() {
    let tmp = TmpDir::new("spki-store-pem");
    let base = tmp.path();
    let certificate = wrap_pem("CERTIFICATE", PUBLIC_SPKI_B64);
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &SpkiSigner::from_base64(SECRET_SEC1_B64).unwrap())
            .await
            .unwrap();
        let store = |name: &str| {
            let dir = base.join(name);
            std::fs::create_dir_all(dir.join("trusted.spki.d")).unwrap();
            std::fs::create_dir_all(dir.join("revoked.spki.d")).unwrap();
            dir
        };

        // A PEM `trusted.spki` verifies.
        let dir = store("pem");
        std::fs::write(dir.join("trusted.spki"), PUBLIC_PEM).unwrap();
        assert!(store_verifies(&repo, &commit, &dir).await);

        // A `trusted.spki` of base64 lines is refused.
        let dir = store("lines");
        std::fs::write(dir.join("trusted.spki"), format!("{PUBLIC_SPKI_B64}\n")).unwrap();
        let file = dir.join("trusted.spki");
        assert_eq!(
            store_refusal(&dir),
            format!(
                "the key file '{}' holds no PEM PUBLIC KEY block",
                file.display()
            )
        );

        // An empty `trusted.spki` adds no keys. A PEM file with CRLF line
        // ends in `trusted.spki.d` adds its key.
        let dir = store("empty");
        std::fs::write(dir.join("trusted.spki"), "").unwrap();
        std::fs::write(
            dir.join("trusted.spki.d/crlf"),
            PUBLIC_PEM.replace('\n', "\r\n"),
        )
        .unwrap();
        assert!(store_verifies(&repo, &commit, &dir).await);

        // A PEM `revoked.spki` revokes the key.
        let dir = store("revoked");
        std::fs::write(dir.join("trusted.spki"), PUBLIC_PEM).unwrap();
        std::fs::write(dir.join("revoked.spki"), PUBLIC_PEM).unwrap();
        assert!(!store_verifies(&repo, &commit, &dir).await);

        // A `revoked.spki` of base64 lines refuses the load.
        let dir = store("revoked-lines");
        std::fs::write(dir.join("trusted.spki"), PUBLIC_PEM).unwrap();
        std::fs::write(dir.join("revoked.spki"), format!("{PUBLIC_SPKI_B64}\n")).unwrap();
        assert!(store_refusal(&dir).ends_with("holds no PEM PUBLIC KEY block"));

        // A PEM file in `revoked.spki.d` revokes the key.
        let dir = store("revoked-d");
        std::fs::write(dir.join("trusted.spki"), PUBLIC_PEM).unwrap();
        std::fs::write(dir.join("revoked.spki.d/key"), PUBLIC_PEM).unwrap();
        assert!(!store_verifies(&repo, &commit, &dir).await);

        // A CERTIFICATE block in `revoked.spki.d` refuses the load.
        let dir = store("revoked-certificate");
        std::fs::write(dir.join("trusted.spki"), PUBLIC_PEM).unwrap();
        std::fs::write(dir.join("revoked.spki.d/cert"), &certificate).unwrap();
        let file = dir.join("revoked.spki.d/cert");
        assert_eq!(
            store_refusal(&dir),
            format!(
                "the key file '{}', line 1: unexpected label \"CERTIFICATE\"",
                file.display()
            )
        );

        // A file of base64 lines in `trusted.spki.d` refuses the load by its
        // name.
        let dir = store("trusted-d-lines");
        std::fs::write(dir.join("trusted.spki"), PUBLIC_PEM).unwrap();
        std::fs::write(
            dir.join("trusted.spki.d/lines"),
            format!("{PUBLIC_SPKI_B64}\n"),
        )
        .unwrap();
        let file = dir.join("trusted.spki.d/lines");
        assert_eq!(
            store_refusal(&dir),
            format!(
                "the key file '{}' holds no PEM PUBLIC KEY block",
                file.display()
            )
        );

        // A CERTIFICATE block in `trusted.spki.d` refuses the load by its
        // name.
        let dir = store("trusted-d-certificate");
        std::fs::write(dir.join("trusted.spki.d/cert"), &certificate).unwrap();
        let file = dir.join("trusted.spki.d/cert");
        assert_eq!(
            store_refusal(&dir),
            format!(
                "the key file '{}', line 1: unexpected label \"CERTIFICATE\"",
                file.display()
            )
        );

        // A CERTIFICATE block beside a valid block in `trusted.spki` refuses
        // the load.
        let dir = store("trusted-certificate");
        std::fs::write(
            dir.join("trusted.spki"),
            format!("{PUBLIC_PEM}{certificate}"),
        )
        .unwrap();
        assert!(store_refusal(&dir).ends_with("line 5: unexpected label \"CERTIFICATE\""));
    });
}

#[test]
fn spki_openssl_interop() {
    if !openssl_available() {
        eprintln!("skipping: openssl tool not available");
        return;
    }
    let tmp = TmpDir::new("spki-openssl");
    let base = tmp.path();
    let key_pem = base.join("key.pem");
    let pub_pem = base.join("pub.pem");

    // The `openssl` command makes a new P-256 key pair.
    assert!(
        Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out"
            ])
            .arg(&key_pem)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .arg("pkey")
            .arg("-in")
            .arg(&key_pem)
            .args(["-pubout", "-out"])
            .arg(&pub_pem)
            .status()
            .unwrap()
            .success()
    );

    block_on(async {
        let (_repo, commit) = build_committed_repo(base).await;
        let payload = commit_bytes(base, &commit);
        let payload_bin = base.join("commit.bin");
        std::fs::write(&payload_bin, &payload).unwrap();

        let key_pem_text = std::fs::read_to_string(&key_pem).unwrap();
        let pub_pem_text = std::fs::read_to_string(&pub_pem).unwrap();

        // Direction 1: ostrya verifies a signature that openssl wrote.
        let os_sig = base.join("openssl.sig");
        assert!(
            Command::new("openssl")
                .args(["dgst", "-sha256", "-sign"])
                .arg(&key_pem)
                .arg("-out")
                .arg(&os_sig)
                .arg(&payload_bin)
                .status()
                .unwrap()
                .success()
        );
        let sig_bytes = std::fs::read(&os_sig).unwrap();
        let verifier = SpkiVerifier::from_pem(&pub_pem_text).unwrap();
        let outcome = verifier.verify(&payload, &[sig_bytes]).unwrap();
        assert!(
            outcome.valid,
            "port rejected an openssl-written spki signature"
        );

        // Direction 2: openssl verifies a signature that ostrya wrote.
        let signer = SpkiSigner::from_pkcs8_pem(&key_pem_text).unwrap();
        let port_sig_bytes = signer.sign(&payload).await.unwrap();
        let port_sig = base.join("port.sig");
        std::fs::write(&port_sig, &port_sig_bytes).unwrap();
        let verified = Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(&pub_pem)
            .arg("-signature")
            .arg(&port_sig)
            .arg(&payload_bin)
            .output()
            .unwrap();
        assert!(
            verified.status.success(),
            "openssl rejected the port's spki signature: {}",
            String::from_utf8_lossy(&verified.stderr)
        );
    });
}
