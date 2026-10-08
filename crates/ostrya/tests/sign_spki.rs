//! Integration tests for commit signing with the spki engine (ECDSA and SPKI).
//!
//! These tests use [`SpkiSigner`], [`SpkiVerifier`], and the key store of the
//! sign API.
//!
//! The observed build of the `ostree` command has no spki engine. The engine
//! needs OpenSSL, and this build does not include OpenSSL, so the
//! cross-verification with the `ostree` command cannot run here. If the
//! command reports the type
//! as not implemented, [`spki_tool_cross_verify_pending`] skips. If a later
//! build supports spki, the test runs the full cross-check.
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

use common::{TmpDir, openssl_available, ostree_available};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree, Repo,
    RepoMode, Signer, SpkiSigner, SpkiVerifier, Verifier, base64, load_sign_keys_from,
};
use ostrya_rt::block_on;

/// The SubjectPublicKeyInfo DER of the embedded key in base64 (a `trusted.spki`
/// line).
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
/// The matching secret key as the raw 32-byte P-256 scalar (hex).
const SECRET_SCALAR_HEX: &str = "D8BEF4F04B279F31C44744986AC30D214706BFADD06A90BFDE456CA0F7ABCCA1";

/// Wraps `b64` into a PEM block of `kind`, with one 64-character line for each
/// chunk. `pem-rfc7468` expects this RFC 7468 line width.
fn wrap_pem(kind: &str, b64: &str) -> String {
    let mut body = String::new();
    for chunk in b64.as_bytes().chunks(64) {
        body.push_str(std::str::from_utf8(chunk).unwrap());
        body.push('\n');
    }
    format!("-----BEGIN {kind}-----\n{body}-----END {kind}-----\n")
}

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
        assert!(repo.verify_commit(&commit, &[&by_der]).await.unwrap().valid);
        let by_pem = SpkiVerifier::from_pem(PUBLIC_PEM).unwrap();
        assert!(repo.verify_commit(&commit, &[&by_pem]).await.unwrap().valid);

        // The signature does not verify with an unrelated well-formed key.
        let stranger = spki_stranger_verifier();
        let outcome = repo.verify_commit(&commit, &[&stranger]).await.unwrap();
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

#[test]
fn spki_secret_key_encodings_agree() {
    // The same key decodes from base64 of PKCS#8 DER, of SEC1 DER, and of the
    // raw 32-byte scalar. Each form gives the embedded public key.
    let want = public_spki_der();
    let scalar_b64 = base64::encode(&from_hex(SECRET_SCALAR_HEX));
    for secret in [SECRET_PKCS8_B64, SECRET_SEC1_B64, &scalar_b64] {
        let signer = SpkiSigner::from_base64(secret).unwrap();
        assert_eq!(signer.public_key_der(), want, "secret form {secret}");
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

#[test]
fn spki_trusted_revoked_directory_convention() {
    let tmp = TmpDir::new("spki-keydir");
    let base = tmp.path();
    let keys_dir = base.join("keys");
    let trusted_d = keys_dir.join("trusted.spki.d");
    std::fs::create_dir_all(&trusted_d).unwrap();
    std::fs::write(trusted_d.join("mykey"), format!("{PUBLIC_SPKI_B64}\n")).unwrap();

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
            repo.verify_commit(&commit, &[&verifier])
                .await
                .unwrap()
                .valid,
            "loaded trusted key should verify"
        );

        // If the key is revoked, the effective trusted set does not hold it.
        let revoked_d = keys_dir.join("revoked.spki.d");
        std::fs::create_dir_all(&revoked_d).unwrap();
        std::fs::write(revoked_d.join("bad"), format!("{PUBLIC_SPKI_B64}\n")).unwrap();
        let keys = load_sign_keys_from(&[keys_dir.as_path()], "spki").unwrap();
        assert_eq!(keys.revoked.len(), 1);
        let verifier = SpkiVerifier::from_sign_keys(keys).unwrap();
        assert!(
            !repo
                .verify_commit(&commit, &[&verifier])
                .await
                .unwrap()
                .valid,
            "a revoked key must not verify"
        );
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
        let outcome = verifier.verify(&payload, &[sig_bytes]).await.unwrap();
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

#[test]
fn spki_tool_cross_verify_pending() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("spki-tool");
    let base = tmp.path();
    let repo_arg = format!("--repo={}", base.join("repo").display());
    let commit = block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &SpkiSigner::from_base64(SECRET_SEC1_B64).unwrap())
            .await
            .unwrap();
        commit
    });

    let out = Command::new("ostree")
        .args([
            &repo_arg,
            "sign",
            "--verify",
            "--sign-type=spki",
            &commit.to_hex(),
            PUBLIC_SPKI_B64,
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("not implemented") || stderr.contains("not supported") {
        eprintln!("skipping spki tool cross-verify: this ostree lacks spki ({stderr})");
        return;
    }
    // An `ostree` command with spki must accept the signature of ostrya.
    assert!(
        out.status.success(),
        "spki-capable tool rejected the port's signature: {stderr}"
    );
}
