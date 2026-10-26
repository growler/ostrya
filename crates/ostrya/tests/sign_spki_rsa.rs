//! Integration tests for commit signing with the RSA key type of the spki
//! engine.
//!
//! The keys are the fixture files in `tests/fixtures/spki/keys/`, which
//! `tests/fixtures/spki/keys/generate.sh` writes with OpenSSL 3. No test makes
//! a key.

#![cfg(feature = "sign-spki-rsa")]

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree, Repo,
    RepoMode, SpkiSigner, SpkiVerifier, load_sign_keys_from, spki_secret_keys,
};
use ostrya_rt::block_on;

/// The lowercase hex SHA-256 of the SubjectPublicKeyInfo DER of
/// `rsa-2048.pub.pem`.
const FINGERPRINT_2048: &str = "e2d83e58fabfb0e5acba74cccf136b03d71794c9fd3921786461435680833875";

/// A P-256 public key in a PEM `PUBLIC KEY` block.
const P256_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8X83xylD3ibci0xjFKMR4bwUtTU/\n\
YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDnRAG1Ua8eR8SKbLQ==\n\
-----END PUBLIC KEY-----\n";

/// Returns the path of the key fixture file `name`.
fn key_path(name: &str) -> PathBuf {
    common::fixture_root().join("../spki/keys").join(name)
}

/// Returns the text of the key fixture file `name`.
fn key_text(name: &str) -> String {
    std::fs::read_to_string(key_path(name)).unwrap()
}

/// Returns the signer of the one `PRIVATE KEY` block of the fixture file
/// `name`.
fn signer(name: &str) -> SpkiSigner {
    let mut signers = spki_secret_keys(std::fs::read(key_path(name)).unwrap(), name).unwrap();
    assert_eq!(signers.len(), 1);
    signers.remove(0)
}

/// Creates an archive repository and commits a small tree on `test/main`.
/// Returns the repository and the commit.
async fn build_committed_repo(base: &Path) -> (Repo, Checksum) {
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostrya\n").unwrap();
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
        subject: Some("spki RSA sign fixture".to_owned()),
        timestamp: Some(1_700_000_000),
        ..CommitOptions::default()
    };
    let commit = txn.write_commit(opts, &root).await.unwrap();
    txn.set_ref("test/main", Some(&commit));
    txn.commit().await.unwrap();
    (repo, commit)
}

/// Returns a key store directory under `base` with the file `trusted.spki`
/// of the text `trusted`, and the file `revoked.spki` of the text `revoked`
/// if it is given.
fn store(base: &Path, name: &str, trusted: &str, revoked: Option<&str>) -> PathBuf {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("trusted.spki"), trusted).unwrap();
    if let Some(revoked) = revoked {
        std::fs::write(dir.join("revoked.spki"), revoked).unwrap();
    }
    dir
}

/// Returns the verifier of the key store at `dir`.
fn store_verifier(dir: &Path) -> SpkiVerifier {
    SpkiVerifier::from_sign_keys(load_sign_keys_from(&[dir], "spki").unwrap()).unwrap()
}

#[test]
fn rsa_keys_of_2048_and_8192_bits_sign_and_verify_a_commit() {
    let tmp = TmpDir::new("spki-rsa-sign");
    block_on(async {
        let (repo, commit) = build_committed_repo(tmp.path()).await;
        for (secret, public) in [
            ("rsa-2048.pem", "rsa-2048.pub.pem"),
            ("rsa-8192.pem", "rsa-8192.pub.pem"),
        ] {
            repo.delete_signatures(&commit, "ostree.sign.spki", |_, _| true)
                .await
                .unwrap();
            repo.sign_commit(&commit, &signer(secret)).await.unwrap();
            let verifier = SpkiVerifier::from_pem(key_text(public)).unwrap();
            let outcome = repo.verify_commit(&commit, &[&verifier]).await.unwrap();
            assert!(outcome.valid, "{secret}");
        }
    });
}

#[test]
fn a_key_store_with_an_rsa_key_verifies_and_its_revocation_removes_the_key() {
    let tmp = TmpDir::new("spki-rsa-store");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &signer("rsa-2048.pem"))
            .await
            .unwrap();
        let public = key_text("rsa-2048.pub.pem");

        let dir = store(base, "trusted", &public, None);
        let outcome = repo
            .verify_commit(&commit, &[&store_verifier(&dir)])
            .await
            .unwrap();
        assert!(outcome.valid);
        let info = &outcome.signatures[0];
        assert_eq!(info.pubkey_algorithm.as_deref(), Some("rsa"));
        assert_eq!(info.fingerprint.as_deref(), Some(FINGERPRINT_2048));

        let dir = store(base, "revoked", &public, Some(&public));
        let verifier = store_verifier(&dir);
        assert!(verifier.is_empty());
        assert!(
            !repo
                .verify_commit(&commit, &[&verifier])
                .await
                .unwrap()
                .valid
        );
    });
}

#[cfg(feature = "sign-spki-p256")]
#[test]
fn a_key_store_of_a_p256_key_and_an_rsa_key_verifies_a_commit_of_each() {
    let tmp = TmpDir::new("spki-rsa-mixed");
    let base = tmp.path();
    // The P-256 key of `P256_PUBLIC_PEM`, base64 of the PKCS#8 DER.
    let p256 = SpkiSigner::from_base64(concat!(
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
        "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
        "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
    ))
    .unwrap();
    let text = format!("{P256_PUBLIC_PEM}{}", key_text("rsa-2048.pub.pem"));
    let dir = store(base, "mixed", &text, None);
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        for (signer, algorithm) in [(p256, "p256"), (signer("rsa-2048.pem"), "rsa")] {
            repo.delete_signatures(&commit, "ostree.sign.spki", |_, _| true)
                .await
                .unwrap();
            repo.sign_commit(&commit, &signer).await.unwrap();
            let outcome = repo
                .verify_commit(&commit, &[&store_verifier(&dir)])
                .await
                .unwrap();
            assert!(outcome.valid, "{algorithm}");
            assert_eq!(
                outcome.signatures[0].pubkey_algorithm.as_deref(),
                Some(algorithm)
            );
        }
    });
}

#[cfg(not(feature = "sign-spki-p256"))]
#[test]
fn a_build_with_rsa_alone_refuses_a_p256_key_and_verifies_an_rsa_key() {
    let tmp = TmpDir::new("spki-rsa-alone");
    let base = tmp.path();
    let dir = store(base, "p256", P256_PUBLIC_PEM, None);
    let file = dir.join("trusted.spki");
    match load_sign_keys_from(&[dir.as_path()], "spki").unwrap_err() {
        ostrya::Error::Signature(m) => assert_eq!(
            m,
            format!(
                "the key file '{}', line 1: this build has no code for the curve P-256; build \
                 with the sign-spki-p256 feature",
                file.display()
            )
        ),
        other => panic!("not a signature error: {other}"),
    }

    // A P-256 key in `revoked.spki` refuses the store, so a revocation that
    // the build cannot read fails closed.
    let public = key_text("rsa-2048.pub.pem");
    let dir = store(base, "revoked-p256", &public, Some(P256_PUBLIC_PEM));
    let file = dir.join("revoked.spki");
    match load_sign_keys_from(&[dir.as_path()], "spki").unwrap_err() {
        ostrya::Error::Signature(m) => assert_eq!(
            m,
            format!(
                "the key file '{}', line 1: this build has no code for the curve P-256; build \
                 with the sign-spki-p256 feature",
                file.display()
            )
        ),
        other => panic!("not a signature error: {other}"),
    }

    let dir = store(base, "rsa", &public, None);
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &signer("rsa-2048.pem"))
            .await
            .unwrap();
        assert!(
            repo.verify_commit(&commit, &[&store_verifier(&dir)])
                .await
                .unwrap()
                .valid
        );
    });
}
