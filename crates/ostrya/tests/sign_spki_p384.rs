//! Integration tests for commit signing with the P-384 key type of the spki
//! engine.
//!
//! The key is the P-384 key of RFC 6979, appendix A.2.6. No test makes a key.

#![cfg(feature = "sign-spki")]

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree, Repo,
    RepoMode, SpkiSigner, SpkiVerifier, load_sign_keys_from,
};
use ostrya_rt::block_on;

/// The secret key, base64 of the PKCS#8 DER.
const SECRET_PKCS8_B64: &str = concat!(
    "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBrnT2tLhuMHAWxmHW2ZZ9N4jw7Znvy",
    "l7qapHdAeHE32JbVck5McKgl+HLJ6mDS7fWhZANiAATsOk5BW04ZpFaGGAKfQn+l2pqLxK6S4C4G",
    "quUoazAMZN748OqQVYZgZKJUUVSAvBOAFdm3LX1XJE6o75rAxiGJZwilk2f537n1TKhLPxydsSiL",
    "Ixw64NT+c0T9JTMmRyA=",
);
/// The secret key, base64 of the SEC1 DER with the curve in its `parameters`
/// field.
const SECRET_SEC1_B64: &str = concat!(
    "MIGkAgEBBDBrnT2tLhuMHAWxmHW2ZZ9N4jw7Znvyl7qapHdAeHE32JbVck5McKgl+HLJ6mDS7fWg",
    "BwYFK4EEACKhZANiAATsOk5BW04ZpFaGGAKfQn+l2pqLxK6S4C4GquUoazAMZN748OqQVYZgZKJU",
    "UVSAvBOAFdm3LX1XJE6o75rAxiGJZwilk2f537n1TKhLPxydsSiLIxw64NT+c0T9JTMmRyA=",
);
/// The public key in a PEM `PUBLIC KEY` block, with an uncompressed point.
const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7DpOQVtOGaRWhhgCn0J/pdqai8SukuAu\n\
BqrlKGswDGTe+PDqkFWGYGSiVFFUgLwTgBXZty19VyROqO+awMYhiWcIpZNn+d+5\n\
9UyoSz8cnbEoiyMcOuDU/nNE/SUzJkcg\n\
-----END PUBLIC KEY-----\n";
/// The public key in a PEM `PUBLIC KEY` block, with a compressed point.
const PUBLIC_COMPRESSED_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MEYwEAYHKoZIzj0CAQYFK4EEACIDMgAC7DpOQVtOGaRWhhgCn0J/pdqai8SukuAu\n\
BqrlKGswDGTe+PDqkFWGYGSiVFFUgLwT\n\
-----END PUBLIC KEY-----\n";
/// The lowercase hex SHA-256 of the SubjectPublicKeyInfo DER of the key, with
/// an uncompressed point.
const FINGERPRINT: &str = "2f95601fa82060b909bfc6b979dbd303d34d34e0afb27ea496beac362f242a4b";

/// Returns the path of the key fixture file `name`.
fn key_path(name: &str) -> PathBuf {
    common::fixture_root().join("../spki/keys").join(name)
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
        subject: Some("spki P-384 sign fixture".to_owned()),
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
fn p384_keys_in_pkcs8_and_sec1_sign_and_verify_a_commit() {
    let tmp = TmpDir::new("spki-p384-sign");
    block_on(async {
        let (repo, commit) = build_committed_repo(tmp.path()).await;
        for secret in [SECRET_PKCS8_B64, SECRET_SEC1_B64] {
            repo.delete_signatures(&commit, "ostree.sign.spki", |_, _| true)
                .await
                .unwrap();
            let signer = SpkiSigner::from_base64(secret).unwrap();
            repo.sign_commit(&commit, &signer).await.unwrap();
            for public in [PUBLIC_PEM, PUBLIC_COMPRESSED_PEM] {
                let verifier = SpkiVerifier::from_pem(public).unwrap();
                let outcome = repo
                    .verify_commit(&commit, &[Arc::new(verifier)])
                    .await
                    .unwrap();
                assert!(outcome.valid, "{secret}");
            }
        }
    });
}

#[test]
fn a_key_store_with_a_p384_key_verifies_and_its_revocation_removes_the_key() {
    let tmp = TmpDir::new("spki-p384-store");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        let signer = SpkiSigner::from_base64(SECRET_PKCS8_B64).unwrap();
        repo.sign_commit(&commit, &signer).await.unwrap();

        let dir = store(base, "trusted", PUBLIC_COMPRESSED_PEM, None);
        let outcome = repo
            .verify_commit(&commit, &[Arc::new(store_verifier(&dir))])
            .await
            .unwrap();
        assert!(outcome.valid);
        let info = &outcome.signatures[0];
        assert_eq!(info.pubkey_algorithm.as_deref(), Some("p384"));
        assert_eq!(info.fingerprint.as_deref(), Some(FINGERPRINT));

        // The revoked key is the trusted key with a compressed point.
        let dir = store(base, "revoked", PUBLIC_PEM, Some(PUBLIC_COMPRESSED_PEM));
        let verifier = store_verifier(&dir);
        assert!(verifier.is_empty());
        assert!(
            !repo
                .verify_commit(&commit, &[Arc::new(verifier)])
                .await
                .unwrap()
                .valid
        );
    });
}

#[test]
fn a_key_store_of_p256_p384_and_rsa_keys_verifies_a_commit_of_each() {
    let tmp = TmpDir::new("spki-p384-mixed");
    let base = tmp.path();
    // A P-256 key, base64 of the PKCS#8 DER.
    let p256 = SpkiSigner::from_base64(concat!(
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
        "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
        "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
    ))
    .unwrap();
    let p256_pem = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8X83xylD3ibci0xjFKMR4bwUtTU/\n\
YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDnRAG1Ua8eR8SKbLQ==\n\
-----END PUBLIC KEY-----\n";
    let rsa_pem = std::fs::read(key_path("rsa-2048.pem")).unwrap();
    let rsa = ostrya::spki_secret_keys(rsa_pem, "rsa-2048.pem")
        .unwrap()
        .remove(0);
    let rsa_public = std::fs::read_to_string(key_path("rsa-2048.pub.pem")).unwrap();
    let text = format!("{p256_pem}{PUBLIC_PEM}{rsa_public}");
    let dir = store(base, "mixed", &text, None);
    let p384 = SpkiSigner::from_base64(SECRET_PKCS8_B64).unwrap();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        for (signer, algorithm) in [(p256, "p256"), (p384, "p384"), (rsa, "rsa")] {
            repo.delete_signatures(&commit, "ostree.sign.spki", |_, _| true)
                .await
                .unwrap();
            repo.sign_commit(&commit, &signer).await.unwrap();
            let outcome = repo
                .verify_commit(&commit, &[Arc::new(store_verifier(&dir))])
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
