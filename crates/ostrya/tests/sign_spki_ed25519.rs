//! Integration tests for commit signing with the Ed25519 key type of the spki
//! engine.
//!
//! The key is the key of test 1 in RFC 8032. No test makes a key.

#![cfg(feature = "sign-spki-ed25519")]

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Ed25519Signer,
    Ed25519Verifier, MutableTree, Repo, RepoMode, Signer, SpkiSigner, SpkiVerifier, Value, base64,
    load_sign_keys_from,
};
use ostrya_rt::block_on;

/// The secret key, base64 of the PKCS#8 version 1 DER: the seed alone.
const SECRET_PKCS8_V1_B64: &str =
    "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g";
/// The secret key, base64 of the PKCS#8 version 2 DER: the seed and the
/// public key.
const SECRET_PKCS8_V2_B64: &str = concat!(
    "MFECAQEwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9ggSEA11qYAYKx",
    "CrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
);
/// The secret key of the ed25519 engine, in base64: the seed, then the
/// public key.
const ENGINE_SECRET_B64: &str = concat!(
    "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2DXWpgBgrEKt9VL/tPJZAc6",
    "DuFy89qmIyWvAhpo9wdRGg==",
);
/// The public key in a PEM `PUBLIC KEY` block.
const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n\
-----END PUBLIC KEY-----\n";
/// The lowercase hex SHA-256 of the SubjectPublicKeyInfo DER of the key.
const FINGERPRINT: &str = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

/// A P-256 public key in a PEM `PUBLIC KEY` block.
#[cfg(not(any(
    feature = "sign-spki-p256",
    feature = "sign-spki-p384",
    feature = "sign-spki-rsa"
)))]
const P256_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8X83xylD3ibci0xjFKMR4bwUtTU/\n\
YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDnRAG1Ua8eR8SKbLQ==\n\
-----END PUBLIC KEY-----\n";

/// The P-384 key of RFC 6979, appendix A.2.6, in a PEM `PUBLIC KEY` block.
#[cfg(any(
    all(
        feature = "sign-spki-p256",
        feature = "sign-spki-p384",
        feature = "sign-spki-rsa"
    ),
    not(any(
        feature = "sign-spki-p256",
        feature = "sign-spki-p384",
        feature = "sign-spki-rsa"
    ))
))]
const P384_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7DpOQVtOGaRWhhgCn0J/pdqai8SukuAu\n\
BqrlKGswDGTe+PDqkFWGYGSiVFFUgLwTgBXZty19VyROqO+awMYhiWcIpZNn+d+5\n\
9UyoSz8cnbEoiyMcOuDU/nNE/SUzJkcg\n\
-----END PUBLIC KEY-----\n";

/// Returns the path of the key fixture file `name`.
#[cfg(any(
    all(
        feature = "sign-spki-p256",
        feature = "sign-spki-p384",
        feature = "sign-spki-rsa"
    ),
    not(any(
        feature = "sign-spki-p256",
        feature = "sign-spki-p384",
        feature = "sign-spki-rsa"
    ))
))]
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
        subject: Some("spki Ed25519 sign fixture".to_owned()),
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

/// Returns the blobs under the key `key` of the detached-metadata dict `dict`.
fn blobs(dict: &Value, key: &str) -> Vec<Vec<u8>> {
    let value = dict.dict_get(key).expect("the dict holds the key");
    let array = value.as_variant().map_or(value, |(_, inner)| inner);
    array
        .as_array()
        .expect("the value is an array")
        .iter()
        .map(|blob| blob.as_bytes().expect("a blob is a byte string").to_vec())
        .collect()
}

#[test]
fn ed25519_keys_in_pkcs8_v1_and_v2_sign_and_verify_a_commit() {
    let tmp = TmpDir::new("spki-ed25519-sign");
    block_on(async {
        let (repo, commit) = build_committed_repo(tmp.path()).await;
        let mut written = Vec::new();
        for secret in [SECRET_PKCS8_V1_B64, SECRET_PKCS8_V2_B64] {
            repo.delete_signatures(&commit, "ostree.sign.spki", |_, _| true)
                .await
                .unwrap();
            let signer = SpkiSigner::from_base64(secret).unwrap();
            repo.sign_commit(&commit, &signer).await.unwrap();
            let verifier = SpkiVerifier::from_pem(PUBLIC_PEM).unwrap();
            let outcome = repo.verify_commit(&commit, &[&verifier]).await.unwrap();
            assert!(outcome.valid, "{secret}");
            let dict = repo
                .read_commit_detached_metadata(&commit)
                .await
                .unwrap()
                .expect("the commit has detached metadata");
            written.push(blobs(&dict, "ostree.sign.spki"));
        }
        // The two forms of the key write the same signature.
        assert_eq!(written[0].len(), 1);
        assert_eq!(written[0][0].len(), 64);
        assert_eq!(written[0], written[1]);
    });
}

#[test]
fn a_key_store_with_an_ed25519_key_verifies_and_its_revocation_removes_the_key() {
    let tmp = TmpDir::new("spki-ed25519-store");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        let signer = SpkiSigner::from_base64(SECRET_PKCS8_V1_B64).unwrap();
        repo.sign_commit(&commit, &signer).await.unwrap();

        let dir = store(base, "trusted", PUBLIC_PEM, None);
        let outcome = repo
            .verify_commit(&commit, &[&store_verifier(&dir)])
            .await
            .unwrap();
        assert!(outcome.valid);
        let info = &outcome.signatures[0];
        assert_eq!(info.pubkey_algorithm.as_deref(), Some("ed25519"));
        assert_eq!(info.fingerprint.as_deref(), Some(FINGERPRINT));

        let dir = store(base, "revoked", PUBLIC_PEM, Some(PUBLIC_PEM));
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

/// The ed25519 engine and the spki engine write the same 64 bytes for one
/// seed and one commit, under two metadata keys. The verifier of each engine
/// reads the blobs under its own key alone, so it does not verify a commit
/// that the other engine signed.
#[test]
fn the_ed25519_engine_and_the_spki_engine_sign_with_the_same_bytes() {
    let tmp = TmpDir::new("spki-ed25519-engines");
    let base = tmp.path();
    let engine_secret = base64::decode(ENGINE_SECRET_B64).unwrap();
    let engine = Ed25519Signer::from_secret_key(&engine_secret).unwrap();
    let spki = SpkiSigner::from_base64(SECRET_PKCS8_V1_B64).unwrap();
    let engine_verifier =
        Ed25519Verifier::new([&engine_secret[32..]], Vec::<&[u8]>::new()).unwrap();
    let spki_verifier = SpkiVerifier::from_pem(PUBLIC_PEM).unwrap();
    block_on(async {
        assert_eq!(
            engine.sign(b"data").await.unwrap(),
            spki.sign(b"data").await.unwrap()
        );
        let (repo, commit) = build_committed_repo(base).await;

        repo.sign_commit(&commit, &spki).await.unwrap();
        assert!(
            !repo
                .verify_commit(&commit, &[&engine_verifier])
                .await
                .unwrap()
                .valid
        );
        repo.delete_signatures(&commit, "ostree.sign.spki", |_, _| true)
            .await
            .unwrap();
        repo.sign_commit(&commit, &engine).await.unwrap();
        assert!(
            !repo
                .verify_commit(&commit, &[&spki_verifier])
                .await
                .unwrap()
                .valid
        );

        repo.sign_commit(&commit, &spki).await.unwrap();
        let dict = repo
            .read_commit_detached_metadata(&commit)
            .await
            .unwrap()
            .expect("the commit has detached metadata");
        let engine_blobs = blobs(&dict, "ostree.sign.ed25519");
        assert_eq!(engine_blobs.len(), 1);
        assert_eq!(engine_blobs, blobs(&dict, "ostree.sign.spki"));
        for verifier in [&engine_verifier as &dyn ostrya::Verifier, &spki_verifier] {
            assert!(
                repo.verify_commit(&commit, &[verifier])
                    .await
                    .unwrap()
                    .valid
            );
        }
    });
}

#[cfg(all(
    feature = "sign-spki-p256",
    feature = "sign-spki-p384",
    feature = "sign-spki-rsa"
))]
#[test]
fn a_key_store_of_the_four_key_types_verifies_a_commit_of_each() {
    let tmp = TmpDir::new("spki-ed25519-mixed");
    let base = tmp.path();
    // A P-256 key and a P-384 key, base64 of the PKCS#8 DER.
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
    let p384 = SpkiSigner::from_base64(concat!(
        "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBrnT2tLhuMHAWxmHW2ZZ9N4jw7Znvy",
        "l7qapHdAeHE32JbVck5McKgl+HLJ6mDS7fWhZANiAATsOk5BW04ZpFaGGAKfQn+l2pqLxK6S4C4G",
        "quUoazAMZN748OqQVYZgZKJUUVSAvBOAFdm3LX1XJE6o75rAxiGJZwilk2f537n1TKhLPxydsSiL",
        "Ixw64NT+c0T9JTMmRyA=",
    ))
    .unwrap();
    let rsa_pem = std::fs::read(key_path("rsa-2048.pem")).unwrap();
    let rsa = ostrya::spki_secret_keys(rsa_pem, "rsa-2048.pem")
        .unwrap()
        .remove(0);
    let rsa_public = std::fs::read_to_string(key_path("rsa-2048.pub.pem")).unwrap();
    let text = format!("{p256_pem}{P384_PUBLIC_PEM}{PUBLIC_PEM}{rsa_public}");
    let dir = store(base, "mixed", &text, None);
    let ed25519 = SpkiSigner::from_base64(SECRET_PKCS8_V1_B64).unwrap();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        for (signer, algorithm) in [
            (p256, "p256"),
            (p384, "p384"),
            (ed25519, "ed25519"),
            (rsa, "rsa"),
        ] {
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

#[cfg(not(any(
    feature = "sign-spki-p256",
    feature = "sign-spki-p384",
    feature = "sign-spki-rsa"
)))]
#[test]
fn a_build_with_ed25519_alone_refuses_the_other_key_types_and_verifies_an_ed25519_key() {
    let tmp = TmpDir::new("spki-ed25519-alone");
    let base = tmp.path();
    let rsa_public = std::fs::read_to_string(key_path("rsa-2048.pub.pem")).unwrap();
    for (name, text, reason) in [
        (
            "p256",
            P256_PUBLIC_PEM,
            "this build has no code for the curve P-256; build with the sign-spki-p256 feature",
        ),
        (
            "p384",
            P384_PUBLIC_PEM,
            "this build has no code for the curve P-384; build with the sign-spki-p384 feature",
        ),
        (
            "rsa",
            rsa_public.as_str(),
            "this build has no code for the key type RSA; build with the sign-spki-rsa feature",
        ),
    ] {
        // The key in `trusted.spki`, and the key in `revoked.spki`, which
        // fails the store closed.
        for (dir, file) in [
            (store(base, name, text, None), "trusted.spki"),
            (
                store(base, &format!("revoked-{name}"), PUBLIC_PEM, Some(text)),
                "revoked.spki",
            ),
        ] {
            match load_sign_keys_from(&[dir.as_path()], "spki").unwrap_err() {
                ostrya::Error::Signature(m) => assert_eq!(
                    m,
                    format!(
                        "the key file '{}', line 1: {reason}",
                        dir.join(file).display()
                    )
                ),
                other => panic!("not a signature error: {other}"),
            }
        }
    }

    let dir = store(base, "ed25519", PUBLIC_PEM, None);
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        let signer = SpkiSigner::from_base64(SECRET_PKCS8_V1_B64).unwrap();
        repo.sign_commit(&commit, &signer).await.unwrap();
        assert!(
            repo.verify_commit(&commit, &[&store_verifier(&dir)])
                .await
                .unwrap()
                .valid
        );
    });
}
