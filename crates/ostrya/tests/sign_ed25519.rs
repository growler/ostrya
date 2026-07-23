//! ed25519 commit-signing integration tests (Phase 13b).
//!
//! These exercise [`Ed25519Signer`] / [`Ed25519Verifier`] and the sign-api key
//! store against the `ostree` tool: a signature the port writes verifies under
//! `ostree sign --verify --sign-type=ed25519`, the port verifies a signature the
//! tool wrote, the `.commitmeta` bytes are identical (ed25519 is deterministic),
//! and the `trusted.ed25519[.d]` / `revoked.ed25519[.d]` directory convention
//! resolves keys the same way in the port and the tool, with a revoked key
//! rejected.
//!
//! The keypair is a fixed vector produced with `openssl genpkey -algorithm
//! ed25519` and validated round-trip against the tool. `SECRET_B64` is the
//! base64 of the 64-byte secret (32-byte seed followed by the 32-byte public
//! key); `PUBLIC_B64` is the base64 of the 32-byte public key.

mod common;

use std::os::fd::AsFd;
use std::path::Path;
use std::process::Command;

use common::{TmpDir, ostree_available};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Ed25519Signer,
    Ed25519Verifier, MutableTree, Repo, RepoMode, base64, load_sign_keys_from,
};
use ostrya_rt::block_on;

/// The base64 of the 64-byte ed25519 secret key (seed followed by public key).
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
/// The base64 of the matching 32-byte ed25519 public key.
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

/// Build a tiny source tree under `base/src`.
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

/// Create an archive repo, ingest `base/src` with canonical permissions and
/// owner 0:0, and commit it on `test/main`. Returns the repo and commit.
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
        subject: Some("ed25519 sign fixture".to_owned()),
        timestamp: Some(1_700_000_000),
        ..CommitOptions::default()
    };
    let commit = txn.write_commit(opts, &root).await.unwrap();
    txn.set_ref("test/main", Some(&commit));
    txn.commit().await.unwrap();
    (repo, commit)
}

/// The `.commitmeta` bytes for `commit` in the repo under `base`.
fn commitmeta_bytes(base: &Path, commit: &Checksum) -> Vec<u8> {
    let hex = commit.to_hex();
    let (a, b) = hex.split_at(2);
    std::fs::read(
        base.join("repo/objects")
            .join(a)
            .join(format!("{b}.commitmeta")),
    )
    .unwrap()
}

/// The raw 32-byte public key.
fn public_key() -> Vec<u8> {
    base64::decode(PUBLIC_B64).unwrap()
}

#[test]
fn port_ed25519_signature_is_verified_by_the_tool() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("ed25519-port-tool");
    let base = tmp.path();
    let repo_arg = format!("--repo={}", base.join("repo").display());
    let commit = block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
        commit
    });
    let commit_hex = commit.to_hex();

    let ok = Command::new("ostree")
        .args([
            &repo_arg,
            "sign",
            "--verify",
            "--sign-type=ed25519",
            &commit_hex,
            PUBLIC_B64,
        ])
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "tool rejected the port's ed25519 signature: {}",
        String::from_utf8_lossy(&ok.stderr)
    );

    // A different public key must not verify.
    let wrong = base64::encode(&[0u8; 32]);
    let bad = Command::new("ostree")
        .args([
            &repo_arg,
            "sign",
            "--verify",
            "--sign-type=ed25519",
            &commit_hex,
            &wrong,
        ])
        .output()
        .unwrap();
    assert!(
        !bad.status.success(),
        "tool accepted a wrong key against the port's signature"
    );
}

#[test]
fn port_verifies_an_ed25519_signature_the_tool_wrote() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("ed25519-tool-port");
    let base = tmp.path();
    let repo_arg = format!("--repo={}", base.join("repo").display());
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;

        // The tool signs the port-built commit with the ed25519 secret key.
        let signed = Command::new("ostree")
            .args([
                &repo_arg,
                "sign",
                "--sign-type=ed25519",
                &commit.to_hex(),
                SECRET_B64,
            ])
            .output()
            .unwrap();
        assert!(
            signed.status.success(),
            "tool failed to sign: {}",
            String::from_utf8_lossy(&signed.stderr)
        );

        // The port verifies it with the matching trusted key, and rejects a
        // verifier that does not trust the key.
        let verifier = Ed25519Verifier::new([public_key()], Vec::<Vec<u8>>::new()).unwrap();
        let outcome = repo.verify_commit(&commit, &[&verifier]).await.unwrap();
        assert!(outcome.valid, "port rejected the tool's ed25519 signature");
        assert_eq!(outcome.signatures.len(), 1);
        assert!(outcome.signatures[0].valid);

        let other = Ed25519Verifier::new([vec![0u8; 32]], Vec::<Vec<u8>>::new()).unwrap();
        let rejected = repo.verify_commit(&commit, &[&other]).await.unwrap();
        assert!(!rejected.valid, "port accepted an untrusted key");
        assert_eq!(rejected.signatures.len(), 1);
        assert!(!rejected.signatures[0].valid);
        assert!(rejected.signatures[0].key_missing);
    });
}

#[test]
fn ed25519_commitmeta_is_byte_identical_to_the_tool() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    // Two repositories hold the identical commit; one is signed by the port and
    // one by the tool with the same key. ed25519 is deterministic, so the
    // `.commitmeta` bytes must match.
    let port_tmp = TmpDir::new("ed25519-bytes-port");
    let port_base = port_tmp.path();
    let (port_commit, port_bytes) = block_on(async {
        let (repo, commit) = build_committed_repo(port_base).await;
        repo.sign_commit(&commit, &Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
        let bytes = commitmeta_bytes(port_base, &commit);
        (commit, bytes)
    });

    let tool_tmp = TmpDir::new("ed25519-bytes-tool");
    let tool_base = tool_tmp.path();
    let tool_commit = block_on(async { build_committed_repo(tool_base).await.1 });
    let repo_arg = format!("--repo={}", tool_base.join("repo").display());
    let signed = Command::new("ostree")
        .args([
            &repo_arg,
            "sign",
            "--sign-type=ed25519",
            &tool_commit.to_hex(),
            SECRET_B64,
        ])
        .output()
        .unwrap();
    assert!(signed.status.success());
    let tool_bytes = commitmeta_bytes(tool_base, &tool_commit);

    assert_eq!(port_commit, tool_commit, "commits are identical");
    assert_eq!(
        port_bytes, tool_bytes,
        "port and tool produce identical .commitmeta bytes"
    );
}

#[test]
fn ed25519_trusted_revoked_directory_convention() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("ed25519-keydir");
    let base = tmp.path();
    let repo_arg = format!("--repo={}", base.join("repo").display());
    let keys_dir = base.join("keys");
    let trusted_d = keys_dir.join("trusted.ed25519.d");
    std::fs::create_dir_all(&trusted_d).unwrap();
    std::fs::write(trusted_d.join("mykey"), format!("{PUBLIC_B64}\n")).unwrap();

    let commit = block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();

        // Port: the loader resolves the trusted key and verifies.
        let keys = load_sign_keys_from(&[keys_dir.as_path()], "ed25519").unwrap();
        assert_eq!(keys.trusted.len(), 1);
        assert!(keys.revoked.is_empty());
        let verifier = Ed25519Verifier::from_sign_keys(keys).unwrap();
        assert!(
            repo.verify_commit(&commit, &[&verifier])
                .await
                .unwrap()
                .valid,
            "loaded trusted key should verify"
        );
        commit
    });
    let commit_hex = commit.to_hex();

    // Tool: the same directory verifies via --keys-dir.
    let keys_dir_arg = format!("--keys-dir={}", keys_dir.display());
    let tool_ok = Command::new("ostree")
        .args([
            &repo_arg,
            "sign",
            "--verify",
            "--sign-type=ed25519",
            &keys_dir_arg,
            &commit_hex,
        ])
        .output()
        .unwrap();
    assert!(
        tool_ok.status.success(),
        "tool rejected the trusted key from --keys-dir: {}",
        String::from_utf8_lossy(&tool_ok.stderr)
    );

    // Revoke the key in both the port's view and the tool's.
    let revoked_d = keys_dir.join("revoked.ed25519.d");
    std::fs::create_dir_all(&revoked_d).unwrap();
    std::fs::write(revoked_d.join("bad"), format!("{PUBLIC_B64}\n")).unwrap();

    block_on(async {
        let (repo, _) = build_committed_repo(base).await;
        let keys = load_sign_keys_from(&[keys_dir.as_path()], "ed25519").unwrap();
        assert_eq!(keys.trusted.len(), 1);
        assert_eq!(keys.revoked.len(), 1);
        let verifier = Ed25519Verifier::from_sign_keys(keys).unwrap();
        assert!(
            !repo
                .verify_commit(&commit, &[&verifier])
                .await
                .unwrap()
                .valid,
            "a revoked key must not verify"
        );
    });

    let tool_bad = Command::new("ostree")
        .args([
            &repo_arg,
            "sign",
            "--verify",
            "--sign-type=ed25519",
            &keys_dir_arg,
            &commit_hex,
        ])
        .output()
        .unwrap();
    assert!(
        !tool_bad.status.success(),
        "tool accepted a revoked key from --keys-dir"
    );
}

#[test]
fn ed25519_round_trip_within_the_port() {
    let tmp = TmpDir::new("ed25519-roundtrip");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();

        let good = Ed25519Verifier::new([public_key()], Vec::<Vec<u8>>::new()).unwrap();
        assert!(repo.verify_commit(&commit, &[&good]).await.unwrap().valid);

        let bad = Ed25519Verifier::new([vec![0u8; 32]], Vec::<Vec<u8>>::new()).unwrap();
        assert!(!repo.verify_commit(&commit, &[&bad]).await.unwrap().valid);
    });
}

#[test]
fn ed25519_verifier_drops_revoked_from_trusted() {
    // The verifier trusts the trusted set minus the revoked set, matched by key
    // bytes; a key in both is dropped.
    let key = public_key();
    let both = Ed25519Verifier::new([key.clone()], [key.clone()]).unwrap();
    // With the only trusted key revoked, nothing verifies.
    let tmp = TmpDir::new("ed25519-revoke-unit");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
        assert!(!repo.verify_commit(&commit, &[&both]).await.unwrap().valid);
    });
}

#[test]
fn sign_key_store_reads_files_dirs_and_tolerates_missing() {
    let tmp = TmpDir::new("ed25519-store");
    let root = tmp.path();

    // A missing root yields empty sets, not an error.
    let empty = load_sign_keys_from(&[root], "ed25519").unwrap();
    assert!(empty.trusted.is_empty() && empty.revoked.is_empty());

    // trusted.ed25519 file with two keys, plus a trusted.ed25519.d/ drop-in.
    std::fs::write(
        root.join("trusted.ed25519"),
        format!("{PUBLIC_B64}\n{}\n", base64::encode(&[1u8; 32])),
    )
    .unwrap();
    let trusted_d = root.join("trusted.ed25519.d");
    std::fs::create_dir_all(&trusted_d).unwrap();
    std::fs::write(
        trusted_d.join("extra"),
        format!("{}\n", base64::encode(&[2u8; 32])),
    )
    .unwrap();
    // A revoked.ed25519 file.
    std::fs::write(root.join("revoked.ed25519"), format!("{PUBLIC_B64}\n")).unwrap();

    let keys = load_sign_keys_from(&[root], "ed25519").unwrap();
    assert_eq!(keys.trusted.len(), 3, "two file keys plus one drop-in key");
    assert_eq!(keys.revoked.len(), 1);
    assert_eq!(keys.trusted[0], public_key());
}

#[test]
fn ed25519_key_input_length_is_validated() {
    // A raw ay public key of the right length is accepted; a wrong length is a
    // signature error, as is a wrong-length secret key.
    assert!(Ed25519Verifier::new([public_key()], Vec::<Vec<u8>>::new()).is_ok());
    assert!(Ed25519Verifier::new([vec![0u8; 31]], Vec::<Vec<u8>>::new()).is_err());
    assert!(Ed25519Signer::from_secret_key(&[0u8; 63]).is_err());
    // A base64 secret that decodes to the wrong length is rejected too.
    assert!(Ed25519Signer::from_base64(PUBLIC_B64).is_err());
}
