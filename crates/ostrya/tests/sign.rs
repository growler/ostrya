//! Commit-signing integration tests (Phase 13a).
//!
//! These exercise the [`Signer`]/[`Verifier`] framework through the dummy
//! engine: a dummy signature the port appends is accepted by `ostree sign
//! --verify --sign-type=dummy`, the port verifies a dummy signature the tool
//! wrote, appending a second engine's signatures leaves the first engine's
//! array intact, and an unsigned commit verifies as not-valid. The dummy engine
//! is gated in the tool behind `OSTREE_DUMMY_SIGN_ENABLED`, so every tool
//! invocation here sets it.

mod common;

use std::os::fd::AsFd;
use std::path::Path;
use std::process::Command;

use common::{TmpDir, ostree_available};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DummySigner,
    DummyVerifier, MutableTree, Repo, RepoMode, Type, Value,
};
use ostrya_rt::block_on;

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

/// Create an archive repo under `base/repo`, ingest `base/src` with canonical
/// permissions and owner 0:0, and commit it on `test/main`. Returns the repo
/// handle and the commit checksum.
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
        subject: Some("sign fixture".to_owned()),
        timestamp: Some(1_700_000_000),
        ..CommitOptions::default()
    };
    let commit = txn.write_commit(opts, &root).await.unwrap();
    txn.set_ref("test/main", Some(&commit));
    txn.commit().await.unwrap();
    (repo, commit)
}

/// Run `ostree` with the dummy engine enabled, returning its captured output.
fn run_ostree_dummy(args: &[&str]) -> std::process::Output {
    Command::new("ostree")
        .env("OSTREE_DUMMY_SIGN_ENABLED", "1")
        .args(args)
        .output()
        .expect("run ostree")
}

#[test]
fn port_dummy_signature_is_verified_by_the_tool() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("sign-port-tool");
    let base = tmp.path();
    let repo_arg = format!("--repo={}", base.join("repo").display());
    let commit = block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &DummySigner::new("mysecretkey"))
            .await
            .unwrap();
        commit
    });

    // The tool verifies the port-written signature with the matching key.
    let commit_hex = commit.to_hex();
    let ok = run_ostree_dummy(&[
        &repo_arg,
        "sign",
        "--verify",
        "--sign-type=dummy",
        &commit_hex,
        "mysecretkey",
    ]);
    assert!(
        ok.status.success(),
        "tool rejected the port's dummy signature: {}",
        String::from_utf8_lossy(&ok.stderr)
    );

    // A different key must not verify.
    let bad = run_ostree_dummy(&[
        &repo_arg,
        "sign",
        "--verify",
        "--sign-type=dummy",
        &commit_hex,
        "wrongkey",
    ]);
    assert!(
        !bad.status.success(),
        "tool accepted a wrong key against the port's signature"
    );
}

#[test]
fn port_verifies_a_dummy_signature_the_tool_wrote() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("sign-tool-port");
    let base = tmp.path();
    let repo_arg = format!("--repo={}", base.join("repo").display());
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        let commit_hex = commit.to_hex();

        // The tool signs the port-built commit with the dummy engine.
        let signed = run_ostree_dummy(&[
            &repo_arg,
            "sign",
            "--sign-type=dummy",
            &commit_hex,
            "toolkey",
        ]);
        assert!(
            signed.status.success(),
            "tool failed to sign: {}",
            String::from_utf8_lossy(&signed.stderr)
        );

        // The port verifies it with the matching trusted key, and rejects a
        // verifier that does not trust the key.
        let outcome = repo
            .verify_commit(&commit, &[&DummyVerifier::new(["toolkey"])])
            .await
            .unwrap();
        assert!(outcome.valid, "port rejected the tool's dummy signature");
        assert_eq!(outcome.signatures.len(), 1);
        assert!(outcome.signatures[0].valid);

        let rejected = repo
            .verify_commit(&commit, &[&DummyVerifier::new(["othertoolkey"])])
            .await
            .unwrap();
        assert!(!rejected.valid, "port accepted an untrusted key");
        assert_eq!(rejected.signatures.len(), 1);
        assert!(!rejected.signatures[0].valid);
        assert!(rejected.signatures[0].key_missing);
    });
}

#[test]
fn dummy_commitmeta_is_byte_identical_to_the_tool() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    // Two repositories hold the identical commit; one is signed by the port and
    // one by the tool with the same key, so the `.commitmeta` files must match.
    let commitmeta_bytes = |base: &Path, commit: &Checksum| -> Vec<u8> {
        let hex = commit.to_hex();
        let (a, b) = hex.split_at(2);
        std::fs::read(
            base.join("repo/objects")
                .join(a)
                .join(format!("{b}.commitmeta")),
        )
        .unwrap()
    };

    let port_tmp = TmpDir::new("sign-bytes-port");
    let port_base = port_tmp.path();
    let (port_commit, port_bytes) = block_on(async {
        let (repo, commit) = build_committed_repo(port_base).await;
        repo.sign_commit(&commit, &DummySigner::new("samekey"))
            .await
            .unwrap();
        let bytes = commitmeta_bytes(port_base, &commit);
        (commit, bytes)
    });

    let tool_tmp = TmpDir::new("sign-bytes-tool");
    let tool_base = tool_tmp.path();
    let tool_commit = block_on(async { build_committed_repo(tool_base).await.1 });
    let repo_arg = format!("--repo={}", tool_base.join("repo").display());
    let signed = run_ostree_dummy(&[
        &repo_arg,
        "sign",
        "--sign-type=dummy",
        &tool_commit.to_hex(),
        "samekey",
    ]);
    assert!(signed.status.success());
    let tool_bytes = commitmeta_bytes(tool_base, &tool_commit);

    assert_eq!(port_commit, tool_commit, "commits are identical");
    assert_eq!(
        port_bytes, tool_bytes,
        "port and tool produce identical .commitmeta bytes"
    );
}

#[test]
fn appending_dummy_signature_leaves_a_foreign_engine_array_intact() {
    let tmp = TmpDir::new("sign-multi-engine");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;

        // Seed a foreign engine's signature array directly into the detached
        // metadata, standing in for a different signing engine.
        let ed_key = "ostree.sign.ed25519";
        let ed_sig = vec![0x11u8; 64];
        let seeded = Value::Array(vec![Value::Tuple(vec![
            Value::Str(ed_key.to_owned()),
            Value::variant(
                Type::parse("aay").unwrap(),
                Value::Array(vec![Value::Bytes(ed_sig.clone())]),
            ),
        ])]);
        repo.write_commit_detached_metadata(&commit, Some(&seeded))
            .await
            .unwrap();

        // Sign with the dummy engine, then again, so the dummy array grows to
        // two blobs.
        repo.sign_commit(&commit, &DummySigner::new("keyone"))
            .await
            .unwrap();
        repo.sign_commit(&commit, &DummySigner::new("keytwo"))
            .await
            .unwrap();

        let dict = repo
            .read_commit_detached_metadata(&commit)
            .await
            .unwrap()
            .expect("detached metadata present");

        // The foreign engine's array is untouched.
        let ed = dict.dict_get(ed_key).and_then(Value::as_variant).unwrap().1;
        let ed_blobs = ed.as_array().unwrap();
        assert_eq!(ed_blobs.len(), 1, "foreign engine array is intact");
        assert_eq!(ed_blobs[0].as_bytes(), Some(ed_sig.as_slice()));

        // The dummy engine accumulated both signatures in order.
        let dummy = dict
            .dict_get("ostree.sign.dummy")
            .and_then(Value::as_variant)
            .unwrap()
            .1;
        let dummy_blobs = dummy.as_array().unwrap();
        assert_eq!(dummy_blobs.len(), 2, "dummy signatures accumulate");
        assert_eq!(dummy_blobs[0].as_bytes(), Some(b"keyone".as_slice()));
        assert_eq!(dummy_blobs[1].as_bytes(), Some(b"keytwo".as_slice()));

        // Verification sees both dummy blobs; trusting one key validates.
        let outcome = repo
            .verify_commit(&commit, &[&DummyVerifier::new(["keytwo"])])
            .await
            .unwrap();
        assert!(outcome.valid);
        assert_eq!(outcome.signatures.len(), 2);
    });
}

#[test]
fn verifying_an_unsigned_commit_is_not_valid() {
    let tmp = TmpDir::new("sign-unsigned");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        let outcome = repo
            .verify_commit(&commit, &[&DummyVerifier::new(["anykey"])])
            .await
            .unwrap();
        assert!(!outcome.valid, "an unsigned commit is not valid");
        assert!(outcome.signatures.is_empty());
    });
}

#[test]
fn dummy_round_trip_within_the_port() {
    let tmp = TmpDir::new("sign-roundtrip");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &DummySigner::new("thekey"))
            .await
            .unwrap();

        let good = repo
            .verify_commit(&commit, &[&DummyVerifier::new(["thekey"])])
            .await
            .unwrap();
        assert!(good.valid);

        let bad = repo
            .verify_commit(&commit, &[&DummyVerifier::new(["nope"])])
            .await
            .unwrap();
        assert!(!bad.valid);
    });
}
