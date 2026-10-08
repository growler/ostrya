//! Integration tests for commit signing.
//!
//! These tests use the dummy engine of the `Signer` and `Verifier` framework.
//! The tests cover:
//!
//! - a dummy signature that ostrya appends, which
//!   `ostree sign --verify --sign-type=dummy` accepts
//! - a dummy signature that the `ostree` command writes, which ostrya verifies
//! - the signatures of a second engine, which keep the array of the first
//!   engine unchanged
//! - an unsigned commit, which does not verify as valid
//!
//! The `ostree` command enables the dummy engine only if
//! `OSTREE_DUMMY_SIGN_ENABLED` is set. Each run of the command in these tests
//! sets this variable.

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

/// Creates an archive repository under `base/repo` and commits `base/src` on
/// `test/main`. The ingest uses canonical permissions and owner 0:0. Returns
/// the repository handle and the commit checksum.
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

/// Runs `ostree` with the dummy engine enabled and returns its captured output.
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

    // With the matching key, the `ostree` command verifies the signature that
    // ostrya wrote.
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

        // The `ostree` command signs the commit that ostrya built, with the
        // dummy engine.
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

        // A verifier that trusts the key verifies the signature. With a
        // verifier that does not trust the key, the signature is not valid.
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
    // Two repositories hold the same commit. In one, ostrya signs it. In the
    // other, the `ostree` command signs it with the same key. The two
    // `.commitmeta` files must be identical.
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

        // Write the signature array of a foreign engine directly into the
        // detached metadata. This array stands for a different signing engine.
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

        // Sign two times with the dummy engine, so the dummy array holds two
        // blobs.
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

        // The array of the foreign engine does not change.
        let ed = dict.dict_get(ed_key).and_then(Value::as_variant).unwrap().1;
        let ed_blobs = ed.as_array().unwrap();
        assert_eq!(ed_blobs.len(), 1, "foreign engine array is intact");
        assert_eq!(ed_blobs[0].as_bytes(), Some(ed_sig.as_slice()));

        // The dummy array holds both signatures in the order of signing.
        let dummy = dict
            .dict_get("ostree.sign.dummy")
            .and_then(Value::as_variant)
            .unwrap()
            .1;
        let dummy_blobs = dummy.as_array().unwrap();
        assert_eq!(dummy_blobs.len(), 2, "dummy signatures accumulate");
        assert_eq!(dummy_blobs[0].as_bytes(), Some(b"keyone".as_slice()));
        assert_eq!(dummy_blobs[1].as_bytes(), Some(b"keytwo".as_slice()));

        // The verification sees both dummy blobs. A verifier that trusts one
        // of the keys gives a valid result.
        let outcome = repo
            .verify_commit(&commit, &[&DummyVerifier::new(["keytwo"])])
            .await
            .unwrap();
        assert!(outcome.valid);
        assert_eq!(outcome.signatures.len(), 2);
    });
}

#[test]
fn delete_signatures_removes_matching_and_empties() {
    let tmp = TmpDir::new("sign-delete");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &DummySigner::new("key-a"))
            .await
            .unwrap();
        repo.sign_commit(&commit, &DummySigner::new("key-b"))
            .await
            .unwrap();

        // Remove only the blob that matches key-a.
        let removed = repo
            .delete_signatures(&commit, "ostree.sign.dummy", |_payload, blob| {
                blob == b"key-a"
            })
            .await
            .unwrap();
        assert_eq!(removed, 1);

        // The signature of key-b stays. The signature of key-a is gone.
        let dict = repo
            .read_commit_detached_metadata(&commit)
            .await
            .unwrap()
            .expect("detached metadata present");
        let blobs = dict
            .dict_get("ostree.sign.dummy")
            .and_then(Value::as_variant)
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].as_bytes(), Some(b"key-b".as_slice()));
        assert!(
            repo.verify_commit(&commit, &[&DummyVerifier::new(["key-b"])])
                .await
                .unwrap()
                .valid
        );
        assert!(
            !repo
                .verify_commit(&commit, &[&DummyVerifier::new(["key-a"])])
                .await
                .unwrap()
                .valid
        );

        // The removal of the last signature empties the dict. Then no detached
        // metadata remains.
        let removed = repo
            .delete_signatures(&commit, "ostree.sign.dummy", |_payload, _blob| true)
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert!(
            repo.read_commit_detached_metadata(&commit)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn delete_signatures_preserves_other_engines() {
    let tmp = TmpDir::new("sign-delete-foreign");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;

        // Write the array of a foreign engine. Then add a dummy signature next
        // to it.
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
        repo.sign_commit(&commit, &DummySigner::new("key-a"))
            .await
            .unwrap();

        // The delete of all dummy signatures removes the dummy entry. The array
        // of the foreign engine stays, so the detached metadata remains.
        let removed = repo
            .delete_signatures(&commit, "ostree.sign.dummy", |_payload, _blob| true)
            .await
            .unwrap();
        assert_eq!(removed, 1);
        let dict = repo
            .read_commit_detached_metadata(&commit)
            .await
            .unwrap()
            .expect("foreign metadata is retained");
        assert!(dict.dict_get("ostree.sign.dummy").is_none());
        let ed = dict.dict_get(ed_key).and_then(Value::as_variant).unwrap().1;
        assert_eq!(
            ed.as_array().unwrap()[0].as_bytes(),
            Some(ed_sig.as_slice())
        );
    });
}

#[test]
fn delete_signatures_without_a_match_is_a_noop() {
    let tmp = TmpDir::new("sign-delete-noop");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &DummySigner::new("key-a"))
            .await
            .unwrap();

        // A key that does not match removes nothing. An engine key with no
        // entry also removes nothing.
        assert_eq!(
            repo.delete_signatures(&commit, "ostree.sign.dummy", |_p, b| b == b"nope")
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            repo.delete_signatures(&commit, "ostree.sign.ed25519", |_p, _b| true)
                .await
                .unwrap(),
            0
        );
        assert!(
            repo.verify_commit(&commit, &[&DummyVerifier::new(["key-a"])])
                .await
                .unwrap()
                .valid
        );
    });
}

#[test]
fn delete_signatures_on_an_unsigned_commit_is_a_noop() {
    let tmp = TmpDir::new("sign-delete-unsigned");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        assert_eq!(
            repo.delete_signatures(&commit, "ostree.sign.dummy", |_p, _b| true)
                .await
                .unwrap(),
            0
        );
        assert!(
            repo.read_commit_detached_metadata(&commit)
                .await
                .unwrap()
                .is_none()
        );
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

/// Returns the stored signature blobs of the dummy engine for `commit`, sorted,
/// as text.
async fn dummy_signatures(repo: &Repo, commit: &Checksum) -> Vec<String> {
    let Some(dict) = repo.read_commit_detached_metadata(commit).await.unwrap() else {
        return Vec::new();
    };
    let Some(array) = dict
        .dict_get("ostree.sign.dummy")
        .and_then(Value::as_variant)
        .map(|(_, value)| value)
    else {
        return Vec::new();
    };
    let mut blobs: Vec<String> = array
        .as_array()
        .unwrap()
        .iter()
        .map(|blob| String::from_utf8(blob.as_bytes().unwrap().to_vec()).unwrap())
        .collect();
    blobs.sort();
    blobs
}

/// Two signatures that two signers make at the same time both reach the
/// `.commitmeta`. The test covers these cases:
///
/// - two signers in one transaction
/// - two signers in two transactions
/// - a transaction signer and a `Repo::sign_commit` caller
///
/// The append goes into a queue under one lock, with no `.await` inside the
/// lock. The write reads, merges, and replaces the file under a guard that the
/// process shares, so neither signer overwrites the other. The order of the
/// signatures depends on which signer finishes first, so the test checks the
/// set.
#[test]
fn concurrent_signatures_are_not_lost() {
    let tmp = TmpDir::new("sign-concurrent");
    let base = tmp.path();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;

        // Two signers in one transaction.
        let txn = repo.transaction().await.unwrap();
        let (one, two) = futures_lite::future::zip(
            txn.sign_commit(&commit, &DummySigner::new("one")),
            txn.sign_commit(&commit, &DummySigner::new("two")),
        )
        .await;
        one.unwrap();
        two.unwrap();
        txn.commit().await.unwrap();
        assert_eq!(
            dummy_signatures(&repo, &commit).await,
            ["one", "two"],
            "a signature was lost inside one transaction"
        );

        // Two transactions in one process sign the same commit. Each
        // transaction appends to the signatures that the other left, as two
        // runs in sequence do.
        async fn sign_in_own_transaction(repo: &Repo, commit: &Checksum, key: &str) {
            let txn = repo.transaction().await.unwrap();
            txn.sign_commit(commit, &DummySigner::new(key))
                .await
                .unwrap();
            txn.commit().await.unwrap();
        }
        futures_lite::future::zip(
            sign_in_own_transaction(&repo, &commit, "three"),
            sign_in_own_transaction(&repo, &commit, "four"),
        )
        .await;
        assert_eq!(
            dummy_signatures(&repo, &commit).await,
            ["four", "one", "three", "two"],
            "a signature was lost across two transactions"
        );

        // A queued replace removes the stored signatures. The signatures that
        // are queued after the replace stay.
        let txn = repo.transaction().await.unwrap();
        txn.set_commit_detached_metadata(&commit, Value::Array(Vec::new()));
        let (five, six) = futures_lite::future::zip(
            txn.sign_commit(&commit, &DummySigner::new("five")),
            txn.sign_commit(&commit, &DummySigner::new("six")),
        )
        .await;
        five.unwrap();
        six.unwrap();
        txn.commit().await.unwrap();
        assert_eq!(
            dummy_signatures(&repo, &commit).await,
            ["five", "six"],
            "the replace did not clear the stored signatures"
        );

        // A `Repo::sign_commit` caller races a transaction signer on the same
        // commit. The two share no queue, so the guard of the read-modify-write
        // is the one thing that keeps both signatures. Each pass adds two
        // signatures. The count shows that all earlier signatures stay.
        for pass in 0usize..8 {
            let direct = format!("direct-{pass}");
            let queued = format!("queued-{pass}");
            let txn = repo.transaction().await.unwrap();
            let (one, two) = futures_lite::future::zip(
                repo.sign_commit(&commit, &DummySigner::new(direct.as_str())),
                async {
                    txn.sign_commit(&commit, &DummySigner::new(queued.as_str()))
                        .await?;
                    txn.commit().await
                },
            )
            .await;
            one.unwrap();
            two.unwrap();
            let stored = dummy_signatures(&repo, &commit).await;
            assert!(
                stored.contains(&direct) && stored.contains(&queued),
                "a signature was lost between Repo::sign_commit and a transaction: {stored:?}"
            );
            assert_eq!(
                stored.len(),
                2 + 2 * (pass + 1),
                "an earlier signature was lost: {stored:?}"
            );
        }
    });
}

/// The signing items resolve at their public paths in `ostrya`. The module
/// paths under `ostrya::sign` and the root paths name the same items. The error
/// of an engine converts into the repository error.
#[test]
fn signing_items_resolve_at_their_public_paths() {
    use ostrya::sign::{
        Error, FromSystemKeys, MAX_KEY_FILE, Result, SignFuture, SignKeys, Signer, VerifyFuture,
        append_signature,
    };
    use ostrya::{DummySigner, Ed25519Signer, Ed25519Verifier};

    fn from_system_keys<T: FromSystemKeys + ostrya::FromSystemKeys>() {}
    from_system_keys::<Ed25519Verifier>();
    #[cfg(feature = "sign-spki")]
    from_system_keys::<ostrya::spki::SpkiVerifier>();

    let signer: Box<dyn ostrya::Signer> = Box::new(DummySigner::new("key"));
    let signer: &dyn Signer = &*signer;
    let signed: SignFuture<'_> = signer.sign(b"payload");
    let signature: Result<Vec<u8>> = block_on(signed);
    let signature = signature.unwrap();
    assert_eq!(signature, b"key");

    let verifier = DummyVerifier::new([b"key".to_vec()]);
    let signatures = [signature.clone()];
    let verified: VerifyFuture<'_> = ostrya::Verifier::verify(&verifier, b"payload", &signatures);
    assert!(block_on(verified).unwrap().valid);

    let mut dict = Value::Array(Vec::new());
    append_signature(&mut dict, signer.metadata_key(), signature).unwrap();
    assert!(dict.dict_get("ostree.sign.dummy").is_some());

    assert_eq!(MAX_KEY_FILE, 1024 * 1024);
    let verifier = Ed25519Verifier::from_sign_keys(SignKeys::default()).unwrap();
    assert!(verifier.is_empty());
    assert!(Ed25519Signer::from_secret_key(&[0u8; 63]).is_err());

    let err: ostrya::Error = Error::Signature("refused".into()).into();
    assert!(
        matches!(&err, ostrya::Error::Signature(m) if m == "refused"),
        "{err}"
    );

    #[cfg(feature = "sign-spki")]
    {
        let signer = ostrya::spki::SpkiSigner::from_secret_key(&[1u8; 32]).unwrap();
        assert_eq!(Signer::name(&signer), "spki");
    }
    #[cfg(feature = "sign-gpg")]
    {
        let signer = ostrya::gpg::GpgSigner::new("key").with_homedir("/nonexistent");
        assert_eq!(Signer::name(&signer), "gpg");
        assert_eq!(signer.homedir(), Some(Path::new("/nonexistent")));
    }
}
