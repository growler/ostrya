//! Summary generation, signing, and verification (Phase 14).
//!
//! Byte-identity is checked against golden summaries the `ostree` tool wrote for
//! the same repositories (`tests/fixtures/generated/summary` and
//! `summary-collection`, produced by `generate.sh`). The tool's wall-clock
//! `ostree.summary.last-modified` is patched in the golden to a fixed epoch, and
//! the port is asked to reproduce that epoch, so the comparison is deterministic.
//! The collection fixture ships the repository in its pre-summary state, so the
//! port generates the `ostree-metadata` anchor commit itself and its checksum is
//! checked against the tool's.

mod common;

use std::path::Path;
use std::process::Command;

use common::{TmpDir, fixture_root, ostree_available};
use ostrya::base64;
use ostrya::{Ed25519Signer, Ed25519Verifier, Repo, SummaryOptions};
use ostrya_rt::block_on;

/// The fixed epoch patched into both golden summaries' `last-modified` and used
/// as the collection anchor commit's timestamp (`generate.sh`).
const FIXED_EPOCH: u64 = 1_700_000_000;
/// The collection id of the `summary-collection` fixture.
const COLLECTION_ID: &str = "org.ostrya.Test";
/// The `ostree-metadata` anchor commit the tool wrote for the collection
/// fixture (first generation, parentless, timestamp `FIXED_EPOCH`).
const ANCHOR_COMMIT: &str = "04fd8792152380dd12ef240cda008ef098407791011c01b3dd4f75f9964d6068";

/// A fixed ed25519 keypair for sign/verify round-trips (from `sign_ed25519.rs`).
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

/// Recursively copy a directory tree, preserving attributes.
fn copy_tree(from: &Path, to: &Path) {
    let status = Command::new("cp")
        .args(["-a"])
        .arg(from)
        .arg(to)
        .status()
        .expect("run cp");
    assert!(status.success(), "cp -a {from:?} {to:?} failed");
}

/// Copy a fixture's `repo/` into a fresh writable temp directory and return it.
fn writable_fixture(fixture: &str, tag: &str) -> (TmpDir, std::path::PathBuf) {
    let tmp = TmpDir::new(tag);
    let repo = tmp.path().join("repo");
    copy_tree(&fixture_root().join(fixture).join("repo"), &repo);
    (tmp, repo)
}

#[test]
fn plain_summary_is_byte_identical_to_the_tool() {
    let (_tmp, repo_dir) = writable_fixture("summary", "summary-plain");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();

        let got = repo.read_summary().await.unwrap().expect("summary written");
        let want = std::fs::read(fixture_root().join("summary").join("summary")).unwrap();
        assert_eq!(
            got, want,
            "the port's summary must be byte-identical to the tool's"
        );
    });
}

#[test]
fn regenerate_removes_a_stale_signature() {
    let (_tmp, repo_dir) = writable_fixture("summary", "summary-stale-sig");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();
        repo.sign_summary(&Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
        assert!(repo.read_summary_signature().await.unwrap().is_some());

        // A fresh summary invalidates the old signature, so it is removed.
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();
        assert!(
            repo.read_summary_signature().await.unwrap().is_none(),
            "regeneration must drop a stale summary.sig"
        );
    });
}

#[test]
fn collection_summary_and_anchor_match_the_tool() {
    let (_tmp, repo_dir) = writable_fixture("summary-collection", "summary-collection");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        assert_eq!(repo.config().collection_id(), Some(COLLECTION_ID));

        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: Some(FIXED_EPOCH),
        })
        .await
        .unwrap();

        // The port generated the anchor commit; its checksum matches the tool's.
        let anchor = repo
            .resolve_rev("ostree-metadata", false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            anchor.to_hex(),
            ANCHOR_COMMIT,
            "the ostree-metadata anchor commit must match the tool's"
        );

        let got = repo.read_summary().await.unwrap().expect("summary written");
        let want =
            std::fs::read(fixture_root().join("summary-collection").join("summary")).unwrap();
        assert_eq!(
            got, want,
            "the port's collection summary must be byte-identical to the tool's"
        );
    });
}

#[test]
fn sign_and_verify_round_trip() {
    let (_tmp, repo_dir) = writable_fixture("summary", "summary-sign");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();

        repo.sign_summary(&Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();

        let public = base64::decode(PUBLIC_B64).unwrap();
        let trusted = Ed25519Verifier::new([public], Vec::<Vec<u8>>::new()).unwrap();
        let outcome = repo.verify_summary(&[&trusted]).await.unwrap();
        assert!(outcome.valid, "a signed summary must verify with the key");

        let wrong = Ed25519Verifier::new([vec![0u8; 32]], Vec::<Vec<u8>>::new()).unwrap();
        let outcome = repo.verify_summary(&[&wrong]).await.unwrap();
        assert!(!outcome.valid, "a foreign key must not verify the summary");
    });
}

/// The reverse-direction gate: the `ostree` tool verifies a summary the port
/// generated and signed. Wrong-key rejection is covered by the port's own
/// `verify_summary` above; the tool's summary cache makes a second in-process
/// verify under a different key unreliable, so it is not asserted here.
#[test]
fn tool_verifies_a_port_signed_summary() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let (_tmp, repo_dir) = writable_fixture("summary", "summary-tool-verify");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();
        repo.sign_summary(&Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
    });

    let url = format!("file://{}", repo_dir.display());
    let add = |name: &str, key: &str| {
        let status = Command::new("ostree")
            .arg(format!("--repo={}", repo_dir.display()))
            .args(["remote", "add", name, &url, "--no-gpg-verify"])
            .arg(format!("--sign-verify=ed25519=inline:{key}"))
            .status()
            .expect("run ostree remote add");
        assert!(status.success(), "ostree remote add {name} failed");
    };
    let remote_summary = |name: &str| {
        Command::new("ostree")
            .arg(format!("--repo={}", repo_dir.display()))
            .args(["remote", "summary", name])
            .output()
            .expect("run ostree remote summary")
            .status
            .success()
    };

    add("good", PUBLIC_B64);
    assert!(
        remote_summary("good"),
        "the tool must verify a summary the port signed"
    );
}
