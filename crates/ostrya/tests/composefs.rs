#![forbid(unsafe_code)]

//! Phase 9d composefs export tests (see docs/port-plan.md).
//!
//! The tree the composefs fixture was exported from is the same source tree the
//! bare-user fixture commits, so [`Repo::export_composefs`] over the bare-user
//! fixture commit must reproduce the golden image `tree.cfs` byte-for-byte and
//! the fs-verity digest the tool recorded in the MANIFEST. A second test drives
//! the digest into a commit's metadata and reads it back.
//!
//! Both tests skip when the composefs fixture is absent (a checkout produced by
//! an `ostree` without composefs support, or without `composefs-info`).

mod common;

use std::path::PathBuf;
use std::process::Command;

use ostrya::{Checksum, Repo};
use ostrya_rt::block_on;

use common::{COMMIT, TmpDir, fixture_repo, fixture_root};

/// The directory holding the checked-in composefs golden fixtures.
fn composefs_dir() -> PathBuf {
    fixture_root().join("composefs")
}

/// Read a `key=value` entry from the fixture MANIFEST.
fn manifest_value(key: &str) -> Option<String> {
    let text = std::fs::read_to_string(fixture_root().join("MANIFEST")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .map(|v| v.trim().to_owned())
}

/// The composefs image digest the tool recorded, or `None` when the fixture is
/// absent (so the test skips).
fn expected_digest() -> Option<String> {
    manifest_value("composefs_digest").filter(|s| !s.is_empty())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn export_matches_golden_image_and_digest() {
    let (Some(digest), Ok(golden)) = (
        expected_digest(),
        std::fs::read(composefs_dir().join("tree.cfs")),
    ) else {
        eprintln!("composefs fixture absent; skipping");
        return;
    };

    let repo_dir = fixture_repo("bare-user");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();
        let image = repo.export_composefs(&commit).await.unwrap();

        assert_eq!(
            image.bytes.len(),
            golden.len(),
            "image length {} != golden {}",
            image.bytes.len(),
            golden.len()
        );
        if let Some(pos) = image.bytes.iter().zip(&golden).position(|(a, b)| a != b) {
            panic!(
                "image diverges from golden at byte {pos:#x}: got {:#04x}, want {:#04x}",
                image.bytes[pos], golden[pos]
            );
        }
        assert_eq!(
            to_hex(&image.fs_verity),
            digest,
            "fs-verity digest mismatch"
        );
    });
}

#[test]
fn stores_digest_in_commit_metadata() {
    let Some(digest) = expected_digest() else {
        eprintln!("composefs fixture absent; skipping");
        return;
    };

    // Copy the fixture repo so the transaction publishes into a throwaway,
    // leaving the shared unpacked fixture untouched. `cp -a` preserves the
    // `user.ostreemeta` xattrs the bare-user objects carry.
    let src = fixture_repo("bare-user");
    let scratch = TmpDir::new("composefs-meta");
    let dst = scratch.path().join("repo");
    let status = Command::new("cp")
        .arg("-a")
        .arg(&src)
        .arg(&dst)
        .status()
        .expect("run cp to copy the fixture repo");
    assert!(status.success(), "cp -a failed to copy the fixture repo");

    block_on(async {
        let repo = Repo::open(&dst).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();

        let txn = repo.transaction().await.unwrap();
        let new_commit = repo
            .commit_add_composefs_metadata(&txn, &commit)
            .await
            .unwrap();
        assert_ne!(
            new_commit, commit,
            "adding the digest metadata yields a distinct commit"
        );
        txn.commit().await.unwrap();

        let (obj, _) = repo.load_commit(&new_commit).await.unwrap();
        let value = obj
            .metadata
            .dict_get("ostree.composefs.digest.v0")
            .expect("ostree.composefs.digest.v0 present in the new commit");
        let (_, inner) = value.as_variant().expect("digest value is a variant");
        let bytes = inner.as_bytes().expect("digest is a byte array");
        assert_eq!(
            to_hex(bytes),
            digest,
            "stored digest equals the tool's recorded digest"
        );
    });
}
