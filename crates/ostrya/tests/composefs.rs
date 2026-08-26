#![forbid(unsafe_code)]

//! Phase 9d composefs export tests (see docs/port-plan.md).
//!
//! The tree the composefs fixture was exported from is the same source tree the
//! bare-user fixture commits, so [`Repo::export_composefs`] over the bare-user
//! fixture commit must reproduce the golden image `tree.cfs` byte-for-byte and
//! the fs-verity digest the tool recorded in the MANIFEST. A second test drives
//! the digest into a commit's metadata and reads it back.
//!
//! [`VerityPolicy::Disabled`] is checked the same way against
//! `tree-noverity.cfs`, and one further test shows that policy reads no
//! payload: a content object's bytes are rewritten in place at their existing
//! length, which leaves the `Disabled` image unchanged and changes the
//! `Computed` one.
//!
//! The tests that compare against a golden image or the tool's recorded digest
//! skip when the composefs fixture is absent (a checkout produced by an
//! `ostree` without composefs support, or without `composefs-info`). The
//! payload test reads no composefs fixture and always runs.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use ostrya::{Checksum, ComposefsOptions, Repo, RepoMode, VerityPolicy};
use ostrya_core::{ObjectType, loose_path};
use ostrya_rt::block_on;

use common::{COMMIT, HELLO_TXT, TmpDir, fixture_repo, fixture_root};

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

/// The composefs image digest the tool recorded under `key`, or `None` when the
/// fixture is absent (so the test skips).
fn manifest_digest(key: &str) -> Option<String> {
    manifest_value(key).filter(|s| !s.is_empty())
}

/// Copy the bare-user fixture repository into `scratch` and return its path.
/// `cp -a` preserves the `user.ostreemeta` xattrs the objects carry.
fn scratch_fixture_repo(scratch: &TmpDir) -> PathBuf {
    let src = fixture_repo("bare-user");
    let dst = scratch.path().join("repo");
    let status = Command::new("cp")
        .arg("-a")
        .arg(&src)
        .arg(&dst)
        .status()
        .expect("run cp to copy the fixture repo");
    assert!(status.success(), "cp -a failed to copy the fixture repo");
    dst
}

/// The loose path of the content object `checksum` in the bare-user repository
/// at `repo_dir`. Naming the object keeps it inside `COMMIT`'s tree, which is
/// what makes the `Computed` image depend on its payload.
fn content_object(repo_dir: &Path, checksum: &str) -> PathBuf {
    repo_dir.join("objects").join(loose_path(
        &Checksum::from_hex(checksum).unwrap(),
        ObjectType::File,
        RepoMode::BareUser,
    ))
}

/// Flip one byte of `path`'s payload in place, leaving the object's length and
/// its `user.ostreemeta` attribute untouched.
fn rewrite_payload(path: &Path) {
    use std::io::Write;

    let mut bytes = std::fs::read(path).expect("read the object payload");
    assert!(!bytes.is_empty(), "the object has a payload to rewrite");
    bytes[0] ^= 0xff;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open the object for writing");
    file.write_all(&bytes).expect("rewrite the object payload");
    file.flush().expect("flush the rewritten object");
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Export the fixture commit under `verity`, and require the image to equal
/// `<stem>.cfs` byte-for-byte and its fs-verity digest to equal the MANIFEST
/// value at `digest_key`. Skips when the golden fixture is absent.
fn check_export(stem: &str, digest_key: &str, verity: VerityPolicy) {
    let (Some(digest), Ok(golden)) = (
        manifest_digest(digest_key),
        std::fs::read(composefs_dir().join(format!("{stem}.cfs"))),
    ) else {
        eprintln!("composefs fixture {stem} absent; skipping");
        return;
    };

    let repo_dir = fixture_repo("bare-user");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();
        let image = repo
            .export_composefs(&commit, &ComposefsOptions { verity })
            .await
            .unwrap();

        assert_eq!(
            image.bytes.len(),
            golden.len(),
            "{stem}: image length {} != golden {}",
            image.bytes.len(),
            golden.len()
        );
        if let Some(pos) = image.bytes.iter().zip(&golden).position(|(a, b)| a != b) {
            panic!(
                "{stem}: image diverges from golden at byte {pos:#x}: got {:#04x}, want {:#04x}",
                image.bytes[pos], golden[pos]
            );
        }
        assert_eq!(
            to_hex(&image.fs_verity),
            digest,
            "{stem}: fs-verity digest mismatch"
        );
    });
}

#[test]
fn export_matches_golden_image_and_digest() {
    check_export("tree", "composefs_digest", VerityPolicy::Computed);
}

#[test]
fn noverity_export_matches_golden_image_and_digest() {
    check_export(
        "tree-noverity",
        "composefs_noverity_digest",
        VerityPolicy::Disabled,
    );
}

#[test]
fn stores_digest_in_commit_metadata() {
    let Some(digest) = manifest_digest("composefs_digest") else {
        eprintln!("composefs fixture absent; skipping");
        return;
    };

    // Copy the fixture repo so the transaction publishes into a throwaway,
    // leaving the shared unpacked fixture untouched.
    let scratch = TmpDir::new("composefs-meta");
    let dst = scratch_fixture_repo(&scratch);

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

/// A content object's payload decides the `Computed` image and nothing in the
/// `Disabled` one. Rewriting it in place at its existing length keeps every
/// inode's metadata, so the object still loads under both policies and the two
/// images part on the payload alone. The bare-user fixture and the library are
/// the whole input, so this runs whatever the host's `ostree` supports.
#[test]
fn disabled_policy_reads_no_payload() {
    let computed = ComposefsOptions {
        verity: VerityPolicy::Computed,
    };
    let disabled = ComposefsOptions {
        verity: VerityPolicy::Disabled,
    };

    let scratch = TmpDir::new("composefs-noverity-payload");
    let repo_dir = scratch_fixture_repo(&scratch);

    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();

        let before_computed = repo.export_composefs(&commit, &computed).await.unwrap();
        let before_disabled = repo.export_composefs(&commit, &disabled).await.unwrap();

        rewrite_payload(&content_object(&repo_dir, HELLO_TXT));

        let after_computed = repo.export_composefs(&commit, &computed).await.unwrap();
        let after_disabled = repo.export_composefs(&commit, &disabled).await.unwrap();

        assert_eq!(
            before_disabled.bytes, after_disabled.bytes,
            "a rewritten payload leaves the Disabled image unchanged"
        );
        assert_ne!(
            before_computed.bytes, after_computed.bytes,
            "a rewritten payload changes the Computed image"
        );
        assert_ne!(
            before_disabled.fs_verity, before_computed.fs_verity,
            "the two policies produce distinct images"
        );
    });
}
