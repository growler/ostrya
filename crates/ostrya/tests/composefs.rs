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
//! Each golden check also exports through a file descriptor with
//! [`Repo::export_composefs_to`] and requires the file to hold the same bytes
//! and the returned digest to equal the fs-verity digest of the file's content.
//! A further test requires [`Transaction::composefs_digest`] over the same tree
//! to reach the digest the tool recorded.
//!
//! The tests that compare against a golden image or the tool's recorded digest
//! skip when the composefs fixture is absent (a checkout produced by an
//! `ostree` without composefs support, or without `composefs-info`). The
//! payload test reads no composefs fixture and always runs.

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use ostrya::{
    Checksum, CommitOptions, ComposefsOptions, CreateOptions, DirMeta, Error, FileMeta,
    MutableTree, Repo, RepoMode, VerityPolicy,
};
use ostrya_composefs::FsVerityHasher;
use ostrya_core::{ObjectType, Xattrs, loose_path};
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

/// Copy the `mode` fixture repository into `scratch` and return its path.
/// `cp -a` preserves the `user.ostreemeta` xattrs the objects carry.
fn scratch_fixture_repo(scratch: &TmpDir, mode: &str) -> PathBuf {
    let src = fixture_repo(mode);
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
/// value at `digest_key`. The fd form is held to the same bytes and the same
/// digest. Skips when the golden fixture is absent.
fn check_export(stem: &str, digest_key: &str, verity: VerityPolicy) {
    let (Some(digest), Ok(golden)) = (
        manifest_digest(digest_key),
        std::fs::read(composefs_dir().join(format!("{stem}.cfs"))),
    ) else {
        eprintln!("composefs fixture {stem} absent; skipping");
        return;
    };

    let scratch = TmpDir::new("composefs-export-to");
    let image_path = scratch.path().join(format!("{stem}.cfs"));
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

        let file = std::fs::File::create(&image_path).expect("create the image file");
        let streamed = repo
            .export_composefs_to(&commit, &ComposefsOptions { verity }, file.as_fd())
            .await
            .unwrap();
        drop(file);

        let written = std::fs::read(&image_path).expect("read the exported image back");
        assert_eq!(
            written, image.bytes,
            "{stem}: the fd form wrote different bytes than the buffer form"
        );
        assert_eq!(
            to_hex(&streamed),
            digest,
            "{stem}: the fd form returned a different digest"
        );
        assert_eq!(
            streamed,
            FsVerityHasher::hash(&written),
            "{stem}: the returned digest differs from the digest of the file"
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
    let dst = scratch_fixture_repo(&scratch, "bare-user");

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

/// `Transaction::composefs_digest` reaches the digest the tool recorded for the
/// fixture tree. The transaction stages nothing, so every object comes from the
/// repository, and the value is the one the buffered export returns.
#[test]
fn transaction_digest_matches_recorded_digest() {
    let Some(digest) = manifest_digest("composefs_digest") else {
        eprintln!("composefs fixture absent; skipping");
        return;
    };

    let repo_dir = fixture_repo("bare-user");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let (tree, commit) = repo.read_commit(COMMIT).await.unwrap();

        let txn = repo.transaction().await.unwrap();
        let staged = txn.composefs_digest(&tree).await.unwrap();
        txn.abort().await.unwrap();

        assert_eq!(
            to_hex(&staged),
            digest,
            "the staged-tree digest equals the tool's recorded digest"
        );

        let image = repo
            .export_composefs(
                &commit,
                &ComposefsOptions {
                    verity: VerityPolicy::Computed,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            staged, image.fs_verity,
            "the staged-tree digest equals the exported image's digest"
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
    let repo_dir = scratch_fixture_repo(&scratch, "bare-user");

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

/// Which inode of the helper's tree carries the attributes under test.
#[derive(Clone, Copy)]
enum Carrier {
    /// The root directory, through its dirmeta object.
    Root,
    /// A regular file in the root. The export adds `overlay.redirect` and
    /// `trusted.overlay.metacopy` to this inode on top of what it carries, so
    /// the case also holds that those additions sit outside the budget.
    File,
}

/// Walk the composefs model of a tree whose `carrier` inode holds `xattrs`, in a
/// repository of its own in `mode`. The dirmeta object is built directly rather
/// than by setting the attributes on a real directory, because a host
/// filesystem's own ceiling decides whether they can be set at all. `mode` is
/// `Archive` where the attributes go on a file object large enough to meet that
/// ceiling in a bare-user repository, since an archive object carries its
/// metadata in its own header.
async fn export_xattrs(
    repo_dir: &Path,
    mode: RepoMode,
    carrier: Carrier,
    xattrs: Xattrs,
) -> Result<(), Error> {
    let repo = Repo::create(repo_dir, CreateOptions::new(mode))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let root_xattrs = match carrier {
        Carrier::Root => xattrs,
        Carrier::File => {
            let meta = FileMeta {
                uid: 0,
                gid: 0,
                mode: 0o100644,
                xattrs,
            };
            let file = txn.write_regfile_inline(None, &meta, b"").await.unwrap();
            mtree.replace_file("f", file).unwrap();
            Xattrs::empty()
        }
    };
    let dirmeta_bytes = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: root_xattrs,
    }
    .serialize()
    .unwrap();
    let dirmeta = txn
        .write_metadata(ObjectType::DirMeta, None, &dirmeta_bytes)
        .await
        .unwrap();
    mtree.set_metadata_checksum(dirmeta);
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("xattr budget".to_owned()),
                timestamp: Some(0),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("budget", Some(&commit));
    txn.commit().await.unwrap();

    // A backing mode writes the image. Any other mode reaches the same refusal
    // through the digest path, which builds no image and so takes no mode.
    // `Image` holds no `Debug`, so each value is dropped rather than matched on.
    if mode == RepoMode::BareUser {
        return repo
            .export_composefs(&commit, &ComposefsOptions::default())
            .await
            .map(|_| ());
    }
    let (tree, _) = repo.read_commit("budget").await.unwrap();
    let txn = repo.transaction().await.unwrap();
    let walked = txn.composefs_digest(&tree).await.map(|_| ());
    txn.abort().await.unwrap();
    walked
}

/// One xattr spends its name, its value, and 7 bytes from the inode's budget of
/// 32755 bytes. At the budget the export builds the image, and one byte past it
/// the export refuses and names the attribute.
#[test]
fn holds_an_inode_to_the_composefs_xattr_budget() {
    let scratch = TmpDir::new("composefs-xattr-budget");
    let name = b"user.long\0".to_vec();
    // 7 + 9 (the name without its NUL) + value == 32755 at the budget.
    let at_budget = 32755 - 7 - 9;
    block_on(async {
        export_xattrs(
            &scratch.path().join("at"),
            RepoMode::BareUser,
            Carrier::Root,
            Xattrs::new([(name.clone(), vec![b'x'; at_budget])]).unwrap(),
        )
        .await
        .expect("the export builds the image at the budget");

        let err = export_xattrs(
            &scratch.path().join("over"),
            RepoMode::BareUser,
            Carrier::Root,
            Xattrs::new([(name, vec![b'x'; at_budget + 1])]).unwrap(),
        )
        .await
        .expect_err("the export refuses one byte past the budget");
        let text = err.to_string();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );
        assert!(
            text.contains("user.long") && text.contains("32756"),
            "the refusal names the attribute and the bytes it takes: {text}"
        );
    });
}

/// The budget covers the inode, so two attributes that each fit spend it
/// together. The refusal names the attribute that takes the inode past it.
#[test]
fn the_composefs_xattr_budget_covers_the_inode() {
    let scratch = TmpDir::new("composefs-xattr-budget-sum");
    // 2 * (7 + 6 + value) == 32756 one byte past the budget.
    let each = (32756 / 2) - 7 - 6;
    block_on(async {
        let err = export_xattrs(
            scratch.path(),
            RepoMode::BareUser,
            Carrier::Root,
            Xattrs::new([
                (b"user.a\0".to_vec(), vec![b'x'; each]),
                (b"user.b\0".to_vec(), vec![b'y'; each]),
            ])
            .unwrap(),
        )
        .await
        .expect_err("the export refuses the pair");
        let text = err.to_string();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );
        assert!(
            text.contains("user.b") && text.contains("32756"),
            "the refusal names the second attribute: {text}"
        );
    });
}

/// A regular file is held to the same budget, and the `overlay.redirect` and
/// `trusted.overlay.metacopy` attributes the export adds to that inode sit
/// outside it: the walk accepts the file at the budget. An archive repository
/// carries the attribute, which a bare-user object's `user.ostreemeta` cannot
/// at this size.
#[test]
fn the_composefs_xattr_budget_covers_a_regular_file() {
    let scratch = TmpDir::new("composefs-xattr-budget-file");
    let name = b"user.long\0".to_vec();
    let at_budget = 32755 - 7 - 9;
    block_on(async {
        export_xattrs(
            &scratch.path().join("at"),
            RepoMode::Archive,
            Carrier::File,
            Xattrs::new([(name.clone(), vec![b'x'; at_budget])]).unwrap(),
        )
        .await
        .expect("the export builds the image at the budget");

        let err = export_xattrs(
            &scratch.path().join("over"),
            RepoMode::Archive,
            Carrier::File,
            Xattrs::new([(name, vec![b'x'; at_budget + 1])]).unwrap(),
        )
        .await
        .expect_err("the export refuses one byte past the budget");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );
    });
}

/// Commit a tree holding one symlink whose target is `len` bytes, in a
/// repository of its own under `dir`, and walk it into the image.
async fn export_symlink(dir: &Path, len: usize) -> Result<(), Error> {
    let repo = Repo::create(dir, CreateOptions::new(RepoMode::BareUser))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let meta = FileMeta {
        uid: 0,
        gid: 0,
        mode: 0o120777,
        xattrs: Xattrs::empty(),
    };
    let link = txn
        .write_symlink(&"z".repeat(len), &meta, None)
        .await
        .unwrap();
    let mut mtree = MutableTree::new();
    mtree.replace_file("l", link).unwrap();
    let dirmeta_bytes = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: Xattrs::empty(),
    }
    .serialize()
    .unwrap();
    let dirmeta = txn
        .write_metadata(ObjectType::DirMeta, None, &dirmeta_bytes)
        .await
        .unwrap();
    mtree.set_metadata_checksum(dirmeta);
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("symlink".to_owned()),
                timestamp: Some(0),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.commit().await.unwrap();
    // `Image` holds no `Debug`, so the value is dropped rather than matched on.
    repo.export_composefs(&commit, &ComposefsOptions::default())
        .await
        .map(|_| ())
}

/// A symlink states its target inline, beside a 32-byte compact inode header,
/// so a target carrying no attributes fits at 4063 bytes and does not at 4064.
/// The tool aborts on the same pair, which `format-reference.md`, "composefs",
/// records.
#[test]
fn holds_a_symlink_target_to_its_inode_block() {
    let scratch = TmpDir::new("composefs-symlink-block");
    block_on(async {
        export_symlink(&scratch.path().join("at"), 4063)
            .await
            .expect("the export builds the image at 4063 bytes");

        let err = export_symlink(&scratch.path().join("over"), 4064)
            .await
            .expect_err("the export refuses a target that fills the block");
        let text = err.to_string();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );
        assert!(
            text.contains("4064"),
            "the refusal names the length: {text}"
        );
    });
}

/// A stored name goes into a one-byte length field, so a name above 255 bytes
/// has no place in the image whatever the budget says. At 255 bytes the walk
/// accepts the attribute, and at 256 it refuses and names it.
#[test]
fn holds_an_xattr_name_to_the_erofs_length_field() {
    let scratch = TmpDir::new("composefs-xattr-name");
    let name_of = |len: usize| {
        let mut name = b"user.".to_vec();
        name.resize(len, b'n');
        name.push(0);
        name
    };
    block_on(async {
        export_xattrs(
            &scratch.path().join("at"),
            RepoMode::Archive,
            Carrier::File,
            Xattrs::new([(name_of(255), b"v".to_vec())]).unwrap(),
        )
        .await
        .expect("the export builds the image at 255 bytes of name");

        let err = export_xattrs(
            &scratch.path().join("over"),
            RepoMode::Archive,
            Carrier::File,
            Xattrs::new([(name_of(256), b"v".to_vec())]).unwrap(),
        )
        .await
        .expect_err("the export refuses a 256-byte name");
        let text = err.to_string();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );
        assert!(
            text.contains("user.nn") && text.contains("256"),
            "the refusal names the attribute and its length: {text}"
        );
    });
}

/// `commit_add_composefs_metadata` builds no image, so it runs in a repository
/// of any mode and records the digest a composefs backing mode records. The
/// export forms keep the mode rule, which the same repository shows.
#[test]
fn digest_metadata_runs_in_a_non_backing_mode() {
    let Some(digest) = manifest_digest("composefs_digest") else {
        eprintln!("composefs fixture absent; skipping");
        return;
    };

    // The transaction publishes, so the archive fixture is copied first.
    let scratch = TmpDir::new("composefs-archive-meta");
    let dst = scratch_fixture_repo(&scratch, "archive");

    block_on(async {
        let repo = Repo::open(&dst).await.unwrap();
        assert_eq!(repo.mode(), RepoMode::Archive, "the fixture is archive");
        let commit = Checksum::from_hex(COMMIT).unwrap();

        // `Image` holds no `Debug`, so the value is dropped rather than
        // matched on.
        let err = repo
            .export_composefs(&commit, &ComposefsOptions::default())
            .await
            .map(|_| ())
            .expect_err("an archive repository writes no image");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );

        let txn = repo.transaction().await.unwrap();
        let stored = repo
            .commit_add_composefs_metadata(&txn, &commit)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let (obj, _) = repo.load_commit(&stored).await.unwrap();
        let value = obj
            .metadata
            .dict_get("ostree.composefs.digest.v0")
            .expect("the new commit carries the digest key");
        let (_, inner) = value.as_variant().expect("digest value is a variant");
        let bytes = inner.as_bytes().expect("digest is a byte array");
        assert_eq!(
            to_hex(bytes),
            digest,
            "the archive repository records the digest the tool recorded"
        );
    });
}
