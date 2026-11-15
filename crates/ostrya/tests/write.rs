//! Integration tests of the object writers.
//!
//! The tests write objects into real repositories and check these items:
//!
//! - archive and bare-user loose objects against the checked-in fixtures,
//!   byte for byte, and the bare-user-shared objects that follow from
//!   bare-user
//! - bare objects against the objects of the `ostree` command
//! - a second write of an object, which is a no-op (dedup)
//! - the free-space guard
//! - concurrent writers on one `&Transaction`
//! - the read-back through `load_file`
//! - the canonical header that bare-user-only stores and names its objects
//!   for

mod common;

use std::path::Path;
use std::process::Command;

use common::{TmpDir, fixture_repo, ostree_available};
use futures_lite::AsyncReadExt;
use futures_lite::io::Cursor;
use ostrya::{
    Checksum, CreateOptions, Error, FileKind, FileMeta, FsckOptions, Repo, RepoMode, Transaction,
    TransactionStats,
};
use ostrya_core::{ObjectType, loose_path};
use ostrya_rt::block_on;

// The fixture tree of the golden repositories (owner 0:0, mode 0644), and the
// object checksums that the `ostree` command gave to it.
const HELLO: &[u8] = b"hello ostree\n";
const NESTED: &[u8] = b"nested\n";
const EMPTY: &[u8] = b"";
const HELLO_TXT: &str = common::HELLO_TXT;
const EMPTY_TXT: &str = common::EMPTY_TXT;
const NESTED_TXT: &str = common::NESTED_TXT;
const LINK: &str = common::LINK;

fn csum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

/// Returns a regular-file `FileMeta` with owner 0:0 and mode 0644, as in the
/// fixtures.
fn reg() -> FileMeta {
    FileMeta::regular(0, 0, 0o644)
}

/// Writes the four fixture content objects into `txn` through ostrya.
///
/// The writes use the inline, streaming, and symlink writers. The function
/// asserts that each computed checksum is equal to the fixture checksum of the
/// `ostree` command.
async fn write_fixture_tree(txn: &Transaction) {
    assert_eq!(
        txn.write_regfile_inline(Some(&csum(HELLO_TXT)), &reg(), HELLO)
            .await
            .unwrap(),
        csum(HELLO_TXT),
        "hello.txt identity"
    );
    // The streaming writer must give the same checksum as the inline writer.
    assert_eq!(
        txn.write_content(None, &reg(), Cursor::new(NESTED.to_vec()))
            .await
            .unwrap(),
        csum(NESTED_TXT),
        "nested.txt identity"
    );
    assert_eq!(
        txn.write_regfile_inline(None, &reg(), EMPTY).await.unwrap(),
        csum(EMPTY_TXT),
        "empty.txt identity"
    );
    assert_eq!(
        txn.write_symlink("hello.txt", &FileMeta::regular(0, 0, 0), Some(&csum(LINK)))
            .await
            .unwrap(),
        csum(LINK),
        "link identity"
    );
}

/// Returns the on-disk bytes of a loose object in the repository at `root`.
fn object_bytes(root: &Path, hex: &str, ty: ObjectType, mode: RepoMode) -> Vec<u8> {
    std::fs::read(root.join("objects").join(loose_path(&csum(hex), ty, mode))).unwrap()
}

/// Returns the bytes of a loose object in the checked-in fixture repository.
fn fixture_bytes(mode_dir: &str, hex: &str, ty: ObjectType, mode: RepoMode) -> Vec<u8> {
    std::fs::read(
        fixture_repo(mode_dir)
            .join("objects")
            .join(loose_path(&csum(hex), ty, mode)),
    )
    .unwrap()
}

/// Returns the `user.ostreemeta` xattr of a loose object.
fn ostreemeta(root: &Path, hex: &str, mode: RepoMode) -> Vec<u8> {
    let path = root
        .join("objects")
        .join(loose_path(&csum(hex), ObjectType::File, mode));
    let mut buf = vec![0u8; 256];
    let n = rustix::fs::getxattr(&path, "user.ostreemeta", &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn inode_perm(root: &Path, hex: &str, ty: ObjectType, mode: RepoMode) -> u32 {
    let path = root.join("objects").join(loose_path(&csum(hex), ty, mode));
    let stat = rustix::fs::stat(&path).unwrap();
    stat.st_mode & 0o7777
}

#[test]
fn archive_objects_are_byte_identical_to_the_fixture() {
    let tmp = TmpDir::new("write-archive");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        write_fixture_tree(&txn).await;
        let stats = txn.commit().await.unwrap();
        assert_eq!(stats.content_written, 4);

        // Each stored `.filez` object (regular files and the symlink) is byte
        // for byte the same as the object that the `ostree` command wrote.
        for hex in [HELLO_TXT, EMPTY_TXT, NESTED_TXT, LINK] {
            assert_eq!(
                object_bytes(&root, hex, ObjectType::File, RepoMode::Archive),
                fixture_bytes("archive", hex, ObjectType::File, RepoMode::Archive),
                "archive object {hex}"
            );
            assert_eq!(
                inode_perm(&root, hex, ObjectType::File, RepoMode::Archive),
                0o644
            );
        }
    });
}

#[test]
fn bare_user_objects_match_the_fixture() {
    let tmp = TmpDir::new("write-bare-user");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        write_fixture_tree(&txn).await;
        txn.commit().await.unwrap();

        // Regular files: the raw payload is on disk, and the logical metadata
        // is in the xattr.
        for (hex, payload) in [(HELLO_TXT, HELLO), (EMPTY_TXT, EMPTY), (NESTED_TXT, NESTED)] {
            assert_eq!(
                object_bytes(&root, hex, ObjectType::File, RepoMode::BareUser),
                payload,
                "bare-user payload {hex}"
            );
            assert_eq!(
                ostreemeta(&root, hex, RepoMode::BareUser),
                fixture_ostreemeta("bare-user", hex),
                "bare-user user.ostreemeta {hex}"
            );
            assert_eq!(
                inode_perm(&root, hex, ObjectType::File, RepoMode::BareUser),
                0o644
            );
        }
        // bare-user stores the symlink as a regular file: the target and then
        // a NUL.
        assert_eq!(
            object_bytes(&root, LINK, ObjectType::File, RepoMode::BareUser),
            b"hello.txt\0"
        );
        assert_eq!(
            ostreemeta(&root, LINK, RepoMode::BareUser),
            fixture_ostreemeta("bare-user", LINK),
        );
    });
}

/// Returns the `user.ostreemeta` xattr of a fixture object.
fn fixture_ostreemeta(mode_dir: &str, hex: &str) -> Vec<u8> {
    let path = fixture_repo(mode_dir).join("objects").join(loose_path(
        &csum(hex),
        ObjectType::File,
        RepoMode::BareUser,
    ));
    let mut buf = vec![0u8; 256];
    let n = rustix::fs::getxattr(&path, "user.ostreemeta", &mut buf).unwrap();
    buf.truncate(n);
    buf
}

#[test]
fn bare_user_shared_shares_bare_user_identity_with_fixed_mode() {
    let tmp = TmpDir::new("write-shared");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUserShared))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        // The checksums are the same as in bare-user (`write_fixture_tree`
        // asserts them).
        write_fixture_tree(&txn).await;
        txn.commit().await.unwrap();

        // The payload and `user.ostreemeta` are byte for byte the same as in
        // bare-user. The inode mode is always 0644, for each logical mode.
        for (hex, payload) in [(HELLO_TXT, HELLO), (NESTED_TXT, NESTED)] {
            assert_eq!(
                object_bytes(&root, hex, ObjectType::File, RepoMode::BareUserShared),
                payload
            );
            assert_eq!(
                ostreemeta(&root, hex, RepoMode::BareUserShared),
                fixture_ostreemeta("bare-user", hex),
            );
            assert_eq!(
                inode_perm(&root, hex, ObjectType::File, RepoMode::BareUserShared),
                0o644
            );
        }
    });
}

#[test]
fn write_metadata_stages_a_metadata_object() {
    let tmp = TmpDir::new("write-meta");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        // A directory metadata object: uid 0, gid 0, mode 040755, no xattrs.
        let dirmeta = ostrya_core::DirMeta {
            uid: 0,
            gid: 0,
            mode: 0o040755,
            xattrs: ostrya_core::Xattrs::empty(),
        };
        let bytes = dirmeta.serialize().unwrap();
        let expected = Checksum::sha256(&bytes);

        let txn = repo.transaction().await.unwrap();
        let c = txn
            .write_metadata(ObjectType::DirMeta, Some(&expected), &bytes)
            .await
            .unwrap();
        assert_eq!(
            c, expected,
            "identity is the sha256 of the normal-form bytes"
        );
        let stats = txn.commit().await.unwrap();
        assert_eq!(stats.metadata_written, 1);
        assert_eq!(stats.content_written, 0);

        // The staged object is at its loose path, with the fixed inode mode
        // 0644 and the same bytes. The repository reads it back.
        assert_eq!(
            object_bytes(&root, &c.to_hex(), ObjectType::DirMeta, RepoMode::BareUser),
            bytes
        );
        assert_eq!(
            inode_perm(&root, &c.to_hex(), ObjectType::DirMeta, RepoMode::BareUser),
            0o644
        );
        let repo = Repo::open(&root).await.unwrap();
        assert_eq!(repo.load_dirmeta(&c).await.unwrap(), dirmeta);
    });
}

#[test]
fn write_metadata_rejects_bare_split_xattrs() {
    let tmp = TmpDir::new("write-meta-split");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareSplitXattrs))
            .await
            .unwrap();
        let dirmeta = ostrya_core::DirMeta {
            uid: 0,
            gid: 0,
            mode: 0o040755,
            xattrs: ostrya_core::Xattrs::empty(),
        };
        let bytes = dirmeta.serialize().unwrap();
        let txn = repo.transaction().await.unwrap();
        // All writers treat bare-split-xattrs as read-only. The content,
        // symlink, and metadata writers refuse the mode.
        let err = txn
            .write_metadata(ObjectType::DirMeta, None, &bytes)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "bare-split-xattrs is read-only, got {err:?}"
        );
        txn.abort().await.unwrap();
    });
}

#[test]
fn bare_content_applies_inode_xattrs() {
    let tmp = TmpDir::new("write-bare-xattr");
    // Bare writes the logical ownership to the inode, so the test uses ids
    // that the process owns. It sets only `user.*` names. A process without
    // privileges can apply both.
    let owned = rustix::fs::stat(tmp.path()).unwrap();
    let uid = owned.st_uid;
    let gid = owned.st_gid;
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        // Stored names end in a NUL. The writer removes the NUL before the
        // `setxattr` syscall.
        let xattrs = ostrya_core::Xattrs::new([
            (b"user.one\0".to_vec(), b"first".to_vec()),
            (b"user.two\0".to_vec(), b"second".to_vec()),
        ])
        .unwrap();
        let mut meta = FileMeta::regular(uid, gid, 0o644);
        meta.xattrs = xattrs;
        let checksum = txn.write_regfile_inline(None, &meta, HELLO).await.unwrap();
        txn.commit().await.unwrap();

        // Bare stores the raw payload and puts the logical xattrs on the inode.
        let hex = checksum.to_hex();
        assert_eq!(
            object_bytes(&root, &hex, ObjectType::File, RepoMode::Bare),
            HELLO
        );
        assert_eq!(inode_xattr(&root, &hex, "user.one"), b"first");
        assert_eq!(inode_xattr(&root, &hex, "user.two"), b"second");
    });
}

/// Returns the value of a named xattr on the inode of a bare loose object.
fn inode_xattr(root: &Path, hex: &str, name: &str) -> Vec<u8> {
    let path = root
        .join("objects")
        .join(loose_path(&csum(hex), ObjectType::File, RepoMode::Bare));
    let mut buf = vec![0u8; 256];
    let n = rustix::fs::getxattr(&path, name, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

#[test]
fn rewriting_an_object_is_a_dedup_noop() {
    let tmp = TmpDir::new("write-dedup");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let a = txn.write_regfile_inline(None, &reg(), HELLO).await.unwrap();
        let b = txn.write_regfile_inline(None, &reg(), HELLO).await.unwrap();
        assert_eq!(a, b, "same content, same identity");
        let stats: TransactionStats = txn.commit().await.unwrap();
        assert_eq!(
            stats.content_written, 1,
            "the second write is a dedup no-op"
        );

        // A new transaction finds the object in `objects/` and does not write
        // it again (dedup).
        let txn = repo.transaction().await.unwrap();
        assert_eq!(
            txn.write_regfile_inline(None, &reg(), HELLO).await.unwrap(),
            a
        );
        let stats = txn.commit().await.unwrap();
        assert_eq!(
            stats.content_written, 0,
            "already published, so no new object"
        );
    });
}

#[test]
fn free_space_guard_trips_on_an_exhausted_budget() {
    let tmp = TmpDir::new("write-space");
    let root = tmp.path().join("repo");
    block_on(async {
        Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        // A reservation of 100% of the file system gives a write budget of 0.
        let config = root.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("min-free-space-percent=100\n");
        std::fs::write(&config, text).unwrap();
        let repo = Repo::open(&root).await.unwrap();

        let txn = repo.transaction().await.unwrap();
        let err = txn
            .write_regfile_inline(None, &reg(), HELLO)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::InsufficientFreeSpace { shortfall } if shortfall > 0),
            "expected a free-space error, got {err:?}"
        );
        txn.abort().await.unwrap();
    });
}

/// Checks that each write path refuses a `[core] fsync` value that the reader
/// does not accept.
///
/// The test runs with no [`Transaction::set_fsync`] override and with an
/// override of each polarity. An override replaces the configured policy. The
/// reader parses the configured value in all cases, so the bad value stops the
/// write.
#[test]
fn a_bad_configured_fsync_is_refused_under_every_override() {
    let tmp = TmpDir::new("write-fsync-bad-config");
    let root = tmp.path().join("repo");
    block_on(async {
        Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let config = root.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("fsync=bogus\n");
        std::fs::write(&config, text).unwrap();
        let repo = Repo::open(&root).await.unwrap();

        for override_value in [None, Some(true), Some(false)] {
            let mut txn = repo.transaction().await.unwrap();
            if let Some(enabled) = override_value {
                txn.set_fsync(enabled);
            }
            let err = txn
                .write_regfile_inline(None, &reg(), HELLO)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    &err,
                    Error::Core(ostrya_core::Error::KeyFile(text))
                        if text.contains("core.fsync")
                ),
                "override {override_value:?} gave {err:?} in place of the config refusal",
            );
            txn.abort().await.unwrap();
        }
    });
}

/// Checks that each write path refuses a `[core] per-object-fsync` value that
/// the reader does not accept.
///
/// The test runs with no [`Transaction::set_per_object_fsync`] override, with
/// an override of each polarity, and with fsync turned off by
/// [`Transaction::set_fsync`]. An override replaces the configured setting. The
/// reader parses the configured value in all cases, so the bad value stops the
/// write.
#[test]
fn a_bad_configured_per_object_fsync_is_refused_under_every_override() {
    let tmp = TmpDir::new("write-per-object-fsync-bad-config");
    let root = tmp.path().join("repo");
    block_on(async {
        Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let config = root.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("per-object-fsync=bogus\n");
        std::fs::write(&config, text).unwrap();
        let repo = Repo::open(&root).await.unwrap();

        // (per-object override, fsync override)
        let rows = [
            (None, None),
            (Some(true), None),
            (Some(false), None),
            (None, Some(false)),
            (Some(true), Some(false)),
        ];
        for (per_object, fsync) in rows {
            let mut txn = repo.transaction().await.unwrap();
            if let Some(enabled) = per_object {
                txn.set_per_object_fsync(enabled);
            }
            if let Some(enabled) = fsync {
                txn.set_fsync(enabled);
            }
            let err = txn
                .write_regfile_inline(None, &reg(), HELLO)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    &err,
                    Error::Core(ostrya_core::Error::KeyFile(text))
                        if text.contains("core.per-object-fsync")
                ),
                "overrides {per_object:?}/{fsync:?} gave {err:?} in place of the config refusal",
            );
            txn.abort().await.unwrap();
        }
    });
}

#[test]
fn concurrent_writers_share_one_transaction() {
    let tmp = TmpDir::new("write-concurrent");
    let root = tmp.path().join("repo");
    let repo = block_on(Repo::create(&root, CreateOptions::new(RepoMode::BareUser))).unwrap();
    let txn = block_on(repo.transaction()).unwrap();

    const N: usize = 8;
    let payloads: Vec<Vec<u8>> = (0..N)
        .map(|i| format!("payload number {i}\n").into_bytes())
        .collect();

    std::thread::scope(|scope| {
        for payload in &payloads {
            let txn = &txn;
            scope.spawn(move || {
                block_on(async {
                    txn.write_content(None, &reg(), Cursor::new(payload.clone()))
                        .await
                        .unwrap();
                });
            });
        }
    });

    let stats = block_on(txn.commit()).unwrap();
    assert_eq!(
        stats.content_written as usize, N,
        "each writer staged one object"
    );

    // Every object is present and reads back to its payload.
    block_on(async {
        let repo = Repo::open(&root).await.unwrap();
        for payload in &payloads {
            let checksum = object_checksum_of(&repo, &reg(), payload).await;
            let file = repo.load_file(&checksum).await.unwrap();
            let mut got = Vec::new();
            file.reader()
                .await
                .unwrap()
                .read_to_end(&mut got)
                .await
                .unwrap();
            assert_eq!(&got, payload);
        }
    });
}

/// Returns the checksum of a payload.
///
/// The function writes the payload in a temporary transaction and then aborts
/// that transaction.
async fn object_checksum_of(repo: &Repo, meta: &FileMeta, payload: &[u8]) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let c = txn.write_regfile_inline(None, meta, payload).await.unwrap();
    txn.abort().await.unwrap();
    c
}

#[test]
fn content_reads_back_through_load_file() {
    let tmp = TmpDir::new("write-roundtrip");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        write_fixture_tree(&txn).await;
        txn.commit().await.unwrap();

        let repo = Repo::open(&root).await.unwrap();
        let hello = repo.load_file(&csum(HELLO_TXT)).await.unwrap();
        assert_eq!(
            hello.kind,
            FileKind::Regular {
                size: HELLO.len() as u64
            }
        );
        assert_eq!((hello.uid, hello.gid, hello.mode), (0, 0, 0o100644));
        let mut got = Vec::new();
        hello
            .reader()
            .await
            .unwrap()
            .read_to_end(&mut got)
            .await
            .unwrap();
        assert_eq!(got, HELLO);

        let link = repo.load_file(&csum(LINK)).await.unwrap();
        assert_eq!(
            link.kind,
            FileKind::Symlink {
                target: "hello.txt".to_owned()
            }
        );
    });
}

#[test]
fn a_read_only_mode_is_stored_in_bare_user() {
    // A logical mode with no owner-write bit is usual in a system tree, for
    // example 0444. bare-user can store such a mode. In bare-user the logical
    // metadata is in a `user.ostreemeta` xattr. The kernel checks this xattr
    // against the write permission of the inode. The test uses both content
    // writers, because each writer stages its own temporary file before it
    // applies the inode policy.
    let tmp = TmpDir::new("write-readonly");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let meta = FileMeta::regular(0, 0, 0o444);
        let inline = txn.write_regfile_inline(None, &meta, HELLO).await.unwrap();
        let streamed = txn
            .write_content(None, &meta, Cursor::new(NESTED.to_vec()))
            .await
            .unwrap();
        txn.commit().await.unwrap();

        for checksum in [inline, streamed] {
            // In bare-user the canonical inode mode of a 0444 file is 0444. The
            // logical mode reads back from the xattr.
            let path = root.join("objects").join(loose_path(
                &checksum,
                ObjectType::File,
                RepoMode::BareUser,
            ));
            let stored = rustix::fs::stat(&path).unwrap();
            assert_eq!(stored.st_mode & 0o7777, 0o444, "stored mode of {checksum}");
            let file = repo.load_file(&checksum).await.unwrap();
            assert_eq!((file.uid, file.gid, file.mode), (0, 0, 0o100444));
        }
    });
}

#[test]
fn a_read_only_mode_with_an_xattr_is_stored_in_bare() {
    // Bare puts the logical xattrs of a content object on the inode. The
    // kernel checks a `user.*` name against the write permission of the inode.
    // Bare can store a logical mode with no owner-write bit together with such
    // an xattr. The test uses both content writers, because each writer stages
    // its own temporary file before it applies the inode policy.
    let tmp = TmpDir::new("write-bare-readonly");
    // Bare writes the logical ownership to the inode, so the test uses ids
    // that the process owns. It sets only `user.*` names. A process without
    // privileges can apply both.
    let owned = rustix::fs::stat(tmp.path()).unwrap();
    let uid = owned.st_uid;
    let gid = owned.st_gid;
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let mut meta = FileMeta::regular(uid, gid, 0o444);
        meta.xattrs =
            ostrya_core::Xattrs::new([(b"user.demo\0".to_vec(), b"value".to_vec())]).unwrap();
        let inline = txn.write_regfile_inline(None, &meta, HELLO).await.unwrap();
        let streamed = txn
            .write_content(None, &meta, Cursor::new(NESTED.to_vec()))
            .await
            .unwrap();
        txn.commit().await.unwrap();

        for checksum in [inline, streamed] {
            let hex = checksum.to_hex();
            assert_eq!(inode_xattr(&root, &hex, "user.demo"), b"value");
            let file = repo.load_file(&checksum).await.unwrap();
            assert_eq!((file.uid, file.gid, file.mode), (uid, gid, 0o100444));
        }
    });
}

#[test]
fn bare_objects_match_the_tool() {
    if !ostree_available() {
        eprintln!("skipping bare_objects_match_the_tool: the ostree tool is unavailable");
        return;
    }
    // Bare stores the logical ownership on the inode, so a faithful write
    // needs ids that the process can apply. The test takes them from a
    // directory that this process owns. ostrya and the `ostree` command then
    // use the same ids, so their objects match.
    let tmp = TmpDir::new("write-bare");
    let owned = rustix::fs::stat(tmp.path()).unwrap();
    let uid = owned.st_uid;
    let gid = owned.st_gid;

    // Build a bare repository with ostrya, with that ownership.
    let port_root = tmp.path().join("port");
    block_on(async {
        let repo = Repo::create(&port_root, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let meta = FileMeta::regular(uid, gid, 0o644);
        txn.write_regfile_inline(None, &meta, HELLO).await.unwrap();
        txn.write_regfile_inline(None, &meta, NESTED).await.unwrap();
        txn.write_regfile_inline(None, &meta, EMPTY).await.unwrap();
        txn.write_symlink("hello.txt", &FileMeta::regular(uid, gid, 0), None)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    });

    // Build the same tree with the `ostree` command in a bare repository.
    let tool_root = tmp.path().join("tool");
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), HELLO).unwrap();
    std::fs::write(src.join("nested.txt"), NESTED).unwrap();
    std::fs::write(src.join("empty.txt"), EMPTY).unwrap();
    std::os::unix::fs::symlink("hello.txt", src.join("link")).unwrap();
    for f in ["hello.txt", "nested.txt", "empty.txt"] {
        std::fs::set_permissions(
            src.join(f),
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();
    }
    let repo_arg = format!("--repo={}", tool_root.display());
    run_ostree(&[&repo_arg, "init", "--mode=bare"]);
    run_ostree(&[
        &repo_arg,
        "commit",
        "--branch=t",
        "--subject=x",
        &format!("--owner-uid={uid}"),
        &format!("--owner-gid={gid}"),
        "--no-xattrs",
        "--timestamp=@1700000000",
        src.to_str().unwrap(),
    ]);

    // Each content object that the `ostree` command wrote is in the ostrya
    // repository, with the same bytes, inode mode, and ownership. The ostrya
    // side writes only content objects, so the test does not compare the tree
    // and commit metadata objects of the `ostree` command.
    for entry in walk_objects(&tool_root.join("objects")) {
        if entry.extension().and_then(|e| e.to_str()) != Some("file") {
            continue;
        }
        let rel = entry.strip_prefix(tool_root.join("objects")).unwrap();
        let ours = port_root.join("objects").join(rel);
        // The test uses `symlink_metadata`. The relative target of a symlink
        // object does not resolve inside `objects/`. `exists()` follows the
        // link, so it returns `false`.
        let our_meta = std::fs::symlink_metadata(&ours)
            .unwrap_or_else(|_| panic!("port is missing object {rel:?}"));
        let tool_meta = std::fs::symlink_metadata(&entry).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(tool_meta.mode(), our_meta.mode(), "mode of {rel:?}");
        assert_eq!(tool_meta.uid(), our_meta.uid(), "uid of {rel:?}");
        assert_eq!(tool_meta.gid(), our_meta.gid(), "gid of {rel:?}");
        if tool_meta.file_type().is_symlink() {
            assert_eq!(
                std::fs::read_link(&entry).unwrap(),
                std::fs::read_link(&ours).unwrap(),
                "symlink target of {rel:?}"
            );
        } else {
            assert_eq!(
                std::fs::read(&entry).unwrap(),
                std::fs::read(&ours).unwrap(),
                "content of {rel:?}"
            );
        }
    }
}

#[test]
fn bare_user_only_hashes_the_canonical_header() {
    // bare-user-only stores no ownership and no xattrs. It reduces the
    // permission bits of a regular file to `perm & 0o755`. The checksum of an
    // object covers that reduced header, so the name of the object matches
    // what the mode stores. As a result, the object reads back as named and
    // passes fsck.
    //
    // The checksum is equal to the checksum of the same canonical entry in
    // each other mode. The test compares against that checksum. The test
    // `commit::bare_user_only_commit_matches_the_tool` pins this behavior to
    // the `ostree` command.
    let tmp = TmpDir::new("write-buo-canon");
    let buo_root = tmp.path().join("buo");
    let bu_root = tmp.path().join("bu");
    block_on(async {
        // A non-canonical entry: ids that the mode discards, a mode with the
        // group-write and other-write bits set, and one xattr.
        let mut meta = FileMeta::regular(4242, 4242, 0o777);
        meta.xattrs =
            ostrya_core::Xattrs::new([(b"user.demo\0".to_vec(), b"value".to_vec())]).unwrap();

        let repo = Repo::create(&buo_root, CreateOptions::new(RepoMode::BareUserOnly))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let inline = txn.write_regfile_inline(None, &meta, HELLO).await.unwrap();
        let streamed = txn
            .write_content(None, &meta, Cursor::new(NESTED.to_vec()))
            .await
            .unwrap();
        let link = txn.write_symlink("hello.txt", &meta, None).await.unwrap();
        txn.commit().await.unwrap();

        // The checksum of the canonical form of each entry, from bare-user. This
        // mode stores the header that the writer gets.
        let canon = FileMeta::regular(0, 0, 0o755);
        let bu = Repo::create(&bu_root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = bu.transaction().await.unwrap();
        let canon_inline = txn.write_regfile_inline(None, &canon, HELLO).await.unwrap();
        let canon_streamed = txn
            .write_content(None, &canon, Cursor::new(NESTED.to_vec()))
            .await
            .unwrap();
        let canon_link = txn.write_symlink("hello.txt", &canon, None).await.unwrap();
        txn.commit().await.unwrap();

        assert_eq!(inline, canon_inline, "inline regular-file identity");
        assert_eq!(streamed, canon_streamed, "streamed regular-file identity");
        assert_eq!(link, canon_link, "symlink identity");

        // Each object reads back with the header that its checksum covers.
        for checksum in [inline, streamed] {
            let file = repo.load_file(&checksum).await.unwrap();
            assert_eq!((file.uid, file.gid, file.mode), (0, 0, 0o100755));
            assert!(file.xattrs.is_empty(), "xattrs of {checksum}");
        }
        let file = repo.load_file(&link).await.unwrap();
        assert_eq!((file.uid, file.gid), (0, 0));

        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert!(report.is_ok(), "fsck reported {:?}", report.errors);
    });
}

/// Returns the bytes and the checksum of a dirmeta object of mode `mode`.
fn dirmeta_object(mode: u32) -> (Vec<u8>, Checksum) {
    let bytes = ostrya_core::DirMeta {
        uid: 0,
        gid: 0,
        mode,
        xattrs: ostrya_core::Xattrs::empty(),
    }
    .serialize()
    .unwrap();
    let checksum = Checksum::sha256(&bytes);
    (bytes, checksum)
}

/// Returns the message of `result`, which must be [`Error::InvalidFormat`].
fn invalid_format<T: std::fmt::Debug>(result: ostrya::Result<T>) -> String {
    match result {
        Err(Error::InvalidFormat(m)) => m,
        other => panic!("{other:?}"),
    }
}

/// Returns the text of the refusal of a symlink at the path `path`.
fn symlink_refusal(path: &str) -> String {
    format!("{path} passes through a symlink; ostrya refuses a symlink in the repository")
}

/// Moves the fan-out directory of the loose path `object` below `root/objects`
/// to `moved`, and puts a symlink to the empty directory `target` there.
fn symlink_fanout(root: &Path, object: &str, moved: &Path, target: &Path) {
    let fanout = root.join("objects").join(&object[..2]);
    std::fs::rename(&fanout, moved).unwrap();
    std::fs::create_dir(target).unwrap();
    std::os::unix::fs::symlink(target, &fanout).unwrap();
}

/// A symlink at `objects/<xx>` fails a write of an object below it with
/// `InvalidFormat` and the object path. The target of the symlink gets no
/// file.
#[test]
fn a_symlink_at_a_fanout_fails_a_write_below_it() {
    let tmp = TmpDir::new("write-fanout-symlink");
    let root = tmp.path().join("repo");
    let mode = RepoMode::BareUser;
    let (bytes, dirmeta) = dirmeta_object(0o040755);
    let file_path = loose_path(&csum(HELLO_TXT), ObjectType::File, mode);
    let meta_path = loose_path(&dirmeta, ObjectType::DirMeta, mode);
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(mode)).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        txn.write_regfile_inline(None, &reg(), HELLO).await.unwrap();
        txn.write_metadata(ObjectType::DirMeta, None, &bytes)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    });
    let targets = [
        tmp.path().join("file-target"),
        tmp.path().join("meta-target"),
    ];
    symlink_fanout(
        &root,
        &file_path,
        &tmp.path().join("file-moved"),
        &targets[0],
    );
    if meta_path[..2] != file_path[..2] {
        symlink_fanout(
            &root,
            &meta_path,
            &tmp.path().join("meta-moved"),
            &targets[1],
        );
    }

    let (file, meta) = block_on(async {
        let repo = Repo::open(&root).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let file = txn.write_regfile_inline(None, &reg(), HELLO).await;
        let meta = txn.write_metadata(ObjectType::DirMeta, None, &bytes).await;
        txn.abort().await.unwrap();
        (file, meta)
    });
    assert_eq!(
        invalid_format(file),
        symlink_refusal(&format!("objects/{file_path}"))
    );
    assert_eq!(
        invalid_format(meta),
        symlink_refusal(&format!("objects/{meta_path}"))
    );
    for target in targets.iter().filter(|t| t.exists()) {
        assert_eq!(std::fs::read_dir(target).unwrap().count(), 0, "{target:?}");
    }
}

/// The publish of a commit refuses a symlink at `objects/<xx>` that appears
/// after the stage, and an entry there that is not a directory. The target of
/// the symlink gets no file.
#[test]
fn the_publish_refuses_a_fanout_that_is_not_a_directory() {
    let mode = RepoMode::BareUser;
    let fanout = &loose_path(&csum(HELLO_TXT), ObjectType::File, mode)[..2];
    for symlink in [true, false] {
        let tmp = TmpDir::new("write-publish-fanout");
        let root = tmp.path().join("repo");
        let target = tmp.path().join("target");
        let result = block_on(async {
            let repo = Repo::create(&root, CreateOptions::new(mode)).await.unwrap();
            let txn = repo.transaction().await.unwrap();
            txn.write_regfile_inline(None, &reg(), HELLO).await.unwrap();
            let at = root.join("objects").join(fanout);
            if symlink {
                std::fs::create_dir(&target).unwrap();
                std::os::unix::fs::symlink(&target, &at).unwrap();
            } else {
                std::fs::write(&at, b"").unwrap();
            }
            txn.commit().await
        });
        let expected = if symlink {
            symlink_refusal(&format!("objects/{fanout}"))
        } else {
            format!("objects/{fanout} is not a directory")
        };
        assert_eq!(invalid_format(result), expected);
        if symlink {
            assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
        }
    }
}

/// The publish of a commit makes again a fan-out directory that was removed
/// after the stage, and moves the object into it.
#[test]
fn the_publish_makes_a_missing_fanout_again() {
    let tmp = TmpDir::new("write-publish-missing-fanout");
    let root = tmp.path().join("repo");
    let mode = RepoMode::BareUser;
    let path = loose_path(&csum(HELLO_TXT), ObjectType::File, mode);
    let fanout = root.join("objects").join(&path[..2]);
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(mode)).await.unwrap();
        let first = repo.transaction().await.unwrap();
        first
            .write_regfile_inline(None, &reg(), HELLO)
            .await
            .unwrap();
        first.commit().await.unwrap();
        std::fs::remove_dir_all(&fanout).unwrap();
        let second = repo.transaction().await.unwrap();
        second
            .write_regfile_inline(None, &reg(), HELLO)
            .await
            .unwrap();
        assert!(!fanout.exists(), "the stage makes no fan-out directory");
        second.commit().await.unwrap();
    });
    assert!(std::fs::symlink_metadata(&fanout).unwrap().is_dir());
    assert_eq!(
        std::fs::read(root.join("objects").join(&path)).unwrap(),
        HELLO
    );
}

/// Two transactions stage the same object. The first commit publishes it,
/// and the second commit keeps the published inode. Both commits succeed.
#[test]
fn a_second_publish_of_an_object_keeps_the_first_inode() {
    use std::os::unix::fs::MetadataExt;

    let tmp = TmpDir::new("write-keep-published");
    let root = tmp.path().join("repo");
    let mode = RepoMode::BareUser;
    let object = root
        .join("objects")
        .join(loose_path(&csum(HELLO_TXT), ObjectType::File, mode));
    let (first, second) = block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(mode)).await.unwrap();
        let one = repo.transaction().await.unwrap();
        let two = repo.transaction().await.unwrap();
        one.write_regfile_inline(None, &reg(), HELLO).await.unwrap();
        two.write_regfile_inline(None, &reg(), HELLO).await.unwrap();
        one.commit().await.unwrap();
        let first = std::fs::symlink_metadata(&object).unwrap().ino();
        two.commit().await.unwrap();
        let second = std::fs::symlink_metadata(&object).unwrap().ino();
        (first, second)
    });
    assert_eq!(first, second, "the second publish keeps the first inode");
    assert_eq!(std::fs::read(&object).unwrap().len(), HELLO.len());
}

/// Returns the name and the inode number of each entry of each staging
/// directory of the repository at `root`, sorted by name.
fn staged_entries(root: &Path) -> Vec<(String, u64)> {
    use std::os::unix::fs::MetadataExt;

    let mut entries = Vec::new();
    for entry in std::fs::read_dir(root.join("tmp")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with("staging-")
            && entry.file_type().unwrap().is_dir()
        {
            for staged in std::fs::read_dir(entry.path()).unwrap() {
                let staged = staged.unwrap();
                let ino = std::fs::symlink_metadata(staged.path()).unwrap().ino();
                entries.push((staged.file_name().to_string_lossy().into_owned(), ino));
            }
        }
    }
    entries.sort();
    entries
}

/// One transaction writes the same metadata object and the same `bare`
/// symlink object two times. The staging directory holds one entry of each
/// and no temp file. The second write keeps the inode of each entry that the
/// first write staged. The published symlink has the owner of the header.
#[test]
fn a_second_stage_of_an_object_keeps_the_staged_entry() {
    use std::os::unix::fs::MetadataExt;

    let tmp = TmpDir::new("write-keep-staged");
    let root = tmp.path().join("repo");
    let mode = RepoMode::Bare;
    let (bytes, dirmeta) = dirmeta_object(0o040700);
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let meta = FileMeta::regular(uid, gid, 0o777);
    let (staged, link) = block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(mode)).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let mut link = None;
        let mut staged = Vec::new();
        for _ in 0..2 {
            txn.write_metadata(ObjectType::DirMeta, None, &bytes)
                .await
                .unwrap();
            link = Some(txn.write_symlink("target", &meta, None).await.unwrap());
            staged.push(staged_entries(&root));
        }
        txn.commit().await.unwrap();
        (staged, link.unwrap())
    });
    let mut expected = vec![
        format!("{}.dirmeta", dirmeta.to_hex()),
        format!("{}.file", link.to_hex()),
    ];
    expected.sort();
    let names: Vec<String> = staged[0].iter().map(|(name, _)| name.clone()).collect();
    assert_eq!(names, expected);
    assert_eq!(
        staged[1], staged[0],
        "the second write keeps each staged inode"
    );

    let published = root
        .join("objects")
        .join(loose_path(&link, ObjectType::File, mode));
    let stat = std::fs::symlink_metadata(&published).unwrap();
    assert!(stat.file_type().is_symlink());
    assert_eq!((stat.uid(), stat.gid()), (uid, gid));
    assert_eq!(std::fs::read_link(&published).unwrap(), Path::new("target"));
}

fn run_ostree(args: &[&str]) {
    let status = Command::new("ostree")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run ostree");
    assert!(status.success(), "ostree {args:?} failed");
}

/// Returns each regular file and symlink under an `objects/` directory.
fn walk_objects(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for fanout in std::fs::read_dir(dir).unwrap().flatten() {
        if fanout.file_type().unwrap().is_dir() {
            for obj in std::fs::read_dir(fanout.path()).unwrap().flatten() {
                out.push(obj.path());
            }
        }
    }
    out
}
