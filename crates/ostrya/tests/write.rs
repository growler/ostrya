//! Write-path integration tests (Phase 7a).
//!
//! These exercise the object-store write layer against real repositories:
//! byte-identical loose objects versus the checked-in fixtures for archive and
//! bare-user (plus the bare-user-shared derivation), a tool cross-check for
//! bare, the dedup no-op, the free-space guard, concurrent writers on one
//! `&Transaction`, and read-back through `load_file`.

mod common;

use std::path::Path;
use std::process::Command;

use common::{TmpDir, fixture_repo, ostree_available};
use futures_lite::AsyncReadExt;
use futures_lite::io::Cursor;
use ostrya::{
    Checksum, CreateOptions, Error, FileKind, FileMeta, Repo, RepoMode, Transaction,
    TransactionStats,
};
use ostrya_core::{ObjectType, loose_path};
use ostrya_rt::block_on;

// The fixture tree the golden repositories were built from (owner 0:0, 0644),
// and the object checksums the `ostree` tool assigned it.
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

/// A regular-file FileMeta owned 0:0 at mode 0644, as in the fixtures.
fn reg() -> FileMeta {
    FileMeta::regular(0, 0, 0o644)
}

/// Write the four fixture content objects through the port into `txn`,
/// exercising the inline, streaming, and symlink writers. Asserts each computed
/// identity equals the tool's fixture checksum.
async fn write_fixture_tree(txn: &Transaction) {
    assert_eq!(
        txn.write_regfile_inline(Some(&csum(HELLO_TXT)), &reg(), HELLO)
            .await
            .unwrap(),
        csum(HELLO_TXT),
        "hello.txt identity"
    );
    // The streaming path must agree with the inline path.
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

/// The on-disk bytes of a loose object in a repository rooted at `root`.
fn object_bytes(root: &Path, hex: &str, ty: ObjectType, mode: RepoMode) -> Vec<u8> {
    std::fs::read(root.join("objects").join(loose_path(&csum(hex), ty, mode))).unwrap()
}

/// The bytes of a loose object in the checked-in fixture repository for `mode`.
fn fixture_bytes(mode_dir: &str, hex: &str, ty: ObjectType, mode: RepoMode) -> Vec<u8> {
    std::fs::read(
        fixture_repo(mode_dir)
            .join("objects")
            .join(loose_path(&csum(hex), ty, mode)),
    )
    .unwrap()
}

/// The `user.ostreemeta` xattr of a loose object.
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

        // Every stored `.filez` (regular files and the symlink) is byte-for-byte
        // what the tool wrote.
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

        // Regular files: raw payload on disk, logical metadata in the xattr.
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
        // The symlink is stored as a regular file: target plus a NUL.
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

/// The `user.ostreemeta` of a fixture object.
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
        // Identity is unchanged from bare-user (asserted inside write_fixture_tree).
        write_fixture_tree(&txn).await;
        txn.commit().await.unwrap();

        // Payload and user.ostreemeta match bare-user byte-for-byte; the inode
        // is the fixed 0644 regardless of the logical mode.
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
        // A directory metadata object: uid/gid 0, mode 040755, no xattrs.
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

        // The staged object lands at its loose path with the fixed 0644 inode
        // mode and byte-identical content, and reads back through the repo.
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
        // The write surface holds the read-only stance for bare-split-xattrs
        // uniformly: content, symlinks, and metadata all refuse the mode.
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
    // Bare writes logical ownership to the inode, so use ids the process owns
    // and set only `user.*` names, both applicable unprivileged.
    let owned = rustix::fs::stat(tmp.path()).unwrap();
    let uid = owned.st_uid;
    let gid = owned.st_gid;
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        // Stored names are NUL-terminated; the write path strips the NUL before
        // the setxattr syscall.
        let xattrs = ostrya_core::Xattrs::new([
            (b"user.one\0".to_vec(), b"first".to_vec()),
            (b"user.two\0".to_vec(), b"second".to_vec()),
        ])
        .unwrap();
        let mut meta = FileMeta::regular(uid, gid, 0o644);
        meta.xattrs = xattrs;
        let checksum = txn.write_regfile_inline(None, &meta, HELLO).await.unwrap();
        txn.commit().await.unwrap();

        // Bare stores the payload raw and carries the logical xattrs on the
        // inode itself.
        let hex = checksum.to_hex();
        assert_eq!(
            object_bytes(&root, &hex, ObjectType::File, RepoMode::Bare),
            HELLO
        );
        assert_eq!(inode_xattr(&root, &hex, "user.one"), b"first");
        assert_eq!(inode_xattr(&root, &hex, "user.two"), b"second");
    });
}

/// The value of a named xattr set directly on a bare loose object's inode.
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

        // A fresh transaction sees the object already in objects/ and dedups.
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
        // Reserving 100% of the filesystem leaves a zero write budget.
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

/// The identity a payload would get, obtained by writing it into a throwaway
/// transaction and rolling that transaction back.
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
    // A logical mode with no owner-write bit -- 0444 is ordinary in a system
    // tree -- is storable in bare-user, where the logical metadata lives in a
    // `user.ostreemeta` xattr the kernel checks against the inode's write
    // permission. Both content writers are exercised, since each stages its own
    // temp before the inode policy is applied.
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
            // bare-user's canonical inode mode for a 0444 file is 0444 itself,
            // and the logical mode reads back from the xattr.
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
fn bare_objects_match_the_tool() {
    if !ostree_available() {
        eprintln!("skipping bare_objects_match_the_tool: the ostree tool is unavailable");
        return;
    }
    // Bare stores logical ownership on the inode, so faithful writes need ids
    // the process may apply. Take them from a directory this process owns; the
    // port and the tool then both use those ids, so their objects match.
    let tmp = TmpDir::new("write-bare");
    let owned = rustix::fs::stat(tmp.path()).unwrap();
    let uid = owned.st_uid;
    let gid = owned.st_gid;

    // Build a bare repository with the port at that ownership.
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

    // Build the same tree with the tool into a bare repository.
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

    // Every content object the tool wrote is present in the port's repo with
    // identical bytes, inode mode, and ownership. Tree and commit metadata
    // objects arrive in Phases 7b-7d, so they are not compared here.
    for entry in walk_objects(&tool_root.join("objects")) {
        if entry.extension().and_then(|e| e.to_str()) != Some("file") {
            continue;
        }
        let rel = entry.strip_prefix(tool_root.join("objects")).unwrap();
        let ours = port_root.join("objects").join(rel);
        // symlink_metadata, not exists(): a symlink object's relative target
        // dangles inside objects/, so exists() (which follows it) is false.
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

fn run_ostree(args: &[&str]) {
    let status = Command::new("ostree")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run ostree");
    assert!(status.success(), "ostree {args:?} failed");
}

/// Every regular file and symlink under an `objects/` directory.
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
