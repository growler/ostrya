//! Reading-path tests for repository modes without checked-in fixtures.
//!
//! bare and bare-user-only need root or a tool to produce faithful ownership,
//! so there are no golden fixtures. These tests instead build real inodes for
//! the bare family directly, then read them back through the port.

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use common::TmpDir;
use futures_lite::AsyncReadExt;
use ostrya::{Checksum, CreateOptions, FileKind, Repo, RepoMode};
use ostrya_core::{ObjectType, loose_path};
use ostrya_rt::block_on;

fn csum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

async fn read_payload(file: &ostrya::FileObject) -> Vec<u8> {
    let mut reader = file.reader().await.expect("open reader");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.expect("read payload");
    buf
}

/// Absolute path of a loose object within a repository.
fn object_path(
    repo_root: &Path,
    checksum: &Checksum,
    ty: ObjectType,
    mode: RepoMode,
) -> std::path::PathBuf {
    let full = repo_root
        .join("objects")
        .join(loose_path(checksum, ty, mode));
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    full
}

#[test]
fn reads_bare_regular_symlink_and_xattrs() {
    block_on(async {
        let tmp = TmpDir::new("bare");
        let root = tmp.path().join("repo");
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::Bare))
            .await
            .expect("create bare repo");

        // A regular file object is a real inode; its metadata is the inode's.
        let reg = csum(&"aa".repeat(32));
        let reg_path = object_path(&root, &reg, ObjectType::File, RepoMode::Bare);
        fs::write(&reg_path, b"bare content\n").unwrap();
        fs::set_permissions(&reg_path, fs::Permissions::from_mode(0o644)).unwrap();
        // A user xattr, where the filesystem supports it, must round-trip.
        let xattr_ok = rustix::fs::setxattr(
            &reg_path,
            "user.demo",
            b"v",
            rustix::fs::XattrFlags::empty(),
        )
        .is_ok();
        let md = fs::metadata(&reg_path).unwrap();

        let file = repo.load_file(&reg).await.unwrap();
        assert_eq!(file.kind, FileKind::Regular { size: 13 });
        assert_eq!(file.uid, md.uid());
        assert_eq!(file.gid, md.gid());
        assert_eq!(file.mode, md.mode());
        assert_eq!(read_payload(&file).await, b"bare content\n");
        if xattr_ok {
            let names: Vec<&[u8]> = file.xattrs.iter().map(|(n, _)| n).collect();
            assert_eq!(names, [b"user.demo\0".as_slice()]);
        }

        // A symlink object is a real symlink.
        let link = csum(&"bb".repeat(32));
        let link_path = object_path(&root, &link, ObjectType::File, RepoMode::Bare);
        symlink("some/target", &link_path).unwrap();
        let file = repo.load_file(&link).await.unwrap();
        assert_eq!(
            file.kind,
            FileKind::Symlink {
                target: "some/target".to_owned()
            }
        );
        assert_eq!(read_payload(&file).await, b"");
    });
}

#[test]
fn reads_bare_user_only_discarding_ownership() {
    block_on(async {
        let tmp = TmpDir::new("buo");
        let root = tmp.path().join("repo");
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUserOnly))
            .await
            .expect("create bare-user-only repo");

        let reg = csum(&"cc".repeat(32));
        let reg_path = object_path(&root, &reg, ObjectType::File, RepoMode::BareUserOnly);
        fs::write(&reg_path, b"data").unwrap();
        fs::set_permissions(&reg_path, fs::Permissions::from_mode(0o644)).unwrap();

        let file = repo.load_file(&reg).await.unwrap();
        // uid/gid are discarded in this mode and read back as 0.
        assert_eq!((file.uid, file.gid), (0, 0));
        assert_eq!(file.mode, 0o100644);
        assert_eq!(file.kind, FileKind::Regular { size: 4 });
        assert!(file.xattrs.is_empty());
        assert_eq!(read_payload(&file).await, b"data");

        let link = csum(&"dd".repeat(32));
        let link_path = object_path(&root, &link, ObjectType::File, RepoMode::BareUserOnly);
        symlink("elsewhere", &link_path).unwrap();
        let file = repo.load_file(&link).await.unwrap();
        assert_eq!((file.uid, file.gid), (0, 0));
        assert_eq!(
            file.kind,
            FileKind::Symlink {
                target: "elsewhere".to_owned()
            }
        );
    });
}

#[test]
fn reads_bare_user_shared_like_bare_user() {
    block_on(async {
        let tmp = TmpDir::new("bus");
        let root = tmp.path().join("repo");
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUserShared))
            .await
            .expect("create bare-user-shared repo");

        // Storage is bare-user: raw payload on the inode, logical metadata in
        // `user.ostreemeta`. A restrictive logical mode (0600) is carried in
        // the xattr while the inode is a plain 0644 object.
        let reg = csum(&"11".repeat(32));
        let reg_path = object_path(&root, &reg, ObjectType::File, RepoMode::BareUserShared);
        fs::write(&reg_path, b"shared\n").unwrap();
        fs::set_permissions(&reg_path, fs::Permissions::from_mode(0o644)).unwrap();
        // The logical uid/gid/mode live in `user.ostreemeta` as the
        // `(uuua(ayay))` stat-metadata form: three big-endian u32s, then an
        // empty xattr array that adds no trailing bytes. The reader must report
        // this logical 0600, never the fixed 0644 the inode carries.
        let mut meta = Vec::new();
        meta.extend_from_slice(&0u32.to_be_bytes()); // uid
        meta.extend_from_slice(&0u32.to_be_bytes()); // gid
        meta.extend_from_slice(&0o100600u32.to_be_bytes()); // mode
        let xattr_ok = rustix::fs::setxattr(
            &reg_path,
            "user.ostreemeta",
            &meta,
            rustix::fs::XattrFlags::empty(),
        )
        .is_ok();
        if !xattr_ok {
            eprintln!("skipping bare-user-shared read: user xattrs unsupported here");
            return;
        }

        let file = repo.load_file(&reg).await.unwrap();
        assert_eq!((file.uid, file.gid, file.mode), (0, 0, 0o100600));
        assert_eq!(file.kind, FileKind::Regular { size: 7 });
        assert_eq!(read_payload(&file).await, b"shared\n");
    });
}
