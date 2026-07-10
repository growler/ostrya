//! Reading-path tests for repository modes without checked-in fixtures.
//!
//! bare and bare-user-only need root or a tool to produce faithful ownership,
//! and bare-user-split-attrs is a port extension the tool does not write, so
//! there are no golden fixtures. These tests instead build objects directly --
//! real inodes for the bare family, and the `.filea`/`.fileb` pair (via the
//! core encoders) for split-attrs -- then read them back through the port.

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use common::TmpDir;
use futures_lite::AsyncReadExt;
use ostrya::{Checksum, CreateOptions, FileKind, Repo, RepoMode};
use ostrya_core::{ContentHasher, FileHeader, ObjectType, Xattrs, loose_path};
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
fn reads_split_attrs_via_the_blob_reference() {
    block_on(async {
        let tmp = TmpDir::new("split");
        let root = tmp.path().join("repo");
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUserSplitAttrs))
            .await
            .expect("create split-attrs repo");
        let mode = RepoMode::BareUserSplitAttrs;

        // A regular file: the payload lives in a content-addressed `.fileb`, and
        // the `.filea` holds the attributes plus the blob reference. The `.filea`
        // is named by the classic file identity, unchanged across modes.
        let payload = b"hello\n";
        let blob = Checksum::sha256(payload);
        let header = FileHeader {
            uid: 500,
            gid: 500,
            mode: 0o100640,
            symlink_target: String::new(),
            xattrs: Xattrs::new([(b"user.k\0".to_vec(), b"val".to_vec())]).unwrap(),
        };
        let mut hasher = ContentHasher::new(&header).unwrap();
        hasher.update(payload);
        let file_id = hasher.finish();

        fs::write(
            object_path(&root, &blob, ObjectType::FileBlob, mode),
            payload,
        )
        .unwrap();
        fs::write(
            object_path(&root, &file_id, ObjectType::File, mode),
            header.serialize_split_attrs(Some(&blob)).unwrap(),
        )
        .unwrap();

        let file = repo.load_file(&file_id).await.unwrap();
        assert_eq!((file.uid, file.gid, file.mode), (500, 500, 0o100640));
        assert_eq!(file.kind, FileKind::Regular { size: 6 });
        assert_eq!(file.xattrs.len(), 1);
        assert_eq!(read_payload(&file).await, b"hello\n");
        assert_eq!(repo.blob_checksum_of(&file_id).await.unwrap(), Some(blob));

        // A symlink keeps its target in the `.filea` and references no blob.
        let link_header = FileHeader {
            uid: 0,
            gid: 0,
            mode: 0o120777,
            symlink_target: "target/path".to_owned(),
            xattrs: Xattrs::empty(),
        };
        let link_id = ContentHasher::new(&link_header).unwrap().finish();
        fs::write(
            object_path(&root, &link_id, ObjectType::File, mode),
            link_header.serialize_split_attrs(None).unwrap(),
        )
        .unwrap();

        let link = repo.load_file(&link_id).await.unwrap();
        assert_eq!(
            link.kind,
            FileKind::Symlink {
                target: "target/path".to_owned()
            }
        );
        assert_eq!(read_payload(&link).await, b"");
        assert_eq!(repo.blob_checksum_of(&link_id).await.unwrap(), None);
    });
}

#[test]
fn blob_checksum_of_requires_split_attrs_mode() {
    block_on(async {
        let tmp = TmpDir::new("nosplit");
        let root = tmp.path().join("repo");
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let err = repo
            .blob_checksum_of(&csum(&"ee".repeat(32)))
            .await
            .unwrap_err();
        assert!(matches!(err, ostrya::Error::Unsupported(_)));
    });
}
