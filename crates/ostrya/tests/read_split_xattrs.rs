//! Reading-path tests for bare-split-xattrs.
//!
//! The `ostree` tool refuses to write this mode, so there is no tool-generated
//! golden fixture. These tests build a repository by hand and read it back
//! through the port. The recovered on-disk shape (see docs/format-reference.md)
//! is: bare inode storage (real uid/gid/mode, real symlinks, no `user.ostreemeta`)
//! with the logical xattrs held in a separate `.file-xattrs` object reached
//! through a `.file-xattrs-link` object keyed by the file checksum. Because the
//! inode carries the identity's uid/gid/mode, a repository the tool accepts must
//! own its objects as the identity expects; a self-consistent repository is
//! therefore built with the running user's ownership, and the tool cross-check
//! runs only when `ostree` is on PATH.

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{TmpDir, ostree_available};
use futures_lite::AsyncReadExt;
use ostrya::{Checksum, CreateOptions, FileKind, Repo, RepoMode};
use ostrya_core::{
    ContentHasher, DirMeta, DirTree, FileHeader, ObjectType, Value, Xattrs, loose_path,
};
use ostrya_rt::block_on;

const MODE: RepoMode = RepoMode::BareSplitXattrs;

fn csum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

async fn read_payload(file: &ostrya::FileObject) -> Vec<u8> {
    let mut reader = file.reader().await.expect("open reader");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.expect("read payload");
    buf
}

/// Absolute path of a loose object within a repository, parents created.
fn object_path(root: &Path, checksum: &Checksum, ty: ObjectType) -> PathBuf {
    let full = root.join("objects").join(loose_path(checksum, ty, MODE));
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    full
}

/// The running user's uid/gid, read off a freshly created file so the
/// hand-built inodes carry the ownership the object identity encodes.
fn current_owner(tmp: &Path) -> (u32, u32) {
    let probe = tmp.join(".owner-probe");
    fs::write(&probe, b"").unwrap();
    let md = fs::metadata(&probe).unwrap();
    (md.uid(), md.gid())
}

/// Write the `.file`, `.file-xattrs`, and `.file-xattrs-link` objects for one
/// file and return its object identity. Regular files store the raw payload on
/// an inode chmodded to the logical mode; symlinks are real symlinks. Every
/// file gets a `.file-xattrs-link` hardlinked to the shared `.file-xattrs`.
fn write_file_object(
    root: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    target: &str,
    xattrs: &Xattrs,
    payload: &[u8],
) -> Checksum {
    let header = FileHeader {
        uid,
        gid,
        mode,
        symlink_target: target.to_owned(),
        xattrs: xattrs.clone(),
    };
    let mut hasher = ContentHasher::new(&header).unwrap();
    hasher.update(payload);
    let id = hasher.finish();

    let file_path = object_path(root, &id, ObjectType::File);
    let _ = fs::remove_file(&file_path);
    if mode & 0o170000 == 0o120000 {
        symlink(target, &file_path).unwrap();
    } else {
        fs::write(&file_path, payload).unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(mode & 0o7777)).unwrap();
    }

    // The xattr object holds the raw GVariant a(ayay); the link is a hardlink to
    // it, named by the file checksum. The empty set is the shared object whose
    // content is the zero-byte empty array.
    let xbytes = xattrs.to_gvariant().unwrap();
    let xid = Checksum::sha256(&xbytes);
    let xattrs_path = object_path(root, &xid, ObjectType::FileXattrs);
    if !xattrs_path.exists() {
        fs::write(&xattrs_path, &xbytes).unwrap();
    }
    let link_path = object_path(root, &id, ObjectType::FileXattrsLink);
    let _ = fs::remove_file(&link_path);
    fs::hard_link(&xattrs_path, &link_path).unwrap();
    id
}

/// Build a self-consistent single-directory commit and return its checksum.
fn write_commit(root: &Path, files: &[(&str, Checksum)]) -> Checksum {
    let dirmeta = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: Xattrs::empty(),
    };
    let dirmeta_bytes = dirmeta.serialize().unwrap();
    let dirmeta_id = Checksum::sha256(&dirmeta_bytes);
    fs::write(
        object_path(root, &dirmeta_id, ObjectType::DirMeta),
        &dirmeta_bytes,
    )
    .unwrap();

    let dirtree = DirTree {
        files: files.iter().map(|(n, c)| (n.to_string(), *c)).collect(),
        dirs: vec![],
    };
    let dirtree_bytes = dirtree.serialize().unwrap();
    let dirtree_id = Checksum::sha256(&dirtree_bytes);
    fs::write(
        object_path(root, &dirtree_id, ObjectType::DirTree),
        &dirtree_bytes,
    )
    .unwrap();

    let commit = ostrya_core::Commit {
        metadata: Value::Array(vec![]),
        parent: None,
        related: vec![],
        subject: "x".to_owned(),
        body: String::new(),
        timestamp: 1_700_000_000,
        root_dirtree: dirtree_id,
        root_dirmeta: dirmeta_id,
    };
    let commit_bytes = commit.serialize().unwrap();
    let commit_id = Checksum::sha256(&commit_bytes);
    fs::write(
        object_path(root, &commit_id, ObjectType::Commit),
        &commit_bytes,
    )
    .unwrap();

    let heads = root.join("refs/heads/test");
    fs::create_dir_all(&heads).unwrap();
    fs::write(heads.join("main"), format!("{}\n", commit_id.to_hex())).unwrap();
    commit_id
}

#[test]
fn reads_metadata_from_inode_and_xattrs_from_the_split_object() {
    block_on(async {
        let tmp = TmpDir::new("bsx");
        let root = tmp.path().join("repo");
        let repo = Repo::create(&root, CreateOptions::new(MODE))
            .await
            .expect("create bare-split-xattrs repo");
        assert_eq!(repo.mode(), MODE);
        let (uid, gid) = current_owner(tmp.path());

        // A regular file: uid/gid/mode come from the inode, the user.demo xattr
        // from the split object, and the payload from the inode content.
        let demo = Xattrs::new([(b"user.demo\0".to_vec(), b"bar".to_vec())]).unwrap();
        let hello = write_file_object(&root, uid, gid, 0o100644, "", &demo, b"hello ostree\n");
        let file = repo.load_file(&hello).await.unwrap();
        assert_eq!((file.uid, file.gid, file.mode), (uid, gid, 0o100644));
        assert_eq!(file.kind, FileKind::Regular { size: 13 });
        let names: Vec<&[u8]> = file.xattrs.iter().map(|(n, _)| n).collect();
        assert_eq!(names, [b"user.demo\0".as_slice()]);
        assert_eq!(read_payload(&file).await, b"hello ostree\n");

        // A symlink with no xattrs: real symlink, empty xattr set from the
        // shared empty split object.
        let link = write_file_object(
            &root,
            uid,
            gid,
            0o120777,
            "hello.txt",
            &Xattrs::empty(),
            b"",
        );
        let file = repo.load_file(&link).await.unwrap();
        assert_eq!(
            file.kind,
            FileKind::Symlink {
                target: "hello.txt".to_owned()
            }
        );
        assert!(file.xattrs.is_empty());
        assert_eq!(read_payload(&file).await, b"");
    });
}

#[test]
fn a_missing_file_xattrs_link_is_a_format_error() {
    block_on(async {
        let tmp = TmpDir::new("bsx-nolink");
        let root = tmp.path().join("repo");
        let repo = Repo::create(&root, CreateOptions::new(MODE)).await.unwrap();

        // A `.file` object with no companion `.file-xattrs-link`.
        let id = csum(&"22".repeat(32));
        fs::write(object_path(&root, &id, ObjectType::File), b"orphan").unwrap();
        let err = repo.load_file(&id).await.unwrap_err();
        assert!(
            matches!(&err, ostrya::Error::InvalidFormat(m) if m.contains("file-xattrs-link")),
            "unexpected error: {err:?}"
        );
    });
}

#[test]
fn tool_accepts_the_hand_built_repository() {
    // The recovered layout is confirmed by the tool: a self-consistent repo,
    // owned by the running user so identities match the inodes, must pass
    // `ostree fsck` and report the split xattrs through `ostree ls -X`.
    if !ostree_available() {
        eprintln!("skipping bare-split-xattrs tool cross-check: ostree not on PATH");
        return;
    }
    let tmp = TmpDir::new("bsx-tool");
    let root = tmp.path().join("repo");
    block_on(async {
        Repo::create(&root, CreateOptions::new(MODE)).await.unwrap();
    });
    let (uid, gid) = current_owner(tmp.path());
    let demo = Xattrs::new([(b"user.demo\0".to_vec(), b"bar".to_vec())]).unwrap();
    let hello = write_file_object(&root, uid, gid, 0o100644, "", &demo, b"hello ostree\n");
    let link = write_file_object(
        &root,
        uid,
        gid,
        0o120777,
        "hello.txt",
        &Xattrs::empty(),
        b"",
    );
    write_commit(&root, &[("hello.txt", hello), ("link", link)]);

    let repo_arg = format!("--repo={}", root.display());
    let fsck = Command::new("ostree")
        .arg(&repo_arg)
        .arg("fsck")
        .output()
        .expect("run ostree fsck");
    assert!(
        fsck.status.success(),
        "ostree fsck failed: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );

    let ls = Command::new("ostree")
        .arg(&repo_arg)
        .args(["ls", "-X", "-R", "test/main"])
        .output()
        .expect("run ostree ls -X");
    assert!(ls.status.success(), "ostree ls -X failed");
    let ls = String::from_utf8_lossy(&ls.stdout);
    // The tool reads user.demo out of the split object and the symlink target
    // off the real symlink.
    assert!(
        ls.contains("user.demo"),
        "tool ls -X missing the xattr:\n{ls}"
    );
    assert!(
        ls.contains("/link -> hello.txt"),
        "tool ls -X missing the symlink:\n{ls}"
    );
}

/// The tool treats a `.file` with no companion `.file-xattrs-link` as
/// corruption, even for a file with no xattrs (which links to the shared
/// empty-set object). Recovered by observation: removing the link from an
/// otherwise self-consistent commit makes `ostree fsck` mark the commit partial
/// and fail, and `ostree ls -X` fail opening the link. This confirms the port's
/// matching strictness in `a_missing_file_xattrs_link_is_a_format_error` is
/// faithful to the tool, not stricter than it.
#[test]
fn tool_rejects_a_missing_file_xattrs_link() {
    if !ostree_available() {
        eprintln!("skipping bare-split-xattrs tool cross-check: ostree not on PATH");
        return;
    }
    let tmp = TmpDir::new("bsx-nolink-tool");
    let root = tmp.path().join("repo");
    block_on(async {
        Repo::create(&root, CreateOptions::new(MODE)).await.unwrap();
    });
    let (uid, gid) = current_owner(tmp.path());

    // A file with no xattrs, linked to the shared empty-set object.
    let plain = write_file_object(
        &root,
        uid,
        gid,
        0o100644,
        "",
        &Xattrs::empty(),
        b"no xattrs\n",
    );
    write_commit(&root, &[("plain.txt", plain)]);

    let repo_arg = format!("--repo={}", root.display());
    let baseline = Command::new("ostree")
        .arg(&repo_arg)
        .arg("fsck")
        .output()
        .expect("run ostree fsck");
    assert!(
        baseline.status.success(),
        "baseline fsck should pass: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );

    fs::remove_file(object_path(&root, &plain, ObjectType::FileXattrsLink)).unwrap();

    let fsck = Command::new("ostree")
        .arg(&repo_arg)
        .arg("fsck")
        .output()
        .expect("run ostree fsck");
    assert!(
        !fsck.status.success(),
        "fsck must reject a .file with a missing .file-xattrs-link"
    );
}
