//! Composefs helpers that the integration tests of `ostrya` share: the
//! golden fixture, and a tree that the running user owns.

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use ostrya::{Checksum, CommitOptions, CreateOptions, MutableTree, Repo, RepoMode};

use super::{TmpDir, fixture_repo, fixture_root};

/// The directory that holds the checked-in composefs golden fixtures.
pub fn composefs_dir() -> PathBuf {
    fixture_root().join("composefs")
}

/// Reads a `key=value` entry from the fixture MANIFEST.
pub fn manifest_value(key: &str) -> Option<String> {
    let text = std::fs::read_to_string(fixture_root().join("MANIFEST")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .map(|v| v.trim().to_owned())
}

/// Returns the composefs image digest under `key` in the MANIFEST.
///
/// The fixture generator measured the digest with
/// `composefs-info measure-file` on the image that the `ostree` command wrote.
/// If the fixture is absent, the value is `None`, and the test skips.
pub fn manifest_digest(key: &str) -> Option<String> {
    manifest_value(key).filter(|s| !s.is_empty())
}

/// Copies the `mode` fixture repository into `scratch` and returns its path.
/// `cp -a` preserves the `user.ostreemeta` xattrs that the objects carry.
pub fn scratch_fixture_repo(scratch: &TmpDir, mode: &str) -> PathBuf {
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

/// Builds a source tree under `base/src` that the running user owns, with fixed
/// modes and `user.*` xattrs. The tree holds:
///
/// - a regular file of each mode class,
/// - a file that spans more than one fs-verity block,
/// - an empty file,
/// - a nested directory,
/// - a symlink.
///
/// Linux refuses a `user.*` xattr on a symlink, so the symlink carries none.
/// The function sets each xattr before the chmod, because a `user.*` xattr
/// needs write access to the inode.
pub fn build_owned_source(base: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let chmod = |p: &Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    };
    let setxattr = |p: &Path, name: &str, value: &[u8]| {
        rustix::fs::setxattr(p, name, value, rustix::fs::XattrFlags::empty()).unwrap();
    };
    let src = base.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello composefs\n").unwrap();
    std::fs::write(src.join("readonly.txt"), b"read only\n").unwrap();
    std::fs::write(src.join("run.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    let big: Vec<u8> = (0..9000).map(|i| i as u8).collect();
    std::fs::write(src.join("big.bin"), big).unwrap();
    std::fs::write(src.join("empty"), b"").unwrap();
    std::fs::write(src.join("sub/nested.txt"), b"nested\n").unwrap();
    std::os::unix::fs::symlink("hello.txt", src.join("link")).unwrap();

    setxattr(&src, "user.dir", b"root");
    setxattr(&src.join("hello.txt"), "user.demo", b"value");
    setxattr(&src.join("hello.txt"), "user.shared", b"s");
    setxattr(&src.join("readonly.txt"), "user.shared", b"s");
    setxattr(&src.join("sub"), "user.dir", b"sub");

    chmod(&src.join("hello.txt"), 0o644);
    chmod(&src.join("readonly.txt"), 0o444);
    chmod(&src.join("run.sh"), 0o755);
    chmod(&src.join("big.bin"), 0o644);
    chmod(&src.join("empty"), 0o644);
    chmod(&src.join("sub/nested.txt"), 0o600);
    chmod(&src.join("sub"), 0o750);
    chmod(&src, 0o755);
}

/// Creates a repository at `root` in `mode`. If `config` is not empty, appends
/// it to the config file of the repository. Then opens the repository again,
/// so that it parses the text.
pub async fn new_repo(root: &Path, mode: RepoMode, config: &str) -> Repo {
    let repo = Repo::create(root, CreateOptions::new(mode)).await.unwrap();
    if config.is_empty() {
        return repo;
    }
    drop(repo);
    let cfg = root.join("config");
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(config);
    std::fs::write(&cfg, text).unwrap();
    Repo::open(root).await.unwrap()
}

/// Walks `base/src` into `repo` with no modifier, so that the commit records
/// the owner, the mode, and the xattrs of each source inode. Commits the tree
/// at timestamp 0, and returns the commit checksum.
pub async fn commit_owned(repo: &Repo, base: &Path) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("owned tree".to_owned()),
                timestamp: Some(0),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.commit().await.unwrap();
    commit
}
