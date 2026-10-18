//! Helpers that the integration tests of `ostrya-mount` share: scratch
//! directories, a source tree, repositories, commits with the composefs key,
//! a walk of a mounted tree, and the guard of the root-only tests.

#![allow(dead_code)]

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ostrya::{
    Checksum, CommitOptions, ComposefsImageAdd, CreateOptions, MutableTree, Repo, RepoMode, Type,
    Value,
};
use rustix::fs::{CWD, Mode, OFlags};
use rustix::mount::{FsOpenFlags, UnmountFlags};

/// The commit metadata key that holds the image digest.
pub const DIGEST_KEY: &str = "ostree.composefs.digest.v0";

/// The environment variable that turns the skip of a root-only test into a
/// failure. A harness that sets it declares that the tests run as root in the
/// initial user namespace, on a file system with fs-verity.
pub const REQUIRE_MOUNT: &str = "OSTRYA_REQUIRE_MOUNT";

/// The top-level directories that each composefs image adds to the tree.
pub const INJECTED_DIRS: [&str; 5] = ["boot", "etc", "sysroot", "usr", "var"];

/// A scratch directory under the temp directory of Cargo for the integration
/// tests. The directory is removed when the value drops.
///
/// The directory is under the target directory, not under `/tmp`, because
/// `/tmp` is a tmpfs on some hosts, and tmpfs has no fs-verity.
pub struct TmpDir(PathBuf);

impl TmpDir {
    pub fn new(tag: &str) -> TmpDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("ostrya-mount-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        TmpDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Detaches a mount at a path when the value drops, so that a test that
/// fails leaves no mount. Declare it after the [`TmpDir`] that holds the
/// path, so that it drops first.
pub struct MountGuard(pub PathBuf);

impl Drop for MountGuard {
    fn drop(&mut self) {
        while rustix::mount::unmount(&self.0, UnmountFlags::DETACH).is_ok() {}
    }
}

/// Returns `true` if the process can attach a loop device and mount EROFS
/// and overlayfs.
fn mount_capable() -> bool {
    let loop_control = rustix::fs::openat(
        CWD,
        "/dev/loop-control",
        OFlags::RDWR | OFlags::CLOEXEC,
        Mode::empty(),
    );
    loop_control.is_ok()
        && rustix::mount::fsopen("erofs", FsOpenFlags::FSOPEN_CLOEXEC).is_ok()
        && rustix::mount::fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC).is_ok()
}

/// Returns `true` if the process can mount, for a root-only test. Without
/// the privilege, the test skips and prints a message. If [`REQUIRE_MOUNT`]
/// is set, the missing privilege fails the test.
pub fn require_mount() -> bool {
    if mount_capable() {
        return true;
    }
    assert!(
        std::env::var_os(REQUIRE_MOUNT).is_none(),
        "{REQUIRE_MOUNT} is set and the process cannot attach a loop device or mount \
         EROFS and overlayfs"
    );
    eprintln!("skipped: the process cannot mount");
    false
}

/// Returns `true` if the file system of `dir` seals a file with fs-verity.
/// If [`REQUIRE_MOUNT`] is set, a file system without fs-verity fails the
/// test.
pub fn require_verity(dir: &Path) -> bool {
    let probe = dir.join("verity-probe");
    std::fs::write(&probe, b"probe\n").unwrap();
    let ro = std::fs::File::open(&probe).unwrap();
    let mut attempts = 0;
    let sealed = loop {
        attempts += 1;
        match ostrya_sys::enable_verity(ro.as_fd()) {
            Err(rustix::io::Errno::TXTBSY) if attempts < 50 => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            result => break result.is_ok(),
        }
    };
    drop(ro);
    let _ = std::fs::remove_file(&probe);
    if !sealed {
        assert!(
            std::env::var_os(REQUIRE_MOUNT).is_none(),
            "{REQUIRE_MOUNT} is set and {} has no fs-verity",
            dir.display()
        );
        eprintln!("skipped: the file system has no fs-verity");
    }
    sealed
}

/// Builds a source tree under `base/src` with fixed modes and `user.*`
/// xattrs: regular files of each mode class, a file that spans more than
/// one block, an empty file, a nested directory, and a symlink.
pub fn build_source(base: &Path) {
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

    setxattr(&src.join("hello.txt"), "user.demo", b"value");
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

/// Creates a repository at `root` in `mode`. If `config` is not empty, the
/// function appends it to the config file and opens the repository again.
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

/// Returns the metadata dict that records `digest` under the image key.
fn key_dict(digest: &[u8; 32]) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str(DIGEST_KEY.to_owned()),
        Value::variant(Type::parse("ay").unwrap(), Value::Bytes(digest.to_vec())),
    ])])
}

/// Commits `base/src` to `repo` at `timestamp`.
///
/// - [`Key::None`]: the commit has no image key.
/// - [`Key::Only`]: the commit has the key and the repository holds no image.
/// - [`Key::Image`]: the commit has the key, and the transaction stores the
///   image.
pub async fn commit_tree(repo: &Repo, base: &Path, timestamp: u64, key: Key) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = {
        let staged = match key {
            Key::Image => Some(txn.build_composefs_image(&root).await.unwrap()),
            Key::None | Key::Only => None,
        };
        let metadata = match (&staged, key) {
            (Some(staged), _) => Some(key_dict(staged.digest())),
            (None, Key::Only) => Some(key_dict(&txn.composefs_digest(&root).await.unwrap())),
            (None, _) => None,
        };
        let opts = CommitOptions {
            subject: Some("mount tree".to_owned()),
            timestamp: Some(timestamp),
            metadata,
            ..CommitOptions::default()
        };
        let commit = txn.write_commit(opts, &root).await.unwrap();
        if let Some(staged) = staged {
            let added = txn.attach_composefs_image(&commit, staged).await.unwrap();
            assert_eq!(added, ComposefsImageAdd::Added);
        }
        commit
    };
    txn.commit().await.unwrap();
    commit
}

/// The image key and the image of a commit that [`commit_tree`] writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// No key and no image.
    None,
    /// The key and no stored image.
    Only,
    /// The key and the stored image.
    Image,
}

/// One entry of a walked tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The path relative to the root of the walk.
    pub path: PathBuf,
    /// The file type and the permission bits, `st_mode`.
    pub mode: u32,
    /// The owner.
    pub uid: u32,
    /// The group.
    pub gid: u32,
    /// The `user.*` xattrs, sorted by name.
    pub xattrs: Vec<(String, Vec<u8>)>,
    /// The content of a regular file, or the target of a symlink.
    pub data: Vec<u8>,
}

/// Walks the tree at `root` and returns its entries in path order. The
/// function leaves out an entry of `skip_top` at the top level.
pub fn walk(root: &Path, skip_top: &[&str]) -> Vec<Entry> {
    let mut out = Vec::new();
    walk_into(root, Path::new(""), skip_top, &mut out);
    out
}

fn walk_into(root: &Path, rel: &Path, skip_top: &[&str], out: &mut Vec<Entry>) {
    use std::os::unix::fs::MetadataExt;

    let mut names: Vec<_> = std::fs::read_dir(root.join(rel))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    for name in names {
        if rel.as_os_str().is_empty() && skip_top.iter().any(|s| name == *s) {
            continue;
        }
        let rel = rel.join(&name);
        let path = root.join(&rel);
        let meta = std::fs::symlink_metadata(&path).unwrap();
        let data = if meta.file_type().is_symlink() {
            std::fs::read_link(&path)
                .unwrap()
                .into_os_string()
                .into_encoded_bytes()
        } else if meta.is_file() {
            std::fs::read(&path).unwrap()
        } else {
            Vec::new()
        };
        let xattrs = if meta.file_type().is_symlink() {
            Vec::new()
        } else {
            user_xattrs(&path)
        };
        out.push(Entry {
            path: rel.clone(),
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            xattrs,
            data,
        });
        if meta.is_dir() {
            walk_into(root, &rel, skip_top, out);
        }
    }
}

/// Returns the `user.*` xattrs of `path`, sorted by name.
fn user_xattrs(path: &Path) -> Vec<(String, Vec<u8>)> {
    let mut names = vec![0u8; 4096];
    let n = rustix::fs::listxattr(path, &mut names).unwrap();
    let mut out: Vec<(String, Vec<u8>)> = names[..n]
        .split(|b| *b == 0)
        .filter(|name| name.starts_with(b"user."))
        .map(|name| {
            let name = String::from_utf8(name.to_vec()).unwrap();
            let mut value = vec![0u8; 4096];
            let len = rustix::fs::getxattr(path, name.as_str(), &mut value).unwrap();
            value.truncate(len);
            (name, value)
        })
        .collect();
    out.sort();
    out
}

/// Returns true if loop device `number` has the backing file `backing`, or
/// a backing file that starts with `backing` if `prefix` is set.
fn has_backing(number: u32, backing: &str, prefix: bool) -> bool {
    let Ok(file) = std::fs::read_to_string(format!("/sys/block/loop{number}/loop/backing_file"))
    else {
        return false;
    };
    let file = file.trim_end();
    file == backing || (prefix && file.starts_with(backing))
}

/// Returns the number of the loop device whose backing file is `backing`,
/// or whose backing file starts with `backing` if `prefix` is set.
pub fn loop_device_of(backing: &str, prefix: bool) -> Option<u32> {
    std::fs::read_dir("/sys/block")
        .unwrap()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.strip_prefix("loop").and_then(|n| n.parse().ok())
        })
        .find(|&number| has_backing(number, backing, prefix))
}

/// Waits up to 5 seconds until loop device `number` no longer has the
/// backing file that `backing` and `prefix` select, as for
/// [`loop_device_of`]. Another test can take the same device after the
/// release, with another backing file.
pub fn wait_detached(number: u32, backing: &str, prefix: bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while has_backing(number, backing, prefix) {
        assert!(
            std::time::Instant::now() < deadline,
            "loop{number} stays attached"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Returns the path of the `.file` object in `repo_root` whose content is
/// `content`.
pub fn object_with_content(repo_root: &Path, content: &[u8]) -> PathBuf {
    for dir in std::fs::read_dir(repo_root.join("objects"))
        .unwrap()
        .flatten()
    {
        if !dir.file_type().unwrap().is_dir() {
            continue;
        }
        for obj in std::fs::read_dir(dir.path()).unwrap().flatten() {
            let path = obj.path();
            if path.extension().is_some_and(|e| e == "file")
                && obj.file_type().unwrap().is_file()
                && std::fs::read(&path).unwrap() == content
            {
                return path;
            }
        }
    }
    panic!("no object holds the content");
}
