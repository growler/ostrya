//! The fixtures that the integration tests of `ostrya-mountd` share:
//! scratch directories under `/var/tmp`, child processes, the guard of the
//! root-only tests, a repository with commits and image commits, a
//! standalone daemon, and the reads of mountinfo.

#![allow(dead_code)]

use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ostrya::{
    COMPOSEFS_RELATION, Checksum, Commit, CommitOptions, ComposefsOptions, CreateOptions, DirMeta,
    DirTree, FileMeta, MutableTree, ObjectType, Repo, RepoMode, Type, Value, Xattrs,
};
use rustix::mount::FsOpenFlags;

/// The environment variable that turns the skip of a test into a failure.
pub const REQUIRE_MOUNT: &str = "OSTRYA_REQUIRE_MOUNT";

/// The commit metadata key that holds the image digest.
pub const DIGEST_KEY: &str = "ostree.composefs.digest.v0";

/// The user of each client.
pub const CLIENT_UID: u32 = 65534;

/// The content of `hello.txt` in the committed tree.
pub const HELLO: &[u8] = b"hello composefs\n";

/// The mode of the empty file `devnode` in the committed tree. The test
/// finds the inode of the file in the image by this mode, and changes it
/// into a character device.
pub const DEVNODE_MODE: u16 = 0o100602;

/// The device of `devnode` in the changed image: 1:3, `/dev/null`.
pub const DEVNODE_RDEV: u32 = (1 << 8) | 3;

/// The arguments that put a client in its own user namespace and mount
/// namespace.
pub const OWN_NAMESPACES: &[&str] = &["unshare", "-Ur", "-m"];

/// A scratch directory under `/var/tmp` that any user can traverse. The
/// directory is removed when the value drops.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Scratch {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from("/var/tmp")
            .join(format!("ostrya-mountd-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Scratch(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A child process that is killed and reaped when the value drops.
pub struct ChildGuard(pub Option<Child>);

impl ChildGuard {
    /// Waits at most `limit` for the child to exit and returns its status.
    pub fn wait_for(&mut self, limit: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + limit;
        let child = self.0.as_mut().unwrap();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Returns `true` if a command runs with exit status 0.
pub fn runs(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Returns `true` if the process can run the daemon and the clients: root
/// in the initial user namespace, the mount calls, and a user namespace for
/// the user 65534. Without them, the test skips and prints a message. If
/// [`REQUIRE_MOUNT`] is set, a missing requirement fails the test.
pub fn require_root() -> bool {
    let capable = ostrya_mount::is_privileged()
        && rustix::mount::fsopen("erofs", FsOpenFlags::FSOPEN_CLOEXEC).is_ok()
        && runs(
            "setpriv",
            &[
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "unshare",
                "-Ur",
                "-m",
                "true",
            ],
        );
    if !capable {
        assert!(
            std::env::var_os(REQUIRE_MOUNT).is_none(),
            "{REQUIRE_MOUNT} is set and the process cannot run the daemon tests"
        );
        eprintln!("skipped: the tests need root, mounts, setpriv, and unshare");
    }
    capable
}

/// The tree, the repository, and the commits of a test.
pub struct Fixture {
    pub scratch: Scratch,
    pub repo: PathBuf,
    pub commit: Checksum,
    /// The commit of [`Fixture::dev_commit`], after its first call.
    dev_commit: OnceLock<Checksum>,
    /// The copy of [`Fixture::client_bin`], after its first call.
    client_bin: OnceLock<PathBuf>,
}

impl Fixture {
    pub fn new(tag: &str) -> Fixture {
        let scratch = Scratch::new(tag);
        let src = scratch.path().join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("hello.txt"), HELLO).unwrap();
        std::fs::write(src.join("sub/nested.txt"), b"nested\n").unwrap();
        std::fs::copy("/usr/bin/id", src.join("suid-id")).unwrap();
        std::fs::set_permissions(src.join("suid-id"), std::fs::Permissions::from_mode(0o4755))
            .unwrap();
        std::fs::write(src.join("devnode"), b"").unwrap();
        std::fs::set_permissions(
            src.join("devnode"),
            std::fs::Permissions::from_mode(u32::from(DEVNODE_MODE) & 0o7777),
        )
        .unwrap();
        let repo = scratch.path().join("repo");
        let commit = ostrya_rt::block_on(async {
            let r = Repo::create(&repo, CreateOptions::new(RepoMode::BareUser))
                .await
                .unwrap();
            commit_tree(&r, scratch.path()).await
        });
        Fixture {
            scratch,
            repo,
            commit,
            dev_commit: OnceLock::new(),
            client_bin: OnceLock::new(),
        }
    }

    /// Returns a commit of the same tree with no key, whose image commit
    /// holds `devnode` as a character device. The first call writes the
    /// commit.
    pub fn dev_commit(&self) -> Checksum {
        *self.dev_commit.get_or_init(|| {
            ostrya_rt::block_on(async {
                let (repo, root) = fixture_root(self).await;
                commit_dev_tree(&repo, &root, &self.commit).await
            })
        })
    }

    /// Returns a copy of the test binary that the user 65534 can run. The
    /// first call makes the copy.
    pub fn client_bin(&self) -> &Path {
        self.client_bin.get_or_init(|| {
            let client_bin = self.scratch.path().join("client");
            std::fs::copy(std::env::current_exe().unwrap(), &client_bin).unwrap();
            std::fs::set_permissions(&client_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            client_bin
        })
    }

    /// Creates the empty directory `name`, owned by the client user.
    pub fn target(&self, name: &str) -> PathBuf {
        let path = self.scratch.path().join(name);
        std::fs::create_dir(&path).unwrap();
        rustix::fs::chown(
            &path,
            Some(rustix::fs::Uid::from_raw(CLIENT_UID)),
            Some(rustix::fs::Gid::from_raw(CLIENT_UID)),
        )
        .unwrap();
        path
    }

    /// The directory for the temp files of the daemon.
    pub fn daemon_tmp(&self) -> PathBuf {
        let path = self.scratch.path().join("daemon-tmp");
        let _ = std::fs::create_dir(&path);
        path
    }

    /// Starts the daemon in the standalone mode at `sock`.
    pub fn standalone(&self, sock: &Path, parent: Option<u32>, idle: u64) -> ChildGuard {
        self.standalone_with(sock, parent, idle, &[])
    }

    /// Starts the daemon in the standalone mode at `sock`, with the options
    /// `extra`.
    pub fn standalone_with(
        &self,
        sock: &Path,
        parent: Option<u32>,
        idle: u64,
        extra: &[&str],
    ) -> ChildGuard {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ostrya-mountd"));
        cmd.arg("--listen").arg(sock).args(extra);
        cmd.arg("--idle-timeout").arg(idle.to_string());
        if let Some(pid) = parent {
            cmd.arg("--parent-pid").arg(pid.to_string());
        }
        let child = ChildGuard(Some(
            cmd.env("TMPDIR", self.daemon_tmp())
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        ));
        wait_for_path(sock);
        child
    }
}

/// Waits at most 10 seconds until `path` exists.
pub fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Returns the metadata dict that records `digest` under the image key.
pub fn key_dict(digest: &[u8; 32]) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str(DIGEST_KEY.to_owned()),
        Value::variant(Type::parse("ay").unwrap(), Value::Bytes(digest.to_vec())),
    ])])
}

/// How a commit names its image commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Named {
    /// The attachment `composefs`.
    Attachment,
    /// The supplement `composefs`.
    Supplement,
    /// No image commit.
    Neither,
}

/// Writes `base/src` to `repo` and returns its root tree.
pub async fn write_source(repo: &Repo, base: &Path) -> ostrya::RepoTree {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    txn.commit().await.unwrap();
    root
}

/// Writes the image commit of `root` and a commit of `root` with the image
/// key and the subject `subject`, which names the image commit as `named`
/// gives. Returns the commit and the image commit.
pub async fn commit_named(
    repo: &Repo,
    root: &ostrya::RepoTree,
    subject: &str,
    named: Named,
) -> (Checksum, Checksum) {
    let txn = repo.transaction().await.unwrap();
    let (image, digest) = txn.write_composefs_commit(root, None).await.unwrap();
    let attachments = match named {
        Named::Attachment => vec![(COMPOSEFS_RELATION.to_owned(), image)],
        Named::Supplement | Named::Neither => Vec::new(),
    };
    let opts = CommitOptions {
        subject: Some(subject.to_owned()),
        timestamp: Some(1),
        metadata: Some(key_dict(&digest)),
        attachments,
        ..CommitOptions::default()
    };
    let commit = txn.write_commit(opts, root).await.unwrap();
    if named == Named::Supplement {
        txn.add_supplement(&commit, COMPOSEFS_RELATION, &image)
            .unwrap();
    }
    txn.commit().await.unwrap();
    (commit, image)
}

/// Writes an image commit whose `/root.cfs` holds `image`, with the shape
/// of an image commit, and returns its checksum.
pub async fn write_image_commit(repo: &Repo, image: &[u8]) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let file = txn
        .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o400), image)
        .await
        .unwrap();
    let root_dirmeta = txn
        .write_dirmeta(&DirMeta {
            uid: 0,
            gid: 0,
            mode: 0o040755,
            xattrs: Xattrs::empty(),
        })
        .await
        .unwrap();
    let tree = DirTree {
        files: vec![("root.cfs".to_owned(), file)],
        dirs: Vec::new(),
    };
    let root_dirtree = txn
        .write_metadata(ObjectType::DirTree, None, &tree.serialize().unwrap())
        .await
        .unwrap();
    let commit = Commit {
        metadata: Value::Array(Vec::new()),
        parent: None,
        related: Vec::new(),
        subject: "composefs image".to_owned(),
        body: String::new(),
        timestamp: 0,
        root_dirtree,
        root_dirmeta,
    };
    let checksum = txn
        .write_metadata(ObjectType::Commit, None, &commit.serialize().unwrap())
        .await
        .unwrap();
    txn.commit().await.unwrap();
    checksum
}

/// Commits `base/src` to `repo` with the image key and the attachment
/// `composefs`, and returns the commit.
pub async fn commit_tree(repo: &Repo, base: &Path) -> Checksum {
    let root = write_source(repo, base).await;
    commit_named(repo, &root, "mountd tree", Named::Attachment)
        .await
        .0
}

/// Writes a commit of the tree `root` with no key, whose attachment
/// `composefs` holds the image of `commit` with `devnode` as a character
/// device, and returns it.
pub async fn commit_dev_tree(repo: &Repo, root: &ostrya::RepoTree, commit: &Checksum) -> Checksum {
    // The commit format holds no device node, so the test writes one into a
    // copy of the image. The commit of that image has no key, so the daemon
    // makes no check of the image.
    let mut image = repo
        .export_composefs(commit, &ComposefsOptions::RECORDED, None)
        .await
        .unwrap()
        .bytes;
    make_devnode(&mut image);
    let dev_image = write_image_commit(repo, &image).await;
    let txn = repo.transaction().await.unwrap();
    let opts = CommitOptions {
        subject: Some("mountd device tree".to_owned()),
        timestamp: Some(3),
        attachments: vec![(COMPOSEFS_RELATION.to_owned(), dev_image)],
        ..CommitOptions::default()
    };
    let dev_commit = txn.write_commit(opts, root).await.unwrap();
    txn.commit().await.unwrap();
    dev_commit
}

/// Changes the compact inode of the empty file with [`DEVNODE_MODE`] in the
/// EROFS image `image` into the character device [`DEVNODE_RDEV`].
///
/// A compact inode is 32 bytes at a 32-byte boundary. It starts with the
/// format, the xattr count, and the mode, each 16 bits. The device number is
/// at byte 16.
pub fn make_devnode(image: &mut [u8]) {
    let at = (0..image.len() - 32)
        .step_by(32)
        .find(|&i| {
            image[i..i + 4] == [0, 0, 0, 0] && image[i + 4..i + 6] == DEVNODE_MODE.to_le_bytes()
        })
        .expect("the image holds the inode of devnode");
    image[at + 4..at + 6].copy_from_slice(&(0o020_666u16).to_le_bytes());
    image[at + 16..at + 20].copy_from_slice(&DEVNODE_RDEV.to_le_bytes());
}

/// Returns the mountinfo lines of the mounts at `target`.
pub fn mounts_at(target: &Path) -> Vec<String> {
    let resolved = std::fs::canonicalize(target).unwrap();
    let want = resolved.to_str().unwrap();
    std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap()
        .lines()
        .filter(|l| l.split(' ').nth(4) == Some(want))
        .map(str::to_owned)
        .collect()
}

/// Unmounts a mount of the test at the path when the value drops.
pub struct Unmount(pub PathBuf);

impl Drop for Unmount {
    fn drop(&mut self) {
        let _ = Command::new("umount")
            .arg("-l")
            .arg(&self.0)
            .stderr(Stdio::null())
            .status();
    }
}

/// Returns the image commit that `commit` names as the attachment
/// `composefs` in the repository at `repo`, and the file object of its
/// `/root.cfs`.
pub fn image_commit_of(repo: &Path, commit: &Checksum) -> (Checksum, Checksum) {
    let image = ostrya_rt::block_on(async {
        let repo = Repo::open(repo).await.unwrap();
        let relations = repo.read_commit_relations(commit).await.unwrap();
        relations.attachments[0].1
    });
    (image, root_cfs_of(repo, &image))
}

/// Returns the file object of `/root.cfs` of the image commit `image` in
/// the repository at `repo`.
pub fn root_cfs_of(repo: &Path, image: &Checksum) -> Checksum {
    ostrya_rt::block_on(async {
        let repo = Repo::open(repo).await.unwrap();
        let (image_obj, _) = repo.load_commit(image).await.unwrap();
        let tree = repo.load_dirtree(&image_obj.root_dirtree).await.unwrap();
        tree.files[0].1
    })
}

/// Returns the number of the loop device whose backing file `backing`
/// accepts.
pub fn loop_device_of(backing: impl Fn(&str) -> bool) -> Option<u32> {
    std::fs::read_dir("/sys/block")
        .unwrap()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.strip_prefix("loop").and_then(|n| n.parse().ok())
        })
        .find(|&number| has_backing(number, &backing))
}

/// Waits up to 5 seconds until loop device `number` no longer has a backing
/// file that `backing` accepts. Another test can take the same device after
/// the release, with another backing file.
pub fn wait_detached(number: u32, backing: impl Fn(&str) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while has_backing(number, &backing) {
        assert!(Instant::now() < deadline, "loop{number} stays attached");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Returns `true` if loop device `number` has a backing file that `backing`
/// accepts.
fn has_backing(number: u32, backing: &impl Fn(&str) -> bool) -> bool {
    std::fs::read_to_string(format!("/sys/block/loop{number}/loop/backing_file"))
        .is_ok_and(|file| backing(file.trim_end()))
}

/// Returns the path of the loose file object `object` in the `bare-user`
/// repository at `repo`.
pub fn file_object_path(repo: &Path, object: &Checksum) -> PathBuf {
    let hex = object.to_hex();
    repo.join("objects")
        .join(&hex[..2])
        .join(format!("{}.file", &hex[2..]))
}

/// Opens the repository of the fixture and returns it with the root tree
/// of the commit of the fixture.
pub async fn fixture_root(fx: &Fixture) -> (Repo, ostrya::RepoTree) {
    let repo = Repo::open(&fx.repo).await.unwrap();
    let root = repo.read_commit(&fx.commit.to_hex()).await.unwrap().0;
    (repo, root)
}
