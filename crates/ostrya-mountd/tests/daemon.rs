#![forbid(unsafe_code)]

//! Tests of the daemon with real mounts. They need root in the initial user
//! namespace, `setpriv`, `unshare`, and user namespaces for an unprivileged
//! user, so they skip elsewhere. If `OSTRYA_REQUIRE_MOUNT` is set, a missing
//! requirement fails them.
//!
//! The client of each request is this test binary, run again as the user
//! 65534 in a child process. The child runs in its own user namespace and
//! mount namespace, except in the test of the initial user namespace. The
//! scratch directories are under `/var/tmp`, because the user 65534 must
//! reach the repository, the target, and the copy of the test binary.
//!
//! The tests check these facts:
//!
//! - A caller in its own user namespace mounts the image of an image commit
//!   and a built image, read-only and read-write. The mounted tree has the
//!   committed files. A read-write mount writes a new file to
//!   `<target>/overlay`.
//! - A caller in its own PID namespace, with its own `/proc`, mounts and
//!   gets the existing mount on a second request.
//! - A request from the initial user namespace is refused.
//! - An `objects` directory that is a mount of its own is refused.
//! - A built image over the size limit of the daemon is refused.
//! - A request for the image of an image commit and for a built image of an
//!   `archive` repository is refused with the class `repository`.
//! - A symlink at the fan-out directory of the commit, of the image commit,
//!   of its root dirtree, or of the file object of `/root.cfs` for op 1, and
//!   of a commit, a dirtree, a dirmeta, or a file for a built image, is
//!   refused with the class `repository`.
//! - Op 1 mounts the image of the attachment `composefs`, of the supplement
//!   `composefs`, and of the attachment of a commit that also has a bad
//!   supplement. A bad attachment next to a valid supplement, and a commit
//!   with neither, are refused with the class `repository`. Op 2 mounts the
//!   commit with neither.
//! - The refusal of an image commit whose `/root.cfs` is not the key of the
//!   commit names the commit and the image commit, and neither digest.
//! - Each mount of the daemon has `nosuid` and `nodev`. A setuid file in a
//!   read-only and in a read-write mount does not change the user id of a
//!   process that runs it, and a device node in the image does not open.
//!   Both stay so when user 0 of the namespace of the caller clears
//!   `nosuid` and `nodev` on the mount.
//! - The standalone mode, socket activation with `Accept=no`, and socket
//!   activation with `Accept=yes` each serve a request.
//! - The standalone mode exits when the parent process exits and after the
//!   idle time, and removes its socket.
//! - A second request for the same target, label, and access returns the
//!   existing mount and stacks no new mount.
//! - The daemon leaves no temp directory behind.

use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ostrya::{
    COMPOSEFS_RELATION, Checksum, Commit, CommitOptions, ComposefsOptions, CreateOptions, DirMeta,
    DirTree, FileMeta, MutableTree, ObjectType, Repo, RepoMode, Type, Value, Xattrs,
};
use ostrya_mount::{Access, Error, Helper, HelperCode, MountOptions};
use rustix::mount::FsOpenFlags;
use rustix::net::{
    AddressFamily, SocketAddrUnix, SocketFlags, SocketType, bind, listen, socket_with,
};

/// The environment variable that turns the skip of a test into a failure.
const REQUIRE_MOUNT: &str = "OSTRYA_REQUIRE_MOUNT";

/// The commit metadata key that holds the image digest.
const DIGEST_KEY: &str = "ostree.composefs.digest.v0";

/// The user of each client.
const CLIENT_UID: u32 = 65534;

/// The name of the ignored test that runs a client in a child process.
const CLIENT_TEST: &str = "client_child";

/// The environment variable that gives the request of the client child.
const CLIENT_ENV: &str = "OSTRYA_TEST_MOUNTD_CLIENT";

/// The content of `hello.txt` in the committed tree.
const HELLO: &[u8] = b"hello composefs\n";

/// The mode of the empty file `devnode` in the committed tree. The test
/// finds the inode of the file in the image by this mode, and changes it
/// into a character device.
const DEVNODE_MODE: u16 = 0o100602;

/// The device of `devnode` in the changed image: 1:3, `/dev/null`.
const DEVNODE_RDEV: u32 = (1 << 8) | 3;

/// The arguments that put a client in its own user namespace and mount
/// namespace.
const OWN_NAMESPACES: &[&str] = &["unshare", "-Ur", "-m"];

/// A scratch directory under `/var/tmp` that any user can traverse. The
/// directory is removed when the value drops.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from("/var/tmp")
            .join(format!("ostrya-mountd-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Scratch(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A child process that is killed and reaped when the value drops.
struct ChildGuard(Option<Child>);

impl ChildGuard {
    /// Waits at most `limit` for the child to exit and returns its status.
    fn wait_for(&mut self, limit: Duration) -> Option<std::process::ExitStatus> {
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
fn runs(program: &str, args: &[&str]) -> bool {
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
fn require_root() -> bool {
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
struct Fixture {
    scratch: Scratch,
    repo: PathBuf,
    commit: Checksum,
    /// A commit of the same tree with no key, whose image commit holds
    /// `devnode` as a character device.
    dev_commit: Checksum,
    /// A copy of the test binary that the user 65534 can run.
    client_bin: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Fixture {
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
        let (commit, dev_commit) = ostrya_rt::block_on(async {
            let r = Repo::create(&repo, CreateOptions::new(RepoMode::BareUser))
                .await
                .unwrap();
            commit_tree(&r, scratch.path()).await
        });
        let client_bin = scratch.path().join("client");
        std::fs::copy(std::env::current_exe().unwrap(), &client_bin).unwrap();
        std::fs::set_permissions(&client_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        Fixture {
            scratch,
            repo,
            commit,
            dev_commit,
            client_bin,
        }
    }

    /// Creates the empty directory `name`, owned by the client user.
    fn target(&self, name: &str) -> PathBuf {
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
    fn daemon_tmp(&self) -> PathBuf {
        let path = self.scratch.path().join("daemon-tmp");
        let _ = std::fs::create_dir(&path);
        path
    }

    /// Starts the daemon in the standalone mode at `sock`.
    fn standalone(&self, sock: &Path, parent: Option<u32>, idle: u64) -> ChildGuard {
        self.standalone_with(sock, parent, idle, &[])
    }

    /// Starts the daemon in the standalone mode at `sock`, with the options
    /// `extra`.
    fn standalone_with(
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

    /// Runs one client request in a child process and returns its outcome
    /// line. `userns` puts the client in its own user namespace and mount
    /// namespace.
    fn client(&self, sock: &Path, req: &ClientRequest, userns: bool) -> String {
        let unshare = if userns { OWN_NAMESPACES } else { &[] };
        self.client_in(sock, req, unshare)
    }

    /// Runs one client request in a child process that `unshare` starts
    /// with the arguments `unshare`, and returns its outcome line. Empty
    /// arguments leave the client in the namespaces of the test.
    fn client_in(&self, sock: &Path, req: &ClientRequest, unshare: &[&str]) -> String {
        let mut cmd = Command::new("setpriv");
        cmd.args(["--reuid=65534", "--regid=65534", "--clear-groups"]);
        cmd.args(unshare);
        let out = cmd
            .arg(&self.client_bin)
            .args([CLIENT_TEST, "--exact", "--ignored", "--nocapture"])
            .env("OSTRYA_MOUNTD_SOCKET", sock)
            .env(CLIENT_ENV, req.encode())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "the client reported {}:\n{stdout}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        stdout
            .lines()
            .find_map(|l| l.strip_prefix("outcome: "))
            .unwrap_or_default()
            .to_owned()
    }
}

/// Waits at most 10 seconds until `path` exists.
fn wait_for_path(path: &Path) {
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
fn key_dict(digest: &[u8; 32]) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str(DIGEST_KEY.to_owned()),
        Value::variant(Type::parse("ay").unwrap(), Value::Bytes(digest.to_vec())),
    ])])
}

/// How a commit names its image commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Named {
    /// The attachment `composefs`.
    Attachment,
    /// The supplement `composefs`.
    Supplement,
    /// No image commit.
    Neither,
}

/// Writes `base/src` to `repo` and returns its root tree.
async fn write_source(repo: &Repo, base: &Path) -> ostrya::RepoTree {
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
async fn commit_named(
    repo: &Repo,
    root: &ostrya::RepoTree,
    subject: &str,
    named: Named,
) -> (Checksum, Checksum) {
    let txn = repo.transaction().await.unwrap();
    let (image, digest) = txn.write_composefs_commit(root).await.unwrap();
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
async fn write_image_commit(repo: &Repo, image: &[u8]) -> Checksum {
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
/// `composefs`. Returns that commit and a second commit of the same tree
/// with no key, whose attachment `composefs` holds `devnode` as a
/// character device.
async fn commit_tree(repo: &Repo, base: &Path) -> (Checksum, Checksum) {
    let root = write_source(repo, base).await;
    let (commit, _) = commit_named(repo, &root, "mountd tree", Named::Attachment).await;

    // The commit format holds no device node, so the test writes one into a
    // copy of the image. The commit of that image has no key, so the daemon
    // makes no check of the image.
    let mut image = repo
        .export_composefs(&commit, &ComposefsOptions::RECORDED)
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
    let dev_commit = txn.write_commit(opts, &root).await.unwrap();
    txn.commit().await.unwrap();
    (commit, dev_commit)
}

/// Changes the compact inode of the empty file with [`DEVNODE_MODE`] in the
/// EROFS image `image` into the character device [`DEVNODE_RDEV`].
///
/// A compact inode is 32 bytes at a 32-byte boundary. It starts with the
/// format, the xattr count, and the mode, each 16 bits. The device number is
/// at byte 16.
fn make_devnode(image: &mut [u8]) {
    let at = (0..image.len() - 32)
        .step_by(32)
        .find(|&i| {
            image[i..i + 4] == [0, 0, 0, 0] && image[i + 4..i + 6] == DEVNODE_MODE.to_le_bytes()
        })
        .expect("the image holds the inode of devnode");
    image[at + 4..at + 6].copy_from_slice(&(0o020_666u16).to_le_bytes());
    image[at + 16..at + 20].copy_from_slice(&DEVNODE_RDEV.to_le_bytes());
}

/// The request of a client child.
struct ClientRequest {
    repo: PathBuf,
    commit: Checksum,
    target: PathBuf,
    built: bool,
    access: Access,
    /// The number of times the child sends the request.
    times: u32,
}

impl ClientRequest {
    fn encode(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.repo.display(),
            self.commit,
            self.target.display(),
            if self.built { "built" } else { "stored" },
            match self.access {
                Access::ReadOnly => "ro",
                Access::ReadWrite => "rw",
            },
            self.times,
        )
    }

    fn decode(text: &str) -> ClientRequest {
        let f: Vec<&str> = text.split('\n').collect();
        ClientRequest {
            repo: PathBuf::from(f[0]),
            commit: f[1].parse().unwrap(),
            target: PathBuf::from(f[2]),
            built: f[3] == "built",
            access: if f[4] == "rw" {
                Access::ReadWrite
            } else {
                Access::ReadOnly
            },
            times: f[5].parse().unwrap(),
        }
    }

    fn new(fx: &Fixture, target: &Path, built: bool, access: Access) -> ClientRequest {
        ClientRequest {
            repo: fx.repo.clone(),
            commit: fx.commit,
            target: target.to_owned(),
            built,
            access,
            times: 1,
        }
    }
}

/// Returns the mountinfo lines of the mounts at `target`.
fn mounts_at(target: &Path) -> Vec<String> {
    let resolved = std::fs::canonicalize(target).unwrap();
    let want = resolved.to_str().unwrap();
    std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap()
        .lines()
        .filter(|l| l.split(' ').nth(4) == Some(want))
        .map(str::to_owned)
        .collect()
}

/// The body of each client child. Outside a child, the test does nothing.
///
/// The child sends the request, checks the mounted tree, and unmounts it. It
/// prints one line `outcome: <text>`: `mounted <mounts> <flags>` for a
/// mount, where `<mounts>` is the count of mounts at the target before the
/// unmount, or `refused <code>` for an error of the daemon.
#[test]
#[ignore = "runs as the client of a daemon test in a child process"]
fn client_child() {
    let Some(text) = std::env::var_os(CLIENT_ENV) else {
        return;
    };
    let req = ClientRequest::decode(text.to_str().unwrap());
    let outcome = client_outcome(&req);
    println!("outcome: {outcome}");
}

/// Sends the request `req` of a client child, checks the mounted tree, and
/// unmounts it. Returns the text of the line `outcome`.
fn client_outcome(req: &ClientRequest) -> String {
    let helper = Helper::new().unwrap();
    let mut opts = MountOptions::default();
    opts.access = req.access;
    let mut roots = Vec::new();
    for _ in 0..req.times {
        let result = if req.built {
            helper.mount_built(&req.repo, &req.commit, &req.target, &opts)
        } else {
            helper.mount_stored(&req.repo, &req.commit, &req.target, &opts)
        };
        match result {
            Ok(root) => roots.push(root),
            Err(Error::Helper { code, message, .. }) => {
                return format!("refused {code}: {message}");
            }
            Err(other) => panic!("{other}"),
        }
    }
    let first = rustix::fs::fstat(&roots[0]).unwrap();
    for root in &roots[1..] {
        let st = rustix::fs::fstat(root).unwrap();
        assert_eq!((st.st_dev, st.st_ino), (first.st_dev, first.st_ino));
    }
    let mounts = mounts_at(&req.target);
    let top = mounts.last().unwrap().clone();
    assert!(top.contains(&req.commit.to_hex()), "{top}");
    assert_eq!(std::fs::read(req.target.join("hello.txt")).unwrap(), HELLO);
    assert_eq!(
        std::fs::read(req.target.join("sub/nested.txt")).unwrap(),
        b"nested\n"
    );
    let suid = std::fs::metadata(req.target.join("suid-id")).unwrap();
    assert_eq!(suid.permissions().mode() & 0o7777, 0o4755);
    let vfs = rustix::fs::fstatvfs(&roots[0]).unwrap();
    let flags = rustix::fs::StatVfsMountFlags::NOSUID | rustix::fs::StatVfsMountFlags::NODEV;
    assert!(vfs.f_flag.contains(flags), "{:?}", vfs.f_flag);
    let options = top.split(' ').nth(5).unwrap().to_owned();
    if req.access == Access::ReadWrite {
        std::fs::write(req.target.join("new.txt"), b"new\n").unwrap();
    }
    drop(roots);
    helper.unmount(&req.target).unwrap();
    if req.access == Access::ReadWrite {
        assert_eq!(
            std::fs::read(req.target.join("overlay/new.txt")).unwrap(),
            b"new\n"
        );
    }
    format!("mounted {} {options}", mounts.len())
}

/// Creates a listening `SOCK_SEQPACKET` socket at `path` with the mode
/// 0666.
fn listener(path: &Path) -> OwnedFd {
    let sock = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    bind(&sock, &SocketAddrUnix::new(path).unwrap()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
    listen(&sock, 4).unwrap();
    sock
}

/// Starts the daemon with `fd` as descriptor 3 and the variables of systemd
/// socket activation.
fn activated(fx: &Fixture, fd: OwnedFd, idle: u64) -> ChildGuard {
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg(
            r#"exec 3<&0 0</dev/null; export LISTEN_PID=$$ LISTEN_FDS=1; exec "$0" --idle-timeout "$1""#,
        )
        .arg(env!("CARGO_BIN_EXE_ostrya-mountd"))
        .arg(idle.to_string())
        .env("TMPDIR", fx.daemon_tmp())
        .stdin(Stdio::from(fd))
        .spawn()
        .unwrap();
    ChildGuard(Some(child))
}

/// Asserts that the temp directory of the daemon holds no entry.
fn assert_no_temp_dirs(fx: &Fixture) {
    let left: Vec<_> = std::fs::read_dir(fx.daemon_tmp())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "the daemon left {left:?}");
}

#[test]
fn a_caller_in_its_own_namespace_mounts_stored_and_built_images() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("modes");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    for built in [false, true] {
        for access in [Access::ReadOnly, Access::ReadWrite] {
            let name = format!("mnt-{built}-{access:?}");
            let target = fx.target(&name);
            let req = ClientRequest::new(&fx, &target, built, access);
            let outcome = fx.client(&sock, &req, true);
            assert!(outcome.starts_with("mounted 1 "), "{name}: {outcome}");
            assert!(outcome.contains("nosuid"), "{name}: {outcome}");
            assert!(outcome.contains("nodev"), "{name}: {outcome}");
        }
    }
    assert_no_temp_dirs(&fx);
}

#[test]
fn a_request_from_the_initial_user_namespace_is_refused() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("initial");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    let target = fx.target("mnt");
    let req = ClientRequest::new(&fx, &target, false, Access::ReadOnly);
    let outcome = fx.client(&sock, &req, false);
    assert!(
        outcome.starts_with(&format!("refused {}", HelperCode::Namespace)),
        "{outcome}"
    );
    assert!(mounts_at(&target).is_empty());
}

#[test]
fn a_second_request_returns_the_existing_mount() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("remount");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    for access in [Access::ReadOnly, Access::ReadWrite] {
        let target = fx.target(&format!("mnt-{access:?}"));
        let mut req = ClientRequest::new(&fx, &target, false, access);
        req.times = 2;
        let outcome = fx.client(&sock, &req, true);
        assert!(outcome.starts_with("mounted 1 "), "{access:?}: {outcome}");
    }
    assert_no_temp_dirs(&fx);
}

/// A client child that holds its mount in place until the value drops.
struct Holder {
    child: ChildGuard,
    stdin: Option<std::process::ChildStdin>,
    /// The process id of the client, in the user namespace and the mount
    /// namespace of the request.
    pid: u32,
}

impl Holder {
    /// Starts a client child that mounts `req` and keeps the mount until its
    /// standard input closes. Returns when the mount is in place.
    fn start(fx: &Fixture, sock: &Path, req: &ClientRequest, marker: &Path) -> Holder {
        let mut child = Command::new("setpriv")
            .args(["--reuid=65534", "--regid=65534", "--clear-groups"])
            .args(OWN_NAMESPACES)
            .arg(&fx.client_bin)
            .args(["holder_child", "--exact", "--ignored", "--nocapture"])
            .env("OSTRYA_MOUNTD_SOCKET", sock)
            .env(CLIENT_ENV, req.encode())
            .env("OSTRYA_TEST_MOUNTD_MARKER", marker)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let pid = child.id();
        let holder = Holder {
            child: ChildGuard(Some(child)),
            stdin,
            pid,
        };
        wait_for_path(marker);
        holder
    }

    /// Closes the standard input of the child, and asserts that it unmounts
    /// and exits with success.
    fn finish(mut self) {
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = stdin.write_all(b"done\n");
        }
        self.stdin = None;
        let status = self.child.wait_for(Duration::from_secs(30)).unwrap();
        assert!(status.success());
    }

    /// Runs `args` in the mount namespace of the child, as root of the
    /// initial user namespace, and returns the output.
    fn run_in_mount_ns(&self, args: &[&std::ffi::OsStr]) -> std::process::Output {
        Command::new("nsenter")
            .arg(format!("--mount=/proc/{}/ns/mnt", self.pid))
            .args(args)
            .output()
            .unwrap()
    }
}

/// Each mount of the daemon has `nosuid` and `nodev`. The test keeps a
/// client child in its namespaces with a read-only or a read-write mount of
/// an image with a setuid file and a device node. User 0 of the namespace of
/// the client then clears `nosuid` and `nodev` on the mount. The setuid file,
/// run as another user from the mount namespace of the client, does not
/// change the user id, and the device node does not open, also for root of
/// the initial user namespace.
#[test]
fn a_setuid_file_and_a_device_node_stay_inert() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("inert");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    let markers = fx.target("markers");
    for access in [Access::ReadOnly, Access::ReadWrite] {
        let target = fx.target(&format!("mnt-{access:?}"));
        let mut req = ClientRequest::new(&fx, &target, false, access);
        req.commit = fx.dev_commit;
        let holder = Holder::start(&fx, &sock, &req, &markers.join(format!("{access:?}")));

        let kind = holder.run_in_mount_ns(&[
            "stat".as_ref(),
            "-c".as_ref(),
            "%F".as_ref(),
            target.join("devnode").as_os_str(),
        ]);
        assert_eq!(
            String::from_utf8_lossy(&kind.stdout).trim(),
            "character special file",
            "{access:?}: {}",
            String::from_utf8_lossy(&kind.stderr)
        );

        let cleared = Command::new("nsenter")
            .args(["--target", &holder.pid.to_string(), "--user", "--mount"])
            .args(["mount", "-o", "remount,bind,suid,dev"])
            .arg(&target)
            .output()
            .unwrap();
        eprintln!(
            "{access:?}: the clear of nosuid and nodev by user 0 of the namespace: {}",
            if cleared.status.success() {
                "accepted"
            } else {
                "refused"
            }
        );

        let out = holder.run_in_mount_ns(&[
            "setpriv".as_ref(),
            "--reuid=12345".as_ref(),
            "--regid=12345".as_ref(),
            "--clear-groups".as_ref(),
            target.join("suid-id").as_os_str(),
            "-u".as_ref(),
        ]);
        assert!(
            out.status.success(),
            "{access:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "12345",
            "{access:?}"
        );

        let out = holder.run_in_mount_ns(&[
            "dd".as_ref(),
            std::ffi::OsString::from(format!("if={}", target.join("devnode").display()))
                .as_os_str(),
            "of=/dev/null".as_ref(),
            "count=1".as_ref(),
        ]);
        assert!(!out.status.success(), "{access:?}: the device node opens");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("Permission denied"), "{access:?}: {err}");
        holder.finish();
    }
}

/// The body of the holder child of [`a_setuid_file_and_a_device_node_stay_inert`].
/// It mounts, writes the marker, and waits until standard input closes.
#[test]
#[ignore = "runs as the holder of a daemon test in a child process"]
fn holder_child() {
    use std::io::Read;

    let (Some(text), Some(marker)) = (
        std::env::var_os(CLIENT_ENV),
        std::env::var_os("OSTRYA_TEST_MOUNTD_MARKER"),
    ) else {
        return;
    };
    let req = ClientRequest::decode(text.to_str().unwrap());
    let helper = Helper::new().unwrap();
    let mut opts = MountOptions::default();
    opts.access = req.access;
    let root = if req.built {
        helper.mount_built(&req.repo, &req.commit, &req.target, &opts)
    } else {
        helper.mount_stored(&req.repo, &req.commit, &req.target, &opts)
    }
    .unwrap();
    drop(root);
    std::fs::write(&marker, b"1").unwrap();
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    helper.unmount(&req.target).unwrap();
}

/// A caller in its own PID namespace has a `/proc` that does not show the
/// worker of the daemon. It mounts, and a second request gets the existing
/// mount.
#[test]
fn a_caller_in_its_own_pid_namespace_mounts() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("pidns");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    let unshare = ["unshare", "-Ur", "-m", "-p", "-f", "--mount-proc"];
    for (built, access) in [(false, Access::ReadOnly), (true, Access::ReadWrite)] {
        let target = fx.target(&format!("mnt-{built}-{access:?}"));
        let mut req = ClientRequest::new(&fx, &target, built, access);
        req.times = 2;
        let outcome = fx.client_in(&sock, &req, &unshare);
        assert!(outcome.starts_with("mounted 1 "), "{access:?}: {outcome}");
    }
    assert_no_temp_dirs(&fx);
}

/// Unmounts a mount of the test at the path when the value drops.
struct Unmount(PathBuf);

impl Drop for Unmount {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg("-l").arg(&self.0).status();
    }
}

/// An `objects` directory that is the root of a mount is refused. The test
/// bind mounts the directory onto itself before the client makes its
/// namespaces, so the namespace of the client has the mount.
#[test]
fn an_objects_directory_that_is_a_mount_is_refused() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("objects-mount");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    let objects = fx.repo.join("objects");
    assert!(
        Command::new("mount")
            .arg("--bind")
            .arg(&objects)
            .arg(&objects)
            .status()
            .unwrap()
            .success()
    );
    let _unmount = Unmount(objects);
    let target = fx.target("mnt");
    let req = ClientRequest::new(&fx, &target, false, Access::ReadOnly);
    let outcome = fx.client(&sock, &req, true);
    assert!(
        outcome.starts_with(&format!("refused {}", HelperCode::Access)),
        "{outcome}"
    );
    assert!(outcome.contains("not on the mount"), "{outcome}");
}

/// A built image larger than `--max-image-size` is refused with the class
/// `repository`.
#[test]
fn a_built_image_over_the_size_limit_is_refused() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("max-size");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone_with(&sock, None, 60, &["--max-image-size", "4096"]);
    let target = fx.target("mnt");
    let req = ClientRequest::new(&fx, &target, true, Access::ReadOnly);
    let outcome = fx.client(&sock, &req, true);
    assert!(
        outcome.starts_with(&format!("refused {}", HelperCode::Repository)),
        "{outcome}"
    );
    assert!(outcome.contains("more than the limit"), "{outcome}");
    let req = ClientRequest::new(&fx, &target, false, Access::ReadOnly);
    assert!(fx.client(&sock, &req, true).starts_with("mounted 1 "));
}

#[test]
fn socket_activation_with_accept_no_serves_requests_and_exits_when_idle() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("accept-no");
    let sock = fx.scratch.path().join("mountd.sock");
    let fd = listener(&sock);
    let mut daemon = activated(&fx, fd, 3);
    for built in [false, true] {
        let target = fx.target(&format!("mnt-{built}"));
        let req = ClientRequest::new(&fx, &target, built, Access::ReadOnly);
        let outcome = fx.client(&sock, &req, true);
        assert!(outcome.starts_with("mounted 1 "), "{outcome}");
    }
    let status = daemon
        .wait_for(Duration::from_secs(30))
        .expect("the daemon exits when idle");
    assert!(status.success(), "{status}");
    assert_no_temp_dirs(&fx);
}

#[test]
fn socket_activation_with_accept_yes_serves_one_connection() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("accept-yes");
    let sock = fx.scratch.path().join("mountd.sock");
    let lsock = listener(&sock);
    let target = fx.target("mnt");
    let req = ClientRequest::new(&fx, &target, false, Access::ReadWrite);
    let fx_ref = &fx;
    let outcome = std::thread::scope(|scope| {
        let client = scope.spawn(|| fx_ref.client(&sock, &req, true));
        let conn = rustix::net::accept_with(&lsock, SocketFlags::CLOEXEC).unwrap();
        let mut daemon = activated(fx_ref, conn, 3);
        let outcome = client.join().unwrap();
        let status = daemon
            .wait_for(Duration::from_secs(30))
            .expect("the daemon exits");
        assert!(status.success(), "{status}");
        outcome
    });
    assert!(outcome.starts_with("mounted 1 "), "{outcome}");
    assert_no_temp_dirs(&fx);
}

#[test]
fn the_standalone_mode_exits_after_the_idle_time() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("idle");
    let sock = fx.scratch.path().join("mountd.sock");
    let started = Instant::now();
    let mut daemon = fx.standalone(&sock, None, 1);
    let status = daemon
        .wait_for(Duration::from_secs(30))
        .expect("the daemon exits");
    assert!(status.success(), "{status}");
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert!(!sock.exists(), "the daemon removes its socket");
}

#[test]
fn the_standalone_mode_exits_when_the_parent_exits() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("parent");
    let sock = fx.scratch.path().join("mountd.sock");
    let mut parent = ChildGuard(Some(Command::new("sleep").arg("600").spawn().unwrap()));
    let parent_pid = parent.0.as_ref().unwrap().id();
    let mut daemon = fx.standalone(&sock, Some(parent_pid), 600);
    let target = fx.target("mnt");
    let req = ClientRequest::new(&fx, &target, false, Access::ReadOnly);
    assert!(fx.client(&sock, &req, true).starts_with("mounted 1 "));
    let mut sleeper = parent.0.take().unwrap();
    sleeper.kill().unwrap();
    sleeper.wait().unwrap();
    let status = daemon
        .wait_for(Duration::from_secs(10))
        .expect("the daemon exits");
    assert_eq!(status.code(), Some(1));
    assert!(!sock.exists(), "the daemon removes its socket");
}

/// Replaces the directory `path` with a symlink to `moved`, runs `f`, and
/// puts the directory back.
fn with_symlink(path: &Path, moved: &Path, f: impl FnOnce()) {
    std::fs::rename(path, moved).unwrap();
    std::os::unix::fs::symlink(moved, path).unwrap();
    f();
    std::fs::remove_file(path).unwrap();
    std::fs::rename(moved, path).unwrap();
}

/// Returns the `.file` object of `repo` that holds [`HELLO`].
fn hello_object(repo: &Path) -> PathBuf {
    for dir in std::fs::read_dir(repo.join("objects")).unwrap().flatten() {
        for obj in std::fs::read_dir(dir.path()).unwrap().flatten() {
            let path = obj.path();
            if path.extension().is_some_and(|e| e == "file")
                && obj.file_type().unwrap().is_file()
                && std::fs::read(&path).unwrap() == HELLO
            {
                return path;
            }
        }
    }
    panic!("no object holds the content");
}

/// Returns the image commit that `commit` names as the attachment
/// `composefs` in the repository at `repo`, and the file object of its
/// `/root.cfs`.
fn image_commit_of(repo: &Path, commit: &Checksum) -> (Checksum, Checksum) {
    ostrya_rt::block_on(async {
        let repo = Repo::open(repo).await.unwrap();
        let relations = repo.read_commit_relations(commit).await.unwrap();
        let image = relations.attachments[0].1;
        let (image_obj, _) = repo.load_commit(&image).await.unwrap();
        let tree = repo.load_dirtree(&image_obj.root_dirtree).await.unwrap();
        (image, tree.files[0].1)
    })
}

/// Returns the path of the loose file object `object` in the `bare-user`
/// repository at `repo`.
fn file_object_path(repo: &Path, object: &Checksum) -> PathBuf {
    let hex = object.to_hex();
    repo.join("objects")
        .join(&hex[..2])
        .join(format!("{}.file", &hex[2..]))
}

/// A symlink at the fan-out directory of an object that the daemon reads is
/// refused with the class `repository`, and the target stays empty. Op 1
/// reads the commit, the image commit, its root dirtree, and the file object
/// of `/root.cfs`. Op 2 reads the commit, the dirtrees, the dirmetas, and
/// the files.
#[test]
fn a_symlink_in_the_repository_is_refused() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("symlinks");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    let target = fx.target("mnt");
    let moved = fx.scratch.path().join("moved");
    let refused = |built: bool, what: &str| {
        let req = ClientRequest::new(&fx, &target, built, Access::ReadOnly);
        let outcome = fx.client(&sock, &req, true);
        assert!(
            outcome.starts_with(&format!("refused {}", HelperCode::Repository)),
            "{what}: {outcome}"
        );
        assert!(mounts_at(&target).is_empty(), "{what}");
    };

    let hex = fx.commit.to_hex();
    let (commit_obj, image_obj) = ostrya_rt::block_on(async {
        let repo = Repo::open(&fx.repo).await.unwrap();
        let (commit_obj, _) = repo.load_commit(&fx.commit).await.unwrap();
        let image = repo
            .read_commit_relations(&fx.commit)
            .await
            .unwrap()
            .attachments[0]
            .1;
        (commit_obj, repo.load_commit(&image).await.unwrap().0)
    });
    let (image, image_file) = image_commit_of(&fx.repo, &fx.commit);
    let objects = fx.repo.join("objects");
    let fanout = |hex: String| objects.join(&hex[..2]);
    for (what, dir) in [
        ("commit", fanout(hex.clone())),
        ("image commit", fanout(image.to_hex())),
        ("image dirtree", fanout(image_obj.root_dirtree.to_hex())),
        ("image file", fanout(image_file.to_hex())),
    ] {
        with_symlink(&dir, &moved, || refused(false, what));
    }
    let hello = hello_object(&fx.repo);
    for (what, dir) in [
        ("commit", fanout(hex.clone())),
        ("dirtree", fanout(commit_obj.root_dirtree.to_hex())),
        ("dirmeta", fanout(commit_obj.root_dirmeta.to_hex())),
        ("file", hello.parent().unwrap().to_owned()),
    ] {
        with_symlink(&dir, &moved, || refused(true, what));
    }
    let req = ClientRequest::new(&fx, &target, false, Access::ReadOnly);
    assert!(fx.client(&sock, &req, true).starts_with("mounted 1 "));
    assert_no_temp_dirs(&fx);
}

/// The refusal of an image commit whose `/root.cfs` does not match the key
/// of the commit names the commit and the image commit, and neither digest.
#[test]
fn the_refusal_of_a_changed_image_names_no_digest() {
    use std::io::{Read, Seek, SeekFrom, Write};

    if !require_root() {
        return;
    }
    let fx = Fixture::new("mismatch");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    let (image, image_file) = image_commit_of(&fx.repo, &fx.commit);
    // The change writes in place, so the object keeps its xattrs.
    let path = file_object_path(&fx.repo, &image_file);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let middle = file.metadata().unwrap().len() / 2;
    let mut byte = [0u8; 1];
    file.seek(SeekFrom::Start(middle)).unwrap();
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xff;
    file.seek(SeekFrom::Start(middle)).unwrap();
    file.write_all(&byte).unwrap();
    drop(file);
    let (expected, actual) = ostrya_rt::block_on(async {
        let repo = Repo::open(&fx.repo).await.unwrap();
        match repo.open_composefs_image(&fx.commit).await {
            Err(ostrya::Error::InvalidComposefsImage { defect, .. }) => match *defect {
                ostrya::ComposefsImageDefect::DigestMismatch { expected, actual } => {
                    (expected, actual)
                }
                other => panic!("expected DigestMismatch, got {other:?}"),
            },
            other => panic!("the changed image has the key: {:?}", other.map(|_| ())),
        }
    });
    let target = fx.target("mnt");
    let req = ClientRequest::new(&fx, &target, false, Access::ReadOnly);
    let outcome = fx.client(&sock, &req, true);
    assert!(
        outcome.starts_with(&format!("refused {}", HelperCode::Repository)),
        "{outcome}"
    );
    assert!(outcome.contains(&fx.commit.to_hex()), "{outcome}");
    assert!(outcome.contains(&image.to_hex()), "{outcome}");
    assert!(outcome.contains("does not match the key"), "{outcome}");
    for digest in [expected, actual] {
        let hex = Checksum::from_bytes(digest).to_hex();
        assert!(!outcome.contains(&hex), "{outcome}");
    }
    assert!(mounts_at(&target).is_empty());
}

/// An `archive` repository stores compressed `.filez` objects, so the daemon
/// refuses a request for the image of an image commit and for a built image
/// with the class `repository`, and the target stays empty.
#[test]
fn an_archive_repository_is_refused() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("archive");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    let archive = fx.scratch.path().join("archive");
    let commit = ostrya_rt::block_on(async {
        let repo = Repo::create(&archive, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let root = write_source(&repo, fx.scratch.path()).await;
        commit_named(&repo, &root, "archive", Named::Attachment)
            .await
            .0
    });
    let target = fx.target("mnt");
    for built in [false, true] {
        let req = ClientRequest {
            repo: archive.clone(),
            commit,
            target: target.clone(),
            built,
            access: Access::ReadOnly,
            times: 1,
        };
        let outcome = fx.client(&sock, &req, true);
        assert!(
            outcome.starts_with(&format!("refused {}", HelperCode::Repository)),
            "built={built}: {outcome}"
        );
        assert!(
            outcome.contains("a repository of the mode archive-z2 cannot be mounted"),
            "built={built}: {outcome}"
        );
        assert!(mounts_at(&target).is_empty(), "built={built}");
        assert_eq!(
            std::fs::read_dir(&target).unwrap().count(),
            0,
            "built={built}"
        );
    }
    assert_no_temp_dirs(&fx);
}

/// Opens the repository of the fixture and returns it with the root tree
/// of the commit of the fixture.
async fn fixture_root(fx: &Fixture) -> (Repo, ostrya::RepoTree) {
    let repo = Repo::open(&fx.repo).await.unwrap();
    let root = repo.read_commit(&fx.commit.to_hex()).await.unwrap().0;
    (repo, root)
}

/// Op 1 mounts the image of the supplement `composefs`, and of the
/// attachment of a commit that has both. The supplement of that commit
/// names an image commit whose image is not the key, and the daemon does
/// not read it.
#[test]
fn op_1_mounts_the_image_of_a_supplement_and_of_both() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("op1-sources");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    let (dev_image, _) = image_commit_of(&fx.repo, &fx.dev_commit);
    let (supplement, both) = ostrya_rt::block_on(async {
        let (repo, root) = fixture_root(&fx).await;
        let (supplement, _) = commit_named(&repo, &root, "supplement", Named::Supplement).await;
        let (both, _) = commit_named(&repo, &root, "both", Named::Attachment).await;
        repo.add_supplement(&both, COMPOSEFS_RELATION, &dev_image)
            .await
            .unwrap();
        (supplement, both)
    });
    for (what, commit) in [("supplement", supplement), ("both", both)] {
        let target = fx.target(&format!("mnt-{what}"));
        let mut req = ClientRequest::new(&fx, &target, false, Access::ReadOnly);
        req.commit = commit;
        let outcome = fx.client(&sock, &req, true);
        assert!(outcome.starts_with("mounted 1 "), "{what}: {outcome}");
    }
    assert_no_temp_dirs(&fx);
}

/// Op 1 refuses a commit whose attachment `composefs` names an image commit
/// with an image that is not the key, also if a valid supplement exists. The
/// text names the attachment.
#[test]
fn op_1_refuses_a_bad_attachment_next_to_a_valid_supplement() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("op1-bad-attachment");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    let (dev_image, _) = image_commit_of(&fx.repo, &fx.dev_commit);
    let (valid, _) = image_commit_of(&fx.repo, &fx.commit);
    let commit = ostrya_rt::block_on(async {
        let (repo, root) = fixture_root(&fx).await;
        let digest = repo
            .export_composefs(&fx.commit, &ComposefsOptions::RECORDED)
            .await
            .unwrap()
            .fs_verity;
        let txn = repo.transaction().await.unwrap();
        let opts = CommitOptions {
            subject: Some("bad attachment".to_owned()),
            timestamp: Some(1),
            metadata: Some(key_dict(&digest)),
            attachments: vec![(COMPOSEFS_RELATION.to_owned(), dev_image)],
            ..CommitOptions::default()
        };
        let commit = txn.write_commit(opts, &root).await.unwrap();
        txn.add_supplement(&commit, COMPOSEFS_RELATION, &valid)
            .unwrap();
        txn.commit().await.unwrap();
        commit
    });
    let target = fx.target("mnt");
    let mut req = ClientRequest::new(&fx, &target, false, Access::ReadOnly);
    req.commit = commit;
    let outcome = fx.client(&sock, &req, true);
    assert_eq!(
        outcome,
        format!(
            "refused {}: composefs image of commit {commit}: attachment composefs names \
             commit {dev_image}, whose /root.cfs does not match the key of the commit",
            HelperCode::Repository
        )
    );
    assert!(mounts_at(&target).is_empty());
}

/// Op 1 refuses a commit with no attachment and no supplement `composefs`
/// with the class `repository`. Op 2 mounts the built image of the same
/// commit.
#[test]
fn op_1_refuses_a_commit_with_no_image_commit() {
    if !require_root() {
        return;
    }
    let fx = Fixture::new("op1-neither");
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    let commit = ostrya_rt::block_on(async {
        let (repo, root) = fixture_root(&fx).await;
        commit_named(&repo, &root, "neither", Named::Neither)
            .await
            .0
    });
    let target = fx.target("mnt");
    let mut req = ClientRequest::new(&fx, &target, false, Access::ReadOnly);
    req.commit = commit;
    let outcome = fx.client(&sock, &req, true);
    assert_eq!(
        outcome,
        format!(
            "refused {}: commit {commit} has no attachment or supplement composefs",
            HelperCode::Repository
        )
    );
    assert!(mounts_at(&target).is_empty());
    req.built = true;
    let outcome = fx.client(&sock, &req, true);
    assert!(outcome.starts_with("mounted 1 "), "{outcome}");
    assert_no_temp_dirs(&fx);
}
