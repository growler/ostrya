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

mod common;

use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{
    ChildGuard, Fixture, HELLO, Named, OWN_NAMESPACES, Unmount, commit_named, file_object_path,
    fixture_root, image_commit_of, key_dict, mounts_at, require_root, wait_for_path, write_source,
};
use ostrya::{
    COMPOSEFS_RELATION, Checksum, CommitOptions, ComposefsOptions, CreateOptions, Repo, RepoMode,
};
use ostrya_mount::{Access, Error, Helper, HelperCode, MountOptions};
use rustix::net::{
    AddressFamily, SocketAddrUnix, SocketFlags, SocketType, bind, listen, socket_with,
};

/// The name of the ignored test that runs a client in a child process.
const CLIENT_TEST: &str = "client_child";

/// The environment variable that gives the request of the client child.
const CLIENT_ENV: &str = "OSTRYA_TEST_MOUNTD_CLIENT";

impl Fixture {
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
            .arg(self.client_bin())
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
            .arg(fx.client_bin())
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
        req.commit = fx.dev_commit();
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
    let (dev_image, _) = image_commit_of(&fx.repo, &fx.dev_commit());
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
    let (dev_image, _) = image_commit_of(&fx.repo, &fx.dev_commit());
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
