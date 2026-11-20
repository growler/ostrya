#![forbid(unsafe_code)]

//! Tests of the mount helper `mount.ostrya` with real mounts. Most of them
//! need root in the initial user namespace, `setpriv`, `unshare`, `nsenter`,
//! and user namespaces for an unprivileged user, so they skip elsewhere. If
//! `OSTRYA_REQUIRE_MOUNT` is set, a missing requirement fails them.
//!
//! The tests run the helper with the arguments in the form that mount(8)
//! gives: `<spec> <dir> [-f] [-v] [-o <options>] [-N <namespace>]`. The
//! tests that mount take a lock, so that no two of them run at the same
//! time and each finds the loop device of its own mount.
//!
//! The tests check these facts:
//!
//! - As root in the initial user namespace, the helper mounts the image of
//!   the attachment `composefs`, of the supplement `composefs`, and a built
//!   image, with the flags of `-o`. The source label of the mount is the
//!   commit. After `umount <dir>`, the mount is gone and the loop device
//!   detaches.
//! - As root, with `-N` and a process id or a namespace file, the helper
//!   mounts in the mount namespace of another process, and adds no mount to
//!   its own namespace.
//! - As the user 65534 in its own user namespace and mount namespace, the
//!   helper asks the daemon for each of the three images. `umount <dir>` in
//!   that namespace removes the mount, and the loop device detaches.
//! - With no `-N` in the initial user namespace, a user who is not root gets
//!   a refusal that names `podman unshare` and `-N`, before a connect.
//! - `-f` on each path checks the arguments and finds the image, mounts
//!   nothing, and connects to no daemon.
//! - `rw` is refused on each path, and `noexec` on the daemon path.
//! - mount(8) runs the helper from `/sbin`, as root and as user 0 of a user
//!   namespace. With no `-o`, mount(8) gives `rw`, and the helper refuses it.

mod common;

use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, ChildStdout, Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use common::{
    ChildGuard, Fixture, HELLO, Named, Scratch, Unmount, commit_named, fixture_root,
    image_commit_of, loop_device_of, mounts_at, require_root, root_cfs_of, wait_detached,
};
use ostrya::{Checksum, Ref};

/// The helper binary that Cargo builds.
const HELPER: &str = env!("CARGO_BIN_EXE_mount-ostrya");

/// The name of the helper that mount(8) runs.
const HELPER_NAME: &str = "mount.ostrya";

/// The start of the name of the directory under `/var/tmp` that holds the
/// copy of the helper. The process id of the test process follows it.
const HELPER_DIR_PREFIX: &str = "ostrya-mountd-helper-bin-";

/// The arguments that run a command as the user 65534 with no groups.
const AS_CLIENT: &[&str] = &[
    "setpriv",
    "--reuid=65534",
    "--regid=65534",
    "--clear-groups",
];

/// The arguments that put a command in its own user namespace and mount
/// namespace, as user 0 of the user namespace.
const OWN_USERNS: &[&str] = &["unshare", "-Ur", "-m"];

/// The script of a [`Session`]. It runs its arguments, writes their exit
/// status, waits for a line, unmounts `$DIR`, writes the exit status of the
/// unmount, and waits for the end of its standard input.
const SESSION_SCRIPT: &str = r#""$@" 2>&1; echo "status $?"; read -r _; umount "$DIR" 2>&1; echo "umount $?"; read -r _; exit 0"#;

/// The script of the tests through mount(8). It binds `$BIN` over `/sbin`,
/// runs mount(8) with no `-o` and with `-o ro`, reads the tree, and runs
/// umount(8).
const MOUNT_SCRIPT: &str = r#"m=$(command -v mount) && u=$(command -v umount) || exit 90
"$m" --bind "$BIN" /sbin || exit 91
"$m" -t ostrya "$SPEC" "$DIR" 2>&1; echo "default $?"
"$m" -t ostrya -o ro "$SPEC" "$DIR" 2>&1; echo "mount $?"
echo "hello $(cat "$DIR/hello.txt")"
grep " $DIR " /proc/self/mountinfo | sed 's/^/mountinfo /'
"$u" "$DIR" 2>&1; echo "umount $?"
echo "left $(grep -c " $DIR " /proc/self/mountinfo)""#;

/// The lock of the tests that mount.
static SERIAL: Mutex<()> = Mutex::new(());

/// Takes the lock of the tests that mount.
fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The image that a commit of a test mounts.
#[derive(Debug, Clone, Copy)]
enum Image {
    /// The image of the image commit of the attachment `composefs`.
    Attachment(Checksum),
    /// The image of the image commit of the supplement `composefs`.
    Supplement(Checksum),
    /// A built image.
    Built,
}

/// A commit of a test and its image.
struct Case {
    /// The name of the case, for the target and the messages.
    name: &'static str,
    /// The revision in the spec.
    rev: String,
    /// The commit of the revision.
    commit: Checksum,
    /// The image of the commit.
    image: Image,
}

impl Case {
    /// Returns the line of `-v` for the path `path`.
    fn verbose(&self, path: &str) -> String {
        let image = match self.image {
            Image::Attachment(c) => format!("attachment {c}"),
            Image::Supplement(c) => format!("supplement {c}"),
            Image::Built => "built".to_owned(),
        };
        format!(
            "{HELPER_NAME}: commit {}, image {image}, path {path}",
            self.commit
        )
    }

    /// Returns the test of the backing file of the loop device of the image.
    /// A named image is the loose object of `/root.cfs` of its image commit,
    /// and a built image is a memory file named for the commit.
    fn backing(&self, repo: &Path) -> Box<dyn Fn(&str) -> bool> {
        match self.image {
            Image::Attachment(image) | Image::Supplement(image) => {
                let hex = root_cfs_of(repo, &image).to_hex();
                let tail = format!("objects/{}/{}.file", &hex[..2], &hex[2..]);
                Box::new(move |file| file.ends_with(&tail))
            }
            Image::Built => {
                let head = format!("/memfd:ostrya-cfs-{}", self.commit);
                Box::new(move |file| file.starts_with(&head))
            }
        }
    }
}

/// Returns the three cases of the fixture: the commit of the fixture with
/// the attachment, through the ref `main`, a commit with the supplement, and
/// a commit with neither, whose image is built.
fn cases(fx: &Fixture) -> Vec<Case> {
    let (attachment, _) = image_commit_of(&fx.repo, &fx.commit);
    let (supplemented, supplement, neither) = ostrya_rt::block_on(async {
        let (repo, root) = fixture_root(fx).await;
        repo.set_ref_immediate(&Ref::local("main"), Some(&fx.commit))
            .await
            .unwrap();
        let (supplemented, supplement) =
            commit_named(&repo, &root, "helper supplement", Named::Supplement).await;
        let (neither, _) = commit_named(&repo, &root, "helper neither", Named::Neither).await;
        (supplemented, supplement, neither)
    });
    vec![
        Case {
            name: "attachment",
            rev: "main".to_owned(),
            commit: fx.commit,
            image: Image::Attachment(attachment),
        },
        Case {
            name: "supplement",
            rev: supplemented.to_hex(),
            commit: supplemented,
            image: Image::Supplement(supplement),
        },
        Case {
            name: "built",
            rev: neither.to_hex(),
            commit: neither,
            image: Image::Built,
        },
    ]
}

/// Returns the spec of `rev` in the repository of the fixture.
fn spec(fx: &Fixture, rev: &str) -> OsString {
    let mut spec = fx.repo.clone().into_os_string();
    spec.push(":");
    spec.push(rev);
    spec
}

/// Creates the target directory `name` of the fixture and returns its
/// canonical path.
fn target(fx: &Fixture, name: &str) -> PathBuf {
    std::fs::canonicalize(fx.target(name)).unwrap()
}

/// Returns the directory `sbin` that holds a copy of the helper as
/// `mount.ostrya`, which any user can run. The first call makes the copy,
/// and the tests of the process share it. The directory stays after the
/// process ends. The first call also removes each such directory of a
/// process that no longer runs.
fn install_helper() -> &'static Path {
    static SBIN: OnceLock<PathBuf> = OnceLock::new();
    SBIN.get_or_init(|| {
        let tmp = Path::new("/var/tmp");
        for entry in std::fs::read_dir(tmp).unwrap().flatten() {
            let name = entry.file_name();
            let stale = name
                .to_str()
                .and_then(|n| n.strip_prefix(HELPER_DIR_PREFIX))
                .and_then(|pid| pid.parse::<u32>().ok())
                .is_some_and(|pid| !Path::new(&format!("/proc/{pid}")).exists());
            if stale {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
        let dir = tmp.join(format!("{HELPER_DIR_PREFIX}{}", std::process::id()));
        let sbin = dir.join("sbin");
        std::fs::create_dir_all(&sbin).unwrap();
        for path in [&dir, &sbin] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let helper = sbin.join(HELPER_NAME);
        std::fs::copy(HELPER, &helper).unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        sbin
    })
}

/// Returns a command that runs `program` with the arguments `args`, after
/// the commands of `prefix`.
fn command(prefix: &[&str], program: impl AsRef<OsStr>, args: &[&OsStr]) -> Command {
    let mut cmd = match prefix.split_first() {
        Some((first, rest)) => {
            let mut cmd = Command::new(first);
            cmd.args(rest).arg(program);
            cmd
        }
        None => Command::new(program),
    };
    cmd.args(args).stdin(Stdio::null());
    cmd
}

/// Runs the helper that Cargo builds as the user of the test.
fn helper(args: &[&OsStr]) -> Output {
    command(&[], HELPER, args).output().unwrap()
}

/// Returns the standard error of `out` as text.
fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Asserts that `out` has the exit status `code`.
fn assert_status(out: &Output, code: i32, what: &str) {
    assert_eq!(
        out.status.code(),
        Some(code),
        "{what}: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        stderr(out)
    );
}

/// Returns the lines of the mountinfo text `text` whose mount point is
/// `target`.
fn mount_lines(text: &str, target: &Path) -> Vec<String> {
    let want = target.to_str().unwrap();
    text.lines()
        .filter(|l| l.split(' ').nth(4) == Some(want))
        .map(str::to_owned)
        .collect()
}

/// Asserts that the mountinfo line `line` is the overlay of `commit` with
/// each of the mount options `flags`.
fn assert_mount_line(line: &str, commit: &Checksum, flags: &[&str]) {
    assert!(
        line.contains(&format!(" - overlay {commit} ")),
        "the source is not the commit: {line}"
    );
    let options: Vec<&str> = line.split(' ').nth(5).unwrap().split(',').collect();
    for flag in flags {
        assert!(options.contains(flag), "no {flag}: {line}");
    }
}

/// The mount namespace of a process of a test, which the test reads and
/// changes with `nsenter` as root of the initial user namespace.
struct MountNs {
    pid: u32,
}

impl MountNs {
    /// Returns the path of the mount namespace file of the process.
    fn file(&self) -> String {
        format!("/proc/{}/ns/mnt", self.pid)
    }

    /// Runs `args` in the mount namespace and returns the output.
    fn run(&self, args: &[&OsStr]) -> Output {
        Command::new("nsenter")
            .arg(format!("--mount={}", self.file()))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// Returns the mountinfo lines of the mounts at `target` in the mount
    /// namespace.
    fn mounts(&self, target: &Path) -> Vec<String> {
        let out = self.run(&["cat".as_ref(), "/proc/self/mountinfo".as_ref()]);
        assert!(out.status.success());
        mount_lines(&String::from_utf8_lossy(&out.stdout), target)
    }

    /// Waits at most 10 seconds until the mount namespace of the process is
    /// not the mount namespace of the test.
    fn wait_entered(&self) {
        let own = std::fs::read_link("/proc/self/ns/mnt").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::fs::read_link(self.file()).ok().as_ref() == Some(&own) {
            assert!(
                Instant::now() < deadline,
                "the process never entered its namespace"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// A shell of [`SESSION_SCRIPT`] in a child process: the user 65534 in its
/// own user namespace and mount namespace runs the helper there, and runs
/// `umount` when the test tells it.
struct Session {
    child: ChildGuard,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    ns: MountNs,
}

impl Session {
    /// Starts the shell with the daemon socket `sock`, the target `dir`, and
    /// the helper command `args`.
    fn start(sock: &Path, dir: &Path, args: &[&OsStr]) -> Session {
        let mut child = command(
            &[AS_CLIENT, OWN_USERNS].concat(),
            "/bin/sh",
            &[
                &["-c".as_ref(), SESSION_SCRIPT.as_ref(), "sh".as_ref()],
                args,
            ]
            .concat(),
        )
        .env("OSTRYA_MOUNTD_SOCKET", sock)
        .env("DIR", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let ns = MountNs { pid: child.id() };
        Session {
            child: ChildGuard(Some(child)),
            stdin,
            stdout,
            ns,
        }
    }

    /// Reads the lines up to the line `<key> <status>`. Returns the lines
    /// before it and the status.
    fn read_to(&mut self, key: &str) -> (Vec<String>, i32) {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let n = self.stdout.read_line(&mut line).unwrap();
            assert!(n > 0, "the session ended before {key}: {lines:?}");
            let line = line.trim_end().to_owned();
            if let Some(status) = line.strip_prefix(&format!("{key} ")) {
                return (lines, status.parse().unwrap());
            }
            lines.push(line);
        }
    }

    /// Tells the shell to run `umount`, and returns the lines of its output
    /// and its status. The shell then waits for [`Session::finish`].
    fn umount(&mut self) -> (Vec<String>, i32) {
        self.stdin.as_mut().unwrap().write_all(b"go\n").unwrap();
        self.read_to("umount")
    }

    /// Closes the standard input of the shell and waits for its exit.
    fn finish(mut self) {
        self.stdin = None;
        let status = self.child.wait_for(Duration::from_secs(30)).unwrap();
        assert!(status.success(), "{status}");
    }
}

/// Returns the arguments that run a command as a user who is not root, in
/// the initial user namespace: `setpriv` for a root test process, and none
/// for a test process that is not root. Returns `None` if the test process
/// is not in the initial user namespace.
fn unprivileged_prefix() -> Option<&'static [&'static str]> {
    if ostrya_mount::is_privileged() {
        Some(AS_CLIENT)
    } else if ostrya_mount::in_initial_user_namespace() {
        Some(&[])
    } else {
        None
    }
}

#[test]
fn the_in_process_path_mounts_each_image_and_umount_releases_it() {
    if !require_root() {
        return;
    }
    let _serial = serial();
    let fx = Fixture::new("helper-root");
    for case in cases(&fx) {
        let dir = target(&fx, &format!("mnt-{}", case.name));
        let _unmount = Unmount(dir.clone());
        let out = helper(&[
            &spec(&fx, &case.rev),
            dir.as_os_str(),
            "-v".as_ref(),
            "-o".as_ref(),
            "ro,nosuid,nodev,noexec".as_ref(),
        ]);
        assert_status(&out, 0, case.name);
        assert!(
            stderr(&out).contains(&case.verbose("in-process")),
            "{}",
            stderr(&out)
        );
        let mounts = mounts_at(&dir);
        assert_eq!(mounts.len(), 1, "{}: {mounts:?}", case.name);
        assert_mount_line(
            &mounts[0],
            &case.commit,
            &["ro", "nosuid", "nodev", "noexec"],
        );
        assert_eq!(std::fs::read(dir.join("hello.txt")).unwrap(), HELLO);
        let backing = case.backing(&fx.repo);
        let number = loop_device_of(&*backing).expect("a loop device");
        let out = command(&[], "umount", &[dir.as_os_str()]).output().unwrap();
        assert_status(&out, 0, "umount");
        assert!(mounts_at(&dir).is_empty(), "{}", case.name);
        wait_detached(number, &*backing);
    }
}

#[test]
fn the_in_process_path_mounts_in_the_namespace_of_n() {
    if !require_root() {
        return;
    }
    let _serial = serial();
    let fx = Fixture::new("helper-ns");
    let cases = cases(&fx);
    let selected = [
        (&cases[0], target(&fx, "mnt-file")),
        (&cases[2], target(&fx, "mnt-pid")),
    ];
    let holder = ChildGuard(Some(
        command(
            &["unshare", "-m", "--propagation", "private"],
            "sleep",
            &["600".as_ref()],
        )
        .spawn()
        .unwrap(),
    ));
    let ns = MountNs {
        pid: holder.0.as_ref().unwrap().id(),
    };
    ns.wait_entered();
    for (case, dir) in selected {
        let n = match case.image {
            Image::Built => ns.pid.to_string(),
            _ => ns.file(),
        };
        let out = helper(&[
            &spec(&fx, &case.rev),
            dir.as_os_str(),
            "-v".as_ref(),
            "-o".as_ref(),
            "ro,nosuid".as_ref(),
            "-N".as_ref(),
            n.as_ref(),
        ]);
        assert_status(&out, 0, case.name);
        assert!(
            stderr(&out).contains(&case.verbose("in-process")),
            "{}",
            stderr(&out)
        );
        assert!(mounts_at(&dir).is_empty(), "a mount in the test namespace");
        let mounts = ns.mounts(&dir);
        assert_eq!(mounts.len(), 1, "{}: {mounts:?}", case.name);
        assert_mount_line(&mounts[0], &case.commit, &["ro", "nosuid"]);
        let hello = ns.run(&["cat".as_ref(), dir.join("hello.txt").as_os_str()]);
        assert_eq!(hello.stdout, HELLO);
        let backing = case.backing(&fx.repo);
        let number = loop_device_of(&*backing).expect("a loop device");
        let out = ns.run(&["umount".as_ref(), dir.as_os_str()]);
        assert_status(&out, 0, "umount");
        assert!(ns.mounts(&dir).is_empty(), "{}", case.name);
        wait_detached(number, &*backing);
    }
}

#[test]
fn the_daemon_path_mounts_in_a_user_namespace_and_umount_releases_it() {
    if !require_root() {
        return;
    }
    let _serial = serial();
    let fx = Fixture::new("helper-daemon");
    let sbin = install_helper();
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    for case in cases(&fx) {
        let dir = target(&fx, &format!("mnt-{}", case.name));
        let mut session = Session::start(
            &sock,
            &dir,
            &[
                sbin.join(HELPER_NAME).as_os_str(),
                &spec(&fx, &case.rev),
                dir.as_os_str(),
                "-v".as_ref(),
                "-o".as_ref(),
                "ro".as_ref(),
            ],
        );
        let (lines, status) = session.read_to("status");
        assert_eq!(status, 0, "{}: {lines:?}", case.name);
        assert!(lines.contains(&case.verbose("daemon")), "{lines:?}");
        assert!(mounts_at(&dir).is_empty(), "a mount in the test namespace");
        let mounts = session.ns.mounts(&dir);
        assert_eq!(mounts.len(), 1, "{}: {mounts:?}", case.name);
        assert_mount_line(&mounts[0], &case.commit, &["ro", "nosuid", "nodev"]);
        let hello = session
            .ns
            .run(&["cat".as_ref(), dir.join("hello.txt").as_os_str()]);
        assert_eq!(hello.stdout, HELLO);
        let backing = case.backing(&fx.repo);
        let number = loop_device_of(&*backing).expect("a loop device");
        let (lines, status) = session.umount();
        assert_eq!(status, 0, "umount: {lines:?}");
        assert!(session.ns.mounts(&dir).is_empty(), "{}", case.name);
        session.finish();
        wait_detached(number, &*backing);
    }
}

#[test]
fn the_initial_user_namespace_is_refused_before_a_connect() {
    let Some(prefix) = unprivileged_prefix() else {
        eprintln!("skipped: the test process is not in the initial user namespace");
        return;
    };
    if !prefix.is_empty() && !require_root() {
        return;
    }
    let scratch = Scratch::new("helper-initial");
    let sbin = install_helper();
    let absent = scratch.path().join("absent.sock");
    for fake in [false, true] {
        let mut args: Vec<&OsStr> = vec![
            "/nonexistent-repo:main".as_ref(),
            "/nonexistent-target".as_ref(),
            "-o".as_ref(),
            "ro".as_ref(),
        ];
        if fake {
            args.push("-f".as_ref());
        }
        let out = command(prefix, sbin.join(HELPER_NAME), &args)
            .env("OSTRYA_MOUNTD_SOCKET", &absent)
            .output()
            .unwrap();
        assert_status(&out, 1, "the refusal");
        let text = stderr(&out);
        assert!(text.contains("podman unshare mount"), "{text}");
        assert!(text.contains("-N <pid>"), "{text}");
    }
}

#[test]
fn the_fake_option_mounts_nothing_and_connects_to_no_daemon() {
    if !require_root() {
        return;
    }
    let _serial = serial();
    let fx = Fixture::new("helper-fake");
    let sbin = install_helper();
    let absent = fx.scratch.path().join("absent.sock");
    let cases = cases(&fx);
    for case in [&cases[0], &cases[2]] {
        let dir = target(&fx, &format!("mnt-{}", case.name));
        let args: [&OsStr; 6] = [
            &spec(&fx, &case.rev),
            dir.as_os_str(),
            "-f".as_ref(),
            "-v".as_ref(),
            "-o".as_ref(),
            "ro".as_ref(),
        ];
        let out = helper(&args);
        assert_status(&out, 0, case.name);
        assert!(
            stderr(&out).contains(&case.verbose("in-process")),
            "{}",
            stderr(&out)
        );
        assert!(mounts_at(&dir).is_empty());
        assert!(loop_device_of(&*case.backing(&fx.repo)).is_none());

        let out = command(
            &[AS_CLIENT, OWN_USERNS].concat(),
            sbin.join(HELPER_NAME),
            &args,
        )
        .env("OSTRYA_MOUNTD_SOCKET", &absent)
        .output()
        .unwrap();
        assert_status(&out, 0, case.name);
        assert!(
            stderr(&out).contains(&case.verbose("daemon")),
            "{}",
            stderr(&out)
        );
    }
}

#[test]
fn rw_is_refused_on_each_path_and_noexec_on_the_daemon_path() {
    let args = |options: &'static str| -> [&'static OsStr; 4] {
        [
            "/nonexistent-repo:main".as_ref(),
            "/nonexistent-target".as_ref(),
            "-o".as_ref(),
            options.as_ref(),
        ]
    };
    let out = helper(&args("rw"));
    assert_status(&out, 1, "rw");
    assert!(stderr(&out).contains("-o ro or -r"), "{}", stderr(&out));
    let Some(prefix) = unprivileged_prefix() else {
        eprintln!("skipped: the test process is not in the initial user namespace");
        return;
    };
    if !prefix.is_empty() && !require_root() {
        return;
    }
    let sbin = install_helper();
    for (options, text) in [("rw", "-o ro or -r"), ("ro,noexec", "noexec")] {
        let out = command(prefix, sbin.join(HELPER_NAME), &args(options))
            .output()
            .unwrap();
        assert_status(&out, 1, options);
        assert!(stderr(&out).contains(text), "{}", stderr(&out));
    }
}

/// Runs [`MOUNT_SCRIPT`] after the commands of `prefix`, with the helper
/// directory `bin`, and returns its lines. Returns `None` if the host has
/// no `/sbin`.
fn through_mount(
    prefix: &[&str],
    bin: &Path,
    spec: &OsStr,
    dir: &Path,
    sock: Option<&Path>,
) -> Option<Vec<String>> {
    if !Path::new("/sbin").is_dir() {
        eprintln!("skipped: the host has no /sbin, where mount(8) looks for the helper");
        return None;
    }
    let mut cmd = command(prefix, "/bin/sh", &["-c".as_ref(), MOUNT_SCRIPT.as_ref()]);
    cmd.env("BIN", bin).env("SPEC", spec).env("DIR", dir);
    if let Some(sock) = sock {
        cmd.env("OSTRYA_MOUNTD_SOCKET", sock);
    }
    let out = cmd.output().unwrap();
    assert_status(&out, 0, "the mount script");
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect(),
    )
}

/// Asserts the lines of [`MOUNT_SCRIPT`] for a mount of `commit` at `dir`.
fn assert_mount_script(lines: &[String], commit: &Checksum, flags: &[&str]) {
    let line = |key: &str| {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(key))
            .unwrap_or_else(|| panic!("no {key}: {lines:?}"))
            .to_owned()
    };
    assert_eq!(line("default "), "1", "{lines:?}");
    assert!(lines.iter().any(|l| l.contains("-o ro or -r")), "{lines:?}");
    assert_eq!(line("mount "), "0", "{lines:?}");
    assert_eq!(
        format!("{}\n", line("hello ")).as_bytes(),
        HELLO,
        "{lines:?}"
    );
    assert_mount_line(&line("mountinfo "), commit, flags);
    assert_eq!(line("umount "), "0", "{lines:?}");
    assert_eq!(line("left "), "0", "{lines:?}");
}

#[test]
fn mount_runs_the_helper_as_root() {
    if !require_root() {
        return;
    }
    let _serial = serial();
    let fx = Fixture::new("helper-mount-root");
    let sbin = install_helper();
    let dir = target(&fx, "mnt");
    let Some(lines) = through_mount(
        &["unshare", "-m", "--propagation", "private"],
        sbin,
        &spec(&fx, &fx.commit.to_hex()),
        &dir,
        None,
    ) else {
        return;
    };
    assert_mount_script(&lines, &fx.commit, &["ro"]);
    assert!(mounts_at(&dir).is_empty());
}

#[test]
fn mount_runs_the_helper_in_a_user_namespace() {
    if !require_root() {
        return;
    }
    let _serial = serial();
    let fx = Fixture::new("helper-mount-userns");
    let sbin = install_helper();
    let sock = fx.scratch.path().join("mountd.sock");
    let _daemon = fx.standalone(&sock, None, 60);
    let built = &cases(&fx)[2];
    let dir = target(&fx, "mnt");
    let Some(lines) = through_mount(
        &[AS_CLIENT, OWN_USERNS].concat(),
        sbin,
        &spec(&fx, &built.rev),
        &dir,
        Some(&sock),
    ) else {
        return;
    };
    assert_mount_script(&lines, &built.commit, &["ro", "nosuid", "nodev"]);
    assert!(mounts_at(&dir).is_empty());
}
