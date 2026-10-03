//! Shared helpers for the reading-path integration tests.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub mod modes;
pub mod pipe;
#[cfg(feature = "receive")]
pub mod receive;

/// Root of the tool-generated fixture repositories, one subdirectory per mode.
pub fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/generated")
}

/// The `repo/` path of a fixture, materializing it if needed.
///
/// The `archive` and `bare` fixtures are plain trees and their path is returned
/// directly. The bare-user-family fixtures (`bare-user`, `canon`, `xattr`) store
/// each file's logical metadata in a `user.ostreemeta` xattr, which git does not
/// track, so they ship as tarballs and are unpacked on demand.
pub fn fixture_repo(mode: &str) -> PathBuf {
    match mode {
        "bare-user" | "canon" | "xattr" => unpack_fixture(mode).join("repo"),
        _ => fixture_root().join(mode).join("repo"),
    }
}

/// Unpack the xattr-preserving fixture tarball `<fixture_root>/<name>.tar` once
/// per test process and return the directory holding its `repo/`. The unpack is
/// memoized and persists for the process, so the returned paths stay valid for
/// the whole test run.
pub fn unpack_fixture(name: &str) -> PathBuf {
    static REGISTRY: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = registry.lock().unwrap();
    if let Some(dir) = map.get(name) {
        return dir.clone();
    }
    let dir = std::env::temp_dir()
        .join(format!("ostrya-fixtures-{}", std::process::id()))
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create fixture unpack dir");
    let tar = fixture_root().join(format!("{name}.tar"));
    let status = Command::new("tar")
        .args(["--xattrs", "--xattrs-include=user.*", "-xf"])
        .arg(&tar)
        .arg("-C")
        .arg(&dir)
        .status()
        .expect("run tar to unpack fixture");
    assert!(status.success(), "tar failed to unpack {}", tar.display());
    map.insert(name.to_owned(), dir.clone());
    dir
}

/// The commit and object checksums recorded by the fixture generator. These are
/// mode-independent (the cross-mode commit-identity invariant), so they hold for
/// every fixture repository.
pub const COMMIT: &str = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";
pub const CONTENT: &str = "d79e5560a90877b47660b639e3d7c88c20ca5a7604f867960e155c552025e104";
pub const ROOT_DIRTREE: &str = "1075002e681eb1fe7ff54ae6b76b1f65285e514b54d96deaa0952330b10c7983";
pub const ROOT_DIRMETA: &str = "446a0ef11b7cc167f3b603e585c7eeeeb675faa412d5ec73f62988eb0b6c5488";
pub const EMPTY_TXT: &str = "cc700d46f407c6c5ab2d5dde474366a928b7398277e61162e7f8ec06f469f07e";
pub const HELLO_TXT: &str = "cfffd52f38d14c87cf46e18d5260074421ba5961f0895954e9921f165f9c91db";
pub const LINK: &str = "f66efa496a72379413c44593de510dc344beb045294f1a543da87b2b6118db35";
pub const SUBDIR_DIRTREE: &str = "78154b9650d2a28716fd4a83584a2d9cba1833be4851714d8a0e89e8933c875a";
pub const NESTED_TXT: &str = "a4d80a620354908d76238bea8185775d2f6d60f55a1506d16ee06af212b4a125";
/// The commit of the archive `--generate-sizes` fixture (its metadata carries
/// the `ostree.sizes` key, so it differs from the sizes-free [`COMMIT`]).
pub const SIZES_COMMIT: &str = "3ecadc59022c36743e1b233afbf3bde7b25239b77035185a3acc2af9d84478f0";

/// A throwaway directory removed when dropped.
pub struct TmpDir(PathBuf);

impl TmpDir {
    pub fn new(tag: &str) -> TmpDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ostrya-read-{}-{tag}-{n}", std::process::id()));
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

// ---------------------------------------------------------------------------
// A lock that another process holds.
// ---------------------------------------------------------------------------

/// The environment variable that names the repository of the lock helper.
const FOREIGN_LOCK_REPO: &str = "OSTRYA_TEST_FOREIGN_LOCK_REPO";

/// The environment variable that names the lock file of the lock helper,
/// relative to the repository.
const FOREIGN_LOCK_FILE: &str = "OSTRYA_TEST_FOREIGN_LOCK_FILE";

/// The file the lock helper writes once it holds the lock.
const FOREIGN_LOCK_MARKER: &str = ".foreign-held";

/// The name of the ignored test each test binary that starts a lock helper
/// defines, which calls [`lock_holder_main`].
pub const LOCK_HOLDER_TEST: &str = "lock_holder_subprocess";

/// A spawned child, killed and reaped when the guard drops.
pub struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Wait until `marker` exists, for at most ten seconds.
fn wait_for_marker(marker: &Path, what: &str) {
    let started = Instant::now();
    while !marker.exists() {
        assert!(started.elapsed() < Duration::from_secs(10), "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Start this test binary again as a process that holds `<repo>/<lock_file>`
/// exclusive, with a raw record lock, until it is killed.
pub fn foreign_holder(repo: &Path, lock_file: &str) -> ChildGuard {
    let holder = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([LOCK_HOLDER_TEST, "--exact", "--ignored", "--nocapture"])
            .env(FOREIGN_LOCK_REPO, repo)
            .env(FOREIGN_LOCK_FILE, lock_file)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the lock holder"),
    );
    wait_for_marker(
        &repo.join(FOREIGN_LOCK_MARKER),
        "the holder never took the lock",
    );
    holder
}

/// The body of the lock helper: take the record lock the environment names,
/// write the readiness marker, and wait until standard input closes. Outside
/// a helper process it does nothing.
pub fn lock_holder_main() {
    use rustix::fs::{FlockOperation, Mode, OFlags};
    use std::io::Read;

    let (Ok(repo), Ok(lock_file)) = (
        std::env::var(FOREIGN_LOCK_REPO),
        std::env::var(FOREIGN_LOCK_FILE),
    ) else {
        return;
    };
    let repo = Path::new(&repo);
    let fd = rustix::fs::open(
        repo.join(lock_file),
        OFlags::RDWR | OFlags::CREATE,
        Mode::from_raw_mode(0o660),
    )
    .expect("open the lock file");
    rustix::fs::fcntl_lock(&fd, FlockOperation::LockExclusive).expect("take the record lock");
    std::fs::write(repo.join(FOREIGN_LOCK_MARKER), b"1").expect("write the readiness marker");
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}

// ---------------------------------------------------------------------------
// An update guard that another process holds.
// ---------------------------------------------------------------------------

/// The environment variable that names the repository of the guard helper.
const GUARD_HOLDER_REPO: &str = "OSTRYA_TEST_GUARD_HOLDER_REPO";

/// The file the guard helper writes once it holds the guard.
pub const GUARD_HELD_MARKER: &str = ".guard-held";

/// The file the guard helper writes after its standard input closed and
/// before it releases the guard.
pub const GUARD_RELEASING_MARKER: &str = ".guard-releasing";

/// The name of the ignored test each test binary that starts a guard helper
/// defines, which calls [`guard_holder_main`].
pub const GUARD_HOLDER_TEST: &str = "guard_holder_subprocess";

/// A child process that holds an `UpdateGuard` of one repository.
pub struct GuardHolder {
    child: Option<std::process::Child>,
}

impl GuardHolder {
    /// Close the standard input of the child, so it releases the guard, and
    /// wait for it to exit. Fails when the child failed.
    pub fn release(mut self) {
        let mut child = self.child.take().unwrap();
        drop(child.stdin.take());
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "the guard holder reported {}:\n{stdout}",
            output.status
        );
    }

    /// The process id of the child.
    pub fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }
}

impl Drop for GuardHolder {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Start this test binary again as a process that opens the repository at
/// `repo`, takes an `UpdateGuard`, and holds it until its standard input
/// closes. The call returns once the child holds the guard.
pub fn guard_holder(repo: &Path) -> GuardHolder {
    let child = Command::new(std::env::current_exe().unwrap())
        .args([GUARD_HOLDER_TEST, "--exact", "--ignored", "--nocapture"])
        .env(GUARD_HOLDER_REPO, repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the guard holder");
    let holder = GuardHolder { child: Some(child) };
    wait_for_marker(
        &repo.join(GUARD_HELD_MARKER),
        "the holder never took the guard",
    );
    holder
}

/// The body of the guard helper: take an `UpdateGuard` of the repository
/// the environment names, write the readiness marker, wait until standard
/// input closes, write the releasing marker, and finish the guard. Outside a
/// helper process it does nothing.
pub fn guard_holder_main() {
    use std::io::Read;

    let Some(path) = std::env::var_os(GUARD_HOLDER_REPO).map(PathBuf::from) else {
        return;
    };
    ostrya_rt::block_on(async {
        let repo = ostrya::Repo::open(&path).await.unwrap();
        let guard = repo.begin_update().await.unwrap();
        std::fs::write(path.join(GUARD_HELD_MARKER), b"1").unwrap();
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        std::fs::write(path.join(GUARD_RELEASING_MARKER), b"1").unwrap();
        guard.finish().await.unwrap();
    });
}

// ---------------------------------------------------------------------------
// A writer in another process.
// ---------------------------------------------------------------------------

/// The environment variable that names the repository of the writer helper.
const WRITER_CHILD_REPO: &str = "OSTRYA_TEST_WRITER_CHILD_REPO";

/// The environment variable that carries the argument of the writer helper.
const WRITER_CHILD_ARG: &str = "OSTRYA_TEST_WRITER_CHILD_ARG";

/// The name of the ignored test each test binary that starts a writer helper
/// defines, which calls [`writer_child_main`].
pub const WRITER_CHILD_TEST: &str = "writer_child_subprocess";

/// A child process that runs one write on one repository.
pub struct WriterChild {
    child: Option<std::process::Child>,
}

impl WriterChild {
    /// Wait for the child to exit. Fails when the write failed.
    pub fn wait(mut self) {
        let child = self.child.take().unwrap();
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "the writer reported {}:\n{stdout}",
            output.status
        );
    }

    /// Whether the child has exited.
    pub fn finished(&mut self) -> bool {
        let child = self.child.as_mut().unwrap();
        child.try_wait().unwrap().is_some()
    }
}

impl Drop for WriterChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Start this test binary again as a process that runs the write of the test
/// binary on the repository at `repo`, with the argument `arg`. The call
/// returns at once.
pub fn writer_child(repo: &Path, arg: &str) -> WriterChild {
    let child = Command::new(std::env::current_exe().unwrap())
        .args([WRITER_CHILD_TEST, "--exact", "--ignored", "--nocapture"])
        .env(WRITER_CHILD_REPO, repo)
        .env(WRITER_CHILD_ARG, arg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the writer");
    WriterChild { child: Some(child) }
}

/// The body of the writer helper: run `write` on the repository and the
/// argument the environment names. Outside a helper process it does nothing.
pub fn writer_child_main(write: impl FnOnce(&Path, &str)) {
    let (Some(path), Ok(arg)) = (
        std::env::var_os(WRITER_CHILD_REPO).map(PathBuf::from),
        std::env::var(WRITER_CHILD_ARG),
    ) else {
        return;
    };
    write(&path, &arg);
}

/// The environment variable that turns the reference-absent skip into a
/// failure. A harness setting it declares that `ostree` is installed, so a run
/// where it is not is a broken harness rather than a test to pass over.
pub const REQUIRE_OSTREE: &str = "OSTRYA_REQUIRE_OSTREE";

/// Whether the `ostree` tool is available for cross-check tests. Some of these
/// tests are the proof a matrix record cites with `evidence:`, so a harness
/// without the tool would otherwise report the cited cells as covered while no
/// assertion ran. With [`REQUIRE_OSTREE`] set the absence fails; without it the
/// caller skips and says so.
pub fn ostree_available() -> bool {
    let found = Command::new("ostree")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    assert!(
        found || std::env::var_os(REQUIRE_OSTREE).is_none(),
        "{REQUIRE_OSTREE} is set and `ostree` is not installed, so the \
         tool-comparison tests cannot run"
    );
    found
}

/// The environment variable that turns the ed25519-unsupported skip into a
/// failure. A harness setting it declares that the installed `ostree` carries
/// the engine, so a run where it does not is a broken harness rather than a
/// test to pass over.
pub const REQUIRE_OSTREE_ED25519: &str = "OSTRYA_REQUIRE_OSTREE_ED25519";

/// Whether the `ostree` tool carries its ed25519 signing engine, which
/// `ostree --version` reports as the `sign-ed25519` feature. The engine is a
/// build option: a tool built without it refuses every ed25519 invocation with
/// `Requested signature type is not implemented`.
///
/// Tests that ask the tool to sign or verify with ed25519 skip when the engine
/// is absent. Such a refusal describes the tool's build and states nothing
/// about the port, and it would otherwise satisfy a test that asserts the tool
/// rejects a signature. With [`REQUIRE_OSTREE_ED25519`] set the absence fails.
pub fn ostree_supports_ed25519() -> bool {
    let supported = ostree_available()
        && Command::new("ostree")
            .arg("--version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("sign-ed25519"))
            .unwrap_or(false);
    assert!(
        supported || std::env::var_os(REQUIRE_OSTREE_ED25519).is_none(),
        "{REQUIRE_OSTREE_ED25519} is set and the installed `ostree` carries no \
         ed25519 engine, so the ed25519 cross-check tests cannot run"
    );
    supported
}

/// Whether the `openssl` tool is available for cross-check tests.
pub fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The environment variable that turns the absent-GnuPG skip into a failure. A
/// harness setting it declares that the GnuPG binaries are installed, so a run
/// where one is not is a broken harness rather than a test to pass over.
pub const REQUIRE_GNUPG: &str = "OSTRYA_REQUIRE_GNUPG";

/// Whether every named GnuPG binary answers, naming the absent one when one
/// does not. The GPG cases build their fixtures with `gpg`, and the agreement
/// gate compares against `gpgv`, so a harness without a binary would otherwise
/// report those cases as tested while no assertion ran. With [`REQUIRE_GNUPG`]
/// set the absence fails; without it the caller skips and the name of the
/// absent binary is written to stderr.
pub fn gnupg_available(programs: &[&str]) -> bool {
    for program in programs {
        let found = Command::new(program)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !found {
            assert!(
                std::env::var_os(REQUIRE_GNUPG).is_none(),
                "{REQUIRE_GNUPG} is set and `{program}` is not available, so \
                 the GPG tests cannot run"
            );
            eprintln!("skipping: {program} not available");
            return false;
        }
    }
    true
}

/// Stop every GnuPG daemon of the home directory `dir` and remove the socket
/// directory GnuPG made for it under the user runtime directory. GnuPG names
/// that directory from the path string of `dir`, so the call also works after
/// `dir` is removed. Failures are ignored.
pub fn remove_gnupg_sockets(dir: &Path) {
    for action in [&["--kill", "all"][..], &["--remove-socketdir"][..]] {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(dir)
            .args(action)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Every regular file and symlink under `root/sub`, as its path relative to
/// `root` and its bytes (a symlink's target), sorted by path.
pub fn file_inventory(root: &Path, sub: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.join(sub)];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                out.push((name, target.into_os_string().into_encoded_bytes()));
            } else {
                out.push((name, std::fs::read(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}
