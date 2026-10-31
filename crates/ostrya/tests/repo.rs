//! Integration tests of the open and the creation of a repository.
//!
//! The tests check three things:
//!
//! - ostrya opens a repository that the `ostree` command created, and reads its
//!   mode and its config.
//! - ostrya creates a repository with the same `config` bytes and the same
//!   layout as the `ostree` command writes.
//! - The `ostree` command opens a repository that ostrya creates, and operates
//!   on it.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use common::{fixture_repo, ostree_available};
use futures_lite::future::poll_once;
use ostrya::{CreateOptions, Error, Repo, RepoMode};
use ostrya_rt::block_on;

/// A temporary directory. `Drop` removes it.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ostrya-test-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        TmpDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn opens_fixture_repos_and_reads_mode() {
    for (mode_dir, expected) in [
        ("archive", RepoMode::Archive),
        ("bare-user", RepoMode::BareUser),
    ] {
        let repo_path = fixture_repo(mode_dir);
        let repo = block_on(Repo::open(&repo_path)).expect("open fixture repo");
        assert_eq!(repo.mode(), expected, "mode for {mode_dir}");
        assert_eq!(repo.config().repo_version(), 1);
    }
}

#[test]
fn create_writes_exact_config_bytes() {
    let cases = [
        (
            CreateOptions::new(RepoMode::Archive),
            "[core]\nrepo_version=1\nmode=archive-z2\n",
        ),
        (
            CreateOptions::new(RepoMode::Bare),
            "[core]\nrepo_version=1\nmode=bare\n",
        ),
        (
            CreateOptions {
                mode: RepoMode::Bare,
                collection_id: Some("org.example.Foo".to_owned()),
            },
            "[core]\nrepo_version=1\nmode=bare\ncollection-id=org.example.Foo\n",
        ),
    ];
    for (i, (opts, expected)) in cases.into_iter().enumerate() {
        let tmp = TmpDir::new(&format!("cfg{i}"));
        let repo_path = tmp.path().join("repo");
        block_on(Repo::create(&repo_path, opts)).expect("create repo");
        let bytes = std::fs::read(repo_path.join("config")).expect("read config");
        assert_eq!(bytes, expected.as_bytes(), "config bytes for case {i}");
    }
}

#[test]
fn create_builds_expected_layout() {
    let tmp = TmpDir::new("layout");
    let repo_path = tmp.path().join("repo");
    let repo = block_on(Repo::create(&repo_path, CreateOptions::new(RepoMode::Bare)))
        .expect("create repo");
    assert_eq!(repo.mode(), RepoMode::Bare);

    for dir in [
        "objects",
        "refs/heads",
        "refs/remotes",
        "refs/mirrors",
        "state",
        "tmp",
        "tmp/cache",
        "extensions",
    ] {
        assert!(repo_path.join(dir).is_dir(), "missing directory {dir}");
    }

    let config_mode = std::fs::metadata(repo_path.join("config"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(config_mode, 0o644, "config file mode");
}

#[test]
fn create_is_idempotent_and_preserves_config() {
    let tmp = TmpDir::new("idem");
    let repo_path = tmp.path().join("repo");
    block_on(Repo::create(&repo_path, CreateOptions::new(RepoMode::Bare))).expect("first create");
    // A second create with a different mode must keep the original config.
    // `ostree init` does the same.
    let repo = block_on(Repo::create(
        &repo_path,
        CreateOptions::new(RepoMode::Archive),
    ))
    .expect("second create");
    assert_eq!(repo.mode(), RepoMode::Bare, "original mode is preserved");
    let bytes = std::fs::read(repo_path.join("config")).unwrap();
    assert_eq!(bytes, b"[core]\nrepo_version=1\nmode=bare\n");
}

#[test]
fn create_then_reopen_roundtrip() {
    let tmp = TmpDir::new("roundtrip");
    let repo_path = tmp.path().join("repo");
    block_on(Repo::create(
        &repo_path,
        CreateOptions::new(RepoMode::BareUser),
    ))
    .expect("create");
    let repo = block_on(Repo::open(&repo_path)).expect("reopen");
    assert_eq!(repo.mode(), RepoMode::BareUser);
}

#[test]
fn open_at_and_create_at_use_the_dir_fd() {
    let tmp = TmpDir::new("atfd");
    let parent = std::fs::File::open(tmp.path()).unwrap();
    let parent_fd = std::os::fd::AsFd::as_fd(&parent);

    block_on(Repo::create_at(
        parent_fd,
        Path::new("repo"),
        CreateOptions::new(RepoMode::Archive),
    ))
    .expect("create_at");

    let repo = block_on(Repo::open_at(parent_fd, Path::new("repo"))).expect("open_at");
    assert_eq!(repo.mode(), RepoMode::Archive);
}

/// Returns a path that names `target` relative to the current working
/// directory. Each component of the working directory becomes one `..`, and the
/// components of `target` come after them. The result resolves to `target`.
/// The function does not change the working directory of the process, because
/// all tests in this binary share it.
///
/// Both paths must be absolute, so the first component of each is the root
/// directory, and `skip(1)` drops it. If the working directory is the root, it
/// gives no `..`, and the result is still relative.
fn relative_to_cwd(target: &Path) -> PathBuf {
    let cwd = std::env::current_dir().expect("current dir");
    assert!(cwd.is_absolute(), "the working directory is absolute");
    assert!(target.is_absolute(), "the target is absolute: {target:?}");
    let mut rel = PathBuf::new();
    for _ in cwd.components().skip(1) {
        rel.push("..");
    }
    for part in target.components().skip(1) {
        rel.push(part);
    }
    rel
}

/// `Repo::path` returns the argument that `create` and `open` got, with no
/// resolution. A relative path stays relative, with its `..` components. The
/// `config` file under the absolute path shows that the relative path names the
/// intended directory.
#[test]
fn path_reports_the_relative_argument_create_and_open_were_given() {
    let tmp = TmpDir::new("relpath");
    let absolute = tmp.path().join("repo");
    let relative = relative_to_cwd(&absolute);
    assert!(relative.is_relative(), "the test path is relative");

    let created = block_on(Repo::create(
        &relative,
        CreateOptions::new(RepoMode::Archive),
    ))
    .expect("create through the relative path");
    assert_eq!(
        created.path(),
        relative.as_path(),
        "create stores the relative argument unchanged"
    );
    assert!(
        absolute.join("config").is_file(),
        "the relative path named the intended directory"
    );

    let opened = block_on(Repo::open(&relative)).expect("open through the relative path");
    assert_eq!(opened.mode(), RepoMode::Archive, "the repository opened");
    assert_eq!(
        opened.path(),
        relative.as_path(),
        "open stores the relative argument unchanged"
    );
}

/// `Repo::path` returns the `dir`-relative argument that `create_at` and
/// `open_at` got. Only that fd resolves the path.
#[test]
fn path_reports_the_dir_relative_argument_the_at_constructors_were_given() {
    let tmp = TmpDir::new("atpath");
    let parent = std::fs::File::open(tmp.path()).unwrap();
    let parent_fd = std::os::fd::AsFd::as_fd(&parent);

    let created = block_on(Repo::create_at(
        parent_fd,
        Path::new("repo"),
        CreateOptions::new(RepoMode::Bare),
    ))
    .expect("create_at");
    assert_eq!(
        created.path(),
        Path::new("repo"),
        "create_at stores the dir-relative argument unchanged"
    );
    assert!(
        tmp.path().join("repo").join("config").is_file(),
        "the dir-relative path named the intended directory"
    );

    let opened = block_on(Repo::open_at(parent_fd, Path::new("repo"))).expect("open_at");
    assert_eq!(
        opened.path(),
        Path::new("repo"),
        "open_at stores the dir-relative argument unchanged"
    );
}

#[test]
fn open_rejects_unsupported_repo_version() {
    let tmp = TmpDir::new("badver");
    let repo_path = tmp.path().join("repo");
    block_on(Repo::create(&repo_path, CreateOptions::new(RepoMode::Bare))).expect("create");
    std::fs::write(
        repo_path.join("config"),
        b"[core]\nrepo_version=2\nmode=bare\n",
    )
    .unwrap();
    let err = block_on(Repo::open(&repo_path)).unwrap_err();
    assert!(err.to_string().contains("version 2"), "got: {err}");
}

#[test]
fn open_missing_repo_is_io_error() {
    let tmp = TmpDir::new("missing");
    let err = block_on(Repo::open(&tmp.path().join("nope"))).unwrap_err();
    assert!(matches!(err, ostrya::Error::Io(_)));
}

#[test]
fn tool_operates_on_created_repo() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not on PATH");
        return;
    }
    let tmp = TmpDir::new("toolop");
    let repo_path = tmp.path().join("repo");
    block_on(Repo::create(
        &repo_path,
        CreateOptions::new(RepoMode::Archive),
    ))
    .expect("create");

    let mode = Command::new("ostree")
        .arg(format!("--repo={}", repo_path.display()))
        .args(["config", "get", "core.mode"])
        .output()
        .expect("run ostree config get");
    assert!(mode.status.success(), "ostree config get failed: {mode:?}");
    assert_eq!(String::from_utf8_lossy(&mode.stdout).trim(), "archive-z2");

    // The `ostree` command accepts the repository for a write operation. A
    // commit of an empty tree succeeds, and this needs a well-formed layout.
    let src = tmp.path().join("tree");
    std::fs::create_dir_all(&src).unwrap();
    let commit = Command::new("ostree")
        .arg(format!("--repo={}", repo_path.display()))
        .args(["commit", "--branch=test", "--subject=x", "--orphan"])
        .arg(&src)
        .output()
        .expect("run ostree commit");
    assert!(
        commit.status.success(),
        "ostree commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
}

/// `Repo::write_config` replaces `config` with an edited document and keeps
/// the mode of the file. A reopen reads the new values.
#[test]
fn write_config_replaces_the_document_and_keeps_the_mode() {
    let tmp = TmpDir::new("write-config");
    let repo_path = tmp.path().join("repo");
    let repo = block_on(Repo::create(
        &repo_path,
        CreateOptions::new(RepoMode::Archive),
    ))
    .expect("create");

    let mut keyfile = repo.config().keyfile().clone();
    keyfile.set_string("core", "fsync", "false").expect("set");
    keyfile
        .set_string("remote \"origin\"", "url", "https://example.invalid/r")
        .expect("set");
    keyfile.set_string("core", "gone", "x").expect("set");
    assert!(keyfile.remove_key("core", "gone"));
    block_on(repo.write_config(&keyfile)).expect("write config");

    let config = repo_path.join("config");
    assert_eq!(
        std::fs::read_to_string(&config).expect("read config"),
        "[core]\nrepo_version=1\nmode=archive-z2\nfsync=false\n\n\
         [remote \"origin\"]\nurl=https://example.invalid/r\n"
    );
    assert_eq!(
        std::fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o644,
        "the rewritten config keeps mode 0644"
    );

    // The handle that wrote the config keeps the config that it opened with. A
    // reopen reads the new config.
    assert!(repo.config().fsync().expect("fsync"));
    let reopened = block_on(Repo::open(&repo_path)).expect("reopen");
    assert!(!reopened.config().fsync().expect("fsync"));
    assert_eq!(
        reopened
            .config()
            .remote("origin")
            .expect("the remote section")
            .url()
            .expect("url")
            .as_deref(),
        Some("https://example.invalid/r")
    );

    // The keyring of a remote goes with its section. `remove_remote_keyring`
    // deletes it.
    let keyring = repo_path.join("origin.trustedkeys.gpg");
    std::fs::write(&keyring, b"not a real keyring").unwrap();
    block_on(reopened.remove_remote_keyring("origin")).expect("remove keyring");
    assert!(!keyring.exists());
    // If the keyring is already absent, the removal succeeds.
    block_on(reopened.remove_remote_keyring("origin")).expect("remove keyring again");
}

/// `Repo::remove_remote_keyring` refuses a remote name that
/// `valid_remote_name` refuses, with `Error::InvalidInput`. The file that the
/// join of the name to the repository reaches stays. The call refuses the name
/// at its first poll, before it takes a lock.
#[test]
fn remove_remote_keyring_refuses_an_invalid_remote_name() {
    let tmp = TmpDir::new("remove-keyring-invalid");
    let outside = tmp.path().join("x.trustedkeys.gpg");
    std::fs::write(&outside, b"outside").unwrap();
    let repo = block_on(Repo::create(
        &tmp.path().join("repo"),
        CreateOptions::new(RepoMode::Archive),
    ))
    .expect("create");

    let err = block_on(repo.remove_remote_keyring("../x")).unwrap_err();
    assert!(
        matches!(&err, Error::InvalidInput(m) if m == "invalid remote name: ../x"),
        "{err:?}"
    );
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside");

    let first = block_on(poll_once(repo.remove_remote_keyring("../x")));
    assert!(
        matches!(&first, Some(Err(Error::InvalidInput(m))) if m == "invalid remote name: ../x"),
        "{first:?}"
    );
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
}

/// Creates a `bare-user` repository `repo` under `tmp` and returns a
/// descriptor of `tmp`.
fn strict_fixture(tmp: &TmpDir) -> std::fs::File {
    block_on(Repo::create(
        &tmp.path().join("repo"),
        CreateOptions::new(RepoMode::BareUser),
    ))
    .expect("create");
    std::fs::File::open(tmp.path()).unwrap()
}

/// Runs `open` on a new thread and waits at most 10 seconds for it, so that
/// an open that blocks fails the test.
fn open_in_time(
    open: impl FnOnce() -> ostrya::Result<Repo> + Send + 'static,
) -> ostrya::Result<Repo> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(open());
    });
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .expect("the open returns in time")
}

/// The strict open mode refuses a `config` that is a symlink. The default
/// open follows it.
#[test]
fn the_strict_open_refuses_a_symlinked_config() {
    let tmp = TmpDir::new("strict-link");
    let parent = strict_fixture(&tmp);
    let repo = tmp.path().join("repo");
    std::fs::rename(repo.join("config"), tmp.path().join("real-config")).unwrap();
    std::os::unix::fs::symlink("../real-config", repo.join("config")).unwrap();

    let fd = std::os::fd::AsFd::as_fd(&parent);
    block_on(Repo::open_at(fd, Path::new("repo"))).expect("the default open follows it");
    let err = block_on(Repo::open_at_strict(fd, Path::new("repo"))).unwrap_err();
    match err {
        ostrya::Error::Io(e) => assert_eq!(e.raw_os_error(), Some(eloop()), "{e}"),
        other => panic!("{other}"),
    }
}

/// The strict open mode refuses a `config` that is a FIFO, and the open does
/// not wait for a writer.
#[test]
fn the_strict_open_refuses_a_fifo_config() {
    let tmp = TmpDir::new("strict-fifo");
    let parent = strict_fixture(&tmp);
    let repo = tmp.path().join("repo");
    std::fs::remove_file(repo.join("config")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        repo.join("config"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o644),
        0,
    )
    .unwrap();

    let err = open_in_time(move || {
        block_on(Repo::open_at_strict(
            std::os::fd::AsFd::as_fd(&parent),
            Path::new("repo"),
        ))
    })
    .unwrap_err();
    match err {
        ostrya::Error::Io(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{e}");
            assert!(e.to_string().contains("not a regular file"), "{e}");
        }
        other => panic!("{other}"),
    }
}

/// A handle in the strict open mode refuses a metadata object that is a
/// symlink. A handle of the default open follows it.
#[test]
fn the_strict_open_refuses_a_symlinked_metadata_object() {
    let tmp = TmpDir::new("strict-meta");
    let parent = strict_fixture(&tmp);
    let fanout = tmp.path().join("repo/objects/ab");
    std::fs::create_dir_all(&fanout).unwrap();
    let rest = "c".repeat(62);
    std::os::unix::fs::symlink("../../config", fanout.join(format!("{rest}.dirtree"))).unwrap();
    let checksum: ostrya::Checksum = format!("ab{rest}").parse().unwrap();

    let fd = std::os::fd::AsFd::as_fd(&parent);
    let plain = block_on(Repo::open_at(fd, Path::new("repo"))).unwrap();
    let bytes = block_on(plain.load_object_bytes(ostrya::ObjectType::DirTree, &checksum))
        .expect("the default handle follows the symlink");
    assert!(bytes.starts_with(b"[core]"));

    let strict = block_on(Repo::open_at_strict(fd, Path::new("repo"))).unwrap();
    let err =
        block_on(strict.load_object_bytes(ostrya::ObjectType::DirTree, &checksum)).unwrap_err();
    match err {
        ostrya::Error::Io(e) => assert_eq!(e.raw_os_error(), Some(eloop()), "{e}"),
        other => panic!("{other}"),
    }
    let err = block_on(strict.metadata_reader(ostrya::ObjectType::DirTree, &checksum))
        .err()
        .expect("the strict reader refuses the symlink");
    assert!(matches!(err, ostrya::Error::Io(_)), "{err}");
}

/// Returns the error number `ELOOP`.
fn eloop() -> i32 {
    rustix::io::Errno::LOOP.raw_os_error()
}
