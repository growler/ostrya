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

use std::ffi::OsStr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::{fixture_repo, ostree_available};
use futures_lite::future::poll_once;
use ostrya::{CreateOptions, Error, OpenOptions, RemotesDir, Repo, RepoMode};
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
            CreateOptions::new(RepoMode::Bare).collection_id("org.example.Foo"),
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

/// A handle in the strict open mode refuses each object whose fan-out
/// directory `objects/<xx>` is a symlink: a commit, a dirtree, a dirmeta, and
/// a file, in `bare-user` and in `bare`. A handle of the default open follows
/// the symlink.
#[test]
fn the_strict_open_refuses_a_symlinked_fanout() {
    use ostrya::ObjectType;

    for mode in ["bare-user", "bare"] {
        let tmp = TmpDir::new("strict-fanout");
        let status = Command::new("cp")
            .arg("-a")
            .arg(fixture_repo(mode))
            .arg(tmp.path().join("repo"))
            .status()
            .unwrap();
        assert!(status.success(), "cp -a of the {mode} fixture");
        let parent = std::fs::File::open(tmp.path()).unwrap();
        let fd = parent.as_fd();
        let plain = block_on(Repo::open_at(fd, Path::new("repo"))).unwrap();
        let strict = block_on(Repo::open_at_strict(fd, Path::new("repo"))).unwrap();
        // The commit of the fixture, its root dirtree and dirmeta, and the
        // first file that a walk of the tree finds.
        let commit = block_on(plain.list_objects())
            .unwrap()
            .into_iter()
            .find(|name| name.ty == ObjectType::Commit)
            .expect("the fixture holds a commit")
            .checksum;
        let (commit_obj, _) = block_on(plain.load_commit(&commit)).unwrap();
        let mut dirtree = commit_obj.root_dirtree;
        let file = loop {
            let tree = block_on(plain.load_dirtree(&dirtree)).unwrap();
            if let Some((_, file)) = tree.files.first() {
                break *file;
            }
            dirtree = tree.dirs.first().expect("the tree holds a file").1;
        };
        let objects = [
            (ObjectType::Commit, commit),
            (ObjectType::DirTree, commit_obj.root_dirtree),
            (ObjectType::DirMeta, commit_obj.root_dirmeta),
            (ObjectType::File, file),
        ];
        for (ty, checksum) in objects {
            let hex = checksum.to_hex();
            let fanout = tmp.path().join("repo/objects").join(&hex[..2]);
            let moved = tmp.path().join("moved");
            std::fs::rename(&fanout, &moved).unwrap();
            std::os::unix::fs::symlink(&moved, &fanout).unwrap();

            if ty == ObjectType::File {
                block_on(plain.load_file(&checksum)).expect("the default handle follows");
                let err = block_on(strict.load_file(&checksum)).err().unwrap();
                match err {
                    Error::Io(e) => assert_eq!(e.raw_os_error(), Some(eloop()), "{mode} {e}"),
                    other => panic!("{mode} {ty:?}: {other}"),
                }
            } else {
                block_on(plain.load_object_bytes(ty, &checksum))
                    .expect("the default handle follows");
                let err = block_on(strict.load_object_bytes(ty, &checksum)).unwrap_err();
                match err {
                    Error::Io(e) => assert_eq!(e.raw_os_error(), Some(eloop()), "{mode} {e}"),
                    other => panic!("{mode} {ty:?}: {other}"),
                }
                let err = block_on(strict.metadata_reader(ty, &checksum))
                    .err()
                    .expect("the strict reader refuses the symlink");
                match err {
                    Error::Io(e) => assert_eq!(e.raw_os_error(), Some(eloop()), "{mode} {e}"),
                    other => panic!("{mode} {ty:?}: {other}"),
                }
            }

            std::fs::remove_file(&fanout).unwrap();
            std::fs::rename(&moved, &fanout).unwrap();
        }
    }
}

/// The reader of a regular file that a strict handle loaded opens the object
/// again through its fan-out directory, and follows no symlink there. A
/// symlink that replaces `objects/<xx>` after the load fails the reader with
/// `ELOOP`. The reader of a handle of the default open follows the symlink.
#[test]
fn the_strict_reader_refuses_a_fanout_symlinked_after_the_load() {
    use ostrya::ObjectType;

    for mode in ["bare-user", "bare"] {
        let tmp = TmpDir::new("strict-reader-fanout");
        let status = Command::new("cp")
            .arg("-a")
            .arg(fixture_repo(mode))
            .arg(tmp.path().join("repo"))
            .status()
            .unwrap();
        assert!(status.success(), "cp -a of the {mode} fixture");
        let parent = std::fs::File::open(tmp.path()).unwrap();
        let fd = parent.as_fd();
        let plain = block_on(Repo::open_at(fd, Path::new("repo"))).unwrap();
        let strict = block_on(Repo::open_at_strict(fd, Path::new("repo"))).unwrap();
        let (strict_file, plain_file) = block_on(strict.list_objects())
            .unwrap()
            .into_iter()
            .filter(|name| name.ty == ObjectType::File)
            .find_map(|name| {
                let file = block_on(strict.load_file(&name.checksum)).unwrap();
                (!file.is_symlink())
                    .then(|| (file, block_on(plain.load_file(&name.checksum)).unwrap()))
            })
            .expect("the fixture holds a regular file");

        let hex = strict_file.checksum().to_hex();
        let fanout = tmp.path().join("repo/objects").join(&hex[..2]);
        let copy = tmp.path().join("copy");
        let status = Command::new("cp")
            .arg("-a")
            .arg(&fanout)
            .arg(&copy)
            .status()
            .unwrap();
        assert!(status.success(), "cp -a of objects/{}", &hex[..2]);
        std::fs::remove_dir_all(&fanout).unwrap();
        std::os::unix::fs::symlink(&copy, &fanout).unwrap();

        block_on(plain_file.reader()).expect("the default handle follows");
        let err = block_on(strict_file.reader())
            .err()
            .expect("the strict reader refuses the symlink");
        match err {
            Error::Io(e) => assert_eq!(e.raw_os_error(), Some(eloop()), "{mode} {e}"),
            other => panic!("{mode}: {other}"),
        }
    }
}

/// Creates a repository `repo` of `mode` under `tmp` with one regular file
/// object. Returns the file object that a strict handle loaded, the same
/// object that a handle of the default open loaded, and the path of the
/// object file.
fn strict_reader_fixture(
    tmp: &TmpDir,
    mode: RepoMode,
) -> (ostrya::FileObject, ostrya::FileObject, PathBuf) {
    let repo = block_on(Repo::create(
        &tmp.path().join("repo"),
        CreateOptions::new(mode),
    ))
    .expect("create");
    let checksum = block_on(async {
        let txn = repo.transaction().await.unwrap();
        let checksum = txn
            .write_regfile_inline(None, &ostrya::FileMeta::regular(0, 0, 0o644), b"payload\n")
            .await
            .unwrap();
        txn.commit().await.unwrap();
        checksum
    });
    let parent = std::fs::File::open(tmp.path()).unwrap();
    let fd = parent.as_fd();
    let strict = block_on(Repo::open_at_strict(fd, Path::new("repo"))).unwrap();
    let plain = block_on(Repo::open_at(fd, Path::new("repo"))).unwrap();
    let strict_file = block_on(strict.load_file(&checksum)).unwrap();
    let plain_file = block_on(plain.load_file(&checksum)).unwrap();
    let path = tmp.path().join("repo/objects").join(ostrya::loose_path(
        &checksum,
        ostrya::ObjectType::File,
        mode,
    ));
    (strict_file, plain_file, path)
}

/// The reader of a regular file that a strict handle loaded follows no
/// symlink at the object path. A symlink that replaces the object file after
/// the load fails the reader with `ELOOP`. The reader of a handle of the
/// default open follows the symlink.
#[test]
fn the_strict_reader_refuses_an_object_symlinked_after_the_load() {
    for mode in [RepoMode::Archive, RepoMode::BareUser] {
        let tmp = TmpDir::new("strict-reader-object");
        let (strict_file, plain_file, path) = strict_reader_fixture(&tmp, mode);
        let outside = tmp.path().join("outside");
        std::fs::rename(&path, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();

        block_on(plain_file.reader()).expect("the default handle follows");
        let err = block_on(strict_file.reader())
            .err()
            .expect("the strict reader refuses the symlink");
        match err {
            Error::Io(e) => assert_eq!(e.raw_os_error(), Some(eloop()), "{mode:?} {e}"),
            other => panic!("{mode:?}: {other}"),
        }
    }
}

/// The reader of a regular file that a strict handle loaded refuses a FIFO
/// that replaces the object file after the load, and does not wait for a
/// writer.
#[test]
fn the_strict_reader_refuses_a_fifo_swapped_in_after_the_load() {
    for mode in [RepoMode::Archive, RepoMode::BareUser] {
        let tmp = TmpDir::new("strict-reader-fifo");
        let (strict_file, _, path) = strict_reader_fixture(&tmp, mode);
        std::fs::remove_file(&path).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(block_on(strict_file.reader()).map(drop));
        });
        let timeout = std::time::Duration::from_secs(10);
        let result = match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => {
                // A writer releases the blocked open, so the thread ends.
                let _ = rustix::fs::open(
                    &path,
                    rustix::fs::OFlags::WRONLY
                        | rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                );
                let _ = rx.recv_timeout(timeout);
                panic!("{mode:?}: the reader waits on the FIFO");
            }
        };
        match result {
            Err(Error::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{mode:?} {e}");
                assert!(e.to_string().contains("not a regular file"), "{mode:?} {e}");
            }
            other => panic!("{mode:?}: {other:?}"),
        }
    }
}

/// Returns the error number `ELOOP`.
fn eloop() -> i32 {
    rustix::io::Errno::LOOP.raw_os_error()
}

/// Asserts that `got` is `want`: the same variant and the same path, or for a
/// descriptor, the same shared descriptor.
fn assert_same_dir(got: Option<&RemotesDir>, want: &RemotesDir) {
    match (got, want) {
        (Some(RemotesDir::Path(a)), RemotesDir::Path(b)) => assert_eq!(a, b),
        (Some(RemotesDir::InRepo(a)), RemotesDir::InRepo(b)) => assert_eq!(a, b),
        (Some(RemotesDir::Fd(a)), RemotesDir::Fd(b)) => assert!(Arc::ptr_eq(a, b)),
        (got, want) => panic!("got {got:?}, want {want:?}"),
    }
}

/// Returns a descriptor of a new directory `name` under `tmp`.
fn scratch_dir_fd(tmp: &TmpDir, name: &str) -> OwnedFd {
    let path = tmp.path().join(name);
    std::fs::create_dir(&path).unwrap();
    std::fs::File::open(&path).unwrap().into()
}

/// Returns the value of `[ex-ostrya] remotes-config-dir` in the `config` of
/// the repository at `path`.
fn remotes_config_dir_key(path: &Path) -> Option<String> {
    let repo = block_on(Repo::open(path)).expect("open");
    repo.config()
        .keyfile()
        .get_string("ex-ostrya", "remotes-config-dir")
        .unwrap()
}

/// The handle keeps the remotes directory of the options, in each form,
/// through each setter, and through `open` and `open_at`.
#[test]
fn open_keeps_the_remotes_dir_of_the_options() {
    let tmp = TmpDir::new("rdopen");
    let parent = std::fs::File::open(tmp.path()).unwrap();
    block_on(Repo::create(
        &tmp.path().join("repo"),
        CreateOptions::new(RepoMode::Archive),
    ))
    .expect("create");
    let values = [
        RemotesDir::path("remotes.d"),
        RemotesDir::path(tmp.path().join("remotes.d")),
        RemotesDir::InRepo(PathBuf::from("remotes.d")),
        RemotesDir::from(scratch_dir_fd(&tmp, "scratch")),
    ];
    for value in &values {
        for opts in [
            OpenOptions::new().remotes_dir(value.clone()),
            OpenOptions::new().default_remotes_dir(value.clone()),
        ] {
            let opened = block_on(opts.open(&tmp.path().join("repo"))).expect("open");
            assert_same_dir(opened.remotes_dir(), value);
            let opened =
                block_on(opts.open_at(parent.as_fd(), Path::new("repo"))).expect("open_at");
            assert_same_dir(opened.remotes_dir(), value);
        }
    }
}

/// `remotes_dir` comes before `default_remotes_dir`, in either call order.
#[test]
fn open_selects_remotes_dir_before_the_default() {
    let tmp = TmpDir::new("rdorder");
    let path = tmp.path().join("repo");
    block_on(Repo::create(&path, CreateOptions::new(RepoMode::Archive))).expect("create");
    let chosen = RemotesDir::path("chosen.d");
    for opts in [
        OpenOptions::new()
            .remotes_dir(chosen.clone())
            .default_remotes_dir(RemotesDir::path("default.d")),
        OpenOptions::new()
            .default_remotes_dir(RemotesDir::path("default.d"))
            .remotes_dir(chosen.clone()),
    ] {
        let opened = block_on(opts.open(&path)).expect("open");
        assert_same_dir(opened.remotes_dir(), &chosen);
    }
}

/// An open or a create with no remotes directory value gives a handle with
/// no remotes directory.
#[test]
fn open_with_no_remotes_dir_gives_none() {
    let tmp = TmpDir::new("rdnone");
    let parent = std::fs::File::open(tmp.path()).unwrap();
    let path = tmp.path().join("repo");
    let created =
        block_on(Repo::create(&path, CreateOptions::new(RepoMode::Archive))).expect("create");
    assert!(created.remotes_dir().is_none());
    let repo = Path::new("repo");
    for opened in [
        block_on(Repo::open(&path)),
        block_on(Repo::open_at(parent.as_fd(), repo)),
        block_on(OpenOptions::new().open(&path)),
        block_on(OpenOptions::new().open_at(parent.as_fd(), repo)),
        block_on(Repo::open_at_strict(parent.as_fd(), repo)),
    ] {
        assert!(opened.expect("open").remotes_dir().is_none());
    }
}

/// An open with a remotes directory that does not exist succeeds and creates
/// nothing. A value that is not valid UTF-8 opens too.
#[test]
fn open_takes_an_absent_remotes_dir_and_creates_nothing() {
    let tmp = TmpDir::new("rdabsent");
    let path = tmp.path().join("repo");
    block_on(Repo::create(&path, CreateOptions::new(RepoMode::Archive))).expect("create");
    let absent = tmp.path().join("absent").join("remotes.d");
    for value in [
        RemotesDir::path(&absent),
        RemotesDir::InRepo(PathBuf::from("absent.d")),
        RemotesDir::path(OsStr::from_bytes(b"\xff")),
    ] {
        let opened = block_on(OpenOptions::new().remotes_dir(value.clone()).open(&path))
            .expect("open with an absent remotes directory");
        assert_same_dir(opened.remotes_dir(), &value);
        assert!(opened.config().remotes().next().is_none());
    }
    assert!(!tmp.path().join("absent").exists());
    assert!(!path.join("absent.d").exists());
}

/// The values that an open and a create refuse: an empty path, a path that
/// holds a NUL byte, and an absolute in-repository path.
fn refused_values() -> [RemotesDir; 5] {
    [
        RemotesDir::path(""),
        RemotesDir::InRepo(PathBuf::new()),
        RemotesDir::path("remotes\0.d"),
        RemotesDir::InRepo(PathBuf::from("remotes\0.d")),
        RemotesDir::InRepo(PathBuf::from("/abs/remotes.d")),
    ]
}

/// An open refuses an empty path, a path that holds a NUL byte, and an
/// absolute in-repository path in each setter, with `Error::InvalidInput`.
#[test]
fn open_refuses_an_empty_nul_or_absolute_in_repo_remotes_dir() {
    let tmp = TmpDir::new("rdrefopen");
    let parent = std::fs::File::open(tmp.path()).unwrap();
    let path = tmp.path().join("repo");
    block_on(Repo::create(&path, CreateOptions::new(RepoMode::Archive))).expect("create");
    for value in refused_values() {
        for opts in [
            OpenOptions::new().remotes_dir(value.clone()),
            OpenOptions::new().default_remotes_dir(value.clone()),
            OpenOptions::new()
                .remotes_dir(RemotesDir::path("ok.d"))
                .default_remotes_dir(value.clone()),
        ] {
            let err = block_on(opts.open(&path)).expect_err("open refuses");
            assert!(matches!(err, Error::InvalidInput(_)), "{value:?}: {err}");
            let err = block_on(opts.open_at(parent.as_fd(), Path::new("repo")))
                .expect_err("open_at refuses");
            assert!(matches!(err, Error::InvalidInput(_)), "{value:?}: {err}");
        }
    }
}

/// A create refuses an empty path, a path that holds a NUL byte, an absolute
/// in-repository path, and a path that is not valid UTF-8, with
/// `Error::InvalidInput`, and writes nothing.
#[test]
fn create_refuses_a_bad_remotes_dir_and_writes_nothing() {
    let tmp = TmpDir::new("rdrefcreate");
    let parent = std::fs::File::open(tmp.path()).unwrap();
    let mut values = refused_values().to_vec();
    values.push(RemotesDir::path(OsStr::from_bytes(b"\xff")));
    values.push(RemotesDir::InRepo(PathBuf::from(OsStr::from_bytes(
        b"\xff",
    ))));
    for value in values {
        let opts = CreateOptions::new(RepoMode::Archive).remotes_dir(value.clone());
        let err = block_on(opts.create(&tmp.path().join("repo"))).expect_err("create refuses");
        assert!(matches!(err, Error::InvalidInput(_)), "{value:?}: {err}");
        let err = block_on(opts.create_at(parent.as_fd(), Path::new("repo")))
            .expect_err("create_at refuses");
        assert!(matches!(err, Error::InvalidInput(_)), "{value:?}: {err}");
        assert!(!tmp.path().join("repo").exists(), "{value:?}");
    }
}

/// A create writes `[ex-ostrya] remotes-config-dir` in the form of the value,
/// and the handle holds the value as given.
#[test]
fn create_writes_the_remotes_config_dir_key() {
    let tmp = TmpDir::new("rdkey");
    let parent = std::fs::File::open(tmp.path()).unwrap();
    let absolute = tmp.path().join("remotes.d");
    let relative = PathBuf::from("ostrya-test-relative-remotes.d");
    let cwd = std::env::current_dir().expect("current dir");
    let cases = [
        (
            "abs",
            RemotesDir::path(&absolute),
            Some(absolute.to_str().unwrap().to_owned()),
        ),
        (
            "rel",
            RemotesDir::path(&relative),
            Some(cwd.join(&relative).to_str().unwrap().to_owned()),
        ),
        (
            "inrepo",
            RemotesDir::InRepo(PathBuf::from("etc/remotes.d")),
            Some("etc/remotes.d".to_owned()),
        ),
        ("fd", RemotesDir::from(scratch_dir_fd(&tmp, "fd.d")), None),
    ];
    for (name, value, expected) in cases {
        let opts = CreateOptions::new(RepoMode::Archive).remotes_dir(value.clone());
        let created = block_on(opts.create(&tmp.path().join(name))).expect("create");
        assert_same_dir(created.remotes_dir(), &value);
        assert_eq!(
            remotes_config_dir_key(&tmp.path().join(name)),
            expected,
            "{name}"
        );

        let at = format!("{name}-at");
        let created = block_on(opts.create_at(parent.as_fd(), Path::new(&at))).expect("create_at");
        assert_same_dir(created.remotes_dir(), &value);
        assert_eq!(
            remotes_config_dir_key(&tmp.path().join(&at)),
            expected,
            "{at}"
        );
    }
    assert!(
        !cwd.join(&relative).exists(),
        "the create writes no remotes directory"
    );

    let bytes = std::fs::read(tmp.path().join("abs").join("config")).unwrap();
    let expected = format!(
        "[core]\nrepo_version=1\nmode=archive-z2\n\n[ex-ostrya]\nremotes-config-dir={}\n",
        absolute.display()
    );
    assert_eq!(bytes, expected.as_bytes());
    let bytes = std::fs::read(tmp.path().join("fd").join("config")).unwrap();
    assert_eq!(bytes, b"[core]\nrepo_version=1\nmode=archive-z2\n");
}

/// A create writes a key value with a leading space, an inner space, and a
/// backslash, and the `config` of the repository gives back the same text.
#[test]
fn create_writes_a_key_value_that_reads_back() {
    let tmp = TmpDir::new("rdescape");
    let path = tmp.path().join("repo");
    let text = " my remotes\\d";
    let opts =
        CreateOptions::new(RepoMode::Archive).remotes_dir(RemotesDir::InRepo(PathBuf::from(text)));
    block_on(opts.create(&path)).expect("create");
    assert_eq!(remotes_config_dir_key(&path).as_deref(), Some(text));
}

/// A create over an existing `config` writes no key, and the handle still
/// holds the value.
#[test]
fn create_over_an_existing_config_writes_no_key() {
    let tmp = TmpDir::new("rdidem");
    let path = tmp.path().join("repo");
    block_on(Repo::create(&path, CreateOptions::new(RepoMode::Archive))).expect("first create");
    let value = RemotesDir::path(tmp.path().join("remotes.d"));
    let created = block_on(
        CreateOptions::new(RepoMode::Archive)
            .remotes_dir(value.clone())
            .create(&path),
    )
    .expect("second create");
    assert_same_dir(created.remotes_dir(), &value);
    let bytes = std::fs::read(path.join("config")).unwrap();
    assert_eq!(bytes, b"[core]\nrepo_version=1\nmode=archive-z2\n");
}

/// Writes the file `name` with `text` in the directory `dir`, and creates
/// the directory if it is absent.
fn write_conf(dir: &Path, name: &str, text: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(name), text).unwrap();
}

/// Returns the text of a `.conf` file with one remote `name`.
fn remote_text(name: &str) -> String {
    format!("[remote \"{name}\"]\nurl=https://example.com/{name}\n")
}

/// Creates an archive repository at `path` whose `config` ends with
/// `[ex-ostrya] remotes-config-dir=` and `value`.
fn create_with_key(path: &Path, value: &str) {
    block_on(Repo::create(path, CreateOptions::new(RepoMode::Archive))).expect("create");
    let mut config = std::fs::read_to_string(path.join("config")).unwrap();
    config.push_str(&format!("\n[ex-ostrya]\nremotes-config-dir={value}\n"));
    std::fs::write(path.join("config"), config).unwrap();
}

/// Returns the names of the remotes of `repo`.
fn remote_names(repo: &Repo) -> Vec<String> {
    repo.config().remotes().map(str::to_owned).collect()
}

/// Asserts that `result` is an `Error::InvalidFormat` whose message holds
/// `part`.
fn assert_invalid_format(result: ostrya::Result<Repo>, part: &str) {
    match result {
        Err(Error::InvalidFormat(m)) => assert!(m.contains(part), "{m:?} lacks {part:?}"),
        Err(other) => panic!("{other}"),
        Ok(_) => panic!("the open succeeds"),
    }
}

/// Returns the `std::io::Error` of an `Error::Io` result.
fn io_error(result: ostrya::Result<Repo>) -> std::io::Error {
    match result {
        Err(Error::Io(e)) => e,
        Err(other) => panic!("{other}"),
        Ok(_) => panic!("the open succeeds"),
    }
}

/// Returns `true` if the test runs as root, which reads each file whatever
/// its mode.
fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// The open selects the option, then the key, then the default, and reads
/// the remotes of the selected directory alone.
#[test]
fn open_selects_the_option_then_the_key_then_the_default() {
    let tmp = TmpDir::new("rdselect");
    let path = tmp.path().join("repo");
    let option = tmp.path().join("option.d");
    let default = tmp.path().join("default.d");
    create_with_key(&path, "key.d");
    write_conf(&option, "o.conf", &remote_text("option"));
    write_conf(&path.join("key.d"), "k.conf", &remote_text("key"));
    write_conf(&default, "d.conf", &remote_text("default"));

    let opened = block_on(
        OpenOptions::new()
            .remotes_dir(RemotesDir::path(&option))
            .default_remotes_dir(RemotesDir::path(&default))
            .open(&path),
    )
    .expect("open");
    assert_same_dir(opened.remotes_dir(), &RemotesDir::path(&option));
    assert_eq!(remote_names(&opened), ["option"]);

    let opened = block_on(
        OpenOptions::new()
            .default_remotes_dir(RemotesDir::path(&default))
            .open(&path),
    )
    .expect("open");
    assert_same_dir(
        opened.remotes_dir(),
        &RemotesDir::InRepo(PathBuf::from("key.d")),
    );
    assert_eq!(remote_names(&opened), ["key"]);

    let plain = tmp.path().join("plain");
    block_on(Repo::create(&plain, CreateOptions::new(RepoMode::Archive))).expect("create");
    let opened = block_on(
        OpenOptions::new()
            .default_remotes_dir(RemotesDir::path(&default))
            .open(&plain),
    )
    .expect("open");
    assert_same_dir(opened.remotes_dir(), &RemotesDir::path(&default));
    assert_eq!(remote_names(&opened), ["default"]);

    let opened = block_on(Repo::open(&plain)).expect("open");
    assert!(opened.remotes_dir().is_none());
    assert!(remote_names(&opened).is_empty());
}

/// An absolute value of the key gives a path, and a relative value a path in
/// the repository, also through `open_at` from another directory.
#[test]
fn open_reads_the_key_as_a_path_or_a_path_in_the_repository() {
    let tmp = TmpDir::new("rdkeyread");
    let absolute = tmp.path().join("abs.d");
    write_conf(&absolute, "a.conf", &remote_text("abs"));
    let path = tmp.path().join("abs");
    create_with_key(&path, absolute.to_str().unwrap());
    let opened = block_on(Repo::open(&path)).expect("open");
    assert_same_dir(opened.remotes_dir(), &RemotesDir::path(&absolute));
    assert_eq!(remote_names(&opened), ["abs"]);

    let path = tmp.path().join("rel");
    create_with_key(&path, "etc/remotes.d");
    write_conf(&path.join("etc/remotes.d"), "r.conf", &remote_text("rel"));
    let parent = std::fs::File::open(tmp.path()).unwrap();
    let opened = block_on(Repo::open_at(parent.as_fd(), Path::new("rel"))).expect("open_at");
    assert_same_dir(
        opened.remotes_dir(),
        &RemotesDir::InRepo(PathBuf::from("etc/remotes.d")),
    );
    assert_eq!(remote_names(&opened), ["rel"]);
}

/// The open refuses an empty value of the key, also when an option comes
/// before the key.
#[test]
fn open_refuses_an_empty_key() {
    let tmp = TmpDir::new("rdkeyempty");
    let path = tmp.path().join("repo");
    create_with_key(&path, "");
    assert_invalid_format(block_on(Repo::open(&path)), "is empty");
    assert_invalid_format(
        block_on(
            OpenOptions::new()
                .remotes_dir(RemotesDir::path(tmp.path().join("r.d")))
                .open(&path),
        ),
        "is empty",
    );
}

/// The strict open reads no key and no remotes directory.
#[test]
fn the_strict_open_reads_no_key() {
    let tmp = TmpDir::new("rdstrict");
    let path = tmp.path().join("repo");
    create_with_key(&path, "remotes.d");
    write_conf(&path.join("remotes.d"), "bad.conf", "not a key file\n");
    let parent = std::fs::File::open(tmp.path()).unwrap();
    let strict =
        block_on(Repo::open_at_strict(parent.as_fd(), Path::new("repo"))).expect("strict open");
    assert!(strict.remotes_dir().is_none());
    assert!(remote_names(&strict).is_empty());
    assert_invalid_format(
        block_on(Repo::open_at(parent.as_fd(), Path::new("repo"))),
        "bad.conf",
    );

    // A key that the open refuses does not stop the strict open.
    let empty = tmp.path().join("empty");
    create_with_key(&empty, "");
    let strict =
        block_on(Repo::open_at_strict(parent.as_fd(), Path::new("empty"))).expect("strict open");
    assert!(strict.remotes_dir().is_none());
    assert_invalid_format(
        block_on(Repo::open_at(parent.as_fd(), Path::new("empty"))),
        "remotes-config-dir",
    );
}

/// The remotes of `config` come first, then the remotes of each file in the
/// byte order of the file names. Two groups of one name in one file give one
/// remote.
#[test]
fn open_lists_remotes_in_source_order() {
    let tmp = TmpDir::new("rdlist");
    let path = tmp.path().join("repo");
    create_with_key(&path, "remotes.d");
    let mut config = std::fs::read_to_string(path.join("config")).unwrap();
    config.push_str(&format!("\n{}", remote_text("main")));
    std::fs::write(path.join("config"), config).unwrap();
    let dir = path.join("remotes.d");
    write_conf(&dir, "b.conf", &remote_text("b"));
    write_conf(
        &dir,
        "a.conf",
        &format!(
            "{}\n{}\n[remote \"a2\"]\nurl=https://example.com/second\n",
            remote_text("a2"),
            remote_text("a1")
        ),
    );
    write_conf(&dir, "B.conf", &remote_text("upper"));
    write_conf(&dir, ".x.conf", &remote_text("hidden"));

    let opened = block_on(Repo::open(&path)).expect("open");
    assert_eq!(
        remote_names(&opened),
        ["main", "hidden", "upper", "a2", "a1", "b"]
    );
    let a2 = opened.config().remote("a2").unwrap();
    assert_eq!(
        a2.url().unwrap().as_deref(),
        Some("https://example.com/second")
    );
    assert_eq!(a2.source(), ostrya::RemoteSource::File("a.conf"));
    assert_eq!(
        opened.config().remote("main").unwrap().source(),
        ostrya::RemoteSource::Config
    );
}

/// The open skips each entry whose name does not end in `.conf` and each
/// entry that is not a regular file after a symlink, and reads no
/// subdirectory.
#[test]
fn open_skips_entries_that_are_not_conf_files() {
    let tmp = TmpDir::new("rdskip");
    let dir = tmp.path().join("remotes.d");
    let path = tmp.path().join("repo");
    create_with_key(&path, dir.to_str().unwrap());
    for name in ["x.CONF", "x.conf~", "x.conf.swp", "noconf"] {
        write_conf(&dir, name, "not a key file\n");
    }
    std::fs::create_dir(dir.join("d.conf")).unwrap();
    write_conf(&dir.join("sub"), "in.conf", "not a key file\n");
    std::os::unix::fs::symlink("sub", dir.join("linkdir.conf")).unwrap();
    std::os::unix::fs::symlink("absent", dir.join("dangling.conf")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        dir.join("f.conf"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o644),
        0,
    )
    .unwrap();
    // The path of a socket has a short length limit, so the bind uses a short
    // path and a rename moves the socket into place.
    let short = tmp.path().join("s");
    let _socket = std::os::unix::net::UnixListener::bind(&short).unwrap();
    std::fs::rename(&short, dir.join("s.conf")).unwrap();
    write_conf(&tmp.path().join("real"), "target", &remote_text("linked"));
    std::os::unix::fs::symlink("../real/target", dir.join("link.conf")).unwrap();
    write_conf(&dir, ".conf", &remote_text("bare"));

    let opened = open_in_time(move || block_on(Repo::open(&path))).expect("open");
    assert_eq!(remote_names(&opened), ["bare", "linked"]);
}

/// The open fails on a `.conf` symlink loop.
#[test]
fn open_refuses_a_conf_symlink_loop() {
    let tmp = TmpDir::new("rdloop");
    let dir = tmp.path().join("remotes.d");
    let path = tmp.path().join("repo");
    create_with_key(&path, dir.to_str().unwrap());
    std::fs::create_dir(&dir).unwrap();
    std::os::unix::fs::symlink("loop.conf", dir.join("loop.conf")).unwrap();
    let err = io_error(block_on(Repo::open(&path)));
    assert!(
        err.to_string()
            .starts_with(&format!("{}: ", dir.join("loop.conf").display())),
        "{err}"
    );
    assert_eq!(
        err.kind(),
        std::io::Error::from_raw_os_error(eloop()).kind(),
        "{err}"
    );
}

/// A `.conf` file of 1 MiB opens, and a larger file fails the open.
#[test]
fn open_refuses_a_conf_file_over_the_size_cap() {
    let tmp = TmpDir::new("rdcap");
    let dir = tmp.path().join("remotes.d");
    let path = tmp.path().join("repo");
    create_with_key(&path, dir.to_str().unwrap());
    let mut text = remote_text("big");
    text.push('#');
    text.push_str(&"x".repeat(1024 * 1024 - text.len() - 1));
    text.push('\n');
    assert_eq!(text.len(), 1024 * 1024);
    write_conf(&dir, "big.conf", &text);
    let opened = block_on(Repo::open(&path)).expect("a file of 1 MiB opens");
    assert_eq!(remote_names(&opened), ["big"]);

    text.push('\n');
    write_conf(&dir, "big.conf", &text);
    assert_invalid_format(
        block_on(Repo::open(&path)),
        &format!("{} exceeds", dir.join("big.conf").display()),
    );
}

/// The open refuses a `.conf` file whose name is not valid UTF-8, and skips
/// another entry with such a name.
#[test]
fn open_refuses_a_conf_name_that_is_not_utf8() {
    let tmp = TmpDir::new("rdname");
    let dir = tmp.path().join("remotes.d");
    let path = tmp.path().join("repo");
    create_with_key(&path, dir.to_str().unwrap());
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join(OsStr::from_bytes(b"\xff.txt")), "x").unwrap();
    std::fs::write(dir.join(OsStr::from_bytes(b"\xff.conf")), remote_text("x")).unwrap();
    assert_invalid_format(
        block_on(Repo::open(&path)),
        "the file name is not valid UTF-8",
    );
    std::fs::remove_file(dir.join(OsStr::from_bytes(b"\xff.conf"))).unwrap();
    block_on(Repo::open(&path)).expect("the other name is skipped");
}

/// The open refuses a `.conf` file whose content is not valid UTF-8, in a
/// value or in a group name.
#[test]
fn open_refuses_conf_content_that_is_not_utf8() {
    let tmp = TmpDir::new("rdcontent");
    let dir = tmp.path().join("remotes.d");
    let path = tmp.path().join("repo");
    create_with_key(&path, dir.to_str().unwrap());
    std::fs::create_dir(&dir).unwrap();
    for bytes in [
        &b"[remote \"x\"]\nurl=\xff\n"[..],
        &b"[remote \"\xff\"]\nurl=https://x\n"[..],
    ] {
        std::fs::write(dir.join("x.conf"), bytes).unwrap();
        assert_invalid_format(
            block_on(Repo::open(&path)),
            &format!(
                "{}: the content is not valid UTF-8",
                dir.join("x.conf").display()
            ),
        );
    }
}

/// The open refuses a remotes directory path that is not a directory.
#[test]
fn open_refuses_a_remotes_dir_that_is_not_a_directory() {
    let tmp = TmpDir::new("rdnotdir");
    let file = tmp.path().join("remotes.d");
    std::fs::write(&file, "x").unwrap();
    let path = tmp.path().join("repo");
    create_with_key(&path, file.to_str().unwrap());
    let err = io_error(block_on(Repo::open(&path)));
    assert_eq!(err.kind(), std::io::ErrorKind::NotADirectory, "{err}");
    assert!(
        err.to_string()
            .starts_with(&format!("{}: ", file.display())),
        "{err}"
    );
}

/// The open fails on a remotes directory or a `.conf` file that it cannot
/// read.
#[test]
fn open_refuses_an_unreadable_remotes_dir_or_conf_file() {
    if is_root() {
        eprintln!("skipped: root reads each file whatever its mode");
        return;
    }
    let tmp = TmpDir::new("rdunread");
    let dir = tmp.path().join("remotes.d");
    let path = tmp.path().join("repo");
    create_with_key(&path, dir.to_str().unwrap());
    write_conf(&dir, "x.conf", &remote_text("x"));

    std::fs::set_permissions(dir.join("x.conf"), std::fs::Permissions::from_mode(0o0)).unwrap();
    let err = io_error(block_on(Repo::open(&path)));
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert!(
        err.to_string()
            .starts_with(&format!("{}: ", dir.join("x.conf").display())),
        "{err}"
    );
    std::fs::set_permissions(dir.join("x.conf"), std::fs::Permissions::from_mode(0o644)).unwrap();

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o0)).unwrap();
    let err = io_error(block_on(Repo::open(&path)));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert!(
        err.to_string().starts_with(&format!("{}: ", dir.display())),
        "{err}"
    );
}

/// The open refuses a `.conf` file that is not a valid key file, and names
/// the file.
#[test]
fn open_refuses_a_broken_conf_file() {
    let tmp = TmpDir::new("rdbroken");
    let path = tmp.path().join("repo");
    create_with_key(&path, "remotes.d");
    write_conf(&path.join("remotes.d"), "x.conf", "not a key file\n");
    assert_invalid_format(block_on(Repo::open(&path)), "remotes.d/x.conf: ");
}

/// The open refuses a remote name that `config` and a file, or two files,
/// define.
#[test]
fn open_refuses_a_name_in_two_sources() {
    let tmp = TmpDir::new("rdtwice");
    let path = tmp.path().join("repo");
    create_with_key(&path, "remotes.d");
    let dir = path.join("remotes.d");
    write_conf(&dir, "a.conf", &remote_text("x"));
    write_conf(&dir, "b.conf", &remote_text("x"));
    assert_invalid_format(
        block_on(Repo::open(&path)),
        "remote \"x\" is defined in remotes.d/a.conf and in remotes.d/b.conf",
    );

    std::fs::remove_file(dir.join("b.conf")).unwrap();
    let mut config = std::fs::read_to_string(path.join("config")).unwrap();
    config.push_str(&format!("\n{}", remote_text("x")));
    std::fs::write(path.join("config"), config).unwrap();
    assert_invalid_format(
        block_on(Repo::open(&path)),
        "remote \"x\" is defined in config and in remotes.d/a.conf",
    );
}

/// The open reads a remotes directory that a descriptor gives, and an error
/// names a file by its name alone.
#[test]
fn open_reads_a_remotes_dir_given_by_descriptor() {
    let tmp = TmpDir::new("rdfd");
    let path = tmp.path().join("repo");
    block_on(Repo::create(&path, CreateOptions::new(RepoMode::Archive))).expect("create");
    let fd = scratch_dir_fd(&tmp, "remotes.d");
    let dir = tmp.path().join("remotes.d");
    write_conf(&dir, "x.conf", &remote_text("x"));
    let opts = OpenOptions::new().remotes_dir(RemotesDir::from(fd));
    let opened = block_on(opts.open(&path)).expect("open");
    assert_eq!(remote_names(&opened), ["x"]);
    assert_eq!(
        opened.config().remote("x").unwrap().source(),
        ostrya::RemoteSource::File("x.conf")
    );

    write_conf(&dir, "y.conf", "not a key file\n");
    match block_on(opts.open(&path)) {
        Err(Error::InvalidFormat(m)) => assert!(m.starts_with("y.conf: "), "{m}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
}

/// `UpdateGuard::read_config` reads the remotes directory again, and the
/// handle keeps the remotes of the open.
#[test]
fn read_config_reads_the_remotes_dir_again() {
    let tmp = TmpDir::new("rdreread");
    let path = tmp.path().join("repo");
    create_with_key(&path, "remotes.d");
    let dir = path.join("remotes.d");
    write_conf(&dir, "a.conf", &remote_text("a"));
    let repo = block_on(Repo::open(&path)).expect("open");
    write_conf(&dir, "b.conf", &remote_text("b"));
    assert_eq!(remote_names(&repo), ["a"]);
    let guard = block_on(repo.begin_update()).expect("begin_update");
    let read = block_on(guard.read_config()).expect("read_config");
    assert_eq!(read.remotes().collect::<Vec<_>>(), ["a", "b"]);
    let file = block_on(guard.read_config_file()).expect("read_config_file");
    assert_eq!(file.remotes().count(), 0);
}

/// A create reads the remotes directory of its value. With no value, it
/// takes the key of an existing `config`.
#[test]
fn create_reads_the_remotes_dir() {
    let tmp = TmpDir::new("rdcreate");
    let dir = tmp.path().join("remotes.d");
    write_conf(&dir, "x.conf", &remote_text("x"));
    let path = tmp.path().join("repo");
    let created = block_on(
        CreateOptions::new(RepoMode::Archive)
            .remotes_dir(RemotesDir::path(&dir))
            .create(&path),
    )
    .expect("create");
    assert_eq!(remote_names(&created), ["x"]);

    let again =
        block_on(Repo::create(&path, CreateOptions::new(RepoMode::Archive))).expect("create");
    assert_same_dir(again.remotes_dir(), &RemotesDir::path(&dir));
    assert_eq!(remote_names(&again), ["x"]);
}

/// A create refuses a collection id that holds a line break, and writes
/// nothing.
#[test]
fn create_refuses_a_collection_id_with_a_line_break() {
    let tmp = TmpDir::new("rdcid");
    let path = tmp.path().join("repo");
    for id in [
        "org.example.Os\n[ex-ostrya]\nremotes-config-dir=x",
        "org.example\rOs",
    ] {
        let err = block_on(
            CreateOptions::new(RepoMode::Archive)
                .collection_id(id)
                .create(&path),
        )
        .expect_err("create refuses");
        assert!(matches!(err, Error::InvalidInput(_)), "{err}");
        assert!(!path.exists());
    }
}
