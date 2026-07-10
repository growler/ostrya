//! Repository open/create integration tests.
//!
//! These exercise the Phase 4 gate: open a tool-created repository and read its
//! mode and config; create a repository whose `config` bytes and layout match
//! what the `ostree` tool writes; and cross-check that the tool opens and
//! operates on a repository this crate creates.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use ostrya::{CreateOptions, Repo, RepoMode};
use ostrya_rt::block_on;

/// Root of the tool-generated fixture repositories, one subdirectory per mode.
fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/generated")
}

/// A throwaway directory removed when dropped.
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

/// Whether the `ostree` tool is available for the cross-check tests.
fn ostree_available() -> bool {
    Command::new("ostree")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn opens_fixture_repos_and_reads_mode() {
    for (mode_dir, expected) in [
        ("archive", RepoMode::Archive),
        ("bare-user", RepoMode::BareUser),
    ] {
        let repo_path = fixture_root().join(mode_dir).join("repo");
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
    // A second create with a different mode must leave the original config,
    // matching the tool's `init`.
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

    // The tool accepts the repository for a write operation: committing an
    // empty tree succeeds, which requires a well-formed layout.
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
