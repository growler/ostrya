//! Phase 11 verification for the `ostrya` binary.
//!
//! These tests drive the built binary as a subprocess over repositories the
//! library creates, checking the three subcommands against the golden fixture
//! and against the `ostree` tool where it is available.
//!
//! The deterministic fixture tree is the one `tests/fixtures/generate.sh`
//! commits with `--branch=test/main --subject="fixture commit" owner=0:0
//! --no-xattrs --timestamp=@1700000000`. Committing it through the binary with
//! `--canonical-permissions` (owner 0:0, `perm & 0755`, no xattrs) and
//! `SOURCE_DATE_EPOCH=1700000000` reproduces the fixture commit id.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use ostrya::{CreateOptions, Repo, RepoMode};
use ostrya_rt::block_on;

/// The fixture commit id, branch, and timestamp from `generate.sh`/MANIFEST.
const COMMIT: &str = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";
const BRANCH: &str = "test/main";
const SUBJECT: &str = "fixture commit";
const SOURCE_DATE_EPOCH: &str = "1700000000";

// --- temp-dir helper ---------------------------------------------------------

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ostrya-cli-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TmpDir(dir)
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

// --- fixtures and process driving --------------------------------------------

/// Build the deterministic fixture source tree under `base/src`, matching
/// `generate.sh`: a regular file, an empty file, a nested file, and a symlink,
/// with explicit modes.
fn build_fixture_source(base: &Path) {
    let set_mode = |p: &Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    };
    let src = base.join("src");
    std::fs::create_dir_all(src.join("subdir")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    std::fs::write(src.join("empty.txt"), b"").unwrap();
    std::fs::write(src.join("subdir/nested.txt"), b"nested\n").unwrap();
    std::os::unix::fs::symlink("hello.txt", src.join("link")).unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    set_mode(&src.join("empty.txt"), 0o644);
    set_mode(&src.join("subdir/nested.txt"), 0o644);
    set_mode(&src.join("subdir"), 0o755);
    set_mode(&src, 0o755);
}

/// Create a fresh repository of `mode` at `base/repo` and return its path.
fn create_repo(base: &Path, mode: RepoMode) -> PathBuf {
    let repo = base.join("repo");
    block_on(async {
        Repo::create(&repo, CreateOptions::new(mode)).await.unwrap();
    });
    repo
}

struct Run {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Run {
    fn ok(&self) -> &Run {
        assert!(
            self.status.success(),
            "ostrya failed: {}\n{}",
            String::from_utf8_lossy(&self.stdout),
            String::from_utf8_lossy(&self.stderr),
        );
        self
    }

    fn stdout_trimmed(&self) -> String {
        String::from_utf8(self.stdout.clone())
            .unwrap()
            .trim()
            .to_owned()
    }
}

/// Run the `ostrya` binary with `args`, optional `stdin`, and extra env.
fn ostrya(args: &[&str], stdin: Option<&[u8]>, env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ostrya"));
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn ostrya");
    if let Some(bytes) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(bytes)
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait ostrya");
    Run {
        status: out.status,
        stdout: out.stdout,
        stderr: out.stderr,
    }
}

fn ostree_available() -> bool {
    Command::new("ostree")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The commit a ref resolves to, read through the library.
fn resolve(repo: &Path, refspec: &str) -> Option<String> {
    block_on(async {
        let repo = Repo::open(repo).await.unwrap();
        repo.resolve_rev(refspec, true)
            .await
            .unwrap()
            .map(|c| c.to_hex())
    })
}

/// A sorted description of a checked-out tree: one `(relpath, kind)` line per
/// entry, where `kind` captures type, permission bits, and content or target.
fn describe_tree(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = format!("{prefix}{name}");
            let meta = entry.path().symlink_metadata().unwrap();
            let ty = meta.file_type();
            let perm = meta.permissions().mode() & 0o7777;
            if ty.is_symlink() {
                let target = std::fs::read_link(entry.path()).unwrap();
                out.push(format!("{rel} symlink -> {}", target.display()));
            } else if ty.is_dir() {
                out.push(format!("{rel} dir {perm:o}"));
                walk(&entry.path(), &format!("{rel}/"), out);
            } else {
                let content = std::fs::read(entry.path()).unwrap();
                out.push(format!("{rel} file {perm:o} {} bytes", content.len()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, "", &mut out);
    out
}

// --- tests -------------------------------------------------------------------

#[test]
fn commit_from_disk_reproduces_fixture_id_and_ref() {
    let tmp = TmpDir::new("commit");
    let base = tmp.path();
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);

    let src = base.join("src");
    let run = ostrya(
        &[
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
            "--canonical-permissions",
            src.to_str().unwrap(),
        ],
        None,
        &[("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)],
    );
    run.ok();

    assert_eq!(
        run.stdout_trimmed(),
        COMMIT,
        "commit id matches the fixture"
    );
    assert_eq!(
        resolve(&repo, BRANCH).as_deref(),
        Some(COMMIT),
        "--branch points the ref at the new commit",
    );

    // The tool accepts the repository the port created and populated.
    if ostree_available() {
        let repo_arg = format!("--repo={}", repo.display());
        for sub in [&["fsck"][..], &["show", COMMIT], &["ls", "-R", COMMIT]] {
            let out = Command::new("ostree")
                .arg(&repo_arg)
                .args(sub)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "ostree {sub:?} rejected the port's repo:\n{}",
                String::from_utf8_lossy(&out.stderr),
            );
        }
        assert_eq!(
            String::from_utf8_lossy(
                &Command::new("ostree")
                    .arg(&repo_arg)
                    .args(["rev-parse", BRANCH])
                    .output()
                    .unwrap()
                    .stdout
            )
            .trim(),
            COMMIT,
            "the tool resolves the branch to the new commit",
        );
    }
}

#[test]
fn tar_roundtrip_via_stdin_reproduces_tree() {
    let tmp = TmpDir::new("tar");
    let base = tmp.path();
    build_fixture_source(base);

    // Commit the fixture tree from disk, then export it to a tar stream.
    let dir_a = base.join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let repo1 = create_repo(&dir_a, RepoMode::Archive);
    let src = base.join("src");
    let commit_disk = ostrya(
        &[
            "commit",
            "--repo",
            repo1.to_str().unwrap(),
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
            "--canonical-permissions",
            src.to_str().unwrap(),
        ],
        None,
        &[("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)],
    );
    commit_disk.ok();
    assert_eq!(
        commit_disk.stdout_trimmed(),
        COMMIT,
        "disk-ingest commit id"
    );

    let export = ostrya(
        &["export", "--repo", repo1.to_str().unwrap(), COMMIT],
        None,
        &[],
    );
    export.ok();
    let tar = export.stdout.clone();
    assert!(!tar.is_empty(), "export produced a tar stream");

    // Feed the same tar stream to `commit` on stdin (no path). The tar carries
    // owner 0:0, so no canonicalization is needed to reproduce the tree.
    let dir_b = base.join("b");
    std::fs::create_dir_all(&dir_b).unwrap();
    let repo2 = create_repo(&dir_b, RepoMode::Archive);
    let commit_tar = ostrya(
        &[
            "commit",
            "--repo",
            repo2.to_str().unwrap(),
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
        ],
        Some(&tar),
        &[("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)],
    );
    commit_tar.ok();
    assert_eq!(
        commit_tar.stdout_trimmed(),
        COMMIT,
        "a tar stream on stdin commits the same tree as its unpacked form",
    );
}

#[test]
fn checkout_roundtrips_and_matches_tool() {
    let tmp = TmpDir::new("checkout");
    let base = tmp.path();
    build_fixture_source(base);
    // bare-user-only discards ownership and xattrs and caps the mode, so a
    // checkout applies no chown (runs unprivileged) and a commit -> checkout ->
    // commit round-trip is stable regardless of host-applied labels.
    let repo = create_repo(base, RepoMode::BareUserOnly);
    let src = base.join("src");

    let commit = ostrya(
        &[
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
            "--canonical-permissions",
            src.to_str().unwrap(),
        ],
        None,
        &[("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)],
    );
    let commit = commit.ok().stdout_trimmed();

    let dest_port = base.join("co-port");
    ostrya(
        &[
            "checkout",
            "--repo",
            repo.to_str().unwrap(),
            &commit,
            dest_port.to_str().unwrap(),
        ],
        None,
        &[],
    )
    .ok();

    // Re-committing the checkout with the same options reproduces the commit:
    // checkout is stable.
    let recommit = ostrya(
        &[
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
            "--canonical-permissions",
            dest_port.to_str().unwrap(),
        ],
        None,
        &[("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)],
    );
    assert_eq!(
        recommit.ok().stdout_trimmed(),
        commit,
        "commit -> checkout -> commit is stable",
    );

    // The port's checkout matches the tool's checkout of the same commit.
    if ostree_available() {
        let dest_tool = base.join("co-tool");
        let out = Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .args(["checkout", &commit, dest_tool.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "ostree checkout failed:\n{}",
            String::from_utf8_lossy(&out.stderr),
        );
        assert_eq!(
            describe_tree(&dest_port),
            describe_tree(&dest_tool),
            "port and tool checkouts agree",
        );
    }
}

#[test]
fn composefs_checkout_matches_library() {
    let tmp = TmpDir::new("composefs");
    let base = tmp.path();
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::BareUser);
    let src = base.join("src");

    let commit = ostrya(
        &[
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
            "--canonical-permissions",
            src.to_str().unwrap(),
        ],
        None,
        &[("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)],
    );
    let commit = commit.ok().stdout_trimmed();
    assert_eq!(commit, COMMIT, "bare-user commit id matches the fixture");

    let image_path = base.join("out.cfs");
    ostrya(
        &[
            "checkout",
            "--repo",
            repo.to_str().unwrap(),
            "--composefs",
            &commit,
            image_path.to_str().unwrap(),
        ],
        None,
        &[],
    )
    .ok();

    let cli_bytes = std::fs::read(&image_path).unwrap();
    let lib_bytes = block_on(async {
        let repo = Repo::open(&repo).await.unwrap();
        let checksum = repo.resolve_rev(&commit, false).await.unwrap().unwrap();
        repo.export_composefs(&checksum).await.unwrap().bytes
    });
    assert_eq!(
        cli_bytes, lib_bytes,
        "--composefs writes the library's EROFS image bytes",
    );
    assert!(!cli_bytes.is_empty(), "composefs image is non-empty");
}
