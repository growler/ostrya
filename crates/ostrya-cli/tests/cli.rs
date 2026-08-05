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

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ostrya::{CreateOptions, Repo, RepoMode, base64};
use ostrya_rt::block_on;

/// The fixture commit id, branch, and timestamp from `generate.sh`/MANIFEST.
const COMMIT: &str = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";
const BRANCH: &str = "test/main";
const SUBJECT: &str = "fixture commit";
const SOURCE_DATE_EPOCH: &str = "1700000000";

/// ed25519 sign fixture (shared with the library `sign_ed25519` test): the
/// base64 of the 64-byte secret key and the matching 32-byte public key.
const ED25519_SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const ED25519_PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

/// Whether the gpg and gpgv binaries are available.
#[cfg(feature = "gpg")]
fn gpg_available() -> bool {
    let has = |program: &str| {
        Command::new(program)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    };
    has("gpg") && has("gpgv")
}

/// A private GnuPG home directory holding one freshly generated,
/// passphrase-free ed25519 signing key. Dropping the fixture kills the
/// gpg-agent GnuPG auto-started for the directory.
#[cfg(feature = "gpg")]
struct GpgHome {
    dir: PathBuf,
}

#[cfg(feature = "gpg")]
impl GpgHome {
    /// Generate a signing key for `uid` in a new home directory under `base`.
    fn create(base: &Path, uid: &str) -> GpgHome {
        let dir = base.join("gnupghome");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let home = GpgHome { dir };
        let status = home
            .gpg()
            .args(["--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--quick-gen-key", uid, "ed25519", "sign", "never"])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-gen-key failed");
        home
    }

    /// A gpg command bound to this home directory, batch mode.
    fn gpg(&self) -> Command {
        let mut cmd = Command::new("gpg");
        cmd.arg("--homedir").arg(&self.dir).arg("--batch");
        cmd
    }

    /// The primary-key fingerprint, as uppercase hex.
    fn fingerprint(&self) -> String {
        let out = self
            .gpg()
            .args(["--with-colons", "--list-keys"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout).unwrap();
        text.lines()
            .find_map(|line| {
                let mut fields = line.split(':');
                (fields.next() == Some("fpr")).then(|| fields.nth(8).unwrap().to_owned())
            })
            .expect("a fpr record in the key listing")
    }

    /// Export the public keyring to `path`.
    fn export_to(&self, path: &Path) {
        let out = self.gpg().arg("--export").output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        std::fs::write(path, out.stdout).unwrap();
    }
}

#[cfg(feature = "gpg")]
impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&self.dir)
            .args(["--kill", "gpg-agent"])
            .status();
    }
}

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
    ostrya_in(None, args, stdin, env)
}

/// Run the `ostrya` binary from `cwd`, for the cases where a relative path
/// argument makes the working directory part of the behaviour under test.
fn ostrya_in(cwd: Option<&Path>, args: &[&str], stdin: Option<&[u8]>, env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ostrya"));
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
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

/// The environment variable that turns the reference-absent skip into a
/// failure. A harness setting it declares that `ostree` is installed, so a run
/// where it is not is a broken harness rather than a test to pass over.
const REQUIRE_OSTREE: &str = "OSTRYA_REQUIRE_OSTREE";

/// Whether the `ostree` tool is available for the cross-check tests. These
/// tests are the proof a matrix record cites with `evidence:`, so a harness
/// without the tool would otherwise report the cited cells as covered while no
/// assertion ran. With [`REQUIRE_OSTREE`] set the absence fails; without it the
/// test skips and says so.
fn ostree_available() -> bool {
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
    if !found {
        eprintln!("skipped: `ostree` is not installed");
    }
    found
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
    // checkout is stable. `--parent=none` keeps the second commit a root commit,
    // the branch it names already holding a tip the implicit parent would take.
    let recommit = ostrya(
        &[
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
            "--parent=none",
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

/// Commit the fixture tree into a fresh archive repo and return its path.
fn commit_fixture(base: &Path) -> PathBuf {
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
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
    assert_eq!(commit.ok().stdout_trimmed(), COMMIT, "fixture commit id");
    repo
}

#[test]
fn sign_verify_delete_ed25519() {
    let tmp = TmpDir::new("sign-ed25519");
    let base = tmp.path();
    let repo = commit_fixture(base);
    let repo_s = repo.to_str().unwrap();

    // Sign with the default (ed25519) engine using the base64 secret key.
    ostrya(
        &["sign", "--repo", repo_s, COMMIT, ED25519_SECRET_B64],
        None,
        &[],
    )
    .ok();

    // The public key verifies; a wrong key does not.
    let good = ostrya(
        &[
            "sign",
            "--verify",
            "--repo",
            repo_s,
            COMMIT,
            ED25519_PUBLIC_B64,
        ],
        None,
        &[],
    );
    good.ok();
    assert!(good.stdout_trimmed().contains("verification OK"));
    let wrong = base64::encode(&[0u8; 32]);
    let bad = ostrya(
        &["sign", "--verify", "--repo", repo_s, COMMIT, wrong.as_str()],
        None,
        &[],
    );
    assert!(!bad.status.success(), "a wrong key must not verify");

    // The tool verifies the port-written signature.
    if ostree_available() {
        let out = Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .args([
                "sign",
                "--verify",
                "--sign-type=ed25519",
                COMMIT,
                ED25519_PUBLIC_B64,
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "tool rejected the port's ed25519 signature:\n{}",
            String::from_utf8_lossy(&out.stderr),
        );
    }

    // Delete by the public key; verification then fails.
    let del = ostrya(
        &[
            "sign",
            "-d",
            "--repo",
            repo_s,
            "-s",
            "ed25519",
            COMMIT,
            ED25519_PUBLIC_B64,
        ],
        None,
        &[],
    );
    assert!(del.ok().stdout_trimmed().contains("Deleted 1"));
    let after = ostrya(
        &[
            "sign",
            "--verify",
            "--repo",
            repo_s,
            COMMIT,
            ED25519_PUBLIC_B64,
        ],
        None,
        &[],
    );
    assert!(
        !after.status.success(),
        "verification must fail after deletion"
    );
}

#[cfg(feature = "spki")]
#[test]
fn sign_verify_spki_selects_the_engine() {
    // The base64 PKCS#8 secret key and SubjectPublicKeyInfo public key shared
    // with the library `sign_spki` test.
    const SECRET_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcGv63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst";
    const PUBLIC_SPKI_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8X83xylD3ibci0xjFKMR4bwUtTU/YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDnRAG1Ua8eR8SKbLQ==";

    let tmp = TmpDir::new("sign-spki");
    let base = tmp.path();
    let repo = commit_fixture(base);
    let repo_s = repo.to_str().unwrap();

    ostrya(
        &[
            "sign",
            "--repo",
            repo_s,
            "-s",
            "spki",
            COMMIT,
            SECRET_PKCS8_B64,
        ],
        None,
        &[],
    )
    .ok();
    let verified = ostrya(
        &[
            "sign",
            "--verify",
            "--repo",
            repo_s,
            "-s",
            "spki",
            COMMIT,
            PUBLIC_SPKI_B64,
        ],
        None,
        &[],
    );
    verified.ok();
    assert!(verified.stdout_trimmed().contains("verification OK"));
}

#[cfg(feature = "gpg")]
#[test]
fn sign_verify_delete_gpg() {
    if !gpg_available() {
        eprintln!("skipping: gpg/gpgv not available");
        return;
    }
    let tmp = TmpDir::new("sign-gpg");
    let base = tmp.path();
    let repo = commit_fixture(base);
    let repo_s = repo.to_str().unwrap();
    let home = GpgHome::create(base, "Ostrya CLI Test <cli-gpg@ostrya.example>");
    let fpr = home.fingerprint();
    let home_s = home.dir.to_str().unwrap().to_owned();

    // gpg signing needs a KEY-ID.
    let missing = ostrya(&["sign", "--repo", repo_s, "-s", "gpg", COMMIT], None, &[]);
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("KEY-ID"),
        "gpg without a key should mention KEY-ID"
    );

    // Export the public keyring for verify and delete.
    let public = base.join("public.gpg");
    home.export_to(&public);
    let public_s = public.to_str().unwrap();

    // Sign with the key gpg resolves in the fixture home directory.
    ostrya(
        &[
            "sign",
            "--repo",
            repo_s,
            "-s",
            "gpg",
            "--gpg-homedir",
            &home_s,
            COMMIT,
            &fpr,
        ],
        None,
        &[],
    )
    .ok();

    // The exported keyring verifies the signature.
    let verified = ostrya(
        &[
            "sign",
            "--verify",
            "--repo",
            repo_s,
            "-s",
            "gpg",
            "--keys-file",
            public_s,
            COMMIT,
        ],
        None,
        &[],
    );
    verified.ok();
    assert!(verified.stdout_trimmed().contains("verification OK"));

    // Delete by the key's fingerprint, then verification fails.
    let del = ostrya(
        &[
            "sign",
            "-d",
            "--repo",
            repo_s,
            "-s",
            "gpg",
            "--keys-file",
            public_s,
            COMMIT,
            &fpr,
        ],
        None,
        &[],
    );
    assert!(del.ok().stdout_trimmed().contains("Deleted 1"));
    let after = ostrya(
        &[
            "sign",
            "--verify",
            "--repo",
            repo_s,
            "-s",
            "gpg",
            "--keys-file",
            public_s,
            COMMIT,
        ],
        None,
        &[],
    );
    assert!(
        !after.status.success(),
        "verification must fail after deletion"
    );
}

/// gpg verify with no `--keys-file` falls back to the default trusted set:
/// the `*.gpg` keyrings in the directory named by `OSTREE_GPG_HOME`.
#[cfg(feature = "gpg")]
#[test]
fn sign_verify_gpg_default_trust() {
    if !gpg_available() {
        eprintln!("skipping: gpg/gpgv not available");
        return;
    }
    let tmp = TmpDir::new("sign-gpg-default");
    let base = tmp.path();
    let repo = commit_fixture(base);
    let repo_s = repo.to_str().unwrap();
    let home = GpgHome::create(base, "Ostrya Default Trust <default-gpg@ostrya.example>");
    let fpr = home.fingerprint();
    let home_s = home.dir.to_str().unwrap().to_owned();

    // Sign, then publish the public keyring as `*.gpg` in a trusted.gpg.d dir.
    ostrya(
        &[
            "sign",
            "--repo",
            repo_s,
            "-s",
            "gpg",
            "--gpg-homedir",
            &home_s,
            COMMIT,
            &fpr,
        ],
        None,
        &[],
    )
    .ok();
    let trusted = base.join("trusted.gpg.d");
    std::fs::create_dir(&trusted).unwrap();
    home.export_to(&trusted.join("key.gpg"));
    let trusted_s = trusted.to_str().unwrap();

    // With OSTREE_GPG_HOME pointing at that directory and no --keys-file,
    // verification succeeds against the discovered keyring.
    let verified = ostrya(
        &["sign", "--verify", "--repo", repo_s, "-s", "gpg", COMMIT],
        None,
        &[("OSTREE_GPG_HOME", trusted_s)],
    );
    verified.ok();
    assert!(verified.stdout_trimmed().contains("verification OK"));

    // An OSTREE_GPG_HOME with no keyrings trusts nothing, so verify fails.
    let empty = base.join("empty.gpg.d");
    std::fs::create_dir(&empty).unwrap();
    let failed = ostrya(
        &["sign", "--verify", "--repo", repo_s, "-s", "gpg", COMMIT],
        None,
        &[("OSTREE_GPG_HOME", empty.to_str().unwrap())],
    );
    assert!(
        !failed.status.success(),
        "verify must fail with an empty trusted set"
    );
}

/// Find the single delta directory under `repo/deltas`.
fn only_delta_dir(repo: &Path) -> PathBuf {
    let deltas = repo.join("deltas");
    std::fs::read_dir(&deltas)
        .unwrap()
        .flat_map(|fanout| std::fs::read_dir(fanout.unwrap().path()).unwrap())
        .map(|leaf| leaf.unwrap().path())
        .next()
        .unwrap_or_else(|| panic!("no delta directory under {}", deltas.display()))
}

#[test]
fn static_delta_list_and_apply_offline() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("static-delta");
    let base = tmp.path();
    let repo = commit_fixture(base);
    let repo_arg = format!("--repo={}", repo.display());

    // The tool generates a from-scratch delta to the fixture commit.
    let generated = Command::new("ostree")
        .args([
            &repo_arg,
            "static-delta",
            "generate",
            "--empty",
            "--to",
            COMMIT,
        ])
        .output()
        .unwrap();
    assert!(generated.status.success(), "tool delta generate failed");

    // `list` prints the delta names, matching the tool.
    let listed = ostrya(
        &["static-delta", "--repo", repo.to_str().unwrap(), "list"],
        None,
        &[],
    );
    assert_eq!(listed.ok().stdout_trimmed(), COMMIT);

    // `apply-offline` reproduces the target commit in a fresh repository.
    let dst = base.join("dst");
    block_on(async {
        Repo::create(&dst, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
    });
    let delta_dir = only_delta_dir(&repo);
    let applied = ostrya(
        &[
            "static-delta",
            "--repo",
            dst.to_str().unwrap(),
            "apply-offline",
            delta_dir.to_str().unwrap(),
        ],
        None,
        &[],
    );
    assert_eq!(applied.ok().stdout_trimmed(), COMMIT, "apply prints target");

    // The tool reads the tree the port produced.
    let ls = Command::new("ostree")
        .args([&format!("--repo={}", dst.display()), "ls", "-R", COMMIT])
        .output()
        .unwrap();
    assert!(
        ls.status.success(),
        "tool could not read the applied tree:\n{}",
        String::from_utf8_lossy(&ls.stderr)
    );
}

#[test]
fn static_delta_generate_signs_and_indexes() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("static-delta-generate");
    let base = tmp.path();
    let repo = commit_fixture(base);
    let repo_arg = repo.to_str().unwrap().to_owned();

    // `generate` prints the directory it wrote, signs it, and indexes it.
    let generated = ostrya(
        &[
            "static-delta",
            "--repo",
            &repo_arg,
            "generate",
            "--to",
            COMMIT,
            "--sign",
            ED25519_SECRET_B64,
            "--reindex",
        ],
        None,
        &[],
    );
    let dir = PathBuf::from(generated.ok().stdout_trimmed());
    assert!(dir.join("superblock").exists(), "no superblock at {dir:?}");
    assert_eq!(dir, only_delta_dir(&repo), "delta written outside deltas/");

    // The tool verifies the signature the port wrote and applies the delta.
    let verified = Command::new("ostree")
        .args([
            &format!("--repo={}", repo.display()),
            "static-delta",
            "verify",
            COMMIT,
            ED25519_PUBLIC_B64,
        ])
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "tool rejected the port's delta signature:\n{}",
        String::from_utf8_lossy(&verified.stderr)
    );

    let indexes = Command::new("ostree")
        .args([
            &format!("--repo={}", repo.display()),
            "static-delta",
            "indexes",
        ])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&indexes.stdout)
            .lines()
            .any(|line| line.trim() == COMMIT),
        "the index does not list the target commit"
    );

    let dst = base.join("dst");
    block_on(async {
        Repo::create(&dst, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
    });
    let applied = ostrya(
        &[
            "static-delta",
            "--repo",
            dst.to_str().unwrap(),
            "apply-offline",
            dir.to_str().unwrap(),
        ],
        None,
        &[],
    );
    assert_eq!(applied.ok().stdout_trimmed(), COMMIT);
}

#[test]
fn static_delta_generate_relative_output_dir() {
    let tmp = TmpDir::new("static-delta-output-dir");
    let base = tmp.path();
    let repo = commit_fixture(base);

    // `--output-dir` resolves against the working directory, so the delta lands
    // at base/rel and signing reaches the same files.
    let generated = ostrya_in(
        Some(base),
        &[
            "static-delta",
            "--repo",
            repo.to_str().unwrap(),
            "generate",
            "--to",
            COMMIT,
            "--output-dir",
            "rel",
            "--sign",
            ED25519_SECRET_B64,
        ],
        None,
        &[],
    );
    assert_eq!(generated.ok().stdout_trimmed(), "rel");
    let dir = base.join("rel");
    assert!(dir.join("superblock").exists(), "no superblock at {dir:?}");
    assert!(
        !repo.join("rel").exists(),
        "the output directory was resolved against the repository too"
    );
    assert!(
        std::fs::read(dir.join("superblock"))
            .unwrap()
            .starts_with(b"OSTSGNDT"),
        "the delta at {dir:?} is unsigned"
    );

    // The signed delta applies into a fresh repository.
    let dst = base.join("dst");
    block_on(async {
        Repo::create(&dst, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
    });
    let applied = ostrya(
        &[
            "static-delta",
            "--repo",
            dst.to_str().unwrap(),
            "apply-offline",
            dir.to_str().unwrap(),
        ],
        None,
        &[],
    );
    assert_eq!(applied.ok().stdout_trimmed(), COMMIT);
}

#[test]
fn static_delta_generate_refuses_output_dir_with_reindex() {
    let tmp = TmpDir::new("static-delta-output-dir-reindex");
    let base = tmp.path();
    let repo = commit_fixture(base);
    let out = base.join("out");

    // Indexing covers the deltas under the repository's `deltas/` tree, so the
    // pair would write a delta and index nothing. It is refused instead, before
    // anything is written.
    let refused = ostrya(
        &[
            "static-delta",
            "--repo",
            repo.to_str().unwrap(),
            "generate",
            "--to",
            COMMIT,
            "--output-dir",
            out.to_str().unwrap(),
            "--reindex",
        ],
        None,
        &[],
    );
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--output-dir"),
        "the refusal does not name the conflicting flag: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(!out.exists(), "the output directory was created anyway");
    assert!(
        !repo.join("delta-indexes").exists(),
        "the index cache was rebuilt anyway"
    );
}

// --- pull over HTTP (Phase 16f) ----------------------------------------------

/// A static file server over HTTP/1.1, serving one directory. The threads are
/// detached and the listener closes with the process.
///
/// It answers `GET /<path>` with the file's bytes and 404 where the directory
/// holds no such regular file, which is the whole of what a repository fetch
/// reads. Each accepted connection runs in its own thread and stays open for as
/// many requests as the client sends, so a pull holding several fetches at once
/// is served without ordering them.
struct FileServer {
    port: u16,
    log: Arc<Mutex<Vec<ServedRequest>>>,
}

/// One request the server answered.
#[derive(Clone)]
struct ServedRequest {
    /// The request path with its leading `/` removed.
    path: String,
    /// The header lines, as sent.
    headers: Vec<String>,
}

impl FileServer {
    fn start(root: &Path) -> FileServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let root = root.to_owned();
        let thread_log = Arc::clone(&log);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let root = root.clone();
                let log = Arc::clone(&thread_log);
                std::thread::spawn(move || serve_connection(stream, &root, &log));
            }
        });
        FileServer { port, log }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The paths served so far, in the order they arrived.
    fn seen(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.path.clone())
            .collect()
    }

    /// Whether every request served so far carried `line` among its headers.
    fn every_request_carried(&self, line: &str) -> bool {
        let log = self.log.lock().unwrap();
        !log.is_empty() && log.iter().all(|r| r.headers.iter().any(|h| h == line))
    }

    /// Drop the record, so a second pull's requests are read on their own.
    fn clear(&self) {
        self.log.lock().unwrap().clear();
    }
}

/// Answer requests on one connection until the client closes it.
fn serve_connection(stream: TcpStream, root: &Path, log: &Mutex<Vec<ServedRequest>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone connection"));
    let mut writer = stream;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let path = match line.split_whitespace().nth(1) {
            Some(target) => target.trim_start_matches('/').to_owned(),
            None => return,
        };
        // The requests a pull sends carry no body, so the head ends the request.
        let mut headers = Vec::new();
        loop {
            let mut header = String::new();
            match reader.read_line(&mut header) {
                Ok(0) | Err(_) => return,
                Ok(_) if header == "\r\n" || header == "\n" => break,
                Ok(_) => headers.push(header.trim_end().to_owned()),
            }
        }
        log.lock().unwrap().push(ServedRequest {
            path: path.clone(),
            headers,
        });

        let body = served_path(root, &path).and_then(|p| std::fs::read(p).ok());
        let head = match &body {
            Some(bytes) => format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", bytes.len()),
            None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned(),
        };
        if writer.write_all(head.as_bytes()).is_err() {
            return;
        }
        if let Some(bytes) = body
            && writer.write_all(&bytes).is_err()
        {
            return;
        }
    }
}

/// The file a request path names under `root`, or `None` where the path names
/// no regular file or would leave the directory.
fn served_path(root: &Path, path: &str) -> Option<PathBuf> {
    if path.is_empty() || path.split('/').any(|part| part == ".." || part == ".") {
        return None;
    }
    let joined = root.join(path);
    joined.is_file().then_some(joined)
}

/// Append `[remote "origin"]` with `url` and the extra keys `extra` supplies to
/// a repository's config.
fn configure_remote(repo: &Path, url: &str, extra: &str) {
    let config = repo.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!("\n[remote \"origin\"]\nurl={url}\n{extra}"));
    std::fs::write(&config, text).unwrap();
}

/// A remote archive repository under `base/<name>` holding the fixture commit
/// on `test/main`, with a summary.
fn build_remote(base: &Path, name: &str) -> PathBuf {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let repo = commit_fixture(&dir);
    ostrya(
        &["summary", "--repo", repo.to_str().unwrap(), "-u"],
        None,
        &[],
    )
    .ok();
    repo
}

/// An empty archive repository under `base/<name>`, the destination of a pull.
fn build_dest(base: &Path, name: &str) -> PathBuf {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    create_repo(&dir, RepoMode::Archive)
}

#[test]
fn pull_over_http_reproduces_the_remote_tree() {
    let tmp = TmpDir::new("pull-http");
    let base = tmp.path();
    let remote = build_remote(base, "remote");
    let server = FileServer::start(&remote);
    // bare-user-only discards ownership, so the checkout below applies no chown
    // and runs unprivileged. The fixture is committed under canonical
    // permissions, which is the form that destination stores.
    let dest_dir = base.join("dest");
    std::fs::create_dir_all(&dest_dir).unwrap();
    let dest = create_repo(&dest_dir, RepoMode::BareUserOnly);
    // The remotes these tests serve publish unsigned commits, and `gpg-verify`
    // defaults to on, so the section states the policy the pull runs under.
    configure_remote(&dest, &server.url(), "gpg-verify=false\n");

    let pulled = ostrya(
        &[
            "pull",
            "--repo",
            dest.to_str().unwrap(),
            "--http-header",
            "X-Ostrya-Test=on",
            "--http-header",
            "X-Trace=a=b=c",
            "origin",
            BRANCH,
        ],
        None,
        &[],
    );
    assert!(
        pulled
            .ok()
            .stdout_trimmed()
            .ends_with("bytes content written"),
        "unexpected stats line: {}",
        pulled.stdout_trimmed()
    );

    // The ref lands under the remote's own name, and the tree it names checks
    // out as the tree the fixture committed.
    assert_eq!(
        resolve(&dest, &format!("origin:{BRANCH}")).as_deref(),
        Some(COMMIT)
    );
    let out = base.join("checkout");
    ostrya(
        &[
            "checkout",
            "--repo",
            dest.to_str().unwrap(),
            COMMIT,
            out.to_str().unwrap(),
        ],
        None,
        &[],
    )
    .ok();
    assert_eq!(describe_tree(&out), describe_tree(&base.join("remote/src")));

    // The header reached every request the fetcher sent.
    assert!(
        server.every_request_carried("x-ostrya-test: on"),
        "the extra header did not reach every request: {:?}",
        server.seen()
    );
    // A header value holding an `=` arrives whole, split only at the first one.
    assert!(
        server.every_request_carried("x-trace: a=b=c"),
        "the header with an `=` in its value did not reach every request: {:?}",
        server.seen()
    );
    assert!(
        server.seen().contains(&"config".to_owned()),
        "the remote's config was not read: {:?}",
        server.seen()
    );
}

#[test]
fn pull_rejects_a_header_without_a_value() {
    let run = ostrya(&["pull", "--http-header", "X-Bad", "origin"], None, &[]);
    assert!(!run.status.success(), "a header with no value was accepted");
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("expected NAME=VALUE"),
        "the refusal does not name the format: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn pull_url_override_states_its_own_policy() {
    let tmp = TmpDir::new("pull-url");
    let base = tmp.path();
    let remote = build_remote(base, "remote");
    let server = FileServer::start(&remote);
    let dest = build_dest(base, "dest");
    let dest_s = dest.to_str().unwrap();
    let url = server.url();

    // No `[remote "origin"]` section describes this remote, so the pull takes
    // the configuration defaults. `gpg-verify` is on by default and the remote
    // holds no keys, so the pull is refused and publishes nothing.
    let refused = ostrya(
        &["pull", "--repo", dest_s, "--url", &url, "origin", BRANCH],
        None,
        &[],
    );
    assert!(!refused.status.success(), "an unsigned commit was accepted");
    assert_eq!(resolve(&dest, &format!("origin:{BRANCH}")), None);

    // Turning the check off on the command line states the policy the absent
    // section cannot.
    ostrya(
        &[
            "pull",
            "--repo",
            dest_s,
            "--url",
            &url,
            "--gpg-verify=false",
            "origin",
            BRANCH,
        ],
        None,
        &[],
    )
    .ok();
    assert_eq!(
        resolve(&dest, &format!("origin:{BRANCH}")).as_deref(),
        Some(COMMIT)
    );
}

#[test]
fn pull_mirror_writes_local_refs_and_copies_the_summary() {
    let tmp = TmpDir::new("pull-mirror");
    let base = tmp.path();
    let remote = build_remote(base, "remote");
    let server = FileServer::start(&remote);
    let dest = build_dest(base, "dest");
    configure_remote(&dest, &server.url(), "gpg-verify=false\n");

    // A mirror pull naming no ref takes every ref the summary lists.
    ostrya(
        &[
            "pull",
            "--repo",
            dest.to_str().unwrap(),
            "--mirror",
            "origin",
        ],
        None,
        &[],
    )
    .ok();

    assert_eq!(resolve(&dest, BRANCH).as_deref(), Some(COMMIT));
    assert_eq!(resolve(&dest, &format!("origin:{BRANCH}")), None);
    assert_eq!(
        std::fs::read(dest.join("summary")).unwrap(),
        std::fs::read(remote.join("summary")).unwrap(),
        "the mirror did not copy the remote's summary"
    );
}

#[test]
fn pull_depth_and_commit_metadata_only() {
    let tmp = TmpDir::new("pull-depth");
    let base = tmp.path();
    let remote = build_remote(base, "remote");
    let remote_s = remote.to_str().unwrap().to_owned();

    // A second commit on the same branch, so the ref names a chain of two.
    std::fs::write(base.join("remote/src/hello.txt"), b"hello again\n").unwrap();
    let child = ostrya(
        &[
            "commit",
            "--repo",
            &remote_s,
            "-b",
            BRANCH,
            "--parent",
            COMMIT,
            "--canonical-permissions",
            base.join("remote/src").to_str().unwrap(),
        ],
        None,
        &[("SOURCE_DATE_EPOCH", "1700000100")],
    )
    .ok()
    .stdout_trimmed();
    ostrya(&["summary", "--repo", &remote_s, "-u"], None, &[]).ok();

    let server = FileServer::start(&remote);
    let dest = build_dest(base, "dest");
    configure_remote(&dest, &server.url(), "gpg-verify=false\n");

    ostrya(
        &[
            "pull",
            "--repo",
            dest.to_str().unwrap(),
            "--depth=-1",
            "--commit-metadata-only",
            "origin",
            BRANCH,
        ],
        None,
        &[],
    )
    .ok();

    // Both commits of the chain are here, each still marked partial, and no
    // content object was fetched.
    for commit in [child.as_str(), COMMIT] {
        let object = dest.join(format!("objects/{}/{}.commit", &commit[..2], &commit[2..]));
        assert!(object.is_file(), "commit {commit} was not imported");
        let marker = dest.join(format!(
            "state/{}{}.commitpartial",
            &commit[..2],
            &commit[2..]
        ));
        assert!(marker.is_file(), "commit {commit} is not marked partial");
    }
    assert!(
        !server.seen().iter().any(|path| path.ends_with(".filez")),
        "a commit-only pull fetched content: {:?}",
        server.seen()
    );
}

#[test]
fn pull_timestamp_check_refuses_an_older_tip() {
    let tmp = TmpDir::new("pull-timestamp");
    let base = tmp.path();
    let newer = build_remote(base, "newer");

    // A second remote publishing the same branch at an earlier timestamp, which
    // is the downgrade the check exists to refuse.
    let older_dir = base.join("older");
    std::fs::create_dir_all(&older_dir).unwrap();
    let older = create_repo(&older_dir, RepoMode::Archive);
    let older_s = older.to_str().unwrap().to_owned();
    let older_commit = ostrya(
        &[
            "commit",
            "--repo",
            &older_s,
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
            "--canonical-permissions",
            base.join("newer/src").to_str().unwrap(),
        ],
        None,
        &[("SOURCE_DATE_EPOCH", "1600000000")],
    )
    .ok()
    .stdout_trimmed();
    ostrya(&["summary", "--repo", &older_s, "-u"], None, &[]).ok();

    let newer_server = FileServer::start(&newer);
    let older_server = FileServer::start(&older);
    let dest = build_dest(base, "dest");
    let dest_s = dest.to_str().unwrap();
    configure_remote(&dest, &newer_server.url(), "gpg-verify=false\n");

    ostrya(&["pull", "--repo", dest_s, "origin", BRANCH], None, &[]).ok();
    assert_eq!(
        resolve(&dest, &format!("origin:{BRANCH}")).as_deref(),
        Some(COMMIT)
    );

    let older_url = older_server.url();
    let refused = ostrya(
        &[
            "pull", "--repo", dest_s, "--url", &older_url, "-T", "origin", BRANCH,
        ],
        None,
        &[],
    );
    assert!(!refused.status.success(), "a downgrade was accepted");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("older"),
        "the refusal does not name the timestamp: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(
        resolve(&dest, &format!("origin:{BRANCH}")).as_deref(),
        Some(COMMIT),
        "the refused pull moved the ref"
    );

    // Without the check the same pull moves the ref back.
    ostrya(
        &[
            "pull", "--repo", dest_s, "--url", &older_url, "origin", BRANCH,
        ],
        None,
        &[],
    )
    .ok();
    assert_eq!(
        resolve(&dest, &format!("origin:{BRANCH}")).as_deref(),
        Some(older_commit.as_str())
    );
}

#[test]
fn pull_timestamp_check_from_rev_refuses_an_older_tip() {
    let tmp = TmpDir::new("pull-timestamp-rev");
    let base = tmp.path();
    let newer = build_remote(base, "newer");

    // A second remote publishing the same branch at an earlier timestamp, which
    // is the downgrade the check exists to refuse.
    let older_dir = base.join("older");
    std::fs::create_dir_all(&older_dir).unwrap();
    let older = create_repo(&older_dir, RepoMode::Archive);
    let older_s = older.to_str().unwrap().to_owned();
    ostrya(
        &[
            "commit",
            "--repo",
            &older_s,
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
            "--canonical-permissions",
            base.join("newer/src").to_str().unwrap(),
        ],
        None,
        &[("SOURCE_DATE_EPOCH", "1600000000")],
    )
    .ok();
    ostrya(&["summary", "--repo", &older_s, "-u"], None, &[]).ok();

    let newer_server = FileServer::start(&newer);
    let older_server = FileServer::start(&older);
    let dest = build_dest(base, "dest");
    let dest_s = dest.to_str().unwrap();
    configure_remote(&dest, &newer_server.url(), "gpg-verify=false\n");

    ostrya(&["pull", "--repo", dest_s, "origin", BRANCH], None, &[]).ok();
    assert_eq!(
        resolve(&dest, &format!("origin:{BRANCH}")).as_deref(),
        Some(COMMIT)
    );

    // `origin:test/main` names the ref the destination now holds, so the rev
    // resolves to the newer tip pulled above.
    let older_url = older_server.url();
    let from_rev = format!("origin:{BRANCH}");
    let refused = ostrya(
        &[
            "pull",
            "--repo",
            dest_s,
            "--url",
            &older_url,
            "--timestamp-check-from-rev",
            &from_rev,
            "origin",
            BRANCH,
        ],
        None,
        &[],
    );
    assert!(!refused.status.success(), "a downgrade was accepted");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("older"),
        "the refusal does not name the timestamp: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(
        resolve(&dest, &format!("origin:{BRANCH}")).as_deref(),
        Some(COMMIT),
        "the refused pull moved the ref"
    );
}

#[test]
fn pull_static_delta_switches() {
    let tmp = TmpDir::new("pull-delta");
    let base = tmp.path();
    let remote = build_remote(base, "remote");
    let remote_s = remote.to_str().unwrap().to_owned();

    // A from-scratch delta to the fixture commit, indexed, so a pull into an
    // empty destination finds one.
    ostrya(
        &[
            "static-delta",
            "--repo",
            &remote_s,
            "generate",
            "--to",
            COMMIT,
            "--reindex",
        ],
        None,
        &[],
    )
    .ok();
    ostrya(&["summary", "--repo", &remote_s, "-u"], None, &[]).ok();

    let server = FileServer::start(&remote);
    let url = server.url();
    let dest = build_dest(base, "dest");
    configure_remote(&dest, &url, "gpg-verify=false\n");

    // The default pull takes the delta: its superblock is fetched, and the
    // objects it carries are never asked for loose.
    ostrya(
        &["pull", "--repo", dest.to_str().unwrap(), "origin", BRANCH],
        None,
        &[],
    )
    .ok();
    assert_eq!(
        resolve(&dest, &format!("origin:{BRANCH}")).as_deref(),
        Some(COMMIT)
    );
    assert!(
        server
            .seen()
            .iter()
            .any(|path| path.ends_with("/superblock")),
        "no delta superblock was fetched: {:?}",
        server.seen()
    );
    assert!(
        !server.seen().iter().any(|path| path.ends_with(".filez")),
        "the delta's own objects were fetched loose: {:?}",
        server.seen()
    );

    // The same pull with deltas off asks for the objects loose instead.
    server.clear();
    let plain = build_dest(base, "plain");
    configure_remote(&plain, &url, "gpg-verify=false\n");
    ostrya(
        &[
            "pull",
            "--repo",
            plain.to_str().unwrap(),
            "--disable-static-deltas",
            "origin",
            BRANCH,
        ],
        None,
        &[],
    )
    .ok();
    assert_eq!(
        resolve(&plain, &format!("origin:{BRANCH}")).as_deref(),
        Some(COMMIT)
    );
    assert!(
        !server
            .seen()
            .iter()
            .any(|path| path.ends_with("/superblock")),
        "a delta was fetched with --disable-static-deltas: {:?}",
        server.seen()
    );
    assert!(
        server.seen().iter().any(|path| path.ends_with(".filez")),
        "no object was fetched loose: {:?}",
        server.seen()
    );

    // A remote advertising no delta at all is refused when one is required.
    let bare_remote = build_remote(base, "nodelta");
    let bare_server = FileServer::start(&bare_remote);
    let required = build_dest(base, "required");
    configure_remote(&required, &bare_server.url(), "gpg-verify=false\n");
    let refused = ostrya(
        &[
            "pull",
            "--repo",
            required.to_str().unwrap(),
            "--require-static-deltas",
            "origin",
            BRANCH,
        ],
        None,
        &[],
    );
    assert!(
        !refused.status.success(),
        "a delta-less remote was accepted"
    );
    assert_eq!(resolve(&required, &format!("origin:{BRANCH}")), None);
}

#[test]
fn pull_localcache_repo_supplies_the_objects() {
    let tmp = TmpDir::new("pull-localcache");
    let base = tmp.path();
    let remote = build_remote(base, "remote");
    let server = FileServer::start(&remote);
    let dest = build_dest(base, "dest");
    configure_remote(&dest, &server.url(), "gpg-verify=false\n");

    // A cache holding everything the commit reaches, which is the remote's own
    // directory read as a local repository.
    ostrya(
        &[
            "pull",
            "--repo",
            dest.to_str().unwrap(),
            "-L",
            remote.to_str().unwrap(),
            "origin",
            BRANCH,
        ],
        None,
        &[],
    )
    .ok();

    assert_eq!(
        resolve(&dest, &format!("origin:{BRANCH}")).as_deref(),
        Some(COMMIT)
    );
    assert!(
        !server.seen().iter().any(|path| path.ends_with(".filez")),
        "the cache was not consulted before the network: {:?}",
        server.seen()
    );
}

#[test]
fn pull_sign_verify_switch_overrides_the_configuration() {
    let tmp = TmpDir::new("pull-sign-verify");
    let base = tmp.path();
    let remote = build_remote(base, "remote");
    let remote_s = remote.to_str().unwrap().to_owned();
    ostrya(
        &["sign", "--repo", &remote_s, COMMIT, ED25519_SECRET_B64],
        None,
        &[],
    )
    .ok();
    let server = FileServer::start(&remote);
    let url = server.url();

    // A destination asking for the sign-api axis, with the key that signed the
    // commit: the pull carries a signature the policy accepts.
    let signed = build_dest(base, "signed");
    configure_remote(
        &signed,
        &url,
        &format!(
            "gpg-verify=false\nsign-verify=ed25519\nverification-ed25519-key={ED25519_PUBLIC_B64}\n"
        ),
    );
    ostrya(
        &["pull", "--repo", signed.to_str().unwrap(), "origin", BRANCH],
        None,
        &[],
    )
    .ok();
    assert_eq!(
        resolve(&signed, &format!("origin:{BRANCH}")).as_deref(),
        Some(COMMIT)
    );

    // The same configuration with another key refuses the commit, and the
    // switch turning the axis off on the command line accepts it.
    let other = base64::encode(&[0u8; 32]);
    let overridden = build_dest(base, "overridden");
    configure_remote(
        &overridden,
        &url,
        &format!("gpg-verify=false\nsign-verify=ed25519\nverification-ed25519-key={other}\n"),
    );
    let dest_s = overridden.to_str().unwrap();
    let refused = ostrya(&["pull", "--repo", dest_s, "origin", BRANCH], None, &[]);
    assert!(
        !refused.status.success(),
        "a foreign key accepted the signature"
    );
    ostrya(
        &[
            "pull",
            "--repo",
            dest_s,
            "--sign-verify=false",
            "origin",
            BRANCH,
        ],
        None,
        &[],
    )
    .ok();
    assert_eq!(
        resolve(&overridden, &format!("origin:{BRANCH}")).as_deref(),
        Some(COMMIT)
    );
}

// --- Phase 17b: refs, rev-parse, and cat against the tool ---------------------
//
// These five tests are the `evidence:` the M10 records
// `refs/nested-prefix-stripping`, `refs/alias-round-trip`,
// `refs/collections-listing`, `rev-parse/ancestry-suffix`, and
// `cat/path-resolution-edges` cite: each covers a case the conformance
// harness's `repo-with-commit` setup cannot bind, so the record names the test
// instead of a `run:` line (`docs/conformance/m10-cli-behavior.matrix`).
//
// Each test builds one repository, gives each implementation its own
// byte-identical copy where the invocation mutates state, and compares the raw
// standard output, standard error, and exit status. The two copies hold the same
// commits, so no checksum needs masking.

/// Run the `ostree` tool with `args`.
fn ostree(args: &[&str]) -> Run {
    ostree_env(args, &[])
}

/// The same with `env` added to the tool's environment, which the commits both
/// implementations must reproduce need for `SOURCE_DATE_EPOCH`.
fn ostree_env(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut command = Command::new("ostree");
    command.args(args).stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    let out = command.output().expect("spawn ostree");
    Run {
        status: out.status,
        stdout: out.stdout,
        stderr: out.stderr,
    }
}

/// Run `args` against each implementation's own repository, passing the path as
/// a trailing `--repo`, the position both accept in either form.
fn run_both(port_repo: &Path, tool_repo: &Path, args: &[&str]) -> (Run, Run) {
    run_both_env(port_repo, tool_repo, args, &[])
}

/// The same with `env` given to both implementations.
fn run_both_env(
    port_repo: &Path,
    tool_repo: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (Run, Run) {
    let with_repo = |repo: &Path| {
        let mut all = vec![args[0].to_owned(), "--repo".to_owned()];
        all.push(repo.display().to_string());
        all.extend(args[1..].iter().map(|arg| (*arg).to_owned()));
        all
    };
    let port_args = with_repo(port_repo);
    let tool_args = with_repo(tool_repo);
    let port = ostrya(
        &port_args.iter().map(String::as_str).collect::<Vec<_>>(),
        None,
        env,
    );
    let tool = ostree_env(
        &tool_args.iter().map(String::as_str).collect::<Vec<_>>(),
        env,
    );
    (port, tool)
}

/// Run `args` against `repo` under both implementations and assert that the
/// exit status and both streams agree.
fn assert_agrees(port_repo: &Path, tool_repo: &Path, args: &[&str]) {
    assert_agrees_env(port_repo, tool_repo, args, &[]);
}

/// The same with `env` given to both implementations.
fn assert_agrees_env(port_repo: &Path, tool_repo: &Path, args: &[&str], env: &[(&str, &str)]) {
    let (port, tool) = run_both_env(port_repo, tool_repo, args, env);
    let render = |run: &Run| {
        format!(
            "exit {:?}\nstdout: {:?}\nstderr: {:?}",
            run.status.code(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr),
        )
    };
    assert_eq!(
        render(&port),
        render(&tool),
        "`ostrya {}` and `ostree {}` disagree",
        args.join(" "),
        args.join(" "),
    );
}

/// The same, for a failing invocation whose message both implementations word
/// identically: the exit status, standard output, and the last line of standard
/// error, which is the `error: ` line the usage block precedes.
fn assert_agrees_on_error(port_repo: &Path, tool_repo: &Path, args: &[&str], message: &str) {
    let (port, tool) = run_both(port_repo, tool_repo, args);
    for (who, run) in [("port", &port), ("tool", &tool)] {
        assert_eq!(
            run.status.code(),
            Some(1),
            "the {who} did not exit 1 for `{}`",
            args.join(" ")
        );
        let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
        assert!(
            stderr.contains(message),
            "the {who}'s stderr for `{}` lacks {message:?}:\n{stderr}",
            args.join(" ")
        );
    }
    assert_eq!(
        String::from_utf8_lossy(&port.stdout),
        String::from_utf8_lossy(&tool.stdout),
        "`{}` wrote different standard output",
        args.join(" ")
    );
}

/// One line per path under `refs/`, sorted: a symlink with its target, a
/// directory with a trailing `/`, and a ref file with its contents.
fn describe_refs(repo: &Path) -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = format!("{prefix}{name}");
            let meta = entry.path().symlink_metadata().unwrap();
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(entry.path()).unwrap();
                out.push(format!("{rel} -> {}", target.display()));
            } else if meta.is_dir() {
                out.push(format!("{rel}/"));
                walk(&entry.path(), &format!("{rel}/"), out);
            } else {
                let content = std::fs::read_to_string(entry.path()).unwrap();
                out.push(format!("{rel} = {}", content.trim()));
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo.join("refs"), "", &mut out);
    out
}

/// Copy `repo` to `base/<name>` so each implementation mutates its own tree
/// while both hold the same commits.
fn clone_repo(base: &Path, repo: &Path, name: &str) -> PathBuf {
    let destination = base.join(name);
    let status = Command::new("cp")
        .arg("-a")
        .arg(repo)
        .arg(&destination)
        .status()
        .expect("spawn cp");
    assert!(status.success(), "cp -a of the repository failed");
    destination
}

/// Commit `tree` onto `branch`, optionally parented on `parent`, and return the
/// new commit checksum.
fn commit_tree(repo: &Path, branch: &str, tree: &Path, parent: Option<&str>) -> String {
    let repo = repo.to_str().unwrap();
    let tree = tree.to_str().unwrap();
    let mut args = vec![
        "commit",
        "--repo",
        repo,
        "-b",
        branch,
        "-s",
        branch,
        "--canonical-permissions",
    ];
    if let Some(parent) = parent {
        args.push("--parent");
        args.push(parent);
    }
    args.push(tree);
    ostrya(&args, None, &[]).ok().stdout_trimmed()
}

/// Point a ref at a commit by writing its file, for the refs a CLI option does
/// not create: a remote ref and a collection-mirror ref.
fn write_ref_file(repo: &Path, relpath: &str, commit: &str) {
    let path = repo.join("refs").join(relpath);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, format!("{commit}\n")).unwrap();
}

/// A repository holding a nested branch name, a flat one, and two remote refs,
/// which the prefix-stripping and sort-order cases need.
fn build_multi_ref_repo(base: &Path) -> PathBuf {
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
    let src = base.join("src");
    for branch in ["test/main", "test/other", "deep/nest/ing", "plain"] {
        commit_tree(&repo, branch, &src, None);
    }
    let head = resolve(&repo, "test/main").unwrap();
    write_ref_file(&repo, "remotes/origin/rr/x", &head);
    write_ref_file(&repo, "remotes/origin/rr/deep/y", &head);
    repo
}

#[test]
fn refs_listing_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refs-list");
    let base = tmp.path();
    let repo = build_multi_ref_repo(base);
    // Listing mutates nothing, so both implementations read the one repository
    // and their output compares with no checksum masking.
    for args in [
        vec!["refs"],
        vec!["refs", "--list"],
        vec!["refs", "-r"],
        vec!["refs", "test"],
        vec!["refs", "test", "--list"],
        vec!["refs", "-r", "test"],
        vec!["refs", "-r", "test", "--list"],
        vec!["refs", "deep"],
        vec!["refs", "deep/nest"],
        vec!["refs", "plain"],
        vec!["refs", "test/main"],
        vec!["refs", "nosuch"],
        vec!["refs", "origin"],
        vec!["refs", "origin:rr"],
        vec!["refs", "-r", "origin:rr"],
        vec!["refs", "origin:rr/deep"],
        vec!["refs", "origin:rr/x"],
        // A whole-remote prefix names every ref of that remote, and there is no
        // ref name below it to strip, so each row keeps its whole refspec.
        vec!["refs", "origin:"],
        vec!["refs", "-r", "origin:"],
        vec!["refs", "origin:."],
        vec!["refs", "-r", "origin:."],
        vec!["refs", "nosuch:"],
        vec!["refs", "test", "origin:"],
        vec!["refs", "origin:", "origin:rr"],
        vec!["refs", "test", "plain"],
        vec!["refs", "plain", "test"],
        vec!["refs", "test", "test"],
        // Two prefixes matching one ref: the name is stripped by the prefix
        // that selected the row, so this prints `main` and then `test/main`.
        vec!["refs", "test", "test/main"],
        vec!["refs", "test/main", "test"],
        vec!["refs", "-r", "test", "test/main"],
    ] {
        assert_agrees(&repo, &repo, &args);
    }
}

/// A PREFIX no ref name can hold ends the invocation in both implementations,
/// before it matches anything, in every listing form and in `--delete`. The two
/// word the refusal differently -- the tool prefixes its line with `Listing
/// refs: ` and the port reports the refspec rule's one message
/// (`docs/conformance/cli-surface.md`, "P1") -- so each side's wording is
/// asserted against itself and the exit status, standard output, and refs tree
/// are compared.
#[test]
fn refs_refuses_an_invalid_prefix() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refs-prefix");
    let base = tmp.path();
    let repo = build_multi_ref_repo(base);
    // An alias, so the `-A` forms print a row of their own before a refusal.
    std::os::unix::fs::symlink("test/main", repo.join("refs/heads/al")).unwrap();

    let refused = |port_repo: &Path, tool_repo: &Path, args: &[&str], prefix: &str| {
        let (port, tool) = run_both(port_repo, tool_repo, args);
        let shown = args.join(" ");
        for (who, run, message) in [
            ("port", &port, format!("error: Invalid refspec {prefix}")),
            (
                "tool",
                &tool,
                format!("error: Listing refs: Invalid refspec {prefix}"),
            ),
        ] {
            assert_eq!(
                run.status.code(),
                Some(1),
                "the {who} did not exit 1 for `{shown}`"
            );
            let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
            assert!(
                stderr.contains(&message),
                "the {who}'s stderr for `{shown}` lacks {message:?}:\n{stderr}"
            );
        }
        assert_eq!(
            String::from_utf8_lossy(&port.stdout),
            String::from_utf8_lossy(&tool.stdout),
            "`{shown}` wrote different standard output",
        );
    };

    // Every form the refspec rule refuses: a component that is empty, `.`, or
    // `..`, and a `<remote>:` half that is empty or holds a `/`. A listing
    // mutates nothing, so both implementations read the one repository.
    for prefix in [
        "test/",
        "/test",
        "a//b",
        ".",
        "..",
        "test/main/",
        "test/../main",
        "",
        ":",
        ":rr",
        "origin:rr/",
        "origin:..",
        "or/igin:rr",
        "or/igin:",
    ] {
        for form in [
            vec!["refs"],
            vec!["refs", "--list"],
            vec!["refs", "-r"],
            vec!["refs", "-A"],
            vec!["refs", "--delete"],
        ] {
            let mut args = form;
            args.push(prefix);
            refused(&repo, &repo, &args, prefix);
        }
    }

    // The check runs where each prefix is taken, so the rows an earlier valid
    // prefix printed stand ahead of the refusal.
    for args in [
        vec!["refs", "test", "test/"],
        vec!["refs", "-r", "test", "test/"],
        vec!["refs", "-A", "al", "test/"],
    ] {
        refused(&repo, &repo, &args, "test/");
    }

    // A `<remote>:` prefix whose ref half is empty or `.` passes this check and
    // names every ref of that remote, which `refs_whole_remote_prefix_matches_
    // the_tool` and `refs_listing_matches_the_tool` cover.

    // A delete mutates, so each implementation gets its own copy: the refs an
    // earlier valid prefix removed stand, and the refused prefix removes
    // nothing.
    let port = clone_repo(base, &repo, "prefix-port");
    let tool = clone_repo(base, &repo, "prefix-tool");
    refused(
        &port,
        &tool,
        &["refs", "--delete", "deep", "test/"],
        "test/",
    );
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "the two deletes left different refs trees",
    );
    assert!(!port.join("refs/heads/deep/nest/ing").exists());
    assert!(port.join("refs/heads/test/main").exists());
}

/// A PREFIX whose path under `refs/` runs through a ref file ends the
/// invocation in both implementations, before the prefix matches anything, in
/// every listing form and in `--delete`. The two word the refusal differently --
/// the tool names the path and the syscall, and the port reports the one message
/// it gives that condition (`docs/conformance/cli-surface.md`, "P1") -- so each
/// side's wording is asserted against itself and the exit status, standard
/// output, and refs tree are compared.
#[test]
fn refs_refuses_a_prefix_through_a_ref_file() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refs-notdir");
    let base = tmp.path();
    let repo = build_multi_ref_repo(base);
    // An alias, so a prefix reaching a ref file through a link is covered and the
    // `-A` forms print a row of their own before a refusal.
    std::os::unix::fs::symlink("test/main", repo.join("refs/heads/al")).unwrap();

    let refused = |port_repo: &Path, tool_repo: &Path, args: &[&str], path: &str| {
        let (port, tool) = run_both(port_repo, tool_repo, args);
        let shown = args.join(" ");
        for (who, run, message) in [
            (
                "port",
                &port,
                "error: i/o error: Not a directory (os error 20)".to_owned(),
            ),
            (
                "tool",
                &tool,
                format!("error: Listing refs: fstatat({path}): Not a directory"),
            ),
        ] {
            assert_eq!(
                run.status.code(),
                Some(1),
                "the {who} did not exit 1 for `{shown}`"
            );
            let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
            assert!(
                stderr.contains(&message),
                "the {who}'s stderr for `{shown}` lacks {message:?}:\n{stderr}"
            );
        }
        assert_eq!(
            String::from_utf8_lossy(&port.stdout),
            String::from_utf8_lossy(&tool.stdout),
            "`{shown}` wrote different standard output",
        );
    };

    // A ref file as the prefix's last component, as an inner one, and reached
    // through an alias, under `refs/heads` and under `refs/remotes` alike. A
    // single prefix removes nothing, so both implementations read the one
    // repository in every form here.
    for (prefix, path) in [
        ("plain/x", "refs/heads/plain/x"),
        ("plain/x/y", "refs/heads/plain/x/y"),
        ("test/main/x", "refs/heads/test/main/x"),
        ("deep/nest/ing/x", "refs/heads/deep/nest/ing/x"),
        ("origin:rr/x/y", "refs/remotes/origin/rr/x/y"),
        ("al/x", "refs/heads/al/x"),
    ] {
        for form in [
            vec!["refs"],
            vec!["refs", "--list"],
            vec!["refs", "-r"],
            vec!["refs", "-A"],
            vec!["refs", "--delete"],
        ] {
            let mut args = form;
            args.push(prefix);
            refused(&repo, &repo, &args, path);
        }
    }

    // A prefix naming nothing at all is not an error, which is what keeps the
    // probe to the one condition.
    for args in [
        vec!["refs", "nosuch/x"],
        vec!["refs", "-A", "nosuch/x"],
        vec!["refs", "--delete", "nosuch/x"],
    ] {
        assert_agrees(&repo, &repo, &args);
    }

    // The refspec rule comes first, so a prefix breaking both rules draws the
    // refspec message from both implementations.
    let (port, tool) = run_both(&repo, &repo, &["refs", "plain/x/"]);
    for (who, run, message) in [
        ("port", &port, "error: Invalid refspec plain/x/"),
        (
            "tool",
            &tool,
            "error: Listing refs: Invalid refspec plain/x/",
        ),
    ] {
        let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
        assert!(
            stderr.contains(message),
            "the {who}'s stderr for `refs plain/x/` lacks {message:?}:\n{stderr}"
        );
    }

    // The rows an earlier valid prefix printed stand ahead of the refusal.
    refused(
        &repo,
        &repo,
        &["refs", "test", "plain/x"],
        "refs/heads/plain/x",
    );
    refused(
        &repo,
        &repo,
        &["refs", "-A", "al", "plain/x"],
        "refs/heads/plain/x",
    );

    // A delete mutates, so each implementation gets its own copy: the refs an
    // earlier valid prefix removed stand, and the refused prefix leaves the ref
    // file its path ran through in place.
    let port = clone_repo(base, &repo, "notdir-port");
    let tool = clone_repo(base, &repo, "notdir-tool");
    refused(
        &port,
        &tool,
        &["refs", "--delete", "deep", "plain/x"],
        "refs/heads/plain/x",
    );
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "the two deletes left different refs trees",
    );
    assert!(!port.join("refs/heads/deep/nest/ing").exists());
    assert!(port.join("refs/heads/plain").exists());

    // The prefix behind the refused one never runs, so the ref it would have
    // removed stands in both.
    let port = clone_repo(base, &repo, "notdir-port-behind");
    let tool = clone_repo(base, &repo, "notdir-tool-behind");
    let before = describe_refs(&port);
    refused(
        &port,
        &tool,
        &["refs", "--delete", "plain/x", "plain"],
        "refs/heads/plain/x",
    );
    assert_eq!(describe_refs(&port), before, "the port removed a ref");
    assert_eq!(describe_refs(&tool), before, "the tool removed a ref");
}

/// A whole-remote PREFIX -- `<remote>:` or `<remote>:.` -- selects every ref of
/// the remote it names. The default listing and `-r` agree with the tool
/// verbatim, and `refs_listing_matches_the_tool` compares them. Three forms
/// diverge, each pinned here so a change to either side is caught: the tool
/// builds every name it prints or deletes by joining the prefix's ref half with
/// the name below it, so `--list` prints `origin:./rr/x`, `-A` prints
/// `./rr/remal`, and `--delete` is refused on that joined name, which the tool's
/// own refspec rule rejects. The port prints the refspec and refuses the delete
/// naming the prefix as given (`docs/conformance/cli-surface.md`, "P1"). Both
/// refuse the delete, remove nothing, and exit 1.
#[test]
fn refs_whole_remote_prefix_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refs-whole-remote");
    let base = tmp.path();
    let repo = build_multi_ref_repo(base);
    // An alias beside the remote refs, so the `-A` forms carry a row.
    std::os::unix::fs::symlink("x", repo.join("refs/remotes/origin/rr/remal")).unwrap();

    // A listing mutates nothing, so both implementations read the one
    // repository. `--list` suppresses the stripping, and the two name the same
    // three refs differently.
    for prefix in ["origin:", "origin:."] {
        let (port, tool) = run_both(&repo, &repo, &["refs", "--list", prefix]);
        assert_eq!(
            port.ok().stdout_trimmed(),
            "origin:rr/deep/y\norigin:rr/remal\norigin:rr/x",
            "the port's `refs --list {prefix}` names the refs differently",
        );
        assert_eq!(
            tool.ok().stdout_trimmed(),
            "origin:./rr/deep/y\norigin:./rr/remal\norigin:./rr/x",
            "the tool's `refs --list {prefix}` names the refs differently",
        );

        let (port, tool) = run_both(&repo, &repo, &["refs", "-A", prefix]);
        assert_eq!(port.ok().stdout_trimmed(), "origin:rr/remal -> x");
        assert_eq!(tool.ok().stdout_trimmed(), "./rr/remal -> x");
    }

    // A delete mutates, so each implementation gets its own copy. A whole-remote
    // prefix matching a ref is refused and removes nothing.
    for (prefix, name) in [("origin:", "empty"), ("origin:.", "dot")] {
        let port = clone_repo(base, &repo, &format!("del-port-{name}"));
        let tool = clone_repo(base, &repo, &format!("del-tool-{name}"));
        let before = describe_refs(&port);
        let (port_run, tool_run) = run_both(&port, &tool, &["refs", "--delete", prefix]);
        for (who, run) in [("port", &port_run), ("tool", &tool_run)] {
            assert_eq!(
                run.status.code(),
                Some(1),
                "the {who} did not refuse `refs --delete {prefix}`"
            );
        }
        let port_stderr = String::from_utf8_lossy(&port_run.stderr).into_owned();
        assert!(
            port_stderr.contains(&format!("error: Invalid refspec {prefix}")),
            "the port's stderr does not name the prefix as given:\n{port_stderr}"
        );
        // The tool names the refspec it built for one of the matched refs, which
        // carries the `.` of the join; which ref it names follows its own
        // directory order, so the assertion stops at the join.
        let tool_stderr = String::from_utf8_lossy(&tool_run.stderr).into_owned();
        assert!(
            tool_stderr.contains("Invalid refspec origin:./"),
            "the tool's stderr does not name a joined refspec:\n{tool_stderr}"
        );
        assert_eq!(describe_refs(&port), before, "the port removed a ref");
        assert_eq!(describe_refs(&tool), before, "the tool removed a ref");
    }

    // A whole-remote prefix matching no ref is not an error.
    for (prefix, name) in [("nosuch:", "empty"), ("nosuch:.", "dot")] {
        let port = clone_repo(base, &repo, &format!("miss-port-{name}"));
        let tool = clone_repo(base, &repo, &format!("miss-tool-{name}"));
        let before = describe_refs(&port);
        assert_agrees(&port, &tool, &["refs", "--delete", prefix]);
        assert_eq!(describe_refs(&port), before);
        assert_eq!(describe_refs(&tool), before);
    }

    // The prefixes ahead of the refused one keep their effect.
    let port = clone_repo(base, &repo, "order-port");
    let tool = clone_repo(base, &repo, "order-tool");
    let (port_run, tool_run) = run_both(&port, &tool, &["refs", "--delete", "deep", "origin:"]);
    for (who, run) in [("port", &port_run), ("tool", &tool_run)] {
        assert_eq!(
            run.status.code(),
            Some(1),
            "the {who} did not refuse `refs --delete deep origin:`"
        );
    }
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "the two deletes left different refs trees",
    );
    assert!(!port.join("refs/heads/deep/nest/ing").exists());
    assert!(port.join("refs/remotes/origin/rr/x").exists());

    // Each prefix is matched against the ref set as the prefixes ahead of it
    // left it. `origin:rr` empties the remote, so the whole-remote prefix behind
    // it matches nothing and exits 0; a prefix emptying part of the remote
    // leaves the whole-remote prefix matching the rest, which is refused.
    for (args, name) in [
        (vec!["refs", "--delete", "origin:rr", "origin:"], "emptied"),
        (
            vec!["refs", "--delete", "origin:rr", "origin:", "origin:."],
            "emptied-twice",
        ),
    ] {
        let port = clone_repo(base, &repo, &format!("live-port-{name}"));
        let tool = clone_repo(base, &repo, &format!("live-tool-{name}"));
        assert_agrees(&port, &tool, &args);
        assert_eq!(
            describe_refs(&port),
            describe_refs(&tool),
            "the two deletes left different refs trees",
        );
        assert!(!port.join("refs/remotes/origin/rr/x").exists());
        assert!(port.join("refs/heads/test/main").exists());
    }
    let port = clone_repo(base, &repo, "live-port-partial");
    let tool = clone_repo(base, &repo, "live-tool-partial");
    let (port_run, tool_run) = run_both(
        &port,
        &tool,
        &["refs", "--delete", "origin:rr/deep", "origin:"],
    );
    for (who, run) in [("port", &port_run), ("tool", &tool_run)] {
        assert_eq!(
            run.status.code(),
            Some(1),
            "the {who} did not refuse `refs --delete origin:rr/deep origin:`"
        );
    }
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "the two deletes left different refs trees",
    );
    assert!(!port.join("refs/remotes/origin/rr/deep/y").exists());
    assert!(port.join("refs/remotes/origin/rr/x").exists());
}

#[test]
fn refs_alias_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refs-alias");
    let base = tmp.path();
    let repo = build_multi_ref_repo(base);
    let head = resolve(&repo, "test/main").unwrap();

    // A create mutates, so each implementation gets its own copy.
    let port = clone_repo(base, &repo, "alias-port");
    let tool = clone_repo(base, &repo, "alias-tool");
    for args in [
        vec!["refs", "-A", "--create=al", "test/main"],
        vec!["refs", "-A", "--create=nested/q", "plain"],
    ] {
        assert_agrees(&port, &tool, &args);
    }
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "the two alias writes left different refs trees",
    );
    // The link body is relative to the alias's own directory.
    assert_eq!(
        std::fs::read_link(port.join("refs/heads/al")).unwrap(),
        Path::new("test/main"),
    );
    assert_eq!(
        std::fs::read_link(port.join("refs/heads/nested/q")).unwrap(),
        Path::new("../plain"),
    );

    // The listings both implementations produce over the aliases just written.
    // A PREFIX naming a ref exactly is answered by that ref, printed with its
    // commit checksum in the target position, whether the ref is an alias
    // (`al`, `nested/q`), a plain ref (`test/main`), or a remote ref
    // (`origin:rr/x`); a bare checksum names no ref and prints nothing. Every
    // other prefix filters the aliases nested under it.
    for args in [
        vec!["refs", "-A"],
        vec!["refs", "-A", "-r"],
        vec!["refs", "-A", "test"],
        vec!["refs", "-A", "nested"],
        vec!["refs", "-A", "al"],
        vec!["refs", "-A", "-r", "al"],
        vec!["refs", "-A", "nested/q"],
        vec!["refs", "-A", "al", "al"],
        vec!["refs", "-A", "al", "nested/q"],
        vec!["refs", "-A", "nested/q", "nested"],
        vec!["refs", "-A", "test/main"],
        vec!["refs", "-A", "origin:rr/x"],
        vec!["refs", "-A", "origin:rr"],
        vec!["refs", "-A", "deep/nest"],
        vec!["refs", "-A", "nosuch"],
        vec!["refs", "-A", &head],
        vec!["refs"],
        vec!["refs", "-r"],
        vec!["rev-parse", "al"],
    ] {
        assert_agrees(&port, &tool, &args);
    }

    // An alias records a name, so a target naming a commit is refused.
    for target in [head.as_str(), "test/main^", "nosuch"] {
        assert_agrees_on_error(
            &port,
            &tool,
            &["refs", "-A", "--create=bad", target],
            &format!("error: Cannot create alias to non-existent ref: {target}"),
        );
    }
    // An alias lives under `refs/heads`, so a NEWREF naming a remote is refused
    // and nothing is written. The remote half is the whole message, whether the
    // remote exists or not, and the step sits after the three NEWREF checks and
    // before the positional resolves: an unresolvable positional and an
    // existence check `--force` suppressed both reach it, and a NEWREF the ref
    // rule refuses stops one step earlier.
    let before = describe_refs(&port);
    for (args, message) in [
        (
            vec!["refs", "-A", "--create=origin:al", "test/main"],
            "error: Cannot create alias to remote ref: origin",
        ),
        (
            vec!["refs", "-A", "--create=origin:rr/al", "origin:rr/x"],
            "error: Cannot create alias to remote ref: origin",
        ),
        (
            vec!["refs", "-A", "--create=nosuchremote:al", "test/main"],
            "error: Cannot create alias to remote ref: nosuchremote",
        ),
        (
            vec!["refs", "-A", "--create=origin:al", "nosuch"],
            "error: Cannot create alias to remote ref: origin",
        ),
        (
            vec!["refs", "-A", "--create=origin:rr/x", "--force", "test/main"],
            "error: Cannot create alias to remote ref: origin",
        ),
        (
            vec!["refs", "-A", "--create=origin:bad/", "test/main"],
            "error: Invalid refspec origin:bad/",
        ),
    ] {
        assert_agrees_on_error(&port, &tool, &args, message);
    }
    // A NEWREF holding a second `:` is one the port's own ref rule accepts and
    // the tool's refuses, so the two refuse it at different steps: the port
    // reaches the remote refusal and reports the first half, and the tool reports
    // the whole name (`docs/conformance/cli-surface.md`, "P1"). Both exit 1 and
    // write nothing, which is what the refs tree below states.
    let (port_run, tool_run) =
        run_both(&port, &tool, &["refs", "-A", "--create=a:b:c", "test/main"]);
    for (who, run) in [("port", &port_run), ("tool", &tool_run)] {
        assert_eq!(
            run.status.code(),
            Some(1),
            "the {who} did not refuse `-A --create=a:b:c`"
        );
    }
    assert!(
        String::from_utf8_lossy(&port_run.stderr)
            .contains("error: Cannot create alias to remote ref: a"),
    );
    assert!(String::from_utf8_lossy(&tool_run.stderr).contains("error: Invalid refspec a:b:c"));

    assert_eq!(
        describe_refs(&port),
        before,
        "the port wrote a remote alias"
    );
    assert_eq!(
        describe_refs(&tool),
        before,
        "the tool wrote a remote alias"
    );

    // --force replaces a ref file with an alias symlink.
    assert_agrees(
        &port,
        &tool,
        &["refs", "-A", "--create=plain", "--force", "test/main"],
    );
    assert_eq!(describe_refs(&port), describe_refs(&tool));
    assert!(
        port.join("refs/heads/plain")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // The one divergence, pinned so a change to either side is caught: the tool
    // names an alias under `refs/remotes/<remote>/` by its path below the
    // remote, dropping the remote and printing a name that resolves to nothing;
    // the port prints the refspec (`docs/conformance/cli-surface.md`, "P1").
    for repo in [&port, &tool] {
        std::os::unix::fs::symlink("x", repo.join("refs/remotes/origin/rr/remal")).unwrap();
    }
    let listing = |run: Run| run.ok().stdout_trimmed();
    let port_lines = listing(ostrya(
        &["refs", "--repo", port.to_str().unwrap(), "-A", "origin:rr"],
        None,
        &[],
    ));
    let tool_lines = listing(ostree(&[
        &format!("--repo={}", tool.display()),
        "refs",
        "-A",
        "origin:rr",
    ]));
    assert_eq!(port_lines, "origin:rr/remal -> x");
    assert_eq!(tool_lines, "rr/remal -> x");

    // A target under `refs/remotes` is the one `-A --create` writes differently,
    // so it gets its own pair of clones. The port writes the path to the target
    // ref's file and the tool writes the refspec verbatim, which under
    // `refs/heads` names no file. Both listings print `origin:rr/x` for it
    // (`docs/conformance/cli-surface.md`, "P1").
    let remote_port = clone_repo(base, &repo, "alias-remote-port");
    let remote_tool = clone_repo(base, &repo, "alias-remote-tool");
    assert_agrees(
        &remote_port,
        &remote_tool,
        &["refs", "-A", "--create=xal", "origin:rr/x"],
    );
    assert_eq!(
        std::fs::read_link(remote_port.join("refs/heads/xal")).unwrap(),
        Path::new("../remotes/origin/rr/x"),
    );
    assert_eq!(
        std::fs::read_link(remote_tool.join("refs/heads/xal")).unwrap(),
        Path::new("origin:rr/x"),
    );
    // Each implementation reading the repository it wrote prints the same line.
    assert_agrees(&remote_port, &remote_tool, &["refs", "-A"]);
    // The port's link resolves under both implementations.
    for run in [
        ostrya(
            &["rev-parse", "--repo", remote_port.to_str().unwrap(), "xal"],
            None,
            &[],
        ),
        ostree(&[
            &format!("--repo={}", remote_port.display()),
            "rev-parse",
            "xal",
        ]),
    ] {
        assert_eq!(run.ok().stdout_trimmed(), head);
    }
    // The tool's link resolves under neither, and its own default listing stops
    // on it, which is the dangling-alias divergence reached by its own write.
    for run in [
        ostrya(
            &["rev-parse", "--repo", remote_tool.to_str().unwrap(), "xal"],
            None,
            &[],
        ),
        ostree(&[
            &format!("--repo={}", remote_tool.display()),
            "rev-parse",
            "xal",
        ]),
    ] {
        assert_eq!(run.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&run.stderr).contains("error: Refspec 'xal' not found"),
            "the tool's own alias link resolved",
        );
    }
    let (port_run, tool_run) = run_both(&remote_port, &remote_tool, &["refs"]);
    assert_eq!(port_run.ok().stdout_trimmed().lines().last(), Some("xal"));
    assert_eq!(tool_run.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&tool_run.stderr)
            .contains("error: Listing refs: openat(xal): No such file or directory"),
    );
}

/// A repository holding the refs and aliases the `--delete` alias guard needs:
/// an alias whose body climbs out of its own directory (`test/al`), one naming
/// another alias (`alal`), one whose flat body names a ref at the `refs/heads`
/// root while the link itself resolves inside the alias's own directory
/// (`test/al2`), and two naming a remote ref, in the port's body form (`ral`)
/// and in the tool's (`ral2`).
fn build_alias_guard_repo(base: &Path) -> PathBuf {
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
    let src = base.join("src");
    for branch in ["test/main", "test/other", "deep/nest/ing", "other"] {
        commit_tree(&repo, branch, &src, None);
    }
    let head = resolve(&repo, "test/main").unwrap();
    write_ref_file(&repo, "remotes/origin/rr/x", &head);
    for (link, target) in [
        ("heads/test/al", "../test/main"),
        ("heads/alal", "test/al"),
        ("heads/test/al2", "other"),
        ("heads/ral", "../remotes/origin/rr/x"),
        ("heads/ral2", "origin:rr/x"),
    ] {
        std::os::unix::fs::symlink(target, repo.join("refs").join(link)).unwrap();
    }
    repo
}

#[test]
fn refs_delete_alias_guard_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refs-delete-alias");
    let base = tmp.path();
    let repo = build_alias_guard_repo(base);

    // A ref an alias names is refused, and the prefix removes nothing. One
    // alias names each of these refs, so both implementations name the same
    // pair. The body an alias names its target by is the link body with the
    // leading `../` components removed, read as a ref name under `refs/heads`:
    // `test/al2 -> other` guards `other`.
    for (name, args, message) in [
        (
            "climbing",
            vec!["refs", "--delete", "test/main"],
            "error: Ref 'test/main' has an active alias: 'test/al'",
        ),
        (
            "flat-from-root",
            vec!["refs", "--delete", "other"],
            "error: Ref 'other' has an active alias: 'test/al2'",
        ),
        (
            "alias-is-the-target",
            vec!["refs", "--delete", "test/al"],
            "error: Ref 'test/al' has an active alias: 'alal'",
        ),
    ] {
        let port = clone_repo(base, &repo, &format!("guard-port-{name}"));
        let tool = clone_repo(base, &repo, &format!("guard-tool-{name}"));
        let before = describe_refs(&port);
        assert_agrees_on_error(&port, &tool, &args, message);
        assert_eq!(describe_refs(&port), before, "the port removed a ref");
        assert_eq!(describe_refs(&tool), before, "the tool removed a ref");
    }

    // The refs outside the guard: the ref the link resolves to, which its body
    // does not name (`test/other`, where `test/al2 -> other`); a remote ref two
    // aliases name, in either body form; an alias no alias names; and an alias
    // the prefix ahead of it freed, the alias set being read as the prefixes
    // ahead left it.
    for (name, args, gone) in [
        (
            "link-resolves-here",
            vec!["refs", "--delete", "test/other"],
            vec!["refs/heads/test/other"],
        ),
        (
            "remote-ref",
            vec!["refs", "--delete", "origin:rr/x"],
            vec!["refs/remotes/origin/rr/x"],
        ),
        (
            "alias-nothing-names",
            vec!["refs", "--delete", "ral"],
            vec!["refs/heads/ral"],
        ),
        (
            "alias-then-its-target",
            vec!["refs", "--delete", "alal", "test/al"],
            vec!["refs/heads/alal", "refs/heads/test/al"],
        ),
    ] {
        let port = clone_repo(base, &repo, &format!("free-port-{name}"));
        let tool = clone_repo(base, &repo, &format!("free-tool-{name}"));
        assert_agrees(&port, &tool, &args);
        assert_eq!(
            describe_refs(&port),
            describe_refs(&tool),
            "`{}` left different refs trees",
            args.join(" "),
        );
        for path in gone {
            assert!(
                port.join(path).symlink_metadata().is_err(),
                "the port kept {path} for `{}`",
                args.join(" "),
            );
        }
    }

    // A prefix matching more than one guarded ref: both refuse and the prefix
    // ahead of it keeps its effect. Which pair the message names follows each
    // implementation's own enumeration order, so the assertion stops at the
    // guard's words (`docs/conformance/cli-surface.md`, "P1").
    let port = clone_repo(base, &repo, "guard-port-order");
    let tool = clone_repo(base, &repo, "guard-tool-order");
    let before = describe_refs(&port);
    let (port_run, tool_run) = run_both(&port, &tool, &["refs", "--delete", "deep", "test"]);
    for (who, run) in [("port", &port_run), ("tool", &tool_run)] {
        assert_eq!(
            run.status.code(),
            Some(1),
            "the {who} did not refuse `refs --delete deep test`"
        );
        let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
        assert!(
            stderr.contains(" has an active alias: '"),
            "the {who}'s stderr lacks the guard:\n{stderr}"
        );
    }
    // The port removes what `deep` matched and nothing of what `test` matched.
    let expected: Vec<String> = before
        .iter()
        .filter(|line| !line.starts_with("heads/deep/nest/ing "))
        .cloned()
        .collect();
    assert_eq!(
        describe_refs(&port),
        expected,
        "the port's refused prefix removed a ref",
    );
    // The tool removes the matched refs its own removal order reached ahead of
    // the guarded one, so its tree is what the port left, less any of the
    // unguarded refs `test` matched (`docs/conformance/cli-surface.md`, "P1").
    let after = describe_refs(&tool);
    let unguarded = ["heads/test/other ", "heads/test/al2 "];
    for line in &expected {
        assert!(
            after.contains(line) || unguarded.iter().any(|name| line.starts_with(name)),
            "the tool removed `{line}`, which the guard holds or no prefix matched",
        );
    }
    for line in &after {
        assert!(expected.contains(line), "the tool wrote `{line}`");
    }
    for who in [&port, &tool] {
        assert!(
            who.join("refs/heads/deep/nest/ing")
                .symlink_metadata()
                .is_err()
        );
        assert!(who.join("refs/heads/test/main").exists());
        assert!(who.join("refs/heads/test/al").symlink_metadata().is_ok());
    }
    assert!(port.join("refs/heads/test/other").exists());

    // With `-c` the guard does not apply: the collection's own refs are removed,
    // the aliases among them included. The same repository refuses the same ref
    // without `-c`.
    let coll = base.join("coll");
    ostrya(
        &[
            "init",
            "--repo",
            coll.to_str().unwrap(),
            "--mode=archive",
            "--collection-id=org.example.Coll",
        ],
        None,
        &[],
    )
    .ok();
    let src = base.join("src");
    for branch in ["test/main", "other"] {
        commit_tree(&coll, branch, &src, None);
    }
    std::os::unix::fs::symlink("../test/main", coll.join("refs/heads/test/al")).unwrap();
    let port = clone_repo(base, &coll, "coll-port");
    let tool = clone_repo(base, &coll, "coll-tool");
    assert_agrees(
        &port,
        &tool,
        &["refs", "-c", "--delete", "org.example.Coll"],
    );
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "the two collection deletes left different refs trees",
    );
    assert!(
        port.join("refs/heads/test/al").symlink_metadata().is_err(),
        "the `-c` delete kept the alias",
    );
    let port = clone_repo(base, &coll, "coll-plain-port");
    let tool = clone_repo(base, &coll, "coll-plain-tool");
    assert_agrees_on_error(
        &port,
        &tool,
        &["refs", "--delete", "test/main"],
        "error: Ref 'test/main' has an active alias: 'test/al'",
    );

    // The refusal is per prefix in both and atomic in the port alone: the tool
    // removes the members of the selected set its own removal order reached
    // ahead of the guarded one (`docs/conformance/cli-surface.md`, "P1"). One
    // guarded member among sixteen sits late in that order, which is what the
    // two repositories below pin -- the plain form over refs, the `-A` form over
    // aliases -- each holding one alias for its guarded member, so both
    // implementations name the same pair.
    let plain = base.join("partial-plain");
    let aliased = base.join("partial-alias");
    for path in [&plain, &aliased] {
        block_on(async {
            Repo::create(path, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
        });
    }
    let head = commit_tree(&plain, "test/g", &src, None);
    for i in 1..=16 {
        write_ref_file(&plain, &format!("heads/test/u{i:02}"), &head);
    }
    std::os::unix::fs::symlink("test/g", plain.join("refs/heads/gal")).unwrap();
    commit_tree(&aliased, "test/m", &src, None);
    for i in 1..=16 {
        std::os::unix::fs::symlink(
            "../test/m",
            aliased.join(format!("refs/heads/test/a{i:02}")),
        )
        .unwrap();
    }
    std::os::unix::fs::symlink("test/a05", aliased.join("refs/heads/alal")).unwrap();

    for (name, source, args, message, guarded) in [
        (
            "plain",
            &plain,
            vec!["refs", "--delete", "test"],
            "error: Ref 'test/g' has an active alias: 'gal'",
            "refs/heads/test/g",
        ),
        (
            "alias-only",
            &aliased,
            vec!["refs", "-A", "--delete", "test"],
            "error: Ref 'test/a05' has an active alias: 'alal'",
            "refs/heads/test/a05",
        ),
    ] {
        let port = clone_repo(base, source, &format!("partial-port-{name}"));
        let tool = clone_repo(base, source, &format!("partial-tool-{name}"));
        let before = describe_refs(&port);
        assert_agrees_on_error(&port, &tool, &args, message);
        assert_eq!(
            describe_refs(&port),
            before,
            "the port's refused prefix removed a ref",
        );
        let after = describe_refs(&tool);
        assert!(
            after.len() < before.len(),
            "the tool removed nothing for `{}`, so its removal order reached the \
             guarded member first",
            args.join(" "),
        );
        for line in &after {
            assert!(before.contains(line), "the tool wrote `{line}`");
        }
        for who in [&port, &tool] {
            assert!(
                who.join(guarded).symlink_metadata().is_ok(),
                "{guarded} was removed for `{}`",
                args.join(" "),
            );
        }
    }
}

/// A repository holding what the `-A --delete` selection needs: an alias nested
/// under a directory prefix (`test/al`), one at the `refs/heads` root naming a
/// ref that a prefix also matches (`topal -> test/other`), an alias under
/// `refs/remotes` (`origin:rr/remal`), and refs no alias names.
fn build_alias_delete_repo(base: &Path) -> PathBuf {
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
    let src = base.join("src");
    for branch in ["test/main", "test/other", "deep/nest/ing", "other"] {
        commit_tree(&repo, branch, &src, None);
    }
    let head = resolve(&repo, "test/main").unwrap();
    write_ref_file(&repo, "remotes/origin/rr/x", &head);
    for (link, target) in [
        ("heads/test/al", "../test/main"),
        ("heads/topal", "test/other"),
        ("remotes/origin/rr/remal", "x"),
    ] {
        std::os::unix::fs::symlink(target, repo.join("refs").join(link)).unwrap();
    }
    repo
}

/// `-A --delete` removes, for each prefix, the set a `-A` listing prints for it:
/// the ref the prefix names exactly, or the aliases nested under it. The plain
/// form removes every ref the prefix matches, so the two select different files
/// for the same prefix.
#[test]
fn refs_delete_aliases_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refs-delete-aliases");
    let base = tmp.path();
    let repo = build_alias_delete_repo(base);

    // A directory prefix removes the aliases below it and leaves the refs; a
    // prefix naming a ref exactly removes that one ref, whether it is an alias,
    // a plain ref, or a remote ref. The plain `--delete` of the same prefix
    // stands beside each alias-only case, since the two select different files.
    for (name, args, gone, kept) in [
        (
            "aliases-below",
            vec!["refs", "-A", "--delete", "test"],
            vec!["refs/heads/test/al"],
            vec!["refs/heads/test/main", "refs/heads/test/other"],
        ),
        (
            "alias-exactly",
            vec!["refs", "-A", "--delete", "test/al"],
            vec!["refs/heads/test/al"],
            vec!["refs/heads/test/main"],
        ),
        (
            "root-alias-exactly",
            vec!["refs", "-A", "--delete", "topal"],
            vec!["refs/heads/topal"],
            vec!["refs/heads/test/other"],
        ),
        (
            "plain-ref-exactly",
            vec!["refs", "-A", "--delete", "other"],
            vec!["refs/heads/other"],
            vec!["refs/heads/test/al"],
        ),
        (
            "remote-ref-exactly",
            vec!["refs", "-A", "--delete", "origin:rr/x"],
            vec!["refs/remotes/origin/rr/x"],
            vec!["refs/remotes/origin/rr/remal"],
        ),
        (
            "remote-alias-exactly",
            vec!["refs", "-A", "--delete", "origin:rr/remal"],
            vec!["refs/remotes/origin/rr/remal"],
            vec!["refs/remotes/origin/rr/x"],
        ),
        // The contrast with the plain form over one prefix: `-A` finds no alias
        // below `deep` and removes nothing, where `--delete deep` removes the
        // ref below it.
        (
            "no-alias-below",
            vec!["refs", "-A", "--delete", "deep"],
            vec![],
            vec!["refs/heads/deep/nest/ing"],
        ),
        (
            "refs-below",
            vec!["refs", "--delete", "deep"],
            vec!["refs/heads/deep/nest/ing"],
            vec!["refs/heads/test/al"],
        ),
        (
            "ref-below-exactly",
            vec!["refs", "-A", "--delete", "deep/nest/ing"],
            vec!["refs/heads/deep/nest/ing"],
            vec!["refs/heads/test/al"],
        ),
        (
            "no-match",
            vec!["refs", "-A", "--delete", "nosuch"],
            vec![],
            vec!["refs/heads/test/al", "refs/heads/topal"],
        ),
        (
            "whole-remote-no-alias",
            vec!["refs", "-A", "--delete", "nosuch:"],
            vec![],
            vec!["refs/remotes/origin/rr/remal"],
        ),
        // Per prefix, in argument order: `test` frees its alias, `deep` holds no
        // alias, and `other` names a ref exactly.
        (
            "per-prefix",
            vec!["refs", "-A", "--delete", "test", "deep", "other"],
            vec!["refs/heads/test/al", "refs/heads/other"],
            vec!["refs/heads/deep/nest/ing", "refs/heads/test/main"],
        ),
        // The alias set is read as the prefixes ahead left it, so the second
        // `test` finds no alias below itself and removes nothing.
        (
            "live-set",
            vec!["refs", "-A", "--delete", "test", "test"],
            vec!["refs/heads/test/al"],
            vec!["refs/heads/test/main", "refs/heads/test/other"],
        ),
    ] {
        let port = clone_repo(base, &repo, &format!("sel-port-{name}"));
        let tool = clone_repo(base, &repo, &format!("sel-tool-{name}"));
        assert_agrees(&port, &tool, &args);
        assert_eq!(
            describe_refs(&port),
            describe_refs(&tool),
            "`{}` left different refs trees",
            args.join(" "),
        );
        for path in gone {
            assert!(
                port.join(path).symlink_metadata().is_err(),
                "the port kept {path} for `{}`",
                args.join(" "),
            );
        }
        for path in kept {
            assert!(
                port.join(path).symlink_metadata().is_ok(),
                "the port removed {path} for `{}`",
                args.join(" "),
            );
        }
    }

    // The guard of the plain form applies to the set `-A` selected: the ref a
    // prefix names exactly, and the alias below a directory prefix.
    for (name, args, message, gone) in [
        (
            "guard-exact",
            vec!["refs", "-A", "--delete", "test/main"],
            "error: Ref 'test/main' has an active alias: 'test/al'",
            vec![],
        ),
        (
            "guard-alias-target",
            vec!["refs", "-A", "--delete", "test/other"],
            "error: Ref 'test/other' has an active alias: 'topal'",
            vec![],
        ),
        // The prefix ahead of the refused one keeps its effect.
        (
            "guard-after-a-prefix",
            vec!["refs", "-A", "--delete", "test", "test/other"],
            "error: Ref 'test/other' has an active alias: 'topal'",
            vec!["refs/heads/test/al"],
        ),
    ] {
        let port = clone_repo(base, &repo, &format!("guard-port-{name}"));
        let tool = clone_repo(base, &repo, &format!("guard-tool-{name}"));
        assert_agrees_on_error(&port, &tool, &args, message);
        assert_eq!(
            describe_refs(&port),
            describe_refs(&tool),
            "`{}` left different refs trees",
            args.join(" "),
        );
        assert!(port.join("refs/heads/test/other").exists());
        for path in gone {
            assert!(
                port.join(path).symlink_metadata().is_err(),
                "the port kept {path} for `{}`",
                args.join(" "),
            );
        }
    }

    // No prefix reports the message the plain form reports.
    let port = clone_repo(base, &repo, "sel-port-no-prefix");
    let tool = clone_repo(base, &repo, "sel-tool-no-prefix");
    assert_agrees_on_error(
        &port,
        &tool,
        &["refs", "-A", "--delete"],
        "error: At least one PREFIX is required when deleting refs",
    );
    assert_eq!(describe_refs(&port), describe_refs(&tool));

    // A whole-remote prefix holding an alias is refused and removes nothing in
    // both, each naming what its own selection produced
    // (`docs/conformance/cli-surface.md`, "P1").
    for prefix in ["origin:", "origin:."] {
        let port = clone_repo(base, &repo, &format!("sel-port-whole{}", prefix.len()));
        let tool = clone_repo(base, &repo, &format!("sel-tool-whole{}", prefix.len()));
        let before = describe_refs(&port);
        let (port_run, tool_run) = run_both(&port, &tool, &["refs", "-A", "--delete", prefix]);
        assert_eq!(port_run.status.code(), Some(1));
        assert_eq!(tool_run.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&port_run.stderr)
                .contains(&format!("error: Invalid refspec {prefix}")),
        );
        assert!(
            String::from_utf8_lossy(&tool_run.stderr).contains("error: Invalid refspec ./rr/remal"),
        );
        assert_eq!(describe_refs(&port), before, "the port removed a ref");
        assert_eq!(describe_refs(&tool), before, "the tool removed a ref");
    }

    // The divergence, pinned so a change to either side is caught: the tool
    // removes each nested alias by the name it prints for it, and for an alias
    // under `refs/remotes` that name drops the remote, so the tool removes no
    // alias of that remote. The port removes the alias its own listing names.
    let port = clone_repo(base, &repo, "sel-port-remote-prefix");
    let tool = clone_repo(base, &repo, "sel-tool-remote-prefix");
    let (port_run, tool_run) = run_both(&port, &tool, &["refs", "-A", "--delete", "origin:rr"]);
    assert_eq!(port_run.ok().stdout_trimmed(), "");
    assert_eq!(tool_run.status.code(), Some(0));
    assert!(
        port.join("refs/remotes/origin/rr/remal")
            .symlink_metadata()
            .is_err(),
        "the port kept the remote alias",
    );
    assert!(
        tool.join("refs/remotes/origin/rr/remal")
            .symlink_metadata()
            .is_ok(),
        "the tool removed the remote alias",
    );
    // The same name read under `refs/heads`: where a local ref carries the
    // remote alias's path below the remote, the tool removes that local ref and
    // the port removes the alias the prefix named.
    let collide = base.join("collide");
    ostrya(
        &[
            "init",
            "--repo",
            collide.to_str().unwrap(),
            "--mode=archive",
        ],
        None,
        &[],
    )
    .ok();
    let src = base.join("src");
    for branch in ["zz/q", "keep"] {
        commit_tree(&collide, branch, &src, None);
    }
    let head = resolve(&collide, "keep").unwrap();
    write_ref_file(&collide, "remotes/origin/zz/x", &head);
    std::os::unix::fs::symlink("x", collide.join("refs/remotes/origin/zz/q")).unwrap();
    let port = clone_repo(base, &collide, "collide-port");
    let tool = clone_repo(base, &collide, "collide-tool");
    let (port_run, tool_run) = run_both(&port, &tool, &["refs", "-A", "--delete", "origin:zz"]);
    assert_eq!(port_run.ok().stdout_trimmed(), "");
    assert_eq!(tool_run.status.code(), Some(0));
    assert!(
        port.join("refs/heads/zz/q").exists(),
        "the port removed a ref"
    );
    assert!(
        !tool.join("refs/heads/zz/q").exists(),
        "the tool kept the local ref its own name reached",
    );

    // `-c` wins over `-A` in either order, so both remove the collection's own
    // refs with the aliases among them. The repository carries no mirror ref, so
    // the two trees compare with the own-collection-id divergence out of the way.
    let coll = base.join("coll");
    ostrya(
        &[
            "init",
            "--repo",
            coll.to_str().unwrap(),
            "--mode=archive",
            "--collection-id=org.example.Coll",
        ],
        None,
        &[],
    )
    .ok();
    for branch in ["test/main", "other"] {
        commit_tree(&coll, branch, &src, None);
    }
    std::os::unix::fs::symlink("../test/main", coll.join("refs/heads/test/al")).unwrap();
    for (name, args) in [
        (
            "ca",
            vec!["refs", "-c", "-A", "--delete", "org.example.Coll"],
        ),
        (
            "ac",
            vec!["refs", "-A", "-c", "--delete", "org.example.Coll"],
        ),
    ] {
        let port = clone_repo(base, &coll, &format!("coll-sel-port-{name}"));
        let tool = clone_repo(base, &coll, &format!("coll-sel-tool-{name}"));
        assert_agrees(&port, &tool, &args);
        assert_eq!(
            describe_refs(&port),
            describe_refs(&tool),
            "`{}` left different refs trees",
            args.join(" "),
        );
        assert!(
            port.join("refs/heads/test/al").symlink_metadata().is_err(),
            "`{}` kept the alias",
            args.join(" "),
        );
        assert!(
            port.join("refs/heads/other").symlink_metadata().is_err(),
            "`{}` kept a ref",
            args.join(" "),
        );
    }
}

/// A collection repository holding both sources of a collection ref under its
/// own id: the local refs its `collection-id` qualifies, an alias among them, and
/// mirror refs carrying that same id, beside the mirror ref of a foreign id.
fn build_own_collection_repo(base: &Path) -> PathBuf {
    build_fixture_source(base);
    let repo = base.join("own-coll");
    ostrya(
        &[
            "init",
            "--repo",
            repo.to_str().unwrap(),
            "--mode=archive",
            "--collection-id=org.example.Coll",
        ],
        None,
        &[],
    )
    .ok();
    let src = base.join("src");
    for branch in ["test/main", "test/other", "other"] {
        commit_tree(&repo, branch, &src, None);
    }
    let head = resolve(&repo, "other").unwrap();
    write_ref_file(&repo, "mirrors/org.example.Coll/mm", &head);
    write_ref_file(&repo, "mirrors/org.example.Coll/deep/x", &head);
    write_ref_file(&repo, "mirrors/org.example.Other/om", &head);
    std::os::unix::fs::symlink("../test/main", repo.join("refs/heads/test/al")).unwrap();
    repo
}

/// `refs -c --delete` of the id equal to the repository's own `collection-id`
/// removes the refs under `refs/heads`, the aliases among them, and keeps the
/// mirror refs carrying that id; a foreign id removes the mirror refs it names.
/// The `-c` listing prints both sets for either id, so the two ids share one
/// selection and differ in the removal.
#[test]
fn refs_delete_collection_own_id_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refs-delete-coll");
    let base = tmp.path();
    let repo = build_own_collection_repo(base);

    // The listing reads the mirror refs of the own id, so what follows compares
    // removals over one selection.
    for args in [
        vec!["refs", "-c"],
        vec!["refs", "-c", "-r"],
        vec!["refs", "-c", "org.example.Coll"],
        vec!["refs", "-c", "org.example.Other"],
    ] {
        assert_agrees(&repo, &repo, &args);
    }

    for (name, args, gone, kept) in [
        (
            "own-id",
            vec!["refs", "-c", "--delete", "org.example.Coll"],
            vec![
                "refs/heads/other",
                "refs/heads/test/main",
                "refs/heads/test/other",
                "refs/heads/test/al",
            ],
            vec![
                "refs/mirrors/org.example.Coll/mm",
                "refs/mirrors/org.example.Coll/deep/x",
                "refs/mirrors/org.example.Other/om",
            ],
        ),
        (
            "own-id-twice",
            vec![
                "refs",
                "-c",
                "--delete",
                "org.example.Coll",
                "org.example.Coll",
            ],
            vec!["refs/heads/other", "refs/heads/test/al"],
            vec![
                "refs/mirrors/org.example.Coll/mm",
                "refs/mirrors/org.example.Coll/deep/x",
            ],
        ),
        (
            "foreign-id",
            vec!["refs", "-c", "--delete", "org.example.Other"],
            vec!["refs/mirrors/org.example.Other/om"],
            vec![
                "refs/heads/other",
                "refs/heads/test/al",
                "refs/mirrors/org.example.Coll/mm",
            ],
        ),
        (
            "both-ids",
            vec![
                "refs",
                "-c",
                "--delete",
                "org.example.Coll",
                "org.example.Other",
            ],
            vec![
                "refs/heads/other",
                "refs/heads/test/al",
                "refs/mirrors/org.example.Other/om",
            ],
            vec![
                "refs/mirrors/org.example.Coll/mm",
                "refs/mirrors/org.example.Coll/deep/x",
            ],
        ),
        (
            "absent-id",
            vec!["refs", "-c", "--delete", "org.example.Absent"],
            vec![],
            vec!["refs/heads/other", "refs/mirrors/org.example.Coll/mm"],
        ),
    ] {
        let port = clone_repo(base, &repo, &format!("own-port-{name}"));
        let tool = clone_repo(base, &repo, &format!("own-tool-{name}"));
        assert_agrees(&port, &tool, &args);
        assert_eq!(
            describe_refs(&port),
            describe_refs(&tool),
            "`{}` left different refs trees",
            args.join(" "),
        );
        for path in gone {
            assert!(
                port.join(path).symlink_metadata().is_err(),
                "the port kept {path} for `{}`",
                args.join(" "),
            );
        }
        for path in kept {
            assert!(
                port.join(path).symlink_metadata().is_ok(),
                "the port removed {path} for `{}`",
                args.join(" "),
            );
        }
    }

    // The own id over a repository whose only ref of that id is a mirror ref:
    // both remove nothing and exit 0.
    let src = base.join("src");
    let mirror_only = base.join("mirror-only");
    ostrya(
        &[
            "init",
            "--repo",
            mirror_only.to_str().unwrap(),
            "--mode=archive",
            "--collection-id=org.example.Coll",
        ],
        None,
        &[],
    )
    .ok();
    let head = commit_tree(&mirror_only, "tmp", &src, None);
    write_ref_file(&mirror_only, "mirrors/org.example.Coll/mm", &head);
    std::fs::remove_file(mirror_only.join("refs/heads/tmp")).unwrap();
    let port = clone_repo(base, &mirror_only, "mirror-only-port");
    let tool = clone_repo(base, &mirror_only, "mirror-only-tool");
    let before = describe_refs(&port);
    assert_agrees(
        &port,
        &tool,
        &["refs", "-c", "--delete", "org.example.Coll"],
    );
    assert_eq!(describe_refs(&port), before, "the port removed a ref");
    assert_eq!(describe_refs(&tool), before, "the tool removed a ref");

    // A local ref carrying a mirror ref's name under the own id: the local ref is
    // removed and the mirror ref of that name stands.
    let same_name = base.join("same-name");
    ostrya(
        &[
            "init",
            "--repo",
            same_name.to_str().unwrap(),
            "--mode=archive",
            "--collection-id=org.example.Coll",
        ],
        None,
        &[],
    )
    .ok();
    let head = commit_tree(&same_name, "mm", &src, None);
    write_ref_file(&same_name, "mirrors/org.example.Coll/mm", &head);
    let port = clone_repo(base, &same_name, "same-name-port");
    let tool = clone_repo(base, &same_name, "same-name-tool");
    assert_agrees(
        &port,
        &tool,
        &["refs", "-c", "--delete", "org.example.Coll"],
    );
    assert_eq!(describe_refs(&port), describe_refs(&tool));
    assert!(!port.join("refs/heads/mm").exists(), "the port kept a ref");
    assert!(
        port.join("refs/mirrors/org.example.Coll/mm").exists(),
        "the port removed the mirror ref",
    );

    // With no `collection-id` the repository owns no id, so every mirror ref a
    // prefix names is removed.
    let no_id = create_repo(base, RepoMode::Archive);
    let head = commit_tree(&no_id, "keep", &src, None);
    write_ref_file(&no_id, "mirrors/org.example.Coll/mm", &head);
    let port = clone_repo(base, &no_id, "no-id-port");
    let tool = clone_repo(base, &no_id, "no-id-tool");
    assert_agrees(
        &port,
        &tool,
        &["refs", "-c", "--delete", "org.example.Coll"],
    );
    assert_eq!(describe_refs(&port), describe_refs(&tool));
    assert!(
        !port.join("refs/mirrors/org.example.Coll/mm").exists(),
        "the port kept the mirror ref of an id the repository does not own",
    );
    assert!(
        port.join("refs/heads/keep").exists(),
        "the port removed a ref"
    );
}

#[test]
fn refs_create_ancestry_suffix_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refs-suffix");
    let base = tmp.path();
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
    let src = base.join("src");
    // Two branches: `chain`, whose tip has a parent, and `only`, a root commit,
    // so a NEWREF suffix resolves in one and stops at the root in the other.
    let root = commit_tree(&repo, "chain", &src, None);
    std::fs::write(src.join("hello.txt"), b"second revision\n").unwrap();
    commit_tree(&repo, "chain", &src, Some(&root));
    let lone = commit_tree(&repo, "only", &src, None);

    let port = clone_repo(base, &repo, "suffix-port");
    let tool = clone_repo(base, &repo, "suffix-tool");
    // Without `--force` the NEWREF is resolved as a revision first, so a suffix
    // whose base resolves reads as an existing ref, and one whose base is a root
    // commit stops there. `-A` takes the same two paths.
    for args in [
        vec!["refs", "--create=chain^", "chain"],
        vec!["refs", "-A", "--create=chain^", "chain"],
    ] {
        assert_agrees_on_error(
            &port,
            &tool,
            &args,
            "error: --create specified but ref chain^ already exists",
        );
    }
    assert_agrees_on_error(
        &port,
        &tool,
        &["refs", "--create=only^", "chain"],
        &format!("error: Commit {lone} has no parent"),
    );
    // `--force` suppresses the already-exists refusal alone: the resolution
    // still runs, so an ancestry that resolves reaches the name check and a base
    // that is a root commit stops at the resolution.
    for args in [
        vec!["refs", "--create=chain^", "--force", "chain"],
        vec!["refs", "-A", "--create=chain^", "--force", "chain"],
    ] {
        assert_agrees_on_error(&port, &tool, &args, "error: Invalid refspec chain^");
    }
    assert_agrees_on_error(
        &port,
        &tool,
        &["refs", "--create=only^", "--force", "chain"],
        &format!("error: Commit {lone} has no parent"),
    );

    // A suffix whose base names no ref: the tool dies on a signal
    // (`docs/conformance/cli-surface.md`, "P1"), so the port's refusal stands on
    // its own, worded the way the tool words the name it does refuse.
    let refused = ostrya(
        &[
            "refs",
            "--repo",
            port.to_str().unwrap(),
            "--create=nosuch^",
            "chain",
        ],
        None,
        &[],
    );
    assert_eq!(refused.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("error: Invalid refspec nosuch^"),
        "the port's stderr lacks the refusal:\n{stderr}"
    );
    let crashed = ostree(&[
        &format!("--repo={}", tool.display()),
        "refs",
        "--create=nosuch^",
        "chain",
    ]);
    assert_eq!(
        crashed.status.code(),
        None,
        "the tool no longer dies on a signal for a NEWREF whose base is absent",
    );
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "a refused create wrote a ref",
    );
}

#[test]
fn refs_collections_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refs-coll");
    let base = tmp.path();
    build_fixture_source(base);
    let repo = base.join("repo");
    ostrya(
        &[
            "init",
            "--repo",
            repo.to_str().unwrap(),
            "--mode=archive",
            "--collection-id=org.example.Local",
        ],
        None,
        &[],
    )
    .ok();
    let src = base.join("src");
    for branch in ["test/main", "plain"] {
        commit_tree(&repo, branch, &src, None);
    }
    let head = resolve(&repo, "test/main").unwrap();
    write_ref_file(&repo, "mirrors/org.example.Mirror/mm/z", &head);
    write_ref_file(&repo, "remotes/origin/rr/x", &head);

    for args in [
        vec!["refs", "-c"],
        vec!["refs", "-c", "-r"],
        vec!["refs", "-c", "org.example.Mirror"],
        vec!["refs", "-c", "org.example.Local"],
        vec!["refs", "-c", "org.example.Local", "org.example.Mirror"],
        // -c wins over -A: the two together list collection refs.
        vec!["refs", "-c", "-A"],
        // A collection-qualified listing excludes the remote refs the plain
        // listing includes.
        vec!["refs"],
    ] {
        assert_agrees(&repo, &repo, &args);
    }

    let port = clone_repo(base, &repo, "coll-port");
    let tool = clone_repo(base, &repo, "coll-tool");
    assert_agrees(
        &port,
        &tool,
        &["refs", "-c", "--delete", "org.example.Mirror"],
    );
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "deleting a mirror collection left different refs trees",
    );
    assert_agrees(
        &port,
        &tool,
        &["refs", "-c", "--delete", "org.example.Local"],
    );
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "deleting the local collection left different refs trees",
    );
}

#[test]
fn refs_create_collection_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refs-coll-create");
    let base = tmp.path();
    let repo = build_multi_ref_repo(base);
    let port = clone_repo(base, &repo, "coll-create-port");
    let tool = clone_repo(base, &repo, "coll-create-tool");

    // `-c --create` takes NEWREF as `<collection-id>:<ref>` and writes
    // `refs/mirrors/<collection-id>/<ref>`. `-c` wins over `-A` here too, so the
    // third write is a ref file and not a symlink.
    for args in [
        vec!["refs", "-c", "--create=org.example.Fresh:new", "plain"],
        vec!["refs", "-c", "--create=org.example.Fresh:a/b", "plain"],
        vec![
            "refs",
            "-c",
            "-A",
            "--create=org.example.Fresh:aliased",
            "plain",
        ],
        vec!["refs", "-c", "--create=_x.y:z", "plain"],
        // --force replaces the collection ref just written.
        vec![
            "refs",
            "-c",
            "--create=org.example.Fresh:new",
            "--force",
            "test/main",
        ],
    ] {
        assert_agrees(&port, &tool, &args);
    }
    assert_agrees(&port, &tool, &["refs", "-c"]);
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "the two collection-ref writes left different refs trees",
    );
    assert!(
        port.join("refs/mirrors/org.example.Fresh/aliased")
            .symlink_metadata()
            .unwrap()
            .is_file()
    );

    // The refusals, in the order the two take them: the existence check reads
    // NEWREF as an ordinary refspec, the pair shape follows, the positional
    // resolves next, and the collection id is validated last.
    for (args, message) in [
        (
            vec!["refs", "-c", "--create=plain", "plain"],
            "error: --create specified but ref plain already exists".to_owned(),
        ),
        (
            vec!["refs", "-c", "--create=org.example.Fresh:a:b", "plain"],
            "error: Invalid refspec org.example.Fresh:a:b".to_owned(),
        ),
        (
            vec!["refs", "-c", "--create=a^b.c:x", "plain"],
            "error: Invalid refspec a^b.c:x".to_owned(),
        ),
        (
            vec!["refs", "-c", "--create=org.example.Fresh:x^y", "plain"],
            "error: Invalid refspec org.example.Fresh:x^y".to_owned(),
        ),
        (
            vec!["refs", "-c", "--create=org.example.Fresh:x", "nosuch"],
            "error: Refspec 'nosuch' not found".to_owned(),
        ),
        (
            vec!["refs", "-c", "--create=a-b.c:x", "plain"],
            "error: Invalid collection ID a-b.c".to_owned(),
        ),
        (
            vec!["refs", "-c", "--create=1a.b:x", "plain"],
            "error: Invalid collection ID 1a.b".to_owned(),
        ),
        (
            vec!["refs", "-c", "--create=nocollection", "plain"],
            "error: Invalid collection ID nocollection".to_owned(),
        ),
        // A NEWREF with no `:` that is a collection id carries no ref name.
        (
            vec!["refs", "-c", "--create=org.example.Fresh", "plain"],
            "error: Invalid ref name (null)".to_owned(),
        ),
        // --force suppresses the already-exists refusal, so a name the existence
        // check resolves reaches the collection-id validation.
        (
            vec!["refs", "-c", "--create=plain", "--force", "plain"],
            "error: Invalid collection ID plain".to_owned(),
        ),
    ] {
        assert_agrees_on_error(&port, &tool, &args, &message);
    }

    // The one divergence: on the missing ref name the tool prints a GLib
    // assertion line before its own message, and the port prints the message
    // alone (`docs/conformance/cli-surface.md`, "P1").
    let refused = ostrya(
        &[
            "refs",
            "--repo",
            port.to_str().unwrap(),
            "-c",
            "--create=org.example.Fresh",
            "plain",
        ],
        None,
        &[],
    );
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        "error: Invalid ref name (null)\n"
    );

    // A ref name ending in `^` kills the tool the way it does without `-c`, so
    // the port's refusal stands on its own (`cli-surface.md`, "P1").
    let refused = ostrya(
        &[
            "refs",
            "--repo",
            port.to_str().unwrap(),
            "-c",
            "--create=org.example.Fresh:x^",
            "plain",
        ],
        None,
        &[],
    );
    assert_eq!(refused.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("error: Invalid refspec org.example.Fresh:x^"),
        "the port's stderr lacks the refusal:\n{stderr}"
    );
    let crashed = ostree(&[
        &format!("--repo={}", tool.display()),
        "refs",
        "-c",
        "--create=org.example.Fresh:x^",
        "plain",
    ]);
    assert_eq!(
        crashed.status.code(),
        None,
        "the tool no longer dies on a signal for a `-c` NEWREF ending in `^`",
    );
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "a refused create wrote a ref",
    );
}

#[test]
fn invalid_refspec_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("refspec-refusal");
    let base = tmp.path();
    let repo = build_multi_ref_repo(base);
    let port = clone_repo(base, &repo, "refspec-port");
    let tool = clone_repo(base, &repo, "refspec-tool");

    // A refspec that would leave the `refs/` tree is refused in the same words
    // wherever it is taken: as NEWREF, as the positional revision, and as a
    // revision of its own. The suffix is stripped before the name is reported,
    // and a `<remote>:` prefix is part of it.
    for (args, message) in [
        (vec!["refs", "--create=a/../b", "plain"], "a/../b"),
        (vec!["refs", "-A", "--create=a/../b", "plain"], "a/../b"),
        // Under `-A` the NEWREF steps precede the target's existence check, so a
        // refused NEWREF is reported over a refused target.
        (vec!["refs", "-A", "--create=a/../b", "a/../b"], "a/../b"),
        (vec!["refs", "--create=fresh", "a/../b"], "a/../b"),
        // A remote is one component, so a `/` in it names no remote.
        (vec!["refs", "--create=fresh", "a/b:x"], "a/b:x"),
        (vec!["rev-parse", "a/../b"], "a/../b"),
        (vec!["rev-parse", "a/../b^"], "a/../b"),
        (vec!["rev-parse", "a//b"], "a//b"),
        (vec!["rev-parse", "."], "."),
        (vec!["rev-parse", "origin:../escape"], "origin:../escape"),
        (vec!["cat", "a/../b", "/hello.txt"], "a/../b"),
        // Under `-c` the whole `<collection-id>:<ref>` pair is the name, and
        // either half can carry the fault.
        (vec!["refs", "-c", "--create=:bar", "plain"], ":bar"),
        (
            vec!["refs", "-c", "--create=org.example.Fresh:", "plain"],
            "org.example.Fresh:",
        ),
        (
            vec!["refs", "-c", "--create=org.example.Fresh:a/../b", "plain"],
            "org.example.Fresh:a/../b",
        ),
        // Under `--force` the name is still refused before the positional
        // resolves, which `nosuch` states.
        (
            vec!["refs", "--create=a/../b", "--force", "nosuch"],
            "a/../b",
        ),
        (
            vec![
                "refs",
                "-c",
                "--create=org.example.Fresh:a/../b",
                "--force",
                "nosuch",
            ],
            "org.example.Fresh:a/../b",
        ),
    ] {
        assert_agrees_on_error(
            &port,
            &tool,
            &args,
            &format!("error: Invalid refspec {message}"),
        );
    }
    // An alias target reaches an existence check that stands ahead of the ref
    // name rule, so every name the rule refuses is reported as a name no ref
    // holds, in both implementations, and no `Invalid refspec` line reaches this
    // site: a traversal component, an empty component, `.`, `..`, the empty
    // name, an empty ref half, a second `:`, a `/` in the remote half, a name
    // the tool's character class refuses and the port's rule accepts, and an
    // ancestry suffix, which names a commit.
    for target in [
        "a/../b",
        "a//b",
        ".",
        "..",
        "",
        "origin:",
        "a:b:c",
        "a/b:x",
        "tes~t",
        "test/main^",
    ] {
        assert_agrees_on_error(
            &port,
            &tool,
            &["refs", "-A", "--create=al", target],
            &format!("error: Cannot create alias to non-existent ref: {target}"),
        );
    }
    // The tool's check answers the two i/o conditions with that same line, where
    // the port reports the message it gives each of them
    // (`docs/conformance/cli-surface.md`, "P1").
    for (target, message) in [
        ("plain/x", "error: i/o error: Not a directory (os error 20)"),
        ("deep", "error: i/o error: Is a directory (os error 21)"),
        (
            "deep/nest",
            "error: i/o error: Is a directory (os error 21)",
        ),
    ] {
        let (refused, missing) = run_both(&port, &tool, &["refs", "-A", "--create=al", target]);
        assert_eq!(refused.status.code(), Some(1));
        assert_eq!(
            String::from_utf8_lossy(&refused.stderr),
            format!("{message}\n"),
        );
        assert_eq!(missing.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&missing.stderr);
        assert!(
            stderr.contains(&format!(
                "error: Cannot create alias to non-existent ref: {target}"
            )),
            "the tool's refusal for the target `{target}` lacks the line:\n{stderr}",
        );
    }
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "a refused name wrote a ref",
    );

    // A target the tool's character class refuses and the port's rule accepts
    // parts the two at this site: with the ref written by `ostrya commit -b`,
    // the port writes the alias and the tool reports the target as non-existent
    // (`docs/conformance/cli-surface.md`, "P1"). The two trees part company, so
    // this pair of clones is its own.
    let odd_port = clone_repo(base, &repo, "refspec-odd-port");
    let odd_tool = clone_repo(base, &repo, "refspec-odd-tool");
    for side in [&odd_port, &odd_tool] {
        commit_tree(side, "tes~t", &base.join("src"), None);
    }
    let (written, missing) = run_both(
        &odd_port,
        &odd_tool,
        &["refs", "-A", "--create=al", "tes~t"],
    );
    written.ok();
    assert_eq!(
        std::fs::read_link(odd_port.join("refs/heads/al")).unwrap(),
        Path::new("tes~t"),
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&missing.stderr)
            .contains("error: Cannot create alias to non-existent ref: tes~t"),
    );
    assert!(
        odd_tool.join("refs/heads/al").symlink_metadata().is_err(),
        "the tool wrote an alias to a name its class refuses",
    );

    // Two divergences the same surface carries, recorded in
    // `docs/conformance/cli-surface.md`, "P1".
    //
    // The empty refspec is a search of the ref store in the tool, which reports
    // the count it found; the port refuses the name.
    let (refused, searched) = run_both(&port, &tool, &["rev-parse", ""]);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        "error: Invalid refspec \n"
    );
    assert_eq!(searched.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&searched.stderr).contains("error: Refspec  not unique"),
        "the tool no longer searches the ref store for an empty refspec:\n{}",
        String::from_utf8_lossy(&searched.stderr),
    );

    // A ref name that names a directory is refused by both where the tool's
    // `--create` scan finds a ref below the name, in one message from the port and
    // in three from the tool, two of which carry a name the port cannot
    // reproduce: a ref read in directory order, and a temporary file.
    for (args, tail) in [
        (
            vec!["refs", "--create=deep", "plain"],
            "exists under deep when attempting write",
        ),
        (
            vec!["refs", "-A", "--create=deep", "plain"],
            ", deep): Is a directory",
        ),
        (
            vec!["rev-parse", "deep"],
            "Couldn't open ref 'deep': Is a directory",
        ),
    ] {
        let (refused, conflicted) = run_both(&port, &tool, &args);
        assert_eq!(refused.status.code(), Some(1));
        assert_eq!(
            String::from_utf8_lossy(&refused.stderr),
            "error: i/o error: Is a directory (os error 21)\n"
        );
        assert_eq!(conflicted.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&conflicted.stderr);
        assert!(
            stderr.contains(tail),
            "the tool's refusal for `{}` lacks {tail:?}:\n{stderr}",
            args.join(" "),
        );
    }
    assert_eq!(
        describe_refs(&port),
        describe_refs(&tool),
        "a refused write over a ref directory changed `refs/`",
    );

    // That scan runs under `refs/heads` alone, so a directory it passes is
    // replaced by the ref file at exit 0 and the refs below it are removed, where
    // the port refuses (`docs/conformance/cli-surface.md`, "P1"). The two trees
    // part company here, so this pair of clones is its own.
    let dir_port = clone_repo(base, &repo, "refspec-dir-port");
    let dir_tool = clone_repo(base, &repo, "refspec-dir-tool");
    let before = describe_refs(&dir_port);
    let head = resolve(&repo, "plain").unwrap();

    // Under `-A` a NEWREF naming a remote reaches no directory check in either
    // implementation: the tool refuses at its remote-alias step and the port at
    // the existence check ahead of it, and neither writes.
    let (refused, aliased) = run_both(
        &dir_port,
        &dir_tool,
        &["refs", "-A", "--create=origin:rr", "plain"],
    );
    for (who, run, message) in [
        (
            "port",
            &refused,
            "error: i/o error: Is a directory (os error 21)\n",
        ),
        (
            "tool",
            &aliased,
            "error: Cannot create alias to remote ref: origin\n",
        ),
    ] {
        assert_eq!(run.status.code(), Some(1), "the {who} did not exit 1");
        assert_eq!(String::from_utf8_lossy(&run.stderr), message);
    }

    // The plain form over a directory under `refs/remotes`: the tool writes the
    // ref file in its place and destroys `origin:rr/x` and `origin:rr/deep/y`.
    let (refused, replaced) = run_both(
        &dir_port,
        &dir_tool,
        &["refs", "--create=origin:rr", "plain"],
    );
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        "error: i/o error: Is a directory (os error 21)\n"
    );
    assert_eq!(
        describe_refs(&dir_port),
        before,
        "the port wrote over a ref directory",
    );
    assert_eq!(replaced.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&replaced.stderr), "");
    let after = describe_refs(&dir_tool);
    assert!(
        after.contains(&format!("remotes/origin/rr = {head}")),
        "the tool wrote no ref file over the remote directory:\n{after:#?}",
    );
    assert!(
        !after
            .iter()
            .any(|line| line.starts_with("remotes/origin/rr/")),
        "the tool kept the refs below the directory it replaced:\n{after:#?}",
    );

    // An empty directory under `refs/heads` takes the same path, and `--delete`
    // leaves one behind in both implementations when it removes a directory's
    // last ref, so the shape arrives from either writer.
    assert_agrees(&dir_port, &dir_tool, &["refs", "--delete", "deep/nest/ing"]);
    let (refused, written) = run_both(
        &dir_port,
        &dir_tool,
        &["refs", "--create=deep/nest", "plain"],
    );
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        "error: i/o error: Is a directory (os error 21)\n"
    );
    assert!(
        describe_refs(&dir_port).contains(&"heads/deep/nest/".to_owned()),
        "the port wrote over the empty ref directory",
    );
    assert_eq!(written.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&written.stderr), "");
    let after = describe_refs(&dir_tool);
    assert!(
        after.contains(&format!("heads/deep/nest = {head}")),
        "the tool wrote no ref file over the empty directory:\n{after:#?}",
    );
}

#[test]
fn rev_parse_ancestry_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("rev-parse");
    let base = tmp.path();
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
    let src = base.join("src");
    // The chain is built by committing three times onto one branch, each commit
    // taking the branch's tip as its parent with no `--parent` of its own, which
    // is the parenting Phase 17b1 landed (`docs/port-plan.md`).
    let root = commit_tree(&repo, "chain", &src, None);
    std::fs::write(src.join("hello.txt"), b"second revision\n").unwrap();
    commit_tree(&repo, "chain", &src, None);
    std::fs::write(src.join("hello.txt"), b"third revision\n").unwrap();
    let tip = commit_tree(&repo, "chain", &src, None);

    let tip_parent = format!("{tip}^");
    for args in [
        vec!["rev-parse", "chain"],
        vec!["rev-parse", "chain^"],
        vec!["rev-parse", "chain^^"],
        vec!["rev-parse", tip.as_str()],
        vec!["rev-parse", tip_parent.as_str()],
        vec!["rev-parse", "chain", "chain^", "chain^^"],
    ] {
        assert_agrees(&repo, &repo, &args);
    }
    // Walking past the root commit reports the root's own checksum.
    assert_agrees_on_error(
        &repo,
        &repo,
        &["rev-parse", "chain^^^"],
        &format!("error: Commit {root} has no parent"),
    );
    // Three commits, so --single has no single answer.
    assert_agrees_on_error(
        &repo,
        &repo,
        &["rev-parse", "-S"],
        "error: Multiple commit objects found",
    );

    // `~N` and `^N` are not revision syntax. The tool refuses both names at its
    // own ref-name character class, and the port's rule accepts them, so the port
    // reads the whole revision as a refspec and reports the not-found line both
    // give a name that resolves to nothing. A checksum carrying either suffix
    // takes the same path (`docs/conformance/cli-surface.md`, "P1").
    let suffixed = format!("{tip}~1");
    for rev in ["chain~1", "chain^2", suffixed.as_str()] {
        let (absent, refused) = run_both(&repo, &repo, &["rev-parse", rev]);
        for (who, run, message) in [
            (
                "port",
                &absent,
                format!("error: Refspec '{rev}' not found\n"),
            ),
            ("tool", &refused, format!("error: Invalid refspec {rev}\n")),
        ] {
            assert_eq!(run.status.code(), Some(1), "the {who} did not exit 1");
            assert_eq!(String::from_utf8_lossy(&run.stderr), message);
            assert_eq!(String::from_utf8_lossy(&run.stdout), "");
        }
    }
}

/// A revision naming a commit the store does not hold: refused where the commit
/// is read, in each implementation's own words, and accepted where the site
/// takes the checksum without reading it
/// (`docs/format-reference.md`, "Revision syntax").
#[test]
fn absent_commit_object_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("absent-commit");
    let base = tmp.path();
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
    let src = base.join("src");
    commit_tree(&repo, "test/main", &src, None);
    let absent = "0".repeat(64);
    let ancestor = format!("{absent}^");

    // The tool names the loose object file it looked for and the port names the
    // object type the library looked up, both exiting 1 and writing nothing.
    let refused = |port_repo: &Path, tool_repo: &Path, args: &[&str]| {
        let (port, tool) = run_both(port_repo, tool_repo, args);
        for (who, run, message) in [
            (
                "port",
                &port,
                format!("error: object not found: Commit {absent}\n"),
            ),
            (
                "tool",
                &tool,
                format!("error: No such metadata object {absent}.commit\n"),
            ),
        ] {
            assert_eq!(
                run.status.code(),
                Some(1),
                "the {who} did not exit 1 for `{}`",
                args.join(" ")
            );
            assert_eq!(String::from_utf8_lossy(&run.stderr), message);
            assert_eq!(String::from_utf8_lossy(&run.stdout), "");
        }
    };

    // `cat` reads the commit, and a `^` suffix reads the base before it walks.
    refused(&repo, &repo, &["cat", &absent, "/hello.txt"]);
    refused(&repo, &repo, &["cat", &ancestor, "/hello.txt"]);
    refused(&repo, &repo, &["rev-parse", &ancestor]);

    // A bare checksum reaches no object, so `rev-parse` prints it and exits 0.
    assert_agrees(&repo, &repo, &["rev-parse", &absent]);

    // The positional revision of `--create` reaches no object either, so both
    // write a ref file holding the absent checksum, and reading that ref reports
    // the same pair the checksum reports.
    let port_repo = clone_repo(base, &repo, "absent-port");
    let tool_repo = clone_repo(base, &repo, "absent-tool");
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["refs", "--create=dangling", &absent],
    );
    assert_eq!(
        describe_refs(&port_repo),
        describe_refs(&tool_repo),
        "the two refs trees differ after a create over an absent checksum",
    );
    assert!(
        describe_refs(&port_repo).contains(&format!("heads/dangling = {absent}")),
        "the ref file does not hold the absent checksum",
    );
    refused(&port_repo, &tool_repo, &["cat", "dangling", "/hello.txt"]);
    assert_agrees(&port_repo, &tool_repo, &["rev-parse", "dangling"]);
}

/// A 64-character revision names a commit in lowercase hex alone. An uppercase
/// or mixed-case name of that length is a ref name wherever a revision or a
/// NEWREF is taken (`docs/format-reference.md`, "Revision syntax").
#[test]
fn checksum_case_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("checksum-case");
    let base = tmp.path();
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
    let src = base.join("src");
    commit_tree(&repo, "test/main", &src, None);
    let real = resolve(&repo, "test/main").unwrap();
    let upper = real.to_uppercase();
    // One uppercase character parts the two readings, so the mixed case raises
    // the checksum's first letter and leaves the rest alone.
    let letter = real.find(|c: char| c.is_ascii_alphabetic()).unwrap();
    let mixed = format!(
        "{}{}{}",
        &real[..letter],
        real[letter..=letter].to_uppercase(),
        &real[letter + 1..]
    );
    let upper_parent = format!("{upper}^");
    let absent_upper = "A".repeat(64);
    let absent_lower = "a".repeat(64);
    let checkout = base.join("co");
    let checkout = checkout.to_str().unwrap();

    // The read sites: the uppercase name reaches the ref lookup and both report
    // the line they give a name that resolves to nothing. The mixed case of a
    // lowercase checksum is that same name, and the lowercase form resolves.
    for args in [
        vec!["rev-parse", real.as_str()],
        vec!["rev-parse", upper.as_str()],
        vec!["rev-parse", mixed.as_str()],
        vec!["rev-parse", upper_parent.as_str()],
        vec!["rev-parse", absent_upper.as_str()],
        vec!["rev-parse", absent_lower.as_str()],
        vec!["cat", upper.as_str(), "/hello.txt"],
        vec!["cat", mixed.as_str(), "/hello.txt"],
        vec!["checkout", upper.as_str(), checkout],
        // As a PREFIX the name is matched and not resolved, so neither case
        // matches a ref here.
        vec!["refs", upper.as_str()],
        vec!["refs", "--list", absent_lower.as_str()],
    ] {
        assert_agrees(&repo, &repo, &args);
    }

    // A NEWREF of that shape is read as a revision by the existence check, so
    // the uppercase name is free and the lowercase one is taken.
    let port_repo = clone_repo(base, &repo, "case-port");
    let tool_repo = clone_repo(base, &repo, "case-tool");
    let same_refs = |port: &Path, tool: &Path, what: &str| {
        assert_eq!(
            describe_refs(port),
            describe_refs(tool),
            "the two refs trees differ {what}",
        );
    };
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["refs", &format!("--create={upper}"), "test/main"],
    );
    same_refs(
        &port_repo,
        &tool_repo,
        "after a create under the upper case",
    );
    assert!(
        describe_refs(&port_repo).contains(&format!("heads/{upper} = {real}")),
        "the ref file the uppercase NEWREF named is absent",
    );
    // The ref that name now carries is what a revision of that name resolves
    // to, and an alias records it.
    assert_agrees(&port_repo, &tool_repo, &["rev-parse", &upper]);
    assert_agrees(&port_repo, &tool_repo, &["cat", &upper, "/hello.txt"]);
    assert_agrees(&port_repo, &tool_repo, &["refs"]);
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["refs", "-A", "--create=al", &upper],
    );
    same_refs(&port_repo, &tool_repo, "after an alias to that ref");
    // The alias guard reads the link body as a name, so the ref it holds is
    // guarded under that name in both.
    assert_agrees_on_error(
        &port_repo,
        &tool_repo,
        &["refs", "--delete", &upper],
        &format!("error: Ref '{upper}' has an active alias: 'al'"),
    );
    assert_agrees(&port_repo, &tool_repo, &["refs", "--delete", "al", &upper]);
    same_refs(
        &port_repo,
        &tool_repo,
        "after removing the alias and the ref",
    );

    // The refusals the same shapes draw, each leaving `refs/` untouched.
    let port_repo = clone_repo(base, &repo, "case-refused-port");
    let tool_repo = clone_repo(base, &repo, "case-refused-tool");
    for (args, message) in [
        (
            vec![
                "refs".to_owned(),
                format!("--create={absent_lower}"),
                "test/main".to_owned(),
            ],
            format!("error: --create specified but ref {absent_lower} already exists"),
        ),
        (
            vec![
                "refs".to_owned(),
                "--create=fromupper".to_owned(),
                upper.clone(),
            ],
            format!("error: Refspec '{upper}' not found"),
        ),
        (
            vec![
                "refs".to_owned(),
                "-A".to_owned(),
                "--create=al".to_owned(),
                upper.clone(),
            ],
            format!("error: Cannot create alias to non-existent ref: {upper}"),
        ),
    ] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_agrees_on_error(&port_repo, &tool_repo, &args, &message);
    }
    same_refs(&port_repo, &tool_repo, "after the refused invocations");
    assert_eq!(
        describe_refs(&port_repo),
        describe_refs(&repo),
        "a refused invocation changed the refs tree",
    );

    // `commit --parent` takes a checksum in the tool and any revision in the
    // port, so the uppercase form is a ref name to the port and a malformed
    // checksum to the tool. Both refuse and write no ref
    // (`docs/conformance/cli-surface.md`, "P2").
    let parent = format!("--parent={upper}");
    let (port, tool) = run_both(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "fresh",
            "-s",
            "fresh",
            "--canonical-permissions",
            &parent,
            src.to_str().unwrap(),
        ],
    );
    // The tool names the first character its own reader refuses, by byte value.
    let raised = upper.as_bytes()[letter];
    for (who, run, message) in [
        (
            "port",
            &port,
            format!("error: Refspec '{upper}' not found\n"),
        ),
        (
            "tool",
            &tool,
            format!("error: Invalid character '{raised}' in rev '{upper}'\n"),
        ),
    ] {
        assert_eq!(run.status.code(), Some(1), "the {who} did not exit 1");
        assert_eq!(String::from_utf8_lossy(&run.stderr), message);
        assert_eq!(String::from_utf8_lossy(&run.stdout), "");
    }
    same_refs(&port_repo, &tool_repo, "after a refused --parent");

    // Ref file content is the other side of the rule, and only an out-of-band
    // write puts an uppercase checksum there: both implementations render a
    // checksum in lowercase. The port's reader takes either case and the tool
    // refuses the file.
    for repo in [&port_repo, &tool_repo] {
        std::fs::write(
            repo.join("refs/heads/uc"),
            format!("{absent_upper}\n").as_bytes(),
        )
        .unwrap();
    }
    let (port, tool) = run_both(&port_repo, &tool_repo, &["rev-parse", "uc"]);
    assert_eq!(port.status.code(), Some(0), "the port refused the content");
    assert_eq!(
        String::from_utf8_lossy(&port.stdout),
        format!("{absent_lower}\n"),
    );
    assert_eq!(tool.status.code(), Some(1), "the tool read the content");
    assert_eq!(
        String::from_utf8_lossy(&tool.stderr),
        format!("error: Invalid character '65' in rev '{absent_upper}'\n"),
    );
}

/// `commit` parenting: a branch's current tip is the parent a commit naming that
/// branch inherits, a tip standing over an absent commit object included,
/// `--parent=none` and `--orphan` each ask for a root commit while the ref still
/// moves, `--orphan` alone permits a commit that names no branch, and a commit
/// naming neither is refused (`docs/format-reference.md`, "CLI output formats").
///
/// Both sides commit under one `SOURCE_DATE_EPOCH`, so each printed checksum
/// states the whole commit object, the `parent` field included, rather than
/// stating that a commit happened.
#[test]
fn commit_parenting_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-parenting");
    let base = tmp.path();
    build_fixture_source(base);
    let tree = base.join("src");
    let src = tree.to_str().unwrap();
    let empty = create_repo(base, RepoMode::Archive);
    let untouched = describe_refs(&empty);
    let objects = |repo: &Path| {
        std::fs::read_dir(repo.join("objects"))
            .unwrap()
            .filter_map(|fanout| std::fs::read_dir(fanout.unwrap().path()).ok())
            .map(|entries| entries.count())
            .sum::<usize>()
    };
    let epoch = [("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)];
    /// A commit onto the branch `chain`, with `extra` between the subject and the
    /// tree the commit reads.
    fn commit_args<'a>(subject: &'a str, extra: &[&'a str], src: &'a str) -> Vec<&'a str> {
        let mut args = vec!["commit", "-b", "chain", "-s", subject];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--canonical-permissions", src]);
        args
    }

    // The first commit onto a fresh branch has no tip to take, so it is a root
    // commit; the second takes the tip the first left.
    let port_repo = clone_repo(base, &empty, "chain-port");
    let tool_repo = clone_repo(base, &empty, "chain-tool");
    assert_agrees_env(
        &port_repo,
        &tool_repo,
        &commit_args("one", &[], src),
        &epoch,
    );
    let root = resolve(&port_repo, "chain").expect("the first commit moved the ref");
    assert_agrees_on_error(
        &port_repo,
        &tool_repo,
        &["rev-parse", "chain^"],
        &format!("error: Commit {root} has no parent"),
    );
    std::fs::write(tree.join("hello.txt"), b"second revision\n").unwrap();
    assert_agrees_env(
        &port_repo,
        &tool_repo,
        &commit_args("two", &[], src),
        &epoch,
    );
    assert_agrees(&port_repo, &tool_repo, &["rev-parse", "chain^"]);
    assert_eq!(
        resolve(&port_repo, "chain^").as_deref(),
        Some(root.as_str()),
        "the second commit did not inherit the tip the first left",
    );
    assert_eq!(
        describe_refs(&port_repo),
        describe_refs(&tool_repo),
        "the two refs trees differ after two commits onto one branch",
    );
    let chained = clone_repo(base, &port_repo, "chained");
    let tip = resolve(&chained, "chain").expect("the second commit moved the ref");

    // The tip is read from the ref file and not loaded, so a ref standing over an
    // absent commit object is inherited unread. Only an out-of-band write puts
    // such a ref in place, so the ref file is written here.
    let port_repo = clone_repo(base, &empty, "unread-port");
    let tool_repo = clone_repo(base, &empty, "unread-tool");
    let unread = "a".repeat(64);
    for repo in [&port_repo, &tool_repo] {
        std::fs::write(
            repo.join("refs/heads/dangling"),
            format!("{unread}\n").as_bytes(),
        )
        .unwrap();
    }
    assert_agrees_env(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "dangling",
            "-s",
            "unread",
            "--canonical-permissions",
            src,
        ],
        &epoch,
    );
    let (port_parent, tool_parent) = run_both(&port_repo, &tool_repo, &["rev-parse", "dangling^"]);
    let inherited = port_parent.ok().stdout_trimmed();
    assert_eq!(
        inherited,
        tool_parent.ok().stdout_trimmed(),
        "the two parents read back over an absent tip differ",
    );
    assert_eq!(
        inherited, unread,
        "the absent tip the ref held is not the parent",
    );
    assert_eq!(
        describe_refs(&port_repo),
        describe_refs(&tool_repo),
        "the two refs trees differ after a commit over an absent tip",
    );

    // Each form that asks for a root commit over a branch that has a tip. The ref
    // moves to the new commit in both cases, so the suppressed parent is the whole
    // observable effect of `--orphan` where a branch is named.
    for (case, extra) in [("none", "--parent=none"), ("orphan", "--orphan")] {
        let port_repo = clone_repo(base, &chained, &format!("{case}-port"));
        let tool_repo = clone_repo(base, &chained, &format!("{case}-tool"));
        assert_agrees_env(
            &port_repo,
            &tool_repo,
            &commit_args("root", &[extra], src),
            &epoch,
        );
        let written = resolve(&port_repo, "chain").expect("the ref holds a commit");
        assert_ne!(written, tip, "`{extra}` left the ref where it was");
        assert_agrees_on_error(
            &port_repo,
            &tool_repo,
            &["rev-parse", "chain^"],
            &format!("error: Commit {written} has no parent"),
        );
        assert_eq!(
            describe_refs(&port_repo),
            describe_refs(&tool_repo),
            "the two refs trees differ after `{extra}`",
        );
    }

    // An explicit `--parent` beside `--orphan` still parents the commit, so what
    // `--orphan` suppresses is the implicit parent alone.
    let port_repo = clone_repo(base, &chained, "orphan-parent-port");
    let tool_repo = clone_repo(base, &chained, "orphan-parent-tool");
    let parent = format!("--parent={root}");
    assert_agrees_env(
        &port_repo,
        &tool_repo,
        &commit_args("both", &["--orphan", &parent], src),
        &epoch,
    );
    assert_eq!(
        resolve(&port_repo, "chain^").as_deref(),
        Some(root.as_str()),
        "`--orphan --parent` did not take the parent it was given",
    );

    // `--orphan` with no branch: both print a checksum and write no ref, and the
    // commit carries an empty `ostree.ref-binding`, which the tool reads back out
    // of the port's own commit.
    let port_repo = clone_repo(base, &empty, "no-branch-port");
    let tool_repo = clone_repo(base, &empty, "no-branch-tool");
    let orphan = [
        "commit",
        "-s",
        "lone",
        "--orphan",
        "--canonical-permissions",
        src,
    ];
    let (port_run, tool_run) = run_both_env(&port_repo, &tool_repo, &orphan, &epoch);
    let lone = port_run.ok().stdout_trimmed();
    assert_eq!(
        lone,
        tool_run.ok().stdout_trimmed(),
        "the two commits that named no branch differ",
    );
    for (who, repo) in [("port", &port_repo), ("tool", &tool_repo)] {
        assert_eq!(
            describe_refs(repo),
            untouched,
            "the {who} wrote a ref for a commit that named no branch",
        );
    }
    let binding = ostree(&[
        &format!("--repo={}", port_repo.display()),
        "show",
        "--print-metadata-key=ostree.ref-binding",
        &lone,
    ]);
    assert_eq!(
        String::from_utf8_lossy(&binding.ok().stdout),
        "@as []\n",
        "the tool read another binding out of the port's orphan commit",
    );

    // A commit naming neither a branch nor `--orphan` is refused before the parent
    // is read, before the tree is read, and before anything is published.
    let port_repo = clone_repo(base, &empty, "neither-port");
    let tool_repo = clone_repo(base, &empty, "neither-tool");
    for args in [
        vec!["commit", "-s", "x", "--canonical-permissions", src],
        vec!["commit", "-s", "x", "--parent=nosuchref", src],
        vec!["commit", "-s", "x", "nosuchdir"],
    ] {
        assert_agrees_on_error(
            &port_repo,
            &tool_repo,
            &args,
            "error: A branch must be specified with --branch, or use --orphan",
        );
    }
    for (who, repo) in [("port", &port_repo), ("tool", &tool_repo)] {
        assert_eq!(
            describe_refs(repo),
            untouched,
            "the {who} wrote a ref for a commit naming no branch",
        );
        assert_eq!(objects(repo), 0, "the {who} published an object");
    }

    // The `--parent` literal is lowercase alone, so any other spelling is a
    // revision, which parts the two implementations the way every `--parent`
    // value that is no checksum does (`docs/conformance/cli-surface.md`, "P2").
    let (port, tool) = run_both(
        &port_repo,
        &tool_repo,
        &commit_args("upper", &["--parent=NONE"], src),
    );
    for (who, run, message) in [
        ("port", &port, "error: Refspec 'NONE' not found\n"),
        ("tool", &tool, "error: Invalid rev NONE\n"),
    ] {
        assert_eq!(run.status.code(), Some(1), "the {who} did not exit 1");
        assert_eq!(String::from_utf8_lossy(&run.stderr), message);
        assert_eq!(String::from_utf8_lossy(&run.stdout), "");
    }
}

/// `commit -b` refuses a branch name of 64 lowercase hex characters -- the shape
/// resolution reads as a checksum, so a ref carrying it is reachable by no
/// revision -- and takes every other name of that length
/// (`docs/format-reference.md`, "Revision syntax").
#[test]
fn commit_checksum_branch_name_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-checksum-branch");
    let base = tmp.path();
    build_fixture_source(base);
    let src = base.join("src");
    let src = src.to_str().unwrap();
    let empty = create_repo(base, RepoMode::Archive);
    let untouched = describe_refs(&empty);
    let objects = |repo: &Path| {
        std::fs::read_dir(repo.join("objects"))
            .unwrap()
            .filter_map(|fanout| std::fs::read_dir(fanout.unwrap().path()).ok())
            .map(|entries| entries.count())
            .sum::<usize>()
    };

    let lower = "b".repeat(64);
    let commit_args = |branch: &str, path: &str| {
        vec![
            "commit".to_owned(),
            "-b".to_owned(),
            branch.to_owned(),
            "-s".to_owned(),
            "y".to_owned(),
            "--canonical-permissions".to_owned(),
            path.to_owned(),
        ]
    };
    let run = |args: &[String], port: &Path, tool: &Path| {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run_both(port, tool, &args)
    };

    // The refusal itself: both name the branch as given and write no ref.
    let port_repo = clone_repo(base, &empty, "guard-port");
    let tool_repo = clone_repo(base, &empty, "guard-tool");
    let refused = commit_args(&lower, src);
    let refused_ref: Vec<&str> = refused.iter().map(String::as_str).collect();
    assert_agrees(&port_repo, &tool_repo, &refused_ref);
    for (who, repo) in [("port", &port_repo), ("tool", &tool_repo)] {
        assert_eq!(
            describe_refs(repo),
            untouched,
            "the {who} wrote a ref for the refused branch name",
        );
    }
    // The tool writes the tree and the commit object before it reads the branch
    // name, so the refusal leaves them in `objects/`; the port publishes a
    // transaction's objects at commit and therefore publishes none
    // (`docs/conformance/cli-surface.md`, "P2"). The refs tree above is the
    // oracle the two share.
    assert_eq!(objects(&port_repo), 0, "the port published an object");
    assert!(
        objects(&tool_repo) > 0,
        "the tool published no object before the refusal",
    );

    // The guard sits at the ref write, so every fault ahead of it is reported
    // instead: an unresolvable `--parent` and a tree path that does not open,
    // each worded per implementation.
    let mut parent = commit_args(&lower, src);
    parent.insert(6, "--parent=nosuchref".to_owned());
    for (args, port_line, tool_line) in [
        (
            parent,
            "error: Refspec 'nosuchref' not found\n",
            "error: Invalid rev nosuchref\n",
        ),
        (
            commit_args(&lower, "nosuchdir"),
            "error: i/o error: No such file or directory (os error 2)\n",
            "error: opendir(nosuchdir): No such file or directory\n",
        ),
    ] {
        let (port, tool) = run(&args, &port_repo, &tool_repo);
        for (who, got, want) in [("port", &port, port_line), ("tool", &tool, tool_line)] {
            assert_eq!(got.status.code(), Some(1), "the {who} did not exit 1");
            assert_eq!(String::from_utf8_lossy(&got.stdout), "");
            assert_eq!(String::from_utf8_lossy(&got.stderr), want);
        }
    }

    // Every other 64-character shape is a branch name to both: one character
    // short, one long, one outside the hex class, all-uppercase, and one raised
    // character. Each side commits with its own binary and neither passes a
    // timestamp, so the two checksums differ wherever the runs straddle a
    // second; the claim is that each wrote the ref its own commit named.
    let port_repo = clone_repo(base, &empty, "shapes-port");
    let tool_repo = clone_repo(base, &empty, "shapes-tool");
    let mixed = format!("{}B", "b".repeat(63));
    for branch in [
        "b".repeat(63),
        "b".repeat(65),
        "g".repeat(64),
        "B".repeat(64),
        mixed,
    ] {
        let (port, tool) = run(&commit_args(&branch, src), &port_repo, &tool_repo);
        for (who, got, repo) in [("port", &port, &port_repo), ("tool", &tool, &tool_repo)] {
            assert_eq!(
                got.status.code(),
                Some(0),
                "the {who} refused the branch name {branch}: {}",
                String::from_utf8_lossy(&got.stderr),
            );
            assert_eq!(String::from_utf8_lossy(&got.stderr), "");
            let checksum = String::from_utf8_lossy(&got.stdout).trim().to_owned();
            assert_eq!(
                checksum.len(),
                64,
                "the {who} printed no checksum for {branch}",
            );
            assert!(
                describe_refs(repo).contains(&format!("heads/{branch} = {checksum}")),
                "the {who} wrote no ref for {branch}",
            );
        }
    }
}

/// `commit -b` refuses a branch name ending in `^` -- the second shape the
/// revision syntax shadows, read as ancestry wherever a revision is taken -- in
/// the words the port already gives that shape at `refs --create`. The tool
/// parts three ways over the base the suffix names
/// (`docs/conformance/cli-surface.md`, "P2").
#[test]
fn commit_ancestry_branch_name_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-ancestry-branch");
    let base = tmp.path();
    build_fixture_source(base);
    let tree = base.join("src");
    let src = tree.to_str().unwrap();
    let empty = create_repo(base, RepoMode::Archive);
    let untouched = describe_refs(&empty);
    let objects = |repo: &Path| {
        std::fs::read_dir(repo.join("objects"))
            .unwrap()
            .filter_map(|fanout| std::fs::read_dir(fanout.unwrap().path()).ok())
            .map(|entries| entries.count())
            .sum::<usize>()
    };

    let commit_args = |branch: &str, path: &str| {
        vec![
            "commit".to_owned(),
            "-b".to_owned(),
            branch.to_owned(),
            "-s".to_owned(),
            "y".to_owned(),
            "--canonical-permissions".to_owned(),
            path.to_owned(),
        ]
    };
    let run = |args: &[String], port: &Path, tool: &Path| {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run_both(port, tool, &args)
    };
    let refused = |who: &str, got: &Run, want: &str| {
        assert_eq!(got.status.code(), Some(1), "the {who} did not exit 1");
        assert_eq!(String::from_utf8_lossy(&got.stdout), "");
        assert_eq!(String::from_utf8_lossy(&got.stderr), want);
    };

    // A base that names no ref: the port refuses at the ref write and the tool
    // dies on a signal, so the refs tree is the oracle the two share.
    let port_repo = clone_repo(base, &empty, "absent-port");
    let tool_repo = clone_repo(base, &empty, "absent-tool");
    for branch in ["main^", "a^^"] {
        let (port, tool) = run(&commit_args(branch, src), &port_repo, &tool_repo);
        refused("port", &port, &format!("error: Invalid refspec {branch}\n"));
        assert_eq!(
            tool.status.code(),
            None,
            "the tool no longer dies on a signal for the branch name {branch}",
        );
    }

    // An empty base, which is a refspec the tool searches its ref store for, so
    // over an empty repository it names nothing and both refuse: the port names
    // the branch as given and the tool the base it split off.
    for branch in ["^", "^^"] {
        let (port, tool) = run(&commit_args(branch, src), &port_repo, &tool_repo);
        refused("port", &port, &format!("error: Invalid refspec {branch}\n"));
        refused("tool", &tool, "error: Invalid refspec \n");
    }

    // The tool reads the branch name before it commits the tree here, where the
    // 64-character guard reads it after, so neither side published an object
    // and both left `refs/` alone.
    for (who, repo) in [("port", &port_repo), ("tool", &tool_repo)] {
        assert_eq!(
            describe_refs(repo),
            untouched,
            "the {who} wrote a ref for a refused branch name",
        );
        assert_eq!(objects(repo), 0, "the {who} published an object");
    }

    // A base resolving to a root commit: the port reports the name and the tool
    // reports the walk it could not take.
    let rooted = clone_repo(base, &empty, "rooted");
    let root = commit_tree(&rooted, "main", &tree, None);
    let rooted_refs = describe_refs(&rooted);
    let port_repo = clone_repo(base, &rooted, "rooted-port");
    let tool_repo = clone_repo(base, &rooted, "rooted-tool");
    let (port, tool) = run(&commit_args("main^", src), &port_repo, &tool_repo);
    refused("port", &port, "error: Invalid refspec main^\n");
    refused(
        "tool",
        &tool,
        &format!("error: Commit {root} has no parent\n"),
    );

    // The two faults that stand ahead of the port's guard, each worded per
    // implementation: an unresolvable `--parent`, which both read first, and a
    // tree path that does not open, which the tool reaches only after the
    // branch name it already refused.
    let mut parent = commit_args("main^", src);
    parent.insert(6, "--parent=nosuchref".to_owned());
    let (port, tool) = run(&parent, &port_repo, &tool_repo);
    refused("port", &port, "error: Refspec 'nosuchref' not found\n");
    refused("tool", &tool, "error: Invalid rev nosuchref\n");
    // The other resolution failure a `--parent` reaches, in the same words every
    // subcommand taking a revision gives it: the ancestry of a root commit. The
    // tool's `--parent` takes a checksum alone, so it refuses the syntax
    // (`docs/conformance/cli-surface.md`, "P2").
    let mut ancestry = commit_args("main^", src);
    ancestry.insert(6, "--parent=main^".to_owned());
    let (port, tool) = run(&ancestry, &port_repo, &tool_repo);
    refused(
        "port",
        &port,
        &format!("error: Commit {root} has no parent\n"),
    );
    refused("tool", &tool, "error: Invalid rev main^\n");
    let (port, tool) = run(&commit_args("main^", "nosuchdir"), &port_repo, &tool_repo);
    refused(
        "port",
        &port,
        "error: i/o error: No such file or directory (os error 2)\n",
    );
    refused(
        "tool",
        &tool,
        &format!("error: Commit {root} has no parent\n"),
    );
    for (who, repo) in [("port", &port_repo), ("tool", &tool_repo)] {
        assert_eq!(
            describe_refs(repo),
            rooted_refs,
            "the {who} moved a ref for a refused branch name",
        );
    }

    // A base resolving to a commit that has a parent, where the two agree in
    // full: the walk succeeds and the tool refuses the name it then reads.
    let chained = clone_repo(base, &rooted, "chained");
    commit_tree(&chained, "main", &tree, Some(&root));
    let port_repo = clone_repo(base, &chained, "chained-port");
    let tool_repo = clone_repo(base, &chained, "chained-tool");
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "main^",
            "-s",
            "y",
            "--canonical-permissions",
            src,
        ],
    );

    // The boundary the guard does not cross: a `^` inside the name is a ref name
    // to the port and a refused one to the tool, which is the ref-name character
    // class `cli-surface.md` "P1" records as deferred.
    let port_repo = clone_repo(base, &empty, "interior-port");
    let tool_repo = clone_repo(base, &empty, "interior-tool");
    let (port, tool) = run(&commit_args("a^b", src), &port_repo, &tool_repo);
    assert_eq!(
        port.status.code(),
        Some(0),
        "the port refused an interior `^`: {}",
        String::from_utf8_lossy(&port.stderr),
    );
    let written = String::from_utf8_lossy(&port.stdout).trim().to_owned();
    assert!(
        describe_refs(&port_repo).contains(&format!("heads/a^b = {written}")),
        "the port wrote no ref for an interior `^`",
    );
    refused("tool", &tool, "error: Invalid refspec a^b\n");
    assert_eq!(
        describe_refs(&tool_repo),
        untouched,
        "the tool wrote a ref for an interior `^`",
    );

    // What the guard stands for. A ref of the refused shape now arrives by an
    // out-of-band write alone, and where one stands the tool's enumeration skips
    // it without a word, so its `prune --refs-only` reads the commit that ref
    // holds as unreachable and deletes it, leaving the ref file over an absent
    // object. This is the class the `odd~1` item of `cli-surface.md` "P1"
    // records for a name the tool's character class refuses.
    let shadowed = clone_repo(base, &rooted, "shadowed");
    std::fs::remove_file(shadowed.join("refs/heads/main")).unwrap();
    write_ref_file(&shadowed, "heads/main^", &root);
    let repo_arg = format!("--repo={}", shadowed.display());
    let listed = ostree(&[&repo_arg, "refs"]);
    assert_eq!(listed.status.code(), Some(0), "the tool's listing failed");
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout),
        "",
        "the tool's listing no longer skips a shadowed ref",
    );
    let object = shadowed
        .join("objects")
        .join(&root[..2])
        .join(format!("{}.commit", &root[2..]));
    assert!(object.exists(), "the fixture holds no commit object");
    let pruned = ostree(&[&repo_arg, "prune", "--refs-only"]);
    assert_eq!(pruned.status.code(), Some(0), "the tool's prune failed");
    assert!(
        !object.exists(),
        "the tool's prune kept the commit a shadowed ref holds",
    );
    assert!(
        shadowed.join("refs/heads/main^").exists(),
        "the tool's prune removed the ref file itself",
    );
}

#[test]
fn cat_path_resolution_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("cat-paths");
    let base = tmp.path();
    let src = base.join("cat-src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"content of a\n").unwrap();
    std::fs::write(src.join("sub/b.txt"), b"content of b\n").unwrap();
    std::os::unix::fs::symlink("a.txt", src.join("to-file")).unwrap();
    std::os::unix::fs::symlink("to-file", src.join("to-link")).unwrap();
    std::os::unix::fs::symlink("sub", src.join("to-dir")).unwrap();
    std::os::unix::fs::symlink("b.txt", src.join("sub/sibling")).unwrap();
    std::os::unix::fs::symlink("../a.txt", src.join("sub/parent")).unwrap();
    std::os::unix::fs::symlink("/a.txt", src.join("absolute")).unwrap();
    std::os::unix::fs::symlink("gone", src.join("dangling")).unwrap();
    // A chain deeper than any one link, ending at a regular file: `deep0` is
    // the head and 64 links lie between it and `a.txt`.
    let mut target = "a.txt".to_owned();
    for index in (0..64).rev() {
        let link = format!("deep{index}");
        std::os::unix::fs::symlink(&target, src.join(&link)).unwrap();
        target = link;
    }
    // A link naming itself, which the tool recurses on until it dies.
    std::os::unix::fs::symlink("self", src.join("self")).unwrap();
    let repo = create_repo(base, RepoMode::Archive);
    commit_tree(&repo, "paths", &src, None);

    for args in [
        // A symlink in the final position is followed, and a chain to its end,
        // 64 links deep included.
        vec!["cat", "paths", "/to-file"],
        vec!["cat", "paths", "/to-link"],
        vec!["cat", "paths", "/deep0"],
        vec!["cat", "paths", "/sub/sibling"],
        // The target is resolved against the link's own directory, and `..` is
        // looked up literally, so a target holding one fails.
        vec!["cat", "paths", "/sub/parent"],
        // An absolute target is resolved against the commit root.
        vec!["cat", "paths", "/absolute"],
        vec!["cat", "paths", "/dangling"],
        // A symlink in a non-final position is not followed.
        vec!["cat", "paths", "/to-dir/b.txt"],
        vec!["cat", "paths", "/to-dir"],
        // `.`, `..`, and an empty component each name nothing.
        vec!["cat", "paths", "/./a.txt"],
        vec!["cat", "paths", "/../a.txt"],
        vec!["cat", "paths", "//a.txt"],
        vec!["cat", "paths", "/sub/../a.txt"],
        // An empty argument reaches no component and reports the root as
        // absent; `/` reaches the root and is refused as a directory.
        vec!["cat", "paths", ""],
        vec!["cat", "paths", "/"],
        // A non-final component that is a file.
        vec!["cat", "paths", "/a.txt/b.txt"],
        // Several paths, with the failure after a file already written.
        vec!["cat", "paths", "/a.txt", "/sub/b.txt"],
        vec!["cat", "paths", "/a.txt", "/nope"],
    ] {
        assert_agrees(&repo, &repo, &args);
    }

    // The link naming itself runs against the port alone, since the tool dies
    // on a signal there.
    let run = ostrya(
        &[
            "cat",
            "--repo",
            &repo.display().to_string(),
            "paths",
            "/self",
        ],
        None,
        &[],
    );
    assert_eq!(run.status.code(), Some(1), "the port did not exit 1");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains("error: Too many levels of symbolic links"),
        "the port's stderr lacks the bound refusal:\n{stderr}"
    );
}

/// A deterministic pseudo-random payload of `len` bytes, from a 64-bit linear
/// congruential generator, so a chunk boundary that dropped, repeated, or
/// reordered bytes changes the output.
fn pseudo_random_payload(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// `cat` writes a payload larger than any buffer on its path byte for byte, in
/// every mode a commit lands in.
///
/// This is the guard on the streaming claim: `FileObject::write_to` moves
/// bounded chunks, and each mode stores the payload differently -- zlib-deflated
/// inside an `archive` object, raw in `bare-user`, raw with no xattr header in
/// `bare-user-only`. Where the tool is available it reads the port's own
/// repository, so the stored bytes are checked from both sides.
#[test]
fn cat_streams_a_large_payload_in_every_mode() {
    let tmp = TmpDir::new("cat-large");
    let base = tmp.path();
    let payload = pseudo_random_payload(5 * 1024 * 1024);
    let src = base.join("large-src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("big.bin"), &payload).unwrap();

    for (mode, name) in [
        (RepoMode::Archive, "archive"),
        (RepoMode::BareUser, "bare-user"),
        (RepoMode::BareUserOnly, "bare-user-only"),
    ] {
        let home = base.join(name);
        std::fs::create_dir_all(&home).unwrap();
        let repo = create_repo(&home, mode);
        commit_tree(&repo, "large", &src, None);

        let run = ostrya(
            &["cat", "--repo", repo.to_str().unwrap(), "large", "/big.bin"],
            None,
            &[],
        );
        run.ok();
        assert_eq!(
            run.stdout.len(),
            payload.len(),
            "`cat` in {name} wrote {} bytes for a {}-byte payload",
            run.stdout.len(),
            payload.len(),
        );
        assert!(
            run.stdout == payload,
            "`cat` in {name} wrote the payload's length and different bytes"
        );

        if ostree_available() {
            let tool = ostree(&[
                &format!("--repo={}", repo.display()),
                "cat",
                "large",
                "/big.bin",
            ]);
            assert!(
                tool.status.success(),
                "the tool failed to read the port's {name} repository: {}",
                String::from_utf8_lossy(&tool.stderr),
            );
            assert!(
                tool.stdout == payload,
                "the tool read different bytes from the port's {name} repository"
            );
        }
    }
}

/// A refusal after a large payload keeps every byte already written.
///
/// The stdout writer stages a write in an in-memory pipe a blocking worker
/// drains, so the bytes it still holds reach the descriptor only once the writes
/// settle. `cat` settles them on the refusal path as well as on the success one,
/// which this pins with a payload larger than that pipe and a second path the
/// lookup refuses.
#[test]
fn cat_keeps_the_payload_written_before_a_refusal() {
    let tmp = TmpDir::new("cat-refusal-tail");
    let base = tmp.path();
    let payload = pseudo_random_payload(16 * 1024 * 1024);
    let src = base.join("tail-src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("big.bin"), &payload).unwrap();
    let repo = create_repo(base, RepoMode::Archive);
    commit_tree(&repo, "tail", &src, None);

    let run = ostrya(
        &[
            "cat",
            "--repo",
            repo.to_str().unwrap(),
            "tail",
            "/big.bin",
            "/nope",
        ],
        None,
        &[],
    );
    assert_eq!(run.status.code(), Some(1), "the port did not exit 1");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains("error: No such file or directory: /nope"),
        "the port's stderr lacks the refusal:\n{stderr}"
    );
    assert_eq!(
        run.stdout.len(),
        payload.len(),
        "`cat` wrote {} bytes of a {}-byte payload before the refusal",
        run.stdout.len(),
        payload.len(),
    );
    assert!(
        run.stdout == payload,
        "`cat` wrote the payload's length and different bytes"
    );

    if ostree_available() {
        let tool = ostree(&[
            &format!("--repo={}", repo.display()),
            "cat",
            "tail",
            "/big.bin",
            "/nope",
        ]);
        assert_eq!(
            tool.status.code(),
            Some(1),
            "the tool did not exit 1: {}",
            String::from_utf8_lossy(&tool.stderr),
        );
        assert!(
            tool.stdout == payload,
            "the tool wrote different bytes before its own refusal"
        );
    }
}
