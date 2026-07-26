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
