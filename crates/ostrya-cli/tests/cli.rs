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
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ostrya::{ComposefsOptions, CreateOptions, LockKind, Repo, RepoMode, base64};
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

/// The instant a faked-clock GnuPG home stands at, 2025-01-01T00:00:00Z.
#[cfg(feature = "gpg")]
const FAKED_CLOCK: &str = "20250101T000000!";

/// Whether the gpg binary is available.
#[cfg(feature = "gpg")]
fn gpg_available() -> bool {
    Command::new("gpg")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
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

    /// Generate a signing key for `uid` in a new home directory under `base`
    /// that was created at the instant [`FAKED_CLOCK`] names and lives for
    /// `expiry` from it.
    ///
    /// The instant stands in the home's `gpg.conf`, so every `gpg` run bound to
    /// it reads that clock, the signing run gpgme drives included. A signature
    /// this home makes is therefore made while the key is live. Verification
    /// reads the real clock in each implementation, which is what makes an
    /// expired key expired.
    fn expiring(base: &Path, uid: &str, expiry: &str) -> GpgHome {
        let dir = base.join("gnupghome");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            dir.join("gpg.conf"),
            format!("faked-system-time {FAKED_CLOCK}\n"),
        )
        .unwrap();
        let home = GpgHome { dir };
        let status = home
            .gpg()
            .args(["--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--quick-gen-key", uid, "ed25519", "sign", expiry])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-gen-key failed");
        home
    }

    /// Set the key's expiry, with `gpg` standing at `when`.
    ///
    /// A fresh self-signature carries a creation time, and `gpg` refuses to
    /// write one at the instant the self-signature it replaces carries. The
    /// clock option stated last answers, so a run at a later instant writes the
    /// signature a run at the home's own instant cannot.
    fn set_expire_at(&self, when: &str, expiry: &str) {
        let primary = self.fingerprint();
        let status = self
            .gpg()
            .args(["--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--faked-system-time", when])
            .args(["--quick-set-expire", &primary, expiry])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-set-expire failed");
    }

    /// Add a signing subkey to the key this home holds and report its
    /// fingerprint. `gpg` 2.4.9 signs with a signing subkey where the
    /// certificate carries one, so a signature made after this call is the
    /// subkey's and names two keys: the subkey and the primary key that binds
    /// it.
    fn add_signing_subkey(&self) -> String {
        let status = self
            .gpg()
            .args(["--pinentry-mode", "loopback", "--passphrase", ""])
            .args([
                "--quick-add-key",
                &self.fingerprint(),
                "ed25519",
                "sign",
                "never",
            ])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-add-key failed");
        let out = self
            .gpg()
            .args(["--with-colons", "--list-keys"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout).unwrap();
        let fingerprints: Vec<&str> = text
            .lines()
            .filter_map(|line| line.strip_prefix("fpr:"))
            .filter_map(|rest| rest.split(':').nth(8))
            .collect();
        assert_eq!(fingerprints.len(), 2, "the primary key and one subkey");
        fingerprints[1].to_owned()
    }

    /// Generate a second signing key for `uid` in this home directory, so a
    /// selector matching both user ids is ambiguous.
    fn add_key(&self, uid: &str) {
        let status = self
            .gpg()
            .args(["--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--quick-gen-key", uid, "ed25519", "sign", "never"])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-gen-key failed");
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

    /// The primary-key fingerprint of the one key `selector` names, as
    /// uppercase hex. A home holding more than one key is read through this,
    /// since the listing order of two keys is `gpg`'s to choose.
    fn fingerprint_of(&self, selector: &str) -> String {
        let out = self
            .gpg()
            .args(["--with-colons", "--list-keys", "--"])
            .arg(selector)
            .output()
            .unwrap();
        assert!(out.status.success(), "gpg --list-keys failed");
        let text = String::from_utf8(out.stdout).unwrap();
        let fingerprints: Vec<&str> = text
            .lines()
            .filter_map(|line| line.strip_prefix("fpr:"))
            .filter_map(|rest| rest.split(':').nth(8))
            .collect();
        assert!(!fingerprints.is_empty(), "no key matched {selector:?}");
        fingerprints[0].to_owned()
    }

    /// Designate the key `revoker` names as a revoker of the key `key` names.
    /// `gpg` writes a fresh direct-key self-signature carrying signature
    /// subpacket 12, so this home must hold both certificates.
    fn add_revoker(&self, key: &str, revoker: &str) {
        let mut cmd = self.gpg_interactive();
        cmd.arg("--edit-key").arg(key);
        answer(
            cmd,
            format!("addrevoker\n{revoker}\ny\ny\nsave\n").as_bytes(),
            "gpg --edit-key addrevoker",
        );
    }

    /// Write to `path` the key revocation a designated revoker makes over the
    /// key `key` names: a transferable public key of the revoked key carrying
    /// the class 0x20 signature. This home must hold the revoker's secret key
    /// and a certificate of the revoked key that designates it.
    fn desig_revoke(&self, key: &str, path: &Path) {
        let mut cmd = self.gpg_interactive();
        cmd.arg("--armor")
            .arg("--output")
            .arg(path)
            .arg("--desig-revoke")
            .arg(key);
        answer(cmd, b"y\n0\n\ny\n", "gpg --desig-revoke");
    }

    /// A `gpg` command bound to this home that reads its answers from standard
    /// input, for the commands that take no batch form.
    fn gpg_interactive(&self) -> Command {
        let mut cmd = Command::new("gpg");
        cmd.arg("--homedir").arg(&self.dir).args([
            "--no-tty",
            "--no-batch",
            "--command-fd",
            "0",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ]);
        cmd
    }

    /// Export the certificate of the one key `selector` names to `path`.
    fn export_one_to(&self, selector: &str, path: &Path) {
        let out = self
            .gpg()
            .arg("--export")
            .arg("--")
            .arg(selector)
            .output()
            .unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        std::fs::write(path, out.stdout).unwrap();
    }

    /// Export the public keyring to `path`.
    fn export_to(&self, path: &Path) {
        let out = self.gpg().arg("--export").output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        std::fs::write(path, out.stdout).unwrap();
    }
}

/// The export of the key `key` names out of a fresh GnuPG home holding the
/// streams `streams` names, imported in the order they stand in, written to
/// `out`.
///
/// The merge runs in a home of its own because `gpg` signs with no key its own
/// keyring reports revoked: it reports "Unusable secret key". The import of the
/// stream `gpg --desig-revoke` writes exits 2 and merges the class 0x20
/// signature into the certificate it holds either way, so the exit status of an
/// import is not read here.
#[cfg(feature = "gpg")]
fn merged_export(dir: &Path, key: &str, streams: &[&Path], out: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let gpg = || {
        let mut cmd = Command::new("gpg");
        cmd.arg("--homedir").arg(dir).arg("--batch");
        cmd
    };
    for stream in streams {
        gpg().arg("--import").arg(stream).status().unwrap();
    }
    let export = gpg().arg("--export").arg("--").arg(key).output().unwrap();
    assert!(export.status.success() && !export.stdout.is_empty());
    std::fs::write(out, export.stdout).unwrap();
    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(dir)
        .args(["--kill", "gpg-agent"])
        .status();
}

/// Run `cmd`, writing `answers` to its standard input, and assert that it
/// reported success. `what` names the command in the assertion message.
#[cfg(feature = "gpg")]
fn answer(mut cmd: Command, answers: &[u8], what: &str) {
    use std::io::Write;

    let out = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(answers)?;
            child.wait_with_output()
        })
        .unwrap();
    assert!(out.status.success(), "{what} failed");
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

/// The environment variable that turns the ed25519-unsupported skip into a
/// failure. A harness setting it declares that the installed `ostree` carries
/// the engine, so a run where it does not is a broken harness rather than a
/// test to pass over.
const REQUIRE_OSTREE_ED25519: &str = "OSTRYA_REQUIRE_OSTREE_ED25519";

/// Whether the `ostree` tool carries its ed25519 signing engine, which
/// `ostree --version` reports as the `sign-ed25519` feature. The engine is a
/// build option: a tool built without it refuses every ed25519 invocation with
/// `Requested signature type is not implemented`, which describes the tool's
/// build and states nothing about the port. With [`REQUIRE_OSTREE_ED25519`] set
/// the absence fails; without it the test skips and says so.
fn ostree_supports_ed25519() -> bool {
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
    if supported {
        return true;
    }
    eprintln!("skipped: `ostree` carries no ed25519 engine");
    false
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

/// The generator's own command line, now that the port accepts every option it
/// uses: declared ownership, no xattrs, and a fixed timestamp reproduce the
/// golden fixture commit without `--canonical-permissions` standing in for
/// them. The ISO form of the same instant, the hexadecimal and octal renderings
/// of the same ids, and a negative id (which declares nothing, so the tree keeps
/// the ownership its source carries) are held beside it.
#[test]
fn commit_flags_reproduce_the_fixture_id() {
    let tmp = TmpDir::new("commit-flags");
    let base = tmp.path();
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
    let src = base.join("src");

    let commit = |timestamp: &str, uid: &str, gid: &str| {
        ostrya(
            &[
                "commit",
                "--repo",
                repo.to_str().unwrap(),
                "-b",
                BRANCH,
                "-s",
                SUBJECT,
                "--parent=none",
                &format!("--owner-uid={uid}"),
                &format!("--owner-gid={gid}"),
                "--no-xattrs",
                &format!("--timestamp={timestamp}"),
                src.to_str().unwrap(),
            ],
            None,
            &[],
        )
    };

    assert_eq!(
        commit("@1700000000", "0", "0").ok().stdout_trimmed(),
        COMMIT,
        "the generator's own flags reproduce the fixture commit id",
    );
    assert_eq!(
        commit("2023-11-14T22:13:20Z", "0", "0")
            .ok()
            .stdout_trimmed(),
        COMMIT,
        "the ISO form of the fixture instant is the same timestamp",
    );
    assert_eq!(
        commit("2023-11-14 23:13:20+01:00", "0x0", "00")
            .ok()
            .stdout_trimmed(),
        COMMIT,
        "an offset-bearing wall clock and hexadecimal and octal ids agree",
    );
    // A negative id declares nothing, so the source's ownership stands. Stating
    // that as equality against the source's own ids holds whoever runs the test;
    // comparing against the fixture instead would collapse under a root run,
    // whose source tree already carries the fixture's `0:0`.
    let source = std::fs::metadata(src.join("hello.txt")).unwrap();
    let (uid, gid) = (source.uid(), source.gid());
    assert_eq!(
        commit("@1700000000", "-1", "-1").ok().stdout_trimmed(),
        commit("@1700000000", &uid.to_string(), &gid.to_string())
            .ok()
            .stdout_trimmed(),
        "a negative id declares nothing, so the source's ownership stands",
    );
    if (uid, gid) != (0, 0) {
        assert_ne!(
            commit("@1700000000", "-1", "-1").ok().stdout_trimmed(),
            COMMIT,
            "the source's ownership differs from the fixture's, so the commit does",
        );
    }

    // `SOURCE_DATE_EPOCH` names the same instant the fixture uses, and
    // `--timestamp` overrides whatever it holds.
    let over_epoch = ostrya(
        &[
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
            "--parent=none",
            "--owner-uid=0",
            "--owner-gid=0",
            "--no-xattrs",
            "--timestamp=@1700000000",
            src.to_str().unwrap(),
        ],
        None,
        &[("SOURCE_DATE_EPOCH", "1")],
    );
    assert_eq!(
        over_epoch.ok().stdout_trimmed(),
        COMMIT,
        "--timestamp wins over SOURCE_DATE_EPOCH",
    );
}

/// The four `commit` tree-and-time options against the tool, over a tree
/// carrying xattrs, a symlink, and a nested directory: each side commits the
/// same tree with the same options and the printed checksums must agree, which
/// states that the recorded ownership, mode, xattr set, and timestamp are
/// byte-identical.
#[test]
fn commit_ownership_and_timestamp_flags_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-owner");
    let base = tmp.path();
    let tree = base.join("tree");
    ostrya_conformance::corpus::materialize("C0", &tree).unwrap();
    ostrya_conformance::corpus::materialize("C4", &tree.join("attrs")).unwrap();
    // The tool records no xattr whose value is zero bytes long, where the port
    // records one, so a tree carrying such an entry compares two different
    // objects whatever the options under test say. The case is corpus `C4`'s own
    // (`docs/conformance/m0-content.matrix`) and is held out here.
    std::fs::remove_file(tree.join("attrs/empty-value")).unwrap();

    let port_repo = base.join("port");
    let tool_repo = base.join("tool");
    for repo in [&port_repo, &tool_repo] {
        block_on(async {
            Repo::create(repo, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
        });
    }

    // A case names the branch its commit binds, and two cases that must produce
    // one commit share it: `ostree.ref-binding` carries the branch name, so a
    // commit's checksum states the name too. Every commit is a root commit
    // whatever the branch already holds.
    let cases: [(&str, &str, Vec<&str>); 7] = [
        ("plain", "plain", vec!["--timestamp=@1234567890"]),
        (
            "owner",
            "owner",
            vec![
                "--timestamp=@1234567890",
                "--owner-uid=42",
                "--owner-gid=43",
            ],
        ),
        (
            "owner-radix",
            "owner",
            vec![
                "--timestamp=@1234567890",
                "--owner-uid=0x2a",
                "--owner-gid=053",
            ],
        ),
        (
            "uid-only",
            "uid-only",
            vec!["--timestamp=@1234567890", "--owner-uid=42"],
        ),
        (
            "no-xattrs",
            "no-xattrs",
            vec!["--timestamp=@1234567890", "--no-xattrs", "--owner-uid=42"],
        ),
        ("iso", "plain", vec!["--timestamp=2009-02-13T23:31:30Z"]),
        ("pre-epoch", "pre-epoch", vec!["--timestamp=@-1"]),
    ];

    let mut checksums = std::collections::BTreeMap::new();
    for (case, branch, options) in &cases {
        let mut args = vec![
            "commit".to_owned(),
            "-b".to_owned(),
            (*branch).to_owned(),
            "-s".to_owned(),
            "x".to_owned(),
            "--parent=none".to_owned(),
        ];
        args.extend(options.iter().map(|option| (*option).to_owned()));
        args.push(tree.to_str().unwrap().to_owned());

        let port = {
            let mut argv = vec!["--repo".to_owned(), port_repo.display().to_string()];
            argv.extend(args.clone());
            let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
            ostrya(&borrowed, None, &[]).ok().stdout_trimmed()
        };
        let tool = {
            let out = Command::new("ostree")
                .arg(format!("--repo={}", tool_repo.display()))
                .args(&args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "ostree commit {case} failed:\n{}",
                String::from_utf8_lossy(&out.stderr),
            );
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        };
        assert_eq!(port, tool, "case `{case}`: the two commits differ");
        checksums.insert(*case, port);
    }

    assert_eq!(
        checksums["owner"], checksums["owner-radix"],
        "`0x2a` and `053` are the ids 42 and 43",
    );
    assert_eq!(
        checksums["plain"], checksums["iso"],
        "`@1234567890` and its ISO form are one instant",
    );
    assert_ne!(
        checksums["plain"], checksums["no-xattrs"],
        "the corpus carries xattrs, so dropping them changes the commit",
    );
}

/// A declared-ownership commit keeps object identity across the modes that
/// store ownership: one checksum in `archive`, `bare-user`, and the port
/// extension `bare-user-shared`. The tool cannot open the third mode, so this is
/// what corpus `C3`'s `bare-user-shared` cell rests on
/// (`docs/conformance/m0-content.matrix`); the other two modes are compared
/// against the tool directly by the cells and the test above.
#[test]
fn declared_ownership_is_one_commit_across_modes() {
    let tmp = TmpDir::new("commit-owner-modes");
    let base = tmp.path();
    build_fixture_source(base);
    let src = base.join("src");

    let mut checksums = Vec::new();
    for (name, mode) in [
        ("archive", RepoMode::Archive),
        ("bare-user", RepoMode::BareUser),
        ("bare-user-shared", RepoMode::BareUserShared),
    ] {
        let repo = base.join(format!("repo-{name}"));
        block_on(async {
            Repo::create(&repo, CreateOptions::new(mode)).await.unwrap();
        });
        let commit = ostrya(
            &[
                "commit",
                "--repo",
                repo.to_str().unwrap(),
                "-b",
                BRANCH,
                "-s",
                SUBJECT,
                "--timestamp=@1700000000",
                "--owner-uid=42",
                "--owner-gid=43",
                src.to_str().unwrap(),
            ],
            None,
            &[],
        );
        checksums.push((name, commit.ok().stdout_trimmed()));
    }

    let (first_name, first) = &checksums[0];
    for (name, checksum) in &checksums[1..] {
        assert_eq!(
            checksum, first,
            "{name} and {first_name} disagree on a declared-ownership commit",
        );
    }
}

/// The values `commit` refuses, in the tool's own words and at the tool's own
/// step: an id no C `int` holds, an id beside `--canonical-permissions`, and a
/// timestamp neither reader accepts. Every case leaves the repository empty.
#[test]
fn commit_refuses_the_values_the_tool_refuses() {
    let tmp = TmpDir::new("commit-refuse");
    let base = tmp.path();
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
    let src = base.join("src");
    let tool = ostree_available();

    let cases: [(Vec<&str>, &str); 9] = [
        (
            vec!["--owner-uid=abc"],
            "error: Cannot parse integer value \u{201c}abc\u{201d} for --owner-uid",
        ),
        (
            vec!["--owner-uid="],
            "error: Cannot parse integer value \u{201c}\u{201d} for --owner-uid",
        ),
        (
            vec!["--owner-uid=5x"],
            "error: Cannot parse integer value \u{201c}5x\u{201d} for --owner-uid",
        ),
        (
            vec!["--owner-gid=zz"],
            "error: Cannot parse integer value \u{201c}zz\u{201d} for --owner-gid",
        ),
        (
            vec!["--owner-uid=2147483648"],
            "error: Integer value \u{201c}2147483648\u{201d} for --owner-uid out of range",
        ),
        (
            vec!["--canonical-permissions", "--owner-uid=1"],
            "error: Cannot specify both --canonical-permissions and non-zero --owner-uid",
        ),
        (
            vec!["--canonical-permissions", "--owner-gid=7", "--owner-uid=0"],
            "error: Cannot specify both --canonical-permissions and non-zero --owner-gid",
        ),
        (
            vec!["--timestamp=nonsense"],
            "error: Could not parse 'nonsense'",
        ),
        // The tool's reader takes no bare epoch count, and neither does the
        // port's; the `@` form is what states one.
        (
            vec!["--timestamp=1234567890"],
            "error: Could not parse '1234567890'",
        ),
    ];

    for (options, message) in &cases {
        // The invocation both implementations receive, `--repo` apart: the port
        // takes it as an option in either position, the tool only ahead of the
        // subcommand name (`docs/conformance/cli-surface.md`, "Global
        // conventions").
        let mut shared = vec!["commit", "-b", "refused", "-s", "x"];
        shared.extend(options.iter().copied());
        shared.push(src.to_str().unwrap());
        let mut args = vec!["--repo", repo.to_str().unwrap()];
        args.extend(shared.iter().copied());

        let run = ostrya(&args, None, &[]);
        assert_eq!(
            run.status.code(),
            Some(1),
            "`{options:?}` was not refused:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
        assert!(run.stdout.is_empty(), "`{options:?}` printed a checksum");
        assert_eq!(
            String::from_utf8_lossy(&run.stderr).trim(),
            *message,
            "`{options:?}` was refused in other words",
        );
        assert_eq!(
            resolve(&repo, "refused"),
            None,
            "`{options:?}` left a ref behind",
        );

        if tool {
            let out = Command::new("ostree")
                .arg(format!("--repo={}", repo.display()))
                .args(&shared)
                .output()
                .unwrap();
            assert_eq!(
                out.status.code(),
                Some(1),
                "the tool accepted `{options:?}`",
            );
            assert_eq!(
                String::from_utf8_lossy(&out.stderr).trim(),
                *message,
                "the tool refuses `{options:?}` in other words",
            );
        }
    }
}

/// Every `commit` refusal that stands after the transaction opens reaps the
/// staging directory, whichever way the refusal ends the process. The seven
/// cases cover the three exit shapes a refusal takes: an abort followed by a
/// process exit (a `dir=` source that does not open, a `tar=` source that does
/// not open, a `--consume` removal that fails, a `--tar-pathname-filter` value
/// the reader refuses, and a `--base` revision that does not resolve), and a
/// process exit taken from inside the revision reader (`--tree=ref=` over an
/// unknown ref and over a revision with no parent). Each leaves `tmp/` holding
/// no `staging-` entry, `objects/` holding the objects it held before, and no
/// new ref.
#[test]
fn commit_source_refusals_leave_no_staging_directory() {
    let tmp = TmpDir::new("commit-staging");
    let base = tmp.path();
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
    let repo_arg = format!("--repo={}", repo.display());
    let src = base.join("src");
    let tar = base.join("src.tar");
    pack_tar(&src, &tar);
    let tar_arg = format!("--tree=tar={}", tar.display());
    // `--consume` removes the source directory once its contents are ingested,
    // and `remove_dir` on a path spelled `./` reports EINVAL, so the refusal is
    // reached without depending on the caller's privileges. The run empties the
    // directory, so it stands apart from the fixture source.
    let consumed = base.join("consumed");
    std::fs::create_dir_all(&consumed).unwrap();
    std::fs::write(consumed.join("f.txt"), b"consume me\n").unwrap();
    let objects = |repo: &Path| {
        std::fs::read_dir(repo.join("objects"))
            .unwrap()
            .filter_map(|fanout| std::fs::read_dir(fanout.unwrap().path()).ok())
            .map(|entries| entries.count())
            .sum::<usize>()
    };

    // A root commit on `held` supplies the revision the two `--tree=ref=` cases
    // read: one names a ref the repository does not carry, the other asks a root
    // commit for a parent. Its objects are the baseline every case is measured
    // against.
    let src_arg = format!("--tree=dir={}", src.display());
    let seed = ostrya(
        &[repo_arg.as_str(), "commit", "-b", "held", &src_arg],
        None,
        &[],
    );
    assert!(seed.status.success(), "seeding the repository failed");
    let held = resolve(&repo, "held").expect("the seed commit moved `held`");
    let baseline = objects(&repo);

    let cases: [(Option<&Path>, Vec<&str>, String); 7] = [
        (
            None,
            vec!["-b", "refused", "/nonexistent-zz"],
            "error: opendir(/nonexistent-zz): No such file or directory".to_owned(),
        ),
        (
            None,
            vec!["-b", "refused", "--tree=tar=/nonexistent.tar"],
            "error: archive_read_open_filename: Failed to open '/nonexistent.tar'".to_owned(),
        ),
        (
            Some(consumed.as_path()),
            vec!["-b", "refused", "--consume", "./"],
            "error: unlinkat(./): Invalid argument".to_owned(),
        ),
        (
            None,
            vec!["-b", "refused", "--tar-pathname-filter=nocomma", &tar_arg],
            "error: Missing ',' in --tar-pathname-filter".to_owned(),
        ),
        (
            None,
            vec!["-b", "refused", "--base=nosuchref", &src_arg],
            "error: Refspec 'nosuchref' not found".to_owned(),
        ),
        (
            None,
            vec!["-b", "refused", "--tree=ref=nosuchref"],
            "error: Refspec 'nosuchref' not found".to_owned(),
        ),
        (
            None,
            vec!["-b", "refused", "--tree=ref=held^"],
            format!("error: Commit {held} has no parent"),
        ),
    ];

    for (cwd, options, message) in &cases {
        let mut args = vec![repo_arg.as_str(), "commit"];
        args.extend(options.iter().copied());
        let run = ostrya_in(*cwd, &args, None, &[]);
        assert_eq!(
            run.status.code(),
            Some(1),
            "`{options:?}` was not refused:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
        assert_eq!(
            String::from_utf8_lossy(&run.stderr).trim(),
            *message,
            "`{options:?}` was refused in other words",
        );
        assert_eq!(resolve(&repo, "refused"), None, "`{options:?}` wrote a ref");
        let staged: Vec<String> = std::fs::read_dir(repo.join("tmp"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("staging-"))
            .collect();
        assert!(
            staged.is_empty(),
            "`{options:?}` left a staging directory: {staged:?}",
        );
        assert_eq!(
            objects(&repo),
            baseline,
            "`{options:?}` published an object"
        );
    }
}

/// `commit --table-output` prints the tool's seven-line block byte for byte, in
/// three repository modes and over three commits per mode: the first into an
/// empty repository, a second of a tree holding one more file, and a third of
/// the first tree again, whose objects the repository already holds. The three
/// commits move every counter, so the comparison states the counts and not the
/// shape of the block alone.
///
/// A `--tree=ref=` source parts the two counter sets, and the last block of the
/// test pins each side at the value it is measured to print
/// (`docs/conformance/m10-cli-behavior.matrix`,
/// `commit/table-output-with-a-ref-source`).
#[test]
fn commit_table_output_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-table");
    let base = tmp.path();
    let tree = base.join("tree");
    ostrya_conformance::corpus::materialize("C0", &tree).unwrap();
    let grown = base.join("grown");
    ostrya_conformance::corpus::materialize("C0", &grown).unwrap();
    std::fs::write(grown.join("added.txt"), b"one more file\n").unwrap();

    for (name, mode) in [
        ("archive", RepoMode::Archive),
        ("bare", RepoMode::Bare),
        ("bare-user", RepoMode::BareUser),
    ] {
        let port_repo = base.join(format!("port-{name}"));
        let tool_repo = base.join(format!("tool-{name}"));
        for repo in [&port_repo, &tool_repo] {
            block_on(async {
                Repo::create(repo, CreateOptions::new(mode)).await.unwrap();
            });
        }
        let mut blocks = Vec::new();
        for source in [&tree, &grown, &tree] {
            let args = [
                "commit",
                "-b",
                "conformance",
                "-s",
                "x",
                "--timestamp=@1700000000",
                "--table-output",
                source.to_str().unwrap(),
            ];
            let (port, tool) = run_both(&port_repo, &tool_repo, &args);
            assert_runs_agree(&port, &tool, &args.join(" "));
            assert!(
                port.status.success(),
                "the `{name}` step failed:\n{}",
                String::from_utf8_lossy(&port.stderr),
            );
            blocks.push(String::from_utf8_lossy(&port.stdout).into_owned());
        }
        // The three steps move the counters apart, so what the comparison above
        // reads is the counts and not the block's shape: the second step writes
        // one content object more than the first, and the third writes none.
        for (earlier, later) in [(0, 1), (1, 2), (0, 2)] {
            assert_ne!(
                blocks[earlier], blocks[later],
                "steps {earlier} and {later} of the `{name}` sequence printed one block",
            );
        }
    }

    // A `tar=` source of three regular files and a `ref=` source whose tree
    // holds one, over an archive pair. The tool adds a `ref=` source's content
    // objects to `Content Total` where that source does not open the source
    // list, and a `ref=` source standing alone carries one metadata object in
    // the tool's total against the port's two. Each side is asserted at the
    // value it prints, so a change on either side fails the run.
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let three = base.join("three");
    std::fs::create_dir_all(three.join("sub")).unwrap();
    std::fs::write(three.join("a.txt"), b"a\n").unwrap();
    std::fs::write(three.join("sub/b.txt"), b"b\n").unwrap();
    std::fs::write(three.join("sub/c.txt"), b"c\n").unwrap();
    let archive = base.join("a.tar");
    pack_tar(&three, &archive);
    let one = base.join("one");
    std::fs::create_dir_all(&one).unwrap();
    std::fs::write(one.join("o.txt"), b"only\n").unwrap();
    let tar_source = format!("--tree=tar={}", archive.display());
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "only1",
            "-s",
            "x",
            "--timestamp=@1700000000",
            &format!("--tree=dir={}", one.display()),
        ],
    );

    // The six counter lines, which carry no checksum and so compare verbatim.
    let counters = |run: &Run| -> String {
        String::from_utf8_lossy(&run.stdout)
            .lines()
            .filter(|line| !line.starts_with("Commit: "))
            .map(|line| format!("{line}\n"))
            .collect()
    };
    let parts = |branch: &str, extra: &[&str], port_block: &str, tool_block: &str| {
        let mut args = vec![
            "commit",
            "-b",
            branch,
            "-s",
            "x",
            "--timestamp=@1700000000",
            "--table-output",
        ];
        args.extend_from_slice(extra);
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let label = args.join(" ");
        for (who, run) in [("port", &port), ("tool", &tool)] {
            assert_eq!(
                run.status.code(),
                Some(0),
                "the {who} did not commit `{label}`:\n{}",
                String::from_utf8_lossy(&run.stderr)
            );
        }
        let first = |run: &Run| {
            String::from_utf8_lossy(&run.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(
            first(&port),
            first(&tool),
            "`{label}` reached different commits"
        );
        // The counters are the whole difference, so the other stream agrees.
        assert_eq!(
            String::from_utf8_lossy(&port.stderr),
            String::from_utf8_lossy(&tool.stderr),
            "`{label}` wrote different standard error",
        );
        assert_eq!(
            counters(&port),
            port_block,
            "the port's counters for `{label}`"
        );
        assert_eq!(
            counters(&tool),
            tool_block,
            "the tool's counters for `{label}`"
        );
    };

    // A `ref=` source second: `Content Total` carries the ref tree's one
    // content object for the tool and not for the port.
    parts(
        "c1",
        &[&tar_source, "--tree=ref=only1"],
        "Metadata Total: 5\nMetadata Written: 3\nContent Total: 3\n\
         Content Written: 3\nContent Cache Hits: 0\nContent Bytes Written: 6\n",
        "Metadata Total: 5\nMetadata Written: 3\nContent Total: 4\n\
         Content Written: 3\nContent Cache Hits: 0\nContent Bytes Written: 6\n",
    );
    // The same two sources in the other order, where the whole block agrees.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "c2",
            "-s",
            "x",
            "--timestamp=@1700000000",
            "--table-output",
            "--tree=ref=only1",
            &tar_source,
        ],
    );
    // A `ref=` source alone: no content object is counted on either side, and
    // `Metadata Total` is the tool's one against the port's two.
    parts(
        "c3",
        &["--tree=ref=only1"],
        "Metadata Total: 2\nMetadata Written: 1\nContent Total: 0\n\
         Content Written: 0\nContent Cache Hits: 0\nContent Bytes Written: 0\n",
        "Metadata Total: 1\nMetadata Written: 1\nContent Total: 0\n\
         Content Written: 0\nContent Cache Hits: 0\nContent Bytes Written: 0\n",
    );
}

/// `commit --fsync=POLICY` takes the tool's boolean words, refuses every other
/// value in the tool's words and at the tool's own step, and changes no byte the
/// repository stores.
#[test]
fn commit_fsync_policy_matches_the_tool() {
    let tmp = TmpDir::new("commit-fsync");
    let base = tmp.path();
    let tree = base.join("tree");
    ostrya_conformance::corpus::materialize("C0", &tree).unwrap();
    let source = tree.to_str().unwrap();
    let tool = ostree_available();

    let port_repo = base.join("port");
    let tool_repo = base.join("tool");
    for repo in [&port_repo, &tool_repo] {
        block_on(async {
            Repo::create(repo, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
        });
    }

    // Every accepted spelling, in both cases. Each commit is a root commit onto
    // one branch, so the whole set must print one checksum: the policy decides
    // durability and no recorded byte.
    let accepted = [
        "true", "TRUE", "tRuE", "yes", "yEs", "1", "false", "False", "no", "NO", "0",
    ];
    let mut checksums = Vec::new();
    for value in accepted {
        let args = [
            "commit",
            "-b",
            "fsync",
            "-s",
            "x",
            "--parent=none",
            "--timestamp=@1700000000",
            &format!("--fsync={value}"),
            source,
        ]
        .map(str::to_owned);
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        if tool {
            assert_agrees(&port_repo, &tool_repo, &borrowed);
        }
        let mut argv = vec!["--repo", port_repo.to_str().unwrap()];
        argv.extend(borrowed.iter().copied());
        checksums.push(ostrya(&argv, None, &[]).ok().stdout_trimmed());
    }
    for (value, checksum) in accepted.iter().zip(&checksums) {
        assert_eq!(
            checksum, &checksums[0],
            "`--fsync={value}` reached another commit",
        );
    }

    // The two policies over two fresh repositories leave the same object store.
    let mut stores = Vec::new();
    for (name, value) in [("on", "true"), ("off", "false")] {
        let repo = base.join(format!("policy-{name}"));
        block_on(async {
            Repo::create(&repo, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
        });
        ostrya(
            &[
                "commit",
                "--repo",
                repo.to_str().unwrap(),
                "-b",
                "fsync",
                "-s",
                "x",
                "--timestamp=@1700000000",
                &format!("--fsync={value}"),
                source,
            ],
            None,
            &[],
        )
        .ok();
        stores.push(describe_tree(&repo.join("objects")));
    }
    assert_eq!(
        stores[0], stores[1],
        "the fsync policy changed the object store",
    );

    // A value the reader does not hold, and the fault order around it: the
    // refusal stands ahead of the missing branch, ahead of the tree, and ahead
    // of the timestamp. The valueless form takes the next word as its value,
    // which is what the last case names.
    let refusals: [(Vec<&str>, &str); 7] = [
        (
            vec!["-b", "f", "--fsync=on", source],
            "error: Invalid boolean argument 'on'",
        ),
        (
            vec!["-b", "f", "--fsync=garbage", source],
            "error: Invalid boolean argument 'garbage'",
        ),
        (
            vec!["-b", "f", "--fsync=", source],
            "error: Invalid boolean argument ''",
        ),
        (
            vec!["--fsync=on", source],
            "error: Invalid boolean argument 'on'",
        ),
        (
            vec!["-b", "f", "--fsync=on", "no-such-tree"],
            "error: Invalid boolean argument 'on'",
        ),
        (
            vec!["-b", "f", "--fsync=on", "--timestamp=nonsense", source],
            "error: Invalid boolean argument 'on'",
        ),
        (vec!["-b", "f", "--fsync", source], ""),
    ];
    for (options, message) in &refusals {
        let mut args = vec!["commit"];
        args.extend(options.iter().copied());
        let expected = if message.is_empty() {
            format!("error: Invalid boolean argument '{source}'")
        } else {
            (*message).to_owned()
        };
        let mut argv = vec!["--repo", port_repo.to_str().unwrap()];
        argv.extend(args.iter().copied());
        let run = ostrya(&argv, None, &[]);
        assert_eq!(
            run.status.code(),
            Some(1),
            "`{options:?}` was not refused:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
        assert!(run.stdout.is_empty(), "`{options:?}` printed output");
        assert_eq!(
            String::from_utf8_lossy(&run.stderr).trim(),
            expected,
            "`{options:?}` was refused in other words",
        );
        if tool {
            assert_agrees(&port_repo, &tool_repo, &args);
        }
    }

    // The one ordering the two do not share: with two refusable values on one
    // command line the tool reports the leftmost and the port reports
    // `--owner-uid` whatever its position (`docs/conformance/cli-surface.md`,
    // "P2"). Both orders are run, since "whatever its position" is the claim.
    if tool {
        for order in [
            ["--fsync=on", "--owner-uid=abc"],
            ["--owner-uid=abc", "--fsync=on"],
        ] {
            let (port, tool_run) = run_both(
                &port_repo,
                &tool_repo,
                &["commit", order[0], order[1], "-b", "f", source],
            );
            assert!(
                String::from_utf8_lossy(&port.stderr)
                    .contains("Cannot parse integer value \u{201c}abc\u{201d} for --owner-uid"),
                "the port reported another fault first under {order:?}",
            );
            let leftmost = if order[0] == "--fsync=on" {
                "Invalid boolean argument 'on'"
            } else {
                "Cannot parse integer value"
            };
            assert!(
                String::from_utf8_lossy(&tool_run.stderr).contains(leftmost),
                "the tool reported another fault first under {order:?}",
            );
        }
    }
}

/// A `[core] fsync` value the reader does not hold is refused under every state
/// of `--fsync`, the option's own value included. The option narrows the
/// configured policy, so the configured value is read before the narrowing and
/// `--fsync=false` conceals nothing (`docs/format-reference.md`, "The fsync
/// vocabulary").
#[test]
fn commit_refuses_a_bad_configured_fsync_under_every_override() {
    let tmp = TmpDir::new("commit-fsync-bad-config");
    let base = tmp.path();
    let tree = base.join("tree");
    ostrya_conformance::corpus::materialize("C0", &tree).unwrap();
    let source = tree.to_str().unwrap();
    let tool = ostree_available();

    let port_repo = base.join("port");
    let tool_repo = base.join("tool");
    for repo in [&port_repo, &tool_repo] {
        block_on(async {
            Repo::create(repo, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
        });
        let config = repo.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("fsync=bogus\n");
        std::fs::write(&config, text).unwrap();
    }

    for option in [None, Some("--fsync=true"), Some("--fsync=false")] {
        let mut args = vec!["commit", "-b", "f", "-s", "x", "--timestamp=@1700000000"];
        args.extend(option);
        args.push(source);

        let mut argv = vec!["--repo", port_repo.to_str().unwrap()];
        argv.extend(args.iter().copied());
        let run = ostrya(&argv, None, &[]);
        assert_eq!(
            run.status.code(),
            Some(1),
            "`{option:?}` committed over a bad `[core] fsync`:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
        assert!(run.stdout.is_empty(), "`{option:?}` printed output");
        assert!(
            String::from_utf8_lossy(&run.stderr).contains("core.fsync"),
            "`{option:?}` was refused for another reason:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
        assert!(
            !port_repo.join("refs/heads/f").exists(),
            "`{option:?}` wrote a ref",
        );

        // The two part on the wording alone: the tool names its key file and
        // the port names the key (`docs/conformance/cli-surface.md`, "Global
        // conventions"). The exit status and the empty standard output are the
        // claim, and so is the ref neither writes.
        if tool {
            let (_, tool_run) = run_both(&port_repo, &tool_repo, &args);
            assert_eq!(
                tool_run.status.code(),
                Some(1),
                "the tool accepted a bad `[core] fsync` under `{option:?}`",
            );
            assert!(tool_run.stdout.is_empty(), "the tool printed output");
            assert!(
                !tool_repo.join("refs/heads/f").exists(),
                "the tool wrote a ref",
            );
        }
    }
}

/// Whether `strace` is installed and can trace a child of this process under
/// the options the two syscall tests use, `-y` among them, since both read the
/// path behind a descriptor. The syscall claims below are stated only where they
/// can be measured.
fn strace_available() -> bool {
    std::process::Command::new("strace")
        .args(["-y", "-f", "-e", "trace=fsync", "-o", "/dev/null", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The `fsync`, `fdatasync`, and `syncfs` calls one `commit` makes, in call
/// order, each a pair of the call's name and the path `strace -y` prints behind
/// the descriptor, named relative to the repository and `.` for the repository
/// itself. The run is returned beside them, so the caller reads the streams and
/// the exit status of the same invocation.
///
/// A call the tracer splits across an `<unfinished ...>` and a `resumed` line is
/// read from the entry line, which is the one carrying the descriptor, so each
/// call is read once.
fn sync_calls(
    binary: &str,
    repo: &std::path::Path,
    trace: &std::path::Path,
    args: &[&str],
) -> (Run, Vec<(&'static str, String)>) {
    let out = std::process::Command::new("strace")
        .args(["-y", "-f", "-e", "trace=fsync,fdatasync,syncfs", "-o"])
        .arg(trace)
        .arg(binary)
        .args(args)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .expect("strace runs");
    let text = std::fs::read_to_string(trace).expect("the trace is written");
    let root = repo.to_str().expect("the repository path is text");
    let prefix = format!("{root}/");
    let calls = text
        .lines()
        .filter_map(|line| {
            let kind = ["fsync", "fdatasync", "syncfs"].into_iter().find(|call| {
                line.split_whitespace()
                    .any(|word| word.starts_with(&format!("{call}(")))
            })?;
            let at = line.find(&format!("{kind}("))? + kind.len() + 1;
            let open = at + line[at..].find('<')? + 1;
            let close = open + line[open..].find('>')?;
            let path = &line[open..close];
            let named = match path.strip_prefix(&prefix) {
                Some(rest) => rest,
                None if path == root => ".",
                None => path,
            };
            Some((kind, named.to_owned()))
        })
        .collect();
    let run = Run {
        status: out.status,
        stdout: out.stdout,
        stderr: out.stderr,
    };
    (run, calls)
}

/// The fanout directories present under `objects/`, named relative to the
/// repository. On a repository created for one commit these are exactly the
/// fanouts that commit wrote into, so the caller reads the expected `fsync`
/// targets out of the tree the run produced instead of naming checksums.
fn object_fanouts(repo: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(repo.join("objects"))
        .expect("the object store is readable")
        .map(|entry| entry.expect("the entry reads").file_name())
        .filter_map(|name| name.to_str().map(str::to_owned))
        .filter(|name| name.len() == 2 && name.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|name| format!("objects/{name}"))
        .collect();
    names.sort();
    names
}

/// The `--fsync=POLICY` policy is resolved from the repository config narrowed
/// by the option, and the resolved value reaches every write the transaction
/// makes, the ref write among them. Neither half shows in a byte the repository
/// stores, so the claim is stated in syscalls: the four rows of the table in
/// `docs/format-reference.md`, "The fsync vocabulary", measured for the port and
/// for the tool over corpus `C0` under the single-component branch name `main`.
/// Three of the four rows must issue no sync call at all.
///
/// The syncing row is held to the whole call inventory the table records, so
/// dropping any one sync fails it. The `fsync` targets are read from the tree
/// the run produced -- every fanout directory under `objects/`, plus `objects/`
/// itself, plus, for the port alone, `refs/heads` -- which states the rule the
/// table states and follows the corpus if the corpus changes. The totals, 11
/// for the tool and 12 for the port, are asserted beside it, so the table and
/// this test stay one record.
///
/// This test reads the single-component ref name, where the ref write creates no
/// directory. `commit_syncs_every_created_ref_directory` reads the names that
/// carry `/`, where it does, and holds the created directories and their call
/// order. Runs where `strace` is installed.
#[test]
fn commit_fsync_policy_controls_the_syscalls() {
    if !strace_available() {
        return;
    }
    let tmp = TmpDir::new("commit-fsync-syscalls");
    // `strace -y` prints the path a descriptor resolves to, so the repository
    // path the targets are named against must be resolved too.
    let base = &tmp.path().canonicalize().expect("the temp dir resolves");
    let tree = base.join("tree");
    ostrya_conformance::corpus::materialize("C0", &tree).unwrap();
    let source = tree.to_str().unwrap();
    let port = env!("CARGO_BIN_EXE_ostrya");

    // (tag, configured `[core] fsync`, option, whether any sync call is
    // expected). The tool is measured beside the port wherever it is installed.
    let rows: [(&str, Option<&str>, Option<&str>, bool); 4] = [
        ("unset-on", None, Some("--fsync=true"), true),
        ("on-off", Some("true"), Some("--fsync=false"), false),
        ("off-plain", Some("false"), None, false),
        ("off-on", Some("false"), Some("--fsync=true"), false),
    ];

    let mut binaries: Vec<(&str, String)> = vec![("port", port.to_owned())];
    if ostree_available() {
        binaries.push(("tool", "ostree".to_owned()));
    }

    // Every row of every binary is held against this one: the policy reaches the
    // sync calls and leaves standard output, standard error, the exit status,
    // and the object store where they stand.
    let mut answer: Option<(String, String, Option<i32>, Vec<String>)> = None;
    for (who, binary) in &binaries {
        for (tag, configured, option, expect_sync) in rows {
            let repo = base.join(format!("{who}-{tag}"));
            block_on(async {
                Repo::create(&repo, CreateOptions::new(RepoMode::Archive))
                    .await
                    .unwrap();
            });
            if let Some(value) = configured {
                let config = repo.join("config");
                let text = std::fs::read_to_string(&config).unwrap();
                std::fs::write(
                    &config,
                    text.replacen("[core]\n", &format!("[core]\nfsync={value}\n"), 1),
                )
                .unwrap();
            }
            // The global `--repo` takes the `=` form, which is the one spelling
            // both binaries read ahead of the subcommand.
            let repo_arg = format!("--repo={}", repo.display());
            let mut args = vec![
                repo_arg.as_str(),
                "commit",
                "-b",
                "main",
                "-s",
                "x",
                "--timestamp=@1700000000",
            ];
            if let Some(option) = option {
                args.push(option);
            }
            args.push(source);
            let trace = base.join(format!("trace-{who}-{tag}"));
            let (run, calls) = sync_calls(binary, &repo, &trace, &args);
            assert!(
                run.status.success(),
                "`{who}` failed the `{tag}` row: {args:?}\n{}",
                String::from_utf8_lossy(&run.stderr),
            );
            assert!(
                repo.join("refs/heads/main").exists(),
                "`{who}` wrote no ref in the `{tag}` row, so the ref write went unmeasured",
            );
            if expect_sync {
                // One `fsync` per fanout the commit wrote into, one of
                // `objects/`, and, for the port, one of the directory holding
                // the ref, which the tool does not issue.
                let mut expected = object_fanouts(&repo);
                expected.push("objects".to_owned());
                if *who == "port" {
                    expected.push("refs/heads".to_owned());
                }
                expected.sort();
                let mut fsyncs: Vec<String> = calls
                    .iter()
                    .filter(|(kind, _)| *kind == "fsync")
                    .map(|(_, path)| path.clone())
                    .collect();
                fsyncs.sort();
                assert_eq!(
                    fsyncs, expected,
                    "`{who}` did not `fsync` the directories the `{tag}` row expects",
                );

                let ref_syncs: Vec<&String> = calls
                    .iter()
                    .filter(|(kind, _)| *kind == "fdatasync")
                    .map(|(_, path)| path)
                    .collect();
                assert_eq!(
                    ref_syncs.len(),
                    1,
                    "`{who}` issued {} `fdatasync` calls in the `{tag}` row, where the \
                     ref's temp file takes one: {calls:?}",
                    ref_syncs.len(),
                );
                assert!(
                    ref_syncs[0].starts_with("refs/heads/"),
                    "`{who}` did not `fdatasync` the ref's temp file in the `{tag}` row: {}",
                    ref_syncs[0],
                );

                let repo_syncs: Vec<&String> = calls
                    .iter()
                    .filter(|(kind, _)| *kind == "syncfs")
                    .map(|(_, path)| path)
                    .collect();
                assert_eq!(
                    repo_syncs,
                    ["."],
                    "`{who}` did not `syncfs` the repository once in the `{tag}` row: {calls:?}",
                );

                // The totals `docs/format-reference.md`, "The fsync
                // vocabulary", records for corpus `C0`. They follow from the
                // rules above and the eight objects the corpus commits.
                let total = if *who == "port" { 12 } else { 11 };
                assert_eq!(
                    calls.len(),
                    total,
                    "`{who}` issued {} sync calls in the `{tag}` row, where the table in \
                     `docs/format-reference.md`, \"The fsync vocabulary\", records {total}: \
                     {calls:?}",
                    calls.len(),
                );
            } else {
                assert!(
                    calls.is_empty(),
                    "`{who}` issued {} sync calls in the `{tag}` row, \
                     where the configured policy is off: {calls:?}",
                    calls.len(),
                );
            }

            // The sync calls are the whole difference. Every row prints the same
            // checksum, says nothing on standard error, exits the same way, and
            // leaves the same object store, across the four policies and across
            // the two binaries.
            let observed = (
                String::from_utf8_lossy(&run.stdout).into_owned(),
                String::from_utf8_lossy(&run.stderr).into_owned(),
                run.status.code(),
                describe_tree(&repo.join("objects")),
            );
            match &answer {
                None => answer = Some(observed),
                Some(first) => assert_eq!(
                    &observed, first,
                    "`{who}` answered the `{tag}` row differently from the first row",
                ),
            }
        }
    }
}

/// The directories under `refs/` one traced run `fsync`-ed, in call order, each
/// named relative to the repository. `strace -y` prints the path behind a
/// descriptor, which is what makes the target of each call readable.
fn ref_dir_fsyncs(
    binary: &str,
    repo: &std::path::Path,
    trace: &std::path::Path,
    args: &[&str],
) -> Vec<String> {
    let run = std::process::Command::new("strace")
        .args(["-y", "-f", "-e", "trace=fsync", "-o"])
        .arg(trace)
        .arg(binary)
        .args(args)
        .output()
        .expect("strace runs");
    assert!(
        run.status.success(),
        "the traced run failed: {args:?}\n{}",
        String::from_utf8_lossy(&run.stderr),
    );
    let text = std::fs::read_to_string(trace).expect("the trace is written");
    let prefix = format!("{}/", repo.display());
    text.lines()
        .filter_map(|line| {
            let call = line.find("fsync(")?;
            let open = call + line[call..].find('<')? + 1;
            let close = open + line[open..].find('>')?;
            line[open..close].strip_prefix(&prefix).map(str::to_owned)
        })
        .filter(|path| path.starts_with("refs/"))
        .collect()
}

/// A ref name carrying `/` is durable as a whole path. Committing
/// `deep/nest/branch` into a repository that holds neither directory creates
/// `refs/heads/deep` and `refs/heads/deep/nest`, and each created name lives in
/// the directory above it, so that directory is the one an `fsync` records.
/// The calls run deepest first, the order the object fanout uses: the ref file's
/// own name, then the name of the directory holding it, then the name above
/// that. A directory already in place is not synced, and `--fsync=false`
/// reaches none of them.
///
/// The tool issues no directory `fsync` for a ref at all
/// (`docs/format-reference.md`, "Ref durability"), so this states the port's own
/// rule and no interop cell reads it. It reads the `fsync` targets under `refs/`
/// alone, and the port alone; the whole call inventory of one commit, for both
/// binaries, is `commit_fsync_policy_controls_the_syscalls`. Runs where `strace`
/// is installed.
#[test]
fn commit_syncs_every_created_ref_directory() {
    if !strace_available() {
        return;
    }
    let tmp = TmpDir::new("ref-parent-fsync");
    let base = tmp.path().canonicalize().expect("the temp dir resolves");
    let tree = base.join("tree");
    ostrya_conformance::corpus::materialize("C0", &tree).unwrap();
    let source = tree.to_str().unwrap();
    let port = env!("CARGO_BIN_EXE_ostrya");

    let repo = create_repo(&base, RepoMode::Archive);
    let repo_arg = format!("--repo={}", repo.display());
    let commit = |branch: &str, fsync: &str, trace: &str| -> Vec<String> {
        ref_dir_fsyncs(
            port,
            &repo,
            &base.join(trace),
            &[
                repo_arg.as_str(),
                "commit",
                "-b",
                branch,
                "-s",
                "x",
                "--timestamp=@1700000000",
                fsync,
                source,
            ],
        )
    };

    assert_eq!(
        commit("deep/nest/branch", "--fsync=true", "trace-created"),
        ["refs/heads/deep/nest", "refs/heads/deep", "refs/heads"],
        "a fresh multi-component ref must sync the holder of every name it created",
    );

    // Every directory of the path is now in place, so the second commit onto it
    // creates nothing and syncs the directory holding the ref alone.
    assert_eq!(
        commit("deep/nest/other", "--fsync=true", "trace-existing"),
        ["refs/heads/deep/nest"],
        "a directory already in place needs no sync",
    );

    assert_eq!(
        commit("other/path/branch", "--fsync=false", "trace-off"),
        Vec::<String>::new(),
        "`--fsync=false` must issue no directory sync",
    );
    assert!(
        repo.join("refs/heads/other/path/branch").exists(),
        "the `--fsync=false` row wrote no ref, so it measured nothing",
    );
}

/// The three tree-shaping options reach the tar stream `commit` reads from
/// standard input, so a tar of a tree and the tree itself commit alike under
/// them. The tool takes its tar through `--tree=tar=PATH`, a form the port does
/// not yet accept (`docs/conformance/cli-surface.md`, "P2"), so this states the
/// port's own two paths against each other.
#[test]
fn commit_tar_stream_honours_the_tree_options() {
    let tmp = TmpDir::new("commit-tar-flags");
    let base = tmp.path();
    build_fixture_source(base);
    let repo = create_repo(base, RepoMode::Archive);
    let src = base.join("src");

    let plain = ostrya(
        &[
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            "plain",
            "-s",
            SUBJECT,
            "--timestamp=@1700000000",
            src.to_str().unwrap(),
        ],
        None,
        &[],
    );
    let plain = plain.ok().stdout_trimmed();
    let tar = ostrya(
        &["export", "--repo", repo.to_str().unwrap(), &plain],
        None,
        &[],
    );
    let tar = tar.ok().stdout.clone();

    let options = [
        "--owner-uid=42",
        "--owner-gid=43",
        "--no-xattrs",
        "--timestamp=@1700000000",
    ];
    let mut from_dir = vec![
        "commit",
        "--repo",
        repo.to_str().unwrap(),
        "-b",
        "declared",
        "-s",
        SUBJECT,
        "--parent=none",
    ];
    from_dir.extend(options);
    let from_tar = from_dir.clone();
    from_dir.push(src.to_str().unwrap());

    assert_eq!(
        ostrya(&from_tar, Some(&tar), &[]).ok().stdout_trimmed(),
        ostrya(&from_dir, None, &[]).ok().stdout_trimmed(),
        "the tar stream and the tree it came from commit alike under the options",
    );
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

/// `checkout -U` and `checkout --subpath=PATH` against the tool's checkout of
/// the same commit, over a tree carrying a setuid file, a setgid directory, a
/// nested directory, and a symlink, in the modes whose checkout path differs:
/// `archive` copies, `bare-user` hardlinks under `-U`, and `bare` copies under
/// `-U` while it hardlinks without it.
#[test]
fn checkout_user_mode_and_subpath_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("checkout-user");
    let base = tmp.path();
    let tree = base.join("tree");
    ostrya_conformance::corpus::materialize("C0", &tree).unwrap();
    ostrya_conformance::corpus::materialize("C2", &tree.join("bits")).unwrap();

    let cases: [(&str, Vec<&str>); 6] = [
        ("user-mode", vec!["-U"]),
        ("subpath-dir", vec!["-U", "--subpath=/dir"]),
        ("subpath-relative", vec!["-U", "--subpath=dir"]),
        ("subpath-file", vec!["-U", "--subpath=/file.txt"]),
        ("subpath-symlink", vec!["-U", "--subpath=/link"]),
        ("subpath-root", vec!["-U", "--subpath=/"]),
    ];

    for (mode_name, mode) in [
        ("archive", RepoMode::Archive),
        ("bare-user", RepoMode::BareUser),
        ("bare", RepoMode::Bare),
    ] {
        let repo = base.join(format!("repo-{mode_name}"));
        block_on(async {
            Repo::create(&repo, CreateOptions::new(mode)).await.unwrap();
        });
        let commit = ostrya(
            &[
                "commit",
                "--repo",
                repo.to_str().unwrap(),
                "-b",
                BRANCH,
                "-s",
                SUBJECT,
                "--timestamp=@1700000000",
                tree.to_str().unwrap(),
            ],
            None,
            &[],
        );
        let commit = commit.ok().stdout_trimmed();

        for (case, options) in &cases {
            let dest_port = base.join(format!("port-{mode_name}-{case}"));
            let mut args = vec!["checkout", "--repo", repo.to_str().unwrap()];
            args.extend(options.iter().copied());
            args.push(&commit);
            args.push(dest_port.to_str().unwrap());
            ostrya(&args, None, &[]).ok();

            let dest_tool = base.join(format!("tool-{mode_name}-{case}"));
            let out = Command::new("ostree")
                .arg(format!("--repo={}", repo.display()))
                .arg("checkout")
                .args(options)
                .args([&commit, &dest_tool.display().to_string()])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "ostree checkout {case} in {mode_name} failed:\n{}",
                String::from_utf8_lossy(&out.stderr),
            );
            assert_eq!(
                describe_tree(&dest_port),
                describe_tree(&dest_tool),
                "case `{case}` in {mode_name}: the two checkouts differ",
            );
        }

        // A file or symlink subpath is placed inside a destination directory the
        // checkout creates, rather than becoming the destination itself.
        let inside = base.join(format!("port-{mode_name}-subpath-file"));
        assert!(
            inside.join("file.txt").is_file(),
            "a file subpath lands inside the destination directory",
        );
    }
}

/// The subpaths `checkout` refuses. Both implementations exit 1 and leave no
/// destination behind; the words differ, which
/// `docs/conformance/cli-surface.md`, "P2" records.
#[test]
fn checkout_refuses_a_subpath_that_names_nothing() {
    let tmp = TmpDir::new("checkout-subpath-refuse");
    let base = tmp.path();
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
            "--timestamp=@1700000000",
            src.to_str().unwrap(),
        ],
        None,
        &[],
    );
    let commit = commit.ok().stdout_trimmed();
    let tool = ostree_available();

    for subpath in ["/nope", "/subdir/nope", "/hello.txt/deeper"] {
        let dest = base.join(format!("dest{}", subpath.replace('/', "-")));
        let run = ostrya(
            &[
                "checkout",
                "--repo",
                repo.to_str().unwrap(),
                &format!("--subpath={subpath}"),
                &commit,
                dest.to_str().unwrap(),
            ],
            None,
            &[],
        );
        assert_eq!(
            run.status.code(),
            Some(1),
            "`{subpath}` was not refused:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
        assert!(!dest.exists(), "`{subpath}` left a destination behind",);

        if tool {
            let dest_tool = base.join(format!("tool{}", subpath.replace('/', "-")));
            let out = Command::new("ostree")
                .arg(format!("--repo={}", repo.display()))
                .args([
                    "checkout",
                    &format!("--subpath={subpath}"),
                    &commit,
                    &dest_tool.display().to_string(),
                ])
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(1), "the tool accepted `{subpath}`",);
            assert!(
                !dest_tool.exists(),
                "the tool left a destination behind for `{subpath}`",
            );
        }
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
        repo.export_composefs(&checksum, &ComposefsOptions::default())
            .await
            .unwrap()
            .bytes
    });
    assert_eq!(
        cli_bytes, lib_bytes,
        "--composefs writes the library's EROFS image bytes",
    );
    assert!(!cli_bytes.is_empty(), "composefs image is non-empty");
}

/// The two composefs switches of `checkout`, over a `bare-user` repository
/// holding one tree. `--composefs` writes the verity image, and
/// `--composefs-noverity` writes the image whose metacopy xattr carries no
/// digest. The switches are independent and the no-verity switch decides, so
/// the two combined forms write the no-verity image whatever their order. Each
/// form is held against the tool's own image for the same commit.
///
/// Every destination is created at mode 0600 first, so each form also states
/// that both implementations replace a destination that already exists rather
/// than write into it: the image lands at the process umask on both sides.
#[test]
fn checkout_composefs_switches_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("checkout-composefs-switches");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::BareUser);
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
            FIXED_TIMESTAMP,
            "--orphan",
            tree.to_str().unwrap(),
        ],
    );
    let rev = ostrya(
        &[
            "rev-parse",
            &format!("--repo={}", port_repo.display()),
            BRANCH,
        ],
        None,
        &[],
    )
    .ok()
    .stdout_trimmed();

    // The tool writes the image through a temporary file it creates in the
    // working directory and links to the destination, so both implementations
    // run from the directory the destinations sit in. One image per form and
    // per implementation leaves eight files to compare.
    let mut written = Vec::new();
    for (n, flags) in [
        ["--composefs"].as_slice(),
        ["--composefs-noverity"].as_slice(),
        ["--composefs", "--composefs-noverity"].as_slice(),
        ["--composefs-noverity", "--composefs"].as_slice(),
    ]
    .iter()
    .enumerate()
    {
        let label = flags.join(" ");
        let port_image = base.join(format!("port{n}.cfs"));
        let tool_image = base.join(format!("tool{n}.cfs"));
        for dest in [&port_image, &tool_image] {
            std::fs::write(dest, b"stale destination").unwrap();
            std::fs::set_permissions(dest, PermissionsExt::from_mode(0o600)).unwrap();
        }
        let line = |repo: &Path, dest: &Path| {
            let mut args = vec!["checkout".to_owned(), format!("--repo={}", repo.display())];
            args.extend(flags.iter().map(|flag| (*flag).to_owned()));
            args.push(rev.clone());
            args.push(dest.display().to_string());
            args
        };
        let port_args = line(&port_repo, &port_image);
        let tool_args = line(&tool_repo, &tool_image);
        let port = ostrya_in(
            Some(base),
            &port_args.iter().map(String::as_str).collect::<Vec<_>>(),
            None,
            &[],
        );
        let tool = ostree_in(
            base,
            &tool_args.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        assert_runs_agree(&port, &tool, &format!("checkout {label}"));
        let port_bytes = std::fs::read(&port_image).unwrap();
        let tool_bytes = std::fs::read(&tool_image).unwrap();
        assert!(!port_bytes.is_empty(), "`{label}` wrote an empty image");
        assert_eq!(
            port_bytes, tool_bytes,
            "`checkout {label}` and the tool wrote different image bytes",
        );
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode(&port_image),
            mode(&tool_image),
            "`checkout {label}` and the tool left the replaced destination at \
             different modes",
        );
        assert_ne!(
            mode(&port_image),
            0o600,
            "`checkout {label}` wrote into the destination instead of \
             replacing it",
        );
        written.push(port_bytes);
    }
    assert_ne!(
        written[0], written[1],
        "the verity image and the no-verity image are the same bytes",
    );
    assert_eq!(
        written[1], written[2],
        "`--composefs --composefs-noverity` did not write the no-verity image",
    );
    assert_eq!(
        written[1], written[3],
        "`--composefs-noverity --composefs` did not write the no-verity image",
    );
}

/// The composefs export refuses a repository outside the backing modes, where
/// the tool exports an image whose redirects name loose paths that repository
/// does not hold. `cli-surface.md`, "P2" records the divergence. The refusal
/// writes no destination and leaves a destination that already exists as it
/// was, byte for byte and at the mode it carried.
#[test]
fn checkout_composefs_refuses_an_archive_repository() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("checkout-composefs-archive");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            BRANCH,
            "-s",
            SUBJECT,
            FIXED_TIMESTAMP,
            "--orphan",
            tree.to_str().unwrap(),
        ],
    );

    for flag in ["--composefs", "--composefs-noverity"] {
        let name = flag.trim_start_matches('-');
        let refuse = |dest: &Path| {
            let port = ostrya_in(
                Some(base),
                &[
                    "checkout",
                    &format!("--repo={}", port_repo.display()),
                    flag,
                    BRANCH,
                    dest.to_str().unwrap(),
                ],
                None,
                &[],
            );
            assert_eq!(port.status.code(), Some(1), "the port took `{flag}`");
            let stderr = String::from_utf8_lossy(&port.stderr).into_owned();
            assert!(
                stderr.contains("composefs export requires a bare-user or bare-user-shared"),
                "the refusal for `{flag}` does not name the mode rule:\n{stderr}",
            );
        };

        // A destination the refusal would have had to create is not created.
        let port_image = base.join(format!("port-{name}.cfs"));
        refuse(&port_image);
        assert!(
            !port_image.exists(),
            "the refusal for `{flag}` left a destination behind",
        );

        // A destination that already exists is left as it was. The export
        // serializes as it builds, so a destination it opened directly would be
        // truncated before the refusal reached it.
        let kept = base.join(format!("kept-{name}.cfs"));
        std::fs::write(&kept, b"a file the export has no claim on").unwrap();
        std::fs::set_permissions(&kept, PermissionsExt::from_mode(0o600)).unwrap();
        refuse(&kept);
        assert_eq!(
            std::fs::read(&kept).unwrap(),
            b"a file the export has no claim on",
            "the refusal for `{flag}` changed a destination that already existed",
        );
        assert_eq!(
            std::fs::metadata(&kept).unwrap().permissions().mode() & 0o777,
            0o600,
            "the refusal for `{flag}` changed the destination's mode",
        );

        let tool_image = base.join(format!("tool-{name}.cfs"));
        let tool = ostree_in(
            base,
            &[
                "checkout",
                &format!("--repo={}", tool_repo.display()),
                flag,
                BRANCH,
                tool_image.to_str().unwrap(),
            ],
        );
        assert_eq!(
            tool.status.code(),
            Some(0),
            "the tool refused `{flag}` against an archive repository",
        );
        assert!(
            !std::fs::read(&tool_image).unwrap().is_empty(),
            "the tool wrote an empty image for `{flag}`",
        );
    }

    // The port exports through a temporary file in the destination's directory.
    // A refusal removes it, so four refusals leave the directory with none.
    let leftover: Vec<_> = std::fs::read_dir(base)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with(".ostrya-composefs-"))
        .collect();
    assert!(
        leftover.is_empty(),
        "the refusals left temporary files behind: {leftover:?}",
    );
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
    if ostree_supports_ed25519() {
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
        eprintln!("skipping: gpg not available");
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
        eprintln!("skipping: gpg not available");
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
    if !ostree_supports_ed25519() {
        eprintln!("skipping: ostree tool has no ed25519 engine");
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

/// Run the `ostree` tool from `cwd`, for the cases where a relative path
/// argument makes the working directory part of the behaviour under test.
fn ostree_in(cwd: &Path, args: &[&str]) -> Run {
    let out = Command::new("ostree")
        .current_dir(cwd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn ostree");
    Run {
        status: out.status,
        stdout: out.stdout,
        stderr: out.stderr,
    }
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
    assert_runs_agree(&port, &tool, &args.join(" "));
}

/// Assert that two finished runs agree on the exit status and both streams.
fn assert_runs_agree(port: &Run, tool: &Run, label: &str) {
    let render = |run: &Run| {
        format!(
            "exit {:?}\nstdout: {:?}\nstderr: {:?}",
            run.status.code(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr),
        )
    };
    assert_eq!(
        render(port),
        render(tool),
        "`ostrya {label}` and `ostree {label}` disagree",
    );
}

/// The same, for a failing invocation whose message both implementations word
/// identically: the exit status, standard output, and the last line of standard
/// error, which is the `error: ` line the usage block precedes.
fn assert_agrees_on_error(port_repo: &Path, tool_repo: &Path, args: &[&str], message: &str) {
    let (port, tool) = run_both(port_repo, tool_repo, args);
    assert_runs_agree_on_error(&port, &tool, &args.join(" "), message);
}

/// Assert that two finished runs both failed and both carry `message`.
fn assert_runs_agree_on_error(port: &Run, tool: &Run, label: &str, message: &str) {
    for (who, run) in [("port", port), ("tool", tool)] {
        assert_eq!(
            run.status.code(),
            Some(1),
            "the {who} did not exit 1 for `{label}`"
        );
        let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
        assert!(
            stderr.contains(message),
            "the {who}'s stderr for `{label}` lacks {message:?}:\n{stderr}"
        );
    }
    assert_eq!(
        String::from_utf8_lossy(&port.stdout),
        String::from_utf8_lossy(&tool.stdout),
        "`{label}` wrote different standard output"
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
        // --force suppresses the already-exists refusal, so a name the existence
        // check resolves reaches the collection-id validation.
        (
            vec!["refs", "-c", "--create=plain", "--force", "plain"],
            "error: Invalid collection ID plain".to_owned(),
        ),
    ] {
        assert_agrees_on_error(&port, &tool, &args, &message);
    }

    // A NEWREF with no `:` that is a collection id carries no ref name. This is
    // the one divergence: the tool prints a GLib assertion line before its own
    // message, and the port prints the message alone
    // (`docs/conformance/cli-surface.md`, "P1"). The two are compared here
    // rather than through `assert_agrees_on_error` because the tool's outcome
    // depends on its build: 2026.1 prints the critical line and exits 1, and
    // 2026.2 leaves the error unset and aborts in `ostree_run` on
    // `assertion failed: (success || error)`. The port's refusal is the same
    // either way, so it is what this states.
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
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        "error: Invalid ref name (null)\n"
    );
    let tool_refused = ostree(&[
        &format!("--repo={}", tool.display()),
        "refs",
        "-c",
        "--create=org.example.Fresh",
        "plain",
    ]);
    match tool_refused.status.code() {
        Some(1) => assert!(
            String::from_utf8_lossy(&tool_refused.stderr)
                .contains("error: Invalid ref name (null)"),
            "the tool exited 1 without its own refusal:\n{}",
            String::from_utf8_lossy(&tool_refused.stderr)
        ),
        None => {}
        other => panic!("the tool neither refused nor died on a signal: {other:?}"),
    }

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
    // The empty refspec is the zero-length case of the tool's
    // abbreviated-checksum scan, and the count that decides it is of commits;
    // the port refuses the name.
    let (refused, searched) = run_both(&port, &tool, &["rev-parse", ""]);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        "error: Invalid refspec \n"
    );
    assert_eq!(searched.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&searched.stderr).contains("error: Refspec  not unique"),
        "the empty refspec no longer matches the four commits this repository holds:\n{}",
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
    // `log` and `ls` resolve a commit too, so the starting revision draws the
    // same pair rather than `log` reading an absent commit as an empty history.
    refused(&repo, &repo, &["log", &absent]);
    refused(&repo, &repo, &["ls", &absent]);

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
            "error: opendir(nosuchdir): No such file or directory\n",
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

    // An empty base, which is the zero-length case of the tool's
    // abbreviated-checksum scan, so over a repository holding no commit it
    // reaches the ref store and names nothing there, and both refuse: the port
    // names the branch as given and the tool the base it split off.
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
        "error: opendir(nosuchdir): No such file or directory\n",
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

// --- show, log, ls, config (Phase 17d) ----------------------------------------

/// The fixture repository read through `show` and `ls`, without the reference
/// tool: the reports the port produces for the commit, its tree, and one file
/// object, held to the text the tool was observed to write for them
/// (`docs/format-reference.md`, "CLI output formats").
#[test]
fn show_and_ls_report_the_fixture() {
    let tmp = TmpDir::new("show-fixture");
    let base = tmp.path();
    let repo = commit_fixture(base);
    let repo_arg = format!("--repo={}", repo.display());

    let ls = ostrya(&[&repo_arg, "ls", "-R", BRANCH], None, &[]);
    assert_eq!(
        ls.ok().stdout_trimmed(),
        "d00755 0 0      0 /\n\
         -00644 0 0      0 /empty.txt\n\
         -00644 0 0     13 /hello.txt\n\
         l00777 0 0      0 /link -> hello.txt\n\
         d00755 0 0      0 /subdir\n\
         -00644 0 0      7 /subdir/nested.txt",
        "the recursive listing"
    );

    let show = ostrya(&[&repo_arg, "show", BRANCH], None, &[]);
    assert_eq!(
        String::from_utf8(show.ok().stdout.clone()).unwrap(),
        format!(
            "commit {COMMIT}\n\
             ContentChecksum:  \
             d79e5560a90877b47660b639e3d7c88c20ca5a7604f867960e155c552025e104\n\
             Date:  2023-11-14 22:13:20 +0000\n\
             \n    {SUBJECT}\n\n"
        ),
        "the commit report"
    );

    // The symlink object's own report, reached by the checksum `ls -C` names.
    let listing = ostrya(&[&repo_arg, "ls", "-C", BRANCH], None, &[]);
    let link_checksum = String::from_utf8(listing.ok().stdout.clone())
        .unwrap()
        .lines()
        .find(|line| line.contains("/link"))
        .and_then(|line| line.split_whitespace().nth(4).map(str::to_owned))
        .expect("a checksum column on the symlink's line");
    let object = ostrya(&[&repo_arg, "show", &link_checksum], None, &[]);
    assert_eq!(
        String::from_utf8(object.ok().stdout.clone()).unwrap(),
        format!(
            "Object: {link_checksum}\n\
             Type: file\n\
             File Type: symlink\n\
             Target: hello.txt\n\
             Mode: 0120777\n\
             Uid: 0\n\
             Gid: 0\n\
             Extended Attributes: {{ @a(ayay) [] }}\n"
        ),
        "the symlink object's report"
    );
}

/// A repository the reference tool builds, holding what the port's own `commit`
/// cannot yet state: a body, an empty subject, a `version` key, metadata of
/// every type the format uses, and recorded sizes. The reading commands are then
/// compared over it, which is also the interop direction that matters -- the
/// port reads what the tool wrote.
#[cfg(unix)]
fn tool_read_fixture(base: &Path) -> PathBuf {
    let repo = base.join("toolrepo");
    let src = base.join("readsrc");
    std::fs::create_dir_all(src.join("nested/deep")).unwrap();
    std::fs::write(src.join("file.txt"), b"hello\n").unwrap();
    std::fs::write(src.join("empty"), b"").unwrap();
    std::fs::write(src.join("exec.sh"), b"#!/bin/sh\necho x\n").unwrap();
    std::os::unix::fs::symlink("file.txt", src.join("link")).unwrap();
    std::fs::write(src.join("nested/a.txt"), b"n\n").unwrap();
    std::fs::write(src.join("nested/deep/inner.bin"), b"deep\n").unwrap();
    std::fs::set_permissions(src.join("exec.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let repo_arg = format!("--repo={}", repo.display());
    ostree(&[&repo_arg, "init", "--mode=archive"]).ok();
    let src_arg = src.display().to_string();
    // A subject and a two-line body, then a second commit onto the same branch
    // so the walk has a parent to follow, with sizes recorded.
    ostree(&[
        &repo_arg,
        "commit",
        "-b",
        BRANCH,
        "-s",
        "first subject",
        "--timestamp=@1700000000",
        &src_arg,
    ])
    .ok();
    std::fs::write(src.join("file.txt"), b"hello\nsecond\n").unwrap();
    ostree(&[
        &repo_arg,
        "commit",
        "-b",
        BRANCH,
        "-s",
        "second subject",
        "-m",
        "a body\nwith two lines",
        "--timestamp=@1700000100",
        "--generate-sizes",
        &src_arg,
    ])
    .ok();
    // A commit with no subject and a body alone, one with a `version` key, one
    // with a multi-line subject, and one carrying metadata of every type.
    ostree(&[
        &repo_arg,
        "commit",
        "-b",
        "nobody",
        "-m",
        "body only line1\nline2",
        "--timestamp=@1700000000",
        &src_arg,
    ])
    .ok();
    ostree(&[
        &repo_arg,
        "commit",
        "-b",
        "versioned",
        "-s",
        "subj",
        "--add-metadata-string=version=1.2.3",
        "--timestamp=@1700000000",
        &src_arg,
    ])
    .ok();
    ostree(&[
        &repo_arg,
        "commit",
        "-b",
        "multiline",
        "-s",
        "line one\nline two",
        "--timestamp=@1700000000",
        &src_arg,
    ])
    .ok();
    ostree(&[
        &repo_arg,
        "commit",
        "-b",
        "typed",
        "--timestamp=@1700000000",
        "--add-metadata=ts=uint64 1234",
        "--add-metadata=n=uint32 7",
        "--add-metadata=by=byte 0x09",
        "--add-metadata=s='hi'",
        "--add-metadata=flag=true",
        "--add-metadata=raw=[byte 0x01, 0x02]",
        "--add-metadata=nulterm=b\"ab\"",
        "--add-metadata=emptyay=@ay []",
        "--add-metadata=nested=[[byte 0x01], @ay []]",
        "--add-metadata=strs=['x','y']",
        "--add-metadata=dict=@a{sv} {}",
        // The nested-maybe chains, whose printed text states its set levels
        // with a `just ` for each of them.
        "--add-metadata=mnothing=@mmi nothing",
        "--add-metadata=mjust=@mmi just nothing",
        "--add-metadata=mjust2=@mmmi just just nothing",
        "--add-metadata=mset=@mmi just 5",
        "--add-metadata=mvar=@mmv just nothing",
        "--add-metadata=marr=@ammi [just nothing, nothing, just just 5]",
        "--add-metadata=mdictv=@a{smmi} {'a': just nothing, 'b': nothing}",
        // The escape tables both printers carry: a string holding the short
        // escapes, one holding the quote in use, one holding characters past
        // ASCII, a bytestring holding an escape and a byte past ASCII, and a
        // byte array that is no bytestring.
        "--add-metadata=esc='a\\tb\\nc\\u001bd\\\\e\"f'",
        "--add-metadata=quoted=\"it's\"",
        "--add-metadata=uni='héllo 中文'",
        "--add-metadata=bstr=b'a\\tb\\377'",
        "--add-metadata=rawbytes=[byte 0x00, 0x01, 0x7f, 0xff]",
        "--add-metadata=zzz='last'",
        "--add-metadata=aaa='first'",
        &src_arg,
    ])
    .ok();
    // A pre-epoch timestamp, whose stored field is the two's-complement form.
    ostree(&[
        &repo_arg,
        "commit",
        "-b",
        "preepoch",
        "-s",
        "pre",
        "--timestamp=@-1",
        &src_arg,
    ])
    .ok();
    repo
}

/// Every `show` form over the tool-built repository, both implementations
/// reading the same objects: the commit report, the raw variant with and without
/// the byte-order conversion, the metadata and detached-metadata modes, the
/// sizes, and the refusals.
#[test]
fn show_forms_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("show-tool");
    let base = tmp.path();
    let repo = tool_read_fixture(base);
    let tip = resolve(&repo, BRANCH).expect("the fixture branch resolves");
    let typed = resolve(&repo, "typed").expect("the typed branch resolves");

    // The tree's own object checksums, read out of the port's `ls -C`.
    let listing = ostrya(
        &[
            &format!("--repo={}", repo.display()),
            "ls",
            "-C",
            "-R",
            BRANCH,
        ],
        None,
        &[],
    );
    let lines: Vec<String> = String::from_utf8(listing.ok().stdout.clone())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    // The path is its own whitespace-delimited column, so a line is found by
    // that column and the checksums read by index: one for a file, the dirtree
    // and then the dirmeta for a directory.
    let column = |path: &str, index: usize| {
        lines
            .iter()
            .find(|line| line.split_whitespace().any(|field| field == path))
            .and_then(|line| line.split_whitespace().nth(index).map(str::to_owned))
            .unwrap_or_else(|| panic!("no listing line for {path}"))
    };
    let root_dirtree = column("/", 4);
    let root_dirmeta = column("/", 5);
    let file_object = column("/file.txt", 4);
    let link_object = column("/link", 4);

    for args in [
        vec!["show", &tip],
        vec!["show", "--raw", &tip],
        vec!["show", "-B", &tip],
        vec!["show", "--raw", "-B", &tip],
        vec!["show", BRANCH],
        vec!["show", "test/main^"],
        vec!["show", "nobody"],
        vec!["show", "versioned"],
        vec!["show", "multiline"],
        vec!["show", "preepoch"],
        vec!["show", "--raw", "preepoch"],
        vec!["show", &root_dirtree],
        vec!["show", "--raw", &root_dirtree],
        vec!["show", &root_dirmeta],
        vec!["show", "--raw", &root_dirmeta],
        vec!["show", "-B", &root_dirmeta],
        vec!["show", &file_object],
        vec!["show", "--raw", &file_object],
        vec!["show", &link_object],
        vec!["show", "--print-sizes", &tip],
        vec!["show", "--print-related", &tip],
        vec!["show", "--list-metadata-keys", &typed],
        vec!["show", "--list-detached-metadata-keys", &tip],
        vec!["show", "--print-detached-metadata-key=any", &tip],
        vec!["show", "--print-metadata-key=nope", &typed],
        vec!["show", "--print-sizes", "nobody"],
        vec!["show", "nosuchref"],
        vec![
            "show",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ],
    ] {
        assert_agrees(&repo, &repo, &args);
    }

    // Every metadata value type, each with and without `--print-hex` and the
    // byte-order conversion.
    for key in [
        "ts",
        "n",
        "by",
        "s",
        "flag",
        "raw",
        "nulterm",
        "emptyay",
        "nested",
        "strs",
        "dict",
        "mnothing",
        "mjust",
        "mjust2",
        "mset",
        "mvar",
        "marr",
        "mdictv",
        "esc",
        "quoted",
        "uni",
        "bstr",
        "rawbytes",
        "ostree.ref-binding",
    ] {
        let arg = format!("--print-metadata-key={key}");
        assert_agrees(&repo, &repo, &["show", &arg, &typed]);
        assert_agrees(&repo, &repo, &["show", "-B", &arg, &typed]);
        assert_agrees(&repo, &repo, &["show", "--print-hex", &arg, &typed]);
    }

    // The precedence among the reporting modes, one pair per observed rule.
    let tip_ref: &str = &tip;
    for args in [
        vec![
            "show",
            "--list-metadata-keys",
            "--print-metadata-key=ostree.ref-binding",
            tip_ref,
        ],
        vec!["show", "--print-sizes", "--raw", tip_ref],
        vec!["show", "--print-sizes", "--list-metadata-keys", tip_ref],
        vec!["show", "--print-related", "--raw", tip_ref],
        vec!["show", "--print-related", "--list-metadata-keys", tip_ref],
        vec!["show", "--print-sizes", "--print-related", tip_ref],
        vec![
            "show",
            "--list-detached-metadata-keys",
            "--print-metadata-key=ostree.ref-binding",
            tip_ref,
        ],
    ] {
        assert_agrees(&repo, &repo, &args);
    }
}

/// `show --print-related` over a commit that carries a non-empty related array.
/// No `commit` option writes one, so the commit is assembled through the library
/// and written into the object store, and both implementations read it back.
#[test]
fn show_print_related_lists_each_pair() {
    let tmp = TmpDir::new("show-related");
    let base = tmp.path();
    let repo_path = commit_fixture(base);
    let source: ostrya::Checksum = COMMIT.parse().unwrap();
    let crafted = block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let (mut commit, _) = repo.load_commit(&source).await.unwrap();
        commit.related = vec![
            ("other/ref".to_owned(), source.as_bytes().to_vec()),
            ("second/ref".to_owned(), source.as_bytes().to_vec()),
        ];
        let bytes = commit.serialize().unwrap();
        let checksum = ostrya::Checksum::sha256(&bytes);
        let hex = checksum.to_hex();
        let dir = repo_path.join("objects").join(&hex[..2]);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{}.commit", &hex[2..])), &bytes).unwrap();
        hex
    });
    let expected = format!("other/ref {COMMIT}\nsecond/ref {COMMIT}\n");
    let run = ostrya(
        &[
            &format!("--repo={}", repo_path.display()),
            "show",
            "--print-related",
            &crafted,
        ],
        None,
        &[],
    );
    assert_eq!(
        String::from_utf8(run.ok().stdout.clone()).unwrap(),
        expected,
        "the related pairs"
    );
    if ostree_available() {
        assert_agrees(
            &repo_path,
            &repo_path,
            &["show", "--print-related", &crafted],
        );
    }
}

/// `log` over the tool-built repository: the walk, the raw form, an ancestry
/// suffix, and the note a parent whose commit object is absent draws.
#[test]
fn log_forms_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("log-tool");
    let base = tmp.path();
    let repo = tool_read_fixture(base);
    let tip = resolve(&repo, BRANCH).expect("the fixture branch resolves");
    let parent = resolve(&repo, "test/main^").expect("the parent resolves");
    for args in [
        vec!["log", BRANCH],
        vec!["log", "--raw", BRANCH],
        vec!["log", "test/main^"],
        vec!["log", &tip],
        vec!["log", "nobody"],
        vec!["log", "preepoch"],
        vec!["log", "nosuchref"],
    ] {
        assert_agrees(&repo, &repo, &args);
    }

    // With the parent's commit object removed, the walk reports what it holds
    // and stops.
    std::fs::remove_file(
        repo.join("objects")
            .join(&parent[..2])
            .join(format!("{}.commit", &parent[2..])),
    )
    .unwrap();
    assert_agrees(&repo, &repo, &["log", BRANCH]);
    assert_agrees(&repo, &repo, &["log", "--raw", BRANCH]);
}

/// `log`'s per-commit report verifies GPG signatures against the repository's
/// own `gpgkeys.gpg`, not the process's working directory. Run with no `cwd`
/// override, so the two differ, the case `log` once broke by passing `.` as
/// the repository path instead of the one `show` receives from `resolve_repo`.
#[cfg(feature = "gpg")]
#[test]
fn log_verifies_signatures_against_the_repo_not_the_cwd() {
    if !gpg_available() {
        eprintln!("skipping: gpg not available");
        return;
    }
    let tmp = TmpDir::new("log-gpg-repo-path");
    let base = tmp.path();
    let repo = commit_fixture(base);
    let repo_s = repo.to_str().unwrap();
    let home = GpgHome::create(base, "Ostrya Log Test <log-gpg@ostrya.example>");
    let fpr = home.fingerprint();
    let home_s = home.dir.to_str().unwrap().to_owned();

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
    home.export_to(&repo.join("gpgkeys.gpg"));

    let log = ostrya(&["log", "--repo", repo_s, COMMIT], None, &[]);
    let stdout = String::from_utf8_lossy(&log.ok().stdout).into_owned();
    assert!(
        stdout.contains("Good signature from"),
        "log did not verify against the repository's own keyring:\n{stdout}"
    );
}

/// `ls` over the tool-built repository, in every option combination and over
/// each path form: the tree root, a nested directory, a file, a symlink, a
/// relative path, and a path naming nothing.
#[test]
fn ls_forms_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("ls-tool");
    let base = tmp.path();
    let repo = tool_read_fixture(base);
    // Two xattrs on one file, so the `-X` column has more than one entry to
    // report and the `a(ayay)` printer's annotation cascade past the first
    // entry runs against the tool rather than only a hand-written value.
    let src = base.join("readsrc");
    let set = std::process::Command::new("setfattr")
        .args(["-n", "user.foo", "-v", "bar"])
        .arg(src.join("file.txt"))
        .status();
    let set2 = std::process::Command::new("setfattr")
        .args(["-n", "user.bar", "-v", "baz"])
        .arg(src.join("file.txt"))
        .status();
    if set.is_ok_and(|status| status.success()) && set2.is_ok_and(|status| status.success()) {
        ostree(&[
            &format!("--repo={}", repo.display()),
            "commit",
            "-b",
            "withxattr",
            "-s",
            "xattr",
            "--timestamp=@1700000000",
            src.to_str().unwrap(),
        ])
        .ok();
        for args in [
            vec!["ls", "-X", "withxattr"],
            vec!["ls", "-C", "-X", "withxattr"],
            vec!["ls", "-X", "-R", "withxattr"],
        ] {
            assert_agrees(&repo, &repo, &args);
        }
    }
    for args in [
        vec!["ls", BRANCH],
        vec!["ls", "-d", BRANCH],
        vec!["ls", "-R", BRANCH],
        vec!["ls", "-C", BRANCH],
        vec!["ls", "-C", "-R", BRANCH],
        vec!["ls", "--nul-filenames-only", BRANCH],
        vec!["ls", "--nul-filenames-only", "-d", BRANCH],
        vec!["ls", "--nul-filenames-only", "-C", BRANCH],
        vec!["ls", "--nul-filenames-only", "-R", BRANCH],
        vec!["ls", BRANCH, "/nested"],
        vec!["ls", BRANCH, "nested"],
        vec!["ls", BRANCH, "/nested/deep"],
        vec!["ls", "-R", BRANCH, "/nested"],
        vec!["ls", "-d", BRANCH, "/nested"],
        vec!["ls", BRANCH, "/file.txt"],
        vec!["ls", BRANCH, "/link"],
        vec!["ls", BRANCH, "/"],
        vec!["ls", BRANCH, ""],
        vec!["ls", BRANCH, "/nope"],
        vec!["ls", BRANCH, "nope"],
        vec!["ls", BRANCH, "/nested", "/file.txt"],
        vec!["ls", "nosuchref"],
    ] {
        assert_agrees(&repo, &repo, &args);
    }
}

/// `ls -R` follows each subdirectory's contents immediately after its own
/// line, even past a sibling directory (`docs/format-reference.md`, "ls",
/// "Order and recursion"). Every fixture elsewhere in this file has at most
/// one subdirectory per level, which cannot tell a level-order listing apart
/// from the tool's pre-order one, so this builds a tree with two.
#[test]
fn ls_recursive_visits_each_subtree_before_its_next_sibling() {
    let tmp = TmpDir::new("ls-siblings");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(src.join("da")).unwrap();
    std::fs::create_dir_all(src.join("db")).unwrap();
    std::fs::write(src.join("da/f1.txt"), b"one\n").unwrap();
    std::fs::write(src.join("db/f2.txt"), b"two\n").unwrap();
    let repo = create_repo(base, RepoMode::Archive);
    let repo_s = repo.to_str().unwrap();
    ostrya(
        &[
            "commit",
            "--repo",
            repo_s,
            "-b",
            "siblings",
            "-s",
            "siblings",
            "--canonical-permissions",
            src.to_str().unwrap(),
        ],
        None,
        &[],
    )
    .ok();
    let ls = ostrya(&["--repo", repo_s, "ls", "-R", "siblings"], None, &[]);
    assert_eq!(
        ls.ok().stdout_trimmed(),
        "d00755 0 0      0 /\n\
         d00755 0 0      0 /da\n\
         -00644 0 0      4 /da/f1.txt\n\
         d00755 0 0      0 /db\n\
         -00644 0 0      4 /db/f2.txt",
        "/da's contents must come before /db's own line"
    );
    if ostree_available() {
        assert_agrees(&repo, &repo, &["ls", "-R", "siblings"]);
    }
}

/// `config get` over each key class the repository config holds, and over the
/// value forms GKeyFile escapes, plus every refusal both implementations word
/// the same way.
#[test]
fn config_get_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("config-tool");
    let base = tmp.path();
    let repo = create_repo(base, RepoMode::Archive);
    let mut config = std::fs::read_to_string(repo.join("config")).unwrap();
    config.push_str(
        "[test]\nplain=value\nescaped=a\\nb\\tc\nspaces= leading and trailing \n\
         semi=a;b;c\nempty=\nquoted=\"quoted\"\nutf8=héllo\nbackslash=a\\\\b\n\
         [a]\nb.c=2\n",
    );
    std::fs::write(repo.join("config"), config).unwrap();
    for args in [
        vec!["config", "get", "core.mode"],
        vec!["config", "get", "core.repo_version"],
        vec!["config", "get", "--group=core", "mode"],
        vec!["config", "get", "test.plain"],
        vec!["config", "get", "test.escaped"],
        vec!["config", "get", "test.spaces"],
        vec!["config", "get", "test.semi"],
        vec!["config", "get", "test.empty"],
        vec!["config", "get", "test.quoted"],
        vec!["config", "get", "test.utf8"],
        vec!["config", "get", "test.backslash"],
        vec!["config", "get", "a.b.c"],
        vec!["config", "get", "--group=test", "plain"],
        vec!["config", "get", "core.nope"],
        vec!["config", "get", "nope.mode"],
        vec!["config", "get", "mode"],
        vec!["config", "get"],
        vec!["config", "get", "--group=core"],
        vec!["config", "get", "--group=core", "core.mode"],
        vec!["config", "badop", "core.mode"],
    ] {
        assert_agrees(&repo, &repo, &args);
    }
}

/// Two repositories of one mode, one per implementation, for a cell whose
/// invocation writes: each side acts on its own repository and the two `config`
/// files are then compared.
fn create_repo_pair(base: &Path, mode: RepoMode) -> (PathBuf, PathBuf) {
    let port = base.join("port");
    let tool = base.join("tool");
    std::fs::create_dir_all(&port).unwrap();
    std::fs::create_dir_all(&tool).unwrap();
    (create_repo(&port, mode), create_repo(&tool, mode))
}

/// The `config` bytes of a repository, as text.
fn config_text(repo: &Path) -> String {
    std::fs::read_to_string(repo.join("config")).unwrap()
}

/// Run `args` against each side's own repository, assert the two agree on the
/// exit status and both streams, and assert their `config` files hold the same
/// bytes afterwards.
fn assert_config_agrees(port_repo: &Path, tool_repo: &Path, args: &[&str]) {
    assert_agrees(port_repo, tool_repo, args);
    assert_eq!(
        config_text(port_repo),
        config_text(tool_repo),
        "`{}` left different config bytes",
        args.join(" ")
    );
}

/// Run one `remote` invocation against each side's own repository with a
/// leading `--repo=PATH`.
///
/// `remote` itself takes no `--repo` in the tool -- its nested subcommands do,
/// and the leading position reaches both -- so the shared trailing-`--repo`
/// runner cannot serve this family.
fn run_remote_both(
    port_repo: &Path,
    tool_repo: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (Run, Run) {
    let with_repo = |repo: &Path| {
        let mut all = vec![format!("--repo={}", repo.display())];
        all.extend(args.iter().map(|arg| (*arg).to_owned()));
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

/// Run one `remote` invocation on both sides, assert the two agree, and assert
/// the two `config` files still hold the same bytes.
fn assert_remote_config_agrees(port_repo: &Path, tool_repo: &Path, args: &[&str]) {
    let (port, tool) = run_remote_both(port_repo, tool_repo, args, &[]);
    assert_runs_agree(&port, &tool, &args.join(" "));
    assert_eq!(
        config_text(port_repo),
        config_text(tool_repo),
        "`{}` left different config bytes",
        args.join(" ")
    );
}

/// The same for a `remote` invocation each implementation precedes with its own
/// usage text.
fn assert_remote_config_agrees_on_error(
    port_repo: &Path,
    tool_repo: &Path,
    args: &[&str],
    message: &str,
) {
    let (port, tool) = run_remote_both(port_repo, tool_repo, args, &[]);
    assert_runs_agree_on_error(&port, &tool, &args.join(" "), message);
    assert_eq!(
        config_text(port_repo),
        config_text(tool_repo),
        "`{}` left different config bytes",
        args.join(" ")
    );
}

/// The same for an invocation each implementation precedes with its own usage
/// text: the exit status, standard output, and the `error: ` line are compared,
/// and the two `config` files must still hold the same bytes.
fn assert_config_agrees_on_error(port_repo: &Path, tool_repo: &Path, args: &[&str], message: &str) {
    assert_agrees_on_error(port_repo, tool_repo, args, message);
    assert_eq!(
        config_text(port_repo),
        config_text(tool_repo),
        "`{}` left different config bytes",
        args.join(" ")
    );
}

/// `config set` and `config unset` write the document the way the tool writes
/// it: the same bytes, the same refusals, and a value that reads back whole.
#[test]
fn config_set_and_unset_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("config-write");
    let (port, tool) = create_repo_pair(tmp.path(), RepoMode::Archive);
    for args in [
        // A new key joins its group at the end; a new group follows a blank line.
        vec!["config", "set", "core.newkey", "somevalue"],
        vec!["config", "set", "newgroup.k", "v"],
        vec!["config", "set", "--group=core", "k2", "v2"],
        // An existing key keeps its position.
        vec!["config", "set", "core.newkey", "second"],
        // The escaping a value carries on write, and reading it back.
        vec!["config", "set", "core.list", "a;b;c"],
        vec!["config", "set", "core.lead", "   ab"],
        vec!["config", "set", "core.nl", "a\nb"],
        vec!["config", "get", "core.nl"],
        vec!["config", "get", "core.lead"],
        // A quoted group name reached through the `section.key` form.
        vec![
            "config",
            "set",
            "remote \"x\".url",
            "https://example.invalid/r",
        ],
        vec!["config", "get", "remote \"x\".url"],
        // Removing a key leaves its group's header behind.
        vec!["config", "set", "g.k", "v"],
        vec!["config", "unset", "g.k"],
        // A key and a group the document does not hold are both success.
        vec!["config", "unset", "core.absent"],
        vec!["config", "unset", "nogroup.k"],
        // The refusals, each worded the same way on both sides.
        vec!["config", "set", "core.k"],
        vec!["config", "set"],
        vec!["config", "unset"],
        vec!["config", "set", "--group=core"],
        vec!["config", "unset", "--group=core"],
        vec!["config", "set", "nodot", "v"],
        vec!["config", "unset", "nodot"],
    ] {
        assert_config_agrees(&port, &tool, &args);
    }
    // The operand-count refusal comes with each implementation's own usage text.
    for args in [
        vec!["config", "set", "core.k", "v", "extra"],
        vec!["config", "unset", "core.k", "extra"],
    ] {
        assert_config_agrees_on_error(&port, &tool, &args, "error: Too many arguments given");
    }
    // The document the port rewrote reparses in the tool.
    let read_back = ostree(&[
        "config",
        "--repo",
        port.to_str().unwrap(),
        "get",
        "core.newkey",
    ]);
    assert_eq!(read_back.ok().stdout_trimmed(), "second");
}

/// `remote add` and `remote delete` write the same configuration the tool
/// writes, and the two agree on every refusal. The one divergence is the blank
/// line a deleted group leaves behind in the tool's file.
#[test]
fn remote_add_and_delete_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("remote-write");
    let base = tmp.path();
    let (port, tool) = create_repo_pair(base, RepoMode::Archive);
    for args in [
        // The key order, one option at a time and all at once.
        vec!["remote", "add", "origin", "https://example.invalid/repo"],
        vec![
            "remote",
            "add",
            "branched",
            "https://example.invalid/repo",
            "main",
            "other/branch",
        ],
        vec![
            "remote",
            "add",
            "opts",
            "https://example.invalid/r",
            "--no-gpg-verify",
            "--contenturl=https://example.invalid/c",
            "--collection-id=org.example.C",
            "--custom-backend=flatpak",
            "--set=tls-permissive=true",
            "--set=zzz=1",
        ],
        // `--no-sign-verify` turns the GPG check off as well.
        vec![
            "remote",
            "add",
            "unsigned",
            "https://example.invalid/r",
            "--no-sign-verify",
        ],
        // A sign-api key, inline and from a file.
        vec![
            "remote",
            "add",
            "inline",
            "https://example.invalid/r",
            "--sign-verify=ed25519=inline:AAAA",
        ],
        vec![
            "remote",
            "add",
            "fromfile",
            "https://example.invalid/r",
            "--sign-verify=ed25519=file:/etc/keys.ed25519",
        ],
        // A metalink URL becomes its own key; a mirrorlist one stays in `url`.
        vec![
            "remote",
            "add",
            "meta",
            "metalink=https://example.invalid/m",
        ],
        vec![
            "remote",
            "add",
            "mirrors",
            "mirrorlist=https://example.invalid/ml",
        ],
        // The existence rules.
        vec!["remote", "add", "origin", "https://other.invalid/r"],
        vec![
            "remote",
            "add",
            "origin",
            "https://other.invalid/r",
            "--if-not-exists",
        ],
        vec![
            "remote",
            "add",
            "origin",
            "https://other.invalid/r",
            "--force",
        ],
        // The name rule: `_` is a name, and `.`, a space, and a slash are not.
        vec!["remote", "add", "_", "https://example.invalid/r"],
        vec!["remote", "add", ".", "https://example.invalid/r"],
        vec!["remote", "add", "we ird", "https://example.invalid/r"],
        vec!["remote", "add", "a/b", "https://example.invalid/r"],
        // The option refusals that carry no usage text.
        vec![
            "remote",
            "add",
            "bad",
            "https://example.invalid/r",
            "--set=novalue",
        ],
        vec![
            "remote",
            "add",
            "bad",
            "https://example.invalid/r",
            "--sign-verify=bogus",
        ],
        // Listing, and the URL of one remote. `list -u` refuses the metalink
        // remote, after the names before it are printed.
        vec!["remote", "list"],
        vec!["remote", "list", "-u"],
        vec!["remote", "show-url", "origin"],
        vec!["remote", "show-url", "absent"],
        vec!["remote", "delete", "absent"],
        vec!["remote", "delete", "absent", "--if-exists"],
        vec!["remote", "delete", "a/b"],
    ] {
        assert_remote_config_agrees(&port, &tool, &args);
    }
    // The refusals each implementation precedes with its own usage text.
    for (args, message) in [
        (
            vec!["remote", "add"],
            "error: NAME and URL must be specified",
        ),
        (
            vec!["remote", "add", "onlyname"],
            "error: NAME and URL must be specified",
        ),
        (
            vec![
                "remote",
                "add",
                "origin",
                "https://other.invalid/r",
                "--if-not-exists",
                "--force",
            ],
            "error: Can only specify one of --if-not-exists and --force",
        ),
        (vec!["remote", "delete"], "error: NAME must be specified"),
        (vec!["remote", "show-url"], "error: NAME must be specified"),
    ] {
        assert_remote_config_agrees_on_error(&port, &tool, &args, message);
    }

    // Either implementation lists the remotes out of the other's file.
    let cross = |repo: &Path| {
        let repo_arg = format!("--repo={}", repo.display());
        let port = ostrya(&[&repo_arg, "remote", "list", "-u"], None, &[]);
        let tool = ostree(&[&repo_arg, "remote", "list", "-u"]);
        assert_runs_agree(&port, &tool, "remote list -u");
    };
    cross(&port);
    cross(&tool);

    // A section removed from the middle of the document leaves both files
    // identical.
    for args in [
        vec!["remote", "delete", "meta"],
        vec!["remote", "delete", "origin"],
    ] {
        assert_remote_config_agrees(&port, &tool, &args);
    }
    assert!(
        !config_text(&port).contains("[remote \"origin\"]"),
        "the port's config still holds the deleted section:\n{}",
        config_text(&port)
    );

    // Removing the last section is where the two files part: the tool keeps the
    // blank line that separated it and the port keeps none. Both documents
    // reparse to the same configuration, which the tool reading the port's own
    // file states.
    for name in [
        "branched", "opts", "unsigned", "inline", "fromfile", "mirrors", "_",
    ] {
        let args = vec!["remote", "delete", name];
        let (port_run, tool_run) = run_remote_both(&port, &tool, &args, &[]);
        assert_runs_agree(&port_run, &tool_run, &args.join(" "));
    }
    assert_eq!(
        config_text(&tool),
        format!("{}\n", config_text(&port)),
        "the two files must differ only in the trailing blank line"
    );
    let listed = ostree(&[&format!("--repo={}", port.display()), "remote", "list"]);
    let tool_listed = ostree(&[&format!("--repo={}", tool.display()), "remote", "list"]);
    assert_eq!(
        listed.ok().stdout_trimmed(),
        tool_listed.ok().stdout_trimmed(),
        "the tool must read the same remotes out of either file"
    );
}

/// `remote refs` and `remote summary` read a live remote over HTTP: the ref
/// listing, the report, the raw variant, and the metadata forms.
#[test]
fn remote_refs_and_summary_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("remote-live");
    let base = tmp.path();
    let remote = build_remote(base, "remote");
    let server = FileServer::start(&remote);
    let (port, tool) = create_repo_pair(base, RepoMode::Archive);
    for repo in [&port, &tool] {
        configure_remote(repo, &server.url(), "gpg-verify=false\n");
    }
    // The summary's `last-modified` is the remote's own, so both sides read one
    // value; `TZ` fixes the zone the tool renders it in, which the port renders
    // in UTC whatever the zone.
    let env = &[("TZ", "UTC")];
    for args in [
        vec!["remote", "refs", "origin"],
        vec!["remote", "refs", "origin", "-r"],
        vec!["remote", "refs", "origin", "--revision"],
        vec!["remote", "summary", "origin"],
        vec!["remote", "summary", "origin", "--raw"],
        vec!["remote", "summary", "origin", "--list-metadata-keys"],
        vec![
            "remote",
            "summary",
            "origin",
            "--print-metadata-key=ostree.summary.mode",
        ],
        vec![
            "remote",
            "summary",
            "origin",
            "--print-metadata-key=ostree.summary.last-modified",
        ],
        vec![
            "remote",
            "summary",
            "origin",
            "--print-metadata-key=ostree.summary.tombstone-commits",
        ],
        vec!["remote", "summary", "origin", "--print-metadata-key=absent"],
        vec!["remote", "refs", "absent"],
        vec!["remote", "summary", "absent"],
    ] {
        let (port_run, tool_run) = run_remote_both(&port, &tool, &args, env);
        assert_runs_agree(&port_run, &tool_run, &args.join(" "));
    }
    // The missing-operand refusal comes with each implementation's own usage.
    for args in [vec!["remote", "refs"], vec!["remote", "summary"]] {
        let (port_run, tool_run) = run_remote_both(&port, &tool, &args, env);
        assert_runs_agree_on_error(
            &port_run,
            &tool_run,
            &args.join(" "),
            "error: NAME must be specified",
        );
    }

    // A remote publishing no summary is refused in each subcommand's own words.
    let bare = build_dest(base, "bare-remote");
    let bare_server = FileServer::start(&bare);
    for repo in [&port, &tool] {
        let config = repo.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(&format!(
            "\n[remote \"nosummary\"]\nurl={}\ngpg-verify=false\n",
            bare_server.url()
        ));
        std::fs::write(&config, text).unwrap();
    }
    for args in [
        vec!["remote", "refs", "nosummary"],
        vec!["remote", "summary", "nosummary"],
    ] {
        let (port_run, tool_run) = run_remote_both(&port, &tool, &args, env);
        assert_runs_agree(&port_run, &tool_run, &args.join(" "));
    }
}

/// `remote gpg-import` writes a keyring the tool reads and reads one the tool
/// wrote, counts what it added the way the tool counts it, and the key it
/// imports verifies a commit signed with that key. `gpg-list-keys` reports the
/// keys either implementation imported.
#[cfg(feature = "gpg")]
#[test]
fn remote_gpg_keyring_round_trips_with_the_tool() {
    if !ostree_available() || !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("remote-gpg");
    let base = tmp.path();
    let home = GpgHome::create(base, "Ostrya Remote <remote-gpg@ostrya.example>");
    let fpr = home.fingerprint();
    let public = base.join("public.gpg");
    home.export_to(&public);
    let public_s = public.to_str().unwrap();
    let keyring_arg = format!("--keyring={public_s}");

    let (port, tool) = create_repo_pair(base, RepoMode::Archive);
    for repo in [&port, &tool] {
        configure_remote(repo, "https://example.invalid/r", "");
    }
    // The import reports the same count on both sides, a repeated import adds
    // nothing, and a `KEY-ID` selection takes the one key it names.
    for args in [
        vec!["remote", "gpg-import", "origin", &keyring_arg],
        vec!["remote", "gpg-import", "origin", &keyring_arg],
        vec!["remote", "gpg-import", "origin", &keyring_arg, &fpr],
        vec!["remote", "gpg-import", "absent", &keyring_arg],
        vec!["remote", "gpg-import", "origin", "--keyring=/nonexistent"],
    ] {
        let (port_run, tool_run) = run_remote_both(&port, &tool, &args, &[]);
        assert_runs_agree(&port_run, &tool_run, &args.join(" "));
    }
    // Naming both key sources is refused ahead of the usage text in both.
    let both_sources = vec!["remote", "gpg-import", "origin", &keyring_arg, "--stdin"];
    let (port_run, tool_run) = run_remote_both(&port, &tool, &both_sources, &[]);
    assert_runs_agree_on_error(
        &port_run,
        &tool_run,
        "remote gpg-import --keyring --stdin",
        "error: --keyring and --stdin are mutually exclusive",
    );

    // Each implementation reads the keyring the other wrote. The listing itself
    // parts on two lines the port does not produce (`cli-surface.md`, "P3"), so
    // the claim is the fingerprint and the user id.
    for repo in [&port, &tool] {
        let repo_arg = format!("--repo={}", repo.display());
        let listing = ostrya(&[&repo_arg, "remote", "gpg-list-keys", "origin"], None, &[]);
        let text = listing.ok().stdout_trimmed();
        assert!(
            text.contains(&format!("Key: {fpr}")) && text.contains("  UID: Ostrya Remote"),
            "the port's listing of {repo:?} lacks the imported key:\n{text}"
        );
        let tool_listing = ostree(&[&repo_arg, "remote", "gpg-list-keys", "origin"]);
        let tool_text = tool_listing.ok().stdout_trimmed();
        assert!(
            tool_text.contains(&format!("Key: {fpr}")),
            "the tool's listing of {repo:?} lacks the imported key:\n{tool_text}"
        );
    }

    // The imported key verifies a commit the tool signed with it, through the
    // remote the keyring belongs to.
    let signed = commit_fixture(base);
    let signed_s = signed.to_str().unwrap();
    configure_remote(&signed, "https://example.invalid/r", "");
    ostree(&[
        "gpg-sign",
        "--repo",
        signed_s,
        "--gpg-homedir",
        home.dir.to_str().unwrap(),
        COMMIT,
        &fpr,
    ])
    .ok();
    ostrya(
        &[
            &format!("--repo={signed_s}"),
            "remote",
            "gpg-import",
            "origin",
            &keyring_arg,
        ],
        None,
        &[],
    )
    .ok();
    let verified = ostrya(
        &[
            "sign", "--verify", "--repo", signed_s, "-s", "gpg", "--remote", "origin", COMMIT,
        ],
        None,
        &[],
    );
    assert!(
        verified.ok().stdout_trimmed().contains("verification OK"),
        "the imported keyring must verify the commit it signed"
    );

    // Deleting the remote takes its keyring with it, in both.
    for repo in [&port, &tool] {
        assert!(repo.join("origin.trustedkeys.gpg").exists());
    }
    let (port_run, tool_run) = run_remote_both(&port, &tool, &["remote", "delete", "origin"], &[]);
    assert_runs_agree(&port_run, &tool_run, "remote delete origin");
    for repo in [&port, &tool] {
        assert!(
            !repo.join("origin.trustedkeys.gpg").exists(),
            "{repo:?} kept the deleted remote's keyring"
        );
    }
}

/// A re-export stating a later key expiry reaches a remote's trusted keyring
/// in both implementations: the count stays at zero, the key that had expired
/// verifies the commit again, and each implementation reads the keyring the
/// other wrote.
///
/// The key was created with a lifetime of one day and signed the commit while
/// it was live. The keyring the first import writes therefore states an expiry
/// that has passed, and both implementations refuse the signature over it. The
/// bytes the second import writes part: the port writes the offered certificate
/// where the held one stood and the tool merges the offered packets into it
/// (`cli-surface.md`, "P3").
#[cfg(feature = "gpg")]
#[test]
fn remote_gpg_import_carries_a_key_expiry_extension() {
    if !ostree_available() || !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("remote-gpg-expiry");
    let base = tmp.path();
    let home = GpgHome::expiring(base, "Renew <renew@ostrya.example>", "1d");
    let fpr = home.fingerprint();
    let expiring = base.join("expiring.gpg");
    home.export_to(&expiring);
    let expiring_arg = format!("--keyring={}", expiring.display());

    // One repository per implementation, each holding the same commit, signed
    // with that key and read through the remote the keyring belongs to.
    build_fixture_source(base);
    let src = base.join("src");
    let mut repos = Vec::new();
    for name in ["port", "tool"] {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = create_repo(&dir, RepoMode::Archive);
        let repo_s = repo.to_str().unwrap().to_owned();
        ostrya(
            &[
                "commit",
                "--repo",
                &repo_s,
                "-b",
                BRANCH,
                "-s",
                SUBJECT,
                "--canonical-permissions",
                src.to_str().unwrap(),
            ],
            None,
            &[("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)],
        )
        .ok();
        configure_remote(&repo, "https://example.invalid/r", "");
        ostree(&[
            "gpg-sign",
            "--repo",
            &repo_s,
            "--gpg-homedir",
            home.dir.to_str().unwrap(),
            COMMIT,
            &fpr,
        ])
        .ok();
        repos.push(repo);
    }
    let (port, tool) = (repos[0].clone(), repos[1].clone());

    // The keyring stating the expiry that has passed. Both implementations
    // count the key and then refuse the signature it made.
    let args = ["remote", "gpg-import", "origin", &expiring_arg];
    let (port_run, tool_run) = run_remote_both(&port, &tool, &args, &[]);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, the first import");
    let show = ["show", "--gpg-verify-remote=origin", BRANCH];
    let (port_run, tool_run) = run_remote_both(&port, &tool, &show, &[]);
    for (label, run) in [("the port", &port_run), ("the tool", &tool_run)] {
        let text = run.ok().stdout_trimmed();
        assert!(
            text.contains("BAD signature from") && !text.contains("Good signature from"),
            "{label} accepted a signature by an expired key:\n{text}"
        );
    }

    // The re-export stating ten years. Both count no key and both then report
    // a good signature.
    home.set_expire_at("20250102T000000!", "10y");
    let extended = base.join("extended.gpg");
    home.export_to(&extended);
    let extended_arg = format!("--keyring={}", extended.display());
    let args = ["remote", "gpg-import", "origin", &extended_arg];
    let (port_run, tool_run) = run_remote_both(&port, &tool, &args, &[]);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, the extension");
    assert!(
        port_run
            .ok()
            .stdout_trimmed()
            .contains("Imported 0 GPG keys"),
        "the extension must count no key"
    );
    let (port_run, tool_run) = run_remote_both(&port, &tool, &show, &[]);
    for (label, run) in [("the port", &port_run), ("the tool", &tool_run)] {
        let text = run.ok().stdout_trimmed();
        assert!(
            text.contains("Good signature from"),
            "{label} refused a signature by a key whose expiry was extended:\n{text}"
        );
    }

    // The bytes part. The port's keyring is the offered export, and the tool's
    // merge keeps the packets the earlier export carried and its own Trust
    // packets, so its file is the longer one.
    let name = "origin.trustedkeys.gpg";
    let port_ring = std::fs::read(port.join(name)).unwrap();
    let tool_ring = std::fs::read(tool.join(name)).unwrap();
    assert_eq!(port_ring, std::fs::read(&extended).unwrap());
    assert!(
        tool_ring.len() > port_ring.len(),
        "the tool's merged keyring must carry more than the offered export"
    );

    // Each implementation reads the keyring the other wrote and reports a good
    // signature over it.
    std::fs::write(port.join(name), &tool_ring).unwrap();
    std::fs::write(tool.join(name), &port_ring).unwrap();
    let (port_run, tool_run) = run_remote_both(&port, &tool, &show, &[]);
    for (label, run) in [("the port", &port_run), ("the tool", &tool_run)] {
        let text = run.ok().stdout_trimmed();
        assert!(
            text.contains("Good signature from"),
            "{label} refused the keyring the other implementation wrote:\n{text}"
        );
    }
}

/// A re-export carrying a key revocation a designated revoker made reaches a
/// remote's trusted keyring in both implementations, where the keyring under
/// edit or the offered stream states the revoker: each implementation then
/// refuses the signature the revoked key made.
///
/// Two states, measured against `ostree` 2026.1 and `gpg` 2.4.9
/// (`docs/conformance/cli-surface.md`, "P3"):
///
/// - H, the keyring holds the signing key K and the revoker R and the offered
///   stream carries the re-export of K. Both count no key and both then refuse
///   the signature;
/// - J, the keyring holds K alone and the offered stream carries the re-export
///   of K together with R's certificate. Both count one key, R, and both then
///   refuse the signature. With the selector naming K alone, R is not written,
///   both count no key, and both then report a good signature, since no key in
///   the keyring resolves the revoker.
///
/// The two verdict lines part in their wording, which "P1" of
/// `cli-surface.md` records: the port reports `BAD signature from` and the tool
/// `Key revoked`. The bytes part as the two carry the revocation in: the port
/// writes the offered certificate where the held one stood and the tool merges
/// the offered packets into it (`cli-surface.md`, "P3").
#[cfg(feature = "gpg")]
#[test]
fn remote_gpg_import_carries_a_designated_revokers_revocation() {
    if !ostree_available() || !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("remote-gpg-desig-revoke");
    let base = tmp.path();
    let state = RevokedKey::build(base);

    // State H. The keyring the seed import writes holds K and R.
    let (port, tool) = state.repositories(base, "h");
    let (port_run, tool_run) = state.import(&port, &tool, &state.pair);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, K and R");
    state.assert_good(&port, &tool);
    let (port_run, tool_run) = state.import(&port, &tool, &state.revoked);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, the revocation");
    assert!(
        port_run
            .ok()
            .stdout_trimmed()
            .contains("Imported 0 GPG keys"),
        "the revocation must count no key"
    );
    state.assert_revoked(&port, &tool);

    // State J. The keyring holds K alone, and the offered stream states R.
    let (port, tool) = state.repositories(base, "j");
    let (port_run, tool_run) = state.import(&port, &tool, &state.designating);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, K alone");
    state.assert_good(&port, &tool);
    let (port_run, tool_run) = state.import(&port, &tool, &state.revoked_pair);
    assert_runs_agree(
        &port_run,
        &tool_run,
        "remote gpg-import, the revocation and R",
    );
    assert!(
        port_run
            .ok()
            .stdout_trimmed()
            .contains("Imported 1 GPG key"),
        "the revoker must count as the one key added"
    );
    state.assert_revoked(&port, &tool);

    // The same offered stream with the selector naming K alone. R is not
    // written, so the keyring states a revocation no key in it resolves.
    let (port, tool) = state.repositories(base, "j2");
    let (port_run, tool_run) = state.import(&port, &tool, &state.designating);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, K alone");
    let keyring = format!("--keyring={}", state.revoked_pair.display());
    let args = ["remote", "gpg-import", "origin", &keyring, &state.key];
    let (port_run, tool_run) = run_remote_both(&port, &tool, &args, &[]);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, K selected");
    assert!(
        port_run
            .ok()
            .stdout_trimmed()
            .contains("Imported 0 GPG keys"),
        "the selected key must count as one the keyring held"
    );
    for repo in [&port, &tool] {
        assert_eq!(
            state.keys_in(repo).len(),
            1,
            "{repo:?} wrote a key the selector did not name"
        );
    }
    state.assert_good(&port, &tool);
}

/// The two states where the revocation reaches the tool's keyring and not the
/// port's, so the revoked key keeps speaking for the port's remote.
///
/// The port's import is a function of the two byte streams it is given and
/// writes no revocation it cannot verify. The tool merges the offered packets
/// into its keyblock whether or not it can verify them, so a revoker that
/// arrives by another route makes the merged packet speak. Measured against
/// `ostree` 2026.1 and `gpg` 2.4.9
/// (`docs/conformance/cli-surface.md`, "P3"):
///
/// - I, R's certificate stands in the global trusted directory and the
///   remote's keyring holds K alone. The port writes nothing and the tool
///   merges the revocation, and both report a good signature, since neither
///   resolves a revoker across the boundary between two keyring sources;
/// - K, R is absent everywhere when the re-export is offered and is imported
///   after. The port writes nothing for the re-export, so R's later arrival
///   revokes nothing, and the port reports a good signature where the tool
///   reports `Key revoked`.
///
/// `cli-surface.md`, "P3", records both, and `docs/port-plan.md`,
/// "Phase 13d", states the rule they follow from.
#[cfg(feature = "gpg")]
#[test]
fn remote_gpg_import_leaves_an_unverifiable_revocation_out() {
    if !ostree_available() || !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("remote-gpg-desig-unreached");
    let base = tmp.path();
    let state = RevokedKey::build(base);
    let global = base.join("global");
    std::fs::create_dir_all(&global).unwrap();
    std::fs::copy(&state.revoker, global.join("r.gpg")).unwrap();
    let env = [("OSTREE_GPG_HOME", global.to_str().unwrap())];

    // State I. The import reads the two streams alone, so R in the global
    // trusted directory reaches neither implementation's import.
    let (port, tool) = state.repositories(base, "i");
    let (port_run, tool_run) = state.import(&port, &tool, &state.designating);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, K alone");
    let keyring = format!("--keyring={}", state.revoked.display());
    let args = ["remote", "gpg-import", "origin", &keyring];
    let (port_run, tool_run) = run_remote_both(&port, &tool, &args, &env);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, the revocation");
    // The bytes part: the port's keyring is the one it held and the tool's
    // carries the merged revocation.
    let name = "origin.trustedkeys.gpg";
    let held = std::fs::read(&state.designating).unwrap();
    assert_eq!(std::fs::read(port.join(name)).unwrap(), held);
    assert!(std::fs::read(tool.join(name)).unwrap().len() > held.len());
    // The verdict agrees, for reasons that part: the port's keyring states no
    // revocation, and the tool holds one and passes it over.
    for (label, repo, is_port) in [("the port", &port, true), ("the tool", &tool, false)] {
        let text = state.show(repo, is_port, &env);
        assert!(
            text.contains("Good signature from"),
            "{label} resolved a revoker out of the global trusted directory:\n{text}"
        );
    }

    // Over the keyring the tool's own import wrote, the two verdicts part and
    // the port is the stricter one: the port's verify path resolves a revoker
    // among every certificate it loads, whichever source carried it, and the
    // tool resolves none standing in another keyring source.
    let merged = std::fs::read(tool.join(name)).unwrap();
    std::fs::write(port.join(name), &merged).unwrap();
    let port_text = state.show(&port, true, &env);
    assert!(
        port_text.contains("BAD signature from"),
        "the port passed over a revocation its own keyring states:\n{port_text}"
    );
    let tool_text = state.show(&tool, false, &env);
    assert!(
        tool_text.contains("Good signature from"),
        "the tool resolved a revoker out of the global trusted directory:\n{tool_text}"
    );

    // State K. The re-export is offered with R absent everywhere, and R is
    // imported after. The tool's merged packet then speaks and the port has
    // written none.
    let (port, tool) = state.repositories(base, "k");
    let (port_run, tool_run) = state.import(&port, &tool, &state.designating);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, K alone");
    let (port_run, tool_run) = state.import(&port, &tool, &state.revoked);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, the revocation");
    let (port_run, tool_run) = state.import(&port, &tool, &state.revoker);
    assert_runs_agree(&port_run, &tool_run, "remote gpg-import, R after the fact");
    let port_text = state.show(&port, true, &[]);
    assert!(
        port_text.contains("Good signature from"),
        "the port refused a revocation it never wrote:\n{port_text}"
    );
    let tool_text = state.show(&tool, false, &[]);
    assert!(
        tool_text.contains("Key revoked"),
        "the tool accepted a revocation it merged:\n{tool_text}"
    );
}

/// A signing key K that designates a revoker R, and the certificate streams a
/// revocation R made over K is stated over. Each stream is a file, since an
/// import names one with `--keyring`.
#[cfg(feature = "gpg")]
struct RevokedKey {
    /// The home holding both secret keys, which signs each commit.
    home: GpgHome,
    /// K's primary key fingerprint, uppercase hex.
    key: String,
    /// K carrying the designation and no revocation.
    designating: PathBuf,
    /// R's certificate.
    revoker: PathBuf,
    /// The two of them, in that order.
    pair: PathBuf,
    /// The re-export of K carrying the revocation R made.
    revoked: PathBuf,
    /// That re-export and R's certificate, in that order.
    revoked_pair: PathBuf,
}

#[cfg(feature = "gpg")]
impl RevokedKey {
    /// Build the keys and the streams under `base`. The home keeps signing
    /// with K, since the revocation is merged in a home of its own (see
    /// [`merged_export`]).
    fn build(base: &Path) -> RevokedKey {
        let home = GpgHome::create(base, "Signing K <k@ostrya.example>");
        home.add_key("Revoker R <r@ostrya.example>");
        let key = home.fingerprint_of("k@ostrya.example");
        let revoker_key = home.fingerprint_of("r@ostrya.example");
        home.add_revoker(&key, &revoker_key);
        let designating = base.join("k-designating.gpg");
        home.export_one_to(&key, &designating);
        let revoker = base.join("r.gpg");
        home.export_one_to(&revoker_key, &revoker);
        let pair = base.join("k-and-r.gpg");
        Self::concat(&pair, &[&designating, &revoker]);
        let revocation = base.join("rev-by-r.asc");
        home.desig_revoke(&key, &revocation);
        let revoked = base.join("k-revoked.gpg");
        merged_export(
            &base.join("merge-home"),
            &key,
            &[&designating, &revocation],
            &revoked,
        );
        let revoked_pair = base.join("k-revoked-and-r.gpg");
        Self::concat(&revoked_pair, &[&revoked, &revoker]);
        build_fixture_source(base);
        RevokedKey {
            home,
            key,
            designating,
            revoker,
            pair,
            revoked,
            revoked_pair,
        }
    }

    /// One repository per implementation under `base/<tag>-<name>`, each
    /// holding the same commit signed with K and the remote `origin`.
    fn repositories(&self, base: &Path, tag: &str) -> (PathBuf, PathBuf) {
        let src = base.join("src");
        let mut repos = Vec::new();
        for name in ["port", "tool"] {
            let dir = base.join(format!("{tag}-{name}"));
            std::fs::create_dir_all(&dir).unwrap();
            let repo = create_repo(&dir, RepoMode::Archive);
            let repo_s = repo.to_str().unwrap().to_owned();
            ostrya(
                &[
                    "commit",
                    "--repo",
                    &repo_s,
                    "-b",
                    BRANCH,
                    "-s",
                    SUBJECT,
                    "--canonical-permissions",
                    src.to_str().unwrap(),
                ],
                None,
                &[("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)],
            )
            .ok();
            configure_remote(&repo, "https://example.invalid/r", "");
            ostree(&[
                "gpg-sign",
                "--repo",
                &repo_s,
                "--gpg-homedir",
                self.home.dir.to_str().unwrap(),
                COMMIT,
                &self.key,
            ])
            .ok();
            repos.push(repo);
        }
        (repos[0].clone(), repos[1].clone())
    }

    /// One `remote gpg-import` of the stream at `keyring` on both sides.
    fn import(&self, port: &Path, tool: &Path, keyring: &Path) -> (Run, Run) {
        let arg = format!("--keyring={}", keyring.display());
        run_remote_both(port, tool, &["remote", "gpg-import", "origin", &arg], &[])
    }

    /// What `show --gpg-verify-remote=origin` reports over `repo`, read by the
    /// port where `port` is set and by the tool where it is not.
    fn show(&self, repo: &Path, port: bool, env: &[(&str, &str)]) -> String {
        let args = ["show", "--gpg-verify-remote=origin", BRANCH];
        let mut all = vec![format!("--repo={}", repo.display())];
        all.extend(args.iter().map(|arg| (*arg).to_owned()));
        let all: Vec<&str> = all.iter().map(String::as_str).collect();
        let run = if port {
            ostrya(&all, None, env)
        } else {
            ostree_env(&all, env)
        };
        run.ok().stdout_trimmed()
    }

    /// Assert that each implementation reports the signature good.
    fn assert_good(&self, port: &Path, tool: &Path) {
        for (label, repo, is_port) in [("the port", port, true), ("the tool", tool, false)] {
            let text = self.show(repo, is_port, &[]);
            assert!(
                text.contains("Good signature from"),
                "{label} refused a signature by a live key:\n{text}"
            );
        }
    }

    /// Assert that each implementation refuses the signature, each in its own
    /// wording.
    fn assert_revoked(&self, port: &Path, tool: &Path) {
        let text = self.show(port, true, &[]);
        assert!(
            text.contains("BAD signature from") && !text.contains("Good signature"),
            "the port accepted a signature by a revoked key:\n{text}"
        );
        let text = self.show(tool, false, &[]);
        assert!(
            text.contains("Key revoked") && !text.contains("Good signature"),
            "the tool accepted a signature by a revoked key:\n{text}"
        );
    }

    /// The primary-key fingerprints the remote's trusted keyring holds, as
    /// `gpg` reports them.
    fn keys_in(&self, repo: &Path) -> Vec<String> {
        let out = self
            .home
            .gpg()
            .arg("--no-default-keyring")
            .arg("--keyring")
            .arg(repo.join("origin.trustedkeys.gpg"))
            .args(["--with-colons", "--list-keys"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "gpg --list-keys over a keyring failed"
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix("fpr:"))
            .filter_map(|rest| rest.split(':').nth(8).map(str::to_owned))
            .collect()
    }

    /// Write the concatenation of `parts` to `path`.
    fn concat(path: &Path, parts: &[&Path]) {
        let mut bytes = Vec::new();
        for part in parts {
            bytes.extend_from_slice(&std::fs::read(part).unwrap());
        }
        std::fs::write(path, bytes).unwrap();
    }
}

/// A repository holding two GPG signatures that do not verify, with the
/// signing key in the trusted keyring of the remote `origin`.
///
/// The commit on `bad/one` is signed, and the commits on `bad/two` and
/// `bad/three` each hold a copy of that commit's detached metadata, so each of
/// those two stored signatures stands over a payload other than the one it was
/// made over and the cryptography refuses it. The issuer stays resolvable, so
/// the report names the signing key. The return value is the repository and
/// the checksums of the commits on `bad/two` and `bad/three`, which carry one
/// refused signature each.
#[cfg(feature = "gpg")]
fn bad_signature_repo(base: &Path, home: &GpgHome, keyring: &Path) -> (PathBuf, String, String) {
    build_fixture_source(base);
    let src = base.join("src");
    let repo = create_repo(base, RepoMode::Archive);
    let repo_s = repo.to_str().unwrap().to_owned();
    let mut checksums: Vec<String> = Vec::new();
    for (branch, subject) in [
        ("bad/one", "signed commit"),
        ("bad/two", "other commit"),
        ("bad/three", "third commit"),
    ] {
        let run = ostrya(
            &[
                "commit",
                "--repo",
                &repo_s,
                "-b",
                branch,
                "-s",
                subject,
                "--canonical-permissions",
                src.to_str().unwrap(),
            ],
            None,
            &[("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)],
        );
        checksums.push(run.ok().stdout_trimmed());
    }
    ostrya(
        &[
            "sign",
            "--repo",
            &repo_s,
            "-s",
            "gpg",
            "--gpg-homedir",
            home.dir.to_str().unwrap(),
            &checksums[0],
            &home.fingerprint(),
        ],
        None,
        &[],
    )
    .ok();
    let meta = |checksum: &str| {
        repo.join(format!(
            "objects/{}/{}.commitmeta",
            &checksum[..2],
            &checksum[2..]
        ))
    };
    std::fs::copy(meta(&checksums[0]), meta(&checksums[1])).unwrap();
    std::fs::copy(meta(&checksums[0]), meta(&checksums[2])).unwrap();
    configure_remote(&repo, "https://example.invalid/r", "");
    ostrya(
        &[
            &format!("--repo={repo_s}"),
            "remote",
            "gpg-import",
            "origin",
            &format!("--keyring={}", keyring.display()),
        ],
        None,
        &[],
    )
    .ok();
    let third = checksums.remove(2);
    (repo, checksums.remove(1), third)
}

/// The one `Signature made` line a signature report draws, with the leading
/// indent removed.
#[cfg(feature = "gpg")]
fn signature_made_line(report: &str) -> &str {
    report
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("Signature made"))
        .unwrap_or_else(|| panic!("no `Signature made` line in the report:\n{report}"))
}

/// The `key ID` field of that line.
#[cfg(feature = "gpg")]
fn reported_key_id(report: &str) -> &str {
    let line = signature_made_line(report);
    line.split(" key ID")
        .nth(1)
        .map(str::trim)
        .unwrap_or_else(|| panic!("no `key ID` field in `{line}`"))
}

/// The signature report line `show` draws over a signature that does not
/// verify names the same key in both implementations, and both refuse the
/// signature in the same words.
///
/// A signing subkey made the signature, so the report names two keys: the
/// subkey on the report line and the primary key that binds it on the tool's
/// `Primary key ID` line. Three differences stand here, all of them recorded
/// in `cli-surface.md`, "P1". The tool holds no instant and no algorithm for a
/// signature the cryptography refused, so it draws the Unix epoch and
/// `[unknown name]` in their places, where the port draws an empty instant and
/// `unknown`. The host time zone and locale decide how the tool renders that
/// instant, so the epoch stands here as the year alone, with `TZ=UTC` set to
/// hold the run inside 1970. The `Primary key ID` line is one the port draws
/// nowhere, and the key it names stands in the port's record, where
/// `sign --delete` reads it
/// (`sign_delete_reaches_a_signature_that_does_not_verify`).
#[cfg(feature = "gpg")]
#[test]
fn show_reports_a_bad_signature_like_the_tool() {
    if !ostree_available() || !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("show-bad-sig");
    let base = tmp.path();
    let home = GpgHome::create(base, "Badsig <badsig@ostrya.example>");
    let subkey = home.add_signing_subkey();
    let keyring = base.join("public.gpg");
    home.export_to(&keyring);
    let (repo, checksum, _) = bad_signature_repo(base, &home, &keyring);
    let repo_arg = format!("--repo={}", repo.display());
    let args = [
        repo_arg.as_str(),
        "show",
        "--gpg-verify-remote=origin",
        &checksum,
    ];
    let port = ostrya(&args, None, &[]).ok().stdout_trimmed();
    let tool = ostree_env(&args, &[("TZ", "UTC")]).ok().stdout_trimmed();

    // Both refuse the signature, word for word.
    let verdict = "BAD signature from \"Badsig <badsig@ostrya.example>\"";
    for (label, report) in [("the port", &port), ("the tool", &tool)] {
        assert!(
            report.contains(verdict),
            "{label} drew no `{verdict}` line:\n{report}"
        );
    }

    // Both name the signing subkey on the line above the verdict.
    let key_id = &subkey[subkey.len() - 16..];
    assert_eq!(reported_key_id(&port), key_id, "the port's key ID");
    assert_eq!(reported_key_id(&tool), key_id, "the tool's key ID");

    // The recorded differences, stated so a change in either is reported. Each
    // one is read off the report line, so no other line of the report answers
    // for it.
    assert_eq!(
        signature_made_line(&port),
        format!("Signature made  using unknown key ID {key_id}"),
        "the port now states an instant or an algorithm here"
    );
    let tool_line = signature_made_line(&tool);
    assert!(
        tool_line.contains("1970") && tool_line.contains("[unknown name]"),
        "the tool now states an instant or an algorithm here: `{tool_line}`"
    );
    let primary = home.fingerprint();
    assert!(
        tool.contains(&format!(
            "Primary key ID {}",
            &primary[primary.len() - 16..]
        )),
        "the tool drew no `Primary key ID` line:\n{tool}"
    );
    assert!(
        !port.contains("Primary key ID"),
        "the port now draws a `Primary key ID` line:\n{port}"
    );
}

/// `sign --delete KEY-ID` removes a signature whose issuer the trusted set
/// holds and whose cryptography fails, under the key id of the signing key and
/// under the key id of the certificate that holds it. A signing subkey made
/// the signature here, so those two key ids differ. The record such a
/// signature draws names both keys, and the delete matches a KEY-ID against
/// either field. `ostree gpg-sign --delete` over the same commit removes the
/// signature under either key id and under either whole fingerprint, measured
/// against `ostree` 2026.1.
#[cfg(feature = "gpg")]
#[test]
fn sign_delete_reaches_a_signature_that_does_not_verify() {
    if !gpg_available() {
        eprintln!("skipping: gpg not available");
        return;
    }
    let tmp = TmpDir::new("sign-delete-bad-sig");
    let base = tmp.path();
    let home = GpgHome::create(base, "Doomed <doomed@ostrya.example>");
    let subkey = home.add_signing_subkey();
    let keyring = base.join("public.gpg");
    home.export_to(&keyring);
    let (repo, by_subkey, by_primary) = bad_signature_repo(base, &home, &keyring);
    let repo_arg = format!("--repo={}", repo.display());
    let primary = home.fingerprint();
    let signing_key_id = subkey[subkey.len() - 16..].to_owned();
    let primary_key_id = primary[primary.len() - 16..].to_owned();
    let report = |checksum: &str| {
        ostrya(
            &[
                repo_arg.as_str(),
                "show",
                "--gpg-verify-remote=origin",
                checksum,
            ],
            None,
            &[],
        )
        .ok()
        .stdout_trimmed()
    };

    // One commit per KEY-ID, so each delete runs over a signature of its own.
    for (checksum, key_id, named) in [
        (&by_subkey, &signing_key_id, "the signing subkey"),
        (&by_primary, &primary_key_id, "the primary key"),
    ] {
        // The commit holds one signature, the trusted set resolves its issuer,
        // and the cryptography refuses it.
        let before = report(checksum);
        assert!(
            before.contains("Found 1 signature:") && before.contains("BAD signature from"),
            "the fixture holds no refused signature:\n{before}"
        );
        assert_eq!(reported_key_id(&before), signing_key_id);

        let deleted = ostrya(
            &[
                repo_arg.as_str(),
                "sign",
                "-d",
                "-s",
                "gpg",
                "--remote",
                "origin",
                checksum,
                key_id,
            ],
            None,
            &[],
        );
        assert!(
            deleted.ok().stdout_trimmed().contains("Deleted 1"),
            "the KEY-ID of {named} reached no signature"
        );

        // Nothing is left to report over the commit.
        let after = report(checksum);
        assert!(
            !after.contains("signature"),
            "the commit kept a signature:\n{after}"
        );
    }
}

/// `show --print-variant-type` reads a file as a value of a named type, which
/// makes the tool a byte-exact oracle for the GVariant text form. Each case is
/// a hand-written serialized value covering one rule of the form.
#[test]
fn variant_text_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("variant-text");
    let base = tmp.path();
    let repo = create_repo(base, RepoMode::Archive);
    let cases: &[(&str, &str, &[u8])] = &[
        // Byte arrays: the bytestring form, its escapes, and the list form.
        ("nul", "ay", &[0x00]),
        ("bytestring", "ay", b"b\0"),
        ("unterminated", "ay", &[0x62]),
        ("interior_nul", "ay", &[0x62, 0x00, 0x63, 0x00]),
        ("hi", "ay", b"hi\0"),
        ("high_byte", "ay", &[0xff, 0x00]),
        ("tab", "ay", b"a\tb\0"),
        ("single_quote", "ay", b"a'b\0"),
        ("double_quote", "ay", b"a\"b\0"),
        ("both_quotes", "ay", b"a'\"b\0"),
        ("utf8", "ay", "hé\0".as_bytes()),
        ("del", "ay", &[0x7f, 0x00]),
        ("escape", "ay", &[0x1b, 0x00]),
        ("empty", "ay", b""),
        ("bytes", "ay", &[0x01, 0x02, 0xff]),
        // Strings and their escapes.
        ("s_plain", "s", b"abc\0"),
        ("s_empty", "s", b"\0"),
        ("s_squote", "s", b"a'b\0"),
        ("s_dquote", "s", b"a\"b\0"),
        ("s_both", "s", b"a'\"b\0"),
        ("s_tab", "s", b"a\tb\0"),
        ("s_newline", "s", b"a\nb\0"),
        ("s_return", "s", b"a\rb\0"),
        ("s_bell", "s", b"a\x07b\0"),
        ("s_backspace", "s", b"a\x08b\0"),
        ("s_vtab", "s", b"a\x0bb\0"),
        ("s_formfeed", "s", b"a\x0cb\0"),
        ("s_escape", "s", b"a\x1bb\0"),
        ("s_del", "s", b"a\x7fb\0"),
        ("s_backslash", "s", b"a\\b\0"),
        ("s_utf8", "s", "héllo\0".as_bytes()),
        // Scalars, which the numeric conversion reaches.
        ("u32", "u", &[0x01, 0x02, 0x03, 0x04]),
        ("u64", "t", &[1, 2, 3, 4, 5, 6, 7, 8]),
        ("bool_false", "b", &[0x00]),
        ("bool_true", "b", &[0x01]),
        ("byte", "y", &[0x2a]),
        // Containers: where the annotation lands, and the empty forms.
        ("as", "as", b"a\0bb\0\x02\x05"),
        (
            "aay_first_bytestring",
            "aay",
            &[0x62, 0x00, 0x63, 0x02, 0x03],
        ),
        (
            "aay_second_bytestring",
            "aay",
            &[0x63, 0x62, 0x00, 0x01, 0x03],
        ),
        ("aay_first_empty", "aay", &[0x63, 0x00, 0x01]),
        ("aay_second_empty", "aay", &[0x63, 0x01, 0x01]),
        ("aay_empty", "aay", b""),
        (
            "dict",
            "a{sy}",
            &[0x61, 0x00, 0x01, 0x02, 0x62, 0x00, 0x02, 0x02, 0x04, 0x08],
        ),
        ("dict_empty", "a{sy}", b""),
        ("dict_entry", "{sy}", &[0x61, 0x00, 0x01, 0x02]),
        ("tuple_one", "(y)", &[0x01]),
        ("tuple_empty", "()", &[0x00]),
        ("tuple_two", "(yy)", &[0x01, 0x02]),
        ("tuple_strings", "(ss)", b"a\0b\0\x02"),
        ("variant_byte", "v", &[0x2a, 0x00, 0x79]),
        ("variant_bytestring", "v", &[0x62, 0x00, 0x00, 0x61, 0x79]),
        ("aab", "aab", &[0x01, 0x00, 0x01, 0x02]),
    ];
    for (name, signature, bytes) in cases {
        let path = base.join(name);
        std::fs::write(&path, bytes).unwrap();
        let arg = format!("--print-variant-type={signature}");
        assert_agrees(&repo, &repo, &["show", &arg, path.to_str().unwrap()]);
    }
    // A path that does not open is refused in the tool's own words.
    let missing = base.join("nosuchfile");
    assert_agrees(
        &repo,
        &repo,
        &["show", "--print-variant-type=u", missing.to_str().unwrap()],
    );
}

/// A signature that names no type is refused, which is the shape the tool dies
/// on (`docs/conformance/cli-surface.md`, "P1").
#[test]
fn show_refuses_a_variant_type_that_is_not_a_type() {
    let tmp = TmpDir::new("variant-type-refused");
    let base = tmp.path();
    let repo = create_repo(base, RepoMode::Archive);
    let path = base.join("value");
    std::fs::write(&path, [0x01, 0x02]).unwrap();
    for signature in ["(s", "zz", "r", "*", "?", "m"] {
        let run = ostrya(
            &[
                &format!("--repo={}", repo.display()),
                "show",
                &format!("--print-variant-type={signature}"),
                path.to_str().unwrap(),
            ],
            None,
            &[],
        );
        assert_eq!(
            run.status.code(),
            Some(1),
            "the port accepted the type {signature:?}"
        );
        assert!(
            String::from_utf8_lossy(&run.stderr).contains("invalid type signature"),
            "the refusal of {signature:?} does not name the signature"
        );
        assert!(run.stdout.is_empty(), "{signature:?} wrote to stdout");
    }
}

// --- Phase 17f: `commit` message, metadata, and ref bindings ------------------
//
// Each test builds one repository per implementation, runs the same invocation
// against both, and compares the exit status and both streams. `commit` prints
// the checksum it made, so an agreeing standard output is checksum agreement
// over the commit object, which is what the subject, the body, the metadata
// dict, and its entry order all reach
// (`docs/format-reference.md`, "CLI output formats").

/// A repository pair in `mode` and the materialized corpus, for the `commit`
/// option families below.
fn commit_pair(base: &Path, mode: RepoMode) -> (PathBuf, PathBuf, PathBuf) {
    let tree = base.join("tree");
    ostrya_conformance::corpus::materialize("C0", &tree).unwrap();
    let (port_repo, tool_repo) = create_repo_pair(base, mode);
    (port_repo, tool_repo, tree)
}

/// The fixed timestamp every commit below states, which is what makes its
/// checksum reproducible across the two implementations.
const FIXED_TIMESTAMP: &str = "--timestamp=@1700000000";

/// `commit -m/--body` and `-F/--body-file` reach the commit's body field, `-F`
/// wins over `-m` in either order, and a body file neither implementation can
/// read is refused in the same words.
#[test]
fn commit_body_forms_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-body");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    let write = |name: &str, bytes: &[u8]| {
        let path = base.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let body_file = write("body.txt", b"from file line1\nline2\n");
    let empty = write("empty.txt", b"");
    let trailing = write("trail.txt", b"trailing\n\n\n");
    let no_newline = write("nonl.txt", b"no newline at end");
    let spaces = write("ws.txt", b"  leading and trailing  \n");
    let bad_utf8 = write("bad.txt", b"bad\xff\xfebytes\n");
    let with_nul = write("nul.txt", b"a\0b\n");
    let absent = base.join("nope.txt");

    let mut cell = 0;
    let mut agrees = |extra: &[&str]| {
        cell += 1;
        let branch = format!("body{cell}");
        let mut args = vec!["commit", "-b", &branch, FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        args.push(src);
        assert_agrees(&port_repo, &tool_repo, &args);
    };

    // The body is stored verbatim: no trimming, no newline normalization, and a
    // body with no subject is accepted.
    agrees(&["-m", "body text"]);
    agrees(&["-s", "subj", "-m", "body text"]);
    agrees(&["-s", "s", "-m", "line1\nline2"]);
    // Given more than once, the last value wins.
    agrees(&["-m", "one", "-m", "two"]);
    // A body file is taken byte for byte, its trailing newlines and its
    // surrounding spaces included, and an empty file gives an empty body.
    for path in [&body_file, &empty, &trailing, &no_newline, &spaces] {
        agrees(&["-F", path.to_str().unwrap()]);
    }
    // `-F` wins over `-m`, whichever comes first.
    agrees(&["-m", "inline", "-F", body_file.to_str().unwrap()]);
    agrees(&["-F", body_file.to_str().unwrap(), "-m", "inline"]);
    // The refusals: a path that does not open, a directory, and content that is
    // not UTF-8 or holds a NUL.
    agrees(&["-F", absent.to_str().unwrap()]);
    agrees(&["-F", "-"]);
    agrees(&["-F", src]);
    // The two content refusals carry `error: Invalid UTF-8` at exit 1 from both,
    // which is what the record states, so the words and the status are held
    // rather than the two sides agreeing on some other answer.
    for (branch, path) in [("bodybad", &bad_utf8), ("bodynul", &with_nul)] {
        let args = [
            "commit",
            "-b",
            branch,
            FIXED_TIMESTAMP,
            "-F",
            path.to_str().unwrap(),
            src,
        ];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let label = args.join(" ");
        assert_runs_agree(&port, &tool, &label);
        assert_runs_agree_on_error(&port, &tool, &label, "error: Invalid UTF-8");
    }
}

/// Write an executable shell script and return its path.
fn write_script(path: &Path, body: &str) -> PathBuf {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_owned()
}

/// `commit -e/--editor` writes the tool's own template into a temporary file,
/// runs the editor named by the environment as a shell command line, and reads
/// the subject and the body back out of what the editor left.
#[test]
fn commit_editor_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-editor");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    // An editor that copies the template it is given to `$DUMP`, so the two
    // templates compare byte for byte.
    let dump = write_script(&base.join("dump.sh"), "#!/bin/sh\ncp \"$1\" \"$DUMP\"\n");
    // An editor that replaces the template, one that leaves it alone, one that
    // writes a message and then fails, and one that fails at once.
    let writer = write_script(
        &base.join("write.sh"),
        "#!/bin/sh\nprintf 'EdSubject\\nEdBody\\n' > \"$1\"\n",
    );
    let untouched = write_script(&base.join("noop.sh"), "#!/bin/sh\nexit 0\n");
    let failing = write_script(&base.join("fail.sh"), "#!/bin/sh\nexit 3\n");
    let write_then_fail = write_script(
        &base.join("writefail.sh"),
        "#!/bin/sh\nprintf 'GoodSubject\\nGoodBody\\n' > \"$1\"\nexit 3\n",
    );
    // An editor that writes whatever `$EDCONTENT` names, for the parse rules.
    let content = write_script(
        &base.join("content.sh"),
        "#!/bin/sh\nprintf '%b' \"$EDCONTENT\" > \"$1\"\n",
    );
    // An editor that writes a byte that is not UTF-8, one that writes a NUL,
    // and one that removes the file it was given.
    let invalid_utf8 = write_script(
        &base.join("badutf8.sh"),
        "#!/bin/sh\nprintf 'Sub\\377ject\\nbody\\n' > \"$1\"\n",
    );
    let nul_byte = write_script(
        &base.join("nulbyte.sh"),
        "#!/bin/sh\nprintf 'Sub\\000ject\\nbody\\n' > \"$1\"\n",
    );
    let removes = write_script(&base.join("remove.sh"), "#!/bin/sh\nrm -f \"$1\"\n");

    // The template bytes. Each side dumps its own copy, and the two are
    // compared directly: the branch block, its absence under `--orphan`, and a
    // `-s` value appended after the block.
    let template = |label: &str, extra: &[&str]| {
        let mut written = Vec::new();
        for (name, repo) in [("port", &port_repo), ("tool", &tool_repo)] {
            let target = base.join(format!("template-{label}-{name}"));
            let mut args = vec![
                "commit".to_owned(),
                format!("--repo={}", repo.display()),
                FIXED_TIMESTAMP.to_owned(),
                "-e".to_owned(),
            ];
            args.extend(extra.iter().map(|arg| (*arg).to_owned()));
            args.push(src.to_owned());
            let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
            // Both variables ahead of `EDITOR` must be absent, not empty: an
            // empty one is set and so is chosen.
            let env: Vec<(&str, &str)> = vec![
                ("EDITOR", dump.to_str().unwrap()),
                ("DUMP", target.to_str().unwrap()),
            ];
            if name == "port" {
                ostrya_no_editor(&borrowed, &env);
            } else {
                ostree_no_editor(&borrowed, &env);
            }
            written.push(std::fs::read(&target).unwrap_or_default());
        }
        assert_eq!(
            String::from_utf8_lossy(&written[0]),
            String::from_utf8_lossy(&written[1]),
            "the {label} template differs",
        );
        assert!(!written[0].is_empty(), "the {label} template is empty");
    };
    template("branch", &["-b", "BR"]);
    template("orphan", &["--orphan"]);
    template(
        "prefill",
        &["-b", "BR", "-s", "Pre subject", "-m", "Pre body"],
    );
    template("multiline", &["-b", "BR", "-s", "S1\nS2"]);

    // The editor's own result, and the fault it reports. Each case runs the same
    // invocation on both sides with the same environment.
    let mut cell = 0;
    let mut agrees = |editor: &Path, edcontent: &str, extra: &[&str]| {
        cell += 1;
        let branch = format!("ed{cell}");
        let mut args = vec!["commit", "-b", &branch, FIXED_TIMESTAMP, "-e"];
        args.extend_from_slice(extra);
        args.push(src);
        let env = [
            ("EDITOR", editor.to_str().unwrap()),
            ("EDCONTENT", edcontent),
        ];
        let (port, tool) = run_both_no_editor(&port_repo, &tool_repo, &args, &env);
        // The temporary file's name is each implementation's own, so a message
        // naming it is compared with the name masked.
        assert_runs_agree(&mask_temp(&port), &mask_temp(&tool), &args.join(" "));
    };
    agrees(&writer, "", &[]);
    agrees(&untouched, "", &[]);
    agrees(&untouched, "", &["-s", "PreSubject", "-m", "PreBody"]);
    agrees(&writer, "", &["-s", "CliSubject"]);
    agrees(&writer, "", &["-m", "CliBody"]);
    agrees(&writer, "", &["-s", "CliS", "-m", "CliB"]);
    // `-e` replaces the body outright, so `-F` is never read: a body file that
    // does not open leaves the commit standing.
    agrees(
        &writer,
        "",
        &["-F", base.join("nope.txt").to_str().unwrap()],
    );
    // A non-zero editor exit aborts, and what the editor wrote is discarded.
    agrees(&failing, "", &[]);
    agrees(&write_then_fail, "", &[]);
    agrees(Path::new("/nonexistent/editor"), "", &[]);
    // What the editor left is read under the rules `-F/--body-file` states: a
    // byte that is not UTF-8 and a NUL both report `Invalid UTF-8`, and a file
    // the editor removed reports `openat(<path>): <reason>`.
    agrees(&invalid_utf8, "", &[]);
    agrees(&nul_byte, "", &[]);
    agrees(&removes, "", &[]);

    // The parse rules over the edited text, each pair one case of the table in
    // `format-reference.md`.
    for text in [
        "Subject line\\n",
        "Subject line\\n\\nBody line 1\\nBody line 2\\n",
        "Subject\\nimmediate body\\n",
        "Subject\\n# a comment\\nbody\\n",
        "\\n\\nSubject after blanks\\nbody\\n",
        "Subject with trailing   \\n\\n\\nbody\\n\\n\\n",
        "Subject\\n\\n\\n\\nbody\\n",
        "   Subject indented\\nbody\\n",
        "Subject\\n\\npara1 line1\\npara1 line2\\n\\npara2\\n",
        "Subject\\nbody\\n   \\n",
        "Subject\\nbody with # hash inside\\n",
        "  # indented comment\\nSubject\\n",
        "Subject\\n\\tTabbed body\\n",
        "Subject only no newline",
        "Subject\\r\\nCRLF body\\r\\n",
        "Sub\\n\\n\\n",
        "#comment\\n\\nSubject\\n\\nbody\\n#trailing comment\\n",
        "Subject\\nline1   \\nline2\\n",
        "Subject\\nline1\\n   \\nline2\\n",
        "Subject\\n\\n   \\n\\nline2\\n",
        // An empty subject aborts.
        "# only comments\\n#\\n",
        "   \\n",
        "",
    ] {
        agrees(&content, text, &[]);
    }

    // The temporary file is created readable and writable by its owner alone.
    let stat = "stat -c %a";
    let (port, tool) = run_both_no_editor(
        &port_repo,
        &tool_repo,
        &["commit", "-b", "edmode", FIXED_TIMESTAMP, "-e", src],
        &[("EDITOR", stat), ("EDCONTENT", "")],
    );
    assert_eq!(
        String::from_utf8_lossy(&port.stdout).lines().next(),
        Some("600"),
        "the port's editor file mode"
    );
    assert_eq!(
        String::from_utf8_lossy(&tool.stdout).lines().next(),
        Some("600"),
        "the tool's editor file mode"
    );

    // Where the editor stands in the fault order. A marker the editor writes
    // states whether it ran; the metadata options are read ahead of it and the
    // tree and the timestamp behind it.
    let marker = write_script(
        &base.join("marker.sh"),
        "#!/bin/sh\ntouch \"$MARK\"\nprintf 'S\\nB\\n' > \"$1\"\n",
    );
    let mut order = 0;
    let mut order_agrees = |extra: &[&str], path: &str, ran: bool| {
        order += 1;
        let branch = format!("edorder{order}");
        let mut args = vec!["commit", "-b", &branch, "-e"];
        args.extend_from_slice(extra);
        args.push(path);
        for (name, repo) in [("port", &port_repo), ("tool", &tool_repo)] {
            let mark = base.join(format!("mark-{order}-{name}"));
            let _ = std::fs::remove_file(&mark);
            let env = [
                ("EDITOR", marker.to_str().unwrap()),
                ("MARK", mark.to_str().unwrap()),
            ];
            let mut all = vec!["commit".to_owned(), "--repo".to_owned()];
            all.push(repo.display().to_string());
            all.extend(args[1..].iter().map(|arg| (*arg).to_owned()));
            let all: Vec<&str> = all.iter().map(String::as_str).collect();
            let run = if name == "port" {
                ostrya_no_editor(&all, &env)
            } else {
                ostree_no_editor(&all, &env)
            };
            assert!(!run.status.success(), "{name} accepted {args:?}");
            assert_eq!(mark.exists(), ran, "{name} editor ran for {args:?}");
        }
    };
    // A metadata value the reader refuses stands ahead of the editor.
    order_agrees(&["--add-metadata=k=[]", FIXED_TIMESTAMP], src, false);
    order_agrees(
        &["--add-metadata-string=noequals", FIXED_TIMESTAMP],
        src,
        false,
    );
    // A timestamp the reader refuses and a tree that does not open stand behind
    // it. The tree refusal is worded per implementation
    // (`docs/conformance/cli-surface.md`, "P2"), so only the order is
    // compared here.
    order_agrees(&["--timestamp=notatime"], src, true);
    order_agrees(
        &[FIXED_TIMESTAMP],
        base.join("nosuchtree").to_str().unwrap(),
        true,
    );
}

/// The `-e/--editor` file is read to at most 128 mebibytes, the bound
/// `-F/--body-file` takes. A file of exactly that size commits, and the tool
/// reaches the same commit; one byte more reports `Commit message larger than
/// 134217728 bytes` at exit 1 and writes no ref, which is the port's own bound
/// (`docs/conformance/cli-surface.md`, "Scope of CLI compatibility").
///
/// Ignored by default: it writes a 128 mebibyte file and copies it once per
/// case; run with `cargo test -p ostrya-cli --test cli -- --ignored`.
#[test]
#[ignore = "writes a 128 MiB editor file; run with --ignored"]
fn commit_editor_file_is_capped() {
    use std::io::Write as _;

    const LIMIT: usize = 128 * 1024 * 1024;

    let tmp = TmpDir::new("editor-cap");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    // The file the editor copies from, one byte over the limit: a subject line
    // and a comment line that carries the bulk, so the message parsed out of it
    // stays small at either size and the commit is cheap to write.
    let big = base.join("big");
    let mut out = std::io::BufWriter::new(std::fs::File::create(&big).unwrap());
    out.write_all(b"S\n#").unwrap();
    let chunk = vec![b'a'; 1024 * 1024];
    let mut left = LIMIT - 3;
    while left > 0 {
        let take = left.min(chunk.len());
        out.write_all(&chunk[..take]).unwrap();
        left -= take;
    }
    out.write_all(b"\n").unwrap();
    drop(out);
    assert_eq!(
        std::fs::metadata(&big).unwrap().len(),
        LIMIT as u64 + 1,
        "the source file is the wrong size"
    );

    // The editor writes the leading `$SIZE` bytes of that file, so one source
    // file serves both sizes.
    let editor = write_script(
        &base.join("copy.sh"),
        "#!/bin/sh\nhead -c \"$SIZE\" \"$BIG\" > \"$1\"\n",
    );
    let invoke = |program: &str, repo: &Path, size: usize, branch: &str| -> Run {
        let repo_arg = format!("--repo={}", repo.display());
        let size = size.to_string();
        let args = [
            "commit",
            &repo_arg,
            "-b",
            branch,
            FIXED_TIMESTAMP,
            "-e",
            src,
        ];
        let env = [
            ("EDITOR", editor.to_str().unwrap()),
            ("BIG", big.to_str().unwrap()),
            ("SIZE", size.as_str()),
        ];
        run_cleared(program, &args, &env)
    };

    // Exactly the limit is accepted, and both implementations reach the same
    // commit.
    let port = invoke(env!("CARGO_BIN_EXE_ostrya"), &port_repo, LIMIT, "atlimit");
    assert!(
        port.status.success(),
        "the port refused a {LIMIT}-byte editor file: {}",
        String::from_utf8_lossy(&port.stderr)
    );
    let checksum = port.stdout_trimmed();
    assert_eq!(checksum.len(), 64, "the port printed `{checksum}`");
    if ostree_available() {
        let tool = invoke("ostree", &tool_repo, LIMIT, "atlimit");
        assert!(
            tool.status.success(),
            "the tool refused a {LIMIT}-byte editor file: {}",
            String::from_utf8_lossy(&tool.stderr)
        );
        assert_eq!(
            checksum,
            tool.stdout_trimmed(),
            "the commit checksums differ at the limit"
        );
    }

    // One byte more is refused and nothing is written.
    let port = invoke(
        env!("CARGO_BIN_EXE_ostrya"),
        &port_repo,
        LIMIT + 1,
        "overlimit",
    );
    assert_eq!(port.status.code(), Some(1), "the port accepted the file");
    assert_eq!(
        String::from_utf8_lossy(&port.stderr).trim_end(),
        format!("error: Commit message larger than {LIMIT} bytes"),
        "the refusal is worded differently"
    );
    assert!(port.stdout.is_empty(), "the refusal printed a checksum");
    let listed = ostrya(&["refs", "--repo", port_repo.to_str().unwrap()], None, &[])
        .ok()
        .stdout_trimmed();
    assert!(
        !listed.lines().any(|line| line == "overlimit"),
        "the refused commit left a ref: {listed}"
    );
}

/// `commit -e` holds no repository lock while the message is being written: the
/// transaction opens once the editor has returned, so an exclusive operation on
/// the same repository runs during the editing session.
///
/// The repository states `lock-timeout-secs=1`, so an acquisition that has to
/// wait for the editing session fails inside a second and this test reports it
/// rather than waiting out the default five-minute timeout.
#[test]
fn commit_editor_holds_no_repository_lock() {
    use std::time::{Duration, Instant};

    let tmp = TmpDir::new("editor-lock");
    let base = tmp.path();
    let tree = base.join("tree");
    ostrya_conformance::corpus::materialize("C0", &tree).unwrap();
    let repo = create_repo(base, RepoMode::Archive);
    let mut config = config_text(&repo);
    config.push_str("lock-timeout-secs=1\n");
    std::fs::write(repo.join("config"), config).unwrap();

    // The editor states that it started, waits long enough for the acquisition
    // below to run inside the session, then writes the message.
    let started_marker = base.join("editing");
    let editor = write_script(
        &base.join("slow.sh"),
        "#!/bin/sh\ntouch \"$STARTED\"\nsleep 4\nprintf 'S\\nB\\n' > \"$1\"\n",
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_ostrya"));
    command
        .args([
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            "locked",
            "-e",
            FIXED_TIMESTAMP,
            tree.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("STARTED", &started_marker);
    for name in EDITOR_VARIABLES {
        command.env_remove(name);
    }
    command.env("OSTREE_EDITOR", &editor);
    let child = command.spawn().expect("spawn the port");

    // Wait for the editing session to open, bounded so a child that never runs
    // the editor fails here instead of hanging.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !started_marker.exists() {
        assert!(Instant::now() < deadline, "the editor never started");
        std::thread::sleep(Duration::from_millis(10));
    }

    // An exclusive hold excludes every other holder, so it succeeds only where
    // the editing session holds nothing. The hold is released at once, well
    // inside the session, so the commit takes its own lock unimpeded.
    let (acquired, waited) = block_on(async {
        let repo = Repo::open(&repo).await.unwrap();
        let started = Instant::now();
        let acquired = repo
            .transaction_with_lock(LockKind::Exclusive)
            .await
            .is_ok();
        (acquired, started.elapsed())
    });
    assert!(
        acquired,
        "an exclusive hold was refused while the editor was running"
    );
    assert!(
        waited < Duration::from_secs(1),
        "an exclusive hold waited {waited:?} for the editing session"
    );

    // The commit itself still takes the lock and writes the ref.
    let out = child.wait_with_output().expect("wait for the port");
    assert!(
        out.status.success(),
        "the commit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed = String::from_utf8_lossy(&out.stdout);
    let checksum = printed.trim();
    assert_eq!(checksum.len(), 64, "the commit printed `{printed}`");
    let listed = ostrya(&["refs", "--repo", repo.to_str().unwrap()], None, &[])
        .ok()
        .stdout_trimmed();
    assert!(
        listed.lines().any(|line| line == "locked"),
        "the branch is missing: {listed}"
    );
}

/// The environment variables that name the editor, which a case controlling one
/// of them must clear on both sides so the host's own value cannot reach the
/// invocation.
const EDITOR_VARIABLES: [&str; 4] = ["OSTREE_EDITOR", "VISUAL", "EDITOR", "GIT_EDITOR"];

/// Run the port with the editor variables cleared and `env` applied over them.
fn ostrya_no_editor(args: &[&str], env: &[(&str, &str)]) -> Run {
    run_cleared(env!("CARGO_BIN_EXE_ostrya"), args, env)
}

/// Run the tool with the editor variables cleared and `env` applied over them.
fn ostree_no_editor(args: &[&str], env: &[(&str, &str)]) -> Run {
    run_cleared("ostree", args, env)
}

/// Run `program` with every editor variable removed from the environment and
/// `env` set over the result.
fn run_cleared(program: &str, args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    for name in EDITOR_VARIABLES {
        command.env_remove(name);
    }
    for (key, value) in env {
        command.env(key, value);
    }
    let out = command.output().expect("spawn the implementation");
    Run {
        status: out.status,
        stdout: out.stdout,
        stderr: out.stderr,
    }
}

/// Run `args` against each side's own repository with the editor environment
/// cleared, passing the repository as a trailing `--repo`.
fn run_both_no_editor(
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
    let port = ostrya_no_editor(
        &port_args.iter().map(String::as_str).collect::<Vec<_>>(),
        env,
    );
    let tool = ostree_no_editor(
        &tool_args.iter().map(String::as_str).collect::<Vec<_>>(),
        env,
    );
    (port, tool)
}

/// The same run with the editor's temporary-file path replaced, each
/// implementation naming its own.
fn mask_temp(run: &Run) -> Run {
    fn mask(bytes: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(bytes);
        let mut out = String::new();
        for (index, part) in text.split('/').enumerate() {
            if index > 0 {
                out.push('/');
            }
            // A temporary name is a dot and six characters, the shape both
            // implementations give it.
            let temp = part.len() >= 7
                && part.starts_with('.')
                && part[1..7].chars().all(|c| c.is_ascii_alphanumeric());
            if temp {
                out.push_str("<TMP>");
                out.push_str(&part[7..]);
            } else {
                out.push_str(part);
            }
        }
        out.into_bytes()
    }
    Run {
        status: run.status,
        stdout: mask(&run.stdout),
        stderr: mask(&run.stderr),
    }
}

/// `commit --add-metadata-string` and `--add-metadata` write the commit
/// metadata dict, in the entry order the commit checksum states, and refuse the
/// same arguments in the same words.
#[test]
fn commit_metadata_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-metadata");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    let mut cell = 0;
    let mut agrees = |extra: &[&str]| -> (Run, Run) {
        cell += 1;
        let branch = format!("meta{cell}");
        let mut args = vec!["commit", "-b", &branch, FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        args.push(src);
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        assert_runs_agree(&port, &tool, &args.join(" "));
        (port, tool)
    };
    // Which side of the reader a value falls on, stated absolutely, so a value
    // both implementations came to refuse could not sit in the accepted set.
    let landed = |port: &Run, tool: &Run, value: &str, code: i32| {
        for (who, run) in [("port", port), ("tool", tool)] {
            assert_eq!(
                run.status.code(),
                Some(code),
                "the {who} answered `{value}` with another status:\n{}",
                String::from_utf8_lossy(&run.stderr),
            );
        }
    };

    // `--add-metadata-string` splits at the first `=`, so a value may hold
    // further ones, and an empty value is accepted.
    agrees(&["--add-metadata-string=foo=bar"]);
    agrees(&["--add-metadata-string=foo=has=equals=in=value"]);
    agrees(&["--add-metadata-string=key="]);
    // A key given twice is written twice.
    agrees(&[
        "--add-metadata-string=foo=bar",
        "--add-metadata-string=foo=second",
    ]);
    // The entry order is by group, not by command-line position: every
    // `--add-metadata-string` first, then every `--add-metadata`.
    agrees(&[
        "--add-metadata-string=s1=A",
        "--add-metadata=m1='B'",
        "--add-metadata-string=s2=C",
        "--add-metadata=m2='D'",
    ]);
    agrees(&["--add-metadata-string=dup=str", "--add-metadata=dup='var'"]);
    agrees(&["--add-metadata=dup='var'", "--add-metadata-string=dup=str"]);
    // A user key may carry a name the binding keys use; the automatic entry is
    // written beside it.
    agrees(&["--add-metadata-string=ostree.ref-binding=hijack"]);

    // Every value form the GVariant text reader accepts, one commit each. The
    // agreeing checksum states that the value serialized to the same bytes, host
    // byte order included.
    for value in [
        "'a string'",
        "\"double quoted\"",
        "uint32 42",
        "42",
        "-42",
        "int64 -5",
        "@x 5",
        "uint64 99",
        "byte 0x41",
        "true",
        "false",
        "1.5",
        "0.1",
        "1.0",
        "1e3",
        "-0.0",
        "1.7976931348623157e308",
        "int16 -5",
        "uint16 5",
        "handle 5",
        "objectpath '/a/b'",
        "signature 'ay'",
        "@o '/a/b'",
        "@g 'ay'",
        "['a','b']",
        "@as ['a','b']",
        "@ay [1,2,3]",
        "b'bytes'",
        "b\"double\"",
        "{'x': 'y'}",
        "@a{ss} {'x': 'y'}",
        "('a', 5)",
        "<'nested variant'>",
        "<<'x'>>",
        "@v <'x'>",
        "@ms 'just'",
        "@ms nothing",
        "just 'x'",
        "@mi 5",
        "@mu 7",
        // A nested maybe, where the set levels and the value both belong to the
        // stored bytes.
        "@mmi nothing",
        "@mmi just nothing",
        "@mmi just 5",
        "@mmi 5",
        "@mmmi just just nothing",
        "@mmmi just nothing",
        "@mmmmi just just just nothing",
        "@mms just nothing",
        "@mmv just nothing",
        "@mmv just just <5>",
        "@mmay just nothing",
        "@mm() just nothing",
        "@mammi just [just nothing]",
        "@ammi [just nothing, nothing, just just 5]",
        "@ammmi [just just nothing, just nothing, nothing, just just just 5]",
        "@a{smmi} {'a': just nothing, 'b': nothing, 'c': just just 5}",
        "@{smmi} {'a', just nothing}",
        "@(mmimmimmi) (just nothing, nothing, just just 5)",
        "'a=b'",
        "[2, 1.5]",
        "[1.5, 2]",
        "[[1],[2]]",
        "{'a': 1, 'b': 2}",
        "{1: 'a'}",
        "{'a', 5}",
        "[@ms 'a', 'b']",
        "['a', @ms 'b']",
        "[nothing, 'a']",
        "[just 'a', nothing]",
        "@(si) ('a', 5)",
        "@ai []",
        "@as []",
        "@a{sv} {}",
        "[b'x', b'y']",
        "[@o '/a', '/b']",
        "@ao ['/a','/b']",
        "'\\x41'",
        "  42  ",
        "@i 42",
        "@au [1,2]",
        "[<'a'>, <5>]",
        "0x41",
        "017",
        "(1,)",
        "()",
        "[1,2,3]",
        // A bytestring ends at the first NUL its escapes produce.
        "b'\\0'",
        "b''",
        "b'\\400'",
        "b'\\0001'",
        "b'a\\0b'",
        "b'\\101'",
        // A bytestring has no `\u` escape, so the backslash drops and the
        // digits stay.
        "b'\\u0000'",
        "b'a\\u0000b'",
        // Every escape a string literal takes: the short forms, the quote in
        // use, an unknown escape that drops the backslash and keeps the byte,
        // and the line continuation a backslash before a line feed makes.
        "'a\\ab'",
        "'a\\bb'",
        "'a\\fb'",
        "'a\\nb'",
        "'a\\rb'",
        "'a\\tb'",
        "'a\\vb'",
        "'a\\\\b'",
        "'a\\'b'",
        "\"a\\\"b\"",
        "'a\\zb'",
        "'a\\\nb'",
        "'\\\n'",
        "b'a\\\nb'",
        // A `\\` takes the backslash, so the line feed after it is the
        // literal's own and stays.
        "'a\\\\\nb'",
        // A unicode escape that names a character, in either digit case, and a
        // character written through as itself.
        "'\\u00e9'",
        "'\\u00E9'",
        "'a\\u0041b'",
        "'\\uffff'",
        "'\\U00000041'",
        "'\\U0001f600'",
        "'\\U0010ffff'",
        "'héllo'",
        "'中文'",
        "b'hé'",
        // The escapes a bytestring takes beside its octal ones.
        "b'a\\tb'",
        "b'a\\nb'",
        "b'a\\vb'",
        "b'a\\\\b'",
        "b\"a\\\"b\"",
        "b'a\\zb'",
        // A binary literal, and the hexadecimal body an integer reader takes.
        "0b101",
        "0B101",
        "byte 0b11111111",
        "0xe",
        "0x1e5",
        "-0x1",
        "+0x10",
        "0x1.8p1",
        // Both prefix letters take either case, and so do the hexadecimal
        // digits.
        "0X41",
        "0xAB",
        "0xaB",
        "byte 0XFF",
        "@t 0XdeadBEEF",
        // A leading zero with no digit after it is octal zero.
        "0",
        "-0",
        // A leading `+`, and the exponent's own sign.
        "+5",
        "1e+3",
        "1.5e+10",
        "+1.5",
        "@d +1",
        // A hexadecimal body carrying a fraction is a double with no binary
        // exponent of its own.
        "0x1.8",
        "@d 0x1.8",
        "@d 0x.8",
        "0x.8p1",
        // The reader the target type picks, which reads the same text twice.
        "@d 017",
        "double 0777",
        "@d 0x10",
        "@d 1E3",
        "double 1E3",
        // The sign the reader takes ahead of the body.
        "-",
        "@i -",
        "@t -",
        "-+5",
        // Not-a-number and the infinities, which the printer also writes.
        "nan",
        "-nan",
        "inf",
        "-inf",
        "+inf",
        "-infinity",
        "double nan",
        "just nan",
        "[1, nan]",
        // An underflow to zero is kept where a decimal subnormal is refused.
        "1e-400",
        "-1e-400",
        "2.2250738585072014e-308",
        // A hexadecimal body states its value in binary, so a subnormal it
        // states exactly is kept, and so is an underflow to zero.
        "@d 0x1p-1023",
        "@d 0x1p-1074",
        "@d -0x1p-1074",
        "@d 0x1.000001p-1030",
        "@d 0x1.fffffffffffffffp-1023",
        "@d 0x1p-1075",
        "@d 0x0.8p-1074",
        "@d 0x1p-9999999999",
        "@d 0x0.0p2147483647",
        // A mantissa past 32 hexadecimal digits keeps the digits it states,
        // and the digits below the double's lowest bit round the result.
        "@d 0xffffffffffffffffffffffffffffffffffffffffp0",
        "@d 0x1.0000000000000000000000000000000000001p0",
        "@d 0x1000000000000000000000000000000000001p-140",
        "@d 0x1.fffffffffffff7ffffffffp1023",
        // The object paths and the signatures both readers take.
        "objectpath '/'",
        "objectpath '/a_b'",
        "objectpath '/A/9'",
        "objectpath '/a/b/c'",
        "objectpath '/_'",
        "signature ''",
        "signature 'ii'",
        "signature '{sv}'",
        "signature 'a{sv}'",
        "signature 'v'",
        "signature '()'",
        "signature '(ii)'",
        "signature '{ss}'",
        "signature 'aay'",
        "signature 'ay(i)s'",
        // Each remaining type keyword, and the range edge of the narrow
        // integer types.
        "boolean true",
        "boolean false",
        "string 'x'",
        "int32 -5",
        "double 5",
        "int16 32767",
        "int16 -32768",
        "uint16 65535",
        "handle -1",
        "handle 2147483647",
        // A declaration ends at the character that closes the value around it,
        // which is `>` in a variant, `:` in a dict key, and `,` in a tuple.
        "<@u 5>",
        "{@s 'a': 5}",
        "(@u 5,)",
        "@a{sv} {'a': <@u 5>}",
        // An array settles one element type over every element, so a later
        // element states the type an earlier empty one could not.
        "[[], [1]]",
        "[@ai [], [1]]",
        "[nothing, just 'a']",
        // A tab separates the same way a space does.
        "\t42",
        "[1,\t2]",
        // The mantissa forms a decimal literal may leave out.
        "1.",
        ".5",
        "-.5",
        "1.e3",
        // A container nested to the depth both readers take.
        "[[[[[[[[[[1]]]]]]]]]]",
        // A dictionary takes its value type from the first entry, so the entry
        // order picks the stored type and the agreeing checksum states it.
        "{'a': 1, 'b': uint32 2}",
        "{'a': uint32 2, 'b': 1}",
        "{'a': 1.5, 'b': 1}",
        "{'a': just 'y', 'b': 'x'}",
        "{'a': [1], 'b': []}",
        "{'a': {'d': 2}, 'c': {}}",
        "{'a': 1, 'b': 2, 'c': uint32 3}",
        "{'a': uint32 1, 'b': 2, 'c': 3}",
        "{1: 'a', 2.5: 'b'}",
        // A type already in force takes the value beside a declaration and
        // drops the declaration, so `@o` under `s` stores a string and its
        // object-path check never runs.
        "{'a': 'x', 'b': @o '/y'}",
        "{'a': 'x', 'b': @o 'notapath'}",
        "{'a': 1, 'b': @mi 2}",
        "@as [@o '/a']",
        "@ai [@u 5]",
    ] {
        let (port, tool) = agrees(&[&format!("--add-metadata=k={value}")]);
        landed(&port, &tool, value, 0);
    }

    // Every refusal the reader gives, with the offsets it reports.
    for value in [
        "[]",
        "",
        "garbage syntax (((",
        "uint32 99999999999999999999",
        "'unterminated",
        "(1,2",
        "{'a':}",
        "nothing",
        "@i 'str'",
        "3000000000",
        "9223372036854775807",
        "18446744073709551615",
        "99999999999999999999",
        "uint32 -1",
        "uint32 4294967296",
        "byte 256",
        "0o17",
        "['a', 5]",
        "{'a': 'b', 'c': 5}",
        "42 43",
        "true false",
        "@u",
        "@",
        "[,]",
        "{}",
        "{'a'}",
        "(,)",
        "@b 1",
        "{[1]: 'a'}",
        "B",
        "_x",
        "Foo",
        "uint32x",
        "x1",
        "a",
        "%",
        "trueX",
        "aB",
        "ju st",
        // A one-member tuple needs its comma.
        "(1)",
        "('a')",
        "((1))",
        "@(i) (1)",
        "(1 2)",
        "(1,2,)",
        // The exponent marker is lower case in a literal with no type.
        "1E3",
        "1E",
        "0x1p3",
        // A subnormal is out of the range the reader takes.
        "5e-324",
        "1e-310",
        "1e-308",
        "1e400",
        "1.7976931348623157e309",
        // A hexadecimal body that rounds to a subnormal it does not state
        // exactly, and one over the double range.
        "@d 0x1.8p-1074",
        "@d 0x1.0000000000001p-1030",
        "@d 0x1.0000000000000000001p-1075",
        "@d 0x1p1024",
        "@d 0x1.fffffffffffff8p1023",
        "@d 0x1p2147483647",
        // The character each reader stopped at.
        "1.5.5",
        "1..5",
        "1e",
        "+",
        "++5",
        "--5",
        "0xg",
        "0b12",
        "0b1e1",
        "08",
        "0778",
        "-INF",
        "infinity",
        "nan5",
        "byte nan",
        "@i nan",
        "byte 1.5",
        "int32 1e3",
        "@d 0b101",
        "int64 -9223372036854775809",
        "-18446744073709551615",
        // The range of each narrow integer type, on both sides.
        "int16 32768",
        "int16 -32769",
        "uint16 65536",
        "uint16 -1",
        "handle 2147483648",
        "handle -2147483649",
        // A type keyword drives the check into the value beside it.
        "boolean 1",
        "string 5",
        // A literal whose quote never closes, with the backslash that reaches
        // the end of the text among them.
        "b'x",
        "'a\\",
        // An array whose elements all state nothing names the whole value.
        "[[], []]",
        // An object path and a signature are checked.
        "objectpath 'notapath'",
        "objectpath ''",
        "objectpath '/a/'",
        "objectpath '//'",
        // A path element takes letters, digits and the underscore alone.
        "objectpath '/a-b'",
        "objectpath '/a.b'",
        "objectpath '/a b'",
        "objectpath 'a/b'",
        "@o 'bad'",
        "signature 'zz'",
        "signature 'ms'",
        "@g 'zz'",
        // A signature body holds complete definite types alone: a tuple that
        // never closes, a closing bracket with no opening one, a dict entry
        // whose key is not basic, and each indefinite character.
        "signature '(i'",
        "signature 'i)'",
        "signature '{as}'",
        "signature '{sv'",
        "signature 'r'",
        "signature '*'",
        "signature '?'",
        // A declaration is scanned whole, and an indefinite one is named.
        "@z 5",
        "@r 5",
        "@* 5",
        "@? 5",
        "@m* 5",
        "@i5",
        "@ii",
        // A declaration drives the check into the members.
        "@as [1]",
        "@ai [1,'a']",
        "@a{ss} {'a': 5}",
        "@a{sv} {'a': 1}",
        "@ai 5",
        // The whole value is named where nothing in it states a type.
        "[[]]",
        "just []",
        "just nothing",
        "[nothing]",
        "nothing 5",
        "[<[]>]",
        "{nothing: 1}",
        "{'a': 1, 2: 'b'}",
        // The closing brackets each carry their own wording.
        "<1 2>",
        "{'a', 5, 6}",
        // A unicode escape names the digits that are there.
        "'\\uZZZZ'",
        "'\\u12'",
        "'\\U0001'",
        // An escape naming U+0000 is refused with the same words, at the
        // offset of the digits, wherever the literal stands.
        "'\\u0000'",
        "'\\U00000000'",
        "'a\\u0000b'",
        "'\\u0000x'",
        "@s '\\u0000'",
        "@o '/a\\u0000b'",
        "objectpath '\\u0000'",
        "@g '\\u0000'",
        "signature 'a\\u0000y'",
        "{'\\u0000': 1}",
        "{'a': '\\u0000'}",
        "['a', '\\u0000']",
        "<'\\u0000'>",
        "@ms '\\u0000'",
        "('\\u0000',)",
        // A later dictionary value is read against the type the first entry
        // settled, and the refusal names that type.
        "{'a': 1, 'b': 1.5}",
        "{'a': 'x', 'b': just 'y'}",
        "{'a': 1, 'b': just 2}",
        "{'a': @o '/y', 'b': 'x'}",
        "{'a': (1,2), 'b': ('x','y')}",
        "{'a': ('x','y'), 'b': (1,2)}",
        "{'a': 1, 'b': ['x', 5]}",
        "{'a': 1, 'b': 2, 'c': nothing}",
        "{'a': 1, 'b': @s 'x'}",
        "{'a': 5, 'b': []}",
        "{'a': 1, 'b': 0x1.8p1}",
        "{'a': 'y', 'b': nothing}",
        "@as [@i 5]",
        // A first value that states no type names the whole value, and no
        // later entry fills it in.
        "{'a': [], 'b': 5}",
        "{'a': [], 'b': [1]}",
        "{'a': nothing, 'b': 'y'}",
        "{'a': {}, 'c': {'d': 2}}",
        "{'q': {'a': [], 'b': 5}}",
        "<{'a': [], 'b': 5}>",
        "{'a': [], [1]: 5}",
    ] {
        let (port, tool) = agrees(&[&format!("--add-metadata=k={value}")]);
        landed(&port, &tool, value, 1);
    }

    // The nesting cap, at the level past the one both readers take. The offset
    // agrees for the brackets; `<`, `just`, a type keyword and a declaration
    // carry an offset the tool leaves uninitialized, which `cli-surface.md`
    // records as a divergence and no cell holds.
    for (open, close) in [("[", "]"), ("(", ")")] {
        for depth in [128usize, 129] {
            let value = format!("{}1{}", open.repeat(depth), close.repeat(depth));
            agrees(&[&format!("--add-metadata=k={value}")]);
        }
    }

    // The type-depth cap. A signature value is checked as a type string
    // alone, which takes 129 levels. A declaration takes the levels its type
    // carries counted from the level the declaration sits at, and 128 levels
    // in all.
    let arrays = |count: usize| "a".repeat(count);
    for value in [
        // Well inside both caps, where a reader carrying a lower one of its
        // own would already part from the tool.
        format!("signature '{}y'", arrays(65)),
        format!("@{}y []", arrays(65)),
        format!("@{}r 5", arrays(66)),
        format!("signature '{}y'", arrays(127)),
        format!("signature '{}y'", arrays(128)),
        format!("signature '{}y'", arrays(129)),
        format!("@g '{}y'", arrays(128)),
        format!("@g '{}y'", arrays(129)),
        format!("@{}y []", arrays(127)),
        format!("@{}y []", arrays(128)),
        format!("@{}y []", arrays(129)),
        // An indefinite declaration is named as such only where it is inside
        // the cap; past it the depth is named, and past the type-string limit
        // the declaration is invalid.
        format!("@{}r 5", arrays(127)),
        format!("@{}r 5", arrays(128)),
        format!("@{}r 5", arrays(129)),
        // The empty tuple carries no level of its own, so it reaches one
        // level deeper than a leaf, and a dict entry is measured by its value.
        format!("@{}() []", arrays(128)),
        format!("@{}() []", arrays(129)),
        format!("@{}(y) []", arrays(126)),
        format!("@{}(y) []", arrays(127)),
        format!("@{}{{s()}} []", arrays(127)),
        format!("@{}{{sy}} []", arrays(126)),
        format!("@{}{{sy}} []", arrays(127)),
        // A declaration inside a container counts from that container's level.
        format!("[@{}y []]", arrays(126)),
        format!("[@{}y []]", arrays(127)),
    ] {
        agrees(&[&format!("--add-metadata=k={value}")]);
    }

    // A missing `=` and an empty key, on each option that takes a pair.
    agrees(&["--add-metadata-string=noequals"]);
    agrees(&["--add-metadata-string==emptykey"]);
    agrees(&["--add-metadata=noequals"]);
    agrees(&["--add-metadata=='x'"]);
    agrees(&["--add-metadata==empty"]);
    agrees(&["--add-detached-metadata-string=noequals"]);
}

/// `commit --keep-metadata` carries a key over from the resolved parent, which
/// is `--parent` where it is given and the branch tip otherwise.
#[test]
fn commit_keep_metadata_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-keep-metadata");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    let mut cell = 0;
    let mut agrees = |extra: &[&str], timestamp: &str| {
        cell += 1;
        let mut args = vec!["commit", timestamp];
        args.extend_from_slice(extra);
        args.push(src);
        assert_agrees(&port_repo, &tool_repo, &args);
    };

    // The parent both sides then read from: one commit holding three keys, one
    // of them numeric so the carried bytes are checked as bytes.
    agrees(
        &[
            "-b",
            "main",
            "--add-metadata-string=k1=v1",
            "--add-metadata-string=k2=v2",
            "--add-metadata=k3=uint32 3",
        ],
        FIXED_TIMESTAMP,
    );
    let parent = ostrya(
        &["rev-parse", "--repo", port_repo.to_str().unwrap(), "main"],
        None,
        &[],
    )
    .ok()
    .stdout_trimmed();
    let explicit = format!("--parent={parent}");

    // Keys are carried in command-line order, after both add groups, and a key
    // given twice is carried twice.
    agrees(
        &[
            "-b",
            "k1",
            &explicit,
            "--keep-metadata=k2",
            "--keep-metadata=k1",
        ],
        FIXED_TIMESTAMP,
    );
    agrees(
        &["-b", "k3", &explicit, "--keep-metadata=k3"],
        FIXED_TIMESTAMP,
    );
    agrees(
        &["-b", "k4", &explicit, "--keep-metadata=ostree.ref-binding"],
        FIXED_TIMESTAMP,
    );
    agrees(
        &[
            "-b",
            "k5",
            &explicit,
            "--keep-metadata=k1",
            "--add-metadata-string=k1=override",
        ],
        FIXED_TIMESTAMP,
    );
    agrees(
        &[
            "-b",
            "k6",
            &explicit,
            "--keep-metadata=k1",
            "--keep-metadata=k1",
        ],
        FIXED_TIMESTAMP,
    );
    agrees(
        &[
            "-b",
            "k7",
            &explicit,
            "--add-metadata=z='zz'",
            "--keep-metadata=k1",
            "--add-metadata-string=s=ss",
        ],
        FIXED_TIMESTAMP,
    );
    // `--no-bindings` suppresses the automatic key alone, so one carried by
    // hand survives it.
    agrees(
        &[
            "-b",
            "k8",
            &explicit,
            "--no-bindings",
            "--keep-metadata=ostree.ref-binding",
        ],
        FIXED_TIMESTAMP,
    );
    // The branch tip is the implicit parent, and `--orphan` beside an explicit
    // `--parent` still reads that parent.
    agrees(
        &["-b", "main", "--keep-metadata=k1"],
        "--timestamp=@1700000001",
    );
    agrees(
        &["--orphan", &explicit, "--keep-metadata=k1"],
        FIXED_TIMESTAMP,
    );

    // The refusals: a key the parent does not hold, and every shape that
    // resolves no parent at all.
    agrees(
        &["-b", "main", &explicit, "--keep-metadata=nosuch"],
        FIXED_TIMESTAMP,
    );
    agrees(&["--orphan", "--keep-metadata=k1"], FIXED_TIMESTAMP);
    agrees(&["-b", "brandnew", "--keep-metadata=k1"], FIXED_TIMESTAMP);
    agrees(
        &["-b", "main", "--parent=none", "--keep-metadata=k1"],
        FIXED_TIMESTAMP,
    );
}

/// A commit metadata dict holding several keys in an order that is neither the
/// command-line order nor a sorted one reaches one checksum in both
/// implementations, and every key of it reads back by name.
#[test]
fn commit_metadata_reads_back_in_any_key_order() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-metadata-order");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    // The option groups put both `--add-metadata` keys after both
    // `--add-metadata-string` keys, so the dict stands as `zulu`, `alpha`,
    // `mike`, `bravo`, `ostree.ref-binding`. That order is the command line's
    // order under neither reading and is sorted under none. The agreeing
    // checksum states the stored bytes, the entry order among them.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "order",
            "-s",
            "x",
            FIXED_TIMESTAMP,
            "--add-metadata-string=zulu=z",
            "--add-metadata=mike='m'",
            "--add-metadata-string=alpha=a",
            "--add-metadata=bravo=uint64 4",
            src,
        ],
    );

    // Every key reads back by name, whatever slot it stands in, and both
    // implementations print the same value for it.
    for key in ["zulu", "alpha", "mike", "bravo", "ostree.ref-binding"] {
        let arg = format!("--print-metadata-key={key}");
        assert_agrees(&port_repo, &tool_repo, &["show", &arg, "order"]);
    }

    // The listing sorts the names, so it states nothing about the stored order
    // and reaches the same five keys on both sides.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["show", "--list-metadata-keys", "order"],
    );
}

/// A metadata key given twice stands twice in the dict, and a read-back by that
/// name reaches the entry standing first in both implementations.
#[test]
fn commit_duplicate_metadata_key_reads_back_the_first() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-metadata-duplicate");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    // The agreeing checksum states that both entries stand, which is what
    // `commit/metadata-duplicate-key` holds.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "dup",
            "-s",
            "x",
            FIXED_TIMESTAMP,
            "--add-metadata-string=foo=first",
            "--add-metadata-string=foo=second",
            src,
        ],
    );

    // The name reaches the first of the two entries, so the slot an entry
    // stands in decides the value a reader by name gets.
    let args = ["show", "--print-metadata-key=foo", "dup"];
    let (port, tool) = run_both(&port_repo, &tool_repo, &args);
    assert_runs_agree(&port, &tool, &args.join(" "));
    assert_eq!(
        tool.stdout_trimmed(),
        "'first'",
        "the name reaches the entry standing first"
    );
}

/// `commit --add-detached-metadata-string` writes the `.commitmeta` file beside
/// the commit and leaves the commit checksum alone.
#[test]
fn commit_detached_metadata_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-detached");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    let mut cell = 0;
    let mut agrees = |extra: &[&str]| {
        cell += 1;
        let branch = format!("det{cell}");
        let mut args = vec!["commit", "-b", &branch, FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        args.push(src);
        assert_agrees(&port_repo, &tool_repo, &args);
        let checksum = ostrya(
            &["rev-parse", "--repo", port_repo.to_str().unwrap(), &branch],
            None,
            &[],
        )
        .ok()
        .stdout_trimmed();
        // The detached file is outside the commit object, so it is compared as
        // bytes at the loose path both implementations write it to.
        let relative = format!("objects/{}/{}.commitmeta", &checksum[..2], &checksum[2..]);
        let written = std::fs::read(port_repo.join(&relative)).unwrap_or_else(|err| {
            panic!("`{}` wrote no detached metadata: {err}", extra.join(" "))
        });
        assert!(
            !written.is_empty(),
            "`{}` wrote an empty detached file",
            extra.join(" "),
        );
        assert_eq!(
            Some(written),
            std::fs::read(tool_repo.join(&relative)).ok(),
            "`{}` wrote different detached metadata",
            extra.join(" "),
        );
        // And the key listing both report over it.
        assert_agrees(
            &port_repo,
            &tool_repo,
            &["show", "--list-detached-metadata-keys", &branch],
        );
    };
    agrees(&["--add-detached-metadata-string=dk=dv"]);
    agrees(&[
        "--add-detached-metadata-string=a=1",
        "--add-detached-metadata-string=b=2",
    ]);
    agrees(&[
        "--add-detached-metadata-string=dup=one",
        "--add-detached-metadata-string=dup=two",
    ]);
    // An empty key is accepted here, unlike the two commit-metadata options.
    agrees(&["--add-detached-metadata-string==x"]);
    agrees(&["--add-detached-metadata-string=k="]);
    agrees(&[
        "--add-detached-metadata-string=x=y",
        "--add-metadata-string=m=n",
    ]);
}

/// `commit --bind-ref` and `--no-bindings` control `ostree.ref-binding` and
/// `ostree.collection-binding`.
#[test]
fn commit_ref_bindings_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-bindings");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    let mut cell = 0;
    let mut agrees = |extra: &[&str], branch: Option<&str>| {
        cell += 1;
        let named = branch.map(str::to_owned).unwrap_or(format!("bind{cell}"));
        let mut args = vec!["commit", FIXED_TIMESTAMP];
        if branch == Some("") {
            args.push("--orphan");
        } else {
            args.extend_from_slice(&["-b", &named]);
        }
        args.extend_from_slice(extra);
        args.push(src);
        assert_agrees(&port_repo, &tool_repo, &args);
    };

    // The array holds the branch and every bound name, sorted byte-wise
    // ascending, with duplicates kept and no name rule applied.
    agrees(&["--bind-ref=extra"], None);
    agrees(&["--bind-ref=e1", "--bind-ref=e2"], None);
    agrees(&["--bind-ref=aaa", "--bind-ref=mmm"], Some("zzz"));
    agrees(
        &["--bind-ref=B", "--bind-ref=a", "--bind-ref=C"],
        Some("s1"),
    );
    agrees(
        &["--bind-ref=b/z", "--bind-ref=b.a", "--bind-ref=b-a"],
        Some("s2"),
    );
    agrees(
        &["--bind-ref=10", "--bind-ref=9", "--bind-ref=2"],
        Some("s4"),
    );
    agrees(
        &["--bind-ref=zzz", "--bind-ref=aaa", "--bind-ref=aaa"],
        Some("s3"),
    );
    agrees(&["--bind-ref=b5"], Some("b5"));
    for name in [
        "bad name",
        "bad//name",
        "-leading",
        "has^caret",
        ".dotstart",
        "trail/",
        "",
        "UPPER/ok",
        "nul\ttab",
    ] {
        agrees(&[&format!("--bind-ref={name}")], None);
    }
    // The 64-lowercase-hex name `-b` refuses is a name `--bind-ref` accepts, so
    // the guard covers the ref the command writes and not the name it records.
    agrees(
        &["--bind-ref=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        Some("okbr"),
    );

    // `--no-bindings` writes no binding key at all and overrides `--bind-ref`,
    // so a commit that adds nothing else reaches one object whatever it names.
    agrees(&["--no-bindings"], Some("b2"));
    agrees(&["--no-bindings", "--bind-ref=x"], Some("b6"));
    agrees(&["--no-bindings"], Some(""));
    let collapsed: Vec<String> = [
        vec![
            "commit",
            "-b",
            "b2",
            "--parent=none",
            FIXED_TIMESTAMP,
            "--no-bindings",
            src,
        ],
        vec!["commit", "--orphan", FIXED_TIMESTAMP, "--no-bindings", src],
        vec![
            "commit",
            "-b",
            "b6",
            "--parent=none",
            FIXED_TIMESTAMP,
            "--no-bindings",
            "--bind-ref=x",
            src,
        ],
    ]
    .iter()
    .map(|args| {
        let mut argv = vec!["--repo", port_repo.to_str().unwrap()];
        argv.extend(args.iter().copied());
        ostrya(&argv, None, &[]).ok().stdout_trimmed()
    })
    .collect();
    for checksum in &collapsed {
        assert_eq!(
            checksum, &collapsed[0],
            "--no-bindings did not collapse the three onto one commit",
        );
    }

    // `--orphan` writes the key with an empty array, and `--bind-ref` beside it
    // fills that array with the bound names alone.
    agrees(&[], Some(""));
    agrees(&["--bind-ref=only"], Some(""));
    agrees(&["--bind-ref=zz", "--bind-ref=aa"], Some(""));
    // `--bind-ref` names no branch, so a commit carrying it alone is refused by
    // the ordinary branch check.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["commit", FIXED_TIMESTAMP, "--bind-ref=noBranch", src],
    );

    // A repository carrying a collection id writes the second binding key after
    // the first, and `--no-bindings` removes both.
    let collection = base.join("collection");
    std::fs::create_dir_all(&collection).unwrap();
    let mut repos = Vec::new();
    for name in ["port", "tool"] {
        let repo = collection.join(name);
        let argv = [
            "init",
            "--repo",
            repo.to_str().unwrap(),
            "--mode=archive",
            "--collection-id=org.example.Test",
        ];
        if name == "port" {
            ostrya(&argv, None, &[]).ok();
        } else {
            assert!(ostree(&argv).status.success(), "ostree init failed");
        }
        repos.push(repo);
    }
    let mut collection_checksums = Vec::new();
    for extra in [
        vec!["-b", "cb1"],
        vec!["-b", "cb2", "--bind-ref=extra"],
        vec!["-b", "cb3", "--no-bindings"],
        vec!["--orphan"],
        vec!["-b", "cb5", "--add-metadata-string=zz=1"],
    ] {
        let mut args = vec!["commit", FIXED_TIMESTAMP];
        args.extend_from_slice(&extra);
        args.push(src);
        let (port, tool) = run_both(&repos[0], &repos[1], &args);
        assert_runs_agree(&port, &tool, &args.join(" "));
        collection_checksums.push(port.stdout_trimmed());
    }

    // The dict itself, read back out of each repository by that implementation's
    // own `show --raw`: the second binding key stands after the first, a
    // `--bind-ref` name reaches the first key alone, and `--no-bindings` leaves
    // neither. The four invocations above agree with each other, so the read-back
    // is what states the order and the removal.
    let raw = |repo: &Path, checksum: &str, port: bool| -> String {
        let repo_arg = format!("--repo={}", repo.display());
        let args = ["show", &repo_arg, "--raw", checksum];
        let run = if port {
            ostrya(&args, None, &[])
        } else {
            ostree(&args)
        };
        assert!(
            run.status.success(),
            "`show --raw {checksum}` failed:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
        String::from_utf8(run.stdout).expect("the printed dict is text")
    };
    let collection = "'ostree.collection-binding': <'org.example.Test'>";
    for (repo, port) in [(&repos[0], true), (&repos[1], false)] {
        // The plain branch, the bound name beside it, and the orphan: the ref
        // binding stands first and the collection binding follows it.
        for (checksum, names) in [
            (&collection_checksums[0], "'ostree.ref-binding': <['cb1']>"),
            (
                &collection_checksums[1],
                "'ostree.ref-binding': <['cb2', 'extra']>",
            ),
            (&collection_checksums[3], "'ostree.ref-binding': <@as []>"),
        ] {
            let text = raw(repo, checksum, port);
            let bound = text
                .find(names)
                .unwrap_or_else(|| panic!("{names} is absent from the metadata:\n{text}"));
            let bound_collection = text
                .find(collection)
                .unwrap_or_else(|| panic!("{collection} is absent from the metadata:\n{text}"));
            assert!(
                bound < bound_collection,
                "the collection binding stands ahead of the ref binding:\n{text}"
            );
        }
        // `--no-bindings` removes both keys.
        let text = raw(repo, &collection_checksums[2], port);
        for key in ["ostree.ref-binding", "ostree.collection-binding"] {
            assert!(
                !text.contains(key),
                "`--no-bindings` left `{key}` in the metadata:\n{text}"
            );
        }
    }
}

/// Every GVariant type prints, the ones outside the on-disk format among them.
/// Each case is one normal-form file read under one signature, compared against
/// the tool (`docs/format-reference.md`, "The GVariant text form").
#[test]
fn show_prints_every_variant_type_the_tool_prints() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("variant-type-all");
    let base = tmp.path();
    let repo = create_repo(base, RepoMode::Archive);
    let cases: &[(&str, &[u8])] = &[
        ("y", &[0x2a]),
        ("b", &[0x01]),
        ("q", &[0x2a, 0x00]),
        ("n", &[0xfb, 0xff]),
        ("i", &[0x2a, 0x00, 0x00, 0x00]),
        ("u", &[0x2a, 0x00, 0x00, 0x00]),
        ("h", &[0x07, 0x00, 0x00, 0x00]),
        ("x", &[0x2a, 0, 0, 0, 0, 0, 0, 0]),
        ("t", &[0x2a, 0, 0, 0, 0, 0, 0, 0]),
        ("d", &[0, 0, 0, 0, 0, 0, 0xf8, 0x3f]),
        ("o", b"/a/b\0"),
        ("g", b"ay\0"),
        ("s", b"hi\0"),
        ("ms", b"hi\0\0"),
        ("ms", b""),
        ("mi", &[0x2a, 0x00, 0x00, 0x00]),
    ];
    for (index, (signature, bytes)) in cases.iter().enumerate() {
        let path = base.join(format!("value{index}"));
        std::fs::write(&path, bytes).unwrap();
        let type_arg = format!("--print-variant-type={signature}");
        let repo_arg = format!("--repo={}", repo.display());
        let args = [&repo_arg, "show", &type_arg, path.to_str().unwrap()];
        let port = ostrya(&args, None, &[]);
        let tool = ostree(&args);
        assert_runs_agree(&port, &tool, &type_arg);
    }
}

// --- Phase 17f, F5 and F6: the walk modifiers and the checkout speedup -------
//
// These five tests are the `evidence:` the M10 records under `commit` cite for
// the cases a single `run:` line cannot state: every one of them needs a
// control file, a checkout, or a second invocation reading what the first left.
// Each builds one source tree and gives each implementation its own repository,
// so the commit checksum both print is the comparison.

/// Build the F5 source tree: two directories, a symlink, and regular files
/// covering the execute-bit and special-bit cases `--mode-ro-executables`
/// distinguishes.
fn build_walk_source(base: &Path) -> PathBuf {
    let src = base.join("walk");
    std::fs::create_dir_all(src.join("dir1/sub")).unwrap();
    std::fs::create_dir_all(src.join("dir2")).unwrap();
    let write = |rel: &str, mode: u32| {
        let path = src.join(rel);
        std::fs::write(&path, format!("{rel}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    write("plain.txt", 0o644);
    write("run.sh", 0o755);
    write("roexec", 0o555);
    write("grpx", 0o754);
    write("setuid", 0o4755);
    write("setgid", 0o2755);
    write("sticky", 0o1777);
    write("groupexec", 0o610);
    write("otherexec", 0o601);
    write("dir1/a.txt", 0o640);
    write("dir1/x.sh", 0o775);
    write("dir1/sub/deep.txt", 0o600);
    write("dir2/b.txt", 0o644);
    std::os::unix::fs::symlink("plain.txt", src.join("link")).unwrap();
    for (rel, mode) in [("dir1", 0o700u32), ("dir1/sub", 0o755), ("dir2", 0o750)] {
        std::fs::set_permissions(src.join(rel), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755)).unwrap();
    src
}

/// Compare a `commit` invocation, with the `Unmatched ... path:` lines of both
/// sides sorted before the comparison.
///
/// The tool emits those lines in a hash order rather than the file order, so
/// the two implementations agree on the set and not on the sequence
/// (`docs/conformance/cli-surface.md`, "P2").
fn assert_agrees_unordered(port_repo: &Path, tool_repo: &Path, args: &[&str]) {
    let (port, tool) = run_both(port_repo, tool_repo, args);
    let sorted = |run: &Run| {
        let text = String::from_utf8_lossy(&run.stderr).into_owned();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.sort_unstable();
        format!(
            "exit {:?}\nstdout: {:?}\nstderr: {:?}",
            run.status.code(),
            String::from_utf8_lossy(&run.stdout),
            lines.join("\n"),
        )
    };
    assert_eq!(
        sorted(&port),
        sorted(&tool),
        "`commit {}` disagrees",
        args.join(" ")
    );
}

/// `commit --statoverride=PATH` reads its file the same way in both
/// implementations: the entry syntax, the mode arithmetic, the entries it
/// applies to, and the three refusals.
#[test]
fn commit_statoverride_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-statoverride");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let tree = build_walk_source(base);
    let src = tree.to_str().unwrap();

    let mut cell = 0;
    let mut file = |body: &str| -> String {
        cell += 1;
        let path = base.join(format!("so{cell}.txt"));
        std::fs::write(&path, body).unwrap();
        format!("--statoverride={}", path.display())
    };
    let mut branch = 0;
    let mut agrees = |option: &str, unordered: bool| {
        branch += 1;
        let name = format!("t{branch}");
        let args = ["commit", "-b", &name, FIXED_TIMESTAMP, option, src];
        if unordered {
            assert_agrees_unordered(&port_repo, &tool_repo, &args);
        } else {
            assert_agrees(&port_repo, &tool_repo, &args);
        }
    };

    // The mode is read in base 10 and ORed into the entry's own mode; an `=`
    // prefix states the permission bits instead, the file-type bits staying.
    agrees(&file("8 /plain.txt\n"), false);
    agrees(
        &file("=384 /plain.txt\n=448 /dir2/b.txt\n8 /grpx\n=511 /dir1\n"),
        false,
    );
    agrees(&file("=4095 /plain.txt\n"), false);
    agrees(&file("=2048 /plain.txt\n"), false);
    agrees(&file("=33261 /plain.txt\n"), false);
    // The root directory, a nested file, and a symlink are all valid targets,
    // and an entry over a directory is not recursive.
    agrees(&file("=511 /\n"), false);
    agrees(&file("=448 /dir1/sub/deep.txt\n"), false);
    agrees(&file("=448 /link\n"), false);
    agrees(&file("=511 /dir1\n"), false);
    // A value whose file-type bits land inside the symlink's own leaves a
    // symlink, permission bits and all.
    agrees(&file("=32768 /link\n"), false);
    agrees(&file("=8192 /link\n"), false);
    agrees(&file("=33261 /link\n"), false);
    // A path named more than once by one form takes the value of the last line
    // naming it, and the OR form stands ahead of the `=` form for a path both
    // forms name, whichever order the two lines come in. A value of zero under
    // the OR form still shadows the `=` entry.
    agrees(&file("=448 /plain.txt\n=511 /plain.txt\n"), false);
    agrees(&file("=511 /plain.txt\n=448 /plain.txt\n"), false);
    agrees(&file("8 /plain.txt\n16 /plain.txt\n"), false);
    agrees(&file("448 /plain.txt\n=511 /plain.txt\n"), false);
    agrees(&file("=511 /plain.txt\n448 /plain.txt\n"), false);
    agrees(&file("=511 /plain.txt\n0 /plain.txt\n"), false);
    agrees(
        &file("1 /plain.txt\n=448 /plain.txt\n2 /plain.txt\n"),
        false,
    );
    agrees(&file("448 /link\n=511 /link\n"), false);
    // A directory below the walk root of this filesystem source spends the OR
    // entry and takes no value from it: the entry counts as matched and the mode
    // stays what the walk found, or what an `=` entry over the same path states.
    // The walk root takes the OR form as a file does.
    // `commit_statoverride_spends_one_entry_per_run` states the archive member
    // that takes the value, and the spend rule over more than one source.
    agrees(&file("16 /dir1\n"), false);
    agrees(&file("2048 /dir1/sub\n"), false);
    agrees(&file("16 /dir1\n=8 /dir1\n"), false);
    agrees(&file("=8 /dir1\n16 /dir1\n"), false);
    agrees(&file("16 /\n"), false);
    agrees(&file("16 /\n=8 /\n"), false);
    // Blank lines are ignored, an empty file changes nothing, and a missing
    // final newline is accepted.
    agrees(&file("\n8 /plain.txt\n\n"), false);
    agrees(&file(""), false);
    agrees(&file("8 /plain.txt"), false);
    // A mode field holding no digit is the value zero.
    agrees(&file("abc /plain.txt\n"), false);
    agrees(&file("= /plain.txt\n"), false);
    agrees(&file("=abc /plain.txt\n"), false);
    // A sign and leading zeros belong to the field: `+448` and `0000448` are
    // the value 448 under either form, and `-0` is zero. A reader dropping the
    // sign or stopping at the zeros would reach another mode than the tool's.
    agrees(&file("+448 /plain.txt\n"), false);
    agrees(&file("0000448 /plain.txt\n"), false);
    agrees(&file("=+448 /plain.txt\n"), false);
    agrees(&file("=0000448 /plain.txt\n"), false);
    agrees(&file("-0 /plain.txt\n"), false);
    // An `=` entry matching nothing is ignored; every other entry that matched
    // nothing is reported, the raw text after the first space being what the
    // report names.
    agrees(&file("=448 /nope\n"), false);
    agrees(&file("448 /nope.txt\n"), true);
    agrees(&file("448 /z1\n448 /a2\n448 /m3\n448 /b4\n448 /y5\n"), true);
    {
        // The one thing the two do not share, held in the direction measured:
        // the port reports each unmatched path in the order the file first
        // names it and the tool reports them in a hash order
        // (`docs/conformance/cli-surface.md`, "P2"). The run exits 1 on both
        // sides, standard output stays empty, and each path draws one line.
        let option = file("448 /z1\n448 /a2\n448 /m3\n448 /b4\n448 /y5\n");
        let args = ["commit", "-b", "unmatched", FIXED_TIMESTAMP, &option, src];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let reported = |run: &Run| -> Vec<String> {
            String::from_utf8_lossy(&run.stderr)
                .lines()
                .filter_map(|line| {
                    line.strip_prefix("Unmatched statoverride path: ")
                        .map(str::to_owned)
                })
                .collect()
        };
        for (who, run) in [("port", &port), ("tool", &tool)] {
            assert_eq!(run.status.code(), Some(1), "the {who} accepted the file");
            assert!(run.stdout.is_empty(), "the {who} printed output");
        }
        assert_eq!(
            reported(&port),
            ["/z1", "/a2", "/m3", "/b4", "/y5"],
            "the port left the order the file names",
        );
        assert_eq!(
            reported(&tool),
            ["/z1", "/a2", "/b4", "/m3", "/y5"],
            "the tool's recorded hash order moved",
        );
        // One line per path, whichever form names it and however often.
        let once = file("448 /nope\n449 /nope\n=450 /nope\n");
        let args = ["commit", "-b", "once", FIXED_TIMESTAMP, &once, src];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        for (who, run) in [("port", &port), ("tool", &tool)] {
            assert_eq!(
                reported(run),
                ["/nope"],
                "the {who} reported the path more than once",
            );
        }
    }
    // A path named more than once is reported once, and an `=` entry over the
    // same path adds no line of its own.
    agrees(&file("448 /nope\n449 /nope\n"), true);
    agrees(&file("448 /nope\n=449 /nope\n"), true);
    agrees(&file("=449 /nope\n448 /nope\n"), true);
    agrees(&file("448  /plain.txt\n"), true);
    agrees(&file(" 448 /plain.txt\n"), true);
    agrees(&file("448 1 2 /plain.txt\n"), true);
    agrees(&file("448 plain.txt\n"), true);
    agrees(&file("448 /dir1/\n"), true);
    // A line with no space, a path that does not open, and a directory.
    agrees(&file("448\n"), false);
    agrees(&file("/plain.txt\n"), false);
    agrees(&file("448\t/plain.txt\n"), false);
    agrees(
        &format!("--statoverride={}", base.join("absent").display()),
        false,
    );
    agrees(&format!("--statoverride={src}"), false);

    // Given more than once, the last value replaces the earlier ones.
    let first = file("448 /nope\n");
    let second = file("8 /plain.txt\n");
    branch += 1;
    let name = format!("t{branch}");
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["commit", "-b", &name, FIXED_TIMESTAMP, &first, &second, src],
    );

    // A byte the file cannot hold refuses the whole file at exit 1, with
    // `error: Invalid UTF-8` alone on standard error, nothing on standard
    // output, and no ref written. Two paths differing only in such a byte would
    // otherwise collapse to one string and match the wrong entry. The check
    // covers the whole file and stands ahead of the walk, ahead of the other
    // control file's unmatched report, and ahead of a tree path that does not
    // open, which the last three rows state.
    let unmatched_skip = base.join("enc-unmatched.txt");
    std::fs::write(&unmatched_skip, "/nope\n").unwrap();
    let unmatched_skip = format!("--skip-list={}", unmatched_skip.display());
    let prune_root = base.join("enc-root.txt");
    std::fs::write(&prune_root, "/\n").unwrap();
    let prune_root = format!("--skip-list={}", prune_root.display());
    let absent_tree = base.join("no-such-tree");
    let absent_tree = absent_tree.to_str().unwrap();
    for (body, extra, source) in [
        (b"=448 /bad\xff.txt\n".to_vec(), None, src),
        (b"=448 /plain.txt\n=511 /bad\xff.txt\n".to_vec(), None, src),
        (b"448 /plain\0.txt\n".to_vec(), None, src),
        (b"448 /bad\xff.txt\n448 /bad\xfe.txt\n".to_vec(), None, src),
        (
            b"=448 /bad\xff.txt\n".to_vec(),
            Some(unmatched_skip.as_str()),
            src,
        ),
        (
            b"=448 /bad\xff.txt\n".to_vec(),
            Some(prune_root.as_str()),
            src,
        ),
        (b"=448 /bad\xff.txt\n".to_vec(), None, absent_tree),
    ] {
        cell += 1;
        branch += 1;
        let path = base.join(format!("so{cell}.txt"));
        std::fs::write(&path, &body).unwrap();
        let option = format!("--statoverride={}", path.display());
        let name = format!("t{branch}");
        let mut args = vec!["commit", "-b", &name, FIXED_TIMESTAMP, &option];
        args.extend(extra);
        args.push(source);
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let label = args.join(" ");
        assert_runs_agree(&port, &tool, &label);
        for (who, run) in [("port", &port), ("tool", &tool)] {
            assert_eq!(
                run.status.code(),
                Some(1),
                "the {who} did not refuse `{label}`",
            );
            assert!(
                run.stdout.is_empty(),
                "the {who} printed output for `{label}`",
            );
            assert_eq!(
                String::from_utf8_lossy(&run.stderr).trim(),
                "error: Invalid UTF-8",
                "the {who} refused `{label}` in other words",
            );
        }
        for repo in [&port_repo, &tool_repo] {
            assert!(
                !repo.join("refs/heads").join(&name).exists(),
                "`{label}` wrote a ref",
            );
        }
    }

    // `--canonical-permissions` stands last of the three mode modifiers, so the
    // reduction states the mode a `--statoverride` entry ends at. This is the
    // pair that breaks commutativity: the other two modifiers are AND masks and
    // commute with the reduction, where an `=` entry assigns and a plain entry
    // ORs. The reduction also restores the file type the walk found, so a value
    // carrying file-type bits of its own leaves the entry the kind it is.
    // The mode one entry ends at, read out of the committed tree, so the order
    // of the three modifiers is stated and not inferred from the checksum. The
    // reverse order would leave `-00777`, `-04000`, and `d00777`.
    let row = |repo: &Path, rev: &str, path: &str, port: bool| -> String {
        let repo_arg = format!("--repo={}", repo.display());
        let args = ["ls", &repo_arg, "-R", rev];
        let run = if port {
            ostrya(&args, None, &[])
        } else {
            ostree(&args)
        };
        assert!(
            run.status.success(),
            "`ls -R {rev}` failed:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
        let listing = String::from_utf8(run.stdout).expect("the listing is text");
        listing
            .lines()
            .find(|line| line.ends_with(path))
            .unwrap_or_else(|| panic!("`{path}` is absent from `ls -R {rev}`:\n{listing}"))
            .split_whitespace()
            .next()
            .expect("a mode column")
            .to_owned()
    };
    for (body, extra, path, mode) in [
        ("=511 /plain.txt\n", None, Some("/plain.txt"), "-00755"),
        ("=2048 /dir1/a.txt\n", None, Some("/dir1/a.txt"), "-00000"),
        ("146 /roexec\n", None, Some("/roexec"), "-00755"),
        ("=511 /\n", None, Some(" /"), "d00755"),
        ("=511 /dir1\n", None, Some("/dir1"), "d00755"),
        ("=33261 /dir1\n", None, Some("/dir1"), "d00755"),
        ("=4096 /plain.txt\n", None, Some("/plain.txt"), "-00000"),
        ("=16384 /plain.txt\n", None, Some("/plain.txt"), "-00000"),
        ("=40960 /plain.txt\n", None, Some("/plain.txt"), "-00000"),
        ("=49152 /dir1\n", None, Some("/dir1"), "d00000"),
        // All three mode modifiers on one command line: the rule runs first,
        // the entry states the mode next, and the reduction stands last.
        (
            "=511 /roexec\n",
            Some("--mode-ro-executables"),
            Some("/roexec"),
            "-00755",
        ),
    ] {
        cell += 1;
        branch += 1;
        let path_file = base.join(format!("so{cell}.txt"));
        std::fs::write(&path_file, body).unwrap();
        let option = format!("--statoverride={}", path_file.display());
        let name = format!("t{branch}");
        let mut args = vec![
            "commit",
            "-b",
            &name,
            FIXED_TIMESTAMP,
            "--canonical-permissions",
            &option,
        ];
        args.extend(extra);
        args.push(src);
        assert_agrees(&port_repo, &tool_repo, &args);
        if let Some(path) = path {
            for (repo, port) in [(&port_repo, true), (&tool_repo, false)] {
                assert_eq!(
                    row(repo, &name, path, port),
                    mode,
                    "`{body}` ended at another mode for `{path}`",
                );
            }
        }
    }

    // A `--skip-list` beside the statoverride file. A path the skip list prunes
    // counts as reached, so the entry naming it draws no report, whichever form
    // it takes and whichever order the command line gives the two options. A
    // path below a pruned directory is one the walk never reached. The walk root
    // counts as reached even where the skip list prunes it, which leaves the
    // empty-tree refusal alone to report.
    for (over, skip, reversed) in [
        ("16 /plain.txt\n", "/plain.txt\n", false),
        ("16 /dir1\n", "/dir1\n", false),
        ("16 /dir1/sub\n", "/dir1/sub\n", false),
        ("16 /link\n", "/link\n", false),
        ("16 /dir2\n", "/dir2\n", false),
        ("=448 /plain.txt\n", "/plain.txt\n", false),
        ("16 /plain.txt\n=448 /plain.txt\n", "/plain.txt\n", false),
        ("16 /dir1/a.txt\n", "/dir1\n", false),
        ("16 /dir1/sub\n", "/dir1\n", false),
        ("16 /dir1/sub/deep.txt\n", "/dir1\n", false),
        ("16 /nope\n", "/nope\n", false),
        ("16 /plain.txt\n16 /absent\n", "/plain.txt\n", false),
        ("16 /\n", "/\n", false),
        ("16 /plain.txt\n", "/plain.txt\n", true),
        ("16 /dir1/a.txt\n", "/dir1\n", true),
    ] {
        cell += 1;
        branch += 1;
        let over_path = base.join(format!("so{cell}.txt"));
        let skip_path = base.join(format!("sk{cell}.txt"));
        std::fs::write(&over_path, over).unwrap();
        std::fs::write(&skip_path, skip).unwrap();
        let over_option = format!("--statoverride={}", over_path.display());
        let skip_option = format!("--skip-list={}", skip_path.display());
        let (first, second) = if reversed {
            (&skip_option, &over_option)
        } else {
            (&over_option, &skip_option)
        };
        let name = format!("t{branch}");
        assert_agrees_unordered(
            &port_repo,
            &tool_repo,
            &["commit", "-b", &name, FIXED_TIMESTAMP, first, second, src],
        );
    }
}

/// An OR-form `--statoverride` entry reaches one entry of the tree per run: the
/// first entry any source offers under the path spends it, and a later source
/// under that path keeps the mode it brought. A directory below the walk root
/// spends the entry and takes no value from it, except over an archive member,
/// where the OR value reaches a directory as well. The `=` form is not spent and
/// applies in every source (`docs/format-reference.md`, "CLI output formats",
/// `commit`).
#[test]
fn commit_statoverride_spends_one_entry_per_run() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-statoverride-spend");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let root = build_overlay_sources(base);
    // `t1` and `t2` hold `/common`, `/f.txt`, and `/link` alike and differ in
    // the content of each, so the source a path ended at is visible. Each is
    // packed as well, giving the same corpus as an archive.
    let dir1 = format!("--tree=dir={}", root.join("t1").display());
    let dir2 = format!("--tree=dir={}", root.join("t2").display());
    let a1 = base.join("a1.tar");
    let a2 = base.join("a2.tar");
    pack_tar(&root.join("t1"), &a1);
    pack_tar(&root.join("t2"), &a2);
    let tar1 = format!("--tree=tar={}", a1.display());
    let tar2 = format!("--tree=tar={}", a2.display());
    // A `ref=` source of the same corpus, the third source kind.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["commit", "-b", "seed", FIXED_TIMESTAMP, &dir1],
    );
    let ref1 = "--tree=ref=seed".to_owned();

    let mut cell = 0;
    let mut file = |body: &str| -> String {
        cell += 1;
        let path = base.join(format!("sp{cell}.txt"));
        std::fs::write(&path, body).unwrap();
        format!("--statoverride={}", path.display())
    };
    let mut branch = 0;
    let mut agrees = |option: &str, sources: &[&String]| -> String {
        branch += 1;
        let name = format!("s{branch}");
        let mut args = vec!["commit", "-b", &name, FIXED_TIMESTAMP, option];
        args.extend(sources.iter().map(|source| source.as_str()));
        assert_agrees(&port_repo, &tool_repo, &args);
        name
    };
    // The mode one path ended at, read out of both repositories, so each arm
    // states the rule and does not merely state that the two sides agree.
    let mode = |branch: &str, path: &str| -> String {
        let mut recorded = Vec::new();
        for (repo, port) in [(&port_repo, true), (&tool_repo, false)] {
            let repo_arg = format!("--repo={}", repo.display());
            let args = ["ls", &repo_arg, "-R", branch];
            let run = if port {
                ostrya(&args, None, &[])
            } else {
                ostree(&args)
            };
            let listing = run.ok().stdout_trimmed();
            let row = listing
                .lines()
                .find(|line| line.split_whitespace().nth(4) == Some(path))
                .unwrap_or_else(|| panic!("`{path}` is absent from `ls -R {branch}`:\n{listing}"))
                .to_owned();
            recorded.push(row.split_whitespace().next().unwrap().to_owned());
        }
        assert_eq!(
            recorded[0], recorded[1],
            "the two implementations recorded different modes for `{path}` on `{branch}`",
        );
        recorded.pop().unwrap()
    };

    // One source. A directory below the walk root takes no value from the OR
    // form over a `dir=` walk and over a `ref=` source, and takes it over an
    // archive member. The `=` form reaches the directory from all three.
    let over_dir = file("16 /common\n");
    let assign_dir = file("=504 /common\n");
    for source in [&dir1, &ref1] {
        let name = agrees(&over_dir, &[source]);
        assert_eq!(
            mode(&name, "/common"),
            "d00755",
            "the OR form reached a directory below the walk root of `{source}`",
        );
    }
    let name = agrees(&over_dir, &[&tar1]);
    assert_eq!(
        mode(&name, "/common"),
        "d00775",
        "the OR form left an archive's directory member alone",
    );
    for source in [&dir1, &ref1, &tar1] {
        let name = agrees(&assign_dir, &[source]);
        assert_eq!(
            mode(&name, "/common"),
            "d00770",
            "the `=` form did not reach the directory of `{source}`",
        );
    }

    // Two sources. The first entry offered under the path spends the OR entry,
    // so an earlier source holding the path leaves the archive's directory
    // member alone, and an earlier source that does not hold it does not.
    let name = agrees(&over_dir, &[&dir1, &tar1]);
    assert_eq!(
        mode(&name, "/common"),
        "d00755",
        "the walk did not spend the entry before the archive offered the path",
    );
    let name = agrees(&over_dir, &[&ref1, &tar1]);
    assert_eq!(
        mode(&name, "/common"),
        "d00755",
        "the `ref=` source did not spend the entry",
    );
    let name = agrees(&over_dir, &[&tar1, &tar2]);
    assert_eq!(
        mode(&name, "/common"),
        "d00755",
        "the second archive took the value the first archive spent",
    );
    // A path the earlier source does not hold is still the archive's to spend:
    // `/onlyB` is `t2`'s alone.
    let over_only = file("16 /onlyB\n");
    let name = agrees(&over_only, &[&dir1, &tar2]);
    assert_eq!(
        mode(&name, "/onlyB"),
        "d00775",
        "the archive did not reach a directory no earlier source offered",
    );
    let name = agrees(&over_only, &[&dir1, &dir2]);
    assert_eq!(
        mode(&name, "/onlyB"),
        "d00755",
        "the OR form reached a directory below the walk root of the second walk",
    );

    // The spend rule holds over every entry kind, not over directories alone: a
    // regular file, a symlink, and the walk root all keep the mode the second
    // source brought.
    for (body, path, spent, alone) in [
        ("16 /f.txt\n", "/f.txt", "-00644", "-00664"),
        ("2048 /link\n", "/link", "l00777", "l04777"),
        ("16 /\n", "/", "d00755", "d00775"),
    ] {
        let option = file(body);
        let name = agrees(&option, &[&dir1]);
        assert_eq!(
            mode(&name, path),
            alone,
            "`{body}` left `{path}` alone over one source",
        );
        for pair in [[&dir1, &dir2], [&ref1, &dir2], [&tar1, &tar2]] {
            let name = agrees(&option, &pair);
            assert_eq!(
                mode(&name, path),
                spent,
                "`{body}` reached `{path}` again in the second source",
            );
        }
    }
    // The `=` form is not spent: it applies in every source that offers the
    // path, so the second source's entry carries it too.
    let assign_file = file("=448 /f.txt\n");
    for pair in [[&dir1, &dir2], [&tar1, &tar2]] {
        let name = agrees(&assign_file, &pair);
        assert_eq!(
            mode(&name, "/f.txt"),
            "-00700",
            "the `=` form was spent by the first source",
        );
    }

    // A spent entry counts as reached, so it draws no unmatched report, and a
    // path no source holds is still reported whichever sources the run names.
    let absent = file("16 /f.txt\n16 /nope\n");
    branch += 1;
    let name = format!("s{branch}");
    let args = [
        "commit",
        "-b",
        &name,
        FIXED_TIMESTAMP,
        &absent,
        &dir1,
        &dir2,
    ];
    let (port, tool) = run_both(&port_repo, &tool_repo, &args);
    assert_runs_agree(&port, &tool, &args.join(" "));
    for (who, run) in [("port", &port), ("tool", &tool)] {
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert_eq!(
            run.status.code(),
            Some(1),
            "the {who} accepted the unmatched entry",
        );
        assert!(
            stderr.contains("Unmatched statoverride path: /nope"),
            "the {who} left `/nope` unreported: {stderr}",
        );
        assert!(
            !stderr.contains("Unmatched statoverride path: /f.txt"),
            "the {who} reported the spent entry `/f.txt`: {stderr}",
        );
    }
}

/// The two `--statoverride` classes the port and the tool part on: a mode field
/// the port reads in decimal alone, and a value renaming an entry's file type to
/// one the object model does not hold (`docs/conformance/cli-surface.md`, "P2").
///
/// Every cell here is a recorded divergence, so the assertion is that each side
/// behaves the recorded way, which pins both.
#[test]
fn commit_statoverride_divergences_stand_as_recorded() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-statoverride-diverge");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let tree = build_walk_source(base);
    let src = tree.to_str().unwrap();

    let mut cell = 0;
    let mut run = |body: &str, extra: &[&str]| -> (Run, Run) {
        cell += 1;
        let path = base.join(format!("div{cell}.txt"));
        std::fs::write(&path, body).unwrap();
        let option = format!("--statoverride={}", path.display());
        let name = format!("t{cell}");
        let mut args = vec!["commit", "-b", &name, FIXED_TIMESTAMP, &option];
        args.extend_from_slice(extra);
        args.push(src);
        let runs = run_both(&port_repo, &tool_repo, &args);
        // A refusal writes nothing, so the branch the run named stays absent.
        if runs.0.status.code() != Some(0) {
            assert!(
                !port_repo.join("refs/heads").join(&name).exists(),
                "the port wrote a ref for the refused `{body}`",
            );
        }
        runs
    };

    // The tool reads the mode field as a C `double`, so a hexadecimal literal, a
    // decimal point, and an exponent all reach it. The port reads the leading
    // decimal run, so each of these lands on a different commit, both at exit 0.
    for body in [
        "0x1ff /plain.txt\n",
        "0X1FF /plain.txt\n",
        "0x10 /plain.txt\n",
        "1e3 /plain.txt\n",
        "2e1 /plain.txt\n",
        ".7e3 /plain.txt\n",
        "inf /plain.txt\n",
        "nan /plain.txt\n",
        "1e100 /plain.txt\n",
        "4294967296 /plain.txt\n",
    ] {
        let (port, tool) = run(body, &[]);
        assert_eq!(port.status.code(), Some(0), "port refused `{body}`");
        assert_eq!(tool.status.code(), Some(0), "tool refused `{body}`");
        assert_ne!(
            port.stdout_trimmed(),
            tool.stdout_trimmed(),
            "`{body}` no longer diverges; the recorded divergence is stale"
        );
    }
    // The port reads the sign, so `4294967295` and `-1` are two spellings of
    // `0xFFFFFFFF`: each renames the type and draws the refusal the class below
    // states, where the tool commits at exit 0.
    for body in ["4294967295 /plain.txt\n", "-1 /plain.txt\n"] {
        let (port, tool) = run(body, &[]);
        assert_eq!(tool.status.code(), Some(0), "tool refused `{body}`");
        assert_eq!(port.status.code(), Some(1), "port accepted `{body}`");
        assert!(
            String::from_utf8_lossy(&port.stderr)
                .contains("invalid file header: mode is not a regular file or symlink"),
            "port stderr for `{body}`: {}",
            String::from_utf8_lossy(&port.stderr)
        );
    }

    // The tool's own conversion of a value its `double` reader cannot hold in
    // 32 bits: `4294967296`, `1e100`, `inf`, `nan`, and `4294967295` all reach
    // the commit the literal `2147483648` gives, which is `0x80000000`. Each row
    // is a root commit onto one branch, so the ref binding is the same in every
    // one and the checksum states the mode alone. The port reads `2147483648`
    // itself, so the two meet there.
    let mut conversion = 0;
    let mut convert = |body: &str| -> (Run, Run) {
        conversion += 1;
        let path = base.join(format!("conv{conversion}.txt"));
        std::fs::write(&path, body).unwrap();
        let option = format!("--statoverride={}", path.display());
        run_both(
            &port_repo,
            &tool_repo,
            &[
                "commit",
                "-b",
                "conv",
                "--parent=none",
                FIXED_TIMESTAMP,
                &option,
                src,
            ],
        )
    };
    let (port_edge, tool_edge) = convert("2147483648 /plain.txt\n");
    let edge = port_edge.ok().stdout_trimmed();
    assert_eq!(
        edge,
        tool_edge.ok().stdout_trimmed(),
        "the two part on the literal `0x80000000`",
    );
    for body in [
        "4294967296 /plain.txt\n",
        "1e100 /plain.txt\n",
        "inf /plain.txt\n",
        "nan /plain.txt\n",
        "4294967295 /plain.txt\n",
    ] {
        let (_, tool) = convert(body);
        assert_eq!(
            tool.ok().stdout_trimmed(),
            edge,
            "the tool no longer converts `{body}` to `0x80000000`",
        );
    }

    // A value renaming a symlink to a type the object model does not hold: the
    // tool writes an object its own reader then refuses, and the port refuses
    // the header. Both name the refusal; neither writes a usable object.
    for body in ["=4096 /link\n", "=16384 /link\n", "=49152 /link\n"] {
        let (port, tool) = run(body, &[]);
        assert_eq!(tool.status.code(), Some(0), "tool refused `{body}`");
        assert_eq!(port.status.code(), Some(1), "port accepted `{body}`");
        assert!(
            String::from_utf8_lossy(&port.stderr)
                .contains("invalid file header: mode is not a regular file or symlink"),
            "port stderr for `{body}`: {}",
            String::from_utf8_lossy(&port.stderr)
        );
    }

    // The directory arm of the same class: both refuse at exit 1 and word it
    // differently.
    for path in ["/dir1", "/"] {
        for value in [33261, 32768, 4096, 8192, 40960, 49152] {
            let body = format!("={value} {path}\n");
            let (port, tool) = run(&body, &[]);
            assert_eq!(port.status.code(), Some(1), "port accepted `{body}`");
            assert_eq!(tool.status.code(), Some(1), "tool accepted `{body}`");
            assert!(
                String::from_utf8_lossy(&port.stderr)
                    .contains("invalid dirmeta: mode is not a directory mode"),
                "port stderr for `{body}`: {}",
                String::from_utf8_lossy(&port.stderr)
            );
            assert!(
                String::from_utf8_lossy(&tool.stderr).contains("not a directory"),
                "tool stderr for `{body}`: {}",
                String::from_utf8_lossy(&tool.stderr)
            );
        }
    }

    // What the tool wrote at exit 0 is an object its own readers refuse. The
    // renamed symlink fails its checkout, and the renamed regular file fails
    // its `fsck`, which reads every object the repository holds.
    let renamed = base.join("div-symlink.txt");
    std::fs::write(&renamed, "=4096 /link\n").unwrap();
    let option = format!("--statoverride={}", renamed.display());
    let (port, tool) = run_both(
        &port_repo,
        &tool_repo,
        &["commit", "-b", "renamed", FIXED_TIMESTAMP, &option, src],
    );
    assert_eq!(
        port.status.code(),
        Some(1),
        "the port accepted `=4096 /link`"
    );
    assert_eq!(
        tool.status.code(),
        Some(0),
        "the tool refused `=4096 /link`"
    );
    let out = base.join("renamed-checkout");
    let checkout = ostree(&[
        "checkout",
        &format!("--repo={}", tool_repo.display()),
        "-U",
        "renamed",
        out.to_str().unwrap(),
    ]);
    assert_ne!(
        checkout.status.code(),
        Some(0),
        "the tool checked out the renamed symlink it wrote",
    );
    let fsck = ostree(&["fsck", &format!("--repo={}", tool_repo.display())]);
    assert_ne!(
        fsck.status.code(),
        Some(0),
        "the tool's fsck accepted the renamed regular file it wrote",
    );
    assert!(
        String::from_utf8_lossy(&fsck.stderr).contains("invalid mode"),
        "the tool's fsck failed for another reason:\n{}",
        String::from_utf8_lossy(&fsck.stderr),
    );
}

/// `commit --skip-list=PATH` prunes the same entries in both implementations,
/// checks every entry it holds, and refuses the same three ways.
#[test]
fn commit_skip_list_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-skip-list");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let tree = build_walk_source(base);
    let src = tree.to_str().unwrap();

    let mut cell = 0;
    let mut file = |body: &str| -> String {
        cell += 1;
        let path = base.join(format!("sk{cell}.txt"));
        std::fs::write(&path, body).unwrap();
        format!("--skip-list={}", path.display())
    };
    let mut branch = 0;
    let mut agrees = |option: &str, unordered: bool| {
        branch += 1;
        let name = format!("t{branch}");
        let args = ["commit", "-b", &name, FIXED_TIMESTAMP, option, src];
        if unordered {
            assert_agrees_unordered(&port_repo, &tool_repo, &args);
        } else {
            assert_agrees(&port_repo, &tool_repo, &args);
        }
    };

    // A file, a symlink, and a directory whose whole subtree goes with it.
    agrees(&file("/plain.txt\n"), false);
    agrees(&file("/link\n"), false);
    agrees(&file("/dir1\n"), false);
    agrees(&file("/plain.txt\n/dir2\n"), false);
    // Blank lines are ignored, duplicates are accepted, and an empty file
    // changes nothing.
    agrees(&file("\n/plain.txt\n\n"), false);
    agrees(&file("/plain.txt\n/plain.txt\n"), false);
    agrees(&file(""), false);
    // Every child of the root may go, leaving a tree of the root alone.
    agrees(
        &file(
            "/plain.txt\n/run.sh\n/roexec\n/grpx\n/setuid\n/setgid\n/sticky\n\
             /groupexec\n/otherexec\n/link\n/dir1\n/dir2\n",
        ),
        false,
    );
    // The root itself is refused, and any other entry is reported first.
    agrees(&file("/\n"), false);
    {
        let option = file("/\n");
        let args = ["commit", "-b", "empty", FIXED_TIMESTAMP, &option, src];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let label = args.join(" ");
        assert_runs_agree(&port, &tool, &label);
        assert_runs_agree_on_error(&port, &tool, &label, "error: Can't commit an empty tree");
    }
    agrees(&file("/\n/nope\n"), true);
    agrees(&file("/\n/plain.txt\n"), true);
    // Every entry is checked, and an entry inside a pruned directory is one the
    // walk never reached.
    agrees(&file("/nope\n"), true);
    agrees(&file("/z1\n/a2\n/m3\n/b4\n/y5\n"), true);
    // A path named more than once is reported once.
    agrees(&file("/nope\n/nope\n"), true);
    agrees(&file("/a1\n/b2\n/a1\n/c3\n"), true);
    agrees(&file("/dir1\n/dir1/a.txt\n"), true);
    agrees(&file("/dir1/a.txt\n/dir1\n"), true);
    agrees(&file("/dir1\n/dir1/sub\n"), true);
    agrees(&file("/plain.txt \n"), true);
    agrees(&file("plain.txt\n"), true);
    agrees(&file("/dir1/\n"), true);
    // A path that does not open, and a directory.
    agrees(
        &format!("--skip-list={}", base.join("absent").display()),
        false,
    );
    agrees(&format!("--skip-list={src}"), false);

    // A byte the file cannot hold refuses the whole file, ahead of the walk.
    for (index, body) in [
        b"/plain.txt\n/bad\xff.txt\n".to_vec(),
        b"/plain\0.txt\n".to_vec(),
    ]
    .into_iter()
    .enumerate()
    {
        let path = base.join(format!("sk-raw{index}.txt"));
        std::fs::write(&path, &body).unwrap();
        let option = format!("--skip-list={}", path.display());
        let name = format!("raw{index}");
        assert_agrees(
            &port_repo,
            &tool_repo,
            &["commit", "-b", &name, FIXED_TIMESTAMP, &option, src],
        );
    }

    // The statoverride file is read first, so its unmatched report stands ahead
    // of the skip list's whichever order the command line states.
    let so = base.join("both-so.txt");
    std::fs::write(&so, "448 /nope-so\n").unwrap();
    let so = format!("--statoverride={}", so.display());
    let sk = file("/nope-sk\n");
    for (first, second) in [(&so, &sk), (&sk, &so)] {
        branch += 1;
        let name = format!("t{branch}");
        let args = ["commit", "-b", &name, FIXED_TIMESTAMP, first, second, src];
        assert_agrees_unordered(&port_repo, &tool_repo, &args);
        // The unordered comparison sorts the lines, so the order of the two
        // checks is stated here: the statoverride report ends the run and the
        // skip list is never reached, whichever order the command line gives.
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let label = args.join(" ");
        for (who, run) in [("port", &port), ("tool", &tool)] {
            let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
            assert_eq!(run.status.code(), Some(1), "the {who} accepted `{label}`",);
            assert!(
                stderr.contains("Unmatched statoverride path: /nope-so"),
                "the {who} reported no statoverride path for `{label}`:\n{stderr}",
            );
            assert!(
                !stderr.contains("skip-list"),
                "the {who} reached the skip list's report for `{label}`:\n{stderr}",
            );
        }
    }
}

/// `commit --mode-ro-executables` clears the write bits of every regular file
/// carrying an execute bit, and runs ahead of `--statoverride`.
#[test]
fn commit_mode_ro_executables_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-mode-ro");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let tree = build_walk_source(base);
    let src = tree.to_str().unwrap();

    let so = base.join("mre-so.txt");
    std::fs::write(&so, "=511 /plain.txt\n146 /roexec\n").unwrap();
    let so = format!("--statoverride={}", so.display());

    let mut branch = 0;
    let mut agrees = |extra: &[&str]| {
        branch += 1;
        let name = format!("t{branch}");
        let mut args = vec![
            "commit",
            "-b",
            &name,
            FIXED_TIMESTAMP,
            "--mode-ro-executables",
        ];
        args.extend_from_slice(extra);
        args.push(src);
        assert_agrees(&port_repo, &tool_repo, &args);
    };

    // The rule alone over the mode grid, then beside each option it composes
    // with: `--statoverride` states the mode it ends at, and
    // `--canonical-permissions` runs ahead of both.
    agrees(&[]);
    agrees(&[&so]);
    agrees(&["--canonical-permissions"]);
    agrees(&["--owner-uid=7", "--owner-gid=8"]);
    agrees(&["--no-xattrs"]);
}

/// `commit --skip-if-unchanged` writes nothing where the walked tree matches
/// the resolved parent: the parent's checksum on standard output, exit 0, and
/// the ref left where it stood.
#[test]
fn commit_skip_if_unchanged_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-skip-unchanged");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let tree = build_walk_source(base);
    let src = tree.to_str().unwrap();

    let agrees = |extra: &[&str], branch: &str| {
        let mut args = vec![
            "commit",
            "-b",
            branch,
            FIXED_TIMESTAMP,
            "--skip-if-unchanged",
        ];
        args.extend_from_slice(extra);
        args.push(src);
        assert_agrees(&port_repo, &tool_repo, &args);
        assert_eq!(
            describe_refs(&port_repo),
            describe_refs(&tool_repo),
            "the refs trees disagree after `{}`",
            args.join(" ")
        );
    };

    // The first run commits and the second one skips.
    agrees(&[], "t1");
    agrees(&[], "t1");
    // The commit's own metadata takes no part in the comparison.
    agrees(&["-s", "a different subject"], "t1");
    agrees(&["--add-metadata-string=k=v"], "t1");
    // A modifier that changes the tree commits, and repeating it skips.
    agrees(&["--owner-uid=0"], "t1");
    agrees(&["--owner-uid=0"], "t1");
    // A change to the root dirmeta alone is a change.
    let so = base.join("siu-so.txt");
    std::fs::write(&so, "=511 /\n").unwrap();
    let so = format!("--statoverride={}", so.display());
    agrees(&["--owner-uid=0", &so], "t1");
    // The walk still runs, so an unmatched entry fails the command at exit 1.
    let bad = base.join("siu-bad.txt");
    std::fs::write(&bad, "448 /nope\n").unwrap();
    let bad = format!("--statoverride={}", bad.display());
    agrees(&[&bad], "t1");
    let (port, tool) = run_both(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "t1",
            FIXED_TIMESTAMP,
            "--skip-if-unchanged",
            &bad,
            src,
        ],
    );
    for (who, run) in [("port", &port), ("tool", &tool)] {
        assert_eq!(
            run.status.code(),
            Some(1),
            "the {who} accepted an unmatched statoverride entry beside `--skip-if-unchanged`",
        );
    }
    // A fresh branch has no parent to compare with, and neither does `--orphan`
    // or `--parent=none`.
    agrees(&[], "t2");
    agrees(&["--parent=none"], "t2");
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "--orphan",
            FIXED_TIMESTAMP,
            "--skip-if-unchanged",
            src,
        ],
    );

    // With `--parent` naming a matching commit and `-b` naming a ref that does
    // not exist, the ref is not created.
    let (port, tool) = run_both(&port_repo, &tool_repo, &["rev-parse", "t2"]);
    assert_runs_agree(&port, &tool, "rev-parse t2");
    let tip = port.stdout_trimmed();
    let parent = format!("--parent={tip}");
    let args = [
        "commit",
        "-b",
        "t3",
        &parent,
        FIXED_TIMESTAMP,
        "--skip-if-unchanged",
        src,
    ];
    let (port, tool) = run_both(&port_repo, &tool_repo, &args);
    assert_runs_agree(&port, &tool, &args.join(" "));
    // The parent's own checksum is printed, at exit 0, and no ref is created.
    for (who, run) in [("port", &port), ("tool", &tool)] {
        assert_eq!(
            run.status.code(),
            Some(0),
            "the {who} refused the matching parent:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
        assert_eq!(
            run.stdout_trimmed(),
            tip,
            "the {who} printed another checksum than the parent's",
        );
    }
    assert_eq!(describe_refs(&port_repo), describe_refs(&tool_repo));
    let (port, tool) = run_both(&port_repo, &tool_repo, &["rev-parse", "t3"]);
    assert_runs_agree(&port, &tool, "rev-parse t3");
    for (who, run) in [("port", &port), ("tool", &tool)] {
        assert_ne!(run.status.code(), Some(0), "the {who} created the ref `t3`",);
    }
}

/// The reason a run gives on standard error, with the one wording the two
/// implementations differ on folded into a single token.
///
/// Recording the ownership write a non-root user cannot make is the tool's
/// `Writing content object: fchown: Operation not permitted` and the port's
/// `i/o error: Operation not permitted (os error 1)`
/// (`docs/conformance/cli-surface.md`, "P2"). Every other line has to match, so
/// a cell where both sides fail still has to fail for the same reason.
fn refusal_reason(run: &Run) -> String {
    let text = String::from_utf8_lossy(&run.stderr).into_owned();
    let mut lines: Vec<String> = text
        .lines()
        .map(|line| {
            if line.contains("Operation not permitted") {
                "error: <an ownership write this user cannot make>".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect();
    lines.sort_unstable();
    lines.join("\n")
}

/// `commit --link-checkout-speedup` and `-I/--devino-canonical` resolve a
/// source file that is a hardlink to one of the repository's own objects, and
/// reach the tool's own commit checksum in every repository mode and in both
/// checkout forms the tool hardlinks under.
#[test]
fn commit_checkout_speedup_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-devino");
    let base = tmp.path();
    let tree = build_walk_source(base);
    let src = tree.to_str().unwrap();

    let so = base.join("dev-so.txt");
    std::fs::write(&so, "=511 /plain.txt\n").unwrap();
    let so = format!("--statoverride={}", so.display());
    let sk = base.join("dev-sk.txt");
    std::fs::write(&sk, "/run.sh\n").unwrap();
    let sk = format!("--skip-list={}", sk.display());

    // The arms are a repository mode paired with a checkout form and with the
    // number of devino-cache hits that pairing leaves.
    //
    // `-U` is the one form every mode accepts, and in `bare-user` it is the
    // form that leaves the repository's own `user.ostreemeta` xattr on the
    // hardlinked files, which is where the two speedup options and the plain
    // walk part. `-H` hardlinks the stored objects themselves, which is the
    // form that puts a `bare` repository's symlink object on one end of a
    // hardlink pair. The tool takes `-H` in `bare` alone: an `archive`
    // repository answers `error: Bare repository mode cannot hardlink in user
    // checkout mode` and a `bare-user` repository answers `error: User
    // repository mode requires user checkout mode to hardlink`, both at exit 1
    // (`docs/conformance/cli-surface.md`, "P2").
    for (index, (mode, form, hits)) in [
        (RepoMode::Archive, "-U", 0),
        (RepoMode::BareUser, "-U", 13),
        (RepoMode::Bare, "-U", 0),
        (RepoMode::Bare, "-H", 14),
    ]
    .into_iter()
    .enumerate()
    {
        let side = base.join(format!("mode{index}"));
        std::fs::create_dir_all(&side).unwrap();
        let (port_repo, tool_repo) = create_repo_pair(&side, mode);
        for (repo, tag) in [(&port_repo, "port"), (&tool_repo, "tool")] {
            let repo_arg = format!("--repo={}", repo.display());
            let args = ["commit", &repo_arg, "-b", "t", FIXED_TIMESTAMP, src];
            if tag == "port" {
                ostrya(&args, None, &[]).ok();
            } else {
                assert!(ostree(&args).status.success());
            }
        }
        let port_out = side.join("port-co");
        let tool_out = side.join("tool-co");
        ostrya(
            &[
                "checkout",
                &format!("--repo={}", port_repo.display()),
                form,
                "t",
                port_out.to_str().unwrap(),
            ],
            None,
            &[],
        )
        .ok();
        assert!(
            ostree(&[
                "checkout",
                &format!("--repo={}", tool_repo.display()),
                form,
                "t",
                tool_out.to_str().unwrap(),
            ])
            .status
            .success()
        );

        // What the `-U` checkout of a `bare-user` repository leaves on disk,
        // which is where the plain walk and the two flagged walks part: the
        // objects are hardlinked, so each file carries the repository's own
        // `user.ostreemeta` xattr and its inode holds the permission bits with
        // the setuid, setgid, and sticky bits cleared. An `-H` checkout of a
        // `bare-user` repository is refused by the tool, so no arm pairs the
        // two and the block stays with `-U`.
        if mode == RepoMode::BareUser && form == "-U" {
            let setuid = port_out.join("setuid");
            let bits = std::fs::symlink_metadata(&setuid)
                .expect("the checked-out file stats")
                .mode()
                & 0o7777;
            assert_eq!(
                bits & 0o7000,
                0,
                "the checkout kept the special bits: {bits:o}",
            );
            let listed = Command::new("getfattr")
                .args(["--absolute-names", "-d", "-m", "-"])
                .arg(&setuid)
                .output();
            if let Ok(out) = listed
                && out.status.success()
            {
                assert!(
                    String::from_utf8_lossy(&out.stdout).contains("user.ostreemeta"),
                    "the checked-out file carries no `user.ostreemeta` xattr",
                );
            }
        }

        // How many entries the cache resolved, read from each side's own
        // `--table-output` block. `Content Cache Hits` counts the content
        // objects a devino-cache hit resolved (`docs/format-reference.md`,
        // "CLI output formats"). The count is the assertion the checksums
        // cannot make: a `bare` repository stores a symlink object as a
        // symlink, so an `-H` checkout hardlinks that inode as well and the
        // walk resolves the symlink beside the thirteen regular files. Dropping
        // the symlink from the cache scan leaves the fourteen at thirteen and
        // every checksum unmoved.
        let cache_hits = |repo: &Path, out: &Path, port: bool| -> u32 {
            let args = [
                "commit".to_owned(),
                format!("--repo={}", repo.display()),
                "--orphan".to_owned(),
                FIXED_TIMESTAMP.to_owned(),
                "--link-checkout-speedup".to_owned(),
                "--table-output".to_owned(),
                out.display().to_string(),
            ];
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let run = if port {
                ostrya(&argv, None, &[])
            } else {
                ostree(&argv)
            };
            assert!(
                run.status.success(),
                "`commit --link-checkout-speedup --table-output` failed:\n{}",
                String::from_utf8_lossy(&run.stderr),
            );
            let text = String::from_utf8_lossy(&run.stdout).into_owned();
            let line = text
                .lines()
                .find_map(|line| line.strip_prefix("Content Cache Hits: "))
                .expect("a `Content Cache Hits` counter");
            line.trim().parse().expect("a counter value")
        };
        let port_hits = cache_hits(&port_repo, &port_out, true);
        let tool_hits = cache_hits(&tool_repo, &tool_out, false);
        assert_eq!(
            (port_hits, tool_hits),
            (hits, hits),
            "`checkout {form}` over {mode:?} resolved a different number of entries",
        );

        // The source path differs per side, so the invocation is assembled per
        // side and the two runs are compared directly. The agreed standard
        // output is returned, so that one invocation's checksum can be held
        // against another's.
        let compare = |extra: &[&str]| -> String {
            let build = |repo: &Path, out: &Path| {
                let mut args = vec![
                    "commit".to_owned(),
                    format!("--repo={}", repo.display()),
                    "--orphan".to_owned(),
                    FIXED_TIMESTAMP.to_owned(),
                ];
                args.extend(extra.iter().map(|arg| (*arg).to_owned()));
                args.push(out.display().to_string());
                args
            };
            let port_args = build(&port_repo, &port_out);
            let tool_args = build(&tool_repo, &tool_out);
            let port = ostrya(
                &port_args.iter().map(String::as_str).collect::<Vec<_>>(),
                None,
                &[],
            );
            let tool = ostree(&tool_args.iter().map(String::as_str).collect::<Vec<_>>());
            assert_eq!(
                (
                    port.status.code(),
                    port.stdout_trimmed(),
                    refusal_reason(&port)
                ),
                (
                    tool.status.code(),
                    tool.stdout_trimmed(),
                    refusal_reason(&tool)
                ),
                "`commit {}` over {mode:?} disagrees\nport stderr: {}\ntool stderr: {}",
                extra.join(" "),
                String::from_utf8_lossy(&port.stderr),
                String::from_utf8_lossy(&tool.stderr),
            );
            port.stdout_trimmed()
        };

        let plain = compare(&[]);
        let speedup = compare(&["--link-checkout-speedup"]);
        let devino = compare(&["-I"]);
        let no_xattrs = compare(&["--no-xattrs"]);
        // Every modifier still applies over an object `--link-checkout-speedup`
        // resolved, so each pairing reaches its own commit. A pairing this user
        // cannot make prints nothing and is left to the agreement above.
        for extra in [
            vec!["--link-checkout-speedup", so.as_str()],
            vec!["--link-checkout-speedup", "--mode-ro-executables"],
            vec!["--link-checkout-speedup", "--owner-uid=7"],
            vec!["--link-checkout-speedup", sk.as_str()],
        ] {
            let with_modifier = compare(&extra);
            if !with_modifier.is_empty() {
                assert_ne!(
                    with_modifier,
                    speedup,
                    "`{}` left the flagged checksum alone over {mode:?}",
                    extra.join(" "),
                );
            }
        }
        compare(&["-I", &so]);
        compare(&["-I", "--mode-ro-executables"]);
        let devino_owned = compare(&["-I", "--owner-uid=7"]);
        compare(&["-I", &sk]);
        // An `archive` repository stores no object a checkout can hardlink, so
        // nothing resolves and `-I` is the plain walk there.
        if mode == RepoMode::Archive {
            assert_eq!(
                devino, plain,
                "`-I` parted from the plain walk over an archive repository",
            );
            assert_eq!(
                speedup, plain,
                "`--link-checkout-speedup` parted from the plain walk over an \
                 archive repository",
            );
        }

        // The cache keys on the inode, so a hardlinked copy of the checkout
        // resolves the same way the checkout itself does.
        let link_copy = |from: &Path, to: &Path| {
            assert!(
                Command::new("cp")
                    .args(["-al"])
                    .arg(from)
                    .arg(to)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        let port_hard = side.join("port-hard");
        let tool_hard = side.join("tool-hard");
        link_copy(&port_out, &port_hard);
        link_copy(&tool_out, &tool_hard);
        let hard_args = |repo: &Path, out: &Path| {
            vec![
                "commit".to_owned(),
                format!("--repo={}", repo.display()),
                "--orphan".to_owned(),
                FIXED_TIMESTAMP.to_owned(),
                "--link-checkout-speedup".to_owned(),
                out.display().to_string(),
            ]
        };
        let port_args = hard_args(&port_repo, &port_hard);
        let tool_args = hard_args(&tool_repo, &tool_hard);
        let port = ostrya(
            &port_args.iter().map(String::as_str).collect::<Vec<_>>(),
            None,
            &[],
        );
        let tool = ostree(&tool_args.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(
            (port.status.code(), port.stdout_trimmed()),
            (tool.status.code(), tool.stdout_trimmed()),
            "a hardlinked copy of the checkout disagrees over {mode:?}"
        );
        // The cache keys on the inode, so the copy reaches the commit the
        // checkout itself reaches.
        assert_eq!(
            port.stdout_trimmed(),
            speedup,
            "a hardlinked copy of the checkout resolved otherwise over {mode:?}",
        );

        // The relation the record `commit/devino-bare-user-user-mode-xattr`
        // states, held between the invocations above rather than between the
        // two implementations. A `-U` checkout of a `bare-user` repository
        // hardlinks the stored objects. Those objects carry the repository's
        // own `user.ostreemeta` xattr, and their inodes hold the permission
        // bits without the setuid, setgid, and sticky bits. The plain walk
        // commits the xattr and the reduced bits; `--no-xattrs` drops the xattr
        // and keeps the reduced bits; either speedup option resolves the object
        // and reaches the source tree itself. Those three walks reach three
        // different commits, so both options change the checksum and
        // `--no-xattrs` does not recover the flagged one. The relations are
        // properties of the `-U` checkout, so the guard names the form as well
        // as the mode.
        if mode == RepoMode::BareUser && form == "-U" {
            let port_repo_arg = format!("--repo={}", port_repo.display());
            let tool_repo_arg = format!("--repo={}", tool_repo.display());
            let port_source = ostrya(
                &["commit", &port_repo_arg, "--orphan", FIXED_TIMESTAMP, src],
                None,
                &[],
            )
            .ok()
            .stdout_trimmed();
            let tool_source = ostree(&["commit", &tool_repo_arg, "--orphan", FIXED_TIMESTAMP, src]);
            assert!(tool_source.status.success());
            let source = tool_source.stdout_trimmed();
            assert_eq!(
                port_source, source,
                "the source tree recommitted disagrees over bare-user",
            );

            assert_eq!(
                speedup, devino,
                "`--link-checkout-speedup` and `-I` reach different commits over bare-user",
            );
            // `-I` skips the modifiers for every entry that resolves, and the
            // directories and the symlink resolve to nothing, so they take the
            // declared uid and the two commits part.
            assert_ne!(
                devino_owned, devino,
                "`-I --owner-uid=7` reached the option-free `-I` commit over bare-user",
            );
            let listing = ostrya(&["ls", &port_repo_arg, "-R", &devino_owned], None, &[])
                .ok()
                .stdout_trimmed();
            for line in listing.lines() {
                let mut fields = line.split_whitespace();
                let mode = fields.next().expect("a mode column");
                let uid = fields.next().expect("a uid column");
                if mode.starts_with('d') || mode.starts_with('l') {
                    assert_eq!(
                        uid, "7",
                        "an entry that resolves to nothing kept its uid: {line}"
                    );
                }
            }
            assert_eq!(
                speedup, source,
                "the resolved commit is not the source tree over bare-user",
            );
            assert_ne!(
                plain, speedup,
                "`--link-checkout-speedup` left the checksum alone over bare-user",
            );
            assert_ne!(plain, devino, "`-I` left the checksum alone over bare-user",);
            assert_ne!(
                plain, no_xattrs,
                "`--no-xattrs` left the plain checksum alone over bare-user",
            );
            assert_ne!(
                no_xattrs, speedup,
                "`--no-xattrs` on the plain walk reached the flagged checksum over bare-user",
            );
        }

        // What an `-H` checkout holds, which is the other side of the block
        // above. That checkout hardlinks the stored objects themselves, and a
        // `bare` repository stores each object with the source file's own mode,
        // uid, gid, and xattrs, so the destination is the source tree again.
        // Every walk over it reaches the source tree's own commit, the plain
        // one included, so the cache-hit count above is the whole record of
        // what the two options resolved.
        if form == "-H" {
            let port_repo_arg = format!("--repo={}", port_repo.display());
            let tool_repo_arg = format!("--repo={}", tool_repo.display());
            let port_source = ostrya(
                &["commit", &port_repo_arg, "--orphan", FIXED_TIMESTAMP, src],
                None,
                &[],
            )
            .ok()
            .stdout_trimmed();
            let tool_source = ostree(&["commit", &tool_repo_arg, "--orphan", FIXED_TIMESTAMP, src]);
            assert!(tool_source.status.success());
            let source = tool_source.stdout_trimmed();
            assert_eq!(
                port_source, source,
                "the source tree recommitted disagrees over {mode:?} with `-H`",
            );
            for (label, reached) in [
                ("the plain walk", &plain),
                ("--link-checkout-speedup", &speedup),
                ("-I", &devino),
                ("--no-xattrs", &no_xattrs),
            ] {
                assert_eq!(
                    reached, &source,
                    "`{label}` parted from the source tree over {mode:?} with `-H`",
                );
            }
        }
    }
}

// --- Phase 17f: `commit` derived metadata ------------------------------------
//
// `--generate-sizes`, `--bootable`, and `--generate-composefs-metadata` each
// derive a metadata key from the tree the commit carries, so the claim is
// checksum agreement over the commit object. The `ostree.sizes` entries are
// compared record by record as well, through the tool's own printer read against
// both repositories (`docs/format-reference.md`, "Metadata object formats").

/// Build a tree holding one kernel directory under `usr/lib/modules`, the shape
/// `--bootable` reads.
fn build_kernel_tree(root: &Path) {
    let modules = root.join("usr/lib/modules/6.1.0-test");
    std::fs::create_dir_all(modules.join("kernel")).unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(modules.join("vmlinuz"), b"a kernel image\n").unwrap();
    std::fs::write(modules.join("initramfs.img"), b"an initramfs\n").unwrap();
    std::fs::write(modules.join("kernel/mod.ko"), b"kernel module\n").unwrap();
    std::fs::write(root.join("etc/conf"), b"etc config\n").unwrap();
    std::os::unix::fs::symlink("../etc/conf", root.join("usr/link")).unwrap();
}

/// The metadata dict of one commit, as that implementation's own `show --raw`
/// prints it. The `port` flag picks the reader, so a claim about the stored key
/// order is read by the implementation that wrote it.
fn raw_commit(repo: &Path, rev: &str, port: bool) -> String {
    let repo_arg = format!("--repo={}", repo.display());
    let args = ["show", &repo_arg, "--raw", rev];
    let run = if port {
        ostrya(&args, None, &[])
    } else {
        ostree(&args)
    };
    assert!(
        run.status.success(),
        "`show --raw {rev}` failed in {}:\n{}",
        repo.display(),
        String::from_utf8_lossy(&run.stderr),
    );
    String::from_utf8(run.stdout).expect("the printed dict is text")
}

/// The `ostree.sizes` value of `rev` in `repo`, as the tool's own printer
/// renders it. Both repositories are read by the tool, so the comparison is over
/// the packed records themselves rather than over the commit checksum.
fn printed_sizes(repo: &Path, rev: &str) -> String {
    let run = ostree(&[
        "show",
        &format!("--repo={}", repo.display()),
        "--print-metadata-key=ostree.sizes",
        rev,
    ]);
    assert!(
        run.status.success(),
        "reading ostree.sizes from {}: {}",
        repo.display(),
        String::from_utf8_lossy(&run.stderr)
    );
    run.stdout_trimmed()
}

/// `commit --generate-sizes` writes `ostree.sizes` in an archive repository and
/// nothing in the others, and the packed records agree with the tool's over
/// several trees, over a second commit that reaches deduplicated objects, and
/// over the tar stream.
#[test]
fn commit_generate_sizes_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-sizes");
    let base = tmp.path();
    let deep = base.join("deep");
    std::fs::create_dir_all(deep.join("a/b/c")).unwrap();
    std::fs::create_dir_all(deep.join("d")).unwrap();
    std::fs::write(deep.join("a/f1"), b"one\n").unwrap();
    std::fs::write(deep.join("a/b/f2"), b"two\n").unwrap();
    std::fs::write(deep.join("a/b/c/f3"), b"three\n").unwrap();
    std::os::unix::fs::symlink("../f1", deep.join("d/link")).unwrap();
    let kernel = base.join("kernel");
    build_kernel_tree(&kernel);

    for mode in [
        RepoMode::Archive,
        RepoMode::Bare,
        RepoMode::BareUser,
        RepoMode::BareUserOnly,
    ] {
        let side = base.join(format!("m{}", mode.as_mode_str()));
        std::fs::create_dir_all(&side).unwrap();
        let (port_repo, tool_repo, tree) = commit_pair(&side, mode);
        for (n, src) in [&tree, &deep, &kernel].iter().enumerate() {
            let branch = format!("sz{n}");
            assert_agrees(
                &port_repo,
                &tool_repo,
                &[
                    "commit",
                    "-b",
                    &branch,
                    FIXED_TIMESTAMP,
                    "--generate-sizes",
                    "--orphan",
                    src.to_str().unwrap(),
                ],
            );
        }
        // Outside archive mode the request writes no key, so the commit is the
        // one the same invocation without it makes.
        let plain = ostrya(
            &[
                "commit",
                &format!("--repo={}", port_repo.display()),
                "-b",
                "plain",
                FIXED_TIMESTAMP,
                "--orphan",
                tree.to_str().unwrap(),
            ],
            None,
            &[],
        );
        let sized = ostrya(
            &[
                "commit",
                &format!("--repo={}", port_repo.display()),
                "-b",
                "plain",
                FIXED_TIMESTAMP,
                "--generate-sizes",
                "--orphan",
                tree.to_str().unwrap(),
            ],
            None,
            &[],
        );
        let identical = plain.ok().stdout_trimmed() == sized.ok().stdout_trimmed();
        assert_eq!(
            identical,
            mode != RepoMode::Archive,
            "size generation in {mode:?} changed the commit where it should not, \
             or left it unchanged where it should"
        );
    }

    // The packed records themselves, read from both repositories by the tool.
    let side = base.join("records");
    std::fs::create_dir_all(&side).unwrap();
    let (port_repo, tool_repo, tree) = commit_pair(&side, RepoMode::Archive);
    for (n, src) in [&tree, &deep, &kernel].iter().enumerate() {
        let branch = format!("rec{n}");
        let args = [
            "commit",
            "-b",
            &branch,
            FIXED_TIMESTAMP,
            "--generate-sizes",
            "--orphan",
            src.to_str().unwrap(),
        ];
        assert_agrees(&port_repo, &tool_repo, &args);
        let printed = printed_sizes(&port_repo, &branch);
        assert_eq!(
            printed,
            printed_sizes(&tool_repo, &branch),
            "the packed ostree.sizes records disagree for {}",
            src.display()
        );
        assert!(printed.starts_with("[[byte "), "unexpected rendering");
    }

    // A second commit lists every object the tree reaches, the ones that
    // deduplicated against the first commit included.
    let more = base.join("more");
    let copy = Command::new("cp")
        .args(["-a"])
        .arg(&tree)
        .arg(&more)
        .status()
        .unwrap();
    assert!(copy.success());
    std::fs::write(more.join("added.txt"), b"added\n").unwrap();
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "rec0",
            FIXED_TIMESTAMP,
            "--generate-sizes",
            more.to_str().unwrap(),
        ],
    );

    // The tar stream: the port reads it on standard input where the tool takes
    // `--tree=tar=PATH`, and the key covers the imported tree the same way.
    let tar = base.join("tree.tar");
    assert!(
        Command::new("tar")
            .arg("-cf")
            .arg(&tar)
            .arg("-C")
            .arg(&tree)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    let tar_bytes = std::fs::read(&tar).unwrap();
    let port = ostrya(
        &[
            "commit",
            &format!("--repo={}", port_repo.display()),
            "-b",
            "tarred",
            FIXED_TIMESTAMP,
            "--generate-sizes",
            "--orphan",
        ],
        Some(&tar_bytes),
        &[],
    );
    let tool = ostree(&[
        "commit",
        &format!("--repo={}", tool_repo.display()),
        "-b",
        "tarred",
        FIXED_TIMESTAMP,
        "--generate-sizes",
        "--orphan",
        &format!("--tree=tar={}", tar.display()),
    ]);
    assert_eq!(
        port.ok().stdout_trimmed(),
        tool.ok().stdout_trimmed(),
        "the tar stream and --tree=tar disagree under --generate-sizes"
    );
    // The key is written for the tar form as it is for a directory walk, so it
    // is read back out of both repositories rather than left to the checksum.
    let port_tar_sizes = printed_sizes(&port_repo, "tarred");
    assert!(
        port_tar_sizes.starts_with("[[byte "),
        "the tar commit carries no packed ostree.sizes: {port_tar_sizes}",
    );
    assert_eq!(
        port_tar_sizes,
        printed_sizes(&tool_repo, "tarred"),
        "the tar form's ostree.sizes records disagree",
    );

    // Over a source list the key is scoped to what the last source contributed
    // plus the directory objects the serialization wrote, so the composition
    // shows in the commit checksum
    // (`docs/format-reference.md`, "CLI output formats", `commit`).
    let sources = build_overlay_sources(base);
    let t1 = sources.join("t1").to_str().unwrap().to_owned();
    let t2 = sources.join("t2").to_str().unwrap().to_owned();
    let empty = sources.join("nothing");
    std::fs::create_dir_all(&empty).unwrap();
    let overlay_tar = base.join("overlay.tar");
    pack_tar(&sources.join("t2"), &overlay_tar);
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "sizebase",
            FIXED_TIMESTAMP,
            &format!("--tree=dir={t1}"),
        ],
    );
    let mut branch = 0;
    let mut sized = |extra: &[&str]| {
        branch += 1;
        let name = format!("sz{branch}");
        let mut args = vec!["commit", "-b", &name, FIXED_TIMESTAMP, "--generate-sizes"];
        args.extend_from_slice(extra);
        assert_agrees(&port_repo, &tool_repo, &args);
        // Each composition writes the key, and the records agree entry by
        // entry, which the commit checksum alone does not state.
        let records = printed_sizes(&port_repo, &name);
        assert!(
            records.starts_with("[[byte "),
            "`{}` wrote no packed ostree.sizes: {records}",
            args.join(" "),
        );
        assert_eq!(
            records,
            printed_sizes(&tool_repo, &name),
            "`{}` wrote different size records",
            args.join(" "),
        );
    };
    sized(&[&format!("--tree=dir={t1}")]);
    sized(&[&format!("--tree=dir={t1}"), &format!("--tree=dir={t2}")]);
    sized(&[&format!("--tree=dir={t2}"), &format!("--tree=dir={t1}")]);
    sized(&[
        &format!("--tree=dir={t1}"),
        &format!("--tree=tar={}", overlay_tar.display()),
    ]);
    // A source that contributes no content leaves the key with no content entry.
    sized(&[
        &format!("--tree=dir={t1}"),
        &format!("--tree=dir={}", empty.display()),
    ]);
    // A `--base` layer contributes nothing; a `ref=` source contributes its
    // whole tree.
    sized(&["--base=sizebase", &format!("--tree=dir={t2}")]);
    sized(&[&format!("--tree=dir={t2}"), "--tree=ref=sizebase"]);
    sized(&["--tree=ref=sizebase", &format!("--tree=dir={t2}")]);
    sized(&[
        &format!("--tree=dir={t1}"),
        &format!("--tree=dir={t2}"),
        "--tree=ref=sizebase",
    ]);
}

/// The stored size of one loose object, named by its checksum, in an archive
/// repository.
fn filez_size(repo: &Path, checksum: &str) -> u64 {
    let (prefix, rest) = checksum.split_at(2);
    let path = repo
        .join("objects")
        .join(prefix)
        .join(format!("{rest}.filez"));
    std::fs::metadata(&path)
        .unwrap_or_else(|err| panic!("stat {}: {err}", path.display()))
        .len()
}

/// The content checksum the tool reads for `path` in `rev`, out of either
/// implementation's repository.
fn content_checksum(repo: &Path, rev: &str, path: &str) -> String {
    let run = ostree(&["ls", "-C", &format!("--repo={}", repo.display()), rev, path]);
    let line = run.ok().stdout_trimmed();
    line.split_whitespace()
        .nth(4)
        .unwrap_or_else(|| panic!("no checksum column in `{line}`"))
        .to_owned()
}

/// The two DEFLATE encoders reach two stored sizes for most payloads, so an
/// archive `--generate-sizes` commit of such a tree reaches two commit
/// checksums (`docs/conformance/cli-surface.md`, "P2"). The named payloads pin
/// the divergence: a change in the port's encoder or in the archive compression
/// level moves the port's numbers, and a change in the tool's moves the tool's.
#[test]
fn commit_generate_sizes_deflate_divergence_stands_as_recorded() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-sizes-deflate");
    let base = tmp.path();
    let tree = base.join("tree");
    // `C9`'s `large.bin` is a 1 MiB byte-cycle; `repeat50` is 50 `a` bytes.
    ostrya_conformance::corpus::materialize("C9", &tree).unwrap();
    std::fs::write(tree.join("repeat50"), vec![b'a'; 50]).unwrap();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let args = |repo: &Path| {
        vec![
            "commit".to_owned(),
            format!("--repo={}", repo.display()),
            "-b".to_owned(),
            "sizes".to_owned(),
            FIXED_TIMESTAMP.to_owned(),
            "--generate-sizes".to_owned(),
            "--orphan".to_owned(),
            tree.to_str().unwrap().to_owned(),
        ]
    };
    let port_args = args(&port_repo);
    let port = ostrya(
        &port_args.iter().map(String::as_str).collect::<Vec<_>>(),
        None,
        &[],
    );
    let tool_args = args(&tool_repo);
    let tool = ostree(&tool_args.iter().map(String::as_str).collect::<Vec<_>>());
    let port_commit = port.ok().stdout_trimmed();
    let tool_commit = tool.ok().stdout_trimmed();

    // Object identity is over the uncompressed bytes, so the two repositories
    // name the same objects and stay interoperable.
    for path in ["/large.bin", "/repeat50"] {
        assert_eq!(
            content_checksum(&port_repo, &port_commit, path),
            content_checksum(&tool_repo, &tool_commit, path),
            "the content checksum of {path} disagrees"
        );
    }

    // The stored sizes part, and the recorded numbers are these.
    for (path, tool_size, port_size) in [("/large.bin", 4424, 4421), ("/repeat50", 40, 50)] {
        let checksum = content_checksum(&port_repo, &port_commit, path);
        assert_eq!(
            (
                filez_size(&tool_repo, &checksum),
                filez_size(&port_repo, &checksum)
            ),
            (tool_size, port_size),
            "the recorded .filez sizes of {path} moved"
        );
    }

    // `ostree.sizes` records those sizes, so the commit checksums part with
    // them, while the same tree without the option reaches one checksum.
    assert_ne!(
        port_commit, tool_commit,
        "the recorded --generate-sizes divergence is gone over a tree that carries it"
    );
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "plain",
            FIXED_TIMESTAMP,
            "--orphan",
            tree.to_str().unwrap(),
        ],
    );
}

/// `commit --bootable` derives `ostree.linux` and `ostree.bootable` from the one
/// kernel directory in the committed tree, and refuses in the tool's words where
/// the tree holds no kernel or more than one.
#[test]
fn commit_bootable_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-bootable");
    let base = tmp.path();
    let kernel = base.join("kernel");
    build_kernel_tree(&kernel);

    for mode in [
        RepoMode::Archive,
        RepoMode::Bare,
        RepoMode::BareUser,
        RepoMode::BareUserOnly,
    ] {
        let side = base.join(format!("m{}", mode.as_mode_str()));
        std::fs::create_dir_all(&side).unwrap();
        let (port_repo, tool_repo) = create_repo_pair(&side, mode);
        let src = kernel.to_str().unwrap();
        for (n, extra) in [
            vec![],
            vec!["--no-bindings"],
            vec!["--bind-ref=other"],
            // The derived value replaces one the command line supplies for the
            // same key, so these three reach the commit `--bootable` alone makes.
            vec!["--add-metadata-string=ostree.linux=9.9.9"],
            vec!["--add-metadata-string=ostree.bootable=false"],
            vec![
                "--add-metadata-string=ostree.linux=1",
                "--add-metadata-string=ostree.linux=2",
            ],
        ]
        .into_iter()
        .enumerate()
        {
            let branch = format!("bt{n}");
            let mut args = vec!["commit", "-b", &branch, FIXED_TIMESTAMP, "--bootable"];
            args.extend_from_slice(&extra);
            args.push(src);
            assert_agrees(&port_repo, &tool_repo, &args);
        }

        // The derived pair itself, read back out of both repositories: the
        // version the one kernel directory names, the boolean beside it, one
        // entry of each name, and the slot the pair holds ahead of the
        // bindings, whatever the command line supplied under those names.
        for (repo, port) in [(&port_repo, true), (&tool_repo, false)] {
            for branch in ["bt0", "bt3", "bt4", "bt5"] {
                let text = raw_commit(repo, branch, port);
                for entry in [
                    "'ostree.linux': <'6.1.0-test'>",
                    "'ostree.bootable': <true>",
                ] {
                    assert!(
                        text.contains(entry),
                        "`{branch}` carries no {entry}:\n{text}"
                    );
                }
                for name in ["'ostree.linux'", "'ostree.bootable'"] {
                    assert_eq!(
                        text.matches(name).count(),
                        1,
                        "`{branch}` carries {name} more than once:\n{text}"
                    );
                }
                let linux = text.find("'ostree.linux'").expect("the derived version");
                let bootable = text.find("'ostree.bootable'").expect("the derived flag");
                let binding = text
                    .find("'ostree.ref-binding'")
                    .expect("the branch binding");
                assert!(
                    linux < bootable && bootable < binding,
                    "the derived pair left its slot in `{branch}`:\n{text}"
                );
            }
        }

        // The derived value replaces one the command line supplies under the
        // same name and keeps the derived slot, so the four spellings reach one
        // commit. One branch name and `--parent=none` hold the ref binding and
        // the parent still, so the checksum states the dict alone.
        let mut reached = Vec::new();
        for extra in [
            vec![],
            vec!["--add-metadata-string=ostree.linux=9.9.9"],
            vec!["--add-metadata-string=ostree.bootable=false"],
            vec![
                "--add-metadata-string=ostree.linux=1",
                "--add-metadata-string=ostree.linux=2",
            ],
        ] {
            let mut args = vec![
                "commit",
                "-b",
                "btone",
                "--parent=none",
                FIXED_TIMESTAMP,
                "--bootable",
            ];
            args.extend_from_slice(&extra);
            args.push(src);
            let (port, tool) = run_both(&port_repo, &tool_repo, &args);
            assert_runs_agree(&port, &tool, &args.join(" "));
            reached.push(port.ok().stdout_trimmed());
        }
        for (index, checksum) in reached.iter().enumerate() {
            assert_eq!(
                checksum, &reached[0],
                "supplied-value case {index} reached another commit than `--bootable` alone",
            );
        }
    }

    // The tree shapes, each committed into an archive pair.
    let side = base.join("shapes");
    std::fs::create_dir_all(&side).unwrap();
    let (port_repo, tool_repo) = create_repo_pair(&side, RepoMode::Archive);
    let shape = |name: &str| -> PathBuf {
        let root = base.join(name);
        std::fs::create_dir_all(&root).unwrap();
        root
    };

    let no_usr = shape("no-usr");
    std::fs::write(no_usr.join("f"), b"x\n").unwrap();
    let no_lib = shape("no-lib");
    std::fs::create_dir_all(no_lib.join("usr/bin")).unwrap();
    std::fs::write(no_lib.join("usr/bin/f"), b"x\n").unwrap();
    let no_modules = shape("no-modules");
    std::fs::create_dir_all(no_modules.join("usr/lib/x")).unwrap();
    std::fs::write(no_modules.join("usr/lib/x/f"), b"x\n").unwrap();
    let no_kernel = shape("no-kernel");
    std::fs::create_dir_all(no_kernel.join("usr/lib/modules/6.1.0")).unwrap();
    std::fs::write(no_kernel.join("usr/lib/modules/README"), b"x\n").unwrap();
    std::fs::write(
        no_kernel.join("usr/lib/modules/6.1.0/initramfs.img"),
        b"x\n",
    )
    .unwrap();
    let two = shape("two-kernels");
    for version in ["1.0", "2.0"] {
        let dir = two.join("usr/lib/modules").join(version);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vmlinuz"), b"k\n").unwrap();
    }
    let symlinked = shape("symlinked-kernel");
    let dir = symlinked.join("usr/lib/modules/7.0.0");
    std::fs::create_dir_all(&dir).unwrap();
    std::os::unix::fs::symlink("vmlinuz-real", dir.join("vmlinuz")).unwrap();
    let lib_is_a_file = shape("lib-is-a-file");
    std::fs::create_dir_all(lib_is_a_file.join("usr")).unwrap();
    std::fs::write(lib_is_a_file.join("usr/lib"), b"x\n").unwrap();
    let nested = shape("nested-kernel");
    std::fs::create_dir_all(nested.join("usr/lib/modules/8.0/sub")).unwrap();
    std::fs::write(nested.join("usr/lib/modules/8.0/sub/vmlinuz"), b"k\n").unwrap();
    let modules_alias = shape("modules-alias");
    let real = modules_alias.join("usr/lib/modules/real");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::write(real.join("vmlinuz"), b"k\n").unwrap();
    std::os::unix::fs::symlink("real", modules_alias.join("usr/lib/modules/alias")).unwrap();
    let stray = shape("stray-file");
    let stray_modules = stray.join("usr/lib/modules");
    std::fs::create_dir_all(stray_modules.join("9.0")).unwrap();
    std::fs::write(stray_modules.join("9.0/vmlinuz"), b"k\n").unwrap();
    std::fs::write(stray_modules.join("README"), b"x\n").unwrap();

    // Each shape is either refused by both or accepted by both, which the
    // agreement alone does not state, so the status is held on each side.
    for (n, (src, accepted)) in [
        (&no_usr, false),
        (&no_lib, false),
        (&no_modules, false),
        (&no_kernel, false),
        (&two, false),
        (&symlinked, true),
        (&lib_is_a_file, false),
        (&nested, false),
        (&modules_alias, true),
        (&stray, true),
    ]
    .iter()
    .enumerate()
    {
        let branch = format!("shape{n}");
        let args = [
            "commit",
            "-b",
            &branch,
            FIXED_TIMESTAMP,
            "--bootable",
            "--orphan",
            src.to_str().unwrap(),
        ];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let label = args.join(" ");
        assert_runs_agree(&port, &tool, &label);
        let expected = if *accepted { 0 } else { 1 };
        for (who, run) in [("port", &port), ("tool", &tool)] {
            assert_eq!(
                run.status.code(),
                Some(expected),
                "the {who} answered `{label}` with another status:\n{}",
                String::from_utf8_lossy(&run.stderr),
            );
        }
    }

    // The derived keys stand after the control-file reports, after the
    // empty-tree refusal, and after `--skip-if-unchanged`, so each of those
    // reaches its own message over a tree holding no kernel.
    let unmatched = base.join("skip.txt");
    std::fs::write(&unmatched, "/nope.txt\n").unwrap();
    let prune_root = base.join("prune.txt");
    std::fs::write(&prune_root, "/\n").unwrap();
    for (extra, reported) in [
        (
            format!("--skip-list={}", unmatched.display()),
            "Unmatched skip-list path",
        ),
        (
            format!("--skip-list={}", prune_root.display()),
            "Can't commit an empty tree",
        ),
    ] {
        let args = [
            "commit",
            "-b",
            "order",
            FIXED_TIMESTAMP,
            "--bootable",
            &extra,
            "--orphan",
            no_usr.to_str().unwrap(),
        ];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let label = args.join(" ");
        assert_runs_agree(&port, &tool, &label);
        // The walk's own fault is the one reported, and the kernel search never
        // runs, so its message is absent.
        assert_runs_agree_on_error(&port, &tool, &label, reported);
        for (who, run) in [("port", &port), ("tool", &tool)] {
            assert!(
                !String::from_utf8_lossy(&run.stderr).contains("/usr"),
                "the {who} reached the kernel search for `{label}`",
            );
        }
    }
    let src = kernel.to_str().unwrap();
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["commit", "-b", "skipped", FIXED_TIMESTAMP, src],
    );
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "skipped",
            FIXED_TIMESTAMP,
            "--bootable",
            "--skip-if-unchanged",
            src,
        ],
    );
    // The same pairing over a tree holding no kernel: the match is reported
    // ahead of the kernel search, so the parent's checksum is printed at exit 0
    // where the search alone would refuse.
    let no_kernel_src = no_usr.to_str().unwrap();
    let seeded = run_both(
        &port_repo,
        &tool_repo,
        &["commit", "-b", "kernelless", FIXED_TIMESTAMP, no_kernel_src],
    );
    assert_runs_agree(&seeded.0, &seeded.1, "commit -b kernelless");
    let parent = seeded.0.ok().stdout_trimmed();
    let args = [
        "commit",
        "-b",
        "kernelless",
        FIXED_TIMESTAMP,
        "--bootable",
        "--skip-if-unchanged",
        no_kernel_src,
    ];
    let (port, tool) = run_both(&port_repo, &tool_repo, &args);
    assert_runs_agree(&port, &tool, &args.join(" "));
    for (who, run) in [("port", &port), ("tool", &tool)] {
        assert_eq!(
            run.status.code(),
            Some(0),
            "the {who} ran the kernel search ahead of `--skip-if-unchanged`:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
        assert_eq!(
            run.stdout_trimmed(),
            parent,
            "the {who} printed another checksum than the parent's",
        );
    }

    // The tar stream carries the same tree, so the derived value is the same.
    let tar = base.join("kernel.tar");
    assert!(
        Command::new("tar")
            .arg("-cf")
            .arg(&tar)
            .arg("-C")
            .arg(&kernel)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    let tar_bytes = std::fs::read(&tar).unwrap();
    let port = ostrya(
        &[
            "commit",
            &format!("--repo={}", port_repo.display()),
            "-b",
            "tarred",
            FIXED_TIMESTAMP,
            "--bootable",
            "--orphan",
        ],
        Some(&tar_bytes),
        &[],
    );
    let tool = ostree(&[
        "commit",
        &format!("--repo={}", tool_repo.display()),
        "-b",
        "tarred",
        FIXED_TIMESTAMP,
        "--bootable",
        "--orphan",
        &format!("--tree=tar={}", tar.display()),
    ]);
    assert_eq!(
        port.ok().stdout_trimmed(),
        tool.ok().stdout_trimmed(),
        "the tar stream and --tree=tar disagree under --bootable"
    );
}

/// `commit --generate-composefs-metadata` stores the fs-verity digest of the
/// tree's composefs image, which is the same value in every repository mode that
/// holds the same tree.
#[test]
fn commit_generate_composefs_metadata_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-composefs");
    let base = tmp.path();
    let kernel = base.join("kernel");
    build_kernel_tree(&kernel);
    let deep = base.join("deep");
    std::fs::create_dir_all(deep.join("a/b/c")).unwrap();
    std::fs::write(deep.join("a/f1"), b"one\n").unwrap();
    std::fs::write(deep.join("a/b/c/big.bin"), vec![b'z'; 70_000]).unwrap();
    std::os::unix::fs::symlink("a/f1", deep.join("link")).unwrap();

    let mut digests = Vec::new();
    for mode in [
        RepoMode::Archive,
        RepoMode::Bare,
        RepoMode::BareUser,
        RepoMode::BareUserOnly,
    ] {
        let side = base.join(format!("m{}", mode.as_mode_str()));
        std::fs::create_dir_all(&side).unwrap();
        let (port_repo, tool_repo, tree) = commit_pair(&side, mode);
        for (n, src) in [&tree, &kernel, &deep].iter().enumerate() {
            let branch = format!("cfs{n}");
            assert_agrees(
                &port_repo,
                &tool_repo,
                &[
                    "commit",
                    "-b",
                    &branch,
                    FIXED_TIMESTAMP,
                    "--generate-composefs-metadata",
                    "--orphan",
                    src.to_str().unwrap(),
                ],
            );
        }
        let printed = ostrya(
            &[
                "show",
                &format!("--repo={}", port_repo.display()),
                "--print-metadata-key=ostree.composefs.digest.v0",
                "--print-hex",
                "cfs0",
            ],
            None,
            &[],
        );
        digests.push((mode, printed.ok().stdout_trimmed()));
    }
    // The digest tracks the tree, so the three modes that store the same tree
    // reach one value; `bare-user-only` canonicalizes the tree and so differs.
    let value = |wanted: RepoMode| {
        digests
            .iter()
            .find(|(mode, _)| *mode == wanted)
            .map(|(_, digest)| digest.clone())
            .unwrap()
    };
    assert_eq!(
        value(RepoMode::Archive).len(),
        64,
        "a 32-byte digest in hex"
    );
    assert_eq!(value(RepoMode::Archive), value(RepoMode::Bare));
    assert_eq!(value(RepoMode::Archive), value(RepoMode::BareUser));
    assert_ne!(value(RepoMode::Archive), value(RepoMode::BareUserOnly));
}

/// A value supplied under the composefs digest's own name takes the derived
/// digest, in the slot the supplied value already stands in, over each of the
/// three routes that reach the metadata dict. A key the dict does not already
/// hold is appended after the bindings, so the supplied value moves the derived
/// entry ahead of `ostree.ref-binding`.
#[test]
fn commit_generate_composefs_metadata_over_a_supplied_value() {
    if !ostree_available() {
        return;
    }
    const KEY: &str = "ostree.composefs.digest.v0";
    let tmp = TmpDir::new("commit-composefs-supplied");
    let base = tmp.path();
    let kernel = base.join("kernel");
    build_kernel_tree(&kernel);
    let (port_repo, tool_repo, _) = commit_pair(base, RepoMode::Archive);
    let src = kernel.to_str().unwrap();

    for (n, extra) in [
        vec![],
        vec![format!("--add-metadata-string={KEY}=bogus")],
        vec![
            format!("--add-metadata-string={KEY}=a"),
            format!("--add-metadata-string={KEY}=b"),
        ],
        vec![format!("--add-metadata={KEY}=uint32 7")],
        vec![
            format!("--add-metadata-string={KEY}=bogus"),
            "--bootable".to_owned(),
            "--generate-sizes".to_owned(),
        ],
    ]
    .into_iter()
    .enumerate()
    {
        let branch = format!("cs{n}");
        let mut args = vec![
            "commit",
            "-b",
            &branch,
            FIXED_TIMESTAMP,
            "--generate-composefs-metadata",
        ];
        args.extend(extra.iter().map(String::as_str));
        args.push(src);
        assert_agrees(&port_repo, &tool_repo, &args);
    }

    // `--keep-metadata` carries the supplied value over from the parent, so the
    // derived digest replaces it there too.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "kept",
            FIXED_TIMESTAMP,
            &format!("--add-metadata-string={KEY}=frombase"),
            src,
        ],
    );
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "kept",
            "--timestamp=@1700000001",
            "--generate-composefs-metadata",
            &format!("--keep-metadata={KEY}"),
            src,
        ],
    );

    // The commits agree, so the entry order agrees with them. The tool's own
    // printer states which order that is: one entry either way, standing after
    // the bindings where nothing supplied the key and ahead of them where
    // something did.
    let slots = |branch: &str| -> (usize, usize) {
        let run = ostree(&[
            "show",
            &format!("--repo={}", tool_repo.display()),
            "--raw",
            branch,
        ]);
        let text = run.ok().stdout_trimmed();
        let key = format!("'{KEY}':");
        assert_eq!(
            text.matches(key.as_str()).count(),
            1,
            "{branch} holds the composefs digest more than once:\n{text}"
        );
        (
            text.find(key.as_str()).unwrap(),
            text.find("'ostree.ref-binding':")
                .unwrap_or_else(|| panic!("{branch} holds no bindings:\n{text}")),
        )
    };
    let (digest, binding) = slots("cs0");
    assert!(
        digest > binding,
        "an unsupplied digest follows the bindings"
    );
    for branch in ["cs1", "cs2", "cs3", "cs4", "kept"] {
        let (digest, binding) = slots(branch);
        assert!(
            digest < binding,
            "the digest left the slot the supplied value held in {branch}"
        );
    }

    // And the value in that slot is the derived digest, which the supplied one
    // never reaches.
    let stored = |branch: &str| -> String {
        let run = ostree(&[
            "show",
            &format!("--repo={}", tool_repo.display()),
            &format!("--print-metadata-key={KEY}"),
            "--print-hex",
            branch,
        ]);
        run.ok().stdout_trimmed()
    };
    let derived = stored("cs0");
    assert_eq!(derived.len(), 64, "a 32-byte digest in hex: {derived}");
    for branch in ["cs1", "cs2", "cs3", "cs4", "kept"] {
        assert_eq!(
            stored(branch),
            derived,
            "the value supplied under the digest's name survived in {branch}",
        );
    }
}

/// The derived keys take the slots the metadata key order gives them: the
/// `--bootable` pair first, the user keys next, then the bindings, then the
/// composefs digest, and `ostree.sizes` last
/// (`docs/format-reference.md`, "CLI output formats", `commit`).
#[test]
fn commit_derived_metadata_key_order() {
    let tmp = TmpDir::new("commit-derived-order");
    let base = tmp.path();
    let kernel = base.join("kernel");
    build_kernel_tree(&kernel);
    let repo = create_repo(base, RepoMode::Archive);
    let made = ostrya(
        &[
            "commit",
            &format!("--repo={}", repo.display()),
            "-b",
            "order",
            FIXED_TIMESTAMP,
            "--bootable",
            "--generate-sizes",
            "--generate-composefs-metadata",
            "--add-metadata-string=user.k=v",
            kernel.to_str().unwrap(),
        ],
        None,
        &[],
    );
    let checksum = made.ok().stdout_trimmed();
    let shown = ostrya(
        &[
            "show",
            &format!("--repo={}", repo.display()),
            "--raw",
            &checksum,
        ],
        None,
        &[],
    );
    let text = shown.ok().stdout_trimmed();
    let mut last = 0;
    for key in [
        "'ostree.linux'",
        "'ostree.bootable'",
        "'user.k'",
        "'ostree.ref-binding'",
        "'ostree.composefs.digest.v0'",
        "'ostree.sizes'",
    ] {
        let at = text
            .find(key)
            .unwrap_or_else(|| panic!("{key} is absent from the commit metadata:\n{text}"));
        assert!(at > last, "{key} is out of order in the metadata dict");
        last = at;
    }
}

/// Build the two overlay sources F4's composition cases use: `t1` and `t2`
/// share `f.txt` and `common/`, and each carries a directory the other does
/// not. Returns the parent holding both.
fn build_overlay_sources(base: &Path) -> PathBuf {
    let root = base.join("sources");
    for (name, own) in [("t1", "onlyA"), ("t2", "onlyB")] {
        let dir = root.join(name);
        std::fs::create_dir_all(dir.join("common")).unwrap();
        std::fs::create_dir_all(dir.join(own)).unwrap();
        std::fs::write(dir.join("f.txt"), format!("{name}-file\n")).unwrap();
        std::fs::write(dir.join("common").join(format!("{name}.txt")), "shared\n").unwrap();
        std::fs::write(dir.join(own).join("own.txt"), "own\n").unwrap();
        std::os::unix::fs::symlink("f.txt", dir.join("link")).unwrap();
    }
    // A symlink naming a directory, for the `dir=` source that resolves to a
    // tree through a link.
    std::os::unix::fs::symlink("t1", root.join("dirlink")).unwrap();
    // A file and a directory at the same path, for the two type-change
    // refusals. The name is reported without its parents.
    std::fs::create_dir_all(root.join("n1/a/b/p")).unwrap();
    std::fs::write(root.join("n1/a/b/p/i"), "inner\n").unwrap();
    std::fs::create_dir_all(root.join("n2/a/b")).unwrap();
    std::fs::write(root.join("n2/a/b/p"), "leaf\n").unwrap();
    // Two trees whose shared directories differ in mode alone.
    for (name, mode) in [("m1", 0o700u32), ("m2", 0o751)] {
        let dir = root.join(name);
        std::fs::create_dir_all(dir.join("d")).unwrap();
        std::fs::write(dir.join("d").join(name), "x\n").unwrap();
        for rel in ["d", ""] {
            std::fs::set_permissions(dir.join(rel), std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }
    root
}

/// Pack `dir` as an uncompressed tar with a `./` root member, next to it.
fn pack_tar(dir: &Path, archive: &Path) {
    let status = Command::new("tar")
        .arg("-cf")
        .arg(archive)
        .arg("-C")
        .arg(dir)
        .arg("./")
        .status()
        .expect("spawn tar");
    assert!(status.success(), "tar failed to pack {}", dir.display());
}

/// One 512-byte tar header block. `gnu` picks the old-GNU magic and version
/// (`ustar` plus two spaces and a NUL) over the ustar pair (`ustar`, NUL, `00`).
/// The name is taken as bytes, so a pathname that is not valid UTF-8 can be
/// stated.
fn tar_header(
    name: &[u8],
    mode: u32,
    typeflag: u8,
    link: &str,
    size: usize,
    gnu: bool,
) -> [u8; 512] {
    let mut h = [0u8; 512];
    let put = |h: &mut [u8; 512], at: usize, bytes: &[u8]| {
        h[at..at + bytes.len()].copy_from_slice(bytes);
    };
    put(&mut h, 0, name);
    put(&mut h, 100, format!("{mode:07o}\0").as_bytes());
    put(&mut h, 108, b"0000000\0");
    put(&mut h, 116, b"0000000\0");
    put(&mut h, 124, format!("{size:011o}\0").as_bytes());
    put(&mut h, 136, b"00000000000\0");
    // The checksum field is summed as eight spaces and written afterwards.
    put(&mut h, 148, b"        ");
    h[156] = typeflag;
    put(&mut h, 157, link.as_bytes());
    if gnu {
        put(&mut h, 257, b"ustar  \0");
    } else {
        put(&mut h, 257, b"ustar\0");
        put(&mut h, 263, b"00");
    }
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    put(&mut h, 148, format!("{sum:06o}\0 ").as_bytes());
    h
}

/// Pack an archive whose symlink members carry a spread of header mode fields.
/// `tar` writes `0777` for every symlink member it packs, so the field is
/// written here directly. The last two names hold a full `st_mode` in the octal
/// field, which states what happens to the bits above the low twelve.
fn pack_symlink_modes(archive: &Path, gnu: bool) {
    let modes: &[(&str, u32)] = &[
        ("l0000", 0o0),
        ("l0600", 0o600),
        ("l0644", 0o644),
        ("l0755", 0o755),
        ("l0777", 0o777),
        ("l1777", 0o1777),
        ("l2777", 0o2777),
        ("l4755", 0o4755),
        ("l7777", 0o7777),
        ("t120777", 0o120777),
        ("t100644", 0o100644),
    ];
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&tar_header(b"./", 0o755, b'5', "", 0, gnu));
    let body = b"hello\n";
    out.extend_from_slice(&tar_header(b"./file.txt", 0o644, b'0', "", body.len(), gnu));
    out.extend_from_slice(body);
    out.resize(out.len().next_multiple_of(512), 0);
    for (name, mode) in modes {
        let member = format!("./{name}");
        out.extend_from_slice(&tar_header(
            member.as_bytes(),
            *mode,
            b'2',
            "file.txt",
            0,
            gnu,
        ));
    }
    // Two zero blocks end the stream, and the whole is padded to a tar record.
    out.resize(out.len() + 1024, 0);
    out.resize(out.len().next_multiple_of(10240), 0);
    std::fs::write(archive, &out).unwrap();
}

/// Pack an archive holding a `./` root member and one regular file whose name
/// holds the byte `0xFF`, which no pathname the `run:` grammar writes can hold.
fn pack_invalid_pathname(archive: &Path) {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&tar_header(b"./", 0o755, b'5', "", 0, false));
    let body = b"hello\n";
    out.extend_from_slice(&tar_header(
        b"./b\xFFd.txt",
        0o644,
        b'0',
        "",
        body.len(),
        false,
    ));
    out.extend_from_slice(body);
    out.resize(out.len().next_multiple_of(512), 0);
    // Two zero blocks end the stream, and the whole is padded to a tar record.
    out.resize(out.len() + 1024, 0);
    out.resize(out.len().next_multiple_of(10240), 0);
    std::fs::write(archive, &out).unwrap();
}

/// `commit --tree=dir=`, `--tree=tar=`, and `--tree=ref=` compose as one
/// ordered overlay: directories merge, a later source's directory metadata
/// replaces the earlier one, later files replace earlier files, and a name that
/// changes between a file and a directory is refused. Every accepted form is
/// compared by the commit checksum, so what is compared is the tree both
/// implementations wrote.
#[test]
fn commit_tree_sources_match_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-tree-sources");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let root = build_overlay_sources(base);
    let path = |name: &str| root.join(name).to_str().unwrap().to_owned();
    let t1 = path("t1");
    let t2 = path("t2");
    let a_tar = base.join("t1.tar");
    pack_tar(&root.join("t1"), &a_tar);
    let b_tar = base.join("t2.tar");
    pack_tar(&root.join("t2"), &b_tar);
    let tar = |archive: &Path| format!("--tree=tar={}", archive.display());

    // Both repositories hold the same two committed trees, so `ref=` names the
    // same revisions on each side.
    for (branch, source) in [("src1", &t1), ("src2", &t2)] {
        assert_agrees(
            &port_repo,
            &tool_repo,
            &[
                "commit",
                "-b",
                branch,
                "--orphan",
                FIXED_TIMESTAMP,
                &format!("--tree=dir={source}"),
            ],
        );
    }

    let mut branch = 0;
    let mut agrees = |extra: &[&str]| {
        branch += 1;
        let name = format!("c{branch}");
        let mut args = vec!["commit", "-b", &name, FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        assert_agrees(&port_repo, &tool_repo, &args);
    };

    // One source of each kind, then every ordered pair of kinds. The order
    // decides `f.txt` and the root's metadata, so the two directions reach
    // different checksums and each is compared on its own.
    agrees(&[&format!("--tree=dir={t1}")]);
    agrees(&["--tree=ref=src1"]);
    agrees(&[&tar(&a_tar)]);
    agrees(&[&format!("--tree=dir={t1}"), &format!("--tree=dir={t2}")]);
    agrees(&[&format!("--tree=dir={t2}"), &format!("--tree=dir={t1}")]);
    agrees(&[&format!("--tree=dir={t1}"), &format!("--tree=dir={t1}")]);
    agrees(&[&format!("--tree=dir={t1}"), "--tree=ref=src2"]);
    agrees(&["--tree=ref=src2", &format!("--tree=dir={t1}")]);
    agrees(&["--tree=ref=src1", "--tree=ref=src2"]);
    agrees(&["--tree=ref=src1", &tar(&b_tar)]);
    agrees(&[&tar(&a_tar), "--tree=ref=src2"]);
    agrees(&[&format!("--tree=dir={t2}"), &tar(&a_tar)]);
    agrees(&[&tar(&a_tar), &format!("--tree=dir={t2}")]);
    agrees(&[&tar(&a_tar), &tar(&b_tar)]);
    agrees(&[&format!("--tree=dir={t1}"), &tar(&b_tar), "--tree=ref=src1"]);
    // A trailing slash on a `dir=` value, and a revision expression `ref=`
    // resolves the way `rev-parse` does.
    agrees(&[&format!("--tree=dir={t1}/")]);
    agrees(&["--tree=ref=src1", "--tree=ref=src2"]);
    // Directory metadata: the later source's dirmeta replaces the earlier one
    // for the root and for a shared subdirectory.
    agrees(&[
        &format!("--tree=dir={}", path("m1")),
        &format!("--tree=dir={}", path("m2")),
    ]);
    agrees(&[
        &format!("--tree=dir={}", path("m2")),
        &format!("--tree=dir={}", path("m1")),
    ]);
    // A positional PATH beside any `--tree` is ignored, unopened, at exit 0,
    // and so is every positional after the first where no `--tree` is given.
    agrees(&[&format!("--tree=dir={t1}"), &t2]);
    agrees(&[&format!("--tree=dir={t1}"), "/nonexistent-xyz"]);
    agrees(&[&t1, &t2]);

    // The two type-change refusals name the entry and not its path.
    for (first, second, message) in [
        ("n1", "n2", "error: Can't replace directory with file: p"),
        ("n2", "n1", "error: Can't replace file with directory: p"),
    ] {
        assert_agrees(
            &port_repo,
            &tool_repo,
            &[
                "commit",
                "-b",
                "conflict",
                FIXED_TIMESTAMP,
                &format!("--tree=dir={}", path(first)),
                &format!("--tree=dir={}", path(second)),
            ],
        );
        let (port, _) = run_both(
            &port_repo,
            &tool_repo,
            &[
                "commit",
                "-b",
                "conflict",
                FIXED_TIMESTAMP,
                &format!("--tree=dir={}", path(first)),
                &format!("--tree=dir={}", path(second)),
            ],
        );
        assert_eq!(
            String::from_utf8_lossy(&port.stderr),
            format!("{message}\n")
        );
    }

    // The specification refusals, and the source that does not open.
    let file = root.join("t1/f.txt");
    let link = root.join("t1/link");
    for args in [
        vec![format!("--tree=foo={t1}")],
        vec![format!("--tree={t1}")],
        vec!["--tree=dir=/nonexistent-zz".to_owned()],
        vec![format!("--tree=dir={}", file.display())],
        vec![format!("--tree=dir={}", link.display())],
        vec![format!("--tree=dir={}", root.join("dirlink").display())],
        vec!["--tree=tar=/nonexistent.tar".to_owned()],
        vec!["--tree=ref=nosuchref".to_owned()],
        vec!["--tree=ref=src1^".to_owned()],
    ] {
        let mut line = vec!["commit", "-b", "refused", FIXED_TIMESTAMP];
        let extra: Vec<&str> = args.iter().map(String::as_str).collect();
        line.extend_from_slice(&extra);
        let (port, tool) = run_both(&port_repo, &tool_repo, &line);
        let label = line.join(" ");
        assert_runs_agree(&port, &tool, &label);
        // Each is a refusal, which the agreement alone does not state.
        for (who, run) in [("port", &port), ("tool", &tool)] {
            assert_eq!(
                run.status.code(),
                Some(1),
                "the {who} accepted `{label}`:\n{}",
                String::from_utf8_lossy(&run.stdout),
            );
        }
    }
}

/// `commit --base=REV` is the bottom layer whatever its position, the last
/// value wins, and no commit modifier reaches an entry that survives from it.
#[test]
fn commit_base_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-base");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let root = build_overlay_sources(base);
    let t1 = root.join("t1").to_str().unwrap().to_owned();
    let t2 = root.join("t2").to_str().unwrap().to_owned();
    let tar = base.join("t2.tar");
    pack_tar(&root.join("t2"), &tar);

    // One xattr on the entry that survives from the base and one on the entry
    // the later source brings, so `--no-xattrs` states which of the two the
    // modifier reaches. A filesystem that carries no user xattr leaves the two
    // arms below out.
    let setfattr = |path: &Path, name: &str, value: &str| -> bool {
        Command::new("setfattr")
            .args(["-n", name, "-v", value])
            .arg(path)
            .status()
            .is_ok_and(|status| status.success())
    };
    let xattrs = setfattr(&root.join("t1/onlyA/own.txt"), "user.base", "kept")
        && setfattr(&root.join("t2/onlyB/own.txt"), "user.tree", "made");

    for (branch, source) in [("src1", &t1), ("src2", &t2)] {
        assert_agrees(
            &port_repo,
            &tool_repo,
            &[
                "commit",
                "-b",
                branch,
                "--orphan",
                FIXED_TIMESTAMP,
                &format!("--tree=dir={source}"),
            ],
        );
    }

    let mut branch = 0;
    let mut agrees = |extra: &[&str]| -> String {
        branch += 1;
        let name = format!("b{branch}");
        let mut args = vec!["commit", "-b", &name, FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        assert_agrees(&port_repo, &tool_repo, &args);
        name
    };

    // The base under one source, on either side of it, and repeated.
    agrees(&["--base=src1", &format!("--tree=dir={t2}")]);
    agrees(&[&format!("--tree=dir={t2}"), "--base=src1"]);
    agrees(&["--base=src1", "--base=src2", &format!("--tree=dir={t2}")]);
    agrees(&["--base=src1", &format!("--tree=tar={}", tar.display())]);
    agrees(&["--base=src1", "--tree=ref=src2"]);
    // A skip list naming the walk root prunes the walk, so the base is the
    // whole tree and the commit is written rather than refused as empty.
    let root_skip = base.join("skip-root.txt");
    std::fs::write(&root_skip, "/\n").unwrap();
    let root_skip = format!("--skip-list={}", root_skip.display());
    agrees(&["--base=src1", &root_skip, &format!("--tree=dir={t2}")]);
    // The pruned walk accounts no object, so `--generate-sizes` writes no
    // `ostree.sizes` key and the commit states the same checksum without one.
    agrees(&[
        "--base=src1",
        &root_skip,
        "--generate-sizes",
        &format!("--tree=dir={t2}"),
    ]);
    // No modifier reaches an entry that survives from the base, and every
    // modifier reaches one that arrives from a `--tree`, `ref=` included.
    let owned = agrees(&[
        "--base=src1",
        &format!("--tree=dir={t2}"),
        "--owner-uid=99",
        "--owner-gid=98",
    ]);
    agrees(&[
        "--base=src1",
        &format!("--tree=dir={t2}"),
        "--canonical-permissions",
    ]);
    agrees(&["--base=src1", "--tree=ref=src2", "--owner-uid=99"]);
    agrees(&["--base=src1", "--tree=ref=src2", "--no-xattrs"]);
    let bare = if xattrs {
        Some(agrees(&[
            "--base=src1",
            &format!("--tree=dir={t2}"),
            "--no-xattrs",
        ]))
    } else {
        None
    };

    // What the two commits above recorded, read back per entry. `ls -X -R`
    // prints the mode, the ownership, the size, and the xattr set of each path,
    // so the row of an entry that survives from the base equals the row the base
    // commit itself holds, and the row of an entry the later source brought
    // carries what the modifier did to it.
    let row = |repo: &Path, rev: &str, path: &str, port: bool| -> String {
        let repo_arg = format!("--repo={}", repo.display());
        let args = ["ls", &repo_arg, "-X", "-R", rev];
        let run = if port {
            ostrya(&args, None, &[])
        } else {
            ostree(&args)
        };
        assert!(
            run.status.success(),
            "`ls -X -R {rev}` failed:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
        let listing = String::from_utf8(run.stdout).expect("the listing is text");
        listing
            .lines()
            .find(|line| line.ends_with(path))
            .unwrap_or_else(|| panic!("`{path}` is absent from `ls -X -R {rev}`:\n{listing}"))
            .to_owned()
    };
    for (repo, port) in [(&port_repo, true), (&tool_repo, false)] {
        let from_base = row(repo, "src1", "/onlyA/own.txt", port);
        let from_tree = row(repo, "src2", "/onlyB/own.txt", port);
        for name in [Some(&owned), bare.as_ref()].into_iter().flatten() {
            assert_eq!(
                row(repo, name, "/onlyA/own.txt", port),
                from_base,
                "a modifier reached the entry `{name}` kept from the base",
            );
            assert_ne!(
                row(repo, name, "/onlyB/own.txt", port),
                from_tree,
                "no modifier reached the entry `{name}` took from the tree",
            );
        }
        if let Some(name) = &bare {
            assert!(
                from_base.contains("user.base"),
                "the base commit recorded no xattr, so `--no-xattrs` states nothing",
            );
            assert!(
                !row(repo, name, "/onlyB/own.txt", port).contains("user.tree"),
                "`--no-xattrs` left the tree entry's xattr in place",
            );
        }
    }
    // The base resolves before the tree specifications and after the
    // missing-branch check.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "bad",
            FIXED_TIMESTAMP,
            "--base=nosuchref",
            &format!("--tree=dir={t1}"),
        ],
    );
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "bad",
            FIXED_TIMESTAMP,
            "--base=nosuchref",
            "--tree=foo=x",
        ],
    );
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            FIXED_TIMESTAMP,
            "--base=nosuchref",
            &format!("--tree=dir={t1}"),
        ],
    );
}

/// `commit --tree=tar=PATH` reads an archive into the same overlay a filesystem
/// source lands in, and `--tar-autocreate-parents` supplies the directories the
/// archive never names.
#[test]
fn commit_tar_source_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-tar-source");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let root = build_overlay_sources(base);
    let t1 = root.join("t1").to_str().unwrap().to_owned();
    let full = base.join("full.tar");
    pack_tar(&root.join("t1"), &full);

    // An archive with no root member, one whose member names a parent no
    // member creates, an empty archive, and one carrying a hardlink.
    let pack = |args: &[&str], archive: &Path| {
        let status = Command::new("tar")
            .arg("-cf")
            .arg(archive)
            .args(args)
            .current_dir(&root)
            .status()
            .expect("spawn tar");
        assert!(status.success(), "tar failed");
    };
    let rootless = base.join("rootless.tar");
    pack(&["t1/f.txt", "t1/common"], &rootless);
    let deep = base.join("deep.tar");
    pack(&["--no-recursion", "t1/common/t1.txt"], &deep);
    let empty = base.join("empty.tar");
    pack(&["-T", "/dev/null"], &empty);
    let hl = root.join("hl");
    std::fs::create_dir_all(&hl).unwrap();
    std::fs::write(hl.join("one"), "hard\n").unwrap();
    std::fs::hard_link(hl.join("one"), hl.join("two")).unwrap();
    let hard = base.join("hard.tar");
    pack_tar(&hl, &hard);

    let mut branch = 0;
    let mut agrees = |extra: &[&str]| -> String {
        branch += 1;
        let name = format!("t{branch}");
        let mut args = vec!["commit", "-b", &name, FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        assert_agrees(&port_repo, &tool_repo, &args);
        name
    };
    let tar = |archive: &Path| format!("--tree=tar={}", archive.display());

    agrees(&[&tar(&full)]);
    agrees(&[&tar(&hard)]);
    // Every modifier that reaches a filesystem source reaches an archive too.
    agrees(&[&tar(&full), "--canonical-permissions"]);
    agrees(&[&tar(&full), "--no-xattrs"]);
    agrees(&[&tar(&full), "--owner-uid=77", "--owner-gid=78"]);
    agrees(&[&tar(&full), "--mode-ro-executables"]);
    // A `--statoverride` entry reaches an archive's symlink member as it reaches
    // a filesystem symlink: the member carries the `S_IFLNK` file type, so the
    // entry states the permission bits the content object records, and the
    // canonical reduction leaves a symlink's mode as the entry left it.
    let over_assign = base.join("over-assign.txt");
    std::fs::write(&over_assign, "=448 /link\n").unwrap();
    let assign = format!("--statoverride={}", over_assign.display());
    let over_or = base.join("over-or.txt");
    std::fs::write(&over_or, "2048 /link\n").unwrap();
    let or = format!("--statoverride={}", over_or.display());
    agrees(&[&tar(&full), &assign]);
    agrees(&[&tar(&full), &or]);
    agrees(&[&tar(&full), &assign, "--canonical-permissions"]);
    // An archive member is the one source the OR form reaches over a directory
    // below the walk root, where a filesystem walk leaves the directory at the
    // mode it found. `commit_statoverride_spends_one_entry_per_run` states the
    // rule in full; the two arms here hold it over this test's own corpus.
    let over_dir = base.join("over-dir.txt");
    std::fs::write(&over_dir, "16 /common\n").unwrap();
    let or_dir = format!("--statoverride={}", over_dir.display());
    let from_tar = agrees(&[&tar(&full), &or_dir]);
    let from_dir = agrees(&[&format!("--tree=dir={t1}"), &or_dir]);
    let common = |branch: &str| -> String {
        let run = ostree(&[
            "ls",
            &format!("--repo={}", tool_repo.display()),
            "-R",
            branch,
        ]);
        run.ok()
            .stdout_trimmed()
            .lines()
            .find(|line| line.split_whitespace().nth(4) == Some("/common"))
            .expect("`/common` is absent from the listing")
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        common(&from_tar),
        "d00775",
        "the OR form left the archive's directory member alone",
    );
    assert_eq!(
        common(&from_dir),
        "d00755",
        "the OR form reached a directory below the walk root of a `dir=` source",
    );
    // The entry reaches an archive's symlink member as it reaches a filesystem
    // symlink, so the two sources under one entry reach one commit. One branch
    // name and `--parent=none` hold the ref binding and the parent still.
    let mut over_both = Vec::new();
    for source in [format!("--tree=dir={t1}"), tar(&full)] {
        let args = [
            "commit",
            "-b",
            "symsame",
            "--parent=none",
            FIXED_TIMESTAMP,
            &assign,
            &source,
        ];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        assert_runs_agree(&port, &tool, &args.join(" "));
        over_both.push(port.ok().stdout_trimmed());
    }
    assert_eq!(
        over_both[0], over_both[1],
        "the entry reached the archive's symlink member otherwise",
    );
    // A walk filter reaches an archive too.
    let skip = base.join("tar-skip.txt");
    std::fs::write(&skip, "/common\n").unwrap();
    agrees(&[&tar(&full), &format!("--skip-list={}", skip.display())]);
    // A symlink member records the low twelve bits of its own header mode
    // field, the setuid, setgid, and sticky bits included, and drops the bits
    // above them. The old-GNU and the ustar header forms are read alike, and
    // the canonical reduction leaves the mode as the member left it.
    let mut header_forms = Vec::new();
    for (gnu, name) in [(true, "sym-gnu.tar"), (false, "sym-ustar.tar")] {
        let sym = base.join(name);
        pack_symlink_modes(&sym, gnu);
        let form = agrees(&[&tar(&sym)]);
        agrees(&[&tar(&sym), "--canonical-permissions"]);
        header_forms.push(form);
    }
    // The two header forms are read alike, which one branch each cannot state,
    // so the two trees are compared through the tool's own recursive listing.
    let listing = |branch: &str| -> String {
        let run = ostree(&[
            "ls",
            &format!("--repo={}", tool_repo.display()),
            "-R",
            branch,
        ]);
        run.ok().stdout_trimmed()
    };
    assert_eq!(
        listing(&header_forms[0]),
        listing(&header_forms[1]),
        "the old-GNU and the ustar header forms are read differently",
    );
    // An archive naming no root member leaves the tree without one, which is
    // the empty-tree refusal, unless another source supplied it.
    agrees(&[&tar(&rootless)]);
    agrees(&[&tar(&empty)]);
    agrees(&[&format!("--tree=dir={t1}"), &tar(&rootless)]);
    // A member whose parent no member names is refused, and the refusal names
    // the first absent ancestor.
    agrees(&[&tar(&deep)]);
    agrees(&[&format!("--tree=dir={t1}"), &tar(&deep)]);
    // `--tar-autocreate-parents` supplies the root as `0755 0:0` where nothing
    // else does, and supplies an intermediate parent with the triggering
    // member's ownership, rewriting the root's metadata to match.
    let supplied_deep = agrees(&[&tar(&deep), "--tar-autocreate-parents"]);
    let supplied_empty = agrees(&[&tar(&empty), "--tar-autocreate-parents"]);
    agrees(&[&tar(&rootless), "--tar-autocreate-parents"]);
    // The values the flag supplies, read out of both repositories: a root no
    // member names is mode `0755` owned `0:0`, and an intermediate parent is
    // mode `0755` with the triggering member's ownership, which the root's own
    // metadata is rewritten to.
    let meta = std::fs::metadata(&root).expect("the source tree stats");
    let owner = format!("{} {}", meta.uid(), meta.gid());
    for (repo, port) in [(&port_repo, true), (&tool_repo, false)] {
        let rows = |branch: &str| -> Vec<String> {
            let repo_arg = format!("--repo={}", repo.display());
            let args = ["ls", &repo_arg, "-R", branch];
            let run = if port {
                ostrya(&args, None, &[])
            } else {
                ostree(&args)
            };
            String::from_utf8(run.ok().stdout.clone())
                .expect("the listing is text")
                .lines()
                .map(str::to_owned)
                .collect()
        };
        let empty_rows = rows(&supplied_empty);
        assert_eq!(empty_rows.len(), 1, "the empty archive holds one entry");
        assert!(
            empty_rows[0].starts_with("d00755 0 0 "),
            "a supplied root is not `0755 0:0`: {}",
            empty_rows[0],
        );
        for row in rows(&supplied_deep) {
            if row.starts_with('d') {
                assert!(
                    row.starts_with(&format!("d00755 {owner} ")),
                    "a supplied parent carries other metadata: {row}",
                );
            }
        }
    }
    agrees(&[
        &format!("--tree=dir={t1}"),
        &tar(&deep),
        "--tar-autocreate-parents",
    ]);
    // The flag is accepted, and does nothing, where no archive is read.
    agrees(&[&format!("--tree=dir={t1}"), "--tar-autocreate-parents"]);
}

/// A member whose pathname holds a byte that is not valid UTF-8 is refused by
/// both at exit 1, in the same words. The `run:` grammar writes no archive, so
/// the cell `commit/tree-tar-pathname-not-utf8` cites this test.
#[test]
fn commit_tar_pathname_not_utf8_is_refused() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-tar-pathname");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let archive = base.join("invalid-pathname.tar");
    pack_invalid_pathname(&archive);
    assert_agrees_on_error(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "conformance",
            FIXED_TIMESTAMP,
            &format!("--tree=tar={}", archive.display()),
        ],
        "error: Archive entry pathname is not valid UTF-8",
    );
}

/// A filesystem entry whose name holds a byte that is not valid UTF-8 refuses
/// the commit in both, ahead of the walk callbacks, so a `--skip-list` or a
/// `--statoverride` path spelling the replacement character reaches no such
/// entry. The `run:` grammar writes no such name, so the cell
/// `commit/tree-dir-name-not-utf8` cites this test.
#[test]
fn commit_tree_name_not_utf8_is_refused() {
    if !ostree_available() {
        return;
    }
    use std::os::unix::ffi::OsStrExt;

    let tmp = TmpDir::new("commit-name-utf8");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let src = base.join("tree");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("plain.txt"), "plain\n").unwrap();
    let raw = src.join(std::ffi::OsStr::from_bytes(b"bad\xff.txt"));
    std::fs::write(&raw, "raw\n").unwrap();
    let src = src.to_str().unwrap().to_owned();

    // The control files spell the replacement character, which is the string a
    // lossy conversion of the raw name would give. Each of the three forms
    // leaves that entry alone, so the walk still reaches the name it cannot
    // hold and the run is refused.
    let skip = base.join("skip.txt");
    std::fs::write(&skip, "/bad\u{fffd}.txt\n").unwrap();
    let skip = format!("--skip-list={}", skip.display());
    let assign = base.join("assign.txt");
    std::fs::write(&assign, "=511 /bad\u{fffd}.txt\n").unwrap();
    let assign = format!("--statoverride={}", assign.display());
    let or = base.join("or.txt");
    std::fs::write(&or, "4095 /bad\u{fffd}.txt\n").unwrap();
    let or = format!("--statoverride={}", or.display());

    for (index, extra) in [vec![], vec![&skip], vec![&assign], vec![&or]]
        .into_iter()
        .enumerate()
    {
        let name = format!("u{index}");
        let mut args = vec!["commit", "-b", &name, FIXED_TIMESTAMP];
        args.extend(extra.into_iter().map(String::as_str));
        args.push(&src);
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let label = args.join(" ");
        // The two word the refusal differently, which
        // `docs/conformance/cli-surface.md`, "P2" records; the exit status, the
        // empty standard output, and the unwritten ref are the requirement.
        for (who, run) in [("port", &port), ("tool", &tool)] {
            assert_eq!(run.status.code(), Some(1), "the {who} accepted `{label}`");
            assert!(
                run.stdout.is_empty(),
                "the {who} printed a checksum for `{label}`",
            );
        }
        assert_eq!(
            describe_refs(&port_repo),
            describe_refs(&tool_repo),
            "`{label}` left different refs",
        );
        assert!(
            !describe_refs(&port_repo)
                .iter()
                .any(|row| row.contains(&name)),
            "`{label}` wrote a ref",
        );
    }
}

/// `commit --tar-pathname-filter=REGEX,REPLACEMENT` renames each member of an
/// archive before it is placed.
#[test]
fn commit_tar_pathname_filter_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-tar-filter");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);
    let root = build_overlay_sources(base);
    let t2 = root.join("t2").to_str().unwrap().to_owned();
    let full = base.join("full.tar");
    pack_tar(&root.join("t1"), &full);
    let hl = root.join("hl");
    std::fs::create_dir_all(&hl).unwrap();
    std::fs::write(hl.join("one"), "hard\n").unwrap();
    std::fs::hard_link(hl.join("one"), hl.join("two")).unwrap();
    let hard = base.join("hard.tar");
    pack_tar(&hl, &hard);
    let source = format!("--tree=tar={}", full.display());

    // The branch name holds a character that is not a hexadecimal digit, so it
    // cannot read as an abbreviated commit checksum. Both implementations
    // resolve the implicit parent of `commit -b NAME` through a revision parse
    // that accepts one, so a hexadecimal name prefixing a commit this repository
    // already holds takes that commit as its parent where no such ref stands.
    // The two agree on that, but it is a second variable in this sweep, whose
    // subject is the filter, so the names here keep clear of it
    // (`docs/format-reference.md`, "Revision syntax").
    let mut branch = 0;
    let mut agrees = |extra: &[&str]| {
        branch += 1;
        let name = format!("tar{branch}");
        let mut args = vec!["commit", "-b", &name, FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        assert_agrees(&port_repo, &tool_repo, &args);
    };

    // The value splits at the first comma, the replacement is global, and a
    // member the expression does not match is kept unchanged.
    agrees(&[&source, "--tar-pathname-filter=^f.txt$,g.txt"]);
    agrees(&[&source, "--tar-pathname-filter=t,T"]);
    agrees(&[&source, "--tar-pathname-filter=zzz,yyy"]);
    agrees(&[&source, "--tar-pathname-filter=^f.txt$,a,b"]);
    // A directory member carries its trailing slash, so renaming a directory
    // and renaming its children are two different expressions.
    agrees(&[&source, r"--tar-pathname-filter=^common/(.*),X/\1"]);
    // A named group, its replacement reference, an inline case flag, and a
    // character class.
    agrees(&[
        &source,
        r"--tar-pathname-filter=(?i)ONLY(?<rest>.*),X\g<rest>",
    ]);
    agrees(&[&source, "--tar-pathname-filter=[aeiou],_"]);
    // `$1` carries no meaning in the replacement.
    agrees(&[&source, "--tar-pathname-filter=^f.txt$,$1.txt"]);
    // The last occurrence of the option wins.
    agrees(&[
        &source,
        "--tar-pathname-filter=^f.txt$,one",
        r"--tar-pathname-filter=^common/(.*),X/\1",
    ]);
    // A hardlink's target is a member name, so the filter reaches it too; a
    // symlink's target is not a member name and is left as it stands.
    agrees(&[
        &format!("--tree=tar={}", hard.display()),
        "--tar-pathname-filter=^one$,uno",
    ]);
    // The filter reaches an archive read beside a filesystem source, and
    // renaming a subtree onto one the filesystem source already made merges
    // the two.
    agrees(&[
        &format!("--tree=dir={t2}"),
        &source,
        r"--tar-pathname-filter=^onlyA(.*),onlyB\1",
    ]);
    // The value is read as an archive is loaded, so a command line naming no
    // archive carries a malformed one at exit 0.
    agrees(&[&format!("--tree=dir={t2}"), "--tar-pathname-filter=nocomma"]);
    agrees(&[
        &format!("--tree=dir={t2}"),
        "--tar-pathname-filter=dir1((,x",
    ]);

    // Constructs both dialects share, each reaching the tool's commit checksum:
    // the absolute anchors, a word boundary and its negation, the POSIX class
    // names, the hexadecimal escapes, a Unicode property, a bound, and an
    // inline-option group.
    for filter in [
        r"--tar-pathname-filter=\Af,Q",
        r"--tar-pathname-filter=f\.txt\z,Q",
        r"--tar-pathname-filter=\bcommon,Q",
        r"--tar-pathname-filter=\Bommon,Q",
        "--tar-pathname-filter=[[:alpha:]]{2},QQ",
        "--tar-pathname-filter=[[:^alpha:]],Q",
        "--tar-pathname-filter=[[:digit:]],Q",
        r"--tar-pathname-filter=\x66,Q",
        r"--tar-pathname-filter=\x{66},Q",
        r"--tar-pathname-filter=\p{L},Q",
        "--tar-pathname-filter=a{2}b,Q",
        "--tar-pathname-filter=(?i:F),Q",
        "--tar-pathname-filter=f(?i)X,Q",
    ] {
        agrees(&[&source, filter]);
    }

    // The canonical use of the option: strip a leading directory. The directory
    // member maps onto the empty string, which names the tree root.
    let dir1 = root.join("dir1");
    std::fs::create_dir_all(dir1.join("sub")).unwrap();
    std::fs::write(dir1.join("t.txt"), "t\n").unwrap();
    std::fs::write(dir1.join("sub/d.txt"), "d\n").unwrap();
    let nested = base.join("nested.tar");
    let status = Command::new("tar")
        .arg("-cf")
        .arg(&nested)
        .arg("-C")
        .arg(&root)
        .arg("./dir1")
        .status()
        .expect("spawn tar");
    assert!(status.success(), "tar failed");
    let nested_source = format!("--tree=tar={}", nested.display());
    agrees(&[&nested_source, r"--tar-pathname-filter=^dir1/(.*)$,\1"]);
    agrees(&[&nested_source, r"--tar-pathname-filter=^dir1/(.*),X/\1"]);

    // A quantified atom over a long member name is matched rather than refused,
    // and so is an expression whose backtracking would grow exponentially
    // without the required literal PCRE2 finds in it: `^(a+)+b` needs a `b` the
    // name does not hold, so the match ends without backtracking. 250
    // characters is the longest name a filesystem holds. Both reach the tool's
    // commit checksum at exit 0, inside a bound a matcher that did backtrack
    // over that name could not meet.
    let long = root.join("long");
    std::fs::create_dir_all(&long).unwrap();
    std::fs::write(long.join("a".repeat(250)), "x\n").unwrap();
    let long_tar = base.join("long.tar");
    pack_tar(&long, &long_tar);
    let long_source = format!("--tree=tar={}", long_tar.display());
    for (name, filter) in [
        ("long1", "--tar-pathname-filter=^a+$,Q"),
        ("long2", "--tar-pathname-filter=^(a+)+b,Q"),
    ] {
        let args = [
            "commit",
            "-b",
            name,
            FIXED_TIMESTAMP,
            long_source.as_str(),
            filter,
        ];
        let started = std::time::Instant::now();
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let elapsed = started.elapsed();
        assert_eq!(
            port.status.code(),
            Some(0),
            "the port did not answer `{filter}`:\n{}",
            String::from_utf8_lossy(&port.stderr),
        );
        assert_eq!(
            tool.status.code(),
            Some(0),
            "the tool did not answer `{filter}`:\n{}",
            String::from_utf8_lossy(&tool.stderr),
        );
        let checksum = port.stdout_trimmed();
        assert_eq!(checksum.len(), 64, "`{filter}` printed no commit checksum");
        assert_eq!(
            checksum,
            tool.stdout_trimmed(),
            "`{filter}` reached two commits",
        );
        assert!(
            elapsed < std::time::Duration::from_secs(60),
            "`{filter}` took {elapsed:?} over a 250-character member name",
        );
    }

    // Constructs PCRE2 carries, each reaching the tool's commit checksum: the
    // four lookarounds, the atomic group, the comment group, the literal span,
    // `\N`, a backreference, the extended flag, and a callout. `\C` matches one
    // byte, which rewrites an all-ASCII name without splitting a character. The
    // two backtracking verbs and the start-of-pattern options close the set;
    // the port injects a start-of-pattern option of its own for the newline
    // convention, and a value that states one itself is placed after it.
    for filter in [
        r"--tar-pathname-filter=(?=f)x,Q",
        r"--tar-pathname-filter=(?=f).,Q",
        r"--tar-pathname-filter=(?!f).,Q",
        r"--tar-pathname-filter=(?<=f)x,Q",
        r"--tar-pathname-filter=(?<!f)t,Q",
        r"--tar-pathname-filter=(?>f),Q",
        r"--tar-pathname-filter=(?#c)f,Q",
        r"--tar-pathname-filter=\Qf+t\E,Q",
        r"--tar-pathname-filter=\Qf.\E,Q",
        r"--tar-pathname-filter=\C,Q",
        r"--tar-pathname-filter=\N,Q",
        r"--tar-pathname-filter=(x)?\1f,Q",
        "--tar-pathname-filter=(?x) f ,Q",
        "--tar-pathname-filter=(?C1)f,Q",
        "--tar-pathname-filter=(*SKIP)f,Q",
        "--tar-pathname-filter=f(*ACCEPT),Q",
        "--tar-pathname-filter=(*UTF)f,Q",
        "--tar-pathname-filter=(*UCP)f,Q",
        "--tar-pathname-filter=(*LIMIT_MATCH=10)f,Q",
        "--tar-pathname-filter=(*NUL)f,Q",
    ] {
        agrees(&[&source, filter]);
    }

    // An archive whose member names hold a doubled letter, a space, and an
    // upper-case letter, which is what a backreference, `\K`, a subroutine
    // call, `\h`, and an octal escape need in order to match.
    let doubled = root.join("doubled");
    std::fs::create_dir_all(&doubled).unwrap();
    for member in ["ff.txt", "f.txt", "a b.txt", "A.txt"] {
        std::fs::write(doubled.join(member), "x\n").unwrap();
    }
    let doubled_tar = base.join("doubled.tar");
    pack_tar(&doubled, &doubled_tar);
    let doubled_source = format!("--tree=tar={}", doubled_tar.display());
    for filter in [
        r"--tar-pathname-filter=(?<=f)f,Q",
        r"--tar-pathname-filter=(f)\1,Q",
        r"--tar-pathname-filter=f\Kf,Q",
        // A possessive quantifier gives nothing back where its greedy form
        // does, so `^f*+f` and `^f*f` answer differently over `ff.txt`.
        r"--tar-pathname-filter=^f*+f,Q",
        r"--tar-pathname-filter=^f*f,Q",
        r"--tar-pathname-filter=^(f(?R)?),Q",
        r"--tar-pathname-filter=(f)(?1),Q",
        r"--tar-pathname-filter=(f)?(?(1)f|x),Q",
        r"--tar-pathname-filter=(f)\g{1},Q",
        r"--tar-pathname-filter=\h,Q",
        r"--tar-pathname-filter=\101,Q",
        r"--tar-pathname-filter=(?J)(?<n>f)|(?<n>x),Q",
        // A duplicate name in the expression, paired with a read of that name
        // from the replacement. The match sets one group of the pair, and the
        // name reaches the group the match set: `f.txt` sets the first group
        // and `A.txt` the second.
        r"--tar-pathname-filter=(?J)(?<n>f)|(?<n>A),[\g<n>]",
        // An empty match advances the splice past one whole character, which
        // leaves that character in the name. The lookbehind holds the
        // expression off the archive's root member, whose name is empty.
        r"--tar-pathname-filter=(?<=.)x*,Q",
        // A lazy quantifier prefers its empty branch, so the splice advances
        // past the character rather than retrying the offset for a non-empty
        // match. The two loop shapes part here and nowhere else.
        r"--tar-pathname-filter=(?<=.)f*?,Q",
        // A greedy quantifier matches once and then matches empty where that
        // match ended, which is where the splice loop's two positions part
        // for a non-empty match. `ff.txt` holds the doubled letter that
        // reaches it.
        r"--tar-pathname-filter=(?<=.)f*,Q",
    ] {
        agrees(&[&doubled_source, filter]);
    }

    // One archive per member name that states a dialect semantic.
    let pack_named = |name: &str, members: &[&str]| -> String {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        for member in members {
            std::fs::write(dir.join(member), "x\n").unwrap();
        }
        let path = base.join(format!("{name}.tar"));
        pack_tar(&dir, &path);
        format!("--tree=tar={}", path.display())
    };
    let digit = pack_named("digit", &["\u{663}.txt"]);
    let letter = pack_named("letter", &["é.txt"]);
    let multibyte = pack_named("multibyte", &["aébc"]);
    let space = pack_named("space", &["\u{a0}.txt"]);
    let trailing = pack_named("trailing", &["f.txt\n"]);
    let embedded = pack_named("embedded", &["a\nb.txt"]);

    // UCP is on, so `\d`, `\w`, `\s`, and the POSIX class names are
    // Unicode-aware, and UTF is on, so `.` consumes one character and not one
    // byte.
    agrees(&[&digit, r"--tar-pathname-filter=\d,Q"]);
    agrees(&[&letter, r"--tar-pathname-filter=^\w,Q"]);
    agrees(&[&letter, "--tar-pathname-filter=[[:alpha:]],Q"]);
    agrees(&[&letter, "--tar-pathname-filter=^.,Q"]);
    agrees(&[&space, r"--tar-pathname-filter=\s,Q"]);
    agrees(&[&multibyte, r"--tar-pathname-filter=(?<=.)x*,Q"]);

    // `$` and `\Z` match before a final newline where `\z` does not.
    for filter in [
        r"--tar-pathname-filter=^f\.txt$,Q",
        r"--tar-pathname-filter=^f\.txt\Z,Q",
        r"--tar-pathname-filter=^f\.txt\z,Q",
    ] {
        agrees(&[&trailing, filter]);
    }

    // Multi-line is off, `(?m)` turns it on, and `.` consumes no line
    // terminator.
    for filter in [
        "--tar-pathname-filter=^a$,Q",
        "--tar-pathname-filter=(?m)^a$,Q",
        "--tar-pathname-filter=a.b,Q",
        r"--tar-pathname-filter=a\Rb,Q",
    ] {
        agrees(&[&embedded, filter]);
    }

    // The newline convention is `any`: a carriage return, the pair, a vertical
    // tab, a form feed, `U+0085`, `U+2028`, and `U+2029` each end a line, so
    // `$` and `\Z` match before one and `.` consumes none of them
    // (`docs/conformance/cli-surface.md`, "P2").
    for (name, member) in [
        ("nl-cr", "c\r"),
        ("nl-crlf", "c\r\n"),
        ("nl-vt", "c\u{b}"),
        ("nl-ff", "c\u{c}"),
        ("nl-nel", "c\u{85}"),
        ("nl-ls", "c\u{2028}"),
        ("nl-ps", "c\u{2029}"),
    ] {
        let one = pack_named(name, &[member]);
        for filter in [
            "--tar-pathname-filter=^c$,Q",
            r"--tar-pathname-filter=^c\Z,Q",
            "--tar-pathname-filter=^c.,Q",
        ] {
            agrees(&[&one, filter]);
        }
    }
    // A convention the value states itself wins over the injected one, in both.
    for (name, member) in [("nl-cr", "c\r"), ("nl-crlf", "c\r\n")] {
        let one = pack_named(name, &[member]);
        for filter in [
            "--tar-pathname-filter=(*LF)^c$,Q",
            "--tar-pathname-filter=(*CRLF)^c$,Q",
            "--tar-pathname-filter=(*ANYCRLF)^c$,Q",
        ] {
            agrees(&[&one, filter]);
        }
    }
    // The same convention decides where `(?m)^` matches and what `\R` consumes,
    // for a terminator inside a name.
    for (name, member) in [
        ("mid-cr", "a\rb"),
        ("mid-vt", "a\u{b}b"),
        ("mid-nel", "a\u{85}b"),
    ] {
        let one = pack_named(name, &[member]);
        for filter in [
            "--tar-pathname-filter=a.b,Q",
            "--tar-pathname-filter=(?m)^a$,Q",
            r"--tar-pathname-filter=a\Rb,Q",
        ] {
            agrees(&[&one, filter]);
        }
    }

    // Values both refuse. The port words its refusals in PCRE2's own terms,
    // which GLib rewords for some reasons, so the refusal is compared and the
    // wording is compared only where it was measured to agree
    // (`docs/conformance/cli-surface.md`, "P2").
    let mut refused = 0;
    let mut both_refuse = |extra: &[&str]| {
        refused += 1;
        let name = format!("r{refused}");
        let mut args = vec!["commit", "-b", &name, FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let label = args.join(" ");
        // The port exits 1 and names the refusal. The tool ends the run without
        // a commit, and for a malformed replacement it ends on a GLib assertion
        // rather than an exit status, which is the recorded reference defect
        // (`docs/conformance/cli-surface.md`, "P2").
        assert_eq!(
            port.status.code(),
            Some(1),
            "the port did not refuse `{label}`:\n{}",
            String::from_utf8_lossy(&port.stderr)
        );
        assert!(
            String::from_utf8_lossy(&port.stderr).starts_with("error: "),
            "the port reported no error line for `{label}`"
        );
        assert!(
            !tool.status.success(),
            "the tool accepted `{label}`, so the mutual refusal no longer holds"
        );
        assert_eq!(
            ostrya(
                &["rev-parse", "--repo", port_repo.to_str().unwrap(), &name],
                None,
                &[],
            )
            .status
            .code(),
            Some(1),
            "`{label}` wrote a commit anyway"
        );
    };
    for filter in [
        // A value with no comma, and an expression neither engine compiles: an
        // unbalanced group, an unknown escape, an unknown verb, an unknown
        // POSIX class name, and a repeat count above PCRE2's own limit.
        "--tar-pathname-filter=nocomma",
        "--tar-pathname-filter=dir1((,x",
        r"--tar-pathname-filter=\q,Q",
        "--tar-pathname-filter=(*BOGUS)f,Q",
        "--tar-pathname-filter=[[:bogus:]],Q",
        "--tar-pathname-filter=f{65536},Q",
        // An expression whose empty match at the start of every name rewrites
        // the archive's own root member, which leaves each remaining member
        // with no parent, and a group reference in the replacement that reaches
        // a member collision.
        r"--tar-pathname-filter=\K,Q",
        "--tar-pathname-filter=f*+,Q",
        "--tar-pathname-filter=(x*)+,Q",
        r"--tar-pathname-filter=^(only)(A.*)$,\2\1",
        // A replacement escape GLib does not know.
        r"--tar-pathname-filter=^f.txt$,\q",
        r"--tar-pathname-filter=^f.txt$,\",
        r"--tar-pathname-filter=^f.txt$,\g<",
        // A rewrite that maps every member onto one name puts a file member
        // where an earlier member made a directory.
        "--tar-pathname-filter=.*,Q",
        // The archive's root member maps onto a name that already stands.
        "--tar-pathname-filter=^$,q/",
        "--tar-pathname-filter=^common/$,QQ/",
    ] {
        both_refuse(&[&source, filter]);
    }

    // Two compile limits whose refusal line agrees character for character, the
    // character offset included, which is what the shared engine buys.
    for (filter, line) in [
        (
            "--tar-pathname-filter=[[:bogus:]],Q",
            "error: --tar-pathname-filter: Error while compiling regular expression \
             \u{2018}[[:bogus:]]\u{2019} at char 10: unknown POSIX class name\n",
        ),
        (
            "--tar-pathname-filter=f{65536},Q",
            "error: --tar-pathname-filter: Error while compiling regular expression \
             \u{2018}f{65536}\u{2019} at char 7: number too big in {} quantifier\n",
        ),
    ] {
        let args = [
            "commit",
            "-b",
            "shared",
            FIXED_TIMESTAMP,
            source.as_str(),
            filter,
        ];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        for (who, run) in [("port", &port), ("tool", &tool)] {
            assert_eq!(run.status.code(), Some(1), "the {who} accepted `{filter}`");
            assert_eq!(
                String::from_utf8_lossy(&run.stderr),
                line,
                "the {who} worded the refusal of `{filter}` differently",
            );
        }
    }

    // The reason string is one of the two recorded divergences left in the
    // compile-failure line: GLib passes some of PCRE2's reasons through and
    // rewords others. The other is the unit the offset counts in, code units in
    // the port and characters in the tool; every expression here is ASCII, so
    // the offset agrees over each of them
    // (`docs/conformance/cli-surface.md`, "P2").
    for (filter, expression, at, port_reason, tool_reason) in [
        (
            "--tar-pathname-filter=dir1((,x",
            "dir1((",
            6,
            "missing closing parenthesis",
            "missing terminating )",
        ),
        (
            r"--tar-pathname-filter=\q,Q",
            r"\q",
            1,
            r"unrecognized character follows \",
            r"unrecognised character following \",
        ),
        (
            "--tar-pathname-filter=(*BOGUS)f,Q",
            "(*BOGUS)f",
            7,
            "(*VERB) not recognized or malformed",
            "(*VERB) not recognised",
        ),
    ] {
        let args = [
            "commit",
            "-b",
            "wording",
            FIXED_TIMESTAMP,
            source.as_str(),
            filter,
        ];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let head = format!(
            "error: --tar-pathname-filter: Error while compiling regular expression \
             \u{2018}{expression}\u{2019} at char {at}: "
        );
        for (who, run, reason) in [("port", &port, port_reason), ("tool", &tool, tool_reason)] {
            assert_eq!(run.status.code(), Some(1), "the {who} accepted `{filter}`");
            assert_eq!(
                String::from_utf8_lossy(&run.stderr),
                format!("{head}{reason}\n"),
                "the {who} worded the refusal of `{filter}` differently",
            );
        }
    }

    // The unit the offset counts in is the other one: the port reports the
    // code-unit offset PCRE2 answers, which is a byte offset for the 8-bit
    // library, and the tool reports a character offset. A non-ASCII character
    // ahead of the error point moves the two apart by the extra bytes it
    // occupies, so the two-byte `é` moves them apart by one and the four-byte
    // `U+1F600` by three, which counts per character and not per two bytes.
    // Each expression carries one error the loop above already words, so the
    // count is stated apart from the error kind
    // (`docs/conformance/cli-surface.md`, "P2").
    for (filter, expression, port_at, tool_at, port_reason, tool_reason) in [
        (
            r"--tar-pathname-filter=é\q,Q",
            r"é\q",
            3,
            2,
            r"unrecognized character follows \",
            r"unrecognised character following \",
        ),
        (
            r"--tar-pathname-filter=éé\q,Q",
            r"éé\q",
            5,
            3,
            r"unrecognized character follows \",
            r"unrecognised character following \",
        ),
        (
            r"--tar-pathname-filter=😀\q,Q",
            r"😀\q",
            5,
            2,
            r"unrecognized character follows \",
            r"unrecognised character following \",
        ),
        (
            "--tar-pathname-filter=é[[:bogus:]],Q",
            "é[[:bogus:]]",
            12,
            11,
            "unknown POSIX class name",
            "unknown POSIX class name",
        ),
        (
            "--tar-pathname-filter=édir1((,x",
            "édir1((",
            8,
            7,
            "missing closing parenthesis",
            "missing terminating )",
        ),
        (
            "--tar-pathname-filter=ééédir1((,x",
            "ééédir1((",
            12,
            9,
            "missing closing parenthesis",
            "missing terminating )",
        ),
        (
            "--tar-pathname-filter=éf{65536},Q",
            "éf{65536}",
            9,
            8,
            "number too big in {} quantifier",
            "number too big in {} quantifier",
        ),
        (
            "--tar-pathname-filter=é(*BOGUS)f,Q",
            "é(*BOGUS)f",
            9,
            8,
            "(*VERB) not recognized or malformed",
            "(*VERB) not recognised",
        ),
    ] {
        let args = [
            "commit",
            "-b",
            "offset",
            FIXED_TIMESTAMP,
            source.as_str(),
            filter,
        ];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let line = |at: usize, reason: &str| {
            format!(
                "error: --tar-pathname-filter: Error while compiling regular expression \
                 \u{2018}{expression}\u{2019} at char {at}: {reason}\n"
            )
        };
        for (who, run, at, reason) in [
            ("port", &port, port_at, port_reason),
            ("tool", &tool, tool_at, tool_reason),
        ] {
            assert_eq!(run.status.code(), Some(1), "the {who} accepted `{filter}`");
            assert_eq!(
                String::from_utf8_lossy(&run.stderr),
                line(at, reason),
                "the {who} reported another offset or reason for `{filter}`",
            );
        }
    }

    // A match-time limit refuses the commit. PCRE2 accounts a step budget, so an
    // expression with no required literal ends the match rather than running on.
    // The tool ends the run on a GLib assertion at exit 134 in the same case,
    // which is the recorded exit-path divergence.
    for (filter, expression) in [
        (r"--tar-pathname-filter=(a+)+\d,Q", r"(a+)+\d"),
        ("--tar-pathname-filter=(a+)+[0-9],Q", "(a+)+[0-9]"),
        (r"--tar-pathname-filter=(a|aa)+\d,Q", r"(a|aa)+\d"),
    ] {
        let args = [
            "commit",
            "-b",
            "budget",
            FIXED_TIMESTAMP,
            long_source.as_str(),
            filter,
        ];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        assert_eq!(
            port.status.code(),
            Some(1),
            "the port did not refuse `{filter}`:\n{}",
            String::from_utf8_lossy(&port.stdout),
        );
        assert_eq!(
            String::from_utf8_lossy(&port.stderr),
            format!(
                "error: tar: --tar-pathname-filter: Error while matching regular \
                 expression \u{2018}{expression}\u{2019}: match limit exceeded\n"
            ),
            "the port worded the match-limit refusal of `{filter}` differently",
        );
        assert!(
            !tool.status.success(),
            "the tool answered `{filter}`, so the recorded divergence no longer holds"
        );
    }

    // `\C` matches one byte, so a rewrite over a multi-byte name can split a
    // character. The port refuses the member, and the tool ends the run on a
    // GLib assertion whose message reads `bad offset into UTF string`. Neither
    // writes a commit.
    let args = [
        "commit",
        "-b",
        "byte",
        FIXED_TIMESTAMP,
        letter.as_str(),
        r"--tar-pathname-filter=\C,Q",
    ];
    let (port, tool) = run_both(&port_repo, &tool_repo, &args);
    assert_eq!(
        port.status.code(),
        Some(1),
        "the port rewrote a name that splits a character"
    );
    assert!(
        String::from_utf8_lossy(&port.stderr).contains("is not valid UTF-8"),
        "the port did not name the invalid rewrite:\n{}",
        String::from_utf8_lossy(&port.stderr),
    );
    assert!(
        !tool.status.success(),
        "the tool rewrote a name that splits a character"
    );
    for (who, repo) in [("port", &port_repo), ("tool", &tool_repo)] {
        assert_eq!(
            ostrya(
                &["rev-parse", "--repo", repo.to_str().unwrap(), "byte"],
                None,
                &[],
            )
            .status
            .code(),
            Some(1),
            "the {who} wrote a commit for a name that splits a character"
        );
    }
}

/// `commit --consume` empties each filesystem source as it is walked, before
/// the commit object and the ref are written, and removes the source directory
/// itself unless the path is spelled `.`.
#[test]
fn commit_consume_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("commit-consume");
    let base = tmp.path();
    let (port_repo, tool_repo) = create_repo_pair(base, RepoMode::Archive);

    // Each case gets its own source pair, one per implementation, since the
    // run destroys it.
    let build = |name: &str| -> (PathBuf, PathBuf) {
        let mut out = Vec::new();
        for side in ["port", "tool"] {
            let dir = base.join(format!("{side}-{name}"));
            std::fs::create_dir_all(dir.join("sub")).unwrap();
            std::fs::write(dir.join("x"), "x\n").unwrap();
            std::fs::write(dir.join("sub/y"), "y\n").unwrap();
            out.push(dir);
        }
        (out[0].clone(), out[1].clone())
    };
    let state = |dir: &Path| -> String {
        match std::fs::read_dir(dir) {
            Ok(entries) => format!("kept with {} entries", entries.count()),
            Err(_) => "gone".to_owned(),
        }
    };

    // A `--tree=dir=` source, a positional one, and a trailing slash: the
    // directory itself goes in each.
    let mut branch = 0;
    let mut consumed = |name: &str, spell: &dyn Fn(&Path) -> Vec<String>| {
        branch += 1;
        let (port_src, tool_src) = build(name);
        let port_args = spell(&port_src);
        let tool_args = spell(&tool_src);
        let line = format!("k{branch}");
        let head = ["commit", "-b", &line, FIXED_TIMESTAMP, "--consume"];
        let mut port_line: Vec<&str> = head.to_vec();
        port_line.extend(port_args.iter().map(String::as_str));
        let mut tool_line: Vec<&str> = head.to_vec();
        tool_line.extend(tool_args.iter().map(String::as_str));
        let port = ostrya(
            &{
                let mut all = vec!["commit", "--repo", port_repo.to_str().unwrap()];
                all.extend_from_slice(&port_line[1..]);
                all
            },
            None,
            &[],
        );
        let tool = ostree(&{
            let mut all = vec!["commit", "--repo", tool_repo.to_str().unwrap()];
            all.extend_from_slice(&tool_line[1..]);
            all
        });
        assert_runs_agree(&port, &tool, name);
        assert_eq!(
            state(&port_src),
            state(&tool_src),
            "the two left {name} in different states"
        );
        // The commit is written and the source directory is gone, which the
        // agreement of the two runs does not state on its own.
        for (who, run) in [("port", &port), ("tool", &tool)] {
            assert_eq!(
                run.status.code(),
                Some(0),
                "the {who} wrote no commit for {name}:\n{}",
                String::from_utf8_lossy(&run.stderr),
            );
        }
        assert_eq!(
            state(&port_src),
            "gone",
            "{name} left the source directory behind",
        );
    };

    consumed("tree", &|dir| vec![format!("--tree=dir={}", dir.display())]);
    consumed("slash", &|dir| {
        vec![format!("--tree=dir={}/", dir.display())]
    });
    consumed("positional", &|dir| vec![dir.display().to_string()]);

    // A `ref=` source and a `tar=` source are left alone: the commit is written,
    // the `dir=` source beside them is gone, and the ref and the archive file
    // both survive. The ref has to resolve for the claim to be stated, so both
    // repositories carry one.
    let seed = base.join("seed");
    std::fs::create_dir_all(seed.join("s")).unwrap();
    std::fs::write(seed.join("s/keep.txt"), "keep\n").unwrap();
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "seed",
            FIXED_TIMESTAMP,
            &format!("--tree=dir={}", seed.display()),
        ],
    );
    let archive = base.join("consume.tar");
    pack_tar(&seed, &archive);
    consumed("with-ref", &|dir| {
        vec![
            format!("--tree=dir={}", dir.display()),
            "--tree=ref=seed".to_owned(),
        ]
    });
    consumed("with-tar", &|dir| {
        vec![
            format!("--tree=dir={}", dir.display()),
            format!("--tree=tar={}", archive.display()),
        ]
    });
    for repo in [&port_repo, &tool_repo] {
        let refs = ostrya(
            &["rev-parse", "--repo", repo.to_str().unwrap(), "seed"],
            None,
            &[],
        );
        assert!(refs.status.success(), "the `ref=` source was consumed");
    }
    assert!(archive.exists(), "the `tar=` source was consumed");

    // A walk filter does not spare a path from the removal: the source is gone
    // whatever the filter kept out of the commit, and the commit is written.
    let skip_list = base.join("skip-list");
    std::fs::write(&skip_list, "/skipme\n").unwrap();
    let (port_filtered, tool_filtered) = build("filtered");
    for dir in [&port_filtered, &tool_filtered] {
        std::fs::create_dir_all(dir.join("skipme")).unwrap();
        std::fs::write(dir.join("skipme/z"), "z\n").unwrap();
    }
    let mut runs = Vec::new();
    for (repo, src) in [(&port_repo, &port_filtered), (&tool_repo, &tool_filtered)] {
        let owned = [
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            "filtered",
            FIXED_TIMESTAMP,
            "--consume",
            &format!("--skip-list={}", skip_list.display()),
            &format!("--tree=dir={}", src.display()),
        ]
        .map(str::to_owned);
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        runs.push(if repo == &port_repo {
            ostrya(&args, None, &[])
        } else {
            ostree(&args)
        });
    }
    assert_runs_agree(&runs[0], &runs[1], "consume with a skip-list");
    assert_eq!(state(&port_filtered), state(&tool_filtered));
    assert_eq!(
        state(&port_filtered),
        "gone",
        "a filtered path left the source behind"
    );

    // A removal that fails reports the entry's own name. The source holds one
    // entry inside a directory the walk may read and not write, so the name is
    // the same in both.
    let mut runs = Vec::new();
    let mut sources = Vec::new();
    for (index, repo) in [&port_repo, &tool_repo].iter().enumerate() {
        let src = base.join(format!("readonly-{index}"));
        std::fs::create_dir_all(src.join("ro")).unwrap();
        std::fs::write(src.join("ro/only.txt"), "x\n").unwrap();
        std::fs::set_permissions(src.join("ro"), std::fs::Permissions::from_mode(0o500)).unwrap();
        let owned = [
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            "readonly",
            FIXED_TIMESTAMP,
            "--consume",
            &format!("--tree=dir={}", src.display()),
        ]
        .map(str::to_owned);
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        runs.push(if index == 0 {
            ostrya(&args, None, &[])
        } else {
            ostree(&args)
        });
        sources.push(src);
    }
    assert_runs_agree(&runs[0], &runs[1], "consume over a read-only directory");
    for (who, run) in [("port", &runs[0]), ("tool", &runs[1])] {
        assert_eq!(
            run.status.code(),
            Some(1),
            "the {who} did not fail the run a removal failure ends",
        );
    }
    assert!(
        String::from_utf8_lossy(&runs[0].stderr).contains("unlinkat(only.txt): Permission denied"),
        "the failed removal did not name the entry:\n{}",
        String::from_utf8_lossy(&runs[0].stderr)
    );
    for src in &sources {
        std::fs::set_permissions(src.join("ro"), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    // Two sources are both consumed, and the second failing leaves the first
    // gone with no commit written.
    let (port_first, tool_first) = build("first");
    let (port_second, tool_second) = build("second");
    for (repo, first, second) in [
        (&port_repo, &port_first, &port_second),
        (&tool_repo, &tool_first, &tool_second),
    ] {
        let both = [
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            "two",
            FIXED_TIMESTAMP,
            "--consume",
            &format!("--tree=dir={}", first.display()),
            &format!("--tree=dir={}", second.display()),
        ]
        .map(str::to_owned);
        let args: Vec<&str> = both.iter().map(String::as_str).collect();
        let run = if repo == &port_repo {
            ostrya(&args, None, &[])
        } else {
            ostree(&args)
        };
        assert!(run.status.success(), "the consuming commit failed");
    }
    assert_eq!(state(&port_first), state(&tool_first));
    assert_eq!(state(&port_second), state(&tool_second));

    let (port_kept, tool_kept) = build("failing");
    for (repo, src) in [(&port_repo, &port_kept), (&tool_repo, &tool_kept)] {
        let both = [
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            "failing",
            FIXED_TIMESTAMP,
            "--consume",
            &format!("--tree=dir={}", src.display()),
            "--tree=dir=/nonexistent-zz",
        ]
        .map(str::to_owned);
        let args: Vec<&str> = both.iter().map(String::as_str).collect();
        let run = if repo == &port_repo {
            ostrya(&args, None, &[])
        } else {
            ostree(&args)
        };
        assert_eq!(run.status.code(), Some(1), "the run did not fail");
        let refs = ostrya(
            &["rev-parse", "--repo", repo.to_str().unwrap(), "failing"],
            None,
            &[],
        );
        assert_eq!(refs.status.code(), Some(1), "a commit was written anyway");
    }
    assert_eq!(
        state(&port_kept),
        state(&tool_kept),
        "the two left the consumed source in different states"
    );
    assert_eq!(
        state(&port_kept),
        "gone",
        "the first source was not consumed"
    );

    // A source spelled `.` keeps the directory and loses its contents; `./` is
    // another spelling, so the removal is attempted and its failure aborts the
    // commit and names the path.
    for (index, spelling) in [".", "./"].iter().enumerate() {
        let (port_src, tool_src) = build(&format!("dot{index}"));
        let mut runs = Vec::new();
        for (repo, src) in [(&port_repo, &port_src), (&tool_repo, &tool_src)] {
            let branch = format!("dot{index}");
            let args = [
                "commit",
                "--repo",
                repo.to_str().unwrap(),
                "-b",
                &branch,
                FIXED_TIMESTAMP,
                "--consume",
                spelling,
            ]
            .map(str::to_owned);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            runs.push(if repo == &port_repo {
                ostrya_in(Some(src), &args, None, &[])
            } else {
                ostree_in(src, &args)
            });
        }
        assert_runs_agree(&runs[0], &runs[1], spelling);
        assert_eq!(state(&port_src), state(&tool_src));
        assert_eq!(state(&port_src), "kept with 0 entries");
    }
}

/// `commit --consume` removes a source subtree the filter kept out of the
/// commit whatever its depth. The removal descends with a bounded number of
/// descriptors, so a chain deeper than the descriptor limit the run holds is
/// removed whole and the commit is written. The run states the limit itself:
/// the limit the harness inherits stands far above any depth a test builds in
/// reasonable time.
#[test]
fn commit_consume_removes_a_deep_filtered_tree() {
    // The depth of the chain the skip list prunes, and the descriptor limit
    // the run holds, which stands well below it.
    const DEPTH: usize = 512;
    const NOFILE: usize = 128;

    let tmp = TmpDir::new("commit-consume-deep");
    let base = tmp.path();
    let repo = create_repo(base, RepoMode::Archive);

    let src = base.join("src");
    let mut chain = src.join("deep");
    for _ in 1..DEPTH {
        chain.push("d");
    }
    std::fs::create_dir_all(&chain).unwrap();
    std::fs::write(src.join("keep.txt"), "keep\n").unwrap();

    // The skip list prunes the chain at its root, so the walk never descends
    // into it and the consuming removal is what empties it.
    let skip_list = base.join("skip-list");
    std::fs::write(&skip_list, "/deep\n").unwrap();

    let skip_option = format!("--skip-list={}", skip_list.display());
    let tree_option = format!("--tree=dir={}", src.display());
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("ulimit -n {NOFILE}; exec \"$0\" \"$@\""))
        .arg(env!("CARGO_BIN_EXE_ostrya"))
        .args([
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            "deep",
            FIXED_TIMESTAMP,
            "--consume",
            &skip_option,
            &tree_option,
        ])
        .output()
        .expect("spawn ostrya under a lowered descriptor limit");

    assert!(
        out.status.success(),
        "a {DEPTH}-level chain was not consumed under {NOFILE} descriptors:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!src.exists(), "the consuming commit left the source behind");
}

/// A second ed25519 sign fixture, so a multi-key run states an order.
const ED25519_SECRET2_B64: &str =
    "vvLhmBcasjZ09s+tBj6bor7aXGEBSB2bM3PS9kc+MpHlZgDjxcMu3VPDpQPqYXmwzMlEJeqlpSM8+s7YLfum2g==";

/// `commit --sign` and `--sign-from-file` reach the same `ostree.sign.ed25519`
/// key, one signature per occurrence and in a fixed order, and both
/// implementations write the same `.commitmeta` bytes.
#[test]
fn commit_sign_ed25519_matches_the_tool() {
    if !ostree_supports_ed25519() {
        return;
    }
    let tmp = TmpDir::new("commit-sign-ed25519");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    let write = |name: &str, text: &str| {
        let path = base.join(name);
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let one = write("k1.txt", &format!("{ED25519_SECRET_B64}\n"));
    let two = write("k2.txt", &format!("{ED25519_SECRET2_B64}\n"));
    let no_newline = write("k3.txt", ED25519_SECRET_B64);
    let padded = write("k4.txt", &format!("  {ED25519_SECRET_B64}  "));
    let extra_lines = write(
        "k5.txt",
        &format!("{ED25519_SECRET_B64}\n{ED25519_SECRET2_B64}\n"),
    );
    // A first line carrying a byte sequence that is not UTF-8, and one a NUL
    // byte cuts short. Both are read as bytes, so the key is what stands ahead
    // of the NUL and the invalid sequence contributes nothing to the decode.
    let write_bytes = |name: &str, bytes: &[u8]| {
        let path = base.join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let mut latin1 = Vec::from(ED25519_SECRET_B64.as_bytes());
    latin1.insert(40, 0xff);
    latin1.push(b'\n');
    let not_utf8 = write_bytes("k6.txt", &latin1);
    let mut nul_tail = Vec::from(ED25519_SECRET_B64.as_bytes());
    nul_tail.extend_from_slice(b"\0ZZZZ\n");
    let nul_after_key = write_bytes("k7.txt", &nul_tail);

    let mut cell = 0;
    let mut agrees = |extra: &[&str]| -> String {
        cell += 1;
        let branch = format!("sig{cell}");
        let mut args = vec!["commit", "-b", &branch, FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        args.push(src);
        assert_agrees(&port_repo, &tool_repo, &args);
        assert_commitmeta_agrees(&port_repo, &tool_repo, &branch, &extra.join(" "));
        assert_agrees(
            &port_repo,
            &tool_repo,
            &["show", "--list-detached-metadata-keys", &branch],
        );
        branch
    };

    // One key, two keys in each order, and the same key twice, which is not
    // deduplicated.
    let single = agrees(&["--sign", ED25519_SECRET_B64]);
    agrees(&["--sign", ED25519_SECRET_B64, "--sign", ED25519_SECRET2_B64]);
    agrees(&["--sign", ED25519_SECRET2_B64, "--sign", ED25519_SECRET_B64]);
    let doubled = agrees(&["--sign", ED25519_SECRET_B64, "--sign", ED25519_SECRET_B64]);
    // One occurrence writes one 64-byte element under the engine's own key, and
    // a second occurrence of one key writes a second element.
    for repo in [&port_repo, &tool_repo] {
        assert_eq!(
            signature_elements(repo, &single, "ostree.sign.ed25519"),
            vec![64],
            "{}: one `--sign` key wrote another array",
            repo.display(),
        );
        assert_eq!(
            signature_elements(repo, &doubled, "ostree.sign.ed25519"),
            vec![64, 64],
            "{}: the repeated key was deduplicated",
            repo.display(),
        );
    }
    // `--sign-type=ed25519` is the default, so naming it changes nothing.
    agrees(&["--sign-type=ed25519", "--sign", ED25519_SECRET_B64]);
    // A file contributes its first line alone, with or without a trailing
    // newline and with surrounding spaces.
    for path in [
        &one,
        &no_newline,
        &padded,
        &extra_lines,
        &not_utf8,
        &nul_after_key,
    ] {
        agrees(&["--sign-from-file", path]);
    }
    agrees(&["--sign-from-file", &one, "--sign-from-file", &two]);
    // The two lists are separate: every `--sign` key signs before every
    // `--sign-from-file` key, whatever the command line's order.
    agrees(&["--sign", ED25519_SECRET_B64, "--sign-from-file", &two]);
    agrees(&["--sign-from-file", &two, "--sign", ED25519_SECRET_B64]);
    // Several shapes held against each other over one orphan commit. Each shape
    // runs against a fresh repository pair, so the signature the run appends
    // stands alone and the bytes of one shape are comparable with another's.
    let mut fresh = 0;
    let mut detached = |extra: &[&str]| -> (Vec<u8>, Vec<u8>) {
        fresh += 1;
        let side = base.join(format!("fresh{fresh}"));
        std::fs::create_dir_all(&side).unwrap();
        let (port_side, tool_side) = create_repo_pair(&side, RepoMode::Archive);
        let mut args = vec!["commit", "--orphan", "-s", "shape", FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        args.push(src);
        let (port, tool) = run_both(&port_side, &tool_side, &args);
        assert_runs_agree(&port, &tool, &args.join(" "));
        let checksum = port.ok().stdout_trimmed();
        let relative = format!("objects/{}/{}.commitmeta", &checksum[..2], &checksum[2..]);
        let read = |repo: &Path| -> Vec<u8> {
            std::fs::read(repo.join(&relative)).unwrap_or_else(|err| {
                panic!(
                    "`{}` wrote no signature in {}: {err}",
                    extra.join(" "),
                    repo.display()
                )
            })
        };
        (read(&port_side), read(&tool_side))
    };
    // The two lists are separate, so the two interleavings write one array.
    let list_order = [
        detached(&["--sign", ED25519_SECRET_B64, "--sign-from-file", &two]),
        detached(&["--sign-from-file", &two, "--sign", ED25519_SECRET_B64]),
    ];
    assert_eq!(
        list_order[0], list_order[1],
        "the two interleavings of the key lists wrote different signatures",
    );
    // The elements follow the command line and no occurrence is dropped, so the
    // two key orders and the one key twice are three different arrays.
    let shapes = [
        detached(&["--sign", ED25519_SECRET_B64, "--sign", ED25519_SECRET2_B64]),
        detached(&["--sign", ED25519_SECRET2_B64, "--sign", ED25519_SECRET_B64]),
        detached(&["--sign", ED25519_SECRET_B64, "--sign", ED25519_SECRET_B64]),
    ];
    for (left, right) in [(0, 1), (0, 2), (1, 2)] {
        assert_ne!(
            shapes[left], shapes[right],
            "signing shapes {left} and {right} wrote one array",
        );
    }
    // Each file form contributes the key its first line holds, so every one of
    // them reaches the signature the key named on the command line makes.
    let plain = detached(&["--sign", ED25519_SECRET_B64]);
    for path in [
        &one,
        &no_newline,
        &padded,
        &extra_lines,
        &not_utf8,
        &nul_after_key,
    ] {
        assert_eq!(
            detached(&["--sign-from-file", path]),
            plain,
            "`--sign-from-file {path}` read another key",
        );
    }

    // Signing an orphan commit writes the `.commitmeta` and no ref, which is
    // what states that the signature stands outside the commit's own hash.
    let orphan = vec![
        "commit",
        "--orphan",
        "-s",
        "orphan",
        FIXED_TIMESTAMP,
        "--sign",
        ED25519_SECRET_B64,
        src,
    ];
    let (port_run, tool_run) = run_both(&port_repo, &tool_repo, &orphan);
    assert_runs_agree(&port_run, &tool_run, "--orphan --sign");
    let orphan_checksum = port_run.ok().stdout_trimmed();
    let (a, b) = orphan_checksum.split_at(2);
    let relative = format!("objects/{a}/{b}.commitmeta");
    assert_eq!(
        std::fs::read(port_repo.join(&relative)).ok(),
        std::fs::read(tool_repo.join(&relative)).ok(),
        "the orphan commits carry different detached metadata",
    );
    for repo in [&port_repo, &tool_repo] {
        assert!(
            repo.join(&relative).exists(),
            "{}: the orphan commit carries no detached metadata",
            repo.display()
        );
        let listed = ostrya(&["refs", "--repo", repo.to_str().unwrap()], None, &[])
            .ok()
            .stdout_trimmed();
        assert!(
            !listed
                .lines()
                .any(|line| resolve(repo, line.trim()).as_deref() == Some(&orphan_checksum)),
            "{}: the orphan commit wrote a ref",
            repo.display()
        );
    }
}

/// The `.commitmeta` bytes both implementations wrote for `branch` agree.
/// The length in bytes of each element one detached signature key holds, read
/// through the tool's own printer, so an element count and an element size are
/// stated rather than inferred from two agreeing files.
fn signature_elements(repo: &Path, rev: &str, key: &str) -> Vec<usize> {
    let run = ostree(&[
        "show",
        &format!("--repo={}", repo.display()),
        &format!("--print-detached-metadata-key={key}"),
        rev,
    ]);
    // The printer annotates the first element alone, so the elements are the
    // bracketed groups inside the outer array and not the annotated ones.
    let text = run.ok().stdout_trimmed();
    let inner = text
        .strip_prefix('[')
        .and_then(|text| text.strip_suffix(']'))
        .unwrap_or_else(|| panic!("`{key}` of {rev} is no array: {text}"));
    inner
        .split('[')
        .skip(1)
        .map(|element| element.matches("0x").count())
        .collect()
}

fn assert_commitmeta_agrees(port_repo: &Path, tool_repo: &Path, rev: &str, label: &str) {
    let checksum = ostrya(
        &["rev-parse", "--repo", port_repo.to_str().unwrap(), rev],
        None,
        &[],
    )
    .ok()
    .stdout_trimmed();
    let relative = format!("objects/{}/{}.commitmeta", &checksum[..2], &checksum[2..]);
    assert_eq!(
        std::fs::read(port_repo.join(&relative)).ok(),
        std::fs::read(tool_repo.join(&relative)).ok(),
        "`{label}` wrote different detached metadata",
    );
}

/// The `commit` signing refusals: a key of the wrong length, a `--sign-type`
/// name no engine carries, and a `--sign-from-file` path that does not open.
#[test]
fn commit_sign_refusals_match_the_tool() {
    if !ostree_supports_ed25519() {
        return;
    }
    let tmp = TmpDir::new("commit-sign-refuse");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();
    let absent = base.join("nope.txt");
    let absent = absent.to_str().unwrap();
    let short = base.join("short.txt");
    std::fs::write(&short, format!("{ED25519_PUBLIC_B64}\n")).unwrap();
    let short = short.to_str().unwrap();
    // A first line that is not UTF-8, and one a NUL byte cuts short. The reader
    // works on bytes, so the first decodes what its alphabet characters carry
    // and the second stops at the NUL.
    let raw = base.join("raw.txt");
    std::fs::write(&raw, b"AAAA\xffAAAA\n").unwrap();
    let raw = raw.to_str().unwrap();
    let nul = base.join("nul.txt");
    std::fs::write(&nul, b"AAAA\0BBBB\n").unwrap();
    let nul = nul.to_str().unwrap();

    let mut cell = 0;
    let mut agrees = |extra: &[&str]| -> String {
        cell += 1;
        let branch = format!("bad{cell}");
        let mut args = vec!["commit", "-b", &branch, FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        args.push(src);
        assert_agrees(&port_repo, &tool_repo, &args);
        // Nothing was published and no ref moved, so the branch resolves to
        // nothing on either side.
        assert_agrees(&port_repo, &tool_repo, &["rev-parse", &branch]);
        branch
    };

    // A key of any length but 64 bytes, read through a decoder that skips every
    // character outside the base64 alphabet. The length the decode reached is
    // the one the refusal names, on both sides.
    for (key, bytes) in [
        ("zzz", 0),
        ("", 0),
        ("not-base64!!!", 6),
        (ED25519_PUBLIC_B64, 32),
    ] {
        let branch = format!("len{bytes}{}", key.len());
        let args = ["commit", "-b", &branch, FIXED_TIMESTAMP, "--sign", key, src];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        let label = args.join(" ");
        assert_runs_agree(&port, &tool, &label);
        assert_runs_agree_on_error(
            &port,
            &tool,
            &label,
            &format!("expected 64 bytes, got {bytes} bytes"),
        );
    }
    agrees(&["--sign-from-file", short]);
    agrees(&["--sign-from-file", raw]);
    agrees(&["--sign-from-file", nul]);
    // Padding acts per group and per position: three bytes come out of each
    // complete four-character group and each of that group's last two
    // characters that is a padding character removes one of them again. Every
    // string over `A` and `=` up to length five states the rule, and a padding
    // character inserted into a valid key states it over a long input.
    let mut padded: Vec<String> = Vec::new();
    for width in 1..=5u32 {
        for bits in 0..1u32 << width {
            padded.push(
                (0..width)
                    .map(|b| if bits >> b & 1 == 1 { '=' } else { 'A' })
                    .collect(),
            );
        }
    }
    // Offset 10 is left out: there the shifted key still decodes to 64 bytes
    // and the two part on the keypair check instead, which
    // `docs/conformance/cli-surface.md` records as its own divergence.
    for offset in [0, 1, 40, 86, 87] {
        let mut key = ED25519_SECRET_B64.to_owned();
        key.insert(offset, '=');
        padded.push(key);
    }
    for key in &padded {
        agrees(&["--sign", key]);
    }
    // A stray character after a pasted key opens an incomplete group, which
    // contributes nothing, so the key still decodes to 64 bytes and signs.
    let with_tail = format!("{ED25519_SECRET_B64}A");
    let signed = agrees(&["--sign", &with_tail]);
    // "still signs" is the claim, so the signature is read back rather than
    // left to the two runs agreeing.
    for repo in [&port_repo, &tool_repo] {
        assert_eq!(
            signature_elements(repo, &signed, "ostree.sign.ed25519"),
            vec![64],
            "{}: the key with a stray character wrote no signature",
            repo.display(),
        );
    }
    // A `--sign-type` name no engine carries, and the one name that carries its
    // own refusal. Both are read only where a key is given.
    agrees(&["--sign-type=nosuch", "--sign", ED25519_SECRET_B64]);
    agrees(&["--sign-type=", "--sign", ED25519_SECRET_B64]);
    agrees(&["--sign-type=ED25519", "--sign", ED25519_SECRET_B64]);
    agrees(&["--sign-type= ed25519", "--sign", ED25519_SECRET_B64]);
    agrees(&["--sign-type=dummy", "--sign", ED25519_SECRET_B64]);
    // Given more than once, the last occurrence decides.
    agrees(&[
        "--sign-type=nosuch",
        "--sign-type=ed25519",
        "--sign",
        ED25519_SECRET_B64,
    ]);
    agrees(&[
        "--sign-type=ed25519",
        "--sign-type=nosuch",
        "--sign",
        ED25519_SECRET_B64,
    ]);
    // With no key at all the name is never read, so a garbage one commits.
    agrees(&["--sign-type=nosuch"]);
    agrees(&["--sign-type=dummy"]);
    // A `--sign-from-file` path that does not open, a directory, and an empty
    // path.
    agrees(&["--sign-from-file", absent]);
    agrees(&["--sign-from-file", src]);
    agrees(&["--sign-from-file", ""]);
    // The fault order inside the step: `--sign-type` first, then every `--sign`
    // key, then every `--sign-from-file` path, whatever the command line's
    // order.
    agrees(&["--sign", "zzz", "--sign-from-file", absent]);
    agrees(&["--sign-from-file", absent, "--sign", "zzz"]);
    agrees(&["--sign", ED25519_SECRET_B64, "--sign-from-file", absent]);
    agrees(&["--sign-type=nosuch", "--sign", "zzz"]);
}

/// The first loose object under `objects` whose name ends in `extension`.
fn find_extension(dir: &Path, extension: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.map(Result::unwrap) {
        let path = entry.path();
        let found = if path.is_dir() {
            find_extension(&path, extension)
        } else {
            path.extension()
                .is_some_and(|found| found == extension)
                .then_some(path)
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

/// The signature is produced before the ref moves. A key that cannot sign
/// leaves the ref where it stood and publishes nothing; a ref write that cannot
/// happen leaves the commit and its `.commitmeta` durable with no ref.
#[test]
fn commit_sign_precedes_the_ref_write() {
    if !ostree_supports_ed25519() {
        return;
    }
    let tmp = TmpDir::new("commit-sign-order");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    let count = |repo: &Path, extension: &str| -> usize {
        fn walk(dir: &Path, extension: &str, found: &mut usize) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.map(Result::unwrap) {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, extension, found);
                } else if path.extension().is_some_and(|e| e == extension) {
                    *found += 1;
                }
            }
        }
        let mut found = 0;
        walk(&repo.join("objects"), extension, &mut found);
        found
    };

    // A first commit both sides make, so the ref has somewhere to stand.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["commit", "-b", "ord", FIXED_TIMESTAMP, "-s", "first", src],
    );
    let before: Vec<usize> = [&port_repo, &tool_repo]
        .iter()
        .map(|repo| count(repo, "commit"))
        .collect();

    // A sign failure over a changed tree: the ref stands and nothing new is
    // published.
    std::fs::write(tree.join("sign-order.txt"), "second\n").unwrap();
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "ord",
            FIXED_TIMESTAMP,
            "-s",
            "second",
            "--sign",
            "zzz",
            src,
        ],
    );
    std::fs::remove_file(tree.join("sign-order.txt")).unwrap();
    let first_tip = resolve(&port_repo, "ord").expect("the first commit stands");
    for (i, repo) in [&port_repo, &tool_repo].iter().enumerate() {
        assert_eq!(count(repo, "commit"), before[i], "a sign failure published");
        assert_eq!(
            count(repo, "commitmeta"),
            0,
            "a sign failure wrote metadata"
        );
        assert_eq!(
            resolve(repo, "ord").as_deref(),
            Some(first_tip.as_str()),
            "{}: a sign failure moved the ref",
            repo.display(),
        );
    }

    // A ref write that cannot happen: the commit and its `.commitmeta` are both
    // durable and the ref does not move.
    for repo in [&port_repo, &tool_repo] {
        let heads = repo.join("refs/heads");
        std::fs::set_permissions(&heads, std::fs::Permissions::from_mode(0o555)).unwrap();
    }
    let (port, tool) = run_both(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "locked",
            FIXED_TIMESTAMP,
            "-s",
            "locked",
            "--sign",
            ED25519_SECRET_B64,
            src,
        ],
    );
    for repo in [&port_repo, &tool_repo] {
        let heads = repo.join("refs/heads");
        std::fs::set_permissions(&heads, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // The two word the write failure differently; the claim is the state each
    // leaves behind (`docs/conformance/cli-surface.md`, "P2").
    for (who, run) in [("port", &port), ("tool", &tool)] {
        assert_eq!(
            run.status.code(),
            Some(1),
            "the {who} did not fail the ref write"
        );
    }
    for repo in [&port_repo, &tool_repo] {
        assert_eq!(
            count(repo, "commitmeta"),
            1,
            "the signature was not written before the ref"
        );
        // The commit the signature names is durable beside it, which the
        // signature's own loose path states.
        let signed = find_extension(&repo.join("objects"), "commitmeta")
            .expect("the signature's loose path");
        assert!(
            signed.with_extension("commit").exists(),
            "{}: the commit object did not survive the failed ref write",
            repo.display(),
        );
        assert!(
            !repo.join("refs/heads/locked").exists(),
            "the ref was written"
        );
    }
}

/// `commit --add-detached-metadata-string` replaces the whole stored detached
/// metadata where a signing option appends to it, and the stored keys keep
/// insertion order: the user keys, then `ostree.sign.<type>`, then
/// `ostree.gpgsigs`.
#[test]
fn commit_sign_replace_and_append_match_the_tool() {
    if !ostree_supports_ed25519() {
        return;
    }
    let tmp = TmpDir::new("commit-sign-append");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();

    // Every step lands on one orphan checksum, so each run edits the metadata
    // the one before it left.
    let step = |extra: &[&str]| -> (String, Vec<u8>) {
        let mut args = vec!["commit", "--orphan", "-s", "same", FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        args.push(src);
        assert_agrees(&port_repo, &tool_repo, &args);
        let checksum = ostrya(
            &[
                "rev-parse",
                "--repo",
                port_repo.to_str().unwrap(),
                "--single",
            ],
            None,
            &[],
        )
        .ok()
        .stdout_trimmed();
        assert_commitmeta_agrees(&port_repo, &tool_repo, &checksum, &extra.join(" "));
        assert_agrees(
            &port_repo,
            &tool_repo,
            &["show", "--list-detached-metadata-keys", &checksum],
        );
        let keys = ostrya(
            &[
                "show",
                "--repo",
                port_repo.to_str().unwrap(),
                "--list-detached-metadata-keys",
                &checksum,
            ],
            None,
            &[],
        )
        .ok()
        .stdout_trimmed();
        let relative = format!("objects/{}/{}.commitmeta", &checksum[..2], &checksum[2..]);
        let stored = std::fs::read(port_repo.join(&relative)).expect("a stored dict");
        (keys, stored)
    };
    let signed = step(&["--sign", ED25519_SECRET_B64]);
    assert!(
        signed.0.contains("ostree.sign.ed25519"),
        "the first signing run wrote no signature: {}",
        signed.0,
    );
    // The replace drops the signature the step before it wrote.
    let replaced = step(&["--add-detached-metadata-string=k=v"]);
    assert!(
        !replaced.0.contains("ostree.sign.ed25519") && replaced.0.contains('k'),
        "the replace kept the signature: {}",
        replaced.0,
    );
    // The append keeps the user key.
    let appended = step(&["--sign", ED25519_SECRET_B64]);
    assert!(
        appended.0.contains("ostree.sign.ed25519") && appended.0.contains('k'),
        "the append dropped one of the two keys: {}",
        appended.0,
    );
    // Both in one run: the user key replaces, the signature appends onto it.
    step(&[
        "--add-detached-metadata-string=k2=v2",
        "--sign",
        ED25519_SECRET2_B64,
    ]);
    // A second signature over a stored commit appends to the array.
    let grown = step(&["--sign", ED25519_SECRET_B64]);
    // `--orphan` resolves no parent, so `--skip-if-unchanged` has nothing to
    // compare against and the run signs like any other: the array grows by one
    // element over the step before it.
    let skipped = step(&["--skip-if-unchanged", "--sign", ED25519_SECRET2_B64]);
    assert!(
        skipped.1.len() > grown.1.len(),
        "the run beside `--skip-if-unchanged` wrote no further signature",
    );
}

/// `commit --gpg-sign` and `--gpg-homedir` write `ostree.gpgsigs`, one element
/// per occurrence and in command-line order, and each implementation's
/// signature verifies through the other's `show --gpg-verify-remote`.
#[cfg(feature = "gpg")]
#[test]
fn commit_gpg_sign_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    if !gpg_available() {
        eprintln!("skipping: gpg not available");
        return;
    }
    let tmp = TmpDir::new("commit-gpg-sign");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let src = tree.to_str().unwrap();
    let home = GpgHome::create(base, "Ostrya Commit Test <cli-commit@ostrya.example>");
    let fpr = home.fingerprint();
    let home_s = home.dir.to_str().unwrap().to_owned();
    let empty_home = base.join("emptyhome");
    std::fs::create_dir(&empty_home).unwrap();
    std::fs::set_permissions(&empty_home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let empty_home = empty_home.to_str().unwrap().to_owned();
    let absent_home = base.join("no-such-home");
    let absent_home = absent_home.to_str().unwrap().to_owned();

    // The refusals, which name the home directory the run read. Neither
    // implementation distinguishes a missing home directory from one holding no
    // matching key.
    let mut cell = 0;
    // `refused` is the line both sides carry, so the refusal is held in the
    // words the record states and not only as an agreement.
    let mut agrees_env = |extra: &[&str], env: &[(&str, &str)], refused: Option<&str>| -> String {
        cell += 1;
        let branch = format!("gpg{cell}");
        let mut args = vec!["commit", "-b", &branch, FIXED_TIMESTAMP];
        args.extend_from_slice(extra);
        args.push(src);
        assert_agrees_env(&port_repo, &tool_repo, &args, env);
        assert_agrees(&port_repo, &tool_repo, &["rev-parse", &branch]);
        if let Some(message) = refused {
            let (port, tool) = run_both_env(&port_repo, &tool_repo, &args, env);
            let label = args.join(" ");
            assert_runs_agree_on_error(&port, &tool, &label, message);
            for (who, run) in [("port", &port), ("tool", &tool)] {
                assert!(
                    resolve(
                        if who == "port" {
                            &port_repo
                        } else {
                            &tool_repo
                        },
                        &branch
                    )
                    .is_none(),
                    "the {who} wrote a ref for `{label}`",
                );
                assert!(run.stdout.is_empty(), "the {who} printed output");
            }
        }
        branch
    };
    let with_home: &[(&str, &str)] = &[("GNUPGHOME", &home_s)];
    // A selector under eight bytes is refused without a lookup, whatever it
    // names, so a user-id substring that resolves to a key still draws the
    // refusal and no arbitrary key is picked.
    for selector in ["", "O", "Ostrya", "Ostrya ", "cli-com", "@cli"] {
        agrees_env(
            &[&format!("--gpg-sign={selector}")],
            with_home,
            Some("Unable to lookup key ID"),
        );
    }
    // Eight bytes and longer reach the lookup: a selector naming nothing is
    // refused by path, and one naming the key signs.
    agrees_env(
        &["--gpg-sign=zzzzzzzz"],
        with_home,
        Some("No gpg key found with ID"),
    );
    let mut signs = String::new();
    for selector in ["Ostrya C", "cli-commit@ostrya.example"] {
        signs = agrees_env(&[&format!("--gpg-sign={selector}")], with_home, None);
    }
    agrees_env(
        &["--gpg-sign=DEADBEEFDEADBEEF"],
        &[],
        Some("No gpg key found with ID DEADBEEFDEADBEEF (homedir: <default>)"),
    );
    agrees_env(
        &["--gpg-sign=DEADBEEFDEADBEEF", "--gpg-homedir", &home_s],
        &[],
        Some(&format!(
            "No gpg key found with ID DEADBEEFDEADBEEF (homedir: {home_s})"
        )),
    );
    agrees_env(
        &["--gpg-sign", &fpr, "--gpg-homedir", &empty_home],
        &[],
        Some("No gpg key found with ID"),
    );
    agrees_env(
        &["--gpg-sign", &fpr, "--gpg-homedir", &absent_home],
        &[],
        Some("No gpg key found with ID"),
    );
    // `--gpg-homedir` wins over `GNUPGHOME`: the populated home the environment
    // names is never read, so the run fails.
    agrees_env(
        &["--gpg-sign", &fpr, "--gpg-homedir", &empty_home],
        with_home,
        Some("No gpg key found with ID"),
    );
    // `--gpg-homedir` with no `--gpg-sign` is accepted and changes nothing.
    agrees_env(&["--gpg-homedir", &home_s], &[], None);
    // The selector that names the key signs, which the refusals above make the
    // discriminating half of the length rule.
    for repo in [&port_repo, &tool_repo] {
        assert_eq!(
            signature_elements(repo, &signs, "ostree.gpgsigs").len(),
            1,
            "{}: a selector naming the key wrote no signature",
            repo.display(),
        );
    }
    // A signed commit reaches the same checksum on both sides. The signature
    // bytes differ per run, so the claim is the checksum and the key set, not
    // the `.commitmeta` bytes.
    for (n, extra) in [
        vec!["--gpg-sign".to_owned(), fpr.clone()],
        vec![
            "--gpg-sign".to_owned(),
            fpr.clone(),
            "--gpg-sign".to_owned(),
            fpr.clone(),
        ],
        vec![
            "--sign".to_owned(),
            ED25519_SECRET_B64.to_owned(),
            "--gpg-sign".to_owned(),
            fpr.clone(),
        ],
    ]
    .into_iter()
    .enumerate()
    {
        let branch = format!("gpgok{n}");
        let mut args = vec!["commit", "-b", &branch, FIXED_TIMESTAMP];
        args.extend(extra.iter().map(String::as_str));
        args.push(src);
        assert_agrees_env(&port_repo, &tool_repo, &args, with_home);
        assert_agrees(
            &port_repo,
            &tool_repo,
            &["show", "--list-detached-metadata-keys", &branch],
        );
    }
    // One element per occurrence, with no deduplication, which the key listing
    // cannot show because it names each key once.
    for repo in [&port_repo, &tool_repo] {
        assert_eq!(
            signature_elements(repo, "gpgok0", "ostree.gpgsigs").len(),
            1,
            "{}: one `--gpg-sign` wrote another element count",
            repo.display(),
        );
        assert_eq!(
            signature_elements(repo, "gpgok1", "ostree.gpgsigs").len(),
            2,
            "{}: the repeated selector was deduplicated",
            repo.display(),
        );
    }

    // Each side's signature verifies through the other's remote keyring.
    let public = base.join("public.gpg");
    home.export_to(&public);
    let public_s = public.to_str().unwrap();
    for signer in [&port_repo, &tool_repo] {
        for verifier in [&port_repo, &tool_repo] {
            let copy = clone_repo(base, signer, "verify-copy");
            let copy_s = copy.to_str().unwrap();
            let add = [
                "remote",
                "add",
                "--repo",
                copy_s,
                "--no-gpg-verify",
                "origin",
                "https://example.invalid/repo",
            ];
            let import = [
                "remote",
                "gpg-import",
                "--repo",
                copy_s,
                "--keyring",
                public_s,
                "origin",
            ];
            let show = [
                "show",
                "--repo",
                copy_s,
                "--gpg-verify-remote=origin",
                "gpgok0",
            ];
            let out = if verifier == &port_repo {
                ostrya(&add, None, &[]).ok();
                ostrya(&import, None, &[]).ok();
                let run = ostrya(&show, None, &[]);
                String::from_utf8_lossy(&run.stdout).into_owned()
            } else {
                ostree(&add).ok();
                ostree(&import).ok();
                let run = ostree(&show);
                String::from_utf8_lossy(&run.stdout).into_owned()
            };
            assert!(
                out.contains("Good signature"),
                "the signature written into {} did not verify in the other \
                 implementation:\n{out}",
                signer.display(),
            );
            std::fs::remove_dir_all(&copy).unwrap();
        }
    }

    // The port's stored dict keeps insertion order: the caller's
    // detached-metadata keys in command-line order, then `ostree.sign.<type>`,
    // then `ostree.gpgsigs`, whatever order the signing options take. The order
    // is read out of the raw `.commitmeta`, since `show
    // --list-detached-metadata-keys` sorts instead. The tool's own order over a
    // set holding all three depends on the key names, so the tool is compared
    // only over the name where the two meet
    // (`docs/conformance/cli-surface.md`, "P2").
    let mut order_cell = 0;
    let mut order_agrees = |users: &[&str], gpg_first: bool, compare_tool: bool| -> String {
        order_cell += 1;
        let branch = format!("gpgorder{order_cell}");
        let user_args: Vec<String> = users
            .iter()
            .map(|user| format!("--add-detached-metadata-string={user}=1"))
            .collect();
        let mut args = vec!["commit", "-b", &branch, FIXED_TIMESTAMP];
        args.extend(user_args.iter().map(String::as_str));
        if gpg_first {
            args.extend(["--gpg-sign", &fpr, "--sign", ED25519_SECRET_B64]);
        } else {
            args.extend(["--sign", ED25519_SECRET_B64, "--gpg-sign", &fpr]);
        }
        args.push(src);
        assert_agrees_env(&port_repo, &tool_repo, &args, with_home);
        let mut wanted: Vec<&str> = users.to_vec();
        wanted.extend(["ostree.sign.ed25519", "ostree.gpgsigs"]);
        assert_eq!(
            detached_key_order(&port_repo, &branch, &wanted),
            wanted,
            "the port stored the keys of `{}` out of insertion order",
            args.join(" "),
        );
        if compare_tool {
            assert_eq!(
                detached_key_order(&tool_repo, &branch, &wanted),
                wanted,
                "the tool stored the keys of `{}` out of insertion order",
                args.join(" "),
            );
        } else {
            // The recorded divergence, held in the direction measured: over
            // these names the tool's own container gives another order.
            assert_ne!(
                detached_key_order(&tool_repo, &branch, &wanted),
                wanted,
                "the tool now stores insertion order for `{}`, so the recorded \
                 divergence is stale",
                args.join(" "),
            );
        }
        branch
    };
    // `zzz` is a name over which the tool's order is the insertion order too.
    order_agrees(&["zzz"], false, true);
    order_agrees(&["zzz"], true, true);
    // `foo` and `user.first` are names over which it is not, so these state the
    // port alone.
    let unsorted = order_agrees(&["foo"], false, false);
    order_agrees(&["foo"], true, false);
    order_agrees(&["user.first"], false, false);
    order_agrees(&["user.first"], true, false);
    // Two user keys of one run keep the command line's order between them.
    order_agrees(&["zzz", "zzy"], false, true);

    // The stored order is the one the raw file holds; the key listing sorts
    // instead, which is why the order is read out of the file.
    let listed = ostrya(
        &[
            "show",
            "--repo",
            port_repo.to_str().unwrap(),
            "--list-detached-metadata-keys",
            &unsorted,
        ],
        None,
        &[],
    )
    .ok()
    .stdout_trimmed();
    let listed: Vec<&str> = listed.lines().map(str::trim).collect();
    let mut sorted = listed.clone();
    sorted.sort_unstable();
    assert_eq!(listed, sorted, "the key listing is not sorted");
    assert_ne!(
        listed,
        detached_key_order(&port_repo, &unsorted, &listed),
        "the listing and the stored order are one, so the listing states the order",
    );

    // A selector eight bytes or longer that names more than one secret key is
    // refused rather than resolved to one of them.
    home.add_key("Ostrya Commit Spare <cli-spare@ostrya.example>");
    agrees_env(&["--gpg-sign=Ostrya C"], with_home, Some("ambiguous"));
    agrees_env(
        &["--gpg-sign=Ostrya C", "--gpg-homedir", &home_s],
        &[],
        Some("ambiguous"),
    );
}

/// The detached-metadata keys of `rev`, ordered as the raw `.commitmeta`
/// stores them.
///
/// A GVariant `a{sv}` holds each entry's key as a NUL-terminated string in
/// stored order, so the first byte offset of each name gives that order.
/// `wanted` names the keys to look for, each of which must be present.
#[cfg(feature = "gpg")]
fn detached_key_order(repo: &Path, rev: &str, wanted: &[&str]) -> Vec<String> {
    let checksum = ostrya(
        &["rev-parse", "--repo", repo.to_str().unwrap(), rev],
        None,
        &[],
    )
    .ok()
    .stdout_trimmed();
    let (a, b) = checksum.split_at(2);
    let bytes = std::fs::read(repo.join(format!("objects/{a}/{b}.commitmeta"))).unwrap();
    let mut found: Vec<(usize, String)> = Vec::new();
    for key in wanted {
        let needle = key.as_bytes();
        let at = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap_or_else(|| panic!("{key} is not in the .commitmeta of {rev}"));
        found.push((at, (*key).to_owned()));
    }
    found.sort();
    found.into_iter().map(|(_, key)| key).collect()
}

/// A `--sign-from-file` file whose first line is empty, and a file with no
/// bytes at all, are refused cleanly. Reference build 2026.1 dies on a signal
/// for each of the two, so this states the port alone
/// (`docs/conformance/cli-surface.md`, "P2").
#[test]
fn commit_sign_from_file_empty_line_is_refused_cleanly() {
    let tmp = TmpDir::new("commit-sign-empty-line");
    let base = tmp.path();
    let repo = create_repo(base, RepoMode::Archive);
    build_fixture_source(base);
    let src = base.join("src");
    let src = src.to_str().unwrap();

    let blank = base.join("blank-first.txt");
    std::fs::write(&blank, format!("\n{ED25519_SECRET_B64}\n")).unwrap();
    let empty = base.join("no-bytes.txt");
    std::fs::write(&empty, "").unwrap();

    // The number of commit objects the repository holds, so "as it stands" is
    // read and not assumed.
    let commits = |repo: &Path| -> usize {
        fn walk(dir: &Path, found: &mut usize) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.map(Result::unwrap) {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, found);
                } else if path.extension().is_some_and(|e| e == "commit") {
                    *found += 1;
                }
            }
        }
        let mut found = 0;
        walk(&repo.join("objects"), &mut found);
        found
    };
    let before = commits(&repo);

    for (n, path) in [&blank, &empty].into_iter().enumerate() {
        let branch = format!("clean{n}");
        let run = ostrya(
            &[
                "commit",
                "--repo",
                repo.to_str().unwrap(),
                "-b",
                &branch,
                FIXED_TIMESTAMP,
                "--sign-from-file",
                path.to_str().unwrap(),
                src,
            ],
            None,
            &[],
        );
        assert_eq!(run.status.code(), Some(1), "the port did not exit 1");
        let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
        assert!(
            stderr.contains(
                "error: Invalid ed25519 secret key: Ill-formed input: expected 64 bytes, \
                 got 0 bytes"
            ),
            "the port's refusal reads {stderr:?}"
        );
        assert!(
            resolve(&repo, &branch).is_none(),
            "a refused signing run moved the ref"
        );
        assert_eq!(
            commits(&repo),
            before,
            "a refused signing run published a commit",
        );
    }

    // A first line longer than the port's cap is refused rather than cut, so
    // no run reports a length shorter than the file holds. The tool reads a
    // line of any length and reports the whole of it
    // (`docs/conformance/cli-surface.md`, "P2").
    let over_long = base.join("over-long.txt");
    std::fs::write(&over_long, "A".repeat(100_000)).unwrap();
    let run = ostrya(
        &[
            "commit",
            "--repo",
            repo.to_str().unwrap(),
            "-b",
            "toolong",
            FIXED_TIMESTAMP,
            "--sign-from-file",
            over_long.to_str().unwrap(),
            src,
        ],
        None,
        &[],
    );
    assert_eq!(run.status.code(), Some(1), "the port did not exit 1");
    let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
    assert_eq!(
        stderr.trim(),
        format!(
            "error: Error reading file {}: the first line is longer than 65536 bytes",
            over_long.display()
        ),
        "the port's refusal reads {stderr:?}"
    );
    assert!(
        resolve(&repo, "toolong").is_none(),
        "a refused signing run moved the ref"
    );
    assert_eq!(
        commits(&repo),
        before,
        "a refused signing run published a commit",
    );
}

/// A 64-byte `--sign` value whose halves are not an ed25519 key pair is refused
/// cleanly. The tool signs both shapes, so this states the port alone
/// (`docs/conformance/cli-surface.md`, "P2").
#[test]
fn commit_sign_keypair_mismatch_is_refused_cleanly() {
    let tmp = TmpDir::new("commit-sign-keypair");
    let base = tmp.path();
    let repo = create_repo(base, RepoMode::Archive);
    build_fixture_source(base);
    let src = base.join("src");
    let src = src.to_str().unwrap();

    // The fixture key's seed followed by another key's public key, and 64 bytes
    // whose trailing half is not a curve point.
    let secret = decode_test_base64(ED25519_SECRET_B64);
    let other = decode_test_base64(ED25519_SECRET2_B64);
    let mismatched = encode_test_base64(&[&secret[..32], &other[32..]].concat());
    let not_a_point = encode_test_base64(&(0..64u8).collect::<Vec<u8>>());

    for (n, (key, reason)) in [
        (mismatched, "Mismatched Keypair detected"),
        (not_a_point, "Cannot decompress Edwards point"),
    ]
    .into_iter()
    .enumerate()
    {
        let branch = format!("pair{n}");
        let run = ostrya(
            &[
                "commit",
                "--repo",
                repo.to_str().unwrap(),
                "-b",
                &branch,
                FIXED_TIMESTAMP,
                "--sign",
                &key,
                src,
            ],
            None,
            &[],
        );
        assert_eq!(run.status.code(), Some(1), "the port did not exit 1");
        let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
        assert!(
            stderr.contains(reason),
            "the port's refusal reads {stderr:?}"
        );
        assert!(
            resolve(&repo, &branch).is_none(),
            "a refused signing run moved the ref"
        );

        // The tool takes the same value: it signs at exit 0 and stores one
        // 64-byte element, which is the state the port refuses to write.
        if ostree_supports_ed25519() {
            let tool_repo = base.join(format!("tool{n}"));
            block_on(async {
                Repo::create(&tool_repo, CreateOptions::new(RepoMode::Archive))
                    .await
                    .unwrap();
            });
            let run = ostree(&[
                "commit",
                "--repo",
                tool_repo.to_str().unwrap(),
                "-b",
                &branch,
                FIXED_TIMESTAMP,
                "--sign",
                &key,
                src,
            ]);
            assert_eq!(
                run.status.code(),
                Some(0),
                "the tool refused the key pair the port refuses:\n{}",
                String::from_utf8_lossy(&run.stderr),
            );
            assert_eq!(
                signature_elements(&tool_repo, &branch, "ostree.sign.ed25519"),
                vec![64],
                "the tool wrote no signature for the key pair the port refuses",
            );
        }
    }
}

// --- Phase 17f, X1 and F10a: abbreviated checksum resolution ------------------
//
// A revision shorter than a full checksum names the one commit object whose
// checksum starts with it, wherever a revision is taken
// (`docs/format-reference.md`, "Revision syntax"). Each test commits corpus `C0`
// under a fixed timestamp, so the two implementations hold the same commit
// checksum and one prefix string states the same case on both sides.

/// Every loose object in a repository as `(checksum, extension)`.
fn loose_objects(repo: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for fanout in object_fanouts(repo) {
        let dir = repo.join(&fanout);
        let name = dir.file_name().unwrap().to_str().unwrap().to_owned();
        for entry in std::fs::read_dir(&dir).expect("the fanout reads") {
            let entry = entry.expect("the entry reads");
            let file = entry.file_name().to_str().unwrap().to_owned();
            let (rest, ext) = file.rsplit_once('.').expect("an object name");
            out.push((format!("{name}{rest}"), ext.to_owned()));
        }
    }
    out.sort();
    out
}

/// The checksum of one loose object that is not a commit, for the prefix that
/// must match nothing.
fn a_non_commit_object(repo: &Path) -> String {
    loose_objects(repo)
        .into_iter()
        .find(|(_, ext)| ext != "commit")
        .expect("the store holds a non-commit object")
        .0
}

/// Commit corpus `C0` into both repositories on `branch` under the fixed
/// timestamp, asserting the two agree, and return the checksum they printed.
fn commit_both(port_repo: &Path, tool_repo: &Path, tree: &Path, branch: &str) -> String {
    let args = [
        "commit",
        "-b",
        branch,
        FIXED_TIMESTAMP,
        tree.to_str().unwrap(),
    ];
    let (port, tool) = run_both(port_repo, tool_repo, &args);
    assert_runs_agree(&port, &tool, &args.join(" "));
    port.ok().stdout_trimmed()
}

/// A prefix resolves to the commit it names at every length, an object that is
/// no commit is not reachable by prefix, and the case rule and the ancestry
/// suffix hold over an abbreviated name as they do over a full checksum.
#[test]
fn abbreviated_checksum_resolves_like_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("abbrev-resolve");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let commit = commit_both(&port_repo, &tool_repo, &tree, "base");

    // Every length from one character to one short of the whole checksum
    // resolves, and the whole checksum keeps resolving to itself.
    for len in [1usize, 2, 3, 4, 8, 32, 63, 64] {
        assert_agrees(&port_repo, &tool_repo, &["rev-parse", &commit[..len]]);
    }
    // One character more than a checksum, and an uppercase rendering, are ref
    // names that name nothing.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["rev-parse", &format!("{commit}a")],
    );
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["rev-parse", &commit[..8].to_uppercase()],
    );
    // A prefix carried by a dirtree, a dirmeta, or a file object alone matches
    // nothing: the match set holds commit objects. Both stores hold the same
    // object names, the corpus and the timestamp being fixed.
    let other = a_non_commit_object(&port_repo);
    assert_eq!(other, a_non_commit_object(&tool_repo));
    for len in [1usize, 4, 8] {
        assert_agrees(&port_repo, &tool_repo, &["rev-parse", &other[..len]]);
    }
    // A hex name no commit begins with is a ref name, so a ref of that name
    // resolves through the ref store.
    assert_agrees(&port_repo, &tool_repo, &["refs", "--create=dddd", "base"]);
    assert_agrees(&port_repo, &tool_repo, &["rev-parse", "dddd"]);
    // The existence check of `--create=NEWREF` resolves NEWREF, so a NEWREF
    // that is a prefix of a commit names one.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["refs", &format!("--create={}", &commit[..6]), "base"],
    );
    // `refs -A --create` takes a ref name and not a revision, so a prefix there
    // names no ref: both report `Cannot create alias to non-existent ref` and
    // neither writes an alias (`docs/format-reference.md`, "Revision syntax").
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["refs", "-A", "--create=al", &commit[..6]],
    );
    // A `-A` listing matches its PREFIX against the ref names and the alias
    // names rather than resolving it, so a prefix naming neither prints nothing
    // at exit 0 in both, where a resolution would print the commit it reaches.
    // The alias written here is what an unfiltered `-A` listing prints, so the
    // empty listing under the prefix states that the prefix selected by match
    // (`docs/format-reference.md`, "Revision syntax").
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["refs", "-A", "--create=alforlist", "base"],
    );
    assert_agrees(&port_repo, &tool_repo, &["refs", "-A"]);
    assert_agrees(&port_repo, &tool_repo, &["refs", "-A", &commit[..6]]);
    // The ancestry suffix applies to what the prefix resolved to, and the one
    // commit here is a root commit.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["rev-parse", &format!("{}^", &commit[..6])],
    );
    // The other revision sites take an abbreviated name too.
    let short = commit[..6].to_owned();
    assert_agrees(&port_repo, &tool_repo, &["show", &short]);
    assert_agrees(&port_repo, &tool_repo, &["log", &short]);
    assert_agrees(&port_repo, &tool_repo, &["ls", &short]);
    assert_agrees(&port_repo, &tool_repo, &["cat", &short, "/file.txt"]);
    assert_agrees(&port_repo, &tool_repo, &["diff", &short, "base"]);
    // `commit` resolves one at `--tree=ref=` and at `--base`, so the checksum
    // both print states that each read the same tree.
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "viatree",
            FIXED_TIMESTAMP,
            &format!("--tree=ref={short}"),
        ],
    );
    assert_agrees(
        &port_repo,
        &tool_repo,
        &[
            "commit",
            "-b",
            "viabase",
            FIXED_TIMESTAMP,
            &format!("--base={short}"),
            tree.to_str().unwrap(),
        ],
    );
    assert_eq!(describe_refs(&port_repo), describe_refs(&tool_repo));
}

/// `commit -b NAME`, where NAME is a prefix of a commit the repository holds and
/// names no ref, parents the new commit on that commit. This is item `F10a`: the
/// checksum both implementations print is the oracle, since a differing parent
/// gives a differing commit object.
#[test]
fn commit_branch_name_as_abbreviated_checksum_matches_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("abbrev-commit-b");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);
    let first = commit_both(&port_repo, &tool_repo, &tree, "base");
    let prefix = first[..4].to_owned();

    // The branch names no ref, so the implicit parent is what the name resolves
    // to as a revision: the commit it prefixes.
    let second = commit_both(&port_repo, &tool_repo, &tree, &prefix);
    assert_ne!(first, second);
    assert_agrees(&port_repo, &tool_repo, &["show", &second]);
    let shown = ostrya(
        &["show", "--repo", port_repo.to_str().unwrap(), &second],
        None,
        &[],
    )
    .ok()
    .stdout_trimmed();
    assert!(
        shown.contains(&format!("Parent:  {first}")),
        "the commit under a prefix branch name carries no parent:\n{shown}"
    );

    // The branch now holds `second`, and the name still resolves to `first`, so
    // a further commit on it takes `first` as its parent again. The ref file is
    // read as a file: resolving the name would give the prefix match, which is
    // the behavior under test.
    let ref_file = port_repo.join("refs").join("heads").join(&prefix);
    assert_eq!(
        std::fs::read_to_string(&ref_file).unwrap().trim(),
        second,
        "the ref file must hold the commit the branch was moved to"
    );
    assert_eq!(
        resolve(&port_repo, &prefix).as_deref(),
        Some(first.as_str()),
        "the name must resolve to the commit it prefixes"
    );
    // The commit object it writes therefore reproduces `second` byte for byte,
    // the tree and the timestamp being the same. A parent taken from the ref
    // file would give another checksum, so this states which of the two the
    // implicit parent read.
    let third = commit_both(&port_repo, &tool_repo, &tree, &prefix);
    assert_eq!(
        third, second,
        "the second commit on a prefix branch must parent on the prefix match"
    );
    assert_eq!(describe_refs(&port_repo), describe_refs(&tool_repo));
}

/// A prefix more than one commit carries resolves nowhere: both implementations
/// report `Refspec <prefix> not unique` at exit 1, at every site that takes a
/// revision, and `commit -b <prefix>` writes neither an object nor a ref.
#[test]
fn ambiguous_abbreviated_checksum_is_refused_like_the_tool() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("abbrev-ambiguous");
    let base = tmp.path();
    let (port_repo, tool_repo, tree) = commit_pair(base, RepoMode::Archive);

    // Commit distinct bodies until two commits share their first character. The
    // checksums are content-addressed and the timestamp is fixed, so the
    // collision falls the same way in both stores.
    let mut heads: Vec<String> = Vec::new();
    let mut prefix = None;
    for n in 0..400 {
        let branch = format!("probe-{n}");
        let args = [
            "commit",
            "-b",
            &branch,
            FIXED_TIMESTAMP,
            "-m",
            &branch,
            tree.to_str().unwrap(),
        ];
        let (port, tool) = run_both(&port_repo, &tool_repo, &args);
        assert_runs_agree(&port, &tool, &args.join(" "));
        let commit = port.ok().stdout_trimmed();
        let head = commit[..1].to_owned();
        if heads.contains(&head) {
            prefix = Some(head);
            break;
        }
        heads.push(head);
    }
    let prefix = prefix.expect("two commits sharing a first character");

    // Every revision site reports the same refusal, the ancestry suffix
    // included: nothing resolved to walk back from.
    for args in [
        vec!["rev-parse", &prefix],
        vec!["show", &prefix],
        vec!["log", &prefix],
        vec!["ls", &prefix],
        vec!["cat", &prefix, "/file.txt"],
        vec!["diff", &prefix, "probe-0"],
        vec!["refs", "--create=fromamb", &prefix],
    ] {
        assert_agrees(&port_repo, &tool_repo, &args);
        assert_agrees_on_error(
            &port_repo,
            &tool_repo,
            &args,
            &format!("error: Refspec {prefix} not unique"),
        );
    }
    // `refs -A --create` takes a ref name and not a revision, so the prefix is
    // matched against no commit there and the ambiguity is never reached: both
    // report the line they report for a prefix one commit carries
    // (`docs/format-reference.md`, "Revision syntax").
    let alias_args = ["refs", "-A", "--create=alamb", &prefix];
    assert_agrees(&port_repo, &tool_repo, &alias_args);
    assert_agrees_on_error(
        &port_repo,
        &tool_repo,
        &alias_args,
        &format!("error: Cannot create alias to non-existent ref: {prefix}"),
    );
    // A `-A` listing matches its PREFIX rather than resolving it, so the
    // ambiguity is never reached there: the prefix names no ref and no alias,
    // and both print nothing at exit 0 in place of the `not unique` line every
    // revision site reports. The alias written here is what an unfiltered `-A`
    // listing prints, so the empty listing under the prefix states that the
    // prefix selected by match (`docs/format-reference.md`, "Revision syntax").
    assert_agrees(
        &port_repo,
        &tool_repo,
        &["refs", "-A", "--create=alforlist", "probe-0"],
    );
    assert_agrees(&port_repo, &tool_repo, &["refs", "-A"]);
    assert_agrees(&port_repo, &tool_repo, &["refs", "-A", &prefix]);
    let caret = format!("{prefix}^");
    assert_agrees(&port_repo, &tool_repo, &["rev-parse", &caret]);

    // `commit -b <ambiguous>` stops at the implicit parent, so no commit is
    // written and no ref is created.
    let before = (describe_refs(&port_repo), loose_objects(&port_repo));
    let commit_args = [
        "commit",
        "-b",
        &prefix,
        FIXED_TIMESTAMP,
        tree.to_str().unwrap(),
    ];
    assert_agrees(&port_repo, &tool_repo, &commit_args);
    assert_agrees_on_error(
        &port_repo,
        &tool_repo,
        &commit_args,
        &format!("error: Refspec {prefix} not unique"),
    );
    assert_eq!(
        (describe_refs(&port_repo), loose_objects(&port_repo)),
        before,
        "a refused commit changed the repository"
    );
    assert_eq!(describe_refs(&port_repo), describe_refs(&tool_repo));
}

/// Decode standard padded base64, for building the key fixtures the tests above
/// need.
fn decode_test_base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let body = text.trim_end_matches('=');
    let padding = text.len() - body.len();
    let mut out = Vec::new();
    let mut group = 0u32;
    let mut held = 0u32;
    for byte in body.bytes() {
        let six = ALPHABET
            .iter()
            .position(|c| *c == byte)
            .expect("a base64 alphabet character") as u32;
        group = group << 6 | six;
        held += 1;
        if held == 4 {
            out.extend_from_slice(&[(group >> 16) as u8, (group >> 8) as u8, group as u8]);
            group = 0;
            held = 0;
        }
    }
    if held > 0 {
        group <<= 6 * (4 - held);
        out.extend_from_slice(&[(group >> 16) as u8, (group >> 8) as u8, group as u8]);
        out.truncate(out.len() - padding);
    }
    out
}

/// Encode bytes as standard padded base64.
fn encode_test_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut group = 0u32;
        for (i, byte) in chunk.iter().enumerate() {
            group |= u32::from(*byte) << (16 - 8 * i);
        }
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(group >> (18 - 6 * i) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
