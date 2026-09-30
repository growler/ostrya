//! `PushSession::connect` and `Repo::push` over a stand-in ssh client that
//! runs the built `ostrya receive` locally, the way the remote shell of ssh
//! runs the remote command.

#![cfg(feature = "receive")]

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ostrya::push::{
    BoxFuture, Compression, ConnectOptions, Encoding, Error, Expected, ObjectData, ObjectSource,
    PushOutcome, PushRemote, PushSession, RefUpdate, SessionOptions,
};
use ostrya::{
    Checksum, CreateOptions, FileKind, ObjectName, ObjectType, Repo, RepoMode, Value, loose_path,
};
use ostrya_rt::block_on;

/// The fixture commit and its branch.
const COMMIT: &str = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";
const BRANCH: &str = "test/main";
const ROOT_DIRMETA: &str = "446a0ef11b7cc167f3b603e585c7eeeeb675faa412d5ec73f62988eb0b6c5488";

const REQUIRE_OSTREE: &str = "OSTRYA_REQUIRE_OSTREE";

/// The stand-in ssh client. Its first two arguments are a file that gets the
/// exit status of the remote command and a file that gets its standard
/// error. It skips `-p PORT` and the host, and runs the remote command string
/// with `sh`.
const STANDIN: &str = r#"status_file=$1; stderr_file=$2; shift 2
if [ "$1" = "-p" ]; then shift 2; fi
shift
sh -c "$*" 2> "$stderr_file"
code=$?
echo "$code" > "$status_file"
exit "$code"
"#;

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ostrya-push-ssh-{}-{tag}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TmpDir(path)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/generated/archive/repo")
}

fn commit() -> Checksum {
    Checksum::from_hex(COMMIT).unwrap()
}

/// Quote `s` for a POSIX shell.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// An async reader over the file at `path`.
fn open_file(path: &Path) -> ostrya_rt::File {
    ostrya_rt::File::from(OwnedFd::from(std::fs::File::open(path).unwrap()))
}

fn source_error(e: ostrya::Error) -> Error {
    Error::Source(Box::new(e))
}

/// A source over the archive fixture. A content object the session asks for
/// in `deflate` is the stored `.filez` file.
struct FixtureSource {
    repo: Repo,
    root: PathBuf,
}

impl FixtureSource {
    fn new() -> FixtureSource {
        let root = fixture();
        FixtureSource {
            repo: block_on(Repo::open(&root)).unwrap(),
            root,
        }
    }

    fn loose(&self, name: &ObjectName) -> PathBuf {
        self.root
            .join("objects")
            .join(loose_path(&name.checksum, name.ty, RepoMode::Archive))
    }

    async fn load(&self, name: &ObjectName, encoding: Encoding) -> ostrya::Result<ObjectData> {
        if name.ty != ObjectType::File || encoding == Encoding::Deflate {
            return Ok(ObjectData::Encoded {
                encoding,
                reader: Box::new(open_file(&self.loose(name))),
            });
        }
        let file = self.repo.load_file(&name.checksum).await?;
        let (size, payload) = match file.kind {
            FileKind::Regular { size } => (size, Some(Box::new(file.reader().await?) as _)),
            FileKind::Symlink { .. } => (0, None),
        };
        Ok(ObjectData::Content {
            header: file.header(),
            size,
            payload,
        })
    }
}

impl ObjectSource for FixtureSource {
    fn objects<'a>(
        &'a self,
        commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya::push::Result<Vec<ObjectName>>> {
        Box::pin(async move {
            let names = self
                .repo
                .traverse_commit(commit, 0)
                .await
                .map_err(source_error)?;
            let mut names: Vec<ObjectName> = names.into_iter().collect();
            names.sort_by_key(|n| (n.ty as u8, n.checksum));
            Ok(names)
        })
    }

    fn open<'a>(
        &'a self,
        name: &'a ObjectName,
        encoding: Encoding,
    ) -> BoxFuture<'a, ostrya::push::Result<ObjectData>> {
        Box::pin(async move { self.load(name, encoding).await.map_err(source_error) })
    }

    fn detached_metadata<'a>(
        &'a self,
        _commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya::push::Result<Option<Value>>> {
        Box::pin(async { Ok(None) })
    }
}

/// A source whose first object does not hash to its name, and whose second
/// object has no end: it reads `/dev/zero`.
struct BadSource;

impl ObjectSource for BadSource {
    fn objects<'a>(
        &'a self,
        _commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya::push::Result<Vec<ObjectName>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn open<'a>(
        &'a self,
        name: &'a ObjectName,
        _encoding: Encoding,
    ) -> BoxFuture<'a, ostrya::push::Result<ObjectData>> {
        Box::pin(async move {
            let path = match name.ty {
                ObjectType::DirMeta => fixture().join("objects").join(loose_path(
                    &Checksum::from_hex(ROOT_DIRMETA).unwrap(),
                    ObjectType::DirMeta,
                    RepoMode::Archive,
                )),
                _ => PathBuf::from("/dev/zero"),
            };
            Ok(ObjectData::Encoded {
                encoding: Encoding::Raw,
                reader: Box::new(open_file(&path)),
            })
        })
    }

    fn detached_metadata<'a>(
        &'a self,
        _commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya::push::Result<Option<Value>>> {
        Box::pin(async { Ok(None) })
    }
}

/// A receiving repository of `mode` at a path that holds a `'` and a space.
fn receiver(base: &TmpDir, mode: RepoMode) -> PathBuf {
    let path = base.0.join("it's a repo");
    block_on(Repo::create(&path, CreateOptions::new(mode))).unwrap();
    path
}

/// The options that run `ostrya -v receive` through the stand-in, with the
/// exit status of the command written to `status` and its standard error to
/// the file beside it that [`stderr_of`] names.
fn options(status: &Path, policy: Option<&Path>) -> ConnectOptions {
    let mut receive = format!("{} -v receive", quote(env!("CARGO_BIN_EXE_ostrya")));
    if let Some(policy) = policy {
        receive.push_str(&format!(" --policy={}", quote(policy.to_str().unwrap())));
    }
    ConnectOptions {
        ssh_command: Some(vec![
            "sh".into(),
            "-c".into(),
            STANDIN.into(),
            "ssh".into(),
            status.to_str().unwrap().into(),
            stderr_of(status).to_str().unwrap().into(),
        ]),
        receive_command: Some(receive),
        ..Default::default()
    }
}

fn stderr_of(status: &Path) -> PathBuf {
    status.with_extension("stderr")
}

fn remote(dest: &Path) -> PushRemote {
    PushRemote::parse(&format!("ssh://localhost{}", dest.display())).unwrap()
}

fn update() -> RefUpdate {
    RefUpdate {
        name: BRANCH.into(),
        expected: Expected::Absent,
        new: Some(commit()),
    }
}

/// Push the fixture commit to `dest` over the stand-in.
fn push(
    dest: &Path,
    status: &Path,
    policy: Option<&Path>,
    compression: Compression,
) -> ostrya::push::Result<PushOutcome> {
    let source = FixtureSource::new();
    block_on(async {
        let session = PushSession::connect(
            &remote(dest),
            options(status, policy),
            &[BRANCH.to_owned()],
            SessionOptions::default(),
        )
        .await?;
        let names = source.objects(&commit()).await?;
        let needed = session.missing(&names).await?;
        session
            .send(&source, &needed, &[commit()], compression)
            .await?;
        session.commit(&[update()], false).await
    })
}

fn exit_status(status: &Path) -> String {
    std::fs::read_to_string(status).unwrap().trim().to_owned()
}

fn tip(dest: &Path) -> Option<Checksum> {
    block_on(async {
        let repo = Repo::open(dest).await.unwrap();
        repo.resolve_rev(BRANCH, true).await.unwrap()
    })
}

/// Whether the `ostree` tool can run. With `OSTRYA_REQUIRE_OSTREE` set, a
/// missing tool fails the test.
fn ostree_available() -> bool {
    let found = Command::new("ostree")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        found || std::env::var_os(REQUIRE_OSTREE).is_none(),
        "{REQUIRE_OSTREE} is set and `ostree` is not installed"
    );
    if !found {
        eprintln!("skipped: `ostree` is not installed");
    }
    found
}

/// `ostree fsck` passes on `repo`, where the tool is installed.
fn tool_fsck(repo: &Path) {
    if !ostree_available() {
        return;
    }
    let out = Command::new("ostree")
        .arg(format!("--repo={}", repo.display()))
        .arg("fsck")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ostree fsck failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_push_over_ssh_writes_the_ref_and_the_tool_checks_the_repository() {
    for (mode, compression) in [
        (RepoMode::Archive, Compression::Deflate { level: 6 }),
        (RepoMode::BareUser, Compression::None),
    ] {
        let base = TmpDir::new("push");
        let dest = receiver(&base, mode);
        let status = base.0.join("status");
        let outcome = push(&dest, &status, None, compression).unwrap();
        assert_eq!(outcome.refs.len(), 1);
        assert_eq!(outcome.refs[0].name, BRANCH);
        assert_eq!(outcome.refs[0].old, None);
        assert_eq!(outcome.refs[0].new, Some(commit()));
        assert_eq!(tip(&dest), Some(commit()), "{mode:?}");
        assert_eq!(exit_status(&status), "0");
        // Nothing on standard error after a committed session, also under
        // `-v`.
        assert_eq!(std::fs::read_to_string(stderr_of(&status)).unwrap(), "");
        tool_fsck(&dest);
    }
}

#[test]
fn a_policy_file_that_refuses_the_ref_leaves_it_absent() {
    let base = TmpDir::new("policy");
    let dest = receiver(&base, RepoMode::Archive);
    let policy = base.0.join("receive.conf");
    std::fs::write(&policy, "[ex-ostrya receive]\naccept=false\n").unwrap();
    let status = base.0.join("status");
    match push(&dest, &status, Some(&policy), Compression::None) {
        Err(Error::RefDenied(_)) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(tip(&dest), None);
    assert_ne!(exit_status(&status), "0");
    let stderr = std::fs::read_to_string(stderr_of(&status)).unwrap();
    assert!(stderr.starts_with("error: ref-denied: "), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
}

#[test]
fn a_server_error_while_the_client_still_sends_reaches_the_client() {
    let base = TmpDir::new("mismatch");
    let dest = receiver(&base, RepoMode::Archive);
    let status = base.0.join("status");
    let names = [
        ObjectName::new(Checksum::from_bytes([1; 32]), ObjectType::DirMeta),
        ObjectName::new(Checksum::from_bytes([2; 32]), ObjectType::File),
    ];
    let start = Instant::now();
    let r = block_on(async {
        let session = PushSession::connect(
            &remote(&dest),
            options(&status, None),
            &[BRANCH.to_owned()],
            SessionOptions::default(),
        )
        .await?;
        session
            .send(&BadSource, &names, &[], Compression::None)
            .await
    });
    let elapsed = start.elapsed();
    match r {
        Err(Error::ChecksumMismatch(_)) => {}
        other => panic!("{other:?}"),
    }
    // The error arrives as the pending message of a failed write, and the
    // limit of that read does not run out.
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    assert_eq!(tip(&dest), None);
}

#[test]
fn receive_with_no_session_on_its_input_fails() {
    let base = TmpDir::new("eof");
    let dest = receiver(&base, RepoMode::Archive);
    let out = Command::new(env!("CARGO_BIN_EXE_ostrya"))
        .arg(format!("--repo={}", dest.display()))
        .arg("receive")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.starts_with("error: "), "{stderr}");
}

#[test]
fn receive_refuses_a_policy_file_it_cannot_read() {
    let base = TmpDir::new("nopolicy");
    let dest = receiver(&base, RepoMode::Archive);
    let out = Command::new(env!("CARGO_BIN_EXE_ostrya"))
        .arg(format!("--repo={}", dest.display()))
        .arg("receive")
        .arg(format!("--policy={}", base.0.join("absent").display()))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("absent"), "{stderr}");
}

/// `Repo::push` to a remote of the local config, over the stand-in.
#[cfg(feature = "push")]
mod repo_push {
    use super::*;
    use ostrya::{PullOptions, RepoPushOptions};

    /// A local repository that holds the fixture commit on its branch, with
    /// the remote `origin` whose `push-url` names `dest` and whose
    /// `receive-command` runs the built `ostrya receive`.
    fn client(base: &TmpDir, dest: &Path) -> Repo {
        let path = base.0.join("client");
        block_on(async {
            let repo = Repo::create(&path, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let fixture = Repo::open(&fixture()).await.unwrap();
            repo.pull_local(
                &fixture,
                PullOptions {
                    refs: vec![BRANCH.to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        });
        let config = path.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(&format!(
            "\n[remote \"origin\"]\npush-url=ssh://localhost{}\nreceive-command={} -v receive\n",
            dest.display(),
            quote(env!("CARGO_BIN_EXE_ostrya")),
        ));
        std::fs::write(&config, text).unwrap();
        block_on(Repo::open(&path)).unwrap()
    }

    /// The options of a push of `refspecs`, with the stand-in as the ssh
    /// command and the receive command left to the remote section.
    fn push_opts(status: &Path, refspecs: &[&str]) -> RepoPushOptions {
        RepoPushOptions {
            refspecs: refspecs.iter().map(|s| (*s).to_owned()).collect(),
            compression: Compression::Deflate { level: 6 },
            connect: ConnectOptions {
                receive_command: None,
                ..options(status, None)
            },
            ..RepoPushOptions::default()
        }
    }

    #[test]
    fn a_push_to_a_configured_remote_writes_the_ref() {
        let base = TmpDir::new("repo-push");
        let dest = receiver(&base, RepoMode::Archive);
        let local = client(&base, &dest);
        let status = base.0.join("status");

        let outcome = block_on(local.push("origin", push_opts(&status, &[BRANCH]))).unwrap();
        assert_eq!(outcome.refs.len(), 1);
        assert_eq!(outcome.refs[0].old, None);
        assert_eq!(outcome.refs[0].new, Some(commit()));
        assert!(outcome.stats.objects_sent > 0);
        assert_eq!(tip(&dest), Some(commit()));
        assert_eq!(exit_status(&status), "0");

        // A repeat push finds every object on the server and sends none.
        let outcome = block_on(local.push("origin", push_opts(&status, &[BRANCH]))).unwrap();
        assert_eq!(outcome.refs[0].old, Some(commit()));
        assert_eq!(outcome.refs[0].new, Some(commit()));
        assert_eq!(outcome.stats.objects_needed, 0);
        assert_eq!(outcome.stats.objects_sent, 0);
        assert_eq!(tip(&dest), Some(commit()));
        assert_eq!(exit_status(&status), "0");
        tool_fsck(&dest);
    }

    #[test]
    fn a_delete_of_a_present_ref_is_delete_denied() {
        let base = TmpDir::new("repo-push-delete");
        let dest = receiver(&base, RepoMode::Archive);
        let local = client(&base, &dest);
        let status = base.0.join("status");
        block_on(local.push("origin", push_opts(&status, &[BRANCH]))).unwrap();

        let delete = format!(":{BRANCH}");
        match block_on(local.push("origin", push_opts(&status, &[&delete]))) {
            Err(ostrya::Error::Push(Error::DeleteDenied(_))) => {}
            other => panic!("expected DeleteDenied, got {other:?}"),
        }
        assert_eq!(tip(&dest), Some(commit()));
        assert_ne!(exit_status(&status), "0");
        let stderr = std::fs::read_to_string(stderr_of(&status)).unwrap();
        assert!(stderr.starts_with("error: delete-denied: "), "{stderr}");
    }
}

/// `ostrya push` over the stand-in, and over ssh to localhost.
#[cfg(feature = "push")]
mod cli {
    use super::*;
    use std::process::Output;

    /// Opts in to the test that pushes over ssh to localhost, with the value
    /// `1` alone.
    const SSH_LOCALHOST: &str = "OSTRYA_TEST_SSH_LOCALHOST";

    /// A run of the built `ostrya` in `dir`, with no ssh command and no
    /// repository from the environment.
    fn ostrya(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ostrya"));
        command
            .args(args)
            .current_dir(dir)
            .env_remove("OSTRYA_SSH_COMMAND")
            .env_remove("OSTREE_REPO")
            .stdin(Stdio::null());
        for (key, value) in envs {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn stdout(out: &Output) -> String {
        String::from_utf8(out.stdout.clone()).unwrap()
    }

    fn stderr(out: &Output) -> String {
        String::from_utf8(out.stderr.clone()).unwrap()
    }

    /// The paths of one test: the base, the client repository, the stand-in
    /// script, and the status file of the stand-in.
    struct Setup {
        base: TmpDir,
        client: PathBuf,
        status: PathBuf,
        standin: PathBuf,
    }

    impl Setup {
        /// A client repository of `mode` and the stand-in script.
        fn new(tag: &str, mode: &str) -> Setup {
            let base = TmpDir::new(tag);
            let client = base.0.join("client");
            let arg = format!("--repo={}", client.display());
            let out = ostrya(&base.0, &[&arg, "init", &format!("--mode={mode}")], &[]);
            assert!(out.status.success(), "{}", stderr(&out));
            let standin = base.0.join("standin");
            std::fs::write(&standin, STANDIN).unwrap();
            let status = base.0.join("status");
            Setup {
                base,
                client,
                status,
                standin,
            }
        }

        /// `--ssh-command` of the stand-in.
        fn ssh_command(&self) -> String {
            format!(
                "--ssh-command=sh {} {} {}",
                self.standin.display(),
                self.status.display(),
                stderr_of(&self.status).display()
            )
        }

        /// Commit a tree of `files` to `branch` of the client, with `extra`
        /// options, and return the commit.
        fn commit(&self, branch: &str, files: &[(&str, &str)], extra: &[&str]) -> Checksum {
            commit_to(&self.base, &self.client, branch, files, extra)
        }

        /// Run `ostrya push` on the client with `args`.
        fn push(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
            let repo = format!("--repo={}", self.client.display());
            let mut all = vec![repo.as_str(), "push"];
            all.extend_from_slice(args);
            ostrya(&self.base.0, &all, envs)
        }

        /// Run `ostrya push` on the client over the stand-in to `dest`, with
        /// the receive command of the built binary and `policy`.
        fn push_to(&self, dest: &Path, policy: Option<&Path>, args: &[&str]) -> Output {
            let ssh = self.ssh_command();
            let receive = receive_command(policy);
            let address = address(dest);
            let mut all = vec![ssh.as_str(), receive.as_str(), address.as_str()];
            all.extend_from_slice(args);
            self.push(&all, &[])
        }

        fn ssh_started(&self) -> bool {
            self.status.exists()
        }
    }

    /// Commit a tree of `files` to `branch` of `repo` with `extra` options.
    fn commit_to(
        base: &TmpDir,
        repo: &Path,
        branch: &str,
        files: &[(&str, &str)],
        extra: &[&str],
    ) -> Checksum {
        static N: AtomicU32 = AtomicU32::new(0);
        let tree = base
            .0
            .join(format!("tree-{}", N.fetch_add(1, Ordering::Relaxed)));
        for (path, content) in files {
            let path = tree.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        std::os::unix::fs::symlink("a", tree.join("link")).unwrap();
        let arg = format!("--repo={}", repo.display());
        let branch = format!("--branch={branch}");
        let tree_arg = tree.to_str().unwrap();
        let mut all = vec![arg.as_str(), "commit", branch.as_str(), "-s", "subject"];
        all.extend_from_slice(extra);
        all.push(tree_arg);
        let out = ostrya(&base.0, &all, &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        Checksum::from_hex(stdout(&out).trim()).unwrap()
    }

    /// `--receive-command` with the built `ostrya -v receive`, and
    /// `--policy` when `policy` is set.
    fn receive_command(policy: Option<&Path>) -> String {
        let mut receive = format!(
            "--receive-command={} -v receive",
            quote(env!("CARGO_BIN_EXE_ostrya"))
        );
        if let Some(policy) = policy {
            receive.push_str(&format!(" --policy={}", quote(policy.to_str().unwrap())));
        }
        receive
    }

    fn address(dest: &Path) -> String {
        format!("ssh://localhost{}", dest.display())
    }

    fn server_tip(dest: &Path, name: &str) -> Option<Checksum> {
        block_on(async {
            let repo = Repo::open(dest).await.unwrap();
            repo.resolve_rev(name, true).await.unwrap()
        })
    }

    fn server_has_commit(dest: &Path, commit: &Checksum) -> bool {
        block_on(async {
            let repo = Repo::open(dest).await.unwrap();
            repo.has_object(ObjectType::Commit, commit).await.unwrap()
        })
    }

    /// A policy file whose default rule holds `keys`.
    fn policy(base: &TmpDir, keys: &str) -> PathBuf {
        let path = base.0.join("receive.conf");
        std::fs::write(&path, format!("[ex-ostrya receive]\n{keys}\n")).unwrap();
        path
    }

    /// The failure shape of `push`: exit 1, nothing on standard output, and
    /// standard error that starts with `prefix`.
    fn assert_failed(out: &Output, prefix: &str) {
        assert_eq!(out.status.code(), Some(1), "{}", stderr(out));
        assert_eq!(stdout(out), "");
        assert!(stderr(out).starts_with(prefix), "{}", stderr(out));
    }

    const FILES: &[(&str, &str)] = &[("a", "alpha\n"), ("dir/b", "beta\n")];

    /// Push `main` and `other:renamed` over ssh to localhost, into an
    /// `archive` receiver with `--compress` and into a `bare-user` receiver
    /// raw, and check each receiver with the tool.
    #[test]
    fn a_push_over_ssh_to_localhost_is_read_by_the_tool() {
        if std::env::var(SSH_LOCALHOST).as_deref() != Ok("1") {
            eprintln!(
                "skipped: {SSH_LOCALHOST} is not 1; set it to 1 to push over ssh to localhost"
            );
            return;
        }
        for (client_mode, mode, compress) in [
            ("archive", RepoMode::Archive, Some("--compress")),
            ("bare-user", RepoMode::BareUser, None),
        ] {
            let setup = Setup::new("ssh-localhost", client_mode);
            let main = setup.commit("main", FILES, &[]);
            // A commit bound to `other` cannot go to `renamed`.
            let other = setup.commit("other", &[("c", "gamma\n")], &["--no-bindings"]);
            let dest = receiver(&setup.base, mode);
            let known_hosts = setup.base.0.join("known_hosts");
            let ssh = format!(
                "--ssh-command=ssh -o UserKnownHostsFile={} -o StrictHostKeyChecking=accept-new \
                 -o BatchMode=yes -o LogLevel=ERROR -o ConnectTimeout=10",
                known_hosts.display()
            );
            let receive = format!(
                "--receive-command={} receive",
                quote(env!("CARGO_BIN_EXE_ostrya"))
            );
            let address = address(&dest);
            let mut args = vec![ssh.as_str(), receive.as_str()];
            args.extend(compress);
            args.extend([address.as_str(), "main", "other:renamed"]);

            let out = setup.push(&args, &[]);
            assert!(out.status.success(), "{mode:?}: {}", stderr(&out));
            assert_eq!(
                stdout(&out),
                format!("main (new) {main}\nrenamed (new) {other}\n")
            );
            assert_eq!(server_tip(&dest, "main"), Some(main));
            assert_eq!(server_tip(&dest, "renamed"), Some(other));
            tool_checks(&setup.base, &dest, &[("main", main), ("renamed", other)]);

            let out = setup.push(&args, &[]);
            assert!(out.status.success(), "{mode:?}: {}", stderr(&out));
            assert_eq!(
                stdout(&out),
                format!("main {main} (unchanged)\nrenamed {other} (unchanged)\n")
            );
        }
    }

    /// `ostree` resolves `refs` in `recv`, checks it, and pulls them into a
    /// new `archive` repository, which it also checks.
    fn tool_checks(base: &TmpDir, recv: &Path, refs: &[(&str, Checksum)]) {
        if !ostree_available() {
            return;
        }
        tool_fsck(recv);
        let tool = |args: &[&str]| {
            let out = Command::new("ostree").args(args).output().unwrap();
            assert!(
                out.status.success(),
                "ostree {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        let recv_arg = format!("--repo={}", recv.display());
        for (name, commit) in refs {
            assert_eq!(
                tool(&[&recv_arg, "rev-parse", name]).trim(),
                commit.to_hex()
            );
        }
        let copy = base.0.join("copy");
        let copy_arg = format!("--repo={}", copy.display());
        tool(&[&copy_arg, "init", "--mode=archive"]);
        let mut pull = vec![copy_arg.as_str(), "pull-local", recv.to_str().unwrap()];
        pull.extend(refs.iter().map(|(name, _)| *name));
        tool(&pull);
        for (name, commit) in refs {
            assert_eq!(
                tool(&[&copy_arg, "rev-parse", name]).trim(),
                commit.to_hex()
            );
        }
        tool_fsck(&copy);
    }

    /// A push to an address, with no remote section in the client config,
    /// writes the ref, and a repeat push reports it unchanged.
    #[test]
    fn a_repeat_push_to_an_address_reports_the_ref_unchanged() {
        let setup = Setup::new("cli-repeat", "archive");
        let config = std::fs::read_to_string(setup.client.join("config")).unwrap();
        assert!(!config.contains("[remote"), "{config}");
        let c = setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);

        let out = setup.push_to(&dest, None, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {c}\n"));
        assert_eq!(stderr(&out), "");
        assert_eq!(exit_status(&setup.status), "0");

        let out = setup.push_to(&dest, None, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main {c} (unchanged)\n"));
        assert_eq!(server_tip(&dest, "main"), Some(c));
        tool_fsck(&dest);
    }

    /// Under `--verbose`, one statistics line goes to standard error after
    /// the repository line, and standard output keeps the ref lines alone.
    #[test]
    fn a_verbose_push_writes_the_statistics_to_standard_error() {
        let setup = Setup::new("cli-verbose", "archive");
        let c = setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let out = setup.push_to(&dest, None, &["-v", "main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {c}\n"));
        let err = stderr(&out);
        let last = err.lines().last().unwrap();
        assert!(last.contains(" objects offered, "), "{err}");
        assert!(last.contains(" bytes sent in "), "{err}");
    }

    /// The server holds `D` on `C1` from another writer, and the client
    /// pushes `C2` on `C1`: the server refuses the update that is not a
    /// fast-forward, keeps `D`, and does not store `C2`.
    #[test]
    fn a_push_onto_a_moved_ref_fails_and_changes_no_ref() {
        let setup = Setup::new("cli-moved", "archive");
        let c1 = setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let out = setup.push_to(&dest, None, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        let d = commit_to(&setup.base, &dest, "main", &[("d", "delta\n")], &[]);
        let c2 = setup.commit("main", &[("e", "epsilon\n")], &[]);

        let out = setup.push_to(&dest, None, &["main"]);
        assert_failed(&out, "error: non-fast-forward: ");
        assert_eq!(server_tip(&dest, "main"), Some(d));
        assert!(server_has_commit(&dest, &c1));
        assert!(!server_has_commit(&dest, &c2));
    }

    /// `--force` expects any state of the ref. The default policy still
    /// refuses the update that is not a fast-forward, and a policy with
    /// `allow-non-fast-forward=true` takes it.
    #[test]
    fn a_forced_push_needs_a_policy_that_allows_a_non_fast_forward() {
        let setup = Setup::new("cli-force", "archive");
        setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let out = setup.push_to(&dest, None, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        let d = commit_to(&setup.base, &dest, "main", &[("d", "delta\n")], &[]);
        let c2 = setup.commit("main", &[("e", "epsilon\n")], &[]);

        let out = setup.push_to(&dest, None, &["--force", "main"]);
        assert_failed(&out, "error: non-fast-forward: ");
        assert_eq!(server_tip(&dest, "main"), Some(d));

        let policy = policy(&setup.base, "allow-non-fast-forward=true");
        let out = setup.push_to(&dest, Some(&policy), &["--force", "main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main {d} {c2}\n"));
        assert_eq!(server_tip(&dest, "main"), Some(c2));
    }

    /// With no refspec the push fails with the usage text before it starts
    /// ssh.
    #[test]
    fn a_push_with_no_refspec_fails_before_ssh_starts() {
        let setup = Setup::new("cli-norefspec", "archive");
        setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let out = setup.push_to(&dest, None, &[]);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(stdout(&out), "");
        let err = stderr(&out);
        assert!(err.starts_with("Push commits to a remote"), "{err}");
        assert!(
            err.contains("Usage: push [OPTIONS] [REMOTE] [REFSPECS]..."),
            "{err}"
        );
        assert!(err.ends_with("error: REFSPEC must be specified\n"), "{err}");
        assert!(!setup.ssh_started());
        assert_eq!(server_tip(&dest, "main"), None);
    }

    /// With no remote the push fails with the usage text before it starts
    /// ssh.
    #[test]
    fn a_push_with_no_remote_fails_before_ssh_starts() {
        let setup = Setup::new("cli-noremote", "archive");
        let ssh = setup.ssh_command();
        let out = setup.push(&[&ssh], &[]);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(stdout(&out), "");
        let err = stderr(&out);
        assert!(
            err.contains("Usage: push [OPTIONS] [REMOTE] [REFSPECS]..."),
            "{err}"
        );
        assert!(err.ends_with("error: REMOTE must be specified\n"), "{err}");
        assert!(!setup.ssh_started());
    }

    /// A depth below -1 fails before ssh starts, and `--compress` takes the
    /// levels 1 to 9 alone.
    #[test]
    fn a_depth_below_minus_one_and_a_bad_level_are_refused() {
        let setup = Setup::new("cli-refused", "archive");
        setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let out = setup.push_to(&dest, None, &["--depth=-2", "main"]);
        assert_failed(&out, "error: invalid input: depth -2 is below -1");
        assert!(!setup.ssh_started());
        for level in ["--compress=0", "--compress=10"] {
            let out = setup.push_to(&dest, None, &[level, "main"]);
            assert_eq!(out.status.code(), Some(1), "{level}");
            assert_eq!(stdout(&out), "");
            assert!(stderr(&out).contains("--compress"), "{}", stderr(&out));
            assert!(!setup.ssh_started());
        }
        let out = setup.push_to(&dest, None, &["--compress=9", "--depth=0", "main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(setup.ssh_started());
    }

    /// A ref line that standard output cannot take, here on `/dev/full`,
    /// gives the error line and exit 1. The ref of the server has moved.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_write_of_the_ref_lines_exits_one() {
        let setup = Setup::new("cli-dev-full", "archive");
        let main = setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let ssh = setup.ssh_command();
        let receive = receive_command(None);
        let address = address(&dest);
        let repo = format!("--repo={}", setup.client.display());
        let out = Command::new(env!("CARGO_BIN_EXE_ostrya"))
            .args([&repo, "push", &ssh, &receive, &address, "main"])
            .current_dir(&setup.base.0)
            .env_remove("OSTRYA_SSH_COMMAND")
            .env_remove("OSTREE_REPO")
            .stdin(Stdio::null())
            .stdout(std::fs::File::create("/dev/full").unwrap())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        let err = stderr(&out);
        assert_eq!(out.status.code(), Some(1), "{err}");
        assert!(err.starts_with("error: "), "{err}");
        assert!(err.contains("os error 28"), "{err}");
        assert_eq!(server_tip(&dest, "main"), Some(main));
    }

    /// `--ssh-command` wins over `OSTRYA_SSH_COMMAND` and over the
    /// `ssh-command` key of the remote, and `--receive-command` wins over the
    /// `receive-command` key.
    #[test]
    fn the_command_options_win_over_the_environment_and_the_remote_keys() {
        let setup = Setup::new("cli-precedence", "archive");
        let c = setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let env = [("OSTRYA_SSH_COMMAND", "/nonexistent/ssh")];

        // The environment variable reaches the push when no option is given.
        let receive = receive_command(None);
        let address = address(&dest);
        let out = setup.push(&[&receive, &address, "main"], &env);
        assert_failed(&out, "error: transport: ");
        assert!(
            stderr(&out).contains("/nonexistent/ssh"),
            "{}",
            stderr(&out)
        );
        assert!(!setup.ssh_started());

        let ssh = setup.ssh_command();
        let out = setup.push(&[&ssh, &receive, &address, "main"], &env);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {c}\n"));

        let config = setup.client.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(&format!(
            "\n[remote \"origin\"]\npush-url={address}\nssh-command=/nonexistent/ssh\n\
             receive-command=/nonexistent/receive\n"
        ));
        std::fs::write(&config, text).unwrap();
        let c2 = setup.commit("main", &[("e", "epsilon\n")], &[]);
        let out = setup.push(&[&ssh, &receive, "origin", "main"], &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main {c} {c2}\n"));
    }

    /// A delete is refused by the default policy, and a policy with
    /// `allow-delete=true` takes it. A delete of an absent ref changes
    /// nothing.
    #[test]
    fn a_delete_needs_a_policy_that_allows_it() {
        let setup = Setup::new("cli-delete", "archive");
        let c = setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let out = setup.push_to(&dest, None, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));

        let out = setup.push_to(&dest, None, &[":main"]);
        assert_failed(&out, "error: delete-denied: ");
        assert_eq!(server_tip(&dest, "main"), Some(c));

        let policy = policy(&setup.base, "allow-delete=true");
        let out = setup.push_to(&dest, Some(&policy), &[":main", ":absent"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(
            stdout(&out),
            format!("main {c} (deleted)\nabsent (absent) (unchanged)\n")
        );
        assert_eq!(server_tip(&dest, "main"), None);
    }

    /// A key that `[ex-ostrya] detached-metadata-exclude` of the client names
    /// does not reach the server, and the other keys do.
    #[test]
    fn an_excluded_detached_metadata_key_does_not_reach_the_server() {
        let setup = Setup::new("cli-exclude", "archive");
        let c = setup.commit(
            "main",
            FILES,
            &[
                "--add-detached-metadata-string=keep.me=1",
                "--add-detached-metadata-string=drop.me=2",
            ],
        );
        let config = setup.client.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("\n[ex-ostrya]\ndetached-metadata-exclude=drop.me\n");
        std::fs::write(&config, text).unwrap();
        let dest = receiver(&setup.base, RepoMode::Archive);

        let out = setup.push_to(&dest, None, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        let meta = block_on(async {
            let repo = Repo::open(&dest).await.unwrap();
            repo.read_commit_detached_metadata(&c).await.unwrap()
        })
        .expect("the server stores the detached metadata");
        let text = format!("{meta:?}");
        assert!(text.contains("keep.me"), "{text}");
        assert!(!text.contains("drop.me"), "{text}");
    }
}
