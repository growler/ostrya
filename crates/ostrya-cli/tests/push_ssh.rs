//! `PushSession::connect` and `Repo::push` over a stand-in ssh client that
//! runs the built `ostrya receive` locally, the way the remote shell of ssh
//! runs the remote command.

#![cfg(feature = "receive")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
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
fn open_file(path: &Path) -> ostrya_rt::FileReader {
    ostrya_rt::FileReader::from(std::fs::File::open(path).unwrap())
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

/// The standard output of `ostree --version`, or `None` when the tool does
/// not run. The first call runs the tool, and each later call reuses its
/// answer.
fn ostree_version() -> Option<&'static str> {
    static VERSION: OnceLock<Option<String>> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            Command::new("ostree")
                .arg("--version")
                .output()
                .ok()
                .filter(|out| out.status.success())
                .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        })
        .as_deref()
}

/// Whether the `ostree` tool can run. With `OSTRYA_REQUIRE_OSTREE` set, a
/// missing tool fails the test.
fn ostree_available() -> bool {
    let found = ostree_version().is_some();
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
            let setup = Setup::without_client(tag);
            let arg = format!("--repo={}", setup.client.display());
            let out = ostrya(
                &setup.base.0,
                &[&arg, "init", &format!("--mode={mode}")],
                &[],
            );
            assert!(out.status.success(), "{}", stderr(&out));
            setup
        }

        /// The stand-in script, and no client repository at `client`.
        fn without_client(tag: &str) -> Setup {
            let base = TmpDir::new(tag);
            let client = base.0.join("client");
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

    /// On a pipe the progress bar writes nothing: standard error carries no
    /// escape byte, and nothing at all without `--verbose`. With it, the
    /// statistics line is the last line. Standard output keeps the ref
    /// line. `TERM` names a terminal, so the pipe alone hides the bar.
    #[test]
    fn a_push_to_a_pipe_writes_no_progress() {
        let setup = Setup::new("cli-progress-pipe", "archive");
        let big = "progress\n".repeat(40_000);
        let c = setup.commit("main", &[("a", "alpha\n"), ("big", &big)], &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let ssh = setup.ssh_command();
        let receive = receive_command(None);
        let address = address(&dest);
        let run = |extra: &[&str]| {
            let mut args = vec![ssh.as_str(), receive.as_str(), address.as_str()];
            args.extend_from_slice(extra);
            setup.push(&args, &[("TERM", "xterm")])
        };

        let out = run(&["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {c}\n"));
        assert_eq!(stderr(&out), "");

        let c2 = setup.commit("main", &[("big", &big.repeat(2))], &[]);
        let out = run(&["-v", "--compress=6", "main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main {c} {c2}\n"));
        assert!(!out.stderr.contains(&0x1b), "{:?}", stderr(&out));
        let err = stderr(&out);
        let last = err.lines().last().unwrap_or_default();
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

    /// A destination of 64 lowercase hex characters, which a revision reads
    /// as a commit checksum, is an invalid refspec, refused before ssh
    /// starts.
    #[test]
    fn a_destination_of_64_lowercase_hex_characters_is_refused() {
        let setup = Setup::new("cli-hex-dst", "archive");
        setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let hex = "ab".repeat(32);
        let out = setup.push_to(&dest, None, &[&format!("main:{hex}")]);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(stdout(&out), "");
        assert_eq!(stderr(&out), format!("error: Invalid refspec {hex}\n"));
        assert!(!setup.ssh_started());
        assert!(!dest.join("refs/heads").join(&hex).exists());
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

    /// `ostrya push-tree` over the stand-in, checked against `ostree commit
    /// --no-xattrs` over the same tree.
    mod tree_cli {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        /// The timestamp of every commit of the tool and of the port here.
        const EPOCH: &str = "1700000000";

        /// ed25519 sign fixture: the base64 of the 64-byte secret key and the
        /// matching 32-byte public key.
        const ED25519_SECRET_B64: &str = "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
        const ED25519_PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

        /// A second and a third ed25519 secret key, so a run with several
        /// keys states an order.
        const ED25519_SECRET2_B64: &str = "vvLhmBcasjZ09s+tBj6bor7aXGEBSB2bM3PS9kc+MpHlZgDjxcMu3VPDpQPqYXmwzMlEJeqlpSM8+s7YLfum2g==";
        const ED25519_SECRET3_B64: &str = "tsJNF0H4IpARVGv9Iz3ROGIx2XelWthR+uCWodpT9JLfG8EF8bnmKaLLqFPCuGTdm36JKb5elhEmLCf8gz/8zQ==";

        /// The environment variable that turns the ed25519-unsupported skip
        /// into a failure.
        const REQUIRE_OSTREE_ED25519: &str = "OSTRYA_REQUIRE_OSTREE_ED25519";

        /// Whether the `ostree` tool carries its ed25519 signing engine, which
        /// `ostree --version` reports as the `sign-ed25519` feature. With
        /// [`REQUIRE_OSTREE_ED25519`] set the absence fails; without it the
        /// test skips and says so.
        fn ostree_supports_ed25519() -> bool {
            let supported = ostree_available()
                && ostree_version().is_some_and(|text| text.contains("sign-ed25519"));
            assert!(
                supported || std::env::var_os(REQUIRE_OSTREE_ED25519).is_none(),
                "{REQUIRE_OSTREE_ED25519} is set and the installed `ostree` carries no \
                 ed25519 engine, so the ed25519 cross-check tests cannot run"
            );
            if !supported {
                eprintln!("skipped: `ostree` carries no ed25519 engine");
            }
            supported
        }

        fn set_mode(path: &Path, mode: u32) {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }

        /// A tree under `base`: the file `a` at `file_mode`, the directory
        /// `dir` at `dir_mode` with the file `dir/b` at 0755, the symlink
        /// `link` to `a`, and the root at 0755.
        fn tree(base: &TmpDir, name: &str, file_mode: u32, dir_mode: u32) -> PathBuf {
            let root = base.0.join(name);
            std::fs::create_dir_all(root.join("dir")).unwrap();
            std::fs::write(root.join("a"), "alpha\n").unwrap();
            std::fs::write(root.join("dir/b"), "beta\n").unwrap();
            std::os::unix::fs::symlink("a", root.join("link")).unwrap();
            set_mode(&root.join("a"), file_mode);
            set_mode(&root.join("dir/b"), 0o755);
            set_mode(&root.join("dir"), dir_mode);
            set_mode(&root, 0o755);
            root
        }

        /// The commit of `ostree commit --no-xattrs` with `args` over `tree`,
        /// in the `archive` repository `tool-ref` under `base`, which the
        /// first call makes with `ostree init`. `None` when the tool is
        /// absent.
        fn tool_commit(base: &TmpDir, tree: &Path, args: &[&str]) -> Option<Checksum> {
            if !ostree_available() {
                return None;
            }
            let repo = base.0.join("tool-ref");
            let repo_arg = format!("--repo={}", repo.display());
            if !repo.exists() {
                let out = Command::new("ostree")
                    .args([&repo_arg, "init", "--mode=archive"])
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            let out = Command::new("ostree")
                .args([&repo_arg, "commit", "--no-xattrs"])
                .args(args)
                .arg(tree)
                .env("SOURCE_DATE_EPOCH", EPOCH)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "ostree commit {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            Some(Checksum::from_hex(String::from_utf8(out.stdout).unwrap().trim()).unwrap())
        }

        /// Run `ostrya push-tree` with `args` in the base directory, with
        /// `SOURCE_DATE_EPOCH` and `envs` set.
        fn push_tree(setup: &Setup, args: &[&str], envs: &[(&str, &str)]) -> Output {
            let mut all = vec!["push-tree"];
            all.extend_from_slice(args);
            let mut envs = envs.to_vec();
            envs.push(("SOURCE_DATE_EPOCH", EPOCH));
            ostrya(&setup.base.0, &all, &envs)
        }

        /// Run `ostrya push-tree` of `tree` over the stand-in to `dest`, with
        /// the receive command of the built binary.
        fn push_tree_to(setup: &Setup, dest: &Path, tree: &Path, args: &[&str]) -> Output {
            let ssh = setup.ssh_command();
            let receive = receive_command(None);
            let address = address(dest);
            let mut all = vec![
                ssh.as_str(),
                receive.as_str(),
                address.as_str(),
                tree.to_str().unwrap(),
            ];
            all.extend_from_slice(args);
            push_tree(setup, &all, &[])
        }

        /// The commit a successful push printed: its one line on standard
        /// output.
        fn pushed(out: &Output) -> Checksum {
            assert!(out.status.success(), "{}", stderr(out));
            let text = stdout(out);
            assert_eq!(text.lines().count(), 1, "{text}");
            assert!(text.ends_with('\n'), "{text:?}");
            Checksum::from_hex(text.trim_end()).unwrap()
        }

        /// One `-b` with a subject, a body, and metadata options in mixed
        /// order gives the commit of the tool, and a second push gives the
        /// second commit of the tool, whose parent is the first. Under `-v`
        /// the statistics line goes to standard error.
        #[test]
        fn a_tree_push_gives_the_commit_of_the_tool() {
            let setup = Setup::without_client("tree-one");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let options = [
                "-s",
                "S",
                "-m",
                "B",
                "--add-metadata=n=uint32 1",
                "--add-metadata-string=a=x",
            ];
            let mut args = vec!["-b", "main"];
            args.extend(options);

            let out = push_tree_to(&setup, &dest, &tree, &args);
            let c1 = pushed(&out);
            assert_eq!(stderr(&out), "");
            assert_eq!(server_tip(&dest, "main"), Some(c1));
            assert_eq!(exit_status(&setup.status), "0");

            args.push("-v");
            let out = push_tree_to(&setup, &dest, &tree, &args);
            let c2 = pushed(&out);
            assert_ne!(c1, c2);
            assert_eq!(server_tip(&dest, "main"), Some(c2));
            let err = stderr(&out);
            let last = err.lines().last().unwrap_or_default();
            assert!(last.contains(" objects offered, "), "{err}");
            assert!(last.contains(" bytes sent in "), "{err}");
            assert_eq!(err.lines().count(), 1, "{err}");

            let mut tool_args = vec!["-b", "main"];
            tool_args.extend(options);
            if let Some(t1) = tool_commit(&setup.base, &tree, &tool_args) {
                assert_eq!(c1, t1);
                let t2 = tool_commit(&setup.base, &tree, &tool_args).unwrap();
                assert_eq!(c2, t2);
            }
            tool_fsck(&dest);
        }

        /// On a pipe the progress bar of a tree push writes nothing:
        /// standard error carries no escape byte, and nothing at all
        /// without `--verbose`. With it, the statistics line is the last
        /// line. Standard output keeps the commit checksum. `TERM` names a
        /// terminal, so the pipe alone hides the bar.
        #[test]
        fn a_tree_push_to_a_pipe_writes_no_progress() {
            let setup = Setup::without_client("tree-progress-pipe");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            std::fs::write(tree.join("big"), "progress\n".repeat(40_000)).unwrap();
            set_mode(&tree.join("big"), 0o644);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let ssh = setup.ssh_command();
            let receive = receive_command(None);
            let address = address(&dest);
            let run = |extra: &[&str]| {
                let mut args = vec![
                    ssh.as_str(),
                    receive.as_str(),
                    address.as_str(),
                    tree.to_str().unwrap(),
                    "-b",
                    "main",
                ];
                args.extend_from_slice(extra);
                push_tree(&setup, &args, &[("TERM", "xterm")])
            };

            let out = run(&[]);
            let c1 = pushed(&out);
            assert_eq!(stderr(&out), "");
            assert_eq!(server_tip(&dest, "main"), Some(c1));

            std::fs::write(tree.join("big"), "progress\n".repeat(80_000)).unwrap();
            let out = run(&["-v", "--compress=6"]);
            let c2 = pushed(&out);
            assert_eq!(server_tip(&dest, "main"), Some(c2));
            assert!(!out.stderr.contains(&0x1b), "{:?}", stderr(&out));
            let err = stderr(&out);
            let last = err.lines().last().unwrap_or_default();
            assert!(last.contains(" objects offered, "), "{err}");
            assert!(last.contains(" bytes sent in "), "{err}");
            assert_eq!(err.lines().count(), 1, "{err}");
        }

        /// Two `-b` give the commit of `ostree commit -b R1 --bind-ref R2`,
        /// and both refs of the server take it.
        #[test]
        fn two_refs_give_the_commit_of_the_tool_with_bind_ref() {
            let setup = Setup::without_client("tree-two");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let c = pushed(&push_tree_to(
                &setup,
                &dest,
                &tree,
                &["-b", "r1", "-b", "r2"],
            ));
            assert_eq!(server_tip(&dest, "r1"), Some(c));
            assert_eq!(server_tip(&dest, "r2"), Some(c));
            if let Some(t) = tool_commit(&setup.base, &tree, &["-b", "r1", "--bind-ref", "r2"]) {
                assert_eq!(c, t);
            }
            tool_fsck(&dest);
        }

        /// `--canonical-permissions` and the owner options give the commit
        /// of the tool with the same options, over a tree whose modes the
        /// canonical rule changes.
        #[test]
        fn the_owner_and_canonical_options_give_the_commit_of_the_tool() {
            let setup = Setup::without_client("tree-owner");
            let tree = tree(&setup.base, "tree", 0o664, 0o2775);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let plain = pushed(&push_tree_to(&setup, &dest, &tree, &["-b", "plain"]));
            for (name, options) in [
                ("canonical", &["--canonical-permissions"][..]),
                ("owner", &["--owner-uid=0", "--owner-gid=0"][..]),
            ] {
                let mut args = vec!["-b", name];
                args.extend(options);
                let c = pushed(&push_tree_to(&setup, &dest, &tree, &args));
                assert_ne!(c, plain, "{name}");
                assert_eq!(server_tip(&dest, name), Some(c));
                if let Some(t) = tool_commit(&setup.base, &tree, &args) {
                    assert_eq!(c, t, "{name}");
                }
            }
            if let Some(t) = tool_commit(&setup.base, &tree, &["-b", "plain"]) {
                assert_eq!(plain, t);
            }
            tool_fsck(&dest);
        }

        /// A push signed with `--sign` verifies with the tool and with the
        /// port in the receiver, and the signature leaves the commit as an
        /// unsigned push gives it.
        #[test]
        fn a_signed_tree_push_verifies_in_the_receiver() {
            let setup = Setup::without_client("tree-sign");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let sign = format!("--sign={ED25519_SECRET_B64}");
            let c = pushed(&push_tree_to(&setup, &dest, &tree, &["-b", "main", &sign]));
            let dest_arg = format!("--repo={}", dest.display());
            let hex = c.to_hex();
            let out = ostrya(
                &setup.base.0,
                &[&dest_arg, "sign", "--verify", &hex, ED25519_PUBLIC_B64],
                &[],
            );
            assert!(out.status.success(), "{}", stderr(&out));
            assert!(stdout(&out).contains("verification OK"), "{}", stdout(&out));
            if ostree_supports_ed25519() {
                let out = Command::new("ostree")
                    .args([&dest_arg, "sign", "--verify", "--sign-type=ed25519"])
                    .args([hex.as_str(), ED25519_PUBLIC_B64])
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            let other = TmpDir::new("tree-sign-unsigned");
            let unsigned = receiver(&other, RepoMode::Archive);
            let u = pushed(&push_tree_to(&setup, &unsigned, &tree, &["-b", "main"]));
            assert_eq!(c, u);
            tool_fsck(&dest);
            tool_fsck(&unsigned);
        }

        /// A `bare-user-only` receiver refuses the owner of the walk and a
        /// mode it does not store. The owner options make a tree of 0644 and
        /// 0755 modes go in, and `--canonical-permissions` a tree of 0664.
        #[test]
        fn the_owner_and_canonical_options_make_a_push_into_bare_user_only_succeed() {
            let setup = Setup::without_client("tree-buo");
            let plain = tree(&setup.base, "plain", 0o644, 0o755);
            let wide = tree(&setup.base, "wide", 0o664, 0o775);
            let dest = receiver(&setup.base, RepoMode::BareUserOnly);
            let root = std::fs::symlink_metadata(&plain).unwrap().uid() == 0;

            let out = push_tree_to(
                &setup,
                &dest,
                &plain,
                &["-b", "x", "--canonical-permissions", "--owner-uid=1"],
            );
            assert_failed(
                &out,
                "error: Cannot specify both --canonical-permissions and non-zero --owner-uid",
            );
            assert!(!setup.ssh_started());

            if !root {
                let out = push_tree_to(&setup, &dest, &plain, &["-b", "main"]);
                assert_failed(&out, "error: mode-refused: ");
                assert_eq!(server_tip(&dest, "main"), None);
            }
            let owner = ["-b", "main", "--owner-uid=0", "--owner-gid=0"];
            let c = pushed(&push_tree_to(&setup, &dest, &plain, &owner));
            assert_eq!(server_tip(&dest, "main"), Some(c));

            let out = push_tree_to(
                &setup,
                &dest,
                &wide,
                &["-b", "wide", "--owner-uid=0", "--owner-gid=0"],
            );
            assert_failed(&out, "error: mode-refused: ");
            assert_eq!(server_tip(&dest, "wide"), None);
            let c = pushed(&push_tree_to(
                &setup,
                &dest,
                &wide,
                &["-b", "wide", "--canonical-permissions"],
            ));
            assert_eq!(server_tip(&dest, "wide"), Some(c));
            tool_fsck(&dest);
        }

        /// Given an address, the command opens no repository: a `--repo`
        /// that does not exist, a `--repo` whose config does not parse,
        /// `OSTREE_REPO` at a missing path, and a current directory that is
        /// no repository leave the push to succeed. A remote name with a
        /// `--repo` that does not exist fails on the open.
        #[test]
        fn an_address_opens_no_repository() {
            let setup = Setup::new("tree-address", "archive");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let ssh = setup.ssh_command();
            let receive = receive_command(None);
            let address = address(&dest);
            let tree_arg = tree.to_str().unwrap();
            let missing = setup.base.0.join("missing");
            let garbage = setup.base.0.join("garbage");
            std::fs::create_dir_all(garbage.join("objects")).unwrap();
            std::fs::write(garbage.join("config"), "this is [no keyfile\n").unwrap();
            let missing_arg = format!("--repo={}", missing.display());
            let garbage_arg = format!("--repo={}", garbage.display());
            let missing_env = [("OSTREE_REPO", missing.to_str().unwrap())];
            // The ref, the `--repo` option, and the environment of each case.
            type Case<'a> = (&'a str, Option<&'a str>, &'a [(&'a str, &'a str)]);
            let cases: [Case; 4] = [
                ("f1", Some(missing_arg.as_str()), &[]),
                ("f2", Some(garbage_arg.as_str()), &[]),
                ("f3", None, &missing_env),
                ("f4", None, &[]),
            ];
            for (name, repo, envs) in cases {
                let mut args: Vec<&str> = repo.into_iter().collect();
                args.extend([
                    ssh.as_str(),
                    receive.as_str(),
                    &address,
                    tree_arg,
                    "-b",
                    name,
                ]);
                let c = pushed(&push_tree(&setup, &args, envs));
                assert_eq!(server_tip(&dest, name), Some(c), "{name}");
            }

            let config = setup.client.join("config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str(&format!("\n[remote \"origin\"]\npush-url={address}\n"));
            std::fs::write(&config, text).unwrap();
            std::fs::remove_file(&setup.status).unwrap();
            let out = push_tree(
                &setup,
                &[&missing_arg, &ssh, &receive, "origin", tree_arg, "-b", "f5"],
                &[],
            );
            assert_failed(&out, "error: opening repo: ");
            assert!(!setup.ssh_started());
            assert_eq!(server_tip(&dest, "f5"), None);
            tool_fsck(&dest);
        }

        /// A remote name reads the push address and the receive command from
        /// the remote section of the repository, and `--ssh-command` gives
        /// the ssh command.
        #[test]
        fn a_configured_remote_gives_the_address_and_the_receive_command() {
            let setup = Setup::new("tree-remote", "archive");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let config = setup.client.join("config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str(&format!(
                "\n[remote \"origin\"]\npush-url={}\nreceive-command={} -v receive\n",
                address(&dest),
                quote(env!("CARGO_BIN_EXE_ostrya")),
            ));
            std::fs::write(&config, text).unwrap();
            let repo = format!("--repo={}", setup.client.display());
            let ssh = setup.ssh_command();
            let out = push_tree(
                &setup,
                &[&repo, &ssh, "origin", tree.to_str().unwrap(), "-b", "main"],
                &[],
            );
            let c = pushed(&out);
            assert_eq!(server_tip(&dest, "main"), Some(c));
            assert_eq!(exit_status(&setup.status), "0");
            tool_fsck(&dest);
        }

        /// A missing REMOTE, DIR, or `-b` fails with the usage text and the
        /// error line, in that order, before ssh starts. A missing DIR wins
        /// over a missing `-b`, and each wins over a `--repo` that does not
        /// open.
        #[test]
        fn a_missing_operand_fails_with_the_usage_text() {
            let setup = Setup::without_client("tree-operands");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let ssh = setup.ssh_command();
            let address = address(&dest);
            let tree_arg = tree.to_str().unwrap();
            let missing_repo = format!("--repo={}", setup.base.0.join("missing").display());
            for (args, message) in [
                (vec![ssh.as_str(), "-b", "main"], "REMOTE must be specified"),
                (
                    vec![ssh.as_str(), &address, "-b", "main"],
                    "DIR must be specified",
                ),
                (
                    vec![ssh.as_str(), &address, tree_arg],
                    "A branch must be specified with --branch",
                ),
                (vec![ssh.as_str(), &address], "DIR must be specified"),
                (
                    vec![&missing_repo, ssh.as_str(), "origin", "-b", "main"],
                    "DIR must be specified",
                ),
                (
                    vec![&missing_repo, ssh.as_str(), "origin", tree_arg],
                    "A branch must be specified with --branch",
                ),
            ] {
                let out = push_tree(&setup, &args, &[]);
                assert_eq!(out.status.code(), Some(1), "{message}");
                assert_eq!(stdout(&out), "");
                let err = stderr(&out);
                assert!(err.contains("Usage: push-tree [OPTIONS]"), "{err}");
                assert!(err.ends_with(&format!("\nerror: {message}\n")), "{err}");
                assert!(!setup.ssh_started());
            }
            assert_eq!(server_tip(&dest, "main"), None);
        }

        /// Each refused option fails with exit 1 and nothing on standard
        /// output, before ssh starts, and sets no ref. Each case gives a DIR
        /// that does not exist, so the refusal comes before the scan.
        #[test]
        fn a_refused_option_fails_before_ssh_starts() {
            let setup = Setup::without_client("tree-refused");
            let dest = receiver(&setup.base, RepoMode::Archive);
            let upper = format!("--parent={}", "AB".repeat(32));
            let hex = "ab".repeat(32);
            let missing = setup.base.0.join("missing");
            let cases: Vec<(Vec<&str>, &str)> = vec![
                (vec!["--parent=abc"], "Invalid --parent 'abc'"),
                (vec![upper.as_str()], "Invalid --parent 'ABAB"),
                (vec!["--timestamp=bogus"], "Could not parse 'bogus'"),
                (vec!["--add-metadata-string=noeq"], "Missing '='"),
                (vec!["--add-metadata=k=@@"], "Parsing k=@@: "),
                (vec!["--add-metadata-string==v"], "Empty metadata key"),
                (
                    vec!["--add-detached-metadata-string==v"],
                    "Empty metadata key",
                ),
                (vec!["--sign=short"], "Invalid ed25519 secret key"),
                (
                    vec!["--sign-type=dummy", "--sign=X"],
                    "dummy signature type is only for ostree testing",
                ),
                (vec!["--compress=0"], "--compress"),
                (vec!["-b", "main"], "named twice"),
                (vec!["-b", "main^"], "Invalid refspec main^"),
                (vec!["-b", "origin:main"], "holds ':'"),
                (vec!["-b", hex.as_str()], "looks like a checksum"),
                (vec!["--owner-uid=abc"], "Cannot parse integer value"),
            ];
            for (options, needle) in cases {
                let mut args = vec!["-b", "main"];
                args.extend(options.iter());
                let out = push_tree_to(&setup, &dest, &missing, &args);
                assert_eq!(out.status.code(), Some(1), "{options:?}: {}", stderr(&out));
                assert_eq!(stdout(&out), "", "{options:?}");
                assert!(
                    stderr(&out).contains(needle),
                    "{options:?}: {}",
                    stderr(&out)
                );
                assert!(!setup.ssh_started(), "{options:?}");
            }
            let out = push_tree_to(&setup, &dest, &missing, &["-b", "main"]);
            assert_failed(&out, "error: ");
            assert!(stderr(&out).contains("missing"), "{}", stderr(&out));
            assert!(!setup.ssh_started());
            assert_eq!(server_tip(&dest, "main"), None);
        }

        /// `--body-file` alone and beside `-m`, `--parent=none`,
        /// `--no-bindings`, an explicit `--timestamp`, and `--parent` with
        /// a commit of the server each give the commit of the tool with the
        /// same options.
        #[test]
        fn the_commit_options_give_the_commit_of_the_tool() {
            let setup = Setup::without_client("tree-options");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let body = setup.base.0.join("body.txt");
            std::fs::write(&body, "file body\n").unwrap();
            let body_file = format!("--body-file={}", body.display());
            let first = pushed(&push_tree_to(&setup, &dest, &tree, &["-b", "first"]));
            let parent = format!("--parent={first}");
            let cases: [&[&str]; 4] = [
                &["-b", "body", &body_file, "--parent=none"],
                &["-b", "both", "-m", "inline", &body_file, "--no-bindings"],
                &["-b", "stamp", "--timestamp=@1600000000"],
                &["-b", "child", &parent],
            ];
            let mut commits = Vec::new();
            for args in cases {
                let c = pushed(&push_tree_to(&setup, &dest, &tree, args));
                assert_eq!(server_tip(&dest, args[1]), Some(c), "{args:?}");
                commits.push(c);
            }
            if let Some(t) = tool_commit(&setup.base, &tree, &["-b", "first"]) {
                assert_eq!(first, t);
                for (args, c) in cases.iter().zip(&commits) {
                    assert_eq!(tool_commit(&setup.base, &tree, args), Some(*c), "{args:?}");
                }
            }
            tool_fsck(&dest);
        }

        /// The `.commitmeta` bytes of `commit` in the `archive` repository
        /// `repo`.
        fn commitmeta(repo: &Path, commit: &Checksum) -> Vec<u8> {
            let hex = commit.to_hex();
            let path = repo
                .join("objects")
                .join(&hex[..2])
                .join(format!("{}.commitmeta", &hex[2..]));
            std::fs::read(path).unwrap()
        }

        /// Detached metadata, two `--sign` keys, and a `--sign-from-file`
        /// key give the detached entry, then the three signatures in the
        /// order of `commit`, and the `.commitmeta` bytes and the commit of
        /// the tool with the same options.
        #[test]
        fn detached_metadata_and_signers_give_the_commitmeta_of_the_tool() {
            let setup = Setup::without_client("tree-detached");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let key_file = setup.base.0.join("key.txt");
            std::fs::write(&key_file, format!("{ED25519_SECRET3_B64}\n")).unwrap();
            let from_file = format!("--sign-from-file={}", key_file.display());
            let second = format!("--sign={ED25519_SECRET2_B64}");
            let first = format!("--sign={ED25519_SECRET_B64}");
            // The file key comes first on the command line and signs last.
            // The receiver keeps one copy of a signature given twice, so the
            // three keys are distinct.
            let args = [
                "-b",
                "main",
                &from_file,
                "--add-detached-metadata-string=k=v",
                &second,
                &first,
            ];
            let c = pushed(&push_tree_to(&setup, &dest, &tree, &args));
            let bytes = commitmeta(&dest, &c);
            let dict = ostrya::from_bytes(&ostrya::Type::parse("a{sv}").unwrap(), &bytes).unwrap();
            let keys: Vec<&str> = dict
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry.as_tuple().unwrap()[0].as_str().unwrap())
                .collect();
            assert_eq!(keys, ["k", "ostree.sign.ed25519"]);
            let (_, signatures) = dict
                .dict_get("ostree.sign.ed25519")
                .and_then(Value::as_variant)
                .unwrap();
            assert_eq!(signatures.as_array().unwrap().len(), 3);
            if ostree_supports_ed25519()
                && let Some(t) = tool_commit(&setup.base, &tree, &args)
            {
                assert_eq!(c, t);
                assert_eq!(bytes, commitmeta(&setup.base.0.join("tool-ref"), &t));
            }
            tool_fsck(&dest);
        }

        /// Under `--sign-type=gpg`, a `--sign` key and a `--sign-from-file`
        /// key that name no secret key in the GnuPG home directory are
        /// refused before the scan and before ssh starts, with the words of
        /// `--gpg-sign`.
        #[cfg(feature = "gpg")]
        #[test]
        fn a_gpg_key_with_no_secret_key_fails_before_ssh_starts() {
            if !gpg_available() {
                return;
            }
            let setup = Setup::without_client("tree-gpg");
            let dest = receiver(&setup.base, RepoMode::Archive);
            let missing = setup.base.0.join("missing");
            let home = EmptyGpgHome::new(&setup.base);
            let homedir = format!("--gpg-homedir={}", home.0.display());
            let key_file = setup.base.0.join("key.txt");
            std::fs::write(&key_file, "DEADBEEFDEADBEEF\n").unwrap();
            let from_file = format!("--sign-from-file={}", key_file.display());
            let message = format!(
                "error: No gpg key found with ID DEADBEEFDEADBEEF (homedir: {})\n",
                home.0.display()
            );
            for key in ["--sign=DEADBEEFDEADBEEF", from_file.as_str()] {
                let args = ["-b", "main", "--sign-type=gpg", key, homedir.as_str()];
                let out = push_tree_to(&setup, &dest, &missing, &args);
                assert_failed(&out, &message);
                assert_eq!(stderr(&out), message);
                assert!(!setup.ssh_started(), "{key}");
            }
            assert_eq!(server_tip(&dest, "main"), None);
        }

        /// Whether the gpg binary runs. With `OSTRYA_REQUIRE_GNUPG` set, a
        /// missing binary fails the test.
        #[cfg(feature = "gpg")]
        fn gpg_available() -> bool {
            const REQUIRE_GNUPG: &str = "OSTRYA_REQUIRE_GNUPG";
            let found = Command::new("gpg")
                .arg("--version")
                .output()
                .is_ok_and(|out| out.status.success());
            assert!(
                found || std::env::var_os(REQUIRE_GNUPG).is_none(),
                "{REQUIRE_GNUPG} is set and `gpg` is not available"
            );
            if !found {
                eprintln!("skipped: `gpg` is not available");
            }
            found
        }

        /// An empty GnuPG home directory. The drop stops the GnuPG daemons
        /// of the directory and removes their socket directory.
        #[cfg(feature = "gpg")]
        struct EmptyGpgHome(PathBuf);

        #[cfg(feature = "gpg")]
        impl EmptyGpgHome {
            fn new(base: &TmpDir) -> EmptyGpgHome {
                let dir = base.0.join("gnupghome");
                std::fs::create_dir(&dir).unwrap();
                set_mode(&dir, 0o700);
                EmptyGpgHome(dir)
            }
        }

        #[cfg(feature = "gpg")]
        impl Drop for EmptyGpgHome {
            fn drop(&mut self) {
                for action in [&["--kill", "all"][..], &["--remove-socketdir"][..]] {
                    let _ = Command::new("gpgconf")
                        .arg("--homedir")
                        .arg(&self.0)
                        .args(action)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            }
        }
    }
}
