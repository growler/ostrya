//! `PushSession::connect` and `Repo::push` over a stand-in ssh client that
//! runs the built `ostrya receive` locally, the way the remote shell of ssh
//! runs the remote command.

#![cfg(feature = "receive")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ostrya::remote::{
    BoxFuture, Compression, Encoding, Endpoint, Error, Expected, ObjectData, ObjectSource,
    PushOutcome, PushSession, RefUpdate, SessionOptions, SshAddress, SshOptions,
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

/// The client name of each push, and of the client group that [`receiver`]
/// writes.
const CLIENT: &str = "pusher";

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
    ) -> BoxFuture<'a, ostrya::remote::Result<Vec<ObjectName>>> {
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
    ) -> BoxFuture<'a, ostrya::remote::Result<ObjectData>> {
        Box::pin(async move { self.load(name, encoding).await.map_err(source_error) })
    }

    fn detached_metadata<'a>(
        &'a self,
        _commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya::remote::Result<Option<Value>>> {
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
    ) -> BoxFuture<'a, ostrya::remote::Result<Vec<ObjectName>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn open<'a>(
        &'a self,
        name: &'a ObjectName,
        _encoding: Encoding,
    ) -> BoxFuture<'a, ostrya::remote::Result<ObjectData>> {
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
    ) -> BoxFuture<'a, ostrya::remote::Result<Option<Value>>> {
        Box::pin(async { Ok(None) })
    }
}

/// A receiving repository of `mode` at a path that holds a `'` and a space.
/// Its config has the client group of [`CLIENT`], which writes each ref as a
/// fast-forward and makes a server commit on each ref.
fn receiver(base: &TmpDir, mode: RepoMode) -> PathBuf {
    let path = base.0.join("it's a repo");
    block_on(Repo::create(&path, CreateOptions::new(mode))).unwrap();
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!(
        "[ex-ostrya client \"{CLIENT}\"]\nauth=ssh:{CLIENT}\nallow=wc:**\n"
    ));
    std::fs::write(&config, text).unwrap();
    path
}

/// The options that run `ostrya -v receive --client=CLIENT` through the
/// stand-in, with the client name `client`, the exit status of the command
/// written to `status`, and its standard error written to the file beside it
/// that [`stderr_of`] names.
fn options_as(status: &Path, client: &str) -> SshOptions {
    let receive = format!(
        "{} -v receive --client={}",
        quote(env!("CARGO_BIN_EXE_ostrya")),
        quote(client)
    );
    SshOptions {
        command: Some(standin(status)),
        remote_command: Some(receive),
        ..Default::default()
    }
}

/// The command line of the stand-in, which writes the exit status of the
/// command to `status`.
fn standin(status: &Path) -> Vec<String> {
    vec![
        "sh".into(),
        "-c".into(),
        STANDIN.into(),
        "ssh".into(),
        status.to_str().unwrap().into(),
        stderr_of(status).to_str().unwrap().into(),
    ]
}

fn stderr_of(status: &Path) -> PathBuf {
    status.with_extension("stderr")
}

/// The endpoint of `dest` with the options of [`options_as`] for [`CLIENT`].
fn endpoint(dest: &Path, status: &Path) -> Endpoint {
    endpoint_as(dest, status, CLIENT)
}

/// The endpoint of `dest` with the options of [`options_as`].
fn endpoint_as(dest: &Path, status: &Path, client: &str) -> Endpoint {
    Endpoint::Ssh {
        address: SshAddress::parse(&format!("ssh://localhost{}", dest.display())).unwrap(),
        options: options_as(status, client),
    }
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
    compression: Compression,
) -> ostrya::remote::Result<PushOutcome> {
    push_as(dest, status, compression, CLIENT)
}

/// [`push`] with the client name `client`.
fn push_as(
    dest: &Path,
    status: &Path,
    compression: Compression,
    client: &str,
) -> ostrya::remote::Result<PushOutcome> {
    let source = FixtureSource::new();
    block_on(async {
        let session = PushSession::connect(
            endpoint_as(dest, status, client),
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

/// The standard output of `ostree --version`, or `None` if the `ostree`
/// command does not run. The first call runs `ostree`, and each later call
/// reuses its answer.
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

/// Returns `true` if the `ostree` command can run. If `OSTRYA_REQUIRE_OSTREE`
/// is set, a missing `ostree` fails the test.
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

/// If the `ostree` command is installed, checks that `ostree fsck` passes on
/// `repo`.
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
        let outcome = push(&dest, &status, compression).unwrap();
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

/// A client name that no `ssh:` item of a group of the local refs names
/// opens no push session. `Hello` gets `ref-denied`, the command exits 1
/// with one error line, and the ref stays absent. A group of a collection
/// does not count, and neither does an `anonymous` or a `net:` item.
#[test]
fn receive_refuses_a_name_with_no_group_with_ref_denied() {
    let base = TmpDir::new("refused");
    let dest = receiver(&base, RepoMode::Archive);
    let config = dest.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(
        "[ex-ostrya client \"mirror\"]\nauth=ssh:other\ncollection=*\nallow=w:**\n\
         [ex-ostrya client \"anyone\"]\nauth=anonymous;net:0.0.0.0/0;net:::/0\nallow=w:**\n",
    );
    std::fs::write(&config, text).unwrap();
    let status = base.0.join("status");
    match push_as(&dest, &status, Compression::None, "other") {
        Err(Error::RefDenied(message)) => {
            assert!(
                message.contains("no client group of the session covers the local refs"),
                "{message}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(tip(&dest), None);
    assert_eq!(exit_status(&status), "1");
    let stderr = std::fs::read_to_string(stderr_of(&status)).unwrap();
    assert!(stderr.starts_with("error: ref-denied: "), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
}

/// `ostrya receive` and `ostrya send` need a client name: `--client`, else
/// `LOGNAME`. With neither, or with an empty `LOGNAME`, each command writes
/// one error line and exits 1 before it reads its input.
#[test]
fn a_session_with_no_client_name_is_refused() {
    let base = TmpDir::new("noname");
    let dest = receiver(&base, RepoMode::Archive);
    for command in ["receive", "send"] {
        for logname in [None, Some("")] {
            let mut run = Command::new(env!("CARGO_BIN_EXE_ostrya"));
            run.arg(format!("--repo={}", dest.display()))
                .arg(command)
                .env_remove("LOGNAME")
                .stdin(Stdio::null());
            if let Some(value) = logname {
                run.env("LOGNAME", value);
            }
            let out = run.output().unwrap();
            assert_eq!(out.status.code(), Some(1), "{command} {logname:?}");
            assert!(out.stdout.is_empty());
            assert_eq!(
                String::from_utf8_lossy(&out.stderr),
                format!("error: {command} needs a client name: give --client, or set LOGNAME\n")
            );
        }
    }
}

/// A name that an `ssh:` item cannot hold ends `ostrya receive` and
/// `ostrya send` with one error line and exit 1, before they read their
/// input. The line shows the name in escaped form, also a name with a line
/// feed.
#[test]
fn a_malformed_client_name_is_refused() {
    let base = TmpDir::new("badname");
    let dest = receiver(&base, RepoMode::Archive);
    for (logname, args) in [(Some("a\nb"), &[][..]), (None, &["--client= x"][..])] {
        for command in ["receive", "send"] {
            let mut run = Command::new(env!("CARGO_BIN_EXE_ostrya"));
            run.arg(format!("--repo={}", dest.display()))
                .arg(command)
                .args(args)
                .env_remove("LOGNAME")
                .stdin(Stdio::null());
            if let Some(value) = logname {
                run.env("LOGNAME", value);
            }
            let out = run.output().unwrap();
            assert!(out.stdout.is_empty(), "{command} {logname:?}");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(1), "{command} {logname:?}");
            assert!(
                stderr.starts_with("error: malformed client name \""),
                "{command}: {stderr}"
            );
            assert_eq!(stderr.lines().count(), 1, "{command}: {stderr}");
        }
    }
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
            endpoint(&dest, &status),
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

/// `ostrya receive` takes no `--policy`.
#[test]
fn receive_takes_no_policy_option() {
    let base = TmpDir::new("nopolicy");
    let dest = receiver(&base, RepoMode::Archive);
    let out = Command::new(env!("CARGO_BIN_EXE_ostrya"))
        .arg(format!("--repo={}", dest.display()))
        .arg("receive")
        .arg(format!("--policy={}", base.0.join("rules").display()))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--policy"), "{stderr}");
}

/// `ostrya receive` reads the client groups at start. A group of the removed
/// receive policy, a bad client group, and a key group whose key it cannot
/// read end the command with status 1 before it reads its input.
#[test]
fn receive_refuses_a_bad_group_at_start() {
    for (groups, needle) in [
        (
            "[ex-ostrya receive]\naccept=true\n",
            "[ex-ostrya client \"NAME\"]",
        ),
        (
            "[ex-ostrya client \"c\"]\nauth=ssh:c\nowner=x\n",
            "unknown key 'owner'",
        ),
        (
            "[ex-ostrya key \"k\"]\ntype=ed25519\nsecret-key-file=/nonexistent/ostrya/k\n",
            "/nonexistent/ostrya/k",
        ),
    ] {
        let base = TmpDir::new("badgroup");
        let dest = receiver(&base, RepoMode::Archive);
        let config = dest.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(groups);
        std::fs::write(&config, text).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ostrya"))
            .arg(format!("--repo={}", dest.display()))
            .arg("receive")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{groups:?}");
        assert!(out.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.starts_with("error: "), "{stderr}");
        assert!(stderr.contains(needle), "{groups:?}: {stderr}");
    }
}

/// `Repo::push` to a remote of the local config, over the stand-in.
#[cfg(feature = "push")]
mod repo_push {
    use super::*;
    use ostrya::endpoint::{EndpointOverrides, resolve_push};
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
            "\n[remote \"origin\"]\npush-url=ssh://localhost{}\n\
             receive-command={} -v receive --client={CLIENT}\n",
            dest.display(),
            quote(env!("CARGO_BIN_EXE_ostrya")),
        ));
        std::fs::write(&config, text).unwrap();
        block_on(Repo::open(&path)).unwrap()
    }

    /// The endpoint of the remote `origin` of `local`, with the stand-in as
    /// the ssh command and the receive command left to the remote section.
    fn origin(local: &Repo, status: &Path) -> Endpoint {
        let overrides = EndpointOverrides {
            ssh_command: Some(standin(status)),
            ..EndpointOverrides::default()
        };
        block_on(resolve_push(Some(local.config()), "origin", overrides)).unwrap()
    }

    /// The options of a push of `refspecs`.
    fn push_opts(refspecs: &[&str]) -> RepoPushOptions {
        RepoPushOptions {
            refspecs: refspecs.iter().map(|s| (*s).to_owned()).collect(),
            compression: Compression::Deflate { level: 6 },
            ..RepoPushOptions::default()
        }
    }

    #[test]
    fn a_push_to_a_configured_remote_writes_the_ref() {
        let base = TmpDir::new("repo-push");
        let dest = receiver(&base, RepoMode::Archive);
        let local = client(&base, &dest);
        let status = base.0.join("status");

        let outcome = block_on(local.push(origin(&local, &status), push_opts(&[BRANCH]))).unwrap();
        assert_eq!(outcome.refs.len(), 1);
        assert_eq!(outcome.refs[0].old, None);
        assert_eq!(outcome.refs[0].new, Some(commit()));
        assert!(outcome.stats.objects_sent > 0);
        assert_eq!(tip(&dest), Some(commit()));
        assert_eq!(exit_status(&status), "0");

        // A repeat push finds every object on the server and sends none.
        let outcome = block_on(local.push(origin(&local, &status), push_opts(&[BRANCH]))).unwrap();
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
        block_on(local.push(origin(&local, &status), push_opts(&[BRANCH]))).unwrap();

        let delete = format!(":{BRANCH}");
        match block_on(local.push(origin(&local, &status), push_opts(&[&delete]))) {
            Err(ostrya::Error::Remote(Error::DeleteDenied(_))) => {}
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
    /// repository from the environment, and with `LOGNAME` set to [`CLIENT`].
    /// The stand-in passes `LOGNAME` on to `ostrya receive`.
    fn ostrya(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ostrya"));
        command
            .args(args)
            .current_dir(dir)
            .env_remove("OSTRYA_SSH_COMMAND")
            .env_remove("OSTREE_REPO")
            .env("LOGNAME", CLIENT)
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
        /// the receive command of the built binary.
        fn push_to(&self, dest: &Path, args: &[&str]) -> Output {
            let ssh = self.ssh_command();
            let receive = receive_command();
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

    /// `--receive-command` with the built `ostrya -v receive`.
    fn receive_command() -> String {
        format!(
            "--receive-command={} -v receive",
            quote(env!("CARGO_BIN_EXE_ostrya"))
        )
    }

    /// Writes the client group of [`CLIENT`] with the allow list `allow` into
    /// the config of `dest`, in place of the group of an earlier call.
    fn client_group(dest: &Path, allow: &str) {
        let config = dest.join("config");
        let text = std::fs::read_to_string(&config).unwrap();
        let header = format!("[ex-ostrya client \"{CLIENT}\"]\n");
        let mut text = match text.find(&header) {
            Some(i) => text[..i].to_owned(),
            None => text,
        };
        text.push_str(&format!("{header}auth=ssh:{CLIENT}\nallow={allow}\n"));
        std::fs::write(&config, text).unwrap();
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
    /// raw, and check each receiver with the `ostree` command.
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
            // sshd sets `LOGNAME` to the name of the user, so the receive
            // command names the client.
            let receive = format!(
                "--receive-command={} receive --client={CLIENT}",
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

    /// The `ostree` command resolves `refs` in `recv`, checks it, and pulls
    /// them into a new `archive` repository, which it also checks.
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

        let out = setup.push_to(&dest, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {c}\n"));
        assert_eq!(stderr(&out), "");
        assert_eq!(exit_status(&setup.status), "0");

        let out = setup.push_to(&dest, &["main"]);
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
        let out = setup.push_to(&dest, &["-v", "main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {c}\n"));
        let err = stderr(&out);
        let last = err.lines().last().unwrap();
        assert!(last.contains(" objects offered, "), "{err}");
        assert!(last.contains(" bytes sent in "), "{err}");
    }

    /// On a pipe, the progress bar writes nothing: standard error carries no
    /// escape byte. Without `--verbose`, standard error carries nothing at
    /// all. With it, the statistics line is the last line. Standard output
    /// keeps the ref line. `TERM` names a terminal, so the pipe alone hides
    /// the bar.
    #[test]
    fn a_push_to_a_pipe_writes_no_progress() {
        let setup = Setup::new("cli-progress-pipe", "archive");
        let big = "progress\n".repeat(40_000);
        let c = setup.commit("main", &[("a", "alpha\n"), ("big", &big)], &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let ssh = setup.ssh_command();
        let receive = receive_command();
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
        let out = setup.push_to(&dest, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        let d = commit_to(&setup.base, &dest, "main", &[("d", "delta\n")], &[]);
        let c2 = setup.commit("main", &[("e", "epsilon\n")], &[]);

        let out = setup.push_to(&dest, &["main"]);
        assert_failed(&out, "error: non-fast-forward: ");
        assert_eq!(server_tip(&dest, "main"), Some(d));
        assert!(server_has_commit(&dest, &c1));
        assert!(!server_has_commit(&dest, &c2));
    }

    /// `--force` expects any state of the ref. A client group with `w` and no
    /// `d` still refuses the update that is not a fast-forward, and a group
    /// with `wd` takes it.
    #[test]
    fn a_forced_push_needs_a_group_with_w_and_d() {
        let setup = Setup::new("cli-force", "archive");
        setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        client_group(&dest, "w:**");
        let out = setup.push_to(&dest, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        let d = commit_to(&setup.base, &dest, "main", &[("d", "delta\n")], &[]);
        let c2 = setup.commit("main", &[("e", "epsilon\n")], &[]);

        let out = setup.push_to(&dest, &["--force", "main"]);
        assert_failed(&out, "error: non-fast-forward: ");
        assert_eq!(server_tip(&dest, "main"), Some(d));

        client_group(&dest, "wd:**");
        let out = setup.push_to(&dest, &["--force", "main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main {d} {c2}\n"));
        assert_eq!(server_tip(&dest, "main"), Some(c2));
    }

    /// Sets `[core] collection-id` of the repository at `repo` to `id`, or
    /// removes it for `None`. `ostrya commit` binds each commit to that id.
    fn set_collection_id(repo: &Path, id: Option<&str>) {
        let config = repo.join("config");
        let text = std::fs::read_to_string(&config).unwrap();
        let mut text: String = text
            .lines()
            .filter(|line| !line.starts_with("collection-id="))
            .map(|line| format!("{line}\n"))
            .collect();
        if let Some(id) = id {
            text = text.replacen("[core]\n", &format!("[core]\ncollection-id={id}\n"), 1);
        }
        std::fs::write(&config, text).unwrap();
    }

    /// Appends the client group `name` of [`CLIENT`] in the collection scope
    /// `collection`, with the allow list `allow`, to the config of `dest`.
    fn collection_group(dest: &Path, name: &str, collection: &str, allow: &str) {
        let config = dest.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(&format!(
            "[ex-ostrya client \"{name}\"]\nauth=ssh:{CLIENT}\ncollection={collection}\n\
             allow={allow}\n"
        ));
        std::fs::write(&config, text).unwrap();
    }

    /// The lines of `ostree refs -c` of `repo`, or `None` if the `ostree`
    /// command is not installed.
    fn tool_collection_refs(repo: &Path) -> Option<Vec<String>> {
        if !ostree_available() {
            return None;
        }
        let out = Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .args(["refs", "-c"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "ostree refs -c: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Some(
            String::from_utf8(out.stdout)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect(),
        )
    }

    /// A commit bound to a collection that the server does not own goes to
    /// `refs/mirrors/ID/` of the server, and `refs/heads/` stays empty. On a
    /// server that owns the collection, the same commit goes to its local
    /// refs. The `ostree` command lists both refs as `(ID, main)` and checks
    /// both repositories.
    #[test]
    fn a_collection_push_writes_the_refs_of_the_collection() {
        let setup = Setup::new("cli-collection", "archive");
        set_collection_id(&setup.client, Some("org.example.Os"));
        let c = setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        collection_group(&dest, "os", "org.example.Os", "w:**");
        let out = setup.push_to(&dest, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {c}\n"));
        assert_eq!(
            std::fs::read_to_string(dest.join("refs/mirrors/org.example.Os/main")).unwrap(),
            format!("{c}\n")
        );
        assert_eq!(server_tip(&dest, "main"), None);

        let own_base = TmpDir::new("cli-collection-own");
        let own = receiver(&own_base, RepoMode::Archive);
        set_collection_id(&own, Some("org.example.Os"));
        let out = setup.push_to(&own, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(server_tip(&own, "main"), Some(c));
        assert!(!own.join("refs/mirrors/org.example.Os").exists());

        for repo in [&dest, &own] {
            if let Some(lines) = tool_collection_refs(repo) {
                assert_eq!(lines, vec!["(org.example.Os, main)".to_owned()], "{repo:?}");
            }
            tool_fsck(repo);
        }
    }

    /// Commits with different bindings, a `--collection` that differs from
    /// the binding, and a `--collection` that fails the collection-id rule
    /// or is longer than 255 bytes are refused before ssh starts.
    #[test]
    fn disagreeing_collections_are_refused_before_ssh_starts() {
        let setup = Setup::new("cli-collection-mixed", "archive");
        set_collection_id(&setup.client, Some("org.example.A"));
        setup.commit("os-a", FILES, &[]);
        set_collection_id(&setup.client, Some("org.example.B"));
        setup.commit("os-b", FILES, &[]);
        set_collection_id(&setup.client, None);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let long = format!("org.{}", "a".repeat(252));
        let long_arg = format!("--collection={long}");
        let long_error = format!("error: Invalid collection ID {long}\n");
        for (args, prefix) in [
            (&["os-a", "os-b"][..], "error: binding-mismatch: "),
            (
                &["--collection=org.example.B", "os-a"],
                "error: binding-mismatch: ",
            ),
            (
                &["--collection=no-dot", "os-a"],
                "error: Invalid collection ID no-dot\n",
            ),
            (&[long_arg.as_str(), "os-a"], long_error.as_str()),
        ] {
            let out = setup.push_to(&dest, args);
            assert_failed(&out, prefix);
            assert!(!setup.ssh_started(), "{args:?}");
        }
        assert!(!dest.join("refs/mirrors").join("org.example.A").exists());
    }

    /// A collection that no group of the client covers gets `ref-denied`
    /// from `ostrya receive`. A group that names the collection wins over a
    /// group with `collection=*`.
    #[test]
    fn the_group_of_the_collection_decides_the_push() {
        let setup = Setup::new("cli-collection-groups", "archive");
        set_collection_id(&setup.client, Some("org.example.Os"));
        let c = setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let out = setup.push_to(&dest, &["main"]);
        assert_failed(&out, "error: ref-denied: ");
        let receive = std::fs::read_to_string(stderr_of(&setup.status)).unwrap();
        assert!(receive.starts_with("error: ref-denied: "), "{receive}");
        assert!(
            receive.contains("the collection 'org.example.Os'"),
            "{receive}"
        );

        // The group of `*` gives no right on `main`.
        collection_group(&dest, "all", "*", "w:other");
        let out = setup.push_to(&dest, &["main"]);
        assert_failed(&out, "error: ref-denied: ");
        collection_group(&dest, "os", "org.example.Os", "w:**");
        let out = setup.push_to(&dest, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {c}\n"));
    }

    /// `--tag` creates the tag at the pushed commit, and its line follows
    /// the line of the refspec. A repeat push of the tag is `ref-mismatch`.
    #[test]
    fn a_tag_is_created_once() {
        let setup = Setup::new("cli-tag", "archive");
        let c = setup.commit("main", FILES, &["--bind-ref=v1"]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        client_group(&dest, "w:main;t:v1");
        let out = setup.push_to(&dest, &["--tag=v1", "main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {c}\nv1 (new) {c}\n"));
        assert_eq!(server_tip(&dest, "v1"), Some(c));
        let out = setup.push_to(&dest, &["--tag=v1", "main"]);
        assert_failed(&out, "error: ref-mismatch: ");
        assert_eq!(server_tip(&dest, "v1"), Some(c));
    }

    /// With no refspec the push fails with the usage text before it starts
    /// ssh.
    #[test]
    fn a_push_with_no_refspec_fails_before_ssh_starts() {
        let setup = Setup::new("cli-norefspec", "archive");
        setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let out = setup.push_to(&dest, &[]);
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

    /// A depth less than -1 fails before ssh starts, and `--compress` takes
    /// the levels 1 to 9 alone.
    #[test]
    fn a_depth_below_minus_one_and_a_bad_level_are_refused() {
        let setup = Setup::new("cli-refused", "archive");
        setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let out = setup.push_to(&dest, &["--depth=-2", "main"]);
        assert_failed(&out, "error: invalid input: depth -2 is below -1");
        assert!(!setup.ssh_started());
        for level in ["--compress=0", "--compress=10"] {
            let out = setup.push_to(&dest, &[level, "main"]);
            assert_eq!(out.status.code(), Some(1), "{level}");
            assert_eq!(stdout(&out), "");
            assert!(stderr(&out).contains("--compress"), "{}", stderr(&out));
            assert!(!setup.ssh_started());
        }
    }

    /// A push with level 9 and depth 0 starts ssh and succeeds.
    #[test]
    fn a_level_of_nine_and_a_depth_of_zero_push() {
        let setup = Setup::new("cli-level-nine", "archive");
        setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let out = setup.push_to(&dest, &["--compress=9", "--depth=0", "main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(setup.ssh_started());
    }

    /// A destination of 64 lowercase hex characters is an invalid refspec,
    /// because a revision reads it as a commit checksum. The push refuses it
    /// before ssh starts.
    #[test]
    fn a_destination_of_64_lowercase_hex_characters_is_refused() {
        let setup = Setup::new("cli-hex-dst", "archive");
        setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let hex = "ab".repeat(32);
        let out = setup.push_to(&dest, &[&format!("main:{hex}")]);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(stdout(&out), "");
        assert_eq!(stderr(&out), format!("error: Invalid refspec {hex}\n"));
        assert!(!setup.ssh_started());
        assert!(!dest.join("refs/heads").join(&hex).exists());
    }

    /// A ref line that standard output cannot take, here on `/dev/full`,
    /// gives the error line and exit 1. The ref of the server moves to the
    /// pushed commit, although the write of the ref line fails.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_write_of_the_ref_lines_exits_one() {
        let setup = Setup::new("cli-dev-full", "archive");
        let main = setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let ssh = setup.ssh_command();
        let receive = receive_command();
        let address = address(&dest);
        let repo = format!("--repo={}", setup.client.display());
        let out = Command::new(env!("CARGO_BIN_EXE_ostrya"))
            .args([&repo, "push", &ssh, &receive, &address, "main"])
            .current_dir(&setup.base.0)
            .env_remove("OSTRYA_SSH_COMMAND")
            .env_remove("OSTREE_REPO")
            .env("LOGNAME", CLIENT)
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

    /// If the command line gives no `--ssh-command`, `OSTRYA_SSH_COMMAND`
    /// gives the ssh command of the push.
    #[test]
    fn the_environment_gives_the_ssh_command_when_no_option_does() {
        let setup = Setup::new("cli-ssh-env", "archive");
        setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let env = [("OSTRYA_SSH_COMMAND", "/nonexistent/ssh")];
        let receive = receive_command();
        let address = address(&dest);
        let out = setup.push(&[&receive, &address, "main"], &env);
        assert_failed(&out, "error: transport: ");
        assert!(
            stderr(&out).contains("/nonexistent/ssh"),
            "{}",
            stderr(&out)
        );
        assert!(!setup.ssh_started());
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
        let receive = receive_command();
        let address = address(&dest);
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

    /// A client group with no `d` refuses a delete of a ref that is present,
    /// and a group with `rd` takes it. A delete of an absent ref changes
    /// nothing.
    #[test]
    fn a_delete_needs_a_group_with_d() {
        let setup = Setup::new("cli-delete", "archive");
        let c = setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        client_group(&dest, "w:**");
        let out = setup.push_to(&dest, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));

        let out = setup.push_to(&dest, &[":main"]);
        assert_failed(&out, "error: delete-denied: ");
        assert_eq!(server_tip(&dest, "main"), Some(c));

        client_group(&dest, "rd:**");
        let out = setup.push_to(&dest, &[":main", ":absent"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(
            stdout(&out),
            format!("main {c} (deleted)\nabsent (absent) (unchanged)\n")
        );
        assert_eq!(server_tip(&dest, "main"), None);
    }

    /// `--client` of the receive command wins over `LOGNAME`. A name with no
    /// `ssh:` item gets `ref-denied`. A receiver whose one push group carries
    /// the `anonymous` item refuses each ssh push with `ref-denied`, because
    /// an ssh session uses the `ssh:` items alone.
    #[test]
    fn the_client_option_wins_over_logname_and_ssh_uses_ssh_items_alone() {
        let setup = Setup::new("cli-client", "archive");
        let c = setup.commit("main", FILES, &[]);
        let dest = receiver(&setup.base, RepoMode::Archive);
        let ssh = setup.ssh_command();
        let address = address(&dest);
        let as_client = |client: &str| {
            format!(
                "--receive-command={} -v receive --client={}",
                quote(env!("CARGO_BIN_EXE_ostrya")),
                quote(client)
            )
        };
        let receive = as_client(CLIENT);
        let out = setup.push(&[&ssh, &receive, &address, "main"], &[("LOGNAME", "other")]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {c}\n"));

        let c2 = setup.commit("main", &[("e", "epsilon\n")], &[]);
        let receive = as_client("other");
        let out = setup.push(&[&ssh, &receive, &address, "main"], &[]);
        assert_failed(&out, "error: ref-denied: ");
        let out = setup.push_to(&dest, &["main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(server_tip(&dest, "main"), Some(c2));

        let config = dest.join("config");
        let text = std::fs::read_to_string(&config).unwrap();
        let start = text.find("[ex-ostrya client ").unwrap();
        std::fs::write(
            &config,
            format!(
                "{}[ex-ostrya client \"anyone\"]\nauth=anonymous\nallow=w:**\n",
                &text[..start]
            ),
        )
        .unwrap();
        setup.commit("main", &[("f", "phi\n")], &[]);
        let out = setup.push_to(&dest, &["main"]);
        assert_failed(&out, "error: ref-denied: ");
        assert_eq!(server_tip(&dest, "main"), Some(c2));
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

        let out = setup.push_to(&dest, &["main"]);
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

        /// The timestamp of every commit that the `ostree` command and ostrya
        /// make in these tests.
        const EPOCH: &str = "1700000000";

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
        /// first call makes with `ostree init`. `None` if `ostree` is
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
        /// `SOURCE_DATE_EPOCH` and then `envs` set.
        fn push_tree(setup: &Setup, args: &[&str], envs: &[(&str, &str)]) -> Output {
            let mut all = vec!["push-tree"];
            all.extend_from_slice(args);
            let mut all_envs = vec![("SOURCE_DATE_EPOCH", EPOCH)];
            all_envs.extend_from_slice(envs);
            ostrya(&setup.base.0, &all, &all_envs)
        }

        /// The ssh command, the receive command, the address of `dest`, and
        /// the directory `tree`: the leading arguments of a push of `tree`.
        fn leading(setup: &Setup, dest: &Path, tree: &Path) -> [String; 4] {
            [
                setup.ssh_command(),
                receive_command(),
                address(dest),
                tree.to_str().unwrap().to_owned(),
            ]
        }

        /// Run `ostrya push-tree` of `tree` over the stand-in to `dest`, with
        /// the receive command of the built binary.
        fn push_tree_to(setup: &Setup, dest: &Path, tree: &Path, args: &[&str]) -> Output {
            let leading = leading(setup, dest, tree);
            let mut all: Vec<&str> = leading.iter().map(String::as_str).collect();
            all.extend_from_slice(args);
            push_tree(setup, &all, &[])
        }

        /// The commit that a successful push prints: its one line on standard
        /// output.
        fn pushed(out: &Output) -> Checksum {
            assert!(out.status.success(), "{}", stderr(out));
            let text = stdout(out);
            assert_eq!(text.lines().count(), 1, "{text}");
            assert!(text.ends_with('\n'), "{text:?}");
            Checksum::from_hex(text.trim_end()).unwrap()
        }

        /// The commit `checksum` of the repository `repo`.
        fn load(repo: &Path, checksum: &Checksum) -> ostrya::Commit {
            block_on(async {
                let repo = Repo::open(repo).await.unwrap();
                repo.load_commit(checksum).await.unwrap().0
            })
        }

        /// One `--onto` with a subject, a body, and metadata options in mixed
        /// order gives the commit of the `ostree` command with `-b`. A second
        /// push gives the second commit of `ostree`, whose parent is the
        /// first. Under `-v`, the statistics line goes to standard error.
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
            let mut args = vec!["--onto", "main"];
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
            assert_eq!(load(&dest, &c2).parent, Some(c1));
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

        /// On a pipe, the progress bar of a tree push writes nothing:
        /// standard error carries no escape byte. Without `--verbose`,
        /// standard error carries nothing at all. With it, the statistics
        /// line is the last line. Standard output keeps the commit checksum.
        /// `TERM` names a terminal, so the pipe alone hides the bar.
        #[test]
        fn a_tree_push_to_a_pipe_writes_no_progress() {
            let setup = Setup::without_client("tree-progress-pipe");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            std::fs::write(tree.join("big"), "progress\n".repeat(40_000)).unwrap();
            set_mode(&tree.join("big"), 0o644);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let leading = leading(&setup, &dest, &tree);
            let run = |extra: &[&str]| {
                let mut args: Vec<&str> = leading.iter().map(String::as_str).collect();
                args.extend(["--onto", "main"]);
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

        /// `--bind-ref` and `--tag` each give the commit of
        /// `ostree commit -b R1 --bind-ref R2`. The server creates the ref of
        /// a tag, and creates no ref for a bound name.
        #[test]
        fn a_tag_and_a_bound_name_give_the_commit_of_the_tool_with_bind_ref() {
            let setup = Setup::without_client("tree-two");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let bound = pushed(&push_tree_to(
                &setup,
                &dest,
                &tree,
                &["--onto", "r1", "--bind-ref", "r2"],
            ));
            assert_eq!(server_tip(&dest, "r1"), Some(bound));
            assert_eq!(server_tip(&dest, "r2"), None);
            let tagged = pushed(&push_tree_to(
                &setup,
                &dest,
                &tree,
                &["--onto", "t1", "--tag", "t2"],
            ));
            assert_eq!(server_tip(&dest, "t1"), Some(tagged));
            assert_eq!(server_tip(&dest, "t2"), Some(tagged));
            let out = push_tree_to(&setup, &dest, &tree, &["--onto", "t3", "--tag", "t2"]);
            assert_failed(&out, "error: ref-mismatch: ");
            assert_eq!(server_tip(&dest, "t3"), None);
            if let Some(t) = tool_commit(&setup.base, &tree, &["-b", "r1", "--bind-ref", "r2"]) {
                assert_eq!(bound, t);
                let t = tool_commit(&setup.base, &tree, &["-b", "t1", "--bind-ref", "t2"]);
                assert_eq!(Some(tagged), t);
            }
            tool_fsck(&dest);
        }

        /// `--canonical-permissions` and the owner options give the commit
        /// of the `ostree` command with the same options, over a tree whose
        /// modes the canonical rule changes.
        #[test]
        fn the_owner_and_canonical_options_give_the_commit_of_the_tool() {
            let setup = Setup::without_client("tree-owner");
            let tree = tree(&setup.base, "tree", 0o664, 0o2775);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let plain = pushed(&push_tree_to(&setup, &dest, &tree, &["--onto", "plain"]));
            for (name, options) in [
                ("canonical", &["--canonical-permissions"][..]),
                ("owner", &["--owner-uid=0", "--owner-gid=0"][..]),
            ] {
                let mut args = vec!["--onto", name];
                args.extend(options);
                let c = pushed(&push_tree_to(&setup, &dest, &tree, &args));
                assert_ne!(c, plain, "{name}");
                assert_eq!(server_tip(&dest, name), Some(c));
                let mut tool_args = vec!["-b", name];
                tool_args.extend(options);
                if let Some(t) = tool_commit(&setup.base, &tree, &tool_args) {
                    assert_eq!(c, t, "{name}");
                }
            }
            if let Some(t) = tool_commit(&setup.base, &tree, &["-b", "plain"]) {
                assert_eq!(plain, t);
            }
            tool_fsck(&dest);
        }

        /// A `bare-user-only` receiver refuses the owner of the walk and a
        /// mode that it does not store. With the owner options, a tree of 0644
        /// and 0755 modes goes in. With `--canonical-permissions`, a tree of
        /// 0664 goes in.
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
                &["--onto", "x", "--canonical-permissions", "--owner-uid=1"],
            );
            assert_failed(
                &out,
                "error: Cannot specify both --canonical-permissions and non-zero --owner-uid",
            );
            assert!(!setup.ssh_started());

            if !root {
                let out = push_tree_to(&setup, &dest, &plain, &["--onto", "main"]);
                assert_failed(&out, "error: mode-refused: ");
                assert_eq!(server_tip(&dest, "main"), None);
            }
            let owner = ["--onto", "main", "--owner-uid=0", "--owner-gid=0"];
            let c = pushed(&push_tree_to(&setup, &dest, &plain, &owner));
            assert_eq!(server_tip(&dest, "main"), Some(c));

            let out = push_tree_to(
                &setup,
                &dest,
                &wide,
                &["--onto", "wide", "--owner-uid=0", "--owner-gid=0"],
            );
            assert_failed(&out, "error: mode-refused: ");
            assert_eq!(server_tip(&dest, "wide"), None);
            let c = pushed(&push_tree_to(
                &setup,
                &dest,
                &wide,
                &["--onto", "wide", "--canonical-permissions"],
            ));
            assert_eq!(server_tip(&dest, "wide"), Some(c));
            tool_fsck(&dest);
        }

        /// If the push names an address, the command opens no repository.
        /// The push succeeds in each of these cases:
        ///
        /// - a `--repo` that does not exist,
        /// - a `--repo` whose config does not parse,
        /// - `OSTREE_REPO` at a missing path,
        /// - a current directory that is no repository.
        #[test]
        fn an_address_opens_no_repository() {
            let setup = Setup::new("tree-address", "archive");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let leading = leading(&setup, &dest, &tree);
            let missing = setup.base.0.join("missing");
            let garbage = setup.base.0.join("garbage");
            std::fs::create_dir_all(garbage.join("objects")).unwrap();
            std::fs::write(garbage.join("config"), "this is [no keyfile\n").unwrap();
            let missing_arg = format!("--repo={}", missing.display());
            let garbage_arg = format!("--repo={}", garbage.display());
            let missing_env = [("OSTREE_REPO", missing.to_str().unwrap())];
            // The branch, the `--repo` option, and the environment of each
            // case.
            type Case<'a> = (&'a str, Option<&'a str>, &'a [(&'a str, &'a str)]);
            let cases: [Case; 4] = [
                ("n1", Some(missing_arg.as_str()), &[]),
                ("n2", Some(garbage_arg.as_str()), &[]),
                ("n3", None, &missing_env),
                ("n4", None, &[]),
            ];
            for (name, repo, envs) in cases {
                let mut args: Vec<&str> = repo.into_iter().collect();
                args.extend(leading.iter().map(String::as_str));
                args.extend(["--onto", name]);
                let c = pushed(&push_tree(&setup, &args, envs));
                assert_eq!(server_tip(&dest, name), Some(c), "{name}");
            }
            tool_fsck(&dest);
        }

        /// A remote name with a `--repo` that does not exist fails on the
        /// open, before ssh starts.
        #[test]
        fn a_remote_name_with_a_missing_repository_fails_on_the_open() {
            let setup = Setup::new("tree-remote-missing", "archive");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let ssh = setup.ssh_command();
            let receive = receive_command();
            let address = address(&dest);
            let tree_arg = tree.to_str().unwrap();
            let missing = setup.base.0.join("missing");
            let missing_arg = format!("--repo={}", missing.display());
            let config = setup.client.join("config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str(&format!("\n[remote \"origin\"]\npush-url={address}\n"));
            std::fs::write(&config, text).unwrap();
            let out = push_tree(
                &setup,
                &[
                    &missing_arg,
                    &ssh,
                    &receive,
                    "origin",
                    tree_arg,
                    "--onto",
                    "n5",
                ],
                &[],
            );
            assert_failed(&out, "error: opening repo: ");
            assert!(!setup.ssh_started());
            assert_eq!(server_tip(&dest, "n5"), None);
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
                &[
                    &repo,
                    &ssh,
                    "origin",
                    tree.to_str().unwrap(),
                    "--onto",
                    "main",
                ],
                &[],
            );
            let c = pushed(&out);
            assert_eq!(server_tip(&dest, "main"), Some(c));
            assert_eq!(exit_status(&setup.status), "0");
            tool_fsck(&dest);
        }

        /// A missing REMOTE, DIR, or `--onto` fails with the usage text and
        /// the error line, in that order, before ssh starts. A missing DIR
        /// wins over a missing `--onto`, and each wins over a `--repo` that
        /// does not open.
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
                (
                    vec![ssh.as_str(), "--onto", "main"],
                    "REMOTE must be specified",
                ),
                (
                    vec![ssh.as_str(), &address, "--onto", "main"],
                    "DIR must be specified",
                ),
                (
                    vec![ssh.as_str(), &address, tree_arg],
                    "A branch must be specified with --onto",
                ),
                (vec![ssh.as_str(), &address], "DIR must be specified"),
                (
                    vec![&missing_repo, ssh.as_str(), "origin", "--onto", "main"],
                    "DIR must be specified",
                ),
                (
                    vec![&missing_repo, ssh.as_str(), "origin", tree_arg],
                    "A branch must be specified with --onto",
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
        /// that does not exist, so the refusal comes before the scan. A
        /// malformed `SOURCE_DATE_EPOCH` is refused too, and `--timestamp`
        /// wins over it.
        #[test]
        fn a_refused_option_fails_before_ssh_starts() {
            let setup = Setup::without_client("tree-refused");
            let dest = receiver(&setup.base, RepoMode::Archive);
            let hex = "ab".repeat(32);
            let missing = setup.base.0.join("missing");
            let cases: Vec<(Vec<&str>, &str)> = vec![
                (vec!["--timestamp=bogus"], "Could not parse 'bogus'"),
                (vec!["--add-metadata-string=noeq"], "Missing '='"),
                (vec!["--add-metadata=k=@@"], "Parsing k=@@: "),
                (vec!["--add-metadata-string==v"], "Empty metadata key"),
                (
                    vec!["--add-metadata-string=ostree.ref-binding=x"],
                    "'ostree.ref-binding', which the server writes",
                ),
                (
                    vec!["--add-metadata=ostree.collection-binding='x'"],
                    "'ostree.collection-binding', which the server writes",
                ),
                (vec!["--compress=0"], "--compress"),
                (vec!["--tag", "main"], "is also the branch"),
                (vec!["--tag", "t", "--tag", "t"], "is named twice"),
                (vec!["--tag", "main^"], "is not a valid ref name"),
                (vec!["--tag", "origin:main"], "holds ':'"),
                (vec!["--tag", hex.as_str()], "looks like a checksum"),
                (vec!["--bind-ref", "o:b"], "bound name 'o:b'"),
                (vec!["--collection=no-dot"], "invalid collection id"),
                (vec!["--owner-uid=abc"], "Cannot parse integer value"),
            ];
            for (options, needle) in cases {
                let mut args = vec!["--onto", "main"];
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
            for branch in ["main^", "origin:main", hex.as_str()] {
                let out = push_tree_to(&setup, &dest, &missing, &["--onto", branch]);
                assert_failed(&out, "error: ");
                assert!(!setup.ssh_started(), "{branch}");
            }

            let leading = leading(&setup, &dest, &missing);
            let mut args: Vec<&str> = leading.iter().map(String::as_str).collect();
            args.extend(["--onto", "main"]);
            let out = push_tree(&setup, &args, &[("SOURCE_DATE_EPOCH", "soon")]);
            assert_failed(
                &out,
                "error: SOURCE_DATE_EPOCH is not a Unix timestamp: \"soon\"",
            );
            assert!(!setup.ssh_started());
            args.push("--timestamp=@1");
            let out = push_tree(&setup, &args, &[("SOURCE_DATE_EPOCH", "soon")]);
            assert_failed(&out, "error: ");
            assert!(stderr(&out).contains("missing"), "{}", stderr(&out));

            let out = push_tree_to(&setup, &dest, &missing, &["--onto", "main"]);
            assert_failed(&out, "error: ");
            assert!(stderr(&out).contains("missing"), "{}", stderr(&out));
            assert!(!setup.ssh_started());
            assert_eq!(server_tip(&dest, "main"), None);
        }

        /// `--body-file` alone and beside `-m`, an explicit `--timestamp`,
        /// and `--orphan` on a new branch each give the commit of the
        /// `ostree` command with the matching options.
        #[test]
        fn the_commit_options_give_the_commit_of_the_tool() {
            let setup = Setup::without_client("tree-options");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let body = setup.base.0.join("body.txt");
            std::fs::write(&body, "file body\n").unwrap();
            let body_file = format!("--body-file={}", body.display());
            // The options of ostrya and the options of the `ostree` command
            // that give the same commit.
            let cases: [(&[&str], &[&str]); 4] = [
                (&["--onto", "body", &body_file], &["-b", "body", &body_file]),
                (
                    &["--onto", "both", "-m", "inline", &body_file],
                    &["-b", "both", "-m", "inline", &body_file],
                ),
                (
                    &["--onto", "stamp", "--timestamp=@1600000000"],
                    &["-b", "stamp", "--timestamp=@1600000000"],
                ),
                (
                    &["--onto", "root", "--orphan"],
                    &["-b", "root", "--parent=none"],
                ),
            ];
            let mut commits = Vec::new();
            for (args, _) in cases {
                let c = pushed(&push_tree_to(&setup, &dest, &tree, args));
                assert_eq!(server_tip(&dest, args[1]), Some(c), "{args:?}");
                commits.push(c);
            }
            assert_eq!(load(&dest, &commits[2]).timestamp, 1_600_000_000);
            if ostree_available() {
                for ((_, tool_args), c) in cases.iter().zip(&commits) {
                    let t = tool_commit(&setup.base, &tree, tool_args);
                    assert_eq!(t, Some(*c), "{tool_args:?}");
                }
            }
            tool_fsck(&dest);
        }

        /// `--orphan` on a branch that exists needs `d`: with `wc` the server
        /// answers `non-fast-forward`, and with `wcd` the new commit has no
        /// parent.
        #[test]
        fn orphan_on_a_present_branch_needs_d() {
            let setup = Setup::without_client("tree-orphan");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let first = pushed(&push_tree_to(&setup, &dest, &tree, &["--onto", "main"]));
            let out = push_tree_to(&setup, &dest, &tree, &["--onto", "main", "--orphan"]);
            assert_failed(&out, "error: non-fast-forward: ");
            assert_eq!(server_tip(&dest, "main"), Some(first));
            client_group(&dest, "wcd:**");
            let out = push_tree_to(
                &setup,
                &dest,
                &tree,
                &["--onto", "main", "--orphan", "--timestamp=@1700000001"],
            );
            let root = pushed(&out);
            assert_eq!(server_tip(&dest, "main"), Some(root));
            assert_eq!(load(&dest, &root).parent, None);
        }

        /// A client group with no `c` gets `ref-denied`. A collection
        /// namespace writes the refs of the collection, and binds the commit
        /// to it.
        #[test]
        fn the_rights_and_the_collection_of_a_tree_push() {
            let setup = Setup::without_client("tree-rights");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            client_group(&dest, "w:**");
            let out = push_tree_to(&setup, &dest, &tree, &["--onto", "main"]);
            assert_failed(&out, "error: ref-denied: ");
            assert_eq!(server_tip(&dest, "main"), None);

            collection_group(&dest, "os", "org.example.Os", "c:**");
            let out = push_tree_to(
                &setup,
                &dest,
                &tree,
                &["--onto", "main", "--collection=org.example.Os"],
            );
            let c = pushed(&out);
            let mirror = dest.join("refs/mirrors/org.example.Os/main");
            assert_eq!(std::fs::read_to_string(mirror).unwrap(), format!("{c}\n"));
            let commit = load(&dest, &c);
            assert_eq!(commit.collection_binding(), Some("org.example.Os"));
            assert_eq!(commit.ref_bindings(), ["main"]);
            assert_eq!(server_tip(&dest, "main"), None);
        }

        /// With no `--timestamp` and no `SOURCE_DATE_EPOCH`, the push sends no
        /// timestamp, and the server takes its clock.
        #[test]
        fn with_no_timestamp_the_server_takes_its_clock() {
            let setup = Setup::without_client("tree-clock");
            let tree = tree(&setup.base, "tree", 0o644, 0o755);
            let dest = receiver(&setup.base, RepoMode::Archive);
            let leading = leading(&setup, &dest, &tree);
            let now = || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            };
            let before = now();
            let out = Command::new(env!("CARGO_BIN_EXE_ostrya"))
                .arg("push-tree")
                .args(&leading)
                .args(["--onto", "main"])
                .current_dir(&setup.base.0)
                .env_remove("OSTRYA_SSH_COMMAND")
                .env_remove("OSTREE_REPO")
                .env_remove("SOURCE_DATE_EPOCH")
                .env("LOGNAME", CLIENT)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let after = now();
            let c = pushed(&out);
            let timestamp = load(&dest, &c).timestamp;
            assert!(
                (before..=after).contains(&timestamp),
                "{timestamp} is not in {before}..={after}"
            );
        }

        /// The commit of the local branch `main` of `setup` over the tree
        /// `tree`, with `extra` options of `ostrya commit`.
        fn local_commit(setup: &Setup, tree: &Path, extra: &[&str]) -> Checksum {
            let repo = format!("--repo={}", setup.client.display());
            let mut args = vec![
                repo.as_str(),
                "commit",
                "--no-xattrs",
                "-b",
                "main",
                "-s",
                "S",
                "-m",
                "B",
                "--add-metadata-string=a=x",
            ];
            args.extend_from_slice(extra);
            args.push(tree.to_str().unwrap());
            let out = ostrya(&setup.base.0, &args, &[("SOURCE_DATE_EPOCH", EPOCH)]);
            assert!(out.status.success(), "{}", stderr(&out));
            Checksum::from_hex(stdout(&out).trim()).unwrap()
        }

        /// `push --onto` prints the commit of the server alone. The commit
        /// takes the subject, the body, the metadata, and the timestamp of
        /// the local commit, with the bindings of the server in place of the
        /// local bindings. It equals the commit of `ostree commit -b` over the
        /// same tree, with the same parent. A second push moves the branch.
        /// `--tag` and `--bind-ref` bind their names, and `--timestamp`
        /// replaces the timestamp.
        #[test]
        fn push_onto_gives_the_commit_of_the_tool() {
            let setup = Setup::new("onto-tool", "archive");
            set_collection_id(&setup.client, Some("org.example.Local"));
            let one = tree(&setup.base, "one", 0o644, 0o755);
            let two = tree(&setup.base, "two", 0o644, 0o700);
            let dest = receiver(&setup.base, RepoMode::Archive);

            let local = local_commit(&setup, &one, &["--bind-ref=local/only"]);
            let out = setup.push_to(&dest, &["--onto=main", "main"]);
            let c1 = pushed(&out);
            assert_ne!(c1, local);
            assert_eq!(server_tip(&dest, "main"), Some(c1));
            assert!(!server_has_commit(&dest, &local));
            let commit = load(&dest, &c1);
            assert_eq!(commit.ref_bindings(), ["main"]);
            assert_eq!(commit.collection_binding(), None);
            assert_eq!(commit.timestamp, 1_700_000_000);

            local_commit(&setup, &two, &[]);
            let out = setup.push_to(
                &dest,
                &[
                    "--onto=main",
                    "--tag=v1",
                    "--bind-ref=b2",
                    "--timestamp=@1600000000",
                    "main",
                ],
            );
            let c2 = pushed(&out);
            assert_eq!(server_tip(&dest, "main"), Some(c2));
            assert_eq!(server_tip(&dest, "v1"), Some(c2));
            assert_eq!(load(&dest, &c2).parent, Some(c1));

            let options = ["-s", "S", "-m", "B", "--add-metadata-string=a=x"];
            let mut first = vec!["-b", "main"];
            first.extend(options);
            if let Some(t1) = tool_commit(&setup.base, &one, &first) {
                assert_eq!(c1, t1);
                let mut second = vec![
                    "-b",
                    "main",
                    "--bind-ref=v1",
                    "--bind-ref=b2",
                    "--timestamp=@1600000000",
                ];
                second.extend(options);
                assert_eq!(tool_commit(&setup.base, &two, &second), Some(c2));
            }
            tool_fsck(&dest);
        }

        /// `push --onto` refuses a second REF, `--depth`, `--force`, a bad
        /// timestamp, and a bad branch before ssh starts. `--bind-ref`,
        /// `--orphan`, and `--timestamp` need `--onto`.
        #[test]
        fn push_onto_refusals_come_before_ssh_starts() {
            let setup = Setup::new("onto-refused", "archive");
            setup.commit("main", FILES, &[]);
            let dest = receiver(&setup.base, RepoMode::Archive);
            for (args, needle) in [
                (
                    &["--onto=main", "main", "main"][..],
                    "error: --onto takes one REF, and 2 were given",
                ),
                (&["--onto=main", "--depth=1", "main"], "cannot be used with"),
                (&["--onto=main", "--force", "main"], "cannot be used with"),
                (
                    &["--onto=main", "--timestamp=bogus", "main"],
                    "error: Could not parse 'bogus'",
                ),
                (&["--onto=main^", "main"], "error: Invalid refspec main^"),
                (&["--onto=main", "--tag=main", "main"], "also the branch"),
                (&["--bind-ref=x", "main"], "--onto"),
                (&["--orphan", "main"], "--onto"),
                (&["--timestamp=@1", "main"], "--onto"),
            ] {
                let out = setup.push_to(&dest, args);
                assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stderr(&out));
                assert_eq!(stdout(&out), "", "{args:?}");
                assert!(stderr(&out).contains(needle), "{args:?}: {}", stderr(&out));
                assert!(!setup.ssh_started(), "{args:?}");
            }
            assert_eq!(server_tip(&dest, "main"), None);
        }

        /// The server refuses a `push --onto` from a client group with no
        /// `c`, a tag that exists, and `--orphan` on a present branch without
        /// `d`. `--orphan` with `d` makes a commit with no parent. A
        /// collection writes the refs of the collection.
        #[test]
        fn push_onto_takes_the_rights_of_the_server() {
            let setup = Setup::new("onto-rights", "archive");
            setup.commit("main", FILES, &[]);
            let dest = receiver(&setup.base, RepoMode::Archive);
            client_group(&dest, "w:**");
            let out = setup.push_to(&dest, &["--onto=main", "main"]);
            assert_failed(&out, "error: ref-denied: ");
            assert_eq!(server_tip(&dest, "main"), None);

            client_group(&dest, "wc:**");
            let first = pushed(&setup.push_to(&dest, &["--onto=main", "--tag=v1", "main"]));
            let out = setup.push_to(&dest, &["--onto=main", "--tag=v1", "main"]);
            assert_failed(&out, "error: ref-mismatch: ");
            let out = setup.push_to(&dest, &["--onto=main", "--orphan", "main"]);
            assert_failed(&out, "error: non-fast-forward: ");
            assert_eq!(server_tip(&dest, "main"), Some(first));

            client_group(&dest, "wcd:**");
            let out = setup.push_to(
                &dest,
                &["--onto=main", "--orphan", "--timestamp=@1", "main"],
            );
            let root = pushed(&out);
            assert_eq!(server_tip(&dest, "main"), Some(root));
            assert_eq!(load(&dest, &root).parent, None);

            collection_group(&dest, "os", "org.example.Os", "c:**");
            let out = setup.push_to(
                &dest,
                &["--onto=main", "--collection=org.example.Os", "main"],
            );
            let mirrored = pushed(&out);
            let mirror = dest.join("refs/mirrors/org.example.Os/main");
            assert_eq!(
                std::fs::read_to_string(mirror).unwrap(),
                format!("{mirrored}\n")
            );
            assert_eq!(
                load(&dest, &mirrored).collection_binding(),
                Some("org.example.Os")
            );
        }
    }
}
