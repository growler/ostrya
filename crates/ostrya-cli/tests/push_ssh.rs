//! `PushSession::connect` over a stand-in ssh client that runs the built
//! `ostrya receive` locally, the way the remote shell of ssh runs the
//! remote command.

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
