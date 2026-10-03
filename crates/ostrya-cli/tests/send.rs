//! `ostrya send` as a process: the exit status after a clean end and after
//! an `Error`, and the pull session it serves from an `archive` and a
//! `bare-user` repository that its user can read and cannot write.

#![cfg(feature = "send")]

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ostrya::Repo;
use ostrya::push::ErrorCode;
use ostrya::push::proto::{FrameReader, FrameWriter, GetReply, Message, ObjectRead, PullHello};
use ostrya_rt::block_on;

/// A scratch directory, made writable again and removed when dropped.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ostrya-send-{}-{tag}-{}",
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
        let _ = Command::new("chmod")
            .arg("-R")
            .arg("u+w")
            .arg(&self.0)
            .status();
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/generated")
}

fn run(program: &str, args: &[&str], dir: &Path) {
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(status.success(), "{program} {args:?} failed");
}

/// A copy of the `archive` fixture repository under `dir`.
fn archive_copy(dir: &Path) -> PathBuf {
    let src = fixtures().join("archive/repo");
    run("cp", &["-a", src.to_str().unwrap(), "archive"], dir);
    dir.join("archive")
}

/// A copy of the `bare-user` fixture repository under `dir`, with the
/// `user.*` extended attributes of its objects.
fn bare_user_copy(dir: &Path) -> PathBuf {
    let tar = fixtures().join("bare-user.tar");
    let to = dir.join("bare-user");
    std::fs::create_dir_all(&to).unwrap();
    run(
        "tar",
        &[
            "--xattrs",
            "--xattrs-include=user.*",
            "-xf",
            tar.to_str().unwrap(),
        ],
        &to,
    );
    to.join("repo")
}

/// The frames of `msgs` in one buffer.
fn frames(msgs: &[Message]) -> Vec<u8> {
    let mut writer = FrameWriter::new(Vec::new());
    block_on(async {
        for msg in msgs {
            writer.write_message(msg).await.unwrap();
        }
    });
    writer.into_inner()
}

fn pull_hello(version: u32) -> Message {
    Message::PullHello(PullHello {
        version,
        agent: None,
    })
}

/// The time a run of `ostrya send` can take before the test kills it and
/// fails.
const SEND_LIMIT: Duration = Duration::from_secs(60);

/// Read all of `pipe` on a thread of its own.
fn drain<P: Read + Send + 'static>(mut pipe: P) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        pipe.read_to_end(&mut out).unwrap();
        out
    })
}

/// Run `ostrya [global] send --repo=REPO` with `input` on standard input. A
/// run longer than [`SEND_LIMIT`] is killed, and the test fails.
fn send(repo: &Path, global: &[&str], input: Vec<u8>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ostrya"))
        .args(global)
        .arg("send")
        .arg(format!("--repo={}", repo.display()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // The input is written while the output is read, so neither pipe can
    // fill while the other waits.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let stdout = drain(child.stdout.take().unwrap());
    let stderr = drain(child.stderr.take().unwrap());
    let deadline = Instant::now() + SEND_LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("ostrya send ran for more than {SEND_LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    writer.join().unwrap();
    Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    }
}

/// The messages of a session output, with the bytes of each body after its
/// reply.
fn messages(bytes: &[u8]) -> Vec<(Message, Vec<u8>)> {
    let mut reader = FrameReader::new(bytes);
    let mut out = Vec::new();
    block_on(async {
        while let Some(msg) = reader.read_message().await.unwrap() {
            let mut body = Vec::new();
            if let Message::GetReply(GetReply { found: true, .. }) = msg {
                let mut buf = vec![0u8; 65_536];
                while let ObjectRead::Data(n) = reader.read_object_data(&mut buf).await.unwrap() {
                    body.extend_from_slice(&buf[..n]);
                }
            }
            out.push((msg, body));
        }
    });
    out
}

/// Each path a pull of the fixture asks for: `config`, each ref, and each
/// object in its archive form.
fn pull_paths(repo: &Path) -> Vec<String> {
    let mut paths = vec!["config".to_owned()];
    let mut stack = vec![repo.join("refs"), repo.join("objects")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path.strip_prefix(repo).unwrap().to_str().unwrap();
            match rel.strip_suffix(".file") {
                Some(stem) => paths.push(format!("{stem}.filez")),
                None => paths.push(rel.to_owned()),
            }
        }
    }
    paths.sort();
    paths
}

/// One entry of a snapshot: the name, the file type, the size, and the
/// modification and change times in seconds and nanoseconds.
type Entry = (String, u32, u64, (i64, i64), (i64, i64));

/// `root` itself, as `.`, and each entry under it, sorted by name. A file
/// created and removed in `root` changes the times of `root`.
fn snapshot(root: &Path) -> Vec<Entry> {
    let entry = |name: String, md: std::fs::Metadata| -> Entry {
        (
            name,
            md.mode() & 0o170000,
            md.size(),
            (md.mtime(), md.mtime_nsec()),
            (md.ctime(), md.ctime_nsec()),
        )
    };
    let mut out = vec![entry(
        ".".to_owned(),
        std::fs::symlink_metadata(root).unwrap(),
    )];
    let mut stack = vec![root.to_owned()];
    while let Some(dir) = stack.pop() {
        for dirent in std::fs::read_dir(&dir).unwrap() {
            let path = dirent.unwrap().path();
            let md = std::fs::symlink_metadata(&path).unwrap();
            if md.is_dir() {
                stack.push(path.clone());
            }
            let name = path.strip_prefix(root).unwrap().display().to_string();
            out.push(entry(name, md));
        }
    }
    out.sort();
    out
}

/// `ostrya send` exits 0 when its input ends at a frame boundary, an empty
/// input included, and writes nothing to standard error, also under
/// `--verbose`. It exits non-zero after an `Error`, which goes to standard
/// output as a frame.
#[test]
fn send_exits_0_after_a_clean_end_and_non_zero_after_an_error() {
    let tmp = TmpDir::new("status");
    let repo = archive_copy(&tmp.0);

    let out = send(&repo, &["-v"], Vec::new());
    assert!(out.status.success(), "{out:?}");
    assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{out:?}");

    let input = frames(&[pull_hello(1), Message::Get("config".to_owned())]);
    let out = send(&repo, &["-v"], input);
    assert!(out.status.success(), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
    let msgs = messages(&out.stdout);
    assert_eq!(msgs.len(), 2);
    assert!(msgs[1].1.starts_with(b"[core]\n"), "{msgs:?}");

    for (input, code) in [
        (frames(&[pull_hello(0)]), ErrorCode::VersionUnsupported),
        (
            frames(&[Message::Get("config".to_owned())]),
            ErrorCode::Protocol,
        ),
    ] {
        let out = send(&repo, &[], input);
        assert_eq!(out.status.code(), Some(1), "{out:?}");
        let msgs = messages(&out.stdout);
        match &msgs[..] {
            [(Message::Error(e), _)] => assert_eq!(e.code, code),
            other => panic!("expected one Error frame, got {other:?}"),
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(code.as_str()), "{stderr}");
    }
}

/// `ostrya send` serves an `archive` and a `bare-user` repository that its
/// user can read and cannot write. It answers each path of the fixture
/// commit as `Repo::send` in the process answers it, and it creates,
/// changes, and removes no entry of the repository: no `.lock` either. As
/// root the mode bits do not stop a write, so the snapshot is the check.
#[test]
fn send_serves_a_repository_its_user_cannot_write() {
    let tmp = TmpDir::new("read-only");
    for repo in [archive_copy(&tmp.0), bare_user_copy(&tmp.0)] {
        let paths = pull_paths(&repo);
        assert!(paths.len() >= 8, "{paths:?}");
        let mut msgs = vec![pull_hello(1)];
        msgs.extend(paths.iter().map(|p| Message::Get(p.clone())));
        let input = frames(&msgs);

        run("chmod", &["-R", "a-w", repo.to_str().unwrap()], &tmp.0);
        let before = snapshot(&repo);

        let out = send(&repo, &[], input.clone());
        assert!(out.status.success(), "{}: {out:?}", repo.display());
        let served = messages(&out.stdout);
        assert_eq!(served.len(), paths.len() + 1);
        for ((msg, _), path) in served[1..].iter().zip(&paths) {
            assert!(
                matches!(msg, Message::GetReply(GetReply { found: true, .. })),
                "{path}: {msg:?}"
            );
        }

        let mut expected = Vec::new();
        block_on(async {
            let handle = Repo::open(&repo).await.unwrap();
            handle.send(&input[..], &mut expected).await.unwrap();
        });
        assert_eq!(out.stdout, expected, "{}", repo.display());

        assert_eq!(snapshot(&repo), before, "{}", repo.display());
        assert!(!repo.join(".lock").exists());
        assert_eq!(
            std::fs::metadata(&repo).unwrap().permissions().mode() & 0o222,
            0
        );
    }
}
