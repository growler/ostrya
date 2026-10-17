//! Tests of `Repo::send`, the serving side of the pull over ssh. The tests
//! cover:
//!
//! - the files of a commit from a repository of each mode
//! - the replies to paths that are not found
//! - the pipeline of `Get` frames and the version reply
//! - the ref listing of a `ListRefs`
//! - each error code of the pull
//! - the abandon marker of a body that fails after its reply
//! - the shape of the writes and the flushes on the output
//!
//! A test client drives the session over two in-process pipes with the frame
//! codec of `ostrya::remote::proto`. Other tests give the session one input
//! buffer and record its output. A second `ArchiveView` of the same
//! repository is the oracle of each reply: the session serves what the view
//! serves over HTTP.

mod common;

use std::cell::Cell;
use std::fs;
use std::future::Future;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use common::modes::{
    WRITABLE, build_tree, commit, file_objects, object_path, repo_of, write_split_object,
};
use common::pipe::{PipeReader, PipeWriter, pipe};
use common::{TmpDir, anyone, repo_access};
use futures_io::AsyncWrite;
use futures_lite::future;
use futures_lite::io::{AsyncReadExt, AsyncWriteExt, Cursor};
use ostrya::RefSelector;
use ostrya::access::ReadAccess;
use ostrya::remote::ErrorCode;
use ostrya::remote::proto::{
    ErrorMessage, FrameReader, FrameWriter, GetReply, Hello, ListRefsRequest, MIN_FRAME_LIMIT,
    Message, ObjectRead, PullHello, PullHelloReply,
};
use ostrya::{
    ArchiveAnswer, ArchiveView, Checksum, CreateOptions, Ed25519Signer, Error, FileKind,
    ObjectType, Repo, RepoMode, SummaryOptions, loose_path,
};
use ostrya_core::Xattrs;
use ostrya_rt::block_on;

/// The capacity of each pipe. It is smaller than the buffers on the path of
/// a large body, so the server waits for the client to read.
const PIPE_CAP: usize = 64 * 1024;

/// The time bound of each session.
const LIMIT: Duration = Duration::from_secs(60);

/// The payload of each chunk of a body but the last.
const CHUNK: usize = 64 * 1024 - 4;

const BASE_CONFIG: &[u8] = b"[core]\nrepo_version=1\nmode=archive-z2\n";

/// The base64 of a 64-byte ed25519 secret key: the seed and then the public
/// key.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";

/// The delta files of an `archive` repository. The view serves them as
/// stored, and from another mode it does not find them.
const DELTA_FILES: [&str; 2] = ["deltas/ab/cdef/superblock", "delta-indexes/ab/cdef.index"];

/// Runs `fut`. If `fut` takes longer than `limit`, the test fails.
async fn within<T>(limit: Duration, what: &str, fut: impl Future<Output = T>) -> T {
    future::or(fut, async {
        ostrya_rt::Timer::after(limit).await;
        panic!("{what} took longer than {limit:?}");
    })
    .await
}

/// `len` bytes that do not compress, from an xorshift generator.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

// ---------------------------------------------------------------------------
// The test client.
// ---------------------------------------------------------------------------

/// One reply: found, the stated length, and the body.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    found: bool,
    len: Option<u64>,
    body: Vec<u8>,
}

impl Reply {
    fn not_found() -> Reply {
        Reply {
            found: false,
            len: None,
            body: Vec::new(),
        }
    }
}

/// The client end of a session.
struct Client {
    writer: FrameWriter<PipeWriter>,
    reader: FrameReader<PipeReader>,
}

impl Client {
    async fn send(&mut self, msg: &Message) {
        self.writer.write_message(msg).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    async fn recv(&mut self) -> Option<Message> {
        self.reader
            .read_message()
            .await
            .expect("a well-formed frame")
    }

    /// Sends `PullHello` of `version` and returns the reply.
    async fn hello(&mut self, version: u32) -> Option<Message> {
        self.send(&Message::PullHello(PullHello {
            version,
            agent: Some("send-test".to_owned()),
        }))
        .await;
        self.recv().await
    }

    /// Opens the session at version 1.
    async fn open(&mut self) {
        let reply = self.hello(1).await;
        assert_eq!(
            reply,
            Some(Message::PullHelloReply(PullHelloReply { version: 1 }))
        );
    }

    /// Reads until the `Error` message, which is the last message of the
    /// session.
    async fn error(&mut self) -> ErrorMessage {
        match self.recv().await {
            Some(Message::Error(e)) => {
                assert_eq!(self.recv().await, None, "the session ends after Error");
                e
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Writes raw bytes and ends the input. The bytes do not have to be frames.
    async fn raw(self, bytes: &[u8]) -> FrameReader<PipeReader> {
        let mut out = self.writer.into_inner();
        out.write_all(bytes).await.unwrap();
        drop(out);
        self.reader
    }
}

/// Reads one reply and its body. A stated length equals the sum of the
/// chunks.
async fn read_reply(reader: &mut FrameReader<PipeReader>) -> Reply {
    let (found, len) = match reader.read_message().await.unwrap() {
        Some(Message::GetReply(GetReply { found, len })) => (found, len),
        other => panic!("expected GetReply, got {other:?}"),
    };
    let mut body = Vec::new();
    if found {
        let mut buf = vec![0u8; 100_000];
        loop {
            match reader.read_object_data(&mut buf).await.unwrap() {
                ObjectRead::Data(n) => body.extend_from_slice(&buf[..n]),
                ObjectRead::End => break,
                ObjectRead::Abandoned => panic!("a pull body takes Error after the marker"),
            }
        }
    }
    if let Some(len) = len {
        assert_eq!(body.len() as u64, len, "the stated length");
    }
    Reply { found, len, body }
}

/// Asks for each of `paths` with at most `depth` `Get` frames in flight, and
/// reads the replies while the frames go out. Returns the replies in the
/// order of `paths`, and the most frames that were in flight at once.
async fn fetch(client: &mut Client, paths: &[String], depth: usize) -> (Vec<Reply>, usize) {
    let in_flight = Cell::new(0usize);
    let peak = Cell::new(0usize);
    let Client { writer, reader } = client;
    let send = async {
        for path in paths {
            while in_flight.get() >= depth {
                future::yield_now().await;
            }
            in_flight.set(in_flight.get() + 1);
            peak.set(peak.get().max(in_flight.get()));
            writer
                .write_message(&Message::Get(path.clone()))
                .await
                .unwrap();
            writer.flush().await.unwrap();
        }
    };
    let receive = async {
        let mut replies = Vec::new();
        for _ in paths {
            replies.push(read_reply(reader).await);
            in_flight.set(in_flight.get() - 1);
        }
        replies
    };
    let ((), replies) = future::zip(send, receive).await;
    (replies, peak.get())
}

/// Runs a session of `repo` against the client `script`, over two pipes of
/// `cap` bytes, with the rights of an anonymous client under the groups of
/// the config of `repo`.
fn session<F, Fut, T>(repo: &Repo, cap: usize, script: F) -> (ostrya::Result<()>, T)
where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = T>,
{
    session_as(repo, &repo_access(repo, "anonymous"), cap, script)
}

/// Runs a session of `repo` with the rights `access` against the client
/// `script`, over two pipes of `cap` bytes.
fn session_as<F, Fut, T>(
    repo: &Repo,
    access: &ReadAccess,
    cap: usize,
    script: F,
) -> (ostrya::Result<()>, T)
where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = T>,
{
    let (client_out, server_in) = pipe(cap);
    let (server_out, client_in) = pipe(cap);
    let client = Client {
        writer: FrameWriter::new(client_out),
        reader: FrameReader::new(client_in),
    };
    block_on(within(
        LIMIT,
        "the session",
        future::zip(repo.send(server_in, server_out, access), script(client)),
    ))
}

/// Runs a session of `repo` with the rights `access` and the options `opts`
/// against the client `script`, over two pipes of `cap` bytes.
fn session_with<F, Fut, T>(
    repo: &Repo,
    access: &ReadAccess,
    opts: &ostrya::SendOptions,
    cap: usize,
    script: F,
) -> (ostrya::Result<()>, T)
where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = T>,
{
    let (client_out, server_in) = pipe(cap);
    let (server_out, client_in) = pipe(cap);
    let client = Client {
        writer: FrameWriter::new(client_out),
        reader: FrameReader::new(client_in),
    };
    block_on(within(
        LIMIT,
        "the session",
        future::zip(
            repo.send_with(server_in, server_out, access, opts),
            script(client),
        ),
    ))
}

/// The wire code that a failed session returned to its caller.
fn returned_code(result: &ostrya::Result<()>) -> Option<ErrorCode> {
    match result {
        Err(Error::Remote(e)) => e.code(),
        other => panic!("expected a push error, got {other:?}"),
    }
}

/// What the archive view serves for `path`.
async fn view_reply(view: &ArchiveView, path: &str) -> Reply {
    match view.get(path, &anyone()).await.unwrap() {
        ArchiveAnswer::Bytes(body) => Reply {
            found: true,
            len: Some(body.len() as u64),
            body,
        },
        ArchiveAnswer::Stream { len, mut body } => {
            let mut bytes = Vec::new();
            body.read_to_end(&mut bytes).await.unwrap();
            Reply {
                found: true,
                len,
                body: bytes,
            }
        }
        ArchiveAnswer::NotFound | ArchiveAnswer::Refused | ArchiveAnswer::StaleSummary { .. } => {
            Reply::not_found()
        }
    }
}

// ---------------------------------------------------------------------------
// The served repositories.
// ---------------------------------------------------------------------------

/// The tree of [`build_tree`] and a file of 200,000 bytes that do not
/// compress, so its `.filez` is longer than one chunk in every mode.
fn source_tree(base: &Path) -> PathBuf {
    let src = build_tree(base);
    fs::write(src.join("noise"), noise(200_000, 7)).unwrap();
    src
}

/// Signs `commit` with ed25519, writes a summary and its signature, and writes
/// the delta files.
async fn decorate(path: &Path, repo: &Repo, commit: &Checksum) {
    let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
    repo.sign_commit(commit, &signer).await.unwrap();
    repo.regenerate_summary(&SummaryOptions {
        last_modified: Some(1_700_000_000),
        ..SummaryOptions::default()
    })
    .await
    .unwrap();
    repo.sign_summary(&signer).await.unwrap();
    write_delta_files(path);
}

fn write_delta_files(path: &Path) {
    for file in DELTA_FILES {
        let full = path.join(file);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(&full, format!("{file}\n")).unwrap();
    }
}

/// A `bare-split-xattrs` repository at `base/bare-split-xattrs` with the
/// commit of the `bare` repository `bare`. ostrya does not write this mode.
/// The function copies the metadata objects and the files at the root. It
/// writes each file object by hand with the same checksum.
async fn split_repo(base: &Path, bare_path: &Path, bare: &Repo, commit: &Checksum) -> PathBuf {
    let root = base.join(RepoMode::BareSplitXattrs.as_mode_str());
    Repo::create(&root, CreateOptions::new(RepoMode::BareSplitXattrs))
        .await
        .unwrap();
    let copy = |rel: &str| {
        let to = root.join(rel);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(bare_path.join(rel), to).unwrap();
    };
    let mut names: Vec<_> = bare
        .traverse_commit(commit, 0)
        .await
        .unwrap()
        .into_iter()
        .collect();
    names.push(ostrya::ObjectName::new(*commit, ObjectType::CommitMeta));
    for name in names {
        if name.ty != ObjectType::File {
            let rel = loose_path(&name.checksum, name.ty, RepoMode::Bare);
            copy(&format!("objects/{rel}"));
            continue;
        }
        let file = bare.load_file(&name.checksum).await.unwrap();
        let header = file.header();
        let mut payload = Vec::new();
        if let FileKind::Regular { .. } = file.kind {
            let mut reader = file.reader().await.unwrap();
            reader.read_to_end(&mut payload).await.unwrap();
        }
        let id = write_split_object(
            &root,
            header.mode,
            &header.symlink_target,
            &header.xattrs,
            &payload,
        );
        assert_eq!(id, name.checksum, "the hand-written split object");
    }
    // The summary of the `anonymous` item needs its `.access` file. Both
    // repositories have the implicit groups and no collection id, so the
    // file of the `bare` repository holds the digest of this one.
    let access = format!(
        "extensions/ostrya/summary/{}.access",
        Checksum::sha256(b"anonymous")
    );
    for rel in ["refs/heads/main", "summary", "summary.sig", &access] {
        copy(rel);
    }
    write_delta_files(&root);
    root
}

/// The paths a pull asks for: `config`, the summary and its signature, the
/// ref, each object of `commit`, its detached metadata, and the delta files.
async fn pull_paths(repo: &Repo, commit: &Checksum) -> Vec<String> {
    let mut paths: Vec<String> = ["config", "summary", "summary.sig", "refs/heads/main"]
        .map(str::to_owned)
        .to_vec();
    let mut names: Vec<_> = repo
        .traverse_commit(commit, 0)
        .await
        .unwrap()
        .into_iter()
        .collect();
    names.sort_by_key(|n| (n.ty as u8, n.checksum));
    for name in names {
        paths.push(object_path(name.ty, &name.checksum));
    }
    paths.push(object_path(ObjectType::CommitMeta, commit));
    paths.extend(DELTA_FILES.map(str::to_owned));
    paths
}

/// A repository of `mode` under `base` with one commit of a single file of
/// `len` bytes that do not compress. Returns the path, the handle, and the
/// checksum of the file object.
async fn large_object_repo(base: &Path, mode: RepoMode, len: usize) -> (PathBuf, Repo, Checksum) {
    let src = base.join(format!("src-{}", mode.as_mode_str()));
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("noise"), noise(len, 11)).unwrap();
    let path = base.join(mode.as_mode_str());
    let repo = Repo::create(&path, CreateOptions::new(mode)).await.unwrap();
    let commit = commit(&repo, &src).await;
    let [file] = file_objects(&repo, &commit).await[..] else {
        panic!("one file object");
    };
    (path, repo, file)
}

// ---------------------------------------------------------------------------
// The files of a commit.
// ---------------------------------------------------------------------------

/// A client that keeps 8 `Get` frames in flight fetches these paths from a
/// repository of each mode that ostrya reads:
///
/// - `config`, the summary and its signature, and the ref
/// - each object of a commit and its detached metadata
/// - the delta files
///
/// Each reply is what a second archive view serves for the path. The replies
/// come in the order of the `Get` frames, and the session ends without an
/// error.
#[test]
fn each_mode_serves_the_files_of_a_commit() {
    let tmp = TmpDir::new("send-modes");
    let src = source_tree(tmp.path());
    let mut served = Vec::new();
    block_on(async {
        let mut bare = None;
        for mode in WRITABLE {
            let (path, repo, commit) = repo_of(tmp.path(), mode, &src).await;
            decorate(&path, &repo, &commit).await;
            if mode == RepoMode::Bare {
                bare = Some((path.clone(), repo.clone(), commit));
            }
            served.push((mode, path, repo, commit));
        }
        let (bare_path, bare, commit) = bare.unwrap();
        let path = split_repo(tmp.path(), &bare_path, &bare, &commit).await;
        let repo = Repo::open(&path).await.unwrap();
        served.push((RepoMode::BareSplitXattrs, path, repo, commit));
    });

    for (mode, path, repo, commit) in served {
        let paths = block_on(pull_paths(&repo, &commit));
        let (result, (replies, peak)) = session(&repo, PIPE_CAP, |mut c| {
            let paths = paths.clone();
            async move {
                c.open().await;
                fetch(&mut c, &paths, 8).await
            }
        });
        result.unwrap();
        assert_eq!(peak, 8, "{mode:?}: the frames in flight");
        assert_eq!(replies.len(), paths.len());

        let view = ArchiveView::new(repo.clone());
        let mut large = 0;
        for (path_rel, reply) in paths.iter().zip(&replies) {
            let expected = block_on(view_reply(&view, path_rel));
            assert_eq!(reply, &expected, "{mode:?} {path_rel}");
            let delta = DELTA_FILES.contains(&path_rel.as_str());
            assert_eq!(
                reply.found,
                !delta || mode == RepoMode::Archive,
                "{mode:?} {path_rel}"
            );
            if path_rel.ends_with(".filez") && reply.body.len() > CHUNK {
                large += 1;
            }
            if path_rel.ends_with(".commit") || path_rel.ends_with(".commitmeta") {
                assert_eq!(reply.body, fs::read(path.join(path_rel)).unwrap());
            }
        }
        assert_eq!(replies[0].body, BASE_CONFIG, "{mode:?}");
        // The noise file and the file of 300,000 bytes.
        assert!(large >= 1, "{mode:?}: no .filez longer than one chunk");
    }
}

/// A path that the view refuses gets the reply of a path that is not found.
/// A path outside the view, or with nothing at it, gets the same reply. The
/// session continues after each of these replies.
#[test]
fn refused_and_absent_paths_get_the_not_found_reply() {
    let tmp = TmpDir::new("send-not-found");
    let src = build_tree(tmp.path());
    let (path, repo, commit) = block_on(repo_of(tmp.path(), RepoMode::BareUser, &src));
    std::os::unix::fs::symlink("/etc/passwd", path.join("refs/heads/abs")).unwrap();
    let file = block_on(file_objects(&repo, &commit))[0];
    let refused = [
        ".lock",
        "tmp/x",
        "state/x",
        "a/../config",
        "/config",
        "refs/heads/abs",
        "objects//x",
    ];
    let bare_file = format!(
        "objects/{}",
        loose_path(&file, ObjectType::File, RepoMode::BareUser)
    );
    let absent_commit = object_path(ObjectType::Commit, &Checksum::sha256(b"absent"));
    let absent = [
        "",
        "nothing",
        "refs/heads/absent",
        bare_file.as_str(),
        absent_commit.as_str(),
        DELTA_FILES[0],
    ];
    let view = ArchiveView::new(repo.clone());
    block_on(async {
        for p in refused {
            assert!(
                matches!(
                    view.get(p, &anyone()).await.unwrap(),
                    ArchiveAnswer::Refused
                ),
                "{p}"
            );
        }
        for p in absent {
            assert!(
                matches!(
                    view.get(p, &anyone()).await.unwrap(),
                    ArchiveAnswer::NotFound
                ),
                "{p}"
            );
        }
    });

    let mut paths: Vec<String> = refused
        .iter()
        .chain(&absent)
        .map(|p| p.to_string())
        .collect();
    paths.push("config".to_owned());
    let (result, replies) = session(&repo, PIPE_CAP, |mut c| {
        let paths = paths.clone();
        async move {
            c.open().await;
            fetch(&mut c, &paths, 4).await.0
        }
    });
    result.unwrap();
    let (last, rest) = replies.split_last().unwrap();
    for (p, reply) in paths.iter().zip(rest) {
        assert_eq!(reply, &Reply::not_found(), "{p}");
    }
    assert_eq!(last.body, BASE_CONFIG);
}

/// The server replies with the lower of the version of the client and its
/// own highest version, and continues at that version.
#[test]
fn a_later_version_gets_the_version_of_the_server() {
    let tmp = TmpDir::new("send-version");
    let src = build_tree(tmp.path());
    let (_, repo, _) = block_on(repo_of(tmp.path(), RepoMode::BareUser, &src));
    for version in [2, u32::MAX] {
        let (result, (hello, config)) = session(&repo, PIPE_CAP, |mut c| async move {
            let hello = c.hello(version).await;
            c.send(&Message::Get("config".to_owned())).await;
            let config = read_reply(&mut c.reader).await;
            (hello, config)
        });
        result.unwrap();
        assert_eq!(
            hello,
            Some(Message::PullHelloReply(PullHelloReply { version: 1 }))
        );
        assert_eq!(config.body, BASE_CONFIG);
    }
}

/// An empty input ends the session without an error. The session writes
/// nothing, flushes nothing, and does not close its output.
#[test]
fn an_empty_input_is_a_clean_end() {
    let tmp = TmpDir::new("send-empty");
    let repo = block_on(Repo::create(
        &tmp.path().join("repo"),
        CreateOptions::new(RepoMode::BareUser),
    ))
    .unwrap();
    let (result, out) = record(&repo, Vec::new());
    result.unwrap();
    assert!(out.events.is_empty(), "{:?}", out.events);
}

// ---------------------------------------------------------------------------
// The error codes.
// ---------------------------------------------------------------------------

/// `PullHello` of version 0 is `version-unsupported`.
#[test]
fn version_0_is_version_unsupported() {
    let tmp = TmpDir::new("send-version-0");
    let src = build_tree(tmp.path());
    let (_, repo, _) = block_on(repo_of(tmp.path(), RepoMode::BareUser, &src));
    let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
        c.send(&Message::PullHello(PullHello {
            version: 0,
            agent: None,
        }))
        .await;
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::VersionUnsupported);
    assert_eq!(returned_code(&result), Some(ErrorCode::VersionUnsupported));
}

/// A `Get` or a `ListRefs` before `PullHello`, a second `PullHello`, a
/// message kind of the push, and a message of the server from the client are
/// `protocol`.
#[test]
fn a_message_out_of_order_is_protocol() {
    let tmp = TmpDir::new("send-protocol");
    let src = build_tree(tmp.path());
    let (_, repo, _) = block_on(repo_of(tmp.path(), RepoMode::BareUser, &src));

    let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
        c.send(&Message::Get("config".to_owned())).await;
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Protocol);
    assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));

    let hello = Message::Hello(Hello {
        version: 1,
        agent: None,
        refs: vec!["main".to_owned()],
        collection: None,
        one_way: false,
    });
    let late = [
        hello.clone(),
        Message::ObjectsEnd,
        Message::Abort,
        Message::PullHello(PullHello {
            version: 1,
            agent: None,
        }),
        Message::PullHelloReply(PullHelloReply { version: 1 }),
        Message::GetReply(GetReply {
            found: false,
            len: None,
        }),
        Message::Error(ErrorMessage {
            code: ErrorCode::Internal,
            message: "x".to_owned(),
            missing: Vec::new(),
            current: None,
        }),
    ];
    for msg in late {
        let what = format!("{:?}", msg.kind());
        let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
            c.open().await;
            c.send(&msg).await;
            c.error().await
        });
        assert_eq!(error.code, ErrorCode::Protocol, "{what}");
        assert_eq!(returned_code(&result), Some(ErrorCode::Protocol), "{what}");
    }

    // A push kind as the first frame.
    let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
        c.send(&hello).await;
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Protocol);
    assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));

    // A `ListRefs` as the first frame.
    let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
        c.send(&Message::ListRefs(local_refs(Vec::new()))).await;
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Protocol);
    assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));
}

// ---------------------------------------------------------------------------
// The ref listing.
// ---------------------------------------------------------------------------

/// Returns the `ListRefs` request of the entries `refs` of the local refs,
/// with no `collections` key.
fn local_refs(refs: Vec<String>) -> ListRefsRequest {
    ListRefsRequest {
        refs,
        collections: None,
    }
}

/// Returns a repository with the refs `a/b`, `a/bc`, and `z` on one commit.
fn listing_repo(tmp: &TmpDir) -> Repo {
    let src = build_tree(tmp.path());
    let (_, repo, commit) = block_on(repo_of(tmp.path(), RepoMode::BareUser, &src));
    for name in ["a/b", "a/bc", "z"] {
        block_on(repo.set_ref_immediate(name, Some(&commit))).unwrap();
    }
    repo
}

/// Appends `groups` to the config of `repo`, and returns the repository
/// opened again.
fn with_groups(repo: &Repo, groups: &str) -> Repo {
    let config = repo.path().join("config");
    let mut text = fs::read_to_string(&config).unwrap();
    text.push_str(groups);
    fs::write(&config, text).unwrap();
    block_on(Repo::open(repo.path())).unwrap()
}

/// The client groups of the rights tests: `ssh:puller` reads the refs under
/// `a/`, and `ssh:all` reads each ref.
const PULLER_GROUPS: &str = "[ex-ostrya client \"puller\"]\nauth=ssh:puller\nallow=r:a/**\n\
                             [ex-ostrya client \"all\"]\nauth=ssh:all\nallow=r:**\n";

/// A session serves the refs that its item reads. Another ref gets the
/// reply of an absent path. An item with no summary gets the reply of an
/// absent path for `summary`.
#[test]
fn a_session_serves_the_refs_of_its_item() {
    let tmp = TmpDir::new("send-ref-rights");
    let repo = listing_repo(&tmp);
    block_on(repo.regenerate_summary(&SummaryOptions::default())).unwrap();
    let paths = ["refs/heads/a/b", "refs/heads/z", "summary", "config"];
    let fetch_all = |repo: &Repo, access: &ReadAccess| {
        let (result, replies) = session_as(repo, access, PIPE_CAP, |mut c| async move {
            c.open().await;
            fetch(&mut c, &paths.map(str::to_owned), 4).await.0
        });
        result.unwrap();
        replies
    };
    let open = fetch_all(&repo, &repo_access(&repo, "anonymous"));
    assert!(open.iter().all(|reply| reply.found), "{open:?}");

    let repo = with_groups(&repo, PULLER_GROUPS);
    let replies = fetch_all(&repo, &repo_access(&repo, "ssh:puller"));
    let found: Vec<bool> = replies.iter().map(|reply| reply.found).collect();
    assert_eq!(found, [true, false, false, true]);
    assert_eq!(
        replies[0].body,
        fs::read(repo.path().join("refs/heads/a/b")).unwrap()
    );
    assert_eq!(replies[1], Reply::not_found());
    let replies = fetch_all(&repo, &repo_access(&repo, "ssh:all"));
    let found: Vec<bool> = replies.iter().map(|reply| reply.found).collect();
    assert_eq!(found, [true, true, false, true]);
}

/// The listing of a `ListRefs` holds the refs that the item of the session
/// reads, and equals the listing that `build_ref_listing` builds with the
/// same rights. A ref that the item cannot read is not read, so a broken
/// ref of that kind does not fail the listing.
#[test]
fn list_refs_holds_the_readable_refs_alone() {
    let tmp = TmpDir::new("send-list-refs-rights");
    let repo = with_groups(&listing_repo(&tmp), PULLER_GROUPS);
    let missing = Checksum::from_bytes([7; 32]);
    block_on(repo.set_ref_immediate("broken", Some(&missing))).unwrap();
    let access = repo_access(&repo, "ssh:puller");
    let (result, reply) = session_as(&repo, &access, PIPE_CAP, |mut c| async move {
        c.open().await;
        c.send(&Message::ListRefs(local_refs(Vec::new()))).await;
        read_reply(&mut c.reader).await
    });
    result.unwrap();
    let selector = RefSelector::parse([]).unwrap();
    assert_eq!(
        reply.body,
        block_on(repo.build_ref_listing(&selector, None, &access))
            .unwrap()
            .bytes
    );
    let parsed = ostrya::Summary::parse(&reply.body).unwrap();
    let names: Vec<&str> = parsed.refs.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["a/b", "a/bc"]);

    let all = repo_access(&repo, "ssh:all");
    let (result, error) = session_as(&repo, &all, PIPE_CAP, |mut c| async move {
        c.open().await;
        c.send(&Message::ListRefs(local_refs(Vec::new()))).await;
        c.error().await
    });
    assert!(
        matches!(result, Err(Error::ObjectNotFound { .. })),
        "{result:?}"
    );
    assert_eq!(error.code, ErrorCode::Internal);
}

/// The session answers each `ListRefs` with a found reply that states the
/// length of the listing, and the body is the listing that
/// `build_ref_listing` builds. A `Get` between two `ListRefs` keeps its
/// place.
#[test]
fn list_refs_answers_with_the_built_listing() {
    let tmp = TmpDir::new("send-list-refs");
    let repo = listing_repo(&tmp);
    let (result, replies) = session(&repo, PIPE_CAP, |mut c| async move {
        c.open().await;
        c.send(&Message::ListRefs(local_refs(vec!["a/b".to_owned()])))
            .await;
        c.send(&Message::Get("config".to_owned())).await;
        c.send(&Message::ListRefs(local_refs(Vec::new()))).await;
        let mut replies = Vec::new();
        for _ in 0..3 {
            replies.push(read_reply(&mut c.reader).await);
        }
        replies
    });
    result.unwrap();
    for (reply, entries) in [(&replies[0], &["a/b"][..]), (&replies[2], &[])] {
        let selector = RefSelector::parse(entries.iter().copied()).unwrap();
        let listing = block_on(repo.build_ref_listing(&selector, None, &anyone()))
            .unwrap()
            .bytes;
        assert!(reply.found, "{entries:?}");
        assert_eq!(reply.len, Some(listing.len() as u64), "{entries:?}");
        assert_eq!(reply.body, listing, "{entries:?}");
    }
    assert_eq!(replies[1].body, BASE_CONFIG);
    let one = ostrya::Summary::parse(&replies[0].body).unwrap();
    let names: Vec<&str> = one.refs.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["a/b"]);
}

/// Each entry of a `ListRefs` is a ref pattern with an optional `!`. The
/// listing holds the refs that the selector of the entries selects: a
/// wildcard, a negative entry, and a mixed list.
#[test]
fn list_refs_selects_refs_by_pattern() {
    let tmp = TmpDir::new("send-list-refs-patterns");
    let repo = listing_repo(&tmp);
    let cases: [(&[&str], &[&str]); 6] = [
        (&["a/*"], &["a/b", "a/bc"]),
        (&["a/**"], &["a/b", "a/bc"]),
        (&["*"], &["main", "z"]),
        (&["!a/**"], &["main", "z"]),
        (&["a/**", "!a/bc"], &["a/b"]),
        (&["a/b", "a/b", "z"], &["a/b", "z"]),
    ];
    for (entries, want) in cases {
        let entries: Vec<String> = entries.iter().map(|e| (*e).to_owned()).collect();
        let sent = entries.clone();
        let (result, reply) = session(&repo, PIPE_CAP, |mut c| async move {
            c.open().await;
            c.send(&Message::ListRefs(local_refs(sent))).await;
            read_reply(&mut c.reader).await
        });
        result.unwrap();
        let selector = RefSelector::parse(entries.iter().map(String::as_str)).unwrap();
        assert_eq!(
            reply.body,
            block_on(repo.build_ref_listing(&selector, None, &anyone()))
                .unwrap()
                .bytes
        );
        let parsed = ostrya::Summary::parse(&reply.body).unwrap();
        let names: Vec<&str> = parsed.refs.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, want, "{entries:?}");
    }
}

/// An entry that is not a ref pattern is `protocol`, and the error names the
/// entry. The session sends no reply before the `Error` message.
#[test]
fn list_refs_with_a_bad_prefix_is_protocol() {
    let tmp = TmpDir::new("send-list-refs-bad");
    let repo = listing_repo(&tmp);
    for bad in [
        "", "/", "a/../b", "a/", "/a", "a b", "-a", "a*", "a/.b", "!!a", "!", "**x", "a//b",
        "a/***", "a!", "a/!b",
    ] {
        let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
            c.open().await;
            c.send(&Message::ListRefs(local_refs(vec![
                "z".to_owned(),
                bad.to_owned(),
            ])))
            .await;
            c.error().await
        });
        assert_eq!(error.code, ErrorCode::Protocol, "{bad:?}");
        assert!(error.message.contains(&format!("{bad:?}")), "{error:?}");
        assert_eq!(returned_code(&result), Some(ErrorCode::Protocol), "{bad:?}");
    }
}

/// An entry of more than 256 parts or 4096 bytes is `protocol`, and the
/// limits pass. The check comes before the parse: an entry over a limit with
/// a bad text gets the same refusal, and its message holds no parse reason.
#[test]
fn list_refs_over_the_entry_limits_is_protocol() {
    let tmp = TmpDir::new("send-list-refs-entry");
    let repo = listing_repo(&tmp);
    let parts = |n: usize| vec!["a"; n].join("/");
    for ok in [
        parts(ostrya::MAX_REF_ENTRY_PARTS),
        "a".repeat(ostrya::MAX_REF_ENTRY_LEN),
        format!("!{}", "a".repeat(ostrya::MAX_REF_ENTRY_LEN - 1)),
    ] {
        let (result, reply) = session(&repo, PIPE_CAP, |mut c| async move {
            c.open().await;
            c.send(&Message::ListRefs(local_refs(vec![ok]))).await;
            read_reply(&mut c.reader).await
        });
        result.unwrap();
        assert!(reply.found);
    }
    for bad in [
        parts(ostrya::MAX_REF_ENTRY_PARTS + 1),
        "a".repeat(ostrya::MAX_REF_ENTRY_LEN + 1),
        format!("!{}", "a".repeat(ostrya::MAX_REF_ENTRY_LEN)),
        "/".repeat(300),
        "*".repeat(5000),
    ] {
        let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
            c.open().await;
            c.send(&Message::ListRefs(local_refs(vec!["z".to_owned(), bad])))
                .await;
            c.error().await
        });
        assert_eq!(error.code, ErrorCode::Protocol);
        assert!(error.message.contains("over the limit"), "{error:?}");
        assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));
    }
}

/// A `ListRefs` with more than `MAX_REF_PATTERNS` entries is `protocol`.
/// Positive and negative entries count together, an entry given two times
/// counts two times, and the limit itself passes.
#[test]
fn list_refs_over_the_entry_count_limit_is_protocol() {
    let tmp = TmpDir::new("send-list-refs-many");
    let repo = listing_repo(&tmp);
    let mixed = |count: usize| -> Vec<String> {
        (0..count)
            .map(|n| if n % 2 == 0 { "a/b" } else { "!a/b" }.to_owned())
            .collect()
    };
    let (result, reply) = session(&repo, PIPE_CAP, |mut c| async move {
        c.open().await;
        c.send(&Message::ListRefs(local_refs(mixed(
            ostrya::MAX_REF_PATTERNS,
        ))))
        .await;
        read_reply(&mut c.reader).await
    });
    result.unwrap();
    assert!(reply.found);
    let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
        c.open().await;
        c.send(&Message::ListRefs(local_refs(mixed(
            ostrya::MAX_REF_PATTERNS + 1,
        ))))
        .await;
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Protocol);
    assert!(error.message.contains("over the limit of 256"), "{error:?}");
    assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));
}

/// A failure of the build of the listing is `internal` on the wire, and
/// `send` returns the error of the build.
#[test]
fn list_refs_with_a_failed_build_is_internal() {
    let tmp = TmpDir::new("send-list-refs-internal");
    let repo = listing_repo(&tmp);
    std::fs::write(
        repo.path().join("refs/heads/x"),
        format!("{}\n", "ab".repeat(32)),
    )
    .unwrap();
    let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
        c.open().await;
        c.send(&Message::ListRefs(local_refs(vec!["x".to_owned()])))
            .await;
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Internal);
    assert!(
        matches!(result, Err(Error::ObjectNotFound { .. })),
        "{result:?}"
    );
}

/// Returns the `ListRefs` request of the entries `refs` of the local refs
/// and of the entries `collections` of the collection refs.
fn both_lists(refs: &[&str], collections: Option<&[&str]>) -> ListRefsRequest {
    let entries = |list: &[&str]| list.iter().map(|e| (*e).to_owned()).collect();
    ListRefsRequest {
        refs: entries(refs),
        collections: collections.map(entries),
    }
}

/// Returns the listing repository with the mirror refs `org.a/x`,
/// `org.a/y/z`, and `org.b/main`.
fn mirror_repo(tmp: &TmpDir) -> Repo {
    let repo = listing_repo(tmp);
    let commit = block_on(repo.resolve_rev("z", false)).unwrap().unwrap();
    for (id, name) in [("org.a", "x"), ("org.a", "y/z"), ("org.b", "main")] {
        let cref = ostrya::CollectionRef::new(id, name);
        block_on(repo.set_collection_ref_immediate(&cref, Some(&commit))).unwrap();
    }
    repo
}

/// A `ListRefs` with the key `collections` gets the listing that
/// `build_ref_listing` builds for the two lists, and a `ListRefs` with no
/// key gets the listing of the local refs alone.
#[test]
fn list_refs_with_collections_answers_with_the_built_listing() {
    let tmp = TmpDir::new("send-list-refs-collections");
    let repo = mirror_repo(&tmp);
    let cases: [(&[&str], Option<&[&str]>); 5] = [
        (&[], Some(&[])),
        (&["a/**"], Some(&["org.a/**"])),
        (&["!**"], Some(&["*/main", "!org.b/**"])),
        (&[], Some(&["org.a"])),
        (&["z"], None),
    ];
    let requests: Vec<ListRefsRequest> = cases
        .iter()
        .map(|(refs, collections)| both_lists(refs, *collections))
        .collect();
    let sent = requests.clone();
    let (result, replies) = session(&repo, PIPE_CAP, |mut c| async move {
        c.open().await;
        let mut replies = Vec::new();
        for request in sent {
            c.send(&Message::ListRefs(request)).await;
            replies.push(read_reply(&mut c.reader).await);
        }
        replies
    });
    result.unwrap();
    for ((refs, collections), reply) in cases.iter().zip(&replies) {
        let collections = collections.map(|entries| RefSelector::parse(entries.iter().copied()));
        let collections = collections.transpose().unwrap();
        let refs_selector = RefSelector::parse(refs.iter().copied()).unwrap();
        let want =
            block_on(repo.build_ref_listing(&refs_selector, collections.as_ref(), &anyone()))
                .unwrap()
                .bytes;
        assert!(reply.found, "{refs:?}");
        assert_eq!(reply.body, want, "{refs:?} {collections:?}");
    }
    let map = ostrya::Summary::parse(&replies[1].body)
        .unwrap()
        .collection_map()
        .unwrap();
    let ids: Vec<&str> = map.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["org.a"]);
    assert_eq!(map[0].1.len(), 2);
    let plain =
        block_on(repo.build_ref_listing(&RefSelector::parse(["z"]).unwrap(), None, &anyone()));
    assert_eq!(replies[4].body, plain.unwrap().bytes);
}

/// The two lists of a `ListRefs` share the limit of 256 entries: 128 and 128
/// pass, and 129 and 128 are `protocol`. A bad entry under `collections`,
/// and an entry there over the limits of one entry, are `protocol`, and the
/// message of each names the key.
#[test]
fn list_refs_lists_share_the_limits_of_a_request() {
    let tmp = TmpDir::new("send-list-refs-shared-limit");
    let repo = mirror_repo(&tmp);
    let names = |count: usize, prefix: &str| -> Vec<String> {
        (0..count).map(|n| format!("{prefix}{n}")).collect()
    };
    let request = |refs: usize, collections: usize| ListRefsRequest {
        refs: names(refs, "r"),
        collections: Some(names(collections, "org.a/c")),
    };
    let (result, reply) = session(&repo, PIPE_CAP, |mut c| async move {
        c.open().await;
        c.send(&Message::ListRefs(request(128, 128))).await;
        read_reply(&mut c.reader).await
    });
    result.unwrap();
    assert!(reply.found);
    let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
        c.open().await;
        c.send(&Message::ListRefs(request(129, 128))).await;
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Protocol);
    assert!(error.message.contains("over the limit of 256"), "{error:?}");
    assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));

    for (bad, says) in [
        ("a//b".to_owned(), "collections"),
        ("!!a".to_owned(), "collections"),
        (
            "a".repeat(ostrya::MAX_REF_ENTRY_LEN + 1),
            "ListRefs: collections: an entry of",
        ),
        (
            vec!["a"; ostrya::MAX_REF_ENTRY_PARTS + 1].join("/"),
            "ListRefs: collections: an entry of",
        ),
    ] {
        let sent = both_lists(&["z"], Some(&["org.a/**", &bad]));
        let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
            c.open().await;
            c.send(&Message::ListRefs(sent)).await;
            c.error().await
        });
        assert_eq!(error.code, ErrorCode::Protocol, "{bad}");
        assert!(error.message.contains(says), "{error:?}");
        assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));
    }
}

/// A session reports each directory under `refs/mirrors/` whose name is not
/// a collection id one time, at the first listing with the key
/// `collections`. A listing with no key reads no such directory. Each
/// session reports again, and a session with no callback runs as `send`
/// does.
#[test]
fn an_invalid_collection_dir_is_reported_one_time_in_a_session() {
    let tmp = TmpDir::new("send-invalid-collection-dir");
    let repo = mirror_repo(&tmp);
    for path in ["bad/x", "a..b/main"] {
        let file = repo.path().join("refs/mirrors").join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(
            file,
            "no checksum
",
        )
        .unwrap();
    }
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = seen.clone();
    let mut opts = ostrya::SendOptions::default();
    opts.on_event = Some(std::sync::Arc::new(move |event: &ostrya::SendEvent| {
        sink.lock().unwrap().push(event.to_string());
    }));
    let script = |mut c: Client| async move {
        c.open().await;
        let mut replies = Vec::new();
        for request in [
            both_lists(&[], None),
            both_lists(&[], Some(&[])),
            both_lists(&[], Some(&["org.a/**"])),
        ] {
            c.send(&Message::ListRefs(request)).await;
            replies.push(read_reply(&mut c.reader).await);
        }
        replies
    };
    let access = anyone();
    let (result, replies) = session_with(&repo, &access, &opts, PIPE_CAP, script);
    result.unwrap();
    assert!(replies.iter().all(|reply| reply.found));
    let line = |name: &str| {
        format!(
            "refs/mirrors/{name}: the directory name is not a collection id, and the ref \
             listing leaves out the directory"
        )
    };
    assert_eq!(*seen.lock().unwrap(), [line("a..b"), line("bad")]);
    let (result, _) = session_with(&repo, &access, &opts, PIPE_CAP, script);
    result.unwrap();
    assert_eq!(seen.lock().unwrap().len(), 4);
    let (result, plain) = session(&repo, PIPE_CAP, script);
    result.unwrap();
    assert_eq!(plain, replies);
}

/// A session serves the summary of the item of its client. When the
/// `.access` file of the item does not match, `summary` and `summary.sig`
/// are absent, and the session reports one `StaleSummary` event, which is no
/// warning.
#[test]
fn a_session_serves_the_summary_of_its_item() {
    let tmp = TmpDir::new("send-item-summary");
    let src = build_tree(tmp.path());
    let repo = block_on(async {
        let (path, _, _) = repo_of(tmp.path(), RepoMode::Archive, &src).await;
        let mut text = fs::read_to_string(path.join("config")).unwrap();
        text.push_str("[ex-ostrya client \"ci\"]\nauth=ssh:ci\nallow=r:**\nsummary=true\n");
        fs::write(path.join("config"), text).unwrap();
        let repo = Repo::open(&path).await.unwrap();
        repo.regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        repo
    });
    let stem = Checksum::sha256(b"ssh:ci");
    let stored = fs::read(
        repo.path()
            .join(format!("extensions/ostrya/summary/{stem}")),
    )
    .unwrap();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = seen.clone();
    let mut opts = ostrya::SendOptions::default();
    opts.on_event = Some(std::sync::Arc::new(move |event: &ostrya::SendEvent| {
        sink.lock().unwrap().push(event.clone());
    }));
    let script = |mut c: Client| async move {
        c.open().await;
        let mut replies = Vec::new();
        for path in ["summary", "summary.sig", "summary"] {
            c.send(&Message::Get(path.to_owned())).await;
            replies.push(read_reply(&mut c.reader).await);
        }
        replies
    };
    let access = repo_access(&repo, "ssh:ci");
    let (result, replies) = session_with(&repo, &access, &opts, PIPE_CAP, script);
    result.unwrap();
    assert_eq!(replies[0].body, stored);
    assert!(!replies[1].found, "no signature file");
    assert!(seen.lock().unwrap().is_empty());

    fs::remove_file(
        repo.path()
            .join(format!("extensions/ostrya/summary/{stem}.access")),
    )
    .unwrap();
    let (result, replies) = session_with(&repo, &access, &opts, PIPE_CAP, script);
    result.unwrap();
    assert!(replies.iter().all(|reply| !reply.found));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(!seen[0].is_warning());
    assert_eq!(
        seen[0].to_string(),
        "the summary of the auth item ssh:ci does not match the client groups, and the \
         session does not serve it; run `ostrya summary -u`"
    );
}

/// An end of the input inside a frame is `protocol`./// An end of the input inside a frame is `protocol`.
#[test]
fn an_end_inside_a_frame_is_protocol() {
    let tmp = TmpDir::new("send-eof");
    let src = build_tree(tmp.path());
    let (_, repo, _) = block_on(repo_of(tmp.path(), RepoMode::BareUser, &src));
    for partial in [&[0u8, 0][..], &[0, 0, 0, 7, 14, b'c'][..]] {
        let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
            c.open().await;
            let mut reader = c.raw(partial).await;
            let error = match reader.read_message().await.unwrap() {
                Some(Message::Error(e)) => e,
                other => panic!("expected Error, got {other:?}"),
            };
            assert_eq!(reader.read_message().await.unwrap(), None);
            error
        });
        assert_eq!(error.code, ErrorCode::Protocol);
        assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));
    }
}

/// A frame from the client over 1 MiB is `limit-exceeded`.
#[test]
fn a_frame_over_the_limit_is_limit_exceeded() {
    let tmp = TmpDir::new("send-limit");
    let src = build_tree(tmp.path());
    let (_, repo, _) = block_on(repo_of(tmp.path(), RepoMode::BareUser, &src));
    let mut head = (MIN_FRAME_LIMIT + 1).to_be_bytes().to_vec();
    head.push(14);
    let (result, error) = session(&repo, PIPE_CAP, |mut c| async move {
        c.open().await;
        let mut reader = c.raw(&head).await;
        match reader.read_message().await.unwrap() {
            Some(Message::Error(e)) => e,
            other => panic!("expected Error, got {other:?}"),
        }
    });
    assert_eq!(error.code, ErrorCode::LimitExceeded);
    assert_eq!(returned_code(&result), Some(ErrorCode::LimitExceeded));
}

/// Asks for `path` after `PullHello`, and expects `Error` with `internal` and
/// no `GetReply` before it. The session returns the error of the view.
fn assert_internal_before_the_reply(repo: &Repo, path: &str) -> Error {
    let path = path.to_owned();
    let (result, error) = session(repo, PIPE_CAP, |mut c| async move {
        c.open().await;
        c.send(&Message::Get(path)).await;
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Internal);
    let err = result.unwrap_err();
    assert!(!matches!(err, Error::Remote(_)), "{err:?}");
    err
}

/// A content object that the server cannot read gets `Error` with
/// `internal` and no `GetReply`. This is also true when the server runs as
/// root. The test uses two objects:
///
/// - a `bare-user` object whose `user.ostreemeta` does not parse
/// - a `bare-split-xattrs` object whose extended attributes do not parse
#[test]
fn an_object_that_does_not_load_is_internal_before_its_reply() {
    let tmp = TmpDir::new("send-internal");
    let src = build_tree(tmp.path());
    let (path, repo, commit) = block_on(repo_of(tmp.path(), RepoMode::BareUser, &src));
    let file = block_on(file_objects(&repo, &commit))[0];
    let stored = path
        .join("objects")
        .join(loose_path(&file, ObjectType::File, RepoMode::BareUser));
    rustix::fs::lsetxattr(
        &stored,
        "user.ostreemeta",
        b"\xff",
        rustix::fs::XattrFlags::REPLACE,
    )
    .unwrap();
    assert_internal_before_the_reply(&repo, &object_path(ObjectType::File, &file));

    let root = tmp.path().join("split");
    let repo = block_on(Repo::create(
        &root,
        CreateOptions::new(RepoMode::BareSplitXattrs),
    ))
    .unwrap();
    let demo = Xattrs::new([(b"user.demo\0".to_vec(), b"x".to_vec())]).unwrap();
    let id = write_split_object(&root, 0o100644, "", &demo, b"payload\n");
    let link = root.join("objects").join(loose_path(
        &id,
        ObjectType::FileXattrsLink,
        RepoMode::BareSplitXattrs,
    ));
    fs::remove_file(&link).unwrap();
    fs::write(&link, b"\xff").unwrap();
    assert_internal_before_the_reply(&repo, &object_path(ObjectType::File, &id));
}

/// A file that the serving account cannot read (`EACCES`) gets `Error` with
/// `internal` and no `GetReply`. The test uses a content object and a stored
/// file. Root reads every file, so the test does not run as root.
#[test]
fn a_file_the_account_cannot_read_is_internal_before_its_reply() {
    if is_root() {
        eprintln!("skipping: root reads a file of mode 0000");
        return;
    }
    let tmp = TmpDir::new("send-eacces");
    let src = build_tree(tmp.path());
    let (path, repo, commit) = block_on(repo_of(tmp.path(), RepoMode::BareUser, &src));
    let file = block_on(file_objects(&repo, &commit))[0];
    for (ty, checksum) in [(ObjectType::File, file), (ObjectType::Commit, commit)] {
        let stored = path
            .join("objects")
            .join(loose_path(&checksum, ty, RepoMode::BareUser));
        let before = fs::metadata(&stored).unwrap().permissions();
        fs::set_permissions(&stored, fs::Permissions::from_mode(0o000)).unwrap();
        let err = assert_internal_before_the_reply(&repo, &object_path(ty, &checksum));
        fs::set_permissions(&stored, before).unwrap();
        assert!(
            matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::PermissionDenied),
            "{ty:?}: {err:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// A body that fails after its reply.
// ---------------------------------------------------------------------------

/// The test truncates a content object of 4 MiB to 2 MiB after the head of
/// its reply arrives. The body ends with the abandon marker and `Error` with
/// `internal`. The pipes hold 64 KiB, so the server waits for the client
/// before it reads past the buffers on the path. These buffers include the
/// read-ahead of the file reader.
#[test]
fn a_content_object_truncated_after_its_reply_is_abandoned() {
    let tmp = TmpDir::new("send-truncated");
    let full = 4 * 1024 * 1024;
    for mode in [RepoMode::Archive, RepoMode::BareUser] {
        let (path, repo, file) = block_on(large_object_repo(tmp.path(), mode, full));
        let stored = path
            .join("objects")
            .join(loose_path(&file, ObjectType::File, mode));
        let filez = object_path(ObjectType::File, &file);
        let (result, (len, got, error)) = session(&repo, PIPE_CAP, |mut c| async move {
            c.open().await;
            c.send(&Message::Get(filez)).await;
            let len = match c.recv().await {
                Some(Message::GetReply(GetReply { found: true, len })) => len,
                other => panic!("expected a found GetReply, got {other:?}"),
            };
            fs::OpenOptions::new()
                .write(true)
                .open(&stored)
                .unwrap()
                .set_len(full as u64 / 2)
                .unwrap();
            let mut buf = vec![0u8; 100_000];
            let mut got = 0;
            let error = loop {
                match c.reader.read_object_data(&mut buf).await {
                    Ok(ObjectRead::Data(n)) => got += n,
                    Ok(other) => panic!("the body ended with {other:?}"),
                    Err(e) => break e,
                }
            };
            assert_eq!(c.recv().await, None, "the session ends after Error");
            (len, got, error)
        });
        assert_eq!(error.code(), Some(ErrorCode::Internal), "{mode:?}");
        assert!(got < full, "{mode:?}: {got} bytes");
        let err = result.unwrap_err();
        match mode {
            RepoMode::Archive => {
                assert!(len.unwrap() > full as u64, "{len:?}");
                assert!(
                    matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof),
                    "{err:?}"
                );
            }
            _ => {
                assert_eq!(len, None);
                assert!(matches!(&err, Error::Io(_)), "{err:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The writes and the flushes.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Write(usize),
    Flush,
    Close,
}

/// An output that takes every write whole and records each call.
#[derive(Default)]
struct Recorder {
    events: Vec<Event>,
    bytes: Vec<u8>,
}

impl AsyncWrite for Recorder {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.events.push(Event::Write(buf.len()));
        self.bytes.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.events.push(Event::Flush);
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.events.push(Event::Close);
        Poll::Ready(Ok(()))
    }
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

/// `PullHello` and a `Get` of each of `paths`, in one buffer.
fn requests(paths: &[String]) -> Vec<u8> {
    let mut msgs = vec![Message::PullHello(PullHello {
        version: 1,
        agent: None,
    })];
    msgs.extend(paths.iter().map(|p| Message::Get(p.clone())));
    frames(&msgs)
}

/// Runs a session of `repo` over the input `input` and a recording output.
fn record(repo: &Repo, input: Vec<u8>) -> (ostrya::Result<()>, Recorder) {
    let mut out = Recorder::default();
    let result = block_on(within(
        LIMIT,
        "the session",
        repo.send(
            Cursor::new(input),
            &mut out,
            &repo_access(repo, "anonymous"),
        ),
    ));
    (result, out)
}

/// The chunk lengths of the body that starts at `at` in `bytes`, up to and
/// with the chunk of length 0, and the offset after it.
fn chunks_at(bytes: &[u8], mut at: usize) -> (Vec<usize>, usize) {
    let mut lengths = Vec::new();
    loop {
        let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        at += 4 + len;
        lengths.push(len);
        if len == 0 {
            return (lengths, at);
        }
    }
}

/// The length of the frame at `at` in `bytes` with its prefix.
fn frame_len(bytes: &[u8], at: usize) -> usize {
    4 + u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

/// The test serves a content object of 4 MiB that does not compress from an
/// `archive` and from a `bare-user` repository. For each mode:
///
/// - each write to the output is at most 64 KiB
/// - no write holds a chunk length alone
/// - each chunk but the last is full
/// - the session flushes once, after the reply
#[test]
fn each_write_is_at_most_64_kib_and_holds_no_length_alone() {
    let tmp = TmpDir::new("send-writes");
    for mode in [RepoMode::Archive, RepoMode::BareUser] {
        let (_, repo, file) = block_on(large_object_repo(tmp.path(), mode, 4 * 1024 * 1024));
        let filez = object_path(ObjectType::File, &file);
        let (result, out) = record(&repo, requests(std::slice::from_ref(&filez)));
        result.unwrap();

        for event in &out.events {
            if let Event::Write(n) = *event {
                assert!(n <= 64 * 1024, "{mode:?}: a write of {n} bytes");
                assert_ne!(n, 4, "{mode:?}: a write of a chunk length alone");
            }
        }
        assert_eq!(
            out.events.iter().filter(|e| **e == Event::Flush).count(),
            1,
            "{mode:?}"
        );
        assert_eq!(out.events.last(), Some(&Event::Flush), "{mode:?}");

        let at = frame_len(&out.bytes, 0);
        let at = at + frame_len(&out.bytes, at);
        let (lengths, end) = chunks_at(&out.bytes, at);
        assert_eq!(end, out.bytes.len());
        let (last_data, full) = lengths[..lengths.len() - 1].split_last().unwrap();
        assert!(full.len() >= 64, "{mode:?}: {} chunks", lengths.len());
        assert!(full.iter().all(|n| *n == CHUNK), "{mode:?}");
        assert!(*last_data > 0 && *last_data <= CHUNK, "{mode:?}");

        let view = ArchiveView::new(repo.clone());
        let expected = block_on(view_reply(&view, &filez));
        assert_eq!(
            lengths.iter().sum::<usize>(),
            expected.body.len(),
            "{mode:?}"
        );
    }
}

/// `PullHello` and 8 `Get` frames that wait in the input buffer get one
/// flush, after the eighth reply. The end of the input adds none.
#[test]
fn eight_gets_in_the_input_buffer_get_one_flush() {
    let tmp = TmpDir::new("send-flush");
    let src = build_tree(tmp.path());
    let (_, repo, commit) = block_on(repo_of(tmp.path(), RepoMode::BareUser, &src));
    let mut paths: Vec<String> = ["config", "nothing", "refs/heads/main"]
        .map(str::to_owned)
        .to_vec();
    for name in block_on(repo.traverse_commit(&commit, 0)).unwrap() {
        paths.push(object_path(name.ty, &name.checksum));
    }
    paths.truncate(8);
    assert_eq!(paths.len(), 8);
    let (result, out) = record(&repo, requests(&paths));
    result.unwrap();
    assert_eq!(
        out.events.iter().filter(|e| **e == Event::Flush).count(),
        1,
        "{:?}",
        out.events
    );
    assert_eq!(out.events.last(), Some(&Event::Flush));

    let mut reader = FrameReader::new(&out.bytes[..]);
    block_on(async {
        assert_eq!(
            reader.read_message().await.unwrap(),
            Some(Message::PullHelloReply(PullHelloReply { version: 1 }))
        );
        for p in &paths {
            let found = match reader.read_message().await.unwrap() {
                Some(Message::GetReply(GetReply { found, .. })) => found,
                other => panic!("{p}: expected GetReply, got {other:?}"),
            };
            assert_eq!(found, p != "nothing", "{p}");
            if found {
                let mut buf = vec![0u8; 65_536];
                while let ObjectRead::Data(_) = reader.read_object_data(&mut buf).await.unwrap() {}
            }
        }
        assert_eq!(reader.read_message().await.unwrap(), None);
    });
}
