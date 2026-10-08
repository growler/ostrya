//! Tests of `Repo::receive_stream`: one one-way stream into one transaction,
//! and the refusal of a one-way `Hello` by the two-way receiver.
//!
//! The tests write each stream by hand with the frame codec of
//! `ostrya::push::proto`. A stream carries the objects of the golden fixture
//! commit, which binds the ref `test/main`. A stream that commits runs through
//! an in-process pipe. The receiver reads a stream that fails from a byte
//! buffer, so a test can cut the stream or change a byte.

#![cfg(feature = "receive")]

mod common;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use common::receive::{
    Obj, PIPE_CAP, assert_nothing_published, fixture_objects, new_repo, pipe, returned_code,
    session, staging_entries,
};
use common::{COMMIT, TmpDir, file_inventory, foreign_holder, lock_holder_main, tool_fsck};
use futures_io::AsyncWrite;
use futures_lite::io::AsyncWriteExt;
use ostrya::push::proto::{CommitRequest, FrameWriter, Hello, Message, ObjectHeader};
use ostrya::push::{self, Encoding, ErrorCode, Expected, RefOutcome, RefUpdate};
use ostrya::{
    Checksum, DictBuilder, Error, FsckOptions, MAX_METADATA_SIZE, ObjectName, ObjectType,
    ReceivePolicy, ReceiveReport, ReceiveRule, ReceiveService, RefPattern, Repo, RepoMode,
    ServerSigner, Type,
};
use ostrya_rt::block_on;

/// The ed25519 secret key of a server signer.
const SERVER_SECRET_B64: &str =
    "Rdkqts/v6AXV6N+XOTlBGoGiItwTHGWaip72oFWzQDDMGsL2Sdl/Bcj+xg4EA2iJqHUuBsmdnNCFKNZMBqTiFw==";

const ED25519_KEY: &str = "ostree.sign.ed25519";

#[test]
#[ignore = "helper process for the lock tests"]
fn lock_holder_subprocess() {
    lock_holder_main();
}

fn fixture_commit() -> Checksum {
    Checksum::from_hex(COMMIT).unwrap()
}

fn update(name: &str, expected: Expected, new: Option<Checksum>) -> RefUpdate {
    RefUpdate {
        name: name.into(),
        expected,
        new,
    }
}

/// The two updates of a stream of the fixture commit: a plain ref and a
/// remote ref.
fn updates() -> Vec<RefUpdate> {
    vec![
        update("test/main", Expected::Absent, Some(fixture_commit())),
        update("origin:test/main", Expected::Any, Some(fixture_commit())),
    ]
}

/// The detached metadata of the fixture commit that a stream carries.
fn detached_meta() -> Vec<u8> {
    let mut dict = DictBuilder::new();
    dict.insert_str("k", "v");
    ostrya_core::to_bytes(&Type::parse("a{sv}").unwrap(), &dict.build()).unwrap()
}

/// A policy that accepts every remote ref, with a server key on each rule, a
/// summary key, and summary regeneration. The one-way receiver ignores the
/// keys and the summary step.
fn policy() -> ReceivePolicy {
    let secret = ostrya::base64::decode(SERVER_SECRET_B64).unwrap();
    let signer = Arc::new(ServerSigner::ed25519(&secret).unwrap());
    let rule = ReceiveRule {
        signers: vec![signer.clone()],
        ..ReceiveRule::default()
    };
    ReceivePolicy {
        default_rule: rule.clone(),
        rules: vec![(RefPattern::parse("*:*").unwrap(), rule)],
        summary_signers: vec![signer],
        update_summary: true,
        ..ReceivePolicy::default()
    }
}

// ---------------------------------------------------------------------------
// The stream.
// ---------------------------------------------------------------------------

/// A sink that keeps the offset after each write. The frame writer writes a
/// frame in one write and a chunk in two writes. The offsets are the
/// boundaries of each frame, each chunk length, and each chunk.
#[derive(Default)]
struct Recorder {
    bytes: Vec<u8>,
    marks: Vec<usize>,
}

impl AsyncWrite for Recorder {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        me.bytes.extend_from_slice(buf);
        me.marks.push(me.bytes.len());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A one-way stream written by hand.
struct Stream {
    writer: FrameWriter<Recorder>,
}

impl Stream {
    /// A stream that starts with `Hello` for `refs`, with `one-way` set to
    /// `one_way`.
    fn hello(refs: &[&str], one_way: bool) -> Stream {
        let mut stream = Stream {
            writer: FrameWriter::new(Recorder::default()),
        };
        stream.message(&Message::Hello(Hello {
            version: 1,
            agent: None,
            refs: refs.iter().map(|r| r.to_string()).collect(),
            one_way,
        }));
        stream
    }

    /// A one-way `Hello` for the refs of [`updates`].
    fn new() -> Stream {
        Stream::hello(&["test/main", "origin:test/main"], true)
    }

    fn message(&mut self, msg: &Message) -> &mut Stream {
        block_on(self.writer.write_message(msg)).unwrap();
        self
    }

    fn header(&mut self, o: &Obj) -> &mut Stream {
        self.message(&Message::ObjectHeader(ObjectHeader {
            name: ObjectName::new(o.checksum, o.ty),
            encoding: o.encoding,
        }))
    }

    /// One object: its header, its bytes in pieces of 40 KiB, and the end
    /// chunk.
    fn object(&mut self, o: &Obj) -> &mut Stream {
        self.header(o);
        block_on(async {
            for piece in o.bytes.chunks(40 * 1024) {
                self.writer.write_object_data(piece).await.unwrap();
            }
            self.writer.end_object().await.unwrap();
        });
        self
    }

    /// One object stream: each of `objects`, the detached metadata of the
    /// fixture commit, and `ObjectsEnd`.
    fn objects(&mut self, objects: &[Obj]) -> &mut Stream {
        for o in objects {
            self.object(o);
        }
        self.object(&Obj {
            ty: ObjectType::CommitMeta,
            checksum: fixture_commit(),
            encoding: Encoding::Raw,
            bytes: detached_meta(),
        });
        self.message(&Message::ObjectsEnd)
    }

    fn commit(&mut self, updates: Vec<RefUpdate>) -> &mut Stream {
        self.message(&Message::Commit(CommitRequest {
            updates,
            force: false,
        }))
    }

    /// The bytes of the stream and the offset after each write.
    fn finish(self) -> (Vec<u8>, Vec<usize>) {
        let Recorder { bytes, marks } = self.writer.into_inner();
        (bytes, marks)
    }

    fn bytes(self) -> Vec<u8> {
        self.finish().0
    }
}

/// The whole stream of the fixture commit in `encoding`.
fn fixture_stream(encoding: Encoding) -> Stream {
    let mut stream = Stream::new();
    stream.objects(&fixture_objects(encoding)).commit(updates());
    stream
}

/// Runs `receive_stream` over an in-process pipe and writes `bytes` into the
/// pipe.
fn receive_piped(
    repo: &Repo,
    policy: &ReceivePolicy,
    bytes: Vec<u8>,
) -> ostrya::Result<ReceiveReport> {
    let (mut writer, reader) = pipe(PIPE_CAP);
    let (result, ()) = block_on(futures_lite::future::zip(
        repo.receive_stream(reader, policy),
        async move {
            writer.write_all(&bytes).await.unwrap();
            // The block drops the writer at its end, so the receiver reads
            // an end of file.
        },
    ));
    result
}

fn receive(repo: &Repo, policy: &ReceivePolicy, bytes: &[u8]) -> ostrya::Result<ReceiveReport> {
    block_on(repo.receive_stream(bytes, policy))
}

fn assert_protocol(result: ostrya::Result<ReceiveReport>) {
    assert!(
        matches!(result, Err(Error::Push(push::Error::Protocol(_)))),
        "{result:?}"
    );
}

/// A new empty `bare-user` repository and its objects.
fn empty_repo(tmp: &TmpDir, core: &str) -> (Repo, Vec<(String, Vec<u8>)>) {
    let repo = new_repo(tmp, RepoMode::BareUser, core);
    let before = file_inventory(repo.path(), "objects");
    (repo, before)
}

// ---------------------------------------------------------------------------
// The commit.
// ---------------------------------------------------------------------------

/// A stream of the fixture commit lands in a `bare-user` repository, in each
/// encoding, with a plain ref, a remote ref, and the detached metadata. The
/// receiver ignores the keys and the summary step of the policy. The detached
/// metadata gets no server signature, and the receiver writes no summary and
/// no anchor commit.
#[test]
fn a_stream_commits_the_fixture_commit() {
    let tool = common::ostree_available();
    if !tool {
        eprintln!("skipping the ostree fsck check: ostree is not installed");
    }
    let policy = policy();
    for encoding in [Encoding::Raw, Encoding::Deflate] {
        let tmp = TmpDir::new("one-way-commit");
        let repo = new_repo(&tmp, RepoMode::BareUser, "collection-id=org.example.C\n");
        let objects = fixture_objects(encoding);
        let report = receive_piped(&repo, &policy, fixture_stream(encoding).bytes())
            .unwrap_or_else(|e| panic!("{encoding:?}: the stream failed: {e}"));
        let outcome = |name: &str| RefOutcome {
            name: name.into(),
            old: None,
            new: Some(fixture_commit()),
        };
        assert_eq!(
            report.refs,
            vec![outcome("test/main"), outcome("origin:test/main")]
        );
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(
            report.stats.metadata_written + report.stats.content_written,
            objects.len() as u32,
            "{encoding:?}"
        );
        let line = format!("{COMMIT}\n").into_bytes();
        assert_eq!(
            file_inventory(repo.path(), "refs"),
            vec![
                ("refs/heads/test/main".to_owned(), line.clone()),
                ("refs/remotes/origin/test/main".to_owned(), line),
            ],
            "the refs of the stream alone, and no anchor commit"
        );
        assert!(!repo.path().join("summary").exists());
        assert!(!repo.path().join("summary.sig").exists());
        assert!(staging_entries(repo.path()).is_empty());

        let reopened = block_on(Repo::open(repo.path())).unwrap();
        let dict = block_on(reopened.read_commit_detached_metadata(&fixture_commit()))
            .unwrap()
            .expect("the detached metadata is stored");
        assert!(dict.dict_get("k").is_some());
        assert!(dict.dict_get(ED25519_KEY).is_none(), "no server signature");
        let fsck = block_on(reopened.fsck(&FsckOptions::default())).unwrap();
        assert!(fsck.is_ok(), "{fsck:?}");
        assert_eq!(fsck.commits_checked, 1);
        if tool {
            tool_fsck(repo.path());
        }
    }
}

/// The one-way receiver accepts a repository with `[core] locking=false`,
/// which the two-way receiver refuses.
#[test]
fn a_stream_commits_into_a_repository_without_locking() {
    let tmp = TmpDir::new("one-way-no-locking");
    let repo = new_repo(&tmp, RepoMode::BareUser, "locking=false\n");
    let policy = policy();
    let report = receive_piped(&repo, &policy, fixture_stream(Encoding::Raw).bytes()).unwrap();
    assert_eq!(report.refs.len(), 2);
    assert!(repo.path().join("refs/heads/test/main").exists());

    let (result, error) = session(&repo, &policy, |mut c| async move {
        c.hello(&["test/main"]).await.unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::LockingDisabled);
    assert_eq!(returned_code(&result), Some(ErrorCode::LockingDisabled));
}

/// If another process holds the repository lock exclusive, the stream waits.
/// After `lock-timeout-secs`, the stream fails with `LockTimeout`, and
/// nothing is published.
#[test]
fn a_held_repository_lock_times_out() {
    let tmp = TmpDir::new("one-way-repo-lock");
    let (repo, before) = empty_repo(&tmp, "lock-timeout-secs=1\n");
    let policy = policy();
    let bytes = fixture_stream(Encoding::Raw).bytes();
    let holder = foreign_holder(repo.path(), ".lock");
    let started = Instant::now();
    let result = receive(&repo, &policy, &bytes);
    let waited = started.elapsed();
    drop(holder);
    assert!(
        matches!(result, Err(Error::LockTimeout { secs: 1 })),
        "{result:?}"
    );
    assert!(
        waited >= Duration::from_secs(1),
        "the stream returned after {waited:?}"
    );
    assert_nothing_published(&repo, &before);
}

/// Under `[core] locking=false`, the commit also takes the update lock. If
/// another process holds the update lock past `lock-timeout-secs`, the stream
/// fails with `LockTimeout`, and nothing is published.
#[test]
fn locking_false_still_takes_the_update_lock() {
    let tmp = TmpDir::new("one-way-update-lock");
    let (repo, before) = empty_repo(&tmp, "locking=false\nlock-timeout-secs=0\n");
    let holder = foreign_holder(repo.path(), ".update.lock");
    let result = receive(&repo, &policy(), &fixture_stream(Encoding::Raw).bytes());
    drop(holder);
    assert!(
        matches!(result, Err(Error::LockTimeout { secs: 0 })),
        "{result:?}"
    );
    assert_nothing_published(&repo, &before);
}

// ---------------------------------------------------------------------------
// Refusals.
// ---------------------------------------------------------------------------

/// A message that a one-way stream does not carry is `protocol` at each
/// position, and nothing is published.
#[test]
fn messages_out_of_place_are_protocol() {
    let tmp = TmpDir::new("one-way-order");
    let (repo, before) = empty_repo(&tmp, "");
    let policy = policy();
    let objects = fixture_objects(Encoding::Raw);
    let have = Message::Have(vec![ObjectName::new(fixture_commit(), ObjectType::Commit)]);

    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    cases.push(("a Hello without one-way", {
        let mut s = Stream::hello(&["test/main", "origin:test/main"], false);
        s.objects(&objects).commit(updates());
        s.bytes()
    }));
    cases.push(("a Hello without one-way of another version", {
        let mut s = Stream {
            writer: FrameWriter::new(Recorder::default()),
        };
        s.message(&Message::Hello(Hello {
            version: 2,
            agent: None,
            refs: vec!["test/main".into()],
            one_way: false,
        }));
        s.bytes()
    }));
    cases.push(("a first frame that is not Hello", {
        let mut s = Stream {
            writer: FrameWriter::new(Recorder::default()),
        };
        s.objects(&objects).commit(updates());
        s.bytes()
    }));
    cases.push(("Have", {
        let mut s = Stream::new();
        s.message(&have).objects(&objects).commit(updates());
        s.bytes()
    }));
    cases.push(("Have after the objects", {
        let mut s = Stream::new();
        s.objects(&objects).message(&have).commit(updates());
        s.bytes()
    }));
    cases.push(("a second Hello", {
        let mut s = Stream::new();
        s.objects(&objects);
        s.message(&Message::Hello(Hello {
            version: 1,
            agent: None,
            refs: vec![],
            one_way: true,
        }));
        s.commit(updates());
        s.bytes()
    }));
    cases.push(("Abort after Hello", {
        let mut s = Stream::new();
        s.message(&Message::Abort);
        s.bytes()
    }));
    cases.push(("Abort between two objects", {
        let mut s = Stream::new();
        s.object(&objects[0]).message(&Message::Abort);
        s.bytes()
    }));
    cases.push(("Abort after ObjectsEnd", {
        let mut s = Stream::new();
        s.objects(&objects).message(&Message::Abort);
        s.bytes()
    }));
    cases.push(("an update that expects a commit", {
        let mut s = Stream::new();
        s.objects(&objects).commit(vec![
            update("test/main", Expected::Absent, Some(fixture_commit())),
            update(
                "origin:test/main",
                Expected::Commit(fixture_commit()),
                Some(fixture_commit()),
            ),
        ]);
        s.bytes()
    }));
    cases.push(("a delete", {
        let mut s = Stream::new();
        s.objects(&objects).commit(vec![
            update("test/main", Expected::Absent, Some(fixture_commit())),
            update("origin:test/main", Expected::Any, None),
        ]);
        s.bytes()
    }));
    for (case, bytes) in cases {
        let result = receive(&repo, &policy, &bytes);
        assert!(
            matches!(result, Err(Error::Push(push::Error::Protocol(_)))),
            "{case}: {result:?}"
        );
        assert_nothing_published(&repo, &before);
    }
}

/// Every byte after `Commit` is `protocol`: one byte, a whole frame, a part
/// of a frame length, and a frame length over the limit. The receiver reads
/// to the end of the input before the commit checks, so nothing is published.
#[test]
fn bytes_after_commit_are_protocol() {
    let tmp = TmpDir::new("one-way-trailing");
    let (repo, before) = empty_repo(&tmp, "");
    let policy = policy();
    let stream = fixture_stream(Encoding::Raw).bytes();
    let objects_end = [0, 0, 0, 1, 6];
    for tail in [
        &[0][..],
        &objects_end[..],
        &[0, 0][..],
        &[0xff, 0xff, 0xff, 0xff][..],
    ] {
        let mut bytes = stream.clone();
        bytes.extend_from_slice(tail);
        assert_protocol(receive(&repo, &policy, &bytes));
        assert_nothing_published(&repo, &before);
    }
}

/// If the sender abandons an object with the abandon marker and `Abort`, the
/// stream ends with `Aborted`. If another frame follows the marker, the
/// stream is `protocol`. Nothing is published.
#[test]
fn an_abandoned_object_is_aborted() {
    let tmp = TmpDir::new("one-way-abandon");
    let (repo, before) = empty_repo(&tmp, "");
    let policy = policy();
    let objects = fixture_objects(Encoding::Raw);
    let large = objects
        .iter()
        .max_by_key(|o| o.bytes.len())
        .expect("the fixture has objects");

    let mut s = Stream::new();
    s.object(&objects[0]).header(large);
    block_on(async {
        let half = &large.bytes[..large.bytes.len() / 2];
        s.writer.write_object_data(half).await.unwrap();
        s.writer.abandon_object().await.unwrap();
    });
    let (abandoned, marks) = s.finish();
    let result = receive(&repo, &policy, &abandoned);
    assert!(
        matches!(result, Err(Error::Push(push::Error::Aborted))),
        "{result:?}"
    );
    assert_nothing_published(&repo, &before);

    // The `Abort` frame is the last write. Put `ObjectsEnd` in its place.
    let mut other = abandoned[..marks[marks.len() - 2]].to_vec();
    other.extend_from_slice(&[0, 0, 0, 1, 6]);
    assert_protocol(receive(&repo, &policy, &other));
    assert_nothing_published(&repo, &before);
}

/// If a stream ends before `Commit` is complete, the result is an end of
/// file, and nothing is published. The test cuts the stream of each encoding
/// at these positions:
///
/// - at each frame or chunk boundary
/// - one byte after a boundary
/// - one byte before a boundary
/// - at offset 0, which gives the empty stream
#[test]
fn a_cut_stream_is_an_end_of_file() {
    let tmp = TmpDir::new("one-way-cut");
    let (repo, before) = empty_repo(&tmp, "");
    let policy = policy();
    for encoding in [Encoding::Raw, Encoding::Deflate] {
        let (bytes, marks) = fixture_stream(encoding).finish();
        let mut cuts = vec![0];
        for &mark in &marks {
            cuts.extend([mark - 1, mark, mark + 1]);
        }
        cuts.retain(|&cut| cut < bytes.len());
        cuts.sort_unstable();
        cuts.dedup();
        assert!(cuts.len() > 30, "{encoding:?}: {} cuts", cuts.len());
        for cut in cuts {
            let result = receive(&repo, &policy, &bytes[..cut]);
            match result {
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {}
                other => panic!("{encoding:?}: a cut at {cut} of {}: {other:?}", bytes.len()),
            }
            assert_nothing_published(&repo, &before);
        }
    }
}

/// A stream with one changed byte in a content object, or in the commit
/// object, is `checksum-mismatch`, and nothing is published.
#[test]
fn a_corrupted_object_is_checksum_mismatch() {
    let tmp = TmpDir::new("one-way-corrupt");
    let (repo, before) = empty_repo(&tmp, "");
    let policy = policy();
    for ty in [ObjectType::File, ObjectType::Commit] {
        let mut objects = fixture_objects(Encoding::Raw);
        let o = objects
            .iter_mut()
            .filter(|o| o.ty == ty)
            .max_by_key(|o| o.bytes.len())
            .unwrap();
        let last = o.bytes.len() - 1;
        o.bytes[last] ^= 0x01;
        let mut s = Stream::new();
        s.objects(&objects).commit(updates());
        let result = receive(&repo, &policy, &s.bytes());
        assert!(
            matches!(result, Err(Error::Push(push::Error::ChecksumMismatch(_)))),
            "{ty:?}: {result:?}"
        );
        assert_nothing_published(&repo, &before);
    }
}

/// The stored and the incoming detached metadata of a commit are each under
/// the size limit. If their merge is over the limit, the stream is
/// `limit-exceeded`, and nothing is published.
#[test]
fn merged_detached_metadata_over_the_limit_is_limit_exceeded() {
    let tmp = TmpDir::new("one-way-meta-limit");
    let repo = new_repo(&tmp, RepoMode::BareUser, "");
    let dict = |key: &str| {
        let mut dict = DictBuilder::new();
        dict.insert_bytes(key, &vec![0; 65 << 20]);
        ostrya_core::to_bytes(&Type::parse("a{sv}").unwrap(), &dict.build()).unwrap()
    };
    let stored = dict("a");
    let incoming = dict("k");
    assert!(stored.len() as u64 <= MAX_METADATA_SIZE);
    assert!((stored.len() + incoming.len()) as u64 > MAX_METADATA_SIZE);
    let path = repo.path().join("objects").join(ostrya::loose_path(
        &fixture_commit(),
        ObjectType::CommitMeta,
        repo.mode(),
    ));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, stored).unwrap();
    let before = file_inventory(repo.path(), "objects");

    let mut s = Stream::new();
    for o in fixture_objects(Encoding::Raw) {
        s.object(&o);
    }
    s.object(&Obj {
        ty: ObjectType::CommitMeta,
        checksum: fixture_commit(),
        encoding: Encoding::Raw,
        bytes: incoming,
    })
    .message(&Message::ObjectsEnd)
    .commit(updates());
    let result = receive(&repo, &policy(), &s.bytes());
    assert!(
        matches!(
            &result,
            Err(Error::Push(push::Error::LimitExceeded(m))) if m.contains("merged detached metadata")
        ),
        "{result:?}"
    );
    assert_nothing_published(&repo, &before);
}

/// A one-way `Hello` gets no reply, so the size of a reply does not limit its
/// names. A `Hello` whose two-way reply cannot fit in a frame passes. A
/// stream of this `Hello` alone ends with an end of file before `Commit`.
#[test]
fn a_one_way_hello_has_no_bound_of_the_reply() {
    let tmp = TmpDir::new("one-way-many-names");
    let (repo, before) = empty_repo(&tmp, "");
    let many = vec!["m"; 100_000];
    match receive(&repo, &policy(), &Stream::hello(&many, true).bytes()) {
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        other => panic!("{other:?}"),
    }
    assert_nothing_published(&repo, &before);
}

// ---------------------------------------------------------------------------
// The two-way receiver.
// ---------------------------------------------------------------------------

/// A two-way session refuses a `Hello` with `one-way` true as `protocol`,
/// before it checks the version.
#[test]
fn the_two_way_receiver_refuses_a_one_way_hello() {
    let one_way = Hello {
        version: 2,
        agent: None,
        refs: vec!["test/main".into()],
        one_way: true,
    };
    let tmp = TmpDir::new("one-way-two-way");
    let (repo, before) = empty_repo(&tmp, "");
    let policy = Arc::new(policy());
    let hello = one_way.clone();
    let (result, error) = session(&repo, &policy, |mut c| async move {
        c.send(&Message::Hello(hello)).await.unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Protocol, "{error:?}");
    assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));
    assert_nothing_published(&repo, &before);

    let opened = block_on(ReceiveService::hello(repo.clone(), policy, 1, one_way));
    assert!(
        matches!(opened, Err(Error::Push(push::Error::Protocol(_)))),
        "{:?}",
        opened.map(|(_, reply)| reply)
    );
    assert_nothing_published(&repo, &before);
}

/// A ref name of 64 lowercase hex characters, which a revision reads as a
/// commit checksum, passes `Hello`. The update that writes a commit to it is
/// `invalid-ref` at `Commit`, and nothing is published.
#[test]
fn a_write_to_a_checksum_shaped_name_is_invalid_ref_at_commit() {
    let tmp = TmpDir::new("one-way-hex-ref");
    let (repo, before) = empty_repo(&tmp, "");
    let hex = "a".repeat(64);
    // A stream of `Hello` alone ends with an end of file before `Commit`, so
    // `Hello` accepted the name.
    match receive(&repo, &policy(), &Stream::hello(&[&hex], true).bytes()) {
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        other => panic!("{other:?}"),
    }
    let mut stream = Stream::hello(&[&hex], true);
    stream
        .objects(&fixture_objects(Encoding::Raw))
        .commit(vec![update(&hex, Expected::Absent, Some(fixture_commit()))]);
    match receive(&repo, &policy(), &stream.bytes()) {
        Err(Error::Push(push::Error::InvalidRef(m))) => {
            assert_eq!(m, format!("invalid ref name '{hex}'"));
        }
        other => panic!("{other:?}"),
    }
    assert_nothing_published(&repo, &before);
}

// ---------------------------------------------------------------------------
// The sender.
// ---------------------------------------------------------------------------

/// Tests of `Repo::export_stream` from an `archive` repository into
/// `Repo::receive_stream`. A stream that commits runs through an in-process
/// pipe. A test keeps a stream that fails in a byte buffer, so it can cut the
/// stream or change a byte.
#[cfg(feature = "push")]
mod export {
    use std::ops::Range;
    use std::sync::atomic::{AtomicU64, Ordering};

    use common::receive::is_root;
    use common::{Untouchable, is_sealed, mark_partial, regular_objects};
    use futures_lite::future::zip;
    use ostrya::push::proto::ABANDON;
    use ostrya::push::{Compression, PushStats};
    use ostrya::{CommitOptions, DirMeta, ExportStreamOptions, FileMeta, MutableTree, Value};
    use ostrya_core::Xattrs;

    use super::*;

    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;

    /// The size of the large file: over the chunk limit of 1 MiB.
    const LARGE: usize = 1_500_000;

    /// The kind bytes of the frames that the tests look for.
    const OBJECT_HEADER_FRAME: u8 = 5;
    const OBJECTS_END_FRAME: u8 = 6;
    const COMMIT_FRAME: u8 = 8;

    /// A version 2 file capability with the effective flag:
    /// cap_net_bind_service in the permitted set.
    const CAPABILITY: [u8; 20] = [1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    /// An `archive` repository with one commit: a setuid file, a file with
    /// `security.capability`, a regular file over 1 MiB, and a symlink, with
    /// detached metadata.
    struct Source {
        _dir: TmpDir,
        repo: Repo,
        commit: Checksum,
        setuid: Checksum,
        capable: Checksum,
        large: Checksum,
    }

    impl Source {
        fn new(tag: &str) -> Source {
            let dir = TmpDir::new(tag);
            let repo = new_repo(&dir, RepoMode::Archive, "");
            let (commit, [setuid, capable, large]) = commit_tree(&repo, None, &large_content());
            Source {
                _dir: dir,
                repo,
                commit,
                setuid,
                capable,
                large,
            }
        }
    }

    /// Pseudo-random bytes, which DEFLATE does not shrink to one chunk.
    fn large_content() -> Vec<u8> {
        let mut x: u32 = 0x9e37_79b9;
        (0..LARGE)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    /// Commits the fixture tree into `repo` with `metadata`, with `large` as
    /// the bytes of the file `large`, and writes its detached metadata.
    /// Returns the commit and the checksums of the setuid file, the file with
    /// the capability, and the file `large`.
    fn commit_tree(
        repo: &Repo,
        metadata: Option<Value>,
        large: &[u8],
    ) -> (Checksum, [Checksum; 3]) {
        let meta = |mode: u32, xattrs: Xattrs| FileMeta {
            uid: 0,
            gid: 0,
            mode,
            xattrs,
        };
        let capability =
            Xattrs::new([(b"security.capability\0".to_vec(), CAPABILITY.to_vec())]).unwrap();
        block_on(async {
            let txn = repo.transaction().await.unwrap();
            let mut mtree = MutableTree::new();
            let setuid = txn
                .write_regfile_inline(None, &meta(S_IFREG | 0o4755, Xattrs::empty()), b"setuid\n")
                .await
                .unwrap();
            let capable = txn
                .write_regfile_inline(None, &meta(S_IFREG | 0o755, capability), b"capable\n")
                .await
                .unwrap();
            let large = txn
                .write_regfile_inline(None, &meta(S_IFREG | 0o644, Xattrs::empty()), large)
                .await
                .unwrap();
            let link = txn
                .write_symlink("large", &meta(S_IFLNK | 0o777, Xattrs::empty()), None)
                .await
                .unwrap();
            for (name, file) in [
                ("setuid", setuid),
                ("capable", capable),
                ("large", large),
                ("link", link),
            ] {
                mtree.replace_file(name, file).unwrap();
            }
            let dirmeta = DirMeta {
                uid: 0,
                gid: 0,
                mode: S_IFDIR | 0o755,
                xattrs: Xattrs::empty(),
            };
            let dm = txn
                .write_metadata(ObjectType::DirMeta, None, &dirmeta.serialize().unwrap())
                .await
                .unwrap();
            mtree.set_metadata_checksum(dm);
            let root = txn.write_mtree(&mut mtree).await.unwrap();
            let commit = txn
                .write_commit(
                    CommitOptions {
                        subject: Some("one-way".into()),
                        timestamp: Some(1_700_000_000),
                        metadata,
                        ..CommitOptions::default()
                    },
                    &root,
                )
                .await
                .unwrap();
            txn.commit().await.unwrap();
            let mut detached = DictBuilder::new();
            detached.insert_str("k", "v");
            repo.write_commit_detached_metadata(&commit, Some(&detached.build()))
                .await
                .unwrap();
            (commit, [setuid, capable, large])
        })
    }

    /// The metadata of a commit bound to `refs`.
    fn bound_to(refs: &[&str]) -> Value {
        let refs: Vec<String> = refs.iter().map(|r| (*r).to_owned()).collect();
        let mut dict = DictBuilder::new();
        dict.insert_strv("ostree.ref-binding", &refs);
        dict.build()
    }

    /// A policy that accepts privileged content and every remote ref.
    fn export_policy() -> ReceivePolicy {
        ReceivePolicy {
            rules: vec![(RefPattern::parse("*:*").unwrap(), ReceiveRule::default())],
            allow_privileged: true,
            ..ReceivePolicy::default()
        }
    }

    /// `main`, which must be absent, and `origin:main` in any state, both to
    /// `commit`.
    fn options(commit: Checksum, compression: Compression) -> ExportStreamOptions {
        ExportStreamOptions {
            updates: vec![
                update("main", Expected::Absent, Some(commit)),
                update("origin:main", Expected::Any, Some(commit)),
            ],
            compression,
            ..ExportStreamOptions::default()
        }
    }

    /// Exports from `source` into an in-process pipe that `target` reads.
    /// The block drops the writer after the export, so the receiver reads an
    /// end of file.
    fn export_piped(
        source: &Repo,
        target: &Repo,
        policy: &ReceivePolicy,
        opts: ExportStreamOptions,
    ) -> (ostrya::Result<ReceiveReport>, ostrya::Result<PushStats>) {
        let (mut writer, reader) = pipe(PIPE_CAP);
        block_on(zip(target.receive_stream(reader, policy), async move {
            let stats = source.export_stream(&mut writer, opts).await;
            drop(writer);
            stats
        }))
    }

    /// The bytes of one export.
    fn capture(source: &Repo, opts: ExportStreamOptions) -> Vec<u8> {
        let mut out = Vec::new();
        block_on(source.export_stream(&mut out, opts)).unwrap();
        out
    }

    /// Asserts that `target` holds the commit of `source` and both refs, with
    /// its detached metadata, no staging entry, and an fsck without errors.
    fn assert_committed(source: &Source, target: &Repo, report: &ReceiveReport, tool: bool) {
        let outcome = |name: &str| RefOutcome {
            name: name.into(),
            old: None,
            new: Some(source.commit),
        };
        assert_eq!(report.refs, vec![outcome("main"), outcome("origin:main")]);
        let line = format!("{}\n", source.commit).into_bytes();
        assert_eq!(
            file_inventory(target.path(), "refs"),
            vec![
                ("refs/heads/main".to_owned(), line.clone()),
                ("refs/remotes/origin/main".to_owned(), line),
            ]
        );
        assert!(staging_entries(target.path()).is_empty());
        let reopened = block_on(Repo::open(target.path())).unwrap();
        let dict = block_on(reopened.read_commit_detached_metadata(&source.commit))
            .unwrap()
            .expect("the detached metadata is stored");
        assert!(dict.dict_get("k").is_some());
        let setuid = block_on(reopened.load_file(&source.setuid)).unwrap();
        assert_eq!(setuid.mode, 0o104755);
        let capable = block_on(reopened.load_file(&source.capable)).unwrap();
        assert!(
            capable
                .xattrs
                .iter()
                .any(|(name, value)| name == b"security.capability\0" && value == CAPABILITY),
            "{:?}",
            capable.xattrs
        );
        let fsck = block_on(reopened.fsck(&FsckOptions::default())).unwrap();
        assert!(fsck.is_ok(), "{fsck:?}");
        assert_eq!(fsck.commits_checked, 1);
        if tool {
            tool_fsck(target.path());
        }
    }

    /// An export of the fixture commit lands in a new empty `bare-user`
    /// repository, in each encoding. The export carries a plain ref, a remote
    /// ref, and the detached metadata. The setuid mode and the capability go into the
    /// logical metadata of the objects. The statistics count each object as
    /// offered, needed, and sent.
    #[test]
    fn an_export_commits_into_a_bare_user_repository() {
        let tool = common::ostree_available();
        if !tool {
            eprintln!("skipping the ostree fsck check: ostree is not installed");
        }
        let source = Source::new("one-way-export-source");
        let policy = export_policy();
        for compression in [Compression::None, Compression::Deflate { level: 6 }] {
            let tmp = TmpDir::new("one-way-export-bare-user");
            let target = new_repo(&tmp, RepoMode::BareUser, "");
            let (received, exported) = export_piped(
                &source.repo,
                &target,
                &policy,
                options(source.commit, compression),
            );
            let report = received.unwrap_or_else(|e| panic!("{compression:?}: {e}"));
            let stats = exported.unwrap();
            // The commit, the root dirtree and dirmeta, and four files.
            assert_eq!(stats.objects_total, 7, "{stats:?}");
            assert_eq!(stats.objects_needed, 7);
            assert_eq!(stats.objects_sent, 7);
            assert_committed(&source, &target, &report, tool);
        }
    }

    /// The same export into a new empty `bare` repository with
    /// `[ex-integrity] fsverity=yes` also seals each regular-file object,
    /// and stores the detached metadata. The test runs only as root on a file
    /// system with fs-verity.
    #[test]
    fn an_export_into_a_bare_repository_seals_each_object_as_root() {
        if !is_root() {
            eprintln!("skipping the bare export: not running as root");
            return;
        }
        let source = Source::new("one-way-export-verity-source");
        let policy = export_policy();
        let probe = TmpDir::new("one-way-export-verity-probe");
        let repo = new_repo(
            &probe,
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=maybe\n",
        );
        let (received, _) = export_piped(
            &source.repo,
            &repo,
            &policy,
            options(source.commit, Compression::None),
        );
        received.unwrap();
        if !regular_objects(repo.path()).iter().any(|p| is_sealed(p)) {
            eprintln!("skipping the bare export: the filesystem does not support fs-verity");
            return;
        }
        let tool = common::ostree_available();
        let tmp = TmpDir::new("one-way-export-bare");
        let target = new_repo(&tmp, RepoMode::Bare, "[ex-integrity]\nfsverity=yes\n");
        let (received, exported) = export_piped(
            &source.repo,
            &target,
            &policy,
            options(source.commit, Compression::Deflate { level: 6 }),
        );
        let report = received.unwrap();
        exported.unwrap();
        assert_committed(&source, &target, &report, tool);
        // The repository seals each regular-file object. The check leaves
        // out the `.commitmeta` file, which the repository does not seal.
        let (metas, regulars): (Vec<_>, Vec<_>) = regular_objects(target.path())
            .into_iter()
            .partition(|p| p.extension().is_some_and(|e| e == "commitmeta"));
        assert_eq!(metas.len(), 1, "{metas:?}");
        assert!(!regulars.is_empty());
        for path in regulars {
            assert!(is_sealed(&path), "{}", path.display());
        }
    }

    /// One part of a captured stream: a frame with its kind, a chunk length,
    /// or the bytes of a chunk.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Part {
        Frame(u8),
        Length,
        Data,
    }

    /// The parts of `bytes`, in order, with their byte ranges.
    fn parts(bytes: &[u8]) -> Vec<(Part, Range<usize>)> {
        let mut out = Vec::new();
        let mut at = 0;
        let mut in_object = false;
        while at < bytes.len() {
            let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
            if !in_object {
                let kind = bytes[at + 4];
                out.push((Part::Frame(kind), at..at + 4 + len as usize));
                in_object = kind == OBJECT_HEADER_FRAME;
                at += 4 + len as usize;
                continue;
            }
            out.push((Part::Length, at..at + 4));
            at += 4;
            if len == 0 || len == ABANDON {
                in_object = false;
            } else {
                out.push((Part::Data, at..at + len as usize));
                at += len as usize;
            }
        }
        out
    }

    /// The ranges of the chunk bytes of the object `checksum` in `bytes`.
    fn object_data(bytes: &[u8], checksum: &Checksum) -> Vec<Range<usize>> {
        let parts = parts(bytes);
        let header = parts
            .iter()
            .position(|(part, range)| {
                *part == Part::Frame(OBJECT_HEADER_FRAME)
                    && bytes[range.clone()]
                        .windows(32)
                        .any(|w| w == checksum.as_bytes())
            })
            .expect("the object is in the stream");
        parts[header + 1..]
            .iter()
            .take_while(|(part, _)| !matches!(part, Part::Frame(_)))
            .filter(|(part, _)| *part == Part::Data)
            .map(|(_, range)| range.clone())
            .collect()
    }

    /// The range of the first frame of `kind` in `bytes`.
    fn frame(bytes: &[u8], kind: u8) -> Range<usize> {
        parts(bytes)
            .into_iter()
            .find(|(part, _)| *part == Part::Frame(kind))
            .map(|(_, range)| range)
            .expect("the frame is in the stream")
    }

    /// A captured stream with one changed byte in the payload of the large
    /// file is `checksum-mismatch`, and nothing is published.
    #[test]
    fn a_changed_byte_of_an_export_is_checksum_mismatch() {
        let source = Source::new("one-way-export-corrupt-source");
        let tmp = TmpDir::new("one-way-export-corrupt");
        let (repo, before) = empty_repo(&tmp, "");
        let mut bytes = capture(&source.repo, options(source.commit, Compression::None));
        let data = object_data(&bytes, &source.large);
        // The first chunk is the file header, and the payload follows.
        assert!(data.len() > 10, "{} chunks", data.len());
        let chunk = &data[data.len() / 2];
        bytes[chunk.start + chunk.len() / 2] ^= 0x01;
        let result = receive(&repo, &export_policy(), &bytes);
        assert!(
            matches!(result, Err(Error::Push(push::Error::ChecksumMismatch(_)))),
            "{result:?}"
        );
        assert_nothing_published(&repo, &before);
    }

    /// A captured stream that ends inside a chunk of the large file, right
    /// after `ObjectsEnd`, or inside `Commit` gives an end of file. One extra byte after the stream is `protocol`. No case changes
    /// the repository.
    #[test]
    fn a_cut_or_extended_export_changes_nothing() {
        let source = Source::new("one-way-export-cut-source");
        let tmp = TmpDir::new("one-way-export-cut");
        let (repo, before) = empty_repo(&tmp, "");
        let policy = export_policy();
        let bytes = capture(
            &source.repo,
            options(source.commit, Compression::Deflate { level: 6 }),
        );
        let data = object_data(&bytes, &source.large);
        let chunk = &data[data.len() / 2];
        let commit = frame(&bytes, COMMIT_FRAME);
        assert_eq!(commit.end, bytes.len(), "Commit is the last frame");
        for (case, cut) in [
            ("inside a chunk", chunk.start + chunk.len() / 2),
            ("after ObjectsEnd", frame(&bytes, OBJECTS_END_FRAME).end),
            ("inside Commit", commit.start + commit.len() / 2),
        ] {
            match receive(&repo, &policy, &bytes[..cut]) {
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {}
                other => panic!("{case}: {other:?}"),
            }
            assert_nothing_published(&repo, &before);
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_protocol(receive(&repo, &policy, &longer));
        assert_nothing_published(&repo, &before);
        // The whole stream commits.
        receive(&repo, &policy, &bytes).unwrap();
    }

    /// The error of an export that is refused, and the number of calls it
    /// made on the output: writes, flushes, and closes.
    fn refused(repo: &Repo, opts: ExportStreamOptions) -> (Error, u64) {
        let calls = Arc::new(AtomicU64::new(0));
        let output = Untouchable {
            calls: Arc::clone(&calls),
        };
        let error = block_on(repo.export_stream(output, opts)).expect_err("the export is refused");
        (error, calls.load(Ordering::Relaxed))
    }

    /// `count` updates of names of `len` bytes each, all to `commit`.
    fn many(count: usize, len: usize, commit: Checksum) -> Vec<RefUpdate> {
        (0..count)
            .map(|i| update(&format!("{i:0len$}"), Expected::Any, Some(commit)))
            .collect()
    }

    /// Each refusal of the export comes before the first byte. In these
    /// commits, the file `large` holds the 6 bytes `small\n`.
    #[test]
    fn an_export_refuses_before_it_writes_a_byte() {
        let tmp = TmpDir::new("one-way-export-refuse");
        let repo = &new_repo(&tmp, RepoMode::Archive, "");
        let (commit, _) = commit_tree(repo, None, b"small\n");
        let (other, _) = commit_tree(repo, Some(bound_to(&["other"])), b"small\n");
        let (x, _) = commit_tree(repo, Some(bound_to(&["x"])), b"small\n");
        let with = |updates: Vec<RefUpdate>| ExportStreamOptions {
            updates,
            ..ExportStreamOptions::default()
        };
        let invalid: Vec<(&str, ExportStreamOptions)> = vec![
            (
                "an expected commit",
                with(vec![update("main", Expected::Commit(commit), Some(commit))]),
            ),
            ("a delete", with(vec![update("main", Expected::Any, None)])),
            (
                "a delete of 64 lowercase hex characters",
                with(vec![update(&"a".repeat(64), Expected::Any, None)]),
            ),
            ("empty updates", with(vec![])),
            (
                "a ref named twice",
                with(vec![
                    update("main", Expected::Absent, Some(commit)),
                    update("main", Expected::Any, Some(commit)),
                ]),
            ),
            (
                "level 0",
                options(commit, Compression::Deflate { level: 0 }),
            ),
            (
                "level 10",
                options(commit, Compression::Deflate { level: 10 }),
            ),
            ("a Hello frame over 1 MiB", with(many(30_000, 40, commit))),
            ("a Commit frame over 1 MiB", with(many(20_000, 40, commit))),
        ];
        for (case, opts) in invalid {
            let (error, calls) = refused(repo, opts);
            assert!(
                matches!(error, Error::Push(push::Error::InvalidInput(_))),
                "{case}: {error:?}"
            );
            assert_eq!(calls, 0, "{case}");
        }

        let (error, calls) = refused(
            repo,
            with(vec![update("a/../b", Expected::Any, Some(commit))]),
        );
        assert!(matches!(error, Error::InvalidRefspec(_)), "{error:?}");
        assert_eq!(calls, 0);
        let hex = "a".repeat(64);
        let (error, calls) = refused(repo, with(vec![update(&hex, Expected::Any, Some(commit))]));
        assert!(
            matches!(&error, Error::InvalidRefspec(n) if *n == hex),
            "{error:?}"
        );
        assert_eq!(calls, 0);
        // With a `REMOTE:` part, the name is a remote ref, and the receiver
        // writes it.
        let remote = format!("origin:{hex}");
        let bytes = capture(
            repo,
            with(vec![update(&remote, Expected::Any, Some(commit))]),
        );
        let target_tmp = TmpDir::new("one-way-export-hex-target");
        let (target, _) = empty_repo(&target_tmp, "");
        let report = receive(&target, &export_policy(), &bytes).unwrap();
        assert_eq!(report.refs[0].name, remote);
        assert!(
            target
                .path()
                .join("refs/remotes/origin")
                .join(&hex)
                .exists()
        );

        for (bound, name) in [(other, "main"), (x, "origin:main")] {
            let (error, calls) =
                refused(repo, with(vec![update(name, Expected::Any, Some(bound))]));
            assert!(
                matches!(error, Error::Push(push::Error::BindingMismatch(_))),
                "{name}: {error:?}"
            );
            assert_eq!(calls, 0, "{name}");
        }
        // A remote ref compares its name without the remote part.
        for name in ["x", "origin:x"] {
            let opts = with(vec![update(name, Expected::Any, Some(x))]);
            assert!(!capture(repo, opts).is_empty(), "{name}");
        }

        mark_partial(repo, &commit);
        let (error, calls) = refused(repo, options(commit, Compression::None));
        assert!(
            matches!(error, Error::Push(push::Error::InvalidInput(_))),
            "{error:?}"
        );
        assert_eq!(calls, 0);
    }

    /// If the source of an export lacks a file object, the export ends the
    /// stream inside that object with the abandon marker and `Abort`. The
    /// export returns the error of the source. The receiver of that stream
    /// returns `Aborted`, and nothing is published.
    #[test]
    fn a_missing_file_object_aborts_the_stream() {
        let source = Source::new("one-way-export-missing");
        let path = source.repo.path().join("objects").join(ostrya::loose_path(
            &source.large,
            ObjectType::File,
            source.repo.mode(),
        ));
        std::fs::remove_file(path).unwrap();
        let tmp = TmpDir::new("one-way-export-missing-target");
        let (repo, before) = empty_repo(&tmp, "");
        for compression in [Compression::None, Compression::Deflate { level: 6 }] {
            let mut bytes = Vec::new();
            let result = block_on(
                source
                    .repo
                    .export_stream(&mut bytes, options(source.commit, compression)),
            );
            assert!(
                matches!(result, Err(Error::Push(push::Error::Source(_)))),
                "{compression:?}: {result:?}"
            );
            let tail = [&ABANDON.to_be_bytes()[..], &[0, 0, 0, 2, 11, 0]].concat();
            assert!(bytes.ends_with(&tail), "{compression:?}");
            let result = receive(&repo, &export_policy(), &bytes);
            assert!(
                matches!(result, Err(Error::Push(push::Error::Aborted))),
                "{compression:?}: {result:?}"
            );
            assert_nothing_published(&repo, &before);
        }
    }
}
