//! Tests of `ReceiveService`, which runs one push session as steps:
//!
//! - concurrent object streams on the one transaction of the session
//! - the count of the steps in flight
//! - the end of the session on an error, a drop, or an abort
//!
//! Each `objects` call reads a body of frames. A test gives it one of these
//! bodies:
//!
//! - an in-memory body
//! - the read half of an in-process pipe whose writer the test holds, so the
//!   call waits for input
//! - a body that stops at a gate until each body of the gate gets to it

#![cfg(feature = "receive")]

mod common;

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use common::receive::{
    Obj, PIPE_CAP, PipeReader, PipeWriter, assert_staging_removed, body, fixture_objects, header,
    new_repo, pipe, raw_object, sha, staging_entries, write_object,
};
use common::{COMMIT, TmpDir, foreign_holder, lock_holder_main};
use futures_io::AsyncRead;
use futures_lite::future::{poll_once, zip};
use ostrya::push::proto::{CommitRequest, FrameWriter, Hello, Message, ObjectHeader};
use ostrya::push::{self, Encoding, ErrorCode, Expected, RefOutcome, RefUpdate};
use ostrya::{
    Checksum, Error, ObjectName, ObjectType, ReceivePolicy, ReceiveService, Repo, RepoMode,
};
use ostrya_rt::block_on;

fn hello(refs: &[&str]) -> Hello {
    Hello {
        version: 1,
        agent: None,
        refs: refs.iter().map(|r| r.to_string()).collect(),
        one_way: false,
    }
}

/// Opens a session on `repo` that runs `parallel` object streams.
fn open(repo: &Repo, parallel: u32, refs: &[&str]) -> ReceiveService {
    let policy = Arc::new(ReceivePolicy::default());
    let (service, reply) = block_on(ReceiveService::hello(
        repo.clone(),
        policy,
        parallel,
        hello(refs),
    ))
    .unwrap();
    assert_eq!(reply.parallel_uploads, parallel);
    service
}

fn fixture_commit() -> Checksum {
    Checksum::from_hex(COMMIT).unwrap()
}

fn fixture_update() -> CommitRequest {
    CommitRequest {
        updates: vec![RefUpdate {
            name: "test/main".into(),
            expected: Expected::Absent,
            new: Some(fixture_commit()),
        }],
        force: false,
    }
}

/// A body that the test writes while the call reads it.
fn live_body() -> (FrameWriter<PipeWriter>, PipeReader) {
    let (writer, reader) = pipe(PIPE_CAP);
    (FrameWriter::new(writer), reader)
}

/// A content object whose bytes do not hash to its name.
fn corrupt_object() -> Obj {
    let (_, bytes) = raw_object(&header(0, 0, 0o100644), b"payload");
    Obj {
        ty: ObjectType::File,
        checksum: sha(b"another object"),
        encoding: Encoding::Raw,
        bytes,
    }
}

/// The wire code of a step that failed.
fn code<T: std::fmt::Debug>(result: &ostrya::Result<T>) -> Option<ErrorCode> {
    match result {
        Err(Error::Push(e)) => e.code(),
        other => panic!("expected a push error, got {other:?}"),
    }
}

/// Asserts that `result` is the `protocol` error of a session that ended,
/// with a message that holds `reason`.
fn assert_ended<T: std::fmt::Debug>(result: ostrya::Result<T>, reason: &str) {
    match result {
        Err(Error::Push(push::Error::Protocol(message))) => {
            assert!(message.contains(reason), "{message}")
        }
        other => panic!("expected protocol with {reason:?}, got {other:?}"),
    }
}

/// A body of the objects before `objects[k]`, the header of `objects[k]`,
/// and the first `part` bytes of its one data chunk. `objects[k]` must fit
/// in one chunk.
fn cut_body(objects: &[Obj], k: usize, part: usize) -> Vec<u8> {
    let o = &objects[k];
    let mut bytes = block_on(async {
        let mut w = FrameWriter::new(Vec::new());
        for o in &objects[..k] {
            write_object(&mut w, o).await.unwrap();
        }
        w.write_message(&Message::ObjectHeader(ObjectHeader {
            name: ObjectName::new(o.checksum, o.ty),
            encoding: o.encoding,
        }))
        .await
        .unwrap();
        w.into_inner()
    });
    bytes.extend_from_slice(&u32::try_from(o.bytes.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&o.bytes[..part]);
    bytes
}

/// The body of every object of `objects`, and the offset of the middle of
/// the one data chunk of `objects[k]`.
fn body_with_middle(objects: &[Obj], k: usize) -> (Vec<u8>, usize) {
    let half = objects[k].bytes.len() / 2;
    let mut bytes = cut_body(objects, k, half);
    let middle = bytes.len();
    bytes.extend_from_slice(&objects[k].bytes[half..]);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    let rest = block_on(async {
        let mut w = FrameWriter::new(Vec::new());
        for o in &objects[k + 1..] {
            write_object(&mut w, o).await.unwrap();
        }
        w.write_message(&Message::ObjectsEnd).await.unwrap();
        w.into_inner()
    });
    bytes.extend_from_slice(&rest);
    (bytes, middle)
}

/// The meeting point of the bodies of one gate.
struct Gate {
    parties: usize,
    arrived: usize,
    wakers: Vec<Waker>,
}

/// A body that stops at the offset `stop` until each body of its gate
/// reaches its own stop, and then reads to its end.
struct Gated {
    bytes: Vec<u8>,
    pos: usize,
    stop: usize,
    arrived: bool,
    gate: Arc<Mutex<Gate>>,
}

fn gated(bodies: Vec<(Vec<u8>, usize)>) -> Vec<Gated> {
    let gate = Arc::new(Mutex::new(Gate {
        parties: bodies.len(),
        arrived: 0,
        wakers: Vec::new(),
    }));
    bodies
        .into_iter()
        .map(|(bytes, stop)| Gated {
            bytes,
            pos: 0,
            stop,
            arrived: false,
            gate: gate.clone(),
        })
        .collect()
}

impl AsyncRead for Gated {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.pos == me.stop {
            let mut gate = me.gate.lock().unwrap();
            if !me.arrived {
                me.arrived = true;
                gate.arrived += 1;
                if gate.arrived == gate.parties {
                    gate.wakers.drain(..).for_each(Waker::wake);
                }
            }
            if gate.arrived < gate.parties {
                gate.wakers.push(cx.waker().clone());
                return Poll::Pending;
            }
        }
        let end = if me.pos < me.stop {
            me.stop
        } else {
            me.bytes.len()
        };
        let n = buf.len().min(end - me.pos);
        buf[..n].copy_from_slice(&me.bytes[me.pos..me.pos + n]);
        me.pos += n;
        Poll::Ready(Ok(n))
    }
}

// ---------------------------------------------------------------------------
// Hello and the steps of one session.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "helper process for the lock tests"]
fn lock_holder_subprocess() {
    lock_holder_main();
}

#[test]
fn zero_parallel_uploads_is_invalid_input() {
    let tmp = TmpDir::new("svc-zero");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let policy = Arc::new(ReceivePolicy::default());
    let result = block_on(ReceiveService::hello(repo.clone(), policy, 0, hello(&[])));
    assert!(matches!(result, Err(Error::InvalidInput(_))));
    assert!(staging_entries(repo.path()).is_empty());
}

#[test]
fn hello_refusals_keep_their_codes() {
    let tmp = TmpDir::new("svc-hello");
    let repo = new_repo(&tmp, RepoMode::Archive, "locking=false\n");
    let policy = Arc::new(ReceivePolicy::default());
    let result = block_on(ReceiveService::hello(repo, policy.clone(), 1, hello(&[]))).map(|_| ());
    assert_eq!(code(&result), Some(ErrorCode::LockingDisabled));

    // A server-side failure, here a bad `[archive] zlib-level`, returns its
    // own error and no wire code.
    let tmp = TmpDir::new("svc-hello-internal");
    let repo = new_repo(&tmp, RepoMode::Archive, "[archive]\nzlib-level=abc\n");
    let result = block_on(ReceiveService::hello(repo.clone(), policy, 1, hello(&[]))).map(|_| ());
    assert!(
        matches!(result, Err(ref e) if !matches!(e, Error::Push(_))),
        "{result:?}"
    );
    assert!(staging_entries(repo.path()).is_empty());
}

/// `check_hello` runs its checks in this order:
///
/// 1. the version
/// 2. the mode
/// 3. `[core] locking=false`, for a two-way `Hello` only
/// 4. the ref names
/// 5. the size of the reply, for a two-way `Hello` only
///
/// It opens no transaction, and it leaves the refusal of a `bare` repository
/// to `hello`. `hello` refuses a reply that is too large before it takes the
/// repository lock, so a foreign exclusive lock does not delay the answer.
#[test]
fn check_hello_runs_its_checks_in_order() {
    let check = |repo: &Repo, hello: &Hello| ReceiveService::check_hello(repo, hello);
    let many = vec!["m"; 100_000];

    let tmp = TmpDir::new("svc-check-locking");
    let repo = new_repo(&tmp, RepoMode::Archive, "locking=false\n");
    let mut wrong_version = hello(&["bad//name"]);
    wrong_version.version = 2;
    assert_eq!(
        code(&check(&repo, &wrong_version)),
        Some(ErrorCode::VersionUnsupported)
    );
    assert_eq!(
        code(&check(&repo, &hello(&["bad//name"]))),
        Some(ErrorCode::LockingDisabled)
    );
    let mut one_way = hello(&many);
    one_way.one_way = true;
    check(&repo, &one_way).unwrap();
    one_way.refs.push("bad//name".into());
    assert_eq!(code(&check(&repo, &one_way)), Some(ErrorCode::InvalidRef));

    let tmp = TmpDir::new("svc-check-bsx");
    let repo = new_repo(&tmp, RepoMode::BareSplitXattrs, "locking=false\n");
    assert_eq!(
        code(&check(&repo, &hello(&["bad//name"]))),
        Some(ErrorCode::ModeRefused)
    );

    let tmp = TmpDir::new("svc-check-reply");
    let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=1\n");
    let mut bad_name = hello(&many);
    bad_name.refs.push("bad//name".into());
    assert_eq!(code(&check(&repo, &bad_name)), Some(ErrorCode::InvalidRef));
    assert_eq!(
        code(&check(&repo, &hello(&many))),
        Some(ErrorCode::LimitExceeded)
    );
    let policy = Arc::new(ReceivePolicy::default());
    let holder = foreign_holder(repo.path(), ".lock");
    let started = Instant::now();
    let opened = block_on(ReceiveService::hello(repo.clone(), policy, 1, hello(&many)));
    let waited = started.elapsed();
    drop(holder);
    let opened = opened.map(|_| ());
    assert_eq!(code(&opened), Some(ErrorCode::LimitExceeded), "{opened:?}");
    let message = opened.unwrap_err().to_string();
    assert!(message.contains("100000 refs"), "{message}");
    assert!(
        waited < Duration::from_secs(1),
        "the Hello returned after {waited:?}"
    );

    let tmp = TmpDir::new("svc-check-bare");
    let repo = new_repo(&tmp, RepoMode::Bare, "");
    check(&repo, &hello(&["main"])).unwrap();
    assert!(staging_entries(repo.path()).is_empty());
}

/// Two concurrent streams carry the objects of the fixture commit. The
/// `commit` step then writes the ref. After that step, each step fails with
/// `protocol`.
#[test]
fn a_push_through_the_steps_commits() {
    let tmp = TmpDir::new("svc-push");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 2, &["test/main"]);
    let objects = fixture_objects(Encoding::Raw);
    let names: Vec<ObjectName> = objects
        .iter()
        .map(|o| ObjectName::new(o.checksum, o.ty))
        .collect();
    let have = block_on(service.have(names.clone())).unwrap();
    assert!((0..names.len()).all(|i| have.is_missing(i)));

    let (first, second) = objects.split_at(objects.len() / 2);
    let (a, b) = (body(first), body(second));
    let (ra, rb) = block_on(zip(service.objects(&a[..]), service.objects(&b[..])));
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!((ra.objects + rb.objects) as usize, objects.len());

    let have = block_on(service.have(names.clone())).unwrap();
    assert!((0..names.len()).all(|i| !have.is_missing(i)));
    let report = block_on(service.commit(fixture_update())).unwrap();
    assert_eq!(
        report.refs,
        vec![RefOutcome {
            name: "test/main".into(),
            old: None,
            new: Some(fixture_commit()),
        }]
    );
    assert_eq!(
        std::fs::read_to_string(repo.path().join("refs/heads/test/main")).unwrap(),
        format!("{COMMIT}\n")
    );
    assert!(staging_entries(repo.path()).is_empty());

    assert_ended(block_on(service.have(names)), "the session committed");
    assert_ended(
        block_on(service.objects(&body(&[])[..])),
        "the session committed",
    );
    assert_ended(
        block_on(service.commit(fixture_update())),
        "the session committed",
    );
}

/// A `commit` step that fails ends the session with its error.
#[test]
fn a_failed_commit_ends_the_session() {
    let tmp = TmpDir::new("svc-commit-fail");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 1, &["other"]);
    let result = block_on(service.commit(fixture_update()));
    assert_eq!(code(&result), Some(ErrorCode::Protocol));
    assert_ended(
        block_on(service.have(vec![])),
        "the session was aborted: protocol:",
    );
    assert!(staging_entries(repo.path()).is_empty());
}

/// If the reply to a `Commit` can pass the frame limit after the server reads
/// the refs, the step fails with `limit-exceeded`. The server writes no ref.
/// Each update expects its ref to be absent, so the request states no
/// old commit. The reply can state one old commit for each ref.
#[test]
fn a_commit_whose_reply_cannot_fit_writes_no_ref() {
    let tmp = TmpDir::new("svc-commit-reply-limit");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let names: Vec<String> = (0..15_000).map(|i| format!("refs-{i:015}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let service = open(&repo, 1, &refs);
    let request = CommitRequest {
        updates: names
            .iter()
            .map(|name| RefUpdate {
                name: name.clone(),
                expected: Expected::Absent,
                new: Some(fixture_commit()),
            })
            .collect(),
        force: false,
    };
    let result = block_on(service.commit(request));
    assert_eq!(code(&result), Some(ErrorCode::LimitExceeded));
    assert_eq!(block_on(repo.resolve_rev(&names[0], true)).unwrap(), None);
    assert!(staging_entries(repo.path()).is_empty());
}

/// If two streams carry the same objects at the same time, both streams
/// succeed. The `commit` step publishes each object once. Each stream stops
/// in the middle of the largest content object until the other stream gets
/// to the same point. As a result, the two streams read that object at the
/// same time.
#[test]
fn the_same_objects_on_two_streams_both_succeed() {
    let tmp = TmpDir::new("svc-same");
    let repo = new_repo(&tmp, RepoMode::BareUser, "");
    let service = open(&repo, 2, &["test/main"]);
    let objects = fixture_objects(Encoding::Raw);
    let k = (0..objects.len())
        .filter(|&i| objects[i].ty == ObjectType::File)
        .max_by_key(|&i| objects[i].bytes.len())
        .unwrap();
    assert!(objects[k].bytes.len() > 16);
    let body = body_with_middle(&objects, k);
    let mut bodies = gated(vec![body.clone(), body]);
    let b = bodies.pop().unwrap();
    let a = bodies.pop().unwrap();
    let (ra, rb) = block_on(zip(service.objects(a), service.objects(b)));
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    // Each stream counts each object once at most, and both count the object
    // they read at the same time.
    assert!(ra.objects as usize <= objects.len(), "{ra:?}");
    assert!(rb.objects as usize <= objects.len(), "{rb:?}");
    assert!(
        ra.objects as usize + rb.objects as usize > objects.len(),
        "{ra:?} {rb:?}"
    );
    let report = block_on(service.commit(fixture_update())).unwrap();
    assert_eq!(
        (report.stats.metadata_written + report.stats.content_written) as usize,
        objects.len(),
        "{report:?}"
    );
    assert_eq!(
        std::fs::read_to_string(repo.path().join("refs/heads/test/main")).unwrap(),
        format!("{COMMIT}\n")
    );
    let reopened = block_on(Repo::open(repo.path())).unwrap();
    let fsck = block_on(reopened.fsck(&ostrya::FsckOptions::default())).unwrap();
    assert!(fsck.is_ok(), "{fsck:?}");
}

// ---------------------------------------------------------------------------
// The body of an objects call.
// ---------------------------------------------------------------------------

#[test]
fn the_body_of_objects_holds_one_object_stream() {
    let mut trailing = body(&[]);
    trailing.push(0);
    let abort = block_on(async {
        let mut w = FrameWriter::new(Vec::new());
        w.write_message(&Message::Abort).await.unwrap();
        w.into_inner()
    });
    let have = block_on(async {
        let mut w = FrameWriter::new(Vec::new());
        w.write_message(&Message::Have(vec![])).await.unwrap();
        w.into_inner()
    });
    let objects = fixture_objects(Encoding::Raw);
    let k = objects
        .iter()
        .position(|o| o.ty == ObjectType::File && o.bytes.len() > 16)
        .unwrap();
    // The cut falls inside the data chunk of an object, and so inside a
    // frame. A body that ends after a whole chunk ends on a frame boundary
    // inside the object.
    let inside = cut_body(&objects, k, objects[k].bytes.len() / 2);
    let boundary = cut_body(&objects, k, objects[k].bytes.len());
    let mut header_cut = cut_body(&objects, k, 0);
    header_cut.truncate(header_cut.len() - 6);
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("an empty body", Vec::new(), "ends before ObjectsEnd"),
        (
            "a body cut inside a data chunk",
            inside,
            "ends before ObjectsEnd",
        ),
        (
            "a body cut after a data chunk",
            boundary,
            "ends before ObjectsEnd",
        ),
        (
            "a body cut inside an ObjectHeader frame",
            header_cut,
            "ends before ObjectsEnd",
        ),
        (
            "a byte after ObjectsEnd",
            trailing,
            "bytes follow ObjectsEnd",
        ),
        ("an Abort frame", abort, "the client aborted the session"),
        ("a Have frame", have, "is out of order"),
    ];
    for (what, bytes, message) in cases {
        let tmp = TmpDir::new("svc-body");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let service = open(&repo, 1, &[]);
        let result = block_on(service.objects(&bytes[..]));
        match &result {
            Err(Error::Push(push::Error::Protocol(m))) => {
                assert!(m.contains(message), "{what}: {m}")
            }
            other => panic!("{what}: expected protocol, got {other:?}"),
        }
        assert_ended(
            block_on(service.have(vec![])),
            "the session was aborted: protocol:",
        );
        assert_staging_removed(repo.path());
    }

    // A body that holds only `ObjectsEnd` is a stream of zero objects.
    let tmp = TmpDir::new("svc-body-empty");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 1, &[]);
    let reply = block_on(service.objects(&body(&[])[..])).unwrap();
    assert_eq!((reply.objects, reply.payload_bytes), (0, 0));
}

// ---------------------------------------------------------------------------
// The steps in flight.
// ---------------------------------------------------------------------------

#[test]
fn an_objects_call_past_parallel_uploads_is_limit_exceeded_and_aborts() {
    let tmp = TmpDir::new("svc-parallel");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 1, &[]);
    let (writer, reader) = live_body();
    let empty = body(&[]);
    let (first, second) = block_on(zip(service.objects(reader), service.objects(&empty[..])));
    assert_eq!(code(&second), Some(ErrorCode::LimitExceeded));
    assert_ended(first, "the session was aborted: limit-exceeded:");
    drop(writer);
    assert_ended(
        block_on(service.commit(fixture_update())),
        "the session was aborted: limit-exceeded:",
    );
    assert_staging_removed(repo.path());
}

#[test]
fn have_runs_next_to_objects_and_does_not_count() {
    let tmp = TmpDir::new("svc-have");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 1, &[]);
    let (mut writer, reader) = live_body();
    let (reply, have) = block_on(zip(service.objects(reader), async {
        let have = service
            .have(vec![ObjectName::new(sha(b"x"), ObjectType::File)])
            .await;
        writer.write_message(&Message::ObjectsEnd).await.unwrap();
        drop(writer);
        have
    }));
    assert!(have.unwrap().is_missing(0));
    assert_eq!(reply.unwrap().objects, 0);
}

#[test]
fn a_commit_while_objects_is_in_flight_is_protocol() {
    let tmp = TmpDir::new("svc-commit-busy");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 2, &["test/main"]);
    let (writer, reader) = live_body();
    let (objects, commit) = block_on(zip(service.objects(reader), async {
        service.commit(fixture_update()).await
    }));
    match &commit {
        Err(Error::Push(push::Error::Protocol(m))) => assert!(m.contains("in flight"), "{m}"),
        other => panic!("expected protocol, got {other:?}"),
    }
    assert_ended(objects, "the session was aborted: protocol:");
    drop(writer);
    assert_staging_removed(repo.path());
    assert!(!repo.path().join("refs/heads/test/main").exists());
}

/// An error in one stream ends the session. The other stream fails at its
/// next read, also in the middle of an object.
#[test]
fn an_error_in_one_stream_fails_the_other_and_aborts() {
    let tmp = TmpDir::new("svc-error");
    let repo = new_repo(&tmp, RepoMode::BareUser, "");
    let service = open(&repo, 2, &[]);
    let (mut writer, reader) = live_body();
    let big = fixture_objects(Encoding::Raw)
        .into_iter()
        .find(|o| o.ty == ObjectType::File && o.bytes.len() > 16)
        .unwrap();
    let corrupt = body(&[corrupt_object()]);
    let (waiting, failed) = block_on(zip(service.objects(reader), async {
        // Half of one object: the other stream waits inside it.
        writer
            .write_message(&Message::ObjectHeader(ObjectHeader {
                name: ObjectName::new(big.checksum, big.ty),
                encoding: big.encoding,
            }))
            .await
            .unwrap();
        writer
            .write_object_data(&big.bytes[..big.bytes.len() / 2])
            .await
            .unwrap();
        futures_lite::future::yield_now().await;
        service.objects(&corrupt[..]).await
    }));
    assert_eq!(code(&failed), Some(ErrorCode::ChecksumMismatch));
    assert_ended(waiting, "the session was aborted: checksum-mismatch:");
    drop(writer);
    assert_staging_removed(repo.path());
}

#[test]
fn abort_wakes_a_waiting_stream_and_ends_the_session() {
    let tmp = TmpDir::new("svc-abort");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 2, &[]);
    let (writer, reader) = live_body();
    let (objects, ()) = block_on(zip(service.objects(reader), async {
        futures_lite::future::yield_now().await;
        service.abort();
    }));
    assert_ended(
        objects,
        "the session was aborted: the host ended the session",
    );
    assert_ended(
        block_on(service.have(vec![])),
        "the session was aborted: the host ended the session",
    );
    assert_ended(
        block_on(service.objects(&body(&[])[..])),
        "the session was aborted: the host ended the session",
    );
    assert_ended(
        block_on(service.commit(fixture_update())),
        "the session was aborted: the host ended the session",
    );
    drop(writer);
    assert_staging_removed(repo.path());
}

/// A drop of a step future in the middle of its body ends the session. A
/// later `commit` step fails with `protocol` and writes no ref.
#[test]
fn a_dropped_objects_call_aborts_the_session() {
    let tmp = TmpDir::new("svc-drop");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 2, &["test/main"]);
    let (mut writer, reader) = live_body();
    let objects = fixture_objects(Encoding::Raw);
    let big = objects
        .iter()
        .find(|o| o.ty == ObjectType::File && o.bytes.len() > 16)
        .unwrap();
    block_on(async {
        let mut call = Box::pin(service.objects(reader));
        writer
            .write_message(&Message::ObjectHeader(ObjectHeader {
                name: ObjectName::new(big.checksum, big.ty),
                encoding: big.encoding,
            }))
            .await
            .unwrap();
        writer
            .write_object_data(&big.bytes[..big.bytes.len() / 2])
            .await
            .unwrap();
        assert!(poll_once(&mut call).await.is_none(), "the call waits");
    });
    let reason = "the session was aborted: a request of the session ended before its reply";
    assert_ended(block_on(service.commit(fixture_update())), reason);
    assert_ended(block_on(service.have(vec![])), reason);
    drop(writer);
    assert_staging_removed(repo.path());
    assert!(!repo.path().join("refs/heads/test/main").exists());
}

#[test]
fn a_dropped_have_aborts_the_session() {
    let tmp = TmpDir::new("svc-drop-have");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 1, &[]);
    block_on(async {
        let mut call = Box::pin(service.have(vec![ObjectName::new(sha(b"x"), ObjectType::File)]));
        assert!(poll_once(&mut call).await.is_none(), "the call waits");
    });
    let reason = "the session was aborted: a request of the session ended before its reply";
    assert_ended(block_on(service.have(vec![])), reason);
    assert_ended(block_on(service.objects(&body(&[])[..])), reason);
    assert_staging_removed(repo.path());
}

#[test]
fn a_dropped_commit_ends_the_session() {
    let tmp = TmpDir::new("svc-drop-commit");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 1, &["test/main"]);
    let objects = fixture_objects(Encoding::Raw);
    block_on(service.objects(&body(&objects)[..])).unwrap();
    block_on(async {
        let mut call = Box::pin(service.commit(fixture_update()));
        assert!(poll_once(&mut call).await.is_none(), "the call waits");
    });
    let reason = "the session was aborted: the commit ended before its result";
    assert_ended(block_on(service.have(vec![])), reason);
    assert_ended(block_on(service.objects(&body(&[])[..])), reason);
    assert_ended(block_on(service.commit(fixture_update())), reason);
}

/// A step that completes after `abort` returns a `protocol` error with the
/// reason for the end of the session.
#[test]
fn a_step_that_completes_after_abort_is_protocol() {
    let tmp = TmpDir::new("svc-late");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 1, &[]);
    let late = block_on(async {
        let mut call = Box::pin(service.have(vec![ObjectName::new(sha(b"x"), ObjectType::File)]));
        assert!(poll_once(&mut call).await.is_none(), "the call waits");
        service.abort();
        call.await
    });
    assert_ended(late, "the session was aborted: the host ended the session");
    assert_staging_removed(repo.path());
}

/// A drop of a service with an open session ends the session and removes
/// the staging directory. This test drops the service outside any runtime.
#[test]
fn a_dropped_open_service_removes_its_staging_directory() {
    let tmp = TmpDir::new("svc-drop-service");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 1, &[]);
    block_on(service.objects(&body(&fixture_objects(Encoding::Raw))[..])).unwrap();
    assert!(!staging_entries(repo.path()).is_empty());
    drop(service);
    assert_staging_removed(repo.path());
}

/// One `have` step runs at a time. If a second `have` starts while the first
/// is in flight, it fails with `limit-exceeded` and ends the session.
#[test]
fn a_second_have_in_flight_is_limit_exceeded_and_aborts() {
    let tmp = TmpDir::new("svc-two-haves");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 1, &[]);
    let names = vec![ObjectName::new(sha(b"x"), ObjectType::File)];
    let second = block_on(async {
        let mut first = Box::pin(service.have(names.clone()));
        assert!(
            poll_once(&mut first).await.is_none(),
            "the first call waits"
        );
        let second = service.have(names.clone()).await;
        // The first call completes after the end of the session. It returns
        // a `protocol` error with the reason for the end.
        assert_ended(first.await, "the session was aborted: limit-exceeded:");
        second
    });
    assert_eq!(code(&second), Some(ErrorCode::LimitExceeded));
    assert_ended(
        block_on(service.have(names)),
        "the session was aborted: limit-exceeded:",
    );
    assert_staging_removed(repo.path());
}

/// The dirtree, dirmeta, and commit objects that the streams of one session
/// read at the same time share one budget. In this test, each object is
/// smaller than the budget, and the two objects together are larger.
#[test]
fn metadata_objects_read_at_the_same_time_past_the_budget_are_limit_exceeded() {
    let tmp = TmpDir::new("svc-budget");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let service = open(&repo, 2, &[]);
    let (mut wa, ra) = live_body();
    let (mut wb, rb) = live_body();
    let zeros = vec![0u8; 64 * 1024];
    let chunks = (65 << 20) / zeros.len();
    let dirtree = |seed: &[u8]| {
        Message::ObjectHeader(ObjectHeader {
            name: ObjectName::new(sha(seed), ObjectType::DirTree),
            encoding: Encoding::Raw,
        })
    };
    let ((a, b), sent) = block_on(zip(zip(service.objects(ra), service.objects(rb)), async {
        // The first stream sends about 65 MiB of an object and does not end
        // the object, so the server holds these bytes. The second stream
        // takes the session past the budget.
        wa.write_message(&dirtree(b"first")).await.unwrap();
        for _ in 0..chunks {
            wa.write_object_data(&zeros).await.unwrap();
        }
        let sent: push::Result<()> = async {
            wb.write_message(&dirtree(b"second")).await?;
            for _ in 0..chunks {
                wb.write_object_data(&zeros).await?;
            }
            Ok(())
        }
        .await;
        drop((wa, wb));
        sent
    }));
    assert!(sent.is_err(), "the server stops reading at the budget");
    let (refused, ended) = match code(&a) {
        Some(ErrorCode::LimitExceeded) => (a, b),
        _ => (b, a),
    };
    match &refused {
        Err(Error::Push(push::Error::LimitExceeded(m))) => {
            assert!(m.contains("at the same time"), "{m}")
        }
        other => panic!("expected limit-exceeded, got {other:?}"),
    }
    assert_ended(ended, "the session was aborted: limit-exceeded:");
    assert_staging_removed(repo.path());
}

/// `ReceiveService` is `Send` and `Sync`, so tasks and threads can share it.
#[test]
fn the_service_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ReceiveService>();
}
