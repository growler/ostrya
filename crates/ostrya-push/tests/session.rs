//! The client session against a scripted server: the replies are encoded in
//! advance, and the bytes the session writes are decoded after it.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::future::block_on;
use futures_lite::io::{AsyncWriteExt, Cursor};
use ostrya_core::filehdr::frame;
use ostrya_core::{Checksum, DeflateSink, FileHeader, ObjectName, ObjectType, Xattrs};
use ostrya_gvariant::{DictBuilder, Type, Value};
use ostrya_push::proto::{
    ErrorMessage, FrameReader, FrameWriter, HaveReply, HelloReply, MIN_FRAME_LIMIT, Message,
    ObjectHeader, ObjectRead, ObjectsReply,
};
use ostrya_push::{
    BoxFuture, Compression, Encoding, Error, ErrorCode, Expected, ObjectData, ObjectSource,
    PushPhase, PushProgress, PushSession, RefOutcome, RefState, RefUpdate, SessionOptions,
};

fn ck(n: u8) -> Checksum {
    Checksum::from_bytes([n; 32])
}

fn file(n: u8) -> ObjectName {
    ObjectName::new(ck(n), ObjectType::File)
}

fn meta_name(ty: ObjectType, n: u8) -> ObjectName {
    ObjectName::new(ck(n), ty)
}

fn regular(mode: u32) -> FileHeader {
    FileHeader {
        uid: 0,
        gid: 0,
        mode: 0o100000 | mode,
        symlink_target: String::new(),
        xattrs: Xattrs::empty(),
    }
}

fn symlink(target: &str) -> FileHeader {
    FileHeader {
        uid: 0,
        gid: 0,
        mode: 0o120777,
        symlink_target: target.into(),
        xattrs: Xattrs::empty(),
    }
}

/// A payload of `len` bytes that compresses in part: runs of four letters,
/// then an xorshift stream.
fn payload(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        if out.len() < len / 2 {
            out.push(b'A' + (state & 3) as u8);
        } else {
            out.push((state >> 24) as u8);
        }
    }
    out
}

/// The raw-DEFLATE stream of `data` at `level`, from a new sink.
fn sink_deflate(data: &[u8], level: u8) -> Vec<u8> {
    block_on(async {
        let mut sink = DeflateSink::new(Vec::new(), level);
        sink.write_all(data).await.unwrap();
        sink.close().await.unwrap();
        sink.into_inner()
    })
}

// ---------------------------------------------------------------------------
// The scripted server.
// ---------------------------------------------------------------------------

/// The bytes a session writes, and the length of each write.
#[derive(Clone, Default)]
struct Capture {
    bytes: Arc<Mutex<Vec<u8>>>,
    writes: Arc<Mutex<Vec<usize>>>,
    /// When set, each write fails with `BrokenPipe`.
    broken: Arc<AtomicBool>,
}

impl Capture {
    fn bytes(&self) -> Vec<u8> {
        self.bytes.lock().unwrap().clone()
    }

    fn writes(&self) -> Vec<usize> {
        self.writes.lock().unwrap().clone()
    }

    fn break_writes(&self) {
        self.broken.store(true, Ordering::SeqCst);
    }
}

impl AsyncWrite for Capture {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.broken.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        self.bytes.lock().unwrap().extend_from_slice(buf);
        self.writes.lock().unwrap().push(buf.len());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn encode(msgs: &[Message]) -> Vec<u8> {
    let mut w = FrameWriter::new(Vec::new());
    for msg in msgs {
        block_on(w.write_message(msg)).unwrap();
    }
    w.into_inner()
}

fn hello_reply(refs: &[&str], encodings: &[Encoding], max_have: u32) -> Message {
    Message::HelloReply(HelloReply {
        version: 1,
        mode: "archive".into(),
        collection_id: None,
        max_frame: MIN_FRAME_LIMIT,
        max_have,
        encodings: encodings.to_vec(),
        parallel_uploads: 1,
        refs: refs
            .iter()
            .map(|r| RefState {
                name: r.to_string(),
                commit: None,
            })
            .collect(),
    })
}

const BOTH: &[Encoding] = &[Encoding::Raw, Encoding::Deflate];

fn objects_reply() -> Message {
    Message::ObjectsReply(ObjectsReply {
        objects: 0,
        payload_bytes: 0,
    })
}

fn error(code: ErrorCode) -> Message {
    Message::Error(ErrorMessage {
        code,
        message: "refused".into(),
        missing: Vec::new(),
        current: None,
    })
}

fn strings(refs: &[&str]) -> Vec<String> {
    refs.iter().map(|r| r.to_string()).collect()
}

/// Open a session on the replies `input`, with the refs `refs`.
fn open_with(
    input: Vec<u8>,
    refs: &[&str],
    opts: SessionOptions,
) -> (ostrya_push::Result<PushSession>, Capture) {
    let out = Capture::default();
    let session = block_on(PushSession::over_stream(
        Cursor::new(input),
        out.clone(),
        &strings(refs),
        opts,
    ));
    (session, out)
}

/// Open a session whose server lists `encodings` and then replies `replies`.
fn open(refs: &[&str], encodings: &[Encoding], replies: &[Message]) -> (PushSession, Capture) {
    let mut msgs = vec![hello_reply(refs, encodings, 16_384)];
    msgs.extend_from_slice(replies);
    let (session, out) = open_with(encode(&msgs), refs, SessionOptions::default());
    (session.unwrap(), out)
}

/// One step of what the session wrote.
#[derive(Debug, PartialEq)]
enum Event {
    Msg(Message),
    Object {
        header: ObjectHeader,
        data: Vec<u8>,
        abandoned: bool,
    },
}

fn decode(bytes: &[u8]) -> Vec<Event> {
    block_on(async {
        let mut r = FrameReader::new(bytes);
        let mut out = Vec::new();
        let mut buf = vec![0u8; 8192];
        while let Some(msg) = r.read_message().await.unwrap() {
            let Message::ObjectHeader(header) = msg else {
                out.push(Event::Msg(msg));
                continue;
            };
            let mut data = Vec::new();
            let abandoned = loop {
                match r.read_object_data(&mut buf).await.unwrap() {
                    ObjectRead::Data(n) => data.extend_from_slice(&buf[..n]),
                    ObjectRead::End => break false,
                    ObjectRead::Abandoned => break true,
                }
            };
            out.push(Event::Object {
                header,
                data,
                abandoned,
            });
            if abandoned {
                out.push(Event::Msg(Message::Abort));
            }
        }
        out
    })
}

/// The events after `Hello`.
fn after_hello(out: &Capture) -> Vec<Event> {
    let mut events = decode(&out.bytes());
    assert!(matches!(
        events.first(),
        Some(Event::Msg(Message::Hello(_)))
    ));
    events.remove(0);
    events
}

/// The objects of `events`, as (name, encoding, bytes).
fn objects(events: &[Event]) -> Vec<(ObjectName, Encoding, Vec<u8>)> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Object { header, data, .. } => {
                Some((header.name, header.encoding, data.clone()))
            }
            Event::Msg(_) => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The test source.
// ---------------------------------------------------------------------------

/// A reader that gives `data` and then fails.
struct Failing {
    data: Cursor<Vec<u8>>,
}

impl AsyncRead for Failing {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.data).poll_read(cx, buf) {
            Poll::Ready(Ok(0)) => Poll::Ready(Err(io::Error::other("the file went away"))),
            other => other,
        }
    }
}

#[derive(Clone)]
enum Item {
    /// A content object the session encodes.
    Content(FileHeader, Option<Vec<u8>>),
    /// Encoded bytes.
    Encoded(Encoding, Vec<u8>),
    /// A regular file whose payload fails after these bytes.
    Failing(Vec<u8>),
    /// An open that never completes.
    Stalled,
}

#[derive(Default)]
struct Source {
    items: HashMap<ObjectName, Item>,
    meta: HashMap<Checksum, Value>,
    /// Each open, with the encoding the session named.
    opened: Mutex<Vec<(ObjectName, Encoding)>>,
    /// Each detached metadata request.
    asked: Mutex<Vec<Checksum>>,
}

impl Source {
    fn with(mut self, name: ObjectName, item: Item) -> Source {
        self.items.insert(name, item);
        self
    }
}

impl ObjectSource for Source {
    fn objects<'a>(
        &'a self,
        _commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya_push::Result<Vec<ObjectName>>> {
        Box::pin(async move { Ok(self.items.keys().copied().collect()) })
    }

    fn open<'a>(
        &'a self,
        name: &'a ObjectName,
        encoding: Encoding,
    ) -> BoxFuture<'a, ostrya_push::Result<ObjectData>> {
        self.opened.lock().unwrap().push((*name, encoding));
        let item = self.items[name].clone();
        Box::pin(async move {
            Ok(match item {
                Item::Content(header, payload) => ObjectData::Content {
                    size: payload.as_ref().map_or(0, |p| p.len() as u64),
                    header,
                    payload: payload.map(|p| Box::new(Cursor::new(p)) as _),
                },
                Item::Encoded(encoding, bytes) => ObjectData::Encoded {
                    encoding,
                    reader: Box::new(Cursor::new(bytes)),
                },
                Item::Failing(bytes) => ObjectData::Content {
                    header: regular(0o644),
                    size: bytes.len() as u64 + 10,
                    payload: Some(Box::new(Failing {
                        data: Cursor::new(bytes),
                    })),
                },
                Item::Stalled => futures_lite::future::pending().await,
            })
        })
    }

    fn detached_metadata<'a>(
        &'a self,
        commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya_push::Result<Option<Value>>> {
        self.asked.lock().unwrap().push(*commit);
        Box::pin(async move { Ok(self.meta.get(commit).cloned()) })
    }
}

fn a_sv_bytes(dict: &Value) -> Vec<u8> {
    ostrya_gvariant::to_bytes(&Type::parse("a{sv}").unwrap(), dict).unwrap()
}

fn assert_invalid<T: std::fmt::Debug>(r: ostrya_push::Result<T>, text: &str) {
    match r {
        Err(Error::InvalidInput(m)) => assert!(m.contains(text), "{m}"),
        other => panic!("expected InvalidInput with {text:?}, got {other:?}"),
    }
}

fn update(name: &str) -> RefUpdate {
    RefUpdate {
        name: name.into(),
        expected: Expected::Absent,
        new: Some(ck(9)),
    }
}

// ---------------------------------------------------------------------------
// Hello.
// ---------------------------------------------------------------------------

#[test]
fn hello_carries_the_version_the_agent_and_the_refs() {
    let (_, out) = open(&["a", "b"], BOTH, &[]);
    match &decode(&out.bytes())[..] {
        [Event::Msg(Message::Hello(h))] => {
            assert_eq!(h.version, 1);
            assert_eq!(
                h.agent.as_deref(),
                Some(concat!("ostrya/", env!("CARGO_PKG_VERSION")))
            );
            assert_eq!(h.refs, strings(&["a", "b"]));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn hello_reply_refs_that_differ_are_protocol() {
    for refs in [&["a", "c"][..], &["b", "a"], &["a"], &["a", "b", "c"]] {
        let input = encode(&[hello_reply(refs, BOTH, 16)]);
        let (r, _) = open_with(input, &["a", "b"], SessionOptions::default());
        assert!(matches!(r, Err(Error::Protocol(_))), "{refs:?}");
    }
}

#[test]
fn hello_reply_of_another_version_is_protocol() {
    let mut reply = hello_reply(&["a"], BOTH, 16);
    if let Message::HelloReply(r) = &mut reply {
        r.version = 2;
    }
    let (r, _) = open_with(encode(&[reply]), &["a"], SessionOptions::default());
    assert!(matches!(r, Err(Error::Protocol(_))));
}

#[test]
fn error_at_hello_is_that_error() {
    let input = encode(&[Message::Error(ErrorMessage {
        code: ErrorCode::LockingDisabled,
        message: "no locks".into(),
        missing: Vec::new(),
        current: None,
    })]);
    let (r, _) = open_with(input, &["a"], SessionOptions::default());
    assert!(matches!(r, Err(Error::LockingDisabled(m)) if m == "no locks"));
    let (r, _) = open_with(Vec::new(), &["a"], SessionOptions::default());
    assert!(matches!(r, Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof));
    let (r, _) = open_with(
        encode(&[objects_reply()]),
        &["a"],
        SessionOptions::default(),
    );
    assert!(matches!(r, Err(Error::Protocol(_))));
}

// ---------------------------------------------------------------------------
// Have.
// ---------------------------------------------------------------------------

#[test]
fn missing_sends_batches_of_max_have() {
    let names: Vec<ObjectName> = (1..=5).map(file).collect();
    let replies = [
        Message::HaveReply(HaveReply::from_missing([true, false])),
        Message::HaveReply(HaveReply::from_missing([false, true])),
        Message::HaveReply(HaveReply::from_missing([true])),
    ];
    let mut msgs = vec![hello_reply(&["a"], BOTH, 2)];
    msgs.extend(replies);
    let (session, out) = open_with(encode(&msgs), &["a"], SessionOptions::default());
    let session = session.unwrap();
    let missing = block_on(session.missing(&names)).unwrap();
    assert_eq!(missing, vec![file(1), file(4), file(5)]);
    let haves: Vec<Vec<ObjectName>> = after_hello(&out)
        .into_iter()
        .map(|e| match e {
            Event::Msg(Message::Have(names)) => names,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        haves,
        vec![
            names[..2].to_vec(),
            names[2..4].to_vec(),
            names[4..].to_vec()
        ]
    );
}

/// The object types that neither `Have` nor the object stream of a client
/// carries.
const OFF_WIRE: [ObjectType; 5] = [
    ObjectType::TombstoneCommit,
    ObjectType::CommitMeta,
    ObjectType::PayloadLink,
    ObjectType::FileXattrs,
    ObjectType::FileXattrsLink,
];

#[test]
fn missing_refuses_types_off_the_wire_and_a_bad_bitmap() {
    let (session, out) = open(
        &["a"],
        BOTH,
        &[Message::HaveReply(HaveReply::from_missing([true]))],
    );
    for ty in OFF_WIRE {
        assert_invalid(
            block_on(session.missing(&[file(1), meta_name(ty, 1)])),
            "is not an object to offer or send",
        );
    }
    assert!(after_hello(&out).is_empty(), "nothing sent");
    // The session stays usable.
    assert_eq!(
        block_on(session.missing(&[file(1)])).unwrap(),
        vec![file(1)]
    );

    let (session, _) = open(
        &["a"],
        BOTH,
        &[Message::HaveReply(HaveReply { bitmap: vec![0, 0] })],
    );
    assert!(matches!(
        block_on(session.missing(&[file(1)])),
        Err(Error::Protocol(_))
    ));
    assert_invalid(
        block_on(session.missing(&[file(1)])),
        "the session is broken",
    );
}

#[test]
fn missing_splits_a_batch_that_does_not_fit_the_frame_limit() {
    let fit = |n: usize| {
        let names = vec![file(1); n];
        let mut w = FrameWriter::new(Vec::new());
        block_on(w.write_message(&Message::Have(names))).is_ok()
    };
    let names: Vec<ObjectName> = (0..30_000u32)
        .map(|i| {
            let mut sum = [0u8; 32];
            sum[..4].copy_from_slice(&i.to_be_bytes());
            ObjectName::new(Checksum::from_bytes(sum), ObjectType::File)
        })
        .collect();
    // The most entries of one Have at the frame limit.
    let counts: Vec<usize> = (1..=names.len()).collect();
    let first = counts.partition_point(|n| fit(*n));
    assert!(first < names.len(), "the names need two frames");
    let msgs = [
        hello_reply(&["a"], BOTH, u32::MAX),
        Message::HaveReply(HaveReply::from_missing(vec![false; first])),
        Message::HaveReply(HaveReply::from_missing(vec![true; names.len() - first])),
    ];
    let (session, out) = open_with(encode(&msgs), &["a"], SessionOptions::default());
    let missing = block_on(session.unwrap().missing(&names)).unwrap();
    assert_eq!(missing, names[first..]);
    let sizes: Vec<usize> = after_hello(&out)
        .into_iter()
        .map(|e| match e {
            Event::Msg(Message::Have(batch)) => batch.len(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(sizes, vec![first, names.len() - first]);
}

#[test]
fn a_failed_request_write_gives_the_pending_error() {
    // Have.
    let (session, out) = open(&["a"], BOTH, &[error(ErrorCode::Unauthorized)]);
    out.break_writes();
    assert!(matches!(
        block_on(session.missing(&[file(1)])),
        Err(Error::Unauthorized(_))
    ));

    // ObjectsEnd, after an object the stream buffer holds.
    let source = Source::default()
        .with(file(1), Item::Encoded(Encoding::Raw, b"x".to_vec()))
        .with(
            file(2),
            Item::Content(regular(0o644), Some(payload(300_000, 7))),
        );
    let (session, out) = open(&["a"], BOTH, &[error(ErrorCode::ModeRefused)]);
    out.break_writes();
    assert!(matches!(
        block_on(session.send(&source, &[file(1)], &[], Compression::None)),
        Err(Error::ModeRefused(_))
    ));

    // A write in the middle of an object.
    for compression in [Compression::None, Compression::Deflate { level: 1 }] {
        let (session, out) = open(&["a"], BOTH, &[error(ErrorCode::LimitExceeded)]);
        out.break_writes();
        assert!(matches!(
            block_on(session.send(&source, &[file(2)], &[], compression)),
            Err(Error::LimitExceeded(_))
        ));
    }
}

// ---------------------------------------------------------------------------
// The object stream.
// ---------------------------------------------------------------------------

#[test]
fn a_full_chunk_goes_out_with_its_length() {
    let data = payload(5 * 65536 + 100, 8);
    let source = Source::default().with(file(1), Item::Content(regular(0o644), Some(data)));
    for compression in [Compression::None, Compression::Deflate { level: 1 }] {
        let (session, out) = open(&["a"], BOTH, &[objects_reply()]);
        let hello = out.writes().len();
        block_on(session.send(&source, &[file(1)], &[], compression)).unwrap();
        let writes = &out.writes()[hello..];
        assert!(writes.len() > 3, "{compression:?}: {writes:?}");
        // The last write ends the stream and may be short.
        assert!(
            writes[..writes.len() - 1].iter().all(|n| *n >= 16),
            "{compression:?}: {writes:?}"
        );
    }
}

#[test]
fn detached_metadata_over_the_frame_limit_goes_in_chunks() {
    let big = vec![7u8; MIN_FRAME_LIMIT as usize * 3 / 2];
    let mut dict = DictBuilder::new();
    dict.insert_bytes("big", &big);
    let dict = dict.build();
    let mut source = Source::default();
    source.meta.insert(ck(1), dict.clone());
    let (session, out) = open(&["a"], BOTH, &[objects_reply()]);
    block_on(session.send(&source, &[], &[ck(1)], Compression::None)).unwrap();
    // The decoder reads at the frame limit, so each chunk fits it.
    assert_eq!(
        objects(&after_hello(&out)),
        vec![(
            meta_name(ObjectType::CommitMeta, 1),
            Encoding::Raw,
            a_sv_bytes(&dict)
        )]
    );
}

#[test]
fn raw_content_metadata_and_encoded_objects() {
    let data = payload(100_000, 1);
    let dirtree = b"dirtree bytes".to_vec();
    let source = Source::default()
        .with(file(1), Item::Content(regular(0o644), Some(data.clone())))
        .with(file(2), Item::Content(symlink("target"), None))
        .with(
            meta_name(ObjectType::DirTree, 3),
            Item::Encoded(Encoding::Raw, dirtree.clone()),
        );
    let (session, out) = open(&["a"], BOTH, &[objects_reply()]);
    let names = [file(1), file(2), meta_name(ObjectType::DirTree, 3)];
    block_on(session.send(&source, &names, &[], Compression::None)).unwrap();
    let events = after_hello(&out);
    assert_eq!(events.last(), Some(&Event::Msg(Message::ObjectsEnd)));
    let mut want1 = frame(&regular(0o644).serialize().unwrap()).unwrap();
    want1.extend_from_slice(&data);
    let want2 = frame(&symlink("target").serialize().unwrap()).unwrap();
    assert_eq!(
        objects(&events),
        vec![
            (file(1), Encoding::Raw, want1),
            (file(2), Encoding::Raw, want2),
            (meta_name(ObjectType::DirTree, 3), Encoding::Raw, dirtree),
        ]
    );
    let opened = source.opened.lock().unwrap().clone();
    assert!(opened.iter().all(|(_, e)| *e == Encoding::Raw));
}

#[test]
fn deflate_falls_back_to_raw_when_the_server_lists_raw_alone() {
    let data = payload(5000, 2);
    let source = Source::default().with(file(1), Item::Content(regular(0o644), Some(data.clone())));
    let (session, out) = open(&["a"], &[Encoding::Raw], &[objects_reply()]);
    block_on(session.send(&source, &[file(1)], &[], Compression::Deflate { level: 6 })).unwrap();
    let mut want = frame(&regular(0o644).serialize().unwrap()).unwrap();
    want.extend_from_slice(&data);
    assert_eq!(
        objects(&after_hello(&out)),
        vec![(file(1), Encoding::Raw, want)]
    );
    assert_eq!(
        source.opened.lock().unwrap()[0],
        (file(1), Encoding::Raw),
        "the source is asked for raw"
    );
}

#[test]
fn deflated_content_equals_the_sink_output() {
    let first = payload(3 * 65536 / 2, 3);
    let second = payload(70_000, 4);
    for level in 1..=9 {
        let source = Source::default()
            .with(file(1), Item::Content(regular(0o644), Some(first.clone())))
            .with(file(2), Item::Content(regular(0o755), Some(second.clone())))
            .with(file(3), Item::Content(symlink("t"), None))
            .with(file(4), Item::Content(regular(0o600), Some(Vec::new())));
        let (session, out) = open(&["a"], BOTH, &[objects_reply()]);
        let names = [file(1), file(2), file(3), file(4)];
        block_on(session.send(&source, &names, &[], Compression::Deflate { level })).unwrap();
        let expect = |header: &FileHeader, data: Option<&[u8]>| {
            let size = data.map_or(0, |d| d.len() as u64);
            let mut bytes = frame(&header.serialize_archive(size).unwrap()).unwrap();
            if let Some(d) = data {
                bytes.extend(sink_deflate(d, level));
            }
            bytes
        };
        let got = objects(&after_hello(&out));
        let want = vec![
            (
                file(1),
                Encoding::Deflate,
                expect(&regular(0o644), Some(&first)),
            ),
            (
                file(2),
                Encoding::Deflate,
                expect(&regular(0o755), Some(&second)),
            ),
            (file(3), Encoding::Deflate, expect(&symlink("t"), None)),
            (
                file(4),
                Encoding::Deflate,
                expect(&regular(0o600), Some(&[])),
            ),
        ];
        assert_eq!(got, want, "level {level}");
        // The symlink carries the framed archive header alone, and the empty
        // file a closed empty DEFLATE stream.
        let symlink_header = frame(&symlink("t").serialize_archive(0).unwrap()).unwrap();
        assert_eq!(got[2].2, symlink_header);
        assert!(
            got[3].2.len()
                > frame(&regular(0o600).serialize_archive(0).unwrap())
                    .unwrap()
                    .len()
        );
        let opened = source.opened.lock().unwrap().clone();
        assert!(opened.iter().all(|(_, e)| *e == Encoding::Deflate));
    }
}

#[test]
fn encoded_objects_pass_through() {
    let filez = b"stored filez bytes".to_vec();
    let raw = b"raw content bytes".to_vec();
    let source = Source::default()
        .with(file(1), Item::Encoded(Encoding::Deflate, filez.clone()))
        .with(file(2), Item::Encoded(Encoding::Raw, raw.clone()));
    for compression in [Compression::None, Compression::Deflate { level: 1 }] {
        let (session, out) = open(&["a"], BOTH, &[objects_reply()]);
        block_on(session.send(&source, &[file(1), file(2)], &[], compression)).unwrap();
        assert_eq!(
            objects(&after_hello(&out)),
            vec![
                (file(1), Encoding::Deflate, filez.clone()),
                (file(2), Encoding::Raw, raw.clone()),
            ],
            "{compression:?}"
        );
    }
}

#[test]
fn deflated_bytes_the_session_cannot_send_are_refused() {
    let cases = [
        (&[Encoding::Raw][..], file(1)),
        (BOTH, meta_name(ObjectType::DirMeta, 1)),
    ];
    for (encodings, name) in cases {
        let source = Source::default()
            .with(file(9), Item::Encoded(Encoding::Raw, b"x".to_vec()))
            .with(name, Item::Encoded(Encoding::Deflate, b"filez".to_vec()));
        let (session, out) = open(&["a"], encodings, &[]);
        assert_invalid(
            block_on(session.send(&source, &[file(9), name], &[], Compression::None)),
            "deflated",
        );
        let events = after_hello(&out);
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(matches!(
            events[0],
            Event::Object {
                abandoned: false,
                ..
            }
        ));
        assert_eq!(events[1], Event::Msg(Message::Abort));
        assert_invalid(
            block_on(session.send(&source, &[], &[], Compression::None)),
            "the session is broken",
        );
    }
}

#[test]
fn content_data_that_does_not_fit_its_header_is_refused() {
    let cases = [
        (file(1), Item::Content(symlink("t"), Some(b"x".to_vec()))),
        (file(1), Item::Content(regular(0o644), None)),
        (
            meta_name(ObjectType::Commit, 1),
            Item::Content(regular(0o644), Some(Vec::new())),
        ),
    ];
    for (name, item) in cases {
        let source = Source::default().with(name, item);
        let (session, out) = open(&["a"], BOTH, &[]);
        assert!(matches!(
            block_on(session.send(&source, &[name], &[], Compression::None)),
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(after_hello(&out), vec![Event::Msg(Message::Abort)]);
    }
}

#[test]
fn send_refusals_before_any_byte() {
    let source = Source::default().with(file(1), Item::Encoded(Encoding::Raw, b"x".to_vec()));
    let (session, out) = open(&["a"], BOTH, &[objects_reply()]);
    for level in [0, 10] {
        assert_invalid(
            block_on(session.send(&source, &[file(1)], &[], Compression::Deflate { level })),
            "level",
        );
    }
    for ty in OFF_WIRE {
        assert_invalid(
            block_on(session.send(
                &source,
                &[file(1), meta_name(ty, 1)],
                &[],
                Compression::None,
            )),
            "is not an object to offer or send",
        );
    }
    assert!(after_hello(&out).is_empty());
    // The session stays usable, and a call with nothing to send writes
    // nothing.
    block_on(session.send(&source, &[], &[ck(5)], Compression::None)).unwrap();
    assert!(after_hello(&out).is_empty());
    block_on(session.send(&source, &[file(1)], &[], Compression::None)).unwrap();
    assert_eq!(objects(&after_hello(&out)).len(), 1);
}

#[test]
fn detached_metadata_goes_once_per_commit() {
    let mut dict = DictBuilder::new();
    dict.insert_str("key", "value");
    let dict = dict.build();
    let mut source = Source::default().with(
        meta_name(ObjectType::Commit, 1),
        Item::Encoded(Encoding::Raw, b"commit".to_vec()),
    );
    source.meta.insert(ck(1), dict.clone());
    source.meta.insert(ck(2), Value::Array(Vec::new()));
    let (session, out) = open(&["a"], BOTH, &[objects_reply(), objects_reply()]);
    block_on(session.send(
        &source,
        &[meta_name(ObjectType::Commit, 1)],
        &[ck(1), ck(3), ck(1)],
        Compression::None,
    ))
    .unwrap();
    block_on(session.send(&source, &[], &[ck(1), ck(2)], Compression::None)).unwrap();
    // A third call has nothing left to send and writes nothing.
    block_on(session.send(&source, &[], &[ck(1), ck(2)], Compression::None)).unwrap();
    let events = after_hello(&out);
    let ends = events
        .iter()
        .filter(|e| **e == Event::Msg(Message::ObjectsEnd))
        .count();
    assert_eq!(ends, 2, "two object streams");
    assert_eq!(
        objects(&events),
        vec![
            (
                meta_name(ObjectType::Commit, 1),
                Encoding::Raw,
                b"commit".to_vec()
            ),
            (
                meta_name(ObjectType::CommitMeta, 1),
                Encoding::Raw,
                a_sv_bytes(&dict)
            ),
            (
                meta_name(ObjectType::CommitMeta, 2),
                Encoding::Raw,
                a_sv_bytes(&Value::Array(Vec::new()))
            ),
        ]
    );
}

#[test]
fn a_failing_source_abandons_the_object_and_aborts() {
    let source = Source::default()
        .with(file(1), Item::Encoded(Encoding::Raw, b"ok".to_vec()))
        .with(file(2), Item::Failing(payload(10_000, 5)));
    for compression in [Compression::None, Compression::Deflate { level: 6 }] {
        let (session, out) = open(&["a"], BOTH, &[]);
        let r = block_on(session.send(&source, &[file(1), file(2)], &[], compression));
        match &r {
            Err(e @ Error::Source(_)) => {
                let cause = std::error::Error::source(e).expect("the cause of the source error");
                assert!(cause.to_string().contains("the file went away"), "{cause}");
            }
            other => panic!("{other:?}"),
        }
        let events = after_hello(&out);
        assert_eq!(events.len(), 3, "{events:?}");
        assert!(matches!(
            events[0],
            Event::Object {
                abandoned: false,
                ..
            }
        ));
        assert!(matches!(
            events[1],
            Event::Object {
                abandoned: true,
                ..
            }
        ));
        assert_eq!(events[2], Event::Msg(Message::Abort));
        assert_invalid(block_on(session.missing(&[])), "the session is broken");
        assert_invalid(block_on(session.abort()), "the session is broken");
    }
}

#[test]
fn a_reply_other_than_objects_reply() {
    let source = Source::default().with(file(1), Item::Encoded(Encoding::Raw, b"x".to_vec()));
    let (session, _) = open(
        &["a"],
        BOTH,
        &[Message::Error(ErrorMessage {
            code: ErrorCode::ChecksumMismatch,
            message: "bad".into(),
            missing: Vec::new(),
            current: None,
        })],
    );
    assert!(matches!(
        block_on(session.send(&source, &[file(1)], &[], Compression::None)),
        Err(Error::ChecksumMismatch(_))
    ));
    let (session, _) = open(
        &["a"],
        BOTH,
        &[Message::HaveReply(HaveReply { bitmap: vec![] })],
    );
    assert!(matches!(
        block_on(session.send(&source, &[file(1)], &[], Compression::None)),
        Err(Error::Protocol(_))
    ));
}

// ---------------------------------------------------------------------------
// Concurrent calls.
// ---------------------------------------------------------------------------

#[test]
fn an_overlapping_call_fails_and_a_dropped_call_breaks_the_session() {
    let source = Source::default().with(file(1), Item::Stalled);
    let (session, _) = open(&["a"], BOTH, &[]);
    block_on(async {
        let names = [file(1)];
        let mut call = Box::pin(session.send(&source, &names, &[], Compression::None));
        assert!(futures_lite::future::poll_once(&mut call).await.is_none());
        assert_invalid(session.missing(&[file(1)]).await, "a call is in progress");
        assert_invalid(
            session.send(&source, &[], &[], Compression::None).await,
            "a call is in progress",
        );
        drop(call);
        assert_invalid(session.missing(&[file(1)]).await, "the session is broken");
    });
    assert_invalid(
        block_on(session.commit(&[update("a")], false)),
        "the session is broken",
    );
}

// ---------------------------------------------------------------------------
// Commit.
// ---------------------------------------------------------------------------

fn commit_reply(names: &[&str]) -> Message {
    Message::CommitReply(
        names
            .iter()
            .map(|n| RefOutcome {
                name: n.to_string(),
                old: None,
                new: Some(ck(9)),
            })
            .collect(),
    )
}

#[test]
fn commit_returns_the_outcomes() {
    let (session, out) = open(&["a", "b"], BOTH, &[commit_reply(&["b", "a"])]);
    let outcome = block_on(session.commit(&[update("b"), update("a")], true)).unwrap();
    assert_eq!(outcome.commit, None);
    assert_eq!(outcome.refs.len(), 2);
    match &after_hello(&out)[..] {
        [Event::Msg(Message::Commit(c))] => {
            assert!(c.force);
            assert_eq!(c.updates, vec![update("b"), update("a")]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn commit_prechecks_send_nothing() {
    let cases: [(&[RefUpdate], &str); 3] = [
        (&[], "at least one"),
        (&[update("c")], "not named"),
        (&[update("a"), update("a")], "twice"),
    ];
    for (updates, text) in cases {
        let (session, out) = open(&["a", "b"], BOTH, &[commit_reply(&["a"])]);
        assert_invalid(block_on(session.commit(updates, false)), text);
        assert!(after_hello(&out).is_empty(), "{text}");
    }
}

#[test]
fn a_break_after_commit_is_an_unknown_outcome() {
    let reply = encode(&[commit_reply(&["a", "b"])]);
    let truncated = reply[..reply.len() - 3].to_vec();
    let others = encode(&[objects_reply()]);
    for tail in [Vec::new(), truncated, others] {
        let mut input = encode(&[hello_reply(&["a", "b"], BOTH, 16)]);
        input.extend(tail);
        let (session, out) = open_with(input, &["a", "b"], SessionOptions::default());
        let r = block_on(session.unwrap().commit(&[update("a"), update("b")], false));
        match r {
            Err(Error::CommitOutcomeUnknown { refs, .. }) => assert_eq!(refs, strings(&["a", "b"])),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            &after_hello(&out)[..],
            [Event::Msg(Message::Commit(_))]
        ));
    }
}

#[test]
fn an_error_after_commit_is_that_error() {
    let error = Message::Error(ErrorMessage {
        code: ErrorCode::RefMismatch,
        message: "moved".into(),
        missing: Vec::new(),
        current: Some(RefState {
            name: "a".into(),
            commit: Some(ck(4)),
        }),
    });
    let (session, _) = open(&["a"], BOTH, &[error]);
    match block_on(session.commit(&[update("a")], false)) {
        Err(Error::RefMismatch { name, current, .. }) => {
            assert_eq!(name, "a");
            assert_eq!(current, Some(ck(4)));
        }
        other => panic!("{other:?}"),
    }
}

/// Assert that `r` is an unknown outcome for `refs`, with `text` in its
/// message.
fn assert_unknown<T: std::fmt::Debug>(r: ostrya_push::Result<T>, refs: &[&str], text: &str) {
    match r {
        Err(Error::CommitOutcomeUnknown { refs: got, message }) => {
            assert_eq!(got, strings(refs));
            assert!(message.contains(text), "{message}");
        }
        other => panic!("expected CommitOutcomeUnknown with {text:?}, got {other:?}"),
    }
}

#[test]
fn a_commit_reply_for_other_refs_is_an_unknown_outcome() {
    for reply in [&["b", "a"][..], &["a"], &["a", "b", "c"]] {
        let (session, _) = open(&["a", "b", "c"], BOTH, &[commit_reply(reply)]);
        assert_unknown(
            block_on(session.commit(&[update("a"), update("b")], false)),
            &["a", "b"],
            "other refs",
        );
    }
}

#[test]
fn a_failed_commit_write_reads_the_pending_reply() {
    // A CommitReply read after the write failed is the reply.
    let (session, out) = open(&["a"], BOTH, &[commit_reply(&["a"])]);
    out.break_writes();
    let outcome = block_on(session.commit(&[update("a")], false)).unwrap();
    assert_eq!(outcome.refs.len(), 1);
    assert_eq!(outcome.refs[0].name, "a");

    // A pending reply for other refs is an unknown outcome.
    let (session, out) = open(&["a", "b"], BOTH, &[commit_reply(&["b"])]);
    out.break_writes();
    assert_unknown(
        block_on(session.commit(&[update("a")], false)),
        &["a"],
        "other refs",
    );

    // A pending Error is that error.
    let (session, out) = open(&["a"], BOTH, &[error(ErrorCode::Unauthorized)]);
    out.break_writes();
    assert!(matches!(
        block_on(session.commit(&[update("a")], false)),
        Err(Error::Unauthorized(_))
    ));

    // No pending message is an unknown outcome.
    let (session, out) = open(&["a"], BOTH, &[]);
    out.break_writes();
    assert_unknown(
        block_on(session.commit(&[update("a")], false)),
        &["a"],
        "the write of Commit failed",
    );
}

#[test]
fn abort_sends_abort() {
    let (session, out) = open(&["a"], BOTH, &[]);
    block_on(session.abort()).unwrap();
    assert_eq!(after_hello(&out), vec![Event::Msg(Message::Abort)]);
}

// ---------------------------------------------------------------------------
// Progress.
// ---------------------------------------------------------------------------

#[test]
fn progress_counts_and_phases() {
    let progress = PushProgress::new();
    assert_eq!(progress.snapshot().phase, PushPhase::Scanning);
    let data = payload(10_000, 6);
    let mut source = Source::default()
        .with(file(1), Item::Content(regular(0o644), Some(data.clone())))
        .with(file(2), Item::Encoded(Encoding::Raw, b"xyz".to_vec()));
    source.meta.insert(ck(7), Value::Array(Vec::new()));
    let msgs = [
        hello_reply(&["a"], BOTH, 16),
        Message::HaveReply(HaveReply::from_missing([true, true, false])),
        objects_reply(),
        commit_reply(&["a"]),
    ];
    let opts = SessionOptions {
        agent: Some("test/1".into()),
        progress: Some(progress.clone()),
    };
    let (session, out) = open_with(encode(&msgs), &["a"], opts);
    let session = session.unwrap();
    assert_eq!(progress.snapshot().phase, PushPhase::Negotiating);
    assert_eq!(progress.snapshot().bytes_sent, out.bytes().len() as u64);

    let needed = block_on(session.missing(&[file(1), file(2), file(3)])).unwrap();
    let snap = progress.snapshot();
    assert_eq!((snap.objects_total, snap.objects_needed), (3, 2));

    block_on(session.send(&source, &needed, &[ck(7)], Compression::None)).unwrap();
    let snap = progress.snapshot();
    assert_eq!(snap.phase, PushPhase::Uploading);
    assert_eq!(snap.objects_sent, 2, "the detached metadata does not count");
    let header = frame(&regular(0o644).serialize().unwrap()).unwrap();
    let meta = a_sv_bytes(&Value::Array(Vec::new()));
    assert_eq!(
        snap.payload_bytes,
        (header.len() + data.len() + 3 + meta.len()) as u64
    );
    assert_eq!(snap.bytes_sent, out.bytes().len() as u64);

    let outcome = block_on(session.commit(&[update("a")], false)).unwrap();
    let snap = progress.snapshot();
    assert_eq!(snap.phase, PushPhase::Committing);
    let stats = outcome.stats;
    assert_eq!(
        (
            stats.objects_total,
            stats.objects_needed,
            stats.objects_sent,
            stats.payload_bytes
        ),
        (3, 2, 2, snap.payload_bytes)
    );
    assert_eq!(stats.bytes_sent, out.bytes().len() as u64);
    assert_eq!(snap.bytes_sent, stats.bytes_sent);
    match &decode(&out.bytes())[0] {
        Event::Msg(Message::Hello(h)) => assert_eq!(h.agent.as_deref(), Some("test/1")),
        other => panic!("{other:?}"),
    }
}
