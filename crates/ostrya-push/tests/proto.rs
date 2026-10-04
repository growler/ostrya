//! The wire protocol: round trips, golden bytes, malformed input, limits,
//! the abandon marker, and the bodies of the pull.

use futures_lite::future::block_on;
use ostrya_core::{Checksum, ObjectName, ObjectType};
use ostrya_gvariant::{DictBuilder, Type, Value};
use ostrya_push::proto::{
    CommitRequest, ErrorMessage, FrameReader, FrameWriter, GetReply, HaveReply, Hello, HelloReply,
    Kind, MAX_FRAME, MAX_FRAME_LIMIT, MAX_HAVE, MIN_FRAME_LIMIT, Message, ObjectHeader, ObjectRead,
    ObjectsReply, PULL_PROTOCOL_VERSION, PullHello, PullHelloReply, RefState,
};
use ostrya_push::{Encoding, Error, ErrorCode, Expected, RefOutcome, RefUpdate};

const MIB: usize = 1 << 20;

fn ck(n: u8) -> Checksum {
    Checksum::from_bytes(std::array::from_fn(|i| n.wrapping_add(i as u8)))
}

fn name(ty: ObjectType, n: u8) -> ObjectName {
    ObjectName::new(ck(n), ty)
}

fn ck_bytes(n: u8) -> Vec<u8> {
    ck(n).as_bytes().to_vec()
}

fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = ((body.len() + 1) as u32).to_be_bytes().to_vec();
    out.push(kind);
    out.extend_from_slice(body);
    out
}

fn ty(signature: &str) -> Type {
    Type::parse(signature).unwrap()
}

fn gv(signature: &str, value: Value) -> Vec<u8> {
    ostrya_gvariant::to_bytes(&ty(signature), &value).unwrap()
}

fn encode(msg: &Message) -> Vec<u8> {
    let mut w = FrameWriter::new(Vec::new());
    block_on(w.write_message(msg)).unwrap();
    w.into_inner()
}

fn read_one(bytes: &[u8]) -> Result<Option<Message>, Error> {
    block_on(FrameReader::new(bytes).read_message())
}

fn assert_protocol(r: Result<impl std::fmt::Debug, Error>) {
    match r {
        Err(Error::Protocol(_)) => {}
        other => panic!("expected protocol, got {other:?}"),
    }
}

fn assert_limit(r: Result<impl std::fmt::Debug, Error>) {
    match r {
        Err(Error::LimitExceeded(_)) => {}
        other => panic!("expected limit-exceeded, got {other:?}"),
    }
}

fn assert_eof(r: Result<impl std::fmt::Debug, Error>) {
    match r {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        other => panic!("expected UnexpectedEof, got {other:?}"),
    }
}

fn round_trip(msg: Message) {
    let bytes = encode(&msg);
    assert_eq!(read_one(&bytes).unwrap(), Some(msg.clone()));
    assert_eq!(encode(&msg), bytes);
}

fn state(name: &str, commit: Option<Checksum>) -> RefState {
    let name = name.into();
    RefState { name, commit }
}

fn outcome(name: &str, old: Option<Checksum>, new: Option<Checksum>) -> RefOutcome {
    let name = name.into();
    RefOutcome { name, old, new }
}

fn update(name: &str, expected: Expected, new: Option<Checksum>) -> RefUpdate {
    let name = name.into();
    RefUpdate {
        name,
        expected,
        new,
    }
}

fn error(code: ErrorCode, message: &str) -> ErrorMessage {
    let (message, missing, current) = (message.into(), vec![], None);
    ErrorMessage {
        code,
        message,
        missing,
        current,
    }
}

/// A valid `Error` of `code`. A `ref-mismatch` carries its ref state.
fn sample_error(code: ErrorCode, message: &str) -> ErrorMessage {
    let mut e = error(code, message);
    if code == ErrorCode::RefMismatch {
        e.current = Some(state("main", None));
    }
    e
}

fn hello(agent: Option<&str>, refs: &[&str]) -> Message {
    let agent = agent.map(Into::into);
    let refs = refs.iter().map(|r| r.to_string()).collect();
    Message::Hello(Hello {
        version: 1,
        agent,
        refs,
        one_way: false,
    })
}

fn hello_reply(refs: Vec<RefState>, collection_id: Option<String>) -> HelloReply {
    let (max_frame, max_have, parallel_uploads) = (MAX_FRAME, MAX_HAVE, 1);
    let (version, mode, encodings) = (
        1,
        "archive-z2".into(),
        vec![Encoding::Raw, Encoding::Deflate],
    );
    HelloReply {
        version,
        mode,
        collection_id,
        max_frame,
        max_have,
        encodings,
        parallel_uploads,
        refs,
    }
}

fn header(ty: ObjectType, n: u8, encoding: Encoding) -> Message {
    Message::ObjectHeader(ObjectHeader {
        name: name(ty, n),
        encoding,
    })
}

fn file_header() -> Message {
    header(ObjectType::File, 0, Encoding::Raw)
}

/// One valid message of each kind.
fn samples() -> Vec<Message> {
    use ObjectType::*;
    let refs = vec![state("main", Some(ck(1))), state("dev", None)];
    let updates = vec![
        update("a", Expected::Absent, Some(ck(1))),
        update("b", Expected::Commit(ck(2)), Some(ck(3))),
        update("c", Expected::Any, None),
    ];
    vec![
        hello(Some("ostrya/0.2.8"), &["main", "origin:main"]),
        Message::HelloReply(hello_reply(refs, Some("org.example.Os".into()))),
        Message::Have(vec![
            name(File, 1),
            name(DirTree, 2),
            name(DirMeta, 3),
            name(Commit, 4),
        ]),
        Message::HaveReply(HaveReply::from_missing([true, false, true])),
        file_header(),
        Message::ObjectsEnd,
        Message::ObjectsReply(ObjectsReply {
            objects: 3,
            payload_bytes: u64::MAX,
        }),
        Message::Commit(CommitRequest {
            updates,
            force: true,
        }),
        Message::CommitReply(vec![
            outcome("a", None, Some(ck(1))),
            outcome("b", Some(ck(2)), Some(ck(3))),
            outcome("c", Some(ck(4)), None),
        ]),
        Message::Error(error(ErrorCode::Protocol, "bad")),
        Message::Abort,
        pull_hello(Some("ostrya/0.2.8")),
        Message::PullHelloReply(PullHelloReply { version: 1 }),
        Message::Get("objects/ab/cd.filez".into()),
        get_reply(true, Some(3)),
    ]
}

fn pull_hello(agent: Option<&str>) -> Message {
    let agent = agent.map(Into::into);
    Message::PullHello(PullHello {
        version: PULL_PROTOCOL_VERSION,
        agent,
    })
}

fn get_reply(found: bool, len: Option<u64>) -> Message {
    Message::GetReply(GetReply { found, len })
}

#[test]
fn every_message_round_trips() {
    use ObjectType::*;
    for msg in samples() {
        round_trip(msg);
    }
    round_trip(hello(None, &[]));
    round_trip(Message::HelloReply(hello_reply(vec![], None)));
    round_trip(Message::Have(vec![]));
    round_trip(header(File, 7, Encoding::Deflate));
    round_trip(header(DirTree, 7, Encoding::Raw));
    round_trip(header(Commit, 7, Encoding::Raw));
    round_trip(header(CommitMeta, 7, Encoding::Raw));
    round_trip(Message::Commit(CommitRequest {
        updates: vec![],
        force: false,
    }));
    for code in ErrorCode::ALL {
        round_trip(Message::Error(sample_error(code, code.as_str())));
    }
    round_trip(Message::Error(error(ErrorCode::RefDenied, "main")));
    let mut e = error(ErrorCode::MissingObjects, "2 missing");
    e.missing = vec![name(File, 1), name(Commit, 2)];
    round_trip(Message::Error(e));
    for commit in [Some(ck(9)), None] {
        let mut e = error(ErrorCode::RefMismatch, "moved");
        e.current = Some(state("main", commit));
        round_trip(Message::Error(e));
    }
    round_trip(pull_hello(None));
    for version in [0, 2, u32::MAX] {
        round_trip(Message::PullHello(PullHello {
            version,
            agent: None,
        }));
        round_trip(Message::PullHelloReply(PullHelloReply { version }));
    }
    for path in ["", "/config", "config", "refs/heads/a b", "refs/heads/%20"] {
        round_trip(Message::Get(path.into()));
    }
    for (found, len) in [
        (false, None),
        (true, None),
        (true, Some(0)),
        (true, Some(u64::MAX)),
    ] {
        round_trip(get_reply(found, len));
    }
}

#[test]
fn the_pull_kinds_are_12_to_15() {
    for (byte, kind) in [
        (12, Kind::PullHello),
        (13, Kind::PullHelloReply),
        (14, Kind::Get),
        (15, Kind::GetReply),
    ] {
        assert_eq!(Kind::from_u8(byte).unwrap(), kind);
        assert_eq!(kind.as_u8(), byte);
    }
    assert_protocol(Kind::from_u8(16));
    assert_eq!(PULL_PROTOCOL_VERSION, 1);
}

#[test]
fn have_reply_bitmap() {
    let bits = [
        true, false, true, true, false, false, false, false, true, true,
    ];
    let r = HaveReply::from_missing(bits);
    assert_eq!(r.bitmap, vec![0b0000_1101, 0b0000_0011]);
    for (i, b) in bits.iter().enumerate() {
        assert_eq!(r.is_missing(i), *b);
    }
    assert!(!r.is_missing(10));
    r.check_len(10).unwrap();
    assert_protocol(r.check_len(9));
    assert_protocol(r.check_len(17));
    let high = HaveReply {
        bitmap: vec![0, 0b0000_0100],
    };
    assert_protocol(high.check_len(10));
    round_trip(Message::HaveReply(r));
}

#[test]
fn error_conversions() {
    let names: std::collections::HashSet<_> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(names.len(), 16);
    for code in ErrorCode::ALL {
        assert_eq!(ErrorCode::from_name(code.as_str()), Some(code));
        let msg = sample_error(code, "m");
        let err = Error::from(msg.clone());
        assert_eq!(err.code(), Some(code));
        assert!(err.to_string().starts_with(code.as_str()));
        assert_eq!(err.to_message(), msg);
    }
    assert_eq!(ErrorCode::from_name("no-such-code"), None);
    assert_eq!(
        ErrorCode::from_name("ref-denied"),
        Some(ErrorCode::RefDenied)
    );
    assert_eq!(ErrorCode::from_name("remote-ref-denied"), None);
    let err = Error::RefDenied("main".into());
    assert_eq!(err.code(), Some(ErrorCode::RefDenied));
    assert_eq!(err.to_string(), "ref-denied: main");
    assert!(matches!(Error::from(err.to_message()), Error::RefDenied(m) if m == "main"));

    let mut msg = error(ErrorCode::MissingObjects, "x");
    msg.missing = vec![name(ObjectType::DirMeta, 5)];
    assert_eq!(Error::from(msg.clone()).to_message(), msg);
    let mut msg = error(ErrorCode::RefMismatch, "y");
    msg.current = Some(state("main", Some(ck(3))));
    let err = Error::from(msg.clone());
    assert!(
        matches!(&err, Error::RefMismatch { name, current: Some(c), .. }
        if name == "main" && *c == ck(3))
    );
    assert_eq!(err.to_message(), msg);

    let io = Error::Io(std::io::Error::other("disk"));
    assert_eq!(io.code(), None);
    assert_eq!(io.to_message(), error(ErrorCode::Internal, "disk"));

    let sign = Error::Sign(ostrya_sign::Error::InvalidFormat("bad".into()));
    assert_eq!(sign.code(), None);
    assert_eq!(
        sign.to_message(),
        error(ErrorCode::Internal, "signing: invalid format: bad")
    );
}

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

fn golden(msg: Message, expected: Vec<u8>) {
    assert_eq!(encode(&msg), expected, "{msg:?}");
    assert_eq!(read_one(&expected).unwrap(), Some(msg));
}

fn header_frame() -> Vec<u8> {
    let mut v = hex("00 00 00 24 05 01");
    v.extend(ck_bytes(0));
    v.extend(hex("00 21"));
    v
}

/// The frame `write_message` gives an `ObjectHeader` equals the frame of the
/// generic body encoder for each type and encoding the header allows, and
/// reads back. A type or an encoding the header does not allow is refused,
/// and nothing is written.
#[test]
fn an_object_header_frame_equals_the_generic_encoding() {
    use ObjectType::*;
    for (ty, encodings) in [
        (File, &[Encoding::Raw, Encoding::Deflate][..]),
        (DirTree, &[Encoding::Raw][..]),
        (DirMeta, &[Encoding::Raw][..]),
        (Commit, &[Encoding::Raw][..]),
        (CommitMeta, &[Encoding::Raw][..]),
    ] {
        for &encoding in encodings {
            for n in [0, 0x7f, 0xff] {
                let msg = header(ty, n, encoding);
                let bytes = encode(&msg);
                assert_eq!(bytes, frame(5, &msg.encode_body().unwrap()), "{msg:?}");
                assert_eq!(read_one(&bytes).unwrap(), Some(msg));
            }
        }
    }
    for msg in [
        header(DirTree, 0, Encoding::Deflate),
        header(CommitMeta, 0, Encoding::Deflate),
        header(TombstoneCommit, 0, Encoding::Raw),
    ] {
        let mut w = FrameWriter::new(Vec::new());
        assert_protocol(block_on(w.write_message(&msg)));
        assert!(w.into_inner().is_empty());
    }
}

/// The frame `write_message` gives a `GetReply` equals the frame of the
/// generic body encoder for each found value and length, and reads back. A
/// reply with found false and a length is refused, and nothing is written.
#[test]
fn a_get_reply_frame_equals_the_generic_encoding() {
    for (found, len) in [
        (false, None),
        (true, Some(0)),
        (true, Some(0x0102_0304_0506_0708)),
        (true, Some(u64::MAX)),
        (true, None),
    ] {
        let msg = get_reply(found, len);
        let bytes = encode(&msg);
        assert_eq!(bytes, frame(15, &msg.encode_body().unwrap()), "{msg:?}");
        assert_eq!(bytes.len(), if len.is_some() { 21 } else { 13 });
        assert_eq!(read_one(&bytes).unwrap(), Some(msg));
    }
    let mut w = FrameWriter::new(Vec::new());
    assert_protocol(block_on(w.write_message(&get_reply(false, Some(0)))));
    assert!(w.into_inner().is_empty());
}

#[test]
fn golden_bytes_pin_the_frame_layout() {
    golden(Message::Abort, hex("00 00 00 02 0b 00"));
    golden(Message::ObjectsEnd, hex("00 00 00 01 06"));
    golden(
        Message::HaveReply(HaveReply { bitmap: vec![5] }),
        hex("00 00 00 02 04 05"),
    );
    golden(
        Message::ObjectsReply(ObjectsReply {
            objects: 3,
            payload_bytes: 0x1122_3344_5566_7788,
        }),
        hex("00 00 00 11 07 03 00 00 00 00 00 00 00 88 77 66 55 44 33 22 11"),
    );
    golden(file_header(), header_frame());

    let mut have = hex("00 00 00 23 03 01");
    have.extend(ck_bytes(0));
    have.push(0x21);
    golden(Message::Have(vec![name(ObjectType::File, 0)]), have);

    golden(
        hello(None, &["main"]),
        hex("00 00 00 10 01 01 00 00 00 00 00 00 00 6d 61 69 6e 00 05 08"),
    );

    let mut reply = hex("00 00 00 2a 09 6d 61 69 6e 00");
    reply.extend(ck_bytes(0));
    reply.extend(hex("00 05 05 28"));
    golden(
        Message::CommitReply(vec![outcome("main", None, Some(ck(0)))]),
        reply,
    );

    golden(
        Message::Error(error(ErrorCode::Protocol, "bad")),
        hex("00 00 00 13 0a 70 72 6f 74 6f 63 6f 6c 00 62 61 64 00 00 00 00 0d 09"),
    );
    golden(
        Message::Error(error(ErrorCode::RefDenied, "main")),
        hex("00 00 00 13 0a 72 65 66 2d 64 65 6e 69 65 64 00 6d 61 69 6e 00 10 0b"),
    );
}

/// The pull messages in GVariant normal form.
///
/// `(ua{sv})`: the `u` is 4 bytes, and the `a{sv}` is aligned to 8, so 4
/// zero bytes of padding follow the `u` also when the dict is empty. The
/// dict is the last member, so the tuple has no framing offset. An empty
/// dict is 0 bytes. The entry `{"agent": <"x">}` is the key `agent\0` (6
/// bytes), 2 bytes of padding to align the variant to 8, the variant `x\0`,
/// a zero separator, and the type `s` (4 bytes), and then the framing offset
/// of the end of the key, 6. The array of one entry of 13 bytes adds the
/// offset of the end of the entry, 13.
///
/// `s`: the bytes of the string and a zero byte.
///
/// `(bmt)`: the `b` is 1 byte, and the `mt` is aligned to 8, so 7 zero bytes
/// of padding follow the `b` also when the maybe is nothing. A maybe of a
/// fixed-size type is 0 bytes for nothing, and the 8 bytes of the `t` with no
/// zero byte after them for a value. The maybe is the last member, so the
/// tuple has no framing offset.
#[test]
fn golden_bytes_pin_the_pull_messages() {
    golden(
        pull_hello(None),
        hex("00 00 00 09 0c 01 00 00 00 00 00 00 00"),
    );
    let mut agent = hex("00 00 00 17 0c 02 00 00 00 00 00 00 00");
    agent.extend(hex("61 67 65 6e 74 00 00 00 78 00 00 73 06 0d"));
    golden(
        Message::PullHello(PullHello {
            version: 2,
            agent: Some("x".into()),
        }),
        agent,
    );
    golden(
        Message::PullHelloReply(PullHelloReply { version: 1 }),
        hex("00 00 00 09 0d 01 00 00 00 00 00 00 00"),
    );
    golden(
        Message::Get("config".into()),
        hex("00 00 00 08 0e 63 6f 6e 66 69 67 00"),
    );
    golden(Message::Get(String::new()), hex("00 00 00 02 0e 00"));
    golden(
        get_reply(false, None),
        hex("00 00 00 09 0f 00 00 00 00 00 00 00 00"),
    );
    golden(
        get_reply(true, None),
        hex("00 00 00 09 0f 01 00 00 00 00 00 00 00"),
    );
    golden(
        get_reply(true, Some(0x1122_3344_5566_7788)),
        hex("00 00 00 11 0f 01 00 00 00 00 00 00 00 88 77 66 55 44 33 22 11"),
    );
    golden(
        get_reply(true, Some(0)),
        hex("00 00 00 11 0f 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"),
    );
}

#[test]
fn malformed_pull_bodies_decode_to_protocol() {
    let cases = [
        // found false with a length, which the encoder refuses too.
        hex("00 00 00 11 0f 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00"),
        // No padding before the maybe.
        hex("00 00 00 02 0f 01"),
        // A maybe of 4 bytes.
        hex("00 00 00 0d 0f 01 00 00 00 00 00 00 00 01 00 00 00"),
        // A boolean of 2.
        hex("00 00 00 09 0f 02 00 00 00 00 00 00 00"),
        // A padding byte that is not zero.
        hex("00 00 00 09 0f 01 00 00 01 00 00 00 00"),
        // A PullHello and a PullHelloReply with no padding before the dict.
        hex("00 00 00 05 0c 01 00 00 00"),
        hex("00 00 00 05 0d 01 00 00 00"),
        // A Get with no terminating zero byte, and one with a zero inside.
        hex("00 00 00 02 0e 61"),
        hex("00 00 00 04 0e 61 00 62 00"),
        frame(14, &[]),
        frame(15, &[]),
    ];
    for bytes in cases {
        assert_protocol(read_one(&bytes));
    }

    let wrong = gv(
        "(ua{sv})",
        t(vec![Value::U32(1), opts(&[("agent", "u", Value::U32(7))])]),
    );
    assert_protocol(read_one(&frame(12, &wrong)));

    let mut w = FrameWriter::new(Vec::new());
    assert_protocol(block_on(w.write_message(&get_reply(false, Some(1)))));
    assert!(w.into_inner().is_empty());
}

/// A decoder ignores a key of `PullHello` or of `PullHelloReply` that it does
/// not know. The first `agent` counts.
#[test]
fn pull_hello_dicts_ignore_unknown_keys() {
    let entries = opts(&[
        ("max-frame", "u", Value::U32(7)),
        ("agent", "s", st("first")),
        ("zz", "a(yay)", Value::Array(vec![])),
    ]);
    let body = gv("(ua{sv})", t(vec![Value::U32(1), entries]));
    assert_eq!(
        read_one(&frame(12, &body)).unwrap(),
        Some(pull_hello(Some("first")))
    );
    assert_eq!(
        read_one(&frame(13, &body)).unwrap(),
        Some(Message::PullHelloReply(PullHelloReply { version: 1 }))
    );
}

#[test]
fn golden_object_stream() {
    let mut w = FrameWriter::new(Vec::new());
    block_on(async {
        w.write_message(&file_header()).await.unwrap();
        w.write_object_data(b"abc").await.unwrap();
        w.write_object_data(b"").await.unwrap();
        w.end_object().await.unwrap();
        w.write_message(&Message::ObjectsEnd).await.unwrap();
        w.flush().await.unwrap();
    });
    let bytes = w.into_inner();
    let mut expected = header_frame();
    expected.extend(hex("00 00 00 03 61 62 63 00 00 00 00 00 00 00 01 06"));
    assert_eq!(bytes, expected);

    for buf_len in [64, 1] {
        let mut r = FrameReader::new(&bytes[..]);
        block_on(async {
            assert_eq!(r.read_message().await.unwrap(), Some(file_header()));
            let mut data = Vec::new();
            let mut buf = vec![0; buf_len];
            loop {
                match r.read_object_data(&mut buf).await.unwrap() {
                    ObjectRead::Data(n) => data.extend_from_slice(&buf[..n]),
                    ObjectRead::End => break,
                    ObjectRead::Abandoned => panic!("abandoned"),
                }
            }
            assert_eq!(data, b"abc");
            assert_eq!(r.read_message().await.unwrap(), Some(Message::ObjectsEnd));
            assert_eq!(r.read_message().await.unwrap(), None);
        });
    }

    let mut w = FrameWriter::new(Vec::new());
    block_on(async {
        w.write_message(&file_header()).await.unwrap();
        w.abandon_object().await.unwrap();
    });
    let bytes = w.into_inner();
    let mut expected = header_frame();
    expected.extend(hex("ff ff ff ff 00 00 00 02 0b 00"));
    assert_eq!(bytes, expected);
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let got = r.read_object_data(&mut [0; 8]).await.unwrap();
        assert_eq!(got, ObjectRead::Abandoned);
    });
}

fn bytes_value(len: usize) -> Value {
    Value::Bytes(vec![0xaa; len])
}

fn t(fields: Vec<Value>) -> Value {
    Value::Tuple(fields)
}

fn st(s: &str) -> Value {
    Value::Str(s.into())
}

fn maybe(v: Option<Value>) -> Value {
    Value::Maybe(v.map(Box::new))
}

fn opts(entries: &[(&str, &str, Value)]) -> Value {
    let mut d = DictBuilder::new();
    for (k, sig, v) in entries {
        d.insert(k, ty(sig), v.clone());
    }
    d.build()
}

/// A `HelloReply` body. `skip` names a key to leave out.
fn reply_body(max_frame: u32, max_have: u32, mode: Value, skip: &str, refs: Vec<Value>) -> Vec<u8> {
    let mode_sig = if let Value::U32(_) = mode { "u" } else { "s" };
    let entries = [
        ("mode", mode_sig, mode),
        ("max-frame", "u", Value::U32(max_frame)),
        ("max-have", "u", Value::U32(max_have)),
        ("encodings", "as", Value::Array(vec![])),
        ("parallel-uploads", "u", Value::U32(1)),
    ];
    let entries: Vec<_> = entries.into_iter().filter(|e| e.0 != skip).collect();
    let body = t(vec![Value::U32(1), opts(&entries), Value::Array(refs)]);
    gv("(ua{sv}a(smay))", body)
}

fn commit_body(state: u8, expected: Option<Value>, new: Option<Value>) -> Vec<u8> {
    let update = t(vec![
        st("main"),
        Value::Byte(state),
        maybe(expected),
        maybe(new),
    ]);
    gv(
        "(a(symaymay)a{sv})",
        t(vec![Value::Array(vec![update]), opts(&[])]),
    )
}

fn commit_reply_body(old: Option<Value>, new: Option<Value>) -> Vec<u8> {
    let entry = t(vec![st("main"), maybe(old), maybe(new)]);
    gv("a(smaymay)", Value::Array(vec![entry]))
}

fn error_body(code: &str, detail: Value) -> Vec<u8> {
    gv("(ssa{sv})", t(vec![st(code), st("m"), detail]))
}

fn names_body(ty: u8, sum: Value) -> Vec<u8> {
    gv("a(yay)", Value::Array(vec![t(vec![Value::Byte(ty), sum])]))
}

fn header_body(ty: u8, sum: Value, enc: u8) -> Vec<u8> {
    gv("(yayy)", t(vec![Value::Byte(ty), sum, Value::Byte(enc)]))
}

#[test]
fn malformed_bodies_decode_to_protocol() {
    for kind in [0, 16, 255] {
        assert_protocol(read_one(&frame(kind, &[0])));
    }

    let good = || Value::Bytes(ck_bytes(0));
    let bare = || st("bare");
    for len in [31, 33] {
        let bad = || bytes_value(len);
        let names = Value::Array(vec![t(vec![Value::Byte(1), bad()])]);
        let reply_ref = vec![t(vec![st("main"), maybe(Some(bad()))])];
        let current = opts(&[
            ("ref", "s", st("main")),
            ("current", "may", maybe(Some(bad()))),
        ]);
        let cases = [
            (3, names_body(1, bad())),
            (5, header_body(1, bad(), 0)),
            (2, reply_body(MAX_FRAME, 1, bare(), "", reply_ref)),
            (8, commit_body(1, Some(bad()), Some(good()))),
            (8, commit_body(1, Some(good()), Some(bad()))),
            (9, commit_reply_body(Some(bad()), None)),
            (9, commit_reply_body(None, Some(bad()))),
            (
                10,
                error_body("missing-objects", opts(&[("missing", "a(yay)", names)])),
            ),
            (10, error_body("ref-mismatch", current)),
        ];
        for (kind, body) in cases {
            assert_protocol(read_one(&frame(kind, &body)));
        }
    }

    for ty in [0, 5, 6, 7, 9] {
        assert_protocol(read_one(&frame(3, &names_body(ty, good()))));
    }
    for (ty, enc) in [(0, 0), (5, 0), (7, 0), (9, 0), (2, 1), (1, 2)] {
        assert_protocol(read_one(&frame(5, &header_body(ty, good(), enc))));
    }
    let mut w = FrameWriter::new(Vec::new());
    let commit_meta = Message::Have(vec![name(ObjectType::CommitMeta, 0)]);
    assert_protocol(block_on(w.write_message(&commit_meta)));
    let no_detail = Message::Error(error(ErrorCode::RefMismatch, "moved"));
    assert_protocol(block_on(w.write_message(&no_detail)));
    assert!(w.into_inner().is_empty());

    // A maybe checksum whose terminating zero byte is 1.
    let mut body = commit_reply_body(Some(good()), None);
    let at = body
        .windows(33)
        .position(|w| w[..32] == ck_bytes(0)[..] && w[32] == 0);
    body[at.unwrap() + 32] = 1;
    assert_protocol(read_one(&frame(9, &body)));

    let mut trailing = gv("(ut)", t(vec![Value::U32(1), Value::U64(2)]));
    trailing.push(0);
    let ref_only = opts(&[("ref", "s", st("main"))]);
    let cases = [
        vec![0, 0, 0, 0],
        frame(6, &[0]),
        frame(11, &[]),
        frame(11, &[1]),
        frame(7, &trailing),
        frame(8, &commit_body(3, None, None)),
        frame(8, &commit_body(1, None, None)),
        frame(8, &commit_body(0, Some(good()), None)),
        frame(2, &reply_body(MAX_FRAME, 1, bare(), "max-frame", vec![])),
        frame(2, &reply_body(MAX_FRAME - 1, 1, bare(), "", vec![])),
        frame(2, &reply_body(u32::MAX, 1, bare(), "", vec![])),
        frame(2, &reply_body(MAX_FRAME, 0, bare(), "", vec![])),
        frame(2, &reply_body(MAX_FRAME, 1, Value::U32(7), "", vec![])),
        frame(10, &error_body("no-such-code", opts(&[]))),
        frame(10, &error_body("remote-ref-denied", opts(&[]))),
        frame(10, &error_body("ref-mismatch", ref_only)),
        frame(10, &error_body("ref-mismatch", opts(&[]))),
    ];
    for bytes in cases {
        assert_protocol(read_one(&bytes));
    }
    assert_protocol(read_one(&hex(
        "00 00 00 1b 0a 72 65 6d 6f 74 65 2d 72 65 66 2d 64 65 6e 69 65 64 00 6d 00 00 00 00 00 14 12",
    )));
    // The valid body that the HelloReply cases above alter decodes.
    let valid = frame(2, &reply_body(MAX_FRAME, 1, bare(), "", vec![]));
    assert!(read_one(&valid).unwrap().is_some());

    assert!(read_one(&[]).unwrap().is_none());
    assert_eof(read_one(&[0, 0]));
    let full = encode(&file_header());
    assert_eof(read_one(&full[..full.len() - 3]));
}

fn have(n: usize) -> Message {
    Message::Have((0..n).map(|i| name(ObjectType::File, i as u8)).collect())
}

#[test]
fn over_the_limit_is_limit_exceeded() {
    let over = ((MIB + 1) as u32).to_be_bytes();
    assert_limit(read_one(&over));

    let mut big = over.to_vec();
    big.push(4);
    big.extend(gv("ay", bytes_value(MIB)));
    assert_eq!(big.len(), 4 + MIB + 1);
    let mut r = FrameReader::new(&big[..]);
    r.set_limit(2 * MIB as u32);
    let got = block_on(r.read_message()).unwrap();
    assert!(matches!(got, Some(Message::HaveReply(h)) if h.bitmap.len() == MIB));

    for (len, ok) in [(MIB + 1, false), (MIB, true)] {
        let mut bytes = header_frame();
        bytes.extend((len as u32).to_be_bytes());
        bytes.resize(bytes.len() + if ok { len } else { 0 }, 0x55);
        bytes.extend([0, 0, 0, 0]);
        let mut r = FrameReader::new(&bytes[..]);
        let mut buf = vec![0; 64 * 1024];
        block_on(async {
            r.read_message().await.unwrap();
            if !ok {
                assert_limit(r.read_object_data(&mut buf).await);
                return;
            }
            let mut total = 0;
            while let ObjectRead::Data(n) = r.read_object_data(&mut buf).await.unwrap() {
                total += n;
            }
            assert_eq!(total, len);
        });
    }

    let mut w = FrameWriter::new(Vec::new());
    assert_limit(block_on(w.write_message(&have(30_000))));
    assert!(w.into_inner().is_empty());

    let mut w = FrameWriter::new(Vec::new());
    let data = vec![7u8; 5 * MIB / 2];
    block_on(async {
        w.write_message(&file_header()).await.unwrap();
        w.write_object_data(&data).await.unwrap();
    });
    let out = w.into_inner();
    let mut rest = &out[header_frame().len()..];
    let mut lens = Vec::new();
    while !rest.is_empty() {
        let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        lens.push(len);
        rest = &rest[4 + len..];
    }
    assert_eq!(lens, vec![MIB, MIB, MIB / 2]);

    let mut r = FrameReader::new(&[][..]);
    r.set_limit(0);
    assert_eq!(r.limit(), MIN_FRAME_LIMIT);
    r.set_limit(u32::MAX);
    assert_eq!(r.limit(), MAX_FRAME_LIMIT);

    let full = encode(&have(MAX_HAVE as usize));
    let frame_len = u32::from_be_bytes(full[..4].try_into().unwrap());
    assert_eq!(frame_len, 606_209);
    assert_eq!(full.len(), 4 + 606_209);
    assert!(frame_len <= MAX_FRAME);
    const { assert!(MAX_FRAME >= MIN_FRAME_LIMIT) };
}

#[test]
fn abandon_marker_needs_abort() {
    let mut marked = header_frame();
    marked.extend([0xff; 4]);
    for msg in samples() {
        if msg == Message::Abort {
            continue;
        }
        let mut bytes = marked.clone();
        bytes.extend(encode(&msg));
        let mut r = FrameReader::new(&bytes[..]);
        block_on(async {
            r.read_message().await.unwrap();
            assert_protocol(r.read_object_data(&mut [0; 8]).await);
        });
    }

    let mut bytes = marked.clone();
    bytes.extend(encode(&Message::Abort));
    bytes.extend(encode(&Message::ObjectsEnd));
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let got = r.read_object_data(&mut [0; 8]).await.unwrap();
        assert_eq!(got, ObjectRead::Abandoned);
        assert_eq!(r.read_message().await.unwrap(), Some(Message::ObjectsEnd));
    });

    let mut r = FrameReader::new(&marked[..]);
    block_on(async {
        r.read_message().await.unwrap();
        assert_eof(r.read_object_data(&mut [0; 8]).await);
    });

    let header = header_frame();
    let mut r = FrameReader::new(&header[..]);
    block_on(async {
        assert_protocol(r.read_object_data(&mut [0; 8]).await);
        r.read_message().await.unwrap();
        assert_protocol(r.read_message().await);
    });
    let mut w = FrameWriter::new(Vec::new());
    block_on(async {
        w.write_message(&file_header()).await.unwrap();
        assert_protocol(w.write_message(&Message::ObjectsEnd).await);
    });
}

#[test]
fn hello_reply_encode_checks_its_limits() {
    let mut w = FrameWriter::new(Vec::new());
    for (max_frame, max_have, parallel_uploads) in [
        (MIN_FRAME_LIMIT - 1, 1, 1),
        (0, 1, 1),
        (u32::MAX, 1, 1),
        (MAX_FRAME, 0, 1),
        (MAX_FRAME, 1, 0),
    ] {
        let mut r = hello_reply(vec![], None);
        (r.max_frame, r.max_have, r.parallel_uploads) = (max_frame, max_have, parallel_uploads);
        assert_protocol(block_on(w.write_message(&Message::HelloReply(r))));
    }
    assert!(w.into_inner().is_empty());
    for max_frame in [MIN_FRAME_LIMIT, MAX_FRAME_LIMIT] {
        let mut r = hello_reply(vec![], None);
        r.max_frame = max_frame;
        round_trip(Message::HelloReply(r));
    }
}

/// A `Hello` body with the dict entries `entries`.
fn hello_body(entries: Vec<Value>) -> Vec<u8> {
    let body = t(vec![
        Value::U32(1),
        Value::Array(entries),
        Value::Array(vec![]),
    ]);
    gv("(ua{sv}as)", body)
}

fn entry(key: &str, sig: &str, v: Value) -> Value {
    t(vec![st(key), Value::variant(ty(sig), v)])
}

#[test]
fn dict_keys_unknown_duplicate_and_malformed() {
    let entries = vec![
        entry("zz-flag", "b", Value::Bool(true)),
        entry("agent", "s", st("first")),
        entry("agent", "u", Value::U32(7)),
        entry("zz", "a(yay)", Value::Array(vec![])),
    ];
    let got = read_one(&frame(1, &hello_body(entries))).unwrap();
    assert_eq!(got, Some(hello(Some("first"), &[])));

    let wrong = vec![entry("agent", "u", Value::U32(7))];
    assert_protocol(read_one(&frame(1, &hello_body(wrong))));

    // An unknown key whose boolean value is 2 is not in normal form.
    let mut body = hello_body(vec![entry("zz", "b", Value::Bool(true))]);
    let at = body.windows(3).position(|w| w == [1, 0, b'b']).unwrap();
    body[at] = 2;
    assert_protocol(read_one(&frame(1, &body)));
}

fn one_way_hello(agent: Option<&str>, refs: &[&str]) -> Message {
    let Message::Hello(h) = hello(agent, refs) else {
        unreachable!("hello gives a Hello")
    };
    Message::Hello(Hello { one_way: true, ..h })
}

/// `one-way` true is written after `agent` and reads back. The encoder writes
/// no key for false, so `golden_bytes_pin_the_frame_layout` pins the bytes of
/// a two-way `Hello`.
///
/// The entry `{"one-way": <true>}` is the key `one-way\0` (8 bytes), the
/// variant `01`, a zero separator, and the type `b`, and then the framing
/// offset of the end of the key, 8. The array of one entry of 12 bytes adds
/// the offset of the end of the entry, 12. The tuple ends with the offset of
/// the end of the dict, 21.
#[test]
fn a_one_way_hello_round_trips() {
    round_trip(one_way_hello(None, &[]));
    round_trip(one_way_hello(
        Some("ostrya/0.2.8"),
        &["main", "origin:main"],
    ));
    golden(
        one_way_hello(None, &["main"]),
        hex(
            "00 00 00 1d 01 01 00 00 00 00 00 00 00 6f 6e 65 2d 77 61 79 00 01 00 62 08 0c \
             6d 61 69 6e 00 05 15",
        ),
    );
}

/// An absent `one-way` key and the value false both read as false. A value
/// of another type is `protocol`. When the key occurs twice, the first one
/// counts.
#[test]
fn the_one_way_key_reads_strictly() {
    let read = |entries| read_one(&frame(1, &hello_body(entries)));
    assert_eq!(read(vec![]).unwrap(), Some(hello(None, &[])));
    assert_eq!(
        read(vec![entry("one-way", "b", Value::Bool(false))]).unwrap(),
        Some(hello(None, &[]))
    );
    assert_eq!(
        read(vec![entry("one-way", "b", Value::Bool(true))]).unwrap(),
        Some(one_way_hello(None, &[]))
    );
    assert_eq!(
        read(vec![
            entry("one-way", "b", Value::Bool(true)),
            entry("one-way", "b", Value::Bool(false)),
        ])
        .unwrap(),
        Some(one_way_hello(None, &[]))
    );
    assert_protocol(read(vec![entry("one-way", "s", st("true"))]));
    assert_protocol(read(vec![entry("one-way", "u", Value::U32(1))]));
}

#[test]
fn abandon_then_header_leaves_the_reader_between_frames() {
    let mut bytes = header_frame();
    bytes.extend([0xff; 4]);
    bytes.extend(encode(&file_header()));
    bytes.extend(encode(&Message::ObjectsEnd));
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        assert_protocol(r.read_object_data(&mut [0; 8]).await);
        assert_eq!(r.read_message().await.unwrap(), Some(Message::ObjectsEnd));
    });
}

#[test]
fn end_of_file_inside_an_object_is_unexpected_eof() {
    let mut chunk = header_frame();
    chunk.extend([0, 0, 0, 3, b'a']);
    let header = header_frame();
    for bytes in [&chunk[..], &header[..], &chunk[..header.len() + 2]] {
        let mut r = FrameReader::new(bytes);
        block_on(async {
            r.read_message().await.unwrap();
            let mut buf = [0; 8];
            let got = loop {
                match r.read_object_data(&mut buf).await {
                    Ok(ObjectRead::Data(_)) => continue,
                    other => break other,
                }
            };
            assert_eof(got);
        });
    }
}

#[test]
fn a_frame_of_exactly_the_limit_passes() {
    // An `ay` body of MIB - 1 bytes makes a frame length of exactly MIB.
    let exact = Message::HaveReply(HaveReply {
        bitmap: vec![0x5a; MIB - 1],
    });
    let bytes = encode(&exact);
    assert_eq!(
        u32::from_be_bytes(bytes[..4].try_into().unwrap()),
        MIN_FRAME_LIMIT
    );
    assert_eq!(read_one(&bytes).unwrap(), Some(exact));

    let over = Message::HaveReply(HaveReply {
        bitmap: vec![0x5a; MIB],
    });
    let mut w = FrameWriter::new(Vec::new());
    assert_limit(block_on(w.write_message(&over)));
    assert!(w.into_inner().is_empty());
}

/// A stream that returns one byte for each read and `Pending` before each
/// byte, so every chunk length and every chunk arrives split.
struct Trickle<'a> {
    bytes: &'a [u8],
    pending: bool,
}

impl futures_io::AsyncRead for Trickle<'_> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        self.pending = true;
        let n = buf.len().min(self.bytes.len()).min(1);
        buf[..n].copy_from_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        std::task::Poll::Ready(Ok(n))
    }
}

fn object_stream(tail: &[u8]) -> Vec<u8> {
    let mut bytes = header_frame();
    bytes.extend(tail);
    bytes
}

#[test]
fn object_body_reads_split_chunks_to_the_end() {
    use futures_lite::io::AsyncReadExt;

    let mut tail = hex("00 00 00 03 61 62 63 00 00 00 02 64 65 00 00 00 00");
    tail.extend(encode(&Message::ObjectsEnd));
    let bytes = object_stream(&tail);
    let mut r = FrameReader::new(Trickle {
        bytes: &bytes,
        pending: false,
    });
    block_on(async {
        assert_eq!(r.read_message().await.unwrap(), Some(file_header()));
        let mut body = r.object_body();
        let mut data = Vec::new();
        body.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"abcde");
        assert!(body.is_finished());
        assert!(!body.is_abandoned());
        assert!(body.take_error().is_none());
        assert_eq!(body.read(&mut [0; 4]).await.unwrap(), 0);
        assert_eq!(r.read_message().await.unwrap(), Some(Message::ObjectsEnd));
    });
}

/// One read takes as many ready chunks as fit, so tiny chunks do not make
/// tiny reads. Bytes read before the marker or an error arrive first.
#[test]
fn object_body_fills_the_buffer_across_chunks() {
    use futures_lite::io::AsyncReadExt;

    let mut tail = Vec::new();
    for i in 0..1000u32 {
        tail.extend([0, 0, 0, 1, i as u8]);
    }
    tail.extend([0, 0, 0, 0]);
    tail.extend(encode(&Message::ObjectsEnd));
    let bytes = object_stream(&tail);
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let mut body = r.object_body();
        let mut buf = [0u8; 4096];
        assert_eq!(body.read(&mut buf[..600]).await.unwrap(), 600);
        assert_eq!(body.read(&mut buf).await.unwrap(), 400);
        assert_eq!(buf[399], 999u32 as u8);
        assert!(body.is_finished());
        assert_eq!(body.read(&mut buf).await.unwrap(), 0);
        assert_eq!(r.read_message().await.unwrap(), Some(Message::ObjectsEnd));
    });

    let mut tail = hex("00 00 00 01 61 00 00 00 01 62 ff ff ff ff");
    tail.extend(encode(&Message::Abort));
    let bytes = object_stream(&tail);
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let mut body = r.object_body();
        let mut buf = [0u8; 16];
        assert_eq!(body.read(&mut buf).await.unwrap(), 2);
        assert_eq!(&buf[..2], b"ab");
        assert!(body.is_abandoned());
        assert!(body.read(&mut buf).await.is_err());
        body.finish_abandon().await.unwrap();
    });

    let mut tail = hex("00 00 00 01 61");
    tail.extend((MIN_FRAME_LIMIT + 1).to_be_bytes());
    let bytes = object_stream(&tail);
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let mut body = r.object_body();
        let mut buf = [0u8; 16];
        assert_eq!(body.read(&mut buf).await.unwrap(), 1);
        assert!(body.read(&mut buf).await.is_err());
        assert_limit(Err::<(), _>(body.take_error().unwrap()));
    });
}

#[test]
fn object_body_reports_the_abandon_marker() {
    use futures_lite::io::AsyncReadExt;

    let mut tail = hex("00 00 00 01 61 ff ff ff ff");
    tail.extend(encode(&Message::Abort));
    let bytes = object_stream(&tail);
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let mut body = r.object_body();
        let mut data = Vec::new();
        assert!(body.read_to_end(&mut data).await.is_err());
        assert!(body.is_abandoned());
        assert!(body.take_error().is_none());
        assert!(body.read(&mut [0; 4]).await.is_err());
        body.finish_abandon().await.unwrap();
        assert_eq!(r.read_message().await.unwrap(), None);
    });

    let mut tail = hex("ff ff ff ff");
    tail.extend(encode(&Message::ObjectsEnd));
    let bytes = object_stream(&tail);
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let mut body = r.object_body();
        assert!(body.read(&mut [0; 4]).await.is_err());
        assert_protocol(body.finish_abandon().await);
    });

    let bytes = object_stream(&hex("00 00 00 00"));
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let mut body = r.object_body();
        assert_eq!(body.read(&mut [0; 4]).await.unwrap(), 0);
        assert_protocol(body.finish_abandon().await);
    });
}

#[test]
fn object_body_keeps_the_codec_error() {
    use futures_lite::io::AsyncReadExt;

    let over = (MIN_FRAME_LIMIT + 1).to_be_bytes();
    let bytes = object_stream(&over);
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let mut body = r.object_body();
        assert!(body.read(&mut [0; 4]).await.is_err());
        assert!(body.read(&mut [0; 4]).await.is_err());
        assert_limit(Err::<(), _>(body.take_error().unwrap()));
        assert!(body.take_error().is_none());
    });

    let bytes = object_stream(&hex("00 00 00 05 61 62"));
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let mut body = r.object_body();
        let mut data = Vec::new();
        let err = body.read_to_end(&mut data).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eof(Err::<(), _>(body.take_error().unwrap()));
    });

    let bytes = encode(&Message::ObjectsEnd);
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        let mut body = r.object_body();
        assert!(body.read(&mut [0; 4]).await.is_err());
        assert_protocol(Err::<(), _>(body.take_error().unwrap()));
    });
}

#[test]
fn aborted_has_no_wire_code() {
    assert_eq!(Error::Aborted.code(), None);
    let msg = Error::Aborted.to_message();
    assert_eq!(msg.code, ErrorCode::Internal);
    assert_eq!(msg.message, "the client aborted the session");
}

fn reply_frame(found: bool, len: Option<u64>) -> Vec<u8> {
    encode(&get_reply(found, len))
}

/// Read a body to its end, or to the error that ends it.
async fn read_body<R: futures_io::AsyncRead + Unpin>(
    r: &mut FrameReader<R>,
) -> Result<(Vec<u8>, ObjectRead), Error> {
    let mut data = Vec::new();
    let mut buf = [0u8; 8];
    loop {
        match r.read_object_data(&mut buf).await? {
            ObjectRead::Data(n) => data.extend_from_slice(&buf[..n]),
            end => return Ok((data, end)),
        }
    }
}

/// The reader enters the body state after a `GetReply` with found true, and
/// stays between frames after a `GetReply` with found false.
#[test]
fn a_found_reply_enters_the_body_state() {
    let mut bytes = reply_frame(true, Some(3));
    bytes.extend(hex("00 00 00 03 61 62 63 00 00 00 00"));
    bytes.extend(reply_frame(false, None));
    bytes.extend(reply_frame(true, None));
    bytes.extend(hex("00 00 00 00"));
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        assert_eq!(
            r.read_message().await.unwrap(),
            Some(get_reply(true, Some(3)))
        );
        let (data, end) = read_body(&mut r).await.unwrap();
        assert_eq!((data.as_slice(), end), (&b"abc"[..], ObjectRead::End));
        assert_eq!(
            r.read_message().await.unwrap(),
            Some(get_reply(false, None))
        );
        assert_protocol(r.read_object_data(&mut [0; 8]).await);
        assert_eq!(r.read_message().await.unwrap(), Some(get_reply(true, None)));
        assert_eq!(read_body(&mut r).await.unwrap(), (vec![], ObjectRead::End));
        assert_eq!(r.read_message().await.unwrap(), None);
    });

    let mut bytes = reply_frame(true, Some(1));
    bytes.extend(hex("00 00 00 01 61 00 00 00 00"));
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        assert_protocol(r.read_message().await);
    });
}

/// After the abandon marker in a pull body, the `Error` frame gives the error
/// of its code, and `Abort` or another frame is `protocol`. After the marker
/// in an object of the push, an `Error` frame is `protocol`.
#[test]
fn the_abandon_marker_of_a_pull_body_takes_error() {
    use futures_lite::io::AsyncReadExt;

    let pull = |tail: &Message| {
        let mut bytes = reply_frame(true, None);
        bytes.extend(hex("00 00 00 01 61 ff ff ff ff"));
        bytes.extend(encode(tail));
        bytes
    };
    for code in [ErrorCode::Internal, ErrorCode::Protocol] {
        let bytes = pull(&Message::Error(error(code, "read failed")));
        let mut r = FrameReader::new(&bytes[..]);
        block_on(async {
            r.read_message().await.unwrap();
            let err = read_body(&mut r).await.unwrap_err();
            assert_eq!(err.code(), Some(code));
            assert_eq!(err.to_message(), error(code, "read failed"));
            assert_eq!(r.read_message().await.unwrap(), None);
        });

        let mut r = FrameReader::new(&bytes[..]);
        block_on(async {
            r.read_message().await.unwrap();
            let mut body = r.object_body();
            let mut data = Vec::new();
            assert!(body.read_to_end(&mut data).await.is_err());
            assert_eq!(data, b"a");
            assert!(body.is_abandoned());
            assert!(body.take_error().is_none());
            let err = body.finish_abandon().await.unwrap_err();
            assert_eq!(err.code(), Some(code));
            assert_eq!(r.read_message().await.unwrap(), None);
        });
    }

    for tail in [Message::Abort, Message::Get("config".into())] {
        let bytes = pull(&tail);
        let mut r = FrameReader::new(&bytes[..]);
        block_on(async {
            r.read_message().await.unwrap();
            assert_protocol(read_body(&mut r).await);
        });
        let mut r = FrameReader::new(&bytes[..]);
        block_on(async {
            r.read_message().await.unwrap();
            let mut body = r.object_body();
            assert!(body.read_to_end(&mut Vec::new()).await.is_err());
            assert_protocol(body.finish_abandon().await);
        });
    }

    // A found reply after the marker sets the body state, and the error
    // leaves the reader between frames.
    let mut bytes = pull(&get_reply(true, None));
    bytes.extend(encode(&Message::Get("config".into())));
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        assert_protocol(read_body(&mut r).await);
        assert_eq!(
            r.read_message().await.unwrap(),
            Some(Message::Get("config".into()))
        );
    });

    let mut bytes = reply_frame(true, None);
    bytes.extend([0xff; 4]);
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        assert_eof(read_body(&mut r).await);
    });

    let mut bytes = header_frame();
    bytes.extend([0xff; 4]);
    bytes.extend(encode(&Message::Error(error(ErrorCode::Internal, "x"))));
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        assert_protocol(r.read_object_data(&mut [0; 8]).await);
    });
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let mut body = r.object_body();
        assert!(body.read(&mut [0; 8]).await.is_err());
        assert_protocol(body.finish_abandon().await);
    });
}

/// The writer enters the body state after a `GetReply` with found true. The
/// body takes the chunks of an object, and `abandon_body` writes the marker
/// and the `Error` frame. Each abandon call refuses the other body kind.
#[test]
fn the_writer_writes_and_abandons_a_pull_body() {
    let mut w = FrameWriter::new(Vec::new());
    block_on(async {
        w.write_message(&get_reply(true, Some(3))).await.unwrap();
        assert_protocol(w.write_message(&Message::Get("config".into())).await);
        assert_protocol(w.abandon_object().await);
        w.write_object_data(b"abc").await.unwrap();
        w.end_object().await.unwrap();
        w.write_message(&get_reply(false, None)).await.unwrap();
        assert_protocol(w.write_object_data(b"x").await);
        assert_protocol(w.end_object().await);
        assert_protocol(w.abandon_body(&error(ErrorCode::Internal, "x")).await);
    });
    let mut expected = reply_frame(true, Some(3));
    expected.extend(hex("00 00 00 03 61 62 63 00 00 00 00"));
    expected.extend(reply_frame(false, None));
    assert_eq!(w.into_inner(), expected);

    let failure = error(ErrorCode::Internal, "read failed");
    let mut w = FrameWriter::new(Vec::new());
    block_on(async {
        w.write_message(&get_reply(true, None)).await.unwrap();
        w.write_object_data(b"a").await.unwrap();
        // An `Error` that does not encode writes nothing, and the body stays
        // open.
        let no_detail = error(ErrorCode::RefMismatch, "moved");
        assert_protocol(w.abandon_body(&no_detail).await);
        w.abandon_body(&failure).await.unwrap();
        assert_protocol(w.abandon_body(&failure).await);
        w.write_message(&Message::Get("config".into()))
            .await
            .unwrap();
    });
    let bytes = w.into_inner();
    let mut expected = reply_frame(true, None);
    expected.extend(hex("00 00 00 01 61 ff ff ff ff"));
    expected.extend(encode(&Message::Error(failure.clone())));
    expected.extend(encode(&Message::Get("config".into())));
    assert_eq!(bytes, expected);
    let mut r = FrameReader::new(&bytes[..]);
    block_on(async {
        r.read_message().await.unwrap();
        let err = read_body(&mut r).await.unwrap_err();
        assert_eq!(err.to_message(), failure);
        assert_eq!(
            r.read_message().await.unwrap(),
            Some(Message::Get("config".into()))
        );
    });

    let mut w = FrameWriter::new(Vec::new());
    block_on(async {
        w.write_message(&file_header()).await.unwrap();
        assert_protocol(w.abandon_body(&failure).await);
        w.abandon_object().await.unwrap();
    });
    let mut expected = header_frame();
    expected.extend(hex("ff ff ff ff 00 00 00 02 0b 00"));
    assert_eq!(w.into_inner(), expected);
}

/// `get_ref` shows the bytes a buffered reader holds after a frame, with no
/// read.
#[test]
fn get_ref_shows_the_buffered_bytes() {
    let first = encode(&Message::Get("a".into()));
    let second = encode(&Message::Get("b".into()));
    let bytes = [first.clone(), second.clone()].concat();
    let mut r = FrameReader::new(futures_lite::io::BufReader::new(&bytes[..]));
    block_on(async {
        assert!(r.get_ref().buffer().is_empty());
        r.read_message().await.unwrap();
        assert_eq!(r.get_ref().buffer(), &second[..]);
        r.read_message().await.unwrap();
        assert!(r.get_ref().buffer().is_empty());
    });
}
