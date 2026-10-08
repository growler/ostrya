//! The messages of the protocol and their GVariant bodies.

use std::sync::LazyLock;

use ostrya_core::{Checksum, ObjectName, ObjectType};
use ostrya_gvariant::{ArrayIter, DictBuilder, GvDecode, GvType, Type, Value};

use super::{
    Encoding, Expected, Kind, MAX_FRAME_LIMIT, MIN_FRAME_LIMIT, RefOutcome, RefState, RefUpdate,
    checksum, have_type, header_type, maybe_value, object_name, object_name_value, protocol,
};
use crate::error::{Error, ErrorCode, Result};

fn parse(signature: &str) -> Type {
    Type::parse(signature).expect("valid signature")
}

static HELLO: LazyLock<Type> = LazyLock::new(|| parse("(ua{sv}as)"));
static HELLO_REPLY: LazyLock<Type> = LazyLock::new(|| parse("(ua{sv}a(smay))"));
static OBJECT_NAMES: LazyLock<Type> = LazyLock::new(|| parse("a(yay)"));
static BYTES: LazyLock<Type> = LazyLock::new(|| parse("ay"));
static OBJECT_HEADER: LazyLock<Type> = LazyLock::new(|| parse("(yayy)"));
static OBJECTS_REPLY: LazyLock<Type> = LazyLock::new(|| parse("(ut)"));
static COMMIT: LazyLock<Type> = LazyLock::new(|| parse("(a(symaymay)a{sv})"));
static COMMIT_REPLY: LazyLock<Type> = LazyLock::new(|| parse("a(smaymay)"));
static ERROR: LazyLock<Type> = LazyLock::new(|| parse("(ssa{sv})"));
static STRV: LazyLock<Type> = LazyLock::new(|| parse("as"));
static MAYBE_CHECKSUM: LazyLock<Type> = LazyLock::new(|| parse("may"));
static PULL_HELLO: LazyLock<Type> = LazyLock::new(|| parse("(ua{sv})"));
static GET_REPLY: LazyLock<Type> = LazyLock::new(|| parse("(bmt)"));

/// The first message of a push client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// The protocol version that the client requests.
    pub version: u32,
    /// The name and version of the client, under the key `agent`.
    pub agent: Option<String>,
    /// The refs that the client intends to update, each `NAME` or
    /// `REMOTE:NAME`.
    pub refs: Vec<String>,
    /// The flag that is `true` if the `Hello` opens a
    /// [one-way stream](super#one-way-stream).
    ///
    /// In a one-way stream, the receiver sends no message. The key is
    /// `one-way`. The encoder writes the key only if the value is `true`, and
    /// the decoder reads an absent key as `false`.
    pub one_way: bool,
}

/// The reply to a `Hello`, with the facts and limits of the server.
///
/// It also gives the state of each ref that the `Hello` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloReply {
    /// The protocol version that the server speaks for the session.
    pub version: u32,
    /// The repository mode, under the key `mode`.
    pub mode: String,
    /// The collection id of the repository, under the key `collection-id`.
    pub collection_id: Option<String>,
    /// The frame limit that the server announces, under the key `max-frame`.
    ///
    /// Encode and decode return [`Error::Protocol`] for a value out of the
    /// range that the [frame rules](crate::proto#frames) give.
    pub max_frame: u32,
    /// The maximum number of entries in one `Have`, under the key `max-have`.
    ///
    /// The value is at least 1. For the value 0, encode and decode return
    /// [`Error::Protocol`].
    pub max_have: u32,
    /// The content encodings that the server accepts, under the key
    /// `encodings`.
    ///
    /// The decoder drops a name that is not an encoding.
    pub encodings: Vec<Encoding>,
    /// The most object streams at a time, under the key `parallel-uploads`.
    ///
    /// The server serves at most this number of object streams at the same
    /// time in one session. The value is at least 1. For the value 0, encode and
    /// decode return [`Error::Protocol`].
    pub parallel_uploads: u32,
    /// The state of each ref that the `Hello` names, one entry for each ref.
    pub refs: Vec<RefState>,
}

/// The reply to a `Have`, with one bit for each entry.
///
/// Bit `i` is bit `i % 8` of byte `i / 8`, counted from the least significant
/// bit. If a bit is set, the server does not hold the object, and the client
/// must send it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaveReply {
    /// The bitmap of the entries.
    pub bitmap: Vec<u8>,
}

impl HaveReply {
    /// Creates a reply from one `bool` for each entry of the `Have`.
    ///
    /// Bit `i` is set if entry `i` of `missing` is `true`. For `n` entries,
    /// the bitmap has `n.div_ceil(8)` bytes.
    pub fn from_missing(missing: impl IntoIterator<Item = bool>) -> HaveReply {
        let mut bitmap = Vec::new();
        for (i, set) in missing.into_iter().enumerate() {
            if i % 8 == 0 {
                bitmap.push(0);
            }
            if set {
                bitmap[i / 8] |= 1 << (i % 8);
            }
        }
        HaveReply { bitmap }
    }

    /// Returns `true` if the server does not hold entry `index`.
    ///
    /// For an `index` after the end of the bitmap, it returns `false`.
    pub fn is_missing(&self, index: usize) -> bool {
        self.bitmap
            .get(index / 8)
            .is_some_and(|b| b & (1 << (index % 8)) != 0)
    }

    /// Checks the reply against a `Have` of `entries` entries.
    ///
    /// The bitmap must be `entries.div_ceil(8)` bytes long, and the bits
    /// after the last entry must be zero.
    ///
    /// # Errors
    ///
    /// - [`Error::Protocol`] if the bitmap has a different length.
    /// - [`Error::Protocol`] if the bitmap sets a bit after the last entry.
    pub fn check_len(&self, entries: usize) -> Result<()> {
        if self.bitmap.len() != entries.div_ceil(8) {
            return Err(protocol(format!(
                "HaveReply of {} bytes for {entries} entries",
                self.bitmap.len()
            )));
        }
        let tail = entries % 8;
        if tail != 0 && self.bitmap[entries / 8] >> tail != 0 {
            return Err(protocol("HaveReply sets a bit after the last entry"));
        }
        Ok(())
    }
}

/// The message that starts one object in the
/// [object stream](super#object-stream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHeader {
    /// The type and the checksum of the object.
    ///
    /// For a `CommitMeta` object, the checksum is the checksum of its commit.
    pub name: ObjectName,
    /// The encoding of the object bytes.
    ///
    /// [`Encoding::Deflate`] is allowed for a file object alone.
    pub encoding: Encoding,
}

/// The reply of the server at the end of one object stream.
///
/// The counts are those of one stream. If two streams of one session send the
/// same content, dirtree, dirmeta, or commit object at the same time, both
/// can count it. A second detached metadata object for one commit is
/// [`Error::Protocol`], also from another stream, and the session ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectsReply {
    /// The number of objects that the server stored.
    pub objects: u32,
    /// The number of payload bytes that the server wrote.
    pub payload_bytes: u64,
}

/// The `Commit` message, with the ref updates of the transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRequest {
    /// The ref updates.
    pub updates: Vec<RefUpdate>,
    /// The flag that allows a ref update that is not a fast-forward.
    ///
    /// The key is `force`. The encoder writes the key only if the value is
    /// `true`, and the decoder reads an absent key as `false`.
    pub force: bool,
}

/// The `Error` message, which the server sends to report a failure.
///
/// The session ends after this message. The `Error` message converts to the
/// [`Error`] variant of its code, and [`Error::to_message`] converts back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMessage {
    /// The code of the failure.
    pub code: ErrorCode,
    /// The text of the failure for a human reader.
    pub message: String,
    /// The missing objects, for the code `missing-objects`.
    ///
    /// The key is `missing`. The encoder writes the key only if the list is
    /// not empty. Each object is of type 1 to 4. For another type, encode and
    /// decode return [`Error::Protocol`].
    pub missing: Vec<ObjectName>,
    /// The current state of the ref, for the code `ref-mismatch`.
    ///
    /// The keys are `ref` and `current`. If the code is `ref-mismatch` and
    /// this field is `None`, encode and decode return [`Error::Protocol`]. The
    /// decode of a body with one of the two keys alone also returns
    /// [`Error::Protocol`].
    pub current: Option<RefState>,
}

/// The first message of a pull client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullHello {
    /// The highest pull protocol version that the client speaks.
    pub version: u32,
    /// The name and version of the client, under the key `agent`.
    pub agent: Option<String>,
}

/// The reply to a `PullHello`, with the pull version of the session.
///
/// The dict of the reply is empty in version 1. A decoder ignores a key that
/// it does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullHelloReply {
    /// The pull protocol version of the session.
    ///
    /// It is the lower of the version of the `PullHello` and the highest
    /// version of the server.
    pub version: u32,
}

/// The reply to one `Get`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetReply {
    /// The flag that is `true` if the server serves the path.
    ///
    /// If `found` is `true`, a [body](super#pull) follows the reply.
    pub found: bool,
    /// The length of the body, if the server knows it.
    ///
    /// If `found` is `false` and the length is present, encode and decode
    /// return [`Error::Protocol`].
    pub len: Option<u64>,
}

/// A message of the push or the pull protocol.
///
/// A later protocol version can add messages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// The `Hello` message.
    Hello(Hello),
    /// The `HelloReply` message.
    HelloReply(HelloReply),
    /// The `Have` message, with the objects that the client offers.
    ///
    /// Each object is of type 1 to 4.
    Have(Vec<ObjectName>),
    /// The `HaveReply` message.
    HaveReply(HaveReply),
    /// The `ObjectHeader` message.
    ObjectHeader(ObjectHeader),
    /// The `ObjectsEnd` message.
    ObjectsEnd,
    /// The `ObjectsReply` message.
    ObjectsReply(ObjectsReply),
    /// The `Commit` message.
    Commit(CommitRequest),
    /// The `CommitReply` message, with one outcome for each ref update.
    CommitReply(Vec<RefOutcome>),
    /// The `Error` message.
    Error(ErrorMessage),
    /// The `Abort` message.
    Abort,
    /// The `PullHello` message.
    PullHello(PullHello),
    /// The `PullHelloReply` message.
    PullHelloReply(PullHelloReply),
    /// The `Get` message, with the path of one file.
    ///
    /// The path is relative to the repository root.
    Get(String),
    /// The `GetReply` message.
    GetReply(GetReply),
}

impl Message {
    /// Returns the kind of the message.
    pub fn kind(&self) -> Kind {
        match self {
            Message::Hello(_) => Kind::Hello,
            Message::HelloReply(_) => Kind::HelloReply,
            Message::Have(_) => Kind::Have,
            Message::HaveReply(_) => Kind::HaveReply,
            Message::ObjectHeader(_) => Kind::ObjectHeader,
            Message::ObjectsEnd => Kind::ObjectsEnd,
            Message::ObjectsReply(_) => Kind::ObjectsReply,
            Message::Commit(_) => Kind::Commit,
            Message::CommitReply(_) => Kind::CommitReply,
            Message::Error(_) => Kind::Error,
            Message::Abort => Kind::Abort,
            Message::PullHello(_) => Kind::PullHello,
            Message::PullHelloReply(_) => Kind::PullHelloReply,
            Message::Get(_) => Kind::Get,
            Message::GetReply(_) => Kind::GetReply,
        }
    }

    /// Encodes the body of the message, with no frame length and no kind byte.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] if the message holds a value that it cannot carry:
    ///
    /// - a `HelloReply` whose `max_frame`, `max_have`, or `parallel_uploads`
    ///   is out of range
    /// - a `Have` entry or a `missing` object of a type other than 1 to 4, for
    ///   example type 6
    /// - an `ObjectHeader` of a type other than 1 to 4 or 6, or with
    ///   [`Encoding::Deflate`] for an object that is not a file
    /// - an `Error` message with the code `ref-mismatch` and no `current`
    ///   state
    /// - a `GetReply` whose `found` is `false` and that has a length
    /// - a string with an interior NUL byte, which the GVariant serializer
    ///   refuses
    pub fn encode_body(&self) -> Result<Vec<u8>> {
        let (ty, value): (&Type, Value) = match self {
            Message::ObjectsEnd => return Ok(Vec::new()),
            Message::Abort => return Ok(vec![0]),
            Message::Hello(h) => {
                let mut opts = DictBuilder::new();
                if let Some(agent) = &h.agent {
                    opts.insert_str("agent", agent);
                }
                if h.one_way {
                    opts.insert_bool("one-way", true);
                }
                let refs = h.refs.iter().cloned().map(Value::Str).collect();
                let v = Value::Tuple(vec![
                    Value::U32(h.version),
                    opts.build(),
                    Value::Array(refs),
                ]);
                (&HELLO, v)
            }
            Message::HelloReply(r) => {
                check_limits(r.max_frame, r.max_have, r.parallel_uploads)?;
                let mut opts = DictBuilder::new();
                opts.insert_str("mode", &r.mode);
                if let Some(id) = &r.collection_id {
                    opts.insert_str("collection-id", id);
                }
                let encodings: Vec<String> =
                    r.encodings.iter().map(|e| e.as_str().to_owned()).collect();
                opts.insert("max-frame", Type::U32, Value::U32(r.max_frame))
                    .insert("max-have", Type::U32, Value::U32(r.max_have))
                    .insert_strv("encodings", &encodings)
                    .insert(
                        "parallel-uploads",
                        Type::U32,
                        Value::U32(r.parallel_uploads),
                    );
                let refs = r
                    .refs
                    .iter()
                    .map(|s| Value::Tuple(vec![Value::Str(s.name.clone()), maybe_value(s.commit)]))
                    .collect();
                let v = Value::Tuple(vec![
                    Value::U32(r.version),
                    opts.build(),
                    Value::Array(refs),
                ]);
                (&HELLO_REPLY, v)
            }
            Message::Have(names) => (&OBJECT_NAMES, object_names_value(names)?),
            Message::HaveReply(r) => (&BYTES, Value::Bytes(r.bitmap.clone())),
            Message::ObjectHeader(h) => {
                check_header(&h.name, h.encoding)?;
                let v = Value::Tuple(vec![
                    Value::Byte(h.name.ty.as_u32() as u8),
                    Value::Bytes(h.name.checksum.as_bytes().to_vec()),
                    Value::Byte(h.encoding.as_u8()),
                ]);
                (&OBJECT_HEADER, v)
            }
            Message::ObjectsReply(r) => {
                let v = Value::Tuple(vec![Value::U32(r.objects), Value::U64(r.payload_bytes)]);
                (&OBJECTS_REPLY, v)
            }
            Message::Commit(c) => {
                let updates = c
                    .updates
                    .iter()
                    .map(|u| {
                        let (state, expected) = match u.expected {
                            Expected::Absent => (0, None),
                            Expected::Commit(c) => (1, Some(c)),
                            Expected::Any => (2, None),
                        };
                        Value::Tuple(vec![
                            Value::Str(u.name.clone()),
                            Value::Byte(state),
                            maybe_value(expected),
                            maybe_value(u.new),
                        ])
                    })
                    .collect();
                let mut opts = DictBuilder::new();
                if c.force {
                    opts.insert_bool("force", true);
                }
                (
                    &COMMIT,
                    Value::Tuple(vec![Value::Array(updates), opts.build()]),
                )
            }
            Message::CommitReply(outcomes) => {
                let v = outcomes
                    .iter()
                    .map(|o| {
                        Value::Tuple(vec![
                            Value::Str(o.name.clone()),
                            maybe_value(o.old),
                            maybe_value(o.new),
                        ])
                    })
                    .collect();
                (&COMMIT_REPLY, Value::Array(v))
            }
            Message::Error(e) => {
                check_error(e)?;
                let mut detail = DictBuilder::new();
                if !e.missing.is_empty() {
                    detail.insert(
                        "missing",
                        OBJECT_NAMES.clone(),
                        object_names_value(&e.missing)?,
                    );
                }
                if let Some(state) = &e.current {
                    detail.insert_str("ref", &state.name).insert(
                        "current",
                        MAYBE_CHECKSUM.clone(),
                        maybe_value(state.commit),
                    );
                }
                let v = Value::Tuple(vec![
                    Value::Str(e.code.as_str().to_owned()),
                    Value::Str(e.message.clone()),
                    detail.build(),
                ]);
                (&ERROR, v)
            }
            Message::PullHello(h) => {
                let mut opts = DictBuilder::new();
                if let Some(agent) = &h.agent {
                    opts.insert_str("agent", agent);
                }
                let v = Value::Tuple(vec![Value::U32(h.version), opts.build()]);
                (&PULL_HELLO, v)
            }
            Message::PullHelloReply(r) => {
                let v = Value::Tuple(vec![Value::U32(r.version), DictBuilder::new().build()]);
                (&PULL_HELLO, v)
            }
            Message::Get(path) => (&Type::Str, Value::Str(path.clone())),
            Message::GetReply(r) => {
                check_get_reply(r)?;
                let len = Value::Maybe(r.len.map(|n| Box::new(Value::U64(n))));
                (&GET_REPLY, Value::Tuple(vec![Value::Bool(r.found), len]))
            }
        };
        ostrya_gvariant::to_bytes(ty, &value).map_err(|e| protocol(format!("encode: {e}")))
    }

    /// Decodes the body of a message of `kind`.
    ///
    /// The decoder borrows strings and byte arrays from `body` and reads each
    /// array one entry at a time. It allocates the decoded message. For a
    /// dict value under a key that it does not know, it allocates a value
    /// tree, checks it for normal form, and then drops it.
    /// [`MAX_FRAME`](super::MAX_FRAME) states the measured peaks.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] if the body is malformed:
    ///
    /// - the body is not in normal form for the type of `kind`
    /// - an `ObjectsEnd` body is not empty, or an `Abort` body is not the one
    ///   byte `0x00`
    /// - a known dict key holds a value of the wrong type
    /// - a `HelloReply` has no `mode`, `max-frame`, `max-have`, `encodings`,
    ///   or `parallel-uploads` key, or a limit is out of range
    /// - a checksum is not 32 bytes long
    /// - an object type or an encoding byte is not allowed in the message
    /// - a ref update of a `Commit` has an unknown expected state, or a state
    ///   that does not match its expected commit
    /// - an `Error` message has an unknown code, has one of the keys `ref`
    ///   and `current` alone, or has the code `ref-mismatch` with neither
    /// - a `GetReply` whose `found` is `false` has a length
    pub fn decode(kind: Kind, body: &[u8]) -> Result<Message> {
        Ok(match kind {
            Kind::ObjectsEnd => {
                if !body.is_empty() {
                    return Err(protocol("ObjectsEnd body is not empty"));
                }
                Message::ObjectsEnd
            }
            Kind::Abort => {
                if body != [0] {
                    return Err(protocol("Abort body is not the unit tuple"));
                }
                Message::Abort
            }
            Kind::Hello => {
                let (version, opts, refs): (u32, Dict, ArrayIter<&str>) = parse_body(body)?;
                let [agent, one_way] = dict(opts, ["agent", "one-way"])?;
                let agent: Option<&str> = field(agent, "agent", &Type::Str)?;
                let one_way = field(one_way, "one-way", &Type::Bool)?.unwrap_or(false);
                Message::Hello(Hello {
                    version,
                    agent: agent.map(str::to_owned),
                    refs: collect(refs, |r| Ok(r.to_owned()))?,
                    one_way,
                })
            }
            Kind::HelloReply => Message::HelloReply(decode_hello_reply(body)?),
            Kind::Have => Message::Have(object_names(parse_body(body)?)?),
            Kind::HaveReply => {
                let bitmap: &[u8] = parse_body(body)?;
                Message::HaveReply(HaveReply {
                    bitmap: bitmap.to_vec(),
                })
            }
            Kind::ObjectHeader => {
                let (ty, sum, enc): (u8, &[u8], u8) = parse_body(body)?;
                let name = object_name((ty, sum), header_type)?;
                let encoding = Encoding::from_u8(enc)?;
                check_header(&name, encoding)?;
                Message::ObjectHeader(ObjectHeader { name, encoding })
            }
            Kind::ObjectsReply => {
                let (objects, payload_bytes) = parse_body(body)?;
                Message::ObjectsReply(ObjectsReply {
                    objects,
                    payload_bytes,
                })
            }
            Kind::Commit => {
                let (updates, opts): (ArrayIter<UpdateView>, Dict) = parse_body(body)?;
                let updates = collect(updates, decode_update)?;
                let [force] = dict(opts, ["force"])?;
                let force = field(force, "force", &Type::Bool)?.unwrap_or(false);
                Message::Commit(CommitRequest { updates, force })
            }
            Kind::CommitReply => {
                let outcomes: ArrayIter<(&str, MaybeBytes, MaybeBytes)> = parse_body(body)?;
                Message::CommitReply(collect(outcomes, |(name, old, new)| {
                    Ok(RefOutcome {
                        name: name.to_owned(),
                        old: maybe_checksum(old)?,
                        new: maybe_checksum(new)?,
                    })
                })?)
            }
            Kind::Error => Message::Error(decode_error(body)?),
            Kind::PullHello => {
                let (version, opts): (u32, Dict) = parse_body(body)?;
                let [agent] = dict(opts, ["agent"])?;
                let agent: Option<&str> = field(agent, "agent", &Type::Str)?;
                Message::PullHello(PullHello {
                    version,
                    agent: agent.map(str::to_owned),
                })
            }
            Kind::PullHelloReply => {
                let (version, opts): (u32, Dict) = parse_body(body)?;
                let [] = dict(opts, [])?;
                Message::PullHelloReply(PullHelloReply { version })
            }
            Kind::Get => {
                let path: &str = parse_body(body)?;
                Message::Get(path.to_owned())
            }
            Kind::GetReply => {
                let (found, len): (bool, MaybeU64) = parse_body(body)?;
                let r = GetReply { found, len: len.0 };
                check_get_reply(&r)?;
                Message::GetReply(r)
            }
        })
    }
}

/// Checks the limits of a `HelloReply`.
///
/// `max-frame` must be in `MIN_FRAME_LIMIT..=MAX_FRAME_LIMIT`, and `max-have`
/// and `parallel-uploads` must be at least 1. Otherwise the function returns
/// `Error::Protocol`.
fn check_limits(max_frame: u32, max_have: u32, parallel_uploads: u32) -> Result<()> {
    if !(MIN_FRAME_LIMIT..=MAX_FRAME_LIMIT).contains(&max_frame) {
        return Err(protocol(format!("max-frame {max_frame} is out of range")));
    }
    if max_have == 0 || parallel_uploads == 0 {
        return Err(protocol("max-have and parallel-uploads must be at least 1"));
    }
    Ok(())
}

/// Checks that a `ref-mismatch` message carries the ref and its current
/// state.
fn check_error(e: &ErrorMessage) -> Result<()> {
    if e.code == ErrorCode::RefMismatch && e.current.is_none() {
        return Err(protocol("ref-mismatch lacks ref and current"));
    }
    Ok(())
}

fn decode_hello_reply(body: &[u8]) -> Result<HelloReply> {
    let (version, opts, refs): (u32, Dict, ArrayIter<(&str, MaybeBytes)>) = parse_body(body)?;
    let [
        mode,
        collection_id,
        max_frame,
        max_have,
        encodings,
        parallel_uploads,
    ] = dict(
        opts,
        [
            "mode",
            "collection-id",
            "max-frame",
            "max-have",
            "encodings",
            "parallel-uploads",
        ],
    )?;
    let mode: &str = required(mode, "mode", &Type::Str)?;
    let collection_id: Option<&str> = field(collection_id, "collection-id", &Type::Str)?;
    let max_frame = required(max_frame, "max-frame", &Type::U32)?;
    let max_have = required(max_have, "max-have", &Type::U32)?;
    let parallel_uploads = required(parallel_uploads, "parallel-uploads", &Type::U32)?;
    check_limits(max_frame, max_have, parallel_uploads)?;
    let names: ArrayIter<&str> = required(encodings, "encodings", &STRV)?;
    let mut encodings = Vec::new();
    for name in names {
        encodings.extend(Encoding::from_name(name.map_err(malformed)?));
    }
    let refs = collect(refs, |(name, commit)| {
        Ok(RefState {
            name: name.to_owned(),
            commit: maybe_checksum(commit)?,
        })
    })?;
    Ok(HelloReply {
        version,
        mode: mode.to_owned(),
        collection_id: collection_id.map(str::to_owned),
        max_frame,
        max_have,
        encodings,
        parallel_uploads,
        refs,
    })
}

/// A `(symaymay)` ref update, as the body holds it.
type UpdateView<'a> = (&'a str, u8, MaybeBytes<'a>, MaybeBytes<'a>);

fn decode_update((name, state, expected, new): UpdateView) -> Result<RefUpdate> {
    let expected = match (state, maybe_checksum(expected)?) {
        (0, None) => Expected::Absent,
        (1, Some(c)) => Expected::Commit(c),
        (2, None) => Expected::Any,
        (s @ 0..=2, _) => {
            return Err(protocol(format!(
                "expected state {s} does not match its commit"
            )));
        }
        (s, _) => return Err(protocol(format!("unknown expected state {s}"))),
    };
    Ok(RefUpdate {
        name: name.to_owned(),
        expected,
        new: maybe_checksum(new)?,
    })
}

fn decode_error(body: &[u8]) -> Result<ErrorMessage> {
    let (name, message, detail): (&str, &str, Dict) = parse_body(body)?;
    let code =
        ErrorCode::from_name(name).ok_or_else(|| protocol(format!("unknown error code {name}")))?;
    let [missing, ref_name, current] = dict(detail, ["missing", "ref", "current"])?;
    let missing = match field(missing, "missing", &OBJECT_NAMES)? {
        Some(names) => object_names(names)?,
        None => Vec::new(),
    };
    let ref_name: Option<&str> = field(ref_name, "ref", &Type::Str)?;
    let current = match (ref_name, field(current, "current", &MAYBE_CHECKSUM)?) {
        (Some(name), Some(commit)) => Some(RefState {
            name: name.to_owned(),
            commit: maybe_checksum(commit)?,
        }),
        (None, None) => None,
        _ => return Err(protocol("Error carries one of ref and current alone")),
    };
    let e = ErrorMessage {
        code,
        message: message.to_owned(),
        missing,
        current,
    };
    check_error(&e)?;
    Ok(e)
}

/// Checks that a reply whose `found` is `false` carries no length.
fn check_get_reply(r: &GetReply) -> Result<()> {
    if !r.found && r.len.is_some() {
        return Err(protocol("GetReply with found false carries a length"));
    }
    Ok(())
}

/// Checks the object type of an `ObjectHeader`, and that `deflate` occurs
/// for a file object alone.
fn check_header(name: &ObjectName, encoding: Encoding) -> Result<()> {
    if !header_type(name.ty) {
        return Err(protocol(format!(
            "object type {} is not allowed in ObjectHeader",
            name.ty.as_u32()
        )));
    }
    if encoding == Encoding::Deflate && name.ty != ObjectType::File {
        return Err(protocol("deflate is allowed for a file object alone"));
    }
    Ok(())
}

/// The length of an `ObjectHeader` frame: the 4 length bytes, the kind, and
/// the 35 bytes of the body.
pub(super) const OBJECT_HEADER_FRAME: usize = 40;

/// Builds the frame of an `ObjectHeader` with no allocation.
///
/// The body `(yayy)` is the type, the 32 checksum bytes, the encoding, and
/// one framing offset: the end of the checksum array, 33. The bytes equal the
/// length, the kind, and the bytes of [`Message::encode_body`].
pub(super) fn object_header_frame(h: &ObjectHeader) -> Result<[u8; OBJECT_HEADER_FRAME]> {
    check_header(&h.name, h.encoding)?;
    let mut frame = [0u8; OBJECT_HEADER_FRAME];
    frame[..4].copy_from_slice(&(OBJECT_HEADER_FRAME as u32 - 4).to_be_bytes());
    frame[4] = Kind::ObjectHeader.as_u8();
    frame[5] = h.name.ty.as_u32() as u8;
    frame[6..38].copy_from_slice(h.name.checksum.as_bytes());
    frame[38] = h.encoding.as_u8();
    frame[39] = 33;
    Ok(frame)
}

/// The length of the longest `GetReply` frame: the 4 length bytes, the
/// kind, and the 16 bytes of a body with a length.
pub(super) const GET_REPLY_FRAME: usize = 21;

/// Builds the frame of a `GetReply` with no allocation.
///
/// The function also returns the number of bytes in use: 13 with no length,
/// 21 with one.
///
/// The body `(bmt)` is the found byte, 7 bytes of padding to the alignment
/// of the `mt`, and, if there is a length, its 8 bytes in little-endian
/// order. A fixed-size first member and a last member take no framing
/// offset. The bytes equal the length, the kind, and the bytes of
/// [`Message::encode_body`].
pub(super) fn get_reply_frame(r: &GetReply) -> Result<([u8; GET_REPLY_FRAME], usize)> {
    check_get_reply(r)?;
    let mut frame = [0u8; GET_REPLY_FRAME];
    let used = match r.len {
        Some(len) => {
            frame[13..].copy_from_slice(&len.to_le_bytes());
            GET_REPLY_FRAME
        }
        None => 13,
    };
    frame[..4].copy_from_slice(&(used as u32 - 4).to_be_bytes());
    frame[4] = Kind::GetReply.as_u8();
    frame[5] = u8::from(r.found);
    Ok((frame, used))
}

fn object_names_value(names: &[ObjectName]) -> Result<Value> {
    if let Some(bad) = names.iter().find(|n| !have_type(n.ty)) {
        return Err(protocol(format!(
            "object type {} is not allowed in an object list",
            bad.ty.as_u32()
        )));
    }
    Ok(Value::Array(names.iter().map(object_name_value).collect()))
}

fn object_names(names: ArrayIter<(u8, &[u8])>) -> Result<Vec<ObjectName>> {
    collect(names, |e| object_name(e, have_type))
}

fn malformed(e: ostrya_gvariant::Error) -> Error {
    protocol(format!("malformed body: {e}"))
}

fn parse_body<'a, T: GvDecode<'a>>(body: &'a [u8]) -> Result<T> {
    T::decode(body).map_err(malformed)
}

/// Decodes every entry of `items` and maps it with `f`.
///
/// A first pass counts the entries, so the function allocates the result
/// once, at its final size.
fn collect<'a, E: GvDecode<'a> + Copy, T>(
    items: ArrayIter<'a, E>,
    mut f: impl FnMut(E) -> Result<T>,
) -> Result<Vec<T>> {
    let mut out = Vec::with_capacity(items.count());
    for e in items {
        out.push(f(e.map_err(malformed)?)?);
    }
    Ok(out)
}

fn maybe_checksum(m: MaybeBytes) -> Result<Option<Checksum>> {
    m.0.map(checksum).transpose()
}

/// A `may` in the body: no bytes for `None`, or the bytes of the array and a
/// zero byte.
#[derive(Clone, Copy)]
struct MaybeBytes<'a>(Option<&'a [u8]>);

impl GvType for MaybeBytes<'_> {
    const ALIGNMENT: usize = 1;
    const FIXED_SIZE: Option<usize> = None;
}

impl<'a> GvDecode<'a> for MaybeBytes<'a> {
    fn decode(data: &'a [u8]) -> ostrya_gvariant::Result<Self> {
        match data.split_last() {
            None => Ok(MaybeBytes(None)),
            Some((0, rest)) => Ok(MaybeBytes(Some(rest))),
            Some(_) => Err(ostrya_gvariant::Error::NotNormal(
                "maybe lacks its terminating zero byte",
            )),
        }
    }
}

/// An `mt` in the body: no bytes for `None`, or the 8 bytes of the `t`.
///
/// A maybe of a fixed-size type has no terminating zero byte.
struct MaybeU64(Option<u64>);

impl GvType for MaybeU64 {
    const ALIGNMENT: usize = 8;
    const FIXED_SIZE: Option<usize> = None;
}

impl<'a> GvDecode<'a> for MaybeU64 {
    fn decode(data: &'a [u8]) -> ostrya_gvariant::Result<Self> {
        match data.len() {
            0 => Ok(MaybeU64(None)),
            8 => u64::decode(data).map(|n| MaybeU64(Some(n))),
            _ => Err(ostrya_gvariant::Error::NotNormal(
                "maybe of a u64 is not 0 or 8 bytes",
            )),
        }
    }
}

/// A `v` in the body: the type of the child and the child bytes, not yet
/// decoded.
struct RawVariant<'a> {
    ty: Type,
    child: &'a [u8],
}

impl GvType for RawVariant<'_> {
    const ALIGNMENT: usize = 8;
    const FIXED_SIZE: Option<usize> = None;
}

impl<'a> GvDecode<'a> for RawVariant<'a> {
    fn decode(data: &'a [u8]) -> ostrya_gvariant::Result<Self> {
        let not_normal = ostrya_gvariant::Error::NotNormal;
        let sep = data
            .iter()
            .rposition(|&b| b == 0)
            .ok_or(not_normal("variant lacks a type separator"))?;
        let signature = std::str::from_utf8(&data[sep + 1..])
            .map_err(|_| not_normal("variant type signature is not UTF-8"))?;
        let ty =
            Type::parse(signature).map_err(|_| not_normal("variant type signature is invalid"))?;
        Ok(RawVariant {
            ty,
            child: &data[..sep],
        })
    }
}

/// An `a{sv}` in the body.
type Dict<'a> = ArrayIter<'a, (&'a str, RawVariant<'a>)>;

/// Returns the first entry of each of `keys` in `entries`.
///
/// The function checks every other entry for normal form and then drops it.
/// The caller decodes each returned entry with [`field`].
fn dict<'a, const N: usize>(
    entries: Dict<'a>,
    keys: [&str; N],
) -> Result<[Option<RawVariant<'a>>; N]> {
    let mut found = [const { None }; N];
    for entry in entries {
        let (key, value) = entry.map_err(malformed)?;
        match keys.iter().position(|k| *k == key) {
            Some(i) if found[i].is_none() => found[i] = Some(value),
            _ => {
                ostrya_gvariant::from_bytes(&value.ty, value.child).map_err(malformed)?;
            }
        }
    }
    Ok(found)
}

/// Returns the value of the dict entry `key`.
///
/// If the key is absent, the function returns `Ok(None)`. If the variant
/// does not hold `ty`, it returns `Error::Protocol`.
fn field<'a, T: GvDecode<'a>>(
    entry: Option<RawVariant<'a>>,
    key: &str,
    ty: &Type,
) -> Result<Option<T>> {
    let Some(v) = entry else {
        return Ok(None);
    };
    if v.ty != *ty {
        return Err(protocol(format!("key {key} has the wrong type")));
    }
    T::decode(v.child).map(Some).map_err(malformed)
}

/// Returns the value of the `HelloReply` key `key`, which must be present.
///
/// If the key is absent, the function returns `Error::Protocol`.
fn required<'a, T: GvDecode<'a>>(entry: Option<RawVariant<'a>>, key: &str, ty: &Type) -> Result<T> {
    field(entry, key, ty)?.ok_or_else(|| protocol(format!("HelloReply lacks {key}")))
}
