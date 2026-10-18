//! The messages of the protocol and their GVariant bodies.

use std::sync::LazyLock;

use ostrya_core::{Checksum, ObjectName, ObjectType};
use ostrya_gvariant::{
    ArrayIter, DictBuilder, GvDecode, GvEncode, GvType, Slice, Type, Value, encode_to_vec, to_bytes,
};

use super::{
    Encoding, Expected, Kind, MAX_FRAME_LIMIT, MIN_FRAME_LIMIT, RefOutcome, RefState, RefUpdate,
    checksum, have_type, header_type, maybe_value, object_name, object_name_value, protocol,
};
use crate::error::{Error, ErrorCode, Result};

/// The type of the `server-commit` value of a `Commit`.
const SERVER_COMMIT_SIGNATURE: &str = "(sasas(ayay)ssa{sv}a{sv})";

fn parse(signature: &str) -> Type {
    Type::parse(signature).expect("valid signature")
}

static HELLO: LazyLock<Type> = LazyLock::new(|| parse("(ua{sv}as)"));
static HELLO_REPLY: LazyLock<Type> = LazyLock::new(|| parse("(ua{sv}a(smay))"));
static OBJECT_NAMES: LazyLock<Type> = LazyLock::new(|| parse("a(yay)"));
static BYTES: LazyLock<Type> = LazyLock::new(|| parse("ay"));
static OBJECT_HEADER: LazyLock<Type> = LazyLock::new(|| parse("(yayy)"));
static OBJECTS_REPLY: LazyLock<Type> = LazyLock::new(|| parse("(ut)"));
static UPDATES: LazyLock<Type> = LazyLock::new(|| parse("a(symaymay)"));
static SERVER_COMMIT: LazyLock<Type> = LazyLock::new(|| parse(SERVER_COMMIT_SIGNATURE));
static COMMIT_REPLY: LazyLock<Type> = LazyLock::new(|| parse("a(smaymay)"));
static ERROR: LazyLock<Type> = LazyLock::new(|| parse("(ssa{sv})"));
static STRV: LazyLock<Type> = LazyLock::new(|| parse("as"));
static MAYBE_CHECKSUM: LazyLock<Type> = LazyLock::new(|| parse("may"));
static PULL_HELLO: LazyLock<Type> = LazyLock::new(|| parse("(ua{sv})"));
static GET_REPLY: LazyLock<Type> = LazyLock::new(|| parse("(bmt)"));
static LIST_REFS: LazyLock<Type> = LazyLock::new(|| parse("(asa{sv})"));
static VALUE_IN_COMMIT: LazyLock<Type> = LazyLock::new(|| parse("((v))"));

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
    /// The collection id of the namespace that the session targets, under
    /// the key `collection`.
    ///
    /// `None` targets the local refs. The collection id of the server also
    /// targets the local refs. The encoder writes the key only if the value
    /// is `Some`.
    pub collection: Option<String>,
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
    /// The collection of the namespace that the server selected for the
    /// session, under the key `collection`.
    ///
    /// `None` is the local refs. The encoder writes the key only if the value
    /// is `Some`.
    pub collection: Option<String>,
    /// The frame limit that the server announces, under the key `max-frame`.
    ///
    /// Encode and decode return [`Error::Protocol`] for a value outside
    /// [`MIN_FRAME_LIMIT`](super::MIN_FRAME_LIMIT)`..=`[`MAX_FRAME_LIMIT`](super::MAX_FRAME_LIMIT).
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
    /// For a `CommitMeta` object and a `ComposefsImage` object, the checksum
    /// is the checksum of its commit.
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
/// can count it. A second detached metadata object or a second composefs
/// image for one commit is [`Error::Protocol`], also from another stream, and
/// the session ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectsReply {
    /// The number of objects that the server stored.
    ///
    /// A composefs image does not count.
    pub objects: u32,
    /// The number of payload bytes that the server wrote.
    ///
    /// The bytes of a composefs image count.
    pub payload_bytes: u64,
}

/// The `Commit` message, with the ref updates of the transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRequest {
    /// The ref updates.
    ///
    /// A `Commit` with a [`server_commit`](Self::server_commit) holds no
    /// update.
    pub updates: Vec<RefUpdate>,
    /// The flag that allows a ref update that is not a fast-forward.
    ///
    /// The key is `force`. The encoder writes the key only if the value is
    /// `true`, and the decoder reads an absent key as `false`.
    pub force: bool,
    /// The commit that the server makes, under the key `server-commit`.
    ///
    /// The encoder writes the key only if the value is `Some`, and the
    /// decoder reads an absent key as `None`. The value is boxed, so a
    /// [`Message`] of another kind stays small.
    pub server_commit: Option<Box<ServerCommit>>,
}

/// A commit that the server makes from a tree and the fields that the client
/// sends, the value of the `server-commit` key of a `Commit`.
///
/// The value has the type `(sasas(ayay)ssa{sv}a{sv})`. Its members hold the
/// fields in the order of this struct. The root dirtree and the root dirmeta
/// make one `(ayay)` member. [`timestamp`](Self::timestamp) and
/// [`orphan`](Self::orphan) are keys of the last member, a dict of options.
///
/// The server reads the tip of the branch under its update lock, and writes
/// the commit with that tip as its parent. It moves the branch and creates
/// each tag at the new commit. The `CommitReply` of a server commit holds
/// one entry for the branch, then one entry for each tag. The `new` commit of
/// each entry is the commit that the server wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCommit {
    /// The branch that the server moves to the new commit.
    pub branch: String,
    /// The tags that the server creates at the new commit, in order.
    pub tags: Vec<String>,
    /// The names that the commit binds and that get no ref, in order.
    ///
    /// The `ostree.ref-binding` of the commit holds the branch, each tag, and
    /// each of these names.
    pub bind_refs: Vec<String>,
    /// The checksum of the root dirtree of the commit.
    pub root_dirtree: Checksum,
    /// The checksum of the root dirmeta of the commit.
    pub root_dirmeta: Checksum,
    /// The subject of the commit.
    pub subject: String,
    /// The body of the commit.
    pub body: String,
    /// The metadata entries of the client, in order.
    ///
    /// Each entry is a key and the bytes of a `v` in normal form: the bytes
    /// of the value, a zero byte, and the type signature of the value.
    /// [`to_bytes`](ostrya_gvariant::to_bytes) with [`Type::Variant`] gives
    /// these bytes. The dict is data, and the rules of a protocol dict do not
    /// apply to it: the decoder keeps each entry in order, also a key that
    /// occurs two times. The decoder and the encoder check the bytes of each
    /// entry and build no value tree.
    pub metadata: Vec<(String, Vec<u8>)>,
    /// The commit time in seconds since the Unix epoch, UTC, under the key
    /// `timestamp`.
    ///
    /// `None` gives the clock of the server. The encoder writes the key only
    /// if the value is `Some`.
    pub timestamp: Option<u64>,
    /// The flag that makes a commit with no parent, under the key `orphan`.
    ///
    /// The encoder writes the key only if the value is `true`, and the
    /// decoder reads an absent key as `false`.
    pub orphan: bool,
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
    /// not empty. Each object is of type 1 to 4 or 100. For another type,
    /// encode and decode return [`Error::Protocol`].
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

/// The reply to one `Get` or one `ListRefs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetReply {
    /// The flag that is `true` if the server serves the path or the listing.
    ///
    /// If `found` is `true`, a body of chunks follows the reply, as
    /// [Object stream](super#object-stream) states.
    pub found: bool,
    /// The length of the body, if the server knows it.
    ///
    /// A reply to a `ListRefs` must hold it, as the specification of
    /// [`ListRefs`](https://github.com/growler/ostrya/blob/main/docs/format-reference.md#listrefs) states. If `found` is `false` and the length
    /// is present, encode and decode return [`Error::Protocol`].
    pub len: Option<u64>,
}

/// The `ListRefs` message: the entries of a ref listing request.
///
/// Each entry is a ref pattern of a
/// [`RefSelector`](ostrya_core::RefSelector), with an optional leading `!`.
/// The codec does not check the entries.
/// [`MAX_REF_PATTERNS`](super::MAX_REF_PATTERNS),
/// [`MAX_REF_ENTRY_PARTS`](super::MAX_REF_ENTRY_PARTS), and
/// [`MAX_REF_ENTRY_LEN`](super::MAX_REF_ENTRY_LEN) are the limits of a
/// request. The two lists share the limit of entries. The specification of
/// [`ListRefs`](https://github.com/growler/ostrya/blob/main/docs/format-reference.md#listrefs)
/// states the reply.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListRefsRequest {
    /// The entries that the server matches against the names of the local
    /// refs.
    pub refs: Vec<String>,
    /// The entries that the server matches against `ID/NAME` of the
    /// collection refs, under the key `collections`.
    ///
    /// `None` asks for no collection ref. The encoder writes the key only if
    /// the value is `Some`, also for an empty list. An empty list selects
    /// each collection ref.
    pub collections: Option<Vec<String>>,
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
    /// Each object is of type 1 to 4 or 100.
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
    /// The `CommitReply` message, with one outcome for each ref update, or
    /// for each ref of a [`ServerCommit`].
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
    /// The `ListRefs` message, with the entries of a ref listing request.
    ListRefs(ListRefsRequest),
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
            Message::ListRefs(_) => Kind::ListRefs,
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
    /// - a `Have` entry or a `missing` object of a type other than 1 to 4 and
    ///   100, for example type 6
    /// - an `ObjectHeader` of a type other than 1 to 4, 6, and 100, or with
    ///   [`Encoding::Deflate`] for an object that is not a file
    /// - an `Error` message with the code `ref-mismatch` and no `current`
    ///   state
    /// - a `GetReply` whose `found` is `false` and that has a length
    /// - a metadata entry of a [`ServerCommit`] whose bytes are not a `v` in
    ///   normal form
    /// - a string with an interior NUL byte, which the GVariant serializer
    ///   refuses
    pub fn encode_body(&self) -> Result<Vec<u8>> {
        let (ty, value): (&Type, Value) = match self {
            Message::Commit(c) => return encode_commit(c),
            Message::ObjectsEnd => return Ok(Vec::new()),
            Message::Abort => return Ok(vec![0]),
            Message::Hello(h) => {
                let mut opts = DictBuilder::new();
                if let Some(agent) = &h.agent {
                    opts.insert_str("agent", agent);
                }
                if let Some(collection) = &h.collection {
                    opts.insert_str("collection", collection);
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
                if let Some(collection) = &r.collection {
                    opts.insert_str("collection", collection);
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
            Message::ListRefs(r) => {
                let mut opts = DictBuilder::new();
                if let Some(collections) = &r.collections {
                    opts.insert_strv("collections", collections);
                }
                let refs = r.refs.iter().cloned().map(Value::Str).collect();
                (
                    &LIST_REFS,
                    Value::Tuple(vec![Value::Array(refs), opts.build()]),
                )
            }
        };
        to_bytes(ty, &value).map_err(encode_error)
    }

    /// Decodes the body of a message of `kind`.
    ///
    /// The decoder borrows strings and byte arrays from `body` and reads each
    /// array one entry at a time. It allocates the decoded message. It checks
    /// a dict value under a key that it does not know for normal form in
    /// place, with no value tree, and then drops it. If a dict holds a key
    /// two times, the first value counts, and the decoder checks each later
    /// value for normal form alone. It checks each metadata entry of a
    /// server commit in place and copies its bytes, with no value tree.
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
    /// - the value under `server-commit` of a `Commit`, or under `timestamp`
    ///   or `orphan` of its options, has the wrong type
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
                let [agent, collection, one_way] = dict(opts, ["agent", "collection", "one-way"])?;
                let agent: Option<&str> = field(agent, "agent", &Type::Str)?;
                let collection: Option<&str> = field(collection, "collection", &Type::Str)?;
                let one_way = field(one_way, "one-way", &Type::Bool)?.unwrap_or(false);
                Message::Hello(Hello {
                    version,
                    agent: agent.map(str::to_owned),
                    refs: collect(refs, |r| Ok(r.to_owned()))?,
                    collection: collection.map(str::to_owned),
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
                let [force, server_commit] = dict(opts, ["force", "server-commit"])?;
                let force = field(force, "force", &Type::Bool)?.unwrap_or(false);
                let server_commit = field(server_commit, "server-commit", &SERVER_COMMIT)?
                    .map(decode_server_commit)
                    .transpose()?
                    .map(Box::new);
                Message::Commit(CommitRequest {
                    updates,
                    force,
                    server_commit,
                })
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
            Kind::ListRefs => {
                let (refs, opts): (ArrayIter<&str>, Dict) = parse_body(body)?;
                let [collections] = dict(opts, ["collections"])?;
                let collections: Option<ArrayIter<&str>> =
                    field(collections, "collections", &STRV)?;
                Message::ListRefs(ListRefsRequest {
                    refs: collect(refs, |e| Ok(e.to_owned()))?,
                    collections: collections
                        .map(|entries| collect(entries, |e| Ok(e.to_owned())))
                        .transpose()?,
                })
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
        collection,
        max_frame,
        max_have,
        encodings,
        parallel_uploads,
    ] = dict(
        opts,
        [
            "mode",
            "collection-id",
            "collection",
            "max-frame",
            "max-have",
            "encodings",
            "parallel-uploads",
        ],
    )?;
    let mode: &str = required(mode, "mode", &Type::Str)?;
    let collection_id: Option<&str> = field(collection_id, "collection-id", &Type::Str)?;
    let collection: Option<&str> = field(collection, "collection", &Type::Str)?;
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
        collection: collection.map(str::to_owned),
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

/// Returns the [`Error::Protocol`] of an encode that fails.
fn encode_error(e: ostrya_gvariant::Error) -> Error {
    protocol(format!("encode: {e}"))
}

/// Returns the bytes of a `v` that holds `value` of the type `ty`.
fn variant_bytes(ty: Type, value: Value) -> Result<Vec<u8>> {
    to_bytes(&Type::Variant, &Value::variant(ty, value)).map_err(encode_error)
}

/// Returns the `a{sv}` entries of `entries`, each a key and the bytes of a
/// `v`, in the form that the typed encoder writes.
fn dict_entries<'a>(
    entries: &'a [(&'static str, Vec<u8>)],
) -> Vec<(&'static str, VariantSlice<'a>)> {
    entries
        .iter()
        .map(|(key, value)| (*key, VariantSlice { inner: value }))
        .collect()
}

/// Encodes the body of a `Commit` message.
///
/// The typed encoder writes the metadata of a server commit from its bytes,
/// so the encode builds no value tree for it, and the depth of a metadata
/// value inside the message does not count against the depth limit of the
/// serializer.
fn encode_commit(c: &CommitRequest) -> Result<Vec<u8>> {
    encode_commit_parts(&c.updates, c.force, c.server_commit.as_deref())
}

/// Returns the length of the frame of a `Commit` that holds the server
/// commit `sc` and no ref update: the kind byte and the body.
///
/// The bytes of each metadata entry of `sc` must be a `v` in normal form,
/// else the call returns [`Error::Protocol`].
pub(crate) fn server_commit_frame_len(sc: &ServerCommit) -> Result<u64> {
    Ok(encode_commit_parts(&[], false, Some(sc))?.len() as u64 + 1)
}

/// Checks that a commit can hold each metadata value of the server commit
/// `sc`.
///
/// A commit holds the depth limit of 128 levels of containers, counted from
/// its metadata dict. In that dict, the `v` of each value is under two
/// containers, the dict and its entry. A tuple with one member of variable
/// size holds the bytes of the member and no framing, so the bytes of a `v`
/// are also the bytes of `((v))`. The check reads the bytes as that type and
/// builds no value tree.
///
/// Bytes that are not a `v` in normal form are [`Error::Protocol`], as the
/// encode of the message gives. A `v` that a commit cannot hold is
/// [`Error::InvalidInput`].
pub(crate) fn check_server_commit_metadata(sc: &ServerCommit) -> Result<()> {
    for (key, value) in &sc.metadata {
        let Err(deep) = ostrya_gvariant::validate(&VALUE_IN_COMMIT, value) else {
            continue;
        };
        if let Err(e) = ostrya_gvariant::validate(&Type::Variant, value) {
            return Err(protocol(format!("encode: metadata entry '{key}': {e}")));
        }
        return Err(Error::InvalidInput(format!(
            "a commit cannot hold the metadata value under '{key}': {deep}"
        )));
    }
    Ok(())
}

/// Returns the length of the frame of the longest `CommitReply` to the
/// server commit `sc`: the kind byte and the body.
///
/// The reply holds the branch with an old commit and each tag with no old
/// commit, each with a new commit.
pub(crate) fn server_commit_reply_frame_len(sc: &ServerCommit) -> Result<u64> {
    let any_commit = Some(Checksum::from_bytes([0; 32]));
    let refs = std::iter::once(RefOutcome {
        name: sc.branch.clone(),
        old: any_commit,
        new: any_commit,
    })
    .chain(sc.tags.iter().map(|tag| RefOutcome {
        name: tag.clone(),
        old: None,
        new: any_commit,
    }))
    .collect();
    Ok(Message::CommitReply(refs).encode_body()?.len() as u64 + 1)
}

/// Encodes the body of a `Commit` message from its parts.
fn encode_commit_parts(
    updates: &[RefUpdate],
    force: bool,
    server_commit: Option<&ServerCommit>,
) -> Result<Vec<u8>> {
    let updates = updates
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
    let updates = to_bytes(&UPDATES, &Value::Array(updates)).map_err(encode_error)?;
    let mut opts = Vec::new();
    if force {
        opts.push(("force", variant_bytes(Type::Bool, Value::Bool(true))?));
    }
    if let Some(sc) = server_commit {
        let mut value = server_commit_bytes(sc)?;
        value.push(0);
        value.extend_from_slice(SERVER_COMMIT_SIGNATURE.as_bytes());
        opts.push(("server-commit", value));
    }
    encode_to_vec(&(updates.as_slice(), Slice(&dict_entries(&opts)))).map_err(encode_error)
}

/// Returns the bytes of the `server-commit` value of a `Commit`.
///
/// The bytes of each metadata entry must be a `v` in normal form, else the
/// call returns [`Error::Protocol`].
fn server_commit_bytes(sc: &ServerCommit) -> Result<Vec<u8>> {
    let tags: Vec<&str> = sc.tags.iter().map(String::as_str).collect();
    let bind_refs: Vec<&str> = sc.bind_refs.iter().map(String::as_str).collect();
    let metadata = sc
        .metadata
        .iter()
        .map(|(key, value)| {
            ostrya_gvariant::validate(&Type::Variant, value)
                .map_err(|e| protocol(format!("encode: metadata entry '{key}': {e}")))?;
            Ok((key.as_str(), VariantSlice { inner: value }))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut opts = Vec::new();
    if let Some(timestamp) = sc.timestamp {
        opts.push((
            "timestamp",
            variant_bytes(Type::U64, Value::U64(timestamp))?,
        ));
    }
    if sc.orphan {
        opts.push(("orphan", variant_bytes(Type::Bool, Value::Bool(true))?));
    }
    encode_to_vec(&(
        sc.branch.as_str(),
        Slice(&tags),
        Slice(&bind_refs),
        (sc.root_dirtree, sc.root_dirmeta),
        sc.subject.as_str(),
        sc.body.as_str(),
        Slice(&metadata),
        Slice(&dict_entries(&opts)),
    ))
    .map_err(encode_error)
}

/// A `(sasas(ayay)ssa{sv}a{sv})` server commit, as the body holds it.
type ServerCommitView<'a> = (
    &'a str,
    ArrayIter<'a, &'a str>,
    ArrayIter<'a, &'a str>,
    (&'a [u8], &'a [u8]),
    &'a str,
    &'a str,
    ArrayIter<'a, (&'a str, VariantSlice<'a>)>,
    Dict<'a>,
);

/// Decodes the `server-commit` value of a `Commit`.
///
/// The decoder checks that the bytes of each entry of the metadata dict are
/// a `v` in normal form, and keeps the bytes, in order, also a key that occurs
/// two times. It builds no value tree.
fn decode_server_commit(
    (branch, tags, bind_refs, (dirtree, dirmeta), subject, body, metadata, opts): ServerCommitView,
) -> Result<ServerCommit> {
    let [timestamp, orphan] = dict(opts, ["timestamp", "orphan"])?;
    let timestamp = field(timestamp, "timestamp", &Type::U64)?;
    let orphan = field(orphan, "orphan", &Type::Bool)?.unwrap_or(false);
    let metadata = collect(metadata, |(key, value)| {
        ostrya_gvariant::validate(&Type::Variant, value.inner).map_err(malformed)?;
        Ok((key.to_owned(), value.inner.to_vec()))
    })?;
    Ok(ServerCommit {
        branch: branch.to_owned(),
        tags: collect(tags, |t| Ok(t.to_owned()))?,
        bind_refs: collect(bind_refs, |n| Ok(n.to_owned()))?,
        root_dirtree: checksum(dirtree)?,
        root_dirmeta: checksum(dirmeta)?,
        subject: subject.to_owned(),
        body: body.to_owned(),
        metadata,
        timestamp,
        orphan,
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

/// A `v` in the body as its bytes, not yet checked.
#[derive(Clone, Copy)]
struct VariantSlice<'a> {
    inner: &'a [u8],
}

impl GvType for VariantSlice<'_> {
    const ALIGNMENT: usize = 8;
    const FIXED_SIZE: Option<usize> = None;
}

impl<'a> GvDecode<'a> for VariantSlice<'a> {
    fn decode(data: &'a [u8]) -> ostrya_gvariant::Result<Self> {
        Ok(VariantSlice { inner: data })
    }
}

impl GvEncode for VariantSlice<'_> {
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        out.extend_from_slice(self.inner);
        Ok(())
    }
}

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
                ostrya_gvariant::validate(&value.ty, value.child).map_err(malformed)?;
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
