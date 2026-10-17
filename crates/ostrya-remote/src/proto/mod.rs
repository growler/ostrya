//! The wire format of the push and the pull, and its codec.
//!
//! Each wire code is the [`Error`] variant of the same name, for example
//! [`Error::Protocol`] for the code `protocol`. [`ErrorCode`] names the
//! codes.
//!
//! `docs/format-reference.md` of the repository specifies the wire format,
//! and this module implements it. The sections below link to each part of the
//! specification.
//!
//! # Frames
//!
//! [Wire conventions] specifies the byte orders. [Frame layout] and
//! [Frame limits] specify the frame and its limits. [Messages] specifies the
//! message kinds with their bodies, and [Error codes] specifies the wire
//! codes.
//!
//! A client writes frames up to the limit that the server announces. It reads
//! frames up to a limit of its own, because the reader allocates each frame
//! body in full.
//!
//! The codec reads and writes every kind. A session refuses a kind of the
//! other protocol with [`Error::Protocol`].
//!
//! # Object stream
//!
//! [Chunks and the abandon marker] specifies the chunks of an object that
//! follow an `ObjectHeader`, and [Object streams] states the rules of the
//! server. [`ABANDON`] is the chunk length of the abandon marker.
//!
//! # One-way stream
//!
//! [The one-way stream] specifies the stream that carries a push in one
//! direction.
//!
//! # Pull
//!
//! [The pull session over a stream] specifies `PullHello`, `Get`, and
//! `ListRefs`. [`PULL_PROTOCOL_VERSION`] is the highest pull version that this
//! crate speaks. A [`GetReply`] answers each `Get` and each `ListRefs`.
//!
//! # Ref listing
//!
//! [The ref listing] specifies the body of a listing. A `ListRefs`
//! ([`ListRefsRequest`]) holds two lists of entries of a
//! [`RefSelector`](ostrya_core::RefSelector), which parses them: the entries
//! of the local refs, and the optional entries of the collection refs.
//! [`MAX_REF_PATTERNS`], [`MAX_REF_ENTRY_PARTS`], [`MAX_REF_ENTRY_LEN`], and
//! [`MAX_REF_LISTING`] are the limits of a request and of a listing.
//!
//! # Codec
//!
//! [`FrameReader`] and [`FrameWriter`] implement the frames, the object
//! stream, and the pull bodies over the `futures-io` traits, so the codec
//! needs no async runtime. Both enter the body state after an `ObjectHeader`
//! and after a `GetReply` whose `found` is `true`. One set of methods reads
//! and writes the bytes of both body kinds.
//!
//! The bytes pass through a buffer of the caller in bounded pieces, so no
//! call holds a whole object. [`ObjectBody`] presents the bytes of one body
//! as an `AsyncRead`.
//!
//! [`ErrorCode`]: crate::ErrorCode
//! [Wire conventions]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#wire-conventions
//! [Frame layout]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#frame-layout
//! [Frame limits]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#frame-limits
//! [Messages]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#messages
//! [Error codes]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#error-codes
//! [Chunks and the abandon marker]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#chunks-and-the-abandon-marker
//! [Object streams]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#object-streams
//! [The one-way stream]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#the-one-way-stream
//! [The pull session over a stream]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#the-pull-session-over-a-stream
//! [The ref listing]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#the-ref-listing

mod frame;
mod message;

pub use frame::{FrameReader, FrameWriter, ObjectBody, ObjectRead};
pub(crate) use frame::{Step, encode_frame};
pub use message::{
    CommitRequest, ErrorMessage, GetReply, HaveReply, Hello, HelloReply, ListRefsRequest, Message,
    ObjectHeader, ObjectsReply, PullHello, PullHelloReply,
};

use ostrya_core::{Checksum, ObjectName, ObjectType};
use ostrya_gvariant::Value;

use crate::error::{Error, Result};

/// The push protocol version that this crate speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// The highest pull protocol version that this crate speaks.
///
/// It is the version of `PullHello` and `PullHelloReply`. It is separate from
/// [`PROTOCOL_VERSION`], and each version changes on its own.
pub const PULL_PROTOCOL_VERSION: u32 = 1;

/// The lowest frame limit: 1 MiB.
///
/// This value is:
///
/// - the frame limit before the server announces one
/// - the lowest limit that a server can announce
/// - the limit of a stream that carries no announcement
pub const MIN_FRAME_LIMIT: u32 = 1 << 20;

/// The `max-frame` value that an ostrya server announces: 1 MiB.
///
/// Object bytes travel as chunks, so a frame carries only metadata messages.
/// The largest bounded message is a `Have` of [`MAX_HAVE`] entries, with a
/// frame length of 606,209 bytes. `Hello`, `HelloReply`, `Commit`, and the
/// `Error` message hold lists with no count limit. Only the frame limit
/// bounds them.
///
/// A chunk can be as long as the limit, so the framing costs 4 bytes for
/// each MiB of object data.
///
/// # Memory
///
/// The reader allocates a frame body in full. The decoder then keeps the body
/// and the decoded message together. On 1 MiB frames, the measured peak is:
///
/// - 2 times the frame for a `Have`
/// - 12 times the frame for a `HelloReply` of refs with empty names
/// - 13 times the frame for a `Commit` of ref updates with empty names
/// - 49 times the frame for a `Hello` whose one unknown key holds an `ab` of
///   1 MiB
///
/// The decoder checks a dict value under an unknown key through a value tree,
/// and then drops the tree. The peak grows in proportion to the limit.
pub const MAX_FRAME: u32 = 1 << 20;

/// The largest ref listing: 128 MiB.
///
/// A ref listing is the summary of the refs that the ref patterns of one
/// request select. An ostrya server builds a listing for each request. The
/// build refuses a larger listing with [`Error::LimitExceeded`]. Over a
/// stream, the server sends this error as the code `limit-exceeded`. Over
/// HTTP, the server answers with the status 500.
///
/// [`PullSession::fetch_refs`](crate::session::PullSession::fetch_refs) reads
/// a listing of at most this many bytes.
pub const MAX_REF_LISTING: u64 = 128 * 1024 * 1024;

/// The most entries in one request of a ref listing: 256.
///
/// Positive and negative entries count together, and the entries of the
/// local refs and of the collection refs count together. A server refuses a
/// request with more entries. It counts an entry that the request holds two
/// times as two entries. Over HTTP, each `pattern=VALUE` pair and each
/// `collection=VALUE` pair of the query is one entry.
///
/// Before it counts, a client removes each exact duplicate of an entry of the
/// same kind in the same list. The
/// [ref patterns](crate::session::PullSession#ref-patterns) of a pull give
/// the client rules.
pub const MAX_REF_PATTERNS: usize = 256;

/// The most parts in one entry of a ref listing request: 256.
///
/// A part is one element of the entry split at each `/`, the first and the
/// last included. For example, `a` has 1 part, and `a/b` has 2 parts. The
/// leading `!` of a negative entry adds no part.
///
/// A server refuses an entry with more parts before it parses the entry. The
/// cost of a match is the product of the part counts of the pattern and the
/// name, so the limit bounds the work of one entry.
pub const MAX_REF_ENTRY_PARTS: usize = 256;

/// The most bytes in one entry of a ref listing request: 4,096.
///
/// The leading `!` of a negative entry counts as one byte. A server refuses a
/// longer entry before it parses the entry.
pub const MAX_REF_ENTRY_LEN: usize = 4096;

/// The `max-have` value that an ostrya server announces: 16,384 entries.
///
/// A `Have` entry is 33 bytes plus a 4-byte offset. A `Have` of 16,384
/// entries has a frame length of 606,209 bytes, which fits in [`MAX_FRAME`].
/// A `Have` of 32,768 entries does not fit. A full `HaveReply` of 16,384
/// entries is 2,048 bytes.
pub const MAX_HAVE: u32 = 16_384;

/// The chunk length that abandons an object or a pull body.
pub const ABANDON: u32 = 0xFFFF_FFFF;

/// The highest valid frame limit.
///
/// It is one less than [`ABANDON`], so a chunk length that the limit allows
/// never equals the abandon marker.
pub const MAX_FRAME_LIMIT: u32 = 0xFFFF_FFFE;

/// A message kind, the byte after the frame length.
///
/// A later protocol version can add kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Kind {
    /// The `Hello` message, from the client to the server.
    Hello = 1,
    /// The `HelloReply` message, from the server to the client.
    HelloReply = 2,
    /// The `Have` message, from the client to the server.
    Have = 3,
    /// The `HaveReply` message, from the server to the client.
    HaveReply = 4,
    /// The `ObjectHeader` message, from the client to the server.
    ///
    /// The chunks of the object follow it.
    ObjectHeader = 5,
    /// The `ObjectsEnd` message, from the client to the server.
    ///
    /// It closes the object stream.
    ObjectsEnd = 6,
    /// The `ObjectsReply` message, from the server to the client.
    ObjectsReply = 7,
    /// The `Commit` message, from the client to the server.
    Commit = 8,
    /// The `CommitReply` message, from the server to the client.
    CommitReply = 9,
    /// The `Error` message, from the server to the client.
    ///
    /// The push and the pull both use it.
    Error = 10,
    /// The `Abort` message, from the client to the server.
    Abort = 11,
    /// The `PullHello` message, from a pull client to the server.
    PullHello = 12,
    /// The `PullHelloReply` message, from the server to a pull client.
    PullHelloReply = 13,
    /// The `Get` message, from a pull client to the server.
    Get = 14,
    /// The `GetReply` message, from the server to a pull client.
    ///
    /// It answers a `Get` or a `ListRefs`. A body follows a reply whose
    /// `found` is `true`.
    GetReply = 15,
    /// The `ListRefs` message, from a pull client to the server.
    ///
    /// The server answers it with one `GetReply`.
    ListRefs = 16,
}

impl Kind {
    /// Returns the kind of a kind byte.
    ///
    /// # Errors
    ///
    /// - [`Error::Protocol`] if the byte is not a kind.
    pub fn from_u8(byte: u8) -> Result<Kind> {
        Ok(match byte {
            1 => Kind::Hello,
            2 => Kind::HelloReply,
            3 => Kind::Have,
            4 => Kind::HaveReply,
            5 => Kind::ObjectHeader,
            6 => Kind::ObjectsEnd,
            7 => Kind::ObjectsReply,
            8 => Kind::Commit,
            9 => Kind::CommitReply,
            10 => Kind::Error,
            11 => Kind::Abort,
            12 => Kind::PullHello,
            13 => Kind::PullHelloReply,
            14 => Kind::Get,
            15 => Kind::GetReply,
            16 => Kind::ListRefs,
            _ => return Err(protocol(format!("unknown message kind {byte}"))),
        })
    }

    /// Returns the kind byte.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The encoding of an object in the object stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// The uncompressed object bytes.
    ///
    /// For a content object, the bytes are the framed file header and the
    /// payload.
    Raw,
    /// A content object in the compressed form of an archive repository.
    Deflate,
}

impl Encoding {
    /// Returns the wire byte: 0 for `raw`, 1 for `deflate`.
    pub fn as_u8(self) -> u8 {
        match self {
            Encoding::Raw => 0,
            Encoding::Deflate => 1,
        }
    }

    /// Returns the encoding of a wire byte.
    ///
    /// # Errors
    ///
    /// - [`Error::Protocol`] if the byte is not 0 or 1.
    pub fn from_u8(byte: u8) -> Result<Encoding> {
        match byte {
            0 => Ok(Encoding::Raw),
            1 => Ok(Encoding::Deflate),
            _ => Err(protocol(format!("unknown encoding {byte}"))),
        }
    }

    /// Returns the name in the `encodings` list of `HelloReply`.
    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Raw => "raw",
            Encoding::Deflate => "deflate",
        }
    }

    /// Returns the encoding of a name, or `None` if the name is not an
    /// encoding.
    pub fn from_name(name: &str) -> Option<Encoding> {
        match name {
            "raw" => Some(Encoding::Raw),
            "deflate" => Some(Encoding::Deflate),
            _ => None,
        }
    }
}

/// The state of a ref as the server reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefState {
    /// The ref name: `NAME` or `REMOTE:NAME`.
    pub name: String,
    /// The commit of the ref, or `None` if the ref is absent.
    pub commit: Option<Checksum>,
}

/// The state that a ref update expects the ref to be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    /// The ref is absent (wire state 0).
    Absent,
    /// The ref points at this commit (wire state 1).
    Commit(Checksum),
    /// The ref is in any state (wire state 2).
    Any,
}

/// One ref update of a `Commit` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    /// The ref name: `NAME` or `REMOTE:NAME`.
    pub name: String,
    /// The state that the ref must be in before the write.
    pub expected: Expected,
    /// The new commit, or `None` to delete the ref.
    pub new: Option<Checksum>,
}

/// The result of one ref update in a `CommitReply` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefOutcome {
    /// The ref name.
    pub name: String,
    /// The commit before the write, or `None` if the ref was absent.
    pub old: Option<Checksum>,
    /// The commit after the write, or `None` if the ref is now absent.
    pub new: Option<Checksum>,
}

pub(crate) fn protocol(msg: impl Into<String>) -> Error {
    Error::Protocol(msg.into())
}

/// Returns a checksum from an `ay` of 32 bytes.
fn checksum(bytes: &[u8]) -> Result<Checksum> {
    Checksum::from_ay(bytes).map_err(|_| protocol("checksum is not 32 bytes"))
}

fn checksum_value(c: &Checksum) -> Value {
    Value::Bytes(c.as_bytes().to_vec())
}

fn maybe_value(c: Option<Checksum>) -> Value {
    Value::Maybe(c.map(|c| Box::new(checksum_value(&c))))
}

/// Returns an object name from a `(y, ay)` pair whose type `allowed`
/// accepts.
fn object_name((byte, sum): (u8, &[u8]), allowed: fn(ObjectType) -> bool) -> Result<ObjectName> {
    let ty = ObjectType::from_u32(u32::from(byte))
        .ok()
        .filter(|t| allowed(*t))
        .ok_or_else(|| protocol(format!("object type {byte} is not allowed here")))?;
    Ok(ObjectName::new(checksum(sum)?, ty))
}

fn object_name_value(name: &ObjectName) -> Value {
    Value::Tuple(vec![
        Value::Byte(name.ty.as_u32() as u8),
        checksum_value(&name.checksum),
    ])
}

/// The length of one `Have` entry in a body of 65,536 bytes or more: the
/// type byte, the 32 bytes of the checksum, and an offset of 4 bytes. A
/// shorter body has offsets of 1 or 2 bytes.
const HAVE_ENTRY_LEN: u32 = 37;

/// Returns the most entries of a `Have` whose frame fits in `limit`.
///
/// The frame length counts the kind byte and the body. Fewer entries make a
/// shorter frame.
pub(crate) fn have_entries_within(limit: u32) -> u32 {
    (limit - 1) / HAVE_ENTRY_LEN
}

/// Returns `true` if a `Have` entry or a `missing` entry can name the type.
///
/// These are the types 1 to 4.
pub(crate) fn have_type(ty: ObjectType) -> bool {
    matches!(
        ty,
        ObjectType::File | ObjectType::DirTree | ObjectType::DirMeta | ObjectType::Commit
    )
}

/// Returns `true` if an `ObjectHeader` can name the type.
///
/// These are the types 1 to 4 and 6.
fn header_type(ty: ObjectType) -> bool {
    have_type(ty) || ty == ObjectType::CommitMeta
}
