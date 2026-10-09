//! The wire format of the push and the pull, and its codec.
//!
//! Each wire code is the [`Error`] variant of the same name, for example
//! [`Error::Protocol`] for the code `protocol`. [`ErrorCode`] names the
//! codes.
//!
//! # Frames
//!
//! The peers exchange frames. A frame has this layout:
//!
//! ```text
//! u32   length, big-endian, of the bytes that follow (kind byte + body)
//! u8    message kind
//! ...   GVariant body, normal form, of the type the kind names
//! ```
//!
//! A frame holds at least the kind byte, so a frame length of 0 is
//! [`Error::Protocol`]. A frame length greater than the current limit is
//! [`Error::LimitExceeded`]. The reader checks the length before it reads or
//! allocates the body.
//!
//! Before the server announces a limit, the limit is [`MIN_FRAME_LIMIT`]. The
//! server announces its limit in the key `max-frame` of `HelloReply`. The
//! value is from [`MIN_FRAME_LIMIT`] (1 MiB) to [`MAX_FRAME_LIMIT`]
//! (`0xFFFFFFFE`), both included. A value out of this range is
//! [`Error::Protocol`].
//!
//! The limit applies in both directions. A client writes frames up to the
//! announced limit. It reads frames up to a limit of its own, because the
//! reader allocates each frame body in full.
//!
//! The message kinds and their body types are:
//!
//! - 1 `Hello` -- `(ua{sv}as)`
//! - 2 `HelloReply` -- `(ua{sv}a(smay))`
//! - 3 `Have` -- `a(yay)`
//! - 4 `HaveReply` -- `ay`
//! - 5 `ObjectHeader` -- `(yayy)`
//! - 6 `ObjectsEnd` -- an empty body of zero bytes, with no GVariant type
//! - 7 `ObjectsReply` -- `(ut)`
//! - 8 `Commit` -- `(a(symaymay)a{sv})`
//! - 9 `CommitReply` -- `a(smaymay)`
//! - 10 `Error` -- `(ssa{sv})`
//! - 11 `Abort` -- `()`, which is the one byte `0x00` in normal form
//! - 12 `PullHello` -- `(ua{sv})`
//! - 13 `PullHelloReply` -- `(ua{sv})`
//! - 14 `Get` -- `s`
//! - 15 `GetReply` -- `(bmt)`
//!
//! The kinds belong to the two protocols as follows:
//!
//! - Kinds 1 to 9 and 11 belong to the push.
//! - Kinds 12 to 15 belong to the pull.
//! - Kind 10, the `Error` message, belongs to both.
//!
//! The codec reads and writes every kind. A session refuses a kind of the
//! other protocol with [`Error::Protocol`].
//!
//! Each of these is [`Error::Protocol`]:
//!
//! - a kind that is not in the list
//! - a body that is not in normal form for its type, or that has trailing
//!   bytes
//! - an `ObjectsEnd` body that is not empty
//! - an `Abort` body other than `0x00`
//!
//! The integers in a message body are little-endian, which is the GVariant
//! normal form. The protocol applies no value-level byte swap. The frame
//! length and the chunk length are big-endian.
//!
//! Every checksum in a body is an `ay` of exactly 32 bytes. A checksum of
//! another length is [`Error::Protocol`].
//!
//! The decoder ignores an `a{sv}` key that it does not know. A known key whose
//! value has the wrong type is [`Error::Protocol`]. If a key occurs twice, the
//! first one counts.
//!
//! # Object stream
//!
//! After an `ObjectHeader` frame, the bytes of the object follow as chunks.
//! A chunk is not a frame. It has this layout:
//!
//! ```text
//! u32   length, big-endian
//! ...   that number of object bytes
//! ```
//!
//! The chunk length has these meanings:
//!
//! - A chunk of length 0 ends the object. Then frames follow again: the next
//!   `ObjectHeader`, or `ObjectsEnd`, which closes the stream.
//! - The length [`ABANDON`] (`0xFFFFFFFF`) abandons the object. The next frame
//!   must be `Abort`. Any other frame is [`Error::Protocol`].
//! - Any other length greater than the current limit is
//!   [`Error::LimitExceeded`]. The chunk limit and the frame limit are the
//!   same number, at most [`MAX_FRAME_LIMIT`].
//!
//! The object type in `ObjectHeader` is one of these values:
//!
//! - 1, a file
//! - 2, a dirtree
//! - 3, a dirmeta
//! - 4, a commit
//! - 6, the detached metadata of a commit
//!
//! For type 6, the checksum is the checksum of the commit that the metadata
//! belongs to. `Have` names only types 1 to 4.
//!
//! The encoding is 0 (`raw`) or 1 (`deflate`). Only type 1 can have the
//! encoding `deflate`.
//!
//! # One-way stream
//!
//! A one-way stream carries the push messages in one direction, and the
//! receiver sends no message. The stream holds these parts, in this order:
//!
//! 1. one `Hello` whose key `one-way` is `true`
//! 2. zero or more object streams, each closed by `ObjectsEnd`
//! 3. one `Commit`
//! 4. the end of file
//!
//! No `HelloReply` announces a limit, so the frame limit and the chunk limit
//! are [`MIN_FRAME_LIMIT`]. A `Have` is [`Error::Protocol`]. An `Abort` message
//! between two objects is also [`Error::Protocol`].
//!
//! If a sender cannot complete an object, it writes the abandon marker and
//! `Abort`, as in a two-way session. A two-way receiver refuses a `Hello`
//! whose `one-way` is `true` with [`Error::Protocol`].
//!
//! # Pull
//!
//! The pull asks for files by their path, relative to the repository root.
//! The client sends `PullHello` with the highest pull version that it speaks,
//! [`PULL_PROTOCOL_VERSION`]. The server sends one of these replies:
//!
//! - `PullHelloReply` with the lower of the version of the client and the
//!   highest version of the server
//! - an `Error` message with the code `version-unsupported` for a version
//!   that the server does not speak. An ostrya server speaks each version
//!   from 1 to its highest, so it refuses only version 0.
//!
//! In version 1, `PullHelloReply` holds an empty dict. A decoder ignores a
//! key of `PullHello` or of `PullHelloReply` that it does not know.
//!
//! The client then sends `Get` frames. The server answers each `Get` with one
//! `GetReply`, in the order of the `Get` frames. A [`GetReply`] holds `found`
//! and, if the server knows it, the length of the body. The frame limit of
//! the pull is [`MIN_FRAME_LIMIT`] in both directions, and no message
//! announces another limit.
//!
//! A body follows a `GetReply` whose `found` is `true`. The body is a
//! sequence of chunks, as in the object stream. A chunk of length 0 ends the
//! body, and a chunk is at most the frame limit.
//!
//! The length [`ABANDON`] ends a body that fails partway. The next frame must
//! be an `Error` message, and any other frame is [`Error::Protocol`]. After
//! the marker, an object of the push takes `Abort`, and a body of the pull
//! takes an `Error` message.
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

mod frame;
mod message;

pub use frame::{FrameReader, FrameWriter, ObjectBody, ObjectRead};
pub(crate) use frame::{Step, encode_frame};
pub use message::{
    CommitRequest, ErrorMessage, GetReply, HaveReply, Hello, HelloReply, Message, ObjectHeader,
    ObjectsReply, PullHello, PullHelloReply,
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
    /// A body follows a reply whose `found` is `true`.
    GetReply = 15,
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
