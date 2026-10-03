//! The push wire protocol: messages, frames, and the object stream.
//!
//! # Frames
//!
//! The peers exchange frames. A frame is:
//!
//! ```text
//! u32   length, big-endian, of the bytes that follow (kind byte + body)
//! u8    message kind
//! ...   GVariant body, normal form, of the type the kind names
//! ```
//!
//! A frame length of 0 is the error `protocol`, because a frame holds at
//! least the kind byte. A frame length greater than the current limit is the
//! error `limit-exceeded`. The reader checks the length before it reads or
//! allocates the body. Before the server announces a limit, the limit is
//! [`MIN_FRAME_LIMIT`]. The server announces its limit as `max-frame` in
//! `HelloReply`, and an announced limit is in
//! `MIN_FRAME_LIMIT..=MAX_FRAME_LIMIT`. The limit applies in both directions.
//! A client writes frames up to the announced limit, and reads frames up to
//! a limit of its own, because the reader allocates each frame body in full.
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
//!
//! A kind that is not in the list is the error `protocol`. A body that is
//! not in normal form for its type, or that has trailing bytes, is the error
//! `protocol`. A non-empty `ObjectsEnd` body, or an `Abort` body other than
//! `0x00`, is the error `protocol`.
//!
//! The integers in a message body are little-endian, which is the GVariant
//! normal form. The protocol applies no value-level byte swap. The frame
//! length and the chunk length are big-endian.
//!
//! Every checksum in a body is an `ay` of exactly 32 bytes. Another length is
//! the error `protocol`. An `a{sv}` key that the decoder does not know is
//! ignored. A known key whose value has the wrong type is the error
//! `protocol`. When a key occurs twice, the first one counts.
//!
//! # Object stream
//!
//! After an `ObjectHeader` frame, the bytes of the object follow as chunks.
//! A chunk is not a frame:
//!
//! ```text
//! u32   length, big-endian
//! ...   that number of object bytes
//! ```
//!
//! - A chunk of length 0 ends the object. Frames follow again: the next
//!   `ObjectHeader`, or `ObjectsEnd`, which closes the stream.
//! - The length [`ABANDON`] (`0xFFFFFFFF`) abandons the object. The next frame
//!   must be `Abort`. Any other frame is the error `protocol`.
//! - Any other length greater than the current limit is the error
//!   `limit-exceeded`. The chunk limit and the frame limit are the same
//!   number. [`MAX_FRAME_LIMIT`] is one below the abandon marker, so a chunk
//!   length never equals the marker.
//!
//! The object type in `ObjectHeader` is 1 (file), 2 (dirtree), 3 (dirmeta),
//! 4 (commit), or 6 (detached commit metadata). For type 6 the checksum is
//! the checksum of the commit that the metadata belongs to. The encoding is
//! 0 (`raw`) or 1 (`deflate`), and `deflate` is allowed for type 1 alone.
//! `Have` names types 1 to 4 alone.
//!
//! [`FrameReader`] and [`FrameWriter`] implement the frames and the object
//! stream over the `futures-io` traits. Object bytes pass through a buffer
//! of the caller in bounded pieces, so no call holds a whole object.
//! [`ObjectBody`] presents the bytes of one object as an `AsyncRead`.

mod frame;
mod message;

pub(crate) use frame::encode_frame;
pub use frame::{FrameReader, FrameWriter, ObjectBody, ObjectRead};
pub use message::{
    CommitRequest, ErrorMessage, HaveReply, Hello, HelloReply, Message, ObjectHeader, ObjectsReply,
};

use ostrya_core::{Checksum, ObjectName, ObjectType};
use ostrya_gvariant::Value;

use crate::error::{Error, Result};

/// The protocol version this crate speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// The frame limit before the server announces one, the lowest limit a
/// server may announce, and the limit of a stream that carries no
/// announcement.
pub const MIN_FRAME_LIMIT: u32 = 1 << 20;

/// The `max-frame` value the port server announces: 1 MiB.
///
/// Object bytes travel as chunks, so a frame carries metadata messages
/// alone. The largest bounded one is a `Have` of [`MAX_HAVE`] entries, with
/// a frame length of 606,209 bytes. `Hello`, `HelloReply`, `Commit`, and
/// `Error` hold lists with no count limit, so the frame limit alone bounds
/// them. A chunk can be as long as the limit, so the framing costs 4 bytes
/// for each MiB of object data.
///
/// The reader allocates a frame body in full, and the decoder then keeps the
/// body and the decoded message together. Measured on 1 MiB frames, the peak
/// is 2 times the frame for a `Have`, 12 times for a `HelloReply` of refs
/// with empty names, and 13 times for a `Commit` of ref updates with empty
/// names. The decoder checks a dict value under a key it does not know
/// through a value tree that it then drops. A `Hello` whose one unknown key
/// holds an `ab` of 1 MiB peaks at 49 times the frame. The peak grows in
/// proportion to the limit.
pub const MAX_FRAME: u32 = 1 << 20;

/// The `max-have` value the port server announces: 16,384 entries.
///
/// A `Have` entry is 33 bytes plus a 4-byte offset, so a `Have` of 16,384
/// entries has a frame length of 606,209 bytes, which fits in
/// [`MAX_FRAME`]. 32,768 entries do not fit. A full `HaveReply` is then
/// 2,048 bytes.
pub const MAX_HAVE: u32 = 16_384;

/// The chunk length that abandons an object.
pub const ABANDON: u32 = 0xFFFF_FFFF;

/// The highest valid frame limit. It is one below [`ABANDON`], so a chunk
/// length that the limit allows never equals the abandon marker.
pub const MAX_FRAME_LIMIT: u32 = 0xFFFF_FFFE;

/// A message kind: the byte after the frame length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    /// `Hello`, client to server.
    Hello = 1,
    /// `HelloReply`, server to client.
    HelloReply = 2,
    /// `Have`, client to server.
    Have = 3,
    /// `HaveReply`, server to client.
    HaveReply = 4,
    /// `ObjectHeader`, client to server. Object chunks follow it.
    ObjectHeader = 5,
    /// `ObjectsEnd`, client to server. It closes the object stream.
    ObjectsEnd = 6,
    /// `ObjectsReply`, server to client.
    ObjectsReply = 7,
    /// `Commit`, client to server.
    Commit = 8,
    /// `CommitReply`, server to client.
    CommitReply = 9,
    /// `Error`, server to client.
    Error = 10,
    /// `Abort`, client to server.
    Abort = 11,
}

impl Kind {
    /// The kind of a kind byte. A byte that is not a kind is the error
    /// `protocol`.
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
            _ => return Err(protocol(format!("unknown message kind {byte}"))),
        })
    }

    /// The kind byte.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The encoding of an object in the object stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// The uncompressed object bytes: for a content object, the framed file
    /// header and the payload.
    Raw,
    /// A content object in the compressed form of an archive repository.
    Deflate,
}

impl Encoding {
    /// The wire byte: 0 for `raw`, 1 for `deflate`.
    pub fn as_u8(self) -> u8 {
        match self {
            Encoding::Raw => 0,
            Encoding::Deflate => 1,
        }
    }

    /// The encoding of a wire byte. Another byte is the error `protocol`.
    pub fn from_u8(byte: u8) -> Result<Encoding> {
        match byte {
            0 => Ok(Encoding::Raw),
            1 => Ok(Encoding::Deflate),
            _ => Err(protocol(format!("unknown encoding {byte}"))),
        }
    }

    /// The name in the `encodings` list of `HelloReply`.
    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Raw => "raw",
            Encoding::Deflate => "deflate",
        }
    }

    /// The encoding of a name, or `None` for a name that is not an encoding.
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
    /// The commit of the ref, or `None` when the ref is absent.
    pub commit: Option<Checksum>,
}

/// The state a ref update expects the ref to be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    /// The ref is absent. Wire state 0.
    Absent,
    /// The ref points at this commit. Wire state 1.
    Commit(Checksum),
    /// The ref is in any state. Wire state 2.
    Any,
}

/// One ref update of a `Commit` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    /// The ref name: `NAME` or `REMOTE:NAME`.
    pub name: String,
    /// The state the ref must be in before the write.
    pub expected: Expected,
    /// The new commit, or `None` to delete the ref.
    pub new: Option<Checksum>,
}

/// The result of one ref update in `CommitReply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefOutcome {
    /// The ref name.
    pub name: String,
    /// The commit before the write, or `None` when the ref was absent.
    pub old: Option<Checksum>,
    /// The commit after the write, or `None` when the ref is now absent.
    pub new: Option<Checksum>,
}

pub(crate) fn protocol(msg: impl Into<String>) -> Error {
    Error::Protocol(msg.into())
}

/// A checksum from an `ay` of 32 bytes.
fn checksum(bytes: &[u8]) -> Result<Checksum> {
    Checksum::from_ay(bytes).map_err(|_| protocol("checksum is not 32 bytes"))
}

fn checksum_value(c: &Checksum) -> Value {
    Value::Bytes(c.as_bytes().to_vec())
}

fn maybe_value(c: Option<Checksum>) -> Value {
    Value::Maybe(c.map(|c| Box::new(checksum_value(&c))))
}

/// An object name from a `(y, ay)` pair whose type `allowed` accepts.
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

/// The most entries of a `Have` whose frame fits in `limit`. The frame
/// length counts the kind byte and the body. Fewer entries make a shorter
/// frame.
pub(crate) fn have_entries_within(limit: u32) -> u32 {
    (limit - 1) / HAVE_ENTRY_LEN
}

/// The types a `Have` entry or a `missing` entry may name: 1 to 4.
pub(crate) fn have_type(ty: ObjectType) -> bool {
    matches!(
        ty,
        ObjectType::File | ObjectType::DirTree | ObjectType::DirMeta | ObjectType::Commit
    )
}

/// The types an `ObjectHeader` may name: 1 to 4 and 6.
fn header_type(ty: ObjectType) -> bool {
    have_type(ty) || ty == ObjectType::CommitMeta
}
