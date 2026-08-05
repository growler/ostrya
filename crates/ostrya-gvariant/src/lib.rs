#![forbid(unsafe_code)]

//! Byte-exact GVariant codec for the ostree on-disk format.
//!
//! This crate has no ostree knowledge. It serializes and deserializes the
//! fixed set of GVariant type signatures ostree uses, in GVariant normal
//! form. The checksum of every metadata object is the hash of these bytes,
//! so byte exactness here is the bedrock for every downstream phase.
//!
//! The supported types are booleans (`b`), bytes (`y`), 32- and 64-bit
//! unsigned integers (`u`, `t`), strings (`s`), variants (`v`), arrays,
//! tuples, and dict entries. [`Type::parse`] rejects everything else.
//!
//! Byte order: framing offsets and multi-byte scalars are written
//! little-endian, the normal-form byte order on the little-endian targets
//! ostree supports. The fields the on-disk format defines as big-endian
//! (uids, gids, modes, timestamps, sizes) are value-level conversions
//! performed by the caller before serialization and after deserialization.
//!
//! [`from_bytes`] is strict: it accepts only normal-form input, so a
//! successful parse re-serializes with [`to_bytes`] to the identical bytes.

mod codec;
mod de;
mod error;
mod print;
mod ser;
mod ty;
mod value;

pub use codec::{
    ArrayIter, GvDecode, GvEncode, GvType, Slice, Variant, encode_to_vec, write_array,
};
pub use de::from_bytes;
pub use error::{Error, Result};
pub use print::to_text;
pub use ser::{choose_offset_size, to_bytes, write_offset};
pub use ty::Type;
pub use value::Value;
