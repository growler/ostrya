#![forbid(unsafe_code)]

//! A byte-exact GVariant codec for the ostree on-disk format.
//!
//! A caller writes values as GVariant bytes in normal form and reads them
//! back. The checksum of each ostree metadata object is the hash of these
//! bytes, so each metadata checksum of ostrya depends on this crate. The
//! typed codec reads fields in place with no allocation. The crate has no
//! ostree knowledge.
//!
//! # Entry points
//!
//! - [`Type::parse`] reads a type signature.
//! - [`to_bytes`] writes a [`Value`] as normal-form bytes.
//! - [`from_bytes`] reads normal-form bytes as a [`Value`].
//! - [`GvEncode`] writes a Rust type as normal-form bytes.
//! - [`GvDecode`] reads a Rust type in place from normal-form bytes.
//! - [`to_text`] writes the GVariant text form of a value.
//! - [`from_text`] reads the GVariant text form.
//! - [`DictBuilder`] builds an `a{sv}` dict.
//!
//! # Examples
//!
//! ```
//! use ostrya_gvariant::{Type, Value, from_bytes, to_bytes};
//!
//! let ty = Type::parse("(su)")?;
//! let value = Value::Tuple(vec![Value::from("ostree"), Value::from(7u32)]);
//! let bytes = to_bytes(&ty, &value)?;
//! // The string, one padding byte, the `u`, and the framing offset 7.
//! assert_eq!(bytes, b"ostree\0\0\x07\0\0\0\x07");
//! assert_eq!(from_bytes(&ty, &bytes)?, value);
//! # Ok::<(), ostrya_gvariant::Error>(())
//! ```

mod codec;
mod de;
mod dict;
mod error;
mod print;
mod ser;
mod text;
mod ty;
mod value;

pub use codec::{
    ArrayIter, GvDecode, GvEncode, GvType, Slice, Variant, VariantBytes, encode_to_vec, write_array,
};
pub use de::{from_bytes, offset_size_for, tuple_field_from_bytes, validate};
pub use dict::DictBuilder;
pub use error::{Error, Result};
pub use print::{to_text, to_text_unannotated};
pub use ser::{choose_offset_size, to_bytes, write_offset};
pub use text::{Span, TextError, from_text};
pub use ty::Type;
pub use value::Value;
