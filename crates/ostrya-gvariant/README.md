# ostrya-gvariant

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

A byte-exact GVariant codec for the ostree on-disk format.

A caller writes values as GVariant bytes in normal form and reads them
back. The checksum of each ostree metadata object is the hash of these
bytes, so each metadata checksum of ostrya depends on this crate. The
typed codec reads fields in place with no allocation. The crate has no
ostree knowledge.

API documentation: <https://docs.rs/ostrya-gvariant>

## Entry points

- `Type::parse` reads a type signature.
- `to_bytes` writes a `Value` as normal-form bytes.
- `from_bytes` reads normal-form bytes as a `Value`.
- `GvEncode` writes a Rust type as normal-form bytes.
- `GvDecode` reads a Rust type in place from normal-form bytes.
- `to_text` writes the GVariant text form of a value.
- `from_text` reads the GVariant text form.
- `DictBuilder` builds an `a{sv}` dict.

## Examples

```rust
use ostrya_gvariant::{Type, Value, from_bytes, to_bytes};

let ty = Type::parse("(su)")?;
let value = Value::Tuple(vec![Value::from("ostree"), Value::from(7u32)]);
let bytes = to_bytes(&ty, &value)?;
// The string, one padding byte, the `u`, and the framing offset 7.
assert_eq!(bytes, b"ostree\0\0\x07\0\0\0\x07");
assert_eq!(from_bytes(&ty, &bytes)?, value);
```
