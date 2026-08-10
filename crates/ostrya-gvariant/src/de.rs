use crate::codec::{ArrayReader, TupleReader};
use crate::ser::offset_max;
use crate::{Error, GvDecode, Result, Type, Value};

/// Maximum value nesting depth. Nested variants let value nesting exceed the
/// static depth of the type signature, so the parser and the serializer carry
/// their own limit.
pub(crate) const MAX_VALUE_DEPTH: usize = 128;

/// Deserialize normal-form GVariant bytes as `ty`.
///
/// The parser is strict: any deviation from normal form (nonzero padding,
/// unterminated or non-UTF-8 strings, out-of-order framing offsets, trailing
/// bytes) is an error. A successful parse therefore re-serializes to the
/// identical bytes, which is what object checksumming relies on.
pub fn from_bytes(ty: &Type, data: &[u8]) -> Result<Value> {
    parse(ty, data, 0)
}

fn parse(ty: &Type, data: &[u8], depth: usize) -> Result<Value> {
    if depth > MAX_VALUE_DEPTH {
        return Err(Error::DepthExceeded);
    }
    match ty {
        // Scalar and string leaves share the strict checks with the typed
        // decoders; the `Value` path only wraps their results.
        Type::Bool => Ok(Value::Bool(bool::decode(data)?)),
        Type::Byte => Ok(Value::Byte(u8::decode(data)?)),
        Type::I16 => Ok(Value::I16(i16::from_le_bytes(exact::<2>(data)?))),
        Type::U16 => Ok(Value::U16(u16::from_le_bytes(exact::<2>(data)?))),
        Type::I32 | Type::Handle => Ok(Value::I32(i32::from_le_bytes(exact::<4>(data)?))),
        Type::U32 => Ok(Value::U32(u32::decode(data)?)),
        Type::I64 => Ok(Value::I64(i64::from_le_bytes(exact::<8>(data)?))),
        Type::U64 => Ok(Value::U64(u64::decode(data)?)),
        Type::Double => Ok(Value::Double(u64::from_le_bytes(exact::<8>(data)?))),
        Type::Str | Type::ObjectPath | Type::Signature => {
            Ok(Value::Str(<&str>::decode(data)?.to_owned()))
        }
        Type::Maybe(elem) => parse_maybe(elem, data, depth),
        Type::Array(elem) if **elem == Type::Byte => Ok(Value::Bytes(data.to_vec())),
        Type::Array(elem) => parse_array(elem, data, depth),
        Type::Tuple(members) => parse_struct(ty, members.iter(), data, depth),
        Type::DictEntry(key, value) => {
            parse_struct(ty, [&**key, &**value].into_iter(), data, depth)
        }
        Type::Variant => {
            let (child, _, child_ty) = split_variant(data)?;
            let value = parse(&child_ty, child, depth + 1)?;
            Ok(Value::variant(child_ty, value))
        }
    }
}

/// Upper bound on the element count preallocated for an array before any
/// element is validated. The count comes straight from the input length (one
/// element per byte for fixed-size elements), so capping it keeps hostile
/// input from forcing an allocation proportional to its own size; a genuinely
/// large valid array still grows amortized past the cap.
const ARRAY_PREALLOC_CAP: usize = 4096;

/// Parse `m<T>`: no bytes is `Nothing`, and any other input is `Just`, whose
/// element bytes are the whole input for a fixed-size element and the input
/// less its trailing zero byte for a variable-size one.
fn parse_maybe(elem: &Type, data: &[u8], depth: usize) -> Result<Value> {
    if data.is_empty() {
        return Ok(Value::Maybe(None));
    }
    let child = if elem.fixed_size().is_some() {
        data
    } else {
        match data.split_last() {
            Some((0, rest)) => rest,
            _ => return Err(Error::NotNormal("maybe lacks its terminating zero byte")),
        }
    };
    Ok(Value::Maybe(Some(Box::new(parse(elem, child, depth + 1)?))))
}

fn parse_array(elem: &Type, data: &[u8], depth: usize) -> Result<Value> {
    let mut reader = ArrayReader::new(data, elem.alignment(), elem.fixed_size())?;
    let mut items = Vec::with_capacity(reader.len().min(ARRAY_PREALLOC_CAP));
    while let Some(slice) = reader.next_slice() {
        items.push(parse(elem, slice?, depth + 1)?);
    }
    Ok(Value::Array(items))
}

fn parse_struct<'t>(
    whole: &Type,
    members: impl ExactSizeIterator<Item = &'t Type> + Clone,
    data: &[u8],
    depth: usize,
) -> Result<Value> {
    let n = members.len();
    if n == 0 {
        if data != [0] {
            return Err(Error::NotNormal("empty tuple is not a single zero byte"));
        }
        return Ok(Value::Tuple(Vec::new()));
    }
    // Framing offsets cover variable-size members other than the last member.
    let n_offsets = members
        .clone()
        .take(n - 1)
        .filter(|m| m.fixed_size().is_none())
        .count();
    let mut reader = TupleReader::new(data, n_offsets, whole.fixed_size())?;
    let mut items = Vec::with_capacity(n);
    let last = n - 1;
    for (i, member_ty) in members.enumerate() {
        let slice = reader.field(member_ty.alignment(), member_ty.fixed_size(), i == last)?;
        items.push(parse(member_ty, slice, depth + 1)?);
    }
    reader.finish()?;
    Ok(Value::Tuple(items))
}

pub(crate) fn exact<const N: usize>(data: &[u8]) -> Result<[u8; N]> {
    data.try_into()
        .map_err(|_| Error::NotNormal("scalar has the wrong size"))
}

/// Split a serialized variant into its child bytes, the borrowed signature
/// bytes, and the parsed child type. Shared by the `Value` and typed decoders.
pub(crate) fn split_variant(data: &[u8]) -> Result<(&[u8], &[u8], Type)> {
    let Some(sep) = data.iter().rposition(|&b| b == 0) else {
        return Err(Error::NotNormal("variant lacks a type separator"));
    };
    let signature = &data[sep + 1..];
    let sig = std::str::from_utf8(signature)
        .map_err(|_| Error::NotNormal("variant type signature is not UTF-8"))?;
    let ty = Type::parse(sig).map_err(|_| Error::NotNormal("variant type signature is invalid"))?;
    Ok((&data[..sep], signature, ty))
}

pub(crate) fn check_padding(padding: &[u8]) -> Result<()> {
    if padding.iter().any(|&b| b != 0) {
        return Err(Error::NotNormal("padding bytes are not zero"));
    }
    Ok(())
}

/// The framing-offset size implied by a container's total serialized size.
pub(crate) fn offset_size_for(len: usize) -> usize {
    for z in [1usize, 2, 4] {
        if len <= offset_max(z) {
            return z;
        }
    }
    8
}

pub(crate) fn read_offset(bytes: &[u8], z: usize) -> usize {
    let mut buf = [0u8; 8];
    buf[..z].copy_from_slice(bytes);
    u64::from_le_bytes(buf) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::to_bytes;

    fn round_trip(sig: &str, value: &Value) {
        let ty = Type::parse(sig).unwrap();
        let bytes = to_bytes(&ty, value).unwrap();
        let parsed = from_bytes(&ty, &bytes).unwrap();
        assert_eq!(&parsed, value, "value round-trip for {sig}");
        assert_eq!(
            to_bytes(&ty, &parsed).unwrap(),
            bytes,
            "byte round-trip for {sig}"
        );
    }

    fn checksum_bytes(seed: u8) -> Value {
        Value::Bytes((0..32).map(|i| seed.wrapping_add(i)).collect())
    }

    #[test]
    fn round_trips_scalars_and_simple_containers() {
        round_trip("y", &Value::Byte(7));
        round_trip("b", &Value::Bool(true));
        round_trip("u", &Value::U32(0xdead_beef));
        round_trip("t", &Value::U64(0x0123_4567_89ab_cdef));
        round_trip("s", &Value::Str("héllo wörld".into()));
        round_trip("ay", &Value::Bytes(vec![0, 1, 2, 0, 4]));
        round_trip(
            "as",
            &Value::Array(vec!["a".into(), "".into(), "ccc".into()]),
        );
        round_trip(
            "aay",
            &Value::Array(vec![Value::Bytes(vec![]), Value::Bytes(vec![1, 2])]),
        );
        round_trip("v", &Value::variant(Type::Str, "nested".into()));
        round_trip(
            "v",
            &Value::variant(
                Type::parse("v").unwrap(),
                Value::variant(Type::U32, Value::U32(5)),
            ),
        );
    }

    /// The types outside the on-disk format, which `commit --add-metadata`
    /// writes into a commit's metadata dict.
    #[test]
    fn round_trips_the_metadata_only_types() {
        round_trip("n", &Value::I16(-5));
        round_trip("q", &Value::U16(5));
        round_trip("i", &Value::I32(-42));
        round_trip("h", &Value::I32(7));
        round_trip("x", &Value::I64(-5));
        round_trip("d", &Value::double(1.5));
        round_trip("o", &Value::Str("/a/b".into()));
        round_trip("g", &Value::Str("ay".into()));
        round_trip("ms", &Value::Maybe(None));
        round_trip("ms", &Value::Maybe(Some(Box::new(Value::Str("x".into())))));
        round_trip(
            "ms",
            &Value::Maybe(Some(Box::new(Value::Str(String::new())))),
        );
        round_trip("mi", &Value::Maybe(None));
        round_trip("mi", &Value::Maybe(Some(Box::new(Value::I32(3)))));
        round_trip(
            "ami",
            &Value::Array(vec![
                Value::Maybe(Some(Box::new(Value::I32(1)))),
                Value::Maybe(None),
            ]),
        );
        round_trip(
            "(sid)",
            &Value::Tuple(vec![
                Value::Str("a".into()),
                Value::I32(5),
                Value::double(-0.5),
            ]),
        );
    }

    /// A maybe of a variable-size element ends in one zero byte, which is what
    /// tells `Just ""` from `Nothing`.
    #[test]
    fn maybe_framing() {
        let ty = Type::parse("ms").unwrap();
        assert_eq!(
            to_bytes(&ty, &Value::Maybe(None)).unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(
            to_bytes(
                &ty,
                &Value::Maybe(Some(Box::new(Value::Str(String::new()))))
            )
            .unwrap(),
            [0, 0]
        );
        assert_eq!(
            from_bytes(&ty, &[]).unwrap(),
            Value::Maybe(None),
            "no bytes is Nothing"
        );
        assert!(from_bytes(&ty, &[1]).is_err(), "a missing terminator");
    }

    #[test]
    fn round_trips_commit_shaped_value() {
        // (a{sv}aya(say)sstayay) with representative metadata.
        let metadata = Value::Array(vec![
            Value::Tuple(vec![
                "ostree.ref-binding".into(),
                Value::variant(
                    Type::parse("as").unwrap(),
                    Value::Array(vec!["test/main".into()]),
                ),
            ]),
            Value::Tuple(vec![
                "version".into(),
                Value::variant(Type::Str, "1.0".into()),
            ]),
        ]);
        let commit = Value::Tuple(vec![
            metadata,
            Value::Bytes(vec![]), // root commit: no parent
            Value::Array(vec![]), // related objects
            "subject".into(),
            "".into(),
            Value::U64(1_700_000_000u64.swap_bytes()),
            checksum_bytes(0x10),
            checksum_bytes(0x50),
        ]);
        round_trip("(a{sv}aya(say)sstayay)", &commit);
    }

    #[test]
    fn round_trips_summary_shaped_value() {
        // (a(s(taya{sv}))a{sv}) with one ref entry and global metadata.
        let ref_meta = Value::Array(vec![Value::Tuple(vec![
            "ostree.commit.timestamp".into(),
            Value::variant(Type::U64, Value::U64(1_700_000_000u64.swap_bytes())),
        ])]);
        let refs = Value::Array(vec![Value::Tuple(vec![
            "test/main".into(),
            Value::Tuple(vec![Value::U64(431), checksum_bytes(0x30), ref_meta]),
        ])]);
        let global = Value::Array(vec![Value::Tuple(vec![
            "ostree.summary.mode".into(),
            Value::variant(Type::Str, "bare".into()),
        ])]);
        round_trip("(a(s(taya{sv}))a{sv})", &Value::Tuple(vec![refs, global]));
    }

    #[test]
    fn round_trips_delta_shaped_values() {
        let meta_entry = Value::Tuple(vec![
            Value::U32(0),
            checksum_bytes(0x60),
            Value::U64(4096),
            Value::U64(8192),
            Value::Bytes(vec![1; 33]),
        ]);
        round_trip("(uayttay)", &meta_entry);

        let fallback = Value::Tuple(vec![
            Value::Byte(1),
            checksum_bytes(0x70),
            Value::U64(100),
            Value::U64(200),
        ]);
        round_trip("(yaytt)", &fallback);

        let modes = Value::Array(vec![Value::Tuple(vec![
            Value::U32(0o100644u32.swap_bytes()),
            Value::U32(0),
            Value::U32(0),
        ])]);
        let xattrs = Value::Array(vec![Value::Array(vec![])]);
        let part = Value::Tuple(vec![
            modes,
            xattrs,
            Value::Bytes(vec![0xaa; 40]),
            Value::Bytes(vec![b'S', 0x01]),
        ]);
        round_trip("(a(uuu)aa(ayay)ayay)", &part);
    }

    #[test]
    fn round_trips_offset_size_boundaries() {
        for n in [250usize, 255, 256, 300, 70_000] {
            let value = Value::Array(vec![Value::Bytes(vec![0x5a; n])]);
            round_trip("aay", &value);
        }
    }

    #[test]
    fn array_length_does_not_drive_preallocation() {
        // A large all-0xFF `ab` buffer names one bool element per byte. The
        // first element fails to decode, so parsing returns an error; the
        // untrusted element count must not drive a preallocation proportional
        // to it before any element is validated (bound checked in
        // `parse_array`; the ratio is enforced by inspection there).
        let data = vec![0xffu8; 1 << 20];
        assert_eq!(
            from_bytes(&Type::parse("ab").unwrap(), &data),
            Err(Error::NotNormal("boolean is not 0 or 1"))
        );
    }

    #[test]
    fn rejects_bad_scalars() {
        let u = Type::parse("u").unwrap();
        assert!(from_bytes(&u, &[1, 2, 3]).is_err());
        assert!(from_bytes(&u, &[1, 2, 3, 4, 5]).is_err());
        let b = Type::parse("b").unwrap();
        assert_eq!(
            from_bytes(&b, &[2]),
            Err(Error::NotNormal("boolean is not 0 or 1"))
        );
    }

    #[test]
    fn rejects_bad_strings() {
        let s = Type::parse("s").unwrap();
        assert!(from_bytes(&s, b"abc").is_err()); // no terminator
        assert!(from_bytes(&s, b"a\0b\0").is_err()); // interior NUL
        assert!(from_bytes(&s, &[0xff, 0xfe, 0]).is_err()); // not UTF-8
        assert!(from_bytes(&s, b"").is_err()); // empty
    }

    #[test]
    fn rejects_nonzero_padding() {
        // (su) with "abcd": bytes 5..8 are alignment padding for the u32.
        let ty = Type::parse("(su)").unwrap();
        let good = to_bytes(&ty, &Value::Tuple(vec!["abcd".into(), Value::U32(9)])).unwrap();
        assert!(from_bytes(&ty, &good).is_ok());
        let mut bad = good.clone();
        bad[6] = 1;
        assert_eq!(
            from_bytes(&ty, &bad),
            Err(Error::NotNormal("padding bytes are not zero"))
        );
    }

    #[test]
    fn rejects_malformed_array_framing() {
        let ty = Type::parse("as").unwrap();
        // Framing offset points past the framing area.
        assert!(from_bytes(&ty, &[b'a', 0, 3]).is_err());
        // Element without a NUL terminator carved out by the offsets.
        assert!(from_bytes(&ty, &[b'a', 0, 1, 2]).is_err());
        // Fixed-element array with a partial element.
        let au = Type::parse("au").unwrap();
        assert!(from_bytes(&au, &[0; 6]).is_err());
    }

    #[test]
    fn rejects_malformed_tuples() {
        let empty = Type::parse("()").unwrap();
        assert!(from_bytes(&empty, &[0]).is_ok());
        assert!(from_bytes(&empty, &[1]).is_err());
        assert!(from_bytes(&empty, &[]).is_err());
        assert!(from_bytes(&empty, &[0, 0]).is_err());
        // Fixed-size tuple with trailing garbage.
        let uuu = Type::parse("(uuu)").unwrap();
        assert!(from_bytes(&uuu, &[0; 13]).is_err());
        // Variable tuple whose members do not reach the framing area.
        let su = Type::parse("(su)").unwrap();
        assert!(from_bytes(&su, b"a\0\0\0\x05\0\0\0\0\0\x02").is_err());
    }

    #[test]
    fn rejects_malformed_variants() {
        let v = Type::parse("v").unwrap();
        assert!(from_bytes(&v, b"").is_err()); // empty
        assert!(from_bytes(&v, b"ab").is_err()); // no separator
        assert!(from_bytes(&v, b"a\0d").is_err()); // unsupported child type
        assert!(from_bytes(&v, b"\0").is_err()); // empty signature
    }

    #[test]
    fn rejects_variant_depth_bomb() {
        // 129 nested variants, built by hand since the serializer rejects
        // values this deep: innermost byte, then one signature per wrapper.
        let ty = Type::parse("v").unwrap();
        let mut bytes = vec![1u8, 0, b'y'];
        for _ in 0..128 {
            bytes.push(0);
            bytes.push(b'v');
        }
        assert_eq!(from_bytes(&ty, &bytes), Err(Error::DepthExceeded));

        // 128 nested variants sit exactly at the limit and round-trip; one
        // more wrapper fails identically on the encode path.
        let mut value = Value::variant(Type::Byte, Value::Byte(1));
        for _ in 0..127 {
            value = Value::variant(Type::Variant, value);
        }
        let ok = to_bytes(&ty, &value).unwrap();
        assert_eq!(from_bytes(&ty, &ok).unwrap(), value);
        let bomb = Value::variant(Type::Variant, value);
        assert_eq!(to_bytes(&ty, &bomb), Err(Error::DepthExceeded));
    }
}
