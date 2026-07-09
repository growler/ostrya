use crate::codec::{TupleWriter, write_array};
use crate::de::MAX_VALUE_DEPTH;
use crate::{Error, GvEncode, Result, Type, Value};

/// Serialize `value` as type `ty` in GVariant normal form.
///
/// Framing offsets and multi-byte scalars are written little-endian, the
/// normal-form byte order on the little-endian targets ostree supports.
/// Fields the on-disk format defines as big-endian (uids, modes, timestamps)
/// are value-level conversions done by the caller before serialization.
pub fn to_bytes(ty: &Type, value: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    serialize(&mut buf, ty, value, 0)?;
    Ok(buf)
}

/// Serialize one value at the current buffer position.
///
/// Alignment is computed on absolute buffer positions: the top-level value
/// starts at 0 and every container is placed at a multiple of its own
/// alignment, which is at least each member's alignment, so absolute and
/// container-relative padding coincide.
///
/// `depth` counts container nesting as in the parser, sharing
/// [`MAX_VALUE_DEPTH`], so a value the serializer accepts is one the parser
/// accepts back.
fn serialize(buf: &mut Vec<u8>, ty: &Type, value: &Value, depth: usize) -> Result<()> {
    if depth > MAX_VALUE_DEPTH {
        return Err(Error::DepthExceeded);
    }
    match (ty, value) {
        // Scalar and string leaves share the encoding (and the interior-NUL
        // check) with the typed encoders; the `Value` path only unwraps.
        (Type::Bool, Value::Bool(b)) => b.encode(buf)?,
        (Type::Byte, Value::Byte(b)) => b.encode(buf)?,
        (Type::U32, Value::U32(x)) => x.encode(buf)?,
        (Type::U64, Value::U64(x)) => x.encode(buf)?,
        (Type::Str, Value::Str(s)) => s.as_str().encode(buf)?,
        (Type::Array(elem), Value::Bytes(b)) if **elem == Type::Byte => {
            b.as_slice().encode(buf)?;
        }
        (Type::Array(elem), Value::Array(items)) if **elem != Type::Byte => {
            serialize_array(buf, elem, items, depth)?;
        }
        (Type::Tuple(members), Value::Tuple(items)) => {
            serialize_struct(buf, ty, members.iter(), items, depth)?;
        }
        (Type::DictEntry(key, val), Value::Tuple(items)) => {
            serialize_struct(buf, ty, [&**key, &**val].into_iter(), items, depth)?;
        }
        (Type::Variant, Value::Variant(inner)) => {
            let (child_ty, child) = &**inner;
            // The buffer is 8-aligned here (variant alignment), which
            // satisfies any child alignment.
            serialize(buf, child_ty, child, depth + 1)?;
            buf.push(0);
            buf.extend_from_slice(child_ty.signature().as_bytes());
        }
        _ => {
            return Err(Error::TypeMismatch {
                expected: ty.signature(),
                found: value.kind(),
            });
        }
    }
    Ok(())
}

fn serialize_array(buf: &mut Vec<u8>, elem: &Type, items: &[Value], depth: usize) -> Result<()> {
    write_array(
        buf,
        elem.alignment(),
        elem.fixed_size().is_some(),
        items.len(),
        |buf, i| serialize(buf, elem, &items[i], depth + 1),
    )
}

/// Serialize a tuple or dict entry.
fn serialize_struct<'t>(
    buf: &mut Vec<u8>,
    whole: &Type,
    members: impl ExactSizeIterator<Item = &'t Type>,
    items: &[Value],
    depth: usize,
) -> Result<()> {
    let n = members.len();
    if items.len() != n {
        return Err(Error::TypeMismatch {
            expected: whole.signature(),
            found: "tuple of a different arity",
        });
    }
    if n == 0 {
        buf.push(0);
        return Ok(());
    }
    let mut writer = TupleWriter::new(buf);
    let last = n - 1;
    for (i, (member_ty, item)) in members.zip(items).enumerate() {
        writer.field_dyn(
            member_ty.alignment(),
            member_ty.fixed_size(),
            i == last,
            |buf| serialize(buf, member_ty, item, depth + 1),
        )?;
    }
    writer.finish(whole.fixed_size());
    Ok(())
}

/// The smallest offset size whose representable range covers the container's
/// total size (data plus the framing offsets themselves). The parser derives
/// the same size from the total, so both sides agree.
pub(crate) fn choose_offset_size(data_len: usize, n_offsets: usize) -> usize {
    for z in [1usize, 2, 4] {
        if data_len + n_offsets * z <= offset_max(z) {
            return z;
        }
    }
    8
}

pub(crate) fn offset_max(z: usize) -> usize {
    match z {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => usize::MAX,
    }
}

pub(crate) fn write_offset(buf: &mut Vec<u8>, value: usize, z: usize) {
    buf.extend_from_slice(&value.to_le_bytes()[..z]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ser(sig: &str, value: &Value) -> Vec<u8> {
        to_bytes(&Type::parse(sig).unwrap(), value).unwrap()
    }

    #[test]
    fn scalars() {
        assert_eq!(ser("y", &Value::Byte(0xab)), [0xab]);
        assert_eq!(ser("b", &Value::Bool(true)), [1]);
        assert_eq!(ser("b", &Value::Bool(false)), [0]);
        assert_eq!(ser("u", &Value::U32(0x0102_0304)), [4, 3, 2, 1]);
        assert_eq!(
            ser("t", &Value::U64(0x0102_0304_0506_0708)),
            [8, 7, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(ser("s", &Value::Str("hi".into())), b"hi\0");
    }

    #[test]
    fn dirmeta_layout() {
        // (uuua(ayay)) with uid 0, gid 0, mode big-endian 0o40755, no xattrs:
        // three fixed u32 members and an empty final array -- 12 bytes, no
        // framing offsets. Matches the golden dirmeta fixture bytes.
        let value = Value::Tuple(vec![
            Value::U32(0),
            Value::U32(0),
            Value::U32(0o40755u32.swap_bytes()),
            Value::Array(vec![]),
        ]);
        assert_eq!(
            ser("(uuua(ayay))", &value),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0xed]
        );
    }

    #[test]
    fn string_array_framing() {
        let value = Value::Array(vec!["foo".into(), "bar".into()]);
        assert_eq!(ser("as", &value), b"foo\0bar\0\x04\x08");
    }

    #[test]
    fn empty_containers() {
        assert_eq!(ser("as", &Value::Array(vec![])), Vec::<u8>::new());
        assert_eq!(ser("ay", &Value::Bytes(vec![])), Vec::<u8>::new());
        assert_eq!(ser("a{sv}", &Value::Array(vec![])), Vec::<u8>::new());
        assert_eq!(ser("()", &Value::Tuple(vec![])), [0]);
    }

    #[test]
    fn dict_with_one_entry() {
        // {"version": <"1">}: key "version\0" fills bytes 0..8 (the variant
        // member is 8-aligned), the variant is "1\0" + NUL + "s", the entry
        // framing offset is the key's end (8), and the array framing offset
        // is the entry's end (13).
        let entry = Value::Tuple(vec![
            "version".into(),
            Value::variant(Type::Str, "1".into()),
        ]);
        assert_eq!(
            ser("a{sv}", &Value::Array(vec![entry])),
            b"version\x001\0\0s\x08\x0d"
        );
    }

    #[test]
    fn variable_tuple_with_fixed_final_member() {
        // (su): the string end needs a framing offset, the trailing u32 does
        // not; padding to the u32 alignment separates them.
        let value = Value::Tuple(vec!["abc".into(), Value::U32(5)]);
        assert_eq!(ser("(su)", &value), b"abc\0\x05\0\0\0\x04");
    }

    #[test]
    fn fixed_element_array_packs_without_offsets() {
        let value = Value::Array(vec![
            Value::Tuple(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
            Value::Tuple(vec![Value::U32(4), Value::U32(5), Value::U32(6)]),
        ]);
        assert_eq!(
            ser("a(uuu)", &value),
            [
                1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0
            ]
        );
    }

    #[test]
    fn fixed_tuple_end_padding() {
        let value = Value::Tuple(vec![Value::U64(1), Value::Byte(2)]);
        assert_eq!(
            ser("(ty)", &value),
            [1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn two_byte_offsets_past_255_bytes() {
        // 30 nine-byte strings: 270 data bytes force 2-byte framing offsets,
        // so the array is 270 + 30 * 2 bytes.
        let items: Vec<Value> = (0..30)
            .map(|i| Value::Str(format!("string{i:02}")))
            .collect();
        let bytes = ser("as", &Value::Array(items));
        assert_eq!(bytes.len(), 270 + 60);
        // First framing offset: end of the first 9-byte element, 2 bytes LE.
        assert_eq!(&bytes[270..272], &9u16.to_le_bytes());
        // Last framing offset: end of the data area.
        assert_eq!(&bytes[328..330], &270u16.to_le_bytes());
    }

    #[test]
    fn rejects_value_depth_bomb() {
        // 129 nested variants exceed MAX_VALUE_DEPTH on the encode path.
        let mut value = Value::variant(Type::Byte, Value::Byte(1));
        for _ in 0..128 {
            value = Value::variant(Type::Variant, value);
        }
        let v = Type::parse("v").unwrap();
        assert_eq!(to_bytes(&v, &value), Err(Error::DepthExceeded));
    }

    #[test]
    fn rejects_interior_nul_in_string() {
        let err = to_bytes(&Type::parse("s").unwrap(), &Value::Str("a\0b".into())).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidValue("string contains an interior NUL byte")
        );
    }

    #[test]
    fn rejects_mismatched_value() {
        let err = to_bytes(&Type::parse("u").unwrap(), &Value::Str("x".into())).unwrap_err();
        assert!(matches!(err, Error::TypeMismatch { .. }));
        // ay must be Bytes, not Array of Byte.
        let err = to_bytes(
            &Type::parse("ay").unwrap(),
            &Value::Array(vec![Value::Byte(1)]),
        )
        .unwrap_err();
        assert!(matches!(err, Error::TypeMismatch { .. }));
        let err = to_bytes(
            &Type::parse("(uu)").unwrap(),
            &Value::Tuple(vec![Value::U32(1)]),
        )
        .unwrap_err();
        assert!(matches!(err, Error::TypeMismatch { .. }));
    }
}
