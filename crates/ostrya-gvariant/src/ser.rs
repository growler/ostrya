use crate::codec::{TupleWriter, write_array};
use crate::de::MAX_VALUE_DEPTH;
use crate::{Error, GvEncode, Result, Type, Value};

/// Serializes `value` as type `ty` in GVariant normal form.
///
/// The serializer writes framing offsets and multi-byte scalars in
/// little-endian byte order. This is the normal-form byte order on the
/// little-endian targets that ostree supports.
///
/// The on-disk format defines some fields as big-endian: uids, gids, modes,
/// timestamps, and sizes. The caller converts the values of these fields
/// before serialization.
///
/// # Errors
///
/// - [`Error::TypeMismatch`] if `value` does not match `ty`. This includes a
///   tuple or a dict entry with a different number of members. It also
///   includes a [`Value::Array`] of [`Value::Byte`] for the type `ay`, which
///   needs [`Value::Bytes`].
/// - [`Error::InvalidValue`] if a [`Value::Str`] holds an interior NUL byte.
/// - [`Error::DepthExceeded`] if `value` nests deeper than the
///   [depth limit](#depth-limit).
///
/// # Depth limit
///
/// A leaf can sit under at most 128 levels of containers. Each variant,
/// array, maybe, tuple, and dict entry adds one level. A value of type `v`
/// with 128 nested variants serializes. A value with 129 nested variants
/// returns [`Error::DepthExceeded`].
///
/// [`from_bytes`] has the same limit, so it accepts each value that
/// `to_bytes` accepts.
///
/// [`from_bytes`]: crate::from_bytes
pub fn to_bytes(ty: &Type, value: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    serialize(&mut buf, ty, value, 0)?;
    Ok(buf)
}

/// Serializes one value at the current buffer position.
///
/// The function computes alignment from absolute buffer positions. The
/// top-level value starts at 0. Each container starts at a multiple of its
/// own alignment. That alignment is at least the alignment of each member,
/// so the absolute padding and the container-relative padding are equal.
///
/// `depth` counts container nesting the same way as the parser. Both use
/// [`MAX_VALUE_DEPTH`], so the parser accepts each value that the serializer
/// accepts.
fn serialize(buf: &mut Vec<u8>, ty: &Type, value: &Value, depth: usize) -> Result<()> {
    if depth > MAX_VALUE_DEPTH {
        return Err(Error::DepthExceeded);
    }
    match (ty, value) {
        // Scalar and string leaves use the encoding of the typed encoders.
        // That encoding includes the interior-NUL check. The `Value` path
        // only unwraps the leaf.
        (Type::Bool, Value::Bool(b)) => b.encode(buf)?,
        (Type::Byte, Value::Byte(b)) => b.encode(buf)?,
        (Type::I16, Value::I16(x)) => buf.extend_from_slice(&x.to_le_bytes()),
        (Type::U16, Value::U16(x)) => buf.extend_from_slice(&x.to_le_bytes()),
        (Type::I32 | Type::Handle, Value::I32(x)) => buf.extend_from_slice(&x.to_le_bytes()),
        (Type::U32, Value::U32(x)) => x.encode(buf)?,
        (Type::I64, Value::I64(x)) => buf.extend_from_slice(&x.to_le_bytes()),
        (Type::U64, Value::U64(x)) => x.encode(buf)?,
        (Type::Double, Value::Double(bits)) => buf.extend_from_slice(&bits.to_le_bytes()),
        (Type::Str | Type::ObjectPath | Type::Signature, Value::Str(s)) => {
            s.as_str().encode(buf)?;
        }
        (Type::Maybe(elem), Value::Maybe(inner)) => {
            // `Nothing` is the empty byte sequence. `Just` is the bytes of the
            // element. If the element is variable-size, one zero byte follows
            // the element bytes. This byte tells `Nothing` and `Just` apart.
            if let Some(child) = inner {
                serialize(buf, elem, child, depth + 1)?;
                if elem.fixed_size().is_none() {
                    buf.push(0);
                }
            }
        }
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
            // The buffer is 8-aligned here because the alignment of a variant
            // is 8. This alignment satisfies the alignment of any child.
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

/// Serializes a tuple or a dict entry.
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

/// Returns the size in bytes of each framing offset of a container.
///
/// `data_len` is the size of the container data, and `n_offsets` is the
/// number of framing offsets. The result is the smallest size `z` whose range
/// covers the total size of the container, `data_len + n_offsets * z`:
///
/// - 1 covers it if `data_len + n_offsets` is at most `0xFF`.
/// - 2 covers it if `data_len + n_offsets * 2` is at most `0xFFFF`.
/// - 4 covers it if `data_len + n_offsets * 4` is at most `0xFFFF_FFFF`.
/// - 8 covers every other total size.
///
/// A reader derives the same size from the total size with
/// [`offset_size_for`], so the writer and the reader agree.
///
/// With this function and [`write_offset`], a caller can write the framing of
/// a container that is too large to buffer. An example is a static-delta part
/// payload, whose two trailing byte arrays stream from disk. When the caller
/// knows the length of each member, it can write the framing.
///
/// [`offset_size_for`]: crate::offset_size_for
pub fn choose_offset_size(data_len: usize, n_offsets: usize) -> usize {
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

/// Appends one framing offset of width `z`.
///
/// `value` is the end of a member, counted from the start of the container.
/// The function writes the low `z` bytes of `value` in little-endian byte
/// order. [`choose_offset_size`] gives the width `z`.
///
/// The offsets of a container follow its data. A tuple has its offsets in
/// reverse member order. An array has its offsets in member order.
///
/// # Panics
///
/// Panics if `z` is more than the size of `usize` in bytes: 8 on a 64-bit
/// target, 4 on a 32-bit target.
pub fn write_offset(buf: &mut Vec<u8>, value: usize, z: usize) {
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
        // (uuua(ayay)) with uid 0, gid 0, mode 0o40755 in big-endian, and no
        // xattrs. The value has three fixed u32 members and an empty final
        // array. It is 12 bytes and has no framing offsets. The bytes match
        // the golden dirmeta fixture.
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
        // {"version": <"1">}: the key "version\0" fills bytes 0..8. The
        // variant member is 8-aligned. The variant is "1\0" + NUL + "s". The
        // framing offset of the entry is the end of the key (8). The framing
        // offset of the array is the end of the entry (13).
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
        // (su): the end of the string needs a framing offset. The trailing
        // u32 needs no framing offset. Padding to the u32 alignment separates
        // the two members.
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
        // 30 nine-byte strings give 270 data bytes. This size forces 2-byte
        // framing offsets, so the array is 270 + 30 * 2 bytes.
        let items: Vec<Value> = (0..30)
            .map(|i| Value::Str(format!("string{i:02}")))
            .collect();
        let bytes = ser("as", &Value::Array(items));
        assert_eq!(bytes.len(), 270 + 60);
        // The first framing offset is the end of the first 9-byte element.
        // It is 2 bytes little-endian.
        assert_eq!(&bytes[270..272], &9u16.to_le_bytes());
        // The last framing offset is the end of the data area.
        assert_eq!(&bytes[328..330], &270u16.to_le_bytes());
    }

    #[test]
    fn rejects_value_depth_bomb() {
        // The encode path accepts at most 128 nested variants. 129 nested
        // variants exceed MAX_VALUE_DEPTH.
        let mut value = Value::variant(Type::Byte, Value::Byte(1));
        for _ in 0..127 {
            value = Value::variant(Type::Variant, value);
        }
        let v = Type::parse("v").unwrap();
        assert!(to_bytes(&v, &value).is_ok());
        value = Value::variant(Type::Variant, value);
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
        // A value of type ay must be Bytes. An Array of Byte is a mismatch.
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
