use crate::codec::{ArrayReader, TupleReader};
use crate::ser::offset_max;
use crate::{Error, GvDecode, Result, Type, Value};

/// The maximum nesting depth of a value.
///
/// A nested variant lets the nesting of a value exceed the static depth of the
/// type signature. For this reason, the parser and the serializer apply their
/// own limit.
pub(crate) const MAX_VALUE_DEPTH: usize = 128;

/// Deserializes normal-form GVariant bytes of type `ty` into a [`Value`].
///
/// The parser accepts normal form only, so a value that it returns
/// re-serializes to the identical bytes. The object checksum depends on this
/// property. The parser preallocates at most 4096 elements for an array, so
/// hostile input cannot force an allocation proportional to its length.
///
/// # Depth limit
///
/// A leaf can sit under at most 128 levels of containers. Each variant, array,
/// maybe, tuple, and dict entry adds one level. The bytes of an `ay` add no
/// level. A `v` that holds 128 nested variants decodes, and a `v` that holds
/// 129 returns [`Error::DepthExceeded`].
///
/// # Errors
///
/// - [`Error::NotNormal`] if `data` deviates from normal form in any way. The
///   variant carries a reason that names the deviation. These are the
///   deviations:
///   - a scalar of the wrong size, or a boolean byte that is not 0 or 1
///   - a string with no NUL terminator, with an interior NUL byte, or with
///     bytes that are not UTF-8
///   - padding bytes that are not zero
///   - framing offsets that are out of bounds, out of order, or wider than
///     normal form needs
///   - an array of fixed-size elements whose size is not a multiple of the
///     element size
///   - a fixed-size tuple of the wrong size, or tuple members that do not fill
///     the tuple
///   - an empty tuple `()` that is not a single zero byte
///   - a maybe of a variable-size element with no terminating zero byte
///   - a variant with no type separator, or with a type signature that is not
///     UTF-8 or not valid
/// - [`Error::DepthExceeded`] if the value nests deeper than the
///   [depth limit](from_bytes#depth-limit).
pub fn from_bytes(ty: &Type, data: &[u8]) -> Result<Value> {
    parse(ty, data, 0)
}

/// Checks that `data` is normal-form GVariant bytes of type `ty`.
///
/// The check accepts exactly the input that [`from_bytes`] accepts, with the
/// same [depth limit](from_bytes#depth-limit) of 128 levels. It keeps no
/// decoded value, so its memory does not grow with the element count of the
/// input.
///
/// # Errors
///
/// For each input that [`from_bytes`] rejects, this function returns the same
/// error:
///
/// - [`Error::NotNormal`] if `data` deviates from normal form. The
///   [`from_bytes` errors](from_bytes#errors) list the deviations.
/// - [`Error::DepthExceeded`] if the value nests deeper than 128 levels.
pub fn validate(ty: &Type, data: &[u8]) -> Result<()> {
    check(ty, data, 0)
}

/// Deserializes one member of a serialized tuple into a [`Value`].
///
/// `ty` is the type of the whole tuple. `index` is the zero-based position of
/// the member to decode.
///
/// The function checks the framing of every member the way [`from_bytes`]
/// checks it: the framing offsets, the padding, and the size of the tuple. It
/// does not decode the other members, so it does not detect a fault inside
/// them. If the other members of a serialized value are large, a reader of one
/// member pays only for their framing.
///
/// # Errors
///
/// - [`Error::NotNormal`] with the reason "the type is not a tuple" if `ty` is
///   not a tuple.
/// - [`Error::NotNormal`] with the reason "the tuple holds no member of that
///   index" if `index` is not less than the member count.
/// - [`Error::NotNormal`] if the framing of the tuple is not normal form, or
///   if the member at `index` is not normal form. The
///   [`from_bytes` errors](from_bytes#errors) list the deviations.
/// - [`Error::DepthExceeded`] if the member nests deeper than the
///   [depth limit](from_bytes#depth-limit). The tuple counts as one level.
pub fn tuple_field_from_bytes(ty: &Type, data: &[u8], index: usize) -> Result<Value> {
    let Type::Tuple(members) = ty else {
        return Err(Error::NotNormal("the type is not a tuple"));
    };
    let n = members.len();
    if index >= n {
        return Err(Error::NotNormal("the tuple holds no member of that index"));
    }
    let n_offsets = members
        .iter()
        .take(n - 1)
        .filter(|member| member.fixed_size().is_none())
        .count();
    let mut reader = TupleReader::new(data, n_offsets, ty.fixed_size())?;
    let mut field = None;
    let last = n - 1;
    for (i, member_ty) in members.iter().enumerate() {
        let slice = reader.field(member_ty.alignment(), member_ty.fixed_size(), i == last)?;
        if i == index {
            field = Some(parse(member_ty, slice, 1)?);
        }
    }
    reader.finish()?;
    Ok(field.expect("the index names a member of the tuple"))
}

fn parse(ty: &Type, data: &[u8], depth: usize) -> Result<Value> {
    if depth > MAX_VALUE_DEPTH {
        return Err(Error::DepthExceeded);
    }
    match ty {
        // Scalar and string leaves use the strict checks of the typed
        // decoders. The `Value` path only wraps their results.
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

/// Applies the checks of [`parse`] and builds no value.
fn check(ty: &Type, data: &[u8], depth: usize) -> Result<()> {
    if depth > MAX_VALUE_DEPTH {
        return Err(Error::DepthExceeded);
    }
    match ty {
        Type::Bool => bool::decode(data).map(drop),
        Type::Byte => u8::decode(data).map(drop),
        Type::I16 | Type::U16 => exact::<2>(data).map(drop),
        Type::I32 | Type::Handle | Type::U32 => exact::<4>(data).map(drop),
        Type::I64 | Type::U64 | Type::Double => exact::<8>(data).map(drop),
        Type::Str | Type::ObjectPath | Type::Signature => <&str>::decode(data).map(drop),
        Type::Maybe(elem) => {
            if data.is_empty() {
                return Ok(());
            }
            let child = if elem.fixed_size().is_some() {
                data
            } else {
                match data.split_last() {
                    Some((0, rest)) => rest,
                    _ => return Err(Error::NotNormal("maybe lacks its terminating zero byte")),
                }
            };
            check(elem, child, depth + 1)
        }
        Type::Array(elem) if **elem == Type::Byte => Ok(()),
        Type::Array(elem) => {
            let mut reader = ArrayReader::new(data, elem.alignment(), elem.fixed_size())?;
            while let Some(slice) = reader.next_slice() {
                check(elem, slice?, depth + 1)?;
            }
            Ok(())
        }
        Type::Tuple(members) => check_struct(ty, members.iter(), data, depth),
        Type::DictEntry(key, value) => {
            check_struct(ty, [&**key, &**value].into_iter(), data, depth)
        }
        Type::Variant => {
            let (child, _, child_ty) = split_variant(data)?;
            check(&child_ty, child, depth + 1)
        }
    }
}

/// Applies the checks of [`parse_struct`] and builds no value.
fn check_struct<'t>(
    whole: &Type,
    members: impl ExactSizeIterator<Item = &'t Type> + Clone,
    data: &[u8],
    depth: usize,
) -> Result<()> {
    let n = members.len();
    if n == 0 {
        if data != [0] {
            return Err(Error::NotNormal("empty tuple is not a single zero byte"));
        }
        return Ok(());
    }
    let n_offsets = members
        .clone()
        .take(n - 1)
        .filter(|m| m.fixed_size().is_none())
        .count();
    let mut reader = TupleReader::new(data, n_offsets, whole.fixed_size())?;
    let last = n - 1;
    for (i, member_ty) in members.enumerate() {
        let slice = reader.field(member_ty.alignment(), member_ty.fixed_size(), i == last)?;
        check(member_ty, slice, depth + 1)?;
    }
    reader.finish()
}

/// The maximum element count that the parser preallocates for an array.
///
/// The parser preallocates before it checks any element. The count comes
/// directly from the input length (one element per byte for fixed-size
/// elements). With the cap, hostile input cannot force an allocation
/// proportional to its own size. A large valid array still grows past the cap,
/// with amortized cost.
const ARRAY_PREALLOC_CAP: usize = 4096;

/// Parses `m<T>`.
///
/// If the input has no bytes, the value is `Nothing`. Any other input is
/// `Just`. For a fixed-size element, the element bytes are the whole input.
/// For a variable-size element, the element bytes are the input less its
/// trailing zero byte.
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
    // Framing offsets cover each variable-size member except the last member.
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

/// Splits a serialized variant into its parts.
///
/// The parts are the child bytes, the borrowed signature bytes, and the parsed
/// child type. The `Value` decoder and the typed decoders both use this
/// function.
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

/// Returns the framing-offset size for a container of `len` serialized bytes.
///
/// The result is the smallest size whose range covers `len`:
///
/// - 1 if `len` is at most `0xFF`.
/// - 2 if `len` is more than `0xFF` and at most `0xFFFF`.
/// - 4 if `len` is more than `0xFFFF` and at most `0xFFFF_FFFF`.
/// - 8 if `len` is more than `0xFFFF_FFFF`.
///
/// [`choose_offset_size`] picks the size on the encode side.
///
/// A reader of a container too large to buffer uses this function to find the
/// framing offsets at the end from the total length. A static-delta part
/// payload, read as a stream, is such a container. [`from_bytes`] finds the
/// offsets the same way.
///
/// [`choose_offset_size`]: crate::choose_offset_size
pub fn offset_size_for(len: usize) -> usize {
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

    /// One member of a tuple decodes to the value that the whole parse gives it.
    ///
    /// The decode still checks the framing of every member. The function
    /// refuses an index outside the tuple.
    #[test]
    fn decodes_one_tuple_member() {
        let ty = Type::parse("(asa{sv}t)").unwrap();
        let value = Value::Tuple(vec![
            Value::Array(vec!["a".into(), "bb".into()]),
            Value::Array(vec![Value::Tuple(vec![
                "k".into(),
                Value::variant(Type::U32, Value::U32(9)),
            ])]),
            Value::U64(0x0123_4567_89ab_cdef),
        ]);
        let bytes = to_bytes(&ty, &value).unwrap();
        let Value::Tuple(members) = from_bytes(&ty, &bytes).unwrap() else {
            panic!("the summary type is a tuple");
        };
        for (index, member) in members.iter().enumerate() {
            assert_eq!(
                &tuple_field_from_bytes(&ty, &bytes, index).unwrap(),
                member,
                "member {index}"
            );
        }
        assert!(tuple_field_from_bytes(&ty, &bytes, 3).is_err());
        assert!(tuple_field_from_bytes(&Type::Str, &bytes, 0).is_err());
        // For each index, the decode reads the framing of every member.
        let mut torn = bytes.clone();
        let last = torn.len() - 1;
        torn[last] = 0xff;
        assert!(tuple_field_from_bytes(&ty, &torn, 2).is_err());
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

    /// The types outside the on-disk format round-trip.
    ///
    /// The `ostree commit --add-metadata` command writes these types into the
    /// metadata dict of a commit.
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

    /// A maybe of a variable-size element ends in one zero byte.
    ///
    /// This byte tells `Just ""` apart from `Nothing`.
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
        // first element fails to decode, so the parse returns an error. The
        // untrusted element count must not drive a preallocation proportional
        // to it before the parser checks any element. `parse_array` applies
        // the bound. Only an inspection of `parse_array` enforces the ratio.
        let data = vec![0xffu8; 1 << 20];
        assert_eq!(
            from_bytes(&Type::parse("ab").unwrap(), &data),
            Err(Error::NotNormal("boolean is not 0 or 1"))
        );
    }

    /// `validate` accepts exactly the input that `from_bytes` accepts.
    ///
    /// For each rejected input, both return the same error. The cases are
    /// valid and malformed inputs of every shape.
    #[test]
    fn validate_agrees_with_from_bytes() {
        let dict = Value::Array(vec![
            Value::Tuple(vec![
                "a".into(),
                Value::variant(Type::parse("ab").unwrap(), Value::Array(vec![true.into()])),
            ]),
            Value::Tuple(vec![
                "b".into(),
                Value::variant(Type::parse("ms").unwrap(), Value::Maybe(None)),
            ]),
            Value::Tuple(vec![
                "c".into(),
                Value::variant(
                    Type::parse("(sid)").unwrap(),
                    Value::Tuple(vec!["x".into(), Value::I32(-1), Value::double(0.5)]),
                ),
            ]),
        ]);
        let asv = Type::parse("a{sv}").unwrap();
        let good = to_bytes(&asv, &dict).unwrap();
        let mut cases: Vec<(&str, Vec<u8>)> = vec![("a{sv}", good.clone())];
        for i in 0..good.len() {
            let mut torn = good.clone();
            torn[i] ^= 0xff;
            cases.push(("a{sv}", torn));
            cases.push(("a{sv}", good[..i].to_vec()));
        }
        let mut deep = vec![1u8, 0, b'y'];
        for _ in 0..128 {
            deep.extend_from_slice(&[0, b'v']);
        }
        cases.extend([
            ("v", deep),
            ("ab", vec![0xff; 64]),
            ("ab", vec![0, 1, 1]),
            ("ms", vec![1]),
            ("ms", vec![0, 0]),
            ("mi", vec![1, 2, 3, 4]),
            ("()", vec![0]),
            ("()", vec![1]),
            ("(uuu)", vec![0; 13]),
            ("(su)", b"a\0\0\0\x05\0\0\0\0\0\x02".to_vec()),
            ("as", vec![b'a', 0, 1, 2]),
            ("au", vec![0; 6]),
            ("s", vec![0xff, 0xfe, 0]),
            ("v", b"a\0d".to_vec()),
            ("ay", vec![1, 2, 3]),
            ("aay", vec![1, 2, 0]),
        ]);
        for (sig, bytes) in &cases {
            let ty = Type::parse(sig).unwrap();
            assert_eq!(
                validate(&ty, bytes),
                from_bytes(&ty, bytes).map(drop),
                "{sig} {bytes:?}"
            );
        }
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
        // The offsets carve out an element without a NUL terminator.
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
        // Build 129 nested variants by hand, because the serializer rejects
        // values this deep. The bytes are the innermost byte, then one
        // signature for each wrapper.
        let ty = Type::parse("v").unwrap();
        let mut bytes = vec![1u8, 0, b'y'];
        for _ in 0..128 {
            bytes.push(0);
            bytes.push(b'v');
        }
        assert_eq!(from_bytes(&ty, &bytes), Err(Error::DepthExceeded));

        // 128 nested variants sit exactly at the limit and round-trip. One
        // more wrapper fails with the same error on the encode path.
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
