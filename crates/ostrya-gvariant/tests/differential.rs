#![forbid(unsafe_code)]

//! Phase R5 verification gate: the `Value` path (`from_bytes`/`to_bytes`) and
//! the typed path (`GvDecode`/`GvEncode`) share one framing engine, so for
//! generated values across every ostree object shape the two must agree
//! byte-for-byte. Each case checks, on the same generated value:
//!
//! - `to_bytes` (Value encode) equals `encode_to_vec` of the typed value;
//! - `from_bytes` (Value decode) reproduces the value;
//! - typed decode of those bytes re-encodes byte-identically.
//!
//! The generated values sweep the framing branches: empty, single, and
//! many-element arrays; element and container sizes that cross the 1-, 2-, and
//! 4-byte framing-offset boundaries; fixed- and variable-size elements; and
//! variants carrying each child type.

use ostrya_gvariant::{
    ArrayIter, GvDecode, GvEncode, Slice, Type, Value, encode_to_vec, from_bytes, to_bytes,
};

#[path = "../../../tests/support.rs"]
mod support;

use support::{
    ARCHIVE_FILE_HEADER_SIG, ArchiveHeaderView, COMMIT_SIG, CommitView, DIRMETA_SIG, DIRTREE_SIG,
    DirMetaView, DirTreeView, MetadataView, checksum,
};

/// An archive-header case: size, mode, symlink target, and xattr pairs.
type ArchiveCase<'a> = (u64, u32, &'a str, &'a [(&'a [u8], &'a [u8])]);

/// The Value path and typed re-encode must both reproduce `bytes`.
///
/// `bytes` is produced by the Value encoder from `value`; the typed decoder
/// reads those same bytes and must re-emit them unchanged.
fn assert_paths_agree<'a, T>(sig: &str, value: &Value, bytes: &'a [u8])
where
    T: GvDecode<'a> + GvEncode,
{
    let ty = Type::parse(sig).unwrap();
    assert_eq!(
        &from_bytes(&ty, bytes).unwrap(),
        value,
        "{sig}: Value decode reproduces the value"
    );
    let typed = T::decode(bytes).unwrap_or_else(|e| panic!("{sig}: typed decode failed: {e}"));
    assert_eq!(
        &encode_to_vec(&typed).unwrap(),
        bytes,
        "{sig}: typed re-encode is byte-identical"
    );
}

/// `encode_to_vec` of a typed value must equal `to_bytes` of the Value.
fn assert_typed_encode<T: GvEncode>(sig: &str, typed: &T, value: &Value) -> Vec<u8> {
    let ty = Type::parse(sig).unwrap();
    let value_bytes = to_bytes(&ty, value).unwrap();
    assert_eq!(
        &encode_to_vec(typed).unwrap(),
        &value_bytes,
        "{sig}: typed encode matches Value encode"
    );
    value_bytes
}

#[test]
fn dirmeta_shape_agrees() {
    // xattr sets sweeping count and the total size that flips the array's
    // framing offsets from 1 byte to 2 bytes (a >255-byte value).
    let sets: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
        vec![],
        vec![(b"user.one".to_vec(), b"x".to_vec())],
        vec![
            (b"user.one".to_vec(), b"first".to_vec()),
            (b"user.two".to_vec(), b"second".to_vec()),
            (
                b"security.selinux".to_vec(),
                b"system_u:object_r:etc_t:s0".to_vec(),
            ),
        ],
        vec![(b"user.big".to_vec(), vec![0xa5; 300])],
    ];
    for xattrs in &sets {
        let value = Value::Tuple(vec![
            Value::U32(0),
            Value::U32(0),
            Value::U32(0o40755u32.swap_bytes()),
            Value::Array(
                xattrs
                    .iter()
                    .map(|(k, v)| {
                        Value::Tuple(vec![Value::from(k.clone()), Value::from(v.clone())])
                    })
                    .collect(),
            ),
        ]);
        let entries: Vec<(&[u8], &[u8])> = xattrs
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();
        let typed = (0u32, 0u32, 0o40755u32.swap_bytes(), Slice(&entries));
        let bytes = assert_typed_encode(DIRMETA_SIG, &typed, &value);
        assert_paths_agree::<DirMetaView>(DIRMETA_SIG, &value, &bytes);
    }
}

#[test]
fn dirtree_shape_agrees() {
    // (file count, dir count), including a large file list that crosses the
    // 2-byte framing-offset boundary.
    for (n_files, n_dirs) in [(0, 0), (1, 0), (3, 1), (40, 5)] {
        let files: Vec<(String, Vec<u8>)> = (0..n_files)
            .map(|i| (format!("file{i:03}.txt"), checksum(i as u8)))
            .collect();
        let dirs: Vec<(String, Vec<u8>, Vec<u8>)> = (0..n_dirs)
            .map(|i| {
                (
                    format!("dir{i:03}"),
                    checksum(0x40 + i as u8),
                    checksum(0x80 + i as u8),
                )
            })
            .collect();
        let value = Value::Tuple(vec![
            Value::Array(
                files
                    .iter()
                    .map(|(name, c)| {
                        Value::Tuple(vec![Value::from(name.as_str()), Value::from(c.clone())])
                    })
                    .collect(),
            ),
            Value::Array(
                dirs.iter()
                    .map(|(name, t, m)| {
                        Value::Tuple(vec![
                            Value::from(name.as_str()),
                            Value::from(t.clone()),
                            Value::from(m.clone()),
                        ])
                    })
                    .collect(),
            ),
        ]);
        let file_refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(n, c)| (n.as_str(), c.as_slice()))
            .collect();
        let dir_refs: Vec<(&str, &[u8], &[u8])> = dirs
            .iter()
            .map(|(n, t, m)| (n.as_str(), t.as_slice(), m.as_slice()))
            .collect();
        let typed = (Slice(&file_refs), Slice(&dir_refs));
        let bytes = assert_typed_encode(DIRTREE_SIG, &typed, &value);
        assert_paths_agree::<DirTreeView>(DIRTREE_SIG, &value, &bytes);
    }
}

#[test]
fn archive_header_shape_agrees() {
    let cases: &[ArchiveCase] = &[
        (13u64.swap_bytes(), 0o100644u32.swap_bytes(), "", &[]),
        (0, 0o120777u32.swap_bytes(), "hello.txt", &[]),
        (
            4096u64.swap_bytes(),
            0o100644u32.swap_bytes(),
            "",
            &[(b"user.k", b"v"), (b"security.selinux", b"unconfined")],
        ),
    ];
    for &(size, mode, target, xattrs) in cases {
        let value = Value::Tuple(vec![
            Value::U64(size),
            Value::U32(0),
            Value::U32(0),
            Value::U32(mode),
            Value::U32(0),
            Value::from(target),
            Value::Array(
                xattrs
                    .iter()
                    .map(|(k, v)| Value::Tuple(vec![Value::from(*k), Value::from(*v)]))
                    .collect(),
            ),
        ]);
        let typed = (size, 0u32, 0u32, mode, 0u32, target, Slice(xattrs));
        let bytes = assert_typed_encode(ARCHIVE_FILE_HEADER_SIG, &typed, &value);
        assert_paths_agree::<ArchiveHeaderView>(ARCHIVE_FILE_HEADER_SIG, &value, &bytes);
    }
}

#[test]
fn metadata_variants_agree() {
    // a{sv} carrying each supported child type; decode-only, since a variant
    // has no from-scratch typed encoder. The typed decoder must reproduce the
    // Value-encoded bytes, and every variant value must match field-for-field.
    const SIG: &str = "a{sv}";
    let ty = Type::parse(SIG).unwrap();
    let entries = vec![
        ("bool", Value::variant(Type::Bool, Value::Bool(true))),
        ("u32", Value::variant(Type::U32, Value::U32(0xdead_beef))),
        (
            "u64",
            Value::variant(Type::U64, Value::U64(0x0123_4567_89ab_cdef)),
        ),
        ("str", Value::variant(Type::Str, Value::from("value"))),
        (
            "bytes",
            Value::variant(Type::parse("ay").unwrap(), Value::from(checksum(9))),
        ),
        (
            "strv",
            Value::variant(
                Type::parse("as").unwrap(),
                Value::Array(vec![Value::from("a"), Value::from("bb")]),
            ),
        ),
    ];
    let value = Value::Array(
        entries
            .iter()
            .map(|(k, v)| Value::Tuple(vec![Value::from(*k), v.clone()]))
            .collect(),
    );
    let bytes = to_bytes(&ty, &value).unwrap();
    assert_eq!(
        from_bytes(&ty, &bytes).unwrap(),
        value,
        "a{{sv}} Value decode"
    );

    let typed = <MetadataView as GvDecode>::decode(&bytes).unwrap();
    assert_eq!(
        encode_to_vec(&typed).unwrap(),
        bytes,
        "a{{sv}} typed re-encode is byte-identical"
    );
    let decoded: Vec<(&str, Value)> = typed
        .map(|e| {
            let (k, variant) = e.unwrap();
            (k, variant.value().clone())
        })
        .collect();
    assert_eq!(decoded.len(), entries.len());
    for ((key, variant_value), (exp_key, exp_variant)) in decoded.iter().zip(&entries) {
        assert_eq!(key, exp_key);
        let (_, exp_inner) = exp_variant.as_variant().unwrap();
        assert_eq!(variant_value, exp_inner, "variant value for {key}");
    }
}

#[test]
fn byte_array_offset_boundaries_agree() {
    // aay: an outer array of byte arrays whose total size crosses the 1-, 2-,
    // and 4-byte framing-offset boundaries.
    const SIG: &str = "aay";
    for n in [0usize, 1, 250, 255, 256, 300, 70_000] {
        let inner = vec![0x5au8; n];
        let value = Value::Array(vec![Value::from(inner.clone())]);
        let slices: [&[u8]; 1] = [inner.as_slice()];
        let typed = Slice(&slices);
        let bytes = assert_typed_encode(SIG, &typed, &value);
        assert_paths_agree::<ArrayIter<&[u8]>>(SIG, &value, &bytes);
    }
}

#[test]
fn string_array_and_fixed_tuple_arrays_agree() {
    // as: variable-size elements with framing offsets.
    const AS_SIG: &str = "as";
    for strings in [
        vec![],
        vec![String::new()],
        vec!["a".to_string(), String::new(), "ccc".to_string()],
    ] {
        let value = Value::Array(strings.iter().map(|s| Value::from(s.as_str())).collect());
        let refs: Vec<&str> = strings.iter().map(String::as_str).collect();
        let typed = Slice(&refs);
        let bytes = assert_typed_encode(AS_SIG, &typed, &value);
        assert_paths_agree::<ArrayIter<&str>>(AS_SIG, &value, &bytes);
    }

    // a(uuu): fixed-size elements pack with no framing offsets.
    const AU3_SIG: &str = "a(uuu)";
    for triples in [
        vec![],
        vec![(1u32, 2u32, 3u32)],
        vec![(1, 2, 3), (4, 5, 6), (7, 8, 9)],
    ] {
        let value = Value::Array(
            triples
                .iter()
                .map(|(a, b, c)| Value::Tuple(vec![Value::U32(*a), Value::U32(*b), Value::U32(*c)]))
                .collect(),
        );
        let typed = Slice(&triples);
        let bytes = assert_typed_encode(AU3_SIG, &typed, &value);
        assert_paths_agree::<ArrayIter<(u32, u32, u32)>>(AU3_SIG, &value, &bytes);
    }
}

#[test]
fn variable_tuple_with_trailing_fixed_member_agrees() {
    // (su): the string needs a framing offset, the trailing u32 does not.
    const SIG: &str = "(su)";
    for (s, u) in [("", 0u32), ("abc", 5), ("a longer string", 0xffff_ffff)] {
        let value = Value::Tuple(vec![Value::from(s), Value::U32(u)]);
        let typed = (s, u);
        let bytes = assert_typed_encode(SIG, &typed, &value);
        assert_paths_agree::<(&str, u32)>(SIG, &value, &bytes);
    }
}

#[test]
fn commit_shape_agrees() {
    // Full commit (a{sv}aya(say)sstayay); decode-only for the a{sv} member.
    let ty = Type::parse(COMMIT_SIG).unwrap();
    let metadata = Value::Array(vec![
        Value::Tuple(vec![
            Value::from("ostree.ref-binding"),
            Value::variant(
                Type::parse("as").unwrap(),
                Value::Array(vec![Value::from("test/main")]),
            ),
        ]),
        Value::Tuple(vec![
            Value::from("version"),
            Value::variant(Type::Str, Value::from("1.0")),
        ]),
    ]);
    let related = Value::Array(vec![Value::Tuple(vec![
        Value::from("other/ref"),
        Value::from(checksum(0x20)),
    ])]);
    let value = Value::Tuple(vec![
        metadata,
        Value::from(Vec::new()),
        related,
        Value::from("subject"),
        Value::from(""),
        Value::U64(1_700_000_000u64.swap_bytes()),
        Value::from(checksum(0x10)),
        Value::from(checksum(0x50)),
    ]);
    let bytes = to_bytes(&ty, &value).unwrap();
    assert_paths_agree::<CommitView>(COMMIT_SIG, &value, &bytes);
}
