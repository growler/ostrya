#![forbid(unsafe_code)]

//! Phase 1a verification gate (see docs/port-plan.md): for every metadata
//! object the `ostree` tool wrote into tests/fixtures/generated/, the typed
//! codec must decode borrow-first, re-encode to identical bytes, and agree
//! field-for-field with the `Value` path.

use std::path::Path;

use ostrya_gvariant::{ArrayIter, GvDecode, Type, Value, Variant, encode_to_vec, from_bytes};

#[path = "../../../tests/support.rs"]
mod support;

use support::{
    ARCHIVE_FILE_HEADER_SIG, ArchiveHeaderView, COMMIT_SIG, CommitView, DIRMETA_SIG, DIRTREE_SIG,
    DirMetaView, DirTreeView, filez_header, objects_with_extension,
};

/// Assert typed re-encoding reproduces the input bytes exactly.
fn assert_byte_identical(context: &Path, typed: &[u8], bytes: &[u8]) {
    assert_eq!(
        typed,
        bytes,
        "{}: typed re-encoding is not byte-identical",
        context.display()
    );
}

/// Compare an `a{sv}`-shaped typed iterator with the `Value` array it decodes.
fn assert_metadata_agrees(typed: ArrayIter<(&str, Variant)>, value_array: &[Value]) {
    let pairs: Vec<(&str, Value)> = typed
        .map(|entry| {
            let (key, variant) = entry.unwrap();
            (key, variant.value().clone())
        })
        .collect();
    assert_eq!(pairs.len(), value_array.len(), "metadata entry count");
    for ((key, val), entry) in pairs.iter().zip(value_array) {
        let fields = entry.as_tuple().unwrap();
        assert_eq!(*key, fields[0].as_str().unwrap(), "metadata key");
        let (_, variant_value) = fields[1].as_variant().unwrap();
        assert_eq!(val, variant_value, "metadata value for {key}");
    }
}

#[test]
fn commit_objects_round_trip() {
    for (object, bytes) in objects_with_extension("commit", None) {
        let value = from_bytes(&Type::parse(COMMIT_SIG).unwrap(), &bytes).unwrap();
        let fields = value.as_tuple().unwrap();

        let commit: CommitView = GvDecode::decode(&bytes).unwrap();

        assert_byte_identical(&object.path, &encode_to_vec(&commit).unwrap(), &bytes);

        assert_metadata_agrees(commit.0, fields[0].as_array().unwrap());
        assert_eq!(commit.1, fields[1].as_bytes().unwrap(), "parent");
        let related: Vec<(&str, &[u8])> = commit.2.map(Result::unwrap).collect();
        assert_eq!(
            related.len(),
            fields[2].as_array().unwrap().len(),
            "related"
        );
        assert_eq!(commit.3, fields[3].as_str().unwrap(), "subject");
        assert_eq!(commit.4, fields[4].as_str().unwrap(), "body");
        assert_eq!(commit.5, fields[5].as_u64().unwrap(), "timestamp");
        assert_eq!(commit.6, fields[6].as_bytes().unwrap(), "root dirtree");
        assert_eq!(commit.7, fields[7].as_bytes().unwrap(), "root dirmeta");
    }
}

#[test]
fn dirtree_objects_round_trip() {
    for (object, bytes) in objects_with_extension("dirtree", None) {
        let value = from_bytes(&Type::parse(DIRTREE_SIG).unwrap(), &bytes).unwrap();
        let fields = value.as_tuple().unwrap();

        let dirtree: DirTreeView = GvDecode::decode(&bytes).unwrap();

        assert_byte_identical(&object.path, &encode_to_vec(&dirtree).unwrap(), &bytes);

        let files: Vec<(&str, &[u8])> = dirtree.0.map(Result::unwrap).collect();
        let value_files = fields[0].as_array().unwrap();
        assert_eq!(files.len(), value_files.len(), "file count");
        for ((name, checksum), entry) in files.iter().zip(value_files) {
            let entry = entry.as_tuple().unwrap();
            assert_eq!(*name, entry[0].as_str().unwrap());
            assert_eq!(*checksum, entry[1].as_bytes().unwrap());
            assert_eq!(checksum.len(), 32, "file checksum length");
        }

        let dirs: Vec<(&str, &[u8], &[u8])> = dirtree.1.map(Result::unwrap).collect();
        let value_dirs = fields[1].as_array().unwrap();
        assert_eq!(dirs.len(), value_dirs.len(), "dir count");
        for ((name, tree, meta), entry) in dirs.iter().zip(value_dirs) {
            let entry = entry.as_tuple().unwrap();
            assert_eq!(*name, entry[0].as_str().unwrap());
            assert_eq!(*tree, entry[1].as_bytes().unwrap());
            assert_eq!(*meta, entry[2].as_bytes().unwrap());
        }
    }
}

#[test]
fn dirmeta_objects_round_trip() {
    for (object, bytes) in objects_with_extension("dirmeta", None) {
        let value = from_bytes(&Type::parse(DIRMETA_SIG).unwrap(), &bytes).unwrap();
        let fields = value.as_tuple().unwrap();

        let dirmeta: DirMetaView = GvDecode::decode(&bytes).unwrap();

        assert_byte_identical(&object.path, &encode_to_vec(&dirmeta).unwrap(), &bytes);

        assert_eq!(dirmeta.0, fields[0].as_u32().unwrap(), "uid");
        assert_eq!(dirmeta.1, fields[1].as_u32().unwrap(), "gid");
        assert_eq!(dirmeta.2, fields[2].as_u32().unwrap(), "mode");
        let xattrs: Vec<(&[u8], &[u8])> = dirmeta.3.map(Result::unwrap).collect();
        assert_eq!(xattrs.len(), fields[3].as_array().unwrap().len(), "xattrs");
    }
}

#[test]
fn archive_file_headers_round_trip() {
    // A .filez object is [4-byte BE u32 header length][4 zero bytes]
    // [header variant][raw-deflate payload]; the header round-trips here.
    for (object, bytes) in objects_with_extension("filez", None) {
        let header = filez_header(&bytes, &object.path);

        let value = from_bytes(&Type::parse(ARCHIVE_FILE_HEADER_SIG).unwrap(), header).unwrap();
        let fields = value.as_tuple().unwrap();

        let parsed: ArchiveHeaderView = GvDecode::decode(header).unwrap();

        assert_byte_identical(&object.path, &encode_to_vec(&parsed).unwrap(), header);

        assert_eq!(parsed.0, fields[0].as_u64().unwrap(), "size");
        assert_eq!(parsed.1, fields[1].as_u32().unwrap(), "uid");
        assert_eq!(parsed.2, fields[2].as_u32().unwrap(), "gid");
        assert_eq!(parsed.3, fields[3].as_u32().unwrap(), "mode");
        assert_eq!(parsed.4, fields[4].as_u32().unwrap(), "rdev");
        assert_eq!(parsed.5, fields[5].as_str().unwrap(), "symlink target");
        let xattrs: Vec<(&[u8], &[u8])> = parsed.6.map(Result::unwrap).collect();
        assert_eq!(xattrs.len(), fields[6].as_array().unwrap().len(), "xattrs");
    }
}
