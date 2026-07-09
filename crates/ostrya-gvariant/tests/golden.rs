#![forbid(unsafe_code)]

//! Golden-fixture tests: every metadata object the `ostree` tool wrote into
//! tests/fixtures/generated/ must deserialize and re-serialize to identical
//! bytes. This is the phase 1 verification gate (see docs/port-plan.md).

use std::path::Path;

use ostrya_gvariant::{Type, Value, from_bytes, to_bytes};

#[path = "../../../tests/support.rs"]
mod support;

use support::{
    ARCHIVE_FILE_HEADER_SIG, COMMIT_SIG, DIRMETA_SIG, DIRTREE_SIG, filez_header,
    objects_with_extension,
};

/// Deserialize strictly, re-serialize, and require byte identity.
fn round_trip(sig: &str, bytes: &[u8], context: &Path) -> Value {
    let ty = Type::parse(sig).unwrap();
    let value = from_bytes(&ty, bytes)
        .unwrap_or_else(|e| panic!("{}: failed to parse as {sig}: {e}", context.display()));
    let reserialized = to_bytes(&ty, &value).unwrap();
    assert_eq!(
        reserialized,
        bytes,
        "{}: re-serialization is not byte-identical",
        context.display()
    );
    value
}

#[test]
fn commit_objects_round_trip() {
    for (object, bytes) in objects_with_extension("commit", None) {
        let commit = round_trip(COMMIT_SIG, &bytes, &object.path);
        let fields = commit.as_tuple().unwrap();
        // Deterministic fixture inputs: root commit, subject "fixture
        // commit", empty body, timestamp 1700000000 stored big-endian.
        assert_eq!(fields[1].as_bytes().unwrap(), b"", "parent");
        assert_eq!(fields[3].as_str().unwrap(), "fixture commit", "subject");
        assert_eq!(fields[4].as_str().unwrap(), "", "body");
        assert_eq!(
            fields[5].as_u64().unwrap(),
            1_700_000_000u64.swap_bytes(),
            "timestamp"
        );
        assert_eq!(fields[6].as_bytes().unwrap().len(), 32, "root dirtree");
        assert_eq!(fields[7].as_bytes().unwrap().len(), 32, "root dirmeta");
    }
}

#[test]
fn dirtree_objects_round_trip() {
    let mut saw_root = false;
    let mut saw_subdir = false;
    for (object, bytes) in objects_with_extension("dirtree", None) {
        let dirtree = round_trip(DIRTREE_SIG, &bytes, &object.path);
        let fields = dirtree.as_tuple().unwrap();
        let file_names: Vec<&str> = fields[0]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_tuple().unwrap()[0].as_str().unwrap())
            .collect();
        let dir_names: Vec<&str> = fields[1]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_tuple().unwrap()[0].as_str().unwrap())
            .collect();
        // The generator commits a fixed tree: the root holds three file
        // entries (the symlink is a file object) and one subdir; the subdir
        // holds one file. Both lists are sorted by name.
        if dir_names == ["subdir"] {
            assert_eq!(file_names, ["empty.txt", "hello.txt", "link"]);
            saw_root = true;
        } else {
            assert_eq!(file_names, ["nested.txt"]);
            assert!(dir_names.is_empty());
            saw_subdir = true;
        }
    }
    assert!(saw_root && saw_subdir);
}

#[test]
fn dirmeta_objects_round_trip() {
    for (object, bytes) in objects_with_extension("dirmeta", None) {
        let dirmeta = round_trip(DIRMETA_SIG, &bytes, &object.path);
        let fields = dirmeta.as_tuple().unwrap();
        assert_eq!(fields[0].as_u32().unwrap(), 0, "uid");
        assert_eq!(fields[1].as_u32().unwrap(), 0, "gid");
        // Directories were committed 0755; the mode is stored big-endian.
        assert_eq!(fields[2].as_u32().unwrap(), 0o40755u32.swap_bytes(), "mode");
        assert!(fields[3].as_array().unwrap().is_empty(), "xattrs");
    }
}

#[test]
fn archive_file_headers_round_trip() {
    // A .filez object is [4-byte BE u32 header length][4 zero bytes]
    // [header variant][raw-deflate payload]; the header round-trips here.
    let mut symlink_targets = Vec::new();
    let mut sizes = Vec::new();
    for (object, bytes) in objects_with_extension("filez", None) {
        let header = filez_header(&bytes, &object.path);
        let value = round_trip(ARCHIVE_FILE_HEADER_SIG, header, &object.path);
        let fields = value.as_tuple().unwrap();
        sizes.push(fields[0].as_u64().unwrap().swap_bytes());
        assert_eq!(fields[1].as_u32().unwrap(), 0, "uid");
        assert_eq!(fields[2].as_u32().unwrap(), 0, "gid");
        let mode = fields[3].as_u32().unwrap().swap_bytes();
        assert!(
            mode == 0o100644 || mode == 0o120777,
            "{}: unexpected mode {mode:o}",
            object.path.display()
        );
        assert_eq!(fields[4].as_u32().unwrap(), 0, "rdev");
        let target = fields[5].as_str().unwrap();
        if !target.is_empty() {
            symlink_targets.push(target.to_owned());
        }
        assert!(fields[6].as_array().unwrap().is_empty(), "xattrs");
    }
    // The fixture tree: hello.txt (13 bytes), empty.txt (0), subdir/nested.txt
    // (7), and a symlink to hello.txt.
    sizes.sort_unstable();
    assert_eq!(sizes, [0, 0, 7, 13]);
    assert_eq!(symlink_targets, ["hello.txt"]);
}
