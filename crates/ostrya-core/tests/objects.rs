#![forbid(unsafe_code)]

//! Phase 3 verification gate (see docs/port-plan.md): read the real objects
//! the `ostree` tool wrote into tests/fixtures/generated/, recompute their
//! checksums, and require byte-identical reserialization. The content-object
//! checksums are additionally recomputed from first principles -- the known
//! deterministic tree the fixture generator commits -- and must equal the
//! object names the tool chose.

use std::collections::BTreeMap;
use std::fs;

use ostrya_core::{
    Checksum, Commit, ContentHasher, DirMeta, DirMetaRef, DirTreeRef, FileHeader, Xattrs, filehdr,
};

#[path = "../../../tests/support.rs"]
mod support;

/// A `key=value` line from the generator's MANIFEST.
fn manifest_value(key: &str) -> String {
    let text = fs::read_to_string(support::fixture_root().join("MANIFEST")).unwrap();
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("MANIFEST records {key}"))
        .to_owned()
}

/// All loose objects with the given extension in one fixture repo, as
/// (checksum-from-filename, object bytes).
fn repo_objects(mode: &str, extension: &str) -> Vec<(Checksum, Vec<u8>)> {
    support::objects_with_extension(extension, Some(mode))
        .into_iter()
        .map(|(object, bytes)| (Checksum::from_hex(&object.hex()).unwrap(), bytes))
        .collect()
}

/// The same objects across both fixture repos.
fn objects(extension: &str) -> Vec<(Checksum, Vec<u8>)> {
    let mut found = repo_objects("archive", extension);
    found.extend(repo_objects("bare-user", extension));
    found
}

/// The deterministic tree the fixture generator commits (see generate.sh):
/// regular files are 0644 owned 0:0 with no xattrs, the symlink points at
/// hello.txt.
fn regular_header() -> FileHeader {
    FileHeader {
        uid: 0,
        gid: 0,
        mode: 0o100644,
        symlink_target: String::new(),
        xattrs: Xattrs::empty(),
    }
}

fn symlink_header() -> FileHeader {
    FileHeader {
        uid: 0,
        gid: 0,
        mode: 0o120777,
        symlink_target: "hello.txt".to_owned(),
        xattrs: Xattrs::empty(),
    }
}

/// (payload, expected header) for every content object, keyed by the
/// checksum recomputed from first principles.
fn expected_content() -> BTreeMap<Checksum, (&'static [u8], FileHeader)> {
    let regular = |payload: &'static [u8]| {
        let mut hasher = ContentHasher::new(&regular_header()).unwrap();
        hasher.update(payload);
        (hasher.finish(), (payload, regular_header()))
    };
    let link = (
        ContentHasher::new(&symlink_header()).unwrap().finish(),
        (&b""[..], symlink_header()),
    );
    BTreeMap::from([
        regular(b"hello ostree\n"),
        regular(b""),
        regular(b"nested\n"),
        link,
    ])
}

#[test]
fn commit_objects_parse_reserialize_and_hash_to_their_names() {
    let expected_commit = Checksum::from_hex(&manifest_value("commit")).unwrap();
    let expected_content = Checksum::from_hex(&manifest_value("content_checksum")).unwrap();
    for (name, bytes) in objects("commit") {
        assert_eq!(name, expected_commit);
        let commit = Commit::parse(&bytes).unwrap();
        assert_eq!(commit.serialize().unwrap(), bytes, "byte-identical");
        assert_eq!(commit.checksum().unwrap(), name, "recomputed checksum");
        assert_eq!(commit.content_checksum(), expected_content);
        assert_eq!(commit.parent, None);
        assert!(commit.related.is_empty());
        assert_eq!(commit.subject, "fixture commit");
        assert_eq!(commit.body, "");
        assert_eq!(commit.timestamp, 1_700_000_000);
        assert_eq!(commit.ref_bindings(), ["test/main"]);
        assert_eq!(commit.version(), None);
        assert_eq!(commit.collection_binding(), None);
    }
}

#[test]
fn dirtree_objects_walk_validate_and_hash_to_their_names() {
    let hash_regular = |payload: &[u8]| {
        let mut hasher = ContentHasher::new(&regular_header()).unwrap();
        hasher.update(payload);
        hasher.finish()
    };
    let hello = hash_regular(b"hello ostree\n");
    let empty = hash_regular(b"");
    let nested = hash_regular(b"nested\n");
    let link = ContentHasher::new(&symlink_header()).unwrap().finish();
    let mut saw_root = false;
    let mut saw_subdir = false;
    for (name, bytes) in objects("dirtree") {
        assert_eq!(Checksum::sha256(&bytes), name, "recomputed checksum");
        let view = DirTreeRef::parse(&bytes).unwrap();
        let files: Vec<(&str, Checksum)> = view.files().map(Result::unwrap).collect();
        let dirs: Vec<(&str, Checksum, Checksum)> = view.dirs().map(Result::unwrap).collect();
        assert_eq!(view.to_owned().unwrap().serialize().unwrap(), bytes);

        let file_names: Vec<&str> = files.iter().map(|(name, _)| *name).collect();
        if dirs.len() == 1 {
            // The root tree: three file entries plus the subdir, name-sorted.
            assert_eq!(file_names, ["empty.txt", "hello.txt", "link"]);
            assert_eq!(dirs[0].0, "subdir");
            let by_name: BTreeMap<&str, Checksum> = files.into_iter().collect();
            assert_eq!(by_name["empty.txt"], empty);
            assert_eq!(by_name["hello.txt"], hello);
            assert_eq!(by_name["link"], link);
            saw_root = true;
        } else {
            assert_eq!(file_names, ["nested.txt"]);
            assert!(dirs.is_empty());
            assert_eq!(files[0].1, nested);
            saw_subdir = true;
        }
    }
    assert!(saw_root && saw_subdir);
}

#[test]
fn dirmeta_objects_parse_reserialize_and_hash_to_their_names() {
    for (name, bytes) in objects("dirmeta") {
        assert_eq!(Checksum::sha256(&bytes), name, "recomputed checksum");
        let view = DirMetaRef::parse(&bytes).unwrap();
        assert_eq!(view.uid(), 0);
        assert_eq!(view.gid(), 0);
        assert_eq!(view.mode(), 0o40755);
        assert_eq!(view.xattrs().iter().count(), 0);
        let owned = view.to_owned().unwrap();
        assert_eq!(
            owned,
            DirMeta {
                uid: 0,
                gid: 0,
                mode: 0o40755,
                xattrs: Xattrs::empty(),
            }
        );
        assert_eq!(owned.serialize().unwrap(), bytes);
    }
}

#[test]
fn content_object_names_match_first_principles_checksums() {
    let expected = expected_content();
    for (mode, extension) in [("archive", "filez"), ("bare-user", "file")] {
        let names: Vec<Checksum> = repo_objects(mode, extension)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let mut computed: Vec<Checksum> = expected.keys().copied().collect();
        let mut names = names;
        names.sort();
        computed.sort();
        assert_eq!(names, computed, "{mode} content-object names");
    }
}

#[test]
fn archive_headers_parse_to_the_committed_metadata() {
    let expected = expected_content();
    for (name, bytes) in repo_objects("archive", "filez") {
        let (header_bytes, _compressed_payload) = filehdr::split_framed(&bytes).unwrap();
        let (header, size) = FileHeader::parse_archive(header_bytes).unwrap();
        let (payload, expected_header) = &expected[&name];
        assert_eq!(&header, expected_header);
        assert_eq!(size, payload.len() as u64);
    }
}

#[test]
fn bare_user_payloads_are_the_raw_content() {
    let expected = expected_content();
    for (name, bytes) in repo_objects("bare-user", "file") {
        let (payload, header) = &expected[&name];
        // Symlink objects are materialized specially in bare-user mode; only
        // regular-file objects store the raw payload.
        if !header.is_symlink() {
            assert_eq!(&bytes, payload, "raw payload for {name}");
        }
    }
}
