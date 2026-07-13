//! Shared fixture-walking helpers for the golden-object tests.
//!
//! The golden tests live in two crates (`ostrya-gvariant` and `ostrya-core`),
//! and integration tests in different crates cannot share an ordinary module,
//! so each test file includes this one with a `#[path]` module declaration.
//! Because each test binary uses only part of the module, the whole file
//! carries a `dead_code` allowance.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use ostrya_gvariant::{ArrayIter, Variant};

/// GVariant signatures of the metadata objects the `ostree` tool writes.
pub const COMMIT_SIG: &str = "(a{sv}aya(say)sstayay)";
pub const DIRTREE_SIG: &str = "(a(say)a(sayay))";
pub const DIRMETA_SIG: &str = "(uuua(ayay))";
pub const ARCHIVE_FILE_HEADER_SIG: &str = "(tuuuusa(ayay))";

/// The ostree object shapes as borrowed views: strings and checksums borrow
/// the object buffer, arrays decode lazily. These are the shapes the object
/// structs formalize in a later phase; the golden tests decode into them and
/// re-encode to check byte identity.
pub type DirMetaView<'a> = (u32, u32, u32, ArrayIter<'a, (&'a [u8], &'a [u8])>);
pub type DirTreeView<'a> = (
    ArrayIter<'a, (&'a str, &'a [u8])>,
    ArrayIter<'a, (&'a str, &'a [u8], &'a [u8])>,
);
pub type ArchiveHeaderView<'a> = (
    u64,
    u32,
    u32,
    u32,
    u32,
    &'a str,
    ArrayIter<'a, (&'a [u8], &'a [u8])>,
);
pub type MetadataView<'a> = ArrayIter<'a, (&'a str, Variant<'a>)>;
pub type CommitView<'a> = (
    MetadataView<'a>,
    &'a [u8],
    ArrayIter<'a, (&'a str, &'a [u8])>,
    &'a str,
    &'a str,
    u64,
    &'a [u8],
    &'a [u8],
);

/// A 32-byte checksum payload seeded deterministically, for building fixture
/// values whose exact bytes do not matter.
pub fn checksum(seed: u8) -> Vec<u8> {
    (0..32).map(|i| seed.wrapping_add(i)).collect()
}

/// Root of the tool-generated fixture repositories, one subdirectory per mode.
pub fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/generated")
}

/// Unpack the xattr-preserving fixture tarball `<fixture_root>/<name>.tar` once
/// per test process and return the directory holding its `repo/`.
///
/// The bare-user-family fixtures store each file's logical metadata in a
/// `user.ostreemeta` xattr, which git does not track, so they ship as tarballs
/// (see tests/fixtures/generate.sh). The unpack is memoized and persists for the
/// process, so the returned paths stay valid for the whole test run.
pub fn unpack_fixture(name: &str) -> PathBuf {
    static REGISTRY: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = registry.lock().unwrap();
    if let Some(dir) = map.get(name) {
        return dir.clone();
    }
    let dir = std::env::temp_dir()
        .join(format!("ostrya-fixtures-{}", std::process::id()))
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create fixture unpack dir");
    let tar = fixture_root().join(format!("{name}.tar"));
    let status = Command::new("tar")
        .args(["--xattrs", "--xattrs-include=user.*", "-xf"])
        .arg(&tar)
        .arg("-C")
        .arg(&dir)
        .status()
        .expect("run tar to unpack fixture");
    assert!(status.success(), "tar failed to unpack {}", tar.display());
    map.insert(name.to_owned(), dir.clone());
    dir
}

/// A loose object located at `<mode>/repo/objects/<prefix>/<stem>.<ext>`.
pub struct LooseObject {
    /// Repository-mode directory name, for example `archive` or `bare-user`.
    pub mode: String,
    /// Two-character fanout prefix (the first checksum byte in hex).
    pub prefix: String,
    /// Filename without the extension (the remaining checksum hex).
    pub stem: String,
    /// Extension without the leading dot.
    pub ext: String,
    /// Absolute path to the object file.
    pub path: PathBuf,
}

impl LooseObject {
    /// The full checksum hex, reassembled from the fanout prefix and the stem.
    pub fn hex(&self) -> String {
        format!("{}{}", self.prefix, self.stem)
    }
}

/// Walk the deterministic golden fixture repositories and return each loose
/// object they hold.
///
/// The golden data these walkers compare against lives in two fixtures: the
/// `archive` plain tree and the `bare-user` tarball (unpacked on demand, so its
/// `user.ostreemeta` xattrs are present). The other fixtures are cross-checked
/// elsewhere: `bare` is owned by the invoking user (see the `bare_owner` note in
/// MANIFEST) and the write-path test checks it against the tool at runtime, and
/// `canon`/`xattr` are Phase 7c ingest fixtures with a different tree shape,
/// checked by the `ostrya` crate's ingest tests.
///
/// This is the single fixture-directory traversal for the golden tests: a
/// broken layout surfaces here in one place rather than in each test.
pub fn loose_objects() -> Vec<LooseObject> {
    let sources = [
        ("archive".to_owned(), fixture_root().join("archive")),
        ("bare-user".to_owned(), unpack_fixture("bare-user")),
    ];
    let mut found = Vec::new();
    for (mode, base) in sources {
        let objects = base.join("repo/objects");
        if !objects.is_dir() {
            continue;
        }
        for fanout in fs::read_dir(&objects).unwrap() {
            let fanout = fanout.unwrap().path();
            if !fanout.is_dir() {
                continue;
            }
            let prefix = fanout.file_name().unwrap().to_str().unwrap().to_owned();
            for object in fs::read_dir(&fanout).unwrap() {
                let path = object.unwrap().path();
                let (Some(stem), Some(ext)) = (
                    path.file_stem().and_then(|s| s.to_str()),
                    path.extension().and_then(|e| e.to_str()),
                ) else {
                    continue;
                };
                found.push(LooseObject {
                    mode: mode.clone(),
                    prefix: prefix.clone(),
                    stem: stem.to_owned(),
                    ext: ext.to_owned(),
                    path: path.clone(),
                });
            }
        }
    }
    found
}

/// Every loose object whose extension is `extension`, with its bytes read.
/// When `mode` is `Some`, only objects from that repository mode are returned.
///
/// Panics if none are present, guarding against a silently empty walk masking
/// a regression.
pub fn objects_with_extension(extension: &str, mode: Option<&str>) -> Vec<(LooseObject, Vec<u8>)> {
    let found: Vec<(LooseObject, Vec<u8>)> = loose_objects()
        .into_iter()
        .filter(|object| object.ext == extension && mode.is_none_or(|m| object.mode == m))
        .map(|object| {
            let bytes = fs::read(&object.path).unwrap();
            (object, bytes)
        })
        .collect();
    let scope = mode.map_or_else(|| "among the fixtures".to_owned(), |m| format!("in {m}"));
    assert!(!found.is_empty(), "no .{extension} objects {scope}");
    found
}

/// Split a `.filez` object's framing envelope and return the GVariant file
/// header slice.
///
/// The envelope is
/// `[4-byte big-endian header length][4 zero bytes][header][deflate payload]`.
/// This asserts the object holds the envelope, the four padding bytes are
/// zero, and the header length stays within the object.
pub fn filez_header<'a>(bytes: &'a [u8], context: &Path) -> &'a [u8] {
    assert!(
        bytes.len() >= 8,
        "{}: truncated .filez framing",
        context.display()
    );
    let header_len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(
        &bytes[4..8],
        [0; 4],
        "{}: .filez framing padding is nonzero",
        context.display()
    );
    let end = 8usize
        .checked_add(header_len)
        .filter(|&end| end <= bytes.len())
        .unwrap_or_else(|| {
            panic!(
                "{}: .filez header length {header_len} overflows object",
                context.display()
            )
        });
    &bytes[8..end]
}
