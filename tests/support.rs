//! Fixture helpers for the golden-object tests.
//!
//! The golden tests are in two crates, `ostrya-gvariant` and `ostrya-core`.
//! Integration tests in different crates cannot share a normal module, so each
//! test file includes this file with a `#[path]` module declaration. Each test
//! binary uses only a part of this file, so the file allows `dead_code`.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use ostrya_gvariant::{ArrayIter, Variant};

/// The GVariant signatures of the metadata objects that the `ostree` command
/// writes.
pub const COMMIT_SIG: &str = "(a{sv}aya(say)sstayay)";
pub const DIRTREE_SIG: &str = "(a(say)a(sayay))";
pub const DIRMETA_SIG: &str = "(uuua(ayay))";
pub const ARCHIVE_FILE_HEADER_SIG: &str = "(tuuuusa(ayay))";

/// The ostree object shapes as borrowed views.
///
/// Strings and checksums borrow the object buffer. Arrays decode lazily. These
/// tuple shapes are the shapes of the `ostrya-core` object structs. The golden
/// tests decode into them and re-encode them to check byte identity.
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

/// Returns a deterministic 32-byte checksum payload made from `seed`.
///
/// The tests use it for fixture values whose exact bytes are not important.
pub fn checksum(seed: u8) -> Vec<u8> {
    (0..32).map(|i| seed.wrapping_add(i)).collect()
}

/// Returns the root directory of the fixture repositories.
///
/// The `ostree` command generated the fixtures. The root holds the fixture
/// repositories, as directories and as tarballs, and other fixture files.
pub fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/generated")
}

/// Unpacks the fixture tarball `<fixture_root>/<name>.tar` and returns its
/// directory.
///
/// The returned directory holds the `repo/` of the fixture. The unpack keeps
/// the xattrs and runs one time for each test process.
///
/// The bare-user family fixtures store the logical metadata of each file in a
/// `user.ostreemeta` xattr. Git does not track xattrs, so these fixtures ship
/// as tarballs (see tests/fixtures/generate.sh). The function memoizes the
/// unpack. The unpacked files stay for the life of the process, so the
/// returned paths stay valid for the whole test run.
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

/// A loose object at `<mode>/repo/objects/<prefix>/<stem>.<ext>`.
pub struct LooseObject {
    /// The directory name of the repository mode, for example `archive` or
    /// `bare-user`.
    pub mode: String,
    /// The two-character fanout prefix (the first checksum byte in hex).
    pub prefix: String,
    /// The file name with no extension (the remaining checksum hex).
    pub stem: String,
    /// The extension with no leading dot.
    pub ext: String,
    /// The absolute path of the object file.
    pub path: PathBuf,
}

impl LooseObject {
    /// Returns the full checksum hex, made from the fanout prefix and the stem.
    pub fn hex(&self) -> String {
        format!("{}{}", self.prefix, self.stem)
    }
}

/// Returns each loose object of the deterministic golden fixture repositories.
///
/// The golden data is in two fixtures: the `archive` plain tree and the
/// `bare-user` tarball. The function unpacks the tarball on demand, so its
/// `user.ostreemeta` xattrs are present.
///
/// Other tests cross-check the other fixtures:
///
/// - The invoking user owns `bare` (see the `bare_owner` note in MANIFEST).
///   The write-path test checks it against the `ostree` command at runtime.
/// - `canon` and `xattr` are ingest fixtures with a different tree shape. The
///   ingest tests of the `ostrya` crate check them.
///
/// The golden tests walk the fixture directories only through this function,
/// so a broken layout shows in one place.
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

/// Returns each loose object with the extension `extension`, and its bytes.
///
/// If `mode` is `Some`, the function returns only the objects of that
/// repository mode. If no object matches, the function panics, because a
/// silent empty walk can hide a regression.
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

/// Returns the GVariant file header of a `.filez` object.
///
/// The framing envelope of the object is
/// `[4-byte big-endian header length][4 zero bytes][header][deflate payload]`.
/// The function asserts these conditions:
///
/// - The object holds at least the 8 bytes of the length and the padding.
/// - The four padding bytes are zero.
/// - The header length stays within the object.
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
