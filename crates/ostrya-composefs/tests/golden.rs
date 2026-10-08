#![forbid(unsafe_code)]

//! Golden-image test of the composefs image writer.
//!
//! The test builds the tree from a `composefs-info dump` and writes its image.
//! The image must be byte-identical to the image of the `ostree` command. Its
//! fs-verity digest must equal the digest in the fixture MANIFEST, which is the
//! value that the `ostree` command stored in `ostree.composefs.digest.v0`.
//!
//! The test checks four fixtures:
//!
//! - `tree.cfs` is a minimal tree.
//! - `tree-rich.cfs` has shared xattrs, inline xattrs, a multi-block
//!   directory, and a long inline symlink. A fault in one of these paths makes
//!   a committed test fail.
//! - `tree-noverity.cfs` and `tree-rich-noverity.cfs` are the images that the
//!   `ostree` command writes for the same trees with
//!   `checkout --composefs-noverity`.
//!
//! In a `-noverity` image, each backed file has an empty
//! `trusted.overlay.metacopy` value. This one value is shared, so it moves into
//! the shared-xattr table and the inode and xattr offsets change. A dump prints
//! `-` in the digest column for these files.

use std::path::{Path, PathBuf};

use ostrya_composefs::{
    Content, Directory, FsVerityHasher, Metadata, Node, Regular, Symlink, build_image,
    write_image_to,
};

/// A sink that records the total byte count and the largest single write.
///
/// The emitting pass only appends, so the largest write is the upper limit of
/// the data that the writer holds at one time.
#[derive(Default)]
struct CountingSink {
    total: usize,
    largest: usize,
    digest: FsVerityHasher,
}

impl std::io::Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.total += buf.len();
        self.largest = self.largest.max(buf.len());
        self.digest.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The largest single write of the emitting pass.
///
/// If each child name is at most 65535 bytes, no write is larger than the
/// largest xattr value. The EROFS value-length field holds that length in two
/// bytes.
const MAX_WRITE: usize = u16::MAX as usize;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/generated/composefs")
}

fn manifest_value(key: &str) -> Option<String> {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/generated/MANIFEST"),
    )
    .ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .map(|v| v.trim().to_owned())
}

fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "expected 64 hex chars, got {s:?}");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digit");
    }
    out
}

fn to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;

/// Returns the `name=value` xattr tokens at the end of a dump line.
///
/// The tokens are the fields from index 11 on. The fixture values are ASCII
/// with no space and no `=`, so the function splits each token at its first
/// `=` and keeps both halves unchanged.
fn parse_xattrs(fields: &[&str]) -> Vec<(Vec<u8>, Vec<u8>)> {
    fields
        .iter()
        .skip(11)
        .filter_map(|tok| tok.split_once('='))
        .map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec()))
        .collect()
}

/// Builds a node from the fields of one `composefs-info dump` line.
fn node_from_fields(fields: &[&str]) -> Node {
    let size: u64 = fields[1].parse().unwrap();
    let mode = u32::from_str_radix(fields[2], 8).unwrap();
    let uid: u32 = fields[4].parse().unwrap();
    let gid: u32 = fields[5].parse().unwrap();
    let payload = fields[8];
    let digest = fields[10];

    let meta = Metadata {
        mode,
        uid,
        gid,
        mtime: (0, 0),
        xattrs: parse_xattrs(fields),
    };

    match mode & S_IFMT {
        S_IFDIR => Node::Directory(Directory::new(meta)),
        S_IFLNK => Node::Symlink(Symlink {
            meta,
            target: payload.as_bytes().to_vec(),
        }),
        S_IFREG => {
            let content = if size == 0 {
                Content::Empty
            } else {
                Content::Backed {
                    size,
                    redirect: format!("/{payload}"),
                    verity: (digest != "-").then(|| hex32(digest)),
                }
            };
            Node::Regular(Regular { meta, content })
        }
        other => panic!("unexpected mode type {other:#o}"),
    }
}

fn insert_at(root: &mut Directory, path: &str, node: Node) {
    let comps: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let (name, dirs) = comps.split_last().unwrap();
    let mut cur = root;
    for d in dirs {
        cur = match cur.children.get_mut(d.as_bytes()) {
            Some(Node::Directory(sub)) => sub,
            _ => panic!("parent directory {d:?} missing for {path:?}"),
        };
    }
    cur.children.insert(name.as_bytes().to_vec(), node);
}

/// Builds the tree from a `composefs-info dump`.
fn tree_from_dump(dump: &str) -> Directory {
    let mut root: Option<Directory> = None;
    for line in dump.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let path = fields[0];
        if path == "/" {
            let mode = u32::from_str_radix(fields[2], 8).unwrap();
            root = Some(Directory::new(Metadata {
                mode,
                uid: fields[4].parse().unwrap(),
                gid: fields[5].parse().unwrap(),
                mtime: (0, 0),
                xattrs: parse_xattrs(&fields),
            }));
        } else {
            let node = node_from_fields(&fields);
            insert_at(root.as_mut().expect("root line first"), path, node);
        }
    }
    root.expect("dump had a root")
}

/// Builds the tree from `<stem>.dump` and checks its image against the fixtures.
///
/// The image bytes must equal `<stem>.cfs`. The fs-verity digest must equal the
/// MANIFEST value at `digest_key`. If the fixtures are absent, the function
/// returns at once. This occurs in a checkout without the `ostree` command.
fn check_fixture(stem: &str, digest_key: &str) {
    let dir = fixture_dir();
    let (Ok(dump), Ok(golden)) = (
        std::fs::read_to_string(dir.join(format!("{stem}.dump"))),
        std::fs::read(dir.join(format!("{stem}.cfs"))),
    ) else {
        eprintln!("composefs fixture {stem} absent; skipping");
        return;
    };

    let root = tree_from_dump(&dump);
    let image = build_image(&root).expect("build the image");

    assert_eq!(
        image.bytes.len(),
        golden.len(),
        "{stem}: image length {} != golden {}",
        image.bytes.len(),
        golden.len()
    );
    // The failure message gives the offset of the first different byte.
    if let Some(pos) = image.bytes.iter().zip(&golden).position(|(a, b)| a != b) {
        panic!(
            "{stem}: image diverges from golden at byte {pos:#x}: got {:#04x}, want {:#04x}",
            image.bytes[pos], golden[pos]
        );
    }

    // The streaming writer writes the same image and returns the same digest.
    // It writes the image in small pieces, with no buffer of the image.
    let mut sink = CountingSink::default();
    let streamed = write_image_to(&root, &mut sink).expect("stream the image");
    assert_eq!(
        sink.total,
        image.bytes.len(),
        "{stem}: streamed length differs from the buffered image"
    );
    // The test checks the largest write against two limits. MAX_WRITE is the
    // limit for a tree with short child names. Each fixture image is smaller
    // than MAX_WRITE, so on these fixtures the image length is the limit that
    // applies.
    assert!(
        sink.largest <= MAX_WRITE,
        "{stem}: one write of {} bytes exceeds the largest field",
        sink.largest
    );
    assert!(
        sink.largest < image.bytes.len(),
        "{stem}: one write of {} bytes carried the whole image",
        sink.largest
    );
    assert_eq!(
        streamed, image.fs_verity,
        "{stem}: streamed digest differs from the buffered digest"
    );
    assert_eq!(
        sink.digest.finalize(),
        streamed,
        "{stem}: the digest differs from the digest of the bytes the sink received"
    );

    let expected = manifest_value(digest_key).unwrap_or_else(|| panic!("MANIFEST {digest_key}"));
    if !expected.is_empty() {
        assert_eq!(
            to_hex(&image.fs_verity),
            expected,
            "{stem}: fs-verity digest mismatch"
        );
    }
}

#[test]
fn image_matches_golden_bytes_and_digest() {
    check_fixture("tree", "composefs_digest");
}

#[test]
fn noverity_image_matches_golden_bytes_and_digest() {
    check_fixture("tree-noverity", "composefs_noverity_digest");
}

#[test]
fn rich_image_matches_golden_bytes_and_digest() {
    check_fixture("tree-rich", "composefs_rich_digest");
}

#[test]
fn rich_noverity_image_matches_golden_bytes_and_digest() {
    check_fixture("tree-rich-noverity", "composefs_rich_noverity_digest");
}
