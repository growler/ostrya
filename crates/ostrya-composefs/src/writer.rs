//! The writer of composefs EROFS images, format version 0.
//!
//! The writer makes two passes over one inode list. The sizing pass counts the
//! bytes and records these offsets:
//!
//! - the offset of each inode
//! - the end of the inode table
//! - the offset of each shared-xattr entry
//! - the offset of the block data of each inode.
//!
//! The EROFS node ids and the shared-xattr references come from these
//! offsets. The emitting pass reads them from the layout of the sizing pass.
//!
//! The emitting pass only appends and patches no byte that it wrote. It writes
//! each byte to the [`std::io::Write`] sink, gives it to the fs-verity hasher,
//! and counts it. The sink needs no seek, and the writer gets the digest
//! without a copy of the image.
//!
//! The sizing pass refuses a child name that is empty, is `.` or `..`, holds
//! `/`, or has more than 255 bytes. It also refuses a symlink target that does
//! not fit its inode block.

use std::collections::VecDeque;
use std::io::{self, Write};

use crate::Error;
use crate::fsverity::FsVerityHasher;
use crate::tree::{Content, Directory, Metadata, Node, Regular, Symlink};
use crate::xxhash::xxh32;

const BLOCK: usize = 4096;
const SLOT: usize = 32;

const EROFS_MAGIC: u32 = 0xE0F5_E1E2;
const COMPOSEFS_MAGIC: u32 = 0xD078_629A;
const COMPOSEFS_HEADER_VERSION: u32 = 1;
const COMPOSEFS_VERSION_V0: u32 = 0;
const BLKSZBITS: u8 = 12;
// feature_compat: MTIME (0x02) | XATTR_FILTER (0x04).
const FEATURE_COMPAT: u32 = 0x02 | 0x04;
const FLAGS_HAS_ACL: u32 = 1;

const XATTR_FILTER_SEED: u32 = 0x25BB_E08F;

// Inode datalayout values, already positioned in the format field's bits 1..3.
const LAYOUT_FLAT_PLAIN: u16 = 0;
const LAYOUT_FLAT_INLINE: u16 = 4;
const LAYOUT_CHUNK_BASED: u16 = 8;

const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;
const S_IFCHR: u16 = 0o020000;
const PERM_MASK: u16 = 0o7777;

// EROFS directory-entry file types.
const FT_REG: u8 = 1;
const FT_DIR: u8 = 2;
const FT_CHR: u8 = 3;
const FT_LNK: u8 = 7;

// EROFS xattr name prefixes indexed by name_index. Index 0 is the empty
// fallback. Indexes 2 and 3 are full POSIX ACL names. Index 5 (`lustre.`) is
// not in the composefs V0 prefix table. The writer skips it, so a `lustre.*`
// name takes the empty fallback.
const XATTR_PREFIXES: [&[u8]; 7] = [
    b"",
    b"user.",
    b"system.posix_acl_access",
    b"system.posix_acl_default",
    b"trusted.",
    b"lustre.",
    b"security.",
];
const XATTR_INDEX_ACL_ACCESS: u8 = 2;
const XATTR_INDEX_ACL_DEFAULT: u8 = 3;

/// The maximum number of shared-xattr references in one inode.
///
/// If an inode has more repeated xattrs, it keeps the rest inline. The cap
/// comes from an observation of the images that the `ostree` command writes.
const MAX_SHARED_XATTRS: usize = 128;

const XATTR_METACOPY: &[u8] = b"trusted.overlay.metacopy";
const XATTR_REDIRECT: &[u8] = b"trusted.overlay.redirect";
const XATTR_OPAQUE_ROOT: &[u8] = b"trusted.overlay.opaque";
const XATTR_OVERLAY_PREFIX: &[u8] = b"trusted.overlay.";
const XATTR_OVERLAY_ESCAPED_PREFIX: &[u8] = b"trusted.overlay.overlay.";

fn round_up(n: usize, align: usize) -> usize {
    n.div_ceil(align) * align
}

fn block_offset(pos: usize) -> usize {
    pos % BLOCK
}

fn bytes_to_block_boundary(pos: usize) -> Option<usize> {
    match block_offset(pos) {
        0 => None,
        off => Some(BLOCK - off),
    }
}

// --- Chunk sizing for backed (external) files -----------------------------

fn chunk_bitsize(size: u64) -> u32 {
    let mut bits = if size > 1 {
        64 - (size - 1).leading_zeros()
    } else {
        1
    };
    let block_bits = BLKSZBITS as u32;
    if bits < block_bits {
        bits = block_bits;
    }
    if bits - block_bits > 31 {
        bits = 31 + block_bits;
    }
    bits
}

fn chunk_format(size: u64) -> u32 {
    chunk_bitsize(size) - BLKSZBITS as u32
}

fn chunk_count(size: u64) -> u32 {
    let bits = chunk_bitsize(size);
    size.div_ceil(1u64 << bits) as u32
}

/// Returns the 36-byte overlay metacopy record for the digest `verity`.
fn metacopy_record(verity: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(36);
    v.push(0); // version
    v.push(36); // record length
    v.push(0); // flags
    v.push(1); // digest algorithm: SHA-256
    v.extend_from_slice(verity);
    v
}

// --- Extended attributes --------------------------------------------------

#[derive(Clone)]
struct LocalXattr {
    prefix: u8,
    suffix: Vec<u8>,
    value: Vec<u8>,
}

impl LocalXattr {
    fn full_key(&self) -> Vec<u8> {
        [XATTR_PREFIXES[self.prefix as usize], &self.suffix].concat()
    }

    /// Compares two xattrs in the sort order of composefs.
    ///
    /// The order is by full key name, then by value length, then by value
    /// bytes.
    fn cmp_by_full_key(&self, other: &Self) -> std::cmp::Ordering {
        self.full_key().cmp(&other.full_key()).then_with(|| {
            self.value
                .len()
                .cmp(&other.value.len())
                .then_with(|| self.value.cmp(&other.value))
        })
    }

    fn entry_size(&self) -> usize {
        round_up(4 + self.suffix.len() + self.value.len(), 4)
    }
}

#[derive(Clone, Default)]
struct XattrSet {
    local: Vec<LocalXattr>,
    shared: Vec<u32>,
    filter: u32,
}

impl XattrSet {
    fn add(&mut self, name: &[u8], value: &[u8]) {
        for idx in (0..XATTR_PREFIXES.len()).rev() {
            // lustre. (index 5) is not in the composefs V0 prefix table.
            if idx == 5 {
                continue;
            }
            if let Some(suffix) = name.strip_prefix(XATTR_PREFIXES[idx]) {
                // The EROFS length field is a `u16` for the value and a `u8`
                // for the name. A longer value or name gets a truncated length
                // in front of its full bytes, so the writer panics on it.
                // `Metadata::xattrs` states both limits.
                assert!(
                    value.len() <= u16::MAX as usize,
                    "an xattr value of {} bytes exceeds the EROFS length field",
                    value.len()
                );
                assert!(
                    suffix.len() <= u8::MAX as usize,
                    "an xattr name of {} bytes exceeds the EROFS length field",
                    suffix.len()
                );
                self.filter |= 1 << (xxh32(suffix, XATTR_FILTER_SEED + idx as u32) % 32);
                self.local.push(LocalXattr {
                    prefix: idx as u8,
                    suffix: suffix.to_vec(),
                    value: value.to_vec(),
                });
                return;
            }
        }
        unreachable!("empty prefix matches every name");
    }

    /// Returns the byte size of the xattr area of the inode, or 0 if it has no
    /// xattrs.
    fn byte_size(&self) -> usize {
        if self.filter == 0 {
            return 0;
        }
        // header (12) + shared references (4 each) + local entries
        12 + self.shared.len() * 4 + self.local.iter().map(LocalXattr::entry_size).sum::<usize>()
    }

    fn icount(&self) -> u16 {
        match self.byte_size() {
            0 => 0,
            n => {
                let icount = 1 + (n - 12) / 4;
                // The EROFS count field is a `u16`. A larger area gets a
                // truncated count, so the writer panics on it.
                // `Metadata::xattrs` states the limit.
                assert!(
                    icount <= u16::MAX as usize,
                    "an xattr area of {n} bytes exceeds the EROFS count field"
                );
                icount as u16
            }
        }
    }

    fn write(&self, out: &mut dyn Output) {
        if self.filter == 0 {
            return;
        }
        // `share_xattrs` caps the list at `MAX_SHARED_XATTRS`, so the count
        // fits in its one-byte field.
        debug_assert!(self.shared.len() <= MAX_SHARED_XATTRS);
        out.write(&(!self.filter).to_le_bytes()); // name filter
        out.write(&[self.shared.len() as u8]); // shared count
        out.write(&[0u8; 7]); // reserved
        for &idx in &self.shared {
            let xattr_ref = out.get_xattr_v1(idx as usize);
            out.write(&xattr_ref.to_le_bytes());
        }
        for attr in &self.local {
            out.write(&[attr.suffix.len() as u8, attr.prefix]);
            out.write(&(attr.value.len() as u16).to_le_bytes());
            out.write(&attr.suffix);
            out.write(&attr.value);
            out.pad_to(4);
        }
    }
}

// --- Inodes ---------------------------------------------------------------

struct DirEnt {
    name: Vec<u8>,
    inode: usize,
    file_type: u8,
}

struct DirData {
    blocks: Vec<Vec<DirEnt>>,
    inline: Vec<DirEnt>,
    size: u64,
    nlink: usize,
}

impl DirData {
    fn from_entries(entries: Vec<DirEnt>) -> Self {
        let mut blocks: Vec<Vec<DirEnt>> = Vec::new();
        let mut rest: Vec<DirEnt> = Vec::new();
        let mut n_bytes: u64 = 0;
        let mut nlink = 0usize;

        for entry in entries {
            let entry_size = (12 + entry.name.len()) as u64;
            if entry.file_type == FT_DIR {
                nlink += 1;
            }
            n_bytes += entry_size;
            if n_bytes <= 4096 {
                rest.push(entry);
            } else {
                blocks.push(std::mem::take(&mut rest));
                rest.push(entry);
                n_bytes = entry_size;
            }
        }

        // The inline tail holds at most 2048 bytes. A longer tail goes into a
        // block of its own.
        if n_bytes > 2048 {
            blocks.push(std::mem::take(&mut rest));
            n_bytes = 0;
        }

        let size = 4096 * blocks.len() as u64 + n_bytes;
        Self {
            blocks,
            inline: rest,
            size,
            nlink,
        }
    }
}

enum Kind {
    Dir(DirData),
    EmptyReg,
    Backed { size: u64, inline_tail: usize },
    Symlink { target: Vec<u8> },
    Whiteout,
}

struct Inode {
    perms: u16,
    uid: u32,
    gid: u32,
    mtime: (u64, u32),
    xattrs: XattrSet,
    kind: Kind,
}

impl Inode {
    fn type_bits(&self) -> u16 {
        match self.kind {
            Kind::Dir(_) => S_IFDIR,
            Kind::EmptyReg | Kind::Backed { .. } => S_IFREG,
            Kind::Symlink { .. } => S_IFLNK,
            Kind::Whiteout => S_IFCHR,
        }
    }

    fn inode_mode(&self) -> u16 {
        self.type_bits() | (self.perms & PERM_MASK)
    }

    /// Returns `(datalayout, i_u, size, nlink)` of the inode for the block-data
    /// offset `block_start`.
    fn meta(&self, block_start: usize) -> (u16, u32, u64, usize) {
        match &self.kind {
            Kind::Dir(dir) => {
                let blkaddr = (block_start / BLOCK) as u32;
                let (layout, i_u) = if dir.inline.is_empty() {
                    (LAYOUT_FLAT_PLAIN, blkaddr)
                } else if !dir.blocks.is_empty() {
                    (LAYOUT_FLAT_INLINE, blkaddr)
                } else {
                    (LAYOUT_FLAT_INLINE, 0)
                };
                (layout, i_u, dir.size, dir.nlink)
            }
            Kind::EmptyReg => (LAYOUT_FLAT_PLAIN, 0, 0, 1),
            Kind::Backed { size, .. } => (LAYOUT_CHUNK_BASED, chunk_format(*size), *size, 1),
            Kind::Symlink { target } => (LAYOUT_FLAT_INLINE, 0, target.len() as u64, 1),
            Kind::Whiteout => (LAYOUT_FLAT_PLAIN, 0, 0, 1),
        }
    }

    fn fits_in_compact(&self, min_mtime: (u64, u32), size: u64, nlink: usize) -> bool {
        self.mtime == min_mtime
            && nlink <= u16::MAX as usize
            && self.uid <= u16::MAX as u32
            && self.gid <= u16::MAX as u32
            && size <= u32::MAX as u64
    }

    fn write(&self, out: &mut dyn Output, idx: usize, min_mtime: (u64, u32)) {
        let block_start = out.get_block_start(idx);
        let (layout, i_u, size, nlink) = self.meta(block_start);
        let xattr_size = self.xattrs.byte_size();
        let use_compact = self.fits_in_compact(min_mtime, size, nlink);
        let header_size = if use_compact { 32 } else { 64 };

        out.pad_to(SLOT);

        // The inline chunk index of a chunk-based file gets the same tail
        // padding as inline data.
        if let Kind::Backed { inline_tail, .. } = &self.kind
            && *inline_tail > 0
        {
            let inline_start = out.len() + header_size + xattr_size;
            if let Some(rem) = bytes_to_block_boundary(inline_start)
                && rem < *inline_tail
            {
                out.write_zeros(round_up(rem, SLOT));
            }
        }

        if layout == LAYOUT_FLAT_INLINE {
            let head = header_size + xattr_size;
            let inline_size = (size % BLOCK as u64) as usize;
            if matches!(self.kind, Kind::Symlink { .. }) {
                let current = out.len();
                if block_offset(current) + head + inline_size > BLOCK
                    && let Some(pad) = bytes_to_block_boundary(current)
                {
                    out.write_zeros(pad);
                }
            } else {
                let inline_start = out.len() + head;
                if let Some(rem) = bytes_to_block_boundary(inline_start)
                    && rem < inline_size
                {
                    out.write_zeros(round_up(rem, SLOT));
                }
            }
        }

        let icount = self.xattrs.icount();
        let mode = self.inode_mode();
        out.note_inode();

        if use_compact {
            out.write(&(layout).to_le_bytes()); // format: compact | layout
            out.write(&icount.to_le_bytes());
            out.write(&mode.to_le_bytes());
            out.write(&(nlink as u16).to_le_bytes());
            out.write(&(size as u32).to_le_bytes());
            out.write(&0u32.to_le_bytes()); // reserved
            out.write(&i_u.to_le_bytes());
            out.write(&(idx as u32).to_le_bytes()); // ino
            out.write(&(self.uid as u16).to_le_bytes());
            out.write(&(self.gid as u16).to_le_bytes());
            out.write(&[0u8; 4]); // reserved2
        } else {
            out.write(&(1 | layout).to_le_bytes()); // format: extended | layout
            out.write(&icount.to_le_bytes());
            out.write(&mode.to_le_bytes());
            out.write(&0u16.to_le_bytes()); // reserved
            out.write(&size.to_le_bytes());
            out.write(&i_u.to_le_bytes());
            out.write(&(idx as u32).to_le_bytes()); // ino
            out.write(&self.uid.to_le_bytes());
            out.write(&self.gid.to_le_bytes());
            out.write(&self.mtime.0.to_le_bytes());
            out.write(&self.mtime.1.to_le_bytes());
            out.write(&(nlink as u32).to_le_bytes());
            out.write(&[0u8; 16]); // reserved2
        }

        self.xattrs.write(out);
        self.write_inline(out);
        out.pad_to(SLOT);
    }

    fn write_inline(&self, out: &mut dyn Output) {
        match &self.kind {
            Kind::Dir(dir) => write_dir_block(out, &dir.inline),
            Kind::Backed { inline_tail, .. } => {
                for _ in 0..(inline_tail / 4) {
                    out.write(&[0xff, 0xff, 0xff, 0xff]);
                }
            }
            Kind::Symlink { target } => out.write(target),
            _ => {}
        }
    }

    /// Writes the block data of the inode.
    ///
    /// A directory is the only inode with block data. Every other inode holds
    /// its content inline.
    fn write_blocks(&self, out: &mut dyn Output) {
        if let Kind::Dir(dir) = &self.kind {
            for block in &dir.blocks {
                write_dir_block(out, block);
                out.pad_to(BLOCK);
            }
        }
    }
}

fn write_dir_block(out: &mut dyn Output, block: &[DirEnt]) {
    let mut nameoff = 12 * block.len();
    for entry in block {
        let nid = out.get_nid(entry.inode);
        out.write(&nid.to_le_bytes());
        out.write(&(nameoff as u16).to_le_bytes());
        out.write(&[entry.file_type, 0]);
        nameoff += entry.name.len();
    }
    for entry in block {
        out.write(&entry.name);
    }
}

// --- Inode collection (breadth-first, with whiteout-stub injection) --------

enum Source<'a> {
    Real(&'a Node),
    Whiteout,
}

/// Returns the children of `dir` in name order, with the root whiteout stubs.
///
/// If `is_root` is `true`, the list gets the 256 overlay whiteout stubs `00` to
/// `ff`. A child with a stub name stays, and the function adds no stub for that
/// name.
fn merged_children(dir: &Directory, is_root: bool) -> Vec<(Vec<u8>, Source<'_>)> {
    let mut out: Vec<(Vec<u8>, Source)> = dir
        .children
        .iter()
        .map(|(name, node)| (name.clone(), Source::Real(node)))
        .collect();
    if is_root {
        for i in 0u8..=255 {
            let name = format!("{i:02x}").into_bytes();
            if !dir.children.contains_key(&name) {
                out.push((name, Source::Whiteout));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

struct Collector<'a> {
    inodes: Vec<Inode>,
    root: &'a Directory,
}

impl<'a> Collector<'a> {
    fn xattrs_of(&self, meta: &Metadata) -> XattrSet {
        let mut set = XattrSet::default();
        add_metadata_xattrs(&mut set, &meta.xattrs);
        set
    }

    fn push_dir(&mut self, meta: &Metadata) -> usize {
        let xattrs = self.xattrs_of(meta);
        self.push(meta, xattrs, Kind::Dir(DirData::from_entries(Vec::new())))
    }

    fn push_regular(&mut self, reg: &Regular) -> usize {
        let mut xattrs = XattrSet::default();
        let kind = match &reg.content {
            Content::Empty => Kind::EmptyReg,
            Content::Backed {
                size,
                redirect,
                verity,
            } => {
                let record = match verity {
                    Some(v) => metacopy_record(v),
                    None => Vec::new(),
                };
                xattrs.add(XATTR_METACOPY, &record);
                xattrs.add(XATTR_REDIRECT, redirect.as_bytes());
                // The writer always writes the chunk index inline. One chunk
                // covers a file of up to 8 TiB, because the chunk size is at
                // most 2^43 bytes. For each file that ostree produces,
                // `chunk_count` is 1. A larger file needs more inline
                // indexes. An index list larger than a block needs a move to
                // a data block, and the writer does not support that move.
                Kind::Backed {
                    size: *size,
                    inline_tail: chunk_count(*size) as usize * 4,
                }
            }
        };
        add_metadata_xattrs(&mut xattrs, &reg.meta.xattrs);
        self.push(&reg.meta, xattrs, kind)
    }

    fn push_symlink(&mut self, link: &Symlink) -> usize {
        let xattrs = self.xattrs_of(&link.meta);
        self.push(
            &link.meta,
            xattrs,
            Kind::Symlink {
                target: link.target.clone(),
            },
        )
    }

    fn push_whiteout(&mut self) -> usize {
        // A whiteout stub is a character device 0:0 with mode 0644. It has the
        // owner and the mtime of the root. Of the root xattrs, it gets only
        // `security.selinux`.
        let mut xattrs = XattrSet::default();
        for (name, value) in &self.root.meta.xattrs {
            if name.as_slice() == b"security.selinux" {
                xattrs.add(name, value);
            }
        }
        self.inodes.push(Inode {
            perms: 0o644,
            uid: self.root.meta.uid,
            gid: self.root.meta.gid,
            mtime: self.root.meta.mtime,
            xattrs,
            kind: Kind::Whiteout,
        });
        self.inodes.len() - 1
    }

    fn push(&mut self, meta: &Metadata, xattrs: XattrSet, kind: Kind) -> usize {
        self.inodes.push(Inode {
            perms: (meta.mode & PERM_MASK as u32) as u16,
            uid: meta.uid,
            gid: meta.gid,
            mtime: meta.mtime,
            xattrs,
            kind,
        });
        self.inodes.len() - 1
    }
}

fn add_metadata_xattrs(set: &mut XattrSet, xattrs: &[(Vec<u8>, Vec<u8>)]) {
    for (name, value) in xattrs {
        if let Some(rest) = name.strip_prefix(XATTR_OVERLAY_PREFIX) {
            let escaped = [XATTR_OVERLAY_ESCAPED_PREFIX, rest].concat();
            set.add(&escaped, value);
        } else {
            set.add(name, value);
        }
    }
}

fn collect(root: &Directory) -> Result<Vec<Inode>, Error> {
    let mut c = Collector {
        inodes: Vec::new(),
        root,
    };
    let root_idx = c.push_dir(&root.meta);

    let mut queue: VecDeque<(&Directory, usize, usize, bool)> = VecDeque::new();
    queue.push_back((root, root_idx, root_idx, true));
    let mut dir_entries: Vec<(usize, Vec<DirEnt>)> = Vec::new();

    while let Some((dir, me, parent, is_root)) = queue.pop_front() {
        // The writer makes `.`, `..`, and the whiteout stubs, so only the
        // names of the tree need the check.
        for name in dir.children.keys() {
            check_name(name)?;
        }

        let mut entries = vec![
            DirEnt {
                name: b".".to_vec(),
                inode: me,
                file_type: FT_DIR,
            },
            DirEnt {
                name: b"..".to_vec(),
                inode: parent,
                file_type: FT_DIR,
            },
        ];

        for (name, source) in merged_children(dir, is_root) {
            let (child, file_type) = match source {
                Source::Real(Node::Directory(sub)) => {
                    let child = c.push_dir(&sub.meta);
                    queue.push_back((sub, child, me, false));
                    (child, FT_DIR)
                }
                Source::Real(Node::Symlink(link)) => (c.push_symlink(link), FT_LNK),
                Source::Real(Node::Regular(reg)) => (c.push_regular(reg), FT_REG),
                Source::Whiteout => (c.push_whiteout(), FT_CHR),
            };
            entries.push(DirEnt {
                name,
                inode: child,
                file_type,
            });
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        dir_entries.push((me, entries));
    }

    for (me, entries) in dir_entries {
        c.inodes[me].kind = Kind::Dir(DirData::from_entries(entries));
    }

    Ok(c.inodes)
}

// --- Shared-xattr promotion ------------------------------------------------

/// Moves each xattr that two or more inodes hold into the shared table.
///
/// Two xattrs are the same if the names and the values are the same. The
/// function returns the table in on-disk order. The writer writes the table
/// after the inode table.
///
/// The table holds each repeated entry. One inode references at most
/// `MAX_SHARED_XATTRS` of them, the lowest keys first. The inode keeps the rest
/// inline.
fn share_xattrs(inodes: &mut [Inode]) -> Vec<LocalXattr> {
    use std::collections::BTreeMap;

    for inode in inodes.iter_mut() {
        inode.xattrs.local.sort_by(|a, b| a.cmp_by_full_key(b));
    }

    let key = |x: &LocalXattr| (x.full_key(), x.value.clone());
    let mut counts: BTreeMap<(Vec<u8>, Vec<u8>), usize> = BTreeMap::new();
    for inode in inodes.iter() {
        for attr in &inode.xattrs.local {
            *counts.entry(key(attr)).or_insert(0) += 1;
        }
    }

    // `shared_keys` holds only the shared entries, in ascending order of full
    // key. The table holds them in descending order, so the largest key gets
    // reference index 0.
    let mut shared_keys: Vec<(Vec<u8>, Vec<u8>)> = counts
        .into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(k, _)| k)
        .collect();
    shared_keys.sort();
    let n = shared_keys.len();

    // full_key+value -> reference index (n-1-i for ascending position i).
    let mut index: BTreeMap<(Vec<u8>, Vec<u8>), u32> = BTreeMap::new();
    let mut table: Vec<LocalXattr> = Vec::with_capacity(n);
    for (i, k) in shared_keys.iter().enumerate() {
        index.insert(k.clone(), (n - 1 - i) as u32);
    }

    // For each shared key, take one `LocalXattr` from any inode. The table
    // gets them in descending on-disk order.
    let mut repr: BTreeMap<(Vec<u8>, Vec<u8>), LocalXattr> = BTreeMap::new();
    for inode in inodes.iter() {
        for attr in &inode.xattrs.local {
            let k = key(attr);
            if index.contains_key(&k) {
                repr.entry(k).or_insert_with(|| attr.clone());
            }
        }
    }
    for k in shared_keys.iter().rev() {
        table.push(repr[k].clone());
    }

    for inode in inodes.iter_mut() {
        let mut promoted = Vec::new();
        // `local` is in full-key order, so `retain` reaches the lowest key
        // first. After the cap, the highest keys stay inline.
        inode.xattrs.local.retain(|attr| {
            if promoted.len() == MAX_SHARED_XATTRS {
                return true;
            }
            match index.get(&key(attr)) {
                Some(&r) => {
                    promoted.push(r);
                    false
                }
                None => true,
            }
        });
        inode.xattrs.shared = promoted;
    }

    table
}

/// The maximum length in bytes of a child name.
///
/// The composefs image format, as the `ostree` command writes and reads it,
/// holds a child name of at most 255 bytes.
const MAX_NAME: usize = 255;

/// Refuses a child name that the image cannot hold.
///
/// The check refuses a name of more than 255 bytes, an empty name, the names
/// `.` and `..`, and a name that holds `/`. The length check comes first, so
/// the other messages show at most 255 bytes of name.
fn check_name(name: &[u8]) -> Result<(), Error> {
    if name.len() > MAX_NAME {
        return Err(Error::Unsupported(format!(
            "a child name of {} bytes is longer than the {MAX_NAME} bytes \
             that a composefs image holds",
            name.len(),
        )));
    }
    match name {
        b"" => Err(Error::Unsupported("a child name is empty".to_owned())),
        b"." | b".." => Err(Error::Unsupported(format!(
            "a child name is `{}`, the name of an entry that the writer adds \
             to each directory",
            name.escape_ascii(),
        ))),
        _ if name.contains(&b'/') => Err(Error::Unsupported(format!(
            "a child name `{}` holds `/`, so it is not one path component",
            name.escape_ascii(),
        ))),
        _ => Ok(()),
    }
}

/// Refuses a symlink whose inode header, xattrs, and target fill a block.
///
/// The image holds the target of a symlink inline in its inode. A target that
/// does not fit the inode block has no place in the image. [`Symlink::target`]
/// states the limit, which comes from an observation of the `ostree` command.
fn check_symlinks(inodes: &[Inode], min_mtime: (u64, u32)) -> Result<(), Error> {
    for inode in inodes {
        let Kind::Symlink { target } = &inode.kind else {
            continue;
        };
        let xattr_size = inode.xattrs.byte_size();
        let use_compact = inode.fits_in_compact(min_mtime, target.len() as u64, 1);
        let header = if use_compact { 32 } else { 64 };
        if header + xattr_size + target.len() >= BLOCK {
            return Err(Error::Unsupported(format!(
                "a symlink target of {} bytes does not fit its inode's block, \
                 which holds {} bytes of target, and a composefs image states \
                 a target inline",
                target.len(),
                BLOCK - header - xattr_size - 1,
            )));
        }
    }
    Ok(())
}

// --- Two-pass output -------------------------------------------------------

trait Output {
    fn write(&mut self, data: &[u8]);
    fn pad_to(&mut self, align: usize);
    fn write_zeros(&mut self, n: usize);
    fn len(&self) -> usize;

    fn note_inode(&mut self);
    fn note_inodes_end(&mut self);
    fn note_xattr(&mut self);
    fn note_block(&mut self);
    fn note_end(&mut self);

    fn inode_offset(&self, idx: usize) -> Option<usize>;
    fn inodes_end(&self) -> Option<usize>;
    fn xattr_offset(&self, idx: usize) -> Option<usize>;
    fn block_start(&self, idx: usize) -> Option<usize>;
    fn image_end(&self) -> Option<usize>;

    fn get_nid(&self, idx: usize) -> u64 {
        self.inode_offset(idx).map_or(0, |o| (o / SLOT) as u64)
    }

    fn get_block_start(&self, idx: usize) -> usize {
        self.block_start(idx).unwrap_or(0)
    }

    fn get_xattr_v1(&self, idx: usize) -> u32 {
        match (self.xattr_offset(idx), self.inodes_end()) {
            (Some(abs), Some(end)) => (((end % BLOCK) + (abs - end)) / 4) as u32,
            _ => 0,
        }
    }

    fn get_xattr_blkaddr(&self) -> u32 {
        self.inodes_end().map_or(0, |e| (e / BLOCK) as u32)
    }

    fn get_block_count(&self) -> u32 {
        self.image_end().map_or(0, |e| (e / BLOCK) as u32)
    }
}

#[derive(Default)]
struct Layout {
    inodes: Vec<usize>,
    inodes_end: Option<usize>,
    xattrs: Vec<usize>,
    blocks: Vec<usize>,
    end: Option<usize>,
}

#[derive(Default)]
struct SizingPass {
    offset: usize,
    layout: Layout,
}

impl Output for SizingPass {
    fn write(&mut self, data: &[u8]) {
        self.offset += data.len();
    }
    fn pad_to(&mut self, align: usize) {
        self.offset = round_up(self.offset, align);
    }
    fn write_zeros(&mut self, n: usize) {
        self.offset += n;
    }
    fn len(&self) -> usize {
        self.offset
    }
    fn note_inode(&mut self) {
        self.layout.inodes.push(self.offset);
    }
    fn note_inodes_end(&mut self) {
        self.layout.inodes_end = Some(self.offset);
    }
    fn note_xattr(&mut self) {
        self.layout.xattrs.push(self.offset);
    }
    fn note_block(&mut self) {
        self.layout.blocks.push(self.offset);
    }
    fn note_end(&mut self) {
        self.layout.end = Some(self.offset);
    }
    fn inode_offset(&self, _idx: usize) -> Option<usize> {
        None
    }
    fn inodes_end(&self) -> Option<usize> {
        None
    }
    fn xattr_offset(&self, _idx: usize) -> Option<usize> {
        None
    }
    fn block_start(&self, _idx: usize) -> Option<usize> {
        None
    }
    fn image_end(&self) -> Option<usize> {
        None
    }
}

/// A block of zeros for the padding writes.
///
/// A pad of any length takes its bytes from this block and allocates nothing.
static ZEROS: [u8; BLOCK] = [0u8; BLOCK];

/// The emitting pass.
///
/// The pass writes each byte to `sink`, gives the same bytes to `hasher`, and
/// counts them in `offset`. The layout arithmetic reads the count through
/// `Output::len`.
///
/// The pass keeps the first sink error in `error`. After that error, it stops
/// the writes and the hash updates, because the caller discards the digest and
/// sees the error once. It continues to count, because the layout arithmetic
/// needs the count.
struct EmitPass<'a, W: Write> {
    sink: W,
    hasher: FsVerityHasher,
    offset: usize,
    layout: &'a Layout,
    error: Option<io::Error>,
}

impl<W: Write> Output for EmitPass<'_, W> {
    fn write(&mut self, data: &[u8]) {
        self.offset += data.len();
        if self.error.is_none() {
            self.hasher.update(data);
            if let Err(err) = self.sink.write_all(data) {
                self.error = Some(err);
            }
        }
    }
    fn pad_to(&mut self, align: usize) {
        self.write_zeros(round_up(self.offset, align) - self.offset);
    }
    fn write_zeros(&mut self, n: usize) {
        let mut left = n;
        while left > 0 {
            let take = left.min(ZEROS.len());
            self.write(&ZEROS[..take]);
            left -= take;
        }
    }
    fn len(&self) -> usize {
        self.offset
    }
    fn note_inode(&mut self) {}
    fn note_inodes_end(&mut self) {}
    fn note_xattr(&mut self) {}
    fn note_block(&mut self) {}
    fn note_end(&mut self) {}
    fn inode_offset(&self, idx: usize) -> Option<usize> {
        Some(self.layout.inodes[idx])
    }
    fn inodes_end(&self) -> Option<usize> {
        self.layout.inodes_end
    }
    fn xattr_offset(&self, idx: usize) -> Option<usize> {
        Some(self.layout.xattrs[idx])
    }
    fn block_start(&self, idx: usize) -> Option<usize> {
        Some(self.layout.blocks[idx])
    }
    fn image_end(&self) -> Option<usize> {
        self.layout.end
    }
}

fn write_superblock(
    out: &mut dyn Output,
    root_nid: u64,
    inos: u64,
    blocks: u32,
    build_time: (u64, u32),
    xattr_blkaddr: u32,
) {
    let mut sb = [0u8; 128];
    sb[0..4].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
    sb[8..12].copy_from_slice(&FEATURE_COMPAT.to_le_bytes());
    sb[12] = BLKSZBITS;
    sb[14..16].copy_from_slice(&(root_nid as u16).to_le_bytes());
    sb[16..24].copy_from_slice(&inos.to_le_bytes());
    sb[24..32].copy_from_slice(&build_time.0.to_le_bytes());
    sb[32..36].copy_from_slice(&build_time.1.to_le_bytes());
    sb[36..40].copy_from_slice(&blocks.to_le_bytes());
    // meta_blkaddr (40..44) stays 0.
    sb[44..48].copy_from_slice(&xattr_blkaddr.to_le_bytes());
    out.write(&sb);
}

fn write_erofs(
    out: &mut dyn Output,
    inodes: &[Inode],
    shared: &[LocalXattr],
    min_mtime: (u64, u32),
    header_flags: u32,
) {
    // composefs header, padded to 1024.
    out.write(&COMPOSEFS_MAGIC.to_le_bytes());
    out.write(&COMPOSEFS_HEADER_VERSION.to_le_bytes());
    out.write(&header_flags.to_le_bytes());
    out.write(&COMPOSEFS_VERSION_V0.to_le_bytes());
    out.write(&[0u8; 16]); // unused[4]
    out.pad_to(1024);

    let root_nid = out.get_nid(0);
    let block_count = out.get_block_count();
    let xattr_blkaddr = out.get_xattr_blkaddr();
    write_superblock(
        out,
        root_nid,
        inodes.len() as u64,
        block_count,
        min_mtime,
        xattr_blkaddr,
    );

    for (idx, inode) in inodes.iter().enumerate() {
        inode.write(out, idx, min_mtime);
    }

    out.pad_to(SLOT);
    out.note_inodes_end();

    for attr in shared {
        out.note_xattr();
        out.write(&[attr.suffix.len() as u8, attr.prefix]);
        out.write(&(attr.value.len() as u16).to_le_bytes());
        out.write(&attr.suffix);
        out.write(&attr.value);
        out.pad_to(4);
    }

    out.pad_to(BLOCK);
    for inode in inodes {
        out.note_block();
        inode.write_blocks(out);
    }

    out.note_end();
}

/// The input of the emitting pass.
///
/// It holds the inode list, the shared-xattr table, the layout from the sizing
/// pass, and the total length of the image.
pub(crate) struct Plan {
    inodes: Vec<Inode>,
    shared: Vec<LocalXattr>,
    min_mtime: (u64, u32),
    header_flags: u32,
    layout: Layout,
    /// The length in bytes of the image that the plan emits.
    pub(crate) size: usize,
}

/// Builds the inode list of the tree at `root` and runs the sizing pass.
pub(crate) fn plan(root: &Directory) -> Result<Plan, Error> {
    let mut inodes = collect(root)?;

    // The root is opaque, as in the images of the composefs image writer.
    inodes[0].xattrs.add(XATTR_OPAQUE_ROOT, b"y");

    // Look for ACLs before `share_xattrs` runs. That function moves the shared
    // entries out of the `local` list of each inode into the shared table.
    // After the move, this check does not see a shared ACL xattr and loses the
    // flag.
    let has_acl = inodes.iter().any(|inode| {
        inode
            .xattrs
            .local
            .iter()
            .any(|x| x.prefix == XATTR_INDEX_ACL_ACCESS || x.prefix == XATTR_INDEX_ACL_DEFAULT)
    });
    let header_flags = if has_acl { FLAGS_HAS_ACL } else { 0 };

    let shared = share_xattrs(&mut inodes);
    let min_mtime = inodes.iter().map(|i| i.mtime).min().unwrap_or((0, 0));
    check_symlinks(&inodes, min_mtime)?;

    let mut sizing = SizingPass::default();
    write_erofs(&mut sizing, &inodes, &shared, min_mtime, header_flags);

    Ok(Plan {
        inodes,
        shared,
        min_mtime,
        header_flags,
        layout: sizing.layout,
        size: sizing.offset,
    })
}

/// Runs the emitting pass of `plan` through `out` and returns the fs-verity
/// digest.
pub(crate) fn emit(plan: &Plan, out: &mut impl Write) -> io::Result<[u8; 32]> {
    let mut pass = EmitPass {
        sink: out,
        hasher: FsVerityHasher::new(),
        offset: 0,
        layout: &plan.layout,
        error: None,
    };
    write_erofs(
        &mut pass,
        &plan.inodes,
        &plan.shared,
        plan.min_mtime,
        plan.header_flags,
    );
    // If the two lengths differ, the image is malformed and the digest is of
    // malformed bytes. The check is one comparison for each image, so it runs
    // in every build.
    assert_eq!(
        pass.offset, plan.size,
        "the emitting pass wrote a different length than the sizing pass"
    );
    let EmitPass {
        sink,
        hasher,
        error,
        ..
    } = pass;
    if let Some(err) = error {
        return Err(err);
    }
    sink.flush()?;
    Ok(hasher.finalize())
}

/// Writes the composefs EROFS image of the tree at `root` through `out`.
///
/// The function returns the fs-verity digest of the image. This digest is the
/// value of [`FsVerityHasher::hash`] for the image bytes.
///
/// # Image format
///
/// The image has the EROFS layout of composefs, format version 0. The `ostree`
/// command writes this format when it exports a commit with composefs support.
/// The image holds only the parts that composefs uses:
///
/// - the superblock
/// - compact and extended inodes
/// - tail-packed directory blocks
/// - inline symlink targets
/// - chunk-based backing files
/// - the overlay xattrs `trusted.overlay.redirect`, `trusted.overlay.metacopy`,
///   and `trusted.overlay.opaque`, with the shared-xattr area and the EROFS
///   xattr name filter.
///
/// The image has no EROFS compression, no fragments, and no multi-device
/// support.
///
/// The writer adds two things to the root directory, as the image writer of the
/// composefs project does. It adds the overlay whiteout table: 256 character-device stubs
/// named `00` to `ff`. A child of the root with one of these names stays, and
/// the writer adds no stub for that name. It also sets the xattr
/// `trusted.overlay.opaque` to `y` on the root.
///
/// # Writes
///
/// The sink receives the image in the order of the EROFS layout. The writer
/// passes each field to `write_all` of the sink, so a file with no buffer makes
/// one system call for each field. A caller can wrap a file in a
/// [`std::io::BufWriter`]. The writer only appends, so the sink needs no seek.
/// The image never exists as a whole in memory.
///
/// One write holds at most 65535 bytes. This limit is the range of the EROFS
/// length field of an xattr value.
/// The superblock is one write of 128 bytes. The writer writes padding in
/// pieces of at most 4096 bytes.
///
/// If the call succeeds, it flushes the sink before it returns. If a write
/// fails, the writer makes no more writes and does not flush the sink. A sink
/// that flushes on drop, such as a [`std::io::BufWriter`], still flushes when
/// the caller drops it.
///
/// # Errors
///
/// - [`Error::Unsupported`] if a child name is empty, is `.` or `..`, holds
///   `/`, or is longer than 255 bytes. [`Directory::children`] gives the
///   rules.
/// - [`Error::Unsupported`] if a symlink target is too long for its inode
///   block. [`Symlink::target`] gives the limit.
/// - [`Error::Io`] with the first error of `out`, if a write or the flush
///   fails.
///
/// # Panics
///
/// Panics if an xattr name, an xattr value, or the xattr area of one node is
/// larger than the limits on [`Metadata::xattrs`].
pub fn write_image_to(root: &Directory, out: &mut impl Write) -> Result<[u8; 32], Error> {
    Ok(emit(&plan(root)?, out)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that accepts `left` more bytes and fails every write after that.
    #[derive(Default)]
    struct FailingSink {
        left: usize,
        written: usize,
        errors: usize,
        flushes: usize,
    }

    impl Write for FailingSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.left == 0 {
                self.errors += 1;
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            let take = buf.len().min(self.left);
            self.left -= take;
            self.written += take;
            Ok(take)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    /// Returns a root directory with one empty regular file.
    ///
    /// The image of this tree goes past the first block.
    fn small_tree() -> Directory {
        let mut root = Directory::new(Metadata {
            mode: 0o040755,
            ..Default::default()
        });
        root.insert(
            "f",
            Node::Regular(Regular {
                meta: Metadata {
                    mode: 0o100644,
                    ..Default::default()
                },
                content: Content::Empty,
            }),
        );
        root
    }

    /// If the sink fails partway, it gets one failed write, takes no more
    /// bytes, and gets no flush. The pass still runs to the end, so the padding
    /// arithmetic reads a counter that advances.
    #[test]
    fn a_failing_sink_reports_its_error_once() {
        let mut sink = FailingSink {
            left: 64,
            ..Default::default()
        };
        let err = write_image_to(&small_tree(), &mut sink).expect_err("the sink fails");
        assert!(
            matches!(&err, Error::Io(err) if err.kind() == io::ErrorKind::BrokenPipe),
            "the sink's error reached the caller as {err:?}"
        );
        assert_eq!(sink.written, 64, "the sink took bytes after it failed");
        assert_eq!(sink.errors, 1, "the sink was written to after it failed");
        assert_eq!(sink.flushes, 0, "a failed emission flushed the sink");
    }

    /// Returns `small_tree` plus one symlink with a target of `len` bytes and
    /// the xattrs `xattrs`.
    fn tree_with_symlink(len: usize, xattrs: Vec<(Vec<u8>, Vec<u8>)>) -> Directory {
        let mut root = small_tree();
        root.insert(
            "l",
            Node::Symlink(Symlink {
                meta: Metadata {
                    mode: 0o120777,
                    xattrs,
                    ..Default::default()
                },
                target: vec![b'z'; len],
            }),
        );
        root
    }

    /// The image holds a symlink target inline, so a target that fills the
    /// inode block has no place in it. A compact inode header is 32 bytes. A
    /// target with no xattrs fits at 4063 bytes and does not fit at 4064 bytes.
    #[test]
    fn a_symlink_target_that_fills_its_block_is_refused() {
        plan(&tree_with_symlink(BLOCK - 33, Vec::new())).expect("4063 bytes fit");

        // `expect_err` needs `Debug` on the value, and `Plan` has no `Debug`,
        // so the test maps the value to `()`.
        let err = plan(&tree_with_symlink(BLOCK - 32, Vec::new()))
            .map(|_| ())
            .expect_err("4064 bytes do not fit");
        let text = err.to_string();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the writer refused with {err:?}"
        );
        assert!(
            text.contains("4064 bytes") && text.contains("4063 bytes of target"),
            "the refusal names the target and what the block holds: {text}"
        );
    }

    /// The xattrs of the inode use the same block, so an xattr lowers the
    /// bound by its size in the xattr area.
    #[test]
    fn a_symlink_xattr_moves_the_target_bound_down() {
        // The area uses a 12-byte header. One `user.k` entry uses a 4-byte
        // entry header, a 1-byte suffix, and a 1-byte value, rounded up to a
        // multiple of 4. The total is 20 bytes.
        let xattrs = vec![(b"user.k".to_vec(), b"v".to_vec())];
        plan(&tree_with_symlink(BLOCK - 33 - 20, xattrs.clone())).expect("4043 bytes fit");
        plan(&tree_with_symlink(BLOCK - 32 - 20, xattrs))
            .map(|_| ())
            .expect_err("4044 bytes do not fit");
    }

    /// Returns `small_tree` plus one empty regular file named `name`.
    fn tree_with_name(name: &[u8]) -> Directory {
        let mut root = small_tree();
        root.insert(
            name,
            Node::Regular(Regular {
                meta: Metadata {
                    mode: 0o100644,
                    ..Default::default()
                },
                content: Content::Empty,
            }),
        );
        root
    }

    /// A name that does not fit one directory block is refused.
    #[test]
    fn a_name_longer_than_a_directory_block_is_refused() {
        let err = plan(&tree_with_name(&[b'n'; BLOCK - 11]))
            .map(|_| ())
            .expect_err("a 4085-byte name is refused");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the writer refused with {err:?}"
        );
    }

    /// A child name fits at 255 bytes and does not fit at 256 bytes.
    #[test]
    fn a_name_of_256_bytes_is_refused() {
        let root = tree_with_name(&[b'n'; MAX_NAME]);
        plan(&root).expect("255 bytes fit");
        crate::build_image(&root).expect("a 255-byte name has an image");

        let err = plan(&tree_with_name(&[b'n'; MAX_NAME + 1]))
            .map(|_| ())
            .expect_err("256 bytes do not fit");
        let text = err.to_string();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the writer refused with {err:?}"
        );
        assert!(
            text.contains("256 bytes") && text.contains("255 bytes"),
            "the refusal names the length and the bound: {text}"
        );
    }

    /// Plans `root` and returns the message of its `Unsupported` refusal.
    fn refusal(root: &Directory) -> String {
        match plan(root).map(|_| ()) {
            Err(Error::Unsupported(msg)) => msg,
            other => panic!("the writer did not refuse with Unsupported: {other:?}"),
        }
    }

    /// An empty child name is refused.
    #[test]
    fn an_empty_name_is_refused() {
        let msg = refusal(&tree_with_name(b""));
        assert!(msg.contains("empty"), "the refusal names the form: {msg}");
    }

    /// A child named `.` is refused.
    #[test]
    fn a_name_of_one_dot_is_refused() {
        let msg = refusal(&tree_with_name(b"."));
        assert!(msg.contains("`.`"), "the refusal names the form: {msg}");
    }

    /// A child named `..` is refused.
    #[test]
    fn a_name_of_two_dots_is_refused() {
        let msg = refusal(&tree_with_name(b".."));
        assert!(msg.contains("`..`"), "the refusal names the form: {msg}");
    }

    /// A child name that holds `/` is refused.
    #[test]
    fn a_name_with_a_slash_is_refused() {
        let msg = refusal(&tree_with_name(b"a/b"));
        assert!(msg.contains("`a/b`"), "the refusal names the name: {msg}");
    }

    /// The check runs in each directory, so a bad name below the root is
    /// refused.
    #[test]
    fn a_bad_name_in_a_subdirectory_is_refused() {
        let mut sub = Directory::new(Metadata {
            mode: 0o040755,
            ..Default::default()
        });
        sub.insert("..", Node::Directory(Directory::new(sub.meta.clone())));
        let mut root = small_tree();
        root.insert("sub", Node::Directory(sub));
        let msg = refusal(&root);
        assert!(msg.contains("`..`"), "the refusal names the form: {msg}");
    }

    /// The names `...`, `.a`, `a.`, and `a\b` are each one path component, so
    /// the writer keeps them.
    #[test]
    fn a_name_with_dots_is_kept() {
        for name in [&b"..."[..], b".a", b"a.", b"a\\b"] {
            plan(&tree_with_name(name)).expect("the name is one path component");
        }
    }

    /// If an inode has more repeated xattrs than the cap, it references the
    /// lowest keys through the shared table. It keeps the highest keys inline.
    /// The table still holds each repeated entry. The golden fixture holds the
    /// bytes, and this test checks the rule behind those bytes.
    #[test]
    fn the_shared_xattr_list_caps_and_spills_the_highest_keys() {
        const N: usize = MAX_SHARED_XATTRS + 20;
        let xattrs: Vec<(Vec<u8>, Vec<u8>)> = (0..N)
            .map(|i| (format!("user.k{i:03}").into_bytes(), b"v".to_vec()))
            .collect();
        let mut root = Directory::new(Metadata {
            mode: 0o040755,
            ..Default::default()
        });
        for name in ["a", "b"] {
            root.insert(
                name,
                Node::Regular(Regular {
                    meta: Metadata {
                        mode: 0o100644,
                        xattrs: xattrs.clone(),
                        ..Default::default()
                    },
                    content: Content::Empty,
                }),
            );
        }

        let plan = plan(&root).expect("the tree has an image");
        let carriers: Vec<&Inode> = plan
            .inodes
            .iter()
            .filter(|i| i.xattrs.shared.len() + i.xattrs.local.len() >= N)
            .collect();
        assert_eq!(carriers.len(), 2, "both files carry the attributes");
        for inode in carriers {
            assert_eq!(inode.xattrs.shared.len(), MAX_SHARED_XATTRS);
            let inline: Vec<Vec<u8>> = inode.xattrs.local.iter().map(|a| a.full_key()).collect();
            let expected: Vec<Vec<u8>> = (MAX_SHARED_XATTRS..N)
                .map(|i| format!("user.k{i:03}").into_bytes())
                .collect();
            assert_eq!(inline, expected, "the highest keys stayed inline");
        }
        assert_eq!(plan.shared.len(), N, "the table holds every repeated entry");
    }
}
