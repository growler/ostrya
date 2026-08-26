//! The EROFS/composefs V0 image serializer.
//!
//! The image is built in two passes over one inode list. The first pass counts
//! bytes and records the offset of every inode, the end of the inode table,
//! every shared-xattr entry, and every inode's block-data region. EROFS node
//! ids and shared-xattr references derive from those offsets, so the second
//! pass, which emits the bytes, resolves them from the first pass's layout.

use std::collections::VecDeque;

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
// fallback; 2 and 3 are full POSIX ACL names, not prefixes; 5 (lustre.) is
// absent from the composefs V0 prefix table and is skipped so lustre.* names
// fall through to the empty fallback.
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

/// The 36-byte overlay metacopy record carrying a backing object's digest.
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

    /// Order by full key name, then by value length, then value bytes, matching
    /// the composefs sort.
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

    /// Serialized byte size of this inode's xattr block, zero when empty.
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
            n => (1 + (n - 12) / 4) as u16,
        }
    }

    fn write(&self, out: &mut dyn Output) {
        if self.filter == 0 {
            return;
        }
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

        // Do not keep more than 2048 bytes of tail inline.
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
    Backed {
        size: u64,
        inline_tail: usize,
    },
    Symlink {
        target: Vec<u8>,
        n_data_blocks: u32,
        inline_tail: usize,
    },
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

    /// `(datalayout, i_u, size, nlink)` for this inode given the byte offset of
    /// its block-data region.
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
            Kind::Symlink {
                target,
                n_data_blocks,
                ..
            } => {
                if *n_data_blocks > 0 {
                    let blkaddr = (block_start / BLOCK) as u32;
                    (LAYOUT_FLAT_PLAIN, blkaddr, target.len() as u64, 1)
                } else {
                    (LAYOUT_FLAT_INLINE, 0, target.len() as u64, 1)
                }
            }
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

        // A promoted symlink (target moved to a data block) still pads its inode
        // start to a block boundary using the original pre-promotion size.
        if let Kind::Symlink { n_data_blocks, .. } = &self.kind
            && *n_data_blocks > 0
        {
            let current = out.len();
            let original_total = header_size + xattr_size + size as usize;
            if current / BLOCK != (current + original_total - 1) / BLOCK
                && let Some(pad) = bytes_to_block_boundary(current)
            {
                out.write_zeros(pad);
            }
        }

        // Chunk-based inline chunk index gets the same tail padding as inline data.
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
            Kind::Symlink {
                target,
                n_data_blocks,
                ..
            } if *n_data_blocks == 0 => out.write(target),
            _ => {}
        }
    }

    fn write_blocks(&self, out: &mut dyn Output) {
        match &self.kind {
            Kind::Dir(dir) => {
                for block in &dir.blocks {
                    write_dir_block(out, block);
                    out.pad_to(BLOCK);
                }
            }
            Kind::Symlink {
                target,
                n_data_blocks,
                ..
            } if *n_data_blocks > 0 => {
                let n = target.len().min(BLOCK);
                out.write(&target[..n]);
                out.pad_to(BLOCK);
            }
            _ => {}
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

/// Root's children merged with the 256 overlay whiteout stubs, name-sorted.
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
                // Chunk indices are always written inline. A single chunk
                // covers files up to 8 TiB (chunk size caps at 2^43), so
                // chunk_count is 1 for every file ostree produces. Larger
                // files would need more inline indices, and files whose index
                // list overflowed a block would require promotion to a data
                // block, which is not supported.
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
                n_data_blocks: 0,
                inline_tail: link.target.len(),
            },
        )
    }

    fn push_whiteout(&mut self) -> usize {
        // A whiteout stub inherits only security.selinux from the root and is
        // mode 0644, owned like the root, char-device 0:0.
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

fn collect(root: &Directory) -> Vec<Inode> {
    let mut c = Collector {
        inodes: Vec::new(),
        root,
    };
    let root_idx = c.push_dir(&root.meta);

    let mut queue: VecDeque<(&Directory, usize, usize, bool)> = VecDeque::new();
    queue.push_back((root, root_idx, root_idx, true));
    let mut dir_entries: Vec<(usize, Vec<DirEnt>)> = Vec::new();

    while let Some((dir, me, parent, is_root)) = queue.pop_front() {
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

    c.inodes
}

// --- Shared-xattr promotion ------------------------------------------------

/// Promote xattrs shared by more than one inode into a shared table written
/// after the inode table, returning the table in on-disk order.
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

    // Keep only shared entries; order them by full key ascending, then write
    // them descending, so the largest key gets reference index 0.
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

    // Extract representative LocalXattr for each shared key (from any inode) in
    // descending on-disk order.
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
        inode.xattrs.local.retain(|attr| {
            if let Some(&r) = index.get(&key(attr)) {
                promoted.push(r);
                false
            } else {
                true
            }
        });
        inode.xattrs.shared = promoted;
    }

    table
}

/// Promote an inline symlink target to a data block when the inode header plus
/// xattrs plus target would fill a block.
fn fixup_data_blocks(inodes: &mut [Inode], min_mtime: (u64, u32)) {
    for inode in inodes.iter_mut() {
        let xattr_size = inode.xattrs.byte_size();
        let tail = match &inode.kind {
            Kind::Symlink { inline_tail, .. } => *inline_tail,
            _ => continue,
        };
        if tail == 0 {
            continue;
        }

        let use_compact = inode.fits_in_compact(min_mtime, tail as u64, 1);
        let header = if use_compact { 32 } else { 64 };
        if header + xattr_size + tail >= BLOCK
            && let Kind::Symlink {
                n_data_blocks,
                inline_tail,
                ..
            } = &mut inode.kind
        {
            *n_data_blocks += 1;
            *inline_tail = 0;
        }
    }
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
struct FirstPass {
    offset: usize,
    layout: Layout,
}

impl Output for FirstPass {
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

struct SecondPass {
    buf: Vec<u8>,
    layout: Layout,
}

impl Output for SecondPass {
    fn write(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    fn pad_to(&mut self, align: usize) {
        self.buf.resize(round_up(self.buf.len(), align), 0);
    }
    fn write_zeros(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }
    fn len(&self) -> usize {
        self.buf.len()
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

/// Serialize the tree at `root` into a composefs V0 EROFS image.
pub fn write_image(root: &Directory) -> Vec<u8> {
    let mut inodes = collect(root);

    // Mark the root opaque, matching the composefs image writer.
    inodes[0].xattrs.add(XATTR_OPAQUE_ROOT, b"y");

    // Detect ACLs before share_xattrs runs. It moves shared entries out of
    // each inode's .local list into the shared table, after which a shared ACL
    // xattr would no longer be visible here and the flag would be dropped.
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
    fixup_data_blocks(&mut inodes, min_mtime);

    let mut first = FirstPass::default();
    write_erofs(&mut first, &inodes, &shared, min_mtime, header_flags);

    let mut second = SecondPass {
        buf: Vec::with_capacity(first.offset),
        layout: first.layout,
    };
    write_erofs(&mut second, &inodes, &shared, min_mtime, header_flags);
    second.buf
}
