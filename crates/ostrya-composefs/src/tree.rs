//! The tree model that the image writer reads: a [`Directory`] of named
//! [`Node`]s, each with its [`Metadata`].

use std::collections::BTreeMap;

/// The logical metadata of a node.
#[derive(Clone, Debug, Default)]
pub struct Metadata {
    /// The full `st_mode` of the node.
    ///
    /// The writer ignores the file-type bits and takes the type from the
    /// [`Node`] variant. It keeps the bits of `mode & 0o7777`: the permission
    /// bits and the setuid, setgid, and sticky bits.
    pub mode: u32,
    /// The user id of the owner.
    pub uid: u32,
    /// The group id of the owner.
    pub gid: u32,
    /// The modification time as `(seconds, nanoseconds)`.
    pub mtime: (u64, u32),
    /// The extended attributes as `(name, value)` pairs.
    ///
    /// The caller gives the logical names and values. The writer makes their
    /// EROFS encoding (prefix indexing, ordering, sharing, and the name
    /// filter). It escapes each `trusted.overlay.X` name as
    /// `trusted.overlay.overlay.X`. The escape adds 8 bytes to the name suffix.
    ///
    /// # Limits
    ///
    /// Each limit is the range of an EROFS length or count field:
    ///
    /// - A value is at most 65535 bytes.
    /// - A name suffix is at most 255 bytes. The suffix is the part of the name
    ///   after its EROFS prefix, and the limit applies after the escape.
    /// - The xattr area of one inode is at most 262148 bytes. The number of
    ///   attributes has no limit of its own.
    ///
    /// If a name, a value, or an area is larger than its limit, the writer
    /// panics. The field in the image cannot state a larger size.
    ///
    /// The writer shares an entry that repeats across inodes. One inode
    /// references at most 128 shared entries, the limit that an observation of
    /// the `ostree` command shows. If an inode has more repeated entries, it
    /// references the first 128 in name order and keeps the others inline.
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A node in the tree.
#[derive(Clone, Debug)]
pub enum Node {
    /// A directory.
    Directory(Directory),
    /// A symbolic link.
    Symlink(Symlink),
    /// A regular file.
    Regular(Regular),
}

/// A directory and its named children.
#[derive(Clone, Debug, Default)]
pub struct Directory {
    /// The logical metadata of the directory inode.
    pub meta: Metadata,
    /// The children, keyed by name and sorted by name.
    ///
    /// A name is raw bytes. It holds no `/` and is never `.` or `..`.
    pub children: BTreeMap<Vec<u8>, Node>,
}

/// A symbolic link, with its target inline in the image.
#[derive(Clone, Debug)]
pub struct Symlink {
    /// The logical metadata of the symlink inode.
    pub meta: Metadata,
    /// The bytes of the link target.
    ///
    /// The target shares one 4096-byte block with the inode header and the
    /// xattr area of the inode. The three together must be less than 4096
    /// bytes, so the target is at most 4095 bytes less the header and the area.
    ///
    /// A header is 32 bytes for a compact inode and 64 bytes for an extended
    /// inode. If the mtime of the inode is not the earliest mtime in the image,
    /// the inode is extended. If the uid or the gid is more than 65535, the
    /// inode is also extended. If the symlink has a compact inode and no
    /// xattrs, the target is at most 4063 bytes.
    ///
    /// If the target is longer than its limit, the writer returns
    /// [`Error::Unsupported`](crate::Error::Unsupported).
    pub target: Vec<u8>,
}

/// A regular file.
#[derive(Clone, Debug)]
pub struct Regular {
    /// The logical metadata of the file inode.
    pub meta: Metadata,
    /// The content of the file: empty, or backed by a loose object.
    pub content: Content,
}

/// The content of a [`Regular`] file in the image.
///
/// The image holds no file content. A backed file names its loose object
/// through the `trusted.overlay.redirect` and `trusted.overlay.metacopy`
/// xattrs.
#[derive(Clone, Debug)]
pub enum Content {
    /// An empty file, with no backing object.
    Empty,
    /// A file backed by a loose object.
    Backed {
        /// The logical (uncompressed) size of the file in bytes.
        size: u64,
        /// The overlay redirect target, an absolute path such as
        /// `/cf/ffd5....file`.
        redirect: String,
        /// The fs-verity digest of the backing object, or `None`.
        ///
        /// The writer puts the digest in the value of the
        /// `trusted.overlay.metacopy` xattr. If the digest is `None`, the
        /// xattr has an empty value.
        verity: Option<[u8; 32]>,
    },
}

impl Directory {
    /// Creates an empty directory with the given metadata.
    pub fn new(meta: Metadata) -> Self {
        Self {
            meta,
            children: BTreeMap::new(),
        }
    }

    /// Inserts a child by name, or replaces the child that has the same name.
    pub fn insert(&mut self, name: impl Into<Vec<u8>>, node: Node) {
        self.children.insert(name.into(), node);
    }
}
