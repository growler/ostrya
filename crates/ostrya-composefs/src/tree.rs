//! The tree model the image writer consumes.
//!
//! A tree is a [`Directory`] whose children are [`Node`]s. Each node carries
//! logical [`Metadata`] (mode, ownership, mtime, xattrs). Regular files are
//! either empty or backed by a loose object referenced through overlay
//! redirect and metacopy xattrs; the writer never stores file content in the
//! image.

use std::collections::BTreeMap;

/// Logical metadata shared by every node.
///
/// `mode` is the full `st_mode`; the file-type bits are ignored (the type is
/// taken from the node kind) and only the permission bits are used. `xattrs`
/// are logical name/value pairs; the writer canonicalizes their EROFS encoding
/// (prefix indexing, ordering, sharing, and the name filter) and escapes any
/// `trusted.overlay.` names, so the caller supplies them verbatim.
#[derive(Clone, Debug, Default)]
pub struct Metadata {
    /// Full `st_mode`; only the permission bits are used.
    pub mode: u32,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
    /// Modification time as `(seconds, nanoseconds)`.
    pub mtime: (u64, u32),
    /// Extended attributes as `(name, value)` pairs.
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
///
/// Children are keyed by name (raw bytes, no `/`, never `.` or `..`) in sorted
/// order.
#[derive(Clone, Debug, Default)]
pub struct Directory {
    /// Logical metadata for the directory inode.
    pub meta: Metadata,
    /// Named children in name-sorted order.
    pub children: BTreeMap<Vec<u8>, Node>,
}

/// A symbolic link. The target is stored inline in the image.
#[derive(Clone, Debug)]
pub struct Symlink {
    /// Logical metadata for the symlink inode.
    pub meta: Metadata,
    /// The link target bytes.
    pub target: Vec<u8>,
}

/// A regular file.
#[derive(Clone, Debug)]
pub struct Regular {
    /// Logical metadata for the file inode.
    pub meta: Metadata,
    /// How the file content is backed.
    pub content: Content,
}

/// How a regular file's content is represented in the image.
#[derive(Clone, Debug)]
pub enum Content {
    /// An empty file (no backing object, no content).
    Empty,
    /// A file backed by a loose object referenced through overlay xattrs.
    Backed {
        /// The logical (uncompressed) file size in bytes.
        size: u64,
        /// The overlay redirect target, an absolute path such as
        /// `/cf/ffd5....file`.
        redirect: String,
        /// The backing object's fs-verity digest.
        verity: [u8; 32],
    },
}

impl Directory {
    /// Create an empty directory with the given metadata.
    pub fn new(meta: Metadata) -> Self {
        Self {
            meta,
            children: BTreeMap::new(),
        }
    }

    /// Insert or replace a child by name.
    pub fn insert(&mut self, name: impl Into<Vec<u8>>, node: Node) {
        self.children.insert(name.into(), node);
    }
}
