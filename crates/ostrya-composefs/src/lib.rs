#![forbid(unsafe_code)]

//! A byte-exact writer of composefs EROFS images, with an fs-verity hasher.
//!
//! A caller builds a tree of directories, symlinks, and regular files. The
//! crate writes the EROFS image of the tree and returns the fs-verity digest of
//! the image. The image is byte-identical to the composefs image of the
//! `ostree` command, format version 0. The crate is synchronous and does not
//! read a repository.
//!
//! # Entry points
//!
//! - [`Directory`] is the root of a tree, and [`Node`] is one entry of it.
//! - [`Metadata`] holds the mode, the owner, the mtime, and the xattrs of a node.
//! - [`Content`] is the content of a [`Regular`] file: empty or a loose object.
//! - [`build_image`] writes the image into an [`Image`] in memory.
//! - [`write_image_to`] writes the image through a sink and does not keep it.
//! - [`FsVerityHasher`] calculates an fs-verity digest of a byte stream.
//! - [`Error`] is the error of the two image writers.
//!
//! # Examples
//!
//! ```
//! use ostrya_composefs::{Content, Directory, FsVerityHasher, Metadata, Node, Regular};
//!
//! let mut root = Directory::new(Metadata { mode: 0o755, ..Metadata::default() });
//! let meta = Metadata { mode: 0o644, ..Metadata::default() };
//! root.insert("empty", Node::Regular(Regular { meta, content: Content::Empty }));
//!
//! let image = ostrya_composefs::build_image(&root)?;
//! assert_eq!(FsVerityHasher::hash(&image.bytes), image.fs_verity);
//!
//! // The streaming writer writes the same bytes and returns the same digest.
//! let mut sink = Vec::new();
//! assert_eq!(ostrya_composefs::write_image_to(&root, &mut sink)?, image.fs_verity);
//! assert_eq!(sink, image.bytes);
//! # Ok::<(), ostrya_composefs::Error>(())
//! ```

// tests/golden.rs compares the output byte for byte with images that the
// `ostree` command wrote.

mod fsverity;
mod tree;
mod writer;
mod xxhash;

use std::fmt;

pub use fsverity::FsVerityHasher;
pub use tree::{Content, Directory, Metadata, Node, Regular, Symlink};
pub use writer::write_image_to;

/// The error of [`build_image`] and [`write_image_to`].
#[derive(Debug)]
pub enum Error {
    /// A tree item that the image cannot hold.
    ///
    /// The message names the item.
    Unsupported(String),
    /// An I/O error from the sink.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unsupported(msg) => f.write_str(msg),
            Error::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Unsupported(_) => None,
            Error::Io(err) => Some(err),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

/// A composefs EROFS image in memory, with its fs-verity digest.
pub struct Image {
    /// The bytes of the complete EROFS image.
    pub bytes: Vec<u8>,
    /// The fs-verity digest of the image (SHA-256, 4096-byte blocks, no salt).
    ///
    /// The `ostree` command stores this value in the
    /// `ostree.composefs.digest.v0` key of the commit metadata.
    pub fs_verity: [u8; 32],
}

/// Writes the composefs EROFS image of the tree at `root` into memory.
///
/// The bytes and the digest are the same as the result of [`write_image_to`].
/// [Image format](write_image_to#image-format) gives the layout of the image.
///
/// # Errors
///
/// - [`Error::Unsupported`] if a symlink target is too long for its inode
///   block. [`Symlink::target`] gives the limit.
///
/// # Panics
///
/// Panics if an xattr name, an xattr value, or the xattr area of one node is
/// larger than the limits on [`Metadata::xattrs`].
pub fn build_image(root: &Directory) -> Result<Image, Error> {
    let plan = writer::plan(root)?;
    let mut bytes = Vec::with_capacity(plan.size);
    // A `Vec<u8>` sink accepts every write, so the emitting pass cannot fail.
    let fs_verity = writer::emit(&plan, &mut bytes).expect("a Vec sink never fails");
    Ok(Image { bytes, fs_verity })
}

#[cfg(test)]
mod send_sync {
    use super::*;

    // The public types are `Send` and `Sync`.
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn public_types_are_send_sync() {
        assert_send_sync::<Image>();
        assert_send_sync::<Directory>();
        assert_send_sync::<Node>();
        assert_send_sync::<Regular>();
        assert_send_sync::<Symlink>();
        assert_send_sync::<Metadata>();
        assert_send_sync::<Content>();
        assert_send_sync::<FsVerityHasher>();
    }
}
