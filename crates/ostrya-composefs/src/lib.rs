#![forbid(unsafe_code)]

//! Byte-exact EROFS/composefs image writer and fs-verity digest.
//!
//! This crate has no ostree or repository knowledge. It is the composefs
//! counterpart to `ostrya-gvariant`: it takes a tree model -- directories,
//! symlinks, and regular-file entries carrying logical metadata, extended
//! attributes, a backing loose path, and an optional backing fs-verity
//! digest -- and emits the EROFS image bytes plus the image's fs-verity
//! digest.
//!
//! The output reproduces the composefs project's EROFS layout, format version
//! 0, the format the `ostree` tool writes when it exports a commit with
//! composefs support. The writer reproduces only the metadata subset composefs
//! uses: the superblock, compact and extended inodes, tail-packed directory
//! blocks, inline symlink targets, chunk-based backing files, and the
//! trusted-namespace overlay xattrs (`overlay.redirect`, `overlay.metacopy`,
//! `overlay.opaque`) with the shared-xattr area and the EROFS xattr name
//! filter. There is no EROFS compression, no fragments, and no multi-device
//! support. The crate is synchronous and takes no runtime dependency.
//!
//! Emission is append-only, so [`write_image_to`] serializes the image straight
//! through a [`std::io::Write`] sink and returns the digest without holding the
//! image. [`build_image`] runs the same emission into a buffer for a caller
//! that wants the bytes.
//!
//! A symlink target sits inline in its inode, so a target that does not fit the
//! inode's block has no place in the image and both forms refuse it with
//! [`Error::Unsupported`].
//!
//! The field-level layout is documented in `docs/format-reference.md`,
//! "composefs", and pinned by the golden-image test.

mod fsverity;
mod tree;
mod writer;
mod xxhash;

use std::fmt;

pub use fsverity::FsVerityHasher;
pub use tree::{Content, Directory, Metadata, Node, Regular, Symlink};
pub use writer::write_image_to;

/// A tree the writer has no image for, or a sink that failed.
#[derive(Debug)]
pub enum Error {
    /// The tree carries something the image has no place for. The message
    /// names it.
    Unsupported(String),
    /// The sink returned an error.
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

/// A generated composefs EROFS image and its fs-verity digest.
pub struct Image {
    /// The complete EROFS image bytes.
    pub bytes: Vec<u8>,
    /// The image's fs-verity digest (SHA-256, 4096-byte blocks, zero salt).
    ///
    /// This is the value the `ostree` tool stores in a commit's
    /// `ostree.composefs.digest.v0` metadata key.
    pub fs_verity: [u8; 32],
}

/// Build the composefs EROFS image for the tree rooted at `root`.
///
/// The writer injects the composefs overlay-whiteout table (256 char-device
/// stubs named `00`..`ff`) into the root directory and marks the root opaque,
/// as the composefs image writer does; those entries are format mechanics and
/// are not part of the caller's tree.
///
/// A symlink whose target does not fit its inode's block is
/// [`Error::Unsupported`], as [`Symlink`] states. Panics when an xattr name or
/// a value exceeds what [`Metadata`] states.
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

    // The public writer types move freely across tasks and threads.
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
