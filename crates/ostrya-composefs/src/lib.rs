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
//! support. The image is assembled in a single in-memory buffer, so the crate
//! is synchronous and takes no runtime dependency.
//!
//! The field-level layout is documented in `docs/format-reference.md`,
//! "composefs", and pinned by the golden-image test.

mod fsverity;
mod tree;
mod writer;
mod xxhash;

pub use fsverity::FsVerityHasher;
pub use tree::{Content, Directory, Metadata, Node, Regular, Symlink};

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
pub fn build_image(root: &Directory) -> Image {
    let bytes = writer::write_image(root);
    let fs_verity = FsVerityHasher::hash(&bytes);
    Image { bytes, fs_verity }
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
