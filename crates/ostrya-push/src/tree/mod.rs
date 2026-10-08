//! The walk of a local directory into a tree model.
//!
//! [`TreeModel::scan`] walks a directory with `std::fs` and computes the
//! checksum of each object of the tree. [`ScanOptions`] holds the
//! [`EntryFilter`]. The filter sees the [`EntryPath`] and the [`EntryMeta`] of
//! each entry, can change the metadata, and returns an [`EntryAction`]. A
//! [`TreeModel`] is the [`ObjectSource`](crate::session::ObjectSource) of a
//! push of the tree.

mod hash;
mod model;
mod walk;

use std::fmt;
use std::io;
use std::path::Path;

use ostrya_core::Xattrs;

pub use model::TreeModel;

/// The file-type mask of an `st_mode`.
const S_IFMT: u32 = 0o170000;
/// The directory file-type bits of an `st_mode`.
const S_IFDIR: u32 = 0o040000;
/// The regular-file file-type bits of an `st_mode`.
const S_IFREG: u32 = 0o100000;
/// The symlink file-type bits of an `st_mode`.
const S_IFLNK: u32 = 0o120000;
/// The bits of an `st_mode`: the file-type bits and the permission bits.
const MODE_BITS: u32 = 0o177777;

/// The mode of every symlink, on every platform.
const SYMLINK_MODE: u32 = S_IFLNK | 0o777;

/// The attribute bit of a Win32 reparse point, `FILE_ATTRIBUTE_REPARSE_POINT`.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// The kind of a tree entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symlink.
    Symlink,
}

impl EntryKind {
    /// Returns the file-type bits of the kind.
    fn type_bits(self) -> u32 {
        match self {
            EntryKind::File => S_IFREG,
            EntryKind::Dir => S_IFDIR,
            EntryKind::Symlink => S_IFLNK,
        }
    }
}

/// The metadata of a tree entry, as the entry filter sees and changes it.
///
/// The walk fills it from the metadata read of the entry:
///
/// - On Unix, `uid`, `gid`, and `mode` come from the read, which does not
///   follow a symlink. The mode of a symlink is the one exception.
/// - On other platforms, `uid` and `gid` are 0. `mode` is `0o100644` for a
///   regular file and `0o40755` for a directory.
/// - A symlink has the mode `0o120777` on every platform. On Unix its owner
///   comes from the read.
/// - `xattrs` is empty on every platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMeta {
    /// The kind of the entry, which the filter must not change.
    pub kind: EntryKind,
    /// The owner uid.
    pub uid: u32,
    /// The owner gid.
    pub gid: u32,
    /// The full `st_mode`, with the file-type bits.
    ///
    /// The filter can change the bits `0o7777`: the permission bits, the
    /// set-id bits, and the sticky bit. It must not change the file-type bits
    /// (`0o170000`) or set a bit outside `0o177777`.
    pub mode: u32,
    /// The extended attributes.
    pub xattrs: Xattrs,
    /// The target of a symlink, present for a symlink alone.
    ///
    /// The filter can give a symlink another target, the empty one included.
    /// It must not remove the target or give a target to an entry of another
    /// kind. On Windows, the walk refuses a target that holds `\` or starts
    /// with a drive prefix, because that target does not resolve on Linux.
    pub symlink_target: Option<String>,
}

/// The action of the walk on an entry, as the entry filter decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryAction {
    /// The entry stays in the tree, and the walk enters it if it is a directory.
    Keep,
    /// The walk leaves out the entry, and for a directory its whole subtree.
    Skip,
}

/// The path of a tree entry relative to the walk root.
///
/// The path joins the UTF-8 names of the parent directories and of the entry
/// with `/`, on every platform. The walk root has the empty path.
#[derive(Debug)]
pub struct EntryPath {
    path: String,
}

impl EntryPath {
    /// Returns the path as a string slice.
    pub fn as_str(&self) -> &str {
        &self.path
    }

    /// Returns the path as a [`Path`].
    pub fn as_path(&self) -> &Path {
        Path::new(&self.path)
    }

    /// Returns `true` if the path names the walk root.
    pub fn is_root(&self) -> bool {
        self.path.is_empty()
    }
}

impl fmt::Display for EntryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.path)
    }
}

/// The entry filter of a scan.
///
/// The filter runs once for each entry, the root included, before the scan
/// hashes the entry. For a directory, it runs before the walk enters the
/// directory. It can change these fields of the [`EntryMeta`]:
///
/// - the owner, `uid` and `gid`
/// - the bits `0o7777` of `mode`
/// - `xattrs`
/// - `symlink_target` of a symlink
///
/// The returned [`EntryAction`] decides whether the walk keeps the entry. If
/// the filter makes a change that [`EntryMeta`] does not allow, the scan
/// fails with [`Error::Walk`](crate::Error::Walk) of the kind `InvalidData`.
///
/// The filter runs on the task that drives the scan, so it must not block for
/// long.
pub type EntryFilter = Box<dyn FnMut(&EntryPath, &mut EntryMeta) -> EntryAction + Send>;

/// The options of [`TreeModel::scan`].
#[derive(Default)]
pub struct ScanOptions {
    /// The filter that sees each entry.
    ///
    /// If it is `None`, the walk keeps each entry with the metadata that
    /// [`EntryMeta`] describes.
    pub entry_filter: Option<EntryFilter>,
    /// The most regular files that the hash pass reads at the same time.
    ///
    /// The default is the number of CPUs, or 1 if that number is not known.
    /// The pass caps the number at the thread count of the blocking pool of
    /// the runtime. If the value is `Some(0)`, the scan returns
    /// [`Error::InvalidInput`](crate::Error::InvalidInput) and the walk does
    /// not start.
    pub hash_jobs: Option<usize>,
}

/// Returns an `io::Error` of the kind `InvalidData`.
fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Returns the kind of the entry whose metadata read gave `md`, or refuses an
/// entry of another kind.
fn classify(md: &std::fs::Metadata) -> io::Result<EntryKind> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 && !md.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the entry is a reparse point that is not a symlink",
            ));
        }
    }
    let ty = md.file_type();
    if ty.is_symlink() {
        Ok(EntryKind::Symlink)
    } else if ty.is_dir() {
        Ok(EntryKind::Dir)
    } else if ty.is_file() {
        Ok(EntryKind::File)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the entry is not a regular file, a directory, or a symlink",
        ))
    }
}

/// Returns the metadata that the filter sees for an entry of `kind` whose
/// metadata read gave `md`.
#[cfg(unix)]
fn default_meta(kind: EntryKind, md: &std::fs::Metadata, target: Option<String>) -> EntryMeta {
    use std::os::unix::fs::MetadataExt;
    unix_meta(kind, md.uid(), md.gid(), md.mode(), target)
}

/// Returns the metadata that the filter sees for an entry of `kind` whose
/// metadata read gave `uid`, `gid`, and `mode`.
#[cfg(unix)]
fn unix_meta(kind: EntryKind, uid: u32, gid: u32, mode: u32, target: Option<String>) -> EntryMeta {
    let mode = match kind {
        EntryKind::Symlink => SYMLINK_MODE,
        EntryKind::File | EntryKind::Dir => mode,
    };
    EntryMeta {
        kind,
        uid,
        gid,
        mode,
        xattrs: Xattrs::empty(),
        symlink_target: target,
    }
}

/// Returns the metadata that the filter sees for an entry of `kind`. The
/// platform gives no owner and no Unix mode, so the values are fixed.
#[cfg(not(unix))]
fn default_meta(kind: EntryKind, _md: &std::fs::Metadata, target: Option<String>) -> EntryMeta {
    let mode = match kind {
        EntryKind::File => S_IFREG | 0o644,
        EntryKind::Dir => S_IFDIR | 0o755,
        EntryKind::Symlink => SYMLINK_MODE,
    };
    EntryMeta {
        kind,
        uid: 0,
        gid: 0,
        mode,
        xattrs: Xattrs::empty(),
        symlink_target: target,
    }
}

/// Checks what the entry filter left in the metadata of an entry of `kind`.
fn check_filtered(kind: EntryKind, meta: &EntryMeta) -> io::Result<()> {
    if meta.kind != kind {
        return Err(invalid_data(
            "the entry filter changed the kind of the entry",
        ));
    }
    if meta.mode & S_IFMT != kind.type_bits() {
        return Err(invalid_data(
            "the entry filter changed the file-type bits of the mode",
        ));
    }
    if meta.mode & !MODE_BITS != 0 {
        return Err(invalid_data(
            "the entry filter set a bit above the file-type bits of the mode",
        ));
    }
    match (kind, &meta.symlink_target) {
        (EntryKind::Symlink, Some(target)) => check_target(target),
        (EntryKind::Symlink, None) => Err(invalid_data(
            "the entry filter removed the target of a symlink",
        )),
        (EntryKind::File | EntryKind::Dir, Some(_)) => Err(invalid_data(
            "the entry filter gave a symlink target to an entry that is not a symlink",
        )),
        (EntryKind::File | EntryKind::Dir, None) => Ok(()),
    }
}

/// Refuses a symlink target that does not resolve on Linux: a target that
/// holds `\` or starts with a drive prefix.
#[cfg(windows)]
fn check_target(target: &str) -> io::Result<()> {
    let bytes = target.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if drive || target.contains('\\') {
        return Err(invalid_data(
            "the symlink target holds `\\` or a drive prefix, and it does not resolve on Linux",
        ));
    }
    Ok(())
}

/// Accepts every UTF-8 symlink target.
#[cfg(not(windows))]
fn check_target(_target: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_symlink_gets_the_mode_0o120777_whatever_the_read_gives() {
        let target = Some("target".to_owned());
        let meta = unix_meta(EntryKind::Symlink, 7, 8, 0o120755, target.clone());
        assert_eq!(meta.mode, 0o120777);
        assert_eq!((meta.uid, meta.gid), (7, 8));
        assert_eq!(meta.symlink_target, target);
        let meta = unix_meta(EntryKind::File, 7, 8, 0o100600, None);
        assert_eq!(meta.mode, 0o100600);
    }
}
