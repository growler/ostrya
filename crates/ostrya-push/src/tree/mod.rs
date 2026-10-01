//! The walk of a local directory into a tree model.
//!
//! [`TreeModel::scan`] walks a directory with `std::fs` and gives the checksum
//! of each object of the tree: a content object for each regular file and
//! symlink, and a dirtree and a dirmeta object for each directory. The model
//! stores each entry once, as its name, its metadata, and the index of its
//! parent directory. Its memory grows with the number of entries and the
//! length of their names, and it holds no file content.
//!
//! # The walk
//!
//! - The walk does not follow symlinks. The walk root must be a directory.
//! - The walk reads a directory listing to its end and closes the directory
//!   before it enters a subdirectory, so it holds one directory open at a
//!   time. It reads the metadata of each entry with `DirEntry::metadata`, and
//!   the target of each symlink, while it reads the listing. Only the walk
//!   root is read with `symlink_metadata`.
//! - Names must be valid UTF-8 and must pass the dirtree name rule of
//!   `ostrya-core`. A symlink target must be valid UTF-8.
//! - Regular files, directories, and symlinks are taken. Any other entry, a
//!   device node, a fifo, a socket, or a Windows reparse point that is not a
//!   symlink, stops the walk before the entry filter runs, so the filter never
//!   sees it.
//! - After the walk closes a directory, it runs the [`EntryFilter`] on each
//!   entry in the order of the listing, and then it enters each kept
//!   subdirectory in turn. The filter sees the root first, with the empty
//!   path. [`EntryAction::Skip`] leaves out an entry, and for a directory its
//!   whole subtree. A skipped entry is not opened. `Skip` on the root stops
//!   the walk.
//! - A file with more than one hard link in the tree is read and hashed once
//!   for each of its paths.
//!
//! # The hash pass
//!
//! - Each kept regular file is read once, on the blocking pool of the
//!   runtime, and hashed over its file header and its payload. The pass
//!   starts a file as soon as the filter keeps it, in the order of the walk,
//!   with at most [`ScanOptions::hash_jobs`] files in flight.
//! - A job reads its file in chunks of at most 64 KiB, and it checks a stop
//!   flag of the pass before each chunk. At the first error of the walk or of
//!   a job, the pass sets the flag and starts no new job. It waits until each
//!   job in flight stops, and then it returns the error. So no file of the
//!   pass is open when [`TreeModel::scan`] returns. When the future of the
//!   scan is dropped, the pass sets the flag, and each job in flight stops at
//!   its next chunk.
//! - On Unix a job opens its file with `O_NOFOLLOW | O_NONBLOCK`, and on
//!   Windows with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`.
//!   One metadata read of the open file must show a regular file. On Unix
//!   its device and inode numbers must also equal those that the walk read,
//!   so a directory above the file that became a symlink after the walk does
//!   not give the job another file. Windows has no such check.
//! - The model records the number of payload bytes each job read.
//! - After the walk and the jobs end, each directory is hashed bottom-up: its
//!   dirtree object with the entries sorted by name, and its dirmeta object.
//!
//! # The send pass
//!
//! - [`TreeModel`] is the [`ObjectSource`](crate::ObjectSource) of a push,
//!   once [`TreeModel::set_commit`] gave it the commit over the tree.
//! - The send pass opens each regular file again, with the open, the type
//!   check, and on Unix the identity check of the hash pass, on the blocking
//!   pool. It gives the file with the number of payload bytes the hash pass
//!   read, and it reads no length and computes no checksum of its own. The
//!   server verifies each object, so a file that changed after the hash
//!   pass fails the push there.
//! - A symlink opens nothing. A dirtree or a dirmeta object is serialized
//!   again from the model.
//!
//! # Errors
//!
//! Each failure of the walk and of the hash pass is [`Error::Walk`], which
//! names the entry on the local filesystem, the walk root included, and keeps
//! the `io::ErrorKind`:
//!
//! - the kind of the call that failed, for example `PermissionDenied` or
//!   `NotFound`;
//! - `InvalidInput` for a walk root that is not a directory, and for `Skip` on
//!   the root;
//! - `Unsupported` for an entry that is not a regular file, a directory, or a
//!   symlink, and on Windows for a symlink whose target `std` cannot read;
//! - `InvalidData` for a name that is not valid UTF-8 or that fails the name
//!   rule, for a symlink target that is not valid UTF-8, for a change of the
//!   filter that the walk refuses, for a file whose type or identity changed
//!   after the walk read it, and for a dirtree or a dirmeta object over
//!   [`MAX_METADATA_SIZE`](ostrya_core::MAX_METADATA_SIZE).
//!
//! A failed open of the send pass is [`Error::Walk`] too, with the same
//! kinds, and the session returns it inside
//! [`Error::Source`](crate::Error::Source).
//!
//! When more than one entry fails, the error names one failing path. With
//! more than one hash job, which failure comes first is not fixed.
//!
//! [`Error::Walk`]: crate::Error::Walk

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
    /// The file-type bits of the kind.
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
///   follow a symlink.
/// - On other platforms, `uid` and `gid` are 0, and `mode` is `0o100644` for
///   a regular file and `0o40755` for a directory.
/// - A symlink has the mode `0o120777` on every platform. On Unix its owner
///   comes from the read.
/// - `xattrs` is empty on every platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMeta {
    /// The kind of the entry. The filter must not change it.
    pub kind: EntryKind,
    /// The owner uid.
    pub uid: u32,
    /// The owner gid.
    pub gid: u32,
    /// The full `st_mode`, the file-type bits included. The filter can change
    /// the bits below the file-type bits, and it must not change the
    /// file-type bits or set a bit above them.
    pub mode: u32,
    /// The extended attributes.
    pub xattrs: Xattrs,
    /// The target of a symlink. It is present for a symlink alone. The filter
    /// can give a symlink another target, the empty one included, and it must
    /// not remove the target or give one to another kind.
    pub symlink_target: Option<String>,
}

/// What the walk does with an entry, as the entry filter decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryAction {
    /// Take the entry, and for a directory enter it.
    Keep,
    /// Leave out the entry, and for a directory its whole subtree.
    Skip,
}

/// The path of a tree entry relative to the walk root.
///
/// The path is the UTF-8 names of the entry and of the directories above it,
/// joined with `/` on every platform. The walk root has the empty path.
#[derive(Debug)]
pub struct EntryPath {
    path: String,
}

impl EntryPath {
    /// The path as a string.
    pub fn as_str(&self) -> &str {
        &self.path
    }

    /// The path as a `Path`.
    pub fn as_path(&self) -> &Path {
        Path::new(&self.path)
    }

    /// Whether the path names the walk root.
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
/// The filter runs once for each entry, the root included, before the entry
/// is hashed. It can change the owner, the mode bits below the file-type
/// bits, the extended attributes, and the target of a symlink, and it
/// decides whether the walk keeps the entry. For a directory it runs before
/// the walk enters the directory.
///
/// The filter runs on the task that drives the scan, and not on the blocking
/// pool, so it must not block for long.
pub type EntryFilter = Box<dyn FnMut(&EntryPath, &mut EntryMeta) -> EntryAction + Send>;

/// The options of [`TreeModel::scan`].
#[derive(Default)]
pub struct ScanOptions {
    /// The filter that sees each entry. With none, the walk keeps each entry
    /// with its default metadata.
    pub entry_filter: Option<EntryFilter>,
    /// The most regular files the hash pass reads at the same time. The
    /// default is the number of CPUs, or 1 when that number is not known.
    /// The pass takes at most the size of the blocking pool of the runtime.
    /// `Some(0)` is [`Error::InvalidInput`](crate::Error::InvalidInput), and
    /// the walk does not start.
    pub hash_jobs: Option<usize>,
}

/// An `io::Error` of the kind `InvalidData`.
fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// The kind of the entry whose metadata read gave `md`, or the refusal of an
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

/// The metadata the filter sees for an entry of `kind`, whose metadata read
/// gave `md`.
#[cfg(unix)]
fn default_meta(kind: EntryKind, md: &std::fs::Metadata, target: Option<String>) -> EntryMeta {
    use std::os::unix::fs::MetadataExt;
    unix_meta(kind, md.uid(), md.gid(), md.mode(), target)
}

/// The metadata the filter sees for an entry of `kind` whose metadata read
/// gave `uid`, `gid`, and `mode`.
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

/// The metadata the filter sees for an entry of `kind`. The platform gives
/// no owner and no Unix mode, so the values are fixed.
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

/// Check what the entry filter left in the metadata of an entry of `kind`.
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

/// Refuse a symlink target that would not resolve on Linux: one that holds
/// `\` or starts with a drive prefix.
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

/// Every UTF-8 symlink target is taken.
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
