//! The size caps of loose objects, and the blocking open of a file below a
//! directory descriptor.
//!
//! A metadata read stops at the metadata cap of the format, 128 MiB
//! ([`MAX_METADATA_SIZE`]), so a malformed object cannot use all memory.

use std::os::fd::OwnedFd;

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags};

pub use ostrya_core::MAX_METADATA_SIZE;

/// The maximum size of the framed file header of a content object.
///
/// A reader loads a header up to this size. The limit applies to the archive
/// form on disk and to the same framing that arrives over HTTP.
///
/// A header holds the uid, the gid, the mode, the rdev, a symlink target, and
/// the xattr array. A typical header is a few hundred bytes. A header with
/// large xattrs is a few kilobytes. Linux limits one xattr value to 64 KiB, so
/// 1 MiB holds a header with many of them.
///
/// The limit is much less than [`MAX_METADATA_SIZE`] (128 MiB) for two reasons:
///
/// - The header length comes from the object stream.
/// - The receive path holds one header buffer for each fetch in flight.
pub(crate) const MAX_FILE_HEADER_SIZE: u64 = 1024 * 1024;

/// Opens the file at `path` under `dir` for reading.
///
/// If `strict` is set, the open is an `openat2` with `RESOLVE_BENEATH` and
/// `RESOLVE_NO_SYMLINKS`. It follows no symlink in any component of `path`,
/// it does not leave `dir`, and it does not wait on a FIFO. A file that is not
/// a regular file is refused with the kind `ErrorKind::InvalidData`. A symlink
/// fails the open with `ELOOP`. This is the strict open mode of
/// [`Repo::open_at_strict`](crate::Repo::open_at_strict).
pub(crate) fn open_regular_file(
    dir: rustix::fd::BorrowedFd<'_>,
    path: &str,
    strict: bool,
) -> std::io::Result<OwnedFd> {
    let fd = if strict {
        rustix::fs::openat2(
            dir,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )?
    } else {
        rustix::fs::openat(dir, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?
    };
    if strict && FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) != FileType::RegularFile {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{path} is not a regular file"),
        ));
    }
    Ok(fd)
}

/// Opens the file at `path` under `dir` for reading, and follows no symlink
/// at the last component of `path`.
///
/// If `strict` is set, the open is the strict open of [`open_regular_file`].
/// If `strict` is not set, the open is an `openat` with `O_NOFOLLOW`. A
/// symlink at the last component fails the open with `ELOOP`. This open
/// follows a symlink at a directory component of `path`. It does not check
/// the file type, and it can wait on a FIFO.
pub(crate) fn open_regular_file_nofollow(
    dir: rustix::fd::BorrowedFd<'_>,
    path: &str,
    strict: bool,
) -> std::io::Result<OwnedFd> {
    if strict {
        return open_regular_file(dir, path, true);
    }
    Ok(rustix::fs::openat(
        dir,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?)
}
