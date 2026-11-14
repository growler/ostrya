//! Blocking I/O functions for loose objects.
//!
//! These synchronous functions make the `openat`, `statat`, and `read` system
//! calls of the read path. Each function takes a borrowed directory
//! descriptor and a loose path that the caller computes. The async methods on
//! [`Repo`](crate::Repo) run them on the blocking pool.
//!
//! A metadata read stops at the metadata cap of the format, 128 MiB
//! ([`MAX_METADATA_SIZE`]), so a malformed object cannot use all memory.

use std::io::Read;
use std::os::fd::OwnedFd;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};

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

/// Opens a loose object for reading, relative to a directory descriptor.
pub(crate) fn open_object(dir: rustix::fd::BorrowedFd<'_>, path: &str) -> std::io::Result<OwnedFd> {
    open_regular_file(dir, path, false)
}

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

/// Opens the fan-out directory `fanout` under `objects_fd` as a path
/// descriptor with `openat2`, `RESOLVE_BENEATH`, and `RESOLVE_NO_SYMLINKS`.
///
/// A symlink there fails the open with `ELOOP`. A missing entry gives the
/// kind `ErrorKind::NotFound`.
pub(crate) fn open_fanout_beneath(
    objects_fd: rustix::fd::BorrowedFd<'_>,
    fanout: &str,
) -> std::io::Result<OwnedFd> {
    Ok(rustix::fs::openat2(
        objects_fd,
        fanout,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )?)
}

/// Returns the error of a metadata read for an object larger than the size cap.
///
/// The buffered loader and the streaming reader both return this error, so the
/// two paths refuse an oversized object in the same way.
pub(crate) fn metadata_cap_exceeded() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "object exceeds the metadata size cap",
    )
}

/// Reads a whole metadata object into memory and refuses one larger than `cap`.
///
/// If the object does not exist, the error has the kind `ErrorKind::NotFound`.
/// The async wrapper maps this kind to [`Error::ObjectNotFound`].
pub(crate) fn read_meta_object(
    dir: rustix::fd::BorrowedFd<'_>,
    path: &str,
    cap: u64,
) -> std::io::Result<Vec<u8>> {
    read_meta_fd(open_object(dir, path)?, cap)
}

/// Reads a whole metadata object from an open descriptor.
///
/// The cap rule is the same as in [`read_meta_object`]. If the descriptor is
/// not a regular file, the error has the kind `ErrorKind::InvalidData`.
pub(crate) fn read_meta_fd(fd: OwnedFd, cap: u64) -> std::io::Result<Vec<u8>> {
    let stat = rustix::fs::fstat(&fd)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "object is not a regular file",
        ));
    }
    let size = stat.st_size.max(0) as u64;
    if size > cap {
        return Err(metadata_cap_exceeded());
    }
    let file = std::fs::File::from(fd);
    let mut buf = Vec::with_capacity(size as usize);
    // `take` stops the read if the file grows between the `fstat` and the read.
    file.take(cap + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(metadata_cap_exceeded());
    }
    Ok(buf)
}

/// Returns `true` if a loose object exists at `path` relative to `dir`.
pub(crate) fn object_exists(dir: rustix::fd::BorrowedFd<'_>, path: &str) -> Result<bool> {
    match rustix::fs::statat(dir, path, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(e) => Err(Error::Io(e.into())),
    }
}
