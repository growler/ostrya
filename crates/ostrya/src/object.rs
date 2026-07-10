//! Blocking loose-object I/O primitives.
//!
//! These synchronous helpers do the `openat`/`statat`/`read`/xattr syscalls
//! that back the reading path. Each takes a borrowed directory fd and a
//! precomputed loose path; the async methods on [`Repo`](crate::Repo) run them
//! on the blocking pool. Metadata reads are bounded by the format's 128 MiB
//! metadata cap so a malformed object cannot exhaust memory.

use std::io::Read;
use std::os::fd::OwnedFd;

use ostrya_core::Xattrs;
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};

/// The maximum size of a metadata object the reader will load, matching the
/// format's 128 MiB metadata cap.
pub(crate) const MAX_METADATA_SIZE: u64 = 128 * 1024 * 1024;

/// Open a loose object for reading, relative to a directory fd.
fn open_object(dir: rustix::fd::BorrowedFd<'_>, path: &str) -> std::io::Result<OwnedFd> {
    Ok(rustix::fs::openat(
        dir,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Read a whole metadata object into memory, rejecting anything larger than
/// `cap`. A missing object surfaces as `ErrorKind::NotFound`, which the async
/// wrapper maps to [`Error::ObjectNotFound`].
pub(crate) fn read_meta_object(
    dir: rustix::fd::BorrowedFd<'_>,
    path: &str,
    cap: u64,
) -> std::io::Result<Vec<u8>> {
    let fd = open_object(dir, path)?;
    let stat = rustix::fs::fstat(&fd)?;
    let size = stat.st_size.max(0) as u64;
    if size > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "object exceeds the metadata size cap",
        ));
    }
    let file = std::fs::File::from(fd);
    let mut buf = Vec::with_capacity(size as usize);
    // `take` guards against a file that grows between stat and read.
    file.take(cap + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "object exceeds the metadata size cap",
        ));
    }
    Ok(buf)
}

/// Whether a loose object exists at `path` relative to `dir`.
pub(crate) fn object_exists(dir: rustix::fd::BorrowedFd<'_>, path: &str) -> Result<bool> {
    match rustix::fs::statat(dir, path, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Open a content object as a positioned [`std::fs::File`], seeking past
/// `skip` bytes (the framed header, for archive objects). The returned file is
/// handed to a streaming reader.
pub(crate) fn open_content_file(
    dir: rustix::fd::BorrowedFd<'_>,
    path: &str,
    skip: u64,
) -> std::io::Result<std::fs::File> {
    let fd = open_object(dir, path)?;
    let mut file = std::fs::File::from(fd);
    if skip > 0 {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(skip))?;
    }
    Ok(file)
}

/// Read the value of one extended attribute from an open fd, or `None` when the
/// attribute is absent.
pub(crate) fn read_xattr(
    fd: rustix::fd::BorrowedFd<'_>,
    name: &str,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; 256];
    loop {
        match rustix::fs::fgetxattr(fd, name, &mut buf[..]) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(Some(buf));
            }
            Err(Errno::RANGE) => {
                let grown = buf.len().saturating_mul(2).max(512);
                buf.resize(grown, 0);
            }
            // No such attribute, or the filesystem has no xattr support.
            Err(Errno::NODATA) | Err(Errno::NOTSUP) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
    }
}

/// Read every extended attribute from an open fd into a canonical [`Xattrs`]
/// set. Names are stored with their terminating NUL, matching the on-disk form.
pub(crate) fn read_all_xattrs(fd: rustix::fd::BorrowedFd<'_>) -> Result<Xattrs> {
    let mut names_buf = vec![0u8; 256];
    let names = loop {
        match rustix::fs::flistxattr(fd, &mut names_buf[..]) {
            Ok(n) => break &names_buf[..n],
            Err(Errno::RANGE) => {
                let grown = names_buf.len().saturating_mul(2).max(512);
                names_buf.resize(grown, 0);
            }
            Err(Errno::NOTSUP) => return Ok(Xattrs::empty()),
            Err(e) => return Err(Error::Io(e.into())),
        }
    };

    let mut pairs = Vec::new();
    for raw_name in names.split(|&b| b == 0) {
        if raw_name.is_empty() {
            continue;
        }
        let name = std::str::from_utf8(raw_name)
            .map_err(|_| Error::InvalidFormat("xattr name is not valid UTF-8".into()))?;
        let Some(value) = read_xattr(fd, name).map_err(Error::Io)? else {
            // Raced away between listing and reading; skip it.
            continue;
        };
        // The canonical stored form terminates the name with a single NUL.
        let mut stored = raw_name.to_vec();
        stored.push(0);
        pairs.push((stored, value));
    }
    Ok(Xattrs::new(pairs)?)
}
