//! Blocking I/O functions for loose objects.
//!
//! These synchronous functions make the `openat`, `statat`, `read`, and xattr
//! system calls of the read path. Each function takes a borrowed directory
//! descriptor and a loose path that the caller computes. The async methods on
//! [`Repo`](crate::Repo) run them on the blocking pool.
//!
//! A metadata read stops at the metadata cap of the format, 128 MiB
//! ([`MAX_METADATA_SIZE`]), so a malformed object cannot use all memory.

use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};

use ostrya_core::Xattrs;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
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
    Ok(rustix::fs::openat(
        dir,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
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

/// Returns the on-disk size in bytes of a loose object at `path` in `dir`.
///
/// If the object does not exist, the error has the kind `ErrorKind::NotFound`.
pub(crate) fn object_size(dir: rustix::fd::BorrowedFd<'_>, path: &str) -> std::io::Result<u64> {
    let stat = rustix::fs::statat(dir, path, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(stat.st_size.max(0) as u64)
}

/// Opens a content object as a [`std::fs::File`] positioned after `skip` bytes.
///
/// For an archive object, `skip` is the length of the framed header. The caller
/// gives the file to a streaming reader.
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

/// Reads the value of one extended attribute from an open descriptor.
///
/// If the attribute does not exist, the function returns `None`.
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
            // The attribute does not exist, or the file system has no xattr support.
            Err(Errno::NODATA) | Err(Errno::NOTSUP) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
    }
}

/// Reads all extended attributes of an open descriptor into an [`Xattrs`] set.
///
/// The set is canonical. Each name keeps its terminating NUL, as in the on-disk
/// form.
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
    collect_xattrs(names, |name| read_xattr(fd, name))
}

/// Reads the extended attributes of an entry relative to a directory descriptor.
///
/// If the entry is a symlink, the function reads the attributes of the symlink
/// itself. `name` can name an entry several directories below `dir`.
///
/// A symlink cannot be opened for a descriptor, so [`read_all_xattrs`] cannot
/// read it. This function addresses the entry through `/proc/self/fd` with
/// no-follow. It reads the entry with the path-based `l` xattr calls.
pub(crate) fn read_link_xattrs(
    dir: rustix::fd::BorrowedFd<'_>,
    name: impl AsRef<std::ffi::OsStr>,
) -> Result<Xattrs> {
    let link = proc_fd_path(dir, name.as_ref());
    let mut names_buf = vec![0u8; 256];
    let names = loop {
        match rustix::fs::llistxattr(&link, &mut names_buf[..]) {
            Ok(n) => break &names_buf[..n],
            Err(Errno::RANGE) => {
                let grown = names_buf.len().saturating_mul(2).max(512);
                names_buf.resize(grown, 0);
            }
            Err(Errno::NOTSUP) => return Ok(Xattrs::empty()),
            Err(e) => return Err(Error::Io(e.into())),
        }
    };
    collect_xattrs(names, |xname| read_link_xattr(&link, xname))
}

/// Reads one extended attribute of the entry at a `/proc/self/fd` path.
///
/// The read does not follow a symlink. If the attribute does not exist, the
/// function returns `None`. The function is [`read_xattr`] with the path-based
/// `lgetxattr` call.
fn read_link_xattr(link: &std::path::Path, name: &str) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; 256];
    loop {
        match rustix::fs::lgetxattr(link, name, &mut buf[..]) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(Some(buf));
            }
            Err(Errno::RANGE) => {
                let grown = buf.len().saturating_mul(2).max(512);
                buf.resize(grown, 0);
            }
            Err(Errno::NODATA) | Err(Errno::NOTSUP) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
    }
}

/// Builds a canonical [`Xattrs`] set from a list of names and a value reader.
///
/// `names` is a NUL-separated list of attribute names. `read_value` reads the
/// value of one name. The set stores each name with one terminating NUL, as in
/// the on-disk form.
///
/// If an attribute disappears between the list call and the read of its value,
/// the function skips it.
fn collect_xattrs(
    names: &[u8],
    mut read_value: impl FnMut(&str) -> std::io::Result<Option<Vec<u8>>>,
) -> Result<Xattrs> {
    let mut pairs = Vec::new();
    for raw_name in names.split(|&b| b == 0) {
        if raw_name.is_empty() {
            continue;
        }
        let name = std::str::from_utf8(raw_name)
            .map_err(|_| Error::InvalidFormat("xattr name is not valid UTF-8".into()))?;
        let Some(value) = read_value(name).map_err(Error::Io)? else {
            continue;
        };
        let mut stored = raw_name.to_vec();
        stored.push(0);
        pairs.push((stored, value));
    }
    Ok(Xattrs::new(pairs)?)
}

/// Returns the `/proc/self/fd` path of `name` relative to a directory descriptor.
///
/// The path has the form `/proc/self/fd/<dirfd>/<name>`. The path-based
/// no-follow xattr calls use it to reach a symlink, because a symlink cannot be
/// opened for a descriptor. They also use it to reach an entry of another kind
/// with no open call.
fn proc_fd_path(dir: rustix::fd::BorrowedFd<'_>, name: &std::ffi::OsStr) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    path.push(name);
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    /// Checks that `read_link_xattrs` reads the symlink itself, with no-follow.
    ///
    /// The test makes a symlink to a regular file that has an xattr. The
    /// function returns the xattr set of the symlink. The set of the target
    /// does not show through the symlink.
    ///
    /// An xattr on a symlink needs a privileged namespace. The VFS refuses
    /// `user.*` on a symlink. The other namespaces need `CAP_SYS_ADMIN` or the
    /// permission of an LSM. An unprivileged test cannot put an xattr on the
    /// symlink, so the test checks only the no-follow rule.
    #[test]
    fn read_link_xattrs_does_not_follow_to_the_target() {
        let dir = std::env::temp_dir().join(format!("ostrya-linkxattr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(dir.join("target"), b"payload").unwrap();
        rustix::fs::setxattr(
            dir.join("target"),
            "user.demo",
            b"value",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        std::os::unix::fs::symlink("target", dir.join("link")).unwrap();

        let dfd = std::fs::File::open(&dir).unwrap();

        // The target has the xattr when the test reads it through its descriptor.
        let tfd = rustix::fs::openat(
            dfd.as_fd(),
            "target",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let target_xattrs = read_all_xattrs(tfd.as_fd()).unwrap();
        assert!(
            target_xattrs
                .iter()
                .any(|(n, v)| n == b"user.demo\0" && v == b"value"),
            "the target file carries user.demo"
        );

        // The link, read with no-follow, has an empty xattr set. The xattr of
        // the target does not show through the link.
        let link_xattrs = read_link_xattrs(dfd.as_fd(), "link").unwrap();
        assert_eq!(
            link_xattrs.iter().count(),
            0,
            "the symlink's own xattr set is empty, not the target's: {link_xattrs:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
