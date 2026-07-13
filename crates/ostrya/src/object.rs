//! Blocking loose-object I/O primitives.
//!
//! These synchronous helpers do the `openat`/`statat`/`read`/xattr syscalls
//! that back the reading path. Each takes a borrowed directory fd and a
//! precomputed loose path; the async methods on [`Repo`](crate::Repo) run them
//! on the blocking pool. Metadata reads are bounded by the format's 128 MiB
//! metadata cap so a malformed object cannot exhaust memory.

use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};

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

/// The on-disk size in bytes of a loose object at `path` relative to `dir`. A
/// missing object surfaces as `ErrorKind::NotFound`.
pub(crate) fn object_size(dir: rustix::fd::BorrowedFd<'_>, path: &str) -> std::io::Result<u64> {
    let stat = rustix::fs::statat(dir, path, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(stat.st_size.max(0) as u64)
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
    collect_xattrs(names, |name| read_xattr(fd, name))
}

/// Read a symlink's own extended attributes -- the link itself, not its
/// target -- relative to a directory fd. A symlink cannot be opened for an fd,
/// so the fd-based [`read_all_xattrs`] cannot reach it; this addresses the link
/// no-follow through `/proc/self/fd` and reads it with the path-based `l` xattr
/// calls.
pub(crate) fn read_link_xattrs(dir: rustix::fd::BorrowedFd<'_>, name: &str) -> Result<Xattrs> {
    let link = proc_fd_path(dir, name);
    let mut names_buf = vec![0u8; 256];
    let names = loop {
        match rustix::fs::llistxattr(link.as_str(), &mut names_buf[..]) {
            Ok(n) => break &names_buf[..n],
            Err(Errno::RANGE) => {
                let grown = names_buf.len().saturating_mul(2).max(512);
                names_buf.resize(grown, 0);
            }
            Err(Errno::NOTSUP) => return Ok(Xattrs::empty()),
            Err(e) => return Err(Error::Io(e.into())),
        }
    };
    collect_xattrs(names, |xname| read_link_xattr(link.as_str(), xname))
}

/// Read one extended attribute of a symlink addressed by a `/proc/self/fd`
/// path, no-follow, or `None` when the attribute is absent. Mirrors
/// [`read_xattr`] with the path-based `lgetxattr`.
fn read_link_xattr(link: &str, name: &str) -> std::io::Result<Option<Vec<u8>>> {
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

/// Build a canonical [`Xattrs`] set from a NUL-separated list of attribute
/// names and a per-name value reader. Names are stored with a single
/// terminating NUL, matching the on-disk form. A name that races away between
/// listing and reading is skipped.
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

/// The `/proc/self/fd/<dirfd>/<name>` path addressing `name` relative to a
/// directory fd. The path-based no-follow xattr calls reach a symlink this way,
/// since a symlink cannot be opened for an fd.
fn proc_fd_path(dir: rustix::fd::BorrowedFd<'_>, name: &str) -> String {
    format!("/proc/self/fd/{}/{}", dir.as_raw_fd(), name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    /// `read_link_xattrs` reads the symlink itself, no-follow: a link pointing
    /// at an xattr-bearing regular file reports the link's own set, never the
    /// target's. Setting an xattr on a symlink needs a privileged namespace
    /// (the VFS forbids `user.*` on symlinks and gates the rest behind
    /// CAP_SYS_ADMIN or an LSM), so the link's own set cannot be populated in an
    /// unprivileged test; the no-follow contract is what the reader must honor.
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

        // The target, read by its fd, carries the xattr.
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

        // The link, read no-follow, does not: its own set is empty, and the
        // target's xattr does not leak through.
        let link_xattrs = read_link_xattrs(dfd.as_fd(), "link").unwrap();
        assert_eq!(
            link_xattrs.iter().count(),
            0,
            "the symlink's own xattr set is empty, not the target's: {link_xattrs:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
