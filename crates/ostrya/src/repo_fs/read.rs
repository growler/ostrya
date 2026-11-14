//! The read primitives: the open of a regular file, of a root file, and of a
//! loose object, the capped reads, the symlink targets, the status of an
//! entry, the extended attributes, and the fs-verity digest.
//!
//! Each open of a path below a [`RepoDir`] is one `openat2` with
//! `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`, as in the directory primitives,
//! with two exceptions. The open of a keyring file by
//! [`open_root_file`](RepoDir::open_root_file) is a plain `openat` that
//! follows a symlink. [`link_xattrs`](RepoDir::link_xattrs) opens the parent
//! directory with `openat2`, and then reaches the leaf through
//! `/proc/self/fd`. The path rules of the directory primitives apply. A
//! regular file opens with `O_NONBLOCK`, so the open of a FIFO does not wait
//! for a writer. One `statx` on the open descriptor then refuses each entry
//! that is not a regular file.
//!
//! Each read has a cap. A read of file content has the cap of the caller, and
//! a symlink target has the cap of the caller or a fixed cap. For
//! [`xattrs`] and [`link_xattrs`](RepoDir::link_xattrs), the cap applies to
//! the list of names and to each value, and not to their sum. It is the limit
//! of the kernel for each of them, 64 KiB.

use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use ostrya_core::Xattrs;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, StatxFlags};
use rustix::io::Errno;

use super::dir::{BENEATH, DIR_OPEN, io_error, is_component, require};
use super::{FsError, ObjectEntry, Opened, Reason, RepoDir, RepoLayout, RootFile, Stat, stat_fd};

/// The flags of the open of a regular file. `O_NOFOLLOW` refuses a symlink at
/// the leaf, and `O_NONBLOCK` keeps the open of a FIFO from waiting for a
/// writer. The flag changes no read of a regular file.
const FILE_OPEN: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

/// The flags of the open of a keyring file at the root. They are the flags of
/// [`FILE_OPEN`] with no `O_NOFOLLOW`, because a keyring file can be a
/// symlink.
const KEYRING_OPEN: OFlags = OFlags::RDONLY
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

/// The flags of the open of an entry itself. With `O_PATH|O_NOFOLLOW`, a
/// symlink at the leaf opens as the symlink, also with
/// `RESOLVE_NO_SYMLINKS`.
const LINK_OPEN: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

/// The size of the first buffer of an xattr list or value.
const XATTR_BUF_START: usize = 256;

/// The maximum size of an xattr list or value. It is the limit of the kernel.
const XATTR_MAX: usize = 64 * 1024;

/// The cap of the target of a symlink object, in bytes. It is `PATH_MAX`
/// with no terminating NUL.
const OBJECT_LINK_CAP: u64 = 4095;

/// The size of the stack buffer of a symlink read. It is `PATH_MAX`, one byte
/// more than the longest symlink target on Linux.
const LINK_STACK_LEN: usize = 4096;

/// The maximum number of passes of [`read_grown`].
const GROW_PASSES: usize = 4;

impl RepoDir {
    /// Opens the regular file at `path` below this handle for read, and gives
    /// the file and its status.
    ///
    /// The open is one `openat2`, and its descriptor keeps `O_NONBLOCK`. The
    /// errors of the open are those of
    /// [`open_dir`](RepoDir::open_dir): a symlink at a component, also at the
    /// leaf, gives [`Reason::Symlink`], and a `..`, `.`, or empty component or
    /// an absolute path gives [`Reason::Escape`]. An absent entry gives
    /// [`FsError::Absent`].
    ///
    /// An entry that is not a regular file gives [`Reason::NotRegular`] with
    /// its type. A FIFO and a directory open, and the `statx` on the
    /// descriptor refuses them. A socket and a device with no driver do not
    /// open, so the function reads their type with
    /// [`lstat`](RepoDir::lstat).
    pub(crate) fn open_regular(&self, path: &str) -> Result<Opened, FsError> {
        self.check_path(path)?;
        match rustix::fs::openat2(self, path, FILE_OPEN, Mode::empty(), BENEATH) {
            Ok(fd) => self.finish(fd, path),
            Err(e) => Err(self.open_error(e, path)),
        }
    }

    /// Opens the root file `file` for read, and gives the file and its
    /// status. The call is on the root handle.
    ///
    /// Each root file other than a keyring opens as
    /// [`open_regular`](RepoDir::open_regular) opens it, so a symlink at it
    /// gives [`Reason::Symlink`].
    ///
    /// A keyring file can be a symlink, also to a path outside the
    /// repository. Its open is one `openat` that follows each symlink. A name
    /// that is not one path component gives [`Reason::Escape`]. An absent
    /// file gives [`FsError::Absent`]. An entry that is not a regular file
    /// gives [`Reason::NotRegular`] with its type: for a socket and a device
    /// with no driver, one `statx` that follows the symlink reads the type.
    /// Each other errno, also `ELOOP` and `ENOTDIR`, gives [`FsError::Io`].
    ///
    /// A call on a handle other than the root is a defect of the caller: it
    /// fails a debug assertion, and gives an `InvalidInput` error in a release
    /// build.
    pub(crate) fn open_root_file(&self, file: RootFile) -> Result<Opened, FsError> {
        require(
            (self.kind == RepoLayout::Root).then_some(()),
            "open_root_file needs the root handle",
        )?;
        let RootFile::Keyring(name) = &file else {
            return self.open_regular(file.name());
        };
        if !is_component(name.as_bytes()) {
            return Err(FsError::Invalid {
                path: self.err_path(name),
                reason: Reason::Escape,
            });
        }
        match rustix::fs::openat(self, name.as_str(), KEYRING_OPEN, Mode::empty()) {
            Ok(fd) => self.finish(fd, name),
            Err(Errno::NOENT) => Err(FsError::Absent {
                path: self.err_path(name),
            }),
            Err(e @ (Errno::NXIO | Errno::NODEV)) => {
                match rustix::fs::statx(self, name.as_str(), AtFlags::empty(), StatxFlags::TYPE) {
                    Ok(stx) => match FileType::from_raw_mode(u32::from(stx.stx_mode)) {
                        FileType::RegularFile => Err(io_error(e)),
                        other => Err(FsError::Invalid {
                            path: self.err_path(name),
                            reason: Reason::NotRegular(other),
                        }),
                    },
                    Err(e) => Err(io_error(e)),
                }
            }
            Err(e) => Err(io_error(e)),
        }
    }

    /// Opens the loose object at `path` below this handle, and gives a
    /// regular file with its status, or the target of a symlink object. The
    /// call is on a handle of kind [`RepoLayout::Objects`] or
    /// [`RepoLayout::Staging`].
    ///
    /// The function first opens the path as
    /// [`open_regular`](RepoDir::open_regular) does. When the open gives
    /// `ELOOP`, a second `openat2` with `O_PATH|O_NOFOLLOW` opens a symlink at
    /// the leaf as the symlink, and the function reads its target with a cap
    /// of 4095 bytes. A longer target gives [`Reason::TooLarge`]. A symlink at
    /// a component before the leaf fails the second open too, and gives
    /// [`Reason::Symlink`]. An entry that is no longer a symlink at the read
    /// of the target gives [`FsError::Io`] with `EINVAL`.
    ///
    /// The other errors are those of [`open_regular`](RepoDir::open_regular).
    /// A call on a handle of another kind is a defect of the caller.
    pub(crate) fn open_object(&self, path: &str) -> Result<ObjectEntry, FsError> {
        require(
            matches!(self.kind, RepoLayout::Objects | RepoLayout::Staging).then_some(()),
            "open_object needs an objects handle or a staging handle",
        )?;
        self.check_path(path)?;
        match rustix::fs::openat2(self, path, FILE_OPEN, Mode::empty(), BENEATH) {
            Ok(fd) => self.finish(fd, path).map(ObjectEntry::Regular),
            Err(Errno::LOOP) => {
                let fd = self.open_link(path)?;
                self.read_link_fd(fd.as_fd(), path, OBJECT_LINK_CAP)
                    .map(ObjectEntry::Symlink)
            }
            Err(e) => Err(self.open_error(e, path)),
        }
    }

    /// Reads the whole regular file at `path` below this handle. The file has
    /// `cap` bytes at most.
    ///
    /// The open and its errors are those of
    /// [`open_regular`](RepoDir::open_regular). A file with a size over `cap`
    /// gives [`Reason::TooLarge`] before the read. The read stops after
    /// `cap + 1` bytes, so a file that grows after the `statx` also gives
    /// [`Reason::TooLarge`]. A buffer of the size of the file that cannot be
    /// allocated gives an `OutOfMemory` error. An error of the read gives
    /// [`FsError::Io`].
    pub(crate) fn read_capped(&self, path: &str, cap: u64) -> Result<Vec<u8>, FsError> {
        let Opened { file, stat } = self.open_regular(path)?;
        let too_large = || FsError::Invalid {
            path: self.err_path(path),
            reason: Reason::TooLarge { cap },
        };
        if stat.size > cap {
            return Err(too_large());
        }
        let mut buf = Vec::new();
        buf.try_reserve_exact(usize::try_from(stat.size).unwrap_or(usize::MAX))
            .map_err(|_| FsError::Io(io::ErrorKind::OutOfMemory.into()))?;
        (&file)
            .take(cap.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(FsError::Io)?;
        if buf.len() as u64 > cap {
            return Err(too_large());
        }
        Ok(buf)
    }

    /// Opens the regular file at `path` below this handle for read, at the
    /// position `offset`, and gives the file and its status.
    ///
    /// The open and its errors are those of
    /// [`open_regular`](RepoDir::open_regular). A positive `offset` costs one
    /// seek, and an error of the seek gives [`FsError::Io`].
    pub(crate) fn open_regular_at(&self, path: &str, offset: u64) -> Result<Opened, FsError> {
        let mut opened = self.open_regular(path)?;
        if offset > 0 {
            opened
                .file
                .seek(SeekFrom::Start(offset))
                .map_err(FsError::Io)?;
        }
        Ok(opened)
    }

    /// Reads the target of the symlink at `path` below this handle. The
    /// target has `cap` bytes at most.
    ///
    /// One `openat2` with `O_PATH|O_NOFOLLOW` opens the symlink itself, and a
    /// `readlinkat` on its descriptor reads the target into a stack buffer of
    /// `cap + 1` bytes, or of 4096 bytes for a larger cap. A symlink target on
    /// Linux has 4095 bytes at most, so the cap in effect is the smaller of
    /// `cap` and 4095. A target over that cap gives [`Reason::TooLarge`]. An
    /// entry that is not a symlink gives [`FsError::Io`] with `EINVAL`. The
    /// path rules and the errors of the open are those of
    /// [`open_dir`](RepoDir::open_dir). A symlink at a component before the
    /// leaf gives [`Reason::Symlink`].
    pub(crate) fn read_link(&self, path: &str, cap: u64) -> Result<Vec<u8>, FsError> {
        self.check_path(path)?;
        let fd = self.open_link(path)?;
        self.read_link_fd(fd.as_fd(), path, cap)
    }

    /// Returns the status of the entry at `path` below this handle. A
    /// symlink at the leaf gives the status of the symlink itself.
    ///
    /// One `openat2` with `O_PATH|O_NOFOLLOW` opens the entry, and one
    /// `statx` reads its status. The path rules and the errors of the open
    /// are those of [`open_dir`](RepoDir::open_dir). A symlink at a component
    /// before the leaf gives [`Reason::Symlink`]. An error of the `statx`
    /// gives [`FsError::Io`].
    pub(crate) fn lstat(&self, path: &str) -> Result<Stat, FsError> {
        self.check_path(path)?;
        let fd = self.open_link(path)?;
        stat_fd(fd.as_fd())
    }

    /// Returns `true` if an entry exists at `path` below this handle. A
    /// symlink at the leaf exists, also when its target does not.
    ///
    /// The check is one `openat2` with `O_PATH|O_NOFOLLOW`. An absent entry
    /// gives `false`. Each other error of the open stays an error, as in
    /// [`lstat`](RepoDir::lstat): a symlink at a component before the leaf
    /// gives [`Reason::Symlink`], and a file there gives
    /// [`Reason::NotDirectory`].
    pub(crate) fn exists(&self, path: &str) -> Result<bool, FsError> {
        self.check_path(path)?;
        match rustix::fs::openat2(self, path, LINK_OPEN, Mode::empty(), BENEATH) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(e) => Err(FsError::at(e, self.err_path(path))),
        }
    }

    /// Returns the extended attributes of the entry at `path` below this
    /// handle. A symlink at the leaf gives the attributes of the symlink
    /// itself.
    ///
    /// One `openat2` opens the parent directory of the leaf, with the path
    /// rules and the errors of [`open_dir`](RepoDir::open_dir). The leaf is
    /// read through `/proc/self/fd` with `llistxattr` and `lgetxattr`, which
    /// do not follow a symlink. An `ENOENT` from them also comes when `/proc`
    /// is not mounted or is of another PID namespace, so one `statx` of the
    /// leaf with `AT_SYMLINK_NOFOLLOW` then makes sure that the leaf is
    /// absent. An absent leaf gives [`FsError::Absent`]. A leaf that the
    /// `statx` finds gives [`FsError::Io`] with a message that names
    /// `/proc/self/fd`. A
    /// file system with no xattr support gives an empty set. An attribute
    /// that is removed between the list and the read of its value is left
    /// out. Each other error gives [`FsError::Io`]. The rules of
    /// [`xattrs`] for the size and the names apply.
    pub(crate) fn link_xattrs(&self, path: &str) -> Result<Xattrs, FsError> {
        self.check_path(path)?;
        let (parent, leaf) = match path.rsplit_once('/') {
            Some((parent, leaf)) => {
                let fd = rustix::fs::openat2(self, parent, DIR_OPEN, Mode::empty(), BENEATH)
                    .map_err(|e| FsError::at(e, self.err_path(parent)))?;
                (Some(fd), leaf)
            }
            None => (None, path),
        };
        let dir = parent.as_ref().map_or(self.as_fd(), AsFd::as_fd);
        let link = format!("/proc/self/fd/{}/{leaf}", dir.as_raw_fd());
        let map = |e| self.link_error(e, dir, leaf, path);
        let mut list = Vec::new();
        let len = match read_grown(&mut list, |buf| rustix::fs::llistxattr(link.as_str(), buf)) {
            Ok(len) => len,
            Err(Errno::NOTSUP) => return Ok(Xattrs::empty()),
            Err(e) => return Err(map(e)),
        };
        collect_xattrs(
            &list[..len],
            |name, buf| read_grown(buf, |b| rustix::fs::lgetxattr(link.as_str(), name, b)),
            map,
        )
    }

    /// Returns the error of `errno` from an xattr call on the leaf `leaf` of
    /// the directory open at `dir`, through `/proc/self/fd`. `path` is the
    /// path of the leaf below this handle.
    ///
    /// For `ENOENT`, one `statx` of the leaf with `AT_SYMLINK_NOFOLLOW` makes
    /// sure that the leaf is absent, and then gives [`FsError::Absent`]. A
    /// leaf that the `statx` finds gives [`FsError::Io`] with a message that
    /// names `/proc/self/fd`. An error of the `statx` and each other errno
    /// give [`FsError::Io`].
    fn link_error(&self, errno: Errno, dir: BorrowedFd<'_>, leaf: &str, path: &str) -> FsError {
        if errno != Errno::NOENT {
            return io_error(errno);
        }
        match rustix::fs::statx(dir, leaf, AtFlags::SYMLINK_NOFOLLOW, StatxFlags::TYPE) {
            Err(Errno::NOENT) => FsError::Absent {
                path: self.err_path(path),
            },
            Err(e) => io_error(e),
            Ok(_) => FsError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "the xattr read of {} through /proc/self/fd gives ENOENT, but \
                     the entry exists: /proc is not mounted or is of another PID \
                     namespace",
                    self.err_path(path)
                ),
            )),
        }
    }

    /// Opens the entry at `path` below this handle itself, with
    /// `O_PATH|O_NOFOLLOW`. The caller checks `path`.
    fn open_link(&self, path: &str) -> Result<OwnedFd, FsError> {
        rustix::fs::openat2(self, path, LINK_OPEN, Mode::empty(), BENEATH)
            .map_err(|e| FsError::at(e, self.err_path(path)))
    }

    /// Reads the target of the symlink open at `fd` with `O_PATH|O_NOFOLLOW`.
    /// The target has `cap` bytes at most. `path` is the path of the symlink
    /// below this handle, for an error.
    ///
    /// `ENOENT` from the `readlinkat` means that the entry is not a symlink,
    /// and gives `EINVAL`.
    ///
    /// The read goes into a stack buffer of `cap + 1` bytes, or of 4096 bytes
    /// for a larger cap, and the target then costs one allocation of its own
    /// size. A target that fills the buffer is over `cap`, or has 4096 bytes
    /// or more, and gives [`Reason::TooLarge`].
    fn read_link_fd(&self, fd: BorrowedFd<'_>, path: &str, cap: u64) -> Result<Vec<u8>, FsError> {
        let map = |e| io_error(if e == Errno::NOENT { Errno::INVAL } else { e });
        let mut stack = [MaybeUninit::<u8>::uninit(); LINK_STACK_LEN];
        let len = usize::try_from(cap)
            .ok()
            .filter(|&c| c < LINK_STACK_LEN)
            .map_or(LINK_STACK_LEN, |c| c + 1);
        let (target, _) = rustix::fs::readlinkat_raw(fd, c"", &mut stack[..len]).map_err(map)?;
        if target.len() == len {
            return Err(FsError::Invalid {
                path: self.err_path(path),
                reason: Reason::TooLarge { cap },
            });
        }
        Ok(target.to_vec())
    }

    /// Gives the file open at `fd` and its status, or [`Reason::NotRegular`]
    /// if the file is not a regular file. `path` is the path of the file
    /// below this handle, for an error.
    fn finish(&self, fd: OwnedFd, path: &str) -> Result<Opened, FsError> {
        let stat = stat_fd(fd.as_fd())?;
        if stat.file_type != FileType::RegularFile {
            return Err(FsError::Invalid {
                path: self.err_path(path),
                reason: Reason::NotRegular(stat.file_type),
            });
        }
        Ok(Opened {
            file: File::from(fd),
            stat,
        })
    }

    /// Returns the error of `errno` from the open of the regular file at
    /// `path` below this handle.
    ///
    /// `ENXIO` and `ENODEV` come from a socket and a device with no driver.
    /// For them, [`lstat`](RepoDir::lstat) reads the type: an entry that is
    /// not a regular file gives [`Reason::NotRegular`], a regular file gives
    /// [`FsError::Io`] with `errno`, and an error of the `lstat` stays as it
    /// is. Each other errno gives the result of [`FsError::at`].
    fn open_error(&self, errno: Errno, path: &str) -> FsError {
        if !matches!(errno, Errno::NXIO | Errno::NODEV) {
            return FsError::at(errno, self.err_path(path));
        }
        match self.lstat(path) {
            Ok(stat) if stat.file_type != FileType::RegularFile => FsError::Invalid {
                path: self.err_path(path),
                reason: Reason::NotRegular(stat.file_type),
            },
            Ok(_) => io_error(errno),
            Err(e) => e,
        }
    }
}

/// Returns the extended attributes of the file open at `fd`.
///
/// The set is canonical, and each name keeps its terminating NUL, as in the
/// storage form of [`Xattrs`]. A name need not be UTF-8. The function reads
/// the list of names with `flistxattr` and each value with `fgetxattr`. Each
/// buffer starts at 256 bytes and grows to the size that the kernel gives,
/// to 64 KiB at most: a larger list or value gives [`FsError::Io`] with
/// `E2BIG`. One buffer serves the read of all values. A file system with no
/// xattr support gives an empty set. An attribute that is removed between
/// the list and the read of its value is left out. Each error gives
/// [`FsError::Io`]. A set that [`Xattrs::new`] refuses gives an
/// `InvalidData` error.
pub(crate) fn xattrs(fd: BorrowedFd<'_>) -> Result<Xattrs, FsError> {
    let mut list = Vec::new();
    let len = match read_grown(&mut list, |buf| rustix::fs::flistxattr(fd, buf)) {
        Ok(len) => len,
        Err(Errno::NOTSUP) => return Ok(Xattrs::empty()),
        Err(e) => return Err(io_error(e)),
    };
    collect_xattrs(
        &list[..len],
        |name, buf| read_grown(buf, |b| rustix::fs::fgetxattr(fd, name, b)),
        io_error,
    )
}

/// Returns the value of the extended attribute `name` of the file open at
/// `fd`, or `None` if the file has no such attribute.
///
/// A file system with no xattr support gives `None`. The buffer starts at 256
/// bytes and grows to the size that the kernel gives, to 64 KiB at most: a
/// larger value gives [`FsError::Io`] with `E2BIG`. Each other error gives
/// [`FsError::Io`].
pub(crate) fn xattr(fd: BorrowedFd<'_>, name: &str) -> Result<Option<Vec<u8>>, FsError> {
    let mut value = Vec::new();
    match read_grown(&mut value, |buf| rustix::fs::fgetxattr(fd, name, buf)) {
        Ok(len) => {
            value.truncate(len);
            Ok(Some(value))
        }
        Err(Errno::NODATA | Errno::NOTSUP) => Ok(None),
        Err(e) => Err(io_error(e)),
    }
}

/// Returns the fs-verity digest that the kernel holds for the file open at
/// `fd`, or `None`.
///
/// The file must be sealed with SHA-256, 4096-byte blocks, no salt, and a
/// data size of `size`. Each other file, each error, and each mismatch gives
/// `None`. The function issues two ioctls, so a caller calls it only for a
/// file that the `statx` reports as sealed ([`Stat::verity`]).
pub(crate) fn verity_digest(fd: BorrowedFd<'_>, size: u64) -> Option<[u8; 32]> {
    let desc = ostrya_sys::read_verity_descriptor(fd).ok()?;
    if desc.hash_algorithm != 1
        || desc.log_blocksize != 12
        || desc.salt_size != 0
        || desc.data_size != size
    {
        return None;
    }
    ostrya_sys::measure_verity(fd).ok()
}

/// Calls `call` with `buf` until the buffer holds the whole result, and gives
/// the length of the result. The result is `buf[..len]`.
///
/// An empty `buf` starts at 256 bytes. When `call` gives `ERANGE`, a call with
/// an empty buffer gives the size of the result, and `buf` grows to that
/// size exactly. A size over 64 KiB gives `E2BIG`. A result that grows
/// between the two calls causes one more pass. The function makes 4 passes
/// at most: `ERANGE` in the fourth pass gives `ERANGE`. `buf` keeps its
/// length, so a caller can use it again with no new allocation.
fn read_grown(
    buf: &mut Vec<u8>,
    mut call: impl FnMut(&mut [u8]) -> Result<usize, Errno>,
) -> Result<usize, Errno> {
    if buf.is_empty() {
        buf.resize(XATTR_BUF_START, 0);
    }
    let mut pass = 1;
    loop {
        match call(buf) {
            Err(Errno::RANGE) if pass < GROW_PASSES => {}
            other => return other,
        }
        let size = call(&mut [])?;
        if size > XATTR_MAX {
            return Err(Errno::TOOBIG);
        }
        if size > buf.len() {
            buf.reserve_exact(size - buf.len());
            buf.resize(size, 0);
        }
        pass += 1;
    }
}

/// Builds the set of the attributes in `list`, a list of names that each end
/// with a NUL.
///
/// `get` reads the value of a name into the buffer that it gets, and gives
/// the length of the value. `ENODATA` leaves the name out, and `map` gives
/// the error of each other errno. One buffer serves all values.
fn collect_xattrs(
    list: &[u8],
    mut get: impl FnMut(&CStr, &mut Vec<u8>) -> Result<usize, Errno>,
    map: impl Fn(Errno) -> FsError,
) -> Result<Xattrs, FsError> {
    let mut pairs = Vec::with_capacity(list.iter().filter(|&&b| b == 0).count());
    let mut value = Vec::new();
    for name in list.split_inclusive(|&b| b == 0) {
        let Ok(c_name) = CStr::from_bytes_with_nul(name) else {
            return Err(FsError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "an xattr name of the list does not end with a NUL",
            )));
        };
        match get(c_name, &mut value) {
            Ok(len) => pairs.push((name.to_vec(), value[..len].to_vec())),
            Err(Errno::NODATA) => {}
            Err(e) => return Err(map(e)),
        }
    }
    Xattrs::new(pairs).map_err(|e| FsError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::Duration;

    use ostrya_composefs::FsVerityHasher;
    use rustix::fs::XattrFlags;

    use super::super::{TestDir, invalid, io_err, root};
    use super::*;

    /// Makes `objects/ab` in `dir`, and returns a handle of `objects/`.
    fn objects(dir: &TestDir) -> RepoDir {
        std::fs::create_dir_all(dir.path().join("objects/ab")).unwrap();
        root(dir).open_layout(RepoLayout::Objects).unwrap()
    }

    /// Makes a FIFO at `path`.
    fn mkfifo(path: &Path) {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            path,
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
    }

    /// Runs `f` in a new thread, and gives its result. If `f` does not return
    /// in 10 seconds, the function opens the FIFO `fifo` for write, which
    /// releases a blocked open, and panics.
    fn without_block<T: Send + 'static>(fifo: &Path, f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(value) => {
                worker.join().unwrap();
                value
            }
            Err(RecvTimeoutError::Disconnected) => match worker.join() {
                Err(panic) => std::panic::resume_unwind(panic),
                Ok(()) => unreachable!("the worker sends a value before it ends"),
            },
            Err(RecvTimeoutError::Timeout) => {
                let _ = rustix::fs::open(
                    fifo,
                    OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                );
                panic!("a read of the FIFO {} blocked", fifo.display());
            }
        }
    }

    /// Returns the path and the file type of a `NotRegular` error.
    fn not_regular<T: Debug>(result: Result<T, FsError>) -> (String, FileType) {
        match invalid(result) {
            (path, Reason::NotRegular(file_type)) => (path, file_type),
            other => panic!("{other:?}"),
        }
    }

    /// Returns the path of an `Absent` error.
    fn absent<T: Debug>(result: Result<T, FsError>) -> String {
        match result {
            Err(FsError::Absent { path }) => path,
            other => panic!("{other:?}"),
        }
    }

    /// Returns the content of `file` from its position.
    fn content(mut file: &File) -> Vec<u8> {
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        buf
    }

    /// Sets the xattr `name` of the file open at `fd`. It gives `false` if the
    /// file system has no support for user xattrs.
    fn set_xattr(fd: BorrowedFd<'_>, name: &str, value: &[u8]) -> bool {
        match rustix::fs::fsetxattr(fd, name, value, XattrFlags::empty()) {
            Ok(()) => true,
            Err(Errno::NOTSUP) => false,
            Err(e) => panic!("fsetxattr {name}: {e}"),
        }
    }

    #[test]
    fn a_fifo_gives_not_regular_and_does_not_block() {
        let dir = TestDir::new("read-fifo");
        let objects = objects(&dir);
        let fifo = dir.path().join("objects/ab/cd.file");
        mkfifo(&fifo);
        let handle = objects.clone();
        let results = without_block(&fifo, move || {
            [
                handle.open_regular("ab/cd.file").map(drop),
                handle.read_capped("ab/cd.file", 16).map(drop),
                handle.open_regular_at("ab/cd.file", 4).map(drop),
                handle.open_object("ab/cd.file").map(drop),
            ]
        });
        for result in results {
            let (path, file_type) = not_regular(result);
            assert_eq!(path, "objects/ab/cd.file");
            assert_eq!(file_type, FileType::Fifo);
        }
    }

    #[test]
    fn a_socket_a_device_or_a_directory_gives_not_regular() {
        let dir = TestDir::new("read-special");
        let objects = objects(&dir);
        let ab = dir.path().join("objects/ab");
        let _listener = UnixListener::bind(ab.join("sock.file")).unwrap();
        std::fs::create_dir(ab.join("dir.file")).unwrap();
        let mut cases = vec![
            ("sock.file", FileType::Socket),
            ("dir.file", FileType::Directory),
        ];
        // A whiteout is a character device 0:0. Its create needs no
        // privilege, and its open gives `ENXIO`.
        match rustix::fs::mknodat(
            rustix::fs::CWD,
            ab.join("dev.file"),
            FileType::CharacterDevice,
            Mode::from_raw_mode(0o600),
            rustix::fs::makedev(0, 0),
        ) {
            Ok(()) => cases.push(("dev.file", FileType::CharacterDevice)),
            Err(e) => eprintln!("skipping the device case: mknod gives {e}"),
        }
        for (name, expected) in cases {
            let path = format!("ab/{name}");
            let results = [
                objects.open_regular(&path).map(drop),
                objects.read_capped(&path, 16).map(drop),
                objects.open_regular_at(&path, 1).map(drop),
                objects.open_object(&path).map(drop),
            ];
            for result in results {
                let (err_path, file_type) = not_regular(result);
                assert_eq!(err_path, format!("objects/{path}"));
                assert_eq!(file_type, expected, "{name}");
            }
        }
    }

    #[test]
    fn open_regular_refuses_a_symlink_and_gives_absent_for_a_missing_file() {
        let dir = TestDir::new("read-regular");
        let objects = objects(&dir);
        let ab = dir.path().join("objects/ab");
        std::fs::write(ab.join("file"), b"content").unwrap();
        symlink("file", ab.join("link")).unwrap();

        let opened = objects.open_regular("ab/file").unwrap();
        assert_eq!(opened.stat.file_type, FileType::RegularFile);
        assert_eq!(opened.stat.size, 7);
        assert_eq!(content(&opened.file), b"content");

        let (path, reason) = invalid(objects.open_regular("ab/link"));
        assert_eq!(path, "objects/ab/link");
        assert!(matches!(reason, Reason::Symlink), "{reason:?}");
        assert_eq!(absent(objects.open_regular("ab/none")), "objects/ab/none");
        let (path, reason) = invalid(objects.open_regular("ab/file/x"));
        assert_eq!(path, "objects/ab/file/x");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
    }

    #[test]
    fn read_capped_reads_a_file_of_cap_bytes_and_refuses_one_more() {
        let dir = TestDir::new("read-capped");
        let objects = objects(&dir);
        let ab = dir.path().join("objects/ab");
        std::fs::write(ab.join("ten"), b"0123456789").unwrap();
        std::fs::write(ab.join("empty"), b"").unwrap();

        assert_eq!(objects.read_capped("ab/ten", 10).unwrap(), b"0123456789");
        assert_eq!(
            objects.read_capped("ab/ten", u64::MAX).unwrap(),
            b"0123456789"
        );
        let (path, reason) = invalid(objects.read_capped("ab/ten", 9));
        assert_eq!(path, "objects/ab/ten");
        assert!(matches!(reason, Reason::TooLarge { cap: 9 }), "{reason:?}");
        assert!(objects.read_capped("ab/empty", 0).unwrap().is_empty());
        assert_eq!(
            absent(objects.read_capped("ab/none", 10)),
            "objects/ab/none"
        );
    }

    #[test]
    fn open_regular_at_starts_at_the_offset() {
        let dir = TestDir::new("read-at");
        let objects = objects(&dir);
        std::fs::write(dir.path().join("objects/ab/ten"), b"0123456789").unwrap();

        let opened = objects.open_regular_at("ab/ten", 0).unwrap();
        assert_eq!(opened.stat.size, 10);
        assert_eq!(content(&opened.file), b"0123456789");
        let opened = objects.open_regular_at("ab/ten", 4).unwrap();
        assert_eq!(opened.stat.size, 10);
        assert_eq!(content(&opened.file), b"456789");
        let opened = objects.open_regular_at("ab/ten", 20).unwrap();
        assert!(content(&opened.file).is_empty());
    }

    #[test]
    fn open_object_gives_a_regular_file_or_the_target_of_a_symlink() {
        let dir = TestDir::new("read-object");
        let objects = objects(&dir);
        let tmp = root(&dir).tmp_dir(false).unwrap();
        let (name, staging, ()) = tmp.make_temp_dir("staging-", |_| Some(())).unwrap();
        let cases = [
            (dir.path().join("objects"), objects, "objects".to_owned()),
            (
                dir.path().join("tmp").join(&name),
                staging,
                format!("tmp/{name}"),
            ),
        ];
        for (base, handle, prefix) in cases {
            let ab = base.join("ab");
            std::fs::create_dir_all(&ab).unwrap();
            std::fs::write(ab.join("cd.file"), b"content").unwrap();
            symlink("target", ab.join("ef.file")).unwrap();

            match handle.open_object("ab/cd.file").unwrap() {
                ObjectEntry::Regular(opened) => {
                    assert_eq!(opened.stat.file_type, FileType::RegularFile);
                    assert_eq!(opened.stat.size, 7);
                    assert_eq!(content(&opened.file), b"content");
                }
                other => panic!("{other:?}"),
            }
            match handle.open_object("ab/ef.file").unwrap() {
                ObjectEntry::Symlink(target) => assert_eq!(target, b"target"),
                other => panic!("{other:?}"),
            }
            assert_eq!(
                absent(handle.open_object("ab/none.file")),
                format!("{prefix}/ab/none.file")
            );
        }
    }

    #[test]
    fn open_object_refuses_a_symlinked_fan_out() {
        let dir = TestDir::new("read-object-fan-out");
        let real = dir.path().join("objects/real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("cd.file"), b"content").unwrap();
        symlink("target", real.join("ef.file")).unwrap();
        symlink("real", dir.path().join("objects/ab")).unwrap();
        let objects = root(&dir).open_layout(RepoLayout::Objects).unwrap();
        for leaf in ["cd.file", "ef.file", "none.file"] {
            let (path, reason) = invalid(objects.open_object(&format!("ab/{leaf}")));
            assert_eq!(path, format!("objects/ab/{leaf}"));
            assert!(matches!(reason, Reason::Symlink), "{leaf}: {reason:?}");
        }
    }

    #[test]
    fn read_link_reads_a_target_to_its_cap_and_refuses_a_longer_one() {
        let dir = TestDir::new("read-link");
        let objects = objects(&dir);
        let ab = dir.path().join("objects/ab");
        let target = "t".repeat(3000);
        symlink(&target, ab.join("link")).unwrap();

        for cap in [3000, 3001, 4095, 4096, 10_000, u64::MAX] {
            assert_eq!(
                objects.read_link("ab/link", cap).unwrap(),
                target.as_bytes(),
                "cap {cap}"
            );
        }
        let (path, reason) = invalid(objects.read_link("ab/link", 2999));
        assert_eq!(path, "objects/ab/link");
        assert!(
            matches!(reason, Reason::TooLarge { cap: 2999 }),
            "{reason:?}"
        );
        let (_, reason) = invalid(objects.read_link("ab/link", 0));
        assert!(matches!(reason, Reason::TooLarge { cap: 0 }), "{reason:?}");

        // A target of 4095 bytes fills the stack buffer to one byte below its
        // size. A file system can refuse a target that long.
        let longest = "u".repeat(4095);
        match symlink(&longest, ab.join("longest")) {
            Ok(()) => {
                for cap in [4095, 4096, 10_000] {
                    assert_eq!(
                        objects.read_link("ab/longest", cap).unwrap(),
                        longest.as_bytes(),
                        "cap {cap}"
                    );
                }
                let (_, reason) = invalid(objects.read_link("ab/longest", 4094));
                assert!(
                    matches!(reason, Reason::TooLarge { cap: 4094 }),
                    "{reason:?}"
                );
            }
            Err(e) => eprintln!("skipping the 4095-byte target: {e}"),
        }
    }

    #[test]
    fn read_link_of_an_entry_that_is_not_a_symlink_gives_einval() {
        let dir = TestDir::new("read-link-errors");
        let objects = objects(&dir);
        let ab = dir.path().join("objects/ab");
        std::fs::write(ab.join("file"), b"x").unwrap();
        std::fs::create_dir(ab.join("dir")).unwrap();
        for path in ["ab/file", "ab/dir"] {
            let err = io_err(objects.read_link(path, 64));
            assert_eq!(
                err.raw_os_error(),
                Some(Errno::INVAL.raw_os_error()),
                "{path}"
            );
        }
        assert_eq!(absent(objects.read_link("ab/none", 64)), "objects/ab/none");

        symlink("ab", dir.path().join("objects/cd")).unwrap();
        symlink("target", ab.join("link")).unwrap();
        let (path, reason) = invalid(objects.read_link("cd/link", 64));
        assert_eq!(path, "objects/cd/link");
        assert!(matches!(reason, Reason::Symlink), "{reason:?}");
    }

    #[test]
    fn lstat_does_not_follow_a_symlink_at_the_leaf() {
        let dir = TestDir::new("read-lstat");
        let objects = objects(&dir);
        let ab = dir.path().join("objects/ab");
        std::fs::write(ab.join("file"), b"0123456789abcdef").unwrap();
        symlink("file", ab.join("link")).unwrap();
        symlink("nowhere-at-all", ab.join("dangling")).unwrap();

        let stat = objects.lstat("ab/link").unwrap();
        assert_eq!(stat.file_type, FileType::Symlink);
        assert_eq!(stat.size, 4);
        let stat = objects.lstat("ab/dangling").unwrap();
        assert_eq!(stat.file_type, FileType::Symlink);
        assert_eq!(stat.size, 14);
        let stat = objects.lstat("ab/file").unwrap();
        assert_eq!(stat.file_type, FileType::RegularFile);
        assert_eq!(stat.size, 16);
        assert_eq!(objects.lstat("ab").unwrap().file_type, FileType::Directory);
        assert_eq!(absent(objects.lstat("ab/none")), "objects/ab/none");
    }

    #[test]
    fn exists_gives_false_for_an_absent_entry_alone() {
        let dir = TestDir::new("read-exists");
        let objects = objects(&dir);
        let ab = dir.path().join("objects/ab");
        std::fs::write(ab.join("file"), b"x").unwrap();
        std::fs::create_dir(ab.join("real")).unwrap();
        std::fs::write(ab.join("real/x"), b"x").unwrap();
        symlink("real", ab.join("link")).unwrap();
        symlink("nowhere", ab.join("dangling")).unwrap();

        assert!(!objects.exists("ab/none").unwrap());
        assert!(!objects.exists("cd/none").unwrap());
        for path in ["ab", "ab/file", "ab/real/x", "ab/link", "ab/dangling"] {
            assert!(objects.exists(path).unwrap(), "{path}");
        }
        let (path, reason) = invalid(objects.exists("ab/file/x"));
        assert_eq!(path, "objects/ab/file/x");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
        let (path, reason) = invalid(objects.exists("ab/link/x"));
        assert_eq!(path, "objects/ab/link/x");
        assert!(matches!(reason, Reason::Symlink), "{reason:?}");
    }

    #[test]
    fn open_root_file_follows_a_symlink_at_a_keyring_alone() {
        let dir = TestDir::new("read-root-file");
        let other = TestDir::new("read-root-file-other");
        std::fs::write(other.path().join("keys.gpg"), b"keys").unwrap();
        symlink(
            other.path().join("keys.gpg"),
            dir.path().join("origin.trustedkeys.gpg"),
        )
        .unwrap();
        std::fs::write(dir.path().join("gpgkeys.gpg"), b"plain").unwrap();
        std::fs::write(dir.path().join("config"), b"[core]\n").unwrap();
        symlink(other.path().join("keys.gpg"), dir.path().join("summary")).unwrap();
        let repo = root(&dir);

        let opened = repo
            .open_root_file(RootFile::Keyring("origin.trustedkeys.gpg".into()))
            .unwrap();
        assert_eq!(content(&opened.file), b"keys");
        assert_eq!(opened.stat.size, 4);
        let opened = repo
            .open_root_file(RootFile::Keyring("gpgkeys.gpg".into()))
            .unwrap();
        assert_eq!(content(&opened.file), b"plain");
        let opened = repo.open_root_file(RootFile::Config).unwrap();
        assert_eq!(content(&opened.file), b"[core]\n");

        let (path, reason) = invalid(repo.open_root_file(RootFile::Summary));
        assert_eq!(path, "summary");
        assert!(matches!(reason, Reason::Symlink), "{reason:?}");
        assert_eq!(
            absent(repo.open_root_file(RootFile::SummarySig)),
            "summary.sig"
        );
    }

    #[test]
    fn open_root_file_maps_the_errors_of_a_keyring() {
        let dir = TestDir::new("read-keyring");
        let other = TestDir::new("read-keyring-other");
        let at = |name: &str| dir.path().join(name);
        std::fs::write(at("file"), b"x").unwrap();
        symlink("nowhere", at("dangling.gpg")).unwrap();
        symlink("loop.gpg", at("loop.gpg")).unwrap();
        symlink("file/x", at("notdir.gpg")).unwrap();
        symlink("/dev/null", at("null.gpg")).unwrap();
        let _listener = UnixListener::bind(other.path().join("sock")).unwrap();
        symlink(other.path().join("sock"), at("sock.gpg")).unwrap();
        symlink(other.path(), at("dir.gpg")).unwrap();
        let repo = root(&dir);
        let keyring = |name: &str| repo.open_root_file(RootFile::Keyring(name.to_owned()));

        assert_eq!(absent(keyring("absent.gpg")), "absent.gpg");
        assert_eq!(absent(keyring("dangling.gpg")), "dangling.gpg");
        for (name, errno) in [("loop.gpg", Errno::LOOP), ("notdir.gpg", Errno::NOTDIR)] {
            let err = io_err(keyring(name));
            assert_eq!(err.raw_os_error(), Some(errno.raw_os_error()), "{name}");
        }
        for (name, expected) in [
            ("null.gpg", FileType::CharacterDevice),
            ("sock.gpg", FileType::Socket),
            ("dir.gpg", FileType::Directory),
        ] {
            let (path, file_type) = not_regular(keyring(name));
            assert_eq!(path, name);
            assert_eq!(file_type, expected, "{name}");
        }
        for name in ["", ".", "..", "a/b", "/etc/passwd"] {
            let (path, reason) = invalid(keyring(name));
            assert_eq!(path, repo.err_path(name), "{name:?}");
            assert!(matches!(reason, Reason::Escape), "{name:?}: {reason:?}");
        }
    }

    #[test]
    fn open_root_file_refuses_a_keyring_fifo_and_does_not_block() {
        let dir = TestDir::new("read-keyring-fifo");
        let other = TestDir::new("read-keyring-fifo-other");
        let fifo = other.path().join("fifo");
        mkfifo(&fifo);
        symlink(&fifo, dir.path().join("fifo.gpg")).unwrap();
        let repo = root(&dir);
        let result = without_block(&fifo, move || {
            repo.open_root_file(RootFile::Keyring("fifo.gpg".into()))
                .map(drop)
        });
        let (path, file_type) = not_regular(result);
        assert_eq!(path, "fifo.gpg");
        assert_eq!(file_type, FileType::Fifo);
    }

    #[test]
    fn each_read_primitive_refuses_an_escape() {
        let dir = TestDir::new("read-escape");
        let objects = objects(&dir);
        std::fs::write(dir.path().join("x"), b"outside").unwrap();
        let cases = [
            "..",
            "../x",
            "ab/../cd",
            "ab/..",
            "/etc/passwd",
            "/",
            "",
            "ab//cd",
            "./ab",
            "ab/.",
            "ab/",
        ];
        for path in cases {
            let results = [
                objects.open_regular(path).map(drop),
                objects.read_capped(path, 64).map(drop),
                objects.open_regular_at(path, 0).map(drop),
                objects.open_object(path).map(drop),
                objects.read_link(path, 64).map(drop),
                objects.lstat(path).map(drop),
                objects.exists(path).map(drop),
                objects.link_xattrs(path).map(drop),
            ];
            for (at, result) in results.into_iter().enumerate() {
                let (err_path, reason) = invalid(result);
                assert_eq!(err_path, objects.err_path(path), "{path:?} #{at}");
                assert!(
                    matches!(reason, Reason::Escape),
                    "{path:?} #{at}: {reason:?}"
                );
            }
        }
    }

    #[test]
    fn read_grown_grows_to_the_size_that_the_kernel_gives() {
        let value: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut calls = Vec::new();
        let mut buf = Vec::new();
        let len = read_grown(&mut buf, |b| {
            calls.push(b.len());
            if b.is_empty() {
                Ok(value.len())
            } else if b.len() < value.len() {
                Err(Errno::RANGE)
            } else {
                b[..value.len()].copy_from_slice(&value);
                Ok(value.len())
            }
        })
        .unwrap();
        assert_eq!(&buf[..len], value.as_slice());
        assert_eq!(calls, [XATTR_BUF_START, 0, 1000]);
        assert_eq!(buf.len(), 1000);

        // A buffer that is large enough serves the next read with no growth.
        let len = read_grown(&mut buf, |b| {
            b[..3].copy_from_slice(b"abc");
            Ok(3)
        })
        .unwrap();
        assert_eq!(&buf[..len], b"abc");
        assert_eq!(buf.len(), 1000);
    }

    #[test]
    fn read_grown_refuses_a_size_over_64_kib() {
        let mut buf = Vec::new();
        let result = read_grown(&mut buf, |b| {
            if b.is_empty() {
                Ok(XATTR_MAX + 1)
            } else {
                Err(Errno::RANGE)
            }
        });
        assert_eq!(result, Err(Errno::TOOBIG));
        assert_eq!(buf.len(), XATTR_BUF_START);
    }

    #[test]
    fn read_grown_stops_after_four_passes() {
        let mut calls = Vec::new();
        let mut buf = Vec::new();
        let result = read_grown(&mut buf, |b| {
            calls.push(b.len());
            if b.is_empty() {
                Ok(100)
            } else {
                Err(Errno::RANGE)
            }
        });
        assert_eq!(result, Err(Errno::RANGE));
        let s = XATTR_BUF_START;
        assert_eq!(calls, [s, 0, s, 0, s, 0, s]);
    }

    #[test]
    fn link_error_gives_absent_only_for_an_absent_leaf() {
        let dir = TestDir::new("read-link-error");
        let objects = objects(&dir);
        let ab = dir.path().join("objects/ab");
        std::fs::write(ab.join("file"), b"x").unwrap();
        symlink("nowhere", ab.join("dangling")).unwrap();
        let ab_dir = objects.open_dir("ab").unwrap();
        let fd = ab_dir.as_fd();

        let error = |leaf: &str| objects.link_error(Errno::NOENT, fd, leaf, &format!("ab/{leaf}"));
        assert_eq!(absent::<()>(Err(error("none"))), "objects/ab/none");
        for leaf in ["file", "dangling"] {
            let err = io_err::<()>(Err(error(leaf)));
            assert_eq!(err.kind(), io::ErrorKind::NotFound, "{leaf}");
            let message = err.to_string();
            assert!(message.contains("/proc/self/fd"), "{message}");
            assert!(message.contains(&format!("objects/ab/{leaf}")), "{message}");
        }
        let err = io_err::<()>(Err(objects.link_error(
            Errno::ACCESS,
            fd,
            "none",
            "ab/none",
        )));
        assert_eq!(err.raw_os_error(), Some(Errno::ACCESS.raw_os_error()));
    }

    #[test]
    fn the_xattr_reads_grow_their_buffers_for_a_large_value_and_a_long_list() {
        let dir = TestDir::new("read-xattr");
        let path = dir.path().join("file");
        std::fs::write(&path, b"x").unwrap();
        let file = File::open(&path).unwrap();
        let fd = file.as_fd();
        let big: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        if !set_xattr(fd, "user.big", &big) {
            eprintln!("skipping: the file system has no user xattrs");
            return;
        }
        let mut expected = vec![(b"user.big\0".to_vec(), big.clone())];
        for i in 0..30 {
            let name = format!("user.a-name-with-a-long-part-{i:02}");
            let value = format!("value {i}");
            assert!(set_xattr(fd, &name, value.as_bytes()));
            expected.push((format!("{name}\0").into_bytes(), value.into_bytes()));
        }
        expected.sort();

        assert_eq!(xattr(fd, "user.big").unwrap(), Some(big));
        assert_eq!(xattr(fd, "user.missing").unwrap(), None);
        assert_eq!(
            xattr(fd, "user.a-name-with-a-long-part-07").unwrap(),
            Some(b"value 7".to_vec())
        );
        let set = xattrs(fd).unwrap();
        let got: Vec<(Vec<u8>, Vec<u8>)> = set
            .iter()
            .filter(|(name, _)| name.starts_with(b"user."))
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn link_xattrs_does_not_follow_the_leaf() {
        let dir = TestDir::new("read-link-xattrs");
        let objects = objects(&dir);
        let ab = dir.path().join("objects/ab");
        std::fs::write(ab.join("file"), b"x").unwrap();
        let file = File::open(ab.join("file")).unwrap();
        if !set_xattr(file.as_fd(), "user.demo", b"value") {
            eprintln!("skipping: the file system has no user xattrs");
            return;
        }
        symlink("file", ab.join("link")).unwrap();
        let has_demo = |set: &Xattrs| {
            set.iter()
                .any(|(name, value)| name == b"user.demo\0" && value == b"value")
        };

        assert!(has_demo(&objects.link_xattrs("ab/file").unwrap()));
        assert!(!has_demo(&objects.link_xattrs("ab/link").unwrap()));
        let ab_dir = objects.open_dir("ab").unwrap();
        assert!(has_demo(&ab_dir.link_xattrs("file").unwrap()));
        assert!(!has_demo(&ab_dir.link_xattrs("link").unwrap()));
        assert!(has_demo(&xattrs(file.as_fd()).unwrap()));

        assert_eq!(absent(objects.link_xattrs("ab/none")), "objects/ab/none");
        assert_eq!(absent(ab_dir.link_xattrs("none")), "objects/ab/none");
        symlink("ab", dir.path().join("objects/cd")).unwrap();
        let (path, reason) = invalid(objects.link_xattrs("cd/file"));
        assert_eq!(path, "objects/cd");
        assert!(matches!(reason, Reason::Symlink), "{reason:?}");
    }

    #[test]
    fn verity_digest_gives_the_digest_of_a_sealed_file_alone() {
        let dir = TestDir::new("read-verity");
        let path = dir.path().join("file");
        let data = vec![7u8; 10_000];
        std::fs::write(&path, &data).unwrap();
        let file = File::open(&path).unwrap();
        let size = data.len() as u64;
        assert_eq!(verity_digest(file.as_fd(), size), None);
        if let Err(e) = ostrya_sys::enable_verity(file.as_fd()) {
            eprintln!("skipping: the file system has no fs-verity: {e}");
            return;
        }
        assert!(stat_fd(file.as_fd()).unwrap().verity);
        assert_eq!(
            verity_digest(file.as_fd(), size),
            Some(FsVerityHasher::hash(&data))
        );
        assert_eq!(verity_digest(file.as_fd(), size + 1), None);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "open_object needs an objects handle or a staging handle")]
    fn open_object_on_another_kind_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-object");
        std::fs::create_dir_all(dir.path().join("refs/ab")).unwrap();
        let refs = root(&dir).open_layout(RepoLayout::Refs).unwrap();
        let _ = refs.open_object("ab/cd.file");
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "open_root_file needs the root handle")]
    fn open_root_file_on_another_handle_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-root-file");
        let objects = objects(&dir);
        let _ = objects.open_root_file(RootFile::Config);
    }
}
