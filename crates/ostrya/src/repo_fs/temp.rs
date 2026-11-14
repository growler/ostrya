//! The temp files and the temp symlinks of a write, and their publish.
//!
//! A [`TempFile`] is a regular file that a caller writes and then publishes
//! at a path below a [`RepoDir`]. A [`TempLink`] is a symlink that a caller
//! publishes in the same way. A temp entry is in the temp home of the kind of
//! the directory that makes it: `tmp/`, or the directory itself for a staging
//! directory and for `tmp/`. The publish thus puts the entry on the file
//! system of its home.
//!
//! A temp file of [`TempFile::create`] is an anonymous `O_TMPFILE` inode
//! where the file system supports it. On each other file system it is a named
//! file `.ostrya-tmp-<pid>-XXXXXX`, where `XXXXXX` is six random characters
//! from `[A-Za-z0-9]`. A temp file of [`TempFile::create_named`] and a temp
//! symlink always have a name of this form. The drop of an entry that has a
//! name in its home unlinks the name.
//!
//! The publish of an entry at a path that exists follows a [`Publish`] rule:
//!
//! - [`Publish::KeepExisting`] keeps the existing entry and gives
//!   [`Published::Existed`]. An anonymous file links into place with
//!   `linkat`. A named entry moves with `renameat2` and `RENAME_NOREPLACE`.
//!   Where the file system refuses that flag, a `linkat` of the name puts the
//!   entry in place, and the drop then unlinks the temp name.
//! - [`Publish::Replace`] replaces the existing entry with one `renameat`. An
//!   anonymous file first links at a temp name in its home. A caller that
//!   knows the rule before the create, such as
//!   [`RepoDir::write_atomic`], makes a named file for [`Publish::Replace`],
//!   so the publish needs no link.

use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::time::Duration;

use rustix::fs::{AtFlags, Gid, Mode, OFlags, RenameFlags, Uid, XattrFlags};
use rustix::io::Errno;

use super::dir::{
    BENEATH, SUFFIX_LEN, TEMP_ATTEMPTS, fsync_dir, io_error, open_beneath, push_random_suffix,
    require,
};
use super::{FsError, Publish, Published, RepoDir, TempHome};
use crate::config::Tristate;

/// The prefix of the name of a named temp entry.
pub(super) const TEMP_PREFIX: &str = ".ostrya-tmp-";

/// The number of decimal digits of the largest `u32`, the largest process id
/// and the largest descriptor number.
const U32_DIGITS: usize = 10;

/// The length of the longest temp name: the prefix, the process id, `-`, and
/// the suffix.
const TEMP_NAME_MAX: usize = TEMP_PREFIX.len() + U32_DIGITS + 1 + SUFFIX_LEN;

/// The prefix of a path through `/proc/self/fd`.
const PROC_FD: &str = "/proc/self/fd/";

/// The length of the longest path that [`proc_path`] writes: the prefix, the
/// descriptor number, `/`, and a temp name.
const PROC_PATH_MAX: usize = PROC_FD.len() + U32_DIGITS + 1 + TEMP_NAME_MAX;

/// The message of an `ENOENT` from the link of an anonymous file through
/// `/proc/self/fd`.
const LINK_ENOENT: &str = "a link through /proc/self/fd gives ENOENT: the directory is gone, \
     or /proc/self/fd is not available";

/// The message of an `ENOENT` from the read-only open of a temp file through
/// `/proc/self/fd`.
const REOPEN_ENOENT: &str =
    "an open through /proc/self/fd gives ENOENT: /proc/self/fd is not available";

/// The message of an `ENOENT` from the `lsetxattr` of a temp symlink through
/// `/proc/self/fd`.
const LINK_XATTR_ENOENT: &str = "an lsetxattr through /proc/self/fd gives ENOENT: the temp \
     symlink or its directory is gone, or /proc/self/fd is not available";

/// The mode of the create request of a temp file. The umask reduces it.
const TEMP_MODE: u32 = 0o600;

/// The number of attempts to enable fs-verity before an `ETXTBSY` error is
/// reported.
///
/// The kernel refuses to seal an inode while a writable descriptor to it is
/// open. `fork` copies the descriptor table, so a child process holds a copy
/// of the writable descriptor until its `exec` closes it. The retries outlast
/// this window. A refusal that stays fails after about 50 ms.
const SEAL_ATTEMPTS: u32 = 50;

/// The pause between two attempts to enable fs-verity.
const SEAL_PAUSE: Duration = Duration::from_millis(1);

/// The flags of the open of an anonymous temp file.
const TMPFILE_OPEN: OFlags = OFlags::RDWR.union(OFlags::TMPFILE).union(OFlags::CLOEXEC);

/// The flags of the create of a named temp file and of an exclusive create.
pub(super) const NAMED_OPEN: OFlags = OFlags::RDWR
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// A regular file that a caller writes, and then publishes at a path below a
/// [`RepoDir`].
///
/// The file is open for read and write until [`seal`](TempFile::seal). The
/// caller streams the content into [`file_mut`](TempFile::file_mut).
///
/// The caller sets the metadata in this order:
///
/// 1. The owner, with [`set_owner`](TempFile::set_owner). A change of the
///    owner clears the set-user-ID bit, the set-group-ID bit, and the
///    `security.capability` attribute.
/// 2. Each `user.*` attribute, with [`set_xattr`](TempFile::set_xattr). The
///    kernel refuses a `user.*` attribute on a file with no write bit for its
///    owner, so these attributes come before such a mode.
/// 3. The seal, with [`seal`](TempFile::seal). The seal opens the file again
///    read-only, which needs the read bit for the owner, so the seal comes
///    before a mode with no such bit. Such a mode before the seal makes the
///    seal fail with `EACCES`.
/// 4. The mode, with [`set_mode`](TempFile::set_mode).
#[derive(Debug)]
pub(crate) struct TempFile {
    /// The open file.
    file: File,
    /// The home and the name of the temp entry. The name is `None` for an
    /// anonymous file.
    entry: TempName,
    /// `true` after [`set_mode`](TempFile::set_mode).
    mode_set: bool,
}

impl TempFile {
    /// Makes a temp file for a write to `dir`, open for read and write.
    ///
    /// The file is in the temp home of the kind of `dir`. The function first
    /// opens an anonymous file with `O_TMPFILE`. Where the file system gives
    /// `EOPNOTSUPP`, `EISDIR`, or `EINVAL`, it makes a named file with
    /// `O_CREAT|O_EXCL`. A name that exists makes the function draw a new
    /// name. The function tries 128 names at most, and then gives an
    /// `AlreadyExists` error. The mode of the create request is `0600`, and
    /// the umask reduces it. Each other error gives [`FsError::Io`]. The
    /// errors of the open of `tmp/` are those of
    /// [`tmp_dir`](RepoDir::tmp_dir).
    pub(crate) fn create(dir: &RepoDir) -> Result<TempFile, FsError> {
        let home = temp_home(dir)?;
        match open_tmpfile(home.as_fd()) {
            Ok(fd) => Ok(TempFile {
                file: File::from(fd),
                entry: TempName { home, name: None },
                mode_set: false,
            }),
            Err(Errno::OPNOTSUPP | Errno::ISDIR | Errno::INVAL) => TempFile::create_named_in(home),
            Err(e) => Err(io_error(e)),
        }
    }

    /// Makes a named temp file for a write to `dir`, open for read and write.
    ///
    /// The function makes no `O_TMPFILE` open. The rules of the name, the
    /// mode, and the errors are those of the named file of
    /// [`create`](TempFile::create). A publish with [`Publish::Replace`] then
    /// costs one `renameat`, with no link of the file at a temp name.
    pub(super) fn create_named(dir: &RepoDir) -> Result<TempFile, FsError> {
        TempFile::create_named_in(temp_home(dir)?)
    }

    /// Makes a named temp file in the temp home `home` with `O_CREAT|O_EXCL`.
    fn create_named_in(home: RepoDir) -> Result<TempFile, FsError> {
        let (name, fd) = make_temp_name(
            |name| {
                rustix::fs::openat2(
                    &home,
                    name,
                    NAMED_OPEN,
                    Mode::from_raw_mode(TEMP_MODE),
                    BENEATH,
                )
            },
            io_error,
        )?;
        Ok(TempFile {
            file: File::from(fd),
            entry: TempName {
                home,
                name: Some(name),
            },
            mode_set: false,
        })
    }

    /// Returns the open file.
    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Sets the permission bits and the special bits `bits` with `fchmod`.
    /// The publish then keeps this mode. An error gives [`FsError::Io`].
    pub(crate) fn set_mode(&mut self, bits: u32) -> Result<(), FsError> {
        rustix::fs::fchmod(&self.file, Mode::from_raw_mode(bits)).map_err(io_error)?;
        self.mode_set = true;
        Ok(())
    }

    /// Sets the owner `uid` and the group `gid` with `fchown`. An error gives
    /// [`FsError::Io`].
    pub(crate) fn set_owner(&self, uid: u32, gid: u32) -> Result<(), FsError> {
        rustix::fs::fchown(
            &self.file,
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(gid)),
        )
        .map_err(io_error)
    }

    /// Sets the extended attribute `name` to `value` with `fsetxattr`. An
    /// error gives [`FsError::Io`].
    pub(crate) fn set_xattr(&self, name: &CStr, value: &[u8]) -> Result<(), FsError> {
        rustix::fs::fsetxattr(&self.file, name, value, XattrFlags::empty()).map_err(io_error)
    }

    /// Syncs the content and the metadata of the file with `fsync`. An error
    /// gives [`FsError::Io`].
    pub(crate) fn sync(&self) -> Result<(), FsError> {
        rustix::fs::fsync(&self.file).map_err(io_error)
    }

    /// Seals the file with fs-verity as `verity` asks, and gives `true` if
    /// the file is sealed.
    ///
    /// [`Tristate::No`] gives `false` and makes no syscall. For each other
    /// value, the function opens the file again read-only through
    /// `/proc/self/fd` and closes the writable descriptor, because the kernel
    /// refuses the seal while a writable descriptor is open. It then enables
    /// fs-verity on the read-only descriptor. It tries again after `ETXTBSY`,
    /// 50 attempts at most with a pause of 1 ms. A failure of the seal gives
    /// `false` for [`Tristate::Maybe`] and [`FsError::Io`] for
    /// [`Tristate::Yes`]. A failure of the open gives [`FsError::Io`] for
    /// both: `ENOENT` gives a message that names `/proc/self/fd`.
    ///
    /// After the open, each other method and the publish use the read-only
    /// descriptor.
    pub(crate) fn seal(&mut self, verity: Tristate) -> Result<bool, FsError> {
        if verity == Tristate::No {
            return Ok(false);
        }
        let mut buf = [0; PROC_PATH_MAX];
        let fd = rustix::fs::open(
            proc_path(&mut buf, self.file.as_fd(), None)?,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| proc_error(e, REOPEN_ENOENT))?;
        self.file = File::from(fd);
        match enable_verity(self.file.as_fd()) {
            Ok(()) => Ok(true),
            Err(_) if verity == Tristate::Maybe => Ok(false),
            Err(e) => Err(io_error(e)),
        }
    }

    /// Unlinks the temp name of a named file, and gives the file. The inode
    /// goes away when the file closes.
    ///
    /// The file is open for read and write, or read-only after
    /// [`seal`](TempFile::seal) with a value other than [`Tristate::No`]. A
    /// caller keeps a scratch file with this function. An error of the unlink
    /// gives [`FsError::Io`], and the drop of the temp entry then tries the
    /// unlink again.
    pub(crate) fn into_file(self) -> Result<File, FsError> {
        let TempFile {
            file, mut entry, ..
        } = self;
        if let Some(name) = entry.name.as_deref() {
            rustix::fs::unlinkat(&entry.home, name, AtFlags::empty()).map_err(io_error)?;
            entry.name = None;
        }
        Ok(file)
    }

    /// Publishes the file at `path` below `dir` by the rule `how`, and gives
    /// the result.
    ///
    /// The path rules are those of [`open_dir`](RepoDir::open_dir). Without
    /// [`set_mode`](TempFile::set_mode), an `fchmod` first sets the file mode
    /// of the kind of `dir`, or the shared file mode in a `bare-user-shared`
    /// repository. A kind with no file mode then is a defect of the caller:
    /// it fails a debug assertion, and gives an `InvalidInput` error in a
    /// release build.
    ///
    /// One `openat2` opens the parent directory of the leaf, with the errors
    /// of [`open_dir`](RepoDir::open_dir): a missing parent gives
    /// [`FsError::Absent`] with the path of the parent. The module doc states
    /// the placement. [`Publish::Replace`] always gives
    /// [`Published::Created`]. An error of the placement gives
    /// [`FsError::Io`], also `ENOENT` and `EXDEV`. An `ENOENT` of the link of
    /// an anonymous file through `/proc/self/fd` gives a message that states
    /// the two causes: the directory of the link is gone, or `/proc/self/fd`
    /// is not available.
    ///
    /// With `fsync`, the function syncs the parent directory after it puts
    /// the file in place. [`Published::Existed`] syncs nothing.
    pub(crate) fn publish(
        mut self,
        dir: &RepoDir,
        path: &str,
        how: Publish,
        fsync: bool,
    ) -> Result<Published, FsError> {
        dir.check_path(path)?;
        if !self.mode_set {
            let mode = require(
                dir.file_mode(),
                "a publish needs set_mode or a kind with a file mode",
            )?;
            rustix::fs::fchmod(&self.file, Mode::from_raw_mode(mode)).map_err(io_error)?;
        }
        let (parent, leaf) = open_parent(dir, path)?;
        let at = parent.as_ref().map_or(dir.as_fd(), AsFd::as_fd);
        let entry = &mut self.entry;
        if entry.name.is_none() {
            let mut buf = [0; PROC_PATH_MAX];
            let from = proc_path(&mut buf, self.file.as_fd(), None)?;
            let link = |to: BorrowedFd<'_>, name: &str| {
                rustix::fs::linkat(rustix::fs::CWD, from, to, name, AtFlags::SYMLINK_FOLLOW)
            };
            if how == Publish::KeepExisting {
                return match link(at, leaf) {
                    Ok(()) => created(at, fsync),
                    Err(Errno::EXIST) => Ok(Published::Existed),
                    Err(e) => Err(proc_error(e, LINK_ENOENT)),
                };
            }
            let (name, ()) = make_temp_name(
                |name| link(entry.home.as_fd(), name),
                |e| proc_error(e, LINK_ENOENT),
            )?;
            entry.name = Some(name);
        }
        place_named(entry.home.as_fd(), &mut entry.name, at, leaf, how, fsync)
    }
}

/// The home and the name of a temp entry. The drop unlinks the name, if the
/// entry has one.
#[derive(Debug)]
struct TempName {
    /// The directory that holds the temp entry.
    home: RepoDir,
    /// The name of the temp entry in `home`, or `None` for an entry with no
    /// name and after a rename moved the entry.
    name: Option<String>,
}

impl Drop for TempName {
    fn drop(&mut self) {
        if let Some(name) = self.name.as_deref() {
            let _ = rustix::fs::unlinkat(&self.home, name, AtFlags::empty());
        }
    }
}

/// A symlink that a caller publishes at a path below a [`RepoDir`].
///
/// The caller sets the owner with [`set_owner`](TempLink::set_owner) before
/// each attribute, as for a [`TempFile`].
#[derive(Debug)]
pub(crate) struct TempLink {
    /// The home and the name of the temp entry. The name is `None` after a
    /// rename moved the entry.
    entry: TempName,
}

impl TempLink {
    /// Makes a temp symlink with the target `target` for a write to `dir`.
    ///
    /// The symlink is in the temp home of the kind of `dir`. A name that
    /// exists makes the function draw a new name. The function tries 128
    /// names at most, and then gives an `AlreadyExists` error. Each other
    /// error gives [`FsError::Io`].
    pub(crate) fn create(dir: &RepoDir, target: &str) -> Result<TempLink, FsError> {
        let home = temp_home(dir)?;
        let (name, ()) =
            make_temp_name(|name| rustix::fs::symlinkat(target, &home, name), io_error)?;
        Ok(TempLink {
            entry: TempName {
                home,
                name: Some(name),
            },
        })
    }

    /// Sets the owner `uid` and the group `gid` of the symlink itself with
    /// `fchownat` and `AT_SYMLINK_NOFOLLOW`. An error gives [`FsError::Io`].
    pub(crate) fn set_owner(&self, uid: u32, gid: u32) -> Result<(), FsError> {
        rustix::fs::chownat(
            &self.entry.home,
            self.name()?,
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io_error)
    }

    /// Sets the extended attribute `name` of the symlink itself to `value`.
    ///
    /// A symlink does not open for a descriptor, so the function calls
    /// `lsetxattr` on the path of the symlink through `/proc/self/fd`. The
    /// kernel refuses a `user.*` attribute on a symlink. An error gives
    /// [`FsError::Io`]: `ENOENT` gives a message that states the two causes:
    /// the symlink or its directory is gone, or `/proc/self/fd` is not
    /// available.
    pub(crate) fn set_xattr(&self, name: &CStr, value: &[u8]) -> Result<(), FsError> {
        let mut buf = [0; PROC_PATH_MAX];
        let link = proc_path(&mut buf, self.entry.home.as_fd(), Some(self.name()?))?;
        rustix::fs::lsetxattr(link, name, value, XattrFlags::empty())
            .map_err(|e| proc_error(e, LINK_XATTR_ENOENT))
    }

    /// Publishes the symlink at `path` below `dir` by the rule `how`, and
    /// gives the result.
    ///
    /// The path rules, the open of the parent, the placement of a named
    /// entry, the errors, and the sync are those of
    /// [`TempFile::publish`]. The `linkat` of the name links the symlink
    /// itself.
    pub(crate) fn publish(
        mut self,
        dir: &RepoDir,
        path: &str,
        how: Publish,
        fsync: bool,
    ) -> Result<Published, FsError> {
        dir.check_path(path)?;
        let (parent, leaf) = open_parent(dir, path)?;
        let at = parent.as_ref().map_or(dir.as_fd(), AsFd::as_fd);
        let entry = &mut self.entry;
        place_named(entry.home.as_fd(), &mut entry.name, at, leaf, how, fsync)
    }

    /// Returns the name of the temp entry.
    fn name(&self) -> Result<&str, FsError> {
        require(
            self.entry.name.as_deref(),
            "a temp link has its name until its publish",
        )
    }
}

/// Returns the directory that holds the temp entries of a write to `dir`.
fn temp_home(dir: &RepoDir) -> Result<RepoDir, FsError> {
    match dir.kind().rules().temp_home {
        TempHome::Tmp => dir.tmp_dir(false),
        TempHome::OwnDir => Ok(dir.clone()),
    }
}

/// Opens an anonymous temp file in `home` with `O_TMPFILE`.
fn open_tmpfile(home: BorrowedFd<'_>) -> Result<OwnedFd, Errno> {
    #[cfg(test)]
    super::dir::run_hook(super::HookPoint::Tmpfile, b"");
    #[cfg(test)]
    if super::FAULTS.with(|faults| faults.borrow().no_tmpfile) {
        return Err(Errno::OPNOTSUPP);
    }
    rustix::fs::openat(home, c".", TMPFILE_OPEN, Mode::from_raw_mode(TEMP_MODE))
}

/// Calls `make` with a new temp name until it does not give `EEXIST`, and
/// gives the name and the result of `make`.
///
/// The function tries [`TEMP_ATTEMPTS`] names at most, and then gives an
/// `AlreadyExists` error. `map` gives the error of each other errno.
pub(super) fn make_temp_name<T>(
    mut make: impl FnMut(&str) -> Result<T, Errno>,
    map: fn(Errno) -> FsError,
) -> Result<(String, T), FsError> {
    let pid = std::process::id();
    let mut name = String::with_capacity(TEMP_NAME_MAX);
    name.push_str(TEMP_PREFIX);
    name.push_str(&pid.to_string());
    name.push('-');
    let base = name.len();
    for _ in 0..TEMP_ATTEMPTS {
        name.truncate(base);
        push_random_suffix(&mut name, pid);
        #[cfg(test)]
        super::dir::run_hook(super::HookPoint::TempName, name.as_bytes());
        #[cfg(test)]
        if super::FAULTS.with(|faults| faults.borrow().force_eexist) {
            continue;
        }
        match make(&name) {
            Ok(made) => return Ok((name, made)),
            Err(Errno::EXIST) => continue,
            Err(e) => return Err(map(e)),
        }
    }
    Err(FsError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique temp file name",
    )))
}

/// Opens the parent directory of `path` below `dir`, and gives it and the
/// leaf. A path with one component gives `None` for the parent: the parent is
/// `dir`. The caller checks `path`.
pub(super) fn open_parent<'p>(
    dir: &RepoDir,
    path: &'p str,
) -> Result<(Option<OwnedFd>, &'p str), FsError> {
    let Some((parent, leaf)) = path.rsplit_once('/') else {
        return Ok((None, path));
    };
    let fd = open_beneath(dir.as_fd(), parent).map_err(|e| FsError::at(e, dir.err_path(parent)))?;
    Ok((Some(fd), leaf))
}

/// Puts the temp entry `name` of `home` at `leaf` of `parent` by the rule
/// `how`, and syncs `parent` with `fsync` when the entry is in place. The
/// function sets `name` to `None` when a rename moved the entry.
pub(super) fn place_named(
    home: BorrowedFd<'_>,
    name: &mut Option<String>,
    parent: BorrowedFd<'_>,
    leaf: &str,
    how: Publish,
    fsync: bool,
) -> Result<Published, FsError> {
    let tmp = require(name.as_deref(), "a named temp entry has its name")?;
    let moved = match how {
        Publish::Replace => rustix::fs::renameat(home, tmp, parent, leaf).map(|()| true),
        Publish::KeepExisting => match rename_noreplace(home, tmp, parent, leaf) {
            Ok(()) => Ok(true),
            // The file system refuses the flag. A link puts the entry in
            // place, and refuses an existing entry as the flag does.
            Err(Errno::INVAL | Errno::NOSYS) => {
                rustix::fs::linkat(home, tmp, parent, leaf, AtFlags::empty()).map(|()| false)
            }
            Err(e) => Err(e),
        },
    };
    match moved {
        Ok(moved) => {
            if moved {
                *name = None;
            }
            created(parent, fsync)
        }
        Err(Errno::EXIST) if how == Publish::KeepExisting => Ok(Published::Existed),
        Err(e) => Err(io_error(e)),
    }
}

/// Moves `tmp` of `home` to `leaf` of `parent` with `renameat2` and
/// `RENAME_NOREPLACE`.
fn rename_noreplace(
    home: BorrowedFd<'_>,
    tmp: &str,
    parent: BorrowedFd<'_>,
    leaf: &str,
) -> Result<(), Errno> {
    #[cfg(test)]
    if super::FAULTS.with(|faults| faults.borrow().no_rename_noreplace) {
        return Err(Errno::INVAL);
    }
    rustix::fs::renameat_with(home, tmp, parent, leaf, RenameFlags::NOREPLACE)
}

/// Syncs `parent` with `fsync`, and gives [`Published::Created`].
pub(super) fn created(parent: BorrowedFd<'_>, fsync: bool) -> Result<Published, FsError> {
    if fsync {
        fsync_dir(parent).map_err(io_error)?;
    }
    Ok(Published::Created)
}

/// Enables fs-verity on the read-only descriptor `fd`. The function tries
/// again after `ETXTBSY`, [`SEAL_ATTEMPTS`] attempts at most with a pause of
/// [`SEAL_PAUSE`].
fn enable_verity(fd: BorrowedFd<'_>) -> Result<(), Errno> {
    let mut attempts = 1;
    loop {
        match ostrya_sys::enable_verity(fd) {
            Err(Errno::TXTBSY) if attempts < SEAL_ATTEMPTS => {
                attempts += 1;
                std::thread::sleep(SEAL_PAUSE);
            }
            other => return other,
        }
    }
}

/// Writes the path `/proc/self/fd/<fd>` into `buf`, followed by `/<name>`
/// when there is a `name`, and gives the path.
///
/// [`PROC_PATH_MAX`] holds each descriptor number and each temp name. A path
/// longer than `buf` is a defect, as for [`require`].
fn proc_path<'b>(
    buf: &'b mut [u8; PROC_PATH_MAX],
    fd: BorrowedFd<'_>,
    name: Option<&str>,
) -> Result<&'b [u8], FsError> {
    let mut rest = &mut buf[..];
    let fd = fd.as_raw_fd();
    let written = match name {
        None => write!(rest, "{PROC_FD}{fd}"),
        Some(name) => write!(rest, "{PROC_FD}{fd}/{name}"),
    };
    require(written.ok(), "a /proc/self/fd path fits its buffer")?;
    let len = PROC_PATH_MAX - rest.len();
    Ok(&buf[..len])
}

/// Returns the error of `errno` from a call through `/proc/self/fd`.
///
/// `ENOENT` gives [`FsError::Io`] with the message `enoent`, which states
/// the causes for the call. Each other errno gives [`FsError::Io`] with the
/// same errno.
fn proc_error(errno: Errno, enoent: &'static str) -> FsError {
    if errno != Errno::NOENT {
        return io_error(errno);
    }
    FsError::Io(io::Error::new(io::ErrorKind::NotFound, enoent))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::path::Path;
    use std::rc::Rc;

    use ostrya_composefs::FsVerityHasher;

    use super::super::read::verity_digest;
    use super::super::{
        FaultReset, HookPoint, RepoLayout, TestDir, id_of, io_err, is_symlink, mode_of, names_with,
        record_syncs, refs, root, set_faults, set_hook, stat_fd, take_synced, temp_names,
    };
    use super::*;

    /// The ways to make a temp file and to publish it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Way {
        /// An `O_TMPFILE` file.
        Anonymous,
        /// A named file, published with `RENAME_NOREPLACE`.
        Named,
        /// A named file, published with the `linkat` fallback.
        NamedLinkat,
    }

    /// Sets the faults that force `way`, or gives `None` with a note if the
    /// file system of `dir` has no `O_TMPFILE` for an anonymous file.
    fn set_way(dir: &TestDir, way: Way) -> Option<FaultReset> {
        if way == Way::Anonymous
            && rustix::fs::openat(dir.fd(), c".", TMPFILE_OPEN, Mode::from_raw_mode(0o600)).is_err()
        {
            eprintln!("skipping the anonymous case: the file system has no O_TMPFILE");
            return None;
        }
        Some(set_faults(|f| {
            f.no_tmpfile = way != Way::Anonymous;
            f.no_rename_noreplace = way == Way::NamedLinkat;
        }))
    }

    /// Makes a temp file for a write to `dir`, with the content `data`.
    fn temp_with(dir: &RepoDir, data: &[u8]) -> TempFile {
        let mut temp = TempFile::create(dir).unwrap();
        temp.file_mut().write_all(data).unwrap();
        temp
    }

    /// Gives `true` if the result is an error of `errno`.
    fn is_errno<T: std::fmt::Debug>(result: &Result<T, FsError>, errno: Errno) -> bool {
        matches!(result, Err(FsError::Io(e)) if e.raw_os_error() == Some(errno.raw_os_error()))
    }

    fn is_root() -> bool {
        rustix::process::geteuid().is_root()
    }

    #[test]
    fn publish_keep_existing_gives_created_then_existed() {
        for way in [Way::Anonymous, Way::Named, Way::NamedLinkat] {
            let dir = TestDir::new("temp-keep");
            let Some(_way) = set_way(&dir, way) else {
                continue;
            };
            let refs = refs(&dir);
            let heads = dir.path().join("refs/heads");
            let _record = record_syncs();

            let first = temp_with(&refs, b"first");
            assert_eq!(
                temp_names(&dir).is_empty(),
                way == Way::Anonymous,
                "{way:?}"
            );
            let result = first.publish(&refs, "heads/main", Publish::KeepExisting, true);
            assert_eq!(result.unwrap(), Published::Created, "{way:?}");
            assert_eq!(take_synced(), [id_of(&heads)], "{way:?}");
            assert_eq!(mode_of(&heads.join("main")), 0o644, "{way:?}");

            let second = temp_with(&refs, b"second");
            let result = second.publish(&refs, "heads/main", Publish::KeepExisting, true);
            assert_eq!(result.unwrap(), Published::Existed, "{way:?}");
            assert!(take_synced().is_empty(), "{way:?}");
            assert_eq!(std::fs::read(heads.join("main")).unwrap(), b"first");
            assert!(temp_names(&dir).is_empty(), "{way:?}");
        }
    }

    #[test]
    fn publish_replace_replaces_a_file_and_a_symlink_and_keeps_its_target() {
        for way in [Way::Anonymous, Way::Named] {
            let dir = TestDir::new("temp-replace");
            let Some(_way) = set_way(&dir, way) else {
                continue;
            };
            let refs = refs(&dir);
            let heads = dir.path().join("refs/heads");
            std::fs::write(heads.join("file"), b"old").unwrap();
            std::fs::write(dir.path().join("target"), b"target").unwrap();
            symlink("../../target", heads.join("link")).unwrap();
            for leaf in ["file", "link"] {
                let temp = temp_with(&refs, b"new");
                let result = temp.publish(&refs, &format!("heads/{leaf}"), Publish::Replace, false);
                assert_eq!(result.unwrap(), Published::Created, "{way:?} {leaf}");
                assert!(!is_symlink(&heads.join(leaf)), "{way:?} {leaf}");
                assert_eq!(std::fs::read(heads.join(leaf)).unwrap(), b"new");
            }
            assert_eq!(std::fs::read(dir.path().join("target")).unwrap(), b"target");

            // A path of one component goes in the directory of the handle.
            let _record = record_syncs();
            let temp = temp_with(&refs, b"top");
            let result = temp.publish(&refs, "top", Publish::Replace, true);
            assert_eq!(result.unwrap(), Published::Created, "{way:?}");
            assert_eq!(take_synced(), [id_of(&dir.path().join("refs"))]);
            assert!(temp_names(&dir).is_empty(), "{way:?}");
        }
    }

    #[test]
    fn the_forced_tmpfile_fallback_makes_a_named_file_in_the_temp_directory() {
        let dir = TestDir::new("temp-named");
        let repo = root(&dir);
        let refs = repo.ensure_layout(RepoLayout::Refs, false).unwrap();
        let _named = set_faults(|f| f.no_tmpfile = true);

        let temp = TempFile::create(&refs).unwrap();
        let names = temp_names(&dir);
        assert_eq!(names.len(), 1);
        let suffix = names[0]
            .strip_prefix(&format!("{TEMP_PREFIX}{}-", std::process::id()))
            .unwrap();
        assert_eq!(suffix.len(), 6, "{names:?}");
        assert!(
            suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
            "{names:?}"
        );
        assert_eq!(temp.entry.name.as_deref(), Some(names[0].as_str()));

        let (staging_name, staging, ()) = repo
            .tmp_dir(false)
            .unwrap()
            .make_temp_dir("staging-", |_| Some(()))
            .unwrap();
        let in_staging = TempFile::create(&staging).unwrap();
        let staging_path = dir.path().join("tmp").join(staging_name);
        assert_eq!(names_with(&staging_path, TEMP_PREFIX).len(), 1);
        assert_eq!(temp_names(&dir), names);

        // A hook that makes the first name forces a real `EEXIST`.
        let tmp_path = dir.path().join("tmp");
        let seen = Rc::new(RefCell::new(Vec::new()));
        let hook_seen = Rc::clone(&seen);
        let _hook = set_hook(HookPoint::TempName, move |name| {
            let name = String::from_utf8(name.to_vec()).unwrap();
            if hook_seen.borrow().is_empty() {
                std::fs::write(tmp_path.join(&name), b"planted").unwrap();
            }
            hook_seen.borrow_mut().push(name);
        });
        let second = TempFile::create(&refs).unwrap();
        let seen = seen.borrow().clone();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert_eq!(second.entry.name.as_deref(), Some(seen[1].as_str()));
        let planted = dir.path().join("tmp").join(&seen[0]);
        assert_eq!(std::fs::read(&planted).unwrap(), b"planted");
        std::fs::remove_file(planted).unwrap();
        drop((temp, in_staging, second));

        let _eexist = set_faults(|f| {
            f.no_tmpfile = true;
            f.force_eexist = true;
        });
        let err = io_err(TempFile::create(&refs));
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            err.to_string(),
            "could not allocate a unique temp file name"
        );
        let err = io_err(TempLink::create(&refs, "target"));
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(temp_names(&dir).is_empty());
    }

    #[test]
    fn drop_unlinks_a_named_temp_file_that_was_not_published() {
        for way in [Way::Anonymous, Way::Named] {
            let dir = TestDir::new("temp-drop");
            let Some(_way) = set_way(&dir, way) else {
                continue;
            };
            let refs = refs(&dir);
            if way == Way::Named {
                let temp = temp_with(&refs, b"x");
                assert_eq!(temp_names(&dir).len(), 1);
                drop(temp);
                assert!(temp_names(&dir).is_empty());
            }

            let temp = temp_with(&refs, b"x");
            match temp.publish(&refs, "heads/missing/main", Publish::KeepExisting, true) {
                Err(FsError::Absent { path }) => assert_eq!(path, "refs/heads/missing"),
                other => panic!("{way:?}: {other:?}"),
            }
            assert!(temp_names(&dir).is_empty(), "{way:?}");

            // A rename over a directory that is not empty fails after the
            // link of an anonymous file at a temp name.
            std::fs::create_dir_all(dir.path().join("refs/heads/dir/sub")).unwrap();
            let temp = temp_with(&refs, b"x");
            let result = temp.publish(&refs, "heads/dir", Publish::Replace, true);
            assert!(matches!(result, Err(FsError::Io(_))), "{way:?}: {result:?}");
            assert!(temp_names(&dir).is_empty(), "{way:?}");
        }
    }

    #[test]
    fn temp_link_publishes_a_symlink_with_its_xattrs() {
        for linkat in [false, true] {
            let dir = TestDir::new("temp-link");
            let refs = refs(&dir);
            let heads = dir.path().join("refs/heads");
            let _linkat = set_faults(|f| f.no_rename_noreplace = linkat);
            let _record = record_syncs();

            let link = TempLink::create(&refs, "target-a").unwrap();
            assert_eq!(temp_names(&dir).len(), 1);
            let result = link.publish(&refs, "heads/link", Publish::KeepExisting, true);
            assert_eq!(result.unwrap(), Published::Created, "{linkat}");
            assert_eq!(take_synced(), [id_of(&heads)], "{linkat}");
            let link = TempLink::create(&refs, "target-b").unwrap();
            let result = link.publish(&refs, "heads/link", Publish::KeepExisting, true);
            assert_eq!(result.unwrap(), Published::Existed, "{linkat}");
            assert!(take_synced().is_empty(), "{linkat}");
            let target = std::fs::read_link(heads.join("link")).unwrap();
            assert_eq!(target, Path::new("target-a"), "{linkat}");

            std::fs::write(heads.join("file"), b"x").unwrap();
            let link = TempLink::create(&refs, "target-c").unwrap();
            let result = link.publish(&refs, "heads/file", Publish::Replace, false);
            assert_eq!(result.unwrap(), Published::Created, "{linkat}");
            let target = std::fs::read_link(heads.join("file")).unwrap();
            assert_eq!(target, Path::new("target-c"), "{linkat}");

            drop(TempLink::create(&refs, "target-d").unwrap());
            assert!(temp_names(&dir).is_empty(), "{linkat}");
        }

        // The kernel refuses a `user.*` attribute on a symlink with `EPERM`.
        // A path through `/proc/self/fd` that does not find the symlink
        // gives `ENOENT`.
        let dir = TestDir::new("temp-link-xattr");
        let refs = refs(&dir);
        let link = TempLink::create(&refs, "target").unwrap();
        let result = link.set_xattr(c"user.demo", b"value");
        assert!(is_errno(&result, Errno::PERM), "{result:?}");
        drop(link);

        if !is_root() {
            eprintln!("skipping the trusted xattr part: a trusted xattr needs root");
            return;
        }
        let link = TempLink::create(&refs, "target").unwrap();
        let result = link.set_xattr(c"trusted.demo", b"value");
        if is_errno(&result, Errno::NOTSUP) {
            eprintln!("skipping the xattr part: the file system has no trusted xattrs");
            return;
        }
        result.unwrap();
        link.publish(&refs, "heads/link", Publish::KeepExisting, false)
            .unwrap();
        let set = refs.link_xattrs("heads/link").unwrap();
        assert!(
            set.iter()
                .any(|(name, value)| name == b"trusted.demo\0" && value == b"value"),
            "{set:?}"
        );
    }

    #[test]
    fn seal_gives_a_sealed_file() {
        let dir = TestDir::new("temp-seal");
        let refs = refs(&dir);
        let data = vec![7u8; 10_000];
        let probe_path = dir.path().join("probe");
        std::fs::write(&probe_path, b"x").unwrap();
        let probe = File::open(&probe_path).unwrap();
        if let Err(e) = ostrya_sys::enable_verity(probe.as_fd()) {
            let mut temp = temp_with(&refs, &data);
            assert!(matches!(temp.seal(Tristate::Yes), Err(FsError::Io(_))));
            let mut temp = temp_with(&refs, &data);
            assert!(!temp.seal(Tristate::Maybe).unwrap());
            eprintln!("skipping: the file system has no fs-verity: {e}");
            return;
        }
        let mut temp = temp_with(&refs, &data);
        assert!(temp.seal(Tristate::Yes).unwrap());
        assert!(stat_fd(temp.file.as_fd()).unwrap().verity);
        let result = temp.publish(&refs, "heads/sealed", Publish::KeepExisting, false);
        assert_eq!(result.unwrap(), Published::Created);
        let file = File::open(dir.path().join("refs/heads/sealed")).unwrap();
        assert_eq!(
            verity_digest(file.as_fd(), data.len() as u64),
            Some(FsVerityHasher::hash(&data))
        );
    }

    #[test]
    fn set_mode_and_set_xattr_apply_and_seal_no_keeps_the_file_writable() {
        let dir = TestDir::new("temp-meta");
        let refs = refs(&dir);
        let mut temp = temp_with(&refs, b"x");
        let result = temp.set_xattr(c"user.demo", b"value");
        let xattrs = !is_errno(&result, Errno::NOTSUP);
        if xattrs {
            result.unwrap();
        } else {
            eprintln!("skipping the xattr part: the file system has no user xattrs");
        }
        temp.set_mode(0o640).unwrap();
        assert!(!temp.seal(Tristate::No).unwrap());
        temp.file_mut().write_all(b"y").unwrap();
        temp.sync().unwrap();
        let result = temp.publish(&refs, "heads/meta", Publish::KeepExisting, false);
        assert_eq!(result.unwrap(), Published::Created);
        let path = dir.path().join("refs/heads/meta");
        assert_eq!(mode_of(&path), 0o640);
        assert_eq!(std::fs::read(&path).unwrap(), b"xy");
        if xattrs {
            let set = refs.link_xattrs("heads/meta").unwrap();
            assert!(
                set.iter()
                    .any(|(name, value)| name == b"user.demo\0" && value == b"value"),
                "{set:?}"
            );
        }
    }

    #[test]
    fn set_owner_to_the_ids_of_the_process_keeps_the_owner() {
        let dir = TestDir::new("temp-own-owner");
        let refs = refs(&dir);
        let (uid, gid) = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        let temp = temp_with(&refs, b"x");
        temp.set_owner(uid, gid).unwrap();
        temp.publish(&refs, "heads/file", Publish::KeepExisting, false)
            .unwrap();
        let link = TempLink::create(&refs, "target").unwrap();
        link.set_owner(uid, gid).unwrap();
        link.publish(&refs, "heads/link", Publish::KeepExisting, false)
            .unwrap();
        let heads = dir.path().join("refs/heads");
        for leaf in ["file", "link"] {
            let meta = std::fs::symlink_metadata(heads.join(leaf)).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (uid, gid), "{leaf}");
        }
    }

    #[test]
    fn set_owner_sets_the_owner_of_a_temp_file_and_a_temp_link() {
        if !is_root() {
            eprintln!("skipping: a change of the owner needs root");
            return;
        }
        let dir = TestDir::new("temp-owner");
        let refs = refs(&dir);
        let temp = temp_with(&refs, b"x");
        temp.set_owner(1, 2).unwrap();
        temp.publish(&refs, "heads/file", Publish::KeepExisting, false)
            .unwrap();
        let link = TempLink::create(&refs, "target").unwrap();
        link.set_owner(3, 4).unwrap();
        link.publish(&refs, "heads/link", Publish::KeepExisting, false)
            .unwrap();
        let heads = dir.path().join("refs/heads");
        let meta = std::fs::symlink_metadata(heads.join("file")).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (1, 2));
        let meta = std::fs::symlink_metadata(heads.join("link")).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (3, 4));
    }

    // `OSTRYA_TEST_VFAT_DIR` names a directory on a vfat file system that the
    // user of the test can write, for example a loop image mounted with
    // `-o uid=$(id -u),gid=$(id -g),quiet`. The mount needs the option
    // `quiet`: without it, vfat refuses with `EPERM` an `fchmod` that changes
    // the read or execute bits, and the publish sets the file mode with
    // `fchmod`.
    #[test]
    fn a_temp_file_on_vfat_uses_a_named_file() {
        let Some(base) = std::env::var_os("OSTRYA_TEST_VFAT_DIR") else {
            eprintln!("skipping: OSTRYA_TEST_VFAT_DIR names no vfat directory");
            return;
        };
        let dir = TestDir::new_in(Path::new(&base), "temp-vfat");
        let refs = refs(&dir);
        let first = temp_with(&refs, b"first");
        assert_eq!(temp_names(&dir).len(), 1);
        let result = first.publish(&refs, "heads/main", Publish::KeepExisting, false);
        assert_eq!(result.unwrap(), Published::Created);
        let second = temp_with(&refs, b"second");
        let result = second.publish(&refs, "heads/main", Publish::KeepExisting, false);
        assert_eq!(result.unwrap(), Published::Existed);
        let third = temp_with(&refs, b"third");
        let result = third.publish(&refs, "heads/main", Publish::Replace, false);
        assert_eq!(result.unwrap(), Published::Created);
        let heads = dir.path().join("refs/heads");
        assert_eq!(std::fs::read(heads.join("main")).unwrap(), b"third");
        drop(temp_with(&refs, b"dropped"));
        assert!(temp_names(&dir).is_empty());
    }

    #[test]
    fn into_file_unlinks_the_temp_name_and_keeps_the_file_open() {
        let dir = TestDir::new("temp-into-file");
        let refs = refs(&dir);
        let _named = set_faults(|f| f.no_tmpfile = true);
        let temp = temp_with(&refs, b"data");
        assert_eq!(temp_names(&dir).len(), 1);
        let mut file = temp.into_file().unwrap();
        assert!(temp_names(&dir).is_empty());
        file.write_all(b"-more").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "data-more");
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a publish needs set_mode or a kind with a file mode")]
    fn publish_to_a_kind_with_no_file_mode_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-publish");
        let objects = root(&dir)
            .ensure_layout(RepoLayout::Objects, false)
            .unwrap();
        let _ = temp_with(&objects, b"x").publish(&objects, "x", Publish::KeepExisting, false);
    }
}
