//! The read and the write of the remotes directory of a repository handle:
//! the key that names the directory in `config`, and the `.conf` files that
//! hold remotes.
//!
//! Each call blocks the calling thread, so a caller runs it on the blocking
//! pool.

use std::ffi::{CStr, OsStr};
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use ostrya_core::KeyFile;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::config::{
    EX_OSTRYA, REMOTES_CONFIG_DIR, RemoteFile, RepoConfig, remote_group, remote_group_name,
};
use crate::error::{Error, Result};
use crate::repo::{MAX_CONFIG_SIZE, RemotesDir};
use crate::write::unique;

/// The name suffix of a file that the read takes.
const SUFFIX: &[u8] = b".conf";

/// The flags of an open of a directory.
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

/// The flags of an open of a directory for a path walk, which needs search
/// permission and no read permission.
const PATH_FLAGS: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);

/// The mode that a write requests for a new file. The umask reduces it.
const FILE_MODE: u32 = 0o666;

/// The mode that a write requests for a new directory. The umask reduces it.
const DIR_MODE: u32 = 0o777;

/// Returns the remotes directory that `[ex-ostrya] remotes-config-dir` of
/// `config` names, or `None` if the key is absent.
///
/// An absolute value gives a [`RemotesDir::Path`], and a relative value a
/// [`RemotesDir::InRepo`].
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if the value is empty or holds a NUL byte.
/// - [`Error::Core`] if the value holds a malformed escape sequence.
pub(crate) fn from_key(config: &RepoConfig) -> Result<Option<RemotesDir>> {
    let Some(value) = config.keyfile().get_string(EX_OSTRYA, REMOTES_CONFIG_DIR)? else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err(Error::InvalidFormat(format!(
            "[{EX_OSTRYA}] {REMOTES_CONFIG_DIR} is empty"
        )));
    }
    if value.contains('\0') {
        return Err(Error::InvalidFormat(format!(
            "[{EX_OSTRYA}] {REMOTES_CONFIG_DIR} holds a NUL byte"
        )));
    }
    let path = PathBuf::from(value);
    Ok(Some(match path.is_absolute() {
        true => RemotesDir::Path(path),
        false => RemotesDir::InRepo(path),
    }))
}

/// Reads the `.conf` files of `dir` and adds their remotes to `config`.
///
/// `repo_fd` is the descriptor of the repository directory, which an
/// [`InRepo`](RemotesDir::InRepo) value resolves against.
///
/// The read takes each entry whose name ends in `.conf`, in the byte order of
/// the names. It follows a symlink. It skips each entry that is not a regular
/// file after the symlink, and it does not read a subdirectory. An absent
/// directory, or an absent parent of it, gives no remotes.
///
/// An error message names the directory or the file. A
/// [`Path`](RemotesDir::Path) value names it with the path as given, and an
/// [`InRepo`](RemotesDir::InRepo) value with the path relative to the
/// repository. A [`Fd`](RemotesDir::Fd) value names a file by its name, and
/// the directory as `.`.
///
/// # Errors
///
/// - [`Error::Io`] if the path is not a directory, if the directory or a
///   file cannot be read, or if a symlink does not resolve for a reason
///   other than an absent target.
/// - [`Error::InvalidFormat`] if a file is larger than 1 MiB (1048576
///   bytes), if its name or its content is not valid UTF-8, or if it is not
///   a valid key file.
/// - [`Error::InvalidFormat`] if two sources define one remote name.
pub(crate) fn read_remotes(
    config: RepoConfig,
    repo_fd: BorrowedFd<'_>,
    dir: &RemotesDir,
) -> Result<RepoConfig> {
    open_for_write(config, repo_fd, dir, false).map(|(config, _)| config)
}

/// Reads the remotes of `dir` into `config`, as [`read_remotes`] does, and
/// returns the directory open for the writes of an edit.
///
/// The caller holds the update lock of the repository for the read and the
/// writes. `fsync` is `[core] fsync` of the repository.
///
/// # Errors
///
/// The errors of [`read_remotes`].
pub(crate) fn open_for_write<'a>(
    config: RepoConfig,
    repo_fd: BorrowedFd<'a>,
    dir: &'a RemotesDir,
    fsync: bool,
) -> Result<(RepoConfig, DirWriter<'a>)> {
    let fd = open_dir(repo_fd, dir)?;
    let config = match &fd {
        Some(fd) => config.with_remote_files(display_base(dir), read_files(fd.as_fd(), dir)?)?,
        None => config,
    };
    Ok((
        config,
        DirWriter {
            repo_fd,
            dir,
            fd,
            fsync,
        },
    ))
}

/// Returns the names of the `[remote "NAME"]` groups of a document for
/// `config`, for [`check_config_remotes`].
pub(crate) fn config_remote_names(keyfile: &KeyFile) -> Vec<String> {
    keyfile
        .groups()
        .filter_map(remote_group_name)
        .map(str::to_owned)
        .collect()
}

/// Refuses a document for `config` with a `[remote "NAME"]` group whose
/// `NAME` a `.conf` file of `dir` defines. `names` are the names of the
/// remote groups of the document. The call reads the files of the directory
/// again. A handle with no remotes directory passes `None`, and the call
/// reads nothing.
///
/// # Errors
///
/// - [`Error::RemoteExists`] if a `.conf` file defines a name of `names`.
/// - The errors of [`read_remotes`], except the refusal of a name in two
///   sources.
pub(crate) fn check_config_remotes(
    repo_fd: BorrowedFd<'_>,
    dir: Option<&RemotesDir>,
    names: &[String],
) -> Result<()> {
    let Some(dir) = dir else {
        return Ok(());
    };
    let Some(fd) = open_dir(repo_fd, dir)? else {
        return Ok(());
    };
    let files = read_files(fd.as_fd(), dir)?;
    for name in names {
        let group = remote_group(name);
        if files.iter().any(|file| file.keyfile.has_group(&group)) {
            return Err(Error::RemoteExists(name.clone()));
        }
    }
    Ok(())
}

/// Returns the descriptor that `dir` resolves against and the path from that
/// descriptor. A [`Fd`](RemotesDir::Fd) value is the directory itself, as
/// `.`.
fn locate<'a>(repo_fd: BorrowedFd<'a>, dir: &'a RemotesDir) -> (BorrowedFd<'a>, &'a Path) {
    match dir {
        RemotesDir::Path(path) => (rustix::fs::CWD, path.as_path()),
        RemotesDir::InRepo(path) => (repo_fd, path.as_path()),
        RemotesDir::Fd(fd) => (fd.as_fd(), Path::new(".")),
    }
}

/// Returns the path that names a file of `dir` in an error message, when it
/// is joined with the file name: the path of a [`Path`](RemotesDir::Path) or
/// an [`InRepo`](RemotesDir::InRepo) value, and the empty path for a
/// [`Fd`](RemotesDir::Fd) value.
fn display_base(dir: &RemotesDir) -> &Path {
    match dir {
        RemotesDir::Path(path) | RemotesDir::InRepo(path) => path,
        RemotesDir::Fd(_) => Path::new(""),
    }
}

/// Returns the descriptor and the path that open the entry `name` of `dir`,
/// and the path that names the entry in an error message.
///
/// The error path is the path of a [`Path`](RemotesDir::Path) value as
/// given, or of an [`InRepo`](RemotesDir::InRepo) value, joined with `name`.
/// For a [`Fd`](RemotesDir::Fd) value, it is `name` alone.
#[cfg(feature = "verify-gpg")]
pub(crate) fn entry<'a>(
    repo_fd: BorrowedFd<'a>,
    dir: &'a RemotesDir,
    name: &str,
) -> (BorrowedFd<'a>, PathBuf, PathBuf) {
    let (base, at) = locate(repo_fd, dir);
    (base, at.join(name), display_base(dir).join(name))
}

/// Opens the directory `dir`. Returns `None` if the directory or a parent of
/// it is absent.
fn open_dir(repo_fd: BorrowedFd<'_>, dir: &RemotesDir) -> Result<Option<OwnedFd>> {
    let (base, at) = locate(repo_fd, dir);
    match rustix::fs::openat(base, at, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        Err(err) => Err(io_error(at, err)),
    }
}

/// Reads the `.conf` files of the open directory `dir_fd` of `dir`.
fn read_files(dir_fd: BorrowedFd<'_>, dir: &RemotesDir) -> Result<Vec<RemoteFile>> {
    let at = match dir {
        RemotesDir::Fd(_) => Path::new("."),
        _ => display_base(dir),
    };
    let mut names = Vec::new();
    let mut reader = Dir::read_from(dir_fd).map_err(|err| io_error(at, err))?;
    for entry in &mut reader {
        let entry = entry.map_err(|err| io_error(at, err))?;
        if entry.file_name().to_bytes().ends_with(SUFFIX) {
            names.push((entry.file_name().to_owned(), entry.file_type()));
        }
    }
    // Each file is read in name order, so the first error does not depend on
    // the order of the directory.
    names.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let mut files = Vec::new();
    for (name, file_type) in &names {
        let display = display_base(dir).join(OsStr::from_bytes(name.to_bytes()));
        if let Some(file) = read_file(dir_fd, name, *file_type, &display)? {
            files.push(file);
        }
    }
    Ok(files)
}

/// Reads one `.conf` entry of the directory `dir`. Returns `None` for an
/// entry that is not a regular file after a symlink.
///
/// The call checks the type before it opens the file, so it opens no device
/// and no socket. It opens the file with `O_NONBLOCK` and checks the type
/// again, so a FIFO that replaces the file after the check does not block
/// the read.
fn read_file(
    dir: BorrowedFd<'_>,
    name: &CStr,
    file_type: FileType,
    display: &Path,
) -> Result<Option<RemoteFile>> {
    let regular = match file_type {
        FileType::RegularFile => true,
        FileType::Symlink | FileType::Unknown => {
            match rustix::fs::statat(dir, name, AtFlags::empty()) {
                Ok(stat) => FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
                Err(Errno::NOENT) => false,
                Err(err) => return Err(io_error(display, err)),
            }
        }
        _ => false,
    };
    if !regular {
        return Ok(None);
    }
    let Ok(name) = name.to_str() else {
        return Err(Error::InvalidFormat(format!(
            "{}: the file name is not valid UTF-8",
            display.display()
        )));
    };
    let fd = match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(err) => return Err(io_error(display, err)),
    };
    let stat = rustix::fs::fstat(&fd).map_err(|err| io_error(display, err))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Ok(None);
    }
    let too_large = || {
        Error::InvalidFormat(format!(
            "{} exceeds the {MAX_CONFIG_SIZE}-byte size cap",
            display.display()
        ))
    };
    let size = u64::try_from(stat.st_size).unwrap_or(0);
    if size > MAX_CONFIG_SIZE {
        return Err(too_large());
    }

    // The size is read again through the cap, so a file that grows after the
    // `fstat` is refused too.
    let mut bytes = Vec::with_capacity(size as usize + 1);
    std::fs::File::from(fd)
        .take(MAX_CONFIG_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| io_error(display, err))?;
    if bytes.len() as u64 > MAX_CONFIG_SIZE {
        return Err(too_large());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        Error::InvalidFormat(format!(
            "{}: the content is not valid UTF-8",
            display.display()
        ))
    })?;
    let keyfile = KeyFile::parse(text)
        .map_err(|err| Error::InvalidFormat(format!("{}: {err}", display.display())))?;
    Ok(Some(RemoteFile {
        name: name.to_owned(),
        keyfile,
    }))
}

/// The remotes directory of a repository handle, open for the writes of one
/// edit under the update lock.
///
/// Each write changes one entry of the directory with one rename or one
/// unlink. With `[core] fsync` on, each write syncs the file and the
/// directory before it returns.
pub(crate) struct DirWriter<'a> {
    repo_fd: BorrowedFd<'a>,
    dir: &'a RemotesDir,
    /// The open directory, or `None` if it was absent at the read.
    fd: Option<OwnedFd>,
    fsync: bool,
}

impl DirWriter<'_> {
    /// Returns the path that names the file `file` of the directory in an
    /// error message.
    fn path(&self, file: &str) -> PathBuf {
        display_base(self.dir).join(file)
    }

    /// Refuses an entry `file` of any type in the directory, a symlink
    /// included, with an [`Error::Io`] of the kind `AlreadyExists`.
    pub(crate) fn check_absent(&self, file: &str) -> Result<()> {
        let Some(fd) = &self.fd else {
            return Ok(());
        };
        match rustix::fs::statat(fd, file, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Err(io_error(&self.path(file), Errno::EXIST)),
            Err(Errno::NOENT) => Ok(()),
            Err(err) => Err(io_error(&self.path(file), err)),
        }
    }

    /// Returns the permission bits of the entry `file`, which a write of the
    /// file keeps. Refuses a symlink with [`Error::InvalidFormat`], because a
    /// rename over the link replaces the link with a regular file.
    pub(crate) fn mode_of(&self, file: &str) -> Result<u32> {
        let stat = match &self.fd {
            Some(fd) => rustix::fs::statat(fd, file, AtFlags::SYMLINK_NOFOLLOW),
            None => Err(Errno::NOENT),
        }
        .map_err(|err| io_error(&self.path(file), err))?;
        if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink {
            return Err(Error::InvalidFormat(format!(
                "{} is a symlink, and a write would replace it with a regular file",
                self.path(file).display()
            )));
        }
        Ok(stat.st_mode & 0o7777)
    }

    /// Refuses `bytes` larger than 1 MiB, the size that an open of the
    /// repository accepts for the file `file`.
    pub(crate) fn check_size(&self, file: &str, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 > MAX_CONFIG_SIZE {
            return Err(Error::InvalidFormat(format!(
                "{} exceeds the {MAX_CONFIG_SIZE}-byte size cap",
                self.path(file).display()
            )));
        }
        Ok(())
    }

    /// Writes `bytes` to the file `file` atomically: a new temporary file in
    /// the directory, then a rename over `file`.
    ///
    /// The temporary file is `.ostrya-tmp-<pid>-<n>`, so its name does not
    /// end in `.conf`, an open never reads it, and its length does not
    /// depend on `file`. With `mode`, the file gets
    /// these permission bits. With no `mode`, it gets mode `0666` with the
    /// umask applied. If the directory is absent, the call creates it and
    /// each absent parent, at mode `0777` with the umask applied. An error
    /// names `file`, and the call removes the temporary file.
    pub(crate) fn put(&self, file: &str, bytes: &[u8], mode: Option<u32>) -> Result<()> {
        use std::io::Write;

        self.check_size(file, bytes)?;
        let path = self.path(file);
        let created;
        let dir_fd = match &self.fd {
            Some(fd) => fd.as_fd(),
            None => {
                created = self.create_dir()?;
                created.as_fd()
            }
        };
        let tmp = format!(".ostrya-tmp-{}-{}", std::process::id(), unique());
        let fd = rustix::fs::openat(
            dir_fd,
            tmp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(FILE_MODE),
        )
        .map_err(|err| io_error(&path, err))?;
        let write_and_rename = || -> std::io::Result<()> {
            let mut out = std::fs::File::from(fd);
            out.write_all(bytes)?;
            if let Some(mode) = mode {
                rustix::fs::fchmod(&out, Mode::from_raw_mode(mode))?;
            }
            if self.fsync {
                rustix::fs::fdatasync(&out)?;
            }
            drop(out);
            rustix::fs::renameat(dir_fd, tmp.as_str(), dir_fd, file)?;
            Ok(())
        };
        write_and_rename().map_err(|err| {
            let _ = rustix::fs::unlinkat(dir_fd, tmp.as_str(), AtFlags::empty());
            io_error(&path, err)
        })?;
        self.sync_dir(dir_fd, file)
    }

    /// Removes the entry `file` of the directory. For a symlink, the call
    /// removes the link, and the target stays.
    pub(crate) fn remove(&self, file: &str) -> Result<()> {
        let removed = match &self.fd {
            Some(fd) => rustix::fs::unlinkat(fd, file, AtFlags::empty()).map(|()| fd),
            None => Err(Errno::NOENT),
        };
        let fd = removed.map_err(|err| io_error(&self.path(file), err))?;
        self.sync_dir(fd.as_fd(), file)
    }

    /// Syncs the directory after a change of the entry `file`, if `[core]
    /// fsync` is on.
    fn sync_dir(&self, dir_fd: impl AsFd, file: &str) -> Result<()> {
        if self.fsync {
            rustix::fs::fsync(dir_fd).map_err(|err| io_error(&self.path(file), err))?;
        }
        Ok(())
    }

    /// Creates the directory and each absent parent, and returns the open
    /// directory. With `[core] fsync` on, the call syncs the parent of each
    /// directory that it creates, and the directory that it returns can be
    /// synced.
    ///
    /// The walk opens each directory with `O_PATH`, so it needs search
    /// permission and no read permission, as `mkdir -p` does. A sync needs
    /// a directory open for read, so with `[core] fsync` on, the call also
    /// needs read permission on the parent of each directory that it
    /// creates.
    fn create_dir(&self) -> Result<OwnedFd> {
        let (base, at) = locate(self.repo_fd, self.dir);
        let error = |err: Errno| io_error(at, err);
        let open_path = |parent: BorrowedFd<'_>, name: &OsStr| {
            rustix::fs::openat(parent, name, PATH_FLAGS, Mode::empty())
        };
        let open_read =
            |dir: BorrowedFd<'_>| rustix::fs::openat(dir, ".", DIR_FLAGS, Mode::empty());
        // `None` is `base`.
        let mut current: Option<OwnedFd> = None;
        for component in at.components() {
            let name = match component {
                Component::RootDir => {
                    current = Some(open_path(rustix::fs::CWD, OsStr::new("/")).map_err(error)?);
                    continue;
                }
                Component::CurDir | Component::Prefix(_) => continue,
                Component::ParentDir => OsStr::new(".."),
                Component::Normal(name) => name,
            };
            let parent = current.as_ref().map_or(base, AsFd::as_fd);
            let next = match open_path(parent, name) {
                Err(Errno::NOENT) => {
                    let created =
                        match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(DIR_MODE)) {
                            Ok(()) => true,
                            Err(Errno::EXIST) => false,
                            Err(err) => return Err(error(err)),
                        };
                    let next = open_path(parent, name).map_err(error)?;
                    if created && self.fsync {
                        rustix::fs::fsync(open_read(parent).map_err(error)?).map_err(error)?;
                    }
                    next
                }
                opened => opened.map_err(error)?,
            };
            current = Some(next);
        }
        match current {
            Some(current) if !self.fsync => Ok(current),
            current => open_read(current.as_ref().map_or(base, AsFd::as_fd)).map_err(error),
        }
    }
}

/// Returns an [`Error::Io`] with the kind of `err` and the message
/// `<path>: <reason>`.
fn io_error(path: &Path, err: impl Into<std::io::Error>) -> Error {
    let err = err.into();
    let reason = err.to_string();
    let reason = match reason.find(" (os error ") {
        Some(cut) => &reason[..cut],
        None => reason.as_str(),
    };
    Error::Io(std::io::Error::new(
        err.kind(),
        format!("{}: {reason}", path.display()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORE: &str = "[core]\nrepo_version=1\nmode=archive-z2\n";

    /// Returns the value that `from_key` gives for the config `CORE` with
    /// `extra` after it.
    fn key(extra: &str) -> Result<Option<RemotesDir>> {
        from_key(&RepoConfig::parse(&format!("{CORE}{extra}")).unwrap())
    }

    #[test]
    fn the_key_gives_a_path_an_in_repo_value_or_a_refusal() {
        assert!(key("").unwrap().is_none());
        assert!(matches!(
            key("[ex-ostrya]\nremotes-config-dir=/etc/remotes.d\n").unwrap(),
            Some(RemotesDir::Path(p)) if p == Path::new("/etc/remotes.d")
        ));
        assert!(matches!(
            key("[ex-ostrya]\nremotes-config-dir=remotes.d\n").unwrap(),
            Some(RemotesDir::InRepo(p)) if p == Path::new("remotes.d")
        ));
        assert!(matches!(
            key("[ex-ostrya]\nremotes-config-dir=\\sa b\n").unwrap(),
            Some(RemotesDir::InRepo(p)) if p == Path::new(" a b")
        ));
        for empty in ["remotes-config-dir=\n", "remotes-config-dir=   \n"] {
            let err = key(&format!("[ex-ostrya]\n{empty}")).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidFormat(m) if m.contains("empty")),
                "{err}"
            );
        }
        let err = key("[ex-ostrya]\nremotes-config-dir=a\0b\n").unwrap_err();
        assert!(
            matches!(&err, Error::InvalidFormat(m) if m.contains("NUL")),
            "{err}"
        );
        let err = key("[ex-ostrya]\nremotes-config-dir=a\\qb\n").unwrap_err();
        assert!(matches!(err, Error::Core(_)), "{err}");
    }
}
