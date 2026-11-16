//! The read and the write of the remotes directory of a repository handle:
//! the key that names the directory in `config`, and the `.conf` files that
//! hold remotes.
//!
//! The remotes directory is not a directory of the repository layout. Each
//! access goes through the named primitives of `repo_fs`: an open follows a
//! symlink at each component of the path of the directory and at each name
//! in it, and a write replaces a symlink at a name with a regular file.
//!
//! Each call blocks the calling thread, so a caller runs it on the blocking
//! pool.

use std::ffi::OsStr;
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use ostrya_core::{KeyFile, RepoMode};
use rustix::fs::FileType;
use rustix::io::Errno;

use crate::config::{
    EX_OSTRYA, REMOTES_CONFIG_DIR, RemoteFile, RepoConfig, remote_group, remote_group_name,
};
use crate::error::{Error, Result};
use crate::repo::{MAX_CONFIG_SIZE, RemotesDir};
use crate::repo_fs::{
    FsError, FsResultExt, Named, Publish, Published, Reason, ensure_named_dir, list_fd, open_named,
    put_named, remove_named,
};

/// The name suffix of a file that the read takes.
const SUFFIX: &[u8] = b".conf";

/// Returns the remotes directory that `[ex-ostrya] remotes-config-dir` of
/// `config` names, or `None` if the key is absent.
///
/// An absolute value gives a [`RemotesDir::Path`], and a relative value a
/// [`RemotesDir::InRepo`].
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if the value is empty, holds a NUL byte, or is
///   a relative path with a `..` component.
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
    if path.is_absolute() {
        return Ok(Some(RemotesDir::Path(path)));
    }
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(Error::InvalidFormat(format!(
            "[{EX_OSTRYA}] {REMOTES_CONFIG_DIR} {} has a `..` component, which a relative path \
             in a config cannot have",
            path.display()
        )));
    }
    Ok(Some(RemotesDir::InRepo(path)))
}

/// Reads the `.conf` files of `dir` and adds their remotes to `config`.
///
/// `repo_fd` is the descriptor of the repository directory, which an
/// [`InRepo`](RemotesDir::InRepo) value resolves against.
///
/// The open of the directory follows a symlink at each component of its
/// path. The read takes each entry whose name ends in `.conf`, in the byte
/// order of the names. It skips a directory, a FIFO, a socket, and a device
/// by the type of the listing, and opens no such entry. It opens a regular
/// file and a symlink with `O_NONBLOCK`, and follows the symlink. It then
/// skips the entry if the open file is not a regular file, so a FIFO that
/// comes in after the listing does not block the read. A symlink to an
/// absent file is skipped. The open of a symlink to a device opens the
/// device before the type check, and the open of a device with a driver can
/// have side effects. The read skips the entry if the open succeeds or if
/// the device has no driver. Each other error of the open fails the read,
/// for example `EACCES` for a device on a `nodev` mount. An absent
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
/// - [`Error::InvalidFormat`] if the path or a component of it is not a
///   directory. The message is `<path> is not a directory`.
/// - [`Error::Io`] if the directory or a file cannot be read, or if a
///   symlink does not resolve for a reason other than an absent target.
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
    let repo_mode = config.mode();
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
            repo_mode,
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

/// Returns the descriptor and the path that open the path `name` relative to
/// `dir`, and the path that names it in an error message.
///
/// `name` is a file name of the directory, or a path that a `.conf` file of
/// the directory names. An absolute `name` ignores `dir`. The error path is
/// the path of a [`Path`](RemotesDir::Path) value as given, or of an
/// [`InRepo`](RemotesDir::InRepo) value, joined with `name`. For a
/// [`Fd`](RemotesDir::Fd) value, it is `name` alone.
///
/// An empty `name` gives the empty path to open and to show, and does not
/// name `dir`. The open of the empty path gives "No such file or directory",
/// as the open of an empty value of `config` does.
pub(crate) fn entry<'a>(
    repo_fd: BorrowedFd<'a>,
    dir: &'a RemotesDir,
    name: &Path,
) -> (BorrowedFd<'a>, PathBuf, PathBuf) {
    let (base, at) = locate(repo_fd, dir);
    if name.as_os_str().is_empty() {
        return (base, PathBuf::new(), PathBuf::new());
    }
    (base, at.join(name), display_base(dir).join(name))
}

/// Opens the directory `dir`. Returns `None` if the directory or a parent of
/// it is absent.
fn open_dir(repo_fd: BorrowedFd<'_>, dir: &RemotesDir) -> Result<Option<OwnedFd>> {
    let (base, at) = locate(repo_fd, dir);
    open_named(base, at, Named::Dir)
        .optional()
        .map_err(|err| fs_error(at, err))
}

/// Reads the `.conf` files of the open directory `dir_fd` of `dir`.
fn read_files(dir_fd: BorrowedFd<'_>, dir: &RemotesDir) -> Result<Vec<RemoteFile>> {
    let at = match dir {
        RemotesDir::Fd(_) => Path::new("."),
        _ => display_base(dir),
    };
    let mut entries = list_fd(dir_fd).map_err(|err| fs_error(at, err))?;
    entries.retain(|entry| entry.name.ends_with(SUFFIX));
    // Each file is read in name order, so the first error does not depend on
    // the order of the directory.
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    let mut files = Vec::new();
    for entry in &entries {
        let name = OsStr::from_bytes(&entry.name);
        let display = display_base(dir).join(name);
        if let Some(file) = read_file(dir_fd, name, entry.file_type, &display)? {
            files.push(file);
        }
    }
    Ok(files)
}

/// Reads one `.conf` entry of the directory `dir`. Returns `None` for an
/// entry that is not a regular file after a symlink.
///
/// The listing gives `file_type`. The call skips a directory, a FIFO, a
/// socket, and a device by this type, with no open. It opens a regular file
/// and a symlink with `O_NONBLOCK`, and checks the type of the open file, so
/// a FIFO that replaces the file after the listing does not block the read.
fn read_file(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    file_type: FileType,
    display: &Path,
) -> Result<Option<RemoteFile>> {
    if !matches!(file_type, FileType::RegularFile | FileType::Symlink) {
        return Ok(None);
    }
    let fd = match open_named(dir, Path::new(name), Named::File) {
        Ok(fd) => fd,
        Err(
            FsError::Absent { .. }
            | FsError::Invalid {
                reason: Reason::NotRegular(_),
                ..
            },
        ) => return Ok(None),
        // A symlink whose target passes through a file that is not a
        // directory does not resolve.
        Err(FsError::Invalid {
            reason: Reason::NotDirectory,
            ..
        }) => return Err(io_error(display, Errno::NOTDIR)),
        Err(err) => return Err(fs_error(display, err)),
    };
    let Some(name) = name.to_str() else {
        return Err(Error::InvalidFormat(format!(
            "{}: the file name is not valid UTF-8",
            display.display()
        )));
    };

    // The read stops one byte over the cap, so a file over the cap is
    // refused with no read of the rest.
    let mut bytes = Vec::with_capacity(8 * 1024);
    std::fs::File::from(fd)
        .take(MAX_CONFIG_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| io_error(display, err))?;
    if bytes.len() as u64 > MAX_CONFIG_SIZE {
        return Err(Error::InvalidFormat(format!(
            "{} exceeds the {MAX_CONFIG_SIZE}-byte size cap",
            display.display()
        )));
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
/// directory with `fsync` before it returns.
pub(crate) struct DirWriter<'a> {
    repo_fd: BorrowedFd<'a>,
    dir: &'a RemotesDir,
    /// The open directory, or `None` if it was absent at the read.
    fd: Option<OwnedFd>,
    fsync: bool,
    /// The mode of the repository, which sets the mode of a new
    /// [`InRepo`](RemotesDir::InRepo) directory.
    repo_mode: RepoMode,
}

impl DirWriter<'_> {
    /// Returns the path that names the file `file` of the directory in an
    /// error message.
    fn path(&self, file: &str) -> PathBuf {
        display_base(self.dir).join(file)
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

    /// Writes `bytes` to the file `file` atomically, by the rule `how`: a
    /// new temp file `.ostrya-tmp-<pid>-XXXXXX` in the directory, then a move
    /// to `file`.
    ///
    /// The temp name does not end in `.conf`, so an open never reads it.
    /// [`Publish::KeepExisting`] keeps an entry of any type at `file`, and
    /// gives an [`Error::Io`] of the kind `AlreadyExists`.
    /// [`Publish::Replace`] replaces the entry. A rewrite of a regular file
    /// keeps its mode. A symlink at `file` is replaced with a regular file,
    /// and its target keeps its content. A new file gets the mode `0666` with
    /// the umask applied.
    ///
    /// If the directory is absent, the call creates it and each absent
    /// parent, at mode `0777` with the umask applied. A new directory of an
    /// [`InRepo`](RemotesDir::InRepo) value in a `bare-user-shared`
    /// repository gets the mode `02770`. With `[core] fsync` on, the call
    /// syncs the parent of each new directory, the file, and the directory,
    /// each with `fsync`. An error names `file` or the directory, and the
    /// call removes the temp file.
    pub(crate) fn put(&self, file: &str, bytes: &[u8], how: Publish) -> Result<()> {
        self.check_size(file, bytes)?;
        let created;
        let dir_fd = match &self.fd {
            Some(fd) => fd.as_fd(),
            None => {
                let (base, at) = locate(self.repo_fd, self.dir);
                let in_repo = matches!(self.dir, RemotesDir::InRepo(_));
                created = ensure_named_dir(base, at, in_repo, self.repo_mode, self.fsync)
                    .map_err(|err| fs_error(at, err))?;
                created.as_fd()
            }
        };
        let path = self.path(file);
        match put_named(dir_fd, file, bytes, how, self.fsync) {
            Ok(Published::Created) => Ok(()),
            Ok(Published::Existed) => Err(io_error(&path, Errno::EXIST)),
            Err(err) => Err(fs_error(&path, err)),
        }
    }

    /// Removes the entry `file` of the directory. For a symlink, the call
    /// removes the link, and the target stays. With `[core] fsync` on, the
    /// call syncs the directory.
    pub(crate) fn remove(&self, file: &str) -> Result<()> {
        let removed = match &self.fd {
            Some(fd) => remove_named(fd.as_fd(), file, self.fsync),
            None => Err(FsError::Absent {
                path: file.to_owned(),
            }),
        };
        removed.map_err(|err| fs_error(&self.path(file), err))
    }
}

/// Returns the [`Error`] of `err`, from an operation on the entry that
/// `display` names in a message.
///
/// [`FsError::Io`] gives an [`Error::Io`] with the message
/// `<display>: <reason>`. [`FsError::Invalid`] gives an
/// [`Error::InvalidFormat`] with the message `<display> <reason>`.
/// [`FsError::Absent`] gives an [`Error::Io`] of the kind `NotFound` with the
/// message `<display> does not exist`.
fn fs_error(display: &Path, err: FsError) -> Error {
    match err {
        FsError::Io(err) => io_error(display, err),
        FsError::Invalid { reason, .. } => {
            Error::InvalidFormat(format!("{} {reason}", display.display()))
        }
        FsError::Absent { .. } => Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} does not exist", display.display()),
        )),
        FsError::Exists => io_error(display, Errno::EXIST),
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
