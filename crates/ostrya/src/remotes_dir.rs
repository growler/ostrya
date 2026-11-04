//! The read of the remotes directory of a repository handle: the key that
//! names the directory in `config`, and the `.conf` files that hold remotes.
//!
//! Each call blocks the calling thread, so a caller runs it on the blocking
//! pool.

use std::ffi::{CStr, OsStr};
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use ostrya_core::KeyFile;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::config::{EX_OSTRYA, REMOTES_CONFIG_DIR, RemoteFile, RepoConfig};
use crate::error::{Error, Result};
use crate::repo::{MAX_CONFIG_SIZE, RemotesDir};

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
    let (base, at, path) = match dir {
        RemotesDir::Path(path) => (rustix::fs::CWD, path.as_path(), path.as_path()),
        RemotesDir::InRepo(path) => (repo_fd, path.as_path(), path.as_path()),
        RemotesDir::Fd(fd) => (fd.as_fd(), Path::new("."), Path::new("")),
    };
    let dir_fd = match rustix::fs::openat(
        base,
        at,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(config),
        Err(err) => return Err(io_error(at, err)),
    };

    let mut names = Vec::new();
    let mut reader = Dir::new(dir_fd).map_err(|err| io_error(at, err))?;
    for entry in &mut reader {
        let entry = entry.map_err(|err| io_error(at, err))?;
        if entry.file_name().to_bytes().ends_with(SUFFIX) {
            names.push((entry.file_name().to_owned(), entry.file_type()));
        }
    }
    // Each file is read in name order, so the first error does not depend on
    // the order of the directory.
    names.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let dir_fd = reader.fd().map_err(|err| io_error(at, err))?;
    let mut files = Vec::new();
    for (name, file_type) in &names {
        let display = path.join(OsStr::from_bytes(name.to_bytes()));
        if let Some(file) = read_file(dir_fd, name, *file_type, &display)? {
            files.push(file);
        }
    }
    config.with_remote_files(path, files)
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
