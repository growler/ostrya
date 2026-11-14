//! The primitives of the paths that a config or a caller names, and of a
//! remotes directory.
//!
//! These paths are not paths of the repository layout, so the resolve rule
//! of a [`RepoDir`](super::RepoDir) does not apply to them. A primitive takes
//! a plain descriptor as its base. A relative path resolves against the base,
//! and an absolute path ignores the base, as the kernel does. Each open
//! follows a symlink at each component, also to a path outside the
//! repository.
//!
//! A relative path with a `..` component gives [`Reason::ParentDir`]. The
//! check reads the text of the path alone, before each syscall. An absolute
//! path with a `..` component is not refused.
//!
//! The path of an error is the path as the caller gives it.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path};

use ostrya_core::RepoMode;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, StatxFlags};
use rustix::io::Errno;

use super::dir::{
    DIR_OPEN, force_new_dir_mode, fsync_dir, io_error, is_component, require, root_error,
};
use super::read::{KEYRING_OPEN, followed_type_error};
use super::temp::{NAMED_OPEN, created, make_temp_name, place_named};
use super::{FsError, Publish, Published, Reason, stat_fd};

/// The mode that the create of a new file requests. The umask reduces it.
const NEW_FILE_MODE: u32 = 0o666;

/// The mode that the create of a new directory requests. The umask reduces
/// it.
const NEW_DIR_MODE: u32 = 0o777;

/// The mode of each directory that [`ensure_named_dir`] makes in a
/// `bare-user-shared` repository for a directory of the repository. It is
/// the shared directory mode of each layout kind.
const SHARED_DIR_MODE: u32 = 0o2770;

/// The flags of the open of a directory in a walk. `O_PATH` needs search
/// permission on the directory alone, as `mkdir -p` does.
const WALK_OPEN: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);

/// The kind of the entry that [`open_named`] opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Named {
    /// A regular file, open for read.
    File,
    /// A directory, open for read.
    Dir,
}

/// Opens the entry `want` at `path` relative to `base`, and gives its
/// descriptor.
///
/// The open is one `openat` that follows a symlink at each component. An
/// absolute `path` ignores `base`. A relative `path` with a `..` component
/// gives [`Reason::ParentDir`] before the open.
///
/// [`Named::File`] opens with `O_RDONLY|O_NONBLOCK|O_NOCTTY`, so the open of
/// a FIFO does not wait for a writer. One `statx` on the descriptor then
/// refuses each type other than a regular file, also a directory, with
/// [`Reason::NotRegular`]. A socket and a device with no driver do not open,
/// so one `statx` that follows each symlink reads their type.
/// [`Named::Dir`] opens with `O_RDONLY|O_DIRECTORY`, and an entry that is not
/// a directory gives [`Reason::NotDirectory`].
///
/// `ENOENT` gives [`FsError::Absent`], and `ENOTDIR` gives
/// [`Reason::NotDirectory`]. Each other errno gives [`FsError::Io`], also
/// `ELOOP`.
pub(crate) fn open_named(
    base: BorrowedFd<'_>,
    path: &Path,
    want: Named,
) -> Result<OwnedFd, FsError> {
    refuse_parent_dir(path)?;
    let flags = match want {
        Named::File => KEYRING_OPEN,
        Named::Dir => DIR_OPEN,
    };
    let fd = match rustix::fs::openat(base, path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(e @ (Errno::NXIO | Errno::NODEV)) => {
            return Err(followed_type_error(base, path, e, || {
                path.display().to_string()
            }));
        }
        Err(e) => return Err(root_error(e, path)),
    };
    if want == Named::File {
        let stat = stat_fd(fd.as_fd())?;
        if stat.file_type != FileType::RegularFile {
            return Err(FsError::Invalid {
                path: path.display().to_string(),
                reason: Reason::NotRegular(stat.file_type),
            });
        }
    }
    Ok(fd)
}

/// Writes `bytes` to the file `name` of the directory open at `dir` in one
/// atomic step, by the rule `how`, and gives the result.
///
/// The function writes `bytes` to a new temp file
/// `.ostrya-tmp-<pid>-XXXXXX` in `dir`, and then moves it to `name`.
/// [`Publish::Replace`] moves it with one `renameat`. [`Publish::KeepExisting`]
/// keeps an existing entry and gives [`Published::Existed`]. With
/// [`Publish::KeepExisting`], an entry that the first `statx` finds at `name`
/// gives [`Published::Existed`] at once, and no temp file. The placement is
/// that of [`TempFile::publish`](super::TempFile::publish) for a named temp
/// file. The temp name is unlinked after an error and after
/// [`Published::Existed`].
///
/// The mode of an existing regular file at `name` stays: an `fchmod` sets it
/// on the new file before the write of `bytes`. Each other entry at `name`
/// gets the mode of a new file: `0666`, which the umask reduces.
/// [`Publish::Replace`] replaces a symlink at `name` with a regular file, and
/// never writes through it. The target of the symlink keeps its content. It
/// also replaces a FIFO and a socket. With [`Publish::Replace`], a directory
/// at `name` gives [`FsError::Io`].
///
/// The caller holds all of `bytes` in memory, so the function is for a file
/// whose size the caller caps.
///
/// With `fsync`, the function syncs the file with `fsync` before the move,
/// and syncs `dir` after [`Published::Created`]. The sync comes after the
/// unlink of the temp name, so a crash leaves no durable temp file.
///
/// A `name` that is not one path component is a defect of the caller: it
/// fails a debug assertion, and gives an `InvalidInput` error in a release
/// build. Each other error gives [`FsError::Io`].
pub(crate) fn put_named(
    dir: BorrowedFd<'_>,
    name: &str,
    bytes: &[u8],
    how: Publish,
    fsync: bool,
) -> Result<Published, FsError> {
    require(
        is_component(name.as_bytes()).then_some(()),
        "put_named needs a name of one path component",
    )?;
    let kept = match rustix::fs::statx(
        dir,
        name,
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::TYPE | StatxFlags::MODE,
    ) {
        Ok(_) if how == Publish::KeepExisting => return Ok(Published::Existed),
        Ok(stx) => {
            let mode = u32::from(stx.stx_mode);
            (FileType::from_raw_mode(mode) == FileType::RegularFile).then_some(mode & 0o7777)
        }
        Err(Errno::NOENT) => None,
        Err(e) => return Err(io_error(e)),
    };
    let (temp, fd) = make_temp_name(
        |temp| rustix::fs::openat(dir, temp, NAMED_OPEN, Mode::from_raw_mode(NEW_FILE_MODE)),
        io_error,
    )?;
    let mut temp = Some(temp);
    let placed = fill(File::from(fd), bytes, kept, fsync)
        .and_then(|()| place_named(dir, &mut temp, dir, name, how, false));
    // The name stays after an error, after `Existed`, and after a link put
    // the file in place.
    if let Some(temp) = temp.as_deref() {
        let _ = rustix::fs::unlinkat(dir, temp, AtFlags::empty());
    }
    match placed? {
        Published::Created => created(dir, fsync),
        Published::Existed => Ok(Published::Existed),
    }
}

/// Unlinks the entry `name` of the directory open at `dir`.
///
/// The unlink is one `unlinkat`. A symlink at `name` is unlinked, and its
/// target stays. An absent entry gives [`FsError::Absent`] with `name` as
/// the path. A directory at `name` gives [`FsError::Io`] with `EISDIR`, and
/// each other errno gives [`FsError::Io`].
///
/// With `fsync`, the function syncs `dir` after the unlink.
///
/// A `name` that is not one path component is a defect of the caller: it
/// fails a debug assertion, and gives an `InvalidInput` error in a release
/// build.
pub(crate) fn remove_named(dir: BorrowedFd<'_>, name: &str, fsync: bool) -> Result<(), FsError> {
    require(
        is_component(name.as_bytes()).then_some(()),
        "remove_named needs a name of one path component",
    )?;
    match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) if fsync => fsync_dir(dir).map_err(io_error),
        Ok(()) => Ok(()),
        Err(Errno::NOENT) => Err(FsError::Absent {
            path: name.to_owned(),
        }),
        Err(e) => Err(io_error(e)),
    }
}

/// Makes the directory at `path` relative to `base` and each missing
/// directory on the way, and gives the directory open for read.
///
/// A relative `path` with a `..` component gives [`Reason::ParentDir`]
/// before each syscall. The function first opens `path` with one `openat`
/// that follows a symlink at each component. If that open gives `ENOENT`, a
/// walk opens each existing component with `O_PATH|O_DIRECTORY`, so it needs
/// search permission alone, as `mkdir -p` does. The walk follows a symlink
/// at each existing component. After a missing component, the walk makes
/// each later component with no open first. An absolute `path` starts at
/// `/`. A path with no component, such as `.`, gives `base`.
///
/// A missing component gets `mkdirat` with the mode `0777`, which the umask
/// reduces. `in_repo` states that the directory is in the repository. With
/// `in_repo` in a `bare-user-shared` repository, the request is `0770`, and
/// an `fchmod` forces `02770` on each new directory. The open for the
/// `fchmod` uses `O_NOFOLLOW`, so a symlink in place of the new directory
/// gives an error. If that open or the `fchmod` fails, the function removes
/// the new directory. An existing directory keeps its mode. A directory that
/// another process makes at the same time is used as it is.
///
/// With `fsync`, the function syncs the parent of each new directory at
/// once. It opens the parent for read for the sync, so it then needs read
/// permission on that parent.
///
/// The errors carry `path` as the caller gives it: `ENOENT` gives
/// [`FsError::Absent`], `ENOTDIR` gives [`Reason::NotDirectory`], and each
/// other errno gives [`FsError::Io`].
pub(crate) fn ensure_named_dir(
    base: BorrowedFd<'_>,
    path: &Path,
    in_repo: bool,
    repo_mode: RepoMode,
    fsync: bool,
) -> Result<OwnedFd, FsError> {
    refuse_parent_dir(path)?;
    let error = |e| root_error(e, path);
    match rustix::fs::openat(base, path, DIR_OPEN, Mode::empty()) {
        Err(Errno::NOENT) => {}
        opened => return opened.map_err(error),
    }
    let (request, force) = if in_repo && repo_mode == RepoMode::BareUserShared {
        (SHARED_DIR_MODE & 0o777, Some(SHARED_DIR_MODE))
    } else {
        (NEW_DIR_MODE, None)
    };
    // `None` is `base`.
    let mut current: Option<OwnedFd> = None;
    // Each component below a missing component is missing too. A directory
    // that another process makes at the same time gives `EEXIST`, which
    // `make_named_dir` accepts.
    let mut missing = false;
    for component in path.components() {
        let name = match component {
            Component::RootDir => {
                current = Some(
                    rustix::fs::openat(rustix::fs::CWD, c"/", WALK_OPEN, Mode::empty())
                        .map_err(error)?,
                );
                continue;
            }
            Component::CurDir | Component::Prefix(_) => continue,
            Component::ParentDir => OsStr::new(".."),
            Component::Normal(name) => name,
        };
        let parent = current.as_ref().map_or(base, AsFd::as_fd);
        let next = if missing {
            make_named_dir(parent, name, request, force, fsync)
        } else {
            match rustix::fs::openat(parent, name, WALK_OPEN, Mode::empty()) {
                Err(Errno::NOENT) => {
                    missing = true;
                    make_named_dir(parent, name, request, force, fsync)
                }
                opened => opened,
            }
        };
        current = Some(next.map_err(error)?);
    }
    let last = current.as_ref().map_or(base, AsFd::as_fd);
    rustix::fs::openat(last, c".", DIR_OPEN, Mode::empty()).map_err(error)
}

/// Makes the directory `name` of `parent` with the mode `request`, and opens
/// it for a walk.
///
/// A directory that exists is used as it is. On a new directory, an `fchmod`
/// sets the mode `force`. The open for the `fchmod` uses `O_NOFOLLOW`, so a
/// symlink in place of the new directory gives `ENOTDIR` and gets no
/// `fchmod`. If that open or the `fchmod` fails, the function removes the
/// directory. A symlink or a file at `name` gives `ENOTDIR` and stays. With
/// `fsync`, the function then syncs `parent`.
fn make_named_dir(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    request: u32,
    force: Option<u32>,
    fsync: bool,
) -> Result<OwnedFd, Errno> {
    let created = match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(request)) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(e) => return Err(e),
    };
    let fd = match force.filter(|_| created) {
        Some(force) => {
            let fd = open_new_dir(parent, name).inspect_err(|&e| {
                if e != Errno::NOTDIR {
                    let _ = rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR);
                }
            })?;
            force_new_dir_mode(parent, name, fd.as_fd(), force)?;
            fd
        }
        None => rustix::fs::openat(parent, name, WALK_OPEN, Mode::empty())?,
    };
    if created && fsync {
        let synced = rustix::fs::openat(parent, c".", DIR_OPEN, Mode::empty())?;
        fsync_dir(synced.as_fd())?;
    }
    Ok(fd)
}

/// Opens the new directory `name` of `parent` for read, for an `fchmod`. An
/// `fchmod` needs a descriptor that is not `O_PATH`. `O_NOFOLLOW` refuses a
/// symlink at `name` with `ENOTDIR`.
fn open_new_dir(parent: BorrowedFd<'_>, name: &OsStr) -> Result<OwnedFd, Errno> {
    #[cfg(test)]
    super::dir::fault_after_mkdir(super::FaultStep::Open)?;
    rustix::fs::openat(parent, name, DIR_OPEN | OFlags::NOFOLLOW, Mode::empty())
}

/// Sets the mode `mode` on the new file `file` with `fchmod` if there is
/// one, writes `bytes` to it, and syncs the file with `fsync` if `fsync` is
/// set. The `fchmod` comes before the write, so the bytes are never readable
/// with a wider mode.
fn fill(mut file: File, bytes: &[u8], mode: Option<u32>, fsync: bool) -> Result<(), FsError> {
    if let Some(mode) = mode {
        rustix::fs::fchmod(&file, Mode::from_raw_mode(mode)).map_err(io_error)?;
    }
    file.write_all(bytes).map_err(FsError::Io)?;
    if fsync {
        rustix::fs::fsync(&file).map_err(io_error)?;
    }
    Ok(())
}

/// Refuses a relative `path` with a `..` component with
/// [`Reason::ParentDir`]. The check reads the text alone.
fn refuse_parent_dir(path: &Path) -> Result<(), FsError> {
    if path.is_relative() && path.components().any(|c| c == Component::ParentDir) {
        return Err(FsError::Invalid {
            path: path.display().to_string(),
            reason: Reason::ParentDir,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::io::Read;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::rc::Rc;

    use super::super::dir::list_fd;
    use super::super::temp::TEMP_PREFIX;
    use super::super::{
        FaultStep, HookPoint, TestDir, id_of, invalid, io_err, is_symlink, mkfifo, mode_of,
        names_with, record_syncs, reference_file_mode, reference_mode, set_faults, set_hook,
        take_synced, without_block,
    };
    use super::*;

    /// Returns the whole content of the file open at `fd`.
    fn content(fd: OwnedFd) -> Vec<u8> {
        let mut buf = Vec::new();
        File::from(fd).read_to_end(&mut buf).unwrap();
        buf
    }

    /// Returns the reason of an `Invalid` error at `path`.
    fn reason_at<T: std::fmt::Debug>(result: Result<T, FsError>, path: &str) -> Reason {
        let (p, reason) = invalid(result);
        assert_eq!(p, path);
        reason
    }

    /// Returns the path of an `Absent` error.
    fn absent<T: std::fmt::Debug>(result: Result<T, FsError>) -> String {
        match result {
            Err(FsError::Absent { path }) => path,
            other => panic!("{other:?}"),
        }
    }

    /// Returns the device and inode of the inode open at `fd`.
    fn id_of_fd(fd: BorrowedFd<'_>) -> (u64, u64) {
        let stat = stat_fd(fd).unwrap();
        (stat.dev, stat.ino)
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn open_named_resolves_a_relative_path_against_its_base_and_ignores_it_for_an_absolute_path() {
        let dir = TestDir::new("named-relative");
        let other = TestDir::new("named-relative-other");
        std::fs::create_dir(dir.path().join("keys")).unwrap();
        std::fs::write(dir.path().join("keys/a.pem"), b"a").unwrap();
        std::fs::write(other.path().join("b.pem"), b"b").unwrap();

        let fd = open_named(dir.fd(), Path::new("keys/a.pem"), Named::File).unwrap();
        assert_eq!(content(fd), b"a");
        let absolute = other.path().join("b.pem");
        let fd = open_named(dir.fd(), &absolute, Named::File).unwrap();
        assert_eq!(content(fd), b"b");
        let result = open_named(other.fd(), Path::new("keys/a.pem"), Named::File);
        assert_eq!(absent(result), "keys/a.pem");
    }

    #[test]
    fn open_named_refuses_a_dot_dot_component_by_the_text_alone() {
        let dir = TestDir::new("named-dot-dot");
        let keys = dir.path().join("keys");
        std::fs::create_dir_all(keys.join("sub")).unwrap();
        std::fs::write(keys.join("a.pem"), b"a").unwrap();
        std::fs::write(dir.path().join("x"), b"x").unwrap();
        let base = rustix::fs::open(&keys, DIR_OPEN, Mode::empty()).unwrap();

        for path in ["..", "../x", "../keys/a.pem", "sub/../a.pem", "../missing"] {
            for want in [Named::File, Named::Dir] {
                let reason = reason_at(open_named(base.as_fd(), Path::new(path), want), path);
                assert!(matches!(reason, Reason::ParentDir), "{path}: {reason:?}");
            }
        }
        let absolute = keys.join("sub/../a.pem");
        let fd = open_named(base.as_fd(), &absolute, Named::File).unwrap();
        assert_eq!(content(fd), b"a");
    }

    #[test]
    fn open_named_follows_a_symlink_at_each_component() {
        let dir = TestDir::new("named-symlink");
        let other = TestDir::new("named-symlink-other");
        let outside = TestDir::new("named-symlink-outside");
        std::fs::write(outside.path().join("file"), b"outside").unwrap();
        symlink(other.path(), dir.path().join("link")).unwrap();
        symlink(outside.path().join("file"), other.path().join("leaf")).unwrap();

        let fd = open_named(dir.fd(), Path::new("link/leaf"), Named::File).unwrap();
        assert_eq!(content(fd), b"outside");
        let absolute = dir.path().join("link/leaf");
        let fd = open_named(outside.fd(), &absolute, Named::File).unwrap();
        assert_eq!(content(fd), b"outside");
        let fd = open_named(dir.fd(), Path::new("link"), Named::Dir).unwrap();
        assert_eq!(id_of_fd(fd.as_fd()), id_of(other.path()));
    }

    #[test]
    fn open_named_refuses_a_fifo_without_a_block() {
        let dir = TestDir::new("named-fifo");
        let fifo = dir.path().join("fifo");
        mkfifo(&fifo);
        let _listener = UnixListener::bind(dir.path().join("sock")).unwrap();
        let base = rustix::io::dup(dir.fd()).unwrap();

        let [file, as_dir] = without_block(&fifo, move || {
            [Named::File, Named::Dir].map(|want| open_named(base.as_fd(), Path::new("fifo"), want))
        });
        let reason = reason_at(file, "fifo");
        assert!(
            matches!(reason, Reason::NotRegular(FileType::Fifo)),
            "{reason:?}"
        );
        let reason = reason_at(as_dir, "fifo");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");

        let reason = reason_at(open_named(dir.fd(), Path::new("sock"), Named::File), "sock");
        assert!(
            matches!(reason, Reason::NotRegular(FileType::Socket)),
            "{reason:?}"
        );
        let reason = reason_at(open_named(dir.fd(), Path::new("sock"), Named::Dir), "sock");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
    }

    #[test]
    fn open_named_opens_a_directory_for_named_dir() {
        let dir = TestDir::new("named-dir");
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("a"), b"a").unwrap();
        std::fs::write(sub.join("b"), b"b").unwrap();

        let fd = open_named(dir.fd(), Path::new("sub"), Named::Dir).unwrap();
        let mut names: Vec<Vec<u8>> = list_fd(fd.as_fd())
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        names.sort();
        assert_eq!(names, [b"a".to_vec(), b"b".to_vec()]);

        let reason = reason_at(open_named(dir.fd(), Path::new("sub"), Named::File), "sub");
        assert!(
            matches!(reason, Reason::NotRegular(FileType::Directory)),
            "{reason:?}"
        );
        let reason = reason_at(
            open_named(dir.fd(), Path::new("sub/a"), Named::Dir),
            "sub/a",
        );
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
        for want in [Named::File, Named::Dir] {
            let result = open_named(dir.fd(), Path::new("none/x"), want);
            assert_eq!(absent(result), "none/x");
            let missing = dir.path().join("none");
            assert_eq!(
                absent(open_named(dir.fd(), &missing, want)),
                missing.display().to_string()
            );
        }
    }

    #[test]
    fn put_named_keeps_the_mode_of_an_existing_file() {
        let dir = TestDir::new("named-put-mode");
        let path = dir.path().join("x.conf");
        std::fs::write(&path, b"old").unwrap();
        set_mode(&path, 0o640);
        let old = id_of(&path);
        let seen = Rc::new(RefCell::new(Vec::new()));
        let hook_seen = Rc::clone(&seen);
        let _hook = set_hook(HookPoint::TempName, move |name| {
            hook_seen
                .borrow_mut()
                .push(String::from_utf8(name.to_vec()).unwrap());
        });

        let result = put_named(dir.fd(), "x.conf", b"new", Publish::Replace, false);
        assert_eq!(result.unwrap(), Published::Created);
        assert_eq!(mode_of(&path), 0o640);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_ne!(id_of(&path), old);
        let seen = seen.borrow().clone();
        assert_eq!(seen.len(), 1, "{seen:?}");
        let suffix = seen[0]
            .strip_prefix(&format!("{TEMP_PREFIX}{}-", std::process::id()))
            .unwrap();
        assert_eq!(suffix.len(), 6, "{seen:?}");
        assert!(
            suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
            "{seen:?}"
        );
        assert!(names_with(dir.path(), TEMP_PREFIX).is_empty());

        set_mode(&path, 0o600);
        let result = put_named(dir.fd(), "x.conf", b"secret", Publish::Replace, false);
        assert_eq!(result.unwrap(), Published::Created);
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
    }

    #[test]
    fn put_named_replaces_a_symlink_and_keeps_its_target() {
        let dir = TestDir::new("named-put-link");
        let outside = TestDir::new("named-put-link-outside");
        let target = outside.path().join("target.conf");
        std::fs::write(&target, b"target").unwrap();
        set_mode(&target, 0o600);
        let path = dir.path().join("x.conf");
        symlink(&target, &path).unwrap();

        let result = put_named(dir.fd(), "x.conf", b"new", Publish::Replace, false);
        assert_eq!(result.unwrap(), Published::Created);
        assert!(!is_symlink(&path));
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(mode_of(&path), reference_file_mode(dir.path(), 0o666));
        assert_eq!(std::fs::read(&target).unwrap(), b"target");
        assert_eq!(mode_of(&target), 0o600);
    }

    #[test]
    fn put_named_makes_a_new_file_syncs_the_directory_and_leaves_no_temp_file() {
        let dir = TestDir::new("named-put-new");
        let _record = record_syncs();

        let result = put_named(dir.fd(), "a.conf", b"a", Publish::Replace, true);
        assert_eq!(result.unwrap(), Published::Created);
        assert_eq!(take_synced(), [id_of(dir.path())]);
        let path = dir.path().join("a.conf");
        assert_eq!(std::fs::read(&path).unwrap(), b"a");
        assert_eq!(mode_of(&path), reference_file_mode(dir.path(), 0o666));

        let result = put_named(dir.fd(), "b.conf", b"b", Publish::Replace, false);
        assert_eq!(result.unwrap(), Published::Created);
        assert!(take_synced().is_empty());
        assert!(names_with(dir.path(), TEMP_PREFIX).is_empty());

        let blocked = dir.path().join("d.conf");
        std::fs::create_dir_all(blocked.join("sub")).unwrap();
        let result = put_named(dir.fd(), "d.conf", b"d", Publish::Replace, true);
        assert!(matches!(result, Err(FsError::Io(_))), "{result:?}");
        assert!(take_synced().is_empty());
        assert!(blocked.join("sub").is_dir());
        assert!(names_with(dir.path(), TEMP_PREFIX).is_empty());
    }

    #[test]
    fn put_named_keep_existing_gives_existed_and_keeps_the_old_content() {
        for linkat in [false, true] {
            let dir = TestDir::new("named-put-keep");
            let path = dir.path().join("x.conf");
            std::fs::write(&path, b"old").unwrap();
            symlink("nowhere", dir.path().join("link.conf")).unwrap();
            let _linkat = set_faults(|f| f.no_rename_noreplace = linkat);
            let _record = record_syncs();
            let calls = Rc::new(Cell::new(0));
            let hook_calls = Rc::clone(&calls);
            let raced = dir.path().join("raced.conf");
            let mut plant = Some(raced.clone());
            // The first temp file name comes after the `statx` of the name,
            // so the file that the hook writes is a racing entry.
            let _hook = set_hook(HookPoint::TempName, move |_| {
                hook_calls.set(hook_calls.get() + 1);
                if let Some(plant) = plant.take() {
                    std::fs::write(plant, b"raced").unwrap();
                }
            });

            // An existing entry gives `Existed` with no temp file.
            for name in ["x.conf", "link.conf"] {
                let result = put_named(dir.fd(), name, b"new", Publish::KeepExisting, true);
                assert_eq!(result.unwrap(), Published::Existed, "{linkat} {name}");
            }
            assert_eq!(calls.get(), 0, "{linkat}");
            let result = put_named(dir.fd(), "raced.conf", b"new", Publish::KeepExisting, true);
            assert_eq!(result.unwrap(), Published::Existed, "{linkat}");
            assert_eq!(calls.get(), 1, "{linkat}");
            assert_eq!(std::fs::read(&raced).unwrap(), b"raced");
            assert!(take_synced().is_empty(), "{linkat}");
            assert_eq!(std::fs::read(&path).unwrap(), b"old");
            assert!(is_symlink(&dir.path().join("link.conf")), "{linkat}");
            assert!(names_with(dir.path(), TEMP_PREFIX).is_empty(), "{linkat}");

            let result = put_named(dir.fd(), "y.conf", b"new", Publish::KeepExisting, true);
            assert_eq!(result.unwrap(), Published::Created, "{linkat}");
            assert_eq!(take_synced(), [id_of(dir.path())], "{linkat}");
            assert_eq!(std::fs::read(dir.path().join("y.conf")).unwrap(), b"new");
            assert!(names_with(dir.path(), TEMP_PREFIX).is_empty(), "{linkat}");
        }
    }

    #[test]
    fn remove_named_gives_absent_for_an_absent_file() {
        let dir = TestDir::new("named-remove");
        let outside = TestDir::new("named-remove-outside");
        let target = outside.path().join("target");
        std::fs::write(&target, b"target").unwrap();
        let _record = record_syncs();

        assert_eq!(
            absent(remove_named(dir.fd(), "absent.conf", true)),
            "absent.conf"
        );
        assert!(take_synced().is_empty());

        let path = dir.path().join("x.conf");
        std::fs::write(&path, b"x").unwrap();
        remove_named(dir.fd(), "x.conf", true).unwrap();
        assert_eq!(take_synced(), [id_of(dir.path())]);
        assert!(!path.exists());

        let link = dir.path().join("link.conf");
        symlink(&target, &link).unwrap();
        remove_named(dir.fd(), "link.conf", false).unwrap();
        assert!(take_synced().is_empty());
        assert!(std::fs::symlink_metadata(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"target");

        std::fs::create_dir(dir.path().join("d.conf")).unwrap();
        let err = io_err(remove_named(dir.fd(), "d.conf", true));
        assert_eq!(err.raw_os_error(), Some(Errno::ISDIR.raw_os_error()));
        assert!(take_synced().is_empty());
        assert!(dir.path().join("d.conf").is_dir());
    }

    #[test]
    fn ensure_named_dir_makes_each_missing_component() {
        let dir = TestDir::new("named-ensure");
        let other = TestDir::new("named-ensure-other");
        let a = dir.path().join("a");
        let mode = RepoMode::BareUser;

        let fd = ensure_named_dir(dir.fd(), Path::new("a/b/c"), false, mode, false).unwrap();
        let c = a.join("b/c");
        assert_eq!(id_of_fd(fd.as_fd()), id_of(&c));
        assert_eq!(mode_of(&a), reference_mode(dir.path(), 0o777));
        assert_eq!(mode_of(&a.join("b")), reference_mode(&a, 0o777));
        assert_eq!(mode_of(&c), reference_mode(&a.join("b"), 0o777));
        std::fs::write(c.join("f"), b"f").unwrap();
        let names: Vec<Vec<u8>> = list_fd(fd.as_fd())
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(names, [b"f".to_vec()]);

        // An existing directory comes back as it is.
        set_mode(&c, 0o700);
        let fd = ensure_named_dir(dir.fd(), Path::new("a/b/c"), false, mode, false).unwrap();
        assert_eq!(id_of_fd(fd.as_fd()), id_of(&c));
        assert_eq!(mode_of(&c), 0o700);

        // The walk follows a symlink at a component.
        std::fs::create_dir(dir.path().join("real")).unwrap();
        symlink("real", dir.path().join("link")).unwrap();
        let fd = ensure_named_dir(dir.fd(), Path::new("link/x"), false, mode, false).unwrap();
        assert_eq!(id_of_fd(fd.as_fd()), id_of(&dir.path().join("real/x")));

        // An absolute path ignores the base, and can hold `..`.
        let absolute = dir.path().join("a/../abs/y");
        let fd = ensure_named_dir(other.fd(), &absolute, false, mode, false).unwrap();
        assert_eq!(id_of_fd(fd.as_fd()), id_of(&dir.path().join("abs/y")));

        // An error carries the whole path.
        std::fs::write(dir.path().join("file"), b"x").unwrap();
        let result = ensure_named_dir(dir.fd(), Path::new("file/x"), false, mode, false);
        let reason = reason_at(result, "file/x");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
        symlink("nowhere", dir.path().join("dangling")).unwrap();
        let result = ensure_named_dir(dir.fd(), Path::new("dangling/x"), false, mode, false);
        assert_eq!(absent(result), "dangling/x");
        assert!(!dir.path().join("nowhere").exists());
    }

    #[test]
    fn ensure_named_dir_forces_the_shared_mode_on_an_in_repo_directory_alone() {
        let dir = TestDir::new("named-ensure-shared");
        let existing = dir.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        set_mode(&existing, 0o700);
        let shared = RepoMode::BareUserShared;

        ensure_named_dir(dir.fd(), Path::new("existing/x/y"), true, shared, false).unwrap();
        assert_eq!(mode_of(&existing), 0o700);
        assert_eq!(mode_of(&existing.join("x")), 0o2770);
        assert_eq!(mode_of(&existing.join("x/y")), 0o2770);

        ensure_named_dir(dir.fd(), Path::new("outside"), false, shared, false).unwrap();
        let expected = reference_mode(dir.path(), 0o777);
        assert_eq!(mode_of(&dir.path().join("outside")), expected);
        ensure_named_dir(
            dir.fd(),
            Path::new("plain"),
            true,
            RepoMode::BareUser,
            false,
        )
        .unwrap();
        assert_eq!(mode_of(&dir.path().join("plain")), expected);

        for step in [FaultStep::Fchmod, FaultStep::Open] {
            let _fault = set_faults(|f| f.fail_after_mkdir = Some((step, Errno::IO)));
            let err = io_err(ensure_named_dir(
                dir.fd(),
                Path::new("fault"),
                true,
                shared,
                false,
            ));
            assert_eq!(
                err.raw_os_error(),
                Some(Errno::IO.raw_os_error()),
                "{step:?}"
            );
            assert!(!dir.path().join("fault").exists(), "{step:?}");
        }
    }

    #[test]
    fn ensure_named_dir_with_fsync_syncs_the_parent_of_each_new_component() {
        let dir = TestDir::new("named-ensure-sync");
        let a = dir.path().join("a");
        std::fs::create_dir(&a).unwrap();
        let mode = RepoMode::BareUser;
        let _record = record_syncs();

        ensure_named_dir(dir.fd(), Path::new("a/b/c"), false, mode, true).unwrap();
        assert_eq!(take_synced(), [id_of(&a), id_of(&a.join("b"))]);
        ensure_named_dir(dir.fd(), Path::new("a/b/c"), false, mode, true).unwrap();
        assert!(take_synced().is_empty());
        ensure_named_dir(dir.fd(), Path::new("a/b/d"), false, mode, false).unwrap();
        assert!(take_synced().is_empty());
        assert!(a.join("b/d").is_dir());
    }

    #[test]
    fn ensure_named_dir_refuses_a_dot_dot_in_a_relative_path() {
        let dir = TestDir::new("named-ensure-dot-dot");
        std::fs::create_dir(dir.path().join("a")).unwrap();
        let _record = record_syncs();
        for path in ["..", "../x", "a/../b", "a/..", "a/b/../../c"] {
            let result =
                ensure_named_dir(dir.fd(), Path::new(path), true, RepoMode::BareUser, true);
            let reason = reason_at(result, path);
            assert!(matches!(reason, Reason::ParentDir), "{path}: {reason:?}");
        }
        assert!(take_synced().is_empty());
        assert_eq!(names_with(dir.path(), ""), ["a"]);
        assert!(names_with(&dir.path().join("a"), "").is_empty());
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "put_named needs a name of one path component")]
    fn put_named_with_a_path_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-put-named");
        let _ = put_named(dir.fd(), "a/b", b"x", Publish::Replace, false);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "remove_named needs a name of one path component")]
    fn remove_named_with_a_path_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-remove-named");
        let _ = remove_named(dir.fd(), "..", false);
    }
}
