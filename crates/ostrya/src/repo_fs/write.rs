//! The other write primitives: the atomic write of a file, the exclusive
//! create of a file, the removal of a file, the hard link and the move of an
//! entry, and the reflink or copy of file content.
//!
//! Each primitive that takes a path below a [`RepoDir`] opens the parent
//! directory of the leaf with one `openat2` with
//! `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`, and then changes the leaf relative
//! to that descriptor. The path rules of the directory primitives apply: a
//! `..`, `.`, or empty component or an absolute path gives
//! [`Reason::Escape`] before each other call, and a symlink at a directory
//! component gives [`Reason::Symlink`]. No primitive follows a symlink at the
//! leaf. A path with more than one component costs one open of its parent
//! directory for each call. A caller that writes many entries into one
//! directory opens that directory one time and gives a path of one component.
//!
//! A primitive that changes the names in one directory takes `fsync`. With
//! `fsync`, it syncs that directory with `fsync` after the change.

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, BorrowedFd};

use rustix::fs::{AtFlags, Mode};
use rustix::io::Errno;

use super::dir::{BENEATH, fchmod_new, fsync_dir, io_error, is_component, require};
use super::temp::{NAMED_OPEN, created, open_parent, place_named};
use super::{FsError, Publish, Published, Reason, RepoDir, RepoLayout, RootFile, TempFile};

/// The way that [`clone_or_copy`] filled a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cloned {
    /// A `FICLONE` reflink shares the extents of the source file.
    Reflinked,
    /// A copy wrote the bytes of the source file.
    Copied,
}

impl RepoDir {
    /// Writes `bytes` to the file at `path` below this directory in one
    /// atomic step, by the rule `how`, and gives the result.
    ///
    /// The function first checks `path`, so a refused path makes no temp
    /// file. It then writes `bytes` to a new [`TempFile`], sets the file mode
    /// of the kind of this directory with `fchmod`, and publishes the file at
    /// `path` with [`TempFile::publish`]. In a `bare-user-shared` repository
    /// the mode is the shared file mode of the kind. `path` can have more
    /// than one component, and its parent directory must exist.
    ///
    /// For [`Publish::Replace`], the temp file is a named file
    /// `.ostrya-tmp-<pid>-XXXXXX` in the temp home, from
    /// [`TempFile::create_named`]. The publish moves it with one `renameat`.
    /// For [`Publish::KeepExisting`], the temp file is the file of
    /// [`TempFile::create`]: an anonymous `O_TMPFILE` file that the publish
    /// links into place, or a named file where the file system has no
    /// `O_TMPFILE`.
    ///
    /// The caller holds all of `bytes` in memory, so the function is for
    /// metadata whose size the format caps. File content whose size the
    /// format does not cap goes through a temp file in chunks of bounded size.
    ///
    /// With `fsync`, the function syncs the file before the publish, and the
    /// publish syncs the parent directory after [`Published::Created`].
    ///
    /// The errors are those of [`TempFile::create`] and
    /// [`TempFile::publish`]. [`TempFile::create_named`] gives the errors of
    /// the named file of [`TempFile::create`]. An error of the write gives
    /// [`FsError::Io`]. A
    /// kind with no file mode is a defect of the caller: it fails a debug
    /// assertion, and gives an `InvalidInput` error in a release build.
    pub(crate) fn write_atomic(
        &self,
        path: &str,
        bytes: &[u8],
        how: Publish,
        fsync: bool,
    ) -> Result<Published, FsError> {
        self.check_path(path)?;
        let mode = require(
            self.file_mode(),
            "write_atomic needs a kind with a file mode",
        )?;
        self.write_temp(path, bytes, mode, how, fsync)
    }

    /// Writes `bytes` to the root file `file` in one atomic step, by the rule
    /// `how`, and gives the result. The call is on the root handle.
    ///
    /// The steps, the temp file of each [`Publish`] rule, the sync, and the
    /// errors are those of [`write_atomic`](RepoDir::write_atomic). The temp
    /// file is in `tmp/`.
    /// The mode is the mode of `file`, or its shared mode in a
    /// `bare-user-shared` repository.
    ///
    /// [`Publish::Replace`] puts a regular file at the name of `file`. A
    /// symlink at the name, such as a keyring symlink, is replaced, and its
    /// target keeps its content. [`Publish::KeepExisting`] keeps an existing
    /// entry at the name, for example the `config` of an existing repository.
    ///
    /// A [`RootFile::Keyring`] name that is not one path component gives
    /// [`Reason::Escape`] before each other call.
    ///
    /// A call on a handle other than the root, and a call for
    /// [`RootFile::Lock`] or [`RootFile::UpdateLock`], are defects of the
    /// caller: a new file at the name of a lock does not hold the lock of
    /// the old file. Each fails a debug assertion, and gives an
    /// `InvalidInput` error in a release build.
    pub(crate) fn write_root_file(
        &self,
        file: RootFile,
        bytes: &[u8],
        how: Publish,
        fsync: bool,
    ) -> Result<Published, FsError> {
        require(
            (self.kind == RepoLayout::Root).then_some(()),
            "write_root_file needs the root handle",
        )?;
        require(
            (!matches!(file, RootFile::Lock | RootFile::UpdateLock)).then_some(()),
            "write_root_file never writes a lock file",
        )?;
        if let RootFile::Keyring(name) = &file
            && !is_component(name.as_bytes())
        {
            return Err(FsError::Invalid {
                path: self.err_path(name),
                reason: Reason::Escape,
            });
        }
        let name = file.name();
        self.check_path(name)?;
        let mode = if self.ctx.is_shared() {
            file.shared_file_mode()
        } else {
            file.file_mode()
        };
        self.write_temp(name, bytes, mode, how, fsync)
    }

    /// Creates a new regular file at `path` below this directory, and gives
    /// it open for read and write.
    ///
    /// The create is one `openat2` with `O_CREAT|O_EXCL|O_NOFOLLOW` relative
    /// to the parent directory. An existing entry at `path`, also a symlink,
    /// gives [`FsError::Exists`], so the create never follows a symlink. The
    /// mode of the create request is the file mode of the kind of this
    /// directory, and the umask reduces it. In a `bare-user-shared`
    /// repository the request is the shared file mode of the kind, and an
    /// `fchmod` then forces that mode. If the `fchmod` fails, the function
    /// removes the new file and gives [`FsError::Io`].
    ///
    /// With `fsync`, the function syncs the parent directory after the
    /// create. If the sync fails, the function removes the new file and
    /// gives [`FsError::Io`].
    ///
    /// The open of the parent directory gives the errors of
    /// [`open_dir`](RepoDir::open_dir): a missing parent gives
    /// [`FsError::Absent`] with the path of the parent. The errno of the
    /// create maps by [`FsError::at`] with `path`. A kind with no file mode
    /// is a defect of the caller: it fails a debug assertion, and gives an
    /// `InvalidInput` error in a release build.
    pub(crate) fn create_exclusive(&self, path: &str, fsync: bool) -> Result<File, FsError> {
        let rules = self.kind.rules();
        let (plain, shared) = require(
            rules.file_mode.zip(rules.shared_file_mode),
            "create_exclusive needs a kind with a file mode",
        )?;
        self.create_new(path, plain, shared, fsync)
    }

    /// Creates a new regular file at `path` below this directory, and gives
    /// it open for read and write. The rules are those of
    /// [`create_exclusive`](RepoDir::create_exclusive), with the mode
    /// `plain` in place of the file mode of the kind, and the mode `shared`
    /// in place of its shared file mode.
    pub(super) fn create_new(
        &self,
        path: &str,
        plain: u32,
        shared: u32,
        fsync: bool,
    ) -> Result<File, FsError> {
        self.check_path(path)?;
        let (parent, leaf) = open_parent(self, path)?;
        let at = parent.as_ref().map_or(self.as_fd(), AsFd::as_fd);
        let is_shared = self.ctx.is_shared();
        let request = if is_shared { shared & 0o777 } else { plain };
        let fd = rustix::fs::openat2(at, leaf, NAMED_OPEN, Mode::from_raw_mode(request), BENEATH)
            .map_err(|e| match e {
            Errno::EXIST => FsError::Exists,
            e => FsError::at(e, self.err_path(path)),
        })?;
        if is_shared && let Err(e) = fchmod_new(fd.as_fd(), shared) {
            let _ = rustix::fs::unlinkat(at, leaf, AtFlags::empty());
            return Err(io_error(e));
        }
        if fsync && let Err(e) = fsync_dir(at) {
            let _ = rustix::fs::unlinkat(at, leaf, AtFlags::empty());
            return Err(io_error(e));
        }
        Ok(File::from(fd))
    }

    /// Unlinks the entry at `path` below this directory, and gives `true`. An
    /// absent entry or an absent parent directory gives `false`.
    ///
    /// The unlink is one `unlinkat` relative to the parent directory. A
    /// symlink at `path` is unlinked, and its target stays. A directory at
    /// `path` gives [`FsError::Io`] with `EISDIR`. Each other errno of the
    /// unlink maps by [`FsError::at`] with `path`. A symlink at a directory
    /// component gives [`Reason::Symlink`] with the path of the parent, as
    /// [`open_dir`](RepoDir::open_dir) gives it.
    ///
    /// With `fsync`, the function syncs the parent directory after the
    /// unlink. A result of `false` syncs nothing.
    pub(crate) fn remove_file(&self, path: &str, fsync: bool) -> Result<bool, FsError> {
        self.check_path(path)?;
        let (parent, leaf) = match open_parent(self, path) {
            Ok(opened) => opened,
            Err(FsError::Absent { .. }) => return Ok(false),
            Err(e) => return Err(e),
        };
        let at = parent.as_ref().map_or(self.as_fd(), AsFd::as_fd);
        match rustix::fs::unlinkat(at, leaf, AtFlags::empty()) {
            Ok(()) => {
                if fsync {
                    fsync_dir(at).map_err(io_error)?;
                }
                Ok(true)
            }
            Err(Errno::NOENT) => Ok(false),
            Err(e) => Err(FsError::at(e, self.err_path(path))),
        }
    }

    /// Writes `bytes` to a new temp file, sets the mode `mode`, and publishes
    /// the file at `path` by the rule `how`. With `fsync`, the function syncs
    /// the file before the publish. The caller checks `path`.
    ///
    /// [`Publish::Replace`] writes a named temp file, which the publish moves
    /// with one `renameat`. [`Publish::KeepExisting`] writes the file of
    /// [`TempFile::create`].
    fn write_temp(
        &self,
        path: &str,
        bytes: &[u8],
        mode: u32,
        how: Publish,
        fsync: bool,
    ) -> Result<Published, FsError> {
        let mut temp = match how {
            Publish::Replace => TempFile::create_named(self)?,
            Publish::KeepExisting => TempFile::create(self)?,
        };
        temp.file_mut().write_all(bytes).map_err(FsError::Io)?;
        temp.set_mode(mode)?;
        if fsync {
            temp.sync()?;
        }
        temp.publish(self, path, how, fsync)
    }
}

/// Hard-links the entry at `src_path` below `src` to the name `dst_name` in
/// the directory open at `dst`, and gives the result.
///
/// The link is one `linkat` with no flag from the parent directory of
/// `src_path`, so a symlink at `src_path` is linked as the symlink itself. An
/// existing entry at `dst_name` stays, and the function gives
/// [`Published::Existed`]. The function applies no mode.
///
/// `src_path` follows the path rules of [`open_dir`](RepoDir::open_dir), and
/// the open of its parent directory gives the errors of that function. A
/// `dst_name` that is not one path component gives [`Reason::Escape`] with
/// `dst_name` as the path. Each other error of the link gives
/// [`FsError::Io`] with its errno, also `ENOENT` and `EXDEV`. Thus a caller
/// can read `EXDEV` for a link across two file systems.
///
/// With `fsync`, the function syncs `dst` after [`Published::Created`].
/// [`Published::Existed`] syncs nothing.
pub(crate) fn link(
    src: &RepoDir,
    src_path: &str,
    dst: BorrowedFd<'_>,
    dst_name: &str,
    fsync: bool,
) -> Result<Published, FsError> {
    src.check_path(src_path)?;
    if !is_component(dst_name.as_bytes()) {
        return Err(FsError::Invalid {
            path: dst_name.to_owned(),
            reason: Reason::Escape,
        });
    }
    let (parent, leaf) = open_parent(src, src_path)?;
    let at = parent.as_ref().map_or(src.as_fd(), AsFd::as_fd);
    match rustix::fs::linkat(at, leaf, dst, dst_name, AtFlags::empty()) {
        Ok(()) => created(dst, fsync),
        Err(Errno::EXIST) => Ok(Published::Existed),
        Err(e) => Err(io_error(e)),
    }
}

/// Moves the entry at `src_path` below `src` to `dst_path` below `dst` by the
/// rule `how`, and gives the result.
///
/// The move is the placement of a named temp entry in
/// [`TempFile::publish`]. [`Publish::Replace`] calls `renameat`, and always
/// gives [`Published::Created`]. [`Publish::KeepExisting`] calls `renameat2`
/// with `RENAME_NOREPLACE`. Where the file system refuses that flag, a
/// `linkat` puts the entry at `dst_path`, and the function then unlinks
/// `src_path`. The function ignores an error of that unlink, because the
/// entry is in place. [`Published::Existed`] keeps the entry at `src_path`.
/// A symlink at `src_path` moves as the symlink itself. The `linkat` cannot
/// link a directory, so on such a file system [`Publish::KeepExisting`]
/// moves a file or a symlink alone, and a directory at `src_path` gives
/// [`FsError::Io`] with `EPERM`.
///
/// If `src_path` and `dst_path` are hard links to the same inode, `renameat`
/// changes nothing and succeeds. [`Publish::Replace`] then gives
/// [`Published::Created`], and the entry at `src_path` stays.
///
/// Both paths follow the path rules of [`open_dir`](RepoDir::open_dir), and
/// the opens of their parent directories give the errors of that function.
/// Each error of the move gives [`FsError::Io`] with its errno, also
/// `ENOENT` and `EXDEV`.
///
/// With `fsync`, the function syncs the parent directory of `dst_path` after
/// [`Published::Created`]. It does not sync the parent directory of
/// `src_path`.
pub(crate) fn rename(
    src: &RepoDir,
    src_path: &str,
    dst: &RepoDir,
    dst_path: &str,
    how: Publish,
    fsync: bool,
) -> Result<Published, FsError> {
    src.check_path(src_path)?;
    dst.check_path(dst_path)?;
    let (src_parent, src_leaf) = open_parent(src, src_path)?;
    let (dst_parent, dst_leaf) = open_parent(dst, dst_path)?;
    let from = src_parent.as_ref().map_or(src.as_fd(), AsFd::as_fd);
    let to = dst_parent.as_ref().map_or(dst.as_fd(), AsFd::as_fd);
    let mut name = Some(src_leaf.to_owned());
    let placed = place_named(from, &mut name, to, dst_leaf, how, false)?;
    if placed == Published::Existed {
        return Ok(placed);
    }
    // The name stays after a link put the entry in place.
    if let Some(name) = name.as_deref() {
        let _ = rustix::fs::unlinkat(from, name, AtFlags::empty());
    }
    created(to, fsync)
}

/// Fills the empty file `dst` with the whole content of `src`, and gives the
/// way.
///
/// `src` is open for read, and `dst` is open for write. The function first
/// calls the `FICLONE` reflink. Where the file system gives `EOPNOTSUPP`,
/// `EXDEV`, or `EINVAL`, the function sets the position of `src` to the start
/// and copies the bytes with [`std::io::copy`]. The copy writes at the
/// position of `dst`. Between two files, the copy uses `copy_file_range` or
/// `sendfile` where the kernel supports them, and else a stack buffer of
/// fixed size. Thus the content does not go into memory as a whole.
///
/// Each other errno of the reflink gives [`FsError::Io`], and the function
/// makes no copy. An error of the copy gives [`FsError::Io`], and `dst` can
/// then hold a part of the content. The errors have no path.
///
/// The positions of `src` and `dst` after the call are not defined.
pub(crate) fn clone_or_copy(src: &File, dst: &File) -> Result<Cloned, FsError> {
    match reflink(dst.as_fd(), src.as_fd()) {
        Ok(()) => Ok(Cloned::Reflinked),
        Err(Errno::OPNOTSUPP | Errno::XDEV | Errno::INVAL) => {
            let (mut src, mut dst) = (src, dst);
            src.seek(SeekFrom::Start(0)).map_err(FsError::Io)?;
            io::copy(&mut src, &mut dst).map_err(FsError::Io)?;
            Ok(Cloned::Copied)
        }
        Err(e) => Err(io_error(e)),
    }
}

/// Shares the extents of `src` with `dst` with the `FICLONE` reflink.
fn reflink(dst: BorrowedFd<'_>, src: BorrowedFd<'_>) -> Result<(), Errno> {
    #[cfg(test)]
    if let Some(errno) = super::FAULTS.with(|faults| faults.borrow().reflink_error) {
        return Err(errno);
    }
    rustix::fs::ioctl_ficlone(dst, src)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::{OpenOptionsExt, symlink};
    use std::path::Path;
    use std::rc::Rc;

    use ostrya_core::RepoMode;
    use rustix::fs::OFlags;

    use super::super::{
        FaultStep, HookPoint, TestDir, id_of, invalid, io_err, is_symlink, mode_of, names_with,
        record_syncs, refs, root, set_faults, set_hook, take_synced, temp_names,
    };
    use super::*;

    /// The paths that each primitive refuses with `Escape`.
    const ESCAPES: [&str; 11] = [
        "..",
        "../x",
        "heads/../x",
        "heads/..",
        "/etc/passwd",
        "/",
        "",
        "heads//x",
        "./heads",
        "heads/.",
        "heads/",
    ];

    /// Opens the directory at `path`.
    fn open_dir_fd(path: &Path) -> OwnedFd {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    /// Makes the directory `out` in `dir`, and returns its path and a
    /// descriptor of it.
    fn out_dir(dir: &TestDir) -> (std::path::PathBuf, OwnedFd) {
        let path = dir.path().join("out");
        std::fs::create_dir(&path).unwrap();
        let fd = open_dir_fd(&path);
        (path, fd)
    }

    /// Makes the file `name` in `dir` with the content `data`, and returns it
    /// open for read and write. The position is at the end of the content.
    fn file_with(dir: &TestDir, name: &str, data: &[u8]) -> File {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.path().join(name))
            .unwrap();
        file.write_all(data).unwrap();
        file
    }

    /// Returns `len` bytes of a fixed pattern.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Returns the raw errno of an `Io` error.
    fn errno_of<T: std::fmt::Debug>(result: Result<T, FsError>) -> Option<i32> {
        io_err(result).raw_os_error()
    }

    /// Returns `true` if no entry is at `path`, with no follow.
    fn is_gone(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_err()
    }

    #[test]
    fn write_atomic_writes_the_bytes_with_the_mode_of_the_kind_and_syncs_the_parent() {
        for named in [false, true] {
            let dir = TestDir::new("write-atomic");
            let refs = refs(&dir);
            let heads = dir.path().join("refs/heads");
            let _named = set_faults(|f| f.no_tmpfile = named);
            let _record = record_syncs();

            let result = refs.write_atomic("heads/main", b"first", Publish::Replace, true);
            assert_eq!(result.unwrap(), Published::Created, "{named}");
            assert_eq!(take_synced(), [id_of(&heads)], "{named}");
            assert_eq!(std::fs::read(heads.join("main")).unwrap(), b"first");
            assert_eq!(mode_of(&heads.join("main")), 0o644, "{named}");

            let result = refs.write_atomic("heads/main", b"second", Publish::Replace, true);
            assert_eq!(result.unwrap(), Published::Created, "{named}");
            assert_eq!(take_synced(), [id_of(&heads)], "{named}");
            assert_eq!(std::fs::read(heads.join("main")).unwrap(), b"second");

            // A path of one component goes in the directory of the handle.
            // With no `fsync`, the write syncs nothing.
            let result = refs.write_atomic("top", b"top", Publish::Replace, false);
            assert_eq!(result.unwrap(), Published::Created, "{named}");
            assert!(take_synced().is_empty(), "{named}");
            assert_eq!(std::fs::read(dir.path().join("refs/top")).unwrap(), b"top");
            assert!(temp_names(&dir).is_empty(), "{named}");
        }
    }

    #[test]
    fn write_atomic_keep_existing_gives_existed_and_keeps_the_old_content() {
        for named in [false, true] {
            let dir = TestDir::new("write-keep");
            let refs = refs(&dir);
            let heads = dir.path().join("refs/heads");
            std::fs::write(heads.join("main"), b"old").unwrap();
            let _named = set_faults(|f| f.no_tmpfile = named);
            let _record = record_syncs();

            let result = refs.write_atomic("heads/main", b"new", Publish::KeepExisting, true);
            assert_eq!(result.unwrap(), Published::Existed, "{named}");
            assert!(take_synced().is_empty(), "{named}");
            assert_eq!(std::fs::read(heads.join("main")).unwrap(), b"old");
            assert!(temp_names(&dir).is_empty(), "{named}");

            let result = refs.write_atomic("heads/other", b"new", Publish::KeepExisting, true);
            assert_eq!(result.unwrap(), Published::Created, "{named}");
            assert_eq!(take_synced(), [id_of(&heads)], "{named}");
            assert_eq!(std::fs::read(heads.join("other")).unwrap(), b"new");
        }
    }

    #[test]
    fn replace_writes_a_named_temp_file_and_keep_existing_an_anonymous_one() {
        let dir = TestDir::new("write-placement");
        let refs = refs(&dir);
        let repo = root(&dir);
        let names = Rc::new(RefCell::new(Vec::new()));
        let hook_names = Rc::clone(&names);
        let _names = set_hook(HookPoint::TempName, move |name| {
            hook_names
                .borrow_mut()
                .push(String::from_utf8(name.to_vec()).unwrap());
        });
        let tmpfiles = Rc::new(Cell::new(0));
        let hook_tmpfiles = Rc::clone(&tmpfiles);
        let _tmpfiles = set_hook(HookPoint::Tmpfile, move |_| {
            hook_tmpfiles.set(hook_tmpfiles.get() + 1);
        });
        // Returns the temp names and the `O_TMPFILE` opens since the last call.
        let take = || {
            (
                std::mem::take(&mut *names.borrow_mut()),
                tmpfiles.replace(0),
            )
        };

        let result = refs.write_atomic("heads/main", b"a", Publish::Replace, false);
        assert_eq!(result.unwrap(), Published::Created);
        let (drawn, opens) = take();
        assert_eq!((drawn.len(), opens), (1, 0), "{drawn:?}");
        assert!(drawn[0].starts_with(super::super::temp::TEMP_PREFIX));
        assert!(temp_names(&dir).is_empty());

        let result = repo.write_root_file(RootFile::Summary, b"s", Publish::Replace, false);
        assert_eq!(result.unwrap(), Published::Created);
        let (drawn, opens) = take();
        assert_eq!((drawn.len(), opens), (1, 0), "{drawn:?}");
        assert!(temp_names(&dir).is_empty());

        let result = refs.write_atomic("heads/other", b"b", Publish::KeepExisting, false);
        assert_eq!(result.unwrap(), Published::Created);
        assert_eq!(take(), (Vec::new(), 1));

        let result = repo.write_root_file(RootFile::Config, b"c", Publish::KeepExisting, false);
        assert_eq!(result.unwrap(), Published::Created);
        assert_eq!(take(), (Vec::new(), 1));
        assert!(temp_names(&dir).is_empty());
    }

    #[test]
    fn write_atomic_in_bare_user_shared_forces_the_shared_file_mode() {
        for (mode, expected) in [
            (RepoMode::BareUserShared, 0o640),
            (RepoMode::BareUser, 0o644),
        ] {
            let dir = TestDir::new("write-shared");
            let repo = root(&dir).with_repo_mode(mode);
            let deltas = repo.ensure_layout(RepoLayout::Deltas, false).unwrap();
            let result = deltas.write_atomic("superblock", b"x", Publish::Replace, false);
            assert_eq!(result.unwrap(), Published::Created, "{mode:?}");
            let path = dir.path().join("deltas/superblock");
            assert_eq!(mode_of(&path), expected, "{mode:?}");
        }
    }

    #[test]
    fn write_root_file_replaces_a_keyring_symlink_and_keeps_its_target() {
        let dir = TestDir::new("write-keyring");
        std::fs::create_dir(dir.path().join("keys")).unwrap();
        let target = dir.path().join("keys/real.gpg");
        std::fs::write(&target, b"target").unwrap();
        let keyring = dir.path().join("origin.trustedkeys.gpg");
        symlink("keys/real.gpg", &keyring).unwrap();
        let repo = root(&dir);
        let _named = set_faults(|f| f.no_tmpfile = true);

        // A hook plants an entry at the first temp name in `tmp/`. The create
        // then draws a second name, so the temp file is in `tmp/`.
        let tmp_path = dir.path().join("tmp");
        let hook_tmp = tmp_path.clone();
        let seen = Rc::new(RefCell::new(Vec::new()));
        let hook_seen = Rc::clone(&seen);
        let _hook = set_hook(HookPoint::TempName, move |name| {
            let name = String::from_utf8(name.to_vec()).unwrap();
            if hook_seen.borrow().is_empty() {
                std::fs::write(hook_tmp.join(&name), b"planted").unwrap();
            }
            hook_seen.borrow_mut().push(name);
        });
        let _record = record_syncs();

        let file = RootFile::Keyring("origin.trustedkeys.gpg".into());
        let result = repo.write_root_file(file, b"new", Publish::Replace, true);
        assert_eq!(result.unwrap(), Published::Created);
        assert_eq!(take_synced(), [id_of(dir.path())]);
        let seen = seen.borrow().clone();
        assert_eq!(seen.len(), 2, "{seen:?}");
        let planted = tmp_path.join(&seen[0]);
        assert_eq!(std::fs::read(&planted).unwrap(), b"planted");
        std::fs::remove_file(planted).unwrap();
        assert!(temp_names(&dir).is_empty());

        assert!(!is_symlink(&keyring));
        assert_eq!(std::fs::read(&keyring).unwrap(), b"new");
        assert_eq!(mode_of(&keyring), 0o644);
        assert_eq!(std::fs::read(&target).unwrap(), b"target");
    }

    #[test]
    fn write_root_file_keep_existing_keeps_an_existing_config() {
        let dir = TestDir::new("write-config");
        let repo = root(&dir);
        let config = dir.path().join("config");
        let _record = record_syncs();

        let result = repo.write_root_file(RootFile::Config, b"first", Publish::KeepExisting, true);
        assert_eq!(result.unwrap(), Published::Created);
        assert_eq!(take_synced(), [id_of(dir.path())]);
        assert_eq!(std::fs::read(&config).unwrap(), b"first");
        assert_eq!(mode_of(&config), 0o644);

        let result = repo.write_root_file(RootFile::Config, b"second", Publish::KeepExisting, true);
        assert_eq!(result.unwrap(), Published::Existed);
        assert!(take_synced().is_empty());
        assert_eq!(std::fs::read(&config).unwrap(), b"first");
        assert!(temp_names(&dir).is_empty());
    }

    #[test]
    fn create_exclusive_gives_exists_for_an_existing_entry_and_does_not_follow_a_symlink() {
        let dir = TestDir::new("create-exclusive");
        let refs = refs(&dir);
        let heads = dir.path().join("refs/heads");

        let mut file = refs.create_exclusive("heads/new", false).unwrap();
        file.write_all(b"data").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"data");
        // The umask reduces the mode of the request, as for each other file.
        let reference = heads.join(".reference");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&reference)
            .unwrap();
        assert_eq!(mode_of(&heads.join("new")), mode_of(&reference));

        assert!(matches!(
            refs.create_exclusive("heads/new", false),
            Err(FsError::Exists)
        ));
        assert_eq!(std::fs::read(heads.join("new")).unwrap(), b"data");

        symlink("../../missing", heads.join("dangling")).unwrap();
        assert!(matches!(
            refs.create_exclusive("heads/dangling", false),
            Err(FsError::Exists)
        ));
        assert!(is_gone(&dir.path().join("missing")));
        assert!(is_symlink(&heads.join("dangling")));

        std::fs::write(dir.path().join("target"), b"target").unwrap();
        symlink("../../target", heads.join("link")).unwrap();
        assert!(matches!(
            refs.create_exclusive("heads/link", false),
            Err(FsError::Exists)
        ));
        assert_eq!(std::fs::read(dir.path().join("target")).unwrap(), b"target");

        match refs.create_exclusive("heads/missing/new", false) {
            Err(FsError::Absent { path }) => assert_eq!(path, "refs/heads/missing"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn create_exclusive_forces_the_shared_mode_and_removes_the_file_when_the_fchmod_fails() {
        let dir = TestDir::new("create-shared");
        let repo = root(&dir).with_repo_mode(RepoMode::BareUserShared);
        let tmp = repo.tmp_dir(false).unwrap();
        let tmp_path = dir.path().join("tmp");
        tmp.create_exclusive("one", false).unwrap();
        assert_eq!(mode_of(&tmp_path.join("one")), 0o660);

        let _fault = set_faults(|f| f.fail_after_mkdir = Some((FaultStep::Fchmod, Errno::IO)));
        let _record = record_syncs();
        let result = tmp.create_exclusive("two", true);
        assert_eq!(errno_of(result), Some(Errno::IO.raw_os_error()));
        assert!(is_gone(&tmp_path.join("two")));
        assert!(take_synced().is_empty());
    }

    #[test]
    fn create_exclusive_with_fsync_syncs_the_parent() {
        let dir = TestDir::new("create-sync");
        let refs = refs(&dir);
        let heads = dir.path().join("refs/heads");
        let _record = record_syncs();

        refs.create_exclusive("heads/a", true).unwrap();
        assert_eq!(take_synced(), [id_of(&heads)]);
        refs.create_exclusive("top", true).unwrap();
        assert_eq!(take_synced(), [id_of(&dir.path().join("refs"))]);
        refs.create_exclusive("heads/b", false).unwrap();
        assert!(take_synced().is_empty());
        assert!(matches!(
            refs.create_exclusive("heads/a", true),
            Err(FsError::Exists)
        ));
        assert!(take_synced().is_empty());
    }

    #[test]
    fn remove_file_gives_false_for_an_absent_file_and_syncs_the_parent() {
        let dir = TestDir::new("remove-file");
        let refs = refs(&dir);
        let heads = dir.path().join("refs/heads");
        let _record = record_syncs();

        assert!(!refs.remove_file("heads/absent", true).unwrap());
        assert!(!refs.remove_file("heads/no-dir/absent", true).unwrap());
        assert!(take_synced().is_empty());

        std::fs::write(heads.join("main"), b"x").unwrap();
        assert!(refs.remove_file("heads/main", true).unwrap());
        assert_eq!(take_synced(), [id_of(&heads)]);
        assert!(is_gone(&heads.join("main")));

        std::fs::write(heads.join("other"), b"x").unwrap();
        assert!(refs.remove_file("heads/other", false).unwrap());
        assert!(take_synced().is_empty());
        assert!(is_gone(&heads.join("other")));
    }

    #[test]
    fn remove_file_unlinks_a_symlink_and_keeps_its_target() {
        let dir = TestDir::new("remove-link");
        let refs = refs(&dir);
        let heads = dir.path().join("refs/heads");
        std::fs::write(dir.path().join("target"), b"target").unwrap();
        symlink("../../target", heads.join("link")).unwrap();

        assert!(refs.remove_file("heads/link", false).unwrap());
        assert!(is_gone(&heads.join("link")));
        assert_eq!(std::fs::read(dir.path().join("target")).unwrap(), b"target");
    }

    #[test]
    fn remove_file_of_a_directory_gives_eisdir() {
        let dir = TestDir::new("remove-dir");
        let refs = refs(&dir);
        let _record = record_syncs();
        let result = refs.remove_file("heads", true);
        assert_eq!(errno_of(result), Some(Errno::ISDIR.raw_os_error()));
        assert!(dir.path().join("refs/heads").is_dir());
        assert!(take_synced().is_empty());
    }

    #[test]
    fn link_keep_existing_gives_created_then_existed() {
        let dir = TestDir::new("link");
        let refs = refs(&dir);
        let heads = dir.path().join("refs/heads");
        let (out_path, out) = out_dir(&dir);
        std::fs::write(heads.join("a"), b"a").unwrap();
        std::fs::write(heads.join("c"), b"c").unwrap();
        let _record = record_syncs();

        let result = link(&refs, "heads/a", out.as_fd(), "b", true);
        assert_eq!(result.unwrap(), Published::Created);
        assert_eq!(take_synced(), [id_of(&out_path)]);
        assert_eq!(id_of(&heads.join("a")), id_of(&out_path.join("b")));

        let result = link(&refs, "heads/c", out.as_fd(), "b", true);
        assert_eq!(result.unwrap(), Published::Existed);
        assert!(take_synced().is_empty());
        assert_eq!(std::fs::read(out_path.join("b")).unwrap(), b"a");

        let result = link(&refs, "heads/absent", out.as_fd(), "d", true);
        assert_eq!(errno_of(result), Some(Errno::NOENT.raw_os_error()));
        assert!(take_synced().is_empty());
        assert!(is_gone(&out_path.join("d")));
    }

    #[test]
    fn link_links_a_symlink_itself() {
        let dir = TestDir::new("link-symlink");
        let refs = refs(&dir);
        let heads = dir.path().join("refs/heads");
        let (out_path, out) = out_dir(&dir);
        symlink("nowhere", heads.join("link")).unwrap();

        let result = link(&refs, "heads/link", out.as_fd(), "copy", false);
        assert_eq!(result.unwrap(), Published::Created);
        let copy = out_path.join("copy");
        assert!(is_symlink(&copy));
        assert_eq!(std::fs::read_link(&copy).unwrap(), Path::new("nowhere"));
        assert_eq!(id_of(&copy), id_of(&heads.join("link")));
    }

    #[test]
    fn rename_keep_existing_gives_created_then_existed_and_keeps_the_source() {
        for linkat in [false, true] {
            let dir = TestDir::new("rename-keep");
            let repo = root(&dir);
            let refs = repo.ensure_layout(RepoLayout::Refs, false).unwrap();
            let tmp = repo.tmp_dir(false).unwrap();
            let heads = dir.path().join("refs/heads");
            let staged = dir.path().join("tmp/staged");
            let _linkat = set_faults(|f| f.no_rename_noreplace = linkat);
            let _record = record_syncs();

            std::fs::write(&staged, b"first").unwrap();
            let id = id_of(&staged);
            let result = rename(
                &tmp,
                "staged",
                &refs,
                "heads/main",
                Publish::KeepExisting,
                true,
            );
            assert_eq!(result.unwrap(), Published::Created, "{linkat}");
            assert_eq!(take_synced(), [id_of(&heads)], "{linkat}");
            assert!(is_gone(&staged), "{linkat}");
            assert_eq!(id_of(&heads.join("main")), id, "{linkat}");

            std::fs::write(&staged, b"second").unwrap();
            let result = rename(
                &tmp,
                "staged",
                &refs,
                "heads/main",
                Publish::KeepExisting,
                true,
            );
            assert_eq!(result.unwrap(), Published::Existed, "{linkat}");
            assert!(take_synced().is_empty(), "{linkat}");
            assert_eq!(std::fs::read(&staged).unwrap(), b"second", "{linkat}");
            assert_eq!(std::fs::read(heads.join("main")).unwrap(), b"first");
        }
    }

    #[test]
    fn rename_replace_replaces_the_entry() {
        let dir = TestDir::new("rename-replace");
        let repo = root(&dir);
        let refs = repo.ensure_layout(RepoLayout::Refs, false).unwrap();
        let tmp = repo.tmp_dir(false).unwrap();
        let heads = dir.path().join("refs/heads");
        let staged = dir.path().join("tmp/staged");
        std::fs::write(heads.join("main"), b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        let _record = record_syncs();

        let result = rename(&tmp, "staged", &refs, "heads/main", Publish::Replace, true);
        assert_eq!(result.unwrap(), Published::Created);
        assert_eq!(take_synced(), [id_of(&heads)]);
        assert!(is_gone(&staged));
        assert_eq!(std::fs::read(heads.join("main")).unwrap(), b"new");

        let result = rename(&tmp, "staged", &refs, "heads/main", Publish::Replace, true);
        assert_eq!(errno_of(result), Some(Errno::NOENT.raw_os_error()));
        assert!(take_synced().is_empty());
    }

    #[test]
    fn clone_or_copy_gives_the_same_bytes_with_no_reflink() {
        let data = pattern(1024 * 1024 + 7);
        for errno in [Errno::OPNOTSUPP, Errno::XDEV, Errno::INVAL] {
            let dir = TestDir::new("copy");
            let mut src = file_with(&dir, "src", &data);
            src.seek(SeekFrom::Start(100)).unwrap();
            let dst = file_with(&dir, "dst", b"");
            let _fault = set_faults(|f| f.reflink_error = Some(errno));
            assert_eq!(
                clone_or_copy(&src, &dst).unwrap(),
                Cloned::Copied,
                "{errno:?}"
            );
            assert!(
                std::fs::read(dir.path().join("dst")).unwrap() == data,
                "{errno:?}"
            );
        }
    }

    #[test]
    fn clone_or_copy_reflinks_where_the_file_system_supports_it() {
        let dir = TestDir::new("reflink");
        let data = pattern(64 * 1024 + 3);
        let src = file_with(&dir, "src", &data);
        let probe = file_with(&dir, "probe", b"");
        let dst = file_with(&dir, "dst", b"");
        let result = clone_or_copy(&src, &dst);
        match rustix::fs::ioctl_ficlone(&probe, &src) {
            Ok(()) => assert_eq!(result.unwrap(), Cloned::Reflinked),
            Err(e @ (Errno::OPNOTSUPP | Errno::XDEV | Errno::INVAL)) => {
                assert_eq!(result.unwrap(), Cloned::Copied);
                eprintln!("skipping the reflink part: the file system has no FICLONE: {e}");
            }
            Err(e) => panic!("the probe of FICLONE gave {e}, and the copy gave {result:?}"),
        }
        assert!(std::fs::read(dir.path().join("dst")).unwrap() == data);
    }

    #[test]
    fn clone_or_copy_gives_io_and_no_copy_for_another_errno() {
        let dir = TestDir::new("copy-error");
        let src = file_with(&dir, "src", b"content");
        let dst = file_with(&dir, "dst", b"");
        let _fault = set_faults(|f| f.reflink_error = Some(Errno::PERM));
        let result = clone_or_copy(&src, &dst);
        assert_eq!(errno_of(result), Some(Errno::PERM.raw_os_error()));
        assert_eq!(dst.metadata().unwrap().len(), 0);
    }

    #[test]
    fn each_write_primitive_refuses_an_escape_and_a_symlinked_parent() {
        let dir = TestDir::new("write-escape");
        let refs = refs(&dir);
        let heads = dir.path().join("refs/heads");
        let (out_path, out) = out_dir(&dir);
        std::fs::write(heads.join("x"), b"x").unwrap();
        let _record = record_syncs();

        let each = |path: &str| -> [Result<(), FsError>; 6] {
            [
                refs.write_atomic(path, b"new", Publish::Replace, true)
                    .map(drop),
                refs.create_exclusive(path, true).map(drop),
                refs.remove_file(path, true).map(drop),
                link(&refs, path, out.as_fd(), "y", true).map(drop),
                rename(&refs, path, &refs, "heads/y", Publish::Replace, true).map(drop),
                rename(&refs, "heads/x", &refs, path, Publish::Replace, true).map(drop),
            ]
        };
        for path in ESCAPES {
            for (at, result) in each(path).into_iter().enumerate() {
                let (err_path, reason) = invalid(result);
                assert_eq!(err_path, refs.err_path(path), "{path:?} #{at}");
                assert!(
                    matches!(reason, Reason::Escape),
                    "{path:?} #{at}: {reason:?}"
                );
            }
        }
        // The check of the path comes before the temp file of a write.
        assert!(is_gone(&dir.path().join("tmp")));
        for name in ["", ".", "..", "a/b", "/y"] {
            let (err_path, reason) = invalid(link(&refs, "heads/x", out.as_fd(), name, true));
            assert_eq!(err_path, name);
            assert!(matches!(reason, Reason::Escape), "{name:?}: {reason:?}");
        }

        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("x"), b"outside").unwrap();
        symlink(&real, heads.join("link")).unwrap();
        for (at, result) in each("heads/link/x").into_iter().enumerate() {
            let (err_path, reason) = invalid(result);
            assert_eq!(err_path, "refs/heads/link", "#{at}");
            assert!(matches!(reason, Reason::Symlink), "#{at}: {reason:?}");
        }
        assert!(take_synced().is_empty());
        assert_eq!(std::fs::read(real.join("x")).unwrap(), b"outside");
        assert_eq!(names_with(&real, ""), ["x"]);
        assert!(names_with(&out_path, "").is_empty());
        assert_eq!(std::fs::read(heads.join("x")).unwrap(), b"x");

        // A named temp file is in `tmp/`, and the refused publish removes it.
        let _named = set_faults(|f| f.no_tmpfile = true);
        let seen = Rc::new(RefCell::new(0));
        let hook_seen = Rc::clone(&seen);
        let _hook = set_hook(HookPoint::TempName, move |_| *hook_seen.borrow_mut() += 1);
        let result = refs.write_atomic("heads/link/x", b"new", Publish::Replace, true);
        let (err_path, reason) = invalid(result);
        assert_eq!(err_path, "refs/heads/link");
        assert!(matches!(reason, Reason::Symlink), "{reason:?}");
        assert_eq!(*seen.borrow(), 1);
        assert!(take_synced().is_empty());
        assert!(temp_names(&dir).is_empty());
        assert_eq!(names_with(&real, ""), ["x"]);
    }

    #[test]
    fn write_root_file_refuses_a_keyring_name_that_is_not_one_component() {
        let dir = TestDir::new("write-keyring-escape");
        let repo = root(&dir);
        std::fs::create_dir(dir.path().join("a")).unwrap();
        for name in ["a/b", "..", ".", ""] {
            let file = RootFile::Keyring(name.into());
            let result = repo.write_root_file(file, b"new", Publish::Replace, false);
            let (err_path, reason) = invalid(result);
            assert_eq!(err_path, repo.err_path(name), "{name:?}");
            assert!(matches!(reason, Reason::Escape), "{name:?}: {reason:?}");
        }
        assert!(is_gone(&dir.path().join("a/b")));
        assert!(is_gone(&dir.path().join("tmp")));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "write_root_file needs the root handle")]
    fn write_root_file_on_another_handle_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-root-file");
        let refs = refs(&dir);
        let _ = refs.write_root_file(RootFile::Config, b"x", Publish::Replace, false);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "write_root_file never writes a lock file")]
    fn write_root_file_of_a_lock_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-lock");
        let _ = root(&dir).write_root_file(RootFile::UpdateLock, b"x", Publish::Replace, false);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "write_atomic needs a kind with a file mode")]
    fn write_atomic_on_a_kind_with_no_file_mode_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-write");
        let objects = root(&dir)
            .ensure_layout(RepoLayout::Objects, false)
            .unwrap();
        let _ = objects.write_atomic("x", b"x", Publish::Replace, false);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "create_exclusive needs a kind with a file mode")]
    fn create_exclusive_on_a_kind_with_no_file_mode_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-create");
        let objects = root(&dir)
            .ensure_layout(RepoLayout::Objects, false)
            .unwrap();
        let _ = objects.create_exclusive("x", false);
    }
}
