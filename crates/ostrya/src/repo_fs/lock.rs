//! The lock primitives: the open of a lock file, and the record lock on it.
//!
//! A lock is an `fcntl` record lock on the whole file, set with `F_SETLK`. The
//! record lock belongs to the process, and not to the descriptor. Thus the
//! close of any descriptor to the inode in the process drops each record lock
//! of the process on it, also the close of a descriptor that a second open
//! gave. A caller that examines a lock file while it holds the lock uses
//! [`lstat`](RepoDir::lstat) or [`exists`](RepoDir::exists): they open the
//! entry with `O_PATH`, and the close of an `O_PATH` descriptor drops no
//! record lock. The open of an existing lock file uses `O_NONBLOCK`, and the
//! create of a new lock file does not. That flag does not change `F_SETLK`,
//! which never waits.

use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::fs::{FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;

use super::dir::{BENEATH, io_error, require};
use super::{FsError, Reason, RepoDir, RepoLayout, RootFile};
use crate::lock::LockKind;

/// The flags of the open of an existing lock file. `O_RDWR` lets a caller
/// take an exclusive lock. `O_NOFOLLOW` refuses a symlink at the leaf, and
/// `O_NONBLOCK` keeps the open of a FIFO from waiting for a writer.
const LOCK_OPEN: OFlags = OFlags::RDWR
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

impl RepoDir {
    /// Opens the lock file `name` below this handle for read and write, and
    /// creates it if it is absent. The call is on the root handle or on the
    /// `tmp/` handle.
    ///
    /// The function first creates the file as
    /// [`create_exclusive`](RepoDir::create_exclusive) does, with the lock
    /// mode. On the root handle the lock mode is the mode of
    /// [`RootFile::Lock`], `0660`. On the `tmp/` handle it is the file mode of
    /// the kind, `0600`. In a `bare-user-shared` repository the mode is
    /// `0660` on both handles, and an `fchmod` forces it on a new file. An
    /// existing entry at `name`, also a symlink, makes the create give
    /// `EEXIST`. The function then opens the existing file as
    /// [`open_existing_lock`](RepoDir::open_existing_lock) does, with its
    /// errors. An existing file keeps its mode. If the existing file is gone
    /// before that open, the function runs the create and the open one more
    /// time, and then gives [`FsError::Absent`].
    ///
    /// The function syncs no directory. A record lock does not stay after a
    /// crash, so the lock file needs no sync.
    ///
    /// The lock on the file is a POSIX record lock that the process owns. The
    /// close of any descriptor of the process to the file drops each lock of
    /// the process on it. A lock that the process holds through another
    /// descriptor does not conflict, so [`try_lock`] on a second descriptor
    /// gives `true`. Thus a caller must not open and close a second
    /// descriptor to a lock file that the process can hold. It examines the
    /// file with [`lstat`](RepoDir::lstat) or [`exists`](RepoDir::exists).
    ///
    /// A call on a handle of another kind is a defect of the caller: it
    /// fails a debug assertion, and gives an `InvalidInput` error in a
    /// release build.
    pub(crate) fn open_lock(&self, name: &str) -> Result<OwnedFd, FsError> {
        let (plain, shared) =
            self.lock_modes("open_lock needs the root handle or the tmp handle")?;
        let mut again = true;
        loop {
            #[cfg(test)]
            super::dir::run_hook(super::HookPoint::LockCreate, name.as_bytes());
            match self.create_new(name, plain, shared, false) {
                Ok(file) => return Ok(OwnedFd::from(file)),
                Err(FsError::Exists) => {}
                Err(e) => return Err(e),
            }
            #[cfg(test)]
            super::dir::run_hook(super::HookPoint::LockOpen, name.as_bytes());
            match self.open_existing_lock(name) {
                Err(FsError::Absent { .. }) if again => again = false,
                other => return other,
            }
        }
    }

    /// Opens the existing lock file `name` below this handle for read and
    /// write. The function never creates the file. The call is on the root
    /// handle or on the `tmp/` handle.
    ///
    /// The open is one `openat2` with
    /// `O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY`. The path rules and the errors
    /// are those of [`open_regular`](RepoDir::open_regular): an absent file
    /// gives [`FsError::Absent`], a symlink gives [`Reason::Symlink`], and an
    /// entry that is not a regular file gives [`Reason::NotRegular`] with its
    /// type. A FIFO opens with no wait, and the `statx` on the descriptor
    /// refuses it. `O_RDWR` refuses a directory with `EISDIR`, which gives
    /// [`Reason::NotRegular`] too.
    ///
    /// The open needs write access, so a lock file in a read-only repository
    /// gives [`FsError::Io`] with `EACCES` or `EROFS`.
    ///
    /// The lock on the file is a POSIX record lock that the process owns. The
    /// close of any descriptor of the process to the file drops each lock of
    /// the process on it. A lock that the process holds through another
    /// descriptor does not conflict, so [`try_lock`] on a second descriptor
    /// gives `true`. Thus a caller must not open and close a second
    /// descriptor to a lock file that the process can hold. It examines the
    /// file with [`lstat`](RepoDir::lstat) or [`exists`](RepoDir::exists).
    ///
    /// A call on a handle of another kind is a defect of the caller: it
    /// fails a debug assertion, and gives an `InvalidInput` error in a
    /// release build.
    pub(crate) fn open_existing_lock(&self, name: &str) -> Result<OwnedFd, FsError> {
        self.lock_modes("open_existing_lock needs the root handle or the tmp handle")?;
        self.check_path(name)?;
        match rustix::fs::openat2(self, name, LOCK_OPEN, Mode::empty(), BENEATH) {
            Ok(fd) => self
                .finish(fd, name)
                .map(|opened| OwnedFd::from(opened.file)),
            Err(Errno::ISDIR) => Err(FsError::Invalid {
                path: self.err_path(name),
                reason: Reason::NotRegular(FileType::Directory),
            }),
            Err(e) => Err(self.open_error(e, name)),
        }
    }

    /// Returns the plain mode and the shared mode of a lock file below this
    /// handle. A handle other than the root and `tmp/` is a defect of the
    /// caller, and `what` states the rule.
    fn lock_modes(&self, what: &'static str) -> Result<(u32, u32), FsError> {
        let modes = match self.kind {
            RepoLayout::Root => Some((
                RootFile::Lock.file_mode(),
                RootFile::Lock.shared_file_mode(),
            )),
            RepoLayout::Tmp => {
                let rules = self.kind.rules();
                rules.file_mode.zip(rules.shared_file_mode)
            }
            _ => None,
        };
        require(modes, what)
    }
}

/// Takes the record lock `kind` on the whole file open at `fd` with `F_SETLK`,
/// and gives `true`. The function never waits.
///
/// `EAGAIN` and `EACCES` mean that another process holds a lock that
/// excludes `kind`, and give `false`. Each other error gives [`FsError::Io`]:
/// for example an exclusive lock on a descriptor that is not open for write
/// gives `EBADF`. A lock that the process holds on the file changes to
/// `kind`.
///
/// The lock is a POSIX record lock that the process owns. A lock that the
/// process holds through another descriptor to the file does not conflict,
/// so the function gives `true` on a second descriptor. The close of any
/// descriptor of the process to the file drops each lock of the process on
/// it. Thus a caller must not open and close a second descriptor to a lock
/// file that the process can hold. The module doc states the rules of a
/// record lock.
pub(crate) fn try_lock(fd: BorrowedFd<'_>, kind: LockKind) -> Result<bool, FsError> {
    let operation = match kind {
        LockKind::Shared => FlockOperation::NonBlockingLockShared,
        LockKind::Exclusive => FlockOperation::NonBlockingLockExclusive,
    };
    match rustix::fs::fcntl_lock(fd, operation) {
        Ok(()) => Ok(true),
        Err(Errno::AGAIN | Errno::ACCESS) => Ok(false),
        Err(e) => Err(io_error(e)),
    }
}

/// Releases the record lock of the process on the whole file open at `fd`.
/// An error gives [`FsError::Io`].
pub(crate) fn unlock(fd: BorrowedFd<'_>) -> Result<(), FsError> {
    rustix::fs::fcntl_lock(fd, FlockOperation::Unlock).map_err(io_error)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::rc::Rc;

    use ostrya_core::RepoMode;

    use super::super::{
        HookPoint, TestDir, id_of, invalid, io_err, mkfifo, mode_of, reference_file_mode, root,
        set_hook, stat_fd, without_block,
    };
    use super::*;

    /// The variable that names the directory of the child process of
    /// [`try_lock_gives_false_while_another_process_holds_the_lock`].
    const CHILD_DIR_ENV: &str = "OSTRYA_TEST_REPO_FS_LOCK_DIR";

    /// The variable that gives the state of the lock that the child process
    /// expects: `held` or `free`.
    const CHILD_EXPECT_ENV: &str = "OSTRYA_TEST_REPO_FS_LOCK_EXPECT";

    /// Returns the file type of a `NotRegular` error at `path`.
    fn not_regular<T: std::fmt::Debug>(result: Result<T, FsError>, path: &str) -> FileType {
        match invalid(result) {
            (p, Reason::NotRegular(file_type)) if p == path => file_type,
            other => panic!("{other:?}"),
        }
    }

    /// Returns the whole content of the file open at `fd`.
    fn content(fd: OwnedFd) -> Vec<u8> {
        let mut buf = Vec::new();
        File::from(fd).read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn open_lock_creates_the_file_with_the_lock_mode() {
        for mode in [None, Some(RepoMode::BareUserShared)] {
            let dir = TestDir::new("lock-create");
            let mut repo = root(&dir);
            if let Some(mode) = mode {
                repo = repo.with_repo_mode(mode);
            }
            let tmp = repo.tmp_dir(false).unwrap();
            let tmp_path = dir.path().join("tmp");
            let cases = [
                (&repo, ".lock", dir.path().to_owned(), 0o660),
                (&repo, ".update.lock", dir.path().to_owned(), 0o660),
                (&tmp, "staging-x-lock", tmp_path, 0o600),
            ];
            for (handle, name, parent, plain) in cases {
                let fd = handle.open_lock(name).unwrap();
                let expected = match mode {
                    Some(_) => 0o660,
                    None => reference_file_mode(&parent, plain),
                };
                let path = parent.join(name);
                assert_eq!(mode_of(&path), expected, "{mode:?} {name}");
                let stat = stat_fd(fd.as_fd()).unwrap();
                assert_eq!((stat.dev, stat.ino), id_of(&path), "{mode:?} {name}");
                assert!(try_lock(fd.as_fd(), LockKind::Exclusive).unwrap());
            }
        }
    }

    #[test]
    fn open_lock_opens_an_existing_regular_file_and_keeps_its_mode() {
        let dir = TestDir::new("lock-existing");
        let repo = root(&dir).with_repo_mode(RepoMode::BareUserShared);
        let path = dir.path().join(".lock");
        std::fs::write(&path, b"content").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let fd = repo.open_lock(".lock").unwrap();
        let stat = stat_fd(fd.as_fd()).unwrap();
        assert_eq!((stat.dev, stat.ino), id_of(&path));
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(content(fd), b"content");
        let fd = repo.open_existing_lock(".lock").unwrap();
        assert_eq!(content(fd), b"content");
    }

    #[test]
    fn open_lock_fails_for_a_symlink_a_fifo_a_socket_and_a_directory() {
        let dir = TestDir::new("lock-special");
        let other = TestDir::new("lock-special-other");
        let at = |name: &str| dir.path().join(name);
        let target = other.path().join("target");
        std::fs::write(&target, b"target").unwrap();
        symlink(&target, at("link.lock")).unwrap();
        symlink(other.path().join("missing"), at("dangling.lock")).unwrap();
        let fifo = at("fifo.lock");
        mkfifo(&fifo);
        let _listener = UnixListener::bind(at("sock.lock")).unwrap();
        std::fs::create_dir(at("dir.lock")).unwrap();
        let repo = root(&dir);

        for name in ["link.lock", "dangling.lock"] {
            for result in [repo.open_lock(name), repo.open_existing_lock(name)] {
                let (path, reason) = invalid(result);
                assert_eq!(path, name);
                assert!(matches!(reason, Reason::Symlink), "{name}: {reason:?}");
            }
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"target");
        assert!(!other.path().join("missing").exists());

        let handle = repo.clone();
        let results = without_block(&fifo, move || {
            [
                handle.open_lock("fifo.lock").map(drop),
                handle.open_existing_lock("fifo.lock").map(drop),
            ]
        });
        for result in results {
            assert_eq!(not_regular(result, "fifo.lock"), FileType::Fifo);
        }
        for (name, expected) in [
            ("sock.lock", FileType::Socket),
            ("dir.lock", FileType::Directory),
        ] {
            for result in [repo.open_lock(name), repo.open_existing_lock(name)] {
                assert_eq!(not_regular(result, name), expected, "{name}");
            }
        }
    }

    #[test]
    fn open_lock_creates_the_file_again_when_it_goes_after_the_create() {
        let dir = TestDir::new("lock-gone");
        let path = dir.path().join(".lock");
        let moved = dir.path().join("moved");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let calls = Rc::new(Cell::new(0));
        let hook_calls = Rc::clone(&calls);
        let (hook_path, hook_moved) = (path.clone(), moved.clone());
        // The move keeps the old inode, so the new file has another inode.
        let _hook = set_hook(HookPoint::LockOpen, move |name| {
            assert_eq!(name, b".lock");
            std::fs::rename(&hook_path, &hook_moved).unwrap();
            hook_calls.set(hook_calls.get() + 1);
        });

        let fd = root(&dir).open_lock(".lock").unwrap();
        assert_eq!(calls.get(), 1);
        let stat = stat_fd(fd.as_fd()).unwrap();
        assert_eq!((stat.dev, stat.ino), id_of(&path));
        assert_ne!(id_of(&path), id_of(&moved));
        assert_eq!(mode_of(&path), reference_file_mode(dir.path(), 0o660));
    }

    #[test]
    fn open_lock_gives_absent_when_the_file_goes_after_each_create() {
        let dir = TestDir::new("lock-gone-twice");
        let path = dir.path().join(".lock");
        let moved = dir.path().join("moved");
        let calls = Rc::new(Cell::new(0));
        let hook_calls = Rc::clone(&calls);
        let create_path = path.clone();
        let (hook_path, hook_moved) = (path.clone(), moved.clone());
        // Each create finds a file, and each open finds none.
        let _create = set_hook(HookPoint::LockCreate, move |_| {
            std::fs::write(&create_path, b"").unwrap();
        });
        let _open = set_hook(HookPoint::LockOpen, move |_| {
            std::fs::rename(&hook_path, &hook_moved).unwrap();
            hook_calls.set(hook_calls.get() + 1);
        });

        match root(&dir).open_lock(".lock") {
            Err(FsError::Absent { path: p }) => assert_eq!(p, ".lock"),
            other => panic!("{other:?}"),
        }
        assert_eq!(calls.get(), 2);
        assert!(!path.exists());
        assert!(moved.exists());
    }

    #[test]
    fn open_existing_lock_gives_absent_for_a_missing_file() {
        let dir = TestDir::new("lock-absent");
        let repo = root(&dir);
        let tmp = repo.tmp_dir(false).unwrap();
        for (handle, name, path) in [
            (&repo, ".lock", ".lock"),
            (&tmp, "staging-x-lock", "tmp/staging-x-lock"),
        ] {
            match handle.open_existing_lock(name) {
                Err(FsError::Absent { path: p }) => assert_eq!(p, path),
                other => panic!("{other:?}"),
            }
        }
        assert!(!dir.path().join(".lock").exists());
        assert!(!dir.path().join("tmp/staging-x-lock").exists());
    }

    #[test]
    fn try_lock_takes_and_unlock_releases_a_record_lock() {
        let dir = TestDir::new("lock-try");
        let fd = root(&dir).open_lock(".lock").unwrap();
        assert!(try_lock(fd.as_fd(), LockKind::Shared).unwrap());
        assert!(try_lock(fd.as_fd(), LockKind::Exclusive).unwrap());
        unlock(fd.as_fd()).unwrap();

        let read_only = rustix::fs::openat(
            dir.fd(),
            ".lock",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let err = io_err(try_lock(read_only.as_fd(), LockKind::Exclusive));
        assert_eq!(err.raw_os_error(), Some(Errno::BADF.raw_os_error()));
    }

    /// Runs [`lock_child_subprocess`] in a new process of this test binary,
    /// with the expectation `expect`, and checks that its test passed.
    fn run_child(dir: &Path, expect: &str) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "repo_fs::lock::tests::lock_child_subprocess",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD_DIR_ENV, dir)
            .env(CHILD_EXPECT_ENV, expect)
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .expect("re-execute this test binary");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "the child reported {}:\n{stdout}",
            output.status
        );
        assert!(dir.join(format!(".child-{expect}")).exists(), "{expect}");
    }

    #[test]
    fn try_lock_gives_false_while_another_process_holds_the_lock() {
        let dir = TestDir::new("lock-process");
        let repo = root(&dir);
        let fd = repo.open_lock(".lock").unwrap();
        assert!(try_lock(fd.as_fd(), LockKind::Exclusive).unwrap());
        // Each probe opens the entry with `O_PATH`. Its close keeps the lock.
        assert_eq!(
            repo.lstat(".lock").unwrap().file_type,
            FileType::RegularFile
        );
        assert!(repo.exists(".lock").unwrap());

        run_child(dir.path(), "held");
        unlock(fd.as_fd()).unwrap();
        run_child(dir.path(), "free");
    }

    /// The child half of
    /// [`try_lock_gives_false_while_another_process_holds_the_lock`].
    ///
    /// It runs only if this test binary runs again with [`CHILD_DIR_ENV`]
    /// set. It opens `.lock` in that directory, and expects `try_lock` to
    /// give `false` for each kind if [`CHILD_EXPECT_ENV`] is `held`, and
    /// `true` if it is `free`. It then writes `.child-<expectation>`.
    #[test]
    #[ignore = "helper process for try_lock_gives_false_while_another_process_holds_the_lock"]
    fn lock_child_subprocess() {
        let Some(path) = std::env::var_os(CHILD_DIR_ENV).map(PathBuf::from) else {
            return;
        };
        let expect = std::env::var(CHILD_EXPECT_ENV).unwrap();
        let free = match expect.as_str() {
            "held" => false,
            "free" => true,
            other => panic!("{other}"),
        };
        let repo = RepoDir::open_root(rustix::fs::CWD, &path).unwrap();
        let fd = repo.open_lock(".lock").unwrap();
        assert_eq!(try_lock(fd.as_fd(), LockKind::Shared).unwrap(), free);
        assert_eq!(try_lock(fd.as_fd(), LockKind::Exclusive).unwrap(), free);
        std::fs::write(path.join(format!(".child-{expect}")), b"1").unwrap();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "open_lock needs the root handle or the tmp handle")]
    fn open_lock_on_another_kind_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-lock");
        let refs = root(&dir).ensure_layout(RepoLayout::Refs, false).unwrap();
        let _ = refs.open_lock("x.lock");
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "open_existing_lock needs the root handle or the tmp handle")]
    fn open_existing_lock_on_another_kind_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-existing-lock");
        let refs = root(&dir).ensure_layout(RepoLayout::Refs, false).unwrap();
        let _ = refs.open_existing_lock("x.lock");
    }
}
