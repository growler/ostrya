//! The repository handle and the options of an open and of a new repository.
//!
//! [`Repo`] is the handle. [`Repo::open`] opens a repository, and
//! [`Repo::create`] creates one with [`CreateOptions`]. [`OpenOptions`] opens
//! a repository with options. [`RemotesDir`] names the remotes directory of a
//! handle.

use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ostrya_core::{KeyFile, RepoMode};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::access::{AuthItem, ClientAccess, ReadAccess};
use crate::config::{EX_OSTRYA, MinFreeSpace, REMOTES_CONFIG_DIR, RepoConfig};
use crate::error::{Error, Result};
use crate::lock::{self, LockGuard, LockKind, RepoLock, UpdateLock, UpdateLockHeld, UpdateLocks};
use crate::perm;
use crate::remotes_dir;
use crate::staging::StagingDir;
use crate::transaction::Transaction;

/// The path of the config file in a repository.
const CONFIG: &str = "config";

/// The largest `config` file that a read accepts, in bytes. A read refuses a
/// larger file with [`Error::InvalidFormat`].
pub(crate) const MAX_CONFIG_SIZE: u64 = 1024 * 1024;

/// The mode that a directory create requests. The process umask reduces it.
const DIR_MODE: u32 = 0o775;

/// The mode that a create forces on the config file. The umask does not
/// change it.
const CONFIG_MODE: u32 = 0o644;

/// The directories of a repository, in an order that puts each parent before
/// its children.
const LAYOUT_DIRS: &[&str] = &[
    "objects",
    "tmp",
    "tmp/cache",
    "refs",
    "refs/heads",
    "refs/remotes",
    "refs/mirrors",
    "state",
    "extensions",
];

/// The remotes directory of a repository handle: a directory of `.conf` files
/// that hold remotes.
///
/// The open reads the directory into the snapshot of [`Repo::config`] and
/// keeps no descriptor of it. Each later access resolves the value again, so
/// a directory that does not exist at the open can come into existence later.
/// The remote calls of an [`UpdateGuard`](crate::UpdateGuard) write the
/// `.conf` files of the directory. An add creates the directory of a
/// [`Path`](RemotesDir::Path) or an [`InRepo`](RemotesDir::InRepo) value if
/// it is absent.
///
/// A clone of a [`Fd`](RemotesDir::Fd) value shares one descriptor.
#[derive(Debug, Clone)]
pub enum RemotesDir {
    /// A path. A relative path is relative to the working directory of the
    /// process at each access.
    Path(PathBuf),
    /// A descriptor of the directory. Each access uses it with `openat`.
    ///
    /// The value owns the descriptor. A caller that keeps its descriptor
    /// gives a duplicate.
    Fd(Arc<OwnedFd>),
    /// A path relative to the repository directory. Each access resolves it
    /// with `openat` on the descriptor of the repository directory.
    InRepo(PathBuf),
}

impl RemotesDir {
    /// Creates a [`Path`](RemotesDir::Path) value.
    pub fn path(path: impl Into<PathBuf>) -> RemotesDir {
        RemotesDir::Path(path.into())
    }

    /// Refuses a value that an open and a create do not take: an empty path,
    /// a path that holds a NUL byte, and an absolute
    /// [`InRepo`](RemotesDir::InRepo) path.
    fn check(&self) -> Result<()> {
        match self {
            RemotesDir::Path(path) | RemotesDir::InRepo(path)
                if path.as_os_str().as_bytes().contains(&0) =>
            {
                Err(Error::InvalidInput(format!(
                    "the remotes directory path {} holds a NUL byte",
                    path.display()
                )))
            }
            RemotesDir::Path(path) if path.as_os_str().is_empty() => Err(Error::InvalidInput(
                "the remotes directory path is empty".into(),
            )),
            RemotesDir::InRepo(path) if path.as_os_str().is_empty() => Err(Error::InvalidInput(
                "the in-repository remotes directory path is empty".into(),
            )),
            RemotesDir::InRepo(path) if path.is_absolute() => Err(Error::InvalidInput(format!(
                "the in-repository remotes directory path {} is absolute",
                path.display()
            ))),
            _ => Ok(()),
        }
    }
}

impl From<PathBuf> for RemotesDir {
    /// Gives a [`Path`](RemotesDir::Path) value.
    fn from(path: PathBuf) -> RemotesDir {
        RemotesDir::Path(path)
    }
}

impl From<OwnedFd> for RemotesDir {
    /// Gives a [`Fd`](RemotesDir::Fd) value that owns `fd`.
    fn from(fd: OwnedFd) -> RemotesDir {
        RemotesDir::Fd(Arc::new(fd))
    }
}

/// The options of an open of a repository.
///
/// [`Repo::open`] and [`Repo::open_at`] open with the default options.
///
/// # Remotes directory
///
/// The open selects the remotes directory of the handle in this order:
///
/// 1. [`remotes_dir`](OpenOptions::remotes_dir);
/// 2. the key `[ex-ostrya] remotes-config-dir` of `config`;
/// 3. [`default_remotes_dir`](OpenOptions::default_remotes_dir);
/// 4. no remotes directory.
///
/// No option turns off the key. An absolute value of the key gives a
/// [`Path`](RemotesDir::Path) value. A relative value gives an
/// [`InRepo`](RemotesDir::InRepo) value, relative to the repository
/// directory. The open refuses an empty value, also when an option comes
/// before the key.
///
/// [`Repo::remotes_dir`] gives the selected value.
///
/// The open detects no system repository, so it reads `/etc/ostree/remotes.d`
/// only when an option or the key names that directory. The `ostree` command
/// uses `/etc/ostree/remotes.d` as the remotes directory of the system
/// repository, the directory of `/ostree/repo`. A program for an ostree host
/// gives `RemotesDir::path("/etc/ostree/remotes.d")` for that repository.
///
/// The open reads the `.conf` files of the selected directory into
/// [`Repo::config`]:
///
/// - It reads each entry whose name ends in `.conf`, in the byte order of the
///   names. The match is case-sensitive. A name that starts with `.` is read.
/// - It follows a symlink. It skips each entry that is not a regular file
///   after the symlink, and it does not read a subdirectory. A symlink to an
///   absent file is skipped. Each other failure of the symlink, such as a
///   loop, fails the open.
/// - It takes the `[remote "<name>"]` groups of each file and ignores each
///   other group.
/// - An absent directory, or an absent parent of it, gives no remotes.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> ostrya::Result<()> {
/// use ostrya::repo::{OpenOptions, RemotesDir};
///
/// let repo = OpenOptions::new()
///     .remotes_dir(RemotesDir::path("/etc/myapp/remotes.d"))
///     .open("/srv/repo".as_ref())
///     .await?;
/// assert!(repo.remotes_dir().is_some());
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    remotes_dir: Option<RemotesDir>,
    default_remotes_dir: Option<RemotesDir>,
}

impl OpenOptions {
    /// Creates the options of an open with no remotes directory.
    pub fn new() -> Self {
        OpenOptions::default()
    }

    /// Sets the remotes directory of the handle. This value comes before
    /// [`default_remotes_dir`](OpenOptions::default_remotes_dir).
    pub fn remotes_dir(mut self, dir: RemotesDir) -> Self {
        self.remotes_dir = Some(dir);
        self
    }

    /// Sets the remotes directory of the handle when no other source gives
    /// one.
    pub fn default_remotes_dir(mut self, dir: RemotesDir) -> Self {
        self.default_remotes_dir = Some(dir);
        self
    }

    /// Refuses a remotes directory value that the open does not take.
    fn check(&self) -> Result<()> {
        for dir in [&self.remotes_dir, &self.default_remotes_dir]
            .into_iter()
            .flatten()
        {
            dir.check()?;
        }
        Ok(())
    }

    /// Opens the repository at `path`, relative to the current working
    /// directory.
    ///
    /// [`Repo::open`] describes the handle.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if a remotes directory value is an empty
    ///   path, a path that holds a NUL byte, or an absolute
    ///   [`InRepo`](RemotesDir::InRepo) path. The call checks the values
    ///   before it opens a file.
    /// - [`Error::Io`] if `path` is not a directory, if it has no `objects`
    ///   directory or no `config` file, or if a read fails.
    /// - [`Error::InvalidFormat`] if `config` is larger than 1 MiB (1048576
    ///   bytes) or is not valid UTF-8.
    /// - [`Error::InvalidFormat`] if the `[core]` group of `config` fails the
    ///   checks of [`RepoConfig::from_keyfile`].
    /// - [`Error::Core`] if `config` is not a valid key file, or if a `[core]`
    ///   value that [`RepoConfig::from_keyfile`] reads does not parse.
    /// - [`Error::InvalidFormat`] if `[ex-ostrya] remotes-config-dir` is
    ///   empty or holds a NUL byte, and [`Error::Core`] if it holds a
    ///   malformed escape sequence.
    /// - [`Error::Io`] if the remotes directory is not a directory, or if it
    ///   or one of its `.conf` files cannot be read. The message starts with
    ///   the path of the directory or of the file. A
    ///   [`Path`](RemotesDir::Path) value gives the path as given, and an
    ///   [`InRepo`](RemotesDir::InRepo) value the path relative to the
    ///   repository. A [`Fd`](RemotesDir::Fd) value gives the name of a file,
    ///   and `.` for the directory.
    /// - [`Error::InvalidFormat`] if a `.conf` file is larger than 1 MiB, if
    ///   its name or its content is not valid UTF-8, or if it is not a valid
    ///   key file. The message names the file.
    /// - [`Error::InvalidFormat`] if `config` and a `.conf` file, or two
    ///   `.conf` files, define one remote name.
    pub async fn open(&self, path: &Path) -> Result<Repo> {
        self.check()?;
        let opts = self.clone();
        let path = path.to_owned();
        let stored = path.clone();
        let materials =
            ostrya_rt::unblock(move || open_materials(rustix::fs::CWD, &path, false, &opts))
                .await?;
        Ok(Repo::assemble(materials, stored))
    }

    /// Opens the repository at `path`, relative to the directory `dir`.
    ///
    /// [`Repo::open_at`] describes the handle.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if a remotes directory value is an empty
    ///   path, a path that holds a NUL byte, or an absolute
    ///   [`InRepo`](RemotesDir::InRepo) path. The call checks the values
    ///   before it opens a file.
    /// - [`Error::Io`] if the call cannot duplicate `dir`.
    /// - [`Error::Io`] if `path` is not a directory, if it has no `objects`
    ///   directory or no `config` file, or if a read fails.
    /// - [`Error::InvalidFormat`] if `config` is larger than 1 MiB (1048576
    ///   bytes) or is not valid UTF-8.
    /// - [`Error::InvalidFormat`] if the `[core]` group of `config` fails the
    ///   checks of [`RepoConfig::from_keyfile`].
    /// - [`Error::Core`] if `config` is not a valid key file, or if a `[core]`
    ///   value that [`RepoConfig::from_keyfile`] reads does not parse.
    /// - [`Error::InvalidFormat`] if `[ex-ostrya] remotes-config-dir` is
    ///   empty or holds a NUL byte, and [`Error::Core`] if it holds a
    ///   malformed escape sequence.
    /// - [`Error::Io`] if the remotes directory is not a directory, or if it
    ///   or one of its `.conf` files cannot be read. The message starts with
    ///   the path of the directory or of the file. A
    ///   [`Path`](RemotesDir::Path) value gives the path as given, and an
    ///   [`InRepo`](RemotesDir::InRepo) value the path relative to the
    ///   repository. A [`Fd`](RemotesDir::Fd) value gives the name of a file,
    ///   and `.` for the directory.
    /// - [`Error::InvalidFormat`] if a `.conf` file is larger than 1 MiB, if
    ///   its name or its content is not valid UTF-8, or if it is not a valid
    ///   key file. The message names the file.
    /// - [`Error::InvalidFormat`] if `config` and a `.conf` file, or two
    ///   `.conf` files, define one remote name.
    pub async fn open_at(&self, dir: BorrowedFd<'_>, path: &Path) -> Result<Repo> {
        self.check()?;
        let opts = self.clone();
        let dir = dir.try_clone_to_owned()?;
        let path = path.to_owned();
        let stored = path.clone();
        let materials =
            ostrya_rt::unblock(move || open_materials(&dir, &path, false, &opts)).await?;
        Ok(Repo::assemble(materials, stored))
    }
}

/// The options of a new repository.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> ostrya::Result<()> {
/// use ostrya::repo::{CreateOptions, RemotesDir};
/// use ostrya::RepoMode;
///
/// let repo = CreateOptions::new(RepoMode::Archive)
///     .collection_id("org.example.Os")
///     .remotes_dir(RemotesDir::path("/etc/myapp/remotes.d"))
///     .create("/srv/repo".as_ref())
///     .await?;
/// assert_eq!(repo.mode(), RepoMode::Archive);
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct CreateOptions {
    mode: RepoMode,
    collection_id: Option<String>,
    remotes_dir: Option<RemotesDir>,
}

impl Default for CreateOptions {
    /// Gives the options of a [`Bare`](RepoMode::Bare) repository, with no
    /// collection id and no remotes directory.
    fn default() -> Self {
        CreateOptions::new(RepoMode::Bare)
    }
}

impl CreateOptions {
    /// Creates the options of a repository of `mode`, with no collection id
    /// and no remotes directory.
    ///
    /// The create writes `mode` to `[core] mode`.
    pub fn new(mode: RepoMode) -> Self {
        CreateOptions {
            mode,
            collection_id: None,
            remotes_dir: None,
        }
    }

    /// Sets the collection id. The create writes it to
    /// `[core] collection-id`. The create refuses an id that holds a line
    /// break.
    pub fn collection_id(mut self, id: impl Into<String>) -> Self {
        self.collection_id = Some(id.into());
        self
    }

    /// Sets the remotes directory of the repository.
    ///
    /// The create writes nothing into the directory. It writes the key
    /// `[ex-ostrya] remotes-config-dir` into the new `config`:
    ///
    /// - A [`Path`](RemotesDir::Path) value writes the absolute form of the
    ///   path, from [`std::path::absolute`]. That call needs no existing
    ///   directory and resolves no symlink.
    /// - An [`InRepo`](RemotesDir::InRepo) value writes its path as given.
    /// - A [`Fd`](RemotesDir::Fd) value writes no key.
    ///
    /// A create over an existing `config` writes no key. The handle that a
    /// create returns holds `dir` in each case, and
    /// [`Repo::remotes_dir`] gives it. The create reads the remotes of the
    /// directory, as an open does.
    ///
    /// With no value, the handle takes the remotes directory that the key of
    /// an existing `config` names, as [`OpenOptions`] describes.
    pub fn remotes_dir(mut self, dir: RemotesDir) -> Self {
        self.remotes_dir = Some(dir);
        self
    }

    /// Creates and opens a repository at `path`, relative to the working
    /// directory.
    ///
    /// The call is idempotent. [`Repo::create`] describes the layout that it
    /// writes.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if the remotes directory value is an empty
    ///   path, a path that holds a NUL byte, or an absolute
    ///   [`InRepo`](RemotesDir::InRepo) path, or if the value of the key is
    ///   not valid UTF-8. The call checks the value before it writes.
    /// - [`Error::InvalidInput`] if the collection id holds a line break. The
    ///   call checks the id before it writes.
    /// - [`Error::Io`] if the call cannot make the absolute form of a
    ///   [`Path`](RemotesDir::Path) value.
    /// - [`Error::Io`] if the parent directory of `path` does not exist, or if
    ///   `path`, `objects`, `tmp`, or `refs` exists and is not a directory.
    /// - [`Error::Io`] if a create, a write, or a read fails.
    /// - [`Error::InvalidFormat`] if an existing `config` is larger than 1 MiB
    ///   (1048576 bytes) or is not valid UTF-8.
    /// - [`Error::InvalidFormat`] if the `[core]` group of an existing `config`
    ///   fails the checks of [`RepoConfig::from_keyfile`].
    /// - [`Error::Core`] if an existing `config` is not a valid key file, or if
    ///   a `[core]` value that [`RepoConfig::from_keyfile`] reads does not
    ///   parse.
    /// - The errors of [`OpenOptions::open`] for the key
    ///   `[ex-ostrya] remotes-config-dir`, the remotes directory, and its
    ///   `.conf` files. The call reads them after it writes the layout and
    ///   `config`, so a refusal leaves the new repository on disk.
    pub async fn create(&self, path: &Path) -> Result<Repo> {
        self.check()?;
        let opts = self.clone();
        let path = path.to_owned();
        let stored = path.clone();
        let materials =
            ostrya_rt::unblock(move || create_materials(rustix::fs::CWD, &path, &opts)).await?;
        Ok(Repo::assemble(materials, stored))
    }

    /// Creates and opens a repository at `path`, relative to the directory
    /// `dir`.
    ///
    /// The call is idempotent. [`Repo::create`] describes the layout that it
    /// writes.
    ///
    /// # Errors
    ///
    /// - The errors of [`create`](CreateOptions::create).
    /// - [`Error::Io`] if the call cannot duplicate `dir`.
    pub async fn create_at(&self, dir: BorrowedFd<'_>, path: &Path) -> Result<Repo> {
        self.check()?;
        let opts = self.clone();
        let dir = dir.try_clone_to_owned()?;
        let path = path.to_owned();
        let stored = path.clone();
        let materials = ostrya_rt::unblock(move || create_materials(&dir, &path, &opts)).await?;
        Ok(Repo::assemble(materials, stored))
    }

    /// Refuses a value that the create does not take: a collection id that
    /// holds a line break, the remotes directory values that the open
    /// refuses, and a remotes directory path that is not valid UTF-8, because
    /// `config` is UTF-8.
    fn check(&self) -> Result<()> {
        if let Some(id) = &self.collection_id
            && id.contains(['\n', '\r'])
        {
            return Err(Error::InvalidInput(format!(
                "the collection id {id:?} holds a line break"
            )));
        }
        let Some(dir) = &self.remotes_dir else {
            return Ok(());
        };
        dir.check()?;
        match dir {
            RemotesDir::Path(path) | RemotesDir::InRepo(path) => utf8_key_value(path).map(drop),
            RemotesDir::Fd(_) => Ok(()),
        }
    }
}

/// A handle to an open ostree repository.
///
/// A clone of a `Repo` is cheap. The clones share one `Arc` that holds the
/// directory descriptors of the repository and its parsed [`RepoConfig`].
/// A `Repo` is `Send + Sync`, so a handle can move into a task. The handle
/// reads the config and the `.conf` files of its remotes directory one time,
/// when it opens.
///
/// The methods that do I/O are `async fn`. A call runs its file system work on
/// the blocking pool through `ostrya_rt::unblock`, so the call does not block
/// the executor. The open parses `config` on the blocking pool, because the
/// key that names the remotes directory selects the next read.
///
/// # Entry points
///
/// - [`open`](Repo::open) and [`create`](Repo::create) give a handle.
/// - [`OpenOptions`] and [`CreateOptions`] give a handle with options, such as
///   a [`RemotesDir`].
/// - [`transaction`](Repo::transaction) begins a [`Transaction`], which writes objects and refs.
/// - [`load_commit`](Repo::load_commit), [`read_commit`](Repo::read_commit), and
///   [`load_file`](Repo::load_file) read objects.
/// - [`resolve_rev`](Repo::resolve_rev) and [`list_refs`](Repo::list_refs) read refs.
/// - [`checkout_at`](Repo::checkout_at) writes the tree of a commit into a directory.
/// - [`pull`](Repo::pull) and [`pull_local`](Repo::pull_local) copy commits from
///   another repository.
/// - [`prune`](Repo::prune) and [`fsck`](Repo::fsck) maintain the object store.
/// - [`begin_update`](Repo::begin_update) holds the writes of refs and `config`.
#[derive(Debug, Clone)]
pub struct Repo {
    inner: Arc<RepoInner>,
}

#[derive(Debug)]
struct RepoInner {
    // All descriptor-relative I/O starts from the root descriptor and the
    // `objects/` descriptor. The open makes them one time, and the read path
    // and the write path use them.
    repo_fd: OwnedFd,
    objects_fd: OwnedFd,
    config: RepoConfig,
    // The path that opened or created the handle, stored as the caller gave
    // it. It is a record of the argument of the caller, and no I/O uses it.
    // Each access goes through `repo_fd` and `objects_fd`.
    path: PathBuf,
    // The remotes directory that the open selected, or that the create took.
    // A value of the caller is stored as the caller gave it.
    remotes_dir: Option<RemotesDir>,
    // The strict open mode of `Repo::open_at_strict`: the reads of `config`,
    // of the metadata objects, and of the composefs image follow no symlink,
    // do not block on a FIFO, and refuse a file that is not a regular file.
    strict: bool,
    // The repository lock. The first acquire of the repository lock creates
    // it, and the handle keeps it for its full life. So all clones of this
    // handle share one `.lock` descriptor and one in-process hold count.
    lock: Mutex<Option<Arc<RepoLock>>>,
    // The update lock. The first acquire of the update lock creates it, and
    // the handle keeps it for its full life beside `lock`. So all clones of
    // this handle share one `.update.lock` descriptor and one queue of waiters.
    update_lock: Mutex<Option<Arc<UpdateLock>>>,
    // The anonymous read access of the implicit client groups. The first
    // use builds it from `config`, and all clones of this handle share it.
    implicit_reads: OnceLock<ReadAccess>,
}

impl RepoInner {
    /// Returns the shared [`RepoLock`] of this repository. The first call
    /// creates and registers `<repo>/.lock`. Runs synchronous file system
    /// calls.
    fn repo_lock(&self) -> std::io::Result<Arc<RepoLock>> {
        let mut slot = self.lock.lock().unwrap();
        if let Some(existing) = slot.as_ref() {
            return Ok(existing.clone());
        }
        let lock = RepoLock::get_or_create(self.repo_fd.as_fd(), self.config.mode())?;
        *slot = Some(lock.clone());
        Ok(lock)
    }

    /// Returns the shared [`UpdateLock`] of this repository. The first call
    /// creates and registers `<repo>/.update.lock`. Runs synchronous file
    /// system calls.
    fn update_lock(&self) -> std::io::Result<Arc<UpdateLock>> {
        let mut slot = self.update_lock.lock().unwrap();
        if let Some(existing) = slot.as_ref() {
            return Ok(existing.clone());
        }
        let lock = UpdateLock::get_or_create(self.repo_fd.as_fd(), self.config.mode())?;
        *slot = Some(lock.clone());
        Ok(lock)
    }
}

/// The materials of a handle that come from the file system. The blocking
/// pool makes them, and the async side assembles them into a [`Repo`].
struct Materials {
    repo_fd: OwnedFd,
    objects_fd: OwnedFd,
    config: RepoConfig,
    remotes_dir: Option<RemotesDir>,
    strict: bool,
}

impl Materials {
    /// Selects the remotes directory of the handle: `first`, then the key of
    /// `config`, then `default`. Reads the remotes of the selected directory
    /// into the config. Blocks the calling thread.
    fn select_remotes_dir(
        mut self,
        first: Option<&RemotesDir>,
        default: Option<&RemotesDir>,
    ) -> Result<Materials> {
        let key = remotes_dir::from_key(&self.config)?;
        let selected = first.cloned().or(key).or_else(|| default.cloned());
        if let Some(dir) = &selected {
            self.config = remotes_dir::read_remotes(self.config, self.repo_fd.as_fd(), dir)?;
        }
        self.remotes_dir = selected;
        Ok(self)
    }
}

/// Methods that open or create a repository and begin a transaction.
impl Repo {
    /// Opens the repository at `path`, relative to the current working directory.
    ///
    /// The call is [`OpenOptions::open`] with the default options, so the
    /// handle takes the remotes directory that the key
    /// `[ex-ostrya] remotes-config-dir` of `config` names.
    ///
    /// The handle stores `path` as given, and [`path`](Repo::path) returns it.
    ///
    /// The handle holds a descriptor of the repository root and one of
    /// `objects/`, which each repository has. The call opens no descriptor of
    /// `tmp/` and does not read the boot id. A repository that is served
    /// read-only can have no `tmp/`, and the call opens it. A transaction
    /// reads the boot id when it begins, as the `ostree` command does. Each
    /// write that needs `tmp/` opens it, and creates it if it is absent.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if `path` is not a directory, if it has no `objects`
    ///   directory or no `config` file, or if a read fails.
    /// - The errors of [`OpenOptions::open`].
    pub async fn open(path: &Path) -> Result<Repo> {
        OpenOptions::new().open(path).await
    }

    /// Opens the repository at `path`, relative to the directory `dir`.
    ///
    /// The call is [`OpenOptions::open_at`] with the default options, so the
    /// handle takes the remotes directory that the key
    /// `[ex-ostrya] remotes-config-dir` of `config` names.
    ///
    /// The handle stores `path` as given, and [`path`](Repo::path) returns it.
    ///
    /// # Errors
    ///
    /// - The errors of [`OpenOptions::open_at`].
    pub async fn open_at(dir: BorrowedFd<'_>, path: &Path) -> Result<Repo> {
        OpenOptions::new().open_at(dir, path).await
    }

    /// Opens the repository at `path`, relative to the directory `dir`, in
    /// the strict open mode. A process that reads a repository of another
    /// user with more privileges than that user opens it in this mode.
    ///
    /// The handle is the handle of [`open_at`](Repo::open_at), with these
    /// changes:
    ///
    /// - The open reads no `[ex-ostrya] remotes-config-dir` key and no remotes
    ///   directory, so the handle has no remotes directory.
    /// - The open of `objects` follows no symlink.
    /// - The reads of `config`, of each metadata object, and of the stored
    ///   composefs image open the file with `O_NOFOLLOW` and `O_NONBLOCK`,
    ///   and refuse a file that is not a regular file. A symlink, a FIFO, or
    ///   a device at such a path fails the read and does not block it.
    ///
    /// The function is not a stable API.
    ///
    /// # Errors
    ///
    /// - The errors of [`open_at`](Repo::open_at), except the errors of the
    ///   remotes directory.
    /// - [`Error::Io`] if `objects` or `config` is a symlink, or if `config`
    ///   is not a regular file.
    #[doc(hidden)]
    pub async fn open_at_strict(dir: BorrowedFd<'_>, path: &Path) -> Result<Repo> {
        let dir = dir.try_clone_to_owned()?;
        let path = path.to_owned();
        let stored = path.clone();
        let materials =
            ostrya_rt::unblock(move || open_materials(&dir, &path, true, &OpenOptions::default()))
                .await?;
        Ok(Repo::assemble(materials, stored))
    }

    /// Creates and opens a repository at `path`, relative to the working directory.
    ///
    /// The call is [`opts.create(path)`](CreateOptions::create).
    ///
    /// The call is idempotent. If `config` exists, the call does not change it,
    /// and the handle reads the mode from it. The `ostree init` command also
    /// keeps an existing `config`. The handle stores `path` as given.
    ///
    /// # Layout
    ///
    /// If the directory at `path` does not exist, the call creates it. Then it
    /// creates the layout that the `ostree` command writes:
    ///
    /// - The directories `objects`, `tmp`, `tmp/cache`, `refs`, `refs/heads`,
    ///   `refs/remotes`, `refs/mirrors`, `state`, and `extensions`.
    /// - The `config` file. Its `[core]` group holds `repo_version=1`, `mode`,
    ///   and `collection-id` if [`collection_id`](CreateOptions::collection_id)
    ///   is set. If [`remotes_dir`](CreateOptions::remotes_dir) is a
    ///   [`Path`](RemotesDir::Path) or an [`InRepo`](RemotesDir::InRepo)
    ///   value, an `[ex-ostrya]` group with the key `remotes-config-dir`
    ///   follows.
    ///
    /// A new directory gets the mode `0775`, reduced by the process umask, as
    /// the `ostree` command does. The `config` file gets the mode `0644`, and
    /// the umask does not change it.
    ///
    /// The call keeps each entry of the layout that exists. It does not check
    /// the type of an existing `tmp/cache`, `refs/heads`, `refs/remotes`,
    /// `refs/mirrors`, `state`, or `extensions`. A file at such a path does not
    /// make the call fail.
    ///
    /// In a `bare-user-shared` repository, the call sets the mode `02770` on
    /// each directory that it creates. The umask does not change this mode.
    /// A directory that exists keeps its mode and its group, the root included.
    /// If ostrya did not create the root, the caller sets its group and its mode.
    ///
    /// # Errors
    ///
    /// - The errors of [`CreateOptions::create`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> ostrya::Result<()> {
    /// use ostrya::repo::CreateOptions;
    /// use ostrya::{Repo, RepoMode};
    ///
    /// let path = std::env::temp_dir().join("example-repo");
    /// let repo = Repo::create(&path, CreateOptions::new(RepoMode::Archive)).await?;
    /// assert_eq!(repo.mode(), RepoMode::Archive);
    /// # Ok(()) }
    /// ```
    pub async fn create(path: &Path, opts: CreateOptions) -> Result<Repo> {
        opts.create(path).await
    }

    /// Creates and opens a repository at `path`, relative to the directory `dir`.
    ///
    /// The call is [`opts.create_at(dir, path)`](CreateOptions::create_at).
    /// It is idempotent. [`create`](Repo::create) describes the layout that it
    /// writes.
    ///
    /// # Errors
    ///
    /// - The errors of [`CreateOptions::create_at`].
    pub async fn create_at(dir: BorrowedFd<'_>, path: &Path, opts: CreateOptions) -> Result<Repo> {
        opts.create_at(dir, path).await
    }

    /// Returns the storage mode of the repository.
    pub fn mode(&self) -> RepoMode {
        self.inner.config.mode()
    }

    /// Returns the parsed config of the repository and the remotes of its
    /// remotes directory, as the open read them.
    ///
    /// A later change of the files does not change the value.
    pub fn config(&self) -> &RepoConfig {
        &self.inner.config
    }

    /// Returns the read access of an anonymous client under the implicit
    /// client groups of the collection id of the repository. The first call
    /// builds the value, and the handle and its clones keep it.
    pub(crate) fn implicit_reads(&self) -> &ReadAccess {
        self.inner.implicit_reads.get_or_init(|| {
            ReadAccess::new(
                Arc::new(ClientAccess::implicit(self.config().collection_id())),
                AuthItem::Anonymous,
                None,
            )
        })
    }

    /// Returns the path that opened or created this handle, as the caller gave it.
    ///
    /// The constructor does not make the path canonical and does not resolve it
    /// with `readlink("/proc/self/fd/N")`, so a relative path stays relative.
    ///
    /// For [`open_at`](Repo::open_at) and [`create_at`](Repo::create_at), the
    /// value is relative to the `dir` descriptor of that call. Without that
    /// descriptor, the value does not resolve.
    ///
    /// A relative path has its meaning only in the process and the working
    /// directory that opened the handle. Another process needs the absolute
    /// form of the path.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Returns the remotes directory of the handle.
    ///
    /// For an open, the value is the value that [`OpenOptions`] selected. A
    /// value of an option is as the caller gave it. The key
    /// `[ex-ostrya] remotes-config-dir` gives a [`Path`](RemotesDir::Path)
    /// value for an absolute path and an [`InRepo`](RemotesDir::InRepo) value
    /// for a relative path. For a create, the value is the value of
    /// [`CreateOptions::remotes_dir`], or else the value of the key of an
    /// existing `config`. A handle with no remotes directory gives `None`,
    /// for example a handle of [`Repo::open_at_strict`].
    pub fn remotes_dir(&self) -> Option<&RemotesDir> {
        self.inner.remotes_dir.as_ref()
    }

    /// Returns the descriptor of the `objects` directory of the repository.
    ///
    /// The handle opened the directory read-only at the open, so the
    /// descriptor refers to the directory that the handle reads, also after a
    /// rename of the repository. The descriptor is valid while the handle
    /// lives. A caller that needs it for a longer time duplicates it with
    /// [`BorrowedFd::try_clone_to_owned`].
    pub fn objects_dir(&self) -> BorrowedFd<'_> {
        self.objects_fd()
    }

    /// Begins a transaction that holds the repository lock shared.
    ///
    /// A shared lock matches the read lock that the `ostree` command holds
    /// during a commit. Many transactions can commit at the same time, in this
    /// process and across processes. If `[core] locking` is on, a held
    /// [`UpdateGuard`](crate::UpdateGuard) holds the repository lock shared,
    /// so a transaction can begin and stage objects while a guard is held.
    ///
    /// [`transaction_with_lock`](Repo::transaction_with_lock) describes the
    /// lock wait and the staging directory.
    ///
    /// # Errors
    ///
    /// - [`Error::LockTimeout`] if the wait for the lock passes
    ///   `[core] lock-timeout-secs`.
    /// - [`Error::Core`] if `[core] locking` is not a boolean, or if
    ///   `lock-timeout-secs`, `tmp-expiry-secs`, or `min-free-space-percent`
    ///   is not an integer.
    /// - [`Error::InvalidFormat`] if `lock-timeout-secs` is less than `-1`,
    ///   if `min-free-space-size` is malformed, or if `min-free-space-percent`
    ///   is outside the range `0` to `100`.
    /// - [`Error::Io`] if the call cannot create the lock file or the staging
    ///   directory, or cannot read the free space of the file system.
    pub async fn transaction(&self) -> Result<Transaction> {
        self.transaction_with_lock(LockKind::Shared).await
    }

    /// Begins a transaction that holds the repository lock in `kind`.
    ///
    /// The wait for the lock retries until `[core] lock-timeout-secs` passes.
    /// If the value is `-1`, the wait has no limit. If `[core] locking` is off,
    /// the transaction takes no repository lock. [`LockKind`] describes the
    /// repository lock.
    ///
    /// The call creates a new staging directory under `tmp/`. Before that, it
    /// removes the staging directories of dead transactions and the other
    /// `tmp/` entries older than `[core] tmp-expiry-secs`. [`Transaction`]
    /// describes the staging directory.
    ///
    /// The transaction starts with a free-space budget. The budget is the
    /// number of bytes available on the file system, less the reserve of
    /// [`RepoConfig::min_free_space`]. Each staged object decreases the budget.
    ///
    /// # Lock order
    ///
    /// A writer outside a transaction takes the repository lock shared, for
    /// example [`set_ref_immediate`](Repo::set_ref_immediate) and
    /// [`write_config`](Repo::write_config). If `[core] locking` is on and a
    /// caller holds a transaction in [`LockKind::Exclusive`], a call to such a
    /// writer waits for the lock of the caller. [`LockKind`] states the result
    /// of this wait.
    ///
    /// # Errors
    ///
    /// - [`Error::LockTimeout`] if the wait for the lock passes
    ///   `[core] lock-timeout-secs`.
    /// - [`Error::Core`] if `[core] locking` is not a boolean, or if
    ///   `lock-timeout-secs`, `tmp-expiry-secs`, or `min-free-space-percent`
    ///   is not an integer.
    /// - [`Error::InvalidFormat`] if `lock-timeout-secs` is less than `-1`,
    ///   if `min-free-space-size` is malformed, or if `min-free-space-percent`
    ///   is outside the range `0` to `100`.
    /// - [`Error::Io`] if the call cannot create the lock file or the staging
    ///   directory, or cannot read the free space of the file system.
    pub async fn transaction_with_lock(&self, kind: LockKind) -> Result<Transaction> {
        // The call parses each `[core]` key that it reads before it takes the
        // lock. So a value that the config cannot carry fails the call before
        // any wait on a contended repository.
        let expiry_secs = self.inner.config.tmp_expiry_secs()?;
        let min_free = self.inner.config.min_free_space()?;
        let guard = self.lock_repo(kind).await?;

        let repo = self.clone();
        let staging = ostrya_rt::unblock(move || {
            let mode = repo.inner.config.mode();
            StagingDir::create(repo.inner.repo_fd.as_fd(), expiry_secs, mode)
        })
        .await?;

        // The initial free-space budget: the available bytes less the reserve
        // of the config. Each staged object decreases it.
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        let budget = ostrya_rt::unblock(move || free_budget(repo_fd.as_fd(), min_free)).await?;

        Ok(Transaction::new(self.clone(), guard, staging, budget))
    }

    /// Takes the repository lock in `kind` and holds it until the guard drops.
    ///
    /// The call reads `[core] locking` and `[core] lock-timeout-secs`. If
    /// `locking` is true, the acquire retries until the timeout passes and then
    /// fails with [`Error::LockTimeout`]. If `lock-timeout-secs` is `-1`, it
    /// retries with no limit.
    ///
    /// If `locking` is false, the guard holds no lock. The call reads
    /// `lock-timeout-secs` in both cases, so a value that the config cannot
    /// carry fails the call.
    pub(crate) async fn lock_repo(&self, kind: LockKind) -> Result<LockGuard> {
        let locking = self.inner.config.locking()?;
        let timeout_secs = self.inner.config.lock_timeout_secs()?;
        if !locking {
            return Ok(LockGuard::disabled());
        }
        // The calling task reads a cached lock. Only the first use of the
        // handle opens the lock file on the blocking pool.
        let cached = self.inner.lock.lock().unwrap().clone();
        let lock = match cached {
            Some(lock) => lock,
            None => {
                let repo = self.clone();
                ostrya_rt::unblock(move || repo.inner.repo_lock()).await?
            }
        };
        lock::acquire(lock, kind, lock_timeout(timeout_secs)).await
    }

    /// Takes the update lock and holds it until the guard drops.
    ///
    /// The lock is exclusive across processes and in the process. The waiters
    /// of one process take it in the order of the first poll of their calls.
    /// Only the first of them makes lock requests.
    ///
    /// The call reads `[core] lock-timeout-secs`. The timeout covers the wait
    /// in the queue and the retries against other processes, and then the call
    /// fails with [`Error::LockTimeout`]. If the value is `-1`, the wait has no
    /// limit. If the value is `0`, the call makes one attempt.
    ///
    /// The call ignores `[core] locking` and always takes the lock.
    ///
    /// The first call on a handle opens the lock file on the blocking pool
    /// before it joins the queue. That call joins the queue when the open
    /// completes, and the timeout does not cover the open. Each later call on
    /// the handle, or on a clone of it, joins the queue on its first poll.
    ///
    /// A release always drops the record lock, so another process can take
    /// the lock between two holders of this process.
    ///
    /// Take the repository lock before the update lock, never the reverse.
    /// Against other processes the lock has no order. A waiter can lose every
    /// retry to another process until the timeout passes.
    pub(crate) async fn lock_update(&self) -> Result<UpdateLockHeld> {
        let timeout_secs = self.inner.config.lock_timeout_secs()?;
        // The calling task reads a cached lock, so the call joins the queue on
        // its first poll. Only the first use of the handle opens the
        // lock file on the blocking pool.
        let cached = self.inner.update_lock.lock().unwrap().clone();
        let lock = match cached {
            Some(lock) => lock,
            None => {
                let repo = self.clone();
                ostrya_rt::unblock(move || repo.inner.update_lock()).await?
            }
        };
        lock::acquire_update(lock, lock_timeout(timeout_secs)).await
    }

    /// Takes the repository lock shared, then the update lock, and holds both
    /// until the returned value drops.
    ///
    /// The call reads `[core] locking` and `[core] lock-timeout-secs` before
    /// it waits, so a value that the config cannot carry fails the call at
    /// once. Each of the two waits gets the full timeout. If `locking` is
    /// false, the call does not take the repository lock. It always takes the
    /// update lock.
    pub(crate) async fn lock_for_update(&self) -> Result<UpdateLocks> {
        self.inner.config.locking()?;
        self.inner.config.lock_timeout_secs()?;
        let repo = self.lock_repo(LockKind::Shared).await?;
        let update = self.lock_update().await?;
        Ok(UpdateLocks { update, repo })
    }

    /// Takes the repository lock shared, then the update lock, as
    /// [`lock_for_update`](Repo::lock_for_update) does, and runs `write` on
    /// the blocking pool under both.
    ///
    /// The locks move into the blocking closure and drop at its end. So a
    /// caller that drops the returned future cannot release them while `write`
    /// still runs.
    pub(crate) async fn write_locked<T, F>(&self, write: F) -> Result<T>
    where
        F: FnOnce(&Repo) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let locks = self.lock_for_update().await?;
        self.write_holding(locks, write).await
    }

    /// Runs `write` on the blocking pool under `locks`, and releases them when
    /// `write` ends, as [`write_locked`](Repo::write_locked) does.
    ///
    /// A caller that must read under the locks before its write takes them
    /// first.
    pub(crate) async fn write_holding<T, F>(&self, locks: UpdateLocks, write: F) -> Result<T>
    where
        F: FnOnce(&Repo) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            let written = write(&repo);
            drop(locks);
            written
        })
        .await
    }

    /// Returns `true` if `held` is a hold of the update lock of this repository.
    pub(crate) fn holds_update_lock(&self, held: &UpdateLockHeld) -> bool {
        self.inner
            .update_lock
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|lock| held.is_of(lock))
    }

    /// Reads `config` from disk and parses it. The call does not read the
    /// remotes directory.
    ///
    /// The handle keeps the config that it read at the open.
    pub(crate) async fn read_config_file(&self) -> Result<RepoConfig> {
        let repo = self.clone();
        ostrya_rt::unblock(move || read_config_blocking(repo.repo_fd(), repo.is_strict())).await
    }

    /// Reads `config` and the `.conf` files of the remotes directory of the
    /// handle from disk and parses them. The call does not read the key
    /// `[ex-ostrya] remotes-config-dir` again.
    pub(crate) async fn read_config_and_remotes(&self) -> Result<RepoConfig> {
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            let config = read_config_blocking(repo.repo_fd(), repo.is_strict())?;
            match repo.remotes_dir() {
                Some(dir) => remotes_dir::read_remotes(config, repo.repo_fd(), dir),
                None => Ok(config),
            }
        })
        .await
    }

    /// Returns `true` if the handle opened in the strict open mode of
    /// [`open_at_strict`](Repo::open_at_strict).
    pub(crate) fn is_strict(&self) -> bool {
        self.inner.strict
    }

    /// Returns the descriptor of the repository root. Descriptor-relative
    /// access to `refs/`, `state/`, and the rest of the layout starts from it.
    pub(crate) fn repo_fd(&self) -> BorrowedFd<'_> {
        self.inner.repo_fd.as_fd()
    }

    /// Returns the descriptor of `objects/`. Access to loose objects starts
    /// from it.
    pub(crate) fn objects_fd(&self) -> BorrowedFd<'_> {
        self.inner.objects_fd.as_fd()
    }

    /// Assembles the handle. `path` is the argument that the caller gave the
    /// constructor, stored as given for [`Repo::path`].
    fn assemble(materials: Materials, path: PathBuf) -> Repo {
        Repo {
            inner: Arc::new(RepoInner {
                repo_fd: materials.repo_fd,
                objects_fd: materials.objects_fd,
                config: materials.config,
                path,
                remotes_dir: materials.remotes_dir,
                strict: materials.strict,
                lock: Mutex::new(None),
                update_lock: Mutex::new(None),
                implicit_reads: OnceLock::new(),
            }),
        }
    }
}

/// Refuses the bytes of a `config` larger than [`MAX_CONFIG_SIZE`], so that a
/// write leaves no file that an open refuses.
pub(crate) fn check_config_size(bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > MAX_CONFIG_SIZE {
        return Err(Error::InvalidFormat(format!(
            "config exceeds the {MAX_CONFIG_SIZE}-byte size cap"
        )));
    }
    Ok(())
}

/// Reads `config` at the repository root and parses it, as the open of a
/// handle does. Blocks the calling thread.
///
/// If `strict` is set, the read uses the strict open mode: the open follows no
/// symlink and does not block, and a file that is not a regular file is
/// refused.
pub(crate) fn read_config_blocking(repo_fd: BorrowedFd<'_>, strict: bool) -> Result<RepoConfig> {
    parse_config(&read_file(repo_fd, CONFIG, strict)?)
}

/// Parses the bytes of `config`. This step is CPU work only.
///
/// A read of `config` stops one byte after [`MAX_CONFIG_SIZE`], so an input
/// longer than the cap stands for a file over the cap.
fn parse_config(bytes: &[u8]) -> Result<RepoConfig> {
    check_config_size(bytes)?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidFormat("config is not valid UTF-8".into()))?;
    RepoConfig::parse(text)
}

/// Returns the lock wait of a `lock-timeout-secs` value. The config reader
/// refuses a value less than -1, so a negative value here is -1, which means
/// no limit.
fn lock_timeout(secs: i64) -> Option<Duration> {
    u64::try_from(secs).ok().map(Duration::from_secs)
}

/// Computes the initial free-space budget of a transaction: the bytes
/// available on the file system of the repository, less the `min-free-space`
/// reserve of the config. Runs a synchronous `fstatvfs`.
fn free_budget(repo_fd: BorrowedFd<'_>, min_free: MinFreeSpace) -> Result<u64> {
    let stat = rustix::fs::fstatvfs(repo_fd)?;
    let available = stat.f_bavail.saturating_mul(stat.f_frsize);
    let total = stat.f_blocks.saturating_mul(stat.f_frsize);
    let reserved = match min_free {
        MinFreeSpace::Percent(percent) => ((u128::from(total) * u128::from(percent)) / 100) as u64,
        MinFreeSpace::Size(spec) => spec.bytes(),
    };
    Ok(available.saturating_sub(reserved))
}

/// Opens an existing repository directory and gathers its materials, in the
/// strict open mode if `strict` is set. The strict open mode reads no remotes
/// directory.
fn open_materials<Fd: AsFd>(
    dir: Fd,
    path: &Path,
    strict: bool,
    opts: &OpenOptions,
) -> Result<Materials> {
    let repo_fd = open_dir(dir, path)?;
    let materials = materials_from_repo(repo_fd, strict)?;
    if strict {
        return Ok(materials);
    }
    materials.select_remotes_dir(opts.remotes_dir.as_ref(), opts.default_remotes_dir.as_ref())
}

/// Makes sure that the repository layout and the config exist, then gathers
/// the materials.
///
/// The call makes the text of a new `config` before it creates a directory,
/// so a refusal of the remotes directory value writes nothing.
fn create_materials<Fd: AsFd>(dir: Fd, path: &Path, opts: &CreateOptions) -> Result<Materials> {
    let config = initial_config_text(opts)?;
    mkdir_idempotent(&dir, path, opts.mode)?;
    let repo_fd = open_dir(&dir, path)?;
    for sub in LAYOUT_DIRS {
        mkdir_idempotent(&repo_fd, Path::new(sub), opts.mode)?;
    }
    write_initial_config(&repo_fd, &config)?;
    materials_from_repo(repo_fd, false)?.select_remotes_dir(opts.remotes_dir.as_ref(), None)
}

/// Opens the `objects/` directory and reads and parses the config, given the
/// descriptor of the repository root. In the strict open mode, the open of
/// `objects/` follows no symlink. The materials have no remotes directory.
fn materials_from_repo(repo_fd: OwnedFd, strict: bool) -> Result<Materials> {
    let objects_fd = match strict {
        true => rustix::fs::openat(
            &repo_fd,
            "objects",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?,
        false => open_dir(&repo_fd, Path::new("objects"))?,
    };
    let config = read_config_blocking(repo_fd.as_fd(), strict)?;
    Ok(Materials {
        repo_fd,
        objects_fd,
        config,
        remotes_dir: None,
        strict,
    })
}

/// Opens a directory relative to `dir` for descriptor-relative access.
fn open_dir<Fd: AsFd>(dir: Fd, path: &Path) -> std::io::Result<OwnedFd> {
    let fd = rustix::fs::openat(
        dir,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(fd)
}

/// Reads the config file relative to `dir`, up to one byte after
/// [`MAX_CONFIG_SIZE`].
///
/// The parse can then refuse a file over the cap, and the read stops there.
/// In the strict open mode, the open follows no symlink and does not block,
/// and a file that is not a regular file is refused.
fn read_file<Fd: AsFd>(dir: Fd, path: &str, strict: bool) -> std::io::Result<Vec<u8>> {
    let fd = crate::object::open_regular_file(dir.as_fd(), path, strict)?;
    let mut buf = Vec::new();
    std::fs::File::from(fd)
        .take(MAX_CONFIG_SIZE + 1)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

/// Creates a directory, and treats an existing entry as success.
///
/// In a `bare-user-shared` repository, the call forces
/// [`perm::SHARED_DIR_MODE`] on a directory that it creates. An entry that
/// exists keeps its mode and its group.
fn mkdir_idempotent<Fd: AsFd>(dir: Fd, path: &Path, mode: RepoMode) -> std::io::Result<()> {
    match rustix::fs::mkdirat(&dir, path, Mode::from_raw_mode(DIR_MODE)) {
        Ok(()) => perm::force_created_dir(&dir, path, mode),
        Err(Errno::EXIST) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Writes the initial `config` text if `config` does not exist. The call
/// forces the mode `0644` on the file whatever the umask, as the `ostree`
/// command does.
fn write_initial_config<Fd: AsFd>(repo_fd: Fd, config: &str) -> std::io::Result<()> {
    let fd = match rustix::fs::openat(
        repo_fd,
        CONFIG,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(CONFIG_MODE),
    ) {
        Ok(fd) => fd,
        // An existing config means the repository is already initialized.
        Err(Errno::EXIST) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(CONFIG_MODE))?;
    std::fs::File::from(fd).write_all(config.as_bytes())
}

/// Returns the exact config bytes of a new repository.
///
/// The call reads the working directory for the absolute form of a
/// [`RemotesDir::Path`] value, so it runs off the async task.
fn initial_config_text(opts: &CreateOptions) -> Result<String> {
    let mut text = String::from("[core]\nrepo_version=1\nmode=");
    text.push_str(opts.mode.as_mode_str());
    text.push('\n');
    if let Some(id) = &opts.collection_id {
        text.push_str("collection-id=");
        text.push_str(id);
        text.push('\n');
    }
    if let Some(group) = remotes_dir_group(opts.remotes_dir.as_ref())? {
        // A blank line separates two groups, as in the text of a `KeyFile`.
        text.push('\n');
        text.push_str(&group);
    }
    Ok(text)
}

/// Returns `path` as the UTF-8 text of the key `remotes-config-dir`, or
/// refuses it with [`Error::InvalidInput`].
fn utf8_key_value(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        Error::InvalidInput(format!(
            "the remotes directory path {} is not valid UTF-8",
            path.display()
        ))
    })
}

/// Returns the `[ex-ostrya]` group that names `dir` in a new `config`, or
/// `None` if the create writes no key.
///
/// A [`RemotesDir::Path`] value gives its absolute form, and a
/// [`RemotesDir::InRepo`] value its path as given. A [`RemotesDir::Fd`] value
/// has no path, so it gives no key. The absolute form of a relative path is
/// not valid UTF-8 if the working directory is not, and the call refuses it.
fn remotes_dir_group(dir: Option<&RemotesDir>) -> Result<Option<String>> {
    let absolute;
    let value = match dir {
        Some(RemotesDir::Path(path)) => {
            absolute = std::path::absolute(path)?;
            &absolute
        }
        Some(RemotesDir::InRepo(path)) => path,
        Some(RemotesDir::Fd(_)) | None => return Ok(None),
    };
    let value = utf8_key_value(value)?;
    let mut group = KeyFile::default();
    group.set_string(EX_OSTRYA, REMOTES_CONFIG_DIR, value)?;
    Ok(Some(group.to_string()))
}

/// Checks at compile time that a repository handle and the options types are
/// `Send + Sync`, so that they can move across tasks and threads, and that the
/// futures of an open and of a create are `Send`.
#[allow(dead_code)]
fn assert_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}
    fn is_send<T: Send>(_: &T) {}
    is_send_sync::<Repo>();
    is_send_sync::<OpenOptions>();
    is_send_sync::<CreateOptions>();
    is_send_sync::<RemotesDir>();
    let _ = |opts: &OpenOptions, path: &Path| is_send(&opts.open(path));
    let _ =
        |opts: &OpenOptions, dir: BorrowedFd<'_>, path: &Path| is_send(&opts.open_at(dir, path));
    let _ = |opts: &CreateOptions, path: &Path| is_send(&opts.create(path));
    let _ = |opts: &CreateOptions, dir: BorrowedFd<'_>, path: &Path| {
        is_send(&opts.create_at(dir, path))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_timeout_maps_the_config_value() {
        assert_eq!(lock_timeout(-1), None);
        assert_eq!(lock_timeout(0), Some(Duration::ZERO));
        assert_eq!(lock_timeout(5), Some(Duration::from_secs(5)));
    }
}
