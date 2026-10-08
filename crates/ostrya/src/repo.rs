//! The repository handle and the options of a new repository.
//!
//! [`Repo`] is the handle. [`Repo::open`] opens a repository, and
//! [`Repo::create`] creates one with [`CreateOptions`].

use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ostrya_core::RepoMode;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::config::{MinFreeSpace, RepoConfig};
use crate::error::{Error, Result};
use crate::lock::{self, LockGuard, LockKind, RepoLock, UpdateLock, UpdateLockHeld, UpdateLocks};
use crate::perm;
use crate::staging::StagingDir;
use crate::transaction::Transaction;

/// The path of the config file in a repository.
const CONFIG: &str = "config";

/// The largest `config` file that a read accepts, in bytes. A read refuses a
/// larger file with [`Error::InvalidFormat`].
const MAX_CONFIG_SIZE: u64 = 1024 * 1024;

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

/// The options of a new repository.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    /// The storage mode, written to `[core] mode`.
    ///
    /// The default is [`Bare`](RepoMode::Bare).
    pub mode: RepoMode,
    /// The collection id, written to `[core] collection-id` if it is set.
    pub collection_id: Option<String>,
}

impl Default for CreateOptions {
    fn default() -> Self {
        CreateOptions {
            mode: RepoMode::Bare,
            collection_id: None,
        }
    }
}

impl CreateOptions {
    /// Creates the options of a repository of `mode`, with no collection id.
    pub fn new(mode: RepoMode) -> Self {
        CreateOptions {
            mode,
            collection_id: None,
        }
    }
}

/// A handle to an open ostree repository.
///
/// A clone of a `Repo` is cheap. The clones share one `Arc` that holds the
/// directory descriptors of the repository and its parsed [`RepoConfig`].
/// A `Repo` is `Send + Sync`, so a handle can move into a task. The handle
/// reads the config one time, when it opens.
///
/// The methods that do I/O are `async fn`. A call runs its file system work on
/// the blocking pool through `ostrya_rt::unblock`, so the call does not block
/// the executor. A config parse is CPU work only and runs on the calling task.
///
/// # Entry points
///
/// - [`open`](Repo::open) and [`create`](Repo::create) give a handle.
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
    // The repository lock. The first acquire of the repository lock creates
    // it, and the handle keeps it for its full life. So all clones of this
    // handle share one `.lock` descriptor and one in-process hold count.
    lock: Mutex<Option<Arc<RepoLock>>>,
    // The update lock. The first acquire of the update lock creates it, and
    // the handle keeps it for its full life beside `lock`. So all clones of
    // this handle share one `.update.lock` descriptor and one queue of waiters.
    update_lock: Mutex<Option<Arc<UpdateLock>>>,
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
    config: Vec<u8>,
}

/// Methods that open or create a repository and begin a transaction.
impl Repo {
    /// Opens the repository at `path`, relative to the current working directory.
    ///
    /// The handle stores `path` as given, and [`path`](Repo::path) returns it.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if `path` is not a directory, if it has no `objects`
    ///   directory or no `config` file, or if a read fails.
    /// - [`Error::InvalidFormat`] if `config` is larger than 1 MiB (1048576
    ///   bytes) or is not valid UTF-8.
    /// - [`Error::InvalidFormat`] if the `[core]` group of `config` fails the
    ///   checks of [`RepoConfig::from_keyfile`].
    /// - [`Error::Core`] if `config` is not a valid key file, or if a `[core]`
    ///   value that [`RepoConfig::from_keyfile`] reads does not parse.
    pub async fn open(path: &Path) -> Result<Repo> {
        let path = path.to_owned();
        let stored = path.clone();
        let materials = ostrya_rt::unblock(move || open_materials(rustix::fs::CWD, &path)).await?;
        Repo::assemble(materials, stored)
    }

    /// Opens the repository at `path`, relative to the directory `dir`.
    ///
    /// The handle stores `path` as given, and [`path`](Repo::path) returns it.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the call cannot duplicate `dir`.
    /// - [`Error::Io`] if `path` is not a directory, if it has no `objects`
    ///   directory or no `config` file, or if a read fails.
    /// - [`Error::InvalidFormat`] if `config` is larger than 1 MiB (1048576
    ///   bytes) or is not valid UTF-8.
    /// - [`Error::InvalidFormat`] if the `[core]` group of `config` fails the
    ///   checks of [`RepoConfig::from_keyfile`].
    /// - [`Error::Core`] if `config` is not a valid key file, or if a `[core]`
    ///   value that [`RepoConfig::from_keyfile`] reads does not parse.
    pub async fn open_at(dir: BorrowedFd<'_>, path: &Path) -> Result<Repo> {
        let dir = dir.try_clone_to_owned()?;
        let path = path.to_owned();
        let stored = path.clone();
        let materials = ostrya_rt::unblock(move || open_materials(&dir, &path)).await?;
        Repo::assemble(materials, stored)
    }

    /// Creates and opens a repository at `path`, relative to the working directory.
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
    ///   is set.
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
        let path = path.to_owned();
        let stored = path.clone();
        let materials =
            ostrya_rt::unblock(move || create_materials(rustix::fs::CWD, &path, &opts)).await?;
        Repo::assemble(materials, stored)
    }

    /// Creates and opens a repository at `path`, relative to the directory `dir`.
    ///
    /// The call is idempotent. [`create`](Repo::create) describes the layout
    /// that it writes.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the call cannot duplicate `dir`.
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
    pub async fn create_at(dir: BorrowedFd<'_>, path: &Path, opts: CreateOptions) -> Result<Repo> {
        let dir = dir.try_clone_to_owned()?;
        let path = path.to_owned();
        let stored = path.clone();
        let materials = ostrya_rt::unblock(move || create_materials(&dir, &path, &opts)).await?;
        Repo::assemble(materials, stored)
    }

    /// Returns the storage mode of the repository.
    pub fn mode(&self) -> RepoMode {
        self.inner.config.mode()
    }

    /// Returns the parsed config of the repository, as the open read it.
    pub fn config(&self) -> &RepoConfig {
        &self.inner.config
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

    /// Reads `config` from disk and parses it, as the open of a handle does.
    ///
    /// The handle keeps the config that it read at the open.
    pub(crate) async fn read_config_file(&self) -> Result<RepoConfig> {
        let repo = self.clone();
        ostrya_rt::unblock(move || read_config_blocking(repo.repo_fd())).await
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

    /// Parses the config bytes and assembles the handle. This step is CPU work
    /// only. `path` is the argument that the caller gave the constructor,
    /// stored as given for [`Repo::path`].
    fn assemble(materials: Materials, path: PathBuf) -> Result<Repo> {
        let config = parse_config(&materials.config)?;
        Ok(Repo {
            inner: Arc::new(RepoInner {
                repo_fd: materials.repo_fd,
                objects_fd: materials.objects_fd,
                config,
                path,
                lock: Mutex::new(None),
                update_lock: Mutex::new(None),
            }),
        })
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
pub(crate) fn read_config_blocking(repo_fd: BorrowedFd<'_>) -> Result<RepoConfig> {
    let bytes = read_file(repo_fd, CONFIG)?;
    parse_config(&bytes)
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

/// Opens an existing repository directory and gathers its materials.
fn open_materials<Fd: AsFd>(dir: Fd, path: &Path) -> std::io::Result<Materials> {
    let repo_fd = open_dir(dir, path)?;
    materials_from_repo(repo_fd)
}

/// Makes sure that the repository layout and the config exist, then gathers
/// the materials.
fn create_materials<Fd: AsFd>(
    dir: Fd,
    path: &Path,
    opts: &CreateOptions,
) -> std::io::Result<Materials> {
    mkdir_idempotent(&dir, path, opts.mode)?;
    let repo_fd = open_dir(&dir, path)?;
    for sub in LAYOUT_DIRS {
        mkdir_idempotent(&repo_fd, Path::new(sub), opts.mode)?;
    }
    write_initial_config(&repo_fd, opts)?;
    materials_from_repo(repo_fd)
}

/// Opens the `objects/` directory and reads the config, given the descriptor
/// of the repository root.
fn materials_from_repo(repo_fd: OwnedFd) -> std::io::Result<Materials> {
    let objects_fd = open_dir(&repo_fd, Path::new("objects"))?;
    let config = read_file(&repo_fd, CONFIG)?;
    Ok(Materials {
        repo_fd,
        objects_fd,
        config,
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
fn read_file<Fd: AsFd>(dir: Fd, path: &str) -> std::io::Result<Vec<u8>> {
    let fd = rustix::fs::openat(dir, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
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

/// Writes the initial `config` if it does not exist. The call forces the mode
/// `0644` on the file whatever the umask, as the `ostree` command does.
fn write_initial_config<Fd: AsFd>(repo_fd: Fd, opts: &CreateOptions) -> std::io::Result<()> {
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
    std::fs::File::from(fd).write_all(initial_config_text(opts).as_bytes())
}

/// Returns the exact config bytes of a new repository.
fn initial_config_text(opts: &CreateOptions) -> String {
    let mut text = String::from("[core]\nrepo_version=1\nmode=");
    text.push_str(opts.mode.as_mode_str());
    text.push('\n');
    if let Some(id) = &opts.collection_id {
        text.push_str("collection-id=");
        text.push_str(id);
        text.push('\n');
    }
    text
}

/// Checks at compile time that a repository handle is `Send + Sync`, so that
/// it can move across tasks and threads.
#[allow(dead_code)]
fn assert_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<Repo>();
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
