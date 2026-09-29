//! The repository handle: open, create, and the parsed config.
//!
//! [`Repo`] is a cheap-to-clone handle (an `Arc` inner) that owns the
//! file descriptors anchoring fd-relative I/O and the parsed [`RepoConfig`].
//! Opening resolves the repository directory and its `objects/` directory and
//! reads the config once; clones share that state so a handle moves freely
//! into a task.
//!
//! The public entry points are `async fn`. The filesystem work -- the
//! `openat`/`mkdirat` syscalls and the config read -- runs on the blocking
//! pool via [`ostrya_rt::unblock`], so a call does not stall the async
//! executor. The config parse that follows is CPU-only and runs inline.
//!
//! Directory-layout creation reproduces what the `ostree` tool writes: the
//! `config` file (mode `0644`, independent of umask), and the `objects`,
//! `refs/{heads,remotes,mirrors}`, `state`, `tmp`, `tmp/cache`, and
//! `extensions` directories (mode `0775`, reduced by the process umask, the
//! same as the tool). Creation is idempotent: an existing `config` is left
//! untouched, matching the tool's `init`.
//!
//! In a `bare-user-shared` repository each directory this module creates is
//! forced to `02770` after the create, independent of the umask (see
//! `crate::perm`). A directory that already stands keeps the mode and the
//! group it has, the repository root included: the group and the mode of a root
//! ostrya did not create are the caller's responsibility.

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

/// The path of the config file within a repository.
const CONFIG: &str = "config";

/// The mode requested for created directories, before the umask is applied.
const DIR_MODE: u32 = 0o775;

/// The mode forced on the config file, independent of the umask.
const CONFIG_MODE: u32 = 0o644;

/// The directories a repository holds, in an order that creates each parent
/// before its children.
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

/// Options for creating a repository.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    /// The storage mode written to `[core] mode`.
    pub mode: RepoMode,
    /// An optional collection id written to `[core] collection-id`.
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
    /// Options for a repository of the given mode with no collection id.
    pub fn new(mode: RepoMode) -> Self {
        CreateOptions {
            mode,
            collection_id: None,
        }
    }
}

/// A repository handle.
#[derive(Debug, Clone)]
pub struct Repo {
    inner: Arc<RepoInner>,
}

#[derive(Debug)]
struct RepoInner {
    // The repository root and `objects/` directory fds anchor all fd-relative
    // I/O; they are opened once here and used by the reading path (Phase 5)
    // and, later, the write path (Phase 7).
    repo_fd: OwnedFd,
    objects_fd: OwnedFd,
    config: RepoConfig,
    // The path the handle was opened or created with, stored exactly as the
    // caller gave it. It is a record of the caller's argument and is never
    // used for I/O; every access goes through `repo_fd` and `objects_fd`.
    path: PathBuf,
    // The repository lock, created on the first transaction and held for the
    // handle's lifetime so every clone of this handle shares one `.lock`
    // descriptor and one in-process hold count.
    lock: Mutex<Option<Arc<RepoLock>>>,
    // The update lock, created on the first update-lock acquire and held for
    // the handle's lifetime beside `lock`, so every clone of this handle
    // shares one `.update.lock` descriptor and one waiter queue.
    update_lock: Mutex<Option<Arc<UpdateLock>>>,
}

impl RepoInner {
    /// The shared [`RepoLock`] for this repository, creating and registering
    /// `<repo>/.lock` on first use. Runs synchronous filesystem calls.
    fn repo_lock(&self) -> std::io::Result<Arc<RepoLock>> {
        let mut slot = self.lock.lock().unwrap();
        if let Some(existing) = slot.as_ref() {
            return Ok(existing.clone());
        }
        let lock = RepoLock::get_or_create(self.repo_fd.as_fd(), self.config.mode())?;
        *slot = Some(lock.clone());
        Ok(lock)
    }

    /// The shared [`UpdateLock`] for this repository, creating and
    /// registering `<repo>/.update.lock` on first use. Runs synchronous
    /// filesystem calls.
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

/// The filesystem-derived materials for a handle, produced on the blocking
/// pool and assembled into a [`Repo`] on the async side.
struct Materials {
    repo_fd: OwnedFd,
    objects_fd: OwnedFd,
    config: Vec<u8>,
}

impl Repo {
    /// Open an existing repository at `path`, resolved against the current
    /// working directory.
    pub async fn open(path: &Path) -> Result<Repo> {
        let path = path.to_owned();
        let stored = path.clone();
        let materials = ostrya_rt::unblock(move || open_materials(rustix::fs::CWD, &path)).await?;
        Repo::assemble(materials, stored)
    }

    /// Open an existing repository at `path`, resolved against `dir`.
    pub async fn open_at(dir: BorrowedFd<'_>, path: &Path) -> Result<Repo> {
        let dir = dir.try_clone_to_owned()?;
        let path = path.to_owned();
        let stored = path.clone();
        let materials = ostrya_rt::unblock(move || open_materials(&dir, &path)).await?;
        Repo::assemble(materials, stored)
    }

    /// Create a repository at `path`, resolved against the current working
    /// directory, then open it. Creation is idempotent.
    pub async fn create(path: &Path, opts: CreateOptions) -> Result<Repo> {
        let path = path.to_owned();
        let stored = path.clone();
        let materials =
            ostrya_rt::unblock(move || create_materials(rustix::fs::CWD, &path, &opts)).await?;
        Repo::assemble(materials, stored)
    }

    /// Create a repository at `path`, resolved against `dir`, then open it.
    /// Creation is idempotent.
    pub async fn create_at(dir: BorrowedFd<'_>, path: &Path, opts: CreateOptions) -> Result<Repo> {
        let dir = dir.try_clone_to_owned()?;
        let path = path.to_owned();
        let stored = path.clone();
        let materials = ostrya_rt::unblock(move || create_materials(&dir, &path, &opts)).await?;
        Repo::assemble(materials, stored)
    }

    /// The repository storage mode.
    pub fn mode(&self) -> RepoMode {
        self.inner.config.mode()
    }

    /// The parsed repository configuration.
    pub fn config(&self) -> &RepoConfig {
        &self.inner.config
    }

    /// The path this handle was opened or created with, exactly as given. The
    /// constructor applies no canonicalization and no
    /// `readlink("/proc/self/fd/N")` resolution, so a relative path stays
    /// relative.
    ///
    /// For [`Repo::open_at`] and [`Repo::create_at`] the value is relative to
    /// the `dir` fd of that call. It does not resolve without that fd.
    ///
    /// A relative path has its meaning in the process and the working
    /// directory that opened the handle. Make such a path absolute before you
    /// give it to another process.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Begin a transaction that holds the repository lock shared.
    ///
    /// A shared lock matches the read lock the tool holds during a commit, so
    /// many transactions commit at once, in this process and across processes.
    /// A held [`UpdateGuard`](crate::UpdateGuard) holds the repository lock
    /// shared too when `[core] locking` is on, so a transaction opens and
    /// stages objects while a guard is held.
    pub async fn transaction(&self) -> Result<Transaction> {
        self.transaction_with_lock(LockKind::Shared).await
    }

    /// Begin a transaction that holds the repository lock in `kind`.
    ///
    /// Acquisition retries until `lock-timeout-secs` elapses, then fails with
    /// [`Error::LockTimeout`]. With `lock-timeout-secs=-1` it retries with no
    /// limit. With `[core] locking` disabled the transaction
    /// takes no repository lock. A fresh staging directory is allocated under
    /// `tmp/`, and stale staging directories left by dead transactions are
    /// reaped first, together with the other `tmp/` entries older than
    /// `tmp-expiry-secs`.
    ///
    /// A writer outside a transaction takes the repository lock shared, as
    /// [`Repo::set_ref_immediate`] and [`Repo::write_config`] do. So when
    /// `[core] locking` is on, a caller that holds a transaction in
    /// [`LockKind::Exclusive`] and calls such a writer waits for its own lock
    /// until `lock-timeout-secs`, and with `-1` it waits forever.
    pub async fn transaction_with_lock(&self, kind: LockKind) -> Result<Transaction> {
        // Every `[core]` key the open reads is parsed before the lock, so a
        // value the config cannot carry refuses the call at once instead of
        // behind the wait a contended repository imposes.
        let expiry_secs = self.inner.config.tmp_expiry_secs()?;
        let min_free = self.inner.config.min_free_space()?;
        let guard = self.lock_repo(kind).await?;

        let repo = self.clone();
        let staging = ostrya_rt::unblock(move || {
            let mode = repo.inner.config.mode();
            StagingDir::create(repo.inner.repo_fd.as_fd(), expiry_secs, mode)
        })
        .await?;

        // The initial free-space budget: the bytes available above the
        // configured reserve. Each staged object debits it.
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        let budget = ostrya_rt::unblock(move || free_budget(repo_fd.as_fd(), min_free)).await?;

        Ok(Transaction::new(self.clone(), guard, staging, budget))
    }

    /// Take the repository lock in `kind`, held until the guard drops.
    ///
    /// The call reads `[core] locking` and `[core] lock-timeout-secs`. Where
    /// `locking` is true the acquisition retries until the timeout elapses and
    /// then fails with [`Error::LockTimeout`]; with `lock-timeout-secs=-1` it
    /// retries with no limit. Where `locking` is false the guard holds no lock.
    /// `lock-timeout-secs` is read in both cases, so a value the config cannot
    /// carry refuses the call.
    pub(crate) async fn lock_repo(&self, kind: LockKind) -> Result<LockGuard> {
        let locking = self.inner.config.locking()?;
        let timeout_secs = self.inner.config.lock_timeout_secs()?;
        if !locking {
            return Ok(LockGuard::disabled());
        }
        // A cached lock is read on the calling task. Only the first use of the
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

    /// Take the update lock, held until the guard drops.
    ///
    /// The lock is exclusive across processes and inside the process. The
    /// waiters of one process take it in the order of the first poll of their
    /// calls, and only the first of them makes lock requests. The call reads
    /// `[core] lock-timeout-secs`, and the timeout covers the wait in the
    /// queue and the retries against other processes. It then fails with
    /// [`Error::LockTimeout`]; with `lock-timeout-secs=-1` it waits with no
    /// limit, and with `0` it makes one attempt. The call ignores `[core]
    /// locking` and always takes the lock.
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
    /// Against other processes the lock has no order: a waiter can lose every
    /// retry to another process until the timeout elapses.
    pub(crate) async fn lock_update(&self) -> Result<UpdateLockHeld> {
        let timeout_secs = self.inner.config.lock_timeout_secs()?;
        // A cached lock is read on the calling task, so the call joins the
        // queue on its first poll. Only the first use of the handle opens the
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

    /// Take the repository lock shared, then the update lock, held until the
    /// returned value drops.
    ///
    /// The call reads `[core] locking` and `[core] lock-timeout-secs` before
    /// it waits, so a value the config cannot carry refuses the call at once.
    /// Each of the two waits gets the whole timeout. With `locking` false the
    /// repository lock is not taken, and the update lock is taken all the
    /// same.
    pub(crate) async fn lock_for_update(&self) -> Result<UpdateLocks> {
        self.inner.config.locking()?;
        self.inner.config.lock_timeout_secs()?;
        let repo = self.lock_repo(LockKind::Shared).await?;
        let update = self.lock_update().await?;
        Ok(UpdateLocks { update, repo })
    }

    /// Take the repository lock shared, then the update lock, as
    /// [`lock_for_update`](Repo::lock_for_update) does, and run `write` on the
    /// blocking pool under both.
    ///
    /// The locks move into the blocking closure and drop at its end, so a
    /// caller that drops the returned future cannot release them while
    /// `write` still runs.
    pub(crate) async fn write_locked<T, F>(&self, write: F) -> Result<T>
    where
        F: FnOnce(&Repo) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let locks = self.lock_for_update().await?;
        self.write_holding(locks, write).await
    }

    /// Run `write` on the blocking pool under `locks`, and release them when
    /// `write` ends, as [`write_locked`](Repo::write_locked) does. A caller
    /// that must read under the locks before its write takes them first.
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

    /// Whether `held` is a hold of the update lock of this repository.
    pub(crate) fn holds_update_lock(&self, held: &UpdateLockHeld) -> bool {
        self.inner
            .update_lock
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|lock| held.is_of(lock))
    }

    /// Read `config` from disk and parse it, as the open of a handle does.
    /// The handle keeps the configuration it was opened with.
    pub(crate) async fn read_config_file(&self) -> Result<RepoConfig> {
        let repo = self.clone();
        let bytes = ostrya_rt::unblock(move || read_file(repo.repo_fd(), CONFIG)).await?;
        parse_config(&bytes)
    }

    /// The repository root directory fd, anchoring fd-relative access to
    /// `refs/`, `state/`, and the rest of the layout.
    pub(crate) fn repo_fd(&self) -> BorrowedFd<'_> {
        self.inner.repo_fd.as_fd()
    }

    /// The `objects/` directory fd, anchoring loose-object access.
    pub(crate) fn objects_fd(&self) -> BorrowedFd<'_> {
        self.inner.objects_fd.as_fd()
    }

    /// Parse the config bytes and assemble the handle. This step is CPU-only.
    /// `path` is the argument the caller gave the constructor, stored as is for
    /// [`Repo::path`].
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

/// Parse the bytes of `config`. This step is CPU-only.
fn parse_config(bytes: &[u8]) -> Result<RepoConfig> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidFormat("config is not valid UTF-8".into()))?;
    RepoConfig::parse(text)
}

/// The lock wait of a `lock-timeout-secs` value. The config reader refuses a
/// value below -1, so a negative value here is -1: no limit.
fn lock_timeout(secs: i64) -> Option<Duration> {
    u64::try_from(secs).ok().map(Duration::from_secs)
}

/// Compute a transaction's initial free-space budget: the bytes free on the
/// repository filesystem, less the configured `min-free-space` reserve. Runs
/// a synchronous `fstatvfs`.
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

/// Open an existing repository directory and gather its materials.
fn open_materials<Fd: AsFd>(dir: Fd, path: &Path) -> std::io::Result<Materials> {
    let repo_fd = open_dir(dir, path)?;
    materials_from_repo(repo_fd)
}

/// Ensure the repository layout and config exist, then gather its materials.
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

/// Open the `objects/` directory and read the config, given the repo root fd.
fn materials_from_repo(repo_fd: OwnedFd) -> std::io::Result<Materials> {
    let objects_fd = open_dir(&repo_fd, Path::new("objects"))?;
    let config = read_file(&repo_fd, CONFIG)?;
    Ok(Materials {
        repo_fd,
        objects_fd,
        config,
    })
}

/// Open a directory relative to `dir` for fd-relative use.
fn open_dir<Fd: AsFd>(dir: Fd, path: &Path) -> std::io::Result<OwnedFd> {
    let fd = rustix::fs::openat(
        dir,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(fd)
}

/// Read a file's full contents relative to `dir`.
fn read_file<Fd: AsFd>(dir: Fd, path: &str) -> std::io::Result<Vec<u8>> {
    let fd = rustix::fs::openat(dir, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
    let mut buf = Vec::new();
    std::fs::File::from(fd).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Create a directory, treating an existing entry as success. A directory this
/// call creates in a `bare-user-shared` repository is forced to
/// [`perm::SHARED_DIR_MODE`]. An entry that already stands keeps the mode and
/// the group it has.
fn mkdir_idempotent<Fd: AsFd>(dir: Fd, path: &Path, mode: RepoMode) -> std::io::Result<()> {
    match rustix::fs::mkdirat(&dir, path, Mode::from_raw_mode(DIR_MODE)) {
        Ok(()) => perm::force_created_dir(&dir, path, mode),
        Err(Errno::EXIST) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Write the initial `config` if it does not already exist. The file is forced
/// to mode `0644` regardless of the umask, matching the tool.
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

/// The exact config bytes a freshly created repository holds.
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

/// A repository handle is `Send + Sync`, so it moves freely across tasks and
/// threads.
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
