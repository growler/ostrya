//! The repository lock and the process-global registry of lock files.
//!
//! [`LockKind`] holds the rules that a caller sees: the lock file, the
//! in-process rules, and the wait. The record lock calls go through
//! [`rustix::fs::fcntl_lock`]. The retry loop waits on [`ostrya_rt::Timer`].
//!
//! A process-global registry maps the `(device, inode)` of each lock file to
//! its lock. Each handle to one repository gets the same [`RepoLock`]: clones
//! and separate opens. Hold counts let many shared holders share one record
//! lock. The calls change the record lock only when the effective lock
//! changes.
//!
//! A dropped lock closes its descriptor and removes its registry entry under
//! the registry mutex. No call opens a new descriptor to an inode while the
//! registry holds an entry for it. As a result, the descriptor of a dropped
//! lock never closes after the process takes a new lock on the same inode.
//!
//! The update lock on `<repo>/.update.lock` serializes the writes of refs and
//! of the other repository state outside the object store (see [`update`]).
//! The same registry holds both locks, so the process never opens one inode
//! through two live descriptors.

use std::collections::HashMap;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use ostrya_core::RepoMode;
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::perm;

mod update;
#[cfg(test)]
pub(crate) use update::held_in_process as update_lock_held_in_process;
pub(crate) use update::{UpdateLock, UpdateLockHeld, acquire_update};

/// The repository lock file, relative to the repository root.
const LOCK_FILE: &str = ".lock";

/// The mode of a new lock file in the create call. The `ostree` command uses
/// the same mode. The process umask reduces it. In a `bare-user-shared`
/// repository, an `fchmod` after the create sets [`perm::SHARED_LOCK_MODE`].
const LOCK_MODE: u32 = 0o660;

/// The delay between two lock attempts while another holder has the lock.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The kind of hold on the repository lock: shared or exclusive.
///
/// A writing transaction takes the lock [`Shared`](LockKind::Shared), so many
/// commits run at the same time. The `ostree` command also holds a read lock
/// during a commit. [`Repo::prune`](crate::Repo::prune) takes the lock
/// [`Exclusive`](LockKind::Exclusive).
///
/// If `[core] locking` is `false`, ostrya does not take the repository lock
/// ([`RepoConfig::locking`](crate::config::RepoConfig::locking)). The default
/// is `true`.
///
/// # Lock file
///
/// The repository lock is an `fcntl` record lock (`F_SETLK`) on
/// `<repo>/.lock`. The `ostree` command takes OFD locks on the same file.
/// Record locks and OFD locks share one lock space, so ostrya and the `ostree`
/// command exclude each other on one repository.
///
/// If the file does not exist, the first lock creates it with mode `0660`.
/// The `ostree` command uses the same mode. The process umask reduces this
/// mode.
///
/// In a `bare-user-shared` repository, ostrya sets the mode of a file that it
/// creates to `0660` after the create. Each member of the repository group can
/// then open the file for reading and writing. A file that another member
/// created keeps its mode.
///
/// If `.lock` and `.update.lock` are hard links to one inode, the repository
/// lock and the update lock refuse each other. While the process has one of
/// the two files open as its lock file, a lock on the other fails with
/// [`Error::Io`].
///
/// # In-process rules
///
/// An `F_SETLK` lock belongs to the process. Two descriptors in one process
/// do not conflict. Also, the close of any descriptor to the file releases
/// each lock of the process on it.
///
/// To prevent both faults, ostrya keeps one `.lock` descriptor for each
/// repository in each process. All handles to one repository share it, clones
/// and separate opens alike.
///
/// Hold counts in the process apply these rules:
///
/// - Many shared holders can hold the lock at the same time. They share one
///   record lock.
/// - An exclusive acquire waits while a shared holder exists.
/// - A shared acquire waits while an exclusive holder exists.
/// - An exclusive hold is not re-entrant. A second exclusive acquire waits for
///   the release of the first, also when the same caller makes it.
/// - When the last holder releases the lock, ostrya releases the record lock.
///
/// # A holder that waits for its own lock
///
/// No call detects a caller that waits for its own hold. This wait occurs if
/// a caller that holds the lock makes an acquire that its hold excludes:
///
/// - A second exclusive acquire while it holds the lock exclusive.
/// - A shared acquire while it holds the lock exclusive. A
///   [`Transaction`](crate::Transaction) and
///   [`Repo::set_ref_immediate`](crate::Repo::set_ref_immediate) make a
///   shared acquire.
/// - An exclusive acquire, for example [`Repo::prune`](crate::Repo::prune),
///   while it holds the lock shared, for example through a transaction or an
///   [`UpdateGuard`](crate::UpdateGuard).
///
/// The wait lasts until `[core] lock-timeout-secs` passes. The acquire then
/// fails with [`Error::LockTimeout`]. If the value is `-1`, the caller waits
/// forever. If `[core] locking` is `false`, no such wait occurs.
///
/// # Waiting
///
/// An acquire makes one non-blocking lock request. If another process holds a
/// conflicting lock, or an in-process rule makes the acquire wait, the acquire
/// tries again every 100 ms. The `ostree` command also tries again until its
/// timeout.
///
/// `[core] lock-timeout-secs` sets the limit of the wait, in seconds
/// ([`RepoConfig::lock_timeout_secs`](crate::config::RepoConfig::lock_timeout_secs)).
/// The default is `300`. If the wait passes the limit, the acquire fails with
/// [`Error::LockTimeout`]. The value `0` makes one attempt. The value `-1`
/// means no limit, as in the `ostree` command.
///
/// No lock request blocks in the kernel. If a caller drops a future that
/// waits for the lock, no lock request stays behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    /// A shared (read) lock.
    Shared,
    /// An exclusive (write) lock.
    Exclusive,
}

/// The effective lock currently applied to the `.lock` descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OsLock {
    Unlocked,
    Shared,
    Exclusive,
}

/// In-process hold counts and the effective descriptor lock.
#[derive(Debug)]
struct LockState {
    shared: usize,
    exclusive: usize,
    os: OsLock,
}

/// The outcome of one non-blocking acquisition attempt.
enum TryOutcome {
    Acquired,
    WouldBlock,
}

/// The per-repository lock, shared by every handle to one repository in a
/// process.
#[derive(Debug)]
pub(crate) struct RepoLock {
    key: (u64, u64),
    /// The `.lock` descriptor. It is `Some` until the drop closes it under the
    /// registry mutex.
    fd: Option<OwnedFd>,
    state: Mutex<LockState>,
}

/// A lock the registry holds for one lock file.
#[derive(Debug)]
enum Registered {
    Repo(Weak<RepoLock>),
    Update(Weak<UpdateLock>),
}

impl Registered {
    /// Returns the repository lock of this entry, or `None` for another kind
    /// of lock.
    fn repo(&self) -> Option<&Weak<RepoLock>> {
        match self {
            Registered::Repo(weak) => Some(weak),
            Registered::Update(_) => None,
        }
    }

    /// Returns the update lock of this entry, or `None` for another kind of
    /// lock.
    fn update(&self) -> Option<&Weak<UpdateLock>> {
        match self {
            Registered::Update(weak) => Some(weak),
            Registered::Repo(_) => None,
        }
    }
}

/// The registry entry of one lock file.
#[derive(Debug)]
struct Entry {
    lock: Registered,
    /// The descriptors to the same inode that an open made after the registry
    /// added the entry. The close of one of them drops the record locks of
    /// `lock`, so each one stays open until the registry removes the entry.
    parked: Vec<OwnedFd>,
}

/// The process-global map from the `(device, inode)` of a lock file to its
/// lock.
type LockRegistry = HashMap<(u64, u64), Entry>;

/// The registry, with the condition variable that a dropped lock signals
/// after it removes its entry.
struct Registry {
    map: Mutex<LockRegistry>,
    gone: Condvar,
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry {
        map: Mutex::new(HashMap::new()),
        gone: Condvar::new(),
    })
}

/// Returns the registry entry for the file `name` under `repo_fd`.
///
/// The call does not open the file. The open and the close of a second
/// descriptor to a lock file drop the live lock.
fn probe<'r>(reg: &'r LockRegistry, repo_fd: BorrowedFd<'_>, name: &str) -> Option<&'r Entry> {
    let stat = rustix::fs::statat(repo_fd, name, AtFlags::empty()).ok()?;
    reg.get(&(stat.st_dev, stat.st_ino))
}

/// What a registry entry holds for a lock of type `T`.
enum Found<T> {
    /// A live lock of type `T`.
    Live(Arc<T>),
    /// A lock of type `T` whose last reference is gone and whose drop has not
    /// yet closed its descriptor.
    Dying,
    /// A lock of another type.
    Other,
}

fn find<T>(entry: &Entry, view: fn(&Registered) -> Option<&Weak<T>>) -> Found<T> {
    match view(&entry.lock) {
        Some(weak) => weak.upgrade().map_or(Found::Dying, Found::Live),
        None => Found::Other,
    }
}

/// Returns the live lock of type `T` for the file `name` under `repo_fd`.
///
/// If no live lock exists, the call opens the file by the rules of
/// [`open_lock_file`]. It then registers the lock that `make` builds from the
/// descriptor and the `(device, inode)`.
///
/// Two rules keep one open descriptor for each lock inode in the process:
///
/// - The call opens a new descriptor only while the registry holds no entry
///   for the inode. A dying entry still owns an open descriptor. The call
///   waits until the drop of that lock closes it and removes the entry.
/// - A link or a rename can occur between the probe and the open. The open
///   then returns a descriptor for an inode that the registry already holds.
///   The call never closes this descriptor. It parks the descriptor in the
///   entry, and the descriptor closes when the entry goes.
///
/// The registry mutex stays held across the open, so no other call registers
/// the inode between the probe and the insert. The first opens in the process
/// therefore run one at a time.
fn get_or_register<T>(
    repo_fd: BorrowedFd<'_>,
    name: &str,
    repo_mode: RepoMode,
    view: fn(&Registered) -> Option<&Weak<T>>,
    make: impl FnOnce(OwnedFd, (u64, u64)) -> (Arc<T>, Registered),
) -> std::io::Result<Arc<T>> {
    let registry = registry();
    let mut reg = registry.map.lock().unwrap();
    loop {
        match probe(&reg, repo_fd, name).map(|entry| find(entry, view)) {
            Some(Found::Live(existing)) => return Ok(existing),
            Some(Found::Other) => return Err(shared_inode(name)),
            Some(Found::Dying) => {
                reg = registry.gone.wait(reg).unwrap();
                continue;
            }
            None => {}
        }

        let (fd, key) = open_lock_file(repo_fd, name, repo_mode)?;
        let Some(entry) = reg.get_mut(&key) else {
            let (lock, registered) = make(fd, key);
            reg.insert(
                key,
                Entry {
                    lock: registered,
                    parked: Vec::new(),
                },
            );
            return Ok(lock);
        };
        // The probe finds a link that stood before the open. This arm catches
        // one made between the probe and the open.
        let found = find(entry, view);
        entry.parked.push(fd);
        match found {
            Found::Live(existing) => return Ok(existing),
            Found::Other => return Err(shared_inode(name)),
            Found::Dying => reg = registry.gone.wait(reg).unwrap(),
        }
    }
}

/// Closes the descriptor `fd` of a dropped lock and removes its entry at
/// `key`, with the parked descriptors, under the registry mutex.
///
/// The call then wakes the calls that wait for the entry to go. No call
/// replaces an entry, so the entry at `key` belongs to the dropped lock.
fn unregister(key: (u64, u64), fd: Option<OwnedFd>) {
    let registry = registry();
    // A poisoned mutex still guards a whole map. If a drop skips the removal,
    // the waiters for this inode wait with no end.
    let mut reg = registry.map.lock().unwrap_or_else(PoisonError::into_inner);
    drop(fd);
    drop(reg.remove(&key));
    drop(reg);
    registry.gone.notify_all();
}

/// Opens the lock file `name` under `repo_fd` and returns the descriptor with
/// the `(device, inode)` of the file.
///
/// If the file does not exist, the call creates it with [`LOCK_MODE`]. In a
/// `bare-user-shared` repository, the call sets [`perm::SHARED_LOCK_MODE`] on
/// a file that it creates. Each member of the repository group can then open
/// the file `O_RDWR` and take the lock. The create attempt carries `O_EXCL` to
/// tell the arm that made the file from the arm that found one. A file that
/// another member owns keeps its mode.
fn open_lock_file(
    repo_fd: BorrowedFd<'_>,
    name: &str,
    repo_mode: RepoMode,
) -> std::io::Result<(OwnedFd, (u64, u64))> {
    let fd = match rustix::fs::openat(
        repo_fd,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(LOCK_MODE),
    ) {
        Ok(fd) => {
            perm::force_created_mode(&fd, repo_mode, perm::SHARED_LOCK_MODE)?;
            fd
        }
        Err(Errno::EXIST) => {
            rustix::fs::openat(repo_fd, name, OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())?
        }
        Err(e) => return Err(e.into()),
    };
    let stat = rustix::fs::fstat(&fd)?;
    Ok((fd, (stat.st_dev, stat.st_ino)))
}

/// Returns the error for a lock file whose inode the registry holds for
/// another kind of lock.
///
/// A hard link between the two lock files causes this state. The close of a
/// second descriptor to that inode drops the other lock. Also, the two locks
/// do not exclude each other inside the process.
fn shared_inode(name: &str) -> std::io::Error {
    std::io::Error::other(format!(
        "lock file {name} shares its inode with another lock file of the repository"
    ))
}

impl RepoLock {
    /// Returns the [`RepoLock`] for the repository at `repo_fd`.
    ///
    /// The first use creates `<repo>/.lock` and registers the lock. The call
    /// opens the file by the rules of [`open_lock_file`], through
    /// [`get_or_register`]. It runs synchronous file system calls, so the
    /// caller runs it on the blocking pool.
    pub(crate) fn get_or_create(
        repo_fd: BorrowedFd<'_>,
        repo_mode: RepoMode,
    ) -> std::io::Result<Arc<RepoLock>> {
        get_or_register(
            repo_fd,
            LOCK_FILE,
            repo_mode,
            Registered::repo,
            |fd, key| {
                let lock = Arc::new(RepoLock {
                    key,
                    fd: Some(fd),
                    state: Mutex::new(LockState {
                        shared: 0,
                        exclusive: 0,
                        os: OsLock::Unlocked,
                    }),
                });
                let registered = Registered::Repo(Arc::downgrade(&lock));
                (lock, registered)
            },
        )
    }

    fn fd(&self) -> &OwnedFd {
        self.fd
            .as_ref()
            .expect("the descriptor stays open until the drop")
    }

    /// Adds one holder of `kind` without blocking.
    ///
    /// A record lock belongs to the process, so the descriptor alone cannot
    /// keep one in-process holder from another. The hold counts do that. If a
    /// rule excludes the acquire, the call reports [`TryOutcome::WouldBlock`]
    /// and raises no count. The caller then goes into the retry loop.
    fn try_acquire(&self, kind: LockKind) -> std::io::Result<TryOutcome> {
        let mut st = self.state.lock().unwrap();
        match kind {
            LockKind::Shared => {
                // An exclusive holder excludes every other holder in this
                // process.
                if st.exclusive > 0 {
                    return Ok(TryOutcome::WouldBlock);
                }
                if st.os == OsLock::Shared {
                    st.shared += 1;
                    return Ok(TryOutcome::Acquired);
                }
                match rustix::fs::fcntl_lock(self.fd(), FlockOperation::NonBlockingLockShared) {
                    Ok(()) => {
                        st.os = OsLock::Shared;
                        st.shared += 1;
                        Ok(TryOutcome::Acquired)
                    }
                    Err(e) if would_block(e) => Ok(TryOutcome::WouldBlock),
                    Err(e) => Err(e.into()),
                }
            }
            LockKind::Exclusive => {
                // An exclusive acquire waits for every other holder, an
                // exclusive one included: the hold is not re-entrant, so two
                // callers never share it.
                if st.shared > 0 || st.exclusive > 0 {
                    return Ok(TryOutcome::WouldBlock);
                }
                match rustix::fs::fcntl_lock(self.fd(), FlockOperation::NonBlockingLockExclusive) {
                    Ok(()) => {
                        st.os = OsLock::Exclusive;
                        st.exclusive += 1;
                        Ok(TryOutcome::Acquired)
                    }
                    Err(e) if would_block(e) => Ok(TryOutcome::WouldBlock),
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    /// Drops one holder of `kind`. When the last holder goes, the call releases
    /// the record lock.
    fn release(&self, kind: LockKind) {
        let mut st = self.state.lock().unwrap();
        match kind {
            LockKind::Shared => st.shared = st.shared.saturating_sub(1),
            LockKind::Exclusive => st.exclusive = st.exclusive.saturating_sub(1),
        }
        let target = if st.exclusive > 0 {
            OsLock::Exclusive
        } else if st.shared > 0 {
            OsLock::Shared
        } else {
            OsLock::Unlocked
        };
        if target == st.os {
            return;
        }
        // A shared holder and an exclusive holder exclude each other, so one of
        // the two counts is zero, and the target here is `Unlocked`. The call
        // ignores errors, so a release never fails, also in a drop.
        let _ = rustix::fs::fcntl_lock(self.fd(), FlockOperation::Unlock);
        st.os = target;
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        // Closing the descriptor releases any residual record lock.
        unregister(self.key, self.fd.take());
    }
}

/// Returns `true` if a lock error means that another holder has the lock.
fn would_block(e: Errno) -> bool {
    e == Errno::AGAIN || e == Errno::ACCESS
}

/// A hold on the repository lock. The drop of the guard releases the hold.
#[derive(Debug)]
pub(crate) struct LockGuard {
    hold: Option<(Arc<RepoLock>, LockKind)>,
}

impl LockGuard {
    /// Creates a guard that holds no lock, for a repository with `[core]
    /// locking` set to `false`.
    pub(crate) fn disabled() -> LockGuard {
        LockGuard { hold: None }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Some((lock, kind)) = &self.hold {
            lock.release(*kind);
        }
    }
}

/// The two locks that a writer of the update-lock state holds: the update
/// lock, and the repository lock held shared. The fields drop in declaration
/// order, so the drop releases the update lock first.
#[derive(Debug)]
pub(crate) struct UpdateLocks {
    // The code never reads the two fields. Each field exists for its drop.
    #[allow(dead_code)]
    pub(crate) update: UpdateLockHeld,
    #[allow(dead_code)]
    pub(crate) repo: LockGuard,
}

/// Acquires `kind` on `lock` and tries again until `timeout` passes. `None`
/// tries again with no limit.
///
/// Each attempt runs on the calling task. It takes the state mutex and makes
/// one non-blocking lock request, so it returns at once. If an attempt ran on
/// the blocking pool, it can complete after the caller drops this future. It
/// then leaves a hold that no guard releases.
pub(crate) async fn acquire(
    lock: Arc<RepoLock>,
    kind: LockKind,
    timeout: Option<Duration>,
) -> Result<LockGuard> {
    // A timeout past the range of `Instant` has no deadline.
    let deadline = timeout.and_then(|t| Some((Instant::now().checked_add(t)?, t.as_secs() as i64)));
    loop {
        match lock.try_acquire(kind)? {
            TryOutcome::Acquired => {
                return Ok(LockGuard {
                    hold: Some((lock, kind)),
                });
            }
            TryOutcome::WouldBlock => {
                let wait = match deadline {
                    Some((deadline, secs)) => {
                        let now = Instant::now();
                        if now >= deadline {
                            return Err(Error::LockTimeout { secs });
                        }
                        POLL_INTERVAL.min(deadline - now)
                    }
                    None => POLL_INTERVAL,
                };
                ostrya_rt::Timer::after(wait).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, AsRawFd};

    /// A repository root fd over a throwaway directory, for lock unit tests.
    struct Scratch {
        _dir: std::path::PathBuf,
        fd: OwnedFd,
    }

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("ostrya-lock-{}-{tag}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let fd = rustix::fs::openat(
                rustix::fs::CWD,
                &dir,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            Scratch { _dir: dir, fd }
        }

        fn repo_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self._dir);
        }
    }

    fn os_lock(lock: &RepoLock) -> OsLock {
        lock.state.lock().unwrap().os
    }

    /// The in-process hold counts, as `(shared, exclusive)`.
    fn counts(lock: &RepoLock) -> (usize, usize) {
        let st = lock.state.lock().unwrap();
        (st.shared, st.exclusive)
    }

    #[test]
    fn shared_holders_share_one_descriptor_lock() {
        let scratch = Scratch::new("shared");
        let lock = RepoLock::get_or_create(scratch.repo_fd(), RepoMode::Bare).unwrap();

        assert!(matches!(
            lock.try_acquire(LockKind::Shared).unwrap(),
            TryOutcome::Acquired
        ));
        assert!(matches!(
            lock.try_acquire(LockKind::Shared).unwrap(),
            TryOutcome::Acquired
        ));
        assert_eq!(os_lock(&lock), OsLock::Shared);

        lock.release(LockKind::Shared);
        assert_eq!(os_lock(&lock), OsLock::Shared); // one holder remains
        lock.release(LockKind::Shared);
        assert_eq!(os_lock(&lock), OsLock::Unlocked);
    }

    #[test]
    fn exclusive_waits_for_a_shared_holder() {
        let scratch = Scratch::new("wait");
        let lock = RepoLock::get_or_create(scratch.repo_fd(), RepoMode::Bare).unwrap();

        lock.try_acquire(LockKind::Shared).unwrap();
        assert_eq!(os_lock(&lock), OsLock::Shared);

        // The exclusive attempt reports `WouldBlock` while the shared holder
        // stands, and the effective lock stays shared.
        assert!(matches!(
            lock.try_acquire(LockKind::Exclusive).unwrap(),
            TryOutcome::WouldBlock
        ));
        assert_eq!(os_lock(&lock), OsLock::Shared);
        assert_eq!(counts(&lock), (1, 0));

        // Once the shared holder releases, the attempt succeeds.
        lock.release(LockKind::Shared);
        assert_eq!(os_lock(&lock), OsLock::Unlocked);
        assert!(matches!(
            lock.try_acquire(LockKind::Exclusive).unwrap(),
            TryOutcome::Acquired
        ));
        assert_eq!(os_lock(&lock), OsLock::Exclusive);

        lock.release(LockKind::Exclusive);
        assert_eq!(os_lock(&lock), OsLock::Unlocked);
    }

    #[test]
    fn shared_waits_for_an_exclusive_holder() {
        let scratch = Scratch::new("shared-waits");
        let lock = RepoLock::get_or_create(scratch.repo_fd(), RepoMode::Bare).unwrap();

        assert!(matches!(
            lock.try_acquire(LockKind::Exclusive).unwrap(),
            TryOutcome::Acquired
        ));
        assert_eq!(os_lock(&lock), OsLock::Exclusive);

        // The shared attempt reports `WouldBlock` while the exclusive holder
        // stands, the effective lock stays exclusive, and no count rises.
        assert!(matches!(
            lock.try_acquire(LockKind::Shared).unwrap(),
            TryOutcome::WouldBlock
        ));
        assert_eq!(os_lock(&lock), OsLock::Exclusive);
        assert_eq!(counts(&lock), (0, 1));

        // Once the exclusive holder releases, the attempt succeeds.
        lock.release(LockKind::Exclusive);
        assert_eq!(os_lock(&lock), OsLock::Unlocked);
        assert_eq!(counts(&lock), (0, 0));
        assert!(matches!(
            lock.try_acquire(LockKind::Shared).unwrap(),
            TryOutcome::Acquired
        ));
        assert_eq!(os_lock(&lock), OsLock::Shared);
        assert_eq!(counts(&lock), (1, 0));

        lock.release(LockKind::Shared);
        assert_eq!(os_lock(&lock), OsLock::Unlocked);
    }

    #[test]
    fn a_second_exclusive_waits_for_the_first() {
        let scratch = Scratch::new("exclusive-waits");
        let lock = RepoLock::get_or_create(scratch.repo_fd(), RepoMode::Bare).unwrap();

        assert!(matches!(
            lock.try_acquire(LockKind::Exclusive).unwrap(),
            TryOutcome::Acquired
        ));

        // The hold is not re-entrant: a second exclusive attempt waits, and the
        // count stays at the one holder.
        assert!(matches!(
            lock.try_acquire(LockKind::Exclusive).unwrap(),
            TryOutcome::WouldBlock
        ));
        assert_eq!(os_lock(&lock), OsLock::Exclusive);
        assert_eq!(counts(&lock), (0, 1));

        // Once the first holder releases, the second attempt succeeds.
        lock.release(LockKind::Exclusive);
        assert_eq!(os_lock(&lock), OsLock::Unlocked);
        assert_eq!(counts(&lock), (0, 0));
        assert!(matches!(
            lock.try_acquire(LockKind::Exclusive).unwrap(),
            TryOutcome::Acquired
        ));
        assert_eq!(os_lock(&lock), OsLock::Exclusive);
        assert_eq!(counts(&lock), (0, 1));

        lock.release(LockKind::Exclusive);
        assert_eq!(os_lock(&lock), OsLock::Unlocked);
    }

    #[test]
    fn one_repo_lock_is_shared_across_handles_and_reclaimed() {
        let scratch = Scratch::new("registry");
        let a = RepoLock::get_or_create(scratch.repo_fd(), RepoMode::Bare).unwrap();
        let b = RepoLock::get_or_create(scratch.repo_fd(), RepoMode::Bare).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "same repo yields one shared lock");
        let key = a.key;

        drop(a);
        drop(b);
        assert!(
            !registry().map.lock().unwrap().contains_key(&key),
            "registry entry is reclaimed once the last handle drops"
        );
    }

    /// Returns `true` if the kernel records an exclusive record lock that
    /// this process set through the descriptor of `lock`.
    ///
    /// The fdinfo of a descriptor lists only the locks that this process set
    /// through that descriptor. The kernel builds it in one pass, so it is a
    /// consistent snapshot. A read of `/proc/locks` takes several calls. If
    /// other locks change between two of them, a line goes missing.
    fn holds_write_lock(lock: &RepoLock) -> bool {
        let path = format!("/proc/self/fdinfo/{}", lock.fd().as_raw_fd());
        let info = std::fs::read_to_string(path).unwrap();
        info.lines().any(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.len() > 4 && fields[0] == "lock:" && fields[2] == "POSIX" && fields[4] == "WRITE"
        })
    }

    /// A lock dropped on another thread closes its descriptor before the
    /// process creates a new lock on the same inode. As a result, the close
    /// does not drop the record lock of the new lock.
    #[test]
    fn a_new_lock_survives_the_close_of_a_dropped_one() {
        for _ in 0..20 {
            let scratch = Scratch::new("redrop");
            let old = RepoLock::get_or_create(scratch.repo_fd(), RepoMode::Bare).unwrap();
            let weak = Arc::downgrade(&old);

            // The held registry mutex stops the drop of `old` before it
            // closes the descriptor. The test then asks for the new lock at
            // once.
            let reg = registry().map.lock().unwrap();
            let dropper = std::thread::spawn(move || drop(old));
            while weak.strong_count() > 0 {
                std::thread::yield_now();
            }
            drop(reg);
            let new = RepoLock::get_or_create(scratch.repo_fd(), RepoMode::Bare).unwrap();
            assert!(matches!(
                new.try_acquire(LockKind::Exclusive).unwrap(),
                TryOutcome::Acquired
            ));
            dropper.join().unwrap();

            assert!(holds_write_lock(&new), "the close dropped the new lock");
            new.release(LockKind::Exclusive);
        }
    }
}
