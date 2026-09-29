//! The repository lock: cross-process exclusion plus in-process coordination.
//!
//! ostree guards a repository with an advisory lock on `<repo>/.lock`. This
//! module reproduces that with a classic `fcntl` record lock (`F_SETLK`, via
//! [`rustix::fs::fcntl_lock`]), which shares a lock space with the OFD locks the
//! `ostree` tool takes, so the library and the tool exclude each other on the
//! same repository.
//!
//! `F_SETLK` locks are process-associated: two descriptors in one process do
//! not conflict, and closing any one descriptor to the file drops every lock
//! the process holds on it. Both hazards are avoided by keeping exactly one
//! `.lock` descriptor per repository per process. A process-global registry
//! keyed by the lock file's `(device, inode)` hands every repository handle to
//! one underlying repository -- clones and independent opens alike -- the same
//! [`RepoLock`], so a single descriptor and a shared reference count mediate all
//! in-process holders. The reference count lets several shared holders share
//! one descriptor lock, touching the descriptor only at the transitions that
//! change the effective lock.
//!
//! A dropped lock closes its descriptor and removes its registry entry under
//! the registry mutex, and no call opens a new descriptor to an inode while
//! the registry holds an entry for it. So the descriptor of a dropped lock
//! never closes after a new lock on the same inode is taken.
//!
//! A shared acquire and an exclusive acquire exclude each other inside the
//! process: an exclusive acquire waits while any shared holder stands, and a
//! shared acquire waits while an exclusive holder stands. An exclusive acquire
//! is not re-entrant, so a second one waits for the first to release. A
//! destructive run therefore excludes this process's own transactions for the
//! whole of the run.
//!
//! Cross-process contention is resolved by a non-blocking attempt followed by an
//! [`ostrya_rt::Timer`] retry loop bounded by `lock-timeout-secs`, matching the
//! tool's retry-until-timeout behavior. A loop with no deadline stands for the
//! value `-1`, which the tool reads as no limit. No attempt blocks in the
//! kernel, so a dropped wait leaves no lock request behind.
//!
//! A second lock file, `<repo>/.update.lock`, holds the update lock, which
//! serializes the writes of refs and of the other repository state outside
//! the object store (see [`update`]). The same registry holds both locks, so
//! one inode is never open through two live descriptors in the process, and a
//! lock file that shares its inode with the other lock file is refused.

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

/// The mode a created lock file is requested with, matching the tool. The
/// process umask reduces it. In a `bare-user-shared` repository an `fchmod`
/// after the create restores [`perm::SHARED_LOCK_MODE`].
const LOCK_MODE: u32 = 0o660;

/// The delay between lock-acquisition attempts while contended.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Whether a transaction takes the repository lock shared or exclusive.
///
/// A writing transaction takes it [`Shared`](LockKind::Shared): many commits
/// proceed at once, matching the read lock the tool holds during a commit.
/// Destructive maintenance takes it [`Exclusive`](LockKind::Exclusive).
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
    /// The repository lock of this entry, or `None` for another kind of lock.
    fn repo(&self) -> Option<&Weak<RepoLock>> {
        match self {
            Registered::Repo(weak) => Some(weak),
            Registered::Update(_) => None,
        }
    }

    /// The update lock of this entry, or `None` for another kind of lock.
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
    /// Descriptors to the same inode that an open made after the entry was
    /// registered. Closing one would drop the record locks of `lock`, so each
    /// stays open until the entry is removed.
    parked: Vec<OwnedFd>,
}

/// The process-global registry mapping a lock file's `(device, inode)` to its
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

/// The registry entry for the file `name` under `repo_fd`, found without
/// opening the file: opening and closing another descriptor to a lock file
/// would drop the live lock.
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

/// Return the live lock of type `T` for the file `name` under `repo_fd`, or
/// open the file by the rules of [`open_lock_file`] and register the lock that
/// `make` builds from the descriptor and the `(device, inode)`.
///
/// Two rules keep one open descriptor for each lock inode in the process:
///
/// - A new descriptor is opened only while the registry holds no entry for
///   the inode. A dying entry still owns an open descriptor, so the call waits
///   until the drop of that lock closes it and removes the entry.
/// - A descriptor the open returns for an inode the registry already holds,
///   as a link or a rename made between the probe and the open makes, is never
///   closed here. It is parked in the entry and closes when the entry goes.
///
/// The registry mutex stays held across the open, so no other call registers
/// the inode between the probe and the insert. This serializes the first
/// opens in the process and keeps both rules simple.
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

/// Close the descriptor `fd` of a dropped lock and then remove its entry at
/// `key`, with the parked descriptors, under the registry mutex. Then wake the
/// calls that wait for the entry to go.
///
/// No call replaces an entry, so the entry at `key` is the one of the dropped
/// lock.
fn unregister(key: (u64, u64), fd: Option<OwnedFd>) {
    let registry = registry();
    // A poisoned mutex still guards a whole map. A drop that skipped the
    // removal would leave the waiters for this inode waiting with no end.
    let mut reg = registry.map.lock().unwrap_or_else(PoisonError::into_inner);
    drop(fd);
    drop(reg.remove(&key));
    drop(reg);
    registry.gone.notify_all();
}

/// Open the lock file `name` under `repo_fd`, creating it with [`LOCK_MODE`]
/// on first use, and return the descriptor with the file's `(device, inode)`.
///
/// A file this call creates in a `bare-user-shared` repository is forced to
/// [`perm::SHARED_LOCK_MODE`], so every member of the repository group opens
/// it `O_RDWR` and takes the lock. The create attempt therefore carries
/// `O_EXCL`, which separates the arm that made the file from the arm that
/// found one: a file another member owns keeps the mode it has.
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

/// The refusal of a lock file whose inode the registry holds for another kind
/// of lock, as a hard link between the two lock files makes. A second
/// descriptor to that inode would drop the other lock when it closes, and the
/// two locks would not exclude each other inside the process.
fn shared_inode(name: &str) -> std::io::Error {
    std::io::Error::other(format!(
        "lock file {name} shares its inode with another lock file of the repository"
    ))
}

impl RepoLock {
    /// Return the [`RepoLock`] for the repository rooted at `repo_fd`, creating
    /// `<repo>/.lock` and registering it on first use. Runs synchronous
    /// filesystem calls and is meant to be offloaded to the blocking pool.
    ///
    /// The file is opened by the rules of [`open_lock_file`], through
    /// [`get_or_register`].
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

    /// Add one holder of `kind` without blocking.
    ///
    /// A record lock is process-associated, so the descriptor alone cannot hold
    /// one in-process holder off another. The hold counts do that: an acquire
    /// that the rule excludes reports [`TryOutcome::WouldBlock`], which sends
    /// the caller into the retry loop, and it raises no count.
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

    /// Drop one holder of `kind`, releasing the descriptor lock when the last
    /// holder goes away.
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
        // the two counts is zero and the target reached here is `Unlocked`.
        // Errors are ignored so a release (including Drop) never fails.
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

/// Whether a lock error means the lock is held elsewhere.
fn would_block(e: Errno) -> bool {
    e == Errno::AGAIN || e == Errno::ACCESS
}

/// An acquired lock hold. Releasing happens on drop.
#[derive(Debug)]
pub(crate) struct LockGuard {
    hold: Option<(Arc<RepoLock>, LockKind)>,
}

impl LockGuard {
    /// A guard that holds no lock, for a repository with locking disabled.
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

/// The two locks a writer of the state the update lock covers holds: the
/// update lock and the repository lock, held shared. The fields drop in
/// declaration order, so the update lock is released first.
#[derive(Debug)]
pub(crate) struct UpdateLocks {
    // Both holds are kept for their drop alone. Never read.
    #[allow(dead_code)]
    pub(crate) update: UpdateLockHeld,
    #[allow(dead_code)]
    pub(crate) repo: LockGuard,
}

/// Acquire `kind` on `lock`, retrying until `timeout` elapses. `None` retries
/// with no deadline.
///
/// Each attempt runs on the calling task: it takes the state mutex and makes one
/// non-blocking lock request, so it returns at once. An attempt that ran on the
/// blocking pool could complete after the caller dropped this future and leave
/// a hold that no guard releases.
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
    use std::os::fd::AsFd;

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

    /// Whether the kernel records an exclusive record lock of this process on
    /// the inode `ino`.
    fn holds_write_lock(ino: u64) -> bool {
        let pid = std::process::id().to_string();
        let locks = std::fs::read_to_string("/proc/locks").unwrap();
        locks.lines().any(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.len() > 5
                && fields[1] == "POSIX"
                && fields[3] == "WRITE"
                && fields[4] == pid
                && fields[5].rsplit(':').next() == Some(&ino.to_string())
        })
    }

    /// A lock dropped on another thread closes its descriptor before a new
    /// lock on the same inode is created, so the close does not drop the
    /// record lock of the new one.
    #[test]
    fn a_new_lock_survives_the_close_of_a_dropped_one() {
        use std::os::unix::fs::MetadataExt;

        for _ in 0..20 {
            let scratch = Scratch::new("redrop");
            let old = RepoLock::get_or_create(scratch.repo_fd(), RepoMode::Bare).unwrap();
            let ino = std::fs::metadata(scratch._dir.join(LOCK_FILE))
                .unwrap()
                .ino();
            let weak = Arc::downgrade(&old);

            // The held registry mutex stops the drop of `old` before it
            // closes the descriptor. The new lock is then asked for at once.
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

            assert!(holds_write_lock(ino), "the close dropped the new lock");
            new.release(LockKind::Exclusive);
        }
    }
}
