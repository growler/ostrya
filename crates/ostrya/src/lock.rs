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
//! in-process holders. The reference count also supports nested locks and
//! shared-to-exclusive upgrade and downgrade, touching the descriptor only at
//! the transitions that change the effective lock.
//!
//! Cross-process contention is resolved by a non-blocking attempt followed by an
//! [`ostrya_rt::Timer`] retry loop bounded by `lock-timeout-secs`, matching the
//! tool's retry-until-timeout behavior.

use std::collections::HashMap;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};

/// The repository lock file, relative to the repository root.
const LOCK_FILE: &str = ".lock";

/// The mode a created `.lock` file is given, matching the tool.
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
    fd: OwnedFd,
    state: Mutex<LockState>,
}

/// The process-global registry mapping a lock file's `(device, inode)` to its
/// live [`RepoLock`].
type LockRegistry = HashMap<(u64, u64), Weak<RepoLock>>;

fn registry() -> &'static Mutex<LockRegistry> {
    static REGISTRY: OnceLock<Mutex<LockRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

impl RepoLock {
    /// Return the [`RepoLock`] for the repository rooted at `repo_fd`, creating
    /// `<repo>/.lock` and registering it on first use. Runs synchronous
    /// filesystem calls and is meant to be offloaded to the blocking pool.
    pub(crate) fn get_or_create(repo_fd: BorrowedFd<'_>) -> std::io::Result<Arc<RepoLock>> {
        let mut reg = registry().lock().unwrap();

        // Probe an existing entry without opening a second descriptor: opening
        // and closing another descriptor to `.lock` would drop the live lock.
        if let Ok(stat) = rustix::fs::statat(repo_fd, LOCK_FILE, AtFlags::empty()) {
            let key = (stat.st_dev, stat.st_ino);
            if let Some(existing) = reg.get(&key).and_then(Weak::upgrade) {
                return Ok(existing);
            }
        }

        let fd = rustix::fs::openat(
            repo_fd,
            LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC,
            Mode::from_raw_mode(LOCK_MODE),
        )?;
        let stat = rustix::fs::fstat(&fd)?;
        let key = (stat.st_dev, stat.st_ino);

        let lock = Arc::new(RepoLock {
            key,
            fd,
            state: Mutex::new(LockState {
                shared: 0,
                exclusive: 0,
                os: OsLock::Unlocked,
            }),
        });
        reg.insert(key, Arc::downgrade(&lock));
        Ok(lock)
    }

    /// Add one holder of `kind` without blocking.
    fn try_acquire(&self, kind: LockKind) -> std::io::Result<TryOutcome> {
        let mut st = self.state.lock().unwrap();
        match kind {
            LockKind::Shared => {
                if matches!(st.os, OsLock::Shared | OsLock::Exclusive) {
                    st.shared += 1;
                    return Ok(TryOutcome::Acquired);
                }
                match rustix::fs::fcntl_lock(&self.fd, FlockOperation::NonBlockingLockShared) {
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
                if st.os == OsLock::Exclusive {
                    st.exclusive += 1;
                    return Ok(TryOutcome::Acquired);
                }
                match rustix::fs::fcntl_lock(&self.fd, FlockOperation::NonBlockingLockExclusive) {
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

    /// Drop one holder of `kind`, weakening or releasing the descriptor lock
    /// when the last holder of a level goes away.
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
        // A release never escalates to exclusive, so the descriptor operation is
        // an unlock or a downgrade to shared, neither of which blocks on our own
        // descriptor. Errors are ignored so a release (including Drop) never
        // fails.
        let op = match target {
            OsLock::Unlocked => FlockOperation::Unlock,
            OsLock::Shared => FlockOperation::LockShared,
            OsLock::Exclusive => FlockOperation::LockExclusive,
        };
        let _ = rustix::fs::fcntl_lock(&self.fd, op);
        st.os = target;
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        // Remove our now-dead registry entry, unless it was already replaced by
        // a newer lock over the same inode.
        if let Ok(mut reg) = registry().lock()
            && let Some(weak) = reg.get(&self.key)
            && weak.strong_count() == 0
        {
            reg.remove(&self.key);
        }
        // Closing `self.fd` releases any residual record lock.
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

/// Acquire `kind` on `lock`, retrying until `timeout` elapses.
pub(crate) async fn acquire(
    lock: Arc<RepoLock>,
    kind: LockKind,
    timeout: Duration,
) -> Result<LockGuard> {
    let deadline = Instant::now() + timeout;
    loop {
        let probe = lock.clone();
        match ostrya_rt::unblock(move || probe.try_acquire(kind)).await? {
            TryOutcome::Acquired => {
                return Ok(LockGuard {
                    hold: Some((lock, kind)),
                });
            }
            TryOutcome::WouldBlock => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(Error::LockTimeout {
                        secs: timeout.as_secs() as i64,
                    });
                }
                let wait = POLL_INTERVAL.min(deadline - now);
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

    #[test]
    fn shared_holders_share_one_descriptor_lock() {
        let scratch = Scratch::new("shared");
        let lock = RepoLock::get_or_create(scratch.repo_fd()).unwrap();

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
    fn exclusive_upgrades_and_downgrades_around_a_shared_holder() {
        let scratch = Scratch::new("upgrade");
        let lock = RepoLock::get_or_create(scratch.repo_fd()).unwrap();

        lock.try_acquire(LockKind::Shared).unwrap();
        assert_eq!(os_lock(&lock), OsLock::Shared);

        // Upgrade: an exclusive holder joins the shared holder on the same
        // descriptor, so the effective lock becomes exclusive.
        lock.try_acquire(LockKind::Exclusive).unwrap();
        assert_eq!(os_lock(&lock), OsLock::Exclusive);

        // Downgrade: dropping the exclusive holder returns to shared while the
        // shared holder remains.
        lock.release(LockKind::Exclusive);
        assert_eq!(os_lock(&lock), OsLock::Shared);

        lock.release(LockKind::Shared);
        assert_eq!(os_lock(&lock), OsLock::Unlocked);
    }

    #[test]
    fn one_repo_lock_is_shared_across_handles_and_reclaimed() {
        let scratch = Scratch::new("registry");
        let a = RepoLock::get_or_create(scratch.repo_fd()).unwrap();
        let b = RepoLock::get_or_create(scratch.repo_fd()).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "same repo yields one shared lock");
        let key = a.key;

        drop(a);
        drop(b);
        assert!(
            !registry().lock().unwrap().contains_key(&key),
            "registry entry is reclaimed once the last handle drops"
        );
    }
}
