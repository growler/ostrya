//! The update lock: the lock that serializes the writes of refs and of the
//! other repository state outside the object store.
//!
//! A holder of [`crate::UpdateGuard`] holds it, the receive path holds it while
//! it reads the state of its target refs, checks it, and commits, and summary
//! regeneration holds it while it refreshes the anchor commit and writes the
//! summary.
//!
//! The lock is an exclusive `fcntl` record lock (`F_SETLK`) on
//! `<repo>/.update.lock`, beside `.lock`. The file is opened by the rules of
//! `.lock` and is held through the same process-global registry, so the process
//! keeps one descriptor to it. The tool never opens this file, so the lock
//! excludes port processes alone.
//!
//! Inside the process the lock is exclusive too. Its waiters queue in the order
//! of their first poll, and only the head of the queue makes lock requests.
//! Against another process the head runs the retry loop of the repository lock:
//! one non-blocking request, then an [`ostrya_rt::Timer`] wait of at most
//! [`POLL_INTERVAL`]. No request blocks in the kernel, so a dropped wait leaves
//! no lock request behind. A release always drops the record lock, so another
//! process can take the lock between two holders of this process.
//!
//! The lock ignores `[core] locking` and always takes the record lock.

use std::collections::VecDeque;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use futures_lite::FutureExt;
use ostrya_core::RepoMode;
use rustix::fs::FlockOperation;

use super::{POLL_INTERVAL, Registered, get_or_register, unregister, would_block};
use crate::error::{Error, Result};

/// The update lock file, relative to the repository root.
const UPDATE_LOCK_FILE: &str = ".update.lock";

/// The in-process holder and the queue of waiters.
#[derive(Debug)]
struct UpdateState {
    /// Whether a guard holds the lock.
    held: bool,
    /// The ticket the next waiter takes.
    next_ticket: u64,
    /// The waiting tickets in request order, each with the waker of its last
    /// pending poll.
    queue: VecDeque<(u64, Option<Waker>)>,
}

/// The per-repository update lock, shared by every handle to one repository
/// in a process.
#[derive(Debug)]
pub(crate) struct UpdateLock {
    key: (u64, u64),
    /// The `.update.lock` descriptor. It is `Some` until the drop closes
    /// it under the registry mutex.
    fd: Option<OwnedFd>,
    state: Mutex<UpdateState>,
}

impl UpdateLock {
    /// Return the [`UpdateLock`] for the repository rooted at `repo_fd`,
    /// creating `<repo>/.update.lock` and registering it on first use. Runs
    /// synchronous filesystem calls and is meant to be offloaded to the
    /// blocking pool.
    ///
    /// The file is opened by the rules of `.lock`, through the registry helper
    /// the repository lock uses. A file that shares its inode with `.lock` is
    /// refused.
    pub(crate) fn get_or_create(
        repo_fd: BorrowedFd<'_>,
        repo_mode: RepoMode,
    ) -> std::io::Result<Arc<UpdateLock>> {
        get_or_register(
            repo_fd,
            UPDATE_LOCK_FILE,
            repo_mode,
            Registered::update,
            |fd, key| {
                let lock = Arc::new(UpdateLock {
                    key,
                    fd: Some(fd),
                    state: Mutex::new(UpdateState {
                        held: false,
                        next_ticket: 0,
                        queue: VecDeque::new(),
                    }),
                });
                let registered = Registered::Update(Arc::downgrade(&lock));
                (lock, registered)
            },
        )
    }

    fn fd(&self) -> &OwnedFd {
        self.fd
            .as_ref()
            .expect("the descriptor stays open until the drop")
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        // Closing the descriptor releases any residual record lock.
        unregister(self.key, self.fd.take());
    }
}

/// Take the waker the head of the queue left, if any, for a wake after the
/// state mutex is released. Call this only while no guard holds the lock.
fn wake_head(st: &mut UpdateState) -> Option<Waker> {
    st.queue.front_mut().and_then(|(_, waker)| waker.take())
}

/// An acquired update lock. Releasing happens on drop.
#[derive(Debug)]
pub(crate) struct UpdateLockHeld {
    lock: Arc<UpdateLock>,
}

impl UpdateLockHeld {
    /// Whether this hold is a hold of `lock`.
    pub(crate) fn is_of(&self, lock: &Arc<UpdateLock>) -> bool {
        Arc::ptr_eq(&self.lock, lock)
    }
}

impl Drop for UpdateLockHeld {
    fn drop(&mut self) {
        // The record lock goes first: no waiter makes a request while `held`
        // stands. Errors are ignored so a release never fails.
        let _ = rustix::fs::fcntl_lock(self.lock.fd(), FlockOperation::Unlock);
        let waker = match self.lock.state.lock() {
            Ok(mut st) => {
                st.held = false;
                wake_head(&mut st)
            }
            Err(_) => None,
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// The outcome of one poll of a waiter's turn.
enum Turn {
    /// The waiter holds the lock.
    Granted,
    /// The waiter is at the head and another process holds the lock.
    Contended,
    /// The deadline passed before the waiter's turn came.
    TimedOut,
}

/// One waiter's place in the queue. Dropping a place that was not granted
/// removes it from the queue.
struct Place {
    lock: Arc<UpdateLock>,
    ticket: u64,
    granted: bool,
}

impl Place {
    /// Take a ticket at the tail of the queue.
    fn enqueue(lock: Arc<UpdateLock>) -> Place {
        let ticket = {
            let mut st = lock.state.lock().unwrap();
            let ticket = st.next_ticket;
            st.next_ticket += 1;
            st.queue.push_back((ticket, None));
            ticket
        };
        Place {
            lock,
            ticket,
            granted: false,
        }
    }

    /// Make one attempt when this place is the head and no guard holds the
    /// lock. Otherwise keep the waker for the release that makes this place
    /// the head, and stay pending.
    ///
    /// The attempt and the grant happen under the state mutex in one poll, so a
    /// dropped wait cannot leave a hold that no guard releases.
    fn poll_turn(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Turn>> {
        let mut st = self.lock.state.lock().unwrap();
        let head = st.queue.front().map(|(ticket, _)| *ticket) == Some(self.ticket);
        if head && !st.held {
            return match rustix::fs::fcntl_lock(
                self.lock.fd(),
                FlockOperation::NonBlockingLockExclusive,
            ) {
                Ok(()) => {
                    st.held = true;
                    st.queue.pop_front();
                    self.granted = true;
                    Poll::Ready(Ok(Turn::Granted))
                }
                Err(e) if would_block(e) => Poll::Ready(Ok(Turn::Contended)),
                Err(e) => Poll::Ready(Err(e.into())),
            };
        }
        if let Some((_, waker)) = st.queue.iter_mut().find(|(t, _)| *t == self.ticket) {
            *waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        if self.granted {
            return;
        }
        // A place that leaves the head hands the turn to the next waiter.
        let waker = match self.lock.state.lock() {
            Ok(mut st) => {
                let head = st.queue.front().map(|(ticket, _)| *ticket) == Some(self.ticket);
                st.queue.retain(|(ticket, _)| *ticket != self.ticket);
                if head && !st.held {
                    wake_head(&mut st)
                } else {
                    None
                }
            }
            Err(_) => None,
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// Acquire the update lock, waiting until `timeout` elapses. `None` waits
/// with no deadline, and `Some(Duration::ZERO)` makes one attempt.
///
/// The waiter takes its place in the queue on the first poll of the returned
/// future. The timeout covers the whole wait: the wait in the queue and the
/// retries against other processes.
pub(crate) async fn acquire_update(
    lock: Arc<UpdateLock>,
    timeout: Option<Duration>,
) -> Result<UpdateLockHeld> {
    // A timeout past the range of `Instant` has no deadline.
    let deadline = timeout.and_then(|t| Some((Instant::now().checked_add(t)?, t.as_secs() as i64)));
    let mut place = Place::enqueue(lock);
    loop {
        let turn = futures_lite::future::poll_fn(|cx| place.poll_turn(cx));
        let turn = match deadline {
            Some((deadline, _)) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                turn.or(async {
                    ostrya_rt::Timer::after(remaining).await;
                    Ok::<_, std::io::Error>(Turn::TimedOut)
                })
                .await?
            }
            None => turn.await?,
        };
        let wait = match turn {
            Turn::Granted => {
                return Ok(UpdateLockHeld {
                    lock: place.lock.clone(),
                });
            }
            Turn::TimedOut => None,
            Turn::Contended => match deadline {
                Some((deadline, _)) => {
                    let now = Instant::now();
                    (now < deadline).then(|| POLL_INTERVAL.min(deadline - now))
                }
                None => Some(POLL_INTERVAL),
            },
        };
        match (wait, deadline) {
            (Some(wait), _) => ostrya_rt::Timer::after(wait).await,
            (None, Some((_, secs))) => return Err(Error::LockTimeout { secs }),
            (None, None) => unreachable!("a wait with no deadline does not time out"),
        }
    }
}

/// Whether a guard of this process holds the update lock of the repository
/// at `repo_fd`, for the unit tests. The registry is read without opening the
/// lock file, and a repository whose lock is not registered reads as free.
#[cfg(test)]
pub(crate) fn held_in_process(repo_fd: BorrowedFd<'_>) -> bool {
    let found = {
        let reg = super::registry().map.lock().unwrap();
        super::probe(&reg, repo_fd, UPDATE_LOCK_FILE)
            .map(|entry| super::find(entry, Registered::update))
    };
    // The registry mutex is released before the lock can drop: the drop of
    // the last reference takes it again.
    match found {
        Some(super::Found::Live(lock)) => lock.state.lock().unwrap().held,
        _ => false,
    }
}

/// The update lock moves freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>(_: &T) {}
    assert_send_sync::<UpdateLock>();
    assert_send_sync::<UpdateLockHeld>();
    let _ = |repo: &crate::Repo| assert_send(&repo.lock_update());
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::LockKind;
    use crate::{CreateOptions, Repo};
    use futures_lite::future::poll_once;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;

    /// The environment variable that names the repository of the lock-holder
    /// helper process.
    const HOLDER_ENV: &str = "OSTRYA_UPDATE_HOLDER";

    /// The environment variable that names the marker file of the umask child.
    const UMASK_ENV: &str = "OSTRYA_UPDATE_UMASK_CHILD";

    /// A scratch directory holding a repository at `repo`, removed when the
    /// guard drops.
    struct Scratch {
        dir: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "ostrya-update-lock-{label}-{}-{}",
                std::process::id(),
                crate::write::unique()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch { dir }
        }

        fn path(&self) -> PathBuf {
            self.dir.join("repo")
        }

        /// Create the repository in `mode`.
        fn create(&self, mode: RepoMode) -> Repo {
            ostrya_rt::block_on(Repo::create(&self.path(), CreateOptions::new(mode))).unwrap()
        }

        /// Create the repository with `lock-timeout-secs` set to `secs`.
        fn create_with_timeout(&self, secs: i64) -> Repo {
            drop(self.create(RepoMode::BareUser));
            let config = self.path().join("config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str(&format!("lock-timeout-secs={secs}\n"));
            std::fs::write(&config, text).unwrap();
            self.open()
        }

        fn open(&self) -> Repo {
            ostrya_rt::block_on(Repo::open(&self.path())).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The lock of `repo`, from the registry the handle's cached lock is in.
    fn lock_of(repo: &Repo) -> Arc<UpdateLock> {
        UpdateLock::get_or_create(repo.repo_fd(), RepoMode::BareUser).unwrap()
    }

    /// The number of waiters in the queue of `lock`.
    fn waiters(lock: &UpdateLock) -> usize {
        lock.state.lock().unwrap().queue.len()
    }

    /// Wait until the queue of `lock` holds `n` waiters. The wait yields to
    /// the executor, so a task spawned on a single-threaded runtime can run.
    async fn wait_for_waiters(lock: &UpdateLock, n: usize) {
        for _ in 0..500 {
            if waiters(lock) == n {
                return;
            }
            ostrya_rt::Timer::after(Duration::from_millis(10)).await;
        }
        panic!("the queue never held {n} waiters");
    }

    type Pending = Pin<Box<dyn Future<Output = Result<UpdateLockHeld>> + Send>>;

    fn waiter(lock: &Arc<UpdateLock>, timeout: Option<Duration>) -> Pending {
        Box::pin(acquire_update(lock.clone(), timeout))
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// The mode a file created with request `0660` takes under the mask this
    /// process runs with.
    fn masked_lock_mode(dir: &Path) -> u32 {
        use std::os::unix::fs::OpenOptionsExt;
        let probe = dir.join("probe-file");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o660)
            .open(&probe)
            .unwrap();
        mode_of(&probe)
    }

    #[test]
    fn the_lock_file_sits_at_the_repository_root_and_stays() {
        let scratch = Scratch::new("file");
        let repo = scratch.create(RepoMode::BareUser);
        let file = scratch.path().join(UPDATE_LOCK_FILE);
        assert!(!file.exists(), "the file is created on the first acquire");

        let guard = ostrya_rt::block_on(repo.lock_update()).unwrap();
        let meta = std::fs::symlink_metadata(&file).unwrap();
        assert!(
            meta.file_type().is_file(),
            "the lock file is a regular file"
        );
        assert_eq!(mode_of(&file), masked_lock_mode(&scratch.dir));

        drop(guard);
        drop(repo);
        assert!(file.exists(), "the lock file stays after the handle drops");
    }

    /// A lock file created in a `bare-user-shared` repository is `0660` under a
    /// umask of `0077`.
    ///
    /// The umask is a property of the process and the tests of this binary run
    /// in parallel threads, so the acquire runs in a child: this test binary
    /// re-executed for this test alone.
    #[test]
    fn a_shared_repository_forces_the_lock_mode() {
        if let Some(marker) = std::env::var_os(UMASK_ENV) {
            let marker = PathBuf::from(marker);
            rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
            let dir = marker.with_file_name("child");
            std::fs::create_dir_all(&dir).unwrap();
            assert_eq!(masked_lock_mode(&dir), 0o600, "umask 0077 applies");
            let path = dir.join("repo");
            ostrya_rt::block_on(async {
                let repo = Repo::create(&path, CreateOptions::new(RepoMode::BareUserShared))
                    .await
                    .unwrap();
                drop(repo.lock_update().await.unwrap());
            });
            assert_eq!(mode_of(&path.join(UPDATE_LOCK_FILE)), 0o660);
            std::fs::write(marker, b"ran").unwrap();
            return;
        }
        let scratch = Scratch::new("shared");
        let marker = scratch.dir.join("ran");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "lock::update::tests::a_shared_repository_forces_the_lock_mode",
                "--exact",
                "--nocapture",
            ])
            .env(UMASK_ENV, &marker)
            .status()
            .expect("re-execute this test binary");
        assert!(status.success(), "the child failed: {status}");
        // A name the child's filter does not match runs nothing and still
        // exits 0, so the marker is what proves the check ran.
        assert!(marker.exists(), "the child ran no check");
    }

    #[test]
    fn an_existing_lock_file_keeps_its_mode() {
        let scratch = Scratch::new("existing");
        let repo = scratch.create(RepoMode::BareUserShared);
        let file = scratch.path().join(UPDATE_LOCK_FILE);
        std::fs::write(&file, b"").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();

        drop(ostrya_rt::block_on(repo.lock_update()).unwrap());
        assert_eq!(mode_of(&file), 0o600);
    }

    #[test]
    fn two_holders_in_one_process_serialize() {
        let scratch = Scratch::new("serialize");
        let repo = scratch.create(RepoMode::BareUser);
        let lock = lock_of(&repo);
        ostrya_rt::block_on(async {
            let first = repo.lock_update().await.unwrap();
            let mut second = waiter(&lock, None);
            assert!(poll_once(&mut second).await.is_none(), "the second waits");
            let err = acquire_update(lock.clone(), Some(Duration::ZERO))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::LockTimeout { secs: 0 }), "{err:?}");

            drop(first);
            second.await.unwrap();
        });
    }

    #[test]
    fn two_handles_share_one_lock() {
        let scratch = Scratch::new("handles");
        drop(scratch.create(RepoMode::BareUser));
        let (a, b) = (scratch.open(), scratch.open());
        ostrya_rt::block_on(async {
            let first = a.lock_update().await.unwrap();
            let lock = lock_of(&b);
            // The first call on `b` opens the lock file on the blocking pool,
            // so it joins the queue only when the open completes.
            let mut second = Box::pin(b.lock_update());
            for _ in 0..500 {
                assert!(poll_once(&mut second).await.is_none(), "the second waits");
                if waiters(&lock) == 1 {
                    break;
                }
                ostrya_rt::Timer::after(Duration::from_millis(10)).await;
            }
            assert_eq!(waiters(&lock), 1, "the second joined the queue");
            assert!(poll_once(&mut second).await.is_none(), "the second waits");
            let first_lock = Arc::as_ptr(&first.lock);

            drop(first);
            let second = second.await.unwrap();
            assert_eq!(Arc::as_ptr(&second.lock), first_lock, "one cached lock");
        });
    }

    #[test]
    fn waiters_acquire_in_request_order() {
        let scratch = Scratch::new("order");
        let repo = scratch.create(RepoMode::BareUser);
        let lock = lock_of(&repo);
        ostrya_rt::block_on(async {
            let holder = repo.lock_update().await.unwrap();
            let mut pending = Vec::new();
            for label in ["B", "C", "D"] {
                let mut w = waiter(&lock, None);
                assert!(poll_once(&mut w).await.is_none());
                pending.push((label, w));
            }
            drop(holder);

            // Poll the waiters from the last to the first, so the poll order
            // does not match the request order.
            let mut order = Vec::new();
            while !pending.is_empty() {
                for i in (0..pending.len()).rev() {
                    if let Some(guard) = poll_once(&mut pending[i].1).await {
                        guard.unwrap();
                        order.push(pending.remove(i).0);
                    }
                }
            }
            assert_eq!(order, ["B", "C", "D"]);
        });
    }

    /// Calls through the handle join the queue on their first poll, so the
    /// call polled first takes the lock first.
    #[test]
    fn handle_calls_acquire_in_first_poll_order() {
        let scratch = Scratch::new("order-handle");
        let repo = scratch.create(RepoMode::BareUser);
        let lock = lock_of(&repo);
        ostrya_rt::block_on(async {
            let holder = repo.lock_update().await.unwrap();
            let mut x = Box::pin(repo.lock_update());
            let mut y = Box::pin(repo.lock_update());
            assert!(poll_once(&mut x).await.is_none());
            assert!(poll_once(&mut y).await.is_none());
            assert_eq!(waiters(&lock), 2, "both calls joined the queue");
            drop(holder);

            // Poll the second call first. It stays pending until the first
            // call releases.
            assert!(poll_once(&mut y).await.is_none(), "the second waits");
            let first = x.await.unwrap();
            assert!(poll_once(&mut y).await.is_none(), "the second waits");
            drop(first);
            drop(y.await.unwrap());
        });
    }

    #[test]
    fn spawned_waiters_acquire_in_request_order() {
        let scratch = Scratch::new("order-spawned");
        let repo = scratch.create(RepoMode::BareUser);
        let lock = lock_of(&repo);
        let order = Arc::new(Mutex::new(Vec::new()));
        ostrya_rt::block_on(async {
            let holder = repo.lock_update().await.unwrap();
            let mut tasks = Vec::new();
            for (n, label) in ["B", "C", "D"].into_iter().enumerate() {
                let (task_lock, order) = (lock.clone(), order.clone());
                tasks.push(ostrya_rt::spawn(async move {
                    let guard = acquire_update(task_lock, Some(Duration::from_secs(10))).await?;
                    order.lock().unwrap().push(label);
                    ostrya_rt::Timer::after(Duration::from_millis(10)).await;
                    drop(guard);
                    Ok::<_, Error>(())
                }));
                wait_for_waiters(&lock, n + 1).await;
            }
            drop(holder);
            for task in tasks {
                task.await.unwrap();
            }
        });
        assert_eq!(*order.lock().unwrap(), ["B", "C", "D"]);
    }

    #[test]
    fn a_dropped_or_timed_out_waiter_leaves_the_queue() {
        let scratch = Scratch::new("leave");
        let repo = scratch.create(RepoMode::BareUser);
        let lock = lock_of(&repo);
        let long = Some(Duration::from_secs(10));
        ostrya_rt::block_on(async {
            // A head dropped after the release woke it hands the turn on.
            let holder = repo.lock_update().await.unwrap();
            let mut head = waiter(&lock, None);
            assert!(poll_once(&mut head).await.is_none());
            let next = ostrya_rt::spawn(acquire_update(lock.clone(), long));
            wait_for_waiters(&lock, 2).await;
            drop(holder);
            drop(head);
            let holder = next.await.unwrap();
            assert_eq!(waiters(&lock), 0);

            // A head that times out leaves the queue, and the next waiter takes
            // the lock on the release.
            let head = acquire_update(lock.clone(), Some(Duration::from_millis(50)));
            let mut head = Box::pin(head);
            assert!(poll_once(&mut head).await.is_none());
            let next = ostrya_rt::spawn(acquire_update(lock.clone(), long));
            wait_for_waiters(&lock, 2).await;
            let err = head.await.unwrap_err();
            assert!(matches!(err, Error::LockTimeout { secs: 0 }), "{err:?}");
            assert_eq!(waiters(&lock), 1);
            drop(holder);
            drop(next.await.unwrap());
            assert_eq!(waiters(&lock), 0);
        });
    }

    #[test]
    fn the_shared_repository_lock_stays_available() {
        let scratch = Scratch::new("repo-lock");
        let repo = scratch.create_with_timeout(0);
        ostrya_rt::block_on(async {
            let _update = repo.lock_update().await.unwrap();
            let first = repo.lock_repo(LockKind::Shared).await.unwrap();
            let second = repo.lock_repo(LockKind::Shared).await.unwrap();
            drop((first, second));
        });
    }

    /// With `lock-timeout-secs=-1` a waiter in the queue takes the lock when
    /// the holder releases it.
    #[test]
    fn a_waiter_with_no_limit_takes_the_lock_on_release() {
        let scratch = Scratch::new("no-limit");
        let repo = scratch.create_with_timeout(-1);
        let lock = lock_of(&repo);
        let holder = ostrya_rt::block_on(repo.lock_update()).unwrap();
        let release = std::thread::spawn(move || {
            for _ in 0..5000 {
                if waiters(&lock) == 1 {
                    drop(holder);
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            panic!("the waiter never joined the queue");
        });
        drop(ostrya_rt::block_on(repo.lock_update()).unwrap());
        release.join().unwrap();
    }

    #[test]
    fn two_processes_serialize() {
        use std::process::{Command, Stdio};

        let scratch = Scratch::new("processes");
        let repo = scratch.create(RepoMode::BareUser);
        let lock = lock_of(&repo);
        let held = scratch.path().join(".held");
        let releasing = scratch.path().join(".releasing");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "lock::update::tests::update_lock_holder_subprocess",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env(HOLDER_ENV, scratch.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("re-execute this test binary");
        for _ in 0..500 {
            if held.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(held.exists(), "the child never took the lock");

        ostrya_rt::block_on(async {
            let err = acquire_update(lock.clone(), Some(Duration::ZERO))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::LockTimeout { secs: 0 }), "{err:?}");
            // A wait of three poll intervals makes several requests, all of
            // which fail. The error states the whole seconds of the wait.
            let start = Instant::now();
            let err = acquire_update(lock.clone(), Some(Duration::from_millis(300)))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::LockTimeout { secs: 0 }), "{err:?}");
            assert!(start.elapsed() >= Duration::from_millis(300));

            let waiting = ostrya_rt::spawn(acquire_update(lock.clone(), None));
            wait_for_waiters(&lock, 1).await;
            drop(child.stdin.take());
            let guard = waiting.await.unwrap();
            assert!(releasing.exists(), "the lock came only after the release");
            drop(guard);
        });
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "the child reported {}:\n{stdout}",
            output.status
        );
    }

    /// The lock-holder half of [`two_processes_serialize`], run only when this
    /// test binary is re-executed with the environment set. It takes the
    /// update lock, states that it holds it, and keeps it until its
    /// standard input closes.
    #[test]
    #[ignore = "helper process for two_processes_serialize"]
    fn update_lock_holder_subprocess() {
        use std::io::Read;

        let Some(path) = std::env::var_os(HOLDER_ENV).map(PathBuf::from) else {
            return;
        };
        let repo = ostrya_rt::block_on(Repo::open(&path)).unwrap();
        let guard = ostrya_rt::block_on(repo.lock_update()).unwrap();
        std::fs::write(path.join(".held"), b"1").unwrap();
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        std::fs::write(path.join(".releasing"), b"1").unwrap();
        drop(guard);
    }

    #[test]
    fn a_lock_file_linked_to_the_repository_lock_is_refused() {
        use std::os::fd::AsRawFd;

        let scratch = Scratch::new("linked");
        let repo = scratch.create(RepoMode::BareUser);
        ostrya_rt::block_on(async {
            let guard = repo.lock_repo(LockKind::Shared).await.unwrap();
            let lock_file = scratch.path().join(".lock");
            std::fs::hard_link(&lock_file, scratch.path().join(UPDATE_LOCK_FILE)).unwrap();

            let err = repo.lock_update().await.unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{err:?}");

            // The kernel still records the shared lock of this process on the
            // inode of `.lock`. The fdinfo of the descriptor that set the lock
            // lists only the locks this process set through that descriptor,
            // and it is a consistent snapshot, which `/proc/locks` is not.
            let (lock, _) = guard.hold.as_ref().unwrap();
            let path = format!("/proc/self/fdinfo/{}", lock.fd().as_raw_fd());
            let info = std::fs::read_to_string(path).unwrap();
            let held = info.lines().any(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                fields.len() > 4
                    && fields[0] == "lock:"
                    && fields[2] == "POSIX"
                    && fields[4] == "READ"
            });
            assert!(held, "the repository lock was dropped:\n{info}");
        });
    }
}
