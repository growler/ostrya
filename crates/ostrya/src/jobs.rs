//! The blocking jobs of a transaction that a caller can wait for after it
//! drops the future that started them.
//!
//! A future that awaits a job on the blocking pool can drop before the job
//! ends. The drop does not stop the job: the job runs to its end on the pool.
//! A job that creates a name under the repository can then create it after the
//! caller has started its cleanup.
//!
//! [`Jobs`] keeps each job whose [`Tracked`] future dropped before the job
//! ended. [`Jobs::settle`] waits for each of them. A failed run calls it
//! before its cleanup, so the cleanup sees each name that the jobs created.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

use futures_lite::FutureExt;
use ostrya_rt::JoinHandle;

/// A job that a dropped [`Tracked`] future left, as a future that ends with
/// the job.
type Orphan = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The jobs that dropped [`Tracked`] futures left before the jobs ended.
///
/// A kept job holds its output until the output drops. The next drop of a
/// [`Tracked`] future that has not resolved frees the output of each kept job
/// that has ended. [`settle`](Jobs::settle) frees the output of each kept
/// job.
#[derive(Default)]
pub(crate) struct Jobs {
    orphans: Mutex<Vec<Orphan>>,
}

impl Jobs {
    /// Returns a future that resolves to the result of the job of `handle`.
    ///
    /// If the future drops before the job ends, [`settle`](Jobs::settle)
    /// waits for the job.
    pub(crate) fn track<T: Send + 'static>(&self, handle: JoinHandle<T>) -> Tracked<'_, T> {
        Tracked {
            handle: Some(handle),
            jobs: self,
        }
    }

    /// Waits for each job that a dropped [`Tracked`] future left.
    ///
    /// The call returns when no such job is left, also a job that a future
    /// dropped during the call. A panic of a job does not reach the caller.
    pub(crate) async fn settle(&self) {
        loop {
            let orphans =
                std::mem::take(&mut *self.orphans.lock().unwrap_or_else(PoisonError::into_inner));
            if orphans.is_empty() {
                return;
            }
            for orphan in orphans {
                orphan.await;
            }
        }
    }
}

/// A future that resolves to the result of a blocking job.
///
/// The future polls the [`JoinHandle`] of the job. A panic of the job reaches
/// the task that awaits the future, as the handle gives it. If the future
/// drops before the job ends, it hands the handle to its [`Jobs`], and frees
/// the output of each job of its [`Jobs`] that has ended.
pub(crate) struct Tracked<'j, T: Send + 'static> {
    /// The handle of the job. The future takes it out when the job ends.
    handle: Option<JoinHandle<T>>,
    jobs: &'j Jobs,
}

impl<T: Send + 'static> Future for Tracked<'_, T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = self.get_mut();
        let handle = this
            .handle
            .as_mut()
            .expect("a tracked job is not polled after it ends");
        let value = std::task::ready!(Pin::new(handle).poll(cx));
        this.handle = None;
        Poll::Ready(value)
    }
}

impl<T: Send + 'static> Drop for Tracked<'_, T> {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        // The job has its own error path. A panic of the job surfaced where
        // the job was awaited, and the wait of `settle` only marks its end.
        // The catch also covers the drop of the output, so a poll of an
        // orphan does not panic.
        let orphan: Orphan = Box::pin(async move {
            let _ = AssertUnwindSafe(async move { drop(handle.await) })
                .catch_unwind()
                .await;
        });
        let mut orphans = self
            .jobs
            .orphans
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // One poll with no waker frees the output of each kept job that has
        // ended. A later wait of `settle` polls with its own waker. The poll
        // comes before the push, so the new job keeps the waker of its last
        // poll.
        let mut cx = Context::from_waker(Waker::noop());
        orphans.retain_mut(|orphan| orphan.as_mut().poll(&mut cx).is_pending());
        orphans.push(orphan);
    }
}

/// A gate for the unit tests, in the blocking jobs that a test names.
///
/// A test arms a rule for one repository root and one job label:
///
/// - [`hold`] stops the job until a [`release`] of its repository. After its
///   body ends, the job reports if its directory had a link at the release.
/// - [`fail`] makes the job fail with an injected [`Error::Io`]. The job
///   first waits until the held job of another label has started.
///
/// A rule applies to one job. The calls compile out of a build that is not a
/// test build.
///
/// [`Error::Io`]: crate::Error::Io
#[cfg(test)]
pub(crate) mod job_gate {
    use std::os::fd::BorrowedFd;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    use crate::error::{Error, Result};

    /// The time that a failing job waits for the start of its held job, and
    /// that a held job waits for its release.
    pub(super) const WAIT: Duration = Duration::from_secs(60);

    /// A repository root, by device and inode.
    type Root = (u64, u64);

    /// The label of one job in one repository.
    pub(crate) struct Key {
        root: Root,
        label: String,
    }

    struct Hold {
        root: Root,
        label: String,
        started: bool,
        released: bool,
        finished: Option<Sender<bool>>,
    }

    struct Fail {
        root: Root,
        label: String,
        after: String,
    }

    struct Rules {
        holds: Vec<Hold>,
        fails: Vec<Fail>,
    }

    static RULES: Mutex<Rules> = Mutex::new(Rules {
        holds: Vec::new(),
        fails: Vec::new(),
    });
    static CHANGED: Condvar = Condvar::new();

    fn rules() -> MutexGuard<'static, Rules> {
        RULES.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn root_of(fd: BorrowedFd<'_>) -> Root {
        let stat = rustix::fs::fstat(fd).unwrap();
        (stat.st_dev, stat.st_ino)
    }

    fn root_at(path: &std::path::Path) -> Root {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).unwrap();
        (meta.dev(), meta.ino())
    }

    /// Returns the key of the job `label` in the repository whose root is
    /// open at `repo_fd`.
    pub(crate) fn key(repo_fd: BorrowedFd<'_>, label: String) -> Key {
        Key {
            root: root_of(repo_fd),
            label,
        }
    }

    /// Holds the job `label` of the repository at `root` until a
    /// [`release`]. After the body of the job ends, the receiver gets `true`
    /// if the directory of the job had a link at the release.
    pub(crate) fn hold(root: &std::path::Path, label: String) -> Receiver<bool> {
        let (finished, report) = channel();
        rules().holds.push(Hold {
            root: root_at(root),
            label,
            started: false,
            released: false,
            finished: Some(finished),
        });
        report
    }

    /// Makes the job `label` of the repository at `root` fail, after the held
    /// job `after` of that repository has started.
    pub(crate) fn fail(root: &std::path::Path, label: String, after: String) {
        rules().fails.push(Fail {
            root: root_at(root),
            label,
            after,
        });
    }

    /// Releases each held job of the repository whose root is open at
    /// `repo_fd`.
    pub(crate) fn release(repo_fd: BorrowedFd<'_>) {
        let root = root_of(repo_fd);
        let mut rules = rules();
        for hold in rules.holds.iter_mut().filter(|hold| hold.root == root) {
            hold.released = true;
        }
        CHANGED.notify_all();
    }

    /// The end report of a held job, sent when the job ends.
    pub(crate) struct Pass {
        finished: Option<(Sender<bool>, bool)>,
    }

    impl Drop for Pass {
        fn drop(&mut self) {
            if let Some((finished, linked)) = self.finished.take() {
                let _ = finished.send(linked);
            }
        }
    }

    /// Applies the rule of `key`, if one is armed. `dir` is the directory
    /// that the job writes in.
    ///
    /// The job keeps the returned value until its body ends.
    pub(crate) fn pass(key: &Key, dir: BorrowedFd<'_>) -> Result<Pass> {
        let mut rules = rules();
        if let Some(at) = rules
            .fails
            .iter()
            .position(|fail| fail.root == key.root && fail.label == key.label)
        {
            let fail = rules.fails.remove(at);
            let deadline = Instant::now() + WAIT;
            while !rules
                .holds
                .iter()
                .any(|hold| hold.root == fail.root && hold.label == fail.after && hold.started)
            {
                let left = deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or_else(|| panic!("the held job {} did not start", fail.after));
                rules = CHANGED.wait_timeout(rules, left).unwrap().0;
            }
            return Err(Error::Io(std::io::Error::other("injected job failure")));
        }
        let Some(at) = rules
            .holds
            .iter()
            .position(|hold| hold.root == key.root && hold.label == key.label && !hold.started)
        else {
            return Ok(Pass { finished: None });
        };
        rules.holds[at].started = true;
        CHANGED.notify_all();
        let matches = |hold: &Hold| hold.root == key.root && hold.label == key.label;
        let deadline = Instant::now() + WAIT;
        while !rules
            .holds
            .iter()
            .any(|hold| matches(hold) && hold.released)
        {
            let left = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_else(|| panic!("the held job {} was not released", key.label));
            rules = CHANGED.wait_timeout(rules, left).unwrap().0;
        }
        let at = rules.holds.iter().position(matches).unwrap();
        let hold = rules.holds.remove(at);
        drop(rules);
        let linked = rustix::fs::fstat(dir).is_ok_and(|stat| stat.st_nlink > 0);
        Ok(Pass {
            finished: hold.finished.map(|finished| (finished, linked)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_rt::block_on;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{Sender, channel};

    /// A dropped job stays with its `Jobs` until `settle`, and `settle` waits
    /// for its end.
    #[test]
    fn settle_waits_for_a_job_whose_future_dropped() {
        let jobs = Jobs::default();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<u32>();
        block_on(async {
            let mut tracked = jobs.track(ostrya_rt::unblock_task(move || {
                go_rx.recv().unwrap();
                done_tx.send(7).unwrap();
            }));
            let polled = futures_lite::future::poll_once(&mut tracked).await;
            assert!(polled.is_none());
            drop(tracked);
            assert_eq!(jobs.orphans.lock().unwrap().len(), 1);
            go_tx.send(()).unwrap();
            jobs.settle().await;
        });
        assert_eq!(done_rx.try_recv(), Ok(7));
        assert!(jobs.orphans.lock().unwrap().is_empty());
    }

    /// A job that ends while its future waits leaves nothing to settle.
    #[test]
    fn an_awaited_job_leaves_no_orphan() {
        let jobs = Jobs::default();
        let value = block_on(async { jobs.track(ostrya_rt::unblock_task(|| 6 * 7)).await });
        assert_eq!(value, 42);
        assert!(jobs.orphans.lock().unwrap().is_empty());
    }

    /// A value that sets its flag when it drops.
    struct Freed {
        flag: Arc<AtomicBool>,
    }

    impl Drop for Freed {
        fn drop(&mut self) {
            self.flag.store(true, Ordering::SeqCst);
        }
    }

    /// A waker that sends on a channel when it is woken.
    struct Signal {
        woken: Sender<()>,
    }

    impl std::task::Wake for Signal {
        fn wake(self: Arc<Self>) {
            let _ = self.woken.send(());
        }
    }

    /// The drop of a `Tracked` that has not resolved frees the output of a
    /// kept job that has ended, with no call to `settle`.
    #[test]
    fn a_drop_frees_the_output_of_a_kept_job_that_ended() {
        let jobs = Jobs::default();
        let freed = Arc::new(AtomicBool::new(false));
        let (go_tx, go_rx) = channel::<()>();
        let (woken_tx, woken_rx) = channel::<()>();
        let (hold_tx, hold_rx) = channel::<()>();
        block_on(async {
            let flag = Arc::clone(&freed);
            let mut ended = jobs.track(ostrya_rt::unblock_task(move || {
                go_rx.recv().unwrap();
                Freed { flag }
            }));
            // The handle keeps this waker, and the end of the job wakes it.
            let waker = Waker::from(Arc::new(Signal { woken: woken_tx }));
            let polled = Pin::new(&mut ended).poll(&mut Context::from_waker(&waker));
            assert!(polled.is_pending());
            drop(ended);
            go_tx.send(()).unwrap();
            woken_rx
                .recv_timeout(job_gate::WAIT)
                .expect("the first job did not end");
            assert!(!freed.load(Ordering::SeqCst));
            drop(jobs.track(ostrya_rt::unblock_task(move || hold_rx.recv().unwrap())));
            assert!(freed.load(Ordering::SeqCst));
            assert_eq!(jobs.orphans.lock().unwrap().len(), 1);
            hold_tx.send(()).unwrap();
            jobs.settle().await;
        });
        assert!(jobs.orphans.lock().unwrap().is_empty());
    }

    /// The panic of a dropped job does not reach `settle`.
    #[test]
    fn settle_does_not_propagate_the_panic_of_a_job() {
        let jobs = Jobs::default();
        block_on(async {
            drop(jobs.track(ostrya_rt::unblock_task(|| panic!("job boom"))));
            jobs.settle().await;
        });
        assert!(jobs.orphans.lock().unwrap().is_empty());
    }
}
