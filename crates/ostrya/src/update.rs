//! The update guard: an exclusive hold on the writes of refs and config.
//!
//! [`Repo::begin_update`] takes the repository lock shared and then the update
//! lock on `<repo>/.update.lock` exclusive, and returns an [`UpdateGuard`]. The
//! guard reads and writes refs, collection refs, and ref aliases, reads
//! `config` from disk, and writes `config`. It stages no object.
//!
//! Each write of the guard is atomic and visible when it returns. With
//! `[core] fsync` set, the guard records each directory that a write changed.
//! [`UpdateGuard::finish`] waits until no write of the guard runs, runs `fsync`
//! on each recorded directory once, deepest first, and then releases both
//! locks. A guard that drops without `finish` runs the same syncs when the
//! guard and each write that still runs are gone. The locks are released only
//! after the syncs ran.

use std::collections::BTreeSet;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use ostrya_core::{Checksum, KeyFile};

use crate::config::RepoConfig;
use crate::error::Result;
use crate::lock::UpdateLocks;
use crate::refs::{
    CollectionRef, collection_ref_to_relpath, put_alias_blocking, put_ref_blocking,
    refspec_to_relpath, relative_link, sync_dirs_all,
};
use crate::repo::{Repo, check_config_size};
use crate::summary::put_root_file_blocking;

/// The config file name at the repository root.
const CONFIG_FILE: &str = "config";

/// The directory that holds `config`: the repository root.
const ROOT_DIR: &str = ".";

/// An exclusive hold on the writes of refs, ref aliases, and `config` of one
/// repository, across processes and inside the process.
///
/// [`Repo::begin_update`] returns it. The guard is a value: a caller holds
/// it, passes it, and stores it. It is `Send + Sync`.
///
/// While you hold the guard, write through the guard. The writers that wait
/// for the guard are:
///
/// - [`Transaction::commit`](crate::Transaction::commit) of a transaction
///   that writes a ref or detached metadata, at the step that writes them.
///   So a pull waits there, and so does the transaction commit of a receive
///   session;
/// - [`Repo::set_ref_immediate`], [`Repo::set_collection_ref_immediate`],
///   and [`Repo::set_ref_alias_immediate`];
/// - [`Repo::write_config`], [`Repo::remove_remote_keyring`], and, under the
///   `verify-gpg` feature, `Repo::gpg_import_keys`;
/// - [`Repo::regenerate_summary`], [`Repo::sign_summary`],
///   [`Repo::sign_summary_all`], and the `summary` and `summary.sig` writes
///   of a mirror pull;
/// - [`Repo::write_commit_detached_metadata`], [`Repo::sign_commit`], and
///   [`Repo::delete_signatures`].
///
/// When `[core] locking` is on, [`Repo::prune`] waits for the guard through
/// the repository lock. No call detects a holder that waits for its own
/// guard: a task that holds the guard and calls one of those writers, or
/// waits for a task that calls one, waits until `lock-timeout-secs` and then
/// fails with [`Error::LockTimeout`](crate::Error::LockTimeout). With
/// `lock-timeout-secs=-1` it waits forever.
///
/// Call [`finish`](UpdateGuard::finish) to release the guard. A guard that
/// drops without `finish` runs the directory syncs of `finish`
/// synchronously, on the thread that drops the last reference to its state,
/// hides every error, and then releases both locks. That thread is the one
/// that drops the guard, or the blocking-pool thread of a write that still
/// runs. The syncs block that thread, so an async caller calls `finish`.
#[derive(Debug)]
pub struct UpdateGuard {
    held: Arc<Held>,
}

/// The state of a guard that a write in flight shares: both locks, the
/// writes in flight, and the directories to sync. The last reference to drop
/// runs the syncs that are still recorded and then releases the locks.
#[derive(Debug)]
struct Held {
    /// The repository handle that the blocking closures use.
    repo: Repo,
    /// `[core] fsync`, read once when the guard is taken.
    fsync: bool,
    /// The writes in flight and the directories to sync.
    state: Mutex<Writes>,
    /// Signalled when the last write in flight ends.
    idle: Condvar,
    /// Both locks, until [`finish`](UpdateGuard::finish) releases them.
    /// Declared last, so a guard that drops without `finish` releases the
    /// locks after the syncs of the drop ran.
    locks: Mutex<Option<UpdateLocks>>,
}

/// The writes of a guard.
#[derive(Debug, Default)]
struct Writes {
    /// The number of write closures that exist and have not ended.
    in_flight: usize,
    /// Each directory, relative to the repository root, that a write changed
    /// and that no sync has run on yet.
    dirs: BTreeSet<String>,
}

impl Held {
    fn writes(&self) -> MutexGuard<'_, Writes> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wait until no write is in flight, sync each recorded directory, and
    /// release both locks. Blocks the calling thread.
    fn finish_blocking(&self) -> Result<()> {
        let mut writes = self.writes();
        while writes.in_flight > 0 {
            writes = self
                .idle
                .wait(writes)
                .unwrap_or_else(PoisonError::into_inner);
        }
        let dirs = std::mem::take(&mut writes.dirs);
        drop(writes);
        let synced = sync_dirs_all(self.repo.repo_fd(), dirs.into_iter().collect());
        self.release();
        synced
    }

    /// Release both locks.
    fn release(&self) {
        let locks = self
            .locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        drop(locks);
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let writes = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        let dirs = std::mem::take(&mut writes.dirs);
        let _ = sync_dirs_all(self.repo.repo_fd(), dirs.into_iter().collect());
    }
}

/// One write closure of a guard, counted in flight from its creation to its
/// drop. The closure owns it, so the count falls when the closure ends, when
/// it panics, and when the pool drops it unrun.
struct InFlight {
    held: Arc<Held>,
}

impl InFlight {
    fn start(held: &Arc<Held>) -> InFlight {
        held.writes().in_flight += 1;
        InFlight { held: held.clone() }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut writes = self.held.writes();
        writes.in_flight -= 1;
        if writes.in_flight == 0 {
            self.held.idle.notify_all();
        }
    }
}

impl Repo {
    /// Take the repository lock shared, then the update lock exclusive, and
    /// return the guard that holds both.
    ///
    /// The repository lock comes first. A transaction holds it shared too, so
    /// the call never waits for a pull. When `[core] locking` is on, it waits
    /// for a [`Repo::prune`] and for any other holder of the repository lock
    /// in [`LockKind::Exclusive`](crate::LockKind::Exclusive). The update
    /// lock is exclusive across processes and inside the process. The waiters
    /// of one process take it in the order of the first poll of their wait
    /// for the update lock.
    ///
    /// Each of the two waits gets the whole of `[core] lock-timeout-secs`, and
    /// then fails with [`Error::LockTimeout`](crate::Error::LockTimeout). With
    /// `-1` a wait has no limit, and with `0` it makes one attempt. There is no
    /// variant that fails at once. With `[core] locking=false` the repository
    /// lock is not taken, and the update lock is taken all the same.
    ///
    /// The call reads `[core] fsync`, `[core] locking`, and `[core]
    /// lock-timeout-secs` from the configuration this handle was opened with,
    /// before it waits. The guard keeps these values: a
    /// [`write_config`](UpdateGuard::write_config) through the guard does not
    /// change them.
    ///
    /// A caller can hold the guard for minutes. While it holds it:
    ///
    /// - every other writer that [`UpdateGuard`] lists waits under
    ///   `lock-timeout-secs` and then fails with `Error::LockTimeout`. A pull
    ///   fails at the step of its commit that writes detached metadata and
    ///   refs. A push fails at `Commit` with `internal`;
    /// - when `[core] locking` is on, a prune waits for the whole hold;
    /// - a transaction opens, stages, and publishes its objects in parallel
    ///   with the hold, and waits only at the step that writes detached
    ///   metadata and refs. A transaction that writes neither commits in
    ///   parallel with the hold.
    ///
    /// While you hold the guard, write through the guard. A holder that waits
    /// for its own guard is not detected (see [`UpdateGuard`]).
    pub async fn begin_update(&self) -> Result<UpdateGuard> {
        let fsync = self.config().fsync()?;
        let locks = self.lock_for_update().await?;
        Ok(UpdateGuard {
            held: Arc::new(Held {
                repo: self.clone(),
                fsync,
                state: Mutex::new(Writes::default()),
                idle: Condvar::new(),
                locks: Mutex::new(Some(locks)),
            }),
        })
    }
}

impl UpdateGuard {
    fn repo(&self) -> &Repo {
        &self.held.repo
    }

    /// The commit a refspec names, read from the ref store as
    /// [`Repo::resolve_ref_tip`] reads it: a ref stored as an alias is
    /// followed to the ref it names. `None` says the store carries no such
    /// ref.
    pub async fn read_ref(&self, refspec: &str) -> Result<Option<Checksum>> {
        self.repo().resolve_ref_tip(refspec).await
    }

    /// The commit a collection ref names, read as
    /// [`read_ref`](UpdateGuard::read_ref) reads a refspec.
    pub async fn read_collection_ref(&self, cref: &CollectionRef) -> Result<Option<Checksum>> {
        self.repo()
            .resolve_relpath_tip(collection_ref_to_relpath(cref)?)
            .await
    }

    /// Write one ref, atomically, as [`Repo::set_ref_immediate`] writes it. A
    /// `None` checksum removes the ref file. The ref is visible when the call
    /// returns. The sync of each directory that changed waits for
    /// [`finish`](UpdateGuard::finish).
    pub async fn set_ref(&self, refspec: &str, checksum: Option<&Checksum>) -> Result<()> {
        let relpath = refspec_to_relpath(refspec)?;
        self.set_relpath(relpath, checksum).await
    }

    /// Write one collection ref, atomically, the way
    /// [`set_ref`](UpdateGuard::set_ref) writes a refspec. A `None` checksum
    /// removes the ref file.
    pub async fn set_collection_ref(
        &self,
        cref: &CollectionRef,
        checksum: Option<&Checksum>,
    ) -> Result<()> {
        let relpath = collection_ref_to_relpath(cref)?;
        self.set_relpath(relpath, checksum).await
    }

    /// Write `refspec` as an alias of `target`, as
    /// [`Repo::set_ref_alias_immediate`] writes it: a relative symlink that
    /// replaces whatever `refspec` named before. Both refspecs are validated,
    /// and neither ref need exist.
    pub async fn set_ref_alias(&self, refspec: &str, target: &str) -> Result<()> {
        let relpath = refspec_to_relpath(refspec)?;
        let link = relative_link(&relpath, &refspec_to_relpath(target)?);
        let repo_mode = self.repo().mode();
        self.write(move |repo_fd, fsync, dirs| {
            put_alias_blocking(repo_fd, &relpath, &link, fsync, repo_mode, dirs)
        })
        .await
    }

    /// The `config` file as it is on disk now, parsed. The repository handle
    /// keeps the configuration it was opened with, so a read-modify-write of
    /// `config` under the guard reads the file here.
    pub async fn read_config(&self) -> Result<RepoConfig> {
        self.repo().read_config_file().await
    }

    /// Replace `config` with the document `keyfile` holds, as
    /// [`Repo::write_config`] writes it. The new file is visible when the call
    /// returns. The sync of the repository directory waits for
    /// [`finish`](UpdateGuard::finish).
    ///
    /// The document is written as given. The repository handle and the guard
    /// keep the values they read before; reopen the repository to read the
    /// new ones. A document over 1 MiB, the size an open accepts, is refused
    /// with [`Error::InvalidFormat`](crate::Error::InvalidFormat) and nothing
    /// is written.
    pub async fn write_config(&self, keyfile: &KeyFile) -> Result<()> {
        let bytes = keyfile.to_string().into_bytes();
        check_config_size(&bytes)?;
        self.write(move |repo_fd, fsync, dirs| {
            put_root_file_blocking(repo_fd, CONFIG_FILE, &bytes, fsync)?;
            if fsync {
                dirs.push(ROOT_DIR.to_owned());
            }
            Ok(())
        })
        .await
    }

    /// Wait until each write of the guard has ended, run `fsync` on each
    /// directory a write changed, once, deepest first, then release the
    /// update lock and the repository lock.
    ///
    /// The wait covers a write whose future was dropped while its work on the
    /// blocking pool still ran: that work ends before the syncs start. So the
    /// call syncs the directories of every write of the guard, and both locks
    /// are free when it returns.
    ///
    /// The call returns the first error of the syncs, and it runs every sync
    /// whatever the errors. The locks are released after the syncs, also when
    /// the returned future is dropped before it completes.
    pub async fn finish(self) -> Result<()> {
        let held = self.held;
        {
            let writes = held.writes();
            if writes.in_flight == 0 && writes.dirs.is_empty() {
                drop(writes);
                held.release();
                return Ok(());
            }
        }
        ostrya_rt::unblock(move || held.finish_blocking()).await
    }

    async fn set_relpath(&self, relpath: String, checksum: Option<&Checksum>) -> Result<()> {
        let checksum = checksum.copied();
        let repo_mode = self.repo().mode();
        self.write(move |repo_fd, fsync, dirs| {
            put_ref_blocking(repo_fd, &relpath, checksum, fsync, repo_mode, dirs)
        })
        .await
    }

    /// Run the write `put` on the blocking pool and record the directories it
    /// changed. The closure owns a reference to the held state and counts in
    /// flight until it ends, so a write whose future drops still holds both
    /// locks until it ends, still records its directories, and holds
    /// [`finish`](UpdateGuard::finish) back until it ends.
    async fn write<F>(&self, put: F) -> Result<()>
    where
        F: FnOnce(std::os::fd::BorrowedFd<'_>, bool, &mut Vec<String>) -> Result<()>
            + Send
            + 'static,
    {
        let flight = InFlight::start(&self.held);
        ostrya_rt::unblock(move || {
            let held = &flight.held;
            let mut dirs = Vec::new();
            let written = put(held.repo.repo_fd(), held.fsync, &mut dirs);
            if held.fsync {
                held.writes().dirs.extend(dirs);
            }
            drop(flight);
            written
        })
        .await
    }
}

/// The guard and the futures of its calls move freely across tasks and
/// threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>(_: &T) {}
    assert_send_sync::<UpdateGuard>();
    let _ = |repo: &Repo| assert_send(&repo.begin_update());
    let _ = |guard: &UpdateGuard, c: &Checksum| assert_send(&guard.set_ref("r", Some(c)));
    let _ = |guard: &UpdateGuard, k: &KeyFile| assert_send(&guard.write_config(k));
    let _ = |guard: UpdateGuard| assert_send(&guard.finish());
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::LockKind;
    use crate::refs::test_syncs;
    use crate::{CreateOptions, RepoMode};
    use futures_lite::future::poll_once;
    use std::path::PathBuf;

    /// A scratch directory holding a repository at `repo`, removed when the
    /// value drops.
    struct Scratch {
        dir: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "ostrya-update-guard-{label}-{}-{}",
                std::process::id(),
                crate::write::unique()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch { dir }
        }

        fn path(&self) -> PathBuf {
            self.dir.join("repo")
        }

        fn create(&self) -> Repo {
            ostrya_rt::block_on(Repo::create(
                &self.path(),
                CreateOptions::new(RepoMode::BareUser),
            ))
            .unwrap()
        }

        /// Create the repository with `line` added to the `[core]` group.
        fn create_with(&self, line: &str) -> Repo {
            drop(self.create());
            let config = self.path().join("config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str(line);
            text.push('\n');
            std::fs::write(&config, text).unwrap();
            ostrya_rt::block_on(Repo::open(&self.path())).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn checksum() -> Checksum {
        Checksum::from_bytes([7; 32])
    }

    /// Take both locks again, as another writer would, and return the number
    /// of directory syncs under the repository at that point.
    async fn syncs_when_free(repo: &Repo, root: &std::path::Path) -> usize {
        let held = repo.lock_update().await.unwrap();
        let exclusive = repo.lock_repo(LockKind::Exclusive).await.unwrap();
        let count = test_syncs::count(root);
        drop((exclusive, held));
        count
    }

    /// Write two refs in two directories and a config through `guard`, so
    /// the guard records three directories.
    async fn write_three_dirs(guard: &UpdateGuard) {
        guard.set_ref("a/one", Some(&checksum())).await.unwrap();
        guard.set_ref("b", Some(&checksum())).await.unwrap();
        let keyfile = guard.read_config().await.unwrap().keyfile().clone();
        guard.write_config(&keyfile).await.unwrap();
    }

    #[test]
    fn a_dropped_guard_syncs_before_the_locks_go() {
        let scratch = Scratch::new("drop");
        let repo = scratch.create();
        ostrya_rt::block_on(async {
            let guard = repo.begin_update().await.unwrap();
            write_three_dirs(&guard).await;
            let before = test_syncs::count(&scratch.path());
            drop(guard);
            // refs/heads/a, refs/heads, and the repository root.
            assert_eq!(syncs_when_free(&repo, &scratch.path()).await, before + 3);
            assert_eq!(test_syncs::unlocked(&scratch.path()), 0);
        });
    }

    #[test]
    fn a_finish_polled_once_and_dropped_syncs_before_the_locks_go() {
        let scratch = Scratch::new("finish-dropped");
        let repo = scratch.create();
        ostrya_rt::block_on(async {
            let guard = repo.begin_update().await.unwrap();
            write_three_dirs(&guard).await;
            let before = test_syncs::count(&scratch.path());
            let mut finish = Box::pin(guard.finish());
            let _ = poll_once(&mut finish).await;
            drop(finish);
            assert_eq!(syncs_when_free(&repo, &scratch.path()).await, before + 3);
            assert_eq!(test_syncs::unlocked(&scratch.path()), 0);
        });
    }

    #[test]
    fn a_finish_never_polled_syncs_before_the_locks_go() {
        let scratch = Scratch::new("finish-unpolled");
        let repo = scratch.create();
        ostrya_rt::block_on(async {
            let guard = repo.begin_update().await.unwrap();
            write_three_dirs(&guard).await;
            let before = test_syncs::count(&scratch.path());
            drop(guard.finish());
            assert_eq!(syncs_when_free(&repo, &scratch.path()).await, before + 3);
            assert_eq!(test_syncs::unlocked(&scratch.path()), 0);
        });
    }

    #[test]
    fn finish_syncs_each_directory_once() {
        let scratch = Scratch::new("finish");
        let repo = scratch.create();
        ostrya_rt::block_on(async {
            let guard = repo.begin_update().await.unwrap();
            write_three_dirs(&guard).await;
            guard.set_ref("a/two", Some(&checksum())).await.unwrap();
            let before = test_syncs::count(&scratch.path());
            guard.finish().await.unwrap();
            assert_eq!(test_syncs::count(&scratch.path()), before + 3);
            assert_eq!(test_syncs::unlocked(&scratch.path()), 0);
        });
    }

    #[test]
    fn finish_waits_for_a_write_whose_future_was_dropped() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::time::Duration;

        let scratch = Scratch::new("in-flight");
        // A second take of the repository lock makes one attempt.
        let repo = scratch.create_with("lock-timeout-secs=0");
        let root = scratch.path();
        ostrya_rt::block_on(async {
            let guard = repo.begin_update().await.unwrap();
            let (started_tx, started_rx) = mpsc::channel();
            let (go_tx, go_rx) = mpsc::channel::<()>();
            let ended = Arc::new(AtomicBool::new(false));
            let ended_in = ended.clone();
            let mut write = Box::pin(guard.write(move |repo_fd, fsync, dirs| {
                started_tx.send(()).unwrap();
                go_rx.recv().unwrap();
                let written = put_ref_blocking(
                    repo_fd,
                    "refs/heads/late/one",
                    Some(checksum()),
                    fsync,
                    RepoMode::BareUser,
                    dirs,
                );
                ended_in.store(true, Ordering::SeqCst);
                written
            }));
            assert!(poll_once(&mut write).await.is_none());
            started_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("the write started on the blocking pool");
            drop(write);

            let before = test_syncs::count(&root);
            let mut finish = Box::pin(guard.finish());
            assert!(poll_once(&mut finish).await.is_none(), "finish waits");
            ostrya_rt::Timer::after(Duration::from_millis(100)).await;
            assert!(poll_once(&mut finish).await.is_none(), "finish waits");
            assert!(crate::lock::update_lock_held_in_process(repo.repo_fd()));

            go_tx.send(()).unwrap();
            finish.await.unwrap();
            assert!(ended.load(Ordering::SeqCst), "the write ended first");
            // refs/heads/late and refs/heads.
            assert_eq!(test_syncs::count(&root), before + 2);
            assert_eq!(test_syncs::unlocked(&root), 0);
            assert!(!crate::lock::update_lock_held_in_process(repo.repo_fd()));
            let exclusive = repo.lock_repo(LockKind::Exclusive).await.unwrap();
            drop(exclusive);
        });
    }

    #[test]
    fn fsync_off_records_no_directory() {
        let scratch = Scratch::new("no-fsync");
        let repo = scratch.create_with("fsync=false");
        ostrya_rt::block_on(async {
            let guard = repo.begin_update().await.unwrap();
            write_three_dirs(&guard).await;
            let before = test_syncs::count(&scratch.path());
            guard.finish().await.unwrap();
            assert_eq!(test_syncs::count(&scratch.path()), before);
        });
    }
}
