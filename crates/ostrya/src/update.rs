//! The update guard: an exclusive hold on the writes of refs and `config`.
//!
//! [`Repo::begin_update`] takes the update lock on `<repo>/.update.lock` and
//! returns an [`UpdateGuard`]. The guard writes refs, ref aliases, and
//! `config`, and edits the remotes of `config`. [`UpdateGuard::finish`] syncs
//! the changed directories and releases the guard.

use std::collections::BTreeSet;
use std::os::fd::BorrowedFd;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use ostrya_core::{Checksum, KeyFile};
use rustix::fs::AtFlags;
use rustix::io::Errno;

use crate::config::{RepoConfig, remote_group, remote_keyring_name, valid_remote_name};
use crate::error::{Error, Result};
use crate::lock::UpdateLocks;
use crate::refs::{
    CollectionRef, collection_ref_to_relpath, put_alias_blocking, put_ref_blocking,
    refspec_to_relpath, relative_link, sync_dirs_all,
};
use crate::repo::{Repo, check_config_size, read_config_blocking};
use crate::summary::put_root_file_blocking;

/// The config file name at the repository root.
const CONFIG_FILE: &str = "config";

/// The directory that holds `config`: the repository root.
const ROOT_DIR: &str = ".";

/// A group name that a key file accepts. `check_key` sets a key in this group
/// to check the key name alone.
const KEY_CHECK_GROUP: &str = "remote";

/// An exclusive hold on the writes of refs and `config` of one repository.
///
/// [`Repo::begin_update`] returns the guard. The guard holds the repository
/// lock shared and the update lock. The update lock is exclusive across
/// processes and inside the process.
///
/// The guard is a value: a caller holds it, passes it, and stores it. It is
/// `Send + Sync`.
///
/// The guard reads and writes refs, collection refs, and ref aliases. It
/// reads `config` from disk and writes `config`. It stages no object. Each
/// write of the guard is atomic and visible when the call returns.
///
/// # Remotes
///
/// The guard edits the remotes of `config` as a read-modify-write of the file
/// on disk:
///
/// - [`add_remote`](UpdateGuard::add_remote)
/// - [`set_remote_key`](UpdateGuard::set_remote_key)
/// - [`unset_remote_key`](UpdateGuard::unset_remote_key)
/// - [`delete_remote`](UpdateGuard::delete_remote), which also removes the
///   trusted keyring of the remote
///
/// These calls and [`write_config`](UpdateGuard::write_config) run one at a
/// time on one guard.
///
/// # Writers that wait for the guard
///
/// A holder of the guard must write refs and `config` through the guard.
/// These writers wait for the guard:
///
/// - [`Transaction::commit`](crate::Transaction::commit) of a transaction
///   that writes a ref or detached metadata, at the step that writes them. A
///   pull and the transaction commit of a receive session wait at this step.
/// - [`Repo::set_ref_immediate`], [`Repo::set_collection_ref_immediate`],
///   and [`Repo::set_ref_alias_immediate`].
/// - [`Repo::write_config`], [`Repo::remove_remote_keyring`], and, under the
///   `verify-gpg` feature, `Repo::gpg_import_keys`.
/// - [`Repo::regenerate_summary`], [`Repo::sign_summary`],
///   [`Repo::sign_summary_all`], and the `summary` and `summary.sig` writes
///   of a mirror pull.
/// - [`Repo::write_commit_detached_metadata`], [`Repo::sign_commit`], and
///   [`Repo::delete_signatures`].
///
/// If `[core] locking` is on, [`Repo::prune`] also waits for the guard,
/// because the guard holds the repository lock shared.
///
/// # A holder that waits for its own guard
///
/// No call detects a holder that waits for its own guard. This wait occurs
/// if a task that holds the guard calls one of the writers that wait for the
/// guard. It also occurs if that task waits for another task that calls one
/// of these writers.
///
/// In both cases the wait lasts until `[core] lock-timeout-secs` passes. The
/// writer then fails with [`Error::LockTimeout`]. If `lock-timeout-secs` is
/// `-1`, the task waits forever.
///
/// # Release
///
/// [`finish`](UpdateGuard::finish) releases the guard. A guard that drops
/// without `finish` runs the directory syncs of `finish` synchronously, on
/// the thread that drops the last reference to its state. It hides every
/// error and then releases both locks.
///
/// That thread is the thread that drops the guard, or the blocking-pool
/// thread of a write that still runs. The syncs block that thread, so an
/// async caller releases the guard with `finish`.
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
    /// Held for the whole of each edit and each write of `config`, so the
    /// read-modify-writes of one guard do not interleave.
    config: Mutex<()>,
    /// Signaled when the last write in flight ends.
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

    /// Waits until no write is in flight, syncs each recorded directory, and
    /// releases both locks. Blocks the calling thread.
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

    /// Releases both locks.
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

/// Methods that hold the update lock.
impl Repo {
    /// Takes the repository lock shared and the update lock, and returns the
    /// guard.
    ///
    /// The returned [`UpdateGuard`] holds both locks until
    /// [`finish`](UpdateGuard::finish) or its drop releases them.
    ///
    /// # Lock order
    ///
    /// The call takes the repository lock first. A transaction also holds it
    /// shared, so a pull does not make this step wait. If `[core] locking` is
    /// on, the call waits for a [`Repo::prune`] and for each other holder of
    /// the repository lock in
    /// [`LockKind::Exclusive`](crate::LockKind::Exclusive).
    ///
    /// If `[core] locking` is `false`, the call does not take the repository
    /// lock. It always takes the update lock.
    ///
    /// # Update lock
    ///
    /// The update lock is exclusive across processes and inside the process.
    /// The waiters of one process take it in the order of the first poll of
    /// their wait for the update lock. A release always drops the record lock,
    /// so another process can take the lock between two holders of this
    /// process.
    ///
    /// The `ostree` command never opens `.update.lock`, so the update lock
    /// excludes ostrya processes alone.
    ///
    /// # Waits
    ///
    /// Each of the two waits gets the whole of `[core] lock-timeout-secs`. If
    /// `lock-timeout-secs` is `-1`, a wait has no limit. If it is `0`, a wait
    /// makes one attempt. This crate has no variant of this call that fails at
    /// once.
    ///
    /// The call reads `[core] fsync`, `[core] locking`, and `[core]
    /// lock-timeout-secs` before it waits. It reads them from the config that
    /// the handle read at open. The guard keeps these values, and a
    /// [`write_config`](UpdateGuard::write_config) through the guard does not
    /// change them.
    ///
    /// # While a caller holds the guard
    ///
    /// A caller can hold the guard for minutes. While it holds the guard:
    ///
    /// - Each other writer that [`UpdateGuard`] lists waits for the guard. If
    ///   the wait passes `lock-timeout-secs`, the writer fails with
    ///   [`Error::LockTimeout`]. A pull then fails at the step of its commit
    ///   that writes detached metadata and refs. A push then fails at `Commit`
    ///   with `internal`.
    /// - If `[core] locking` is on, a prune waits for the whole hold.
    /// - A transaction opens, stages, and publishes its objects in parallel
    ///   with the hold. It waits only at the step that writes detached
    ///   metadata and refs. A transaction that writes neither commits in
    ///   parallel with the hold.
    ///
    /// A holder must write through the guard. [`UpdateGuard`] states the
    /// result if a holder waits for its own guard.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if `[core] fsync` or `[core] locking` is not a
    ///   boolean, or if `[core] lock-timeout-secs` is not an integer.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is less than
    ///   `-1`.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::Io`] if the open of a lock file or a lock request fails.
    pub async fn begin_update(&self) -> Result<UpdateGuard> {
        let fsync = self.config().fsync()?;
        let locks = self.lock_for_update().await?;
        Ok(UpdateGuard {
            held: Arc::new(Held {
                repo: self.clone(),
                fsync,
                state: Mutex::new(Writes::default()),
                config: Mutex::new(()),
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

    /// Returns the commit that a refspec names in the ref store.
    ///
    /// The call reads the ref as [`Repo::resolve_ref_tip`] reads it. If the
    /// store holds the ref as an alias, the call follows the alias to the ref
    /// that it names. The result is `None` if the store holds no such ref.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if `refspec` is not a valid refspec.
    /// - [`Error::InvalidFormat`] if the ref file is not UTF-8.
    /// - [`Error::Core`] if the ref file holds no checksum.
    /// - [`Error::Io`] if the read fails, for example if the ref path names a
    ///   directory.
    pub async fn read_ref(&self, refspec: &str) -> Result<Option<Checksum>> {
        self.repo().resolve_ref_tip(refspec).await
    }

    /// Returns the commit that a collection ref names in the ref store.
    ///
    /// The call reads the ref as [`read_ref`](UpdateGuard::read_ref) reads a
    /// refspec.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if the collection id is not one path
    ///   component, or if the ref name is not valid.
    /// - [`Error::InvalidFormat`] if the ref file is not UTF-8.
    /// - [`Error::Core`] if the ref file holds no checksum.
    /// - [`Error::Io`] if the read fails, for example if the ref path names a
    ///   directory.
    pub async fn read_collection_ref(&self, cref: &CollectionRef) -> Result<Option<Checksum>> {
        self.repo()
            .resolve_relpath_tip(collection_ref_to_relpath(cref)?)
            .await
    }

    /// Writes one ref atomically, as [`Repo::set_ref_immediate`] writes it.
    ///
    /// If `checksum` is `None`, the call removes the ref file. The ref is
    /// visible when the call returns. The sync of each directory that changed
    /// waits for [`finish`](UpdateGuard::finish).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if `refspec` is not a valid refspec.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn set_ref(&self, refspec: &str, checksum: Option<&Checksum>) -> Result<()> {
        let relpath = refspec_to_relpath(refspec)?;
        self.set_relpath(relpath, checksum).await
    }

    /// Writes one collection ref atomically, as
    /// [`set_ref`](UpdateGuard::set_ref) writes a refspec.
    ///
    /// If `checksum` is `None`, the call removes the ref file.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if the collection id is not one path
    ///   component, or if the ref name is not valid.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn set_collection_ref(
        &self,
        cref: &CollectionRef,
        checksum: Option<&Checksum>,
    ) -> Result<()> {
        let relpath = collection_ref_to_relpath(cref)?;
        self.set_relpath(relpath, checksum).await
    }

    /// Writes `refspec` as an alias of `target`, as
    /// [`Repo::set_ref_alias_immediate`] writes it.
    ///
    /// The alias is a relative symlink. It replaces the entry that `refspec`
    /// named before. The call checks both refspecs, and the two refs do not
    /// have to exist.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if `refspec` or `target` is not a valid
    ///   refspec.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn set_ref_alias(&self, refspec: &str, target: &str) -> Result<()> {
        let relpath = refspec_to_relpath(refspec)?;
        let link = relative_link(&relpath, &refspec_to_relpath(target)?);
        let repo_mode = self.repo().mode();
        self.write(move |repo_fd, fsync, dirs| {
            put_alias_blocking(repo_fd, &relpath, &link, fsync, repo_mode, dirs)
        })
        .await
    }

    /// Reads the `config` file from disk and parses it.
    ///
    /// The repository handle keeps the config that it read at open. A
    /// read-modify-write of `config` under the guard reads the file with this
    /// call.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `config` is larger than 1 MiB or is not
    ///   UTF-8.
    /// - An error of [`RepoConfig::parse`] if `config` does not parse.
    /// - [`Error::Io`] if the read fails.
    pub async fn read_config(&self) -> Result<RepoConfig> {
        self.repo().read_config_file().await
    }

    /// Replaces `config` with the document that `keyfile` holds.
    ///
    /// The call writes the file as [`Repo::write_config`] writes it. The new
    /// file is visible when the call returns. The sync of the repository
    /// directory waits for [`finish`](UpdateGuard::finish).
    ///
    /// The call writes the document as given. The repository handle and the
    /// guard keep the values that they read before. A new open of the
    /// repository reads the new values. The write does not interleave with a
    /// remote call of the same guard.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the document is larger than 1 MiB, the
    ///   size that an open accepts. The call then writes nothing.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn write_config(&self, keyfile: &KeyFile) -> Result<()> {
        let bytes = config_bytes(keyfile)?;
        self.edit_config(move |repo_fd, fsync, dirs| {
            put_config_blocking(repo_fd, &bytes, fsync, dirs)
        })
        .await
    }

    /// Adds the remote `name` to `config`, with the keys of `keys` in order.
    ///
    /// The `[remote "<name>"]` group goes at the end of the file. The call
    /// does not touch a trusted keyring of the name. A refusal writes nothing.
    ///
    /// The call reads `config` from disk, edits it, and writes it in one step
    /// on the blocking pool. It writes the file as
    /// [`write_config`](UpdateGuard::write_config) does: atomically, with the
    /// sync of the repository directory left to
    /// [`finish`](UpdateGuard::finish). [`Repo::config`] keeps the copy that
    /// the handle read at open.
    ///
    /// The rewrite keeps the groups and keys of the file in their order. It
    /// drops the comment lines and the blank lines of the file.
    ///
    /// The remote calls and [`write_config`](UpdateGuard::write_config) of one
    /// guard run one at a time, so concurrent calls on one guard lose no edit.
    /// If the future of a call drops after its first poll, the call makes the
    /// whole edit or none of it. An edit that runs completes, and `finish`
    /// waits for it.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if [`valid_remote_name`] refuses `name`, if
    ///   `keys` is empty, or if `config` cannot hold a key name of `keys`.
    /// - [`Error::RemoteExists`] if `config` has a remote of that name.
    /// - [`Error::InvalidFormat`] if `config` on disk is larger than 1 MiB or
    ///   is not UTF-8, or if the new `config` is larger than 1 MiB.
    /// - An error of [`RepoConfig::parse`] if `config` on disk does not parse.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn add_remote(&self, name: &str, keys: &[(&str, &str)]) -> Result<()> {
        if !valid_remote_name(name) {
            return Err(Error::InvalidInput(format!("invalid remote name: {name}")));
        }
        if keys.is_empty() {
            return Err(Error::InvalidInput(format!(
                "remote {name} is added with no keys"
            )));
        }
        let name = name.to_owned();
        let keys: Vec<(String, String)> = keys
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        self.edit_config(move |repo_fd, fsync, dirs| {
            let group = remote_group(&name);
            let mut keyfile = read_config_blocking(repo_fd)?.into_keyfile();
            if keyfile.has_group(&group) {
                return Err(Error::RemoteExists(name));
            }
            for (key, value) in &keys {
                check_key(key)?;
                keyfile.set_string(&group, key, value)?;
            }
            put_config_blocking(repo_fd, &config_bytes(&keyfile)?, fsync, dirs)
        })
        .await
    }

    /// Sets the key `key` of the remote `name` in `config` to `value`.
    ///
    /// A key that exists keeps its position. A new key goes at the end of the
    /// group. If the key holds `value` already, the call writes nothing.
    ///
    /// The call reads and writes `config` as
    /// [`add_remote`](UpdateGuard::add_remote) does. A refusal writes
    /// nothing.
    ///
    /// # Errors
    ///
    /// - [`Error::RemoteNotFound`] if `config` does not hold the remote.
    /// - [`Error::InvalidInput`] if `config` cannot hold the key name.
    /// - [`Error::InvalidFormat`] if `config` on disk is larger than 1 MiB or
    ///   is not UTF-8, or if the new `config` is larger than 1 MiB.
    /// - An error of [`RepoConfig::parse`] if `config` on disk does not parse.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn set_remote_key(&self, name: &str, key: &str, value: &str) -> Result<()> {
        let name = name.to_owned();
        let key = key.to_owned();
        let value = value.to_owned();
        self.edit_config(move |repo_fd, fsync, dirs| {
            let group = remote_group(&name);
            let mut keyfile = read_config_blocking(repo_fd)?.into_keyfile();
            if !keyfile.has_group(&group) {
                return Err(Error::RemoteNotFound(name));
            }
            check_key(&key)?;
            if matches!(keyfile.get_string(&group, &key), Ok(Some(held)) if held == value) {
                return Ok(());
            }
            keyfile.set_string(&group, &key, &value)?;
            put_config_blocking(repo_fd, &config_bytes(&keyfile)?, fsync, dirs)
        })
        .await
    }

    /// Removes the key `key` of the remote `name` from `config`.
    ///
    /// The call returns `true` if it removed the key. If the key is absent,
    /// the call returns `false` and writes nothing. The group stays, also when
    /// it has no key left.
    ///
    /// The call reads and writes `config` as
    /// [`add_remote`](UpdateGuard::add_remote) does.
    ///
    /// # Errors
    ///
    /// - [`Error::RemoteNotFound`] if `config` does not hold the remote. The
    ///   call then writes nothing.
    /// - [`Error::InvalidFormat`] if `config` on disk is larger than 1 MiB or
    ///   is not UTF-8, or if the new `config` is larger than 1 MiB.
    /// - An error of [`RepoConfig::parse`] if `config` on disk does not parse.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn unset_remote_key(&self, name: &str, key: &str) -> Result<bool> {
        let name = name.to_owned();
        let key = key.to_owned();
        self.edit_config(move |repo_fd, fsync, dirs| {
            let group = remote_group(&name);
            let mut keyfile = read_config_blocking(repo_fd)?.into_keyfile();
            if !keyfile.has_group(&group) {
                return Err(Error::RemoteNotFound(name));
            }
            if !keyfile.remove_key(&group, &key) {
                return Ok(false);
            }
            put_config_blocking(repo_fd, &config_bytes(&keyfile)?, fsync, dirs)?;
            Ok(true)
        })
        .await
    }

    /// Deletes the remote `name` from `config`, together with its trusted
    /// keyring.
    ///
    /// The call removes the trusted keyring `<name>.trustedkeys.gpg` at the
    /// repository root, and then the group of the remote from `config`. An
    /// absent keyring is not an error. A keyring name that is too long for the
    /// file system is not an error, because no file can have that name.
    ///
    /// The keyring goes with the remote, so a later remote of the same name
    /// does not trust the keys of this one. The keyring goes first, so a
    /// failure between the two steps can leave a remote with no keys. It
    /// cannot leave keys with no remote.
    ///
    /// The removal is visible when the call returns. The sync of the
    /// repository directory waits for [`finish`](UpdateGuard::finish). The
    /// call reads and writes `config` as
    /// [`add_remote`](UpdateGuard::add_remote) does. A refusal removes no
    /// file and writes nothing.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if [`valid_remote_name`] refuses `name`.
    /// - [`Error::RemoteNotFound`] if `config` does not hold the remote.
    /// - [`Error::InvalidFormat`] if `config` on disk is larger than 1 MiB or
    ///   is not UTF-8, or if the new `config` is larger than 1 MiB.
    /// - An error of [`RepoConfig::parse`] if `config` on disk does not parse.
    /// - [`Error::Io`] if the removal of the keyring or the write of `config`
    ///   fails.
    pub async fn delete_remote(&self, name: &str) -> Result<()> {
        if !valid_remote_name(name) {
            return Err(Error::InvalidInput(format!("invalid remote name: {name}")));
        }
        let name = name.to_owned();
        self.edit_config(move |repo_fd, fsync, dirs| {
            let mut keyfile = read_config_blocking(repo_fd)?.into_keyfile();
            if !keyfile.remove_group(&remote_group(&name)) {
                return Err(Error::RemoteNotFound(name));
            }
            let bytes = config_bytes(&keyfile)?;
            let removed = remove_keyring_blocking(repo_fd, &remote_keyring_name(&name))?;
            let put = put_root_file_blocking(repo_fd, CONFIG_FILE, &bytes, fsync);
            if fsync && (removed || put.is_ok()) {
                dirs.push(ROOT_DIR.to_owned());
            }
            put
        })
        .await
    }

    /// Syncs the directories that the writes changed, and releases both locks.
    ///
    /// The call first waits until each write of the guard ends. It then runs
    /// `fsync` once on each directory that a write changed, deepest first. It
    /// then releases the update lock and the repository lock. If `[core]
    /// fsync` is off, the guard records no directory, and the call runs no
    /// sync.
    ///
    /// The wait covers a write whose future was dropped while its work on the
    /// blocking pool still ran. That work ends before the syncs start, so the
    /// call syncs the directories of each write of the guard. Both locks are
    /// free when the call returns.
    ///
    /// The call runs each sync, also after a sync that fails. The release of
    /// the locks comes after the syncs, also if the returned future drops
    /// before it completes.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if a sync fails. The call returns the error of the
    ///   first sync that fails.
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

    /// Runs `edit` as a write of the guard, as [`write`](UpdateGuard::write)
    /// runs it, and holds the `config` lock of the guard for the whole edit.
    async fn edit_config<T, F>(&self, edit: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd<'_>, bool, &mut Vec<String>) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let held = self.held.clone();
        self.write(move |repo_fd, fsync, dirs| {
            let _config = held.config.lock().unwrap_or_else(PoisonError::into_inner);
            edit(repo_fd, fsync, dirs)
        })
        .await
    }

    /// Runs the write `put` on the blocking pool and records the directories
    /// that it changed.
    ///
    /// The closure owns a reference to the held state and counts in flight
    /// until it ends. A write whose future drops still holds both locks until
    /// it ends, and still records its directories. It also holds
    /// [`finish`](UpdateGuard::finish) back until it ends.
    async fn write<T, F>(&self, put: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd<'_>, bool, &mut Vec<String>) -> Result<T> + Send + 'static,
        T: Send + 'static,
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

/// Refuses a key name that no key file can hold, as an argument error of the
/// caller. The check sets the key alone in an empty key file. As a result, an
/// error of the group of `config` does not count as an error of the key.
fn check_key(key: &str) -> Result<()> {
    KeyFile::default()
        .set_string(KEY_CHECK_GROUP, key, "")
        .map_err(|e| Error::InvalidInput(e.to_string()))
}

/// Returns the bytes of `keyfile` as `config` holds them. Refuses a document
/// larger than the size that an open accepts.
fn config_bytes(keyfile: &KeyFile) -> Result<Vec<u8>> {
    let bytes = keyfile.to_string().into_bytes();
    check_config_size(&bytes)?;
    Ok(bytes)
}

/// Writes `bytes` to `config` atomically and records the repository root.
fn put_config_blocking(
    repo_fd: BorrowedFd<'_>,
    bytes: &[u8],
    fsync: bool,
    dirs: &mut Vec<String>,
) -> Result<()> {
    put_root_file_blocking(repo_fd, CONFIG_FILE, bytes, fsync)?;
    if fsync {
        dirs.push(ROOT_DIR.to_owned());
    }
    Ok(())
}

/// Removes the trusted keyring `name` at the repository root, and returns
/// `true` if a file was removed. An absent file is not an error. A name that
/// is too long for the file system is not an error, because no file can have
/// that name.
fn remove_keyring_blocking(repo_fd: BorrowedFd<'_>, name: &str) -> Result<bool> {
    match rustix::fs::unlinkat(repo_fd, name, AtFlags::empty()) {
        Ok(()) => Ok(true),
        Err(Errno::NOENT | Errno::NAMETOOLONG) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Compile-time checks that the guard is `Send + Sync` and that the futures of
/// its calls are `Send`.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>(_: &T) {}
    assert_send_sync::<UpdateGuard>();
    let _ = |repo: &Repo| assert_send(&repo.begin_update());
    let _ = |guard: &UpdateGuard, c: &Checksum| assert_send(&guard.set_ref("r", Some(c)));
    let _ = |guard: &UpdateGuard, k: &KeyFile| assert_send(&guard.write_config(k));
    let _ = |guard: &UpdateGuard| assert_send(&guard.add_remote("r", &[("url", "u")]));
    let _ = |guard: &UpdateGuard| assert_send(&guard.set_remote_key("r", "url", "u"));
    let _ = |guard: &UpdateGuard| assert_send(&guard.unset_remote_key("r", "url"));
    let _ = |guard: &UpdateGuard| assert_send(&guard.delete_remote("r"));
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

    /// A scratch directory that holds a repository at `repo`. The drop of the
    /// value removes the directory.
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

        /// Creates the repository with `line` added to the `[core]` group.
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

    /// Takes both locks again, as another writer does, and returns the number
    /// of directory syncs under the repository at that point.
    async fn syncs_when_free(repo: &Repo, root: &std::path::Path) -> usize {
        let held = repo.lock_update().await.unwrap();
        let exclusive = repo.lock_repo(LockKind::Exclusive).await.unwrap();
        let count = test_syncs::count(root);
        drop((exclusive, held));
        count
    }

    /// Writes two refs in two directories and a config through `guard`, so
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
