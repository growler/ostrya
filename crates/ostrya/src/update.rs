//! The update guard: an exclusive hold on the writes of refs and `config`.
//!
//! [`Repo::begin_update`] takes the update lock on `<repo>/.update.lock` and
//! returns an [`UpdateGuard`]. The guard writes refs, ref aliases, and
//! `config`, and edits the remotes of `config` and of the remotes directory.
//! [`UpdateGuard::finish`] syncs the changed directories and releases the
//! guard.

use std::collections::BTreeSet;
use std::os::fd::BorrowedFd;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use ostrya_core::{Checksum, KeyFile};
use rustix::fs::AtFlags;
use rustix::io::Errno;

use crate::config::{
    RemoteSource, RepoConfig, remote_group, remote_group_name, remote_keyring_name,
    valid_remote_name,
};
use crate::error::{Error, Result};
use crate::lock::UpdateLocks;
use crate::refs::{
    CollectionRef, collection_ref_to_relpath, put_alias_blocking, put_ref_blocking,
    refspec_to_relpath, relative_link, sync_dirs_all,
};
use crate::remotes_dir::{self, DirWriter};
use crate::repo::{RemotesDir, Repo, check_config_size, read_config_blocking};
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
/// reads and writes `config` and the `.conf` files of the remotes directory.
/// It stages no object. Each write of the guard is atomic and visible when
/// the call returns.
///
/// # Remotes
///
/// The guard edits the remotes of `config` and of the `.conf` files of the
/// remotes directory, [`Repo::remotes_dir`], as a read-modify-write of the
/// files on disk:
///
/// - [`add_remote`](UpdateGuard::add_remote)
/// - [`set_remote_key`](UpdateGuard::set_remote_key)
/// - [`unset_remote_key`](UpdateGuard::unset_remote_key)
/// - [`replace_remote`](UpdateGuard::replace_remote)
/// - [`delete_remote`](UpdateGuard::delete_remote), which also removes the
///   repository keyring of the remote
///
/// An add writes a new remote into the remotes directory if the handle has
/// one and `[core] add-remotes-config-dir` of `config` is not `false`. Else
/// it writes into `config`. Each other call edits the file that holds the
/// remote, so a remote stays in its file.
///
/// Each of these calls reads `config` and the remotes directory again, and
/// [`write_config`](UpdateGuard::write_config) reads the remotes directory
/// again. A `.conf` file that an open refuses, and that comes into the
/// directory after the open, makes each of these calls fail.
///
/// A write of a `.conf` file is atomic: the guard writes a temporary file in
/// the directory, whose name does not end in `.conf`, and renames it over the
/// file. With `[core] fsync` on, the write syncs the file and the directory
/// before the call returns. A rewrite of a file keeps its permission bits,
/// and does not keep its owner. The guard refuses a rewrite of a `.conf` file
/// that is a symlink, because the rename replaces the link with a regular
/// file.
///
/// The update lock is the lock of one repository. Two repositories that
/// share one remotes directory do not exclude each other. Each write changes
/// one entry of the directory, so a race of the two loses at most the edit
/// of one file.
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
/// - [`Repo::regenerate_summary`], [`Repo::regenerate_summaries`],
///   [`Repo::sign_summary`], [`Repo::sign_summary_all`], and the `summary`
///   and `summary.sig` writes of a mirror pull.
/// - [`Repo::write_commit_detached_metadata`],
///   [`Repo::add_detached_related`], [`Repo::sign_commit`], and
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
    /// refspec. It reads the path of the collection ref alone. For the
    /// collection id of the repository, it does not read `refs/heads/NAME`
    /// when the mirror ref is absent. [`Repo::resolve_collection_ref`] reads
    /// a collection ref with no lock, and for the collection id of the
    /// repository it reads `refs/heads/NAME` when the mirror path holds no
    /// ref file.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if the collection id does not pass
    ///   [`is_collection_id`](crate::is_collection_id) or is longer than 255
    ///   bytes, or if the ref name is not valid. The call reads no file.
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
    /// - [`Error::InvalidRefspec`] if the collection id does not pass
    ///   [`is_collection_id`](crate::is_collection_id) or is longer than 255
    ///   bytes, or if the ref name is not valid. The call writes nothing.
    /// - [`Error::Io`] if a file system operation fails.
    ///
    /// If a directory of `refs/mirrors/` has a name that fails the rule, a
    /// ref under it cannot be written or removed through this call. Remove
    /// such a ref by hand.
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

    /// Reads the `config` file and the `.conf` files of the remotes directory
    /// of the handle from disk and parses them.
    ///
    /// The repository handle keeps the config that it read at open. A
    /// read-modify-write of `config` under the guard reads the file with this
    /// call. The call reads the directory of
    /// [`Repo::remotes_dir`](crate::Repo::remotes_dir), and does not read the
    /// key `[ex-ostrya] remotes-config-dir` again.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `config` is larger than 1 MiB or is not
    ///   UTF-8.
    /// - An error of [`RepoConfig::parse`] if `config` does not parse.
    /// - [`Error::Io`] if the read fails.
    /// - The errors of [`OpenOptions::open`](crate::OpenOptions::open) for the
    ///   remotes directory and its `.conf` files.
    pub async fn read_config(&self) -> Result<RepoConfig> {
        self.repo().read_config_and_remotes().await
    }

    /// Reads the `config` file from disk and parses it, as
    /// [`read_config`](UpdateGuard::read_config) does. The call does not read
    /// the remotes directory, so the config has no remotes of the directory.
    ///
    /// The function is not a stable API.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `config` is larger than 1 MiB or is not
    ///   UTF-8.
    /// - An error of [`RepoConfig::parse`] if `config` does not parse.
    /// - [`Error::Io`] if the read fails.
    #[doc(hidden)]
    pub async fn read_config_file(&self) -> Result<RepoConfig> {
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
    /// The call refuses a document with a `[remote "NAME"]` group when a
    /// `.conf` file of the remotes directory defines `NAME`, as
    /// [`Repo::write_config`] does. It reads the directory again for this
    /// check.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the document is larger than 1 MiB, the
    ///   size that an open accepts. The call then writes nothing.
    /// - [`Error::RemoteExists`] if the document has a group of a remote of
    ///   the remotes directory. The call then writes nothing.
    /// - The errors of [`OpenOptions::open`](crate::OpenOptions::open) for the
    ///   remotes directory and its `.conf` files.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn write_config(&self, keyfile: &KeyFile) -> Result<()> {
        let bytes = config_bytes(keyfile)?;
        let names = remotes_dir::config_remote_names(keyfile);
        let dir = self.repo().remotes_dir().cloned();
        self.edit_config(move |repo_fd, fsync, dirs| {
            remotes_dir::check_config_remotes(repo_fd, dir.as_ref(), &names)?;
            put_config_blocking(repo_fd, &bytes, fsync, dirs)
        })
        .await
    }

    /// Adds the remote `name`, with the keys of `keys` in order.
    ///
    /// If the handle has a remotes directory and `[core]
    /// add-remotes-config-dir` of `config` is not `false`, the call writes
    /// the file `<name>.conf` into the directory. The file holds the one
    /// group `[remote "<name>"]`. Its mode is `0666` with the umask applied.
    /// If the directory is absent, the call creates it and each absent
    /// parent, at mode `0777` with the umask applied. The call refuses the
    /// name if the directory holds an entry `<name>.conf` of any type.
    ///
    /// Else the `[remote "<name>"]` group goes at the end of `config`. The
    /// call does not touch a trusted keyring of the name. A refusal writes
    /// nothing.
    ///
    /// The call reads `config` and the remotes directory from disk, edits
    /// the target, and writes it in one step on the blocking pool. It writes
    /// `config` as [`write_config`](UpdateGuard::write_config) does:
    /// atomically, with the sync of the repository directory left to
    /// [`finish`](UpdateGuard::finish). It writes a `.conf` file as
    /// [`UpdateGuard`] states in "Remotes". [`Repo::config`] keeps the copy
    /// that the handle read at open.
    ///
    /// The rewrite of `config` keeps the groups and keys of the file in their
    /// order. It drops the comment lines and the blank lines of the file.
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
    ///   `keys` is empty, or if a key file cannot hold a key name of `keys`.
    /// - [`Error::RemoteExists`] if `config` or a `.conf` file has a remote
    ///   of that name.
    /// - [`Error::Io`] of the kind
    ///   [`AlreadyExists`](std::io::ErrorKind::AlreadyExists) if the call
    ///   writes into the remotes directory and the directory holds an entry
    ///   `<name>.conf`. The message starts with the path of the entry.
    /// - [`Error::Core`] if `[core] add-remotes-config-dir` is not a boolean.
    ///   The call reads the key only for a handle with a remotes directory.
    /// - The errors of [`read_config`](UpdateGuard::read_config).
    /// - [`Error::InvalidFormat`] if the new file is larger than 1 MiB.
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
        let dir = self.repo().remotes_dir().cloned();
        self.edit_config(move |repo_fd, fsync, dirs| {
            let (config, writer) = read_sources(repo_fd, dir.as_ref(), fsync)?;
            if config.remote(&name).is_some() {
                return Err(Error::RemoteExists(name));
            }
            let writer = match writer {
                Some(writer) if config.add_remotes_config_dir()? => Some(writer),
                _ => None,
            };
            let group = remote_group(&name);
            let mut keyfile = match writer {
                Some(_) => KeyFile::default(),
                None => config.into_keyfile(),
            };
            for (key, value) in &keys {
                check_key(key)?;
                keyfile.set_string(&group, key, value)?;
            }
            match writer {
                Some(writer) => {
                    let file = remote_file_name(&name);
                    writer.check_absent(&file)?;
                    writer.put(&file, keyfile.to_string().as_bytes(), None)
                }
                None => put_config_blocking(repo_fd, &config_bytes(&keyfile)?, fsync, dirs),
            }
        })
        .await
    }

    /// Sets the key `key` of the remote `name` to `value`, in the file that
    /// holds the remote: `config` or a `.conf` file of the remotes directory.
    ///
    /// A key that exists keeps its position. A new key goes at the end of the
    /// group. If the key holds `value` already, the call writes nothing.
    ///
    /// The call reads the files and writes `config` as
    /// [`add_remote`](UpdateGuard::add_remote) does. A rewrite of a `.conf`
    /// file keeps the other groups of the file and the groups and keys in
    /// their order, and drops the comment lines and the blank lines. A
    /// refusal writes nothing.
    ///
    /// # Errors
    ///
    /// - [`Error::RemoteNotFound`] if no source holds the remote.
    /// - [`Error::InvalidInput`] if a key file cannot hold the key name.
    /// - [`Error::InvalidFormat`] if the `.conf` file of the remote is a
    ///   symlink.
    /// - The errors of [`read_config`](UpdateGuard::read_config).
    /// - [`Error::InvalidFormat`] if the new file is larger than 1 MiB.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn set_remote_key(&self, name: &str, key: &str, value: &str) -> Result<()> {
        let name = name.to_owned();
        let key = key.to_owned();
        let value = value.to_owned();
        let dir = self.repo().remotes_dir().cloned();
        self.edit_config(move |repo_fd, fsync, dirs| {
            let group = remote_group(&name);
            let mut source = Source::read(repo_fd, dir.as_ref(), fsync, &name)?;
            check_key(&key)?;
            let keyfile = source.keyfile_mut();
            if matches!(keyfile.get_string(&group, &key), Ok(Some(held)) if held == value) {
                return Ok(());
            }
            keyfile.set_string(&group, &key, &value)?;
            source.put(repo_fd, fsync, dirs)
        })
        .await
    }

    /// Removes the key `key` of the remote `name` from the file that holds
    /// the remote.
    ///
    /// The call returns `true` if it removed the key. If the key is absent,
    /// the call returns `false` and writes nothing. The group stays, also when
    /// it has no key left.
    ///
    /// The call reads and writes the files as
    /// [`set_remote_key`](UpdateGuard::set_remote_key) does.
    ///
    /// # Errors
    ///
    /// - [`Error::RemoteNotFound`] if no source holds the remote. The call
    ///   then writes nothing.
    /// - [`Error::InvalidFormat`] if the `.conf` file of the remote is a
    ///   symlink.
    /// - The errors of [`read_config`](UpdateGuard::read_config).
    /// - [`Error::InvalidFormat`] if the new file is larger than 1 MiB.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn unset_remote_key(&self, name: &str, key: &str) -> Result<bool> {
        let name = name.to_owned();
        let key = key.to_owned();
        let dir = self.repo().remotes_dir().cloned();
        self.edit_config(move |repo_fd, fsync, dirs| {
            let group = remote_group(&name);
            let mut source = Source::read(repo_fd, dir.as_ref(), fsync, &name)?;
            if !source.keyfile_mut().remove_key(&group, &key) {
                return Ok(false);
            }
            source.put(repo_fd, fsync, dirs)?;
            Ok(true)
        })
        .await
    }

    /// Replaces the remote `name` with a remote of the keys of `keys`, in
    /// order, in the file that holds it.
    ///
    /// The call removes the `[remote "<name>"]` group from its source,
    /// `config` or a `.conf` file of the remotes directory, and writes a new
    /// group with `keys` at the end of the same source. The other groups of
    /// the source stay. The call does not touch a trusted keyring of the
    /// name. A refusal writes nothing.
    ///
    /// The call reads and writes the source as
    /// [`set_remote_key`](UpdateGuard::set_remote_key) does.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if [`valid_remote_name`] refuses `name`, if
    ///   `keys` is empty, or if a key file cannot hold a key name of `keys`.
    /// - [`Error::RemoteNotFound`] if no source holds the remote.
    /// - [`Error::InvalidFormat`] if the `.conf` file of the remote is a
    ///   symlink.
    /// - The errors of [`read_config`](UpdateGuard::read_config).
    /// - [`Error::InvalidFormat`] if the new file is larger than 1 MiB.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn replace_remote(&self, name: &str, keys: &[(&str, &str)]) -> Result<()> {
        if !valid_remote_name(name) {
            return Err(Error::InvalidInput(format!("invalid remote name: {name}")));
        }
        if keys.is_empty() {
            return Err(Error::InvalidInput(format!(
                "remote {name} is replaced with no keys"
            )));
        }
        let name = name.to_owned();
        let keys: Vec<(String, String)> = keys
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        let dir = self.repo().remotes_dir().cloned();
        self.edit_config(move |repo_fd, fsync, dirs| {
            let group = remote_group(&name);
            let mut source = Source::read(repo_fd, dir.as_ref(), fsync, &name)?;
            let keyfile = source.keyfile_mut();
            keyfile.remove_group(&group);
            for (key, value) in &keys {
                check_key(key)?;
                keyfile.set_string(&group, key, value)?;
            }
            source.put(repo_fd, fsync, dirs)
        })
        .await
    }

    /// Deletes the remote `name` from the file that holds it, together with
    /// its repository keyring.
    ///
    /// The call removes the trusted keyring `<name>.trustedkeys.gpg` at the
    /// repository root, and then the group of the remote from its file. An
    /// absent keyring is not an error. A keyring name that is too long for the
    /// file system is not an error, because no file can have that name. The
    /// call does not remove a keyring of the remotes directory.
    ///
    /// In a `.conf` file of the remotes directory, the call removes the group.
    /// If the file then holds no `[remote "NAME"]` group, the call removes the
    /// file, together with each other group of it. For a symlink, it removes
    /// the link, and the target stays. Else it writes the file back, as
    /// [`set_remote_key`](UpdateGuard::set_remote_key) does.
    ///
    /// The repository keyring goes with the remote. A keyring of the remotes
    /// directory stays, as the `ostree` command keeps it. A later remote of the
    /// same name trusts the keys of that keyring while the repository holds no
    /// keyring of that name. The repository keyring goes first, so a failure
    /// between the two steps can leave a remote with no repository keyring. It
    /// cannot leave a repository keyring with no remote.
    ///
    /// The removal is visible when the call returns. The sync of the
    /// repository directory waits for [`finish`](UpdateGuard::finish). The
    /// call reads the files and writes `config` as
    /// [`add_remote`](UpdateGuard::add_remote) does. A refusal removes no
    /// file and writes nothing.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if [`valid_remote_name`] refuses `name`.
    /// - [`Error::RemoteNotFound`] if no source holds the remote.
    /// - [`Error::InvalidFormat`] if the call writes back a `.conf` file that
    ///   is a symlink.
    /// - The errors of [`read_config`](UpdateGuard::read_config).
    /// - [`Error::InvalidFormat`] if the new file is larger than 1 MiB.
    /// - [`Error::Io`] if the removal of the keyring or the write of the file
    ///   fails.
    pub async fn delete_remote(&self, name: &str) -> Result<()> {
        if !valid_remote_name(name) {
            return Err(Error::InvalidInput(format!("invalid remote name: {name}")));
        }
        let name = name.to_owned();
        let dir = self.repo().remotes_dir().cloned();
        self.edit_config(move |repo_fd, fsync, dirs| {
            let group = remote_group(&name);
            let keyring = remote_keyring_name(&name);
            match Source::read(repo_fd, dir.as_ref(), fsync, &name)? {
                Source::Config(mut keyfile) => {
                    keyfile.remove_group(&group);
                    let bytes = config_bytes(&keyfile)?;
                    let removed = remove_keyring_blocking(repo_fd, &keyring)?;
                    let put = put_root_file_blocking(repo_fd, CONFIG_FILE, &bytes, fsync);
                    if fsync && (removed || put.is_ok()) {
                        dirs.push(ROOT_DIR.to_owned());
                    }
                    put
                }
                Source::File {
                    writer,
                    file,
                    mut keyfile,
                } => {
                    keyfile.remove_group(&group);
                    // Each check comes before the removal of the keyring.
                    let rewrite = if keyfile.groups().any(|g| remote_group_name(g).is_some()) {
                        let bytes = keyfile.to_string().into_bytes();
                        writer.check_size(&file, &bytes)?;
                        Some((writer.mode_of(&file)?, bytes))
                    } else {
                        None
                    };
                    if remove_keyring_blocking(repo_fd, &keyring)? && fsync {
                        dirs.push(ROOT_DIR.to_owned());
                    }
                    match rewrite {
                        Some((mode, bytes)) => writer.put(&file, &bytes, Some(mode)),
                        None => writer.remove(&file),
                    }
                }
            }
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

/// Returns the name of the `.conf` file that an add writes for the remote
/// `name`.
fn remote_file_name(name: &str) -> String {
    format!("{name}.conf")
}

/// Reads `config` and the `.conf` files of the remotes directory `dir` from
/// disk, as [`UpdateGuard::read_config`] reads them. Returns the directory
/// open for a write if the handle has one.
fn read_sources<'a>(
    repo_fd: BorrowedFd<'a>,
    dir: Option<&'a RemotesDir>,
    fsync: bool,
) -> Result<(RepoConfig, Option<DirWriter<'a>>)> {
    let config = read_config_blocking(repo_fd)?;
    match dir {
        Some(dir) => remotes_dir::open_for_write(config, repo_fd, dir, fsync)
            .map(|(config, writer)| (config, Some(writer))),
        None => Ok((config, None)),
    }
}

/// The file on disk that holds a remote, with its parsed text.
enum Source<'a> {
    /// The `config` file of the repository.
    Config(KeyFile),
    /// The `.conf` file `file` of the remotes directory.
    File {
        writer: DirWriter<'a>,
        file: String,
        keyfile: KeyFile,
    },
}

impl<'a> Source<'a> {
    /// Reads the sources from disk, as [`read_sources`] does, and returns the
    /// source that holds the remote `name`.
    ///
    /// # Errors
    ///
    /// [`Error::RemoteNotFound`] if no source holds the remote, and the
    /// errors of the read.
    fn read(
        repo_fd: BorrowedFd<'a>,
        dir: Option<&'a RemotesDir>,
        fsync: bool,
        name: &str,
    ) -> Result<Source<'a>> {
        let (config, writer) = read_sources(repo_fd, dir, fsync)?;
        let not_found = || Error::RemoteNotFound(name.to_owned());
        let file = match config.remote(name).ok_or_else(not_found)?.source() {
            RemoteSource::Config => None,
            RemoteSource::File(file) => Some(file.to_owned()),
        };
        let Some(file) = file else {
            return Ok(Source::Config(config.into_keyfile()));
        };
        let keyfile = config.into_remote_file(&file).ok_or_else(not_found)?;
        Ok(Source::File {
            writer: writer.ok_or_else(not_found)?,
            file,
            keyfile,
        })
    }

    fn keyfile_mut(&mut self) -> &mut KeyFile {
        match self {
            Source::Config(keyfile) | Source::File { keyfile, .. } => keyfile,
        }
    }

    /// Writes the edited text back to its file.
    ///
    /// A write of `config` records the repository root for the sync of
    /// [`UpdateGuard::finish`]. A write of a `.conf` file keeps the permission
    /// bits of the file, syncs before it returns, and refuses a file that is
    /// a symlink.
    fn put(&self, repo_fd: BorrowedFd<'_>, fsync: bool, dirs: &mut Vec<String>) -> Result<()> {
        match self {
            Source::Config(keyfile) => {
                put_config_blocking(repo_fd, &config_bytes(keyfile)?, fsync, dirs)
            }
            Source::File {
                writer,
                file,
                keyfile,
            } => {
                let mode = writer.mode_of(file)?;
                writer.put(file, keyfile.to_string().as_bytes(), Some(mode))
            }
        }
    }
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
    let _ = |guard: &UpdateGuard| assert_send(&guard.replace_remote("r", &[("url", "u")]));
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
