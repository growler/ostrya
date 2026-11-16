//! Per-transaction staging directories under `<repo>/tmp`.
//!
//! The `Transaction` type doc, under `# Staging directory`, states the names,
//! the locks, and the rules of the reaper that a caller sees.
//!
//! The open of a staging lock file, its record lock, the status reads, the
//! listing of `tmp/`, and each removal go through the primitives of
//! `repo_fs`.
//!
//! A process-global map holds the staging directories that this process owns.
//! The reaper does not touch a directory in this map. The record locks are
//! process-associated. A lock through a second descriptor to a live sibling
//! lock does not conflict, and the close of that descriptor releases the hold.
//!
//! A directory enters the map before its creation and leaves the map after its
//! removal. As a result, each directory that a reaper of the same process can
//! list is in the map.
//!
//! Each entry of the map holds a handle of the `tmp/` directory that holds the
//! staging directory. With these handles, [`reap_owned`] removes each
//! owned directory without a live [`StagingDir`]. A process that ends without
//! its destructors calls it through
//! [`reap_process_staging`](crate::reap_process_staging).

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::ops::ControlFlow;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Mutex, OnceLock};

use rustix::fs::FileType;
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::lock::LockKind;
use crate::repo_fs::{self, FsError, RepoDir, RepoLayout};

/// Returns the map of the staging directories that this process owns.
///
/// The map keys each name to a handle of the `tmp/` directory that holds the
/// staging directory.
fn active() -> &'static Mutex<HashMap<String, RepoDir>> {
    static ACTIVE: OnceLock<Mutex<HashMap<String, RepoDir>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The claim of a staging name in the map of [`active`]. The drop removes the
/// name from the map.
#[derive(Debug)]
struct Claim {
    /// The claimed name.
    name: String,
}

impl Drop for Claim {
    fn drop(&mut self) {
        active().lock().unwrap().remove(&self.name);
    }
}

/// Removes the staging directories that this process owns and their sibling
/// lock files.
///
/// A [`StagingDir`] removes its own directory when it drops. This function is
/// for a process that ends without its destructors. After the call, `tmp/` is
/// in the state that a return with an unwind leaves. It removes each owned
/// directory, so a transaction that continues after the call finds its staged
/// objects gone.
pub(crate) fn reap_owned() {
    let owned = std::mem::take(&mut *active().lock().unwrap());
    for (name, tmp) in owned {
        remove_staging(&tmp, &name);
    }
}

/// Removes the staging directory `name` in the `tmp/` handle `tmp`, and then
/// its sibling lock file.
///
/// The tree removal of [`RepoDir::remove_tree`] follows no symlink and does
/// not go into a mount. The function syncs no directory. An absent entry is
/// already in the wanted state. If a removal fails, the entry stays for the
/// next reaper.
fn remove_staging(tmp: &RepoDir, name: &str) {
    let _ = tmp.remove_tree(OsStr::new(name), false);
    let _ = tmp.remove_file(&format!("{name}-lock"), false);
}

/// The staging area of a transaction: the directory, its held sibling lock,
/// and the handle of the `tmp/` directory that holds them.
#[derive(Debug)]
pub(crate) struct StagingDir {
    /// The claim of the name in `active`. It drops first after the body of
    /// the drop of the value, so the claim ends after the directory and its
    /// sibling lock are gone. Otherwise a concurrent reaper of this process
    /// can find the directory without protection while its lock still exists.
    #[allow(dead_code)]
    claim: Claim,
    tmp: RepoDir,
    /// The handle of the staging directory, of kind
    /// [`Staging`](crate::repo_fs::RepoLayout::Staging). The write path
    /// ingests objects into this directory. The transaction commit renames
    /// them from it into `objects/`.
    dir: RepoDir,
    /// The descriptor of the sibling lock. The value holds it while the
    /// transaction lives, as the mark of an owned directory. Only its lock has
    /// a function, and nothing reads it.
    #[allow(dead_code)]
    lock_fd: OwnedFd,
    name: String,
}

impl StagingDir {
    /// Creates a new staging directory in `tmp/` of the repository of the
    /// root handle `root`.
    ///
    /// Each call opens `tmp/` again with [`RepoDir::ensure_layout`], which
    /// makes `tmp/` and `tmp/cache` if they are absent and refuses a symlink
    /// at each of them. Thus a `tmp/` that is removed after a transaction
    /// comes back at the next one. The function removes the stale leftovers
    /// first. The staging directory comes from [`RepoDir::make_temp_dir`], and
    /// [`lock_staging`] locks its sibling lock file. If the lock fails, the
    /// function removes the new directory. Its calls to the file system are
    /// synchronous, so the caller must run it on the blocking pool.
    pub(crate) fn create(root: &RepoDir, expiry_secs: i64) -> Result<StagingDir> {
        let tmp = root.ensure_layout(RepoLayout::Tmp, false)?;

        reap_stale(&tmp, expiry_secs);

        let prefix = format!("staging-{}-", boot_id()?);
        // The claim of a name in `active` comes before the `mkdirat` that
        // publishes the name, so each directory that a reaper of this process
        // can list already has a claim. In one process, the claim is the only
        // barrier that holds. The record locks are process-associated, so a
        // reaper of this process takes the sibling lock of a live directory
        // without conflict and removes the directory. A name that another
        // live transaction of this process owns stays with its owner.
        let (name, dir, claim) = tmp.make_temp_dir(&prefix, |name| {
            let mut active = active().lock().unwrap();
            if active.contains_key(name) {
                return None;
            }
            active.insert(name.to_owned(), tmp.clone());
            Some(Claim {
                name: name.to_owned(),
            })
        })?;

        let lock_name = format!("{name}-lock");
        let lock_fd = match lock_staging(&tmp, &lock_name) {
            Ok(fd) => fd,
            Err(e) => {
                let _ = tmp.remove_tree(OsStr::new(&name), false);
                drop(claim);
                return Err(e);
            }
        };

        Ok(StagingDir {
            claim,
            tmp,
            dir,
            lock_fd,
            name,
        })
    }

    /// Returns the handle of the staging directory, of kind
    /// [`Staging`](crate::repo_fs::RepoLayout::Staging).
    pub(crate) fn dir(&self) -> &RepoDir {
        &self.dir
    }

    /// Returns the handle of the `tmp/` directory of the repository, which
    /// holds the staging directory. [`create`](StagingDir::create) opened it.
    pub(crate) fn tmp(&self) -> &RepoDir {
        &self.tmp
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        remove_staging(&self.tmp, &self.name);
        // The fields drop after this body: first the claim in `active`, then
        // the descriptors. Their close releases the sibling lock and the
        // directory handle.
    }
}

/// Opens the sibling lock file `lock_name` in the `tmp/` handle `tmp`, and
/// takes an exclusive lock on it.
///
/// [`RepoDir::open_lock`] opens the file, and creates it if it is absent. A
/// new file gets the mode `0600`, which the umask reduces. In a
/// `bare-user-shared` repository an `fchmod` forces `0660` on a new file, so
/// the reaper of another member of the repository group can open the file for
/// write and take the lock. A file that exists keeps its mode, because another
/// member of the group can own it. The open follows no symlink, and a symlink
/// or an entry that is not a regular file at `lock_name` gives
/// [`Error::InvalidFormat`], or [`Error::Io`] if the process cannot open the
/// entry for write. The entry then stays.
///
/// The name is the sibling of the directory that [`RepoDir::make_temp_dir`]
/// created just before, so the open usually creates the file. A removal
/// unlinks a staging directory before its sibling lock. If a process ends
/// between the two steps, it leaves a lock file without its directory. A later
/// staging directory that draws the same name opens that file.
///
/// The open never reaches a lock file that this process holds. The claim of
/// [`StagingDir::create`] skips a name in `active`, and the `mkdirat` of
/// [`RepoDir::make_temp_dir`] fails on a directory that exists. As a result,
/// the name belongs to no live [`StagingDir`] of this process.
///
/// If another process holds a lock on the file, the function gives
/// [`Error::Io`] with `EAGAIN`, and the file stays for that process. If the
/// lock request fails, the function removes the file, so that a failed lock
/// leaves no orphan, and gives the error.
fn lock_staging(tmp: &RepoDir, lock_name: &str) -> Result<OwnedFd> {
    let lock_fd = tmp.open_lock(lock_name)?;
    match repo_fs::try_lock(lock_fd.as_fd(), LockKind::Exclusive) {
        Ok(true) => Ok(lock_fd),
        Ok(false) => Err(Error::Io(io::Error::from(Errno::AGAIN))),
        Err(e) => {
            let _ = tmp.remove_file(lock_name, false);
            Err(e.into())
        }
    }
}

/// Returns the current boot id, read once and cached for the process.
fn boot_id() -> io::Result<&'static str> {
    static BOOT_ID: OnceLock<String> = OnceLock::new();
    if let Some(id) = BOOT_ID.get() {
        return Ok(id);
    }
    let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let id = raw.trim().to_owned();
    if id.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty boot id"));
    }
    Ok(BOOT_ID.get_or_init(|| id))
}

/// Removes the leftover entries at the top level of the `tmp/` handle `tmp`.
///
/// [`reap_one`] gets each `staging-*` directory, and the reap of that directory
/// also gets its `-lock` sibling. A `-lock` file with no directory stays. This
/// function never touches `cache`, and it skips each name that is not UTF-8.
/// [`reap_aged`] removes each other entry, a temp entry of a write in
/// progress included, if it is older than `expiry_secs`.
///
/// The listing types an entry of unknown type with no follow. If the listing
/// fails, the function reaps the names that it collected before the error.
fn reap_stale(tmp: &RepoDir, expiry_secs: i64) {
    // Collect the names first, so that the removals do not change the
    // directory during the read.
    let mut staging: Vec<String> = Vec::new();
    let mut other: Vec<String> = Vec::new();
    let _ = tmp.for_each_entry(|name, file_type| {
        let Ok(name) = name.to_str() else {
            return ControlFlow::Continue(());
        };
        if name == "cache" || (name.starts_with("staging-") && name.ends_with("-lock")) {
            return ControlFlow::Continue(());
        }
        if name.starts_with("staging-") && file_type == FileType::Directory {
            staging.push(name.to_owned());
        } else {
            other.push(name.to_owned());
        }
        ControlFlow::Continue(())
    });
    for name in staging {
        reap_one(tmp, &name, expiry_secs);
    }
    for name in other {
        reap_aged(tmp, &name, expiry_secs);
    }
}

/// Removes the entry `name` of the `tmp/` handle `tmp` if its mtime is older
/// than `expiry_secs`.
///
/// It removes a directory as a whole tree with [`RepoDir::remove_tree`], which
/// does not go into a mount. It removes each other entry with one `unlinkat`:
/// a symlink goes as the link, and a FIFO goes with no open. It never follows a
/// symlink.
fn reap_aged(tmp: &RepoDir, name: &str, expiry_secs: i64) {
    let Ok(stat) = tmp.lstat(name) else {
        return;
    };
    if !expired(stat.mtime_sec, expiry_secs) {
        return;
    }
    if stat.file_type == FileType::Directory {
        let _ = tmp.remove_tree(OsStr::new(name), false);
    } else {
        let _ = tmp.remove_file(name, false);
    }
}

/// Removes one candidate staging directory if its owner is gone.
///
/// The lock file opens with [`RepoDir::open_existing_lock`], which follows no
/// symlink. A symlink, a FIFO, a socket, a device, or a directory at the lock
/// name keeps the directory and the lock entry.
fn reap_one(tmp: &RepoDir, name: &str, expiry_secs: i64) {
    // Never touch a directory that this process owns. Another descriptor holds
    // its sibling lock. The record locks are process-associated, so one open
    // and one close of that lock file release the hold.
    if active().lock().unwrap().contains_key(name) {
        return;
    }
    let lock_name = format!("{name}-lock");
    match tmp.open_existing_lock(&lock_name) {
        Ok(lock_fd) => {
            // If this call gets the lock, the directory has no live owner in
            // any process. The removal of the lock file comes while the lock
            // is held.
            if matches!(
                repo_fs::try_lock(lock_fd.as_fd(), LockKind::Exclusive),
                Ok(true)
            ) {
                let _ = tmp.remove_tree(OsStr::new(name), false);
                let _ = tmp.remove_file(&lock_name, false);
            }
        }
        Err(FsError::Absent { .. }) => {
            // No lock file exists. Another process is in the middle of the
            // creation, or the directory is an orphan. Remove it only if it is
            // older than the expiry window.
            if older_than(tmp, name, expiry_secs) {
                let _ = tmp.remove_tree(OsStr::new(name), false);
            }
        }
        Err(_) => {}
    }
}

/// Returns `true` if the entry `name` of the `tmp/` handle `tmp` is older than
/// `expiry_secs`.
///
/// The age test is the same as the age test of the `ostree` command. An entry
/// expires when its age in whole seconds is more than `expiry_secs`. At
/// `expiry_secs = 0`, an entry from the current second (age 0) stays, and only
/// entries of one second or more go. As a result, the age test does not remove
/// a directory in the middle of its creation.
fn older_than(tmp: &RepoDir, name: &str, expiry_secs: i64) -> bool {
    tmp.lstat(name)
        .is_ok_and(|stat| expired(stat.mtime_sec, expiry_secs))
}

/// Returns `true` if an entry with the mtime `mtime` is older than
/// `expiry_secs`, by a strict test on whole seconds.
fn expired(mtime: i64, expiry_secs: i64) -> bool {
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    (now.as_secs() as i64 - mtime) > expiry_secs
}
