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
//! [`reap_process_staging`](crate::reap_process_staging). A ref write, a
//! detached-metadata write, and a tombstone write create a [`TempEntry`] at
//! the top level of `tmp/`.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::ops::ControlFlow;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Mutex, OnceLock};

use ostrya_core::RepoMode;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::lock::LockKind;
use crate::perm;
use crate::repo_fs::{self, FsError, RepoDir, RepoLayout};

/// The requested mode of a staging directory, the same mode that the `ostree`
/// command requests. The process umask reduces it. In a `bare-user-shared`
/// repository, an `fchmod` after the creation sets [`perm::SHARED_DIR_MODE`].
const STAGING_DIR_MODE: u32 = 0o775;

/// The character set of the random suffix of a staging name (the alphabet of
/// `mkdtemp`).
const SUFFIX_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The length of the random suffix of a staging name.
const SUFFIX_LEN: usize = 6;

/// The maximum number of attempts to find a unique name.
const MKDTEMP_ATTEMPTS: u32 = 128;

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

/// Opens the `tmp/` directory of the repository at `repo_fd`, and creates it
/// if it is absent.
///
/// A new `tmp/` gets [`STAGING_DIR_MODE`], reduced by the umask. In a
/// `bare-user-shared` repository, this function forces the mode of a new
/// `tmp/` to [`perm::SHARED_DIR_MODE`]. If `tmp/` is a symlink, the open
/// follows it.
pub(crate) fn open_tmp_dir(repo_fd: BorrowedFd<'_>, repo_mode: RepoMode) -> io::Result<OwnedFd> {
    match rustix::fs::mkdirat(repo_fd, "tmp", Mode::from_raw_mode(STAGING_DIR_MODE)) {
        Ok(()) => perm::force_created_dir(repo_fd, "tmp", repo_mode)?,
        Err(Errno::EXIST) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(rustix::fs::openat(
        repo_fd,
        "tmp",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// The name prefix of the temp entry of a ref file or of an alias symlink.
pub(crate) const REF_TEMP_PREFIX: &str = ".ostrya-ref-";

/// A temp entry in `tmp/` that a write renames over its target.
///
/// The name is `<prefix><pid>-<counter>-XXXXXX`. `XXXXXX` is a random suffix,
/// so a process in another PID namespace with the same pid and counter draws a
/// different name. If the value drops before
/// [`rename_into`](TempEntry::rename_into) succeeds, the drop unlinks the
/// entry.
pub(crate) struct TempEntry<'a> {
    tmp_fd: BorrowedFd<'a>,
    /// The name of the entry under `tmp_fd`. It is empty after the rename.
    name: String,
}

impl<'a> TempEntry<'a> {
    /// Creates a regular file with the permission bits `mode` and opens it for
    /// writing.
    ///
    /// The umask reduces `mode`. The function returns the entry and the
    /// descriptor.
    pub(crate) fn create_file(
        tmp_fd: BorrowedFd<'a>,
        prefix: &str,
        mode: u32,
    ) -> io::Result<(TempEntry<'a>, OwnedFd)> {
        Self::create(tmp_fd, prefix, |name| {
            rustix::fs::openat(
                tmp_fd,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(mode),
            )
        })
    }

    /// Creates a symlink with the target `link`.
    pub(crate) fn create_symlink(
        tmp_fd: BorrowedFd<'a>,
        prefix: &str,
        link: &str,
    ) -> io::Result<TempEntry<'a>> {
        let (entry, ()) = Self::create(tmp_fd, prefix, |name| {
            rustix::fs::symlinkat(link, tmp_fd, name)
        })?;
        Ok(entry)
    }

    /// Runs `make` with a new name, and draws a new name if the name is taken.
    ///
    /// It makes at most [`MKDTEMP_ATTEMPTS`] attempts.
    fn create<T>(
        tmp_fd: BorrowedFd<'a>,
        prefix: &str,
        mut make: impl FnMut(&str) -> rustix::io::Result<T>,
    ) -> io::Result<(TempEntry<'a>, T)> {
        for _ in 0..MKDTEMP_ATTEMPTS {
            let name = format!(
                "{prefix}{}-{}-{}",
                std::process::id(),
                crate::write::unique(),
                random_suffix()
            );
            match make(&name) {
                Ok(made) => return Ok((TempEntry { tmp_fd, name }, made)),
                Err(Errno::EXIST) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temp name",
        ))
    }

    /// Renames the entry over `dest` under `dir_fd`.
    ///
    /// If the rename fails, the entry stays for the drop, which unlinks it.
    pub(crate) fn rename_into(mut self, dir_fd: BorrowedFd<'_>, dest: &str) -> io::Result<()> {
        rustix::fs::renameat(self.tmp_fd, self.name.as_str(), dir_fd, dest)?;
        self.name.clear();
        Ok(())
    }
}

impl Drop for TempEntry<'_> {
    fn drop(&mut self) {
        if !self.name.is_empty() {
            let _ = rustix::fs::unlinkat(self.tmp_fd, self.name.as_str(), AtFlags::empty());
        }
    }
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

    /// Returns the descriptor of the staging directory.
    ///
    /// The write path ingests objects here. The transaction commit renames them
    /// into `objects/`.
    pub(crate) fn dir_fd(&self) -> BorrowedFd<'_> {
        self.dir.as_fd()
    }

    /// Returns the handle of the `tmp/` directory of the repository, which
    /// holds the staging directory. [`create`](StagingDir::create) opened it.
    pub(crate) fn tmp(&self) -> &RepoDir {
        &self.tmp
    }

    /// Returns the descriptor of the `tmp/` directory of the repository, which
    /// holds the staging directory.
    pub(crate) fn tmp_fd(&self) -> BorrowedFd<'_> {
        self.tmp.as_fd()
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

/// Returns a six-character `[A-Za-z0-9]` suffix from a seed of the time, the
/// pid, and a per-process counter.
///
/// The name must be unique on the host only. A collision causes a new attempt.
fn random_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut state =
        nanos ^ (u64::from(std::process::id()) << 32) ^ counter.wrapping_mul(0x9E37_79B9_7F4A_7C15);

    let mut suffix = String::with_capacity(SUFFIX_LEN);
    for _ in 0..SUFFIX_LEN {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        suffix.push(SUFFIX_ALPHABET[(state % 62) as usize] as char);
    }
    suffix
}

/// Removes the leftover entries at the top level of the `tmp/` handle `tmp`.
///
/// [`reap_one`] gets each `staging-*` directory, and the reap of that directory
/// also gets its `-lock` sibling. A `-lock` file with no directory stays. This
/// function never touches `cache`, and it skips each name that is not UTF-8.
/// [`reap_aged`] removes each other entry, a [`TempEntry`] in progress
/// included, if it is older than `expiry_secs`.
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
