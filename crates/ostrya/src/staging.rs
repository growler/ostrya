//! Per-transaction staging directories under `<repo>/tmp`.
//!
//! A transaction stages objects in `tmp/staging-<boot-id>-XXXXXX`, created fresh
//! per transaction and removed when the transaction ends. A sibling file
//! `staging-<boot-id>-XXXXXX-lock` is held with an exclusive record lock for the
//! transaction's lifetime, marking the directory as owned by a live
//! transaction. Encoding the boot id in the name separates directories from the
//! current boot, whose owner may still be alive, from earlier boots, whose owner
//! is certainly gone.
//!
//! On transaction start the reaper reads the top level of `tmp/`. It never
//! touches `cache`. A `staging-*` directory and its `-lock` sibling follow the
//! staging rule below. Every other entry is removed once its mtime is older
//! than `tmp-expiry-secs`, as the tool does: a directory as a whole tree judged
//! by its own mtime, and a symlink as the link itself. A staging lock file is
//! exempt from that age test, because the lock of a transaction that lives
//! past the window is still held.
//!
//! The staging rule removes leftover staging directories whose owner has died.
//! It takes each sibling lock non-blockingly; a directory whose lock it can
//! take, with no live holder, is removed. A directory with no lock
//! file is removed only once it is older than `tmp-expiry-secs`, since it may be
//! mid-creation in another process. A process-global map of the staging
//! directories this process currently owns keeps the reaper from touching them:
//! the record locks are process-associated, so a second descriptor to a live
//! sibling lock would neither conflict nor survive being closed. A directory
//! enters that map before it is created and leaves it after it is removed, so
//! every directory a same-process reaper can list is already in the map.
//!
//! Each entry of that map holds a descriptor for the `tmp/` directory the
//! staging directory lives in, so [`reap_owned`] removes every one of them with
//! no live [`StagingDir`] in hand. A process that ends without running
//! destructors reaches it through
//! [`reap_process_staging`](crate::reap_process_staging).

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Mutex, OnceLock};

use ostrya_core::RepoMode;
use rustix::fs::{AtFlags, Dir, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;

use crate::perm;

/// The mode staging directories are requested with, matching the tool. The
/// process umask reduces it. In a `bare-user-shared` repository an `fchmod`
/// after the create restores [`perm::SHARED_DIR_MODE`].
const STAGING_DIR_MODE: u32 = 0o775;

/// The mode a staging lock file is requested with, matching the tool. In a
/// `bare-user-shared` repository an `fchmod` after the create raises it to
/// [`perm::SHARED_LOCK_MODE`], so the reaper of another member of the
/// repository group opens the file `O_RDWR` and tests the owner.
const STAGING_LOCK_MODE: u32 = 0o600;

/// The character set of the random staging-name suffix (mkdtemp's alphabet).
const SUFFIX_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The length of the random staging-name suffix.
const SUFFIX_LEN: usize = 6;

/// The number of unique-name attempts before giving up.
const MKDTEMP_ATTEMPTS: u32 = 128;

/// The staging directories this process currently owns, each name mapped to a
/// descriptor for the `tmp/` directory it lives in.
fn active() -> &'static Mutex<HashMap<String, OwnedFd>> {
    static ACTIVE: OnceLock<Mutex<HashMap<String, OwnedFd>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Remove the staging directories this process owns, together with their
/// sibling lock files.
///
/// A [`StagingDir`] removes its own directory when it drops, so this is for a
/// process that ends without running destructors: it leaves `tmp/` as an
/// unwound return would. Every owned directory is removed, so a transaction
/// that continues afterward finds its staged objects gone.
pub(crate) fn reap_owned() {
    let owned = std::mem::take(&mut *active().lock().unwrap());
    for (name, tmp_fd) in owned {
        remove_staging(tmp_fd.as_fd(), &name);
    }
}

/// Remove the staging directory `name` under `tmp_fd` and its sibling lock
/// file. Absent entries are already in the wanted state, and a removal that
/// fails leaves the entry for the next reaper.
fn remove_staging(tmp_fd: BorrowedFd<'_>, name: &str) {
    let _ = remove_tree_at(tmp_fd, name);
    let lock_name = format!("{name}-lock");
    let _ = rustix::fs::unlinkat(tmp_fd, lock_name.as_str(), AtFlags::empty());
}

/// A transaction's staging area: the directory, its held sibling lock, and the
/// `tmp/` descriptor they live under.
#[derive(Debug)]
pub(crate) struct StagingDir {
    tmp_fd: OwnedFd,
    /// The staging directory descriptor. Objects are ingested into this
    /// directory by the write path and renamed out of it into `objects/` at
    /// commit.
    dir_fd: OwnedFd,
    /// The sibling lock descriptor, held for the transaction's lifetime to mark
    /// the directory as owned. Kept only for its lock; never read.
    #[allow(dead_code)]
    lock_fd: OwnedFd,
    name: String,
}

impl StagingDir {
    /// Create a fresh staging directory under the repository rooted at
    /// `repo_fd`, reaping stale leftovers first. Runs synchronous filesystem
    /// calls and is meant to be offloaded to the blocking pool.
    pub(crate) fn create(
        repo_fd: BorrowedFd<'_>,
        expiry_secs: i64,
        repo_mode: RepoMode,
    ) -> io::Result<StagingDir> {
        match rustix::fs::mkdirat(repo_fd, "tmp", Mode::from_raw_mode(STAGING_DIR_MODE)) {
            Ok(()) => perm::force_created_dir(repo_fd, "tmp", repo_mode)?,
            Err(Errno::EXIST) => {}
            Err(e) => return Err(e.into()),
        }
        let tmp_fd = rustix::fs::openat(
            repo_fd,
            "tmp",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;

        reap_stale(tmp_fd.as_fd(), expiry_secs);

        let prefix = format!("staging-{}-", boot_id()?);
        // `mkdtemp` claims the name in `active` before the directory exists, so
        // a concurrent same-process reaper never sees it unclaimed.
        let (name, dir_fd) = mkdtemp(tmp_fd.as_fd(), &prefix, repo_mode)?;

        let lock_name = format!("{name}-lock");
        let lock_fd = match acquire_staging_lock(tmp_fd.as_fd(), &lock_name, repo_mode) {
            Ok(fd) => fd,
            Err(e) => {
                active().lock().unwrap().remove(&name);
                let _ = remove_tree_at(tmp_fd.as_fd(), &name);
                return Err(e);
            }
        };

        Ok(StagingDir {
            tmp_fd,
            dir_fd,
            lock_fd,
            name,
        })
    }

    /// The staging directory descriptor. Objects are ingested here and renamed
    /// into `objects/` at commit.
    pub(crate) fn dir_fd(&self) -> BorrowedFd<'_> {
        self.dir_fd.as_fd()
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        remove_staging(self.tmp_fd.as_fd(), &self.name);
        // Release the in-process claim only after the directory and its lock
        // sibling are gone, so a concurrent same-process reaper never sees the
        // directory unprotected while its lock still exists.
        active().lock().unwrap().remove(&self.name);
        // The descriptor fields close after this body, releasing the sibling
        // lock and the directory handle.
    }
}

/// Create the sibling lock file and hold it exclusively. A fresh lock file is
/// uncontended, so the attempt does not block.
///
/// The name is the sibling of the directory [`mkdtemp`] has just created, so
/// this open normally makes the file. A removal unlinks a staging directory
/// before its sibling lock, so a process that ends between the two leaves a
/// lock file whose directory is gone, and a later staging directory that draws
/// the same name finds that file. `O_EXCL` separates the two cases: a lock file
/// this call makes is forced to [`perm::SHARED_LOCK_MODE`] in a
/// `bare-user-shared` repository, and a file that already stands keeps the mode
/// and the group it has, which another member of the group may own. The second
/// open carries `O_CREAT`, because a reaper in another process removes such a
/// leftover and the name is free again by the time this call reaches it.
///
/// The second open never reaches a lock file this process holds: [`mkdtemp`]
/// skips a name in `active` and its `mkdirat` fails on a directory that stands,
/// so the name belongs to no live [`StagingDir`] of this process.
fn acquire_staging_lock(
    tmp_fd: BorrowedFd<'_>,
    lock_name: &str,
    repo_mode: RepoMode,
) -> io::Result<OwnedFd> {
    let lock_fd = match rustix::fs::openat(
        tmp_fd,
        lock_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(STAGING_LOCK_MODE),
    ) {
        Ok(fd) => {
            if let Err(e) = perm::force_created_mode(&fd, repo_mode, perm::SHARED_LOCK_MODE) {
                // The open created the lock file; remove it so a failed force
                // leaves no orphaned sibling behind.
                drop(fd);
                let _ = rustix::fs::unlinkat(tmp_fd, lock_name, AtFlags::empty());
                return Err(e);
            }
            fd
        }
        Err(Errno::EXIST) => rustix::fs::openat(
            tmp_fd,
            lock_name,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(STAGING_LOCK_MODE),
        )?,
        Err(e) => return Err(e.into()),
    };
    if let Err(e) = rustix::fs::fcntl_lock(&lock_fd, FlockOperation::NonBlockingLockExclusive) {
        // The caller removes the staging directory; remove its sibling lock too
        // so a failed acquire leaves no orphan behind.
        let _ = rustix::fs::unlinkat(tmp_fd, lock_name, AtFlags::empty());
        return Err(e.into());
    }
    Ok(lock_fd)
}

/// The current boot id, read once and cached for the process.
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

/// Create a uniquely named directory `prefix + suffix` under `tmp_fd`, retrying
/// on a name collision. The returned name is claimed in `active`, which the
/// caller releases when the staging directory ends.
///
/// The claim precedes the `mkdirat` that publishes the name, so every directory
/// a same-process reaper can list is already claimed. The claim is the only
/// barrier that holds within one process: the record locks are
/// process-associated, so a reaper reaching the sibling lock of a live directory
/// takes it without conflict and removes the directory. The claim carries its
/// own duplicate of `tmp_fd`, which is what [`reap_owned`] removes the
/// directory through.
fn mkdtemp(
    tmp_fd: BorrowedFd<'_>,
    prefix: &str,
    repo_mode: RepoMode,
) -> io::Result<(String, OwnedFd)> {
    for _ in 0..MKDTEMP_ATTEMPTS {
        let name = format!("{prefix}{}", random_suffix());
        let claim = tmp_fd.try_clone_to_owned()?;
        // A name another live transaction in this process owns is left to its
        // owner: releasing that claim here would strip its protection.
        {
            let mut active = active().lock().unwrap();
            if active.contains_key(&name) {
                continue;
            }
            active.insert(name.clone(), claim);
        }
        match rustix::fs::mkdirat(tmp_fd, name.as_str(), Mode::from_raw_mode(STAGING_DIR_MODE)) {
            Ok(()) => {
                match rustix::fs::openat(
                    tmp_fd,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                ) {
                    Ok(dir_fd) => {
                        if let Err(e) =
                            perm::force_created_mode(&dir_fd, repo_mode, perm::SHARED_DIR_MODE)
                        {
                            active().lock().unwrap().remove(&name);
                            return Err(e);
                        }
                        return Ok((name, dir_fd));
                    }
                    Err(e) => {
                        active().lock().unwrap().remove(&name);
                        return Err(e.into());
                    }
                }
            }
            Err(Errno::EXIST) => {
                active().lock().unwrap().remove(&name);
                continue;
            }
            Err(e) => {
                active().lock().unwrap().remove(&name);
                return Err(e.into());
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique staging directory",
    ))
}

/// A six-character `[A-Za-z0-9]` suffix, seeded from the time, pid, and a
/// per-process counter. The name only needs to be unique on the host, so a
/// collision simply retries.
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

/// Remove the leftover entries at the top level of `tmp/`.
///
/// A `staging-*` directory goes through [`reap_one`], and its `-lock` sibling
/// is left to that directory's reap. `cache` is never touched. Every other
/// entry is removed through [`reap_aged`] once it is past `expiry_secs`.
fn reap_stale(tmp_fd: BorrowedFd<'_>, expiry_secs: i64) {
    let Ok(entries) = Dir::read_from(tmp_fd) else {
        return;
    };
    // Collect names first so removals do not disturb the directory read.
    let mut staging: Vec<String> = Vec::new();
    let mut other: Vec<CString> = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        if name == c"." || name == c".." || name == c"cache" {
            continue;
        }
        if let Ok(text) = name.to_str()
            && text.starts_with("staging-")
        {
            if text.ends_with("-lock") {
                continue;
            }
            if is_dir_entry(tmp_fd, &entry) {
                staging.push(text.to_owned());
                continue;
            }
        }
        other.push(name.to_owned());
    }
    for name in staging {
        reap_one(tmp_fd, &name, expiry_secs);
    }
    for name in other {
        reap_aged(tmp_fd, &name, expiry_secs);
    }
}

/// Whether `entry` under `dir` is a directory, not following a symlink.
fn is_dir_entry(dir: BorrowedFd<'_>, entry: &rustix::fs::DirEntry) -> bool {
    match entry.file_type() {
        FileType::Directory => true,
        FileType::Unknown => rustix::fs::statat(dir, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
            .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::Directory),
        _ => false,
    }
}

/// Remove the entry `name` under `tmp_fd` once its mtime is past
/// `expiry_secs`: a directory as a whole tree, any other entry, a symlink
/// included, with one `unlinkat`. A symlink is never followed.
fn reap_aged(tmp_fd: BorrowedFd<'_>, name: &CStr, expiry_secs: i64) {
    let Ok(stat) = rustix::fs::statat(tmp_fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
        return;
    };
    if !expired(stat.st_mtime, expiry_secs) {
        return;
    }
    if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
        let _ = remove_tree_at(tmp_fd, name);
    } else {
        let _ = rustix::fs::unlinkat(tmp_fd, name, AtFlags::empty());
    }
}

/// Reap one candidate staging directory if its owner is gone.
fn reap_one(tmp_fd: BorrowedFd<'_>, name: &str, expiry_secs: i64) {
    // Never touch a directory this process owns: its sibling lock is held on
    // another descriptor, and even opening and closing that lock file would drop
    // the hold under the process-associated record-lock semantics.
    if active().lock().unwrap().contains_key(name) {
        return;
    }
    let lock_name = format!("{name}-lock");
    match rustix::fs::openat(
        tmp_fd,
        lock_name.as_str(),
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(lock_fd) => {
            // Taking the lock means no live owner in any process.
            if rustix::fs::fcntl_lock(&lock_fd, FlockOperation::NonBlockingLockExclusive).is_ok() {
                let _ = remove_tree_at(tmp_fd, name);
                let _ = rustix::fs::unlinkat(tmp_fd, lock_name.as_str(), AtFlags::empty());
            }
        }
        Err(Errno::NOENT) => {
            // No lock file: mid-creation elsewhere or an orphan. Reap only once
            // it is past the expiry window.
            if older_than(tmp_fd, name, expiry_secs) {
                let _ = remove_tree_at(tmp_fd, name);
            }
        }
        Err(_) => {}
    }
}

/// Whether the entry `name` under `tmp_fd` is older than `expiry_secs`.
///
/// The age test matches the tool: an entry is expired once its age in whole
/// seconds exceeds `expiry_secs`. At `expiry_secs = 0` an entry created in the
/// current second (age 0) is kept and only entries at least a second old are
/// reaped, so a directory still being created is not removed by age.
fn older_than(tmp_fd: BorrowedFd<'_>, name: &str, expiry_secs: i64) -> bool {
    let Ok(stat) = rustix::fs::statat(tmp_fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
        return false;
    };
    expired(stat.st_mtime, expiry_secs)
}

/// Whether an entry with mtime `mtime` is older than `expiry_secs`, strict on
/// whole seconds.
fn expired(mtime: i64, expiry_secs: i64) -> bool {
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    (now.as_secs() as i64 - mtime) > expiry_secs
}

/// Remove the directory `name` under `parent` and everything below it.
fn remove_tree_at<P: rustix::path::Arg + Copy>(parent: BorrowedFd<'_>, name: P) -> io::Result<()> {
    match rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(dir_fd) => clear_dir(dir_fd.as_fd())?,
        Err(Errno::NOENT) => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    match rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Remove every entry within the directory `dir`, recursing into
/// subdirectories.
fn clear_dir(dir: BorrowedFd<'_>) -> io::Result<()> {
    let mut children: Vec<(CString, bool)> = Vec::new();
    let entries = Dir::read_from(dir)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let is_dir = match entry.file_type() {
            FileType::Directory => true,
            FileType::Unknown => {
                let stat = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
                FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            }
            _ => false,
        };
        children.push((name.to_owned(), is_dir));
    }

    for (name, is_dir) in children {
        let name = name.as_c_str();
        if is_dir {
            match rustix::fs::openat(
                dir,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ) {
                Ok(child) => clear_dir(child.as_fd())?,
                Err(Errno::NOENT) => continue,
                Err(e) => return Err(e.into()),
            }
            match rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR) {
                Ok(()) | Err(Errno::NOENT) => {}
                Err(e) => return Err(e.into()),
            }
        } else {
            match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
                Ok(()) | Err(Errno::NOENT) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}
