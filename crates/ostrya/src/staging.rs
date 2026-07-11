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
//! On transaction start the reaper removes leftover staging directories whose
//! owner has died. It takes each sibling lock non-blockingly; a directory whose
//! lock it can take, with no live holder, is removed. A directory with no lock
//! file is removed only once it is older than `tmp-expiry-secs`, since it may be
//! mid-creation in another process. A process-global set of the staging
//! directories this process currently owns keeps the reaper from touching them:
//! the record locks are process-associated, so a second descriptor to a live
//! sibling lock would neither conflict nor survive being closed.

use std::collections::HashSet;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Mutex, OnceLock};

use rustix::fs::{AtFlags, Dir, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;

/// The mode staging directories are created with, matching the tool.
const STAGING_DIR_MODE: u32 = 0o775;

/// The mode a staging lock file is created with, matching the tool.
const STAGING_LOCK_MODE: u32 = 0o600;

/// The character set of the random staging-name suffix (mkdtemp's alphabet).
const SUFFIX_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The length of the random staging-name suffix.
const SUFFIX_LEN: usize = 6;

/// The number of unique-name attempts before giving up.
const MKDTEMP_ATTEMPTS: u32 = 128;

/// The staging directory names this process currently owns.
fn active() -> &'static Mutex<HashSet<String>> {
    static ACTIVE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(HashSet::new()))
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
    pub(crate) fn create(repo_fd: BorrowedFd<'_>, expiry_secs: i64) -> io::Result<StagingDir> {
        match rustix::fs::mkdirat(repo_fd, "tmp", Mode::from_raw_mode(STAGING_DIR_MODE)) {
            Ok(()) | Err(Errno::EXIST) => {}
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
        let (name, dir_fd) = mkdtemp(tmp_fd.as_fd(), &prefix)?;

        // Claim ownership before the sibling lock exists, so a concurrent
        // same-process reaper that sees the directory finds it already in
        // `active` and leaves it alone.
        active().lock().unwrap().insert(name.clone());

        let lock_name = format!("{name}-lock");
        let lock_fd = match acquire_staging_lock(tmp_fd.as_fd(), &lock_name) {
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
        let _ = remove_tree_at(self.tmp_fd.as_fd(), &self.name);
        let lock_name = format!("{}-lock", self.name);
        match rustix::fs::unlinkat(&self.tmp_fd, lock_name.as_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(_) => {}
        }
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
fn acquire_staging_lock(tmp_fd: BorrowedFd<'_>, lock_name: &str) -> io::Result<OwnedFd> {
    let lock_fd = rustix::fs::openat(
        tmp_fd,
        lock_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(STAGING_LOCK_MODE),
    )?;
    if let Err(e) = rustix::fs::fcntl_lock(&lock_fd, FlockOperation::NonBlockingLockExclusive) {
        // The open created the lock file; remove it so a failed acquire leaves
        // no orphaned sibling behind.
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
/// on a name collision.
fn mkdtemp(tmp_fd: BorrowedFd<'_>, prefix: &str) -> io::Result<(String, OwnedFd)> {
    for _ in 0..MKDTEMP_ATTEMPTS {
        let name = format!("{prefix}{}", random_suffix());
        match rustix::fs::mkdirat(tmp_fd, name.as_str(), Mode::from_raw_mode(STAGING_DIR_MODE)) {
            Ok(()) => {
                let dir_fd = rustix::fs::openat(
                    tmp_fd,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )?;
                return Ok((name, dir_fd));
            }
            Err(Errno::EXIST) => continue,
            Err(e) => return Err(e.into()),
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

/// Remove leftover staging directories whose owning transaction has died.
fn reap_stale(tmp_fd: BorrowedFd<'_>, expiry_secs: i64) {
    let Ok(entries) = Dir::read_from(tmp_fd) else {
        return;
    };
    // Collect names first so removals do not disturb the directory read.
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if !name.starts_with("staging-") || name.ends_with("-lock") {
            continue;
        }
        names.push(name.to_owned());
    }
    for name in names {
        reap_one(tmp_fd, &name, expiry_secs);
    }
}

/// Reap one candidate staging directory if its owner is gone.
fn reap_one(tmp_fd: BorrowedFd<'_>, name: &str, expiry_secs: i64) {
    // Never touch a directory this process owns: its sibling lock is held on
    // another descriptor, and even opening and closing that lock file would drop
    // the hold under the process-associated record-lock semantics.
    if active().lock().unwrap().contains(name) {
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
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    (now.as_secs() as i64 - stat.st_mtime) > expiry_secs
}

/// Remove the directory `name` under `parent` and everything below it.
fn remove_tree_at(parent: BorrowedFd<'_>, name: &str) -> io::Result<()> {
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
