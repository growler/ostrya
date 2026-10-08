//! Per-transaction staging directories under `<repo>/tmp`.
//!
//! The `Transaction` type doc, under `# Staging directory`, states the names,
//! the locks, and the rules of the reaper that a caller sees.
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
//! Each entry of the map holds a descriptor of the `tmp/` directory that holds
//! the staging directory. With these descriptors, [`reap_owned`] removes each
//! owned directory without a live [`StagingDir`]. A process that ends without
//! its destructors calls it through
//! [`reap_process_staging`](crate::reap_process_staging). A ref write, a
//! detached-metadata write, and a tombstone write create a [`TempEntry`] at
//! the top level of `tmp/`.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Mutex, OnceLock};

use ostrya_core::RepoMode;
use rustix::fs::{AtFlags, Dir, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;

use crate::perm;

/// The requested mode of a staging directory, the same mode that the `ostree`
/// command requests. The process umask reduces it. In a `bare-user-shared`
/// repository, an `fchmod` after the creation sets [`perm::SHARED_DIR_MODE`].
const STAGING_DIR_MODE: u32 = 0o775;

/// The requested mode of a staging lock file, the same mode that the `ostree`
/// command requests. In a `bare-user-shared` repository, an `fchmod` after the
/// creation raises it to [`perm::SHARED_LOCK_MODE`]. Then the reaper of another
/// member of the repository group can open the file `O_RDWR` and take the lock
/// to check for a live owner.
const STAGING_LOCK_MODE: u32 = 0o600;

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
/// The map keys each name to a descriptor of the `tmp/` directory that holds
/// the staging directory.
fn active() -> &'static Mutex<HashMap<String, OwnedFd>> {
    static ACTIVE: OnceLock<Mutex<HashMap<String, OwnedFd>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(HashMap::new()))
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
    for (name, tmp_fd) in owned {
        remove_staging(tmp_fd.as_fd(), &name);
    }
}

/// Removes the staging directory `name` under `tmp_fd` and its sibling lock
/// file.
///
/// An absent entry is already in the wanted state. If a removal fails, the
/// entry stays for the next reaper.
fn remove_staging(tmp_fd: BorrowedFd<'_>, name: &str) {
    let _ = remove_tree_at(tmp_fd, name);
    let lock_name = format!("{name}-lock");
    let _ = rustix::fs::unlinkat(tmp_fd, lock_name.as_str(), AtFlags::empty());
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

/// The name prefix of the temp file of a `.commitmeta` or a
/// `.tombstone-commit` object.
pub(crate) const META_TEMP_PREFIX: &str = ".ostrya-meta-";

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
/// and the descriptor of the `tmp/` directory that holds them.
#[derive(Debug)]
pub(crate) struct StagingDir {
    tmp_fd: OwnedFd,
    /// The descriptor of the staging directory. The write path ingests objects
    /// into this directory. The transaction commit renames them from it into
    /// `objects/`.
    dir_fd: OwnedFd,
    /// The descriptor of the sibling lock. The value holds it while the
    /// transaction lives, as the mark of an owned directory. Only its lock has
    /// a function, and nothing reads it.
    #[allow(dead_code)]
    lock_fd: OwnedFd,
    name: String,
}

impl StagingDir {
    /// Creates a new staging directory under the repository at `repo_fd`.
    ///
    /// It removes the stale leftovers first. Its calls to the file system are
    /// synchronous, so the caller must run it on the blocking pool.
    pub(crate) fn create(
        repo_fd: BorrowedFd<'_>,
        expiry_secs: i64,
        repo_mode: RepoMode,
    ) -> io::Result<StagingDir> {
        let tmp_fd = open_tmp_dir(repo_fd, repo_mode)?;

        reap_stale(tmp_fd.as_fd(), expiry_secs);

        let prefix = format!("staging-{}-", boot_id()?);
        // `mkdtemp` claims the name in `active` before the directory exists, so
        // a concurrent reaper of this process never finds it without a claim.
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

    /// Returns the descriptor of the staging directory.
    ///
    /// The write path ingests objects here. The transaction commit renames them
    /// into `objects/`.
    pub(crate) fn dir_fd(&self) -> BorrowedFd<'_> {
        self.dir_fd.as_fd()
    }

    /// Returns the descriptor of the `tmp/` directory of the repository, which
    /// holds the staging directory.
    pub(crate) fn tmp_fd(&self) -> BorrowedFd<'_> {
        self.tmp_fd.as_fd()
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        remove_staging(self.tmp_fd.as_fd(), &self.name);
        // Release the claim in `active` only after the directory and its
        // sibling lock are gone. Otherwise a concurrent reaper of this process
        // can find the directory without protection while its lock still
        // exists.
        active().lock().unwrap().remove(&self.name);
        // The descriptor fields close after this body. Their close releases the
        // sibling lock and the directory handle.
    }
}

/// Creates the sibling lock file and takes an exclusive lock on it.
///
/// A new lock file has no other holder, so the attempt does not block.
///
/// The name is the sibling of the directory that [`mkdtemp`] created just
/// before, so this open usually creates the file. A removal unlinks a staging
/// directory before its sibling lock. If a process ends between the two steps,
/// it leaves a lock file without its directory. A later staging directory that
/// draws the same name finds that file.
///
/// `O_EXCL` separates the two cases. In a `bare-user-shared` repository, this
/// function forces a lock file that it creates to [`perm::SHARED_LOCK_MODE`].
/// A file that already exists keeps its mode and its group, because another
/// member of the group can own it. The second open has `O_CREAT`, because a
/// reaper in another process can remove the leftover before the second open.
///
/// The second open never reaches a lock file that this process holds.
/// [`mkdtemp`] skips a name in `active`, and its `mkdirat` fails on a directory
/// that exists. As a result, the name belongs to no live [`StagingDir`] of this
/// process.
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
                // The open created the lock file. Remove it, so that a failed
                // force leaves no orphan sibling.
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
        // The caller removes the staging directory. Remove its sibling lock
        // too, so that a failed acquire leaves no orphan.
        let _ = rustix::fs::unlinkat(tmp_fd, lock_name, AtFlags::empty());
        return Err(e.into());
    }
    Ok(lock_fd)
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

/// Creates a directory with the unique name `prefix + suffix` under `tmp_fd`.
///
/// On a name collision, it draws a new suffix. The returned name has a claim
/// in `active`. The caller releases the claim when the staging directory ends.
///
/// The claim comes before the `mkdirat` that publishes the name, so each
/// directory that a reaper of this process can list already has a claim. In
/// one process, the claim is the only barrier that holds. The record locks are
/// process-associated, so a reaper of this process takes the sibling lock of a
/// live directory without conflict and removes the directory.
///
/// The claim holds its own duplicate of `tmp_fd`. [`reap_owned`] removes the
/// directory through this duplicate.
fn mkdtemp(
    tmp_fd: BorrowedFd<'_>,
    prefix: &str,
    repo_mode: RepoMode,
) -> io::Result<(String, OwnedFd)> {
    for _ in 0..MKDTEMP_ATTEMPTS {
        let name = format!("{prefix}{}", random_suffix());
        let claim = tmp_fd.try_clone_to_owned()?;
        // Leave a name that another live transaction of this process owns to
        // its owner. A release of that claim here removes its protection.
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

/// Removes the leftover entries at the top level of `tmp/`.
///
/// [`reap_one`] gets each `staging-*` directory, and the reap of that directory
/// also gets its `-lock` sibling. A `-lock` file with no directory stays. This
/// function never touches `cache`. [`reap_aged`] removes each other entry, a
/// [`TempEntry`] in progress included, if it is older than `expiry_secs`.
fn reap_stale(tmp_fd: BorrowedFd<'_>, expiry_secs: i64) {
    let Ok(entries) = Dir::read_from(tmp_fd) else {
        return;
    };
    // Collect the names first, so that the removals do not change the
    // directory during the read.
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

/// Returns `true` if `entry` under `dir` is a directory. A symlink is never
/// followed.
fn is_dir_entry(dir: BorrowedFd<'_>, entry: &rustix::fs::DirEntry) -> bool {
    match entry.file_type() {
        FileType::Directory => true,
        FileType::Unknown => rustix::fs::statat(dir, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
            .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::Directory),
        _ => false,
    }
}

/// Removes the entry `name` under `tmp_fd` if its mtime is older than
/// `expiry_secs`.
///
/// It removes a directory as a whole tree. It removes each other entry, a
/// symlink included, with one `unlinkat`. It never follows a symlink.
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

/// Removes one candidate staging directory if its owner is gone.
fn reap_one(tmp_fd: BorrowedFd<'_>, name: &str, expiry_secs: i64) {
    // Never touch a directory that this process owns. Another descriptor holds
    // its sibling lock. The record locks are process-associated, so one open
    // and one close of that lock file release the hold.
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
            // If this call gets the lock, the directory has no live owner in
            // any process.
            if rustix::fs::fcntl_lock(&lock_fd, FlockOperation::NonBlockingLockExclusive).is_ok() {
                let _ = remove_tree_at(tmp_fd, name);
                let _ = rustix::fs::unlinkat(tmp_fd, lock_name.as_str(), AtFlags::empty());
            }
        }
        Err(Errno::NOENT) => {
            // No lock file exists. Another process is in the middle of the
            // creation, or the directory is an orphan. Remove it only if it is
            // older than the expiry window.
            if older_than(tmp_fd, name, expiry_secs) {
                let _ = remove_tree_at(tmp_fd, name);
            }
        }
        Err(_) => {}
    }
}

/// Returns `true` if the entry `name` under `tmp_fd` is older than
/// `expiry_secs`.
///
/// The age test is the same as the age test of the `ostree` command. An entry
/// expires when its age in whole seconds is more than `expiry_secs`. At
/// `expiry_secs = 0`, an entry from the current second (age 0) stays, and only
/// entries of one second or more go. As a result, the age test does not remove
/// a directory in the middle of its creation.
fn older_than(tmp_fd: BorrowedFd<'_>, name: &str, expiry_secs: i64) -> bool {
    let Ok(stat) = rustix::fs::statat(tmp_fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
        return false;
    };
    expired(stat.st_mtime, expiry_secs)
}

/// Returns `true` if an entry with the mtime `mtime` is older than
/// `expiry_secs`, by a strict test on whole seconds.
fn expired(mtime: i64, expiry_secs: i64) -> bool {
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    (now.as_secs() as i64 - mtime) > expiry_secs
}

/// Removes the directory `name` under `parent` and all of its contents.
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

/// Removes each entry in the directory `dir`, and recurses into the
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
