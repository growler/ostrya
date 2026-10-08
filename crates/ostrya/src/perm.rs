//! The permission bits that ostrya forces on the entries that it creates inside
//! a `bare-user-shared` repository.
//!
//! `mkdirat` and `openat(O_CREAT)` reduce their mode argument by the
//! file-creation mask of the calling process, so the mode argument alone cannot
//! give a guarantee. Each helper here applies the wanted bits with `fchmod`
//! after the create, and the mask does not apply to `fchmod`. All other
//! repository modes keep the masked result, so the helpers return at once for
//! them.
//!
//! A directory gets `02770`. The setgid bit is part of the forced mode, because
//! `mkdirat` inherits it from the parent. If an `fchmod` leaves the bit out, it
//! clears the bit, and group inheritance stops below that level. If a
//! non-privileged `chmod` sets the `S_ISGID` bit on a directory, the directory
//! keeps the bit. The silent-clear rule of the kernel applies to non-directory
//! files. The sticky bit stays off `tmp/` and off the repository root, because
//! the stale-staging reaper removes staging trees that other members of the
//! group own.
//!
//! A helper runs on the arm of a create where that call made the entry. An
//! entry that exists before the call can belong to another uid, and then
//! `fchmod` returns `EPERM`.
//!
//! [`force_created_dir`] opens the entry and calls `fchmod` on the descriptor.
//! Linux does not support `AT_SYMLINK_NOFOLLOW` in `fchmodat`, so a chmod by
//! path has a symlink-swap race. An `openat` with `O_NOFOLLOW` and then an
//! `fchmod` on the descriptor has no such race.

use std::os::fd::AsFd;

use ostrya_core::RepoMode;
use rustix::fs::{Mode, OFlags};
use rustix::path::Arg;

/// The mode forced on a directory created inside a `bare-user-shared`
/// repository.
pub(crate) const SHARED_DIR_MODE: u32 = 0o2770;

/// The mode forced on a lock file created inside a `bare-user-shared`
/// repository.
pub(crate) const SHARED_LOCK_MODE: u32 = 0o660;

/// The mode forced on a regular file created inside a `bare-user-shared`
/// repository outside the object store, such as a `.commitpartial` marker.
pub(crate) const SHARED_FILE_MODE: u32 = 0o644;

/// Forces [`SHARED_DIR_MODE`] on the directory that the calling code created
/// at `path` under `dir`.
///
/// Call this on the arm of the create that made the directory. In all other
/// repository modes, the function returns at once.
pub(crate) fn force_created_dir<Fd: AsFd, P: Arg>(
    dir: Fd,
    path: P,
    repo_mode: RepoMode,
) -> std::io::Result<()> {
    if repo_mode != RepoMode::BareUserShared {
        return Ok(());
    }
    let fd = rustix::fs::openat(
        dir,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(SHARED_DIR_MODE))?;
    Ok(())
}

/// Forces `bits` on an open descriptor of an entry that the calling code
/// created.
///
/// Call this on the arm of the create that made the entry. In all other
/// repository modes, the function returns at once.
pub(crate) fn force_created_mode<Fd: AsFd>(
    fd: Fd,
    repo_mode: RepoMode,
    bits: u32,
) -> std::io::Result<()> {
    if repo_mode != RepoMode::BareUserShared {
        return Ok(());
    }
    rustix::fs::fchmod(fd, Mode::from_raw_mode(bits))?;
    Ok(())
}
