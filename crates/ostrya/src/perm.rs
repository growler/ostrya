//! The permission bits ostrya forces on the entries it creates inside a
//! `bare-user-shared` repository.
//!
//! `mkdirat` and `openat(O_CREAT)` reduce their mode argument by the calling
//! process's file-creation mask, so the mode argument alone cannot carry a
//! guarantee. Each helper here applies the wanted bits with `fchmod` after the
//! create, which the mask does not touch. Every other repository mode keeps the
//! masked result, so the helpers return immediately for it.
//!
//! A directory takes `02770`. The setgid bit is part of the forced mode:
//! `mkdirat` inherits it from the parent, and an `fchmod` that leaves it out
//! clears it, which stops group inheritance below that level. A directory keeps
//! an `S_ISGID` bit a non-privileged `chmod` sets; the kernel's silent-clear
//! rule covers non-directory files. The sticky bit stays off `tmp/` and off the
//! repository root, because the stale-staging reaper removes staging trees that
//! other members of the group own.
//!
//! A helper runs on the arm of a create where that call made the entry. An
//! entry that already stands may belong to another uid, where `fchmod` answers
//! `EPERM`.
//!
//! [`force_created_dir`] opens the entry and calls `fchmod` on the descriptor.
//! Linux does not honour `AT_SYMLINK_NOFOLLOW` in `fchmodat`, so a path-based
//! chmod carries a symlink-swap race that an `openat` with `O_NOFOLLOW`
//! followed by `fchmod` does not.

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

/// Force [`SHARED_DIR_MODE`] on the directory `path` names under `dir`, which
/// the calling code has just created.
///
/// Call this on the arm of the create that made the directory. Every other
/// repository mode returns at once.
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

/// Force `bits` on an open descriptor for an entry the calling code has just
/// created.
///
/// Call this on the arm of the create that made the entry. Every other
/// repository mode returns at once.
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
