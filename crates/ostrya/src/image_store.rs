//! The store of the composefs images of commits.
//!
//! The composefs image of a commit is the file
//! `extensions/ostrya/composefs/<xx>/<rest>.cfs` of the repository, where
//! `<xx><rest>` is the checksum of the commit. The store is a part of the
//! repository outside `objects/`. No transfer carries an image.
//!
//! - [`open_blocking`] opens an image with one `openat2` under the root of
//!   the repository, with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`.
//! - [`list_blocking`] lists the commits that have an image.
//! - [`unlink_blocking`] removes the images of commits.
//! - [`publish_blocking`] renames the staged images of a transaction into
//!   the store.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use ostrya_core::{Checksum, RepoMode};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::perm;
use crate::repo::Repo;
use crate::summary::{EXTENSION_DIR_MODE, extension_entry_error, open_extension_dir};

/// The directory of the images, relative to the root of the repository.
pub(crate) const IMAGE_DIR: &str = "extensions/ostrya/composefs";
/// The components of [`IMAGE_DIR`], from the root of the repository.
const IMAGE_DIR_PARTS: [&str; 3] = ["extensions", "ostrya", "composefs"];
/// The extension of an image file.
const EXTENSION: &str = "cfs";

/// Returns the path of the image of `commit` relative to [`IMAGE_DIR`]:
/// `<xx>/<rest>.cfs`.
pub(crate) fn rel_path(commit: &Checksum) -> String {
    let hex = commit.to_hex();
    format!("{}/{}.{EXTENSION}", &hex[..2], &hex[2..])
}

/// Returns the name of the image of `commit` in the staging directory of a
/// transaction: `<checksum>.cfs`.
pub(crate) fn staging_name(commit: &Checksum) -> String {
    format!("{}.{EXTENSION}", commit.to_hex())
}

/// Opens the image of `commit` in `repo` for reading, or returns `None` if
/// the image is absent.
///
/// The open is one `openat2` of `extensions/ostrya/composefs/<xx>/<rest>.cfs`
/// under the root of the repository, with `RESOLVE_BENEATH` and
/// `RESOLVE_NO_SYMLINKS`. A symlink at any component of the path fails the
/// open with `ELOOP`. Only `ENOENT` gives `None`. Each other errno of the
/// open, `ENOSYS` included, is an error. In the strict open mode of
/// [`Repo::open_at_strict`], the open also does not wait on a FIFO, and it
/// refuses a file that is not a regular file.
pub(crate) fn open_blocking(repo: &Repo, commit: &Checksum) -> Result<Option<std::fs::File>> {
    let path = format!("{IMAGE_DIR}/{}", rel_path(commit));
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if repo.is_strict() {
        flags |= OFlags::NONBLOCK | OFlags::NOCTTY;
    }
    let fd = match rustix::fs::openat2(
        repo.repo_fd(),
        path.as_str(),
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if repo.is_strict()
        && FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) != FileType::RegularFile
    {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the composefs image is not a regular file",
        )));
    }
    Ok(Some(std::fs::File::from(fd)))
}

/// Returns the commits that have an image in the store under `repo_fd`, in
/// sorted order.
///
/// The listing reads each `<xx>/` directory of [`IMAGE_DIR`] whose name is 2
/// lowercase hex digits, and parses each `<rest>.cfs` name in it whose
/// `<rest>` is 62 lowercase hex digits. It skips each other name, and each
/// `<xx>` entry that is a symlink or no directory. An absent [`IMAGE_DIR`]
/// gives an empty list.
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if a component of [`IMAGE_DIR`] is a symlink or
///   no directory.
/// - [`Error::Io`] if a read of a directory fails.
pub(crate) fn list_blocking(repo_fd: BorrowedFd<'_>) -> Result<Vec<Checksum>> {
    let Some(dir) = open_extension_dir(repo_fd, &IMAGE_DIR_PARTS, None, false)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for fanout in crate::traverse::read_dir_names(dir.as_fd())? {
        if !is_lower_hex(&fanout, 2) {
            continue;
        }
        let sub = match open_fanout(dir.as_fd(), &fanout) {
            Ok(fd) => fd,
            Err(Errno::NOENT | Errno::NOTDIR | Errno::LOOP) => continue,
            Err(e) => return Err(e.into()),
        };
        for entry in crate::traverse::read_dir_names(sub.as_fd())? {
            let Some(rest) = entry.strip_suffix(".cfs") else {
                continue;
            };
            if !is_lower_hex(rest, 62) {
                continue;
            }
            if let Ok(commit) = Checksum::from_hex(&format!("{fanout}{rest}")) {
                out.push(commit);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Returns `true` if `name` is `len` lowercase hex digits.
fn is_lower_hex(name: &str, len: usize) -> bool {
    name.len() == len && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Removes the images of `commits` from the store under `repo_fd`.
///
/// The call opens [`IMAGE_DIR`] one time, and each `<xx>/` directory one
/// time. An absent image, an absent `<xx>/` directory, and an absent
/// [`IMAGE_DIR`] count as a success. With `fsync`, after the last removal,
/// the call syncs one time each `<xx>/` directory from which it removed an
/// image.
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if a component of [`IMAGE_DIR`] or `<xx>/` is
///   a symlink or no directory.
/// - [`Error::Io`] if a removal or a sync fails.
pub(crate) fn unlink_blocking(
    repo_fd: BorrowedFd<'_>,
    commits: impl IntoIterator<Item = Checksum>,
    fsync: bool,
) -> Result<()> {
    let Some(dir) = open_extension_dir(repo_fd, &IMAGE_DIR_PARTS, None, false)? else {
        return Ok(());
    };
    // Each `<xx>/` that the call opened, with the switch that it removed an
    // image there. An absent `<xx>/` has `None`.
    let mut fanouts: HashMap<String, Option<(OwnedFd, bool)>> = HashMap::new();
    for commit in commits {
        let path = rel_path(&commit);
        let (fanout, name) = path.split_at(2);
        let entry = match fanouts.entry(fanout.to_owned()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(match open_fanout(dir.as_fd(), fanout) {
                Ok(fd) => Some((fd, false)),
                Err(Errno::NOENT) => None,
                Err(e) => return Err(fanout_error(dir.as_fd(), fanout, e)),
            }),
        };
        let Some((sub, removed)) = entry else {
            continue;
        };
        match rustix::fs::unlinkat(&*sub, &name[1..], AtFlags::empty()) {
            Ok(()) => *removed = true,
            Err(Errno::NOENT) => {}
            Err(e) => return Err(e.into()),
        }
    }
    if fsync {
        for (sub, _) in fanouts.values().flatten().filter(|(_, removed)| *removed) {
            rustix::fs::fsync(sub)?;
        }
    }
    Ok(())
}

/// Renames the staged images of a transaction into the store under
/// `repo_fd`.
///
/// Each entry of `images` is the staging name of an image in `staging_fd`
/// and its path relative to [`IMAGE_DIR`]. The call runs these steps:
///
/// 1. It opens [`IMAGE_DIR`], one component at a time, with no symlink
///    followed. It creates each component that does not exist, as
///    [`open_extension_dir`] states. With `fsync`, it syncs the parent of
///    each directory that it creates.
/// 2. For each image, it creates the `<xx>/` directory if it does not exist,
///    with the same mode rule, opens it with no symlink followed, and renames
///    the image into it. The rename replaces a stored image of the same
///    commit.
/// 3. With `fsync`, it syncs each `<xx>/` directory that got an image, and
///    then [`IMAGE_DIR`].
pub(crate) fn publish_blocking(
    repo_fd: BorrowedFd<'_>,
    staging_fd: BorrowedFd<'_>,
    images: &[(String, String)],
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<()> {
    if images.is_empty() {
        return Ok(());
    }
    let dir = open_extension_dir(repo_fd, &IMAGE_DIR_PARTS, Some(repo_mode), fsync)?
        .expect("a create of the image directory gives the directory");
    let mut fanouts: Vec<(String, OwnedFd)> = Vec::new();
    for (staging, dest) in images {
        let (fanout, name) = dest.split_at(2);
        let index = match fanouts.iter().position(|(f, _)| f == fanout) {
            Some(index) => index,
            None => {
                match rustix::fs::mkdirat(&dir, fanout, Mode::from_raw_mode(EXTENSION_DIR_MODE)) {
                    Ok(()) => perm::force_created_dir(&dir, fanout, repo_mode)?,
                    Err(Errno::EXIST) => {}
                    Err(e) => return Err(e.into()),
                }
                let sub = open_fanout(dir.as_fd(), fanout)
                    .map_err(|e| fanout_error(dir.as_fd(), fanout, e))?;
                fanouts.push((fanout.to_owned(), sub));
                fanouts.len() - 1
            }
        };
        rustix::fs::renameat(staging_fd, staging.as_str(), &fanouts[index].1, &name[1..])?;
    }
    if fsync {
        for (_, sub) in &fanouts {
            rustix::fs::fsync(sub)?;
        }
        rustix::fs::fsync(&dir)?;
    }
    Ok(())
}

/// Opens the `<xx>/` directory `fanout` of [`IMAGE_DIR`] with no symlink
/// followed.
fn open_fanout(dir: BorrowedFd<'_>, fanout: &str) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat(
        dir,
        fanout,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Returns the error of an open of the `<xx>/` directory `fanout` of `dir`
/// that failed with `err`, as [`extension_entry_error`] states.
fn fanout_error(dir: BorrowedFd<'_>, fanout: &str, err: Errno) -> Error {
    match err {
        Errno::NOTDIR | Errno::LOOP => {
            extension_entry_error(dir, fanout, &format!("{IMAGE_DIR}/{fanout}"))
        }
        e => e.into(),
    }
}
