//! The store of the composefs images of commits.
//!
//! The composefs image of a commit is the file
//! `extensions/ostrya/composefs/<xx>/<rest>.cfs` of the repository, where
//! `<xx><rest>` is the checksum of the commit. The store is a part of the
//! repository outside `objects/`. No transfer carries an image.
//!
//! - [`open_blocking`] opens an image with one `openat2` below the root of
//!   the repository, with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`.
//! - [`list_blocking`] lists the commits that have an image.
//! - [`unlink_blocking`] removes the images of commits.
//! - [`publish_blocking`] renames the staged images of a transaction into
//!   the store.
//!
//! The store is a directory of the kind [`RepoLayout::Extensions`]: each
//! directory that a write makes below `extensions/` gets the mode `0775`,
//! and `02770` in a `bare-user-shared` repository.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use ostrya_core::Checksum;

use crate::error::Result;
use crate::repo::Repo;
use crate::repo_fs::{self, FsError, FsResultExt, Opened, Publish, Reason, RepoDir, RepoLayout};

/// The directory of the images, relative to the root of the repository.
pub(crate) const IMAGE_DIR: &str = "extensions/ostrya/composefs";
/// The path of [`IMAGE_DIR`] below `extensions/`.
const IMAGE_SUBDIR: &str = "ostrya/composefs";
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

/// Opens the image of `commit` in `repo` for reading, and gives the file and
/// its status. Returns `None` if the image is absent.
///
/// The open is [`RepoDir::open_regular`] of
/// `extensions/ostrya/composefs/<xx>/<rest>.cfs` on the root handle: one
/// `openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`, then one
/// `statx` of the open file. The open does not wait on a FIFO.
///
/// # Errors
///
/// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if a symlink is
///   at a component of the path, if a component before the image is not a
///   directory, or if the image is not a regular file.
/// - [`Error::Io`](crate::Error::Io) if the open or the `statx` fails for
///   another reason, `ENOSYS` included.
pub(crate) fn open_blocking(repo: &Repo, commit: &Checksum) -> Result<Option<Opened>> {
    let path = format!("{IMAGE_DIR}/{}", rel_path(commit));
    Ok(repo.root_dir().open_regular(&path).optional()?)
}

/// Opens [`IMAGE_DIR`] below the repository root `root`, or returns `None`
/// if `extensions` or a directory below it does not exist.
///
/// The call opens `extensions` with one `openat2`, and then
/// `ostrya/composefs` below it with one `openat2`. A symlink at a component
/// or an entry that is not a directory fails the open.
fn open_store(root: &RepoDir) -> std::result::Result<Option<RepoDir>, FsError> {
    let Some(extensions) = root.open_layout(RepoLayout::Extensions).optional()? else {
        return Ok(None);
    };
    extensions.open_dir(IMAGE_SUBDIR).optional()
}

/// Returns the commits that have an image in the store below the repository
/// root `root`, in sorted order.
///
/// The listing reads each `<xx>/` directory of [`IMAGE_DIR`] whose name is 2
/// lowercase hex digits, and parses each `<rest>.cfs` name in it whose
/// `<rest>` is 62 lowercase hex digits. It skips each other name, and each
/// `<xx>` entry that is a symlink or no directory. An absent [`IMAGE_DIR`]
/// gives an empty list.
///
/// # Errors
///
/// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if a component
///   of [`IMAGE_DIR`] is a symlink or no directory.
/// - [`Error::Io`](crate::Error::Io) if a read of a directory fails.
pub(crate) fn list_blocking(root: &RepoDir) -> Result<Vec<Checksum>> {
    let Some(store) = open_store(root)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in store.list()? {
        let Ok(fanout) = std::str::from_utf8(&entry.name) else {
            continue;
        };
        if !is_lower_hex(fanout, 2) {
            continue;
        }
        let sub = match store.open_dir(fanout) {
            Ok(sub) => sub,
            Err(
                FsError::Absent { .. }
                | FsError::Invalid {
                    reason: Reason::Symlink | Reason::NotDirectory,
                    ..
                },
            ) => continue,
            Err(e) => return Err(e.into()),
        };
        for entry in sub.list()? {
            let Some(rest) = std::str::from_utf8(&entry.name)
                .ok()
                .and_then(|name| name.strip_suffix(".cfs"))
            else {
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

/// Removes the images of `commits` from the store below the repository root
/// `root`.
///
/// The call opens [`IMAGE_DIR`] one time, and each `<xx>/` directory of the
/// commits one time, with one `openat2` each. It unlinks each image relative
/// to its `<xx>/` directory. An absent image, an absent `<xx>/` directory,
/// and an absent [`IMAGE_DIR`] count as a success. With `fsync`, after the
/// last removal, the call syncs one time each `<xx>/` directory from which it
/// removed an image.
///
/// # Errors
///
/// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if a component
///   of [`IMAGE_DIR`] or `<xx>/` is a symlink or no directory.
/// - [`Error::Io`](crate::Error::Io) if a removal or a sync fails.
pub(crate) fn unlink_blocking(
    root: &RepoDir,
    commits: impl IntoIterator<Item = Checksum>,
    fsync: bool,
) -> Result<()> {
    let Some(store) = open_store(root)? else {
        return Ok(());
    };
    // Each `<xx>/` that the call opened, with the switch that it removed an
    // image there. An absent `<xx>/` has `None`.
    let mut fanouts: HashMap<String, Option<(RepoDir, bool)>> = HashMap::new();
    for commit in commits {
        let path = rel_path(&commit);
        let (fanout, name) = path.split_at(2);
        let entry = match fanouts.entry(fanout.to_owned()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                entry.insert(store.open_dir(fanout).optional()?.map(|sub| (sub, false)))
            }
        };
        if let Some((sub, removed)) = entry {
            *removed |= sub.remove_file(&name[1..], false)?;
        }
    }
    if fsync {
        for (sub, _) in fanouts.values().flatten().filter(|(_, removed)| *removed) {
            sub.sync()?;
        }
    }
    Ok(())
}

/// Renames the staged images of a transaction into the store below the
/// repository root `root`.
///
/// Each entry of `images` is the staging name of an image in `staging` and
/// its path relative to [`IMAGE_DIR`]. The call runs these steps:
///
/// 1. It makes `extensions` and [`IMAGE_DIR`] below it if they do not
///    exist, with [`RepoDir::ensure_layout`] and [`RepoDir::ensure_dir`].
///    With `fsync`, it syncs the parent of each directory that it makes.
/// 2. For each image, it renames the image into its `<xx>/` directory. The
///    call makes each `<xx>/` directory that does not exist, with no sync,
///    and opens it one time. The rename replaces a stored image of the same
///    commit.
/// 3. With `fsync`, it syncs each `<xx>/` directory that got an image, and
///    then [`IMAGE_DIR`].
///
/// A symlink at a component of the path and an entry that is not a
/// directory fail the call.
pub(crate) fn publish_blocking(
    root: &RepoDir,
    staging: &RepoDir,
    images: &[(String, String)],
    fsync: bool,
) -> Result<()> {
    if images.is_empty() {
        return Ok(());
    }
    let store = root
        .ensure_layout(RepoLayout::Extensions, fsync)?
        .ensure_dir(IMAGE_SUBDIR, fsync)?;
    let mut fanouts: Vec<(&str, RepoDir)> = Vec::new();
    for (staged, dest) in images {
        let (fanout, name) = dest.split_at(2);
        let index = match fanouts.iter().position(|(f, _)| *f == fanout) {
            Some(index) => index,
            None => {
                fanouts.push((fanout, store.ensure_dir(fanout, false)?));
                fanouts.len() - 1
            }
        };
        let sub = &fanouts[index].1;
        repo_fs::rename(staging, staged, sub, &name[1..], Publish::Replace, false)?;
    }
    if fsync {
        for (_, sub) in &fanouts {
            sub.sync()?;
        }
        store.sync()?;
    }
    Ok(())
}
