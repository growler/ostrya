//! The depth-first walk: one blocking listing call for each directory, and
//! the entry filter on the task that drives the scan.

use std::fs;
use std::io;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use ostrya_core::DirTree;

use super::hash::{FileId, Jobs, Stopped};
use super::model::TreeModel;
use super::{
    EntryAction, EntryFilter, EntryKind, EntryMeta, EntryPath, ScanOptions, check_filtered,
    classify, default_meta, invalid_data,
};
use crate::error::{Error, Result};
use crate::session::{PushPhase, PushProgress};

/// One entry of a directory listing, with its default metadata and its
/// identity.
struct RawEntry {
    name: String,
    meta: EntryMeta,
    id: FileId,
}

/// The state of one walk.
struct Walker {
    model: TreeModel,
    filter: Option<EntryFilter>,
    /// The path that the filter sees. The walk uses this one buffer for each
    /// entry.
    path: EntryPath,
}

/// Walks and hashes the tree at `root`.
///
/// If `progress` is `Some`, it shows [`PushPhase::Scanning`] until the walk
/// lists and filters each directory. Then it shows [`PushPhase::Hashing`]
/// while the hash jobs in flight end and the bottom-up pass runs.
pub(super) async fn scan(
    root: &Path,
    options: ScanOptions,
    progress: Option<&PushProgress>,
) -> Result<TreeModel> {
    let ScanOptions {
        entry_filter,
        hash_jobs,
    } = options;
    if hash_jobs == Some(0) {
        return Err(Error::InvalidInput(
            "hash_jobs is 0; the hash pass needs at least one job".into(),
        ));
    }
    if let Some(progress) = progress {
        progress.set_phase(PushPhase::Scanning);
    }
    let mut jobs = Jobs::new();
    let mut walker = Walker {
        model: TreeModel::new(root),
        filter: entry_filter,
        path: EntryPath {
            path: String::new(),
        },
    };
    // A walk that stops records its error in `jobs`. `finish` returns the
    // error after each job in flight stops.
    let _ = walker.walk(&mut jobs, hash_jobs).await;
    if let Some(progress) = progress {
        progress.set_phase(PushPhase::Hashing);
    }
    jobs.finish(&mut walker.model)
        .await
        .map_err(|(path, source)| Error::Walk { path, source })?;
    let mut model = walker.model;
    model.finish()?;
    Ok(model)
}

impl Walker {
    /// Reads the walk root, runs the filter on it, and walks the tree
    /// depth-first. An explicit stack holds the pairs (directory, next entry).
    ///
    /// If `hash_jobs` is `None`, the blocking call that reads the root also
    /// counts the CPUs, because the count can read files of the system.
    async fn walk(
        &mut self,
        jobs: &mut Jobs,
        hash_jobs: Option<usize>,
    ) -> std::result::Result<(), Stopped> {
        let root = self.model.root().to_path_buf();
        let (read, limit) = {
            let root = root.clone();
            jobs.drive(
                &mut self.model,
                ostrya_rt::unblock(move || {
                    let limit = hash_jobs
                        .unwrap_or_else(|| {
                            std::thread::available_parallelism().map_or(1, NonZeroUsize::get)
                        })
                        .min(ostrya_rt::blocking_threads());
                    (fs::symlink_metadata(root), limit)
                }),
            )
            .await
        };
        jobs.set_limit(limit);
        if jobs.is_stopped() {
            return Err(Stopped);
        }
        let md = match read {
            Ok(md) => md,
            Err(e) => return Err(jobs.fail(root, e)),
        };
        if !matches!(classify(&md), Ok(EntryKind::Dir)) {
            let e = io::Error::new(
                io::ErrorKind::InvalidInput,
                "the walk root is not a directory",
            );
            return Err(jobs.fail(root, e));
        }
        let mut meta = default_meta(EntryKind::Dir, &md, None);
        if let Some(filter) = &mut self.filter
            && filter(&self.path, &mut meta) == EntryAction::Skip
        {
            let e = io::Error::new(
                io::ErrorKind::InvalidInput,
                "the entry filter skipped the walk root",
            );
            return Err(jobs.fail(root, e));
        }
        if let Err(e) = check_filtered(EntryKind::Dir, &meta) {
            return Err(jobs.fail(root, e));
        }
        self.model.push_root(meta, FileId::of(&md));
        self.enter(0, jobs).await?;

        let mut stack = vec![(0u32, self.model.children(0).start)];
        while let Some(&(dir, cursor)) = stack.last() {
            let end = self.model.children(dir).end;
            match (cursor..end).find(|&i| self.model.is_dir(i)) {
                Some(child) => {
                    let top = stack.len() - 1;
                    stack[top].1 = child + 1;
                    self.enter(child, jobs).await?;
                    stack.push((child, self.model.children(child).start));
                }
                None => {
                    stack.pop();
                }
            }
        }
        Ok(())
    }

    /// Lists the directory `dir`, runs the filter on each entry in the order
    /// of the listing, and adds the kept entries to the model.
    ///
    /// The call queues a kept regular file for the hash pass at once, and
    /// hashes a kept symlink at once.
    async fn enter(&mut self, dir: u32, jobs: &mut Jobs) -> std::result::Result<(), Stopped> {
        let os_dir = self.model.os_path(dir);
        let listing = jobs
            .drive(
                &mut self.model,
                ostrya_rt::unblock(move || list_dir(os_dir)),
            )
            .await;
        if jobs.is_stopped() {
            return Err(Stopped);
        }
        let entries = match listing {
            Ok(entries) => entries,
            Err((path, e)) => return Err(jobs.fail(path, e)),
        };

        self.model.rel_path(dir, &mut self.path.path);
        let dir_len = self.path.path.len();
        let start = match self.model.next_index() {
            Ok(index) => index,
            Err(e) => return Err(jobs.fail(self.model.os_path(dir), e)),
        };
        for RawEntry { name, mut meta, id } in entries {
            self.path.path.truncate(dir_len);
            if dir_len > 0 {
                self.path.path.push('/');
            }
            self.path.path.push_str(&name);
            let kind = meta.kind;
            if let Some(filter) = &mut self.filter
                && filter(&self.path, &mut meta) == EntryAction::Skip
            {
                continue;
            }
            let index = match check_filtered(kind, &meta).and_then(|()| self.model.next_index()) {
                Ok(index) => index,
                Err(e) => return Err(jobs.fail(self.model.os_path(dir).join(&name), e)),
            };
            self.model.push(dir, name, meta, id);
            match kind {
                EntryKind::File => jobs.push(index),
                EntryKind::Symlink => {
                    if let Err(e) = self.model.hash_symlink(index) {
                        return Err(jobs.fail(self.model.os_path(index), e));
                    }
                }
                EntryKind::Dir => {}
            }
        }
        let end = match self.model.next_index() {
            Ok(index) => index,
            Err(e) => return Err(jobs.fail(self.model.os_path(dir), e)),
        };
        self.model.set_children(dir, start..end);
        Ok(())
    }
}

/// Reads the directory `dir` to its end in one blocking call, with the
/// metadata of each entry and the target of each symlink.
///
/// The first failure ends the listing and names its path, so the filter never
/// sees a listing that holds an entry that the walk refuses. The call closes
/// the directory before it returns.
fn list_dir(dir: PathBuf) -> std::result::Result<Vec<RawEntry>, (PathBuf, io::Error)> {
    let listing = fs::read_dir(&dir).map_err(|e| (dir.clone(), e))?;
    let mut entries = Vec::new();
    for entry in listing {
        let entry = entry.map_err(|e| (dir.clone(), e))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| (entry.path(), invalid_data("the name is not valid UTF-8")))?;
        DirTree::check_name(&name).map_err(|e| (entry.path(), invalid_data(e.to_string())))?;
        let md = entry.metadata().map_err(|e| (entry.path(), e))?;
        let kind = classify(&md).map_err(|e| (entry.path(), e))?;
        let target = match kind {
            EntryKind::Symlink => Some(read_target(&entry.path()).map_err(|e| (entry.path(), e))?),
            EntryKind::File | EntryKind::Dir => None,
        };
        entries.push(RawEntry {
            name,
            meta: default_meta(kind, &md, target),
            id: FileId::of(&md),
        });
    }
    Ok(entries)
}

/// Returns the target of the symlink at `path`. A target that is not valid
/// UTF-8 is an error of the kind `InvalidData`.
fn read_target(path: &Path) -> io::Result<String> {
    fs::read_link(path)
        .map_err(unsupported_link)?
        .into_os_string()
        .into_string()
        .map_err(|_| invalid_data("the symlink target is not valid UTF-8"))
}

/// Returns the error of a failed read of a symlink target on Windows.
///
/// `std` reads some reparse points as symlinks, but it cannot read their
/// target. The read then fails with the kind `Uncategorized`. The walk
/// refuses such an entry with the kind `Unsupported`. The call returns each
/// other error unchanged.
///
/// Because `io::ErrorKind` names `Uncategorized` only as an unstable variant,
/// the call gets the kind from an OS error that `std` cannot categorize. That
/// error is a Win32 code with the customer bit set, which no system error
/// has.
#[cfg(windows)]
fn unsupported_link(e: io::Error) -> io::Error {
    let uncategorized = io::Error::from_raw_os_error(0x2000_0000).kind();
    if e.kind() == uncategorized {
        return io::Error::new(
            io::ErrorKind::Unsupported,
            format!("the entry is a reparse point whose target cannot be read: {e}"),
        );
    }
    e
}

/// Returns the error of a failed read of a symlink target unchanged.
#[cfg(not(windows))]
fn unsupported_link(e: io::Error) -> io::Error {
    e
}
