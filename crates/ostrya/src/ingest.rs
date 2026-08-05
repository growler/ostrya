//! Filesystem ingest: walking an on-disk tree into a [`MutableTree`].
//!
//! [`Transaction::write_dfd_to_mtree`] walks the directory tree rooted at a
//! path relative to a directory fd, ingesting its contents through the object
//! writers (in [`crate::write`]) and recording them in a
//! [`MutableTree`](crate::MutableTree). A [`CommitModifier`] shapes the walk:
//! canonical permissions, declared ownership, an include/prune filter, an
//! xattr-replacing callback, an SELinux label hook, a devino cache, and source
//! consumption.
//!
//! The walk reads each directory in one offloaded blocking pass (fd-relative
//! `Dir` iteration, `statat` per entry, xattr reads, `readlinkat`), then
//! ingests the entries: regular-file payloads stream through
//! [`write_content`](crate::Transaction::write_content) over an `rt::File`,
//! symlinks and per-directory metadata go through the metadata writers. The
//! per-entry namespace syscalls that open, unlink, and recurse are issued
//! inline, keeping the offload at per-directory granularity.

use std::future::Future;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::pin::Pin;

use ostrya_core::{DirMeta, RepoMode, Xattrs};
use ostrya_rt::File as RtFile;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::modifier::{
    CommitModifier, CommitModifierFlags, FilterResult, Owner, with_selinux, without_selinux,
};
use crate::mtree::MutableTree;
use crate::transaction::Transaction;
use crate::write::FileMeta;

/// The file-type mask of an `st_mode`.
const S_IFMT: u32 = 0o170000;
/// The canonical permission mask (`perm & 0o755`).
const CANONICAL_PERM_MASK: u32 = 0o755;

impl Transaction {
    /// Walk the on-disk tree at `path` relative to `dfd` and ingest it into
    /// `mtree`, shaped by `modifier`.
    ///
    /// The walk-root directory's own metadata becomes `mtree`'s dirmeta; its
    /// entries are ingested recursively. Regular-file contents stream through
    /// the object store, symlinks and directory metadata are written as
    /// objects, and each directory's dirtree is assembled later by
    /// [`write_mtree`](Transaction::write_mtree). A modifier filter that skips
    /// a directory prunes its whole subtree.
    pub async fn write_dfd_to_mtree(
        &self,
        dfd: BorrowedFd<'_>,
        path: &Path,
        mtree: &mut MutableTree,
        modifier: Option<&mut CommitModifier>,
    ) -> Result<()> {
        if self.repo().mode() == RepoMode::BareSplitXattrs {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
        let flags = modifier
            .as_deref()
            .map_or(CommitModifierFlags::empty(), |m| m.flags);
        if flags.contains(CommitModifierFlags::GENERATE_SIZES)
            && self.repo().mode() == RepoMode::Archive
        {
            self.mark_generate_sizes();
        }

        let root_fd = open_walk_root(dfd, path)?;
        walk_dir(self, root_fd, mtree, modifier, "/".to_owned(), None).await?;

        if flags.contains(CommitModifierFlags::CONSUME) {
            remove_walk_root(dfd, path);
        }
        Ok(())
    }
}

/// One directory entry captured during a blocking snapshot.
struct EntryInfo {
    name: String,
    kind: EntryKind,
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    /// The full `st_mode`, including the file-type bits.
    mode: u32,
    xattrs: Xattrs,
}

/// What kind of object an entry ingests to.
enum EntryKind {
    Dir,
    Regular,
    Symlink(String),
}

/// A directory's own metadata plus its entries, captured in one blocking pass.
struct DirSnapshot {
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: Xattrs,
    entries: Vec<EntryInfo>,
}

/// The boxed future for the recursive post-order walk; async recursion needs
/// indirection, so each level returns a boxed future.
type WalkFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Ingest one directory: write its dirmeta onto `node`, then ingest each entry.
///
/// `dir_meta` carries this directory's fully adjusted metadata, computed once by
/// the parent so the user callbacks fire once per directory. It is `None` only
/// for the walk root, which has no parent and is adjusted here.
fn walk_dir<'a>(
    txn: &'a Transaction,
    dir_fd: OwnedFd,
    node: &'a mut MutableTree,
    mut modifier: Option<&'a mut CommitModifier>,
    path: String,
    dir_meta: Option<FileMeta>,
) -> WalkFuture<'a> {
    Box::pin(async move {
        let flags = modifier
            .as_deref()
            .map_or(CommitModifierFlags::empty(), |m| m.flags);
        let owner = Owner::of(modifier.as_deref());
        let skip_xattrs = flags.contains(CommitModifierFlags::SKIP_XATTRS);

        // The heavy per-directory work runs on the blocking pool in one pass.
        let snap = {
            let dir = dir_fd.as_fd().try_clone_to_owned()?;
            ostrya_rt::unblock(move || snapshot_dir(dir.as_fd(), skip_xattrs)).await?
        };

        // This directory's own metadata becomes `node`'s dirmeta. The walk root
        // is adjusted here; a nested directory reuses what its parent computed.
        let dir_meta = match dir_meta {
            Some(m) => m,
            None => {
                let base = FileMeta {
                    uid: snap.uid,
                    gid: snap.gid,
                    mode: snap.mode,
                    xattrs: snap.xattrs,
                };
                let adjusted = adjust_meta(flags, owner, base, false);
                finalize_meta(modifier.as_deref_mut(), Path::new(&path), adjusted)?
            }
        };
        let dirmeta = txn.write_dirmeta(&to_dirmeta(&dir_meta)).await?;
        node.set_metadata_checksum(dirmeta);

        let consume = flags.contains(CommitModifierFlags::CONSUME);

        for entry in snap.entries {
            let cb_path = join_path(&path, &entry.name);
            let is_symlink = matches!(entry.kind, EntryKind::Symlink(_));

            // Canonical permissions are cheap and deterministic and feed the
            // filter; the user callbacks run only for entries that survive the
            // filter (and, for regular files, miss the devino cache).
            let base = FileMeta {
                uid: entry.uid,
                gid: entry.gid,
                mode: entry.mode,
                xattrs: entry.xattrs,
            };
            let filter_meta = adjust_meta(flags, owner, base, is_symlink);

            if let Some(m) = modifier.as_deref_mut()
                && let Some(filter) = &mut m.filter
                && filter(Path::new(&cb_path), &filter_meta) == FilterResult::Skip
            {
                txn.note_filtered();
                continue;
            }

            match entry.kind {
                EntryKind::Regular => {
                    // A devino hit takes the cached checksum verbatim and runs
                    // no callbacks; the file's content is never read.
                    if let Some(checksum) =
                        devino_hit(txn, modifier.as_deref(), entry.dev, entry.ino)
                    {
                        node.replace_file(&entry.name, checksum)?;
                        if consume {
                            unlink(dir_fd.as_fd(), &entry.name, false)?;
                        }
                        continue;
                    }
                    let meta =
                        finalize_meta(modifier.as_deref_mut(), Path::new(&cb_path), filter_meta)?;
                    let fd = rustix::fs::openat(
                        dir_fd.as_fd(),
                        entry.name.as_str(),
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?;
                    let checksum = txn.write_content(None, &meta, RtFile::from(fd)).await?;
                    node.replace_file(&entry.name, checksum)?;
                    if consume {
                        unlink(dir_fd.as_fd(), &entry.name, false)?;
                    }
                }
                EntryKind::Symlink(target) => {
                    let meta =
                        finalize_meta(modifier.as_deref_mut(), Path::new(&cb_path), filter_meta)?;
                    let checksum = txn.write_symlink(&target, &meta, None).await?;
                    node.replace_file(&entry.name, checksum)?;
                    if consume {
                        unlink(dir_fd.as_fd(), &entry.name, false)?;
                    }
                }
                EntryKind::Dir => {
                    let meta =
                        finalize_meta(modifier.as_deref_mut(), Path::new(&cb_path), filter_meta)?;
                    let child_fd = rustix::fs::openat(
                        dir_fd.as_fd(),
                        entry.name.as_str(),
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?;
                    let child = node.ensure_dir(&entry.name).await?;
                    walk_dir(
                        txn,
                        child_fd,
                        child,
                        modifier.as_deref_mut(),
                        cb_path,
                        Some(meta),
                    )
                    .await?;
                    if consume {
                        // A pruned entry can leave the directory non-empty;
                        // leave such a directory in place rather than failing
                        // the walk. Any other error is real. Each level
                        // tolerates this independently, so it cascades through
                        // nested directories without threading any state.
                        match rustix::fs::unlinkat(
                            dir_fd.as_fd(),
                            entry.name.as_str(),
                            AtFlags::REMOVEDIR,
                        ) {
                            Ok(()) | Err(Errno::NOTEMPTY) => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
            }
        }
        Ok(())
    })
}

/// A devino-cache checksum for `(dev, ino)`, when the cache is present and
/// [`DEVINO_CANONICAL`](CommitModifierFlags::DEVINO_CANONICAL) is set. A hit is
/// counted in the transaction statistics.
fn devino_hit(
    txn: &Transaction,
    modifier: Option<&CommitModifier>,
    dev: u64,
    ino: u64,
) -> Option<ostrya_core::Checksum> {
    let m = modifier?;
    if !m.flags.contains(CommitModifierFlags::DEVINO_CANONICAL) {
        return None;
    }
    let checksum = m.devino_cache.as_ref()?.get(dev, ino)?;
    txn.note_devino_hit();
    Some(checksum)
}

/// Apply the cheap, deterministic metadata adjustments a modifier states: the
/// [`CANONICAL_PERMISSIONS`](CommitModifierFlags::CANONICAL_PERMISSIONS)
/// reduction, then the declared ownership. Runs no user callbacks. A walk
/// without a modifier carries the empty flag set and no declared ownership,
/// making this a no-op.
///
/// Under `CANONICAL_PERMISSIONS` the owner becomes 0:0, the xattr set is
/// emptied, and a regular file's or directory's permission bits become
/// `perm & 0o755`; a symlink's mode is fixed by the object model, so only
/// regular-file and directory bits are canonicalized. The xattr set is emptied
/// here, ahead of the callbacks, so a callback that supplies xattrs or an
/// SELinux label still lands them, as it does under
/// [`SKIP_XATTRS`](CommitModifierFlags::SKIP_XATTRS).
///
/// The declared ownership is applied last, so a modifier that states both an
/// id and the canonical flag records the id.
pub(crate) fn adjust_meta(
    flags: CommitModifierFlags,
    owner: Owner,
    mut meta: FileMeta,
    is_symlink: bool,
) -> FileMeta {
    if flags.contains(CommitModifierFlags::CANONICAL_PERMISSIONS) {
        meta.uid = 0;
        meta.gid = 0;
        meta.xattrs = Xattrs::empty();
        if !is_symlink {
            meta.mode = (meta.mode & S_IFMT) | (meta.mode & CANONICAL_PERM_MASK);
        }
    }
    owner.apply(&mut meta);
    meta
}

/// Apply the xattr callback and the SELinux label hook, in that order. Runs the
/// user callbacks, so it is invoked once per committed entry: after the filter,
/// and after the devino-cache check for regular files.
fn apply_callbacks(m: &mut CommitModifier, path: &Path, mut meta: FileMeta) -> Result<FileMeta> {
    if let Some(callback) = &mut m.xattr_callback {
        meta.xattrs = callback(path, &meta);
    }

    if let Some(callback) = &mut m.label_callback {
        // Drop any pre-existing label so the callback's is never double-counted.
        meta.xattrs = without_selinux(&meta.xattrs)?;
        match callback(path, &meta) {
            Some(label) => meta.xattrs = with_selinux(&meta.xattrs, label)?,
            None => {
                if m.flags.contains(CommitModifierFlags::ERROR_ON_UNLABELED) {
                    return Err(Error::InvalidFormat(format!(
                        "no SELinux label for {}",
                        path.display()
                    )));
                }
            }
        }
    }
    Ok(meta)
}

/// Run the modifier's user callbacks over `meta`, returning it unchanged when no
/// modifier is attached.
pub(crate) fn finalize_meta(
    modifier: Option<&mut CommitModifier>,
    path: &Path,
    meta: FileMeta,
) -> Result<FileMeta> {
    match modifier {
        Some(m) => apply_callbacks(m, path, meta),
        None => Ok(meta),
    }
}

/// Build a directory-metadata object from an adjusted entry's metadata.
pub(crate) fn to_dirmeta(meta: &FileMeta) -> DirMeta {
    DirMeta {
        uid: meta.uid,
        gid: meta.gid,
        mode: meta.mode,
        xattrs: meta.xattrs.clone(),
    }
}

/// Capture a directory's own metadata and all of its entries in one blocking
/// pass. Each entry's own xattrs are read here unless `skip_xattrs`; a
/// symlink's xattrs are read no-follow, the link itself rather than its target.
fn snapshot_dir(dir: BorrowedFd<'_>, skip_xattrs: bool) -> Result<DirSnapshot> {
    let stat = rustix::fs::fstat(dir)?;
    let dir_xattrs = if skip_xattrs {
        Xattrs::empty()
    } else {
        crate::object::read_all_xattrs(dir)?
    };

    let mut entries = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let name = name
            .to_str()
            .map_err(|_| Error::InvalidFormat("directory entry name is not valid UTF-8".into()))?
            .to_owned();

        let stat = rustix::fs::statat(dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => EntryKind::Dir,
            FileType::RegularFile => EntryKind::Regular,
            FileType::Symlink => {
                let target = rustix::fs::readlinkat(dir, name.as_str(), Vec::new())?
                    .into_string()
                    .map_err(|_| {
                        Error::InvalidFormat("symlink target is not valid UTF-8".into())
                    })?;
                EntryKind::Symlink(target)
            }
            _ => {
                return Err(Error::Unsupported(format!(
                    "unsupported file type for entry {name:?}"
                )));
            }
        };

        let xattrs = if skip_xattrs {
            Xattrs::empty()
        } else {
            read_entry_xattrs(dir, name.as_str(), &kind)?
        };

        entries.push(EntryInfo {
            name,
            kind,
            dev: stat.st_dev,
            ino: stat.st_ino,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
            xattrs,
        });
    }

    Ok(DirSnapshot {
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode,
        xattrs: dir_xattrs,
        entries,
    })
}

/// Read an entry's own xattrs, no-follow. A regular file or directory is opened
/// and read from its fd; a symlink cannot be opened for an fd, so its own xattrs
/// are read through the path-based no-follow reader.
fn read_entry_xattrs(dir: BorrowedFd<'_>, name: &str, kind: &EntryKind) -> Result<Xattrs> {
    let oflags = match kind {
        EntryKind::Regular => OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        EntryKind::Dir => OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        EntryKind::Symlink(_) => return crate::object::read_link_xattrs(dir, name),
    };
    let fd = rustix::fs::openat(dir, name, oflags, Mode::empty())?;
    crate::object::read_all_xattrs(fd.as_fd())
}

/// Open the walk root relative to `dfd`. An empty path or `.` opens `dfd`
/// itself; any other path is opened no-follow so a symlink at the root is not
/// traversed.
fn open_walk_root(dfd: BorrowedFd<'_>, path: &Path) -> Result<OwnedFd> {
    let name = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    Ok(rustix::fs::openat(
        dfd,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Remove the walk-root directory after a consuming walk. Ignored when the root
/// is `dfd` itself (`.`) or already gone.
fn remove_walk_root(dfd: BorrowedFd<'_>, path: &Path) {
    if path.as_os_str().is_empty() || path == Path::new(".") {
        return;
    }
    let _ = rustix::fs::unlinkat(dfd, path, AtFlags::REMOVEDIR);
}

/// Unlink an entry from a directory: a file, or a directory with `AT_REMOVEDIR`.
fn unlink(dir: BorrowedFd<'_>, name: &str, is_dir: bool) -> Result<()> {
    let flags = if is_dir {
        AtFlags::REMOVEDIR
    } else {
        AtFlags::empty()
    };
    rustix::fs::unlinkat(dir, name, flags)?;
    Ok(())
}

/// Join a walk path and an entry name into the modifier callback path.
pub(crate) fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CreateOptions, Repo};
    use ostrya_rt::block_on;

    /// A throwaway directory removed on drop.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("ostrya-ingest-{}-{tag}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `GENERATE_SIZES` marks the transaction so commit assembly (Phase 7d) can
    /// emit `ostree.sizes`.
    #[test]
    fn generate_sizes_flag_marks_the_transaction() {
        let scratch = Scratch::new("gensizes");
        block_on(async {
            let repo = Repo::create(
                &scratch.0.join("repo"),
                CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let txn = repo.transaction().await.unwrap();
            assert!(!txn.generate_sizes(), "not marked until a walk requests it");

            let src = scratch.0.join("src");
            std::fs::create_dir_all(&src).unwrap();
            let dfd = std::fs::File::open(&scratch.0).unwrap();
            let mut mtree = MutableTree::new();
            let mut modifier = CommitModifier::new(CommitModifierFlags::GENERATE_SIZES);
            txn.write_dfd_to_mtree(
                dfd.as_fd(),
                Path::new("src"),
                &mut mtree,
                Some(&mut modifier),
            )
            .await
            .unwrap();

            assert!(txn.generate_sizes(), "GENERATE_SIZES marks the transaction");
            txn.abort().await.unwrap();

            // Outside archive mode GENERATE_SIZES is a silent no-op: the flag is
            // left unset, so Phase 7d emits no empty `ostree.sizes`.
            let repo = Repo::create(
                &scratch.0.join("repo-bare"),
                CreateOptions::new(RepoMode::BareUser),
            )
            .await
            .unwrap();
            let txn = repo.transaction().await.unwrap();
            let dfd = std::fs::File::open(&scratch.0).unwrap();
            let mut mtree = MutableTree::new();
            let mut modifier = CommitModifier::new(CommitModifierFlags::GENERATE_SIZES);
            txn.write_dfd_to_mtree(
                dfd.as_fd(),
                Path::new("src"),
                &mut mtree,
                Some(&mut modifier),
            )
            .await
            .unwrap();
            assert!(
                !txn.generate_sizes(),
                "GENERATE_SIZES is a no-op outside archive mode"
            );
            txn.abort().await.unwrap();
        });
    }
}
