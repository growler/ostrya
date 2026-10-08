//! The file system ingest of a transaction.
//!
//! This module reads a tree on disk, or a committed tree, into a
//! `MutableTree`. The docs of `Transaction::write_dfd_to_mtree` and
//! `Transaction::overlay_tree_to_mtree` hold the behavior that a caller sees.
//! The object writers are in `write.rs`.

use std::future::Future;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::pin::Pin;

use ostrya_core::{DirMeta, RepoMode, Xattrs};
use ostrya_rt::FileReader;
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
/// The symlink file-type bits of an `st_mode`.
const S_IFLNK: u32 = 0o120000;
/// The canonical permission mask (`perm & 0o755`).
const CANONICAL_PERM_MASK: u32 = 0o755;

/// Methods that read a directory on disk into a mutable tree.
impl Transaction {
    /// Walks the directory at `path` under `dfd` and adds its tree to `mtree`.
    ///
    /// The metadata of the walk root becomes the dirmeta of `mtree`. The walk
    /// adds each entry below the root to `mtree`:
    ///
    /// - The payload of a regular file streams into a content object.
    /// - A symlink and the metadata of each directory become objects.
    /// - A directory merges with a directory of the same name in `mtree`.
    /// - A regular file or a symlink replaces a file of the same name in
    ///   `mtree`.
    ///
    /// [`write_mtree`](Transaction::write_mtree) writes the dirtree of each
    /// directory later. If `path` is empty or `.`, the walk root is `dfd`
    /// itself. The walk does not follow a symlink at the last component of
    /// `path`.
    ///
    /// # Modifier
    ///
    /// Without a modifier, each entry records the ownership, the mode, and the
    /// xattrs that it has on disk. A [`CommitModifier`] applies its steps to
    /// each entry in this order:
    ///
    /// 1. The [`CANONICAL_PERMISSIONS`](CommitModifierFlags::CANONICAL_PERMISSIONS)
    ///    reduction: owner 0:0, no xattrs, and `perm & 0o755` on a regular
    ///    file or a directory. A symlink keeps its mode.
    /// 2. [`SKIP_XATTRS`](CommitModifierFlags::SKIP_XATTRS): the walk reads no
    ///    xattrs from the disk, and the entry has no xattrs.
    /// 3. The declared ownership (`owner_uid` and `owner_gid`).
    /// 4. The filter. It gets the metadata of steps 1 to 3. If it returns
    ///    [`FilterResult::Skip`] for a directory, the walk skips the whole
    ///    subtree.
    /// 5. The mode callback.
    /// 6. The `CANONICAL_PERMISSIONS` reduction again, on the mode that the
    ///    callback returns. The file type stays the type that the walk found.
    ///    A symlink keeps its mode.
    /// 7. The xattr callback.
    /// 8. The SELinux label callback. The walk drops the `security.selinux`
    ///    xattr of the entry, then adds the label that the callback returns.
    ///    If the callback returns no label, the entry has no label.
    ///
    /// Steps 5 to 8 run only for an entry that the filter keeps. The walk root
    /// goes through each step except the filter.
    ///
    /// If the modifier holds a [`DevInoCache`](crate::DevInoCache), the walk
    /// looks up each regular file and symlink in it, and never a directory.
    /// The walk does not read a source file that the cache knows. Without
    /// [`DEVINO_CANONICAL`](CommitModifierFlags::DEVINO_CANONICAL), a hit
    /// takes its metadata from the stored object. For this reason, a
    /// `user.ostreemeta` xattr on a file of a `bare-user` checkout does not
    /// enter the commit.
    ///
    /// # Consume
    ///
    /// Under [`CONSUME`](CommitModifierFlags::CONSUME), the walk removes each
    /// source entry after it records the entry. It also removes each entry
    /// that the filter skips, with its whole subtree. Then the call removes the
    /// walk root.
    ///
    /// The test for the walk root is on the bytes of `path`. If `path` is
    /// exactly `.`, the call keeps the root. For each other spelling, `./`
    /// included, the call tries to remove the root and ignores a failure.
    ///
    /// # File system access
    ///
    /// The walk reads each directory in one pass on the blocking pool. The pass
    /// reads the entry list, the `statat` of each entry, the xattrs, and the
    /// symlink targets. The walk reads the xattrs of a symlink from the link itself. The
    /// calls that open and remove entries run on the calling task.
    /// The walk holds at most two directory descriptors at a time, at any
    /// depth of the source.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`,
    ///   or if an entry is not a directory, a regular file, or a symlink.
    /// - [`Error::Unsupported`] if `[ex-integrity] fsverity` is `yes` and the
    ///   fs-verity seal of an object fails.
    /// - [`Error::InvalidFormat`] if an entry name or a symlink target is not
    ///   valid UTF-8.
    /// - [`Error::InvalidFormat`] if the label callback returns no label and
    ///   [`ERROR_ON_UNLABELED`](CommitModifierFlags::ERROR_ON_UNLABELED) is
    ///   set.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::InvalidFormat`] if the stored object of a devino-cache hit
    ///   does not have the form of the repository mode.
    /// - [`Error::ConsumeUnlink`] if `CONSUME` is set and the removal of a
    ///   source entry fails.
    /// - [`Error::ReplaceDirWithFile`] if a regular file or a symlink has the
    ///   name of a directory in `mtree`.
    /// - [`Error::ReplaceFileWithDir`] if a directory has the name of a file
    ///   in `mtree`.
    /// - [`Error::InsufficientFreeSpace`] if an object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::ObjectNotFound`] if a devino-cache hit or a lazy
    ///   subdirectory of `mtree` names an object that the repository does not
    ///   hold.
    /// - [`Error::Core`] if a stored object does not parse, or if the xattr
    ///   set with a label is not valid.
    /// - [`Error::Core`] if a `[core]` or `[archive]` value in the repository
    ///   config is malformed.
    /// - [`Error::Io`] if a file system operation fails, for example if the
    ///   walk root is not a directory.
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
        // The walk root asks for no parent descriptor. The directory above it
        // can be unreadable or outside the tree that the caller names. A
        // failure to open it then fails a commit that works otherwise.
        walk_dir(self, root_fd, mtree, modifier, "/".to_owned(), None, false).await?;

        if flags.contains(CommitModifierFlags::CONSUME) {
            remove_walk_root(dfd, path);
        }
        Ok(())
    }
}

/// Methods that read a committed tree into a mutable tree.
impl Transaction {
    /// Merges the committed tree of `dirtree` and `dirmeta` into `mtree`.
    ///
    /// The merge obeys the rules of
    /// [`write_dfd_to_mtree`](Transaction::write_dfd_to_mtree), so a committed
    /// tree and a walk of the file system can build one tree under one
    /// modifier. `dirmeta` becomes the dirmeta of `mtree`. A directory merges
    /// with a directory of the same name, and a file replaces a file of the
    /// same name.
    ///
    /// If `modifier` is `None`, the merge records the committed checksums
    /// unchanged. It reads only the dirtrees on the paths where `mtree`
    /// already holds a directory. It records each other subdirectory with no
    /// read.
    ///
    /// If `modifier` is set, the merge reads each entry and applies the steps
    /// of the modifier to its metadata, in the order that
    /// [`write_dfd_to_mtree`](Transaction::write_dfd_to_mtree) states. If the
    /// result differs from the stored metadata, the merge writes a new object
    /// from the stored payload. Otherwise it records the stored checksum. The
    /// merge does not use `CONSUME`, `GENERATE_SIZES`, `DEVINO_CANONICAL`, or
    /// the devino cache.
    ///
    /// The transaction can write `ostree.sizes` in an `archive` repository
    /// after a call to [`begin_tree_source`](Transaction::begin_tree_source).
    /// Then each object of the committed tree enters the scope of that key,
    /// also an object that the merge does not write.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if `dirtree`, `dirmeta`, or an object that
    ///   the merge reads is not in the repository.
    /// - [`Error::ReplaceDirWithFile`] if a file of the committed tree has the
    ///   name of a directory in `mtree`.
    /// - [`Error::ReplaceFileWithDir`] if a directory of the committed tree has
    ///   the name of a file in `mtree`.
    /// - [`Error::InvalidFormat`] if the label callback returns no label and
    ///   [`ERROR_ON_UNLABELED`](CommitModifierFlags::ERROR_ON_UNLABELED) is
    ///   set.
    /// - [`Error::InvalidFormat`] if a stored file object does not have the
    ///   form of the repository mode.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::Unsupported`] if the merge writes an object and the
    ///   repository mode is `bare-split-xattrs`.
    /// - [`Error::Unsupported`] if `[ex-integrity] fsverity` is `yes` and the
    ///   fs-verity seal of an object fails.
    /// - [`Error::InsufficientFreeSpace`] if an object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] if a stored object does not parse, or if the xattr
    ///   set with a label is not valid.
    /// - [`Error::Core`] if a `[core]` or `[archive]` value in the repository
    ///   config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn overlay_tree_to_mtree(
        &self,
        dirtree: &ostrya_core::Checksum,
        dirmeta: &ostrya_core::Checksum,
        mtree: &mut MutableTree,
        modifier: Option<&mut CommitModifier>,
    ) -> Result<()> {
        // A committed source adds its objects to `ostree.sizes`, also where
        // the overlay records the stored checksums and writes nothing.
        if self.size_scoped() && self.generate_sizes() && self.repo().mode().is_archive() {
            note_tree_scope(self, *dirtree, *dirmeta).await?;
        }
        overlay_dir(self, *dirtree, *dirmeta, mtree, modifier, "/".to_owned()).await
    }
}

/// Records each object of a committed tree in the `ostree.sizes` scope of the
/// transaction.
///
/// The commit limits the scope to the objects that its root reaches. A part
/// of the tree that a later source replaces leaves the key again.
async fn note_tree_scope(
    txn: &Transaction,
    dirtree: ostrya_core::Checksum,
    dirmeta: ostrya_core::Checksum,
) -> Result<()> {
    let repo = txn.repo().clone();
    txn.note_size_scope(dirmeta, ostrya_core::ObjectType::DirMeta);
    let mut stack = vec![dirtree];
    while let Some(checksum) = stack.pop() {
        if !txn.note_size_scope(checksum, ostrya_core::ObjectType::DirTree) {
            continue;
        }
        let loaded = repo.load_dirtree(&checksum).await?;
        for (_, file) in loaded.files {
            txn.note_size_scope(file, ostrya_core::ObjectType::File);
        }
        for (_, subtree, submeta) in loaded.dirs {
            txn.note_size_scope(submeta, ostrya_core::ObjectType::DirMeta);
            stack.push(subtree);
        }
    }
    Ok(())
}

/// Merges one committed directory into `node`, as
/// [`Transaction::overlay_tree_to_mtree`] states.
fn overlay_dir<'a>(
    txn: &'a Transaction,
    dirtree: ostrya_core::Checksum,
    dirmeta: ostrya_core::Checksum,
    node: &'a mut MutableTree,
    mut modifier: Option<&'a mut CommitModifier>,
    path: String,
) -> WalkFuture<'a> {
    Box::pin(async move {
        let repo = txn.repo().clone();
        let flags = modifier
            .as_deref()
            .map_or(CommitModifierFlags::empty(), |m| m.flags);
        let owner = Owner::of(modifier.as_deref());

        // The metadata of the directory goes to the callbacks as the walk root
        // of a file system walk does: adjusted, then finalized, and never
        // filtered.
        let written = if modifier.is_none() {
            dirmeta
        } else {
            let meta = repo.load_dirmeta(&dirmeta).await?;
            let base = FileMeta {
                uid: meta.uid,
                gid: meta.gid,
                mode: meta.mode,
                xattrs: meta.xattrs,
            };
            let adjusted = adjust_meta(flags, owner, base, false);
            let meta = finalize_meta(modifier.as_deref_mut(), Path::new(&path), adjusted)?;
            txn.write_dirmeta(&to_dirmeta(&meta)).await?
        };
        node.set_metadata_checksum(written);

        let loaded = repo.load_dirtree(&dirtree).await?;
        for (name, checksum) in loaded.files {
            let entry_path = join_path(&path, &name);
            match overlay_file(txn, modifier.as_deref_mut(), &entry_path, checksum).await? {
                Some(checksum) => node.replace_file(&name, checksum)?,
                None => continue,
            }
        }
        for (name, child_dirtree, child_dirmeta) in loaded.dirs {
            let entry_path = join_path(&path, &name);
            if let Some(m) = modifier.as_deref_mut()
                && m.filter.is_some()
            {
                let meta = repo.load_dirmeta(&child_dirmeta).await?;
                let base = FileMeta {
                    uid: meta.uid,
                    gid: meta.gid,
                    mode: meta.mode,
                    xattrs: meta.xattrs,
                };
                let adjusted = adjust_meta(flags, owner, base, false);
                let filter = m.filter.as_mut().expect("the filter was just seen");
                if filter(Path::new(&entry_path), &adjusted) == FilterResult::Skip {
                    txn.note_filtered();
                    continue;
                }
            }
            // If the destination does not hold the subdirectory and no
            // modifier is set, the merge records it unread. Each other
            // subdirectory merges entry by entry.
            if modifier.is_none()
                && matches!(node.child_kind(&name), crate::mtree::ChildKind::Absent)
            {
                node.insert_lazy_dir(&name, child_dirtree, child_dirmeta, &repo)?;
                continue;
            }
            let child = node.ensure_dir(&name).await?;
            overlay_dir(
                txn,
                child_dirtree,
                child_dirmeta,
                child,
                modifier.as_deref_mut(),
                entry_path,
            )
            .await?;
        }
        Ok(())
    })
}

/// Applies the modifier to one committed file or symlink of an overlay.
///
/// The result is one of these:
///
/// - `None` if the filter of the modifier skips the entry.
/// - The stored checksum if the shaped metadata equals the stored metadata.
/// - The checksum of a new object, written from the stored payload, in each
///   other case.
async fn overlay_file(
    txn: &Transaction,
    mut modifier: Option<&mut CommitModifier>,
    path: &str,
    checksum: ostrya_core::Checksum,
) -> Result<Option<ostrya_core::Checksum>> {
    if modifier.is_none() {
        return Ok(Some(checksum));
    }
    let stored = txn.repo().load_file(&checksum).await?;
    let flags = modifier
        .as_deref()
        .map_or(CommitModifierFlags::empty(), |m| m.flags);
    let owner = Owner::of(modifier.as_deref());
    let is_symlink = stored.is_symlink();
    let adjusted = adjust_meta(flags, owner, stored.meta(), is_symlink);

    if let Some(m) = modifier.as_deref_mut()
        && let Some(filter) = &mut m.filter
        && filter(Path::new(path), &adjusted) == FilterResult::Skip
    {
        txn.note_filtered();
        return Ok(None);
    }

    let meta = finalize_meta(modifier, Path::new(path), adjusted)?;
    if meta_eq(&meta, &stored.meta()) {
        return Ok(Some(checksum));
    }
    let written = match &stored.kind {
        crate::file::FileKind::Symlink { target } => {
            let target = target.clone();
            txn.write_symlink(&target, &meta, None).await?
        }
        crate::file::FileKind::Regular { .. } => {
            let reader = stored.reader().await?;
            txn.write_content(None, &meta, reader).await?
        }
    };
    Ok(Some(written))
}

/// One directory entry that a blocking snapshot reads.
struct EntryInfo {
    name: String,
    kind: EntryKind,
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    /// The full `st_mode`, including the file-type bits.
    mode: u32,
    /// The `st_size` that the walk read. It limits the read-ahead of a regular
    /// file.
    size: u64,
    xattrs: Xattrs,
}

/// The kind of object that an entry becomes.
enum EntryKind {
    Dir,
    Regular,
    Symlink(String),
}

/// The metadata of a directory and its entries, read in one blocking pass.
struct DirSnapshot {
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: Xattrs,
    entries: Vec<EntryInfo>,
}

/// The boxed future of the recursive post-order walk.
///
/// Async recursion needs indirection, so each level returns a boxed future.
type WalkFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// The boxed future of one level of the file system walk.
///
/// If the caller asks for the descriptor of the parent directory, the result
/// holds it. Otherwise the result is `None`.
type WalkDirFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<OwnedFd>>> + Send + 'a>>;

/// Ingests one directory: writes its dirmeta onto `node`, then ingests each
/// entry.
///
/// `dir_meta` holds the fully adjusted metadata of this directory. The parent
/// computes it once, so the user callbacks run once for each directory. It is
/// `None` only for the walk root, which has no parent. The function adjusts
/// the metadata of the walk root itself.
///
/// If `needs_parent` is set, the function closes `dir_fd` and returns the
/// descriptor of the directory above, opened through `..`. This keeps the walk
/// to at most two directory descriptors at any depth of the source.
fn walk_dir<'a>(
    txn: &'a Transaction,
    dir_fd: OwnedFd,
    node: &'a mut MutableTree,
    mut modifier: Option<&'a mut CommitModifier>,
    path: String,
    dir_meta: Option<FileMeta>,
    needs_parent: bool,
) -> WalkDirFuture<'a> {
    Box::pin(async move {
        let mut dir_fd = dir_fd;
        let flags = modifier
            .as_deref()
            .map_or(CommitModifierFlags::empty(), |m| m.flags);
        let owner = Owner::of(modifier.as_deref());
        let skip_xattrs = flags.contains(CommitModifierFlags::SKIP_XATTRS);

        // The large work of each directory runs on the blocking pool in one
        // pass.
        let snap = {
            let dir = dir_fd.as_fd().try_clone_to_owned()?;
            ostrya_rt::unblock(move || snapshot_dir(dir.as_fd(), skip_xattrs)).await?
        };

        // The metadata of this directory becomes the dirmeta of `node`. The
        // walk root is adjusted here. A nested directory uses the metadata
        // that its parent computed.
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

            // Under DEVINO_CANONICAL, a cache hit is the whole identity of the
            // entry. The walk skips the filter and each callback for it, and
            // does not open or read the file. A directory is never one end of
            // a hardlink pair with an object. The walk looks up only the two
            // content kinds in the cache.
            if !matches!(entry.kind, EntryKind::Dir)
                && let Some(checksum) =
                    canonical_devino_hit(txn, modifier.as_deref(), entry.dev, entry.ino)
            {
                node.replace_file(&entry.name, checksum)?;
                if consume {
                    unlink(dir_fd.as_fd(), &entry.name, false)?;
                }
                continue;
            }

            // The canonical permissions cost little and are deterministic, and
            // the filter gets them. The user callbacks run only for the entries
            // that the filter keeps.
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
                // A consuming walk empties the source, also the entries that
                // the filter keeps out of the commit. If a skipped entry
                // stays, the source stays half removed, and the removal of its
                // directory fails.
                if consume {
                    remove_tree(
                        dir_fd.as_fd(),
                        &entry.name,
                        matches!(entry.kind, EntryKind::Dir),
                    )?;
                }
                continue;
            }

            // Without the flag, a cache hit also prevents the read. The stored
            // object supplies the metadata that the modifier shapes. The walk
            // writes the object again from the stored payload only if the
            // shaped metadata differs from it.
            if !matches!(entry.kind, EntryKind::Dir)
                && let Some(cached) = devino_lookup(modifier.as_deref(), entry.dev, entry.ino)
            {
                let checksum = commit_cached_entry(
                    txn,
                    modifier.as_deref_mut(),
                    &cb_path,
                    flags,
                    owner,
                    cached,
                )
                .await?;
                node.replace_file(&entry.name, checksum)?;
                if consume {
                    unlink(dir_fd.as_fd(), &entry.name, false)?;
                }
                continue;
            }

            match entry.kind {
                EntryKind::Regular => {
                    let meta =
                        finalize_meta(modifier.as_deref_mut(), Path::new(&cb_path), filter_meta)?;
                    let fd = rustix::fs::openat(
                        dir_fd.as_fd(),
                        entry.name.as_str(),
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?;
                    let reader = FileReader::with_len_hint(fd.into(), entry.size);
                    let checksum = txn.write_content(None, &meta, reader).await?;
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
                    // The walk closes the descriptor of this level before the
                    // descent and gets it back, opened again through `..`.
                    // The walk holds at most two directory descriptors at a
                    // time, at any depth below it.
                    drop(dir_fd);
                    let parent = walk_dir(
                        txn,
                        child_fd,
                        child,
                        modifier.as_deref_mut(),
                        cb_path,
                        Some(meta),
                        true,
                    )
                    .await?;
                    dir_fd = parent.expect("the descent was asked for the parent descriptor");
                    if consume {
                        unlink(dir_fd.as_fd(), &entry.name, true)?;
                    }
                }
            }
        }

        if !needs_parent {
            return Ok(None);
        }
        let parent = open_dir(dir_fd.as_fd(), "..")?;
        drop(dir_fd);
        Ok(Some(parent))
    })
}

/// Returns the devino-cache checksum of `(dev, ino)`, if a cache is attached.
fn devino_lookup(
    modifier: Option<&CommitModifier>,
    dev: u64,
    ino: u64,
) -> Option<ostrya_core::Checksum> {
    modifier?.devino_cache.as_ref()?.get(dev, ino)
}

/// Returns the devino-cache checksum of `(dev, ino)`, if the cache is present
/// and [`DEVINO_CANONICAL`](CommitModifierFlags::DEVINO_CANONICAL) is set.
///
/// The statistics of the transaction count a hit.
fn canonical_devino_hit(
    txn: &Transaction,
    modifier: Option<&CommitModifier>,
    dev: u64,
    ino: u64,
) -> Option<ostrya_core::Checksum> {
    let m = modifier?;
    if !m.flags.contains(CommitModifierFlags::DEVINO_CANONICAL) {
        return None;
    }
    let checksum = devino_lookup(modifier, dev, ino)?;
    txn.note_devino_hit();
    Some(checksum)
}

/// Commits the entry of a devino-cache hit, with the modifier applied to the
/// metadata of the stored object.
///
/// The stored metadata replaces the metadata of the source entry. A checkout
/// artifact that the object store puts on the file never enters the commit.
/// An example is the `user.ostreemeta` xattr of a `bare-user` object.
///
/// If the shaped metadata equals the stored metadata, the function returns the
/// cached checksum and counts the hit. Otherwise it writes a new object from
/// the stored payload. The function does not read the source entry in either
/// case.
async fn commit_cached_entry(
    txn: &Transaction,
    modifier: Option<&mut CommitModifier>,
    path: &str,
    flags: CommitModifierFlags,
    owner: Owner,
    cached: ostrya_core::Checksum,
) -> Result<ostrya_core::Checksum> {
    let stored = txn.repo().load_file(&cached).await?;
    let base = stored.meta();
    let is_symlink = stored.is_symlink();
    let adjusted = adjust_meta(flags, owner, base, is_symlink);
    let meta = finalize_meta(modifier, Path::new(path), adjusted)?;
    if meta_eq(&meta, &stored.meta()) {
        txn.note_devino_hit();
        return Ok(cached);
    }
    match &stored.kind {
        crate::file::FileKind::Symlink { target } => {
            let target = target.clone();
            txn.write_symlink(&target, &meta, None).await
        }
        crate::file::FileKind::Regular { .. } => {
            let reader = stored.reader().await?;
            txn.write_content(None, &meta, reader).await
        }
    }
}

/// Returns `true` if two metadata sets record the same object header.
fn meta_eq(a: &FileMeta, b: &FileMeta) -> bool {
    a.uid == b.uid && a.gid == b.gid && a.mode == b.mode && a.xattrs == b.xattrs
}

/// Applies the metadata adjustments of a modifier that cost little and are
/// deterministic.
///
/// The order is the
/// [`CANONICAL_PERMISSIONS`](CommitModifierFlags::CANONICAL_PERMISSIONS)
/// reduction, the [`SKIP_XATTRS`](CommitModifierFlags::SKIP_XATTRS) drop, and
/// then the declared ownership. The function runs no user callbacks. A walk
/// without a modifier has the empty flag set and no declared ownership, so the
/// function changes nothing for it.
///
/// Under `CANONICAL_PERMISSIONS`, the owner becomes 0:0 and the xattr set
/// becomes empty. The permission bits of a regular file or a directory become
/// `perm & 0o755`. The object model fixes the mode of a symlink, so the
/// reduction does not change it.
///
/// `SKIP_XATTRS` empties the xattr set and keeps the mode and the ownership.
/// Each of the two flags empties the set here, before the callbacks, so a
/// callback that supplies xattrs or an SELinux label still adds them.
///
/// The xattr drop is at this one site, so it applies to each source that the
/// modifier shapes:
///
/// - The file system walk. Its set is already empty.
/// - An overlay of a committed tree, with the set of the stored object.
/// - A devino-cache hit, with the set of the stored object.
///
/// The tar importer sets the xattr set of the archive again after this call.
/// For this reason, `TarImportOptions::skip_xattrs` drops the set in the tar
/// importer.
///
/// The filter and the mode callback get the mode that this function returns.
/// The entry records the mode that `canonical_mode` returns for the result of
/// the callback, because the reduction is the last step of the modifier order.
///
/// The declared ownership comes last in this function. If a modifier states an
/// id and the canonical flag, the entry records the id.
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
    if flags.contains(CommitModifierFlags::SKIP_XATTRS) {
        meta.xattrs = Xattrs::empty();
    }
    owner.apply(&mut meta);
    meta
}

/// Returns the canonical permission reduction of the mode of one entry.
///
/// The result is the file type that the walk found, and `perm & 0o755`. The
/// object model fixes the mode of a symlink, so the function returns it
/// unchanged.
///
/// The type comes from `entry_type`. A mode callback can name a file type of
/// its own, as a `--statoverride` value with bits in the file-type field does.
/// The entry then stays the kind that the walk found.
fn canonical_mode(entry_type: u32, mode: u32) -> u32 {
    if entry_type == S_IFLNK {
        mode
    } else {
        entry_type | (mode & CANONICAL_PERM_MASK)
    }
}

/// Applies the mode callback, the canonical permission reduction, the xattr
/// callback, and the SELinux label hook, in that order.
///
/// The function runs the user callbacks, so it runs once for each committed
/// entry. It runs after the filter. For a devino-cache hit, it runs on the
/// stored metadata.
///
/// The reduction comes after the mode callback because the `ostree` command
/// applies this order: `--mode-ro-executables`, then `--statoverride`, then
/// `--canonical-permissions`. The CLI puts the first two in the mode callback.
/// Each of the first two is an AND mask or an OR. Only `--statoverride` gives
/// a different result if the reduction comes first.
fn apply_callbacks(m: &mut CommitModifier, path: &Path, mut meta: FileMeta) -> Result<FileMeta> {
    let entry_type = meta.mode & S_IFMT;
    if let Some(callback) = &mut m.mode_callback {
        meta.mode = callback(path, &meta);
    }

    if m.flags.contains(CommitModifierFlags::CANONICAL_PERMISSIONS) {
        meta.mode = canonical_mode(entry_type, meta.mode);
    }

    if let Some(callback) = &mut m.xattr_callback {
        meta.xattrs = callback(path, &meta);
    }

    if let Some(callback) = &mut m.label_callback {
        // Drop a label that the entry holds, so the label of the callback
        // counts only once.
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

/// Runs the user callbacks of the modifier on `meta`.
///
/// If no modifier is attached, the function returns `meta` unchanged.
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

/// Returns the directory-metadata object for the adjusted metadata of an entry.
pub(crate) fn to_dirmeta(meta: &FileMeta) -> DirMeta {
    DirMeta {
        uid: meta.uid,
        gid: meta.gid,
        mode: meta.mode,
        xattrs: meta.xattrs.clone(),
    }
}

/// Reads the metadata of a directory and all of its entries in one blocking
/// pass.
///
/// If `skip_xattrs` is not set, the function reads the xattrs of each entry.
/// It reads the xattrs of a symlink with no-follow, from the link itself.
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
            size: stat.st_size as u64,
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

/// Reads the xattrs of an entry, no-follow.
///
/// The function opens a regular file or a directory and reads from its fd. A
/// symlink cannot give an fd, so the function reads its xattrs with the
/// path-based no-follow reader.
fn read_entry_xattrs(dir: BorrowedFd<'_>, name: &str, kind: &EntryKind) -> Result<Xattrs> {
    let oflags = match kind {
        EntryKind::Regular => OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        EntryKind::Dir => OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        EntryKind::Symlink(_) => return crate::object::read_link_xattrs(dir, name),
    };
    let fd = rustix::fs::openat(dir, name, oflags, Mode::empty())?;
    crate::object::read_all_xattrs(fd.as_fd())
}

/// Opens the walk root relative to `dfd`.
///
/// An empty path or `.` opens `dfd` itself. The function opens each other path
/// no-follow, so it does not follow a symlink at the root.
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

/// Removes the walk-root directory after a consuming walk.
///
/// The test is on the bytes of the path. If the path is exactly `.`, the
/// function keeps the root. It removes the root for each other spelling, `./`
/// included. This is the rule of `ostree commit --consume`.
///
/// The CLI opens each source and removes its own walk root, so this function
/// runs only for a caller of the library API. The function ignores a failed
/// removal for these reasons:
///
/// - If the root is already removed, nothing is left to remove.
/// - An empty path names `dfd` itself.
/// - The kernel refuses a path whose last component is `.`.
fn remove_walk_root(dfd: BorrowedFd<'_>, path: &Path) {
    if path.as_os_str().as_bytes() == b"." {
        return;
    }
    let _ = rustix::fs::unlinkat(dfd, path, AtFlags::REMOVEDIR);
}

/// Unlinks an entry from a directory: a file, or a directory with
/// `AT_REMOVEDIR`.
///
/// The error of a failed removal names the entry, as the `ostree` command
/// reports it.
fn unlink(dir: BorrowedFd<'_>, name: &str, is_dir: bool) -> Result<()> {
    let flags = if is_dir {
        AtFlags::REMOVEDIR
    } else {
        AtFlags::empty()
    };
    rustix::fs::unlinkat(dir, name, flags).map_err(|err| unlink_error(name, err))
}

/// Removes `name` under `dir` and all entries below it.
///
/// A consuming walk uses it for an entry that the filter keeps out of the
/// commit. The walk does not visit the children of such an entry, so it does
/// not remove them one by one.
///
/// The removal is a loop over an explicit stack of levels. One descriptor is
/// open at a time. A descent replaces the descriptor of the level with the
/// descriptor of the child. An ascent replaces it with the descriptor that
/// `..` opens. `..` names the parent because the emptied level is still linked
/// where it was opened.
///
/// Each level costs a name and an entry list on the heap. The function can
/// remove a subtree that is deeper than the descriptor limit of the process.
fn remove_tree(dir: BorrowedFd<'_>, name: &str, is_dir: bool) -> Result<()> {
    if !is_dir {
        return unlink(dir, name, false);
    }
    let mut level = open_dir(dir, name).map_err(|err| unlink_error(name, err))?;
    // One entry for each level from `name` to the current level: the name of
    // the level, and the entries left to remove in it.
    let mut levels = vec![(name.to_owned(), read_level(level.as_fd(), name)?)];

    while let Some((_, entries)) = levels.last_mut() {
        match entries.pop() {
            Some((child, false)) => unlink(level.as_fd(), &child, false)?,
            Some((child, true)) => {
                let child_fd =
                    open_dir(level.as_fd(), &child).map_err(|err| unlink_error(&child, err))?;
                let child_entries = read_level(child_fd.as_fd(), &child)?;
                level = child_fd;
                levels.push((child, child_entries));
            }
            None => {
                let (cleared, _) = levels.pop().expect("a level is in hand within the loop");
                if levels.is_empty() {
                    drop(level);
                    return unlink(dir, &cleared, true);
                }
                level = open_dir(level.as_fd(), "..").map_err(|err| unlink_error(&cleared, err))?;
                unlink(level.as_fd(), &cleared, true)?;
            }
        }
    }
    Ok(())
}

/// Opens `name` under `dir` as a directory, no-follow.
fn open_dir(dir: BorrowedFd<'_>, name: &str) -> std::result::Result<OwnedFd, Errno> {
    rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Returns the entries of one directory level, each with a flag that is `true`
/// for a directory.
///
/// `name` is the name of the level. The error of a failed read names it.
fn read_level(level: BorrowedFd<'_>, name: &str) -> Result<Vec<(String, bool)>> {
    let mut entries = Vec::new();
    for entry in Dir::read_from(level).map_err(|err| unlink_error(name, err))? {
        let entry = entry.map_err(|err| unlink_error(name, err))?;
        let child_name = entry.file_name();
        if child_name == c"." || child_name == c".." {
            continue;
        }
        let child_name = child_name
            .to_str()
            .map_err(|_| Error::InvalidFormat("directory entry name is not valid UTF-8".into()))?
            .to_owned();
        let stat = rustix::fs::statat(level, child_name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|err| unlink_error(&child_name, err))?;
        let child_is_dir = FileType::from_raw_mode(stat.st_mode) == FileType::Directory;
        entries.push((child_name, child_is_dir));
    }
    Ok(entries)
}

/// Returns the error of a failed removal: the name of the entry and the
/// reason, in the words of the `ostree` command.
fn unlink_error(name: &str, err: Errno) -> Error {
    let reason = std::io::Error::from(err).to_string();
    let reason = match reason.find(" (os error ") {
        Some(cut) => reason[..cut].to_owned(),
        None => reason,
    };
    Error::ConsumeUnlink {
        name: name.to_owned(),
        reason,
    }
}

/// Joins a walk path and an entry name into the path for a modifier callback.
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

    /// A temporary directory that the drop removes.
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

    /// `GENERATE_SIZES` marks the transaction, so the commit can write
    /// `ostree.sizes`.
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

            // Outside archive mode, GENERATE_SIZES does nothing and gives no
            // message. The mark stays unset, so the commit writes no empty
            // `ostree.sizes`.
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
