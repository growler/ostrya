//! Filesystem ingest: walking an on-disk tree into a [`MutableTree`].
//!
//! [`Transaction::write_dfd_to_mtree`] walks the directory tree rooted at a
//! path relative to a directory fd, ingesting its contents through the object
//! writers (in [`crate::write`]) and recording them in a
//! [`MutableTree`](crate::MutableTree). A [`CommitModifier`] shapes the walk:
//! canonical permissions, declared ownership, an include/prune filter, a
//! mode-replacing callback, an xattr-replacing callback, an SELinux label hook,
//! a devino cache, and source consumption.
//!
//! The walk reads each directory in one offloaded blocking pass (fd-relative
//! `Dir` iteration, `statat` per entry, xattr reads, `readlinkat`), then
//! ingests the entries: regular-file payloads stream through
//! [`write_content`](crate::Transaction::write_content) over an `rt::File`,
//! symlinks and per-directory metadata go through the metadata writers. The
//! per-entry namespace syscalls that open, unlink, and recurse are issued
//! inline, keeping the offload at per-directory granularity.
//!
//! [`Transaction::overlay_tree_to_mtree`] ingests a committed tree the same
//! way, so a tree already in the repository composes with a filesystem walk
//! under one modifier. Without a modifier it copies the committed checksums
//! and reads only the dirtrees along the paths it merges.

use std::future::Future;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
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
/// The symlink file-type bits of an `st_mode`.
const S_IFLNK: u32 = 0o120000;
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
        // The walk root is asked for no parent descriptor: the directory above
        // it can be unreadable or outside the tree the caller named, and a
        // failure to open it would fail a commit that otherwise works.
        walk_dir(self, root_fd, mtree, modifier, "/".to_owned(), None, false).await?;

        if flags.contains(CommitModifierFlags::CONSUME) {
            remove_walk_root(dfd, path);
        }
        Ok(())
    }
}

impl Transaction {
    /// Overlay the committed tree named by `dirtree` and `dirmeta` onto
    /// `mtree`, shaped by `modifier`.
    ///
    /// The composition rule is the one [`write_dfd_to_mtree`](Transaction::write_dfd_to_mtree)
    /// follows: directories merge, this tree's directory metadata replaces
    /// what the destination held, and this tree's files replace files of the
    /// same name. A name that is a directory on one side and a file on the
    /// other is an error.
    ///
    /// With no modifier the committed checksums are reused as they are, and a
    /// subdirectory the destination does not hold is recorded without being
    /// read. With a modifier every entry is read, its metadata is shaped, and
    /// a content object whose shaped metadata differs from the stored one is
    /// written again from the stored payload.
    pub async fn overlay_tree_to_mtree(
        &self,
        dirtree: &ostrya_core::Checksum,
        dirmeta: &ostrya_core::Checksum,
        mtree: &mut MutableTree,
        modifier: Option<&mut CommitModifier>,
    ) -> Result<()> {
        // A committed source contributes its objects to `ostree.sizes` even
        // where the overlay reuses the stored checksums and writes nothing.
        if self.size_scoped() && self.generate_sizes() && self.repo().mode().is_archive() {
            note_tree_scope(self, *dirtree, *dirmeta).await?;
        }
        overlay_dir(self, *dirtree, *dirmeta, mtree, modifier, "/".to_owned()).await
    }
}

/// Record every object of a committed tree in the transaction's `ostree.sizes`
/// scope. The commit narrows the scope to the objects its root reaches, so a
/// part of the tree a later source replaces leaves the key again.
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

/// Overlay one committed directory onto `node`. See
/// [`Transaction::overlay_tree_to_mtree`].
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

        // The directory's own metadata reaches the callbacks the way the
        // filesystem walk's root does: adjusted, then finalized, never
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
            // A subdirectory the destination does not hold and no modifier
            // shapes is recorded unread; anything else is merged entry by
            // entry.
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

/// Shape one committed file or symlink for an overlay: `None` where the
/// modifier's filter skips it, the stored checksum where the shaped metadata
/// equals the stored metadata, and a fresh object written from the stored
/// payload otherwise.
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

/// The boxed future for one level of the filesystem walk. Its result carries
/// the parent directory's descriptor where the caller asked for it, and `None`
/// where it did not.
type WalkDirFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<OwnedFd>>> + Send + 'a>>;

/// Ingest one directory: write its dirmeta onto `node`, then ingest each entry.
///
/// `dir_meta` carries this directory's fully adjusted metadata, computed once by
/// the parent so the user callbacks fire once per directory. It is `None` only
/// for the walk root, which has no parent and is adjusted here.
///
/// `needs_parent` states whether the caller wants its own directory back. Where
/// it is set, `dir_fd` is released and the descriptor of the directory above,
/// opened through `..`, is returned in its place. This is what keeps the walk
/// to at most two directory descriptors whatever the depth of the source.
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

            // Under DEVINO_CANONICAL a cache hit is the entry's whole identity:
            // the filter and every callback are skipped for it and the file is
            // neither opened nor read. A directory is never one end of a
            // hardlink pair with an object, so only the two content kinds are
            // offered to the cache.
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

            // Canonical permissions are cheap and deterministic and feed the
            // filter; the user callbacks run only for entries that survive the
            // filter.
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
                // A consuming walk empties the source whatever the filter kept
                // out of the commit, so a skipped entry is removed too. Leaving
                // it would strand the source half-deleted and fail the removal
                // of the directory that holds it.
                if consume {
                    remove_tree(
                        dir_fd.as_fd(),
                        &entry.name,
                        matches!(entry.kind, EntryKind::Dir),
                    )?;
                }
                continue;
            }

            // Without the flag a cache hit still spares the read: the stored
            // object supplies the metadata the modifier shapes, and the object
            // is rewritten from the stored payload only where the shaped
            // metadata differs from it.
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
                    // This level's descriptor is released before the descent
                    // and comes back reopened through `..`, so the walk holds
                    // at most two directory descriptors at any instant,
                    // whatever the depth below it.
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

/// The devino-cache checksum for `(dev, ino)`, when a cache is attached.
fn devino_lookup(
    modifier: Option<&CommitModifier>,
    dev: u64,
    ino: u64,
) -> Option<ostrya_core::Checksum> {
    modifier?.devino_cache.as_ref()?.get(dev, ino)
}

/// A devino-cache checksum for `(dev, ino)`, when the cache is present and
/// [`DEVINO_CANONICAL`](CommitModifierFlags::DEVINO_CANONICAL) is set. A hit is
/// counted in the transaction statistics.
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

/// Commit the entry a devino-cache hit resolved, with the modifier applied over
/// the stored object's own metadata.
///
/// The stored metadata replaces what the source entry carries, so a checkout
/// artifact the object store puts on the file -- a `bare-user` object's
/// `user.ostreemeta` xattr, say -- never enters the commit. Where the shaped
/// metadata equals the stored metadata the object is reused and the hit is
/// counted; otherwise a new object is written from the stored payload, which
/// still spares reading the source entry.
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

/// Whether two metadata sets record the same object header.
fn meta_eq(a: &FileMeta, b: &FileMeta) -> bool {
    a.uid == b.uid && a.gid == b.gid && a.mode == b.mode && a.xattrs == b.xattrs
}

/// Apply the cheap, deterministic metadata adjustments a modifier states: the
/// [`CANONICAL_PERMISSIONS`](CommitModifierFlags::CANONICAL_PERMISSIONS)
/// reduction, the [`SKIP_XATTRS`](CommitModifierFlags::SKIP_XATTRS) drop, then
/// the declared ownership. Runs no user callbacks. A walk without a modifier
/// carries the empty flag set and no declared ownership, making this a no-op.
///
/// Under `CANONICAL_PERMISSIONS` the owner becomes 0:0, the xattr set is
/// emptied, and a regular file's or directory's permission bits become
/// `perm & 0o755`; a symlink's mode is fixed by the object model, so only
/// regular-file and directory bits are canonicalized. `SKIP_XATTRS` empties the
/// xattr set and leaves the mode and the ownership as they stand. Either flag
/// empties the set here, ahead of the callbacks, so a callback that supplies
/// xattrs or an SELinux label still lands them.
///
/// The xattr drop stands at this one site, so it reaches every source the
/// modifier shapes: the filesystem walk arrives with the set already empty, and
/// an overlay of a committed tree and a devino-cache hit arrive with the set the
/// stored object carries. The tar importer restores the archive's own set after
/// this call, which is where `TarImportOptions::skip_xattrs` drops it instead.
///
/// The mode this states is what the filter and the mode callback are shown. The
/// mode the entry records is the one `canonical_mode` states over the
/// callback's own result, the reduction standing last in the modifier order.
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
    if flags.contains(CommitModifierFlags::SKIP_XATTRS) {
        meta.xattrs = Xattrs::empty();
    }
    owner.apply(&mut meta);
    meta
}

/// The canonical permission reduction of one entry's mode: the file type the
/// walk found it with, and `perm & 0o755`. A symlink's mode is fixed by the
/// object model and is returned as it stands.
///
/// The type comes from `entry_type` rather than from `mode`, so a mode callback
/// that names a file type of its own -- what a `--statoverride` value carrying
/// bits inside the file-type field does -- leaves the entry the kind the walk
/// found. See `format-reference.md`, "CLI output formats", `commit`.
fn canonical_mode(entry_type: u32, mode: u32) -> u32 {
    if entry_type == S_IFLNK {
        mode
    } else {
        entry_type | (mode & CANONICAL_PERM_MASK)
    }
}

/// Apply the mode callback, the canonical permission reduction, the xattr
/// callback, and the SELinux label hook, in that order. Runs the user
/// callbacks, so it is invoked once per committed entry: after the filter, and
/// over the stored metadata for an entry a devino-cache hit resolved.
///
/// The reduction stands after the mode callback because that is the order the
/// tool applies: `--mode-ro-executables`, then `--statoverride`, then
/// `--canonical-permissions`, with the CLI carrying the first two in the mode
/// callback. Both of the first two are cheap to state as an AND mask or an OR,
/// and only `--statoverride` breaks commutativity with the reduction.
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

/// Remove the walk-root directory after a consuming walk.
///
/// The test is on the bytes the path carries, so the root is spared where the
/// path is exactly `.` and is removed under every other spelling, `./`
/// included. This is the rule `docs/format-reference.md`, "CLI output
/// formats", `commit` records for `--consume`.
///
/// The CLI opens each source itself and removes its own walk root, so this
/// runs only for a caller that comes through the library API. A removal that
/// fails is ignored: a root already gone leaves nothing to remove, an empty
/// path names `dfd` itself, and the kernel refuses a path whose last component
/// is `.`.
fn remove_walk_root(dfd: BorrowedFd<'_>, path: &Path) {
    if path.as_os_str().as_bytes() == b"." {
        return;
    }
    let _ = rustix::fs::unlinkat(dfd, path, AtFlags::REMOVEDIR);
}

/// Unlink an entry from a directory: a file, or a directory with `AT_REMOVEDIR`.
///
/// A removal that fails names the entry, which is how the tool reports it.
fn unlink(dir: BorrowedFd<'_>, name: &str, is_dir: bool) -> Result<()> {
    let flags = if is_dir {
        AtFlags::REMOVEDIR
    } else {
        AtFlags::empty()
    };
    rustix::fs::unlinkat(dir, name, flags).map_err(|err| unlink_error(name, err))
}

/// Remove `name` under `dir` and everything below it. A consuming walk uses it
/// for an entry the filter kept out of the commit, whose children were never
/// visited and so were never removed one by one.
///
/// The removal is a loop over an explicit stack of levels, and one descriptor
/// stands open at a time: descending replaces the level's descriptor with the
/// child's, and ascending replaces it with the one `..` opens, which names the
/// parent while the emptied level is still linked where it was opened. Depth
/// costs a name and an entry list on the heap, so a subtree deeper than the
/// process descriptor limit is removed whole.
fn remove_tree(dir: BorrowedFd<'_>, name: &str, is_dir: bool) -> Result<()> {
    if !is_dir {
        return unlink(dir, name, false);
    }
    let mut level = open_dir(dir, name).map_err(|err| unlink_error(name, err))?;
    // One entry per level on the path from `name` down to the level in hand:
    // the level's own name, and what is left to remove within it.
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

/// Open `name` under `dir` as a directory, no-follow.
fn open_dir(dir: BorrowedFd<'_>, name: &str) -> std::result::Result<OwnedFd, Errno> {
    rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// The entries of one directory level, each with whether it is a directory.
/// `name` is the level's own name, which a failure to read it reports.
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

/// The error a failed removal reports: the entry's own name and the reason,
/// spelled the way the tool spells it.
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
