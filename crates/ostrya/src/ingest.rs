//! The file system ingest of a transaction.
//!
//! This module reads a tree on disk, or a committed tree, into a
//! `MutableTree`. The docs of `Transaction::write_dfd_to_mtree` and
//! `Transaction::overlay_tree_to_mtree` hold the behavior that a caller sees.
//! The object writers are in `write.rs`.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::future::Future;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use ostrya_core::{DirMeta, RepoMode, Xattrs};
use ostrya_rt::FileReader;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::modifier::{
    CommitModifier, CommitModifierFlags, FilterResult, Owner, with_selinux, without_selinux,
};
use crate::mtree::MutableTree;
use crate::repo_fs::link_xattrs_at;
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
    ///    file or a directory. A symlink keeps its mode. The walk reads no
    ///    xattrs from the disk.
    /// 2. [`SKIP_XATTRS`](CommitModifierFlags::SKIP_XATTRS): the walk reads no
    ///    xattrs from the disk, and the entry has no xattrs.
    /// 3. The declared ownership (`owner_uid` and `owner_gid`).
    /// 4. The filter. It gets the metadata of steps 1 to 3 with no xattrs,
    ///    because the walk reads the xattrs after the filter. If it returns
    ///    [`FilterResult::Skip`], the walk does not open the entry. For a
    ///    directory, the walk skips the whole subtree.
    /// 5. If the filter keeps a regular file or a directory, the walk opens
    ///    it. Unless step 1 or 2 applies, the walk reads the xattrs of the
    ///    entry. For a symlink, it reads them from the link. The walk does
    ///    not open an entry that the devino cache finds, and it does not read
    ///    the xattrs of that entry from the disk.
    /// 6. The mode callback.
    /// 7. The `CANONICAL_PERMISSIONS` reduction again, on the mode that the
    ///    callback returns. The file type stays the type that the walk found.
    ///    A symlink keeps its mode.
    /// 8. The xattr callback.
    /// 9. The SELinux label callback. The walk drops the `security.selinux`
    ///    xattr of the entry, then adds the label that the callback returns.
    ///    If the callback returns no label, the entry has no label.
    ///
    /// Steps 5 to 9 run only for an entry that the filter keeps. The walk root
    /// goes through each step except the filter. The `statat`, the type
    /// check, and the read of a symlink target come before the filter, so a
    /// skipped FIFO or socket still causes an error, and so does a skipped
    /// entry whose `statat` fails. A skipped entry that the walk cannot open
    /// or whose xattrs it cannot read does not cause an error.
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
    /// source entry after it records the entry, and each directory after it
    /// records the directory. Then the call removes the walk root. The walk
    /// does not open or remove an entry that the filter skips. That entry
    /// stays, and each directory that holds it stays, the walk root included.
    ///
    /// The test for the walk root is on the bytes of `path`. If `path` is
    /// exactly `.`, the call keeps the root. For each other spelling, `./`
    /// included, the call tries to remove the root and ignores a failure.
    ///
    /// # File system access
    ///
    /// The walk reads each directory in one pass on the blocking pool. The pass
    /// reads the entry list, the `statat` of each entry, the symlink targets,
    /// and the xattrs of the directory itself. The pass opens no entry. The
    /// walk opens an entry only after the filter keeps it, and the calls that
    /// open and remove entries run on the calling task. The walk reads the
    /// xattrs of a regular file from the descriptor that it opens for the
    /// content, and the xattrs of a symlink from the link itself. A
    /// subdirectory gives its xattrs in its own pass. The walk holds at most
    /// two directory descriptors at a time, at any depth of the source.
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
        let walked = walk_dir(self, root_fd, mtree, modifier, "/".to_owned(), false).await?;

        if flags.contains(CommitModifierFlags::CONSUME) && !walked.skipped {
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
    /// [`write_dfd_to_mtree`](Transaction::write_dfd_to_mtree) states. The
    /// xattrs come from the stored object before the filter, so the filter
    /// gets the xattrs that steps 1 to 3 leave. If the result differs from
    /// the stored metadata, the merge writes a new object from the stored
    /// payload. Otherwise it records the stored checksum. The merge does not
    /// use `CONSUME`, `GENERATE_SIZES`, `DEVINO_CANONICAL`, or the devino
    /// cache.
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
}

/// The kind of object that an entry becomes.
enum EntryKind {
    Dir,
    Regular,
    Symlink(String),
}

/// The metadata of a directory and its entries, read in one blocking pass.
///
/// The xattrs are the xattrs of the directory itself. The pass reads no xattrs
/// of an entry.
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

/// The result of one level of the file system walk.
struct WalkedDir {
    /// The descriptor of the parent directory, if the caller asks for it.
    parent: Option<OwnedFd>,
    /// `true` if the filter skipped an entry in the directory or below it.
    /// A consuming walk then keeps the directory.
    skipped: bool,
}

/// The boxed future of one level of the file system walk.
type WalkDirFuture<'a> = Pin<Box<dyn Future<Output = Result<WalkedDir>> + Send + 'a>>;

/// Ingests one directory: writes its dirmeta onto `node`, then ingests each
/// entry.
///
/// The function reads the metadata and the xattrs of the directory from
/// `dir_fd`, and runs the user callbacks for the directory before it ingests
/// the entries. Thus the callbacks run once for each directory, and before the
/// callbacks of its entries. The parent gives the filter the metadata of the
/// directory, with no xattrs, before it opens the directory.
///
/// For each entry, the function applies the filter before it opens the entry
/// or reads its xattrs. It never opens or removes an entry that the filter
/// skips.
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
    needs_parent: bool,
) -> WalkDirFuture<'a> {
    Box::pin(async move {
        let mut dir_fd = dir_fd;
        let flags = modifier
            .as_deref()
            .map_or(CommitModifierFlags::empty(), |m| m.flags);
        let owner = Owner::of(modifier.as_deref());
        // Each of the two flags empties the xattr set in `adjust_meta`, so the
        // walk reads no xattrs under either.
        let read_xattrs = !flags.contains(CommitModifierFlags::SKIP_XATTRS)
            && !flags.contains(CommitModifierFlags::CANONICAL_PERMISSIONS);

        // The large work of each directory runs on the blocking pool in one
        // pass.
        let snap = {
            let dir = dir_fd.as_fd().try_clone_to_owned()?;
            ostrya_rt::unblock(move || snapshot_dir(dir.as_fd(), read_xattrs)).await?
        };

        // The metadata of this directory becomes the dirmeta of `node`.
        let base = FileMeta {
            uid: snap.uid,
            gid: snap.gid,
            mode: snap.mode,
            xattrs: snap.xattrs,
        };
        let adjusted = adjust_meta(flags, owner, base, false);
        let dir_meta = finalize_meta(modifier.as_deref_mut(), Path::new(&path), adjusted)?;
        let dirmeta = txn.write_dirmeta(&to_dirmeta(&dir_meta)).await?;
        node.set_metadata_checksum(dirmeta);

        let consume = flags.contains(CommitModifierFlags::CONSUME);
        let mut skipped = false;

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
            // the filter gets them. The walk has not opened the entry yet, so
            // the filter gets no xattrs from the disk. The user callbacks run
            // only for the entries that the filter keeps.
            let base = FileMeta {
                uid: entry.uid,
                gid: entry.gid,
                mode: entry.mode,
                xattrs: Xattrs::empty(),
            };
            let filter_meta = adjust_meta(flags, owner, base, is_symlink);

            if let Some(m) = modifier.as_deref_mut()
                && let Some(filter) = &mut m.filter
                && filter(Path::new(&cb_path), &filter_meta) == FilterResult::Skip
            {
                txn.note_filtered();
                // The walk does not open or remove a skipped entry, also under
                // CONSUME. A consuming walk then keeps each directory that
                // holds the entry.
                skipped = true;
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
                    let fd = rustix::fs::openat(
                        dir_fd.as_fd(),
                        entry.name.as_str(),
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?;
                    let mut meta = filter_meta;
                    if read_xattrs {
                        meta.xattrs = read_all_xattrs(fd.as_fd())?;
                    }
                    let meta = finalize_meta(modifier.as_deref_mut(), Path::new(&cb_path), meta)?;
                    let reader = FileReader::with_len_hint(fd.into(), entry.size);
                    let checksum = txn.write_content(None, &meta, reader).await?;
                    node.replace_file(&entry.name, checksum)?;
                    if consume {
                        unlink(dir_fd.as_fd(), &entry.name, false)?;
                    }
                }
                EntryKind::Symlink(target) => {
                    let mut meta = filter_meta;
                    if read_xattrs {
                        // A symlink gives no descriptor, so the walk reads the
                        // xattrs of the link itself by its name.
                        let name = Path::new(&entry.name);
                        meta.xattrs = utf8_names(link_xattrs_at(dir_fd.as_fd(), name)?)?;
                    }
                    let meta = finalize_meta(modifier.as_deref_mut(), Path::new(&cb_path), meta)?;
                    let checksum = txn.write_symlink(&target, &meta, None).await?;
                    node.replace_file(&entry.name, checksum)?;
                    if consume {
                        unlink(dir_fd.as_fd(), &entry.name, false)?;
                    }
                }
                EntryKind::Dir => {
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
                    let walked =
                        walk_dir(txn, child_fd, child, modifier.as_deref_mut(), cb_path, true)
                            .await?;
                    dir_fd = walked
                        .parent
                        .expect("the descent was asked for the parent descriptor");
                    if walked.skipped {
                        skipped = true;
                    } else if consume {
                        unlink(dir_fd.as_fd(), &entry.name, true)?;
                    }
                }
            }
        }

        if !needs_parent {
            return Ok(WalkedDir {
                parent: None,
                skipped,
            });
        }
        let parent = open_dir(dir_fd.as_fd(), "..")?;
        drop(dir_fd);
        Ok(WalkedDir {
            parent: Some(parent),
            skipped,
        })
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
/// If `read_xattrs` is set, the function reads the xattrs of the directory
/// from `dir`. It reads no xattrs of an entry, and it opens no entry. For each
/// entry, it reads the `statat` and the target of a symlink.
fn snapshot_dir(dir: BorrowedFd<'_>, read_xattrs: bool) -> Result<DirSnapshot> {
    let stat = rustix::fs::fstat(dir)?;
    let dir_xattrs = if read_xattrs {
        read_all_xattrs(dir)?
    } else {
        Xattrs::empty()
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

        entries.push(EntryInfo {
            name,
            kind,
            dev: stat.st_dev,
            ino: stat.st_ino,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
            size: stat.st_size as u64,
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
/// The walk does not call the function if the filter skipped an entry. The
/// walk root then holds that entry, or a directory that holds it, and stays.
///
/// The CLI does not set `CONSUME`. It removes each source after the commit
/// with [`remove_source_tree`], so this function runs only for a caller of the
/// library API. The function ignores a failed removal for these reasons:
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

/// Removes the source tree at `path` under `dfd`, with all entries in it,
/// except the entries that `keep` names.
///
/// A caller calls this function after the commit of a directory source, so
/// that the source stays in place if the commit fails. The commit does not
/// need [`CONSUME`](crate::CommitModifierFlags::CONSUME) for it.
///
/// The function removes each entry below `path`, and then the directory at
/// `path`. If the last component of `path` is `.`, for example `.`, `./`, or
/// `a/.`, the function removes the entries and keeps the directory. An empty
/// `path` names `dfd` itself and has the same result as `.`. An absolute
/// `path` ignores `dfd`, so an absolute path to the working directory removes
/// that directory. `dfd` can be [`rustix::fs::CWD`]: then a relative `path`
/// starts at the working directory, and the function needs no read
/// permission on the working directory.
///
/// The function strips trailing slashes from `path` before it opens the
/// directory, and it does not follow a symlink at `path`. A symlink or a file
/// at `path` gives an error, and the function removes nothing. The function
/// removes a symlink in the tree and does not follow it. If nothing is at
/// `path`, the function returns `Ok(())`, because nothing is left to remove.
///
/// # Kept entries
///
/// Each item of `keep` is an in-tree path, as the filter of
/// [`Transaction::write_dfd_to_mtree`](crate::Transaction::write_dfd_to_mtree)
/// gets it: `/` for the directory at `path`, and `/a/b` for the entry `b` in
/// its subdirectory `a`. The test is on the exact bytes. The function does not
/// open, read, or remove an entry that `keep` names, and it keeps each
/// directory that holds such an entry, the directory at `path` included. A
/// directory that `keep` names stays with its whole subtree. If `keep` holds
/// `/`, the function changes nothing and returns `Ok(())`. An item that names
/// no entry has no effect. The set is shared, so a caller can build it once
/// and give a clone of the [`Arc`] to each call.
///
/// # File system access
///
/// The removal runs on the blocking pool. It holds a copy of `dfd`, except
/// for [`rustix::fs::CWD`], and at most two descriptors of the tree: the
/// descriptor of the current directory, and for a short time the descriptor
/// of the next directory down or up. So it removes a tree that is deeper than
/// the descriptor limit of the process. It goes back up the tree through
/// `..`, so the tree must not move during the call. If the caller drops the
/// future, a removal that has started runs to its end.
///
/// The read of a directory unlinks each entry that is not a directory when
/// the read returns it. For each directory on the path from `path` to the
/// current directory, the removal holds the name of the directory and the
/// names of its subdirectories that are not removed yet. The memory thus
/// grows with the depth of the tree and the number of subdirectories on that
/// path, and not with the number of files in a directory.
///
/// # Errors
///
/// - [`Error::ConsumeUnlink`] if the open, the read, or the removal of an
///   entry fails, or if the name of an entry below `path` is not valid UTF-8.
///   The error names the entry, with each byte that is not valid UTF-8 shown
///   as the replacement character. For the directory at `path`, it names
///   `path` with its trailing slashes removed, or `.` for an empty `path`. An
///   entry with a name that is not valid UTF-8 stays. The entries that the
///   function removed before the failure stay removed.
/// - [`Error::Io`] if the copy of `dfd` fails.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> ostrya::Result<()> {
/// use std::collections::HashSet;
/// use std::os::fd::AsFd;
/// use std::sync::Arc;
///
/// let cwd = std::fs::File::open(".")?;
/// // Remove `src` and keep `src/cache` with its subtree.
/// let keep = Arc::new(HashSet::from(["/cache".to_owned()]));
/// ostrya::remove_source_tree(cwd.as_fd(), "src".as_ref(), keep).await?;
/// # Ok(()) }
/// ```
pub async fn remove_source_tree(
    dfd: BorrowedFd<'_>,
    path: &Path,
    keep: Arc<HashSet<String>>,
) -> Result<()> {
    if keep.contains("/") {
        return Ok(());
    }
    // `AT_FDCWD` is not a descriptor, so it has no copy. It is valid on each
    // thread, so the closure uses it as it is.
    let copy = if dfd.as_raw_fd() == rustix::fs::CWD.as_raw_fd() {
        None
    } else {
        Some(dfd.try_clone_to_owned()?)
    };
    let path = path.to_owned();
    ostrya_rt::unblock(move || {
        let dir = copy.as_ref().map_or(rustix::fs::CWD, |copy| copy.as_fd());
        let bytes = path.as_os_str().as_bytes();
        let mut end = bytes.len();
        while end > 1 && bytes[end - 1] == b'/' {
            end -= 1;
        }
        let root = match &bytes[..end] {
            b"" => b".".as_slice(),
            trimmed => trimmed,
        };
        // The test is on the bytes. `Path::components` drops a `.` that is
        // not the first component, so it cannot see `a/.`.
        let keep_root = root == b"." || root.ends_with(b"/.");
        let root = Path::new(OsStr::from_bytes(root));
        let level = match open_dir(dir, root) {
            Ok(level) => level,
            Err(Errno::NOENT) => return Ok(()),
            Err(err) => return Err(unlink_error(root, err)),
        };
        remove_opened_tree(dir, level, root, keep_root, &keep)
    })
    .await
}

/// Unlinks an entry from a directory: a file, or a directory with
/// `AT_REMOVEDIR`.
///
/// The error of a failed removal names the entry, as the `ostree` command
/// reports it.
fn unlink(dir: BorrowedFd<'_>, name: &(impl AsRef<Path> + ?Sized), is_dir: bool) -> Result<()> {
    let flags = if is_dir {
        AtFlags::REMOVEDIR
    } else {
        AtFlags::empty()
    };
    rustix::fs::unlinkat(dir, name.as_ref(), flags).map_err(|err| unlink_error(name, err))
}

/// Removes all entries below `name` under `dir`, and then `name` itself
/// unless `keep_root` is set. `level` is the open descriptor of `name`.
///
/// The function does not touch an entry whose in-tree path is in `keep`, and
/// it keeps each directory that holds such an entry, `name` included. The
/// in-tree path of `name` is `/`.
///
/// The removal is a loop over an explicit stack of levels. The descriptor of
/// the current level is open, and at most one more for a short time. A
/// descent replaces the descriptor of the level with the descriptor of the
/// child. An ascent replaces it with the descriptor that `..` opens. `..`
/// names the parent because the emptied level is still linked where it was
/// opened.
///
/// The read of a level unlinks each entry that is not a directory when the
/// read returns it. So each level on the path from `name` to the current
/// level holds its own name and the names of its subdirectories that are not
/// removed yet, and no other name. The function can remove a subtree that is
/// deeper than the descriptor limit of the process.
fn remove_opened_tree(
    dir: BorrowedFd<'_>,
    level: OwnedFd,
    name: &Path,
    keep_root: bool,
    keep: &HashSet<String>,
) -> Result<()> {
    let mut level = Dir::new(level).map_err(|err| unlink_error(name, err))?;
    // The in-tree path of the current level: empty for `name`, then `/a`,
    // `/a/b`, and so on.
    let mut tree_path = String::new();
    // One entry for each level from `name` to the current level: the name of
    // the level, the names of the subdirectories left to remove in it, and
    // `true` if the level holds a kept entry.
    let (subdirs, kept) = clear_level(&mut level, name, keep, &mut tree_path)?;
    let mut levels = vec![(name.to_owned(), subdirs, kept)];

    while let Some((_, subdirs, _)) = levels.last_mut() {
        let level_fd = level.fd().map_err(|err| unlink_error(name, err))?;
        match subdirs.pop() {
            Some(child) => {
                let mut child_dir = open_dir(level_fd, &child)
                    .and_then(Dir::new)
                    .map_err(|err| unlink_error(&child, err))?;
                tree_path.push('/');
                tree_path.push_str(&child);
                let (child_subdirs, child_kept) =
                    clear_level(&mut child_dir, Path::new(&child), keep, &mut tree_path)?;
                level = child_dir;
                levels.push((PathBuf::from(child), child_subdirs, child_kept));
            }
            None => {
                let (cleared, _, kept) = levels.pop().expect("a level is in hand within the loop");
                if levels.is_empty() {
                    drop(level);
                    if keep_root || kept {
                        return Ok(());
                    }
                    return unlink(dir, &cleared, true);
                }
                level = open_dir(level_fd, "..")
                    .and_then(Dir::new)
                    .map_err(|err| unlink_error(&cleared, err))?;
                let cut = tree_path
                    .rfind('/')
                    .expect("a level below `name` has a path");
                tree_path.truncate(cut);
                if kept {
                    levels.last_mut().expect("the parent level is in hand").2 = true;
                } else {
                    let parent_fd = level.fd().map_err(|err| unlink_error(&cleared, err))?;
                    unlink(parent_fd, &cleared, true)?;
                }
            }
        }
    }
    Ok(())
}

/// Opens `name` under `dir` as a directory, no-follow.
fn open_dir(
    dir: BorrowedFd<'_>,
    name: &(impl AsRef<Path> + ?Sized),
) -> std::result::Result<OwnedFd, Errno> {
    rustix::fs::openat(
        dir,
        name.as_ref(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Reads one directory level, unlinks each entry that is not a directory when
/// the read returns it, and returns the names of the subdirectories.
///
/// `name` is the name of the level, and `tree_path` is its in-tree path, empty
/// for the root of the removal. The function uses `tree_path` as a buffer for
/// the in-tree path of each entry, and gives it back with the value that it
/// had. The error of a failed read names the level.
/// The type comes from the directory entry. Only an entry of unknown type
/// costs a `stat`. A name that is not valid UTF-8 stops the read with an error
/// that names the entry, and the entry stays.
///
/// The function does not touch an entry whose in-tree path is in `keep`. The
/// flag in the result is `true` if the level holds such an entry.
fn clear_level(
    level: &mut Dir,
    name: &Path,
    keep: &HashSet<String>,
    tree_path: &mut String,
) -> Result<(Vec<String>, bool)> {
    let mut subdirs = Vec::new();
    let mut kept = false;
    while let Some(entry) = level.read() {
        let entry = entry.map_err(|err| unlink_error(name, err))?;
        let child_name = entry.file_name();
        if child_name == c"." || child_name == c".." {
            continue;
        }
        let Ok(child_str) = child_name.to_str() else {
            return Err(Error::ConsumeUnlink {
                name: child_name.to_string_lossy().into_owned(),
                reason: "Name is not valid UTF-8".to_owned(),
            });
        };
        if !keep.is_empty() {
            let len = tree_path.len();
            tree_path.push('/');
            tree_path.push_str(child_str);
            let named = keep.contains(tree_path.as_str());
            tree_path.truncate(len);
            if named {
                kept = true;
                continue;
            }
        }
        let level_fd = level.fd().map_err(|err| unlink_error(name, err))?;
        let child_is_dir = match entry.file_type() {
            FileType::Unknown => {
                let stat = rustix::fs::statat(level_fd, child_name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|err| unlink_error(child_str, err))?;
                FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            }
            file_type => file_type == FileType::Directory,
        };
        if child_is_dir {
            subdirs.push(child_str.to_owned());
        } else {
            rustix::fs::unlinkat(level_fd, child_name, AtFlags::empty())
                .map_err(|err| unlink_error(child_str, err))?;
        }
    }
    Ok((subdirs, kept))
}

/// Returns the error of a failed removal: the name of the entry and the
/// reason, in the words of the `ostree` command.
fn unlink_error(name: &(impl AsRef<Path> + ?Sized), err: Errno) -> Error {
    let reason = std::io::Error::from(err).to_string();
    let reason = match reason.find(" (os error ") {
        Some(cut) => reason[..cut].to_owned(),
        None => reason,
    };
    Error::ConsumeUnlink {
        name: name.as_ref().to_string_lossy().into_owned(),
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

/// Reads all extended attributes of an open descriptor into an [`Xattrs`] set.
///
/// The function reads with [`repo_fs::xattrs`](crate::repo_fs::xattrs), and
/// then checks the names with [`utf8_names`]. The set is canonical. Each name
/// keeps its terminating NUL, as in the on-disk form. A list or a value over
/// 64 KiB gives [`Error::Io`] with `E2BIG`. A set that [`Xattrs::new`]
/// refuses gives [`Error::Io`] with the kind `InvalidData`.
pub(crate) fn read_all_xattrs(fd: BorrowedFd<'_>) -> Result<Xattrs> {
    utf8_names(crate::repo_fs::xattrs(fd)?)
}

/// Gives `xattrs` back if each name is valid UTF-8. A name that is not valid
/// UTF-8 gives [`Error::InvalidFormat`].
pub(crate) fn utf8_names(xattrs: Xattrs) -> Result<Xattrs> {
    if xattrs
        .iter()
        .any(|(name, _)| std::str::from_utf8(name).is_err())
    {
        return Err(Error::InvalidFormat("xattr name is not valid UTF-8".into()));
    }
    Ok(xattrs)
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
