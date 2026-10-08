//! The overlay merge of a transaction.
//!
//! The doc of `Transaction::merge_overlay_dfd_to_mtree` holds the behavior
//! that a caller sees.
//!
//! The merge is a separate walk. A file system ingest and a tree merge after
//! it cannot do this work, because a `MutableTree` has no tombstone form. A
//! whiteout must act on the base tree when the walk gets to it. The walk uses
//! the helpers of `ingest.rs` (canonical permissions, the filter and callback
//! hooks, the dirmeta assembly) and the object writers of `write.rs`.

use std::future::Future;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::pin::Pin;

use ostrya_core::{RepoMode, Xattrs};
use ostrya_rt::FileReader;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

use crate::error::{Error, Result};
use crate::ingest::{adjust_meta, finalize_meta, join_path, to_dirmeta};
use crate::modifier::{CommitModifier, CommitModifierFlags, FilterResult, Owner};
use crate::mtree::MutableTree;
use crate::transaction::Transaction;
use crate::write::FileMeta;

/// The two xattr namespace prefixes of the overlayfs control attributes.
///
/// A privileged overlay uses `trusted.*`, and a rootless `userxattr` overlay
/// uses `user.*`.
const OVERLAY_PREFIXES: [&[u8]; 2] = [b"trusted.overlay.", b"user.overlay."];

/// Methods that merge an overlayfs upper directory into a mutable tree.
impl Transaction {
    /// Merges the overlayfs upper directory at `dfd` into `mtree`.
    ///
    /// `dfd` is the root of the upper directory (the `upperdir` of the mount).
    /// `mtree` holds the lower layer that the overlay was mounted over. The
    /// merge applies the upper directory to `mtree` as a changeset. The overlay
    /// must be unmounted, and the call does not check this.
    ///
    /// Each upper entry other than a whiteout becomes an object, and the entry
    /// replaces or extends the base tree. The merge is an ostrya extension
    /// with no counterpart in the `ostree` command. It changes no on-disk
    /// format, because a deletion acts on the in-memory tree during the walk.
    ///
    /// # Overlay rules
    ///
    /// - A whiteout (a character device with device number 0:0) removes its
    ///   path from the base tree. If the base tree has no entry at the path,
    ///   the whiteout has no effect.
    /// - An opaque directory (`trusted.overlay.opaque` or
    ///   `user.overlay.opaque` set to `y`) clears the base subtree at its name.
    ///   The merge then reads the upper entries. An opaque root clears the
    ///   whole base tree.
    /// - The merge reads both xattr namespaces. A rootless `userxattr` overlay
    ///   writes `user.*`, and an unprivileged reader cannot see `trusted.*`.
    /// - A merged (non-opaque) directory takes its dirmeta from the upper
    ///   inode, because overlayfs copies a directory up with its metadata. The
    ///   root of the upper directory is a merged directory too.
    /// - The merge removes each xattr whose name starts with `trusted.overlay.`
    ///   or `user.overlay.` from each file, symlink, and directory that it
    ///   records, dirmeta included. It keeps every other xattr, also an xattr
    ///   whose name contains `overlay` at another position.
    /// - An entry with an `overlay.metacopy` or `overlay.redirect` xattr is an
    ///   error, because such an entry is not self-contained. The overlay must
    ///   be mounted with these features off (`metacopy=off` and
    ///   `redirect_dir=off`).
    /// - An upper entry replaces a base entry of a different type. An upper
    ///   file or symlink over a base directory removes the directory. An upper
    ///   directory over a base file or symlink removes the leaf and creates a
    ///   new directory.
    ///
    /// A usrmerge migration changes a directory to a symlink. Overlayfs
    /// records this change as a plain leaf with no whiteout and no opaque
    /// marker. A non-directory upper entry hides a lower entry of any type.
    ///
    /// # Modifier
    ///
    /// A [`CommitModifier`] applies to each recorded entry the steps that
    /// [`write_dfd_to_mtree`](Transaction::write_dfd_to_mtree) lists under
    /// its `Modifier` heading. The root of the upper directory goes through
    /// each step except the filter. The merge does not use a
    /// [`DevInoCache`](crate::DevInoCache) or
    /// [`CONSUME`](CommitModifierFlags::CONSUME).
    ///
    /// Whiteouts and opaque markers are merge mechanics, and the modifier
    /// does not see them. The other rules for a modifier are these:
    ///
    /// - If the filter returns [`FilterResult::Skip`] for an upper entry, the
    ///   base entry stays as it is. For a directory, the merge skips the whole
    ///   upper subtree.
    /// - The merge removes the overlay xattrs before the filter and the
    ///   callbacks see the xattr set of an entry. The xattr callback can add a
    ///   removed name again, and the merge does not remove it a second time.
    /// - Under [`SKIP_XATTRS`](CommitModifierFlags::SKIP_XATTRS), the merge
    ///   still reads the xattrs of each entry for the overlay rules. The
    ///   recorded entry has no xattrs.
    /// - The merge checks for `overlay.metacopy` and `overlay.redirect` before
    ///   the filter, so an entry that the filter skips can cause the error.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`,
    ///   or if an upper entry is not a directory, a regular file, a symlink,
    ///   or a whiteout.
    /// - [`Error::Unsupported`] if `[ex-integrity] fsverity` is `yes` and the
    ///   fs-verity seal of an object fails.
    /// - [`Error::UnsupportedOverlayFeature`] if an upper entry has an
    ///   `overlay.metacopy` or `overlay.redirect` xattr in one of the two
    ///   namespaces.
    /// - [`Error::InvalidFormat`] if an entry name or a symlink target is not
    ///   valid UTF-8.
    /// - [`Error::InvalidFormat`] if the label callback returns no label and
    ///   [`ERROR_ON_UNLABELED`](CommitModifierFlags::ERROR_ON_UNLABELED) is
    ///   set.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::InvalidFormat`] if the repository is in `bare` mode and an
    ///   xattr name of a symlink is not valid UTF-8.
    /// - [`Error::InsufficientFreeSpace`] if an object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::ObjectNotFound`] if a lazy subdirectory of `mtree` names a
    ///   dirtree that the repository does not hold.
    /// - [`Error::Core`] if the dirtree of a lazy subdirectory does not parse,
    ///   or if the xattr set with a label is not valid.
    /// - [`Error::Core`] if the mode callback returns a file type that the
    ///   object writer refuses for the entry.
    /// - [`Error::Core`] if a `[core]` or `[archive]` value in the repository
    ///   config is malformed.
    /// - [`Error::Core`] if `dfd` is not a directory: the dirmeta writer
    ///   refuses the file type of the root.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn merge_overlay_dfd_to_mtree(
        &self,
        dfd: BorrowedFd<'_>,
        mtree: &mut MutableTree,
        modifier: Option<&mut CommitModifier>,
    ) -> Result<()> {
        let mode = self.repo().mode();
        if mode == RepoMode::BareSplitXattrs {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
        let mut modifier = modifier;
        let flags = modifier
            .as_deref()
            .map_or(CommitModifierFlags::empty(), |m| m.flags);
        let skip_xattrs = flags.contains(CommitModifierFlags::SKIP_XATTRS);
        if flags.contains(CommitModifierFlags::GENERATE_SIZES) && mode == RepoMode::Archive {
            self.mark_generate_sizes();
        }

        // The root of the upper directory is a merged directory. Its metadata
        // becomes the dirmeta of the base root. An opaque root clears the whole
        // base.
        let root_fd = dfd.try_clone_to_owned()?;
        let (uid, gid, dmode, root_xattrs) = {
            let fd = root_fd.as_fd().try_clone_to_owned()?;
            ostrya_rt::unblock(move || read_dir_own(fd.as_fd())).await?
        };
        if is_opaque(&root_xattrs) {
            mtree.clear_children();
        }
        let base = FileMeta {
            uid,
            gid,
            mode: dmode,
            xattrs: content_xattrs(skip_xattrs, &root_xattrs)?,
        };
        let adjusted = adjust_meta(flags, Owner::of(modifier.as_deref()), base, false);
        let root_meta = finalize_meta(modifier.as_deref_mut(), Path::new("/"), adjusted)?;
        merge_dir(self, root_fd, mtree, modifier, "/".to_owned(), root_meta).await
    }
}

/// One entry of an upper directory, read in a blocking snapshot.
struct OverlayEntry {
    name: String,
    kind: OverlayKind,
    uid: u32,
    gid: u32,
    /// The full `st_mode`, including the file-type bits.
    mode: u32,
    /// The `st_size` that the snapshot read. It bounds the read-ahead of a
    /// regular file.
    size: u64,
    /// The full xattr set of the entry on disk, with each `trusted.overlay.`
    /// or `user.overlay.` attribute. The merge reads these attributes for its
    /// decisions and removes them from the recorded object.
    xattrs: Xattrs,
}

/// The kind of an upper directory entry.
enum OverlayKind {
    Dir,
    Regular,
    Symlink(String),
    /// A character device with device number 0:0, which marks a deletion.
    Whiteout,
}

/// The boxed future of one level of the recursive walk.
///
/// Async recursion needs indirection, so each level returns a boxed future.
type WalkFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Merges one upper directory into `node`.
///
/// `dir_meta` is the fully adjusted metadata of this directory. The caller
/// computes it, so the filter and the user callbacks run once for each
/// directory. The function writes it as the dirmeta of `node`.
///
/// If this directory is opaque, the caller clears the node first: an opaque
/// child through `remove` and `ensure_dir`, and the opaque root through
/// `clear_children`. This level only sets the dirmeta and records the entries.
fn merge_dir<'a>(
    txn: &'a Transaction,
    dir_fd: OwnedFd,
    node: &'a mut MutableTree,
    mut modifier: Option<&'a mut CommitModifier>,
    path: String,
    dir_meta: FileMeta,
) -> WalkFuture<'a> {
    Box::pin(async move {
        let flags = modifier
            .as_deref()
            .map_or(CommitModifierFlags::empty(), |m| m.flags);
        let owner = Owner::of(modifier.as_deref());
        let skip_xattrs = flags.contains(CommitModifierFlags::SKIP_XATTRS);

        // The dirmeta of this directory comes from the upper inode.
        let dirmeta = txn.write_dirmeta(&to_dirmeta(&dir_meta)).await?;
        node.set_metadata_checksum(dirmeta);

        // The merge reads the upper directory in one blocking pass, always with
        // the xattrs and the device number. The merge decisions use both, also under
        // SKIP_XATTRS. SKIP_XATTRS controls only the xattr set of the content.
        let snap = {
            let dir = dir_fd.as_fd().try_clone_to_owned()?;
            ostrya_rt::unblock(move || snapshot_overlay(dir.as_fd())).await?
        };

        for entry in snap {
            let cb_path = join_path(&path, &entry.name);

            // A whiteout is a merge mechanic. It runs no callback and removes
            // the base path. If the base has no entry there, nothing changes.
            if matches!(entry.kind, OverlayKind::Whiteout) {
                node.remove(&entry.name, true)?;
                continue;
            }

            // An entry with `overlay.metacopy` or `overlay.redirect` is not
            // self-contained.
            if has_overlay_attr(&entry.xattrs, b"metacopy") {
                return Err(Error::UnsupportedOverlayFeature(format!(
                    "overlay.metacopy on {cb_path}; mount the overlay with metacopy=off"
                )));
            }
            if has_overlay_attr(&entry.xattrs, b"redirect") {
                return Err(Error::UnsupportedOverlayFeature(format!(
                    "overlay.redirect on {cb_path}; mount the overlay with redirect_dir=off"
                )));
            }

            let is_symlink = matches!(entry.kind, OverlayKind::Symlink(_));
            let base = FileMeta {
                uid: entry.uid,
                gid: entry.gid,
                mode: entry.mode,
                xattrs: content_xattrs(skip_xattrs, &entry.xattrs)?,
            };
            let filter_meta = adjust_meta(flags, owner, base, is_symlink);

            // If the filter returns Skip, the base version stays. The merge does
            // not apply the upper change and does not touch the base entry.
            if let Some(m) = modifier.as_deref_mut()
                && let Some(filter) = &mut m.filter
                && filter(Path::new(&cb_path), &filter_meta) == FilterResult::Skip
            {
                txn.note_filtered();
                continue;
            }

            match entry.kind {
                OverlayKind::Regular => {
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
                    // The leaf replaces the base entry at this name (a file, a
                    // symlink, or a directory). A non-directory upper entry hides
                    // a lower entry of any type. For this reason, a replacement
                    // of a directory with a leaf arrives here as a plain entry
                    // with no whiteout and no opaque marker.
                    node.remove(&entry.name, true)?;
                    node.replace_file(&entry.name, checksum)?;
                }
                OverlayKind::Symlink(target) => {
                    let meta =
                        finalize_meta(modifier.as_deref_mut(), Path::new(&cb_path), filter_meta)?;
                    let checksum = txn.write_symlink(&target, &meta, None).await?;
                    // The leaf replaces the base entry at this name.
                    node.remove(&entry.name, true)?;
                    node.replace_file(&entry.name, checksum)?;
                }
                OverlayKind::Dir => {
                    // An opaque directory replaces the entry at this name with a
                    // new directory that holds only the upper entries. A
                    // non-opaque directory merges over a base directory. If the
                    // base holds a file or a symlink at the name, the merge
                    // removes the base leaf and creates a new directory.
                    // `ensure_dir` cannot merge onto a file entry.
                    if is_opaque(&entry.xattrs) || node.file_checksum(&entry.name).is_some() {
                        node.remove(&entry.name, true)?;
                    }
                    let meta =
                        finalize_meta(modifier.as_deref_mut(), Path::new(&cb_path), filter_meta)?;
                    let child_fd = open_dir(dir_fd.as_fd(), &entry.name)?;
                    let child = node.ensure_dir(&entry.name).await?;
                    merge_dir(txn, child_fd, child, modifier.as_deref_mut(), cb_path, meta).await?;
                }
                OverlayKind::Whiteout => unreachable!("whiteouts are handled above"),
            }
        }
        Ok(())
    })
}

/// Returns `true` if a device number marks an overlayfs whiteout (0:0).
fn is_whiteout(rdev: u64) -> bool {
    rustix::fs::major(rdev) == 0 && rustix::fs::minor(rdev) == 0
}

/// Reads the owner, the mode, and the full xattr set of a directory.
fn read_dir_own(dir: BorrowedFd<'_>) -> Result<(u32, u32, u32, Xattrs)> {
    let stat = rustix::fs::fstat(dir)?;
    let xattrs = crate::object::read_all_xattrs(dir)?;
    Ok((stat.st_uid, stat.st_gid, stat.st_mode, xattrs))
}

/// Reads the entries of one upper directory in one blocking pass.
///
/// The function always reads the xattrs and the device number of each entry.
/// The merge needs the `overlay.*` attributes and the device number also
/// under SKIP_XATTRS. It reads the xattrs of a symlink with no-follow,
/// from the link itself.
fn snapshot_overlay(dir: BorrowedFd<'_>) -> Result<Vec<OverlayEntry>> {
    let mut entries = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let name = name
            .to_str()
            .map_err(|_| Error::InvalidFormat("upperdir entry name is not valid UTF-8".into()))?
            .to_owned();

        let stat = rustix::fs::statat(dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = match FileType::from_raw_mode(stat.st_mode) {
            FileType::CharacterDevice if is_whiteout(stat.st_rdev) => OverlayKind::Whiteout,
            FileType::Directory => OverlayKind::Dir,
            FileType::RegularFile => OverlayKind::Regular,
            FileType::Symlink => {
                let target = rustix::fs::readlinkat(dir, name.as_str(), Vec::new())?
                    .into_string()
                    .map_err(|_| {
                        Error::InvalidFormat("symlink target is not valid UTF-8".into())
                    })?;
                OverlayKind::Symlink(target)
            }
            _ => {
                return Err(Error::Unsupported(format!(
                    "unsupported upperdir entry type for {name:?}"
                )));
            }
        };

        // A whiteout carries no content, so it needs no xattr read.
        let xattrs = match kind {
            OverlayKind::Whiteout => Xattrs::empty(),
            _ => read_entry_xattrs(dir, name.as_str(), &kind)?,
        };

        entries.push(OverlayEntry {
            name,
            kind,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
            size: stat.st_size as u64,
            xattrs,
        });
    }
    Ok(entries)
}

/// Reads the xattrs of one upper directory entry with no-follow.
///
/// The function opens a regular file or a directory and reads from its
/// descriptor. It reads a symlink through the path-based no-follow reader.
fn read_entry_xattrs(dir: BorrowedFd<'_>, name: &str, kind: &OverlayKind) -> Result<Xattrs> {
    let oflags = match kind {
        OverlayKind::Regular => OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        OverlayKind::Dir => OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        OverlayKind::Symlink(_) => return crate::object::read_link_xattrs(dir, name),
        OverlayKind::Whiteout => return Ok(Xattrs::empty()),
    };
    let fd = rustix::fs::openat(dir, name, oflags, Mode::empty())?;
    crate::object::read_all_xattrs(fd.as_fd())
}

/// Opens the subdirectory `name` of `parent` with no-follow.
fn open_dir(parent: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    Ok(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Returns the xattr set of a recorded object.
///
/// The set is the set on disk without each `trusted.overlay.` or
/// `user.overlay.` attribute. Under SKIP_XATTRS, the set is empty.
fn content_xattrs(skip: bool, full: &Xattrs) -> Result<Xattrs> {
    if skip {
        return Ok(Xattrs::empty());
    }
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = full
        .iter()
        .filter(|(name, _)| !is_overlay_name(name))
        .map(|(name, value)| (name.to_vec(), value.to_vec()))
        .collect();
    Ok(Xattrs::new(pairs)?)
}

/// Returns `true` if an xattr name is in one of the overlay control namespaces.
fn is_overlay_name(name: &[u8]) -> bool {
    OVERLAY_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Returns `true` if the xattr set holds `<ns>.overlay.<suffix>`.
///
/// `<ns>` is one of the two namespaces. If `require_y` is set, the value must
/// be exactly `y` (the opaque marker).
fn overlay_attr_present(xattrs: &Xattrs, suffix: &[u8], require_y: bool) -> bool {
    xattrs.iter().any(|(name, value)| {
        let matches_name = OVERLAY_PREFIXES.iter().any(|p| {
            let mut want = Vec::with_capacity(p.len() + suffix.len() + 1);
            want.extend_from_slice(p);
            want.extend_from_slice(suffix);
            want.push(0);
            name == want.as_slice()
        });
        matches_name && (!require_y || value == b"y")
    })
}

/// Returns `true` if a directory is opaque (`overlay.opaque` set to `y`).
fn is_opaque(xattrs: &Xattrs) -> bool {
    overlay_attr_present(xattrs, b"opaque", true)
}

/// Returns `true` if an entry has the named overlay feature attribute.
///
/// The value of the attribute does not matter.
fn has_overlay_attr(xattrs: &Xattrs, suffix: &[u8]) -> bool {
    overlay_attr_present(xattrs, suffix, false)
}
