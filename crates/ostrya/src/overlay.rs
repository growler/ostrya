//! Overlay changeset import: merging an overlayfs upperdir into a mutable tree.
//!
//! [`Transaction::merge_overlay_dfd_to_mtree`] walks an overlayfs upperdir and
//! applies it as a changeset onto a [`MutableTree`](crate::MutableTree) holding
//! the lower layer the overlay was mounted over. It is a port extension with no
//! `ostree` tool counterpart and no on-disk format impact: the deletions a
//! changeset expresses apply to the in-memory tree during the walk and never
//! serialize.
//!
//! It is a separate walk rather than filesystem ingest ([`crate::ingest`])
//! followed by a tree merge because a [`MutableTree`](crate::MutableTree) has no
//! tombstone representation; a whiteout has to act on the base tree as the walk
//! reaches it. The walk still reuses the 7c helpers -- canonical permissions,
//! the filter and callback hooks, dirmeta assembly -- and the 7a object writers.
//!
//! Overlay mechanics recognized during the walk:
//!
//! - A whiteout (a character device with device number 0:0) removes the
//!   corresponding path from the base tree.
//! - An opaque directory (`trusted.overlay.opaque` or `user.overlay.opaque`
//!   set to `y`) clears the base subtree at that name before the upper entries
//!   are ingested. Both namespaces are honored: a rootless `userxattr` overlay
//!   writes `user.*`, while `trusted.*` is invisible to an unprivileged reader.
//! - A merged (non-opaque) directory takes its dirmeta from the upper inode,
//!   since overlayfs copies a directory up with its metadata.
//! - `overlay.*` control xattrs are stripped from every ingested object.
//! - `overlay.metacopy` and `overlay.redirect` entries are hard errors: such an
//!   entry is not self-contained, so the overlay must be mounted with those
//!   features disabled.
//! - A cross-type replacement drops the base entry and applies the upper one:
//!   an upper file or symlink over a base directory removes the directory, and
//!   an upper directory over a base file or symlink removes the leaf and creates
//!   a fresh directory. usrmerge-style migrations move a directory to a symlink,
//!   and overlayfs records that as a plain non-opaque leaf, since a non-directory
//!   upper entry shadows a lower entry of any type without a whiteout or opaque
//!   marker.
//!
//! Whiteouts and opaque markers are merge mechanics, not content: the modifier
//! callbacks never see them, and a filter `Skip` on an upper entry leaves the
//! base version untouched.

use std::future::Future;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::pin::Pin;

use ostrya_core::{RepoMode, Xattrs};
use ostrya_rt::File as RtFile;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

use crate::error::{Error, Result};
use crate::ingest::{adjust_meta, finalize_meta, join_path, to_dirmeta};
use crate::modifier::{CommitModifier, CommitModifierFlags, FilterResult, Owner};
use crate::mtree::MutableTree;
use crate::transaction::Transaction;
use crate::write::FileMeta;

/// The two extended-attribute namespace prefixes overlayfs uses for its control
/// attributes: `trusted.*` for a privileged overlay, `user.*` for a rootless
/// `userxattr` overlay.
const OVERLAY_PREFIXES: [&[u8]; 2] = [b"trusted.overlay.", b"user.overlay."];

impl Transaction {
    /// Merge the overlayfs upperdir rooted at `dfd` into `mtree`, applying its
    /// changeset onto the lower layer the tree holds.
    ///
    /// `dfd` is the upperdir root; the overlay is expected to be unmounted,
    /// which is not checked. Whiteouts remove base paths, opaque directories
    /// clear base subtrees, and every other entry ingests through the object
    /// writers and replaces or extends the base tree. `modifier` shapes the
    /// ingested entries exactly as it does a filesystem walk; the whiteouts and
    /// opaque markers it never sees.
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

        // The upperdir root is a merged directory: its own metadata becomes the
        // base root's dirmeta, and a root marked opaque clears the whole base.
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

/// One directory entry captured from the upperdir in a blocking snapshot.
struct OverlayEntry {
    name: String,
    kind: OverlayKind,
    uid: u32,
    gid: u32,
    /// The full `st_mode`, including the file-type bits.
    mode: u32,
    /// The entry's full on-disk xattr set, including any `overlay.*` control
    /// attributes; the merge reads those for its decisions and strips them from
    /// the ingested object.
    xattrs: Xattrs,
}

/// What kind of upperdir entry the merge is looking at.
enum OverlayKind {
    Dir,
    Regular,
    Symlink(String),
    /// A character device with device number 0:0: a deletion marker.
    Whiteout,
}

/// The boxed future for the recursive walk; async recursion needs indirection,
/// so each level returns a boxed future.
type WalkFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Merge one upperdir directory into `node`.
///
/// `dir_meta` is this directory's fully adjusted metadata, computed by the
/// caller so the filter and the user callbacks fire once per directory; it is
/// written as `node`'s dirmeta. The caller has already cleared the node when
/// this directory is opaque (an opaque child through `remove` + `ensure_dir`,
/// the opaque root through `clear_children`), so this level only sets the
/// dirmeta and ingests the entries.
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

        // This directory's dirmeta comes from the upper inode.
        let dirmeta = txn.write_dirmeta(&to_dirmeta(&dir_meta)).await?;
        node.set_metadata_checksum(dirmeta);

        // Read the upper directory in one blocking pass, always with xattrs and
        // the device number: the merge decisions depend on both regardless of
        // SKIP_XATTRS, which only governs the ingested content xattr set.
        let snap = {
            let dir = dir_fd.as_fd().try_clone_to_owned()?;
            ostrya_rt::unblock(move || snapshot_overlay(dir.as_fd())).await?
        };

        for entry in snap {
            let cb_path = join_path(&path, &entry.name);

            // A whiteout is a merge mechanic: no callbacks, it just removes the
            // base path, whether or not the base has an entry there.
            if matches!(entry.kind, OverlayKind::Whiteout) {
                node.remove(&entry.name, true)?;
                continue;
            }

            // metacopy and redirect entries are not self-contained.
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

            // A filter Skip leaves the base version in place: the upper change is
            // not applied, and the base entry (if any) is untouched.
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
                    let checksum = txn.write_content(None, &meta, RtFile::from(fd)).await?;
                    // The leaf wins: drop whatever the base held at this name
                    // (file, symlink, or directory) before applying the override.
                    // A non-directory upper entry shadows a lower entry of any
                    // type, so a directory-to-leaf replacement arrives here as a
                    // plain entry with no whiteout or opaque marker.
                    node.remove(&entry.name, true)?;
                    node.replace_file(&entry.name, checksum)?;
                }
                OverlayKind::Symlink(target) => {
                    let meta =
                        finalize_meta(modifier.as_deref_mut(), Path::new(&cb_path), filter_meta)?;
                    let checksum = txn.write_symlink(&target, &meta, None).await?;
                    // The leaf wins: drop whatever the base held before applying.
                    node.remove(&entry.name, true)?;
                    node.replace_file(&entry.name, checksum)?;
                }
                OverlayKind::Dir => {
                    // An opaque directory replaces whatever is at this name with a
                    // fresh directory holding only the upper entries. A non-opaque
                    // directory merges over a base directory, but when the base
                    // holds a file or symlink at the name the directory wins: the
                    // base leaf is dropped and a fresh directory takes its place,
                    // since `ensure_dir` cannot merge onto a file entry.
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

/// Whether a device number denotes an overlayfs whiteout (major 0, minor 0).
fn is_whiteout(rdev: u64) -> bool {
    rustix::fs::major(rdev) == 0 && rustix::fs::minor(rdev) == 0
}

/// Read a directory's own owner, mode, and full xattr set from its fd.
fn read_dir_own(dir: BorrowedFd<'_>) -> Result<(u32, u32, u32, Xattrs)> {
    let stat = rustix::fs::fstat(dir)?;
    let xattrs = crate::object::read_all_xattrs(dir)?;
    Ok((stat.st_uid, stat.st_gid, stat.st_mode, xattrs))
}

/// Capture one upperdir directory's entries in a single blocking pass. Each
/// entry's own xattrs are always read -- the merge needs the `overlay.*`
/// attributes and the device number regardless of SKIP_XATTRS. A symlink's
/// xattrs are read no-follow, the link itself rather than its target.
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
            xattrs,
        });
    }
    Ok(entries)
}

/// Read an upperdir entry's own xattrs, no-follow. A regular file or directory
/// is opened and read from its fd; a symlink is read through the path-based
/// no-follow reader.
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

/// Open a subdirectory of `parent` no-follow.
fn open_dir(parent: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    Ok(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// The xattr set an ingested object should carry: the on-disk set with every
/// `overlay.*` control attribute removed, or empty under SKIP_XATTRS.
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

/// Whether an xattr name is in one of the overlay control namespaces.
fn is_overlay_name(name: &[u8]) -> bool {
    OVERLAY_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Whether the xattr set carries `<ns>.overlay.<suffix>` in either namespace.
/// With `require_y`, the value must be exactly `y` (the opaque marker).
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

/// Whether a directory is opaque (`overlay.opaque` set to `y`).
fn is_opaque(xattrs: &Xattrs) -> bool {
    overlay_attr_present(xattrs, b"opaque", true)
}

/// Whether an entry carries the named overlay feature attribute (presence
/// alone, any value).
fn has_overlay_attr(xattrs: &Xattrs, suffix: &[u8]) -> bool {
    overlay_attr_present(xattrs, suffix, false)
}
