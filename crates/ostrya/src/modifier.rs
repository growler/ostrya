//! The commit modifier: what a filesystem walk commits and how.
//!
//! [`Transaction::write_dfd_to_mtree`](crate::Transaction::write_dfd_to_mtree)
//! ingests an on-disk tree into a [`MutableTree`](crate::MutableTree). A
//! [`CommitModifier`] shapes that ingest: a set of [`CommitModifierFlags`], a
//! declared owner uid and gid that replace what the source carries, a
//! synchronous filter that includes or prunes each entry, a synchronous mode
//! callback that replaces an entry's recorded `st_mode`, a synchronous xattr
//! callback that replaces an entry's stored xattr set, an optional SELinux
//! label callback, and an optional [`DevInoCache`] that skips re-hashing a file
//! already known by its `(device, inode)`.
//!
//! The callbacks are synchronous `FnMut` closures held in public boxed
//! fields, invoked once per path during the walk. The walk borrows the
//! modifier exclusively (`Option<&mut CommitModifier>`), so a callback
//! mutates its own captured state through that borrow. Every callback box is
//! `Send`, which keeps the modifier and the walk future `Send`.

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;

use ostrya_core::{Checksum, Xattrs};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::error::Result;
use crate::repo::Repo;
use crate::traverse::read_dir_names;
use crate::write::FileMeta;

/// The loose-object file-name suffix of an uncompressed content object. A
/// compressed one (`.filez`) is never a hardlink target, so only this form
/// enters a devino cache.
const CONTENT_SUFFIX: &str = ".file";
/// The hex-character count of a loose object's name below its fanout directory.
const LOOSE_NAME_HEX: usize = 62;

/// Flags controlling how a filesystem tree is ingested.
///
/// A bitset over the individual flag constants. Combine with `|` and test with
/// [`contains`](CommitModifierFlags::contains).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommitModifierFlags(u32);

impl CommitModifierFlags {
    /// No flags set.
    pub const NONE: CommitModifierFlags = CommitModifierFlags(0);
    /// Do not read on-disk extended attributes; the stored xattr set starts
    /// empty (a callback may still add to it).
    pub const SKIP_XATTRS: CommitModifierFlags = CommitModifierFlags(1 << 0);
    /// Mark the transaction to emit `ostree.sizes` at commit. Archive-only:
    /// elsewhere the request is a silent no-op.
    pub const GENERATE_SIZES: CommitModifierFlags = CommitModifierFlags(1 << 1);
    /// Force owner 0:0, canonicalize each permission set (`perm & 0o755` for
    /// regular files and directories; symlinks unchanged), and record no
    /// extended attributes. The xattr set is emptied before the callbacks run,
    /// so a callback may still add to it, as under
    /// [`SKIP_XATTRS`](CommitModifierFlags::SKIP_XATTRS).
    pub const CANONICAL_PERMISSIONS: CommitModifierFlags = CommitModifierFlags(1 << 2);
    /// With a label callback present, treat a path the callback leaves
    /// unlabeled as an error.
    pub const ERROR_ON_UNLABELED: CommitModifierFlags = CommitModifierFlags(1 << 3);
    /// Delete each source file as it is consumed and remove emptied
    /// directories, including the walk root.
    pub const CONSUME: CommitModifierFlags = CommitModifierFlags(1 << 4);
    /// Trust a [`DevInoCache`] hit as the file's identity and skip ingestion.
    pub const DEVINO_CANONICAL: CommitModifierFlags = CommitModifierFlags(1 << 5);
    /// Select the version-1 SELinux labeling rules for the label callback. A
    /// real policy backend is out of scope; the flag is carried for callers
    /// that implement their own labeling.
    pub const SELINUX_LABEL_V1: CommitModifierFlags = CommitModifierFlags(1 << 6);

    /// The empty flag set.
    pub const fn empty() -> CommitModifierFlags {
        CommitModifierFlags(0)
    }

    /// Whether every bit in `other` is set in `self`.
    pub const fn contains(self, other: CommitModifierFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// The raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl std::ops::BitOr for CommitModifierFlags {
    type Output = CommitModifierFlags;

    fn bitor(self, rhs: CommitModifierFlags) -> CommitModifierFlags {
        CommitModifierFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CommitModifierFlags {
    fn bitor_assign(&mut self, rhs: CommitModifierFlags) {
        self.0 |= rhs.0;
    }
}

/// A filter callback's verdict for one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterResult {
    /// Include the entry (and, for a directory, descend into it).
    Allow,
    /// Exclude the entry; for a directory, prune its whole subtree.
    Skip,
}

/// A `(device, inode)` to content-checksum map.
///
/// Populated by checkout (Phase 8), which records the inode of each object it
/// writes, and by [`Repo::devino_cache`](crate::Repo::devino_cache), which
/// reads the same mapping out of a repository's own loose objects. A source
/// file whose `(device, inode)` is present is taken to be that object and its
/// content is never read.
///
/// The cache is consulted whenever it is attached to a modifier. Without
/// [`DEVINO_CANONICAL`](CommitModifierFlags::DEVINO_CANONICAL) a hit supplies
/// the stored object's own metadata, the modifier is applied over that
/// metadata, and the object is rewritten from the stored content where the
/// result differs. With the flag the hit is taken verbatim and the filter and
/// every callback are skipped for that entry.
#[derive(Debug, Default, Clone)]
pub struct DevInoCache {
    map: HashMap<(u64, u64), Checksum>,
}

impl DevInoCache {
    /// An empty cache.
    pub fn new() -> DevInoCache {
        DevInoCache {
            map: HashMap::new(),
        }
    }

    /// Record that the object at `(dev, ino)` has the given content checksum.
    pub fn insert(&mut self, dev: u64, ino: u64, checksum: Checksum) {
        self.map.insert((dev, ino), checksum);
    }

    /// The checksum recorded for `(dev, ino)`, if any.
    pub fn get(&self, dev: u64, ino: u64) -> Option<Checksum> {
        self.map.get(&(dev, ino)).copied()
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Repo {
    /// Build a [`DevInoCache`] from this repository's own uncompressed loose
    /// content objects.
    ///
    /// Each `objects/<xx>/<62hex>.file` entry that is a regular file
    /// contributes its `(st_dev, st_ino)` and the checksum its name spells. A
    /// checkout that hardlinks those objects into a destination tree therefore
    /// produces files this cache resolves, whichever process made the
    /// checkout.
    ///
    /// An `archive` repository stores every content object compressed
    /// (`.filez`), so it contributes nothing and the cache comes back empty.
    pub async fn devino_cache(&self) -> Result<DevInoCache> {
        let repo = self.clone();
        ostrya_rt::unblock(move || devino_cache_blocking(repo.objects_fd())).await
    }
}

/// Scan an `objects/` directory fd for uncompressed loose content objects.
fn devino_cache_blocking(objects_fd: BorrowedFd<'_>) -> Result<DevInoCache> {
    let mut cache = DevInoCache::new();
    // The reader accepts only the lower-case namespace both implementations
    // write. A name holding upper-case hex folds to a checksum no writer here
    // produced, and the entry it adds is what `-I` then commits for a source
    // file hardlinked to that object. Such a name exists only if something
    // outside either implementation wrote it, so no test produces one.
    for fanout in read_dir_names(objects_fd)? {
        if fanout.len() != 2
            || !fanout
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            continue;
        }
        let dir = match rustix::fs::openat(
            objects_fd,
            fanout.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => continue,
            Err(e) => return Err(e.into()),
        };
        for entry in read_dir_names(dir.as_fd())? {
            let Some(rest) = entry.strip_suffix(CONTENT_SUFFIX) else {
                continue;
            };
            if rest.len() != LOOSE_NAME_HEX {
                continue;
            }
            let Ok(checksum) = Checksum::from_hex_lower(&format!("{fanout}{rest}")) else {
                continue;
            };
            let Ok(st) = rustix::fs::statat(dir.as_fd(), entry.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            else {
                continue;
            };
            // A `bare` repository stores a symlink object as a symlink, and a
            // hardlinking checkout links that inode into the destination, so
            // both file types can be one end of a hardlink pair with a source
            // entry. Nothing else under `objects/` can.
            if !matches!(
                FileType::from_raw_mode(st.st_mode),
                FileType::RegularFile | FileType::Symlink
            ) {
                continue;
            }
            cache.insert(st.st_dev, st.st_ino, checksum);
        }
    }
    Ok(cache)
}

/// A synchronous filter over ingested paths.
pub type FilterFn = Box<dyn FnMut(&Path, &FileMeta) -> FilterResult + Send>;
/// A synchronous callback that replaces an entry's recorded `st_mode`. The
/// returned value carries the file-type bits as well as the permission bits.
pub type ModeFn = Box<dyn FnMut(&Path, &FileMeta) -> u32 + Send>;
/// A synchronous callback that replaces an entry's stored xattr set.
pub type XattrFn = Box<dyn FnMut(&Path, &FileMeta) -> Xattrs + Send>;
/// A synchronous callback that returns the SELinux label for an entry.
pub type LabelFn = Box<dyn FnMut(&Path, &FileMeta) -> Option<Vec<u8>> + Send>;

/// The stored name of the SELinux label xattr, in on-disk NUL-terminated form.
const SELINUX_XATTR: &[u8] = b"security.selinux\0";

/// Shapes what a filesystem walk commits.
///
/// Construct with [`new`](CommitModifier::new) and set the callback fields
/// directly. The walk takes the modifier as `&mut`, so the callbacks run
/// through an exclusive borrow.
pub struct CommitModifier {
    /// Flags controlling the ingest.
    pub flags: CommitModifierFlags,
    /// The owner uid every ingested entry records, in place of the uid its
    /// source carries. Applied after the
    /// [`CANONICAL_PERMISSIONS`](CommitModifierFlags::CANONICAL_PERMISSIONS)
    /// reduction and before the callbacks, so a declared id wins over that
    /// flag's `0`.
    pub owner_uid: Option<u32>,
    /// The owner gid every ingested entry records, on the same terms as
    /// [`owner_uid`](CommitModifier::owner_uid).
    pub owner_gid: Option<u32>,
    /// A filter called per path to include or prune entries.
    pub filter: Option<FilterFn>,
    /// A callback whose return value replaces an entry's recorded `st_mode`.
    /// Runs after the
    /// [`CANONICAL_PERMISSIONS`](CommitModifierFlags::CANONICAL_PERMISSIONS)
    /// reduction and the declared ownership, and ahead of the xattr callback
    /// and the SELinux label hook.
    pub mode_callback: Option<ModeFn>,
    /// A callback whose return value replaces an entry's stored xattr set.
    pub xattr_callback: Option<XattrFn>,
    /// A callback returning an entry's SELinux label. A pre-existing
    /// `security.selinux` xattr is dropped before the callback runs, so a
    /// returned label is never double-counted.
    pub label_callback: Option<LabelFn>,
    /// A devino cache, consulted under
    /// [`DEVINO_CANONICAL`](CommitModifierFlags::DEVINO_CANONICAL).
    pub devino_cache: Option<DevInoCache>,
}

impl CommitModifier {
    /// A modifier with the given flags, no declared ownership, and no
    /// callbacks.
    pub fn new(flags: CommitModifierFlags) -> CommitModifier {
        CommitModifier {
            flags,
            owner_uid: None,
            owner_gid: None,
            filter: None,
            mode_callback: None,
            xattr_callback: None,
            label_callback: None,
            devino_cache: None,
        }
    }
}

/// The declared ownership a walk applies to every entry, read out of the
/// modifier once so the per-entry adjustment holds no borrow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Owner {
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
}

impl Owner {
    /// The ownership `modifier` declares; nothing declared for `None`.
    pub(crate) fn of(modifier: Option<&CommitModifier>) -> Owner {
        modifier.map_or(Owner::default(), |m| Owner {
            uid: m.owner_uid,
            gid: m.owner_gid,
        })
    }

    /// Replace the ids `meta` carries with the declared ones.
    pub(crate) fn apply(self, meta: &mut FileMeta) {
        if let Some(uid) = self.uid {
            meta.uid = uid;
        }
        if let Some(gid) = self.gid {
            meta.gid = gid;
        }
    }
}

/// Rebuild an xattr set with any `security.selinux` entry removed. Used by the
/// label hook so a pre-existing label is not double-counted.
pub(crate) fn without_selinux(xattrs: &Xattrs) -> ostrya_core::Result<Xattrs> {
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = xattrs
        .iter()
        .filter(|(name, _)| *name != SELINUX_XATTR)
        .map(|(name, value)| (name.to_vec(), value.to_vec()))
        .collect();
    Xattrs::new(pairs)
}

/// Rebuild an xattr set with a `security.selinux` entry carrying `label`.
pub(crate) fn with_selinux(xattrs: &Xattrs, label: Vec<u8>) -> ostrya_core::Result<Xattrs> {
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = xattrs
        .iter()
        .filter(|(name, _)| *name != SELINUX_XATTR)
        .map(|(name, value)| (name.to_vec(), value.to_vec()))
        .collect();
    pairs.push((SELINUX_XATTR.to_vec(), label));
    Xattrs::new(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_combine_and_test() {
        let flags = CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::CONSUME;
        assert!(flags.contains(CommitModifierFlags::CANONICAL_PERMISSIONS));
        assert!(flags.contains(CommitModifierFlags::CONSUME));
        assert!(!flags.contains(CommitModifierFlags::SKIP_XATTRS));
        assert!(!CommitModifierFlags::empty().contains(CommitModifierFlags::CONSUME));

        let mut acc = CommitModifierFlags::NONE;
        acc |= CommitModifierFlags::GENERATE_SIZES;
        assert!(acc.contains(CommitModifierFlags::GENERATE_SIZES));
    }

    #[test]
    fn devino_cache_round_trips() {
        let mut cache = DevInoCache::new();
        assert!(cache.is_empty());
        let c = Checksum::sha256(b"x");
        cache.insert(7, 42, c);
        assert_eq!(cache.get(7, 42), Some(c));
        assert_eq!(cache.get(7, 43), None);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn selinux_helpers_drop_and_add() {
        let base = Xattrs::new([
            (b"security.selinux\0".to_vec(), b"old".to_vec()),
            (b"user.a\0".to_vec(), b"1".to_vec()),
        ])
        .unwrap();
        let dropped = without_selinux(&base).unwrap();
        assert_eq!(dropped.len(), 1);
        assert!(dropped.iter().all(|(n, _)| n != SELINUX_XATTR));

        let relabeled = with_selinux(&dropped, b"new".to_vec()).unwrap();
        assert_eq!(relabeled.len(), 2);
        let label = relabeled
            .iter()
            .find(|(n, _)| *n == SELINUX_XATTR)
            .map(|(_, v)| v.to_vec());
        assert_eq!(label, Some(b"new".to_vec()));
    }
}
