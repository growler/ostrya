//! The commit modifier: the options that shape the ingest of a directory.
//!
//! [`Transaction::write_dfd_to_mtree`](crate::Transaction::write_dfd_to_mtree)
//! reads a directory on disk into a [`MutableTree`](crate::MutableTree). A
//! [`CommitModifier`] changes what that walk records for each entry. It holds:
//!
//! - a set of [`CommitModifierFlags`]
//! - a declared owner uid and gid
//! - a filter, a mode callback, an xattr callback, and a SELinux label
//!   callback
//! - a [`DevInoCache`], which is optional

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

/// The file-name suffix of a loose uncompressed content object. A compressed
/// object (`.filez`) is never a hardlink target, so only this form enters a
/// devino cache.
const CONTENT_SUFFIX: &str = ".file";
/// The number of hex characters in the name of a loose object in its fanout
/// directory.
const LOOSE_NAME_HEX: usize = 62;

/// The flags that control the ingest of a directory tree.
///
/// The value is a bitset of the flag constants. Combine flags with `|`, and
/// test them with [`contains`](CommitModifierFlags::contains).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommitModifierFlags(u32);

impl CommitModifierFlags {
    /// The flag set with no flags.
    pub const NONE: CommitModifierFlags = CommitModifierFlags(0);
    /// The flag that stops the walk from reading the extended attributes on
    /// disk.
    ///
    /// The xattr set of each entry starts empty. A callback can add to it.
    pub const SKIP_XATTRS: CommitModifierFlags = CommitModifierFlags(1 << 0);
    /// The flag that marks the transaction to write `ostree.sizes` in the
    /// commit.
    ///
    /// The flag has an effect in an `archive` repository only. In other modes
    /// it does nothing and gives no error.
    pub const GENERATE_SIZES: CommitModifierFlags = CommitModifierFlags(1 << 1);
    /// The flag that records canonical ownership and permissions.
    ///
    /// Each entry gets owner 0:0 and no extended attributes. A regular file or
    /// a directory gets `perm & 0o755`, and a symlink keeps its mode. The walk
    /// empties the xattr set before the callbacks run, so a callback can add to
    /// it, as under [`SKIP_XATTRS`](CommitModifierFlags::SKIP_XATTRS).
    pub const CANONICAL_PERMISSIONS: CommitModifierFlags = CommitModifierFlags(1 << 2);
    /// The flag that makes a path with no label an error.
    ///
    /// If a label callback is set and returns no label for a path, the walk
    /// fails with [`Error::InvalidFormat`](crate::Error::InvalidFormat).
    pub const ERROR_ON_UNLABELED: CommitModifierFlags = CommitModifierFlags(1 << 3);
    /// The flag that deletes the source tree during the walk.
    ///
    /// The walk deletes each source file after it consumes the file. It
    /// removes each directory that becomes empty, the walk root included.
    /// [`Transaction::write_dfd_to_mtree`](crate::Transaction::write_dfd_to_mtree)
    /// gives the rules for the walk root.
    pub const CONSUME: CommitModifierFlags = CommitModifierFlags(1 << 4);
    /// The flag that takes a [`DevInoCache`] hit as the identity of the file.
    ///
    /// The walk does not ingest a file that the cache knows.
    pub const DEVINO_CANONICAL: CommitModifierFlags = CommitModifierFlags(1 << 5);
    /// The flag that selects the version-1 SELinux labeling rules.
    ///
    /// ostrya has no SELinux policy backend and does not read this flag. The
    /// flag is for callers that implement their own labeling in the label
    /// callback.
    pub const SELINUX_LABEL_V1: CommitModifierFlags = CommitModifierFlags(1 << 6);

    /// Returns the empty flag set.
    pub const fn empty() -> CommitModifierFlags {
        CommitModifierFlags(0)
    }

    /// Returns `true` if `self` holds every bit of `other`.
    pub const fn contains(self, other: CommitModifierFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the raw bits.
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

/// The verdict of a filter callback for one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterResult {
    /// The walk includes the entry, and descends into it if it is a directory.
    Allow,
    /// The walk excludes the entry, with the whole subtree of a directory.
    Skip,
}

/// A map from `(device, inode)` to the checksum of a content object.
///
/// Two sources fill the cache:
///
/// - A checkout with
///   [`CheckoutOptions::devino_cache`](crate::CheckoutOptions::devino_cache)
///   set records the inode of each regular file that it writes or links.
/// - [`Repo::devino_cache`](crate::Repo::devino_cache) reads the same map
///   from the loose objects of a repository.
///
/// If the `(device, inode)` of a source file is in the cache, the walk takes
/// the file to be that object. It never reads the content of the file.
///
/// # Hits
///
/// If the cache is attached to a modifier, the walk looks up each entry that
/// is not a directory.
/// Without [`DEVINO_CANONICAL`](CommitModifierFlags::DEVINO_CANONICAL), a hit
/// gives the metadata of the stored object, and the walk applies the modifier
/// to that metadata. If the result differs, the walk writes a new object from
/// the stored content.
///
/// With the flag, the walk takes the hit as it is. It skips the filter and
/// every callback for that entry.
#[derive(Debug, Default, Clone)]
pub struct DevInoCache {
    map: HashMap<(u64, u64), Checksum>,
}

impl DevInoCache {
    /// Creates an empty cache.
    pub fn new() -> DevInoCache {
        DevInoCache {
            map: HashMap::new(),
        }
    }

    /// Records that the object at `(dev, ino)` has the given content checksum.
    pub fn insert(&mut self, dev: u64, ino: u64, checksum: Checksum) {
        self.map.insert((dev, ino), checksum);
    }

    /// Returns the checksum recorded for `(dev, ino)`, if there is one.
    pub fn get(&self, dev: u64, ino: u64) -> Option<Checksum> {
        self.map.get(&(dev, ino)).copied()
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the cache has no entries.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Methods that build a device and inode cache.
impl Repo {
    /// Builds a [`DevInoCache`] from the uncompressed loose content objects.
    ///
    /// Each `objects/<xx>/<62hex>.file` entry that is a regular file or a
    /// symlink adds its `(st_dev, st_ino)` and the checksum that its name
    /// spells. The scan reads lower-case hex names only. If a checkout
    /// hardlinks these objects into a destination tree, the cache resolves the
    /// files of that tree, whatever process made the checkout.
    ///
    /// An `archive` repository stores each content object compressed
    /// (`.filez`), so its cache is empty.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`](crate::Error::Io) if the read of `objects/` or of a
    ///   fanout directory fails.
    /// - [`Error::Io`](crate::Error::Io) if the open of a fanout directory
    ///   fails with an error other than `ENOENT`.
    pub async fn devino_cache(&self) -> Result<DevInoCache> {
        let repo = self.clone();
        ostrya_rt::unblock(move || devino_cache_blocking(repo.objects_fd())).await
    }
}

/// Scans an `objects/` directory descriptor for loose uncompressed content
/// objects.
fn devino_cache_blocking(objects_fd: BorrowedFd<'_>) -> Result<DevInoCache> {
    let mut cache = DevInoCache::new();
    // The scan reads lower-case names only, because ostrya and the `ostree`
    // command write only these. An upper-case hex name folds to a checksum
    // that no writer produced. If the scan added such an entry, `-I` commits
    // that checksum for a source file hardlinked to the object. Only a writer
    // outside ostrya and the `ostree` command can make such a name, so no
    // test produces one.
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
            // A `bare` repository stores a symlink object as a symlink. A
            // hardlinking checkout links that inode into the destination, so
            // both file types can be one end of a hardlink pair with a source
            // entry. No other entry under `objects/` can.
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

/// A synchronous filter over the ingested paths.
pub type FilterFn = Box<dyn FnMut(&Path, &FileMeta) -> FilterResult + Send>;
/// A synchronous callback that replaces the recorded `st_mode` of an entry.
///
/// The returned value holds the file-type bits and the permission bits.
pub type ModeFn = Box<dyn FnMut(&Path, &FileMeta) -> u32 + Send>;
/// A synchronous callback that replaces the stored xattr set of an entry.
pub type XattrFn = Box<dyn FnMut(&Path, &FileMeta) -> Xattrs + Send>;
/// A synchronous callback that returns the SELinux label of an entry.
pub type LabelFn = Box<dyn FnMut(&Path, &FileMeta) -> Option<Vec<u8>> + Send>;

/// The stored name of the SELinux label xattr, in the NUL-terminated form on
/// disk.
const SELINUX_XATTR: &[u8] = b"security.selinux\0";

/// The options that shape what the walk of a directory commits.
///
/// Create a modifier with [`new`](CommitModifier::new), then set the fields.
/// [`Transaction::write_dfd_to_mtree`](crate::Transaction::write_dfd_to_mtree)
/// gives the order in which the walk applies them.
///
/// # Callbacks
///
/// The callbacks are synchronous `FnMut` closures in public boxed fields. The
/// walk calls each callback at most once for each path. It borrows the
/// modifier exclusively (`Option<&mut CommitModifier>`), so a callback can
/// change its own captured state. Each callback box is `Send`, so the modifier
/// and the walk future are `Send`.
pub struct CommitModifier {
    /// The flags that control the ingest.
    pub flags: CommitModifierFlags,
    /// The owner uid that each ingested entry records, in place of the uid of
    /// its source.
    ///
    /// The walk applies it after the
    /// [`CANONICAL_PERMISSIONS`](CommitModifierFlags::CANONICAL_PERMISSIONS)
    /// reduction and before the callbacks, so a declared id replaces the `0`
    /// of that flag.
    pub owner_uid: Option<u32>,
    /// The owner gid that each ingested entry records, by the rules of
    /// [`owner_uid`](CommitModifier::owner_uid).
    pub owner_gid: Option<u32>,
    /// A filter that the walk calls for each path to include or skip the
    /// entry.
    pub filter: Option<FilterFn>,
    /// A callback whose return value replaces the recorded `st_mode` of an
    /// entry.
    ///
    /// The callback runs after the
    /// [`CANONICAL_PERMISSIONS`](CommitModifierFlags::CANONICAL_PERMISSIONS)
    /// reduction and the declared ownership. It runs before the xattr callback
    /// and the SELinux label callback. Under `CANONICAL_PERMISSIONS`, the walk
    /// applies the reduction again to the returned mode, and the entry keeps
    /// the file type that the walk found.
    pub mode_callback: Option<ModeFn>,
    /// A callback whose return value replaces the stored xattr set of an
    /// entry.
    pub xattr_callback: Option<XattrFn>,
    /// A callback that returns the SELinux label of an entry.
    ///
    /// The walk removes the `security.selinux` xattr of the entry before the
    /// callback runs, so the returned label counts only once.
    pub label_callback: Option<LabelFn>,
    /// A devino cache that the walk looks up for each regular file and
    /// symlink.
    ///
    /// [`DevInoCache`] gives the rules for a hit, with and without
    /// [`DEVINO_CANONICAL`](CommitModifierFlags::DEVINO_CANONICAL).
    pub devino_cache: Option<DevInoCache>,
}

impl CommitModifier {
    /// Creates a modifier with the given flags, no declared ownership, and no
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

/// The declared ownership that a walk applies to each entry.
///
/// The walk reads it from the modifier once, so the adjustment of each entry
/// holds no borrow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Owner {
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
}

impl Owner {
    /// Returns the ownership that `modifier` declares, or no ownership for
    /// `None`.
    pub(crate) fn of(modifier: Option<&CommitModifier>) -> Owner {
        modifier.map_or(Owner::default(), |m| Owner {
            uid: m.owner_uid,
            gid: m.owner_gid,
        })
    }

    /// Replaces the ids in `meta` with the declared ids.
    pub(crate) fn apply(self, meta: &mut FileMeta) {
        if let Some(uid) = self.uid {
            meta.uid = uid;
        }
        if let Some(gid) = self.gid {
            meta.gid = gid;
        }
    }
}

/// Returns a copy of an xattr set without its `security.selinux` entry.
///
/// The label callback step uses it, so an existing label counts only once.
pub(crate) fn without_selinux(xattrs: &Xattrs) -> ostrya_core::Result<Xattrs> {
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = xattrs
        .iter()
        .filter(|(name, _)| *name != SELINUX_XATTR)
        .map(|(name, value)| (name.to_vec(), value.to_vec()))
        .collect();
    Xattrs::new(pairs)
}

/// Returns a copy of an xattr set with a `security.selinux` entry that holds
/// `label`, in place of an existing one.
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
