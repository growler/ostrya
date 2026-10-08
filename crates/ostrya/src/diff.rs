//! The comparison of two trees.
//!
//! [`Repo::diff`] compares two sides and returns the paths that changed. Each
//! side is a commit in the repository or a directory on the file system, as
//! [`DiffSide`] states. [`Repo::diff_commits`] compares two commits with the
//! default options. [`Repo::diff_stats`] returns the object counts and the
//! shared size of two commits.

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use futures_lite::AsyncReadExt;
use futures_lite::future::zip;
use ostrya_core::{
    Checksum, ContentHasher, DirMeta, DirTree, FileHeader, ObjectName, Xattrs, loose_path,
};
use ostrya_rt::FileReader;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::ingest::{adjust_meta, to_dirmeta};
use crate::modifier::{CommitModifierFlags, Owner};
use crate::object;
use crate::repo::Repo;
use crate::write::FileMeta;

/// The size of the payload chunk that hashes a local file. A file of any size
/// uses a fixed amount of memory.
const HASH_CHUNK: usize = 64 * 1024;

/// The kind of change to a path between two sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffChange {
    /// The path exists only on the second side.
    Added,
    /// The path exists only on the first side.
    Removed,
    /// The path exists on both sides, and its stored form or its type differs.
    Modified,
}

/// One entry in the result of a comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    /// The kind of change.
    pub change: DiffChange,
    /// The absolute path in the tree, for example `/etc/hostname`.
    ///
    /// An [`Added`](DiffChange::Added) path names an entry of the second side.
    /// A [`Modified`](DiffChange::Modified) or [`Removed`](DiffChange::Removed)
    /// path names an entry of the first side.
    ///
    /// If the name of an entry on a directory side is not valid UTF-8, this
    /// field holds a lossy conversion of the name. Each byte sequence that is
    /// not valid UTF-8 becomes U+FFFD.
    pub path: String,
}

/// One side of a comparison.
#[derive(Debug, Clone, Copy)]
pub enum DiffSide<'a> {
    /// A commit in the repository.
    Commit(&'a Checksum),
    /// A directory on the file system.
    Directory(&'a Path),
}

/// The options that control how [`Repo::diff`] reads the two sides.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiffOptions {
    /// If `true`, the comparison reads no extended attributes from a directory
    /// side.
    ///
    /// This option does not change a commit side. Its objects hold the
    /// extended attributes of the commit.
    pub skip_xattrs: bool,
    /// The user id of each entry of the `to` side, if that side is a directory.
    ///
    /// `None` keeps the user id that the file system returns.
    pub owner_uid: Option<u32>,
    /// The group id of each entry of the `to` side, if that side is a
    /// directory.
    ///
    /// `None` keeps the group id that the file system returns.
    pub owner_gid: Option<u32>,
}

/// The object counts and the shared size of two commits.
///
/// [`Repo::diff_stats`] states which objects the object set of a commit holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffStats {
    /// The number of objects in the object set of the first commit.
    pub from_objects: usize,
    /// The number of objects in the object set of the second commit.
    pub to_objects: usize,
    /// The number of objects in the intersection of the two sets.
    pub common_objects: usize,
    /// The sum of the on-disk sizes of the loose object files in the
    /// intersection.
    pub common_bytes: u64,
}

/// One directory of one side, ready for a listing.
enum Side {
    /// A directory of a commit, named by its dirtree object.
    Repo(Checksum),
    /// A directory on the file system.
    Local(LocalDir),
}

/// A directory on the file system, named by its path below the root of the
/// side.
///
/// Only the root stays open. Each read below the root opens what it needs from
/// the root descriptor by `rel`, and then closes it. A walk of any depth holds
/// one descriptor for each side.
struct LocalDir {
    root: Arc<OwnedFd>,
    /// The path below the root. It is empty at the root.
    rel: PathBuf,
    /// The path from the argument to this directory. A read failure names
    /// this path.
    path: PathBuf,
}

impl LocalDir {
    /// Returns the name that `openat` uses for this directory from the root
    /// descriptor.
    fn at(&self) -> &Path {
        if self.rel.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &self.rel
        }
    }

    /// Returns the subdirectory `name`. It opens nothing.
    fn child(&self, name: &OsStr) -> LocalDir {
        LocalDir {
            root: self.root.clone(),
            rel: self.rel.join(name),
            path: self.path.join(name),
        }
    }
}

/// One entry of one directory, in the order of its side.
struct SideEntry {
    name: OsString,
    kind: EntryKind,
}

/// The entries of one directory as its side lists them. The comparison then
/// decides which entries it reads further.
enum SideList {
    /// A committed directory. The listing holds all data of each entry.
    Repo(Vec<SideEntry>),
    /// A directory on the file system, listed with no extended attributes.
    Local(Vec<RawEntry>),
}

impl SideList {
    /// Returns each entry name with its comparison class, in listing order.
    fn classes(&self) -> Vec<(&OsStr, Class)> {
        match self {
            SideList::Repo(entries) => entries
                .iter()
                .map(|entry| {
                    let class = match entry.kind {
                        EntryKind::Dir { .. } => Class::Dir,
                        _ => Class::Content,
                    };
                    (entry.name.as_os_str(), class)
                })
                .collect(),
            SideList::Local(raw) => raw
                .iter()
                .map(|entry| (entry.name.as_os_str(), entry.kind.class()))
                .collect(),
        }
    }
}

/// The data that the comparison uses for one entry.
enum EntryKind {
    /// A regular file or a symlink of a commit. The dirtree object holds its
    /// content object checksum.
    Content(Checksum),
    /// A directory of a commit, with its dirmeta checksum and the dirtree
    /// object for the descent.
    Dir { meta: Checksum, dirtree: Checksum },
    /// A regular file on the file system. The comparison reads the payload
    /// only if the metadata and the size do not decide the pair.
    File { meta: FileMeta, size: u64 },
    /// A symlink on the file system, with the target bytes that the file
    /// system returned.
    Symlink { meta: FileMeta, target: Vec<u8> },
    /// A directory on the file system.
    LocalDir { meta: FileMeta },
    /// A device, a fifo, or a socket.
    Other(FileMeta),
}

/// The comparison class of an entry. The comparison reads two entries of one
/// name further only if their classes pair.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A directory, on a side of either kind.
    Dir,
    /// A regular file or a symlink of a commit. A dirtree object names both
    /// kinds by one checksum and does not tell them apart.
    Content,
    /// A regular file on the file system.
    File,
    /// A symlink on the file system.
    Symlink,
    /// A device, a fifo, or a socket.
    Other,
}

/// Returns `true` if two classes pair. Only then does the comparison read
/// either entry further. Two entries that do not pair are one modification,
/// which the listing alone decides.
fn classes_pair(left: Class, right: Class) -> bool {
    matches!(
        (left, right),
        (Class::Dir, Class::Dir)
            | (Class::Other, Class::Other)
            | (Class::File, Class::File)
            | (Class::Symlink, Class::Symlink)
            | (
                Class::Content,
                Class::Content | Class::File | Class::Symlink
            )
            | (Class::File | Class::Symlink, Class::Content)
    )
}

/// The three lists that a walk fills, each in walk order.
#[derive(Default)]
struct Lists {
    modified: Vec<String>,
    removed: Vec<String>,
    added: Vec<String>,
}

/// The boxed future that one level of the walk returns. Async recursion needs
/// this indirection.
type WalkFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Methods that compare two trees.
impl Repo {
    /// Compares two sides and returns the paths that changed.
    ///
    /// The classification and the order match the observed output of the
    /// `ostree diff` command.
    ///
    /// # Classification
    ///
    /// - If a regular file or a symlink is on both sides and its content object
    ///   checksum differs, the path is [`Modified`](DiffChange::Modified). This
    ///   checksum covers the uid, the gid, the mode, the extended attributes,
    ///   the symlink target, and the payload.
    /// - If a directory is on both sides and its dirmeta checksum differs, the
    ///   path is [`Modified`](DiffChange::Modified). The comparison also
    ///   descends into the directory to find the changes below it.
    /// - A device, a fifo, or a socket has no change kind of its own. If such
    ///   an entry is on both sides and its uid, gid, mode, or extended
    ///   attributes differ, the path is [`Modified`](DiffChange::Modified).
    /// - If the type of a name differs between the two sides, the path is one
    ///   [`Modified`](DiffChange::Modified) entry. The comparison does not
    ///   descend into it.
    /// - If a name is only on the second side, the path is
    ///   [`Added`](DiffChange::Added). An added directory gives one entry for
    ///   itself and one entry for each entry below it, at each depth.
    /// - If a name is only on the first side, the path is
    ///   [`Removed`](DiffChange::Removed). A removed directory gives one entry,
    ///   with no entries for its children.
    ///
    /// The comparison does not include the metadata of the root directory.
    ///
    /// # Order
    ///
    /// The result holds the [`Modified`](DiffChange::Modified) entries first,
    /// then the [`Removed`](DiffChange::Removed) entries, then the
    /// [`Added`](DiffChange::Added) entries. The `ostree diff` command prints
    /// the groups in this order. In each group, the entries are in the order
    /// in which the walk finds them.
    ///
    /// At each pair of directories with the same name, the walk does these
    /// steps:
    ///
    /// 1. It reads the entries of the first side in the order of that side. It
    ///    descends into each pair of directories at the position of the pair.
    /// 2. It reads the entries of the second side in the order of that side.
    ///
    /// The order of a commit side is the files of the directory in stored
    /// order, then the subdirectories in stored order. The order of a
    /// directory side is the order in which the directory returns its
    /// entries.
    ///
    /// # Directory side
    ///
    /// A commit side reads the checksums that its dirtree objects hold. It
    /// reads no payload. A directory side reads only the data that the
    /// comparison needs.
    ///
    /// Two entries of one name pair if both are directories, both are regular
    /// files, or both are symlinks. Two devices, fifos, or sockets also pair. A
    /// file or a symlink of a commit side pairs with a regular file or a
    /// symlink of a directory side.
    ///
    /// - A directory side reads the extended attributes of a name only if both
    ///   sides hold the name and the two entries pair. It does not open an
    ///   entry that only one side holds, or two entries that do not pair.
    /// - It computes a content object checksum only for a pair that the known
    ///   data does not decide. If two local entries differ in uid, gid, mode,
    ///   extended attributes, or size, this difference decides the pair.
    /// - If these values agree for two local regular files, the comparison
    ///   streams both payloads through a fixed buffer, and the two checksums
    ///   decide. Two local symlinks compare their metadata and their targets.
    /// - A local regular file against a committed object always streams the
    ///   local payload, and the checksum decides.
    ///
    /// A directory side holds one descriptor for its root. It opens each entry
    /// below the root from this descriptor, by the relative path that the walk
    /// builds. The number of open descriptors does not grow with the depth of
    /// the tree.
    ///
    /// A directory side keeps entry names and symlink targets as the bytes
    /// that the file system returns. It compares, descends into, and lists a
    /// name that is not valid UTF-8. [`DiffEntry::path`] states how the result
    /// holds such a name. If the target of a local symlink is not valid UTF-8,
    /// the symlink differs from each committed file or symlink.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if a commit side names a commit that the
    ///   repository does not hold, or if a dirtree that the walk reads is
    ///   absent.
    /// - [`Error::Core`] if a commit or a dirtree does not parse.
    /// - [`Error::InvalidFormat`] if the name of an extended attribute on a
    ///   directory side is not valid UTF-8.
    /// - [`Error::Io`] if a read of the repository fails. This includes a
    ///   commit or a dirtree that is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or that is not a
    ///   regular file.
    /// - [`Error::Io`] if a read of a directory side fails. The message has the
    ///   form `call(path): reason`, for example
    ///   `open(/srv/tree/etc/shadow): Permission denied`. The call is
    ///   `opendir`, `readdir`, `stat`, `readlink`, `open`, or `getxattr`.
    pub async fn diff(
        &self,
        from: DiffSide<'_>,
        to: DiffSide<'_>,
        options: &DiffOptions,
    ) -> Result<Vec<DiffEntry>> {
        let from_root = self.open_side(from).await?;
        let to_root = self.open_side(to).await?;

        let mut lists = Lists::default();
        walk(
            self,
            from_root,
            to_root,
            OsString::new(),
            options,
            &mut lists,
        )
        .await?;

        let mut out =
            Vec::with_capacity(lists.modified.len() + lists.removed.len() + lists.added.len());
        out.extend(entries(DiffChange::Modified, lists.modified));
        out.extend(entries(DiffChange::Removed, lists.removed));
        out.extend(entries(DiffChange::Added, lists.added));
        Ok(out)
    }

    /// Compares the trees of two commits and returns the paths that changed.
    ///
    /// This call is [`diff`](Repo::diff) with two [`Commit`](DiffSide::Commit)
    /// sides and the default options.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the repository does not hold `from` or
    ///   `to`, or if a dirtree that the walk reads is absent.
    /// - [`Error::Core`] if a commit or a dirtree does not parse.
    /// - [`Error::Io`] if a read of the repository fails. This includes a
    ///   commit or a dirtree that is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or that is not a
    ///   regular file.
    pub async fn diff_commits(&self, from: &Checksum, to: &Checksum) -> Result<Vec<DiffEntry>> {
        self.diff(
            DiffSide::Commit(from),
            DiffSide::Commit(to),
            &DiffOptions::default(),
        )
        .await
    }

    /// Returns the object counts and the shared size of two commits.
    ///
    /// Each count is the number of objects in the object set of one commit.
    /// This set holds these objects:
    ///
    /// - the commit object
    /// - the root dirmeta object
    /// - each dirtree object and each other dirmeta object
    /// - each content object that the tree of the commit reaches
    ///
    /// The set does not hold the parent commits or the detached metadata
    /// object.
    ///
    /// [`common_bytes`](DiffStats::common_bytes) is the sum of the on-disk
    /// sizes of the loose object files in the intersection of the two sets. In
    /// an `archive` repository, this sum counts the compressed size. In a
    /// `bare` repository, it counts the payload size.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the repository does not hold `from` or
    ///   `to`.
    /// - [`Error::ObjectNotFound`] if the repository does not hold an object of
    ///   the intersection.
    /// - [`Error::Core`] if a commit or a dirtree does not parse.
    /// - [`Error::Io`] if a read of the object store fails. This includes a
    ///   commit or a dirtree that is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or that is not a
    ///   regular file.
    pub async fn diff_stats(&self, from: &Checksum, to: &Checksum) -> Result<DiffStats> {
        let from_set = self.traverse_commit(from, 0).await?;
        let to_set = self.traverse_commit(to, 0).await?;
        let common: Vec<ObjectName> = from_set.intersection(&to_set).copied().collect();
        let common_objects = common.len();
        // One pass on the blocking pool sizes the whole intersection. The cost
        // is one dispatch for all objects.
        let repo = self.clone();
        let mode = self.mode();
        let common_bytes = ostrya_rt::unblock(move || {
            let dir = repo.objects_fd();
            let mut total = 0u64;
            for name in &common {
                let path = loose_path(&name.checksum, name.ty, mode);
                match object::object_size(dir, &path) {
                    Ok(size) => total += size,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        return Err(Error::ObjectNotFound {
                            checksum: name.checksum,
                            ty: name.ty,
                        });
                    }
                    Err(err) => return Err(Error::Io(err)),
                }
            }
            Ok(total)
        })
        .await?;
        Ok(DiffStats {
            from_objects: from_set.len(),
            to_objects: to_set.len(),
            common_objects,
            common_bytes,
        })
    }

    /// Opens the root directory of one side.
    async fn open_side(&self, side: DiffSide<'_>) -> Result<Side> {
        match side {
            DiffSide::Commit(commit) => {
                let (commit, _) = self.load_commit(commit).await?;
                Ok(Side::Repo(commit.root_dirtree))
            }
            DiffSide::Directory(path) => {
                let owned = path.to_path_buf();
                let fd = ostrya_rt::unblock(move || {
                    rustix::fs::open(
                        &owned,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|err| path_error("opendir", &owned, err))
                })
                .await?;
                Ok(Side::Local(LocalDir {
                    root: Arc::new(fd),
                    rel: PathBuf::new(),
                    path: path.to_path_buf(),
                }))
            }
        }
    }
}

/// Compares one pair of directories with the same name and records the
/// differences.
///
/// The first pass reads the entries of `from` in the order of that side. It
/// descends into each pair of directories at the position of the pair. The
/// second pass reads the entries of `to` in the order of that side. It records
/// the entries that `from` does not hold.
fn walk<'a>(
    repo: &'a Repo,
    from: Side,
    to: Side,
    prefix: OsString,
    options: &'a DiffOptions,
    out: &'a mut Lists,
) -> WalkFuture<'a> {
    Box::pin(async move {
        // The walk lists both sides before it reads either side further. It
        // reads extended attributes only for the names that both sides hold
        // with kinds that pair. The walk names an entry that only one side
        // holds without an open. The same applies to a name with two kinds
        // that do not pair. As a result, the walk can list an added file that
        // the process cannot read. It can also report a type change over an
        // entry that the process cannot read.
        let (from_list, to_list) = zip(read_list(repo, &from), read_list(repo, &to)).await;
        let (from_list, to_list) = (from_list?, to_list?);
        let wanted = paired_names(&from_list, &to_list, options);
        let (from_entries, to_entries) = zip(
            shape(&from, from_list, &wanted, options, Owner::default()),
            shape(&to, to_list, &wanted, options, to_owner(options)),
        )
        .await;
        let (from_entries, to_entries) = (from_entries?, to_entries?);

        let index: HashMap<&OsStr, usize> = to_entries
            .iter()
            .enumerate()
            .map(|(at, entry)| (entry.name.as_os_str(), at))
            .collect();
        let held: HashSet<&OsStr> = from_entries
            .iter()
            .map(|entry| entry.name.as_os_str())
            .collect();

        for entry in &from_entries {
            let path = join(&prefix, &entry.name);
            let Some(other) = index.get(entry.name.as_os_str()).map(|at| &to_entries[*at]) else {
                out.removed.push(render(&path));
                continue;
            };
            match (&entry.kind, &other.kind) {
                // A directory on both sides.
                (
                    EntryKind::Dir { .. } | EntryKind::LocalDir { .. },
                    EntryKind::Dir { .. } | EntryKind::LocalDir { .. },
                ) => {
                    if dirmeta_differs(&entry.kind, &other.kind)? {
                        out.modified.push(render(&path));
                    }
                    // If two commit sides name one dirtree object, they hold
                    // the same subtree. The descent finds nothing there.
                    if let (
                        EntryKind::Dir { dirtree: left, .. },
                        EntryKind::Dir { dirtree: right, .. },
                    ) = (&entry.kind, &other.kind)
                        && left == right
                    {
                        continue;
                    }
                    let child_from = descend(&from, entry)?;
                    let child_to = descend(&to, other)?;
                    walk(repo, child_from, child_to, path, options, out).await?;
                }
                // A device, a fifo, or a socket on both sides.
                (EntryKind::Other(left), EntryKind::Other(right)) => {
                    if !meta_eq(left, right) {
                        out.modified.push(render(&path));
                    }
                }
                // Two local regular files. If the listing already holds a
                // difference, this difference decides the pair, and the walk
                // reads no payload. Equal sizes decide nothing, so the walk
                // hashes both payloads.
                (
                    EntryKind::File {
                        meta: left,
                        size: left_size,
                    },
                    EntryKind::File {
                        meta: right,
                        size: right_size,
                    },
                ) => {
                    if !meta_eq(left, right) || left_size != right_size {
                        out.modified.push(render(&path));
                    } else {
                        let (a, b) = zip(
                            hash_local_file(&from, &entry.name, left, *left_size),
                            hash_local_file(&to, &entry.name, right, *right_size),
                        )
                        .await;
                        if a? != b? {
                            out.modified.push(render(&path));
                        }
                    }
                }
                // Two local symlinks. The metadata and the target are the full
                // stored form, so the walk opens neither side.
                (
                    EntryKind::Symlink {
                        meta: left,
                        target: left_target,
                    },
                    EntryKind::Symlink {
                        meta: right,
                        target: right_target,
                    },
                ) => {
                    if !meta_eq(left, right) || left_target != right_target {
                        out.modified.push(render(&path));
                    }
                }
                // A file or a symlink against a committed content object. The
                // checksums decide the pair.
                (
                    EntryKind::Content(_),
                    EntryKind::Content(_) | EntryKind::File { .. } | EntryKind::Symlink { .. },
                )
                | (EntryKind::File { .. } | EntryKind::Symlink { .. }, EntryKind::Content(_)) => {
                    let (left, right) = zip(
                        content_checksum(&from, &entry.name, &entry.kind),
                        content_checksum(&to, &entry.name, &other.kind),
                    )
                    .await;
                    match (left?, right?) {
                        (Some(left), Some(right)) if left == right => {}
                        _ => out.modified.push(render(&path)),
                    }
                }
                // If the type of a name differs between the two sides, the
                // name is one entry. The comparison does not descend into it.
                _ => out.modified.push(render(&path)),
            }
        }

        for entry in &to_entries {
            if held.contains(entry.name.as_os_str()) {
                continue;
            }
            let path = join(&prefix, &entry.name);
            out.added.push(render(&path));
            if matches!(
                entry.kind,
                EntryKind::Dir { .. } | EntryKind::LocalDir { .. }
            ) {
                let child = descend(&to, entry)?;
                collect_added(repo, child, path, options, out).await?;
            }
        }
        Ok(())
    })
}

/// Records each entry of an added directory, in the order of its side.
///
/// It descends into each subdirectory at the position of the subdirectory.
fn collect_added<'a>(
    repo: &'a Repo,
    dir: Side,
    prefix: OsString,
    options: &'a DiffOptions,
    out: &'a mut Lists,
) -> WalkFuture<'a> {
    Box::pin(async move {
        // The walk lists an added subtree and does not compare it. It opens
        // no entry of the subtree and reads no extended attribute of it.
        let list = read_list(repo, &dir).await?;
        let entries = shape(&dir, list, &HashSet::new(), options, to_owner(options)).await?;
        for entry in &entries {
            let path = join(&prefix, &entry.name);
            out.added.push(render(&path));
            if matches!(
                entry.kind,
                EntryKind::Dir { .. } | EntryKind::LocalDir { .. }
            ) {
                let child = descend(&dir, entry)?;
                collect_added(repo, child, path, options, out).await?;
            }
        }
        Ok(())
    })
}

/// Returns the names that both sides hold with kinds that pair.
///
/// The comparison reads the extended attributes of these names. The set is
/// empty if no side is a directory side or if `skip_xattrs` is set.
fn paired_names(from: &SideList, to: &SideList, options: &DiffOptions) -> HashSet<OsString> {
    let local = matches!(from, SideList::Local(_)) || matches!(to, SideList::Local(_));
    if options.skip_xattrs || !local {
        return HashSet::new();
    }
    let to_classes: HashMap<&OsStr, Class> = to.classes().into_iter().collect();
    from.classes()
        .into_iter()
        .filter(|(name, class)| {
            to_classes
                .get(name)
                .is_some_and(|other| classes_pair(*class, *other))
        })
        .map(|(name, _)| name.to_owned())
        .collect()
}

/// Returns the path of one entry in the directory at `prefix`.
fn join(prefix: &OsStr, name: &OsStr) -> OsString {
    let mut path = prefix.to_owned();
    path.push("/");
    path.push(name);
    path
}

/// Returns one path in the form that [`DiffEntry`] holds.
///
/// This function converts a name of a directory side that is not valid UTF-8
/// with a lossy conversion. It is the one place where the byte form is lost.
fn render(path: &OsStr) -> String {
    path.to_string_lossy().into_owned()
}

/// Returns the ownership that applies to a directory side on the `to` side.
///
/// The ownership does not apply to the first side or to a commit side.
fn to_owner(options: &DiffOptions) -> Owner {
    Owner {
        uid: options.owner_uid,
        gid: options.owner_gid,
    }
}

/// Returns `true` if two metadata sets record the same entry.
fn meta_eq(a: &FileMeta, b: &FileMeta) -> bool {
    a.uid == b.uid && a.gid == b.gid && a.mode == b.mode && a.xattrs == b.xattrs
}

/// Returns `true` if the two directory metadata records differ.
///
/// The function compares two local directories directly. For a commit, it
/// builds the dirmeta checksum of the local directory and compares it with the
/// checksum that the commit records.
fn dirmeta_differs(left: &EntryKind, right: &EntryKind) -> Result<bool> {
    match (left, right) {
        (EntryKind::Dir { meta: a, .. }, EntryKind::Dir { meta: b, .. }) => Ok(a != b),
        (EntryKind::LocalDir { meta: a }, EntryKind::LocalDir { meta: b }) => Ok(!meta_eq(a, b)),
        (EntryKind::Dir { meta: a, .. }, EntryKind::LocalDir { meta: b })
        | (EntryKind::LocalDir { meta: b }, EntryKind::Dir { meta: a, .. }) => {
            Ok(*a != dirmeta_checksum(&to_dirmeta(b))?)
        }
        _ => Err(Error::InvalidFormat(
            "a directory metadata comparison outside a pair of directories".into(),
        )),
    }
}

/// Lists the entries of one directory in the order of its side.
///
/// It reads no extended attributes and opens nothing below the directory.
async fn read_list(repo: &Repo, side: &Side) -> Result<SideList> {
    match side {
        Side::Repo(dirtree) => Ok(SideList::Repo(repo_entries(
            &repo.load_dirtree(dirtree).await?,
        ))),
        Side::Local(dir) => {
            let root = dir.root.clone();
            let at = dir.at().to_path_buf();
            let path = dir.path.clone();
            let raw = ostrya_rt::unblock(move || {
                let fd = rustix::fs::openat(
                    root.as_fd(),
                    &at,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|err| path_error("opendir", &path, err))?;
                snapshot_dir(fd.as_fd(), &path)
            })
            .await?;
            Ok(SideList::Local(raw))
        }
    }
}

/// Turns a listing into the form that the comparison reads.
///
/// It reads the extended attributes of the entries in `wanted` and of no other
/// entries.
async fn shape(
    side: &Side,
    list: SideList,
    wanted: &HashSet<OsString>,
    options: &DiffOptions,
    owner: Owner,
) -> Result<Vec<SideEntry>> {
    let raw = match list {
        SideList::Repo(entries) => return Ok(entries),
        SideList::Local(raw) => raw,
    };
    let Side::Local(dir) = side else {
        return Err(Error::InvalidFormat(
            "a filesystem listing outside a directory side".into(),
        ));
    };

    let mut xattrs: HashMap<usize, Xattrs> = HashMap::new();
    if !options.skip_xattrs {
        let asked: Vec<(usize, OsString)> = raw
            .iter()
            .enumerate()
            .filter(|(_, entry)| wanted.contains(entry.name.as_os_str()))
            .map(|(at, entry)| (at, entry.name.clone()))
            .collect();
        if !asked.is_empty() {
            let root = dir.root.clone();
            let rel = dir.rel.clone();
            let path = dir.path.clone();
            xattrs =
                ostrya_rt::unblock(move || read_xattrs(root.as_fd(), &rel, &path, asked)).await?;
        }
    }

    Ok(raw
        .into_iter()
        .enumerate()
        .map(|(at, entry)| {
            local_entry(
                entry,
                xattrs.remove(&at).unwrap_or_else(Xattrs::empty),
                owner,
            )
        })
        .collect())
}

/// Returns the entries of one committed directory.
///
/// The files come first in stored order, then the subdirectories in stored
/// order.
fn repo_entries(dirtree: &DirTree) -> Vec<SideEntry> {
    let mut entries = Vec::with_capacity(dirtree.files.len() + dirtree.dirs.len());
    for (name, checksum) in &dirtree.files {
        entries.push(SideEntry {
            name: OsString::from(name.clone()),
            kind: EntryKind::Content(*checksum),
        });
    }
    for (name, sub, meta) in &dirtree.dirs {
        entries.push(SideEntry {
            name: OsString::from(name.clone()),
            kind: EntryKind::Dir {
                meta: *meta,
                dirtree: *sub,
            },
        });
    }
    entries
}

/// Turns one file system entry into the form that the comparison reads.
///
/// The entry gets the extended attributes that the comparison asked for.
fn local_entry(raw: RawEntry, xattrs: Xattrs, owner: Owner) -> SideEntry {
    let base = FileMeta {
        uid: raw.uid,
        gid: raw.gid,
        mode: raw.mode,
        xattrs,
    };
    let is_symlink = matches!(raw.kind, RawKind::Symlink(_));
    let meta = adjust_meta(CommitModifierFlags::empty(), owner, base, is_symlink);
    let kind = match raw.kind {
        RawKind::Dir => EntryKind::LocalDir { meta },
        RawKind::Regular => EntryKind::File {
            meta,
            size: raw.size,
        },
        RawKind::Symlink(target) => EntryKind::Symlink { meta, target },
        RawKind::Other => EntryKind::Other(meta),
    };
    SideEntry {
        name: raw.name,
        kind,
    }
}

/// Returns the checksum of a dirmeta object built from `meta`.
///
/// The checksum is the SHA-256 of the serialized normal form. A directory side
/// compares it with the checksum that a commit records.
fn dirmeta_checksum(meta: &DirMeta) -> Result<Checksum> {
    Ok(Checksum::from_bytes(
        Sha256::digest(meta.serialize()?).into(),
    ))
}

/// Returns the content object checksum of one entry.
///
/// For a file system entry, the function computes the checksum. For a
/// committed entry, it reads the checksum from the dirtree object.
///
/// If the target of a local symlink is not valid UTF-8, the symlink has no
/// content object form, and the function returns `None`. A committed target is
/// always valid UTF-8, so such an entry differs from each committed object.
async fn content_checksum(side: &Side, name: &OsStr, kind: &EntryKind) -> Result<Option<Checksum>> {
    match kind {
        EntryKind::Content(checksum) => Ok(Some(*checksum)),
        EntryKind::File { meta, size } => Ok(Some(hash_local_file(side, name, meta, *size).await?)),
        EntryKind::Symlink { meta, target } => {
            let Ok(target) = std::str::from_utf8(target) else {
                return Ok(None);
            };
            // The header of a symlink holds its target, so there is no
            // payload to read.
            let header = local_header(meta, target);
            Ok(Some(ContentHasher::new(&header)?.finish()))
        }
        _ => Err(Error::InvalidFormat(
            "a directory compared as a content object".into(),
        )),
    }
}

/// Returns the content object header of one file system entry.
fn local_header(meta: &FileMeta, symlink_target: &str) -> FileHeader {
    FileHeader {
        uid: meta.uid,
        gid: meta.gid,
        mode: meta.mode,
        symlink_target: symlink_target.to_owned(),
        xattrs: meta.xattrs.clone(),
    }
}

/// Hashes a local regular file as a content object.
///
/// The function streams the payload through a fixed buffer. It writes nothing
/// to the repository.
///
/// The open and the first chunk share one dispatch. If the file is not longer
/// than one chunk, this dispatch reads it to its end. `size` is the size that
/// the walk read. It sets the limit of the read-ahead for the rest of the file.
async fn hash_local_file(
    side: &Side,
    name: &OsStr,
    meta: &FileMeta,
    size: u64,
) -> Result<Checksum> {
    let Side::Local(dir) = side else {
        return Err(Error::InvalidFormat(
            "a filesystem entry outside a directory side".into(),
        ));
    };
    let mut hasher = ContentHasher::new(&local_header(meta, ""))?;
    let root = dir.root.clone();
    let at = dir.rel.join(name);
    let path = dir.path.join(name);
    let (rest, mut buf, filled) =
        ostrya_rt::unblock(move || open_and_read(root.as_fd(), &at, &path)).await?;
    hasher.update(&buf[..filled]);
    if let Some(fd) = rest {
        let rest_len = size.saturating_sub(filled as u64);
        let mut file = FileReader::with_len_hint(fd.into(), rest_len);
        loop {
            let read = file.read(&mut buf).await.map_err(Error::Io)?;
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
        }
    }
    Ok(hasher.finish())
}

/// Opens one file below `root` and reads its first chunk.
///
/// If a read reports the end of the file in the chunk, the function returns no
/// descriptor. A file that is not longer than one chunk costs one dispatch in
/// all.
fn open_and_read(
    root: BorrowedFd<'_>,
    at: &Path,
    path: &Path,
) -> Result<(Option<OwnedFd>, Vec<u8>, usize)> {
    use std::io::Read;

    let fd = rustix::fs::openat(
        root,
        at,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| path_error("open", path, err))?;
    let mut file = std::fs::File::from(fd);
    let mut buf = vec![0u8; HASH_CHUNK];
    let mut filled = 0;
    while filled < HASH_CHUNK {
        let read = file.read(&mut buf[filled..]).map_err(Error::Io)?;
        if read == 0 {
            return Ok((None, buf, filled));
        }
        filled += read;
    }
    Ok((Some(OwnedFd::from(file)), buf, filled))
}

/// Returns the subdirectory that `entry` names, ready for a listing.
///
/// A directory side opens nothing here. The child holds the root descriptor and
/// the relative path, and the listing pass opens it.
fn descend(side: &Side, entry: &SideEntry) -> Result<Side> {
    match side {
        Side::Repo(_) => {
            let EntryKind::Dir { dirtree, .. } = &entry.kind else {
                return Err(Error::InvalidFormat(
                    "a committed directory with no directory tree object".into(),
                ));
            };
            Ok(Side::Repo(*dirtree))
        }
        Side::Local(dir) => Ok(Side::Local(dir.child(&entry.name))),
    }
}

/// One file system entry as the directory pass captured it.
struct RawEntry {
    name: OsString,
    kind: RawKind,
    uid: u32,
    gid: u32,
    /// The full `st_mode`, with the file-type bits.
    mode: u32,
    /// The payload length. A different length tells two regular files apart
    /// with no read.
    size: u64,
}

/// The kind of entry that a directory pass found.
enum RawKind {
    Dir,
    Regular,
    /// A symlink, with the target bytes that the file system returned.
    Symlink(Vec<u8>),
    /// A device, a fifo, or a socket. The comparison compares such an entry
    /// with another entry of its class and never reads it.
    Other,
}

impl RawKind {
    /// Returns the comparison class of this entry.
    fn class(&self) -> Class {
        match self {
            RawKind::Dir => Class::Dir,
            RawKind::Regular => Class::File,
            RawKind::Symlink(_) => Class::Symlink,
            RawKind::Other => Class::Other,
        }
    }
}

/// Captures the entries of one directory in one blocking pass.
///
/// The entries are in the order in which the directory returns them. The
/// function opens nothing below the directory. An entry that the comparison
/// never reads costs one `statat`, and for a symlink also one `readlinkat`.
fn snapshot_dir(dir: BorrowedFd<'_>, path: &Path) -> Result<Vec<RawEntry>> {
    let mut entries = Vec::new();
    for entry in Dir::read_from(dir).map_err(|err| path_error("opendir", path, err))? {
        let entry = entry.map_err(|err| path_error("readdir", path, err))?;
        let raw = entry.file_name();
        if raw == c"." || raw == c".." {
            continue;
        }
        let name = OsStr::from_bytes(raw.to_bytes()).to_owned();

        let stat = rustix::fs::statat(dir, raw, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|err| path_error("stat", &path.join(&name), err))?;
        let kind = match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => RawKind::Dir,
            FileType::RegularFile => RawKind::Regular,
            FileType::Symlink => RawKind::Symlink(
                rustix::fs::readlinkat(dir, raw, Vec::new())
                    .map_err(|err| path_error("readlink", &path.join(&name), err))?
                    .into_bytes(),
            ),
            _ => RawKind::Other,
        };

        entries.push(RawEntry {
            name,
            kind,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
            size: stat.st_size.max(0) as u64,
        });
    }
    Ok(entries)
}

/// Reads the extended attributes of the named entries in one blocking pass.
///
/// The key of each result is the position of the entry in the listing. Each
/// kind goes through the path-based no-follow reader. An entry that the
/// comparison later opens for its payload is opened only once.
fn read_xattrs(
    root: BorrowedFd<'_>,
    rel: &Path,
    path: &Path,
    asked: Vec<(usize, OsString)>,
) -> Result<HashMap<usize, Xattrs>> {
    let mut out = HashMap::with_capacity(asked.len());
    for (at, name) in asked {
        let xattrs = object::read_link_xattrs(root, rel.join(&name)).map_err(|err| match err {
            Error::Io(io) => path_error_io("getxattr", &path.join(&name), &io),
            other => other,
        })?;
        out.insert(at, xattrs);
    }
    Ok(out)
}

/// Returns an I/O error that names the path and the call of a failure.
fn path_error(call: &str, path: &Path, err: Errno) -> Error {
    path_error_io(call, path, &std::io::Error::from(err))
}

/// Returns the error of `path_error` for a failure that is already an
/// [`std::io::Error`].
fn path_error_io(call: &str, path: &Path, err: &std::io::Error) -> Error {
    let reason = err.to_string();
    let reason = match reason.find(" (os error ") {
        Some(cut) => &reason[..cut],
        None => reason.as_str(),
    };
    Error::Io(std::io::Error::new(
        err.kind(),
        format!("{call}({}): {reason}", path.display()),
    ))
}

/// Turns a list of paths into diff entries of one change kind.
fn entries(change: DiffChange, paths: Vec<String>) -> impl Iterator<Item = DiffEntry> {
    paths
        .into_iter()
        .map(move |path| DiffEntry { change, path })
}
