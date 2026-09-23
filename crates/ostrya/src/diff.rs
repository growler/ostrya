//! Comparing two trees.
//!
//! [`Repo::diff`] compares two sides -- a commit in the repository or a
//! directory on the filesystem -- and reports the paths that changed.
//! [`Repo::diff_commits`] is the two-commit case with the default options, and
//! [`Repo::diff_stats`] reports the object counts and the shared size of two
//! commits. The classification and the print order reproduce `ostree diff`
//! (recovered by black-box observation, and recorded in
//! `format-reference.md`, "CLI output formats", `diff`):
//!
//! - A regular file or a symlink present on both sides whose content object
//!   checksum differs is [`Modified`](DiffChange::Modified). That checksum
//!   covers the uid, the gid, the mode, the extended attributes, the symlink
//!   target, and the payload.
//! - A directory present on both sides whose directory metadata checksum
//!   differs is [`Modified`](DiffChange::Modified); the comparison still
//!   descends to find nested changes.
//! - A device, a fifo, and a socket carry no change kind of their own. Two of
//!   them compare on the uid, the gid, the mode, and the extended attributes.
//! - A name whose type differs between the two sides is a single
//!   [`Modified`](DiffChange::Modified) entry, with no descent into it.
//! - A name only on the second side is [`Added`](DiffChange::Added); an added
//!   directory lists itself and, recursively, every descendant.
//! - A name only on the first side is [`Removed`](DiffChange::Removed); a
//!   removed directory is a single entry, without its former children.
//!
//! The root directory's own metadata is outside the comparison.
//!
//! The returned entries are grouped as the tool prints them -- modified, then
//! removed, then added. Within one group the order is the order the walk found
//! the entries: at each pair of directories of one name the walk reads the
//! first side's entries in that side's own order, descending into a pair of
//! directories where it stands, and then reads the second side's entries in
//! that side's own order. A commit side's own order is the files of the
//! directory in stored order followed by the subdirectories in stored order; a
//! directory side's own order is the order the directory returns its entries
//! in.
//!
//! A commit side reads the checksums the directory tree objects hold, so no
//! payload is read for it. A directory side reads what the pairing needs and
//! nothing more:
//!
//! - the extended attributes of a name both sides hold whose two kinds pair,
//!   and of no other name, so a pair of differing kinds and an entry one side
//!   alone holds are named without being opened;
//! - a content object checksum for a pair a fact already in hand leaves
//!   undecided. Two local entries whose uid, gid, mode, extended attributes, or
//!   size differ are decided as they stand; where those agree, both payloads
//!   are streamed through a fixed buffer and the two checksums decide.
//!
//! A directory side holds one descriptor for its root and opens every entry
//! below it from that descriptor by the relative path the walk builds, so the
//! descriptor count does not follow the depth.
//!
//! A directory side's entry names and symlink targets are carried as the bytes
//! the filesystem returned, so a name that is not valid UTF-8 is compared,
//! descended into, and listed. [`DiffEntry::path`] is a `String`, so such a
//! name reaches it through a lossy conversion
//! (`docs/conformance/cli-surface.md`, "P2").

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
use ostrya_rt::File as RtFile;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::ingest::{adjust_meta, to_dirmeta};
use crate::modifier::{CommitModifierFlags, Owner};
use crate::object;
use crate::repo::Repo;
use crate::write::FileMeta;

/// The payload chunk a local file is hashed in, so a file of any size costs a
/// fixed amount of memory.
const HASH_CHUNK: usize = 64 * 1024;

/// The kind of change to a path between two sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffChange {
    /// The path exists only on the second side.
    Added,
    /// The path exists only on the first side.
    Removed,
    /// The path exists on both sides but its stored form differs.
    Modified,
}

/// One entry in a diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    /// What changed.
    pub change: DiffChange,
    /// The absolute path within the tree, for example `/etc/hostname`. The
    /// side that names it is the second side for [`Added`](DiffChange::Added)
    /// and the first side for the other two. A directory side's name that is
    /// not valid UTF-8 reaches this field through a lossy conversion.
    pub path: String,
}

/// One side of a comparison.
#[derive(Debug, Clone, Copy)]
pub enum DiffSide<'a> {
    /// A commit in the repository.
    Commit(&'a Checksum),
    /// A directory on the filesystem.
    Directory(&'a Path),
}

/// How the two sides are read.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiffOptions {
    /// Read no extended attributes from a directory side. A commit side is
    /// unaffected, its objects carrying the attributes they were committed
    /// with.
    pub skip_xattrs: bool,
    /// The user id given to the entries of the `to` side, where that side is a
    /// directory.
    pub owner_uid: Option<u32>,
    /// The group id given to the entries of the `to` side, on the same terms.
    pub owner_gid: Option<u32>,
}

/// The object counts and the shared size of two commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffStats {
    /// The size of the first commit's own object set.
    pub from_objects: usize,
    /// The size of the second commit's own object set.
    pub to_objects: usize,
    /// The size of the intersection of the two sets.
    pub common_objects: usize,
    /// The sum of the on-disk sizes of the loose object files of the
    /// intersection.
    pub common_bytes: u64,
}

/// One directory of one side, ready to enumerate.
enum Side {
    /// A directory of a commit, named by its directory tree object.
    Repo(Checksum),
    /// A directory on the filesystem.
    Local(LocalDir),
}

/// A directory on the filesystem, named by its path below the side's root.
///
/// Only the root is held open. Every read below it opens what it needs from the
/// root descriptor by `rel` and closes it again, so a walk of any depth holds
/// one descriptor per side.
struct LocalDir {
    root: Arc<OwnedFd>,
    /// The path below the root, empty at the root itself.
    rel: PathBuf,
    /// The path the argument reached this directory by, which a read failure
    /// names.
    path: PathBuf,
}

impl LocalDir {
    /// The name `openat` reaches this directory by from the root descriptor.
    fn at(&self) -> &Path {
        if self.rel.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &self.rel
        }
    }

    /// The subdirectory `name` names, opening nothing.
    fn child(&self, name: &OsStr) -> LocalDir {
        LocalDir {
            root: self.root.clone(),
            rel: self.rel.join(name),
            path: self.path.join(name),
        }
    }
}

/// One entry of one directory, in the order the side names it.
struct SideEntry {
    name: OsString,
    kind: EntryKind,
}

/// One directory's entries as its side names them, before the comparison
/// decides which of them must be read any further.
enum SideList {
    /// A committed directory, whose entries are complete as they are listed.
    Repo(Vec<SideEntry>),
    /// A directory on the filesystem, listed with no extended attributes.
    Local(Vec<RawEntry>),
}

impl SideList {
    /// Every entry name paired with the class it compares in, in listing order.
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

/// What one entry compares as.
enum EntryKind {
    /// A regular file or a symlink of a commit, whose content object checksum
    /// the directory tree object holds.
    Content(Checksum),
    /// A directory of a commit, with its metadata checksum and the directory
    /// tree object to descend into.
    Dir { meta: Checksum, dirtree: Checksum },
    /// A regular file on the filesystem. The payload is read only where the
    /// metadata and the size leave the pair undecided.
    File { meta: FileMeta, size: u64 },
    /// A symlink on the filesystem, with the target bytes the filesystem
    /// returned.
    Symlink { meta: FileMeta, target: Vec<u8> },
    /// A directory on the filesystem.
    LocalDir { meta: FileMeta },
    /// A device, a fifo, or a socket.
    Other(FileMeta),
}

/// The class an entry compares in. Two entries of one name are read any further
/// only where their classes pair.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A directory, on either kind of side.
    Dir,
    /// A regular file or a symlink of a commit, which a directory tree object
    /// names by one checksum and does not tell apart.
    Content,
    /// A regular file on the filesystem.
    File,
    /// A symlink on the filesystem.
    Symlink,
    /// A device, a fifo, or a socket.
    Other,
}

/// Whether two classes pair, which decides whether either side is read any
/// further. A pair that does not pair is one modification, reached from the
/// listing alone.
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

/// The three lists a walk fills, each in walk order.
#[derive(Default)]
struct Lists {
    modified: Vec<String>,
    removed: Vec<String>,
    added: Vec<String>,
}

/// The boxed future one level of the walk returns; async recursion needs the
/// indirection.
type WalkFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

impl Repo {
    /// Compare two sides and return the changed paths, in the order
    /// `ostree diff` prints them.
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

    /// Compare the trees of commits `from` and `to`, returning the changed
    /// paths. Equal to [`diff`](Repo::diff) over two
    /// [`Commit`](DiffSide::Commit) sides with the default options.
    pub async fn diff_commits(&self, from: &Checksum, to: &Checksum) -> Result<Vec<DiffEntry>> {
        self.diff(
            DiffSide::Commit(from),
            DiffSide::Commit(to),
            &DiffOptions::default(),
        )
        .await
    }

    /// The object counts and the shared size of two commits.
    ///
    /// Each count is the size of that commit's own object set: the commit
    /// object, the root directory metadata object, every directory tree
    /// object, every further directory metadata object, and every content
    /// object the commit's tree reaches. The set holds neither the commit's
    /// parents nor its detached metadata object. `common_bytes` sums the
    /// on-disk sizes of the loose object files of the intersection, so an
    /// `archive` repository counts the compressed size and a `bare` repository
    /// the payload size.
    pub async fn diff_stats(&self, from: &Checksum, to: &Checksum) -> Result<DiffStats> {
        let from_set = self.traverse_commit(from, 0).await?;
        let to_set = self.traverse_commit(to, 0).await?;
        let common: Vec<ObjectName> = from_set.intersection(&to_set).copied().collect();
        let common_objects = common.len();
        // The whole intersection is sized in one pass on the blocking pool, so
        // the cost is one dispatch and not one per object.
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

    /// Open one side's root directory.
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

/// Compare one pair of directories of the same name and record what differs.
///
/// The first pass reads `from`'s entries in that side's own order, descending
/// into a pair of directories where it stands. The second pass reads `to`'s
/// entries in that side's own order and records the ones `from` does not hold.
fn walk<'a>(
    repo: &'a Repo,
    from: Side,
    to: Side,
    prefix: OsString,
    options: &'a DiffOptions,
    out: &'a mut Lists,
) -> WalkFuture<'a> {
    Box::pin(async move {
        // Both sides are listed before either is read any further, so the
        // extended attributes are read for the names both sides hold whose two
        // kinds pair and for no other. An entry one side alone holds, and a
        // name the two sides hold at different kinds, is named without being
        // opened, which is what lets an unreadable added file be listed and a
        // type change be reported over an unreadable entry.
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
                    // Two commit sides naming one directory tree object hold
                    // the same subtree, so the descent would find nothing.
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
                // Two local regular files. A difference the listing already
                // holds decides the pair, so no payload is read to reach a
                // conclusion the metadata already carries. Equal sizes decide
                // nothing, so both payloads are hashed there.
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
                            hash_local_file(&from, &entry.name, left),
                            hash_local_file(&to, &entry.name, right),
                        )
                        .await;
                        if a? != b? {
                            out.modified.push(render(&path));
                        }
                    }
                }
                // Two local symlinks, whose whole stored form is the metadata
                // and the target, so neither side is opened.
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
                // A file or a symlink held against a committed content object,
                // which the checksums decide.
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
                // A name whose type differs between the two sides is one
                // entry, and the comparison does not descend into it.
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

/// Record every entry of an added directory, in that side's own order,
/// descending into each subdirectory where it stands.
fn collect_added<'a>(
    repo: &'a Repo,
    dir: Side,
    prefix: OsString,
    options: &'a DiffOptions,
    out: &'a mut Lists,
) -> WalkFuture<'a> {
    Box::pin(async move {
        // An added subtree is listed and never compared, so no entry of it is
        // opened and no extended attribute of it is read.
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

/// The names both sides hold whose two kinds pair, which are the names whose
/// extended attributes the comparison reads. The set is built only where a
/// directory side is going to be asked for them.
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

/// The path one entry of a directory named by `prefix` carries.
fn join(prefix: &OsStr, name: &OsStr) -> OsString {
    let mut path = prefix.to_owned();
    path.push("/");
    path.push(name);
    path
}

/// One path as [`DiffEntry`] carries it. A directory side's name that is not
/// valid UTF-8 is converted lossily here, which is the one place the byte form
/// is lost.
fn render(path: &OsStr) -> String {
    path.to_string_lossy().into_owned()
}

/// The ownership a directory side on the `to` side declares. The first side
/// and every commit side are unaffected.
fn to_owner(options: &DiffOptions) -> Owner {
    Owner {
        uid: options.owner_uid,
        gid: options.owner_gid,
    }
}

/// Whether two metadata sets record the same entry.
fn meta_eq(a: &FileMeta, b: &FileMeta) -> bool {
    a.uid == b.uid && a.gid == b.gid && a.mode == b.mode && a.xattrs == b.xattrs
}

/// Whether the two directory metadata records differ. Two local directories are
/// held against each other directly; a commit's recorded checksum is matched by
/// building the local directory's own.
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

/// List one directory's entries in the order its side names them, reading no
/// extended attributes and opening nothing below it.
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

/// Turn a listing into the form the comparison reads, reading the extended
/// attributes of the entries `wanted` names and of no others.
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

/// The entries of one committed directory: the files in stored order, then the
/// subdirectories in stored order.
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

/// Shape one filesystem entry into the form it compares in, with the extended
/// attributes the comparison asked for.
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

/// The checksum of a directory metadata object built from `meta`. The identity
/// is the SHA-256 of the serialized normal form, which is what a directory side
/// compares against the checksum a commit recorded.
fn dirmeta_checksum(meta: &DirMeta) -> Result<Checksum> {
    Ok(Checksum::from_bytes(
        Sha256::digest(meta.serialize()?).into(),
    ))
}

/// The content object checksum of one entry, computed for a filesystem entry
/// and read off the directory tree object for a committed one.
///
/// A local symlink whose target is not valid UTF-8 has no content object form,
/// so it reports `None`. A commit's target is always valid UTF-8, so such an
/// entry differs from every committed object.
async fn content_checksum(side: &Side, name: &OsStr, kind: &EntryKind) -> Result<Option<Checksum>> {
    match kind {
        EntryKind::Content(checksum) => Ok(Some(*checksum)),
        EntryKind::File { meta, .. } => Ok(Some(hash_local_file(side, name, meta).await?)),
        EntryKind::Symlink { meta, target } => {
            let Ok(target) = std::str::from_utf8(target) else {
                return Ok(None);
            };
            // A symlink's target is in its header, so there is no payload to
            // read.
            let header = local_header(meta, target);
            Ok(Some(ContentHasher::new(&header)?.finish()))
        }
        _ => Err(Error::InvalidFormat(
            "a directory compared as a content object".into(),
        )),
    }
}

/// The content object header one filesystem entry carries.
fn local_header(meta: &FileMeta, symlink_target: &str) -> FileHeader {
    FileHeader {
        uid: meta.uid,
        gid: meta.gid,
        mode: meta.mode,
        symlink_target: symlink_target.to_owned(),
        xattrs: meta.xattrs.clone(),
    }
}

/// Hash a local regular file as a content object, streaming the payload through
/// a fixed buffer. Nothing is written to the repository.
///
/// The open and the first chunk share one dispatch, and a file no longer than
/// the chunk is read to its end inside it.
async fn hash_local_file(side: &Side, name: &OsStr, meta: &FileMeta) -> Result<Checksum> {
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
        let mut file = RtFile::from(fd);
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

/// Open one file below `root` and read its first chunk. A read that reports the
/// end of the file inside the chunk returns no descriptor, so a file no longer
/// than one chunk costs one dispatch in all.
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

/// The subdirectory `entry` names, ready to enumerate. A directory side opens
/// nothing here: the child carries the root descriptor and the relative path,
/// and the listing pass opens it.
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

/// One filesystem entry as the directory pass captured it.
struct RawEntry {
    name: OsString,
    kind: RawKind,
    uid: u32,
    gid: u32,
    /// The full `st_mode`, including the file-type bits.
    mode: u32,
    /// The payload length, which parts two regular files with no read.
    size: u64,
}

/// What kind of entry a directory pass found.
enum RawKind {
    Dir,
    Regular,
    /// A symlink, with the target bytes the filesystem returned.
    Symlink(Vec<u8>),
    /// A device, a fifo, or a socket. The comparison holds such an entry
    /// against another of its kind and never reads it.
    Other,
}

impl RawKind {
    /// The class this entry compares in.
    fn class(&self) -> Class {
        match self {
            RawKind::Dir => Class::Dir,
            RawKind::Regular => Class::File,
            RawKind::Symlink(_) => Class::Symlink,
            RawKind::Other => Class::Other,
        }
    }
}

/// Capture one directory's entries in one blocking pass, in the order the
/// directory returns them. Nothing below the directory is opened here, so an
/// entry the comparison never reads costs one `statat` and, for a symlink, one
/// `readlinkat`.
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

/// Read the extended attributes of the named entries in one blocking pass,
/// keyed by each entry's position in the listing.
///
/// Every kind is read through the path-based no-follow reader, so an entry the
/// comparison later opens for its payload is opened once and not twice.
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

/// An I/O failure that names the path it happened at and the call that made it.
fn path_error(call: &str, path: &Path, err: Errno) -> Error {
    path_error_io(call, path, &std::io::Error::from(err))
}

/// The same for a failure already carried as an [`std::io::Error`].
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

/// Turn a list of paths into diff entries of one change kind.
fn entries(change: DiffChange, paths: Vec<String>) -> impl Iterator<Item = DiffEntry> {
    paths
        .into_iter()
        .map(move |path| DiffEntry { change, path })
}
