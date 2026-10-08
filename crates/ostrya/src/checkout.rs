//! The checkout of a committed tree into a directory on the file system.
//!
//! [`Repo::checkout_at`] writes the tree of a commit, or a subpath of it, into
//! a destination directory. It applies the metadata that the repository mode
//! records. [`CheckoutOptions`] holds the options: a [`CheckoutMode`], an
//! [`OverwriteMode`], a subpath, the hardlink and whiteout switches, a
//! [`DevInoCache`] to fill, and a [`CheckoutFilterFn`].

use std::future::Future;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use futures_lite::AsyncReadExt;
use ostrya_core::{Checksum, Commit, DirMeta, ObjectType, RepoMode, Xattrs, loose_path};
use ostrya_rt::{File as RtFile, FileReader};
use rustix::fs::{AtFlags, CWD, Dir, FileType, Gid, Mode, OFlags, RenameFlags, Uid};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject};
use crate::ingest::join_path;
use crate::modifier::{DevInoCache, FilterResult};
use crate::read::CommitState;
use crate::repo::Repo;
use crate::tree::{Comp, RepoTree, TreeEntry};
use crate::write::{FileMeta, TempKind};

/// The permission-and-special-bit mask of an `st_mode` (`perm & 0o7777`).
const PERM_MASK: u32 = 0o7777;
/// The permission mask that a [`User`](CheckoutMode::User) checkout applies to
/// a regular file that it writes (`perm & 0o1777`).
///
/// The mask drops the setuid and setgid bits. It keeps the sticky bit and the
/// rwx bits, group write and other write included. Observed with a tree of
/// assorted special-bit modes, checked out with
/// `ostree checkout -U --force-copy` in each repository mode.
const USER_PERM_MASK: u32 = 0o1777;
/// The mask that [`bareuseronly_dirs`](CheckoutOptions::bareuseronly_dirs)
/// applies to the mode of a created directory.
///
/// Observed with a tree of thirteen directory modes, checked out with
/// `ostree checkout -M`: each result is `mode & 0o775`.
const BAREUSERONLY_DIR_MASK: u32 = 0o775;
/// The chunk size in which the identity comparison reads a destination file,
/// so that no whole file is in memory.
const HASH_CHUNK: usize = 64 * 1024;
/// The mode of a new directory while the checkout writes its children. The
/// final logical mode goes on after the children.
const TRANSIENT_DIR_MODE: u32 = 0o700;
/// The overlayfs opaque-directory marker. This entry clears the existing
/// content of the destination directory before the checkout writes the
/// committed entries.
const OPAQUE_MARKER: &str = ".wh..wh..opq";
/// The prefix of a Docker-style whiteout name. `.wh.<name>` removes `<name>`
/// from the destination directory.
const WHITEOUT_PREFIX: &str = ".wh.";
/// The prefix of an overlayfs passthrough whiteout name.
/// `.ostree-wh.<name>` becomes a character device 0:0 at `<name>`.
const PASSTHROUGH_PREFIX: &str = ".ostree-wh.";

/// The way a checkout applies ownership, permission bits, and xattrs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CheckoutMode {
    /// The checkout that applies all recorded metadata (`ostree checkout`).
    ///
    /// It sets the owner to the logical uid and gid, sets all logical
    /// permission bits, and applies the logical xattrs.
    #[default]
    None,
    /// The unprivileged checkout (`ostree checkout -U`), with no owner change
    /// and no xattrs.
    ///
    /// A regular file that the checkout writes loses the setuid and setgid
    /// bits and keeps the sticky bit. A directory keeps all three bits.
    ///
    /// A regular file that the checkout hardlinks keeps the mode of the object
    /// inode. In `bare-user`, that mode holds no special bit, so the file has
    /// no sticky bit. The `ostree` command gives the same result for the same
    /// commit.
    User,
}

/// The policy of a checkout for an existing destination entry.
///
/// [`Repo::checkout_at`] states the rules for type conflicts and for symlinks
/// at directory names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverwriteMode {
    /// Each collision with an existing entry is an error (`ostree checkout`).
    #[default]
    None,
    /// Existing files are overwritten and new entries are added
    /// (`ostree checkout --union`).
    ///
    /// Existing directories stay and the checkout writes into them. An
    /// existing entry that the tree does not hold stays in place.
    UnionFiles,
    /// Only absent entries are added (`ostree checkout --union-add`).
    ///
    /// Existing files and directories stay as they are.
    AddFiles,
    /// New entries are added, and existing entries must match the tree.
    ///
    /// This mode is `ostree checkout --union-identical`.
    ///
    /// An existing entry that matches stays in place. An existing entry that
    /// does not match is an [`Error::Checkout`]. An entry matches by these
    /// rules, observed with the `ostree` command:
    ///
    /// - A regular file matches if it is the inode of the loose object. It also
    ///   matches if its file-object checksum equals the checksum of the object
    ///   and its permission bits equal those of the loose object inode.
    /// - A symlink matches if its target is the same.
    /// - A directory stays with no comparison, as under the other union modes.
    /// - At the name of a passthrough whiteout device, the checkout keeps an
    ///   existing entry of any type, with no comparison. This is the one place
    ///   where the rules do not run.
    /// - An entry of another type than the tree entry does not match.
    ///
    /// The checksum reduces the metadata of the destination as the repository
    /// mode reduces an ingested entry. In `bare-user-only`, it drops the owner
    /// and the xattrs and masks the permission bits. The comparison does not
    /// read the modification time or the link count.
    ///
    /// This mode needs
    /// [`require_hardlinks`](CheckoutOptions::require_hardlinks). If the flag
    /// is clear, the checkout fails with [`Error::Checkout`] before it touches
    /// the destination. The `ostree` command demands the same pairing.
    UnionIdentical,
}

/// A filter that decides which paths a checkout writes.
///
/// The path starts at the checkout root, has a leading slash, and has no
/// trailing slash. The root itself is `/`. The [`FileMeta`] holds the recorded
/// metadata of the entry: the dirmeta of a directory, or the file object of a
/// file or a symlink. Its `mode` gives the type of the entry.
///
/// The checkout loads the metadata object before it calls the filter, so a
/// pruned entry still costs the load of its own metadata.
///
/// The filter decides the checkout root, each directory entry, and each file
/// and symlink entry of the walk. A [`Skip`](FilterResult::Skip) on the root
/// writes nothing and creates no destination. A [`Skip`](FilterResult::Skip)
/// on a directory prunes its whole subtree.
///
/// Two sites do not call the filter:
///
/// - the single file or symlink that a
///   [`subpath`](CheckoutOptions::subpath) names
/// - the clear of the opaque whiteout marker, which is a pass of the directory
///   walk over the names in the destination
///
/// The filter decides a file entry before the whiteout verdict. A
/// [`Skip`](FilterResult::Skip) on the path of a marker entry removes nothing
/// and writes no device.
pub type CheckoutFilterFn = Box<dyn FnMut(&Path, &FileMeta) -> FilterResult + Send>;

/// The options of [`Repo::checkout_at`].
///
/// A caller creates the options with [`new`](CheckoutOptions::new) or
/// [`Default`] and sets the fields. `checkout_at` takes the options by `&mut`.
/// The filter runs through this exclusive borrow, and the checkout fills the
/// devino cache in place.
pub struct CheckoutOptions {
    /// The checkout mode.
    pub mode: CheckoutMode,
    /// The policy for an existing destination entry.
    pub overwrite: OverwriteMode,
    /// A path in the commit tree to check out as the destination root.
    ///
    /// A path with no name component names the whole tree. A path with a name
    /// component and a `..` component names nothing, because no directory
    /// holds a `..` entry. The checkout refuses such a path with
    /// [`Error::SubpathNotFound`]. If a component before the first `..` names
    /// a file or a symlink, the refusal is [`Error::SubpathNotADirectory`].
    pub subpath: Option<PathBuf>,
    /// `true` to fsync each directory and each new regular file of the checkout.
    ///
    /// A hardlinked file, a symlink, and a whiteout device get no fsync. The
    /// default is `false`. `ostrya checkout` reads the value from
    /// `[core] fsync` of the repository, narrowed by `--fsync`.
    pub enable_fsync: bool,
    /// `true` to copy each object and make no hardlink.
    ///
    /// The copy still tries a reflink first.
    pub force_copy: bool,
    /// `true` to refuse each entry that the checkout must copy
    /// (`ostree checkout -H`).
    ///
    /// The refusal comes at the entry, so a tree that holds no such entry is
    /// written whole. A directory never needs a copy. A zero-length regular
    /// file needs no copy either, because each mode writes it as a new file.
    ///
    /// The checkout refuses each destination directory on another file system
    /// than the repository, before it writes an entry into that directory. The
    /// two refusals are [`Error::RequireHardlinks`] and
    /// [`Error::HardlinkAcrossDevices`].
    /// [`Repo::checkout_at`] states the cases that need a copy.
    ///
    /// This flag and [`force_copy`](CheckoutOptions::force_copy) exclude each
    /// other. If both are set, the checkout fails with [`Error::Checkout`]
    /// before it touches the destination. [`OverwriteMode::UnionIdentical`]
    /// needs this flag.
    pub require_hardlinks: bool,
    /// `true` to reduce each directory that the checkout creates to
    /// `mode & 0o775` (`ostree checkout -M`).
    ///
    /// A directory that the checkout reuses keeps its own mode. The flag has
    /// no effect on regular files and symlinks.
    pub bareuseronly_dirs: bool,
    /// `true` to process Docker-style whiteouts (`.wh.<name>` and
    /// `.wh..wh..opq`).
    ///
    /// If the flag is `false`, the checkout writes them as ordinary files. If
    /// the flag is `true`:
    ///
    /// - `.wh.<name>` removes `<name>` and its subtree from the destination
    ///   directory. A `.wh.` with no name is an [`Error::Checkout`].
    /// - `.wh..wh..opq` clears the existing content of the destination
    ///   directory before the checkout writes the committed entries.
    /// - The checkout does not write a marker under its own name.
    ///
    /// Only a regular-file entry acts as a marker. The checkout writes an
    /// entry of another type with a marker name as it is, as the `ostree`
    /// command does. The clear checks the names of all file entries, so a
    /// symlink named `.wh..wh..opq` clears the directory and is then written.
    ///
    /// A [`subpath`](CheckoutOptions::subpath) that names a marker gets the
    /// same verdict, so the checkout never writes the marker under its own
    /// name. A subpath that names `.wh..wh..opq` drops the entry and clears
    /// nothing. The `ostree` command gives the same result.
    ///
    /// Under [`OverwriteMode::UnionFiles`], this flag also replaces an
    /// existing entry whose type differs from the tree entry.
    /// [`Repo::checkout_at`] states this rule.
    pub process_whiteouts: bool,
    /// `true` to process overlayfs passthrough whiteouts.
    ///
    /// A regular-file entry named `.ostree-wh.<name>` becomes a character
    /// device 0:0 at `<name>`. The checkout does not write the entry under its
    /// own name. A `.ostree-wh.` with no name is an [`Error::Checkout`].
    ///
    /// The device gets the permission bits of the marker. Under
    /// [`CheckoutMode::None`], it also gets the owner and the xattrs of the
    /// marker. The process umask reduces the bits at `mknodat`, as it does for
    /// the `ostree` command. [`CheckoutMode::None`] then applies the recorded
    /// mode in full, so the umask stays in effect under
    /// [`CheckoutMode::User`] only.
    pub process_passthrough_whiteouts: bool,
    /// A devino cache to fill.
    ///
    /// For each regular file, the checkout records the `(st_dev, st_ino)` of
    /// the destination against the checksum, when it writes or links the file.
    /// A later commit under
    /// [`DEVINO_CANONICAL`](crate::modifier::CommitModifierFlags::DEVINO_CANONICAL)
    /// reads the cache.
    pub devino_cache: Option<DevInoCache>,
    /// A filter that includes or prunes entries by path.
    ///
    /// [`CheckoutFilterFn`] states the paths that the filter gets and the sites
    /// that it does not reach.
    pub filter: Option<CheckoutFilterFn>,
}

impl Default for CheckoutOptions {
    fn default() -> CheckoutOptions {
        CheckoutOptions {
            mode: CheckoutMode::None,
            overwrite: OverwriteMode::None,
            subpath: None,
            enable_fsync: false,
            force_copy: false,
            require_hardlinks: false,
            bareuseronly_dirs: false,
            process_whiteouts: false,
            process_passthrough_whiteouts: false,
            devino_cache: None,
            filter: None,
        }
    }
}

impl CheckoutOptions {
    /// Creates options for the given checkout mode, with all other fields at
    /// their defaults.
    pub fn new(mode: CheckoutMode) -> CheckoutOptions {
        CheckoutOptions {
            mode,
            ..CheckoutOptions::default()
        }
    }
}

/// Methods that check out the tree of a commit.
impl Repo {
    /// Checks out the tree of `commit` into `dest_path` under `dest_dir`.
    ///
    /// `opts` holds the checkout mode, the overwrite policy, and the other
    /// options.
    ///
    /// `dest_path` names the destination root relative to `dest_dir`. Its
    /// parent components must exist. If `dest_path` is `.` or empty, the
    /// checkout writes into `dest_dir` itself. It then creates no root
    /// directory and applies no metadata to `dest_dir`.
    ///
    /// The per-file work (metadata, reflink, hardlink, rename) runs on the
    /// blocking pool.
    ///
    /// # Subpath
    ///
    /// If [`subpath`](CheckoutOptions::subpath) is `None`, the checkout writes
    /// the whole commit tree. The destination root gets the dirmeta of the
    /// tree root. If the subpath names a directory, the checkout writes that
    /// subtree, and the destination root gets its dirmeta. If the subpath names
    /// a file or a symlink, the checkout creates the destination directory and
    /// puts the object in it under its own name.
    ///
    /// # Hardlinks and copies
    ///
    /// The checkout hardlinks the loose object of a regular file if the object
    /// inode already holds the metadata that the destination needs. Otherwise
    /// it copies the object. A hardlink keeps the mode of the object inode as
    /// it is. A regular file gets a hardlink in these cases:
    ///
    /// - `bare` under [`CheckoutMode::None`]
    /// - `bare-user` under [`CheckoutMode::User`]
    /// - `bare-user-only` under either checkout mode
    ///
    /// A symlink gets a hardlink only in `bare` under [`CheckoutMode::None`].
    /// In all other cases, the checkout creates the symlink again.
    /// [`force_copy`](CheckoutOptions::force_copy) stops all hardlinks. If a
    /// hardlink crosses a file system (`EXDEV`), the checkout copies the
    /// object.
    ///
    /// A `bare-user-only` repository always gets a
    /// [`User`](CheckoutMode::User) checkout, whatever mode `opts` holds. Its
    /// objects carry no owner and no xattrs, and the object inode already holds
    /// the canonical mode.
    ///
    /// The checkout writes a zero-length object as a new file in each mode. The
    /// destination file has its own inode with a link count of 1. The `ostree`
    /// command does the same, so the link counts of both destinations agree
    /// entry for entry.
    ///
    /// A copy streams the payload through [`FileObject::reader`] in bounded
    /// chunks, so no whole object is in memory. For an object that is not in
    /// an `archive` repository, the copy first tries a `FICLONE` reflink of the
    /// loose object. If the reflink fails, the copy streams the bytes.
    ///
    /// The checkout creates each directory with `mkdir` and never links one. A
    /// new directory gets its full logical mode after the checkout writes its
    /// children, so a restrictive mode does not block these writes. A directory
    /// that the checkout reuses keeps its own metadata.
    ///
    /// # Required hardlinks
    ///
    /// Under [`require_hardlinks`](CheckoutOptions::require_hardlinks), the
    /// checkout refuses each entry that it must copy, with
    /// [`Error::RequireHardlinks`]. The refusal comes before the overwrite
    /// policy, so the checkout also refuses an entry that a union mode keeps or
    /// skips. The whiteout verdict comes first, so a marker still removes its
    /// name or writes its device. The `ostree` command uses the same order.
    ///
    /// The refusal tables, observed with a one-byte-file commit and a
    /// symlink-only commit, checked out of each repository mode under both
    /// checkout modes:
    ///
    /// - A regular file of non-zero length is refused in each case that has no
    ///   hardlink.
    /// - A symlink is refused in `archive` under either checkout mode and in
    ///   `bare` under [`User`](CheckoutMode::User). `bare-user` under
    ///   [`None`](CheckoutMode::None) creates the symlink again and does not
    ///   refuse it.
    ///
    /// The `ostree` command does not carry `bare-user-shared` and
    /// `bare-split-xattrs`, so no observation decides them. Each of these
    /// modes stores a symlink as `bare-user` does and creates it again. Each
    /// follows `bare-user` for a symlink and refuses none.
    ///
    /// The checkout also compares the device of each directory that the walk
    /// enters with the device of the object store. This includes the
    /// destination root and each directory below it, new or reused. If the
    /// devices differ, the checkout fails with [`Error::HardlinkAcrossDevices`]
    /// before it reads or writes anything in that directory. An empty directory
    /// fails all the same.
    ///
    /// The check comes after the checkout creates the directory, as in the
    /// `ostree` command, so both leave the same destination. Observed with a
    /// commit whose subtree sits behind a destination symlink to a second file
    /// system, checked out with `-H`. The `ostree` command refuses whatever the
    /// subtree holds, in each repository mode.
    ///
    /// A file or symlink subpath reaches no directory walk, so it gets no
    /// device check. If its link fails with `EXDEV`, the checkout fails with
    /// [`Error::HardlinkAcrossDevices`]. The `ostree` command writes a
    /// zero-length file into a destination on another file system at exit 0,
    /// and refuses the other shapes at the link.
    ///
    /// # Existing destination
    ///
    /// A union mode follows a symlink at a directory name, the destination root
    /// included. The checkout writes into the directory that the link resolves
    /// to, also outside the destination tree. The `ostree` command does the
    /// same. If the link resolves to nothing, to a non-directory, or to itself,
    /// the open fails with an I/O error.
    ///
    /// Where the tree holds a directory, an existing entry of another type is
    /// an [`Error::Checkout`] in each overwrite mode. A symlink that a union
    /// mode follows is the exception. Under
    /// [`OverwriteMode::UnionFiles`], an existing directory where the tree
    /// holds a file or a symlink is an [`Error::Checkout`] too. The `ostree`
    /// command fails there with `renameat(...): Is a directory`.
    ///
    /// If [`process_whiteouts`](CheckoutOptions::process_whiteouts) is set
    /// under [`OverwriteMode::UnionFiles`], the checkout removes such an
    /// entry, with its subtree, and writes the tree entry in its place. For a
    /// symlink at a directory name, it removes the link alone, and the
    /// directory that the link resolves to stays. This rule does not apply to
    /// the destination directory of a file subpath or to a passthrough
    /// whiteout device.
    ///
    /// # Errors
    ///
    /// - [`Error::Checkout`] if
    ///   [`OverwriteMode::UnionIdentical`] is set with
    ///   [`require_hardlinks`](CheckoutOptions::require_hardlinks) clear, or if
    ///   `require_hardlinks` and [`force_copy`](CheckoutOptions::force_copy)
    ///   are both set. These two checks run before the checkout touches the
    ///   destination.
    /// - [`Error::Checkout`] if the commit is [`CommitState::Partial`].
    /// - [`Error::Checkout`] if the subpath names a file or a symlink and
    ///   `dest_path` has no final name.
    /// - [`Error::Checkout`] if the final name of `dest_path` is not valid
    ///   UTF-8.
    /// - [`Error::Checkout`] if a destination entry collides under the
    ///   overwrite policy, or has a type that the policy does not replace.
    /// - [`Error::Checkout`] if a destination entry does not match under
    ///   [`OverwriteMode::UnionIdentical`].
    /// - [`Error::Checkout`] if a whiteout marker names no entry, or if an
    ///   xattr of a passthrough whiteout device cannot be set.
    /// - [`Error::SubpathNotFound`] if the subpath names no entry.
    /// - [`Error::SubpathNotADirectory`] if the subpath runs through an entry
    ///   that is not a directory.
    /// - [`Error::RequireHardlinks`] if `require_hardlinks` is set and an entry
    ///   needs a copy.
    /// - [`Error::HardlinkAcrossDevices`] if `require_hardlinks` is set and a
    ///   destination directory or the link of a file subpath is on another
    ///   file system.
    /// - [`Error::ObjectNotFound`] if the commit, a dirtree, a dirmeta, or a
    ///   file object is not in the object store.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if an object does not
    ///   parse.
    /// - [`Error::InvalidFormat`] if the name of a destination entry to remove
    ///   is not valid UTF-8.
    /// - [`Error::InvalidFormat`] if the name of an xattr that the checkout
    ///   applies to a file, a symlink, or a directory is not valid UTF-8.
    /// - [`Error::Io`] for an I/O error from the file system.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> ostrya::Result<()> {
    /// use std::os::fd::AsFd;
    ///
    /// use ostrya::Repo;
    /// use ostrya::checkout::{CheckoutMode, CheckoutOptions};
    ///
    /// let repo = Repo::open("/srv/repo".as_ref()).await?;
    /// let rev = repo.resolve_rev("exampleos/stable", false).await?;
    /// if let Some(commit) = rev {
    ///     let dest = std::fs::File::open("/srv/checkouts")?;
    ///     let mut opts = CheckoutOptions::new(CheckoutMode::User);
    ///     let path = "stable".as_ref();
    ///     repo.checkout_at(&mut opts, dest.as_fd(), path, &commit).await?;
    /// }
    /// # Ok(()) }
    /// ```
    pub async fn checkout_at(
        &self,
        opts: &mut CheckoutOptions,
        dest_dir: BorrowedFd<'_>,
        dest_path: &Path,
        commit: &Checksum,
    ) -> Result<()> {
        let policy = Policy::new(self.mode(), opts);
        // The `ostree` command takes `--union-identical` only together with
        // `--require-hardlinks`, so a checkout under it makes hardlinks. These
        // two refusals read the options alone and do no I/O. The per-entry
        // `require_hardlinks` refusal decides which repository mode and
        // checkout mode can hardlink, as in the `ostree` command. So a tree
        // that holds no entry that needs a copy is written whole under
        // `UnionIdentical`.
        if policy.overwrite == OverwriteMode::UnionIdentical && !policy.require_hardlinks {
            return Err(Error::Checkout(
                "union-identical requires require_hardlinks".into(),
            ));
        }
        if policy.require_hardlinks && policy.force_copy {
            return Err(Error::Checkout(
                "require_hardlinks and force_copy are mutually exclusive".into(),
            ));
        }
        let (commit_obj, state) = self.load_commit(commit).await?;
        if state == CommitState::Partial {
            return Err(Error::Checkout(format!(
                "commit {} is partial; checkout needs a complete commit",
                commit.to_hex()
            )));
        }
        let target = resolve_target(self, &commit_obj, opts.subpath.as_deref()).await?;

        match target {
            Target::Dir { dirtree, dirmeta } => {
                let dm = self.load_dirmeta(&dirmeta).await?;
                // The filter decides the root before the checkout touches the
                // destination path. A pruned root writes nothing, creates no
                // destination, and reads nothing of the parent of the
                // destination.
                if let Some(filter) = &mut opts.filter {
                    let fm = FileMeta {
                        uid: dm.uid,
                        gid: dm.gid,
                        mode: dm.mode,
                        xattrs: dm.xattrs.clone(),
                    };
                    if filter(Path::new("/"), &fm) == FilterResult::Skip {
                        return Ok(());
                    }
                }
                let (parent_fd, name) = open_dest_parent(dest_dir, dest_path)?;
                let (dir_fd, fresh) = match &name {
                    Some(n) => create_dest_dir(
                        parent_fd.as_fd(),
                        n,
                        policy.overwrite,
                        widens_type_conflict(policy),
                    )?,
                    None => (parent_fd.as_fd().try_clone_to_owned()?, false),
                };
                checkout_dir(
                    self,
                    opts,
                    policy,
                    DirNode {
                        dir_fd,
                        dirtree,
                        dirmeta: dm,
                        fresh,
                        base_path: "/".to_owned(),
                    },
                )
                .await?;
            }
            Target::File {
                name: entry_name,
                checksum,
            } => {
                let (parent_fd, name) = open_dest_parent(dest_dir, dest_path)?;
                let dir_name = name.ok_or_else(|| {
                    Error::Checkout("a file subpath needs a named destination directory".into())
                })?;
                // The widening of the whiteout switch does not reach the
                // destination directory of a file target.
                let (dir_fd, _fresh) =
                    create_dest_dir(parent_fd.as_fd(), &dir_name, policy.overwrite, false)?;
                // A single file or symlink target reaches no directory walk, so
                // it gets no device check before the write. The `ostree`
                // command writes a zero-length file at exit 0 into a
                // destination on another file system. It refuses the other
                // shapes at the link. The `EXDEV` arms of `place_regular` and
                // `place_symlink` make that refusal.
                let obj = self.load_file(&checksum).await?;
                checkout_entry(self, opts, policy, dir_fd.as_fd(), &entry_name, &obj).await?;
                if policy.enable_fsync {
                    fsync_dir(dir_fd).await?;
                }
            }
        }
        Ok(())
    }
}

/// The resolved node that a checkout writes as its destination root.
enum Target {
    /// A directory subtree: its dirtree and dirmeta checksums.
    Dir {
        dirtree: Checksum,
        dirmeta: Checksum,
    },
    /// A single file or symlink: its name in the tree and its content checksum.
    File { name: String, checksum: Checksum },
}

/// Resolves the checkout target in a commit tree, with an optional subpath.
///
/// An absent subpath or a root subpath selects the whole tree. The function
/// resolves any other subpath through the tree, and a subpath that does not
/// resolve is an error.
///
/// A value that names no entry is [`Error::SubpathNotFound`]. A value that
/// runs through an entry that is not a directory is
/// [`Error::SubpathNotADirectory`]. The `ostree` command makes the same split,
/// and `ostrya checkout --allow-noent` acts on it.
async fn resolve_target(repo: &Repo, commit: &Commit, subpath: Option<&Path>) -> Result<Target> {
    let root = Target::Dir {
        dirtree: commit.root_dirtree,
        dirmeta: commit.root_dirmeta,
    };
    let Some(sub) = subpath else {
        return Ok(root);
    };
    if is_root_path(sub) {
        return Ok(root);
    }
    let tree = RepoTree::from_parts(repo.clone(), commit.root_dirtree, commit.root_dirmeta);
    match tree.lookup(sub).await? {
        Some(TreeEntry::Dir { tree, .. }) => Ok(Target::Dir {
            dirtree: *tree.dirtree_checksum(),
            dirmeta: *tree.dirmeta_checksum(),
        }),
        Some(TreeEntry::File { name, checksum }) => Ok(Target::File { name, checksum }),
        None => Err(unresolved_subpath(&tree, sub).await),
    }
}

/// Returns the refusal for a subpath that resolved to nothing.
///
/// The walk descends the leading components of the value one at a time. If a
/// component names an entry that is not a directory, the value runs through a
/// non-directory. Every other result means that the value names nothing. The
/// walk splits the components as [`RepoTree::lookup`](crate::RepoTree::lookup)
/// does, so the walk stops where the lookup stopped.
async fn unresolved_subpath(tree: &RepoTree, sub: &Path) -> Error {
    let not_found = || Error::SubpathNotFound(sub.to_path_buf());
    let components = crate::tree::normalize(sub);
    let Some(leading) = components.len().checked_sub(1) else {
        return not_found();
    };
    let mut current = tree.clone();
    for component in &components[..leading] {
        let Comp::Normal(component) = component else {
            // A `..` component. No directory holds an entry of this name, so
            // the value names nothing, whatever follows it.
            return not_found();
        };
        match current.lookup(Path::new(component)).await {
            Ok(Some(TreeEntry::Dir { tree, .. })) => current = tree,
            Ok(Some(TreeEntry::File { .. })) => {
                return Error::SubpathNotADirectory(sub.to_path_buf());
            }
            Ok(None) => return not_found(),
            // A failed lookup keeps its own error. If the walk reported it as
            // an absent subpath, `ostrya checkout --allow-noent` can turn a
            // read or decode failure into exit 0.
            Err(e) => return e,
        }
    }
    not_found()
}

/// Returns `true` if a path has no name component, so it names the tree root.
pub(crate) fn is_root_path(p: &Path) -> bool {
    use std::path::Component;
    !p.components().any(|c| matches!(c, Component::Normal(_)))
}

/// Opens the parent directory of `dest_path` relative to `dest_dir`, and
/// returns it with the name of the final component.
///
/// A `.` or empty `dest_path` has no final component, so the function returns
/// `dest_dir` itself with no name.
fn open_dest_parent(
    dest_dir: BorrowedFd<'_>,
    dest_path: &Path,
) -> Result<(OwnedFd, Option<String>)> {
    match dest_path.file_name() {
        Some(name) => {
            let name = name
                .to_str()
                .ok_or_else(|| Error::Checkout("destination name is not valid UTF-8".into()))?
                .to_owned();
            let parent_fd = match dest_path.parent() {
                Some(p) if !p.as_os_str().is_empty() => rustix::fs::openat(
                    dest_dir,
                    p,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?,
                _ => dest_dir.try_clone_to_owned()?,
            };
            Ok((parent_fd, Some(name)))
        }
        None => Ok((dest_dir.try_clone_to_owned()?, None)),
    }
}

/// The boxed future of the recursive directory walk. Async recursion needs
/// indirection, so each level returns a boxed future.
type CheckoutFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// A destination directory that the checkout writes into.
///
/// It holds the fd of the created directory, the dirtree and the dirmeta to
/// write, and the path for filter calls. `fresh` is `true` if the checkout
/// created the directory, so the checkout applies its metadata. A reused
/// directory keeps its metadata.
struct DirNode {
    dir_fd: OwnedFd,
    dirtree: Checksum,
    dirmeta: DirMeta,
    fresh: bool,
    base_path: String,
}

/// Writes one directory: its files, then its subdirectories, then its own
/// metadata.
fn checkout_dir<'a>(
    repo: &'a Repo,
    opts: &'a mut CheckoutOptions,
    policy: Policy,
    node: DirNode,
) -> CheckoutFuture<'a> {
    Box::pin(async move {
        let DirNode {
            dir_fd,
            dirtree: dirtree_csum,
            dirmeta,
            fresh,
            base_path,
        } = node;
        // The walk checks each destination directory that it enters, new or
        // reused, before it reads or writes anything in it. An empty directory
        // is refused all the same, as in the `ostree` command.
        check_hardlink_device(repo, policy, dir_fd.as_fd())?;
        let dirtree = repo.load_dirtree(&dirtree_csum).await?;

        // An opaque marker clears the destination directory before the
        // checkout writes the committed entries. A new directory holds
        // nothing, so the clear has nothing to do there.
        if !fresh
            && policy.process_whiteouts
            && dirtree.files.iter().any(|(n, _)| n == OPAQUE_MARKER)
        {
            let d = dir_fd.as_fd().try_clone_to_owned()?;
            ostrya_rt::unblock(move || clear_dir(d.as_fd())).await?;
        }

        for (name, checksum) in &dirtree.files {
            let obj = repo.load_file(checksum).await?;
            // The filter decides the entry ahead of the whiteout verdict, so a
            // pruned marker removes nothing and writes no device.
            if let Some(filter) = &mut opts.filter {
                let cb_path = join_path(&base_path, name);
                let fm = FileMeta {
                    uid: obj.uid,
                    gid: obj.gid,
                    mode: obj.mode,
                    xattrs: obj.xattrs.clone(),
                };
                if filter(Path::new(&cb_path), &fm) == FilterResult::Skip {
                    continue;
                }
            }
            checkout_entry(repo, &mut *opts, policy, dir_fd.as_fd(), name, &obj).await?;
        }

        for (name, sub_dirtree, sub_dirmeta) in &dirtree.dirs {
            let dm = repo.load_dirmeta(sub_dirmeta).await?;
            let cb_path = join_path(&base_path, name);
            if let Some(filter) = &mut opts.filter {
                let fm = FileMeta {
                    uid: dm.uid,
                    gid: dm.gid,
                    mode: dm.mode,
                    xattrs: dm.xattrs.clone(),
                };
                if filter(Path::new(&cb_path), &fm) == FilterResult::Skip {
                    continue;
                }
            }
            let (child_fd, child_fresh) = create_dest_dir(
                dir_fd.as_fd(),
                name,
                policy.overwrite,
                widens_type_conflict(policy),
            )?;
            checkout_dir(
                repo,
                &mut *opts,
                policy,
                DirNode {
                    dir_fd: child_fd,
                    dirtree: *sub_dirtree,
                    dirmeta: dm,
                    fresh: child_fresh,
                    base_path: cb_path,
                },
            )
            .await?;
        }

        // The final metadata of the directory goes on after its children, so a
        // restrictive mode does not block their writes. A reused directory
        // keeps its metadata.
        if fresh {
            let d = dir_fd.as_fd().try_clone_to_owned()?;
            let effective = policy.effective;
            let masked = policy.bareuseronly_dirs;
            ostrya_rt::unblock(move || apply_dir_metadata(d.as_fd(), effective, masked, &dirmeta))
                .await?;
        }
        if policy.enable_fsync {
            fsync_dir(dir_fd).await?;
        }
        Ok(())
    })
}

/// Acts on one file entry of a tree.
///
/// If a whiteout switch claims the name, the function applies the whiteout
/// verdict. Otherwise it writes the entry.
///
/// A `--subpath` that names a marker file gets the same verdict, so a subpath
/// never writes a marker under its own name. The clear of the opaque marker is a pass of the directory walk.
/// So a subpath that names `.wh..wh..opq` drops the entry and clears nothing,
/// as in the `ostree` command.
async fn checkout_entry(
    repo: &Repo,
    opts: &mut CheckoutOptions,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    obj: &FileObject,
) -> Result<()> {
    match whiteout_verdict(policy, name, obj)? {
        Some(Whiteout::Drop) => Ok(()),
        Some(Whiteout::Remove(target)) => {
            let d = dir_fd.try_clone_to_owned()?;
            ostrya_rt::unblock(move || remove_dir_entry(d.as_fd(), &target)).await
        }
        Some(Whiteout::Device(target)) => place_whiteout_device(policy, dir_fd, &target, obj).await,
        None => checkout_file(repo, opts, policy, dir_fd, name, obj).await,
    }
}

/// Writes one file or symlink entry.
///
/// Under [`require_hardlinks`](CheckoutOptions::require_hardlinks), the
/// function refuses the entry here, before the destination disposition. So it
/// also refuses an entry that a union mode keeps or skips. The whiteout verdict
/// comes before this call, so a marker that removes a name and a marker that
/// writes a device both take effect. The `ostree` command uses the same order
/// for both.
async fn checkout_file(
    repo: &Repo,
    opts: &mut CheckoutOptions,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    obj: &FileObject,
) -> Result<()> {
    if require_hardlinks_refuses(policy, obj) {
        return Err(Error::RequireHardlinks(name.to_owned()));
    }
    match &obj.kind {
        FileKind::Symlink { target } => {
            place_symlink(repo, policy, dir_fd, name, obj, target).await
        }
        FileKind::Regular { .. } => place_regular(repo, opts, policy, dir_fd, name, obj).await,
    }
}

/// The result of the whiteout options for one file entry.
///
/// Both marker sets act on a regular-file entry only. The checkout writes an
/// entry of another type with a marker name as it is, as the `ostree` command
/// does. The clear of the opaque marker is a separate decision, by name over
/// the full list of file entries. So a symlink with that name clears the
/// directory, and the checkout then writes it.
enum Whiteout {
    /// The opaque marker, whose clear already ran: drop the entry.
    Drop,
    /// A per-name marker: remove this name from the destination directory and
    /// write nothing.
    Remove(String),
    /// A passthrough marker: write a character device 0:0 under this name.
    Device(String),
}

/// Returns the whiteout verdict for one file entry, or `None` if the checkout
/// writes the entry as it is. A marker that names nothing is an error.
fn whiteout_verdict(policy: Policy, name: &str, obj: &FileObject) -> Result<Option<Whiteout>> {
    if !matches!(obj.kind, FileKind::Regular { .. }) {
        return Ok(None);
    }
    if policy.process_whiteouts {
        if name == OPAQUE_MARKER {
            return Ok(Some(Whiteout::Drop));
        }
        if let Some(target) = name.strip_prefix(WHITEOUT_PREFIX) {
            if target.is_empty() {
                return Err(Error::Checkout(format!(
                    "{WHITEOUT_PREFIX}: the whiteout names no entry"
                )));
            }
            return Ok(Some(Whiteout::Remove(target.to_owned())));
        }
    }
    if policy.process_passthrough_whiteouts
        && let Some(target) = name.strip_prefix(PASSTHROUGH_PREFIX)
    {
        if target.is_empty() {
            return Err(Error::Checkout(format!(
                "{PASSTHROUGH_PREFIX}: the overlayfs whiteout names no entry"
            )));
        }
        return Ok(Some(Whiteout::Device(target.to_owned())));
    }
    Ok(None)
}

/// Writes an overlayfs passthrough whiteout: a character device 0:0 under the
/// target name of the marker.
///
/// [`CheckoutOptions::process_passthrough_whiteouts`] states the metadata of
/// the device and the effect of the umask.
///
/// [`UnionIdentical`](OverwriteMode::UnionIdentical) keeps an existing entry of
/// any type here, with no comparison. This is the one place where the identity
/// rule does not run. Observed with a passthrough marker, checked out over a
/// destination that holds a regular file, a symlink, a directory, and a device.
async fn place_whiteout_device(
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    obj: &FileObject,
) -> Result<()> {
    // The whiteout device keeps its refusal of a destination directory under
    // either switch, so the widening does not reach it.
    let remove_existing = match pre_check(dir_fd, name, policy.overwrite, false)? {
        Disposition::Skip | Disposition::Check(_) => return Ok(()),
        Disposition::Error => return Err(collision(name)),
        Disposition::Place => false,
        Disposition::Overwrite => true,
    };

    let plan = PlaceWhiteoutDevice {
        dir: dir_fd.try_clone_to_owned()?,
        name: name.to_owned(),
        effective: policy.effective,
        uid: obj.uid,
        gid: obj.gid,
        mode: obj.mode & PERM_MASK,
        xattrs: obj.xattrs.clone(),
        remove_existing,
    };
    ostrya_rt::unblock(move || place_whiteout_device_blocking(plan)).await
}

/// The data of the blocking half of [`place_whiteout_device`].
struct PlaceWhiteoutDevice {
    dir: OwnedFd,
    name: String,
    effective: CheckoutMode,
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: Xattrs,
    remove_existing: bool,
}

/// Creates the whiteout device and applies its checkout-mode metadata.
fn place_whiteout_device_blocking(plan: PlaceWhiteoutDevice) -> Result<()> {
    if plan.remove_existing {
        remove_dir_entry(plan.dir.as_fd(), &plan.name)?;
    }
    match rustix::fs::mknodat(
        plan.dir.as_fd(),
        plan.name.as_str(),
        FileType::CharacterDevice,
        Mode::from_raw_mode(plan.mode),
        rustix::fs::makedev(0, 0),
    ) {
        Ok(()) => {}
        Err(Errno::EXIST) => return Err(collision(&plan.name)),
        Err(e) => return Err(e.into()),
    }
    if plan.effective == CheckoutMode::None {
        // The order is the observed order of the `ostree` command for the
        // marker: the attributes, then the owner, then the mode. `chown` on a
        // device node clears the setuid bit. It also clears the setgid bit if
        // group execute is set, for root too and where the ids do not change.
        // So the recorded mode goes on after the owner.
        //
        // The attributes come first, so if the kernel refuses an attribute of
        // the marker, the device keeps the mode that `mknod` gave it. The
        // `ostree` command gives the same result.
        // `apply_regular_metadata` applies the owner first, so a regular file
        // keeps its `security.capability`. The chown here removes that xattr
        // from the device, which has no use for a file capability.
        for (name, value) in plan.xattrs.iter() {
            crate::write::set_link_xattr(plan.dir.as_fd(), &plan.name, name, value).map_err(
                |err| {
                    Error::Checkout(format!(
                        "{}: setting the extended attribute {}: {}",
                        plan.name,
                        xattr_name(name),
                        reason(err),
                    ))
                },
            )?;
        }
        rustix::fs::chownat(
            plan.dir.as_fd(),
            plan.name.as_str(),
            Some(Uid::from_raw(plan.uid)),
            Some(Gid::from_raw(plan.gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        rustix::fs::chmodat(
            plan.dir.as_fd(),
            plan.name.as_str(),
            Mode::from_raw_mode(plan.mode),
            AtFlags::empty(),
        )?;
    }
    Ok(())
}

/// Returns the name of an extended attribute for a message, without its
/// terminating NUL. A name that is not UTF-8 gets a lossy conversion.
fn xattr_name(name: &[u8]) -> String {
    String::from_utf8_lossy(name.strip_suffix(&[0]).unwrap_or(name)).into_owned()
}

/// Returns the text of an error for a message that a caller wraps, without the
/// numeric tail of an I/O error.
fn reason(err: Error) -> String {
    let text = match &err {
        Error::Io(io) => io.to_string(),
        other => other.to_string(),
    };
    match text.find(" (os error ") {
        Some(cut) => text[..cut].to_owned(),
        None => text,
    }
}

/// Writes a regular file. The function hardlinks the loose object if the object
/// inode is already the target inode. Otherwise it copies the object, with a
/// reflink if possible.
async fn place_regular(
    repo: &Repo,
    opts: &mut CheckoutOptions,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    obj: &FileObject,
) -> Result<()> {
    let checksum = obj.checksum();
    let remove_existing =
        match pre_check(dir_fd, name, policy.overwrite, widens_type_conflict(policy))? {
            Disposition::Skip => return Ok(()),
            Disposition::Error => return Err(collision(name)),
            Disposition::Place => false,
            Disposition::Overwrite => true,
            Disposition::Check(st) => {
                if destination_is_identical(repo, policy, dir_fd, name, &st, obj).await? {
                    return Ok(());
                }
                return Err(collision(name));
            }
        };

    // A link across file systems (EXDEV) gives None, and the copy path runs.
    // Under `require_hardlinks`, the switch refuses the copy, so the entry is
    // refused. The device check of the directory walk does not reach a single
    // file or symlink target. This check does.
    if hardlink_regular_object(policy, obj) {
        match try_link_object(repo, policy, dir_fd, name, checksum, remove_existing).await? {
            Some((dev, ino)) => {
                record_devino(opts, dev, ino, checksum);
                return Ok(());
            }
            None if policy.require_hardlinks => {
                return hardlink_across_devices(repo, dir_fd);
            }
            None => {}
        }
    }

    let (temp, kind) = crate::write::open_temp(dir_fd)?;
    // A loose object of a bare-family mode holds the raw payload. So a
    // recorded size of zero is the `st_size` of the object, and the empty temp
    // file already holds all bytes of the destination. An `archive` object
    // records the declared uncompressed size of its header. That size is not
    // proof of the payload, so that mode always copies.
    if !(policy.repo_mode != RepoMode::Archive && matches!(obj.kind, FileKind::Regular { size: 0 }))
    {
        copy_object(repo, obj, &temp, policy).await?;
    }
    let plan = FinishCopy {
        dir: dir_fd.try_clone_to_owned()?,
        name: name.to_owned(),
        temp,
        kind,
        effective: policy.effective,
        uid: obj.uid,
        gid: obj.gid,
        mode: obj.mode,
        xattrs: obj.xattrs.clone(),
        enable_fsync: policy.enable_fsync,
        remove_existing,
    };
    let (dev, ino) = ostrya_rt::unblock(move || finish_copy_blocking(plan)).await?;
    record_devino(opts, dev, ino, checksum);
    Ok(())
}

/// Writes a symlink. The function hardlinks the loose object only under `bare`
/// and [`None`](CheckoutMode::None). Otherwise it creates the link again.
async fn place_symlink(
    repo: &Repo,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    obj: &FileObject,
    target: &str,
) -> Result<()> {
    let checksum = obj.checksum();
    let remove_existing =
        match pre_check(dir_fd, name, policy.overwrite, widens_type_conflict(policy))? {
            Disposition::Skip => return Ok(()),
            Disposition::Error => return Err(collision(name)),
            Disposition::Place => false,
            Disposition::Overwrite => true,
            Disposition::Check(st) => {
                if destination_is_identical(repo, policy, dir_fd, name, &st, obj).await? {
                    return Ok(());
                }
                return Err(collision(name));
            }
        };

    // The `EXDEV` arm makes the same refusal as `place_regular`. Under
    // `require_hardlinks`, the switch refuses a copy, and a new link is a
    // copy.
    if hardlink_symlink(policy) {
        match try_link_object(repo, policy, dir_fd, name, checksum, remove_existing).await? {
            Some(_) => return Ok(()),
            None if policy.require_hardlinks => {
                return hardlink_across_devices(repo, dir_fd);
            }
            None => {}
        }
    }

    let plan = RecreateSymlink {
        dir: dir_fd.try_clone_to_owned()?,
        name: name.to_owned(),
        target: target.to_owned(),
        effective: policy.effective,
        uid: obj.uid,
        gid: obj.gid,
        xattrs: obj.xattrs.clone(),
        remove_existing,
    };
    ostrya_rt::unblock(move || recreate_symlink_blocking(plan)).await
}

/// Records the destination inode of a written regular file against its
/// checksum, for a later ingest under `DEVINO_CANONICAL`.
fn record_devino(opts: &mut CheckoutOptions, dev: u64, ino: u64, checksum: &Checksum) {
    if let Some(cache) = &mut opts.devino_cache {
        cache.insert(dev, ino, *checksum);
    }
}

/// The overwrite verdict for one destination entry.
enum Disposition {
    /// The entry is absent. The checkout writes it.
    Place,
    /// The entry exists and must be removed before writing.
    Overwrite,
    /// The entry exists and is left in place.
    Skip,
    /// The entry exists, and the checkout must compare it with the object for
    /// that name. The stat is the input of the comparison.
    Check(rustix::fs::Stat),
    /// The entry exists and its presence is a conflict.
    Error,
}

/// Returns the disposition of a destination entry under the overwrite mode.
///
/// Under [`UnionIdentical`](OverwriteMode::UnionIdentical), the caller runs
/// [`destination_is_identical`] on the returned stat.
///
/// `widen_type_conflict` holds [`widens_type_conflict`] for the entry sites
/// that the switch reaches. The whiteout device is not one of them, so it
/// passes `false` and keeps its refusal of a destination directory.
fn pre_check(
    dir_fd: BorrowedFd<'_>,
    name: &str,
    overwrite: OverwriteMode,
    widen_type_conflict: bool,
) -> Result<Disposition> {
    let st = match rustix::fs::statat(dir_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::NOENT) => return Ok(Disposition::Place),
        Err(e) => return Err(e.into()),
    };
    Ok(match overwrite {
        OverwriteMode::None => Disposition::Error,
        OverwriteMode::UnionFiles => {
            // The `ostree` command overwrites an existing non-directory in
            // place, with a rename over the name. It cannot rename a file or a
            // symlink over a directory. A directory where the commit holds a
            // non-directory is a conflict, and it fails with
            // `renameat(...): Is a directory`. `--whiteouts` widens the
            // disposition, and the checkout then removes the directory and its
            // whole subtree.
            if FileType::from_raw_mode(st.st_mode) == FileType::Directory && !widen_type_conflict {
                Disposition::Error
            } else {
                Disposition::Overwrite
            }
        }
        OverwriteMode::AddFiles => Disposition::Skip,
        OverwriteMode::UnionIdentical => Disposition::Check(st),
    })
}

/// Returns the `(st_dev, st_ino)` and the permission bits of the inode of a
/// loose content object, for the identity comparison.
fn loose_object_stat(repo: &Repo, mode: RepoMode, checksum: &Checksum) -> Result<(u64, u64, u32)> {
    let path = loose_path(checksum, ObjectType::File, mode);
    let st =
        rustix::fs::statat(repo.objects_fd(), &path, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
            if e == Errno::NOENT {
                Error::ObjectNotFound {
                    checksum: *checksum,
                    ty: ObjectType::File,
                }
            } else {
                e.into()
            }
        })?;
    Ok((st.st_dev, st.st_ino, st.st_mode & PERM_MASK))
}

/// Returns `true` if an existing destination entry matches the object, for
/// [`OverwriteMode::UnionIdentical`].
///
/// [`OverwriteMode::UnionIdentical`] states the rules, observed with the
/// `ostree` command.
///
/// The checksum covers the framed header and then the payload. So a
/// destination of a different size, or with a different canonical header, has
/// a different checksum, whatever its bytes hold. The stat and the extended
/// attributes decide both, so the function reads the payload only if a match
/// is still possible.
async fn destination_is_identical(
    repo: &Repo,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    st: &rustix::fs::Stat,
    obj: &FileObject,
) -> Result<bool> {
    match &obj.kind {
        FileKind::Symlink { target } => {
            if FileType::from_raw_mode(st.st_mode) != FileType::Symlink {
                return Ok(false);
            }
            let link = rustix::fs::readlinkat(dir_fd, name, Vec::new())?;
            Ok(link.as_bytes() == target.as_bytes())
        }
        FileKind::Regular { size } => {
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                return Ok(false);
            }
            let (dev, ino, obj_perm) = loose_object_stat(repo, policy.repo_mode, obj.checksum())?;
            if st.st_dev == dev && st.st_ino == ino {
                return Ok(true);
            }
            if u64::try_from(st.st_size).ok() != Some(*size) {
                return Ok(false);
            }
            if st.st_mode & PERM_MASK != obj_perm {
                return Ok(false);
            }
            let fd = rustix::fs::openat(
                dir_fd,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let meta = FileMeta {
                uid: st.st_uid,
                gid: st.st_gid,
                mode: st.st_mode,
                xattrs: crate::object::read_all_xattrs(fd.as_fd())?,
            };
            let header = crate::write::canonical_header(policy.repo_mode, meta.regular_header());
            if header != crate::write::canonical_header(policy.repo_mode, obj.header()) {
                return Ok(false);
            }
            let checksum = hash_destination_file(fd, &header, *size).await?;
            Ok(checksum == *obj.checksum())
        }
    }
}

/// Returns the file-object checksum of a destination regular file of `size`
/// bytes, open as `fd`, with `header`. This is the checksum that an ingest of
/// the file gives. The payload streams in bounded chunks, so no whole file is
/// in memory.
async fn hash_destination_file(
    fd: OwnedFd,
    header: &ostrya_core::FileHeader,
    size: u64,
) -> Result<Checksum> {
    let mut hasher = ostrya_core::ContentHasher::new(header)?;
    let mut file = FileReader::with_len_hint(std::fs::File::from(fd), size);
    let mut buf = vec![
        0u8;
        usize::try_from(size)
            .unwrap_or(HASH_CHUNK)
            .clamp(1, HASH_CHUNK)
    ];
    loop {
        let n = file.read(&mut buf).await.map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finish())
}

/// Creates the destination directory `name` under `parent`, and returns its fd
/// and `true` if the directory is new.
///
/// The function opens a new directory writable, so the checkout can write its
/// children. An existing directory is an error under [`OverwriteMode::None`].
/// The other modes reuse it.
///
/// A union mode follows a symlink at any directory name, the destination of
/// the checkout included. [`Repo::checkout_at`] states this rule.
///
/// `widen_type_conflict` holds [`widens_type_conflict`] for the directory sites
/// that the switch reaches. These are the destination root of a directory
/// target and each directory of the walk below it.
///
/// The function removes the entry at the name and creates a directory in its
/// place. For a symlink, it removes the link alone, and the directory that the
/// link resolved to stays.
/// The destination directory of a file target is not one of the sites. So it
/// passes `false` and keeps the rule that follows symlinks.
fn create_dest_dir(
    parent: BorrowedFd<'_>,
    name: &str,
    overwrite: OverwriteMode,
    widen_type_conflict: bool,
) -> Result<(OwnedFd, bool)> {
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(TRANSIENT_DIR_MODE)) {
        Ok(()) => Ok((open_fresh_dir(parent, name)?, true)),
        Err(Errno::EXIST) => {
            // The name is taken. The `ostree` command reuses a directory and
            // merges its subtree. It never changes the type of an entry. A
            // non-directory at the name where the commit holds a directory is a
            // conflict, and it fails in every mode. This function returns a
            // checkout error for that case. The directory open then cannot
            // give a raw ENOTDIR, or ELOOP for a symlink.
            let st = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(st.st_mode) != FileType::Directory && widen_type_conflict {
                unlink_entry(parent, name, false)?;
                rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(TRANSIENT_DIR_MODE))?;
                return Ok((open_fresh_dir(parent, name)?, true));
            }
            if overwrite != OverwriteMode::None && is_symlink(st.st_mode) {
                return Ok((open_dir_following(parent, name)?, false));
            }
            if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
                return Err(Error::Checkout(format!(
                    "{name}: destination entry exists and is not a directory"
                )));
            }
            match overwrite {
                OverwriteMode::None => Err(Error::Checkout(format!(
                    "{name}: destination directory already exists"
                ))),
                _ => Ok((open_dir(parent, name)?, false)),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// Opens a directory just created under `parent`, and sets its mode past the
/// umask, so it is writable while the checkout writes its children.
fn open_fresh_dir(parent: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    let fd = open_dir(parent, name)?;
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(TRANSIENT_DIR_MODE))?;
    Ok(fd)
}

/// Returns `true` if an `st_mode` names a symlink.
fn is_symlink(mode: u32) -> bool {
    FileType::from_raw_mode(mode) == FileType::Symlink
}

/// Opens the directory that `name` under `parent` resolves to. The open follows
/// a symlink at the final component.
fn open_dir_following(parent: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    Ok(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Opens an existing directory `name` under `parent`, with no symlink follow.
fn open_dir(parent: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    Ok(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Tries to hardlink a loose object to its destination name.
///
/// Returns the destination `(dev, ino)` if the link succeeds. Returns `None`
/// if the link crossed a file system (`EXDEV`), and the caller must copy.
async fn try_link_object(
    repo: &Repo,
    policy: Policy,
    dir_fd: BorrowedFd<'_>,
    name: &str,
    checksum: &Checksum,
    remove_existing: bool,
) -> Result<Option<(u64, u64)>> {
    let objects = repo.objects_fd().try_clone_to_owned()?;
    let dir = dir_fd.try_clone_to_owned()?;
    let loose = loose_path(checksum, ObjectType::File, policy.repo_mode);
    let name = name.to_owned();
    ostrya_rt::unblock(move || {
        if remove_existing {
            remove_dir_entry(dir.as_fd(), &name)?;
        }
        match rustix::fs::linkat(
            objects.as_fd(),
            &loose,
            dir.as_fd(),
            &name,
            AtFlags::empty(),
        ) {
            Ok(()) => {
                let st = rustix::fs::statat(dir.as_fd(), &name, AtFlags::SYMLINK_NOFOLLOW)?;
                Ok(Some((st.st_dev, st.st_ino)))
            }
            Err(Errno::XDEV) => Ok(None),
            Err(Errno::EXIST) => Err(collision(&name)),
            Err(e) => Err(e.into()),
        }
    })
    .await
}

/// Fills the destination temp file with the payload of the object.
///
/// If the loose object holds the raw payload (the bare family), the function
/// tries a `FICLONE` reflink. Otherwise it streams the bytes through
/// [`FileObject::reader`], which inflates an archive object while it reads. No
/// whole payload is in memory.
async fn copy_object(repo: &Repo, obj: &FileObject, temp: &OwnedFd, policy: Policy) -> Result<()> {
    if policy.repo_mode != RepoMode::Archive {
        let objects = repo.objects_fd().try_clone_to_owned()?;
        let loose = loose_path(obj.checksum(), ObjectType::File, policy.repo_mode);
        let dst = temp.as_fd().try_clone_to_owned()?;
        let cloned =
            ostrya_rt::unblock(move || reflink_object(objects.as_fd(), &loose, dst.as_fd())).await;
        if cloned {
            return Ok(());
        }
    }
    let reader = obj.reader().await?;
    let mut writer = RtFile::from(temp.as_fd().try_clone_to_owned()?);
    crate::write::copy_stream(reader, &mut writer)
        .await
        .map_err(Error::Io)?;
    crate::write::flush(&mut writer).await.map_err(Error::Io)?;
    Ok(())
}

/// Tries to clone the extents of a loose object into `dst` with `FICLONE`.
///
/// Each failure returns `false`, and the caller then streams the payload. The
/// failures include a file system without reflink, a destination on another
/// file system, and a missing object. If `FICLONE` fails, it writes nothing,
/// so `dst` stays empty for the stream.
fn reflink_object(objects: BorrowedFd<'_>, loose: &str, dst: BorrowedFd<'_>) -> bool {
    match rustix::fs::openat(
        objects,
        loose,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(src) => rustix::fs::ioctl_ficlone(dst, &src).is_ok(),
        Err(_) => false,
    }
}

/// The data that the blocking pool needs to finish a copied regular file.
struct FinishCopy {
    dir: OwnedFd,
    name: String,
    temp: OwnedFd,
    kind: TempKind,
    effective: CheckoutMode,
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: Xattrs,
    enable_fsync: bool,
    remove_existing: bool,
}

/// Applies the metadata to the temp inode of a copied regular file and links
/// it to its destination name. If the plan says so, it fsyncs the inode first.
///
/// Returns the destination `(dev, ino)`.
fn finish_copy_blocking(plan: FinishCopy) -> Result<(u64, u64)> {
    apply_regular_metadata(
        plan.temp.as_fd(),
        plan.effective,
        plan.uid,
        plan.gid,
        plan.mode,
        &plan.xattrs,
    )?;
    if plan.enable_fsync {
        rustix::fs::fsync(plan.temp.as_fd())?;
    }
    if plan.remove_existing {
        remove_dir_entry(plan.dir.as_fd(), &plan.name)?;
    }
    match &plan.kind {
        TempKind::Anonymous => {
            let proc = format!("/proc/self/fd/{}", plan.temp.as_raw_fd());
            match rustix::fs::linkat(
                CWD,
                proc.as_str(),
                plan.dir.as_fd(),
                &plan.name,
                AtFlags::SYMLINK_FOLLOW,
            ) {
                Ok(()) => {}
                Err(Errno::EXIST) => return Err(collision(&plan.name)),
                Err(e) => return Err(e.into()),
            }
        }
        TempKind::Named(tmp) => {
            // If the copy does not remove an existing entry first, a taken
            // destination name is a collision. The anonymous (linkat) path
            // refuses it with EEXIST. A plain renameat replaces the name in
            // place, with no error, and overwrites an entry that arrived after
            // pre_check. RENAME_NOREPLACE gives the same collision as the
            // anonymous path.
            let result = if !plan.remove_existing {
                match rustix::fs::renameat_with(
                    plan.dir.as_fd(),
                    tmp.as_str(),
                    plan.dir.as_fd(),
                    &plan.name,
                    RenameFlags::NOREPLACE,
                ) {
                    // On a kernel or file system without RENAME_NOREPLACE, the
                    // function uses a plain rename. That rename cannot guard
                    // against a concurrent writer.
                    Err(Errno::INVAL | Errno::NOSYS) => rustix::fs::renameat(
                        plan.dir.as_fd(),
                        tmp.as_str(),
                        plan.dir.as_fd(),
                        &plan.name,
                    ),
                    other => other,
                }
            } else {
                rustix::fs::renameat(plan.dir.as_fd(), tmp.as_str(), plan.dir.as_fd(), &plan.name)
            };
            if let Err(e) = result {
                let _ = rustix::fs::unlinkat(plan.dir.as_fd(), tmp.as_str(), AtFlags::empty());
                return Err(if e == Errno::EXIST {
                    collision(&plan.name)
                } else {
                    e.into()
                });
            }
        }
    }
    let st = rustix::fs::statat(plan.dir.as_fd(), &plan.name, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok((st.st_dev, st.st_ino))
}

/// Applies the checkout-mode metadata of a regular file to its inode fd.
fn apply_regular_metadata(
    fd: BorrowedFd<'_>,
    effective: CheckoutMode,
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: &Xattrs,
) -> Result<()> {
    match effective {
        CheckoutMode::None => {
            // The owner goes on first. A chown of a regular file removes
            // `security.capability` and clears the set-user-ID bit. It also
            // clears the set-group-ID bit if group execute is set, also when
            // the ids do not change.
            //
            // The xattrs go on before the mode. The kernel checks a `user.*`
            // xattr against the write permission of the inode. A logical mode
            // without owner write (0444, 0555) does not give it.
            rustix::fs::fchown(fd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
            for (name, value) in xattrs.iter() {
                crate::write::set_inode_xattr(fd, name, value)?;
            }
            rustix::fs::fchmod(fd, Mode::from_raw_mode(mode & PERM_MASK))?;
        }
        CheckoutMode::User => {
            rustix::fs::fchmod(fd, Mode::from_raw_mode(mode & USER_PERM_MASK))?;
        }
    }
    Ok(())
}

/// Applies the checkout-mode metadata of a directory to its fd.
///
/// Both checkout modes apply the full logical mode (`mode & 0o7777`, with the
/// special bits). Only the chown and the xattrs differ. The mode goes on last,
/// because a `user.*` xattr needs write permission on the inode. A chown of a
/// directory removes no xattr and keeps the special bits, so the xattrs can go
/// on before the owner.
///
/// If `bareuseronly_dirs` is set, the function applies
/// [`BAREUSERONLY_DIR_MASK`]. The one call site is the fresh arm of the
/// directory walk. So the mask reaches the destination root and each directory
/// that the checkout creates, and no directory that it reuses.
fn apply_dir_metadata(
    fd: BorrowedFd<'_>,
    effective: CheckoutMode,
    bareuseronly_dirs: bool,
    dm: &DirMeta,
) -> Result<()> {
    if effective == CheckoutMode::None {
        for (name, value) in dm.xattrs.iter() {
            crate::write::set_inode_xattr(fd, name, value)?;
        }
        rustix::fs::fchown(fd, Some(Uid::from_raw(dm.uid)), Some(Gid::from_raw(dm.gid)))?;
    }
    let mask = if bareuseronly_dirs {
        BAREUSERONLY_DIR_MASK
    } else {
        PERM_MASK
    };
    rustix::fs::fchmod(fd, Mode::from_raw_mode(dm.mode & mask))?;
    Ok(())
}

/// The data that the blocking pool needs to create a symlink again.
struct RecreateSymlink {
    dir: OwnedFd,
    name: String,
    target: String,
    effective: CheckoutMode,
    uid: u32,
    gid: u32,
    xattrs: Xattrs,
    remove_existing: bool,
}

/// Creates a symlink again and applies its checkout-mode metadata.
fn recreate_symlink_blocking(plan: RecreateSymlink) -> Result<()> {
    if plan.remove_existing {
        remove_dir_entry(plan.dir.as_fd(), &plan.name)?;
    }
    match rustix::fs::symlinkat(plan.target.as_str(), plan.dir.as_fd(), &plan.name) {
        Ok(()) => {}
        Err(Errno::EXIST) => return Err(collision(&plan.name)),
        Err(e) => return Err(e.into()),
    }
    if plan.effective == CheckoutMode::None {
        rustix::fs::chownat(
            plan.dir.as_fd(),
            plan.name.as_str(),
            Some(Uid::from_raw(plan.uid)),
            Some(Gid::from_raw(plan.gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        for (name, value) in plan.xattrs.iter() {
            crate::write::set_link_xattr(plan.dir.as_fd(), &plan.name, name, value)?;
        }
    }
    Ok(())
}

/// Removes a destination entry, and the subtree of a directory. A missing entry
/// is not an error.
fn remove_dir_entry(dir: BorrowedFd<'_>, name: &str) -> Result<()> {
    match entry_is_dir(dir, name)? {
        None => Ok(()),
        Some(false) => unlink_entry(dir, name, false),
        Some(true) => remove_subtree(dir, name),
    }
}

/// Returns `true` if `name` under `dir` is a directory, or `None` if the name
/// is not taken.
fn entry_is_dir(dir: BorrowedFd<'_>, name: &str) -> Result<Option<bool>> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(
            FileType::from_raw_mode(st.st_mode) == FileType::Directory,
        )),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Unlinks `name` under `dir`. A name that is already gone is not an error.
fn unlink_entry(dir: BorrowedFd<'_>, name: &str, is_dir: bool) -> Result<()> {
    let flags = if is_dir {
        AtFlags::REMOVEDIR
    } else {
        AtFlags::empty()
    };
    match rustix::fs::unlinkat(dir, name, flags) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Removes `name` under `dir` and everything below it.
///
/// The removal is a loop over an explicit stack of levels, with one directory
/// descriptor open at a time. A step down replaces the descriptor of the level
/// with that of the child. A step up replaces it with the one that `..` opens.
/// That `..` names the parent, because the empty level is still linked where
/// the walk opened it.
///
/// Each level costs a name and an entry list on the heap. So the function
/// removes a subtree whole, also if it is deeper than the process descriptor
/// limit or the thread stack allows.
fn remove_subtree(dir: BorrowedFd<'_>, name: &str) -> Result<()> {
    let mut level = match open_dir(dir, name) {
        Ok(fd) => fd,
        // The subtree is gone, which is the goal of the removal. The type
        // comes from `getdents64` or from a `statat` of the caller, so the
        // name can disappear between the two calls.
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    // One entry for each level on the path from `name` down to the level in
    // hand. The entry holds the name of the level and what is left to remove
    // in it.
    let mut levels = vec![(name.to_owned(), read_level(level.as_fd())?)];

    while let Some((_, entries)) = levels.last_mut() {
        match entries.pop() {
            Some((child, false)) => unlink_entry(level.as_fd(), &child, false)?,
            Some((child, true)) => {
                let child_fd = match open_dir(level.as_fd(), &child) {
                    Ok(fd) => fd,
                    // The child is gone, which is the goal of the removal.
                    Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                let child_entries = read_level(child_fd.as_fd())?;
                level = child_fd;
                levels.push((child, child_entries));
            }
            None => {
                let (cleared, _) = levels.pop().expect("a level is in hand within the loop");
                if levels.is_empty() {
                    drop(level);
                    return unlink_entry(dir, &cleared, true);
                }
                level = open_dir(level.as_fd(), "..")?;
                unlink_entry(level.as_fd(), &cleared, true)?;
            }
        }
    }
    Ok(())
}

/// Removes each entry of a directory, with the subtrees of its subdirectories.
/// The function reads all names before the removal, so the unlinks do not
/// change the iteration.
fn clear_dir(dir: BorrowedFd<'_>) -> Result<()> {
    for (name, is_dir) in read_level(dir)? {
        if is_dir {
            remove_subtree(dir, &name)?;
        } else {
            unlink_entry(dir, &name, false)?;
        }
    }
    Ok(())
}

/// Returns the entries of one directory, each with `true` if it is a
/// directory.
///
/// `getdents64` already holds the type, so the function reads the type from
/// the entry and makes no call for each name. If a file system reports
/// [`FileType::Unknown`], one `statat` for that name gives the type. If the
/// name is gone when that call runs, the function leaves the name out.
fn read_level(level: BorrowedFd<'_>) -> Result<Vec<(String, bool)>> {
    let mut entries = Vec::new();
    for entry in Dir::read_from(level)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let name = name
            .to_str()
            .map_err(|_| Error::InvalidFormat("directory entry name is not valid UTF-8".into()))?
            .to_owned();
        let is_dir = match entry.file_type() {
            FileType::Directory => true,
            FileType::Unknown => match entry_is_dir(level, &name)? {
                Some(is_dir) => is_dir,
                None => continue,
            },
            _ => false,
        };
        entries.push((name, is_dir));
    }
    Ok(entries)
}

/// Fsyncs a directory on the blocking pool.
async fn fsync_dir(dir: OwnedFd) -> Result<()> {
    ostrya_rt::unblock(move || rustix::fs::fsync(dir.as_fd()).map_err(Error::from)).await
}

/// Returns the error for a destination collision.
fn collision(name: &str) -> Error {
    Error::Checkout(format!("{name}: destination entry already exists"))
}

/// The checkout decisions that come from the options and the repository mode.
#[derive(Debug, Clone, Copy)]
struct Policy {
    /// The storage mode of the repository.
    repo_mode: RepoMode,
    /// The checkout mode that the caller requested.
    requested: CheckoutMode,
    /// The checkout mode that the checkout applies. `bare-user-only` forces
    /// [`User`](CheckoutMode::User) for each request, because its objects
    /// carry no owner and no xattrs, and the inode already holds the canonical
    /// mode.
    effective: CheckoutMode,
    force_copy: bool,
    require_hardlinks: bool,
    bareuseronly_dirs: bool,
    overwrite: OverwriteMode,
    enable_fsync: bool,
    process_whiteouts: bool,
    process_passthrough_whiteouts: bool,
}

impl Policy {
    fn new(repo_mode: RepoMode, opts: &CheckoutOptions) -> Policy {
        let effective = if repo_mode == RepoMode::BareUserOnly {
            CheckoutMode::User
        } else {
            opts.mode
        };
        Policy {
            repo_mode,
            requested: opts.mode,
            effective,
            force_copy: opts.force_copy,
            require_hardlinks: opts.require_hardlinks,
            bareuseronly_dirs: opts.bareuseronly_dirs,
            overwrite: opts.overwrite,
            enable_fsync: opts.enable_fsync,
            process_whiteouts: opts.process_whiteouts,
            process_passthrough_whiteouts: opts.process_passthrough_whiteouts,
        }
    }
}

/// Returns `true` if the checkout can hardlink the loose object of a regular
/// file. This is the case only if the stored inode already matches the
/// destination, and never under `force_copy`.
fn hardlink_regular(policy: Policy) -> bool {
    if policy.force_copy {
        return false;
    }
    matches!(
        (policy.repo_mode, policy.requested),
        (RepoMode::Bare, CheckoutMode::None)
            | (RepoMode::BareUser, CheckoutMode::User)
            | (RepoMode::BareUserOnly, _)
    )
}

/// Returns `true` if the checkout can hardlink the loose object of a symlink.
/// This is the case only under `bare` and [`None`](CheckoutMode::None), where
/// the object is a real symlink with the logical owner and xattrs.
fn hardlink_symlink(policy: Policy) -> bool {
    !policy.force_copy
        && policy.repo_mode == RepoMode::Bare
        && policy.requested == CheckoutMode::None
}

/// Returns `true` if the checkout can hardlink the loose object of this
/// regular file.
///
/// The checkout writes a zero-length object as a new file in each mode, so its
/// destination has its own inode at link count 1. The `ostree` command gives
/// the same result, so the link counts of both destinations agree entry for
/// entry.
fn hardlink_regular_object(policy: Policy, obj: &FileObject) -> bool {
    hardlink_regular(policy) && !matches!(obj.kind, FileKind::Regular { size: 0 })
}

/// Returns `true` if [`require_hardlinks`](CheckoutOptions::require_hardlinks)
/// refuses this entry.
///
/// A directory reaches no file site, so the switch never refuses it. The
/// checkout writes a zero-length regular file as a new file in each mode, so
/// it is not a copy that the switch refuses. A regular file of non-zero length
/// and a symlink each follow a table of their own.
fn require_hardlinks_refuses(policy: Policy, obj: &FileObject) -> bool {
    if !policy.require_hardlinks {
        return false;
    }
    match obj.kind {
        FileKind::Regular { size } => size != 0 && require_hardlinks_refuses_regular(policy),
        FileKind::Symlink { .. } => require_hardlinks_refuses_symlink(policy),
    }
}

/// Returns `true` if [`require_hardlinks`](CheckoutOptions::require_hardlinks)
/// refuses a regular file of non-zero length.
///
/// The table is the complement of [`hardlink_regular`]. Observed with a
/// one-byte-file commit, checked out of each mode under both checkout modes.
/// [`require_hardlinks_refuses`], the one caller, reads the switch itself.
fn require_hardlinks_refuses_regular(policy: Policy) -> bool {
    !hardlink_regular(policy)
}

/// Returns `true` if [`require_hardlinks`](CheckoutOptions::require_hardlinks)
/// refuses a symlink.
///
/// Observed with a symlink-only commit, checked out of each mode under both
/// checkout modes. The refused set is `archive` under either checkout mode and
/// `bare` under [`User`](CheckoutMode::User). This table differs from the one
/// that [`hardlink_symlink`] follows. `bare-user` under
/// [`None`](CheckoutMode::None) creates the link again and does not refuse it.
///
/// `bare-user-shared` and `bare-split-xattrs` are modes of ostrya that the
/// `ostree` command does not carry, so no observation decides them. Each
/// stores a symlink as `bare-user` does and creates it again. So each follows
/// `bare-user` here and refuses nothing.
///
/// [`require_hardlinks_refuses`], the one caller, reads the switch itself.
fn require_hardlinks_refuses_symlink(policy: Policy) -> bool {
    matches!(
        (policy.repo_mode, policy.requested),
        (RepoMode::Archive, _) | (RepoMode::Bare, CheckoutMode::User)
    )
}

/// Refuses a [`require_hardlinks`](CheckoutOptions::require_hardlinks) checkout
/// at a destination directory on another file system than the repository.
///
/// No entry of such a directory can be a hardlink. Each directory that the
/// walk enters reaches this check: the destination root and each directory
/// below it, new or reused. The check refuses each one before the walk reads or
/// writes anything in it. The two `fstat` calls are synchronous and cost
/// little.
///
/// The check comes after the walk creates the directory. This is the order of
/// the `ostree` command, so both leave the same destination. Observed with a
/// commit whose subtree sits behind a destination symlink to a second file
/// system, checked out with `-H`. The `ostree` command refuses whatever the
/// subtree holds, a subtree of one empty directory included, in each
/// repository mode.
fn check_hardlink_device(repo: &Repo, policy: Policy, dest: BorrowedFd<'_>) -> Result<()> {
    if !policy.require_hardlinks {
        return Ok(());
    }
    let src = rustix::fs::fstat(repo.objects_fd())?.st_dev;
    let dst = rustix::fs::fstat(dest)?.st_dev;
    if src == dst {
        return Ok(());
    }
    Err(Error::HardlinkAcrossDevices { src, dst })
}

/// Returns the cross-device refusal for a `linkat` that returned `EXDEV`, with
/// the device of each side. The caller knows that the link crossed a file
/// system, so this function always returns the error.
fn hardlink_across_devices(repo: &Repo, dest: BorrowedFd<'_>) -> Result<()> {
    let src = rustix::fs::fstat(repo.objects_fd())?.st_dev;
    let dst = rustix::fs::fstat(dest)?.st_dev;
    Err(Error::HardlinkAcrossDevices { src, dst })
}

/// Returns `true` if the whiteout switch widens the union-files disposition
/// over a type conflict.
///
/// The checkout then removes a destination entry whose type differs from the
/// tree entry. `process_whiteouts` widens
/// [`UnionFiles`](OverwriteMode::UnionFiles) only.
/// `process_passthrough_whiteouts` widens nothing.
fn widens_type_conflict(policy: Policy) -> bool {
    policy.process_whiteouts && policy.overwrite == OverwriteMode::UnionFiles
}

/// `CheckoutOptions` can move across tasks and threads, so the recursive
/// checkout future stays `Send`.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<CheckoutOptions>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(repo_mode: RepoMode, mode: CheckoutMode, force_copy: bool) -> Policy {
        Policy::new(
            repo_mode,
            &CheckoutOptions {
                mode,
                force_copy,
                ..CheckoutOptions::default()
            },
        )
    }

    /// The same with `require_hardlinks` set.
    fn require_policy(repo_mode: RepoMode, mode: CheckoutMode) -> Policy {
        Policy::new(
            repo_mode,
            &CheckoutOptions {
                mode,
                require_hardlinks: true,
                ..CheckoutOptions::default()
            },
        )
    }

    /// The hardlink matrix: the checkout hardlinks a regular file exactly when
    /// the object inode is already the target inode.
    #[test]
    fn hardlink_regular_matrix() {
        use CheckoutMode::{None, User};
        use RepoMode::{Archive, Bare, BareUser, BareUserOnly, BareUserShared};

        assert!(hardlink_regular(policy(Bare, None, false)));
        assert!(!hardlink_regular(policy(Bare, User, false)));
        assert!(!hardlink_regular(policy(BareUser, None, false)));
        assert!(hardlink_regular(policy(BareUser, User, false)));
        assert!(hardlink_regular(policy(BareUserOnly, None, false)));
        assert!(hardlink_regular(policy(BareUserOnly, User, false)));
        assert!(!hardlink_regular(policy(BareUserShared, None, false)));
        assert!(!hardlink_regular(policy(BareUserShared, User, false)));
        assert!(!hardlink_regular(policy(Archive, None, false)));
        assert!(!hardlink_regular(policy(Archive, User, false)));

        // force_copy suppresses every hardlink.
        assert!(!hardlink_regular(policy(Bare, None, true)));
        assert!(!hardlink_regular(policy(BareUserOnly, None, true)));
    }

    /// The checkout hardlinks a symlink only under `bare` and `None`. In all
    /// other cases, it creates the symlink again.
    #[test]
    fn hardlink_symlink_matrix() {
        use CheckoutMode::{None, User};
        use RepoMode::{Archive, Bare, BareUser, BareUserOnly};

        assert!(hardlink_symlink(policy(Bare, None, false)));
        assert!(!hardlink_symlink(policy(Bare, User, false)));
        assert!(!hardlink_symlink(policy(Bare, None, true)));
        assert!(!hardlink_symlink(policy(BareUser, None, false)));
        assert!(!hardlink_symlink(policy(BareUserOnly, None, false)));
        assert!(!hardlink_symlink(policy(Archive, None, false)));
    }

    /// The refusal table for regular files. The switch refuses a regular file
    /// of non-zero length wherever the repository mode and the checkout mode
    /// in effect give a copy. `require_hardlinks_refuses` reads the switch
    /// itself. `tests/checkout.rs::require_hardlinks_refuses_at_the_entry`
    /// covers its clear arm.
    #[test]
    fn require_hardlinks_regular_matrix() {
        use CheckoutMode::{None, User};
        use RepoMode::{Archive, Bare, BareSplitXattrs, BareUser, BareUserOnly, BareUserShared};

        assert!(!require_hardlinks_refuses_regular(require_policy(
            Bare, None
        )));
        assert!(require_hardlinks_refuses_regular(require_policy(
            Bare, User
        )));
        assert!(require_hardlinks_refuses_regular(require_policy(
            BareUser, None
        )));
        assert!(!require_hardlinks_refuses_regular(require_policy(
            BareUser, User
        )));
        assert!(!require_hardlinks_refuses_regular(require_policy(
            BareUserOnly,
            None
        )));
        assert!(!require_hardlinks_refuses_regular(require_policy(
            BareUserOnly,
            User
        )));
        assert!(require_hardlinks_refuses_regular(require_policy(
            BareUserShared,
            None
        )));
        assert!(require_hardlinks_refuses_regular(require_policy(
            BareUserShared,
            User
        )));
        assert!(require_hardlinks_refuses_regular(require_policy(
            Archive, None
        )));
        assert!(require_hardlinks_refuses_regular(require_policy(
            Archive, User
        )));
        assert!(require_hardlinks_refuses_regular(require_policy(
            BareSplitXattrs,
            None
        )));
        assert!(require_hardlinks_refuses_regular(require_policy(
            BareSplitXattrs,
            User
        )));
    }

    /// The refusal table for symlinks, which differs from the table for regular
    /// files. `bare-user` under `None` refuses a regular file and accepts a
    /// symlink. `require_hardlinks_refuses` reads the switch itself.
    /// `tests/checkout.rs::require_hardlinks_refuses_at_the_entry` covers its
    /// clear arm.
    #[test]
    fn require_hardlinks_symlink_matrix() {
        use CheckoutMode::{None, User};
        use RepoMode::{Archive, Bare, BareSplitXattrs, BareUser, BareUserOnly, BareUserShared};

        assert!(require_hardlinks_refuses_symlink(require_policy(
            Archive, None
        )));
        assert!(require_hardlinks_refuses_symlink(require_policy(
            Archive, User
        )));
        assert!(!require_hardlinks_refuses_symlink(require_policy(
            Bare, None
        )));
        assert!(require_hardlinks_refuses_symlink(require_policy(
            Bare, User
        )));
        assert!(!require_hardlinks_refuses_symlink(require_policy(
            BareUser, None
        )));
        assert!(!require_hardlinks_refuses_symlink(require_policy(
            BareUser, User
        )));
        assert!(!require_hardlinks_refuses_symlink(require_policy(
            BareUserOnly,
            None
        )));
        assert!(!require_hardlinks_refuses_symlink(require_policy(
            BareUserOnly,
            User
        )));
        assert!(!require_hardlinks_refuses_symlink(require_policy(
            BareUserShared,
            None
        )));
        assert!(!require_hardlinks_refuses_symlink(require_policy(
            BareUserShared,
            User
        )));
        assert!(!require_hardlinks_refuses_symlink(require_policy(
            BareSplitXattrs,
            None
        )));
        assert!(!require_hardlinks_refuses_symlink(require_policy(
            BareSplitXattrs,
            User
        )));
    }

    /// `bare-user-only` forces `User` for each requested mode, so a `None`
    /// request never tries a chown to 0:0 that cannot succeed.
    #[test]
    fn bare_user_only_forces_user_semantics() {
        assert_eq!(
            policy(RepoMode::BareUserOnly, CheckoutMode::None, false).effective,
            CheckoutMode::User
        );
        assert_eq!(
            policy(RepoMode::Bare, CheckoutMode::None, false).effective,
            CheckoutMode::None
        );
    }

    /// A scratch directory removed on drop, for the named-temp copy-path tests.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("ostrya-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Returns a named-temp `FinishCopy` that removes nothing first
    /// (`remove_existing == false`). It stages `b"NEW"` as `.ostrya-test-tmp`
    /// and targets `dest` in `scratch`.
    fn named_none_plan(scratch: &Scratch) -> FinishCopy {
        use std::io::Write as _;

        let dir_fd: OwnedFd = std::fs::File::open(scratch.path()).unwrap().into();
        let tmp_name = ".ostrya-test-tmp".to_owned();
        let mut tmp = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(scratch.path().join(&tmp_name))
            .unwrap();
        tmp.write_all(b"NEW").unwrap();
        FinishCopy {
            dir: dir_fd,
            name: "dest".to_owned(),
            temp: tmp.into(),
            kind: TempKind::Named(tmp_name),
            effective: CheckoutMode::User,
            uid: 0,
            gid: 0,
            mode: 0o644,
            xattrs: Xattrs::empty(),
            enable_fsync: false,
            remove_existing: false,
        }
    }

    /// The named-temp path obeys `OverwriteMode::None`. A destination name that
    /// appears before the rename is a collision, and the existing entry stays
    /// as it is. The test needs a file system with `RENAME_NOREPLACE`, which
    /// each file system has since Linux 3.15.
    #[test]
    fn named_temp_none_rejects_a_racing_collision() {
        let scratch = Scratch::new("co-named-collide");
        std::fs::write(scratch.path().join("dest"), b"OLD").unwrap();

        let err = finish_copy_blocking(named_none_plan(&scratch));
        assert!(
            matches!(err, Err(Error::Checkout(_))),
            "a colliding destination is a checkout error, got {err:?}"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("dest")).unwrap(),
            b"OLD",
            "the existing entry is not overwritten"
        );
    }

    /// The same named-temp `OverwriteMode::None` path writes the file if no
    /// destination entry exists.
    #[test]
    fn named_temp_none_places_when_absent() {
        let scratch = Scratch::new("co-named-fresh");

        finish_copy_blocking(named_none_plan(&scratch)).unwrap();
        assert_eq!(std::fs::read(scratch.path().join("dest")).unwrap(), b"NEW");
    }
}
