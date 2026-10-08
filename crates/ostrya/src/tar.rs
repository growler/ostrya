//! Tar import and export.
//!
//! - [`Repo::export_tar`] writes the tree of a commit as a file system tar
//!   stream. [`TarExportOptions`] holds its options.
//! - [`Repo::import_tar`] reads a file system tar stream into a new
//!   [`MutableTree`]. [`TarImportOptions`] holds its options.
//! - [`Repo::import_tar_into`] reads a tar stream into a tree that can hold
//!   the entries of an earlier source, and applies a [`CommitModifier`].
//!
//! The caller writes the imported tree with
//! [`Transaction::write_mtree`](crate::Transaction::write_mtree) and commits it
//! with [`Transaction::write_commit`](crate::Transaction::write_commit).

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, UNIX_EPOCH};

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::StreamExt;
use ostrya_core::{Checksum, Commit, DirMeta, Xattrs};
use smol_tar::{
    AttrList, TarDirectory, TarEntry, TarLink, TarReader, TarRegularFile, TarSymlink, TarWriter,
};

use crate::checkout::is_root_path;
use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject};
use crate::ingest::{adjust_meta, finalize_meta, to_dirmeta};
use crate::modifier::{CommitModifier, CommitModifierFlags, FilterResult, Owner};
use crate::mtree::{ChildKind, MutableTree};
use crate::repo::Repo;
use crate::transaction::{FileMeta, Transaction};
use crate::tree::{RepoTree, TreeEntry};

/// The `S_IFDIR` file-type bits in the `st_mode` of a directory.
const S_IFDIR: u32 = 0o040000;
/// The `S_IFLNK` file-type bits in the `st_mode` of a symlink.
const S_IFLNK: u32 = 0o120000;
/// The permission bits that the octal mode field of a tar header keeps.
const PERM_MASK: u32 = 0o7777;

/// A boxed payload reader that does not depend on the runtime. One type
/// serves all entry kinds, so one [`TarWriter`] instance serves the whole
/// stream. `Pin<Box<..>>` is `Unpin`, which the writer requires of the body
/// reader.
type BodyReader = Pin<Box<dyn AsyncRead + Send>>;

/// The options of [`Repo::export_tar`].
#[derive(Debug, Default, Clone)]
pub struct TarExportOptions {
    /// The directory of the commit tree that becomes the archive root.
    ///
    /// If it is `None`, the archive root is the commit root. A path with no
    /// name component names the whole tree. A path with a name component and
    /// a `..` component names nothing, because no directory holds a `..`
    /// entry. If the path names a file, a symlink, or nothing, the export
    /// fails with [`Error::Tar`].
    pub subpath: Option<PathBuf>,
    /// A prefix for each member pathname.
    ///
    /// The name of the root member is the prefix with one `/` added, if the
    /// prefix does not end in `/`. The name of each other member is the prefix
    /// followed by the relative path of the member, with no separator.
    /// Because of this, a prefix that acts as a directory must end in `/`.
    ///
    /// The link name of a hardlink carries the prefix. The target of a symlink
    /// is the stored target and carries no prefix. If the prefix is empty or
    /// `None`, the root member is `./` and each other member has its bare
    /// relative name.
    pub prefix: Option<String>,
    /// If `true`, the export writes no `SCHILY.xattr.*` records, whatever
    /// extended attributes the tree holds.
    pub skip_xattrs: bool,
}

impl TarExportOptions {
    /// Creates the default export options.
    pub fn new() -> TarExportOptions {
        TarExportOptions::default()
    }
}

/// A hook that renames the member pathnames of an import.
///
/// The hook receives the normalized member name and returns the name that the
/// import uses for the member. [`Repo::import_tar_into`] states the
/// normalization. If the hook returns an error, the import fails with that
/// error.
pub type TarRename = Box<dyn FnMut(&str) -> Result<String> + Send>;

/// The options of [`Repo::import_tar`] and [`Repo::import_tar_into`].
#[derive(Default)]
pub struct TarImportOptions {
    /// If `true`, the import rewrites a top-level `etc` component to
    /// `usr/etc`.
    ///
    /// This matches the ostree convention that composes the configuration
    /// into `/usr`. The default is `false`.
    pub etc_to_usr_etc: bool,
    /// The owner uid that each imported entry records, if set.
    ///
    /// It replaces the uid in the tar header. It also applies to the default
    /// metadata of a directory that the archive does not name.
    pub owner_uid: Option<u32>,
    /// The owner gid that each imported entry records, if set.
    ///
    /// It follows the rules of [`owner_uid`](TarImportOptions::owner_uid).
    pub owner_gid: Option<u32>,
    /// If `true`, the import records no extended attributes.
    ///
    /// The import ignores each `SCHILY.xattr.*` record of the archive.
    pub skip_xattrs: bool,
    /// If `true`, the import creates each parent directory that the archive
    /// does not name.
    ///
    /// If `true`, the import also sets the root metadata at its end.
    /// [`Repo::import_tar_into`] states the rule. If `false`, a member that
    /// needs such a parent fails the import with [`Error::TarMissingParent`].
    ///
    /// A created directory records mode `0755` and empty extended attributes.
    /// Its owner is the uid and gid in the tar header of the member whose
    /// import created it, after [`owner_uid`](TarImportOptions::owner_uid)
    /// and [`owner_gid`](TarImportOptions::owner_gid). A directory that a
    /// hardlink member creates records `0:0`, or `owner_uid` and `owner_gid`
    /// if they are set.
    pub autocreate_parents: bool,
    /// A hook that rewrites the pathname of each member before the import
    /// uses it.
    pub rename: Option<TarRename>,
}

impl std::fmt::Debug for TarImportOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TarImportOptions")
            .field("etc_to_usr_etc", &self.etc_to_usr_etc)
            .field("owner_uid", &self.owner_uid)
            .field("owner_gid", &self.owner_gid)
            .field("skip_xattrs", &self.skip_xattrs)
            .field("autocreate_parents", &self.autocreate_parents)
            .field("rename", &self.rename.is_some())
            .finish()
    }
}

impl TarImportOptions {
    /// Creates the default import options.
    pub fn new() -> TarImportOptions {
        TarImportOptions::default()
    }

    /// Sets [`etc_to_usr_etc`](TarImportOptions::etc_to_usr_etc) to `on`.
    pub fn with_etc_migration(mut self, on: bool) -> TarImportOptions {
        self.etc_to_usr_etc = on;
        self
    }

    /// Returns the uid that an entry records: the declared one, else the one
    /// given.
    fn uid(&self, from_header: u32) -> u32 {
        self.owner_uid.unwrap_or(from_header)
    }

    /// Returns the gid that an entry records: the declared one, else the one
    /// given.
    fn gid(&self, from_header: u32) -> u32 {
        self.owner_gid.unwrap_or(from_header)
    }
}

/// One entry of the export, in output order. The walk captures the metadata.
/// The export opens the payload of a regular file only when it writes the
/// entry. It holds at most one content fd at a time.
enum Item {
    Dir {
        path: String,
        meta: DirMeta,
    },
    Regular {
        path: String,
        file: FileObject,
        size: u64,
    },
    Symlink {
        path: String,
        file: FileObject,
        target: String,
    },
    Hardlink {
        path: String,
        target: String,
    },
}

/// Methods that export and import tar streams.
impl Repo {
    /// Writes the tree of a commit to `out` as a tar stream.
    ///
    /// [`TarExportOptions`] selects the archive root, the name prefix, and the
    /// xattr records.
    ///
    /// # Stream format
    ///
    /// The stream is a file system tar. It holds the files of the tree and no
    /// ostree objects:
    ///
    /// - Member names are relative paths. The root directory is the member
    ///   `./`. The name of each directory member ends in `/`.
    /// - Ownership is numeric.
    /// - Each timestamp is the commit timestamp, with a zero nanosecond part.
    /// - Extended attributes are `SCHILY.xattr.*` PAX records.
    ///
    /// The export walks the tree depth-first. In each directory, it writes the
    /// entries in name order, with files and subdirectories in one sequence.
    /// A directory member comes just before its contents.
    ///
    /// The first regular file of a content object goes into the stream in
    /// full. Each later regular file of the same object is a hardlink to the
    /// first one. Two files have the same object if they have the same
    /// ownership, mode, xattrs, and content, because all of these go into the
    /// object checksum. The export writes each symlink as its own symlink
    /// member.
    ///
    /// # Errors
    ///
    /// - [`Error::Tar`] if [`subpath`](TarExportOptions::subpath) names a
    ///   file, a symlink, or nothing.
    /// - [`Error::Tar`] if an xattr name in the tree is not valid UTF-8.
    /// - [`Error::ObjectNotFound`] if the commit or an object that it reaches
    ///   is not in the object store.
    /// - [`Error::Core`] if a commit, dirtree, or dirmeta object does not
    ///   parse.
    /// - [`Error::InvalidFormat`] if a file object does not have the form of
    ///   the repository mode.
    /// - [`Error::Io`] if an xattr name holds a byte that is not graphic
    ///   ASCII, or holds `=`.
    /// - [`Error::Io`] if a write to `out` fails, or if a read of the object
    ///   store fails.
    pub async fn export_tar(
        &self,
        commit: &Checksum,
        opts: TarExportOptions,
        out: impl AsyncWrite,
    ) -> Result<()> {
        let (commit_obj, _) = self.load_commit(commit).await?;
        let mtime = UNIX_EPOCH + Duration::from_secs(commit_obj.timestamp);
        let (dirtree, dirmeta) = export_root(self, &commit_obj, opts.subpath.as_deref()).await?;
        let root = RepoTree::from_parts(self.clone(), dirtree, dirmeta);
        let root_meta = self.load_dirmeta(&dirmeta).await?;

        let (root_path, member_prefix) = prefix_parts(opts.prefix.as_deref());
        let mut items = vec![Item::Dir {
            path: root_path,
            meta: root_meta,
        }];
        let mut seen: HashMap<Checksum, String> = HashMap::new();
        collect(self, root, member_prefix, &mut items, &mut seen).await?;

        let mut writer = TarWriter::<'_, '_, _, BodyReader>::new(out);
        for item in items {
            match item {
                Item::Dir { path, meta } => {
                    let entry = TarDirectory::new(path)
                        .with_uid(meta.uid)
                        .with_gid(meta.gid)
                        .with_mode(meta.mode & PERM_MASK)
                        .with_mtime(mtime)
                        .with_attrs(export_attrs(&meta.xattrs, &opts)?);
                    writer.write(entry.into()).await.map_err(Error::Io)?;
                }
                Item::Regular { path, file, size } => {
                    let attrs = export_attrs(&file.xattrs, &opts)?;
                    let body: BodyReader = Box::pin(file.reader().await?);
                    let entry = TarRegularFile::new(path, size, body)
                        .with_uid(file.uid)
                        .with_gid(file.gid)
                        .with_mode(file.mode & PERM_MASK)
                        .with_mtime(mtime)
                        .with_attrs(attrs);
                    writer.write(entry.into()).await.map_err(Error::Io)?;
                }
                Item::Symlink { path, file, target } => {
                    let entry = TarSymlink::new(path, target)
                        .with_uid(file.uid)
                        .with_gid(file.gid)
                        .with_mode(file.mode & PERM_MASK)
                        .with_mtime(mtime)
                        .with_attrs(export_attrs(&file.xattrs, &opts)?);
                    writer.write(entry.into()).await.map_err(Error::Io)?;
                }
                Item::Hardlink { path, target } => {
                    writer
                        .write(TarLink::new(path, target).into())
                        .await
                        .map_err(Error::Io)?;
                }
            }
        }
        writer.finish().await.map_err(Error::Io)?;
        Ok(())
    }

    /// Reads a file system tar stream from `input` into a new [`MutableTree`].
    ///
    /// The import stages its objects in `txn`. The call is
    /// [`import_tar_into`](Repo::import_tar_into) with an empty destination
    /// tree and no modifier.
    ///
    /// # Members
    ///
    /// - A regular file member streams into a content object.
    /// - A symlink member becomes a content object.
    /// - A directory member becomes a dirmeta object.
    /// - A hardlink member gets the content object of its target. The import
    ///   resolves hardlinks after it reads the last member.
    /// - A device node or FIFO member fails the import, because an ostree tree
    ///   stores only regular files, symlinks, and directories.
    ///
    /// # Errors
    ///
    /// The errors of [`import_tar_into`](Repo::import_tar_into).
    pub async fn import_tar(
        &self,
        txn: &Transaction,
        opts: TarImportOptions,
        input: impl AsyncRead,
    ) -> Result<MutableTree> {
        let mut mtree = MutableTree::new();
        self.import_tar_into(txn, opts, input, &mut mtree, None)
            .await?;
        Ok(mtree)
    }

    /// Reads a file system tar stream from `input` into `mtree`.
    ///
    /// The import stages one content object for each regular file and
    /// symlink, and one dirmeta object for each directory, in `txn`. `mtree`
    /// can hold the entries of an earlier source. [`Repo::import_tar`] lists
    /// what each member kind becomes. After the import, the caller writes the
    /// tree with [`write_mtree`](Transaction::write_mtree) and commits it.
    ///
    /// # Parent directories
    ///
    /// Each member goes under the directory that its pathname names. This
    /// directory must already be in the tree, so an archive must name a parent
    /// directory before its members. If the parent is not in the tree and
    /// [`autocreate_parents`](TarImportOptions::autocreate_parents) is off,
    /// the import fails with [`Error::TarMissingParent`]. If
    /// `autocreate_parents` is on, the import creates the parent.
    ///
    /// A root member of the archive sets the root metadata of `mtree`. If
    /// `autocreate_parents` is off, the archive names no root member, and
    /// `mtree` has no root metadata, `mtree` has no root metadata after the
    /// import.
    ///
    /// If `autocreate_parents` is on, the import sets the root metadata after
    /// the last member, with mode `0755` and empty extended attributes:
    ///
    /// - If the import created a parent, the root gets the owner of the last
    ///   parent that it created. This replaces each earlier root metadata,
    ///   also the metadata that a root member set.
    /// - If the import created no parent and `mtree` has no root metadata, the
    ///   root gets the owner `0:0`.
    ///   [`owner_uid`](TarImportOptions::owner_uid) and
    ///   [`owner_gid`](TarImportOptions::owner_gid) replace these values if
    ///   they are set.
    ///
    /// # Pathnames
    ///
    /// The import normalizes the pathname of each member. It removes one
    /// leading `./` and one leading `/`. The name of a directory keeps its
    /// trailing `/`. The root member of the archive gets the empty string.
    ///
    /// The [`rename`](TarImportOptions::rename) hook receives this normalized
    /// name. The member goes under the name that the hook returns. The link
    /// target of a hardlink member goes through the same normalization and the
    /// same hook.
    ///
    /// # Modifier
    ///
    /// `modifier` shapes each member as it shapes a walk of a file system,
    /// with one difference.
    /// [`CANONICAL_PERMISSIONS`](crate::CommitModifierFlags::CANONICAL_PERMISSIONS)
    /// records the ownership and the mode that it states, and keeps the
    /// extended attributes of the archive. The option that drops them is
    /// [`skip_xattrs`](TarImportOptions::skip_xattrs). A parent directory that
    /// the import creates does not go through the modifier.
    ///
    /// # Errors
    ///
    /// - [`Error::TarPathname`] if the pathname of a member is not valid
    ///   UTF-8.
    /// - [`Error::Tar`] if the archive holds a device node or a FIFO member.
    /// - [`Error::Tar`] if a pathname has a `..` component.
    /// - [`Error::Tar`] if a regular file, symlink, or hardlink member has an
    ///   empty pathname.
    /// - [`Error::Tar`] if the target of a hardlink is not a regular file or
    ///   symlink member that the import placed, or an earlier hardlink member.
    ///   The import does not place a member that the filter of the modifier
    ///   skips.
    /// - [`Error::TarMissingParent`] if a parent directory of a member is not
    ///   in the tree and
    ///   [`autocreate_parents`](TarImportOptions::autocreate_parents) is off.
    /// - [`Error::ReplaceFileWithDir`] if a member needs a directory at a path
    ///   where the tree holds a file.
    /// - [`Error::ReplaceDirWithFile`] if a regular file, symlink, or hardlink
    ///   member names a path where the tree holds a directory.
    /// - [`Error::Core`] if two `SCHILY.xattr.*` records of a member have the
    ///   same name, or if a record name is empty or holds a NUL byte.
    /// - An error from a callback of the modifier. For example,
    ///   [`Error::InvalidFormat`] if the modifier sets
    ///   [`ERROR_ON_UNLABELED`](crate::CommitModifierFlags::ERROR_ON_UNLABELED)
    ///   and its label callback gives no label for a member.
    /// - An error from the staging write of an object, as
    ///   [`Transaction::write_content`] lists. For example,
    ///   [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`.
    /// - An error from the load of a committed subdirectory of `mtree`. For
    ///   example, [`Error::ObjectNotFound`] if its dirtree is not in the
    ///   object store.
    /// - [`Error::Io`] if a read from `input` fails, or if a member header is
    ///   malformed.
    /// - The error that the [`rename`](TarImportOptions::rename) hook returns.
    pub async fn import_tar_into(
        &self,
        txn: &Transaction,
        mut opts: TarImportOptions,
        input: impl AsyncRead,
        mtree: &mut MutableTree,
        mut modifier: Option<&mut CommitModifier>,
    ) -> Result<()> {
        let mut reader = TarReader::new(input);
        let flags = modifier
            .as_deref()
            .map_or(CommitModifierFlags::empty(), |m| m.flags);
        let owner = Owner::of(modifier.as_deref());

        // The files and symlinks by path, to resolve hardlink targets. Also the
        // hardlink members, whose targets the import resolves after the walk.
        let mut file_index: HashMap<Vec<String>, Checksum> = HashMap::new();
        let mut hardlinks: Vec<(Vec<String>, Vec<String>)> = Vec::new();
        // The ownership that the last synthesized parent directory recorded.
        // The metadata of the root takes it too.
        let mut synthesized: Option<(u32, u32)> = None;

        while let Some(entry) = reader.next().await {
            let entry = entry.map_err(read_error)?;
            match entry {
                TarEntry::Directory(dir) => {
                    let comps = member_path(dir.path(), true, &mut opts)?;
                    let base = FileMeta {
                        uid: opts.uid(dir.uid()),
                        gid: opts.gid(dir.gid()),
                        mode: S_IFDIR | (dir.mode() & PERM_MASK),
                        xattrs: attrs_to_xattrs(dir.attrs(), &opts)?,
                    };
                    let Some(meta) = shape(
                        txn,
                        modifier.as_deref_mut(),
                        flags,
                        owner,
                        &comps,
                        base,
                        false,
                    )?
                    else {
                        continue;
                    };
                    let checksum = txn.write_dirmeta(&to_dirmeta(&meta)).await?;
                    let raw = (opts.uid(dir.uid()), opts.gid(dir.gid()));
                    place_dir(
                        txn,
                        mtree,
                        &comps,
                        checksum,
                        opts.autocreate_parents,
                        raw,
                        &mut synthesized,
                    )
                    .await?;
                }
                TarEntry::File(file) => {
                    let comps = member_path(file.path(), false, &mut opts)?;
                    require_leaf(&comps, "regular file")?;
                    let mut base = FileMeta::regular(
                        opts.uid(file.uid()),
                        opts.gid(file.gid()),
                        file.mode() & PERM_MASK,
                    );
                    base.xattrs = attrs_to_xattrs(file.attrs(), &opts)?;
                    let raw = (opts.uid(file.uid()), opts.gid(file.gid()));
                    let Some(meta) = shape(
                        txn,
                        modifier.as_deref_mut(),
                        flags,
                        owner,
                        &comps,
                        base,
                        false,
                    )?
                    else {
                        continue;
                    };
                    let checksum = txn.write_content(None, &meta, file).await?;
                    place(
                        txn,
                        mtree,
                        &comps,
                        checksum,
                        opts.autocreate_parents,
                        raw,
                        &mut synthesized,
                    )
                    .await?;
                    file_index.insert(comps, checksum);
                }
                TarEntry::Symlink(link) => {
                    let comps = member_path(link.path(), false, &mut opts)?;
                    require_leaf(&comps, "symlink")?;
                    // The permission bits of the header, under the file type
                    // of the member kind. With this file type, the mode
                    // callback and the canonical reduction see a symlink. It
                    // also lets the permission bits of a `--statoverride` entry
                    // reach the header of the content object.
                    let base = FileMeta {
                        uid: opts.uid(link.uid()),
                        gid: opts.gid(link.gid()),
                        mode: S_IFLNK | (link.mode() & PERM_MASK),
                        xattrs: attrs_to_xattrs(link.attrs(), &opts)?,
                    };
                    let raw = (opts.uid(link.uid()), opts.gid(link.gid()));
                    let target = link.link().to_owned();
                    let Some(meta) = shape(
                        txn,
                        modifier.as_deref_mut(),
                        flags,
                        owner,
                        &comps,
                        base,
                        true,
                    )?
                    else {
                        continue;
                    };
                    let checksum = txn.write_symlink(&target, &meta, None).await?;
                    place(
                        txn,
                        mtree,
                        &comps,
                        checksum,
                        opts.autocreate_parents,
                        raw,
                        &mut synthesized,
                    )
                    .await?;
                    file_index.insert(comps, checksum);
                }
                TarEntry::Link(link) => {
                    let comps = member_path(link.path(), false, &mut opts)?;
                    require_leaf(&comps, "hardlink")?;
                    // The target names another member, so it goes through the
                    // same rename hook as the member names.
                    let target = member_path(link.link(), false, &mut opts)?;
                    let raw = (opts.uid(0), opts.gid(0));
                    let parents = &comps[..comps.len() - 1];
                    descend(
                        txn,
                        mtree,
                        parents,
                        opts.autocreate_parents,
                        raw,
                        &mut synthesized,
                    )
                    .await?;
                    hardlinks.push((comps, target));
                }
                TarEntry::Device(dev) => {
                    return Err(Error::Tar(format!(
                        "cannot import device node {:?}: an ostree tree stores only \
                         regular files, symlinks, and directories",
                        dev.path()
                    )));
                }
                TarEntry::Fifo(fifo) => {
                    return Err(Error::Tar(format!(
                        "cannot import FIFO {:?}: an ostree tree stores only \
                         regular files, symlinks, and directories",
                        fifo.path()
                    )));
                }
            }
        }

        // Resolve hardlinks against the paths that the walk placed. GNU tar
        // points a hardlink at the first, real occurrence of the content, so
        // the target is always a member earlier in the walk.
        for (link, target) in hardlinks {
            let checksum = file_index.get(&target).copied().ok_or_else(|| {
                Error::Tar(format!(
                    "hardlink {} has no target {} in the archive",
                    join(&link),
                    join(&target)
                ))
            })?;
            let (leaf, parents) = link
                .split_last()
                .expect("a hardlink path has at least one component");
            let node = mtree
                .dir_at_mut(parents)
                .expect("the hardlink's parents were created during the walk");
            node.replace_file(leaf, checksum)?;
            file_index.insert(link, checksum);
        }

        // The metadata of the root: what the last synthesized parent recorded.
        // If the archive named no root and nothing else supplied one, the
        // root gets `0755 0:0`.
        if opts.autocreate_parents
            && let Some((uid, gid)) = synthesized.or_else(|| {
                mtree
                    .metadata_checksum()
                    .is_none()
                    .then_some((opts.uid(0), opts.gid(0)))
            })
        {
            let meta = DirMeta {
                uid,
                gid,
                mode: S_IFDIR | 0o755,
                xattrs: Xattrs::empty(),
            };
            let checksum = txn.write_dirmeta(&meta).await?;
            mtree.set_metadata_checksum(checksum);
        }

        Ok(())
    }
}

/// Shapes the metadata of one member: the deterministic adjustments, then the
/// filter of the modifier, then its callbacks. Returns `None` if the filter
/// skips the member.
///
/// Canonical permissions keep the extended attributes of the archive. Here
/// the tar import differs from the walk of a file system.
/// [`TarImportOptions::skip_xattrs`] drops them.
fn shape(
    txn: &Transaction,
    mut modifier: Option<&mut CommitModifier>,
    flags: CommitModifierFlags,
    owner: Owner,
    comps: &[String],
    base: FileMeta,
    is_symlink: bool,
) -> Result<Option<FileMeta>> {
    let path = callback_path(comps);
    let xattrs = base.xattrs.clone();
    let mut adjusted = adjust_meta(flags, owner, base, is_symlink);
    adjusted.xattrs = xattrs;

    if let Some(m) = modifier.as_deref_mut()
        && let Some(filter) = &mut m.filter
        && filter(std::path::Path::new(&path), &adjusted) == FilterResult::Skip
    {
        txn.note_filtered();
        return Ok(None);
    }
    Ok(Some(finalize_meta(
        modifier,
        std::path::Path::new(&path),
        adjusted,
    )?))
}

/// Returns the modifier callback path of a member: `/` for the root member of
/// the archive, else a path with a leading `/` and no trailing `/`.
fn callback_path(comps: &[String]) -> String {
    if comps.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", comps.join("/"))
    }
}

/// Returns the directory node that `ancestors` names. Each component must
/// already be in the tree, or
/// [`autocreate_parents`](TarImportOptions::autocreate_parents) must permit
/// its creation.
async fn descend<'a>(
    txn: &Transaction,
    root: &'a mut MutableTree,
    ancestors: &[String],
    autocreate_parents: bool,
    raw_owner: (u32, u32),
    synthesized: &mut Option<(u32, u32)>,
) -> Result<&'a mut MutableTree> {
    let mut node = root;
    for name in ancestors {
        match node.child_kind(name) {
            ChildKind::File(_) => return Err(Error::ReplaceFileWithDir(name.clone())),
            ChildKind::Absent => {
                if !autocreate_parents {
                    return Err(Error::TarMissingParent(name.clone()));
                }
                let meta = DirMeta {
                    uid: raw_owner.0,
                    gid: raw_owner.1,
                    mode: S_IFDIR | 0o755,
                    xattrs: Xattrs::empty(),
                };
                let checksum = txn.write_dirmeta(&meta).await?;
                *synthesized = Some(raw_owner);
                let child = node.ensure_dir(name).await?;
                child.set_metadata_checksum(checksum);
                node = child;
            }
            _ => node = node.ensure_dir(name).await?,
        }
    }
    Ok(node)
}

/// Records the metadata of a directory member. It creates the node that the
/// member names, under the parents that [`descend`] resolves. The root member
/// of the archive sets the metadata of the tree root.
async fn place_dir(
    txn: &Transaction,
    root: &mut MutableTree,
    comps: &[String],
    dirmeta: Checksum,
    autocreate_parents: bool,
    raw_owner: (u32, u32),
    synthesized: &mut Option<(u32, u32)>,
) -> Result<()> {
    let Some((leaf, parents)) = comps.split_last() else {
        root.set_metadata_checksum(dirmeta);
        return Ok(());
    };
    let node = descend(
        txn,
        root,
        parents,
        autocreate_parents,
        raw_owner,
        synthesized,
    )
    .await?;
    node.ensure_dir(leaf).await?.set_metadata_checksum(dirmeta);
    Ok(())
}

/// Records a content object at the path of the member. It resolves the
/// parents as [`descend`] does.
async fn place(
    txn: &Transaction,
    root: &mut MutableTree,
    comps: &[String],
    checksum: Checksum,
    autocreate_parents: bool,
    raw_owner: (u32, u32),
    synthesized: &mut Option<(u32, u32)>,
) -> Result<()> {
    let (leaf, parents) = comps
        .split_last()
        .expect("a content member has at least one component");
    let node = descend(
        txn,
        root,
        parents,
        autocreate_parents,
        raw_owner,
        synthesized,
    )
    .await?;
    node.replace_file(leaf, checksum)?;
    Ok(())
}

/// Walks `tree` depth-first and appends ordered [`Item`]s. In a directory, the
/// files and subdirectories share one name order. A subdirectory entry comes
/// just before its contents. `seen` maps a content object to the first path
/// that carried it, so a repeat becomes a hardlink.
fn collect<'a>(
    repo: &'a Repo,
    tree: RepoTree,
    prefix: String,
    items: &'a mut Vec<Item>,
    seen: &'a mut HashMap<Checksum, String>,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let mut entries = tree.read_dir().await?;
        entries.sort_by(|a, b| entry_name(a).as_bytes().cmp(entry_name(b).as_bytes()));
        for entry in entries {
            match entry {
                TreeEntry::File { name, checksum } => {
                    let path = format!("{prefix}{name}");
                    if let Some(target) = seen.get(&checksum) {
                        items.push(Item::Hardlink {
                            path,
                            target: target.clone(),
                        });
                        continue;
                    }
                    let file = repo.load_file(&checksum).await?;
                    match &file.kind {
                        FileKind::Regular { size } => {
                            let size = *size;
                            seen.insert(checksum, path.clone());
                            items.push(Item::Regular { path, file, size });
                        }
                        FileKind::Symlink { target } => {
                            let target = target.clone();
                            items.push(Item::Symlink { path, file, target });
                        }
                    }
                }
                TreeEntry::Dir {
                    name,
                    tree: subtree,
                } => {
                    let path = format!("{prefix}{name}/");
                    let meta = repo.load_dirmeta(subtree.dirmeta_checksum()).await?;
                    items.push(Item::Dir {
                        path: path.clone(),
                        meta,
                    });
                    collect(repo, subtree, path, items, seen).await?;
                }
            }
        }
        Ok(())
    })
}

/// Converts a read error of a tar member header to an [`Error`]. The reader
/// reports a pathname that is not valid UTF-8 as an `InvalidData` I/O error.
/// ostrya stores pathnames as text, so it reports this case as the `ostree`
/// command does.
fn read_error(err: std::io::Error) -> Error {
    // The match uses the message text of the dependency. smol-tar 0.1.7, the
    // registry version that the workspace resolves, spells it `utf8 in file
    // path`, and `Cargo.lock` records that version. If that text changes
    // upstream, the failure stays an `Error::Io`.
    // `import_rejects_a_pathname_that_is_not_utf8` in
    // `crates/ostrya/tests/tar.rs` asserts `Error::TarPathname` and fails
    // when the text moves. `commit_tar_pathname_not_utf8_is_refused` in the
    // CLI tests holds the same case against the `ostree` command, if it is
    // installed.
    if err.kind() == std::io::ErrorKind::InvalidData
        && err.to_string().contains("utf8 in file path")
    {
        return Error::TarPathname;
    }
    Error::Io(err)
}

/// Returns the name of a directory entry of either kind.
fn entry_name(entry: &TreeEntry) -> &str {
    match entry {
        TreeEntry::File { name, .. } => name,
        TreeEntry::Dir { name, .. } => name,
    }
}

/// Returns the path components that a member is imported under.
///
/// The function normalizes the name. It drops one leading `./` and one
/// leading `/`. A directory keeps its trailing `/`, and the root member of the
/// archive is the empty string. The rename hook gets this name, and
/// [`normalize`] splits the result.
fn member_path(raw: &str, is_dir: bool, opts: &mut TarImportOptions) -> Result<Vec<String>> {
    let stripped = raw.strip_prefix("./").unwrap_or(raw);
    let stripped = stripped.strip_prefix('/').unwrap_or(stripped);
    let mut name = if stripped == "." {
        String::new()
    } else {
        stripped.to_owned()
    };
    if is_dir && !name.is_empty() && !name.ends_with('/') {
        name.push('/');
    }
    if let Some(rename) = &mut opts.rename {
        name = rename(&name)?;
    }
    normalize(&name, opts)
}

/// Splits a tar member name into path components. It drops empty components,
/// `.` components, and the root, and it refuses `..`. If `etc_to_usr_etc` is
/// set, a leading `etc` component becomes `usr/etc`.
fn normalize(raw: &str, opts: &TarImportOptions) -> Result<Vec<String>> {
    let mut comps = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                return Err(Error::Tar(format!(
                    "tar member {raw:?} has a '..' path component"
                )));
            }
            other => comps.push(other.to_owned()),
        }
    }
    if opts.etc_to_usr_etc && comps.first().is_some_and(|c| c == "etc") {
        let mut remapped = vec!["usr".to_owned(), "etc".to_owned()];
        remapped.extend(comps.into_iter().skip(1));
        comps = remapped;
    }
    Ok(comps)
}

/// Refuses an entry whose normalized path is empty, because that path names
/// the tree root as a file.
fn require_leaf(comps: &[String], kind: &str) -> Result<()> {
    if comps.is_empty() {
        return Err(Error::Tar(format!("{kind} entry has an empty path")));
    }
    Ok(())
}

/// Joins path components with `/` for an error message.
fn join(comps: &[String]) -> String {
    comps.join("/")
}

/// Returns the dirtree and dirmeta of the root member of the archive: the
/// commit root, or the directory that a subpath names in it.
///
/// A subpath with no name component names the whole tree, as
/// [`CheckoutOptions::subpath`](crate::CheckoutOptions::subpath) does. A
/// subpath that names a file or a symlink has no tree to walk. A subpath that
/// names nothing has no node. The function refuses both.
async fn export_root(
    repo: &Repo,
    commit: &Commit,
    subpath: Option<&Path>,
) -> Result<(Checksum, Checksum)> {
    let root = (commit.root_dirtree, commit.root_dirmeta);
    let Some(sub) = subpath else {
        return Ok(root);
    };
    if is_root_path(sub) {
        return Ok(root);
    }
    let tree = RepoTree::from_parts(repo.clone(), commit.root_dirtree, commit.root_dirmeta);
    match tree.lookup(sub).await? {
        Some(TreeEntry::Dir { tree, .. }) => {
            Ok((*tree.dirtree_checksum(), *tree.dirmeta_checksum()))
        }
        Some(TreeEntry::File { .. }) => Err(Error::Tar(format!(
            "subpath is not a directory: {}",
            sub.display()
        ))),
        None => Err(Error::Tar(format!("subpath not found: {}", sub.display()))),
    }
}

/// Returns the member name of the archive root and the prefix of each other
/// member name, for the [`prefix`](TarExportOptions::prefix) option.
fn prefix_parts(prefix: Option<&str>) -> (String, String) {
    match prefix.filter(|p| !p.is_empty()) {
        None => ("./".to_owned(), String::new()),
        Some(p) if p.ends_with('/') => (p.to_owned(), p.to_owned()),
        Some(p) => (format!("{p}/"), p.to_owned()),
    }
}

/// Returns the PAX attributes of an exported entry: its extended attributes,
/// or none if [`skip_xattrs`](TarExportOptions::skip_xattrs) is set.
fn export_attrs(xattrs: &Xattrs, opts: &TarExportOptions) -> Result<AttrList> {
    if opts.skip_xattrs {
        return Ok(AttrList::new());
    }
    xattrs_to_attrs(xattrs)
}

/// Converts an ostrya xattr set to tar PAX attributes. It drops the stored
/// terminating NUL from each name and keeps each value byte for byte.
/// smol-tar prepends `SCHILY.xattr.` and requires a graphic-ASCII name.
fn xattrs_to_attrs(xattrs: &Xattrs) -> Result<AttrList> {
    let mut attrs = AttrList::new();
    for (name, value) in xattrs.iter() {
        let name = name.strip_suffix(&[0]).unwrap_or(name);
        let name = std::str::from_utf8(name)
            .map_err(|_| Error::Tar("xattr name is not valid UTF-8".to_owned()))?;
        attrs.push(name.to_owned(), value.to_vec());
    }
    Ok(attrs)
}

/// Converts tar PAX attributes to a canonical ostrya xattr set. It appends the
/// terminating NUL that each stored name carries. [`Xattrs::new`] sorts and
/// checks the set.
fn attrs_to_xattrs(attrs: &AttrList, opts: &TarImportOptions) -> Result<Xattrs> {
    if opts.skip_xattrs || attrs.is_empty() {
        return Ok(Xattrs::empty());
    }
    let mut pairs = Vec::with_capacity(attrs.len());
    for (name, value) in attrs.iter() {
        let mut stored = name.as_bytes().to_vec();
        stored.push(0);
        pairs.push((stored, value.to_vec()));
    }
    Ok(Xattrs::new(pairs)?)
}

/// A compile-time check that the tar option types can move across tasks and
/// threads. [`TarImportOptions`] holds a callback field that is called through
/// `&mut`, so the type is `Send` only, as [`CommitModifier`] is.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>() {}
    assert_send_sync::<TarExportOptions>();
    assert_send::<TarImportOptions>();
};
