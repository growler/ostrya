//! Tar import and export.
//!
//! [`Repo::export_tar`] writes a commit's tree as a tar stream, and
//! [`Repo::import_tar`] reads a filesystem tar into a [`MutableTree`] over a
//! transaction. The stream is a plain filesystem tar, not an object-embedding
//! format: member names are relative paths, ownership is numeric, every
//! timestamp is the commit timestamp with a zero nanosecond part, extended
//! attributes travel as `SCHILY.xattr.*` PAX records, and files that share a
//! content object are coalesced into tar hardlinks.
//!
//! Export walks the commit tree depth-first with each directory's entries in
//! name order. The root directory is the member `./`; every other member is a
//! bare relative path, and directories carry a trailing slash. The first file
//! seen for a given content object is written in full; a later file with the
//! same object identity -- identical ownership, mode, xattrs, and content, since
//! all of those feed the object checksum -- is written as a hardlink to it.
//! Symlinks are written as symlink members and never coalesced.
//!
//! Import builds a [`MutableTree`]: regular files stream into content objects,
//! symlinks and directory metadata become their objects, and hardlink members
//! are resolved after the walk against the paths already ingested. Each member
//! is placed under a directory the tree already holds, so an archive naming a
//! member before its parent is refused unless
//! [`TarImportOptions::autocreate_parents`] permits synthesizing the parent.
//! With [`TarImportOptions::etc_to_usr_etc`], a top-level `etc` component is
//! rewritten to `usr/etc`. [`TarImportOptions::owner_uid`] and
//! [`TarImportOptions::owner_gid`] replace the ownership every member records,
//! a synthesized parent directory included, and
//! [`TarImportOptions::skip_xattrs`] records no extended attributes at all.
//! [`TarImportOptions::rename`] rewrites each member's pathname before the
//! member is placed. Device and FIFO members are rejected, since an ostree tree
//! stores only regular files, symlinks, and directories.
//! [`Repo::import_tar_into`] reads into a tree an earlier source already
//! filled, and shapes each member with a
//! [`CommitModifier`](crate::CommitModifier). The tree is serialized and
//! committed by the caller through
//! [`Transaction::write_mtree`](crate::Transaction::write_mtree) and
//! [`Transaction::write_commit`](crate::Transaction::write_commit).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, UNIX_EPOCH};

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::StreamExt;
use ostrya_core::{Checksum, DirMeta, Xattrs};
use smol_tar::{
    AttrList, TarDirectory, TarEntry, TarLink, TarReader, TarRegularFile, TarSymlink, TarWriter,
};

use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject};
use crate::ingest::{adjust_meta, finalize_meta, to_dirmeta};
use crate::modifier::{CommitModifier, CommitModifierFlags, FilterResult, Owner};
use crate::mtree::{ChildKind, MutableTree};
use crate::repo::Repo;
use crate::transaction::{FileMeta, Transaction};
use crate::tree::{RepoTree, TreeEntry};

/// The `S_IFDIR` file-type bits a directory's `st_mode` carries.
const S_IFDIR: u32 = 0o040000;
/// The `S_IFLNK` file-type bits a symlink's `st_mode` carries.
const S_IFLNK: u32 = 0o120000;
/// The permission bits kept in a tar header's octal mode field.
const PERM_MASK: u32 = 0o7777;

/// A boxed, runtime-neutral payload reader. Uniform across entry kinds so one
/// [`TarWriter`] instance serves the whole stream; `Pin<Box<..>>` is `Unpin`,
/// which the writer requires of the body reader.
type BodyReader = Pin<Box<dyn AsyncRead + Send>>;

/// Options for [`Repo::export_tar`].
///
/// Export follows fixed conventions (see the module docs), so there is nothing
/// to configure yet; the type is a placeholder for options the CLI adds later.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct TarExportOptions {}

impl TarExportOptions {
    /// Default export options.
    pub fn new() -> TarExportOptions {
        TarExportOptions::default()
    }
}

/// A rename hook over member pathnames. It receives the normalized member name
/// (see [`Repo::import_tar_into`]) and returns the name the member is imported
/// under.
pub type TarRename = Box<dyn FnMut(&str) -> Result<String> + Send>;

/// Options for [`Repo::import_tar`].
#[derive(Default)]
#[non_exhaustive]
pub struct TarImportOptions {
    /// Rewrite a top-level `etc` component to `usr/etc`, matching the ostree
    /// convention that composes configuration into `/usr`. Off by default.
    pub etc_to_usr_etc: bool,
    /// The owner uid every imported entry records, in place of the uid its tar
    /// header carries. Applies to the default metadata of a directory the
    /// archive never names as well.
    pub owner_uid: Option<u32>,
    /// The owner gid every imported entry records, on the same terms as
    /// [`owner_uid`](TarImportOptions::owner_uid).
    pub owner_gid: Option<u32>,
    /// Record no extended attributes, whatever `SCHILY.xattr.*` records the
    /// archive carries.
    pub skip_xattrs: bool,
    /// Create a parent directory the archive never names, in place of
    /// refusing the member that needs it. A synthesized directory records
    /// mode `0755`, empty extended attributes, and the ownership of the
    /// member whose import created it; a synthesized root with no such
    /// member records `0:0`.
    pub autocreate_parents: bool,
    /// Rewrite each member's pathname before it is imported. See
    /// [`TarRename`].
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
    /// Default import options.
    pub fn new() -> TarImportOptions {
        TarImportOptions::default()
    }

    /// Set whether a top-level `etc` component is imported as `usr/etc`.
    pub fn with_etc_migration(mut self, on: bool) -> TarImportOptions {
        self.etc_to_usr_etc = on;
        self
    }

    /// The uid an entry records: the declared one, else the one given.
    fn uid(&self, from_header: u32) -> u32 {
        self.owner_uid.unwrap_or(from_header)
    }

    /// The gid an entry records: the declared one, else the one given.
    fn gid(&self, from_header: u32) -> u32 {
        self.owner_gid.unwrap_or(from_header)
    }
}

/// One ordered entry to emit during export. Metadata is captured during the
/// walk; a regular file's payload is opened only when the entry is written, so
/// the export holds at most one content fd at a time.
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

impl Repo {
    /// Write a commit's tree to `out` as a tar stream. See the module docs for
    /// the member naming, hardlink coalescing, and metadata conventions.
    pub async fn export_tar(
        &self,
        commit: &Checksum,
        _opts: TarExportOptions,
        out: impl AsyncWrite,
    ) -> Result<()> {
        let (commit_obj, _) = self.load_commit(commit).await?;
        let mtime = UNIX_EPOCH + Duration::from_secs(commit_obj.timestamp);
        let root = RepoTree::from_parts(
            self.clone(),
            commit_obj.root_dirtree,
            commit_obj.root_dirmeta,
        );
        let root_meta = self.load_dirmeta(&commit_obj.root_dirmeta).await?;

        let mut items = vec![Item::Dir {
            path: "./".to_owned(),
            meta: root_meta,
        }];
        let mut seen: HashMap<Checksum, String> = HashMap::new();
        collect(self, root, String::new(), &mut items, &mut seen).await?;

        let mut writer = TarWriter::<'_, '_, _, BodyReader>::new(out);
        for item in items {
            match item {
                Item::Dir { path, meta } => {
                    let entry = TarDirectory::new(path)
                        .with_uid(meta.uid)
                        .with_gid(meta.gid)
                        .with_mode(meta.mode & PERM_MASK)
                        .with_mtime(mtime)
                        .with_attrs(xattrs_to_attrs(&meta.xattrs)?);
                    writer.write(entry.into()).await.map_err(Error::Io)?;
                }
                Item::Regular { path, file, size } => {
                    let attrs = xattrs_to_attrs(&file.xattrs)?;
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
                        .with_attrs(xattrs_to_attrs(&file.xattrs)?);
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

    /// Read a filesystem tar from `input` into a fresh [`MutableTree`] over
    /// `txn`. A convenience over [`import_tar_into`](Repo::import_tar_into)
    /// with no destination tree and no modifier.
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

    /// Read a filesystem tar from `input` into `mtree` over `txn`, staging one
    /// content object per regular file and symlink and one metadata object per
    /// directory. The tree is ready for
    /// [`write_mtree`](Transaction::write_mtree); the caller commits it.
    ///
    /// Each member is placed under the directory its pathname names, which
    /// must already be in the tree: an archive that names a member before its
    /// parent directory is refused with [`Error::TarMissingParent`] unless
    /// [`autocreate_parents`](TarImportOptions::autocreate_parents) is set. The
    /// tree's own root is one such parent, so an archive that names no root
    /// member leaves `mtree` without root metadata where the destination
    /// supplied none.
    ///
    /// The pathname a member is placed under, and the name
    /// [`rename`](TarImportOptions::rename) receives, drops one leading `./`
    /// and one leading `/`, keeps a directory's trailing `/`, and is the empty
    /// string for the archive's own root member.
    ///
    /// `modifier` shapes every member the way it shapes a filesystem walk, with
    /// one difference:
    /// [`CANONICAL_PERMISSIONS`](crate::CommitModifierFlags::CANONICAL_PERMISSIONS)
    /// records the ownership and the mode it states and keeps the extended
    /// attributes the archive carries, which
    /// [`skip_xattrs`](TarImportOptions::skip_xattrs) drops instead. A
    /// synthesized parent directory takes no part in the modifier.
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

        // Files and symlinks by path, for resolving hardlink targets, and the
        // hardlink members themselves, whose targets are resolved once the
        // walk is over.
        let mut file_index: HashMap<Vec<String>, Checksum> = HashMap::new();
        let mut hardlinks: Vec<(Vec<String>, Vec<String>)> = Vec::new();
        // The ownership the last synthesized parent directory recorded. The
        // root's own metadata takes it too.
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
                    place_dir(txn, mtree, &comps, checksum, &opts, raw, &mut synthesized).await?;
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
                    place(txn, mtree, &comps, checksum, &opts, raw, &mut synthesized).await?;
                    file_index.insert(comps, checksum);
                }
                TarEntry::Symlink(link) => {
                    let comps = member_path(link.path(), false, &mut opts)?;
                    require_leaf(&comps, "symlink")?;
                    // The header's own permission bits, under the file type the
                    // member kind states. The file type makes the mode callback
                    // and the canonical reduction see a symlink, and lets the
                    // permission bits a `--statoverride` entry states reach the
                    // content object's header.
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
                    place(txn, mtree, &comps, checksum, &opts, raw, &mut synthesized).await?;
                    file_index.insert(comps, checksum);
                }
                TarEntry::Link(link) => {
                    let comps = member_path(link.path(), false, &mut opts)?;
                    require_leaf(&comps, "hardlink")?;
                    // The target names another member, so it is read through
                    // the same rename hook the member names went through.
                    let target = member_path(link.link(), false, &mut opts)?;
                    let raw = (opts.uid(0), opts.gid(0));
                    let parents = &comps[..comps.len() - 1];
                    descend(txn, mtree, parents, &opts, raw, &mut synthesized).await?;
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

        // Resolve hardlinks against the already-ingested paths. GNU tar points a
        // hardlink at the first, real occurrence of the content, so the target
        // is always a member seen earlier in the walk.
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

        // The root's own metadata: what the last synthesized parent recorded,
        // else `0755 0:0` where the archive named no root and nothing else
        // supplied one.
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

/// Shape one member's metadata: the deterministic adjustments, then the
/// modifier's filter, then its callbacks. `None` where the filter skipped the
/// member.
///
/// Canonical permissions keep the extended attributes the archive carries,
/// which is where the tar importer parts from the filesystem walk;
/// [`TarImportOptions::skip_xattrs`] is what drops them.
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

/// The modifier callback path of a member: `/` for the archive's root member,
/// and a leading-slash path with no trailing slash for every other.
fn callback_path(comps: &[String]) -> String {
    if comps.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", comps.join("/"))
    }
}

/// Navigate to the directory node named by `ancestors`. Every component must
/// already be in the tree, or
/// [`autocreate_parents`](TarImportOptions::autocreate_parents) must permit
/// synthesizing it.
async fn descend<'a>(
    txn: &Transaction,
    root: &'a mut MutableTree,
    ancestors: &[String],
    opts: &TarImportOptions,
    raw_owner: (u32, u32),
    synthesized: &mut Option<(u32, u32)>,
) -> Result<&'a mut MutableTree> {
    let mut node = root;
    for name in ancestors {
        match node.child_kind(name) {
            ChildKind::File(_) => return Err(Error::ReplaceFileWithDir(name.clone())),
            ChildKind::Absent => {
                if !opts.autocreate_parents {
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

/// Record a directory member's own metadata, creating the node it names under
/// parents [`descend`] resolves. The archive's root member sets the tree root's
/// metadata.
async fn place_dir(
    txn: &Transaction,
    root: &mut MutableTree,
    comps: &[String],
    dirmeta: Checksum,
    opts: &TarImportOptions,
    raw_owner: (u32, u32),
    synthesized: &mut Option<(u32, u32)>,
) -> Result<()> {
    let Some((leaf, parents)) = comps.split_last() else {
        root.set_metadata_checksum(dirmeta);
        return Ok(());
    };
    let node = descend(txn, root, parents, opts, raw_owner, synthesized).await?;
    node.ensure_dir(leaf).await?.set_metadata_checksum(dirmeta);
    Ok(())
}

/// Record a content object at the member's path, resolving its parents the way
/// [`descend`] does.
async fn place(
    txn: &Transaction,
    root: &mut MutableTree,
    comps: &[String],
    checksum: Checksum,
    opts: &TarImportOptions,
    raw_owner: (u32, u32),
    synthesized: &mut Option<(u32, u32)>,
) -> Result<()> {
    let (leaf, parents) = comps
        .split_last()
        .expect("a content member has at least one component");
    let node = descend(txn, root, parents, opts, raw_owner, synthesized).await?;
    node.replace_file(leaf, checksum)?;
    Ok(())
}

/// Walk `tree` depth-first, appending ordered [`Item`]s. Within a directory the
/// files and subdirectories are interleaved in name order; a subdirectory's
/// entry is emitted just before its contents. `seen` maps a content object to
/// the first path that carried it, so a repeat becomes a hardlink.
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

/// The failure a tar member's header states. The reader reports a pathname that
/// is not valid UTF-8 as an `InvalidData` i/o error; the port stores pathnames
/// as text, so it reports that case the way the tool reports it.
fn read_error(err: std::io::Error) -> Error {
    // The refusal is recognized by the dependency's message text: smol-tar
    // 0.1.7, the registry version the workspace resolves, spells it `utf8 in
    // file path`. The exact pin `=0.1.7` in `crates/ostrya/Cargo.toml` holds
    // that text. A change to that text upstream leaves the failure an
    // `Error::Io`; `commit_tar_pathname_not_utf8_is_refused` in the CLI tests
    // covers the case against the tool and fails when the text moves.
    if err.kind() == std::io::ErrorKind::InvalidData
        && err.to_string().contains("utf8 in file path")
    {
        return Error::TarPathname;
    }
    Error::Io(err)
}

/// The name of a directory entry regardless of kind.
fn entry_name(entry: &TreeEntry) -> &str {
    match entry {
        TreeEntry::File { name, .. } => name,
        TreeEntry::Dir { name, .. } => name,
    }
}

/// The path components a member is imported under: the normalized name (one
/// leading `./` and one leading `/` dropped, a directory keeping its trailing
/// `/`, the archive's own root member being the empty string), put through the
/// rename hook, then split.
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

/// Split a tar member name into path components, dropping empty and `.`
/// components and the root, and rejecting `..`. With `etc_to_usr_etc`, a leading
/// `etc` component becomes `usr/etc`.
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

/// Reject an entry whose normalized path is empty (it would name the tree root
/// as a file).
fn require_leaf(comps: &[String], kind: &str) -> Result<()> {
    if comps.is_empty() {
        return Err(Error::Tar(format!("{kind} entry has an empty path")));
    }
    Ok(())
}

/// Render path components as a slash-joined string for diagnostics.
fn join(comps: &[String]) -> String {
    comps.join("/")
}

/// Convert an ostrya xattr set to tar PAX attributes: drop the stored
/// terminating NUL from each name (smol-tar prepends `SCHILY.xattr.` and
/// requires a graphic-ASCII name), keeping values byte-for-byte.
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

/// Convert tar PAX attributes to a canonical ostrya xattr set, appending the
/// terminating NUL each stored name carries. [`Xattrs::new`] sorts and validates.
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

/// The tar option types move freely across tasks and threads.
/// [`TarImportOptions`] holds a callback field, which is called through `&mut`
/// and so is `Send` alone, the way [`CommitModifier`] is.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>() {}
    assert_send_sync::<TarExportOptions>();
    assert_send::<TarImportOptions>();
};
