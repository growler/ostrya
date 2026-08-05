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
//! are resolved after the walk against the paths already ingested. A directory
//! that the archive never names explicitly is given a default `0755` root-owned
//! metadata object so the tree can serialize. With
//! [`TarImportOptions::etc_to_usr_etc`], a top-level `etc` component is rewritten
//! to `usr/etc`. [`TarImportOptions::owner_uid`] and
//! [`TarImportOptions::owner_gid`] replace the ownership every member records,
//! the default directory metadata included, and
//! [`TarImportOptions::skip_xattrs`] records no extended attributes at all.
//! Device and FIFO members are rejected, since an ostree tree
//! stores only regular files, symlinks, and directories. The returned tree is
//! serialized and committed by the caller through
//! [`Transaction::write_mtree`](crate::Transaction::write_mtree) and
//! [`Transaction::write_commit`](crate::Transaction::write_commit).

use std::collections::{BTreeSet, HashMap};
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
use crate::mtree::MutableTree;
use crate::repo::Repo;
use crate::transaction::{FileMeta, Transaction};
use crate::tree::{RepoTree, TreeEntry};

/// The `S_IFDIR` file-type bits a directory's `st_mode` carries.
const S_IFDIR: u32 = 0o040000;
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

/// Options for [`Repo::import_tar`].
#[derive(Debug, Default, Clone)]
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

    /// Read a filesystem tar from `input` into a [`MutableTree`] over `txn`,
    /// staging one content object per regular file and symlink and one metadata
    /// object per directory. The returned tree is ready for
    /// [`write_mtree`](Transaction::write_mtree); the caller commits it.
    pub async fn import_tar(
        &self,
        txn: &Transaction,
        opts: TarImportOptions,
        input: impl AsyncRead,
    ) -> Result<MutableTree> {
        let mut reader = TarReader::new(input);

        // Files and symlinks by path, in encounter order, plus an index for
        // resolving hardlink targets. Directory dirmeta checksums and the set of
        // every directory path (explicit entries and the ancestors of every
        // member) are tracked so each directory ends up with a dirmeta.
        let mut files: Vec<(Vec<String>, Checksum)> = Vec::new();
        let mut file_index: HashMap<Vec<String>, Checksum> = HashMap::new();
        let mut dir_meta: HashMap<Vec<String>, Checksum> = HashMap::new();
        let mut all_dirs: BTreeSet<Vec<String>> = BTreeSet::new();
        all_dirs.insert(Vec::new());
        let mut hardlinks: Vec<(Vec<String>, Vec<String>)> = Vec::new();

        while let Some(entry) = reader.next().await {
            let entry = entry.map_err(Error::Io)?;
            match entry {
                TarEntry::Directory(dir) => {
                    let comps = normalize(dir.path(), &opts)?;
                    let meta = DirMeta {
                        uid: opts.uid(dir.uid()),
                        gid: opts.gid(dir.gid()),
                        mode: S_IFDIR | (dir.mode() & PERM_MASK),
                        xattrs: attrs_to_xattrs(dir.attrs(), &opts)?,
                    };
                    let checksum = self.stage_dirmeta(txn, &meta).await?;
                    register_ancestors(&comps, &mut all_dirs);
                    all_dirs.insert(comps.clone());
                    dir_meta.insert(comps, checksum);
                }
                TarEntry::File(file) => {
                    let comps = normalize(file.path(), &opts)?;
                    require_leaf(&comps, "regular file")?;
                    let mut meta = FileMeta::regular(
                        opts.uid(file.uid()),
                        opts.gid(file.gid()),
                        file.mode() & PERM_MASK,
                    );
                    meta.xattrs = attrs_to_xattrs(file.attrs(), &opts)?;
                    let checksum = txn.write_content(None, &meta, file).await?;
                    register_ancestors(&comps, &mut all_dirs);
                    file_index.insert(comps.clone(), checksum);
                    files.push((comps, checksum));
                }
                TarEntry::Symlink(link) => {
                    let comps = normalize(link.path(), &opts)?;
                    require_leaf(&comps, "symlink")?;
                    let mut meta =
                        FileMeta::regular(opts.uid(link.uid()), opts.gid(link.gid()), 0o777);
                    meta.xattrs = attrs_to_xattrs(link.attrs(), &opts)?;
                    let checksum = txn.write_symlink(link.link(), &meta, None).await?;
                    register_ancestors(&comps, &mut all_dirs);
                    file_index.insert(comps.clone(), checksum);
                    files.push((comps, checksum));
                }
                TarEntry::Link(link) => {
                    let comps = normalize(link.path(), &opts)?;
                    require_leaf(&comps, "hardlink")?;
                    let target = normalize(link.link(), &opts)?;
                    register_ancestors(&comps, &mut all_dirs);
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
            file_index.insert(link.clone(), checksum);
            files.push((link, checksum));
        }

        let mut root = MutableTree::new();
        for (comps, checksum) in &files {
            let (leaf, parents) = comps
                .split_last()
                .expect("a file path has at least one component");
            let mut node = &mut root;
            for parent in parents {
                node = node.ensure_dir(parent).await?;
            }
            node.replace_file(leaf, *checksum)?;
        }

        // Give every directory its dirmeta: the explicit one where the archive
        // named the directory, a shared default otherwise.
        let mut default_dirmeta: Option<Checksum> = None;
        for comps in &all_dirs {
            let mut node = &mut root;
            for component in comps {
                node = node.ensure_dir(component).await?;
            }
            let checksum = match dir_meta.get(comps) {
                Some(checksum) => *checksum,
                None => match default_dirmeta {
                    Some(checksum) => checksum,
                    None => {
                        let meta = DirMeta {
                            uid: opts.uid(0),
                            gid: opts.gid(0),
                            mode: S_IFDIR | 0o755,
                            xattrs: Xattrs::empty(),
                        };
                        let checksum = self.stage_dirmeta(txn, &meta).await?;
                        default_dirmeta = Some(checksum);
                        checksum
                    }
                },
            };
            node.set_metadata_checksum(checksum);
        }

        Ok(root)
    }

    /// Stage a dirmeta as a metadata object.
    async fn stage_dirmeta(&self, txn: &Transaction, meta: &DirMeta) -> Result<Checksum> {
        txn.write_dirmeta(meta).await
    }
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

/// The name of a directory entry regardless of kind.
fn entry_name(entry: &TreeEntry) -> &str {
    match entry {
        TreeEntry::File { name, .. } => name,
        TreeEntry::Dir { name, .. } => name,
    }
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

/// Every proper ancestor directory of `comps` (the root is inserted once by the
/// caller), so a member whose parents the archive never named still yields
/// directory nodes with metadata.
fn register_ancestors(comps: &[String], all_dirs: &mut BTreeSet<Vec<String>>) {
    for i in 1..comps.len() {
        all_dirs.insert(comps[..i].to_vec());
    }
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
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TarExportOptions>();
    assert_send_sync::<TarImportOptions>();
};
