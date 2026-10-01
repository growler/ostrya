//! The tree model: the entries of a walk, their checksums, and the source of
//! each object.

use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};

use futures_lite::io::{AsyncReadExt, Cursor};
use ostrya_core::{
    Checksum, DirMeta, DirTree, FileHeader, MAX_METADATA_SIZE, ObjectName, ObjectType, Xattrs,
};
use ostrya_gvariant::Value;

use super::hash::{FileId, open_regular};
use super::{EntryMeta, ScanOptions, invalid_data, walk};
use crate::error::{Error, Result};
use crate::proto::Encoding;
use crate::session::{BoxFuture, ObjectData, ObjectSource, PushProgress};

/// The result of the hash of one regular file.
#[derive(Debug, Clone, Copy)]
pub(super) struct Hashed {
    /// The content-object checksum.
    pub(super) checksum: Checksum,
    /// The number of payload bytes the hash read.
    pub(super) size: u64,
}

/// The owner, the mode, and the extended attributes of an entry.
struct Meta {
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: Xattrs,
}

/// What the model keeps of an entry.
enum NodeData {
    /// A directory.
    Dir {
        meta: Meta,
        /// The indices of the kept entries of the directory, which are
        /// contiguous.
        children: Range<u32>,
        /// The dirtree and dirmeta checksums, once the bottom-up pass ran.
        sums: Option<(Checksum, Checksum)>,
    },
    /// A regular file or a symlink.
    Content {
        meta: Meta,
        /// The identity of a regular file, as the walk read it. The open of
        /// the file checks it.
        id: FileId,
        /// The target of a symlink. A regular file has none.
        target: Option<Box<str>>,
        /// The checksum and the payload size, once the entry is hashed.
        hashed: Option<Hashed>,
    },
}

/// One entry of the model.
struct Node {
    /// The index of the parent directory. The root names itself.
    parent: u32,
    /// The name of the entry. The root has the empty name.
    name: Box<str>,
    data: NodeData,
}

/// The model of a local tree that [`TreeModel::scan`] walked and hashed.
///
/// The model keeps, for each entry, its name, its metadata, and the index of
/// its parent directory. For each regular file it keeps the number of payload
/// bytes the hash pass read. It serializes a dirtree or a dirmeta object
/// again from these fields when a caller asks for it, and it holds no file
/// content.
///
/// The model is the [`ObjectSource`] of a push of the tree, once
/// [`set_commit`](TreeModel::set_commit) gave it the commit over the tree:
///
/// - [`objects`](ObjectSource::objects) of that commit gives each object of
///   the tree once, and then the commit.
/// - [`open`](ObjectSource::open) of a regular file opens the file again,
///   with the open and the checks of the hash pass, and gives it as
///   [`ObjectData::Content`]. Its `size` is the number of payload bytes the
///   hash pass read. The model does not read the length of the file again,
///   and it does not hash the file again, so a file that changed after the
///   hash pass reaches the server, which refuses it. A symlink opens
///   nothing. A dirtree or a dirmeta object is serialized again from the
///   model, and the commit object is the bytes that `set_commit` gave. Each
///   of them is [`ObjectData::Encoded`] in `raw`.
/// - [`detached_metadata`](ObjectSource::detached_metadata) of the commit
///   gives the dict that `set_commit` gave.
///
/// Another commit, and an object that the model does not hold, are
/// [`Error::InvalidInput`]. A failed open of a file is [`Error::Walk`] that
/// names the file.
pub struct TreeModel {
    /// The walk root.
    root: PathBuf,
    /// The entries in the order the walk kept them. The root is at 0, and the
    /// kept entries of a directory follow each other.
    nodes: Vec<Node>,
    /// The source entry of each object.
    sources: Sources,
    /// The commit over the tree, once [`set_commit`](TreeModel::set_commit)
    /// gave it.
    commit: Option<CommitObject>,
}

/// The commit object of a model and its detached metadata.
struct CommitObject {
    checksum: Checksum,
    bytes: Vec<u8>,
    detached: Option<Value>,
}

/// The source entry of each object: the first entry, in walk order, that
/// gives it. Each list holds one entry for each distinct object of its type,
/// sorted by the checksum of the object.
#[derive(Default)]
struct Sources {
    files: Vec<u32>,
    dirtrees: Vec<u32>,
    dirmetas: Vec<u32>,
}

impl TreeModel {
    /// Walk the directory `root` and hash each object of its tree.
    ///
    /// The module docs give the rules of the walk and of the hash pass.
    /// A failure of either is [`Error::Walk`]. `hash_jobs` of `Some(0)` is
    /// [`Error::InvalidInput`].
    pub async fn scan(root: &Path, options: ScanOptions) -> Result<TreeModel> {
        walk::scan(root, options, None).await
    }

    /// [`scan`](TreeModel::scan), which also sets the phases of the scan in
    /// `progress`: [`Scanning`](crate::PushPhase::Scanning) during the walk,
    /// and [`Hashing`](crate::PushPhase::Hashing) after it.
    pub(crate) async fn scan_with(
        root: &Path,
        options: ScanOptions,
        progress: Option<&PushProgress>,
    ) -> Result<TreeModel> {
        walk::scan(root, options, progress).await
    }

    /// The dirtree checksum of the walk root.
    pub fn root_dirtree(&self) -> Checksum {
        self.dir_sums(0).0
    }

    /// The dirmeta checksum of the walk root.
    pub fn root_dirmeta(&self) -> Checksum {
        self.dir_sums(0).1
    }

    /// Each object of the tree once: the content object of each regular file
    /// and symlink, and the dirtree and dirmeta objects of each directory, in
    /// the order the walk reached their first source.
    pub fn object_names(&self) -> Vec<ObjectName> {
        let Sources {
            files,
            dirtrees,
            dirmetas,
        } = &self.sources;
        let mut names = Vec::with_capacity(files.len() + dirtrees.len() + dirmetas.len());
        for (index, node) in (0u32..).zip(&self.nodes) {
            for name in node_names(node).into_iter().flatten() {
                if self.source(&name) == Some(index) {
                    names.push(name);
                }
            }
        }
        names
    }

    /// Give the model the commit object over the tree: its checksum
    /// `checksum`, its serialized bytes `bytes`, and the `a{sv}` dict
    /// `detached` that the push sends as its detached metadata. A later call
    /// replaces the commit.
    ///
    /// The model does not check the bytes. The server verifies the commit
    /// object as it does each other object.
    pub fn set_commit(&mut self, checksum: Checksum, bytes: Vec<u8>, detached: Option<Value>) {
        self.commit = Some(CommitObject {
            checksum,
            bytes,
            detached,
        });
    }

    /// An empty model of the walk root `root`.
    pub(super) fn new(root: &Path) -> TreeModel {
        TreeModel {
            root: root.to_path_buf(),
            nodes: Vec::new(),
            sources: Sources::default(),
            commit: None,
        }
    }

    /// The walk root.
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    /// The index the next entry gets.
    pub(super) fn next_index(&self) -> io::Result<u32> {
        u32::try_from(self.nodes.len())
            .map_err(|_| invalid_data("the tree holds more entries than the model can index"))
    }

    /// Add the walk root, with the metadata the filter left.
    pub(super) fn push_root(&mut self, meta: EntryMeta, id: FileId) {
        self.push(0, String::new(), meta, id);
    }

    /// Add an entry under the directory `parent`, with the metadata the filter
    /// left and the identity the walk read. The caller checked the index with
    /// [`next_index`](TreeModel::next_index).
    pub(super) fn push(&mut self, parent: u32, name: String, meta: EntryMeta, id: FileId) {
        let EntryMeta {
            kind,
            uid,
            gid,
            mode,
            xattrs,
            symlink_target,
        } = meta;
        let meta = Meta {
            uid,
            gid,
            mode,
            xattrs,
        };
        let data = match kind {
            super::EntryKind::Dir => NodeData::Dir {
                meta,
                children: 0..0,
                sums: None,
            },
            super::EntryKind::File | super::EntryKind::Symlink => NodeData::Content {
                meta,
                id,
                target: symlink_target.map(String::into_boxed_str),
                hashed: None,
            },
        };
        self.nodes.push(Node {
            parent,
            name: name.into_boxed_str(),
            data,
        });
    }

    /// Record the hash of the symlink `index`, whose content object has no
    /// payload.
    pub(super) fn hash_symlink(&mut self, index: u32) -> io::Result<()> {
        let checksum = ostrya_core::ContentHasher::new(&self.header(index))
            .map_err(|e| invalid_data(e.to_string()))?
            .finish();
        self.set_hashed(index, Hashed { checksum, size: 0 });
        Ok(())
    }

    /// Record the kept entries of the directory `dir`.
    pub(super) fn set_children(&mut self, dir: u32, range: Range<u32>) {
        if let NodeData::Dir { children, .. } = &mut self.node_mut(dir).data {
            *children = range;
        }
    }

    /// The kept entries of the directory `dir`.
    pub(super) fn children(&self, dir: u32) -> Range<u32> {
        match &self.node(dir).data {
            NodeData::Dir { children, .. } => children.clone(),
            NodeData::Content { .. } => 0..0,
        }
    }

    /// Whether the entry `index` is a directory.
    pub(super) fn is_dir(&self, index: u32) -> bool {
        matches!(self.node(index).data, NodeData::Dir { .. })
    }

    /// The path of the entry `index` relative to the walk root, joined with
    /// `/`, written into `out`.
    pub(super) fn rel_path(&self, index: u32, out: &mut String) {
        out.clear();
        for i in self.chain(index) {
            if !out.is_empty() {
                out.push('/');
            }
            out.push_str(&self.node(i).name);
        }
    }

    /// The path of the entry `index` on the local filesystem.
    pub(super) fn os_path(&self, index: u32) -> PathBuf {
        let mut path = self.root.clone();
        for i in self.chain(index) {
            path.push(&*self.node(i).name);
        }
        path
    }

    /// The identity of the regular file `index`, as the walk read it.
    pub(super) fn file_id(&self, index: u32) -> FileId {
        match &self.node(index).data {
            NodeData::Content { id, .. } => *id,
            NodeData::Dir { .. } => unreachable!("a directory is not opened as a file"),
        }
    }

    /// The file header of the regular file or symlink `index`.
    pub(super) fn header(&self, index: u32) -> FileHeader {
        match &self.node(index).data {
            NodeData::Content { meta, target, .. } => FileHeader {
                uid: meta.uid,
                gid: meta.gid,
                mode: meta.mode,
                symlink_target: target.as_deref().unwrap_or_default().to_owned(),
                xattrs: meta.xattrs.clone(),
            },
            NodeData::Dir { .. } => unreachable!("a directory has no file header"),
        }
    }

    /// Hash each directory bottom-up, once each regular file is hashed, and
    /// record the source of each object.
    pub(super) fn finish(&mut self) -> Result<()> {
        // The entries of a directory come after it, so the reverse order
        // hashes each directory after all of its subdirectories.
        for index in (0..self.next_index_unchecked()).rev() {
            if !self.is_dir(index) {
                continue;
            }
            let sums = self.hash_dir(index).map_err(|source| Error::Walk {
                path: self.os_path(index),
                source,
            })?;
            if let NodeData::Dir { sums: slot, .. } = &mut self.node_mut(index).data {
                *slot = Some(sums);
            }
        }
        let mut sources = Sources::default();
        for (index, node) in (0u32..).zip(&self.nodes) {
            match node.data {
                NodeData::Content { .. } => sources.files.push(index),
                NodeData::Dir { .. } => {
                    sources.dirtrees.push(index);
                    sources.dirmetas.push(index);
                }
            }
        }
        for (list, ty) in [
            (&mut sources.files, ObjectType::File),
            (&mut sources.dirtrees, ObjectType::DirTree),
            (&mut sources.dirmetas, ObjectType::DirMeta),
        ] {
            // The sort is stable, so the first entry of each run of equal
            // checksums is the first in walk order, and the dedup keeps it.
            list.sort_by_key(|&index| self.object_checksum(index, ty));
            list.dedup_by_key(|index| self.object_checksum(*index, ty));
            list.shrink_to_fit();
        }
        self.sources = sources;
        Ok(())
    }

    /// The source entry of the object `name`, or `None` for an object the
    /// tree does not give.
    fn source(&self, name: &ObjectName) -> Option<u32> {
        let list = match name.ty {
            ObjectType::File => &self.sources.files,
            ObjectType::DirTree => &self.sources.dirtrees,
            ObjectType::DirMeta => &self.sources.dirmetas,
            _ => return None,
        };
        list.binary_search_by_key(&name.checksum, |&index| {
            self.object_checksum(index, name.ty)
        })
        .ok()
        .map(|k| list[k])
    }

    /// The checksum of the object of type `ty` that the hashed entry `index`
    /// gives.
    fn object_checksum(&self, index: u32, ty: ObjectType) -> Checksum {
        match (&self.node(index).data, ty) {
            (
                NodeData::Content {
                    hashed: Some(hashed),
                    ..
                },
                ObjectType::File,
            ) => hashed.checksum,
            (NodeData::Dir { .. }, ObjectType::DirTree) => self.dir_sums(index).0,
            (NodeData::Dir { .. }, ObjectType::DirMeta) => self.dir_sums(index).1,
            _ => unreachable!("each source entry is hashed and gives an object of its type"),
        }
    }

    /// The dirtree object of the directory `dir`.
    fn dirtree(&self, dir: u32) -> DirTree {
        let mut tree = DirTree::default();
        for index in self.children(dir) {
            let node = self.node(index);
            let name = node.name.to_string();
            match &node.data {
                NodeData::Content { hashed, .. } => {
                    let hashed = hashed.expect("each kept file is hashed before its directory");
                    tree.files.push((name, hashed.checksum));
                }
                NodeData::Dir { .. } => {
                    let (dirtree, dirmeta) = self.dir_sums(index);
                    tree.dirs.push((name, dirtree, dirmeta));
                }
            }
        }
        tree.files.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        tree.dirs.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        tree
    }

    /// The dirmeta object of the directory `dir`.
    fn dirmeta(&self, dir: u32) -> DirMeta {
        match &self.node(dir).data {
            NodeData::Dir { meta, .. } => DirMeta {
                uid: meta.uid,
                gid: meta.gid,
                mode: meta.mode,
                xattrs: meta.xattrs.clone(),
            },
            NodeData::Content { .. } => unreachable!("a file has no dirmeta"),
        }
    }

    /// The dirtree and dirmeta checksums of the directory `dir`.
    fn hash_dir(&self, dir: u32) -> io::Result<(Checksum, Checksum)> {
        let dirtree = self
            .dirtree(dir)
            .serialize()
            .map_err(|e| invalid_data(e.to_string()))?;
        check_metadata_size(&dirtree, "dirtree", MAX_METADATA_SIZE)?;
        let dirmeta = self
            .dirmeta(dir)
            .serialize()
            .map_err(|e| invalid_data(e.to_string()))?;
        check_metadata_size(&dirmeta, "dirmeta", MAX_METADATA_SIZE)?;
        Ok((Checksum::sha256(&dirtree), Checksum::sha256(&dirmeta)))
    }

    /// The commit object of the model, when its checksum is `checksum`.
    fn commit_object(&self, checksum: &Checksum) -> Result<&CommitObject> {
        match &self.commit {
            Some(commit) if commit.checksum == *checksum => Ok(commit),
            Some(commit) => Err(Error::InvalidInput(format!(
                "commit {checksum} is not the commit {} of the tree model",
                commit.checksum
            ))),
            None => Err(Error::InvalidInput(format!(
                "commit {checksum} is not in the tree model, which has no commit"
            ))),
        }
    }

    /// The data of the object `name` for the send pass.
    async fn open_object(&self, name: &ObjectName) -> Result<ObjectData> {
        if name.ty == ObjectType::Commit {
            let commit = self.commit_object(&name.checksum)?;
            return Ok(encoded(commit.bytes.clone()));
        }
        let index = self.source(name).ok_or_else(|| {
            Error::InvalidInput(format!(
                "object {} of type {:?} is not in the tree model",
                name.checksum, name.ty
            ))
        })?;
        let bytes = match name.ty {
            ObjectType::File => return self.open_content(index).await,
            ObjectType::DirTree => self.dirtree(index).serialize(),
            ObjectType::DirMeta => self.dirmeta(index).serialize(),
            _ => unreachable!("the model is the source of three object types alone"),
        };
        let bytes = bytes.map_err(|e| Error::Walk {
            path: self.os_path(index),
            source: invalid_data(e.to_string()),
        })?;
        Ok(encoded(bytes))
    }

    /// The content object of the regular file or symlink `index`. A regular
    /// file is opened again, on the blocking pool, with the open of the hash
    /// pass, and its payload stops after the size of the hash pass plus one
    /// byte. A symlink opens nothing.
    async fn open_content(&self, index: u32) -> Result<ObjectData> {
        let NodeData::Content {
            target,
            hashed: Some(hashed),
            ..
        } = &self.node(index).data
        else {
            unreachable!("each source of a content object is a hashed file or symlink");
        };
        let header = self.header(index);
        if target.is_some() {
            return Ok(ObjectData::Content {
                header,
                size: 0,
                payload: None,
            });
        }
        let path = self.os_path(index);
        let id = self.file_id(index);
        let open_path = path.clone();
        let (file, _len) = ostrya_rt::unblock(move || open_regular(&open_path, &id))
            .await
            .map_err(|source| Error::Walk { path, source })?;
        Ok(ObjectData::Content {
            header,
            size: hashed.size,
            // One byte past the size of the hash pass lets the server see a
            // file that grew, and stops the read there.
            payload: Some(Box::new(
                ostrya_rt::FileReader::with_len_hint(file, hashed.size)
                    .take(hashed.size.saturating_add(1)),
            )),
        })
    }

    /// The dirtree and dirmeta checksums of the hashed directory `dir`.
    fn dir_sums(&self, dir: u32) -> (Checksum, Checksum) {
        match &self.node(dir).data {
            NodeData::Dir {
                sums: Some(sums), ..
            } => *sums,
            _ => unreachable!("each directory is hashed after its subdirectories"),
        }
    }

    /// Record the hash of the regular file or symlink `index`.
    pub(super) fn set_hashed(&mut self, index: u32, result: Hashed) {
        if let NodeData::Content { hashed, .. } = &mut self.node_mut(index).data {
            *hashed = Some(result);
        }
    }

    /// The number of entries. [`push`](TreeModel::push) keeps it within `u32`.
    fn next_index_unchecked(&self) -> u32 {
        self.nodes.len() as u32
    }

    /// The indices of the entries from the root down to `index`, the root
    /// left out.
    fn chain(&self, mut index: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        while index != 0 {
            chain.push(index);
            index = self.node(index).parent;
        }
        chain.reverse();
        chain
    }

    fn node(&self, index: u32) -> &Node {
        &self.nodes[index as usize]
    }

    fn node_mut(&mut self, index: u32) -> &mut Node {
        &mut self.nodes[index as usize]
    }
}

/// The objects an entry gives: the content object of a regular file or a
/// symlink, and the dirtree and dirmeta objects of a directory.
fn node_names(node: &Node) -> [Option<ObjectName>; 2] {
    match &node.data {
        NodeData::Content { hashed, .. } => [
            hashed.map(|h| ObjectName::new(h.checksum, ObjectType::File)),
            None,
        ],
        NodeData::Dir { sums, .. } => match sums {
            Some((dirtree, dirmeta)) => [
                Some(ObjectName::new(*dirtree, ObjectType::DirTree)),
                Some(ObjectName::new(*dirmeta, ObjectType::DirMeta)),
            ],
            None => [None, None],
        },
    }
}

impl ObjectSource for TreeModel {
    fn objects<'a>(&'a self, commit: &'a Checksum) -> BoxFuture<'a, Result<Vec<ObjectName>>> {
        Box::pin(async move {
            let commit = self.commit_object(commit)?;
            let mut names = self.object_names();
            names.push(ObjectName::new(commit.checksum, ObjectType::Commit));
            Ok(names)
        })
    }

    fn open<'a>(
        &'a self,
        name: &'a ObjectName,
        _encoding: Encoding,
    ) -> BoxFuture<'a, Result<ObjectData>> {
        Box::pin(self.open_object(name))
    }

    fn detached_metadata<'a>(
        &'a self,
        commit: &'a Checksum,
    ) -> BoxFuture<'a, Result<Option<Value>>> {
        Box::pin(async move { Ok(self.commit_object(commit)?.detached.clone()) })
    }
}

/// Metadata object bytes, given as they are in `raw`.
fn encoded(bytes: Vec<u8>) -> ObjectData {
    ObjectData::Encoded {
        encoding: Encoding::Raw,
        reader: Box::new(Cursor::new(bytes)),
    }
}

/// Refuse a metadata object of more than `limit` bytes.
fn check_metadata_size(bytes: &[u8], what: &str, limit: u64) -> io::Result<()> {
    if bytes.len() as u64 > limit {
        return Err(invalid_data(format!(
            "the {what} object of the directory is {} bytes, over the limit of {limit}",
            bytes.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_limit(bytes: &[u8], what: &str) {
        let len = bytes.len() as u64;
        check_metadata_size(bytes, what, len).unwrap();
        let err = check_metadata_size(bytes, what, len - 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(what), "{err}");
    }

    #[test]
    fn a_dirtree_one_byte_over_the_limit_is_invalid_data() {
        let dirtree = DirTree {
            files: ["a", "b", "c"]
                .into_iter()
                .map(|name| (name.to_owned(), Checksum::sha256(name.as_bytes())))
                .collect(),
            dirs: vec![(
                "d".to_owned(),
                Checksum::sha256(b"dirtree"),
                Checksum::sha256(b"dirmeta"),
            )],
        };
        assert_limit(&dirtree.serialize().unwrap(), "dirtree");
    }

    #[test]
    fn a_dirmeta_one_byte_over_the_limit_is_invalid_data() {
        let dirmeta = DirMeta {
            uid: 0,
            gid: 0,
            mode: 0o40755,
            xattrs: Xattrs::new([(b"user.test\0".to_vec(), vec![7; 100])]).unwrap(),
        };
        assert_limit(&dirmeta.serialize().unwrap(), "dirmeta");
    }
}
