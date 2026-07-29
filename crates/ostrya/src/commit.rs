//! Commit assembly and detached commit metadata.
//!
//! [`Transaction::write_commit`] serializes a commit object over a written root
//! tree and stages it like any other metadata object. The caller supplies the
//! commit's metadata dict, parent, subject, body, and timestamp through
//! [`CommitOptions`]; the well-known binding keys (`ostree.ref-binding`,
//! `ostree.collection-binding`) are ordinary metadata entries the caller
//! provides, so `write_commit` adds nothing of its own beyond `ostree.sizes`.
//!
//! `ostree.sizes` is emitted only when a filesystem ingest requested
//! [`GENERATE_SIZES`](crate::CommitModifierFlags::GENERATE_SIZES) and the
//! repository is archive mode; it is appended as the last metadata entry,
//! matching the tool. Its records cover exactly the objects reachable from the
//! committed root -- the root dirmeta, each dirtree, each subdirectory dirmeta,
//! and each file entry -- and no others, so a transaction that stages more than
//! one commit gives each commit its own reachable-scoped key. The set is
//! recovered by walking the committed tree at commit time. A freshly staged
//! object uses the size record the transaction kept; an object that already
//! existed in `objects/` and deduplicated has its sizes recovered from its loose
//! object, so an incremental commit that reaches pre-existing objects lists them
//! too, matching the tool. The commit object itself is never among them, since
//! the walk starts below it. In every other mode the request is a silent no-op,
//! so a commit's bytes are identical with and without it.
//!
//! Detached metadata ([`read_commit_detached_metadata`](Repo::read_commit_detached_metadata),
//! [`write_commit_detached_metadata`](Repo::write_commit_detached_metadata))
//! is a bare `a{sv}` at the commit's `.commitmeta` loose path, replaced
//! atomically and outside the commit checksum. Writing `None` produces the
//! documented zero-length file.

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd};

use ostrya_core::sizes::SizeEntry;
use ostrya_core::{
    Checksum, Commit, DirTree, ObjectType, RepoMode, Type, Value, loose_path, to_bytes,
};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::file::FileKind;
use crate::repo::Repo;
use crate::transaction::Transaction;
use crate::tree::RepoTree;

/// The metadata dict type string for detached commit metadata and, wrapped in
/// the commit tuple, the commit metadata dict.
const METADATA_SIGNATURE: &str = "a{sv}";
/// The `ostree.sizes` value type: an array of packed byte buffers.
const SIZES_SIGNATURE: &str = "aay";
/// The metadata key `ostree.sizes` is written under.
const SIZES_KEY: &str = "ostree.sizes";
/// The permission bits forced on the `.commitmeta` file, matching the `0644`
/// every metadata object carries.
const COMMITMETA_MODE: u32 = 0o644;

/// Options for [`Transaction::write_commit`].
///
/// Every field is optional. `metadata`, when set, must be an `a{sv}` dict
/// value; its entries appear in the commit in insertion order, which byte
/// identity with a tool commit relies on, so a caller reproducing a tool commit
/// supplies the binding keys in the tool's observed order.
#[derive(Debug, Default, Clone)]
pub struct CommitOptions {
    /// The parent commit, or `None` for a root commit.
    pub parent: Option<Checksum>,
    /// The commit subject; an empty string when `None`.
    pub subject: Option<String>,
    /// The commit body; an empty string when `None`.
    pub body: Option<String>,
    /// The commit timestamp in seconds since the Unix epoch, UTC. When `None`,
    /// `SOURCE_DATE_EPOCH` is used if set, otherwise the current time.
    pub timestamp: Option<u64>,
    /// The `a{sv}` metadata dict, or `None` for an empty dict.
    pub metadata: Option<Value>,
}

impl Transaction {
    /// Assemble a commit object over `root` and stage it, returning its
    /// checksum.
    ///
    /// The commit's metadata dict comes from `opts.metadata` (empty when
    /// unset); `ostree.sizes` is appended when the transaction was marked for
    /// size generation and the repository is archive mode. The timestamp
    /// resolves from `opts.timestamp`, else `SOURCE_DATE_EPOCH`, else the
    /// current time. The root dirtree and dirmeta come from `root`.
    pub async fn write_commit(&self, opts: CommitOptions, root: &RepoTree) -> Result<Checksum> {
        if self.repo().mode() == RepoMode::BareSplitXattrs {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }

        let timestamp = resolve_timestamp(opts.timestamp)?;
        let mut metadata = opts.metadata.unwrap_or_else(|| Value::Array(Vec::new()));

        if self.generate_sizes() && self.repo().mode().is_archive() {
            let entries = self.reachable_size_entries(root).await?;
            let packed = ostrya_core::sizes::pack_sizes(entries);
            let elements = packed.into_iter().map(Value::Bytes).collect();
            let sizes_type = Type::parse(SIZES_SIGNATURE).map_err(ostrya_core::Error::from)?;
            let sizes = Value::variant(sizes_type, Value::Array(elements));
            append_dict_entry(&mut metadata, SIZES_KEY, sizes)?;
        }

        let commit = Commit {
            metadata,
            parent: opts.parent,
            related: Vec::new(),
            subject: opts.subject.unwrap_or_default(),
            body: opts.body.unwrap_or_default(),
            timestamp,
            root_dirtree: *root.dirtree_checksum(),
            root_dirmeta: *root.dirmeta_checksum(),
        };
        let bytes = commit.serialize()?;
        self.write_metadata(ObjectType::Commit, None, &bytes).await
    }

    /// Build the `ostree.sizes` entries for `root`: one record per object
    /// reachable from the committed root, covering both the objects this
    /// transaction freshly staged and the objects that already existed in
    /// `objects/` and deduplicated. A freshly staged object uses the size record
    /// the transaction kept; a deduplicated object has its sizes recovered from
    /// its loose object. The commit object itself is never among them, since the
    /// walk starts below it.
    async fn reachable_size_entries(&self, root: &RepoTree) -> Result<Vec<SizeEntry>> {
        let reachable = self.reachable_objects(root).await?;
        let staged: HashMap<Checksum, SizeEntry> = self
            .size_entries()
            .into_iter()
            .map(|entry| (entry.checksum, entry))
            .collect();
        let mut entries = Vec::with_capacity(reachable.len());
        for (checksum, ty) in reachable {
            match staged.get(&checksum) {
                Some(entry) => entries.push(entry.clone()),
                None => entries.push(self.recover_size_entry(checksum, ty).await?),
            }
        }
        Ok(entries)
    }

    /// Recover the `ostree.sizes` entry for a reachable object that deduplicated
    /// against `objects/`, so has no freshly staged size record. Archive mode
    /// only. The compressed size is the loose object's on-disk size; the
    /// unpacked size is a metadata object's serialized byte length, a regular
    /// file's uncompressed payload length, or a symlink's target length.
    async fn recover_size_entry(&self, checksum: Checksum, ty: ObjectType) -> Result<SizeEntry> {
        let compressed = self.repo().loose_object_size(ty, &checksum).await?;
        let unpacked = if ty == ObjectType::File {
            match self.repo().load_file(&checksum).await?.kind {
                FileKind::Regular { size } => size,
                FileKind::Symlink { target } => target.len() as u64,
            }
        } else {
            // A metadata object is stored uncompressed, so its unpacked size
            // equals its on-disk size.
            compressed
        };
        Ok(SizeEntry {
            checksum,
            compressed,
            unpacked,
            objtype: Some(ty),
        })
    }

    /// Collect the objects reachable from `root`, each mapped to its type: the
    /// root dirmeta, every dirtree in the committed tree, each subdirectory
    /// dirmeta, and each file entry. Used to scope `ostree.sizes` to one commit's
    /// objects even when the transaction stages more than one commit.
    ///
    /// The walk descends into every subtree, whether freshly staged or
    /// pre-existing: [`load_reachable_dirtree`](Self::load_reachable_dirtree)
    /// reads a dirtree from the transaction's staging directory when present, and
    /// falls back to the published `objects/` loose object when it deduplicated,
    /// so an unchanged subtree's objects are visited instead of being skipped.
    async fn reachable_objects(&self, root: &RepoTree) -> Result<HashMap<Checksum, ObjectType>> {
        let mut reachable: HashMap<Checksum, ObjectType> = HashMap::new();
        reachable.insert(*root.dirmeta_checksum(), ObjectType::DirMeta);
        let mut stack = vec![*root.dirtree_checksum()];
        while let Some(dirtree_checksum) = stack.pop() {
            if reachable
                .insert(dirtree_checksum, ObjectType::DirTree)
                .is_some()
            {
                continue;
            }
            let dirtree = self.load_reachable_dirtree(&dirtree_checksum).await?;
            for (_, file_checksum) in dirtree.files {
                reachable.insert(file_checksum, ObjectType::File);
            }
            for (_, subtree, submeta) in dirtree.dirs {
                reachable.insert(submeta, ObjectType::DirMeta);
                stack.push(subtree);
            }
        }
        Ok(reachable)
    }

    /// Load a dirtree reachable from the committed root: from the transaction's
    /// staging directory when freshly staged, else from the published `objects/`
    /// loose object when it deduplicated.
    async fn load_reachable_dirtree(&self, checksum: &Checksum) -> Result<DirTree> {
        if let Some(dirtree) = self.load_staged_dirtree(checksum).await? {
            return Ok(dirtree);
        }
        self.repo().load_dirtree(checksum).await
    }

    /// Load a dirtree staged in this transaction, or `None` when it is not in
    /// the staging directory because it deduplicated against `objects/`.
    async fn load_staged_dirtree(&self, checksum: &Checksum) -> Result<Option<DirTree>> {
        let name = crate::write::flat_name(checksum, ObjectType::DirTree, self.repo().mode());
        let staging = self.staging_fd().try_clone_to_owned()?;
        let res = ostrya_rt::unblock(move || {
            crate::object::read_meta_object(
                staging.as_fd(),
                &name,
                crate::object::MAX_METADATA_SIZE,
            )
        })
        .await;
        match res {
            Ok(bytes) => Ok(Some(DirTree::parse(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }
}

impl Repo {
    /// Read a commit's detached metadata, or `None` when absent or stored as
    /// the zero-length "no metadata" file.
    pub async fn read_commit_detached_metadata(
        &self,
        checksum: &Checksum,
    ) -> Result<Option<Value>> {
        let bytes = match self
            .load_object_bytes(ObjectType::CommitMeta, checksum)
            .await
        {
            Ok(bytes) => bytes,
            Err(Error::ObjectNotFound { .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        // A zero-length file is the documented deletion marker, not an empty
        // dict.
        if bytes.is_empty() {
            return Ok(None);
        }
        let ty = Type::parse(METADATA_SIGNATURE).map_err(ostrya_core::Error::from)?;
        Ok(Some(
            ostrya_core::from_bytes(&ty, &bytes).map_err(ostrya_core::Error::from)?,
        ))
    }

    /// Write (or clear) a commit's detached metadata at its `.commitmeta` loose
    /// path, replaced atomically. `Some(meta)` serializes the `a{sv}` dict;
    /// `None` writes the documented zero-length file.
    pub async fn write_commit_detached_metadata(
        &self,
        checksum: &Checksum,
        meta: Option<&Value>,
    ) -> Result<()> {
        let bytes = match meta {
            Some(value) => {
                let ty = Type::parse(METADATA_SIGNATURE).map_err(ostrya_core::Error::from)?;
                to_bytes(&ty, value).map_err(ostrya_core::Error::from)?
            }
            None => Vec::new(),
        };
        self.write_commit_detached_bytes(checksum, bytes).await
    }

    /// Write a commit's detached metadata from its serialized bytes, replaced
    /// atomically. Used by the pull path, which copies a source repository's
    /// `.commitmeta` verbatim rather than re-serializing a decoded dict.
    pub(crate) async fn write_commit_detached_bytes(
        &self,
        checksum: &Checksum,
        bytes: Vec<u8>,
    ) -> Result<()> {
        let dest = loose_path(checksum, ObjectType::CommitMeta, self.mode());
        let fsync = self.config().fsync()?;
        let objects_fd = self.objects_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || {
            write_detached_blocking(objects_fd.as_fd(), &dest, &bytes, fsync)
        })
        .await
    }
}

/// Resolve a commit timestamp: an explicit value, else `SOURCE_DATE_EPOCH`,
/// else the current time. A malformed `SOURCE_DATE_EPOCH` is an error rather
/// than a silent fallback, matching the reproducible-build convention.
fn resolve_timestamp(explicit: Option<u64>) -> Result<u64> {
    if let Some(timestamp) = explicit {
        return Ok(timestamp);
    }
    if let Ok(raw) = std::env::var("SOURCE_DATE_EPOCH") {
        return raw.trim().parse::<u64>().map_err(|_| {
            Error::InvalidFormat(format!(
                "SOURCE_DATE_EPOCH is not a Unix timestamp: {raw:?}"
            ))
        });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidFormat("the system clock is before the Unix epoch".into()))?;
    Ok(now.as_secs())
}

/// Append one entry to an `a{sv}` dict value, preserving insertion order.
pub(crate) fn append_dict_entry(metadata: &mut Value, key: &str, value: Value) -> Result<()> {
    match metadata {
        Value::Array(entries) => {
            entries.push(Value::Tuple(vec![Value::Str(key.to_owned()), value]));
            Ok(())
        }
        _ => Err(Error::InvalidFormat(
            "commit metadata must be an a{sv} dict".into(),
        )),
    }
}

/// Write detached-metadata bytes to the `.commitmeta` loose path atomically:
/// the fanout directory is created on demand (`0777` reduced by the umask), the
/// bytes go to a temp file (`fchmod` 0644, `fdatasync` when fsync is on), and
/// the temp is renamed over the target. When fsync is on, the fanout directory
/// is fsynced after the rename so the new name survives a crash, and `objects/`
/// is fsynced too when the fanout directory was newly created, matching the
/// durability the object publication path honors.
fn write_detached_blocking(
    objects_fd: BorrowedFd<'_>,
    dest: &str,
    bytes: &[u8],
    fsync: bool,
) -> Result<()> {
    use std::io::Write;

    let fanout = &dest[..2];
    let fanout_created = match rustix::fs::mkdirat(objects_fd, fanout, Mode::from_raw_mode(0o777)) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(e) => return Err(e.into()),
    };

    let tmp = format!(
        "{dest}.tmp-{}-{}",
        std::process::id(),
        crate::write::unique()
    );
    let fd = rustix::fs::openat(
        objects_fd,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(COMMITMETA_MODE),
    )?;
    let write_and_rename = || -> Result<()> {
        let mut file = std::fs::File::from(fd);
        file.write_all(bytes)?;
        file.flush()?;
        rustix::fs::fchmod(file.as_fd(), Mode::from_raw_mode(COMMITMETA_MODE))?;
        if fsync {
            rustix::fs::fdatasync(file.as_fd())?;
        }
        drop(file);
        rustix::fs::renameat(objects_fd, tmp.as_str(), objects_fd, dest)?;
        if fsync {
            // Make the renamed-in directory entry durable: fsync the fanout
            // directory, and `objects/` too when the fanout was newly created.
            let dir = rustix::fs::openat(
                objects_fd,
                fanout,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            rustix::fs::fsync(&dir)?;
            if fanout_created {
                rustix::fs::fsync(objects_fd)?;
            }
        }
        Ok(())
    };
    write_and_rename().inspect_err(|_| {
        let _ = rustix::fs::unlinkat(objects_fd, tmp.as_str(), AtFlags::empty());
    })
}
