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
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::file::FileKind;
use crate::perm;
use crate::repo::Repo;
use crate::staging::{META_TEMP_PREFIX, TempEntry, open_tmp_dir};
use crate::transaction::Transaction;
use crate::tree::RepoTree;

pub use ostrya_core::commit_metadata;

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

        let timestamp = ostrya_core::commit_timestamp(opts.timestamp)
            .map_err(|e| Error::InvalidFormat(e.to_string()))?;
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
            // A commit composed from several tree sources scopes the key to the
            // objects the last source contributed plus the directory objects the
            // serialization wrote; see
            // [`begin_tree_source`](Transaction::begin_tree_source).
            if !self.in_size_scope(&checksum) {
                continue;
            }
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
    ///
    /// The call takes the repository lock shared and then the update lock, as
    /// [`Repo::begin_update`] does, and writes under both. Each of the two
    /// waits fails with [`Error::LockTimeout`] after `lock-timeout-secs`. A
    /// caller that holds an [`UpdateGuard`](crate::UpdateGuard) of this
    /// repository waits for its own guard until the timeout, and with
    /// `lock-timeout-secs=-1` it waits forever.
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
        let fsync = self.config().fsync()?;
        let repo_mode = self.mode();
        let dest = loose_path(checksum, ObjectType::CommitMeta, repo_mode);
        self.write_locked(move |repo| {
            let tmp_fd = open_tmp_dir(repo.repo_fd(), repo_mode)?;
            write_detached_blocking(
                tmp_fd.as_fd(),
                repo.objects_fd(),
                &dest,
                &bytes,
                fsync,
                repo_mode,
            )
        })
        .await
    }
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

/// Apply one detached-metadata edit at a commit's `.commitmeta` loose path,
/// on the blocking pool.
///
/// `replace` is the dict that stands in for whatever the file holds; with
/// `None` the edit starts from the file's own dict, or from an empty dict
/// where the file is absent or is the zero-length marker. `merge`, where
/// given, is the serialized `a{sv}` dict merged into that dict with a union
/// of each signature list, and the keys whose value stays where that dict
/// holds them. Each entry of `appends` then appends one signature
/// to its engine's `aay` array, in order, and the result replaces the file
/// atomically.
///
/// The read, the merge and the replacing write run as one step under
/// [`DETACHED_MERGE`], for this edit alone, so a caller can apply several
/// edits in one trip to the blocking pool. The caller holds the update lock.
#[allow(clippy::too_many_arguments)]
pub(crate) fn merge_detached_blocking(
    tmp_fd: BorrowedFd<'_>,
    objects_fd: BorrowedFd<'_>,
    checksum: &Checksum,
    replace: Option<Value>,
    merge: Option<(Vec<u8>, Vec<String>)>,
    appends: Vec<(String, Vec<u8>)>,
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<()> {
    let dest = loose_path(checksum, ObjectType::CommitMeta, repo_mode);
    edit_detached_blocking(tmp_fd, objects_fd, &dest, fsync, repo_mode, |read| {
        let base = match replace {
            Some(dict) => Some(dict),
            None => read()?,
        };
        // Only a receiving session queues a merge.
        let mut dict = match merge {
            #[cfg(feature = "receive")]
            Some((incoming, keep)) => match crate::summary::parse_signature_dict(&incoming)? {
                Some(incoming) => crate::receive::merge_detached(base, incoming, &keep)?,
                None => base.unwrap_or_else(|| Value::Array(Vec::new())),
            },
            _ => base.unwrap_or_else(|| Value::Array(Vec::new())),
        };
        for (key, signature) in appends {
            crate::sign::append_signature(&mut dict, &key, signature)?;
        }
        Ok((DetachedWrite::Dict(dict), ()))
    })
}

/// Remove signatures at a commit's `.commitmeta` loose path, on the blocking
/// pool.
///
/// `remove(payload, blob)` decides each blob stored under `metadata_key`,
/// where `payload` is the commit's canonical bytes. The read, the removal and
/// the replacing write run as one step under [`DETACHED_MERGE`], as the edit
/// of [`merge_detached_blocking`] does. Returns the number of blobs removed:
/// zero leaves the file as it stands, and a dict the removal empties is
/// written as the zero-length "no metadata" marker. The caller holds the
/// update lock.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prune_detached_signatures_blocking(
    tmp_fd: BorrowedFd<'_>,
    objects_fd: BorrowedFd<'_>,
    checksum: &Checksum,
    metadata_key: &str,
    payload: &[u8],
    remove: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<usize> {
    let dest = loose_path(checksum, ObjectType::CommitMeta, repo_mode);
    edit_detached_blocking(tmp_fd, objects_fd, &dest, fsync, repo_mode, |read| {
        let Some(mut dict) = read()? else {
            return Ok((DetachedWrite::Keep, 0));
        };
        let removed = crate::sign::remove_signatures(&mut dict, metadata_key, payload, remove)?;
        if removed == 0 {
            return Ok((DetachedWrite::Keep, 0));
        }
        let empty = matches!(&dict, Value::Array(entries) if entries.is_empty());
        let write = if empty {
            DetachedWrite::Marker
        } else {
            DetachedWrite::Dict(dict)
        };
        Ok((write, removed))
    })
}

/// Write the bytes of a commit's detached metadata to the file `name` in a
/// transaction's staging directory, for
/// [`install_detached_blocking`] to move into `objects/` at the commit. The
/// file takes the `0644` of every metadata object. A file already at `name`
/// is replaced. The call syncs nothing: the commit makes the file durable
/// before the install.
pub(crate) fn stage_detached_blocking(
    staging_fd: BorrowedFd<'_>,
    name: &str,
    bytes: &[u8],
) -> Result<()> {
    use std::io::Write;

    let fd = rustix::fs::openat(
        staging_fd,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(COMMITMETA_MODE),
    )?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes)?;
    file.flush()?;
    rustix::fs::fchmod(file.as_fd(), Mode::from_raw_mode(COMMITMETA_MODE))?;
    Ok(())
}

/// Rename each file of a transaction's staging directory in `staged` over
/// the `.commitmeta` loose path of its commit, under [`DETACHED_MERGE`]. Each
/// fanout directory is created on demand as [`write_detached_blocking`]
/// creates it. With fsync on, after the last rename each fanout directory
/// that gained a file is `fsync`-ed once, and `objects/` is `fsync`-ed once
/// when a fanout directory was newly created. The caller holds the update
/// lock, and with fsync on the staged files are durable before the call.
pub(crate) fn install_detached_blocking(
    staging_fd: BorrowedFd<'_>,
    staged: &[(&Checksum, &str)],
    objects_fd: BorrowedFd<'_>,
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<()> {
    let _guard = DETACHED_MERGE.lock().unwrap_or_else(|err| err.into_inner());
    // Each fanout directory that gained a file, and whether this call
    // created it.
    let mut fanouts = std::collections::BTreeMap::<String, bool>::new();
    for (checksum, name) in staged {
        let dest = loose_path(checksum, ObjectType::CommitMeta, repo_mode);
        let fanout = &dest[..2];
        let created = create_fanout(objects_fd, fanout, repo_mode)?;
        rustix::fs::renameat(staging_fd, *name, objects_fd, dest.as_str())?;
        *fanouts.entry(fanout.to_owned()).or_default() |= created;
    }
    if fsync {
        for fanout in fanouts.keys() {
            sync_fanout(objects_fd, fanout, false)?;
        }
        if fanouts.values().any(|&created| created) {
            rustix::fs::fsync(objects_fd)?;
        }
    }
    Ok(())
}

/// Serializes the read-modify-write cycle behind
/// [`edit_detached_blocking`], and the install of a staged file, across the
/// whole process. The section holds one small read, one serialize and one
/// atomic rename, and it holds no await, so it cannot block a task. Every
/// edit of a `.commitmeta` also runs under the update lock, which excludes
/// other processes and the other writers of this process, so two processes
/// that sign one commit at the same time keep both signatures. The mutex
/// guards only a caller of this process that edits without the update lock.
static DETACHED_MERGE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// What one guarded edit leaves at a `.commitmeta` loose path.
enum DetachedWrite {
    /// Replace the file with this `a{sv}` dict's bytes.
    Dict(Value),
    /// Replace the file with the zero-length "no metadata" marker.
    Marker,
    /// Leave the file as it stands.
    Keep,
}

/// Run one read-modify-write of a `.commitmeta` loose path under
/// [`DETACHED_MERGE`].
///
/// `edit` receives a reader for the stored dict -- the `a{sv}` the file holds,
/// or `None` where the file is absent or is the zero-length marker -- and
/// returns what to leave at the path together with the value the caller wants
/// back. The reader, `edit` and the write all run inside the guard, so no other
/// edit of this process lands between them.
fn edit_detached_blocking<T>(
    tmp_fd: BorrowedFd<'_>,
    objects_fd: BorrowedFd<'_>,
    dest: &str,
    fsync: bool,
    repo_mode: RepoMode,
    edit: impl FnOnce(&dyn Fn() -> Result<Option<Value>>) -> Result<(DetachedWrite, T)>,
) -> Result<T> {
    let ty = Type::parse(METADATA_SIGNATURE).map_err(ostrya_core::Error::from)?;
    let _guard = DETACHED_MERGE.lock().unwrap_or_else(|err| err.into_inner());
    let (write, value) = edit(&|| read_detached_blocking(objects_fd, dest, &ty))?;
    match write {
        DetachedWrite::Dict(dict) => {
            let bytes = to_bytes(&ty, &dict).map_err(ostrya_core::Error::from)?;
            write_detached_blocking(tmp_fd, objects_fd, dest, &bytes, fsync, repo_mode)?;
        }
        DetachedWrite::Marker => {
            write_detached_blocking(tmp_fd, objects_fd, dest, &[], fsync, repo_mode)?
        }
        DetachedWrite::Keep => {}
    }
    Ok(value)
}

/// Read the `a{sv}` dict at a `.commitmeta` loose path, or `None` where the
/// file is absent or is the zero-length "no metadata" marker.
fn read_detached_blocking(
    objects_fd: BorrowedFd<'_>,
    dest: &str,
    ty: &Type,
) -> Result<Option<Value>> {
    let bytes =
        match crate::object::read_meta_object(objects_fd, dest, crate::object::MAX_METADATA_SIZE) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(Error::Io(err)),
        };
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        ostrya_core::from_bytes(ty, &bytes).map_err(ostrya_core::Error::from)?,
    ))
}

/// Write metadata bytes to a loose path atomically. The detached-metadata
/// writers reach it for a `.commitmeta`, and the prune sweep reaches it for a
/// `.tombstone-commit`; both objects carry the `0644` every metadata object
/// carries. `tmp_fd` is the open `tmp/` of the repository. The fanout
/// directory is created on demand (`0777` reduced by the umask, and forced to
/// [`perm::SHARED_DIR_MODE`] where this call creates it in a
/// `bare-user-shared` repository), the bytes go to a temp file in `tmp/`
/// (`fchmod` 0644, `fdatasync` when fsync is on), and the temp is renamed over
/// the target. A `tmp/` on another filesystem makes the rename fail with
/// `EXDEV`, and the temp is removed. When fsync is on, the fanout directory is
/// fsynced after the rename so the new name survives a crash, and `objects/` is
/// fsynced too when the fanout directory was newly created, matching the
/// durability the object publication path honors.
pub(crate) fn write_detached_blocking(
    tmp_fd: BorrowedFd<'_>,
    objects_fd: BorrowedFd<'_>,
    dest: &str,
    bytes: &[u8],
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<()> {
    use std::io::Write;

    let fanout = &dest[..2];
    let fanout_created = create_fanout(objects_fd, fanout, repo_mode)?;

    let (temp, fd) = TempEntry::create_file(tmp_fd, META_TEMP_PREFIX, COMMITMETA_MODE)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes)?;
    file.flush()?;
    rustix::fs::fchmod(file.as_fd(), Mode::from_raw_mode(COMMITMETA_MODE))?;
    if fsync {
        rustix::fs::fdatasync(file.as_fd())?;
    }
    drop(file);
    temp.rename_into(objects_fd, dest)?;
    if fsync {
        sync_fanout(objects_fd, fanout, fanout_created)?;
    }
    Ok(())
}

/// Create the fanout directory `fanout` under `objects/` where it is absent
/// (`0777` reduced by the umask, and forced to [`perm::SHARED_DIR_MODE`] in a
/// `bare-user-shared` repository), and return whether this call created it.
fn create_fanout(objects_fd: BorrowedFd<'_>, fanout: &str, repo_mode: RepoMode) -> Result<bool> {
    match rustix::fs::mkdirat(objects_fd, fanout, Mode::from_raw_mode(0o777)) {
        Ok(()) => {
            perm::force_created_dir(objects_fd, fanout, repo_mode)?;
            Ok(true)
        }
        Err(Errno::EXIST) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Make a directory entry renamed into `fanout` durable: `fsync` the fanout
/// directory, and `objects/` too when `created` says the fanout was newly
/// created.
fn sync_fanout(objects_fd: BorrowedFd<'_>, fanout: &str, created: bool) -> Result<()> {
    let dir = rustix::fs::openat(
        objects_fd,
        fanout,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    rustix::fs::fsync(&dir)?;
    if created {
        rustix::fs::fsync(objects_fd)?;
    }
    Ok(())
}
