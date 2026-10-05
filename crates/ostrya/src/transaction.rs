//! Owned transaction handles.
//!
//! A [`Transaction`] is created from a [`Repo`] and owns the
//! repository lock hold and a staging directory for its duration. Multiple
//! transactions may exist at once in one process, each with its own staging
//! directory; the shared repository lock coordinates them and excludes other
//! processes, and the `ostree` tool, per the configured lock kind.
//!
//! A transaction ingests objects into its staging directory through the write
//! methods (in `crate::write`) and publishes them into `objects/` at
//! [`commit`](Transaction::commit). Object identity, dedup, free-space
//! accounting, and the archive size map live in the shared staged state behind
//! a mutex, so concurrent writers may share a `&Transaction`. Dropping a
//! transaction without committing reaps the staging directory (discarding every
//! staged object) and releases the lock.

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use ostrya_core::{Checksum, ObjectType, RepoMode, Value};

use crate::config::Tristate;
use crate::error::{Error, Result};
use crate::lock::{LockGuard, UpdateLockHeld};
use crate::repo::Repo;
use crate::staging::StagingDir;
use crate::write::{
    Blocks, StageCtx, StageOutcome, TempKind, probe_fresh_owner, publish_blocking,
    stage_clone_content_blocking, stage_content_blocking, stage_import_blocking,
    stage_metadata_blocking, stage_symlink_blocking,
};

pub use crate::write::{ContentWriter, FileMeta};

/// Statistics accumulated over a transaction, returned by
/// [`commit`](Transaction::commit).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransactionStats {
    /// Metadata objects the transaction offered for staging (dirtree, dirmeta,
    /// commit, and the like), counted before dedup. One directory's dirmeta is
    /// counted once per directory, so a tree whose directories share one dirmeta
    /// counts it once for each of them.
    pub metadata_total: u32,
    /// Metadata objects freshly staged (dirtree, dirmeta, commit, and the
    /// like). A dedup hit does not count.
    pub metadata_written: u32,
    /// Content objects the transaction offered for staging, counted before
    /// dedup. A content object a [`DevInoCache`](crate::DevInoCache) hit
    /// resolved is never offered, so it does not count here.
    pub content_total: u32,
    /// Content objects freshly staged. A dedup hit does not count.
    pub content_written: u32,
    /// The total on-disk size of the freshly staged content objects. An object
    /// imported from another repository counts its size whether its bytes were
    /// written, shared by reflink, or shared by hardlink, so this is the storage
    /// the objects occupy and not the space the transaction consumed.
    pub content_bytes_written: u64,
    /// The total payload size of the freshly staged regular-file content
    /// objects, before any compression the repository mode applies. A symlink
    /// contributes nothing, and an object hardlinked from another repository
    /// contributes nothing, its payload never being read; an object whose
    /// payload was cloned contributes that payload's length. An object a
    /// static delta produced contributes nothing, which is what the tool
    /// reports for a pull.
    pub content_bytes_unpacked: u64,
    /// Content objects skipped because their (device, inode) was already known
    /// through a [`DevInoCache`](crate::DevInoCache) hit during a filesystem
    /// ingest.
    pub devino_cache_hits: u32,
    /// Entries a commit-modifier filter excluded during a filesystem ingest.
    pub filtered: u32,
}

/// One object staged in a transaction, awaiting publication.
struct StagedObject {
    /// The flat name the object holds in the staging directory.
    staging_name: String,
    /// The loose path under `objects/` the object publishes to.
    dest: String,
}

/// The archive size record for one staged object, the input for `ostree.sizes`
/// emission in [`write_commit`](crate::Transaction::write_commit). The tool's
/// `ostree.sizes` covers every object in the commit -- content and metadata
/// alike -- so a record is kept per object type, not only for content.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SizeRecord {
    /// The on-disk size: the `.filez` storage size for archive content, the
    /// serialized byte length for a metadata object.
    pub(crate) compressed: u64,
    /// The logical (unpacked) size: a file's payload length, a symlink's
    /// target length, or a metadata object's byte length.
    pub(crate) unpacked: u64,
    /// The object type, written as the trailing `ostree.sizes` entry byte.
    pub(crate) objtype: ObjectType,
}

/// The mutable state shared by concurrent writers on one transaction.
struct Staged {
    /// Objects staged so far, keyed by identity and type for in-transaction
    /// dedup and for publication at commit.
    objects: HashMap<(Checksum, ObjectType), StagedObject>,
    /// Per-object size records (archive mode), keyed by checksum. Covers
    /// content and metadata objects, the input for `ostree.sizes`.
    sizes: HashMap<Checksum, SizeRecord>,
    /// Which objects `ostree.sizes` covers, where a caller scopes the key by
    /// tree source (see [`begin_tree_source`](Transaction::begin_tree_source)).
    /// `None` leaves the key covering every object the commit reaches.
    size_scope: Option<HashMap<Checksum, ObjectType>>,
    /// Remaining write budget in bytes before the configured free-space reserve
    /// is breached.
    free_budget: u64,
    /// Accumulated statistics.
    stats: TransactionStats,
    /// The number of staged objects that are durable before publication: the
    /// objects the last [`sync_staged`](Transaction::sync_staged) made durable,
    /// and each metadata object synced on its own after it. The publication
    /// step skips its `syncfs` while this equals the number of staged objects,
    /// so another object staged after the sync gets the `syncfs` it needs.
    presynced: Option<usize>,
}

/// One commit's queued detached-metadata edit.
///
/// The edit is held as a plan rather than as a finished dict, so the read of
/// what the repository already stores happens once, at the write, under the
/// guard that serializes it. `staged` names the file a pull staged in place of
/// the stored one; `replace` is the dict
/// [`set_commit_detached_metadata`](Transaction::set_commit_detached_metadata)
/// put in place of the stored one; `merge` is the dict a receiving session
/// merges into it, with the keys whose stored value stays; `appends` are the
/// signatures
/// [`sign_commit`](Transaction::sign_commit) produced after it, in call order.
#[derive(Default)]
struct DetachedEdit {
    /// The file in the staging directory whose bytes replace whatever the
    /// repository stores, when a pull staged one. The write installs it
    /// first, and the other parts of the edit then apply to it.
    staged: Option<String>,
    /// The dict that replaces whatever the repository stores, when a caller
    /// queued one. `None` starts the edit from the stored dict.
    replace: Option<Value>,
    /// The serialized `a{sv}` dict merged into the dict the edit starts
    /// from, before the appends, and the keys whose stored value stays: each
    /// signature list gets the union of the two lists, a key of the list
    /// that the dict the edit starts from holds keeps its value, and each
    /// other key takes the value of this dict.
    merge: Option<(Vec<u8>, Vec<String>)>,
    /// Signatures to append, each an engine metadata key and one signature.
    appends: Vec<(String, Vec<u8>)>,
}

/// The queued detached-metadata edits of a transaction, one per commit in the
/// order of the first edit of each, with an index from each commit to the
/// position of its edit.
#[derive(Default)]
struct DetachedQueue {
    edits: Vec<(Checksum, DetachedEdit)>,
    index: HashMap<Checksum, usize>,
}

/// An owned transaction over a repository.
///
/// The handle carries its repository lock hold, staging directory, and the
/// shared staged state. `&Transaction` is `Send + Sync`: concurrent writers may
/// stage objects through one shared reference. Dropping it without
/// [`commit`](Transaction::commit) or [`abort`](Transaction::abort) reaps the
/// staging directory and releases the lock, so an abandoned transaction leaves
/// nothing behind.
pub struct Transaction {
    repo: Repo,
    /// A per-transaction replacement for the repository config's `[core] fsync`
    /// setting, from [`set_fsync`](Transaction::set_fsync). `None` leaves the
    /// config in charge.
    fsync_override: Option<bool>,
    /// A per-transaction replacement for the repository config's
    /// `[core] per-object-fsync` setting, from
    /// [`set_per_object_fsync`](Transaction::set_per_object_fsync). `None`
    /// leaves the config in charge.
    per_object_fsync_override: Option<bool>,
    /// Set by a filesystem ingest under
    /// [`GENERATE_SIZES`](crate::CommitModifierFlags::GENERATE_SIZES). Read by
    /// commit assembly (Phase 7d) to decide whether to emit `ostree.sizes`.
    generate_sizes: AtomicBool,
    /// A caller's answer for the whole transaction, from
    /// [`set_generate_sizes`](Transaction::set_generate_sizes). It wins over
    /// `generate_sizes` in both directions; `None` leaves the ingest in charge.
    generate_sizes_override: Option<bool>,
    // Dropped in declaration order: the staged state and staging directory are
    // released, then the lock.
    staged: Mutex<Staged>,
    /// Refspec-to-checksum writes queued by [`set_ref`](Transaction::set_ref)
    /// and applied at [`commit`](Transaction::commit), after object
    /// publication, per the durability contract.
    pub(crate) refs: Mutex<Vec<crate::refs::RefWrite>>,
    /// Detached-metadata edits queued by
    /// [`set_commit_detached_metadata`](Transaction::set_commit_detached_metadata)
    /// and by [`sign_commit`](Transaction::sign_commit), applied at
    /// [`commit`](Transaction::commit) after object publication and before the
    /// queued ref writes, so a commit a ref names carries its signatures.
    detached: Mutex<DetachedQueue>,
    /// The uid and gid an object freshly staged in this transaction takes,
    /// measured once on first use by [`fresh_owner`](Transaction::fresh_owner).
    fresh_owner: OnceLock<(u32, u32)>,
    staging: Option<StagingDir>,
    /// The repository lock hold, kept for the transaction's lifetime and
    /// released when this field drops. A commit that writes a ref or detached
    /// metadata moves it into the blocking closure of that write.
    lock: LockGuard,
}

impl Transaction {
    /// Assemble a transaction from a repository handle, an acquired lock, a
    /// staging directory, and the initial free-space budget.
    pub(crate) fn new(
        repo: Repo,
        lock: LockGuard,
        staging: StagingDir,
        free_budget: u64,
    ) -> Transaction {
        Transaction {
            repo,
            fsync_override: None,
            per_object_fsync_override: None,
            generate_sizes: AtomicBool::new(false),
            generate_sizes_override: None,
            staged: Mutex::new(Staged {
                objects: HashMap::new(),
                sizes: HashMap::new(),
                size_scope: None,
                free_budget,
                stats: TransactionStats::default(),
                presynced: None,
            }),
            refs: Mutex::new(Vec::new()),
            detached: Mutex::new(DetachedQueue::default()),
            fresh_owner: OnceLock::new(),
            staging: Some(staging),
            lock,
        }
    }

    /// Replace the repository config's `[core] fsync` setting for this
    /// transaction alone, for the whole of it: the per-object writes, the
    /// publication step, and the ref writes all read it. The setting changes the
    /// durability of the writes and no byte the repository stores.
    pub fn set_fsync(&mut self, enabled: bool) {
        self.fsync_override = Some(enabled);
    }

    /// Replace the repository config's `[core] per-object-fsync` setting for
    /// this transaction alone. With the setting on, the file of each content
    /// object is synced as it is staged, before publication. A metadata object
    /// is never synced on its own, and an object imported by hardlink is not
    /// synced. The setting has no effect while fsync is off, from the config or
    /// from [`set_fsync`](Transaction::set_fsync). It changes the durability of
    /// the writes and no byte the repository stores.
    pub fn set_per_object_fsync(&mut self, enabled: bool) {
        self.per_object_fsync_override = Some(enabled);
    }

    /// Settle whether this transaction emits `ostree.sizes` in every commit it
    /// writes, the way a filesystem ingest under
    /// [`GENERATE_SIZES`](crate::CommitModifierFlags::GENERATE_SIZES) does. The
    /// request serves an ingest that runs no commit modifier, the tar import
    /// among them. The answer given here holds for the whole transaction and
    /// wins over the flag any ingest sets, so `false` turns the key off again.
    /// Outside archive mode the request is a silent no-op, since no other mode
    /// writes the key.
    pub fn set_generate_sizes(&mut self, enabled: bool) {
        self.generate_sizes_override = Some(enabled);
    }

    /// The repository this transaction writes to.
    pub(crate) fn repo(&self) -> &Repo {
        &self.repo
    }

    /// The staging directory descriptor objects are ingested into.
    pub(crate) fn staging_fd(&self) -> BorrowedFd<'_> {
        self.staging
            .as_ref()
            .expect("staging directory present during the transaction")
            .dir_fd()
    }

    /// The uid and gid an object freshly staged in this transaction takes,
    /// measured on first use and held for the transaction's lifetime. Read by the
    /// import path, which admits a hardlink only where the source inode's
    /// ownership is already this pair. Two callers racing the first read measure
    /// the same directory and one of the two results is kept.
    pub(crate) async fn fresh_owner(&self) -> Result<(u32, u32)> {
        if let Some(owner) = self.fresh_owner.get() {
            return Ok(*owner);
        }
        let staging = self.staging_fd().try_clone_to_owned()?;
        let owner = ostrya_rt::unblock(move || probe_fresh_owner(staging.as_fd())).await?;
        Ok(*self.fresh_owner.get_or_init(|| owner))
    }

    /// Mark that this transaction should emit `ostree.sizes` at commit. Set by
    /// a filesystem ingest under
    /// [`GENERATE_SIZES`](crate::CommitModifierFlags::GENERATE_SIZES).
    pub(crate) fn mark_generate_sizes(&self) {
        self.generate_sizes.store(true, Ordering::Relaxed);
    }

    /// Whether size generation was requested: the caller's answer where
    /// [`set_generate_sizes`](Transaction::set_generate_sizes) gave one, and
    /// the ingest flag otherwise. Read by
    /// [`write_commit`](Transaction::write_commit) to decide whether to emit
    /// `ostree.sizes`.
    pub(crate) fn generate_sizes(&self) -> bool {
        self.generate_sizes_override
            .unwrap_or_else(|| self.generate_sizes.load(Ordering::Relaxed))
    }

    /// Open a new tree source for `ostree.sizes` accounting.
    ///
    /// The tool scopes the key to the objects the last tree source contributed,
    /// together with the directory objects the tree serialization writes: a
    /// content object an earlier source contributed leaves the key, while a
    /// directory object stays. A caller that composes a commit from several
    /// sources calls this before each of them, so the key it writes is the one
    /// the tool writes; a caller that never calls it leaves the key covering
    /// every object the commit reaches.
    ///
    /// A `--base` layer is applied before the first call, so it contributes
    /// nothing to the key, which is what the tool records.
    pub fn begin_tree_source(&self) {
        let mut staged = self.staged.lock().unwrap();
        let scope = staged.size_scope.get_or_insert_with(HashMap::new);
        scope.retain(|_, ty| *ty != ObjectType::File);
    }

    /// Record one object in the `ostree.sizes` scope, when a scope is in force.
    /// `true` where the object was not already in it.
    pub(crate) fn note_size_scope(&self, checksum: Checksum, ty: ObjectType) -> bool {
        let mut staged = self.staged.lock().unwrap();
        match &mut staged.size_scope {
            Some(scope) => scope.insert(checksum, ty).is_none(),
            None => false,
        }
    }

    /// Whether a size scope is in force.
    pub(crate) fn size_scoped(&self) -> bool {
        self.staged.lock().unwrap().size_scope.is_some()
    }

    /// Whether `checksum` is inside the `ostree.sizes` scope. Every object is,
    /// where no scope is in force.
    pub(crate) fn in_size_scope(&self, checksum: &Checksum) -> bool {
        match &self.staged.lock().unwrap().size_scope {
            Some(scope) => scope.contains_key(checksum),
            None => true,
        }
    }

    /// Snapshot the archive size records for the objects freshly staged so far,
    /// as `ostree.sizes` entries. Read by
    /// [`write_commit`](Transaction::write_commit) before it stages the commit
    /// object, so the commit's own size is never among them; `write_commit`
    /// looks each reachable object up in this snapshot and recovers the sizes of
    /// any it does not find (an object that deduplicated against `objects/`)
    /// from disk, so a multi-commit transaction gives each commit its own
    /// reachable-scoped key.
    pub(crate) fn size_entries(&self) -> Vec<ostrya_core::sizes::SizeEntry> {
        let staged = self.staged.lock().unwrap();
        staged
            .sizes
            .iter()
            .map(|(checksum, rec)| ostrya_core::sizes::SizeEntry {
                checksum: *checksum,
                compressed: rec.compressed,
                unpacked: rec.unpacked,
                objtype: Some(rec.objtype),
            })
            .collect()
    }

    /// Count one content object skipped through a devino-cache hit.
    pub(crate) fn note_devino_hit(&self) {
        self.staged.lock().unwrap().stats.devino_cache_hits += 1;
    }

    /// Count one entry excluded by a commit-modifier filter.
    pub(crate) fn note_filtered(&self) {
        self.staged.lock().unwrap().stats.filtered += 1;
    }

    /// Whether an object of the given identity and type is staged in this
    /// transaction (present in the staging directory, not yet published into
    /// `objects/`).
    pub(crate) fn is_staged(&self, checksum: &Checksum, ty: ObjectType) -> bool {
        self.staged
            .lock()
            .unwrap()
            .objects
            .contains_key(&(*checksum, ty))
    }

    /// The checksums of the objects of type `ty` staged in this transaction.
    #[cfg(feature = "receive")]
    pub(crate) fn staged_of_type(&self, ty: ObjectType) -> Vec<Checksum> {
        self.staged
            .lock()
            .unwrap()
            .objects
            .keys()
            .filter(|(_, t)| *t == ty)
            .map(|(checksum, _)| *checksum)
            .collect()
    }

    /// Load a file object, checking this transaction's staged set before the
    /// repository's `objects/`. Used by the staging-tree read and merge paths so
    /// content staged in the current transaction is visible before it publishes.
    pub(crate) async fn load_file_staged_first(
        &self,
        checksum: &Checksum,
    ) -> Result<crate::file::FileObject> {
        self.load_file_staged_first_with(checksum, false).await
    }

    /// [`load_file_staged_first`], with the `measure` flag of
    /// [`Repo::load_file_with`].
    ///
    /// [`load_file_staged_first`]: Transaction::load_file_staged_first
    pub(crate) async fn load_file_staged_first_with(
        &self,
        checksum: &Checksum,
        measure: bool,
    ) -> Result<crate::file::FileObject> {
        if self.is_staged(checksum, ObjectType::File) {
            crate::file::load_staged_file(&self.repo, self.staging_fd(), checksum, measure).await
        } else {
            self.repo.load_file_with(checksum, measure).await
        }
    }

    /// Load a dirtree object, checking this transaction's staged set before the
    /// repository's `objects/`. Mirrors [`load_file_staged_first`] for the
    /// merge path's right side, so a dirtree staged in the current transaction
    /// is visible before it publishes.
    ///
    /// [`load_file_staged_first`]: Transaction::load_file_staged_first
    pub(crate) async fn load_dirtree_staged_first(
        &self,
        checksum: &Checksum,
    ) -> Result<ostrya_core::DirTree> {
        if self.is_staged(checksum, ObjectType::DirTree) {
            let name = crate::write::flat_name(checksum, ObjectType::DirTree, self.repo.mode());
            let staging = self.staging_fd().try_clone_to_owned()?;
            let bytes = ostrya_rt::unblock(move || {
                crate::object::read_meta_object(
                    staging.as_fd(),
                    &name,
                    crate::object::MAX_METADATA_SIZE,
                )
            })
            .await
            .map_err(Error::Io)?;
            Ok(ostrya_core::DirTree::parse(&bytes)?)
        } else {
            self.repo.load_dirtree(checksum).await
        }
    }

    /// Load a dirmeta object, checking this transaction's staged set before the
    /// repository's `objects/`. Mirrors
    /// [`load_dirtree_staged_first`](Self::load_dirtree_staged_first) for the
    /// directory metadata a staged tree carries.
    pub(crate) async fn load_dirmeta_staged_first(
        &self,
        checksum: &Checksum,
    ) -> Result<ostrya_core::DirMeta> {
        if self.is_staged(checksum, ObjectType::DirMeta) {
            let name = crate::write::flat_name(checksum, ObjectType::DirMeta, self.repo.mode());
            let staging = self.staging_fd().try_clone_to_owned()?;
            let bytes = ostrya_rt::unblock(move || {
                crate::object::read_meta_object(
                    staging.as_fd(),
                    &name,
                    crate::object::MAX_METADATA_SIZE,
                )
            })
            .await
            .map_err(Error::Io)?;
            Ok(ostrya_core::DirMeta::parse(&bytes)?)
        } else {
            self.repo.load_dirmeta(checksum).await
        }
    }

    /// List one directory of a tree this transaction assembled, reading the
    /// objects it staged before the repository's `objects/`.
    ///
    /// [`RepoTree::read_dir`](crate::RepoTree::read_dir) reads `objects/`
    /// alone, so it sees a tree only once the transaction has committed. This
    /// reads the same listing -- files first, then subdirectories, each group
    /// name-sorted -- over a tree that is still staged, which is what a caller
    /// deriving commit metadata from the tree it is about to commit needs. Each
    /// [`TreeEntry::Dir`](crate::TreeEntry::Dir) it returns is read back the
    /// same way: passing one to `RepoTree::read_dir` before the transaction
    /// commits reaches [`Error::ObjectNotFound`]
    /// for the subtree's dirtree.
    pub async fn read_dir(&self, tree: &crate::RepoTree) -> Result<Vec<crate::TreeEntry>> {
        let dirtree = self
            .load_dirtree_staged_first(tree.dirtree_checksum())
            .await?;
        let mut entries = Vec::with_capacity(dirtree.files.len() + dirtree.dirs.len());
        for (name, checksum) in dirtree.files {
            entries.push(crate::TreeEntry::File { name, checksum });
        }
        for (name, subtree, submeta) in dirtree.dirs {
            entries.push(crate::TreeEntry::Dir {
                name,
                tree: crate::RepoTree::from_parts(self.repo.clone(), subtree, submeta),
            });
        }
        Ok(entries)
    }

    /// Queue the detached metadata of a commit this transaction writes.
    ///
    /// `meta` is an `a{sv}` dict, and it replaces whatever the repository
    /// already stores for `checksum`. The write happens at
    /// [`commit`](Transaction::commit), after the staged objects publish and
    /// before the queued refs are written, so a commit is durable together with
    /// its detached metadata and both are durable before a ref names them.
    /// Queueing twice for one checksum keeps the last dict, and it drops the
    /// signatures [`sign_commit`](Transaction::sign_commit) queued before it.
    pub fn set_commit_detached_metadata(&self, checksum: &Checksum, meta: Value) {
        let mut queue = self.detached.lock().unwrap();
        let edit = Self::edit_for(&mut queue, checksum);
        edit.staged = None;
        edit.replace = Some(meta);
        edit.merge = None;
        edit.appends.clear();
    }

    /// Stage `bytes`, the serialized detached metadata of `checksum`, in
    /// place of whatever the repository stores. A pull copies a source's
    /// `.commitmeta` verbatim through this call.
    ///
    /// The bytes go to a file in the staging directory at once, so the queue
    /// holds no copy of them. At [`commit`](Transaction::commit) the write
    /// renames the file over the `.commitmeta` of `checksum`, after the staged
    /// objects publish and before the queued refs are written. With fsync on,
    /// the file is durable before the rename: the `syncfs` of the publication
    /// step covers it, and where that step runs no `syncfs` the write runs
    /// one of its own. A transaction that does not
    /// commit leaves the stored file as it stands. Staging again for one
    /// checksum replaces the file, and like
    /// [`set_commit_detached_metadata`](Transaction::set_commit_detached_metadata)
    /// the call drops the edits queued for `checksum` before it.
    pub(crate) async fn stage_commit_detached_bytes(
        &self,
        checksum: &Checksum,
        bytes: Vec<u8>,
    ) -> Result<()> {
        let name = crate::write::flat_name(checksum, ObjectType::CommitMeta, self.repo.mode());
        let staging = self.staging_fd().try_clone_to_owned()?;
        let staged = name.clone();
        ostrya_rt::unblock(move || {
            crate::commit::stage_detached_blocking(staging.as_fd(), &staged, &bytes)
        })
        .await?;
        let mut queue = self.detached.lock().unwrap();
        let edit = Self::edit_for(&mut queue, checksum);
        edit.staged = Some(name);
        edit.replace = None;
        edit.merge = None;
        edit.appends.clear();
        Ok(())
    }

    /// Queue a merge of `incoming`, the bytes of an `a{sv}` dict, into the
    /// detached metadata of `checksum`.
    ///
    /// At [`commit`](Transaction::commit) the write reads the stored dict,
    /// parses `incoming`, and merges it into the stored dict under the guard
    /// the whole process shares for
    /// detached-metadata edits: each signature list gets the union of the
    /// stored and the incoming list, a key of `keep` that the stored dict
    /// holds keeps the stored value, and each other key takes the incoming
    /// value. The signatures
    /// [`append_signature`](Transaction::append_signature) queues follow the
    /// merge. Queueing twice for one checksum keeps the last dict and its
    /// `keep`.
    #[cfg(feature = "receive")]
    pub(crate) fn merge_commit_detached(
        &self,
        checksum: &Checksum,
        incoming: Vec<u8>,
        keep: Vec<String>,
    ) {
        let mut queue = self.detached.lock().unwrap();
        Self::edit_for(&mut queue, checksum).merge = Some((incoming, keep));
    }

    /// Queue `signature`, a signature made before this call, for the engine
    /// metadata key `key` of the detached metadata of `checksum`. The write at
    /// [`commit`](Transaction::commit) appends it as
    /// [`sign_commit`](Transaction::sign_commit) appends the signature it
    /// makes.
    #[cfg(feature = "receive")]
    pub(crate) fn append_signature(&self, checksum: &Checksum, key: &str, signature: Vec<u8>) {
        let mut queue = self.detached.lock().unwrap();
        Self::edit_for(&mut queue, checksum)
            .appends
            .push((key.to_owned(), signature));
    }

    /// Sign a commit this transaction wrote, appending the signature to the
    /// commit's queued detached metadata.
    ///
    /// The payload is the commit object's canonical bytes, read from the
    /// staging directory when the object is staged and from `objects/` when it
    /// deduplicated. The signature appends to the engine's `aay` array in the
    /// dict
    /// [`set_commit_detached_metadata`](Transaction::set_commit_detached_metadata)
    /// queued, else in the dict the repository stores at the moment of the
    /// write, else in an empty one.
    ///
    /// The queueing takes one lock and holds no await. The signature is made
    /// here, before any lock of the commit. The write at `commit` reads,
    /// merges and replaces the file under the update lock, so signatures that
    /// several tasks or processes produce for one commit all reach it -- from
    /// one transaction, from concurrent transactions, and from
    /// [`Repo::sign_commit`](crate::Repo::sign_commit) alike. The `ostree`
    /// tool can lose a signature in that case.
    ///
    /// Nothing reaches the filesystem here: the whole signing step precedes
    /// object publication and the ref writes, so a signature that cannot be
    /// produced fails the transaction with no object published and no ref
    /// moved.
    pub async fn sign_commit(&self, checksum: &Checksum, signer: &dyn crate::Signer) -> Result<()> {
        let payload = self.load_commit_bytes_staged_first(checksum).await?;
        let signature = signer.sign(&payload).await?;
        let mut queue = self.detached.lock().unwrap();
        Self::edit_for(&mut queue, checksum)
            .appends
            .push((signer.metadata_key().to_owned(), signature));
        Ok(())
    }

    /// The queued edit for `checksum`, added empty when the queue holds none.
    fn edit_for<'a>(queue: &'a mut DetachedQueue, checksum: &Checksum) -> &'a mut DetachedEdit {
        let edits = &mut queue.edits;
        let index = *queue.index.entry(*checksum).or_insert_with(|| {
            edits.push((*checksum, DetachedEdit::default()));
            edits.len() - 1
        });
        &mut edits[index].1
    }

    /// Load a commit object's canonical bytes, checking this transaction's
    /// staged set before the repository's `objects/`, the way the other
    /// staged-first readers do.
    pub(crate) async fn load_commit_bytes_staged_first(
        &self,
        checksum: &Checksum,
    ) -> Result<Vec<u8>> {
        if !self.is_staged(checksum, ObjectType::Commit) {
            return self
                .repo
                .load_object_bytes(ObjectType::Commit, checksum)
                .await;
        }
        let name = crate::write::flat_name(checksum, ObjectType::Commit, self.repo.mode());
        let staging = self.staging_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || {
            crate::object::read_meta_object(
                staging.as_fd(),
                &name,
                crate::object::MAX_METADATA_SIZE,
            )
        })
        .await
        .map_err(Error::Io)
    }

    /// Take the queued detached-metadata edits, for
    /// [`DetachedJob::run`] to apply between publication and the ref writes,
    /// under the transaction's own fsync policy.
    ///
    /// `synced` tells whether the publication step ran its `syncfs`, which
    /// makes the staged files durable too.
    fn detached_job(&self, synced: bool) -> Result<DetachedJob> {
        let queued = std::mem::take(&mut self.detached.lock().unwrap().edits);
        let (fsync, _) = self.fsync_flags()?;
        Ok(DetachedJob {
            queued,
            fsync,
            staged_durable: synced,
            repo_mode: self.repo.mode(),
            objects_fd: self.repo.objects_fd().try_clone_to_owned()?,
            staging_fd: self.staging_fd().try_clone_to_owned()?,
        })
    }

    /// Stage a regular-file content object whose payload is already written to
    /// `file`. Called by [`ContentWriter::finish`](crate::ContentWriter::finish).
    /// `counted` chooses whether the payload adds to
    /// [`content_bytes_unpacked`](TransactionStats::content_bytes_unpacked).
    pub(crate) async fn stage_regular(
        &self,
        checksum: Checksum,
        header: ostrya_core::FileHeader,
        file: std::fs::File,
        temp: TempKind,
        unpacked: u64,
        counted: bool,
    ) -> Result<Checksum> {
        let mode = self.repo.mode();
        let (fsync, per_object_fsync) = self.fsync_flags()?;
        let verity = self.verity()?;
        let objects = self.repo.objects_fd().try_clone_to_owned()?;
        let staging = self.staging_fd().try_clone_to_owned()?;
        let key = checksum;
        let outcome = ostrya_rt::unblock(move || {
            let ctx = StageCtx {
                objects_fd: objects.as_fd(),
                staging_fd: staging.as_fd(),
                mode,
                fsync,
                per_object_fsync,
                sync_metadata: false,
                verity,
            };
            stage_content_blocking(&ctx, &key, &header, file, temp, unpacked)
        })
        .await?;
        self.record(checksum, ObjectType::File, mode, outcome, counted)
    }

    /// Stage a symlink content object. Called by
    /// [`write_symlink`](Transaction::write_symlink).
    pub(crate) async fn stage_symlink(
        &self,
        checksum: Checksum,
        header: ostrya_core::FileHeader,
    ) -> Result<Checksum> {
        let mode = self.repo.mode();
        let (fsync, per_object_fsync) = self.fsync_flags()?;
        let verity = self.verity()?;
        let objects = self.repo.objects_fd().try_clone_to_owned()?;
        let staging = self.staging_fd().try_clone_to_owned()?;
        let key = checksum;
        let outcome = ostrya_rt::unblock(move || {
            let ctx = StageCtx {
                objects_fd: objects.as_fd(),
                staging_fd: staging.as_fd(),
                mode,
                fsync,
                per_object_fsync,
                sync_metadata: false,
                verity,
            };
            stage_symlink_blocking(&ctx, &key, &header)
        })
        .await?;
        self.record(checksum, ObjectType::File, mode, outcome, false)
    }

    /// Stage a metadata object from its serialized bytes. Called by
    /// [`write_metadata`](Transaction::write_metadata).
    pub(crate) async fn stage_metadata(
        &self,
        checksum: Checksum,
        ty: ObjectType,
        bytes: Vec<u8>,
    ) -> Result<Checksum> {
        self.stage_metadata_outcome(checksum, ty, bytes)
            .await
            .map(|_| checksum)
    }

    /// Stage a metadata object as [`stage_metadata`](Transaction::stage_metadata)
    /// does, and return whether it was written: `false` where the repository
    /// already holds it.
    pub(crate) async fn stage_metadata_outcome(
        &self,
        checksum: Checksum,
        ty: ObjectType,
        bytes: Vec<u8>,
    ) -> Result<bool> {
        let mode = self.repo.mode();
        let (fsync, per_object_fsync) = self.fsync_flags()?;
        let verity = self.verity()?;
        // After `sync_staged` each metadata object is synced on its own, so the
        // `syncfs` that already ran still covers every staged object.
        let sync_metadata = fsync && self.staged.lock().unwrap().presynced.is_some();
        let objects = self.repo.objects_fd().try_clone_to_owned()?;
        let staging = self.staging_fd().try_clone_to_owned()?;
        let key = checksum;
        let outcome = ostrya_rt::unblock(move || {
            let ctx = StageCtx {
                objects_fd: objects.as_fd(),
                staging_fd: staging.as_fd(),
                mode,
                fsync,
                per_object_fsync,
                sync_metadata,
                verity,
            };
            stage_metadata_blocking(&ctx, &key, ty, &bytes)
        })
        .await?;
        let written = !outcome.deduped;
        self.record_object(checksum, ty, mode, outcome, true, false, sync_metadata)?;
        Ok(written)
    }

    /// Import one object from another local repository's `objects/` directory by
    /// hardlinking it, which shares the source inode. The two repositories must
    /// store the object identically, and the source inode must already carry the
    /// ownership a write here produces; see [`stage_import_blocking`]. Called by
    /// the local pull path.
    ///
    /// Returns whether the object is staged. `false` is a content object whose
    /// link was refused, which the caller imports through the object's logical
    /// header instead; a metadata object is always staged, by link or by copy.
    pub(crate) async fn stage_import(
        &self,
        src_objects_fd: BorrowedFd<'_>,
        checksum: Checksum,
        ty: ObjectType,
        src_mode: RepoMode,
        force_copy: bool,
    ) -> Result<bool> {
        let mode = self.repo.mode();
        let (fsync, per_object_fsync) = self.fsync_flags()?;
        let verity = self.verity()?;
        let objects = self.repo.objects_fd().try_clone_to_owned()?;
        let staging = self.staging_fd().try_clone_to_owned()?;
        let source = src_objects_fd.try_clone_to_owned()?;
        // The ownership a link must match, withheld where no link is attempted:
        // measuring it creates and removes a staging temporary, which a forced
        // copy and a sealing repository would never read.
        let link_owner = if force_copy || verity != Tristate::No {
            None
        } else {
            Some(self.fresh_owner().await?)
        };
        let outcome = ostrya_rt::unblock(move || {
            let ctx = StageCtx {
                objects_fd: objects.as_fd(),
                staging_fd: staging.as_fd(),
                mode,
                fsync,
                per_object_fsync,
                sync_metadata: false,
                verity,
            };
            stage_import_blocking(&ctx, source.as_fd(), &checksum, ty, src_mode, link_owner)
        })
        .await?;
        let Some(outcome) = outcome else {
            return Ok(false);
        };
        // An imported object carries no size record: a pull writes no commit, so
        // `ostree.sizes` is never emitted from this transaction, and the payload
        // is never read, so its unpacked length is unknown anyway.
        self.record_object(checksum, ty, mode, outcome, false, false, false)?;
        Ok(true)
    }

    /// Import one regular-file content object from another local repository by
    /// cloning its payload and applying this repository's inode policy from the
    /// object's logical header. The two modes must store the payload the same
    /// way; see [`stage_clone_content_blocking`]. Called by the local pull path.
    pub(crate) async fn stage_clone_content(
        &self,
        src_objects_fd: BorrowedFd<'_>,
        checksum: Checksum,
        src_mode: RepoMode,
        header: ostrya_core::FileHeader,
        unpacked: u64,
    ) -> Result<()> {
        let mode = self.repo.mode();
        let (fsync, per_object_fsync) = self.fsync_flags()?;
        let verity = self.verity()?;
        let objects = self.repo.objects_fd().try_clone_to_owned()?;
        let staging = self.staging_fd().try_clone_to_owned()?;
        let source = src_objects_fd.try_clone_to_owned()?;
        let outcome = ostrya_rt::unblock(move || {
            let ctx = StageCtx {
                objects_fd: objects.as_fd(),
                staging_fd: staging.as_fd(),
                mode,
                fsync,
                per_object_fsync,
                sync_metadata: false,
                verity,
            };
            stage_clone_content_blocking(
                &ctx,
                source.as_fd(),
                &checksum,
                src_mode,
                &header,
                unpacked,
            )
        })
        .await?;
        // An imported object carries no size record: a pull writes no commit, so
        // `ostree.sizes` is never emitted from this transaction.
        self.record_object(
            checksum,
            ObjectType::File,
            mode,
            outcome,
            false,
            true,
            false,
        )?;
        Ok(())
    }

    /// Record a staged object's outcome: debit the free-space budget by the
    /// blocks the object allocated, insert it into the staged set, and update the
    /// statistics. Idempotent by identity, so restaging an object already staged
    /// in this transaction is a no-op.
    fn record(
        &self,
        checksum: Checksum,
        ty: ObjectType,
        mode: RepoMode,
        outcome: StageOutcome,
        payload: bool,
    ) -> Result<Checksum> {
        self.record_object(checksum, ty, mode, outcome, true, payload, false)
    }

    /// The body of [`record`](Transaction::record). `with_size` chooses whether
    /// the object contributes an archive size record; an import contributes none,
    /// since the pull that imports it writes no commit to carry one. `payload`
    /// marks a regular-file content object, whose unpacked length is what
    /// [`content_bytes_unpacked`](TransactionStats::content_bytes_unpacked)
    /// sums; a symlink and a metadata object carry none. `synced` marks an
    /// object whose file was synced on its own after
    /// [`sync_staged`](Transaction::sync_staged), which the count of durable
    /// objects then includes.
    #[allow(clippy::too_many_arguments)]
    fn record_object(
        &self,
        checksum: Checksum,
        ty: ObjectType,
        mode: RepoMode,
        outcome: StageOutcome,
        with_size: bool,
        payload: bool,
        synced: bool,
    ) -> Result<Checksum> {
        let mut staged = self.staged.lock().unwrap();
        // The totals count every object offered, dedup hits included, which is
        // the work the transaction was asked for rather than the work it did.
        if ty == ObjectType::File {
            staged.stats.content_total += 1;
        } else {
            staged.stats.metadata_total += 1;
        }
        // An object the store already held is inside the `ostree.sizes` scope
        // just as a freshly staged one is; its sizes are recovered from disk.
        if with_size
            && mode.is_archive()
            && let Some(scope) = &mut staged.size_scope
        {
            scope.insert(checksum, ty);
        }
        if outcome.deduped {
            return Ok(checksum);
        }
        if staged.objects.contains_key(&(checksum, ty)) {
            // Already staged in this transaction: idempotent no-op.
            return Ok(checksum);
        }
        // Only freshly written blocks come off the budget. An imported object
        // that shares the source inode by hardlink allocates nothing, and one
        // whose payload came from a `FICLONE` reflink shares the source extents,
        // so neither reduces the bytes free on the filesystem.
        let allocated = match outcome.blocks {
            Blocks::Written => outcome.on_disk_size,
            Blocks::Linked | Blocks::Reflinked => 0,
        };
        if allocated > staged.free_budget {
            return Err(Error::InsufficientFreeSpace {
                shortfall: allocated - staged.free_budget,
            });
        }
        staged.free_budget -= allocated;
        staged.objects.insert(
            (checksum, ty),
            StagedObject {
                staging_name: outcome.staging_name,
                dest: outcome.dest,
            },
        );
        if synced && let Some(durable) = &mut staged.presynced {
            *durable += 1;
        }
        // In archive mode every staged object -- content and metadata alike --
        // contributes an `ostree.sizes` record. A metadata object is stored
        // raw, so its unpacked size equals its on-disk size.
        if with_size && mode.is_archive() {
            let unpacked = if ty == ObjectType::File {
                outcome.unpacked
            } else {
                outcome.on_disk_size
            };
            staged.sizes.insert(
                checksum,
                SizeRecord {
                    compressed: outcome.on_disk_size,
                    unpacked,
                    objtype: ty,
                },
            );
        }
        if ty == ObjectType::File {
            staged.stats.content_written += 1;
            staged.stats.content_bytes_written += outcome.on_disk_size;
            if payload {
                staged.stats.content_bytes_unpacked += outcome.unpacked;
            }
        } else {
            staged.stats.metadata_written += 1;
        }
        Ok(checksum)
    }

    /// The `fsync` and `per-object-fsync` settings, the first from
    /// [`set_fsync`](Transaction::set_fsync) and the second from
    /// [`set_per_object_fsync`](Transaction::set_per_object_fsync) where the
    /// transaction carries an override, and each from the repository config
    /// otherwise. Every write path of the transaction reads this pair: the
    /// per-object writes, the publication step, the detached-metadata writes,
    /// and the ref writes.
    ///
    /// The configured `[core] fsync` and `[core] per-object-fsync` are both
    /// read whether or not an override stands, so a value the reader refuses is
    /// reported from every transaction and an override never conceals it
    /// (`docs/format-reference.md`, "The fsync vocabulary").
    pub(crate) fn fsync_flags(&self) -> Result<(bool, bool)> {
        let config = self.repo.config();
        let configured = config.fsync()?;
        let configured_per_object = config.per_object_fsync()?;
        let fsync = self.fsync_override.unwrap_or(configured);
        let per_object = self
            .per_object_fsync_override
            .unwrap_or(configured_per_object);
        Ok((fsync, per_object))
    }

    /// The effective `[ex-integrity] fsverity` setting from the repository
    /// config, applied when staging each regular-file object.
    fn verity(&self) -> Result<Tristate> {
        self.repo.config().fsverity()
    }

    /// Finish the transaction, publishing its staged objects into `objects/`
    /// and then applying the queued ref writes.
    ///
    /// Publication follows the durability contract, under the one fsync policy
    /// the transaction resolves from [`set_fsync`](Transaction::set_fsync) and
    /// the repository config: with fsync on, the repository is `syncfs`-ed
    /// before the staged objects are renamed into `objects/<xx>/`, and each
    /// touched fanout directory and `objects/` is `fsync`-ed afterward. The
    /// queued detached-metadata edits are written next, and then the queued
    /// refs, in one trip to the blocking pool, so a commit and its
    /// `.commitmeta` are both durable before a ref names them. Each ref is
    /// written atomically (tmpfile, rename, with the tmpfile `fdatasync`-ed
    /// under the same policy). After the last rename each directory that
    /// gained or lost a ref name is `fsync`-ed once, deepest first, so every
    /// ref is durable when the call returns and every object a ref names is
    /// durable before the ref points at it; the set of ref writes is not atomic
    /// as a whole. With fsync off no step of the sequence syncs. Queued
    /// refspecs are validated up front, before any object is published, so a
    /// malformed refspec fails the commit with nothing written. The staging
    /// directory is then reaped and the lock released.
    ///
    /// The objects publish with no update lock held. When the transaction
    /// writes a ref, a ref removal included, or detached metadata, the call
    /// then takes the update lock, which excludes the other writers of refs
    /// and detached metadata, and writes the detached metadata and the refs
    /// under it. A transaction that writes neither takes no update lock. The
    /// transaction holds the repository lock already, so the wait is for the
    /// update lock alone. It fails with [`Error::LockTimeout`] after
    /// `lock-timeout-secs`, and the commit then leaves its published objects
    /// with no detached metadata and no ref written. A caller that holds an
    /// [`UpdateGuard`](crate::UpdateGuard) of this repository and commits a
    /// transaction that writes a ref waits for its own guard until the
    /// timeout, and with `lock-timeout-secs=-1` it waits forever.
    ///
    /// The update lock, the repository lock, and the staging directory move
    /// into the blocking closure that writes the detached metadata and the
    /// refs, and the closure releases them when those writes end. So a caller
    /// that drops the returned future cannot release a lock or lose a staged
    /// file while those writes still run, and the writes complete.
    pub async fn commit(mut self) -> Result<TransactionStats> {
        let refs = self.resolve_ref_queue()?;
        let synced = self.publish().await?;
        if refs.is_empty() && self.detached.lock().unwrap().edits.is_empty() {
            let stats = self.staged.lock().unwrap().stats;
            self.reap_staging().await;
            return Ok(stats);
        }
        let held = self.repo.lock_update().await?;
        self.write_tail(refs, synced, Some(held)).await
    }

    /// Commit the transaction as [`commit`](Transaction::commit) does, under
    /// the update lock the caller holds. The reference to the hold makes a
    /// call without the lock a type error, and the call does not take the
    /// lock again.
    pub(crate) async fn commit_under(self, held: &UpdateLockHeld) -> Result<TransactionStats> {
        debug_assert!(
            self.repo.holds_update_lock(held),
            "the hold is not the update lock of this repository"
        );
        let refs = self.resolve_ref_queue()?;
        let synced = self.publish().await?;
        self.write_tail(refs, synced, None).await
    }

    /// Write the queued detached metadata and then `refs`, reap the staging
    /// directory, and release the locks, in one trip to the blocking pool.
    /// `synced` tells whether the publication step ran its `syncfs`.
    ///
    /// The staging directory, the repository lock, and `held`, where given,
    /// move into the blocking closure. The closure releases the update lock
    /// after the last ref write, then reaps the staging directory, then
    /// releases the repository lock. So a caller that drops the returned
    /// future cannot release a lock or remove a staged file while the writes
    /// still run.
    async fn write_tail(
        mut self,
        refs: Vec<(String, Option<Checksum>)>,
        synced: bool,
        held: Option<UpdateLockHeld>,
    ) -> Result<TransactionStats> {
        let detached = self.detached_job(synced)?;
        let (fsync, _) = self.fsync_flags()?;
        let repo_mode = self.repo.mode();
        let repo_fd = self.repo.repo_fd().try_clone_to_owned()?;
        let stats = self.staged.lock().unwrap().stats;
        let staging = self.staging.take();
        let lock = self.lock;
        ostrya_rt::unblock(move || {
            #[cfg(test)]
            test_tail::pass(repo_fd.as_fd());
            let written = detached.run().and_then(|()| {
                crate::refs::write_resolved_refs_blocking(repo_fd.as_fd(), &refs, fsync, repo_mode)
            });
            drop(held);
            drop(staging);
            drop(lock);
            written
        })
        .await?;
        Ok(stats)
    }

    /// Make the objects staged so far durable ahead of
    /// [`commit`](Transaction::commit): with fsync on, run one `syncfs` of the
    /// repository. The publication step of `commit` then runs no `syncfs` of
    /// its own, unless an object was staged after this call. With fsync off the
    /// call does nothing.
    #[cfg(feature = "receive")]
    pub(crate) async fn sync_staged(&self) -> Result<()> {
        let (fsync, _) = self.fsync_flags()?;
        if !fsync {
            return Ok(());
        }
        // Each object in the count is in the staging directory before the
        // `syncfs` starts, because an object is recorded after its write.
        let count = self.staged.lock().unwrap().objects.len();
        let repo_fd = self.repo.repo_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || rustix::fs::syncfs(repo_fd.as_fd())).await?;
        self.staged.lock().unwrap().presynced = Some(count);
        Ok(())
    }

    /// Whether the publication step runs its `syncfs`: with fsync on, unless
    /// [`sync_staged`](Transaction::sync_staged) made every staged object
    /// durable already.
    fn syncfs_at_publish(&self, fsync: bool) -> bool {
        let staged = self.staged.lock().unwrap();
        fsync && staged.presynced != Some(staged.objects.len())
    }

    /// Discard the transaction and its staged objects, releasing the lock.
    pub async fn abort(mut self) -> Result<()> {
        self.reap_staging().await;
        Ok(())
    }

    /// Rename every staged object into `objects/` on the blocking pool, and
    /// return whether the step ran its `syncfs`.
    async fn publish(&self) -> Result<bool> {
        let objects: Vec<(String, String)> = {
            let staged = self.staged.lock().unwrap();
            staged
                .objects
                .values()
                .map(|o| (o.staging_name.clone(), o.dest.clone()))
                .collect()
        };
        if objects.is_empty() {
            return Ok(false);
        }
        let (fsync, _) = self.fsync_flags()?;
        let syncfs = self.syncfs_at_publish(fsync);
        let repo_mode = self.repo.mode();
        let repo_fd = self.repo.repo_fd().try_clone_to_owned()?;
        let objects_fd = self.repo.objects_fd().try_clone_to_owned()?;
        let staging_fd = self.staging_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || {
            publish_blocking(
                repo_fd.as_fd(),
                objects_fd.as_fd(),
                staging_fd.as_fd(),
                &objects,
                syncfs,
                fsync,
                repo_mode,
            )
        })
        .await?;
        Ok(syncfs)
    }

    /// Remove the staging directory on the blocking pool, if still present.
    async fn reap_staging(&mut self) {
        if let Some(staging) = self.staging.take() {
            ostrya_rt::unblock(move || drop(staging)).await;
        }
    }
}

/// The queued detached-metadata edits of a commit, taken from the
/// transaction for one trip to the blocking pool.
struct DetachedJob {
    queued: Vec<(Checksum, DetachedEdit)>,
    fsync: bool,
    /// Whether the staged files are durable already, from the `syncfs` of
    /// the publication step.
    staged_durable: bool,
    repo_mode: RepoMode,
    objects_fd: std::os::fd::OwnedFd,
    staging_fd: std::os::fd::OwnedFd,
}

impl DetachedJob {
    /// Apply the edits. The staged files are installed first, in one step,
    /// and the rest of the edit of each commit then applies to its installed
    /// file. With fsync on, a `syncfs` makes the staged files durable before
    /// the install where the publication step ran none. Each other edit is
    /// written and, with fsync on, made durable before the next one starts,
    /// and each takes the process-wide guard of detached-metadata edits for
    /// itself alone. The caller holds the update lock.
    fn run(self) -> Result<()> {
        let staged: Vec<(&Checksum, &str)> = self
            .queued
            .iter()
            .filter_map(|(checksum, edit)| Some((checksum, edit.staged.as_deref()?)))
            .collect();
        if !staged.is_empty() {
            if self.fsync && !self.staged_durable {
                rustix::fs::syncfs(self.staging_fd.as_fd())?;
            }
            crate::commit::install_detached_blocking(
                self.staging_fd.as_fd(),
                &staged,
                self.objects_fd.as_fd(),
                self.fsync,
                self.repo_mode,
            )?;
        }
        for (checksum, edit) in self.queued {
            if edit.staged.is_some()
                && edit.replace.is_none()
                && edit.merge.is_none()
                && edit.appends.is_empty()
            {
                continue;
            }
            crate::commit::merge_detached_blocking(
                self.objects_fd.as_fd(),
                &checksum,
                edit.replace,
                edit.merge,
                edit.appends,
                self.fsync,
                self.repo_mode,
            )?;
        }
        Ok(())
    }
}

/// A transaction moves freely across tasks and threads.
const _: fn() = || {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<Transaction>();
};

/// A gate that the step of a commit that writes detached metadata and refs
/// passes, for the unit tests. A test arms it for one repository root. The
/// next such step of a commit of that repository then reports that it started
/// and waits until the test opens the gate.
#[cfg(test)]
mod test_tail {
    use std::os::fd::BorrowedFd;
    use std::sync::Mutex;
    use std::sync::mpsc::{Receiver, Sender, channel};

    type Gate = ((u64, u64), Sender<()>, Receiver<()>);

    static GATES: Mutex<Vec<Gate>> = Mutex::new(Vec::new());

    /// Arm the gate for the repository root `root`, and return the receiver
    /// of the start report and the sender that opens the gate.
    pub(super) fn arm(root: &std::path::Path) -> (Receiver<()>, Sender<()>) {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(root).unwrap();
        let (started_tx, started_rx) = channel();
        let (go_tx, go_rx) = channel();
        GATES
            .lock()
            .unwrap()
            .push(((meta.dev(), meta.ino()), started_tx, go_rx));
        (started_rx, go_tx)
    }

    /// Report the start and wait for the gate, when a gate is armed for the
    /// repository root `repo_fd`.
    pub(super) fn pass(repo_fd: BorrowedFd<'_>) {
        let Ok(stat) = rustix::fs::fstat(repo_fd) else {
            return;
        };
        let key = (stat.st_dev, stat.st_ino);
        let gate = {
            let mut gates = GATES.lock().unwrap();
            let index = gates.iter().position(|gate| gate.0 == key);
            index.map(|index| gates.remove(index))
        };
        if let Some((_, started, go)) = gate {
            let _ = started.send(());
            let _ = go.recv();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CreateOptions;
    use crate::write::FileMeta;
    use ostrya_rt::block_on;

    /// A throwaway directory removed on drop.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("ostrya-txn-{}-{tag}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The archive size record separates the compressed `.filez` size from the
    /// uncompressed payload size. A highly compressible payload makes the two
    /// diverge, so recording the payload size in the `unpacked` field is the
    /// only value that satisfies the assertions.
    #[test]
    fn archive_size_record_separates_compressed_and_unpacked() {
        let scratch = Scratch::new("sizes");
        let root = scratch.0.join("repo");
        block_on(async {
            let repo = crate::Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let txn = repo.transaction().await.unwrap();
            let payload = vec![b'a'; 8192];
            let checksum = txn
                .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o644), &payload)
                .await
                .unwrap();

            // Read the record out from under the lock so the guard is released
            // before the abort await.
            let (record, content_bytes) = {
                let staged = txn.staged.lock().unwrap();
                let record = staged.sizes.get(&checksum).copied().expect("size record");
                (record, staged.stats.content_bytes_written)
            };
            assert_eq!(
                record.unpacked,
                payload.len() as u64,
                "unpacked is the pre-compression payload size"
            );
            assert_eq!(
                record.compressed, content_bytes,
                "compressed is the on-disk .filez size"
            );
            assert!(
                record.compressed < record.unpacked,
                "a compressible payload stores smaller than it unpacks: \
                 compressed={} unpacked={}",
                record.compressed,
                record.unpacked,
            );
            txn.abort().await.unwrap();
        });
    }

    /// `sync_staged` makes the objects staged so far durable, so the
    /// publication step runs no `syncfs` of its own. An object staged after the
    /// call brings the `syncfs` back, an object staged a second time does not,
    /// and the commit publishes every object.
    #[cfg(feature = "receive")]
    #[test]
    fn sync_staged_skips_the_publication_syncfs_until_a_later_stage() {
        let scratch = Scratch::new("presynced");
        block_on(async {
            let repo = crate::Repo::create(
                &scratch.0.join("repo"),
                CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let mut txn = repo.transaction().await.unwrap();
            txn.set_fsync(true);
            let meta = FileMeta::regular(0, 0, 0o644);
            let first = txn.write_regfile_inline(None, &meta, b"one").await.unwrap();
            assert!(txn.syncfs_at_publish(true));
            txn.sync_staged().await.unwrap();
            assert!(!txn.syncfs_at_publish(true));
            txn.write_regfile_inline(None, &meta, b"one").await.unwrap();
            assert!(
                !txn.syncfs_at_publish(true),
                "a second stage adds no object"
            );
            let second = txn.write_regfile_inline(None, &meta, b"two").await.unwrap();
            assert!(
                txn.syncfs_at_publish(true),
                "a later object needs the syncfs"
            );
            txn.sync_staged().await.unwrap();
            assert!(!txn.syncfs_at_publish(true));
            txn.commit().await.unwrap();
            for checksum in [first, second] {
                assert!(repo.has_object(ObjectType::File, &checksum).await.unwrap());
            }
        });
    }

    /// Metadata objects staged after `sync_staged` are synced one by one and
    /// counted as durable, so the anchor commit a receiving session stages
    /// under its lock brings no `syncfs` back at publication.
    #[cfg(feature = "receive")]
    #[test]
    fn metadata_staged_after_sync_staged_needs_no_second_syncfs() {
        let scratch = Scratch::new("presynced-anchor");
        block_on(async {
            let repo = crate::Repo::create(
                &scratch.0.join("repo"),
                CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let mut txn = repo.transaction().await.unwrap();
            txn.set_fsync(true);
            let meta = FileMeta::regular(0, 0, 0o644);
            txn.write_regfile_inline(None, &meta, b"one").await.unwrap();
            txn.sync_staged().await.unwrap();
            let anchor = repo
                .stage_anchor_commit(&txn, "org.example.C", None, Some(1_700_000_000))
                .await
                .unwrap();
            {
                let staged = txn.staged.lock().unwrap();
                assert_eq!(
                    staged.objects.len(),
                    4,
                    "the file, dirmeta, dirtree, commit"
                );
                assert_eq!(staged.presynced, Some(staged.objects.len()));
            }
            assert!(!txn.syncfs_at_publish(true));
            txn.commit().await.unwrap();
            assert_eq!(
                repo.resolve_ref_tip(crate::summary::OSTREE_METADATA_REF)
                    .await
                    .unwrap(),
                Some(anchor)
            );
        });
    }

    /// A queued merge runs on the stored dict before the queued signatures:
    /// the signature lists get the union, another key takes the incoming
    /// value, and a stored key the incoming dict does not hold stays.
    #[cfg(feature = "receive")]
    #[test]
    fn a_queued_merge_applies_before_the_appended_signatures() {
        use crate::sign::append_signature;

        const KEY: &str = "ostree.sign.ed25519";
        let scratch = Scratch::new("merge-edit");
        block_on(async {
            let repo = crate::Repo::create(
                &scratch.0.join("repo"),
                CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let commit = Checksum::from_bytes([0x22; 32]);
            let str_variant = |text: &str| {
                Value::variant(
                    ostrya_core::Type::parse("s").unwrap(),
                    Value::Str(text.into()),
                )
            };
            let mut stored = Value::Array(Vec::new());
            append_signature(&mut stored, KEY, b"A".to_vec()).unwrap();
            crate::commit::append_dict_entry(&mut stored, "kept", str_variant("stored")).unwrap();
            crate::commit::append_dict_entry(&mut stored, "other", str_variant("stored")).unwrap();
            repo.write_commit_detached_metadata(&commit, Some(&stored))
                .await
                .unwrap();

            let mut incoming = Value::Array(Vec::new());
            append_signature(&mut incoming, KEY, b"A".to_vec()).unwrap();
            append_signature(&mut incoming, KEY, b"B".to_vec()).unwrap();
            crate::commit::append_dict_entry(&mut incoming, "other", str_variant("incoming"))
                .unwrap();
            let txn = repo.transaction().await.unwrap();
            txn.append_signature(&commit, KEY, b"C".to_vec());
            txn.merge_commit_detached(
                &commit,
                crate::summary::serialize_signature_dict(&incoming).unwrap(),
                Vec::new(),
            );
            txn.commit().await.unwrap();

            let dict = repo
                .read_commit_detached_metadata(&commit)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                crate::sign::signatures_for(&dict, KEY),
                vec![b"A".to_vec(), b"B".to_vec(), b"C".to_vec()]
            );
            let text = |key: &str| {
                dict.dict_get(key)
                    .and_then(Value::as_variant)
                    .and_then(|(_, value)| value.as_str().map(str::to_owned))
            };
            assert_eq!(text("kept").as_deref(), Some("stored"));
            assert_eq!(text("other").as_deref(), Some("incoming"));
        });
    }

    /// With fsync off `sync_staged` does nothing, and the publication step runs
    /// no `syncfs` either way.
    #[cfg(feature = "receive")]
    #[test]
    fn sync_staged_with_fsync_off_does_nothing() {
        let scratch = Scratch::new("presynced-off");
        block_on(async {
            let repo = crate::Repo::create(
                &scratch.0.join("repo"),
                CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let mut txn = repo.transaction().await.unwrap();
            txn.set_fsync(false);
            txn.write_regfile_inline(None, &FileMeta::regular(0, 0, 0o644), b"one")
                .await
                .unwrap();
            txn.sync_staged().await.unwrap();
            assert_eq!(txn.staged.lock().unwrap().presynced, None);
            assert!(!txn.syncfs_at_publish(false));
            txn.abort().await.unwrap();
        });
    }

    /// A source object the clone path cannot open because it is gone is reported
    /// as the missing object it is, the answer the link path gives for the same
    /// condition.
    #[test]
    fn a_clone_of_an_absent_source_object_reports_it_missing() {
        let scratch = Scratch::new("clone-missing");
        block_on(async {
            let src = crate::Repo::create(
                &scratch.0.join("src"),
                CreateOptions::new(RepoMode::BareUserShared),
            )
            .await
            .unwrap();
            let dst = crate::Repo::create(
                &scratch.0.join("dst"),
                CreateOptions::new(RepoMode::BareUser),
            )
            .await
            .unwrap();
            let txn = dst.transaction().await.unwrap();
            let checksum = Checksum::from_bytes([0x11; 32]);
            let err = txn
                .stage_clone_content(
                    src.objects_fd(),
                    checksum,
                    src.mode(),
                    FileMeta::regular(0, 0, 0o644).regular_header(),
                    0,
                )
                .await
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::ObjectNotFound { checksum: c, ty }
                        if c == checksum && ty == ObjectType::File
                ),
                "unexpected error: {err}"
            );
            txn.abort().await.unwrap();
        });
    }

    /// Create an archive repository under `scratch`, with `lock-timeout-secs=0`
    /// in its `[core]` group, and open it again so the handle reads the value.
    async fn no_wait_repo(scratch: &Scratch) -> crate::Repo {
        let root = scratch.0.join("repo");
        drop(
            crate::Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap(),
        );
        let config = root.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("lock-timeout-secs=0\n");
        std::fs::write(&config, text).unwrap();
        crate::Repo::open(&root).await.unwrap()
    }

    /// The `.commitmeta` path of `commit` under the archive repository at
    /// `root`.
    fn commitmeta(root: &std::path::Path, commit: &Checksum) -> std::path::PathBuf {
        root.join("objects").join(ostrya_core::loose_path(
            commit,
            ObjectType::CommitMeta,
            RepoMode::Archive,
        ))
    }

    /// An `a{sv}` dict of one string entry.
    fn string_dict(key: &str, text: &str) -> Value {
        Value::Array(vec![Value::Tuple(vec![
            Value::Str(key.into()),
            Value::variant(
                ostrya_core::Type::parse("s").unwrap(),
                Value::Str(text.into()),
            ),
        ])])
    }

    /// Staged bytes reach `objects/` verbatim at the commit, at mode 0644, and
    /// the signatures queued after the stage append to them.
    #[test]
    fn a_staged_file_is_installed_at_the_commit_and_takes_later_appends() {
        use std::os::unix::fs::PermissionsExt;

        const KEY: &str = "ostree.sign.ed25519";
        let scratch = Scratch::new("staged-detached");
        block_on(async {
            let repo = no_wait_repo(&scratch).await;
            let root = scratch.0.join("repo");
            let commit = Checksum::from_bytes([0x31; 32]);
            let staged = crate::summary::serialize_signature_dict(&string_dict("a", "x")).unwrap();

            let txn = repo.transaction().await.unwrap();
            txn.stage_commit_detached_bytes(&commit, b"first".to_vec())
                .await
                .unwrap();
            txn.stage_commit_detached_bytes(&commit, staged.clone())
                .await
                .unwrap();
            assert!(
                !commitmeta(&root, &commit).exists(),
                "nothing before commit"
            );
            txn.commit().await.unwrap();
            assert_eq!(std::fs::read(commitmeta(&root, &commit)).unwrap(), staged);
            let mode = std::fs::metadata(commitmeta(&root, &commit))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, 0o644);

            let txn = repo.transaction().await.unwrap();
            txn.stage_commit_detached_bytes(&commit, staged.clone())
                .await
                .unwrap();
            Transaction::edit_for(&mut txn.detached.lock().unwrap(), &commit)
                .appends
                .push((KEY.to_owned(), vec![9; 64]));
            txn.commit().await.unwrap();
            let stored = repo
                .read_commit_detached_metadata(&commit)
                .await
                .unwrap()
                .unwrap();
            assert!(stored.dict_get("a").is_some(), "the staged key stays");
            assert_eq!(crate::sign::signatures_for(&stored, KEY), vec![vec![9; 64]]);
        });
    }

    /// A dict queued after a stage replaces it, and a stage after a queued
    /// dict replaces the dict.
    #[test]
    fn the_last_of_a_stage_and_a_queued_dict_wins() {
        let scratch = Scratch::new("staged-replace");
        block_on(async {
            let repo = no_wait_repo(&scratch).await;
            let commit = Checksum::from_bytes([0x32; 32]);
            let staged = crate::summary::serialize_signature_dict(&string_dict("a", "x")).unwrap();

            let txn = repo.transaction().await.unwrap();
            txn.stage_commit_detached_bytes(&commit, staged.clone())
                .await
                .unwrap();
            txn.set_commit_detached_metadata(&commit, string_dict("b", "y"));
            txn.commit().await.unwrap();
            assert_eq!(
                repo.read_commit_detached_metadata(&commit).await.unwrap(),
                Some(string_dict("b", "y"))
            );

            let txn = repo.transaction().await.unwrap();
            txn.set_commit_detached_metadata(&commit, string_dict("b", "z"));
            txn.stage_commit_detached_bytes(&commit, staged)
                .await
                .unwrap();
            txn.commit().await.unwrap();
            assert_eq!(
                repo.read_commit_detached_metadata(&commit).await.unwrap(),
                Some(string_dict("a", "x"))
            );
        });
    }

    /// A transaction that does not commit leaves the stored file as it
    /// stands.
    #[test]
    fn an_aborted_transaction_installs_no_staged_file() {
        let scratch = Scratch::new("staged-abort");
        block_on(async {
            let repo = no_wait_repo(&scratch).await;
            let root = scratch.0.join("repo");
            let commit = Checksum::from_bytes([0x33; 32]);

            let txn = repo.transaction().await.unwrap();
            txn.stage_commit_detached_bytes(&commit, b"staged".to_vec())
                .await
                .unwrap();
            txn.abort().await.unwrap();
            assert!(!commitmeta(&root, &commit).exists());

            repo.write_commit_detached_metadata(&commit, Some(&string_dict("a", "x")))
                .await
                .unwrap();
            let before = std::fs::read(commitmeta(&root, &commit)).unwrap();
            let txn = repo.transaction().await.unwrap();
            txn.stage_commit_detached_bytes(&commit, b"staged".to_vec())
                .await
                .unwrap();
            drop(txn);
            assert_eq!(std::fs::read(commitmeta(&root, &commit)).unwrap(), before);
        });
    }

    /// The update lock is taken only by a commit that writes a ref, a ref
    /// removal included, or detached metadata. A commit that waits in vain
    /// leaves its published objects, no ref, and no detached metadata.
    #[test]
    fn only_a_commit_that_writes_a_ref_or_detached_metadata_takes_the_update_lock() {
        let scratch = Scratch::new("lock-condition");
        block_on(async {
            let repo = no_wait_repo(&scratch).await;
            let root = scratch.0.join("repo");
            let meta = FileMeta::regular(0, 0, 0o644);
            let held = repo.lock_update().await.unwrap();

            let txn = repo.transaction().await.unwrap();
            let object = txn.write_regfile_inline(None, &meta, b"one").await.unwrap();
            txn.commit().await.unwrap();
            assert!(repo.has_object(ObjectType::File, &object).await.unwrap());

            let commit = Checksum::from_bytes([0x34; 32]);
            let refused: [&dyn Fn(&Transaction); 3] = [
                &|txn| txn.set_ref("main", Some(&commit)),
                &|txn| txn.set_ref("main", None),
                &|txn| txn.set_commit_detached_metadata(&commit, string_dict("a", "x")),
            ];
            for queue in refused {
                let txn = repo.transaction().await.unwrap();
                let object = txn.write_regfile_inline(None, &meta, b"two").await.unwrap();
                queue(&txn);
                let err = txn.commit().await.unwrap_err();
                assert!(matches!(err, Error::LockTimeout { secs: 0 }), "{err:?}");
                assert!(repo.has_object(ObjectType::File, &object).await.unwrap());
                assert_eq!(repo.resolve_ref_tip("main").await.unwrap(), None);
                assert!(!commitmeta(&root, &commit).exists());
            }
            drop(held);
        });
    }

    /// Poll the commit of `txn` until its ref step reports the start through
    /// `started`, and then drop the commit future.
    async fn drop_commit_at_the_tail(txn: Transaction, started: &std::sync::mpsc::Receiver<()>) {
        use futures_lite::future::poll_once;
        use std::time::{Duration, Instant};

        let mut committing = Box::pin(txn.commit());
        let deadline = Instant::now() + Duration::from_secs(10);
        while started.try_recv().is_err() {
            assert!(Instant::now() < deadline, "the ref step never started");
            assert!(poll_once(&mut committing).await.is_none());
            ostrya_rt::Timer::after(Duration::from_millis(10)).await;
        }
        drop(committing);
    }

    /// Retry `attempt` every 10 ms until it no longer fails with
    /// [`Error::LockTimeout`], for at most 10 s.
    async fn retry_lock<T, F: std::future::Future<Output = Result<T>>>(
        mut attempt: impl FnMut() -> F,
    ) -> T {
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match attempt().await {
                Ok(held) => return held,
                Err(Error::LockTimeout { .. }) => {
                    assert!(Instant::now() < deadline, "the lock was never released");
                    ostrya_rt::Timer::after(Duration::from_millis(10)).await;
                }
                Err(err) => panic!("{err:?}"),
            }
        }
    }

    /// A commit future dropped while its ref step runs on the blocking pool
    /// keeps the update lock until that step ends, and the step completes.
    #[test]
    fn a_dropped_commit_holds_the_update_lock_until_its_ref_step_ends() {
        let scratch = Scratch::new("dropped-commit");
        block_on(async {
            let repo = no_wait_repo(&scratch).await;
            let root = scratch.0.join("repo");
            let commit = Checksum::from_bytes([0x35; 32]);
            let txn = repo.transaction().await.unwrap();
            txn.set_ref("main", Some(&commit));
            let (started, go) = test_tail::arm(&root);
            drop_commit_at_the_tail(txn, &started).await;

            assert!(crate::lock::update_lock_held_in_process(repo.repo_fd()));
            let err = repo.lock_update().await.unwrap_err();
            assert!(matches!(err, Error::LockTimeout { secs: 0 }), "{err:?}");

            go.send(()).unwrap();
            drop(retry_lock(|| repo.lock_update()).await);
            assert_eq!(repo.resolve_ref_tip("main").await.unwrap(), Some(commit));
        });
    }

    /// A commit future dropped while its ref step runs on the blocking pool
    /// keeps the repository lock until that step ends, so an exclusive holder
    /// such as a prune cannot start before the ref is written.
    #[test]
    fn a_dropped_commit_holds_the_repository_lock_until_its_ref_step_ends() {
        use crate::LockKind;

        let scratch = Scratch::new("dropped-commit-repo-lock");
        block_on(async {
            let repo = no_wait_repo(&scratch).await;
            let root = scratch.0.join("repo");
            let commit = Checksum::from_bytes([0x36; 32]);
            let txn = repo.transaction().await.unwrap();
            txn.set_ref("main", Some(&commit));
            let (started, go) = test_tail::arm(&root);
            drop_commit_at_the_tail(txn, &started).await;

            let err = repo.lock_repo(LockKind::Exclusive).await.unwrap_err();
            assert!(matches!(err, Error::LockTimeout { secs: 0 }), "{err:?}");

            go.send(()).unwrap();
            drop(retry_lock(|| repo.lock_repo(LockKind::Exclusive)).await);
            assert_eq!(repo.resolve_ref_tip("main").await.unwrap(), Some(commit));
        });
    }

    /// A commit future dropped while its ref step runs on the blocking pool
    /// still installs the staged detached metadata and writes the ref.
    #[test]
    fn a_dropped_commit_installs_its_staged_file_and_writes_its_ref() {
        let scratch = Scratch::new("dropped-commit-staged");
        block_on(async {
            let repo = no_wait_repo(&scratch).await;
            let root = scratch.0.join("repo");
            let commit = Checksum::from_bytes([0x37; 32]);
            let staged = crate::summary::serialize_signature_dict(&string_dict("a", "x")).unwrap();
            let txn = repo.transaction().await.unwrap();
            txn.stage_commit_detached_bytes(&commit, staged.clone())
                .await
                .unwrap();
            txn.set_ref("main", Some(&commit));
            let (started, go) = test_tail::arm(&root);
            drop_commit_at_the_tail(txn, &started).await;

            go.send(()).unwrap();
            drop(retry_lock(|| repo.lock_update()).await);
            assert_eq!(repo.resolve_ref_tip("main").await.unwrap(), Some(commit));
            assert_eq!(std::fs::read(commitmeta(&root, &commit)).unwrap(), staged);
        });
    }
}
