//! Owned transaction handles.
//!
//! A [`Transaction`] is created from a [`Repo`](crate::Repo) and owns the
//! repository lock hold and a staging directory for its duration. Multiple
//! transactions may exist at once in one process, each with its own staging
//! directory; the shared repository lock coordinates them and excludes other
//! processes, and the `ostree` tool, per the configured lock kind.
//!
//! A transaction ingests objects into its staging directory through the write
//! methods (in [`crate::write`]) and publishes them into `objects/` at
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
use crate::lock::LockGuard;
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
    /// payload was cloned contributes that payload's length.
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
}

/// One commit's queued detached-metadata edit.
///
/// The edit is held as a plan rather than as a finished dict, so the read of
/// what the repository already stores happens once, at the write, under the
/// guard that serializes it. `replace` is the dict
/// [`set_commit_detached_metadata`](Transaction::set_commit_detached_metadata)
/// put in place of the stored one; `appends` are the signatures
/// [`sign_commit`](Transaction::sign_commit) produced after it, in call order.
#[derive(Default)]
struct DetachedEdit {
    /// The dict that replaces whatever the repository stores, when a caller
    /// queued one. `None` starts the edit from the stored dict.
    replace: Option<Value>,
    /// Signatures to append, each an engine metadata key and one signature.
    appends: Vec<(String, Vec<u8>)>,
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
    detached: Mutex<Vec<(Checksum, DetachedEdit)>>,
    /// The uid and gid an object freshly staged in this transaction takes,
    /// measured once on first use by [`fresh_owner`](Transaction::fresh_owner).
    fresh_owner: OnceLock<(u32, u32)>,
    staging: Option<StagingDir>,
    /// The repository lock hold, kept for the transaction's lifetime and
    /// released when this field drops. Never read.
    #[allow(dead_code)]
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
            generate_sizes: AtomicBool::new(false),
            generate_sizes_override: None,
            staged: Mutex::new(Staged {
                objects: HashMap::new(),
                sizes: HashMap::new(),
                size_scope: None,
                free_budget,
                stats: TransactionStats::default(),
            }),
            refs: Mutex::new(Vec::new()),
            detached: Mutex::new(Vec::new()),
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

    /// Load a file object, checking this transaction's staged set before the
    /// repository's `objects/`. Used by the staging-tree read and merge paths so
    /// content staged in the current transaction is visible before it publishes.
    pub(crate) async fn load_file_staged_first(
        &self,
        checksum: &Checksum,
    ) -> Result<crate::file::FileObject> {
        if self.is_staged(checksum, ObjectType::File) {
            crate::file::load_staged_file(&self.repo, self.staging_fd(), checksum).await
        } else {
            self.repo.load_file(checksum).await
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
    /// commits reaches [`Error::ObjectNotFound`](crate::Error::ObjectNotFound)
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
        edit.replace = Some(meta);
        edit.appends.clear();
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
    /// The queueing takes one lock and holds no await, and the write reads,
    /// merges and replaces the file under a guard the whole process shares, so
    /// signatures several tasks produce for one commit all reach it -- from one
    /// transaction, from concurrent transactions, and from
    /// [`Repo::sign_commit`](crate::Repo::sign_commit) alike. The guard covers
    /// this process alone, and the repository lock a transaction takes is
    /// shared, so two processes that sign one commit at the same time can lose
    /// a signature. The `ostree` tool loses one the same way.
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
    fn edit_for<'a>(
        queue: &'a mut Vec<(Checksum, DetachedEdit)>,
        checksum: &Checksum,
    ) -> &'a mut DetachedEdit {
        let index = match queue.iter().position(|(c, _)| c == checksum) {
            Some(index) => index,
            None => {
                queue.push((*checksum, DetachedEdit::default()));
                queue.len() - 1
            }
        };
        &mut queue[index].1
    }

    /// Load a commit object's canonical bytes, checking this transaction's
    /// staged set before the repository's `objects/`, the way the other
    /// staged-first readers do.
    async fn load_commit_bytes_staged_first(&self, checksum: &Checksum) -> Result<Vec<u8>> {
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

    /// Apply the queued detached-metadata edits. Called between publication and
    /// the ref writes, under the transaction's own fsync policy.
    async fn write_detached(&self) -> Result<()> {
        let queued: Vec<(Checksum, DetachedEdit)> =
            std::mem::take(&mut *self.detached.lock().unwrap());
        if queued.is_empty() {
            return Ok(());
        }
        let (fsync, _) = self.fsync_flags()?;
        for (checksum, edit) in queued {
            self.repo
                .merge_commit_detached_metadata(&checksum, edit.replace, edit.appends, fsync)
                .await?;
        }
        Ok(())
    }

    /// Stage a regular-file content object whose payload is already written to
    /// `file`. Called by [`ContentWriter::finish`](crate::ContentWriter::finish).
    pub(crate) async fn stage_regular(
        &self,
        checksum: Checksum,
        header: ostrya_core::FileHeader,
        file: std::fs::File,
        temp: TempKind,
        unpacked: u64,
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
                verity,
            };
            stage_content_blocking(&ctx, &key, &header, file, temp, unpacked)
        })
        .await?;
        self.record(checksum, ObjectType::File, mode, outcome, true)
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
                verity,
            };
            stage_metadata_blocking(&ctx, &key, ty, &bytes)
        })
        .await?;
        self.record(checksum, ty, mode, outcome, false)
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
        self.record_object(checksum, ty, mode, outcome, false, false)?;
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
        self.record_object(checksum, ObjectType::File, mode, outcome, false, true)?;
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
        self.record_object(checksum, ty, mode, outcome, true, payload)
    }

    /// The body of [`record`](Transaction::record). `with_size` chooses whether
    /// the object contributes an archive size record; an import contributes none,
    /// since the pull that imports it writes no commit to carry one. `payload`
    /// marks a regular-file content object, whose unpacked length is what
    /// [`content_bytes_unpacked`](TransactionStats::content_bytes_unpacked)
    /// sums; a symlink and a metadata object carry none.
    fn record_object(
        &self,
        checksum: Checksum,
        ty: ObjectType,
        mode: RepoMode,
        outcome: StageOutcome,
        with_size: bool,
        payload: bool,
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
    /// [`set_fsync`](Transaction::set_fsync) where the transaction carries an
    /// override and from the repository config otherwise. Every write path of
    /// the transaction reads this pair: the per-object writes, the publication
    /// step, the detached-metadata writes, and the ref writes.
    ///
    /// The configured `[core] fsync` is read whether or not an override stands,
    /// so a value the reader refuses is reported from every transaction and an
    /// override never conceals it (`docs/format-reference.md`, "The fsync
    /// vocabulary").
    pub(crate) fn fsync_flags(&self) -> Result<(bool, bool)> {
        let config = self.repo.config();
        let configured = config.fsync()?;
        let fsync = self.fsync_override.unwrap_or(configured);
        Ok((fsync, config.per_object_fsync()?))
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
    /// queued detached-metadata dicts are written next, so a commit and its
    /// `.commitmeta` are both durable before a ref names them. Only
    /// then are the queued refs written, each individually atomic (tmpfile,
    /// rename, with the tmpfile `fdatasync`-ed and the holding directory
    /// `fsync`-ed under the same policy), so every object a ref names is
    /// durable before the ref points at it; the set of ref writes is not atomic
    /// as a whole. With fsync off no step of the sequence syncs. Queued
    /// refspecs are validated up front, before any object is published, so a
    /// malformed refspec fails the commit with nothing written. The staging
    /// directory is then reaped and the lock released.
    pub async fn commit(mut self) -> Result<TransactionStats> {
        let refs = self.resolve_ref_queue()?;
        self.publish().await?;
        self.write_detached().await?;
        self.write_resolved_refs(&refs).await?;
        let stats = self.staged.lock().unwrap().stats;
        self.reap_staging().await;
        Ok(stats)
    }

    /// Discard the transaction and its staged objects, releasing the lock.
    pub async fn abort(mut self) -> Result<()> {
        self.reap_staging().await;
        Ok(())
    }

    /// Rename every staged object into `objects/` on the blocking pool.
    async fn publish(&self) -> Result<()> {
        let objects: Vec<(String, String)> = {
            let staged = self.staged.lock().unwrap();
            staged
                .objects
                .values()
                .map(|o| (o.staging_name.clone(), o.dest.clone()))
                .collect()
        };
        if objects.is_empty() {
            return Ok(());
        }
        let (fsync, _) = self.fsync_flags()?;
        let repo_fd = self.repo.repo_fd().try_clone_to_owned()?;
        let objects_fd = self.repo.objects_fd().try_clone_to_owned()?;
        let staging_fd = self.staging_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || {
            publish_blocking(
                repo_fd.as_fd(),
                objects_fd.as_fd(),
                staging_fd.as_fd(),
                &objects,
                fsync,
            )
        })
        .await
    }

    /// Remove the staging directory on the blocking pool, if still present.
    async fn reap_staging(&mut self) {
        if let Some(staging) = self.staging.take() {
            ostrya_rt::unblock(move || drop(staging)).await;
        }
    }
}

/// A transaction moves freely across tasks and threads.
const _: fn() = || {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<Transaction>();
};

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
}
