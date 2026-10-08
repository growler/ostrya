//! Transactions: the write path of a repository.
//!
//! [`Repo::transaction`] begins a [`Transaction`]. The transaction stages
//! objects in its own staging directory. [`commit`](Transaction::commit)
//! publishes them into `objects/` and writes the queued refs.
//! [`TransactionStats`] counts the work of a transaction.
//!
//! [`ContentWriter`] streams the payload of one regular file into a
//! transaction. [`FileMeta`] holds the uid, the gid, the mode, and the
//! extended attributes of a file object.

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

/// The counts and sizes of the work of a transaction.
///
/// [`commit`](Transaction::commit) returns them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransactionStats {
    /// The number of metadata objects offered for staging, dedup hits included.
    ///
    /// A metadata object is a dirtree, a dirmeta, a commit, or another object
    /// that is not a content object. Each directory counts its dirmeta once, so
    /// a tree whose directories share one dirmeta counts it once for each
    /// directory.
    pub metadata_total: u32,
    /// The number of metadata objects freshly staged.
    ///
    /// A dedup hit does not count.
    pub metadata_written: u32,
    /// The number of content objects offered for staging, dedup hits included.
    ///
    /// A content object that a [`DevInoCache`](crate::DevInoCache) hit
    /// resolves is never offered, so it does not count.
    pub content_total: u32,
    /// The number of content objects freshly staged.
    ///
    /// A dedup hit does not count.
    pub content_written: u32,
    /// The total on-disk size of the freshly staged content objects.
    ///
    /// An object imported from another repository counts its full size. This
    /// is true if its bytes were written, shared by reflink, or shared by
    /// hardlink. So the value is the storage that the objects occupy. A shared
    /// object uses no new space on the file system.
    pub content_bytes_written: u64,
    /// The total payload size of the freshly staged regular-file content objects.
    ///
    /// The size is the size before the compression of the repository mode. An
    /// object whose payload is cloned adds the length of its payload. These
    /// objects add nothing:
    ///
    /// - A symlink.
    /// - An object hardlinked from another repository, because its payload is
    ///   never read.
    /// - An object that a static delta produced. The `ostree` command also
    ///   counts nothing for such an object in a pull.
    pub content_bytes_unpacked: u64,
    /// The number of content objects that a [`DevInoCache`](crate::DevInoCache)
    /// hit skipped in a file system ingest.
    ///
    /// A hit is a file whose device and inode pair the cache knows already.
    pub devino_cache_hits: u32,
    /// The number of entries that a commit-modifier filter excluded in a file
    /// system ingest.
    pub filtered: u32,
}

/// One object staged in a transaction that waits for publication.
struct StagedObject {
    /// The flat name of the object in the staging directory.
    staging_name: String,
    /// The loose path under `objects/` that the object publishes to.
    dest: String,
}

/// The archive size record of one staged object.
///
/// [`write_commit`](crate::Transaction::write_commit) reads the records to
/// write `ostree.sizes`. The `ostree.sizes` key of the `ostree` command covers
/// each object of the commit, content and metadata. So the transaction keeps a
/// record for each object type.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SizeRecord {
    /// The on-disk size: the `.filez` storage size for archive content, or the
    /// serialized byte length for a metadata object.
    pub(crate) compressed: u64,
    /// The logical (unpacked) size: the payload length of a file, the target
    /// length of a symlink, or the byte length of a metadata object.
    pub(crate) unpacked: u64,
    /// The object type, written as the last byte of the `ostree.sizes` entry.
    pub(crate) objtype: ObjectType,
}

/// The mutable state that concurrent writers of one transaction share.
struct Staged {
    /// The objects staged so far, by identity and type, for the dedup in the
    /// transaction and for publication at commit.
    objects: HashMap<(Checksum, ObjectType), StagedObject>,
    /// The size record of each object in archive mode, by checksum. The
    /// records cover content and metadata objects, the input of `ostree.sizes`.
    sizes: HashMap<Checksum, SizeRecord>,
    /// The objects that `ostree.sizes` covers, if a caller limits the key by
    /// tree source with [`begin_tree_source`](Transaction::begin_tree_source).
    /// `None` makes the key cover each object that the commit reaches.
    size_scope: Option<HashMap<Checksum, ObjectType>>,
    /// The bytes that the transaction can write before the free space is less
    /// than the configured reserve.
    free_budget: u64,
    /// The statistics so far.
    stats: TransactionStats,
    /// The number of staged objects that are durable before publication.
    ///
    /// The count is the objects that the last `sync_staged` made durable, plus
    /// each metadata object synced on its own after it. The publication step
    /// skips its `syncfs` while this count equals the number of staged objects.
    /// So an object staged after the sync gets the `syncfs` that it needs.
    presynced: Option<usize>,
}

/// The queued detached-metadata edit of one commit.
///
/// The edit is a plan, so the read of the stored dict happens once, at the
/// write, under the guard that serializes the write. The parts are:
///
/// - `staged`: the file that a pull staged to replace the stored one.
/// - `replace`: the dict that
///   [`set_commit_detached_metadata`](Transaction::set_commit_detached_metadata)
///   queued to replace the stored one.
/// - `merge`: the dict that a receiving session merges in, with the keys whose
///   stored value stays.
/// - `appends`: the signatures that [`sign_commit`](Transaction::sign_commit)
///   made after it, in call order.
#[derive(Default)]
struct DetachedEdit {
    /// The file in the staging directory whose bytes replace the stored
    /// detached metadata, if a pull staged one. The write installs it first,
    /// and the other parts of the edit apply to it next.
    staged: Option<String>,
    /// The dict that replaces the stored detached metadata, if a caller queued
    /// one. `None` starts the edit from the stored dict.
    replace: Option<Value>,
    /// The serialized `a{sv}` dict that the edit merges in before the appends,
    /// and the keys whose stored value stays.
    ///
    /// Each signature list gets the union of the two lists. A listed key that
    /// the starting dict holds keeps its value. Each other key takes the value
    /// of this dict.
    merge: Option<(Vec<u8>, Vec<String>)>,
    /// The signatures to append, each an engine metadata key and one signature.
    appends: Vec<(String, Vec<u8>)>,
}

/// The queued detached-metadata edits of a transaction.
///
/// The queue holds one edit for each commit, in the order of the first edit of
/// each commit. An index maps each commit to the position of its edit.
#[derive(Default)]
struct DetachedQueue {
    edits: Vec<(Checksum, DetachedEdit)>,
    index: HashMap<Checksum, usize>,
}

/// A set of staged objects and queued writes to one repository.
///
/// [`Repo::transaction`] and [`Repo::transaction_with_lock`] begin a
/// transaction. The transaction holds the repository lock and its own staging
/// directory until it ends. [`commit`](Transaction::commit) publishes the
/// staged objects and writes the queued refs and detached metadata.
/// [`abort`](Transaction::abort) discards them.
///
/// If a transaction drops without `commit` or `abort`, it removes its staging
/// directory with each staged object and releases the lock. So an abandoned
/// transaction leaves nothing behind.
///
/// # Concurrency
///
/// One process can hold many transactions at once, each with its own staging
/// directory. The repository lock coordinates them. It also excludes other
/// processes and the `ostree` command, as [`LockKind`](crate::LockKind)
/// states.
///
/// `&Transaction` is `Send + Sync`, so concurrent writers can stage objects
/// through one shared reference. A mutex guards the state that the writers
/// share: the set of staged objects for the dedup, the free-space budget, and
/// the archive size records.
///
/// # Staging directory
///
/// A transaction stages its objects in `tmp/staging-<boot-id>-XXXXXX`. It
/// creates the directory when it begins and removes it when it ends. While the
/// transaction lives, it holds an exclusive record lock on the sibling file
/// `staging-<boot-id>-XXXXXX-lock`.
///
/// The boot id separates the directories of the current boot from the
/// directories of earlier boots. The owner of a directory of the current boot
/// can still be alive. The owner of a directory of an earlier boot is gone.
///
/// When a transaction begins, it removes these stale entries at the top level
/// of `tmp/`:
///
/// - A staging directory whose lock it can take, because no live holder has
///   the lock.
/// - A staging directory with no lock file, if the directory is older than
///   `tmp-expiry-secs`. The age test is necessary because another process can
///   be in the middle of the creation of the directory.
/// - Each other entry whose mtime is older than `tmp-expiry-secs`, as the
///   `ostree` command does. A directory goes as a whole tree, by its own
///   mtime. A symlink goes as the link itself.
///
/// It never touches `tmp/cache`, and it never removes a staging directory that
/// this process owns. A staging lock file has no age test, because a
/// transaction can live longer than `tmp-expiry-secs` and still hold the lock.
///
/// A ref write, a detached-metadata write, and a tombstone write create a temp
/// entry at the top level of `tmp/` and rename it over the target. The entry
/// of a ref write is named `.ostrya-ref-<pid>-<n>-XXXXXX`. The entry of the
/// other two writes is named `.ostrya-meta-<pid>-<n>-XXXXXX`. The age test
/// applies to such an entry.
///
/// If `tmp-expiry-secs` is very small or negative, a transaction that begins
/// can remove the entry before its rename. The write then fails with `ENOENT`,
/// and the ref or the object stays unchanged.
///
/// # Examples
///
/// Commit the directory `/srv/rootfs` and point a ref at the new commit:
///
/// ```no_run
/// # async fn run() -> ostrya::Result<()> {
/// use std::os::fd::AsFd;
/// use std::path::Path;
///
/// use ostrya::{CommitOptions, MutableTree, Repo};
///
/// let repo = Repo::open(Path::new("/srv/repo")).await?;
/// let txn = repo.transaction().await?;
///
/// let parent = std::fs::File::open("/srv")?;
/// let mut mtree = MutableTree::new();
/// txn.write_dfd_to_mtree(parent.as_fd(), Path::new("rootfs"), &mut mtree, None)
///     .await?;
/// let root = txn.write_mtree(&mut mtree).await?;
///
/// let opts = CommitOptions {
///     subject: Some("Build 1".into()),
///     ..CommitOptions::default()
/// };
/// let commit = txn.write_commit(opts, &root).await?;
/// txn.set_ref("exampleos/stable", Some(&commit));
/// let stats = txn.commit().await?;
/// println!("{} content objects written", stats.content_written);
/// # Ok(()) }
/// ```
pub struct Transaction {
    repo: Repo,
    /// The `[core] fsync` value of this transaction alone, from
    /// [`set_fsync`](Transaction::set_fsync). `None` leaves the config value in
    /// force.
    fsync_override: Option<bool>,
    /// The `[core] per-object-fsync` value of this transaction alone, from
    /// [`set_per_object_fsync`](Transaction::set_per_object_fsync). `None`
    /// leaves the config value in force.
    per_object_fsync_override: Option<bool>,
    /// The `ostree.sizes` request of a file system ingest under
    /// [`GENERATE_SIZES`](crate::CommitModifierFlags::GENERATE_SIZES). The
    /// commit assembly reads it to decide if it writes `ostree.sizes`.
    generate_sizes: AtomicBool,
    /// The answer of a caller for the whole transaction, from
    /// [`set_generate_sizes`](Transaction::set_generate_sizes).
    ///
    /// It overrides `generate_sizes` in both directions. `None` leaves the
    /// ingest flag in force.
    generate_sizes_override: Option<bool>,
    // Fields drop in declaration order: the staged state and the staging
    // directory go first, then the lock.
    staged: Mutex<Staged>,
    /// The refspec-to-checksum writes that [`set_ref`](Transaction::set_ref)
    /// queues. [`commit`](Transaction::commit) applies them after object
    /// publication, for durability.
    pub(crate) refs: Mutex<Vec<crate::refs::RefWrite>>,
    /// The detached-metadata edits that
    /// [`set_commit_detached_metadata`](Transaction::set_commit_detached_metadata)
    /// and [`sign_commit`](Transaction::sign_commit) queue.
    ///
    /// [`commit`](Transaction::commit) applies them after object publication
    /// and before the queued ref writes. So a commit that a ref names carries
    /// its signatures.
    detached: Mutex<DetachedQueue>,
    /// The uid and gid of an object freshly staged in this transaction.
    /// [`fresh_owner`](Transaction::fresh_owner) measures them once, on first
    /// use.
    fresh_owner: OnceLock<(u32, u32)>,
    staging: Option<StagingDir>,
    /// The repository lock hold, kept for the life of the transaction.
    ///
    /// The drop of this field releases the lock. A commit that writes a ref
    /// or detached metadata moves the hold into the blocking closure of that
    /// write.
    lock: LockGuard,
}

/// Methods that set the options of a transaction, read its staged trees, queue
/// detached metadata, and end it.
impl Transaction {
    /// Assembles a transaction from a repository handle, an acquired lock, a
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

    /// Overrides the `[core] fsync` value for this transaction alone.
    ///
    /// The value applies to the whole transaction: the per-object writes, the
    /// publication step, the detached-metadata writes, and the ref writes. It
    /// changes the durability of the writes and no byte that the repository
    /// stores.
    /// [`commit`](Transaction::commit) states the sync sequence.
    pub fn set_fsync(&mut self, enabled: bool) {
        self.fsync_override = Some(enabled);
    }

    /// Overrides the `[core] per-object-fsync` value for this transaction alone.
    ///
    /// If the value is `true`, the transaction syncs the file of each content
    /// object when it stages the object, before publication. It never syncs a
    /// metadata object on its own. It does not sync an object imported by
    /// hardlink.
    ///
    /// The value has no effect while fsync is off, from the config or from
    /// [`set_fsync`](Transaction::set_fsync). It changes the durability of the
    /// writes and no byte that the repository stores.
    /// [`commit`](Transaction::commit) states the sync sequence.
    pub fn set_per_object_fsync(&mut self, enabled: bool) {
        self.per_object_fsync_override = Some(enabled);
    }

    /// Sets if each commit of this transaction carries the `ostree.sizes` key.
    ///
    /// A file system ingest under
    /// [`GENERATE_SIZES`](crate::CommitModifierFlags::GENERATE_SIZES) turns the
    /// key on. This call serves an ingest that runs no commit modifier, for
    /// example the tar import. The value holds for the whole transaction and
    /// overrides the flag of each ingest, so `false` turns the key off again.
    ///
    /// Outside archive mode the call has no effect, because no other mode
    /// writes the key.
    pub fn set_generate_sizes(&mut self, enabled: bool) {
        self.generate_sizes_override = Some(enabled);
    }

    /// Returns the repository that this transaction writes to.
    pub(crate) fn repo(&self) -> &Repo {
        &self.repo
    }

    /// Returns the descriptor of the staging directory, where the objects go.
    pub(crate) fn staging_fd(&self) -> BorrowedFd<'_> {
        self.staging
            .as_ref()
            .expect("staging directory present during the transaction")
            .dir_fd()
    }

    /// Returns the uid and gid of an object freshly staged in this transaction.
    ///
    /// The call measures the pair on first use and keeps it for the life of the
    /// transaction. The import path reads it. It accepts a hardlink only if the
    /// source inode has this ownership already. If two callers race for the
    /// first read, both measure the same directory, and one result stays.
    pub(crate) async fn fresh_owner(&self) -> Result<(u32, u32)> {
        if let Some(owner) = self.fresh_owner.get() {
            return Ok(*owner);
        }
        let staging = self.staging_fd().try_clone_to_owned()?;
        let owner = ostrya_rt::unblock(move || probe_fresh_owner(staging.as_fd())).await?;
        Ok(*self.fresh_owner.get_or_init(|| owner))
    }

    /// Records that this transaction writes `ostree.sizes` at commit.
    ///
    /// A file system ingest under
    /// [`GENERATE_SIZES`](crate::CommitModifierFlags::GENERATE_SIZES) calls it.
    pub(crate) fn mark_generate_sizes(&self) {
        self.generate_sizes.store(true, Ordering::Relaxed);
    }

    /// Returns `true` if the transaction writes `ostree.sizes`.
    ///
    /// The answer of the caller from
    /// [`set_generate_sizes`](Transaction::set_generate_sizes) applies if it
    /// exists, else the ingest flag. [`write_commit`](Transaction::write_commit)
    /// reads it.
    pub(crate) fn generate_sizes(&self) -> bool {
        self.generate_sizes_override
            .unwrap_or_else(|| self.generate_sizes.load(Ordering::Relaxed))
    }

    /// Starts a new tree source for the `ostree.sizes` key.
    ///
    /// The `ostree` command limits the key to the objects that the last tree
    /// source added, plus the directory objects that the tree serialization
    /// writes. So a content object from an earlier source leaves the key, and a
    /// directory object stays.
    ///
    /// A caller that builds a commit from several sources calls this method
    /// before each source. Then the key that ostrya writes is the key that the
    /// `ostree` command writes. If a caller never calls this method, the key
    /// covers each object that the commit reaches.
    ///
    /// The `--base` layer of a commit goes in before the first call, so it adds
    /// nothing to the key. The `ostree` command records the same key.
    pub fn begin_tree_source(&self) {
        let mut staged = self.staged.lock().unwrap();
        let scope = staged.size_scope.get_or_insert_with(HashMap::new);
        scope.retain(|_, ty| *ty != ObjectType::File);
    }

    /// Records one object in the `ostree.sizes` scope, if a scope is in force.
    ///
    /// Returns `true` if the object was not in the scope before.
    pub(crate) fn note_size_scope(&self, checksum: Checksum, ty: ObjectType) -> bool {
        let mut staged = self.staged.lock().unwrap();
        match &mut staged.size_scope {
            Some(scope) => scope.insert(checksum, ty).is_none(),
            None => false,
        }
    }

    /// Returns `true` if a size scope is in force.
    pub(crate) fn size_scoped(&self) -> bool {
        self.staged.lock().unwrap().size_scope.is_some()
    }

    /// Returns `true` if `checksum` is inside the `ostree.sizes` scope.
    ///
    /// If no scope is in force, each object is inside it.
    pub(crate) fn in_size_scope(&self, checksum: &Checksum) -> bool {
        match &self.staged.lock().unwrap().size_scope {
            Some(scope) => scope.contains_key(checksum),
            None => true,
        }
    }

    /// Returns a copy of the archive size records of the objects freshly staged
    /// so far, as `ostree.sizes` entries.
    ///
    /// [`write_commit`](Transaction::write_commit) reads the copy before it
    /// stages the commit object, so the size of the commit itself is never in
    /// it. `write_commit` looks up each reachable object in the copy. It reads
    /// the sizes of an object that it does not find from disk: an object that
    /// was a dedup hit against `objects/`. So in a transaction with many
    /// commits, each commit gets its own key, limited to its reachable objects.
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

    /// Counts one content object that a devino-cache hit skipped.
    pub(crate) fn note_devino_hit(&self) {
        self.staged.lock().unwrap().stats.devino_cache_hits += 1;
    }

    /// Counts one entry that a commit-modifier filter excluded.
    pub(crate) fn note_filtered(&self) {
        self.staged.lock().unwrap().stats.filtered += 1;
    }

    /// Returns `true` if an object of this identity and type is staged in this
    /// transaction.
    ///
    /// A staged object is in the staging directory and is not yet published
    /// into `objects/`.
    pub(crate) fn is_staged(&self, checksum: &Checksum, ty: ObjectType) -> bool {
        self.staged
            .lock()
            .unwrap()
            .objects
            .contains_key(&(*checksum, ty))
    }

    /// Returns the checksums of the objects of type `ty` staged in this
    /// transaction.
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

    /// Loads a file object from the staged set of this transaction, or else
    /// from `objects/`.
    ///
    /// The read and merge paths of a staging tree use it, so they see the
    /// content staged in this transaction before it publishes.
    pub(crate) async fn load_file_staged_first(
        &self,
        checksum: &Checksum,
    ) -> Result<crate::file::FileObject> {
        self.load_file_staged_first_with(checksum, false).await
    }

    /// Loads a file object as [`load_file_staged_first`] does, with the
    /// `measure` flag of [`Repo::load_file_with`].
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

    /// Loads a dirtree object from the staged set of this transaction, or else
    /// from `objects/`.
    ///
    /// It does for the right side of the merge path what
    /// [`load_file_staged_first`] does for files. So the merge sees a dirtree
    /// staged in this transaction before it publishes.
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

    /// Loads a dirmeta object from the staged set of this transaction, or else
    /// from `objects/`.
    ///
    /// It does for the directory metadata of a staged tree what
    /// [`load_dirtree_staged_first`](Self::load_dirtree_staged_first) does for
    /// dirtrees.
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

    /// Lists one directory of a tree that this transaction staged.
    ///
    /// The call reads the objects that this transaction staged first, and then
    /// `objects/`. A caller can use it to derive commit metadata from a tree
    /// before the transaction commit.
    ///
    /// [`RepoTree::read_dir`](crate::RepoTree::read_dir) reads `objects/`
    /// alone, so it sees a tree only after the transaction commit. The order of
    /// the entries is the same in both calls: files first, then subdirectories,
    /// each group sorted by name.
    ///
    /// Before the transaction commit, `RepoTree::read_dir` on a
    /// [`TreeEntry::Dir`](crate::TreeEntry::Dir) of a staged tree fails with
    /// [`Error::ObjectNotFound`]. This method reads such an entry.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the dirtree of `tree` is not staged and
    ///   not in `objects/`.
    /// - [`Error::Io`] if the read of the dirtree fails, or if the dirtree is
    ///   larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    /// - [`Error::Core`] if the dirtree does not parse.
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

    /// Queues the detached metadata of a commit that this transaction writes.
    ///
    /// `meta` is an `a{sv}` dict. It replaces the detached metadata that the
    /// repository stores for `checksum`. The write happens at
    /// [`commit`](Transaction::commit), after the staged objects publish and
    /// before the queued ref writes. So the commit and its detached metadata are
    /// durable before a ref names them.
    ///
    /// If the call runs twice for one checksum, the last dict stays. The call
    /// also drops the signatures that [`sign_commit`](Transaction::sign_commit)
    /// queued before it.
    pub fn set_commit_detached_metadata(&self, checksum: &Checksum, meta: Value) {
        let mut queue = self.detached.lock().unwrap();
        let edit = Self::edit_for(&mut queue, checksum);
        edit.staged = None;
        edit.replace = Some(meta);
        edit.merge = None;
        edit.appends.clear();
    }

    /// Stages `bytes`, the serialized detached metadata of `checksum`, to
    /// replace the stored detached metadata.
    ///
    /// A pull copies the `.commitmeta` of a source byte for byte through this
    /// call. The bytes go to a file in the staging directory at once, so the
    /// queue holds no copy of them.
    ///
    /// At [`commit`](Transaction::commit) the write renames the file over the
    /// `.commitmeta` of `checksum`. The rename comes after the staged objects
    /// publish and before the queued ref writes. With fsync on, the file is
    /// durable before the rename. The `syncfs` of the publication step covers
    /// it, and if that step runs no `syncfs`, the write runs one of its own.
    ///
    /// A transaction that does not commit leaves the stored file unchanged. A
    /// second stage for one checksum replaces the file. As
    /// [`set_commit_detached_metadata`](Transaction::set_commit_detached_metadata)
    /// does, the call drops the edits queued for `checksum` before it.
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

    /// Queues a merge of `incoming`, the bytes of an `a{sv}` dict, into the
    /// detached metadata of `checksum`.
    ///
    /// At [`commit`](Transaction::commit) the write reads the stored dict and
    /// parses `incoming`. It merges `incoming` into the stored dict under the
    /// process-wide guard of detached-metadata edits:
    ///
    /// - Each signature list gets the union of the stored and the incoming list.
    /// - A key of `keep` that the stored dict holds keeps the stored value.
    /// - Each other key takes the incoming value.
    ///
    /// The signatures that [`append_signature`](Transaction::append_signature)
    /// queues come after the merge. If the call runs twice for one checksum, the
    /// last dict and its `keep` stay.
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

    /// Queues `signature`, made before this call, for the engine metadata key
    /// `key` of the detached metadata of `checksum`.
    ///
    /// The write at [`commit`](Transaction::commit) appends it as it appends a
    /// signature from [`sign_commit`](Transaction::sign_commit).
    #[cfg(feature = "receive")]
    pub(crate) fn append_signature(&self, checksum: &Checksum, key: &str, signature: Vec<u8>) {
        let mut queue = self.detached.lock().unwrap();
        Self::edit_for(&mut queue, checksum)
            .appends
            .push((key.to_owned(), signature));
    }

    /// Signs a commit that this transaction wrote and queues the signature.
    ///
    /// The signature goes into the detached metadata of the commit. The
    /// payload is the canonical bytes of the commit object. The call reads them
    /// from the staging directory if the object is staged, and from `objects/`
    /// if the repository holds the object already.
    ///
    /// The signature appends to the `aay` array of the engine, in the first of
    /// these dicts that exists:
    ///
    /// 1. The dict that
    ///    [`set_commit_detached_metadata`](Transaction::set_commit_detached_metadata)
    ///    queued.
    /// 2. The dict that the repository stores at the time of the write.
    /// 3. An empty dict.
    ///
    /// The call writes nothing to the file system. The signing step comes
    /// before the object publication and the ref writes. So a signer failure
    /// fails the transaction before it publishes an object or moves a ref.
    ///
    /// # Concurrent signers
    ///
    /// The queue step takes one lock and holds no await. The call makes the
    /// signature here, before it takes a lock of the commit.
    ///
    /// The write at [`commit`](Transaction::commit) reads, merges, and replaces
    /// the file under the update lock. So each signature that tasks or
    /// processes make for one commit reaches the file: from one transaction,
    /// from concurrent transactions, and from [`Repo::sign_commit`]. The
    /// `ostree` command can lose a signature in that case.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the commit is not staged and not in
    ///   `objects/`.
    /// - [`Error::Io`] if the read of the commit object fails, or if the object
    ///   is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    /// - [`Error::Signature`] if `signer` cannot make a signature. An error of
    ///   a signer can also convert to [`Error::InvalidFormat`] or
    ///   [`Error::Core`].
    pub async fn sign_commit(&self, checksum: &Checksum, signer: &dyn crate::Signer) -> Result<()> {
        let payload = self.load_commit_bytes_staged_first(checksum).await?;
        let signature = signer.sign(&payload).await?;
        let mut queue = self.detached.lock().unwrap();
        Self::edit_for(&mut queue, checksum)
            .appends
            .push((signer.metadata_key().to_owned(), signature));
        Ok(())
    }

    /// Returns the queued edit of `checksum`, and adds an empty edit if the
    /// queue holds none.
    fn edit_for<'a>(queue: &'a mut DetachedQueue, checksum: &Checksum) -> &'a mut DetachedEdit {
        let edits = &mut queue.edits;
        let index = *queue.index.entry(*checksum).or_insert_with(|| {
            edits.push((*checksum, DetachedEdit::default()));
            edits.len() - 1
        });
        &mut edits[index].1
    }

    /// Loads the canonical bytes of a commit object from the staged set of
    /// this transaction, or else from `objects/`, as the other staged-first
    /// readers do.
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

    /// Takes the queued detached-metadata edits for [`DetachedJob::run`].
    ///
    /// The job applies them between publication and the ref writes, under the
    /// fsync policy of the transaction. `synced` is `true` if the publication
    /// step ran its `syncfs`, which also makes the staged files durable.
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

    /// Stages a regular-file content object whose payload is in `file`
    /// already.
    ///
    /// [`ContentWriter::finish`](crate::ContentWriter::finish) calls it. If
    /// `counted` is `true`, the payload adds to
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

    /// Stages a symlink content object.
    ///
    /// [`write_symlink`](Transaction::write_symlink) calls it.
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

    /// Stages a metadata object from its serialized bytes.
    ///
    /// [`write_metadata`](Transaction::write_metadata) calls it.
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

    /// Stages a metadata object as
    /// [`stage_metadata`](Transaction::stage_metadata) does.
    ///
    /// Returns `true` if the call wrote the object, and `false` if the
    /// repository holds it already.
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

    /// Imports one object from the `objects/` directory of another local
    /// repository with a hardlink, which shares the source inode.
    ///
    /// The two repositories must store the object in the same form. The source
    /// inode must have the ownership that a write here gives already.
    /// [`stage_import_blocking`] states the rules. The local pull path calls
    /// this method.
    ///
    /// Returns `true` if the object is staged. `false` is a content object
    /// whose link the call refused. The caller then imports it through the
    /// logical header of the object. A metadata object is always staged, by
    /// link or by copy.
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
        // The ownership that a link must match. The call measures it only if it
        // tries a link. The measure creates and removes a staging temporary,
        // and a forced copy or a sealing repository never reads the result.
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
        // An imported object has no size record. A pull writes no commit, so
        // this transaction never writes `ostree.sizes`. The call also never
        // reads the payload, so the unpacked length is not known.
        self.record_object(checksum, ty, mode, outcome, false, false, false)?;
        Ok(true)
    }

    /// Imports one regular-file content object from another local repository
    /// with a clone of its payload.
    ///
    /// The call applies the inode policy of this repository from the logical
    /// header of the object. The two modes must store the payload in the same
    /// form. [`stage_clone_content_blocking`] states the rules. The local pull
    /// path calls this method.
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
        // An imported object has no size record. A pull writes no commit, so
        // this transaction never writes `ostree.sizes`.
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

    /// Records the outcome of a staged object.
    ///
    /// The call takes the blocks that the object allocated from the free-space
    /// budget, adds the object to the staged set, and updates the statistics.
    /// The call is idempotent by identity, so a second stage of an object that
    /// is staged in this transaction does nothing.
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

    /// Records the outcome of a staged object, as [`record`](Transaction::record)
    /// does, with all flags.
    ///
    /// - `with_size`: the object adds an archive size record. An import adds
    ///   none, because the pull that imports it writes no commit to carry one.
    /// - `payload`: the object is a regular-file content object. Its unpacked
    ///   length adds to
    ///   [`content_bytes_unpacked`](TransactionStats::content_bytes_unpacked).
    ///   A symlink and a metadata object add none.
    /// - `synced`: the file of the object was synced on its own after
    ///   `sync_staged`. The count of durable objects then includes it.
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
        // The totals count each object offered, dedup hits included. They are
        // the work that the caller asked for.
        if ty == ObjectType::File {
            staged.stats.content_total += 1;
        } else {
            staged.stats.metadata_total += 1;
        }
        // An object that the object store holds already is inside the
        // `ostree.sizes` scope, as a freshly staged one is. `write_commit` reads
        // its sizes from disk.
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
        // that shares the source inode by hardlink allocates nothing. An object
        // whose payload came from a `FICLONE` reflink shares the source extents.
        // So neither reduces the bytes free on the file system.
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

    /// Returns the `fsync` and `per-object-fsync` values of the transaction.
    ///
    /// Each value comes from its override, from
    /// [`set_fsync`](Transaction::set_fsync) or
    /// [`set_per_object_fsync`](Transaction::set_per_object_fsync), if the
    /// transaction has one. Else it comes from the repository config. Each write
    /// path of the transaction reads this pair: the per-object writes, the
    /// publication step, the detached-metadata writes, and the ref writes.
    ///
    /// The call reads `[core] fsync` and `[core] per-object-fsync` in all
    /// cases, also when an override is set. So each transaction reports a value
    /// that the reader refuses, and an override never hides it.
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

    /// Returns the `[ex-integrity] fsverity` value of the repository config.
    ///
    /// The stage of each regular-file object applies it.
    fn verity(&self) -> Result<Tristate> {
        self.repo.config().fsverity()
    }

    /// Publishes the staged objects into `objects/` and writes the queued refs.
    ///
    /// # Sequence
    ///
    /// 1. The call checks each queued refspec. If a refspec is malformed, the
    ///    call fails before it publishes an object, and it writes nothing.
    /// 2. The call renames each staged object into `objects/<xx>/`.
    /// 3. The call writes the queued detached-metadata edits.
    /// 4. The call writes the queued refs. Each ref write is atomic: a temp
    ///    file, then a rename. The set of ref writes is not atomic as a whole.
    /// 5. The call removes the staging directory and releases the repository
    ///    lock.
    ///
    /// Steps 3 and 4 run in one trip to the blocking pool.
    ///
    /// # Durability
    ///
    /// One fsync policy applies to all steps: the value from
    /// [`set_fsync`](Transaction::set_fsync), or else `[core] fsync` of the
    /// repository config. With fsync on, the call syncs as follows:
    ///
    /// - Before the renames of step 2, it runs `syncfs` on the repository.
    /// - After the renames, it runs `fsync` on each fanout directory that got
    ///   an object, and on `objects/`.
    /// - Before the rename of each ref, it runs `fdatasync` on the temp file.
    /// - After the last ref rename, it runs `fsync` once on each directory that
    ///   gained or lost a ref name, deepest first.
    ///
    /// With this sequence, a commit and its `.commitmeta` are durable before a
    /// ref names them. Each ref is durable when the call returns. With fsync
    /// off, no step syncs.
    ///
    /// # Locks
    ///
    /// The transaction holds the repository lock from its begin to the end of
    /// this call, in the [`LockKind`](crate::LockKind) of its begin. Step 2
    /// runs with no update lock.
    ///
    /// If the transaction writes a ref, a ref removal included, or detached
    /// metadata, the call takes the update lock for steps 3 and 4. The update
    /// lock excludes the other writers of refs and detached metadata, as
    /// [`UpdateGuard`](crate::UpdateGuard) states. The wait is for the update
    /// lock alone, because the transaction holds the repository lock already. A
    /// transaction that writes neither does not take the update lock.
    ///
    /// # Cancellation
    ///
    /// The update lock, the repository lock, and the staging directory move
    /// into the blocking closure of steps 3 and 4. The closure releases them
    /// when its writes end. If a caller drops the returned future, the writes
    /// complete, and the locks and the staged files stay until the writes end.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if a queued refspec is malformed. The call
    ///   publishes no object.
    /// - [`Error::LockTimeout`] if the wait for the update lock passes
    ///   `[core] lock-timeout-secs`. The published objects stay, and the call
    ///   writes no detached metadata and no ref.
    /// - [`Error::Core`] if `[core] fsync`, `[core] per-object-fsync`, or
    ///   `[core] lock-timeout-secs` has a value that does not parse.
    /// - [`Error::Core`] if the stored detached metadata of a commit does not
    ///   parse.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is less than
    ///   `-1`, or if a signature entry of the stored detached metadata is not
    ///   an array.
    /// - [`Error::Io`] if a rename, a sync, or a write of a ref or of the
    ///   detached metadata fails.
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

    /// Commits the transaction as [`commit`](Transaction::commit) does, under
    /// the update lock that the caller holds.
    ///
    /// The reference to the hold makes a call without the lock a type error.
    /// The call does not take the lock again.
    pub(crate) async fn commit_under(self, held: &UpdateLockHeld) -> Result<TransactionStats> {
        debug_assert!(
            self.repo.holds_update_lock(held),
            "the hold is not the update lock of this repository"
        );
        let refs = self.resolve_ref_queue()?;
        let synced = self.publish().await?;
        self.write_tail(refs, synced, None).await
    }

    /// Writes the queued detached metadata and then `refs`, removes the
    /// staging directory, and releases the locks, in one trip to the blocking
    /// pool.
    ///
    /// `synced` is `true` if the publication step ran its `syncfs`. The staging
    /// directory, the repository lock, and `held`, if given, move into the
    /// blocking closure. The closure releases the update lock after the last
    /// ref write, then removes the staging directory, then releases the
    /// repository lock.
    ///
    /// The move makes sure that a caller that drops the returned future cannot
    /// release a lock or remove a staged file while the writes run.
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
        let staging = self
            .staging
            .take()
            .expect("staging directory present during the transaction");
        let lock = self.lock;
        ostrya_rt::unblock(move || {
            #[cfg(test)]
            test_tail::pass(repo_fd.as_fd());
            let tmp_fd = staging.tmp_fd();
            let written = detached.run(tmp_fd).and_then(|()| {
                crate::refs::write_resolved_refs_blocking(
                    repo_fd.as_fd(),
                    tmp_fd,
                    &refs,
                    fsync,
                    repo_mode,
                )
            });
            drop(held);
            drop(staging);
            drop(lock);
            written
        })
        .await?;
        Ok(stats)
    }

    /// Makes the objects staged so far durable before
    /// [`commit`](Transaction::commit).
    ///
    /// With fsync on, the call runs one `syncfs` of the repository. The
    /// publication step of `commit` then runs no `syncfs` of its own, unless an
    /// object was staged after this call. With fsync off, the call does
    /// nothing.
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

    /// Returns `true` if the publication step runs its `syncfs`.
    ///
    /// The step runs it with fsync on, unless `sync_staged` made each staged
    /// object durable already.
    fn syncfs_at_publish(&self, fsync: bool) -> bool {
        let staged = self.staged.lock().unwrap();
        fsync && staged.presynced != Some(staged.objects.len())
    }

    /// Discards the transaction and its staged objects, and releases the lock.
    ///
    /// # Errors
    ///
    /// The call does not fail. It always returns `Ok(())`.
    pub async fn abort(mut self) -> Result<()> {
        self.reap_staging().await;
        Ok(())
    }

    /// Renames each staged object into `objects/` on the blocking pool.
    ///
    /// Returns `true` if the step ran its `syncfs`.
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

    /// Removes the staging directory on the blocking pool, if it is still
    /// present.
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
    /// `true` if the staged files are durable already, from the `syncfs` of
    /// the publication step.
    staged_durable: bool,
    repo_mode: RepoMode,
    objects_fd: std::os::fd::OwnedFd,
    staging_fd: std::os::fd::OwnedFd,
}

impl DetachedJob {
    /// Applies the edits.
    ///
    /// The call installs the staged files first, in one step. The rest of the
    /// edit of each commit then applies to its installed file. With fsync on,
    /// if the publication step ran no `syncfs`, a `syncfs` makes the staged
    /// files durable before the install.
    ///
    /// The call writes each other edit before the next one starts, and with
    /// fsync on it makes the edit durable first. Each edit takes the
    /// process-wide guard of detached-metadata edits for itself alone.
    ///
    /// `tmp_fd` is the open `tmp/` of the repository, where each edit creates
    /// its temp file. The caller holds the update lock.
    fn run(self, tmp_fd: BorrowedFd<'_>) -> Result<()> {
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
                tmp_fd,
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

/// A gate for the unit tests, at the commit step that writes detached metadata
/// and refs.
///
/// A test arms the gate for one repository root. The next such step of a
/// commit of that repository then reports that it started, and waits until the
/// test opens the gate.
#[cfg(test)]
mod test_tail {
    use std::os::fd::BorrowedFd;
    use std::sync::Mutex;
    use std::sync::mpsc::{Receiver, Sender, channel};

    type Gate = ((u64, u64), Sender<()>, Receiver<()>);

    static GATES: Mutex<Vec<Gate>> = Mutex::new(Vec::new());

    /// Arms the gate for the repository root `root`, and returns the receiver
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

    /// Reports the start and waits for the gate, if a gate is armed for the
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
    /// counted as durable. So the anchor commit that a receiving session stages
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

    /// A queued merge runs on the stored dict before the queued signatures.
    /// The signature lists get the union, another key takes the incoming
    /// value, and a stored key that the incoming dict does not hold stays.
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

    /// If the clone path cannot open a source object because it is gone, the
    /// error reports the object as missing. The link path gives the same
    /// answer for the same condition.
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
    /// keeps the repository lock until that step ends. So an exclusive holder,
    /// for example a prune, cannot start before the ref is written.
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
