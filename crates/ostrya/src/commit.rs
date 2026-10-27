//! Commit objects and the detached metadata of a commit.
//!
//! - [`Transaction::write_commit`] stages a commit object over a root tree,
//!   with the options in [`CommitOptions`].
//! - [`Repo::read_commit_detached_metadata`] and
//!   [`Repo::write_commit_detached_metadata`] read and write the detached
//!   metadata of a commit.
//! - [`Repo::read_commit_related`] reads the related commits of a commit:
//!   the dependencies and the build sources.
//! - [`Repo::add_detached_related`] adds a build source to a commit.

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd};

use ostrya_core::sizes::SizeEntry;
use ostrya_core::{
    Checksum, Commit, DirTree, ObjectType, RepoMode, Type, Value, loose_path, to_bytes,
};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::config::RepoConfig;
use crate::error::{Error, Result};
use crate::file::FileKind;
use crate::perm;
use crate::related::{self, CommitRelated, RelatedField};
use crate::repo::Repo;
use crate::staging::{META_TEMP_PREFIX, TempEntry, open_tmp_dir};
use crate::transaction::Transaction;
use crate::tree::RepoTree;

pub use ostrya_core::commit_metadata;

/// The type string of a metadata dict: the detached metadata, and the commit
/// metadata inside the commit tuple.
const METADATA_SIGNATURE: &str = "a{sv}";
/// The type of the `ostree.sizes` value: an array of packed byte buffers.
const SIZES_SIGNATURE: &str = "aay";
/// The metadata key of the size records.
const SIZES_KEY: &str = "ostree.sizes";
/// The permission bits of a `.commitmeta` file: the `0644` of each metadata
/// object.
const COMMITMETA_MODE: u32 = 0o644;

/// The options of [`Transaction::write_commit`].
///
/// Each field is optional. If `metadata` is set, it must be an `a{sv}` dict
/// value. Its entries appear in the commit in insertion order. A caller that
/// reproduces a commit of the `ostree` command byte for byte supplies the
/// binding keys in the observed order of that command.
#[derive(Debug, Default, Clone)]
pub struct CommitOptions {
    /// The parent commit, or `None` for a root commit.
    pub parent: Option<Checksum>,
    /// The subject of the commit, or an empty string if `None`.
    pub subject: Option<String>,
    /// The body of the commit, or an empty string if `None`.
    pub body: Option<String>,
    /// The commit time in seconds since the Unix epoch, UTC.
    ///
    /// If the value is `None` and `SOURCE_DATE_EPOCH` is set, the commit uses
    /// that variable. If both are absent, the commit uses the current time.
    pub timestamp: Option<u64>,
    /// The `a{sv}` metadata dict, or `None` for an empty dict.
    pub metadata: Option<Value>,
    /// The dependencies of the commit: the name and the checksum of each
    /// commit that field 2 of the commit object names.
    ///
    /// The name has the form `<class>/<name>` by convention, for example
    /// `container/fe`. The write sorts the entries by name in byte order, so
    /// one set of entries gives one commit checksum. It refuses an empty name
    /// and two entries with the same name. Each dependency must be complete
    /// in the repository or in the writing transaction, and must have no
    /// dependency of its own. [`Transaction::write_commit`] states the rule.
    ///
    /// A local prune keeps the dependencies of each commit that it reaches.
    /// [`Repo::prune`], "Related commits", states the rules.
    pub related: Vec<(String, Checksum)>,
}

/// Methods that write a commit object.
impl Transaction {
    /// Stages a commit object over the tree `root` and returns its checksum.
    ///
    /// The call stages the commit in the same way as other metadata objects.
    /// The root dirtree and the root dirmeta come from `root`. The other
    /// fields come from `opts`.
    ///
    /// The metadata dict is `opts.metadata`, or an empty dict if it is `None`.
    /// The call adds no key of its own except `ostree.sizes`. The binding keys
    /// `ostree.ref-binding` and `ostree.collection-binding` are normal
    /// metadata entries that the caller supplies.
    ///
    /// # `ostree.sizes`
    ///
    /// The commit gets the `ostree.sizes` key if the transaction generates
    /// sizes and the repository is in archive mode. A file system ingest under
    /// [`GENERATE_SIZES`](crate::CommitModifierFlags::GENERATE_SIZES) turns
    /// size generation on. [`set_generate_sizes`](Transaction::set_generate_sizes)
    /// sets it for the whole transaction.
    ///
    /// The key is the last metadata entry, as in a commit of the `ostree`
    /// command. Its records cover the objects that the committed root reaches,
    /// and no other objects:
    ///
    /// - the root dirmeta
    /// - each dirtree
    /// - each subdirectory dirmeta
    /// - each file entry
    ///
    /// The commit object is not in the list, because the walk starts below it.
    /// If a transaction stages more than one commit, the key of each commit
    /// holds the objects that this commit reaches. If the caller uses
    /// [`begin_tree_source`](Transaction::begin_tree_source), the key holds the
    /// objects of the last tree source and the directory objects.
    ///
    /// The call walks the committed tree at commit time. An object that the
    /// transaction staged uses the size record that the transaction kept. An
    /// object that deduplicated against `objects/` gets its sizes from its
    /// loose object. As in a commit of the `ostree` command, an incremental
    /// commit also lists the objects that existed before.
    ///
    /// In each other mode the call writes no key. The bytes of the commit are
    /// the same with and without the request.
    ///
    /// # GC anchor keys
    ///
    /// If `opts.metadata` holds at least one entry, the call reads the
    /// repository config key `[ex-ostrya] gc-root-metadata-keys`
    /// ([`RepoConfig::gc_root_metadata_keys`]). It checks each entry whose key
    /// is in that list with the rules of a prune: the value is an `aay`, an
    /// `a(say)`, or an `a{s(say)}`, and each checksum in it is 32 bytes. A
    /// checksum that names no commit in the store passes. The call checks
    /// each entry, also when a key occurs more than one time.
    ///
    /// The call checks before it serializes the commit and writes nothing on
    /// a refusal. The transaction stays open, and the caller commits or aborts
    /// it. The call does not check the `ostree.sizes` entry that it adds.
    ///
    /// # Dependencies
    ///
    /// Field 2 of the commit object holds the entries of `opts.related`,
    /// sorted by name in byte order. The call refuses an entry with an empty
    /// name and two entries with the same name. It checks nothing else in a
    /// name.
    ///
    /// Each dependency must be complete: this transaction stages its commit
    /// object or the repository holds it, and the repository holds no
    /// `state/<checksum>.commitpartial` marker for it. A dependency that this
    /// transaction writes must be staged before the call that names it. A
    /// dependency must have no dependency of its own, so a dependency names
    /// no dependency. It can have a parent and build sources.
    ///
    /// The call checks the dependencies as
    /// [`check_related`](Transaction::check_related) does, after the GC anchor
    /// keys and the timestamp and before it serializes the commit. On a
    /// refusal, it writes nothing and the transaction stays open.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`.
    /// - [`Error::InvalidGcAnchor`] if an entry of `opts.metadata` gives a key
    ///   of `[ex-ostrya] gc-root-metadata-keys` a value that a prune refuses.
    /// - [`Error::InvalidRelated`] if an entry of `opts.related` has an empty
    ///   name, if two entries have the same name, or if a dependency is
    ///   absent, partial, or has a dependency of its own.
    /// - [`Error::Core`] if the commit tuple of a dependency does not frame,
    ///   or if its field 2 does not decode.
    /// - [`Error::Core`] if `opts.metadata` holds at least one entry and
    ///   `[ex-ostrya] gc-root-metadata-keys` holds a malformed escape
    ///   sequence.
    /// - [`Error::Unsupported`] if `[ex-integrity] fsverity` is `yes` and the
    ///   fs-verity seal fails.
    /// - [`Error::InvalidFormat`] if `opts.timestamp` is `None` and
    ///   `SOURCE_DATE_EPOCH` is not a count of seconds.
    /// - [`Error::InvalidFormat`] if the call reads the system clock and the
    ///   clock is before the Unix epoch.
    /// - [`Error::InvalidFormat`] if the call adds `ostree.sizes` and
    ///   `opts.metadata` is not an array value.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::Core`] if the commit does not serialize: `opts.metadata` is
    ///   not an `a{sv}` dict, a string holds an interior NUL byte, or the
    ///   metadata nests too deep.
    /// - [`Error::Core`] if `[core] fsync` or `[core] per-object-fsync` in the
    ///   repository config is malformed.
    /// - [`Error::Core`] if the call adds `ostree.sizes` and a dirtree that
    ///   the commit reaches does not parse.
    /// - [`Error::ObjectNotFound`] if the call adds `ostree.sizes` and an
    ///   object that the commit reaches is in neither the staging directory
    ///   nor `objects/`.
    /// - The errors of [`load_file`](Repo::load_file) if the call adds
    ///   `ostree.sizes` and a file object from `objects/` does not load.
    /// - [`Error::InsufficientFreeSpace`] if the commit object needs more
    ///   space than the free-space budget of the transaction holds.
    /// - [`Error::Io`] if the call adds `ostree.sizes` and a dirtree that the
    ///   commit reaches is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn write_commit(&self, mut opts: CommitOptions, root: &RepoTree) -> Result<Checksum> {
        if self.repo().mode() == RepoMode::BareSplitXattrs {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
        check_gc_anchors(self.repo().config(), opts.metadata.as_slice())?;
        let timestamp = ostrya_core::commit_timestamp(opts.timestamp)
            .map_err(|e| Error::InvalidFormat(e.to_string()))?;
        opts.timestamp = Some(timestamp);
        self.check_related(&opts.related).await?;
        opts.related.sort_by(|(a, _), (b, _)| a.cmp(b));
        self.write_commit_unchecked(opts, root).await
    }

    /// Checks the dependencies `related` of a new commit, as
    /// [`write_commit`](Transaction::write_commit) checks
    /// [`CommitOptions::related`].
    ///
    /// The call refuses an entry with an empty name and two entries with the
    /// same name. Then it checks each dependency in the byte order of the
    /// names: the dependency must be complete in the repository or in this
    /// transaction, and it must have no dependency of its own.
    /// [`write_commit`](Transaction::write_commit) states the rules and runs
    /// the same checks. The call does not change `related` and writes
    /// nothing.
    ///
    /// The call reads no tree. A caller can call it before it builds a large
    /// tree, so that a refused dependency stops the work before the build.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRelated`] with no commit, if an entry of `related`
    ///   has an empty name, if two entries have the same name, or if a
    ///   dependency is absent, partial, or has a dependency of its own.
    /// - [`Error::Core`] if the commit tuple of a dependency does not frame,
    ///   or if its field 2 does not decode.
    /// - [`Error::Io`] if the commit object of a dependency is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), or if a file system
    ///   operation fails.
    pub async fn check_related(&self, related: &[(String, Checksum)]) -> Result<()> {
        let sorted = related::sorted_new(related)?;
        related::check_dependencies(self, None, sorted).await
    }

    /// Writes a commit as [`write_commit`](Transaction::write_commit) does,
    /// with no check of the GC anchor keys or the dependencies.
    ///
    /// Field 2 holds the entries of `opts.related` in the given order. The
    /// anchor commit of a summary uses this path, because the port builds its
    /// binding keys, and it has no dependency. A `bare-split-xattrs`
    /// repository refuses the write in
    /// [`write_metadata`](Transaction::write_metadata).
    pub(crate) async fn write_commit_unchecked(
        &self,
        opts: CommitOptions,
        root: &RepoTree,
    ) -> Result<Checksum> {
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
            related: opts
                .related
                .into_iter()
                .map(|(name, checksum)| (name, checksum.as_bytes().to_vec()))
                .collect(),
            subject: opts.subject.unwrap_or_default(),
            body: opts.body.unwrap_or_default(),
            timestamp,
            root_dirtree: *root.dirtree_checksum(),
            root_dirmeta: *root.dirmeta_checksum(),
        };
        let bytes = commit.serialize()?;
        self.write_metadata(ObjectType::Commit, None, &bytes).await
    }

    /// Builds the `ostree.sizes` entries for `root`.
    ///
    /// The list has one record for each object that the committed root
    /// reaches. It holds the objects that this transaction staged and the
    /// objects that deduplicated against `objects/`. A staged object uses the
    /// size record that the transaction kept. A deduplicated object gets its
    /// sizes from its loose object. The commit object is not in the list,
    /// because the walk starts below it.
    async fn reachable_size_entries(&self, root: &RepoTree) -> Result<Vec<SizeEntry>> {
        let reachable = self.reachable_objects(root).await?;
        let staged: HashMap<Checksum, SizeEntry> = self
            .size_entries()
            .into_iter()
            .map(|entry| (entry.checksum, entry))
            .collect();
        let mut entries = Vec::with_capacity(reachable.len());
        for (checksum, ty) in reachable {
            // If a commit comes from several tree sources, the key holds the
            // objects of the last source and the directory objects that the
            // serialization wrote. See `Transaction::begin_tree_source`.
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

    /// Returns the `ostree.sizes` entry of an object that deduplicated against
    /// `objects/`.
    ///
    /// The object has no size record from this transaction. The call serves
    /// archive mode only. The compressed size is the size of the loose object
    /// on disk. The unpacked size is:
    ///
    /// - the serialized length of a metadata object
    /// - the uncompressed payload length of a regular file
    /// - the target length of a symlink
    async fn recover_size_entry(&self, checksum: Checksum, ty: ObjectType) -> Result<SizeEntry> {
        let compressed = self.repo().loose_object_size(ty, &checksum).await?;
        let unpacked = if ty == ObjectType::File {
            match self.repo().load_file(&checksum).await?.kind {
                FileKind::Regular { size } => size,
                FileKind::Symlink { target } => target.len() as u64,
            }
        } else {
            // A metadata object is stored uncompressed, so its unpacked size
            // is its size on disk.
            compressed
        };
        Ok(SizeEntry {
            checksum,
            compressed,
            unpacked,
            objtype: Some(ty),
        })
    }

    /// Returns the objects that `root` reaches, each with its type.
    ///
    /// The map holds the root dirmeta, each dirtree of the committed tree, each
    /// subdirectory dirmeta, and each file entry. It limits `ostree.sizes` to
    /// the objects of one commit, also if the transaction stages more than one
    /// commit.
    ///
    /// The walk goes into each subtree, staged or not.
    /// [`load_reachable_dirtree`](Self::load_reachable_dirtree) reads a dirtree
    /// from the staging directory of the transaction if it is there. If the
    /// dirtree deduplicated, it reads the loose object in `objects/`. This
    /// read order lets the walk visit the objects of an unchanged subtree.
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

    /// Loads a dirtree that the committed root reaches.
    ///
    /// The call reads the staging directory of the transaction first. If the
    /// dirtree deduplicated, the call reads the loose object in `objects/`.
    async fn load_reachable_dirtree(&self, checksum: &Checksum) -> Result<DirTree> {
        if let Some(dirtree) = self.load_staged_dirtree(checksum).await? {
            return Ok(dirtree);
        }
        self.repo().load_dirtree(checksum).await
    }

    /// Loads a dirtree from the staging directory of this transaction.
    ///
    /// Returns `None` if the dirtree is not there, because it deduplicated
    /// against `objects/`.
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

/// Methods that read and write the detached metadata of a commit.
impl Repo {
    /// Returns the detached metadata of a commit, or `None` if it has none.
    ///
    /// The detached metadata is an `a{sv}` dict at the `.commitmeta` loose
    /// path of the commit. It is outside the commit checksum. The call returns
    /// `None` if the file is absent, or if it is the zero-length file that
    /// marks no metadata. The call reads and parses the file on the blocking
    /// pool.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if the file does not parse as an `a{sv}` dict.
    /// - [`Error::Io`] if the file is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), or if a file system
    ///   operation fails.
    pub async fn read_commit_detached_metadata(
        &self,
        checksum: &Checksum,
    ) -> Result<Option<Value>> {
        let repo = self.clone();
        let key = *checksum;
        ostrya_rt::unblock(move || repo.read_commit_detached_metadata_blocking(&key)).await
    }

    /// Returns the related commits of the commit `commit`.
    ///
    /// The dependencies come from field 2 of the commit object. The build
    /// sources come from the key `ostrya.related` of the detached metadata.
    /// If the detached metadata is absent or has no such key, the list of
    /// build sources is empty. If the key occurs more than one time, the
    /// first entry gives the value. Each list keeps the stored order.
    ///
    /// The call checks the format alone: each entry has a name that is not
    /// empty and a checksum of 32 bytes, and the value of `ostrya.related`
    /// is a variant of type `a(say)`. It accepts entries that are not sorted
    /// and two entries with the same name. It does not check that the
    /// repository holds a related commit. The checks of the dependencies of
    /// [`Transaction::write_commit`] apply when a commit is written.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the repository does not hold the commit
    ///   object.
    /// - [`Error::Core`] if the commit tuple does not frame, if field 2 does
    ///   not decode, or if the detached metadata does not parse.
    /// - [`Error::InvalidRelated`] with the field and the reason, if an entry
    ///   of either field has an empty name or a checksum that is not 32
    ///   bytes, or if the value of `ostrya.related` is not a variant of type
    ///   `a(say)`.
    /// - [`Error::Io`] if the commit object or the detached metadata is
    ///   larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), or if a
    ///   file system operation fails.
    pub async fn read_commit_related(&self, commit: &Checksum) -> Result<CommitRelated> {
        let repo = self.clone();
        let commit = *commit;
        // A commit object can be as large as `MAX_METADATA_SIZE`, so the two
        // reads and the parse run in one call on the blocking pool. The read
        // of the commit comes first, then the read of the `.commitmeta`, then
        // the parse.
        ostrya_rt::unblock(move || {
            let bytes = repo.load_object_bytes_blocking(ObjectType::Commit, &commit)?;
            let detached = repo.read_commit_detached_metadata_blocking(&commit)?;
            let dependencies = related::checked_entries(
                RelatedField::Dependencies,
                Some(commit),
                related::parse_dependencies(&bytes)?,
            )?;
            let build_sources = related::build_sources(detached.as_ref())
                .map_err(|reason| Error::InvalidRelated {
                    commit: Some(commit),
                    field: RelatedField::BuildSources,
                    reason,
                })?
                .map(|entries| {
                    related::checked_entries(RelatedField::BuildSources, Some(commit), entries)
                })
                .transpose()?
                .unwrap_or_default();
            Ok(CommitRelated {
                dependencies,
                build_sources,
            })
        })
        .await
    }

    /// Runs
    /// [`read_commit_detached_metadata`](Repo::read_commit_detached_metadata)
    /// on the calling thread.
    ///
    /// The read and the parse block the thread, so an async caller runs this
    /// call on the blocking pool.
    pub(crate) fn read_commit_detached_metadata_blocking(
        &self,
        checksum: &Checksum,
    ) -> Result<Option<Value>> {
        let bytes = match self.load_object_bytes_blocking(ObjectType::CommitMeta, checksum) {
            Ok(bytes) => bytes,
            Err(Error::ObjectNotFound { .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        parse_detached_metadata(&bytes)
    }

    /// Loads the bytes of the commit object `checksum` and its detached
    /// metadata, as
    /// [`read_commit_detached_metadata`](Repo::read_commit_detached_metadata)
    /// reads it.
    ///
    /// The two reads and the parse run in one call on the blocking pool. The
    /// read of the commit comes first, so a commit that this repository does
    /// not hold gives [`Error::ObjectNotFound`] before an error of the
    /// `.commitmeta`.
    pub(crate) async fn load_commit_and_detached(
        &self,
        checksum: &Checksum,
    ) -> Result<(Vec<u8>, Option<Value>)> {
        let repo = self.clone();
        let key = *checksum;
        ostrya_rt::unblock(move || {
            let bytes = repo.load_object_bytes_blocking(ObjectType::Commit, &key)?;
            let detached = repo.read_commit_detached_metadata_blocking(&key)?;
            Ok((bytes, detached))
        })
        .await
    }

    /// Writes or clears the detached metadata of a commit.
    ///
    /// If `meta` is `Some`, the call writes the `a{sv}` dict at the
    /// `.commitmeta` loose path of the commit. If `meta` is `None`, the call
    /// writes a zero-length file, which marks no metadata. The new file
    /// replaces the old file atomically and gets mode `0644`. The detached
    /// metadata is outside the commit checksum.
    ///
    /// The call writes a temp file in `tmp/` and renames it over the loose
    /// path. If `[core] fsync` is on, the call syncs the file before the
    /// rename and syncs its directory after the rename.
    ///
    /// # Locks
    ///
    /// The call takes a shared hold of the repository lock
    /// ([`LockKind`](crate::LockKind)), then the update lock, as
    /// [`begin_update`](Repo::begin_update) does. It writes under both locks.
    /// If the caller holds an [`UpdateGuard`](crate::UpdateGuard) of this
    /// repository, the call waits for that guard.
    ///
    /// # GC anchor keys
    ///
    /// If `meta` holds at least one entry, the call reads the repository
    /// config key `[ex-ostrya] gc-root-metadata-keys` and checks each entry
    /// whose key is in that list, as [`Transaction::write_commit`] does. The
    /// call checks before it takes a lock. On a refusal the `.commitmeta` file
    /// stays as it was.
    ///
    /// # Build sources
    ///
    /// The key `ostrya.related` holds the build sources of the commit. The
    /// call checks each entry with this key, also when the key occurs more
    /// than one time. The value must be a variant of type `a(say)`, and each
    /// element must have a name that is not empty and a checksum of 32 bytes.
    /// The call accepts elements that are not sorted, two elements with the
    /// same name, and a checksum of a commit that the repository does not
    /// hold. It checks after the GC anchor keys and before it takes a lock.
    /// On a refusal the `.commitmeta` file stays as it was.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidGcAnchor`] if an entry of `meta` gives a key of
    ///   `[ex-ostrya] gc-root-metadata-keys` a value that a prune refuses.
    /// - [`Error::Core`] if `meta` holds at least one entry and `[ex-ostrya]
    ///   gc-root-metadata-keys` holds a malformed escape sequence.
    /// - [`Error::InvalidRelated`] with `checksum` and
    ///   [`RelatedField::BuildSources`] if an `ostrya.related` entry of `meta`
    ///   is not a variant of type `a(say)`, or if one of its elements has an
    ///   empty name or a checksum that is not 32 bytes.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`. Each of the two waits gets the full timeout.
    /// - [`Error::Core`] if `meta` is not an `a{sv}` dict value.
    /// - [`Error::Core`] if `[core] fsync` or `[core] locking` is not a
    ///   boolean, or if `[core] lock-timeout-secs` is not an integer.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is less than
    ///   `-1`.
    /// - [`Error::Io`] with `EXDEV` if `tmp/` and `objects/` are on different
    ///   file systems.
    /// - [`Error::Io`] if another file system operation fails.
    pub async fn write_commit_detached_metadata(
        &self,
        checksum: &Checksum,
        meta: Option<&Value>,
    ) -> Result<()> {
        check_gc_anchors(self.config(), meta)?;
        if let Some(meta) = meta {
            related::check_detached(checksum, meta)?;
        }
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

    /// Adds the build source `name` with the checksum `source` to the commit
    /// `commit`.
    ///
    /// The build sources of a commit are the entries of the key
    /// `ostrya.related` in its detached metadata, a variant of type `a(say)`.
    /// Each entry is a name and the checksum of a commit. The name has the
    /// form `<class>/<name>` by convention, for example `layer/base`. The
    /// call checks nothing else in the name. It does not check that the
    /// repository holds `source`. A build source can name build sources of
    /// its own, and the add can make a cycle.
    ///
    /// The call edits the first `ostrya.related` entry of the detached
    /// metadata. It replaces the element with the name `name`, or adds a new
    /// one, and sorts the elements by name in byte order. If the detached
    /// metadata has no such entry, the call appends one after the other
    /// entries. If the commit has no detached metadata, the call writes a new
    /// dict with the one entry. Each other entry stays as it is. The new
    /// file replaces the old file atomically.
    ///
    /// A local prune keeps the build sources of each commit that it reaches.
    /// [`Repo::prune`], "Related commits", states the rules.
    ///
    /// # Locks
    ///
    /// The call takes the repository lock as
    /// [`Shared`](crate::LockKind::Shared) and the update lock, as
    /// [`sign_commit`](Repo::sign_commit) does. Under both locks, it checks
    /// that the repository holds the commit object, reads the dict, adds the
    /// entry, and writes the file. A prune takes the repository lock as
    /// [`Exclusive`](crate::LockKind::Exclusive), so it cannot delete the
    /// commit between the check and the write. If the caller holds an
    /// [`UpdateGuard`](crate::UpdateGuard) of this repository, the call waits
    /// for that guard.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRelated`] with `commit` and
    ///   [`RelatedField::BuildSources`] if `name` is empty. The call refuses
    ///   it before it reads anything.
    /// - [`Error::ObjectNotFound`] if the repository does not hold the commit
    ///   object. The call writes no file.
    /// - [`Error::InvalidRelated`] with `commit` and
    ///   [`RelatedField::BuildSources`] if the stored value of the first
    ///   `ostrya.related` entry is not a variant of type `a(say)`, or if one
    ///   of its elements has an empty name or a checksum that is not 32
    ///   bytes. The `.commitmeta` file stays as it was.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`. Each of the two waits gets the full timeout.
    /// - [`Error::Core`] if `[core] fsync` or `[core] locking` is not a
    ///   boolean, or if `[core] lock-timeout-secs` is not an integer.
    /// - [`Error::Core`] if the `.commitmeta` file does not parse as an
    ///   `a{sv}` dict.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is less than
    ///   `-1`.
    /// - [`Error::Io`] if the `.commitmeta` file is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    /// - [`Error::Io`] with `EXDEV` if `tmp/` and `objects/` are on different
    ///   file systems.
    /// - [`Error::Io`] if another file system operation fails.
    pub async fn add_detached_related(
        &self,
        commit: &Checksum,
        name: &str,
        source: &Checksum,
    ) -> Result<()> {
        if name.is_empty() {
            return Err(empty_build_source_name(commit));
        }
        let fsync = self.config().fsync()?;
        let repo_mode = self.mode();
        let checksum = *commit;
        let related = vec![(name.to_owned(), *source)];
        self.write_locked(move |repo| {
            // A prune takes the exclusive lock, so the commit stays until the
            // write ends.
            if !repo.has_object_blocking(ObjectType::Commit, &checksum)? {
                return Err(Error::ObjectNotFound {
                    checksum,
                    ty: ObjectType::Commit,
                });
            }
            let tmp_fd = open_tmp_dir(repo.repo_fd(), repo_mode)?;
            merge_detached_blocking(
                tmp_fd.as_fd(),
                repo.objects_fd(),
                &checksum,
                None,
                None,
                related,
                Vec::new(),
                fsync,
                repo_mode,
            )
        })
        .await
    }
}

/// Returns the refusal of a build source with an empty name, for the commit
/// `commit`.
pub(crate) fn empty_build_source_name(commit: &Checksum) -> Error {
    Error::InvalidRelated {
        commit: Some(*commit),
        field: RelatedField::BuildSources,
        reason: "the new entry has an empty name".into(),
    }
}

/// Checks the values of the GC anchor keys in each metadata dict of `dicts`.
///
/// The GC anchor keys are the list of `[ex-ostrya] gc-root-metadata-keys` in
/// `config`. The function reads the list once, at the first dict that holds
/// an entry. If no dict holds an entry, the function does not read the list.
/// It checks each entry whose key is in the list with the decoder of the
/// prune walk. The first defect in the order of the dicts, then of the keys
/// in the list, then of the entries in the dict, gives the error.
///
/// # Errors
///
/// - [`Error::InvalidGcAnchor`] with the key and the reason of the decoder.
/// - [`Error::Core`] if the list holds a malformed escape sequence.
pub(crate) fn check_gc_anchors<'a>(
    config: &RepoConfig,
    dicts: impl IntoIterator<Item = &'a Value>,
) -> Result<()> {
    let mut keys: Option<Vec<String>> = None;
    for dict in dicts {
        if dict.as_array().is_none_or(<[Value]>::is_empty) {
            continue;
        }
        let keys = match &mut keys {
            Some(keys) => keys,
            None => keys.insert(config.gc_root_metadata_keys()?),
        };
        for key in keys.iter() {
            for value in crate::traverse::dict_values(dict, key) {
                crate::traverse::for_each_metadata_key_target(value, |_| {}).map_err(|reason| {
                    Error::InvalidGcAnchor {
                        metadata_key: key.clone(),
                        reason,
                    }
                })?;
            }
        }
    }
    Ok(())
}

/// Parses `bytes`, the contents of a `.commitmeta` file, as detached
/// metadata.
///
/// Returns `None` for a zero-length file. Such a file marks deleted
/// metadata. It is not an empty dict. The parse blocks the thread, so an
/// async caller runs it on the blocking pool.
///
/// # Errors
///
/// [`Error::Core`] if `bytes` does not parse as an `a{sv}` dict.
pub(crate) fn parse_detached_metadata(bytes: &[u8]) -> Result<Option<Value>> {
    crate::summary::parse_signature_dict(bytes)
}

/// Appends one entry to an `a{sv}` dict value, after its existing entries.
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

/// Applies one edit of the detached metadata at the `.commitmeta` loose path
/// of a commit.
///
/// The call runs on the blocking pool. The edit starts from a base dict:
///
/// - `replace`, if it is `Some`, in place of the dict of the file
/// - else the dict that the file holds
/// - else an empty dict, if the file is absent or is the zero-length marker
///
/// If `merge` is given, it holds a serialized `a{sv}` dict and a list of
/// keys. The call merges that dict into the base dict with a union of each
/// signature list. The listed keys keep the value that the base dict holds.
/// Next, each entry of `build_sources` adds one build source to the first
/// `ostrya.related` entry, in order, as [`Repo::add_detached_related`] states.
/// Then each entry of `appends` appends one signature to the `aay` array of
/// its engine, in order. The result replaces the file atomically. If a step
/// fails, the file stays as it was.
///
/// The read, the merge, and the write run as one step under
/// [`DETACHED_MERGE`], for this edit only. Because the guard covers one edit,
/// a caller can apply several edits in one call on the blocking pool. The
/// caller holds the update lock.
#[allow(clippy::too_many_arguments)]
pub(crate) fn merge_detached_blocking(
    tmp_fd: BorrowedFd<'_>,
    objects_fd: BorrowedFd<'_>,
    checksum: &Checksum,
    replace: Option<Value>,
    merge: Option<(Vec<u8>, Vec<String>)>,
    build_sources: Vec<(String, Checksum)>,
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
        for (name, source) in build_sources {
            related::add_build_source(&mut dict, checksum, &name, &source)?;
        }
        for (key, signature) in appends {
            crate::sign::append_signature(&mut dict, &key, signature)?;
        }
        Ok((DetachedWrite::Dict(dict), ()))
    })
}

/// Removes signatures at the `.commitmeta` loose path of a commit.
///
/// The call runs on the blocking pool. `remove(payload, blob)` decides for
/// each blob under `metadata_key`. `payload` is the canonical bytes of the
/// commit. The read, the removal, and the write run as one step under
/// [`DETACHED_MERGE`], as in [`merge_detached_blocking`]. The caller holds the
/// update lock.
///
/// Returns the number of blobs removed. If the count is zero, the file stays
/// as it is. If the removal empties the dict, the call writes the zero-length
/// "no metadata" marker.
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

/// Writes detached metadata to the file `name` in a staging directory.
///
/// [`install_detached_blocking`] moves the file into `objects/` at the
/// transaction commit. The file gets the `0644` of each metadata object. If a
/// file exists at `name`, the call replaces it. The call syncs nothing,
/// because the transaction commit makes the file durable before the install.
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

/// Renames each staged file in `staged` over the `.commitmeta` loose path of
/// its commit.
///
/// The call runs under [`DETACHED_MERGE`]. It creates each fanout directory
/// on demand, as [`write_detached_blocking`] does. If fsync is on, the call
/// runs `fsync` once on each fanout directory that got a file, after the last
/// rename. It also runs `fsync` once on `objects/` if it created a fanout
/// directory.
///
/// The caller holds the update lock. If fsync is on, the staged files are
/// durable before the call.
pub(crate) fn install_detached_blocking(
    staging_fd: BorrowedFd<'_>,
    staged: &[(&Checksum, &str)],
    objects_fd: BorrowedFd<'_>,
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<()> {
    let _guard = DETACHED_MERGE.lock().unwrap_or_else(|err| err.into_inner());
    // Each fanout directory that got a file, and `true` if this call created
    // it.
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

/// The process-wide mutex of each edit of a `.commitmeta` file.
///
/// It serializes the read-modify-write cycle of [`edit_detached_blocking`]
/// and the install of a staged file. The section holds one small read, one
/// serialization, and one atomic rename. It holds no await, so it cannot
/// block a task.
///
/// Each edit of a `.commitmeta` also runs under the update lock. That lock
/// excludes other processes and the other writers of this process. If two
/// processes sign one commit at the same time, both signatures stay. The
/// mutex guards only a caller of this process that edits without the update
/// lock.
static DETACHED_MERGE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The result of one guarded edit at a `.commitmeta` loose path.
enum DetachedWrite {
    /// The bytes of this `a{sv}` dict replace the file.
    Dict(Value),
    /// The zero-length "no metadata" marker replaces the file.
    Marker,
    /// The file stays as it is.
    Keep,
}

/// Runs one read-modify-write of a `.commitmeta` loose path under
/// [`DETACHED_MERGE`].
///
/// `edit` receives a reader of the stored dict. The reader returns the
/// `a{sv}` dict of the file, or `None` if the file is absent or is the
/// zero-length marker. `edit` returns what to leave at the path and the value
/// for the caller. The reader, `edit`, and the write all run inside the guard,
/// so no other edit of this process occurs between them.
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

/// Reads the `a{sv}` dict at a `.commitmeta` loose path.
///
/// Returns `None` if the file is absent or is the zero-length "no metadata"
/// marker.
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

/// Writes metadata bytes to a loose path atomically.
///
/// The detached metadata writers use it for a `.commitmeta` file. The prune
/// sweep uses it for a `.tombstone-commit` file. Both objects get the `0644`
/// of each metadata object. `tmp_fd` is the open `tmp/` directory of the
/// repository. The steps are:
///
/// 1. The call creates the fanout directory if it is absent, with `0777`
///    reduced by the umask. If the call creates it in a `bare-user-shared`
///    repository, the mode is [`perm::SHARED_DIR_MODE`].
/// 2. The call writes the bytes to a temp file in `tmp/` and runs `fchmod`
///    0644. If fsync is on, it runs `fdatasync` on the file.
/// 3. The call renames the temp file over the target. If `tmp/` is on another
///    file system, the rename fails with `EXDEV` and the temp file is removed.
/// 4. If fsync is on, the call runs `fsync` on the fanout directory, so the
///    new name survives a crash. If the call created the fanout directory, it
///    also runs `fsync` on `objects/`.
///
/// The object publication path gives the same durability.
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

/// Creates the fanout directory `fanout` under `objects/` if it is absent.
///
/// The directory gets `0777` reduced by the umask. In a `bare-user-shared`
/// repository, its mode is [`perm::SHARED_DIR_MODE`]. Returns `true` if this
/// call created the directory.
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

/// Makes a directory entry renamed into `fanout` durable.
///
/// The call runs `fsync` on the fanout directory. If `created` is `true`, the
/// fanout directory is new, and the call also runs `fsync` on `objects/`.
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
