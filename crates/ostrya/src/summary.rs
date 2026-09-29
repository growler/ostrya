//! Summary generation, signing, and verification.
//!
//! The summary is a `(a(s(taya{sv}))a{sv})` GVariant at the repository root
//! (`format-reference.md`, "Summary"). [`Repo::regenerate_summary`] assembles it
//! from the local refs: field 0 lists the `refs/heads` refs sorted byte-wise,
//! each carrying its commit-object size (host order), the 32-byte commit
//! checksum, and per-ref metadata (`ostree.commit.version` when the commit
//! records one, then `ostree.commit.timestamp` big-endian). Field 1 is the
//! global metadata dict, whose entries appear in a fixed insertion order that
//! byte identity relies on: `ostree.summary.mode`, `ostree.summary.last-modified`
//! (big-endian), `ostree.summary.tombstone-commits`, the optional
//! `ostree.static-deltas`, the optional `ostree.summary.collection-map`,
//! `ostree.summary.indexed-deltas`, and the optional
//! `ostree.summary.collection-id`. The keys a caller adds through
//! [`SummaryOptions::additional_metadata`] follow the standard entries in the
//! order the caller first names them. A caller key that names a key the writer
//! writes in the same run gives way to the writer's value, and a repeated caller
//! key keeps its first position and takes its last value.
//!
//! `ostree.static-deltas` maps each delta under `deltas/` to the SHA-256 of its
//! `superblock`, which is what lets a pull find a delta and check the superblock
//! it fetches. It is present only when the repository holds a delta, and its
//! entries are ordered by delta name. The tool emits the map in hash-table
//! order, which follows the set of names and, for some names, the order they
//! were read. The two writers agree on the entries, and on their order only
//! where the tool's order is name order by chance.
//!
//! When the repository sets `[core] collection-id`, regeneration first refreshes
//! the `ostree-metadata` anchor commit: an empty-tree commit bound to the
//! collection, committed onto `refs/heads/ostree-metadata` with the previous
//! anchor as its parent, so its fresh checksum is what the summary lists. Mirror
//! refs (`refs/mirrors/<collection>/<ref>`) belonging to other collections are
//! grouped by collection into `ostree.summary.collection-map`.
//!
//! Regeneration holds the repository lock shared and then the update lock from
//! the read of the previous anchor to the removal of `summary.sig`, so two
//! regenerations never chain their anchors onto one parent, and a regeneration
//! waits for a held [`UpdateGuard`](crate::UpdateGuard). The anchor commit
//! commits under that hold and does not take the update lock again.
//!
//! The summary's `last-modified` is wall-clock and is not pinned by
//! `SOURCE_DATE_EPOCH`; [`SummaryOptions::last_modified`] overrides it for
//! reproducible output. The anchor commit's timestamp resolves like any commit
//! (explicit, else `SOURCE_DATE_EPOCH`, else now).
//!
//! Regeneration writes `summary` atomically and removes any stale `summary.sig`,
//! since a new summary invalidates an old signature. [`Repo::sign_summary`] and
//! [`Repo::verify_summary`] reuse the Phase 13 signing framework over the exact
//! `summary` bytes; the signatures live in `summary.sig`, a bare `a{sv}` with the
//! same engine keys as detached commit metadata.
//!
//! [`Summary`] is the read side of the same file: the ref list a pull resolves
//! its targets against, and the global metadata dict verbatim.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::os::fd::{AsFd, BorrowedFd};

use ostrya_core::{
    Checksum, Commit, DirMeta, ObjectType, Type, Value, from_bytes, loose_path, to_bytes,
    tuple_field_from_bytes,
};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::commit::{CommitOptions, append_dict_entry};
use crate::deltagen::STATIC_DELTAS_KEY;
use crate::error::{Error, Result};
use crate::lock::{LockKind, UpdateLockHeld};
use crate::mtree::MutableTree;
use crate::repo::Repo;
use crate::sign::{Signer, Verifier, VerifyOutcome, append_signature, signatures_for};

/// The summary GVariant type: `(refs, global_metadata)`.
const SUMMARY_SIGNATURE: &str = "(a(s(taya{sv}))a{sv})";
/// The `a{sv}` type of the summary global metadata and of `summary.sig`.
const METADATA_SIGNATURE: &str = "a{sv}";
/// The `ostree.summary.collection-map` value type: a map of collection id to a
/// ref array shaped like the summary's own ref field.
const COLLECTION_MAP_SIGNATURE: &str = "a{sa(s(taya{sv}))}";

/// The summary file name at the repository root.
pub(crate) const SUMMARY_FILE: &str = "summary";
/// The summary signature file name at the repository root.
pub(crate) const SUMMARY_SIG_FILE: &str = "summary.sig";
/// The permission bits forced on `summary` and `summary.sig`, matching the
/// tool's `0644`.
const SUMMARY_MODE: u32 = 0o644;

/// The ref the collection anchor commit is written to.
pub(crate) const OSTREE_METADATA_REF: &str = "ostree-metadata";
/// The mode of the anchor commit's empty root directory: `S_IFDIR | 0755`.
const ANCHOR_DIR_MODE: u32 = 0o40755;

const MODE_KEY: &str = "ostree.summary.mode";
const LAST_MODIFIED_KEY: &str = "ostree.summary.last-modified";
const TOMBSTONE_KEY: &str = "ostree.summary.tombstone-commits";
const COLLECTION_MAP_KEY: &str = "ostree.summary.collection-map";
/// The summary key stating whether the remote indexes its deltas.
pub(crate) const INDEXED_DELTAS_KEY: &str = "ostree.summary.indexed-deltas";
const COLLECTION_ID_KEY: &str = "ostree.summary.collection-id";
const COMMIT_VERSION_KEY: &str = "ostree.commit.version";
const COMMIT_TIMESTAMP_KEY: &str = "ostree.commit.timestamp";
const COLLECTION_BINDING_KEY: &str = "ostree.collection-binding";
const REF_BINDING_KEY: &str = "ostree.ref-binding";

/// A parsed repository summary.
///
/// Field 0 of the summary is the remote's ref list, which is what a pull
/// resolves a requested ref against before falling back to `refs/heads/<ref>`,
/// and what a mirror pull of every ref takes its targets from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// The refs the summary lists, in the order it lists them (byte-wise sorted
    /// by name, as the writer produced them).
    pub refs: Vec<SummaryRef>,
    /// The global metadata dict, as the `a{sv}` [`Value`] the file holds.
    pub metadata: Value,
}

/// One field-0 entry of a summary: a ref, the commit it names, and what the
/// summary records about that commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryRef {
    /// The ref name.
    pub name: String,
    /// The commit the ref names.
    pub commit: Checksum,
    /// The size of the commit object, in bytes. The field is stored in host
    /// order, unlike the numbers in the metadata dicts.
    pub commit_size: u64,
    /// The per-ref metadata dict, as the `a{sv}` [`Value`] the file holds:
    /// `ostree.commit.version` when the commit carries one, and a big-endian
    /// `ostree.commit.timestamp`.
    pub metadata: Value,
}

impl Summary {
    /// Parse the bytes of a `summary` file.
    ///
    /// Bytes the codec cannot read as the summary type fail as the codec's own
    /// error; bytes that decode but do not hold the shape the type promises --
    /// a ref naming a checksum that is not 32 bytes, for one -- fail with
    /// [`Error::InvalidFormat`].
    pub fn parse(bytes: &[u8]) -> Result<Summary> {
        let ty = Type::parse(SUMMARY_SIGNATURE).map_err(ostrya_core::Error::from)?;
        let value = from_bytes(&ty, bytes).map_err(ostrya_core::Error::from)?;
        let Value::Tuple(mut fields) = value else {
            return Err(malformed("summary is not a tuple"));
        };
        if fields.len() != 2 {
            return Err(malformed("summary does not hold two fields"));
        }
        let metadata = fields.pop().expect("the summary tuple holds two fields");
        let entries = fields.pop().expect("the summary tuple holds two fields");
        let Value::Array(entries) = entries else {
            return Err(malformed("summary field 0 is not an array"));
        };
        let mut refs = Vec::with_capacity(entries.len());
        for entry in entries {
            refs.push(parse_ref_entry(entry)?);
        }
        Ok(Summary { refs, metadata })
    }

    /// Parse the global metadata dict of a `summary` file and nothing else.
    ///
    /// The ref list is left undecoded, so a reader that reports the metadata
    /// alone -- the key listing and one value looked up by name -- pays for the
    /// framing of field 0 and not for its contents. The framing checks are the
    /// ones [`Summary::parse`] applies.
    pub fn parse_metadata(bytes: &[u8]) -> Result<Value> {
        let ty = Type::parse(SUMMARY_SIGNATURE).map_err(ostrya_core::Error::from)?;
        Ok(tuple_field_from_bytes(&ty, bytes, 1).map_err(ostrya_core::Error::from)?)
    }

    /// The value stored under `key` in the global metadata dict, unwrapped from
    /// the variant the dict holds it in.
    ///
    /// This is how a pull reads what the remote states about itself:
    /// `ostree.static-deltas` names the deltas it publishes, and
    /// `ostree.summary.indexed-deltas` states whether it keeps a delta index.
    pub fn metadata_value(&self, key: &str) -> Option<&Value> {
        self.metadata
            .dict_get(key)?
            .as_variant()
            .map(|(_, value)| value)
    }

    /// The refs of each collection `ostree.summary.collection-map` lists, in the
    /// order the map lists them.
    ///
    /// The map is what a repository publishes about the refs it mirrors from
    /// other collections; a summary without the key lists none. A map that does
    /// not hold the shape the key's type promises fails with
    /// [`Error::InvalidFormat`].
    pub fn collection_map(&self) -> Result<Vec<(String, Vec<SummaryRef>)>> {
        let Some(map) = self.metadata_value(COLLECTION_MAP_KEY) else {
            return Ok(Vec::new());
        };
        let Some(entries) = map.as_array() else {
            return Err(malformed("the collection map is not an array"));
        };
        let mut collections = Vec::with_capacity(entries.len());
        for entry in entries {
            let Some([Value::Str(collection), Value::Array(refs)]) = entry.as_tuple() else {
                return Err(malformed("a collection-map entry is not (id, refs)"));
            };
            let mut parsed = Vec::with_capacity(refs.len());
            for value in refs {
                parsed.push(parse_ref_entry(value.clone())?);
            }
            collections.push((collection.clone(), parsed));
        }
        Ok(collections)
    }

    /// The commit a ref names, or `None` when the summary does not list it.
    pub fn lookup(&self, ref_name: &str) -> Option<Checksum> {
        self.refs
            .iter()
            .find(|entry| entry.name == ref_name)
            .map(|entry| entry.commit)
    }
}

/// One field-0 entry `(s, (t, ay, a{sv}))`.
fn parse_ref_entry(entry: Value) -> Result<SummaryRef> {
    let Value::Tuple(mut fields) = entry else {
        return Err(malformed("a summary ref entry is not a tuple"));
    };
    let [Value::Str(name), Value::Tuple(inner)] = &mut fields[..] else {
        return Err(malformed("a summary ref entry is not (name, details)"));
    };
    let Some(Value::U64(size)) = inner.first() else {
        return Err(malformed("a summary ref entry holds no commit size"));
    };
    let size = *size;
    let Some(Value::Bytes(checksum)) = inner.get(1) else {
        return Err(malformed("a summary ref entry holds no commit checksum"));
    };
    let raw: [u8; 32] = checksum.as_slice().try_into().map_err(|_| {
        malformed(&format!(
            "the summary ref '{name}' names a {}-byte checksum",
            checksum.len()
        ))
    })?;
    let Some(metadata) = inner.get_mut(2) else {
        return Err(malformed("a summary ref entry holds no metadata dict"));
    };
    // The entry is owned, so the name and the metadata dict move out of it
    // rather than being cloned out; a summary lists one entry per ref.
    Ok(SummaryRef {
        name: std::mem::take(name),
        commit: Checksum::from_bytes(raw),
        commit_size: size,
        metadata: std::mem::replace(metadata, Value::Array(Vec::new())),
    })
}

/// A summary that does not hold the shape its type promises.
fn malformed(what: &str) -> Error {
    Error::InvalidFormat(format!("malformed summary: {what}"))
}

/// Options for [`Repo::regenerate_summary`].
#[derive(Debug, Default, Clone)]
pub struct SummaryOptions {
    /// The `ostree.summary.last-modified` timestamp (seconds since the Unix
    /// epoch, UTC). `None` uses the current time. The tool always uses the
    /// current time here; setting this makes the output reproducible.
    pub last_modified: Option<u64>,
    /// The timestamp of the `ostree-metadata` anchor commit refreshed for a
    /// collection repository. `None` resolves like a commit timestamp:
    /// `SOURCE_DATE_EPOCH` if set, otherwise the current time. Ignored when the
    /// repository has no collection id.
    pub metadata_commit_timestamp: Option<u64>,
    /// Keys the caller adds to the global metadata dict, each paired with the
    /// `v` the entry carries. Every value must be a [`Value::Variant`]. The
    /// entries follow the standard ones in the order of their first
    /// occurrence, and a repeated key takes its last value. A key the writer
    /// writes in the same run is dropped, so the writer's value stands. A key
    /// the writer does not write in this run is kept, whatever its name, and
    /// the empty key is kept too. A repository with a collection id refuses
    /// any caller key.
    pub additional_metadata: Vec<(String, Value)>,
}

impl Repo {
    /// Regenerate the repository summary from its local refs.
    ///
    /// Assembles `summary` from `refs/heads` (field 0, byte-wise sorted) and the
    /// global metadata dict, writes it atomically at the repository root, and
    /// removes any `summary.sig` (a new summary invalidates the old signature).
    /// When `[core] collection-id` is set, the `ostree-metadata` anchor commit is
    /// refreshed first, and mirror refs from other collections populate
    /// `ostree.summary.collection-map`.
    ///
    /// [`SummaryOptions::additional_metadata`] is merged into the global
    /// metadata dict after the standard entries. A value that is not a
    /// [`Value::Variant`] fails with [`Error::InvalidFormat`] before anything is
    /// written, the anchor commit included. In a repository with a collection
    /// id, any caller key fails with [`Error::Unsupported`] at the same point.
    ///
    /// The write honors `[core] fsync`.
    ///
    /// The call takes the repository lock shared and then the update lock, as
    /// [`Repo::begin_update`] does, and holds both from the read of the
    /// anchor commit to the removal of `summary.sig`. So regenerations run one
    /// at a time, in this process and across processes, and a regeneration
    /// waits for each holder of an [`UpdateGuard`](crate::UpdateGuard). Each
    /// of the two waits fails with [`Error::LockTimeout`] after
    /// `lock-timeout-secs`. A caller that holds an `UpdateGuard` of this
    /// repository and calls this waits for its own guard until the timeout,
    /// and with `lock-timeout-secs=-1` it waits forever. The call also takes
    /// the repository lock shared in a repository with no collection id, so
    /// when `[core] locking` is on it waits for each exclusive holder of the
    /// repository lock, a caller that holds one itself included. The refusals
    /// above come before any lock.
    pub async fn regenerate_summary(&self, opts: &SummaryOptions) -> Result<()> {
        // A caller value the dict cannot hold is refused before the anchor
        // commit advances, so a refusal leaves the repository as it stood.
        if let Some((key, _)) = opts
            .additional_metadata
            .iter()
            .find(|(_, value)| !matches!(value, Value::Variant(_)))
        {
            return Err(Error::InvalidFormat(format!(
                "summary metadata key '{key}' does not hold a variant"
            )));
        }
        let collection_id = self.config().collection_id().map(str::to_owned);
        // The tool copies the caller keys into the metadata of the anchor
        // commit, in an order the port does not reproduce, so a collection
        // repository refuses them before the anchor advances rather than write
        // another anchor (`docs/format-reference.md`, "The `ostree-metadata`
        // anchor commit").
        if collection_id.is_some() && !opts.additional_metadata.is_empty() {
            return Err(Error::Unsupported(
                "summary metadata keys in a repository with a collection id".into(),
            ));
        }

        let fsync = self.config().fsync()?;

        // The repository lock comes before the update lock. The anchor
        // transaction takes the repository lock shared too, before the update
        // lock, so its staging directory is made outside the update lock.
        let repo_lock = self.lock_repo(LockKind::Shared).await?;
        let txn = match &collection_id {
            Some(_) => Some(self.transaction().await?),
            None => None,
        };
        let held = self.lock_update().await?;

        // A collection repository advertises a fresh anchor commit, so refresh
        // it before enumerating refs -- it lands on refs/heads/ostree-metadata
        // and must appear in the summary with its new checksum.
        if let (Some(cid), Some(txn)) = (&collection_id, txn) {
            self.refresh_anchor_commit(txn, cid, opts, &held).await?;
        }

        let bytes = self.build_summary(opts).await?;
        self.write_root_file(SUMMARY_FILE, bytes, fsync).await?;
        self.remove_root_file(SUMMARY_SIG_FILE).await?;
        drop(held);
        drop(repo_lock);
        Ok(())
    }

    /// The bytes of the summary of the refs the repository holds now, as
    /// [`regenerate_summary`](Repo::regenerate_summary) writes them. The call
    /// writes nothing and does not refresh the anchor commit of a repository
    /// with a collection id: the summary lists the anchor that
    /// `ostree-metadata` names. The caller checks the values of
    /// [`SummaryOptions::additional_metadata`].
    pub(crate) async fn build_summary(&self, opts: &SummaryOptions) -> Result<Vec<u8>> {
        let collection_id = self.config().collection_id().map(str::to_owned);

        // Field 0: the local refs, byte-wise sorted by name.
        let mut heads = self.list_refs(None).await?;
        heads.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let mirrors = self.mirror_refs_by_collection().await?;

        // The commits of the local refs and then of the mirror refs, loaded
        // in one pass on the blocking pool.
        let commits = heads
            .iter()
            .chain(mirrors.values().flatten())
            .map(|(_, commit)| *commit)
            .collect();
        let mut facts = self.summary_commit_facts(commits).await?.into_iter();
        let mut entry = |name: &str, commit: &Checksum| {
            let fact = facts.next().expect("one fact for each commit of the pass");
            ref_entry(
                name,
                fact.size,
                commit,
                fact.version.as_deref(),
                fact.timestamp,
            )
        };
        let ref_entries = heads
            .iter()
            .map(|(name, commit)| entry(name, commit))
            .collect::<Result<Vec<_>>>()?;
        let collection_map = if mirrors.is_empty() {
            None
        } else {
            let mut collections = Vec::with_capacity(mirrors.len());
            for (collection, refs) in &mirrors {
                let ref_values = refs
                    .iter()
                    .map(|(name, commit)| entry(name, commit))
                    .collect::<Result<Vec<_>>>()?;
                collections.push(Value::Tuple(vec![
                    Value::Str(collection.clone()),
                    Value::Array(ref_values),
                ]));
            }
            Some(variant(
                COLLECTION_MAP_SIGNATURE,
                Value::Array(collections),
            )?)
        };

        let last_modified = resolve_last_modified(opts.last_modified)?;
        let mut metadata = Value::Array(Vec::new());
        append_dict_entry(
            &mut metadata,
            MODE_KEY,
            variant("s", Value::Str(self.mode().as_mode_str().to_owned()))?,
        )?;
        append_dict_entry(
            &mut metadata,
            LAST_MODIFIED_KEY,
            variant("t", big_endian_u64(last_modified))?,
        )?;
        append_dict_entry(
            &mut metadata,
            TOMBSTONE_KEY,
            variant("b", Value::Bool(self.config().tombstone_commits()?))?,
        )?;
        // The deltas this repository holds, so a fetcher can find them without
        // asking for an index file. Absent when the repository holds none.
        if let Some(deltas) = self.static_deltas_summary_value().await? {
            append_dict_entry(&mut metadata, STATIC_DELTAS_KEY, deltas)?;
        }
        if let Some(map) = collection_map {
            append_dict_entry(&mut metadata, COLLECTION_MAP_KEY, map)?;
        }
        append_dict_entry(
            &mut metadata,
            INDEXED_DELTAS_KEY,
            variant("b", Value::Bool(self.config().indexed_deltas()?))?,
        )?;
        if let Some(cid) = &collection_id {
            append_dict_entry(
                &mut metadata,
                COLLECTION_ID_KEY,
                variant("s", Value::Str(cid.clone()))?,
            )?;
        }
        for (key, value) in caller_entries(&metadata, &opts.additional_metadata) {
            append_dict_entry(&mut metadata, key, value.clone())?;
        }

        let summary = Value::Tuple(vec![Value::Array(ref_entries), metadata]);
        let ty = Type::parse(SUMMARY_SIGNATURE).map_err(ostrya_core::Error::from)?;
        Ok(to_bytes(&ty, &summary).map_err(ostrya_core::Error::from)?)
    }

    /// The read side of the summary: its raw bytes, or `None` when absent.
    pub async fn read_summary(&self) -> Result<Option<Vec<u8>>> {
        self.read_root_file(SUMMARY_FILE).await
    }

    /// Read the summary signature dict from `summary.sig`, or `None` when absent
    /// or stored as the zero-length marker.
    pub async fn read_summary_signature(&self) -> Result<Option<Value>> {
        let Some(bytes) = self.read_root_file(SUMMARY_SIG_FILE).await? else {
            return Ok(None);
        };
        parse_signature_dict(&bytes)
    }

    /// Sign the summary with `signer`, appending the signature to `summary.sig`.
    ///
    /// The signed payload is the exact `summary` bytes. The signature is added to
    /// the engine's `aay` array in the `summary.sig` `a{sv}` dict, created if
    /// absent, leaving other engines' arrays in place; `summary.sig` is replaced
    /// atomically. [`sign_summary_all`](Repo::sign_summary_all) signs with
    /// several signers in one write, and it states the locks the call takes.
    pub async fn sign_summary(&self, signer: &dyn Signer) -> Result<()> {
        self.sign_summary_all(&[signer]).await
    }

    /// Sign the summary with every signer in `signers`, appending the
    /// signatures to `summary.sig` in slice order.
    ///
    /// The result is the `summary.sig` one [`sign_summary`](Repo::sign_summary)
    /// call per signer writes, in the same order. The batch reads `summary` and
    /// `summary.sig` once, makes every signature, and then replaces
    /// `summary.sig` atomically in one write. A signer that fails stops the
    /// batch before the write, so `summary.sig` stays as it stood. An empty
    /// slice reads and writes nothing and takes no lock.
    ///
    /// The call takes the repository lock shared and then the update lock, as
    /// [`Repo::begin_update`] does, before it reads `summary`, and it holds
    /// both until `summary.sig` is written. So a signature always covers the
    /// `summary` it is stored beside, and the batches of several tasks or
    /// processes and [`Repo::regenerate_summary`] run one at a time, with no
    /// signature lost. Each of the two waits fails with
    /// [`Error::LockTimeout`] after `lock-timeout-secs`. A caller that holds an
    /// [`UpdateGuard`](crate::UpdateGuard) of this repository waits for its
    /// own guard until the timeout, and with `lock-timeout-secs=-1` it waits
    /// forever.
    pub async fn sign_summary_all(&self, signers: &[&dyn Signer]) -> Result<()> {
        if signers.is_empty() {
            return Ok(());
        }
        let fsync = self.config().fsync()?;
        let locks = self.lock_for_update().await?;
        let data = self.read_summary().await?.ok_or_else(|| {
            Error::InvalidFormat("no summary to sign; regenerate it first".into())
        })?;
        let mut dict = self
            .read_summary_signature()
            .await?
            .unwrap_or_else(|| Value::Array(Vec::new()));
        for signer in signers {
            let signature = signer.sign(&data).await?;
            append_signature(&mut dict, signer.metadata_key(), signature)?;
        }
        let ty = Type::parse(METADATA_SIGNATURE).map_err(ostrya_core::Error::from)?;
        let bytes = to_bytes(&ty, &dict).map_err(ostrya_core::Error::from)?;
        self.write_holding(locks, move |repo| {
            write_root_file_blocking(repo.repo_fd(), SUMMARY_SIG_FILE, &bytes, fsync)
        })
        .await
    }

    /// Verify the summary against `verifiers`.
    ///
    /// Each verifier receives the blobs stored under its engine key in
    /// `summary.sig` (empty when the key or the file is absent) together with the
    /// `summary` bytes. The outcome is valid when any verifier reports a valid
    /// signature.
    pub async fn verify_summary(&self, verifiers: &[&dyn Verifier]) -> Result<VerifyOutcome> {
        let data = self
            .read_summary()
            .await?
            .ok_or_else(|| Error::InvalidFormat("no summary to verify".into()))?;
        let dict = self.read_summary_signature().await?;
        let mut outcome = VerifyOutcome::default();
        for verifier in verifiers {
            let signatures = match &dict {
                Some(dict) => signatures_for(dict, verifier.metadata_key()),
                None => Vec::new(),
            };
            let result = verifier.verify(&data, &signatures).await?;
            outcome.valid |= result.valid;
            outcome.signatures.extend(result.signatures);
        }
        Ok(outcome)
    }

    /// The size, the version, and the timestamp of each commit of `commits`,
    /// in order, read in one pass on the blocking pool. Each commit object is
    /// read under the size cap of a metadata object, and only one commit is in
    /// memory at a time.
    async fn summary_commit_facts(&self, commits: Vec<Checksum>) -> Result<Vec<CommitFacts>> {
        let repo = self.clone();
        let mode = self.mode();
        ostrya_rt::unblock(move || {
            commits
                .iter()
                .map(|commit| {
                    let path = loose_path(commit, ObjectType::Commit, mode);
                    let bytes = crate::object::read_meta_object(
                        repo.objects_fd(),
                        &path,
                        crate::object::MAX_METADATA_SIZE,
                    )
                    .map_err(|e| match e.kind() {
                        std::io::ErrorKind::NotFound => Error::ObjectNotFound {
                            checksum: *commit,
                            ty: ObjectType::Commit,
                        },
                        _ => Error::Io(e),
                    })?;
                    let parsed = Commit::parse(&bytes)?;
                    Ok(CommitFacts {
                        // Commit objects are stored uncompressed, so the
                        // on-disk size equals the serialized byte length the
                        // tool reports.
                        size: bytes.len() as u64,
                        version: parsed.version().map(str::to_owned),
                        timestamp: parsed.timestamp,
                    })
                })
                .collect()
        })
        .await
    }

    /// The mirror refs, grouped by collection, for
    /// `ostree.summary.collection-map`. Collections and refs are byte-wise
    /// sorted: a `BTreeMap` keyed by the UTF-8 collection id orders
    /// collections by byte value, and each collection's refs are sorted by
    /// name the same way.
    async fn mirror_refs_by_collection(
        &self,
    ) -> Result<std::collections::BTreeMap<String, Vec<(String, Checksum)>>> {
        let mut by_collection: std::collections::BTreeMap<String, Vec<(String, Checksum)>> =
            std::collections::BTreeMap::new();
        for (collection, name, commit) in self.list_mirror_refs().await? {
            by_collection
                .entry(collection)
                .or_default()
                .push((name, commit));
        }
        for refs in by_collection.values_mut() {
            refs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        }
        Ok(by_collection)
    }

    /// Refresh the collection anchor commit onto `refs/heads/ostree-metadata`.
    ///
    /// The anchor is an empty-tree commit bound to `collection_id` with the
    /// current anchor (if any) as parent, so each regeneration extends the chain
    /// and yields a fresh checksum. The empty tree carries a `(0, 0, 0o40755)`
    /// root dirmeta and no entries.
    ///
    /// The anchor is staged in `txn`, and `txn` commits under `held`, the
    /// update lock the caller holds, so the read of the parent and the ref
    /// write run under one hold.
    async fn refresh_anchor_commit(
        &self,
        txn: crate::Transaction,
        collection_id: &str,
        opts: &SummaryOptions,
        held: &UpdateLockHeld,
    ) -> Result<Checksum> {
        let parent = self.resolve_ref_tip(OSTREE_METADATA_REF).await?;
        let commit = self
            .stage_anchor_commit(&txn, collection_id, parent, opts.metadata_commit_timestamp)
            .await?;
        txn.commit_under(held).await?;
        Ok(commit)
    }

    /// Stage the collection anchor commit in `txn`, with `parent` as its
    /// parent and `timestamp` as its timestamp, and queue its write to
    /// `refs/heads/ostree-metadata`. A `timestamp` of `None` resolves as for
    /// any commit. Nothing is published until `txn` commits.
    pub(crate) async fn stage_anchor_commit(
        &self,
        txn: &crate::Transaction,
        collection_id: &str,
        parent: Option<Checksum>,
        timestamp: Option<u64>,
    ) -> Result<Checksum> {
        let dirmeta = DirMeta {
            uid: 0,
            gid: 0,
            mode: ANCHOR_DIR_MODE,
            xattrs: Default::default(),
        };
        let dirmeta_bytes = dirmeta.serialize()?;
        let dirmeta_csum = txn
            .write_metadata(ObjectType::DirMeta, None, &dirmeta_bytes)
            .await?;
        let mut mtree = MutableTree::new();
        mtree.set_metadata_checksum(dirmeta_csum);
        let root = txn.write_mtree(&mut mtree).await?;

        let mut metadata = Value::Array(Vec::new());
        append_dict_entry(
            &mut metadata,
            COLLECTION_BINDING_KEY,
            variant("s", Value::Str(collection_id.to_owned()))?,
        )?;
        append_dict_entry(
            &mut metadata,
            REF_BINDING_KEY,
            variant(
                "as",
                Value::Array(vec![Value::Str(OSTREE_METADATA_REF.to_owned())]),
            )?,
        )?;
        let commit = txn
            .write_commit(
                CommitOptions {
                    parent,
                    subject: None,
                    body: None,
                    timestamp,
                    metadata: Some(metadata),
                },
                &root,
            )
            .await?;
        txn.set_ref(OSTREE_METADATA_REF, Some(&commit));
        Ok(commit)
    }

    /// Read a whole file at the repository root, or `None` when it does not exist.
    pub(crate) async fn read_root_file(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        let name = name.to_owned();
        ostrya_rt::unblock(move || read_root_file_blocking(repo_fd.as_fd(), &name)).await
    }

    /// Write `bytes` to a file at the repository root, atomically. A mirror pull
    /// writes the remote's summary here verbatim.
    pub(crate) async fn write_root_file(
        &self,
        name: &str,
        bytes: Vec<u8>,
        fsync: bool,
    ) -> Result<()> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        let name = name.to_owned();
        ostrya_rt::unblock(move || write_root_file_blocking(repo_fd.as_fd(), &name, &bytes, fsync))
            .await
    }

    /// Remove a file at the repository root; an already-absent file is success.
    pub(crate) async fn remove_root_file(&self, name: &str) -> Result<()> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        let name = name.to_owned();
        ostrya_rt::unblock(move || remove_root_file_blocking(repo_fd.as_fd(), &name)).await
    }
}

/// Read the signature dict a `summary.sig` file holds, an `a{sv}` of one
/// signature array per engine. The zero-length marker the writer uses for an
/// empty dict reads back as `None`.
pub(crate) fn parse_signature_dict(bytes: &[u8]) -> Result<Option<Value>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let ty = Type::parse(METADATA_SIGNATURE).map_err(ostrya_core::Error::from)?;
    Ok(Some(
        from_bytes(&ty, bytes).map_err(ostrya_core::Error::from)?,
    ))
}

/// Serialize an `a{sv}` dict, the inverse of [`parse_signature_dict`].
pub(crate) fn serialize_signature_dict(dict: &Value) -> Result<Vec<u8>> {
    let ty = Type::parse(METADATA_SIGNATURE).map_err(ostrya_core::Error::from)?;
    Ok(to_bytes(&ty, dict).map_err(ostrya_core::Error::from)?)
}

/// What a summary ref entry carries of one commit object.
struct CommitFacts {
    size: u64,
    version: Option<String>,
    timestamp: u64,
}

/// Build one ref-array entry `(s, (t, ay, a{sv}))`: the ref name, the commit
/// object size in host order, the 32-byte commit checksum, and the per-ref
/// metadata (`ostree.commit.version` when present, then a big-endian
/// `ostree.commit.timestamp`).
fn ref_entry(
    name: &str,
    size: u64,
    commit: &Checksum,
    version: Option<&str>,
    timestamp: u64,
) -> Result<Value> {
    let mut refmeta = Value::Array(Vec::new());
    if let Some(version) = version {
        append_dict_entry(
            &mut refmeta,
            COMMIT_VERSION_KEY,
            variant("s", Value::Str(version.to_owned()))?,
        )?;
    }
    append_dict_entry(
        &mut refmeta,
        COMMIT_TIMESTAMP_KEY,
        variant("t", big_endian_u64(timestamp))?,
    )?;
    let inner = Value::Tuple(vec![
        // The commit-object size is written in the codec's native little-endian
        // form, matching the host-order value the tool writes on the
        // little-endian targets ostree supports.
        Value::U64(size),
        Value::Bytes(commit.as_bytes().to_vec()),
        refmeta,
    ]);
    Ok(Value::Tuple(vec![Value::Str(name.to_owned()), inner]))
}

/// The caller keys to append after the standard entries of `standard`, in
/// the order of their first occurrence, each with its last value. A key
/// `standard` already holds is left out, so the writer's own value stands.
fn caller_entries<'a>(standard: &Value, added: &'a [(String, Value)]) -> Vec<(&'a str, &'a Value)> {
    let mut entries: Vec<(&str, &Value)> = Vec::new();
    // The slot each key holds in `entries`, so a repeated key is found in
    // constant time and keeps the position of its first occurrence.
    let mut slots: HashMap<&str, usize> = HashMap::new();
    for (key, value) in added {
        if standard.dict_get(key).is_some() {
            continue;
        }
        match slots.entry(key.as_str()) {
            Entry::Occupied(slot) => entries[*slot.get()].1 = value,
            Entry::Vacant(slot) => {
                slot.insert(entries.len());
                entries.push((key.as_str(), value));
            }
        }
    }
    entries
}

/// Wrap `value` in a GVariant variant of type `type_str`, for an `a{sv}` value.
fn variant(type_str: &str, value: Value) -> Result<Value> {
    let ty = Type::parse(type_str).map_err(ostrya_core::Error::from)?;
    Ok(Value::variant(ty, value))
}

/// A `t` value whose on-disk bytes are big-endian. GVariant serializes `U64`
/// little-endian, so pre-swapping yields the big-endian wire form on any host.
fn big_endian_u64(value: u64) -> Value {
    Value::U64(value.swap_bytes())
}

/// Resolve the summary `last-modified`: an explicit value, else the current
/// time. `SOURCE_DATE_EPOCH` is deliberately not consulted, matching the tool.
fn resolve_last_modified(explicit: Option<u64>) -> Result<u64> {
    if let Some(timestamp) = explicit {
        return Ok(timestamp);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidFormat("the system clock is before the Unix epoch".into()))?;
    Ok(now.as_secs())
}

/// The largest summary the reader loads whole. The summary scales with the ref
/// and delta count and is loaded whole by every consumer; this bound guards
/// against a corrupt or hostile file.
pub(crate) const SUMMARY_READ_CAP: u64 = 64 * 1024 * 1024;

/// Read a whole file relative to `repo_fd`, or `None` when it does not exist.
pub(crate) fn read_root_file_blocking(
    repo_fd: BorrowedFd<'_>,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    use std::io::Read;

    let fd = match rustix::fs::openat(
        repo_fd,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let file = std::fs::File::from(fd);
    // The buffer is sized from the file before the read, so the file lands in
    // one allocation. Without the hint the buffer grows by doubling and the
    // bytes already read are copied at every step of the ladder. The hint is
    // clamped to the same bound the reader takes, so a file that states a
    // hostile size allocates no more than that.
    let hint = file.metadata()?.len().min(SUMMARY_READ_CAP) + 1;
    let mut buf = Vec::with_capacity(hint as usize);
    file.take(SUMMARY_READ_CAP).read_to_end(&mut buf)?;
    Ok(Some(buf))
}

/// Write `bytes` to `name` at the repository root atomically: a fresh temp file
/// (`fchmod` 0644, `fdatasync` when `fsync` is set) renamed over the target,
/// then the root directory fsynced so the rename survives a crash.
pub(crate) fn write_root_file_blocking(
    repo_fd: BorrowedFd<'_>,
    name: &str,
    bytes: &[u8],
    fsync: bool,
) -> Result<()> {
    put_root_file_blocking(repo_fd, name, bytes, fsync)?;
    if fsync {
        rustix::fs::fsync(repo_fd)?;
    }
    Ok(())
}

/// Remove `name` at the repository root; an already-absent file is success.
pub(crate) fn remove_root_file_blocking(repo_fd: BorrowedFd<'_>, name: &str) -> Result<()> {
    match rustix::fs::unlinkat(repo_fd, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// The body of [`write_root_file_blocking`], with the sync of the root
/// directory left to the caller.
pub(crate) fn put_root_file_blocking(
    repo_fd: BorrowedFd<'_>,
    name: &str,
    bytes: &[u8],
    fsync: bool,
) -> Result<()> {
    use std::io::Write;

    let tmp = format!(
        "{name}.tmp-{}-{}",
        std::process::id(),
        crate::write::unique()
    );
    let fd = rustix::fs::openat(
        repo_fd,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(SUMMARY_MODE),
    )?;
    let write_and_rename = || -> Result<()> {
        let mut file = std::fs::File::from(fd);
        file.write_all(bytes)?;
        file.flush()?;
        rustix::fs::fchmod(file.as_fd(), Mode::from_raw_mode(SUMMARY_MODE))?;
        if fsync {
            rustix::fs::fdatasync(file.as_fd())?;
        }
        drop(file);
        rustix::fs::renameat(repo_fd, tmp.as_str(), repo_fd, name)?;
        Ok(())
    };
    write_and_rename().inspect_err(|_| {
        let _ = rustix::fs::unlinkat(repo_fd, tmp.as_str(), AtFlags::empty());
    })
}

/// `SummaryOptions` and the parsed summary move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SummaryOptions>();
    assert_send_sync::<Summary>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    /// Serialize a summary of `refs` with an empty metadata dict, the way
    /// [`Repo::regenerate_summary`] assembles one.
    fn encode(refs: &[(&str, Checksum)]) -> Vec<u8> {
        let entries = refs
            .iter()
            .map(|(name, commit)| ref_entry(name, 100, commit, None, 7).unwrap())
            .collect();
        let value = Value::Tuple(vec![Value::Array(entries), Value::Array(Vec::new())]);
        let ty = Type::parse(SUMMARY_SIGNATURE).unwrap();
        to_bytes(&ty, &value).unwrap()
    }

    #[test]
    fn parses_the_ref_list_and_looks_names_up() {
        let bytes = encode(&[("test/main", checksum(1)), ("other", checksum(2))]);
        let summary = Summary::parse(&bytes).unwrap();
        assert_eq!(
            summary
                .refs
                .iter()
                .map(|entry| (entry.name.clone(), entry.commit))
                .collect::<Vec<_>>(),
            vec![
                ("test/main".to_owned(), checksum(1)),
                ("other".to_owned(), checksum(2)),
            ]
        );
        assert_eq!(summary.lookup("test/main"), Some(checksum(1)));
        assert_eq!(summary.lookup("absent"), None);
    }

    /// The size and the per-ref metadata the file records, which
    /// `remote summary` reports for each ref.
    #[test]
    fn retains_each_ref_size_and_metadata() {
        let bytes = encode(&[("test/main", checksum(1))]);
        let summary = Summary::parse(&bytes).unwrap();
        let entry = &summary.refs[0];
        assert_eq!(entry.commit_size, 100);
        let timestamp = entry
            .metadata
            .dict_get(COMMIT_TIMESTAMP_KEY)
            .and_then(Value::as_variant)
            .and_then(|(_, value)| value.as_u64())
            .expect("the entry carries a timestamp");
        // The field is stored big-endian, so one byteswap recovers the number
        // the writer put in.
        assert_eq!(timestamp.swap_bytes(), 7);
    }

    #[test]
    fn parses_a_summary_listing_no_refs() {
        let summary = Summary::parse(&encode(&[])).unwrap();
        assert!(summary.refs.is_empty());
        assert_eq!(summary.metadata, Value::Array(Vec::new()));
    }

    /// The metadata dict is retained as written, so a caller reading a key the
    /// port does not model sees the bytes the remote published.
    #[test]
    fn retains_the_global_metadata_dict() {
        let mut metadata = Value::Array(Vec::new());
        append_dict_entry(
            &mut metadata,
            INDEXED_DELTAS_KEY,
            variant("b", Value::Bool(true)).unwrap(),
        )
        .unwrap();
        let value = Value::Tuple(vec![Value::Array(Vec::new()), metadata.clone()]);
        let ty = Type::parse(SUMMARY_SIGNATURE).unwrap();
        let bytes = to_bytes(&ty, &value).unwrap();
        assert_eq!(Summary::parse(&bytes).unwrap().metadata, metadata);
        assert_eq!(Summary::parse_metadata(&bytes).unwrap(), metadata);
    }

    /// The metadata dict reads the same whether the ref list is decoded with
    /// it or left alone, and a document the framing checks refuse is refused
    /// either way.
    #[test]
    fn reads_the_metadata_dict_without_the_ref_list() {
        let bytes = encode(&[("test/main", checksum(1)), ("other", checksum(2))]);
        assert_eq!(
            Summary::parse_metadata(&bytes).unwrap(),
            Summary::parse(&bytes).unwrap().metadata
        );
        let err = Summary::parse_metadata(b"not a summary at all").unwrap_err();
        assert!(matches!(err, Error::Core(_)), "{err}");
    }

    #[test]
    fn rejects_bytes_that_are_not_a_summary() {
        let err = Summary::parse(b"not a summary at all").unwrap_err();
        assert!(matches!(err, Error::Core(_)), "{err}");
    }

    /// A ref entry whose `ay` is not 32 bytes names no commit, and the message
    /// says which ref it was.
    #[test]
    fn rejects_a_ref_naming_a_short_checksum() {
        let inner = Value::Tuple(vec![
            Value::U64(0),
            Value::Bytes(vec![0u8; 16]),
            Value::Array(Vec::new()),
        ]);
        let entry = Value::Tuple(vec![Value::Str("short".to_owned()), inner]);
        let value = Value::Tuple(vec![Value::Array(vec![entry]), Value::Array(Vec::new())]);
        let ty = Type::parse(SUMMARY_SIGNATURE).unwrap();
        let bytes = to_bytes(&ty, &value).unwrap();
        let err = Summary::parse(&bytes).unwrap_err();
        assert!(err.to_string().contains("'short'"), "{err}");
        assert!(err.to_string().contains("16-byte"), "{err}");
    }

    /// `build_summary` gives the bytes `regenerate_summary` writes, for a
    /// repository with a collection id, whose anchor commit the regeneration
    /// refreshed, and it writes nothing.
    #[test]
    fn build_summary_gives_the_bytes_regenerate_summary_writes() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-build-summary-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ostrya_rt::block_on(async {
            let mut create = crate::CreateOptions::new(ostrya_core::RepoMode::Archive);
            create.collection_id = Some("org.example.C".into());
            let repo = Repo::create(&dir, create).await.unwrap();
            let opts = SummaryOptions {
                last_modified: Some(1_700_000_000),
                metadata_commit_timestamp: Some(1_700_000_000),
                ..SummaryOptions::default()
            };
            repo.regenerate_summary(&opts).await.unwrap();
            let written = repo.read_summary().await.unwrap().unwrap();
            let anchor = repo.resolve_ref_tip(OSTREE_METADATA_REF).await.unwrap();
            assert!(anchor.is_some(), "the regeneration wrote the anchor");
            assert_eq!(repo.build_summary(&opts).await.unwrap(), written);
            assert_eq!(
                repo.resolve_ref_tip(OSTREE_METADATA_REF).await.unwrap(),
                anchor,
                "the build refreshes no anchor"
            );
            assert_eq!(repo.read_summary().await.unwrap().unwrap(), written);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
