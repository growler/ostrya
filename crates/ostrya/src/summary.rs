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
//! `ostree.summary.collection-map`, `ostree.summary.indexed-deltas`, and the
//! optional `ostree.summary.collection-id`.
//!
//! When the repository sets `[core] collection-id`, regeneration first refreshes
//! the `ostree-metadata` anchor commit: an empty-tree commit bound to the
//! collection, committed onto `refs/heads/ostree-metadata` with the previous
//! anchor as its parent, so its fresh checksum is what the summary lists. Mirror
//! refs (`refs/mirrors/<collection>/<ref>`) belonging to other collections are
//! grouped by collection into `ostree.summary.collection-map`.
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

use std::os::fd::{AsFd, BorrowedFd};

use ostrya_core::{Checksum, Commit, DirMeta, ObjectType, Type, Value, from_bytes, to_bytes};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::commit::{CommitOptions, append_dict_entry};
use crate::error::{Error, Result};
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
const SUMMARY_FILE: &str = "summary";
/// The summary signature file name at the repository root.
const SUMMARY_SIG_FILE: &str = "summary.sig";
/// The permission bits forced on `summary` and `summary.sig`, matching the
/// tool's `0644`.
const SUMMARY_MODE: u32 = 0o644;

/// The ref the collection anchor commit is written to.
const OSTREE_METADATA_REF: &str = "ostree-metadata";
/// The mode of the anchor commit's empty root directory: `S_IFDIR | 0755`.
const ANCHOR_DIR_MODE: u32 = 0o40755;

const MODE_KEY: &str = "ostree.summary.mode";
const LAST_MODIFIED_KEY: &str = "ostree.summary.last-modified";
const TOMBSTONE_KEY: &str = "ostree.summary.tombstone-commits";
const COLLECTION_MAP_KEY: &str = "ostree.summary.collection-map";
const INDEXED_DELTAS_KEY: &str = "ostree.summary.indexed-deltas";
const COLLECTION_ID_KEY: &str = "ostree.summary.collection-id";
const COMMIT_VERSION_KEY: &str = "ostree.commit.version";
const COMMIT_TIMESTAMP_KEY: &str = "ostree.commit.timestamp";
const COLLECTION_BINDING_KEY: &str = "ostree.collection-binding";
const REF_BINDING_KEY: &str = "ostree.ref-binding";

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
    /// The write honors `[core] fsync`. Concurrent regeneration is not
    /// serialized beyond each file's atomic replace; run at most one regeneration
    /// per repository at a time.
    pub async fn regenerate_summary(&self, opts: &SummaryOptions) -> Result<()> {
        let collection_id = self.config().collection_id().map(str::to_owned);

        // A collection repository advertises a fresh anchor commit, so refresh
        // it before enumerating refs -- it lands on refs/heads/ostree-metadata
        // and must appear in the summary with its new checksum.
        if let Some(cid) = &collection_id {
            self.refresh_anchor_commit(cid, opts).await?;
        }

        // Field 0: the local refs, byte-wise sorted by name.
        let mut heads = self.list_refs(None).await?;
        heads.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let mut ref_entries = Vec::with_capacity(heads.len());
        for (name, commit) in &heads {
            ref_entries.push(self.summary_ref_entry(name, commit).await?);
        }

        let collection_map = self.collection_map_value().await?;

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

        let summary = Value::Tuple(vec![Value::Array(ref_entries), metadata]);
        let ty = Type::parse(SUMMARY_SIGNATURE).map_err(ostrya_core::Error::from)?;
        let bytes = to_bytes(&ty, &summary).map_err(ostrya_core::Error::from)?;

        let fsync = self.config().fsync()?;
        self.write_root_file(SUMMARY_FILE, bytes, fsync).await?;
        self.remove_root_file(SUMMARY_SIG_FILE).await
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
        if bytes.is_empty() {
            return Ok(None);
        }
        let ty = Type::parse(METADATA_SIGNATURE).map_err(ostrya_core::Error::from)?;
        Ok(Some(
            from_bytes(&ty, &bytes).map_err(ostrya_core::Error::from)?,
        ))
    }

    /// Sign the summary with `signer`, appending the signature to `summary.sig`.
    ///
    /// The signed payload is the exact `summary` bytes. The signature is added to
    /// the engine's `aay` array in the `summary.sig` `a{sv}` dict, created if
    /// absent, leaving other engines' arrays in place; `summary.sig` is replaced
    /// atomically. Like [`sign_commit`](Repo::sign_commit), the read-modify-write
    /// is not serialized across calls; sign a summary from one task at a time.
    pub async fn sign_summary(&self, signer: &dyn Signer) -> Result<()> {
        let data = self.read_summary().await?.ok_or_else(|| {
            Error::InvalidFormat("no summary to sign; regenerate it first".into())
        })?;
        let signature = signer.sign(&data).await?;
        let mut dict = self
            .read_summary_signature()
            .await?
            .unwrap_or_else(|| Value::Array(Vec::new()));
        append_signature(&mut dict, signer.metadata_key(), signature)?;
        let ty = Type::parse(METADATA_SIGNATURE).map_err(ostrya_core::Error::from)?;
        let bytes = to_bytes(&ty, &dict).map_err(ostrya_core::Error::from)?;
        let fsync = self.config().fsync()?;
        self.write_root_file(SUMMARY_SIG_FILE, bytes, fsync).await
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

    /// Build one field-0 ref entry `(name, (size, checksum, refmeta))`.
    async fn summary_ref_entry(&self, name: &str, commit: &Checksum) -> Result<Value> {
        let bytes = self.load_object_bytes(ObjectType::Commit, commit).await?;
        // Commit objects are stored uncompressed, so the on-disk size equals the
        // serialized byte length the tool reports.
        let size = bytes.len() as u64;
        let parsed = Commit::parse(&bytes)?;
        ref_entry(name, size, commit, parsed.version(), parsed.timestamp)
    }

    /// Assemble `ostree.summary.collection-map` from the mirror refs, or `None`
    /// when the repository holds none. Collections and refs are byte-wise sorted.
    /// A `BTreeMap` keyed by the UTF-8 collection id orders collections by byte
    /// value, and each collection's refs are sorted by name the same way.
    async fn collection_map_value(&self) -> Result<Option<Value>> {
        use std::collections::BTreeMap;

        let mirrors = self.list_mirror_refs().await?;
        if mirrors.is_empty() {
            return Ok(None);
        }
        let mut by_collection: BTreeMap<String, Vec<(String, Checksum)>> = BTreeMap::new();
        for (collection, name, commit) in mirrors {
            by_collection
                .entry(collection)
                .or_default()
                .push((name, commit));
        }

        let mut entries = Vec::with_capacity(by_collection.len());
        for (collection, mut refs) in by_collection {
            refs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            let mut ref_values = Vec::with_capacity(refs.len());
            for (name, commit) in &refs {
                ref_values.push(self.summary_ref_entry(name, commit).await?);
            }
            entries.push(Value::Tuple(vec![
                Value::Str(collection),
                Value::Array(ref_values),
            ]));
        }
        Ok(Some(variant(
            COLLECTION_MAP_SIGNATURE,
            Value::Array(entries),
        )?))
    }

    /// Refresh the collection anchor commit onto `refs/heads/ostree-metadata`.
    ///
    /// The anchor is an empty-tree commit bound to `collection_id` with the
    /// current anchor (if any) as parent, so each regeneration extends the chain
    /// and yields a fresh checksum. The empty tree carries a `(0, 0, 0o40755)`
    /// root dirmeta and no entries.
    async fn refresh_anchor_commit(
        &self,
        collection_id: &str,
        opts: &SummaryOptions,
    ) -> Result<Checksum> {
        let parent = self.resolve_rev(OSTREE_METADATA_REF, true).await?;

        let txn = self.transaction().await?;
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
                    timestamp: opts.metadata_commit_timestamp,
                    metadata: Some(metadata),
                },
                &root,
            )
            .await?;
        txn.set_ref(OSTREE_METADATA_REF, Some(&commit));
        txn.commit().await?;
        Ok(commit)
    }

    /// Read a whole file at the repository root, or `None` when it does not exist.
    async fn read_root_file(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        let name = name.to_owned();
        ostrya_rt::unblock(move || read_root_file_blocking(repo_fd.as_fd(), &name)).await
    }

    /// Write `bytes` to a file at the repository root, atomically.
    async fn write_root_file(&self, name: &str, bytes: Vec<u8>, fsync: bool) -> Result<()> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        let name = name.to_owned();
        ostrya_rt::unblock(move || write_root_file_blocking(repo_fd.as_fd(), &name, &bytes, fsync))
            .await
    }

    /// Remove a file at the repository root; an already-absent file is success.
    async fn remove_root_file(&self, name: &str) -> Result<()> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        let name = name.to_owned();
        ostrya_rt::unblock(move || {
            match rustix::fs::unlinkat(repo_fd.as_fd(), name.as_str(), AtFlags::empty()) {
                Ok(()) | Err(Errno::NOENT) => Ok(()),
                Err(e) => Err(e.into()),
            }
        })
        .await
    }
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
const SUMMARY_READ_CAP: u64 = 64 * 1024 * 1024;

/// Read a whole file relative to `repo_fd`, or `None` when it does not exist.
fn read_root_file_blocking(repo_fd: BorrowedFd<'_>, name: &str) -> Result<Option<Vec<u8>>> {
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
    let mut buf = Vec::new();
    std::fs::File::from(fd)
        .take(SUMMARY_READ_CAP)
        .read_to_end(&mut buf)?;
    Ok(Some(buf))
}

/// Write `bytes` to `name` at the repository root atomically: a fresh temp file
/// (`fchmod` 0644, `fdatasync` when `fsync` is set) renamed over the target,
/// then the root directory fsynced so the rename survives a crash.
fn write_root_file_blocking(
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
        if fsync {
            rustix::fs::fsync(repo_fd)?;
        }
        Ok(())
    };
    write_and_rename().inspect_err(|_| {
        let _ = rustix::fs::unlinkat(repo_fd, tmp.as_str(), AtFlags::empty());
    })
}

/// `SummaryOptions` moves freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SummaryOptions>();
};
