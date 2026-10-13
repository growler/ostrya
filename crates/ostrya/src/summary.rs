//! The summary of a repository: the `summary` file and its signatures.
//!
//! The summary is a GVariant file at the repository root. It lists the refs
//! of the repository and holds a dict of global metadata. A pull reads it to
//! resolve refs and to find static deltas.
//!
//! - [`Repo::regenerate_summary`] writes `summary` from the local refs, with
//!   the options in [`SummaryOptions`].
//! - [`Repo::sign_summary`] and [`Repo::sign_summary_all`] add signatures to
//!   `summary.sig`. [`Repo::verify_summary`] verifies them.
//! - [`Repo::read_summary`] and [`Repo::read_summary_signature`] read the two
//!   files.
//! - [`Repo::build_ref_listing`] builds a ref listing for one request: a
//!   summary of the refs under a set of prefixes, with a size cap.
//! - [`Summary`] is the parsed form of a `summary` file.
//!   [`Summary::static_deltas`] reads its delta map as [`AdvertisedDelta`]
//!   values.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::os::fd::{AsFd, BorrowedFd};

use ostrya_core::{
    Checksum, Commit, DirMeta, ObjectType, Type, Value, choose_offset_size, from_bytes, loose_path,
    to_bytes, tuple_field_from_bytes, write_offset,
};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::commit::{CommitOptions, append_dict_entry};
use crate::deltagen::{STATIC_DELTAS_KEY, advertised_delta_map, parse_delta_name};
use crate::error::{Error, Result};
use crate::lock::{LockKind, UpdateLockHeld};
use crate::mtree::MutableTree;
use crate::remote::proto::MAX_REF_LISTING;
use crate::repo::Repo;
use crate::sign::{Signer, Verifier, VerifyOutcome, append_signature, signatures_for};

/// The GVariant type of the summary: `(refs, global_metadata)`.
const SUMMARY_SIGNATURE: &str = "(a(s(taya{sv}))a{sv})";
/// The `a{sv}` type of the global metadata of the summary and of `summary.sig`.
const METADATA_SIGNATURE: &str = "a{sv}";
/// The type of one entry of the ref list of the summary.
const REF_ENTRY_SIGNATURE: &str = "(s(taya{sv}))";
/// The alignment of a ref entry and of the global metadata dict, in bytes.
const LISTING_ALIGNMENT: usize = 8;
/// The fewest bytes of a ref entry other than its name.
///
/// The count is the NUL after the name, the 8-byte commit size, the 32-byte
/// commit checksum, the `ostree.commit.timestamp` entry of the ref metadata,
/// and 2 framing offsets of the entry: the end of the name and the end of the
/// checksum. The timestamp entry is the key and its NUL, the variant of type
/// `t` (8 bytes, a zero byte, and the type `t`), the framing offset of the
/// entry, and the framing offset of the dict array. The padding after the
/// name is not in the count, so the count is a lower bound for each name.
const REF_ENTRY_FLOOR: u64 = 1 + 8 + 32 + (COMMIT_TIMESTAMP_KEY.len() as u64 + 1 + 10 + 2) + 2;
/// The fewest bytes of one entry of the delta map: a key of 64 hex characters
/// and its NUL, the variant of type `ay` (32 bytes, a zero byte, and the type
/// `ay`), and the framing offset of the entry.
const DELTA_ENTRY_FLOOR: u64 = 64 + 1 + (32 + 1 + 2) + 1;
/// The type of the `ostree.summary.collection-map` value: a map from a
/// collection id to a ref array with the shape of the ref list of the summary.
const COLLECTION_MAP_SIGNATURE: &str = "a{sa(s(taya{sv}))}";
/// The type of a delta map: the `ostree.static-deltas` value of a summary, and
/// the map of an index file under `delta-indexes/`.
const DELTA_MAP_SIGNATURE: &str = "a{sv}";

/// The name of the summary file at the repository root.
pub(crate) const SUMMARY_FILE: &str = "summary";
/// The name of the summary signature file at the repository root.
pub(crate) const SUMMARY_SIG_FILE: &str = "summary.sig";
/// The permission bits of each file that `put_root_file_blocking` writes.
/// The `ostree` command gives `summary` and `summary.sig` the mode `0644`.
const SUMMARY_MODE: u32 = 0o644;

/// The ref of the anchor commit of a collection.
pub(crate) const OSTREE_METADATA_REF: &str = "ostree-metadata";
/// The mode of the empty root directory of the anchor commit: `S_IFDIR | 0755`.
const ANCHOR_DIR_MODE: u32 = 0o40755;

const MODE_KEY: &str = "ostree.summary.mode";
const LAST_MODIFIED_KEY: &str = "ostree.summary.last-modified";
const TOMBSTONE_KEY: &str = "ostree.summary.tombstone-commits";
const COLLECTION_MAP_KEY: &str = "ostree.summary.collection-map";
/// The summary key that states if the remote indexes its deltas.
pub(crate) const INDEXED_DELTAS_KEY: &str = "ostree.summary.indexed-deltas";
const COLLECTION_ID_KEY: &str = "ostree.summary.collection-id";
const COMMIT_VERSION_KEY: &str = "ostree.commit.version";
const COMMIT_TIMESTAMP_KEY: &str = "ostree.commit.timestamp";
const COLLECTION_BINDING_KEY: &str = "ostree.collection-binding";
const REF_BINDING_KEY: &str = "ostree.ref-binding";

/// A parsed `summary` file.
///
/// The summary is a `(a(s(taya{sv}))a{sv})` GVariant. Field 0 is the ref list
/// and field 1 is the global metadata dict.
///
/// A pull resolves a requested ref against the ref list of the remote. If the
/// list does not hold the ref, the pull reads `refs/heads/<ref>`. A mirror
/// pull of every ref takes its targets from the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// The refs that the summary lists, in the order of the file.
    ///
    /// [`Repo::regenerate_summary`] sorts the refs byte-wise by name.
    pub refs: Vec<SummaryRef>,
    /// The global metadata dict, as the `a{sv}` [`Value`] of the file.
    pub metadata: Value,
}

/// One static delta that a delta map advertises.
///
/// The map is the `ostree.static-deltas` map of a summary, or the map of an
/// index file under `delta-indexes/`. [`Summary::static_deltas`] reads the map
/// of a summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdvertisedDelta {
    /// The source commit of the delta, or `None` for a delta from scratch.
    pub from: Option<Checksum>,
    /// The target commit of the delta.
    pub to: Checksum,
    /// The SHA-256 digest of the `superblock` file of the delta.
    pub superblock: Checksum,
}

/// One entry of the ref list of a summary.
///
/// The entry holds a ref, the commit that the ref names, and the facts that
/// the summary records about that commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryRef {
    /// The ref name.
    pub name: String,
    /// The commit that the ref names.
    pub commit: Checksum,
    /// The size of the commit object, in bytes.
    ///
    /// The file stores this number in host order. The numbers in the metadata
    /// dicts are big-endian.
    pub commit_size: u64,
    /// The metadata dict of the ref, as the `a{sv}` [`Value`] of the file.
    ///
    /// The dict holds `ostree.commit.version` if the commit records a version.
    /// It also holds `ostree.commit.timestamp`, big-endian.
    pub metadata: Value,
}

impl Summary {
    /// Parses the bytes of a `summary` file.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if the codec cannot read the bytes as the summary
    ///   type `(a(s(taya{sv}))a{sv})`.
    /// - [`Error::InvalidFormat`] if the bytes decode but do not have the
    ///   shape of the type, for example if a ref names a checksum that is not
    ///   32 bytes.
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

    /// Parses only the global metadata dict of a `summary` file.
    ///
    /// The ref list stays undecoded, so the call costs the framing of the ref
    /// list and not its contents. A key listing and the lookup of one value
    /// need the metadata alone. The framing checks are those of
    /// [`parse`](Summary::parse).
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if the codec cannot read the bytes as the summary
    ///   type.
    pub fn parse_metadata(bytes: &[u8]) -> Result<Value> {
        let ty = Type::parse(SUMMARY_SIGNATURE).map_err(ostrya_core::Error::from)?;
        Ok(tuple_field_from_bytes(&ty, bytes, 1).map_err(ostrya_core::Error::from)?)
    }

    /// Returns the value of `key` in the global metadata dict, without its
    /// variant wrapper.
    ///
    /// Returns `None` if the dict has no such key, or if its value is not a
    /// variant.
    ///
    /// A pull reads the facts that a remote states about itself with this
    /// call. `ostree.static-deltas` names the deltas that the remote publishes.
    /// `ostree.summary.indexed-deltas` states if the remote keeps a delta
    /// index.
    pub fn metadata_value(&self, key: &str) -> Option<&Value> {
        self.metadata
            .dict_get(key)?
            .as_variant()
            .map(|(_, value)| value)
    }

    /// Returns the refs of each collection in `ostree.summary.collection-map`,
    /// in map order.
    ///
    /// A repository publishes this map for the refs that it mirrors from
    /// other collections. If the summary has no such key, the list is empty.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the map does not have the shape of its
    ///   type `a{sa(s(taya{sv}))}`.
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

    /// Returns the deltas in `ostree.static-deltas`, in map order.
    ///
    /// The key of each entry is the name of a delta in lowercase hex: `<to>`
    /// for a delta from scratch, and `<from>-<to>` for other deltas. The value
    /// is the SHA-256 digest of the `superblock` file of the delta, as an `ay`
    /// variant. A key that occurs two times gives two entries. If the summary
    /// has no such key, the list is empty.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the variant that holds the map has a type
    ///   other than `a{sv}`, if a key is not a delta name, or if a value is
    ///   not an `ay` variant of 32 bytes.
    pub fn static_deltas(&self) -> Result<Vec<AdvertisedDelta>> {
        let Some((ty, map)) = self
            .metadata
            .dict_get(STATIC_DELTAS_KEY)
            .and_then(Value::as_variant)
        else {
            return Ok(Vec::new());
        };
        check_delta_map_type(ty)?;
        parse_delta_map(map)
    }

    /// Returns the commit that `ref_name` names, or `None` if the summary does
    /// not list the ref.
    pub fn lookup(&self, ref_name: &str) -> Option<Checksum> {
        self.refs
            .iter()
            .find(|entry| entry.name == ref_name)
            .map(|entry| entry.commit)
    }
}

/// Parses one entry `(s, (t, ay, a{sv}))` of the ref list.
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
    // with no clone. A summary lists one entry for each ref.
    Ok(SummaryRef {
        name: std::mem::take(name),
        commit: Checksum::from_bytes(raw),
        commit_size: size,
        metadata: std::mem::replace(metadata, Value::Array(Vec::new())),
    })
}

/// Checks that `ty`, the type in the variant that holds a delta map, is
/// `a{sv}`.
///
/// The value of a decoded variant cannot show its type: an `a(sv)`, or an
/// empty array of any type, has the shape of an `a{sv}`. The type in the
/// variant is the only record of it.
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if `ty` is not `a{sv}`.
pub(crate) fn check_delta_map_type(ty: &Type) -> Result<()> {
    let signature = ty.signature();
    if signature != DELTA_MAP_SIGNATURE {
        return Err(Error::InvalidFormat(format!(
            "the static delta map has type `{signature}`, not `{DELTA_MAP_SIGNATURE}`"
        )));
    }
    Ok(())
}

/// Parses a delta map: an `a{sv}` from the name of each delta to the digest
/// of its superblock. The result is in map order, with each entry kept.
///
/// A summary and an index file under `delta-indexes/` carry a map of this
/// form. The caller checks the type of the map with
/// [`check_delta_map_type`] first.
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if `map` is not an array of `{sv}` entries, if
///   a key is not a name that [`delta_name`](crate::deltagen::delta_name)
///   gives, or if a value fails [`delta_digest`].
pub(crate) fn parse_delta_map(map: &Value) -> Result<Vec<AdvertisedDelta>> {
    let Some(entries) = map.as_array() else {
        return Err(Error::InvalidFormat(
            "the static delta map is not an array".into(),
        ));
    };
    let mut deltas = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some([Value::Str(name), value]) = entry.as_tuple() else {
            return Err(Error::InvalidFormat(
                "a static delta map entry is not (name, digest)".into(),
            ));
        };
        let Some((from, to)) = parse_delta_name(name) else {
            return Err(Error::InvalidFormat(format!(
                "the static delta map key '{name}' is not a delta name"
            )));
        };
        deltas.push(AdvertisedDelta {
            from,
            to,
            superblock: delta_digest(name, value)?,
        });
    }
    Ok(deltas)
}

/// Returns the superblock digest in the value `value` of the delta `name` in
/// a delta map.
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if `value` is not a variant that holds an `ay`
///   of 32 bytes.
pub(crate) fn delta_digest(name: &str, value: &Value) -> Result<Checksum> {
    let bytes = value
        .as_variant()
        .and_then(|(_, value)| value.as_bytes())
        .ok_or_else(|| {
            Error::InvalidFormat(format!(
                "the static delta map gives delta {name} no superblock digest"
            ))
        })?;
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        Error::InvalidFormat(format!(
            "the static delta map gives delta {name} a {}-byte superblock digest",
            bytes.len()
        ))
    })?;
    Ok(Checksum::from_bytes(raw))
}

/// Returns the error for a summary that does not have the shape of its type.
fn malformed(what: &str) -> Error {
    Error::InvalidFormat(format!("malformed summary: {what}"))
}

/// The options of [`Repo::regenerate_summary`].
#[derive(Debug, Default, Clone)]
pub struct SummaryOptions {
    /// The `ostree.summary.last-modified` timestamp, in seconds since the Unix
    /// epoch (UTC).
    ///
    /// If `None`, the call uses the current time. `SOURCE_DATE_EPOCH` does not
    /// change this value, as in the `ostree` command. A set value makes the
    /// output reproducible.
    pub last_modified: Option<u64>,
    /// The timestamp of the `ostree-metadata` anchor commit of a repository
    /// with a collection id.
    ///
    /// If `None`, the timestamp resolves as for each commit: `SOURCE_DATE_EPOCH`
    /// if it is set, else the current time. A repository with no collection id
    /// ignores this field.
    pub metadata_commit_timestamp: Option<u64>,
    /// The keys that the caller adds to the global metadata dict.
    ///
    /// Each key has the `v` value of its entry, and each value must be a
    /// [`Value::Variant`]. The entries come after the standard entries, in the
    /// order of the first occurrence of each key. A repeated key keeps the
    /// position of its first occurrence and takes its last value.
    ///
    /// If the call writes the same key as a standard entry in this run, it
    /// drops the caller key and keeps its own value. The call keeps each other
    /// key, whatever its name, the empty key included. A repository with a
    /// collection id refuses each caller key.
    pub additional_metadata: Vec<(String, Value)>,
}

/// Methods that write, read, sign, and verify the summary.
impl Repo {
    /// Writes the summary of the repository from its local refs.
    ///
    /// The call writes `summary` atomically at the repository root, with the
    /// mode `0644`. It removes `summary.sig`, because a new summary makes an
    /// old signature invalid. If `[core] fsync` is `true`, the call syncs the
    /// data of the file and the repository root directory.
    ///
    /// The checks of [`SummaryOptions::additional_metadata`] come before each
    /// write and before each lock. A refusal writes nothing, the anchor commit
    /// included.
    ///
    /// # Layout
    ///
    /// The summary is a `(a(s(taya{sv}))a{sv})` GVariant. Field 0 lists the
    /// refs under `refs/heads`, sorted byte-wise by name. Each entry holds:
    ///
    /// - the size of the commit object in bytes, in host order,
    /// - the 32-byte checksum of the commit,
    /// - a metadata dict of the ref: `ostree.commit.version` if the commit
    ///   records a version, then `ostree.commit.timestamp`, big-endian.
    ///
    /// Field 1 is the global metadata dict. Its entries have a fixed order,
    /// and the byte identity of the file depends on this order:
    ///
    /// 1. `ostree.summary.mode`, the mode of the repository.
    /// 2. `ostree.summary.last-modified`, big-endian
    ///    ([`SummaryOptions::last_modified`]).
    /// 3. `ostree.summary.tombstone-commits`, the value of `[core]
    ///    tombstone-commits`.
    /// 4. `ostree.static-deltas`, if the repository holds a delta.
    /// 5. `ostree.summary.collection-map`, if the repository holds mirror
    ///    refs.
    /// 6. `ostree.summary.indexed-deltas`, the value of `[core]
    ///    indexed-deltas`.
    /// 7. `ostree.summary.collection-id`, if `[core] collection-id` is set.
    ///
    /// The keys of [`SummaryOptions::additional_metadata`] come after these
    /// entries.
    ///
    /// # Static deltas
    ///
    /// `ostree.static-deltas` maps the name of each delta under `deltas/` to
    /// the SHA-256 digest of its `superblock`, as an `ay` variant. A pull uses
    /// the map to find a delta and to verify the superblock that it fetches.
    /// The entries are in the order of the delta names.
    ///
    /// The `ostree` command writes the map in hash-table order. This order
    /// depends on the set of names and, for some names, on the order of the
    /// reads of the names. The two writers write the same entries. Their
    /// orders agree only where the hash-table order is name order by chance.
    ///
    /// # Collection id
    ///
    /// If the repository sets `[core] collection-id`, the call first writes a
    /// new anchor commit to `refs/heads/ostree-metadata`. The anchor commit:
    ///
    /// - has an empty root tree, with uid 0, gid 0, and the mode `0o40755`,
    /// - holds the collection id in `ostree.collection-binding`, and
    ///   `["ostree-metadata"]` in `ostree.ref-binding`,
    /// - has the previous anchor commit as its parent, if one exists,
    /// - has the timestamp that
    ///   [`SummaryOptions::metadata_commit_timestamp`] states.
    ///
    /// Each regeneration adds a commit to the chain, and the summary lists the
    /// new checksum of the anchor commit.
    ///
    /// The mirror refs `refs/mirrors/<collection>/<ref>` go into
    /// `ostree.summary.collection-map`, grouped by collection. The collections
    /// and the refs of each collection are sorted byte-wise.
    ///
    /// The `ostree` command copies the caller keys into the metadata of the
    /// anchor commit. ostrya does not reproduce the order of these keys, so a
    /// repository with a collection id refuses each caller key.
    ///
    /// # Locks
    ///
    /// The call takes the repository lock shared and then the update lock, as
    /// [`begin_update`](Repo::begin_update) does. It holds both from the read
    /// of the previous anchor commit to the removal of `summary.sig`. Because
    /// of this hold, two regenerations never put their anchor commits on one
    /// parent. The anchor commit commits under this hold and does not take the
    /// update lock again.
    ///
    /// Regenerations run one at a time, in this process and across processes.
    /// A regeneration waits for each holder of an
    /// [`UpdateGuard`](crate::UpdateGuard), a caller that holds one included.
    /// When `[core] locking` is on, the call also waits for each exclusive
    /// holder of the repository lock, a caller that holds one included.
    /// [`LockKind`] states the rules of the repository lock.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a value of
    ///   [`SummaryOptions::additional_metadata`] is not a [`Value::Variant`],
    ///   if `[core] lock-timeout-secs` is below `-1`, if a ref file is not
    ///   UTF-8, or if the system clock is before the Unix epoch.
    /// - [`Error::Unsupported`] if the repository has a collection id and
    ///   [`SummaryOptions::additional_metadata`] is not empty.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, `[core]
    ///   lock-timeout-secs`, `[core] tombstone-commits`, or `[core]
    ///   indexed-deltas` does not parse, if a ref file holds no checksum, or if
    ///   a commit object does not parse.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::ObjectNotFound`] if a ref names a commit that is not in the
    ///   object store.
    /// - In a repository with a collection id, an error of
    ///   [`transaction`](Repo::transaction) or of
    ///   [`Transaction::commit`](crate::Transaction::commit) for the anchor
    ///   commit.
    /// - [`Error::Io`] if a file system operation fails.
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
        // The `ostree` command copies the caller keys into the metadata of
        // the anchor commit, in an order that ostrya does not reproduce. So a
        // repository with a collection id refuses them before the anchor
        // advances, and writes no other anchor.
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

        // A repository with a collection id advertises a new anchor commit, so
        // the anchor commit comes before the list of refs. It goes to
        // refs/heads/ostree-metadata, and the summary must list its new
        // checksum.
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

    /// Returns the bytes of the summary of the current refs, as
    /// [`regenerate_summary`](Repo::regenerate_summary) writes them.
    ///
    /// The call writes nothing. In a repository with a collection id, it
    /// writes no new anchor commit, and the summary lists the anchor that
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

    /// Returns a ref listing: a summary of the local refs under `prefixes`,
    /// built for one request.
    ///
    /// The listing has the type of a `summary` file, `(a(s(taya{sv}))a{sv})`,
    /// and [`Summary::parse`] reads it. The call writes nothing and takes no
    /// lock. One state of the repository gives the same bytes.
    ///
    /// # Refs
    ///
    /// A prefix is a ref name. It selects the ref of the same name and each
    /// ref below `<prefix>/`. The prefix `a/b` selects `a/b` and `a/b/c`. It
    /// does not select `a/bc`. This is the rule of
    /// [`list_refs`](Repo::list_refs) with a prefix. An empty slice selects
    /// each ref under `refs/heads`. A prefix with a part longer than the file
    /// system permits for a file name selects no ref, as a missing prefix
    /// does.
    ///
    /// The listing holds each selected ref one time, sorted byte-wise by name.
    /// An alias is in the listing under its own name, with the commit of its
    /// target. The listing holds no mirror ref. Each entry has the bytes of
    /// the entry of the same ref in a summary of the same repository state.
    ///
    /// The call drops each prefix that a shorter prefix of the slice selects.
    /// It reads only the subtree of `refs/heads` under each other prefix, and
    /// it reads each commit one time, also when more than one ref names it.
    /// So the cost of the call follows the number of selected refs. An empty
    /// slice reads all of `refs/heads`.
    ///
    /// # Global metadata
    ///
    /// The global metadata dict holds these entries, in this order:
    ///
    /// 1. `ostree.summary.mode`, the mode of the repository.
    /// 2. `ostree.static-deltas`, if the index files advertise a delta.
    /// 3. `ostree.summary.collection-id`, if `[core] collection-id` is set.
    ///
    /// The values have the encoding of the same keys in a summary. The dict
    /// holds no `ostree.summary.last-modified` and no
    /// `ostree.summary.collection-map`.
    ///
    /// The deltas come from the index files under `delta-indexes/` alone,
    /// which [`reindex_static_deltas`](Repo::reindex_static_deltas) writes.
    /// The call reads the index file of each listed commit. Then it reads the
    /// index file of each source commit that an index file names, until it
    /// finds no new commit. A commit with no index file adds no delta. The map
    /// is sorted by delta name.
    ///
    /// # Size
    ///
    /// The listing is at most [`MAX_REF_LISTING`] bytes. The call refuses a
    /// larger listing before the whole listing is in memory. It never cuts
    /// the listing short. Each check below compares a lower bound of the
    /// size of the listing with the cap, so a listing that fits passes each
    /// check. The call refuses the listing at the first check that fails:
    ///
    /// 1. After the read of the refs: the size of each entry, from the length
    ///    of the ref name. No commit and no index file is read before this
    ///    check.
    /// 2. After the delta walk: the same sum and the size of the delta map,
    ///    from the number of deltas.
    /// 3. After the serialization of the global metadata: the same sum and
    ///    the length of the metadata. No commit is read before this check.
    /// 4. During the read of the commits: the same sum and, for each ref, the
    ///    size of the version of its commit.
    /// 5. During the write of the entries: the length of the listing.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if a prefix is not a valid ref name. The
    ///   check comes before each read.
    /// - [`Error::Remote`] with
    ///   [`LimitExceeded`](crate::remote::Error::LimitExceeded) if the
    ///   listing is larger than [`MAX_REF_LISTING`] bytes.
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8, or if an index
    ///   file is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE),
    ///   does not decode as a delta index, or names a delta to another commit.
    /// - [`Error::Core`] if a ref file holds no checksum, or if a commit
    ///   object does not parse.
    /// - [`Error::ObjectNotFound`] if a listed ref names a commit that is not
    ///   in the object store.
    /// - [`Error::Io`] if a read fails, for example for an alias that names a
    ///   directory, or if `delta-indexes/` is not a directory.
    ///
    /// A failure of one selected ref or of one index file fails the whole
    /// listing. The call does not read a ref that no prefix selects.
    pub async fn build_ref_listing(&self, prefixes: &[&str]) -> Result<Vec<u8>> {
        self.build_ref_listing_capped(prefixes, MAX_REF_LISTING)
            .await
    }

    /// Builds the listing of [`build_ref_listing`](Repo::build_ref_listing)
    /// with a size cap of `cap` bytes. A listing of exactly `cap` bytes fits.
    pub(crate) async fn build_ref_listing_capped(
        &self,
        prefixes: &[&str],
        cap: u64,
    ) -> Result<Vec<u8>> {
        // The refs come sorted byte-wise by name, each one time, which is the
        // order of `build_summary`.
        let refs = self.list_refs_under(prefixes).await?;

        // Each entry is at least its name and the fixed fields. If the sum of
        // these sizes is over the cap, the listing is too.
        let mut floor: u64 = refs
            .iter()
            .map(|(name, _)| name.len() as u64 + REF_ENTRY_FLOOR)
            .sum();
        check_floor(floor, cap)?;

        // The global metadata comes before the commit reads, so its length
        // is in the floor before a commit is in memory.
        let deltas = self
            .walk_delta_indexes(refs.iter().map(|(_, commit)| *commit))
            .await?;
        check_floor(floor + deltas.len() as u64 * DELTA_ENTRY_FLOOR, cap)?;
        let mut dict = Value::Array(Vec::new());
        append_dict_entry(
            &mut dict,
            MODE_KEY,
            variant("s", Value::Str(self.mode().as_mode_str().to_owned()))?,
        )?;
        if !deltas.is_empty() {
            append_dict_entry(&mut dict, STATIC_DELTAS_KEY, advertised_delta_map(&deltas)?)?;
        }
        drop(deltas);
        if let Some(cid) = self.config().collection_id() {
            append_dict_entry(
                &mut dict,
                COLLECTION_ID_KEY,
                variant("s", Value::Str(cid.to_owned()))?,
            )?;
        }
        let metadata = serialize_signature_dict(&dict)?;
        drop(dict);
        floor += metadata.len() as u64;
        check_floor(floor, cap)?;

        let repo = self.clone();
        ostrya_rt::unblock(move || write_ref_listing(&repo, &refs, &metadata, floor, cap)).await
    }

    /// Returns the bytes of `summary`, or `None` if the file does not exist.
    ///
    /// The read stops at 64 MiB. If the file is longer, the call returns the
    /// first 64 MiB and no error.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the read fails, for example if `summary` is a
    ///   symlink.
    pub async fn read_summary(&self) -> Result<Option<Vec<u8>>> {
        self.read_root_file(SUMMARY_FILE).await
    }

    /// Returns the signature dict of `summary.sig`, or `None` if the file does
    /// not exist or is empty.
    ///
    /// The dict is an `a{sv}` with one entry for each signing engine. The read
    /// stops at 64 MiB. If the file is longer, the call parses the first
    /// 64 MiB. The read and the parse run in one call on the blocking pool.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if the file is not an `a{sv}` dict.
    /// - [`Error::Io`] if the read fails, for example if `summary.sig` is a
    ///   symlink.
    pub async fn read_summary_signature(&self) -> Result<Option<Value>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            let Some(bytes) = read_root_file_blocking(repo.repo_fd(), SUMMARY_SIG_FILE)? else {
                return Ok(None);
            };
            parse_signature_dict(&bytes)
        })
        .await
    }

    /// Signs the summary with `signer` and adds the signature to `summary.sig`.
    ///
    /// The signed payload is the exact bytes of `summary`. `summary.sig` is an
    /// `a{sv}` dict with the same engine keys as the detached metadata of a
    /// commit. The value of each key is an `aay` array of signature blobs.
    ///
    /// The call appends the signature to the array of the engine of `signer`.
    /// If the dict or the array does not exist, the call creates it. The
    /// arrays of the other engines stay as they are. The call replaces
    /// `summary.sig` atomically, with the mode `0644`.
    ///
    /// [`sign_summary_all`](Repo::sign_summary_all) signs with several signers
    /// in one write. It also states the locks that this call takes.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the repository has no `summary`, if
    ///   `[core] lock-timeout-secs` is below `-1`, or if the entry of the
    ///   engine in `summary.sig` is not an array.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or `[core]
    ///   lock-timeout-secs` does not parse, or if `summary.sig` is not an
    ///   `a{sv}` dict.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::Signature`], or the variant that the engine error converts
    ///   to, if the signer fails.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn sign_summary(&self, signer: &dyn Signer) -> Result<()> {
        self.sign_summary_all(&[signer]).await
    }

    /// Signs the summary with each signer in `signers` and adds the signatures
    /// to `summary.sig` in slice order.
    ///
    /// The result is the `summary.sig` that one
    /// [`sign_summary`](Repo::sign_summary) call for each signer writes, in
    /// the same order. The call reads `summary` and `summary.sig` once and
    /// makes each signature. Then it replaces `summary.sig` atomically in one
    /// write.
    ///
    /// If a signer fails, the call stops before the write, and `summary.sig`
    /// stays as it is. An empty slice reads nothing, writes nothing, and takes
    /// no lock.
    ///
    /// # Locks
    ///
    /// The call takes the repository lock shared and then the update lock, as
    /// [`begin_update`](Repo::begin_update) does. It takes them before it
    /// reads `summary` and holds both until it writes `summary.sig`, so a
    /// signature always covers the `summary` next to it.
    ///
    /// The calls of several tasks or processes and
    /// [`regenerate_summary`](Repo::regenerate_summary) run one at a time, and
    /// no signature is lost. A caller that holds an
    /// [`UpdateGuard`](crate::UpdateGuard) of this repository waits for its
    /// own guard.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the repository has no `summary`, if
    ///   `[core] lock-timeout-secs` is below `-1`, or if the entry of the
    ///   engine of a signer in `summary.sig` is not an array.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or `[core]
    ///   lock-timeout-secs` does not parse, or if `summary.sig` is not an
    ///   `a{sv}` dict.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::Signature`], or the variant that the engine error converts
    ///   to, if a signer fails.
    /// - [`Error::Io`] if a file system operation fails.
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

    /// Verifies the signatures of the summary with `verifiers`.
    ///
    /// Each verifier gets the bytes of `summary` and the blobs under its engine
    /// key in `summary.sig`. The set of blobs is empty if the key or the file
    /// does not exist, or if the entry is not an array. The set leaves out
    /// each element that is not a byte array.
    ///
    /// The outcome is valid if a verifier reports a valid signature. The
    /// outcome holds the signatures that each verifier reports.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the repository has no `summary`.
    /// - [`Error::Core`] if `summary.sig` is not an `a{sv}` dict.
    /// - [`Error::Signature`], or the variant that the engine error converts
    ///   to, if a verifier fails.
    /// - [`Error::Io`] if a read fails.
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

    /// Returns the size, the version, and the timestamp of each commit of
    /// `commits`, in order.
    ///
    /// The call reads the commits in one pass on the blocking pool. It reads
    /// each commit object under the size cap of a metadata object, and holds
    /// one commit in memory at a time.
    async fn summary_commit_facts(&self, commits: Vec<Checksum>) -> Result<Vec<CommitFacts>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            commits
                .iter()
                .map(|commit| read_commit_facts(&repo, commit))
                .collect()
        })
        .await
    }

    /// Returns the mirror refs, grouped by collection, for
    /// `ostree.summary.collection-map`.
    ///
    /// The collections and the refs are sorted byte-wise. A `BTreeMap` with
    /// the UTF-8 collection id as key sorts the collections by byte value.
    /// The refs of each collection are sorted by name in the same way.
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

    /// Writes a new anchor commit of the collection to
    /// `refs/heads/ostree-metadata`.
    ///
    /// The anchor is an empty-tree commit bound to `collection_id`. Its parent
    /// is the current anchor, if one exists, so each regeneration extends the
    /// chain and gives a new checksum. The empty tree has a `(0, 0, 0o40755)`
    /// root dirmeta and no entries.
    ///
    /// The call stages the anchor in `txn`. `txn` commits under `held`, the
    /// update lock that the caller holds, so the read of the parent and the
    /// ref write run under one hold.
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

    /// Stages the anchor commit of the collection in `txn` and queues its
    /// write to `refs/heads/ostree-metadata`.
    ///
    /// The commit has `parent` as its parent and `timestamp` as its timestamp.
    /// A `timestamp` of `None` resolves as for each commit. The call publishes
    /// nothing. The commit of `txn` publishes the anchor.
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

    /// Reads a whole file at the repository root, or returns `None` if it does
    /// not exist. The read stops at [`SUMMARY_READ_CAP`].
    pub(crate) async fn read_root_file(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        let name = name.to_owned();
        ostrya_rt::unblock(move || read_root_file_blocking(repo_fd.as_fd(), &name)).await
    }

    /// Writes `bytes` to a file at the repository root, atomically.
    ///
    /// A mirror pull writes the summary of the remote with this call, byte for
    /// byte.
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

    /// Removes a file at the repository root. If the file does not exist, the
    /// call succeeds.
    pub(crate) async fn remove_root_file(&self, name: &str) -> Result<()> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        let name = name.to_owned();
        ostrya_rt::unblock(move || remove_root_file_blocking(repo_fd.as_fd(), &name)).await
    }
}

/// Parses the signature dict of a `summary.sig` file.
///
/// The dict is an `a{sv}` with one signature array for each engine. An empty
/// file is the form of an empty dict, and it reads as `None`.
pub(crate) fn parse_signature_dict(bytes: &[u8]) -> Result<Option<Value>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let ty = Type::parse(METADATA_SIGNATURE).map_err(ostrya_core::Error::from)?;
    Ok(Some(
        from_bytes(&ty, bytes).map_err(ostrya_core::Error::from)?,
    ))
}

/// Serializes an `a{sv}` dict, the inverse of [`parse_signature_dict`].
pub(crate) fn serialize_signature_dict(dict: &Value) -> Result<Vec<u8>> {
    let ty = Type::parse(METADATA_SIGNATURE).map_err(ostrya_core::Error::from)?;
    Ok(to_bytes(&ty, dict).map_err(ostrya_core::Error::from)?)
}

/// The facts about one commit object that a ref entry of the summary holds.
struct CommitFacts {
    size: u64,
    version: Option<String>,
    timestamp: u64,
}

/// Reads the size, the version, and the timestamp of the commit `commit`.
///
/// The call reads the commit object under the size cap of a metadata object,
/// on the calling thread.
fn read_commit_facts(repo: &Repo, commit: &Checksum) -> Result<CommitFacts> {
    let path = loose_path(commit, ObjectType::Commit, repo.mode());
    let bytes =
        crate::object::read_meta_object(repo.objects_fd(), &path, crate::object::MAX_METADATA_SIZE)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::ObjectNotFound {
                    checksum: *commit,
                    ty: ObjectType::Commit,
                },
                _ => Error::Io(e),
            })?;
    // Commit objects are stored uncompressed, so the size on disk is the
    // serialized length that the `ostree` command reports.
    let size = bytes.len() as u64;
    let parsed = Commit::parse(&bytes)?;
    drop(bytes);
    Ok(CommitFacts {
        size,
        version: parsed.version().map(str::to_owned),
        timestamp: parsed.timestamp,
    })
}

/// Writes the ref listing of `refs`, with the serialized global metadata
/// `metadata`, on the calling thread.
///
/// `floor` is a lower bound of the size of the listing from the names of
/// `refs` and from `metadata`. The call reads each distinct commit one time.
/// It adds the size of the version of each commit to the floor, one time for
/// each ref that names the commit, and refuses the listing when the floor
/// passes `cap`. Then it writes the entries one at a time.
fn write_ref_listing(
    repo: &Repo,
    refs: &[(String, Checksum)],
    metadata: &[u8],
    mut floor: u64,
    cap: u64,
) -> Result<Vec<u8>> {
    // `slots[i]` is the index in `commits` of the commit of `refs[i]`. Each
    // item of `commits` is a distinct commit and the number of refs that
    // name it.
    let mut index: HashMap<Checksum, usize> = HashMap::new();
    let mut commits: Vec<(Checksum, u64)> = Vec::new();
    let slots: Vec<usize> = refs
        .iter()
        .map(|(_, commit)| match index.entry(*commit) {
            Entry::Occupied(slot) => {
                commits[*slot.get()].1 += 1;
                *slot.get()
            }
            Entry::Vacant(slot) => {
                commits.push((*commit, 1));
                *slot.insert(commits.len() - 1)
            }
        })
        .collect();
    drop(index);

    let mut facts = Vec::with_capacity(commits.len());
    for (commit, uses) in &commits {
        let fact = read_commit_facts(repo, commit)?;
        if let Some(version) = &fact.version {
            floor += uses * version_floor(version);
            check_floor(floor, cap)?;
        }
        facts.push(fact);
    }
    drop(commits);

    let entry_ty = Type::parse(REF_ENTRY_SIGNATURE).map_err(ostrya_core::Error::from)?;
    let mut listing = ListingWriter::new(cap, floor, refs.len());
    for ((name, commit), slot) in refs.iter().zip(slots) {
        let fact = &facts[slot];
        let entry = ref_entry(
            name,
            fact.size,
            commit,
            fact.version.as_deref(),
            fact.timestamp,
        )?;
        listing.push_entry(&to_bytes(&entry_ty, &entry).map_err(ostrya_core::Error::from)?)?;
    }
    drop(facts);
    listing.finish(metadata)
}

/// Returns the fewest bytes that the `ostree.commit.version` entry with the
/// value `version` adds to a ref entry: the key and its NUL, the variant of
/// type `s` (the value, its NUL, a zero byte, and the type `s`), the framing
/// offset of the entry, and the framing offset of the dict array.
fn version_floor(version: &str) -> u64 {
    (COMMIT_VERSION_KEY.len() + 1 + version.len() + 3 + 2) as u64
}

/// Fails with the cap error if `floor`, a lower bound of the size of a ref
/// listing, is over `cap`.
fn check_floor(floor: u64, cap: u64) -> Result<()> {
    if floor > cap {
        return Err(listing_too_large(cap));
    }
    Ok(())
}

/// Builds one entry `(s, (t, ay, a{sv}))` of the ref list.
///
/// The entry holds the ref name, the size of the commit object in host order,
/// the 32-byte commit checksum, and the metadata of the ref. The metadata
/// holds `ostree.commit.version` if present, then `ostree.commit.timestamp`,
/// big-endian.
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
        // The codec writes the size of the commit object little-endian. On
        // the little-endian targets of ostree, this is the host-order value
        // that the `ostree` command writes.
        Value::U64(size),
        Value::Bytes(commit.as_bytes().to_vec()),
        refmeta,
    ]);
    Ok(Value::Tuple(vec![Value::Str(name.to_owned()), inner]))
}

/// The writer of a ref listing, a `(a(s(taya{sv}))a{sv})` GVariant, one ref
/// entry at a time.
///
/// The writer gives the bytes that `to_bytes` gives for the whole value. It
/// checks the length against the cap before each append, so a listing over
/// the cap fails before it is whole in memory.
struct ListingWriter {
    out: Vec<u8>,
    /// The end of each entry, counted from the start of the ref array.
    ends: Vec<usize>,
    cap: u64,
}

impl ListingWriter {
    /// Returns a writer of a listing of `entries` ref entries, with a size cap
    /// of `cap` bytes. The buffer starts with a capacity of `floor` bytes, a
    /// lower bound of the size of the listing, and no more than the cap.
    fn new(cap: u64, floor: u64, entries: usize) -> ListingWriter {
        ListingWriter {
            out: Vec::with_capacity(usize::try_from(floor.min(cap)).unwrap_or(usize::MAX)),
            ends: Vec::with_capacity(entries),
            cap,
        }
    }

    /// Fails with the cap error if `extra` more bytes do not fit in the cap.
    /// Otherwise it makes the buffer large enough for them. The buffer grows
    /// to two times its capacity at most, and never past the cap.
    fn make_room(&mut self, extra: usize) -> Result<()> {
        let need = self.out.len() + extra;
        if need as u64 > self.cap {
            return Err(listing_too_large(self.cap));
        }
        if need > self.out.capacity() {
            let cap = usize::try_from(self.cap).unwrap_or(usize::MAX);
            let target = need.max(self.out.capacity().saturating_mul(2)).min(cap);
            self.out.reserve_exact(target - self.out.len());
        }
        Ok(())
    }

    /// Appends zero bytes up to the alignment of an entry and of the
    /// metadata dict, then `bytes`.
    fn append_aligned(&mut self, bytes: &[u8]) -> Result<()> {
        let aligned = self.out.len().next_multiple_of(LISTING_ALIGNMENT);
        self.make_room(aligned - self.out.len() + bytes.len())?;
        self.out.resize(aligned, 0);
        self.out.extend_from_slice(bytes);
        Ok(())
    }

    /// Appends the serialized ref entry `entry` to the ref array.
    ///
    /// An entry has an alignment of 8, so its bytes at an aligned position
    /// equal its bytes alone.
    fn push_entry(&mut self, entry: &[u8]) -> Result<()> {
        self.append_aligned(entry)?;
        self.ends.push(self.out.len());
        Ok(())
    }

    /// Closes the ref array, appends the serialized metadata dict `metadata`,
    /// and returns the listing. The function gives the unused capacity of the
    /// buffer back to the allocator.
    ///
    /// The ref array starts at offset 0. Its framing offsets follow its
    /// entries, in entry order. An empty array has no offsets. The tuple then
    /// holds the dict, aligned to 8, and one framing offset: the end of the
    /// array.
    fn finish(mut self, metadata: &[u8]) -> Result<Vec<u8>> {
        if !self.ends.is_empty() {
            let width = choose_offset_size(self.out.len(), self.ends.len());
            self.make_room(self.ends.len() * width)?;
            for &end in &self.ends {
                write_offset(&mut self.out, end, width);
            }
        }
        let array_end = self.out.len();
        self.append_aligned(metadata)?;
        let width = choose_offset_size(self.out.len(), 1);
        self.make_room(width)?;
        write_offset(&mut self.out, array_end, width);
        self.out.shrink_to_fit();
        Ok(self.out)
    }
}

/// Returns the error for a ref listing over `cap` bytes.
fn listing_too_large(cap: u64) -> Error {
    Error::Remote(crate::remote::Error::LimitExceeded(format!(
        "the ref listing is larger than its cap of {cap} bytes"
    )))
}

/// Returns the caller keys to append after the standard entries of
/// `standard`.
///
/// The keys are in the order of their first occurrence, each with its last
/// value. A key that `standard` already holds is left out, so the value of the
/// writer stays.
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

/// Wraps `value` in a GVariant variant of type `type_str`, for an `a{sv}`
/// value.
fn variant(type_str: &str, value: Value) -> Result<Value> {
    let ty = Type::parse(type_str).map_err(ostrya_core::Error::from)?;
    Ok(Value::variant(ty, value))
}

/// Returns a `t` value whose bytes on disk are big-endian.
///
/// GVariant serializes `U64` little-endian, so a byte swap before the write
/// gives the big-endian form on each host.
fn big_endian_u64(value: u64) -> Value {
    Value::U64(value.swap_bytes())
}

/// Resolves the `last-modified` value of the summary: an explicit value, else
/// the current time.
///
/// The call does not read `SOURCE_DATE_EPOCH`, as the `ostree` command does
/// not.
fn resolve_last_modified(explicit: Option<u64>) -> Result<u64> {
    if let Some(timestamp) = explicit {
        return Ok(timestamp);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidFormat("the system clock is before the Unix epoch".into()))?;
    Ok(now.as_secs())
}

/// The largest summary that the reader loads whole: 64 MiB.
///
/// The size of the summary grows with the number of refs and deltas, and each
/// reader loads it whole. This bound protects against a corrupt or hostile
/// file.
pub(crate) const SUMMARY_READ_CAP: u64 = 64 * 1024 * 1024;

/// Reads a whole file relative to `repo_fd`, or returns `None` if it does not
/// exist.
///
/// The read does not follow a symlink, and it stops at [`SUMMARY_READ_CAP`].
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

/// Writes `bytes` to `name` at the repository root, atomically.
///
/// The call writes a new temp file (`fchmod` 0644, `fdatasync` if `fsync` is
/// set) and renames it over the target. If `fsync` is set, it then syncs the
/// root directory, so the rename survives a crash.
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

/// Removes `name` at the repository root. If the file does not exist, the
/// call succeeds.
pub(crate) fn remove_root_file_blocking(repo_fd: BorrowedFd<'_>, name: &str) -> Result<()> {
    match rustix::fs::unlinkat(repo_fd, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Writes a file as [`write_root_file_blocking`] does, with no sync of the
/// root directory. The caller syncs the root directory.
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

/// `SummaryOptions`, the parsed summary, and its deltas move across tasks and
/// threads, and so does the future of a ref listing.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SummaryOptions>();
    assert_send_sync::<Summary>();
    assert_send_sync::<AdvertisedDelta>();
    fn assert_send<T: Send>(_: &T) {}
    let _ = |repo: &Repo| assert_send(&repo.build_ref_listing(&[]));
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

    /// The metadata dict stays as written, so a caller that reads a key that
    /// ostrya does not model sees the bytes that the remote published.
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

    /// The metadata dict reads the same if the ref list is decoded with it or
    /// left undecoded. Each of the two reads refuses bytes that the framing
    /// checks refuse.
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

    /// Returns a summary with no refs whose metadata holds `map` under
    /// `ostree.static-deltas`, in a variant of type `ty`.
    fn with_delta_map(ty: &str, map: Value) -> Summary {
        let mut metadata = Value::Array(Vec::new());
        append_dict_entry(&mut metadata, STATIC_DELTAS_KEY, variant(ty, map).unwrap()).unwrap();
        Summary {
            refs: Vec::new(),
            metadata,
        }
    }

    /// Returns a delta map that gives each name its value.
    fn delta_map(entries: Vec<(String, Value)>) -> Value {
        let mut map = Value::Array(Vec::new());
        for (name, value) in entries {
            append_dict_entry(&mut map, &name, value).unwrap();
        }
        map
    }

    /// Returns the `ay` variant of a digest.
    fn digest_value(bytes: &[u8]) -> Value {
        variant("ay", Value::Bytes(bytes.to_vec())).unwrap()
    }

    /// The delta map reads in map order, with one delta of each shape.
    #[test]
    fn static_deltas_reads_the_map_in_map_order() {
        let (from, to) = (checksum(0xee), checksum(0x11));
        let map = delta_map(vec![
            (
                format!("{}-{}", from.to_hex(), to.to_hex()),
                digest_value(checksum(2).as_bytes()),
            ),
            (to.to_hex(), digest_value(checksum(3).as_bytes())),
        ]);
        let summary = with_delta_map("a{sv}", map);
        assert_eq!(
            summary.static_deltas().unwrap(),
            [
                AdvertisedDelta {
                    from: Some(from),
                    to,
                    superblock: checksum(2),
                },
                AdvertisedDelta {
                    from: None,
                    to,
                    superblock: checksum(3),
                },
            ]
        );
    }

    /// A summary with no delta map, or with an empty one, lists no delta.
    #[test]
    fn static_deltas_is_empty_without_a_map() {
        let summary = Summary::parse(&encode(&[])).unwrap();
        assert_eq!(summary.static_deltas().unwrap(), Vec::new());
        let summary = with_delta_map("a{sv}", Value::Array(Vec::new()));
        assert_eq!(summary.static_deltas().unwrap(), Vec::new());
    }

    /// A key that is not a delta name, a digest that is not an `ay` of 32
    /// bytes, and a map that is not an `a{sv}` are refused. The type in the
    /// variant decides: an `a(sv)` map with a valid entry and an empty `as`
    /// map are refused too.
    #[test]
    fn static_deltas_refuses_a_malformed_map() {
        let to = checksum(0xab).to_hex();
        let good = || digest_value(checksum(2).as_bytes());
        let summaries = [
            with_delta_map("a{sv}", delta_map(vec![("zz".to_owned(), good())])),
            with_delta_map("a{sv}", delta_map(vec![(format!("{to}-"), good())])),
            with_delta_map("a{sv}", delta_map(vec![(to.to_uppercase(), good())])),
            with_delta_map(
                "a{sv}",
                delta_map(vec![(to.clone(), digest_value(&[0u8; 31]))]),
            ),
            with_delta_map(
                "a{sv}",
                delta_map(vec![(to.clone(), digest_value(&[0u8; 33]))]),
            ),
            with_delta_map(
                "a{sv}",
                delta_map(vec![(
                    to.clone(),
                    variant("s", Value::Str("nope".into())).unwrap(),
                )]),
            ),
            with_delta_map("s", Value::Str("nope".into())),
            with_delta_map("as", Value::Array(vec![Value::Str(to.clone())])),
            with_delta_map("as", Value::Array(Vec::new())),
            with_delta_map("a(sv)", delta_map(vec![(to.clone(), good())])),
        ];
        for summary in summaries {
            let outcome = summary.static_deltas();
            assert!(
                matches!(outcome, Err(Error::InvalidFormat(_))),
                "{:?}: {outcome:?}",
                summary.metadata
            );
        }
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

    /// Writes a listing of `entries` and `metadata` with [`ListingWriter`]
    /// and with `to_bytes` of the whole value, checks that the two agree, and
    /// returns the bytes.
    fn listing_both_ways(entries: Vec<Value>, metadata: Value) -> Vec<u8> {
        let entry_ty = Type::parse(REF_ENTRY_SIGNATURE).unwrap();
        let mut writer = ListingWriter::new(u64::MAX, 0, entries.len());
        for entry in &entries {
            writer
                .push_entry(&to_bytes(&entry_ty, entry).unwrap())
                .unwrap();
        }
        let streamed = writer
            .finish(&serialize_signature_dict(&metadata).unwrap())
            .unwrap();
        let whole = Value::Tuple(vec![Value::Array(entries), metadata]);
        let ty = Type::parse(SUMMARY_SIGNATURE).unwrap();
        assert_eq!(streamed, to_bytes(&ty, &whole).unwrap());
        streamed
    }

    /// Returns `count` ref entries whose names are `len` bytes long.
    fn entries_of(count: usize, len: usize) -> Vec<Value> {
        (0..count)
            .map(|i| {
                let name = format!("{i:0>len$}");
                ref_entry(&name, 100, &checksum(i as u8), Some("1.0"), 7).unwrap()
            })
            .collect()
    }

    /// Returns the value that `build` gives for the first length `n` at which
    /// the serialized form of the value under `ty` is `size` bytes long.
    ///
    /// The serialized length of `build(n)` grows by one byte for each step of
    /// `n`, with a few bytes more where a framing offset gets wider.
    fn value_of_size(ty: &str, size: usize, build: impl Fn(usize) -> Value) -> Value {
        let ty = Type::parse(ty).unwrap();
        let len = |n: usize| to_bytes(&ty, &build(n)).unwrap().len();
        let mut n = size.saturating_sub(len(0));
        for _ in 0..16 {
            let got = len(n);
            if got == size {
                return build(n);
            }
            n = (n + size).saturating_sub(got);
        }
        panic!("no value of {size} bytes");
    }

    /// Returns an `a{sv}` dict whose last bytes are a string of `n` bytes.
    fn dict_ending_in(n: usize) -> Value {
        let mut dict = Value::Array(Vec::new());
        append_dict_entry(
            &mut dict,
            "k",
            variant("s", Value::Str("x".repeat(n))).unwrap(),
        )
        .unwrap();
        dict
    }

    /// Returns a ref entry of `size` bytes.
    fn entry_of_size(size: usize) -> Value {
        value_of_size(REF_ENTRY_SIGNATURE, size, |n| {
            Value::Tuple(vec![
                Value::Str("r".into()),
                Value::Tuple(vec![
                    Value::U64(0),
                    Value::Bytes(vec![0; 32]),
                    dict_ending_in(n),
                ]),
            ])
        })
    }

    /// Returns the end of the ref array of `listing`: the framing offset at
    /// the end of the listing.
    fn array_end(listing: &[u8]) -> usize {
        let width = ostrya_core::offset_size_for(listing.len());
        let mut end = [0u8; 8];
        end[..width].copy_from_slice(&listing[listing.len() - width..]);
        usize::try_from(u64::from_le_bytes(end)).unwrap()
    }

    /// The listing writer gives the bytes of `to_bytes` for no entries, and
    /// for framing offsets of 1, 2, and 4 bytes. One case has offsets of 1
    /// byte in the ref array and of 2 bytes in the outer tuple.
    ///
    /// The boundary cases put the data of the ref array, or of the outer
    /// tuple, and its framing offsets at 255 and 256 bytes for offsets of 1
    /// byte, and at 65,535 and 65,536 bytes for offsets of 2 bytes. At the
    /// first size of each pair, the offsets keep their width. At the second,
    /// they get wider.
    #[test]
    fn the_listing_writer_frames_as_to_bytes_does() {
        let mode = || {
            let mut metadata = Value::Array(Vec::new());
            append_dict_entry(
                &mut metadata,
                MODE_KEY,
                variant("s", Value::Str("archive-z2".into())).unwrap(),
            )
            .unwrap();
            metadata
        };
        let long_metadata = {
            let mut metadata = mode();
            append_dict_entry(
                &mut metadata,
                COLLECTION_ID_KEY,
                variant("s", Value::Str("c".repeat(200))).unwrap(),
            )
            .unwrap();
            metadata
        };
        let cases = [
            (Vec::new(), Value::Array(Vec::new()), 1),
            (Vec::new(), mode(), 1),
            (entries_of(1, 4), mode(), 1),
            (entries_of(1, 4), long_metadata, 2),
            (entries_of(8, 40), mode(), 2),
            (entries_of(3, 30_000), mode(), 4),
        ];
        for (entries, metadata, width) in cases {
            let bytes = listing_both_ways(entries, metadata);
            assert_eq!(ostrya_core::offset_size_for(bytes.len()), width);
        }

        // The ref array holds one entry, so its data and its offsets at the
        // narrow width are the entry and one offset.
        for (data_and_offset, narrow, array_len) in [
            (255, 1, 255),
            (256, 1, 257),
            (65_535, 2, 65_535),
            (65_536, 2, 65_538),
        ] {
            let entry = entry_of_size(data_and_offset - narrow);
            let listing = listing_both_ways(vec![entry], Value::Array(Vec::new()));
            assert_eq!(array_end(&listing), array_len, "{data_and_offset}");
        }

        // With no entry, the outer tuple holds the metadata dict and one
        // offset.
        for (data_and_offset, narrow, listing_len) in [
            (255, 1, 255),
            (256, 1, 257),
            (65_535, 2, 65_535),
            (65_536, 2, 65_538),
        ] {
            let metadata = value_of_size(METADATA_SIGNATURE, data_and_offset - narrow, |n| {
                dict_ending_in(n)
            });
            let listing = listing_both_ways(Vec::new(), metadata);
            assert_eq!(listing.len(), listing_len, "{data_and_offset}");
        }
    }

    /// The listing that the writer returns holds no large unused capacity,
    /// after the buffer grew from a capacity of 0.
    #[test]
    fn the_listing_writer_returns_a_buffer_near_its_length() {
        let listing = listing_both_ways(entries_of(1000, 40), Value::Array(Vec::new()));
        let spare = listing.capacity() - listing.len();
        assert!(spare < listing.len() / 8, "{spare} of {}", listing.len());
    }

    /// The floor of a ref entry is at most the size of each entry, and is the
    /// size of the smallest entry: a name whose NUL ends at a multiple of 8
    /// bytes, and no version. A version adds at least its floor.
    #[test]
    fn the_ref_entry_floor_is_the_size_of_the_smallest_entry() {
        let entry_ty = Type::parse(REF_ENTRY_SIGNATURE).unwrap();
        let size = |name: &str, version: Option<&str>| {
            let entry = ref_entry(name, 0, &checksum(0), version, 0).unwrap();
            to_bytes(&entry_ty, &entry).unwrap().len() as u64
        };
        let long = "v".repeat(300);
        for len in 1..=40 {
            let name = "n".repeat(len);
            let bare = size(&name, None);
            assert!(bare >= len as u64 + REF_ENTRY_FLOOR, "{len}");
            if (len + 1) % 8 == 0 {
                assert_eq!(bare, len as u64 + REF_ENTRY_FLOOR, "{len}");
            }
            for version in ["", "1", "1.0.0", long.as_str()] {
                let with = size(&name, Some(version));
                assert!(with >= bare + version_floor(version), "{len} {version}");
            }
        }
    }

    /// The floor of a delta map entry is at most the size of each entry.
    #[test]
    fn the_delta_entry_floor_is_a_lower_bound() {
        let ty = Type::parse("v").unwrap();
        for count in 1..=3u8 {
            let deltas: Vec<AdvertisedDelta> = (0..count)
                .map(|i| AdvertisedDelta {
                    from: None,
                    to: checksum(i),
                    superblock: checksum(100 + i),
                })
                .collect();
            let map = advertised_delta_map(&deltas).unwrap();
            let len = to_bytes(&ty, &map).unwrap().len() as u64;
            assert!(len >= u64::from(count) * DELTA_ENTRY_FLOOR, "{count}");
        }
    }

    /// Returns a new archive repository in `dir` with one commit that has a
    /// version, a delta from scratch to it with an index file, and each ref of
    /// `names` on that commit.
    async fn repo_with_refs(dir: &std::path::Path, names: &[&str]) -> Repo {
        let create = crate::CreateOptions::new(ostrya_core::RepoMode::Archive);
        let repo = Repo::create(dir, create).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let dirmeta = DirMeta {
            uid: 0,
            gid: 0,
            mode: ANCHOR_DIR_MODE,
            xattrs: Default::default(),
        };
        let dirmeta = txn
            .write_metadata(ObjectType::DirMeta, None, &dirmeta.serialize().unwrap())
            .await
            .unwrap();
        let mut mtree = MutableTree::new();
        mtree.set_metadata_checksum(dirmeta);
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let mut metadata = Value::Array(Vec::new());
        append_dict_entry(
            &mut metadata,
            "version",
            variant("s", Value::Str("1.0.0".into())).unwrap(),
        )
        .unwrap();
        let options = CommitOptions {
            parent: None,
            subject: None,
            body: None,
            timestamp: Some(1_700_000_000),
            metadata: Some(metadata),
        };
        let commit = txn.write_commit(options, &root).await.unwrap();
        txn.commit().await.unwrap();
        for name in names {
            repo.set_ref_immediate(name, Some(&commit)).await.unwrap();
        }
        let options = crate::DeltaOptions {
            timestamp: Some(1_700_000_000),
            ..crate::DeltaOptions::default()
        };
        repo.generate_static_delta(None, &commit, &options)
            .await
            .unwrap();
        repo.reindex_static_deltas().await.unwrap();
        repo
    }

    /// Returns `true` if `outcome` is the cap error.
    fn is_cap_error(outcome: &Result<Vec<u8>>) -> bool {
        matches!(
            outcome,
            Err(Error::Remote(crate::remote::Error::LimitExceeded(_)))
        )
    }

    /// A listing fits in a cap of its own length, in a buffer no larger than
    /// the cap, and each lower cap refuses it with the cap error. The listing
    /// has a version in each entry and a delta map, so each floor check is
    /// on the path. The checks of the names and of the metadata come before
    /// the commit reads.
    #[test]
    fn a_ref_listing_fits_its_cap_to_the_byte() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-ref-listing-cap-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ostrya_rt::block_on(async {
            let names = ["a/b", "a/c", "z"];
            let repo = repo_with_refs(&dir, &names).await;
            let full = repo.build_ref_listing(&[]).await.unwrap();
            let parsed = Summary::parse(&full).unwrap();
            assert_eq!(parsed.refs.len(), 3);
            assert_eq!(parsed.static_deltas().unwrap().len(), 1);
            assert!(
                parsed.refs[0]
                    .metadata
                    .dict_get(COMMIT_VERSION_KEY)
                    .is_some()
            );
            let len = full.len() as u64;
            let capped = repo.build_ref_listing_capped(&[], len).await.unwrap();
            assert_eq!(capped, full);
            assert!(capped.capacity() as u64 <= len);
            for cap in 0..len {
                let outcome = repo.build_ref_listing_capped(&[], cap).await;
                assert!(is_cap_error(&outcome), "cap {cap}: {outcome:?}");
            }

            // With no commit object, a cap below the floor of the names and
            // the metadata still gives the cap error, so these checks come
            // before the commit reads. A cap of that floor passes them, and
            // the commit read fails.
            let names_floor: u64 = names
                .iter()
                .map(|name| name.len() as u64 + REF_ENTRY_FLOOR)
                .sum();
            let floor =
                names_floor + serialize_signature_dict(&parsed.metadata).unwrap().len() as u64;
            let commit = parsed.refs[0].commit;
            let path = loose_path(&commit, ObjectType::Commit, repo.mode());
            std::fs::remove_file(dir.join("objects").join(path)).unwrap();
            for cap in [names_floor - 1, floor - 1] {
                let outcome = repo.build_ref_listing_capped(&[], cap).await;
                assert!(is_cap_error(&outcome), "cap {cap}: {outcome:?}");
            }
            for cap in [floor, MAX_REF_LISTING] {
                let outcome = repo.build_ref_listing_capped(&[], cap).await;
                assert!(
                    matches!(outcome, Err(Error::ObjectNotFound { .. })),
                    "cap {cap}: {outcome:?}"
                );
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
