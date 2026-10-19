//! The summary of a repository: the `summary` file and its signatures.
//!
//! The summary is a GVariant file at the repository root. It lists the refs
//! of the repository and holds a dict of global metadata. A pull reads it to
//! resolve refs and to find static deltas.
//!
//! - [`Repo::regenerate_summaries`] writes the root summary `summary`, which
//!   holds each ref, and the summary of each auth item of the client groups,
//!   with the options in [`SummaryOptions`]. It signs each one, and returns
//!   a [`SummaryReport`]. [`Repo::regenerate_summary`] writes them
//!   unsigned. With [`SummaryOptions::auth_items_only`], the two calls write
//!   the summaries of the auth items alone.
//! - [`Repo::sign_summary`] and [`Repo::sign_summary_all`] add signatures to
//!   each summary. [`Repo::verify_summary`] verifies the signatures in
//!   `summary.sig`.
//! - [`Repo::read_summary`] and [`Repo::read_summary_signature`] read
//!   `summary` and `summary.sig`. [`Repo::read_summary_of`] reads the
//!   summary of one auth item.
//! - [`Repo::build_ref_listing`] builds a ref listing for one request: a
//!   summary of the local refs and of the collection refs that two
//!   [`RefSelector`] values select, with a size cap. It returns a
//!   [`RefListing`].
//! - [`Summary`] is the parsed form of a `summary` file.
//!   [`Summary::static_deltas`] reads its delta map as [`AdvertisedDelta`]
//!   values.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

use ostrya_core::{
    Checksum, Commit, DirMeta, ObjectType, RefSelector, RepoMode, Type, Value, choose_offset_size,
    from_bytes, loose_path, to_bytes, tuple_field_from_bytes, write_offset,
};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::access::{AuthItem, ClientAccess, ReadAccess, SummaryFiles};
use crate::commit::{CommitOptions, append_dict_entry};
use crate::deltagen::{
    DeltaDigest, STATIC_DELTAS_KEY, advertised_delta_map, parse_delta_name, summary_delta_map,
};
use crate::error::{Error, Result};
use crate::lock::{LockKind, UpdateLockHeld};
use crate::mtree::MutableTree;
use crate::perm;
use crate::refs::RefSelection;
use crate::remote::proto::MAX_REF_LISTING;
use crate::repo::Repo;
use crate::sign::{Signer, Verifier, VerifyOutcome, append_signature, signatures_for};

/// The GVariant type of the summary: `(refs, global_metadata)`.
const SUMMARY_SIGNATURE: &str = "(a(s(taya{sv}))a{sv})";
/// The `a{sv}` type of the global metadata of the summary and of `summary.sig`.
const METADATA_SIGNATURE: &str = "a{sv}";
/// The type of one entry of the ref list of the summary.
const REF_ENTRY_SIGNATURE: &str = "(s(taya{sv}))";
/// The type of one entry of the global metadata dict.
const DICT_ENTRY_SIGNATURE: &str = "{sv}";
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
pub(crate) const COLLECTION_ID_KEY: &str = "ostree.summary.collection-id";
const COMMIT_VERSION_KEY: &str = "ostree.commit.version";
pub(crate) const COMMIT_TIMESTAMP_KEY: &str = "ostree.commit.timestamp";
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

/// A ref listing that [`Repo::build_ref_listing`] built for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefListing {
    /// The bytes of the listing: a summary GVariant
    /// `(a(s(taya{sv}))a{sv})` with no signature, which [`Summary::parse`]
    /// reads.
    pub bytes: Vec<u8>,
    /// The name of each directory under `refs/mirrors/` whose name fails
    /// the collection-id rule, sorted byte-wise, each one time.
    ///
    /// The listing holds no ref of these directories. The list is empty for
    /// a request with no selector of the collection refs, because the build
    /// then reads no such directory. A server writes a warning for each
    /// name.
    pub invalid_collection_dirs: Vec<String>,
}

/// The report of [`Repo::regenerate_summaries`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SummaryReport {
    /// The name of each directory under `refs/mirrors/` whose name fails
    /// the collection-id rule, sorted byte-wise, each one time.
    ///
    /// No summary holds a ref of these directories. A command writes a
    /// warning for each name.
    pub invalid_collection_dirs: Vec<String>,
}

/// The step at which [`Repo::write_summaries`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SummaryStep {
    /// The read of the refs or of the deltas, or the build of a summary.
    Build,
    /// A signature of a summary.
    Sign,
    /// A write or a removal of a file.
    Write,
}

/// A failure of [`Repo::write_summaries`]: the step, the key, and the
/// error.
///
/// The receive path reads the step and the key for its warning.
#[derive(Debug)]
pub(crate) struct SummaryFailure {
    #[cfg_attr(not(feature = "receive"), allow(dead_code))]
    pub(crate) step: SummaryStep,
    /// The name of the key whose signature failed, for
    /// [`SummaryStep::Sign`].
    #[cfg_attr(not(feature = "receive"), allow(dead_code))]
    pub(crate) key: Option<String>,
    pub(crate) error: Error,
}

/// The kind of a summary that the writer builds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SummaryKind {
    /// The root summary, which a local reader reads. It states the mode of
    /// the repository.
    Root,
    /// The summary of an auth item, which a server serves through the
    /// archive view. It states the mode `archive-z2`.
    Served,
}

impl SummaryKind {
    /// Returns the mode that a summary of this kind states in a repository
    /// of the mode `mode`.
    fn mode(self, mode: RepoMode) -> RepoMode {
        match self {
            SummaryKind::Root => mode,
            SummaryKind::Served => RepoMode::Archive,
        }
    }

    /// Returns `true` if a summary of this kind in a repository of the mode
    /// `mode` names static deltas.
    ///
    /// The archive view serves `deltas/` and `delta-indexes/` in an
    /// `archive` repository alone, so outside that mode a served summary
    /// names no delta.
    fn names_deltas(self, mode: RepoMode) -> bool {
        self == SummaryKind::Root || mode.is_archive()
    }
}

/// The state of one run of [`Repo::write_summaries`].
struct SummaryRun {
    /// The client groups that give the items.
    access: Arc<ClientAccess>,
    /// The `ostree.summary.last-modified` value of each summary.
    last_modified: u64,
    /// The selection of each ref of the repository.
    every: RefSelection,
    /// The facts of the commit of each ref of `every`. With
    /// [`SummaryOptions::auth_items_only`], the facts of the commit of each
    /// ref of `every` that an item with a summary reads.
    facts: HashMap<Checksum, CommitFacts>,
    /// Each static delta of the repository, sorted by name. With
    /// [`SummaryOptions::auth_items_only`], empty when no summary of an item
    /// of the run names a delta.
    deltas: Vec<DeltaDigest>,
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
    /// A ref listing that a request with a selector of the collection refs
    /// gets holds the selected collection refs in this map.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the variant that holds the map has a type
    ///   other than `a{sa(s(taya{sv}))}`, or if the map does not have the
    ///   shape of that type.
    pub fn collection_map(&self) -> Result<Vec<(String, Vec<SummaryRef>)>> {
        let entries = collection_map_entries(&self.metadata)?;
        let mut collections = Vec::with_capacity(entries.len());
        for entry in entries {
            let (collection, refs) = collection_map_entry(entry)?;
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

/// Parses only the ref list, field 0, of the bytes of a `summary` file.
///
/// The global metadata dict stays undecoded. The framing checks are those of
/// [`Summary::parse`].
///
/// # Errors
///
/// - [`Error::Core`] if the codec cannot read the bytes as the summary type.
/// - [`Error::InvalidFormat`] if a ref entry does not have the shape of the
///   type.
pub(crate) fn parse_ref_list(bytes: &[u8]) -> Result<Vec<SummaryRef>> {
    let ty = Type::parse(SUMMARY_SIGNATURE).map_err(ostrya_core::Error::from)?;
    let Value::Array(entries) =
        tuple_field_from_bytes(&ty, bytes, 0).map_err(ostrya_core::Error::from)?
    else {
        return Err(malformed("summary field 0 is not an array"));
    };
    entries.into_iter().map(parse_ref_entry).collect()
}

/// Returns the refs of the collection `id` in the
/// `ostree.summary.collection-map` of the global metadata dict `metadata`.
///
/// The list is empty if the dict has no map, or if the map has no entry of
/// `id`. If the map holds `id` two times, the first entry counts. The call
/// parses the refs of that entry alone, and copies no ref of another
/// collection.
///
/// # Errors
///
/// - [`Error::InvalidFormat`] for the reasons of
///   [`Summary::collection_map`], in the entries up to the entry of `id`.
pub(crate) fn collection_map_refs(metadata: &Value, id: &str) -> Result<Vec<SummaryRef>> {
    for entry in collection_map_entries(metadata)? {
        let (collection, refs) = collection_map_entry(entry)?;
        if collection == id {
            return refs.iter().cloned().map(parse_ref_entry).collect();
        }
    }
    Ok(Vec::new())
}

/// Returns the entries of the `ostree.summary.collection-map` of the global
/// metadata dict `metadata`, or no entry if the dict has no map.
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if the variant that holds the map has a type
///   other than `a{sa(s(taya{sv}))}`, or if the map is not an array.
fn collection_map_entries(metadata: &Value) -> Result<&[Value]> {
    let Some((ty, map)) = metadata
        .dict_get(COLLECTION_MAP_KEY)
        .and_then(Value::as_variant)
    else {
        return Ok(&[]);
    };
    let signature = ty.signature();
    if signature != COLLECTION_MAP_SIGNATURE {
        return Err(malformed(&format!(
            "the collection map has type `{signature}`, not `{COLLECTION_MAP_SIGNATURE}`"
        )));
    }
    map.as_array()
        .ok_or_else(|| malformed("the collection map is not an array"))
}

/// Returns the collection id and the ref entries of one entry of the
/// collection map.
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if the entry is not a pair of an id and an
///   array.
fn collection_map_entry(entry: &Value) -> Result<(&String, &[Value])> {
    let Some([Value::Str(collection), Value::Array(refs)]) = entry.as_tuple() else {
        return Err(malformed("a collection-map entry is not (id, refs)"));
    };
    Ok((collection, refs))
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

/// The options of [`Repo::regenerate_summary`] and
/// [`Repo::regenerate_summaries`].
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
    /// ignores this field. A call with [`SummaryOptions::auth_items_only`]
    /// set to `true` writes no anchor commit, so it also ignores this field.
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
    /// The switch that writes the summaries of the auth items alone.
    ///
    /// If it is `false` (the default), the call writes the root summary and
    /// the summary of each auth item. If it is `true`, the call writes the
    /// summary of each auth item and removes the files of each item with no
    /// summary, as with `false`. It leaves `summary` and `summary.sig` at the
    /// repository root as they are, and no signer signs them. In a repository
    /// with a collection id, the call writes no anchor commit.
    pub auth_items_only: bool,
}

/// Methods that write, read, sign, and verify the summary.
impl Repo {
    /// Writes the summaries that
    /// [`regenerate_summaries`](Repo::regenerate_summaries) writes, unsigned.
    ///
    /// The call is [`regenerate_summaries`](Repo::regenerate_summaries) with
    /// no signer. It drops the report.
    ///
    /// # Errors
    ///
    /// The errors of [`regenerate_summaries`](Repo::regenerate_summaries).
    pub async fn regenerate_summary(&self, opts: &SummaryOptions) -> Result<()> {
        self.regenerate_summaries(opts, &[]).await.map(drop)
    }

    /// Writes the root summary and the summary of each auth item that has a
    /// summary, and signs each summary with `signers`.
    ///
    /// The root summary holds each ref of the repository, whatever the
    /// client groups. It is the summary that the `ostree` command writes for
    /// the same refs. A local reader reads it, for example
    /// [`read_summary`](Repo::read_summary) and a local pull. A server never
    /// serves it.
    ///
    /// The client groups of the config ([`ClientAccess::from_config`]) give
    /// the auth items. An item has a summary when one or more of its groups
    /// has `summary=true`. A config with no client group has the two
    /// implicit groups, which set `summary=true`, so the `anonymous` item has
    /// a summary that holds each ref.
    ///
    /// If [`SummaryOptions::auth_items_only`] is `true`, the call writes the
    /// summaries of the auth items alone. It does not build, sign, or write
    /// the root summary, and it writes no anchor commit.
    ///
    /// The checks of [`SummaryOptions::additional_metadata`] and of the
    /// client groups come before each write and before each lock. A refusal
    /// writes nothing, the anchor commit included.
    ///
    /// # Files
    ///
    /// `HEX` below is the SHA-256 digest, in 64 lowercase hex digits, of the
    /// text of the item ([`AuthItem`] `Display`).
    ///
    /// - The root summary is `summary` and `summary.sig` at the repository
    ///   root.
    /// - The summary of each item, `anonymous` included, is
    ///   `extensions/ostrya/summary/HEX` and
    ///   `extensions/ostrya/summary/HEX.sig`.
    /// - Each item with a summary, `anonymous` included, has
    ///   `extensions/ostrya/summary/HEX.access`. It holds the access digest
    ///   of the item ([`ClientAccess::summary_digest`]) in 64 lowercase hex
    ///   digits and a newline.
    ///
    /// Unless [`SummaryOptions::auth_items_only`] is set, the call first
    /// builds and signs the root summary. It removes the old
    /// `summary.sig`, writes `summary`, and writes the new `summary.sig` if
    /// `signers` is not empty.
    ///
    /// Then the call handles one item at a time, in the order of
    /// [`ClientAccess::items`]. It builds the summary and makes each
    /// signature. Then it writes the files of the item in this order:
    ///
    /// 1. When the `.access` file holds another digest, the call removes it.
    /// 2. It removes the old signature file, writes the summary, and writes
    ///    the new signature file if `signers` is not empty.
    /// 3. When the `.access` file does not hold the access digest of the
    ///    item, it writes the `.access` file.
    ///
    /// So while the `.access` file of an item holds a digest, the summary
    /// next to it is a summary of that digest. Each file is written
    /// atomically, with the mode `0644`. If `[core] fsync` is `true`, the
    /// call syncs the data of each file and the repository root after the
    /// write of the root summary. It also syncs the directory of the
    /// `.access` file after the removal of step 1 and after the write of
    /// step 3, and the directory of the summary before step 3.
    ///
    /// Then the call removes the files of each item that has no summary.
    /// Under `extensions/ostrya/summary/`, it removes each file
    /// `HEX`, `HEX.sig`, and `HEX.access` of no item with a summary, the
    /// `.access` files first, and each temp file of these names that an
    /// interrupted write left. It leaves each other entry.
    ///
    /// The call creates `extensions/`, `extensions/ostrya/`, and
    /// `extensions/ostrya/summary/` with the mode `0775`, less the
    /// file-creation mask. In a `bare-user-shared` repository, it forces the
    /// mode `02770` on each directory that it creates. It opens each of these
    /// directories with no symlink followed.
    ///
    /// # Refs
    ///
    /// The root summary holds each local ref and each collection ref. The
    /// summary of an item holds the refs that the item reads in each
    /// namespace whose selected group has `summary=true`, by the rules of
    /// [`build_ref_listing`](Repo::build_ref_listing) with empty selectors
    /// for the local refs and for the collection refs. A namespace whose
    /// selected group has `summary=false` adds no ref. Field 0 holds the
    /// local refs, sorted byte-wise by name: the refs under `refs/heads` and,
    /// in a repository with `[core] collection-id`, the refs under
    /// `refs/mirrors/ID/` of that id, under their plain names. When the two
    /// directories hold one name, field 0 holds the commit of the mirror ref.
    /// The refs of each other collection go into
    /// `ostree.summary.collection-map`. A directory under `refs/mirrors/`
    /// whose name fails the collection-id rule is in no summary, and its
    /// name is in [`SummaryReport::invalid_collection_dirs`].
    ///
    /// Each entry of field 0 and of the map holds:
    ///
    /// - the size of the commit object in bytes, in host order,
    /// - the 32-byte checksum of the commit,
    /// - a metadata dict of the ref: `ostree.commit.version` if the commit
    ///   records a version, then `ostree.commit.timestamp`, big-endian.
    ///
    /// # Global metadata
    ///
    /// The summary is a `(a(s(taya{sv}))a{sv})` GVariant. Field 1 is the
    /// global metadata dict. Its entries have a fixed order, and the byte
    /// identity of the file depends on this order:
    ///
    /// 1. `ostree.summary.mode`. The root summary states the mode of the
    ///    repository. The summary of an item states `archive-z2`, the mode
    ///    of the [`ArchiveView`](crate::ArchiveView) that serves it.
    /// 2. `ostree.summary.last-modified`, big-endian
    ///    ([`SummaryOptions::last_modified`]). Each summary of one call has
    ///    the same value.
    /// 3. `ostree.summary.tombstone-commits`, the value of `[core]
    ///    tombstone-commits`.
    /// 4. `ostree.static-deltas`, if the summary lists a delta.
    /// 5. `ostree.summary.collection-map`, if the summary holds a collection
    ///    ref.
    /// 6. `ostree.summary.indexed-deltas`, the value of `[core]
    ///    indexed-deltas`. The summary of an item outside `archive` mode
    ///    has no such entry.
    /// 7. `ostree.summary.collection-id`, if `[core] collection-id` is set.
    ///
    /// The keys of [`SummaryOptions::additional_metadata`] come after these
    /// entries, in each summary. The summary of an item outside `archive`
    /// mode drops the caller keys `ostree.static-deltas` and
    /// `ostree.summary.indexed-deltas`.
    ///
    /// # Static deltas
    ///
    /// `ostree.static-deltas` maps the name of a delta under `deltas/` to the
    /// SHA-256 digest of its `superblock`, as an `ay` variant. A pull uses
    /// the map to find a delta and to verify the superblock that it fetches.
    /// The entries are in the order of the delta names.
    ///
    /// The root summary names deltas in each mode. The summary of an item
    /// names deltas in an `archive` repository alone, because the
    /// [`ArchiveView`](crate::ArchiveView) serves `deltas/` and
    /// `delta-indexes/` in that mode alone. The summary of an item outside
    /// `archive` mode has no `ostree.static-deltas` and no
    /// `ostree.summary.indexed-deltas`.
    ///
    /// When the summary holds each local ref and each collection ref of the
    /// repository, as the root summary does, the map holds each delta. Else it holds the deltas whose
    /// target commit is the commit of a ref in the summary.
    ///
    /// The `ostree` command writes the map in hash-table order. This order
    /// depends on the set of names and, for some names, on the order of the
    /// reads of the names. The two writers write the same entries. Their
    /// orders agree only where the hash-table order is name order by chance.
    ///
    /// # Collection id
    ///
    /// If the repository sets `[core] collection-id` and
    /// [`SummaryOptions::auth_items_only`] is `false`, the call first writes
    /// a new anchor commit to `refs/heads/ostree-metadata`. The anchor
    /// commit:
    ///
    /// - has an empty root tree, with uid 0, gid 0, and the mode `0o40755`,
    /// - holds the collection id in `ostree.collection-binding`, and
    ///   `["ostree-metadata"]` in `ostree.ref-binding`,
    /// - has the previous anchor commit as its parent, if one exists,
    /// - has the timestamp that
    ///   [`SummaryOptions::metadata_commit_timestamp`] states.
    ///
    /// Each regeneration that writes an anchor commit adds a commit to the
    /// chain, and a summary whose item reads `ostree-metadata` lists the new
    /// checksum of the anchor commit.
    ///
    /// The `ostree` command copies the caller keys into the metadata of the
    /// anchor commit. ostrya does not reproduce the order of these keys, so a
    /// repository with a collection id refuses each caller key.
    ///
    /// # Signatures
    ///
    /// Each signer signs the exact bytes of each summary, in slice order. Two
    /// summaries with the same bytes get the same signatures, which the
    /// signers make one time. The signature file of a summary holds these
    /// signatures alone, in the form of
    /// [`sign_summary_all`](Repo::sign_summary_all). With no signer, the
    /// call removes each signature file of the summaries that it writes. If
    /// a signer fails, the summaries before the summary of the failure keep
    /// their new files, and the summary of the failure and the summaries
    /// after it keep their old files. The root summary, when the call writes
    /// it, comes first.
    ///
    /// # Size
    ///
    /// A summary is at most 64 MiB (67108864 bytes), the cap of each reader
    /// of a summary in this crate. The call refuses a larger summary before
    /// it writes a file of the summary. The summaries before it keep their
    /// new files, and the summary of the refusal and the summaries after it
    /// keep their old files. The root summary, when the call writes it, comes
    /// first. The names of the refs give a lower bound of the size, so the
    /// call can refuse a summary before it reads the commits of its refs.
    ///
    /// # Locks
    ///
    /// The call takes the repository lock shared and then the update lock, as
    /// [`begin_update`](Repo::begin_update) does. It holds both from the read
    /// of the previous anchor commit to the last removal. Because of this
    /// hold, two regenerations never put their anchor commits on one parent.
    /// The anchor commit commits under this hold and does not take the update
    /// lock again.
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
    ///   if a client group or the server group is malformed
    ///   ([`ClientAccess::from_config`]), if `[core] lock-timeout-secs` is
    ///   below `-1`, if a ref file is not UTF-8, if the system clock is
    ///   before the Unix epoch, if a summary is larger than 64 MiB, or if
    ///   `extensions`, `extensions/ostrya`, or `extensions/ostrya/summary` is
    ///   not a directory.
    /// - [`Error::Unsupported`] if the repository has a collection id and
    ///   [`SummaryOptions::additional_metadata`] is not empty.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, `[core]
    ///   lock-timeout-secs`, `[core] tombstone-commits`, or `[core]
    ///   indexed-deltas` does not parse, if a value of a client group does
    ///   not parse, if a ref file holds no checksum, or if a commit object
    ///   does not parse.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::ObjectNotFound`] if a ref names a commit that is not in the
    ///   object store.
    /// - [`Error::Signature`], or the variant that the engine error converts
    ///   to, if a signer fails.
    /// - In a repository with a collection id, an error of
    ///   [`transaction`](Repo::transaction) or of
    ///   [`Transaction::commit`](crate::Transaction::commit) for the anchor
    ///   commit.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn regenerate_summaries(
        &self,
        opts: &SummaryOptions,
        signers: &[&dyn Signer],
    ) -> Result<SummaryReport> {
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
        // The client groups give the items. A malformed group is refused
        // before the anchor advances.
        let access = Arc::new(ClientAccess::from_config(self.config(), self.path())?);
        self.config().fsync()?;

        // The repository lock comes before the update lock. The anchor
        // transaction takes the repository lock shared too, before the update
        // lock, so its staging directory is made outside the update lock. A
        // run that writes the summaries of the auth items alone writes no
        // anchor.
        let repo_lock = self.lock_repo(LockKind::Shared).await?;
        let txn = match &collection_id {
            Some(_) if !opts.auth_items_only => Some(self.transaction().await?),
            _ => None,
        };
        let held = self.lock_update().await?;

        // A repository with a collection id advertises a new anchor commit, so
        // the anchor commit comes before the list of refs. It goes to
        // refs/heads/ostree-metadata, and a summary must list its new
        // checksum.
        if let (Some(cid), Some(txn)) = (&collection_id, txn) {
            self.refresh_anchor_commit(txn, cid, opts, &held).await?;
        }

        let report = self
            .write_summaries(access, opts, signers)
            .await
            .map_err(|failure| failure.error)?;
        drop(held);
        drop(repo_lock);
        Ok(report)
    }

    /// Writes the root summary, unless [`SummaryOptions::auth_items_only`] is
    /// set, and the summary of each item of `access`, as
    /// [`regenerate_summaries`](Repo::regenerate_summaries) states. Then it
    /// removes the files of each other item.
    ///
    /// The caller holds the update lock, and the anchor commit of the run, if
    /// the run writes one, is in place.
    /// The call checks no value of [`SummaryOptions::additional_metadata`].
    /// A failure names the step at which the call stopped.
    pub(crate) async fn write_summaries(
        &self,
        access: Arc<ClientAccess>,
        opts: &SummaryOptions,
        signers: &[&dyn Signer],
    ) -> std::result::Result<SummaryReport, SummaryFailure> {
        let build = |error| SummaryFailure {
            step: SummaryStep::Build,
            key: None,
            error,
        };
        let write = |error| SummaryFailure {
            step: SummaryStep::Write,
            key: None,
            error,
        };
        let fsync = self.config().fsync().map_err(write)?;
        let run = self.summary_run(access, opts).await.map_err(build)?;
        let items: Vec<(AuthItem, SummaryFiles)> = run
            .access
            .items()
            .filter_map(|item| {
                let files = run.access.summary_files(item)?;
                Some((item.clone(), files.clone()))
            })
            .collect();
        // The signature file of each distinct summary of the run, by the
        // SHA-256 digest of its bytes. Two summaries with the same bytes
        // share one signature file, so each signer signs each distinct
        // summary one time.
        let mut signed: HashMap<Checksum, Vec<u8>> = HashMap::new();
        let mut sign = async |bytes: &[u8]| -> std::result::Result<_, SummaryFailure> {
            if signers.is_empty() {
                return Ok(None);
            }
            let key = Checksum::sha256(bytes);
            if let Some(signatures) = signed.get(&key) {
                return Ok(Some(signatures.clone()));
            }
            let signatures = sign_summary_bytes(bytes, signers)
                .await
                .map_err(|(key, error)| SummaryFailure {
                    step: SummaryStep::Sign,
                    key,
                    error,
                })?;
            if let Some(signatures) = &signatures {
                signed.insert(key, signatures.clone());
            }
            Ok(signatures)
        };
        // The root summary holds each ref, whatever the client groups.
        if !opts.auth_items_only {
            let bytes = self
                .selection_summary(&run, &run.every, SummaryKind::Root, opts)
                .await
                .map_err(build)?;
            let signatures = sign(&bytes).await?;
            let repo = self.clone();
            ostrya_rt::unblock(move || put_root_summary_blocking(&repo, &bytes, signatures, fsync))
                .await
                .map_err(write)?;
        }
        for (item, files) in &items {
            let bytes = self.item_summary(&run, item, opts).await.map_err(build)?;
            let signatures = sign(&bytes).await?;
            let repo = self.clone();
            let files = files.clone();
            ostrya_rt::unblock(move || {
                put_item_summary_blocking(&repo, &bytes, signatures, &files, fsync)
            })
            .await
            .map_err(write)?;
        }
        let kept: HashSet<String> = items.iter().map(|(_, files)| files.stem.clone()).collect();
        let repo = self.clone();
        ostrya_rt::unblock(move || remove_other_summaries_blocking(&repo, &kept, fsync))
            .await
            .map_err(write)?;
        Ok(SummaryReport {
            invalid_collection_dirs: run.every.invalid_dirs,
        })
    }

    /// Returns the state of one run of the summary writer: the selection of
    /// each ref of the repository, the facts of the commits of these refs,
    /// the static deltas, and the `ostree.summary.last-modified` value of
    /// each summary.
    ///
    /// With [`SummaryOptions::auth_items_only`], the call reads the commits
    /// of the refs that the items with a summary read, and reads the static
    /// deltas only when a summary of an item names deltas.
    async fn summary_run(
        &self,
        access: Arc<ClientAccess>,
        opts: &SummaryOptions,
    ) -> Result<SummaryRun> {
        let last_modified = resolve_last_modified(opts.last_modified)?;
        let all = RefSelector::parse([])?;
        let own = self.config().collection_id();
        let everyone = ReadAccess::new(
            Arc::new(ClientAccess::implicit(own)),
            AuthItem::Anonymous,
            None,
        );
        let every = self.select_refs(&all, Some(&all), &everyone, None).await?;
        let (facts, deltas) = if opts.auth_items_only {
            // The run writes no root summary, so it reads only what the
            // summaries of the items use. `summary_bytes` reads each commit
            // that the walk of an item finds.
            let items: Vec<&AuthItem> = access
                .items()
                .filter(|item| access.summary_files(item).is_some())
                .collect();
            let commits: HashSet<Checksum> = if access.has_client_groups() {
                items
                    .iter()
                    .filter_map(|item| {
                        let read = ReadAccess::for_summary(access.clone(), (*item).clone());
                        every.readable(&read)
                    })
                    .flat_map(|selection| commits_of(&selection))
                    .collect()
            } else {
                commits_of(&every)
            };
            let facts = if commits.is_empty() {
                HashMap::new()
            } else {
                self.commit_facts(commits).await?
            };
            let deltas = if items.is_empty() || !SummaryKind::Served.names_deltas(self.mode()) {
                Vec::new()
            } else {
                self.static_delta_digests().await?
            };
            (facts, deltas)
        } else {
            (
                self.commit_facts(commits_of(&every)).await?,
                self.static_delta_digests().await?,
            )
        };
        Ok(SummaryRun {
            access,
            last_modified,
            every,
            facts,
            deltas,
        })
    }

    /// Returns the bytes of the summary of `item` in the run `run`.
    ///
    /// The call writes nothing. The caller checks the values of
    /// [`SummaryOptions::additional_metadata`].
    async fn item_summary(
        &self,
        run: &SummaryRun,
        item: &AuthItem,
        opts: &SummaryOptions,
    ) -> Result<Vec<u8>> {
        // With no client group, the item is `anonymous` under the implicit
        // groups, which have `summary=true`. Its rights are the rights of the
        // full selection of the run, so the call takes that selection. Each
        // other item takes the refs of the full selection that it reads. When
        // the full selection did not read a ref that the item reads, the
        // call walks the refs with the rights of the item.
        let selected;
        let selection = if run.access.has_client_groups() {
            let read = ReadAccess::for_summary(run.access.clone(), item.clone());
            selected = match run.every.readable(&read) {
                Some(selected) => selected,
                None => {
                    let all = RefSelector::parse([])?;
                    self.select_refs(&all, Some(&all), &read, None).await?
                }
            };
            &selected
        } else {
            &run.every
        };
        self.selection_summary(run, selection, SummaryKind::Served, opts)
            .await
    }

    /// Returns the bytes of the summary of the kind `kind` of the refs
    /// `selection` in the run `run`.
    async fn selection_summary(
        &self,
        run: &SummaryRun,
        selection: &RefSelection,
        kind: SummaryKind,
        opts: &SummaryOptions,
    ) -> Result<Vec<u8>> {
        // A summary of each ref lists each delta. Each other summary lists
        // the deltas to the commits of its refs, because another delta can
        // name a commit that the item does not read.
        let deltas: Vec<&DeltaDigest> = if !kind.names_deltas(self.mode()) {
            Vec::new()
        } else if same_refs(selection, &run.every) {
            run.deltas.iter().collect()
        } else {
            let commits = commits_of(selection);
            run.deltas
                .iter()
                .filter(|delta| commits.contains(&delta.to))
                .collect()
        };
        let deltas = if deltas.is_empty() {
            None
        } else {
            Some(summary_delta_map(
                deltas
                    .iter()
                    .map(|delta| (delta.name.as_str(), &delta.digest)),
            )?)
        };
        self.summary_bytes(
            &selection.local,
            &selection.collections,
            run,
            deltas,
            kind,
            &opts.additional_metadata,
        )
        .await
    }

    /// Returns the bytes of a summary of the kind `kind` of the local refs
    /// `local` and of the collection refs `collections`, with the delta map
    /// `deltas`.
    ///
    /// `local` and each list of `collections` are sorted byte-wise by name.
    /// The call takes the facts of the commits and the
    /// `ostree.summary.last-modified` value of the run `run`. It reads each
    /// other commit one time.
    /// The global metadata has the order of
    /// [`regenerate_summaries`](Repo::regenerate_summaries), "Global metadata".
    async fn summary_bytes(
        &self,
        local: &[(String, Checksum)],
        collections: &BTreeMap<String, Vec<(String, Checksum)>>,
        run: &SummaryRun,
        deltas: Option<Value>,
        kind: SummaryKind,
        added: &[(String, Value)],
    ) -> Result<Vec<u8>> {
        let facts = &run.facts;
        // The names give a lower bound of the size of the summary, so a
        // summary over the cap is refused before the commit reads and the
        // build.
        check_summary_size(
            local
                .iter()
                .map(|(name, _)| name.len() as u64 + REF_ENTRY_FLOOR)
                .sum::<u64>()
                + collection_map_floor(collections),
        )?;
        // A ref can name a commit that the facts of the run do not hold, if
        // the walk of an item read a ref of `refs/heads` that the full
        // selection did not read, or if the ref changed after the full
        // selection.
        let missing: HashSet<Checksum> = local
            .iter()
            .chain(collections.values().flatten())
            .map(|(_, commit)| *commit)
            .filter(|commit| !facts.contains_key(commit))
            .collect();
        let read = if missing.is_empty() {
            HashMap::new()
        } else {
            self.commit_facts(missing).await?
        };
        let entry = |name: &str, commit: &Checksum| {
            let fact = facts
                .get(commit)
                .or_else(|| read.get(commit))
                .expect("the facts of each commit are in one of the two maps");
            ref_entry(
                name,
                fact.size,
                commit,
                fact.version.as_deref(),
                fact.timestamp,
            )
        };
        let ref_entries = local
            .iter()
            .map(|(name, commit)| entry(name, commit))
            .collect::<Result<Vec<_>>>()?;
        let collection_map = if collections.is_empty() {
            None
        } else {
            let mut values = Vec::with_capacity(collections.len());
            for (collection, refs) in collections {
                let ref_values = refs
                    .iter()
                    .map(|(name, commit)| entry(name, commit))
                    .collect::<Result<Vec<_>>>()?;
                values.push(Value::Tuple(vec![
                    Value::Str(collection.clone()),
                    Value::Array(ref_values),
                ]));
            }
            Some(variant(COLLECTION_MAP_SIGNATURE, Value::Array(values))?)
        };

        let names_deltas = kind.names_deltas(self.mode());
        let mut metadata = Value::Array(Vec::new());
        append_dict_entry(
            &mut metadata,
            MODE_KEY,
            variant(
                "s",
                Value::Str(kind.mode(self.mode()).as_mode_str().to_owned()),
            )?,
        )?;
        append_dict_entry(
            &mut metadata,
            LAST_MODIFIED_KEY,
            variant("t", big_endian_u64(run.last_modified))?,
        )?;
        append_dict_entry(
            &mut metadata,
            TOMBSTONE_KEY,
            variant("b", Value::Bool(self.config().tombstone_commits()?))?,
        )?;
        if let Some(deltas) = deltas {
            append_dict_entry(&mut metadata, STATIC_DELTAS_KEY, deltas)?;
        }
        if let Some(map) = collection_map {
            append_dict_entry(&mut metadata, COLLECTION_MAP_KEY, map)?;
        }
        if names_deltas {
            append_dict_entry(
                &mut metadata,
                INDEXED_DELTAS_KEY,
                variant("b", Value::Bool(self.config().indexed_deltas()?))?,
            )?;
        }
        if let Some(cid) = self.config().collection_id() {
            append_dict_entry(
                &mut metadata,
                COLLECTION_ID_KEY,
                variant("s", Value::Str(cid.to_owned()))?,
            )?;
        }
        for (key, value) in caller_entries(&metadata, added) {
            // A summary that names no static delta takes no delta key of the
            // caller.
            if !names_deltas && (key == STATIC_DELTAS_KEY || key == INDEXED_DELTAS_KEY) {
                continue;
            }
            append_dict_entry(&mut metadata, key, value.clone())?;
        }

        let summary = Value::Tuple(vec![Value::Array(ref_entries), metadata]);
        let ty = Type::parse(SUMMARY_SIGNATURE).map_err(ostrya_core::Error::from)?;
        let bytes = to_bytes(&ty, &summary).map_err(ostrya_core::Error::from)?;
        check_summary_size(bytes.len() as u64)?;
        Ok(bytes)
    }

    /// Returns a ref listing: a summary of the local refs that `refs`
    /// selects, and of the collection refs that `collections` selects, that
    /// `access` reads, built for one request.
    ///
    /// The listing has the type of a `summary` file, `(a(s(taya{sv}))a{sv})`,
    /// and [`Summary::parse`] reads it. The call writes nothing and takes no
    /// lock. One state of the repository gives the same bytes.
    ///
    /// # Refs
    ///
    /// A ref is selected when the selector has no positive pattern or a
    /// positive pattern matches its name, and no negative pattern matches it.
    /// The pattern `a/*` selects `a/b` and the pattern `a/**` selects `a/b`
    /// and `a/b/c`. An empty selector selects each ref. A selector of
    /// negative patterns alone selects each ref that they do not match. The
    /// order of the entries has no effect.
    ///
    /// Field 0 holds the local refs that `refs` selects, each one time,
    /// sorted byte-wise by name. The local refs are the refs under
    /// `refs/heads` and, in a repository with `[core] collection-id`, the
    /// refs under `refs/mirrors/ID/` of that id, under their plain names.
    /// When the two directories hold one name, field 0 holds one entry with
    /// the commit of the mirror ref. `collections` has no effect on field 0.
    /// In a repository with no `refs/mirrors/ID/` of its own id, field 0
    /// holds the refs of `refs/heads` alone.
    ///
    /// `collections` selects the refs under `refs/mirrors/` of each other
    /// collection by `ID/NAME`, for example `org.example.Os/stable` or
    /// `*/stable`. An entry of one part, such as `org.example.Os`, selects no
    /// ref, and an entry of the own id selects no ref. The selected refs go
    /// into `ostree.summary.collection-map`, in the form of the summary: the
    /// collections sorted byte-wise by id, and the refs of each collection
    /// sorted byte-wise by name. A collection with no selected ref is not in
    /// the map, and with no selected collection ref the listing holds no
    /// map. With `None`, the call reads no collection ref, and the listing
    /// has the bytes of the listing of `refs` alone.
    ///
    /// An alias is in the listing under its own name, with the commit of its
    /// target. The listing holds no remote ref. Each entry has the bytes of
    /// the entry of the same ref in a summary of the same repository state.
    ///
    /// # Collection directories
    ///
    /// With `collections`, the call reads the top level of `refs/mirrors/`
    /// one time, whatever the rights of `access`. A directory whose name
    /// fails the collection-id rule ([`is_collection_id`](crate::is_collection_id))
    /// is left out of the listing, and the call reads no entry in it. The
    /// names of these directories are in
    /// [`RefListing::invalid_collection_dirs`], so a server can write a
    /// warning. A name that is not UTF-8, and an entry at the top level that
    /// is no directory, are left out with no report. With `None`, the call
    /// reads only `refs/mirrors/ID/` of the own id.
    ///
    /// # Access
    ///
    /// The listing holds a selected ref only when `access` reads it
    /// ([`ReadAccess::can_read`](crate::access::ReadAccess::can_read)). A
    /// local ref takes the group of the item in the local namespace, and a
    /// collection ref takes the group of the item in the namespace of its
    /// collection: the group of the exact id, else the group of
    /// `collection=*`. The rules of two groups never combine. In a group
    /// with `tls-accept-claim=true`, the claims of the namespace replace the
    /// rules of the group. The call checks the name before it reads the ref
    /// file, so it never reads a ref file that `access` does not read. The
    /// content of such a file does not fail the listing. The call reads no
    /// directory of a collection whose group gives no `r`.
    ///
    /// An alias is in the listing when `access` reads its name and its
    /// target, and the target is a regular file. The alias resolves by the
    /// rule of [`ArchiveView`](crate::ArchiveView#routing): its body is
    /// relative, it stays inside `refs/`, and the call follows one link with
    /// no symlink followed on the path of the target. The path of the target
    /// gives its namespace. Each other alias is not in the listing, also an
    /// alias of an alias and an alias to a ref under `refs/remotes/`.
    ///
    /// The call reads only the directories that a positive pattern can
    /// match, and it reads no ref file outside the literal leading parts of
    /// a positive pattern and its matches. A leading wildcard lists the
    /// directories at its level. It skips a directory that a negative
    /// pattern covers, and it applies the negative patterns to a name before
    /// it reads the ref file, so it reads no ref that the selector does not
    /// select. It reads each commit one time, also when more than one ref
    /// names it. An empty selector, and a selector of negative patterns
    /// alone, read only the directories that an allow item that gives `r`
    /// in the group of the namespace can match, and no directory that a deny
    /// item of that group covers. A name that the ref-name rule refuses is in
    /// the walk, and a wildcard selects it.
    ///
    /// # Global metadata
    ///
    /// The global metadata dict holds these entries, in this order:
    ///
    /// 1. `ostree.summary.mode`, `archive-z2`, the mode of the
    ///    [`ArchiveView`](crate::ArchiveView).
    /// 2. `ostree.static-deltas`, if the index files advertise a delta.
    /// 3. `ostree.summary.collection-map`, if the listing holds a collection
    ///    ref.
    /// 4. `ostree.summary.collection-id`, if `[core] collection-id` is set.
    ///
    /// This is the order of the same keys in a summary. The values have the
    /// encoding of the same keys in a summary. The dict holds no
    /// `ostree.summary.last-modified`.
    ///
    /// In an `archive` repository, the deltas come from the index files under
    /// `delta-indexes/` alone, which
    /// [`reindex_static_deltas`](Repo::reindex_static_deltas) writes.
    /// The call reads the index file of the commit of each listed ref, a
    /// collection ref included. Then it reads the index file of each source
    /// commit that an index file names, until it finds no new commit. A
    /// commit with no index file adds no delta. The map is sorted by delta
    /// name. In every other mode, the listing names no delta, and the call
    /// reads nothing under `delta-indexes/`, because the view serves no
    /// delta in these modes.
    ///
    /// # Size
    ///
    /// The listing is at most [`MAX_REF_LISTING`] bytes. The call refuses a
    /// larger listing before the whole listing is in memory. It never cuts
    /// the listing short. Each check below compares a lower bound of the
    /// size of the listing with the cap, so a listing that fits passes each
    /// check. The call refuses the listing at the first check that fails:
    ///
    /// 1. During and after the read of the refs: the size of each entry, from
    ///    the length of the ref name, and the size of the collection map,
    ///    from the length of each collection id. The call checks the sum
    ///    after each ref that it selects, and reads no more ref file when the
    ///    sum passes the cap. No commit and no index file is read before
    ///    this check.
    /// 2. After the delta walk: the same sum and the size of the delta map,
    ///    from the number of deltas.
    /// 3. After the serialization of the global metadata other than the
    ///    collection map: the same sum and the length of the metadata. No
    ///    commit is read before this check.
    /// 4. During the read of the commits: the same sum and, for each ref, the
    ///    size of the version of its commit.
    /// 5. During the write of the entries and of the collection map: the
    ///    length of the listing.
    ///
    /// # Errors
    ///
    /// - [`Error::Remote`] with
    ///   [`LimitExceeded`](crate::remote::Error::LimitExceeded) if the
    ///   listing is larger than [`MAX_REF_LISTING`] bytes.
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8, or, in an
    ///   `archive` repository, if an index file is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), does not decode as
    ///   a delta index, or names a delta to another commit.
    /// - [`Error::Core`] if a ref file holds no checksum, or if a commit
    ///   object does not parse.
    /// - [`Error::ObjectNotFound`] if a listed ref names a commit that is not
    ///   in the object store.
    /// - [`Error::Io`] if a read fails, for example if `delta-indexes/` is not
    ///   a directory in an `archive` repository.
    ///
    /// A failure of one selected ref or of one index file fails the whole
    /// listing. The call does not read a ref that the selectors do not
    /// select or that `access` does not read.
    ///
    /// `ostrya-server` exports no handler of the listing. A host with a router
    /// of its own calls this method in its own handler.
    pub async fn build_ref_listing(
        &self,
        refs: &RefSelector,
        collections: Option<&RefSelector>,
        access: &ReadAccess,
    ) -> Result<RefListing> {
        self.build_ref_listing_capped(refs, collections, access, MAX_REF_LISTING)
            .await
    }

    /// Builds the listing of [`build_ref_listing`](Repo::build_ref_listing)
    /// with a size cap of `cap` bytes. A listing of exactly `cap` bytes fits.
    pub(crate) async fn build_ref_listing_capped(
        &self,
        refs: &RefSelector,
        collections: Option<&RefSelector>,
        access: &ReadAccess,
        cap: u64,
    ) -> Result<RefListing> {
        // The refs come sorted byte-wise by name, each one time, which is the
        // order of `build_summary`.
        let RefSelection {
            local,
            collections,
            invalid_dirs,
            ..
        } = self
            .select_refs(refs, collections, access, Some(cap))
            .await?;

        // Each entry is at least its name and the fixed fields. If the sum of
        // these sizes is over the cap, the listing is too. The selection
        // checks the same sum while it reads the refs.
        let mut floor: u64 = local
            .iter()
            .map(|(name, _)| name.len() as u64 + REF_ENTRY_FLOOR)
            .sum::<u64>()
            + collection_map_floor(&collections);
        check_floor(floor, cap)?;

        // The global metadata other than the map comes before the commit
        // reads, so its length is in the floor before a commit is in memory.
        // The listing has the kind of a served summary.
        let kind = SummaryKind::Served;
        let deltas = if kind.names_deltas(self.mode()) {
            let commits = local.iter().chain(collections.values().flatten());
            self.walk_delta_indexes(commits.map(|(_, commit)| *commit))
                .await?
        } else {
            Vec::new()
        };
        check_floor(floor + deltas.len() as u64 * DELTA_ENTRY_FLOOR, cap)?;
        let mut head = vec![dict_entry(
            MODE_KEY,
            variant(
                "s",
                Value::Str(kind.mode(self.mode()).as_mode_str().to_owned()),
            )?,
        )?];
        if !deltas.is_empty() {
            head.push(dict_entry(
                STATIC_DELTAS_KEY,
                advertised_delta_map(&deltas)?,
            )?);
        }
        drop(deltas);
        let mut tail = Vec::new();
        if let Some(cid) = self.config().collection_id() {
            tail.push(dict_entry(
                COLLECTION_ID_KEY,
                variant("s", Value::Str(cid.to_owned()))?,
            )?);
        }
        floor += dict_len(head.iter().chain(&tail)) as u64;
        check_floor(floor, cap)?;

        let repo = self.clone();
        let parts = ListingParts {
            local,
            collections,
            head,
            tail,
        };
        let bytes =
            ostrya_rt::unblock(move || write_ref_listing(&repo, &parts, floor, cap)).await?;
        Ok(RefListing {
            bytes,
            invalid_collection_dirs: invalid_dirs,
        })
    }

    /// Returns the bytes of `summary`, or `None` if the file does not exist.
    ///
    /// The call refuses a file larger than 64 MiB, the cap of a summary
    /// ([`regenerate_summaries`](Repo::regenerate_summaries), "Size").
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the file is larger than 64 MiB.
    /// - [`Error::Io`] if the read fails, for example if `summary` is a
    ///   symlink.
    pub async fn read_summary(&self) -> Result<Option<Vec<u8>>> {
        self.read_root_file(SUMMARY_FILE).await
    }

    /// Returns the bytes of the summary of the auth item `item`, or `None` if
    /// the file does not exist.
    ///
    /// The summary of each item, `anonymous` included, is
    /// `extensions/ostrya/summary/HEX`, where `HEX` is the SHA-256 digest of
    /// the text of the item
    /// ([`regenerate_summaries`](Repo::regenerate_summaries), "Files"). The call
    /// opens each component with no symlink followed. It does not compare the
    /// `.access` file of the item with the client groups. The call refuses a
    /// file larger than 64 MiB, as [`read_summary`](Repo::read_summary) does.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `extensions`, `extensions/ostrya`, or
    ///   `extensions/ostrya/summary` is not a directory, or if the file is
    ///   larger than 64 MiB.
    /// - [`Error::Io`] if the read fails, for example if the file is a
    ///   symlink.
    pub async fn read_summary_of(&self, item: &AuthItem) -> Result<Option<Vec<u8>>> {
        let repo = self.clone();
        let name = summary_stem(item);
        ostrya_rt::unblock(
            move || match open_summary_dir(repo.repo_fd(), None, false)? {
                Some(dir) => read_root_file_blocking(dir.as_fd(), &name),
                None => Ok(None),
            },
        )
        .await
    }

    /// Returns the signature dict of `summary.sig`, or `None` if the file does
    /// not exist or is empty.
    ///
    /// The dict is an `a{sv}` with one entry for each signing engine. The call
    /// refuses a file larger than 64 MiB. The read and the parse run in one
    /// call on the blocking pool.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the file is larger than 64 MiB.
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

    /// Signs each summary with `signer` and adds the signature to its
    /// signature file.
    ///
    /// The summaries are `summary` at the repository root and each
    /// `extensions/ostrya/summary/HEX` file, where `HEX` is 64 lowercase hex
    /// digits ([`regenerate_summaries`](Repo::regenerate_summaries), "Files").
    /// The signature file of `summary` is `summary.sig`, and the signature
    /// file of `HEX` is `HEX.sig`. The text below states `summary` and
    /// `summary.sig`, and each other summary follows the same rules.
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
    /// - [`Error::InvalidFormat`] if the repository has no summary, if
    ///   `[core] lock-timeout-secs` is below `-1`, if a summary or a signature
    ///   file is larger than 64 MiB, if the entry of the engine in a
    ///   signature file is not an array, or if `extensions`,
    ///   `extensions/ostrya`, or `extensions/ostrya/summary` is not a
    ///   directory.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or `[core]
    ///   lock-timeout-secs` does not parse, or if a signature file is not an
    ///   `a{sv}` dict.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::Signature`], or the variant that the engine error converts
    ///   to, if the signer fails.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn sign_summary(&self, signer: &dyn Signer) -> Result<()> {
        self.sign_summary_all(&[signer]).await
    }

    /// Signs each summary with each signer in `signers` and adds the
    /// signatures to its signature file in slice order.
    ///
    /// The summaries and their signature files are those of
    /// [`sign_summary`](Repo::sign_summary). The result is the signature
    /// file that one [`sign_summary`](Repo::sign_summary) call for each
    /// signer writes, in the same order. The call reads each summary and its
    /// signature file once and makes each signature. Two summaries with the
    /// same bytes get the same signatures, which the signers make one time.
    /// Then the call replaces each signature file atomically, with one write
    /// for each file.
    ///
    /// If a signer fails, the call stops before the first write, and each
    /// signature file stays as it is. An empty slice reads nothing, writes
    /// nothing, and takes no lock.
    ///
    /// # Locks
    ///
    /// The call takes the repository lock shared and then the update lock, as
    /// [`begin_update`](Repo::begin_update) does. It takes them before it
    /// reads the first summary and holds both until it writes the last
    /// signature file, so a signature always covers the summary next to it.
    ///
    /// The calls of several tasks or processes and
    /// [`regenerate_summary`](Repo::regenerate_summary) run one at a time, and
    /// no signature is lost. A caller that holds an
    /// [`UpdateGuard`](crate::UpdateGuard) of this repository waits for its
    /// own guard.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the repository has no summary, if
    ///   `[core] lock-timeout-secs` is below `-1`, if a summary or a signature
    ///   file is larger than 64 MiB, if the entry of the engine of a signer in
    ///   a signature file is not an array, or if `extensions`,
    ///   `extensions/ostrya`, or `extensions/ostrya/summary` is not a
    ///   directory.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or `[core]
    ///   lock-timeout-secs` does not parse, or if a signature file is not an
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
        let repo = self.clone();
        // The one open of the summary directory, for each read and each
        // write of the call.
        let (dir, stems) = ostrya_rt::unblock(move || -> Result<_> {
            match open_summary_dir(repo.repo_fd(), None, false)? {
                Some(dir) => {
                    let stems = item_summary_stems(&dir)?;
                    Ok((Some(Arc::new(dir)), stems))
                }
                None => Ok((None, Vec::new())),
            }
        })
        .await?;
        // The signatures of each distinct summary, by the SHA-256 digest of
        // its bytes, so each signer signs each distinct summary one time.
        let mut made: HashMap<Checksum, Vec<Vec<u8>>> = HashMap::new();
        // `None` is the summary at the repository root.
        let mut written: Vec<(Option<String>, Vec<u8>)> = Vec::new();
        for stem in std::iter::once(None).chain(stems.into_iter().map(Some)) {
            let repo = self.clone();
            let dir = dir.clone();
            let name = stem.clone();
            let read = ostrya_rt::unblock(move || -> Result<Option<(Vec<u8>, Option<Value>)>> {
                let (at, file, sig) = match &name {
                    Some(stem) => (
                        dir.as_deref()
                            .expect("each stem comes from the directory")
                            .as_fd(),
                        stem.clone(),
                        format!("{stem}{SIG_SUFFIX}"),
                    ),
                    None => (
                        repo.repo_fd(),
                        SUMMARY_FILE.to_owned(),
                        SUMMARY_SIG_FILE.to_owned(),
                    ),
                };
                let Some(data) = read_root_file_blocking(at, &file)? else {
                    return Ok(None);
                };
                let dict = match read_root_file_blocking(at, &sig)? {
                    Some(bytes) => parse_signature_dict(&bytes)?,
                    None => None,
                };
                Ok(Some((data, dict)))
            })
            .await?;
            let Some((data, dict)) = read else {
                continue;
            };
            let key = Checksum::sha256(&data);
            let signatures = match made.get(&key) {
                Some(signatures) => signatures.clone(),
                None => {
                    let mut signatures = Vec::with_capacity(signers.len());
                    for signer in signers {
                        signatures.push(signer.sign(&data).await?);
                    }
                    made.insert(key, signatures.clone());
                    signatures
                }
            };
            drop(data);
            let mut dict = dict.unwrap_or_else(|| Value::Array(Vec::new()));
            for (signer, signature) in signers.iter().zip(signatures) {
                append_signature(&mut dict, signer.metadata_key(), signature)?;
            }
            written.push((stem, serialize_signature_dict(&dict)?));
        }
        if written.is_empty() {
            return Err(Error::InvalidFormat(
                "no summary to sign; regenerate it first".into(),
            ));
        }
        self.write_holding(locks, move |repo| {
            for (stem, bytes) in &written {
                let Some(stem) = stem else {
                    write_root_file_blocking(repo.repo_fd(), SUMMARY_SIG_FILE, bytes, fsync)?;
                    continue;
                };
                let at = dir.as_deref().expect("each stem comes from the directory");
                let name = format!("{stem}{SIG_SUFFIX}");
                write_root_file_blocking(at.as_fd(), &name, bytes, fsync)?;
            }
            Ok(())
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
    /// `commits`, by checksum.
    ///
    /// The call reads the commits in one pass on the blocking pool. It reads
    /// each commit object one time, under the size cap of a metadata object,
    /// and holds one commit in memory at a time.
    async fn commit_facts(
        &self,
        commits: HashSet<Checksum>,
    ) -> Result<HashMap<Checksum, CommitFacts>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            commits
                .into_iter()
                .map(|commit| Ok((commit, read_commit_facts(&repo, &commit)?)))
                .collect()
        })
        .await
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
            .write_commit_unchecked(
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
    /// not exist. The call refuses a file larger than [`SUMMARY_READ_CAP`].
    pub(crate) async fn read_root_file(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        let name = name.to_owned();
        ostrya_rt::unblock(move || read_root_file_blocking(repo_fd.as_fd(), &name)).await
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

/// The parts of a ref listing that [`write_ref_listing`] writes.
struct ListingParts {
    /// The refs of field 0, sorted byte-wise by name.
    local: Vec<(String, Checksum)>,
    /// The refs of `ostree.summary.collection-map`, by collection id.
    collections: BTreeMap<String, Vec<(String, Checksum)>>,
    /// The serialized `{sv}` entries of the global metadata before the map.
    head: Vec<Vec<u8>>,
    /// The serialized `{sv}` entries of the global metadata after the map.
    tail: Vec<Vec<u8>>,
}

/// Writes the ref listing of `parts` on the calling thread.
///
/// `floor` is a lower bound of the size of the listing from the names of
/// the refs, from the collection ids, and from the metadata entries. The
/// call reads each distinct commit of field 0 and of the map one time. It
/// adds the size of the version of each commit to the floor, one time for
/// each ref that names the commit, and refuses the listing when the floor
/// passes `cap`. Then it writes the entries of field 0, the metadata
/// entries, and the map, one entry at a time.
fn write_ref_listing(
    repo: &Repo,
    parts: &ListingParts,
    mut floor: u64,
    cap: u64,
) -> Result<Vec<u8>> {
    // `slots[i]` is the index in `commits` of the commit of ref `i`, field 0
    // first and then the map in its order. Each item of `commits` is a
    // distinct commit and the number of refs that name it.
    let mut index: HashMap<Checksum, usize> = HashMap::new();
    let mut commits: Vec<(Checksum, u64)> = Vec::new();
    let slots: Vec<usize> = parts
        .local
        .iter()
        .chain(parts.collections.values().flatten())
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
    let mut slots = slots.into_iter();
    let mut entry = |name: &str, commit: &Checksum| -> Result<Vec<u8>> {
        let fact = &facts[slots.next().expect("one slot for each ref")];
        let entry = ref_entry(
            name,
            fact.size,
            commit,
            fact.version.as_deref(),
            fact.timestamp,
        )?;
        Ok(to_bytes(&entry_ty, &entry).map_err(ostrya_core::Error::from)?)
    };
    let mut listing = ListingWriter::new(cap, floor, parts.local.len());
    for (name, commit) in &parts.local {
        listing.push_entry(&entry(name, commit)?)?;
    }
    listing.start_metadata()?;
    for bytes in &parts.head {
        listing.push_entry(bytes)?;
    }
    if !parts.collections.is_empty() {
        listing.start_map(COLLECTION_MAP_KEY)?;
        for (id, refs) in &parts.collections {
            listing.start_collection(id, refs.len())?;
            for (name, commit) in refs {
                listing.push_entry(&entry(name, commit)?)?;
            }
            listing.end_collection()?;
        }
        listing.end_map(COLLECTION_MAP_SIGNATURE)?;
    }
    for bytes in &parts.tail {
        listing.push_entry(bytes)?;
    }
    listing.finish()
}

/// Returns a lower bound of the bytes that `ostree.summary.collection-map`
/// of `collections` adds to a ref listing, or 0 for no collection.
///
/// The count is the key of the entry and its NUL, the zero byte and the type
/// of the variant, and for each collection the id, its NUL, and the framing
/// offset of the end of the id. Each ref adds the floor of a ref entry,
/// [`REF_ENTRY_FLOOR`] and the name. The padding and the framing offsets of
/// the arrays are not in the count.
fn collection_map_floor(collections: &BTreeMap<String, Vec<(String, Checksum)>>) -> u64 {
    if collections.is_empty() {
        return 0;
    }
    let each: u64 = collections
        .iter()
        .map(|(id, refs)| {
            let names: u64 = refs
                .iter()
                .map(|(name, _)| name.len() as u64 + REF_ENTRY_FLOOR)
                .sum();
            id.len() as u64 + 2 + names
        })
        .sum();
    COLLECTION_MAP_FIXED_FLOOR + each
}

/// The fewest bytes of `ostree.summary.collection-map` other than its
/// collections: the key of the entry and its NUL, and the zero byte and the
/// type of the variant.
const COLLECTION_MAP_FIXED_FLOOR: u64 =
    (COLLECTION_MAP_KEY.len() + 1 + 1 + COLLECTION_MAP_SIGNATURE.len()) as u64;

/// The lower bound of the size of a ref listing that
/// [`Repo::select_refs`] keeps while it reads the refs.
///
/// The bound grows to the sum of the first size check of
/// [`build_ref_listing`](Repo::build_ref_listing): each ref adds
/// [`REF_ENTRY_FLOOR`] and its name, and the collection map adds the count of
/// [`collection_map_floor`]. The bound never passes that sum.
pub(crate) struct SelectionFloor {
    /// The bound so far.
    floor: u64,
    /// The cap of the listing, or `None` for no cap.
    cap: Option<u64>,
    /// `true` once the bound holds a collection of the map.
    map: bool,
}

impl SelectionFloor {
    /// Returns the bound of no ref, for a listing with the cap `cap`.
    pub(crate) fn new(cap: Option<u64>) -> SelectionFloor {
        SelectionFloor {
            floor: 0,
            cap,
            map: false,
        }
    }

    /// Adds a ref entry with the name `name`.
    ///
    /// # Errors
    ///
    /// The cap error of the listing if the bound passes the cap.
    pub(crate) fn add_ref(&mut self, name: &str) -> Result<()> {
        self.add(name.len() as u64 + REF_ENTRY_FLOOR)
    }

    /// Adds the collection `id` of the map, before its first ref. The first
    /// collection also adds the fixed part of the map.
    ///
    /// # Errors
    ///
    /// The cap error of the listing if the bound passes the cap.
    pub(crate) fn add_collection(&mut self, id: &str) -> Result<()> {
        let fixed = if self.map {
            0
        } else {
            COLLECTION_MAP_FIXED_FLOOR
        };
        self.map = true;
        self.add(fixed + id.len() as u64 + 2)
    }

    /// Adds `bytes` to the bound and checks it against the cap.
    fn add(&mut self, bytes: u64) -> Result<()> {
        self.floor += bytes;
        match self.cap {
            Some(cap) => check_floor(self.floor, cap),
            None => Ok(()),
        }
    }
}

/// Returns the serialized `{sv}` entry of `key` and `value`, a variant.
fn dict_entry(key: &str, value: Value) -> Result<Vec<u8>> {
    let ty = Type::parse(DICT_ENTRY_SIGNATURE).map_err(ostrya_core::Error::from)?;
    let entry = Value::Tuple(vec![Value::Str(key.to_owned()), value]);
    Ok(to_bytes(&ty, &entry).map_err(ostrya_core::Error::from)?)
}

/// Returns the length of the `a{sv}` dict of the serialized entries
/// `entries`: each entry at a multiple of 8 bytes, then the framing offset of
/// the end of each entry.
fn dict_len<'a>(entries: impl Iterator<Item = &'a Vec<u8>>) -> usize {
    let mut len: usize = 0;
    let mut count = 0;
    for entry in entries {
        len = len.next_multiple_of(LISTING_ALIGNMENT) + entry.len();
        count += 1;
    }
    if count == 0 {
        return 0;
    }
    len + count * choose_offset_size(len, count)
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

/// The writer of a ref listing, a `(a(s(taya{sv}))a{sv})` GVariant, one
/// entry at a time.
///
/// The writer gives the bytes that `to_bytes` gives for the whole value. It
/// writes the ref entries of field 0, then the entries of the metadata dict.
/// The map of `ostree.summary.collection-map` goes into the dict one
/// collection and one ref entry at a time. The writer checks the length
/// against the cap before each append, so a listing over the cap fails
/// before it is whole in memory.
///
/// Each container of the listing has an alignment of 8: the outer tuple, the
/// ref arrays, the dict, a dict entry, the map, and an entry of the map. So
/// a value at an aligned position of the buffer has the bytes of the value
/// alone.
struct ListingWriter {
    out: Vec<u8>,
    /// The containers that are open, the outer tuple first.
    open: Vec<Container>,
    cap: u64,
}

/// One open container of a listing: a tuple, an array, or a dict entry.
struct Container {
    /// The position of the container in the buffer.
    start: usize,
    /// The framing offsets of the container, counted from its start: the end
    /// of each member of an array, and the end of each member of a tuple or
    /// a dict entry other than the last member.
    ends: Vec<usize>,
}

impl ListingWriter {
    /// Returns a writer of a listing of `entries` ref entries in field 0,
    /// with a size cap of `cap` bytes. The buffer starts with a capacity of
    /// `floor` bytes, a lower bound of the size of the listing, and no more
    /// than the cap. The outer tuple and the ref array of field 0 are open.
    fn new(cap: u64, floor: u64, entries: usize) -> ListingWriter {
        let container = |members| Container {
            start: 0,
            ends: Vec::with_capacity(members),
        };
        ListingWriter {
            out: Vec::with_capacity(usize::try_from(floor.min(cap)).unwrap_or(usize::MAX)),
            open: vec![container(1), container(entries)],
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

    /// Appends `bytes` with no padding.
    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        self.make_room(bytes.len())?;
        self.out.extend_from_slice(bytes);
        Ok(())
    }

    /// Appends zero bytes up to the alignment of each container.
    fn align(&mut self) -> Result<()> {
        let aligned = self.out.len().next_multiple_of(LISTING_ALIGNMENT);
        self.make_room(aligned - self.out.len())?;
        self.out.resize(aligned, 0);
        Ok(())
    }

    /// Records the end of the buffer as a framing offset of the innermost
    /// open container.
    fn mark(&mut self) {
        let container = self.open.last_mut().expect("a container is open");
        container.ends.push(self.out.len() - container.start);
    }

    /// Opens a container of `members` framing offsets at the next aligned
    /// position.
    fn open(&mut self, members: usize) -> Result<()> {
        self.align()?;
        self.open.push(Container {
            start: self.out.len(),
            ends: Vec::with_capacity(members),
        });
        Ok(())
    }

    /// Closes the innermost open container: it appends the framing offsets
    /// of the container, in order. An empty array has no offset.
    fn close(&mut self) -> Result<()> {
        let container = self.open.pop().expect("a container is open");
        if !container.ends.is_empty() {
            let len = self.out.len() - container.start;
            let width = choose_offset_size(len, container.ends.len());
            self.make_room(container.ends.len() * width)?;
            for end in container.ends {
                write_offset(&mut self.out, end, width);
            }
        }
        Ok(())
    }

    /// Appends the serialized entry `entry` to the innermost open array: the
    /// ref array of field 0, the metadata dict, or the ref array of a
    /// collection.
    ///
    /// An entry has an alignment of 8, so its bytes at an aligned position
    /// equal its bytes alone.
    fn push_entry(&mut self, entry: &[u8]) -> Result<()> {
        self.align()?;
        self.append(entry)?;
        self.mark();
        Ok(())
    }

    /// Closes the ref array of field 0, and opens the metadata dict.
    fn start_metadata(&mut self) -> Result<()> {
        self.close()?;
        // The tuple holds the end of field 0 as its one framing offset.
        self.mark();
        self.open(0)
    }

    /// Opens the dict entry `key` of the map, and the map in its variant.
    fn start_map(&mut self, key: &str) -> Result<()> {
        self.open(1)?;
        self.append(key.as_bytes())?;
        self.append(&[0])?;
        self.mark();
        // The child of a variant starts at the start of the variant.
        self.open(0)
    }

    /// Opens the entry of the collection `id` in the map, and its ref array
    /// of `refs` entries.
    fn start_collection(&mut self, id: &str, refs: usize) -> Result<()> {
        self.open(1)?;
        self.append(id.as_bytes())?;
        self.append(&[0])?;
        self.mark();
        self.open(refs)
    }

    /// Closes the ref array and the entry of a collection.
    fn end_collection(&mut self) -> Result<()> {
        self.close()?;
        self.close()?;
        self.mark();
        Ok(())
    }

    /// Closes the map, ends its variant with the type `signature`, and
    /// closes the dict entry of the map.
    fn end_map(&mut self, signature: &str) -> Result<()> {
        self.close()?;
        self.append(&[0])?;
        self.append(signature.as_bytes())?;
        self.close()?;
        self.mark();
        Ok(())
    }

    /// Closes the metadata dict and the outer tuple, and returns the listing.
    /// The function gives the unused capacity of the buffer back to the
    /// allocator.
    fn finish(mut self) -> Result<Vec<u8>> {
        self.close()?;
        self.close()?;
        debug_assert!(self.open.is_empty(), "each container is closed");
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

/// The largest summary: 64 MiB.
///
/// The size of the summary grows with the number of refs and deltas, and each
/// reader loads it whole. This bound protects against a corrupt or hostile
/// file. The writer refuses a larger summary, so each summary that it writes
/// passes each reader.
pub(crate) const SUMMARY_READ_CAP: u64 = 64 * 1024 * 1024;

/// Reads a whole file relative to `repo_fd`, or returns `None` if it does not
/// exist.
///
/// The read does not follow a symlink. It refuses a file larger than
/// [`SUMMARY_READ_CAP`] with [`Error::InvalidFormat`], and reads at most one
/// byte past the cap.
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
    file.take(SUMMARY_READ_CAP + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > SUMMARY_READ_CAP {
        return Err(Error::InvalidFormat(format!(
            "{name} is larger than its cap of {SUMMARY_READ_CAP} bytes"
        )));
    }
    Ok(Some(buf))
}

/// Refuses a summary of `size` bytes, or of at least `size` bytes, when
/// `size` is larger than [`SUMMARY_READ_CAP`], the cap of each reader.
fn check_summary_size(size: u64) -> Result<()> {
    if size > SUMMARY_READ_CAP {
        return Err(Error::InvalidFormat(format!(
            "the summary is larger than its cap of {SUMMARY_READ_CAP} bytes"
        )));
    }
    Ok(())
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

/// Removes `name` at the repository root, and returns `true` if it removed
/// a file. If the file does not exist, the call succeeds with `false`.
pub(crate) fn remove_root_file_blocking(repo_fd: BorrowedFd<'_>, name: &str) -> Result<bool> {
    match rustix::fs::unlinkat(repo_fd, name, AtFlags::empty()) {
        Ok(()) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// The directory of the summaries of the auth items, and of the `.access`
/// file of each item with a summary.
pub(crate) const SUMMARY_DIR: &str = "extensions/ostrya/summary";
/// The components of [`SUMMARY_DIR`], from the repository root.
const SUMMARY_DIR_PARTS: [&str; 3] = ["extensions", "ostrya", "summary"];
/// The mode of each directory of [`SUMMARY_DIR`] that the writer creates,
/// before the file-creation mask.
const SUMMARY_DIR_MODE: u32 = 0o775;
/// The suffix of the signature file of the summary of an item.
pub(crate) const SIG_SUFFIX: &str = ".sig";
/// The suffix of the file that holds the access digest of an item.
pub(crate) const ACCESS_SUFFIX: &str = ".access";

/// Returns `HEX`, the file stem of the files of the summary of `item`: the
/// SHA-256 digest of the text of the item in 64 lowercase hex digits.
pub(crate) fn summary_stem(item: &AuthItem) -> String {
    Checksum::sha256(item.to_string().as_bytes()).to_hex()
}

/// Returns the bytes of an `.access` file that holds `digest`.
pub(crate) fn access_file_bytes(digest: &Checksum) -> Vec<u8> {
    format!("{}\n", digest.to_hex()).into_bytes()
}

/// Opens [`SUMMARY_DIR`] under `repo_fd`, one component at a time, with no
/// symlink followed.
///
/// With `create`, the mode of the repository, the call creates each
/// component that does not exist, with [`SUMMARY_DIR_MODE`], and forces the
/// shared mode on it in a `bare-user-shared` repository. With `fsync`, it
/// then syncs the parent of each directory that it creates. Without
/// `create`, a component that does not exist gives `None`.
///
/// A component that is a symlink, or that is no directory, gives
/// [`Error::InvalidFormat`].
fn open_summary_dir(
    repo_fd: BorrowedFd<'_>,
    create: Option<RepoMode>,
    fsync: bool,
) -> Result<Option<OwnedFd>> {
    let mut dir: Option<OwnedFd> = None;
    let mut path = String::new();
    for part in SUMMARY_DIR_PARTS {
        let parent = dir.as_ref().map_or(repo_fd, AsFd::as_fd);
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(part);
        let open = || {
            rustix::fs::openat(
                parent,
                part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        };
        let opened = match (open(), create) {
            (Err(Errno::NOENT), None) => return Ok(None),
            (Err(Errno::NOENT), Some(mode)) => {
                match rustix::fs::mkdirat(parent, part, Mode::from_raw_mode(SUMMARY_DIR_MODE)) {
                    Ok(()) => {
                        perm::force_created_dir(parent, part, mode)?;
                        if fsync {
                            rustix::fs::fsync(parent)?;
                        }
                    }
                    Err(Errno::EXIST) => {}
                    Err(e) => return Err(e.into()),
                }
                open()
            }
            (opened, _) => opened,
        };
        dir = Some(match opened {
            Ok(fd) => fd,
            Err(Errno::NOTDIR | Errno::LOOP) => {
                return Err(Error::InvalidFormat(format!(
                    "{path} is not a directory; the summaries follow no symlink"
                )));
            }
            Err(e) => return Err(e.into()),
        });
    }
    Ok(dir)
}

/// Returns `true` if `name` is 64 lowercase hex digits.
fn is_stem(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// One file name under [`SUMMARY_DIR`] that the writer owns: `HEX`,
/// `HEX.sig`, or `HEX.access`, or a temp file of one of these names.
struct SummaryEntry<'a> {
    stem: &'a str,
    /// `true` for a temp file of [`put_root_file_blocking`].
    temp: bool,
}

/// Returns the entry of `name`, or `None` for a name that the writer does
/// not own.
fn summary_entry(name: &str) -> Option<SummaryEntry<'_>> {
    let (name, temp) = match name.split_once(".tmp-") {
        Some((name, tail)) => {
            let (pid, n) = tail.split_once('-')?;
            let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
            if !digits(pid) || !digits(n) {
                return None;
            }
            (name, true)
        }
        None => (name, false),
    };
    let (stem, suffix) = name.split_at_checked(64)?;
    if !is_stem(stem) || !matches!(suffix, "" | SIG_SUFFIX | ACCESS_SUFFIX) {
        return None;
    }
    Some(SummaryEntry { stem, temp })
}

/// Returns the stem of each summary in `dir`, the open [`SUMMARY_DIR`],
/// sorted: each file name that is 64 lowercase hex digits.
fn item_summary_stems(dir: &OwnedFd) -> Result<Vec<String>> {
    let mut stems: Vec<String> = crate::delta::dir_child_names(dir)?
        .into_iter()
        .filter(|name| is_stem(name))
        .collect();
    stems.sort();
    Ok(stems)
}

/// Returns the signature file of `bytes` with a signature of each signer of
/// `signers`, in order, or `None` with no signer.
///
/// A failure of a signer gives the name of its key with the error.
async fn sign_summary_bytes(
    bytes: &[u8],
    signers: &[&dyn Signer],
) -> std::result::Result<Option<Vec<u8>>, (Option<String>, Error)> {
    if signers.is_empty() {
        return Ok(None);
    }
    let mut dict = Value::Array(Vec::new());
    for signer in signers {
        let signature = signer
            .sign(bytes)
            .await
            .map_err(|e| (Some(signer.name().to_owned()), e.into()))?;
        append_signature(&mut dict, signer.metadata_key(), signature)
            .map_err(|e| (None, e.into()))?;
    }
    serialize_signature_dict(&dict)
        .map(Some)
        .map_err(|e| (None, e))
}

/// Writes `summary` and `summary.sig` at the repository root: the summary
/// `bytes` and the signature file `signatures`.
fn put_root_summary_blocking(
    repo: &Repo,
    bytes: &[u8],
    signatures: Option<Vec<u8>>,
    fsync: bool,
) -> Result<()> {
    put_summary_files_blocking(
        repo.repo_fd(),
        SUMMARY_FILE,
        SUMMARY_SIG_FILE,
        bytes,
        signatures,
        fsync,
    )
}

/// Writes the summary `bytes` to `file` and the signature file `signatures`
/// to `sig`, both under `at`, after it removes the old `sig`. With `fsync`,
/// the call syncs `at` last.
fn put_summary_files_blocking(
    at: BorrowedFd<'_>,
    file: &str,
    sig: &str,
    bytes: &[u8],
    signatures: Option<Vec<u8>>,
    fsync: bool,
) -> Result<()> {
    // The old signatures never pair with the new summary.
    remove_root_file_blocking(at, sig)?;
    put_root_file_blocking(at, file, bytes, fsync)?;
    if let Some(signatures) = signatures {
        put_root_file_blocking(at, sig, &signatures, fsync)?;
    }
    if fsync {
        rustix::fs::fsync(at)?;
    }
    Ok(())
}

/// Writes the files of the summary of an item, whose access digest and file
/// stem are `files`.
///
/// When the `.access` file of the item holds another digest, the call
/// removes it first. Then it removes the old signature file, writes the
/// summary `bytes` and the signature file `signatures`, and writes the
/// `.access` file last, unless it holds the digest. So while the `.access`
/// file holds a digest, the summary next to it is a summary of that digest.
///
/// With `fsync`, the call syncs the directory of the `.access` file after
/// its removal and after its write, and the directory of the summary before
/// the write of the `.access` file. So after a crash too, an `.access` file
/// never pairs with a summary of another digest. When the summary and the
/// `.access` file are in one directory, the sync before the write of the
/// `.access` file keeps the order of the two renames.
fn put_item_summary_blocking(
    repo: &Repo,
    bytes: &[u8],
    signatures: Option<Vec<u8>>,
    files: &SummaryFiles,
    fsync: bool,
) -> Result<()> {
    let dir = open_summary_dir(repo.repo_fd(), Some(repo.mode()), fsync)?
        .expect("the call creates the directory");
    let access = format!("{}{ACCESS_SUFFIX}", files.stem);
    let want = access_file_bytes(&files.digest);
    let held = holds_blocking(dir.as_fd(), &access, &want)?;
    if held == Some(false) && remove_root_file_blocking(dir.as_fd(), &access)? && fsync {
        rustix::fs::fsync(&dir)?;
    }
    put_summary_files_blocking(
        dir.as_fd(),
        &files.stem,
        &format!("{}{SIG_SUFFIX}", files.stem),
        bytes,
        signatures,
        fsync,
    )?;
    // An `.access` file that holds the digest stays as it is.
    if held != Some(true) {
        put_root_file_blocking(dir.as_fd(), &access, &want, fsync)?;
        if fsync {
            rustix::fs::fsync(&dir)?;
        }
    }
    Ok(())
}

/// Returns `None` if `name` under `dir` does not exist, else `true` if it
/// is a file that holds exactly `want`.
///
/// The call follows no symlink, and a symlink gives `false`. The read stops
/// one byte past the length of `want`.
fn holds_blocking(dir: BorrowedFd<'_>, name: &str, want: &[u8]) -> Result<Option<bool>> {
    match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(crate::archive::holds(&std::fs::File::from(fd), want)?)),
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::LOOP) => Ok(Some(false)),
        Err(e) => Err(e.into()),
    }
}

/// Removes the files of each item with no summary.
///
/// `kept` holds the stem of each item with a summary. Under
/// [`SUMMARY_DIR`], the call removes each [`SummaryEntry`] of a stem outside
/// `kept`, the `.access` files first, and each temp file.
fn remove_other_summaries_blocking(repo: &Repo, kept: &HashSet<String>, fsync: bool) -> Result<()> {
    if let Some(dir) = open_summary_dir(repo.repo_fd(), None, false)? {
        let mut gone: Vec<String> = crate::delta::dir_child_names(&dir)?
            .into_iter()
            .filter(|name| match summary_entry(name) {
                None => false,
                Some(entry) => entry.temp || !kept.contains(entry.stem),
            })
            .collect();
        // The server stops serving a summary at the removal of its
        // `.access` file, so that file goes first.
        gone.sort_by_key(|name| !name.ends_with(ACCESS_SUFFIX));
        let mut removed = false;
        for name in &gone {
            removed |= remove_root_file_blocking(dir.as_fd(), name)?;
        }
        if fsync && removed {
            rustix::fs::fsync(&dir)?;
        }
    }
    Ok(())
}

/// Returns the commit of each ref of `selection`, each one time.
fn commits_of(selection: &RefSelection) -> HashSet<Checksum> {
    selection
        .local
        .iter()
        .chain(selection.collections.values().flatten())
        .map(|(_, commit)| *commit)
        .collect()
}

/// Returns `true` if `a` and `b` hold the same names of local refs and the
/// same names of collection refs.
fn same_refs(a: &RefSelection, b: &RefSelection) -> bool {
    fn same(a: &[(String, Checksum)], b: &[(String, Checksum)]) -> bool {
        a.iter()
            .map(|(name, _)| name)
            .eq(b.iter().map(|(name, _)| name))
    }
    same(&a.local, &b.local)
        && a.collections.len() == b.collections.len()
        && a.collections
            .iter()
            .zip(&b.collections)
            .all(|((a_id, a_refs), (b_id, b_refs))| a_id == b_id && same(a_refs, b_refs))
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

/// `SummaryOptions`, the parsed summary, its deltas, and a ref listing move
/// across tasks and threads, and so does the future of a ref listing.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SummaryOptions>();
    assert_send_sync::<Summary>();
    assert_send_sync::<AdvertisedDelta>();
    assert_send_sync::<RefListing>();
    fn assert_send<T: Send>(_: &T) {}
    let _ = |repo: &Repo, selector: &RefSelector, access: &ReadAccess| {
        assert_send(&repo.build_ref_listing(selector, Some(selector), access))
    };
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The rights of an anonymous client under the implicit groups.
    fn anyone() -> ReadAccess {
        let config = crate::RepoConfig::parse("[core]\nrepo_version=1\nmode=archive-z2\n").unwrap();
        let access =
            crate::access::ClientAccess::from_config(&config, std::path::Path::new("/")).unwrap();
        ReadAccess::new(
            std::sync::Arc::new(access),
            crate::access::AuthItem::Anonymous,
            None,
        )
    }

    /// The selector with no entry, which selects each ref.
    fn all_refs() -> RefSelector {
        RefSelector::parse([]).unwrap()
    }

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

    /// `item_summary` gives the bytes `regenerate_summary` writes for the
    /// `anonymous` item, for a repository with a collection id, whose anchor
    /// commit the regeneration refreshed, and it writes nothing.
    #[test]
    fn item_summary_gives_the_bytes_regenerate_summary_writes() {
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
            let access = Arc::new(ClientAccess::from_config(repo.config(), repo.path()).unwrap());
            let run = repo.summary_run(access, &opts).await.unwrap();
            let built = repo
                .item_summary(&run, &AuthItem::Anonymous, &opts)
                .await
                .unwrap();
            assert_eq!(built, written);
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
        let Value::Array(head) = metadata else {
            panic!("the metadata is a dict");
        };
        listing_with_map(entries, head, Vec::new(), Vec::new())
    }

    /// Writes a listing of `entries` with [`ListingWriter`] and with
    /// `to_bytes` of the whole value, checks that the two agree, and returns
    /// the bytes.
    ///
    /// The metadata dict holds the entries `head`, then the collection map
    /// of `map` if it is not empty, then the entries `tail`.
    fn listing_with_map(
        entries: Vec<Value>,
        head: Vec<Value>,
        map: Vec<(String, Vec<Value>)>,
        tail: Vec<Value>,
    ) -> Vec<u8> {
        let entry_ty = Type::parse(REF_ENTRY_SIGNATURE).unwrap();
        let dict_ty = Type::parse(DICT_ENTRY_SIGNATURE).unwrap();
        let mut writer = ListingWriter::new(u64::MAX, 0, entries.len());
        for entry in &entries {
            writer
                .push_entry(&to_bytes(&entry_ty, entry).unwrap())
                .unwrap();
        }
        writer.start_metadata().unwrap();
        for entry in &head {
            writer
                .push_entry(&to_bytes(&dict_ty, entry).unwrap())
                .unwrap();
        }
        if !map.is_empty() {
            writer.start_map(COLLECTION_MAP_KEY).unwrap();
            for (id, refs) in &map {
                writer.start_collection(id, refs.len()).unwrap();
                for entry in refs {
                    writer
                        .push_entry(&to_bytes(&entry_ty, entry).unwrap())
                        .unwrap();
                }
                writer.end_collection().unwrap();
            }
            writer.end_map(COLLECTION_MAP_SIGNATURE).unwrap();
        }
        for entry in &tail {
            writer
                .push_entry(&to_bytes(&dict_ty, entry).unwrap())
                .unwrap();
        }
        let streamed = writer.finish().unwrap();

        let mut metadata = head;
        if !map.is_empty() {
            let collections = map
                .into_iter()
                .map(|(id, refs)| Value::Tuple(vec![Value::Str(id), Value::Array(refs)]))
                .collect();
            metadata.push(Value::Tuple(vec![
                Value::Str(COLLECTION_MAP_KEY.to_owned()),
                variant(COLLECTION_MAP_SIGNATURE, Value::Array(collections)).unwrap(),
            ]));
        }
        metadata.extend(tail);
        let whole = Value::Tuple(vec![Value::Array(entries), Value::Array(metadata)]);
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
        value_of_size(REF_ENTRY_SIGNATURE, size, entry_ending_in)
    }

    /// Returns a ref entry whose metadata dict ends in a string of `n` bytes.
    fn entry_ending_in(n: usize) -> Value {
        Value::Tuple(vec![
            Value::Str("r".into()),
            Value::Tuple(vec![
                Value::U64(0),
                Value::Bytes(vec![0; 32]),
                dict_ending_in(n),
            ]),
        ])
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

    /// Returns the `{sv}` entry `key` of the metadata dict with a string of
    /// `len` bytes.
    fn string_entry(key: &str, len: usize) -> Value {
        Value::Tuple(vec![
            Value::Str(key.to_owned()),
            variant("s", Value::Str("c".repeat(len))).unwrap(),
        ])
    }

    /// The listing writer gives the bytes of `to_bytes` with a collection
    /// map, with metadata entries before and after the map, and for framing
    /// offsets of 1, 2, and 4 bytes in each container of the map: the ref
    /// array of a collection, the entry of a collection, the map, the dict
    /// entry of the map, and the dict.
    #[test]
    fn the_listing_writer_frames_a_collection_map_as_to_bytes_does() {
        let mode = || string_entry(MODE_KEY, 10);
        let id = || string_entry(COLLECTION_ID_KEY, 8);
        let cases = [
            (entries_of(0, 4), vec![("a.b".to_owned(), entries_of(1, 4))]),
            (
                entries_of(2, 4),
                vec![
                    ("a.b".to_owned(), entries_of(3, 5)),
                    ("c.d".to_owned(), entries_of(1, 1)),
                    ("e".repeat(200), entries_of(2, 3)),
                ],
            ),
            (
                entries_of(1, 4),
                vec![("a.b".to_owned(), entries_of(8, 40))],
            ),
            (
                entries_of(1, 4),
                vec![
                    ("a.b".to_owned(), entries_of(2, 30_000)),
                    ("c.d".to_owned(), entries_of(1, 30_000)),
                ],
            ),
        ];
        for (entries, map) in cases {
            listing_with_map(entries.clone(), vec![mode()], map.clone(), vec![id()]);
            listing_with_map(entries.clone(), Vec::new(), map.clone(), Vec::new());
            listing_with_map(
                entries,
                vec![mode(), string_entry("x", 300)],
                map,
                Vec::new(),
            );
        }

        // One collection with one ref entry of each size near the boundaries
        // of 1-byte and 2-byte offsets moves each container of the map across
        // each boundary.
        for n in (0..=260).chain(65_250..=65_520) {
            let map = vec![("a.b".to_owned(), vec![entry_ending_in(n)])];
            listing_with_map(Vec::new(), vec![mode()], map, vec![id()]);
        }
    }

    /// `dict_len` is the length of the serialized dict of its entries.
    #[test]
    fn the_dict_length_is_the_length_of_the_serialized_dict() {
        let dict_ty = Type::parse(DICT_ENTRY_SIGNATURE).unwrap();
        for lens in [&[][..], &[1], &[1, 7], &[5, 300, 2], &[70_000, 1]] {
            let entries: Vec<Value> = lens
                .iter()
                .enumerate()
                .map(|(i, len)| string_entry(&format!("k{i}"), *len))
                .collect();
            let bytes: Vec<Vec<u8>> = entries
                .iter()
                .map(|entry| to_bytes(&dict_ty, entry).unwrap())
                .collect();
            let whole = serialize_signature_dict(&Value::Array(entries)).unwrap();
            assert_eq!(dict_len(bytes.iter()), whole.len(), "{lens:?}");
        }
    }

    /// The floor of a collection map, with the floor of the names of field 0
    /// and the length of the dict without the map, is at most the length of
    /// the listing.
    #[test]
    fn the_collection_map_floor_is_a_lower_bound() {
        let dict_ty = Type::parse(DICT_ENTRY_SIGNATURE).unwrap();
        let shapes: [&[(usize, usize, usize)]; 5] = [
            &[(1, 1, 1)],
            &[(3, 2, 7), (1, 1, 1)],
            &[(255, 1, 300)],
            &[(5, 40, 8), (6, 1, 2), (7, 3, 1)],
            &[(10, 2, 30_000)],
        ];
        for shape in shapes {
            for (head, tail) in [
                (vec![string_entry(MODE_KEY, 10)], Vec::new()),
                (
                    vec![string_entry(MODE_KEY, 10)],
                    vec![string_entry(COLLECTION_ID_KEY, 3)],
                ),
                (Vec::new(), vec![string_entry(COLLECTION_ID_KEY, 9)]),
            ] {
                let mut floor_map = BTreeMap::new();
                let mut map = Vec::new();
                for (n, &(id_len, count, name_len)) in shape.iter().enumerate() {
                    let id = format!("{n}{}", "i".repeat(id_len));
                    let refs = entries_of(count, name_len);
                    let names = refs
                        .iter()
                        .map(|_| ("n".repeat(name_len), checksum(0)))
                        .collect();
                    floor_map.insert(id.clone(), names);
                    map.push((id, refs));
                }
                let entries = entries_of(2, 3);
                let names = 2 * (3 + REF_ENTRY_FLOOR);
                let metadata: Vec<Vec<u8>> = head
                    .iter()
                    .chain(&tail)
                    .map(|entry| to_bytes(&dict_ty, entry).unwrap())
                    .collect();
                let floor =
                    names + dict_len(metadata.iter()) as u64 + collection_map_floor(&floor_map);
                let listing = listing_with_map(entries, head, map, tail);
                assert!(floor <= listing.len() as u64, "{shape:?}");
            }
        }
        assert_eq!(collection_map_floor(&BTreeMap::new()), 0);
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
    fn is_cap_error(outcome: &Result<RefListing>) -> bool {
        matches!(
            outcome,
            Err(Error::Remote(crate::remote::Error::LimitExceeded(_)))
        )
    }

    /// A listing fits in a cap of its own length, in a buffer no larger than
    /// the cap, and each lower cap refuses it with the cap error. The listing
    /// has a version in each entry and a delta map, so each floor check is
    /// on the path. The checks of the names and of the metadata come before
    /// the commit reads. With a selector of the collection refs, the listing
    /// holds a collection map, and the same holds.
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
            let commit = repo.resolve_ref_tip("z").await.unwrap().unwrap();
            let mirrors = [("org.a", "x"), ("org.a", "y/z"), ("org.b", "main")];
            for (id, name) in mirrors {
                repo.set_collection_ref_immediate(
                    &crate::CollectionRef::new(id, name),
                    Some(&commit),
                )
                .await
                .unwrap();
            }
            let all = all_refs();
            let anyone = anyone();
            for collections in [None, Some(&all)] {
                let build = |cap| repo.build_ref_listing_capped(&all, collections, &anyone, cap);
                let full = repo
                    .build_ref_listing(&all, collections, &anyone)
                    .await
                    .unwrap()
                    .bytes;
                let parsed = Summary::parse(&full).unwrap();
                assert_eq!(parsed.refs.len(), 3);
                assert_eq!(parsed.static_deltas().unwrap().len(), 1);
                assert!(
                    parsed.refs[0]
                        .metadata
                        .dict_get(COMMIT_VERSION_KEY)
                        .is_some()
                );
                let map = parsed.collection_map().unwrap();
                assert_eq!(map.len(), if collections.is_some() { 2 } else { 0 });
                let len = full.len() as u64;
                let capped = build(len).await.unwrap().bytes;
                assert_eq!(capped, full);
                assert!(capped.capacity() as u64 <= len);
                for cap in 0..len {
                    let outcome = build(cap).await;
                    assert!(is_cap_error(&outcome), "cap {cap}: {outcome:?}");
                }
            }

            // With no commit object, a cap below the floor of the names and
            // the metadata still gives the cap error, so these checks come
            // before the commit reads. A cap of that floor passes them, and
            // the commit read fails.
            let names_floor: u64 = names
                .iter()
                .map(|name| name.len() as u64 + REF_ENTRY_FLOOR)
                .sum();
            let mut by_id: BTreeMap<String, Vec<(String, Checksum)>> = BTreeMap::new();
            for (id, name) in mirrors {
                by_id
                    .entry(id.to_owned())
                    .or_default()
                    .push((name.to_owned(), commit));
            }
            let listing = repo
                .build_ref_listing(&all, Some(&all), &anyone)
                .await
                .unwrap()
                .bytes;
            let mut metadata = Summary::parse(&listing).unwrap().metadata;
            let Value::Array(entries) = &mut metadata else {
                panic!("the metadata is a dict");
            };
            entries.retain(|entry| {
                entry.as_tuple().and_then(|t| t.first()?.as_str()) != Some(COLLECTION_MAP_KEY)
            });
            let metadata = serialize_signature_dict(&metadata).unwrap().len() as u64;
            let path = loose_path(&commit, ObjectType::Commit, repo.mode());
            std::fs::remove_file(dir.join("objects").join(path)).unwrap();
            for (collections, floor) in [
                (None, names_floor + metadata),
                (
                    Some(&all),
                    names_floor + collection_map_floor(&by_id) + metadata,
                ),
            ] {
                let build = |cap| repo.build_ref_listing_capped(&all, collections, &anyone, cap);
                for cap in [names_floor - 1, floor - 1] {
                    let outcome = build(cap).await;
                    assert!(is_cap_error(&outcome), "cap {cap}: {outcome:?}");
                }
                for cap in [floor, MAX_REF_LISTING] {
                    let outcome = build(cap).await;
                    assert!(
                        matches!(outcome, Err(Error::ObjectNotFound { .. })),
                        "cap {cap}: {outcome:?}"
                    );
                }
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The selection stops with the cap error of the listing at the first ref
    /// that takes the floor of the names over the cap, so it reads no ref
    /// file after that ref. With a cap that holds the names, and with no
    /// cap, the selection reads each selected ref.
    #[test]
    fn a_listing_over_its_cap_fails_during_the_selection() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-ref-listing-selection-cap-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ostrya_rt::block_on(async {
            let repo = repo_with_refs(&dir, &["z"]).await;
            // A collection ref with no checksum. The selection reads the
            // collection refs after the local refs.
            let bad = dir.join("refs/mirrors/org.a/x");
            std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
            std::fs::write(&bad, "no checksum\n").unwrap();
            let all = all_refs();
            let anyone = anyone();
            let cap = "z".len() as u64 + REF_ENTRY_FLOOR - 1;
            let outcome = repo
                .build_ref_listing_capped(&all, Some(&all), &anyone, cap)
                .await;
            assert!(is_cap_error(&outcome), "{outcome:?}");
            let error = outcome.err().unwrap().to_string();
            assert_eq!(error, listing_too_large(cap).to_string());
            let selected = repo.select_refs(&all, Some(&all), &anyone, Some(cap)).await;
            let error = selected.err().map(|e| e.to_string());
            assert_eq!(error, Some(listing_too_large(cap).to_string()));

            let outcome = repo
                .build_ref_listing_capped(&all, Some(&all), &anyone, MAX_REF_LISTING)
                .await;
            assert!(matches!(outcome, Err(Error::Core(_))), "{outcome:?}");
            let selected = repo.select_refs(&all, Some(&all), &anyone, None).await;
            assert!(matches!(selected, Err(Error::Core(_))));
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Writes a commit with no version and an empty root tree to `repo`, at
    /// `timestamp`, and returns it.
    async fn commit_at(repo: &Repo, timestamp: u64) -> Checksum {
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
        let options = CommitOptions {
            parent: None,
            subject: None,
            body: None,
            timestamp: Some(timestamp),
            metadata: None,
        };
        let commit = txn.write_commit(options, &root).await.unwrap();
        txn.commit().await.unwrap();
        commit
    }

    /// Returns the local refs and the collection refs of `summary`, by name
    /// and commit.
    #[allow(clippy::type_complexity)]
    fn summary_refs(
        summary: &Summary,
    ) -> (
        Vec<(String, Checksum)>,
        BTreeMap<String, Vec<(String, Checksum)>>,
    ) {
        let pairs = |refs: &[SummaryRef]| -> Vec<(String, Checksum)> {
            refs.iter().map(|r| (r.name.clone(), r.commit)).collect()
        };
        let collections = summary
            .collection_map()
            .unwrap()
            .into_iter()
            .map(|(id, refs)| (id, pairs(&refs)))
            .collect();
        (pairs(&summary.refs), collections)
    }

    /// The summary of each item holds the refs that a walk of the repository
    /// with the rights of the summary of the item selects: the local refs
    /// with the mirror refs of the own id, the collection refs, the aliases
    /// whose names and targets the item reads, and no ref that a deny item
    /// covers. A mirror alias of the own id that the item does not read
    /// gives its place to the ref of `refs/heads` of the same name.
    #[test]
    fn each_item_summary_holds_the_refs_of_a_walk_with_its_rights() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-item-summary-walk-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ostrya_rt::block_on(async {
            let repo = repo_with_refs(
                &dir,
                &["main", "pub/a", "pub/b/c", "pub/secret/s", "shadow", "free"],
            )
            .await;
            let first = repo.resolve_ref_tip("main").await.unwrap().unwrap();
            let second = commit_at(&repo, 1_700_000_100).await;
            for name in ["priv/p", "pub/secret/t"] {
                repo.set_ref_immediate(name, Some(&second)).await.unwrap();
            }
            repo.set_ref_alias_immediate("pub/link", "priv/p")
                .await
                .unwrap();
            repo.set_ref_alias_immediate("pub/open", "main")
                .await
                .unwrap();
            let own = "org.example.Own";
            for (id, name, commit) in [
                (own, "pub/m", &second),
                ("org.example.A", "a/x", &first),
                ("org.example.A", "hidden/h", &second),
                ("org.example.B", "b", &second),
            ] {
                let cref = crate::CollectionRef::new(id, name);
                repo.set_collection_ref_immediate(&cref, Some(commit))
                    .await
                    .unwrap();
            }
            // A mirror alias of the own id hides `refs/heads/shadow`, and
            // aliases under the directory of a collection.
            let mirrors = dir.join("refs/mirrors");
            for (link, body) in [
                (format!("{own}/shadow"), "../../heads/priv/p"),
                ("org.example.A/a/l".to_owned(), "../../../heads/main"),
                ("org.example.A/a/p".to_owned(), "../../../heads/priv/p"),
            ] {
                std::os::unix::fs::symlink(body, mirrors.join(link)).unwrap();
            }
            let config = dir.join("config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str(&format!("collection-id={own}\n"));
            text.push_str(
                "[ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:pub/**;r:main\n\
                 deny=pub/secret/**\nsummary=true\n\
                 [ex-ostrya client \"public-c\"]\nauth=anonymous\ncollection=*\n\
                 allow=r:**\ndeny=hidden/**\nsummary=true\n\
                 [ex-ostrya client \"ci\"]\nauth=ssh:ci\nallow=r:**\ndeny=priv/**\n\
                 summary=true\n\
                 [ex-ostrya client \"ci-a\"]\nauth=ssh:ci\ncollection=org.example.A\n\
                 allow=r:a/**\nsummary=true\n\
                 [ex-ostrya client \"admin\"]\nauth=ssh:admin\nallow=r:**\nsummary=true\n\
                 [ex-ostrya client \"admin-c\"]\nauth=ssh:admin\ncollection=*\n\
                 allow=r:**\nsummary=true\n\
                 [ex-ostrya client \"none\"]\nauth=ssh:none\nallow=d:**\nsummary=true\n",
            );
            std::fs::write(&config, text).unwrap();
            let repo = Repo::open(&dir).await.unwrap();

            let opts = SummaryOptions {
                last_modified: Some(1_700_000_000),
                ..SummaryOptions::default()
            };
            let access = Arc::new(ClientAccess::from_config(repo.config(), repo.path()).unwrap());
            let run = repo.summary_run(access.clone(), &opts).await.unwrap();
            let all = all_refs();
            let mut fallbacks = 0;
            for text in ["anonymous", "ssh:ci", "ssh:admin", "ssh:none"] {
                let item = AuthItem::parse(text).unwrap();
                let bytes = repo.item_summary(&run, &item, &opts).await.unwrap();
                let summary = Summary::parse(&bytes).unwrap();
                let read = ReadAccess::for_summary(access.clone(), item.clone());
                let walked = repo
                    .select_refs(&all, Some(&all), &read, None)
                    .await
                    .unwrap();
                let (local, collections) = summary_refs(&summary);
                assert_eq!(local, walked.local, "{text}");
                assert_eq!(collections, walked.collections, "{text}");
                let built = repo
                    .selection_summary(&run, &walked, SummaryKind::Served, &opts)
                    .await
                    .unwrap();
                assert_eq!(bytes, built, "{text}");
                if run.every.readable(&read).is_none() {
                    assert!(local.contains(&("shadow".to_owned(), first)), "{text}");
                    fallbacks += 1;
                }
            }
            assert_eq!(fallbacks, 1, "the ci item walks the refs");
            let anonymous = Summary::parse(
                &repo
                    .item_summary(&run, &AuthItem::Anonymous, &opts)
                    .await
                    .unwrap(),
            )
            .unwrap();
            let (local, collections) = summary_refs(&anonymous);
            let names: Vec<&str> = local.iter().map(|(name, _)| name.as_str()).collect();
            assert_eq!(names, ["main", "pub/a", "pub/b/c", "pub/m", "pub/open"]);
            let ids: Vec<&str> = collections.keys().map(String::as_str).collect();
            assert_eq!(ids, ["org.example.A", "org.example.B"]);
            let a: Vec<&str> = collections["org.example.A"]
                .iter()
                .map(|(name, _)| name.as_str())
                .collect();
            assert_eq!(a, ["a/l", "a/x"]);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The writer refuses a summary larger than [`SUMMARY_READ_CAP`] and
    /// keeps the summary that the repository holds.
    #[test]
    fn a_summary_over_the_read_cap_is_refused() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-summary-write-cap-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ostrya_rt::block_on(async {
            let repo = repo_with_refs(&dir, &["main"]).await;
            repo.regenerate_summary(&SummaryOptions::default())
                .await
                .unwrap();
            let before = std::fs::read(dir.join(SUMMARY_FILE)).unwrap();
            let big = "x".repeat(SUMMARY_READ_CAP as usize);
            let opts = SummaryOptions {
                additional_metadata: vec![(
                    "big".to_owned(),
                    Value::Variant(Box::new((Type::parse("s").unwrap(), Value::Str(big)))),
                )],
                ..SummaryOptions::default()
            };
            let outcome = repo.regenerate_summary(&opts).await;
            assert!(
                matches!(&outcome, Err(Error::InvalidFormat(m)) if m.contains("cap")),
                "{outcome:?}"
            );
            assert_eq!(std::fs::read(dir.join(SUMMARY_FILE)).unwrap(), before);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A reader of a summary file refuses a file larger than
    /// [`SUMMARY_READ_CAP`], and reads a file of the cap whole.
    #[test]
    fn a_summary_file_over_the_read_cap_is_refused() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-summary-read-cap-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ostrya_rt::block_on(async {
            let repo = repo_with_refs(&dir, &["main"]).await;
            let file = std::fs::File::create(dir.join(SUMMARY_FILE)).unwrap();
            file.set_len(SUMMARY_READ_CAP).unwrap();
            let bytes = repo.read_summary().await.unwrap().unwrap();
            assert_eq!(bytes.len() as u64, SUMMARY_READ_CAP);
            drop(bytes);
            file.set_len(SUMMARY_READ_CAP + 1).unwrap();
            let outcome = repo.read_summary().await;
            assert!(
                matches!(&outcome, Err(Error::InvalidFormat(m)) if m.contains("cap")),
                "{:?}",
                outcome.map(|bytes| bytes.map(|bytes| bytes.len()))
            );
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The removal of a root file reports whether it removed a file. A file
    /// that does not exist is no error.
    #[test]
    fn the_removal_of_a_root_file_reports_the_removal() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-remove-root-file-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file"), b"x").unwrap();
        let fd = std::fs::File::open(&dir).unwrap();
        assert!(remove_root_file_blocking(fd.as_fd(), "file").unwrap());
        assert!(!dir.join("file").exists());
        assert!(!remove_root_file_blocking(fd.as_fd(), "file").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A collection map in a variant of another type than
    /// `a{sa(s(taya{sv}))}` is refused. An empty array of another type has
    /// the shape of an empty map, and the type of the variant tells them
    /// apart.
    #[test]
    fn collection_map_checks_the_type_of_its_variant() {
        let with_map = |ty: &str, map: Value| {
            let mut metadata = Value::Array(Vec::new());
            append_dict_entry(&mut metadata, COLLECTION_MAP_KEY, variant(ty, map).unwrap())
                .unwrap();
            Summary {
                refs: Vec::new(),
                metadata,
            }
        };
        let empty = with_map(COLLECTION_MAP_SIGNATURE, Value::Array(Vec::new()));
        assert_eq!(empty.collection_map().unwrap(), Vec::new());
        for (ty, map) in [
            ("as", Value::Array(Vec::new())),
            ("a{sv}", Value::Array(Vec::new())),
            ("s", Value::Str("x".into())),
        ] {
            let outcome = with_map(ty, map).collection_map();
            assert!(
                matches!(outcome, Err(Error::InvalidFormat(_))),
                "{ty}: {outcome:?}"
            );
        }
    }
}
