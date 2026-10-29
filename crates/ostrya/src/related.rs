//! The related commits of a commit.
//!
//! A commit names related commits in two places:
//!
//! - Field 2 of the commit object, an `a(say)` array, holds the
//!   dependencies. The commit checksum covers them.
//! - The detached metadata key `ostrya.related`, a variant of type `a(say)`,
//!   holds the build sources. The commit checksum does not cover them.
//!
//! Each entry is a name and the 32-byte checksum of a commit. The name has
//! the form `<class>/<name>` by convention, for example `container/fe`.
//!
//! - [`Repo::read_commit_related`] reads both fields.
//! - [`Repo::add_detached_related`] and [`Transaction::add_detached_related`]
//!   add a build source to a commit.
//! - [`Repo::prune`] keeps the commits that the two fields of each reached
//!   commit name, and gives a [`RelatedWarning`] for each defective value.
//!   `BucketRepo::prune` keeps the commits that field 2 of each reached
//!   commit names, and gives a [`RelatedWarning`] for each defective field 2
//!   entry.
//! - [`Repo::pull`], [`Repo::pull_with_session`], and [`Repo::pull_collection`]
//!   fetch the dependencies of each commit that they read.
//!   [`Repo::pull_local`] imports the dependencies of each commit that it
//!   walks.
//! - `Repo::push`, `Repo::push_over_stream`, and `Repo::push_to_bucket` send
//!   the dependencies of each commit that they offer.
//! - `Repo::receive` and `Repo::receive_stream` check the dependencies of each
//!   commit that the session stages. They check no signature of a dependency
//!   and add no server signature to it, unless the dependency is also the new
//!   commit of a ref update.
//! - [`Repo::apply_static_delta`] and [`Repo::apply_static_delta_offline`]
//!   check the dependencies of the target commit before they write an object.
//! - [`Repo::fsck`] reports each dependency of a checked commit that is
//!   absent, partial, or defective, and marks the commit of an absent or a
//!   partial dependency as partial. `BucketRepo::fsck` reports the same
//!   dependencies and writes nothing for them.

use std::collections::HashSet;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::LazyLock;

use ostrya_core::{Checksum, ObjectType, Type, Value, tuple_field_from_bytes};

use crate::config::RepoConfig;
use crate::error::{Error, Result};
use crate::read::CommitState;
use crate::repo::Repo;
use crate::transaction::Transaction;

/// The detached metadata key of the build sources.
pub(crate) const RELATED_KEY: &str = "ostrya.related";

/// The bytes of the key [`RELATED_KEY`] in a serialized `a{sv}` dict: the
/// key and its terminating NUL.
const RELATED_KEY_BYTES: &[u8] = b"ostrya.related\0";

/// The type string of a field of related entries.
const RELATED_SIGNATURE: &str = "a(say)";

/// The end of the reason of a dependency whose own field 2 is not empty.
pub(crate) const NESTED_REASON: &str = "which has dependencies of its own";

/// The end of the reason of a dependency that the repository marks partial.
pub(crate) const PARTIAL_REASON: &str = "which is partial";

/// The end of the reason of a dependency that the repository does not hold.
pub(crate) const ABSENT_REASON: &str = "which the repository does not hold";

/// The type of a commit object. The parse of field 2 decodes member 2 alone.
static COMMIT_TYPE: LazyLock<Type> =
    LazyLock::new(|| Type::parse("(a{sv}aya(say)sstayay)").expect("the commit signature is valid"));

/// The field of a commit that holds a list of related entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelatedField {
    /// Field 2 of the commit object: the dependencies.
    Dependencies,
    /// The detached metadata key `ostrya.related`: the build sources.
    BuildSources,
}

impl std::fmt::Display for RelatedField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RelatedField::Dependencies => "field 2",
            RelatedField::BuildSources => RELATED_KEY,
        })
    }
}

/// A defective related value that [`Repo::prune`] or `BucketRepo::prune`
/// read.
///
/// The prune gives this warning in place of [`Error::InvalidRelated`] and
/// continues. The defective value or entry roots nothing. The other entries
/// of the field root as usual. The text of the warning is the text of the
/// error with the same commit, field, and reason. `BucketRepo::prune` reads
/// field 2 alone, so each of its warnings is about field 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelatedWarning {
    /// The commit that holds the defective value.
    pub commit: Checksum,
    /// The field that holds the defective value.
    pub field: RelatedField,
    /// The text that names the defect.
    pub reason: String,
}

impl std::fmt::Display for RelatedWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "related commits in {} of commit {}: {}",
            self.field, self.commit, self.reason
        )
    }
}

/// The related commits of a commit, from [`Repo::read_commit_related`].
///
/// Each list holds the entries in the order that the commit stores them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitRelated {
    /// The entries of field 2 of the commit object: the name and the
    /// checksum of each dependency.
    pub dependencies: Vec<(String, Checksum)>,
    /// The entries of the detached metadata key `ostrya.related`: the name
    /// and the checksum of each build source. The list is empty if the
    /// commit has no detached metadata or no such key.
    pub build_sources: Vec<(String, Checksum)>,
}

/// One related entry as stored, before the check of its format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelatedEntry {
    /// The name of the entry.
    pub(crate) name: String,
    /// The checksum, or the byte length of a checksum that is not 32 bytes.
    pub(crate) checksum: std::result::Result<Checksum, usize>,
}

impl RelatedEntry {
    /// Returns the defect of the entry at `index` of its field, or `None` if
    /// the entry has a name that is not empty and a 32-byte checksum.
    pub(crate) fn defect(&self, index: usize) -> Option<String> {
        if self.name.is_empty() {
            return Some(format!("entry {index} has an empty name"));
        }
        match self.checksum {
            Ok(_) => None,
            Err(len) => Some(format!(
                "entry {index} ({}) has a checksum of {len} bytes, not 32",
                self.name
            )),
        }
    }
}

/// Parses the entries of field 2 from the bytes of one commit object.
///
/// The parse checks the framing of the commit tuple and decodes member 2
/// alone. It keeps the stored order and checks no entry.
///
/// # Errors
///
/// [`Error::Core`] if the commit tuple does not frame, or if field 2 does not
/// decode.
pub(crate) fn parse_dependencies(commit_bytes: &[u8]) -> Result<Vec<RelatedEntry>> {
    let field =
        tuple_field_from_bytes(&COMMIT_TYPE, commit_bytes, 2).map_err(ostrya_core::Error::from)?;
    entries_of_value(&field).map_err(Error::InvalidFormat)
}

/// Returns `true` if field 2 of the commit object `commit_bytes` holds at
/// least one entry.
///
/// The call checks the framing of the commit tuple and decodes member 2
/// alone.
///
/// # Errors
///
/// [`Error::Core`] if the commit tuple does not frame, or if field 2 does not
/// decode.
pub(crate) fn has_dependencies(commit_bytes: &[u8]) -> Result<bool> {
    let field =
        tuple_field_from_bytes(&COMMIT_TYPE, commit_bytes, 2).map_err(ostrya_core::Error::from)?;
    Ok(field.as_array().is_some_and(|entries| !entries.is_empty()))
}

/// Returns the entries of field 2 of a parsed commit, in the stored order.
pub(crate) fn entries_of(related: &[(String, Vec<u8>)]) -> Vec<RelatedEntry> {
    related
        .iter()
        .map(|(name, bytes)| RelatedEntry {
            name: name.clone(),
            checksum: Checksum::from_ay(bytes).map_err(|_| bytes.len()),
        })
        .collect()
}

/// Returns the entries of field 2 of a parsed commit, in the stored order,
/// as [`entries_of`] does, and takes the names of `related`.
pub(crate) fn into_entries(related: Vec<(String, Vec<u8>)>) -> Vec<RelatedEntry> {
    related
        .into_iter()
        .map(|(name, bytes)| RelatedEntry {
            checksum: Checksum::from_ay(&bytes).map_err(|_| bytes.len()),
            name,
        })
        .collect()
}

/// Returns the entries of `ostrya.related` in the detached metadata dict
/// `detached`, in the stored order.
///
/// Returns `None` if `detached` is `None` or holds no such key. If the key
/// occurs more than one time, the first entry gives the value.
///
/// # Errors
///
/// The reason of the defect, if the value is not a variant of type `a(say)`.
pub(crate) fn build_sources(
    detached: Option<&Value>,
) -> std::result::Result<Option<Vec<RelatedEntry>>, String> {
    match detached.and_then(|dict| dict.dict_get(RELATED_KEY)) {
        Some(value) => entries_of_variant(value).map(Some),
        None => Ok(None),
    }
}

/// Returns `true` if `bytes`, the contents of a `.commitmeta` file, can hold
/// an `ostrya.related` entry.
///
/// The test searches `bytes` for the key and its terminating NUL. In a
/// serialized `a{sv}` dict, the key of each entry is a NUL-terminated string
/// at contiguous bytes. So a parse of `bytes` finds an `ostrya.related` entry
/// only if `bytes` holds these bytes. These bytes can also be in a value, for
/// example in a string. Then the test gives `true`, and the parse finds no
/// entry.
pub(crate) fn may_hold_build_sources(bytes: &[u8]) -> bool {
    bytes
        .windows(RELATED_KEY_BYTES.len())
        .any(|window| window == RELATED_KEY_BYTES)
}

/// Reads the value of one `ostrya.related` entry as related entries.
///
/// # Errors
///
/// The reason of the defect, if the value is not a variant of type `a(say)`.
fn entries_of_variant(value: &Value) -> std::result::Result<Vec<RelatedEntry>, String> {
    let Some((ty, child)) = value.as_variant() else {
        return Err("value is not a variant".into());
    };
    let signature = ty.signature();
    if signature != RELATED_SIGNATURE {
        return Err(format!("type is `{signature}`, not `{RELATED_SIGNATURE}`"));
    }
    entries_of_value(child)
}

/// Returns the checksum of each entry of `entries` that has a name that is
/// not empty and a 32-byte checksum, and the defect of each other entry.
///
/// Both lists keep the order of `entries`.
pub(crate) fn split_entries(entries: Vec<RelatedEntry>) -> (Vec<Checksum>, Vec<String>) {
    let mut valid = Vec::with_capacity(entries.len());
    let mut defects = Vec::new();
    for (index, entry) in entries.into_iter().enumerate() {
        match entry.defect(index) {
            Some(reason) => defects.push(reason),
            None => valid.push(entry.checksum.expect("the defect check passed")),
        }
    }
    (valid, defects)
}

/// Checks each `ostrya.related` entry of the detached metadata dict `dict`
/// of the commit `commit`.
///
/// The check reads each entry with the key, also when the key occurs more
/// than one time. Each value must be a variant of type `a(say)`, and each
/// element must have a name that is not empty and a 32-byte checksum. The
/// check accepts elements that are not sorted and two elements with the same
/// name. It does not check that the repository holds a named commit. A dict
/// that is not an array has no entry, so it passes.
///
/// # Errors
///
/// [`Error::InvalidRelated`] with `commit` and
/// [`RelatedField::BuildSources`] for the first defect, in the order of the
/// entries and then of the elements.
pub(crate) fn check_detached(commit: &Checksum, dict: &Value) -> Result<()> {
    for value in related_values(dict) {
        let entries = entries_of_variant(value).map_err(|reason| Error::InvalidRelated {
            commit: Some(*commit),
            field: RelatedField::BuildSources,
            reason,
        })?;
        checked_entries(RelatedField::BuildSources, Some(*commit), entries)?;
    }
    Ok(())
}

/// Returns the value of each `ostrya.related` entry of the `a{sv}` dict
/// `dict`, in the order of the dict.
///
/// The function skips each entry that does not have the `{s?}` shape. If
/// `dict` is not an array, the result is empty.
fn related_values(dict: &Value) -> impl Iterator<Item = &Value> {
    dict.as_array()
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| match entry.as_tuple()? {
            [key, value] if key.as_str() == Some(RELATED_KEY) => Some(value),
            _ => None,
        })
}

/// The rule of `[ex-ostrya] keep-detached-related` for the detached metadata
/// that a transfer stores.
///
/// If `drop_related` is `true`, the transfer drops `ostrya.related` from each
/// detached metadata dict that it stores, and keeps each other property. If it
/// is `false`, the transfer stores the dict of the source unchanged. The rule
/// applies after each signature verification of the transfer, over the dict
/// as the source holds it.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RelatedRule {
    /// `true` if the transfer drops `ostrya.related`.
    pub(crate) drop_related: bool,
}

impl RelatedRule {
    /// Returns the rule of `[ex-ostrya] keep-detached-related` of `config`,
    /// the config of the repository that stores the dicts.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not a boolean.
    pub(crate) fn of(config: &RepoConfig) -> Result<RelatedRule> {
        Ok(RelatedRule {
            drop_related: !config.keep_detached_related()?,
        })
    }

    /// Returns the serialized properties of `bytes` that this rule keeps, or
    /// `None` if the caller writes nothing.
    ///
    /// A rule that drops nothing, a dict with no `ostrya.related` entry, and
    /// the zero-length "no metadata" marker each give the input bytes back
    /// unchanged. A dict that holds only `ostrya.related` entries gives `None`
    /// if the rule drops them, and the destination keeps the detached metadata
    /// that it holds.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the rule drops `ostrya.related` and `bytes` is not
    /// an `a{sv}` dict.
    pub(crate) fn apply(&self, commit: &Checksum, bytes: Vec<u8>) -> Result<Option<Vec<u8>>> {
        if !self.drop_related {
            return Ok(Some(bytes));
        }
        let Some(dict) = crate::summary::parse_signature_dict(&bytes)? else {
            return Ok(Some(bytes));
        };
        self.apply_parsed(commit, bytes, dict)
    }

    /// Runs [`apply`](RelatedRule::apply) on the blocking pool.
    ///
    /// A rule that drops nothing and the zero-length marker parse nothing, so
    /// they give the input bytes back on the calling task.
    pub(crate) async fn apply_on_pool(
        &self,
        commit: &Checksum,
        bytes: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        if !self.drop_related || bytes.is_empty() {
            return Ok(Some(bytes));
        }
        let rule = *self;
        let commit = *commit;
        ostrya_rt::unblock(move || rule.apply(&commit, bytes)).await
    }

    /// Runs [`apply`](RelatedRule::apply) over the `.commitmeta` bytes
    /// `bytes`, whose parse is `dict`.
    ///
    /// The call parses nothing. It serializes only a dict of which the rule
    /// keeps some properties. The result is the result of `apply`.
    pub(crate) fn apply_parsed(
        &self,
        commit: &Checksum,
        bytes: Vec<u8>,
        dict: Value,
    ) -> Result<Option<Vec<u8>>> {
        if !self.drop_related {
            return Ok(Some(bytes));
        }
        match kept_entries(commit, dict)? {
            Kept::All(_) => Ok(Some(bytes)),
            Kept::Nothing => Ok(None),
            Kept::Part(kept) => {
                // The source bytes are not part of the result, so they drop
                // before the serialization.
                drop(bytes);
                crate::summary::serialize_signature_dict(&Value::Array(kept)).map(Some)
            }
        }
    }

    /// Returns the properties of the parsed detached metadata `dict` that this
    /// rule keeps, or `None` if the caller writes nothing.
    ///
    /// A rule that drops nothing and a dict with no `ostrya.related` entry
    /// give `dict` back unchanged. A dict that holds only `ostrya.related`
    /// entries gives `None` if the rule drops them.
    #[cfg_attr(not(feature = "push"), allow(dead_code))]
    pub(crate) fn apply_value(&self, commit: &Checksum, dict: Value) -> Result<Option<Value>> {
        if !self.drop_related {
            return Ok(Some(dict));
        }
        match kept_entries(commit, dict)? {
            Kept::All(dict) => Ok(Some(dict)),
            Kept::Nothing => Ok(None),
            Kept::Part(kept) => Ok(Some(Value::Array(kept))),
        }
    }
}

/// The properties of a detached metadata dict that a [`RelatedRule`] keeps.
enum Kept {
    /// Every property: the dict as it came in.
    All(Value),
    /// Some of the properties, in their order.
    Part(Vec<Value>),
    /// No property.
    Nothing,
}

/// Drops each `ostrya.related` property of the detached metadata `dict` of
/// `commit`.
///
/// A value that is not a dict, and an entry that is not `{sv}`, are
/// [`Error::InvalidFormat`].
fn kept_entries(commit: &Checksum, dict: Value) -> Result<Kept> {
    let Value::Array(entries) = dict else {
        return Err(Error::InvalidFormat(format!(
            "detached metadata of {commit} is not a dict"
        )));
    };
    let mut allowed = Vec::with_capacity(entries.len());
    for entry in &entries {
        let key = entry
            .as_tuple()
            .and_then(|fields| match fields {
                [key, _] => key.as_str(),
                _ => None,
            })
            .ok_or_else(|| {
                Error::InvalidFormat(format!(
                    "detached metadata of {commit} holds an entry that is not `{{sv}}`"
                ))
            })?;
        allowed.push(key != RELATED_KEY);
    }
    if allowed.iter().all(|allow| *allow) {
        return Ok(Kept::All(Value::Array(entries)));
    }
    if !allowed.iter().any(|allow| *allow) {
        return Ok(Kept::Nothing);
    }
    let kept = entries
        .into_iter()
        .zip(allowed)
        .filter_map(|(entry, allow)| allow.then_some(entry))
        .collect();
    Ok(Kept::Part(kept))
}

/// Adds the build source `name` with the checksum `source` to the detached
/// metadata dict `dict` of the commit `commit`.
///
/// The add edits the first `ostrya.related` entry of `dict`. It removes each
/// element with the name `name`, adds the new element, and sorts the elements
/// by name in byte order. The sort is stable. If `dict` has no such entry,
/// the add appends one after the other entries, with the new element alone.
/// Each other entry of `dict` stays as it is.
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if `dict` is not an array.
/// - [`Error::InvalidRelated`] with `commit` and
///   [`RelatedField::BuildSources`] if the value of the first entry is not a
///   variant of type `a(say)`, or if one of its elements has an empty name or
///   a checksum that is not 32 bytes. `dict` then stays as it is.
pub(crate) fn add_build_source(
    dict: &mut Value,
    commit: &Checksum,
    name: &str,
    source: &Checksum,
) -> Result<()> {
    let Value::Array(entries) = dict else {
        return Err(Error::InvalidFormat(
            "detached metadata must be an a{sv} dict".into(),
        ));
    };
    let slot = entries.iter_mut().find_map(|entry| match entry {
        Value::Tuple(fields) => match fields.as_mut_slice() {
            [key, value] if key.as_str() == Some(RELATED_KEY) => Some(value),
            _ => None,
        },
        _ => None,
    });
    let mut sources = match &slot {
        Some(value) => {
            let entries = entries_of_variant(value).map_err(|reason| Error::InvalidRelated {
                commit: Some(*commit),
                field: RelatedField::BuildSources,
                reason,
            })?;
            checked_entries(RelatedField::BuildSources, Some(*commit), entries)?
        }
        None => Vec::new(),
    };
    sources.retain(|(stored, _)| stored != name);
    sources.push((name.to_owned(), *source));
    sources.sort_by(|(a, _), (b, _)| a.cmp(b));
    let elements = sources
        .into_iter()
        .map(|(name, checksum)| {
            Value::Tuple(vec![
                Value::Str(name),
                Value::Bytes(checksum.as_bytes().to_vec()),
            ])
        })
        .collect();
    let ty = Type::parse(RELATED_SIGNATURE).map_err(ostrya_core::Error::from)?;
    let value = Value::variant(ty, Value::Array(elements));
    match slot {
        Some(slot) => *slot = value,
        None => entries.push(Value::Tuple(vec![
            Value::Str(RELATED_KEY.to_owned()),
            value,
        ])),
    }
    Ok(())
}

/// Reads an `a(say)` value as related entries.
///
/// # Errors
///
/// The reason of the defect, if the value is not an array of `(say)` pairs.
fn entries_of_value(value: &Value) -> std::result::Result<Vec<RelatedEntry>, String> {
    let Some(items) = value.as_array() else {
        return Err("value is not an array".into());
    };
    items
        .iter()
        .enumerate()
        .map(|(index, item)| match item.as_tuple() {
            Some([Value::Str(name), Value::Bytes(bytes)]) => Ok(RelatedEntry {
                name: name.clone(),
                checksum: Checksum::from_ay(bytes).map_err(|_| bytes.len()),
            }),
            _ => Err(format!("element {index} is not a (say) pair")),
        })
        .collect()
}

/// Checks the format of each entry of `field` and returns the entries as
/// names and checksums, in the given order.
///
/// # Errors
///
/// [`Error::InvalidRelated`] with `commit` and `field` for the first entry
/// with an empty name or with a checksum that is not 32 bytes.
pub(crate) fn checked_entries(
    field: RelatedField,
    commit: Option<Checksum>,
    entries: impl IntoIterator<Item = RelatedEntry>,
) -> Result<Vec<(String, Checksum)>> {
    entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| match entry.defect(index) {
            Some(reason) => Err(Error::InvalidRelated {
                commit,
                field,
                reason,
            }),
            None => Ok((entry.name, entry.checksum.expect("the defect check passed"))),
        })
        .collect()
}

/// Checks the format of each entry of field 2 of the parsed commit `commit`
/// and returns the entries as names and checksums, in the stored order.
///
/// The check accepts entries that are not sorted and two entries with the
/// same name.
///
/// # Errors
///
/// [`Error::InvalidRelated`] with `commit` and [`RelatedField::Dependencies`]
/// for the first entry with an empty name or with a checksum that is not 32
/// bytes.
pub(crate) fn checked_dependencies(
    commit: &Checksum,
    related: Vec<(String, Vec<u8>)>,
) -> Result<Vec<(String, Checksum)>> {
    let entries = related.into_iter().map(|(name, bytes)| RelatedEntry {
        checksum: Checksum::from_ay(&bytes).map_err(|_| bytes.len()),
        name,
    });
    checked_entries(RelatedField::Dependencies, Some(*commit), entries)
}

/// Checks the format of each entry of field 2 of the parsed commit `commit`
/// and returns the name and the checksum of each entry, in the stored order.
///
/// The call is [`checked_dependencies`] over a borrowed field: the result
/// borrows the names, and the call copies a name only for its error.
///
/// # Errors
///
/// [`Error::InvalidRelated`] with `commit` and [`RelatedField::Dependencies`]
/// for the first entry with an empty name or with a checksum that is not 32
/// bytes.
#[cfg_attr(not(feature = "receive"), allow(dead_code))]
pub(crate) fn borrowed_dependencies<'a>(
    commit: &Checksum,
    related: &'a [(String, Vec<u8>)],
) -> Result<Vec<(&'a str, Checksum)>> {
    related
        .iter()
        .enumerate()
        .map(|(index, (name, bytes))| match Checksum::from_ay(bytes) {
            Ok(checksum) if !name.is_empty() => Ok((name.as_str(), checksum)),
            checksum => {
                let entry = RelatedEntry {
                    name: name.clone(),
                    checksum: checksum.map_err(|_| bytes.len()),
                };
                Err(Error::InvalidRelated {
                    commit: Some(*commit),
                    field: RelatedField::Dependencies,
                    reason: entry.defect(index).expect("the entry is defective"),
                })
            }
        })
        .collect()
}

/// The state of a commit that the repository or the transaction holds, as a
/// dependency.
///
/// `T` is the value that the caller reads from the commit object of a
/// complete dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldDependency<T = ()> {
    /// The repository does not hold the commit object, and the transaction
    /// does not stage it.
    Absent,
    /// The repository or the transaction holds the commit object, and the
    /// repository marks it partial.
    Partial,
    /// The repository or the transaction holds the commit object, and the
    /// repository does not mark it partial.
    /// `nested` is `true` if the field 2 of the commit is not empty. `value`
    /// is the value that the caller reads from the commit object.
    Complete { nested: bool, value: T },
}

/// Returns the state of the dependency `checksum` in `repo` or in the
/// transaction that stages it.
///
/// If `staging` is set, the transaction stages the commit object of
/// `checksum` in the staging directory `staging`, and the call reads the
/// object from that directory. Otherwise the call reads the object from the
/// object store of `repo`.
///
/// The call reads the partial marker, then the commit object, on the calling
/// thread. A caller on the executor calls it on the blocking pool. For a
/// commit with a partial marker, the call reads no object. A staged commit is
/// then [`HeldDependency::Partial`]. For a commit that is not staged, the call
/// only finds if the object store holds the object. For a commit with no
/// marker, the call reads the object, decodes field 2 alone, and then calls
/// `read` with the bytes of the object.
///
/// # Errors
///
/// - [`Error::Core`] if the commit tuple does not frame, or if its field 2
///   does not decode.
/// - [`Error::Io`] if a file system operation fails, or if the commit object
///   is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
/// - Each error of `read`.
pub(crate) fn held_dependency_blocking<T>(
    repo: &Repo,
    staging: Option<BorrowedFd<'_>>,
    checksum: &Checksum,
    read: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<HeldDependency<T>> {
    if repo.commit_state_blocking(checksum)? == CommitState::Partial {
        let held = staging.is_some() || repo.has_object_blocking(ObjectType::Commit, checksum)?;
        return Ok(if held {
            HeldDependency::Partial
        } else {
            HeldDependency::Absent
        });
    }
    let bytes = match staging {
        Some(staging) => {
            let flat = crate::write::flat_name(checksum, ObjectType::Commit, repo.mode());
            crate::object::read_meta_object(staging, &flat, crate::object::MAX_METADATA_SIZE)?
        }
        None => match repo.load_object_bytes_blocking(ObjectType::Commit, checksum) {
            Ok(bytes) => bytes,
            Err(Error::ObjectNotFound { .. }) => return Ok(HeldDependency::Absent),
            Err(e) => return Err(e),
        },
    };
    let nested = has_dependencies(&bytes)?;
    Ok(HeldDependency::Complete {
        nested,
        value: read(&bytes)?,
    })
}

/// Returns the error for the dependency `name` of `commit`, which names the
/// commit `dependency` whose own field 2 is not empty.
pub(crate) fn nested_dependency(commit: Checksum, name: &str, dependency: &Checksum) -> Error {
    Error::InvalidRelated {
        commit: Some(commit),
        field: RelatedField::Dependencies,
        reason: dependency_reason(name, dependency, NESTED_REASON),
    }
}

/// Returns the error for the dependency `name` of `commit`, which names the
/// commit `dependency` that the repository marks partial.
#[cfg_attr(not(any(feature = "push", feature = "receive")), allow(dead_code))]
pub(crate) fn partial_dependency(commit: Checksum, name: &str, dependency: &Checksum) -> Error {
    Error::InvalidRelated {
        commit: Some(commit),
        field: RelatedField::Dependencies,
        reason: dependency_reason(name, dependency, PARTIAL_REASON),
    }
}

/// Returns the reason for the dependency `name`, which names the commit
/// `dependency`, with the end `end`.
pub(crate) fn dependency_reason(name: &str, dependency: &Checksum, end: &str) -> String {
    format!("dependency {name} names commit {dependency}, {end}")
}

/// Returns the dependencies `entries` of a new commit, sorted by name in byte
/// order.
///
/// The call does no I/O. The sort is stable. The index in the error for an
/// empty name is the position of the entry in `entries` before the sort.
///
/// # Errors
///
/// [`Error::InvalidRelated`] with no commit, if an entry has an empty name or
/// if two entries have the same name.
pub(crate) fn sorted_new(mut entries: Vec<(String, Checksum)>) -> Result<Vec<(String, Checksum)>> {
    if let Some(index) = entries.iter().position(|(name, _)| name.is_empty()) {
        return Err(Error::InvalidRelated {
            commit: None,
            field: RelatedField::Dependencies,
            reason: format!("entry {index} has an empty name"),
        });
    }
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    check_order(None, entries.iter().map(|(name, _)| name.as_str()))?;
    Ok(entries)
}

/// Checks that the names of the dependencies are sorted in byte order, with
/// no name two times.
///
/// # Errors
///
/// [`Error::InvalidRelated`] with `commit` for the first pair of names out of
/// order or with the same value.
pub(crate) fn check_order<'a>(
    commit: Option<Checksum>,
    names: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let mut names = names.into_iter();
    let Some(mut a) = names.next() else {
        return Ok(());
    };
    for b in names {
        let reason = match a.cmp(b) {
            std::cmp::Ordering::Less => {
                a = b;
                continue;
            }
            std::cmp::Ordering::Equal => format!("two entries have the name {a}"),
            std::cmp::Ordering::Greater => {
                format!("entries are not sorted by name: {b} follows {a}")
            }
        };
        return Err(Error::InvalidRelated {
            commit,
            field: RelatedField::Dependencies,
            reason,
        });
    }
    Ok(())
}

/// Checks that the dependencies `deps` are complete and that none of them is
/// nested.
///
/// A dependency is complete if `txn` stages its commit object or the
/// repository holds it, and the repository holds no
/// `state/<checksum>.commitpartial` marker for it. A dependency is nested if
/// its own field 2 is not empty. The checks of all dependencies run in one
/// trip to the blocking pool, in the order of `deps`. A checksum that `deps`
/// names more than once is checked once, at its first entry. For each
/// dependency, the check reads the partial marker first, and reads no commit
/// object of a dependency with a marker.
///
/// # Errors
///
/// - [`Error::InvalidRelated`] with `commit` for the first dependency that is
///   absent, partial, or nested.
/// - [`Error::Core`] if the commit tuple of a dependency with no partial
///   marker does not frame, or if its field 2 does not decode.
/// - [`Error::Io`] if a file system operation fails, or if the commit object
///   of a dependency with no partial marker is larger than
///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
pub(crate) async fn check_dependencies<'a>(
    txn: &Transaction,
    commit: Option<Checksum>,
    deps: impl IntoIterator<Item = &'a (String, Checksum)>,
) -> Result<()> {
    let deps: Vec<&(String, Checksum)> = deps.into_iter().collect();
    if deps.is_empty() {
        return Ok(());
    }
    let checksums: Vec<Checksum> = deps.iter().map(|(_, checksum)| *checksum).collect();
    let staged = txn.staged_flags(ObjectType::Commit, &checksums);
    let staging = if staged.contains(&true) {
        Some(txn.staging_fd().try_clone_to_owned()?)
    } else {
        None
    };
    let repo: Repo = txn.repo().clone();
    // The closure gives the index of the first refused dependency and the end
    // of the reason. The names stay here.
    let refused = ostrya_rt::unblock(move || -> Result<Option<(usize, &'static str)>> {
        // A repeated checksum has the result of its first entry, so the check
        // reads it once.
        let mut checked = HashSet::new();
        for (index, (checksum, staged)) in checksums.iter().zip(staged).enumerate() {
            if !checked.insert(*checksum) {
                continue;
            }
            let staging = staging.as_ref().filter(|_| staged).map(|fd| fd.as_fd());
            let defect = match held_dependency_blocking(&repo, staging, checksum, |_| Ok(()))? {
                HeldDependency::Absent => "which is in neither the repository nor the transaction",
                HeldDependency::Partial => PARTIAL_REASON,
                HeldDependency::Complete { nested: true, .. } => NESTED_REASON,
                HeldDependency::Complete { nested: false, .. } => continue,
            };
            return Ok(Some((index, defect)));
        }
        Ok(None)
    })
    .await?;
    match refused {
        None => Ok(()),
        Some((index, defect)) => {
            let (name, checksum) = deps[index];
            Err(Error::InvalidRelated {
                commit,
                field: RelatedField::Dependencies,
                reason: dependency_reason(name, checksum, defect),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use ostrya_core::Commit;

    use super::*;

    fn checksum(byte: u8) -> Checksum {
        Checksum::from_ay(&[byte; 32]).unwrap()
    }

    fn commit_bytes(related: Vec<(String, Vec<u8>)>) -> Vec<u8> {
        Commit {
            metadata: Value::Array(Vec::new()),
            parent: None,
            related,
            subject: String::new(),
            body: String::new(),
            timestamp: 0,
            root_dirtree: checksum(1),
            root_dirmeta: checksum(2),
        }
        .serialize()
        .unwrap()
    }

    fn reason(err: Error) -> (Option<Checksum>, RelatedField, String) {
        match err {
            Error::InvalidRelated {
                commit,
                field,
                reason,
            } => (commit, field, reason),
            other => panic!("expected InvalidRelated, got {other:?}"),
        }
    }

    #[test]
    fn parse_dependencies_of_empty_field() {
        let bytes = commit_bytes(Vec::new());
        assert!(parse_dependencies(&bytes).unwrap().is_empty());
        assert!(!has_dependencies(&bytes).unwrap());
    }

    #[test]
    fn parse_dependencies_keeps_stored_order_and_lengths() {
        let bytes = commit_bytes(vec![
            ("b/x".into(), vec![3; 32]),
            ("a/y".into(), vec![4; 31]),
            (String::new(), vec![5; 32]),
        ]);
        let entries = parse_dependencies(&bytes).unwrap();
        assert_eq!(
            entries,
            vec![
                RelatedEntry {
                    name: "b/x".into(),
                    checksum: Ok(checksum(3)),
                },
                RelatedEntry {
                    name: "a/y".into(),
                    checksum: Err(31),
                },
                RelatedEntry {
                    name: String::new(),
                    checksum: Ok(checksum(5)),
                },
            ]
        );
        assert!(has_dependencies(&bytes).unwrap());
        assert_eq!(entries[0].defect(0), None);
        assert_eq!(
            entries[1].defect(1).unwrap(),
            "entry 1 (a/y) has a checksum of 31 bytes, not 32"
        );
        assert_eq!(entries[2].defect(2).unwrap(), "entry 2 has an empty name");
        assert_eq!(entries_of(&Commit::parse(&bytes).unwrap().related), entries);
        assert_eq!(
            into_entries(Commit::parse(&bytes).unwrap().related),
            entries
        );
    }

    #[test]
    fn parse_dependencies_refuses_torn_bytes() {
        let bytes = commit_bytes(vec![("a/x".into(), vec![3; 32])]);
        let torn = &bytes[..bytes.len() - 3];
        assert!(matches!(parse_dependencies(torn), Err(Error::Core(_))));
        assert!(matches!(has_dependencies(torn), Err(Error::Core(_))));
    }

    #[test]
    fn checked_entries_names_the_first_defect() {
        let entries = vec![
            RelatedEntry {
                name: "a/x".into(),
                checksum: Ok(checksum(3)),
            },
            RelatedEntry {
                name: "b/x".into(),
                checksum: Err(0),
            },
        ];
        let (commit, field, reason) = reason(
            checked_entries(RelatedField::BuildSources, Some(checksum(9)), entries).unwrap_err(),
        );
        assert_eq!(commit, Some(checksum(9)));
        assert_eq!(field, RelatedField::BuildSources);
        assert_eq!(reason, "entry 1 (b/x) has a checksum of 0 bytes, not 32");
    }

    #[test]
    fn checked_dependencies_keeps_order_and_names_the_commit() {
        let related = vec![("b/x".into(), vec![3; 32]), ("a/y".into(), vec![4; 32])];
        assert_eq!(
            checked_dependencies(&checksum(9), related).unwrap(),
            vec![("b/x".into(), checksum(3)), ("a/y".into(), checksum(4))]
        );
        let (commit, field, text) = reason(
            checked_dependencies(&checksum(9), vec![(String::new(), vec![3; 32])]).unwrap_err(),
        );
        assert_eq!(commit, Some(checksum(9)));
        assert_eq!(field, RelatedField::Dependencies);
        assert_eq!(text, "entry 0 has an empty name");

        let (commit, field, text) = reason(nested_dependency(checksum(9), "lib/b", &checksum(3)));
        assert_eq!(commit, Some(checksum(9)));
        assert_eq!(field, RelatedField::Dependencies);
        assert_eq!(
            text,
            format!(
                "dependency lib/b names commit {}, which has dependencies of its own",
                checksum(3)
            )
        );
    }

    #[test]
    fn sorted_new_sorts_by_bytes() {
        let entries: Vec<(String, Checksum)> = vec![
            ("container/fe".into(), checksum(1)),
            ("boot/uki".into(), checksum(2)),
            ("Z/upper".into(), checksum(3)),
            ("boot/uki-2".into(), checksum(4)),
        ];
        let sorted = sorted_new(entries).unwrap();
        let names: Vec<&str> = sorted.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["Z/upper", "boot/uki", "boot/uki-2", "container/fe"]);
    }

    #[test]
    fn sorted_new_refuses_empty_and_duplicate_names() {
        let (commit, field, text) = reason(
            sorted_new(vec![
                ("a".into(), checksum(1)),
                (String::new(), checksum(2)),
            ])
            .unwrap_err(),
        );
        assert_eq!(commit, None);
        assert_eq!(field, RelatedField::Dependencies);
        assert_eq!(text, "entry 1 has an empty name");

        let (_, _, text) = reason(
            sorted_new(vec![
                ("b".into(), checksum(1)),
                ("a".into(), checksum(2)),
                ("b".into(), checksum(3)),
            ])
            .unwrap_err(),
        );
        assert_eq!(text, "two entries have the name b");
    }

    #[test]
    fn check_order_refuses_unsorted_entries() {
        let (commit, _, text) = reason(check_order(Some(checksum(7)), ["b", "a"]).unwrap_err());
        assert_eq!(commit, Some(checksum(7)));
        assert_eq!(text, "entries are not sorted by name: a follows b");
    }

    fn detached(value: Value) -> Value {
        Value::Array(vec![Value::Tuple(vec![
            Value::Str(RELATED_KEY.into()),
            value,
        ])])
    }

    #[test]
    fn the_key_bytes_are_the_key_and_a_nul() {
        let mut expected = RELATED_KEY.as_bytes().to_vec();
        expected.push(0);
        assert_eq!(RELATED_KEY_BYTES, expected);
    }

    #[test]
    fn may_hold_build_sources_needs_the_key_and_its_nul() {
        assert!(!may_hold_build_sources(b""));
        assert!(!may_hold_build_sources(b"ostree.gpgsigs\0"));
        assert!(may_hold_build_sources(b"ostrya.related\0"));
        assert!(may_hold_build_sources(b"\x01\x02ostrya.related\0\0\0v"));
        assert!(!may_hold_build_sources(b"\x01\x02ostrya.related"));
        assert!(!may_hold_build_sources(b"ostrya.relatedX\0"));
        assert!(!may_hold_build_sources(b"ostrya.relate\0"));
    }

    #[test]
    fn may_hold_build_sources_finds_the_key_of_a_serialized_dict() {
        let dict = detached(Value::variant(
            Type::parse(RELATED_SIGNATURE).unwrap(),
            Value::Array(Vec::new()),
        ));
        let bytes = crate::summary::serialize_signature_dict(&dict).unwrap();
        assert!(may_hold_build_sources(&bytes));
    }

    #[test]
    fn build_sources_of_absent_key() {
        assert_eq!(build_sources(None), Ok(None));
        assert_eq!(build_sources(Some(&Value::Array(Vec::new()))), Ok(None));
    }

    #[test]
    fn build_sources_reads_pairs() {
        let ty = Type::parse(RELATED_SIGNATURE).unwrap();
        let value = Value::variant(
            ty,
            Value::Array(vec![Value::Tuple(vec![
                Value::Str("container/fe".into()),
                Value::Bytes(vec![6; 32]),
            ])]),
        );
        let entries = build_sources(Some(&detached(value))).unwrap().unwrap();
        assert_eq!(
            entries,
            vec![RelatedEntry {
                name: "container/fe".into(),
                checksum: Ok(checksum(6)),
            }]
        );
    }

    #[test]
    fn build_sources_refuses_wrong_type_and_non_variant() {
        let strings = Value::variant(
            Type::parse("as").unwrap(),
            Value::Array(vec![Value::Str("x".into())]),
        );
        assert_eq!(
            build_sources(Some(&detached(strings))),
            Err("type is `as`, not `a(say)`".into())
        );
        assert_eq!(
            build_sources(Some(&detached(Value::Str("x".into())))),
            Err("value is not a variant".into())
        );
        let shape = Value::variant(
            Type::parse(RELATED_SIGNATURE).unwrap(),
            Value::Array(vec![Value::Str("x".into())]),
        );
        assert_eq!(
            build_sources(Some(&detached(shape))),
            Err("element 0 is not a (say) pair".into())
        );
    }
}
