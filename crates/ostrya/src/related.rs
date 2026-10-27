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

use std::os::fd::AsFd;
use std::sync::LazyLock;

use ostrya_core::{Checksum, ObjectType, Type, Value, tuple_field_from_bytes};

use crate::error::{Error, Result};
use crate::read::CommitState;
use crate::repo::Repo;
use crate::transaction::Transaction;

/// The detached metadata key of the build sources.
pub(crate) const RELATED_KEY: &str = "ostrya.related";

/// The type string of a field of related entries.
const RELATED_SIGNATURE: &str = "a(say)";

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
    entries: Vec<RelatedEntry>,
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

/// Returns the dependencies `entries` of a new commit, sorted by name in byte
/// order.
///
/// The call does no I/O and does not change `entries`. The sort is stable.
///
/// # Errors
///
/// [`Error::InvalidRelated`] with no commit, if an entry has an empty name or
/// if two entries have the same name.
pub(crate) fn sorted_new(entries: &[(String, Checksum)]) -> Result<Vec<&(String, Checksum)>> {
    if let Some(index) = entries.iter().position(|(name, _)| name.is_empty()) {
        return Err(Error::InvalidRelated {
            commit: None,
            field: RelatedField::Dependencies,
            reason: format!("entry {index} has an empty name"),
        });
    }
    let mut sorted: Vec<&(String, Checksum)> = entries.iter().collect();
    sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
    check_order(None, sorted.iter().map(|(name, _)| name.as_str()))?;
    Ok(sorted)
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
/// trip to the blocking pool, in the order of `deps`.
///
/// # Errors
///
/// - [`Error::InvalidRelated`] with `commit` for the first dependency that is
///   absent, partial, or nested.
/// - [`Error::Core`] if the commit tuple of a dependency does not frame, or if
///   its field 2 does not decode.
/// - [`Error::Io`] if a file system operation fails, or if the commit object
///   of a dependency is larger than
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
        for (index, (checksum, staged)) in checksums.iter().zip(staged).enumerate() {
            let bytes = match staging.as_ref().filter(|_| staged) {
                Some(staging) => {
                    let flat = crate::write::flat_name(checksum, ObjectType::Commit, repo.mode());
                    crate::object::read_meta_object(
                        staging.as_fd(),
                        &flat,
                        crate::object::MAX_METADATA_SIZE,
                    )?
                }
                None => match repo.load_object_bytes_blocking(ObjectType::Commit, checksum) {
                    Ok(bytes) => bytes,
                    Err(Error::ObjectNotFound {
                        checksum: missing,
                        ty: ObjectType::Commit,
                    }) if missing == *checksum => {
                        return Ok(Some((
                            index,
                            "which is in neither the repository nor the transaction",
                        )));
                    }
                    Err(e) => return Err(e),
                },
            };
            if repo.commit_state_blocking(checksum)? == CommitState::Partial {
                return Ok(Some((index, "which is partial")));
            }
            if has_dependencies(&bytes)? {
                return Ok(Some((index, "which has dependencies of its own")));
            }
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
                reason: format!("dependency {name} names commit {checksum}, {defect}"),
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
    fn sorted_new_sorts_by_bytes() {
        let entries: Vec<(String, Checksum)> = vec![
            ("container/fe".into(), checksum(1)),
            ("boot/uki".into(), checksum(2)),
            ("Z/upper".into(), checksum(3)),
            ("boot/uki-2".into(), checksum(4)),
        ];
        let sorted = sorted_new(&entries).unwrap();
        let names: Vec<&str> = sorted.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["Z/upper", "boot/uki", "boot/uki-2", "container/fe"]);
        assert_eq!(entries[0].0, "container/fe", "the input keeps its order");
    }

    #[test]
    fn sorted_new_refuses_empty_and_duplicate_names() {
        let (commit, field, text) = reason(
            sorted_new(&[("a".into(), checksum(1)), (String::new(), checksum(2))]).unwrap_err(),
        );
        assert_eq!(commit, None);
        assert_eq!(field, RelatedField::Dependencies);
        assert_eq!(text, "entry 1 has an empty name");

        let (_, _, text) = reason(
            sorted_new(&[
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
