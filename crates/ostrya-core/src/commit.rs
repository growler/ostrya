//! Commit objects.
//!
//! This module has no borrowed view type. `Commit::parse` returns the owned
//! struct.

use std::sync::LazyLock;

use ostrya_gvariant::{
    ArrayIter, GvDecode, GvEncode, GvType, Slice, Type, Value, from_bytes, to_bytes,
};

use crate::be::Be64;
use crate::checksum::Checksum;
use crate::error::{Error, Result};

/// The type `a{sv}` of the metadata dict, parsed one time and shared. `Type`
/// is `Send + Sync`, so each parse call and each serialize call use this value.
static METADATA_TYPE: LazyLock<Type> =
    LazyLock::new(|| Type::parse("a{sv}").expect("a{sv} is a valid signature"));

/// An owned commit object.
///
/// # Wire form
///
/// A commit object is the GVariant tuple `(a{sv}aya(say)sstayay)`. It holds
/// these members, in this order:
///
/// 1. `a{sv}`: the metadata dict
/// 2. `ay`: the checksum of the parent commit, empty for a root commit
/// 3. `a(say)`: the related objects
/// 4. `s`: the subject
/// 5. `s`: the body
/// 6. `t`: the timestamp, big-endian
/// 7. `ay`: the checksum of the root dirtree
/// 8. `ay`: the checksum of the root dirmeta
///
/// The struct holds the timestamp in host byte order.
///
/// The metadata is a [`Value`] tree. It writes back to the same bytes,
/// because [`from_bytes`] accepts only normal form and [`to_bytes`] writes
/// normal form.
///
/// A walk of a long parent chain uses [`Commit::parse_link`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// The `a{sv}` metadata dict as a [`Value`] tree.
    ///
    /// The tree is an array of two-element tuples, in on-disk order.
    pub metadata: Value,
    /// The checksum of the parent commit, or `None` for a root commit.
    pub parent: Option<Checksum>,
    /// The related objects.
    ///
    /// The `ostree` command writes an empty array. A parse keeps the entries
    /// as read, so the commit serializes to the same bytes.
    pub related: Vec<(String, Vec<u8>)>,
    /// The commit subject, the first line of its message.
    pub subject: String,
    /// The commit body, the rest of its message.
    pub body: String,
    /// The commit time, in seconds since the Unix epoch, UTC.
    pub timestamp: u64,
    /// The checksum of the dirtree object of the root directory.
    pub root_dirtree: Checksum,
    /// The checksum of the dirmeta object of the root directory.
    pub root_dirmeta: Checksum,
}

/// The parent and the root checksums of a commit, from [`Commit::parse_link`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitLink {
    /// The checksum of the parent commit, or `None` for a root commit.
    pub parent: Option<Checksum>,
    /// The checksum of the dirtree object of the root directory.
    pub root_dirtree: Checksum,
    /// The checksum of the dirmeta object of the root directory.
    pub root_dirmeta: Checksum,
}

/// The commit tuple with the metadata and the checksums as raw slices. The
/// parse functions apply the value checks to this view.
type CommitView<'a> = (
    &'a [u8],
    &'a [u8],
    ArrayIter<'a, (&'a str, &'a [u8])>,
    &'a str,
    &'a str,
    Be64,
    &'a [u8],
    &'a [u8],
);

impl Commit {
    /// Parses a serialized commit object.
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] with [`NotNormal`] if `data`, the metadata dict,
    ///   or an entry of the related objects is not in normal form.
    /// - [`Error::Gvariant`] with [`DepthExceeded`] if the metadata dict nests
    ///   deeper than the depth limit of [`from_bytes`].
    /// - [`Error::InvalidCommit`] with "parent checksum is neither empty nor
    ///   32 bytes" if the parent checksum has a length other than 0 or 32.
    /// - [`Error::InvalidCommit`] with "root dirtree checksum is not 32 bytes"
    ///   if the root dirtree checksum has a length other than 32.
    /// - [`Error::InvalidCommit`] with "root dirmeta checksum is not 32 bytes"
    ///   if the root dirmeta checksum has a length other than 32.
    ///
    /// [`NotNormal`]: ostrya_gvariant::Error::NotNormal
    /// [`DepthExceeded`]: ostrya_gvariant::Error::DepthExceeded
    pub fn parse(data: &[u8]) -> Result<Commit> {
        let (metadata, parent, related, subject, body, timestamp, root_dirtree, root_dirmeta): CommitView = GvDecode::decode(data)?;
        let metadata = from_bytes(&METADATA_TYPE, metadata)?;
        let parent = parse_parent(parent)?;
        let related = related
            .map(|item| item.map(|(name, bytes)| (name.to_owned(), bytes.to_vec())))
            .collect::<ostrya_gvariant::Result<Vec<_>>>()?;
        Ok(Commit {
            metadata,
            parent,
            related,
            subject: subject.to_owned(),
            body: body.to_owned(),
            timestamp: timestamp.0,
            root_dirtree: parse_root_dirtree(root_dirtree)?,
            root_dirmeta: parse_root_dirmeta(root_dirmeta)?,
        })
    }

    /// Parses the parent and the root checksums of a serialized commit object.
    ///
    /// The function does not decode the metadata dict or the entries of the
    /// related objects. It checks the tuple frame, the subject, the body, and
    /// the three checksums as [`Commit::parse`] does.
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] with [`NotNormal`] if the tuple frame, the
    ///   subject, or the body is not in normal form.
    /// - [`Error::InvalidCommit`] with the messages of [`Commit::parse`] if
    ///   the parent, the root dirtree, or the root dirmeta checksum has a
    ///   wrong length.
    ///
    /// [`NotNormal`]: ostrya_gvariant::Error::NotNormal
    pub fn parse_link(data: &[u8]) -> Result<CommitLink> {
        let (_, parent, _, _, _, _, root_dirtree, root_dirmeta): CommitView =
            GvDecode::decode(data)?;
        Ok(CommitLink {
            parent: parse_parent(parent)?,
            root_dirtree: parse_root_dirtree(root_dirtree)?,
            root_dirmeta: parse_root_dirmeta(root_dirmeta)?,
        })
    }

    /// Serializes the commit to normal-form bytes.
    ///
    /// The SHA-256 of these bytes is the commit checksum, which
    /// [`checksum`](Commit::checksum) returns.
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] with [`TypeMismatch`] if
    ///   [`metadata`](Commit::metadata) is not a value of type `a{sv}`.
    /// - [`Error::Gvariant`] with [`InvalidValue`] if a string holds an
    ///   interior NUL byte. This applies to the strings in the metadata, the
    ///   subject, the body, and the names of the related objects.
    /// - [`Error::Gvariant`] with [`DepthExceeded`] if the metadata nests
    ///   deeper than the depth limit of [`to_bytes`].
    ///
    /// [`TypeMismatch`]: ostrya_gvariant::Error::TypeMismatch
    /// [`InvalidValue`]: ostrya_gvariant::Error::InvalidValue
    /// [`DepthExceeded`]: ostrya_gvariant::Error::DepthExceeded
    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(ostrya_gvariant::encode_to_vec(self)?)
    }

    /// Returns the commit checksum, the SHA-256 of the serialized bytes.
    ///
    /// # Errors
    ///
    /// The errors of [`serialize`](Commit::serialize).
    pub fn checksum(&self) -> Result<Checksum> {
        Ok(Checksum::sha256(&self.serialize()?))
    }

    /// Returns the content checksum of the commit.
    ///
    /// The content checksum is the SHA-256 of the 32-byte root dirtree
    /// checksum followed by the 32-byte root dirmeta checksum. The metadata
    /// and the timestamp of the commit do not change it.
    pub fn content_checksum(&self) -> Checksum {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.root_dirtree.as_bytes());
        buf[32..].copy_from_slice(self.root_dirmeta.as_bytes());
        Checksum::sha256(&buf)
    }

    /// Returns the child of the variant under `key` in the metadata dict.
    ///
    /// If `key` occurs in more than one entry, the first entry applies. If no
    /// entry has `key`, or if its value is not a variant, the result is `None`.
    pub fn metadata_value(&self, key: &str) -> Option<&Value> {
        self.metadata
            .dict_get(key)?
            .as_variant()
            .map(|(_, value)| value)
    }

    /// Returns the value of the `version` metadata key.
    ///
    /// `version` is the only well-known key without the `ostree.` prefix. If
    /// the key is absent, or if its value is not a string, the result is
    /// `None`.
    pub fn version(&self) -> Option<&str> {
        self.metadata_value("version")?.as_str()
    }

    /// Returns the ref names in the `ostree.ref-binding` metadata key.
    ///
    /// If the key is absent, or if the commit is bound to no ref, the list is
    /// empty.
    pub fn ref_bindings(&self) -> Vec<&str> {
        self.metadata_value("ostree.ref-binding")
            .and_then(Value::as_array)
            .map(|refs| refs.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    /// Returns the value of the `ostree.collection-binding` metadata key.
    ///
    /// If the key is absent, or if its value is not a string, the result is
    /// `None`.
    pub fn collection_binding(&self) -> Option<&str> {
        self.metadata_value("ostree.collection-binding")?.as_str()
    }
}

/// The parent checksum of a commit: an empty `ay` for a root commit.
fn parse_parent(parent: &[u8]) -> Result<Option<Checksum>> {
    match parent.len() {
        0 => Ok(None),
        32 => Ok(Some(Checksum::from_ay(parent)?)),
        _ => Err(Error::InvalidCommit(
            "parent checksum is neither empty nor 32 bytes",
        )),
    }
}

/// The root dirtree checksum of a commit.
fn parse_root_dirtree(root_dirtree: &[u8]) -> Result<Checksum> {
    Checksum::from_ay(root_dirtree)
        .map_err(|_| Error::InvalidCommit("root dirtree checksum is not 32 bytes"))
}

/// The root dirmeta checksum of a commit.
fn parse_root_dirmeta(root_dirmeta: &[u8]) -> Result<Checksum> {
    Checksum::from_ay(root_dirmeta)
        .map_err(|_| Error::InvalidCommit("root dirmeta checksum is not 32 bytes"))
}

/// A pre-serialized `a{sv}` spliced in as the first tuple member.
struct RawDict<'a>(&'a [u8]);

impl GvType for RawDict<'_> {
    const ALIGNMENT: usize = 8;
    const FIXED_SIZE: Option<usize> = None;
}

impl GvEncode for RawDict<'_> {
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        out.extend_from_slice(self.0);
        Ok(())
    }
}

impl GvType for Commit {
    const SIGNATURE: &'static str = "(a{sv}aya(say)sstayay)";
    // Greatest member alignment: the metadata dict and the timestamp.
    const ALIGNMENT: usize = 8;
    const FIXED_SIZE: Option<usize> = None;
}

impl GvEncode for Commit {
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        let metadata = to_bytes(&METADATA_TYPE, &self.metadata)?;
        let parent: &[u8] = match &self.parent {
            Some(checksum) => checksum.as_bytes(),
            None => &[],
        };
        let related: Vec<(&str, &[u8])> = self
            .related
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
            .collect();
        (
            RawDict(&metadata),
            parent,
            Slice(&related),
            self.subject.as_str(),
            self.body.as_str(),
            Be64(self.timestamp),
            self.root_dirtree,
            self.root_dirmeta,
        )
            .encode(out)
    }
}

/// The metadata key that holds the ref names a commit is bound to.
const REF_BINDING_KEY: &str = "ostree.ref-binding";
/// The metadata key that holds the collection id a commit is bound to.
const COLLECTION_BINDING_KEY: &str = "ostree.collection-binding";

/// Returns the `ostree.ref-binding` value for `refs`.
///
/// The value is a variant of type `as`. It holds the names sorted byte-wise
/// in ascending order, with duplicates kept. An empty list gives the empty
/// array, which is the value of a commit bound to no ref.
pub fn ref_binding(refs: &[&str]) -> Value {
    let mut names = refs.to_vec();
    names.sort_unstable();
    Value::variant(
        Type::parse("as").expect("\"as\" is a valid gvariant type"),
        Value::Array(
            names
                .into_iter()
                .map(|name| Value::Str(name.to_owned()))
                .collect(),
        ),
    )
}

/// Returns the `a{sv}` metadata dict of a new commit.
///
/// The entry order is part of the commit checksum. The dict holds these
/// entries, in this order:
///
/// 1. `entries`, in the order given, with duplicate keys kept
/// 2. `ostree.ref-binding` with the [`ref_binding`] value for `refs`, if
///    `refs` is set
/// 3. `ostree.collection-binding` with `collection_id`, if `collection_id` is
///    set
///
/// If `refs` is `None`, the dict holds neither binding key, and the function
/// ignores `collection_id`. Each value in `entries` must be a
/// [`Value::Variant`], or [`Commit::serialize`] returns an error.
pub fn commit_metadata(
    entries: impl IntoIterator<Item = (String, Value)>,
    refs: Option<&[&str]>,
    collection_id: Option<&str>,
) -> Value {
    let mut dict: Vec<Value> = entries
        .into_iter()
        .map(|(key, value)| Value::Tuple(vec![Value::Str(key), value]))
        .collect();
    if let Some(refs) = refs {
        dict.push(Value::Tuple(vec![
            Value::Str(REF_BINDING_KEY.to_owned()),
            ref_binding(refs),
        ]));
        if let Some(collection) = collection_id {
            dict.push(Value::Tuple(vec![
                Value::Str(COLLECTION_BINDING_KEY.to_owned()),
                Value::variant(Type::Str, Value::Str(collection.to_owned())),
            ]));
        }
    }
    Value::Array(dict)
}

/// An error of [`commit_timestamp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampError {
    /// A `SOURCE_DATE_EPOCH` value that is not a count of seconds.
    ///
    /// The variant holds the value as read, before the trim.
    SourceDateEpoch(String),
    /// The system clock is before the Unix epoch.
    ClockBeforeEpoch,
}

impl std::fmt::Display for TimestampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimestampError::SourceDateEpoch(raw) => {
                write!(f, "SOURCE_DATE_EPOCH is not a Unix timestamp: {raw:?}")
            }
            TimestampError::ClockBeforeEpoch => {
                f.write_str("the system clock is before the Unix epoch")
            }
        }
    }
}

impl std::error::Error for TimestampError {}

/// Returns the timestamp of a new commit.
///
/// The timestamp is in seconds since the Unix epoch, UTC. The function takes
/// it from the first of these sources that is set:
///
/// 1. `explicit`
/// 2. the `SOURCE_DATE_EPOCH` environment variable
/// 3. the system clock
///
/// The function trims white space from `SOURCE_DATE_EPOCH` before it parses
/// the value. If `SOURCE_DATE_EPOCH` is not valid Unicode, the function
/// treats it as unset.
///
/// # Errors
///
/// - [`TimestampError::SourceDateEpoch`] if `explicit` is `None` and
///   `SOURCE_DATE_EPOCH` is set to a value that is not a count of seconds.
///   The function does not use the clock in this case, as the
///   reproducible-build convention requires.
/// - [`TimestampError::ClockBeforeEpoch`] if the function reads the system
///   clock and the clock is before the Unix epoch.
pub fn commit_timestamp(explicit: Option<u64>) -> std::result::Result<u64, TimestampError> {
    timestamp_from(explicit, std::env::var("SOURCE_DATE_EPOCH").ok())
}

/// [`commit_timestamp`] over a given `SOURCE_DATE_EPOCH` value.
fn timestamp_from(
    explicit: Option<u64>,
    source_date_epoch: Option<String>,
) -> std::result::Result<u64, TimestampError> {
    if let Some(timestamp) = explicit {
        return Ok(timestamp);
    }
    if let Some(raw) = source_date_epoch {
        return raw
            .trim()
            .parse::<u64>()
            .map_err(|_| TimestampError::SourceDateEpoch(raw));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TimestampError::ClockBeforeEpoch)?;
    Ok(now.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    fn sample() -> Commit {
        Commit {
            metadata: Value::Array(vec![Value::Tuple(vec![
                Value::Str("version".to_owned()),
                Value::variant(Type::Str, Value::Str("42".to_owned())),
            ])]),
            parent: Some(csum(0xaa)),
            related: Vec::new(),
            subject: "subject".to_owned(),
            body: "body".to_owned(),
            timestamp: 1_700_000_000,
            root_dirtree: csum(1),
            root_dirmeta: csum(2),
        }
    }

    #[test]
    fn round_trips_with_parent_and_metadata() {
        let commit = sample();
        let bytes = commit.serialize().unwrap();
        let parsed = Commit::parse(&bytes).unwrap();
        assert_eq!(parsed, commit);
        assert_eq!(parsed.serialize().unwrap(), bytes);
        assert_eq!(parsed.version(), Some("42"));
        assert!(parsed.ref_bindings().is_empty());
        assert_eq!(parsed.collection_binding(), None);
    }

    #[test]
    fn empty_parent_ay_means_a_root_commit() {
        let commit = Commit {
            parent: None,
            ..sample()
        };
        let parsed = Commit::parse(&commit.serialize().unwrap()).unwrap();
        assert_eq!(parsed.parent, None);
    }

    /// Serializes a commit through the `Value` tree with any width of the
    /// parent and the root dirtree checksums. The `Commit` struct cannot hold
    /// such widths.
    fn craft(parent: &[u8], root_dirtree: &[u8]) -> Vec<u8> {
        craft_with(parent, root_dirtree, &[2; 32])
    }

    /// [`craft`] with any width of the root dirmeta checksum.
    fn craft_with(parent: &[u8], root_dirtree: &[u8], root_dirmeta: &[u8]) -> Vec<u8> {
        let ty = Type::parse(<Commit as GvType>::SIGNATURE).unwrap();
        let value = Value::Tuple(vec![
            Value::Array(Vec::new()),
            Value::Bytes(parent.to_vec()),
            Value::Array(Vec::new()),
            Value::Str(String::new()),
            Value::Str(String::new()),
            Value::U64(0),
            Value::Bytes(root_dirtree.to_vec()),
            Value::Bytes(root_dirmeta.to_vec()),
        ]);
        to_bytes(&ty, &value).unwrap()
    }

    #[test]
    fn parse_rejects_malformed_checksum_widths() {
        assert_eq!(
            Commit::parse(&craft(&[0xaa; 31], &[1; 32])),
            Err(Error::InvalidCommit(
                "parent checksum is neither empty nor 32 bytes"
            ))
        );
        assert_eq!(
            Commit::parse(&craft(&[], &[1; 31])),
            Err(Error::InvalidCommit(
                "root dirtree checksum is not 32 bytes"
            ))
        );
    }

    #[test]
    fn parse_link_agrees_with_parse() {
        let root = Commit {
            parent: None,
            ..sample()
        };
        for commit in [sample(), root] {
            let bytes = commit.serialize().unwrap();
            let parsed = Commit::parse(&bytes).unwrap();
            assert_eq!(
                Commit::parse_link(&bytes).unwrap(),
                CommitLink {
                    parent: parsed.parent,
                    root_dirtree: parsed.root_dirtree,
                    root_dirmeta: parsed.root_dirmeta,
                }
            );
        }
    }

    #[test]
    fn parse_link_refuses_what_parse_refuses_in_its_fields() {
        let whole = sample().serialize().unwrap();
        for bytes in [
            craft_with(&[0xaa; 31], &[1; 32], &[2; 32]),
            craft_with(&[0xaa; 33], &[1; 32], &[2; 32]),
            craft_with(&[], &[1; 31], &[2; 32]),
            craft_with(&[], &[1; 32], &[2; 33]),
            craft_with(&[], &[1; 32], &[]),
            whole[..whole.len() - 1].to_vec(),
            Vec::new(),
        ] {
            let refused = Commit::parse(&bytes).expect_err("the full parse refuses the object");
            assert_eq!(Commit::parse_link(&bytes), Err(refused));
        }
    }

    #[test]
    fn content_checksum_hashes_the_two_root_checksums() {
        let commit = sample();
        let mut buf = Vec::new();
        buf.extend_from_slice(csum(1).as_bytes());
        buf.extend_from_slice(csum(2).as_bytes());
        assert_eq!(commit.content_checksum(), Checksum::sha256(&buf));
    }

    fn entry(key: &str, value: &str) -> (String, Value) {
        (
            key.to_owned(),
            Value::variant(Type::Str, Value::Str(value.to_owned())),
        )
    }

    fn text(value: &Value) -> String {
        ostrya_gvariant::to_text(&METADATA_TYPE, value).unwrap()
    }

    #[test]
    fn commit_metadata_orders_entries_then_bindings() {
        let dict = commit_metadata(
            [entry("b", "1"), entry("a", "2"), entry("b", "3")],
            Some(&["zeta", "alpha", "mid", "alpha"]),
            Some("org.example.C"),
        );
        assert_eq!(
            text(&dict),
            "{'b': <'1'>, 'a': <'2'>, 'b': <'3'>, \
             'ostree.ref-binding': <['alpha', 'alpha', 'mid', 'zeta']>, \
             'ostree.collection-binding': <'org.example.C'>}"
        );
    }

    #[test]
    fn commit_metadata_without_refs_holds_no_binding_key() {
        let dict = commit_metadata([entry("k", "v")], None, Some("org.example.C"));
        assert_eq!(text(&dict), "{'k': <'v'>}");
        assert_eq!(commit_metadata([], None, None), Value::Array(Vec::new()));
    }

    #[test]
    fn empty_ref_list_writes_the_empty_array() {
        let dict = commit_metadata([], Some(&[]), None);
        assert_eq!(text(&dict), "{'ostree.ref-binding': <@as []>}");
        assert_eq!(
            dict,
            Value::Array(vec![Value::Tuple(vec![
                Value::Str("ostree.ref-binding".to_owned()),
                ref_binding(&[]),
            ])])
        );
    }

    #[test]
    fn timestamp_prefers_explicit_then_source_date_epoch() {
        assert_eq!(timestamp_from(Some(5), Some("abc".to_owned())), Ok(5));
        assert_eq!(
            timestamp_from(None, Some(" 1700000000\n".to_owned())),
            Ok(1_700_000_000)
        );
        let err = timestamp_from(None, Some("abc".to_owned())).unwrap_err();
        assert_eq!(err, TimestampError::SourceDateEpoch("abc".to_owned()));
        assert_eq!(
            err.to_string(),
            "SOURCE_DATE_EPOCH is not a Unix timestamp: \"abc\""
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let got = timestamp_from(None, None).unwrap();
        assert!(got.abs_diff(now) <= 5, "{got} is near {now}");
    }
}
