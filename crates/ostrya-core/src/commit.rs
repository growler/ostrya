//! Commit objects.
//!
//! Wire form `(a{sv}aya(say)sstayay)`: the metadata dict, the parent commit
//! checksum (an empty `ay` for a root commit), the related-objects array
//! (written empty, retained verbatim on parse), subject, body, the big-endian
//! timestamp, and the root dirtree and dirmeta checksums.
//!
//! Commits are read a handful at a time and their fields are retained, so
//! there is no borrowed view type: [`Commit::parse`] produces the owned
//! struct. The dynamic `a{sv}` metadata is held as a [`Value`] tree, which
//! round-trips byte-identically because both codec paths emit normal form.

use std::sync::LazyLock;

use ostrya_gvariant::{
    ArrayIter, GvDecode, GvEncode, GvType, Slice, Type, Value, from_bytes, to_bytes,
};

use crate::be::Be64;
use crate::checksum::Checksum;
use crate::error::{Error, Result};

/// The `a{sv}` metadata dict type, parsed once and shared. `Type` is
/// `Send + Sync`, so the same value serves every parse and serialize call.
static METADATA_TYPE: LazyLock<Type> =
    LazyLock::new(|| Type::parse("a{sv}").expect("a{sv} is a valid signature"));

/// An owned commit object. The timestamp is host-order seconds since the
/// Unix epoch, UTC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// The `a{sv}` metadata dict as a [`Value`] tree (an array of two-element
    /// tuples, in on-disk order).
    pub metadata: Value,
    /// Parent commit, `None` for a root commit (an empty `ay` on the wire).
    pub parent: Option<Checksum>,
    /// Related objects: written as an empty array by the tool; parsed
    /// entries are retained verbatim for byte-exact reserialization.
    pub related: Vec<(String, Vec<u8>)>,
    pub subject: String,
    pub body: String,
    pub timestamp: u64,
    pub root_dirtree: Checksum,
    pub root_dirmeta: Checksum,
}

/// The commit shape with the metadata and checksum fields as raw slices; the
/// value-level conventions are applied on top of this view.
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
    /// Parse a serialized commit object.
    pub fn parse(data: &[u8]) -> Result<Commit> {
        let (metadata, parent, related, subject, body, timestamp, root_dirtree, root_dirmeta): CommitView = GvDecode::decode(data)?;
        let metadata = from_bytes(&METADATA_TYPE, metadata)?;
        let parent = match parent.len() {
            0 => None,
            32 => Some(Checksum::from_ay(parent)?),
            _ => {
                return Err(Error::InvalidCommit(
                    "parent checksum is neither empty nor 32 bytes",
                ));
            }
        };
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
            root_dirtree: Checksum::from_ay(root_dirtree)
                .map_err(|_| Error::InvalidCommit("root dirtree checksum is not 32 bytes"))?,
            root_dirmeta: Checksum::from_ay(root_dirmeta)
                .map_err(|_| Error::InvalidCommit("root dirmeta checksum is not 32 bytes"))?,
        })
    }

    /// Serialize to normal-form bytes; their SHA-256 is the commit checksum.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(ostrya_gvariant::encode_to_vec(self)?)
    }

    /// The commit checksum: SHA-256 of the serialized bytes.
    pub fn checksum(&self) -> Result<Checksum> {
        Ok(Checksum::sha256(&self.serialize()?))
    }

    /// The commit content checksum: SHA-256 over the binary root dirtree and
    /// dirmeta checksums, a content identity independent of commit metadata
    /// and timestamp.
    pub fn content_checksum(&self) -> Checksum {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.root_dirtree.as_bytes());
        buf[32..].copy_from_slice(self.root_dirmeta.as_bytes());
        Checksum::sha256(&buf)
    }

    /// The variant value stored under `key` in the metadata dict.
    pub fn metadata_value(&self, key: &str) -> Option<&Value> {
        self.metadata
            .dict_get(key)?
            .as_variant()
            .map(|(_, value)| value)
    }

    /// The `version` metadata key (the only well-known key without the
    /// `ostree.` prefix).
    pub fn version(&self) -> Option<&str> {
        self.metadata_value("version")?.as_str()
    }

    /// The refs named by `ostree.ref-binding`, empty when unbound.
    pub fn ref_bindings(&self) -> Vec<&str> {
        self.metadata_value("ostree.ref-binding")
            .and_then(Value::as_array)
            .map(|refs| refs.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    /// The `ostree.collection-binding` metadata key.
    pub fn collection_binding(&self) -> Option<&str> {
        self.metadata_value("ostree.collection-binding")?.as_str()
    }
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

    /// Serialize a commit through the `Value` tree with an arbitrary parent
    /// and root checksum widths, bypassing the struct's validation.
    fn craft(parent: &[u8], root_dirtree: &[u8]) -> Vec<u8> {
        let ty = Type::parse(<Commit as GvType>::SIGNATURE).unwrap();
        let value = Value::Tuple(vec![
            Value::Array(Vec::new()),
            Value::Bytes(parent.to_vec()),
            Value::Array(Vec::new()),
            Value::Str(String::new()),
            Value::Str(String::new()),
            Value::U64(0),
            Value::Bytes(root_dirtree.to_vec()),
            Value::Bytes(vec![2; 32]),
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
    fn content_checksum_hashes_the_two_root_checksums() {
        let commit = sample();
        let mut buf = Vec::new();
        buf.extend_from_slice(csum(1).as_bytes());
        buf.extend_from_slice(csum(2).as_bytes());
        assert_eq!(commit.content_checksum(), Checksum::sha256(&buf));
    }
}
