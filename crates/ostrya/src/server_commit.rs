//! The commit object of a server commit: the commit that a writer makes
//! from a tree and the fields of a [`ServerCommit`].
//!
//! The receive side of a push and the tree push to a bucket repository make
//! the commit with the same function, so the same inputs give the same
//! bytes.

use ostrya_core::{
    Checksum, Commit, GvDecode, GvEncode, Type, Value, VariantBytes, ref_binding, to_bytes,
    write_array,
};

use crate::error::Error;
use crate::remote::proto::ServerCommit;

/// The metadata key of the ref binding.
const REF_BINDING_KEY: &str = "ostree.ref-binding";
/// The metadata key of the collection binding.
const COLLECTION_BINDING_KEY: &str = "ostree.collection-binding";
/// The metadata key of the composefs digest of a commit.
const COMPOSEFS_DIGEST_KEY: &str = "ostree.composefs.digest.v0";
/// The metadata key of the size records of a commit.
const SIZES_KEY: &str = "ostree.sizes";

/// Returns the bytes of the commit object of `sc`.
///
/// The parent is `tip`, or none with `orphan`. The metadata comes from
/// [`server_commit_metadata`], with the branch, each tag, and each bound name
/// as the ref binding, and `collection_id` as the collection binding. The
/// commit has no related objects. The caller checked that a commit can hold
/// each metadata value of `sc`.
pub(crate) fn commit_bytes(
    sc: &ServerCommit,
    tip: Option<Checksum>,
    timestamp: u64,
    collection_id: Option<&str>,
) -> ostrya_core::Result<Vec<u8>> {
    let bound: Vec<&str> = std::iter::once(sc.branch.as_str())
        .chain(sc.tags.iter().map(String::as_str))
        .chain(sc.bind_refs.iter().map(String::as_str))
        .collect();
    let metadata = server_commit_metadata(&sc.metadata, &bound, collection_id)?;
    Commit {
        metadata: Value::Array(Vec::new()),
        parent: if sc.orphan { None } else { tip },
        related: Vec::new(),
        subject: sc.subject.clone(),
        body: sc.body.clone(),
        timestamp,
        root_dirtree: sc.root_dirtree,
        root_dirmeta: sc.root_dirmeta,
    }
    .serialize_with_metadata(&metadata)
}

/// Returns the time of the system clock in seconds since the Unix epoch, UTC.
///
/// The call reads no `SOURCE_DATE_EPOCH`.
pub(crate) fn clock() -> crate::error::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|now| now.as_secs())
        .map_err(|_| Error::InvalidFormat("the system clock is before the Unix epoch".into()))
}

/// Returns the serialized `a{sv}` metadata dict of a server commit.
///
/// Each entry of `client` is a key and the bytes of a `v` in normal form. The
/// call copies these bytes into the dict and builds no value tree of them.
/// The dict holds these entries, in this order, which is the order of a
/// commit of the `ostree` command:
///
/// 1. Each entry of `client`, in order, with duplicate keys kept. The entries
///    under `ostree.ref-binding` and `ostree.collection-binding` are dropped.
///    The entries under `ostree.composefs.digest.v0` and `ostree.sizes` come
///    later.
/// 2. `ostree.ref-binding` with `refs`, sorted byte-wise, duplicates kept.
/// 3. `ostree.collection-binding` with `collection_id`, if it is set.
/// 4. Each entry of `client` under `ostree.composefs.digest.v0`, in order.
/// 5. Each entry of `client` under `ostree.sizes`, in order.
fn server_commit_metadata(
    client: &[(String, Vec<u8>)],
    refs: &[&str],
    collection_id: Option<&str>,
) -> ostrya_core::Result<Vec<u8>> {
    let refs = to_bytes(&Type::Variant, &ref_binding(refs))?;
    let collection = collection_id
        .map(|id| to_bytes(&Type::Variant, &Value::variant(Type::Str, id.into())))
        .transpose()?;
    let mut entries = Vec::with_capacity(client.len() + 2);
    let mut digests = Vec::new();
    let mut sizes = Vec::new();
    for (key, value) in client {
        let entry = (key.as_str(), value.as_slice());
        match entry.0 {
            REF_BINDING_KEY | COLLECTION_BINDING_KEY => {}
            COMPOSEFS_DIGEST_KEY => digests.push(entry),
            SIZES_KEY => sizes.push(entry),
            _ => entries.push(entry),
        }
    }
    entries.push((REF_BINDING_KEY, &refs));
    if let Some(collection) = &collection {
        entries.push((COLLECTION_BINDING_KEY, collection));
    }
    entries.extend(digests);
    entries.extend(sizes);
    let mut dict = Vec::new();
    write_array(&mut dict, 8, false, entries.len(), |out, i| {
        let (key, value) = entries[i];
        (key, VariantBytes::decode(value)?).encode(out)
    })?;
    Ok(dict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_core::from_bytes;

    fn text(value: &str) -> Value {
        Value::variant(Type::Str, Value::Str(value.into()))
    }

    /// An entry of the client: `key` and the bytes of the `v` `value`.
    fn entry(key: &str, value: Value) -> (String, Vec<u8>) {
        (key.into(), to_bytes(&Type::Variant, &value).unwrap())
    }

    /// Returns the dict of the serialized `a{sv}` `dict` as a value tree.
    fn parse_dict(dict: &[u8]) -> Value {
        from_bytes(&Type::parse("a{sv}").unwrap(), dict).unwrap()
    }

    /// The keys of the dict, in order.
    fn keys(dict: &Value) -> Vec<String> {
        let Value::Array(items) = dict else {
            panic!("the dict is an array")
        };
        items
            .iter()
            .map(|item| match item {
                Value::Tuple(fields) => match &fields[0] {
                    Value::Str(key) => key.clone(),
                    other => panic!("a key {other:?}"),
                },
                other => panic!("an entry {other:?}"),
            })
            .collect()
    }

    /// The binding keys of the client are dropped, each occurrence. The other
    /// entries keep their order and their duplicates, the digest and the sizes
    /// come after the binding keys, and the ref binding is sorted with its
    /// duplicates. The bytes are the bytes of the dict as a value tree.
    #[test]
    fn the_metadata_has_the_order_of_commit() {
        let client = vec![
            entry(SIZES_KEY, text("sizes")),
            entry("b", text("1")),
            entry(REF_BINDING_KEY, text("x")),
            entry(COMPOSEFS_DIGEST_KEY, text("digest")),
            entry("a", text("2")),
            entry(COLLECTION_BINDING_KEY, text("y")),
            entry("b", text("3")),
            entry(REF_BINDING_KEY, text("z")),
        ];
        let refs = ["main", "v1", "alias", "main"];
        let bytes = server_commit_metadata(&client, &refs, Some("org.a")).unwrap();
        let dict = parse_dict(&bytes);
        assert_eq!(
            keys(&dict),
            [
                "b",
                "a",
                "b",
                REF_BINDING_KEY,
                COLLECTION_BINDING_KEY,
                COMPOSEFS_DIGEST_KEY,
                SIZES_KEY,
            ]
        );
        assert_eq!(dict.dict_get("b"), Some(&text("1")));
        let tree = |key: &str, value: Value| (key.to_owned(), value);
        let mut expected = ostrya_core::commit_metadata(
            [
                tree("b", text("1")),
                tree("a", text("2")),
                tree("b", text("3")),
            ],
            Some(&refs),
            Some("org.a"),
        );
        if let Value::Array(items) = &mut expected {
            for (key, value) in [(COMPOSEFS_DIGEST_KEY, "digest"), (SIZES_KEY, "sizes")] {
                items.push(Value::Tuple(vec![Value::Str(key.into()), text(value)]));
            }
        }
        assert_eq!(
            bytes,
            to_bytes(&Type::parse("a{sv}").unwrap(), &expected).unwrap()
        );
        let commit = Commit {
            metadata: dict,
            parent: None,
            related: Vec::new(),
            subject: String::new(),
            body: String::new(),
            timestamp: 0,
            root_dirtree: Checksum::from_bytes([1; 32]),
            root_dirmeta: Checksum::from_bytes([2; 32]),
        };
        let commit = Commit::parse(&commit.serialize().unwrap()).unwrap();
        assert_eq!(commit.ref_bindings(), ["alias", "main", "main", "v1"]);
        assert_eq!(commit.collection_binding(), Some("org.a"));
    }

    /// With no collection id, the dict holds no collection binding.
    #[test]
    fn no_collection_id_writes_no_collection_binding() {
        let bytes = server_commit_metadata(&[entry("k", text("v"))], &["main"], None).unwrap();
        assert_eq!(keys(&parse_dict(&bytes)), ["k", REF_BINDING_KEY]);
    }

    /// The commit takes the tip as its parent, and none with `orphan`. The
    /// bound names are the branch, each tag, and each bound name.
    #[test]
    fn the_commit_takes_the_tip_unless_orphan() {
        let tip = Checksum::from_bytes([7; 32]);
        let mut sc = ServerCommit {
            branch: "main".into(),
            tags: vec!["v1".into()],
            bind_refs: vec!["alias".into()],
            root_dirtree: Checksum::from_bytes([1; 32]),
            root_dirmeta: Checksum::from_bytes([2; 32]),
            subject: "s".into(),
            body: "b".into(),
            metadata: vec![entry("k", text("v"))],
            timestamp: None,
            orphan: false,
        };
        let commit =
            Commit::parse(&commit_bytes(&sc, Some(tip), 42, Some("org.a")).unwrap()).unwrap();
        assert_eq!(commit.parent, Some(tip));
        assert_eq!(commit.timestamp, 42);
        assert_eq!((commit.subject.as_str(), commit.body.as_str()), ("s", "b"));
        assert_eq!(commit.ref_bindings(), ["alias", "main", "v1"]);
        assert_eq!(commit.collection_binding(), Some("org.a"));
        assert_eq!(commit.metadata.dict_get("k"), Some(&text("v")));
        sc.orphan = true;
        let commit = Commit::parse(&commit_bytes(&sc, Some(tip), 42, None).unwrap()).unwrap();
        assert_eq!(commit.parent, None);
        assert_eq!(commit.collection_binding(), None);
    }
}
