//! The union merge of an incoming detached-metadata dict into the dict the
//! receiving repository holds for the same commit.

use std::collections::{HashMap, HashSet};

use ostrya_core::{ArrayIter, GvDecode, Type, Value, VariantBytes};

use crate::error::{Error, Result};

/// The detached-metadata keys whose value is a list of signatures, each an
/// `aay`. The merge takes the union of the stored list and the incoming list
/// under these keys.
///
/// The list does not depend on the engines this build has, so a build without
/// `sign-spki` keeps the stored `ostree.sign.spki` signatures and adds the
/// incoming ones.
pub(crate) const SIGNATURE_KEYS: [&str; 4] = [
    "ostree.gpgsigs",
    "ostree.sign.ed25519",
    "ostree.sign.spki",
    "ostree.sign.dummy",
];

/// The GVariant type of a signature list.
const SIGNATURE_ARRAY: &str = "aay";
/// How a refusal names each input.
const INCOMING: &str = "the incoming detached metadata";
const STORED: &str = "the stored detached metadata";

/// Merge the `a{sv}` dict `incoming` into `stored`, the dict the repository
/// holds for the same commit, and give the merged dict.
///
/// `stored` is `None` where the repository holds no detached metadata for the
/// commit, or holds the zero-length "no metadata" marker. The merged dict has
/// the stored keys first, in the stored order, and then each key only the
/// incoming dict holds, in the incoming order.
///
/// - Under a key of [`SIGNATURE_KEYS`], the value is the union of the two
///   lists: the stored blobs in the stored order, then each incoming blob that
///   is not byte-equal to a blob already in the list. A duplicate the stored
///   list already holds stays as it is.
/// - Under any other key, the incoming value replaces the stored value, at the
///   position of the stored key.
/// - A key only the stored dict holds stays.
///
/// Refused as [`Error::InvalidFormat`]: an input that is not an array of
/// `{sv}` entries, an incoming dict that holds one key twice, and a value under
/// a signature key that is not an `aay`, on either side. The type of a
/// signature value is checked, so a stored list the merge cannot extend is
/// refused and not replaced.
///
/// The merged dict can be larger than either input. The caller refuses a
/// merged dict whose serialized form is over
/// [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) before it writes it. This
/// function applies no `detached-metadata-exclude` filter: the caller filters
/// the incoming dict first.
///
/// The merge moves the entries and the blobs of both inputs into the merged
/// dict and copies no blob. Its time is linear in the number of keys and
/// blobs of the two inputs.
pub(crate) fn merge_detached(stored: Option<Value>, incoming: Value) -> Result<Value> {
    let incoming = dict_entries(incoming, INCOMING)?;
    let mut seen = HashSet::with_capacity(incoming.len());
    for (key, _) in &incoming {
        if !seen.insert(key.as_str()) {
            return Err(Error::InvalidFormat(format!(
                "the incoming detached metadata holds the key '{key}' more than once"
            )));
        }
    }
    drop(seen);
    let mut merged = match stored {
        Some(stored) => dict_entries(stored, STORED)?,
        None => Vec::new(),
    };
    // The position of each stored key in `merged`. A key the stored dict holds
    // twice maps to its first entry. The incoming keys are distinct, so the
    // loop never looks up a key that it appends.
    let mut positions: HashMap<String, usize> = HashMap::with_capacity(merged.len());
    for (position, (key, _)) in merged.iter().enumerate() {
        positions.entry(key.clone()).or_insert(position);
    }
    for (key, value) in incoming {
        let signatures = SIGNATURE_KEYS.contains(&key.as_str());
        match positions.get(&key) {
            Some(&position) if signatures => {
                let list = signature_list(&mut merged[position].1, &key, STORED)?;
                union(list, signature_blobs(value, &key, INCOMING)?);
            }
            Some(&position) => merged[position].1 = value,
            None if signatures => {
                let mut list = Vec::new();
                union(&mut list, signature_blobs(value, &key, INCOMING)?);
                merged.push((key, signature_value(list)?));
            }
            None => merged.push((key, value)),
        }
    }
    Ok(Value::Array(
        merged
            .into_iter()
            .map(|(key, value)| Value::Tuple(vec![Value::Str(key), value]))
            .collect(),
    ))
}

/// Check, building no value, that [`merge_detached`] takes the serialized
/// dict `bytes` as its incoming dict: an `a{sv}` in normal form that holds
/// each key once, with an `aay` under each key of [`SIGNATURE_KEYS`].
///
/// The check applies the limits of the parser, and its memory grows with the
/// number of keys alone. Refused as [`Error::InvalidFormat`].
pub(crate) fn check_incoming(bytes: &[u8]) -> Result<()> {
    let mut seen = HashSet::new();
    for entry in entries_in_place(bytes, INCOMING)? {
        let (key, value) = entry.map_err(|e| not_a_dict(INCOMING, e))?;
        if !seen.insert(key) {
            return Err(Error::InvalidFormat(format!(
                "the incoming detached metadata holds the key '{key}' more than once"
            )));
        }
        if SIGNATURE_KEYS.contains(&key) && value.signature() != SIGNATURE_ARRAY {
            return Err(not_aay(key, INCOMING));
        }
    }
    Ok(())
}

/// The keys of [`SIGNATURE_KEYS`] that `bytes`, a serialized incoming dict,
/// holds, as one flag for each key, in the order of the list. A dict that is
/// not an `a{sv}` in normal form is refused as [`Error::InvalidFormat`].
pub(crate) fn signature_keys_in(bytes: &[u8]) -> Result<[bool; SIGNATURE_KEYS.len()]> {
    let mut held = [false; SIGNATURE_KEYS.len()];
    for entry in entries_in_place(bytes, INCOMING)? {
        let (key, _) = entry.map_err(|e| not_a_dict(INCOMING, e))?;
        if let Some(i) = SIGNATURE_KEYS.iter().position(|k| *k == key) {
            held[i] = true;
        }
    }
    Ok(held)
}

/// Check, building no value, that an edit accepts `stored`, the serialized
/// dict the repository holds: an `a{sv}` in normal form whose first entry
/// under each key of [`SIGNATURE_KEYS`] that `touched` flags holds an `aay`.
/// A key is touched when the incoming dict holds it or a signature is
/// appended under it, which are the two steps that extend the stored list.
///
/// This is the refusal of [`merge_detached`] and of the signature append for
/// the stored dict, so an edit that passes the check does not fail on the
/// stored dict at the write. Refused as [`Error::InvalidFormat`].
pub(crate) fn check_stored(stored: &[u8], touched: [bool; SIGNATURE_KEYS.len()]) -> Result<()> {
    let mut checked = [false; SIGNATURE_KEYS.len()];
    for entry in entries_in_place(stored, STORED)? {
        let (key, value) = entry.map_err(|e| not_a_dict(STORED, e))?;
        if let Some(i) = SIGNATURE_KEYS.iter().position(|k| *k == key)
            && touched[i]
            && !std::mem::replace(&mut checked[i], true)
            && value.signature() != SIGNATURE_ARRAY
        {
            return Err(not_aay(key, STORED));
        }
    }
    Ok(())
}

/// The `{sv}` entries of the serialized dict `bytes`, read in place after a
/// check of the whole dict. `subject` names the dict in a refusal.
fn entries_in_place<'a>(
    bytes: &'a [u8],
    subject: &str,
) -> Result<ArrayIter<'a, (&'a str, VariantBytes<'a>)>> {
    let ty = Type::parse("a{sv}").map_err(ostrya_core::Error::from)?;
    ostrya_core::validate(&ty, bytes).map_err(|e| not_a_dict(subject, e))?;
    ArrayIter::decode(bytes).map_err(|e| not_a_dict(subject, e))
}

/// The refusal of a dict that is not an `a{sv}` in normal form.
fn not_a_dict(subject: &str, e: impl std::fmt::Display) -> Error {
    Error::InvalidFormat(format!("{subject} is not a dict `a{{sv}}`: {e}"))
}

/// The `{sv}` entries of an `a{sv}` dict, each as its key and its variant,
/// moved out of the dict. `subject` names the dict in a refusal.
fn dict_entries(dict: Value, subject: &str) -> Result<Vec<(String, Value)>> {
    let Value::Array(entries) = dict else {
        return Err(Error::InvalidFormat(format!("{subject} is not a dict")));
    };
    entries
        .into_iter()
        .map(|entry| {
            if let Value::Tuple(fields) = entry
                && let Ok([Value::Str(key), value @ Value::Variant(_)]) =
                    <[Value; 2]>::try_from(fields)
            {
                return Ok((key, value));
            }
            Err(Error::InvalidFormat(format!(
                "{subject} holds an entry that is not `{{sv}}`"
            )))
        })
        .collect()
}

/// The refusal of a signature value that is not an `aay`. `subject` names the
/// dict the value comes from.
fn not_aay(key: &str, subject: &str) -> Error {
    Error::InvalidFormat(format!(
        "{subject} holds '{key}' as a value that is not `aay`"
    ))
}

/// The blobs of one signature list, a variant holding an `aay`, for the merge
/// to extend in place.
fn signature_list<'a>(
    value: &'a mut Value,
    key: &str,
    subject: &str,
) -> Result<&'a mut Vec<Value>> {
    if let Value::Variant(inner) = value
        && inner.0.signature() == SIGNATURE_ARRAY
        && let Value::Array(blobs) = &mut inner.1
        && blobs.iter().all(|blob| matches!(blob, Value::Bytes(_)))
    {
        return Ok(blobs);
    }
    Err(not_aay(key, subject))
}

/// The blobs of one signature list, a variant holding an `aay`, moved out of
/// the value.
fn signature_blobs(value: Value, key: &str, subject: &str) -> Result<Vec<Vec<u8>>> {
    if let Value::Variant(inner) = value
        && let (ty, Value::Array(blobs)) = *inner
        && ty.signature() == SIGNATURE_ARRAY
    {
        return blobs
            .into_iter()
            .map(|blob| match blob {
                Value::Bytes(bytes) => Ok(bytes),
                _ => Err(not_aay(key, subject)),
            })
            .collect();
    }
    Err(not_aay(key, subject))
}

/// Append to `list` each blob of `incoming` that no blob of `list` equals
/// byte for byte, in the incoming order. A duplicate `list` already holds
/// stays as it is.
fn union(list: &mut Vec<Value>, incoming: Vec<Vec<u8>>) {
    let fresh: Vec<bool> = {
        let mut seen: HashSet<&[u8]> = list
            .iter()
            .filter_map(|blob| match blob {
                Value::Bytes(bytes) => Some(bytes.as_slice()),
                _ => None,
            })
            .collect();
        incoming.iter().map(|blob| seen.insert(blob)).collect()
    };
    list.extend(
        incoming
            .into_iter()
            .zip(fresh)
            .filter_map(|(blob, fresh)| fresh.then_some(Value::Bytes(blob))),
    );
}

/// A signature list as the variant a dict entry holds.
fn signature_value(list: Vec<Value>) -> Result<Value> {
    let ty = Type::parse(SIGNATURE_ARRAY).map_err(ostrya_core::Error::from)?;
    Ok(Value::variant(ty, Value::Array(list)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signature list of `blobs`.
    fn sigs(blobs: &[&[u8]]) -> Value {
        signature_value(
            blobs
                .iter()
                .map(|blob| Value::Bytes(blob.to_vec()))
                .collect(),
        )
        .unwrap()
    }

    /// A `u` value, which stands for any key that is not a signature list.
    fn number(n: u32) -> Value {
        Value::variant(Type::parse("u").unwrap(), Value::U32(n))
    }

    /// An `a{sv}` dict of `entries`, in order.
    fn dict(entries: Vec<(&str, Value)>) -> Value {
        Value::Array(
            entries
                .into_iter()
                .map(|(key, value)| Value::Tuple(vec![Value::Str(key.to_owned()), value]))
                .collect(),
        )
    }

    /// The keys of a dict, in order.
    fn keys(dict: &Value) -> Vec<String> {
        dict_entries(dict.clone(), "the dict")
            .unwrap()
            .into_iter()
            .map(|(key, _)| key)
            .collect()
    }

    /// The blobs under `key`.
    fn blobs(dict: &Value, key: &str) -> Vec<Vec<u8>> {
        crate::sign::signatures_for(dict, key)
    }

    const ED: &str = "ostree.sign.ed25519";

    /// A stored signature A and an incoming signature B give [A, B].
    #[test]
    fn a_stored_and_an_incoming_signature_give_both() {
        let merged = merge_detached(
            Some(dict(vec![(ED, sigs(&[b"A"]))])),
            dict(vec![(ED, sigs(&[b"B"]))]),
        )
        .unwrap();
        assert_eq!(blobs(&merged, ED), [b"A".to_vec(), b"B".to_vec()]);
    }

    /// An incoming signature byte-equal to a stored one is not added twice.
    #[test]
    fn a_byte_equal_signature_is_added_once() {
        let merged = merge_detached(
            Some(dict(vec![(ED, sigs(&[b"A"]))])),
            dict(vec![(ED, sigs(&[b"A", b"B"]))]),
        )
        .unwrap();
        assert_eq!(blobs(&merged, ED), [b"A".to_vec(), b"B".to_vec()]);

        let merged = merge_detached(
            Some(dict(vec![(ED, sigs(&[b"A"]))])),
            dict(vec![(ED, sigs(&[b"B", b"B"]))]),
        )
        .unwrap();
        assert_eq!(blobs(&merged, ED), [b"A".to_vec(), b"B".to_vec()]);

        // A duplicate the stored list holds stays as it is.
        let merged = merge_detached(
            Some(dict(vec![(ED, sigs(&[b"A", b"A"]))])),
            dict(vec![(ED, sigs(&[b"A"]))]),
        )
        .unwrap();
        assert_eq!(blobs(&merged, ED), [b"A".to_vec(), b"A".to_vec()]);
    }

    /// Every signature key takes the union, also one this build has no engine
    /// for.
    #[test]
    fn every_signature_key_takes_the_union() {
        for key in SIGNATURE_KEYS {
            let merged = merge_detached(
                Some(dict(vec![(key, sigs(&[b"A"]))])),
                dict(vec![(key, sigs(&[b"B"]))]),
            )
            .unwrap();
            assert_eq!(blobs(&merged, key), [b"A".to_vec(), b"B".to_vec()], "{key}");
        }
    }

    /// Another key takes the incoming value at the stored position, a key only
    /// the stored dict holds stays, and a key only the incoming dict holds
    /// comes after the stored keys, in the incoming order.
    #[test]
    fn other_keys_take_the_incoming_value() {
        let stored = dict(vec![
            ("x", number(1)),
            (ED, sigs(&[b"A"])),
            ("kept", number(7)),
        ]);
        let incoming = dict(vec![
            ("new.b", number(3)),
            ("x", number(2)),
            ("ostree.gpgsigs", sigs(&[b"G", b"G"])),
            ("new.a", number(4)),
        ]);
        let merged = merge_detached(Some(stored), incoming).unwrap();
        assert_eq!(
            keys(&merged),
            ["x", ED, "kept", "new.b", "ostree.gpgsigs", "new.a"]
        );
        assert_eq!(merged.dict_get("x"), Some(&number(2)));
        assert_eq!(merged.dict_get("kept"), Some(&number(7)));
        assert_eq!(blobs(&merged, ED), [b"A".to_vec()]);
        assert_eq!(blobs(&merged, "ostree.gpgsigs"), [b"G".to_vec()]);
    }

    /// With no stored dict, the merge gives the incoming dict.
    #[test]
    fn no_stored_dict_gives_the_incoming_dict() {
        let incoming = dict(vec![(ED, sigs(&[b"A"])), ("x", number(1))]);
        let merged = merge_detached(None, incoming.clone()).unwrap();
        assert_eq!(merged, incoming);
    }

    /// The merged dict serializes as an `a{sv}` and reads back the same.
    #[test]
    fn the_merged_dict_serializes() {
        let merged = merge_detached(
            Some(dict(vec![(ED, sigs(&[b"A"]))])),
            dict(vec![(ED, sigs(&[b"B"])), ("x", number(1))]),
        )
        .unwrap();
        let bytes = crate::summary::serialize_signature_dict(&merged).unwrap();
        let back = crate::summary::parse_signature_dict(&bytes)
            .unwrap()
            .unwrap();
        assert_eq!(back, merged);
    }

    /// Each malformed input is refused by what is wrong with it.
    #[test]
    fn malformed_inputs_are_refused() {
        let refused = |stored: Option<Value>, incoming: Value, part: &str| {
            let err = merge_detached(stored, incoming).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidFormat(m) if m.contains(part)),
                "{err}"
            );
        };
        // A signature value that is not `aay`, on either side.
        refused(None, dict(vec![(ED, number(1))]), "not `aay`");
        refused(
            Some(dict(vec![(ED, number(1))])),
            dict(vec![(ED, sigs(&[b"A"]))]),
            "the stored detached metadata holds",
        );
        let as_strings = Value::variant(
            Type::parse("as").unwrap(),
            Value::Array(vec![Value::Str("A".into())]),
        );
        refused(None, dict(vec![(ED, as_strings)]), "not `aay`");
        // Not a dict, and an entry that is not `{sv}`.
        refused(None, Value::U32(1), "is not a dict");
        refused(
            None,
            Value::Array(vec![Value::Tuple(vec![
                Value::Str("x".into()),
                Value::U32(1),
            ])]),
            "not `{sv}`",
        );
        // A key the incoming dict holds twice.
        refused(
            None,
            dict(vec![("x", number(1)), ("x", number(2))]),
            "more than once",
        );
    }
}
