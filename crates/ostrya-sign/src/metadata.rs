//! The signature arrays of a detached-metadata dict.

use ostrya_core::{Type, Value};

use crate::{Error, Result};

/// The GVariant type of a per-engine signature array in the detached-metadata
/// dict: an array of signature blobs.
const SIGNATURE_ARRAY_SIGNATURE: &str = "aay";

/// Append `signature` to the `metadata_key` engine's `aay` array in the `a{sv}`
/// dict `dict`, creating the entry when absent and preserving insertion order.
/// Other entries, including other engines' signature arrays, are left in place.
pub fn append_signature(dict: &mut Value, metadata_key: &str, signature: Vec<u8>) -> Result<()> {
    let entries = match dict {
        Value::Array(entries) => entries,
        _ => {
            return Err(Error::InvalidFormat(
                "detached metadata must be an a{sv} dict".into(),
            ));
        }
    };
    for entry in entries.iter_mut() {
        if let Value::Tuple(fields) = entry
            && let [key, value] = fields.as_mut_slice()
            && key.as_str() == Some(metadata_key)
        {
            return push_blob(value, signature);
        }
    }
    let array_type = Type::parse(SIGNATURE_ARRAY_SIGNATURE).map_err(ostrya_core::Error::from)?;
    let value = Value::variant(array_type, Value::Array(vec![Value::Bytes(signature)]));
    entries.push(Value::Tuple(vec![
        Value::Str(metadata_key.to_owned()),
        value,
    ]));
    Ok(())
}

/// Push a signature blob onto an existing engine value, an `aay` wrapped in the
/// `a{sv}` variant.
fn push_blob(value: &mut Value, signature: Vec<u8>) -> Result<()> {
    let array = match value {
        Value::Variant(inner) => &mut inner.1,
        other => other,
    };
    match array {
        Value::Array(blobs) => {
            blobs.push(Value::Bytes(signature));
            Ok(())
        }
        _ => Err(Error::InvalidFormat(
            "detached-metadata signature value is not an array".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The blobs stored under `key` in the dict, read through the variant.
    fn blobs(dict: &Value, key: &str) -> Vec<Vec<u8>> {
        let (ty, inner) = dict.dict_get(key).unwrap().as_variant().unwrap();
        assert_eq!(ty.signature(), SIGNATURE_ARRAY_SIGNATURE);
        inner
            .as_array()
            .unwrap()
            .iter()
            .map(|blob| blob.as_bytes().unwrap().to_vec())
            .collect()
    }

    #[test]
    fn a_new_engine_entry_is_an_aay_variant() {
        let mut dict = Value::Array(Vec::new());
        append_signature(&mut dict, "ostree.sign.dummy", b"one".to_vec()).unwrap();
        assert_eq!(blobs(&dict, "ostree.sign.dummy"), [b"one".to_vec()]);
    }

    #[test]
    fn an_existing_entry_is_appended_and_other_engines_kept() {
        let mut dict = Value::Array(Vec::new());
        append_signature(&mut dict, "ostree.sign.dummy", b"one".to_vec()).unwrap();
        append_signature(&mut dict, "ostree.sign.ed25519", b"other".to_vec()).unwrap();
        append_signature(&mut dict, "ostree.sign.dummy", b"two".to_vec()).unwrap();
        assert_eq!(
            blobs(&dict, "ostree.sign.dummy"),
            [b"one".to_vec(), b"two".to_vec()]
        );
        assert_eq!(blobs(&dict, "ostree.sign.ed25519"), [b"other".to_vec()]);
        let keys: Vec<&str> = dict
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_tuple().unwrap()[0].as_str().unwrap())
            .collect();
        assert_eq!(keys, ["ostree.sign.dummy", "ostree.sign.ed25519"]);
    }

    #[test]
    fn a_dict_of_another_shape_is_refused() {
        let mut dict = Value::Str("not a dict".into());
        let err = append_signature(&mut dict, "ostree.sign.dummy", b"one".to_vec()).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
    }

    #[test]
    fn an_engine_value_that_is_not_an_array_is_refused() {
        let mut dict = Value::Array(vec![Value::Tuple(vec![
            Value::Str("ostree.sign.dummy".into()),
            Value::variant(Type::parse("s").unwrap(), Value::Str("x".into())),
        ])]);
        let err = append_signature(&mut dict, "ostree.sign.dummy", b"one".to_vec()).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
    }
}
