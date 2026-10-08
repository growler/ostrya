//! The builder of `a{sv}` dict values, `DictBuilder`.

use crate::{Type, Value};

/// A builder for an `a{sv}` dict value.
///
/// An `a{sv}` is an array of key-value tuples. The value member of each tuple
/// is a variant. Because the dict is an array, it keeps the entry order that
/// its writer gives it.
///
/// The builder appends each entry. [`build`](DictBuilder::build) returns the
/// entries in insertion order. If the caller inserts a key twice, the dict
/// holds two entries with that key. The commit metadata dict of ostree
/// accepts two entries with one key.
///
/// Each insert method returns `&mut Self`, so a chain of inserts reads as the
/// dict that it produces.
///
/// # Examples
///
/// ```
/// use ostrya_gvariant::DictBuilder;
///
/// let mut builder = DictBuilder::new();
/// builder
///     .insert_str("version", "1")
///     .insert_bool("ostree.bootable", true);
/// let dict = builder.build();
/// let (_, version) = dict.dict_get("version").unwrap().as_variant().unwrap();
/// assert_eq!(version.as_str(), Some("1"));
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DictBuilder {
    entries: Vec<Value>,
}

impl DictBuilder {
    /// Creates a builder that holds an empty dict.
    pub fn new() -> DictBuilder {
        DictBuilder {
            entries: Vec::new(),
        }
    }

    /// Appends the entry `key` with `value` of type `ty`.
    ///
    /// The builder wraps `value` in a `v`, which is the type of the value
    /// member of the dict. The builder does not check `value` against `ty`.
    /// If they do not match, [`to_bytes`] returns [`Error::TypeMismatch`].
    ///
    /// [`to_bytes`]: crate::to_bytes
    /// [`Error::TypeMismatch`]: crate::Error::TypeMismatch
    pub fn insert(&mut self, key: &str, ty: Type, value: Value) -> &mut Self {
        self.entries.push(Value::Tuple(vec![
            Value::Str(key.to_owned()),
            Value::variant(ty, value),
        ]));
        self
    }

    /// Appends the entry `key` with an `s` value.
    pub fn insert_str(&mut self, key: &str, value: &str) -> &mut Self {
        self.insert(key, Type::Str, Value::Str(value.to_owned()))
    }

    /// Appends the entry `key` with a `t` value.
    pub fn insert_u64(&mut self, key: &str, value: u64) -> &mut Self {
        self.insert(key, Type::U64, Value::U64(value))
    }

    /// Appends the entry `key` with a `b` value.
    pub fn insert_bool(&mut self, key: &str, value: bool) -> &mut Self {
        self.insert(key, Type::Bool, Value::Bool(value))
    }

    /// Appends the entry `key` with an `as` value.
    pub fn insert_strv(&mut self, key: &str, values: &[String]) -> &mut Self {
        let items = values.iter().map(|v| Value::Str(v.clone())).collect();
        self.insert(key, Type::Array(Box::new(Type::Str)), Value::Array(items))
    }

    /// Appends the entry `key` with an `ay` value.
    pub fn insert_bytes(&mut self, key: &str, value: &[u8]) -> &mut Self {
        self.insert(
            key,
            Type::Array(Box::new(Type::Byte)),
            Value::Bytes(value.to_vec()),
        )
    }

    /// Returns the assembled `a{sv}` with its entries in insertion order.
    pub fn build(self) -> Value {
        Value::Array(self.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{from_bytes, to_bytes};

    /// Returns the `a{sv}` type of the commit metadata dict and of related
    /// dicts.
    fn dict_type() -> Type {
        Type::parse("a{sv}").unwrap()
    }

    fn entry(key: &str, ty: Type, value: Value) -> Value {
        Value::Tuple(vec![Value::Str(key.to_owned()), Value::variant(ty, value)])
    }

    /// A dict from the builder equals the same dict that the test assembles by
    /// hand from `Value::Array` and `Value::Tuple`. The test compares the
    /// values and the serialized bytes.
    #[test]
    fn builds_the_hand_assembled_value() {
        let mut builder = DictBuilder::new();
        builder
            .insert_str("s", "text")
            .insert_u64("t", 7)
            .insert_bool("b", true)
            .insert_strv("as", &["one".to_owned(), "two".to_owned()])
            .insert_bytes("ay", &[0xde, 0xad])
            .insert("v", Type::U32, Value::U32(3));
        let built = builder.build();

        let hand = Value::Array(vec![
            entry("s", Type::Str, Value::Str("text".to_owned())),
            entry("t", Type::U64, Value::U64(7)),
            entry("b", Type::Bool, Value::Bool(true)),
            entry(
                "as",
                Type::Array(Box::new(Type::Str)),
                Value::Array(vec![
                    Value::Str("one".to_owned()),
                    Value::Str("two".to_owned()),
                ]),
            ),
            entry(
                "ay",
                Type::Array(Box::new(Type::Byte)),
                Value::Bytes(vec![0xde, 0xad]),
            ),
            entry("v", Type::U32, Value::U32(3)),
        ]);

        assert_eq!(built, hand);
        let ty = dict_type();
        assert_eq!(
            to_bytes(&ty, &built).unwrap(),
            to_bytes(&ty, &hand).unwrap()
        );
    }

    /// The serialized dict holds the keys in insertion order. A parse of those
    /// bytes returns the same order and the same value model. An `ay` parses
    /// back as [`Value::Bytes`], and an `as` parses back as an array of
    /// strings. The builder produces these same forms.
    #[test]
    fn round_trips_with_insertion_order_intact() {
        let mut builder = DictBuilder::new();
        builder
            .insert_str("zulu", "z")
            .insert_bytes("alpha", &[0xde, 0xad])
            .insert_strv("mike", &["one".to_owned(), "two".to_owned()]);
        let dict = builder.build();

        let ty = dict_type();
        let bytes = to_bytes(&ty, &dict).unwrap();
        let parsed = from_bytes(&ty, &bytes).unwrap();
        assert_eq!(parsed, dict);

        let keys: Vec<&str> = parsed
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_tuple().unwrap()[0].as_str().unwrap())
            .collect();
        assert_eq!(keys, ["zulu", "alpha", "mike"]);
    }

    /// If the builder inserts a key twice, the dict holds two entries for it.
    /// A lookup by name returns the first entry.
    #[test]
    fn keeps_a_repeated_key() {
        let mut builder = DictBuilder::new();
        builder.insert_str("k", "first").insert_str("k", "second");
        let dict = builder.build();

        assert_eq!(dict.as_array().unwrap().len(), 2);
        let (_, first) = dict.dict_get("k").unwrap().as_variant().unwrap();
        assert_eq!(first.as_str(), Some("first"));
    }

    /// An empty builder produces the empty dict.
    #[test]
    fn builds_an_empty_dict() {
        assert_eq!(DictBuilder::new().build(), Value::Array(Vec::new()));
    }
}
