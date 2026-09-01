//! Ordered `a{sv}` dict construction.

use crate::{Type, Value};

/// Builds an `a{sv}` dict value one entry at a time.
///
/// An `a{sv}` is an array of key-value tuples whose value member is a variant,
/// so the dict holds whatever order its writer produced. The builder appends,
/// and [`build`](DictBuilder::build) hands back the entries in insertion order.
/// A key inserted twice yields two entries of that name, which the commit
/// metadata dict allows (`docs/format-reference.md`, "Commit").
///
/// Every insert returns `&mut Self`, so a chain of them reads as the dict it
/// produces:
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
    /// An empty dict.
    pub fn new() -> DictBuilder {
        DictBuilder {
            entries: Vec::new(),
        }
    }

    /// Append `key` holding `value` of type `ty`, wrapped as the `v` the dict's
    /// value member carries.
    pub fn insert(&mut self, key: &str, ty: Type, value: Value) -> &mut Self {
        self.entries.push(Value::Tuple(vec![
            Value::Str(key.to_owned()),
            Value::variant(ty, value),
        ]));
        self
    }

    /// Append `key` holding an `s`.
    pub fn insert_str(&mut self, key: &str, value: &str) -> &mut Self {
        self.insert(key, Type::Str, Value::Str(value.to_owned()))
    }

    /// Append `key` holding a `t`.
    pub fn insert_u64(&mut self, key: &str, value: u64) -> &mut Self {
        self.insert(key, Type::U64, Value::U64(value))
    }

    /// Append `key` holding a `b`.
    pub fn insert_bool(&mut self, key: &str, value: bool) -> &mut Self {
        self.insert(key, Type::Bool, Value::Bool(value))
    }

    /// Append `key` holding an `as`.
    pub fn insert_strv(&mut self, key: &str, values: &[String]) -> &mut Self {
        let items = values.iter().map(|v| Value::Str(v.clone())).collect();
        self.insert(key, Type::Array(Box::new(Type::Str)), Value::Array(items))
    }

    /// Append `key` holding an `ay`.
    pub fn insert_bytes(&mut self, key: &str, value: &[u8]) -> &mut Self {
        self.insert(
            key,
            Type::Array(Box::new(Type::Byte)),
            Value::Bytes(value.to_vec()),
        )
    }

    /// The assembled `a{sv}`, its entries in insertion order.
    pub fn build(self) -> Value {
        Value::Array(self.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{from_bytes, to_bytes};

    /// The `a{sv}` signature the commit metadata dict and its relatives carry.
    fn dict_type() -> Type {
        Type::parse("a{sv}").unwrap()
    }

    fn entry(key: &str, ty: Type, value: Value) -> Value {
        Value::Tuple(vec![Value::Str(key.to_owned()), Value::variant(ty, value)])
    }

    /// A dict the builder produces equals, value for value and byte for byte,
    /// the same dict assembled by hand out of `Value::Array` and `Value::Tuple`.
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

    /// The serialized dict holds the keys in the order they were inserted, and
    /// a parse of those bytes gives that order back, value model included: an
    /// `ay` parses back as [`Value::Bytes`] and an `as` as an array of strings,
    /// which are the spellings the builder produces.
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

    /// A key inserted twice stands twice, and a lookup by name reads the first.
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
