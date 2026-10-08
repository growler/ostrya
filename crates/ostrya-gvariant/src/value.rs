use crate::Type;

/// A dynamically typed GVariant value.
///
/// The representation is canonical for a [`Type`]:
///
/// - A byte array (`ay`) is [`Value::Bytes`]. The canonical form holds no
///   [`Value::Array`] of [`Value::Byte`].
/// - A dict entry is a two-element [`Value::Tuple`].
/// - A [`Value::Variant`] carries the type of its child, because the
///   serialized form embeds the signature of the child.
/// - A double is its IEEE-754 bit pattern, so a value compares by the bytes
///   that it serializes to.
/// - An object path (`o`) and a signature (`g`) are [`Value::Str`]. A handle
///   (`h`) is [`Value::I32`]. The [`Type`] states which of these types a
///   value carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `b`.
    Bool(bool),
    /// `y`.
    Byte(u8),
    /// `n`.
    I16(i16),
    /// `q`.
    U16(u16),
    /// `i` or `h`.
    I32(i32),
    /// `u`.
    U32(u32),
    /// `x`.
    I64(i64),
    /// `t`.
    U64(u64),
    /// The IEEE-754 bit pattern of a `d` value, as [`Value::double`] creates it.
    Double(u64),
    /// `s`, `o`, or `g`.
    Str(String),
    /// `ay`, held as its bytes.
    Bytes(Vec<u8>),
    /// `m<T>`: the value it holds, or `None` for `nothing`.
    Maybe(Option<Box<Value>>),
    /// `a<T>`: the elements, in order.
    Array(Vec<Value>),
    /// `(...)` or a dict entry.
    Tuple(Vec<Value>),
    /// `v`: the type of the child and the child.
    Variant(Box<(Type, Value)>),
}

impl Value {
    /// Creates a variant that holds `value` of type `ty`.
    pub fn variant(ty: Type, value: Value) -> Value {
        Value::Variant(Box::new((ty, value)))
    }

    /// Creates a `d` value from an `f64`.
    pub fn double(value: f64) -> Value {
        Value::Double(value.to_bits())
    }

    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Value::Bool(_) => "bool",
            Value::Byte(_) => "byte",
            Value::I16(_) => "i16",
            Value::U16(_) => "u16",
            Value::I32(_) => "i32",
            Value::U32(_) => "u32",
            Value::I64(_) => "i64",
            Value::U64(_) => "u64",
            Value::Double(_) => "double",
            Value::Str(_) => "string",
            Value::Bytes(_) => "byte array",
            Value::Maybe(_) => "maybe",
            Value::Array(_) => "array",
            Value::Tuple(_) => "tuple",
            Value::Variant(_) => "variant",
        }
    }

    /// Returns the `b` that this value holds, or `None` for any other type.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the `y` that this value holds, or `None` for any other type.
    pub fn as_byte(&self) -> Option<u8> {
        match self {
            Value::Byte(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the `u` that this value holds, or `None` for any other type.
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Value::U32(x) => Some(*x),
            _ => None,
        }
    }

    /// Returns the `t` that this value holds, or `None` for any other type.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(x) => Some(*x),
            _ => None,
        }
    }

    /// Returns the string that this value holds, or `None` for any other type.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the byte array that this value holds, or `None` for any other type.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Returns the elements of this array value, or `None` for any other type.
    ///
    /// A byte array (`ay`) is a [`Value::Bytes`], so this method returns `None`
    /// for it. [`as_bytes`](Value::as_bytes) returns its bytes.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the strings of this array value, or `None` for any other type.
    ///
    /// If one element is not a string, the result is `None` for the whole
    /// array. The empty array yields the empty list.
    pub fn as_strv(&self) -> Option<Vec<&str>> {
        self.as_array()?.iter().map(Value::as_str).collect()
    }

    /// Returns the members of this tuple value, or `None` for any other type.
    pub fn as_tuple(&self) -> Option<&[Value]> {
        match self {
            Value::Tuple(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the type and the child of this variant, or `None` for any other type.
    pub fn as_variant(&self) -> Option<(&Type, &Value)> {
        match self {
            Value::Variant(inner) => Some((&inner.0, &inner.1)),
            _ => None,
        }
    }

    /// Returns a copy of the value with each multi-byte scalar byte-swapped.
    ///
    /// The swap recurses through arrays, maybes, tuples, dict entries, and the
    /// child of a variant. Booleans, bytes, strings, and byte arrays stay
    /// unchanged.
    ///
    /// The method is the byte-order conversion of GVariant itself. The ostree
    /// on-disk format stores some numeric fields big-endian inside the
    /// little-endian framing, so [`from_bytes`] returns each of them
    /// byte-reversed. One swap of the whole tree recovers the numbers that
    /// the fields state. [`to_bytes`] lists these fields.
    ///
    /// [`from_bytes`]: crate::from_bytes
    /// [`to_bytes`]: crate::to_bytes
    pub fn byteswapped(&self) -> Value {
        match self {
            Value::I16(x) => Value::I16(x.swap_bytes()),
            Value::U16(x) => Value::U16(x.swap_bytes()),
            Value::I32(x) => Value::I32(x.swap_bytes()),
            Value::U32(x) => Value::U32(x.swap_bytes()),
            Value::I64(x) => Value::I64(x.swap_bytes()),
            Value::U64(x) => Value::U64(x.swap_bytes()),
            Value::Double(bits) => Value::Double(bits.swap_bytes()),
            Value::Maybe(inner) => Value::Maybe(inner.as_ref().map(|v| Box::new(v.byteswapped()))),
            Value::Array(items) => Value::Array(items.iter().map(Value::byteswapped).collect()),
            Value::Tuple(items) => Value::Tuple(items.iter().map(Value::byteswapped).collect()),
            Value::Variant(inner) => {
                let (ty, child) = &**inner;
                Value::variant(ty.clone(), child.byteswapped())
            }
            Value::Bool(_) | Value::Byte(_) | Value::Str(_) | Value::Bytes(_) => self.clone(),
        }
    }

    /// Looks up a key in a dictionary value (`a{s?}`).
    ///
    /// A dictionary value is an array of two-element tuples. The first member
    /// of each tuple is the key string. The method returns the value member
    /// of the first entry whose key matches. If a [`DictBuilder`] inserted one
    /// key twice, the method returns the value of the first entry.
    ///
    /// The method skips each entry that does not have the `{s?}` shape. If
    /// `self` is not an array, or if no key matches, the result is `None`.
    ///
    /// [`DictBuilder`]: crate::DictBuilder
    pub fn dict_get(&self, key: &str) -> Option<&Value> {
        for entry in self.as_array()? {
            let Some(fields) = entry.as_tuple() else {
                continue;
            };
            if let [k, v] = fields
                && k.as_str() == Some(key)
            {
                return Some(v);
            }
        }
        None
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Value {
        Value::Bool(v)
    }
}

impl From<u8> for Value {
    fn from(v: u8) -> Value {
        Value::Byte(v)
    }
}

impl From<u32> for Value {
    fn from(v: u32) -> Value {
        Value::U32(v)
    }
}

impl From<u64> for Value {
    fn from(v: u64) -> Value {
        Value::U64(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Value {
        Value::Str(v.to_owned())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Value {
        Value::Str(v)
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Value {
        Value::Bytes(v)
    }
}

impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Value {
        Value::Bytes(v.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DictBuilder, from_bytes, to_bytes};

    /// A key written as an `as` reads back as the same strings in the same
    /// order. The test reads the key through the dict that the builder
    /// produces.
    #[test]
    fn reads_back_an_inserted_strv() {
        let mut builder = DictBuilder::new();
        builder.insert_strv(
            "ostree.ref-binding",
            &["one".to_owned(), "two".to_owned(), "three".to_owned()],
        );
        let dict = builder.build();

        let (_, value) = dict
            .dict_get("ostree.ref-binding")
            .unwrap()
            .as_variant()
            .unwrap();
        assert_eq!(value.as_strv(), Some(vec!["one", "two", "three"]));
    }

    /// A serialized `a{sv}` with an `as` key returns the strings after a parse
    /// of its bytes.
    #[test]
    fn reads_back_a_parsed_strv() {
        let mut builder = DictBuilder::new();
        builder
            .insert_str("version", "1")
            .insert_strv("ostree.ref-binding", &["alpha".to_owned(), "".to_owned()]);
        let dict = builder.build();

        let ty = Type::parse("a{sv}").unwrap();
        let bytes = to_bytes(&ty, &dict).unwrap();
        let parsed = from_bytes(&ty, &bytes).unwrap();

        let (_, value) = parsed
            .dict_get("ostree.ref-binding")
            .unwrap()
            .as_variant()
            .unwrap();
        assert_eq!(value.as_strv(), Some(vec!["alpha", ""]));
    }

    /// The empty array yields the empty list. A key written as an empty `as`
    /// holds this list.
    #[test]
    fn reads_an_empty_array_as_an_empty_list() {
        assert_eq!(Value::Array(Vec::new()).as_strv(), Some(Vec::new()));

        let mut builder = DictBuilder::new();
        builder.insert_strv("k", &[]);
        let dict = builder.build();
        let (_, value) = dict.dict_get("k").unwrap().as_variant().unwrap();
        assert_eq!(value.as_strv(), Some(Vec::new()));
    }

    /// A value holds an `o` and a `g` as strings, so an `ao` and an `ag`
    /// return their strings the same as an `as` does.
    #[test]
    fn reads_a_folded_object_path_and_signature_array() {
        let paths = Value::Array(vec![
            Value::Str("/org/example/One".to_owned()),
            Value::Str("/org/example/Two".to_owned()),
        ]);
        let ty = Type::parse("ao").unwrap();
        let parsed = from_bytes(&ty, &to_bytes(&ty, &paths).unwrap()).unwrap();
        assert_eq!(
            parsed.as_strv(),
            Some(vec!["/org/example/One", "/org/example/Two"])
        );

        let signatures = Value::Array(vec![Value::Str("a{sv}".to_owned())]);
        let ty = Type::parse("ag").unwrap();
        let parsed = from_bytes(&ty, &to_bytes(&ty, &signatures).unwrap()).unwrap();
        assert_eq!(parsed.as_strv(), Some(vec!["a{sv}"]));
    }

    /// If an array holds an element that is not a string, the result is
    /// `None` for the whole array. A byte array, a nested array, and a dict
    /// entry are such elements.
    #[test]
    fn refuses_an_array_with_a_non_string_element() {
        let mixed = Value::Array(vec![Value::Str("one".to_owned()), Value::U32(2)]);
        assert_eq!(mixed.as_strv(), None);
        assert_eq!(Value::Array(vec![Value::Bytes(vec![0x41])]).as_strv(), None);
        let nested = Value::Array(vec![Value::Array(vec![Value::Str("one".to_owned())])]);
        assert_eq!(nested.as_strv(), None);
        let entries = Value::Array(vec![Value::Tuple(vec![
            Value::Str("k".to_owned()),
            Value::Str("v".to_owned()),
        ])]);
        assert_eq!(entries.as_strv(), None);
    }

    /// Only an array yields the strings. The string, the byte array, the
    /// tuple, the maybe, and the variant all yield `None`.
    #[test]
    fn refuses_every_other_type() {
        assert_eq!(Value::Str("one".to_owned()).as_strv(), None);
        assert_eq!(Value::Bytes(vec![0x41, 0x42]).as_strv(), None);
        assert_eq!(
            Value::Tuple(vec![Value::Str("one".to_owned())]).as_strv(),
            None
        );
        assert_eq!(
            Value::Maybe(Some(Box::new(Value::Array(vec![Value::Str(
                "one".to_owned()
            )]))))
            .as_strv(),
            None
        );
        assert_eq!(Value::Maybe(None).as_strv(), None);
        assert_eq!(
            Value::variant(Type::Array(Box::new(Type::Str)), Value::Array(Vec::new())).as_strv(),
            None
        );
    }
}
