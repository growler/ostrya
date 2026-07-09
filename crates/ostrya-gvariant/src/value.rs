use crate::Type;

/// A dynamically-typed GVariant value.
///
/// The representation is canonical with respect to a [`Type`]:
///
/// - byte arrays (`ay`) are `Bytes`, never `Array` of `Byte`;
/// - dict entries are two-element `Tuple`s;
/// - a `Variant` carries the child's type, since the serialized form embeds
///   the child's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Byte(u8),
    U32(u32),
    U64(u64),
    Str(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Tuple(Vec<Value>),
    Variant(Box<(Type, Value)>),
}

impl Value {
    /// Wrap `value` of type `ty` as a variant.
    pub fn variant(ty: Type, value: Value) -> Value {
        Value::Variant(Box::new((ty, value)))
    }

    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Value::Bool(_) => "bool",
            Value::Byte(_) => "byte",
            Value::U32(_) => "u32",
            Value::U64(_) => "u64",
            Value::Str(_) => "string",
            Value::Bytes(_) => "byte array",
            Value::Array(_) => "array",
            Value::Tuple(_) => "tuple",
            Value::Variant(_) => "variant",
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_byte(&self) -> Option<u8> {
        match self {
            Value::Byte(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Value::U32(x) => Some(*x),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(x) => Some(*x),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_tuple(&self) -> Option<&[Value]> {
        match self {
            Value::Tuple(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_variant(&self) -> Option<(&Type, &Value)> {
        match self {
            Value::Variant(inner) => Some((&inner.0, &inner.1)),
            _ => None,
        }
    }

    /// Look up a key in a dictionary value (`a{s?}`): an array of two-element
    /// tuples whose first member is the key string. Returns the value member of
    /// the first entry whose key matches. Entries that are not `{s?}`-shaped are
    /// skipped; a non-array `self` yields `None`.
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
