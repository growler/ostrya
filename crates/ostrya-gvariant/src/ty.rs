use crate::{Error, Result};

/// Maximum container nesting depth accepted in a type signature. It is the
/// depth the value parser and the serializer carry, so a value either of them
/// accepts names a type this parser accepts back.
const MAX_TYPE_DEPTH: usize = crate::de::MAX_VALUE_DEPTH;

/// A GVariant type.
///
/// The ostree on-disk format uses booleans, bytes, u32, u64, strings, variants,
/// arrays, tuples, and dict entries. The remaining GVariant types -- the signed
/// and the narrow integers, the handle, the double, the object path, the
/// signature, and the maybe -- reach a repository through
/// `commit --add-metadata`, which takes any value the GVariant text form states
/// (`docs/format-reference.md`, "CLI output formats"). Any character outside the
/// GVariant type alphabet is rejected by [`Type::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    /// `b`
    Bool,
    /// `y`
    Byte,
    /// `n`
    I16,
    /// `q`
    U16,
    /// `i`
    I32,
    /// `u`
    U32,
    /// `x`
    I64,
    /// `t`
    U64,
    /// `h`
    Handle,
    /// `d`
    Double,
    /// `s`
    Str,
    /// `o`
    ObjectPath,
    /// `g`
    Signature,
    /// `v`
    Variant,
    /// `m<T>`
    Maybe(Box<Type>),
    /// `a<T>`
    Array(Box<Type>),
    /// `(<T>...)`
    Tuple(Vec<Type>),
    /// `{<K><V>}`; the key must be a basic (non-container) type.
    DictEntry(Box<Type>, Box<Type>),
}

impl Type {
    /// Parse a complete type signature such as `(a{sv}aya(say)sstayay)`.
    pub fn parse(signature: &str) -> Result<Type> {
        let sig = signature.as_bytes();
        let mut pos = 0;
        let err = |offset, reason| Error::InvalidTypeString {
            signature: signature.to_owned(),
            offset,
            reason,
        };
        let ty = parse_one(sig, &mut pos, 0).map_err(|(offset, reason)| err(offset, reason))?;
        if pos != sig.len() {
            return Err(err(pos, "trailing characters after a complete type"));
        }
        Ok(ty)
    }

    /// The signature string for this type.
    pub fn signature(&self) -> String {
        let mut out = String::new();
        self.write_signature(&mut out);
        out
    }

    fn write_signature(&self, out: &mut String) {
        match self {
            Type::Bool => out.push('b'),
            Type::Byte => out.push('y'),
            Type::I16 => out.push('n'),
            Type::U16 => out.push('q'),
            Type::I32 => out.push('i'),
            Type::U32 => out.push('u'),
            Type::I64 => out.push('x'),
            Type::U64 => out.push('t'),
            Type::Handle => out.push('h'),
            Type::Double => out.push('d'),
            Type::Str => out.push('s'),
            Type::ObjectPath => out.push('o'),
            Type::Signature => out.push('g'),
            Type::Variant => out.push('v'),
            Type::Maybe(elem) => {
                out.push('m');
                elem.write_signature(out);
            }
            Type::Array(elem) => {
                out.push('a');
                elem.write_signature(out);
            }
            Type::Tuple(members) => {
                out.push('(');
                for m in members {
                    m.write_signature(out);
                }
                out.push(')');
            }
            Type::DictEntry(key, value) => {
                out.push('{');
                key.write_signature(out);
                value.write_signature(out);
                out.push('}');
            }
        }
    }

    /// The alignment requirement of the serialized form, in bytes.
    pub fn alignment(&self) -> usize {
        match self {
            Type::Bool | Type::Byte | Type::Str | Type::ObjectPath | Type::Signature => 1,
            Type::I16 | Type::U16 => 2,
            Type::I32 | Type::U32 | Type::Handle => 4,
            Type::I64 | Type::U64 | Type::Double | Type::Variant => 8,
            Type::Maybe(elem) | Type::Array(elem) => elem.alignment(),
            Type::Tuple(members) => members.iter().map(Type::alignment).max().unwrap_or(1),
            Type::DictEntry(key, value) => key.alignment().max(value.alignment()),
        }
    }

    /// The serialized size if this type is fixed-size, else `None`.
    pub fn fixed_size(&self) -> Option<usize> {
        match self {
            Type::Bool | Type::Byte => Some(1),
            Type::I16 | Type::U16 => Some(2),
            Type::I32 | Type::U32 | Type::Handle => Some(4),
            Type::I64 | Type::U64 | Type::Double => Some(8),
            Type::Str
            | Type::ObjectPath
            | Type::Signature
            | Type::Variant
            | Type::Maybe(_)
            | Type::Array(_) => None,
            Type::Tuple(members) => fixed_size_of(members.iter(), self.alignment()),
            Type::DictEntry(key, value) => {
                fixed_size_of([&**key, &**value].into_iter(), self.alignment())
            }
        }
    }

    /// Whether this is a basic type: a scalar or a string, the types a dict
    /// entry accepts as its key.
    pub fn is_basic(&self) -> bool {
        matches!(
            self,
            Type::Bool
                | Type::Byte
                | Type::I16
                | Type::U16
                | Type::I32
                | Type::U32
                | Type::I64
                | Type::U64
                | Type::Handle
                | Type::Double
                | Type::Str
                | Type::ObjectPath
                | Type::Signature
        )
    }
}

/// Combined fixed size of a struct's members, or `None` if any is variable.
/// The empty structure has fixed size 1.
fn fixed_size_of<'a>(members: impl Iterator<Item = &'a Type>, alignment: usize) -> Option<usize> {
    let mut size = 0;
    let mut any = false;
    for m in members {
        any = true;
        size = align_up(size, m.alignment()) + m.fixed_size()?;
    }
    if !any {
        return Some(1);
    }
    Some(align_up(size, alignment))
}

pub(crate) const fn align_up(n: usize, alignment: usize) -> usize {
    (n + alignment - 1) & !(alignment - 1)
}

type SigError = (usize, &'static str);

fn parse_one(sig: &[u8], pos: &mut usize, depth: usize) -> std::result::Result<Type, SigError> {
    if depth > MAX_TYPE_DEPTH {
        return Err((*pos, "nesting exceeds the supported depth"));
    }
    let Some(&c) = sig.get(*pos) else {
        return Err((*pos, "unexpected end of signature"));
    };
    *pos += 1;
    match c {
        b'b' => Ok(Type::Bool),
        b'y' => Ok(Type::Byte),
        b'n' => Ok(Type::I16),
        b'q' => Ok(Type::U16),
        b'i' => Ok(Type::I32),
        b'u' => Ok(Type::U32),
        b'x' => Ok(Type::I64),
        b't' => Ok(Type::U64),
        b'h' => Ok(Type::Handle),
        b'd' => Ok(Type::Double),
        b's' => Ok(Type::Str),
        b'o' => Ok(Type::ObjectPath),
        b'g' => Ok(Type::Signature),
        b'v' => Ok(Type::Variant),
        b'm' => Ok(Type::Maybe(Box::new(parse_one(sig, pos, depth + 1)?))),
        b'a' => Ok(Type::Array(Box::new(parse_one(sig, pos, depth + 1)?))),
        b'(' => {
            let mut members = Vec::new();
            while sig.get(*pos) != Some(&b')') {
                members.push(parse_one(sig, pos, depth + 1)?);
            }
            *pos += 1;
            Ok(Type::Tuple(members))
        }
        b'{' => {
            let key_offset = *pos;
            let key = parse_one(sig, pos, depth + 1)?;
            if !key.is_basic() {
                return Err((key_offset, "dict-entry key must be a basic type"));
            }
            let value = parse_one(sig, pos, depth + 1)?;
            if sig.get(*pos) != Some(&b'}') {
                return Err((*pos, "expected '}' after the dict-entry value"));
            }
            *pos += 1;
            Ok(Type::DictEntry(Box::new(key), Box::new(value)))
        }
        _ => Err((*pos - 1, "unsupported type character")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every type string the ostree on-disk format uses (format-reference.md).
    const OSTREE_SIGNATURES: &[&str] = &[
        "(a{sv}aya(say)sstayay)",                                 // commit
        "(a(say)a(sayay))",                                       // dirtree
        "(uuua(ayay))",                                           // dirmeta, user.ostreemeta
        "(uuuusa(ayay))",                                         // uncompressed file header
        "(tuuuusa(ayay))",                                        // archive file header
        "a{sv}",                                                  // commitmeta, summary.sig
        "(a(s(taya{sv}))a{sv})",                                  // summary
        "a{sa(s(taya{sv}))}",                                     // collection map
        "(a(uuu)aa(ayay)ayay)",                                   // delta part payload
        "(uayttay)",                                              // delta meta entry
        "(yaytt)",                                                // delta fallback
        "(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))", // delta superblock
        "(taya{sv})",                                             // signed delta
        "(yay)",                                                  // delta part framing
        "(su)",                                                   // object name
        "ay",
        "aay",
        "as",
    ];

    /// The type characters outside the on-disk format, which reach a
    /// repository through `commit --add-metadata`.
    const METADATA_SIGNATURES: &[&str] = &[
        "n", "q", "i", "x", "h", "d", "o", "g", "ms", "mi", "ami", "a{sd}", "(sid)", "mmy",
    ];

    #[test]
    fn parses_and_round_trips_every_ostree_signature() {
        for sig in OSTREE_SIGNATURES.iter().chain(METADATA_SIGNATURES) {
            let ty = Type::parse(sig).unwrap();
            assert_eq!(ty.signature(), *sig);
        }
    }

    #[test]
    fn alignment_and_fixed_size() {
        let cases: &[(&str, usize, Option<usize>)] = &[
            ("y", 1, Some(1)),
            ("b", 1, Some(1)),
            ("u", 4, Some(4)),
            ("t", 8, Some(8)),
            ("s", 1, None),
            ("v", 8, None),
            ("ay", 1, None),
            ("a(uuu)", 4, None),
            ("(uuu)", 4, Some(12)),
            ("(ty)", 8, Some(16)), // end padding to the tuple alignment
            ("(uuua(ayay))", 4, None),
            ("(tuuuusa(ayay))", 8, None),
            ("(su)", 4, None),
            ("(yaytt)", 8, None),
            ("{sv}", 8, None),
            ("()", 1, Some(1)),
            ("n", 2, Some(2)),
            ("q", 2, Some(2)),
            ("i", 4, Some(4)),
            ("h", 4, Some(4)),
            ("x", 8, Some(8)),
            ("d", 8, Some(8)),
            ("o", 1, None),
            ("g", 1, None),
            ("ms", 1, None),
            ("mi", 4, None),
            ("(id)", 8, Some(16)),
        ];
        for (sig, alignment, fixed) in cases {
            let ty = Type::parse(sig).unwrap();
            assert_eq!(ty.alignment(), *alignment, "alignment of {sig}");
            assert_eq!(ty.fixed_size(), *fixed, "fixed size of {sig}");
        }
    }

    #[test]
    fn rejects_invalid_signatures() {
        for sig in ["", "r", "*", "?", "(s", "{vs}", "{s", "{sv", "ss", "a", "m"] {
            assert!(Type::parse(sig).is_err(), "expected {sig:?} to be rejected");
        }
    }

    #[test]
    fn rejects_overdeep_nesting() {
        // The depth the value parser and the serializer accept, the first depth
        // past it, and one further.
        let sig = format!("{}y", "a".repeat(MAX_TYPE_DEPTH));
        assert!(Type::parse(&sig).is_ok());
        let sig = format!("{}y", "a".repeat(MAX_TYPE_DEPTH + 1));
        assert!(Type::parse(&sig).is_err());
        let sig = format!("{}y", "a".repeat(MAX_TYPE_DEPTH + 2));
        assert!(Type::parse(&sig).is_err());
    }
}
