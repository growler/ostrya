use crate::{Error, Result};

/// Maximum container nesting depth accepted in a type signature.
const MAX_TYPE_DEPTH: usize = 64;

/// A GVariant type, restricted to the signatures the ostree on-disk format
/// uses: booleans, bytes, u32, u64, strings, variants, arrays, tuples, and
/// dict entries. Any other type character is rejected by [`Type::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    /// `b`
    Bool,
    /// `y`
    Byte,
    /// `u`
    U32,
    /// `t`
    U64,
    /// `s`
    Str,
    /// `v`
    Variant,
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
            Type::U32 => out.push('u'),
            Type::U64 => out.push('t'),
            Type::Str => out.push('s'),
            Type::Variant => out.push('v'),
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
            Type::Bool | Type::Byte | Type::Str => 1,
            Type::U32 => 4,
            Type::U64 | Type::Variant => 8,
            Type::Array(elem) => elem.alignment(),
            Type::Tuple(members) => members.iter().map(Type::alignment).max().unwrap_or(1),
            Type::DictEntry(key, value) => key.alignment().max(value.alignment()),
        }
    }

    /// The serialized size if this type is fixed-size, else `None`.
    pub fn fixed_size(&self) -> Option<usize> {
        match self {
            Type::Bool | Type::Byte => Some(1),
            Type::U32 => Some(4),
            Type::U64 => Some(8),
            Type::Str | Type::Variant | Type::Array(_) => None,
            Type::Tuple(members) => fixed_size_of(members.iter(), self.alignment()),
            Type::DictEntry(key, value) => {
                fixed_size_of([&**key, &**value].into_iter(), self.alignment())
            }
        }
    }

    fn is_basic(&self) -> bool {
        matches!(
            self,
            Type::Bool | Type::Byte | Type::U32 | Type::U64 | Type::Str
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
        b'u' => Ok(Type::U32),
        b't' => Ok(Type::U64),
        b's' => Ok(Type::Str),
        b'v' => Ok(Type::Variant),
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

    #[test]
    fn parses_and_round_trips_every_ostree_signature() {
        for sig in OSTREE_SIGNATURES {
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
        ];
        for (sig, alignment, fixed) in cases {
            let ty = Type::parse(sig).unwrap();
            assert_eq!(ty.alignment(), *alignment, "alignment of {sig}");
            assert_eq!(ty.fixed_size(), *fixed, "fixed size of {sig}");
        }
    }

    #[test]
    fn rejects_invalid_signatures() {
        for sig in [
            "", "d", "i", "x", "n", "q", "o", "g", "ms", "(s", "{vs}", "{s", "{sv", "ss", "a",
        ] {
            assert!(Type::parse(sig).is_err(), "expected {sig:?} to be rejected");
        }
    }

    #[test]
    fn rejects_overdeep_nesting() {
        let sig = format!("{}y", "a".repeat(100));
        assert!(Type::parse(&sig).is_err());
    }
}
