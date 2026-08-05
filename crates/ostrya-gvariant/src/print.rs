use std::fmt::Write as _;

use crate::{Error, Result, Type, Value};

/// Render `value` of type `ty` in the GVariant text form.
///
/// The text form is the one GLib's own printer produces, recovered by
/// observation against `ostree show --raw`, `ostree show --print-metadata-key`,
/// and `ostree show --print-variant-type` (`docs/format-reference.md`, "The
/// GVariant text form"). The rules:
///
/// - A value whose literal does not state its own type carries a type
///   annotation: `byte 0x2a`, `uint32 42`, `uint64 42`. A boolean and a string
///   are unambiguous and carry none.
/// - A container that holds at least one element delegates its annotation to
///   its first element, and the elements after it print unannotated. A tuple
///   annotates every member, since a tuple's members do not share a type.
/// - A container that holds no element has nowhere to delegate to, so it
///   carries its own signature: `@ay []`, `@a(say) []`, `@a{sv} {}`.
/// - A byte array whose last byte is the only NUL it holds prints as a
///   bytestring literal, `b'user.foo'`, which states its own type and so carries
///   no annotation. Every other byte array prints as `[byte 0x01, 0x02]`.
/// - An array of dict entries prints as one brace-enclosed list of `key: value`
///   pairs. A dict entry outside an array prints `{key, value}`, with a comma.
/// - A variant prints as `<child>`, and the child is always annotated, since a
///   variant states no child type of its own.
///
/// Returns [`Error::TypeMismatch`] when `value` does not match `ty`, the same
/// pairing [`crate::to_bytes`] requires.
pub fn to_text(ty: &Type, value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(&mut out, ty, value, true)?;
    Ok(out)
}

/// Write one value, annotating it when `annotate` is set and its literal does
/// not state its type.
fn write_value(out: &mut String, ty: &Type, value: &Value, annotate: bool) -> Result<()> {
    match (ty, value) {
        (Type::Bool, Value::Bool(b)) => out.push_str(if *b { "true" } else { "false" }),
        (Type::Byte, Value::Byte(b)) => {
            if annotate {
                out.push_str("byte ");
            }
            write!(out, "0x{b:02x}").expect("writing to a String cannot fail");
        }
        (Type::U32, Value::U32(x)) => write_number(out, annotate, "uint32", *x as u64),
        (Type::U64, Value::U64(x)) => write_number(out, annotate, "uint64", *x),
        (Type::Str, Value::Str(s)) => write_string(out, s),
        (Type::Array(elem), Value::Bytes(bytes)) if **elem == Type::Byte => {
            if bytes.is_empty() {
                write_empty(out, ty, annotate, "[]");
                return Ok(());
            }
            if is_bytestring(bytes) {
                write_bytestring(out, &bytes[..bytes.len() - 1]);
                return Ok(());
            }
            out.push('[');
            for (index, byte) in bytes.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_value(
                    out,
                    &Type::Byte,
                    &Value::Byte(*byte),
                    annotate && index == 0,
                )?;
            }
            out.push(']');
        }
        (Type::Array(elem), Value::Array(items)) if **elem != Type::Byte => {
            let (open, close) = if matches!(**elem, Type::DictEntry(..)) {
                ('{', '}')
            } else {
                ('[', ']')
            };
            if items.is_empty() {
                write_empty(out, ty, annotate, if open == '{' { "{}" } else { "[]" });
                return Ok(());
            }
            out.push(open);
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                let annotate = annotate && index == 0;
                if open == '{' {
                    write_entry(out, elem, item, annotate, ": ")?;
                } else {
                    write_value(out, elem, item, annotate)?;
                }
            }
            out.push(close);
        }
        (Type::Tuple(members), Value::Tuple(items)) if members.len() == items.len() => {
            out.push('(');
            for (index, (member, item)) in members.iter().zip(items).enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_value(out, member, item, annotate)?;
            }
            // A one-member tuple needs the trailing comma to stay a tuple.
            if items.len() == 1 {
                out.push(',');
            }
            out.push(')');
        }
        (Type::DictEntry(..), Value::Tuple(_)) => {
            out.push('{');
            write_entry(out, ty, value, annotate, ", ")?;
            out.push('}');
        }
        (Type::Variant, Value::Variant(inner)) => {
            let (child_ty, child) = &**inner;
            out.push('<');
            write_value(out, child_ty, child, true)?;
            out.push('>');
        }
        _ => {
            return Err(Error::TypeMismatch {
                expected: ty.signature(),
                found: value.kind(),
            });
        }
    }
    Ok(())
}

/// Write an unsigned integer, prefixed by `keyword` when annotated.
fn write_number(out: &mut String, annotate: bool, keyword: &str, value: u64) {
    if annotate {
        out.push_str(keyword);
        out.push(' ');
    }
    write!(out, "{value}").expect("writing to a String cannot fail");
}

/// Write an empty container: `literal` alone, or `@signature literal` when the
/// container has to carry the annotation its absent elements cannot.
fn write_empty(out: &mut String, ty: &Type, annotate: bool, literal: &str) {
    if annotate {
        out.push('@');
        out.push_str(&ty.signature());
        out.push(' ');
    }
    out.push_str(literal);
}

/// Write a dict entry's key and value joined by `separator`, without the braces
/// the caller supplies: an array of entries brackets the whole list once and
/// joins each pair with `": "`, a lone entry brackets itself and joins with
/// `", "`.
fn write_entry(
    out: &mut String,
    ty: &Type,
    value: &Value,
    annotate: bool,
    separator: &str,
) -> Result<()> {
    let mismatch = || Error::TypeMismatch {
        expected: ty.signature(),
        found: value.kind(),
    };
    let Type::DictEntry(key_ty, value_ty) = ty else {
        return Err(mismatch());
    };
    let Some([key, val]) = value.as_tuple() else {
        return Err(mismatch());
    };
    write_value(out, key_ty, key, annotate)?;
    out.push_str(separator);
    write_value(out, value_ty, val, annotate)
}

/// Whether a byte array prints as a bytestring literal: it ends in a NUL and
/// holds no other one, so the bytes before that NUL are the literal's content.
fn is_bytestring(bytes: &[u8]) -> bool {
    match bytes.split_last() {
        Some((0, rest)) => !rest.contains(&0),
        _ => false,
    }
}

/// Write a bytestring literal, `b'...'`, over `content` -- the byte array
/// without its terminating NUL. The escaping is C's rather than the string
/// form's: a backslash and a double quote are always escaped, `\b`, `\f`, `\n`,
/// `\r`, `\t`, and `\v` take their short form, and every other byte outside the
/// printable ASCII range takes a three-digit octal escape. A single quote is
/// never escaped, so a content byte holding one selects double quotes.
fn write_bytestring(out: &mut String, content: &[u8]) {
    let quote = if content.contains(&b'\'') { '"' } else { '\'' };
    out.push('b');
    out.push(quote);
    for &b in content {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x0b => out.push_str("\\v"),
            0x20..=0x7e => out.push(b as char),
            other => write!(out, "\\{other:03o}").expect("writing to a String cannot fail"),
        }
    }
    out.push(quote);
}

/// Write a string literal. Single quotes are the default; a string that holds a
/// single quote is written in double quotes instead, so the quote it holds needs
/// no escape. Only the quote in use is escaped, so `"` stays literal inside
/// single quotes. Control characters take their short escape where one exists
/// and `\uXXXX` otherwise, and every other character, ASCII or not, is written
/// through.
fn write_string(out: &mut String, s: &str) {
    let quote = if s.contains('\'') { '"' } else { '\'' };
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                write!(out, "\\u{:04x}", c as u32).expect("writing to a String cannot fail");
            }
            c => out.push(c),
        }
    }
    out.push(quote);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Print a value described by its signature, panicking on a mismatch.
    fn text(signature: &str, value: Value) -> String {
        to_text(&Type::parse(signature).unwrap(), &value).unwrap()
    }

    fn bytes(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }

    /// Each case is one form of `ostree show --print-variant-type=TYPE`,
    /// `show --raw`, or `show --print-metadata-key` observed against `ostree`
    /// 2026.1 (`docs/format-reference.md`, "The GVariant text form").
    #[test]
    fn prints_the_forms_recovered_from_the_tool() {
        let cases: &[(&str, Value, &str)] = &[
            // Scalars carry an annotation where the literal does not state the
            // type; a boolean and a string state their own.
            ("b", Value::Bool(false), "false"),
            ("b", Value::Bool(true), "true"),
            ("y", Value::Byte(0x2a), "byte 0x2a"),
            ("y", Value::Byte(0x09), "byte 0x09"),
            ("u", Value::U32(16909060), "uint32 16909060"),
            ("t", Value::U64(1700000000), "uint64 1700000000"),
            ("s", Value::Str("abc".into()), "'abc'"),
            // Byte arrays: the bytestring form for a lone trailing NUL, the
            // element list otherwise, and the signature when empty.
            ("ay", bytes(&[]), "@ay []"),
            ("ay", bytes(&[0x01, 0x02, 0xff]), "[byte 0x01, 0x02, 0xff]"),
            ("ay", bytes(&[0x62]), "[byte 0x62]"),
            ("ay", bytes(&[0x00]), "b''"),
            ("ay", bytes(&[0x62, 0x00]), "b'b'"),
            ("ay", bytes(b"hi\0"), "b'hi'"),
            (
                "ay",
                bytes(&[0x62, 0x00, 0x63, 0x00]),
                "[byte 0x62, 0x00, 0x63, 0x00]",
            ),
            ("ay", bytes(&[0xff, 0x00]), "b'\\377'"),
            ("ay", bytes(&[0x7f, 0x00]), "b'\\177'"),
            ("ay", bytes(&[0x1b, 0x00]), "b'\\033'"),
            ("ay", bytes(b"a\tb\0"), "b'a\\tb'"),
            ("ay", bytes(b"a'b\0"), "b\"a'b\""),
            ("ay", bytes(b"a\"b\0"), "b'a\\\"b'"),
            ("ay", bytes(b"a'\"b\0"), "b\"a'\\\"b\""),
            ("ay", bytes("hé\0".as_bytes()), "b'h\\303\\251'"),
            // A container delegates its annotation to its first element alone.
            (
                "aay",
                Value::Array(vec![bytes(&[0x62, 0x00]), bytes(&[0x63])]),
                "[b'b', [0x63]]",
            ),
            (
                "aay",
                Value::Array(vec![bytes(&[0x63]), bytes(&[0x62, 0x00])]),
                "[[byte 0x63], b'b']",
            ),
            (
                "aay",
                Value::Array(vec![bytes(&[]), bytes(&[0x63])]),
                "[@ay [], [0x63]]",
            ),
            (
                "aay",
                Value::Array(vec![bytes(&[0x63]), bytes(&[])]),
                "[[byte 0x63], []]",
            ),
            ("aay", Value::Array(vec![]), "@aay []"),
            (
                "as",
                Value::Array(vec!["a".into(), "bb".into()]),
                "['a', 'bb']",
            ),
            (
                "aab",
                Value::Array(vec![
                    Value::Array(vec![Value::Bool(true)]),
                    Value::Array(vec![Value::Bool(false)]),
                ]),
                "[[true], [false]]",
            ),
            // A dict prints its entries as one brace-enclosed list; a lone
            // entry joins its pair with a comma.
            (
                "a{sy}",
                Value::Array(vec![
                    Value::Tuple(vec!["a".into(), Value::Byte(1)]),
                    Value::Tuple(vec!["b".into(), Value::Byte(2)]),
                ]),
                "{'a': byte 0x01, 'b': 0x02}",
            ),
            ("a{sy}", Value::Array(vec![]), "@a{sy} {}"),
            (
                "{sy}",
                Value::Tuple(vec!["a".into(), Value::Byte(1)]),
                "{'a', byte 0x01}",
            ),
            // A tuple annotates every member; one member keeps a trailing comma.
            ("(y)", Value::Tuple(vec![Value::Byte(1)]), "(byte 0x01,)"),
            ("()", Value::Tuple(vec![]), "()"),
            (
                "(yy)",
                Value::Tuple(vec![Value::Byte(1), Value::Byte(2)]),
                "(byte 0x01, byte 0x02)",
            ),
            (
                "(ss)",
                Value::Tuple(vec!["a".into(), "b".into()]),
                "('a', 'b')",
            ),
            // A variant states no child type, so the child is always annotated.
            (
                "v",
                Value::variant(Type::Byte, Value::Byte(0x2a)),
                "<byte 0x2a>",
            ),
            (
                "v",
                Value::variant(Type::parse("ay").unwrap(), bytes(&[0x62, 0x00])),
                "<b'b'>",
            ),
        ];
        for (signature, value, expected) in cases {
            assert_eq!(
                text(signature, value.clone()),
                *expected,
                "printing {signature}"
            );
        }
    }

    /// The string escapes, each recovered from `show --print-variant-type=s`.
    #[test]
    fn escapes_strings_the_way_the_tool_does() {
        let cases: &[(&str, &str)] = &[
            ("abc", "'abc'"),
            ("", "''"),
            ("a'b", "\"a'b\""),
            ("a\"b", "'a\"b'"),
            ("a'\"b", "\"a'\\\"b\""),
            ("a\tb", "'a\\tb'"),
            ("a\nb", "'a\\nb'"),
            ("a\rb", "'a\\rb'"),
            ("a\u{7}b", "'a\\ab'"),
            ("a\u{8}b", "'a\\bb'"),
            ("a\u{b}b", "'a\\vb'"),
            ("a\u{c}b", "'a\\fb'"),
            ("a\\b", "'a\\\\b'"),
            ("a\u{1b}b", "'a\\u001bb'"),
            ("a\u{7f}b", "'a\\u007fb'"),
            ("héllo", "'héllo'"),
        ];
        for (input, expected) in cases {
            assert_eq!(text("s", Value::Str((*input).into())), *expected);
        }
    }

    /// The dirmeta and commit forms, whole, as `show --raw` prints them.
    #[test]
    fn prints_the_ostree_metadata_object_forms() {
        let dirmeta = Value::Tuple(vec![
            Value::U32(1000),
            Value::U32(100),
            Value::U32(0o40755),
            Value::Array(vec![]),
        ]);
        assert_eq!(
            text("(uuua(ayay))", dirmeta),
            "(uint32 1000, uint32 100, uint32 16877, @a(ayay) [])"
        );
        let xattrs = Value::Array(vec![Value::Tuple(vec![
            bytes(b"user.foo\0"),
            bytes(b"bar"),
        ])]);
        assert_eq!(
            text("a(ayay)", xattrs),
            "[(b'user.foo', [byte 0x62, 0x61, 0x72])]"
        );
    }

    /// A byteswap turns the big-endian fields the on-disk format states into
    /// the numbers they name, and leaves everything else alone.
    #[test]
    fn byteswap_reaches_every_numeric_field() {
        let value = Value::Tuple(vec![
            Value::U64(1700000000u64.swap_bytes()),
            Value::U32(1000u32.swap_bytes()),
            Value::Str("kept".into()),
            Value::Bytes(vec![0x01, 0x02]),
            Value::Bool(true),
            Value::Byte(0x03),
            Value::Array(vec![Value::U32(7u32.swap_bytes())]),
            Value::variant(Type::U64, Value::U64(9u64.swap_bytes())),
        ]);
        assert_eq!(
            text("(tusaybyauv)", value.byteswapped()),
            "(uint64 1700000000, uint32 1000, 'kept', [byte 0x01, 0x02], true, \
             byte 0x03, [uint32 7], <uint64 9>)"
        );
    }

    #[test]
    fn refuses_a_value_that_does_not_match_the_type() {
        let ty = Type::parse("s").unwrap();
        assert!(to_text(&ty, &Value::Byte(1)).is_err());
        let ty = Type::parse("(ss)").unwrap();
        assert!(to_text(&ty, &Value::Tuple(vec!["a".into()])).is_err());
    }
}
