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
/// - A maybe prints the value it holds and nothing else, since its type states
///   how many maybe levels that value sits under. A chain of nested maybes that
///   ends at `nothing` states how many of its levels are set instead, with one
///   `just ` for each set level: `@mmi nothing`, `@mmi just nothing`,
///   `@mmi 5`.
///
/// Returns [`Error::TypeMismatch`] when `value` does not match `ty`, the same
/// pairing [`crate::to_bytes`] requires.
pub fn to_text(ty: &Type, value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(&mut out, ty, value, true)?;
    Ok(out)
}

/// Render `value` of type `ty` in the GVariant text form, with no type
/// annotations.
///
/// The rules are [`to_text`]'s with every annotation left out: a byte and an
/// unsigned integer print bare, an empty container prints `[]` or `{}` rather
/// than its signature, and a tuple's members print bare. A variant child still
/// carries an annotation, a variant stating no child type of its own. The
/// `just ` prefixes of a nested maybe are part of the value rather than an
/// annotation, so they stay.
///
/// This is the form a report that names the value itself uses, where the reader
/// already knows what it is looking at (`docs/format-reference.md`, "The
/// GVariant text form").
pub fn to_text_unannotated(ty: &Type, value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(&mut out, ty, value, false)?;
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
        (Type::I16, Value::I16(x)) => write_number(out, annotate, "int16", x),
        (Type::U16, Value::U16(x)) => write_number(out, annotate, "uint16", x),
        // An `i` literal states its own type, so it never carries a keyword.
        (Type::I32, Value::I32(x)) => write_number(out, false, "int32", x),
        (Type::Handle, Value::I32(x)) => write_number(out, annotate, "handle", x),
        (Type::U32, Value::U32(x)) => write_number(out, annotate, "uint32", x),
        (Type::I64, Value::I64(x)) => write_number(out, annotate, "int64", x),
        (Type::U64, Value::U64(x)) => write_number(out, annotate, "uint64", x),
        (Type::Double, Value::Double(bits)) => write_double(out, f64::from_bits(*bits)),
        (Type::Str, Value::Str(s)) => write_string(out, s),
        (Type::ObjectPath, Value::Str(s)) => {
            if annotate {
                out.push_str("objectpath ");
            }
            write_string(out, s);
        }
        (Type::Signature, Value::Str(s)) => {
            if annotate {
                out.push_str("signature ");
            }
            write_string(out, s);
        }
        (Type::Maybe(elem), Value::Maybe(inner)) => {
            // A maybe states no type of its own in either literal it has, so an
            // annotated one carries its whole signature and its child then
            // prints bare.
            if annotate {
                out.push('@');
                out.push_str(&ty.signature());
                out.push(' ');
            }
            // Walk the chain of nested maybes to its end. A chain that reaches a
            // value prints that value alone, since the type states how many
            // levels are set. A chain that ends at `nothing` states the set
            // levels itself, with one `just ` for each of them.
            let mut set = 0usize;
            let mut elem: &Type = elem;
            let mut inner: &Option<Box<Value>> = inner;
            while let Some(child) = inner {
                set += 1;
                match (elem, &**child) {
                    (Type::Maybe(next), Value::Maybe(rest)) => {
                        elem = next.as_ref();
                        inner = rest;
                    }
                    _ => return write_value(out, elem, child, false),
                }
            }
            for _ in 0..set {
                out.push_str("just ");
            }
            out.push_str("nothing");
        }
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

/// Write an integer, prefixed by `keyword` when annotated.
fn write_number(out: &mut String, annotate: bool, keyword: &str, value: impl std::fmt::Display) {
    if annotate {
        out.push_str(keyword);
        out.push(' ');
    }
    write!(out, "{value}").expect("writing to a String cannot fail");
}

/// Write a `d` value. The literal states its own type, so it carries no
/// keyword: it is the `%.17g` rendering of the double, with `.0` appended when
/// that rendering holds none of `.`, `e`, `n`, and `N`, so the literal always
/// reads back as a double. The `n` withholds the suffix from `nan`, `-nan`,
/// `inf`, and `-inf`, the four renderings that carry one; `N` appears in no
/// rendering `format_g17` writes.
fn write_double(out: &mut String, value: f64) {
    let text = format_g17(value);
    if !text.contains(['.', 'e', 'n', 'N']) {
        out.push_str(&text);
        out.push_str(".0");
        return;
    }
    out.push_str(&text);
}

/// The C `%.17g` rendering of a double, which is the shortest of a fixed-point
/// and an exponent form at 17 significant digits, with the trailing zeros of the
/// fraction removed. The exponent form carries a sign and at least two digits.
fn format_g17(value: f64) -> String {
    /// The significant-digit count `%.17g` asks for.
    const PRECISION: i32 = 17;

    if value.is_nan() {
        // The sign bit is printed, so a not-a-number whose bits carry one comes
        // out as `-nan`.
        return if value.is_sign_negative() {
            "-nan".to_owned()
        } else {
            "nan".to_owned()
        };
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        };
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0".to_owned()
        } else {
            "0".to_owned()
        };
    }
    let scientific = format!("{:.*e}", (PRECISION - 1) as usize, value);
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("Rust's `e` format writes an exponent");
    let exponent: i32 = exponent.parse().expect("the exponent is an integer");
    /// The exponent range `%g` renders in fixed-point form.
    const FIXED_POINT: std::ops::Range<i32> = -4..PRECISION;

    if !FIXED_POINT.contains(&exponent) {
        let sign = if exponent < 0 { '-' } else { '+' };
        return format!(
            "{}e{sign}{:02}",
            trim_fraction(mantissa),
            exponent.unsigned_abs()
        );
    }
    let places = (PRECISION - 1 - exponent).max(0) as usize;
    trim_fraction(&format!("{value:.places$}"))
}

/// Remove a fixed-point rendering's trailing fraction zeros, and the decimal
/// point with them where nothing of the fraction is left.
fn trim_fraction(text: &str) -> String {
    if !text.contains('.') {
        return text.to_owned();
    }
    text.trim_end_matches('0').trim_end_matches('.').to_owned()
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

    /// The unannotated form, observed against `ostree summary -v`, which reports
    /// a metadata value the reader has already been told the name of.
    #[test]
    fn prints_the_unannotated_forms_recovered_from_the_tool() {
        let bare = |signature: &str, value: Value| {
            to_text_unannotated(&Type::parse(signature).unwrap(), &value).unwrap()
        };
        assert_eq!(bare("t", Value::U64(7)), "7");
        assert_eq!(bare("y", Value::Byte(0x2a)), "0x2a");
        assert_eq!(bare("b", Value::Bool(true)), "true");
        assert_eq!(bare("s", Value::Str("str".into())), "'str'");
        // An empty container prints its brackets alone, where the annotated form
        // carries the signature.
        assert_eq!(bare("ay", bytes(&[])), "[]");
        assert_eq!(bare("a{sv}", Value::Array(Vec::new())), "{}");
        assert_eq!(bare("ay", bytes(&[0x01, 0x02])), "[0x01, 0x02]");
        assert_eq!(
            bare(
                "as",
                Value::Array(vec![Value::Str("a".into()), Value::Str("b".into())])
            ),
            "['a', 'b']"
        );
        assert_eq!(
            bare(
                "(ts)",
                Value::Tuple(vec![Value::U64(1), Value::Str("s".into())])
            ),
            "(1, 's')"
        );
        // A variant child states no type of its own, so it is annotated even
        // inside an unannotated value.
        let deltas = Value::Array(vec![Value::Tuple(vec![
            Value::Str("from-to".into()),
            Value::variant(Type::parse("ay").unwrap(), bytes(&[0xeb, 0x57])),
        ])]);
        assert_eq!(bare("a{sv}", deltas), "{'from-to': <[byte 0xeb, 0x57]>}");
    }

    /// Build a maybe chain of `set` set levels over `inner`, or over `nothing`
    /// when `inner` is `None`. `maybe_chain(1, None)` is `just nothing`.
    fn maybe_chain(set: usize, inner: Option<Value>) -> Value {
        let mut value = inner.unwrap_or(Value::Maybe(None));
        for _ in 0..set {
            value = Value::Maybe(Some(Box::new(value)));
        }
        value
    }

    /// The maybe forms, each recovered from
    /// `ostree commit --add-metadata="k=@TYPE VALUE"` read back through
    /// `ostree show -B --print-metadata-key=k` against `ostree` 2026.1
    /// (`docs/format-reference.md`, "The GVariant text form").
    #[test]
    fn prints_the_just_prefix_of_a_nested_maybe() {
        let int = || Value::I32(5);
        let cases: &[(&str, Value, &str)] = &[
            // One level: the value alone, or `nothing`.
            ("mi", maybe_chain(1, Some(int())), "@mi 5"),
            ("mi", maybe_chain(0, None), "@mi nothing"),
            // Two levels. A set chain prints the value alone; a chain that ends
            // at `nothing` counts its set levels.
            ("mmi", maybe_chain(2, Some(int())), "@mmi 5"),
            ("mmi", maybe_chain(1, None), "@mmi just nothing"),
            ("mmi", maybe_chain(0, None), "@mmi nothing"),
            // Three and four levels.
            ("mmmi", maybe_chain(3, Some(int())), "@mmmi 5"),
            ("mmmi", maybe_chain(2, None), "@mmmi just just nothing"),
            ("mmmi", maybe_chain(1, None), "@mmmi just nothing"),
            ("mmmi", maybe_chain(0, None), "@mmmi nothing"),
            (
                "mmmmi",
                maybe_chain(3, None),
                "@mmmmi just just just nothing",
            ),
            // The element type does not change the rule.
            ("mms", maybe_chain(1, None), "@mms just nothing"),
            ("mmb", maybe_chain(2, Some(Value::Bool(true))), "@mmb true"),
            ("mmt", maybe_chain(1, None), "@mmt just nothing"),
            ("mmd", maybe_chain(1, None), "@mmd just nothing"),
            (
                "mmo",
                maybe_chain(2, Some(Value::Str("/a".into()))),
                "@mmo '/a'",
            ),
            ("mmg", maybe_chain(1, None), "@mmg just nothing"),
            // A maybe of a variant, of an array, and of the unit tuple.
            (
                "mmv",
                maybe_chain(2, Some(Value::variant(Type::I32, int()))),
                "@mmv <5>",
            ),
            ("mmv", maybe_chain(1, None), "@mmv just nothing"),
            // The maybe consumed the annotation, so the array it holds prints
            // unannotated and its first byte carries no keyword.
            ("mmay", maybe_chain(2, Some(bytes(&[0x01]))), "@mmay [0x01]"),
            ("mmay", maybe_chain(1, None), "@mmay just nothing"),
            (
                "mm()",
                maybe_chain(2, Some(Value::Tuple(vec![]))),
                "@mm() ()",
            ),
            ("mm()", maybe_chain(1, None), "@mm() just nothing"),
            // Inside an array: the first element carries the annotation, and
            // every element carries its own `just ` prefixes.
            (
                "ammi",
                Value::Array(vec![
                    maybe_chain(1, None),
                    maybe_chain(0, None),
                    maybe_chain(2, Some(int())),
                ]),
                "[@mmi just nothing, nothing, 5]",
            ),
            (
                "ammmi",
                Value::Array(vec![
                    maybe_chain(2, None),
                    maybe_chain(1, None),
                    maybe_chain(0, None),
                    maybe_chain(3, Some(int())),
                ]),
                "[@mmmi just just nothing, just nothing, nothing, 5]",
            ),
            // Inside a dict value, a lone dict entry, and a tuple member.
            (
                "a{smmi}",
                Value::Array(vec![
                    Value::Tuple(vec!["a".into(), maybe_chain(1, None)]),
                    Value::Tuple(vec!["b".into(), maybe_chain(0, None)]),
                    Value::Tuple(vec!["c".into(), maybe_chain(2, Some(int()))]),
                ]),
                "{'a': @mmi just nothing, 'b': nothing, 'c': 5}",
            ),
            (
                "{smmi}",
                Value::Tuple(vec!["a".into(), maybe_chain(1, None)]),
                "{'a', @mmi just nothing}",
            ),
            (
                "(mmimmimmi)",
                Value::Tuple(vec![
                    maybe_chain(1, None),
                    maybe_chain(0, None),
                    maybe_chain(2, Some(int())),
                ]),
                "(@mmi just nothing, @mmi nothing, @mmi 5)",
            ),
            (
                "(mmi)",
                Value::Tuple(vec![maybe_chain(1, None)]),
                "(@mmi just nothing,)",
            ),
            // A maybe whose child is a maybe inside an array keeps both rules.
            (
                "mammi",
                maybe_chain(1, Some(Value::Array(vec![maybe_chain(1, None)]))),
                "@mammi [just nothing]",
            ),
            (
                "mmammi",
                maybe_chain(2, Some(Value::Array(vec![maybe_chain(1, None)]))),
                "@mmammi [just nothing]",
            ),
            (
                "amm()",
                Value::Array(vec![
                    maybe_chain(1, None),
                    maybe_chain(2, Some(Value::Tuple(vec![]))),
                    maybe_chain(0, None),
                ]),
                "[@mm() just nothing, (), nothing]",
            ),
            (
                "ammay",
                Value::Array(vec![
                    maybe_chain(1, None),
                    maybe_chain(2, Some(bytes(b"x\0"))),
                    maybe_chain(0, None),
                ]),
                "[@mmay just nothing, b'x', nothing]",
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

    /// The `just ` prefixes are part of the value, so the unannotated form keeps
    /// them and drops only the signature.
    #[test]
    fn keeps_the_just_prefix_in_the_unannotated_form() {
        let bare = |signature: &str, value: Value| {
            to_text_unannotated(&Type::parse(signature).unwrap(), &value).unwrap()
        };
        assert_eq!(bare("mmi", maybe_chain(1, None)), "just nothing");
        assert_eq!(bare("mmmi", maybe_chain(2, None)), "just just nothing");
        assert_eq!(bare("mmi", maybe_chain(0, None)), "nothing");
        assert_eq!(bare("mmi", maybe_chain(2, Some(Value::I32(5)))), "5");
        assert_eq!(bare("mmy", maybe_chain(2, Some(Value::Byte(1)))), "0x01");
    }

    #[test]
    fn refuses_a_maybe_whose_chain_does_not_match_the_type() {
        // A `just` where the type states a plain element.
        let ty = Type::parse("mi").unwrap();
        assert!(to_text(&ty, &maybe_chain(2, Some(Value::I32(5)))).is_err());
        // A plain element where the type states another maybe.
        let ty = Type::parse("mmi").unwrap();
        assert!(to_text(&ty, &maybe_chain(1, Some(Value::I32(5)))).is_err());
        // A mismatched leaf below a set chain.
        let ty = Type::parse("mms").unwrap();
        assert!(to_text(&ty, &maybe_chain(2, Some(Value::I32(5)))).is_err());
    }

    #[test]
    fn refuses_a_value_that_does_not_match_the_type() {
        let ty = Type::parse("s").unwrap();
        assert!(to_text(&ty, &Value::Byte(1)).is_err());
        let ty = Type::parse("(ss)").unwrap();
        assert!(to_text(&ty, &Value::Tuple(vec!["a".into()])).is_err());
    }
}
