use std::fmt::Write as _;

use crate::{Error, Result, Type, Value};

/// Renders `value` of type `ty` in the GVariant text form.
///
/// The text form is the form that the GLib printer writes, and [`from_text`]
/// reads it back. The rules come from observation of `ostree show --raw`,
/// `ostree show --print-metadata-key`, and `ostree show --print-variant-type`.
///
/// # Type annotations
///
/// - If the literal of a value does not state its type, the value carries a
///   type annotation: `byte 0x2a`, `uint32 42`, `uint64 42`. A boolean, an `i`
///   integer, a double, and a string state their own type and carry no
///   annotation.
/// - If a container holds one or more elements, its first element carries the
///   annotation. The elements after the first element print with no
///   annotation. A tuple annotates every member, because the members of a
///   tuple do not share a type.
/// - An empty container carries its own signature, because no element can
///   carry the annotation: `@ay []`, `@a(say) []`, `@a{sv} {}`.
/// - A variant prints as `<child>`. The child always carries an annotation,
///   because a variant states no child type of its own.
/// - An annotated maybe carries its whole signature, because neither literal
///   of a maybe states a type. The value in the maybe then prints with no
///   annotation: `@mmay [0x01]`.
///
/// # Containers
///
/// - If the last byte of a byte array is the only NUL in the array, the array
///   prints as a bytestring literal, `b'user.foo'`. This literal states its own
///   type, so it carries no annotation. Every other byte array prints as
///   `[byte 0x01, 0x02]`.
/// - An array of dict entries prints as one list of `key: value` pairs in
///   braces. A dict entry outside an array prints as `{key, value}`, with a
///   comma.
/// - A tuple with one member keeps a trailing comma: `(byte 0x01,)`.
/// - A maybe prints the value that it holds and nothing else. The type of the
///   maybe states how many maybe levels enclose that value. If a
///   chain of nested maybes ends at `nothing`, the text has one `just ` for
///   each set level of the chain: `@mmi nothing`, `@mmi just nothing`,
///   `@mmi 5`.
///
/// # Literals
///
/// - A double prints as the C `%.17g` rendering. If that text holds none of
///   `.`, `e`, `n`, and `N`, a `.0` suffix follows, so the literal reads back
///   as a double.
/// - A string prints in single quotes, or in double quotes if it holds a single
///   quote. Of the printable characters, only the backslash and the quote in
///   use get an escape. A control character prints as `\a`, `\b`, `\f`, `\n`,
///   `\r`, `\t`, or `\v` if it has that short form, and as `\uXXXX` otherwise.
///   All other characters, ASCII or not, print unchanged.
/// - A bytestring literal uses the C escape rules. The backslash and the double
///   quote always get an escape. `\b`, `\f`, `\n`, `\r`, `\t`, and `\v` use
///   their short form, and every other byte outside printable ASCII gets a
///   three-digit octal escape: `b'\377'`. A single quote gets no escape, and
///   the literal uses double quotes if the content holds one.
///
/// # Errors
///
/// - [`Error::TypeMismatch`] if `value` does not match `ty`. The pairing rules
///   are the rules of [`to_bytes`].
///
/// [`from_text`]: crate::from_text
/// [`to_bytes`]: crate::to_bytes
pub fn to_text(ty: &Type, value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(&mut out, ty, value, true)?;
    Ok(out)
}

/// Renders `value` of type `ty` in the GVariant text form with no annotations.
///
/// This function uses the rules of [`to_text`] and leaves out every
/// annotation:
///
/// - A byte, an integer, a handle, an object path, and a signature print with
///   no type keyword.
/// - An empty container prints as `[]` or `{}`, with no signature.
/// - The members of a tuple print with no annotation.
/// - A maybe prints with no signature.
///
/// The child of a variant still carries an annotation, because a variant
/// states no child type of its own. The `just ` prefixes of a nested maybe are
/// part of the value, so this form keeps them.
///
/// A report that names the value before it prints the value uses this form.
/// `ostree summary -v` prints metadata values in this form.
///
/// # Errors
///
/// - [`Error::TypeMismatch`] if `value` does not match `ty`.
pub fn to_text_unannotated(ty: &Type, value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(&mut out, ty, value, false)?;
    Ok(out)
}

/// Writes one value.
///
/// If `annotate` is set and the literal does not state its type, the value
/// carries an annotation.
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
            // Neither literal of a maybe states a type, so an annotated maybe
            // carries its whole signature. Its child then prints with no
            // annotation.
            if annotate {
                out.push('@');
                out.push_str(&ty.signature());
                out.push(' ');
            }
            // The loop walks the chain of nested maybes to its end. If the
            // chain reaches a value, it prints that value alone, because the
            // type states how many levels are set. If the chain ends at
            // `nothing`, it writes one `just ` for each set level.
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

/// Writes an integer.
///
/// If `annotate` is set, `keyword` comes before the integer.
fn write_number(out: &mut String, annotate: bool, keyword: &str, value: impl std::fmt::Display) {
    if annotate {
        out.push_str(keyword);
        out.push(' ');
    }
    write!(out, "{value}").expect("writing to a String cannot fail");
}

/// Writes a `d` value.
///
/// The literal states its own type, so it carries no keyword. The literal is
/// the `%.17g` rendering of the double. If that rendering holds none of `.`,
/// `e`, `n`, and `N`, the function appends `.0`, so the literal always reads
/// back as a double.
///
/// The `n` in the check keeps the suffix off `nan`, `-nan`, `inf`, and `-inf`.
/// These four renderings are the renderings that hold an `n`. No rendering
/// that `format_g17` writes holds an `N`.
fn write_double(out: &mut String, value: f64) {
    let text = format_g17(value);
    if !text.contains(['.', 'e', 'n', 'N']) {
        out.push_str(&text);
        out.push_str(".0");
        return;
    }
    out.push_str(&text);
}

/// Returns the C `%.17g` rendering of a double.
///
/// The rendering has 17 significant digits. If the decimal exponent is in the
/// range `-4..17`, the rendering uses the fixed-point form. Otherwise, it uses
/// the exponent form. The function removes the trailing zeros of the fraction.
/// The exponent carries a sign and at least two digits.
fn format_g17(value: f64) -> String {
    /// The number of significant digits that `%.17g` asks for.
    const PRECISION: i32 = 17;

    if value.is_nan() {
        // The rendering prints the sign bit. If the sign bit of a
        // not-a-number is set, the rendering is `-nan`.
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
    /// The range of exponents that `%g` renders in fixed-point form.
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

/// Removes the trailing zeros of the fraction in a fixed-point rendering.
///
/// If no digit of the fraction is left, the function also removes the decimal
/// point.
fn trim_fraction(text: &str) -> String {
    if !text.contains('.') {
        return text.to_owned();
    }
    text.trim_end_matches('0').trim_end_matches('.').to_owned()
}

/// Writes an empty container.
///
/// If `annotate` is set, the output is `@signature literal`, because no element
/// can carry the annotation. If `annotate` is not set, the output is `literal`
/// alone.
fn write_empty(out: &mut String, ty: &Type, annotate: bool, literal: &str) {
    if annotate {
        out.push('@');
        out.push_str(&ty.signature());
        out.push(' ');
    }
    out.push_str(literal);
}

/// Writes the key and the value of a dict entry, with `separator` between them.
///
/// The caller writes the braces. An array of entries puts one pair of braces
/// around the whole list and uses `": "` as the separator. A lone entry puts
/// braces around itself and uses `", "`.
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

/// Returns `true` if a byte array prints as a bytestring literal.
///
/// The array must end in a NUL and hold no other NUL. The bytes before that
/// NUL are the content of the literal.
fn is_bytestring(bytes: &[u8]) -> bool {
    match bytes.split_last() {
        Some((0, rest)) => !rest.contains(&0),
        _ => false,
    }
}

/// Writes a bytestring literal, `b'...'`, from `content`.
///
/// `content` is the byte array without its terminating NUL. The bytestring
/// form uses the C escape rules. The string form uses other rules (see
/// `write_string`). The C escape rules are:
///
/// - A backslash and a double quote always get an escape.
/// - `\b`, `\f`, `\n`, `\r`, `\t`, and `\v` use their short form.
/// - Every other byte outside the printable ASCII range gets a three-digit
///   octal escape.
///
/// A single quote never gets an escape. If `content` holds a single quote, the
/// literal uses double quotes.
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

/// Writes a string literal.
///
/// The literal uses single quotes by default. If the string holds a single
/// quote, the literal uses double quotes, and that quote needs no escape. Of
/// the printable characters, only the backslash and the quote in use get an
/// escape, so `"` stays literal inside single quotes.
/// If a control character has a short escape, it uses that escape. Every other
/// control character uses `\uXXXX`. All other characters, ASCII or not, go
/// into the output unchanged.
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

    /// Prints a value of the type that `signature` names.
    ///
    /// A mismatch causes a panic.
    fn text(signature: &str, value: Value) -> String {
        to_text(&Type::parse(signature).unwrap(), &value).unwrap()
    }

    fn bytes(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }

    /// Each case is one form that `ostree` 2026.1 writes for
    /// `ostree show --print-variant-type=TYPE`, `show --raw`, or
    /// `show --print-metadata-key`.
    #[test]
    fn prints_the_forms_recovered_from_the_tool() {
        let cases: &[(&str, Value, &str)] = &[
            // If the literal of a scalar does not state the type, the scalar
            // carries an annotation. A boolean and a string state their own.
            ("b", Value::Bool(false), "false"),
            ("b", Value::Bool(true), "true"),
            ("y", Value::Byte(0x2a), "byte 0x2a"),
            ("y", Value::Byte(0x09), "byte 0x09"),
            ("u", Value::U32(16909060), "uint32 16909060"),
            ("t", Value::U64(1700000000), "uint64 1700000000"),
            ("s", Value::Str("abc".into()), "'abc'"),
            // Byte arrays. If the only NUL is the last byte, the array prints
            // as a bytestring. An empty array prints its signature. Any other
            // array prints as a list of elements.
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
            // Only the first element of a container carries the annotation.
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
            // A dict prints its entries as one list in braces. A lone entry
            // puts a comma between its key and its value.
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
            // A tuple annotates every member. A one-member tuple keeps a
            // trailing comma.
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
            // A variant states no child type, so the child always carries an
            // annotation.
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

    /// The string escapes, each observed in `show --print-variant-type=s`.
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

    /// A byteswap changes the big-endian fields of the on-disk format into the
    /// numbers that they name.
    ///
    /// The byteswap does not change other fields.
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

    /// The unannotated form, observed in `ostree summary -v`.
    ///
    /// That command reports a metadata value after it gives the name of the
    /// value to the reader.
    #[test]
    fn prints_the_unannotated_forms_recovered_from_the_tool() {
        let bare = |signature: &str, value: Value| {
            to_text_unannotated(&Type::parse(signature).unwrap(), &value).unwrap()
        };
        assert_eq!(bare("t", Value::U64(7)), "7");
        assert_eq!(bare("y", Value::Byte(0x2a)), "0x2a");
        assert_eq!(bare("b", Value::Bool(true)), "true");
        assert_eq!(bare("s", Value::Str("str".into())), "'str'");
        // An empty container prints its brackets alone. The annotated form
        // adds the signature.
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
        // A variant child states no type of its own, so it carries an
        // annotation even inside an unannotated value.
        let deltas = Value::Array(vec![Value::Tuple(vec![
            Value::Str("from-to".into()),
            Value::variant(Type::parse("ay").unwrap(), bytes(&[0xeb, 0x57])),
        ])]);
        assert_eq!(bare("a{sv}", deltas), "{'from-to': <[byte 0xeb, 0x57]>}");
    }

    /// Builds a maybe chain of `set` set levels over `inner`.
    ///
    /// If `inner` is `None`, the chain ends at `nothing`.
    /// `maybe_chain(1, None)` is `just nothing`.
    fn maybe_chain(set: usize, inner: Option<Value>) -> Value {
        let mut value = inner.unwrap_or(Value::Maybe(None));
        for _ in 0..set {
            value = Value::Maybe(Some(Box::new(value)));
        }
        value
    }

    /// The maybe forms, each observed in `ostree` 2026.1.
    ///
    /// Each form comes from `ostree commit --add-metadata="k=@TYPE VALUE"`,
    /// and `ostree show -B --print-metadata-key=k` reads it back.
    #[test]
    fn prints_the_just_prefix_of_a_nested_maybe() {
        let int = || Value::I32(5);
        let cases: &[(&str, Value, &str)] = &[
            // One level: the value alone, or `nothing`.
            ("mi", maybe_chain(1, Some(int())), "@mi 5"),
            ("mi", maybe_chain(0, None), "@mi nothing"),
            // Two levels. A set chain prints the value alone. A chain that
            // ends at `nothing` counts its set levels.
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
            // The maybe carries the annotation, so the array in the maybe
            // prints with no annotation and its first byte carries no keyword.
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

    /// The unannotated form keeps the `just ` prefixes.
    ///
    /// The prefixes are part of the value. The form drops only the signature.
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
        // A mismatched leaf under a set chain.
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
