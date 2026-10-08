//! The JSON document of `--format json`, which [`grids`](crate::report::grids) reads.
//!
//! [`Json`] holds the part of JSON that a report uses: objects with ordered
//! keys, arrays, strings, integers, booleans, and null. A report holds no
//! floating-point number, so [`Json::render`] writes none and [`parse`] refuses
//! one.

use std::fmt::Write as _;

/// A JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer in the range of `i64`.
    Int(i64),
    /// A string.
    Str(String),
    /// An array, in document order.
    Array(Vec<Json>),
    /// An object, with its members in document order.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Creates an object from a list of members, in list order.
    pub fn object(fields: Vec<(&str, Json)>) -> Json {
        Json::Object(
            fields
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
        )
    }

    /// Creates a string value.
    pub fn string(text: impl Into<String>) -> Json {
        Json::Str(text.into())
    }

    /// Returns the first member named `name` of an object, or `None`.
    ///
    /// If `self` is not an object, the result is `None`.
    pub fn get(&self, name: &str) -> Option<&Json> {
        match self {
            Json::Object(fields) => fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// Returns the text of a string value, or `""` for any other value.
    pub fn as_str(&self) -> &str {
        match self {
            Json::Str(text) => text,
            _ => "",
        }
    }

    /// Returns the items of an array value, or an empty slice for any other value.
    pub fn as_array(&self) -> &[Json] {
        match self {
            Json::Array(items) => items,
            _ => &[],
        }
    }

    /// Returns the value as indented JSON text with a trailing newline.
    ///
    /// Each level indents by two spaces. In a string, the function escapes `"`,
    /// `\`, newline, carriage return, and tab. It writes each other control
    /// character as `\uXXXX`, with lowercase hexadecimal digits.
    pub fn render(&self) -> String {
        let mut out = String::new();
        write_value(&mut out, self, 0);
        out.push('\n');
        out
    }
}

fn write_value(out: &mut String, value: &Json, depth: usize) {
    let pad = "  ".repeat(depth);
    let inner = "  ".repeat(depth + 1);
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Json::Int(number) => {
            let _ = write!(out, "{number}");
        }
        Json::Str(text) => write_string(out, text),
        Json::Array(items) if items.is_empty() => out.push_str("[]"),
        Json::Array(items) => {
            out.push_str("[\n");
            for (index, item) in items.iter().enumerate() {
                out.push_str(&inner);
                write_value(out, item, depth + 1);
                if index + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push(']');
        }
        Json::Object(fields) if fields.is_empty() => out.push_str("{}"),
        Json::Object(fields) => {
            out.push_str("{\n");
            for (index, (name, item)) in fields.iter().enumerate() {
                out.push_str(&inner);
                write_string(out, name);
                out.push_str(": ");
                write_value(out, item, depth + 1);
                if index + 1 < fields.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", character as u32);
            }
            character => out.push(character),
        }
    }
    out.push('"');
}

/// Parses a JSON document.
///
/// White space is space, tab, newline, and carriage return. A `\u` escape that
/// names no Unicode scalar value, for example one half of a surrogate pair,
/// gives U+FFFD.
///
/// # Errors
///
/// Each error is a `String` message. Most messages hold the byte offset of the
/// error.
///
/// - An error if the text ends where a value must start.
/// - An error if a byte starts no value, or a literal is not `null`, `true`, or
///   `false`.
/// - An error if a number is not an integer in the range of `i64`. A fraction or
///   an exponent gives an error at its first byte.
/// - An error if a string does not close, holds an unknown escape, or holds a
///   `\u` escape that is not followed by four hexadecimal digits.
/// - An error if an array or an object has no `,` between two items, or no
///   closing `]` or `}`.
/// - An error if an object member has no `:`.
/// - An error if text other than white space follows the value.
pub fn parse(text: &str) -> Result<Json, String> {
    let mut cursor = Cursor {
        bytes: text.as_bytes(),
        at: 0,
    };
    cursor.skip_space();
    let value = cursor.value()?;
    cursor.skip_space();
    if cursor.at != cursor.bytes.len() {
        return Err(format!("trailing text at byte {}", cursor.at));
    }
    Ok(value)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn skip_space(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(format!("expected `{}` at byte {}", byte as char, self.at))
        }
    }

    fn literal(&mut self, text: &str) -> Result<(), String> {
        if self.bytes[self.at..].starts_with(text.as_bytes()) {
            self.at += text.len();
            Ok(())
        } else {
            Err(format!("expected `{text}` at byte {}", self.at))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        match self.peek() {
            None => Err("document ends where a value was expected".to_owned()),
            Some(b'n') => self.literal("null").map(|()| Json::Null),
            Some(b't') => self.literal("true").map(|()| Json::Bool(true)),
            Some(b'f') => self.literal("false").map(|()| Json::Bool(false)),
            Some(b'"') => self.string().map(Json::Str),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(byte) if byte == b'-' || byte.is_ascii_digit() => self.integer(),
            Some(byte) => Err(format!(
                "byte {} at {} starts no value",
                byte as char, self.at
            )),
        }
    }

    fn integer(&mut self) -> Result<Json, String> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at])
            .map_err(|err| format!("number at byte {start}: {err}"))?;
        text.parse::<i64>()
            .map(Json::Int)
            .map_err(|err| format!("number {text:?} at byte {start}: {err}"))
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("string does not close".to_owned()),
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    let escape = self
                        .peek()
                        .ok_or_else(|| "string ends inside an escape".to_owned())?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = self
                                .bytes
                                .get(self.at..self.at + 4)
                                .ok_or_else(|| "short \\u escape".to_owned())?;
                            let hex = std::str::from_utf8(hex)
                                .map_err(|err| format!("\\u escape: {err}"))?;
                            let code = u32::from_str_radix(hex, 16)
                                .map_err(|err| format!("\\u escape: {err}"))?;
                            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                            self.at += 4;
                        }
                        other => {
                            return Err(format!("unknown escape `\\{}`", other as char));
                        }
                    }
                }
                Some(_) => {
                    let rest = std::str::from_utf8(&self.bytes[self.at..])
                        .map_err(|err| format!("string is not UTF-8: {err}"))?;
                    let character = rest.chars().next().expect("rest is non-empty");
                    out.push(character);
                    self.at += character.len_utf8();
                }
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_space();
            items.push(self.value()?);
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(format!("expected `,` or `]` at byte {}", self.at)),
            }
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut fields = Vec::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Json::Object(fields));
        }
        loop {
            self.skip_space();
            let name = self.string()?;
            self.skip_space();
            self.expect(b':')?;
            self.skip_space();
            fields.push((name, self.value()?));
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Object(fields));
                }
                _ => return Err(format!("expected `,` or `}}` at byte {}", self.at)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_round_trips() {
        let document = Json::object(vec![
            (
                "cells",
                Json::Array(vec![Json::object(vec![
                    ("id", Json::string("m10/init/mode=bare")),
                    ("verdict", Json::string("pass")),
                    ("elapsed-ms", Json::Int(12)),
                    ("reason", Json::Null),
                    ("quoted", Json::string("a \"line\"\nbreak")),
                ])]),
            ),
            ("summary", Json::object(vec![("pass", Json::Int(1))])),
        ]);
        let text = document.render();
        assert_eq!(parse(&text).expect("parses"), document);
    }
}
