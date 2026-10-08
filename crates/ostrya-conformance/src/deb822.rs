//! The deb822 paragraph format of the record files.
//!
//! [`parse`] reads a file into [`Paragraph`] values. [Format](parse#format)
//! gives the rules of the format.

use std::path::{Path, PathBuf};

/// A `key: value` field and the line on which it starts.
#[derive(Clone, Debug)]
pub struct Field {
    /// The name of the field, as written.
    pub name: String,
    /// The value of the field, with the continuation lines joined.
    pub value: String,
    /// The 1-based line on which the field starts.
    pub line: usize,
}

/// A paragraph of fields.
#[derive(Clone, Debug)]
pub struct Paragraph {
    /// The file that holds the paragraph.
    pub file: PathBuf,
    /// The 1-based line of the first field of the paragraph.
    pub line: usize,
    /// The fields, in file order.
    pub fields: Vec<Field>,
}

impl Paragraph {
    /// Returns the value of the first field named `name`, or `None` if there is none.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.value.as_str())
    }

    /// Returns the value of the field `name`, split at white space.
    ///
    /// If the paragraph has no field `name`, the vector is empty.
    pub fn list(&self, name: &str) -> Vec<&str> {
        self.get(name)
            .map(|value| value.split_whitespace().collect())
            .unwrap_or_default()
    }

    /// Returns the 1-based line of the field `name`, for an error message.
    ///
    /// If the paragraph has no field `name`, the line is the line of the first
    /// field of the paragraph.
    pub fn field_line(&self, name: &str) -> usize {
        self.fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.line)
            .unwrap_or(self.line)
    }

    /// Returns `file:line` of the paragraph, the prefix of each message about it.
    pub fn origin(&self) -> String {
        format!("{}:{}", self.file.display(), self.line)
    }
}

/// A syntax error in a deb822 file, with its position.
///
/// The error displays as `FILE:LINE: MESSAGE`.
#[derive(Debug)]
pub struct ParseError {
    /// The file that holds the error.
    pub file: PathBuf,
    /// The 1-based line of the error.
    pub line: usize,
    /// The description of the error.
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.file.display(), self.line, self.message)
    }
}

/// Parses the text of the file `file` into paragraphs.
///
/// # Format
///
/// - One or more blank lines separate two paragraphs.
/// - A paragraph holds `key: value` lines. The first `:` ends the key. The key
///   and the value lose their leading and trailing white space.
/// - A line that starts with a space continues the value of the field before
///   it. The function joins the value and the trimmed line with one space.
/// - A line whose first non-blank character is `#` is a comment. A comment
///   does not end a paragraph.
///
/// # Errors
///
/// The function stops at the first error and returns a [`ParseError`] with its
/// line.
///
/// - An error if a continuation line has no field before it in its paragraph.
/// - An error if a line holds no `:`.
/// - An error if a field name is empty.
/// - An error if a paragraph gives the same field name two times.
pub fn parse(file: &Path, text: &str) -> Result<Vec<Paragraph>, ParseError> {
    let mut paragraphs = Vec::new();
    let mut fields: Vec<Field> = Vec::new();
    let mut start = 0usize;

    let error = |line: usize, message: String| ParseError {
        file: file.to_path_buf(),
        line,
        message,
    };

    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;

        if raw.trim_start().starts_with('#') {
            continue;
        }
        if raw.trim().is_empty() {
            if !fields.is_empty() {
                paragraphs.push(Paragraph {
                    file: file.to_path_buf(),
                    line: start,
                    fields: std::mem::take(&mut fields),
                });
            }
            continue;
        }

        if let Some(rest) = raw.strip_prefix(' ') {
            let Some(field) = fields.last_mut() else {
                return Err(error(
                    number,
                    "continuation line with no field to continue".to_owned(),
                ));
            };
            field.value.push(' ');
            field.value.push_str(rest.trim());
            continue;
        }

        let Some((name, value)) = raw.split_once(':') else {
            return Err(error(
                number,
                format!("line holds no `key: value`: {raw:?}"),
            ));
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(error(number, format!("empty field name: {raw:?}")));
        }
        if fields.is_empty() {
            start = number;
        }
        if fields.iter().any(|field| field.name == name) {
            return Err(error(number, format!("field `{name}` is given twice")));
        }
        fields.push(Field {
            name: name.to_owned(),
            value: value.trim().to_owned(),
            line: number,
        });
    }

    if !fields.is_empty() {
        paragraphs.push(Paragraph {
            file: file.to_path_buf(),
            line: start,
            fields,
        });
    }
    Ok(paragraphs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuations_join_with_one_space() {
        let text = "family: M0\nnote: first\n second\n\nfamily: M1\n";
        let paragraphs = parse(Path::new("t"), text).expect("parses");
        assert_eq!(paragraphs.len(), 2);
        assert_eq!(paragraphs[0].get("note"), Some("first second"));
        assert_eq!(paragraphs[1].get("family"), Some("M1"));
    }

    #[test]
    fn a_repeated_field_is_an_error() {
        let text = "family: M0\nfamily: M1\n";
        assert!(parse(Path::new("t"), text).is_err());
    }

    #[test]
    fn a_comment_does_not_break_a_paragraph() {
        let text = "family: M0\n# a comment\ncorpus: C0\n";
        let paragraphs = parse(Path::new("t"), text).expect("parses");
        assert_eq!(paragraphs.len(), 1);
        assert_eq!(paragraphs[0].get("corpus"), Some("C0"));
    }
}
