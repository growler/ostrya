//! The deb822 paragraph form the record files use.
//!
//! A file holds paragraphs separated by blank lines. A paragraph holds
//! `key: value` lines; a line starting with one space continues the value of
//! the preceding key, joined with a single space. A line whose first
//! non-blank character is `#` is a comment.

use std::path::{Path, PathBuf};

/// One `key: value` field, with the line it started on.
#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub value: String,
    pub line: usize,
}

/// One paragraph: the fields in file order.
#[derive(Clone, Debug)]
pub struct Paragraph {
    pub file: PathBuf,
    pub line: usize,
    pub fields: Vec<Field>,
}

impl Paragraph {
    /// The value of `name`, or `None` when the paragraph has no such field.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.value.as_str())
    }

    /// The whitespace-separated values of `name`, empty when absent.
    pub fn list(&self, name: &str) -> Vec<&str> {
        self.get(name)
            .map(|value| value.split_whitespace().collect())
            .unwrap_or_default()
    }

    /// The line `name` starts on, for an error message.
    pub fn field_line(&self, name: &str) -> usize {
        self.fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.line)
            .unwrap_or(self.line)
    }

    /// `file:line`, the prefix of every message about this paragraph.
    pub fn origin(&self) -> String {
        format!("{}:{}", self.file.display(), self.line)
    }
}

/// A syntax error, carrying the position that produced it.
#[derive(Debug)]
pub struct ParseError {
    pub file: PathBuf,
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.file.display(), self.line, self.message)
    }
}

/// Split `text` into paragraphs.
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
