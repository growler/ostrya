//! The reader of the shared AWS config file and credentials file.
//!
//! The syntax:
//!
//! - The file is UTF-8. A line ends with LF or CRLF.
//! - A blank line is skipped. A line whose first non-blank character is `#`
//!   or `;` is a comment. A comment cannot follow a value on its line.
//! - A line with no indent that starts with `[` opens a section. The name is
//!   the text between `[` and `]`, without the white space around it.
//! - A line with no indent in a section is a key and a value. It splits at the
//!   first `=` or `:`. The key is lowercased. White space around the key and
//!   around the value is removed.
//! - An indented line after a key with an empty value is a key and a value of
//!   a sub-section of that key, with the same split.
//!
//! These are refused, and the message names the file and the line:
//!
//! - a key before the first section
//! - an indented line after a key with a value, which continues that value
//! - an indented line with no key before it
//! - a malformed section header, or a line with no `=` and no `:`
//! - a section name twice in the file, or a key twice in a section or in a
//!   sub-section
//! - bytes that are not UTF-8
//!
//! No message holds a value, because a value can be a secret.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// One parsed file.
#[derive(Debug)]
pub(super) struct IniFile {
    /// The path of the file, for the messages.
    pub(super) path: PathBuf,
    sections: Vec<Section>,
}

/// One section of a file.
#[derive(Debug)]
pub(super) struct Section {
    pub(super) name: String,
    /// The line of the header, from 1.
    pub(super) line: usize,
    pub(super) entries: Vec<Entry>,
}

/// One key of a section.
#[derive(Debug)]
pub(super) struct Entry {
    pub(super) key: String,
    pub(super) value: String,
    /// The line of the key, from 1.
    pub(super) line: usize,
    /// The keys, the values, and the lines of the sub-section of the key.
    pub(super) sub: Vec<(String, String, usize)>,
}

impl IniFile {
    /// Returns the section named `name`.
    pub(super) fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|section| section.name == name)
    }
}

impl Section {
    /// Returns the entry of `key`.
    pub(super) fn entry(&self, key: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.key == key)
    }

    /// Returns the value of `key`, or `None` if the key is absent or its value
    /// is empty.
    pub(super) fn value(&self, key: &str) -> Option<&Entry> {
        self.entry(key).filter(|entry| !entry.value.is_empty())
    }
}

impl Entry {
    /// Returns the value and the line of `key` of the sub-section, or `None`
    /// if the key is absent or its value is empty.
    pub(super) fn sub_value(&self, key: &str) -> Option<(&str, usize)> {
        self.sub
            .iter()
            .find(|(k, v, _)| k == key && !v.is_empty())
            .map(|(_, v, line)| (v.as_str(), *line))
    }
}

/// Parses `bytes`, the content of the file at `path`.
pub(super) fn parse(path: &Path, bytes: &[u8]) -> Result<IniFile> {
    let refused =
        |line: usize, why: &str| Error::InvalidInput(format!("{}:{line}: {why}", path.display()));
    let text = std::str::from_utf8(bytes).map_err(|e| {
        let line = 1 + bytes[..e.valid_up_to()]
            .iter()
            .filter(|&&b| b == b'\n')
            .count();
        refused(line, "the line is not UTF-8")
    })?;
    let mut sections: Vec<Section> = Vec::new();
    // The section names of the file, the keys of the last section, and the
    // keys of the sub-section of the last key.
    let mut names: HashSet<&str> = HashSet::new();
    let mut keys: HashSet<String> = HashSet::new();
    let mut sub_keys: HashSet<String> = HashSet::new();
    for (index, raw) in text.split('\n').enumerate() {
        let line = index + 1;
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let indented = raw.starts_with([' ', '\t']);
        if !indented && trimmed.starts_with('[') {
            let name = trimmed
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| refused(line, "malformed section header"))?;
            if !names.insert(name) {
                return Err(refused(
                    line,
                    &format!("the section [{name}] is in the file twice"),
                ));
            }
            keys.clear();
            sub_keys.clear();
            sections.push(Section {
                name: name.to_owned(),
                line,
                entries: Vec::new(),
            });
            continue;
        }
        let Some(section) = sections.last_mut() else {
            return Err(refused(line, "a key comes before the first section"));
        };
        if indented {
            let Some(open) = section.entries.last_mut() else {
                return Err(refused(line, "an indented line has no key before it"));
            };
            if !open.value.is_empty() {
                return Err(refused(
                    line,
                    &format!(
                        "an indented line continues the value of the key '{}', \
                         and a value of more than one line is not read",
                        open.key
                    ),
                ));
            }
            let (key, value) = key_value(trimmed).map_err(|why| refused(line, why))?;
            if !sub_keys.insert(key.clone()) {
                return Err(refused(
                    line,
                    &format!(
                        "the key '{key}' is in the sub-section '{}' of the section [{}] twice",
                        open.key, section.name
                    ),
                ));
            }
            open.sub.push((key, value.to_owned(), line));
            continue;
        }
        let (key, value) = key_value(trimmed).map_err(|why| refused(line, why))?;
        if !keys.insert(key.clone()) {
            return Err(refused(
                line,
                &format!("the key '{key}' is in the section [{}] twice", section.name),
            ));
        }
        sub_keys.clear();
        section.entries.push(Entry {
            key,
            value: value.to_owned(),
            line,
            sub: Vec::new(),
        });
    }
    Ok(IniFile {
        path: path.to_owned(),
        sections,
    })
}

/// Splits `line` at its first `=` or `:`, and returns the lowercased key and
/// the value, each without the white space around it, or the reason of its
/// refusal.
fn key_value(line: &str) -> std::result::Result<(String, &str), &'static str> {
    let at = line
        .find(['=', ':'])
        .ok_or("the line has no '=' and no ':'")?;
    let key = line[..at].trim().to_ascii_lowercase();
    if key.is_empty() {
        return Err("the line has no key");
    }
    Ok((key, line[at + 1..].trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> IniFile {
        parse(Path::new("/aws/config"), text.as_bytes()).unwrap()
    }

    fn refused(text: &[u8]) -> String {
        match parse(Path::new("/aws/config"), text) {
            Err(Error::InvalidInput(msg)) => msg,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn each_accepted_construct_is_read() {
        let file = parsed(
            "# a comment\r\n\
             ; another comment\n\
             \n\
             [default]\n\
             Region = eu-west-1 \n\
             output: json\n\
             empty =\n\
             value = a=b:c # not a comment\n\
             \x20 # an indented comment\n\
             [ profile dev ]\r\n\
             s3 =\n\
             \x20 addressing_style = path\n\
             \tEndpoint_URL : http://localhost:9000\n\
             \n\
             region = us-east-2\n\
             [unknown]\n\
             x = y\n",
        );
        let default = file.section("default").unwrap();
        assert_eq!(default.line, 4);
        assert_eq!(default.value("region").unwrap().value, "eu-west-1");
        assert_eq!(default.value("region").unwrap().line, 5);
        assert_eq!(default.value("output").unwrap().value, "json");
        assert!(default.entry("empty").is_some());
        assert!(default.value("empty").is_none());
        assert_eq!(
            default.value("value").unwrap().value,
            "a=b:c # not a comment"
        );
        let dev = file.section("profile dev").unwrap();
        let s3 = dev.entry("s3").unwrap();
        assert_eq!(s3.sub_value("addressing_style"), Some(("path", 12)));
        assert_eq!(
            s3.sub_value("endpoint_url"),
            Some(("http://localhost:9000", 13))
        );
        assert_eq!(dev.value("region").unwrap().value, "us-east-2");
        assert!(file.section("unknown").is_some());
        assert!(file.section("dev").is_none());
        assert_eq!(file.path, Path::new("/aws/config"));
    }

    #[test]
    fn an_empty_file_has_no_section() {
        assert!(parsed("").section("default").is_none());
    }

    #[test]
    fn each_refusal_names_the_file_and_the_line() {
        let cases: &[(&[u8], &str)] = &[
            (b"region = x\n", "/aws/config:1: a key comes before"),
            (
                b"[default]\nregion = x\n  more\n",
                "/aws/config:3: an indented line continues",
            ),
            (
                b"[default]\nregion = x\n  key = more\n",
                "/aws/config:3: an indented line continues",
            ),
            (
                b"[default]\n  key = x\n",
                "/aws/config:2: an indented line has no key",
            ),
            (b"  key = x\n", "/aws/config:1: a key comes before"),
            (b"[default\n", "/aws/config:1: malformed section header"),
            (b"[]\n", "/aws/config:1: malformed section header"),
            (b"[a] x\n", "/aws/config:1: malformed section header"),
            (b"[default]\njunk\n", "/aws/config:2: the line has no '='"),
            (b"[default]\n= x\n", "/aws/config:2: the line has no key"),
            (
                b"[a]\n[b]\n[a]\n",
                "/aws/config:3: the section [a] is in the file twice",
            ),
            (
                b"[a]\nkey = 1\nKEY = 2\n",
                "/aws/config:3: the key 'key' is in the section [a] twice",
            ),
            (
                b"[a]\ns3 =\n  k = 1\n  k = 2\n",
                "/aws/config:4: the key 'k' is in the sub-section 's3'",
            ),
            (b"[a]\ns3 =\n  k\n", "/aws/config:3: the line has no '='"),
            (
                b"[a]\nk = v\n\xff\n",
                "/aws/config:3: the line is not UTF-8",
            ),
        ];
        for (text, want) in cases {
            let msg = refused(text);
            assert!(
                msg.starts_with(want),
                "{:?}: {msg}",
                String::from_utf8_lossy(text)
            );
        }
    }

    #[test]
    fn a_file_near_1_mib_of_names_is_read() {
        use std::fmt::Write;

        // Each case is a head, then one line for each name up to about
        // 1 MiB, then the first name again.
        let cases = [
            ("", "[s{n}]\n"),
            ("[a]\n", "k{n}=v\n"),
            ("[a]\ns3 =\n", " k{n}=v\n"),
        ];
        for (head, form) in cases {
            let mut text = head.to_owned();
            let mut n = 0;
            while text.len() < 1_000_000 {
                writeln!(text, "{}", form.replace("{n}", &n.to_string()).trim_end()).unwrap();
                n += 1;
            }
            assert!(n > 90_000 && text.len() < 1 << 20, "{n} {}", text.len());
            let file = parsed(&text);
            assert!(
                file.section(if head.is_empty() { "s0" } else { "a" })
                    .is_some()
            );
            let lines = text.lines().count();
            text.push_str(&form.replace("{n}", "0"));
            let msg = refused(text.as_bytes());
            assert!(
                msg.starts_with(&format!("/aws/config:{}: the ", lines + 1))
                    && msg.contains("twice"),
                "{msg}"
            );
        }
    }

    #[test]
    fn no_refusal_holds_a_value() {
        let msg = refused(b"[a]\nkey = SECRETVALUE\n  SECRETVALUE2 = x\n");
        assert!(!msg.contains("SECRET"), "{msg}");
    }
}
