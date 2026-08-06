//! A GKeyFile/INI subset parser for the repository `config` file.
//!
//! The repository config is a GLib key file: `[group]` headers, `key=value`
//! entries, `#` comment lines, and blank lines. Parsing keeps the group and
//! key order and the raw value text, so a parsed file re-serializes in the
//! order the `ostree` tool wrote it. Line classification, the whitespace
//! trimmed around a key, and a value's leading-whitespace trim all use ASCII
//! space and tab only; a value's trailing whitespace and any non-ASCII
//! whitespace such as a non-breaking space are kept. A group header names the
//! text from `[` to the first `]`, with only whitespace allowed after it.
//! Comment and blank lines are dropped, and a repeated group header merges
//! into the existing group; [`Display`](std::fmt::Display) output reparses to
//! an equal [`KeyFile`].
//!
//! [`KeyFile::get_value`] returns the raw value; the typed accessors apply
//! the GLib string-unescaping and list-splitting rules on read.
//! [`KeyFile::set_value`] takes a raw value and rejects group names, keys, and
//! values whose structural characters would not survive a re-parse;
//! [`KeyFile::set_string`] escapes a value the way the tool does on write.
//! [`KeyFile::remove_key`] and [`KeyFile::remove_group`] are the write side's
//! other half: a rewritten document keeps the groups and keys the caller did
//! not touch, in the order it read them, and drops the comment and blank lines
//! the input carried, which is what the tool's own rewrite does.

use crate::error::{Error, Result};

/// A parsed key file: an ordered list of groups, each an ordered list of
/// (key, raw value) entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyFile {
    groups: Vec<Group>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Group {
    name: String,
    entries: Vec<(String, String)>,
}

impl KeyFile {
    /// Parse a key file from text.
    pub fn parse(input: &str) -> Result<KeyFile> {
        let mut groups: Vec<Group> = Vec::new();
        let mut current: Option<usize> = None;

        // Split on '\n'; a trailing newline leaves a final empty segment that
        // is not a line. One trailing carriage return is stripped per raw
        // line, so CRLF input is accepted and a doubled CR keeps one.
        let body = input.strip_suffix('\n').unwrap_or(input);
        for (n, raw) in body.split('\n').enumerate() {
            let lineno = n + 1;
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            let trimmed = line.trim_matches(ASCII_WS);
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix('[') {
                // The group name runs from '[' to the first ']'; only
                // whitespace may follow the ']', and the name may not contain
                // '[' or ']'. This mirrors [`validate_group`] so a header the
                // tool rejects does not parse cleanly here either.
                let Some(close) = rest.find(']') else {
                    return Err(Error::KeyFile(format!(
                        "line {lineno}: group header is not closed with ']'"
                    )));
                };
                if !rest[close + 1..].trim_matches(ASCII_WS).is_empty() {
                    return Err(Error::KeyFile(format!(
                        "line {lineno}: group header has trailing text after ']'"
                    )));
                }
                let name = &rest[..close];
                if name.is_empty() {
                    return Err(Error::KeyFile(format!("line {lineno}: empty group name")));
                }
                if name.contains(['[', ']']) {
                    return Err(Error::KeyFile(format!(
                        "line {lineno}: group name '{name}' contains '[' or ']'"
                    )));
                }
                current = Some(match groups.iter().position(|g| g.name == name) {
                    Some(i) => i,
                    None => {
                        groups.push(Group {
                            name: name.to_string(),
                            entries: Vec::new(),
                        });
                        groups.len() - 1
                    }
                });
                continue;
            }
            let Some(eq) = line.find('=') else {
                return Err(Error::KeyFile(format!(
                    "line {lineno}: expected a key=value pair"
                )));
            };
            let key = line[..eq].trim_matches(ASCII_WS);
            // The tool trims leading whitespace after `=` and keeps trailing
            // whitespace as part of the value.
            let value = line[eq + 1..].trim_start_matches(ASCII_WS);
            if key.is_empty() {
                return Err(Error::KeyFile(format!("line {lineno}: empty key")));
            }
            let Some(idx) = current else {
                return Err(Error::KeyFile(format!(
                    "line {lineno}: key '{key}' precedes any group"
                )));
            };
            let entries = &mut groups[idx].entries;
            match entries.iter_mut().find(|(k, _)| k == key) {
                Some(entry) => entry.1 = value.to_string(),
                None => entries.push((key.to_string(), value.to_string())),
            }
        }
        Ok(KeyFile { groups })
    }

    /// Whether a group is present.
    pub fn has_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g.name == group)
    }

    /// Iterate group names in file order.
    pub fn groups(&self) -> impl Iterator<Item = &str> {
        self.groups.iter().map(|g| g.name.as_str())
    }

    fn find(&self, group: &str, key: &str) -> Option<&str> {
        self.groups
            .iter()
            .find(|g| g.name == group)?
            .entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The raw (still-escaped) value for a key, or `None` if absent.
    pub fn get_value(&self, group: &str, key: &str) -> Option<&str> {
        self.find(group, key)
    }

    /// The unescaped string value for a key.
    pub fn get_string(&self, group: &str, key: &str) -> Result<Option<String>> {
        self.find(group, key).map(unescape).transpose()
    }

    /// A boolean value: one of `true`, `false`, `1`, or `0`, matched exactly.
    pub fn get_bool(&self, group: &str, key: &str) -> Result<Option<bool>> {
        match self.find(group, key) {
            None => Ok(None),
            Some("true") | Some("1") => Ok(Some(true)),
            Some("false") | Some("0") => Ok(Some(false)),
            Some(other) => Err(Error::KeyFile(format!(
                "value '{other}' for {group}.{key} is not a boolean"
            ))),
        }
    }

    /// A signed integer value.
    pub fn get_integer(&self, group: &str, key: &str) -> Result<Option<i64>> {
        match self.find(group, key) {
            None => Ok(None),
            Some(v) => v.parse::<i64>().map(Some).map_err(|_| {
                Error::KeyFile(format!("value '{v}' for {group}.{key} is not an integer"))
            }),
        }
    }

    /// A `;`-separated list of unescaped strings. A trailing separator does not
    /// produce a final empty element.
    pub fn get_string_list(&self, group: &str, key: &str) -> Result<Option<Vec<String>>> {
        match self.find(group, key) {
            None => Ok(None),
            Some(v) => split_list(v).map(Some),
        }
    }

    /// Set a key's raw value, creating the group if needed and preserving the
    /// position of an existing key.
    ///
    /// The group name, key, and value are validated so the serialized form
    /// reparses to an equal `KeyFile`: a group name may not be empty or
    /// contain `[`, `]`, or a newline; a key may not be empty, contain `=` or
    /// a newline, carry leading or trailing whitespace, or begin with `#` or
    /// `[`; a value may not contain a newline or begin with whitespace.
    pub fn set_value(&mut self, group: &str, key: &str, value: &str) -> Result<()> {
        validate_group(group)?;
        validate_key(key)?;
        validate_value(value)?;
        let idx = match self.groups.iter().position(|g| g.name == group) {
            Some(i) => i,
            None => {
                self.groups.push(Group {
                    name: group.to_string(),
                    entries: Vec::new(),
                });
                self.groups.len() - 1
            }
        };
        let entries = &mut self.groups[idx].entries;
        match entries.iter_mut().find(|(k, _)| k == key) {
            Some(entry) => entry.1 = value.to_string(),
            None => entries.push((key.to_string(), value.to_string())),
        }
        Ok(())
    }

    /// Set a key to a string value, applying the escaping the tool uses on
    /// write so a value that contains a newline, carriage return, backslash,
    /// or leading whitespace is stored in a form that reparses. This is the
    /// inverse of [`get_string`](KeyFile::get_string). Use
    /// [`set_value`](KeyFile::set_value) to store an already-escaped raw value.
    pub fn set_string(&mut self, group: &str, key: &str, value: &str) -> Result<()> {
        self.set_value(group, key, &escape(value))
    }

    /// Remove one key, reporting whether it was there.
    ///
    /// The group stays, even when the removed key was its last: the tool leaves
    /// the header of an emptied group in place, and
    /// [`Display`](std::fmt::Display) writes it back with no entries.
    pub fn remove_key(&mut self, group: &str, key: &str) -> bool {
        let Some(entries) = self
            .groups
            .iter_mut()
            .find(|g| g.name == group)
            .map(|g| &mut g.entries)
        else {
            return false;
        };
        let Some(index) = entries.iter().position(|(k, _)| k == key) else {
            return false;
        };
        entries.remove(index);
        true
    }

    /// Remove a group and every key in it, reporting whether it was there.
    ///
    /// The remaining groups keep their order.
    pub fn remove_group(&mut self, group: &str) -> bool {
        let Some(index) = self.groups.iter().position(|g| g.name == group) else {
            return false;
        };
        self.groups.remove(index);
        true
    }
}

/// The whitespace the tool trims: ASCII space and tab only. Recovered by
/// feeding the tool crafted config files -- a line of only spaces or only tabs
/// is ignored, a leading space or tab before a header or comment is stripped,
/// and a surrounding space or tab is removed from a key, while a non-breaking
/// space (U+00A0) or other non-ASCII whitespace is preserved everywhere.
const ASCII_WS: [char; 2] = [' ', '\t'];

/// A structural character must not appear where it would change how the text
/// reparses.
fn validate_group(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::KeyFile("group name is empty".into()));
    }
    if name.contains(['\n', '\r', '[', ']']) {
        return Err(Error::KeyFile(format!(
            "group name '{name}' contains a structural character"
        )));
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::KeyFile("key is empty".into()));
    }
    if key.starts_with(ASCII_WS) || key.ends_with(ASCII_WS) {
        return Err(Error::KeyFile(format!(
            "key '{key}' has leading or trailing whitespace"
        )));
    }
    if key.contains(['\n', '\r', '=']) {
        return Err(Error::KeyFile(format!(
            "key '{key}' contains a structural character"
        )));
    }
    if key.starts_with('#') || key.starts_with('[') {
        return Err(Error::KeyFile(format!(
            "key '{key}' begins with '#' or '[' and would not reparse"
        )));
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<()> {
    if value.contains(['\n', '\r']) {
        return Err(Error::KeyFile(
            "value contains a newline; escape it as \\n".into(),
        ));
    }
    if value.starts_with([' ', '\t']) {
        return Err(Error::KeyFile(
            "value begins with whitespace; escape it as \\s".into(),
        ));
    }
    Ok(())
}

/// Serialize in file order, matching GLib's layout: a blank line separates
/// groups, each entry is `key=value`. Use `.to_string()` (via `Display`).
impl std::fmt::Display for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, group) in self.groups.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            writeln!(f, "[{}]", group.name)?;
            for (key, value) in &group.entries {
                writeln!(f, "{key}={value}")?;
            }
        }
        Ok(())
    }
}

/// Apply the tool's write escaping to a string value. Recovered by driving
/// `ostree config set` with crafted values and reading the raw config bytes:
/// a backslash becomes `\\`, a newline `\n`, and a carriage return `\r`
/// anywhere in the value; within the leading whitespace run each space becomes
/// `\s` and each tab `\t`; a space or tab elsewhere, and a `;`, are written
/// literally. [`unescape`] reverses each of these sequences.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut leading = true;
    for c in s.chars() {
        match c {
            '\\' => {
                out.push_str("\\\\");
                leading = false;
            }
            '\n' => {
                out.push_str("\\n");
                leading = false;
            }
            '\r' => {
                out.push_str("\\r");
                leading = false;
            }
            ' ' if leading => out.push_str("\\s"),
            '\t' if leading => out.push_str("\\t"),
            _ => {
                out.push(c);
                leading = false;
            }
        }
    }
    out
}

fn unescape(s: &str) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push(' '),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(';') => out.push(';'),
            Some(other) => return Err(Error::KeyFile(format!("invalid escape '\\{other}'"))),
            None => return Err(Error::KeyFile("value ends with a lone backslash".into())),
        }
    }
    Ok(out)
}

fn split_list(raw: &str) -> Result<Vec<String>> {
    let mut items: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                // Keep the escape intact; unescape resolves it below.
                Some(next) => {
                    current.push('\\');
                    current.push(next);
                }
                None => return Err(Error::KeyFile("value ends with a lone backslash".into())),
            },
            ';' => {
                items.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        items.push(current);
    }
    items.iter().map(|s| unescape(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The exact bytes the `ostree` tool wrote for an archive repo config.
    const ARCHIVE_CONFIG: &str = "[core]\nrepo_version=1\nmode=archive-z2\n";

    #[test]
    fn parses_tool_written_config() {
        let kf = KeyFile::parse(ARCHIVE_CONFIG).unwrap();
        assert_eq!(kf.get_value("core", "repo_version"), Some("1"));
        assert_eq!(kf.get_value("core", "mode"), Some("archive-z2"));
        assert_eq!(kf.get_integer("core", "repo_version").unwrap(), Some(1));
        assert_eq!(kf.get_value("core", "absent"), None);
        assert_eq!(kf.get_value("nogroup", "x"), None);
    }

    #[test]
    fn round_trips_tool_written_config_byte_for_byte() {
        let kf = KeyFile::parse(ARCHIVE_CONFIG).unwrap();
        assert_eq!(kf.to_string(), ARCHIVE_CONFIG);
    }

    #[test]
    fn drops_comments_and_blanks_and_trims_leading_value_whitespace() {
        // Leading whitespace on a line, around a key, and after `=` is
        // removed; trailing whitespace in a value is kept, matching the tool.
        let text = "# a comment\n\n[core]\n  repo_version = 1\n\n# trailing\nmode=bare \n";
        let kf = KeyFile::parse(text).unwrap();
        assert_eq!(kf.get_value("core", "repo_version"), Some("1"));
        assert_eq!(kf.get_integer("core", "repo_version").unwrap(), Some(1));
        assert_eq!(kf.get_value("core", "mode"), Some("bare "));
    }

    #[test]
    fn value_keeps_trailing_and_strips_leading_whitespace() {
        let kf = KeyFile::parse("[g]\nk=  a b  \n").unwrap();
        assert_eq!(kf.get_value("g", "k"), Some("a b  "));
    }

    #[test]
    fn hash_inside_a_value_is_literal() {
        let kf = KeyFile::parse("[core]\nk=a # b\n").unwrap();
        assert_eq!(kf.get_value("core", "k"), Some("a # b"));
    }

    #[test]
    fn accepts_crlf_line_endings() {
        let kf = KeyFile::parse("[core]\r\nrepo_version=1\r\nk=v\r\n").unwrap();
        assert_eq!(kf.get_value("core", "k"), Some("v"));
        assert_eq!(kf.get_integer("core", "repo_version").unwrap(), Some(1));
    }

    #[test]
    fn strips_one_trailing_cr_per_line() {
        // The tool strips a single trailing carriage return from a raw line.
        // A doubled CR before the newline keeps one CR in the value; stripping
        // twice would drop the byte.
        let kf = KeyFile::parse("[g]\r\nk=v\r\r\n").unwrap();
        assert_eq!(kf.get_value("g", "k"), Some("v\r"));
    }

    #[test]
    fn accepts_indented_comment_header_and_key() {
        let kf = KeyFile::parse("   # c\n   [core]\n  k=v\n").unwrap();
        assert_eq!(kf.get_value("core", "k"), Some("v"));
    }

    #[test]
    fn duplicate_groups_merge_and_last_key_wins() {
        let kf = KeyFile::parse("[s]\na=first\n[s]\nb=second\na=third\n").unwrap();
        assert_eq!(kf.get_value("s", "a"), Some("third"));
        assert_eq!(kf.get_value("s", "b"), Some("second"));
        assert_eq!(kf.groups().count(), 1);
    }

    #[test]
    fn rejects_empty_group_and_semicolon_line() {
        assert!(KeyFile::parse("[]\nk=v\n").is_err());
        // A line starting with `;` is not a comment; with no `=` it is an error.
        assert!(KeyFile::parse("[core]\n;not a comment\nk=v\n").is_err());
    }

    #[test]
    fn parses_quoted_remote_group_name() {
        let text = "[remote \"origin\"]\nurl=https://example.invalid/repo\ngpg-verify=false\n";
        let kf = KeyFile::parse(text).unwrap();
        assert!(kf.has_group("remote \"origin\""));
        assert_eq!(
            kf.get_value("remote \"origin\"", "url"),
            Some("https://example.invalid/repo")
        );
        assert_eq!(
            kf.get_bool("remote \"origin\"", "gpg-verify").unwrap(),
            Some(false)
        );
    }

    #[test]
    fn boolean_and_integer_validation() {
        let kf = KeyFile::parse(
            "[core]\nt=true\nf=false\none=1\nzero=0\nbad=maybe\nyes=yes\ncase=True\ntwo=2\ndepth=-1\n",
        )
        .unwrap();
        assert_eq!(kf.get_bool("core", "t").unwrap(), Some(true));
        assert_eq!(kf.get_bool("core", "f").unwrap(), Some(false));
        assert_eq!(kf.get_bool("core", "one").unwrap(), Some(true));
        assert_eq!(kf.get_bool("core", "zero").unwrap(), Some(false));
        // The tool accepts only true/false/1/0, matched exactly.
        assert!(kf.get_bool("core", "bad").is_err());
        assert!(kf.get_bool("core", "yes").is_err());
        assert!(kf.get_bool("core", "case").is_err());
        assert!(kf.get_bool("core", "two").is_err());
        assert_eq!(kf.get_integer("core", "depth").unwrap(), Some(-1));
    }

    #[test]
    fn string_list_splits_on_semicolons() {
        let kf = KeyFile::parse("[core]\ndefault-repo-finders=config;mount\n").unwrap();
        assert_eq!(
            kf.get_string_list("core", "default-repo-finders").unwrap(),
            Some(vec!["config".to_string(), "mount".to_string()])
        );
        // A trailing separator does not add an empty element.
        let kf = KeyFile::parse("[core]\nl=a;b;\n").unwrap();
        assert_eq!(
            kf.get_string_list("core", "l").unwrap(),
            Some(vec!["a".to_string(), "b".to_string()])
        );
    }

    #[test]
    fn unescape_handles_glib_sequences() {
        let kf = KeyFile::parse("[g]\nk=a\\sb\\tc\\\\d\n").unwrap();
        assert_eq!(
            kf.get_string("g", "k").unwrap(),
            Some("a b\tc\\d".to_string())
        );
    }

    #[test]
    fn rejects_key_before_group_and_unclosed_header() {
        assert!(KeyFile::parse("key=value\n").is_err());
        assert!(KeyFile::parse("[core\nkey=value\n").is_err());
    }

    #[test]
    fn set_value_creates_group_and_updates_in_place() {
        let mut kf = KeyFile::default();
        kf.set_value("core", "repo_version", "1").unwrap();
        kf.set_value("core", "mode", "bare").unwrap();
        kf.set_value("core", "mode", "archive-z2").unwrap();
        assert_eq!(kf.to_string(), "[core]\nrepo_version=1\nmode=archive-z2\n");
    }

    #[test]
    fn to_string_separates_groups_with_a_blank_line() {
        let mut kf = KeyFile::default();
        kf.set_value("core", "repo_version", "1").unwrap();
        kf.set_value("remote \"o\"", "url", "x").unwrap();
        assert_eq!(
            kf.to_string(),
            "[core]\nrepo_version=1\n\n[remote \"o\"]\nurl=x\n"
        );
    }

    #[test]
    fn set_value_rejects_structural_characters() {
        let mut kf = KeyFile::default();
        assert!(kf.set_value("core", "k", "a\nb").is_err()); // newline in value
        assert!(kf.set_value("core", "k", " lead").is_err()); // leading space
        assert!(kf.set_value("core", "k", "\ttab").is_err()); // leading tab
        assert!(kf.set_value("core", "a=b", "v").is_err()); // `=` in key
        assert!(kf.set_value("core", "a\nb", "v").is_err()); // newline in key
        assert!(kf.set_value("core", " spaced ", "v").is_err()); // ws around key
        assert!(kf.set_value("", "k", "v").is_err()); // empty group
        assert!(kf.set_value("a\nb", "k", "v").is_err()); // newline in group
        assert!(kf.set_value("a[b]", "k", "v").is_err()); // brackets in group
        // Spaces and semicolons inside a value are ordinary content.
        assert!(kf.set_value("core", "list", "a;b;c").is_ok());
        assert!(kf.set_value("core", "spaces", "a b c").is_ok());
    }

    #[test]
    fn set_value_rejects_keys_that_would_not_reparse() {
        let mut kf = KeyFile::default();
        // A '#'-leading key serializes to a line the parser drops as a comment.
        assert!(kf.set_value("core", "#weird", "v").is_err());
        // A '['-leading key serializes to a line the parser reads as a group
        // header.
        assert!(kf.set_value("core", "[k", "v").is_err());
        // A '#' or '[' elsewhere in the key is ordinary content that reparses.
        assert!(kf.set_value("core", "a#b", "v").is_ok());
        assert!(kf.set_value("core", "a[b", "v").is_ok());
        let reparsed = KeyFile::parse(&kf.to_string()).unwrap();
        assert_eq!(kf, reparsed);
    }

    #[test]
    fn set_value_round_trips_through_display() {
        let mut kf = KeyFile::default();
        kf.set_value("remote \"o\"", "url", "https://example.invalid/repo")
            .unwrap();
        kf.set_value("remote \"o\"", "finders", "config;mount")
            .unwrap();
        kf.set_value("core", "mode", "archive-z2").unwrap();
        let reparsed = KeyFile::parse(&kf.to_string()).unwrap();
        assert_eq!(kf, reparsed);
    }

    #[test]
    fn parse_display_parse_is_stable() {
        let text = "# note\n\n[core]\nrepo_version=1\nmode=archive-z2\nval=keep me \n\n\
                    [remote \"o\"]\nurl=https://example.invalid/repo\ngpg-verify=false\n";
        let first = KeyFile::parse(text).unwrap();
        let second = KeyFile::parse(&first.to_string()).unwrap();
        assert_eq!(first, second);
    }

    // ---- B3: group-header bracket handling (observed via `ostree config`) ----

    #[test]
    fn group_name_runs_to_first_bracket() {
        // Each of these whole files is rejected by the tool; the parser
        // matches by erroring rather than reading a stray group name.
        // `[a]b]`: text follows the first ']'.
        assert!(KeyFile::parse("[a]b]\nk=v\n").is_err());
        // `[a]b]c`: trailing non-']' text after the first ']'.
        assert!(KeyFile::parse("[a]b]c\nk=v\n").is_err());
        // `[a[b]`: the group name would contain '['.
        assert!(KeyFile::parse("[a[b]\nk=v\n").is_err());
        // `[]x]`: empty name plus trailing text.
        assert!(KeyFile::parse("[]x]\nk=v\n").is_err());
        // Trailing ASCII whitespace after the ']' is allowed.
        let kf = KeyFile::parse("[grp]  \nk=v\n").unwrap();
        assert_eq!(kf.get_value("grp", "k"), Some("v"));
    }

    // ---- B4: ASCII-only whitespace trimming (observed via `ostree config`) --

    #[test]
    fn non_ascii_whitespace_is_preserved() {
        // A line that is only a non-breaking space is not blank; with no '='
        // it is a parse error, matching the tool.
        assert!(KeyFile::parse("[g]\n\u{a0}\nk=v\n").is_err());
        // A non-breaking space around a key stays part of the key name.
        let kf = KeyFile::parse("[g]\n\u{a0}k\u{a0}=v\n").unwrap();
        assert_eq!(kf.get_value("g", "\u{a0}k\u{a0}"), Some("v"));
        assert_eq!(kf.get_value("g", "k"), None);
        // A non-breaking space around a value is kept on both sides.
        let kf = KeyFile::parse("[g]\nvk=\u{a0}nbv\u{a0}\n").unwrap();
        assert_eq!(kf.get_value("g", "vk"), Some("\u{a0}nbv\u{a0}"));
    }

    #[test]
    fn ascii_whitespace_lines_and_keys_are_trimmed() {
        // A line of only spaces or only tabs is ignored; a leading tab before
        // a header or comment is stripped; a tab-wrapped key trims to bare.
        let kf = KeyFile::parse("[g]\n   \n\t\n\t[h]\n\t#c\n\tk\t=v\n").unwrap();
        assert_eq!(kf.get_value("h", "k"), Some("v"));
    }

    #[test]
    fn set_value_allows_non_ascii_whitespace_in_key() {
        let mut kf = KeyFile::default();
        // ASCII whitespace around a key would not reparse and is rejected.
        assert!(kf.set_value("g", " k", "v").is_err());
        assert!(kf.set_value("g", "k\t", "v").is_err());
        // A trailing non-breaking space reparses and is accepted.
        assert!(kf.set_value("g", "k\u{a0}", "v").is_ok());
        let reparsed = KeyFile::parse(&kf.to_string()).unwrap();
        assert_eq!(kf, reparsed);
    }

    // ---- B5: value escaping on write (observed via `ostree config set`) ----

    #[test]
    fn set_string_escapes_like_the_tool() {
        // (input, stored form) pairs read back from the raw config bytes the
        // tool wrote for `ostree config set core.<k> <input>`.
        for (input, stored) in [
            ("a\nb", "a\\nb"),
            ("a\tb", "a\tb"), // interior tab is literal
            ("a\rb", "a\\rb"),
            ("a\\b", "a\\\\b"),
            ("   ab", "\\s\\s\\sab"),
            ("ab   ", "ab   "),   // trailing spaces are literal
            ("a;b", "a;b"),       // the separator is literal
            ("\tab", "\\tab"),    // leading tab
            ("ab\t", "ab\t"),     // trailing tab is literal
            ("a b", "a b"),       // interior space is literal
            ("   ", "\\s\\s\\s"), // an all-space value is all leading
            (" \tx", "\\s\\tx"),  // the leading run mixes space and tab
        ] {
            let mut kf = KeyFile::default();
            kf.set_string("core", "k", input).unwrap();
            assert_eq!(kf.get_value("core", "k"), Some(stored), "input {input:?}");
        }
    }

    #[test]
    fn set_string_get_string_round_trips() {
        for v in [
            "plain",
            "a\nb\tc",
            "  leading and trailing  ",
            "back\\slash",
            "a\r\nb",
            "line1\nline2",
            "",
        ] {
            let mut kf = KeyFile::default();
            kf.set_string("core", "k", v).unwrap();
            // The stored value carries no raw newline, so it is a single line.
            assert!(!kf.get_value("core", "k").unwrap().contains(['\n', '\r']));
            // get_string reverses the escaping.
            assert_eq!(kf.get_string("core", "k").unwrap().as_deref(), Some(v));
            // The serialized file reparses to an equal KeyFile.
            let reparsed = KeyFile::parse(&kf.to_string()).unwrap();
            assert_eq!(kf, reparsed);
        }
    }

    // ---- B6: removal (observed via `ostree config unset`) -------------------

    #[test]
    fn remove_key_keeps_the_group_header() {
        // `ostree config set g.k v` followed by `ostree config unset g.k` leaves
        // the emptied `[g]` header in the file, which this reproduces.
        let mut kf = KeyFile::parse("[core]\nrepo_version=1\nmode=archive-z2\n\n[g]\nk=v\n")
            .expect("the file parses");
        assert!(kf.remove_key("g", "k"));
        assert_eq!(
            kf.to_string(),
            "[core]\nrepo_version=1\nmode=archive-z2\n\n[g]\n"
        );
        assert!(kf.has_group("g"));
        assert_eq!(kf.get_value("g", "k"), None);
    }

    #[test]
    fn remove_key_reports_an_absent_key_and_group() {
        let mut kf = KeyFile::parse(ARCHIVE_CONFIG).expect("the file parses");
        assert!(!kf.remove_key("core", "absent"));
        assert!(!kf.remove_key("nogroup", "mode"));
        // Nothing moved.
        assert_eq!(kf.to_string(), ARCHIVE_CONFIG);
    }

    #[test]
    fn remove_key_leaves_the_other_keys_in_order() {
        let mut kf =
            KeyFile::parse("[core]\nrepo_version=1\nmode=bare\nfsync=false\n").expect("parses");
        assert!(kf.remove_key("core", "mode"));
        assert_eq!(kf.to_string(), "[core]\nrepo_version=1\nfsync=false\n");
    }

    #[test]
    fn remove_group_drops_the_header_and_its_keys() {
        let text = "[core]\nrepo_version=1\nmode=bare\n\n\
                    [remote \"a\"]\nurl=https://a.invalid/r\n\n\
                    [remote \"b\"]\nurl=https://b.invalid/r\n";
        let mut kf = KeyFile::parse(text).expect("the file parses");
        assert!(kf.remove_group("remote \"a\""));
        assert!(!kf.remove_group("remote \"a\""));
        assert_eq!(
            kf.to_string(),
            "[core]\nrepo_version=1\nmode=bare\n\n[remote \"b\"]\nurl=https://b.invalid/r\n"
        );
        assert_eq!(kf.groups().collect::<Vec<_>>(), ["core", "remote \"b\""]);
    }

    #[test]
    fn a_rewrite_keeps_untouched_groups_and_drops_comments() {
        // The tool's own rewrite: the groups and keys it did not touch keep
        // their order and their bytes, and the comment and blank lines the
        // input carried are gone.
        let text = "# leading comment\n[core]\nrepo_version=1\nmode=archive-z2\n\
                    # inner comment\nfoo=bar\n\n[other]\nx=1\n";
        let mut kf = KeyFile::parse(text).expect("the file parses");
        kf.set_value("core", "new", "v").expect("the key is valid");
        assert_eq!(
            kf.to_string(),
            "[core]\nrepo_version=1\nmode=archive-z2\nfoo=bar\nnew=v\n\n[other]\nx=1\n"
        );
    }

    #[test]
    fn set_string_matches_tool_written_line_bytes() {
        // The exact stored bytes `ostree config set core.knl $'a\nb'` and
        // `... core.klead '   ab'` produced in a fresh archive repo config.
        let mut kf = KeyFile::default();
        kf.set_value("core", "repo_version", "1").unwrap();
        kf.set_value("core", "mode", "archive-z2").unwrap();
        kf.set_string("core", "knl", "a\nb").unwrap();
        kf.set_string("core", "klead", "   ab").unwrap();
        assert_eq!(
            kf.to_string(),
            "[core]\nrepo_version=1\nmode=archive-z2\nknl=a\\nb\nklead=\\s\\s\\sab\n"
        );
    }
}
