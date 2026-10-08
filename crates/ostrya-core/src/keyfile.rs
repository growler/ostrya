//! A parser and writer for a subset of the GLib key file format.
//!
//! The parse rules and the write rules are on the [`KeyFile`] type doc. The
//! parse rules, the escape rules of `set_string`, and the removal rules come
//! from the observation of `ostree config` with crafted config files. The
//! tests record each observed case.

use std::collections::HashMap;

use crate::error::{Error, Result};

/// A parsed key file, such as the repository `config` file.
///
/// A key file is an ordered list of groups. Each group is an ordered list of
/// entries, and each entry is a key and its raw value text.
///
/// # Syntax
///
/// [`parse`](KeyFile::parse) reads a subset of the GLib key file format:
///
/// - A `[group]` line starts a group. The group name is the text from `[` to
///   the first `]`. Only white space can follow the `]`.
/// - A `key=value` line is an entry of the current group. The key is the text
///   before the first `=`.
/// - A line that starts with `#` is a comment line. Only `#` starts a comment.
///   A `#` in a value is part of the value.
/// - A blank line has no text or only white space.
/// - A line ends with LF or with CRLF. The parser removes one carriage return
///   at the end of a line.
///
/// The parser uses ASCII space and tab as white space:
///
/// - It ignores this white space around a blank line, a comment line, and a
///   group header.
/// - It removes this white space around a key and at the start of a value.
/// - It keeps the white space at the end of a value.
/// - It keeps a non-breaking space (U+00A0) and all other non-ASCII white
///   space everywhere.
///
/// The parser keeps the group order, the key order, and the raw value text.
/// It drops comment lines and blank lines. A repeated group header merges into
/// the group of the first header. A repeated key keeps its first position and
/// takes the last value.
///
/// # Writes
///
/// [`get_value`](KeyFile::get_value) returns the raw value text. The typed
/// getters unescape the value on read, and
/// [`get_string_list`](KeyFile::get_string_list) also splits it into items.
///
/// The [`Display`](std::fmt::Display) output parses to an equal `KeyFile`. A
/// rewritten file keeps the groups and the keys that the caller did not
/// change, in their order and with their value text. It does not keep the
/// comment lines and the blank lines of the input. The `ostree` command
/// rewrites a `config` file in the same way.
///
/// # Examples
///
/// ```
/// use ostrya_core::KeyFile;
///
/// let mut config = KeyFile::parse("[core]\nrepo_version=1\nmode=archive-z2\n")?;
/// assert_eq!(config.get_value("core", "mode"), Some("archive-z2"));
/// assert_eq!(config.get_integer("core", "repo_version")?, Some(1));
///
/// config.set_string("core", "fsync", "false")?;
/// assert_eq!(
///     config.to_string(),
///     "[core]\nrepo_version=1\nmode=archive-z2\nfsync=false\n",
/// );
/// # Ok::<(), ostrya_core::Error>(())
/// ```
#[derive(Clone, Default)]
pub struct KeyFile {
    groups: Vec<Group>,
    /// The position in `groups` of each group, by name, so a lookup does not
    /// scan every group.
    index: HashMap<String, usize>,
}

impl PartialEq for KeyFile {
    fn eq(&self, other: &KeyFile) -> bool {
        self.groups == other.groups
    }
}

impl Eq for KeyFile {}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile")
            .field("groups", &self.groups)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Group {
    name: String,
    entries: Vec<(String, String)>,
}

impl KeyFile {
    /// Parses a key file from text.
    ///
    /// The rules are in [`KeyFile` syntax](KeyFile#syntax).
    ///
    /// # Errors
    ///
    /// [`Error::KeyFile`] with one of these reasons, after a "line N:" prefix:
    ///
    /// - "group header is not closed with ']'" if a line starts with `[` and
    ///   has no `]`.
    /// - "group header has trailing text after ']'" if text other than white
    ///   space follows the first `]`.
    /// - "empty group name" if the group name is empty.
    /// - "group name 'NAME' contains '[' or ']'" if the group name contains
    ///   a `[`.
    /// - "expected a key=value pair" if a line is not blank, not a comment,
    ///   not a group header, and has no `=`.
    /// - "empty key" if the text before the `=` is empty or only white space.
    /// - "key 'KEY' precedes any group" if an entry comes before the first
    ///   group header.
    pub fn parse(input: &str) -> Result<KeyFile> {
        let mut keyfile = KeyFile::default();
        let mut current: Option<usize> = None;
        // The position of each key in its group, by group position and key.
        // With this map, a repeated key needs no scan of the group entries.
        let mut keys: HashMap<(usize, String), usize> = HashMap::new();

        // Split on '\n'. A trailing newline leaves a final empty segment that
        // is not a line. The loop removes one trailing carriage return from
        // each raw line, so CRLF input parses and a doubled CR keeps one CR.
        let body = input.strip_suffix('\n').unwrap_or(input);
        for (n, raw) in body.split('\n').enumerate() {
            let lineno = n + 1;
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            let trimmed = line.trim_matches(ASCII_WS);
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix('[') {
                // The group name runs from '[' to the first ']'. Only white
                // space can follow the ']', and the name cannot contain '[' or
                // ']'. These are the rules of `validate_group`, so a header
                // that the `ostree` command refuses does not parse here.
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
                current = Some(keyfile.group_index_or_insert(name));
                continue;
            }
            let Some(eq) = line.find('=') else {
                return Err(Error::KeyFile(format!(
                    "line {lineno}: expected a key=value pair"
                )));
            };
            let key = line[..eq].trim_matches(ASCII_WS);
            // The `ostree` command removes the leading white space after `=`
            // and keeps the trailing white space as part of the value.
            let value = line[eq + 1..].trim_start_matches(ASCII_WS);
            if key.is_empty() {
                return Err(Error::KeyFile(format!("line {lineno}: empty key")));
            }
            let Some(idx) = current else {
                return Err(Error::KeyFile(format!(
                    "line {lineno}: key '{key}' precedes any group"
                )));
            };
            let entries = &mut keyfile.groups[idx].entries;
            match keys.get(&(idx, key.to_string())) {
                Some(&at) => entries[at].1 = value.to_string(),
                None => {
                    keys.insert((idx, key.to_string()), entries.len());
                    entries.push((key.to_string(), value.to_string()));
                }
            }
        }
        Ok(keyfile)
    }

    /// Returns the position of `name` in `groups`. If the group is absent,
    /// adds a new empty group at the end.
    fn group_index_or_insert(&mut self, name: &str) -> usize {
        if let Some(&i) = self.index.get(name) {
            return i;
        }
        self.groups.push(Group {
            name: name.to_string(),
            entries: Vec::new(),
        });
        self.index.insert(name.to_string(), self.groups.len() - 1);
        self.groups.len() - 1
    }

    fn group(&self, name: &str) -> Option<&Group> {
        self.index.get(name).map(|&i| &self.groups[i])
    }

    /// Returns `true` if the key file has the group `group`.
    pub fn has_group(&self, group: &str) -> bool {
        self.index.contains_key(group)
    }

    /// Returns an iterator over the group names in file order.
    pub fn groups(&self) -> impl Iterator<Item = &str> {
        self.groups.iter().map(|g| g.name.as_str())
    }

    /// Returns an iterator over the keys of one group in file order.
    ///
    /// If the group is absent, the iterator is empty.
    pub fn keys(&self, group: &str) -> impl Iterator<Item = &str> {
        self.group(group)
            .into_iter()
            .flat_map(|g| g.entries.iter().map(|(k, _)| k.as_str()))
    }

    fn find(&self, group: &str, key: &str) -> Option<&str> {
        self.group(group)?
            .entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Returns the raw value text of a key.
    ///
    /// The text keeps its escape sequences. If the group or the key is absent,
    /// the method returns `None`.
    pub fn get_value(&self, group: &str, key: &str) -> Option<&str> {
        self.find(group, key)
    }

    /// Returns the unescaped string value of a key.
    ///
    /// The method replaces each escape sequence with its character:
    ///
    /// - `\s` with a space
    /// - `\t` with a tab
    /// - `\n` with a newline
    /// - `\r` with a carriage return
    /// - `\\` with a backslash
    /// - `\;` with a `;`
    ///
    /// If the group or the key is absent, the method returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// - [`Error::KeyFile`] with the reason "invalid escape '\X'" if a
    ///   backslash comes before a character `X` that is not in the list.
    /// - [`Error::KeyFile`] with the reason "value ends with a lone backslash"
    ///   if the value ends with a backslash that starts no escape sequence.
    pub fn get_string(&self, group: &str, key: &str) -> Result<Option<String>> {
        self.find(group, key).map(unescape).transpose()
    }

    /// Returns the boolean value of a key.
    ///
    /// The value text `true` or `1` gives `true`, and `false` or `0` gives
    /// `false`. The match is exact. If the group or the key is absent, the
    /// method returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// [`Error::KeyFile`] with the reason "value 'VALUE' for GROUP.KEY is not a
    /// boolean" if the value text is not one of the four values.
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

    /// Returns the signed integer value of a key.
    ///
    /// The value text is a decimal `i64` with an optional `+` or `-` sign. If
    /// the group or the key is absent, the method returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// [`Error::KeyFile`] with the reason "value 'VALUE' for GROUP.KEY is not
    /// an integer" if the value text is not a decimal `i64`. White space in
    /// the text causes this error.
    pub fn get_integer(&self, group: &str, key: &str) -> Result<Option<i64>> {
        match self.find(group, key) {
            None => Ok(None),
            Some(v) => v.parse::<i64>().map(Some).map_err(|_| {
                Error::KeyFile(format!("value '{v}' for {group}.{key} is not an integer"))
            }),
        }
    }

    /// Returns the list value of a key as unescaped strings.
    ///
    /// A `;` separates two items, and `\;` is a `;` in an item. The text after
    /// the last `;` is an item only if it is not empty, so a trailing `;` adds
    /// no empty item. The method unescapes each item as
    /// [`get_string`](KeyFile::get_string) does. If the group or the key is
    /// absent, the method returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// - [`Error::KeyFile`] with the reason "invalid escape '\X'" if a
    ///   backslash comes before a character `X` that `get_string` does not
    ///   accept.
    /// - [`Error::KeyFile`] with the reason "value ends with a lone backslash"
    ///   if the value ends with a backslash that starts no escape sequence.
    pub fn get_string_list(&self, group: &str, key: &str) -> Result<Option<Vec<String>>> {
        match self.find(group, key) {
            None => Ok(None),
            Some(v) => split_list(v).map(Some),
        }
    }

    /// Sets the raw value text of a key.
    ///
    /// If the group is absent, the method adds it at the end of the file. If
    /// the key is present, the new value replaces the old value at the same
    /// position. If the key is absent, the method adds it at the end of the
    /// group.
    ///
    /// The method does not escape the value.
    /// [`set_string`](KeyFile::set_string) escapes it.
    ///
    /// The method checks the group name, the key, and the value, so that the
    /// [`Display`](std::fmt::Display) output parses to an equal `KeyFile`. If
    /// a check fails, the key file does not change.
    ///
    /// # Errors
    ///
    /// [`Error::KeyFile`] if one of these conditions is true:
    ///
    /// - The group name is empty.
    /// - The group name contains `[`, `]`, a newline, or a carriage return.
    /// - The key is empty.
    /// - The key starts or ends with a space or a tab.
    /// - The key contains `=`, a newline, or a carriage return.
    /// - The key starts with `#` or `[`.
    /// - The value contains a newline or a carriage return.
    /// - The value starts with a space or a tab.
    pub fn set_value(&mut self, group: &str, key: &str, value: &str) -> Result<()> {
        validate_group(group)?;
        validate_key(key)?;
        validate_value(value)?;
        let idx = self.group_index_or_insert(group);
        let entries = &mut self.groups[idx].entries;
        match entries.iter_mut().find(|(k, _)| k == key) {
            Some(entry) => entry.1 = value.to_string(),
            None => entries.push((key.to_string(), value.to_string())),
        }
        Ok(())
    }

    /// Sets the string value of a key and escapes the value.
    ///
    /// The method escapes the value as the `ostree` command does when it
    /// writes a value:
    ///
    /// - A backslash becomes `\\`, a newline `\n`, and a carriage return `\r`,
    ///   at each position in the value.
    /// - In the run of white space at the start of the value, each space
    ///   becomes `\s` and each tab `\t`.
    /// - A space or a tab after that run, and a `;`, stay as they are.
    ///
    /// The escaped value parses again to the same text, and
    /// [`get_string`](KeyFile::get_string) returns the original value. The
    /// method places the group and the key as
    /// [`set_value`](KeyFile::set_value) does. `set_value` stores a value
    /// that is already escaped.
    ///
    /// # Errors
    ///
    /// [`Error::KeyFile`] if the group name or the key fails a check of
    /// [`set_value`](KeyFile::set_value). The escaped value always passes the
    /// checks.
    pub fn set_string(&mut self, group: &str, key: &str, value: &str) -> Result<()> {
        self.set_value(group, key, &escape(value))
    }

    /// Sets the list value of a key and escapes each item.
    ///
    /// [`get_string_list`](KeyFile::get_string_list) returns the same list.
    /// The method escapes each item as [`set_string`](KeyFile::set_string)
    /// escapes a value, so each space and tab at the start of an item becomes
    /// `\s` or `\t`. A `;` in an item becomes `\;`.
    ///
    /// A `;` follows each item, also the last item. An empty list gives an
    /// empty value. Because the last item always has a separator, an empty
    /// item reads back: `["a", ""]` gives `a;;`, and `[""]` gives `;`.
    ///
    /// # Errors
    ///
    /// [`Error::KeyFile`] if the group name or the key fails a check of
    /// [`set_value`](KeyFile::set_value). The escaped value always passes the
    /// checks.
    pub fn set_string_list(
        &mut self,
        group: &str,
        key: &str,
        items: &[impl AsRef<str>],
    ) -> Result<()> {
        let mut value = String::new();
        for item in items {
            // `escape` writes a backslash only as the first character of a
            // two-character sequence. The second character is never `;`, so
            // each `;` that `escape` writes stands alone. The `\;` added here
            // stays a single escape sequence.
            for c in escape(item.as_ref()).chars() {
                if c == ';' {
                    value.push('\\');
                }
                value.push(c);
            }
            value.push(';');
        }
        self.set_value(group, key, &value)
    }

    /// Removes one key and returns `true` if the key was present.
    ///
    /// The group stays, also when it loses its last key. The `ostree` command
    /// keeps the header of an empty group in the same way.
    /// [`Display`](std::fmt::Display) writes the header with no entries.
    pub fn remove_key(&mut self, group: &str, key: &str) -> bool {
        let Some(entries) = self.index.get(group).map(|&i| &mut self.groups[i].entries) else {
            return false;
        };
        let Some(index) = entries.iter().position(|(k, _)| k == key) else {
            return false;
        };
        entries.remove(index);
        true
    }

    /// Removes a group and its keys, and returns `true` if the group was
    /// present.
    ///
    /// The other groups keep their order.
    pub fn remove_group(&mut self, group: &str) -> bool {
        let Some(index) = self.index.remove(group) else {
            return false;
        };
        self.groups.remove(index);
        for i in self.index.values_mut() {
            if *i > index {
                *i -= 1;
            }
        }
        true
    }
}

/// The white space that the `ostree` command trims: ASCII space and tab.
///
/// These facts come from crafted config files that the `ostree` command read:
///
/// - It ignores a line of only spaces or only tabs.
/// - It removes a leading space or tab before a group header or a comment.
/// - It removes a space or a tab around a key.
/// - It keeps a non-breaking space (U+00A0) and all other non-ASCII white
///   space everywhere.
const ASCII_WS: [char; 2] = [' ', '\t'];

/// Checks that a group name is not empty and has no structural character.
///
/// A structural character changes how the `Display` output parses. The
/// checks of `validate_key` and `validate_value` have the same purpose.
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

/// Writes the groups and the keys in file order, in the GLib key file layout.
///
/// Each group starts with a `[name]` line, and each entry is a `key=value`
/// line. A blank line separates two groups. `to_string` gives the text of
/// the whole file.
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

/// Escapes a string value as the `ostree` command does when it writes a value.
///
/// The rules come from `ostree config set` with crafted values and a read of
/// the raw config bytes:
///
/// - A backslash becomes `\\`, a newline `\n`, and a carriage return `\r`, at
///   each position in the value.
/// - In the run of white space at the start of the value, each space becomes
///   `\s` and each tab `\t`.
/// - A space or a tab after that run, and a `;`, stay as they are.
///
/// [`unescape`] reverses each of these sequences.
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
                // The escape sequence stays as it is. `unescape` resolves it
                // after the split.
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

    // The exact bytes that the `ostree` command wrote for the config of an
    // archive repo.
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
        // The parser removes the leading white space of a line, the white
        // space around a key, and the white space after `=`. It keeps the
        // trailing white space of a value, as the `ostree` command does.
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
        // The `ostree` command removes one trailing carriage return from a
        // raw line. A doubled CR before the newline keeps one CR in the value.
        // A second removal drops that byte.
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
        // A line that starts with `;` is not a comment. With no `=`, it is an
        // error.
        assert!(KeyFile::parse("[core]\n;not a comment\nk=v\n").is_err());
    }

    #[test]
    fn keys_lists_one_group_in_file_order() {
        // A repeated header merges into the first group, and a repeated key
        // keeps its first position.
        let text = "[a]\nz=1\ny=2\n[b]\nx=3\n[a]\nw=4\nz=5\n";
        let kf = KeyFile::parse(text).unwrap();
        assert_eq!(kf.keys("a").collect::<Vec<_>>(), ["z", "y", "w"]);
        assert_eq!(kf.keys("b").collect::<Vec<_>>(), ["x"]);
        assert_eq!(kf.keys("absent").count(), 0);
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
        // The `ostree` command accepts only `true`, `false`, `1`, and `0`,
        // matched exactly.
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
        // A key that starts with '#' gives a line that the parser drops as a
        // comment.
        assert!(kf.set_value("core", "#weird", "v").is_err());
        // A key that starts with '[' gives a line that the parser reads as a
        // group header.
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

    // ---- group-header brackets (observed with `ostree config`) -------------

    #[test]
    fn group_name_runs_to_first_bracket() {
        // The `ostree` command refuses each of these whole files. The parser
        // returns an error for each file and reads no stray group name.
        // `[a]b]`: text follows the first ']'.
        assert!(KeyFile::parse("[a]b]\nk=v\n").is_err());
        // `[a]b]c`: trailing non-']' text after the first ']'.
        assert!(KeyFile::parse("[a]b]c\nk=v\n").is_err());
        // `[a[b]`: the group name contains '['.
        assert!(KeyFile::parse("[a[b]\nk=v\n").is_err());
        // `[]x]`: empty name plus trailing text.
        assert!(KeyFile::parse("[]x]\nk=v\n").is_err());
        // Trailing ASCII white space after the ']' is allowed.
        let kf = KeyFile::parse("[grp]  \nk=v\n").unwrap();
        assert_eq!(kf.get_value("grp", "k"), Some("v"));
    }

    // ---- ASCII-only white space trim (observed with `ostree config`) -------

    #[test]
    fn non_ascii_whitespace_is_preserved() {
        // A line that is only a non-breaking space is not blank. With no '=',
        // it is a parse error, as in the `ostree` command.
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
        // The parser ignores a line of only spaces or only tabs. It removes a
        // leading tab before a header or a comment, and the tabs around a key.
        let kf = KeyFile::parse("[g]\n   \n\t\n\t[h]\n\t#c\n\tk\t=v\n").unwrap();
        assert_eq!(kf.get_value("h", "k"), Some("v"));
    }

    #[test]
    fn set_value_allows_non_ascii_whitespace_in_key() {
        let mut kf = KeyFile::default();
        // ASCII white space around a key does not parse back, so `set_value`
        // refuses it.
        assert!(kf.set_value("g", " k", "v").is_err());
        assert!(kf.set_value("g", "k\t", "v").is_err());
        // A trailing non-breaking space parses back, so `set_value` accepts it.
        assert!(kf.set_value("g", "k\u{a0}", "v").is_ok());
        let reparsed = KeyFile::parse(&kf.to_string()).unwrap();
        assert_eq!(kf, reparsed);
    }

    // ---- value escape on write (observed with `ostree config set`) ---------

    #[test]
    fn set_string_escapes_like_the_tool() {
        // (input, stored form) pairs, read back from the raw config bytes that
        // the `ostree` command wrote for `ostree config set core.<k> <input>`.
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
            // get_string reverses the escape sequences.
            assert_eq!(kf.get_string("core", "k").unwrap().as_deref(), Some(v));
            // The serialized file reparses to an equal KeyFile.
            let reparsed = KeyFile::parse(&kf.to_string()).unwrap();
            assert_eq!(kf, reparsed);
        }
    }

    // ---- string lists on write ----------------------------------------------

    #[test]
    fn set_string_list_writes_a_trailing_separator() {
        let mut kf = KeyFile::default();
        kf.set_string_list("g", "k", &["a", "b"]).unwrap();
        assert_eq!(kf.get_value("g", "k"), Some("a;b;"));
        assert_eq!(kf.to_string(), "[g]\nk=a;b;\n");
    }

    /// (items, stored raw value) pairs shared by the escaping and round-trip
    /// tests.
    const LIST_CASES: &[(&[&str], &str)] = &[
        (&["a;b", "c"], "a\\;b;c;"),
        (&["a b"], "a b;"),
        (&[" a"], "\\sa;"),
        (&["x", " b"], "x;\\sb;"),
        (&["a ", "b "], "a ;b ;"),
        (&["\tx", "y\tz"], "\\tx;y\tz;"), // an interior tab is literal
        (&["a\\b"], "a\\\\b;"),
        (&["\\;"], "\\\\\\;;"),
        (&["a\\"], "a\\\\;"),
        (&["\\\\;"], "\\\\\\\\\\;;"),
        (&[";"], "\\;;"),
        (&[";;"], "\\;\\;;"),
        (&["a\nb", "c\rd"], "a\\nb;c\\rd;"),
    ];

    #[test]
    fn set_string_list_escapes_each_item() {
        for &(items, stored) in LIST_CASES {
            let mut kf = KeyFile::default();
            kf.set_string_list("g", "k", items).unwrap();
            assert_eq!(kf.get_value("g", "k"), Some(stored), "input {items:?}");
        }
    }

    #[test]
    fn set_string_list_get_string_list_round_trips() {
        let extra: &[&[&str]] = &[
            &["#c", "=", "[g]", "k=v"],
            &["\u{a0}nb\u{a0}"],
            &["   "],
            &["a", "", ""],
        ];
        for &items in LIST_CASES.iter().map(|(items, _)| items).chain(extra) {
            let mut kf = KeyFile::default();
            kf.set_string_list("g", "k", items).unwrap();
            assert_eq!(
                kf.get_string_list("g", "k").unwrap().unwrap(),
                items,
                "input {items:?}"
            );
            // The stored value carries no raw newline, so it is a single line.
            assert!(
                !kf.get_value("g", "k").unwrap().contains(['\n', '\r']),
                "input {items:?}"
            );
            // The serialized file reparses to an equal KeyFile and list.
            let reparsed = KeyFile::parse(&kf.to_string()).unwrap();
            assert_eq!(kf, reparsed, "input {items:?}");
            assert_eq!(
                reparsed.get_string_list("g", "k").unwrap().unwrap(),
                items,
                "input {items:?}"
            );
        }
        // An owned list is accepted too.
        let owned: Vec<String> = vec!["a;b".to_string(), " c".to_string()];
        let mut kf = KeyFile::default();
        kf.set_string_list("g", "k", &owned).unwrap();
        assert_eq!(kf.get_value("g", "k"), Some("a\\;b;\\sc;"));
        assert_eq!(kf.get_string_list("g", "k").unwrap(), Some(owned.clone()));
        let reparsed = KeyFile::parse(&kf.to_string()).unwrap();
        assert_eq!(kf, reparsed);
        assert_eq!(reparsed.get_string_list("g", "k").unwrap(), Some(owned));
    }

    #[test]
    fn set_string_list_keeps_empty_items() {
        for (items, stored) in [
            (&["a", ""][..], "a;;"),
            (&[""][..], ";"),
            (&["", "a"][..], ";a;"),
            (&["", ""][..], ";;"),
        ] {
            let mut kf = KeyFile::default();
            kf.set_string_list("g", "k", items).unwrap();
            assert_eq!(kf.get_value("g", "k"), Some(stored), "input {items:?}");
            assert_eq!(
                kf.get_string_list("g", "k").unwrap().unwrap(),
                items,
                "input {items:?}"
            );
            let reparsed = KeyFile::parse(&kf.to_string()).unwrap();
            assert_eq!(
                reparsed.get_string_list("g", "k").unwrap().unwrap(),
                items,
                "input {items:?}"
            );
        }
    }

    #[test]
    fn set_string_list_writes_an_empty_list_as_an_empty_value() {
        let mut kf = KeyFile::default();
        kf.set_string_list("g", "k", &[] as &[&str]).unwrap();
        assert_eq!(kf.get_value("g", "k"), Some(""));
        assert_eq!(kf.to_string(), "[g]\nk=\n");
        assert_eq!(kf.get_string_list("g", "k").unwrap(), Some(vec![]));
        let reparsed = KeyFile::parse(&kf.to_string()).unwrap();
        assert_eq!(reparsed.get_string_list("g", "k").unwrap(), Some(vec![]));
    }

    #[test]
    fn set_string_list_replaces_in_place_and_validates_names() {
        let mut kf = KeyFile::parse("[g]\nk=1\nz=2\n").unwrap();
        kf.set_string_list("g", "k", &["x"]).unwrap();
        assert_eq!(kf.to_string(), "[g]\nk=x;\nz=2\n");
        let before = kf.clone();
        assert!(kf.set_string_list("a[b", "k", &["x"]).is_err());
        assert_eq!(kf, before);
        assert!(kf.set_string_list("g", "a=b", &["x"]).is_err());
        assert_eq!(kf, before);
    }

    // ---- removal (observed with `ostree config unset`) ----------------------

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
        // This is the rewrite of the `ostree` command. The groups and keys
        // that the caller did not change keep their order and their bytes. The
        // comment lines and the blank lines of the input are gone.
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
