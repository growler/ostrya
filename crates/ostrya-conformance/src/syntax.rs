//! The grammar of a `run:` line and of an `expect-*` claim.
//!
//! [`split`] and [`substitute`] read a `run:` line. [`parse_claim`] reads a
//! claim.

use std::collections::BTreeMap;

/// Splits a `run:` line into arguments.
///
/// The line splits at white space. A single-quoted span is part of one
/// argument and can hold white space. This function reads no other shell
/// syntax, and no shell runs. The placeholders stay in the arguments for
/// [`substitute`].
///
/// # Errors
///
/// - An error if a single quote does not close.
pub fn split(line: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quoted = false;

    for character in line.chars() {
        match character {
            '\'' => {
                quoted = !quoted;
                started = true;
            }
            character if character.is_whitespace() && !quoted => {
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            character => {
                current.push(character);
                started = true;
            }
        }
    }
    if quoted {
        return Err(format!("unterminated single quote in {line:?}"));
    }
    if started {
        args.push(current);
    }
    Ok(args)
}

/// Returns each placeholder name of `line`, in order, with the duplicates.
///
/// A placeholder is `$NAME`, where `NAME` holds ASCII uppercase letters,
/// digits, and `_`. A setup binds each placeholder. `$$` is a literal dollar
/// sign and names no placeholder.
///
/// # Errors
///
/// - An error if a `$` is not followed by a name or by a second `$`.
pub fn placeholders(line: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut rest = line.chars().peekable();
    while let Some(character) = rest.next() {
        if character != '$' {
            continue;
        }
        if rest.peek() == Some(&'$') {
            rest.next();
            continue;
        }
        let mut name = String::new();
        while let Some(next) = rest.peek() {
            if next.is_ascii_uppercase() || next.is_ascii_digit() || *next == '_' {
                name.push(*next);
                rest.next();
            } else {
                break;
            }
        }
        if name.is_empty() {
            return Err(format!("a bare `$` in {line:?} names no placeholder"));
        }
        names.push(name);
    }
    Ok(names)
}

/// Replaces each placeholder in one argument with its binding.
///
/// `$$` gives a literal dollar sign.
///
/// # Errors
///
/// - An error if `bindings` holds no value for a placeholder. A `$` with no
///   name after it is a placeholder with an empty name.
pub fn substitute(argument: &str, bindings: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = argument.chars().peekable();
    while let Some(character) = rest.next() {
        if character != '$' {
            out.push(character);
            continue;
        }
        if rest.peek() == Some(&'$') {
            rest.next();
            out.push('$');
            continue;
        }
        let mut name = String::new();
        while let Some(next) = rest.peek() {
            if next.is_ascii_uppercase() || next.is_ascii_digit() || *next == '_' {
                name.push(*next);
                rest.next();
            } else {
                break;
            }
        }
        let value = bindings
            .get(&name)
            .ok_or_else(|| format!("placeholder `${name}` is not bound"))?;
        out.push_str(value);
    }
    Ok(out)
}

/// The claim of an `expect-stdout` or `expect-stderr` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Claim {
    /// The stream is empty.
    Empty,
    /// The stream holds this text at some position.
    Contains(String),
    /// The stream is exactly this text.
    Equals(String),
}

impl Claim {
    /// Returns `true` if `text` satisfies the claim.
    pub fn holds(&self, text: &str) -> bool {
        match self {
            Claim::Empty => text.is_empty(),
            Claim::Contains(needle) => text.contains(needle.as_str()),
            Claim::Equals(whole) => text == whole,
        }
    }

    /// Returns the claim in the form that a record uses.
    pub fn render(&self) -> String {
        match self {
            Claim::Empty => "empty".to_owned(),
            Claim::Contains(needle) => format!("contains {}", quote(needle)),
            Claim::Equals(whole) => format!("equals {}", quote(whole)),
        }
    }
}

/// Parses a claim: `empty`, `contains "TEXT"`, or `equals "TEXT"`.
///
/// `TEXT` is a double-quoted string with the escapes `\\`, `\"`, `\n`, and
/// `\t`. The function removes the leading and trailing white space of `text`.
///
/// # Errors
///
/// - An error if `text` is not `empty` and has no white space between the form
///   and the quoted text.
/// - An error if the form is not `contains` or `equals`.
/// - An error if the quoted text does not start with `"` or does not close.
/// - An error if the quoted text holds an unknown escape or ends inside an
///   escape.
/// - An error if text follows the closing quote.
pub fn parse_claim(text: &str) -> Result<Claim, String> {
    let text = text.trim();
    if text == "empty" {
        return Ok(Claim::Empty);
    }
    let (form, rest) = text.split_once(char::is_whitespace).ok_or_else(|| {
        format!("claim {text:?} is not `empty`, `contains \"…\"`, or `equals \"…\"`")
    })?;
    let value = unquote(rest.trim())?;
    match form {
        "contains" => Ok(Claim::Contains(value)),
        "equals" => Ok(Claim::Equals(value)),
        other => Err(format!(
            "claim form `{other}` is not `empty`, `contains`, or `equals`"
        )),
    }
}

/// Reads a double-quoted string with the escapes `\\`, `\"`, `\n`, and `\t`.
fn unquote(text: &str) -> Result<String, String> {
    let mut characters = text.chars();
    if characters.next() != Some('"') {
        return Err(format!("claim text {text:?} does not open with a quote"));
    }
    let mut out = String::new();
    loop {
        match characters.next() {
            None => return Err(format!("claim text {text:?} does not close its quote")),
            Some('"') => break,
            Some('\\') => match characters.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => return Err(format!("unknown escape `\\{other}` in {text:?}")),
                None => return Err(format!("claim text {text:?} ends inside an escape")),
            },
            Some(character) => out.push(character),
        }
    }
    if characters.next().is_some() {
        return Err(format!("claim text {text:?} holds text after the quote"));
    }
    Ok(out)
}

/// Returns `text` as the double-quoted text of a claim.
///
/// The function escapes `"`, `\`, newline, and tab. In a claim,
/// [`parse_claim`] reads this form back to the same text.
pub fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_span_is_one_argument() {
        let args = split("commit -s 'a subject with spaces' $TREE").expect("splits");
        assert_eq!(args, ["commit", "-s", "a subject with spaces", "$TREE"]);
    }

    #[test]
    fn an_unterminated_quote_is_an_error() {
        assert!(split("commit -s 'oops").is_err());
    }

    #[test]
    fn placeholders_skip_the_literal_dollar() {
        let names = placeholders("init --repo=$REPO --x=$$HOME/$REPO2").expect("scans");
        assert_eq!(names, ["REPO", "REPO2"]);
    }

    #[test]
    fn substitution_binds_and_unescapes() {
        let mut bindings = BTreeMap::new();
        bindings.insert("REPO".to_owned(), "/scratch/repo".to_owned());
        let out = substitute("--repo=$REPO$$", &bindings).expect("substitutes");
        assert_eq!(out, "--repo=/scratch/repo$");
    }

    #[test]
    fn an_unbound_placeholder_is_an_error() {
        assert!(substitute("$NOPE", &BTreeMap::new()).is_err());
    }

    #[test]
    fn claims_round_trip() {
        let claim = parse_claim("contains \"error: it\\nfailed\"").expect("parses");
        assert_eq!(claim, Claim::Contains("error: it\nfailed".to_owned()));
        assert_eq!(parse_claim(&claim.render()).expect("re-parses"), claim);
        assert!(claim.holds("prefix error: it\nfailed suffix"));
    }
}
