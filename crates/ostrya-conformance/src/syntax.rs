//! The grammar of a `run:` line and of an `expect-*` claim.
//!
//! A `run:` line splits on whitespace. A single-quoted span becomes one
//! argument and may hold spaces. No other shell syntax is interpreted, and no
//! shell runs. `$NAME` names a placeholder a setup bound; `$$` produces a
//! literal dollar sign.

use std::collections::BTreeMap;

/// Split a `run:` line into arguments.
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

/// Every placeholder name the line names, in order, with duplicates kept.
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

/// Replace every placeholder in one argument with its binding.
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

/// What an `expect-stdout` or `expect-stderr` field claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Claim {
    /// The stream held nothing.
    Empty,
    /// The stream held this text somewhere.
    Contains(String),
    /// The stream held exactly this text.
    Equals(String),
}

impl Claim {
    /// Whether `text` satisfies the claim.
    pub fn holds(&self, text: &str) -> bool {
        match self {
            Claim::Empty => text.is_empty(),
            Claim::Contains(needle) => text.contains(needle.as_str()),
            Claim::Equals(whole) => text == whole,
        }
    }

    /// The claim as a record would write it.
    pub fn render(&self) -> String {
        match self {
            Claim::Empty => "empty".to_owned(),
            Claim::Contains(needle) => format!("contains {}", quote(needle)),
            Claim::Equals(whole) => format!("equals {}", quote(whole)),
        }
    }
}

/// Parse `empty`, `contains "TEXT"`, or `equals "TEXT"`.
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

/// Read a double-quoted string, honouring `\\`, `\"`, `\n`, and `\t`.
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

/// Render a string as a claim's quoted text.
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
