//! The ref patterns of the receive rules.

use ostrya_core::RefPattern;

use crate::error::{Error, Result};
use crate::refs::is_component;

/// A pattern that names the refs of one receive rule.
///
/// A pattern has an optional remote part and a name part. The name part is a
/// [`RefPattern`]: a path of parts, split at `/`. Each part is a literal, `*`,
/// or `**`. `*` selects exactly one part of a name. `**` selects one or more
/// parts. A pattern has one of these forms:
///
/// - `NAME` -- the plain refs that the name pattern `NAME` matches.
/// - `REMOTE:NAME` -- the remote refs of the remote `REMOTE` that `NAME`
///   matches.
/// - `*:NAME` -- the remote refs of every remote that `NAME` matches.
///
/// For example, `apps/*` selects `apps/web` and does not select `apps` or
/// `apps/web/db`. `apps/**` selects `apps/web` and `apps/web/db`, and does not
/// select `apps`. `central:**` selects every ref of the remote `central`.
///
/// `REMOTE` is one component of a ref path, under the wider rule of
/// `is_ref_component`, and holds no `*`. [`ReceivePattern::parse`] refuses
/// each other form:
///
/// - A `!` at the start of the pattern or in the name part. A receive pattern
///   has no negative form. A `!` in a remote part follows the component rule
///   of the remote part.
/// - A `*` in a remote part other than the whole part `*`.
/// - A `*` in a name part other than the whole part `*` or `**`.
/// - An empty pattern, an empty part, or a `:` in the name part.
/// - A control character.
/// - A literal part that fails the ref-name rule, for example one with a space
///   or one that starts with `-`.
///
/// If more than one pattern matches a ref,
/// [`ReceivePolicy::rule_for`](super::ReceivePolicy::rule_for) states which
/// rule applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivePattern {
    /// The pattern as written.
    text: String,
    /// The remote part. It is `None` for a pattern of plain refs.
    remote: Option<RemotePart>,
    /// The name part.
    name: RefPattern,
    /// The kind of each part of the name part, in order.
    kinds: Vec<Kind>,
}

/// The remote part of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RemotePart {
    /// `*:`, every remote.
    Any,
    /// `REMOTE:`, one remote.
    Literal(String),
}

/// The kind of one part of a name part. A larger value is more specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// `**`.
    Many,
    /// `*`.
    One,
    /// A literal.
    Literal,
}

/// The strength of the match of a pattern on a ref. A larger value wins.
///
/// The fields compare in order. A literal remote part wins over `*:`. Then the
/// kinds of the parts of the name part compare from the left: a literal wins
/// over `*`, and `*` wins over `**`. If one list of kinds is the start of the
/// other, the longer one wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Specificity<'a> {
    literal_remote: bool,
    kinds: &'a [Kind],
}

impl ReceivePattern {
    /// Parses a ref pattern of a receive rule.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] if `pattern` is empty, holds a control
    /// character, or has a form outside the syntax of [`ReceivePattern`].
    pub fn parse(pattern: &str) -> Result<ReceivePattern> {
        let malformed = |why: &str| {
            Error::InvalidFormat(format!("malformed receive pattern '{pattern}': {why}"))
        };
        if pattern.is_empty() {
            return Err(malformed("the pattern is empty"));
        }
        if pattern.chars().any(char::is_control) {
            return Err(malformed("the pattern holds a control character"));
        }
        if pattern.starts_with('!') {
            return Err(malformed("a receive pattern has no '!'"));
        }
        let (remote, name) = match pattern.split_once(':') {
            Some((remote, name)) => (Some(remote), name),
            None => (None, pattern),
        };
        let remote = match remote {
            None => None,
            Some("*") => Some(RemotePart::Any),
            Some(remote) if remote.contains('*') => {
                return Err(malformed("a remote part is one remote or '*'"));
            }
            Some(remote) if !is_component(remote) => {
                return Err(malformed("the remote part is not a remote name"));
            }
            Some(remote) => Some(RemotePart::Literal(remote.to_owned())),
        };
        let name_text = name;
        let name = RefPattern::parse(name_text).map_err(|err| match err {
            ostrya_core::Error::InvalidRefPattern(reason) => {
                let quoted = format!("{name_text:?}: ");
                malformed(reason.strip_prefix(&quoted).unwrap_or(&reason))
            }
            other => malformed(&other.to_string()),
        })?;
        let kinds = name
            .as_str()
            .split('/')
            .map(|part| match part {
                "**" => Kind::Many,
                "*" => Kind::One,
                _ => Kind::Literal,
            })
            .collect();
        Ok(ReceivePattern {
            text: pattern.to_owned(),
            remote,
            name,
            kinds,
        })
    }

    /// Returns the pattern as written.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the strength of the match of this pattern on the ref `name` of
    /// the remote `remote`.
    ///
    /// `remote` is `None` for a plain ref. The result is `None` if the pattern
    /// does not match. A pattern with a remote part matches only remote refs.
    /// A pattern with no remote part matches only plain refs.
    pub(crate) fn specificity(&self, remote: Option<&str>, name: &str) -> Option<Specificity<'_>> {
        let literal_remote = match (&self.remote, remote) {
            (None, None) => false,
            (Some(RemotePart::Any), Some(_)) => false,
            (Some(RemotePart::Literal(want)), Some(remote)) if want == remote => true,
            _ => return None,
        };
        if !self.name.matches(name) {
            return None;
        }
        Some(Specificity {
            literal_remote,
            kinds: &self.kinds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, remote: Option<&str>, name: &str) -> bool {
        ReceivePattern::parse(pattern)
            .unwrap()
            .specificity(remote, name)
            .is_some()
    }

    /// Each accepted form parses and keeps its text.
    #[test]
    fn the_accepted_forms_parse() {
        for pattern in [
            "main",
            "apps/x",
            "apps/*",
            "apps/**",
            "a/b/**",
            "a/*/b",
            "*/x",
            "a/**/b",
            "*",
            "**",
            "origin:main",
            "origin:apps/**",
            "origin:*",
            "origin:**",
            "*:main",
            "*:apps/*",
            "*:*",
            "*:**",
            "r!:a",
        ] {
            let parsed = ReceivePattern::parse(pattern).unwrap();
            assert_eq!(parsed.as_str(), pattern);
        }
    }

    /// The parser refuses each form outside the syntax as malformed.
    #[test]
    fn the_other_forms_are_refused() {
        for pattern in [
            "",
            "!a",
            "!*:x",
            "r:!a",
            "a*",
            "*a",
            "***",
            "*/",
            "a//**",
            "a/**x",
            "/*",
            "a//*",
            "a/",
            "/a",
            ":x",
            "r:",
            "r/x:y",
            "r*:x",
            "**:x",
            ".",
            "..",
            "a/./b",
            "a/../*",
            "r:.",
            "..:x",
            "a\tb",
            "a\nb",
            "r:a\u{7f}",
            "a/*b",
            "*:a*",
            "r:a:b",
            "a b/*",
            "a b",
            "-a",
            "a/.b/*",
        ] {
            let err = ReceivePattern::parse(pattern).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidFormat(m) if m.contains("malformed receive pattern")),
                "{pattern:?}: {err}"
            );
        }
    }

    /// `*` selects one part and `**` selects one or more parts.
    #[test]
    fn the_wildcards_select_parts() {
        assert!(matches("a/*", None, "a/b"));
        assert!(!matches("a/*", None, "a/b/c"));
        assert!(!matches("a/*", None, "a"));
        assert!(matches("a/**", None, "a/b"));
        assert!(matches("a/**", None, "a/b/c"));
        assert!(!matches("a/**", None, "a"));
        assert!(!matches("a/**", None, "ab/c"));
        assert!(!matches("a/**", None, "b/a/c"));
        assert!(matches("a/*/c", None, "a/b/c"));
        assert!(!matches("a/*/c", None, "a/b/d/c"));
        assert!(matches("main", None, "main"));
        assert!(!matches("main", None, "main2"));
        assert!(matches("**", None, "a/b"));
        assert!(matches("*", None, "a"));
        assert!(!matches("*", None, "a/b"));
    }

    /// A plain pattern never matches a remote ref, and a remote pattern never
    /// matches a plain ref.
    #[test]
    fn the_remote_part_separates_the_two_kinds() {
        assert!(!matches("main", Some("origin"), "main"));
        assert!(!matches("a/**", Some("origin"), "a/b"));
        assert!(!matches("origin:main", None, "main"));
        assert!(!matches("*:**", None, "main"));
        assert!(matches("*:**", Some("origin"), "main"));
        assert!(matches("origin:**", Some("origin"), "a/b"));
        assert!(!matches("origin:**", Some("other"), "a/b"));
        assert!(!matches("origin:**", Some("origin2"), "a"));
        assert!(!matches("origin:*", Some("origin"), "a/b"));
    }
}
