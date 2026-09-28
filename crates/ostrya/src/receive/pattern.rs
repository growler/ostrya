//! The ref patterns of the receive rules.

use crate::error::{Error, Result};
use crate::refs::{is_component, is_ref_path};

/// The refs one receive rule applies to.
///
/// A pattern has one of these forms:
///
/// - `NAME` -- the plain ref `NAME`.
/// - `PREFIX/*` -- every plain ref under `PREFIX/`, at any depth. The pattern
///   does not match `PREFIX` itself.
/// - `REMOTE:NAME`, `REMOTE:PREFIX/*`, and `REMOTE:*` -- the same, and every
///   ref, for the remote refs of the remote `REMOTE`.
/// - `*:NAME`, `*:PREFIX/*`, and `*:*` -- the same, for the remote refs of
///   every remote.
///
/// `NAME` and `PREFIX` are ref names, and `REMOTE` is one component of a ref
/// path. [`RefPattern::parse`] refuses every other form: a `*` in another
/// place, a second `*`, an empty part, a `.` or `..` component, and a control
/// character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefPattern {
    /// The pattern as written.
    text: String,
    /// The remote part, `None` for a pattern of plain refs.
    remote: Option<RemotePart>,
    /// The name part.
    name: NamePart,
}

/// The remote part of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RemotePart {
    /// `*:`, every remote.
    Any,
    /// `REMOTE:`, one remote.
    Literal(String),
}

/// The name part of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NamePart {
    /// One ref name.
    Exact(String),
    /// Every ref under a prefix, held with its trailing `/`.
    Prefix(String),
    /// `*` after a remote part: every ref.
    All,
}

/// How closely a pattern matches a ref. A larger value wins.
///
/// The fields compare in order: a literal remote part wins over `*:`, then an
/// exact name wins over a prefix, and then a longer prefix wins over a shorter
/// one. `REMOTE:*` and `*:*` are prefixes of length zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Specificity {
    literal_remote: bool,
    exact: bool,
    prefix_len: usize,
}

impl RefPattern {
    /// Parse a pattern, refusing a form outside the syntax as
    /// [`Error::InvalidFormat`].
    pub fn parse(pattern: &str) -> Result<RefPattern> {
        let malformed = |why: &str| {
            Error::InvalidFormat(format!("malformed receive pattern '{pattern}': {why}"))
        };
        if pattern.is_empty() {
            return Err(malformed("the pattern is empty"));
        }
        if pattern.chars().any(char::is_control) {
            return Err(malformed("the pattern holds a control character"));
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
        let name = if name == "*" {
            if remote.is_none() {
                return Err(malformed(
                    "'*' alone matches remote refs only; write '*:*' or 'PREFIX/*'",
                ));
            }
            NamePart::All
        } else if let Some(prefix) = name.strip_suffix("/*") {
            if prefix.contains('*') || !is_ref_path(prefix) {
                return Err(malformed("the prefix is not a ref name"));
            }
            NamePart::Prefix(format!("{prefix}/"))
        } else {
            if name.contains('*') || !is_ref_path(name) {
                return Err(malformed("the name is not a ref name"));
            }
            NamePart::Exact(name.to_owned())
        };
        Ok(RefPattern {
            text: pattern.to_owned(),
            remote,
            name,
        })
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// How closely this pattern matches the ref `name` of the remote `remote`,
    /// or of no remote where `remote` is `None`. `None` is a pattern that does
    /// not match: a pattern with a remote part matches remote refs alone, and
    /// one without matches plain refs alone.
    pub(crate) fn specificity(&self, remote: Option<&str>, name: &str) -> Option<Specificity> {
        let literal_remote = match (&self.remote, remote) {
            (None, None) => false,
            (Some(RemotePart::Any), Some(_)) => false,
            (Some(RemotePart::Literal(want)), Some(remote)) if want == remote => true,
            _ => return None,
        };
        let (exact, prefix_len) = match &self.name {
            NamePart::Exact(want) if want == name => (true, 0),
            NamePart::Prefix(prefix) if name.len() > prefix.len() && name.starts_with(prefix) => {
                (false, prefix.len())
            }
            NamePart::All => (false, 0),
            _ => return None,
        };
        Some(Specificity {
            literal_remote,
            exact,
            prefix_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, remote: Option<&str>, name: &str) -> bool {
        RefPattern::parse(pattern)
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
            "a/b/*",
            "origin:main",
            "origin:apps/*",
            "origin:*",
            "*:main",
            "*:apps/*",
            "*:*",
            "r:a:b",
        ] {
            let parsed = RefPattern::parse(pattern).unwrap();
            assert_eq!(parsed.as_str(), pattern);
        }
    }

    /// Each form outside the syntax is refused as malformed.
    #[test]
    fn the_other_forms_are_refused() {
        for pattern in [
            "",
            "*",
            "**",
            "a*",
            "*a",
            "*/x",
            "a/*/b",
            "a/**",
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
            "*:**",
            "*:a*",
        ] {
            let err = RefPattern::parse(pattern).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidFormat(m) if m.contains("malformed receive pattern")),
                "{pattern:?}: {err}"
            );
        }
    }

    /// A prefix matches the refs below it at any depth, and not the prefix
    /// itself or a longer component.
    #[test]
    fn a_prefix_matches_below_it() {
        assert!(matches("a/*", None, "a/b"));
        assert!(matches("a/*", None, "a/b/c"));
        assert!(!matches("a/*", None, "a"));
        assert!(!matches("a/*", None, "ab/c"));
        assert!(!matches("a/*", None, "b/a/c"));
        assert!(matches("main", None, "main"));
        assert!(!matches("main", None, "main2"));
    }

    /// A plain pattern never matches a remote ref, and a remote pattern never
    /// matches a plain ref.
    #[test]
    fn the_remote_part_separates_the_two_kinds() {
        assert!(!matches("main", Some("origin"), "main"));
        assert!(!matches("a/*", Some("origin"), "a/b"));
        assert!(!matches("origin:main", None, "main"));
        assert!(!matches("*:*", None, "main"));
        assert!(matches("*:*", Some("origin"), "main"));
        assert!(matches("origin:*", Some("origin"), "a/b"));
        assert!(!matches("origin:*", Some("other"), "a/b"));
        assert!(!matches("origin:*", Some("origin2"), "a"));
    }
}
