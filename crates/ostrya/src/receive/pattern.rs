//! The ref patterns of the rules of a one-way stream.

use ostrya_core::{Ref, RefPattern};

use crate::error::{Error, Result};
use crate::refs::is_component;

/// A pattern that names the refs of one rule of a one-way stream.
///
/// A pattern has an optional remote part or collection part, and a name
/// part. The name part is a [`RefPattern`]: a path of parts, split at `/`.
/// Each part is a literal, `*`, or `**`. `*` selects exactly one part of a
/// name. `**` selects one or more parts. A pattern has one of these forms:
///
/// - `NAME` -- the plain refs that the name pattern `NAME` matches.
/// - `REMOTE:NAME` -- the remote refs of the remote `REMOTE` that `NAME`
///   matches.
/// - `*:NAME` -- the remote refs of every remote that `NAME` matches.
/// - `@ID:NAME` -- the refs of the collection `ID` that `NAME` matches. In a
///   repository whose collection id is `ID`, these are the plain refs, so
///   `@ID:NAME` matches the same refs as `NAME`.
///
/// For example, `apps/*` selects `apps/web` and does not select `apps` or
/// `apps/web/db`. `apps/**` selects `apps/web` and `apps/web/db`, and does not
/// select `apps`. `central:**` selects every ref of the remote `central`.
/// `@org.example.Os:**` selects every ref of the collection `org.example.Os`.
///
/// `REMOTE` is one component of a ref path, under the wider rule of
/// `is_ref_component`, and holds no `*`. `ID` is one literal collection id:
/// it passes [`is_collection_id`](crate::is_collection_id) and is at most
/// [`MAX_COLLECTION_ID_LEN`](ostrya_core::MAX_COLLECTION_ID_LEN) bytes.
/// [`ReceivePattern::parse`] refuses each other form:
///
/// - A `!` at the start of the pattern or in the name part. A receive pattern
///   has no negative form. A `!` in a remote part follows the component rule
///   of the remote part.
/// - A `*` in a remote part other than the whole part `*`.
/// - An `@` with no `:`, or a collection part that is not a collection id.
/// - A `*` in a name part other than the whole part `*` or `**`.
/// - An empty pattern, an empty part, or a `:` in the name part.
/// - A control character.
/// - A literal part that fails the ref-name rule, for example one with a space
///   or one that starts with `-`.
///
/// If more than one pattern matches a ref,
/// [`StreamPolicy::rule_for`](super::StreamPolicy::rule_for) states which
/// rule applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivePattern {
    /// The pattern as written.
    text: String,
    /// The refs that the pattern can match, from the part before the name
    /// part.
    scope: Scope,
    /// The name part.
    name: RefPattern,
    /// The kind of each part of the name part, in order.
    kinds: Vec<Kind>,
}

/// The part of a pattern before its name part.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Scope {
    /// No part: the plain refs.
    Local,
    /// `*:`, every remote.
    AnyRemote,
    /// `REMOTE:`, one remote.
    Remote(String),
    /// `@ID:`, one collection.
    Collection(String),
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
/// other, the longer one wins. Two patterns that match one collection ref
/// both have the literal collection part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Specificity<'a> {
    literal_remote: bool,
    kinds: &'a [Kind],
}

impl ReceivePattern {
    /// Parses a ref pattern of a rule of a one-way stream.
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
        let (scope, name) = if pattern.starts_with('@') {
            let Some((id, name)) = ostrya_core::split_collection(pattern) else {
                return Err(malformed("a collection part '@ID' has no ':'"));
            };
            if !ostrya_core::is_valid_collection_id(id) {
                return Err(malformed("the collection part is not a collection id"));
            }
            (Scope::Collection(id.to_owned()), name)
        } else {
            match pattern.split_once(':') {
                None => (Scope::Local, pattern),
                Some(("*", name)) => (Scope::AnyRemote, name),
                Some((remote, _)) if remote.contains('*') => {
                    return Err(malformed("a remote part is one remote or '*'"));
                }
                Some((remote, _)) if !is_component(remote) => {
                    return Err(malformed("the remote part is not a remote name"));
                }
                Some((remote, name)) => (Scope::Remote(remote.to_owned()), name),
            }
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
            scope,
            name,
            kinds,
        })
    }

    /// Returns the pattern as written.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the strength of the match of this pattern on the ref `r`, in
    /// a repository whose collection id is `own`.
    ///
    /// `r` is in its canonical form: `@OWN:NAME` is the local ref `NAME`.
    /// The result is `None` if the pattern does not match. A pattern with a
    /// remote part matches only remote refs, and a pattern with a collection
    /// part matches only the refs of its collection. A pattern with neither
    /// part, or with the collection part of `own`, matches only plain refs,
    /// with the strength of a pattern with neither part.
    pub(crate) fn specificity(&self, r: &Ref, own: Option<&str>) -> Option<Specificity<'_>> {
        let (literal_remote, name) = match (&self.scope, r) {
            (Scope::Local, Ref::Local { name }) => (false, name),
            (Scope::Collection(want), Ref::Local { name }) if Some(want.as_str()) == own => {
                (false, name)
            }
            (Scope::AnyRemote, Ref::Remote { name, .. }) => (false, name),
            (Scope::Remote(want), Ref::Remote { remote, name }) if want == remote => (true, name),
            (Scope::Collection(want), Ref::Collection { id, name }) if want == id => (true, name),
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
        let r = match remote {
            Some(remote) => Ref::remote(remote, name),
            None => Ref::local(name),
        };
        matches_ref(pattern, &r)
    }

    fn matches_ref(pattern: &str, r: &Ref) -> bool {
        ReceivePattern::parse(pattern)
            .unwrap()
            .specificity(r, None)
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
            "@org.example.Os:main",
            "@org.example.Os:**",
            "@org.example.Os:apps/*",
        ] {
            let parsed = ReceivePattern::parse(pattern).unwrap();
            assert_eq!(parsed.as_str(), pattern);
        }
    }

    #[test]
    fn a_collection_part_must_be_a_collection_id_within_the_limit() {
        let longest = format!("a.{}", "b".repeat(ostrya_core::MAX_COLLECTION_ID_LEN - 2));
        assert!(ReceivePattern::parse(&format!("@{longest}:**")).is_ok());
        for id in [format!("{longest}b"), "nodot".to_owned()] {
            let err = ReceivePattern::parse(&format!("@{id}:**")).unwrap_err();
            assert!(
                err.to_string()
                    .ends_with("the collection part is not a collection id"),
                "{err}"
            );
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
            "@org.example.Os",
            "@:a",
            "@*:a",
            "@org.*:a",
            "@nodot:a",
            "@org.example.Os:",
            "@org.example.Os:a:b",
            "@org.example.Os:!a",
            "!@org.example.Os:a",
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

    /// A collection pattern matches only the refs of its collection, and no
    /// other pattern matches a collection ref.
    #[test]
    fn a_collection_pattern_matches_its_collection_alone() {
        let os = |name: &str| Ref::collection("org.example.Os", name);
        assert!(matches_ref("@org.example.Os:**", &os("a/b")));
        assert!(matches_ref("@org.example.Os:a", &os("a")));
        assert!(!matches_ref("@org.example.Os:a", &os("b")));
        assert!(!matches_ref(
            "@org.example.Os:**",
            &Ref::collection("org.example.Other", "a")
        ));
        assert!(!matches_ref("@org.example.Os:**", &Ref::local("a")));
        assert!(!matches_ref(
            "@org.example.Os:**",
            &Ref::remote("origin", "a")
        ));
        for pattern in ["**", "*:**", "origin:**"] {
            assert!(!matches_ref(pattern, &os("a")), "{pattern}");
        }
    }
}
