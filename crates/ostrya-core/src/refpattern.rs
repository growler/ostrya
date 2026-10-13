//! Ref patterns and ref selectors.
//!
//! A [`RefPattern`] is a path of parts that a ref name can match. A
//! [`RefSelector`] is a list of patterns that selects ref names.
//!
//! # Grammar
//!
//! A pattern is split at `/`. Each part is one of these:
//!
//! - A literal. It passes [`is_ref_name_component`], and it matches a part of
//!   a name that is equal to it.
//! - `*`. It matches exactly one part of a name.
//! - `**`. It matches one or more parts of a name.
//!
//! `*` and `**` are valid only as a whole part, so `b*c`, `x**`, and `***`
//! are refused. A pattern is not empty and has no empty part. A pattern has
//! no `!`: the ref-name rule refuses `!` in a name, so a literal never holds
//! one. A name matches a pattern when the parts of the pattern, in order,
//! cover all parts of the name.
//!
//! For example, `a/*` matches `a/b` and does not match `a` or `a/b/c`. `a/**`
//! matches `a/b` and `a/c/d`, and does not match `a`. `a/**/c` matches
//! `a/b/c` and `a/b/d/c`, and does not match `a/c`.
//!
//! # Selectors
//!
//! An entry of a selector is a pattern with an optional first character `!`.
//! The entry with the `!` is a negative pattern, and each other entry is a
//! positive pattern. A name is selected when both of these conditions are
//! true:
//!
//! - The selector has no positive pattern, or a positive pattern matches the
//!   name.
//! - No negative pattern matches the name.
//!
//! The order of the entries has no effect. So `["!a/**", "a/b"]` does not
//! select `a/b`. An empty list is valid and selects each name. An entry
//! with a second `!`, such as `!!a`, is refused.
//!
//! # Cost
//!
//! The matcher is a dynamic program over the parts of the pattern and the
//! parts of the name. It does not recurse and does not backtrack. Its cost
//! is at most the number of pattern parts times the number of name parts, so
//! a pattern such as `**/**/**/x` cannot make a match slow. A caller that
//! takes patterns from the network must cap the number and the length of
//! the patterns, because the cost of all matches grows with both.
//!
//! # Names
//!
//! Matching compares parts and does not check that the name is a valid ref
//! name. A walk of the ref tree can yield a name that the ref-name rule
//! refuses, and a wildcard selects such a name.
//!
//! # Examples
//!
//! ```
//! use ostrya_core::{RefPattern, RefSelector};
//!
//! let pattern = RefPattern::parse("apps/*/stable")?;
//! assert!(pattern.matches("apps/web/stable"));
//! assert!(!pattern.matches("apps/web/db/stable"));
//!
//! let selector = RefSelector::parse(["apps/**", "!apps/web/**"])?;
//! assert!(selector.matches("apps/db/stable"));
//! assert!(!selector.matches("apps/web/stable"));
//! assert!(!selector.matches("os/main"));
//! # Ok::<(), ostrya_core::Error>(())
//! ```

use crate::error::{Error, Result};
use crate::refname::is_ref_name_component;

/// One part of a [`RefPattern`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    /// A part that a name part must equal.
    Literal(String),
    /// `*`: exactly one name part.
    One,
    /// `**`: one or more name parts.
    Many,
}

/// One ref pattern, with no `!`.
///
/// A pattern is split at `/`. Each part is a literal that passes
/// [`is_ref_name_component`], `*`, or `**`. `*` matches exactly one part of a
/// name, and `**` matches one or more parts. `*` and `**` are valid only as a
/// whole part. The matcher costs at most the number of pattern parts times
/// the number of name parts, so a caller that takes patterns from the
/// network must cap the number and the length of the patterns. It does not
/// check that a name is a valid ref name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefPattern {
    text: String,
    parts: Vec<Part>,
}

impl RefPattern {
    /// Parses one pattern.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefPattern`] if the pattern is empty, has an empty
    ///   part, holds `!`, has a part with `*` that is not `*` or `**`, or has
    ///   a literal part that fails [`is_ref_name_component`]. The text names
    ///   the pattern.
    pub fn parse(pattern: &str) -> Result<RefPattern> {
        parse_pattern(pattern, pattern)
    }

    /// Returns the text of the pattern as parsed.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns `true` if the pattern matches `name`.
    ///
    /// The name is not checked against the ref-name rule.
    pub fn matches(&self, name: &str) -> bool {
        let name: Vec<&str> = name.split('/').collect();
        match_parts(&self.parts, &name, &mut 0)
    }
}

/// Parses `pattern`. `entry` is the text that an error names.
fn parse_pattern(pattern: &str, entry: &str) -> Result<RefPattern> {
    let refuse = |why: &str| Error::InvalidRefPattern(format!("{entry:?}: {why}"));
    if pattern.is_empty() {
        return Err(refuse("the pattern is empty"));
    }
    if pattern.contains('!') {
        return Err(refuse(
            "a `!` is valid only as the first character of a selector entry",
        ));
    }
    let mut parts = Vec::new();
    for part in pattern.split('/') {
        parts.push(match part {
            "" => return Err(refuse("the pattern has an empty part")),
            "*" => Part::One,
            "**" => Part::Many,
            _ if part.contains('*') => {
                return Err(refuse("`*` is valid only as a whole part"));
            }
            _ if is_ref_name_component(part) => Part::Literal(part.to_owned()),
            _ => return Err(refuse("a part is not a valid ref-name component")),
        });
    }
    Ok(RefPattern {
        text: pattern.to_owned(),
        parts,
    })
}

/// Matches `name` against `parts` and adds one to `steps` for each cell of
/// the table. Row `i` of the table tells which prefixes of the name the first
/// `i` parts cover.
fn match_parts(parts: &[Part], name: &[&str], steps: &mut usize) -> bool {
    let (m, n) = (parts.len(), name.len());
    if n < m {
        return false;
    }
    let mut prev = vec![false; n + 1];
    prev[0] = true;
    let mut cur = vec![false; n + 1];
    for part in parts {
        // No part covers zero name parts.
        cur[0] = false;
        for j in 1..=n {
            *steps += 1;
            cur[j] = match part {
                Part::Literal(literal) => prev[j - 1] && name[j - 1] == literal,
                Part::One => prev[j - 1],
                Part::Many => prev[j - 1] || cur[j - 1],
            };
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[n]
}

/// A list of positive and negative [`RefPattern`]s.
///
/// An entry is a pattern with an optional first `!`, which makes it negative.
/// A name is selected when the list has no positive pattern or a positive
/// pattern matches it, and no negative pattern matches it. The order of the
/// entries has no effect, and an empty list selects each name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefSelector {
    positive: Vec<RefPattern>,
    negative: Vec<RefPattern>,
}

impl RefSelector {
    /// Parses a list of entries. An entry is a pattern with an optional first
    /// `!`. The selector keeps the entries in their order, with repeats.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefPattern`] if an entry is not valid. The text
    ///   names the entry with its `!`.
    pub fn parse<'a>(entries: impl IntoIterator<Item = &'a str>) -> Result<RefSelector> {
        let mut positive = Vec::new();
        let mut negative = Vec::new();
        for entry in entries {
            match entry.strip_prefix('!') {
                Some(rest) => negative.push(parse_pattern(rest, entry)?),
                None => positive.push(parse_pattern(entry, entry)?),
            }
        }
        Ok(RefSelector { positive, negative })
    }

    /// Returns `true` if the selector selects `name`.
    ///
    /// The name is not checked against the ref-name rule.
    pub fn matches(&self, name: &str) -> bool {
        (self.positive.is_empty() || self.positive.iter().any(|p| p.matches(name)))
            && !self.negative.iter().any(|p| p.matches(name))
    }

    /// Returns the positive patterns in entry order.
    pub fn positive(&self) -> &[RefPattern] {
        &self.positive
    }

    /// Returns the negative patterns in entry order, with the `!` removed.
    pub fn negative(&self) -> &[RefPattern] {
        &self.negative
    }
}

/// The pattern types move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RefPattern>();
    assert_send_sync::<RefSelector>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(p: &str) -> RefPattern {
        RefPattern::parse(p).unwrap()
    }

    #[test]
    fn examples_match() {
        let cases: [(&str, &[&str], &[&str]); 6] = [
            ("a", &["a"], &["a/b"]),
            ("a/b", &["a/b"], &["a/b/c"]),
            ("a/*", &["a/b"], &["a/b/c"]),
            ("a/**", &["a/b", "a/c/d"], &["a"]),
            ("a/*/c", &["a/b/c"], &["a/b/d/c", "a/c"]),
            ("a/**/c", &["a/b/c", "a/b/d/c"], &["a/c"]),
        ];
        for (p, yes, no) in cases {
            let p = pat(p);
            for n in yes {
                assert!(p.matches(n), "{p:?} should match {n:?}");
            }
            for n in no {
                assert!(!p.matches(n), "{p:?} should not match {n:?}");
            }
        }
    }

    #[test]
    fn parse_refusals() {
        let cases = [
            "", "a//b", "/a", "a/", "b*c", "x**", "***", "*a", "a/*b", "!a", "a!", "!", ".", "..",
            "a/.", "-a", "a b", "a:b", "a\0b",
        ];
        for p in cases {
            let err = RefPattern::parse(p).unwrap_err();
            assert!(matches!(err, Error::InvalidRefPattern(_)), "{p:?}: {err:?}");
        }
    }

    #[test]
    fn as_str_returns_text() {
        assert_eq!(pat("a/*/**").as_str(), "a/*/**");
    }

    #[test]
    fn single_star_and_double_star() {
        let star = pat("*");
        let many = pat("**");
        for n in ["a", "main", "x.y"] {
            assert!(star.matches(n), "{n:?}");
        }
        for n in ["a/b", "a/b/c"] {
            assert!(!star.matches(n), "{n:?}");
        }
        for n in ["a", "a/b", "a/b/c/d"] {
            assert!(many.matches(n), "{n:?}");
        }
    }

    #[test]
    fn double_star_minimums() {
        let two = pat("**/**");
        assert!(!two.matches("a"));
        assert!(two.matches("a/b"));
        assert!(two.matches("a/b/c"));
        let lead = pat("**/c");
        assert!(!lead.matches("c"));
        assert!(lead.matches("a/c"));
        assert!(lead.matches("a/b/c"));
        assert!(!pat("a/**/c").matches("a/c"));
    }

    #[test]
    fn names_the_rule_refuses_still_match() {
        for n in ["a^b", "-x/.y", "a b/c"] {
            assert!(pat("**").matches(n), "{n:?}");
        }
        assert!(pat("*").matches("a^b"));
        assert!(pat("*/*").matches("-x/.y"));
    }

    fn sel(entries: &[&str]) -> RefSelector {
        RefSelector::parse(entries.iter().copied()).unwrap()
    }

    #[test]
    fn selector_positive_only() {
        let s = sel(&["a/*", "b"]);
        for (n, want) in [("a/x", true), ("b", true), ("c", false), ("a/x/y", false)] {
            assert_eq!(s.matches(n), want, "{n:?}");
        }
    }

    #[test]
    fn selector_negative_only() {
        let s = sel(&["!a/**"]);
        for (n, want) in [("a/x", false), ("b", true), ("b/c", true)] {
            assert_eq!(s.matches(n), want, "{n:?}");
        }
    }

    #[test]
    fn selector_mixed() {
        let s = sel(&["a/**", "!a/x/**"]);
        for (n, want) in [("a/y", true), ("a/x/z", false), ("b", false)] {
            assert_eq!(s.matches(n), want, "{n:?}");
        }
    }

    #[test]
    fn selector_empty_selects_all() {
        let s = RefSelector::parse(std::iter::empty()).unwrap();
        for n in ["a", "a/b", "x^y"] {
            assert!(s.matches(n), "{n:?}");
        }
        assert!(s.positive().is_empty() && s.negative().is_empty());
    }

    #[test]
    fn selector_order_has_no_effect() {
        for entries in [["!a/**", "a/b"], ["a/b", "!a/**"]] {
            assert!(!sel(&entries).matches("a/b"), "{entries:?}");
        }
    }

    #[test]
    fn selector_repeats_and_order() {
        let s = sel(&["b", "!x", "a", "b", "!y/*", "!x"]);
        let pos: Vec<&str> = s.positive().iter().map(RefPattern::as_str).collect();
        let neg: Vec<&str> = s.negative().iter().map(RefPattern::as_str).collect();
        assert_eq!(pos, ["b", "a", "b"]);
        assert_eq!(neg, ["x", "y/*", "x"]);
        assert!(s.matches("a") && !s.matches("x"));
    }

    #[test]
    fn selector_refusals_name_the_entry() {
        for entry in [
            "!!a", "!", "!a!", "", "a//b", "!b*c", "a!", "! ", "!\0", "!-a",
        ] {
            let err = RefSelector::parse(["ok", entry]).unwrap_err();
            let Error::InvalidRefPattern(text) = &err else {
                panic!("{entry:?}: {err:?}");
            };
            assert!(text.contains(&format!("{entry:?}")), "{entry:?}: {text}");
            assert!(
                err.to_string().starts_with("invalid ref pattern: "),
                "{err}"
            );
        }
    }

    fn count(p: &str, n: usize) -> (bool, usize, usize) {
        let pattern = pat(p);
        let name = vec!["a"; n];
        let mut steps = 0;
        let hit = match_parts(&pattern.parts, &name, &mut steps);
        (hit, steps, pattern.parts.len() * n)
    }

    #[test]
    fn cost_is_bounded_by_the_product() {
        let cases = [
            ("**/**/**/**/x", false),
            ("**/a/**/a/**/a/**/b", false),
            ("*/*/*/*/*/x", false),
            ("**/**/**/**/a", true),
            ("**/a/**/a/**/a/**/a", true),
        ];
        for (p, want) in cases {
            for n in [10, 100, 1000] {
                let (hit, steps, bound) = count(p, n);
                assert_eq!(hit, want, "{p:?} {n}");
                assert!(steps <= bound, "{p:?} {n}: {steps} > {bound}");
                let (_, double, _) = count(p, 2 * n);
                assert!(double <= 2 * steps + 8, "{p:?} {n}: {steps} -> {double}");
            }
        }
    }

    /// A recursive reference matcher, for the cross-check.
    fn naive(parts: &[&str], name: &[&str]) -> bool {
        match parts.split_first() {
            None => name.is_empty(),
            Some((&"**", rest)) => (1..=name.len()).any(|k| naive(rest, &name[k..])),
            Some((&"*", rest)) => !name.is_empty() && naive(rest, &name[1..]),
            Some((lit, rest)) => name.first() == Some(lit) && naive(rest, &name[1..]),
        }
    }

    /// Returns each sequence of 1 to `max` items from `alphabet`.
    fn sequences<'a>(alphabet: &[&'a str], max: usize) -> Vec<Vec<&'a str>> {
        let mut all: Vec<Vec<&str>> = Vec::new();
        let mut layer: Vec<Vec<&str>> = vec![Vec::new()];
        for _ in 0..max {
            layer = layer
                .iter()
                .flat_map(|s| {
                    alphabet.iter().map(move |a| {
                        let mut t = s.clone();
                        t.push(a);
                        t
                    })
                })
                .collect();
            all.extend(layer.iter().cloned());
        }
        all
    }

    #[test]
    fn agrees_with_the_naive_matcher() {
        let patterns = sequences(&["a", "b", "*", "**"], 4);
        let names = sequences(&["a", "b"], 5);
        for p in &patterns {
            let text = p.join("/");
            let pattern = pat(&text);
            for n in &names {
                let name = n.join("/");
                assert_eq!(pattern.matches(&name), naive(p, n), "{text:?} vs {name:?}");
            }
        }
    }
}
