//! The policy of a one-way stream and its rules.

use std::sync::Arc;

use ostrya_core::Ref;

use super::{ReceivePattern, ReceiveVerify, ServerSigner};

/// The rules that decide what a one-way stream accepts.
///
/// [`Repo::receive_stream`](crate::Repo::receive_stream) and
/// [`Repo::receive_stream_to_commit`](crate::Repo::receive_stream_to_commit)
/// take this policy. A caller builds it in code. The rules select a ref by a
/// [`ReceivePattern`], and they can accept a remote ref or a collection ref.
/// A client group of the config does not apply to a one-way stream.
///
/// The [`Default`] policy holds:
///
/// - the default rule with its defaults, which accepts fast-forward updates of
///   plain refs with no signature verification
/// - no pattern rule, so every remote ref and every collection ref is refused
/// - no privileged content
/// - the check of `ostree.ref-binding`
/// - no summary signer and no summary regeneration.
///
/// A one-way stream adds no server signature and does not regenerate the
/// summary. It ignores [`StreamRule::signers`],
/// [`summary_signers`](StreamPolicy::summary_signers), and
/// [`update_summary`](StreamPolicy::update_summary).
#[derive(Debug, Default)]
pub struct StreamPolicy {
    /// The rule of each plain ref that no pattern of
    /// [`rules`](StreamPolicy::rules) matches.
    ///
    /// A plain ref is a local ref `NAME`, or `@ID:NAME` with `ID` the
    /// collection id of the repository.
    pub default_rule: StreamRule,
    /// The rules of the refs that their patterns match.
    ///
    /// [`rule_for`](StreamPolicy::rule_for) selects one rule for a ref.
    pub rules: Vec<(ReceivePattern, StreamRule)>,
    /// The switch that accepts privileged content in a `bare` repository.
    ///
    /// Privileged content is a setuid or setgid mode bit, or the
    /// `security.capability` or `security.selinux` extended attribute.
    pub allow_privileged: bool,
    /// The switch that skips the check of `ostree.ref-binding` of each new
    /// commit.
    ///
    /// With `true`, the name of a ref update need not be in the
    /// `ostree.ref-binding` of its new commit. The check of
    /// `ostree.collection-binding` stays on.
    pub disable_verify_bindings: bool,
    /// The keys of a summary signature. A one-way stream ignores them.
    pub summary_signers: Vec<Arc<ServerSigner>>,
    /// The switch of the summary regeneration. A one-way stream ignores it.
    pub update_summary: bool,
}

/// The rule that applies to an update of a ref in a one-way stream.
///
/// A [`StreamPolicy`] holds one rule for each pattern, and a default rule
/// for the plain refs that no pattern matches.
///
/// [`Default`] accepts fast-forward updates with no signature verification.
#[derive(Debug, Clone)]
pub struct StreamRule {
    /// The switch that accepts an update of a matching ref.
    ///
    /// `false` refuses each update.
    pub accept: bool,
    /// The signatures that a commit must carry to become the new value of a
    /// matching ref.
    ///
    /// With [`ReceiveVerify::Keys`], each new commit must pass the
    /// verification on each axis of the keys. A commit with no signature
    /// fails. The rule applies to the new commit of an update of a matching
    /// ref alone. A dependency that field 2 of that commit names gets no
    /// verification, unless an update also takes it as its new commit. Then
    /// the rule of that update applies.
    pub verify: ReceiveVerify,
    /// The switch that accepts an update whose new commit does not descend
    /// from the current one.
    ///
    /// The switch applies only if the client asks for such an update.
    pub allow_non_fast_forward: bool,
    /// The switch that accepts a delete of a matching ref.
    pub allow_delete: bool,
    /// The keys of a server signature. A one-way stream ignores them.
    pub signers: Vec<Arc<ServerSigner>>,
}

impl Default for StreamRule {
    fn default() -> StreamRule {
        StreamRule {
            accept: true,
            verify: ReceiveVerify::Off,
            allow_non_fast_forward: false,
            allow_delete: false,
            signers: Vec::new(),
        }
    }
}

impl StreamPolicy {
    /// Returns the rule of an update of the ref `r` in a repository whose
    /// `[core] collection-id` is `own`, or `None` if no rule covers it.
    ///
    /// `r` is a local ref `NAME`, a remote ref `REMOTE:NAME`, or a collection
    /// ref `@ID:NAME`. `None` means that the update is refused. With `own`
    /// set to `OWN`, the call reads the ref `@OWN:NAME` as the local ref
    /// `NAME`, and the pattern `@OWN:PATTERN` as the pattern `PATTERN`.
    ///
    /// A remote ref matches only a pattern with a remote part. A collection
    /// ref matches only a pattern with the collection part of its id. A local
    /// ref matches only a pattern with neither part, or with the collection
    /// part of `own`. Among the patterns that match, the call selects in this
    /// order:
    ///
    /// 1. A literal remote part wins over `*:`.
    /// 2. The parts of the name pattern compare from the left. At the first
    ///    part where the two patterns differ in kind, a literal wins over `*`,
    ///    and `*` wins over `**`.
    /// 3. If one pattern is a leading run of the other, the longer pattern
    ///    wins.
    ///
    /// For example, `a/b` wins over `a/*`, `a/*` wins over `a/**`, and
    /// `a/b/**` wins over `a/**`. For the ref `a/b/c`, `a/*/c` wins over
    /// `*/b/c`, because the first part decides.
    ///
    /// If two entries of [`rules`](StreamPolicy::rules) tie, the first one
    /// wins. Two patterns tie if they differ only in the text of their
    /// literal parts, for example `**/x/**` and `**/y/**` on the ref
    /// `p/x/y/q`. A local ref that no pattern matches gets
    /// [`default_rule`](StreamPolicy::default_rule). A remote ref or a
    /// collection ref that no pattern matches gets `None`.
    pub fn rule_for(&self, r: &Ref, own: Option<&str>) -> Option<&StreamRule> {
        let r = &r.clone().canonical(own);
        let mut best = None;
        for (pattern, rule) in &self.rules {
            if let Some(found) = pattern.specificity(r, own)
                && best.is_none_or(|(held, _)| found > held)
            {
                best = Some((found, rule));
            }
        }
        match best {
            Some((_, rule)) => Some(rule),
            None => matches!(r, Ref::Local { .. }).then_some(&self.default_rule),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a policy with one default rule for each of `patterns`, in order.
    fn policy(patterns: &[&str]) -> StreamPolicy {
        StreamPolicy {
            rules: patterns
                .iter()
                .map(|pattern| {
                    (
                        ReceivePattern::parse(pattern).unwrap(),
                        StreamRule::default(),
                    )
                })
                .collect(),
            ..StreamPolicy::default()
        }
    }

    /// Returns the pattern of the rule that `rule_for` selects for `refspec`.
    ///
    /// The result is `Some("")` for the default rule and `None` for a refusal.
    fn selected<'a>(policy: &'a StreamPolicy, refspec: &str) -> Option<&'a str> {
        selected_in(policy, None, refspec)
    }

    /// Returns the pattern that `selected` gives, in a repository whose
    /// collection id is `own`.
    fn selected_in<'a>(
        policy: &'a StreamPolicy,
        own: Option<&str>,
        refspec: &str,
    ) -> Option<&'a str> {
        let rule = policy.rule_for(&refspec.parse().unwrap(), own)?;
        if std::ptr::eq(rule, &policy.default_rule) {
            return Some("");
        }
        policy
            .rules
            .iter()
            .find(|(_, held)| std::ptr::eq(held, rule))
            .map(|(pattern, _)| pattern.as_str())
    }

    /// A plain ref never takes a remote rule, and a remote ref never takes a
    /// plain one.
    #[test]
    fn the_remote_part_decides_first() {
        let policy = policy(&["main", "*:**"]);
        assert_eq!(selected(&policy, "main"), Some("main"));
        assert_eq!(selected(&policy, "origin:main"), Some("*:**"));
        assert_eq!(selected(&policy, "other"), Some(""));
    }

    /// A literal remote part wins over `*:`, before the name is compared.
    #[test]
    fn a_literal_remote_wins_over_any_remote() {
        let policy = policy(&["*:apps/x", "origin:**"]);
        assert_eq!(selected(&policy, "origin:apps/x"), Some("origin:**"));
        assert_eq!(selected(&policy, "other:apps/x"), Some("*:apps/x"));
        assert_eq!(selected(&policy, "other:apps/y"), None);
        let policy = self::policy(&["*:a/b", "origin:**"]);
        assert_eq!(selected(&policy, "origin:a/b"), Some("origin:**"));
        let policy = self::policy(&["origin:**", "*:a/b"]);
        assert_eq!(selected(&policy, "origin:a/b"), Some("origin:**"));
    }

    /// A literal wins over `*`, and `*` wins over `**`. The test gives the
    /// rules in both orders.
    #[test]
    fn a_literal_wins_over_one_and_one_over_many() {
        for patterns in [["a/b", "a/*", "a/**"], ["a/**", "a/*", "a/b"]] {
            let policy = policy(&patterns);
            assert_eq!(selected(&policy, "a/b"), Some("a/b"));
            assert_eq!(selected(&policy, "a/c"), Some("a/*"));
            assert_eq!(selected(&policy, "a/c/d"), Some("a/**"));
            assert_eq!(selected(&policy, "a"), Some(""));
        }
        let policy = policy(&["origin:**", "origin:a/**", "origin:a/b"]);
        assert_eq!(selected(&policy, "origin:a/b"), Some("origin:a/b"));
        assert_eq!(selected(&policy, "origin:a/c"), Some("origin:a/**"));
        assert_eq!(selected(&policy, "origin:b"), Some("origin:**"));
    }

    /// A longer pattern wins when the shorter one is its leading run, and the
    /// leftmost differing part decides otherwise.
    #[test]
    fn the_leftmost_part_and_the_length_decide() {
        for patterns in [["a/**", "a/b/**"], ["a/b/**", "a/**"]] {
            let policy = policy(&patterns);
            assert_eq!(selected(&policy, "a/b/c"), Some("a/b/**"));
            assert_eq!(selected(&policy, "a/x/c"), Some("a/**"));
        }
        for patterns in [["a/*/c", "*/b/c"], ["*/b/c", "a/*/c"]] {
            let policy = policy(&patterns);
            assert_eq!(selected(&policy, "a/b/c"), Some("a/*/c"));
        }
        for patterns in [["a/**", "a/**/c"], ["a/**/c", "a/**"]] {
            let policy = policy(&patterns);
            assert_eq!(selected(&policy, "a/x/c"), Some("a/**/c"));
            assert_eq!(selected(&policy, "a/x/d"), Some("a/**"));
        }
    }

    /// Two patterns of equal kinds tie, and the first entry wins.
    #[test]
    fn a_tie_goes_to_the_first_entry() {
        for patterns in [["**/x/**", "**/y/**"], ["**/y/**", "**/x/**"]] {
            let policy = policy(&patterns);
            assert_eq!(selected(&policy, "p/x/y/q"), Some(patterns[0]));
        }
    }

    /// A plain ref that no pattern matches gets the default rule, and a remote
    /// ref that no pattern matches is refused.
    #[test]
    fn an_unmatched_ref_takes_the_default_or_is_refused() {
        let policy = StreamPolicy::default();
        assert_eq!(selected(&policy, "main"), Some(""));
        assert_eq!(selected(&policy, "origin:main"), None);
        let policy = self::policy(&["other:**"]);
        assert_eq!(selected(&policy, "origin:main"), None);
    }

    /// If a hand-built policy repeats a pattern, the first entry wins.
    #[test]
    fn the_first_of_two_equal_patterns_wins() {
        let policy = policy(&["main", "main"]);
        let rule = policy.rule_for(&Ref::local("main"), None).unwrap();
        assert!(std::ptr::eq(rule, &policy.rules[0].1));
    }

    /// A collection ref takes no default rule. It takes only a rule whose
    /// pattern names its collection, and the name part decides among those.
    #[test]
    fn a_collection_ref_needs_a_pattern_of_its_collection() {
        let os = "@org.example.Os";
        assert_eq!(selected(&StreamPolicy::default(), &format!("{os}:a")), None);
        let policy = policy(&["**", "*:**", "@org.example.Os:**", "@org.example.Os:a/*"]);
        assert_eq!(
            selected(&policy, &format!("{os}:a/b")),
            Some("@org.example.Os:a/*")
        );
        assert_eq!(
            selected(&policy, &format!("{os}:b")),
            Some("@org.example.Os:**")
        );
        assert_eq!(selected(&policy, "@org.example.Other:a"), None);
        assert_eq!(selected(&policy, "a"), Some("**"));
        assert_eq!(selected(&policy, "origin:a"), Some("*:**"));
    }

    /// In a repository whose collection id is `OWN`, `@OWN:PATTERN` matches
    /// the plain refs as `PATTERN` does, with the same strength, and the ref
    /// `@OWN:NAME` is the plain ref `NAME`. With another collection id, or
    /// none, the pattern matches only the refs of its collection.
    #[test]
    fn a_pattern_of_the_own_collection_matches_the_plain_refs() {
        let own = Some("org.example.Os");
        let policy = policy(&[
            "@org.example.Os:secret",
            "@org.example.Os:a/*",
            "a/**",
            "a/b",
        ]);
        for name in ["secret", "@org.example.Os:secret"] {
            assert_eq!(
                selected_in(&policy, own, name),
                Some("@org.example.Os:secret")
            );
        }
        assert_eq!(
            selected_in(&policy, own, "a/c"),
            Some("@org.example.Os:a/*")
        );
        assert_eq!(selected_in(&policy, own, "a/b"), Some("a/b"));
        assert_eq!(selected_in(&policy, own, "a/c/d"), Some("a/**"));
        assert_eq!(selected_in(&policy, own, "@org.example.Os:main"), Some(""));
        for patterns in [
            ["@org.example.Os:main", "main"],
            ["main", "@org.example.Os:main"],
        ] {
            let policy = self::policy(&patterns);
            assert_eq!(selected_in(&policy, own, "main"), Some(patterns[0]));
        }
        assert_eq!(selected_in(&policy, None, "secret"), Some(""));
        assert_eq!(
            selected_in(&policy, None, "@org.example.Os:secret"),
            Some("@org.example.Os:secret")
        );
        assert_eq!(
            selected_in(&policy, Some("org.example.Other"), "secret"),
            Some("")
        );
    }
}
