//! The policy of a one-way stream and its rules.

use std::sync::Arc;

use super::{ReceivePattern, ReceiveVerify, ServerSigner};

/// The rules that decide what a one-way stream accepts.
///
/// [`Repo::receive_stream`](crate::Repo::receive_stream) takes this policy.
/// A caller builds it in code. The rules select a ref by a
/// [`ReceivePattern`], and they can accept a remote ref. A client group of
/// the config does not apply to a one-way stream.
///
/// The [`Default`] policy holds:
///
/// - the default rule with its defaults, which accepts fast-forward updates of
///   plain refs with no signature verification
/// - no pattern rule, so every remote ref is refused
/// - no privileged content
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
    /// fails.
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
    /// Returns the rule of an update of `refspec`, or `None` if no rule covers
    /// it.
    ///
    /// `refspec` is a plain ref `NAME` or a remote ref `REMOTE:NAME`. `None`
    /// means that the update is refused.
    ///
    /// A remote ref matches only a pattern with a remote part. A plain ref
    /// matches only a pattern without one. Among the patterns that match, the
    /// call selects in this order:
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
    /// `p/x/y/q`. A plain ref that no pattern matches gets
    /// [`default_rule`](StreamPolicy::default_rule). A remote ref that no
    /// pattern matches gets `None`.
    pub fn rule_for(&self, refspec: &str) -> Option<&StreamRule> {
        let (remote, name) = match refspec.split_once(':') {
            Some((remote, name)) => (Some(remote), name),
            None => (None, refspec),
        };
        let mut best = None;
        for (pattern, rule) in &self.rules {
            if let Some(found) = pattern.specificity(remote, name)
                && best.is_none_or(|(held, _)| found > held)
            {
                best = Some((found, rule));
            }
        }
        match best {
            Some((_, rule)) => Some(rule),
            None => remote.is_none().then_some(&self.default_rule),
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
        let rule = policy.rule_for(refspec)?;
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
        let rule = policy.rule_for("main").unwrap();
        assert!(std::ptr::eq(rule, &policy.rules[0].1));
    }
}
