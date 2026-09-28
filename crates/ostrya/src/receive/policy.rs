//! The receive policy and its rules.

use std::path::Path;
use std::sync::Arc;

use crate::error::Result;
use crate::pull::DetachedMetadataFilter;
use crate::repo::Repo;

use super::reader::{self, Origin};
use super::{RefPattern, ServerSigner, TrustedKeys};

/// What a receiving repository accepts, and what it does after it accepts a
/// session.
///
/// [`Default`] is the policy of a repository with no receive group: the
/// default rule with its defaults, which accepts fast-forward updates of
/// plain refs with no signature check and no server signature, no pattern
/// rule, so every remote ref is refused, no privileged content, no summary
/// signer, no summary regeneration, and no detached-metadata filter.
/// [`ReceivePolicy::from_config`] and [`ReceivePolicy::from_file`] read the
/// policy that key-file groups state.
#[derive(Debug, Default)]
pub struct ReceivePolicy {
    /// The rule of each plain ref that no pattern of
    /// [`rules`](ReceivePolicy::rules) matches.
    pub default_rule: ReceiveRule,
    /// The rules of the refs their patterns match. [`ReceivePolicy::rule_for`]
    /// selects one.
    pub rules: Vec<(RefPattern, ReceiveRule)>,
    /// Accept privileged content in a `bare` repository: a setuid or setgid
    /// mode bit, and the `security.capability` and `security.selinux`
    /// extended attributes.
    pub allow_privileged: bool,
    /// The keys the server signs the regenerated summary with, in order.
    pub summary_signers: Vec<Arc<ServerSigner>>,
    /// Regenerate the summary after a session that writes a ref.
    pub update_summary: bool,
    /// The detached-metadata keys the repository does not store, `None` to
    /// store every key.
    pub detached_metadata_filter: Option<DetachedMetadataFilter>,
}

/// The rule of the refs one pattern matches.
///
/// [`Default`] accepts fast-forward updates with no signature check and no
/// server signature.
#[derive(Debug, Clone)]
pub struct ReceiveRule {
    /// Accept an update of a matching ref. `false` refuses each one.
    pub accept: bool,
    /// The signatures each commit that becomes the new value of a matching
    /// ref must carry.
    pub verify: ReceiveVerify,
    /// Accept an update whose new commit does not descend from the current
    /// one, where the client asks for it.
    pub allow_non_fast_forward: bool,
    /// Accept a delete of a matching ref.
    pub allow_delete: bool,
    /// The keys the server signs each commit that becomes the new value of a
    /// matching ref with, in order.
    pub signers: Vec<Arc<ServerSigner>>,
}

impl Default for ReceiveRule {
    fn default() -> ReceiveRule {
        ReceiveRule {
            accept: true,
            verify: ReceiveVerify::Off,
            allow_non_fast_forward: false,
            allow_delete: false,
            signers: Vec::new(),
        }
    }
}

/// The signatures a received commit must carry.
#[derive(Debug, Clone, Default)]
pub enum ReceiveVerify {
    /// No signature check.
    #[default]
    Off,
    /// A valid signature on each axis of the trusted keys.
    Keys(Arc<TrustedKeys>),
}

impl ReceivePolicy {
    /// The policy that the receive groups of the configuration of `repo`
    /// state: `[ex-ostrya receive]` for the default rule and the session keys,
    /// `[ex-ostrya receive "PATTERN"]` for the rule of each pattern,
    /// `[ex-ostrya trust "NAME"]` for each set of trusted keys, and
    /// `[ex-ostrya key "NAME"]` for each server signing key.
    /// `update_summary` comes from `[core] auto-update-summary` and its alias
    /// (see [`RepoConfig::auto_update_summary`](crate::RepoConfig::auto_update_summary)),
    /// and the filter from `[ex-ostrya] detached-metadata-exclude`.
    ///
    /// The groups are parsed strictly. Each of these is refused as
    /// [`Error::InvalidFormat`](crate::Error::InvalidFormat): a group name that
    /// starts with `ex-ostrya ` and has no shape of the list above, a key a
    /// group does not take, a session key in a pattern group, a pattern
    /// outside the syntax of [`RefPattern`], a malformed `verify` value, a
    /// reference to a trust group, a key group, or a remote section that does
    /// not exist, a key that has no effect, and a trust group or a `remote:`
    /// reference that turns on no signature check. A malformed boolean is the
    /// key-file error [`Error::Core`](crate::Error::Core). An engine this build
    /// does not have is [`Error::Unsupported`](crate::Error::Unsupported).
    ///
    /// Each key group and each trust group is built here once, also one that
    /// no rule names, and the rules share it, so a key source the policy
    /// cannot use fails the call. A key source that cannot be read, a key the
    /// engine refuses, and a GPG selector that names no secret key or more
    /// than one are [`Error::Signature`](crate::Error::Signature). A key that is
    /// not valid base64 is the base64 error [`Error::Core`](crate::Error::Core).
    pub async fn from_config(repo: &Repo) -> Result<ReceivePolicy> {
        reader::read(repo, repo.config().keyfile(), Origin::Config).await
    }

    /// The same as [`from_config`](ReceivePolicy::from_config), with the
    /// receive groups and the remote sections read from the file at `path`
    /// alone. A remote section in the file can be one that no rule names. The receive groups of the repository config
    /// are not read. A `remote:` reference reads no keyring inside the
    /// repository: `<repo>/NAME.trustedkeys.gpg` does not take part.
    /// `update_summary` and the filter still come from the repository config.
    ///
    /// The file is read as a regular file alone, up to 1 MiB, in UTF-8. A
    /// group in it that is not a receive group or a remote section is
    /// refused as [`Error::InvalidFormat`](crate::Error::InvalidFormat), and
    /// so is a file that cannot be read.
    pub async fn from_file(repo: &Repo, path: &Path) -> Result<ReceivePolicy> {
        let keyfile = reader::read_policy_file(path).await?;
        reader::read(repo, &keyfile, Origin::File).await
    }

    /// The rule of an update of `refspec`, a plain ref `NAME` or a remote ref
    /// `REMOTE:NAME`, or `None` where the update is refused because no rule
    /// covers it.
    ///
    /// A remote ref matches only a pattern with a remote part, and a plain ref
    /// only a pattern without one. Among the patterns that match, a literal
    /// remote part wins over `*:`, then an exact name wins over a prefix, and
    /// a longer prefix wins over a shorter one. Where two entries of
    /// [`rules`](ReceivePolicy::rules) tie, which only a repeated pattern can
    /// do, the first one wins. A plain ref that no pattern matches gets
    /// [`default_rule`](ReceivePolicy::default_rule), and a remote ref that no
    /// pattern matches gets `None`.
    pub fn rule_for(&self, refspec: &str) -> Option<&ReceiveRule> {
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

    /// A policy with one default rule for each of `patterns`, in order.
    fn policy(patterns: &[&str]) -> ReceivePolicy {
        ReceivePolicy {
            rules: patterns
                .iter()
                .map(|pattern| (RefPattern::parse(pattern).unwrap(), ReceiveRule::default()))
                .collect(),
            ..ReceivePolicy::default()
        }
    }

    /// The pattern of the rule `rule_for` selects for `refspec`, `Some("")`
    /// for the default rule, and `None` for a refusal.
    fn selected<'a>(policy: &'a ReceivePolicy, refspec: &str) -> Option<&'a str> {
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
        let policy = policy(&["main", "*:*"]);
        assert_eq!(selected(&policy, "main"), Some("main"));
        assert_eq!(selected(&policy, "origin:main"), Some("*:*"));
        assert_eq!(selected(&policy, "other"), Some(""));
    }

    /// A literal remote part wins over `*:`, before the name is compared.
    #[test]
    fn a_literal_remote_wins_over_any_remote() {
        let policy = policy(&["*:apps/x", "origin:*"]);
        assert_eq!(selected(&policy, "origin:apps/x"), Some("origin:*"));
        assert_eq!(selected(&policy, "other:apps/x"), Some("*:apps/x"));
        assert_eq!(selected(&policy, "other:apps/y"), None);
    }

    /// An exact name wins over a prefix, and a longer prefix wins over a
    /// shorter one, in the order the rules come in and the reverse.
    #[test]
    fn an_exact_name_and_a_longer_prefix_win() {
        for patterns in [
            ["apps/*", "apps/x/*", "apps/x/main"],
            ["apps/x/main", "apps/x/*", "apps/*"],
        ] {
            let policy = policy(&patterns);
            assert_eq!(selected(&policy, "apps/x/main"), Some("apps/x/main"));
            assert_eq!(selected(&policy, "apps/x/other"), Some("apps/x/*"));
            assert_eq!(selected(&policy, "apps/y"), Some("apps/*"));
            assert_eq!(selected(&policy, "apps"), Some(""));
        }
        let policy = policy(&["origin:*", "origin:a/*", "origin:a/b"]);
        assert_eq!(selected(&policy, "origin:a/b"), Some("origin:a/b"));
        assert_eq!(selected(&policy, "origin:a/c"), Some("origin:a/*"));
        assert_eq!(selected(&policy, "origin:b"), Some("origin:*"));
    }

    /// A plain ref that no pattern matches gets the default rule, and a remote
    /// ref that no pattern matches is refused.
    #[test]
    fn an_unmatched_ref_takes_the_default_or_is_refused() {
        let policy = ReceivePolicy::default();
        assert_eq!(selected(&policy, "main"), Some(""));
        assert_eq!(selected(&policy, "origin:main"), None);
        let policy = self::policy(&["other:*"]);
        assert_eq!(selected(&policy, "origin:main"), None);
    }

    /// Where a hand-built policy repeats a pattern, the first entry wins.
    #[test]
    fn the_first_of_two_equal_patterns_wins() {
        let policy = policy(&["main", "main"]);
        let rule = policy.rule_for("main").unwrap();
        assert!(std::ptr::eq(rule, &policy.rules[0].1));
    }
}
