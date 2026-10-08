//! The receive policy and its rules.

use std::path::Path;
use std::sync::Arc;

use crate::error::Result;
use crate::pull::DetachedMetadataFilter;
use crate::repo::Repo;

use super::reader::{self, Origin};
use super::{RefPattern, ServerSigner, TrustedKeys};

/// The rules that decide what a receiving repository accepts.
///
/// The policy also states the steps after an accepted session: the server
/// signatures, the summary regeneration, and the detached-metadata filter.
///
/// The [`Default`] policy holds:
///
/// - the default rule with its defaults, which accepts fast-forward updates of
///   plain refs with no signature verification and no server signature
/// - no pattern rule, so every remote ref is refused
/// - no privileged content
/// - no summary signer and no summary regeneration
/// - no detached-metadata filter.
///
/// [`from_config`](ReceivePolicy::from_config) and
/// [`from_file`](ReceivePolicy::from_file) read the policy from key-file
/// groups. For a repository with no receive group, `from_config` gives the
/// rules of the default policy.
#[derive(Debug, Default)]
pub struct ReceivePolicy {
    /// The rule of each plain ref that no pattern of
    /// [`rules`](ReceivePolicy::rules) matches.
    pub default_rule: ReceiveRule,
    /// The rules of the refs that their patterns match.
    ///
    /// [`rule_for`](ReceivePolicy::rule_for) selects one rule for a ref.
    pub rules: Vec<(RefPattern, ReceiveRule)>,
    /// The switch that accepts privileged content in a `bare` repository.
    ///
    /// Privileged content is a setuid or setgid mode bit, or the
    /// `security.capability` or `security.selinux` extended attribute.
    pub allow_privileged: bool,
    /// The keys that the server signs the regenerated summary with, in order.
    pub summary_signers: Vec<Arc<ServerSigner>>,
    /// The switch that regenerates the summary after a session that writes a
    /// ref.
    pub update_summary: bool,
    /// The detached-metadata keys that the repository does not store.
    ///
    /// `None` stores every key.
    pub detached_metadata_filter: Option<DetachedMetadataFilter>,
}

/// The rule that applies to an update of a ref.
///
/// A [`ReceivePolicy`] holds one rule for each pattern, and a default rule
/// for the plain refs that no pattern matches.
///
/// [`Default`] accepts fast-forward updates with no signature verification
/// and no server signature.
#[derive(Debug, Clone)]
pub struct ReceiveRule {
    /// The switch that accepts an update of a matching ref.
    ///
    /// `false` refuses each update.
    pub accept: bool,
    /// The signatures that a commit must carry to become the new value of a
    /// matching ref.
    pub verify: ReceiveVerify,
    /// The switch that accepts an update whose new commit does not descend
    /// from the current one.
    ///
    /// The switch applies only if the client asks for such an update.
    pub allow_non_fast_forward: bool,
    /// The switch that accepts a delete of a matching ref.
    pub allow_delete: bool,
    /// The keys that the server signs the new commits of a matching ref with.
    ///
    /// A new commit is a commit that becomes the new value of the ref. The
    /// server signs with the keys in order.
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

/// The signatures that a received commit must carry.
#[derive(Debug, Clone, Default)]
pub enum ReceiveVerify {
    /// No signature verification.
    #[default]
    Off,
    /// A valid signature on each axis of the trusted keys.
    Keys(Arc<TrustedKeys>),
}

impl ReceivePolicy {
    /// Reads the receive policy from the configuration of `repo`.
    ///
    /// The policy comes from these groups:
    ///
    /// - `[ex-ostrya receive]` for the default rule and the session keys
    /// - `[ex-ostrya receive "PATTERN"]` for the rule of each pattern
    /// - `[ex-ostrya trust "NAME"]` for each set of trusted keys
    /// - `[ex-ostrya key "NAME"]` for each server signing key.
    ///
    /// [`update_summary`](ReceivePolicy::update_summary) comes from
    /// `[core] auto-update-summary` and its alias, as
    /// [`auto_update_summary`](crate::RepoConfig::auto_update_summary) reads
    /// them. The filter comes from `[ex-ostrya] detached-metadata-exclude`.
    ///
    /// The call parses the groups strictly. It builds each key group and each
    /// trust group once, in file order, also a group that no rule names. The
    /// rules share these builds, so a key source that the policy cannot use
    /// fails the call.
    ///
    /// # Keys
    ///
    /// Each receive group takes the rule keys:
    ///
    /// - `accept`: a boolean, `true` by default. `false` refuses each update
    ///   of a matching ref.
    /// - `verify`: `off` (the default), `trust:NAME`, or `remote:NAME`.
    /// - `allow-non-fast-forward`: a boolean. If `true`, the rule accepts a
    ///   new commit that does not descend from the current commit of the ref.
    /// - `allow-delete`: a boolean. If `true`, the rule accepts a ref delete.
    /// - `sign`: a list of key group names. The server signs each new commit
    ///   of a matching ref with these keys.
    ///
    /// `trust:NAME` uses the trust group `NAME`. `remote:NAME` uses the keys
    /// that a pull from the remote `NAME` trusts, as
    /// [`TrustedKeys::for_remote`] reads them. A pattern rule takes no key
    /// from the default rule.
    ///
    /// `[ex-ostrya receive]` also takes the session keys:
    ///
    /// - `allow-privileged`: a boolean. If `true`, a session on a `bare`
    ///   repository accepts the setuid and setgid bits, `security.capability`,
    ///   and `security.selinux`.
    /// - `sign-summary`: a list of key group names. These keys sign the new
    ///   summary.
    ///
    /// A trust group takes `gpg-verify`, `gpgkeypath`, `sign-verify`,
    /// `verification-ENGINE-key`, and `verification-ENGINE-file`, in the value
    /// forms of a remote section.
    ///
    /// A key group takes `type`, which is `ed25519`, `spki`, or `gpg`. An
    /// `ed25519` or `spki` key group takes `secret-key-file`. A `gpg` key group
    /// takes `gpg-key`, and `gpg-homedir` as an option.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if:
    ///   - a group name starts with `ex-ostrya ` and is not one of the four
    ///     groups, or its quoted name is malformed
    ///   - a group holds a key that it does not take, or a pattern group holds
    ///     a session key
    ///   - a pattern is outside the syntax of [`RefPattern`]
    ///   - a `verify` value is malformed
    ///   - a reference names a trust group, a key group, or a remote section
    ///     that does not exist
    ///   - a key has no effect
    ///   - a trust group or a `remote:` reference turns on no signature
    ///     verification
    ///   - a trust group names an engine other than `ed25519` or `spki`, or
    ///     sets `gpg-verify=true` and its `gpgkeypath` names no keyring
    ///   - a key group has no `type`, an unknown `type`, the type `dummy`, or
    ///     no value for a required key.
    /// - [`Error::Unsupported`](crate::Error::Unsupported) if a group names a
    ///   signing or verification engine that this build does not have.
    /// - [`Error::Signature`](crate::Error::Signature) if:
    ///   - a key source cannot be read
    ///   - a secret key file does not exist, holds no key, or holds more than
    ///     one key
    ///   - an engine refuses a key
    ///   - a GPG selector names no secret key or more than one, or `gpg` fails
    ///   - an engine that `sign-verify` names has no trusted key, or no engine
    ///     has a trusted key
    ///   - the keyrings that a trust group names hold no certificate.
    /// - [`Error::Core`](crate::Error::Core) if a boolean value is malformed,
    ///   a string value holds a malformed escape sequence, or a key is not
    ///   valid base64.
    /// - [`Error::Io`](crate::Error::Io) if a directory of keys cannot be
    ///   listed, or if the read of the output of `gpg` or the wait for `gpg`
    ///   fails.
    pub async fn from_config(repo: &Repo) -> Result<ReceivePolicy> {
        reader::read(repo, repo.config().keyfile(), Origin::Config).await
    }

    /// Reads the receive policy from the file at `path`.
    ///
    /// The call reads the receive groups and the remote sections from the file
    /// only, and parses them as [`from_config`](ReceivePolicy::from_config)
    /// does. It does not read the receive groups of the repository config. The
    /// file can hold a remote section that no rule names.
    ///
    /// A `remote:` reference reads no keyring inside the repository:
    /// `<repo>/NAME.trustedkeys.gpg` does not take part.
    /// [`update_summary`](ReceivePolicy::update_summary) and the filter come
    /// from the repository config.
    ///
    /// The file must be a regular file of up to 1 MiB, in UTF-8.
    ///
    /// # Errors
    ///
    /// - Each error of [`from_config`](ReceivePolicy::from_config).
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if the file
    ///   cannot be opened or read, is not a regular file, is larger than
    ///   1 MiB, or is not valid UTF-8.
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if the file
    ///   holds a group that is not a receive group or a remote section.
    /// - [`Error::Core`](crate::Error::Core) if the file is not a valid key
    ///   file.
    pub async fn from_file(repo: &Repo, path: &Path) -> Result<ReceivePolicy> {
        let keyfile = reader::read_policy_file(path).await?;
        reader::read(repo, &keyfile, Origin::File).await
    }

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
    /// 2. An exact name wins over a prefix.
    /// 3. A longer prefix wins over a shorter one.
    ///
    /// If two entries of [`rules`](ReceivePolicy::rules) tie, the first one
    /// wins. Only a repeated pattern can cause a tie. A plain ref that no
    /// pattern matches gets [`default_rule`](ReceivePolicy::default_rule). A
    /// remote ref that no pattern matches gets `None`.
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

    /// Returns a policy with one default rule for each of `patterns`, in order.
    fn policy(patterns: &[&str]) -> ReceivePolicy {
        ReceivePolicy {
            rules: patterns
                .iter()
                .map(|pattern| (RefPattern::parse(pattern).unwrap(), ReceiveRule::default()))
                .collect(),
            ..ReceivePolicy::default()
        }
    }

    /// Returns the pattern of the rule that `rule_for` selects for `refspec`.
    ///
    /// The result is `Some("")` for the default rule and `None` for a refusal.
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
    /// shorter one. The test gives the rules in both orders.
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

    /// If a hand-built policy repeats a pattern, the first entry wins.
    #[test]
    fn the_first_of_two_equal_patterns_wins() {
        let policy = policy(&["main", "main"]);
        let rule = policy.rule_for("main").unwrap();
        assert!(std::ptr::eq(rule, &policy.rules[0].1));
    }
}
