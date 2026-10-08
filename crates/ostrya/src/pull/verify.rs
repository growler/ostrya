//! The signature verification of a pull.
//!
//! A pull holds two independent policies: one for the commits that it fetches
//! and one for the summary of the remote. The pull builds each policy once,
//! from the config of the remote and the overrides of the pull.
//!
//! The crate module `verify` holds the policy, its two axes, and the keys that
//! the section of a remote names. The receive path shares that module.
//! [`PullVerify`] states the rules that a caller sees.

use ostrya_core::{Checksum, Value};

use crate::config::SignVerify;
use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::verify::{Found, KeySource, Policy, Verifiers, build_policy, examine};

use super::PullVerify;

/// The source of the policy when the options of a pull state no policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defaults {
    /// Read the config of the remote. [`Repo::pull`] uses this source.
    Config,
    /// Verify nothing. [`Repo::pull_local`] uses this source.
    Off,
}

/// The signature verification of one pull.
pub(crate) struct Verification {
    /// The policy for each commit that the pull carries.
    commit: Policy,
    /// The policy for the summary of the remote.
    summary: Policy,
}

impl Verification {
    /// Builds the verification of a pull of `remote` from its config in `repo`
    /// and the overrides in `verify`.
    ///
    /// The config section of `remote` supplies the policy and the keys. If a
    /// local pull names no remote and asks for a verification, this function
    /// fails with [`Error::Pull`]. The failure comes before the pull imports
    /// an object.
    pub(crate) async fn build(
        repo: &Repo,
        remote: Option<&str>,
        verify: &PullVerify,
        defaults: Defaults,
    ) -> Result<Verification> {
        let section = remote.and_then(|name| repo.config().remote(name));
        let configured = defaults == Defaults::Config;

        let gpg_commit = switch(verify.gpg, || match &section {
            Some(section) if configured => section.gpg_verify(),
            // If an HTTP pull names a remote that the config does not
            // describe, the remote takes the default of a described remote.
            None if configured => Ok(true),
            _ => Ok(false),
        })?;
        let gpg_summary = switch(verify.gpg_summary, || match &section {
            Some(section) if configured => section.gpg_verify_summary(),
            _ => Ok(false),
        })?;
        let sign_commit = engines(verify.sign, || match &section {
            Some(section) if configured => section.sign_verify(),
            _ => Ok(SignVerify::Off),
        })?;
        let sign_summary = engines(verify.sign_summary, || match &section {
            Some(section) if configured => section.sign_verify_summary(),
            _ => Ok(SignVerify::Off),
        })?;

        let asks_for_a_check = gpg_commit
            || gpg_summary
            || sign_commit != SignVerify::Off
            || sign_summary != SignVerify::Off;
        let Some(name) = remote else {
            if asks_for_a_check {
                return Err(Error::Pull(
                    "a signature check takes its keys from a remote's configuration, \
                     so the pull has to name a remote"
                        .into(),
                ));
            }
            return Ok(Verification {
                commit: Policy::default(),
                summary: Policy::default(),
            });
        };

        let source = KeySource::Remote {
            name,
            section: section.as_ref(),
            repo_keyring: true,
        };
        let mut cache = Verifiers::default();
        let commit = build_policy(repo, &source, &mut cache, gpg_commit, &sign_commit).await?;
        let summary = build_policy(repo, &source, &mut cache, gpg_summary, &sign_summary).await?;
        Ok(Verification { commit, summary })
    }

    /// Returns `true` if this pull verifies the commits that it carries.
    pub(crate) fn checks_commits(&self) -> bool {
        self.commit.applies()
    }

    /// Returns `true` if this pull verifies the summary of the remote.
    pub(crate) fn checks_summary(&self) -> bool {
        self.summary.applies()
    }

    /// Verifies one commit against the commit policy.
    ///
    /// `detached` is the detached metadata of the commit, which holds its
    /// signatures.
    pub(crate) async fn check_commit(
        &self,
        checksum: &Checksum,
        bytes: &[u8],
        detached: Option<&Value>,
    ) -> Result<()> {
        if !self.commit.applies() {
            return Ok(());
        }
        self.commit
            .check(&format!("commit {checksum}"), bytes, detached)
            .await
    }

    /// Verifies the summary of the remote against the summary policy.
    ///
    /// A policy that applies needs both files. If the source publishes no
    /// summary, or a summary with no `summary.sig`, this function fails with
    /// [`Error::Signature`]. The message names the missing file. The `ostree`
    /// command reports the same two cases.
    pub(crate) async fn check_summary(
        &self,
        summary: Option<&[u8]>,
        signature: Option<&[u8]>,
    ) -> Result<()> {
        if !self.summary.applies() {
            return Ok(());
        }
        let Some(summary) = summary else {
            return Err(Error::Signature(
                "summary verification is enabled, but no summary is published".into(),
            ));
        };
        let Some(signature) = signature else {
            return Err(Error::Signature(
                "summary verification is enabled, but no summary.sig is published".into(),
            ));
        };
        let dict = crate::summary::parse_signature_dict(signature)?;
        self.summary
            .check("the summary", summary, dict.as_ref())
            .await
    }

    /// Verifies a fetched static delta against the sign-api axis of the commit
    /// policy.
    ///
    /// The signatures cover the raw bytes of the superblock. Only the sign api
    /// signs a delta, so the GPG axis has no part.
    ///
    /// A delta with no signature that the axis can read passes. The removal of
    /// a signature does not let a pull accept other bytes:
    ///
    /// - The superblock names what the delta produces.
    /// - The advertisement names the superblock.
    /// - The commit policy applies to the delivered commit, as to each other
    ///   commit.
    ///
    /// If a delta carries signatures and no signature is from a trusted key,
    /// this function fails with [`Error::Signature`].
    pub(crate) async fn check_delta(
        &self,
        name: &str,
        superblock: &[u8],
        signatures: Option<&Value>,
    ) -> Result<()> {
        let Some(engines) = self.commit.sign_axis() else {
            return Ok(());
        };
        match examine(engines, superblock, signatures).await? {
            Found::Valid | Found::Nothing => Ok(()),
            Found::Untrusted => Err(Error::Signature(format!(
                "static delta {name}: no signature is from a trusted key"
            ))),
        }
    }
}

/// Resolves one boolean switch: the override of the pull, or else the config.
fn switch(override_: Option<bool>, configured: impl FnOnce() -> Result<bool>) -> Result<bool> {
    match override_ {
        Some(value) => Ok(value),
        None => configured(),
    }
}

/// Resolves one sign-api switch: the override of the pull, or else the config.
///
/// An override of `true` selects each engine of this build.
fn engines(
    override_: Option<bool>,
    configured: impl FnOnce() -> Result<SignVerify>,
) -> Result<SignVerify> {
    match override_ {
        Some(true) => Ok(SignVerify::All),
        Some(false) => Ok(SignVerify::Off),
        None => configured(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An override takes precedence over the config. With no override, the
    /// config applies.
    #[test]
    fn switches_resolve_the_override_first() {
        assert!(switch(Some(true), || Ok(false)).unwrap());
        assert!(!switch(Some(false), || Ok(true)).unwrap());
        assert!(switch(None, || Ok(true)).unwrap());

        assert_eq!(
            engines(Some(true), || Ok(SignVerify::Off)).unwrap(),
            SignVerify::All
        );
        assert_eq!(
            engines(Some(false), || Ok(SignVerify::All)).unwrap(),
            SignVerify::Off
        );
        assert_eq!(
            engines(None, || Ok(SignVerify::Engines(vec!["ed25519".to_owned()]))).unwrap(),
            SignVerify::Engines(vec!["ed25519".to_owned()])
        );
    }
}
