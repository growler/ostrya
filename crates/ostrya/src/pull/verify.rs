//! The signature checks a pull makes.
//!
//! Two independent policies, one for the commits a pull fetches and one for the
//! remote's summary, each built once per pull from the remote's configuration
//! and the pull's own overrides. The policy, its two axes, and the keys a
//! remote's section names are in the crate's `verify` module, which the receive
//! path shares.
//!
//! A local pull makes no check unless one is asked for, and an HTTP pull reads
//! the remote's configuration, which is what the tool does with `pull-local` and
//! `pull` respectively. Either way the keys come from a remote's configuration
//! section, so a check without a remote name is refused rather than made against
//! an empty trusted set.
//!
//! Where the checks run: the summary is checked as soon as it and its signature
//! are here, before either is read, and a commit is checked in the step that
//! fetched it, before its bytes are staged and before its tree is asked for.
//! Every commit a pull carries is checked, the parents a depth pull follows
//! included, and so is one this repository already holds, since the pull is what
//! states the policy rather than the stored object.

use ostrya_core::{Checksum, Value};

use crate::config::SignVerify;
use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::verify::{Found, KeySource, Policy, Verifiers, build_policy, examine};

use super::PullVerify;

/// What a pull's options leave to the caller's convention when they state no
/// policy of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defaults {
    /// Read the remote's configuration, which is what [`Repo::pull`] does.
    Config,
    /// Check nothing, which is what [`Repo::pull_local`] does.
    Off,
}

/// The checks one pull makes.
pub(crate) struct Verification {
    /// The policy every commit the pull carries is held to.
    commit: Policy,
    /// The policy the remote's summary is held to.
    summary: Policy,
}

impl Verification {
    /// The checks a pull of `remote` makes, from that remote's configuration in
    /// `repo` and the overrides in `verify`.
    ///
    /// `remote` is the name whose configuration section supplies the policy and
    /// the keys. A local pull that names none and asks for a check is refused
    /// here, before anything is imported.
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
            // A remote an HTTP pull names but the configuration does not
            // describe takes the same default a described one does.
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
        };
        let mut cache = Verifiers::default();
        let commit = build_policy(repo, &source, &mut cache, gpg_commit, &sign_commit).await?;
        let summary = build_policy(repo, &source, &mut cache, gpg_summary, &sign_summary).await?;
        Ok(Verification { commit, summary })
    }

    /// Whether this pull checks the commits it carries.
    pub(crate) fn checks_commits(&self) -> bool {
        self.commit.applies()
    }

    /// Whether this pull checks the remote's summary.
    pub(crate) fn checks_summary(&self) -> bool {
        self.summary.applies()
    }

    /// Hold one commit to the commit policy. `detached` is the commit's
    /// detached metadata, which is where its signatures live.
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

    /// Hold the remote's summary to the summary policy.
    ///
    /// A policy that applies needs both files: a source publishing no summary,
    /// and one publishing a summary with no `summary.sig`, are each refused by
    /// name, which is what the tool reports for the same two cases.
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

    /// Hold a fetched static delta to the commit policy's sign-api axis, over
    /// the raw superblock bytes the signatures cover.
    ///
    /// A delta is signed by the sign api alone, so the GPG axis plays no part.
    /// A delta carrying no signature the axis can read is accepted: what the
    /// delta produces is named by the superblock, the superblock is named by the
    /// advertisement, and the commit it delivers is held to the commit policy
    /// like any other, so a stripped signature buys nothing. A delta that does
    /// carry one has to have it from a trusted key.
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

/// Resolve one boolean switch: the pull's override, or the configuration.
fn switch(override_: Option<bool>, configured: impl FnOnce() -> Result<bool>) -> Result<bool> {
    match override_ {
        Some(value) => Ok(value),
        None => configured(),
    }
}

/// Resolve one sign-api switch: the pull's override, where `true` selects every
/// engine this build has, or the configuration.
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

    /// An override wins over the configuration, and an absent one reads it.
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
