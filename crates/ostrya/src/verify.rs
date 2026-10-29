//! The trusted keys and the trust of one pull.
//!
//! [`TrustedKeys`] holds a set of verifiers and the signature axes that the set
//! requires. The axes are GPG and the sign api. The axes are ANDed: each axis
//! of a set must find a valid signature. The engines of the sign-api axis are
//! ORed: one valid signature from one engine is enough.
//!
//! [`PullTrust`] holds the trusted keys of one pull: one set for the commits
//! and one set for the summary of the remote. [`PullTrust::from_remote`] reads
//! the trust from the configuration of a remote, as [`Repo::pull`] does.
//! [`PullTrust::commits`] and [`PullTrust::with_summary`] take keys that the
//! caller holds.

// The module also builds the policy of a target from a key source: the
// configuration section of a remote, or a trust group.
// The pull and the receive path share this build.

#[cfg(feature = "verify-gpg")]
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;

use ostrya_core::{Value, base64};
use rustix::fs::{Mode, OFlags};
#[cfg(feature = "verify-gpg")]
use rustix::io::Errno;

use crate::config::{Remote, SignVerify, valid_remote_name};
use crate::error::{Error, Result};
#[cfg(feature = "verify-gpg")]
use crate::gpg::read_keyring_fd;
use crate::pull::PullVerify;
use crate::repo::Repo;
use crate::sign::{
    Ed25519Verifier, MAX_KEY_FILE, SignKeys, Verifier, key_text, load_sign_keys, read_key_source,
    signatures_for,
};

pub(crate) mod trust;

/// The detached-metadata key of the dummy engine.
const DUMMY_METADATA_KEY: &str = "ostree.sign.dummy";

/// A set of trusted keys and the signature axes that it requires.
///
/// A set with a GPG axis and a sign-api axis needs a valid signature on each
/// axis. On the sign-api axis, one valid signature from one engine is enough.
/// The set holds its verifiers, so the verification of a commit reads no key
/// source.
///
/// [`PullTrust`] holds a set for the commits and a set for the summary of one
/// pull. With the `receive` feature, the policy of a client group and a rule
/// of a one-way stream can each hold a set, in `ReceiveVerify::Keys`, for the
/// commits that they accept.
#[derive(Clone)]
pub struct TrustedKeys {
    /// The built axes. At least one axis applies.
    policy: Policy,
}

impl TrustedKeys {
    /// Creates trusted keys with a sign-api axis over `sign`.
    ///
    /// `sign` holds one verifier for each engine. The call refuses a verifier
    /// of the dummy engine, because its signature is its key and proves
    /// nothing about the signer.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `sign` is empty, because an empty set
    ///   trusts no key.
    /// - [`Error::InvalidFormat`] if `sign` holds a verifier of the dummy
    ///   engine.
    pub fn new(sign: Vec<Arc<dyn Verifier>>) -> Result<TrustedKeys> {
        if sign.is_empty() {
            return Err(Error::InvalidFormat(
                "the trusted keys name no verifier".into(),
            ));
        }
        refuse_dummy(&sign)?;
        Ok(TrustedKeys {
            policy: Policy::from_axes(None, Some(sign)),
        })
    }

    /// Creates trusted keys with a GPG axis over `gpg`.
    ///
    /// If `sign` is not empty, the set also gets a sign-api axis over `sign`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] if `sign` holds a verifier of the dummy engine,
    /// as [`new`](TrustedKeys::new) refuses it.
    #[cfg(feature = "verify-gpg")]
    pub fn with_gpg(
        gpg: crate::gpg::GpgVerifier,
        sign: Vec<Arc<dyn Verifier>>,
    ) -> Result<TrustedKeys> {
        refuse_dummy(&sign)?;
        let sign = (!sign.is_empty()).then_some(sign);
        Ok(TrustedKeys {
            policy: Policy::from_axes(Some(Arc::new(gpg)), sign),
        })
    }

    /// Creates trusted keys over a built policy.
    ///
    /// The policy must apply: it holds at least one axis.
    pub(crate) fn from_policy(policy: Policy) -> TrustedKeys {
        debug_assert!(policy.applies(), "trusted keys need at least one axis");
        TrustedKeys { policy }
    }

    /// Returns the policy of this set.
    #[cfg(any(feature = "receive", feature = "s3"))]
    pub(crate) fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Returns the policy of this set, and drops the set.
    pub(crate) fn into_policy(self) -> Policy {
        self.policy
    }
}

/// Refuses a verifier of the dummy engine in `sign`.
fn refuse_dummy(sign: &[Arc<dyn Verifier>]) -> Result<()> {
    if sign.iter().any(|v| v.metadata_key() == DUMMY_METADATA_KEY) {
        return Err(Error::InvalidFormat(
            "the trusted keys name a dummy verifier, whose signature is its key".into(),
        ));
    }
    Ok(())
}

impl std::fmt::Debug for TrustedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sign: Option<Vec<&str>> = self
            .policy
            .sign_axis()
            .map(|engines| engines.iter().map(|v| v.metadata_key()).collect());
        f.debug_struct("TrustedKeys")
            .field("gpg", &self.policy.gpg_axis())
            .field("sign", &sign)
            .finish()
    }
}

/// The trusted keys of one pull: a set for the commits, and a set for the
/// summary of the remote.
///
/// A pull checks each target, each parent that its depth takes, and each
/// commit of a chain of static deltas against the commit set, and the summary
/// against the summary set. A dependency in no other role gets no check. The
/// pull does not check a target that has no set. If the commit set has a
/// sign-api axis and a static delta carries signatures that this axis reads,
/// one of them must be valid. The pull does not check the signatures of other
/// static deltas.
///
/// [`PullTrust::from_remote`] reads the trust that [`Repo::pull`] uses.
/// [`PullTrust::commits`] and [`PullTrust::with_summary`] take keys that the
/// caller holds. [`PullTrust::unverified`] checks nothing.
///
/// # Examples
///
/// The trust of a pull that checks its commits against one ed25519 key:
///
/// ```
/// use std::sync::Arc;
///
/// use ostrya::base64;
/// use ostrya::sign::Ed25519Verifier;
/// use ostrya::verify::{PullTrust, TrustedKeys};
///
/// # fn main() -> ostrya::Result<()> {
/// let public = base64::decode("wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=")?;
/// let verifier = Ed25519Verifier::new([public], Vec::<Vec<u8>>::new())?;
/// let trust = PullTrust::commits(TrustedKeys::new(vec![Arc::new(verifier)])?);
/// # let _ = trust;
/// # Ok(()) }
/// ```
#[derive(Clone, Debug)]
pub struct PullTrust {
    /// The keys of the commits, or `None` if the pull does not check them.
    commit: Option<TrustedKeys>,
    /// The keys of the summary, or `None` if the pull does not check it.
    summary: Option<TrustedKeys>,
}

impl PullTrust {
    /// Creates the trust of a pull that checks no signature.
    pub fn unverified() -> PullTrust {
        PullTrust {
            commit: None,
            summary: None,
        }
    }

    /// Creates the trust of a pull that checks its commits against `keys`.
    ///
    /// The pull does not check the summary. `keys` is the whole trusted set of
    /// the commits: the pull reads no system key store and no keyring of the
    /// repository for them.
    pub fn commits(keys: TrustedKeys) -> PullTrust {
        PullTrust {
            commit: Some(keys),
            summary: None,
        }
    }

    /// Sets the keys that the pull checks the summary of the remote against.
    ///
    /// `keys` replaces the summary keys that this trust held before. The
    /// commit keys do not change. `keys` is the whole trusted set of the
    /// summary: the pull reads no system key store and no keyring of the
    /// repository for it.
    pub fn with_summary(self, keys: TrustedKeys) -> PullTrust {
        PullTrust {
            summary: Some(keys),
            ..self
        }
    }

    /// Returns the keys that the pull checks the summary of the remote
    /// against, or `None` if the pull does not check the summary.
    ///
    /// With the `s3` feature, `BucketRepo::fsck` takes these keys in
    /// `BucketFsckOptions::summary_keys`.
    pub fn summary_keys(&self) -> Option<&TrustedKeys> {
        self.summary.as_ref()
    }

    /// Reads the trust that [`Repo::pull`] uses for a pull from `remote`.
    ///
    /// The keys come from the `[remote "NAME"]` section of the repository
    /// config and from these key sources:
    ///
    /// - `gpgkeypath`
    /// - the repository keyring `<repo>/NAME.trustedkeys.gpg`
    /// - the system keyring `/etc/ostree/remotes.d/NAME.trustedkeys.gpg`
    /// - the global GPG trusted directory
    /// - the `verification-*` keys
    /// - the system sign-api key store, minus its revoked set
    ///
    /// Each field of `verify` that is set overrides the config key of the
    /// same name (see [`PullVerify`]). If the config has no section for
    /// `remote`, the trust takes the defaults of a described remote: the GPG
    /// verification of the commits is on, and the other checks are off.
    ///
    /// The call reads each key source before it returns. The trust that it
    /// gives reads no key source again.
    ///
    /// # Trust groups
    ///
    /// If the section holds the key [`trust`](crate::config::Remote::trust),
    /// the trust group `[ex-ostrya trust "NAME"]` that the key names sets the
    /// commit policy. The commit keys come from the group alone: no system
    /// key store, no repository keyring `<repo>/NAME.trustedkeys.gpg`, no
    /// system keyring, and no global GPG trusted directory. The keys
    /// `gpg-verify-summary` and `sign-verify-summary` of the section and the
    /// key sources that they read set the summary policy, as without a trust
    /// group. The two policies share no verifier.
    ///
    /// The call checks the group as the receive side does, and builds only
    /// the axes that stay on. `Some(false)` in `verify.gpg` or `verify.sign`
    /// turns off that commit axis of the group. The summary fields of
    /// `verify` override the summary keys of the section.
    ///
    /// The section must not turn on a commit check: the call refuses
    /// `gpg-verify=true` and a `sign-verify` value other than false. It
    /// accepts `gpg-verify=false` and an absent `gpg-verify`, and both give no
    /// GPG check of the commits. The call also refuses a key source of the
    /// section that no summary check reads: `gpgkeypath` when
    /// `gpg-verify-summary` is not true, and a `verification-ENGINE-key` or a
    /// `verification-ENGINE-file` of an engine that `sign-verify-summary` does
    /// not select. `sign-verify-summary=true` selects `ed25519` and `spki`.
    /// This rule reads the summary keys of the section, and not the fields of
    /// `verify`.
    ///
    /// Each refusal of a trust group comes before the call reads a key
    /// source.
    ///
    /// This call reads the key `trust` alone. [`Repo::pull`] and
    /// [`Repo::pull_collection`] also read
    /// [`PullOptions::trust_group`](crate::PullOptions::trust_group). The field
    /// names a trust group that wins over the key, and the rules of this
    /// section apply to that group.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if [`valid_remote_name`] refuses `remote`.
    ///   The call refuses the name before it reads a key source.
    /// - [`Error::InvalidFormat`] if the `trust` value is empty or holds a `"`
    ///   or a control character, if it names no trust group, if the group
    ///   fails the check of a trust group, or if the section breaks a rule of
    ///   a trust group above.
    /// - [`Error::InvalidInput`] if the section holds `trust`, and
    ///   `verify.gpg` or `verify.sign` is `Some(true)`.
    /// - [`Error::Core`] if `gpg-verify` or `gpg-verify-summary` is not a
    ///   boolean, if a value holds a malformed escape sequence, or if a
    ///   sign-api key is not valid base64.
    /// - [`Error::Signature`] if `sign-verify` or `sign-verify-summary` names
    ///   an engine that has no trusted key, or if a check of every engine finds
    ///   no engine with a trusted key.
    /// - [`Error::Signature`] if a keyring or a key file cannot be read, or if
    ///   its content is not valid for its engine.
    /// - [`Error::Unsupported`] if `sign-verify` or `sign-verify-summary` names
    ///   an engine that this build does not verify with.
    /// - [`Error::Unsupported`] if the trust asks for GPG verification and the
    ///   build has no `verify-gpg` feature. Also if a trust group sets
    ///   `gpg-verify=true` in such a build, or names the spki engine in a
    ///   build with no spki key feature, whatever the fields of `verify`.
    /// - [`Error::Io`] if a directory of keys cannot be listed.
    pub async fn from_remote(repo: &Repo, remote: &str, verify: &PullVerify) -> Result<PullTrust> {
        PullTrust::for_pull(repo, remote, verify, None).await
    }

    /// Reads the trust of a pull from `remote`, as
    /// [`from_remote`](PullTrust::from_remote) does, with the trust group
    /// `group` of [`PullOptions::trust_group`](crate::PullOptions::trust_group).
    ///
    /// The call refuses a name that [`valid_remote_name`] refuses with
    /// [`Error::InvalidInput`], before it reads a key source.
    pub(crate) async fn for_pull(
        repo: &Repo,
        remote: &str,
        verify: &PullVerify,
        group: Option<&mut trust::FieldGroup<'_>>,
    ) -> Result<PullTrust> {
        if !valid_remote_name(remote) {
            return Err(Error::InvalidInput(format!(
                "invalid remote name: {remote}"
            )));
        }
        PullTrust::resolve(repo, Some(remote), verify, group, Defaults::Config).await
    }

    /// Resolves the trust of a pull of `remote` from its config in `repo` and
    /// the overrides in `verify`.
    ///
    /// The config section of `remote` supplies the policy and the keys.
    /// `defaults` gives the policy of a remote that has no section. If a
    /// local pull names no remote and asks for a verification, this function
    /// fails with [`Error::Pull`]. The failure comes before the pull imports
    /// an object.
    ///
    /// `group` is the trust group that the options of the pull name. It wins
    /// over the key `trust` of the section, and the call then does not read
    /// that key. With a trust group, the group sets the commit policy, and the
    /// call ignores `defaults`. A pull with a trust group that names no remote
    /// checks no summary. The call keeps the commit policy of the group in
    /// `group`, and a later call with the same `group` and the same `verify`
    /// reads no key source of the group again.
    pub(crate) async fn resolve(
        repo: &Repo,
        remote: Option<&str>,
        verify: &PullVerify,
        group: Option<&mut trust::FieldGroup<'_>>,
        defaults: Defaults,
    ) -> Result<PullTrust> {
        let section = remote.and_then(|name| repo.config().remote(name));
        // A trust group that the options of the pull name, or else the trust
        // group that the key `trust` of the remote names, supplies the commit
        // keys.
        if let Some(group) = group {
            let name = trust::GroupName::Field(group.name);
            return trust::pull_trust(
                repo,
                remote,
                section.as_ref(),
                name,
                verify,
                &mut group.commit,
            )
            .await;
        }
        if let (Some(remote), Some(section)) = (remote, &section)
            && let Some(value) = section.trust()?
        {
            let name = trust::GroupName::Key {
                remote,
                value: &value,
            };
            return trust::pull_trust(repo, Some(remote), Some(section), name, verify, &mut None)
                .await;
        }

        let gpg_commit = switch(verify.gpg, || match &section {
            Some(section) => section.gpg_verify(),
            // If an HTTP pull names a remote that the config does not
            // describe, the remote takes the default of a described remote.
            None => Ok(defaults == Defaults::Config),
        })?;
        let sign_commit = engines(verify.sign, || match &section {
            Some(section) => section.sign_verify(),
            None => Ok(SignVerify::Off),
        })?;
        let (gpg_summary, sign_summary) = summary_switches(section.as_ref(), verify)?;

        let asks_for_a_check = gpg_commit
            || gpg_summary
            || sign_commit != SignVerify::Off
            || sign_summary != SignVerify::Off;
        let Some(name) = remote else {
            if asks_for_a_check {
                return Err(no_remote());
            }
            return Ok(PullTrust::unverified());
        };

        let source = KeySource::Remote {
            name,
            section: section.as_ref(),
            repo_keyring: true,
        };
        let mut cache = Verifiers::default();
        let commit = build_policy(repo, &source, &mut cache, gpg_commit, &sign_commit).await?;
        let summary = build_policy(repo, &source, &mut cache, gpg_summary, &sign_summary).await?;
        Ok(PullTrust {
            commit: commit.applies().then(|| TrustedKeys::from_policy(commit)),
            summary: summary.applies().then(|| TrustedKeys::from_policy(summary)),
        })
    }

    /// Returns the commit policy and the summary policy of this trust. A
    /// target with no keys gets a policy that holds no axis.
    pub(crate) fn into_policies(self) -> (Policy, Policy) {
        (
            self.commit
                .map(TrustedKeys::into_policy)
                .unwrap_or_default(),
            self.summary
                .map(TrustedKeys::into_policy)
                .unwrap_or_default(),
        )
    }
}

/// The trust types move freely across tasks and threads, so one trust can
/// serve pulls on many tasks.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TrustedKeys>();
    assert_send_sync::<PullTrust>();
};

/// Returns the refusal of a check that takes its keys from the section of a
/// remote, in a pull that names no remote.
fn no_remote() -> Error {
    Error::Pull(
        "a signature check takes its keys from a remote's configuration, so the pull \
         has to name a remote"
            .into(),
    )
}

/// The source of the policy when the options of a pull state no policy.
///
/// A trust group of the pull sets the commit policy whatever the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defaults {
    /// Read the config of the remote. A remote with no section takes the
    /// defaults of a described remote, so the GPG check of the commits is on.
    /// [`Repo::pull`] uses this source.
    Config,
    /// Read the config of the remote if the config has a section for it. A
    /// remote with no section, or no remote, gives no check.
    /// [`Repo::pull_local`] uses this source.
    Section,
}

/// Resolves the summary switches of a pull: the overrides in `verify`, or else
/// the summary keys of `section`. A remote with no section checks no summary.
fn summary_switches(
    section: Option<&Remote<'_>>,
    verify: &PullVerify,
) -> Result<(bool, SignVerify)> {
    let gpg = switch(verify.gpg_summary, || match section {
        Some(section) => section.gpg_verify_summary(),
        None => Ok(false),
    })?;
    let sign = engines(verify.sign_summary, || match section {
        Some(section) => section.sign_verify_summary(),
        None => Ok(SignVerify::Off),
    })?;
    Ok((gpg, sign))
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

/// The sign-api engines that `sign-verify=true` selects: every engine of this
/// build.
///
/// The list does not hold the dummy engine, because its signature is its key.
/// Any writer can make a dummy signature, so a dummy verification proves
/// nothing. If a configuration names `dummy` by hand, `dummy` resolves to no
/// verifier here. The pull then fails as for any other unknown name.
///
/// The `ostree` command has the dummy engine and accepts
/// `sign-verify=ed25519;dummy`.
pub(crate) const ALL_ENGINES: &[&str] = &[
    "ed25519",
    #[cfg(any(
        feature = "sign-spki-p256",
        feature = "sign-spki-p384",
        feature = "sign-spki-ed25519",
        feature = "sign-spki-rsa"
    ))]
    "spki",
];

/// The signature policy of one target. Each axis of the policy must find a
/// valid signature.
///
/// The policy holds each verifier in an [`Arc`], so the two targets of one pull
/// share the verifiers that both ask for. The default policy holds no axis.
#[derive(Clone, Default)]
pub(crate) struct Policy {
    /// The GPG axis, if it applies.
    gpg: Option<Arc<dyn Verifier>>,
    /// The sign-api axis, if it applies, with one verifier for each engine that
    /// the policy names. A valid signature from any one verifier satisfies it.
    sign: Option<Vec<Arc<dyn Verifier>>>,
}

impl Policy {
    /// Returns `true` if this policy holds at least one axis.
    pub(crate) fn applies(&self) -> bool {
        self.gpg.is_some() || self.sign.is_some()
    }

    /// Returns the verifiers of the sign-api axis, or `None` if the axis does
    /// not apply.
    pub(crate) fn sign_axis(&self) -> Option<&[Arc<dyn Verifier>]> {
        self.sign.as_deref()
    }

    /// Creates a policy from the given axes, each present if it applies.
    pub(crate) fn from_axes(
        gpg: Option<Arc<dyn Verifier>>,
        sign: Option<Vec<Arc<dyn Verifier>>>,
    ) -> Policy {
        Policy { gpg, sign }
    }

    /// Returns `true` if the GPG axis applies.
    pub(crate) fn gpg_axis(&self) -> bool {
        self.gpg.is_some()
    }

    /// Verifies the signatures over `payload` on every axis of this policy.
    ///
    /// `signatures` is the detached-metadata dict that holds the signatures. It
    /// is `None` if the payload carries no signatures. `subject` names the
    /// payload in an error message.
    pub(crate) async fn check(
        &self,
        subject: &str,
        payload: &[u8],
        signatures: Option<&Value>,
    ) -> Result<()> {
        self.check_on(subject, payload, signatures, false).await
    }

    /// Verifies as [`check`](Self::check) does, and runs the verifiers of the
    /// sign-api axis on the blocking pool.
    ///
    /// The ed25519 and spki verifiers do their work in the call. The pool
    /// gets a copy of `payload`, and the signature blobs that the check reads
    /// for each verifier. The GPG verifier moves its own work to the
    /// blocking pool, so the GPG axis runs in the calling task.
    pub(crate) async fn check_unblocked(
        &self,
        subject: &str,
        payload: &[u8],
        signatures: Option<&Value>,
    ) -> Result<()> {
        self.check_on(subject, payload, signatures, true).await
    }

    /// Verifies as [`check`](Self::check) does. If `unblock` is `true`, the
    /// verifiers of the sign-api axis run on the blocking pool.
    async fn check_on(
        &self,
        subject: &str,
        payload: &[u8],
        signatures: Option<&Value>,
        unblock: bool,
    ) -> Result<()> {
        if let Some(gpg) = &self.gpg {
            check_axis(
                subject,
                "GPG",
                std::slice::from_ref(gpg),
                payload,
                signatures,
                false,
            )
            .await?;
        }
        if let Some(engines) = &self.sign {
            check_axis(subject, "sign-api", engines, payload, signatures, unblock).await?;
        }
        Ok(())
    }
}

/// The result of the verification of a payload on one axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Found {
    /// One of the verifiers accepted a signature.
    Valid,
    /// The payload carries signatures that the axis reads, and no verifier
    /// accepted one.
    Untrusted,
    /// The payload carries no signature that a verifier of the axis reads.
    Nothing,
}

/// Verifies `payload` on one axis and reports what it found.
///
/// The result tells if any of `verifiers` reports a valid signature over the
/// payload, and if a signature was there to verify. The callers keep the last
/// two cases apart, as the `ostree` command does. For a commit or a summary,
/// [`Found::Nothing`] is a refusal. An unsigned static delta gives
/// [`Found::Nothing`], and the delta check accepts it.
pub(crate) async fn examine(
    verifiers: &[Arc<dyn Verifier>],
    payload: &[u8],
    signatures: Option<&Value>,
) -> Result<Found> {
    examine_on(verifiers, payload, signatures, false).await
}

/// Verifies `payload` on one axis as [`examine`] does. If `unblock` is
/// `true`, each verifier runs on the blocking pool, with a copy of `payload`
/// and the blobs that the search reads for the verifier.
async fn examine_on(
    verifiers: &[Arc<dyn Verifier>],
    payload: &[u8],
    signatures: Option<&Value>,
    unblock: bool,
) -> Result<Found> {
    let mut found = Found::Nothing;
    let mut copy: Option<Arc<[u8]>> = None;
    for verifier in verifiers {
        let blobs = match signatures {
            Some(dict) => signatures_for(dict, verifier.metadata_key()),
            None => Vec::new(),
        };
        if blobs.is_empty() {
            continue;
        }
        found = Found::Untrusted;
        let outcome = if unblock {
            let payload = Arc::clone(copy.get_or_insert_with(|| Arc::from(payload)));
            let verifier = Arc::clone(verifier);
            ostrya_rt::unblock(move || {
                futures_lite::future::block_on(verifier.verify(&payload, &blobs))
            })
            .await?
        } else {
            verifier.verify(payload, &blobs).await?
        };
        if outcome.valid {
            return Ok(Found::Valid);
        }
    }
    Ok(found)
}

/// Verifies `payload` on one axis, and refuses it if no key of the axis signed
/// it or if it carries no signature. If `unblock` is `true`, the verifiers
/// run on the blocking pool.
async fn check_axis(
    subject: &str,
    axis: &str,
    verifiers: &[Arc<dyn Verifier>],
    payload: &[u8],
    signatures: Option<&Value>,
    unblock: bool,
) -> Result<()> {
    match examine_on(verifiers, payload, signatures, unblock).await? {
        Found::Valid => Ok(()),
        Found::Untrusted => Err(Error::Signature(format!(
            "{subject}: no {axis} signature is from a trusted key"
        ))),
        Found::Nothing => Err(Error::Signature(format!(
            "{subject}: {axis} verification is enabled, but it carries no signature"
        ))),
    }
}

/// The origin of the trusted keys of a policy.
pub(crate) enum KeySource<'a> {
    /// The configuration section of a remote, as a pull reads it. `section` is
    /// `None` for a remote that the configuration does not describe.
    Remote {
        /// The name of the remote, which names its keyrings.
        name: &'a str,
        /// The configuration section of the remote.
        section: Option<&'a Remote<'a>>,
        /// If `true`, the `<remote>.trustedkeys.gpg` file of the repository
        /// adds to the GPG trusted set.
        #[cfg_attr(not(feature = "verify-gpg"), allow(dead_code))]
        repo_keyring: bool,
    },
    /// A trust group, `[ex-ostrya trust "NAME"]`. The accessors of a remote
    /// section read it.
    Trust {
        /// The name of the group, which a refusal names.
        name: &'a str,
        /// The group, read as a remote section.
        section: &'a Remote<'a>,
    },
}

impl KeySource<'_> {
    /// Returns the inline trusted key for one sign-api engine.
    fn verification_key(&self, engine: &str) -> Result<Option<String>> {
        match self {
            KeySource::Remote { section, .. } => match section {
                Some(section) => section.verification_key(engine),
                None => Ok(None),
            },
            KeySource::Trust { section, .. } => section.verification_key(engine),
        }
    }

    /// Returns the path of a file of trusted keys for one sign-api engine.
    fn verification_file(&self, engine: &str) -> Result<Option<String>> {
        match self {
            KeySource::Remote { section, .. } => match section {
                Some(section) => section.verification_file(engine),
                None => Ok(None),
            },
            KeySource::Trust { section, .. } => section.verification_file(engine),
        }
    }

    /// Returns `true` if the system key store and its revoked set add to the
    /// keys that this source names.
    fn system_store(&self) -> bool {
        match self {
            KeySource::Remote { .. } => true,
            KeySource::Trust { .. } => false,
        }
    }
}

/// The verifiers that one policy build makes, each from one read of its key
/// sources.
///
/// Both targets of a pull take their keys from the same remote. If the commit
/// policy and the summary policy ask for the same verifier, the build makes it
/// once and both policies hold it. A pull from a remote with a trust group
/// takes its commit keys from the group, so each target gets its own set.
#[derive(Default)]
pub(crate) struct Verifiers {
    /// The GPG verifier, built for the first target that asks for it.
    gpg: Option<Arc<dyn Verifier>>,
    /// One entry for each sign-api engine that a target asks for. An entry is
    /// `None` if no source holds a key for that engine.
    sign: Vec<(String, Option<Arc<dyn Verifier>>)>,
}

impl Verifiers {
    /// Returns the GPG verifier for `source`, from one read of its keyrings.
    async fn gpg(&mut self, repo: &Repo, source: &KeySource<'_>) -> Result<Arc<dyn Verifier>> {
        match &self.gpg {
            Some(verifier) => Ok(Arc::clone(verifier)),
            None => {
                let verifier = gpg_verifier(repo, source).await?;
                self.gpg = Some(Arc::clone(&verifier));
                Ok(verifier)
            }
        }
    }

    /// Returns the verifier for one sign-api engine, from one read of its key
    /// sources.
    ///
    /// `None` means that the engine has no key to verify with.
    async fn sign(
        &mut self,
        engine: &str,
        source: &KeySource<'_>,
    ) -> Result<Option<Arc<dyn Verifier>>> {
        if let Some((_, verifier)) = self.sign.iter().find(|(name, _)| name == engine) {
            return Ok(verifier.clone());
        }
        let verifier = sign_verifier(engine, source).await?;
        self.sign.push((engine.to_owned(), verifier.clone()));
        Ok(verifier)
    }
}

/// Builds the policy of one target from the two resolved switches.
///
/// Each verifier comes from `cache`, so the policy of the other target shares
/// it.
pub(crate) async fn build_policy(
    repo: &Repo,
    source: &KeySource<'_>,
    cache: &mut Verifiers,
    gpg: bool,
    sign: &SignVerify,
) -> Result<Policy> {
    let mut policy = Policy::default();
    if gpg {
        policy.gpg = Some(cache.gpg(repo, source).await?);
    }
    // If the configuration names an engine by hand, the engine must have a key.
    // The configuration asks for it, and an engine with no key refuses every
    // signature. `sign-verify=true` names every engine of this build. Under it,
    // the build skips an engine with no key, and refuses only a policy that
    // ends with no engine. The `ostree` command reports the two cases
    // separately too.
    let (names, required): (Vec<String>, bool) = match sign {
        SignVerify::Off => (Vec::new(), false),
        SignVerify::All => (
            ALL_ENGINES.iter().map(|name| (*name).to_owned()).collect(),
            false,
        ),
        SignVerify::Engines(names) => (each_engine_once(names), true),
    };
    if !names.is_empty() {
        let mut verifiers: Vec<Arc<dyn Verifier>> = Vec::with_capacity(names.len());
        for name in &names {
            match cache.sign(name, source).await? {
                Some(verifier) => verifiers.push(verifier),
                None if required => {
                    return Err(Error::Signature(format!(
                        "no trusted key for signature engine '{name}'"
                    )));
                }
                None => {}
            }
        }
        if verifiers.is_empty() {
            return Err(Error::Signature(
                "signature verification is enabled, but no engine of this build \
                 has a trusted key"
                    .into(),
            ));
        }
        policy.sign = Some(verifiers);
    }
    Ok(policy)
}

/// Returns the engine names of a `sign-verify` value, each name once, at the
/// place where the value first names it.
///
/// `ostrya remote add` writes `sign-verify=ed25519,ed25519` for an engine
/// given twice.
/// With one verifier for each name, the build verifies each signature against
/// the keys of that engine as many times as the value names it.
fn each_engine_once(names: &[String]) -> Vec<String> {
    let mut kept: Vec<String> = Vec::with_capacity(names.len());
    for name in names {
        if !kept.iter().any(|held| held == name) {
            kept.push(name.clone());
        }
    }
    kept
}

/// Builds the GPG verifier for a key source.
///
/// For a remote, the trusted set has three parts:
///
/// - the keyring of the repository for the remote, read through the repository
///   descriptor, if the source asks for it
/// - the system trusted set
/// - the keyrings that `gpgkeypath` names
///
/// For a trust group, the trusted set is the keyrings that its `gpgkeypath`
/// names, and nothing else.
#[cfg(feature = "verify-gpg")]
async fn gpg_verifier(repo: &Repo, source: &KeySource<'_>) -> Result<Arc<dyn Verifier>> {
    let verifier = match source {
        KeySource::Remote {
            name,
            section,
            repo_keyring,
        } => {
            let keyring = if *repo_keyring {
                read_repo_keyring(repo, name).await?
            } else {
                None
            };
            let keypath = match section {
                Some(section) => section.gpgkeypath()?,
                None => Vec::new(),
            };
            let remote = (*name).to_owned();
            ostrya_rt::unblock(move || {
                crate::gpg::GpgVerifier::for_remote_keyrings(keyring, &remote, &keypath)
            })
            .await?
        }
        KeySource::Trust { name, section } => {
            let keypath = section.gpgkeypath()?;
            let key = format!("[ex-ostrya trust \"{name}\"] gpgkeypath");
            ostrya_rt::unblock(move || crate::gpg::GpgVerifier::from_keypath(&key, &keypath))
                .await?
        }
    };
    Ok(Arc::new(verifier))
}

/// Returns [`Error::Unsupported`], because a build without the GPG engine
/// cannot verify a GPG axis.
///
/// The build refuses, so it never passes a commit that it did not verify.
#[cfg(not(feature = "verify-gpg"))]
async fn gpg_verifier(_repo: &Repo, source: &KeySource<'_>) -> Result<Arc<dyn Verifier>> {
    match source {
        KeySource::Remote { name, .. } => Err(Error::Unsupported(format!(
            "remote '{name}' asks for GPG verification, which this build has no \
             engine for; build with the verify-gpg feature or set gpg-verify=false"
        ))),
        KeySource::Trust { name, .. } => Err(Error::Unsupported(format!(
            "[ex-ostrya trust \"{name}\"] asks for GPG verification, which this \
             build has no engine for; build with the verify-gpg feature"
        ))),
    }
}

/// The engines that this build verifies with.
///
/// The build resolves a name to one of these engines before it reads a key
/// source.
enum Engine {
    Ed25519,
    #[cfg(any(
        feature = "sign-spki-p256",
        feature = "sign-spki-p384",
        feature = "sign-spki-ed25519",
        feature = "sign-spki-rsa"
    ))]
    Spki,
}

/// Builds the verifier for one sign-api engine from the keys that `source`
/// names.
///
/// For a remote, the keys of the system key store add to these keys.
///
/// `None` means that the engine has no key to verify with. The policy decides
/// the result. It refuses an engine that it names by hand. It skips an engine
/// that it reached through a value that names every engine.
async fn sign_verifier(engine: &str, source: &KeySource<'_>) -> Result<Option<Arc<dyn Verifier>>> {
    let kind = match engine {
        "ed25519" => Engine::Ed25519,
        #[cfg(any(
            feature = "sign-spki-p256",
            feature = "sign-spki-p384",
            feature = "sign-spki-ed25519",
            feature = "sign-spki-rsa"
        ))]
        "spki" => Engine::Spki,
        _ => {
            return Err(Error::Unsupported(format!(
                "signature engine '{engine}' is not one this build verifies with"
            )));
        }
    };
    let Some(keys) = sign_keys(engine, source).await? else {
        return Ok(None);
    };
    build_verifier(kind, keys)
}

/// Builds the verifier of one engine over the keys of its sources, or returns
/// `None` if the engine has no key left.
///
/// The engine applies the revoked set when it matches keys. Each engine uses
/// its own key equality. The set of keys that is left after this step decides.
///
/// If the store revokes the only key that the sources hold, the engine has no
/// key, and the function returns `None`. A verifier with no key refuses every
/// commit with an error about the signature of the commit. That error does not
/// name the cause, the revocation.
fn build_verifier(kind: Engine, keys: SignKeys) -> Result<Option<Arc<dyn Verifier>>> {
    Ok(match kind {
        Engine::Ed25519 => {
            let verifier = Ed25519Verifier::from_sign_keys(keys)?;
            (!verifier.is_empty()).then(|| Arc::new(verifier) as Arc<dyn Verifier>)
        }
        #[cfg(any(
            feature = "sign-spki-p256",
            feature = "sign-spki-p384",
            feature = "sign-spki-ed25519",
            feature = "sign-spki-rsa"
        ))]
        Engine::Spki => {
            let verifier = crate::spki::SpkiVerifier::from_sign_keys(keys)?;
            (!verifier.is_empty()).then(|| Arc::new(verifier) as Arc<dyn Verifier>)
        }
    })
}

/// Returns the trusted and revoked keys for one engine.
///
/// The keys come from the inline key and the key file of the source. For a
/// remote, the system key store adds its keys, and its revoked set applies to
/// all of them.
///
/// This function reads the configuration. The blocking pool reads the paths
/// that the configuration names, so a slow path holds a pool thread and cannot
/// hold an executor thread.
///
/// `None` means that no source holds a key for the engine.
async fn sign_keys(engine: &str, source: &KeySource<'_>) -> Result<Option<SignKeys>> {
    let inline = source.verification_key(engine)?;
    let path = source.verification_file(engine)?;
    let system = source.system_store();
    let engine = engine.to_owned();
    ostrya_rt::unblock(move || read_sign_keys(&engine, inline, path, system)).await
}

/// Runs the blocking half of [`sign_keys`].
///
/// The function decodes the inline key and reads the key file. If `system` is
/// `true`, it adds the keys of the system key store.
///
/// The inline key is base64. For the spki engine, the function removes each
/// white space character of the key before the decode, so the key can hold
/// the line breaks of a PEM body. White space is space, horizontal tab, LF,
/// form feed, and CR. For the other engines, the function removes the leading
/// and trailing white space alone. Then it decodes the key with
/// `base64::decode`.
fn read_sign_keys(
    engine: &str,
    inline: Option<String>,
    path: Option<String>,
    system: bool,
) -> Result<Option<SignKeys>> {
    let mut keys = SignKeys::default();
    if let Some(mut inline) = inline {
        if engine == "spki" {
            inline.retain(|c| !c.is_ascii_whitespace());
        }
        keys.trusted.push(base64::decode(inline.trim())?);
    }
    if let Some(path) = path {
        keys.trusted.extend(read_verification_file(engine, &path)?);
    }
    if system {
        let store = load_sign_keys(engine)?;
        keys.trusted.extend(store.trusted);
        keys.revoked.extend(store.revoked);
    }
    if keys.trusted.is_empty() {
        return Ok(None);
    }
    Ok(Some(keys))
}

/// Reads the `<remote>.trustedkeys.gpg` file of the repository, up to
/// [`MAX_KEYRING`](crate::gpg::MAX_KEYRING) bytes.
///
/// Returns `None` if the repository holds no such file. The name resolves
/// through the repository descriptor on the blocking pool. A keyring on a slow
/// file system holds a pool thread and cannot hold an executor thread.
#[cfg(feature = "verify-gpg")]
async fn read_repo_keyring(repo: &Repo, remote: &str) -> Result<Option<Vec<u8>>> {
    let repo_fd = repo.repo_fd().try_clone_to_owned()?;
    let name = format!("{remote}.trustedkeys.gpg");
    ostrya_rt::unblock(move || read_keyring_blocking(repo_fd.as_fd(), &name)).await
}

/// Runs the blocking half of [`read_repo_keyring`].
///
/// The name resolves against the repository descriptor. The bytes come through
/// [`read_keyring_fd`], which applies the same rule to every other keyring
/// source. If a symlink is at the name, the read follows it. The `ostree`
/// command was observed to follow it too.
#[cfg(feature = "verify-gpg")]
fn read_keyring_blocking(repo_fd: BorrowedFd<'_>, name: &str) -> Result<Option<Vec<u8>>> {
    // `NONBLOCK` makes a fifo answer the open at once. Without it, the open
    // waits for a writer. On a regular file, the flag has no effect on the
    // read that the reader makes.
    let fd = match rustix::fs::openat(
        repo_fd,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => {
            return Err(Error::Signature(format!(
                "the keyring '{name}' cannot be opened: {e}"
            )));
        }
    };
    read_keyring_fd(fd, name).map(Some)
}

/// Reads the keys of one `verification-<engine>-file`, up to [`MAX_KEY_FILE`]
/// bytes, under the rule that [`read_key_source`] states.
///
/// The function opens the path once and reads it through the ceiling, so the
/// keys come from the bytes that the ceiling admits. It refuses a file of
/// another kind, a file over the ceiling, and a file that it cannot read. Each
/// error names the file, so an operator can find the entry that names it.
///
/// A file of the spki engine holds PEM `PUBLIC KEY` blocks, which
/// `spki_public_keys` reads. An empty file adds no keys. A file of another
/// engine holds one base64 key on each line, and the function skips a line of
/// white space only.
fn read_verification_file(engine: &str, path: &str) -> Result<Vec<Vec<u8>>> {
    let subject = format!("the '{engine}' key file '{path}'");
    // `NONBLOCK` makes a fifo answer the open at once. Without it, the open
    // waits for a writer. On a regular file, the flag has no effect on the
    // later read.
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::Signature(format!("{subject} cannot be read: {e}")))?;
    let bytes = read_key_source(std::fs::File::from(fd), &subject, MAX_KEY_FILE)?;
    #[cfg(any(
        feature = "sign-spki-p256",
        feature = "sign-spki-p384",
        feature = "sign-spki-ed25519",
        feature = "sign-spki-rsa"
    ))]
    if engine == "spki" {
        return Ok(crate::spki::spki_public_keys(&bytes, &subject)?);
    }
    let mut keys = Vec::new();
    for line in key_text(bytes, &subject)?.lines() {
        let line = line.trim();
        if !line.is_empty() {
            keys.push(base64::decode(line)?);
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use rustix::fs::FileType;

    use super::*;

    /// A remote that the configuration does not describe.
    const NO_SECTION: KeySource<'static> = KeySource::Remote {
        name: "origin",
        section: None,
        repo_keyring: true,
    };

    /// The base64 of a 64-byte ed25519 secret key (seed, then public key).
    const SECRET_B64: &str =
        "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
    /// The matching 32-byte ed25519 public key.
    const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

    const PAYLOAD: &[u8] = b"the commit bytes";

    /// A P-256 secret key, base64 of the PKCS#8 DER.
    #[cfg(feature = "sign-spki-p256")]
    const SPKI_SECRET_A: &str = concat!(
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
        "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
        "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
    );
    /// A second P-256 secret key, base64 of the PKCS#8 DER.
    #[cfg(feature = "sign-spki-p256")]
    const SPKI_SECRET_B: &str = concat!(
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgU5tYPz/hTTxfsSTPOxD/H9U+",
        "IkBj5qWV4/H3D1NBfRChRANCAAQPyTr9rh2d6WiYOi3oxNiE3ppTP2g5JP2xX9D7rEKnzixp",
        "MqVuqA9XnzQr5GlCYd71m/D7BnYIqS4MytNawYrR",
    );

    /// The ed25519 signature of `secret` over [`PAYLOAD`], in its dict.
    fn ed25519_signed(secret: &str) -> Value {
        use crate::sign::{Ed25519Signer, Signer, append_signature};

        let signer = Ed25519Signer::from_base64(secret).unwrap();
        let blob = ostrya_rt::block_on(signer.sign(PAYLOAD)).unwrap();
        let mut dict = Value::Array(Vec::new());
        append_signature(&mut dict, signer.metadata_key(), blob).unwrap();
        dict
    }

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

    /// `TrustedKeys::new` refuses an empty set, and a set with one verifier
    /// verifies a signature from its key.
    #[test]
    fn explicit_keys_need_a_verifier() {
        let err = TrustedKeys::new(Vec::new()).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        let verifier =
            Ed25519Verifier::new([base64::decode(PUBLIC_B64).unwrap()], Vec::<Vec<u8>>::new())
                .unwrap();
        let keys = TrustedKeys::new(vec![Arc::new(verifier)]).unwrap();
        ostrya_rt::block_on(keys.policy.check(
            "commit",
            PAYLOAD,
            Some(&ed25519_signed(SECRET_B64)),
        ))
        .unwrap();
    }

    /// `TrustedKeys::new` refuses a dummy verifier, alone and next to a real
    /// engine.
    #[test]
    fn explicit_keys_refuse_the_dummy_engine() {
        let dummy = || -> Arc<dyn Verifier> { Arc::new(crate::sign::DummyVerifier::new([b"k"])) };
        let ed25519: Arc<dyn Verifier> = Arc::new(
            Ed25519Verifier::new([base64::decode(PUBLIC_B64).unwrap()], Vec::<Vec<u8>>::new())
                .unwrap(),
        );
        for sign in [vec![dummy()], vec![ed25519, dummy()]] {
            let err = TrustedKeys::new(sign).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidFormat(m) if m.contains("dummy verifier")),
                "{err}"
            );
        }
    }

    /// `sign-verify=true` names the engines of this build. It never names the
    /// dummy engine, because the dummy signature is its key.
    #[test]
    fn all_engines_excludes_the_dummy_engine() {
        assert!(ALL_ENGINES.contains(&"ed25519"));
        assert!(!ALL_ENGINES.contains(&"dummy"));
    }

    /// `sign_verifier` refuses by name an engine that no build verifies with.
    /// For an engine that no source holds a key for, it reports no key. The
    /// policy reads that report to refuse an engine that it names by hand.
    #[test]
    fn unknown_engines_and_empty_key_sets_are_told_apart() {
        ostrya_rt::block_on(async {
            let Err(err) = sign_verifier("nosuchengine", &NO_SECTION).await else {
                panic!("an engine this build has no verifier for is refused");
            };
            assert!(
                err.to_string().contains("not one this build verifies with"),
                "{err}"
            );
            // There is no remote section. On a host with no key store of its
            // own, the engine has no key at all.
            if load_sign_keys("ed25519").unwrap().trusted.is_empty() {
                assert!(
                    sign_verifier("ed25519", &NO_SECTION)
                        .await
                        .unwrap()
                        .is_none()
                );
            }
        });
    }

    /// `sign_verifier` refuses a configuration that names the dummy engine, by
    /// that name. The dummy signature is the bytes of the dummy key. A commit
    /// verified against it passes a verification that reads no key.
    #[test]
    fn the_dummy_engine_is_refused_by_name() {
        ostrya_rt::block_on(async {
            let Err(err) = sign_verifier("dummy", &NO_SECTION).await else {
                panic!("a configuration naming the dummy engine is refused");
            };
            assert!(
                err.to_string().contains("not one this build verifies with"),
                "{err}"
            );
        });
    }

    /// If the store revokes the only key of an engine, the engine has no key at
    /// all. The set of keys that is left after the revoked set applies decides.
    ///
    /// The policy then reports the engine. It refuses an engine that the
    /// configuration names by hand. It skips an engine that it reached through
    /// a value that names every engine. No commit goes to a verifier that
    /// trusts nothing.
    ///
    /// The test makes the decision at this level because the revoked set comes
    /// from the system key store. The store is under `/etc/ostree` and
    /// `/usr/share/ostree`, and a test cannot write there.
    #[test]
    fn a_revoked_key_leaves_the_engine_without_a_key() {
        const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";
        let key = base64::decode(PUBLIC_B64).unwrap();

        let held = SignKeys {
            trusted: vec![key.clone()],
            revoked: Vec::new(),
        };
        assert!(
            build_verifier(Engine::Ed25519, held).unwrap().is_some(),
            "a key no source revokes builds a verifier"
        );

        let revoked = SignKeys {
            trusted: vec![key.clone()],
            revoked: vec![key],
        };
        assert!(
            build_verifier(Engine::Ed25519, revoked).unwrap().is_none(),
            "the engine's only key is revoked, so the engine has no key"
        );
    }

    /// An engine that the value names twice builds one verifier, so each
    /// signature gets one verification against the keys of that engine.
    /// `ostrya remote add` writes such a value for an engine given twice.
    #[test]
    fn a_repeated_engine_name_builds_one_verifier() {
        use crate::{CreateOptions, RepoMode};

        const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";
        let config = crate::config::RepoConfig::parse(&format!(
            "[core]\nrepo_version=1\nmode=archive\n\
             [remote \"origin\"]\nurl=http://localhost/\n\
             sign-verify=ed25519,ed25519\nverification-ed25519-key={PUBLIC_B64}\n"
        ))
        .unwrap();
        let section = config.remote("origin");
        let sign = section.as_ref().unwrap().sign_verify().unwrap();
        assert_eq!(
            sign,
            SignVerify::Engines(vec!["ed25519".to_owned(), "ed25519".to_owned()]),
            "the configured value names the engine twice"
        );

        let dir = std::env::temp_dir().join(format!(
            "ostrya-verify-repeat-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let outcome = ostrya_rt::block_on(async {
            let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let mut cache = Verifiers::default();
            let source = KeySource::Remote {
                name: "origin",
                section: section.as_ref(),
                repo_keyring: true,
            };
            build_policy(&repo, &source, &mut cache, false, &sign).await
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let policy = outcome.expect("the configured key builds a policy");
        let verifiers = policy.sign.expect("the sign-api axis applies");
        assert_eq!(verifiers.len(), 1, "the repeated name holds one verifier");
    }

    /// The two targets of one pull share the verifier that both ask for. The
    /// cache reads the key sources of an engine once and hands out the same
    /// verifier again.
    #[test]
    fn an_engine_is_read_once_for_both_targets() {
        const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";
        let config = crate::config::RepoConfig::parse(&format!(
            "[core]\nrepo_version=1\nmode=archive\n\
             [remote \"origin\"]\nurl=http://localhost/\n\
             verification-ed25519-key={PUBLIC_B64}\n"
        ))
        .unwrap();
        let section = config.remote("origin");
        ostrya_rt::block_on(async {
            let source = KeySource::Remote {
                name: "origin",
                section: section.as_ref(),
                repo_keyring: true,
            };
            let mut cache = Verifiers::default();
            let first = cache.sign("ed25519", &source).await.unwrap();
            let second = cache.sign("ed25519", &source).await.unwrap();
            let (Some(first), Some(second)) = (first, second) else {
                panic!("the configured key builds a verifier");
            };
            assert!(Arc::ptr_eq(&first, &second));
            assert_eq!(cache.sign.len(), 1);
        });
    }

    /// A pull from a remote with a trust group builds the commit policy from
    /// the group and the summary policy from the remote, and the two share no
    /// verifier. The group trusts key A, and the remote trusts key B for the
    /// summary: the commit policy refuses B, and the summary policy refuses A.
    #[test]
    fn a_trust_group_and_the_remote_share_no_verifier() {
        use crate::{CreateOptions, RepoMode};

        const OTHER_SECRET_B64: &str = "5ILWxT+l9G/u3h0BptRpmSi35C9uog7YDdD+Fp1Xk+Hz52p0NlYh6xBA73kJEJKhKbbnjcE0rsWA5XA/K5Sq5Q==";
        const OTHER_PUBLIC_B64: &str = "8+dqdDZWIesQQO95CRCSoSm2543BNK7FgOVwPyuUquU=";
        let dir = std::env::temp_dir().join(format!(
            "ostrya-verify-trust-split-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let group_key = ed25519_signed(SECRET_B64);
        let remote_key = ed25519_signed(OTHER_SECRET_B64);
        let outcome = ostrya_rt::block_on(async {
            drop(
                Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                    .await
                    .unwrap(),
            );
            let config = root.join("config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str(&format!(
                "\n[remote \"origin\"]\nurl=http://localhost/\ngpg-verify=false\ntrust=t\n\
                 sign-verify-summary=ed25519\nverification-ed25519-key={OTHER_PUBLIC_B64}\n\
                 [ex-ostrya trust \"t\"]\nsign-verify=ed25519\n\
                 verification-ed25519-key={PUBLIC_B64}\n"
            ));
            std::fs::write(&config, text).unwrap();
            let repo = Repo::open(&root).await.unwrap();
            let trust = PullTrust::from_remote(&repo, "origin", &PullVerify::default())
                .await
                .unwrap();
            let (commit, summary) = trust.into_policies();
            (
                commit.check("commit", PAYLOAD, Some(&group_key)).await,
                commit.check("commit", PAYLOAD, Some(&remote_key)).await,
                summary.check("summary", PAYLOAD, Some(&remote_key)).await,
                summary.check("summary", PAYLOAD, Some(&group_key)).await,
            )
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let (commit_a, commit_b, summary_b, summary_a) = outcome;
        commit_a.expect("the commit policy trusts the key of the group");
        let err = commit_b.expect_err("the commit policy does not trust the remote key");
        assert!(err.to_string().contains("is from a trusted key"), "{err}");
        summary_b.expect("the summary policy trusts the key of the remote");
        let err = summary_a.expect_err("the summary policy does not trust the group key");
        assert!(err.to_string().contains("is from a trusted key"), "{err}");
    }

    /// `read_verification_file` refuses a key file over the ceiling by its own
    /// name, so the size of the file cannot decide an allocation.
    #[test]
    fn an_oversized_key_file_is_refused_by_name() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-verify-keyfile-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.ed25519");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_KEY_FILE + 1)
            .unwrap();
        let outcome = read_verification_file("ed25519", &path.display().to_string());
        std::fs::remove_dir_all(&dir).unwrap();
        let err = outcome.expect_err("a key file over the ceiling has to be refused");
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("keys.ed25519") && m.contains("ceiling")),
            "{err}"
        );
    }

    /// `gpg_verifier` refuses a repository keyring over the ceiling by its own
    /// name. A read of the part that the ceiling admits gives the pull a
    /// trusted set that the operator never put there. No message reports it.
    #[cfg(feature = "verify-gpg")]
    #[test]
    fn an_oversized_repository_keyring_is_refused_by_name() {
        use crate::gpg::MAX_KEYRING;
        use crate::{CreateOptions, RepoMode};

        let dir = std::env::temp_dir().join(format!(
            "ostrya-verify-keyring-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let outcome = ostrya_rt::block_on(async {
            let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            std::fs::File::create(root.join("origin.trustedkeys.gpg"))
                .unwrap()
                .set_len(MAX_KEYRING + 1)
                .unwrap();
            gpg_verifier(&repo, &NO_SECTION).await.map(|_| ())
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let err = outcome.expect_err("a keyring over the ceiling has to be refused");
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("origin.trustedkeys.gpg")
                && m.contains("ceiling")),
            "{err}"
        );
    }

    /// `gpg_verifier` refuses a fifo at the name of a repository keyring, by
    /// that name. A read of a fifo returns what its writers sent, so a pull
    /// that reads one takes its trusted set from them. The open uses
    /// `NONBLOCK`, so it does not wait for a writer. The read refuses the file
    /// kind before it reads a byte.
    #[cfg(feature = "verify-gpg")]
    #[test]
    fn a_fifo_repository_keyring_is_refused_by_name() {
        use crate::{CreateOptions, RepoMode};

        let dir = std::env::temp_dir().join(format!(
            "ostrya-verify-keyfifo-repo-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let outcome = ostrya_rt::block_on(async {
            let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            rustix::fs::mknodat(
                rustix::fs::CWD,
                root.join("origin.trustedkeys.gpg"),
                FileType::Fifo,
                Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap();
            gpg_verifier(&repo, &NO_SECTION).await.map(|_| ())
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let err = outcome.expect_err("a fifo at a keyring's name has to be refused");
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("origin.trustedkeys.gpg")
                && m.contains("regular file")),
            "{err}"
        );
    }

    /// `read_verification_file` refuses a fifo at the name of a key file, by
    /// that name. A blocking read of a fifo holds the thread until a writer
    /// opens it. The length that a fifo reports is not the length of its
    /// content. The open uses `NONBLOCK`, so it does not wait for a writer. The
    /// read refuses the file kind before it reads a byte.
    #[test]
    fn a_fifo_key_file_is_refused_by_name() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-verify-keyfifo-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.ed25519");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let outcome = read_verification_file("ed25519", &path.display().to_string());
        std::fs::remove_dir_all(&dir).unwrap();
        let err = outcome.expect_err("a fifo at a key file's name has to be refused");
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("keys.ed25519")
                && m.contains("regular file")),
            "{err}"
        );
    }

    /// A `verification-spki-file` holds PEM `PUBLIC KEY` blocks. A file of
    /// base64 lines is refused by its name. An empty file adds no keys, so the
    /// engine has no key.
    #[cfg(feature = "sign-spki-p256")]
    #[test]
    fn an_spki_key_file_holds_pem_blocks() {
        const SPKI_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8X83xylD3ibci0xjFKMR4bwUtTU/\
                                YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDnRAG1Ua8eR8SKbLQ==";
        let dir = std::env::temp_dir().join(format!(
            "ostrya-verify-spkifile-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, text: &str| {
            let path = dir.join(name);
            std::fs::write(&path, text).unwrap();
            path.display().to_string()
        };
        let pem = write(
            "pem",
            &format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n{}\n-----END PUBLIC KEY-----\n",
                &SPKI_B64[..64],
                &SPKI_B64[64..]
            ),
        );
        let lines = write("lines", &format!("{SPKI_B64}\n"));
        let empty = write("empty", "");
        let read = |path: &str| read_sign_keys("spki", None, Some(path.to_owned()), false);
        let by_pem = read(&pem);
        let by_lines = read(&lines);
        let by_empty = read(&empty);
        std::fs::remove_dir_all(&dir).unwrap();

        let keys = by_pem.unwrap().expect("the PEM file holds a key");
        assert_eq!(keys.trusted, [base64::decode(SPKI_B64).unwrap()]);
        let err = by_lines.expect_err("a file of base64 lines has to be refused");
        assert!(
            matches!(&err, Error::Signature(m) if m.ends_with(&format!(
                "the 'spki' key file '{lines}' holds no PEM PUBLIC KEY block"
            ))),
            "{err}"
        );
        assert!(by_empty.unwrap().is_none());
    }

    /// An inline `verification-spki-key` and a PEM `verification-spki-file`
    /// add their keys together. A signature of each key verifies.
    #[cfg(feature = "sign-spki-p256")]
    #[test]
    fn an_spki_inline_key_and_key_file_are_both_trusted() {
        use crate::sign::Signer;
        use crate::spki::SpkiSigner;

        let inline = SpkiSigner::from_base64(SPKI_SECRET_A).unwrap();
        let in_file = SpkiSigner::from_base64(SPKI_SECRET_B).unwrap();
        let b64 = base64::encode(&in_file.public_key_der());
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let dir = std::env::temp_dir().join(format!(
            "ostrya-verify-spkiboth-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pem");
        std::fs::write(
            &path,
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                lines.join("\n")
            ),
        )
        .unwrap();
        let read = read_sign_keys(
            "spki",
            Some(base64::encode(&inline.public_key_der())),
            Some(path.display().to_string()),
            false,
        );
        std::fs::remove_dir_all(&dir).unwrap();

        let keys = read.unwrap().expect("both sources hold a key");
        assert_eq!(
            keys.trusted,
            [inline.public_key_der(), in_file.public_key_der()]
        );
        let verifier = build_verifier(Engine::Spki, keys).unwrap().unwrap();
        for signer in [&inline, &in_file] {
            let signature = ostrya_rt::block_on(signer.sign(PAYLOAD)).unwrap();
            let outcome = ostrya_rt::block_on(verifier.verify(PAYLOAD, &[signature])).unwrap();
            assert!(outcome.valid);
        }
    }

    /// An inline `verification-spki-key` is the base64 of a
    /// SubjectPublicKeyInfo DER, and it can hold line breaks. A SEC1 point,
    /// the base64 of the PEM text, and a PKCS#8 secret key are refused when
    /// the verifier is built.
    #[cfg(feature = "sign-spki-p256")]
    #[test]
    fn an_spki_inline_key_is_a_subject_public_key_info() {
        use crate::spki::SpkiSigner;

        let der = SpkiSigner::from_base64(SPKI_SECRET_A)
            .unwrap()
            .public_key_der();
        let b64 = base64::encode(&der);
        let (head, tail) = b64.split_at(64);
        for inline in [
            b64.clone(),
            format!("{head}\n{tail}\n"),
            format!("{head}\r\n{tail}\r\n"),
            format!(" {head}\t{tail} "),
        ] {
            let keys = read_sign_keys("spki", Some(inline), None, false)
                .unwrap()
                .expect("the inline key is a key");
            assert_eq!(keys.trusted, std::slice::from_ref(&der));
            assert!(build_verifier(Engine::Spki, keys).unwrap().is_some());
        }

        let pem = format!("-----BEGIN PUBLIC KEY-----\n{head}\n{tail}\n-----END PUBLIC KEY-----\n");
        let point = der[der.len() - 65..].to_vec();
        let secret = base64::decode(SPKI_SECRET_A).unwrap();
        for bytes in [point, pem.into_bytes(), secret] {
            let keys = read_sign_keys("spki", Some(base64::encode(&bytes)), None, false)
                .unwrap()
                .expect("the inline key decodes");
            match build_verifier(Engine::Spki, keys) {
                Err(Error::Signature(m)) => {
                    assert_eq!(m, "spki public key: expected SubjectPublicKeyInfo DER");
                }
                Err(other) => panic!("not a signature error: {other}"),
                Ok(_) => panic!("the key has to be refused"),
            }
        }

        // An ed25519 inline key keeps its strict decode, with no white space
        // inside the key.
        let (a, b) = PUBLIC_B64.split_at(20);
        assert!(read_sign_keys("ed25519", Some(format!("{a}\n{b}")), None, false).is_err());
    }

    /// The trust source reads the `verification-*` keys of its group. The
    /// remote keys of the same name do not reach it. The trust source reads no
    /// system key store, and a remote source reads one.
    #[test]
    fn trust_source_reads_its_own_group() {
        let keyfile = ostrya_core::KeyFile::parse(
            "[remote \"t\"]\nverification-ed25519-key=REMOTE\n\
             [ex-ostrya trust \"t\"]\nverification-ed25519-key=INLINE\n\
             verification-ed25519-file=/keys.ed25519\n",
        )
        .unwrap();
        let section = Remote::view(&keyfile, "ex-ostrya trust \"t\"".to_owned());
        let source = KeySource::Trust {
            name: "t",
            section: &section,
        };
        assert_eq!(
            source.verification_key("ed25519").unwrap().as_deref(),
            Some("INLINE")
        );
        assert_eq!(
            source.verification_file("ed25519").unwrap().as_deref(),
            Some("/keys.ed25519")
        );
        assert_eq!(source.verification_key("spki").unwrap(), None);
        assert!(!source.system_store());
        assert!(NO_SECTION.system_store());
    }

    /// A remote source without the repository keyring does not open
    /// `<repo>/<remote>.trustedkeys.gpg`. A keyring there over the ceiling,
    /// which the pull refuses, does not reach the build.
    #[cfg(feature = "verify-gpg")]
    #[test]
    fn a_source_without_the_repository_keyring_does_not_read_it() {
        use crate::gpg::MAX_KEYRING;
        use crate::{CreateOptions, RepoMode};

        let dir = std::env::temp_dir().join(format!(
            "ostrya-verify-nokeyring-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let outcome = ostrya_rt::block_on(async {
            let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            std::fs::File::create(root.join("origin.trustedkeys.gpg"))
                .unwrap()
                .set_len(MAX_KEYRING + 1)
                .unwrap();
            let without = KeySource::Remote {
                name: "origin",
                section: None,
                repo_keyring: false,
            };
            (
                gpg_verifier(&repo, &without).await.map(|_| ()),
                gpg_verifier(&repo, &NO_SECTION).await.map(|_| ()),
            )
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let (without, with) = outcome;
        without.expect("the repository keyring is not read");
        let err = with.expect_err("the repository keyring is read, and refused");
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("origin.trustedkeys.gpg")),
            "{err}"
        );
    }
}
