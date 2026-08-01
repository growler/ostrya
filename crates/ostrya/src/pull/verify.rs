//! The signature checks a pull makes (Phase 16e).
//!
//! Two independent policies, one for the commits a pull fetches and one for the
//! remote's summary, each built once per pull from the remote's configuration
//! and the pull's own overrides. A policy holds up to two axes:
//!
//! - GPG, which `gpg-verify` (default true) and `gpg-verify-summary` (default
//!   false) select. The trusted set is the remote's: the repository's
//!   `<remote>.trustedkeys.gpg`, `/etc/ostree/remotes.d/<remote>.trustedkeys.gpg`,
//!   the global trusted directory, and the keyrings `gpgkeypath` names.
//! - The sign api, which `sign-verify` and `sign-verify-summary` select (both
//!   default off). Each value is a boolean or a list of engine names; `true`
//!   selects every engine this build has. An engine's keys are its
//!   `verification-<engine>-key` and `verification-<engine>-file` entries plus
//!   the system key store, minus the store's revoked set.
//!
//! An axis that applies has to find a valid signature, and the axes are
//! independent: a remote that asks for both gets both. Within the sign-api axis
//! one engine reporting a valid signature is enough, so `sign-verify=ed25519;spki`
//! accepts a commit signed by either. This is what the tool was observed to do.
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

#[cfg(feature = "sign-gpg")]
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;

use ostrya_core::{Checksum, Value, base64};
use rustix::fs::{Mode, OFlags};
#[cfg(feature = "sign-gpg")]
use rustix::io::Errno;

use crate::config::{Remote, SignVerify};
use crate::error::{Error, Result};
#[cfg(feature = "sign-gpg")]
use crate::gpg::read_keyring_fd;
use crate::repo::Repo;
use crate::sign::{
    Ed25519Verifier, MAX_KEY_FILE, SignKeys, Verifier, key_text, load_sign_keys, read_key_source,
    signatures_for,
};

use super::PullVerify;

/// The sign-api engines `sign-verify=true` selects: every engine this build
/// has. The dummy engine is not one of them -- its signature is its key, so
/// accepting it under a policy that names no engine would be a check in name
/// only. The same holds for a configuration that names it by hand: `dummy`
/// resolves to no verifier here and fails the pull as any other unknown name
/// does. The tool has that engine and takes `sign-verify=ed25519;dummy`.
const ALL_ENGINES: &[&str] = &[
    "ed25519",
    #[cfg(feature = "sign-spki")]
    "spki",
];

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

/// One target's checks. Each axis present here has to find a valid signature.
///
/// A verifier is held behind an [`Arc`], so the two targets of one pull share
/// the verifiers they both ask for.
#[derive(Default)]
struct Policy {
    /// The GPG axis, present when it applies.
    gpg: Option<Arc<dyn Verifier>>,
    /// The sign-api axis, present when it applies, holding one verifier per
    /// engine named. Any one of them reporting a valid signature satisfies it.
    sign: Option<Vec<Arc<dyn Verifier>>>,
}

impl Policy {
    /// Whether this policy checks anything.
    fn applies(&self) -> bool {
        self.gpg.is_some() || self.sign.is_some()
    }

    /// Hold `payload` to every axis of this policy. `signatures` is the
    /// detached-metadata dict the signatures live in, absent when the payload
    /// carries none at all. `subject` names the payload in a message.
    async fn check(&self, subject: &str, payload: &[u8], signatures: Option<&Value>) -> Result<()> {
        if let Some(gpg) = &self.gpg {
            check_axis(
                subject,
                "GPG",
                std::slice::from_ref(gpg),
                payload,
                signatures,
            )
            .await?;
        }
        if let Some(engines) = &self.sign {
            check_axis(subject, "sign-api", engines, payload, signatures).await?;
        }
        Ok(())
    }
}

/// What holding a payload to one axis found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Found {
    /// One of the verifiers accepted a signature.
    Valid,
    /// Signatures the axis reads were there, and no verifier accepted one.
    Untrusted,
    /// The payload carries no signature any verifier of the axis reads.
    Nothing,
}

/// Hold `payload` to one axis: whether any of `verifiers` reports a valid
/// signature over it, and whether there was one to report on at all.
///
/// The callers tell the last two apart, as the tool tells them apart: a payload
/// carrying no signature the axis can read is a refusal for a commit or a
/// summary and is what an unsigned delta carries.
async fn examine(
    verifiers: &[Arc<dyn Verifier>],
    payload: &[u8],
    signatures: Option<&Value>,
) -> Result<Found> {
    let mut found = Found::Nothing;
    for verifier in verifiers {
        let blobs = match signatures {
            Some(dict) => signatures_for(dict, verifier.metadata_key()),
            None => Vec::new(),
        };
        if blobs.is_empty() {
            continue;
        }
        found = Found::Untrusted;
        if verifier.verify(payload, &blobs).await?.valid {
            return Ok(Found::Valid);
        }
    }
    Ok(found)
}

/// Hold `payload` to one axis, refusing both a payload no key of the axis
/// signed and one carrying no signature at all.
async fn check_axis(
    subject: &str,
    axis: &str,
    verifiers: &[Arc<dyn Verifier>],
    payload: &[u8],
    signatures: Option<&Value>,
) -> Result<()> {
    match examine(verifiers, payload, signatures).await? {
        Found::Valid => Ok(()),
        Found::Untrusted => Err(Error::Signature(format!(
            "{subject}: no {axis} signature is from a trusted key"
        ))),
        Found::Nothing => Err(Error::Signature(format!(
            "{subject}: {axis} verification is enabled, but it carries no signature"
        ))),
    }
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

        let mut cache = Verifiers::default();
        let commit = build_policy(
            repo,
            name,
            section.as_ref(),
            &mut cache,
            gpg_commit,
            &sign_commit,
        )
        .await?;
        let summary = build_policy(
            repo,
            name,
            section.as_ref(),
            &mut cache,
            gpg_summary,
            &sign_summary,
        )
        .await?;
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
        let Some(engines) = &self.commit.sign else {
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

/// The verifiers one pull builds, each from one read of its key sources.
///
/// Both targets of a pull take their keys from the same remote, so a verifier
/// the commit policy and the summary policy both ask for is built once and held
/// by both.
#[derive(Default)]
struct Verifiers {
    /// The GPG verifier, built for the first target that asks for it.
    gpg: Option<Arc<dyn Verifier>>,
    /// One entry per sign-api engine asked for, `None` where no source holds a
    /// key for that engine.
    sign: Vec<(String, Option<Arc<dyn Verifier>>)>,
}

impl Verifiers {
    /// The GPG verifier for `remote`, from one read of its keyrings.
    async fn gpg(
        &mut self,
        repo: &Repo,
        remote: &str,
        section: Option<&Remote<'_>>,
    ) -> Result<Arc<dyn Verifier>> {
        match &self.gpg {
            Some(verifier) => Ok(Arc::clone(verifier)),
            None => {
                let verifier = gpg_verifier(repo, remote, section).await?;
                self.gpg = Some(Arc::clone(&verifier));
                Ok(verifier)
            }
        }
    }

    /// The verifier for one sign-api engine, from one read of its key sources.
    /// `None` is an engine with no key to check with.
    async fn sign(
        &mut self,
        engine: &str,
        section: Option<&Remote<'_>>,
    ) -> Result<Option<Arc<dyn Verifier>>> {
        if let Some((_, verifier)) = self.sign.iter().find(|(name, _)| name == engine) {
            return Ok(verifier.clone());
        }
        let verifier = sign_verifier(engine, section).await?;
        self.sign.push((engine.to_owned(), verifier.clone()));
        Ok(verifier)
    }
}

/// Build one target's policy from the two resolved switches, taking each
/// verifier from `cache` so the other target's policy shares it.
async fn build_policy(
    repo: &Repo,
    remote: &str,
    section: Option<&Remote<'_>>,
    cache: &mut Verifiers,
    gpg: bool,
    sign: &SignVerify,
) -> Result<Policy> {
    let mut policy = Policy::default();
    if gpg {
        policy.gpg = Some(cache.gpg(repo, remote, section).await?);
    }
    // An engine the configuration names by hand has to have a key: it was asked
    // for, and no key would leave a check that refuses everything. Under
    // `sign-verify=true`, which names every engine this build has, an engine
    // with no key is passed over instead, and only a policy that ends up with no
    // engine at all is refused. The tool reports the same two cases separately.
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
            match cache.sign(name, section).await? {
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

/// The engine names of a `sign-verify` value, each kept where the value first
/// names it. `remote add` writes `sign-verify=ed25519,ed25519` for an engine
/// given twice, and one verifier per name would hold every signature to that
/// engine's keys as many times as the value names it.
fn each_engine_once(names: &[String]) -> Vec<String> {
    let mut kept: Vec<String> = Vec::with_capacity(names.len());
    for name in names {
        if !kept.iter().any(|held| held == name) {
            kept.push(name.clone());
        }
    }
    kept
}

/// The GPG verifier for a remote: the repository's own keyring for it, read
/// through the repository descriptor, plus the system trusted set and whatever
/// `gpgkeypath` names.
#[cfg(feature = "sign-gpg")]
async fn gpg_verifier(
    repo: &Repo,
    remote: &str,
    section: Option<&Remote<'_>>,
) -> Result<Arc<dyn Verifier>> {
    let keyring = read_repo_keyring(repo, remote).await?;
    let keypath = match section {
        Some(section) => section.gpgkeypath()?,
        None => Vec::new(),
    };
    let remote = remote.to_owned();
    let verifier = ostrya_rt::unblock(move || {
        crate::gpg::GpgVerifier::for_remote_keyrings(keyring, &remote, &keypath)
    })
    .await?;
    Ok(Arc::new(verifier))
}

/// A build without the GPG engine cannot make the check `gpg-verify` asks for,
/// so it refuses the pull rather than pass a commit it did not check.
#[cfg(not(feature = "sign-gpg"))]
async fn gpg_verifier(
    _repo: &Repo,
    remote: &str,
    _section: Option<&Remote<'_>>,
) -> Result<Arc<dyn Verifier>> {
    Err(Error::Unsupported(format!(
        "remote '{remote}' asks for GPG verification, which this build has no \
         engine for; build with the sign-gpg feature or set gpg-verify=false"
    )))
}

/// The engines this build verifies with. A name is resolved to one of these
/// before any key source is read.
enum Engine {
    Ed25519,
    #[cfg(feature = "sign-spki")]
    Spki,
}

/// The verifier for one sign-api engine, over the keys the remote names and the
/// system key store.
///
/// `None` is an engine with no key to check with. What that means is the
/// policy's to say: a refusal for an engine the policy names by hand, and the
/// engine passed over for one the policy reached by naming every engine.
async fn sign_verifier(
    engine: &str,
    section: Option<&Remote<'_>>,
) -> Result<Option<Arc<dyn Verifier>>> {
    let kind = match engine {
        "ed25519" => Engine::Ed25519,
        #[cfg(feature = "sign-spki")]
        "spki" => Engine::Spki,
        _ => {
            return Err(Error::Unsupported(format!(
                "signature engine '{engine}' is not one this build verifies with"
            )));
        }
    };
    let Some(keys) = sign_keys(engine, section).await? else {
        return Ok(None);
    };
    build_verifier(kind, keys)
}

/// Build one engine's verifier over the keys its sources hold, or `None` where
/// the engine is left with no key.
///
/// The engine applies the revoked set as it matches keys, each engine by its own
/// key equality, so the set left after that is what decides. A key the sources
/// hold and the store revokes leaves the engine with none, and a verifier
/// holding no key refuses every commit for the signature it carries, which sends
/// an operator to the signature rather than to the revocation.
fn build_verifier(kind: Engine, keys: SignKeys) -> Result<Option<Arc<dyn Verifier>>> {
    Ok(match kind {
        Engine::Ed25519 => {
            let verifier = Ed25519Verifier::from_sign_keys(keys)?;
            (!verifier.is_empty()).then(|| Arc::new(verifier) as Arc<dyn Verifier>)
        }
        #[cfg(feature = "sign-spki")]
        Engine::Spki => {
            let verifier = crate::spki::SpkiVerifier::from_sign_keys(keys)?;
            (!verifier.is_empty()).then(|| Arc::new(verifier) as Arc<dyn Verifier>)
        }
    })
}

/// The trusted and revoked keys for one engine: the remote's inline key and key
/// file, then the system key store, whose revoked set applies to all of them.
///
/// The configuration is read here, and the paths it names are read on the
/// blocking pool, so a slow path holds a pool thread and not an executor thread.
///
/// `None` is an engine no source holds a key for.
async fn sign_keys(engine: &str, section: Option<&Remote<'_>>) -> Result<Option<SignKeys>> {
    let (inline, path) = match section {
        Some(section) => (
            section.verification_key(engine)?,
            section.verification_file(engine)?,
        ),
        None => (None, None),
    };
    let engine = engine.to_owned();
    ostrya_rt::unblock(move || read_sign_keys(&engine, inline, path)).await
}

/// The blocking half of [`sign_keys`]: decode the inline key, read the key file,
/// and add the system key store.
fn read_sign_keys(
    engine: &str,
    inline: Option<String>,
    path: Option<String>,
) -> Result<Option<SignKeys>> {
    let mut keys = SignKeys::default();
    if let Some(inline) = inline {
        keys.trusted.push(base64::decode(inline.trim())?);
    }
    if let Some(path) = path {
        for line in read_verification_file(engine, &path)?.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            keys.trusted.push(base64::decode(line)?);
        }
    }
    let system = load_sign_keys(engine)?;
    keys.trusted.extend(system.trusted);
    keys.revoked.extend(system.revoked);
    if keys.trusted.is_empty() {
        return Ok(None);
    }
    Ok(Some(keys))
}

/// Read the repository's `<remote>.trustedkeys.gpg`, up to
/// [`MAX_KEYRING`](crate::gpg::MAX_KEYRING), or `None` where the repository
/// holds none.
///
/// The name is resolved through the repository descriptor, on the blocking pool,
/// so a keyring on a slow filesystem holds a pool thread and not an executor
/// thread.
#[cfg(feature = "sign-gpg")]
async fn read_repo_keyring(repo: &Repo, remote: &str) -> Result<Option<Vec<u8>>> {
    let repo_fd = repo.repo_fd().try_clone_to_owned()?;
    let name = format!("{remote}.trustedkeys.gpg");
    ostrya_rt::unblock(move || read_keyring_blocking(repo_fd.as_fd(), &name)).await
}

/// The blocking half of [`read_repo_keyring`]. The name is resolved against the
/// repository descriptor and the bytes come through [`read_keyring_fd`], which
/// is the rule every other keyring source is read under. A symlink at the name
/// is followed, which the tool was observed to do.
#[cfg(feature = "sign-gpg")]
fn read_keyring_blocking(repo_fd: BorrowedFd<'_>, name: &str) -> Result<Option<Vec<u8>>> {
    // `NONBLOCK` so a fifo answers the open rather than waiting for a writer.
    // On a regular file the flag has no effect on the read the reader makes.
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

/// Read one `verification-<engine>-file`, up to [`MAX_KEY_FILE`], under the rule
/// [`read_key_source`] states. The path is opened once and read through the
/// ceiling, so the bytes the ceiling admits are the bytes the keys come from. A
/// file of another kind, one over the ceiling, and one that cannot be read are
/// each refused by the file's name, so an operator can find the entry that named
/// it.
fn read_verification_file(engine: &str, path: &str) -> Result<String> {
    let subject = format!("the '{engine}' key file '{path}'");
    // `NONBLOCK` so a fifo answers the open rather than waiting for a writer.
    // On a regular file the flag has no effect on the read below.
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::Signature(format!("{subject} cannot be read: {e}")))?;
    key_text(read_key_source(fd, &subject, MAX_KEY_FILE)?, &subject)
}

#[cfg(test)]
mod tests {
    use rustix::fs::FileType;

    use super::*;

    /// `sign-verify=true` names the engines this build has, and never the dummy
    /// engine, whose signature is its key.
    #[test]
    fn all_engines_excludes_the_dummy_engine() {
        assert!(ALL_ENGINES.contains(&"ed25519"));
        assert!(!ALL_ENGINES.contains(&"dummy"));
    }

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

    /// An engine no build verifies with is refused by name, and an engine no
    /// source holds a key for reports that it has none, which is what the
    /// policy reads to refuse an engine it named by hand.
    #[test]
    fn unknown_engines_and_empty_key_sets_are_told_apart() {
        ostrya_rt::block_on(async {
            let Err(err) = sign_verifier("nosuchengine", None).await else {
                panic!("an engine this build has no verifier for is refused");
            };
            assert!(
                err.to_string().contains("not one this build verifies with"),
                "{err}"
            );
            // No remote section, so a host with no key store of its own has no
            // key for the engine at all.
            if load_sign_keys("ed25519").unwrap().trusted.is_empty() {
                assert!(sign_verifier("ed25519", None).await.unwrap().is_none());
            }
        });
    }

    /// A configuration naming the dummy engine is refused by that name. The
    /// dummy signature is the bytes of the dummy key, so a commit held to it
    /// would pass a check that read nothing.
    #[test]
    fn the_dummy_engine_is_refused_by_name() {
        ostrya_rt::block_on(async {
            let Err(err) = sign_verifier("dummy", None).await else {
                panic!("a configuration naming the dummy engine is refused");
            };
            assert!(
                err.to_string().contains("not one this build verifies with"),
                "{err}"
            );
        });
    }

    /// An engine whose only key the store revokes has no key at all: the set
    /// left after the revoked set is applied is what decides. The policy then
    /// reports the engine, by refusing an engine the configuration names by hand
    /// and by passing over one it reached by naming every engine, rather than
    /// hold every commit to a verifier that trusts nothing.
    ///
    /// The decision is made here because the revoked set comes from the system
    /// key store, under `/etc/ostree` and `/usr/share/ostree`, which a test
    /// cannot write to.
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

    /// An engine the value names twice, which `remote add` writes for an engine
    /// given twice, builds one verifier, so each signature is held to that
    /// engine's keys once.
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
            build_policy(&repo, "origin", section.as_ref(), &mut cache, false, &sign).await
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let policy = outcome.expect("the configured key builds a policy");
        let verifiers = policy.sign.expect("the sign-api axis applies");
        assert_eq!(verifiers.len(), 1, "the repeated name holds one verifier");
    }

    /// The two targets of one pull share the verifier they both ask for: an
    /// engine's key sources are read once and the same verifier is handed out
    /// again.
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
            let mut cache = Verifiers::default();
            let first = cache.sign("ed25519", section.as_ref()).await.unwrap();
            let second = cache.sign("ed25519", section.as_ref()).await.unwrap();
            let (Some(first), Some(second)) = (first, second) else {
                panic!("the configured key builds a verifier");
            };
            assert!(Arc::ptr_eq(&first, &second));
            assert_eq!(cache.sign.len(), 1);
        });
    }

    /// A key file over the ceiling is refused by its own name, so its size
    /// cannot decide an allocation.
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

    /// A repository keyring over the ceiling is refused by its own name. Reading
    /// the part the ceiling admits would hand the pull a trusted set the
    /// operator never placed there, with nothing said about it.
    #[cfg(feature = "sign-gpg")]
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
            gpg_verifier(&repo, "origin", None).await.map(|_| ())
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let err = outcome.expect_err("a keyring over the ceiling has to be refused");
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("origin.trustedkeys.gpg")
                && m.contains("ceiling")),
            "{err}"
        );
    }

    /// A fifo at a repository keyring's name is refused by that name. What a
    /// fifo answers a read with is what its writers sent, so a pull reading one
    /// would take its trusted set from them. This test returns only because the
    /// read refuses the kind before it reads.
    #[cfg(feature = "sign-gpg")]
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
            gpg_verifier(&repo, "origin", None).await.map(|_| ())
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let err = outcome.expect_err("a fifo at a keyring's name has to be refused");
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("origin.trustedkeys.gpg")
                && m.contains("regular file")),
            "{err}"
        );
    }

    /// A fifo at a key file's name is refused by that name. Reading it would
    /// hold the thread until a writer opens it, and the length it reports is
    /// not the length of what it carries. This test returns only because the
    /// read refuses the kind before it reads.
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
}
