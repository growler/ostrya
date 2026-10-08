//! The commit signature policy that the pull and the receive path share.
//!
//! A policy holds up to two axes: GPG and the sign api. Each axis that a
//! policy holds must find a valid signature. `PullVerify` states the keys of
//! each axis for a pull. `TrustedKeys` states the keys of a trust group.
//!
//! [`KeySource`] names the origin of the keys: the configuration section of a
//! remote, or a trust group of the receive path. `PullVerify` states the rules
//! of the pull: when the verification runs, and what a pull without a remote
//! can ask for.

#[cfg(feature = "verify-gpg")]
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;

use ostrya_core::{Value, base64};
use rustix::fs::{Mode, OFlags};
#[cfg(feature = "verify-gpg")]
use rustix::io::Errno;

use crate::config::{Remote, SignVerify};
use crate::error::{Error, Result};
#[cfg(feature = "verify-gpg")]
use crate::gpg::read_keyring_fd;
use crate::repo::Repo;
use crate::sign::{
    Ed25519Verifier, MAX_KEY_FILE, SignKeys, Verifier, key_text, load_sign_keys, read_key_source,
    signatures_for,
};

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
    #[cfg(feature = "sign-spki")]
    "spki",
];

/// The signature policy of one target. Each axis of the policy must find a
/// valid signature.
///
/// The policy holds each verifier in an [`Arc`], so the two targets of one pull
/// share the verifiers that both ask for.
#[derive(Default)]
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
    #[cfg(feature = "receive")]
    pub(crate) fn from_axes(
        gpg: Option<Arc<dyn Verifier>>,
        sign: Option<Vec<Arc<dyn Verifier>>>,
    ) -> Policy {
        Policy { gpg, sign }
    }

    /// Returns `true` if the GPG axis applies.
    #[cfg(feature = "receive")]
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

/// Verifies `payload` on one axis, and refuses it if no key of the axis signed
/// it or if it carries no signature.
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
    #[cfg(feature = "receive")]
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
            #[cfg(feature = "receive")]
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
            #[cfg(feature = "receive")]
            KeySource::Trust { section, .. } => section.verification_file(engine),
        }
    }

    /// Returns `true` if the system key store and its revoked set add to the
    /// keys that this source names.
    fn system_store(&self) -> bool {
        match self {
            KeySource::Remote { .. } => true,
            #[cfg(feature = "receive")]
            KeySource::Trust { .. } => false,
        }
    }
}

/// The verifiers that one policy build makes, each from one read of its key
/// sources.
///
/// Both targets of a pull take their keys from the same remote. If the commit
/// policy and the summary policy ask for the same verifier, the build makes it
/// once and both policies hold it.
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
        #[cfg(feature = "receive")]
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
        #[cfg(feature = "receive")]
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
    #[cfg(feature = "sign-spki")]
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
        #[cfg(feature = "sign-spki")]
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
        #[cfg(feature = "sign-spki")]
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
fn read_sign_keys(
    engine: &str,
    inline: Option<String>,
    path: Option<String>,
    system: bool,
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

/// Reads one `verification-<engine>-file`, up to [`MAX_KEY_FILE`] bytes, under
/// the rule that [`read_key_source`] states.
///
/// The function opens the path once and reads it through the ceiling, so the
/// keys come from the bytes that the ceiling admits. It refuses a file of
/// another kind, a file over the ceiling, and a file that it cannot read. Each
/// error names the file, so an operator can find the entry that names it.
fn read_verification_file(engine: &str, path: &str) -> Result<String> {
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
    Ok(key_text(
        read_key_source(std::fs::File::from(fd), &subject, MAX_KEY_FILE)?,
        &subject,
    )?)
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

    /// The trust source reads the `verification-*` keys of its group. The
    /// remote keys of the same name do not reach it. The trust source reads no
    /// system key store, and a remote source reads one.
    #[cfg(feature = "receive")]
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
