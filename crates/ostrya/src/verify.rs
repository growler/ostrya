//! The commit signature policy the pull and the receive path share.
//!
//! A policy holds up to two axes, and each axis present has to find a valid
//! signature:
//!
//! - GPG. A pull turns it on with `gpg-verify` (default true) and
//!   `gpg-verify-summary` (default false). The trusted set is the remote's: the
//!   repository's `<remote>.trustedkeys.gpg`,
//!   `/etc/ostree/remotes.d/<remote>.trustedkeys.gpg`, the global trusted
//!   directory, and the keyrings `gpgkeypath` names.
//! - The sign api. A pull turns it on with `sign-verify` and
//!   `sign-verify-summary` (both default off). Each value is a boolean or a
//!   list of engine names; `true` selects every engine this build has. An
//!   engine's keys are its `verification-<engine>-key` and
//!   `verification-<engine>-file` entries plus the system key store, minus the
//!   store's revoked set.
//!
//! The axes are independent: a policy that asks for both gets both. Within the
//! sign-api axis one engine reporting a valid signature is enough, so
//! `sign-verify=ed25519;spki` accepts a commit signed by either. This is what
//! the tool was observed to do.
//!
//! [`KeySource`] names where the keys come from. A pull reads them from a
//! remote's configuration section. The receive path reads them from a remote
//! section in the same way, for a rule that takes the pull trust of a remote,
//! or from a trust group, `[ex-ostrya trust "NAME"]`, which takes the key names
//! of a remote section: `gpgkeypath` for the GPG axis, and
//! `verification-<engine>-key` and `verification-<engine>-file` for the sign
//! api. A trust group trusts these keys alone. It reads no system key store,
//! no revoked set, no per-remote keyring, and no global trusted directory, so
//! the keys a server holds commits to are the keys the group names.
//!
//! The pull's own rules, where the checks run and what a pull without a remote
//! may ask for, are in the `pull::verify` module.

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

/// The sign-api engines `sign-verify=true` selects: every engine this build
/// has. The dummy engine is not one of them -- its signature is its key, so
/// accepting it under a policy that names no engine would be a check in name
/// only. The same holds for a configuration that names it by hand: `dummy`
/// resolves to no verifier here and fails the pull as any other unknown name
/// does. The tool has that engine and takes `sign-verify=ed25519;dummy`.
pub(crate) const ALL_ENGINES: &[&str] = &[
    "ed25519",
    #[cfg(feature = "sign-spki")]
    "spki",
];

/// One target's checks. Each axis present here has to find a valid signature.
///
/// A verifier is held behind an [`Arc`], so the two targets of one pull share
/// the verifiers they both ask for.
#[derive(Default)]
pub(crate) struct Policy {
    /// The GPG axis, present when it applies.
    gpg: Option<Arc<dyn Verifier>>,
    /// The sign-api axis, present when it applies, holding one verifier per
    /// engine named. Any one of them reporting a valid signature satisfies it.
    sign: Option<Vec<Arc<dyn Verifier>>>,
}

impl Policy {
    /// Whether this policy checks anything.
    pub(crate) fn applies(&self) -> bool {
        self.gpg.is_some() || self.sign.is_some()
    }

    /// The verifiers of the sign-api axis, `None` where the axis does not
    /// apply.
    pub(crate) fn sign_axis(&self) -> Option<&[Arc<dyn Verifier>]> {
        self.sign.as_deref()
    }

    /// A policy over the axes given, each present where it applies.
    #[cfg(feature = "receive")]
    pub(crate) fn from_axes(
        gpg: Option<Arc<dyn Verifier>>,
        sign: Option<Vec<Arc<dyn Verifier>>>,
    ) -> Policy {
        Policy { gpg, sign }
    }

    /// Whether the GPG axis applies.
    #[cfg(feature = "receive")]
    pub(crate) fn gpg_axis(&self) -> bool {
        self.gpg.is_some()
    }

    /// Hold `payload` to every axis of this policy. `signatures` is the
    /// detached-metadata dict the signatures live in, absent when the payload
    /// carries none at all. `subject` names the payload in a message.
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

/// What holding a payload to one axis found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Found {
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

/// Where a policy's trusted keys come from.
pub(crate) enum KeySource<'a> {
    /// A remote's configuration section, as a pull reads it. `section` is
    /// `None` for a remote the configuration does not describe.
    Remote {
        /// The remote's name, which names its keyrings.
        name: &'a str,
        /// The remote's configuration section.
        section: Option<&'a Remote<'a>>,
        /// Whether the repository's own `<remote>.trustedkeys.gpg` adds to the
        /// GPG trusted set.
        #[cfg_attr(not(feature = "verify-gpg"), allow(dead_code))]
        repo_keyring: bool,
    },
    /// A trust group, `[ex-ostrya trust "NAME"]`, read through the accessors
    /// of a remote section.
    #[cfg(feature = "receive")]
    Trust {
        /// The group's name, which a refusal names.
        name: &'a str,
        /// The group, read as a remote section.
        section: &'a Remote<'a>,
    },
}

impl KeySource<'_> {
    /// The inline trusted key for one sign-api engine.
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

    /// The path to a file of trusted keys for one sign-api engine.
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

    /// Whether the system key store, and its revoked set, add to the keys
    /// this source names.
    fn system_store(&self) -> bool {
        match self {
            KeySource::Remote { .. } => true,
            #[cfg(feature = "receive")]
            KeySource::Trust { .. } => false,
        }
    }
}

/// The verifiers one policy build makes, each from one read of its key
/// sources.
///
/// Both targets of a pull take their keys from the same remote, so a verifier
/// the commit policy and the summary policy both ask for is built once and held
/// by both.
#[derive(Default)]
pub(crate) struct Verifiers {
    /// The GPG verifier, built for the first target that asks for it.
    gpg: Option<Arc<dyn Verifier>>,
    /// One entry per sign-api engine asked for, `None` where no source holds a
    /// key for that engine.
    sign: Vec<(String, Option<Arc<dyn Verifier>>)>,
}

impl Verifiers {
    /// The GPG verifier for `source`, from one read of its keyrings.
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

    /// The verifier for one sign-api engine, from one read of its key sources.
    /// `None` is an engine with no key to check with.
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

/// Build one target's policy from the two resolved switches, taking each
/// verifier from `cache` so the other target's policy shares it.
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

/// The GPG verifier for a key source.
///
/// For a remote: the repository's own keyring for it, read through the
/// repository descriptor where the source asks for it, plus the system trusted
/// set and whatever `gpgkeypath` names. For a trust group: the keyrings its
/// `gpgkeypath` names, and nothing else.
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

/// A build without the GPG engine cannot make the check a GPG axis asks for,
/// so it refuses rather than pass a commit it did not check.
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

/// The engines this build verifies with. A name is resolved to one of these
/// before any key source is read.
enum Engine {
    Ed25519,
    #[cfg(feature = "sign-spki")]
    Spki,
}

/// The verifier for one sign-api engine, over the keys `source` names and, for
/// a remote, the system key store.
///
/// `None` is an engine with no key to check with. What that means is the
/// policy's to say: a refusal for an engine the policy names by hand, and the
/// engine passed over for one the policy reached by naming every engine.
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

/// The trusted and revoked keys for one engine: the source's inline key and key
/// file, then, for a remote, the system key store, whose revoked set applies to
/// all of them.
///
/// The configuration is read here, and the paths it names are read on the
/// blocking pool, so a slow path holds a pool thread and not an executor thread.
///
/// `None` is an engine no source holds a key for.
async fn sign_keys(engine: &str, source: &KeySource<'_>) -> Result<Option<SignKeys>> {
    let inline = source.verification_key(engine)?;
    let path = source.verification_file(engine)?;
    let system = source.system_store();
    let engine = engine.to_owned();
    ostrya_rt::unblock(move || read_sign_keys(&engine, inline, path, system)).await
}

/// The blocking half of [`sign_keys`]: decode the inline key, read the key file,
/// and add the system key store where `system` asks for it.
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

/// Read the repository's `<remote>.trustedkeys.gpg`, up to
/// [`MAX_KEYRING`](crate::gpg::MAX_KEYRING), or `None` where the repository
/// holds none.
///
/// The name is resolved through the repository descriptor, on the blocking pool,
/// so a keyring on a slow filesystem holds a pool thread and not an executor
/// thread.
#[cfg(feature = "verify-gpg")]
async fn read_repo_keyring(repo: &Repo, remote: &str) -> Result<Option<Vec<u8>>> {
    let repo_fd = repo.repo_fd().try_clone_to_owned()?;
    let name = format!("{remote}.trustedkeys.gpg");
    ostrya_rt::unblock(move || read_keyring_blocking(repo_fd.as_fd(), &name)).await
}

/// The blocking half of [`read_repo_keyring`]. The name is resolved against the
/// repository descriptor and the bytes come through [`read_keyring_fd`], which
/// is the rule every other keyring source is read under. A symlink at the name
/// is followed, which the tool was observed to do.
#[cfg(feature = "verify-gpg")]
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
    Ok(key_text(
        read_key_source(std::fs::File::from(fd), &subject, MAX_KEY_FILE)?,
        &subject,
    )?)
}

#[cfg(test)]
mod tests {
    use rustix::fs::FileType;

    use super::*;

    /// A remote the configuration does not describe.
    const NO_SECTION: KeySource<'static> = KeySource::Remote {
        name: "origin",
        section: None,
        repo_keyring: true,
    };

    /// `sign-verify=true` names the engines this build has, and never the dummy
    /// engine, whose signature is its key.
    #[test]
    fn all_engines_excludes_the_dummy_engine() {
        assert!(ALL_ENGINES.contains(&"ed25519"));
        assert!(!ALL_ENGINES.contains(&"dummy"));
    }

    /// An engine no build verifies with is refused by name, and an engine no
    /// source holds a key for reports that it has none, which is what the
    /// policy reads to refuse an engine it named by hand.
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
            // No remote section, so a host with no key store of its own has no
            // key for the engine at all.
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

    /// A configuration naming the dummy engine is refused by that name. The
    /// dummy signature is the bytes of the dummy key, so a commit held to it
    /// would pass a check that read nothing.
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

    /// A fifo at a repository keyring's name is refused by that name. What a
    /// fifo answers a read with is what its writers sent, so a pull reading one
    /// would take its trusted set from them. This test returns only because the
    /// read refuses the kind before it reads.
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

    /// The trust source reads the `verification-*` keys of its group, and the
    /// remote keys of the same name do not reach it. It reads no system key
    /// store, where a remote does.
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

    /// A remote source that leaves the repository keyring out does not open
    /// `<repo>/<remote>.trustedkeys.gpg`: a keyring there over the ceiling,
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
