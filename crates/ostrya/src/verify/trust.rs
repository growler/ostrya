//! The trust groups, `[ex-ostrya trust "NAME"]`: the check of a group, the
//! build of its policy, and the trust of a pull that names a group.
//!
//! `check_trust` checks the keys and the values of a group. It reads no file
//! and runs no program. `trust_group_policy` builds the policy of a group that
//! passed the check. `pull_trust` resolves the trust of a pull that names a
//! group: in the key `trust` of the section of its remote, or in
//! `PullOptions::trust_group`.

use ostrya_core::KeyFile;

use crate::config::{Remote, SignVerify};
use crate::error::{Error, Result};
use crate::pull::PullVerify;
use crate::repo::Repo;

use super::{
    KeySource, Policy, PullTrust, TrustedKeys, Verifiers, build_policy, no_remote, summary_switches,
};

/// The sign-api engines that a trust group can name.
const TRUST_ENGINES: &[&str] = &["ed25519", "spki"];

/// Builds the policy of the trust group `name` from the key-file group
/// `group`.
///
/// The policy holds the GPG axis of the group if `gpg_on` is `true`, and the
/// sign-api axis of the group if `sign_on` is `true`. The build reads no key
/// source of an axis that is off. Each call makes its own verifiers, so a
/// policy of a group shares no verifier with a policy of a remote.
///
/// The caller checks the group with [`check_trust`] first. As a result, the
/// group turns on at least one axis, and an axis reads each key that the group
/// holds.
pub(crate) async fn trust_group_policy(
    repo: &Repo,
    keyfile: &KeyFile,
    name: &str,
    group: &str,
    gpg_on: bool,
    sign_on: bool,
) -> Result<Policy> {
    let section = Remote::view(keyfile, group.to_owned());
    let gpg = gpg_on && keyfile.get_bool(group, "gpg-verify")?.unwrap_or(false);
    let sign = if sign_on {
        section.sign_verify()?
    } else {
        SignVerify::Off
    };
    let source = KeySource::Trust {
        name,
        section: &section,
    };
    build_policy(repo, &source, &mut Verifiers::default(), gpg, &sign).await
}

/// The source of the name of the trust group of a pull.
#[derive(Debug, Clone, Copy)]
pub(crate) enum GroupName<'a> {
    /// The value of the key `trust` of the section of `remote`.
    Key {
        /// The name of the remote.
        remote: &'a str,
        /// The value of the key.
        value: &'a str,
    },
    /// The value of [`PullOptions::trust_group`](crate::PullOptions::trust_group).
    Field(&'a str),
}

impl GroupName<'_> {
    /// Returns the name of the trust group.
    fn value(&self) -> &str {
        match self {
            GroupName::Key { value, .. } | GroupName::Field(value) => value,
        }
    }
}

/// The trust group that [`PullOptions::trust_group`](crate::PullOptions::trust_group)
/// names, with the commit policy of the group after a call of [`pull_trust`] built it.
///
/// The commit policy of a group depends on the group and on the commit fields of
/// `PullVerify` alone. A pull gives one value to the trust of each of its remotes, so
/// it reads the key sources of the group one time.
pub(crate) struct FieldGroup<'a> {
    /// The name of the trust group.
    pub(super) name: &'a str,
    /// The commit policy of the group, or `None` before a call built it.
    pub(super) commit: Option<Policy>,
}

impl<'a> FieldGroup<'a> {
    /// Creates the trust group `name`, with no commit policy built.
    pub(crate) fn new(name: &'a str) -> FieldGroup<'a> {
        FieldGroup { name, commit: None }
    }
}

/// Resolves the trust of a pull whose trust group `name` names.
///
/// `remote` is the remote of the pull, if the pull names one, and `section`
/// is its section, if the config has one. The trust group sets the commit
/// policy, and the summary keys of the section set the summary policy. A
/// field `Some(false)` of `verify` turns off its commit axis of the group.
/// The summary fields of `verify` override the summary keys of the section.
/// A pull that names no remote checks no summary.
///
/// The checks come in this order, and each one comes before the call reads a
/// key source:
///
/// 1. the name is a valid group name, and the group exists;
/// 2. [`check_trust`] accepts the group;
/// 3. `verify` does not turn on a commit check;
/// 4. a pull that names no remote does not turn on a summary check;
/// 5. the section turns on no commit check, and holds no key source that no
///    summary check reads;
/// 6. the summary keys of the section that `verify` does not override
///    parse.
///
/// The first check refuses a name of the key `trust` with
/// [`Error::InvalidFormat`], and a name of
/// [`PullOptions::trust_group`](crate::PullOptions::trust_group) with
/// [`Error::InvalidInput`]. The words of each refusal name the source of the
/// name.
///
/// `commit` holds the commit policy of the group if an earlier call with the
/// same group and the same `verify` built it. In that case the call reads no
/// key source of the group. Otherwise the call builds the policy after the
/// checks and keeps it in `commit`.
pub(crate) async fn pull_trust(
    repo: &Repo,
    remote: Option<&str>,
    section: Option<&Remote<'_>>,
    name: GroupName<'_>,
    verify: &PullVerify,
    commit: &mut Option<Policy>,
) -> Result<PullTrust> {
    let value = name.value();
    let group = format!("ex-ostrya trust \"{value}\"");
    if !valid_group_name(value) {
        return Err(match name {
            GroupName::Key { remote, .. } => Error::InvalidFormat(format!(
                "malformed [remote \"{remote}\"] trust value '{value}': the value names a \
                 trust group, is not empty, and holds no '\"' and no control character"
            )),
            GroupName::Field(_) => Error::InvalidInput(format!(
                "malformed trust group name '{value}': the name is not empty, and holds \
                 no '\"' and no control character"
            )),
        });
    }
    let keyfile = repo.config().keyfile();
    if !keyfile.has_group(&group) {
        return Err(match name {
            GroupName::Key { remote, .. } => Error::InvalidFormat(format!(
                "[remote \"{remote}\"] trust={value} names no [{group}] group"
            )),
            GroupName::Field(_) => Error::InvalidInput(format!(
                "the pull names the trust group '{value}', and the config has no \
                 [{group}] group"
            )),
        });
    }
    check_trust(keyfile, &group)?;
    for (field, check) in [
        (verify.gpg, "the GPG check"),
        (verify.sign, "the sign-api check"),
    ] {
        if field == Some(true) {
            return Err(Error::InvalidInput(match name {
                GroupName::Key { remote, .. } => format!(
                    "remote '{remote}' takes its commit keys from [{group}], so a pull \
                     cannot turn on {check} of the commits"
                ),
                GroupName::Field(_) => format!(
                    "the pull takes its commit keys from [{group}], so it cannot turn on \
                     {check} of the commits"
                ),
            }));
        }
    }
    // With no remote, no section supplies the keys of a summary check.
    if remote.is_none() && (verify.gpg_summary == Some(true) || verify.sign_summary == Some(true)) {
        return Err(no_remote());
    }
    if let (Some(remote), Some(section)) = (remote, section)
        && let Some(void) = void_commit_key(section)?
    {
        let VoidKey { holds, key, reason } = void;
        return Err(Error::InvalidFormat(match name {
            GroupName::Key { .. } => {
                let verb = if holds { "holds " } else { "" };
                format!("[remote \"{remote}\"] sets trust={value} and {verb}{key}{reason}")
            }
            GroupName::Field(_) => {
                let verb = if holds { "holds" } else { "sets" };
                format!(
                    "the pull takes its commit keys from [{group}], and [remote \"{remote}\"] \
                     {verb} {key}{reason}"
                )
            }
        }));
    }
    let (gpg_summary, sign_summary) = summary_switches(section, verify)?;

    let commit = match commit.as_ref() {
        Some(policy) => policy.clone(),
        None => commit
            .insert(
                trust_group_policy(
                    repo,
                    keyfile,
                    value,
                    &group,
                    verify.gpg != Some(false),
                    verify.sign != Some(false),
                )
                .await?,
            )
            .clone(),
    };
    let summary = match remote {
        Some(remote) => {
            let source = KeySource::Remote {
                name: remote,
                section,
                repo_keyring: true,
            };
            build_policy(
                repo,
                &source,
                &mut Verifiers::default(),
                gpg_summary,
                &sign_summary,
            )
            .await?
        }
        None => Policy::default(),
    };
    Ok(PullTrust {
        commit: commit.applies().then(|| TrustedKeys::from_policy(commit)),
        summary: summary.applies().then(|| TrustedKeys::from_policy(summary)),
    })
}

/// Returns `true` if `name` is a valid name of a trust group: it is not
/// empty, and holds no `"` and no control character.
fn valid_group_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('"') && !name.contains(char::is_control)
}

/// A key of a remote section that a trust group makes void.
struct VoidKey {
    /// `true` if the section holds the key, and `false` if the section
    /// sets the key to the value that `key` names.
    holds: bool,
    /// The key, as the refusal names it.
    key: String,
    /// The reason of the refusal, with its leading punctuation.
    reason: String,
}

/// Returns the first key of the remote section `section` that a trust group
/// makes void: a key that turns on a commit check, or a key source that no
/// summary check reads. `None` if the section holds no such key.
///
/// The rule reads the summary keys of the section, and no override of a pull.
fn void_commit_key(section: &Remote<'_>) -> Result<Option<VoidKey>> {
    let sets = |key: String, reason: &str| {
        Some(VoidKey {
            holds: false,
            key,
            reason: reason.to_owned(),
        })
    };
    if section.gpg_verify_key()? == Some(true) {
        return Ok(sets(
            "gpg-verify=true".to_owned(),
            ": the trust group sets the commit checks, so set gpg-verify=false or \
             remove the key",
        ));
    }
    if section.sign_verify()? != SignVerify::Off {
        let raw = section.get("sign-verify").unwrap_or_default();
        return Ok(sets(
            format!("sign-verify={raw}"),
            ": the trust group sets the commit checks, so remove sign-verify",
        ));
    }
    if section.get("gpgkeypath").is_some() && !section.gpg_verify_summary()? {
        return Ok(sets(
            "gpgkeypath".to_owned(),
            ", and gpg-verify-summary is not true, so no check reads it",
        ));
    }
    let summary = section.sign_verify_summary()?;
    let engines: Vec<&str> = match &summary {
        SignVerify::Off => Vec::new(),
        SignVerify::All => TRUST_ENGINES.to_vec(),
        SignVerify::Engines(names) => names.iter().map(String::as_str).collect(),
    };
    for key in section.keys() {
        if let Some(engine) = verification_engine(key)
            && !engines.contains(&engine)
        {
            return Ok(Some(VoidKey {
                holds: true,
                key: format!("'{key}'"),
                reason: format!(
                    ", and sign-verify-summary does not select {engine}, so no check \
                     reads it"
                ),
            }));
        }
    }
    Ok(None)
}

/// Checks the trust group `group`.
///
/// Each key must be one that an axis reads. The group must turn on at least
/// one axis.
pub(crate) fn check_trust(keyfile: &KeyFile, group: &str) -> Result<()> {
    let mut engine_keys: Vec<(&str, &str)> = Vec::new();
    for key in keyfile.keys(group) {
        match key {
            "gpg-verify" | "gpgkeypath" | "sign-verify" => {}
            "gpg-verify-summary" | "sign-verify-summary" => {
                return Err(Error::InvalidFormat(format!(
                    "[{group}] holds '{key}', and a trust group sets a commit policy alone"
                )));
            }
            _ => match verification_engine(key) {
                Some(engine) if TRUST_ENGINES.contains(&engine) => {
                    engine_keys.push((key, engine));
                }
                Some(engine) => {
                    return Err(Error::InvalidFormat(format!(
                        "[{group}] holds '{key}', and '{engine}' is not ed25519 or spki"
                    )));
                }
                None => return Err(unknown_key(group, key)),
            },
        }
    }

    let gpg = keyfile.get_bool(group, "gpg-verify")?.unwrap_or(false);
    let sign = Remote::view(keyfile, group.to_owned()).sign_verify()?;
    let engines: Vec<&str> = match &sign {
        SignVerify::Off => Vec::new(),
        SignVerify::All => TRUST_ENGINES.to_vec(),
        SignVerify::Engines(names) => names.iter().map(String::as_str).collect(),
    };
    for engine in &engines {
        if !TRUST_ENGINES.contains(engine) {
            return Err(Error::InvalidFormat(format!(
                "[{group}] sign-verify names '{engine}', which is not ed25519 or spki"
            )));
        }
    }
    if !gpg && engines.is_empty() {
        return Err(Error::InvalidFormat(format!(
            "[{group}] turns on no signature check: set gpg-verify=true or sign-verify"
        )));
    }

    let keypath = keyfile.get_value(group, "gpgkeypath").is_some();
    if keypath && !gpg {
        return Err(Error::InvalidFormat(format!(
            "[{group}] sets gpgkeypath, and gpg-verify is not true, so no check reads it"
        )));
    }
    // `sign-verify=true` names every engine of the build, so it names spki
    // only in a build that has it.
    let names_spki = matches!(&sign, SignVerify::Engines(names) if names.iter().any(|n| n == "spki"))
        || engine_keys.iter().any(|(_, engine)| *engine == "spki");
    if cfg!(not(feature = "sign-spki")) && names_spki {
        return Err(Error::Unsupported(format!(
            "[{group}] names the spki engine, which this build has no engine for; \
             build with the sign-spki feature"
        )));
    }
    for (key, engine) in engine_keys {
        if !engines.contains(&engine) {
            return Err(Error::InvalidFormat(format!(
                "[{group}] holds '{key}', and sign-verify does not select {engine}, so \
                 no check reads it"
            )));
        }
    }
    if gpg {
        if cfg!(not(feature = "verify-gpg")) {
            return Err(Error::Unsupported(format!(
                "[{group}] asks for GPG verification, which this build has no engine \
                 for; build with the verify-gpg feature"
            )));
        }
        if Remote::view(keyfile, group.to_owned())
            .gpgkeypath()?
            .is_empty()
        {
            return Err(Error::InvalidFormat(format!(
                "[{group}] sets gpg-verify=true, and gpgkeypath names no keyring"
            )));
        }
    }
    Ok(())
}

/// Returns the engine that a `verification-ENGINE-key` or
/// `verification-ENGINE-file` key names, or `None` for another key.
fn verification_engine(key: &str) -> Option<&str> {
    let rest = key.strip_prefix("verification-")?;
    rest.strip_suffix("-key")
        .or_else(|| rest.strip_suffix("-file"))
}

/// Returns the error for a key that `group` does not take.
pub(crate) fn unknown_key(group: &str, key: &str) -> Error {
    Error::InvalidFormat(format!("[{group}] holds the unknown key '{key}'"))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread::ThreadId;

    use ostrya_core::Value;

    use super::*;
    use crate::sign::{Ed25519Signer, Signer, append_signature};
    use crate::{CreateOptions, RepoMode};

    /// The base64 of a 64-byte ed25519 secret key (seed, then public key).
    const SECRET_B64: &str =
        "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
    /// The matching 32-byte ed25519 public key.
    const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";
    /// Another ed25519 secret key.
    const OTHER_SECRET_B64: &str =
        "5ILWxT+l9G/u3h0BptRpmSi35C9uog7YDdD+Fp1Xk+Hz52p0NlYh6xBA73kJEJKhKbbnjcE0rsWA5XA/K5Sq5Q==";

    pub(crate) const PAYLOAD: &[u8] = b"the commit bytes";

    /// A scratch directory with an archive repository at `repo`. The guard
    /// removes the directory when it drops.
    struct Scratch {
        dir: std::path::PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "ostrya-trust-{label}-{}-{}",
                std::process::id(),
                crate::write::unique()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch { dir }
        }

        fn repo(&self) -> Repo {
            ostrya_rt::block_on(Repo::create(
                &self.dir.join("repo"),
                CreateOptions::new(RepoMode::Archive),
            ))
            .unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A detached-metadata dict that holds `blob` under `key`.
    pub(crate) fn dict_with(key: &str, blob: Vec<u8>) -> Value {
        let mut dict = Value::Array(Vec::new());
        append_signature(&mut dict, key, blob).unwrap();
        dict
    }

    /// The address of the data and a copy of the data of one call to
    /// `verify`.
    pub(crate) type SeenPayload = (usize, Vec<u8>);

    /// A verifier that accepts each blob and records the thread and the data
    /// of each call.
    ///
    /// A clone shares the record, so a test keeps a handle on the record after
    /// it gives the verifier away.
    #[derive(Clone)]
    pub(crate) struct ThreadRecorder {
        /// The detached-metadata key that the verifier reads.
        key: &'static str,
        /// The thread of each call to `verify`, in order.
        threads: Arc<Mutex<Vec<ThreadId>>>,
        /// The address of the data and a copy of the data of each call to
        /// `verify`, in order.
        payloads: Arc<Mutex<Vec<SeenPayload>>>,
    }

    impl ThreadRecorder {
        /// Creates a recorder that reads the blobs under `key`.
        pub(crate) fn new(key: &'static str) -> ThreadRecorder {
            ThreadRecorder {
                key,
                threads: Arc::default(),
                payloads: Arc::default(),
            }
        }

        /// Returns the thread of each call to `verify`, in order.
        pub(crate) fn threads(&self) -> Vec<ThreadId> {
            self.threads.lock().unwrap().clone()
        }

        /// Returns the address of the data and a copy of the data of each
        /// call to `verify`, in order.
        pub(crate) fn payloads(&self) -> Vec<SeenPayload> {
            self.payloads.lock().unwrap().clone()
        }

        /// Asserts that one call to `verify` ran, on a thread other than the
        /// thread of the test.
        pub(crate) fn assert_one_foreign_call(&self) {
            let threads = self.threads();
            assert_eq!(threads.len(), 1, "{threads:?}");
            assert_ne!(threads[0], std::thread::current().id());
        }

        /// Asserts that each call to `verify` got `data` at its address, with
        /// no copy.
        pub(crate) fn assert_no_copy_of(&self, data: &[u8]) {
            let payloads = self.payloads();
            assert!(!payloads.is_empty());
            for (address, bytes) in payloads {
                assert_eq!(address, data.as_ptr() as usize);
                assert_eq!(bytes, data);
            }
        }
    }

    impl crate::sign::Verifier for ThreadRecorder {
        fn metadata_key(&self) -> &str {
            self.key
        }

        fn verify(
            &self,
            data: &[u8],
            signatures: &[Vec<u8>],
        ) -> ostrya_sign::Result<crate::sign::VerifyOutcome> {
            self.threads
                .lock()
                .unwrap()
                .push(std::thread::current().id());
            self.payloads
                .lock()
                .unwrap()
                .push((data.as_ptr() as usize, data.to_vec()));
            Ok(crate::sign::VerifyOutcome {
                valid: !signatures.is_empty(),
                ..Default::default()
            })
        }
    }

    /// The ed25519 signature of `secret` over [`PAYLOAD`], in its dict.
    fn ed25519_signed(secret: &str) -> Value {
        let signer = Ed25519Signer::from_base64(secret).unwrap();
        let blob = ostrya_rt::block_on(signer.sign(PAYLOAD)).unwrap();
        dict_with(signer.metadata_key(), blob)
    }

    /// A trust group verifies a commit against the key that it names. A
    /// signature from this key passes. A commit with no signature fails, and a
    /// signature from another key fails.
    #[test]
    fn a_trust_group_checks_a_commit() {
        let scratch = Scratch::new("group");
        let repo = scratch.repo();
        let group = "ex-ostrya trust \"t\"";
        let keyfile = KeyFile::parse(&format!(
            "[{group}]\nsign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n"
        ))
        .unwrap();
        let policy =
            ostrya_rt::block_on(trust_group_policy(&repo, &keyfile, "t", group, true, true))
                .unwrap();
        let own = ed25519_signed(SECRET_B64);
        let other = ed25519_signed(OTHER_SECRET_B64);
        let (valid, unsigned, untrusted) = ostrya_rt::block_on(async {
            (
                policy.check("commit", PAYLOAD, Some(&own)).await,
                policy.check("commit", PAYLOAD, None).await,
                policy.check("commit", PAYLOAD, Some(&other)).await,
            )
        });
        valid.expect("a signature from the named key passes");
        let err = unsigned.unwrap_err();
        assert!(err.to_string().contains("carries no signature"), "{err}");
        let err = untrusted.unwrap_err();
        assert!(
            err.to_string()
                .contains("no sign-api signature is from a trusted key"),
            "{err}"
        );
    }

    /// A trust group refuses an engine with no key. The system key store does
    /// not supply a key for the engine.
    #[test]
    fn a_trust_group_engine_needs_a_key() {
        let scratch = Scratch::new("nokey");
        let repo = scratch.repo();
        let group = "ex-ostrya trust \"t\"";
        let keyfile = KeyFile::parse(&format!("[{group}]\nsign-verify=ed25519\n")).unwrap();
        let Err(err) =
            ostrya_rt::block_on(trust_group_policy(&repo, &keyfile, "t", group, true, true))
        else {
            panic!("an engine with no key is refused");
        };
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("no trusted key for signature engine 'ed25519'")),
            "{err}"
        );
    }

    /// The build of a trust group builds only the axes that stay on, and
    /// reads no key source of an axis that is off. With both axes off, the
    /// policy holds no axis.
    #[test]
    fn a_trust_group_builds_the_axes_that_stay_on() {
        let scratch = Scratch::new("axes");
        let repo = scratch.repo();
        let group = "ex-ostrya trust \"t\"";
        // The keyring path does not exist, so a build of the GPG axis fails.
        let keyfile = KeyFile::parse(&format!(
            "[{group}]\ngpg-verify=true\ngpgkeypath={}\n\
             sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n",
            scratch.dir.join("absent.gpg").display()
        ))
        .unwrap();
        let build = |gpg_on: bool, sign_on: bool| {
            ostrya_rt::block_on(trust_group_policy(
                &repo, &keyfile, "t", group, gpg_on, sign_on,
            ))
        };

        let sign = build(false, true).expect("the GPG axis is off, so no keyring is read");
        assert!(!sign.gpg_axis());
        assert_eq!(sign.sign_axis().map(<[_]>::len), Some(1));
        let own = ed25519_signed(SECRET_B64);
        ostrya_rt::block_on(sign.check("commit", PAYLOAD, Some(&own)))
            .expect("the sign-api axis reads the key of the group");

        let none = build(false, false).unwrap();
        assert!(!none.applies());

        let Err(err) = build(true, false) else {
            panic!("the GPG axis reads the keyring that the group names");
        };
        #[cfg(feature = "verify-gpg")]
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("absent.gpg")),
            "{err}"
        );
        #[cfg(not(feature = "verify-gpg"))]
        assert!(matches!(&err, Error::Unsupported(_)), "{err}");
    }

    /// Returns `true` if `gpg` answers.
    ///
    /// If `gpg` does not answer, a test that needs it skips. If
    /// `OSTRYA_REQUIRE_GNUPG` is set, the absence of `gpg` fails the test.
    #[cfg(feature = "verify-gpg")]
    fn gpg_or_skip() -> bool {
        if crate::gpg::tests::gpg_available() {
            return true;
        }
        assert!(
            std::env::var_os("OSTRYA_REQUIRE_GNUPG").is_none(),
            "OSTRYA_REQUIRE_GNUPG is set and `gpg` is not available"
        );
        eprintln!("skipping: gpg not available");
        false
    }

    /// The environment variable that tells the child process of
    /// [`the_global_gpg_directory_is_not_part_of_a_trust_group`] where its
    /// fixtures are.
    #[cfg(feature = "verify-gpg")]
    const FIXTURE_ENV: &str = "OSTRYA_TRUST_TEST_FIXTURES";

    /// The global GPG trusted directory, which `OSTREE_GPG_HOME` names, is not
    /// part of a trust group. The test sets the environment for a child
    /// process, so no test of this process reads the directory.
    #[cfg(feature = "verify-gpg")]
    #[test]
    fn the_global_gpg_directory_is_not_part_of_a_trust_group() {
        use crate::gpg::tests::KeyFixture;

        if !gpg_or_skip() {
            return;
        }
        let key = KeyFixture::new("Global <global@example.org>");
        let stranger = KeyFixture::new("Stranger <stranger@example.org>");
        let scratch = Scratch::new("global");
        let global = scratch.dir.join("global");
        std::fs::create_dir(&global).unwrap();
        std::fs::write(global.join("global.gpg"), key.export(false)).unwrap();
        std::fs::write(scratch.dir.join("own.gpg"), key.export(false)).unwrap();
        std::fs::write(scratch.dir.join("stranger.gpg"), stranger.export(false)).unwrap();
        std::fs::write(scratch.dir.join("signature"), key.sign(PAYLOAD)).unwrap();

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "verify::trust::tests::global_gpg_directory_subprocess",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("OSTREE_GPG_HOME", &global)
            .env(FIXTURE_ENV, &scratch.dir)
            .output()
            .expect("re-execute this test binary");
        let stdout = String::from_utf8_lossy(&child.stdout);
        assert!(
            child.status.success() && stdout.contains("1 passed"),
            "the child reported {}:\n{stdout}{}",
            child.status,
            String::from_utf8_lossy(&child.stderr),
        );
    }

    /// The half of [`the_global_gpg_directory_is_not_part_of_a_trust_group`]
    /// that builds the trusted keys. It runs only if this test binary runs
    /// again with the environment set.
    ///
    /// A trust group whose keyring holds the key of the signature passes, so
    /// the signature is valid. A trust group whose keyring holds another key
    /// fails, and the global directory does not supply the key.
    #[cfg(feature = "verify-gpg")]
    #[test]
    #[ignore = "helper process for the_global_gpg_directory_is_not_part_of_a_trust_group"]
    fn global_gpg_directory_subprocess() {
        let Some(fixtures) = std::env::var_os(FIXTURE_ENV).map(std::path::PathBuf::from) else {
            return;
        };
        let signed = dict_with(
            "ostree.gpgsigs",
            std::fs::read(fixtures.join("signature")).unwrap(),
        );
        let scratch = Scratch::new("global-child");
        let repo = scratch.repo();
        let check = |keyring: &str| {
            let group = "ex-ostrya trust \"t\"";
            let keyfile = KeyFile::parse(&format!(
                "[{group}]\ngpg-verify=true\ngpgkeypath={}\n",
                fixtures.join(keyring).display()
            ))
            .unwrap();
            ostrya_rt::block_on(async {
                trust_group_policy(&repo, &keyfile, "t", group, true, true)
                    .await
                    .unwrap()
                    .check("commit", PAYLOAD, Some(&signed))
                    .await
            })
        };
        check("own.gpg").expect("the keyring of the group holds the key");
        let err = check("stranger.gpg").expect_err("a trust group reads no global directory");
        assert!(matches!(err, Error::Signature(_)), "{err}");
    }

    /// `verification_engine` returns the engine that a verification key
    /// names.
    #[test]
    fn verification_keys_name_their_engine() {
        assert_eq!(
            verification_engine("verification-ed25519-key"),
            Some("ed25519")
        );
        assert_eq!(verification_engine("verification-spki-file"), Some("spki"));
        assert_eq!(verification_engine("verification-x-y"), None);
        assert_eq!(verification_engine("gpgkeypath"), None);
    }
}
