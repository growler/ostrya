//! The trust groups, `[ex-ostrya trust "NAME"]`: the check of a group and the
//! build of its trusted keys.
//!
//! `check_trust` checks the keys and the values of a group. It reads no file
//! and runs no program. `TrustedKeys::for_trust_group` builds the trusted
//! keys of a group that passed the check.
#![cfg_attr(not(feature = "receive"), allow(dead_code))]

use ostrya_core::KeyFile;

use crate::config::{Remote, SignVerify};
use crate::error::{Error, Result};
use crate::repo::Repo;

use super::{KeySource, TrustedKeys, Verifiers, build_policy};

/// The sign-api engines that a trust group can name.
const TRUST_ENGINES: &[&str] = &["ed25519", "spki"];

impl TrustedKeys {
    /// Creates the keys of the trust group `name` from the key-file group
    /// `group`.
    ///
    /// The policy reader checks the group first. As a result, the group turns
    /// on at least one axis, and an axis reads each key that the group holds.
    pub(crate) async fn for_trust_group(
        repo: &Repo,
        keyfile: &KeyFile,
        name: &str,
        group: &str,
    ) -> Result<TrustedKeys> {
        let section = Remote::view(keyfile, group.to_owned());
        let gpg = keyfile.get_bool(group, "gpg-verify")?.unwrap_or(false);
        let sign = section.sign_verify()?;
        let source = KeySource::Trust {
            name,
            section: &section,
        };
        let policy = build_policy(repo, &source, &mut Verifiers::default(), gpg, &sign).await?;
        Ok(TrustedKeys::from_policy(policy))
    }
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
                    "[{group}] holds '{key}', and a push carries no summary"
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
    if cfg!(not(any(
        feature = "sign-spki-p256",
        feature = "sign-spki-p384",
        feature = "sign-spki-ed25519",
        feature = "sign-spki-rsa"
    ))) && names_spki
    {
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
        let policy = ostrya_rt::block_on(TrustedKeys::for_trust_group(&repo, &keyfile, "t", group))
            .unwrap()
            .into_policy();
        let own = ed25519_signed(SECRET_B64);
        let other = ed25519_signed(OTHER_SECRET_B64);
        let (valid, unsigned, untrusted) = ostrya_rt::block_on(async {
            (
                policy.check_unblocked("commit", PAYLOAD, Some(&own)).await,
                policy.check_unblocked("commit", PAYLOAD, None).await,
                policy
                    .check_unblocked("commit", PAYLOAD, Some(&other))
                    .await,
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
            ostrya_rt::block_on(TrustedKeys::for_trust_group(&repo, &keyfile, "t", group))
        else {
            panic!("an engine with no key is refused");
        };
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("no trusted key for signature engine 'ed25519'")),
            "{err}"
        );
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
                TrustedKeys::for_trust_group(&repo, &keyfile, "t", group)
                    .await
                    .unwrap()
                    .into_policy()
                    .check_unblocked("commit", PAYLOAD, Some(&signed))
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
