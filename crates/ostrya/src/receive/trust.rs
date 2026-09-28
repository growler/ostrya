//! The trusted keys a receive rule holds a commit to.

use std::sync::Arc;

use ostrya_core::{KeyFile, Value};

use crate::config::{Remote, SignVerify};
use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::sign::Verifier;
use crate::verify::{KeySource, Policy, Verifiers, build_policy};

/// The detached-metadata key of the dummy engine.
const DUMMY_METADATA_KEY: &str = "ostree.sign.dummy";

/// A built set of trusted keys and the axes it requires.
///
/// The two axes are ANDed: a set with a GPG axis and a sign-api axis needs a
/// valid signature on each. The sign-api engines are ORed: one valid signature
/// from one of them is enough. The set holds its verifiers, so a commit is
/// checked with no read of a key source.
pub struct TrustedKeys {
    /// The built axes.
    policy: Policy,
}

impl TrustedKeys {
    /// The keys a pull from `remote` trusts for a commit, from the
    /// `[remote "NAME"]` section of the repository config: `gpg-verify` (default
    /// true), `gpgkeypath`, the repository keyring `<repo>/NAME.trustedkeys.gpg`,
    /// the system keyring `/etc/ostree/remotes.d/NAME.trustedkeys.gpg`, the
    /// global GPG trusted directory, `sign-verify`, the `verification-*` keys,
    /// and the system sign-api key store minus its revoked set.
    ///
    /// A remote the config does not describe, and one whose section turns on
    /// no axis, is refused as [`Error::InvalidFormat`]. The key sources are
    /// read as a pull reads them, with the errors a pull gives.
    pub async fn for_remote(repo: &Repo, remote: &str) -> Result<TrustedKeys> {
        TrustedKeys::for_remote_in(repo, repo.config().keyfile(), remote, true).await
    }

    /// Trusted keys with a sign-api axis over `sign`, one verifier for each
    /// engine. An empty `sign` is refused as [`Error::InvalidFormat`]: it
    /// trusts no key. A verifier of the dummy engine is refused the same way:
    /// its signature is its key, so it proves nothing about who signed.
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

    /// Trusted keys with a GPG axis over `gpg`, and a sign-api axis over `sign`
    /// where `sign` is not empty. A verifier of the dummy engine in `sign` is
    /// refused as [`Error::InvalidFormat`], as [`new`](TrustedKeys::new)
    /// refuses it.
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

    /// The pull trust of the `[remote "NAME"]` section of `keyfile`. The
    /// repository keyring of the remote takes part where `repo_keyring` is
    /// true.
    pub(crate) async fn for_remote_in(
        repo: &Repo,
        keyfile: &KeyFile,
        remote: &str,
        repo_keyring: bool,
    ) -> Result<TrustedKeys> {
        let Some(section) = Remote::in_keyfile(keyfile, remote) else {
            return Err(Error::InvalidFormat(format!(
                "remote:{remote} names no [remote \"{remote}\"] section"
            )));
        };
        let gpg = section.gpg_verify()?;
        let sign = section.sign_verify()?;
        if !gpg && sign == SignVerify::Off {
            return Err(Error::InvalidFormat(format!(
                "remote:{remote} turns on no signature check: the remote sets \
                 gpg-verify=false and no sign-verify; write verify=off for no check"
            )));
        }
        let source = KeySource::Remote {
            name: remote,
            section: Some(&section),
            repo_keyring,
        };
        let policy = build_policy(repo, &source, &mut Verifiers::default(), gpg, &sign).await?;
        Ok(TrustedKeys { policy })
    }

    /// The keys of the trust group `name`, whose key-file group is `group`.
    /// The group has passed the checks of the policy reader, so it turns on
    /// one axis at least, and each key it holds is one an axis reads.
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
        Ok(TrustedKeys { policy })
    }

    /// Hold `payload` to every axis of this set. `detached` is the
    /// detached-metadata dict the signatures live in, absent when the payload
    /// carries none. `subject` names the payload in a message.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn check(
        &self,
        subject: &str,
        payload: &[u8],
        detached: Option<&Value>,
    ) -> Result<()> {
        self.policy.check(subject, payload, detached).await
    }
}

/// Refuse a verifier of the dummy engine in `sign`.
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

#[cfg(test)]
mod tests {
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

    const PAYLOAD: &[u8] = b"the commit bytes";

    /// A scratch directory holding an archive repository at `repo`, removed
    /// when the guard drops.
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

    /// A detached-metadata dict holding `blob` under `key`.
    fn dict_with(key: &str, blob: Vec<u8>) -> Value {
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

    /// A trust group holds a commit to the key it names: a signature from it
    /// passes, and a commit with no signature and a signature from another
    /// key are each refused.
    #[test]
    fn a_trust_group_checks_a_commit() {
        let scratch = Scratch::new("group");
        let repo = scratch.repo();
        let group = "ex-ostrya trust \"t\"";
        let keyfile = KeyFile::parse(&format!(
            "[{group}]\nsign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n"
        ))
        .unwrap();
        let keys =
            ostrya_rt::block_on(TrustedKeys::for_trust_group(&repo, &keyfile, "t", group)).unwrap();
        let own = ed25519_signed(SECRET_B64);
        let other = ed25519_signed(OTHER_SECRET_B64);
        let (valid, unsigned, untrusted) = ostrya_rt::block_on(async {
            (
                keys.check("commit", PAYLOAD, Some(&own)).await,
                keys.check("commit", PAYLOAD, None).await,
                keys.check("commit", PAYLOAD, Some(&other)).await,
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

    /// A trust group engine with no key is refused, and the system key store
    /// does not stand in for one.
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

    /// The pull trust of a remote reads the section's keys, and a remote that
    /// turns on no check, or that the file does not describe, is refused.
    #[test]
    fn the_pull_trust_of_a_remote() {
        let scratch = Scratch::new("remote");
        let repo = scratch.repo();
        let keyfile = KeyFile::parse(&format!(
            "[remote \"origin\"]\nurl=http://localhost/\ngpg-verify=false\n\
             sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n\
             [remote \"plain\"]\nurl=http://localhost/\ngpg-verify=false\n"
        ))
        .unwrap();
        let keys = ostrya_rt::block_on(TrustedKeys::for_remote_in(&repo, &keyfile, "origin", true))
            .unwrap();
        ostrya_rt::block_on(keys.check("commit", PAYLOAD, Some(&ed25519_signed(SECRET_B64))))
            .expect("a signature from the remote's key passes");
        for remote in ["plain", "absent"] {
            let Err(err) =
                ostrya_rt::block_on(TrustedKeys::for_remote_in(&repo, &keyfile, remote, true))
            else {
                panic!("{remote} is refused");
            };
            assert!(matches!(err, Error::InvalidFormat(_)), "{remote}: {err}");
        }
    }

    /// Explicit keys: an empty set is refused.
    #[test]
    fn explicit_keys_need_a_verifier() {
        let err = TrustedKeys::new(Vec::new()).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        let verifier = crate::sign::Ed25519Verifier::new(
            [ostrya_core::base64::decode(PUBLIC_B64).unwrap()],
            Vec::<Vec<u8>>::new(),
        )
        .unwrap();
        let keys = TrustedKeys::new(vec![Arc::new(verifier)]).unwrap();
        ostrya_rt::block_on(keys.check("commit", PAYLOAD, Some(&ed25519_signed(SECRET_B64))))
            .unwrap();
    }

    /// Explicit keys: a dummy verifier is refused, alone and next to a real
    /// engine.
    #[test]
    fn explicit_keys_refuse_the_dummy_engine() {
        let dummy = || -> Arc<dyn Verifier> { Arc::new(crate::sign::DummyVerifier::new([b"k"])) };
        let ed25519: Arc<dyn Verifier> = Arc::new(
            crate::sign::Ed25519Verifier::new(
                [ostrya_core::base64::decode(PUBLIC_B64).unwrap()],
                Vec::<Vec<u8>>::new(),
            )
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

    /// Whether `gpg` answers. A test that needs it skips where it does not,
    /// unless `OSTRYA_REQUIRE_GNUPG` is set, where the absence fails the test.
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

    /// The pull trust of a remote takes the repository keyring of the remote
    /// where the source asks for it, and not otherwise.
    #[cfg(feature = "verify-gpg")]
    #[test]
    fn the_repository_keyring_takes_part_on_request() {
        use crate::gpg::tests::KeyFixture;

        if !gpg_or_skip() {
            return;
        }
        let key = KeyFixture::new("Central <central@example.org>");
        let signed = dict_with("ostree.gpgsigs", key.sign(PAYLOAD));
        let scratch = Scratch::new("keyring");
        let repo = scratch.repo();
        std::fs::write(
            scratch.dir.join("repo").join("origin.trustedkeys.gpg"),
            key.export(false),
        )
        .unwrap();
        let keyfile = KeyFile::parse("[remote \"origin\"]\nurl=http://localhost/\n").unwrap();
        let check = |repo_keyring: bool| {
            ostrya_rt::block_on(async {
                TrustedKeys::for_remote_in(&repo, &keyfile, "origin", repo_keyring)
                    .await
                    .unwrap()
                    .check("commit", PAYLOAD, Some(&signed))
                    .await
            })
        };
        check(true).expect("the repository keyring holds the key");
        let err = check(false).expect_err("the repository keyring does not take part");
        assert!(matches!(err, Error::Signature(_)), "{err}");
    }

    /// A `remote:` rule read from the repository config trusts the repository
    /// keyring of the remote, and the same rule read from a policy file does
    /// not.
    #[cfg(feature = "verify-gpg")]
    #[test]
    fn a_policy_file_leaves_out_the_repository_keyring() {
        use crate::gpg::tests::KeyFixture;
        use crate::receive::{ReceivePolicy, ReceiveVerify};

        if !gpg_or_skip() {
            return;
        }
        let key = KeyFixture::new("Central <central@example.org>");
        let signed = dict_with("ostree.gpgsigs", key.sign(PAYLOAD));
        let scratch = Scratch::new("policy-keyring");
        scratch.repo();
        let root = scratch.dir.join("repo");
        std::fs::write(root.join("central.trustedkeys.gpg"), key.export(false)).unwrap();
        let groups = "[remote \"central\"]\nurl=http://localhost/\n\
                      [ex-ostrya receive]\nverify=remote:central\n";
        let mut config = std::fs::read_to_string(root.join("config")).unwrap();
        config.push('\n');
        config.push_str(groups);
        std::fs::write(root.join("config"), config).unwrap();
        let file = scratch.dir.join("receive.conf");
        std::fs::write(&file, groups).unwrap();
        let repo = ostrya_rt::block_on(Repo::open(&root)).unwrap();

        let check = |policy: ReceivePolicy| {
            let ReceiveVerify::Keys(keys) = &policy.default_rule.verify else {
                panic!("the default rule checks signatures");
            };
            ostrya_rt::block_on(keys.check("commit", PAYLOAD, Some(&signed)))
        };
        check(ostrya_rt::block_on(ReceivePolicy::from_config(&repo)).unwrap())
            .expect("the repository config trusts the repository keyring");
        let err = check(ostrya_rt::block_on(ReceivePolicy::from_file(&repo, &file)).unwrap())
            .expect_err("a policy file reads no keyring inside the repository");
        assert!(matches!(err, Error::Signature(_)), "{err}");
    }

    /// The environment variable that tells the child process of
    /// [`the_global_gpg_directory_reaches_remotes_alone`] where its fixtures
    /// are.
    #[cfg(feature = "verify-gpg")]
    const FIXTURE_ENV: &str = "OSTRYA_TRUST_TEST_FIXTURES";

    /// The global GPG trusted directory, which `OSTREE_GPG_HOME` names, takes
    /// part in the pull trust of a remote and not in a trust group. The
    /// environment is set for a child process, so no test of this process
    /// reads the directory.
    #[cfg(feature = "verify-gpg")]
    #[test]
    fn the_global_gpg_directory_reaches_remotes_alone() {
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
        std::fs::write(scratch.dir.join("stranger.gpg"), stranger.export(false)).unwrap();
        std::fs::write(scratch.dir.join("signature"), key.sign(PAYLOAD)).unwrap();

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "receive::trust::tests::global_gpg_directory_subprocess",
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

    /// The half of [`the_global_gpg_directory_reaches_remotes_alone`] that
    /// builds the trusted keys, run only when this test binary is re-executed
    /// with the environment set.
    #[cfg(feature = "verify-gpg")]
    #[test]
    #[ignore = "helper process for the_global_gpg_directory_reaches_remotes_alone"]
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
        let group = "ex-ostrya trust \"t\"";
        let keyfile = KeyFile::parse(&format!(
            "[remote \"origin\"]\nurl=http://localhost/\n\
             [{group}]\ngpg-verify=true\ngpgkeypath={}\n",
            fixtures.join("stranger.gpg").display()
        ))
        .unwrap();
        ostrya_rt::block_on(async {
            TrustedKeys::for_remote_in(&repo, &keyfile, "origin", true)
                .await
                .unwrap()
                .check("commit", PAYLOAD, Some(&signed))
                .await
                .expect("the global directory holds the key");
            let err = TrustedKeys::for_trust_group(&repo, &keyfile, "t", group)
                .await
                .unwrap()
                .check("commit", PAYLOAD, Some(&signed))
                .await
                .expect_err("a trust group reads no global directory");
            assert!(matches!(err, Error::Signature(_)), "{err}");
        });
    }
}
