//! The receive-side constructor of the trusted keys: the keys of a trust
//! group.

use ostrya_core::{KeyFile, Value};

use crate::config::Remote;
use crate::error::Result;
use crate::repo::Repo;
use crate::verify::{KeySource, TrustedKeys, Verifiers, build_policy};

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

    /// Verifies `payload` against every axis of this set.
    ///
    /// `detached` is the detached-metadata dict that holds the signatures. It
    /// is `None` if the payload has no detached metadata. `subject` names the
    /// payload in a message.
    ///
    /// The verifiers of the sign-api axis run on the blocking pool, with a
    /// copy of `payload`, because the ed25519 and spki verifiers do their work
    /// in the call. A client controls the number of signature blobs, and an
    /// RSA verify with a 16384-bit key takes milliseconds of CPU time.
    pub(crate) async fn check(
        &self,
        subject: &str,
        payload: &[u8],
        detached: Option<&Value>,
    ) -> Result<()> {
        self.policy()
            .check_unblocked(subject, payload, detached)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
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

    /// A verifier that accepts each blob and records the thread of each call.
    #[derive(Default)]
    struct ThreadRecorder {
        /// The thread of each call to `verify`, in order.
        threads: std::sync::Mutex<Vec<std::thread::ThreadId>>,
    }

    impl crate::sign::Verifier for ThreadRecorder {
        fn metadata_key(&self) -> &str {
            "ostree.sign.ed25519"
        }

        fn verify<'a>(
            &'a self,
            _data: &'a [u8],
            signatures: &'a [Vec<u8>],
        ) -> crate::sign::VerifyFuture<'a> {
            self.threads
                .lock()
                .unwrap()
                .push(std::thread::current().id());
            let outcome = crate::sign::VerifyOutcome {
                valid: !signatures.is_empty(),
                ..Default::default()
            };
            Box::pin(async move { Ok(outcome) })
        }
    }

    /// The trust check runs the verifiers of the sign-api axis on the blocking
    /// pool, so a verifier that works in the call does not hold the async
    /// executor.
    #[test]
    fn the_sign_api_axis_verifies_on_the_blocking_pool() {
        let recorder = std::sync::Arc::new(ThreadRecorder::default());
        let verifier: std::sync::Arc<dyn crate::sign::Verifier> = recorder.clone();
        let keys = TrustedKeys::new(vec![verifier]).unwrap();
        let dict = dict_with("ostree.sign.ed25519", vec![7; 64]);
        ostrya_rt::block_on(keys.check("commit", PAYLOAD, Some(&dict))).unwrap();
        let threads = recorder.threads.lock().unwrap();
        assert_eq!(threads.len(), 1);
        assert_ne!(threads[0], std::thread::current().id());
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
                    .check("commit", PAYLOAD, Some(&signed))
                    .await
            })
        };
        check("own.gpg").expect("the keyring of the group holds the key");
        let err = check("stranger.gpg").expect_err("a trust group reads no global directory");
        assert!(matches!(err, Error::Signature(_)), "{err}");
    }
}
