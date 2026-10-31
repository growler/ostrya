//! The signature verification of a pull.
//!
//! A pull holds two independent policies: one for the commits that it verifies
//! and one for the summary of the remote. The pull builds them once, from the
//! [`PullTrust`] of the pull.
//!
//! The crate module `verify` holds the policy, its two axes, the trusted keys,
//! and the resolution of the trust from the config of a remote. The receive
//! path shares that module. [`PullVerify`](crate::PullVerify) states the rules
//! that a caller sees.

use std::sync::Arc;

use ostrya_core::{Checksum, Value};

use crate::error::{Error, Result};
use crate::verify::{Found, Payload, Policy, PullTrust, examine};

/// The signature verification of one pull.
pub(crate) struct Verification {
    /// The policy for each commit that the pull carries, except a dependency
    /// in no other role.
    commit: Policy,
    /// The policy for the summary of the remote.
    summary: Policy,
}

impl Verification {
    /// Creates the verification of a pull from its trust.
    ///
    /// The trust holds its verifiers, so this function reads no key source.
    pub(crate) fn from_trust(trust: PullTrust) -> Verification {
        let (commit, summary) = trust.into_policies();
        Verification { commit, summary }
    }

    /// Returns `true` if this pull verifies its commits. A dependency in no
    /// other role gets no check.
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
    /// signatures. `bytes` is the serialized commit. Each verifier runs on the
    /// blocking pool, as [`Policy::check`] states.
    pub(crate) async fn check_commit<'p>(
        &self,
        checksum: &Checksum,
        bytes: impl Into<Payload<'p>>,
        detached: Option<&Value>,
    ) -> Result<()> {
        if !self.commit.applies() {
            return Ok(());
        }
        self.commit
            .check(&format!("commit {checksum}"), bytes, detached)
            .await
    }

    /// Verifies the summary of the remote against the summary policy, and
    /// gives back the `summary.sig` bytes `signature`.
    ///
    /// A policy that applies needs both files. If the source publishes no
    /// summary, or a summary with no `summary.sig`, this function fails with
    /// [`Error::Signature`]. The message names the missing file. The `ostree`
    /// command reports the same two cases. A policy that does not apply reads
    /// nothing.
    ///
    /// The parse of `summary.sig` and each verifier run on the blocking pool,
    /// because each file can be as large as the read cap of a summary. The
    /// verifiers share the `Arc` of `summary`, so the check makes no copy of
    /// the summary.
    pub(crate) async fn check_summary(
        &self,
        summary: Option<&Arc<Vec<u8>>>,
        signature: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>> {
        if !self.summary.applies() {
            return Ok(signature);
        }
        let Some(summary) = summary else {
            return Err(no_summary());
        };
        let Some(signature) = signature else {
            return Err(no_summary_sig());
        };
        let (dict, signature) = super::parse_detached(signature).await;
        self.summary
            .check("the summary", summary, dict?.as_ref())
            .await?;
        Ok(Some(signature))
    }

    /// Refuses a summary check that misses a file, before the pull reads a
    /// file.
    ///
    /// `summary` and `signature` tell if the source publishes `summary` and
    /// `summary.sig`. A policy that applies needs both files, and the error
    /// is the error of [`check_summary`](Self::check_summary) for the same
    /// files. A policy that does not apply passes.
    pub(crate) fn check_summary_files(&self, summary: bool, signature: bool) -> Result<()> {
        if !self.summary.applies() {
            return Ok(());
        }
        if !summary {
            return Err(no_summary());
        }
        if !signature {
            return Err(no_summary_sig());
        }
        Ok(())
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
    /// - The commit policy applies to the delivered commit: a target or a
    ///   commit of a chain. The pull does not call this function for the
    ///   delta of a dependency.
    ///
    /// If a delta carries signatures and no signature is from a trusted key,
    /// this function fails with [`Error::Signature`].
    ///
    /// Each verifier runs on the blocking pool, as [`examine`] states.
    pub(crate) async fn check_delta<'p>(
        &self,
        name: &str,
        superblock: impl Into<Payload<'p>>,
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

/// Returns the error of a summary check with no `summary` to check.
fn no_summary() -> Error {
    Error::Signature("summary verification is enabled, but no summary is published".into())
}

/// Returns the error of a summary check with no `summary.sig` to check.
fn no_summary_sig() -> Error {
    Error::Signature("summary verification is enabled, but no summary.sig is published".into())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::pull::PullVerify;
    use crate::repo::Repo;
    use crate::sign::{Ed25519Signer, Ed25519Verifier, Signer, Verifier, append_signature};
    use crate::verify::TrustedKeys;
    use crate::{CreateOptions, RepoMode};

    /// The base64 of a 64-byte ed25519 secret key (seed, then public key).
    const SECRET_B64: &str =
        "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
    /// The matching 32-byte ed25519 public key.
    const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";
    /// Another ed25519 secret key.
    const OTHER_SECRET_B64: &str =
        "5ILWxT+l9G/u3h0BptRpmSi35C9uog7YDdD+Fp1Xk+Hz52p0NlYh6xBA73kJEJKhKbbnjcE0rsWA5XA/K5Sq5Q==";
    /// The matching public key of [`OTHER_SECRET_B64`].
    const OTHER_PUBLIC_B64: &str = "8+dqdDZWIesQQO95CRCSoSm2543BNK7FgOVwPyuUquU=";

    /// The bytes that each test signs: a commit, a summary, or a superblock.
    const PAYLOAD: &[u8] = b"the signed bytes";

    /// The name of the commit in a message.
    fn checksum() -> Checksum {
        Checksum::from_bytes([0x5a; 32])
    }

    /// The trusted keys of one ed25519 public key.
    fn keys(public: &str) -> TrustedKeys {
        let verifier = Ed25519Verifier::new(
            [ostrya_core::base64::decode(public).unwrap()],
            Vec::<Vec<u8>>::new(),
        )
        .unwrap();
        TrustedKeys::new(vec![Arc::new(verifier) as Arc<dyn Verifier>]).unwrap()
    }

    /// The ed25519 signature of `secret` over [`PAYLOAD`], in its dict.
    fn signed(secret: &str) -> Value {
        let signer = Ed25519Signer::from_base64(secret).unwrap();
        let blob = ostrya_rt::block_on(signer.sign(PAYLOAD)).unwrap();
        let mut dict = Value::Array(Vec::new());
        append_signature(&mut dict, signer.metadata_key(), blob).unwrap();
        dict
    }

    /// The bytes of a `summary.sig` that holds the signature of `secret` over
    /// [`PAYLOAD`].
    fn summary_sig(secret: &str) -> Vec<u8> {
        crate::summary::serialize_signature_dict(&signed(secret)).unwrap()
    }

    /// Keys from `TrustedKeys::new` are the whole trusted set of the commits.
    ///
    /// The proof is by construction. A verification from a trust takes no
    /// [`Repo`], so it cannot read the keyring of a repository or the config
    /// of a remote. The system key store is under `/etc/ostree` and
    /// `/usr/share/ostree`, and a test cannot write it to add the other key.
    /// The verification reads no key source at all: it holds the verifiers
    /// that the trust holds. So a commit signed with another key fails, on any
    /// host.
    #[test]
    fn explicit_keys_are_the_whole_trusted_set() {
        let verification = Verification::from_trust(PullTrust::commits(keys(PUBLIC_B64)));
        assert!(verification.checks_commits());
        assert!(!verification.checks_summary());
        let (own, other) = (signed(SECRET_B64), signed(OTHER_SECRET_B64));
        let (own, other, unsigned, summary) = ostrya_rt::block_on(async {
            (
                verification
                    .check_commit(&checksum(), PAYLOAD, Some(&own))
                    .await,
                verification
                    .check_commit(&checksum(), PAYLOAD, Some(&other))
                    .await,
                verification.check_commit(&checksum(), PAYLOAD, None).await,
                verification.check_summary(None, None).await.map(drop),
            )
        });
        own.expect("a commit signed with the trusted key passes");
        let err = other.expect_err("a commit signed with another key fails");
        assert!(
            matches!(&err, Error::Signature(m)
                if m.contains("no sign-api signature is from a trusted key")),
            "{err}"
        );
        let err = unsigned.expect_err("an unsigned commit fails");
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("carries no signature")),
            "{err}"
        );
        summary.expect("the summary is not checked");
    }

    /// The delta check runs each verifier on the blocking pool, so a verifier
    /// that works in the call does not hold the async executor. The check
    /// gives a superblock in an [`Arc`] to the verifier with no copy.
    #[test]
    fn the_delta_check_verifies_on_the_blocking_pool() {
        use crate::verify::trust::tests::{ThreadRecorder, dict_with};

        let recorder = ThreadRecorder::new("ostree.sign.ed25519");
        let keys = TrustedKeys::new(vec![Arc::new(recorder.clone()) as Arc<dyn Verifier>]).unwrap();
        let verification = Verification::from_trust(PullTrust::commits(keys));
        let dict = dict_with("ostree.sign.ed25519", vec![7; 64]);
        let superblock = Arc::new(PAYLOAD.to_vec());
        ostrya_rt::block_on(verification.check_delta("delta", &superblock, Some(&dict))).unwrap();
        recorder.assert_one_foreign_call();
        recorder.assert_no_copy_of(&superblock);
    }

    /// The summary check gives a summary in an [`Arc`] to the verifier with
    /// no copy.
    #[test]
    fn the_summary_check_gives_the_summary_with_no_copy() {
        use crate::verify::trust::tests::{ThreadRecorder, dict_with};

        let recorder = ThreadRecorder::new("ostree.sign.ed25519");
        let keys = TrustedKeys::new(vec![Arc::new(recorder.clone()) as Arc<dyn Verifier>]).unwrap();
        let verification = Verification::from_trust(PullTrust::unverified().with_summary(keys));
        let dict = dict_with("ostree.sign.ed25519", vec![7; 64]);
        let signature = crate::summary::serialize_signature_dict(&dict).unwrap();
        let summary = Arc::new(PAYLOAD.to_vec());
        ostrya_rt::block_on(verification.check_summary(Some(&summary), Some(signature))).unwrap();
        recorder.assert_one_foreign_call();
        recorder.assert_no_copy_of(&summary);
    }

    /// A trust with summary keys alone checks the summary, and no commit and
    /// no static delta. `with_summary` replaces the summary keys of the trust.
    #[test]
    fn a_summary_trust_checks_the_summary_alone() {
        let verification = Verification::from_trust(
            PullTrust::unverified()
                .with_summary(keys(OTHER_PUBLIC_B64))
                .with_summary(keys(PUBLIC_B64)),
        );
        assert!(!verification.checks_commits());
        assert!(verification.checks_summary());
        let other = signed(OTHER_SECRET_B64);
        let (unsigned, other, delta) = ostrya_rt::block_on(async {
            (
                verification.check_commit(&checksum(), PAYLOAD, None).await,
                verification
                    .check_commit(&checksum(), PAYLOAD, Some(&other))
                    .await,
                verification
                    .check_delta("delta", PAYLOAD, Some(&other))
                    .await,
            )
        });
        unsigned.expect("an unsigned commit passes");
        other.expect("a commit signed with another key passes");
        delta.expect("a delta signed with another key passes");

        let own_sig = summary_sig(SECRET_B64);
        let other = summary_sig(OTHER_SECRET_B64);
        let summary = Arc::new(PAYLOAD.to_vec());
        let (own, other, missing) = ostrya_rt::block_on(async {
            (
                verification
                    .check_summary(Some(&summary), Some(own_sig.clone()))
                    .await,
                verification
                    .check_summary(Some(&summary), Some(other))
                    .await,
                verification.check_summary(Some(&summary), None).await,
            )
        });
        assert_eq!(
            own.expect("a summary signed with the last summary key passes"),
            Some(own_sig),
            "the check gives back the summary.sig bytes"
        );
        let err = other.expect_err("a summary signed with a replaced key fails");
        assert!(
            matches!(&err, Error::Signature(m)
                if m.contains("no sign-api signature is from a trusted key")),
            "{err}"
        );
        let err = missing.expect_err("a summary with no summary.sig fails");
        assert!(
            matches!(&err, Error::Signature(m)
                if m == "summary verification is enabled, but no summary.sig is published"),
            "{err}"
        );
    }

    /// `PullTrust::from_remote` reads the keys and the switches of the
    /// section of the remote. The fields of `PullVerify` override the
    /// switches.
    #[test]
    fn from_remote_reads_the_remote_section() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-pull-trust-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let outcome = ostrya_rt::block_on(async {
            Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let mut config = std::fs::read_to_string(root.join("config")).unwrap();
            config.push_str(&format!(
                "\n[remote \"origin\"]\nurl=http://localhost/\ngpg-verify=false\n\
                 sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n"
            ));
            std::fs::write(root.join("config"), config).unwrap();
            let repo = Repo::open(&root).await.unwrap();
            let plain = PullTrust::from_remote(&repo, "origin", &PullVerify::default()).await;
            let summary = PullVerify {
                sign_summary: Some(true),
                ..PullVerify::default()
            };
            let summary = PullTrust::from_remote(&repo, "origin", &summary).await;
            (plain, summary)
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let (plain, summary) = outcome;

        let verification = Verification::from_trust(plain.unwrap());
        assert!(verification.checks_commits());
        assert!(!verification.checks_summary());
        let (own, other) = (signed(SECRET_B64), signed(OTHER_SECRET_B64));
        let (own, unsigned, other) = ostrya_rt::block_on(async {
            (
                verification
                    .check_commit(&checksum(), PAYLOAD, Some(&own))
                    .await,
                verification.check_commit(&checksum(), PAYLOAD, None).await,
                verification
                    .check_commit(&checksum(), PAYLOAD, Some(&other))
                    .await,
            )
        });
        own.expect("a commit signed with the key of the section passes");
        unsigned.expect_err("an unsigned commit fails");
        // The system key store adds its keys to the keys of the section. On a
        // host with no store of its own, the other key is not trusted. The
        // test reads the store only if the commit passes.
        if other.is_ok() {
            assert!(
                crate::sign::load_sign_keys("ed25519").is_ok_and(|store| !store.trusted.is_empty()),
                "a commit signed with another key passes, and the system key \
                 store holds no ed25519 key"
            );
        }

        let verification = Verification::from_trust(summary.unwrap());
        assert!(verification.checks_commits());
        assert!(verification.checks_summary());
        let own = summary_sig(SECRET_B64);
        let summary = Arc::new(PAYLOAD.to_vec());
        ostrya_rt::block_on(verification.check_summary(Some(&summary), Some(own)))
            .expect("a summary signed with the key of the section passes");
    }

    /// `PullTrust::from_remote` refuses a name that `valid_remote_name`
    /// refuses, before it reads a key source. The keyring paths hold the
    /// name, so a name with `/` names a keyring outside the repository or
    /// outside the system keyring directory.
    #[test]
    fn from_remote_refuses_an_invalid_remote_name() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-pull-trust-name-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let outcome = ostrya_rt::block_on(async {
            let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let mut refused = Vec::new();
            for name in ["../../x", ""] {
                let result = PullTrust::from_remote(&repo, name, &PullVerify::default()).await;
                refused.push((name, result));
            }
            refused
        });
        std::fs::remove_dir_all(&dir).unwrap();
        for (name, result) in outcome {
            let err = result.expect_err("an invalid remote name is refused");
            assert!(
                matches!(&err, Error::InvalidInput(m) if m.contains("invalid remote name")),
                "{name:?}: {err}"
            );
        }
    }
}
