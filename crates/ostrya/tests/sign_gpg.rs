//! GPG commit-signing integration tests (Phase 13d).
//!
//! These exercise [`GpgSigner`] / [`GpgVerifier`] against the system GnuPG
//! installation: a throwaway signing key is generated in a private GnuPG home
//! directory under the test's scratch tree, the port signs a commit through
//! the `gpg` binary, and verification runs in the process over exported
//! keyrings (binary and armored). Every gpg invocation passes an explicit
//! `--homedir`; the user's GnuPG home and any running agent of theirs are
//! never touched, and the agent GnuPG auto-starts for the scratch home is
//! killed when the fixture drops.
//!
//! Every case here signs, so each needs the `gpg` binary and skips itself
//! where it is absent. Tool cross-verification against `ostree gpg-sign` is
//! stated by `docs/conformance/m10-cli-behavior.matrix`,
//! `commit/gpg-sign-round-trip`.

#![cfg(feature = "sign-gpg")]

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DummySigner,
    DummyVerifier, GpgSigner, GpgVerifier, MutableTree, Repo, RepoMode, Signer, Verifier,
};
use ostrya_rt::block_on;

/// Whether the gpg binary is available. The GnuPG cases build their fixtures
/// with it, so a harness without it skips them rather than passing them, and
/// [`common::REQUIRE_GNUPG`] turns that skip into a failure.
fn gpg_available() -> bool {
    common::gnupg_available(&["gpg"])
}

/// A private GnuPG home directory holding one freshly generated,
/// passphrase-free ed25519 signing key. Dropping the fixture kills the
/// gpg-agent GnuPG auto-started for the directory.
struct GpgHome {
    dir: PathBuf,
}

impl GpgHome {
    /// A new home directory under `base` holding no key.
    fn empty(base: &Path, name: &str) -> GpgHome {
        use std::os::unix::fs::DirBuilderExt;
        let dir = base.join(name);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        GpgHome { dir }
    }

    /// Generate a signing key for `uid` in a new home directory under `base`.
    fn create(base: &Path, name: &str, uid: &str) -> GpgHome {
        let home = GpgHome::empty(base, name);
        let status = home
            .gpg()
            .args(["--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--quick-gen-key", uid, "ed25519", "sign", "never"])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-gen-key failed");
        home
    }

    /// A gpg command bound to this home directory, batch mode.
    fn gpg(&self) -> Command {
        let mut cmd = Command::new("gpg");
        cmd.arg("--homedir").arg(&self.dir).arg("--batch");
        cmd
    }

    /// The primary-key fingerprint, as uppercase hex.
    fn fingerprint(&self) -> String {
        let out = self
            .gpg()
            .args(["--with-colons", "--list-keys"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout).unwrap();
        text.lines()
            .find_map(|line| {
                let mut fields = line.split(':');
                (fields.next() == Some("fpr")).then(|| fields.nth(8).unwrap().to_owned())
            })
            .expect("a fpr record in the key listing")
    }

    /// The exported public keyring, binary.
    fn export(&self) -> Vec<u8> {
        let out = self.gpg().arg("--export").output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        out.stdout
    }

    /// The exported public keyring, ASCII-armored.
    fn export_armored(&self) -> Vec<u8> {
        let out = self.gpg().args(["--export", "--armor"]).output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        out.stdout
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&self.dir)
            .args(["--kill", "gpg-agent"])
            .status();
    }
}

/// Build a tiny source tree under `base/src`.
fn build_source(base: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostrya\n").unwrap();
    std::fs::set_permissions(
        src.join("hello.txt"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Create an archive repo, ingest `base/src`, and commit it on `test/main`.
async fn build_committed_repo(base: &Path) -> (Repo, Checksum) {
    build_source(base);
    let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    );
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new("src"),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let opts = CommitOptions {
        subject: Some("gpg sign fixture".to_owned()),
        timestamp: Some(1_700_000_000),
        ..CommitOptions::default()
    };
    let commit = txn.write_commit(opts, &root).await.unwrap();
    txn.set_ref("test/main", Some(&commit));
    txn.commit().await.unwrap();
    (repo, commit)
}

#[test]
fn gpg_round_trip_within_the_port() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("gpg-roundtrip");
    let base = tmp.path();
    let home = GpgHome::create(base, "gnupghome", "Ostrya Test <gpg-test@ostrya.example>");
    let fpr = home.fingerprint();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        let signer = GpgSigner::new(&fpr).with_homedir(&home.dir);
        repo.sign_commit(&commit, &signer).await.unwrap();

        // The trusted keyring accepts the signature and reports its detail.
        let verifier = GpgVerifier::from_keyring_bytes([home.export()]).unwrap();
        let outcome = repo.verify_commit(&commit, &[&verifier]).await.unwrap();
        assert!(outcome.valid);
        assert_eq!(outcome.signatures.len(), 1);
        let info = &outcome.signatures[0];
        assert!(info.valid);
        assert_eq!(info.fingerprint.as_deref(), Some(fpr.as_str()));
        assert_eq!(info.primary_fingerprint.as_deref(), Some(fpr.as_str()));
        assert!(info.created.is_some());
        assert_eq!(info.pubkey_algorithm.as_deref(), Some("EdDSA"));
        assert_eq!(info.user_name.as_deref(), Some("Ostrya Test"));
        assert_eq!(info.user_email.as_deref(), Some("gpg-test@ostrya.example"));

        // An empty trusted set reports the key missing.
        let untrusted = GpgVerifier::from_keyring_bytes(Vec::<Vec<u8>>::new()).unwrap();
        let outcome = repo.verify_commit(&commit, &[&untrusted]).await.unwrap();
        assert!(!outcome.valid);
        assert_eq!(outcome.signatures.len(), 1);
        assert!(outcome.signatures[0].key_missing);
    });
}

#[test]
fn armored_and_file_keyrings_load() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("gpg-keyrings");
    let base = tmp.path();
    let home = GpgHome::create(base, "gnupghome", "Armored <armored@ostrya.example>");
    let fpr = home.fingerprint();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        let signer = GpgSigner::new(&fpr).with_homedir(&home.dir);
        repo.sign_commit(&commit, &signer).await.unwrap();

        // The armored export decodes on load and verifies.
        let armored = GpgVerifier::from_keyring_bytes([home.export_armored()]).unwrap();
        let outcome = repo.verify_commit(&commit, &[&armored]).await.unwrap();
        assert!(outcome.valid);

        // Keyring files load from disk; missing paths are skipped.
        let ring_path = base.join("trusted.gpg");
        std::fs::write(&ring_path, home.export()).unwrap();
        let files =
            GpgVerifier::from_keyring_files([&ring_path, &base.join("absent.gpg")]).unwrap();
        let outcome = repo.verify_commit(&commit, &[&files]).await.unwrap();
        assert!(outcome.valid);
    });
}

#[test]
fn wrong_payload_is_rejected() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("gpg-badsig");
    let base = tmp.path();
    let home = GpgHome::create(base, "gnupghome", "Bad <bad@ostrya.example>");
    let fpr = home.fingerprint();
    block_on(async {
        let payload = b"the signed payload".to_vec();
        let signer = GpgSigner::new(&fpr).with_homedir(&home.dir);
        let signature = signer.sign(&payload).await.unwrap();

        let verifier = GpgVerifier::from_keyring_bytes([home.export()]).unwrap();
        let good = verifier
            .verify(&payload, std::slice::from_ref(&signature))
            .await
            .unwrap();
        assert!(good.valid);

        let bad = verifier
            .verify(b"a different payload", &[signature])
            .await
            .unwrap();
        assert!(!bad.valid);
        assert_eq!(bad.signatures.len(), 1);
        assert!(!bad.signatures[0].key_missing);
    });
}

#[test]
fn unknown_signer_key_is_an_error() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("gpg-nokey");
    let base = tmp.path();
    let home = GpgHome::create(base, "gnupghome", "Present <present@ostrya.example>");
    block_on(async {
        let signer =
            GpgSigner::new("0000000000000000000000000000000000000000").with_homedir(&home.dir);
        let err = signer.sign(b"payload").await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("gpg"), "unexpected error: {text}");
    });
}

/// The key selector reaches gpg as a key name, never as one of gpg's options.
///
/// `secret_key_fingerprints` puts the selector after `--`. An option-shaped
/// selector therefore names no key in the home directory the signer carries, and
/// it does not move the lookup to a home directory of its own choosing, where gpg
/// would create a keybox and a trust database as a side effect of a read.
#[test]
fn an_option_shaped_selector_is_a_key_name() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("gpg-selector");
    let base = tmp.path();
    // The home directory holding the key, and the empty one the lookups run in.
    let keyed = GpgHome::create(base, "gnupghome", "Selector <selector@ostrya.example>");
    let lookup = GpgHome::empty(base, "lookup-home");
    // A home directory no lookup may reach, kept as a home directory so any
    // agent a failure starts for it is killed with the fixture.
    let elsewhere = GpgHome::empty(base, "elsewhere");

    block_on(async {
        // A selector naming the keyed home directory does not re-home the
        // lookup, so the key it holds is not found.
        let redirect = format!("--homedir={}", keyed.dir.display());
        let signer = GpgSigner::new(&redirect).with_homedir(&lookup.dir);
        assert!(
            signer.secret_key_fingerprints().await.unwrap().is_empty(),
            "the selector re-homed the lookup onto the keyed home directory"
        );

        // A selector naming an untouched directory leaves it untouched.
        let side_effect = format!("--homedir={}", elsewhere.dir.display());
        let signer = GpgSigner::new(&side_effect).with_homedir(&lookup.dir);
        assert!(signer.secret_key_fingerprints().await.unwrap().is_empty());
        assert!(
            !elsewhere.dir.join("pubring.kbx").exists(),
            "the lookup created a keybox in the directory the selector named"
        );
        assert!(
            !elsewhere.dir.join("trustdb.gpg").exists(),
            "the lookup created a trust database in the directory the selector named"
        );
    });

    // The keyed home directory keeps its own key: the lookups read nothing out
    // of it and wrote nothing into it.
    assert!(!keyed.fingerprint().is_empty());
}

#[test]
fn gpg_coexists_with_the_dummy_engine() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("gpg-coexist");
    let base = tmp.path();
    let home = GpgHome::create(base, "gnupghome", "Coexist <coexist@ostrya.example>");
    let fpr = home.fingerprint();
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        repo.sign_commit(&commit, &DummySigner::new(b"dummy-key".to_vec()))
            .await
            .unwrap();
        let signer = GpgSigner::new(&fpr).with_homedir(&home.dir);
        repo.sign_commit(&commit, &signer).await.unwrap();

        let gpg_verifier = GpgVerifier::from_keyring_bytes([home.export()]).unwrap();
        let dummy_verifier = DummyVerifier::new([b"dummy-key".to_vec()]);
        let outcome = repo
            .verify_commit(&commit, &[&dummy_verifier, &gpg_verifier])
            .await
            .unwrap();
        assert!(outcome.valid);
        assert_eq!(outcome.signatures.len(), 2);
        assert!(outcome.signatures.iter().all(|info| info.valid));
    });
}
