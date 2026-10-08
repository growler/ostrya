//! Integration tests for GPG commit signing.
//!
//! These tests use [`GpgSigner`] and [`GpgVerifier`] with the GnuPG
//! installation of the system:
//!
//! - Each test generates a temporary signing key in a private GnuPG home
//!   directory under its scratch tree.
//! - ostrya signs a commit through the `gpg` binary.
//! - Verification runs in the process over exported keyrings, in binary and
//!   in armored form.
//!
//! Each `gpg` run gives an explicit `--homedir`. The tests never touch the
//! GnuPG home of the user or an agent that the user runs. GnuPG starts an
//! agent for the scratch home automatically. The fixture kills this agent
//! when it drops.
//!
//! Each test signs, so each test needs the `gpg` binary. If the binary is
//! absent, the test skips itself. The conformance record
//! `commit/gpg-sign-round-trip` verifies signatures across ostrya and the
//! `ostree gpg-sign` command.

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

/// Returns `true` if the `gpg` binary is available.
///
/// The GnuPG tests build their fixtures with this binary. If it is absent,
/// the harness skips these tests. [`common::REQUIRE_GNUPG`] changes the skip
/// into a failure.
fn gpg_available() -> bool {
    common::gnupg_available(&["gpg"])
}

/// A private GnuPG home directory with one new ed25519 signing key.
///
/// The key has no passphrase. When the fixture drops, it stops the GnuPG
/// daemons of the directory and removes their socket directory.
struct GpgHome {
    dir: PathBuf,
}

impl GpgHome {
    /// Creates a new home directory under `base` with no key.
    fn empty(base: &Path, name: &str) -> GpgHome {
        use std::os::unix::fs::DirBuilderExt;
        let dir = base.join(name);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        GpgHome { dir }
    }

    /// Creates a new home directory under `base` with a signing key for `uid`.
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

    /// Returns a `gpg` command in batch mode for this home directory.
    fn gpg(&self) -> Command {
        let mut cmd = Command::new("gpg");
        cmd.arg("--homedir").arg(&self.dir).arg("--batch");
        cmd
    }

    /// Returns the fingerprint of the primary key as uppercase hex.
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

    /// Returns the exported public keyring in binary form.
    fn export(&self) -> Vec<u8> {
        let out = self.gpg().arg("--export").output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        out.stdout
    }

    /// Returns the exported public keyring with ASCII armor.
    fn export_armored(&self) -> Vec<u8> {
        let out = self.gpg().args(["--export", "--armor"]).output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        out.stdout
    }

    /// Revokes the primary key with an import of its revocation certificate.
    ///
    /// `gpg` stored this certificate when it generated the key. The stored
    /// file has text before the armored block. It also has a colon before the
    /// first dash of the block, so an accidental import does nothing. The
    /// import in this function reads the armored block alone.
    fn revoke_primary(&self) {
        let stored = self
            .dir
            .join("openpgp-revocs.d")
            .join(format!("{}.rev", self.fingerprint()));
        let text = std::fs::read_to_string(&stored).unwrap();
        let at = text.find("-----BEGIN PGP").unwrap();
        let path = self.dir.join("revocation.asc");
        std::fs::write(&path, &text.as_bytes()[at..]).unwrap();
        let status = self.gpg().arg("--import").arg(&path).status().unwrap();
        assert!(status.success(), "gpg --import of the revocation failed");
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        common::remove_gnupg_sockets(&self.dir);
    }
}

/// Builds a small source tree under `base/src`.
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

/// Creates an archive repository, ingests `base/src`, and commits it on
/// `test/main`.
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

        // The trusted keyring accepts the signature and reports its details.
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

        // With an empty trusted set, the verifier reports the key as missing.
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

        // The verifier decodes the armored export when it loads it. The
        // signature verifies.
        let armored = GpgVerifier::from_keyring_bytes([home.export_armored()]).unwrap();
        let outcome = repo.verify_commit(&commit, &[&armored]).await.unwrap();
        assert!(outcome.valid);

        // The verifier loads keyring files from disk. It skips a path that
        // does not exist.
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

/// The key selector goes to `gpg` as a key name, never as a `gpg` option.
///
/// `secret_key_fingerprints` puts the selector after `--`, so a selector with
/// the shape of an option is a key name. No key in the home directory of the
/// signer has this name. The selector does not move the lookup to a home
/// directory that the selector names. A read in such a directory makes `gpg`
/// create a keybox and a trust database as a side effect.
#[test]
fn an_option_shaped_selector_is_a_key_name() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("gpg-selector");
    let base = tmp.path();
    // The home directory with the key, and the empty home directory where the
    // lookups run.
    let keyed = GpgHome::create(base, "gnupghome", "Selector <selector@ostrya.example>");
    let lookup = GpgHome::empty(base, "lookup-home");
    // A home directory that the lookups must not reach. It is a `GpgHome`, so
    // if a failure starts an agent for it, the fixture kills this agent.
    let elsewhere = GpgHome::empty(base, "elsewhere");

    block_on(async {
        // A selector that names the keyed home directory does not move the
        // lookup to that directory, so the lookup does not find its key.
        let redirect = format!("--homedir={}", keyed.dir.display());
        let signer = GpgSigner::new(&redirect).with_homedir(&lookup.dir);
        assert!(
            signer.secret_key_fingerprints().await.unwrap().is_empty(),
            "the selector re-homed the lookup onto the keyed home directory"
        );

        // A selector that names an unused directory does not change it.
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

    // The keyed home directory keeps its key. The lookups read nothing from it
    // and wrote nothing to it.
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

/// A revoked re-export of a key in the keyring of a remote revokes that key.
///
/// The import reports that it added no key. After the import, the signature
/// of that key is not valid.
///
/// `ostree remote gpg-import` merges the offered signatures into the
/// certificate in the keyring. For this import, it reports `Imported 0 GPG
/// keys`. Observed with `ostree` 2026.1 and the re-export of a revoked RSA
/// key:
///
/// - The keyring grew from 690 to 1053 bytes.
/// - In the merged run of packets, the key revocation came directly after the
///   primary key packet.
/// - The output of `ostree show` changed from `Good signature from "..."` to
///   `Key revoked`.
#[test]
fn a_revoked_re_export_revokes_the_held_key() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("gpg-revoke-import");
    let base = tmp.path();
    let home = GpgHome::create(base, "gnupghome", "Revoked <revoked@ostrya.example>");
    let fpr = home.fingerprint();
    let root = base.join("repo");
    block_on(async {
        let (repo, commit) = build_committed_repo(base).await;
        let signer = GpgSigner::new(&fpr).with_homedir(&home.dir);
        repo.sign_commit(&commit, &signer).await.unwrap();

        // The certificate without the revocation goes into the keyring of the
        // remote. The signature of its key is good.
        let count = repo
            .gpg_import_keys("origin", &home.export(), &[])
            .await
            .unwrap();
        assert_eq!(count, 1);
        let verifier = GpgVerifier::for_remote(&root, "origin").unwrap();
        let outcome = repo.verify_commit(&commit, &[&verifier]).await.unwrap();
        assert!(outcome.valid);
        assert!(!outcome.signatures[0].revoked);

        // The re-export of the revoked key adds no key. It puts the revocation
        // into the keyring.
        home.revoke_primary();
        let count = repo
            .gpg_import_keys("origin", &home.export(), &[])
            .await
            .unwrap();
        assert_eq!(count, 0);
        let verifier = GpgVerifier::for_remote(&root, "origin").unwrap();
        let outcome = repo.verify_commit(&commit, &[&verifier]).await.unwrap();
        assert_eq!(outcome.signatures.len(), 1);
        assert!(
            outcome.signatures[0].revoked,
            "the keyring did not carry the revocation"
        );
        assert!(!outcome.signatures[0].key_missing);
        assert!(!outcome.valid);
    });
}

/// A remote keyring with bytes after its last framed packet gets a refusal
/// that names the keyring.
///
/// - The key listing reports the refusal.
/// - Each import reports the refusal.
/// - The file keeps its bytes.
///
/// One reader reads the keyring for each path, so the refusal applies to the
/// whole file. A revoked re-export of a key in the file and a certificate for
/// a key that is not in the file get the same refusal. The `ostree` command
/// also reads no certificate from a keyring with one `0xff` byte at the end.
/// Its import reports a count of zero and writes nothing (divergence P3).
#[test]
fn an_unframeable_remote_keyring_is_refused() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("gpg-revoke-unframeable");
    let base = tmp.path();
    let home = GpgHome::create(base, "gnupghome", "Tailed <tailed@ostrya.example>");
    let other = GpgHome::create(base, "othergnupghome", "Other <other@ostrya.example>");
    let keyring = base.join("repo").join("origin.trustedkeys.gpg");
    block_on(async {
        let (repo, _) = build_committed_repo(base).await;
        let count = repo
            .gpg_import_keys("origin", &home.export(), &[])
            .await
            .unwrap();
        assert_eq!(count, 1);

        // One byte after the last packet that the walk frames.
        let mut tailed = std::fs::read(&keyring).unwrap();
        tailed.push(0xff);
        std::fs::write(&keyring, &tailed).unwrap();

        let refusal = repo.gpg_list_keys("origin").await.unwrap_err().to_string();
        assert!(refusal.contains("origin.trustedkeys.gpg"), "{refusal}");
        assert!(refusal.contains("OpenPGP keyring"), "{refusal}");

        // The revoked re-export of the key in the file and a certificate for
        // a key that is not in the file get the same refusal.
        home.revoke_primary();
        for offered in [home.export(), other.export()] {
            let refusal = repo
                .gpg_import_keys("origin", &offered, &[])
                .await
                .unwrap_err()
                .to_string();
            assert!(refusal.contains("origin.trustedkeys.gpg"), "{refusal}");
            assert!(refusal.contains("OpenPGP keyring"), "{refusal}");
            assert_eq!(std::fs::read(&keyring).unwrap(), tailed);
        }
    });
}
