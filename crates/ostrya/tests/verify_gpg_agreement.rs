//! Differential tests of the in-process GPG verify engine against `gpgv`.
//!
//! Each case builds its fixtures with `gpg` in a private GnuPG home under the
//! scratch tree of the test. It puts the same keyring, signature blob, and
//! payload through [`GpgVerifier`] and through `gpgv`. Then it compares the two
//! reports field by field. `gpgv` writes its machine-readable status stream,
//! and [`gpgv_records`] reads that stream into the record shape of the engine.
//!
//! `gpg` builds the fixtures and `gpgv` is the reference, so each case needs
//! both binaries. If a binary is absent, the case skips itself and names the
//! absent binary. It does not pass without a comparison. A harness that holds
//! both binaries sets [`common::REQUIRE_GNUPG`], which makes the skip a
//! failure.
//!
//! The unit tests of the engine check each policy rule against `gpgv` through
//! the internal entry point. These cases run the public path: the keyring load,
//! the async `Verifier::verify`, and the move to the blocking pool. They also
//! cover the axes that those rules do not reach:
//!
//! - the key algorithm
//! - the user id set of the certificate
//! - the keyring encoding
//! - the legacy keyring form that carries Trust packets
//! - a corpus of malformed keyrings and blobs
//!
//! This file declares four divergences and does not compare them. Each one
//! names the `gpgv` behavior that it differs from:
//!
//! - an Ed25519 or EdDSA-legacy key with a digest of less than 256 bits
//!   ([`DIVERGENCE_ED25519_DIGEST`])
//! - the digest policy, which is fixed in this engine and configurable in GnuPG
//!   ([`DIVERGENCE_DIGEST_POLICY`])
//! - public-key algorithm id 27, which this GnuPG build does not support
//!   ([`DIVERGENCE_ED25519_ALGORITHM`])
//! - a key that the trusted set holds through two certificates with different
//!   statements about the key ([`DIVERGENCE_DUPLICATE_CERTIFICATE`])

#![cfg(feature = "verify-gpg")]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::TmpDir;
use ostrya::{CreateOptions, GpgVerifier, Repo, RepoMode, SignatureInfo, Verifier};
use ostrya_rt::block_on;

/// The payload every fixture signs.
const PAYLOAD: &[u8] = b"ostrya commit payload";
/// A payload no fixture signs, for the changed-payload case.
const OTHER_PAYLOAD: &[u8] = b"ostrya other payload";
/// The time of a home with a faked clock: 2025-01-01T00:00:00Z.
const FAKED_CLOCK: &str = "20250101T000000!";

/// The divergence for an Ed25519 key with a digest of less than 256 bits.
///
/// rPGP verifies an Ed25519 or an EdDSA-legacy signature only with a digest of
/// at least 256 bits. A SHA-1 or SHA-224 data signature by such a key verifies
/// against no payload. `gpgv` 2.4.9 reports `GOODSIG` for the same signature.
const DIVERGENCE_ED25519_DIGEST: &str = "an Ed25519 key with a digest under 256 bits";
/// The divergence for the digest policy.
///
/// The digest policy of this engine is fixed: it refuses MD5 and accepts SHA-1.
/// The GnuPG set is configurable and changes between versions:
///
/// - `gpgv --weak-digest SHA1` refuses a SHA-1 signature that this engine
///   accepts.
/// - `gpg --verify --allow-weak-digest-algos` accepts an MD5 signature that
///   this engine refuses.
const DIVERGENCE_DIGEST_POLICY: &str = "the digest policy is fixed here and configurable in GnuPG";
/// The divergence for public-key algorithm id 27.
///
/// The report names id 27 `Ed25519` and id 22 `EdDSA`. `gpg` 2.4.9 lists
/// `EDDSA` and no `Ed25519` in its supported public-key algorithms. It
/// generates id 22 for the `ed25519` curve, so no fixture on this reference can
/// carry id 27. The matrix has no cell for id 27.
const DIVERGENCE_ED25519_ALGORITHM: &str = "public-key algorithm id 27 has no reference fixture";
/// The divergence for a key with two certificates.
///
/// The verdict reads each certificate for the issuer, so a revocation on any of
/// them refuses the signature. `gpgv` 2.4.9 reads the first certificate for the
/// key in its keyrings, so its answer depends on the load order. If the
/// unrevoked certificate is first, it reports `GOODSIG`. If the revoked
/// certificate is first, it reports `REVKEYSIG`.
const DIVERGENCE_DUPLICATE_CERTIFICATE: &str =
    "a revocation on any certificate for the key refuses the signature";

/// Returns `true` if both binaries answer, and names the absent one if not.
///
/// An absent reference binary skips a case and never passes it. These cases are
/// the full coverage of the differential gate. If a case passes without `gpg`
/// or `gpgv`, a runner image without them reports the gate as tested. Then no
/// test compares the two reports.
fn tools_available() -> bool {
    common::gnupg_available(&["gpg", "gpgv"])
}

/// A private GnuPG home with one generated signing key without a passphrase.
///
/// Each `gpg` and `gpgv` run names a directory inside the home. The GnuPG home
/// of the user and any agent of the user take no part. When a `Home` drops, it
/// stops the GnuPG daemons of the directory and removes their socket directory.
struct Home {
    dir: PathBuf,
    /// The fingerprint of the primary key, in uppercase hex.
    primary: String,
    /// `true` if each `gpg` run in this home uses [`FAKED_CLOCK`].
    faked: bool,
}

impl Home {
    /// Creates a home under `base` with one ed25519 signing key for `uid`.
    ///
    /// The key never expires. `gpg` 2.4.9 generates public-key algorithm id 22
    /// for this curve, and the report names it `EdDSA`.
    fn eddsa(base: &Path, name: &str, uid: &str) -> Home {
        Home::build(base, name, uid, "ed25519", false, "never")
    }

    /// Creates a home under `base` with one RSA signing key for `uid`.
    ///
    /// The key never expires. RSA accepts a digest of less than 256 bits.
    fn rsa(base: &Path, name: &str, uid: &str) -> Home {
        Home::build(base, name, uid, "rsa2048", false, "never")
    }

    /// Creates a home with a key that `gpg` creates at [`FAKED_CLOCK`].
    ///
    /// The key expires `expiry` after that time. Each `gpg` run in the home
    /// uses [`FAKED_CLOCK`], so the key is live when it makes a signature.
    /// `gpgv` reads the real clock, and the real clock makes the key expired.
    fn expiring(base: &Path, name: &str, uid: &str, expiry: &str) -> Home {
        Home::build(base, name, uid, "ed25519", true, expiry)
    }

    fn build(
        base: &Path,
        name: &str,
        uid: &str,
        algorithm: &str,
        faked: bool,
        expiry: &str,
    ) -> Home {
        use std::os::unix::fs::DirBuilderExt;
        let dir = base.join(name);
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&dir).unwrap();
        builder.create(dir.join("gv")).unwrap();
        let mut home = Home {
            dir,
            primary: String::new(),
            faked,
        };
        let status = home
            .gpg()
            .args(["--quick-gen-key", uid, algorithm, "sign", expiry])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-gen-key failed");
        home.primary = home.fingerprints().remove(0);
        home
    }

    /// Returns a `gpg` command for this home in batch mode, with the empty
    /// passphrase given without a prompt.
    fn gpg(&self) -> Command {
        let mut cmd = Command::new("gpg");
        cmd.arg("--homedir").arg(&self.dir).arg("--batch").args([
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ]);
        if self.faked {
            cmd.args(["--faked-system-time", FAKED_CLOCK]);
        }
        cmd
    }

    /// Returns each key fingerprint of the home in listing order: the primary
    /// key first, then its subkeys.
    fn fingerprints(&self) -> Vec<String> {
        let out = self
            .gpg()
            .args(["--with-colons", "--list-keys"])
            .output()
            .unwrap();
        assert!(out.status.success(), "gpg --list-keys failed");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix("fpr:"))
            .filter_map(|rest| rest.split(':').nth(8).map(str::to_owned))
            .collect()
    }

    /// Adds a signing subkey and returns its fingerprint.
    fn add_signing_subkey(&self) -> String {
        let status = self
            .gpg()
            .args(["--quick-add-key", &self.primary, "ed25519", "sign", "never"])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-add-key failed");
        let fingerprints = self.fingerprints();
        assert_eq!(fingerprints.len(), 2);
        fingerprints[1].clone()
    }

    /// Adds a user id.
    fn add_uid(&self, uid: &str) {
        let status = self
            .gpg()
            .args(["--quick-add-uid", &self.primary, uid])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-add-uid failed");
    }

    /// Marks a user id as primary.
    fn set_primary_uid(&self, uid: &str) {
        let status = self
            .gpg()
            .args(["--quick-set-primary-uid", &self.primary, uid])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-set-primary-uid failed");
    }

    /// Revokes a user id.
    fn revoke_uid(&self, uid: &str) {
        let status = self
            .gpg()
            .args(["--quick-revoke-uid", &self.primary, uid])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-revoke-uid failed");
    }

    /// Revokes the primary key.
    ///
    /// The method imports the revocation certificate that `gpg` stores when it
    /// generates the key. The stored file has prose before the armored block.
    /// It also has a colon before the first dash of the block, so an accidental
    /// import does nothing.
    fn revoke_primary(&self) {
        let path = self
            .dir
            .join("openpgp-revocs.d")
            .join(format!("{}.rev", self.primary));
        let text = std::fs::read_to_string(path).unwrap();
        let at = text.find("-----BEGIN PGP").unwrap();
        let path = self.write("revocation.asc", &text.as_bytes()[at..]);
        let status = self.gpg().arg("--import").arg(path).status().unwrap();
        assert!(status.success(), "gpg --import of the revocation failed");
    }

    /// Imports a public keyring.
    ///
    /// After the import, this home holds the certificate of another home and
    /// can certify a user id on it.
    fn import(&self, keyring: &[u8]) {
        let path = self.write("import.gpg", keyring);
        let status = self.gpg().arg("--import").arg(path).status().unwrap();
        assert!(status.success(), "gpg --import of a public keyring failed");
    }

    /// Certifies one user id of the key that `key` names with the key of this
    /// home.
    ///
    /// The certified user id is the one that `uid` matches. The certification
    /// is exportable, so the certificate that this home exports carries it.
    fn certify_uid(&self, key: &str, uid: &str) {
        let status = self
            .gpg()
            .args(["--quick-sign-key", key, uid])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-sign-key failed");
    }

    /// Returns the exported binary public keyring.
    fn keyring(&self) -> Vec<u8> {
        let out = self.gpg().arg("--export").output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        out.stdout
    }

    /// Returns the diagnostics that `gpg` writes when it imports `keyring`.
    ///
    /// The import goes into a scratch home `into` under this home. `gpg`
    /// verifies each self-signature that it imports. If a certificate carries a
    /// self-signature that does not verify, the diagnostics name it.
    fn import_diagnostics(&self, into: &str, keyring: &[u8]) -> String {
        use std::os::unix::fs::DirBuilderExt;
        let home = self.dir.join(into);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&home)
            .unwrap();
        let path = self.write(&format!("{into}.gpg"), keyring);
        let out = Command::new("gpg")
            .arg("--homedir")
            .arg(&home)
            .args(["--batch", "--import"])
            .arg(path)
            .output()
            .unwrap();
        common::remove_gnupg_sockets(&home);
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    /// Returns the exported binary certificate of the one key that `key` names.
    fn export_key(&self, key: &str) -> Vec<u8> {
        let out = self.gpg().args(["--export", key]).output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        out.stdout
    }

    /// Returns the exported ASCII-armored public keyring.
    fn keyring_armored(&self) -> Vec<u8> {
        let out = self.gpg().args(["--export", "--armor"]).output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        out.stdout
    }

    /// Returns one detached signature over `payload` by exactly the key that
    /// `key` names.
    ///
    /// The method passes `extra` to `gpg` in addition to the base options.
    fn sign(&self, key: &str, payload: &[u8], extra: &[&str]) -> Vec<u8> {
        let file = self.write("payload", payload);
        let out = self
            .gpg()
            .args(extra)
            .args(["--detach-sign", "--output", "-", "--local-user"])
            .arg(format!("{key}!"))
            .arg(file)
            .output()
            .unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        out.stdout
    }

    /// Returns the records that `gpgv` reports for `keyring`, `blob`, and
    /// `payload`.
    fn gpgv_records(&self, keyring: &[u8], blob: &[u8], payload: &[u8]) -> Vec<SignatureInfo> {
        let ring = self.write("ring.gpg", keyring);
        let sig = self.write("blob.sig", blob);
        let data = self.write("data", payload);
        let out = Command::new("gpgv")
            .arg("--homedir")
            .arg(self.dir.join("gv"))
            .args(["--status-fd", "1", "--keyring"])
            .arg(ring)
            .arg(sig)
            .arg(data)
            .output()
            .unwrap();
        gpgv_records(&out.stdout)
    }

    /// Writes one file into the home and returns its path.
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        common::remove_gnupg_sockets(&self.dir);
    }
}

/// The prefix every machine-readable status line carries.
const STATUS_PREFIX: &str = "[GNUPG:] ";

/// Reads the machine-readable status stream of one `gpgv` run into one record
/// for each signature.
///
/// Each `NEWSIG` line starts a record. The four verdict keywords and the
/// `VALIDSIG`, `ERRSIG`, `NO_PUBKEY`, and `KEYEXPIRED` lines fill it. A field
/// with the value zero reads as absent, because `gpgv` writes zero for "no
/// expiry" and "no creation time".
fn gpgv_records(stdout: &[u8]) -> Vec<SignatureInfo> {
    let text = String::from_utf8_lossy(stdout);
    let mut records: Vec<SignatureInfo> = Vec::new();
    let mut current: Option<SignatureInfo> = None;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(STATUS_PREFIX) else {
            continue;
        };
        let mut fields = rest.split(' ');
        let keyword = fields.next().unwrap_or("");
        match keyword {
            "NEWSIG" => {
                if let Some(record) = current.take() {
                    records.push(record);
                }
                current = Some(SignatureInfo::default());
            }
            "GOODSIG" | "EXPKEYSIG" | "REVKEYSIG" | "BADSIG" => {
                let record = current.get_or_insert_with(SignatureInfo::default);
                let _keyid = fields.next();
                let (name, email) = split_uid(&fields.collect::<Vec<_>>().join(" "));
                record.user_name = name;
                record.user_email = email;
                match keyword {
                    "GOODSIG" => record.valid = true,
                    "EXPKEYSIG" => record.expired = true,
                    "REVKEYSIG" => record.revoked = true,
                    _ => {}
                }
            }
            // VALIDSIG <fpr> <date> <sig-epoch> <sig-expire-epoch> <version>
            //          <reserved> <pk-algo> <hash-algo> <class> [<primary-fpr>]
            "VALIDSIG" => {
                let record = current.get_or_insert_with(SignatureInfo::default);
                let fpr = fields.next().map(str::to_owned);
                let _date = fields.next();
                record.created = fields.next().and_then(epoch);
                record.expires = fields.next().and_then(epoch);
                let _version = fields.next();
                let _reserved = fields.next();
                record.pubkey_algorithm = fields.next().map(pubkey_algorithm_name);
                record.hash_algorithm = fields.next().map(hash_algorithm_name);
                let _class = fields.next();
                record.primary_fingerprint =
                    fields.next().map(str::to_owned).or_else(|| fpr.clone());
                record.fingerprint = fpr;
            }
            // ERRSIG <keyid> <pk-algo> <hash-algo> <class> <epoch> <rc> <fpr>
            "ERRSIG" => {
                let record = current.get_or_insert_with(SignatureInfo::default);
                let _keyid = fields.next();
                record.pubkey_algorithm = fields.next().map(pubkey_algorithm_name);
                record.hash_algorithm = fields.next().map(hash_algorithm_name);
                let _class = fields.next();
                record.created = fields.next().and_then(epoch);
                let _rc = fields.next();
                record.fingerprint = fields.next().filter(|f| *f != "-").map(str::to_owned);
            }
            "NO_PUBKEY" => {
                current
                    .get_or_insert_with(SignatureInfo::default)
                    .key_missing = true;
            }
            "KEYEXPIRED" => {
                let record = current.get_or_insert_with(SignatureInfo::default);
                record.key_expires = fields.next().and_then(epoch);
            }
            _ => {}
        }
    }
    if let Some(record) = current.take() {
        records.push(record);
    }
    records
}

/// Parses a status-line epoch field. The value zero reads as absent.
fn epoch(field: &str) -> Option<u64> {
    match field.parse::<u64>() {
        Ok(0) | Err(_) => None,
        Ok(secs) => Some(secs),
    }
}

/// Returns the OpenPGP public-key algorithm name for a status-line algorithm
/// id.
fn pubkey_algorithm_name(id: &str) -> String {
    match id {
        "1" | "2" | "3" => "RSA".to_owned(),
        "17" => "DSA".to_owned(),
        "18" => "ECDH".to_owned(),
        "19" => "ECDSA".to_owned(),
        "22" => "EdDSA".to_owned(),
        "27" => "Ed25519".to_owned(),
        "28" => "Ed448".to_owned(),
        other => other.to_owned(),
    }
}

/// Returns the OpenPGP digest algorithm name for a status-line algorithm id.
fn hash_algorithm_name(id: &str) -> String {
    match id {
        "1" => "MD5".to_owned(),
        "2" => "SHA1".to_owned(),
        "3" => "RIPEMD160".to_owned(),
        "8" => "SHA256".to_owned(),
        "9" => "SHA384".to_owned(),
        "10" => "SHA512".to_owned(),
        "11" => "SHA224".to_owned(),
        other => other.to_owned(),
    }
}

/// Splits an OpenPGP user id into name and email.
///
/// The trailing `<address>` is the email, and the text before it is the name.
fn split_uid(uid: &str) -> (Option<String>, Option<String>) {
    let non_empty = |s: &str| {
        let s = s.trim();
        (!s.is_empty()).then(|| s.to_owned())
    };
    if let Some(start) = uid.rfind('<')
        && let Some(end) = uid.rfind('>')
        && end > start
    {
        (non_empty(&uid[..start]), non_empty(&uid[start + 1..end]))
    } else {
        (non_empty(uid), None)
    }
}

/// Returns the records that the engine reports over the public path.
///
/// The keyring blobs load into a verifier, and the async `Verifier::verify`
/// gives the answer.
fn port_records(keyrings: &[&[u8]], blobs: &[&[u8]], payload: &[u8]) -> Vec<SignatureInfo> {
    let verifier = GpgVerifier::from_keyring_bytes(keyrings).expect("the keyrings load");
    let blobs: Vec<Vec<u8>> = blobs.iter().map(|blob| blob.to_vec()).collect();
    block_on(verifier.verify(payload, &blobs))
        .expect("the blobs are within the input caps")
        .signatures
}

/// Renders each field of one record as text.
///
/// The comparison then treats two records as one value, and a difference names
/// its field.
fn summary(record: &SignatureInfo) -> String {
    format!(
        "valid={}\nexpired={}\nrevoked={}\nkey_missing={}\nfingerprint={:?}\n\
         primary_fingerprint={:?}\ncreated={:?}\nexpires={:?}\nkey_expires={:?}\n\
         pubkey_algorithm={:?}\nhash_algorithm={:?}\nuser_name={:?}\nuser_email={:?}",
        record.valid,
        record.expired,
        record.revoked,
        record.key_missing,
        record.fingerprint,
        record.primary_fingerprint,
        record.created,
        record.expires,
        record.key_expires,
        record.pubkey_algorithm,
        record.hash_algorithm,
        record.user_name,
        record.user_email,
    )
}

/// Asserts that one record states the same as `gpgv` about the same signature,
/// field by field, with the verdict.
fn assert_agrees(label: &str, port: &SignatureInfo, reference: &SignatureInfo) {
    assert_eq!(
        summary(port),
        summary(reference),
        "{label}: the engine and gpgv report different fields",
    );
}

/// Asserts that one record states the same as `gpgv` about the same signature,
/// except for the two key fingerprints.
///
/// The two references differ on these two fields if the issuer resolves and the
/// cryptography fails. `gpgv` writes `BADSIG <keyid> <uid>`, which names the
/// issuer by eight bytes. The field holds a full fingerprint, so
/// [`gpgv_records`] ignores that key id, and the reference record states
/// neither fingerprint.
///
/// The `ostree` command, version 2026.1, names both keys in its output for such
/// a signature. For a signature by a subkey, it writes `key ID <subkey-key-id>`
/// with the key id of the subkey. Under that line it writes
/// `Primary key ID <primary-key-id>`. For a signature by the primary key, it
/// writes the same pair with the primary key in both places.
///
/// The report that a user reads is the oracle here, so the engine states both
/// keys. The creation time and the algorithm stay absent. `gpgv` states neither
/// on this path, and the engine states neither. The `ostree` command writes the
/// Unix epoch and `[unknown name]` in their places.
fn assert_agrees_but_fingerprints(label: &str, port: &SignatureInfo, reference: &SignatureInfo) {
    let mut port = port.clone();
    port.fingerprint = reference.fingerprint.clone();
    port.primary_fingerprint = reference.primary_fingerprint.clone();
    assert_agrees(label, &port, reference);
}

/// Puts one cell through both engines and asserts that they agree record for
/// record.
fn assert_cell_agrees(
    label: &str,
    home: &Home,
    keyring: &[u8],
    blob: &[u8],
    payload: &[u8],
) -> Vec<SignatureInfo> {
    let port = port_records(&[keyring], &[blob], payload);
    let reference = home.gpgv_records(keyring, blob, payload);
    assert_eq!(
        port.len(),
        reference.len(),
        "{label}: the engine reports {} records where gpgv reports {}",
        port.len(),
        reference.len(),
    );
    for (index, (port, reference)) in port.iter().zip(&reference).enumerate() {
        assert_agrees(&format!("{label}, record {index}"), port, reference);
    }
    port
}

/// The verdict matrix: the shapes that a stored blob and a trusted certificate
/// take. Each shape goes through both engines over the public path.
#[test]
fn the_agreement_matrix_agrees_with_gpgv() {
    if !tools_available() {
        return;
    }
    let tmp = TmpDir::new("verify-gpg-matrix");
    let base = tmp.path();
    let trusted = Home::eddsa(base, "trusted", "Trusted <trusted@ostrya.example>");
    let stranger = Home::eddsa(base, "stranger", "Stranger <stranger@ostrya.example>");
    let keyring = trusted.keyring();
    let good = trusted.sign(&trusted.primary, PAYLOAD, &[]);

    // A signature by the primary key over the payload that it signed.
    let records = assert_cell_agrees("a good signature", &trusted, &keyring, &good, PAYLOAD);
    assert!(records[0].valid, "the good signature is not valid");

    // The same signature against another payload. On this path the engine names
    // the resolved signing key and its certificate, and the reference names
    // neither. `assert_agrees_but_fingerprints` declares this difference. The
    // primary key signed here, so both fields name it.
    let port = port_records(&[&keyring], &[&good], OTHER_PAYLOAD);
    let reference = trusted.gpgv_records(&keyring, &good, OTHER_PAYLOAD);
    assert_eq!(port.len(), 1);
    assert_eq!(reference.len(), 1);
    assert_agrees_but_fingerprints("a changed payload", &port[0], &reference[0]);
    assert!(!port[0].valid);
    assert_eq!(port[0].fingerprint.as_deref(), Some(&*trusted.primary));
    assert_eq!(
        port[0].primary_fingerprint.as_deref(),
        Some(&*trusted.primary)
    );
    assert_eq!(reference[0].fingerprint, None);
    assert_eq!(reference[0].primary_fingerprint, None);

    // A signature whose issuer is in no loaded certificate.
    let foreign = stranger.sign(&stranger.primary, PAYLOAD, &[]);
    let records = assert_cell_agrees("an untrusted issuer", &trusted, &keyring, &foreign, PAYLOAD);
    assert!(records[0].key_missing && !records[0].valid);

    // One blob that holds two signature packets, one from each issuer.
    let mut two = good.clone();
    two.extend_from_slice(&foreign);
    let records = assert_cell_agrees("a multi-signature blob", &trusted, &keyring, &two, PAYLOAD);
    assert_eq!(records.len(), 2);
    assert!(records[0].valid && records[1].key_missing);

    // If the parser reads no whole signature packet out of a blob, the engine
    // still reports one record. The record count follows the count of stored
    // blobs. `gpgv` reports no record for either blob, so the comparison uses
    // the count that the engine owns and the verdict.
    for (label, blob) in [
        ("a truncated blob", good[..good.len() / 2].to_vec()),
        ("an empty blob", Vec::new()),
    ] {
        let records = port_records(&[&keyring], &[&blob], PAYLOAD);
        assert_eq!(records.len(), 1, "{label}: the record count");
        assert!(!records[0].valid, "{label}: reported a valid signature");
        assert!(
            trusted.gpgv_records(&keyring, &blob, PAYLOAD).is_empty(),
            "{label}: gpgv reported a record",
        );
    }

    // A signing subkey with a cross-certification by the primary key speaks for
    // its certificate. The report names the subkey and the certificate
    // separately.
    let subkey_home = Home::eddsa(base, "subkey", "Subkey <subkey@ostrya.example>");
    let subkey = subkey_home.add_signing_subkey();
    let subkey_ring = subkey_home.keyring();
    let subkey_blob = subkey_home.sign(&subkey, PAYLOAD, &[]);
    let records = assert_cell_agrees(
        "a subkey signature",
        &subkey_home,
        &subkey_ring,
        &subkey_blob,
        PAYLOAD,
    );
    assert!(records[0].valid);
    assert_eq!(records[0].fingerprint.as_deref(), Some(subkey.as_str()));
    assert_eq!(
        records[0].primary_fingerprint.as_deref(),
        Some(subkey_home.primary.as_str()),
    );

    // A key past its own lifetime. The home uses the faked clock, so the key is
    // live when it makes the signature. `gpgv` reads the real clock.
    let expired_home = Home::expiring(base, "expired", "Expired <expired@ostrya.example>", "1d");
    let expired_ring = expired_home.keyring();
    let expired_blob = expired_home.sign(&expired_home.primary, PAYLOAD, &[]);
    let records = assert_cell_agrees(
        "an expired key",
        &expired_home,
        &expired_ring,
        &expired_blob,
        PAYLOAD,
    );
    assert!(records[0].expired && !records[0].valid);
    assert!(records[0].key_expires.is_some());

    // A revoked primary key.
    let revoked_home = Home::eddsa(base, "revoked", "Revoked <revoked@ostrya.example>");
    let revoked_blob = revoked_home.sign(&revoked_home.primary, PAYLOAD, &[]);
    revoked_home.revoke_primary();
    let records = assert_cell_agrees(
        "a revoked key",
        &revoked_home,
        &revoked_home.keyring(),
        &revoked_blob,
        PAYLOAD,
    );
    assert!(records[0].revoked && !records[0].valid);
}

/// The public-key algorithm axis, and the one divergence that the cryptography
/// under the engine causes.
#[test]
fn key_algorithms_agree_with_gpgv() {
    if !tools_available() {
        return;
    }
    let tmp = TmpDir::new("verify-gpg-algorithms");
    let base = tmp.path();

    // Public-key algorithm id 22, which the report names `EdDSA`.
    let eddsa = Home::eddsa(base, "eddsa", "EdDSA <eddsa@ostrya.example>");
    let eddsa_ring = eddsa.keyring();
    let blob = eddsa.sign(&eddsa.primary, PAYLOAD, &[]);
    let records = assert_cell_agrees("an EdDSA key", &eddsa, &eddsa_ring, &blob, PAYLOAD);
    assert!(records[0].valid);
    assert_eq!(records[0].pubkey_algorithm.as_deref(), Some("EdDSA"));

    // Public-key algorithm id 1, over each digest that `gpg` 2.4.9 offers and
    // the policy allows.
    let rsa = Home::rsa(base, "rsa", "RSA <rsa@ostrya.example>");
    let rsa_ring = rsa.keyring();
    for (digest, name) in [
        ("SHA1", "SHA1"),
        ("SHA224", "SHA224"),
        ("SHA256", "SHA256"),
        ("SHA384", "SHA384"),
        ("SHA512", "SHA512"),
    ] {
        let blob = rsa.sign(&rsa.primary, PAYLOAD, &["--digest-algo", digest]);
        let label = format!("an RSA key over {digest}");
        let records = assert_cell_agrees(&label, &rsa, &rsa_ring, &blob, PAYLOAD);
        assert!(records[0].valid, "{label}: not valid");
        assert_eq!(records[0].pubkey_algorithm.as_deref(), Some("RSA"));
        assert_eq!(records[0].hash_algorithm.as_deref(), Some(name));
    }

    // The digest policy: both engines refuse MD5. The refusal is a rule of this
    // engine, because the cryptography under it verifies an MD5 signature.
    let md5 = rsa.sign(&rsa.primary, PAYLOAD, &["--digest-algo", "MD5"]);
    let records = assert_cell_agrees("an MD5 signature", &rsa, &rsa_ring, &md5, PAYLOAD);
    assert!(!records[0].valid, "{DIVERGENCE_DIGEST_POLICY}");
    assert_eq!(records[0].hash_algorithm.as_deref(), Some("MD5"));

    // Declared divergence: an EdDSA-legacy key with a digest of less than 256
    // bits. `gpgv` reports `GOODSIG`. The engine reports the signature as not
    // valid, because rPGP refuses the digest before it verifies.
    for digest in ["SHA1", "SHA224"] {
        let blob = eddsa.sign(&eddsa.primary, PAYLOAD, &["--digest-algo", digest]);
        let port = port_records(&[&eddsa_ring], &[&blob], PAYLOAD);
        let reference = eddsa.gpgv_records(&eddsa_ring, &blob, PAYLOAD);
        assert_eq!(port.len(), 1);
        assert_eq!(reference.len(), 1);
        assert!(
            reference[0].valid,
            "{DIVERGENCE_ED25519_DIGEST}: gpgv no longer reports {digest} as good, \
             so the divergence is gone and this case states the wrong thing",
        );
        assert!(
            !port[0].valid,
            "{DIVERGENCE_ED25519_DIGEST}: the engine now accepts {digest}, so the \
             divergence is gone and this case states the wrong thing",
        );
        // The record has the shape of a signature that does not verify. It
        // holds the resolved signing key, its certificate, and the user id of
        // the certificate. It holds no field that the signature states about
        // itself, because the engine did not verify these fields. The primary
        // key signed here, so both fingerprints name it. Both agree with the
        // reference, which reads them from the `VALIDSIG` line that comes with
        // its `GOODSIG`. The reference names the creation time and the two
        // algorithms, so the divergence covers those fields.
        assert_eq!(port[0].user_email, reference[0].user_email);
        assert!(!port[0].key_missing && !port[0].expired && !port[0].revoked);
        assert_eq!(port[0].fingerprint.as_deref(), Some(&*eddsa.primary));
        assert_eq!(port[0].fingerprint, reference[0].fingerprint);
        assert_eq!(
            port[0].primary_fingerprint.as_deref(),
            Some(&*eddsa.primary)
        );
        assert_eq!(
            port[0].primary_fingerprint,
            reference[0].primary_fingerprint
        );
        assert_eq!(port[0].created, None);
        assert_eq!(port[0].pubkey_algorithm, None);
        assert_eq!(port[0].hash_algorithm, None);
        assert_eq!(reference[0].pubkey_algorithm.as_deref(), Some("EdDSA"));
        assert_eq!(reference[0].hash_algorithm.as_deref(), Some(digest));
    }

    // Declared divergence: no fixture on this reference carries public-key
    // algorithm id 27. `gpg` lists the algorithms that it supports, and
    // `Ed25519` is not in the list.
    let out = Command::new("gpg").arg("--version").output().unwrap();
    let version = String::from_utf8_lossy(&out.stdout);
    let pubkeys = version
        .lines()
        .find_map(|line| line.trim().strip_prefix("Pubkey: "))
        .expect("gpg --version states its public-key algorithms");
    assert!(
        !pubkeys.split(", ").any(|name| name == "Ed25519"),
        "{DIVERGENCE_ED25519_ALGORITHM}: gpg now lists Ed25519 among `{pubkeys}`, \
         so a reference fixture for id 27 can be built and this matrix should \
         carry a cell for it",
    );
}

/// The keyring encodings and certificate counts in which a trusted set arrives.
#[test]
fn keyring_forms_agree_with_gpgv() {
    if !tools_available() {
        return;
    }
    let tmp = TmpDir::new("verify-gpg-keyrings");
    let base = tmp.path();
    let first = Home::eddsa(base, "first", "First <first@ostrya.example>");
    let second = Home::eddsa(base, "second", "Second <second@ostrya.example>");
    let first_blob = first.sign(&first.primary, PAYLOAD, &[]);
    let second_blob = second.sign(&second.primary, PAYLOAD, &[]);

    // An armored keyring gets the same verdict as the binary keyring that it
    // encodes. `gpgv` reads the binary form, so it is the reference for both.
    let binary = first.keyring();
    let armored = first.keyring_armored();
    let reference = first.gpgv_records(&binary, &first_blob, PAYLOAD);
    assert_eq!(reference.len(), 1);
    for (label, keyring) in [
        ("a binary keyring", &binary),
        ("an armored keyring", &armored),
    ] {
        let port = port_records(&[keyring], &[&first_blob], PAYLOAD);
        assert_eq!(port.len(), 1, "{label}: the record count");
        assert_agrees(label, &port[0], &reference[0]);
        assert!(port[0].valid, "{label}: not valid");
    }

    // One keyring with two certificates answers for a signature by either
    // certificate. Each record names the user id of its own certificate.
    let mut both = binary.clone();
    both.extend_from_slice(&second.keyring());
    for (label, home, blob, email) in [
        (
            "the first certificate",
            &first,
            &first_blob,
            "first@ostrya.example",
        ),
        (
            "the second certificate",
            &second,
            &second_blob,
            "second@ostrya.example",
        ),
    ] {
        let records = assert_cell_agrees(
            &format!("a two-certificate keyring over {label}"),
            home,
            &both,
            blob,
            PAYLOAD,
        );
        assert!(records[0].valid, "{label}: not valid");
        assert_eq!(records[0].user_email.as_deref(), Some(email));
    }

    // The two certificates as two keyring blobs give the same trusted set as
    // the one concatenated blob.
    let second_ring = second.keyring();
    let records = port_records(&[&binary, &second_ring], &[&second_blob], PAYLOAD);
    assert_eq!(records.len(), 1);
    assert!(records[0].valid, "two keyring blobs did not merge");
}

/// The engine refuses a key with two certificates, one of them revoked, in each
/// order and in one keyring blob or in two.
///
/// Two certificates for one key reach the trusted set on ordinary paths:
///
/// - the `<remote>.trustedkeys.gpg` file of a repository next to the global
///   trusted directory
/// - two `gpgkeypath` entries
/// - one keyring file with two exports of one key
///
/// If one copy carries a revocation and the other does not, the verdict reads
/// both.
///
/// This is [`DIVERGENCE_DUPLICATE_CERTIFICATE`], so the case does not compare
/// the verdict over the two-certificate keyrings. Each certificate alone is a
/// control on which the two engines agree. The case states the answer of the
/// reference for each order. It limits the divergence to the two verdict fields
/// and compares each other field that the reference names.
#[test]
fn a_duplicate_certificate_carries_its_revocation() {
    if !tools_available() {
        return;
    }
    let tmp = TmpDir::new("verify-gpg-duplicate");
    let base = tmp.path();
    let home = Home::eddsa(base, "duplicate", "Dup <dup@ostrya.example>");
    let blob = home.sign(&home.primary, PAYLOAD, &[]);
    let unrevoked = home.keyring();
    home.revoke_primary();
    let revoked = home.keyring();

    // Each certificate alone, on which both engines agree.
    let records = assert_cell_agrees(
        "one unrevoked certificate",
        &home,
        &unrevoked,
        &blob,
        PAYLOAD,
    );
    assert!(records[0].valid && !records[0].revoked);
    let records = assert_cell_agrees("one revoked certificate", &home, &revoked, &blob, PAYLOAD);
    assert!(records[0].revoked && !records[0].valid);

    for (label, first, second, reference_revoked) in [
        ("the revocation second", &unrevoked, &revoked, false),
        ("the revocation first", &revoked, &unrevoked, true),
    ] {
        let mut keyring = first.clone();
        keyring.extend_from_slice(second);
        let port = port_records(&[&keyring], &[&blob], PAYLOAD);
        assert_eq!(port.len(), 1, "{label}: the record count");
        // The two orders together show that both certificates reach the trusted
        // set, so the verdict reads both of them and the parse drops neither.
        // If the parse keeps only the leading certificate, the second order
        // fails. If it keeps only the trailing certificate, the first order
        // fails.
        assert!(port[0].revoked, "{label}: the revocation was not read");
        assert!(!port[0].valid, "{label}: a revoked key reported valid");

        // The same two certificates as two keyring blobs give the same trusted
        // set and the same verdict.
        let split = port_records(&[first, second], &[&blob], PAYLOAD);
        assert_eq!(split.len(), 1, "{label}: the record count over two blobs");
        assert_eq!(
            summary(&split[0]),
            summary(&port[0]),
            "{label}: two keyring blobs and one concatenated blob part",
        );

        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(reference.len(), 1, "{label}: the reference record count");
        assert_eq!(
            reference[0].revoked, reference_revoked,
            "{DIVERGENCE_DUPLICATE_CERTIFICATE}: gpgv no longer answers on the \
             load order, so this case states the wrong thing about the reference",
        );
        // The divergence is limited to the verdict. If the two fields that the
        // engine sets by its own rule are set aside, each other field agrees.
        let mut adjusted = reference[0].clone();
        adjusted.revoked = true;
        adjusted.valid = false;
        assert_agrees(label, &port[0], &adjusted);
    }
}

/// The user id that the report names for a certificate with several user ids.
///
/// The rule takes the primary user id first, then the newest self-signed user
/// id. In each case, the rule takes only user ids that are not revoked.
#[test]
fn multi_uid_certificates_agree_with_gpgv() {
    if !tools_available() {
        return;
    }
    const ALPHA: &str = "Alpha <alpha@ostrya.example>";
    const BRAVO: &str = "Bravo <bravo@ostrya.example>";
    const CHARLIE: &str = "Charlie <charlie@ostrya.example>";
    let tmp = TmpDir::new("verify-gpg-uids");
    let base = tmp.path();

    // No user id has the primary mark, so the newest self-signed one answers.
    // `gpg` writes a new self-signature for each user id. The clock has a
    // resolution of one second, so each addition waits for the next second.
    let newest = Home::eddsa(base, "newest", ALPHA);
    next_second();
    newest.add_uid(BRAVO);
    next_second();
    newest.add_uid(CHARLIE);
    let blob = newest.sign(&newest.primary, PAYLOAD, &[]);
    let records = assert_cell_agrees(
        "a multi-uid certificate with no primary user id",
        &newest,
        &newest.keyring(),
        &blob,
        PAYLOAD,
    );
    assert_eq!(
        records[0].user_email.as_deref(),
        Some("charlie@ostrya.example")
    );

    // A marked primary user id answers also when it is not the newest.
    let marked = Home::eddsa(base, "marked", ALPHA);
    next_second();
    marked.add_uid(BRAVO);
    marked.set_primary_uid(ALPHA);
    next_second();
    marked.add_uid(CHARLIE);
    let blob = marked.sign(&marked.primary, PAYLOAD, &[]);
    let records = assert_cell_agrees(
        "a multi-uid certificate with a marked primary user id",
        &marked,
        &marked.keyring(),
        &blob,
        PAYLOAD,
    );
    assert_eq!(
        records[0].user_email.as_deref(),
        Some("alpha@ostrya.example")
    );

    // The report passes over a revoked user id, and its primary mark has no
    // effect. The verdict does not change, because a user id revocation revokes
    // no key.
    let revoked = Home::eddsa(base, "revoked-uid", ALPHA);
    next_second();
    revoked.add_uid(BRAVO);
    revoked.set_primary_uid(ALPHA);
    revoked.revoke_uid(ALPHA);
    let blob = revoked.sign(&revoked.primary, PAYLOAD, &[]);
    let records = assert_cell_agrees(
        "a multi-uid certificate with a revoked primary user id",
        &revoked,
        &revoked.keyring(),
        &blob,
        PAYLOAD,
    );
    assert_eq!(
        records[0].user_email.as_deref(),
        Some("bravo@ostrya.example")
    );
    assert!(records[0].valid && !records[0].revoked);
}

/// A certification that the key of the certificate did not make does not choose
/// the user id of the report.
///
/// The fixture holds two user ids and marks neither as primary. The user ids
/// rank by their self-signatures, and the self-signature of Bravo is newer than
/// that of Alpha. A second key then certifies Alpha alone, at a later time.
/// Alpha then carries the newest signature of any kind, and Bravo carries the
/// newest self-signature.
///
/// `gpgv` names Bravo. A certification that does not verify under the key of
/// the certificate is outside the ranking.
///
/// The `gpg` binary makes the full fixture. The home of the stranger imports
/// the certificate, certifies one user id on it with `--quick-sign-key`, and
/// exports it again. The certification is a real signature packet, and no
/// packet is spliced by hand.
#[test]
fn a_third_party_certification_does_not_choose_the_reported_user_id() {
    if !tools_available() {
        return;
    }
    const ALPHA: &str = "Alpha <alpha@ostrya.example>";
    const BRAVO: &str = "Bravo <bravo@ostrya.example>";
    let tmp = TmpDir::new("verify-gpg-third-party-uid");
    let base = tmp.path();

    let home = Home::eddsa(base, "certified", ALPHA);
    next_second();
    home.add_uid(BRAVO);
    let plain = home.keyring();

    let stranger = Home::eddsa(base, "stranger", "Stranger <stranger@ostrya.example>");
    stranger.import(&plain);
    next_second();
    stranger.certify_uid(&home.primary, "alpha@ostrya.example");
    let keyring = stranger.export_key(&home.primary);
    // The certification states its issuer fingerprint in a hashed subpacket. If
    // the exported certificate contains the fingerprint of the stranger, it
    // carries a packet that the key of the stranger made.
    let issuer = from_hex(&stranger.primary);
    assert!(
        keyring.len() > plain.len() && keyring.windows(issuer.len()).any(|run| run == issuer),
        "the exported certificate carries no third-party certification",
    );

    let blob = home.sign(&home.primary, PAYLOAD, &[]);
    let records = assert_cell_agrees(
        "a user id carrying a newer third-party certification",
        &home,
        &keyring,
        &blob,
        PAYLOAD,
    );
    assert_eq!(
        records[0].user_email.as_deref(),
        Some("bravo@ostrya.example")
    );
    assert!(records[0].valid);
}

/// A primary mark on a self-signature that does not verify does not choose the
/// user id of the report.
///
/// The fixture marks Alpha as primary and then adds Bravo. Alpha wins on its
/// mark alone, and Bravo carries the newest self-signature. The case then flips
/// one byte inside the signature of Alpha. That signature does not verify after
/// the flip, and the primary-user-id subpacket stays in its position.
///
/// `gpgv` names Alpha over the intact certificate and Bravo over the spliced
/// certificate. A mark on a certification that does not verify marks nothing.
///
/// The case finds the splice position by a read of the exported certificate,
/// and it uses no fixed offset from an earlier run. `gpg --export` writes the
/// marked user id first, so the signature packet of Alpha ends where the Bravo
/// user id packet starts. The last byte of that packet is in the trailing MPI
/// of the signature, after each subpacket.
///
/// Before the case compares the two reports, it checks that the splice landed
/// and that the mark did not change. It also puts the intact certificate
/// through the same comparison as a control.
///
/// `gpg` writes the full certificate. The splice changes the exported bytes
/// after the export, because no `gpg` option makes a signature fail to verify.
#[test]
fn an_unverified_primary_mark_does_not_choose_the_reported_user_id() {
    if !tools_available() {
        return;
    }
    const ALPHA: &str = "Alpha <alpha@ostrya.example>";
    const BRAVO: &str = "Bravo <bravo@ostrya.example>";
    /// A primary-user-id subpacket with the value true: subpacket length 2,
    /// subpacket type 25, value 1.
    const MARK: [u8; 3] = [0x02, 0x19, 0x01];
    /// A user id packet header for a body of less than 192 bytes: the
    /// old-format tag byte for tag 13, then one length byte.
    const UID_TAG: u8 = 0xb4;
    let tmp = TmpDir::new("verify-gpg-unverified-primary");
    let base = tmp.path();

    let home = Home::eddsa(base, "marked", ALPHA);
    next_second();
    home.set_primary_uid(ALPHA);
    next_second();
    home.add_uid(BRAVO);
    let intact = home.keyring();
    let blob = home.sign(&home.primary, PAYLOAD, &[]);

    let alpha_at = find_once(&intact, ALPHA.as_bytes());
    let bravo_at = find_once(&intact, BRAVO.as_bytes());
    assert!(
        alpha_at < bravo_at,
        "the marked user id is not written first"
    );
    assert_eq!(
        intact[bravo_at - 2..bravo_at],
        [UID_TAG, BRAVO.len() as u8],
        "the Bravo user id packet does not open two bytes before its text",
    );
    let at = bravo_at - 3;
    let mark_at = alpha_at
        + intact[alpha_at..bravo_at]
            .windows(MARK.len())
            .position(|run| run == MARK)
            .expect("Alpha's signature packet carries the primary mark");
    assert!(
        mark_at + MARK.len() <= at,
        "the byte to splice stands inside the primary mark",
    );
    let mut spliced = intact.clone();
    spliced[at] ^= 0xff;
    assert_eq!(
        spliced.iter().zip(&intact).filter(|(a, b)| a != b).count(),
        1,
        "the splice changed more than the one byte",
    );
    assert_eq!(
        spliced[mark_at..mark_at + MARK.len()],
        MARK,
        "the splice moved the primary mark",
    );
    // `gpg` reports a bad signature on the spliced certificate and none on the
    // intact certificate. This shows that the one flipped byte stops the
    // verification of the self-signature of Alpha.
    assert!(
        home.import_diagnostics("spliced", &spliced)
            .contains("bad signature"),
        "the splice left every signature on the certificate verifying",
    );
    assert!(
        !home
            .import_diagnostics("intact", &intact)
            .contains("bad signature"),
        "the intact certificate carries a signature that does not verify",
    );

    // The control: the mark answers over the intact certificate. Without the
    // mark, the ranking names Bravo.
    let records = assert_cell_agrees(
        "a marked primary user id under a self-signature that verifies",
        &home,
        &intact,
        &blob,
        PAYLOAD,
    );
    assert_eq!(
        records[0].user_email.as_deref(),
        Some("alpha@ostrya.example")
    );
    let records = assert_cell_agrees(
        "a primary mark under a self-signature that does not verify",
        &home,
        &spliced,
        &blob,
        PAYLOAD,
    );
    assert_eq!(
        records[0].user_email.as_deref(),
        Some("bravo@ostrya.example")
    );
    assert!(records[0].valid);
}

/// Returns the one offset of `needle` in `haystack`.
fn find_once(haystack: &[u8], needle: &[u8]) -> usize {
    let mut found = haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, run)| *run == needle)
        .map(|(at, _)| at);
    let at = found.next().expect("the needle stands in the haystack");
    assert!(found.next().is_none(), "the needle stands more than once");
    at
}

/// Returns the bytes of an uppercase-hex fingerprint.
fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Waits for the wall clock to reach the next second.
///
/// The next self-signature that `gpg` makes then has a later creation time than
/// the one before it.
fn next_second() {
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > start {
            return;
        }
    }
}

/// A signature by a signing subkey verifies against a legacy GnuPG keyring.
///
/// A legacy keyring carries a Trust packet after the primary key packet and
/// after each user id and signature packet. The subkey packet comes after the
/// Trust packet of the primary key. This case checks how the certificate parser
/// reaches the subkey packet over the tag runs of such a keyring.
///
/// Two keyrings hold the key here, and `gpgv` reads each of them as the
/// reference:
///
/// - the keyring that GnuPG writes, which carries the Trust packets. The import
///   of the `ostree` command leaves this keyring at the repository root.
/// - the keyring that `Repo::gpg_import_keys` writes, which carries none.
#[test]
fn a_subkey_signature_over_a_trust_packet_keyring_agrees_with_gpgv() {
    if !tools_available() {
        return;
    }
    let tmp = TmpDir::new("verify-gpg-trust-subkey");
    let base = tmp.path();
    let home = Home::eddsa(base, "trust", "Trust <trust@ostrya.example>");
    let subkey = home.add_signing_subkey();
    let exported = home.keyring();
    let legacy = gnupg_keyring(&home);
    let imported = imported_keyring(base, &exported);

    // The fixture has the shape under test: the GnuPG keyring carries Trust
    // packets, and the export and the import carry none.
    assert!(
        lists_a_trust_packet(&home, &legacy),
        "the GnuPG keyring carries no Trust packet",
    );
    assert!(
        !lists_a_trust_packet(&home, &exported),
        "the exported keyring carries a Trust packet",
    );
    assert!(
        !lists_a_trust_packet(&home, &imported),
        "the imported keyring carries a Trust packet",
    );

    let blob = home.sign(&subkey, PAYLOAD, &[]);
    for (label, keyring) in [
        ("a GnuPG keyring over a subkey signature", &legacy),
        ("an imported keyring over a subkey signature", &imported),
    ] {
        let records = assert_cell_agrees(label, &home, keyring, &blob, PAYLOAD);
        assert!(records[0].valid, "{label}: not valid");
        assert!(!records[0].key_missing, "{label}: the subkey is missing");
        assert_eq!(records[0].fingerprint.as_deref(), Some(subkey.as_str()));
        assert_eq!(
            records[0].primary_fingerprint.as_deref(),
            Some(home.primary.as_str())
        );
    }
}

/// A primary-key signature over a legacy GnuPG keyring reports the user id of
/// the certificate.
///
/// The user id packet comes after the Trust packet of the primary key, so the
/// parser reaches it over the same tag runs. The keyring that the import of
/// ostrya writes reports the same user id.
#[test]
fn a_trust_packet_keyring_reports_the_user_id() {
    if !tools_available() {
        return;
    }
    let tmp = TmpDir::new("verify-gpg-trust-uid");
    let base = tmp.path();
    let home = Home::eddsa(base, "trust", "Trust <trust@ostrya.example>");
    let legacy = gnupg_keyring(&home);
    let imported = imported_keyring(base, &home.keyring());
    assert!(
        lists_a_trust_packet(&home, &legacy),
        "the GnuPG keyring carries no Trust packet",
    );

    let blob = home.sign(&home.primary, PAYLOAD, &[]);
    for (label, keyring) in [
        ("a GnuPG keyring over a primary-key signature", &legacy),
        (
            "an imported keyring over a primary-key signature",
            &imported,
        ),
    ] {
        let records = assert_cell_agrees(label, &home, keyring, &blob, PAYLOAD);
        assert!(records[0].valid, "{label}: not valid");
        assert_eq!(records[0].user_name.as_deref(), Some("Trust"));
        assert_eq!(
            records[0].user_email.as_deref(),
            Some("trust@ostrya.example")
        );
    }
}

/// Returns the keyring that GnuPG writes for the keys of `home`.
///
/// This keyring carries a Trust packet after the primary key packet, after each
/// user id packet, and after each signature packet.
///
/// If the keyring file exists, `gpg` writes a legacy keyring. If `gpg` creates
/// the file itself, it writes a keybox. For this reason, the import runs over
/// an empty keyring file in a separate home.
fn gnupg_keyring(home: &Home) -> Vec<u8> {
    use std::os::unix::fs::DirBuilderExt;

    let source = home.write("gnupg-source.gpg", &home.keyring());
    let dir = home.dir.join("gnupg-ring");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let ring = dir.join("ring.gpg");
    std::fs::write(&ring, b"").unwrap();
    let status = Command::new("gpg")
        .arg("--homedir")
        .arg(&dir)
        .arg("--batch")
        .arg("--no-default-keyring")
        .arg("--keyring")
        .arg(&ring)
        .arg("--import")
        .arg(&source)
        .status()
        .unwrap();
    common::remove_gnupg_sockets(&dir);
    assert!(status.success(), "gpg --import into a keyring failed");
    std::fs::read(&ring).unwrap()
}

/// Returns the keyring that `Repo::gpg_import_keys` writes for `keys`.
///
/// The function reads it from the repository root, where `remote gpg-import`
/// leaves it.
fn imported_keyring(base: &Path, keys: &[u8]) -> Vec<u8> {
    let root = base.join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let count = repo.gpg_import_keys("origin", keys, &[]).await.unwrap();
        assert_eq!(count, 1, "the import added no key");
    });
    std::fs::read(root.join("origin.trustedkeys.gpg")).unwrap()
}

/// Returns `true` if `gpg --list-packets` reports a Trust packet in `keyring`.
fn lists_a_trust_packet(home: &Home, keyring: &[u8]) -> bool {
    let path = home.write("listed.gpg", keyring);
    let out = home.gpg().arg("--list-packets").arg(path).output().unwrap();
    assert!(out.status.success(), "gpg --list-packets failed");
    String::from_utf8_lossy(&out.stdout).contains("trust packet")
}

/// The number of leading bytes that the single-bit flips cover.
///
/// A keyring and a detached signature both carry their packet headers,
/// algorithm ids, and subpacket structure in the first bytes. A flip in these
/// bytes reaches the parser in addition to the cryptography.
const FLIP_PREFIX: usize = 64;

/// The number of calls to the panic hook of the corpus case.
///
/// The hook is global to the process, so the count includes a panic from any
/// thread while the hook is installed.
static CORPUS_PANICS: AtomicUsize = AtomicUsize::new(0);

/// A corpus of malformed input: keyrings and signature blobs made from the good
/// fixtures by truncation and by single-bit flips.
///
/// Three properties hold for each input.
///
/// The first property is that the call returns. A malformed keyring fails the
/// load or loads to a trusted set. A malformed blob gets a refusal by name or
/// reports records. The case puts each input through the load and the verify
/// call and reaches its end, which shows this property. No assertion states it.
///
/// The second property is that no input panics. The engine contains a panic
/// inside rPGP and converts it to an error. A panic in the parser then reads as
/// a refusal, and the assertions on the returned value ignore it.
///
/// The case counts the panic itself. A hook is installed over the two corpus
/// loops. For each call, the hook adds one to [`CORPUS_PANICS`] and calls the
/// previous hook, so a panic still writes its message. After the previous hook
/// is back, the case asserts that the count is zero.
///
/// The hook is global to the process. This binary runs its cases on several
/// threads, so the count covers each panic while the hook is installed. No case
/// in this binary carries `#[should_panic]`. A case that panics for another
/// reason fails the run by itself. In both cases, a count of more than zero
/// shows a defect.
///
/// If an assertion fails inside the corpus loops, the counting hook stays
/// installed, because [`std::panic::set_hook`] panics when a panicking thread
/// calls it. The case fails at that point. The installed hook still writes the
/// message of each later panic, and no later case reads the count.
///
/// The third property is that no altered input gets a valid verdict over a
/// payload that nothing signed. A change to the bytes cannot forge a signature,
/// so this property holds for each alteration. A caller depends on this
/// property.
///
/// Over the payload that the fixture signed, a valid verdict stays possible. A
/// keyring cut after its public-key packet keeps the trusted key intact. A bit
/// flip in the unhashed area of a signature keeps the signed material intact.
///
/// The case asserts that such an input reports only the key of the fixture. No
/// alteration makes the report name a key outside the trusted set.
#[test]
fn a_malformed_keyring_or_blob_never_reaches_a_valid_verdict() {
    if !tools_available() {
        return;
    }
    let tmp = TmpDir::new("verify-gpg-malformed");
    let base = tmp.path();
    let home = Home::eddsa(base, "corpus", "Corpus <corpus@ostrya.example>");
    let keyring = home.keyring();
    let blob = home.sign(&home.primary, PAYLOAD, &[]);

    // The good fixtures verify, so the later assertions state a property of the
    // altered bytes. They state nothing about the fixture.
    let records = port_records(&[&keyring], &[&blob], PAYLOAD);
    assert_eq!(records.len(), 1);
    assert!(records[0].valid, "the corpus fixture does not verify");

    let keyrings = corpus(&keyring, "the keyring");
    let blobs = corpus(&blob, "the blob");
    let keyring_inputs = keyrings.len();
    let blob_inputs = blobs.len();

    let stood = Arc::new(std::panic::take_hook());
    let counting = Arc::clone(&stood);
    std::panic::set_hook(Box::new(move |info| {
        CORPUS_PANICS.fetch_add(1, Ordering::Relaxed);
        (*counting)(info);
    }));

    for (label, altered) in &keyrings {
        assert_bounded(label, &[altered], &[&blob], &home.primary);
    }
    for (label, altered) in &blobs {
        assert_bounded(label, &[&keyring], &[altered], &home.primary);
    }

    // The previous hook goes back here, so the count covers only the corpus
    // run. The counting closure shares that hook, so it goes back inside a
    // closure that calls it through the `Arc`.
    std::panic::set_hook(Box::new(move |info| (*stood)(info)));
    let panics = CORPUS_PANICS.load(Ordering::Relaxed);
    assert_eq!(panics, 0, "the corpus panicked {panics} times");

    // The case asserts each count against its fixture length plus 64 bytes
    // times eight bits. The flip axis is written out here and is not read from
    // [`FLIP_PREFIX`]. If the fixture or the axis shrinks, this assertion
    // fails, and the case does not become vacuous.
    assert_eq!(
        keyring_inputs,
        keyring.len() + 64 * 8,
        "the corpus covered {keyring_inputs} keyrings",
    );
    assert_eq!(
        blob_inputs,
        blob.len() + 64 * 8,
        "the corpus covered {blob_inputs} blobs",
    );
    eprintln!("malformed corpus: {keyring_inputs} keyrings, {blob_inputs} signature blobs");
}

/// Returns each truncation of `bytes` and each single-bit flip over its first
/// [`FLIP_PREFIX`] bytes.
///
/// The truncations go one byte at a time, from zero bytes up to one byte less
/// than the full length.
fn corpus(bytes: &[u8], subject: &str) -> Vec<(String, Vec<u8>)> {
    let mut inputs = Vec::new();
    for length in 0..bytes.len() {
        inputs.push((
            format!("{subject} cut to {length} bytes"),
            bytes[..length].to_vec(),
        ));
    }
    for index in 0..bytes.len().min(FLIP_PREFIX) {
        for bit in 0..8u32 {
            let mut altered = bytes.to_vec();
            altered[index] ^= 1 << bit;
            inputs.push((
                format!("{subject} with byte {index} bit {bit} flipped"),
                altered,
            ));
        }
    }
    inputs
}

/// Asserts the two properties of the corpus on the value that each call returns
/// for one input pair.
///
/// `primary` is the fingerprint of the one key in the good fixtures, so a
/// record that reports valid must name it.
fn assert_bounded(label: &str, keyrings: &[&[u8]], blobs: &[&[u8]], primary: &str) {
    let owned: Vec<Vec<u8>> = blobs.iter().map(|blob| blob.to_vec()).collect();
    // Over a payload that nothing signed, no record is ever valid.
    if let Ok(verifier) = GpgVerifier::from_keyring_bytes(keyrings) {
        if let Ok(outcome) = block_on(verifier.verify(OTHER_PAYLOAD, &owned)) {
            assert!(
                !outcome.valid,
                "{label}: verified over a payload nothing signed",
            );
            for record in &outcome.signatures {
                assert!(
                    !record.valid,
                    "{label}: reported a valid signature over a payload nothing signed",
                );
            }
        }
        // Over the payload that the fixture signed, a valid record names the
        // key of the fixture and its certificate.
        if let Ok(outcome) = block_on(verifier.verify(PAYLOAD, &owned)) {
            for record in &outcome.signatures {
                if record.valid {
                    assert_eq!(
                        record.fingerprint.as_deref(),
                        Some(primary),
                        "{label}: a valid record names a key the trusted set does not hold",
                    );
                    assert_eq!(
                        record.primary_fingerprint.as_deref(),
                        Some(primary),
                        "{label}: a valid record names a certificate the trusted set \
                         does not hold",
                    );
                }
            }
        }
    }
}
