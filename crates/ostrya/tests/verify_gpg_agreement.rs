//! Differential agreement between the in-process GPG verify engine and
//! `gpgv`.
//!
//! Each case builds its fixtures with `gpg` in a private GnuPG home under the
//! test's scratch tree, puts the same keyring, signature blob, and payload
//! through [`GpgVerifier`] and through `gpgv`, and compares the two reports
//! field by field. `gpgv` writes its machine-readable status stream, which
//! [`gpgv_records`] reads into the same record shape the engine answers in.
//!
//! `gpg` builds the fixtures and `gpgv` is the reference, so both binaries are
//! required: a case skips itself and names the absent binary rather than
//! passing without a comparison. A harness that holds both binaries sets
//! [`common::REQUIRE_GNUPG`], which turns that skip into a failure.
//!
//! The engine's own unit tests state each policy rule against `gpgv` over the
//! internal entry point. These cases run the public path -- keyring loading,
//! the async `Verifier::verify`, and the blocking-pool hop -- and carry the
//! axes those rules do not reach: the key algorithm, the certificate's user id
//! set, the keyring encoding, the legacy keyring form that carries Trust
//! packets, and a corpus of malformed keyrings and blobs.
//!
//! Three divergences are declared here rather than compared, each with the
//! `gpgv` behavior it parts from:
//!
//! - an Ed25519 or EdDSA-legacy key with a digest under 256 bits
//!   ([`DIVERGENCE_ED25519_DIGEST`]);
//! - the digest policy, which is fixed here and configurable in GnuPG
//!   ([`DIVERGENCE_DIGEST_POLICY`]);
//! - public-key algorithm id 27, which this GnuPG build carries no support for
//!   ([`DIVERGENCE_ED25519_ALGORITHM`]).

#![cfg(feature = "verify-gpg")]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::TmpDir;
use ostrya::{CreateOptions, GpgVerifier, Repo, RepoMode, SignatureInfo, Verifier};
use ostrya_rt::block_on;

/// The payload every fixture signs.
const PAYLOAD: &[u8] = b"ostrya commit payload";
/// A payload no fixture signs, for the changed-payload case.
const OTHER_PAYLOAD: &[u8] = b"ostrya other payload";
/// The instant a faked-clock home stands at, 2025-01-01T00:00:00Z.
const FAKED_CLOCK: &str = "20250101T000000!";

/// rPGP holds an Ed25519 or an EdDSA-legacy verification to a digest of at
/// least 256 bits, so a SHA-1 or SHA-224 data signature by such a key verifies
/// against nothing. `gpgv` 2.4.9 reports `GOODSIG` for the same signature.
const DIVERGENCE_ED25519_DIGEST: &str = "an Ed25519 key with a digest under 256 bits";
/// The digest policy is this engine's own and is fixed: MD5 is refused and
/// SHA-1 is accepted. GnuPG's set is configurable and moves between versions
/// -- `gpgv --weak-digest SHA1` refuses a SHA-1 signature this engine accepts,
/// and `gpg --verify --allow-weak-digest-algos` accepts an MD5 signature this
/// engine refuses.
const DIVERGENCE_DIGEST_POLICY: &str = "the digest policy is fixed here and configurable in GnuPG";
/// Public-key algorithm id 27 is reported as `Ed25519` and id 22 as `EdDSA`.
/// `gpg` 2.4.9 lists `EDDSA` and no `Ed25519` among its supported public-key
/// algorithms and generates id 22 for the `ed25519` curve, so no fixture on
/// this reference can carry id 27 and the matrix holds no cell for it.
const DIVERGENCE_ED25519_ALGORITHM: &str = "public-key algorithm id 27 has no reference fixture";

/// Whether both binaries answer, naming the absent one when they do not. An
/// absent reference tool skips a case and never passes one. These cases are the
/// whole of the differential gate's coverage, so a runner image without `gpg` or
/// `gpgv` would otherwise report the gate as tested when nothing compared the
/// two reports.
fn tools_available() -> bool {
    common::gnupg_available(&["gpg", "gpgv"])
}

/// A private GnuPG home holding one generated, passphrase-free signing key.
///
/// Every `gpg` and `gpgv` run names a directory inside it, so the invoking
/// user's GnuPG home and any agent of theirs take no part. Dropping the home
/// kills the agent GnuPG auto-started for the directory.
struct Home {
    dir: PathBuf,
    /// The primary key fingerprint, uppercase hex.
    primary: String,
    /// Whether every `gpg` run in this home stands at [`FAKED_CLOCK`].
    faked: bool,
}

impl Home {
    /// A home under `base` holding one ed25519 signing key for `uid` that
    /// never expires. `gpg` 2.4.9 generates public-key algorithm id 22 for
    /// this curve, which the report names `EdDSA`.
    fn eddsa(base: &Path, name: &str, uid: &str) -> Home {
        Home::build(base, name, uid, "ed25519", false, "never")
    }

    /// The same with an RSA signing key, whose cryptography admits a digest
    /// under 256 bits.
    fn rsa(base: &Path, name: &str, uid: &str) -> Home {
        Home::build(base, name, uid, "rsa2048", false, "never")
    }

    /// A home whose key was created at [`FAKED_CLOCK`] and lives for `expiry`,
    /// and whose every `gpg` run stands at that instant, so a signature it
    /// makes was made while the key was live. `gpgv` reads the real clock,
    /// which is what makes the key expired.
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

    /// A `gpg` command bound to this home, batch mode and with the empty
    /// passphrase supplied without a prompt.
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

    /// Every key fingerprint the home holds, in listing order: the primary key
    /// first, then its subkeys.
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

    /// Add a signing subkey and report its fingerprint.
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

    /// Add a user id.
    fn add_uid(&self, uid: &str) {
        let status = self
            .gpg()
            .args(["--quick-add-uid", &self.primary, uid])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-add-uid failed");
    }

    /// Mark a user id primary.
    fn set_primary_uid(&self, uid: &str) {
        let status = self
            .gpg()
            .args(["--quick-set-primary-uid", &self.primary, uid])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-set-primary-uid failed");
    }

    /// Revoke a user id.
    fn revoke_uid(&self, uid: &str) {
        let status = self
            .gpg()
            .args(["--quick-revoke-uid", &self.primary, uid])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-revoke-uid failed");
    }

    /// Revoke the primary key by importing the revocation certificate `gpg`
    /// stored when it generated the key. The stored file carries prose before
    /// the armored block, and a colon before the block's first dash so that an
    /// accidental import does nothing.
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

    /// Import a public keyring, so this home holds another home's certificate
    /// and can certify a user id on it.
    fn import(&self, keyring: &[u8]) {
        let path = self.write("import.gpg", keyring);
        let status = self.gpg().arg("--import").arg(path).status().unwrap();
        assert!(status.success(), "gpg --import of a public keyring failed");
    }

    /// Certify the one user id of the key `key` names that `uid` matches, with
    /// this home's own key. The certification is exportable, so it rides on
    /// the certificate this home exports.
    fn certify_uid(&self, key: &str, uid: &str) {
        let status = self
            .gpg()
            .args(["--quick-sign-key", key, uid])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-sign-key failed");
    }

    /// The exported binary public keyring.
    fn keyring(&self) -> Vec<u8> {
        let out = self.gpg().arg("--export").output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        out.stdout
    }

    /// The diagnostics `gpg` writes when it imports `keyring` into a scratch
    /// home named `into` under this one. `gpg` verifies each self-signature it
    /// imports, so a certificate carrying one that does not verify is named
    /// here.
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
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    /// The exported binary certificate of the one key `key` names.
    fn export_key(&self, key: &str) -> Vec<u8> {
        let out = self.gpg().args(["--export", key]).output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        out.stdout
    }

    /// The exported ASCII-armored public keyring.
    fn keyring_armored(&self) -> Vec<u8> {
        let out = self.gpg().args(["--export", "--armor"]).output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        out.stdout
    }

    /// One detached signature over `payload` by the key `key` names exactly,
    /// with `extra` passed to `gpg` on top of the base options.
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

    /// The records `gpgv` reports for the same inputs.
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

    /// Write one file into the home and report its path.
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&self.dir)
            .args(["--kill", "gpg-agent"])
            .status();
    }
}

/// The prefix every machine-readable status line carries.
const STATUS_PREFIX: &str = "[GNUPG:] ";

/// Read the machine-readable status stream of one `gpgv` run into
/// per-signature records. Each `NEWSIG` starts a record; the four verdict
/// keywords and the `VALIDSIG`, `ERRSIG`, `NO_PUBKEY`, and `KEYEXPIRED` lines
/// fill it. A field stating zero reads as absent, which is how `gpgv` states
/// "no expiry" and "no creation time".
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

/// A status-line epoch field, with zero reading as absent.
fn epoch(field: &str) -> Option<u64> {
    match field.parse::<u64>() {
        Ok(0) | Err(_) => None,
        Ok(secs) => Some(secs),
    }
}

/// The OpenPGP public-key algorithm name for a status-line algorithm id.
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

/// The OpenPGP digest algorithm name for a status-line algorithm id.
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

/// Split an OpenPGP user id into name and email: the trailing `<address>` is
/// the email and what precedes it is the name.
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

/// The records the engine reports over the public path: the keyring blobs load
/// into a verifier and the async `Verifier::verify` answers.
fn port_records(keyrings: &[&[u8]], blobs: &[&[u8]], payload: &[u8]) -> Vec<SignatureInfo> {
    let verifier = GpgVerifier::from_keyring_bytes(keyrings).expect("the keyrings load");
    let blobs: Vec<Vec<u8>> = blobs.iter().map(|blob| blob.to_vec()).collect();
    block_on(verifier.verify(payload, &blobs))
        .expect("the blobs are within the input caps")
        .signatures
}

/// Render every field of one record, so two records are compared as one value
/// and a difference names the field it stands in.
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

/// Assert one record states what `gpgv` states about the same signature, field
/// by field, the verdict included.
fn assert_agrees(label: &str, port: &SignatureInfo, reference: &SignatureInfo) {
    assert_eq!(
        summary(port),
        summary(reference),
        "{label}: the engine and gpgv report different fields",
    );
}

/// Put one cell through both engines and assert they agree record for record.
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

/// The verdict matrix: the shapes a stored blob and a trusted certificate take,
/// each put through both engines over the public path.
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

    // A signature the primary key made over the payload it signed.
    let records = assert_cell_agrees("a good signature", &trusted, &keyring, &good, PAYLOAD);
    assert!(records[0].valid, "the good signature is not valid");

    // The same signature against another payload.
    let records = assert_cell_agrees(
        "a changed payload",
        &trusted,
        &keyring,
        &good,
        OTHER_PAYLOAD,
    );
    assert!(!records[0].valid);

    // A signature whose issuer no loaded certificate holds.
    let foreign = stranger.sign(&stranger.primary, PAYLOAD, &[]);
    let records = assert_cell_agrees("an untrusted issuer", &trusted, &keyring, &foreign, PAYLOAD);
    assert!(records[0].key_missing && !records[0].valid);

    // One blob holding two signature packets, one of each issuer.
    let mut two = good.clone();
    two.extend_from_slice(&foreign);
    let records = assert_cell_agrees("a multi-signature blob", &trusted, &keyring, &two, PAYLOAD);
    assert_eq!(records.len(), 2);
    assert!(records[0].valid && records[1].key_missing);

    // A blob the parser reads no whole signature packet out of still reports
    // one record, so the record count follows the stored blob count. `gpgv`
    // reports no record for either, so the two are compared on the count the
    // engine owns and on the verdict.
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

    // A signing subkey the primary key cross-certified speaks for its
    // certificate, and the report names the subkey and the certificate apart.
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

    // A key past its own lifetime. The home stands at the faked clock, so the
    // signature was made while the key was live, and `gpgv` reads the real
    // clock.
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

/// The public-key algorithm axis, and the one divergence the cryptography
/// under the engine imposes.
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

    // Public-key algorithm id 1, over each digest `gpg` 2.4.9 offers that the
    // policy allows.
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

    // The digest policy: MD5 is refused by both, and the refusal is this
    // engine's own -- the cryptography under it verifies an MD5 signature.
    let md5 = rsa.sign(&rsa.primary, PAYLOAD, &["--digest-algo", "MD5"]);
    let records = assert_cell_agrees("an MD5 signature", &rsa, &rsa_ring, &md5, PAYLOAD);
    assert!(!records[0].valid, "{DIVERGENCE_DIGEST_POLICY}");
    assert_eq!(records[0].hash_algorithm.as_deref(), Some("MD5"));

    // Declared divergence: an EdDSA-legacy key with a digest under 256 bits.
    // `gpgv` reports `GOODSIG`; the engine reports the signature as not valid,
    // because rPGP refuses the digest before it verifies.
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
        // The record takes the shape a signature that does not verify takes:
        // the certificate's user id, and no field the signature claims about
        // itself, since none of them was checked. The reference names the key
        // and the two algorithms, so the divergence covers those fields too.
        assert_eq!(port[0].user_email, reference[0].user_email);
        assert!(!port[0].key_missing && !port[0].expired && !port[0].revoked);
        assert_eq!(port[0].fingerprint, None);
        assert_eq!(port[0].primary_fingerprint, None);
        assert_eq!(port[0].created, None);
        assert_eq!(port[0].pubkey_algorithm, None);
        assert_eq!(port[0].hash_algorithm, None);
        assert_eq!(reference[0].pubkey_algorithm.as_deref(), Some("EdDSA"));
        assert_eq!(reference[0].hash_algorithm.as_deref(), Some(digest));
    }

    // Declared divergence: no fixture on this reference carries public-key
    // algorithm id 27. `gpg` lists the algorithms it supports, and `Ed25519`
    // is not among them.
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

/// The keyring encodings and certificate counts a trusted set arrives in.
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

    // An armored keyring reaches the same verdict as the binary one it encodes.
    // `gpgv` reads the binary form, so it is the reference for both.
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

    // One keyring holding two certificates answers for a signature by either
    // of them, and each record names its own certificate's user id.
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

    // The two certificates offered as two keyring blobs reach the same trusted
    // set as the one concatenated blob.
    let second_ring = second.keyring();
    let records = port_records(&[&binary, &second_ring], &[&second_blob], PAYLOAD);
    assert_eq!(records.len(), 1);
    assert!(records[0].valid, "two keyring blobs did not merge");
}

/// Which user id the report names for a certificate holding several. The rule
/// is the primary user id, then the newest self-signed one, in each case among
/// those not revoked.
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

    // No user id is marked primary, so the newest self-signed one answers.
    // `gpg` writes a fresh self-signature per user id, and the clock has one
    // second of resolution, so each addition waits for the next second.
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

    // A marked primary user id answers even where it is not the newest.
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

    // A revoked user id is passed over, and the primary mark on it counts for
    // nothing. The verdict is untouched: a user id revocation revokes no key.
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

/// A certification the certificate's own key did not make does not choose the
/// user id the report names.
///
/// The fixture holds two user ids and marks neither primary, so the user ids
/// rank by their self-signatures and Bravo's stands after Alpha's. A second
/// key then certifies Alpha alone, later again, so Alpha carries the newest
/// signature of any kind while Bravo carries the newest self-signature. `gpgv`
/// names Bravo: a certification that does not verify under the certificate's
/// own key stands outside the ranking.
///
/// The whole fixture comes from the `gpg` binary. The stranger's home imports
/// the certificate, certifies one user id on it with `--quick-sign-key`, and
/// exports it again, so the certification is a real signature packet and no
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
    // The certification states its issuer fingerprint in a hashed subpacket,
    // so the stranger's fingerprint standing in the exported certificate is
    // the proof that a packet the stranger's key made rides on it.
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

/// A primary mark riding on a self-signature that does not verify does not
/// choose the user id the report names.
///
/// The fixture marks Alpha primary and adds Bravo afterwards, so Alpha wins on
/// its mark alone while Bravo carries the newest self-signature. One byte
/// inside Alpha's signature is then flipped, so that signature no longer
/// verifies while the primary-user-id subpacket stands where it stood. `gpgv`
/// names Alpha over the intact certificate and Bravo over the spliced one: a
/// mark on a certification that does not verify marks nothing.
///
/// The splice is located by reading the exported certificate, not by an offset
/// taken off one run. `gpg --export` writes the marked user id first, so
/// Alpha's signature packet is the one that ends where the Bravo user id packet
/// opens, and the last byte of that packet stands in the signature's trailing
/// MPI, past every subpacket. The case states that the splice landed and that
/// it left the mark alone before it compares the two reports, and it puts the
/// intact certificate through the same comparison as a control.
///
/// `gpg` writes the whole certificate. The splice is made on the exported bytes
/// afterwards, since no `gpg` option makes a signature stop verifying.
#[test]
fn an_unverified_primary_mark_does_not_choose_the_reported_user_id() {
    if !tools_available() {
        return;
    }
    const ALPHA: &str = "Alpha <alpha@ostrya.example>";
    const BRAVO: &str = "Bravo <bravo@ostrya.example>";
    /// A primary-user-id subpacket stating true: subpacket length 2,
    /// subpacket type 25, value 1.
    const MARK: [u8; 3] = [0x02, 0x19, 0x01];
    /// A user id packet header over a body under 192 bytes: the old-format tag
    /// byte for tag 13, then one length byte.
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
    // `gpg` states that the splice landed and that the intact certificate
    // carries nothing of the kind, so the one flipped byte is what stops
    // Alpha's self-signature verifying.
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

    // The control: the mark answers over the intact certificate, where the
    // ranking would name Bravo.
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

/// The one offset `needle` stands at in `haystack`.
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

/// The bytes an uppercase-hex fingerprint states.
fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Wait for the wall clock to reach the next second, so a self-signature `gpg`
/// makes next carries a later creation time than the one before it.
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

/// A signature by a signing subkey verifies against a legacy GnuPG keyring,
/// which carries a Trust packet after the primary key packet and after each
/// user id and signature packet. The subkey packet stands after the primary
/// key's Trust packet, so this is the case such a keyring reaches over the
/// certificate parser's tag runs.
///
/// Two keyrings hold the key here, and `gpgv` reads each of them as the
/// reference: the one GnuPG writes, which carries the Trust packets and is what
/// the `ostree` tool's own import leaves at the repository root, and the one
/// `Repo::gpg_import_keys` writes, which carries none.
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

    // The fixture is the shape under test: GnuPG's keyring carries Trust
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

/// A primary-key signature over a legacy GnuPG keyring reports the
/// certificate's user id. The user id packet stands after the primary key's
/// Trust packet, so a keyring of this shape reaches it over the same tag runs.
/// The keyring the port's own import writes reports the same user id.
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

/// The keyring GnuPG writes for `home`'s own keys, which carries a Trust packet
/// after the primary key packet, after each user id packet, and after each
/// signature packet.
///
/// `gpg` writes a keybox when it creates a keyring file itself and a legacy
/// keyring when the file is already there, so the import runs over an empty
/// keyring file in a home of its own.
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
    assert!(status.success(), "gpg --import into a keyring failed");
    std::fs::read(&ring).unwrap()
}

/// The keyring `Repo::gpg_import_keys` writes for `keys`, read back out of the
/// repository root as `remote gpg-import` leaves it.
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

/// Whether `gpg --list-packets` reports a Trust packet in `keyring`.
fn lists_a_trust_packet(home: &Home, keyring: &[u8]) -> bool {
    let path = home.write("listed.gpg", keyring);
    let out = home.gpg().arg("--list-packets").arg(path).output().unwrap();
    assert!(out.status.success(), "gpg --list-packets failed");
    String::from_utf8_lossy(&out.stdout).contains("trust packet")
}

/// The number of leading bytes each single-bit flip walks over. A keyring and
/// a detached signature both carry their packet headers, their algorithm ids,
/// and their subpacket structure in the first bytes, which is where a flip
/// reaches the parser rather than the cryptography alone.
const FLIP_PREFIX: usize = 64;

/// A corpus of malformed input: keyrings and signature blobs derived from the
/// good fixtures by truncation and by single-bit flipping.
///
/// Two properties are asserted over every input.
///
/// The first is that the call returns. A malformed keyring either fails the
/// load or loads to a trusted set, and a malformed blob either is refused by
/// name or reports records. A panic inside rPGP is contained and converted to
/// an error, so a panicking parser shows up here as a refusal; a panic that
/// escapes ends this test with the panic message, which is what makes the
/// containment testable.
///
/// The second is that no altered input reaches a valid verdict over a payload
/// nothing signed. Altering the bytes cannot forge a signature, so this holds
/// whatever the alteration did, and it is the property a caller depends on.
///
/// Over the payload the fixture signed, a valid verdict stays possible: cutting
/// a keyring after its public-key packet leaves the trusted key intact, and
/// flipping a bit in a signature's unhashed area leaves the signed material
/// intact. Such an input is asserted to report the fixture's own key and
/// nothing else, so no alteration ever makes the report name a key the trusted
/// set does not hold.
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

    // The good fixtures verify, so the assertions below state a property of the
    // altered bytes and not of the fixture.
    let records = port_records(&[&keyring], &[&blob], PAYLOAD);
    assert_eq!(records.len(), 1);
    assert!(records[0].valid, "the corpus fixture does not verify");

    let keyrings = corpus(&keyring, "the keyring");
    let blobs = corpus(&blob, "the blob");
    let keyring_inputs = keyrings.len();
    let blob_inputs = blobs.len();

    for (label, altered) in &keyrings {
        assert_bounded(label, &[altered], &[&blob], &home.primary);
    }
    for (label, altered) in &blobs {
        assert_bounded(label, &[&keyring], &[altered], &home.primary);
    }
    // Each count is asserted against its fixture length plus 64 bytes times
    // eight bits, which is the flip axis written out rather than read back off
    // [`FLIP_PREFIX`], so that a shrinking fixture and a shrinking axis both
    // fail here instead of making this case vacuous.
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

/// Every truncation of `bytes`, one byte at a time from nothing up to one byte
/// short of the whole, and every single-bit flip over its first
/// [`FLIP_PREFIX`] bytes.
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

/// Assert the two properties the corpus states over one input pair.
///
/// `primary` is the fingerprint of the one key the good fixtures hold, so a
/// record reported valid must name it.
fn assert_bounded(label: &str, keyrings: &[&[u8]], blobs: &[&[u8]], primary: &str) {
    let owned: Vec<Vec<u8>> = blobs.iter().map(|blob| blob.to_vec()).collect();
    // Over a payload nothing signed, no record is ever valid.
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
        // Over the payload the fixture signed, a record reported valid names
        // the fixture's own key and its own certificate.
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
