//! The in-process OpenPGP signature engine: it answers the cryptographic
//! question a stored signature blob asks and reports what the certificate and
//! the signature packet state about it.
//!
//! [`verify_signatures`] takes the certificates a [`GpgVerifier`](super::GpgVerifier)
//! loaded, the signed payload, and the `aay` blobs stored under
//! `ostree.gpgsigs`, and reports one [`SignatureInfo`] per signature packet.
//! One blob holds one or more signature packets, so a blob can contribute
//! several records; a blob the parser reads no signature out of contributes
//! one record of its own, so the record count follows the stored blob count.
//!
//! Each signature names its issuer in a subpacket. Resolution reads the issuer
//! fingerprint first and the issuer key id second, and each is matched against
//! every certificate's primary key and then its subkeys. A signature whose
//! issuer no loaded certificate holds is reported with `key_missing`, and the
//! fields the report then carries -- the fingerprint, the creation time, and
//! the two algorithm names -- come out of the signature packet itself.
//!
//! A stored blob is untrusted input, so it is bounded and the parse is
//! contained. One blob is held to one mebibyte, which is checked before the
//! parser sees the bytes, and to 64 signature packets, which is checked as the
//! packets are read. Each refusal names the cap it reached.

use std::io::Cursor;

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::Signature;
use pgp::types::{Fingerprint, KeyDetails, SignedUser, Timestamp};

use crate::error::{Error, Result};
use crate::sign::{SignatureInfo, VerifyOutcome};

/// The ceiling on one stored signature blob, whose whole content is parsed in
/// memory. One detached signature is a few hundred bytes, so a mebibyte holds
/// thousands of them.
const MAX_SIGNATURE_BLOB: usize = 1024 * 1024;
/// The ceiling on the signature packets one blob may hold. A commit carries a
/// handful of signatures, and the ceiling bounds the work a blob out of a
/// pulled commit's detached metadata can ask the parser and the public-key
/// operations for.
const MAX_SIGNATURE_PACKETS: usize = 64;

/// Report on each signature `blobs` holds, over `payload`, against the
/// certificates `certs` holds.
///
/// [`VerifyOutcome::valid`] is the OR over the per-signature flags, so one
/// valid signature among several makes the outcome valid.
///
/// The work is public-key cryptography over untrusted input and belongs on the
/// blocking pool.
// The `Verifier` implementation for `GpgVerifier` runs `gpgv`, so this entry
// point has its callers in the tests below alone. The allow covers the
// functions it reaches as well, so it is the one the module needs.
#[allow(dead_code)]
pub(super) fn verify_signatures(
    certs: &[SignedPublicKey],
    payload: &[u8],
    blobs: &[Vec<u8>],
) -> Result<VerifyOutcome> {
    let mut outcome = VerifyOutcome::default();
    for (index, blob) in blobs.iter().enumerate() {
        let infos = verify_blob(certs, payload, blob, &format!("the signature blob {index}"))?;
        if infos.is_empty() {
            outcome.signatures.push(SignatureInfo::default());
        } else {
            for info in infos {
                outcome.valid |= info.valid;
                outcome.signatures.push(info);
            }
        }
    }
    Ok(outcome)
}

/// Report on each signature one blob holds. `subject` names the blob, so a
/// refusal states which blob reached which cap.
///
/// A blob is untrusted input, so the parse and the public-key operations run
/// inside [`std::panic::catch_unwind`] and a caught panic reads as a blob the
/// parser rejects. Two limits hold: `catch_unwind` catches nothing where the
/// final binary is built with `panic = "abort"`, and it says nothing about a
/// parser that returns a wrong answer without panicking.
fn verify_blob(
    certs: &[SignedPublicKey],
    payload: &[u8],
    blob: &[u8],
    subject: &str,
) -> Result<Vec<SignatureInfo>> {
    if blob.len() > MAX_SIGNATURE_BLOB {
        return Err(Error::Signature(format!(
            "{subject} is over the {MAX_SIGNATURE_BLOB}-byte ceiling"
        )));
    }
    let work = || -> Result<Vec<SignatureInfo>> {
        let mut infos: Vec<SignatureInfo> = Vec::new();
        // A blob the parser reads no whole signature packet out of reports no
        // record here, whether the packet stream refuses to open or the first
        // packet is incomplete. The caller gives such a blob one record, so the
        // record count follows the blob count.
        let Ok(signatures) = DetachedSignature::from_bytes_many(Cursor::new(blob)) else {
            return Ok(infos);
        };
        for signature in signatures {
            if infos.len() == MAX_SIGNATURE_PACKETS {
                return Err(Error::Signature(format!(
                    "{subject} holds more than {MAX_SIGNATURE_PACKETS} signature packets"
                )));
            }
            // The packets that were read whole keep their records, and the
            // stream stops at the first one that was not.
            let Ok(signature) = signature else { break };
            infos.push(describe(certs, payload, &signature));
        }
        Ok(infos)
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
        Ok(result) => result,
        Err(_) => Err(Error::Signature(format!(
            "{subject} is not readable as an OpenPGP signature: the parser panicked"
        ))),
    }
}

/// Report on one signature packet.
///
/// Three outcomes carry three field sets. A signature a resolved key verifies
/// reports the signing key, its certificate, and the certificate's user id. A
/// signature whose issuer resolved and whose cryptography failed reports the
/// user id alone, since nothing else it claims was checked. A signature whose
/// issuer no certificate holds reports what its own packet states.
fn describe(
    certs: &[SignedPublicKey],
    payload: &[u8],
    signature: &DetachedSignature,
) -> SignatureInfo {
    let sig = &signature.signature;
    let mut info = SignatureInfo::default();
    let Some(issuer) = resolve_issuer(certs, sig) else {
        info.key_missing = true;
        info.fingerprint = sig.issuer_fingerprint().first().map(|f| format!("{f:X}"));
        info.created = created_at(sig);
        info.pubkey_algorithm = pubkey_algorithm_name(sig);
        info.hash_algorithm = hash_algorithm_name(sig);
        return info;
    };
    let (user_name, user_email) = reported_user_id(issuer.cert);
    info.user_name = user_name;
    info.user_email = user_email;
    if !issuer.verify(signature, payload) {
        return info;
    }
    info.fingerprint = Some(format!("{:X}", issuer.fingerprint()));
    info.primary_fingerprint = Some(format!("{:X}", issuer.cert.fingerprint()));
    info.created = created_at(sig);
    info.expires = expires_at(sig);
    info.pubkey_algorithm = pubkey_algorithm_name(sig);
    info.hash_algorithm = hash_algorithm_name(sig);
    info
}

/// The key a signature names as its issuer: a certificate, and the subkey of
/// it that signed where a subkey did.
struct Issuer<'a> {
    cert: &'a SignedPublicKey,
    subkey: Option<&'a SignedPublicSubKey>,
}

impl Issuer<'_> {
    /// The signing key's own fingerprint: the subkey's where a subkey signed,
    /// and the primary key's otherwise.
    fn fingerprint(&self) -> Fingerprint {
        match self.subkey {
            Some(subkey) => subkey.fingerprint(),
            None => self.cert.fingerprint(),
        }
    }

    /// Whether the signing key verifies `signature` over `payload`.
    fn verify(&self, signature: &DetachedSignature, payload: &[u8]) -> bool {
        match self.subkey {
            Some(subkey) => signature.verify(subkey, payload).is_ok(),
            None => signature.verify(self.cert, payload).is_ok(),
        }
    }
}

/// Resolve the key a signature names as its issuer, over the loaded
/// certificates: by issuer fingerprint first, then by issuer key id, and each
/// over the primary key before the subkeys.
fn resolve_issuer<'a>(certs: &'a [SignedPublicKey], sig: &Signature) -> Option<Issuer<'a>> {
    for wanted in sig.issuer_fingerprint() {
        for cert in certs {
            if &cert.fingerprint() == wanted {
                return Some(Issuer { cert, subkey: None });
            }
            for subkey in &cert.public_subkeys {
                if &subkey.fingerprint() == wanted {
                    return Some(Issuer {
                        cert,
                        subkey: Some(subkey),
                    });
                }
            }
        }
    }
    for wanted in sig.issuer_key_id() {
        for cert in certs {
            if &cert.legacy_key_id() == wanted {
                return Some(Issuer { cert, subkey: None });
            }
            for subkey in &cert.public_subkeys {
                if &subkey.legacy_key_id() == wanted {
                    return Some(Issuer {
                        cert,
                        subkey: Some(subkey),
                    });
                }
            }
        }
    }
    None
}

/// The signature creation time the packet carries, in seconds since the Unix
/// epoch. A zero instant reads as absent.
fn created_at(sig: &Signature) -> Option<u64> {
    epoch(sig.created()?.as_secs())
}

/// The instant the signature itself expires: its creation time plus the
/// expiration the packet carries. Absent where the packet carries no
/// expiration or carries a zero one.
fn expires_at(sig: &Signature) -> Option<u64> {
    let created = created_at(sig)?;
    let lifetime = epoch(sig.signature_expiration_time()?.as_secs())?;
    Some(created + lifetime)
}

/// A packet time field in seconds, with zero read as absent.
fn epoch(secs: u32) -> Option<u64> {
    (secs != 0).then(|| u64::from(secs))
}

/// The public-key algorithm name the report writes. Algorithm id 22 is
/// reported as `EdDSA`. The enum admits ids the port knows no name for, which
/// are reported as their number.
fn pubkey_algorithm_name(sig: &Signature) -> Option<String> {
    let alg = sig.config()?.pub_alg;
    Some(match alg {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            "RSA".to_owned()
        }
        PublicKeyAlgorithm::DSA => "DSA".to_owned(),
        PublicKeyAlgorithm::ECDH => "ECDH".to_owned(),
        PublicKeyAlgorithm::ECDSA => "ECDSA".to_owned(),
        PublicKeyAlgorithm::EdDSALegacy => "EdDSA".to_owned(),
        PublicKeyAlgorithm::Ed25519 => "Ed25519".to_owned(),
        PublicKeyAlgorithm::Ed448 => "Ed448".to_owned(),
        other => u8::from(other).to_string(),
    })
}

/// The digest algorithm name the report writes. The enum admits ids the port
/// knows no name for, which are reported as their number.
fn hash_algorithm_name(sig: &Signature) -> Option<String> {
    let alg = sig.hash_alg()?;
    Some(match alg {
        HashAlgorithm::Md5
        | HashAlgorithm::Sha1
        | HashAlgorithm::Ripemd160
        | HashAlgorithm::Sha256
        | HashAlgorithm::Sha384
        | HashAlgorithm::Sha512
        | HashAlgorithm::Sha224 => alg.to_string(),
        other => u8::from(other).to_string(),
    })
}

/// The name and the email of the user id the report names for a certificate:
/// the primary user id, or, where no user id is marked primary, the newest
/// self-signed one. A user id that is not valid UTF-8 is read with the invalid
/// sequences replaced.
fn reported_user_id(cert: &SignedPublicKey) -> (Option<String>, Option<String>) {
    let user = cert
        .details
        .users
        .iter()
        .find(|user| user.is_primary())
        .or_else(|| cert.details.users.iter().max_by_key(newest_certification));
    match user {
        Some(user) => super::split_uid(&String::from_utf8_lossy(user.id.id())),
        None => (None, None),
    }
}

/// The creation time of the newest certification over a user id.
fn newest_certification(user: &&SignedUser) -> u32 {
    user.signatures
        .iter()
        .filter_map(Signature::created)
        .map(Timestamp::as_secs)
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;
    use crate::gpg::{GpgVerifier, parse_status, scratch_dir};

    /// The payload every fixture signs.
    const PAYLOAD: &[u8] = b"ostrya commit payload";
    /// A payload no fixture signs, for the changed-payload case.
    const OTHER_PAYLOAD: &[u8] = b"ostrya other payload";

    /// Whether the named binary answers. The cases below build their fixtures
    /// with `gpg` and read their reference records from `gpgv`, so an absent
    /// binary skips a case and never passes one.
    fn available(program: &str) -> bool {
        Command::new(program)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// A private GnuPG home holding one freshly generated, passphrase-free
    /// ed25519 signing key, under the test scratch tree. Every `gpg` and
    /// `gpgv` run names a directory inside it, so the invoking user's GnuPG
    /// home and any agent of theirs take no part. Dropping the fixture kills
    /// the agent GnuPG auto-started for the directory and removes the tree.
    struct Fixture {
        dir: PathBuf,
        /// The primary key fingerprint, uppercase hex.
        primary: String,
    }

    impl Fixture {
        /// A new home directory holding one signing key for `uid`.
        fn new(uid: &str) -> Fixture {
            use std::os::unix::fs::DirBuilderExt;
            let dir = scratch_dir();
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&dir).unwrap();
            builder.create(dir.join("gv")).unwrap();
            let mut fixture = Fixture {
                dir,
                primary: String::new(),
            };
            let status = fixture
                .gpg()
                .args(["--quick-gen-key", uid, "ed25519", "sign", "never"])
                .status()
                .unwrap();
            assert!(status.success(), "gpg --quick-gen-key failed");
            fixture.primary = fixture.fingerprints().remove(0);
            fixture
        }

        /// A `gpg` command bound to this home directory, batch mode and with
        /// the empty passphrase supplied without a prompt.
        fn gpg(&self) -> Command {
            let mut cmd = Command::new("gpg");
            cmd.arg("--homedir").arg(&self.dir).arg("--batch").args([
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
            ]);
            cmd
        }

        /// Add a signing subkey to the primary key and report its
        /// fingerprint.
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

        /// Every key fingerprint the home directory holds, in listing order:
        /// the primary key first, then its subkeys.
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

        /// The exported binary public keyring.
        fn keyring(&self) -> Vec<u8> {
            let out = self.gpg().arg("--export").output().unwrap();
            assert!(out.status.success() && !out.stdout.is_empty());
            out.stdout
        }

        /// The certificates a verifier loads the exported keyring into.
        fn certs(&self) -> Vec<SignedPublicKey> {
            GpgVerifier::from_keyring_bytes([self.keyring()])
                .unwrap()
                .certs
        }

        /// One detached signature over `payload`, made by the key `key`
        /// names exactly.
        fn sign(&self, key: &str, payload: &[u8]) -> Vec<u8> {
            self.sign_with(key, payload, &[])
        }

        /// One detached signature over `payload`, made by the key `key` names
        /// exactly, with `extra` passed to `gpg` on top of the base options.
        fn sign_with(&self, key: &str, payload: &[u8], extra: &[&str]) -> Vec<u8> {
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

        /// The records `gpgv` reports for the same inputs, read through the
        /// status-stream parser. This is the reference every case below
        /// compares against.
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
            parse_status(&out.stdout)
        }

        /// Write one file into the fixture directory and report its path.
        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = Command::new("gpgconf")
                .arg("--homedir")
                .arg(&self.dir)
                .args(["--kill", "gpg-agent"])
                .status();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Whether both binaries answer, naming the absent one when they do not.
    fn tools_available() -> bool {
        for program in ["gpg", "gpgv"] {
            if !available(program) {
                eprintln!("skipping: {program} not available");
                return false;
            }
        }
        true
    }

    /// Assert one record states what `gpgv` states about the same signature.
    /// The comparison covers the descriptive fields alone: `valid`, `expired`,
    /// `revoked`, and `key_expires` are the validity policy's answer, and the
    /// engine leaves `valid` false.
    fn assert_agrees(port: &SignatureInfo, reference: &SignatureInfo) {
        assert_eq!(port.fingerprint, reference.fingerprint, "fingerprint");
        assert_eq!(
            port.primary_fingerprint, reference.primary_fingerprint,
            "primary_fingerprint"
        );
        assert_eq!(port.created, reference.created, "created");
        assert_eq!(port.expires, reference.expires, "expires");
        assert_eq!(
            port.pubkey_algorithm, reference.pubkey_algorithm,
            "pubkey_algorithm"
        );
        assert_eq!(
            port.hash_algorithm, reference.hash_algorithm,
            "hash_algorithm"
        );
        assert_eq!(port.user_name, reference.user_name, "user_name");
        assert_eq!(port.user_email, reference.user_email, "user_email");
        assert_eq!(port.key_missing, reference.key_missing, "key_missing");
        assert!(!port.valid);
    }

    /// A signature the primary key made reports the primary key as both the
    /// signing key and the certificate, with the certificate's user id.
    #[test]
    fn primary_key_signature_agrees_with_gpgv() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Prim <prim@ostrya.example>");
        let keyring = home.keyring();
        let blob = home.sign(&home.primary, PAYLOAD);
        let outcome =
            verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        // The reference verified the signature, and the port reports the key
        // that did so.
        assert!(reference[0].valid);
        assert_eq!(
            outcome.signatures[0].fingerprint.as_deref(),
            Some(&*home.primary)
        );
        assert_eq!(
            outcome.signatures[0].primary_fingerprint.as_deref(),
            Some(&*home.primary)
        );
        assert_eq!(
            outcome.signatures[0].user_email.as_deref(),
            Some("prim@ostrya.example")
        );
    }

    /// A signature carrying an expiry of its own reports the instant it
    /// expires. The packet states a lifetime counted from the creation time and
    /// the reference states an absolute instant, so this is the one field whose
    /// value the engine computes.
    #[test]
    fn expiring_signature_agrees_with_gpgv() {
        if !tools_available() {
            return;
        }
        /// The lifetime `--default-sig-expire 1d` writes, in seconds.
        const ONE_DAY: u64 = 24 * 60 * 60;
        let home = Fixture::new("Exp <exp@ostrya.example>");
        let keyring = home.keyring();
        let blob = home.sign_with(&home.primary, PAYLOAD, &["--default-sig-expire", "1d"]);
        let outcome =
            verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        let created = info.created.expect("the packet carries a creation time");
        assert_eq!(reference[0].expires, Some(created + ONE_DAY));
        assert_eq!(info.expires, Some(created + ONE_DAY));
    }

    /// A signature a signing subkey made reports the subkey as the signing key
    /// and its certificate as the primary fingerprint.
    #[test]
    fn subkey_signature_agrees_with_gpgv() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Sub <sub@ostrya.example>");
        let subkey = home.add_signing_subkey();
        let keyring = home.keyring();
        let blob = home.sign(&subkey, PAYLOAD);
        let outcome =
            verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(reference[0].valid);
        assert_eq!(outcome.signatures[0].fingerprint.as_deref(), Some(&*subkey));
        assert_eq!(
            outcome.signatures[0].primary_fingerprint.as_deref(),
            Some(&*home.primary)
        );
    }

    /// One blob holding two concatenated signatures reports two records, in
    /// the order the packets stand in.
    #[test]
    fn two_signature_blob_agrees_with_gpgv() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Two <two@ostrya.example>");
        let subkey = home.add_signing_subkey();
        let keyring = home.keyring();
        let mut blob = home.sign(&home.primary, PAYLOAD);
        blob.extend_from_slice(&home.sign(&subkey, PAYLOAD));
        let outcome =
            verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 2);
        assert_eq!(reference.len(), 2);
        for (port, reference) in outcome.signatures.iter().zip(&reference) {
            assert_agrees(port, reference);
        }
        assert_eq!(
            outcome.signatures[0].fingerprint.as_deref(),
            Some(&*home.primary)
        );
        assert_eq!(outcome.signatures[1].fingerprint.as_deref(), Some(&*subkey));
    }

    /// A signature whose issuer no loaded certificate holds reports
    /// `key_missing`, with the fingerprint, the creation time, and the two
    /// algorithm names read out of the signature packet. These are the fields
    /// `ERRSIG` carries.
    #[test]
    fn unknown_issuer_agrees_with_errsig() {
        if !tools_available() {
            return;
        }
        let signer = Fixture::new("Signer <signer@ostrya.example>");
        let other = Fixture::new("Other <other@ostrya.example>");
        let blob = signer.sign(&signer.primary, PAYLOAD);
        let outcome =
            verify_signatures(&other.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = signer.gpgv_records(&other.keyring(), &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(info.key_missing);
        assert!(reference[0].key_missing);
        // The three field groups `ERRSIG` supplies, named one at a time.
        assert_eq!(info.pubkey_algorithm.as_deref(), Some("EdDSA"));
        assert_eq!(info.pubkey_algorithm, reference[0].pubkey_algorithm);
        assert_eq!(info.hash_algorithm, reference[0].hash_algorithm);
        assert_eq!(info.created, reference[0].created);
        assert!(info.created.is_some());
        assert_eq!(info.fingerprint.as_deref(), Some(&*signer.primary));
        assert_eq!(info.fingerprint, reference[0].fingerprint);
        // No key verified, so the certificate fields stay absent.
        assert_eq!(info.primary_fingerprint, None);
        assert_eq!(info.user_name, None);
    }

    /// A signature over a payload other than the one it was made over reports
    /// the certificate's user id alone. Nothing else the signature claims was
    /// checked, and `gpgv` names nothing else either.
    #[test]
    fn changed_payload_agrees_with_gpgv() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Bad <bad@ostrya.example>");
        let keyring = home.keyring();
        let blob = home.sign(&home.primary, PAYLOAD);
        let outcome =
            verify_signatures(&home.certs(), OTHER_PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, OTHER_PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(!reference[0].valid);
        assert_eq!(info.user_email.as_deref(), Some("bad@ostrya.example"));
        assert_eq!(info.fingerprint, None);
        assert_eq!(info.primary_fingerprint, None);
        assert_eq!(info.created, None);
        assert!(!info.key_missing);
    }

    /// A blob holding half a signature packet reports one record and nothing
    /// about it, so the record count follows the stored blob count. `gpgv`
    /// reads no signature out of it and states no record at all.
    #[test]
    fn truncated_blob_reports_one_bare_record() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Cut <cut@ostrya.example>");
        let keyring = home.keyring();
        let whole = home.sign(&home.primary, PAYLOAD);
        let blob = whole[..whole.len() / 2].to_vec();
        let outcome =
            verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        assert!(home.gpgv_records(&keyring, &blob, PAYLOAD).is_empty());
        assert_eq!(outcome.signatures.len(), 1);
        assert_bare(&outcome.signatures[0]);
        assert!(!outcome.valid);
    }

    /// An empty blob reports one record and nothing about it, as a truncated
    /// one does.
    #[test]
    fn empty_blob_reports_one_bare_record() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Empty <empty@ostrya.example>");
        let keyring = home.keyring();
        let outcome = verify_signatures(&home.certs(), PAYLOAD, &[Vec::new()]).unwrap();
        assert!(home.gpgv_records(&keyring, b"", PAYLOAD).is_empty());
        assert_eq!(outcome.signatures.len(), 1);
        assert_bare(&outcome.signatures[0]);
        assert!(!outcome.valid);
    }

    /// Assert a record states nothing about a signature.
    fn assert_bare(info: &SignatureInfo) {
        assert!(!info.valid);
        assert_eq!(info.fingerprint, None);
        assert_eq!(info.primary_fingerprint, None);
        assert_eq!(info.created, None);
        assert_eq!(info.expires, None);
        assert_eq!(info.pubkey_algorithm, None);
        assert_eq!(info.hash_algorithm, None);
        assert_eq!(info.user_name, None);
        assert_eq!(info.user_email, None);
        assert!(!info.key_missing);
    }

    /// A blob over the one-mebibyte ceiling is refused by the name of the blob
    /// that carried it, and the refusal states the ceiling. The blob is
    /// bounded before it is parsed, so the packet cap is not what refused it.
    /// The ceiling is the port's own bound and the reference tool holds none,
    /// which is why nothing is compared against `gpgv` here.
    #[test]
    fn oversized_blob_is_refused() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Big <big@ostrya.example>");
        let one = home.sign(&home.primary, PAYLOAD);
        let copies = MAX_SIGNATURE_BLOB / one.len() + 1;
        let blob = one.repeat(copies);
        assert!(blob.len() > MAX_SIGNATURE_BLOB);
        let err = verify_signatures(&home.certs(), PAYLOAD, &[blob]).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("signature blob 0")
                && m.contains("ceiling") && !m.contains("packets")),
            "{err}"
        );
    }

    /// A blob holding more than 64 signature packets is refused by name, and
    /// the refusal states the cap. `gpgv` reads every packet and reports one
    /// record each, so the cap is a bound of the port's own.
    #[test]
    fn too_many_signature_packets_is_refused() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Many <many@ostrya.example>");
        let keyring = home.keyring();
        let certs = home.certs();
        let one = home.sign(&home.primary, PAYLOAD);
        let many = one.repeat(MAX_SIGNATURE_PACKETS + 1);
        assert!(many.len() <= MAX_SIGNATURE_BLOB);
        let err = verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&many)).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("signature blob 0")
                && m.contains("64 signature packets")),
            "{err}"
        );
        assert_eq!(
            home.gpgv_records(&keyring, &many, PAYLOAD).len(),
            MAX_SIGNATURE_PACKETS + 1
        );
        // One packet short of the cap reports one record each, so the cap is
        // what refused the blob above.
        let allowed = one.repeat(MAX_SIGNATURE_PACKETS);
        let outcome = verify_signatures(&certs, PAYLOAD, &[allowed]).unwrap();
        assert_eq!(outcome.signatures.len(), MAX_SIGNATURE_PACKETS);
    }

    /// Every stored blob contributes at least one record, so a run over
    /// several blobs reports them in the order they were stored.
    #[test]
    fn record_count_follows_the_blob_count() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Count <count@ostrya.example>");
        let good = home.sign(&home.primary, PAYLOAD);
        let blobs = vec![good.clone(), Vec::new(), good];
        let outcome = verify_signatures(&home.certs(), PAYLOAD, &blobs).unwrap();
        assert_eq!(outcome.signatures.len(), 3);
        assert!(outcome.signatures[0].fingerprint.is_some());
        assert_bare(&outcome.signatures[1]);
        assert!(outcome.signatures[2].fingerprint.is_some());
    }
}
