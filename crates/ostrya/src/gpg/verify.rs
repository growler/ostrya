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
//! The engine also owns the trust and validity policy: which signature classes
//! and which digest algorithms a data signature may use, when a subkey speaks
//! for its certificate, when a key has expired, and when it is revoked. A
//! signature is valid where it verifies, where the certificate that holds the
//! signing key is loaded, where the signature is over a document, where the
//! bindings hold, where the digest is allowed, where the signature's own expiry
//! has not passed, and where the key is neither expired nor revoked. Each rule
//! below cites the `gpgv` 2.4.9 behavior it reproduces, observed in an isolated
//! `GNUPGHOME` on fixtures the unit tests build.
//!
//! A stored blob is untrusted input, so it is bounded and the parse is
//! contained. One blob is held to one mebibyte, which is checked before the
//! parser sees the bytes, and to 64 signature packets, which is checked as the
//! packets are read. Each refusal names the cap it reached. The policy runs
//! inside the same containment, so a crafted certificate that drives a public-
//! key operation into a panic reads as a blob the parser rejects.

use std::io::Cursor;

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{Signature, SignatureType};
use pgp::types::{Fingerprint, KeyDetails, SignedUser, Tag, Timestamp};

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
/// blocking pool, which is where
/// [`Verifier::verify`](crate::sign::Verifier::verify) for
/// [`GpgVerifier`](super::GpgVerifier) calls it.
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
/// Six outcomes carry four field sets. A signature whose issuer no certificate
/// holds reports what its own packet states, with `key_missing`. A signature
/// whose class is not a document signature, one whose digest algorithm the
/// policy refuses, and one by a signing subkey the primary key did not
/// cross-certify report the same fields without `key_missing`. A signature
/// whose issuer resolved and whose cryptography failed reports the user id
/// alone, since nothing else it claims was checked. A signature a resolved key
/// verifies reports the signing key, its certificate, the certificate's user
/// id, and the validity policy's answer.
fn describe(
    certs: &[SignedPublicKey],
    payload: &[u8],
    signature: &DetachedSignature,
) -> SignatureInfo {
    let sig = &signature.signature;
    let mut info = SignatureInfo::default();
    // The issuer is resolved first, which is the order `gpgv` answers in: over
    // an MD5 data signature whose issuer no loaded keyring holds it reports
    // `ERRSIG <keyid> 1 1 00 <created> 9 <fingerprint>` and `NO_PUBKEY`, and it
    // names the digest as the cause only where the issuer resolved. No rule
    // below can make such a record valid, so a refused digest and a refused
    // class stay refused on every path.
    let Some(issuer) = resolve_issuer(certs, sig) else {
        info.key_missing = true;
        describe_packet(&mut info, sig);
        return info;
    };
    // `gpgv` over a class 0x02 signature reports
    // `ERRSIG <keyid> 22 10 02 <created> 32 <fingerprint>` and no user id,
    // where a class 0x00 signature by the same key over the same payload
    // reports `GOODSIG`.
    if !is_data_signature(sig) {
        describe_packet(&mut info, sig);
        return info;
    }
    // `gpgv` over an MD5 data signature by a key its keyring holds reports
    // `ERRSIG <keyid> 22 1 00 <created> 5 <fingerprint>` and "Invalid digest
    // algorithm", so it names the signature packet's own fields and no user id.
    if !digest_allowed(sig) {
        describe_packet(&mut info, sig);
        return info;
    }
    // A signing subkey the primary key did not cross-certify signs for
    // nothing. `gpgv` over the same certificate with the back-signature
    // removed reports `ERRSIG <keyid> 22 10 00 <created> 1 <fingerprint>`,
    // "signing subkey ... is not cross-certified", and no `NO_PUBKEY`, where
    // the intact certificate reports `GOODSIG`.
    if !issuer.cross_certified() {
        describe_packet(&mut info, sig);
        return info;
    }
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
    let now = now();
    // `gpgv` reports an expired key as `EXPKEYSIG` with `KEYEXPIRED <instant>`
    // and a revoked one as `REVKEYSIG`, and it prints the `VALIDSIG` detail
    // line in both cases, so both records carry the fields above. Neither is
    // `GOODSIG`, so neither is valid. A key stands live at the instant it
    // expires and expires from the next second: polled second by second across
    // its expiry instant, `gpgv` reports `GOODSIG` through that instant and
    // `EXPKEYSIG` from the second after it.
    let key_expires = issuer.key_expires_at();
    if key_expires.is_some_and(|instant| instant < now) {
        info.expired = true;
        info.key_expires = key_expires;
    }
    info.revoked = issuer.revoked();
    // A signature past its own expiry reports `EXPSIG` and no `GOODSIG`, so it
    // is not valid, and no status keyword states more about it. The signature
    // expires at the instant it names: polled second by second across that
    // instant, `gpgv` reports `GOODSIG` through the second before it and
    // `EXPSIG` from the instant on.
    let signature_expired = info.expires.is_some_and(|instant| instant <= now);
    info.valid = !signature_expired && !info.expired && !info.revoked;
    info
}

/// Fill the fields a signature packet states about itself: the issuer
/// fingerprint it names, its creation time, and the two algorithm names. These
/// are the fields `ERRSIG` carries, and they are all a record holds where no
/// key answered for the signature.
fn describe_packet(info: &mut SignatureInfo, sig: &Signature) {
    info.fingerprint = sig.issuer_fingerprint().first().map(|f| format!("{f:X}"));
    info.created = created_at(sig);
    info.pubkey_algorithm = pubkey_algorithm_name(sig);
    info.hash_algorithm = hash_algorithm_name(sig);
}

/// Whether a signature is over a document, which is the class a stored blob
/// may hold. The two document classes are the binary one and the text one.
/// `gpgv` 2.4.9 refuses every other class: over a class 0x02 signature and over
/// a class 0x40 signature it reports "Invalid signature class" and no
/// `GOODSIG`. Such a signature covers one payload byte, so one of them would
/// otherwise answer for every payload that starts with that byte.
fn is_data_signature(sig: &Signature) -> bool {
    matches!(sig.typ(), Some(SignatureType::Binary | SignatureType::Text))
}

/// Whether a data signature's digest algorithm is allowed. MD5 is refused and
/// SHA-1 is accepted, which is what `gpgv` 2.4.9 answers on a data signature:
/// an MD5 signature reports `ERRSIG ... 5` and "Note: signatures using the MD5
/// algorithm are rejected", and a SHA-1 signature reports `GOODSIG`. The
/// policy is the port's own, because GnuPG's is configurable and moves between
/// versions, so the divergence to record is a class and not a version number.
fn digest_allowed(sig: &Signature) -> bool {
    sig.hash_alg() != Some(HashAlgorithm::Md5)
}

/// The instant the policy is evaluated against, in seconds since the Unix
/// epoch. A clock standing before the epoch reads as the epoch itself.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The key a signature names as its issuer: a certificate, and the subkey of
/// it that signed where a subkey did.
struct Issuer<'a> {
    cert: &'a SignedPublicKey,
    /// The subkey that signed, together with the newest binding signature the
    /// primary key made over it.
    subkey: Option<(&'a SignedPublicSubKey, &'a Signature)>,
}

impl Issuer<'_> {
    /// The signing key's own fingerprint: the subkey's where a subkey signed,
    /// and the primary key's otherwise.
    fn fingerprint(&self) -> Fingerprint {
        match self.subkey {
            Some((subkey, _)) => subkey.fingerprint(),
            None => self.cert.fingerprint(),
        }
    }

    /// Whether the signing key verifies `signature` over `payload`.
    fn verify(&self, signature: &DetachedSignature, payload: &[u8]) -> bool {
        match self.subkey {
            Some((subkey, _)) => signature.verify(subkey, payload).is_ok(),
            None => signature.verify(self.cert, payload).is_ok(),
        }
    }

    /// Whether the signing key is cross-certified: a subkey's binding
    /// signature must carry an embedded primary-key binding signature -- the
    /// back-signature -- that the subkey itself made over the primary key. A
    /// primary key that signed for itself needs none.
    ///
    /// This is the check that keeps a subkey stapled onto a trusted
    /// certificate from speaking for it. rPGP's `verify_subkey_binding` reads
    /// the binding signature alone, and the back-signature stands in a
    /// separate `verify_primary_key_binding` call over the binding's embedded
    /// signature. The requirement holds for every subkey that produced a data
    /// signature, whatever key flags its binding carries.
    fn cross_certified(&self) -> bool {
        let Some((subkey, binding)) = self.subkey else {
            return true;
        };
        binding.embedded_signature().is_some_and(|back| {
            back.verify_primary_key_binding(&subkey.key, &self.cert.primary_key)
                .is_ok()
        })
    }

    /// The instant the signing key expires: the key creation time plus the key
    /// expiration time its newest verified self-signature states. For a subkey
    /// this is the earlier of the primary key's instant and the binding
    /// signature's own, because a subkey stops with its certificate. `gpgv`
    /// over a certificate whose primary key expired and whose signing subkey
    /// states no expiry of its own reports `EXPKEYSIG` with the primary key's
    /// `KEYEXPIRED` instant.
    fn key_expires_at(&self) -> Option<u64> {
        let primary = primary_key_lifetime(self.cert)
            .map(|life| u64::from(self.cert.primary_key.created_at().as_secs()) + life);
        let Some((subkey, binding)) = self.subkey else {
            return primary;
        };
        let own =
            key_lifetime(binding).map(|life| u64::from(subkey.key.created_at().as_secs()) + life);
        match (primary, own) {
            (Some(primary), Some(own)) => Some(primary.min(own)),
            (primary, own) => primary.or(own),
        }
    }

    /// Whether the signing key is revoked: a key revocation signature the
    /// primary key made over itself, or, where a subkey signed, a subkey
    /// revocation the primary key made over that subkey.
    ///
    /// A revocation is verified before it is honored. A key revocation
    /// signature another key made and anyone can staple onto a certificate
    /// revokes nothing, which is what `gpgv` answers: over a certificate
    /// carrying such a packet it still reports `GOODSIG`.
    fn revoked(&self) -> bool {
        let primary = &self.cert.primary_key;
        let key_revoked = self.cert.details.revocation_signatures.iter().any(|sig| {
            sig.typ() == Some(SignatureType::KeyRevocation) && sig.verify_key(primary).is_ok()
        });
        if key_revoked {
            return true;
        }
        let Some((subkey, _)) = self.subkey else {
            return false;
        };
        subkey.signatures.iter().any(|sig| {
            sig.typ() == Some(SignatureType::SubkeyRevocation)
                && sig.verify_subkey_binding(primary, &subkey.key).is_ok()
        })
    }
}

/// Resolve the key a signature names as its issuer, over the loaded
/// certificates: by issuer fingerprint first, then by issuer key id, and each
/// over the primary key before the subkeys.
///
/// A subkey answers only where the primary key made a binding signature over
/// it that verifies. A subkey whose binding does not verify -- one taken from
/// another certificate and attached with the binding it carried there --
/// belongs to no loaded certificate, and `gpgv` answers the same way: it
/// reports `ERRSIG ... 9` and `NO_PUBKEY` for a signature such a subkey made.
fn resolve_issuer<'a>(certs: &'a [SignedPublicKey], sig: &Signature) -> Option<Issuer<'a>> {
    for wanted in sig.issuer_fingerprint() {
        for cert in certs {
            if &cert.fingerprint() == wanted {
                return Some(Issuer { cert, subkey: None });
            }
            for subkey in &cert.public_subkeys {
                if &subkey.fingerprint() == wanted
                    && let Some(binding) = verified_binding(cert, subkey)
                {
                    return Some(Issuer {
                        cert,
                        subkey: Some((subkey, binding)),
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
                if &subkey.legacy_key_id() == wanted
                    && let Some(binding) = verified_binding(cert, subkey)
                {
                    return Some(Issuer {
                        cert,
                        subkey: Some((subkey, binding)),
                    });
                }
            }
        }
    }
    None
}

/// The newest binding signature the primary key made over `subkey` that
/// verifies.
fn verified_binding<'a>(
    cert: &'a SignedPublicKey,
    subkey: &'a SignedPublicSubKey,
) -> Option<&'a Signature> {
    subkey
        .signatures
        .iter()
        .filter(|sig| {
            sig.typ() == Some(SignatureType::SubkeyBinding)
                && sig
                    .verify_subkey_binding(&cert.primary_key, &subkey.key)
                    .is_ok()
        })
        .max_by_key(|sig| created_secs(sig))
}

/// The key expiration time a certificate's primary key carries: the newest
/// verified direct-key self-signature that states a lifetime, and, where the
/// certificate carries no such signature, the lifetime the newest verified
/// certification self-signature states.
///
/// A direct-key signature that states a lifetime is what `gpgv` reads.
/// Measured on a certificate carrying both a direct-key and a certification
/// self-signature, with two key-expiration-time subpackets that disagree. The
/// direct-key signature's value answers in both directions: it makes an expired
/// key live and a live key expired. It answers whether it stands older or newer
/// than the certification self-signature. A direct-key signature whose bytes
/// were altered is passed over, and so is one whose key-expiration-time
/// subpacket is absent or zero; the certification self-signature then answers.
///
/// Among the certification self-signatures the newest verified one answers on
/// its own terms, and no older one stands in for it: over a certificate whose
/// newest certification self-signature states a zero lifetime, and again over
/// one whose newest states no lifetime at all, `gpgv` reports `GOODSIG` while
/// an older certification self-signature states a lifetime already past. An
/// altered newest one is passed over, and `gpgv` then reports the expiry the
/// older one states.
fn primary_key_lifetime(cert: &SignedPublicKey) -> Option<u64> {
    let primary = &cert.primary_key;
    let direct = cert
        .details
        .direct_signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::Key) && sig.verify_key(primary).is_ok())
        .filter_map(|sig| Some((created_secs(sig), key_lifetime(sig)?)))
        .max_by_key(|(created, _)| *created);
    if let Some((_, lifetime)) = direct {
        return Some(lifetime);
    }
    cert.details
        .users
        .iter()
        .flat_map(|user| user.signatures.iter().map(move |sig| (user, sig)))
        .filter(|(user, sig)| {
            is_certification(sig)
                && sig
                    .verify_certification(primary, Tag::UserId, &user.id)
                    .is_ok()
        })
        .max_by_key(|(_, sig)| created_secs(sig))
        .and_then(|(_, sig)| key_lifetime(sig))
}

/// Whether a signature is a certification over a user id, which is what a
/// primary key's own key expiration time rides on. A revocation over a user id
/// is a certification of another kind and states no key expiration time.
fn is_certification(sig: &Signature) -> bool {
    matches!(
        sig.typ(),
        Some(
            SignatureType::CertGeneric
                | SignatureType::CertPersona
                | SignatureType::CertCasual
                | SignatureType::CertPositive
        )
    )
}

/// The key lifetime a self-signature states, in seconds after the key creation
/// time. A zero lifetime means no expiry, so it reads as absent, as a zero
/// `gpgv` status field does.
fn key_lifetime(sig: &Signature) -> Option<u64> {
    epoch(sig.key_expiration_time()?.as_secs())
}

/// Whether a verified revocation stands over a user id.
fn user_revoked(cert: &SignedPublicKey, user: &SignedUser) -> bool {
    user.signatures.iter().any(|sig| {
        sig.typ() == Some(SignatureType::CertRevocation)
            && sig
                .verify_certification(&cert.primary_key, Tag::UserId, &user.id)
                .is_ok()
    })
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
///
/// A revoked user id is passed over, and the primary-user-id subpacket on a
/// revoked user id counts for nothing. This is what `gpgv` names on the
/// verdict line: over a certificate whose primary user id is revoked and whose
/// second user id is not, it names the second one. Where every user id is
/// revoked it names a revoked one, so a certificate holding nothing else still
/// reports a user id.
fn reported_user_id(cert: &SignedPublicKey) -> (Option<String>, Option<String>) {
    let mut usable: Vec<&SignedUser> = cert
        .details
        .users
        .iter()
        .filter(|user| !user_revoked(cert, user))
        .collect();
    if usable.is_empty() {
        usable = cert.details.users.iter().collect();
    }
    let user = usable
        .iter()
        .copied()
        .find(|user| user.is_primary())
        .or_else(|| usable.iter().copied().max_by_key(newest_certification));
    match user {
        Some(user) => split_uid(&String::from_utf8_lossy(user.id.id())),
        None => (None, None),
    }
}

/// Split an OpenPGP user id into name and email: the trailing `<address>` is
/// the email and what precedes it is the name. A user id without an address is
/// all name.
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

/// The creation time of the newest certification over a user id.
fn newest_certification(user: &&SignedUser) -> u32 {
    user.signatures
        .iter()
        .filter_map(Signature::created)
        .map(Timestamp::as_secs)
        .max()
        .unwrap_or(0)
}

/// The creation time a signature packet states, with an absent one reading as
/// the epoch, so that a signature stating none is the oldest.
fn created_secs(sig: &Signature) -> u32 {
    sig.created().map(Timestamp::as_secs).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;
    use crate::gpg::{GpgVerifier, STATUS_PREFIX, parse_epoch, scratch_dir};

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
        /// Whether every `gpg` run in this home stands at the instant
        /// [`KEY_CREATED`] names.
        faked: bool,
    }

    impl Fixture {
        /// A new home directory holding one ed25519 signing key for `uid`
        /// that never expires.
        fn new(uid: &str) -> Fixture {
            Fixture::build(uid, "ed25519", false, "never")
        }

        /// The same with an RSA signing key. rPGP refuses a digest weaker than
        /// 256 bits with an Ed25519 key, so the digest policy of the port is
        /// stated over a key whose cryptography admits one.
        fn rsa(uid: &str) -> Fixture {
            Fixture::build(uid, "rsa2048", false, "never")
        }

        /// A new home directory whose key was created at the instant
        /// [`KEY_CREATED`] names and expires after `expiry`. Every `gpg` run
        /// in it stands at that instant, so a signature it makes was made
        /// while the key was live. `gpgv` reads the real clock, which is what
        /// makes an expired key expired.
        fn at(uid: &str, expiry: &str) -> Fixture {
            Fixture::build(uid, "ed25519", true, expiry)
        }

        fn build(uid: &str, algorithm: &str, faked: bool, expiry: &str) -> Fixture {
            use std::os::unix::fs::DirBuilderExt;
            let dir = scratch_dir();
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&dir).unwrap();
            builder.create(dir.join("gv")).unwrap();
            let mut fixture = Fixture {
                dir,
                primary: String::new(),
                faked,
            };
            let status = fixture
                .gpg()
                .args(["--quick-gen-key", uid, algorithm, "sign", expiry])
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
            if self.faked {
                cmd.args(["--faked-system-time", "20250101T000000!"]);
            }
            cmd
        }

        /// The exported secret key, which `gpg` writes unprotected because the
        /// passphrase is empty.
        fn secret_key(&self) -> Vec<u8> {
            let out = self.gpg().arg("--export-secret-keys").output().unwrap();
            assert!(out.status.success() && !out.stdout.is_empty());
            out.stdout
        }

        /// The revocation certificate `gpg` stored when it generated the key,
        /// as the binary key revocation signature packet it holds. The stored
        /// file carries prose before the armored block, and a colon before the
        /// block's first dash so that an accidental import does nothing.
        fn revocation_packet(&self) -> Vec<u8> {
            let text = std::fs::read_to_string(self.revocation_path()).unwrap();
            let at = text.find("-----BEGIN PGP").unwrap();
            let packet = crate::gpg::dearmor(&text.as_bytes()[at..]).unwrap();
            assert_eq!(split_packets(&packet).len(), 1);
            packet
        }

        fn revocation_path(&self) -> PathBuf {
            self.dir
                .join("openpgp-revocs.d")
                .join(format!("{}.rev", self.primary))
        }

        /// Revoke the primary key by importing the revocation certificate
        /// `gpg` stored for it.
        fn revoke_primary(&self) {
            let text = std::fs::read_to_string(self.revocation_path()).unwrap();
            let at = text.find("-----BEGIN PGP").unwrap();
            let path = self.write("revocation.asc", &text.as_bytes()[at..]);
            let status = self.gpg().arg("--import").arg(path).status().unwrap();
            assert!(status.success(), "gpg --import of the revocation failed");
        }

        /// Revoke the first subkey.
        fn revoke_subkey(&self) {
            let out = self
                .gpg()
                .args(["--command-fd", "0", "--edit-key", &self.primary])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    child
                        .stdin
                        .take()
                        .unwrap()
                        .write_all(b"key 1\nrevkey\ny\n1\n\ny\nsave\n")?;
                    child.wait_with_output()
                })
                .unwrap();
            assert!(out.status.success(), "gpg --edit-key revkey failed");
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

        /// Add a signing subkey to the primary key and report its
        /// fingerprint.
        fn add_signing_subkey(&self) -> String {
            self.add_signing_subkey_expiring("never")
        }

        /// The same, with a lifetime for the subkey.
        fn add_signing_subkey_expiring(&self, expiry: &str) -> String {
            let status = self
                .gpg()
                .args(["--quick-add-key", &self.primary, "ed25519", "sign", expiry])
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

    /// Assert one record states what `gpgv` states about the same signature,
    /// field by field, the verdict included. A case that parts from `gpgv` on
    /// purpose states the divergence itself and does not come here.
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
        assert_eq!(port.valid, reference.valid, "valid");
        assert_eq!(port.expired, reference.expired, "expired");
        assert_eq!(port.revoked, reference.revoked, "revoked");
        assert_eq!(port.key_expires, reference.key_expires, "key_expires");
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

    /// The instant `Fixture::at` pins the clock to, in seconds since the Unix
    /// epoch: 2025-01-01T00:00:00Z.
    const KEY_CREATED: u64 = 1735689600;
    /// One day in seconds, the lifetime `1d` states.
    const ONE_DAY: u64 = 24 * 60 * 60;
    /// Ten years in seconds, as `gpg` counts a year at 365 days.
    const TEN_YEARS: u64 = 10 * 365 * ONE_DAY;

    /// The certificates a verifier loads a keyring blob into.
    fn certs_of(keyring: &[u8]) -> Vec<SignedPublicKey> {
        GpgVerifier::from_keyring_bytes([keyring]).unwrap().certs
    }

    /// Split an OpenPGP packet stream into (tag, body) pairs. Both packet
    /// header formats are read, since `gpg` writes the old one and the `pgp`
    /// crate writes the new one.
    fn split_packets(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let ctb = bytes[i];
            assert_eq!(ctb & 0x80, 0x80, "a packet tag byte at offset {i}");
            let (tag, len, header) = if ctb & 0x40 == 0 {
                let tag = (ctb >> 2) & 0x0f;
                match ctb & 0x03 {
                    0 => (tag, usize::from(bytes[i + 1]), 2),
                    1 => (
                        tag,
                        usize::from(u16::from_be_bytes([bytes[i + 1], bytes[i + 2]])),
                        3,
                    ),
                    other => panic!("packet length type {other}"),
                }
            } else {
                let tag = ctb & 0x3f;
                match bytes[i + 1] {
                    first @ 0..=191 => (tag, usize::from(first), 2),
                    first @ 192..=223 => (
                        tag,
                        ((usize::from(first) - 192) << 8) + usize::from(bytes[i + 2]) + 192,
                        3,
                    ),
                    other => panic!("packet length octet {other}"),
                }
            };
            out.push((tag, bytes[i + header..i + header + len].to_vec()));
            i += header + len;
        }
        out
    }

    /// Write (tag, body) pairs back as an OpenPGP packet stream, in the
    /// old header format `gpg` writes.
    fn join_packets(packets: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, body) in packets {
            assert!(*tag < 16, "tag {tag} needs the new header format");
            if body.len() < 256 {
                out.push(0x80 | (tag << 2));
                out.push(body.len() as u8);
            } else {
                out.push(0x80 | (tag << 2) | 1);
                out.extend_from_slice(&(u16::try_from(body.len()).unwrap()).to_be_bytes());
            }
            out.extend_from_slice(body);
        }
        out
    }

    /// Remove the embedded primary-key binding signature -- unhashed
    /// subpacket 32 -- from every subkey binding signature a certificate
    /// carries. The subpacket stands in the unhashed area, so the binding
    /// signature still verifies over what is left, which is what makes the
    /// certificate the shape a stapled subkey has: a binding the primary key
    /// made and no back-signature under it.
    fn strip_backsig(cert: &[u8]) -> Vec<u8> {
        let mut packets = split_packets(cert);
        let mut stripped = 0;
        for (tag, body) in &mut packets {
            if *tag != 2 || body[1] != 0x18 {
                continue;
            }
            let hashed = usize::from(u16::from_be_bytes([body[4], body[5]]));
            let start = 6 + hashed;
            let len = usize::from(u16::from_be_bytes([body[start], body[start + 1]]));
            let area = &body[start + 2..start + 2 + len];
            let mut kept: Vec<u8> = Vec::new();
            let mut i = 0;
            while i < area.len() {
                let (subpacket, header) = match area[i] {
                    first @ 0..=191 => (usize::from(first), 1),
                    first @ 192..=254 => (
                        ((usize::from(first) - 192) << 8) + usize::from(area[i + 1]) + 192,
                        2,
                    ),
                    other => panic!("subpacket length octet {other}"),
                };
                let whole = header + subpacket;
                if area[i + header] & 0x7f == 32 {
                    stripped += 1;
                } else {
                    kept.extend_from_slice(&area[i..i + whole]);
                }
                i += whole;
            }
            let mut new = body[..start].to_vec();
            new.extend_from_slice(&(u16::try_from(kept.len()).unwrap()).to_be_bytes());
            new.extend_from_slice(&kept);
            new.extend_from_slice(&body[start + 2 + len..]);
            *body = new;
        }
        assert_eq!(stripped, 1, "one back-signature was removed");
        join_packets(&packets)
    }

    /// Flip the last byte of the embedded primary-key binding signature --
    /// unhashed subpacket 32 -- in every subkey binding signature a certificate
    /// carries, so that the back-signature stands and verifies against nothing.
    /// The subpacket stands in the unhashed area, so the binding signature
    /// still verifies, which is the shape an attacker who holds no subkey
    /// secret can build over a genuine binding.
    fn alter_backsig(cert: &[u8]) -> Vec<u8> {
        let mut packets = split_packets(cert);
        let mut altered = 0;
        for (tag, body) in &mut packets {
            if *tag != 2 || body[1] != 0x18 {
                continue;
            }
            let hashed = usize::from(u16::from_be_bytes([body[4], body[5]]));
            let start = 6 + hashed;
            let len = usize::from(u16::from_be_bytes([body[start], body[start + 1]]));
            let area = start + 2;
            let mut i = 0;
            while i < len {
                let at = area + i;
                let (subpacket, header) = match body[at] {
                    first @ 0..=191 => (usize::from(first), 1),
                    first @ 192..=254 => (
                        ((usize::from(first) - 192) << 8) + usize::from(body[at + 1]) + 192,
                        2,
                    ),
                    other => panic!("subpacket length octet {other}"),
                };
                let whole = header + subpacket;
                if body[at + header] & 0x7f == 32 {
                    let last = at + whole - 1;
                    body[last] ^= 0xff;
                    altered += 1;
                }
                i += whole;
            }
        }
        assert_eq!(altered, 1, "one back-signature was altered");
        join_packets(&packets)
    }

    /// Splice one packet in right after a certificate's primary key packet,
    /// where a direct-key signature and a key revocation signature stand.
    fn insert_after_primary(cert: &[u8], packet: &[u8]) -> Vec<u8> {
        let mut packets = split_packets(cert);
        assert_eq!(packets[0].0, 6, "the first packet is the primary key");
        let mut inserted = split_packets(packet);
        assert_eq!(inserted.len(), 1);
        packets.insert(1, inserted.remove(0));
        join_packets(&packets)
    }

    /// Attach the first subkey of `donor`, with the binding signature it
    /// carries there, to the end of `host`.
    fn attach_subkey(host: &[u8], donor: &[u8]) -> Vec<u8> {
        let donor = split_packets(donor);
        let at = donor
            .iter()
            .position(|(tag, _)| *tag == 14)
            .expect("the donor holds a subkey");
        assert_eq!(donor[at + 1].0, 2, "the binding signature follows it");
        let mut packets = split_packets(host);
        packets.push(donor[at].clone());
        packets.push(donor[at + 1].clone());
        join_packets(&packets)
    }

    /// Remove one user id, and the signatures that stand under it, from a
    /// certificate.
    fn remove_user_id(cert: &[u8], id: &str) -> Vec<u8> {
        let packets = split_packets(cert);
        let at = packets
            .iter()
            .position(|(tag, body)| *tag == 13 && body == id.as_bytes())
            .expect("the certificate holds the user id");
        let mut end = at + 1;
        while end < packets.len() && packets[end].0 == 2 {
            end += 1;
        }
        let mut kept = packets[..at].to_vec();
        kept.extend_from_slice(&packets[end..]);
        join_packets(&kept)
    }

    /// A direct-key self-signature (type 0x1F) over a primary key, created at
    /// `created` and stating the key lifetime `lifetime`.
    ///
    /// `gpg` 2.4.9 writes the key expiration time into the certification
    /// self-signature alone, so a certificate carrying both statements is
    /// built by signing the direct-key signature here, over the secret key the
    /// same GnuPG home exported.
    fn direct_key_signature(secret: &[u8], created: u64, lifetime: u64) -> Vec<u8> {
        use pgp::packet::{PacketTrait, SignatureConfig, Subpacket, SubpacketData};
        use pgp::types::{Duration, Password};

        let secret_key = pgp::composed::SignedSecretKey::from_bytes(Cursor::new(secret)).unwrap();
        let public = secret_key.primary_key.public_key();
        let mut config = SignatureConfig::v4(
            SignatureType::Key,
            PublicKeyAlgorithm::EdDSALegacy,
            HashAlgorithm::Sha512,
        );
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                u32::try_from(created).unwrap(),
            )))
            .unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(public.fingerprint())).unwrap(),
            Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(
                u32::try_from(lifetime).unwrap(),
            )))
            .unwrap(),
        ];
        config.unhashed_subpackets =
            vec![Subpacket::regular(SubpacketData::IssuerKeyId(public.legacy_key_id())).unwrap()];
        let signature = config
            .sign_key(&secret_key.primary_key, &Password::empty(), public)
            .unwrap();
        let mut bytes = Vec::new();
        signature.to_writer_with_header(&mut bytes).unwrap();
        bytes
    }

    /// A signature by a primary key is valid where the key is live, is not
    /// revoked, and the digest is allowed.
    #[test]
    fn good_primary_key_signature_is_valid() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Good <good@ostrya.example>");
        let keyring = home.keyring();
        let blob = home.sign(&home.primary, PAYLOAD);
        let outcome =
            verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(reference[0].valid);
        assert!(outcome.signatures[0].valid);
        assert!(outcome.valid);
        assert!(!outcome.signatures[0].expired);
        assert!(!outcome.signatures[0].revoked);
        assert_eq!(outcome.signatures[0].key_expires, None);
    }

    /// A signature by a signing subkey is valid where the binding signature
    /// the primary key made carries the back-signature the subkey made.
    #[test]
    fn cross_certified_subkey_signature_is_valid() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Cross <cross@ostrya.example>");
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
        assert!(outcome.signatures[0].valid);
        assert_eq!(outcome.signatures[0].fingerprint.as_deref(), Some(&*subkey));
    }

    /// A subkey stapled onto a certificate signs for nothing. Three shapes
    /// state it: a binding signature the primary key made with the
    /// back-signature removed, the same binding with a back-signature that
    /// stands and verifies against nothing, and a subkey taken from another
    /// certificate together with the binding it carried there. The first two
    /// are what an attacker who holds no subkey secret can produce.
    #[test]
    fn stapled_subkey_is_refused() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Staple <staple@ostrya.example>");
        let subkey = home.add_signing_subkey();
        let whole = home.keyring();
        let blob = home.sign(&subkey, PAYLOAD);
        // The intact certificate is the control: the same signature verifies.
        let control =
            verify_signatures(&certs_of(&whole), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        assert!(control.valid);

        let stripped = strip_backsig(&whole);
        let outcome =
            verify_signatures(&certs_of(&stripped), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&stripped, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(!info.valid);
        assert!(!outcome.valid);
        // The binding signature still verifies, so the subkey is a key the
        // certificate holds; the back-signature is what is missing.
        assert!(!info.key_missing);
        assert_eq!(info.fingerprint.as_deref(), Some(&*subkey));
        assert_eq!(info.user_name, None);

        // The back-signature is present and verifies against nothing. The
        // binding signature still verifies, since the subpacket stands in its
        // unhashed area, so presence alone must not answer for it.
        let bad = alter_backsig(&whole);
        let outcome =
            verify_signatures(&certs_of(&bad), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&bad, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(!outcome.valid);
        assert!(!outcome.signatures[0].key_missing);
        assert_eq!(outcome.signatures[0].fingerprint.as_deref(), Some(&*subkey));
        assert_eq!(outcome.signatures[0].user_name, None);

        // The same subkey attached to another certificate, with the binding
        // signature it carried. The binding does not verify under the other
        // primary key, so the subkey belongs to no loaded certificate.
        let other = Fixture::new("Host <host@ostrya.example>");
        let attached = attach_subkey(&other.keyring(), &whole);
        let outcome =
            verify_signatures(&certs_of(&attached), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = other.gpgv_records(&attached, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(!outcome.valid);
        assert!(outcome.signatures[0].key_missing);
        assert_eq!(
            outcome.signatures[0].fingerprint.as_deref(),
            Some(&*subkey),
            "the fingerprint the signature packet names"
        );
    }

    /// An expired key states the instant it expired and is not valid. The
    /// instant is the key creation time plus the lifetime the self-signature
    /// states.
    #[test]
    fn expired_key_agrees_with_gpgv() {
        if !tools_available() {
            return;
        }
        let home = Fixture::at("Old <old@ostrya.example>", "1d");
        let keyring = home.keyring();
        let blob = home.sign(&home.primary, PAYLOAD);
        let outcome =
            verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(info.expired);
        assert!(!info.valid);
        assert!(!outcome.valid);
        assert_eq!(info.key_expires, Some(KEY_CREATED + ONE_DAY));
        assert_eq!(reference[0].key_expires, Some(KEY_CREATED + ONE_DAY));
        // The signature was made while the key was live, and the key state is
        // read against the current clock, not against that instant.
        assert_eq!(info.created, Some(KEY_CREATED));
    }

    /// A signing subkey does not outlive its certificate. The primary key
    /// below expired and the subkey's binding signature states no expiry of
    /// its own, and `gpgv` reports the primary key's instant.
    #[test]
    fn expired_primary_key_expires_its_subkey() {
        if !tools_available() {
            return;
        }
        let home = Fixture::at("Both <both@ostrya.example>", "1d");
        let subkey = home.add_signing_subkey();
        let keyring = home.keyring();
        let blob = home.sign(&subkey, PAYLOAD);
        let outcome =
            verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(info.expired);
        assert!(!info.valid);
        assert_eq!(info.key_expires, Some(KEY_CREATED + ONE_DAY));
        assert_eq!(info.fingerprint.as_deref(), Some(&*subkey));

        // A subkey that states a lifetime of its own does not outlive the
        // certificate either: the earlier of the two instants answers.
        let later = Fixture::at("Later <later@ostrya.example>", "1d");
        let subkey = later.add_signing_subkey_expiring("10y");
        let keyring = later.keyring();
        let blob = later.sign(&subkey, PAYLOAD);
        let outcome =
            verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = later.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(outcome.signatures[0].expired);
        assert_eq!(
            outcome.signatures[0].key_expires,
            Some(KEY_CREATED + ONE_DAY)
        );
    }

    /// A key expiration time of zero on a direct-key self-signature states no
    /// lifetime, so the certification self-signature answers. The certificate
    /// below states one day there, which has passed, and the direct-key
    /// signature states zero; `gpgv` reports the expiry the one day names.
    #[test]
    fn zero_direct_key_expiration_reads_as_absent() {
        if !tools_available() {
            return;
        }
        let home = Fixture::at("Zero <zero@ostrya.example>", "1d");
        let blob = home.sign(&home.primary, PAYLOAD);
        let secret = home.secret_key();
        let keyring = insert_after_primary(
            &home.keyring(),
            &direct_key_signature(&secret, KEY_CREATED + 10, 0),
        );
        let outcome =
            verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(!info.valid);
        assert!(info.expired);
        assert_eq!(info.key_expires, Some(KEY_CREATED + ONE_DAY));
        // The control states that the direct-key signature is read at all: the
        // same signature stating ten years makes the same key live.
        let live = insert_after_primary(
            &home.keyring(),
            &direct_key_signature(&secret, KEY_CREATED + 10, TEN_YEARS),
        );
        let outcome =
            verify_signatures(&certs_of(&live), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&live, &blob, PAYLOAD);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(outcome.signatures[0].valid);
        assert_eq!(outcome.signatures[0].key_expires, None);
    }

    /// The key expiration time of a primary key comes from the direct-key
    /// self-signature where the certificate carries one that verifies, and
    /// from the certification self-signature otherwise. The three states below
    /// are what `gpgv` answers over the same three certificates.
    #[test]
    fn direct_key_signature_states_the_key_expiry() {
        if !tools_available() {
            return;
        }
        // The certification self-signature states one day, which has passed,
        // and the direct-key signature states ten years.
        let home = Fixture::at("Live <live@ostrya.example>", "1d");
        let blob = home.sign(&home.primary, PAYLOAD);
        let secret = home.secret_key();
        let keyring = insert_after_primary(
            &home.keyring(),
            &direct_key_signature(&secret, KEY_CREATED + 10, TEN_YEARS),
        );
        let outcome =
            verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(
            outcome.signatures[0].valid,
            "the direct-key signature is read"
        );
        assert_eq!(outcome.signatures[0].key_expires, None);

        // A direct-key signature whose bytes were altered verifies against
        // nothing and is passed over, so the certification self-signature
        // answers and the key is expired.
        let mut altered = direct_key_signature(&secret, KEY_CREATED + 10, TEN_YEARS);
        let last = altered.len() - 1;
        altered[last] ^= 0xff;
        let keyring = insert_after_primary(&home.keyring(), &altered);
        let outcome =
            verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(outcome.signatures[0].expired);
        assert_eq!(
            outcome.signatures[0].key_expires,
            Some(KEY_CREATED + ONE_DAY)
        );

        // The certification self-signature states ten years and the direct-key
        // signature states one day, so the key is expired.
        let live = Fixture::at("Dead <dead@ostrya.example>", "10y");
        let blob = live.sign(&live.primary, PAYLOAD);
        let keyring = insert_after_primary(
            &live.keyring(),
            &direct_key_signature(&live.secret_key(), KEY_CREATED + 10, ONE_DAY),
        );
        let outcome =
            verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = live.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(outcome.signatures[0].expired);
        assert!(!outcome.signatures[0].valid);
        assert_eq!(
            outcome.signatures[0].key_expires,
            Some(KEY_CREATED + ONE_DAY)
        );
    }

    /// A revoked primary key is reported revoked and is not valid.
    #[test]
    fn revoked_primary_key_agrees_with_gpgv() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Gone <gone@ostrya.example>");
        let blob = home.sign(&home.primary, PAYLOAD);
        home.revoke_primary();
        let keyring = home.keyring();
        let outcome =
            verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(info.revoked);
        assert!(!info.valid);
        assert!(!outcome.valid);
        // The record still names the key and the user id, which is what the
        // `REVKEYSIG` and `VALIDSIG` pair carries.
        assert_eq!(info.fingerprint.as_deref(), Some(&*home.primary));
        assert_eq!(info.user_email.as_deref(), Some("gone@ostrya.example"));
    }

    /// A revoked signing subkey is reported revoked and is not valid, and its
    /// certificate's primary key is not.
    #[test]
    fn revoked_subkey_agrees_with_gpgv() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("SubGone <subgone@ostrya.example>");
        let subkey = home.add_signing_subkey();
        let by_subkey = home.sign(&subkey, PAYLOAD);
        let by_primary = home.sign(&home.primary, PAYLOAD);
        home.revoke_subkey();
        let keyring = home.keyring();
        let outcome = verify_signatures(
            &certs_of(&keyring),
            PAYLOAD,
            std::slice::from_ref(&by_subkey),
        )
        .unwrap();
        let reference = home.gpgv_records(&keyring, &by_subkey, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(info.revoked);
        assert!(!info.valid);
        assert_eq!(info.fingerprint.as_deref(), Some(&*subkey));
        // The revocation stands over the subkey alone.
        let outcome = verify_signatures(
            &certs_of(&keyring),
            PAYLOAD,
            std::slice::from_ref(&by_primary),
        )
        .unwrap();
        let reference = home.gpgv_records(&keyring, &by_primary, PAYLOAD);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(outcome.signatures[0].valid);
        assert!(!outcome.signatures[0].revoked);
    }

    /// A revoked user id leaves the signature valid and sets no field of its
    /// own. The user id the record names is one that is not revoked, and the
    /// primary-user-id subpacket on a revoked user id counts for nothing.
    /// Where every user id is revoked, a revoked one is named.
    #[test]
    fn revoked_user_id_agrees_with_gpgv() {
        if !tools_available() {
            return;
        }
        const ALPHA: &str = "Alpha <alpha@ostrya.example>";
        const BRAVO: &str = "Bravo <bravo@ostrya.example>";
        let home = Fixture::new(ALPHA);
        home.add_uid(BRAVO);
        home.set_primary_uid(ALPHA);
        home.revoke_uid(ALPHA);
        let keyring = home.keyring();
        let blob = home.sign(&home.primary, PAYLOAD);
        let outcome =
            verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(info.valid);
        assert!(!info.revoked);
        assert_eq!(info.user_email.as_deref(), Some("bravo@ostrya.example"));

        // `gpg` refuses to revoke the last valid user id, so the state where
        // every user id is revoked is reached by removing the other one.
        let alone = remove_user_id(&keyring, BRAVO);
        let outcome =
            verify_signatures(&certs_of(&alone), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&alone, &blob, PAYLOAD);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(outcome.signatures[0].valid);
        assert_eq!(
            outcome.signatures[0].user_email.as_deref(),
            Some("alpha@ostrya.example")
        );
    }

    /// An MD5 data signature is refused. The port and `gpgv` 2.4.9 agree here,
    /// and the port parts from the cryptography under it: rPGP verifies an MD5
    /// signature as good, so the refusal is the port's own policy. GnuPG's
    /// digest policy is configurable and moves between versions, so the port
    /// states its own and the divergence to record is that class rather than a
    /// version number.
    #[test]
    fn md5_data_signature_is_refused() {
        if !tools_available() {
            return;
        }
        let home = Fixture::rsa("Md5 <md5@ostrya.example>");
        let keyring = home.keyring();
        let blob = home.sign_with(&home.primary, PAYLOAD, &["--digest-algo", "MD5"]);
        let outcome =
            verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(!info.valid);
        assert!(!outcome.valid);
        assert_eq!(info.hash_algorithm.as_deref(), Some("MD5"));
        // The digest answered before the key did, so the record carries the
        // signature packet's own fields and no user id, and the key it names
        // is in the keyring.
        assert!(!info.key_missing);
        assert_eq!(info.fingerprint.as_deref(), Some(&*home.primary));
        assert_eq!(info.user_name, None);
        // The same key over the same payload with an allowed digest is valid,
        // so the digest policy is what refused this signature and not the
        // cryptography under it.
        let allowed = home.sign(&home.primary, PAYLOAD);
        let outcome = verify_signatures(&home.certs(), PAYLOAD, &[allowed]).unwrap();
        assert!(outcome.valid);
    }

    /// A SHA-1 data signature is accepted. The port and `gpgv` 2.4.9 agree.
    /// The key is RSA, because rPGP holds a rule of its own over an Ed25519
    /// key: a digest under 256 bits "is too weak for Ed25519", so a SHA-1
    /// signature by an Ed25519 key verifies against nothing. That is a
    /// divergence from `gpgv`, which reports `GOODSIG`, and the case below
    /// states it.
    #[test]
    fn sha1_data_signature_is_accepted() {
        if !tools_available() {
            return;
        }
        let home = Fixture::rsa("Sha1 <sha1@ostrya.example>");
        let keyring = home.keyring();
        let blob = home.sign_with(&home.primary, PAYLOAD, &["--digest-algo", "SHA1"]);
        let outcome =
            verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(reference[0].valid);
        assert!(outcome.signatures[0].valid);
        assert_eq!(
            outcome.signatures[0].hash_algorithm.as_deref(),
            Some("SHA1")
        );

        // The divergence, declared: the same digest with an Ed25519 key. The
        // reference accepts the signature and the port reports it as one that
        // verified against nothing, because rPGP refuses the digest for that
        // algorithm before any policy of the port is reached.
        let eddsa = Fixture::new("Ed <ed@ostrya.example>");
        let ring = eddsa.keyring();
        let blob = eddsa.sign_with(&eddsa.primary, PAYLOAD, &["--digest-algo", "SHA1"]);
        let outcome =
            verify_signatures(&eddsa.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = eddsa.gpgv_records(&ring, &blob, PAYLOAD);
        assert_eq!(reference.len(), 1);
        assert!(reference[0].valid, "the reference accepts it");
        assert!(!outcome.signatures[0].valid, "the port does not");
        assert_eq!(outcome.signatures[0].fingerprint, None);
        assert_eq!(
            outcome.signatures[0].user_email.as_deref(),
            Some("ed@ostrya.example")
        );
    }

    /// A key revocation signature another key made, stapled onto a
    /// certificate, revokes nothing. A revocation is verified before it is
    /// honored, so a packet anyone can attach carries no weight.
    #[test]
    fn a_stapled_revocation_does_not_revoke() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Keep <keep@ostrya.example>");
        let other = Fixture::new("Other <other@ostrya.example>");
        let blob = home.sign(&home.primary, PAYLOAD);
        let keyring = insert_after_primary(&home.keyring(), &other.revocation_packet());
        let certs = certs_of(&keyring);
        // The stapled packet reached the parsed certificate, so it is the
        // verification that refused it and not the parse.
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].details.revocation_signatures.len(), 1);
        let outcome = verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(!outcome.signatures[0].revoked);
        assert!(outcome.signatures[0].valid);
        assert!(outcome.valid);
        // The same packet over the certificate it was made for revokes it.
        let own = other.keyring();
        let own_blob = other.sign(&other.primary, PAYLOAD);
        let revoked = insert_after_primary(&own, &other.revocation_packet());
        let outcome = verify_signatures(
            &certs_of(&revoked),
            PAYLOAD,
            std::slice::from_ref(&own_blob),
        )
        .unwrap();
        assert!(outcome.signatures[0].revoked);
        assert!(!outcome.valid);
    }

    /// A certification self-signature (type 0x13) over the certificate's first
    /// user id, created at `created`, stating the key lifetime `lifetime` where
    /// one is given and carrying no key-expiration-time subpacket where none
    /// is.
    ///
    /// `gpg` 2.4.9 keeps one certification self-signature per user id, so a
    /// certificate carrying two is built by signing the second one here, over
    /// the secret key the same GnuPG home exported.
    fn certification_signature(secret: &[u8], created: u64, lifetime: Option<u64>) -> Vec<u8> {
        use pgp::packet::{PacketTrait, SignatureConfig, Subpacket, SubpacketData};
        use pgp::types::{Duration, Password};

        let secret_key = pgp::composed::SignedSecretKey::from_bytes(Cursor::new(secret)).unwrap();
        let public = secret_key.primary_key.public_key();
        let user = &secret_key.details.users[0];
        let mut config = SignatureConfig::v4(
            SignatureType::CertPositive,
            PublicKeyAlgorithm::EdDSALegacy,
            HashAlgorithm::Sha512,
        );
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                u32::try_from(created).unwrap(),
            )))
            .unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(public.fingerprint())).unwrap(),
        ];
        if let Some(lifetime) = lifetime {
            config.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(
                    u32::try_from(lifetime).unwrap(),
                )))
                .unwrap(),
            );
        }
        config.unhashed_subpackets =
            vec![Subpacket::regular(SubpacketData::IssuerKeyId(public.legacy_key_id())).unwrap()];
        let signature = config
            .sign_certification(
                &secret_key.primary_key,
                &public,
                &Password::empty(),
                Tag::UserId,
                &user.id,
            )
            .unwrap();
        let mut bytes = Vec::new();
        signature.to_writer_with_header(&mut bytes).unwrap();
        bytes
    }

    /// A signature of the class `typ` over one byte of `payload`, which is what
    /// a class the stored blob may not hold looks like. Such a signature is
    /// built here because `gpg` writes a document signature alone.
    fn other_class_signature(secret: &[u8], typ: SignatureType, payload: &[u8]) -> Vec<u8> {
        use pgp::packet::{PacketTrait, SignatureConfig, Subpacket, SubpacketData};
        use pgp::types::{Password, SigningKey};

        let secret_key = pgp::composed::SignedSecretKey::from_bytes(Cursor::new(secret)).unwrap();
        let public = secret_key.primary_key.public_key();
        let mut config =
            SignatureConfig::v4(typ, PublicKeyAlgorithm::EdDSALegacy, HashAlgorithm::Sha512);
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                u32::try_from(KEY_CREATED).unwrap(),
            )))
            .unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(public.fingerprint())).unwrap(),
        ];
        config.unhashed_subpackets =
            vec![Subpacket::regular(SubpacketData::IssuerKeyId(public.legacy_key_id())).unwrap()];
        let mut hasher = config.hash_alg.new_hasher().unwrap();
        hasher.update(&payload[..1]);
        let len = config.hash_signature_data(&mut hasher).unwrap();
        hasher.update(&config.trailer(len).unwrap());
        let hash = hasher.finalize();
        let raw = secret_key
            .primary_key
            .sign(&Password::empty(), config.hash_alg, &hash)
            .unwrap();
        let signature = Signature::from_config(config, [hash[0], hash[1]], raw).unwrap();
        let mut bytes = Vec::new();
        signature.to_writer_with_header(&mut bytes).unwrap();
        bytes
    }

    /// Append one packet to the end of a certificate.
    fn append_packet(cert: &[u8], packet: &[u8]) -> Vec<u8> {
        let mut packets = split_packets(cert);
        let mut extra = split_packets(packet);
        assert_eq!(extra.len(), 1);
        packets.push(extra.remove(0));
        join_packets(&packets)
    }

    /// Flip the last byte of the one signature of class `class` a certificate
    /// carries, so that the signature verifies against nothing.
    fn alter_signature(cert: &[u8], class: u8) -> Vec<u8> {
        let mut packets = split_packets(cert);
        let mut altered = 0;
        for (tag, body) in &mut packets {
            if *tag == 2 && body[0] == 4 && body[1] == class {
                let last = body.len() - 1;
                body[last] ^= 0xff;
                altered += 1;
            }
        }
        assert_eq!(
            altered, 1,
            "one signature of class {class:#04x} was altered"
        );
        join_packets(&packets)
    }

    /// Assert one record states what `gpgv` states about the same signature,
    /// apart from the user id. The status stream carries the user id on the
    /// verdict line for the keywords [`parse_status`] matches, and a case whose
    /// verdict keyword it does not match leaves the reference record without
    /// one; the engine reads the user id off the certificate and reports it.
    fn assert_agrees_but_user_id(port: &SignatureInfo, reference: &SignatureInfo) {
        let mut port = port.clone();
        port.user_name = reference.user_name.clone();
        port.user_email = reference.user_email.clone();
        assert_agrees(&port, reference);
    }

    /// A signature past its own expiry is not valid. `gpgv` reports `EXPSIG`
    /// and no `GOODSIG` for it, and names no field of its own, so the record
    /// carries the instant the signature expires and nothing more.
    #[test]
    fn expired_signature_is_not_valid() {
        if !tools_available() {
            return;
        }
        let home = Fixture::at("Sigexp <sigexp@ostrya.example>", "never");
        let keyring = home.keyring();
        let blob = home.sign_with(&home.primary, PAYLOAD, &["--default-sig-expire", "1d"]);
        let outcome =
            verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees_but_user_id(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(!reference[0].valid, "the reference refuses it");
        assert!(!info.valid);
        assert!(!outcome.valid);
        assert_eq!(info.expires, Some(KEY_CREATED + ONE_DAY));
        // The key itself is live and is not revoked, so the signature's own
        // expiry is what refused it.
        assert!(!info.expired);
        assert!(!info.revoked);
        assert_eq!(info.key_expires, None);
        // The control is the same key over the same payload with no expiry on
        // the signature.
        let fresh = home.sign(&home.primary, PAYLOAD);
        let outcome = verify_signatures(&home.certs(), PAYLOAD, &[fresh]).unwrap();
        assert!(outcome.valid);
        assert_eq!(outcome.signatures[0].expires, None);
    }

    /// A signature of a class other than a document signature is refused. Such
    /// a signature covers one payload byte, so one of them would otherwise
    /// answer for every payload that starts with that byte.
    #[test]
    fn signature_of_another_class_is_refused() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Class <class@ostrya.example>");
        let keyring = home.keyring();
        let secret = home.secret_key();
        for class in [SignatureType::Standalone, SignatureType::Timestamp] {
            let blob = other_class_signature(&secret, class, PAYLOAD);
            let outcome =
                verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
            let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
            assert_eq!(outcome.signatures.len(), 1);
            assert_eq!(reference.len(), 1);
            assert_agrees(&outcome.signatures[0], &reference[0]);
            let info = &outcome.signatures[0];
            assert!(!info.valid, "{class:?}");
            assert!(!outcome.valid);
            // The key is in the keyring and the record names it, so the class
            // is what refused the signature.
            assert!(!info.key_missing);
            assert_eq!(info.fingerprint.as_deref(), Some(&*home.primary));
            assert_eq!(info.user_name, None);
            // The same signature over another payload that starts with the same
            // byte is refused as well.
            let other = b"ostrya other payload".to_vec();
            assert_eq!(other[0], PAYLOAD[0]);
            let outcome = verify_signatures(&home.certs(), &other, &[blob]).unwrap();
            assert!(!outcome.valid, "{class:?} over another payload");
        }
        // The control is a document signature by the same key, which is valid.
        let blob = home.sign(&home.primary, PAYLOAD);
        assert!(
            verify_signatures(&home.certs(), PAYLOAD, &[blob])
                .unwrap()
                .valid
        );
    }

    /// An MD5 data signature whose issuer no loaded certificate holds is
    /// refused, and the record names the absent key. The digest policy cannot
    /// be reached around: a record no key answered for is never valid.
    #[test]
    fn md5_signature_with_an_unknown_issuer_is_refused() {
        if !tools_available() {
            return;
        }
        let signer = Fixture::rsa("Md5x <md5x@ostrya.example>");
        let other = Fixture::new("Other <other@ostrya.example>");
        let blob = signer.sign_with(&signer.primary, PAYLOAD, &["--digest-algo", "MD5"]);
        let outcome =
            verify_signatures(&other.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = signer.gpgv_records(&other.keyring(), &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(!info.valid);
        assert!(info.key_missing);
        assert_eq!(info.hash_algorithm.as_deref(), Some("MD5"));
    }

    /// A key stands live at the instant it expires and expires from the second
    /// after it. Polled second by second across its expiry instant, `gpgv`
    /// reports `GOODSIG` through that instant and `EXPKEYSIG` from the next
    /// second. The pair of certificates below states both sides of that
    /// boundary, and the run is repeated where the clock moved while it was
    /// being read.
    #[test]
    fn a_key_stands_live_at_the_instant_it_expires() {
        if !tools_available() {
            return;
        }
        let home = Fixture::at("Edge <edge@ostrya.example>", "10y");
        let keyring = home.keyring();
        let blob = home.sign(&home.primary, PAYLOAD);
        let secret = home.secret_key();
        for _ in 0..5 {
            let instant = now();
            let at = insert_after_primary(
                &keyring,
                &direct_key_signature(&secret, KEY_CREATED + 10, instant - KEY_CREATED),
            );
            let before = insert_after_primary(
                &keyring,
                &direct_key_signature(&secret, KEY_CREATED + 10, instant - KEY_CREATED - 1),
            );
            let live = verify_signatures(&certs_of(&at), PAYLOAD, std::slice::from_ref(&blob))
                .unwrap()
                .signatures
                .remove(0);
            let live_reference = home.gpgv_records(&at, &blob, PAYLOAD).remove(0);
            let past = verify_signatures(&certs_of(&before), PAYLOAD, std::slice::from_ref(&blob))
                .unwrap()
                .signatures
                .remove(0);
            let past_reference = home.gpgv_records(&before, &blob, PAYLOAD).remove(0);
            if now() != instant {
                // The second turned over while the four records were read, so
                // they state nothing about the boundary.
                continue;
            }
            assert_agrees(&live, &live_reference);
            assert_agrees(&past, &past_reference);
            assert!(!live.expired, "live at the instant it expires");
            assert!(live.valid);
            assert_eq!(live.key_expires, None);
            assert!(past.expired, "expired one second after");
            assert!(!past.valid);
            assert_eq!(past.key_expires, Some(instant - 1));
            return;
        }
        panic!("the clock turned over on every attempt");
    }

    /// The newest certification self-signature that verifies states the key
    /// expiry on its own terms. An older one does not stand in for it where it
    /// states no lifetime, and an altered newest one is passed over.
    #[test]
    fn the_newest_certification_self_signature_states_the_key_expiry() {
        if !tools_available() {
            return;
        }
        /// What each certificate states, and whether the key is then expired.
        struct Case {
            /// The lifetime the fixture's own self-signature states.
            first: &'static str,
            /// The lifetime the spliced newer self-signature states, in
            /// seconds, or `None` for a signature carrying no lifetime.
            second: Option<u64>,
            /// Whether the newer self-signature's bytes are altered.
            altered: bool,
            /// The instant the key expires, absent where it does not.
            expires: Option<u64>,
        }
        let cases = [
            // The newest self-signature answers, in both directions.
            Case {
                first: "10y",
                second: Some(ONE_DAY),
                altered: false,
                expires: Some(KEY_CREATED + ONE_DAY),
            },
            Case {
                first: "1d",
                second: Some(TEN_YEARS),
                altered: false,
                expires: None,
            },
            // A zero lifetime and an absent one both state no expiry, and the
            // older self-signature does not answer in place of either.
            Case {
                first: "1d",
                second: Some(0),
                altered: false,
                expires: None,
            },
            Case {
                first: "1d",
                second: None,
                altered: false,
                expires: None,
            },
            // An altered newest self-signature verifies against nothing, so the
            // older one answers.
            Case {
                first: "1d",
                second: Some(TEN_YEARS),
                altered: true,
                expires: Some(KEY_CREATED + ONE_DAY),
            },
        ];
        for (index, case) in cases.iter().enumerate() {
            let home = Fixture::at(
                &format!("Cert{index} <cert{index}@ostrya.example>"),
                case.first,
            );
            let blob = home.sign(&home.primary, PAYLOAD);
            let mut newer =
                certification_signature(&home.secret_key(), KEY_CREATED + 20, case.second);
            if case.altered {
                let last = newer.len() - 1;
                newer[last] ^= 0xff;
            }
            let keyring = append_packet(&home.keyring(), &newer);
            let outcome =
                verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob))
                    .unwrap();
            let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
            assert_eq!(reference.len(), 1, "case {index}");
            assert_agrees(&outcome.signatures[0], &reference[0]);
            let info = &outcome.signatures[0];
            assert_eq!(info.key_expires, case.expires, "case {index}");
            assert_eq!(info.expired, case.expires.is_some(), "case {index}");
            assert_eq!(info.valid, case.expires.is_none(), "case {index}");
        }
    }

    /// A subkey revocation that verifies against nothing revokes nothing, so
    /// the subkey still speaks for its certificate. The revocation the
    /// certificate carries is altered, which is what an attacker who cannot
    /// make the primary key's signatures can produce.
    #[test]
    fn an_altered_subkey_revocation_does_not_revoke() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("SubAlt <subalt@ostrya.example>");
        let subkey = home.add_signing_subkey();
        let blob = home.sign(&subkey, PAYLOAD);
        home.revoke_subkey();
        let revoked = home.keyring();
        // The control states that the intact revocation is honored.
        let outcome =
            verify_signatures(&certs_of(&revoked), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        assert!(outcome.signatures[0].revoked);
        assert!(!outcome.valid);

        let altered = alter_signature(&revoked, 0x28);
        let outcome =
            verify_signatures(&certs_of(&altered), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&altered, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(!outcome.signatures[0].revoked);
        assert!(outcome.signatures[0].valid);
        assert_eq!(outcome.signatures[0].fingerprint.as_deref(), Some(&*subkey));
    }

    /// A signature expires at the instant it names. Polled second by second
    /// across its expiry instant, `gpgv` reports `GOODSIG` through the second
    /// before that instant and `EXPSIG` from the instant on. The pair of
    /// signatures below states both sides of the boundary, and the run is
    /// repeated where the clock moved while it was being read.
    #[test]
    fn a_signature_expires_at_the_instant_it_names() {
        if !tools_available() {
            return;
        }
        let home = Fixture::at("Sedge <sedge@ostrya.example>", "never");
        let keyring = home.keyring();
        for _ in 0..5 {
            let instant = now();
            let at = home.sign_with(
                &home.primary,
                PAYLOAD,
                &[
                    "--default-sig-expire",
                    &format!("seconds={}", instant - KEY_CREATED),
                ],
            );
            let later = home.sign_with(
                &home.primary,
                PAYLOAD,
                &[
                    "--default-sig-expire",
                    &format!("seconds={}", instant - KEY_CREATED + 1),
                ],
            );
            let gone = verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&at))
                .unwrap()
                .signatures
                .remove(0);
            let gone_reference = home.gpgv_records(&keyring, &at, PAYLOAD).remove(0);
            let live = verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&later))
                .unwrap()
                .signatures
                .remove(0);
            let live_reference = home.gpgv_records(&keyring, &later, PAYLOAD).remove(0);
            if now() != instant {
                // The second turned over while the four records were read, so
                // they state nothing about the boundary.
                continue;
            }
            assert_eq!(gone.expires, Some(instant));
            assert_eq!(live.expires, Some(instant + 1));
            assert_agrees_but_user_id(&gone, &gone_reference);
            assert_agrees(&live, &live_reference);
            assert!(!gone.valid, "expired at the instant it names");
            assert!(live.valid, "live one second before that instant");
            return;
        }
        panic!("the clock turned over on every attempt");
    }

    /// Parse the machine-readable status stream of one `gpgv` run into
    /// per-signature records. Each `NEWSIG` starts a record; the verdict
    /// keywords and the `VALIDSIG` and `ERRSIG` detail lines fill it.
    ///
    /// This is the reference reader the cases above compare the engine
    /// against, so it states what `gpgv` reports in the same shape the engine
    /// answers in.
    fn parse_status(stdout: &[u8]) -> Vec<SignatureInfo> {
        let text = String::from_utf8_lossy(stdout);
        let mut infos: Vec<SignatureInfo> = Vec::new();
        let mut current: Option<SignatureInfo> = None;
        for line in text.lines() {
            let Some(rest) = line.strip_prefix(STATUS_PREFIX) else {
                continue;
            };
            let mut fields = rest.split(' ');
            let keyword = fields.next().unwrap_or("");
            match keyword {
                "NEWSIG" => {
                    if let Some(info) = current.take() {
                        infos.push(info);
                    }
                    current = Some(SignatureInfo::default());
                }
                "GOODSIG" | "EXPKEYSIG" | "REVKEYSIG" | "BADSIG" => {
                    let info = current.get_or_insert_with(SignatureInfo::default);
                    let _keyid = fields.next();
                    let uid = fields.collect::<Vec<_>>().join(" ");
                    let (name, email) = split_uid(&uid);
                    info.user_name = name;
                    info.user_email = email;
                    match keyword {
                        "GOODSIG" => info.valid = true,
                        "EXPKEYSIG" => info.expired = true,
                        "REVKEYSIG" => info.revoked = true,
                        _ => {}
                    }
                }
                // VALIDSIG <fpr> <date> <sig-epoch> <sig-expire-epoch> <version>
                //          <reserved> <pk-algo> <hash-algo> <class> [<primary-fpr>]
                "VALIDSIG" => {
                    let info = current.get_or_insert_with(SignatureInfo::default);
                    let fpr = fields.next().map(str::to_owned);
                    let _date = fields.next();
                    info.created = fields.next().and_then(parse_epoch);
                    info.expires = fields.next().and_then(parse_epoch);
                    let _version = fields.next();
                    let _reserved = fields.next();
                    info.pubkey_algorithm = fields.next().map(pubkey_algo_name);
                    info.hash_algorithm = fields.next().map(hash_algo_name);
                    let _class = fields.next();
                    info.primary_fingerprint =
                        fields.next().map(str::to_owned).or_else(|| fpr.clone());
                    info.fingerprint = fpr;
                }
                // ERRSIG <keyid> <pk-algo> <hash-algo> <class> <epoch> <rc> <fpr>
                "ERRSIG" => {
                    let info = current.get_or_insert_with(SignatureInfo::default);
                    let _keyid = fields.next();
                    info.pubkey_algorithm = fields.next().map(pubkey_algo_name);
                    info.hash_algorithm = fields.next().map(hash_algo_name);
                    let _class = fields.next();
                    info.created = fields.next().and_then(parse_epoch);
                    let _rc = fields.next();
                    info.fingerprint = fields.next().filter(|f| *f != "-").map(str::to_owned);
                }
                "NO_PUBKEY" => {
                    current
                        .get_or_insert_with(SignatureInfo::default)
                        .key_missing = true;
                }
                "KEYEXPIRED" => {
                    let info = current.get_or_insert_with(SignatureInfo::default);
                    info.key_expires = fields.next().and_then(parse_epoch);
                }
                _ => {}
            }
        }
        if let Some(info) = current.take() {
            infos.push(info);
        }
        infos
    }

    /// The OpenPGP public-key algorithm name for a status-line algorithm id.
    fn pubkey_algo_name(id: &str) -> String {
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

    /// The OpenPGP hash algorithm name for a status-line algorithm id.
    fn hash_algo_name(id: &str) -> String {
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

    #[test]
    fn reference_reads_a_good_signature_group() {
        let status = b"[GNUPG:] NEWSIG\n\
[GNUPG:] KEY_CONSIDERED A8F57B71FCDE8767005FED7BD1960140B3A73EF1 0\n\
[GNUPG:] SIG_ID JFFMsT+jReslGyUGdsIHB0VWYmc 2026-07-23 1784843948\n\
[GNUPG:] GOODSIG D1960140B3A73EF1 Ostrya Obs <obs@ostrya.example>\n\
[GNUPG:] VALIDSIG A8F57B71FCDE8767005FED7BD1960140B3A73EF1 2026-07-23 1784843948 0 4 0 22 10 00 A8F57B71FCDE8767005FED7BD1960140B3A73EF1\n\
[GNUPG:] TRUST_ULTIMATE 0 pgp\n";
        let infos = parse_status(status);
        assert_eq!(infos.len(), 1);
        let info = &infos[0];
        assert!(info.valid);
        assert_eq!(
            info.fingerprint.as_deref(),
            Some("A8F57B71FCDE8767005FED7BD1960140B3A73EF1")
        );
        assert_eq!(
            info.primary_fingerprint.as_deref(),
            Some("A8F57B71FCDE8767005FED7BD1960140B3A73EF1")
        );
        assert_eq!(info.created, Some(1_784_843_948));
        assert_eq!(info.expires, None);
        assert_eq!(info.pubkey_algorithm.as_deref(), Some("EdDSA"));
        assert_eq!(info.hash_algorithm.as_deref(), Some("SHA512"));
        assert_eq!(info.user_name.as_deref(), Some("Ostrya Obs"));
        assert_eq!(info.user_email.as_deref(), Some("obs@ostrya.example"));
        assert!(!info.expired && !info.revoked && !info.key_missing);
    }

    #[test]
    fn reference_reads_a_missing_key_group() {
        let status = b"[GNUPG:] NEWSIG\n\
[GNUPG:] ERRSIG D1960140B3A73EF1 22 10 00 1784843948 9 A8F57B71FCDE8767005FED7BD1960140B3A73EF1\n\
[GNUPG:] NO_PUBKEY D1960140B3A73EF1\n";
        let infos = parse_status(status);
        assert_eq!(infos.len(), 1);
        let info = &infos[0];
        assert!(!info.valid);
        assert!(info.key_missing);
        assert_eq!(
            info.fingerprint.as_deref(),
            Some("A8F57B71FCDE8767005FED7BD1960140B3A73EF1")
        );
        assert_eq!(info.created, Some(1_784_843_948));
        assert_eq!(info.pubkey_algorithm.as_deref(), Some("EdDSA"));
        assert_eq!(info.hash_algorithm.as_deref(), Some("SHA512"));
    }

    #[test]
    fn reference_reads_a_bad_signature_group() {
        let status = b"[GNUPG:] NEWSIG\n\
[GNUPG:] KEY_CONSIDERED A8F57B71FCDE8767005FED7BD1960140B3A73EF1 0\n\
[GNUPG:] BADSIG D1960140B3A73EF1 Ostrya Obs <obs@ostrya.example>\n";
        let infos = parse_status(status);
        assert_eq!(infos.len(), 1);
        assert!(!infos[0].valid);
        assert!(!infos[0].key_missing);
        assert_eq!(infos[0].user_email.as_deref(), Some("obs@ostrya.example"));
    }

    #[test]
    fn reference_reads_an_expired_key_group() {
        let status = b"[GNUPG:] NEWSIG\n\
[GNUPG:] KEY_CONSIDERED 6AD5971478704B77113ADBB848D090AA43A2A526 0\n\
[GNUPG:] KEYEXPIRED 1704153600\n\
[GNUPG:] SIG_ID +XcyGaLbMGu3b/KdjZwUEMjugoA 2024-01-01 1704070800\n\
[GNUPG:] EXPKEYSIG 48D090AA43A2A526 Expired <exp@ostrya.example>\n\
[GNUPG:] VALIDSIG 6AD5971478704B77113ADBB848D090AA43A2A526 2024-01-01 1704070800 0 4 0 22 10 00 6AD5971478704B77113ADBB848D090AA43A2A526\n";
        let infos = parse_status(status);
        assert_eq!(infos.len(), 1);
        let info = &infos[0];
        assert!(!info.valid);
        assert!(info.expired);
        assert_eq!(info.key_expires, Some(1_704_153_600));
        assert_eq!(info.created, Some(1_704_070_800));
    }

    #[test]
    fn reference_reads_a_revoked_key_group() {
        let status = b"[GNUPG:] NEWSIG\n\
[GNUPG:] KEY_CONSIDERED 159446FE5B9606A44046DCE5A3106528346CA760 0\n\
[GNUPG:] SIG_ID 9+MSlwFSpYu41OSggWc6zYgnd5Y 2026-07-23 1784844103\n\
[GNUPG:] REVKEYSIG A3106528346CA760 Obs Two <obs2@ostrya.example>\n\
[GNUPG:] VALIDSIG 159446FE5B9606A44046DCE5A3106528346CA760 2026-07-23 1784844103 0 4 0 22 10 00 159446FE5B9606A44046DCE5A3106528346CA760\n";
        let infos = parse_status(status);
        assert_eq!(infos.len(), 1);
        assert!(!infos[0].valid);
        assert!(infos[0].revoked);
    }

    #[test]
    fn reference_reads_two_signature_groups() {
        let status = b"[GNUPG:] NEWSIG\n\
[GNUPG:] GOODSIG A3106528346CA760 Obs Two <obs2@ostrya.example>\n\
[GNUPG:] VALIDSIG 159446FE5B9606A44046DCE5A3106528346CA760 2026-07-23 1784844103 0 4 0 22 10 00 159446FE5B9606A44046DCE5A3106528346CA760\n\
[GNUPG:] NEWSIG\n\
[GNUPG:] ERRSIG A6E1C7D5D3E3ECB2 22 10 00 1784844139 9 778742FE807AADB2F6419736A6E1C7D5D3E3ECB2\n\
[GNUPG:] NO_PUBKEY A6E1C7D5D3E3ECB2\n";
        let infos = parse_status(status);
        assert_eq!(infos.len(), 2);
        assert!(infos[0].valid);
        assert!(!infos[1].valid);
        assert!(infos[1].key_missing);
    }

    #[test]
    fn reference_reads_an_empty_status_as_no_records() {
        assert!(parse_status(b"").is_empty());
        assert!(parse_status(b"gpgv: verification error\n").is_empty());
    }

    #[test]
    fn splits_uids() {
        assert_eq!(
            split_uid("Ostrya Obs <obs@ostrya.example>"),
            (
                Some("Ostrya Obs".to_owned()),
                Some("obs@ostrya.example".to_owned())
            )
        );
        assert_eq!(
            split_uid("no-address"),
            (Some("no-address".to_owned()), None)
        );
        assert_eq!(
            split_uid("<only@address>"),
            (None, Some("only@address".to_owned()))
        );
    }
}
