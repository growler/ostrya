//! The in-process OpenPGP signature engine. It verifies the signatures of a
//! stored signature blob. It reports what the certificate and the signature
//! packet state about each signature.
//!
//! [`verify_signatures`] takes the certificates that a
//! [`GpgVerifier`](super::GpgVerifier) loaded, the signed payload, and the
//! `aay` blobs stored under `ostree.gpgsigs`. It reports one [`SignatureInfo`]
//! for each signature packet. The `GpgVerifier` type doc states the rules that
//! a caller sees, under `# Verdict` and `# Limits of a stored blob`.
//!
//! The engine also owns the trust and validity policy:
//!
//! - the signature classes and the digest algorithms that a data signature can
//!   use
//! - the conditions in which a subkey speaks for its certificate
//! - the instant at which a key expires
//! - the conditions in which a key is revoked.
//!
//! The doc of each rule names the `gpgv` 2.4.9 behavior that the rule
//! reproduces. The behavior was observed in an isolated `GNUPGHOME`, on
//! fixtures that the unit tests build.

use std::io::Cursor;

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{PublicKey, Signature, SignatureType, SubpacketData};
use pgp::types::{Fingerprint, KeyDetails, SignedUser, Tag, Timestamp};

use ostrya_sign::{Error, Result};

use crate::sign::{SignatureInfo, VerifyOutcome};

/// The maximum size of one stored signature blob. The parser reads the whole
/// blob in memory. One detached signature is a few hundred bytes, so one
/// mebibyte holds thousands of them.
const MAX_SIGNATURE_BLOB: usize = 1024 * 1024;
/// The maximum number of signature packets in one blob. A commit carries a few
/// signatures. The limit bounds the parser work and the public-key operations
/// that a blob from the detached metadata of a pulled commit can cause.
const MAX_SIGNATURE_PACKETS: usize = 64;

/// Reports on each signature in `blobs`, over `payload`, against the
/// certificates in `certs`.
///
/// [`VerifyOutcome::valid`] is the OR of the flags of all signatures. One valid
/// signature among several makes the outcome valid.
///
/// The work is public-key cryptography over untrusted input, so it runs on the
/// blocking pool. [`Verifier::verify`](crate::sign::Verifier::verify) for
/// [`GpgVerifier`](super::GpgVerifier) calls this function there.
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

/// Reports on each signature in one blob. `subject` names the blob, so a
/// refusal states which blob reached which limit.
///
/// A blob is untrusted input. The parse and the public-key operations run
/// inside [`std::panic::catch_unwind`]. A caught panic reads as a blob that the
/// parser rejects. This containment has two limits:
///
/// - If the final binary is built with `panic = "abort"`, `catch_unwind`
///   catches nothing.
/// - `catch_unwind` does not find a parser that returns a wrong answer with no
///   panic.
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
        // If the parser reads no whole signature packet from a blob, this
        // function reports no record for it. This is true if the packet stream
        // does not open, and also if the first packet is incomplete. The caller
        // gives such a blob one record, so the record count follows the blob
        // count.
        let Ok(signatures) = DetachedSignature::from_bytes_many(Cursor::new(blob)) else {
            return Ok(infos);
        };
        for signature in signatures {
            // Each packet that the parser read whole keeps its record. The
            // stream stops at the first packet that is not whole. The parser
            // reads each packet before the limit test, so the limit refuses a
            // blob only on a whole packet. If a blob holds the limit and ends
            // in a partial packet, it reports the whole packets and stops.
            let Ok(signature) = signature else { break };
            if infos.len() == MAX_SIGNATURE_PACKETS {
                return Err(Error::Signature(format!(
                    "{subject} holds more than {MAX_SIGNATURE_PACKETS} signature packets"
                )));
            }
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

/// Reports on one signature packet.
///
/// Six outcomes carry four sets of fields:
///
/// - If no certificate holds the issuer, the record holds the fields of the
///   packet itself and `key_missing`.
/// - Three outcomes give the same fields without `key_missing`. They are a
///   class that is not a document signature, a digest algorithm that the
///   policy refuses, and a signing subkey without cross-certification.
/// - If the issuer resolves and the cryptography fails, the record holds the
///   resolved signing key, its certificate, and the user id of the
///   certificate. It holds no other claim of the packet, because nothing else
///   was checked.
/// - If a resolved key verifies the signature, the record holds the signing
///   key, its certificate, and the user id of the certificate. It also holds
///   the result of the validity policy.
fn describe(
    certs: &[SignedPublicKey],
    payload: &[u8],
    signature: &DetachedSignature,
) -> SignatureInfo {
    let sig = &signature.signature;
    let mut info = SignatureInfo::default();
    // The issuer resolves first, because `gpgv` answers in this order. Over an
    // MD5 data signature whose issuer no loaded keyring holds, `gpgv` reports
    // `ERRSIG <keyid> 1 1 00 <created> 9 <fingerprint>` and `NO_PUBKEY`. It
    // names the digest as the cause only if the issuer resolved. No later rule
    // can make such a record valid. So a refused digest and a refused class
    // stay refused on every path.
    let Some(issuers) = resolve_issuers(certs, sig) else {
        info.key_missing = true;
        describe_packet(&mut info, sig);
        return info;
    };
    // The fields that follow name one key and one certificate. The
    // cross-certification rule reads one binding. All of them read the first
    // match.
    let issuer = issuers.reported();
    // Over a class 0x02 signature, `gpgv` reports
    // `ERRSIG <keyid> 22 10 02 <created> 32 <fingerprint>` and no user id.
    // Over a class 0x00 signature by the same key over the same payload, it
    // reports `GOODSIG`.
    if !is_data_signature(sig) {
        describe_packet(&mut info, sig);
        return info;
    }
    // Over an MD5 data signature by a key in its keyring, `gpgv` reports
    // `ERRSIG <keyid> 22 1 00 <created> 5 <fingerprint>` and "Invalid digest
    // algorithm". So it names the fields of the signature packet and no user
    // id.
    if !digest_allowed(sig) {
        describe_packet(&mut info, sig);
        return info;
    }
    // A signing subkey that the primary key did not cross-certify signs for
    // nothing. Over the same certificate without the back-signature, `gpgv`
    // reports `ERRSIG <keyid> 22 10 00 <created> 1 <fingerprint>`, "signing
    // subkey ... is not cross-certified", and no `NO_PUBKEY`. Over the intact
    // certificate, it reports `GOODSIG`.
    if !issuer.cross_certified() {
        describe_packet(&mut info, sig);
        return info;
    }
    let (user_name, user_email) = reported_user_id(issuer.cert);
    info.user_name = user_name;
    info.user_email = user_email;
    // The record names the signing key that the lookup resolved, and the
    // certificate that holds it, on both paths. So a signature that the
    // cryptography refuses states which key made it. `sign --delete` finds it
    // by the key id or the fingerprint of either key.
    //
    // `ostree` 2026.1 names both keys over a commit whose payload changed. A
    // signature by a subkey gets `key ID <subkey-key-id>`, the key id of the
    // subkey, with `Primary key ID <primary-key-id>` under it. Its
    // `gpg-sign --delete` removes such a signature by the key id or the
    // fingerprint of either key.
    //
    // Each value comes from the key that the lookup resolved. So a packet
    // cannot name a key of its own choice. Each value is a whole fingerprint,
    // also if the signature named its issuer by eight bytes only.
    info.fingerprint = Some(format!("{:X}", issuer.fingerprint()));
    info.primary_fingerprint = Some(format!("{:X}", issuer.cert.fingerprint()));
    if !issuer.verify(signature, payload) {
        return info;
    }
    info.created = created_at(sig);
    info.expires = expires_at(sig);
    info.pubkey_algorithm = pubkey_algorithm_name(sig);
    info.hash_algorithm = hash_algorithm_name(sig);
    let now = now();
    // `gpgv` reports an expired key as `EXPKEYSIG` with `KEYEXPIRED <instant>`.
    // It reports a revoked key as `REVKEYSIG`. In both cases it prints the
    // `VALIDSIG` detail line, so both records carry the fields set so far.
    // Neither case is `GOODSIG`, so neither record is valid.
    //
    // A key is live at the instant it expires, and expires from the next
    // second. In a poll of each second across the expiry instant, `gpgv`
    // reports `GOODSIG` through that instant and `EXPKEYSIG` from the next
    // second.
    let key_expires = issuers.key_expires_at();
    if key_expires.is_some_and(|instant| instant < now) {
        info.expired = true;
        info.key_expires = key_expires;
    }
    info.revoked = issuers.revoked();
    // For a signature after its own expiry, `gpgv` reports `EXPSIG` and no
    // `GOODSIG`. So the signature is not valid, and no status keyword states
    // more about it. The signature expires at the instant that it names. In a
    // poll of each second across that instant, `gpgv` reports `GOODSIG`
    // through the second before it, and `EXPSIG` from the instant on.
    let signature_expired = info.expires.is_some_and(|instant| instant <= now);
    info.valid = !signature_expired && !info.expired && !info.revoked;
    info
}

/// Fills the fields that a signature packet states about itself.
///
/// The fields are the issuer fingerprint that the packet names, its creation
/// time, and the two algorithm names. `ERRSIG` carries these fields. If no key
/// answers for the signature, the record holds only these fields.
fn describe_packet(info: &mut SignatureInfo, sig: &Signature) {
    info.fingerprint = sig.issuer_fingerprint().first().map(|f| format!("{f:X}"));
    info.created = created_at(sig);
    info.pubkey_algorithm = pubkey_algorithm_name(sig);
    info.hash_algorithm = hash_algorithm_name(sig);
}

/// Returns `true` if a signature is over a document.
///
/// A stored blob can hold only this class. The two document classes are the
/// binary class and the text class. `gpgv` 2.4.9 refuses every other class.
/// Over a class 0x02 signature and over a class 0x40 signature, it reports
/// "Invalid signature class" and no `GOODSIG`. Such a signature covers one
/// payload byte. Without this refusal, one such signature answers for every
/// payload that starts with that byte.
fn is_data_signature(sig: &Signature) -> bool {
    matches!(sig.typ(), Some(SignatureType::Binary | SignatureType::Text))
}

/// Returns `true` if the digest algorithm of a data signature is allowed.
///
/// The policy refuses MD5 and accepts SHA-1. `gpgv` 2.4.9 gives the same
/// answers on a data signature. For an MD5 signature, it reports
/// `ERRSIG ... 5` and "Note: signatures using the MD5 algorithm are rejected".
/// For a SHA-1 signature, it reports `GOODSIG`.
///
/// The policy belongs to ostrya. The GnuPG policy is configurable and changes
/// between versions. So the divergence to record is a class of difference,
/// with no version number.
fn digest_allowed(sig: &Signature) -> bool {
    sig.hash_alg() != Some(HashAlgorithm::Md5)
}

/// Returns the instant for the policy checks, in seconds since the Unix epoch.
/// A clock before the epoch reads as the epoch.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The key that a signature names as its issuer: a certificate, and the
/// subkey of it that signed, if a subkey signed.
#[derive(Clone, Copy)]
struct Issuer<'a> {
    cert: &'a SignedPublicKey,
    /// The subkey that signed, with the newest binding signature that the
    /// primary key made over it.
    subkey: Option<(&'a SignedPublicSubKey, &'a Signature)>,
}

impl Issuer<'_> {
    /// Returns the fingerprint of the signing key. If a subkey signed, this is
    /// the fingerprint of the subkey. If not, it is that of the primary key.
    fn fingerprint(&self) -> Fingerprint {
        match self.subkey {
            Some((subkey, _)) => subkey.fingerprint(),
            None => self.cert.fingerprint(),
        }
    }

    /// Returns `true` if the signing key verifies `signature` over `payload`.
    fn verify(&self, signature: &DetachedSignature, payload: &[u8]) -> bool {
        match self.subkey {
            Some((subkey, _)) => signature.verify(subkey, payload).is_ok(),
            None => signature.verify(self.cert, payload).is_ok(),
        }
    }

    /// Returns `true` if the signing key is cross-certified.
    ///
    /// The binding signature of a subkey must carry an embedded primary-key
    /// binding signature (the back-signature). The subkey itself makes the
    /// back-signature over the primary key. A primary key that signed for
    /// itself needs no back-signature.
    ///
    /// This check stops a subkey stapled onto a trusted certificate from
    /// speaking for that certificate. `verify_subkey_binding` of rPGP reads
    /// only the binding signature. A separate `verify_primary_key_binding` call
    /// verifies the back-signature, which is the embedded signature of the
    /// binding. The requirement applies to each subkey that made a data
    /// signature, for all key flags on its binding.
    fn cross_certified(&self) -> bool {
        let Some((subkey, binding)) = self.subkey else {
            return true;
        };
        binding.embedded_signature().is_some_and(|back| {
            back.verify_primary_key_binding(&subkey.key, &self.cert.primary_key)
                .is_ok()
        })
    }

    /// Returns `true` if this certificate revokes the signing key.
    ///
    /// Two revocation sites apply, each with its own reach:
    ///
    /// - A key revocation signature over the primary key revokes the whole
    ///   certificate. So no key that the certificate binds speaks for it, and
    ///   this includes the signing subkey. [`key_revoked`] states which keys
    ///   can make such a signature. `trusted` is the set in which a designated
    ///   revoker resolves.
    /// - A subkey revocation signature that the primary key made over the
    ///   signing subkey revokes only that subkey. The primary key and the
    ///   other subkeys of the certificate stay as they are.
    ///
    /// If a certificate answers for the issuer through a subkey, this function
    /// reads both sites. If it answers through its primary key, this function
    /// reads the first site only.
    ///
    /// The second site accepts only the signature of the primary key itself.
    /// `gpg` 2.4.9 writes the revocation of a designated revoker with
    /// `--desig-revoke`, which makes a key revocation over the primary key. So
    /// the observed states cover the first site. They state nothing about a
    /// designated revoker at the second site.
    ///
    /// This function verifies each revocation before it accepts it. Another key
    /// can make a key revocation signature that no self-signature designates.
    /// Anyone can staple such a signature onto a certificate, so it revokes
    /// nothing. `gpgv` gives the same answer: over a certificate that carries
    /// such a packet, it reports `GOODSIG`.
    fn revoked(&self, trusted: &[SignedPublicKey]) -> bool {
        if key_revoked(self.cert, trusted) {
            return true;
        }
        let primary = &self.cert.primary_key;
        let Some((subkey, _)) = self.subkey else {
            return false;
        };
        subkey.signatures.iter().any(|sig| {
            sig.typ() == Some(SignatureType::SubkeyRevocation)
                && sig.verify_subkey_binding(primary, &subkey.key).is_ok()
        })
    }
}

/// The keys of the loaded certificates that answer for the issuer of one
/// signature, in the order of the trusted set.
///
/// The list is never empty, because a match is necessary to build it.
///
/// One key can reach the trusted set through more than one certificate on
/// usual paths:
///
/// - the `<remote>.trustedkeys.gpg` of a repository and the global trusted
///   directory
/// - two `gpgkeypath` entries
/// - one keyring file with two exports of one key.
///
/// The certificates can state different things about the key. So the key
/// state is read over every match:
///
/// - The matches of one certificate read as one certificate (see
///   [`Issuers::groups`]).
/// - A revocation in any match refuses the signature.
/// - The key expires at the earliest instant of all groups.
///
/// The load order decides neither the revocation nor the expiry.
struct Issuers<'a> {
    matched: Vec<Issuer<'a>>,
    /// Every loaded certificate. A designated revoker resolves in this set
    /// (see [`key_revoked`]).
    ///
    /// A revoker speaks for a certificate that does not hold it. So the whole
    /// trusted set applies here. Its certificates come from the keyring of a
    /// remote, the global trusted directory, or a `gpgkeypath` entry.
    ///
    /// The `ostree` command resolves a revoker only in the keyring source that
    /// carries the revocation. So if the revoker and the revocation come from
    /// different sources, the two implementations give different answers.
    /// ostrya is the stricter one (divergence P3).
    trusted: &'a [SignedPublicKey],
}

impl<'a> Issuers<'a> {
    /// Returns the match that gives the fields of the report.
    ///
    /// These fields are the signing key, its certificate, the user id of that
    /// certificate, the cryptography, and [`Issuer::cross_certified`].
    ///
    /// If the issuer fingerprint matched, every match holds the same signing
    /// key. So the reported fingerprint of the signing key is the same for all
    /// matches. The certificate around that key can be different. One
    /// certificate can hold the key as its primary key, and another can bind
    /// it as a subkey. So the reported user id, the primary-key fingerprint,
    /// and the cross-certification check follow the order of the trusted set.
    fn reported(&self) -> &Issuer<'a> {
        &self.matched[0]
    }

    /// Returns `true` if any matching certificate revokes the signing key.
    ///
    /// This function reads each certificate at the sites that
    /// [`Issuer::revoked`] gives it. So a key revocation on one copy of a
    /// certificate refuses a signature for which another copy answers. A
    /// revocation is permanent. So this function reads each copy separately,
    /// and no copy replaces another.
    fn revoked(&self) -> bool {
        self.matched
            .iter()
            .any(|issuer| issuer.revoked(self.trusted))
    }

    /// Returns the earliest expiry instant of the signing key over all groups.
    ///
    /// A group that states no expiry adds nothing here. It does not extend a
    /// life that another group limits.
    fn key_expires_at(&self) -> Option<u64> {
        self.groups().iter().filter_map(Group::key_expires_at).min()
    }

    /// Returns the matches as merged certificates.
    ///
    /// There is one group for each primary key, in load order. Each group holds
    /// the certificates that its matches came from.
    ///
    /// Two exports of one certificate go in one group and read as one
    /// certificate. If one certificate holds the signing key as its primary
    /// key and another binds it as a subkey, they go in two groups. Their
    /// self-signatures verify under different primary keys.
    ///
    /// The group key is the primary key packet. A fingerprint is a digest over
    /// that packet, so the grouping is the same for each normal certificate.
    /// Under a broken digest, two certificates can have the same fingerprint.
    /// Each such certificate gets its own group. The rule across groups then
    /// limits it to the earliest instant of all groups.
    fn groups(&self) -> Vec<Group<'a>> {
        let mut groups: Vec<Group<'a>> = Vec::new();
        for issuer in &self.matched {
            let primary = &issuer.cert.primary_key;
            let group = match groups
                .iter_mut()
                .find(|group| group.primary_key() == primary)
            {
                Some(group) => group,
                None => {
                    groups.push(Group {
                        matched: Vec::new(),
                        copies: vec![issuer.cert],
                    });
                    groups.last_mut().expect("the group pushed above")
                }
            };
            group.matched.push(*issuer);
            if !group
                .copies
                .iter()
                .any(|cert| std::ptr::eq(*cert, issuer.cert))
            {
                group.copies.push(issuer.cert);
            }
        }
        groups
    }
}

/// The matches from the certificates that hold one primary key, read as one
/// certificate.
///
/// Every copy in a group states the same primary key. So the self-signatures
/// of every copy verify under that key, and their signatures make one set. The
/// key expiry of the group is read over that set:
///
/// - [`key_expiry_over`] runs the tiered rule of [`primary_key_lifetime`] one
///   time, over the direct signatures and the user ids of every copy.
/// - The lifetime of a subkey comes from the binding signature that
///   [`verified_binding`] selects, from the bindings over the subkey in every
///   copy.
///
/// If the owner replaced the lifetime that a copy states, that copy alone
/// states nothing. The newest statement applies.
///
/// The group holds at least one match and at least one copy, because a match
/// is necessary to build it.
struct Group<'a> {
    /// The matches, in load order.
    matched: Vec<Issuer<'a>>,
    /// The certificates that the matches came from, one entry for each
    /// certificate, in load order.
    copies: Vec<&'a SignedPublicKey>,
}

impl Group<'_> {
    /// Returns the expiry instant of the signing key in this group.
    ///
    /// This is the earliest instant that its matches state. It is `None` if no
    /// match states an instant.
    fn key_expires_at(&self) -> Option<u64> {
        let primary = key_expiry_over(self.copies.iter().copied());
        self.matched
            .iter()
            .filter_map(|issuer| match issuer.subkey {
                None => primary,
                Some((subkey, _)) => earlier(primary, self.subkey_expires_at(subkey)),
            })
            .min()
    }

    /// Returns the expiry instant of `subkey` on its own terms.
    ///
    /// The instant is the creation time of the subkey plus a lifetime. The
    /// lifetime comes from the binding signature that [`verified_binding`]
    /// selects, from the bindings for that subkey in every copy.
    fn subkey_expires_at(&self, subkey: &SignedPublicSubKey) -> Option<u64> {
        let wanted = subkey.fingerprint();
        let bindings = self
            .copies
            .iter()
            .flat_map(|cert| &cert.public_subkeys)
            .filter(|held| held.fingerprint() == wanted)
            .flat_map(|held| &held.signatures);
        let lifetime = key_lifetime(verified_binding(self.primary_key(), subkey, bindings)?)?;
        Some(u64::from(subkey.key.created_at().as_secs()) + lifetime)
    }

    /// Returns the primary key that every copy states.
    fn primary_key(&self) -> &PublicKey {
        &self.copies[0].primary_key
    }
}

/// Returns the earlier of two instants. An absent instant states nothing.
fn earlier(one: Option<u64>, two: Option<u64>) -> Option<u64> {
    match (one, two) {
        (Some(one), Some(two)) => Some(one.min(two)),
        (one, two) => one.or(two),
    }
}

/// Resolves each key of the loaded certificates for the issuer that a
/// signature names.
///
/// The lookup uses the issuer fingerprint first, then the issuer key id. Each
/// lookup reads the primary key before the subkeys. The matches of the first
/// identifier that answers are the whole set. So if the trusted set holds the
/// issuer fingerprint, the issuer key id has no effect.
///
/// A subkey answers only if the primary key made a binding signature over it
/// that [`verified_binding`] selects. These subkeys belong to no loaded
/// certificate:
///
/// - a subkey whose binding does not verify, for example a subkey taken from
///   another certificate with the binding that it carried there
/// - a subkey whose binding signatures all expired.
///
/// `gpgv` gives the same answer. For a signature by such a subkey, it reports
/// `ERRSIG ... 9` and `NO_PUBKEY`.
fn resolve_issuers<'a>(certs: &'a [SignedPublicKey], sig: &Signature) -> Option<Issuers<'a>> {
    for wanted in sig.issuer_fingerprint() {
        let mut matched: Vec<Issuer<'a>> = Vec::new();
        for cert in certs {
            if &cert.fingerprint() == wanted {
                matched.push(Issuer { cert, subkey: None });
            }
            for subkey in &cert.public_subkeys {
                if &subkey.fingerprint() == wanted
                    && let Some(binding) =
                        verified_binding(&cert.primary_key, subkey, &subkey.signatures)
                {
                    matched.push(Issuer {
                        cert,
                        subkey: Some((subkey, binding)),
                    });
                }
            }
        }
        if !matched.is_empty() {
            return Some(Issuers {
                matched,
                trusted: certs,
            });
        }
    }
    for wanted in sig.issuer_key_id() {
        let mut matched: Vec<Issuer<'a>> = Vec::new();
        for cert in certs {
            if &cert.legacy_key_id() == wanted {
                matched.push(Issuer { cert, subkey: None });
            }
            for subkey in &cert.public_subkeys {
                if &subkey.legacy_key_id() == wanted
                    && let Some(binding) =
                        verified_binding(&cert.primary_key, subkey, &subkey.signatures)
                {
                    matched.push(Issuer {
                        cert,
                        subkey: Some((subkey, binding)),
                    });
                }
            }
        }
        if !matched.is_empty() {
            return Some(Issuers {
                matched,
                trusted: certs,
            });
        }
    }
    None
}

/// Returns the newest binding signature in `signatures` that `primary` made
/// over `subkey`, that verifies, and that is not expired.
///
/// There are two sources of signatures. One is the signatures that a subkey
/// carries. The other is the bindings over that subkey in every copy of one
/// certificate. So the caller gives the set for the rule.
///
/// A binding signature after its own expiration time binds nothing. A live
/// older binding next to it still binds. `gpgv` 2.4.9 gives the same answers:
///
/// - The certificate has one binding signature, with signature subpacket 3 at
///   an instant in the past. For a signature by that subkey, `gpgv` reports
///   `ERRSIG <keyid> 22 10 00 <created> 9 <fingerprint>` and `NO_PUBKEY`, and
///   exits 2.
/// - The same binding without subpacket 3 gives `GOODSIG`.
/// - The certificate carries that expired binding next to the live one. `gpgv`
///   reports `GOODSIG`.
fn verified_binding<'a, I>(
    primary: &PublicKey,
    subkey: &SignedPublicSubKey,
    signatures: I,
) -> Option<&'a Signature>
where
    I: IntoIterator<Item = &'a Signature>,
{
    signatures
        .into_iter()
        .filter(|sig| {
            sig.typ() == Some(SignatureType::SubkeyBinding)
                && !signature_expired(sig)
                && sig.verify_subkey_binding(primary, &subkey.key).is_ok()
        })
        .max_by_key(|sig| created_secs(sig))
}

/// Returns the expiry instant of the primary key that the copies of one
/// certificate state.
///
/// The instant is the key creation time plus the lifetime that
/// [`primary_key_lifetime`] reads over the union of the copies. It is `None` if
/// the copies state no lifetime, or if the set is empty.
///
/// Every copy states one primary key, which is the key that the caller grouped
/// them by. So the first copy gives the key. The verdict reads a match group
/// through this function. The keyring import reads the copies of one key in a
/// keyring through it. So the two use the same signature.
pub(super) fn key_expiry_over<'a, I>(copies: I) -> Option<u64>
where
    I: IntoIterator<Item = &'a SignedPublicKey> + Clone,
{
    let primary = &copies.clone().into_iter().next()?.primary_key;
    let lifetime = primary_key_lifetime(
        primary,
        copies
            .clone()
            .into_iter()
            .flat_map(|cert| &cert.details.direct_signatures),
        copies.into_iter().flat_map(|cert| &cert.details.users),
    )?;
    Some(u64::from(primary.created_at().as_secs()) + lifetime)
}

/// Returns the key expiration time of a primary key, in seconds after the key
/// creation time.
///
/// The rule has two tiers:
///
/// 1. The newest verified direct-key self-signature in `direct` that states a
///    lifetime.
/// 2. If there is no such signature, the lifetime that the newest verified
///    certification self-signature over a user id in `users` states.
///
/// The two sets are the signatures of one certificate, or the signatures of
/// every copy of one certificate in the trusted set. In both cases the tier
/// has priority over the creation time. So a direct-key self-signature answers
/// before a newer certification self-signature.
///
/// # Direct-key tier
///
/// `gpgv` reads a direct-key signature that states a lifetime. The measurement
/// used a certificate with a direct-key and a certification self-signature.
/// The two key-expiration-time subpackets did not agree. The results:
///
/// - The value of the direct-key signature applies in both directions. It
///   makes an expired key live, and a live key expired.
/// - It applies if it is older than the certification self-signature, and
///   also if it is newer.
/// - The rule skips a direct-key signature with altered bytes. It also skips
///   one whose key-expiration-time subpacket is absent or zero. The
///   certification self-signature then answers.
///
/// # Certification tier
///
/// The newest verified certification self-signature answers on its own terms.
/// No older one replaces it. `gpgv` gives these results:
///
/// - The newest certification self-signature states a zero lifetime, and an
///   older one states a lifetime in the past. `gpgv` reports `GOODSIG`.
/// - The newest one states no lifetime, and an older one states a lifetime in
///   the past. `gpgv` reports `GOODSIG`.
/// - The newest one is altered. The rule skips it, and `gpgv` reports the
///   expiry that the older one states.
///
/// # Expired self-signatures
///
/// A self-signature after its own expiration time states no lifetime (see
/// [`key_lifetime`]). The two tiers apply this rule differently. `gpgv` 2.4.9
/// gives the same answers in both tiers:
///
/// - The direct-key tier skips such a signature. The newest live one that
///   states a lifetime answers. If all direct-key self-signatures are
///   expired, the certification tier answers.
/// - In the certification tier, the newest one answers, also if it is
///   expired. So an expired newest one makes the tier state nothing.
fn primary_key_lifetime<'a, D, U>(primary: &PublicKey, direct: D, users: U) -> Option<u64>
where
    D: IntoIterator<Item = &'a Signature>,
    U: IntoIterator<Item = &'a SignedUser>,
{
    let newest = direct
        .into_iter()
        .filter(|sig| sig.typ() == Some(SignatureType::Key) && sig.verify_key(primary).is_ok())
        .filter_map(|sig| Some((created_secs(sig), key_lifetime(sig)?)))
        .max_by_key(|(created, _)| *created);
    if let Some((_, lifetime)) = newest {
        return Some(lifetime);
    }
    users
        .into_iter()
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

/// Returns `true` if a signature is a certification over a user id.
///
/// The key expiration time of a primary key is carried on such a signature. A
/// revocation over a user id is a certification of another kind. It states no
/// key expiration time.
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

/// Returns the key lifetime that a self-signature states, in seconds after the
/// key creation time.
///
/// A zero lifetime means no expiry, so it reads as absent. A zero `gpgv` status
/// field has the same meaning.
///
/// A self-signature after its own expiration time states no lifetime. `gpgv`
/// 2.4.9 gives the same answer. The measurement used a certificate whose newest
/// certification self-signature carries signature subpacket 3 with an instant
/// in the past:
///
/// - If that signature states a one-day key lifetime and an older
///   certification self-signature states ten years, `gpgv` reports `GOODSIG`.
///   So `gpgv` does not read the statement of the expired signature.
/// - If it states no key lifetime and an older certification self-signature
///   states one day, `gpgv` reports `GOODSIG`. So the older signature does not
///   answer in its place.
///
/// The same rule applies to a direct-key self-signature:
///
/// - The one direct-key self-signature of a certificate is expired and states
///   ten years. `gpgv` reports `EXPKEYSIG` with the instant of the one-day
///   lifetime of the certification self-signature.
/// - The same signature without subpacket 3 gives `GOODSIG`.
/// - A live older direct-key self-signature that states ten years is next to
///   it. `gpgv` reports `GOODSIG`. So the direct-key tier reads the newest one
///   that states a lifetime, and the expired one states none.
fn key_lifetime(sig: &Signature) -> Option<u64> {
    if signature_expired(sig) {
        return None;
    }
    epoch(sig.key_expiration_time()?.as_secs())
}

/// Returns `true` if the time is at or after the expiration time of the
/// signature itself.
///
/// A signature expires at the instant that it names. [`describe`] applies this
/// boundary to a data signature, with the measurement of `gpgv` in its body.
/// Signature subpacket 3 is the same field on a
/// self-signature, so one boundary applies to both. The boundary second on a
/// self-signature is not measured.
fn signature_expired(sig: &Signature) -> bool {
    expires_at(sig).is_some_and(|instant| instant <= now())
}

/// Returns `true` if a verified key revocation signature is over the primary
/// key of `cert`.
///
/// Such a signature revokes the whole certificate. Two keys can make one:
///
/// - the primary key of the certificate
/// - a revoker key that a verified self-signature of the certificate
///   designates through signature subpacket 12. `trusted` must hold the
///   certificate of that revoker.
///
/// # Revoker certificate
///
/// The certificate of the revoker must be available. `gpgv` 2.4.9 gives the
/// same answer. The measurement used two keyrings with the same bytes for the
/// revoked key, and one of them also held the certificate of the revoker:
///
/// - The keyring without it reports `GOODSIG` and prints no `KEY_CONSIDERED`
///   line for the revoker.
/// - The keyring with it reports `REVKEYSIG`.
///
/// For this reason, `trusted` is the whole loaded set. This function matches
/// the designation against the primary key of each certificate in the set.
///
/// # Designation
///
/// The designation is the condition that admits the revocation. `gpgv` gives
/// these results with the byte-identical revocation:
///
/// - The primary key carries no subpacket 12. `gpgv` reports `GOODSIG`.
/// - The same keyring also holds the certificate of the revoker. `gpgv`
///   reports `GOODSIG` again.
///
/// Another key can make a key revocation signature that no self-signature
/// designates. Anyone can staple such a signature onto a certificate, so it
/// revokes nothing.
///
/// # Verification
///
/// This function verifies each revocation before it accepts it:
///
/// - The primary key of the certificate verifies its own revocation through
///   [`Signature::verify_key`].
/// - A designated revoker verifies its revocation over the revoked primary key
///   through [`Signature::verify_key_third_party`].
///
/// A revocation after its own expiration time still revokes. The rule of
/// `gpgv` for this case is not measured. So the check reads only the
/// mathematics of the signature.
///
/// # Keyring import
///
/// The keyring import reads a certificate through this function if the
/// keyring already holds its key. It gives as `trusted` every certificate in
/// the keyring under edit and in the offered stream. So a revocation by a
/// designated revoker carries into the keyring if either stream holds the
/// revoker.
pub(super) fn key_revoked<'a, I>(cert: &SignedPublicKey, trusted: I) -> bool
where
    I: IntoIterator<Item = &'a SignedPublicKey>,
{
    let primary = &cert.primary_key;
    let revocations: Vec<&Signature> = cert
        .details
        .revocation_signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::KeyRevocation))
        .collect();
    if revocations.is_empty() {
        return false;
    }
    if revocations
        .iter()
        .any(|sig| sig.verify_key(primary).is_ok())
    {
        return true;
    }
    let designated = designated_revokers(cert);
    if designated.is_empty() {
        return false;
    }
    trusted.into_iter().any(|revoker| {
        let fingerprint = revoker.fingerprint();
        designated
            .iter()
            .any(|named| *named == fingerprint.as_bytes())
            && revocations.iter().any(|sig| {
                sig.verify_key_third_party(primary, &revoker.primary_key)
                    .is_ok()
            })
    })
}

/// Returns the keys that a certificate designates as revokers, each as the
/// fingerprint bytes that the designation names.
///
/// A designation is carried on a self-signature. Only a self-signature that
/// verifies under the primary key designates. This function reads the
/// direct-key signatures and the certifications over a user id. It verifies
/// each one under the primary key.
///
/// A designation on a signature that does not verify designates nothing.
/// [`revocation_keys`] reads only the hashed subpacket area. So a subpacket 12
/// that anyone staples onto a certificate names no revoker in both cases.
///
/// A designation on a self-signature after its own expiration time still names
/// a revoker. The rule of `gpgv` for this case is not measured. So the check
/// reads only the mathematics of the signature.
///
/// This function reads both designation classes, the default class and the
/// sensitive class. The class states if the designation is for publication.
fn designated_revokers(cert: &SignedPublicKey) -> Vec<&[u8]> {
    let primary = &cert.primary_key;
    let direct = cert
        .details
        .direct_signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::Key) && sig.verify_key(primary).is_ok());
    let certifications = cert
        .details
        .users
        .iter()
        .flat_map(|user| user.signatures.iter().map(move |sig| (user, sig)))
        .filter(|(user, sig)| {
            is_certification(sig)
                && sig
                    .verify_certification(primary, Tag::UserId, &user.id)
                    .is_ok()
        })
        .map(|(_, sig)| sig);
    direct
        .chain(certifications)
        .flat_map(revocation_keys)
        .collect()
}

/// Returns the fingerprints that the revocation-key subpackets of one
/// signature name.
///
/// This function reads only the hashed area. So a subpacket that the signature
/// does not cover names no revoker. `gpgv` 2.4.9 gives the same answer. The
/// measurement used a keyring with these items:
///
/// - the revocation
/// - the certificate of the revoker
/// - a subpacket 12 stapled into the unhashed area of a self-signature that
///   still verifies.
///
/// `gpgv` reports `GOODSIG`. A signature can carry more than one such
/// subpacket, and each one names a key.
fn revocation_keys(sig: &Signature) -> impl Iterator<Item = &[u8]> {
    sig.config().into_iter().flat_map(|config| {
        config
            .hashed_subpackets()
            .filter_map(|packet| match &packet.data {
                SubpacketData::RevocationKey(key) => Some(&key.fingerprint[..]),
                _ => None,
            })
    })
}

/// Returns `true` if a verified revocation is over a user id.
fn user_revoked(cert: &SignedPublicKey, user: &SignedUser) -> bool {
    user.signatures.iter().any(|sig| {
        sig.typ() == Some(SignatureType::CertRevocation)
            && sig
                .verify_certification(&cert.primary_key, Tag::UserId, &user.id)
                .is_ok()
    })
}

/// Returns the signature creation time of the packet, in seconds since the
/// Unix epoch. A zero instant reads as absent.
fn created_at(sig: &Signature) -> Option<u64> {
    epoch(sig.created()?.as_secs())
}

/// Returns the expiry instant of the signature itself.
///
/// The instant is the creation time plus the expiration that the packet
/// carries. It is `None` if the packet carries no expiration, or a zero one.
fn expires_at(sig: &Signature) -> Option<u64> {
    let created = created_at(sig)?;
    let lifetime = epoch(sig.signature_expiration_time()?.as_secs())?;
    Some(created + lifetime)
}

/// Returns a packet time field in seconds. Zero reads as absent.
fn epoch(secs: u32) -> Option<u64> {
    (secs != 0).then(|| u64::from(secs))
}

/// Returns the public-key algorithm name for the report.
///
/// The report gives algorithm id 22 as `EdDSA`. The enum accepts ids that
/// ostrya has no name for. The report gives these ids as their number.
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

/// Returns the digest algorithm name for the report.
///
/// The enum accepts ids that ostrya has no name for. The report gives these
/// ids as their number.
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

/// Returns the name and the email of the user id that the report names for a
/// certificate.
///
/// This is the primary user id. If no user id is marked primary, it is the
/// newest self-signed user id. If a user id is not valid UTF-8, the invalid
/// sequences are replaced.
///
/// # Revoked user ids
///
/// The choice skips a revoked user id. A primary-user-id subpacket on a
/// revoked user id has no effect. `gpgv` names the same user id on the verdict
/// line:
///
/// - If the primary user id is revoked and the second user id is not, `gpgv`
///   names the second one.
/// - If every user id is revoked, `gpgv` names a revoked one. So a certificate
///   with only revoked user ids still reports a user id.
///
/// # Certifications that count
///
/// The choice reads only the certifications that verify under the primary
/// key. This applies to the primary mark and to the rank. So a third-party
/// certification and a packet that anyone stapled onto the certificate choose
/// nothing. `gpgv` names the same user id:
///
/// - One user id carries the newest self-signature, and another carries a
///   newer third-party certification. `gpgv` names the user id of the
///   self-signature.
/// - The primary mark is on a self-signature that does not verify. `gpgv`
///   names the other user id.
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
        .find(|user| user_marked_primary(cert, user))
        .or_else(|| {
            usable
                .iter()
                .copied()
                .max_by_key(|user| newest_certification(cert, user))
        });
    match user {
        Some(user) => split_uid(&String::from_utf8_lossy(user.id.id())),
        None => (None, None),
    }
}

/// Splits an OpenPGP user id into a name and an email.
///
/// The trailing `<address>` is the email, and the text before it is the name.
/// A user id without an address is all name.
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

/// Returns the creation time of the newest certification over a user id that
/// verifies under the primary key and is not expired.
///
/// A third-party certification and a packet that anyone stapled onto the
/// certificate do not verify under that key. So neither ranks a user id. A
/// user id with no such certification ranks at the epoch.
///
/// A certification after its own expiration time ranks nothing. `gpgv` 2.4.9
/// names the same user id:
///
/// - The newest certification self-signature over one user id carries
///   signature subpacket 3 with an instant in the past. `gpgv` names the other
///   user id. The self-signature of that user id is older and live.
/// - The same signature without subpacket 3 makes `gpgv` name the first user
///   id.
///
/// A certification that another signature revokes still ranks. The rule of
/// `gpgv` for this case is not measured. The rule decides only the reported
/// name.
fn newest_certification(cert: &SignedPublicKey, user: &SignedUser) -> u32 {
    let primary = &cert.primary_key;
    user.signatures
        .iter()
        .filter(|sig| {
            is_certification(sig)
                && !signature_expired(sig)
                && sig
                    .verify_certification(primary, Tag::UserId, &user.id)
                    .is_ok()
        })
        .filter_map(|sig| sig.created())
        .map(Timestamp::as_secs)
        .max()
        .unwrap_or(0)
}

/// Returns `true` if a live certification that verifies under the primary key
/// marks a user id primary.
///
/// A primary-user-id subpacket on a packet that the primary key did not make
/// marks nothing. `gpgv` names the same user id. If the primary-marked
/// self-signature of a certificate is altered, `gpgv` names the other user id.
///
/// A certification after its own expiration time also marks nothing. `gpgv`
/// 2.4.9 gives the same answer:
///
/// - The primary mark is on a self-signature with signature subpacket 3 at an
///   instant in the past. `gpgv` names the other user id.
/// - The same signature without subpacket 3 makes `gpgv` name the marked one.
fn user_marked_primary(cert: &SignedPublicKey, user: &SignedUser) -> bool {
    let primary = &cert.primary_key;
    user.signatures.iter().any(|sig| {
        sig.is_primary()
            && is_certification(sig)
            && !signature_expired(sig)
            && sig
                .verify_certification(primary, Tag::UserId, &user.id)
                .is_ok()
    })
}

/// Returns the creation time that a signature packet states.
///
/// An absent creation time reads as the epoch. So a signature that states no
/// creation time is the oldest.
fn created_secs(sig: &Signature) -> u32 {
    sig.created().map(Timestamp::as_secs).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;
    use crate::gpg::{GpgVerifier, STATUS_PREFIX, parse_epoch, remove_home_sockets, scratch_dir};

    /// The payload every fixture signs.
    const PAYLOAD: &[u8] = b"ostrya commit payload";
    /// A payload no fixture signs, for the changed-payload case.
    const OTHER_PAYLOAD: &[u8] = b"ostrya other payload";

    /// Returns `true` if the named binary answers.
    ///
    /// The cases build their fixtures with `gpg` and read their reference
    /// records from `gpgv`. An absent binary skips a case and never passes it.
    fn available(program: &str) -> bool {
        Command::new(program)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// A private GnuPG home with one new ed25519 signing key and no passphrase.
    ///
    /// The home is in the test scratch tree. Each `gpg` and `gpgv` run names a
    /// directory in it. The GnuPG home and the agents of the user who runs the
    /// tests take no part. On drop, the fixture stops the GnuPG daemons of the
    /// directory, removes their socket directory, and removes the tree.
    struct Fixture {
        dir: PathBuf,
        /// The fingerprint of the primary key, in uppercase hex.
        primary: String,
        /// If `true`, each `gpg` run in this home stands at the instant that
        /// [`KEY_CREATED`] names.
        faked: bool,
    }

    impl Fixture {
        /// Creates a home with one ed25519 signing key for `uid` that never
        /// expires.
        fn new(uid: &str) -> Fixture {
            Fixture::build(uid, "ed25519", false, "never")
        }

        /// Creates a home with one RSA signing key.
        ///
        /// rPGP refuses a digest of fewer than 256 bits with an Ed25519 key.
        /// The cases that state the digest policy of ostrya use this RSA key,
        /// which accepts such a digest.
        fn rsa(uid: &str) -> Fixture {
            Fixture::build(uid, "rsa2048", false, "never")
        }

        /// Creates a home whose key has the creation instant that
        /// [`KEY_CREATED`] names and expires after `expiry`.
        ///
        /// Each `gpg` run in it stands at that instant, so each signature that
        /// it makes is made while the key is live. `gpgv` reads the real clock.
        /// For this reason, an expired key is expired for `gpgv`.
        fn at(uid: &str, expiry: &str) -> Fixture {
            Fixture::build(uid, "ed25519", true, expiry)
        }

        /// Creates a home with no key. The cases build a keyring in it from the
        /// certificates that other homes export.
        fn bare() -> Fixture {
            use std::os::unix::fs::DirBuilderExt;
            let dir = scratch_dir();
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&dir).unwrap();
            builder.create(dir.join("gv")).unwrap();
            Fixture {
                dir,
                primary: String::new(),
                faked: false,
            }
        }

        fn build(uid: &str, algorithm: &str, faked: bool, expiry: &str) -> Fixture {
            let mut fixture = Fixture::bare();
            fixture.faked = faked;
            for _ in 0..16 {
                let status = fixture
                    .gpg()
                    .args(["--quick-gen-key", uid, algorithm, "sign", expiry])
                    .status()
                    .unwrap();
                assert!(status.success(), "gpg --quick-gen-key failed");
                fixture.primary = fixture.fingerprints().remove(0);
                if fixture.secret_key_is_read() {
                    return fixture;
                }
                fixture.delete_key();
            }
            panic!("no generated key exported a secret key the pgp crate reads");
        }

        /// Returns `true` if the `pgp` crate reads the exported secret key of
        /// the home.
        ///
        /// `gpg` writes the ed25519 secret scalar as an MPI that declares 256
        /// bits, also when its leading octet is zero. The two-octet checksum
        /// that `gpg` writes covers the octets that it wrote. The `pgp` crate
        /// reads the MPI, drops the leading zero, and sums the shorter form, so
        /// it refuses such a key with "Invalid checksum".
        ///
        /// One scalar in 256 has a zero leading octet. If the crate refuses the
        /// secret export of a key, the fixture generates a new key. As a
        /// result, the cases that sign with the key work on each run.
        fn secret_key_is_read(&self) -> bool {
            pgp::composed::SignedSecretKey::from_bytes(Cursor::new(self.secret_key())).is_ok()
        }

        /// Removes the key of the home, both its secret part and its public
        /// part.
        fn delete_key(&self) {
            let status = self
                .gpg()
                .args(["--yes", "--delete-secret-and-public-key", &self.primary])
                .status()
                .unwrap();
            assert!(
                status.success(),
                "gpg --delete-secret-and-public-key failed"
            );
        }

        /// Returns a `gpg` command bound to this home, in batch mode, that
        /// supplies the empty passphrase without a prompt.
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

        /// Returns a `gpg` command bound to this home that reads prompt answers
        /// from standard input.
        ///
        /// Batch mode answers no prompt, so the interactive commands that show
        /// a prompt run through this command.
        fn gpg_interactive(&self) -> Command {
            let mut cmd = Command::new("gpg");
            cmd.arg("--homedir").arg(&self.dir).args([
                "--no-tty",
                "--no-batch",
                "--command-fd",
                "0",
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

        /// Imports a certificate stream into this home.
        fn import(&self, bytes: &[u8]) {
            let path = self.write("import.gpg", bytes);
            let status = self.gpg().arg("--import").arg(path).status().unwrap();
            assert!(status.success(), "gpg --import failed");
        }

        /// Imports a stream that `gpg` merges while it reports a failure.
        ///
        /// Over a revocation by a designated revoker, `gpg --import` exits 2.
        /// If the home does not hold the certificate of the revoker, it reports
        /// "no public key - can't apply revocation certificate". If the home
        /// holds that certificate, it also exits 2. In both cases, it merges
        /// the class 0x20 signature into the certificate that it holds.
        ///
        /// The export of the home carries the packet. The case that reads the
        /// export states that the packet is there.
        fn import_merging(&self, bytes: &[u8]) {
            let path = self.write("import.gpg", bytes);
            self.gpg().arg("--import").arg(path).status().unwrap();
        }

        /// Returns the exported binary certificates of the keys that `keys`
        /// names, in the order of the names.
        fn export_keys(&self, keys: &[&str]) -> Vec<u8> {
            let out = self.gpg().arg("--export").args(keys).output().unwrap();
            assert!(out.status.success() && !out.stdout.is_empty());
            out.stdout
        }

        /// Designates the key that `revoker` names as a revoker of the primary
        /// key of this home.
        ///
        /// `gpg` writes a new direct-key self-signature with signature
        /// subpacket 12, so this home must already hold the certificate of the
        /// revoker.
        fn add_revoker(&self, revoker: &str) {
            let mut cmd = self.gpg_interactive();
            cmd.arg("--edit-key").arg(&self.primary);
            answer(
                cmd,
                format!("addrevoker\n{revoker}\ny\ny\nsave\n").as_bytes(),
                "gpg --edit-key addrevoker",
            );
        }

        /// Returns the key revocation that a designated revoker makes over the
        /// key that `key` names.
        ///
        /// The bytes are the binary packet stream that `gpg --desig-revoke`
        /// writes. The stream is a transferable public key of the revoked key,
        /// with the class 0x20 signature directly after the primary key packet.
        /// This home must hold the secret key of the revoker. It must also hold
        /// a certificate of the revoked key that designates the revoker.
        fn desig_revoke(&self, key: &str) -> Vec<u8> {
            let path = self.dir.join("desig-revoke.asc");
            let mut cmd = self.gpg_interactive();
            cmd.arg("--armor")
                .arg("--output")
                .arg(&path)
                .arg("--desig-revoke")
                .arg(key);
            answer(cmd, b"y\n0\n\ny\n", "gpg --desig-revoke");
            crate::gpg::dearmor(&std::fs::read(&path).unwrap()).unwrap()
        }

        /// Returns the exported secret key. `gpg` writes it unprotected because
        /// the passphrase is empty.
        fn secret_key(&self) -> Vec<u8> {
            let out = self.gpg().arg("--export-secret-keys").output().unwrap();
            assert!(out.status.success() && !out.stdout.is_empty());
            out.stdout
        }

        /// Returns the stored revocation certificate of the key as one binary
        /// key revocation signature packet.
        ///
        /// `gpg` stores this certificate when it generates the key. The stored
        /// file has prose before the armored block. It also has a colon before
        /// the first dash of the block, so an accidental import does nothing.
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

        /// Revokes the primary key with an import of the revocation
        /// certificate that `gpg` stored for it.
        fn revoke_primary(&self) {
            let text = std::fs::read_to_string(self.revocation_path()).unwrap();
            let at = text.find("-----BEGIN PGP").unwrap();
            let path = self.write("revocation.asc", &text.as_bytes()[at..]);
            let status = self.gpg().arg("--import").arg(path).status().unwrap();
            assert!(status.success(), "gpg --import of the revocation failed");
        }

        /// Revokes the first subkey.
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

        /// Adds a user id.
        fn add_uid(&self, uid: &str) {
            let status = self
                .gpg()
                .args(["--quick-add-uid", &self.primary, uid])
                .status()
                .unwrap();
            assert!(status.success(), "gpg --quick-add-uid failed");
        }

        /// Adds a user id, with `gpg` at the instant `when`.
        ///
        /// The self-signature over the new user id then has a creation time
        /// that the caller selects. If the clock option is given twice, the
        /// last one applies.
        fn add_uid_at(&self, when: &str, uid: &str) {
            let status = self
                .gpg()
                .args(["--faked-system-time", when])
                .args(["--quick-add-uid", &self.primary, uid])
                .status()
                .unwrap();
            assert!(status.success(), "gpg --quick-add-uid failed");
        }

        /// Marks a user id primary.
        fn set_primary_uid(&self, uid: &str) {
            let status = self
                .gpg()
                .args(["--quick-set-primary-uid", &self.primary, uid])
                .status()
                .unwrap();
            assert!(status.success(), "gpg --quick-set-primary-uid failed");
        }

        /// Sets the expiry of the primary key, with `gpg` at the instant
        /// `when`.
        ///
        /// A new self-signature has a creation time. `gpg` refuses to write one
        /// at the creation time of the self-signature that it replaces. It
        /// reports "make_keysig_packet failed: Time conflict".
        ///
        /// If the clock option is given twice, the last one applies. As a
        /// result, a run at a later instant writes the signature that a run at
        /// the instant of the fixture cannot write.
        fn set_expire_at(&self, when: &str, expiry: &str) {
            let status = self
                .gpg()
                .args(["--faked-system-time", when])
                .args(["--quick-set-expire", &self.primary, expiry])
                .status()
                .unwrap();
            assert!(status.success(), "gpg --quick-set-expire failed");
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

        /// Adds a signing subkey to the primary key and returns its
        /// fingerprint.
        fn add_signing_subkey(&self) -> String {
            self.add_signing_subkey_expiring("never")
        }

        /// Adds a signing subkey with the lifetime `expiry` and returns its
        /// fingerprint.
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

        /// Returns each key fingerprint in the home, in listing order: the
        /// primary key first, then its subkeys.
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

        /// Returns the exported binary public keyring.
        fn keyring(&self) -> Vec<u8> {
            let out = self.gpg().arg("--export").output().unwrap();
            assert!(out.status.success() && !out.stdout.is_empty());
            out.stdout
        }

        /// Returns the certificates that a verifier loads from the exported
        /// keyring.
        fn certs(&self) -> Vec<SignedPublicKey> {
            std::sync::Arc::unwrap_or_clone(
                GpgVerifier::from_keyring_bytes([self.keyring()])
                    .unwrap()
                    .certs,
            )
        }

        /// Returns one detached signature over `payload`, made by exactly the
        /// key that `key` names.
        fn sign(&self, key: &str, payload: &[u8]) -> Vec<u8> {
            self.sign_with(key, payload, &[])
        }

        /// Returns one detached signature over `payload`, made by exactly the
        /// key that `key` names. `gpg` gets the options in `extra` in addition
        /// to the base options.
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

        /// Returns the records that `gpgv` reports for the same inputs, read
        /// through the status-stream parser. Each case compares against this
        /// reference.
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

        /// Writes one file into the fixture directory and returns its path.
        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            remove_home_sockets(&self.dir);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Runs `cmd` with `answers` on its standard input and asserts that the
    /// command succeeds. `what` names the command in the assertion message.
    fn answer(mut cmd: Command, answers: &[u8], what: &str) {
        use std::io::Write;

        let out = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .and_then(|mut child| {
                child.stdin.take().unwrap().write_all(answers)?;
                child.wait_with_output()
            })
            .unwrap();
        assert!(out.status.success(), "{what} failed");
    }

    /// The environment variable that changes the skip for an absent GnuPG
    /// binary into a failure.
    ///
    /// A harness that sets it declares that the GnuPG binaries are installed.
    /// If a binary is then absent, the harness is broken, and the test fails.
    /// The integration tests read the same variable.
    const REQUIRE_GNUPG: &str = "OSTRYA_REQUIRE_GNUPG";

    /// Returns `true` if both binaries answer. If one does not answer, it
    /// prints the name of the absent binary.
    ///
    /// These cases state each policy rule against `gpgv`. Without this check,
    /// a harness without a binary reports the rules as tested while no
    /// assertion runs. If [`REQUIRE_GNUPG`] is set, an absent binary fails.
    fn tools_available() -> bool {
        for program in ["gpg", "gpgv"] {
            if !available(program) {
                assert!(
                    std::env::var_os(REQUIRE_GNUPG).is_none(),
                    "{REQUIRE_GNUPG} is set and `{program}` is not available, \
                     so the GPG tests cannot run"
                );
                eprintln!("skipping: {program} not available");
                return false;
            }
        }
        true
    }

    /// Asserts that one record states what `gpgv` states about the same
    /// signature, field by field, the verdict included. A case that diverges
    /// from `gpgv` on purpose states the divergence itself and does not call
    /// this function.
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

    /// Asserts that one record states what `gpgv` states about the same
    /// signature, except the two key fingerprints.
    ///
    /// The two references differ on these two fields if the issuer resolved
    /// and the cryptography failed. `gpgv` prints `BADSIG <keyid> <uid>`,
    /// which names the issuer by eight bytes. The field holds a whole
    /// fingerprint, so [`parse_status`] skips that key id, and the reference
    /// record states neither fingerprint.
    ///
    /// The `ostree` command (2026.1) names both keys on the lines that it
    /// prints over such a signature:
    ///
    /// - For a signature that a subkey made, it prints
    ///   `key ID <subkey-key-id>`, the key id of the subkey, with
    ///   `Primary key ID <primary-key-id>` under it.
    /// - For a signature that the primary key made, it prints the same pair
    ///   with the primary key in both places.
    ///
    /// The report that a user reads is the oracle here, so the engine states
    /// both keys.
    ///
    /// The instant and the algorithm stay absent. `gpgv` states neither on
    /// this path. The `ostree` command prints the Unix epoch and
    /// `[unknown name]` in their places, and the engine states neither.
    fn assert_agrees_but_fingerprints(port: &SignatureInfo, reference: &SignatureInfo) {
        let mut port = port.clone();
        port.fingerprint = reference.fingerprint.clone();
        port.primary_fingerprint = reference.primary_fingerprint.clone();
        assert_agrees(&port, reference);
    }

    /// A primary-key signature reports the primary key as both the signing
    /// key and the certificate, with the user id of the certificate.
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
        // The reference verified the signature, and ostrya reports the key
        // that verified it.
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

    /// A signature with its own expiry reports the instant that it expires.
    ///
    /// The packet states a lifetime from the creation time, and the reference
    /// states an absolute instant. The engine computes the value of this field
    /// and of no other field.

    #[test]
    fn expiring_signature_agrees_with_gpgv() {
        if !tools_available() {
            return;
        }
        /// The lifetime that `--default-sig-expire 1d` writes, in seconds.
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

    /// A signature that a signing subkey made reports the subkey as the
    /// signing key and its certificate as the primary fingerprint.
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

    /// One blob with two concatenated signatures reports two records, in the
    /// order of the packets.
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
    /// `key_missing`.
    ///
    /// The record has the fingerprint, the creation time, and the two
    /// algorithm names from the signature packet. These are the fields that
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
        // The three field groups that `ERRSIG` supplies, one at a time.
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

    /// A signature over a changed payload reports the resolved signing key,
    /// its certificate, and the user id of the certificate.
    ///
    /// The engine verifies nothing else that the signature claims, so the
    /// record states nothing else. Neither reference states more.
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
        assert_agrees_but_fingerprints(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(!reference[0].valid);
        assert!(!info.key_missing);
        // The fields that the record carries on this path: the resolved
        // signing key, its certificate, and the user id of the certificate.
        // Here the signing key is the primary key, so both fingerprints name
        // it. `gpgv` names this key by eight bytes on its `BADSIG` line, and
        // `ostree` names it on the line that it prints.
        assert_eq!(info.fingerprint.as_deref(), Some(&*home.primary));
        assert_eq!(info.primary_fingerprint.as_deref(), Some(&*home.primary));
        assert_eq!(reference[0].fingerprint, None);
        assert_eq!(reference[0].primary_fingerprint, None);
        assert_eq!(info.user_name.as_deref(), Some("Bad"));
        assert_eq!(info.user_email.as_deref(), Some("bad@ostrya.example"));
        // The record states nothing else that the packet claims. `gpgv` names
        // no instant and no algorithm on `BADSIG`. `ostree` 2026.1 prints the
        // epoch instant and `[unknown name]` in their places.
        assert_eq!(info.created, None);
        assert_eq!(info.pubkey_algorithm, None);
        assert_eq!(info.hash_algorithm, None);
    }

    /// A signature by a signing subkey over a changed payload reports the
    /// subkey as the signing key and its certificate as the primary
    /// fingerprint.
    ///
    /// The `ostree` command (2026.1) names the same two keys over such a
    /// signature. It names them in the `key ID` field of the report line and
    /// on the `Primary key ID` line under the verdict. Its `gpg-sign --delete`
    /// removes the signature under the key id of either key.
    #[test]
    fn changed_payload_by_a_subkey_reports_both_keys() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Subbad <subbad@ostrya.example>");
        let subkey = home.add_signing_subkey();
        let keyring = home.keyring();
        let blob = home.sign(&subkey, PAYLOAD);
        let outcome =
            verify_signatures(&home.certs(), OTHER_PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&keyring, &blob, OTHER_PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees_but_fingerprints(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(!info.valid && !reference[0].valid);
        assert_eq!(info.fingerprint.as_deref(), Some(&*subkey));
        assert_eq!(info.primary_fingerprint.as_deref(), Some(&*home.primary));
        assert_eq!(info.user_email.as_deref(), Some("subbad@ostrya.example"));
    }

    /// A blob with half a signature packet reports one empty record.
    ///
    /// The count of records follows the count of stored blobs. `gpgv` reads
    /// no signature from the blob and states no record.
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

    /// An empty blob reports one empty record, as a truncated blob does.
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

    /// Asserts that a record states nothing about a signature.
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

    /// A blob over the limit of one mebibyte is refused.
    ///
    /// The error names the blob and states the limit. The size check comes
    /// before the parse, so the packet limit does not cause the refusal. The
    /// limit belongs to ostrya, and `gpgv` has no such limit. For this
    /// reason, this case compares nothing against `gpgv`.
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

    /// A blob with more than 64 signature packets is refused.
    ///
    /// The error names the blob and states the limit. `gpgv` reads each packet
    /// and reports one record for each, so the limit belongs to ostrya.
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
        // With one packet fewer, at the limit, the engine reports one record
        // for each packet. This shows that the limit caused the first refusal.
        let allowed = one.repeat(MAX_SIGNATURE_PACKETS);
        let outcome = verify_signatures(&certs, PAYLOAD, &[allowed]).unwrap();
        assert_eq!(outcome.signatures.len(), MAX_SIGNATURE_PACKETS);
    }

    /// A blob with the maximum number of whole packets and a partial packet at
    /// the end reports one record for each whole packet.
    ///
    /// The stream stops at the partial packet. Each blob that ends in a
    /// partial packet gets this report. The limit counts only the whole
    /// packets of the stream, as `too_many_signature_packets_is_refused`
    /// states.
    ///
    /// `gpgv` reads the same whole packets and states one record for each.
    /// Over this blob, it reports one `GOODSIG` line for each whole packet and
    /// exits 0. It skips the partial packet with no diagnostic.
    #[test]
    fn a_partial_packet_after_the_cap_ends_the_stream() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Cap <cap@ostrya.example>");
        let keyring = home.keyring();
        let one = home.sign(&home.primary, PAYLOAD);
        let mut blob = one.repeat(MAX_SIGNATURE_PACKETS);
        blob.extend_from_slice(&one[..one.len() / 2]);
        assert!(blob.len() <= MAX_SIGNATURE_BLOB);
        let outcome =
            verify_signatures(&home.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        assert_eq!(outcome.signatures.len(), MAX_SIGNATURE_PACKETS);
        assert!(outcome.valid);
        assert_eq!(
            home.gpgv_records(&keyring, &blob, PAYLOAD).len(),
            MAX_SIGNATURE_PACKETS
        );
    }

    /// Each stored blob gives at least one record, so a run over several
    /// blobs reports them in the order of storage.
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

    /// The instant that `Fixture::at` sets the clock to, in seconds since the
    /// Unix epoch: 2025-01-01T00:00:00Z.
    const KEY_CREATED: u64 = 1735689600;
    /// One day in seconds, the lifetime that `1d` states.
    const ONE_DAY: u64 = 24 * 60 * 60;
    /// Ten years in seconds. `gpg` counts a year as 365 days.
    const TEN_YEARS: u64 = 10 * 365 * ONE_DAY;

    /// Returns the certificates that a verifier loads from a keyring blob.
    fn certs_of(keyring: &[u8]) -> Vec<SignedPublicKey> {
        std::sync::Arc::unwrap_or_clone(GpgVerifier::from_keyring_bytes([keyring]).unwrap().certs)
    }

    /// Splits an OpenPGP packet stream into (tag, body) pairs.
    ///
    /// The function reads both packet header formats, because `gpg` writes the
    /// old one and the `pgp` crate writes the new one.
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

    /// Joins (tag, body) pairs into an OpenPGP packet stream, in the old
    /// header format that `gpg` writes.
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

    /// Removes the embedded primary-key binding signature (unhashed subpacket
    /// 32) from each subkey binding signature of a certificate.
    ///
    /// The subpacket is in the unhashed area, so the binding signature still
    /// verifies over the remaining bytes. The result has the shape of a
    /// stapled subkey: a binding that the primary key made, with no
    /// back-signature under it.
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

    /// Inverts the last byte of the embedded primary-key binding signature
    /// (unhashed subpacket 32) in each subkey binding signature of a
    /// certificate.
    ///
    /// The back-signature stays in place and verifies against nothing. The
    /// subpacket is in the unhashed area, so the binding signature still
    /// verifies. An attacker who holds no subkey secret can build this shape
    /// over a genuine binding.
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

    /// Inserts one packet directly after the primary key packet of a
    /// certificate, where a direct-key signature and a key revocation
    /// signature go.
    fn insert_after_primary(cert: &[u8], packet: &[u8]) -> Vec<u8> {
        let mut packets = split_packets(cert);
        assert_eq!(packets[0].0, 6, "the first packet is the primary key");
        let mut inserted = split_packets(packet);
        assert_eq!(inserted.len(), 1);
        packets.insert(1, inserted.remove(0));
        join_packets(&packets)
    }

    /// Staples a revocation-key subpacket into the unhashed area of the one
    /// certification self-signature of a certificate.
    ///
    /// The subpacket names the key that `revoker` names in uppercase hex. The
    /// unhashed area is outside the bytes that the signature covers, so the
    /// self-signature still verifies over the bytes that it covered before.
    /// A person who holds no key of the certificate can build this shape. The
    /// designation is stapled on, and the certificate still parses and
    /// verifies.
    fn staple_revocation_key(cert: &[u8], revoker: &str) -> Vec<u8> {
        let fingerprint: Vec<u8> = (0..revoker.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&revoker[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(fingerprint.len(), 20, "a version 4 key fingerprint");
        // Signature subpacket 12 carries a class octet and a public-key
        // algorithm octet before the fingerprint. For an ed25519 revoker,
        // `gpg` writes class 0x80 and algorithm 22.
        let mut body = vec![12, 0x80, 22];
        body.extend_from_slice(&fingerprint);
        let mut subpacket = vec![u8::try_from(body.len()).unwrap()];
        subpacket.extend_from_slice(&body);

        let mut packets = split_packets(cert);
        let mut stapled = 0;
        for (tag, body) in &mut packets {
            if *tag != 2 || body[0] != 4 || body[1] != 0x13 {
                continue;
            }
            let hashed = usize::from(u16::from_be_bytes([body[4], body[5]]));
            let start = 6 + hashed;
            let len = usize::from(u16::from_be_bytes([body[start], body[start + 1]]));
            let mut new = body[..start].to_vec();
            new.extend_from_slice(&(u16::try_from(len + subpacket.len()).unwrap()).to_be_bytes());
            new.extend_from_slice(&body[start + 2..start + 2 + len]);
            new.extend_from_slice(&subpacket);
            new.extend_from_slice(&body[start + 2 + len..]);
            *body = new;
            stapled += 1;
        }
        assert_eq!(stapled, 1, "one designation was stapled");
        join_packets(&packets)
    }

    /// Returns the key revocation signature packet of a certificate, as a
    /// stream of one packet.
    fn key_revocation_packet(cert: &[u8]) -> Vec<u8> {
        let packets = split_packets(cert);
        let found = packets
            .iter()
            .find(|(tag, body)| *tag == 2 && body[0] == 4 && body[1] == 0x20)
            .expect("a key revocation signature packet");
        join_packets(std::slice::from_ref(found))
    }

    /// Attaches the first subkey of `donor`, with its binding signature in
    /// `donor`, to the end of `host`.
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

    /// Returns the first subkey of a certificate as a separate certificate.
    ///
    /// The Public-Subkey packet (tag 14) is written as a Public-Key packet
    /// (tag 6), with no signature under it. A v4 key fingerprint is a digest
    /// over the key material, so the new certificate holds the same key as the
    /// subkey. It answers for the same issuer. The keyring parser reads this
    /// shape, a certificate with a key and nothing else.
    fn subkey_as_certificate(cert: &[u8]) -> Vec<u8> {
        let packets = split_packets(cert);
        let (_, body) = packets
            .iter()
            .find(|(tag, _)| *tag == 14)
            .expect("the certificate holds a subkey");
        join_packets(&[(6, body.clone())])
    }

    /// Removes one user id and the signatures under it from a certificate.
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

    /// The fields of one self-signature that the cases build.
    ///
    /// `gpg` 2.4.9 writes no signature expiration time into a self-signature.
    /// It writes the key expiration time only into the certification
    /// self-signature. The cases build each other combination with the `pgp`
    /// crate, over the secret key that the same GnuPG home exported.
    #[derive(Clone, Copy)]
    struct SelfSig {
        /// The creation instant of the signature.
        created: u64,
        /// The key lifetime that signature subpacket 9 states, in seconds after
        /// the key creation time. `None` if the signature has no such
        /// subpacket.
        key_lifetime: Option<u64>,
        /// The signature lifetime that signature subpacket 3 states, in seconds
        /// after the signature creation time. `None` if the signature has no
        /// such subpacket.
        sig_lifetime: Option<u64>,
        /// If `true`, the signature marks its user id as primary.
        marks_primary: bool,
    }

    impl SelfSig {
        /// Creates a self-signature made at `created` that states nothing
        /// else.
        fn at(created: u64) -> SelfSig {
            SelfSig {
                created,
                key_lifetime: None,
                sig_lifetime: None,
                marks_primary: false,
            }
        }

        /// Returns the same self-signature with the key lifetime `lifetime`,
        /// if one is given.
        fn key_lifetime(self, lifetime: Option<u64>) -> SelfSig {
            SelfSig {
                key_lifetime: lifetime,
                ..self
            }
        }

        /// Returns the same self-signature, which expires `lifetime` seconds
        /// after its creation.
        fn expiring_after(self, lifetime: u64) -> SelfSig {
            SelfSig {
                sig_lifetime: Some(lifetime),
                ..self
            }
        }

        /// Returns the same self-signature, which marks its user id as
        /// primary.
        fn marking_primary(self) -> SelfSig {
            SelfSig {
                marks_primary: true,
                ..self
            }
        }
    }

    /// Returns the hashed subpackets of the self-signature that `spec`
    /// describes: the creation time, the issuer fingerprint, and the
    /// subpackets that `spec` states.
    fn self_signature_subpackets<K: pgp::types::KeyDetails>(
        spec: SelfSig,
        public: &K,
    ) -> Vec<pgp::packet::Subpacket> {
        use pgp::packet::{Subpacket, SubpacketData};
        use pgp::types::Duration;

        let mut hashed = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                u32::try_from(spec.created).unwrap(),
            )))
            .unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(public.fingerprint())).unwrap(),
        ];
        if let Some(lifetime) = spec.key_lifetime {
            hashed.push(
                Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(
                    u32::try_from(lifetime).unwrap(),
                )))
                .unwrap(),
            );
        }
        if let Some(lifetime) = spec.sig_lifetime {
            hashed.push(
                Subpacket::regular(SubpacketData::SignatureExpirationTime(Duration::from_secs(
                    u32::try_from(lifetime).unwrap(),
                )))
                .unwrap(),
            );
        }
        if spec.marks_primary {
            hashed.push(Subpacket::regular(SubpacketData::IsPrimary(true)).unwrap());
        }
        hashed
    }

    /// Returns a direct-key self-signature (type 0x1F) over a primary key, as
    /// `spec` states it.
    fn direct_self_signature(secret: &[u8], spec: SelfSig) -> Vec<u8> {
        use pgp::packet::{PacketTrait, SignatureConfig, Subpacket, SubpacketData};
        use pgp::types::Password;

        let secret_key = pgp::composed::SignedSecretKey::from_bytes(Cursor::new(secret)).unwrap();
        let public = secret_key.primary_key.public_key();
        let mut config = SignatureConfig::v4(
            SignatureType::Key,
            PublicKeyAlgorithm::EdDSALegacy,
            HashAlgorithm::Sha512,
        );
        config.hashed_subpackets = self_signature_subpackets(spec, &public);
        config.unhashed_subpackets =
            vec![Subpacket::regular(SubpacketData::IssuerKeyId(public.legacy_key_id())).unwrap()];
        let signature = config
            .sign_key(&secret_key.primary_key, &Password::empty(), public)
            .unwrap();
        let mut bytes = Vec::new();
        signature.to_writer_with_header(&mut bytes).unwrap();
        bytes
    }

    /// Returns a certification self-signature (type 0x13) over the first user
    /// id of the certificate, as `spec` states it.
    fn certification_self_signature(secret: &[u8], spec: SelfSig) -> Vec<u8> {
        use pgp::packet::{PacketTrait, SignatureConfig, Subpacket, SubpacketData};
        use pgp::types::Password;

        let secret_key = pgp::composed::SignedSecretKey::from_bytes(Cursor::new(secret)).unwrap();
        let public = secret_key.primary_key.public_key();
        let user = &secret_key.details.users[0];
        let mut config = SignatureConfig::v4(
            SignatureType::CertPositive,
            PublicKeyAlgorithm::EdDSALegacy,
            HashAlgorithm::Sha512,
        );
        config.hashed_subpackets = self_signature_subpackets(spec, &public);
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

    /// Returns a subkey binding signature (type 0x18) that the primary key
    /// makes over the first subkey of the certificate.
    ///
    /// The signature has the creation time `created`. It carries these items:
    ///
    /// - the signing key flag
    /// - the back-signature that the subkey makes
    /// - the signature lifetime `sig_lifetime`, if one is given
    fn subkey_binding_signature(secret: &[u8], created: u64, sig_lifetime: Option<u64>) -> Vec<u8> {
        use pgp::packet::{KeyFlags, PacketTrait, SignatureConfig, Subpacket, SubpacketData};
        use pgp::types::Password;

        let secret_key = pgp::composed::SignedSecretKey::from_bytes(Cursor::new(secret)).unwrap();
        let primary = secret_key.primary_key.public_key();
        let sub = &secret_key.secret_subkeys[0];
        let sub_public = sub.key.public_key();

        let mut back = SignatureConfig::v4(
            SignatureType::KeyBinding,
            PublicKeyAlgorithm::EdDSALegacy,
            HashAlgorithm::Sha512,
        );
        back.hashed_subpackets = self_signature_subpackets(SelfSig::at(created), &sub_public);
        back.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerKeyId(sub_public.legacy_key_id())).unwrap(),
        ];
        let back = back
            .sign_primary_key_binding(&sub.key, &sub_public, &Password::empty(), &primary)
            .unwrap();

        let mut flags = KeyFlags::default();
        flags.set_sign(true);
        let mut config = SignatureConfig::v4(
            SignatureType::SubkeyBinding,
            PublicKeyAlgorithm::EdDSALegacy,
            HashAlgorithm::Sha512,
        );
        let spec = SelfSig::at(created);
        config.hashed_subpackets = self_signature_subpackets(
            match sig_lifetime {
                Some(lifetime) => spec.expiring_after(lifetime),
                None => spec,
            },
            &primary,
        );
        config
            .hashed_subpackets
            .push(Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap());
        config.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerKeyId(primary.legacy_key_id())).unwrap(),
            Subpacket::regular(SubpacketData::EmbeddedSignature(Box::new(back))).unwrap(),
        ];
        let signature = config
            .sign_subkey_binding(
                &secret_key.primary_key,
                &primary,
                &Password::empty(),
                &sub_public,
            )
            .unwrap();
        let mut bytes = Vec::new();
        signature.to_writer_with_header(&mut bytes).unwrap();
        bytes
    }

    /// Replaces the one subkey binding signature of a certificate with
    /// `packet`.
    fn replace_subkey_binding(cert: &[u8], packet: &[u8]) -> Vec<u8> {
        let mut inserted = split_packets(packet);
        assert_eq!(inserted.len(), 1);
        let replacement = inserted.remove(0);
        let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut replaced = 0;
        for (tag, body) in split_packets(cert) {
            if tag == 2 && body[0] == 4 && body[1] == 0x18 {
                out.push(replacement.clone());
                replaced += 1;
            } else {
                out.push((tag, body));
            }
        }
        assert_eq!(replaced, 1, "one binding signature was replaced");
        join_packets(&out)
    }

    /// Inserts one packet directly after the signatures under the user id
    /// `id`. A certification over that user id goes there.
    fn insert_after_user_id(cert: &[u8], id: &str, packet: &[u8]) -> Vec<u8> {
        let packets = split_packets(cert);
        let at = packets
            .iter()
            .position(|(tag, body)| *tag == 13 && body == id.as_bytes())
            .expect("the certificate holds the user id");
        let mut end = at + 1;
        while end < packets.len() && packets[end].0 == 2 {
            end += 1;
        }
        let mut inserted = split_packets(packet);
        assert_eq!(inserted.len(), 1);
        let mut out = packets[..end].to_vec();
        out.push(inserted.remove(0));
        out.extend_from_slice(&packets[end..]);
        join_packets(&out)
    }

    /// Returns a direct-key self-signature with the creation time `created`
    /// and the key lifetime `lifetime`.
    fn direct_key_signature(secret: &[u8], created: u64, lifetime: u64) -> Vec<u8> {
        direct_self_signature(secret, SelfSig::at(created).key_lifetime(Some(lifetime)))
    }

    /// A signature by a primary key is valid if the key is live and not
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

    /// A signature by a signing subkey is valid if the binding signature of
    /// the primary key carries the back-signature of the subkey.

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

    /// A subkey stapled onto a certificate signs for nothing.
    ///
    /// Three shapes state this rule:
    ///
    /// - a binding signature by the primary key, with the back-signature
    ///   removed
    /// - the same binding, with a back-signature that is present and verifies
    ///   against nothing
    /// - a subkey from another certificate, together with its binding from
    ///   that certificate
    ///
    /// An attacker who holds no subkey secret can make the first two shapes.
    #[test]
    fn stapled_subkey_is_refused() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Staple <staple@ostrya.example>");
        let subkey = home.add_signing_subkey();
        let whole = home.keyring();
        let blob = home.sign(&subkey, PAYLOAD);
        // The intact certificate is the control. With it, the same signature
        // verifies.
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
        // The binding signature still verifies, so the certificate holds the
        // subkey. Only the back-signature is missing.
        assert!(!info.key_missing);
        assert_eq!(info.fingerprint.as_deref(), Some(&*subkey));
        assert_eq!(info.user_name, None);

        // The back-signature is present and verifies against nothing. The
        // subpacket is in the unhashed area, so the binding signature still
        // verifies. The presence of a back-signature must not be sufficient.
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

        // The same subkey attached to another certificate, with its binding
        // signature. The binding does not verify under the other primary key,
        // so the subkey belongs to no loaded certificate.
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

    /// An expired key states its expiry instant and is not valid. The instant
    /// is the key creation time plus the lifetime that the self-signature
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
        // The signature was made while the key was live. The engine reads the
        // key state against the current clock.
        assert_eq!(info.created, Some(KEY_CREATED));
    }

    /// A signing subkey does not outlive its certificate.
    ///
    /// In this case, the primary key is expired, and the binding signature of
    /// the subkey states no expiry. `gpgv` reports the expiry instant of the
    /// primary key.
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

        // A subkey with its own lifetime also does not outlive the
        // certificate. The earlier of the two instants applies.
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
    /// lifetime, so the certification self-signature applies.
    ///
    /// In this case, the certification self-signature states one day, which
    /// is past. The direct-key signature states zero. `gpgv` reports the
    /// expiry that the one day gives.
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
        // The control shows that the engine reads the direct-key signature.
        // The same signature with ten years makes the same key live.
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

    /// The key expiration time of a primary key comes from a verified
    /// direct-key self-signature, if the certificate has one.
    ///
    /// If it has none, the expiration time comes from the certification
    /// self-signature. The three states in this case are the answers of `gpgv`
    /// over the same three certificates.
    #[test]
    fn direct_key_signature_states_the_key_expiry() {
        if !tools_available() {
            return;
        }
        // The certification self-signature states one day, which is past. The
        // direct-key signature states ten years.
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

        // A direct-key signature with changed bytes verifies against nothing,
        // and the engine skips it. The certification self-signature applies,
        // and the key is expired.
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

        // The certification self-signature states ten years, and the
        // direct-key signature states one day, so the key is expired.
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
        // The record still names the key and the user id. The `REVKEYSIG` and
        // `VALIDSIG` pair carries the same fields.
        assert_eq!(info.fingerprint.as_deref(), Some(&*home.primary));
        assert_eq!(info.user_email.as_deref(), Some("gone@ostrya.example"));
    }

    /// A revoked signing subkey is reported revoked and is not valid. The
    /// primary key of its certificate stays valid and not revoked.
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
        // The revocation applies only to the subkey.
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
    /// own.
    ///
    /// The record names a user id that is not revoked. The primary-user-id
    /// subpacket on a revoked user id has no effect. If all user ids are
    /// revoked, the record names a revoked one.
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

        // `gpg` refuses to revoke the last valid user id. To get the state
        // where all user ids are revoked, the case removes the other user id.

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

    /// An MD5 data signature is refused. This crate and `gpgv` 2.4.9 agree.
    ///
    /// rPGP verifies an MD5 signature as good. The refusal is a policy that
    /// belongs to ostrya. The digest policy of GnuPG is configurable and
    /// changes between versions, so ostrya states its own policy. The
    /// divergence record names this class of digest and no `gpgv` version.
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
        // The digest check applies before the key check. For this reason, the
        // record carries the fields of the signature packet and no user id.
        // The key that the record names is in the keyring.
        assert!(!info.key_missing);
        assert_eq!(info.fingerprint.as_deref(), Some(&*home.primary));
        assert_eq!(info.user_name, None);
        // With an allowed digest, a signature of the same key over the same
        // payload is valid. This shows that the digest policy refused the MD5
        // signature.
        let allowed = home.sign(&home.primary, PAYLOAD);
        let outcome = verify_signatures(&home.certs(), PAYLOAD, &[allowed]).unwrap();
        assert!(outcome.valid);
    }

    /// A SHA-1 data signature is accepted. This crate and `gpgv` 2.4.9 agree.
    ///
    /// The key is RSA because rPGP has its own rule for an Ed25519 key. A
    /// digest of less than 256 bits "is too weak for Ed25519". For this reason,
    /// a SHA-1 signature by an Ed25519 key verifies against nothing. This is a
    /// divergence from `gpgv`, which reports `GOODSIG`.
    ///
    /// The second part of this test states the divergence.
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

        // The declared divergence: the same digest with an Ed25519 key. `gpgv`
        // accepts the signature. This crate reports a signature that verifies
        // against nothing. The cause is that rPGP refuses the digest for that
        // algorithm before a policy of ostrya applies.
        let eddsa = Fixture::new("Ed <ed@ostrya.example>");
        let ring = eddsa.keyring();
        let blob = eddsa.sign_with(&eddsa.primary, PAYLOAD, &["--digest-algo", "SHA1"]);
        let outcome =
            verify_signatures(&eddsa.certs(), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = eddsa.gpgv_records(&ring, &blob, PAYLOAD);
        assert_eq!(reference.len(), 1);
        assert!(reference[0].valid, "the reference accepts it");
        assert!(!outcome.signatures[0].valid, "the port does not");
        // The record has the form of a signature that verifies against
        // nothing. It names the resolved signing key, its certificate, and the
        // user id of the certificate. The primary key made this signature, so
        // both fingerprints name it.
        assert_eq!(
            outcome.signatures[0].fingerprint.as_deref(),
            Some(&*eddsa.primary)
        );
        assert_eq!(
            outcome.signatures[0].primary_fingerprint.as_deref(),
            Some(&*eddsa.primary)
        );
        assert_eq!(
            outcome.signatures[0].user_email.as_deref(),
            Some("ed@ostrya.example")
        );
    }

    /// A key revocation signature of another key, stapled onto a certificate,
    /// revokes nothing. The engine verifies a revocation before it applies it.
    /// For this reason, a packet that anyone can attach has no effect.
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
        // The stapled packet is in the parsed certificate. This shows that the
        // parse kept the packet and the verification refused it.
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
        // The same packet revokes the certificate that it was made for.
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

    /// The signature and the keyrings for the designated-revoker tests.
    ///
    /// The fixture generates two keys. The signing key makes the data
    /// signature. It designates the other key, the revoker, through signature
    /// subpacket 12. `gpg --desig-revoke` writes the class 0x20 revocation of
    /// the revoker over the signing key.
    ///
    /// The four keyring fields hold the states that the tests read.
    struct Designated {
        /// The home of the signing key. Its key made [`Designated::blob`]. Its
        /// `gv` directory is the `--homedir` of each `gpgv` run.
        home: Fixture,
        /// The fingerprint of the primary key of the revoker, in uppercase hex.
        revoker: String,
        /// The exported certificate of the revoker.
        revoker_cert: Vec<u8>,
        /// The detached signature of the signing key over [`PAYLOAD`].
        blob: Vec<u8>,
        /// The signing key with the designation and with the revocation of the
        /// designated revoker.
        designated: Vec<u8>,
        /// The `designated` state and the certificate of the revoker.
        designated_with_revoker: Vec<u8>,
        /// The signing key with the same revocation and no designation.
        undesignated: Vec<u8>,
        /// The `undesignated` state and the certificate of the revoker.
        undesignated_with_revoker: Vec<u8>,
    }

    impl Designated {
        fn build() -> Designated {
            let home = Fixture::new("Signing K <k@ostrya.example>");
            let revoker = Fixture::new("Revoker R <r@ostrya.example>");
            let blob = home.sign(&home.primary, PAYLOAD);
            let plain = home.export_keys(&[&home.primary]);
            let revoker_cert = revoker.export_keys(&[&revoker.primary]);
            // The designation names the revoker by fingerprint. For this
            // reason, the home of the signing key holds the certificate of the
            // revoker when it writes the designating self-signature.
            home.import(&revoker_cert);
            home.add_revoker(&revoker.primary);
            let designating = home.export_keys(&[&home.primary]);
            // The revoker makes the revocation in a home that holds its secret
            // key and the certificate that designates it.
            revoker.import(&designating);
            let revocation = revoker.desig_revoke(&home.primary);

            // This function builds each keyring as in the measurement of the
            // states. A home imports the certificates of the state and exports
            // them.
            let with_designation = Fixture::bare();
            with_designation.import(&designating);
            with_designation.import_merging(&revocation);
            let designated = with_designation.export_keys(&[&home.primary]);
            let and_revoker = Fixture::bare();
            and_revoker.import(&designating);
            and_revoker.import_merging(&revocation);
            and_revoker.import(&revoker_cert);
            let designated_with_revoker =
                and_revoker.export_keys(&[&home.primary, &revoker.primary]);

            // An import of the revocation also merges the designating
            // self-signature. For this reason, this function splices the state
            // with the revocation and no designation. The revocation packet
            // goes after the primary key packet of a certificate without
            // subpacket 12.
            let undesignated = insert_after_primary(&plain, &key_revocation_packet(&designated));
            let undesignated_with_revoker = [&undesignated[..], &revoker_cert[..]].concat();
            Designated {
                home,
                revoker: revoker.primary.clone(),
                revoker_cert,
                blob,
                designated,
                designated_with_revoker,
                undesignated,
                undesignated_with_revoker,
            }
        }

        /// Asserts the shape of `keyring` and returns its certificates.
        ///
        /// The function checks these conditions:
        ///
        /// - `keyring` holds `certs` certificates
        /// - the first certificate carries one key revocation signature
        /// - the first certificate names `designations` revokers.
        ///
        /// If the fixture of a test is not the state that the test names, the
        /// test fails here.
        fn assert_state(keyring: &[u8], certs: usize, designations: usize) -> Vec<SignedPublicKey> {
            let parsed = certs_of(keyring);
            assert_eq!(parsed.len(), certs, "the trusted set");
            assert_eq!(
                parsed[0].details.revocation_signatures.len(),
                1,
                "the key revocation signature reached the parsed certificate"
            );
            assert_eq!(
                designated_revokers(&parsed[0]).len(),
                designations,
                "the designations the certificate carries"
            );
            parsed
        }
    }

    /// If the certificate of a designated revoker is not in the trusted set,
    /// its key revocation has no effect.
    ///
    /// The signature stays good. `gpgv` 2.4.9 gives the same result. On this
    /// keyring, it reports `GOODSIG` and prints no `KEY_CONSIDERED` line for
    /// the revoker. This shows that `gpgv` did not resolve the revoker.
    #[test]
    fn an_unloaded_designated_revoker_does_not_revoke() {
        if !tools_available() {
            return;
        }
        let state = Designated::build();
        let certs = Designated::assert_state(&state.designated, 1, 1);
        let outcome =
            verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&state.blob)).unwrap();
        let reference = state
            .home
            .gpgv_records(&state.designated, &state.blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(!outcome.signatures[0].revoked);
        assert!(outcome.signatures[0].valid);
        assert!(outcome.valid);
    }

    /// If the certificate of a designated revoker is loaded, its key
    /// revocation revokes the key. The signature is refused. `gpgv` 2.4.9
    /// reports `REVKEYSIG` on this keyring.
    ///
    /// For the signing key, the keyring holds the same bytes as the keyring of
    /// `an_unloaded_designated_revoker_does_not_revoke`. The certificate of the
    /// revoker is the only difference between the two states.
    #[test]
    fn a_loaded_designated_revoker_revokes_the_key() {
        if !tools_available() {
            return;
        }
        let state = Designated::build();
        assert_eq!(
            &state.designated_with_revoker[..state.designated.len()],
            &state.designated[..],
            "the keyring holds the signing key as the unloaded state holds it"
        );
        let certs = Designated::assert_state(&state.designated_with_revoker, 2, 1);
        assert_eq!(format!("{:X}", certs[1].fingerprint()), state.revoker);
        let outcome =
            verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&state.blob)).unwrap();
        let reference =
            state
                .home
                .gpgv_records(&state.designated_with_revoker, &state.blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(info.revoked);
        assert!(!info.valid);
        assert!(!outcome.valid);
        // The record still names the key and the user id. The `REVKEYSIG` and
        // `VALIDSIG` pair carries the same fields.
        assert_eq!(
            info.fingerprint.as_deref(),
            Some(&*state.home.primary),
            "the signing key"
        );
        assert_eq!(info.user_email.as_deref(), Some("k@ostrya.example"));
    }

    /// A revocation by another key applies only through a designation.
    ///
    /// On a certificate that designates no revoker, the byte-identical
    /// revocation revokes nothing. This is true if the certificate of the
    /// revoker is loaded, and also if it is not. The signature stays good.
    /// `gpgv` 2.4.9 reports `GOODSIG` on both keyrings.
    #[test]
    fn an_undesignated_revocation_does_not_revoke() {
        if !tools_available() {
            return;
        }
        let state = Designated::build();
        assert_eq!(
            key_revocation_packet(&state.undesignated),
            key_revocation_packet(&state.designated),
            "the two states carry the same revocation packet"
        );
        for (label, keyring, certs) in [
            ("the revoker absent", &state.undesignated, 1),
            ("the revoker loaded", &state.undesignated_with_revoker, 2),
        ] {
            let certs = Designated::assert_state(keyring, certs, 0);
            let outcome =
                verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&state.blob)).unwrap();
            let reference = state.home.gpgv_records(keyring, &state.blob, PAYLOAD);
            assert_eq!(outcome.signatures.len(), 1, "{label}");
            assert_eq!(reference.len(), 1, "{label}");
            assert_agrees(&outcome.signatures[0], &reference[0]);
            assert!(!outcome.signatures[0].revoked, "{label}");
            assert!(outcome.signatures[0].valid, "{label}");
            assert!(outcome.valid, "{label}");
        }
    }

    /// A designation that the self-signature does not cover names no revoker.
    ///
    /// The signature does not cover the unhashed subpacket area. For this
    /// reason, anyone can staple a subpacket 12 onto a certificate, and the
    /// self-signature still verifies. The engine reads only the hashed area.
    /// The revocation of the named key revokes nothing, and the signature
    /// stays good.
    ///
    /// `gpgv` 2.4.9 gives the same result. It reports `GOODSIG` on a keyring
    /// with these parts:
    ///
    /// - the revocation
    /// - the certificate of the revoker
    /// - the designation, stapled into the unhashed area.
    #[test]
    fn a_stapled_designation_names_no_revoker() {
        if !tools_available() {
            return;
        }
        let state = Designated::build();
        let stapled = staple_revocation_key(&state.undesignated, &state.revoker);
        let keyring = [&stapled[..], &state.revoker_cert[..]].concat();
        let certs = Designated::assert_state(&keyring, 2, 0);
        assert_eq!(format!("{:X}", certs[1].fingerprint()), state.revoker);
        let outcome =
            verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&state.blob)).unwrap();
        let reference = state.home.gpgv_records(&keyring, &state.blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(!outcome.signatures[0].revoked);
        assert!(outcome.signatures[0].valid);
        assert!(outcome.valid);
    }

    /// A designation on a self-signature that does not verify names no
    /// revoker.
    ///
    /// The revocation of the designated revoker revokes nothing, and the
    /// signature stays good. `gpgv` 2.4.9 gives the same result.
    ///
    /// The test starts from the state on which `gpgv` reports `REVKEYSIG`. It
    /// inverts the last byte of the designating self-signature. On this
    /// keyring, `gpgv` reports `GOODSIG` and prints no `KEY_CONSIDERED` line
    /// for the revoker.
    #[test]
    fn an_unverified_designation_names_no_revoker() {
        if !tools_available() {
            return;
        }
        let state = Designated::build();
        // `gpg` writes the designation into a direct-key self-signature. It is
        // the only class 0x1f signature of the state.
        let keyring = alter_signature(&state.designated_with_revoker, 0x1f);
        let certs = Designated::assert_state(&keyring, 2, 0);
        let outcome =
            verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&state.blob)).unwrap();
        let reference = state.home.gpgv_records(&keyring, &state.blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(!outcome.signatures[0].revoked);
        assert!(outcome.signatures[0].valid);
        assert!(outcome.valid);
    }

    /// A key with two certificates in the trusted set, one of them revoked, is
    /// refused in either order.
    ///
    /// Two certificates for one key reach the trusted set on ordinary paths,
    /// so the verdict reads each certificate for the issuer. If one of them
    /// carries a revocation, the signature is refused. The ordinary paths:
    ///
    /// - the `<remote>.trustedkeys.gpg` of a repository and the global trusted
    ///   directory
    /// - two `gpgkeypath` entries
    /// - one keyring file that holds two exports of one key.
    ///
    /// The result of `gpgv` 2.4.9 depends on the load order, so the test does
    /// not compare the verdict with it. If the unrevoked certificate is first,
    /// `gpgv` reports `GOODSIG`. In the reverse order, it reports `REVKEYSIG`.
    ///
    /// The engine reports the revocation in both orders. The test asserts the
    /// result of `gpgv` too, so it fails if `gpgv` changes this behavior. Each
    /// certificate alone is a control on which the two engines agree.
    #[test]
    fn a_revocation_on_a_duplicate_certificate_refuses_the_signature() {
        if !tools_available() {
            return;
        }
        let home = Fixture::new("Dup <dup@ostrya.example>");
        let blob = home.sign(&home.primary, PAYLOAD);
        let unrevoked = home.keyring();
        home.revoke_primary();
        let revoked = home.keyring();
        for (label, keyring, is_revoked) in [
            ("the unrevoked certificate", &unrevoked, false),
            ("the revoked certificate", &revoked, true),
        ] {
            let certs = certs_of(keyring);
            assert_eq!(certs.len(), 1, "{label}: the trusted set");
            let outcome = verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&blob)).unwrap();
            let reference = home.gpgv_records(keyring, &blob, PAYLOAD);
            assert_eq!(outcome.signatures.len(), 1);
            assert_eq!(reference.len(), 1);
            assert_agrees(&outcome.signatures[0], &reference[0]);
            assert_eq!(outcome.signatures[0].revoked, is_revoked, "{label}");
            assert_eq!(outcome.signatures[0].valid, !is_revoked, "{label}");
        }
        for (label, first, second, reference_revoked) in [
            ("the revocation second", &unrevoked, &revoked, false),
            ("the revocation first", &revoked, &unrevoked, true),
        ] {
            let mut keyring = first.clone();
            keyring.extend_from_slice(second);
            let certs = certs_of(&keyring);
            // Both certificates are in the trusted set. This shows that the
            // parse kept both of them and the verdict reads both of them.
            assert_eq!(certs.len(), 2, "{label}: the trusted set");
            let outcome = verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&blob)).unwrap();
            assert_eq!(outcome.signatures.len(), 1);
            let info = &outcome.signatures[0];
            assert!(info.revoked, "{label}: the revocation was not read");
            assert!(!info.valid, "{label}: a revoked key reported valid");
            assert!(!outcome.valid, "{label}: the outcome");
            // The fields of the report come from the first match. The two
            // certificates state the same key and the same user id.
            assert_eq!(info.fingerprint.as_deref(), Some(&*home.primary), "{label}");
            assert_eq!(
                info.user_email.as_deref(),
                Some("dup@ostrya.example"),
                "{label}"
            );
            let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
            assert_eq!(reference.len(), 1, "{label}: the reference record count");
            assert_eq!(
                reference[0].revoked, reference_revoked,
                "{label}: gpgv no longer answers on the load order, so this \
                 case states the wrong thing about the reference",
            );
        }
    }

    /// Two exports of one certificate state the key expiry of the newest
    /// self-signature, in either order.
    ///
    /// The engine reads two exports of one certificate as one certificate. Two
    /// exports reach the trusted set on the ordinary paths that
    /// `a_revocation_on_a_duplicate_certificate_refuses_the_signature` lists.
    /// An expiry is renewable. If the owner of the key replaces an export, the
    /// newer export states the lifetime.
    ///
    /// The key of each fixture has the creation time [`KEY_CREATED`]. `gpg`
    /// writes the second export with a clock one day later. For this reason,
    /// its new self-signature has its own creation time and is the newer
    /// statement.
    ///
    /// The result of `gpgv` 2.4.9 depends on the load order, so the test does
    /// not compare the verdict with it. `gpgv` reads the first certificate for
    /// the key in its keyrings. `gpg --import` merges the two exports into one
    /// keyblock and uses the newest statement. The engine gives this result
    /// for the two exports in either order.
    ///
    /// The three pairs of `cases` were measured, imported in both orders. On
    /// the merged keyring, `gpgv` reports `GOODSIG` for the first two pairs
    /// and `EXPKEYSIG` for the third.
    #[test]
    fn a_duplicate_certificate_states_the_newest_expiry() {
        if !tools_available() {
            return;
        }
        /// One pair of exports of one certificate.
        struct Case {
            /// The lifetime of the key at creation.
            created: &'static str,
            /// If `true`, that lifetime is over.
            created_expired: bool,
            /// The lifetime that the second export states. `gpg` writes it one
            /// day later.
            replaced: &'static str,
            /// If `true`, that lifetime is over.
            replaced_expired: bool,
            /// The expiry instant of the key that the two exports state
            /// together. `None` if the key stays live.
            expires: Option<u64>,
        }
        let cases = [
            // An expiry in the past, extended by ten years.
            Case {
                created: "1d",
                created_expired: true,
                replaced: "10y",
                replaced_expired: false,
                expires: None,
            },
            // The same expiry, removed.
            Case {
                created: "1d",
                created_expired: true,
                replaced: "never",
                replaced_expired: false,
                expires: None,
            },
            // A key with no expiry gets an expiry in the past. The newest
            // statement applies, also when it gives the shorter lifetime.
            Case {
                created: "never",
                created_expired: false,
                replaced: "1d",
                replaced_expired: true,
                expires: Some(KEY_CREATED + 2 * ONE_DAY),
            },
        ];
        for (index, case) in cases.iter().enumerate() {
            let email = format!("twice{index}@ostrya.example");
            let home = Fixture::at(&format!("Twice{index} <{email}>"), case.created);
            let blob = home.sign(&home.primary, PAYLOAD);
            let created = home.keyring();
            home.set_expire_at("20250102T000000!", case.replaced);
            let replaced = home.keyring();
            for (label, first, second, reference_expired) in [
                (
                    "the replacement second",
                    &created,
                    &replaced,
                    case.created_expired,
                ),
                (
                    "the replacement first",
                    &replaced,
                    &created,
                    case.replaced_expired,
                ),
            ] {
                let mut keyring = first.clone();
                keyring.extend_from_slice(second);
                let certs = certs_of(&keyring);
                assert_eq!(certs.len(), 2, "case {index}, {label}: the trusted set");
                let outcome =
                    verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&blob)).unwrap();
                assert_eq!(outcome.signatures.len(), 1);
                let info = &outcome.signatures[0];
                assert_eq!(
                    info.key_expires, case.expires,
                    "case {index}, {label}: the instant reported"
                );
                assert_eq!(
                    info.expired,
                    case.expires.is_some(),
                    "case {index}, {label}: the expired flag"
                );
                assert_eq!(
                    info.valid,
                    case.expires.is_none(),
                    "case {index}, {label}: the verdict"
                );
                // The fields of the report come from the first match. The two
                // exports state the same key and the same user id.
                assert_eq!(
                    info.user_email.as_deref(),
                    Some(&*email),
                    "case {index}, {label}"
                );
                let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
                assert_eq!(
                    reference.len(),
                    1,
                    "case {index}, {label}: the reference record count"
                );
                assert_eq!(
                    reference[0].expired, reference_expired,
                    "case {index}, {label}: gpgv no longer answers on the load \
                     order, so this case states the wrong thing about the \
                     reference",
                );
            }
        }
    }

    /// The direct-key tier applies over two exports of one certificate.
    ///
    /// One export carries a direct-key self-signature that states the key
    /// expiry. The other export carries a newer certification self-signature
    /// that states a different expiry. Inside one certificate, the tier
    /// outranks recency. Over the union of two exports, it outranks recency in
    /// the same way.
    ///
    /// The direct-key self-signature states ten years. The newer certification
    /// self-signature states a lifetime that is over. The union leaves the key
    /// live. Two other readings bound the key: each export read as a separate
    /// certificate, and recency alone.
    ///
    /// The result of `gpgv` 2.4.9 depends on the load order of the pair, so
    /// the test does not compare the verdict with it. If the export with the
    /// direct-key self-signature is first, `gpgv` reports `GOODSIG`. In the
    /// reverse order, it reports `EXPKEYSIG`.
    #[test]
    fn the_direct_key_tier_answers_over_a_duplicate_certificate() {
        if !tools_available() {
            return;
        }
        let home = Fixture::at("Tier <tier@ostrya.example>", "10y");
        let blob = home.sign(&home.primary, PAYLOAD);
        // One export carries a direct-key self-signature that states ten years.
        let direct = insert_after_primary(
            &home.keyring(),
            &direct_key_signature(&home.secret_key(), KEY_CREATED + 10, TEN_YEARS),
        );
        // The other export carries a certification self-signature that is
        // newer than the direct-key self-signature. It states a lifetime that
        // is over.
        home.set_expire_at("20250102T000000!", "1d");
        let bounded = home.keyring();
        // The controls: each export alone states the result of the tier rule
        // for that export.
        let outcome =
            verify_signatures(&certs_of(&direct), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        assert!(
            outcome.signatures[0].valid,
            "the export carrying the direct-key self-signature leaves the key live"
        );
        let outcome =
            verify_signatures(&certs_of(&bounded), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        assert!(
            outcome.signatures[0].expired,
            "the newer certification self-signature bounds the key over one export"
        );
        for (label, first, second, reference_expired) in [
            ("the direct-key export second", &bounded, &direct, true),
            ("the direct-key export first", &direct, &bounded, false),
        ] {
            let mut keyring = first.clone();
            keyring.extend_from_slice(second);
            let certs = certs_of(&keyring);
            assert_eq!(certs.len(), 2, "{label}: the trusted set");
            let outcome = verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&blob)).unwrap();
            assert_eq!(outcome.signatures.len(), 1);
            let info = &outcome.signatures[0];
            assert!(!info.expired, "{label}: the direct-key tier did not answer");
            assert!(info.valid, "{label}: a live key reported not valid");
            assert_eq!(info.key_expires, None, "{label}: the instant reported");
            let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
            assert_eq!(reference.len(), 1, "{label}: the reference record count");
            assert_eq!(
                reference[0].expired, reference_expired,
                "{label}: gpgv no longer answers on the load order, so this \
                 case states the wrong thing about the reference",
            );
        }
    }

    /// A primary-key certificate and a subkey certificate of one key give two
    /// key states.
    ///
    /// One certificate holds the signing key as its primary key. The other
    /// binds the key as a subkey. The engine reads them as two certificates, so
    /// it reads the key state of each, and the earlier expiry applies. Their
    /// self-signatures verify under different primary keys, so their
    /// signatures stay in separate sets.
    ///
    /// The certificate without an expiry does not extend the lifetime that the
    /// other certificate bounds. The signature is refused in either order.
    #[test]
    fn a_subkey_and_a_primary_key_certificate_state_two_key_states() {
        if !tools_available() {
            return;
        }
        let home = Fixture::at("Split <split@ostrya.example>", "1d");
        let subkey = home.add_signing_subkey();
        let full = home.keyring();
        let blob = home.sign(&subkey, PAYLOAD);
        // The subkey as a separate certificate. A v4 fingerprint is a digest
        // over the key material, so this certificate holds the same key as the
        // subkey. It carries no signature, so it states no expiry.
        let alone = subkey_as_certificate(&full);
        // The control: with that certificate alone, the key is live because
        // nothing states an expiry for it.
        let outcome =
            verify_signatures(&certs_of(&alone), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        assert_eq!(
            outcome.signatures[0].fingerprint.as_deref(),
            Some(&*subkey),
            "the subkey certificate answers for the signature"
        );
        assert!(
            outcome.signatures[0].valid,
            "the subkey certificate states no expiry"
        );
        for (label, first, second) in [
            ("the subkey certificate second", &full, &alone),
            ("the subkey certificate first", &alone, &full),
        ] {
            let mut keyring = first.clone();
            keyring.extend_from_slice(second);
            let certs = certs_of(&keyring);
            assert_eq!(certs.len(), 2, "{label}: the trusted set");
            let outcome = verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&blob)).unwrap();
            assert_eq!(outcome.signatures.len(), 1);
            let info = &outcome.signatures[0];
            assert!(info.expired, "{label}: the expiry was not read");
            assert!(!info.valid, "{label}: an expired key reported valid");
            assert_eq!(
                info.key_expires,
                Some(KEY_CREATED + ONE_DAY),
                "{label}: the instant reported"
            );
        }
    }

    /// Returns a certification self-signature over the first user id of the
    /// certificate.
    ///
    /// The signature has the creation time `created`. If `lifetime` is `Some`,
    /// it states that key lifetime. If `lifetime` is `None`, it carries no
    /// key-expiration-time subpacket.
    ///
    /// `gpg` 2.4.9 keeps one certification self-signature for each user id.
    /// For this reason, a test that needs two makes the second one with this
    /// function.
    fn certification_signature(secret: &[u8], created: u64, lifetime: Option<u64>) -> Vec<u8> {
        certification_self_signature(secret, SelfSig::at(created).key_lifetime(lifetime))
    }

    /// Returns a signature of the class `typ` over the first byte of `payload`.
    ///
    /// This is the form of a signature class that the stored blob must not
    /// hold. `gpg` writes only document signatures, so this function builds
    /// the signature itself.
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

    /// Returns a certificate with one packet appended at the end.
    fn append_packet(cert: &[u8], packet: &[u8]) -> Vec<u8> {
        let mut packets = split_packets(cert);
        let mut extra = split_packets(packet);
        assert_eq!(extra.len(), 1);
        packets.push(extra.remove(0));
        join_packets(&packets)
    }

    /// Returns `cert` with the last byte of its one signature of class `class`
    /// inverted. That signature then verifies against nothing.
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

    /// Asserts that one record states what `gpgv` states about the same
    /// signature, except the user id.
    ///
    /// The status stream carries the user id on the verdict line for the
    /// keywords that [`parse_status`] matches. If [`parse_status`] does not
    /// match the verdict keyword of a test, the `gpgv` record has no user id.
    /// The engine reads the user id from the certificate and reports it.
    fn assert_agrees_but_user_id(port: &SignatureInfo, reference: &SignatureInfo) {
        let mut port = port.clone();
        port.user_name = reference.user_name.clone();
        port.user_email = reference.user_email.clone();
        assert_agrees(&port, reference);
    }

    /// A signature after its own expiry is not valid. `gpgv` reports `EXPSIG`
    /// and no `GOODSIG` for it. The `EXPSIG` line names no field of its own.
    /// For this reason, the record carries the expiry instant of the signature
    /// and nothing more.
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
        // The key is live and not revoked. This shows that the expiry of the
        // signature refused it.
        assert!(!info.expired);
        assert!(!info.revoked);
        assert_eq!(info.key_expires, None);
        // The control: a signature of the same key over the same payload,
        // with no expiry.
        let fresh = home.sign(&home.primary, PAYLOAD);
        let outcome = verify_signatures(&home.certs(), PAYLOAD, &[fresh]).unwrap();
        assert!(outcome.valid);
        assert_eq!(outcome.signatures[0].expires, None);
    }

    /// A signature of a class other than a document signature is refused. Such
    /// a signature covers one byte of the payload. Without the refusal, one
    /// such signature is valid for each payload that starts with that byte.
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
            // The key is in the keyring, and the record names it. This shows
            // that the class check refused the signature.
            assert!(!info.key_missing);
            assert_eq!(info.fingerprint.as_deref(), Some(&*home.primary));
            assert_eq!(info.user_name, None);
            // The same signature is also refused over another payload that
            // starts with the same byte.
            let other = b"ostrya other payload".to_vec();
            assert_eq!(other[0], PAYLOAD[0]);
            let outcome = verify_signatures(&home.certs(), &other, &[blob]).unwrap();
            assert!(!outcome.valid, "{class:?} over another payload");
        }
        // The control: a document signature of the same key is valid.
        let blob = home.sign(&home.primary, PAYLOAD);
        assert!(
            verify_signatures(&home.certs(), PAYLOAD, &[blob])
                .unwrap()
                .valid
        );
    }

    /// An MD5 data signature of an issuer that no loaded certificate holds is
    /// refused. The record names the missing key. No path goes around the
    /// digest policy, because a record without a key is never valid.
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

    /// A key is live at its expiry instant and expired from the next second.
    ///
    /// When polled once each second across the expiry instant, `gpgv` reports
    /// `GOODSIG` up to and including that instant. From the next second, it
    /// reports `EXPKEYSIG`. The test makes two certificates, one on each side
    /// of that boundary. If the clock moves during the reads, the test runs
    /// again.
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
                // The second changed during the four reads, so the records
                // state nothing about the boundary.
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
    /// expiry. If it states no lifetime, an older one does not apply in its
    /// place. If the newest one is altered, the engine ignores it.
    #[test]
    fn the_newest_certification_self_signature_states_the_key_expiry() {
        if !tools_available() {
            return;
        }
        /// What one certificate states, and the key expiry that results.
        struct Case {
            /// The lifetime that the self-signature of the fixture states.
            first: &'static str,
            /// The lifetime in seconds that the spliced newer self-signature
            /// states. `None` if the signature carries no lifetime.
            second: Option<u64>,
            /// If `true`, the bytes of the newer self-signature are altered.
            altered: bool,
            /// The expiry instant of the key. `None` if the key does not
            /// expire.
            expires: Option<u64>,
        }
        let cases = [
            // The newest self-signature applies, for a shorter and for a longer
            // lifetime.
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
            // A zero lifetime and an absent lifetime both state no expiry. The
            // older self-signature does not apply in place of either.
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
            // older one applies.
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

    /// A signature lifetime that is over, in seconds after the signature
    /// creation time.
    ///
    /// The tests make a self-signature less than one minute after
    /// [`KEY_CREATED`]. A signature with this lifetime expired long before the
    /// clock time of each `gpgv` run.
    const SPENT_LIFETIME: u64 = 100;

    /// Returns the first signature packet of a detached signature blob.
    fn signature_of(blob: &[u8]) -> DetachedSignature {
        DetachedSignature::from_bytes_many(Cursor::new(blob))
            .expect("the blob opens as a packet stream")
            .next()
            .expect("the blob holds a signature packet")
            .expect("the signature packet is whole")
    }

    /// A certification self-signature after its own expiration time states no
    /// key lifetime. No older certification self-signature applies in its
    /// place.
    #[test]
    fn an_expired_certification_self_signature_states_no_key_lifetime() {
        if !tools_available() {
            return;
        }
        /// What one certificate carries and what it states.
        struct Case {
            /// The lifetime that the certification self-signature of the
            /// fixture states.
            own: &'static str,
            /// The key lifetime that the spliced newer certification states.
            spliced: Option<u64>,
            /// If `true`, the spliced certification is itself expired.
            expired: bool,
            /// The expiry instant of the key. `None` if the key does not
            /// expire.
            expires: Option<u64>,
        }
        let cases = [
            // The spliced certification states no lifetime. The older one
            // states a lifetime that is over. It does not apply in place of the
            // spliced one, if the spliced one is expired or live.
            Case {
                own: "1d",
                spliced: Some(0),
                expired: true,
                expires: None,
            },
            Case {
                own: "1d",
                spliced: Some(0),
                expired: false,
                expires: None,
            },
            // The spliced certification states a lifetime that is over. If it
            // is live, it applies. If it is itself expired, it states nothing.
            Case {
                own: "10y",
                spliced: Some(ONE_DAY),
                expired: true,
                expires: None,
            },
            Case {
                own: "10y",
                spliced: Some(ONE_DAY),
                expired: false,
                expires: Some(KEY_CREATED + ONE_DAY),
            },
        ];
        for (index, case) in cases.iter().enumerate() {
            let home = Fixture::at(
                &format!("Cexp{index} <cexp{index}@ostrya.example>"),
                case.own,
            );
            let blob = home.sign(&home.primary, PAYLOAD);
            let mut spec = SelfSig::at(KEY_CREATED + 20).key_lifetime(case.spliced);
            if case.expired {
                spec = spec.expiring_after(SPENT_LIFETIME);
            }
            let spliced = certification_self_signature(&home.secret_key(), spec);
            let keyring = append_packet(&home.keyring(), &spliced);
            let outcome =
                verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob))
                    .unwrap();
            let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
            assert_eq!(outcome.signatures.len(), 1, "case {index}");
            assert_eq!(reference.len(), 1, "case {index}");
            assert_agrees(&outcome.signatures[0], &reference[0]);
            let info = &outcome.signatures[0];
            assert_eq!(info.key_expires, case.expires, "case {index}");
            assert_eq!(info.expired, case.expires.is_some(), "case {index}");
            assert_eq!(info.valid, case.expires.is_none(), "case {index}");
        }
    }

    /// A direct-key self-signature after its own expiration time states no key
    /// lifetime. The newest live one that states a lifetime applies. If all
    /// direct-key self-signatures are expired, the certification
    /// self-signature applies.
    #[test]
    fn an_expired_direct_key_self_signature_states_no_key_lifetime() {
        if !tools_available() {
            return;
        }
        /// What one certificate carries and what it states. In each fixture,
        /// the certification self-signature states one day, which is over.
        struct Case {
            /// The direct-key self-signatures spliced onto the certificate.
            /// Each tuple holds the creation time after [`KEY_CREATED`], the
            /// key lifetime, and `true` if the signature is itself expired.
            spliced: &'static [(u64, u64, bool)],
            /// The expiry instant of the key. `None` if the key does not
            /// expire.
            expires: Option<u64>,
        }
        let cases = [
            // One expired direct-key self-signature. It states nothing, so the
            // certification self-signature applies. A zero key lifetime states
            // nothing in all cases. For this reason, the first case holds for
            // an expired and for a live signature. The expiration time decides
            // only the second case.
            Case {
                spliced: &[(20, 0, true)],
                expires: Some(KEY_CREATED + ONE_DAY),
            },
            Case {
                spliced: &[(20, TEN_YEARS, true)],
                expires: Some(KEY_CREATED + ONE_DAY),
            },
            // The same signature applies while it is live, and the key is live
            // for ten years.
            Case {
                spliced: &[(20, TEN_YEARS, false)],
                expires: None,
            },
            // A live older direct-key self-signature next to an expired newer
            // one applies. If one signature of the tier is live, the rule does
            // not go to the next tier.
            Case {
                spliced: &[(10, TEN_YEARS, false), (20, TEN_YEARS, true)],
                expires: None,
            },
        ];
        for (index, case) in cases.iter().enumerate() {
            let home = Fixture::at(&format!("Dexp{index} <dexp{index}@ostrya.example>"), "1d");
            let blob = home.sign(&home.primary, PAYLOAD);
            let secret = home.secret_key();
            let mut keyring = home.keyring();
            for (created, lifetime, expired) in case.spliced {
                let mut spec = SelfSig::at(KEY_CREATED + created).key_lifetime(Some(*lifetime));
                if *expired {
                    spec = spec.expiring_after(SPENT_LIFETIME);
                }
                keyring = insert_after_primary(&keyring, &direct_self_signature(&secret, spec));
            }
            let outcome =
                verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob))
                    .unwrap();
            let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
            assert_eq!(outcome.signatures.len(), 1, "case {index}");
            assert_eq!(reference.len(), 1, "case {index}");
            assert_agrees(&outcome.signatures[0], &reference[0]);
            let info = &outcome.signatures[0];
            assert_eq!(info.key_expires, case.expires, "case {index}");
            assert_eq!(info.expired, case.expires.is_some(), "case {index}");
            assert_eq!(info.valid, case.expires.is_none(), "case {index}");
        }
    }

    /// A subkey binding signature after its own expiration time binds nothing.
    /// A signature of the subkey then resolves to no key and reports
    /// `key_missing`. A live older binding next to it still binds.
    #[test]
    fn an_expired_subkey_binding_signature_binds_nothing() {
        if !tools_available() {
            return;
        }
        let home = Fixture::at("Bexp <bexp@ostrya.example>", "never");
        let subkey = home.add_signing_subkey();
        let blob = home.sign(&subkey, PAYLOAD);
        let secret = home.secret_key();

        // The control: the binding that this test builds, without an
        // expiration time, binds the subkey. This shows that only the
        // expiration time differs in the next case.
        let live = replace_subkey_binding(
            &home.keyring(),
            &subkey_binding_signature(&secret, KEY_CREATED + 20, None),
        );
        let certs = certs_of(&live);
        let outcome = verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&live, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(outcome.signatures[0].valid);
        assert_eq!(outcome.signatures[0].fingerprint.as_deref(), Some(&*subkey));
        assert!(resolve_issuers(&certs, &signature_of(&blob).signature).is_some());

        // The same binding, expired. The subkey belongs to no loaded
        // certificate.
        let expired = replace_subkey_binding(
            &home.keyring(),
            &subkey_binding_signature(&secret, KEY_CREATED + 20, Some(SPENT_LIFETIME)),
        );
        let certs = certs_of(&expired);
        let outcome = verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&expired, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        let info = &outcome.signatures[0];
        assert!(info.key_missing, "the subkey resolved to a certificate");
        assert!(!info.valid);
        assert!(!outcome.valid);
        assert_eq!(
            info.fingerprint.as_deref(),
            Some(&*subkey),
            "the fingerprint the signature packet names"
        );
        assert_eq!(info.user_name, None);
        assert!(resolve_issuers(&certs, &signature_of(&blob).signature).is_none());

        // The expired binding next to the live binding that `gpg` wrote. The
        // live binding binds, so one expired binding does not unbind a subkey.
        let both = append_packet(
            &home.keyring(),
            &subkey_binding_signature(&secret, KEY_CREATED + 20, Some(SPENT_LIFETIME)),
        );
        let outcome =
            verify_signatures(&certs_of(&both), PAYLOAD, std::slice::from_ref(&blob)).unwrap();
        let reference = home.gpgv_records(&both, &blob, PAYLOAD);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(reference.len(), 1);
        assert_agrees(&outcome.signatures[0], &reference[0]);
        assert!(outcome.signatures[0].valid);
        assert!(!outcome.signatures[0].key_missing);
    }

    /// A certification self-signature after its own expiration time ranks no
    /// user id and marks none primary. The report names the user id with a
    /// live certification.
    #[test]
    fn an_expired_certification_self_signature_ranks_no_user_id() {
        if !tools_available() {
            return;
        }
        const ALPHA: &str = "Alpha <alpha@ostrya.example>";
        const BRAVO: &str = "Bravo <bravo@ostrya.example>";
        /// What the certification spliced onto the first user id carries.
        struct Case {
            /// The creation time, in seconds after [`KEY_CREATED`].
            created: u64,
            /// If `true`, it marks the user id primary.
            marks_primary: bool,
        }
        let cases = [
            // The primary mark outranks recency. A live signature that is older
            // than the certification of the second user id names the first
            // user id.
            Case {
                created: 20,
                marks_primary: true,
            },
            // Only recency ranks. A live signature that is newer than the
            // certification of the second user id names the first user id.
            Case {
                created: 40,
                marks_primary: false,
            },
        ];
        for (index, case) in cases.iter().enumerate() {
            let home = Fixture::at(ALPHA, "never");
            // The certification of the second user id has a creation time 30
            // seconds after the key creation time. This is between the two
            // instants of the cases.
            home.add_uid_at("20250101T000030!", BRAVO);
            let blob = home.sign(&home.primary, PAYLOAD);
            let secret = home.secret_key();
            for expired in [false, true] {
                let mut spec = SelfSig::at(KEY_CREATED + case.created);
                if case.marks_primary {
                    spec = spec.marking_primary();
                }
                if expired {
                    spec = spec.expiring_after(SPENT_LIFETIME);
                }
                let keyring = insert_after_user_id(
                    &home.keyring(),
                    ALPHA,
                    &certification_self_signature(&secret, spec),
                );
                let outcome =
                    verify_signatures(&certs_of(&keyring), PAYLOAD, std::slice::from_ref(&blob))
                        .unwrap();
                let reference = home.gpgv_records(&keyring, &blob, PAYLOAD);
                assert_eq!(outcome.signatures.len(), 1, "case {index}");
                assert_eq!(reference.len(), 1, "case {index}");
                assert_agrees(&outcome.signatures[0], &reference[0]);
                let info = &outcome.signatures[0];
                let named = if expired { "bravo" } else { "alpha" };
                assert_eq!(
                    info.user_email.as_deref(),
                    Some(&*format!("{named}@ostrya.example")),
                    "case {index}, expired {expired}"
                );
                assert!(info.valid, "case {index}, expired {expired}");
            }
        }
    }

    /// A subkey revocation that verifies against nothing revokes nothing. The
    /// subkey still speaks for its certificate. The test alters the revocation
    /// of the certificate. An attacker who cannot sign with the primary key can
    /// produce this form.
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
        // The control: the intact revocation applies.
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

    /// A signature expires at the instant that it names.
    ///
    /// When polled once each second across the expiry instant, `gpgv` reports
    /// `GOODSIG` up to the second before that instant. From that instant on,
    /// it reports `EXPSIG`. The test makes two signatures, one on each side of
    /// the boundary. If the clock moves during the reads, the test runs again.
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
                // The second changed during the four reads, so the records
                // state nothing about the boundary.
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

    /// Parses the machine-readable status stream of one `gpgv` run into one
    /// record for each signature.
    ///
    /// Each `NEWSIG` starts a record. The verdict keywords and the `VALIDSIG`
    /// and `ERRSIG` detail lines fill it. The tests compare the engine with
    /// these records, so the records state the report of `gpgv` in the form of
    /// the engine result.
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

    /// Returns the OpenPGP public-key algorithm name for a status-line
    /// algorithm id.
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

    /// Returns the OpenPGP hash algorithm name for a status-line algorithm id.
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
