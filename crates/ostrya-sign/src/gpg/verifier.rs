//! The GPG verifier, the parse of a keyring, the key listing, and the
//! keyring merge of an import, over rPGP.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use ostrya_core::base64;
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::packet::PacketHeader;
use pgp::types::{KeyDetails, PacketLength, Tag};

use super::GPG_METADATA_KEY;
use crate::{Error, Result, Verifier, VerifyOutcome, read_key_file};

mod verify;

/// The ceiling for one keyring, in bytes.
///
/// A keyring reader puts the whole keyring in memory. One exported ed25519
/// certificate is a few hundred bytes. So four mebibytes hold thousands of
/// certificates, and the trusted set of a remote is a few.
pub const MAX_KEYRING: u64 = 4 * 1024 * 1024;
/// The maximum number of certificates in one keyring.
///
/// The trusted set of a remote is a few certificates. The limit bounds the
/// parser work that a keyring from a remote or from `trusted.gpg.d` can cause.
const MAX_KEYRING_CERTS: usize = 256;
/// The magic of a GnuPG keybox, and its offset.
///
/// A keybox starts with a header blob. A four-byte length, a one-byte blob
/// type, a one-byte version, and two bytes of flags come before the magic.
const KEYBOX_MAGIC: &[u8] = b"KBXf";
const KEYBOX_MAGIC_OFFSET: usize = 8;

/// The GPG commit verifier, with the trusted certificates of its keyrings.
///
/// `GpgVerifier` implements [`Verifier`]. Trust is membership in the keyrings
/// of the verifier. The ownertrust model of GnuPG has no effect. The verifier
/// does its work in the call to [`Verifier::verify`]. It starts no process and
/// writes no scratch directory.
///
/// [`from_keyring_bytes`](GpgVerifier::from_keyring_bytes) and
/// [`from_keyring_files`](GpgVerifier::from_keyring_files) make a verifier in
/// one call. A verifier from several sources starts from
/// [`GpgVerifier::default`], which trusts no certificate.
/// [`add_keyring`](GpgVerifier::add_keyring) and
/// [`add_keyring_files`](GpgVerifier::add_keyring_files) then add each source.
/// [`add_keyring_files_skipping`](GpgVerifier::add_keyring_files_skipping)
/// adds the files of a source that can hold files of other kinds, as a
/// `gpgkeypath` entry can. It skips a file with no armor that is a GnuPG
/// keybox or that is not a whole OpenPGP packet stream.
///
/// # Format
///
/// - The detached metadata holds the signatures under the key
///   `ostree.gpgsigs`, as an `aay`.
/// - Each `ay` element is one detached OpenPGP signature: the binary signature
///   packet stream, with no armor. One element can hold more than one signature
///   packet.
/// - The signed payload is the same commit bytes that the other engines sign.
///
/// # Verdict
///
/// The verifier reports one [`SignatureInfo`](crate::SignatureInfo)
/// for each signature packet in the `aay` blobs stored under
/// `ostree.gpgsigs`. One blob holds one or more signature packets, so a blob
/// can give several records. If the parser reads no signature from a blob,
/// that blob gives one record of its own. So the record count follows the
/// stored blob count.
///
/// Each signature names its issuer in a subpacket. The verifier reads the
/// issuer fingerprint first and the issuer key id second. It compares each
/// with the primary key of each certificate and then with its subkeys. If no
/// loaded certificate holds the issuer, the record has
/// [`key_missing`](crate::SignatureInfo::key_missing) set. Its
/// fingerprint, creation time, and two algorithm names then come from the
/// signature packet.
///
/// Each certificate that matches the issuer takes part in the verdict. The
/// verifier groups the matches by the primary key of their certificate, and
/// reads one group as one certificate. The direct signatures, the user ids
/// with their certifications, and the subkey bindings of every copy form one
/// set. The key expiry rule runs once over this set, so the newest statement
/// of any copy applies.
///
/// Across groups, a revocation in any group refuses the signature. The key
/// expires at the earliest instant that any group states. So the load order of
/// the trusted set has no effect on revocation and expiry. The first match
/// gives the reported user id, the primary-key fingerprint, the cryptography,
/// and the cross-certification check, so the load order sets these values.
///
/// A signature is valid if all of these are true:
///
/// - The signature verifies.
/// - The certificate that holds the signing key is loaded.
/// - The signature is over a document.
/// - The bindings hold.
/// - The digest algorithm is allowed.
/// - The signature itself states no expiry time, or a time later than now.
/// - The key is not expired and not revoked.
///
/// The record of each signature reports an expired key, a revoked key, a bad
/// signature, and an absent key. A self-signature whose own expiry time is in
/// the past sets no key expiry, binds no subkey, and ranks no user id. These
/// rules give the behavior of `gpgv` 2.4.9.
///
/// # Fields of a record
///
/// A record carries one of three field sets. The set tells how far the
/// verification went.
///
/// - A signature that a loaded key verifies gives the signing key in
///   `fingerprint` and the certificate that holds it in
///   `primary_fingerprint`. It also gives the user id of that certificate in
///   `user_name` and `user_email`, the instants and the algorithm names of the
///   signature packet, and the verdict of the policy in `valid`. `expires` is
///   the creation time plus the lifetime that the packet states. It is `None`
///   if the packet states no lifetime.
/// - A signature whose issuer no loaded certificate holds gives the fields of
///   its own packet, with `key_missing` set: the issuer fingerprint, or none
///   if the packet names none, the creation time, and the two algorithm
///   names. A signature that the policy refuses for its class, for its digest
///   algorithm, or for a subkey that the primary key did not cross-certify
///   gives the same fields with `key_missing` clear. Neither set has a user
///   id.
/// - A signature whose issuer resolved and whose cryptography failed gives the
///   signing key, the certificate that holds it, and the user id of that
///   certificate. It gives no instant and no algorithm name, because the
///   verifier checked no claim of the packet.
///
/// A signature after its own expiry is not valid and adds no field to the set
/// of a verified signature.
///
/// # Limits of a keyring
///
/// A keyring is untrusted input. Each keyring, as bytes or as a file, has
/// these limits:
///
/// - At most 4 MiB (`4194304` bytes).
/// - At most 256 certificates.
/// - No GnuPG keybox. A keybox carries the `KBXf` magic at byte offset 8. rPGP
///   reads OpenPGP packet streams, and a keybox is a container of a different
///   kind.
///
/// Each refusal names the file or the blob, and the limit that it reached. If
/// the parser refuses a keyring, the load fails. If the packet stream of a
/// keyring does not frame to its end, the load also fails. So each
/// verification uses a trusted set that was read whole.
/// [`add_keyring_files_skipping`](GpgVerifier::add_keyring_files_skipping)
/// skips a file with no armor that is a keybox or that does not frame to its
/// end, and adds no certificate from it. It refuses each other file that it
/// cannot read whole.
///
/// The parse runs under `catch_unwind`, so a panic in the parser gives
/// [`Error::Signature`]. If the binary is built with `panic = "abort"`, a panic
/// stops the process. The containment does not find a parser that returns a
/// wrong answer with no panic.
///
/// # Limits of a stored blob
///
/// A stored blob is untrusted input. One blob has a limit of 1 MiB, which the
/// verifier checks before the parser reads the bytes. One blob also has a limit
/// of 64 signature packets, which the verifier checks as it reads the packets.
/// Each refusal names the limit that it reached. The policy runs in the same
/// containment. So if a crafted certificate causes a panic in a public-key
/// operation, the result is the same as for a blob that the parser refuses.
#[derive(Debug, Clone, Default)]
pub struct GpgVerifier {
    /// The certificates of the loaded keyrings, in load order.
    ///
    /// The parse runs when a keyring loads. So if the parser refuses a keyring,
    /// the load fails, and no verification uses that keyring.
    ///
    /// If the sources hold several certificates for one key, this list keeps
    /// all of them. The verdict reads all the certificates that match the
    /// issuer of a signature. So a revocation in any of them refuses the
    /// signature, and the load order has no effect on this result.
    ///
    /// One reference count holds the set, so a clone of the verifier is cheap
    /// and shares the certificates. An add to a clone copies the set first,
    /// and the other clones keep their certificates.
    certs: Arc<Vec<SignedPublicKey>>,
}

impl GpgVerifier {
    /// Creates a verifier that trusts each certificate in the keyring blobs.
    ///
    /// Each blob is a binary or ASCII-armored OpenPGP keyring, and can hold
    /// several certificates. All blobs merge into one trusted set. The load
    /// decodes armored input to the binary packet stream. It drops the Trust
    /// packets from that stream. So a legacy GnuPG keyring and the
    /// `gpg --export` stream of the same keys parse to the same certificates.
    ///
    /// Each blob has
    /// [the limits of a keyring](GpgVerifier#limits-of-a-keyring). A refusal
    /// names the blob by its position in the sequence, as
    /// `the keyring blob <index>`.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if a blob is over 4 MiB, is a GnuPG keybox, holds
    ///   more than 256 certificates, or does not parse as an OpenPGP keyring.
    /// - [`Error::Signature`] if an armored blob is not valid UTF-8.
    /// - [`Error::Core`] if the armor of a blob holds text that is not valid
    ///   base64.
    pub fn from_keyring_bytes<I, B>(keyrings: I) -> Result<GpgVerifier>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut verifier = GpgVerifier::default();
        for (index, keyring) in keyrings.into_iter().enumerate() {
            verifier.add_keyring(keyring.as_ref(), &format!("the keyring blob {index}"))?;
        }
        Ok(verifier)
    }

    /// Creates a verifier from keyring files on disk, binary or armored.
    ///
    /// If a file does not exist, the load skips it. So an absent optional
    /// keyring does not cause a failure. The load reads only a regular file, up
    /// to 4 MiB. The decode rules of
    /// [`from_keyring_bytes`](GpgVerifier::from_keyring_bytes) and
    /// [the limits of a keyring](GpgVerifier#limits-of-a-keyring) apply. A
    /// refusal names the path.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if a path cannot be opened for a reason other
    ///   than a missing file, or a read of the file fails.
    /// - [`Error::Signature`] if a path names a file that is not a regular
    ///   file, for example a directory or a fifo.
    /// - The errors of [`from_keyring_bytes`](GpgVerifier::from_keyring_bytes)
    ///   for the content of each file.
    pub fn from_keyring_files<I, P>(paths: I) -> Result<GpgVerifier>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut verifier = GpgVerifier::default();
        verifier.add_keyring_files(paths)?;
        Ok(verifier)
    }

    /// Adds each keyring that `paths` names to the trusted set, in the given
    /// order. If a path names no file, the load skips it.
    ///
    /// The read rules of
    /// [`from_keyring_files`](GpgVerifier::from_keyring_files) apply. A
    /// refusal names the path, as `the keyring '<path>'`.
    ///
    /// The call reads and parses each keyring before it adds a certificate.
    /// So the trusted set gets either all keyrings or none of them.
    ///
    /// # Errors
    ///
    /// - The errors of [`from_keyring_files`](GpgVerifier::from_keyring_files).
    ///
    /// On an error, the verifier is unchanged.
    pub fn add_keyring_files<I, P>(&mut self, paths: I) -> Result<()>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut certs = Vec::new();
        for path in paths {
            let path = path.as_ref();
            let subject = format!("the keyring '{}'", path.display());
            if let Some(bytes) = read_key_file(path, &subject, MAX_KEYRING)? {
                certs.extend(keyring_certs(&bytes, &subject)?);
            }
        }
        self.trust(certs);
        Ok(())
    }

    /// Adds each keyring that `paths` names to the trusted set, in the given
    /// order, and skips each file that is not an OpenPGP packet stream. If a
    /// path names no file, the load skips it.
    ///
    /// The call skips a file only if the file does not hold the bytes
    /// `-----BEGIN PGP`, and one of these conditions applies:
    ///
    /// - The file is a GnuPG keybox.
    /// - The file does not frame as a whole OpenPGP packet stream. Text,
    ///   random bytes, a truncated keyring, and a keyring with bytes after its
    ///   last packet are examples.
    ///
    /// A skipped file adds no certificate and gives no message. The call reads
    /// a file whole, so a file that holds a keyring and then other bytes adds
    /// no certificate. An empty file gives no certificate.
    ///
    /// The call refuses each other file that it cannot read whole as a
    /// keyring. A file that holds the bytes `-----BEGIN PGP` is armored, and
    /// the call refuses it if its armor does not decode to a keyring. Armor
    /// after other bytes, an armor line that does not start a line, an armor
    /// header that is not valid UTF-8, a block that is not valid base64 after
    /// a valid block, and armor of bytes that are not a whole packet stream
    /// are examples. Another tool can read a key or a revocation from such a
    /// file, so a skip could trust a key that the file revokes. The call also
    /// refuses a whole packet stream if the parser refuses or panics on a
    /// certificate of it.
    ///
    /// The other read rules of
    /// [`from_keyring_files`](GpgVerifier::from_keyring_files) apply. So a
    /// file that cannot be opened or read, a path that names a file that is
    /// not a regular file, a file over 4 MiB, and a keyring with more than 256
    /// certificates are refused. Each refusal names the path, as
    /// `the keyring '<path>'`.
    ///
    /// The call reads and parses each keyring before it adds a certificate.
    /// So the trusted set gets either all keyrings or none of them.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if a path cannot be opened for a reason other
    ///   than a missing file, or a read of the file fails.
    /// - [`Error::Signature`] if a path names a file that is not a regular
    ///   file, for example a directory or a fifo.
    /// - [`Error::Signature`] if a file is over 4 MiB, or holds more than 256
    ///   certificates.
    /// - [`Error::Signature`] if a file holds the bytes `-----BEGIN PGP` and
    ///   its armor does not decode to a keyring that the parser reads.
    /// - [`Error::Signature`] if the parser refuses a certificate of a whole
    ///   packet stream, or panics.
    ///
    /// On an error, the verifier is unchanged.
    pub fn add_keyring_files_skipping<I, P>(&mut self, paths: I) -> Result<()>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut certs = Vec::new();
        for path in paths {
            let path = path.as_ref();
            let subject = format!("the keyring '{}'", path.display());
            if let Some(bytes) = read_key_file(path, &subject, MAX_KEYRING)? {
                certs.extend(skippable_keyring_certs(&bytes, &subject)?);
            }
        }
        self.trust(certs);
        Ok(())
    }

    /// Adds one keyring to the trusted set.
    ///
    /// The call decodes the armor, applies
    /// [the limits of a keyring](GpgVerifier#limits-of-a-keyring), refuses a
    /// keybox, and parses the certificates of the keyring. `subject` names the
    /// source, so a refusal states which keyring reached which limit.
    ///
    /// The extend runs in place on a verifier that no clone shares. On a
    /// verifier that a clone shares, the call first copies the set. A keyring
    /// with no certificate leaves the set as it is, and the call copies
    /// nothing.
    ///
    /// # Errors
    ///
    /// - The errors of [`from_keyring_bytes`](GpgVerifier::from_keyring_bytes),
    ///   with `subject` in the place of `the keyring blob <index>`.
    ///
    /// On an error, the verifier is unchanged.
    pub fn add_keyring(&mut self, bytes: &[u8], subject: &str) -> Result<()> {
        let certs = keyring_certs(bytes, subject)?;
        self.trust(certs);
        Ok(())
    }

    /// Adds `certs` to the trusted set.
    ///
    /// An empty `certs` leaves the set as it is. So a verifier that a clone
    /// shares does not copy its set for no change.
    fn trust(&mut self, certs: Vec<SignedPublicKey>) {
        if !certs.is_empty() {
            Arc::make_mut(&mut self.certs).extend(certs);
        }
    }

    /// Returns `true` if the trusted set holds no certificate.
    ///
    /// A verifier with no trusted certificate refuses every signature.
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }
}

/// The refusal of the read of one keyring, with the cause of the refusal.
///
/// Each variant holds the error that the refusal gives. A caller that refuses
/// each keyring it cannot read changes the value to that error, with
/// [`From`]. [`skippable_keyring_certs`] reads the variant.
#[derive(Debug)]
enum KeyringRefusal {
    /// The bytes are not a whole OpenPGP packet stream: the blob is a GnuPG
    /// keybox, or the packet stream does not frame to its end. The error
    /// names the source.
    NotPacketStream(Error),
    /// The armor does not decode: an armored blob is not valid UTF-8, or its
    /// armor holds text that is not valid base64. The error does not name the
    /// source.
    Armor(Error),
    /// The packet stream frames to its end, and the parser refuses a
    /// certificate or panics. The error names the source.
    Unreadable(Error),
    /// The blob is over [`MAX_KEYRING`], or holds more than
    /// [`MAX_KEYRING_CERTS`] certificates. The error names the source.
    OverLimit(Error),
}

impl From<KeyringRefusal> for Error {
    fn from(refusal: KeyringRefusal) -> Error {
        match refusal {
            KeyringRefusal::NotPacketStream(err)
            | KeyringRefusal::Armor(err)
            | KeyringRefusal::Unreadable(err)
            | KeyringRefusal::OverLimit(err) => err,
        }
    }
}

/// The bytes that start an armor header line.
const ARMOR_BEGIN: &[u8] = b"-----BEGIN PGP";

/// Returns the certificates of one file of a `gpgkeypath` entry, as
/// [`GpgVerifier::add_keyring_files_skipping`] reads it.
///
/// Returns no certificate for a file to skip: a file that does not hold
/// [`ARMOR_BEGIN`] and that is a GnuPG keybox or does not frame to its end.
/// Each other refusal of the read is an error that names `subject`. A file
/// that holds [`ARMOR_BEGIN`] must start with its armor, after white space
/// alone, and each [`ARMOR_BEGIN`] must start a line. [`dearmor`] reads no
/// other armor.
fn skippable_keyring_certs(bytes: &[u8], subject: &str) -> Result<Vec<SignedPublicKey>> {
    let mut begins = bytes
        .windows(ARMOR_BEGIN.len())
        .enumerate()
        .filter(|(_, window)| *window == ARMOR_BEGIN)
        .map(|(at, _)| at)
        .peekable();
    let armored = begins.peek().is_some();
    if armored {
        let first = bytes.iter().position(|b| !b.is_ascii_whitespace());
        let starts_lines = begins.all(|at| at == 0 || bytes[at - 1] == b'\n');
        if !starts_lines || !first.is_some_and(|at| bytes[at..].starts_with(ARMOR_BEGIN)) {
            return Err(Error::Signature(format!(
                "{subject} is not readable as an OpenPGP keyring: it holds armor \
                 after other bytes, or armor that does not start a line"
            )));
        }
    }
    match keyring_certs(bytes, subject) {
        Ok(certs) => Ok(certs),
        Err(KeyringRefusal::NotPacketStream(_)) if !armored => Ok(Vec::new()),
        Err(KeyringRefusal::Armor(err)) => {
            let detail = match err {
                Error::Signature(message) => message,
                other => other.to_string(),
            };
            Err(Error::Signature(format!(
                "{subject} is not readable as an OpenPGP keyring: its armor does \
                 not decode: {detail}"
            )))
        }
        Err(refusal) => Err(refusal.into()),
    }
}

/// Returns the certificates of one keyring blob, binary or armored.
///
/// The call applies [`keyring_stream`] and [`parse_keyring`]. `subject` names
/// the source in a refusal.
fn keyring_certs(
    bytes: &[u8],
    subject: &str,
) -> std::result::Result<Vec<SignedPublicKey>, KeyringRefusal> {
    let binary = keyring_stream(bytes, subject)?;
    let certs = parse_keyring(&binary, subject)?;
    Ok(certs.into_iter().map(|(cert, _)| cert).collect())
}

/// Returns the binary packet stream of one keyring blob.
///
/// The call applies [`MAX_KEYRING`], decodes the armor, and refuses a GnuPG
/// keybox. `subject` names the source, so a refusal states which keyring
/// reached which limit. A binary blob comes back as a borrow of `bytes`, with
/// no copy.
///
/// A blob over [`MAX_KEYRING`] gives [`KeyringRefusal::OverLimit`]. Armor
/// that does not decode gives [`KeyringRefusal::Armor`], and a keybox gives
/// [`KeyringRefusal::NotPacketStream`].
fn keyring_stream<'a>(
    bytes: &'a [u8],
    subject: &str,
) -> std::result::Result<Cow<'a, [u8]>, KeyringRefusal> {
    if bytes.len() as u64 > MAX_KEYRING {
        return Err(KeyringRefusal::OverLimit(Error::Signature(format!(
            "{subject} is over the {MAX_KEYRING}-byte ceiling"
        ))));
    }
    let binary = dearmor(bytes).map_err(KeyringRefusal::Armor)?;
    if binary.len() >= KEYBOX_MAGIC_OFFSET + KEYBOX_MAGIC.len()
        && &binary[KEYBOX_MAGIC_OFFSET..KEYBOX_MAGIC_OFFSET + KEYBOX_MAGIC.len()] == KEYBOX_MAGIC
    {
        return Err(KeyringRefusal::NotPacketStream(Error::Signature(format!(
            "{subject} is a GnuPG keybox, and a keyring is read as an OpenPGP \
             packet stream"
        ))));
    }
    Ok(binary)
}

/// Frames the first packet of `rest`, and returns its tag and its length in
/// bytes, with the header.
///
/// The call frames the packet with the header parser of rPGP. The same parser
/// reads the packet stream, so the packet boundaries are the same in both
/// reads.
///
/// Returns `None` if one of these conditions applies:
///
/// - The parser refuses the header.
/// - The length form is not a fixed length.
/// - The length goes past the end of `rest`.
fn next_packet(rest: &[u8]) -> Option<(Tag, usize)> {
    let mut reader = rest;
    let header = PacketHeader::try_from_reader(&mut reader).ok()?;
    let PacketLength::Fixed(body) = header.packet_length() else {
        return None;
    };
    let total = (rest.len() - reader.len()).saturating_add(body as usize);
    (total != 0 && total <= rest.len()).then_some((header.tag(), total))
}

/// The certificates of a binary keyring stream, as [`certificate_chunks`]
/// splits it.
#[derive(Debug)]
enum Chunks {
    /// The stream frames to its end. Each value holds the packets of one
    /// certificate, with no Trust packets.
    Framed(Vec<Vec<u8>>),
    /// The stream does not frame to its end, and holds at most
    /// [`MAX_KEYRING_CERTS`] Public-Key packets before the first byte that
    /// does not frame.
    Unframed,
    /// The framed part of the stream holds more than [`MAX_KEYRING_CERTS`]
    /// Public-Key packets.
    OverLimit,
}

/// Returns the certificates of a binary keyring stream, with no Trust packets.
///
/// Each certificate is the packets of one transferable public key. A
/// Public-Key packet starts a certificate. Each packet up to the next
/// Public-Key packet is part of it. A packet before the first Public-Key packet
/// is part of no certificate, and the call drops it.
///
/// A Trust packet (tag 12) holds a trust value that is local to GnuPG. It is
/// not part of a transferable public key, so the call also drops it. A legacy
/// GnuPG keyring writes one after the primary key packet, after each user id
/// packet, and after each signature packet. The certificate parser of rPGP
/// reads the packets of one certificate in runs of tag tests. A packet of a
/// different tag ends a run. So a Trust packet after the primary key gives a
/// certificate with no user id and no subkey. With no Trust packets, a legacy
/// keyring parses to the same certificates as the `gpg --export` form of the
/// same keys.
///
/// The call walks the stream once, and counts the Public-Key packets as it
/// frames them (see [`next_packet`]). At the Public-Key packet after
/// [`MAX_KEYRING_CERTS`], the walk stops with [`Chunks::OverLimit`]. So the
/// call keeps at most that number of certificates, and no list with one item
/// for each packet. If the walk then reaches a byte that does not frame, the
/// result is [`Chunks::Unframed`]. A truncated keyring gives this result, and
/// the `ostree` command also refuses such a keyring. The certificates are not
/// longer than the input, and [`keyring_stream`] already applied
/// [`MAX_KEYRING`] to the input.
fn certificate_chunks(binary: &[u8]) -> Chunks {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut at = 0usize;
    while at < binary.len() {
        let Some((tag, len)) = next_packet(&binary[at..]) else {
            return Chunks::Unframed;
        };
        let packet = &binary[at..at + len];
        match tag {
            Tag::Trust => {}
            Tag::PublicKey => {
                if chunks.len() == MAX_KEYRING_CERTS {
                    return Chunks::OverLimit;
                }
                chunks.push(packet.to_vec());
            }
            _ => {
                if let Some(chunk) = chunks.last_mut() {
                    chunk.extend_from_slice(packet);
                }
            }
        }
        at += len;
    }
    Chunks::Framed(chunks)
}

/// Parses a binary OpenPGP keyring into its certificates, each with its
/// packets.
///
/// The result has the limit [`MAX_KEYRING_CERTS`]. The call splits the stream
/// into one packet run for each certificate, and parses each run separately
/// (see [`certificate_chunks`]). So the Trust packets and a packet before the
/// first certificate go to no parser. A legacy GnuPG keyring and a
/// `gpg --export` stream of the same keys parse to the same certificates. A
/// keyring with no packet parses to no certificate.
///
/// If the stream does not frame to its end, or the parser refuses a
/// certificate, the read fails by the name of the source. So a caller gets
/// only a keyring that was read whole. `subject` names the source, so a
/// refusal states which keyring was read. A stream that does not frame gives
/// [`KeyringRefusal::NotPacketStream`]. A parser refusal and a caught panic
/// give [`KeyringRefusal::Unreadable`]. A stream over [`MAX_KEYRING_CERTS`]
/// gives [`KeyringRefusal::OverLimit`].
///
/// Each read of a keyring goes through this function: a verification load, a
/// key listing, and both streams of an import. The parse runs inside
/// [`contained`], because a keyring is untrusted input.
fn parse_keyring(
    binary: &[u8],
    subject: &str,
) -> std::result::Result<Vec<(SignedPublicKey, Vec<u8>)>, KeyringRefusal> {
    let refusal = format!("{subject} is not readable as an OpenPGP keyring: the parser panicked");
    let unreadable =
        |detail: String| format!("{subject} is not readable as an OpenPGP keyring{detail}");
    // The outer `Err` is a caught panic. The inner result is the result of
    // the read.
    contained(&refusal, || {
        let chunks = match certificate_chunks(binary) {
            Chunks::Framed(chunks) => chunks,
            Chunks::Unframed => {
                return Ok(Err(KeyringRefusal::NotPacketStream(Error::Signature(
                    unreadable(String::new()),
                ))));
            }
            Chunks::OverLimit => {
                return Ok(Err(KeyringRefusal::OverLimit(Error::Signature(format!(
                    "{subject} holds more than {MAX_KEYRING_CERTS} certificates"
                )))));
            }
        };
        let mut certs = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            match SignedPublicKey::from_bytes(Cursor::new(&chunk)) {
                Ok(cert) => certs.push((cert, chunk)),
                Err(e) => {
                    return Ok(Err(KeyringRefusal::Unreadable(Error::Signature(
                        unreadable(format!(": {e}")),
                    ))));
                }
            }
        }
        Ok(Ok(certs))
    })
    .unwrap_or_else(|panicked| Err(KeyringRefusal::Unreadable(panicked)))
}

/// Runs `work`, which reads OpenPGP packets, and changes a panic in it to the
/// error that `refusal` states.
///
/// A keyring is untrusted input, so each read of a keyring runs here. A caught
/// panic gives the same result as input that the parser refuses. Two limits
/// apply:
///
/// - If the final binary is built with `panic = "abort"`, `catch_unwind`
///   catches nothing.
/// - The call does not find a parser that returns a wrong answer with no
///   panic.
fn contained<T>(refusal: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
        Ok(result) => result,
        Err(_) => Err(Error::Signature(refusal.to_owned())),
    }
}

impl Verifier for GpgVerifier {
    fn metadata_key(&self) -> &str {
        GPG_METADATA_KEY
    }

    fn verify(&self, data: &[u8], signatures: &[Vec<u8>]) -> Result<VerifyOutcome> {
        verify::verify_signatures(&self.certs, data, signatures)
    }
}

/// One key of a keyring, as [`gpg_keyring_keys`] lists it.
///
/// The fields are the data that a certificate states about its primary key,
/// as `ostree remote gpg-list-keys` reports them. These are the fingerprint,
/// the creation time, and the user ids in listing order. A subkey has no
/// record of its own. The record of its primary key represents it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpgKey {
    /// The primary key fingerprint, uppercase hex.
    pub fingerprint: String,
    /// The creation time of the key, in seconds since the Unix epoch.
    ///
    /// `None` if the certificate states the time `0`.
    pub created: Option<u64>,
    /// The user ids bound to the key, in listing order.
    pub user_ids: Vec<String>,
}

/// Merges the certificates of `offered` into the keyring `existing`, as one
/// import does, and returns the number of new certificates.
///
/// The call runs [`gpg_offered_keys`] and then [`gpg_merge_keyring`].
#[cfg(test)]
fn merge_keyring(
    existing: &[u8],
    offered: &[u8],
    key_ids: &[String],
    subject: &str,
) -> Result<(usize, Vec<u8>)> {
    gpg_merge_keyring(
        existing,
        gpg_offered_keys(offered, key_ids, subject),
        subject,
    )
}

/// The offered stream of a keyring import, read and not merged yet.
///
/// [`gpg_offered_keys`] reads the stream before the read of the keyring that
/// the import changes. [`gpg_merge_keyring`] merges it into that keyring. The
/// value holds the certificates of the stream that the selectors take, or the
/// refusal of the stream, which the merge reports.
#[derive(Debug)]
pub struct GpgOfferedKeys {
    inner: OfferedKeys,
}

/// The offered stream of an import, as [`gpg_offered_keys`] read it.
#[derive(Debug)]
enum OfferedKeys {
    /// A stream that is refused before the read of its packets. It is over
    /// [`MAX_KEYRING`], its armor does not decode, or it is a keybox.
    Refused(Error),
    /// The packets of the stream: each certificate with its packets, and the
    /// indices of the certificates that the selectors take.
    ///
    /// `Err` holds the refusal of the read, of a stream with no certificate,
    /// or of a selector.
    Read(Result<OfferedCerts>),
}

/// The certificates of an offered stream, the packets of each certificate at
/// the same index, and the indices of the selected certificates in selection
/// order.
type OfferedCerts = (Vec<SignedPublicKey>, Vec<Vec<u8>>, Vec<usize>);

/// Reads the offered stream of an import into the keyring that `subject`
/// names, and selects the certificates that `key_ids` names.
///
/// `offered` is a binary or ASCII-armored certificate stream, as an exported
/// public keyring is. If `key_ids` is not empty, the import takes only the
/// keys that these selectors name. A selector is a fingerprint, a key id, or
/// a user id substring, as `gpg --export` reads a key name.
///
/// The call uses no byte of the keyring, so an import runs it before it takes
/// its locks. The call cannot fail. It keeps a refusal of the stream in the
/// result, and [`gpg_merge_keyring`] reports it after the refusals of the
/// keyring. So the result of an import does not change with the place where
/// the stream was read.
///
/// The stream is untrusted input. It has
/// [the limits of a keyring](GpgVerifier#limits-of-a-keyring), and must frame
/// to its end.
pub fn gpg_offered_keys(offered: &[u8], key_ids: &[String], subject: &str) -> GpgOfferedKeys {
    let source = "the keyring to import";
    let stream = match keyring_stream(offered, source) {
        Ok(stream) => stream,
        Err(err) => {
            return GpgOfferedKeys {
                inner: OfferedKeys::Refused(err.into()),
            };
        }
    };
    let refusal = format!("{source} cannot be merged into {subject}: the parser panicked");
    let read = contained(&refusal, || {
        let (certs, packets): (Vec<_>, Vec<_>) =
            parse_keyring(&stream, source)?.into_iter().unzip();
        if certs.is_empty() {
            return Err(Error::Signature(format!(
                "{source} holds no OpenPGP certificate"
            )));
        }
        let selected = select_keys(&certs, key_ids)?;
        Ok((certs, packets, selected))
    });
    GpgOfferedKeys {
        inner: OfferedKeys::Read(read),
    }
}

/// Merges the certificates of `offered` into the keyring `existing`, and
/// returns the number of new certificates and the new keyring.
///
/// [`gpg_offered_keys`] read `offered`. The call keeps the packet stream of
/// `existing` as it is, and appends the packets of each certificate that the
/// keyring does not hold. So a keyring that a different implementation wrote
/// keeps its own packets. An added certificate is as the offered stream wrote
/// it. The result is a binary packet stream with no armor. An armored
/// `existing` decodes to its packets, and the merge keeps these packets. This
/// import adds no Trust packet to the keyring.
///
/// If the keyring already holds a fingerprint, the call keeps that
/// certificate as it is. Two exceptions replace the held certificate with the
/// offered one:
///
/// - An offered certificate with a key revocation that verifies. So a revoked
///   key stops speaking for the remote.
/// - An offered certificate with a later key expiry. So a key whose owner
///   extended its life speaks again.
///
/// The call looks for a designated revoker in all certificates of the two
/// streams. So a revocation by such a revoker gets in if either stream
/// states the revoker. The replacement writes the keyring again, because a
/// keyring is one run of packets for each certificate. A signature at the end
/// of the stream attaches to the last certificate in it. The new keyring has
/// no Trust packets. In all cases, the count treats the certificate as
/// already held.
///
/// The same two rules apply inside one offered stream. If a stream holds
/// several states of one key, the first state applies. A later state replaces
/// it only if it revokes the key or states a later expiry. The count includes
/// the key once.
///
/// The reader of a verification load reads each stream. So each stream must
/// frame to its end. If a keyring holds bytes after its last framed packet,
/// the merge fails by the name of the keyring.
///
/// Both streams are untrusted input. So each one has
/// [the limits of a keyring](GpgVerifier#limits-of-a-keyring), and a panic of
/// the parser gives a refusal. `subject` names the keyring that `existing`
/// holds, so a refusal states which keyring was read.
///
/// # Errors
///
/// The call reports a refusal of `existing` first, and then the refusal that
/// `offered` holds.
///
/// - [`Error::Signature`] if `existing` or the offered stream is over 4 MiB,
///   is a GnuPG keybox, holds more than 256 certificates, or does not parse
///   as an OpenPGP keyring.
/// - [`Error::Signature`] if the offered stream holds no certificate, or a
///   selector names no key in it.
/// - [`Error::Signature`] if an armored stream is not valid UTF-8.
/// - [`Error::Core`] if the armor of a stream holds text that is not valid
///   base64.
pub fn gpg_merge_keyring(
    existing: &[u8],
    offered: GpgOfferedKeys,
    subject: &str,
) -> Result<(usize, Vec<u8>)> {
    let source = "the keyring to import";
    let keyring = keyring_stream(existing, subject)?;
    let offered = match offered.inner {
        OfferedKeys::Refused(err) => return Err(err),
        OfferedKeys::Read(read) => read,
    };
    let refusal = format!("{source} cannot be merged into {subject}: the parser panicked");
    contained(&refusal, || {
        // The certificate runs of the keyring in their order, and the state
        // of each key in it, by fingerprint. If the keyring holds one key in
        // two certificates, the key has one state over both. The verify path
        // reads the two certificates in the same way.
        let mut runs: Vec<(String, Vec<u8>)> = Vec::new();
        let mut copies: BTreeMap<String, Vec<SignedPublicKey>> = BTreeMap::new();
        for (cert, packets) in parse_keyring(&keyring, subject)? {
            let fingerprint = fingerprint_hex(&cert);
            runs.push((fingerprint.clone(), packets));
            copies.entry(fingerprint).or_default().push(cert);
        }
        let (offered, mut packets, selected) = offered?;
        // The set in which the call looks for a designated revoker. It holds
        // all certificates of the two streams, for all keys, with or without a
        // selector match (see [`KeyState`]).
        let known: Vec<&SignedPublicKey> =
            copies.values().flatten().chain(offered.iter()).collect();
        let mut held: BTreeMap<String, KeyState> = copies
            .iter()
            .map(|(fingerprint, copies)| (fingerprint.clone(), KeyState::over(copies, &known)))
            .collect();
        // The certificates to append, in append order, each with its state,
        // and the held certificates that a replacement writes again.
        let mut added: Vec<(String, KeyState, Vec<u8>)> = Vec::new();
        let mut replaced: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut imported = 0;
        // Two selectors can name one certificate. Its second index states the
        // same key state again, which replaces nothing. So the loop skips it,
        // and takes the packets of each index one time.
        let mut seen = vec![false; offered.len()];
        for index in selected {
            if std::mem::replace(&mut seen[index], true) {
                continue;
            }
            let cert = &offered[index];
            let fingerprint = fingerprint_hex(cert);
            let state = KeyState::of(cert, &known);
            if let Some(entry) = held.get_mut(&fingerprint) {
                if replaces(entry, &state) {
                    *entry = state;
                    replaced.insert(fingerprint, std::mem::take(&mut packets[index]));
                }
            } else if let Some(entry) = added.iter_mut().find(|(f, _, _)| *f == fingerprint) {
                if replaces(&entry.1, &state) {
                    entry.1 = state;
                    entry.2 = std::mem::take(&mut packets[index]);
                }
            } else {
                added.push((fingerprint, state, std::mem::take(&mut packets[index])));
                imported += 1;
            }
        }
        let appended: usize = added.iter().map(|(_, _, packets)| packets.len()).sum();
        let mut merged = if replaced.is_empty() {
            let mut merged = Vec::with_capacity(keyring.len() + appended);
            merged.extend_from_slice(&keyring);
            merged
        } else {
            replace_certificates(&runs, &replaced, appended)
        };
        for (_, _, packets) in added {
            merged.extend_from_slice(&packets);
        }
        Ok((imported, merged))
    })
}

/// The statements of the certificates of one key about that key.
#[derive(Clone, Copy)]
struct KeyState {
    /// `true` if a verified key revocation signature applies to the key.
    ///
    /// The key itself made the signature, or a designated revoker of the
    /// certificate made it. A designated revoker counts only if its
    /// certificate is among the certificates that the import knows.
    ///
    /// The import reads a revocation through the verify engine, so the import
    /// and the verdict read the same signature. The engine looks for a
    /// designated revoker in the certificates that it gets. The import gives it
    /// all certificates of its two streams: the keyring that the import
    /// changes, and the offered stream. A selector controls what the import
    /// writes, and has no effect on what it knows. So a certificate that the
    /// selector leaves out still identifies a revoker.
    ///
    /// Two states are outside that set. In each one, the keyring keeps the
    /// trust in a key, and the keyring of the `ostree` command stops the trust
    /// in it. This is a divergence:
    ///
    /// - The certificate of the revoker is in the global trusted directory or
    ///   in a `gpgkeypath` entry, and not in the keyring that the import
    ///   changes.
    /// - The revoker is imported after the revocation was offered.
    ///
    /// The import is a function of its two byte streams only. So one import
    /// writes the same bytes on each host. It writes no revocation that it
    /// cannot verify, so an offered keyring cannot remove a held certificate.
    revoked: bool,
    /// The expiry instant of the key, or `None` if the certificates state no
    /// expiry.
    ///
    /// The import reads the instant through the verify engine, so the import
    /// and the verdict use the same signature.
    expires: Option<u64>,
}

impl KeyState {
    /// Returns the state that `cert` gives, with designated revokers looked up
    /// in `known`.
    fn of(cert: &SignedPublicKey, known: &[&SignedPublicKey]) -> KeyState {
        KeyState::over(std::slice::from_ref(cert), known)
    }

    /// Returns the state that the copies of one certificate give together.
    ///
    /// The state holds a revocation in any copy, and the key expiry of the
    /// newest self-signature of the union. The verify path reads a keyring
    /// with one key in several certificates in the same way.
    ///
    /// `known` is the set in which the call looks for a designated revoker, as
    /// [`KeyState::revoked`] describes. The copies and `known` are two
    /// different sets. A revocation applies to the key of the copies, and the
    /// revoker is a different key.
    fn over(copies: &[SignedPublicKey], known: &[&SignedPublicKey]) -> KeyState {
        KeyState {
            revoked: copies
                .iter()
                .any(|cert| verify::key_revoked(cert, known.iter().copied())),
            expires: verify::key_expiry_over(copies),
        }
    }
}

/// Returns `true` if an offered certificate with the state `offered` replaces
/// a held certificate with the state `held`.
///
/// Two statements go into a held certificate. The keyring has no other way to
/// get either of them:
///
/// - A key revocation that the held certificate does not have. A revocation
///   is permanent, so a keyring whose certificate states no revocation takes
///   it.
/// - A key expiry later than the expiry of the held certificate. An absent
///   expiry is later than any instant. An expiry is renewable, so a held
///   certificate can state a lifetime that the owner of the key replaced.
///
/// A held certificate that revokes its key takes no expiry replacement. The
/// replacement writes the offered packets in the place of the held run. An
/// offered certificate with no revocation in that place removes the revocation
/// from the keyring, so this rule prevents it.
///
/// The direction of the expiry rule has two results. A shorter expiry does not
/// get into the keyring. An older certificate with a longer expiry replaces a
/// shorter expiry in the keyring.
fn replaces(held: &KeyState, offered: &KeyState) -> bool {
    let revocation = offered.revoked && !held.revoked;
    let extension = !held.revoked && states_later(offered.expires, held.expires);
    revocation || extension
}

/// Returns `true` if `offered` states a later key expiry than `held`.
///
/// An absent instant is the later statement, because a key with no expiry
/// lives longer than a key with an expiry instant.
fn states_later(offered: Option<u64>, held: Option<u64>) -> bool {
    match (offered, held) {
        (None, Some(_)) => true,
        (Some(offered), Some(held)) => offered > held,
        (_, None) => false,
    }
}

/// Returns the keyring of the certificate runs `runs`, with the packets of
/// `replaced` in the place of the run of each fingerprint that it names.
///
/// A keyring is one run of packets for each certificate. So the call replaces
/// a certificate in its position, and copies each other run as it is. If a
/// keyring holds one key in two runs, the call replaces both. The offered
/// packets then occur two times, and the key has the state of these packets.
///
/// `runs` comes from [`parse_keyring`], which drops the Trust packets and a
/// packet before the first Public-Key packet. So the new keyring has the same
/// form that the import writes for an added certificate.
///
/// The result has room for `extra` more bytes, the packets that the caller
/// appends.
fn replace_certificates(
    runs: &[(String, Vec<u8>)],
    replaced: &BTreeMap<String, Vec<u8>>,
    extra: usize,
) -> Vec<u8> {
    let len: usize = runs
        .iter()
        .map(|(fingerprint, packets)| replaced.get(fingerprint).unwrap_or(packets).len())
        .sum();
    let mut rewritten: Vec<u8> = Vec::with_capacity(len + extra);
    for (fingerprint, packets) in runs {
        rewritten.extend_from_slice(replaced.get(fingerprint).unwrap_or(packets));
    }
    rewritten
}

/// Returns the indices of the offered certificates that `key_ids` names, in
/// selector order.
///
/// An empty `key_ids` names all offered certificates. If a selector names no
/// certificate, the call refuses it by name, and the keyring does not change.
fn select_keys(offered: &[SignedPublicKey], key_ids: &[String]) -> Result<Vec<usize>> {
    if key_ids.is_empty() {
        return Ok((0..offered.len()).collect());
    }
    let mut selected = Vec::new();
    for id in key_ids {
        let matched = offered
            .iter()
            .enumerate()
            .filter(|(_, cert)| selector_matches(cert, id))
            .map(|(index, _)| index);
        let before = selected.len();
        selected.extend(matched);
        if selected.len() == before {
            return Err(Error::Signature(format!(
                "no key matching '{id}' among the keys to import"
            )));
        }
    }
    Ok(selected)
}

/// Returns `true` if `selector` names `cert`.
///
/// A selector names a key, a user id, or nothing, as [`read_selector`] reads
/// it. A key selector applies to the primary key and to each subkey. A user id
/// selector is a substring of a user id of the certificate. The match ignores
/// case for ASCII letters only.
fn selector_matches(cert: &SignedPublicKey, selector: &str) -> bool {
    match read_selector(selector) {
        Selector::Key(hex) => {
            key_matches(cert, &hex)
                || cert
                    .public_subkeys
                    .iter()
                    .any(|subkey| key_matches(subkey, &hex))
        }
        Selector::UserId(wanted) => cert.details.users.iter().any(|user| {
            String::from_utf8_lossy(user.id.id())
                .to_ascii_lowercase()
                .contains(&wanted)
        }),
        Selector::Nothing => false,
    }
}

/// The item that a `KEY-ID` selector names.
enum Selector {
    /// A key, by the lowercase hex of a key id or a fingerprint.
    Key(String),
    /// A substring of a user id, ASCII-lowercased.
    UserId(String),
    /// Nothing.
    Nothing,
}

/// Returns the item that `selector` names, as `gpg --export` reads a key name.
///
/// These rules come from `gpg --export -- <selector>` on `gpg` 2.4.9. If no key
/// matches a key selector, the export is empty. A user id selector exports the
/// key whose user id holds the substring.
///
/// - Hex digits only name a key at five lengths. 8 digits are a short key id,
///   16 a key id, and 32, 40, or 64 a fingerprint. Each other length is a
///   user id substring. `0123456789ab` exports the key whose user id holds
///   these twelve digits.
/// - A `0x` prefix names a key, and never a user id. `0xhello` reports
///   `key "0xhello" not found: Invalid user ID` over a certificate whose user id
///   holds `0xhello`. Only the lower-case prefix counts. So `0X1234` is a user
///   id substring, and exports the key whose user id holds `0X1234`.
/// - Interior spaces are allowed in one shape only, the printed v4
///   fingerprint: ten groups of four hex digits with one space between them.
///   Each other spaced shape is a user id substring. Forty hex digits in groups
///   of two, and 32 or 64 in groups of four, each export the key whose user id
///   holds them. A `0x` prefix with a space reports `Invalid user ID`.
/// - The read drops white space before and after a key selector. It also drops
///   white space before a user id selector.
/// - A selector that holds only white space names nothing.
///   `gpg --export -- ''` reports `key "" not found: Invalid user ID`.
/// - The user id search ignores case for ASCII letters only. Over the user id
///   `Ärger`, `ÄRGER` exports the key and `ärger` exports nothing.
fn read_selector(selector: &str) -> Selector {
    // `gpg` drops a space and a tab as white space, and no other character.
    // So the read drops these characters at the start of a selector.
    let space = |c: char| c == ' ' || c == '\t';
    let head = selector.trim_start_matches(space);
    if let Some(rest) = head.strip_prefix("0x") {
        return match key_hex(rest.trim_end_matches(space)) {
            Some(hex) => Selector::Key(hex),
            None => Selector::Nothing,
        };
    }
    if head.is_empty() {
        return Selector::Nothing;
    }
    let bare = head.trim_end_matches(space);
    if let Some(hex) = key_hex(bare).or_else(|| spaced_fingerprint(bare)) {
        return Selector::Key(hex);
    }
    Selector::UserId(head.to_ascii_lowercase())
}

/// Returns the lowercase hex of `text` if `text` is hex digits only, with the
/// length of a key id or a fingerprint.
fn key_hex(text: &str) -> Option<String> {
    let named = matches!(text.len(), 8 | 16 | 32 | 40 | 64);
    (named && text.chars().all(|c| c.is_ascii_hexdigit())).then(|| text.to_ascii_lowercase())
}

/// Returns the lowercase hex of a printed v4 fingerprint: ten groups of four
/// hex digits with one space between them.
fn spaced_fingerprint(text: &str) -> Option<String> {
    let groups: Vec<&str> = text.split(' ').collect();
    let shaped = groups.len() == 10
        && groups
            .iter()
            .all(|group| group.len() == 4 && group.chars().all(|c| c.is_ascii_hexdigit()));
    shaped.then(|| groups.concat().to_ascii_lowercase())
}

/// Returns `true` if one key matches the hex of a key selector.
fn key_matches<K: KeyDetails>(key: &K, hex: &str) -> bool {
    let id = key.legacy_key_id().to_string();
    match hex.len() {
        8 => id.ends_with(hex),
        16 => id == hex,
        _ => format!("{:x}", key.fingerprint()) == hex,
    }
}

/// Returns the primary key fingerprint of a certificate, in uppercase hex.
fn fingerprint_hex(cert: &SignedPublicKey) -> String {
    format!("{:X}", cert.fingerprint())
}

/// Returns the keys of a keyring, in the order of its certificates.
///
/// `keyring` is a binary or ASCII-armored OpenPGP keyring. A keyring with no
/// packet gives an empty list. The keyring is untrusted input. It has
/// [the limits of a keyring](GpgVerifier#limits-of-a-keyring), and a panic of
/// the parser gives a refusal. `subject` names the keyring in a refusal.
///
/// # Errors
///
/// - [`Error::Signature`] if the keyring is over 4 MiB, is a GnuPG keybox,
///   holds more than 256 certificates, or does not parse as an OpenPGP
///   keyring.
/// - [`Error::Signature`] if an armored keyring is not valid UTF-8.
/// - [`Error::Core`] if the armor of the keyring holds text that is not valid
///   base64.
pub fn gpg_keyring_keys(keyring: &[u8], subject: &str) -> Result<Vec<GpgKey>> {
    let binary = keyring_stream(keyring, subject)?;
    let refusal = format!("{subject} is not readable as an OpenPGP keyring: the parser panicked");
    contained(&refusal, || {
        let keys = parse_keyring(&binary, subject)?
            .into_iter()
            .map(|(cert, _)| {
                let created = cert.primary_key.created_at().as_secs();
                GpgKey {
                    fingerprint: fingerprint_hex(&cert),
                    created: (created != 0).then(|| u64::from(created)),
                    user_ids: cert
                        .details
                        .users
                        .iter()
                        .map(|user| String::from_utf8_lossy(user.id.id()).into_owned())
                        .collect(),
                }
            })
            .collect();
        Ok(keys)
    })
}

/// Decodes ASCII-armored OpenPGP data (RFC 4880 radix-64) into the binary
/// packet stream.
///
/// The result is the concatenation of all armored blocks. Binary input comes
/// back with no change, as a borrow of `bytes`. The call skips the optional
/// armor headers and the `=XXXX` checksum line.
fn dearmor(bytes: &[u8]) -> Result<Cow<'_, [u8]>> {
    let is_armored = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .is_some_and(|i| bytes[i..].starts_with(b"-----BEGIN PGP"));
    if !is_armored {
        return Ok(Cow::Borrowed(bytes));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Signature("gpg keyring: armored data is not valid UTF-8".into()))?;
    let mut out = Vec::new();
    let mut lines = text.lines().map(str::trim_end);
    while let Some(line) = lines.next() {
        if !line.starts_with("-----BEGIN PGP") {
            continue;
        }
        let mut body = String::new();
        let mut in_headers = true;
        for line in lines.by_ref() {
            if line.starts_with("-----END") {
                break;
            }
            if in_headers {
                if line.trim().is_empty() {
                    in_headers = false;
                    continue;
                }
                // An armor header is `Key: Value`. A line with no colon is
                // body, because the blank separator line is absent.
                if line.contains(':') {
                    continue;
                }
                in_headers = false;
            }
            // The `=XXXX` line is the radix-64 checksum. It is not body.
            if line.starts_with('=') {
                continue;
            }
            body.push_str(line.trim());
        }
        out.extend_from_slice(&base64::decode(&body)?);
    }
    Ok(Cow::Owned(out))
}

/// Returns a scratch directory path for one test fixture, unique in the
/// process.
///
/// The path is the GnuPG home of the `gpg` runs of the fixture, or a directory
/// of keyring files. The fixtures of this module and of [`verify`] both get
/// their paths from this function.
#[cfg(test)]
fn scratch_dir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "ostrya-gpg-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Stops each GnuPG daemon of the home directory `dir`, and removes its
/// socket directory.
///
/// GnuPG makes the socket directory under the user runtime directory. It names
/// that directory from the path string of `dir`, so the call also works after
/// the removal of `dir`. The fixtures of this module and of [`verify`] call it
/// before they remove their home. The call ignores failures.
#[cfg(test)]
fn remove_home_sockets(dir: &Path) {
    use std::process::{Command, Stdio};

    for action in [&["--kill", "all"][..], &["--remove-socketdir"][..]] {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(dir)
            .args(action)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Parses an epoch field of a status line. The value `0` gives `None`.
///
/// The differential cases in [`verify`] compare with a reference reader. This
/// reader reads the `gpgv` status stream through this function.
#[cfg(test)]
fn parse_epoch(field: &str) -> Option<u64> {
    match field.parse::<u64>() {
        Ok(0) => None,
        Ok(secs) => Some(secs),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;
    use std::path::PathBuf;

    use super::*;

    /// Returns the packets of a binary OpenPGP stream and the length of the
    /// framed prefix. Each packet comes as its tag and its byte range. The
    /// walk stops where [`next_packet`] frames no packet.
    fn packet_spans(binary: &[u8]) -> (Vec<(Tag, Range<usize>)>, usize) {
        let mut spans = Vec::new();
        let mut at = 0usize;
        while let Some((tag, len)) = next_packet(&binary[at..]) {
            spans.push((tag, at..at + len));
            at += len;
        }
        (spans, at)
    }

    #[test]
    fn dearmor_passes_binary_through() {
        let binary = [0x99, 0x01, 0x0d, 0x04];
        assert_eq!(*dearmor(&binary).unwrap(), binary);
    }

    #[test]
    fn dearmor_decodes_an_armored_block() {
        let armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
Comment: a header\n\
\n\
aGVsbG8=\n\
=abcd\n\
-----END PGP PUBLIC KEY BLOCK-----\n";
        assert_eq!(*dearmor(armored.as_bytes()).unwrap(), *b"hello");
    }

    #[test]
    fn dearmor_concatenates_blocks_and_tolerates_missing_blank_line() {
        let armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
aGVs\n\
bG8=\n\
-----END PGP PUBLIC KEY BLOCK-----\n\
-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
\n\
IHdvcmxk\n\
-----END PGP PUBLIC KEY BLOCK-----\n";
        assert_eq!(*dearmor(armored.as_bytes()).unwrap(), *b"hello world");
    }

    /// Returns `true` if the `gpg` binary runs.
    ///
    /// The keyring cases build their fixtures with `gpg`. Each of these cases
    /// calls [`gpg_or_skip`], so it skips if the binary is absent, and fails if
    /// `OSTRYA_REQUIRE_GNUPG` is set.
    fn gpg_available() -> bool {
        std::process::Command::new("gpg")
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// Returns `true` if `gpg` answers.
    ///
    /// If `gpg` does not answer, a test that needs it skips. If
    /// `OSTRYA_REQUIRE_GNUPG` is set, the absence of `gpg` fails the test.
    fn gpg_or_skip() -> bool {
        if gpg_available() {
            return true;
        }
        assert!(
            std::env::var_os("OSTRYA_REQUIRE_GNUPG").is_none(),
            "OSTRYA_REQUIRE_GNUPG is set and `gpg` is not available"
        );
        eprintln!("skipping: gpg not available");
        false
    }

    /// A private GnuPG home with new ed25519 signing keys that have no
    /// passphrase, under the test scratch tree.
    ///
    /// Each `gpg` run names this directory with `--homedir`. So the GnuPG home
    /// and the agents of the user that runs the tests take no part. When the
    /// fixture drops, it stops the GnuPG daemons of the directory, removes
    /// their socket directory, and removes the directory.
    struct KeyFixture {
        dir: PathBuf,
        /// `true` if each `gpg` run in this home uses the time [`FAKED_CLOCK`].
        faked: bool,
    }

    impl KeyFixture {
        /// Creates a home directory with one key for `uid` that never expires.
        fn new(uid: &str) -> KeyFixture {
            let fixture = KeyFixture {
                dir: KeyFixture::make_dir(),
                faked: false,
            };
            fixture.add_key(uid);
            fixture
        }

        /// Creates a home directory with one key for `uid`, created at
        /// [`FAKED_CLOCK`], with the lifetime `expiry` from that instant.
        ///
        /// Each `gpg` run in this home uses that instant. So the key is live
        /// when it makes a signature. The verify path reads the real clock, so
        /// an expired key is expired there.
        fn expiring(uid: &str, expiry: &str) -> KeyFixture {
            let fixture = KeyFixture {
                dir: KeyFixture::make_dir(),
                faked: true,
            };
            fixture.generate(uid, expiry);
            fixture
        }

        /// Creates a new directory under the test scratch tree that only its
        /// owner can read. `gpg` requires this of a home directory.
        fn make_dir() -> PathBuf {
            use std::os::unix::fs::DirBuilderExt;
            let dir = scratch_dir();
            std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
            dir
        }

        /// Generates one more key, for `uid`, in the same home directory.
        fn add_key(&self, uid: &str) {
            self.generate(uid, "never");
        }

        /// Generates one key for `uid` with the lifetime `expiry`.
        fn generate(&self, uid: &str, expiry: &str) {
            let status = self
                .gpg()
                .args(["--pinentry-mode", "loopback", "--passphrase", ""])
                .args(["--quick-gen-key", uid, "ed25519", "sign", expiry])
                .status()
                .unwrap();
            assert!(status.success(), "gpg --quick-gen-key failed");
        }

        /// Sets the expiry of the first key, with `gpg` at the time `when`.
        ///
        /// A new self-signature has a creation time. `gpg` refuses to write one
        /// at the same instant as the self-signature that it replaces. It
        /// reports "make_keysig_packet failed: Time conflict". The last clock
        /// option applies. So a run at a later instant writes the signature
        /// that a run at the instant of the fixture cannot write.
        fn set_expire_at(&self, when: &str, expiry: &str) {
            let primary = self.fingerprint();
            let status = self
                .gpg()
                .args(["--pinentry-mode", "loopback", "--passphrase", ""])
                .args(["--faked-system-time", when])
                .args(["--quick-set-expire", &primary, expiry])
                .status()
                .unwrap();
            assert!(status.success(), "gpg --quick-set-expire failed");
        }

        /// Returns one detached signature over `payload` by the first key of
        /// the home.
        fn sign(&self, payload: &[u8]) -> Vec<u8> {
            let file = self.dir.join("payload");
            std::fs::write(&file, payload).unwrap();
            let out = self
                .gpg()
                .args(["--pinentry-mode", "loopback", "--passphrase", ""])
                .args(["--detach-sign", "--output", "-", "--local-user"])
                .arg(format!("{}!", self.fingerprint()))
                .arg(&file)
                .output()
                .unwrap();
            assert!(out.status.success() && !out.stdout.is_empty());
            out.stdout
        }

        /// Adds a signing subkey to the first key of the home.
        fn add_signing_subkey(&self) {
            let primary = self.fingerprint();
            let status = self
                .gpg()
                .args(["--pinentry-mode", "loopback", "--passphrase", ""])
                .args(["--quick-add-key", &primary, "ed25519", "sign", "never"])
                .status()
                .unwrap();
            assert!(status.success(), "gpg --quick-add-key failed");
        }

        /// Returns the fingerprint of the first key of the home, in uppercase
        /// hex.
        fn fingerprint(&self) -> String {
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
                .next()
                .unwrap()
        }

        /// Returns a `gpg` command for this home directory, in batch mode.
        fn gpg(&self) -> std::process::Command {
            let mut cmd = std::process::Command::new("gpg");
            cmd.arg("--homedir").arg(&self.dir).arg("--batch");
            if self.faked {
                cmd.args(["--faked-system-time", FAKED_CLOCK]);
            }
            cmd
        }

        /// Returns the exported public keyring, binary or ASCII-armored.
        fn export(&self, armored: bool) -> Vec<u8> {
            let mut cmd = self.gpg();
            cmd.arg("--export");
            if armored {
                cmd.arg("--armor");
            }
            let out = cmd.output().unwrap();
            assert!(out.status.success() && !out.stdout.is_empty());
            out.stdout
        }

        /// Returns the keybox in which `gpg` keeps the public keys of this
        /// home.
        fn keybox(&self) -> Vec<u8> {
            std::fs::read(self.dir.join("pubring.kbx")).unwrap()
        }

        /// Binds one more user id to the first key of the home.
        fn add_uid(&self, uid: &str) {
            let primary = self.fingerprint();
            let status = self
                .gpg()
                .args(["--pinentry-mode", "loopback", "--passphrase", ""])
                .args(["--quick-add-uid", &primary, uid])
                .status()
                .unwrap();
            assert!(status.success(), "gpg --quick-add-uid failed");
        }

        /// Returns the `--with-colons` key listing of this home, as `gpg`
        /// writes it.
        ///
        /// The differential listing case reads its `pub`, `fpr`, and `uid`
        /// records as the reference.
        fn listing(&self) -> String {
            let out = self
                .gpg()
                .args(["--with-colons", "--fixed-list-mode", "--list-keys"])
                .output()
                .unwrap();
            assert!(out.status.success(), "gpg --list-keys failed");
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        /// Returns the primary-key fingerprints that `gpg` reports over
        /// `keyring`, in listing order.
        ///
        /// The `ostree` command uses this reader through gpgme. So if `gpg`
        /// lists a keyring, the `ostree` command reads it.
        fn fingerprints_of(&self, keyring: &[u8]) -> Vec<String> {
            let path = self.dir.join("listed.gpg");
            std::fs::write(&path, keyring).unwrap();
            let out = std::process::Command::new("gpg")
                .arg("--homedir")
                .arg(&self.dir)
                .arg("--batch")
                .arg("--no-default-keyring")
                .arg("--keyring")
                .arg(&path)
                .args(["--with-colons", "--list-keys"])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "gpg --list-keys over a keyring failed"
            );
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            let mut found = Vec::new();
            let mut wanted = false;
            for line in text.lines() {
                let mut fields = line.split(':');
                match fields.next() {
                    Some("pub") => wanted = true,
                    Some("fpr") if wanted => {
                        wanted = false;
                        found.push(fields.nth(8).unwrap().to_owned());
                    }
                    Some("sub") => wanted = false,
                    _ => {}
                }
            }
            found
        }

        /// Returns the `gpg --export-secret-keys` stream of the keys of this
        /// home. The stream holds no transferable public key.
        fn export_secret(&self) -> Vec<u8> {
            let out = self
                .gpg()
                .args(["--pinentry-mode", "loopback", "--passphrase", ""])
                .arg("--export-secret-keys")
                .output()
                .unwrap();
            assert!(out.status.success() && !out.stdout.is_empty());
            out.stdout
        }

        /// Returns the `gpg --export` stream of the one key that `selector`
        /// names.
        fn export_one(&self, selector: &str) -> Vec<u8> {
            let out = self
                .gpg()
                .arg("--export")
                .arg("--")
                .arg(selector)
                .output()
                .unwrap();
            assert!(out.status.success() && !out.stdout.is_empty());
            out.stdout
        }

        /// Returns the legacy keyring that `gpg --import` writes for the keys
        /// of this home.
        ///
        /// In such a keyring, GnuPG puts a Trust packet after the primary key
        /// packet, after each user id packet, and after each signature packet.
        /// The import of the `ostree` command leaves this form at the
        /// repository root.
        fn legacy_keyring(&self) -> Vec<u8> {
            self.imported_keyring("legacy", &[&self.export(false)])
        }

        /// Returns the legacy keyring that `gpg --import` writes for
        /// `streams`, imported in their order.
        ///
        /// `name` names the home directory of the import, so one fixture can
        /// build more than one such keyring. If `gpg` creates a keyring file
        /// itself, it writes a keybox. If the file exists, it writes a legacy
        /// keyring. So the import runs in its own home over an empty keyring
        /// file.
        fn imported_keyring(&self, name: &str, streams: &[&[u8]]) -> Vec<u8> {
            use std::os::unix::fs::DirBuilderExt;
            let home = self.dir.join(name);
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&home)
                .unwrap();
            let ring = home.join("ring.gpg");
            std::fs::write(&ring, b"").unwrap();
            for (index, stream) in streams.iter().enumerate() {
                let source = home.join(format!("offered-{index}.gpg"));
                std::fs::write(&source, stream).unwrap();
                let status = std::process::Command::new("gpg")
                    .arg("--homedir")
                    .arg(&home)
                    .arg("--batch")
                    .arg("--no-default-keyring")
                    .arg("--keyring")
                    .arg(&ring)
                    .arg("--import")
                    .arg(&source)
                    .status()
                    .unwrap();
                remove_home_sockets(&home);
                assert!(status.success(), "gpg --import into a keyring failed");
            }
            std::fs::read(&ring).unwrap()
        }

        /// Revokes the first key of the home. The call imports the revocation
        /// certificate that `gpg` stored when it generated the key.
        fn revoke_primary(&self) {
            let path = self.dir.join("revocation.asc");
            std::fs::write(&path, self.revocation_armor()).unwrap();
            let status = self.gpg().arg("--import").arg(&path).status().unwrap();
            assert!(status.success(), "gpg --import of the revocation failed");
        }

        /// Returns the key revocation signature packet that `gpg` stored for
        /// the first key of the home, in the binary form.
        fn revocation_packet(&self) -> Vec<u8> {
            let packet = dearmor(&self.revocation_armor()).unwrap().into_owned();
            let (spans, framed) = packet_spans(&packet);
            assert_eq!((spans.len(), framed), (1, packet.len()));
            packet
        }

        /// Imports a certificate stream into this home.
        fn import(&self, bytes: &[u8]) {
            let path = self.dir.join("import.gpg");
            std::fs::write(&path, bytes).unwrap();
            let status = self.gpg().arg("--import").arg(&path).status().unwrap();
            assert!(status.success(), "gpg --import failed");
        }

        /// Imports a stream that `gpg` merges, although it reports a failure.
        ///
        /// `gpg --import` exits 2 over the stream that `gpg --desig-revoke`
        /// writes. It exits 2 with or without the certificate of the revoker
        /// in the home. Without it, the run reports "no public key - can't
        /// apply revocation certificate". With it, the run reports "invalid
        /// revocation certificate: Bad signature - rejected" against the key id
        /// of the revoker.
        ///
        /// In both cases it reports "revocation certificate added" for the
        /// revoked key. It merges the class 0x20 signature into its
        /// certificate, so the export of the home holds the packet.
        fn import_merging(&self, bytes: &[u8]) {
            let path = self.dir.join("import.gpg");
            std::fs::write(&path, bytes).unwrap();
            self.gpg().arg("--import").arg(&path).status().unwrap();
        }

        /// Designates the key that `revoker` names as a revoker of the first
        /// key of this home.
        ///
        /// `gpg` writes a new direct-key self-signature with signature
        /// subpacket 12. So this home must already hold the certificate of the
        /// revoker.
        fn add_revoker(&self, revoker: &str) {
            let mut cmd = self.gpg_interactive();
            cmd.arg("--edit-key").arg(self.fingerprint());
            answer(
                cmd,
                format!("addrevoker\n{revoker}\ny\ny\nsave\n").as_bytes(),
                "gpg --edit-key addrevoker",
            );
        }

        /// Returns the key revocation that a designated revoker makes over the
        /// key that `key` names.
        ///
        /// The result is the binary packet stream that `gpg --desig-revoke`
        /// writes. It is a transferable public key of the revoked key, with the
        /// class 0x20 signature immediately after the primary key packet. This
        /// home must hold the secret key of the revoker. It must also hold a
        /// certificate of the revoked key that designates the revoker.
        fn desig_revoke(&self, key: &str) -> Vec<u8> {
            let path = self.dir.join("desig-revoke.asc");
            let mut cmd = self.gpg_interactive();
            cmd.arg("--armor")
                .arg("--output")
                .arg(&path)
                .arg("--desig-revoke")
                .arg(key);
            answer(cmd, b"y\n0\n\ny\n", "gpg --desig-revoke");
            dearmor(&std::fs::read(&path).unwrap())
                .unwrap()
                .into_owned()
        }

        /// Returns a `gpg` command for this home that reads its answers from
        /// standard input. It is for the commands that have no batch form.
        fn gpg_interactive(&self) -> std::process::Command {
            let mut cmd = std::process::Command::new("gpg");
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
            cmd
        }

        /// Returns the armored block of the revocation certificate that `gpg`
        /// stored for the first key of the home.
        ///
        /// The stored file has prose before the block. It also has a colon
        /// before the first dash of the block, so an accidental import does
        /// nothing.
        fn revocation_armor(&self) -> Vec<u8> {
            let stored = self
                .dir
                .join("openpgp-revocs.d")
                .join(format!("{}.rev", self.fingerprint()));
            let text = std::fs::read_to_string(&stored).unwrap();
            let at = text.find("-----BEGIN PGP").unwrap();
            text.as_bytes()[at..].to_vec()
        }
    }

    /// Runs `cmd` with `answers` on its standard input, and asserts that it
    /// reported success. `what` names the command in the assertion message.
    fn answer(mut cmd: std::process::Command, answers: &[u8], what: &str) {
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

    impl Drop for KeyFixture {
        fn drop(&mut self) {
            remove_home_sockets(&self.dir);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A binary keyring holding one certificate loads to that certificate.
    #[test]
    fn loads_a_binary_keyring() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Binary <binary@ostrya.example>");
        let verifier = GpgVerifier::from_keyring_bytes([home.export(false)]).unwrap();
        assert_eq!(verifier.certs.len(), 1);
    }

    /// An armored keyring loads to the same certificate as the binary form.
    /// The armor decoder gives the binary export byte for byte, so the parser
    /// reads the same packet stream from both forms.
    #[test]
    fn loads_an_armored_keyring() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Armored <armored@ostrya.example>");
        let exported = home.export(false);
        assert_eq!(dearmor(&home.export(true)).unwrap(), exported);
        let binary = GpgVerifier::from_keyring_bytes([&exported]).unwrap();
        let armored = GpgVerifier::from_keyring_bytes([home.export(true)]).unwrap();
        assert_eq!(armored.certs.len(), 1);
        assert_eq!(armored.certs, binary.certs);
    }

    /// A keyring holding two certificates loads both.
    #[test]
    fn loads_a_two_certificate_keyring() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("First <first@ostrya.example>");
        home.add_key("Second <second@ostrya.example>");
        let verifier = GpgVerifier::from_keyring_bytes([home.export(false)]).unwrap();
        assert_eq!(verifier.certs.len(), 2);
    }

    /// An empty keyring loads and holds no certificate. An optional keyring
    /// that exists and holds nothing does not cause a failure.
    #[test]
    fn loads_an_empty_keyring() {
        let verifier = GpgVerifier::from_keyring_bytes([b""]).unwrap();
        assert!(verifier.certs.is_empty());
    }

    /// The load refuses a truncated keyring by the name of its blob.
    #[test]
    fn refuses_a_truncated_keyring() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Cut <cut@ostrya.example>");
        let keyring = home.export(false);
        let cut = &keyring[..keyring.len() / 2];
        let err = GpgVerifier::from_keyring_bytes([cut]).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("keyring blob 0")
                && m.contains("OpenPGP keyring")),
            "{err}"
        );
    }

    /// The load refuses a GnuPG keybox by name.
    ///
    /// rPGP reads an OpenPGP packet stream, and a keybox is a container of a
    /// different kind. A read of a keybox as a keyring gives an empty trusted
    /// set with no message.
    #[test]
    fn refuses_a_keybox() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Box <box@ostrya.example>");
        let keybox = home.keybox();
        assert_eq!(
            &keybox[KEYBOX_MAGIC_OFFSET..KEYBOX_MAGIC_OFFSET + KEYBOX_MAGIC.len()],
            KEYBOX_MAGIC
        );
        let err = GpgVerifier::from_keyring_bytes([keybox]).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("keyring blob 0")
                && m.contains("keybox")),
            "{err}"
        );
    }

    /// The load refuses a keyring over the four-mebibyte limit by name, and
    /// the refusal states the limit. The size check comes before the parse.
    #[test]
    fn refuses_an_oversized_keyring() {
        let oversized = vec![0u8; MAX_KEYRING as usize + 1];
        let err = GpgVerifier::from_keyring_bytes([oversized]).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("keyring blob 0")
                && m.contains("ceiling")),
            "{err}"
        );
    }

    /// The load refuses a keyring with more than 256 certificates by name, and
    /// the refusal states the limit. The keyring is one certificate 257 times:
    /// 257 transferable public keys in one packet stream.
    #[test]
    fn refuses_too_many_certificates() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Many <many@ostrya.example>");
        let one = home.export(false);
        let many = one.repeat(MAX_KEYRING_CERTS + 1);
        assert!(many.len() as u64 <= MAX_KEYRING);
        let err = GpgVerifier::from_keyring_bytes([&many]).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("keyring blob 0")
                && m.contains("256 certificates")),
            "{err}"
        );
        // One certificate less than the limit loads, so the limit caused the
        // refusal.
        let allowed = one.repeat(MAX_KEYRING_CERTS);
        let verifier = GpgVerifier::from_keyring_bytes([&allowed]).unwrap();
        assert_eq!(verifier.certs.len(), MAX_KEYRING_CERTS);
    }

    /// A refused path adds no keyring to the trusted set. The keyring file
    /// before the refused path does not get into the set.
    #[test]
    fn a_refused_keyring_file_adds_no_keyring() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Whole <whole@ostrya.example>");
        let good = home.dir.join("good.gpg");
        std::fs::write(&good, home.export(false)).unwrap();
        let mut verifier = GpgVerifier::default();
        let err = verifier
            .add_keyring_files([good.as_path(), home.dir.as_path()])
            .unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("is not a regular file")),
            "{err}"
        );
        assert!(verifier.is_empty());
        verifier.add_keyring_files([&good]).unwrap();
        assert_eq!(verifier.certs.len(), 1);
    }

    /// The skipping load skips each file with no armor that is a GnuPG
    /// keybox or that does not frame as a whole OpenPGP packet stream, and
    /// gives no error. It adds the certificates of each keyring file, binary
    /// or armored. A path that names no file is also skipped. An empty file
    /// gives no certificate.
    #[test]
    fn the_skipping_load_skips_a_file_that_is_not_a_keyring() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Skip <skip@ostrya.example>");
        let dir = home.dir.join("keys");
        std::fs::create_dir(&dir).unwrap();
        let binary = home.export(false);
        let text = b"This directory holds the trusted keys.\n".to_vec();
        let mut trailing = binary.clone();
        trailing.extend_from_slice(&text);
        let noise: Vec<u8> = (0..512u32).map(|i| (i * 7919 % 251) as u8).collect();
        let keyrings = [
            ("binary.gpg", binary.clone()),
            ("armored.asc", home.export(true)),
        ];
        let others = [
            ("README", text),
            ("pubring.kbx", home.keybox()),
            ("truncated.gpg", binary[..binary.len() / 2].to_vec()),
            ("trailing.gpg", trailing),
            ("noise.bin", noise),
        ];
        let mut paths = Vec::new();
        for (name, bytes) in keyrings.iter().chain(&others) {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            paths.push(path);
        }
        // The load that refuses each file that is not a keyring refuses each
        // of these files.
        for (name, _) in &others {
            let err = GpgVerifier::from_keyring_files([dir.join(name)]).unwrap_err();
            assert!(
                matches!(&err, Error::Signature(_) | Error::Core(_)),
                "{name}: {err}"
            );
        }
        let empty = dir.join("empty.gpg");
        std::fs::write(&empty, b"").unwrap();
        let mut verifier = GpgVerifier::default();
        verifier.add_keyring_files_skipping([&empty]).unwrap();
        assert!(verifier.is_empty());
        paths.push(empty);
        paths.push(dir.join("absent.gpg"));
        verifier.add_keyring_files_skipping(&paths).unwrap();
        assert_eq!(verifier.certs.len(), 2);
        let alone = GpgVerifier::from_keyring_files([dir.join("binary.gpg")]).unwrap();
        assert_eq!(verifier.certs[0], alone.certs[0]);
        assert_eq!(verifier.certs[1], alone.certs[0]);
    }

    /// The skipping load refuses a file over a limit of the port, a file that
    /// is not a regular file, and a file that cannot be opened, by the path of
    /// the file. On each refusal, the verifier is unchanged.
    #[cfg(unix)]
    #[test]
    fn the_skipping_load_refuses_a_limit_and_a_file_it_cannot_read() {
        use std::os::unix::fs::PermissionsExt;

        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Limit <limit@ostrya.example>");
        let dir = home.dir.join("keys");
        std::fs::create_dir(&dir).unwrap();
        let one = home.export(false);
        let good = dir.join("good.gpg");
        std::fs::write(&good, &one).unwrap();
        let oversized = dir.join("oversized.gpg");
        std::fs::write(&oversized, vec![0u8; MAX_KEYRING as usize + 1]).unwrap();
        let many = dir.join("many.gpg");
        std::fs::write(&many, one.repeat(MAX_KEYRING_CERTS + 1)).unwrap();
        // The certificates come before bytes that do not frame. The count
        // reaches the limit before the walk reaches these bytes.
        let many_tailed = dir.join("many-tailed.gpg");
        let mut tailed = one.repeat(MAX_KEYRING_CERTS + 1);
        tailed.extend_from_slice(b"This file holds the trusted keys.\n");
        std::fs::write(&many_tailed, tailed).unwrap();
        let mut refused = vec![
            (oversized, "ceiling"),
            (many, "256 certificates"),
            (many_tailed, "256 certificates"),
            (dir.clone(), "is not a regular file"),
        ];
        let fifo = dir.join("fifo.gpg");
        match std::process::Command::new("mkfifo").arg(&fifo).status() {
            Ok(status) if status.success() => refused.push((fifo, "is not a regular file")),
            other => eprintln!("skipping the fifo arm: mkfifo did not create a fifo: {other:?}"),
        }
        let unreadable = dir.join("unreadable.gpg");
        std::fs::write(&unreadable, &one).unwrap();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
        // A process that holds the override of file permissions, as root
        // does, opens the file. The arm then has no refusal to observe.
        if std::fs::File::open(&unreadable).is_ok() {
            eprintln!("skipping the unreadable arm: the file opens with mode 000");
        } else {
            refused.push((unreadable, "cannot be opened"));
        }
        let mut verifier = GpgVerifier::default();
        verifier.add_keyring_files_skipping([&good]).unwrap();
        for (path, reason) in &refused {
            let err = verifier
                .add_keyring_files_skipping([good.as_path(), path.as_path()])
                .unwrap_err();
            let named = format!("the keyring '{}'", path.display());
            assert!(
                matches!(&err, Error::Signature(m) if m.contains(&named) && m.contains(reason)),
                "{err}"
            );
            assert_eq!(verifier.certs.len(), 1);
        }
    }

    /// Returns `path` with `bytes` written to it.
    fn write_file(path: PathBuf, bytes: &[u8]) -> PathBuf {
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// Asserts that the skipping load refuses each of `paths` by its path,
    /// after a load of `good`, and leaves the verifier unchanged.
    fn skipping_load_refuses(good: &Path, paths: &[PathBuf]) {
        let mut verifier = GpgVerifier::default();
        verifier.add_keyring_files_skipping([good]).unwrap();
        let before = verifier.certs.len();
        for path in paths {
            let err = verifier
                .add_keyring_files_skipping([good, path.as_path()])
                .unwrap_err();
            let named = format!("the keyring '{}'", path.display());
            assert!(
                matches!(&err, Error::Signature(m) if m.contains(&named)),
                "{}: {err}",
                path.display()
            );
            assert_eq!(verifier.certs.len(), before);
        }
    }

    /// The skipping load refuses, by its path, each file that holds the
    /// line `-----BEGIN PGP` and that the load cannot read whole as an
    /// armored keyring. Armor after other bytes, an armor line that does not
    /// start a line, an armor header that is not UTF-8, a good block before a
    /// block that is not base64, and armor that does not decode to a whole
    /// packet stream are examples. The `ostree` command reads the armor of
    /// most of these files and can find a revocation in it, so a skip can
    /// trust a revoked key.
    #[test]
    fn the_skipping_load_refuses_armor_it_cannot_read_whole() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Armor <armor@ostrya.example>");
        let dir = home.dir.join("keys");
        std::fs::create_dir(&dir).unwrap();
        let binary = home.export(false);
        let armored = home.export(true);
        let good = write_file(dir.join("good.gpg"), &binary);
        let first_line = armored.iter().position(|b| *b == b'\n').unwrap() + 1;
        let block = |payload: &[u8]| {
            format!(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{}\n\
                 -----END PGP PUBLIC KEY BLOCK-----\n",
                base64::encode(payload)
            )
            .into_bytes()
        };
        let bad_block = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!!\n\
                          -----END PGP PUBLIC KEY BLOCK-----\n";
        let refused = [
            write_file(
                dir.join("after-text.asc"),
                &[&b"The trusted keys of the remote.\n"[..], &armored].concat(),
            ),
            write_file(
                dir.join("after-bom.asc"),
                &[&b"\xef\xbb\xbf"[..], &armored].concat(),
            ),
            write_file(
                dir.join("indented.asc"),
                &[&b"\n\n  "[..], &armored].concat(),
            ),
            write_file(
                dir.join("latin1-header.asc"),
                &[
                    &armored[..first_line],
                    &b"Comment: caf\xe9\n"[..],
                    &armored[first_line..],
                ]
                .concat(),
            ),
            write_file(
                dir.join("bad-later-block.asc"),
                &[&armored[..], &bad_block[..]].concat(),
            ),
            write_file(dir.join("bad-block.asc"), bad_block),
            write_file(dir.join("not-a-keyring.asc"), &block(b"hello")),
            write_file(
                dir.join("truncated.asc"),
                &block(&binary[..binary.len() / 2]),
            ),
            write_file(dir.join("keybox.asc"), &block(&home.keybox())),
            write_file(
                dir.join("in-binary.gpg"),
                &[
                    &binary[..],
                    &b"\n-----BEGIN PGP PUBLIC KEY BLOCK-----\n"[..],
                ]
                .concat(),
            ),
        ];
        skipping_load_refuses(&good, &refused);
        // The same armor with no text before it adds the key.
        let mut verifier = GpgVerifier::default();
        verifier
            .add_keyring_files_skipping([write_file(dir.join("plain.asc"), &armored)])
            .unwrap();
        assert_eq!(verifier.certs.len(), 1);
    }

    /// The skipping load refuses, by its path, a file that frames as a whole
    /// OpenPGP packet stream and that the parser refuses. Each stream here is
    /// one Public-Key packet whose body the parser refuses.
    #[test]
    fn the_skipping_load_refuses_a_framed_stream_the_parser_refuses() {
        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let streams: [&[u8]; 3] = [
            // A version 4 key with no creation time.
            b"\xc6\x01\x04",
            // A version 4 key of algorithm 1 (RSA) with no key material.
            b"\xc6\x06\x04\x00\x00\x00\x00\x01",
            // A key of version 9.
            b"\xc6\x06\x09\x00\x00\x00\x00\x01",
        ];
        let mut results = Vec::new();
        for (index, stream) in streams.iter().enumerate() {
            let path = write_file(dir.join(format!("{index}.gpg")), stream);
            assert!(matches!(certificate_chunks(stream), Chunks::Framed(_)));
            let mut verifier = GpgVerifier::default();
            results.push((path.clone(), verifier.add_keyring_files_skipping([&path])));
        }
        std::fs::remove_dir_all(&dir).unwrap();
        for (path, result) in results {
            let named = format!("the keyring '{}'", path.display());
            assert!(
                matches!(&result, Err(Error::Signature(m)) if m.contains(&named)
                    && m.contains("is not readable as an OpenPGP keyring: ")),
                "{}: {result:?}",
                path.display()
            );
        }
    }

    /// A stream of empty Public-Key packets reaches the certificate limit.
    /// The walk counts the Public-Key packets and stops at the first packet
    /// over the limit, so the split keeps at most the limit in memory. Bytes
    /// that do not frame after the limit do not change the refusal.
    #[test]
    fn a_stream_of_empty_key_packets_reaches_the_certificate_limit() {
        let full = [0xc6u8, 0x00].repeat(MAX_KEYRING as usize / 2);
        assert_eq!(full.len() as u64, MAX_KEYRING);
        let mut tailed = [0xc6u8, 0x00].repeat(MAX_KEYRING_CERTS + 1);
        tailed.extend_from_slice(b"trailing text");
        for stream in [&full, &tailed] {
            assert!(matches!(certificate_chunks(stream), Chunks::OverLimit));
            let err = GpgVerifier::from_keyring_bytes([stream]).unwrap_err();
            assert!(
                matches!(&err, Error::Signature(m) if m.contains("keyring blob 0")
                    && m.contains("holds more than 256 certificates")),
                "{err}"
            );
        }
        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_file(dir.join("empty-keys.gpg"), &full);
        let result = GpgVerifier::default().add_keyring_files_skipping([&path]);
        std::fs::remove_dir_all(&dir).unwrap();
        let named = format!("the keyring '{}'", path.display());
        assert!(
            matches!(&result, Err(Error::Signature(m)) if m.contains(&named)
                && m.contains("holds more than 256 certificates")),
            "{result:?}"
        );
    }

    /// Returns the user ids of each certificate, one list for each
    /// certificate. The certificates and the ids are sorted. So two trusted
    /// sets compare as one value, and the order in their keyrings has no
    /// effect.
    fn user_ids(verifier: &GpgVerifier) -> Vec<Vec<String>> {
        let mut all: Vec<Vec<String>> = verifier
            .certs
            .iter()
            .map(|cert| {
                let mut ids: Vec<String> = cert
                    .details
                    .users
                    .iter()
                    .map(|user| String::from_utf8_lossy(user.id.id()).into_owned())
                    .collect();
                ids.sort();
                ids
            })
            .collect();
        all.sort();
        all
    }

    /// A legacy keyring and the `gpg --export` stream of the same keys parse to
    /// the same certificate count, user ids, and subkeys.
    ///
    /// A legacy keyring has a Trust packet after the primary key packet and
    /// after each user id and signature packet.
    #[test]
    fn loads_a_trust_packet_keyring() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Trust <trust@ostrya.example>");
        home.add_key("Second <second@ostrya.example>");
        let exported = home.export(false);
        let legacy = home.legacy_keyring();
        // The fixture has the shape under test: the two forms have different
        // bytes.
        assert_ne!(legacy, exported);
        assert!(legacy.len() > exported.len());

        let from_export = GpgVerifier::from_keyring_bytes([&exported]).unwrap();
        let from_legacy = GpgVerifier::from_keyring_bytes([&legacy]).unwrap();
        assert_eq!(from_legacy.certs.len(), 2);
        assert_eq!(from_legacy.certs.len(), from_export.certs.len());
        assert_eq!(user_ids(&from_legacy), user_ids(&from_export));
        assert_eq!(
            user_ids(&from_legacy),
            [
                ["Second <second@ostrya.example>"],
                ["Trust <trust@ostrya.example>"]
            ]
        );
        let subkeys = |v: &GpgVerifier| -> usize {
            v.certs.iter().map(|cert| cert.public_subkeys.len()).sum()
        };
        assert_eq!(subkeys(&from_legacy), subkeys(&from_export));
    }

    /// A signing subkey from a legacy keyring gets into the trusted set.
    ///
    /// The subkey packet comes after the Trust packet of the primary key. If
    /// the Trust packets go to the parser, the keyring loses this subkey.
    #[test]
    fn loads_a_subkey_from_a_trust_packet_keyring() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Subkey <subkey@ostrya.example>");
        home.add_signing_subkey();
        let verifier = GpgVerifier::from_keyring_bytes([home.legacy_keyring()]).unwrap();
        assert_eq!(verifier.certs.len(), 1);
        assert_eq!(verifier.certs[0].public_subkeys.len(), 1);
    }

    /// If the packet stream of a keyring stops framing part of the way, the
    /// load refuses the keyring by the name of its blob. All its certificates
    /// are refused with it.
    ///
    /// The stream holds one whole certificate, then a second one. In the second
    /// one, a Trust packet with an indeterminate length follows the primary key
    /// packet. The packet walk frames only a fixed length, so it stops there.
    /// The certificate parser reads the rest of the stream as the body of that
    /// packet.
    ///
    /// The second certificate is after the point where the walk stopped, and
    /// has its own Trust packets there. So without the refusal, it gets into
    /// the trusted set with no user id and no subkey. The refusal covers the
    /// whole keyring, so a verification uses a keyring that was read whole.
    ///
    /// The reference tools read such a keyring up to the packet where they
    /// stop, and trust the certificates before it. These results are measured
    /// over this shape:
    ///
    /// - `gpgv` 2.4.9 reports `GOODSIG` at exit 0 over a signature by the
    ///   first certificate.
    /// - `gpgv` 2.4.9 reports
    ///   `[don't know]: indeterminate length for invalid packet type 12`,
    ///   `keydb_search failed: Invalid packet`, `ERRSIG`, and `NO_PUBKEY` at
    ///   exit 2 over a signature by the second one.
    /// - `gpg --list-keys` over the file lists only the first key.
    /// - `ostree show --gpg-verify-remote` reports `Good signature from "..."`
    ///   for the first and `Can't check signature: public key not found` for
    ///   the second.
    #[test]
    fn refuses_a_keyring_holding_a_certificate_past_its_framed_prefix() {
        if !gpg_or_skip() {
            return;
        }
        let first = KeyFixture::new("First <first@ostrya.example>");
        let second = KeyFixture::new("Second <second@ostrya.example>");
        second.add_signing_subkey();
        // A Trust packet, tag 12, in the old header form with length type 3,
        // which is the indeterminate length.
        let indeterminate_trust = [0xb3];
        let legacy = second.legacy_keyring();
        let mut keyring = first.export(false);
        keyring.extend_from_slice(&insert_after_primary(&legacy, &indeterminate_trust));
        // The fixture has the shape under test: the walk stops inside the
        // second certificate, and the run split returns nothing.
        assert!(packet_spans(&keyring).1 < keyring.len());
        assert!(matches!(certificate_chunks(&keyring), Chunks::Unframed));

        let err = GpgVerifier::from_keyring_bytes([&keyring]).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("keyring blob 0")
                && m.contains("OpenPGP keyring")),
            "{err}"
        );

        // The same two certificates, in a keyring without that packet, load
        // with the user id and the subkey of each one.
        let intact = [first.export(false), legacy].concat();
        let verifier = GpgVerifier::from_keyring_bytes([&intact]).unwrap();
        assert_eq!(verifier.certs.len(), 2);
        assert_eq!(verifier.certs[1].details.users.len(), 1);
        assert_eq!(verifier.certs[1].public_subkeys.len(), 1);
    }

    /// The certificate limit counts the certificates that a keyring parses
    /// to, with or without Trust packets. The load refuses 257 legacy
    /// certificates by name, and 256 load.
    #[test]
    fn refuses_too_many_certificates_with_trust_packets() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Capped <capped@ostrya.example>");
        let one = home.legacy_keyring();
        let many = one.repeat(MAX_KEYRING_CERTS + 1);
        assert!(many.len() as u64 <= MAX_KEYRING);
        let err = GpgVerifier::from_keyring_bytes([&many]).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("keyring blob 0")
                && m.contains("256 certificates")),
            "{err}"
        );
        let allowed = one.repeat(MAX_KEYRING_CERTS);
        let verifier = GpgVerifier::from_keyring_bytes([&allowed]).unwrap();
        assert_eq!(verifier.certs.len(), MAX_KEYRING_CERTS);
    }

    /// A keyring with no Trust packet parses to its packets, byte for byte.
    ///
    /// The parse drops a packet before the first certificate. A keyring with
    /// no packet parses to no certificate. If the header parser cannot frame a
    /// stream to its end, the parse refuses it by the name of the source.
    #[test]
    fn parse_keyring_reads_the_packets_of_a_trust_free_stream() {
        assert!(parse_keyring(b"", SUBJECT).unwrap().is_empty());
        // No OpenPGP packet header opens with these bits.
        refuses_the_stream(b"\x00\x01\x02");
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Untouched <untouched@ostrya.example>");
        let exported = home.export(false);
        let read = parse_keyring(&exported, SUBJECT).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].1, exported);
        // A packet before the first Public-Key packet is part of no
        // certificate, so the keyring parses to the certificate after it.
        let mut prefixed = home.revocation_packet();
        prefixed.extend_from_slice(&exported);
        let read = parse_keyring(&prefixed, SUBJECT).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].1, exported);
        // The parse refuses a truncated keyring by the name of the source.
        refuses_the_stream(&exported[..exported.len() / 2]);
    }

    /// Asserts that [`parse_keyring`] refuses `stream` by the name of the
    /// source, as a stream that does not frame to its end. A keyring that the
    /// certificate reader does not read whole gets this refusal.
    fn refuses_the_stream(stream: &[u8]) {
        let err = parse_keyring(stream, SUBJECT).unwrap_err();
        assert!(
            matches!(&err, KeyringRefusal::NotPacketStream(Error::Signature(m)) if m.contains(SUBJECT)
                && m.contains("OpenPGP keyring")),
            "{err:?}"
        );
    }

    /// Returns the concatenated packets that a keyring parses to.
    ///
    /// The result is the stream without its Trust packets, and without a
    /// packet before its first certificate.
    fn certificate_stream(keyring: &[u8]) -> Vec<u8> {
        parse_keyring(keyring, SUBJECT)
            .unwrap()
            .into_iter()
            .flat_map(|(_, packets)| packets)
            .collect()
    }

    /// The subject that a refusal names for the keyring of the repository.
    const SUBJECT: &str = "the keyring 'origin.trustedkeys.gpg'";

    /// The time of a faked-clock fixture, 2025-01-01T00:00:00Z.
    const FAKED_CLOCK: &str = "20250101T000000!";

    /// The payload that the signature of a fixture covers.
    const PAYLOAD: &[u8] = b"ostrya commit payload";

    /// Returns `true` if the certificates of `keyring` report `blob` as a
    /// valid signature over [`PAYLOAD`].
    ///
    /// This is the verdict of the trusted keyring of a remote after an import.
    /// The call reads it through the same engine as a verification.
    fn signature_is_valid(keyring: &[u8], blob: &[u8]) -> bool {
        let certs = GpgVerifier::from_keyring_bytes([keyring]).unwrap().certs;
        verify::verify_signatures(&certs, PAYLOAD, &[blob.to_vec()])
            .unwrap()
            .valid
    }

    /// An import into no keyring writes the offered stream as it is and counts
    /// each certificate. `gpg` reads the result. A repeated import counts no
    /// certificate and does not change the bytes.
    #[test]
    fn an_import_writes_the_offered_certificates() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("First <first@ostrya.example>");
        home.add_key("Second <second@ostrya.example>");
        let offered = home.export(false);

        let (imported, keyring) = merge_keyring(b"", &offered, &[], SUBJECT).unwrap();
        assert_eq!(imported, 2);
        assert_eq!(keyring, offered);
        // `gpg` reads the keyring that the import writes. The `ostree` command
        // uses this reader through gpgme.
        assert_eq!(home.fingerprints_of(&keyring).len(), 2);

        let (again, repeated) = merge_keyring(&keyring, &offered, &[], SUBJECT).unwrap();
        assert_eq!(again, 0);
        assert_eq!(repeated, keyring);
    }

    /// An import into a keyring that GnuPG wrote keeps that keyring byte for
    /// byte, and appends the packets of the added certificate.
    ///
    /// `gpg` reads the result, which holds both keys. So both implementations
    /// read a keyring with Trust packets for one key and none for the other.
    #[test]
    fn an_import_keeps_the_keyring_it_was_given() {
        if !gpg_or_skip() {
            return;
        }
        let held = KeyFixture::new("Held <held@ostrya.example>");
        let added = KeyFixture::new("Added <added@ostrya.example>");
        let existing = held.legacy_keyring();
        let offered = added.export(false);

        let (imported, keyring) = merge_keyring(&existing, &offered, &[], SUBJECT).unwrap();
        assert_eq!(imported, 1);
        assert_eq!(&keyring[..existing.len()], &existing[..]);
        assert_eq!(&keyring[existing.len()..], &offered[..]);
        let listed = held.fingerprints_of(&keyring);
        assert_eq!(listed, [held.fingerprint(), added.fingerprint()]);
    }

    /// An import into an armored keyring keeps the packet stream of that
    /// keyring, and writes it back in the binary form.
    ///
    /// The armor decodes to the packets of the binary export of the same key.
    /// These packets start the result, and the packets of the added
    /// certificate follow them. `gpg` reads the result and lists both keys.
    #[test]
    fn an_import_keeps_the_packet_stream_of_an_armored_keyring() {
        if !gpg_or_skip() {
            return;
        }
        let held = KeyFixture::new("Armored <armored@ostrya.example>");
        let added = KeyFixture::new("Added <added@ostrya.example>");
        let binary = held.export(false);
        let armored = held.export(true);
        let offered = added.export(false);
        assert!(armored.starts_with(b"-----BEGIN PGP"));

        let (imported, keyring) = merge_keyring(&armored, &offered, &[], SUBJECT).unwrap();
        assert_eq!(imported, 1);
        assert_eq!(&keyring[..binary.len()], &binary[..]);
        assert_eq!(&keyring[binary.len()..], &offered[..]);
        let listed = held.fingerprints_of(&keyring);
        assert_eq!(listed, [held.fingerprint(), added.fingerprint()]);
    }

    /// The Trust packets are the only difference between the keyring that
    /// GnuPG writes and the keyring that this import writes for the same keys.
    ///
    /// An offered legacy keyring loses its Trust packets. So the keyring that
    /// the import writes has no Trust packets for each form of the offered
    /// stream.
    #[test]
    fn the_trust_packets_are_the_whole_difference() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Same <same@ostrya.example>");
        home.add_signing_subkey();
        let exported = home.export(false);
        let legacy = home.legacy_keyring();
        assert!(legacy.len() > exported.len());
        assert_eq!(certificate_stream(&legacy), exported);
        for offered in [&exported, &legacy] {
            let (imported, keyring) = merge_keyring(b"", offered, &[], SUBJECT).unwrap();
            assert_eq!(imported, 1);
            assert_eq!(keyring, exported);
        }
        // A selection from a legacy keyring also writes the selected
        // certificate without its Trust packets.
        let selector = [home.fingerprint()];
        let (imported, keyring) = merge_keyring(b"", &legacy, &selector, SUBJECT).unwrap();
        assert_eq!(imported, 1);
        assert_eq!(keyring, exported);
    }

    /// Inserts one packet immediately after the primary key packet of a
    /// certificate, the position of a key revocation signature.
    fn insert_after_primary(cert: &[u8], packet: &[u8]) -> Vec<u8> {
        let (spans, framed) = packet_spans(cert);
        assert_eq!(framed, cert.len());
        assert_eq!(spans[0].0, Tag::PublicKey);
        let at = spans[0].1.end;
        let mut spliced = cert[..at].to_vec();
        spliced.extend_from_slice(packet);
        spliced.extend_from_slice(&cert[at..]);
        spliced
    }

    /// A re-export with a key revocation replaces the certificate of that key
    /// in the keyring, and the import counts no key.
    ///
    /// The merge gets the keyring that the import of the `ostree` command
    /// leaves at the repository root, with the Trust packets. The merged
    /// keyring holds the offered certificate in the place of the held one. The
    /// `ostree` command writes the same shape. Measured against `ostree` 2026.1
    /// over the re-export of a revoked RSA key, the merged run had the key
    /// revocation immediately after the primary key packet. The revocation came
    /// before the first user id packet, and the `ostree` command reported
    /// `Imported 0 GPG keys`.
    #[test]
    fn a_revoked_re_export_replaces_the_held_certificate() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Revoked <revoked@ostrya.example>");
        let unrevoked = home.export(false);
        let held = home.legacy_keyring();
        home.revoke_primary();
        let revoked = home.export(false);
        // The fixture has the shape under test: the revoked export has the
        // revocation packet, and the unrevoked export does not.
        assert!(revoked.len() > unrevoked.len());

        let (imported, keyring) = merge_keyring(&held, &revoked, &[], SUBJECT).unwrap();
        assert_eq!(imported, 0);
        assert_ne!(keyring, certificate_stream(&held));
        // One certificate run for each key, with the offered packets.
        assert_eq!(keyring, revoked);
        // `gpg` reads the result, and its certificate revokes the key. The
        // `ostree` command uses this reader through gpgme.
        assert_eq!(home.fingerprints_of(&keyring), [home.fingerprint()]);
        let certs = GpgVerifier::from_keyring_bytes([&keyring]).unwrap().certs;
        assert_eq!(certs.len(), 1);
        assert!(verify::key_revoked(&certs[0], certs.as_slice()));

        // The Trust packets are still the only difference from the keyring
        // that GnuPG writes for the same two imports.
        let gnupg = home.imported_keyring("merged", &[&unrevoked, &revoked]);
        assert!(gnupg.len() > keyring.len());
        assert_eq!(certificate_stream(&gnupg), keyring);

        // One offered stream with both states of the key gives the same
        // keyring in either order, and counts one key. The `ostree` command
        // gives the same result. Over the revoked export alone, and over the
        // two exports concatenated in either order, `ostree` 2026.1 reported
        // `Imported 1 GPG key`. It wrote three byte-identical keyrings, each
        // with the revocation.
        for stream in [
            revoked.clone(),
            [unrevoked.clone(), revoked.clone()].concat(),
            [revoked.clone(), unrevoked.clone()].concat(),
        ] {
            let (imported, fresh) = merge_keyring(b"", &stream, &[], SUBJECT).unwrap();
            assert_eq!(imported, 1);
            assert_eq!(fresh, revoked);
        }
    }

    /// A key revocation signature by a different key, attached to an offered
    /// certificate, does not remove the held key from the keyring.
    ///
    /// The import verifies a revocation before it accepts it. So a packet that
    /// anyone can attach has no effect, and the keyring keeps its bytes. The
    /// verify engine applies the same rule to the same packet.
    #[test]
    fn a_stapled_revocation_does_not_replace_the_held_certificate() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Kept <kept@ostrya.example>");
        let other = KeyFixture::new("Other <other@ostrya.example>");
        let existing = home.export(false);
        let offered = insert_after_primary(&existing, &other.revocation_packet());

        // The attached packet gets into the parsed certificate. So the merge
        // refused it, and the parse did not.
        let certs = GpgVerifier::from_keyring_bytes([&offered]).unwrap().certs;
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].details.revocation_signatures.len(), 1);
        assert!(!verify::key_revoked(&certs[0], certs.as_slice()));

        let (imported, keyring) = merge_keyring(&existing, &offered, &[], SUBJECT).unwrap();
        assert_eq!(imported, 0);
        assert_eq!(keyring, existing);

        // The same packet on the certificate that it was made for replaces
        // that certificate.
        let own = other.export(false);
        let revoked = insert_after_primary(&own, &other.revocation_packet());
        let (imported, keyring) = merge_keyring(&own, &revoked, &[], SUBJECT).unwrap();
        assert_eq!(imported, 0);
        assert_eq!(keyring, revoked);
    }

    /// The certificate streams for a revocation by a designated revoker.
    ///
    /// The streams are:
    ///
    /// - A signing key K that designates a revoker R.
    /// - The certificate of R.
    /// - The re-export of K with the class 0x20 signature that R made over K.
    ///
    /// [`verify`] has its own builder for these states. It inserts a revocation
    /// into a certificate that has no designation. The import cases need no
    /// such state. So this builder makes each stream with `gpg` runs only, and
    /// the insertion stays in [`verify`].
    struct Revoked {
        /// The home of K. It made [`Revoked::blob`], and it reads each keyring
        /// that the cases build.
        home: KeyFixture,
        /// The primary key fingerprint of K, in uppercase hex.
        key: String,
        /// The primary key fingerprint of R, in uppercase hex.
        revoker: String,
        /// The certificate of R.
        revoker_cert: Vec<u8>,
        /// K with the designation and no revocation.
        designating: Vec<u8>,
        /// The re-export of K with the revocation that R made.
        revoked: Vec<u8>,
        /// The detached signature K made over [`PAYLOAD`].
        blob: Vec<u8>,
    }

    impl Revoked {
        fn build() -> Revoked {
            let home = KeyFixture::new("Signing K <k@ostrya.example>");
            let revoker_home = KeyFixture::new("Revoker R <r@ostrya.example>");
            let (key, revoker) = (home.fingerprint(), revoker_home.fingerprint());
            let blob = home.sign(PAYLOAD);
            let revoker_cert = revoker_home.export(false);
            // The designation names the revoker by fingerprint. So the home of
            // K holds the certificate of R when it writes the self-signature
            // with the designation.
            home.import(&revoker_cert);
            home.add_revoker(&revoker);
            let designating = home.export_one(&key);
            // The revocation is made in the home with the secret key of R and a
            // certificate of K that designates R.
            revoker_home.import(&designating);
            let revocation = revoker_home.desig_revoke(&key);
            // The re-export of K holds the class 0x20 signature that `gpg`
            // merges into the certificate of the home.
            home.import_merging(&revocation);
            let revoked = home.export_one(&key);
            let state = Revoked {
                home,
                key,
                revoker,
                revoker_cert,
                designating,
                revoked,
                blob,
            };
            state.assert_shape();
            state
        }

        /// Asserts that the streams have the state that the cases name.
        ///
        /// The re-export has one key revocation signature that the designating
        /// certificate does not have, and R made that revocation. So a case
        /// fails if its fixture does not have the state that it names.
        fn assert_shape(&self) {
            let designating = self.certs(&self.designating);
            assert_eq!(designating[0].details.revocation_signatures.len(), 0);
            let revoked = self.certs(&self.revoked);
            assert_eq!(revoked[0].details.revocation_signatures.len(), 1);
            let revoker = self.certs(&self.revoker_cert);
            assert!(!verify::key_revoked(&revoked[0], &designating));
            assert!(verify::key_revoked(&revoked[0], &revoker));
        }

        /// Returns the certificates of `keyring`.
        fn certs(&self, keyring: &[u8]) -> Vec<SignedPublicKey> {
            GpgVerifier::from_keyring_bytes([keyring])
                .unwrap()
                .certs
                .to_vec()
        }

        /// Returns the result of a verifier over `keyring` for the signature
        /// that K made.
        ///
        /// The result tells if the verifier reports the key as revoked, and if
        /// the load is valid.
        fn verdict(&self, keyring: &[u8]) -> (bool, bool) {
            let certs = self.certs(keyring);
            let outcome =
                verify::verify_signatures(&certs, PAYLOAD, std::slice::from_ref(&self.blob))
                    .unwrap();
            assert_eq!(outcome.signatures.len(), 1);
            (outcome.signatures[0].revoked, outcome.valid)
        }
    }

    /// A re-export with a key revocation by a designated revoker replaces the
    /// certificate of the revoked key in a keyring that holds the revoker.
    ///
    /// The import counts no key. A verifier over the result refuses a
    /// signature by the revoked key. The import looks for the revoker in the
    /// certificates of both streams. So the import and the verdict use the
    /// same signature for each key of one keyring.
    ///
    /// The `ostree` command also takes this revocation in. It merges the
    /// offered packets into its own keyblock. Measured against `ostree` 2026.1
    /// over a remote whose keyring held K and R:
    ///
    /// - The import of the re-export reported `Imported 0 GPG keys` at exit 0.
    /// - The keyring became longer by the class 0x20 packet.
    /// - `ostree show --gpg-verify-remote=origin` then reported `Key revoked`.
    #[test]
    fn a_designated_revokers_revocation_replaces_the_held_certificate() {
        if !gpg_or_skip() {
            return;
        }
        let state = Revoked::build();
        // The keyring that the import of the `ostree` command leaves at the
        // repository root, with the signing key and the revoker, in that order.
        let held = state
            .home
            .imported_keyring("held", &[&state.designating, &state.revoker_cert]);
        // Over the keyring before the merge, the signature is good. So the
        // merge changes the result.
        assert_eq!(state.verdict(&certificate_stream(&held)), (false, true));

        let (imported, keyring) = merge_keyring(&held, &state.revoked, &[], SUBJECT).unwrap();
        assert_eq!(imported, 0);
        // The revoked re-export is in the place of the held run, and the run
        // of the revoker does not change.
        assert_eq!(
            keyring,
            [&state.revoked[..], &state.revoker_cert[..]].concat()
        );
        // `gpg` reads the result, and both keys are in it. The `ostree`
        // command uses this reader through gpgme.
        assert_eq!(
            state.home.fingerprints_of(&keyring),
            [state.key.clone(), state.revoker.clone()]
        );
        assert_eq!(state.verdict(&keyring), (true, false));
    }

    /// The import also looks for the revoker in the offered stream.
    ///
    /// A stream with the revoked re-export and the certificate of the revoker
    /// revokes the key in a keyring. The result is the same with or without
    /// the revoker in the keyring. The count reports the revoker as the one
    /// added key.
    ///
    /// A `KEY-ID` selector controls what the import writes, and has no effect
    /// on what it knows. If the selector names only the revoked key, the
    /// revocation still gets in, and the certificate of the revoker is not
    /// written. So the keyring states the revocation, and no key in it
    /// identifies the revoker.
    ///
    /// The `ostree` command gives the same results for both selections.
    /// Measured against `ostree` 2026.1:
    ///
    /// - The import with no selector reported `Imported 1 GPG key`.
    ///   `ostree show --gpg-verify-remote=origin` then reported `Key revoked`.
    /// - The import that named the revoked key reported `Imported 0 GPG keys`,
    ///   wrote the class 0x20 packet into the keyring, and reported a good
    ///   signature.
    #[test]
    fn an_offered_revoker_certificate_resolves_the_revocation() {
        if !gpg_or_skip() {
            return;
        }
        let state = Revoked::build();
        let held = state.home.imported_keyring("held", &[&state.designating]);
        let offered = [&state.revoked[..], &state.revoker_cert[..]].concat();

        let (imported, keyring) = merge_keyring(&held, &offered, &[], SUBJECT).unwrap();
        assert_eq!(imported, 1);
        assert_eq!(
            keyring,
            [&state.revoked[..], &state.revoker_cert[..]].concat()
        );
        assert_eq!(state.verdict(&keyring), (true, false));

        // The selector names only the revoked key. The revocation gets in,
        // and the certificate of the revoker stays out. So the keyring holds
        // one key, and its revocation identifies no revoker.
        let (imported, keyring) =
            merge_keyring(&held, &offered, std::slice::from_ref(&state.key), SUBJECT).unwrap();
        assert_eq!(imported, 0);
        assert_eq!(keyring, state.revoked);
        assert_eq!(
            state.home.fingerprints_of(&keyring),
            std::slice::from_ref(&state.key)
        );
        assert_eq!(state.verdict(&keyring), (false, true));
    }

    /// With the wider set, the revoker of one key still cannot remove a
    /// different key from the keyring.
    ///
    /// R made a key revocation signature over the key K. The case attaches it
    /// to an offered certificate of a third key that also designates R. The
    /// keyring keeps its bytes. The designation resolves, and the certificate
    /// of R is in the keyring. So only the rule that the revocation must verify
    /// over its own key refuses it.
    #[test]
    fn a_revocation_over_another_key_strikes_out_no_held_key() {
        if !gpg_or_skip() {
            return;
        }
        let state = Revoked::build();
        let packet = revocation_packet_of(&state.revoked);
        // The packet is the revocation that R made. On a certificate of K,
        // with the certificate of R in the trusted set, it revokes K.
        let spliced = insert_after_primary(&state.designating, &packet);
        let revoker = state.certs(&state.revoker_cert);
        assert!(verify::key_revoked(&state.certs(&spliced)[0], &revoker));

        // A third key that also designates R as a revoker.
        let third = KeyFixture::new("Third <third@ostrya.example>");
        third.import(&state.revoker_cert);
        third.add_revoker(&state.revoker);
        let designating = third.export_one(&third.fingerprint());
        let stapled = insert_after_primary(&designating, &packet);
        // The attached packet gets into the parsed certificate. So the merge
        // refuses it, and the parse does not.
        assert_eq!(
            state.certs(&stapled)[0].details.revocation_signatures.len(),
            1
        );

        let held = third.imported_keyring("held", &[&designating, &state.revoker_cert]);
        let (imported, keyring) = merge_keyring(&held, &stapled, &[], SUBJECT).unwrap();
        assert_eq!(imported, 0);
        // No replacement applies, so the file keeps all its bytes. This
        // includes the Trust packets that the import of the `ostree` command
        // wrote.
        assert_eq!(keyring, held);
    }

    /// Returns `certs` as the set in which a designated revoker is looked up.
    /// [`merge_keyring`] gives this set to [`KeyState::over`] for its streams.
    fn known(certs: &[SignedPublicKey]) -> Vec<&SignedPublicKey> {
        certs.iter().collect()
    }

    /// Returns the key revocation signature packet of the certificate stream
    /// `cert`. `gpg --desig-revoke` writes it immediately after the primary key
    /// packet.
    fn revocation_packet_of(cert: &[u8]) -> Vec<u8> {
        let (spans, _) = packet_spans(cert);
        let span = spans
            .iter()
            .find(|(tag, _)| *tag == Tag::Signature)
            .expect("a signature packet in the certificate")
            .1
            .clone();
        cert[span].to_vec()
    }

    /// A re-export with a later key expiry replaces the certificate of that
    /// key in the keyring, and the import counts no key. The key in the
    /// keyring then verifies a signature that it made.
    ///
    /// The merge gets the keyring that the import of the `ostree` command
    /// leaves at the repository root, with the Trust packets. The merged
    /// keyring holds the offered certificate in the place of the held one.
    #[test]
    fn an_expiry_extension_replaces_the_held_certificate() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::expiring("Renew <renew@ostrya.example>", "1d");
        let blob = home.sign(PAYLOAD);
        let expiring = home.export(false);
        let held = home.legacy_keyring();
        home.set_expire_at("20250102T000000!", "10y");
        let extended = home.export(false);
        // The fixture has the shape under test. The held keyring states an
        // expiry in the past, so it refuses the signature. The offered
        // re-export states an expiry ten years in the future.
        assert_ne!(extended, expiring);
        assert!(
            !signature_is_valid(&held, &blob),
            "the held keyring must state an expiry that has passed"
        );

        let (imported, keyring) = merge_keyring(&held, &extended, &[], SUBJECT).unwrap();
        assert_eq!(imported, 0);
        assert_ne!(keyring, certificate_stream(&held));
        // One certificate run for each key, with the offered packets.
        assert_eq!(keyring, extended);
        // `gpg` reads the result, and its key is live again. The `ostree`
        // command uses this reader through gpgme.
        assert_eq!(home.fingerprints_of(&keyring), [home.fingerprint()]);
        assert!(
            signature_is_valid(&keyring, &blob),
            "the merged keyring must state the extended expiry"
        );

        // The keyring that GnuPG writes for the same two imports states the
        // same expiry, and has one more signature packet. The GnuPG merge keeps
        // the self-signature of the earlier export. The replacement writes
        // only the offered packets. Both keyrings report the key as live.
        let gnupg = home.imported_keyring("merged", &[&expiring, &extended]);
        let merged = certificate_stream(&gnupg);
        let signatures = |bytes: &[u8]| {
            packet_spans(bytes)
                .0
                .iter()
                .filter(|(tag, _)| *tag == Tag::Signature)
                .count()
        };
        assert_eq!(signatures(&keyring), 1, "the offered packets alone");
        assert_eq!(
            signatures(&merged),
            2,
            "GnuPG keeps the self-signature the earlier export carried"
        );
        assert!(signature_is_valid(&gnupg, &blob));
    }

    /// A keyring with one key in two certificates states the expiry of their
    /// newest self-signature. The verify path reads the same instant over the
    /// pair. So a re-export later than that instant replaces both runs.
    ///
    /// The two held certificates have different expiries, so the newest
    /// statement and the widest statement are different. The older one states
    /// ten years, and the newer one an instant in the past. The offered
    /// re-export states five years. This is later than the newest held
    /// statement and earlier than the widest.
    #[test]
    fn two_held_certificates_state_their_newest_expiry() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::expiring("Pair <pair@ostrya.example>", "10y");
        let blob = home.sign(PAYLOAD);
        let widest = home.export(false);
        home.set_expire_at("20250102T000000!", "1d");
        let newest = home.export(false);
        home.set_expire_at("20250103T000000!", "5y");
        let offered = home.export(false);
        let mut held = widest.clone();
        held.extend_from_slice(&newest);
        // The fixture has the shape under test: the pair reads as expired, so
        // the widest statement does not apply to it.
        assert!(
            !signature_is_valid(&held, &blob),
            "the pair must read as expired"
        );
        assert!(
            signature_is_valid(&widest, &blob),
            "the older certificate must state a lifetime that has not passed"
        );

        let (imported, keyring) = merge_keyring(&held, &offered, &[], SUBJECT).unwrap();
        assert_eq!(imported, 0);
        // If a keyring holds one key in two runs, the replacement applies to
        // both.
        assert_eq!(keyring, [&offered[..], &offered[..]].concat());
        assert!(
            signature_is_valid(&keyring, &blob),
            "the merged keyring must state the offered expiry"
        );
    }

    /// If an offered certificate states an expiry that is not later than the
    /// held expiry, the keyring keeps its bytes.
    ///
    /// The case has two directions: a shorter expiry over a longer held one,
    /// and an expiry over a held certificate that states no expiry.
    #[test]
    fn an_earlier_expiry_leaves_the_held_certificate() {
        if !gpg_or_skip() {
            return;
        }
        let long = KeyFixture::expiring("Long <long@ostrya.example>", "10y");
        let held = long.export(false);
        long.set_expire_at("20250102T000000!", "1d");
        let shortened = long.export(false);
        assert_ne!(shortened, held);
        let (imported, keyring) = merge_keyring(&held, &shortened, &[], SUBJECT).unwrap();
        assert_eq!(imported, 0);
        assert_eq!(keyring, held);

        let never = KeyFixture::expiring("Never <never@ostrya.example>", "never");
        let held = never.export(false);
        never.set_expire_at("20250102T000000!", "1d");
        let expiring = never.export(false);
        assert_ne!(expiring, held);
        let (imported, keyring) = merge_keyring(&held, &expiring, &[], SUBJECT).unwrap();
        assert_eq!(imported, 0);
        assert_eq!(keyring, held);
    }

    /// A held certificate that revokes its key takes no expiry replacement.
    ///
    /// A revocation is permanent. So if the offered certificate has no
    /// revocation, the keyring keeps the bytes that hold the revocation.
    #[test]
    fn a_revoked_key_takes_no_expiry_replacement() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::expiring("Struck <struck@ostrya.example>", "1d");
        // The held certificate revokes the key and states the shorter expiry.
        let held = insert_after_primary(&home.export(false), &home.revocation_packet());
        home.set_expire_at("20250102T000000!", "10y");
        let extended = home.export(false);
        // The fixture has the shape under test. The held certificate revokes
        // the key, and the offered one does not. The offered one states the
        // later expiry.
        let certs = GpgVerifier::from_keyring_bytes([&held]).unwrap().certs;
        assert_eq!(certs.len(), 1);
        let held_state = KeyState::over(&certs, &known(&certs));
        assert!(held_state.revoked);
        let offered = GpgVerifier::from_keyring_bytes([&extended]).unwrap().certs;
        let offered_state = KeyState::over(&offered, &known(&offered));
        assert!(!offered_state.revoked);
        assert!(states_later(offered_state.expires, held_state.expires));

        let (imported, keyring) = merge_keyring(&held, &extended, &[], SUBJECT).unwrap();
        assert_eq!(imported, 0);
        assert_eq!(keyring, held);
    }

    /// A keyring with bytes after its last framed packet takes no import.
    ///
    /// The merge reads the keyring of the repository with the reader of a
    /// verification load. So the refusal names the keyring, and the merge
    /// writes no keyring.
    ///
    /// The refusal applies for each content of the offered stream. The case
    /// offers a revocation for the key in the keyring, which a replacement
    /// writes in the place of the held run. It also offers a certificate for a
    /// key that the keyring does not hold, which an append writes after the
    /// held bytes.
    ///
    /// These results are measured over the same shape: one exported ed25519
    /// certificate with one `0xff` byte appended.
    ///
    /// - `gpgv` 2.4.9 reports `[don't know]: 1st length byte missing`,
    ///   `keyring_get_keyblock: read error: Invalid packet`,
    ///   `keydb_search failed: Invalid keyring`, `ERRSIG`, and `NO_PUBKEY` at
    ///   exit 2 over a signature by that key.
    /// - `gpg --list-keys` over the file lists no key.
    /// - `ostree show --gpg-verify-remote` reports
    ///   `Can't check signature: public key not found`.
    ///
    /// No implementation trusts a key from a file of that shape.
    #[test]
    fn an_unframeable_keyring_takes_no_import() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Tailed <tailed@ostrya.example>");
        let added = KeyFixture::new("Added <added@ostrya.example>");
        let unrevoked = home.export(false);
        home.revoke_primary();
        let revoked = home.export(false);
        let mut held = unrevoked.clone();
        held.push(0xff);
        // The fixture has the shape under test: the walk frames the export and
        // stops at the trailing byte, so the run split returns nothing.
        assert_eq!(packet_spans(&held).1, unrevoked.len());
        assert!(matches!(certificate_chunks(&held), Chunks::Unframed));

        for offered in [&revoked, &added.export(false)] {
            let refusal = merge_keyring(&held, offered, &[], SUBJECT).unwrap_err();
            let text = refusal.to_string();
            assert!(text.contains(SUBJECT), "{text}");
            assert!(text.contains("OpenPGP keyring"), "{text}");
        }
    }

    /// Each selector form takes the key that it names from the offered stream.
    ///
    /// The forms are:
    ///
    /// - A fingerprint: plain, with a `0x` prefix, and with spaces.
    /// - A long and a short key id.
    /// - A subkey fingerprint.
    /// - A user id substring in a different case.
    #[test]
    fn a_selector_takes_the_key_it_names() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Wanted <wanted@ostrya.example>");
        home.add_signing_subkey();
        home.add_key("Other <other@ostrya.example>");
        let primary = home.fingerprint();
        let wanted = home.export_one(&primary);
        let offered = home.export(false);
        assert!(offered.len() > wanted.len());
        let subkey = {
            let verifier = GpgVerifier::from_keyring_bytes([&wanted]).unwrap();
            format!("{:X}", verifier.certs[0].public_subkeys[0].fingerprint())
        };
        let spaced = primary
            .as_bytes()
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join(" ");

        for selector in [
            primary.clone(),
            format!("0x{primary}"),
            spaced,
            primary[24..].to_owned(),
            primary[32..].to_owned(),
            subkey,
            "wanted".to_owned(),
            "WANTED@ostrya".to_owned(),
            "Wanted <wanted@ostrya.example>".to_owned(),
        ] {
            let (imported, keyring) =
                merge_keyring(b"", &offered, std::slice::from_ref(&selector), SUBJECT).unwrap();
            assert_eq!(imported, 1, "the selector '{selector}' took no key");
            assert_eq!(
                keyring, wanted,
                "the selector '{selector}' took another key"
            );
        }

        // Two selectors take two keys. One selector that matches both user
        // ids takes both keys.
        let both = [primary.clone(), "other".to_owned()];
        assert_eq!(merge_keyring(b"", &offered, &both, SUBJECT).unwrap().0, 2);
        let shared = ["ostrya.example".to_owned()];
        assert_eq!(merge_keyring(b"", &offered, &shared, SUBJECT).unwrap().0, 2);
    }

    /// The import refuses a selector that names no offered key by name, and
    /// the keyring does not change.
    ///
    /// A hex selector names only a key, and is not a user id substring.
    /// `gpg --export` reads a hex selector in the same way.
    #[test]
    fn a_selector_naming_nothing_is_refused() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("DEADBEEF Person <hex@ostrya.example>");
        let offered = home.export(false);
        for selector in ["nomatch", "0000000000000000", "DEADBEEF", "", "  "] {
            let err = merge_keyring(b"", &offered, &[selector.to_owned()], SUBJECT).unwrap_err();
            assert!(
                matches!(&err, Error::Signature(m)
                    if m == &format!("no key matching '{selector}' among the keys to import")),
                "{err}"
            );
        }
        // The name of the person is a user id substring and takes the key.
        let taken = ["DEADBEEF Person".to_owned()];
        assert_eq!(merge_keyring(b"", &offered, &taken, SUBJECT).unwrap().0, 1);
    }

    /// If `gpg --export` reads a selector as a user id substring, this crate
    /// also does not read it as a key selector. So a shape that the key reader
    /// does not accept names no key.
    ///
    /// Each row was measured against `gpg --export -- <selector>` on
    /// `gpg` 2.4.9. No row exports the key that the hex names.
    #[test]
    fn a_selector_the_key_reader_does_not_carry_names_nothing() {
        if !gpg_or_skip() {
            return;
        }
        // The user id holds a word with a `0x` prefix. So if the read takes a
        // `0x` selector that is not a key as a user id substring, the selector
        // takes this key.
        let home = KeyFixture::new("Narrow 0xnope <narrow@ostrya.example>");
        let offered = home.export(false);
        let primary = home.fingerprint();
        let group = |width: usize| -> String {
            primary
                .as_bytes()
                .chunks(width)
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        };
        // The same fingerprint in ten groups of different widths.
        let uneven = format!(
            "{} {} {}",
            &primary[..3],
            &primary[3..8],
            group(4)[10..].to_owned()
        );
        // These rows check five rules:
        // - Only the lower-case `0x` prefix counts, and it names a key or
        //   nothing.
        // - A key id has no interior space.
        // - The one shape with spaces is a printed v4 fingerprint, ten groups
        //   of four.
        // - An interior tab is not a space.
        // - `0x` accepts no space.
        let narrowed = [
            format!("0X{primary}"),
            format!("0X{}", &primary[32..]),
            format!("{} {}", &primary[24..32], &primary[32..]),
            format!("{} {}", &primary[32..36], &primary[36..]),
            group(2),
            uneven,
            primary.replace(&primary[20..21], &format!("\t{}", &primary[20..21])),
            format!("0x{}", group(4)),
            format!("0x{}", &primary[..7]),
            "0xnope".to_owned(),
        ];
        for selector in narrowed {
            let err =
                merge_keyring(b"", &offered, std::slice::from_ref(&selector), SUBJECT).unwrap_err();
            assert!(
                matches!(&err, Error::Signature(m)
                    if m == &format!("no key matching '{selector}' among the keys to import")),
                "the selector '{selector}' took a key: {err}"
            );
            // The reference: the export of the selector through `gpg` is empty.
            let out = home
                .gpg()
                .arg("--export")
                .arg("--")
                .arg(&selector)
                .output()
                .unwrap();
            assert!(
                out.stdout.is_empty(),
                "gpg --export took a key for '{selector}'"
            );
        }
        // The forms that the reader accepts still take the key: a printed
        // fingerprint in its ten groups of four, and both hex cases. The read
        // drops spaces before and after the selector.
        for selector in [group(4), format!(" {} ", primary.to_lowercase())] {
            assert_eq!(
                merge_keyring(b"", &offered, std::slice::from_ref(&selector), SUBJECT)
                    .unwrap()
                    .0,
                1,
                "the selector '{selector}' took no key"
            );
        }
    }

    /// The user id search ignores case for ASCII letters only, as `gpg` does.
    /// Over the user id `Ärger`, `ÄRGER` takes the key and `ärger` takes none.
    #[test]
    fn a_user_id_selector_folds_ascii_case_alone() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Umlaut Ärger <umlaut@ostrya.example>");
        let offered = home.export(false);
        for selector in ["Ärger", "ÄRGER", "ärgER"] {
            let taken = merge_keyring(b"", &offered, &[selector.to_owned()], SUBJECT)
                .map(|(count, _)| count);
            let exported = !home
                .gpg()
                .arg("--export")
                .arg("--")
                .arg(selector)
                .output()
                .unwrap()
                .stdout
                .is_empty();
            assert_eq!(
                taken.is_ok(),
                exported,
                "the selector '{selector}' parts from gpg --export"
            );
        }
    }

    /// The import refuses a stream with no certificate, a stream that the
    /// packet walk cannot frame to its end, and a keybox. The keyring does not
    /// change. The `ostree` command also refuses all three.
    #[test]
    fn an_unreadable_offered_stream_is_refused() {
        let empty = merge_keyring(b"", b"", &[], SUBJECT).unwrap_err();
        assert!(
            matches!(&empty, Error::Signature(m) if m.contains("no OpenPGP certificate")),
            "{empty}"
        );
        let oversized = vec![0u8; MAX_KEYRING as usize + 1];
        let err = merge_keyring(b"", &oversized, &[], SUBJECT).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("ceiling")),
            "{err}"
        );
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Cut <cut@ostrya.example>");
        let offered = home.export(false);
        let cut = &offered[..offered.len() - 1];
        let err = merge_keyring(b"", cut, &[], SUBJECT).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("OpenPGP keyring")),
            "{err}"
        );
        let err = merge_keyring(b"", &home.keybox(), &[], SUBJECT).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("keybox")),
            "{err}"
        );
        // A keyring holds transferable public keys, so a secret-key export
        // holds none. The `ostree` command takes the public part of such a
        // stream. This is a divergence.
        let err = merge_keyring(b"", &home.export_secret(), &[], SUBJECT).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("no OpenPGP certificate")),
            "{err}"
        );
        // The certificate limit also applies to an offered stream. The import
        // refuses 257 by name, and takes 256.
        let many = offered.repeat(MAX_KEYRING_CERTS + 1);
        assert!(many.len() as u64 <= MAX_KEYRING);
        let err = merge_keyring(b"", &many, &[], SUBJECT).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("the keyring to import")
                && m.contains("256 certificates")),
            "{err}"
        );
        let allowed = offered.repeat(MAX_KEYRING_CERTS);
        assert_eq!(merge_keyring(b"", &allowed, &[], SUBJECT).unwrap().0, 1);
    }

    /// The listing reports the same data as `gpg` over the same keyring: the
    /// fingerprint, the creation time, and the user ids in listing order. A
    /// keyring with no key gives an empty list.
    #[test]
    fn the_listing_agrees_with_gpg() {
        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Listed <listed@ostrya.example>");
        home.add_uid("Second <second@ostrya.example>");
        home.add_signing_subkey();
        home.add_key("Another <another@ostrya.example>");

        // The reference: the `pub`, `fpr`, and `uid` records of the
        // machine-readable listing of `gpg`, one record set for each primary
        // key.
        let listing = home.listing();
        let mut reference: Vec<GpgKey> = Vec::new();
        let mut in_subkey = false;
        for line in listing.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            match fields[0] {
                "pub" => {
                    in_subkey = false;
                    reference.push(GpgKey {
                        fingerprint: String::new(),
                        created: parse_epoch(fields[5]),
                        user_ids: Vec::new(),
                    });
                }
                "sub" => in_subkey = true,
                "fpr" if !in_subkey => {
                    let key = reference.last_mut().unwrap();
                    if key.fingerprint.is_empty() {
                        key.fingerprint = fields[9].to_owned();
                    }
                }
                "uid" => reference
                    .last_mut()
                    .unwrap()
                    .user_ids
                    .push(fields[9].to_owned()),
                _ => {}
            }
        }
        assert_eq!(reference.len(), 2);
        assert_eq!(reference[0].user_ids.len(), 2);

        for keyring in [home.export(false), home.legacy_keyring()] {
            assert_eq!(gpg_keyring_keys(&keyring, SUBJECT).unwrap(), reference);
        }
        assert!(gpg_keyring_keys(b"", SUBJECT).unwrap().is_empty());
    }
}
