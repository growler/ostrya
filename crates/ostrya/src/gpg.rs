//! GPG (OpenPGP) commit-signing engine (Phase 13d).
//!
//! Behind the `verify-gpg` feature: keyrings are parsed, signatures are
//! verified, and a remote's trusted keyring is managed in the process with the
//! `pgp` crate (rPGP). The `sign-gpg` feature adds signing through
//! `gpg --detach-sign` and turns on `verify-gpg` with it. That signing run is a
//! short-lived subprocess through [`ostrya_rt::Command`], and it is the one
//! `gpg` run the library makes. The private key stays with GnuPG and its agent
//! and never passes through the library.
//!
//! Format (`format-reference.md`, "Signing details -- GPG"):
//!
//! - The `ostree.gpgsigs` value is an `aay`; each `ay` element is one detached
//!   OpenPGP signature (the binary signature packet stream, unarmored). A blob
//!   may hold more than one signature packet.
//! - The signed payload is the same commit bytes as the other engines.
//!
//! [`GpgSigner`] addresses its key the way the `gpg` binary does: a
//! fingerprint, key id, or user id resolved in a GnuPG home directory
//! (`--local-user`, with an optional `--homedir` override). `gpg` performs
//! the private-key operation itself, consulting its `gpg-agent` -- and any
//! hardware token behind it -- as needed.
//!
//! [`GpgVerifier`] holds the certificates its keyrings parse to. Keyrings are
//! loaded through [`from_keyring_bytes`](GpgVerifier::from_keyring_bytes) and
//! [`from_keyring_files`](GpgVerifier::from_keyring_files) (armored input is
//! decoded to the binary packet stream the parser reads, and Trust packets are
//! dropped from that stream, so a legacy GnuPG keyring and the `gpg --export`
//! stream of the same keys parse to the same certificates).
//! [`from_system_trust`](GpgVerifier::from_system_trust) loads the global
//! trusted set -- every `*.gpg` keyring in the directory named by the
//! `OSTREE_GPG_HOME` environment variable, or `<datadir>/ostree/trusted.gpg.d/`
//! when it is unset. [`for_remote`](GpgVerifier::for_remote) adds the
//! per-remote keyring (`<remote>.trustedkeys.gpg` in the repo or under
//! `/etc/ostree/remotes.d/`) on top of that global set, and
//! [`for_remote_keyrings`](GpgVerifier::for_remote_keyrings) takes the
//! repository's keyring as bytes and adds the keyrings a remote's `gpgkeypath`
//! names, which is what a pull trusts. Every keyring file reaches the trusted
//! set through one reader: only a regular file is read, and only up to four
//! mebibytes, so a path naming a fifo and a keyring over that ceiling are each
//! refused by that path's own name.
//!
//! A keyring is untrusted input, so its load is bounded and its parse is
//! contained. The four-mebibyte ceiling holds over a keyring supplied as bytes
//! as well, and one keyring holds at most 256 certificates; each refusal names
//! the cap it reached. A GnuPG keybox, which carries the `KBXf` magic, is
//! refused by the name of the file or the blob that holds it, since rPGP reads
//! OpenPGP packet streams and a keybox is a container of another kind. A
//! keyring the parser rejects fails the load, so the trusted set a
//! verification works over is one that was read whole.
//!
//! Verification reads the stored blobs and the loaded certificates and answers
//! in the process, on the blocking pool. The `verify` module holds the engine,
//! the trust and validity policy it applies, and the input caps a stored blob
//! is held to. No process is spawned and no scratch directory is written.
//!
//! A remote's own trusted keyring is managed in the process:
//! [`Repo::gpg_import_keys`] adds certificates to `<remote>.trustedkeys.gpg`
//! and reports how many the keyring did not already hold, and
//! [`Repo::gpg_list_keys`] reads back the keys it holds as
//! [`GpgKey`] records. The keyring the import writes keeps the packet stream it
//! already held and carries the packets of each added certificate as the
//! offered stream wrote them, with the Trust packets dropped. The keyring is
//! written in the binary form, so an armored keyring keeps its packets and
//! loses its armor. `gpg` and the `ostree` tool both read a keyring of that
//! form. A certificate for a key the keyring already holds is left as the
//! keyring holds it, so an updated certificate reaches the keyring through
//! [`Repo::remove_remote_keyring`] and a fresh import. A keyring offered for
//! import is untrusted input and is held to the same caps and the same
//! containment a keyring loaded for verification is, and a stream the
//! certificate parser does not read fails the import, which leaves the keyring
//! as it was.
//!
//! A signature is valid only where it verifies against a trusted key whose
//! bindings hold and which is neither expired nor revoked. An expired key, a
//! revoked key, a bad signature, and an absent key are each reported per
//! signature in [`SignatureInfo`](crate::sign::SignatureInfo). Trust is
//! membership in the verifier's keyrings; GnuPG's ownertrust model plays no
//! part.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::ops::Range;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use ostrya_core::base64;
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::packet::PacketHeader;
use pgp::types::{KeyDetails, PacketLength, Tag};

use crate::config::remote_keyring_name;
use crate::error::{Error, Result};
use crate::repo::Repo;
#[cfg(feature = "sign-gpg")]
use crate::sign::{SignFuture, Signer};
use crate::sign::{Verifier, VerifyFuture, VerifyOutcome, read_key_path, read_key_source};

mod verify;

/// The GPG engine's short name.
#[cfg(feature = "sign-gpg")]
const GPG_SIGN_TYPE: &str = "gpg";
/// The GPG engine's detached-metadata dict key. Unlike the sign-api engines,
/// GPG signatures live under `ostree.gpgsigs`, not `ostree.sign.<type>`.
const GPG_METADATA_KEY: &str = "ostree.gpgsigs";
/// The system directory holding keyrings trusted for every remote.
const GLOBAL_TRUSTED_GPG_D: &str = "/usr/share/ostree/trusted.gpg.d";
/// The environment variable that overrides the global trusted-keyring
/// directory, as the `ostree` tool honors it.
const OSTREE_GPG_HOME_ENV: &str = "OSTREE_GPG_HOME";
/// The system directory holding per-remote configuration and keyrings.
const SYSTEM_REMOTES_D: &str = "/etc/ostree/remotes.d";
/// The prefix of a machine-readable status line on the status fd.
#[cfg(any(feature = "sign-gpg", test))]
const STATUS_PREFIX: &str = "[GNUPG:] ";
/// The ceiling on one keyring file, whose whole content is read into memory.
/// One exported ed25519 certificate is a few hundred bytes, so four mebibytes
/// holds thousands of them, and a remote's trusted set is a handful.
pub(crate) const MAX_KEYRING: u64 = 4 * 1024 * 1024;
/// The ceiling on the certificates one keyring may hold. A remote's trusted
/// set is a handful of certificates, and the ceiling bounds the work a keyring
/// from a remote or from `trusted.gpg.d` can ask the parser for.
const MAX_KEYRING_CERTS: usize = 256;
/// The magic a GnuPG keybox carries, and the offset it stands at. A keybox
/// opens with a header blob: a four-byte length, a one-byte blob type, a
/// one-byte version, and two bytes of flags stand before the magic.
const KEYBOX_MAGIC: &[u8] = b"KBXf";
const KEYBOX_MAGIC_OFFSET: usize = 8;

/// The GPG commit-signing engine.
///
/// Holds the key selector `gpg --local-user` resolves -- a fingerprint, a key
/// id, or a user id -- and an optional GnuPG home directory. Signing runs
/// `gpg --detach-sign` with the payload on stdin and reads the binary
/// signature from stdout.
#[cfg(feature = "sign-gpg")]
#[derive(Debug, Clone)]
pub struct GpgSigner {
    key: String,
    homedir: Option<PathBuf>,
}

#[cfg(feature = "sign-gpg")]
impl GpgSigner {
    /// A signer for the key `gpg` resolves from `key` (a fingerprint, key id,
    /// or user id) in the default GnuPG home directory.
    pub fn new(key: impl Into<String>) -> GpgSigner {
        GpgSigner {
            key: key.into(),
            homedir: None,
        }
    }

    /// Resolve the signing key in `dir` instead of the default GnuPG home
    /// directory.
    pub fn with_homedir(mut self, dir: impl Into<PathBuf>) -> GpgSigner {
        self.homedir = Some(dir.into());
        self
    }

    /// The GnuPG home directory this signer resolves its key in, or `None` for
    /// gpg's own default.
    pub fn homedir(&self) -> Option<&Path> {
        self.homedir.as_deref()
    }

    /// The fingerprints of the secret keys `gpg` resolves this signer's
    /// selector to, in listing order.
    ///
    /// Runs `gpg --list-secret-keys` over the selector, which reports the keys
    /// without touching the private material or starting a signing operation. A
    /// home directory that does not exist, one that cannot be read, and one
    /// holding no matching key all answer an empty list, so a caller reports one
    /// "no such key" refusal for the three. More than one fingerprint means the
    /// selector names more than one key and a caller that needs a single signing
    /// key refuses it.
    ///
    /// The selector stands after `--`, so gpg reads it as a key name alone.
    /// Without the terminator gpg reads an option-shaped selector as one of its
    /// own options, and a selector such as `--homedir=<path>` moves the lookup
    /// to another home directory and creates a keybox and a trust database
    /// there.
    pub async fn secret_key_fingerprints(&self) -> Result<Vec<String>> {
        let mut cmd = ostrya_rt::Command::new("gpg");
        if let Some(dir) = &self.homedir {
            cmd.arg("--homedir").arg(dir);
        }
        cmd.arg("--batch")
            .arg("--with-colons")
            .arg("--list-secret-keys")
            .arg("--")
            .arg(&self.key);
        let output = cmd.output(&[]).await.map_err(|e| spawn_err("gpg", &e))?;
        if !output.status.success() {
            return Ok(Vec::new());
        }
        Ok(primary_fingerprints(&output.stdout))
    }
}

/// The primary-key fingerprints in a `--with-colons` secret-key listing, in
/// listing order.
///
/// Each `sec` record opens one key and the `fpr` record that follows it carries
/// that key's fingerprint in field ten. A `ssb` record opens a subkey, whose own
/// `fpr` record names the subkey and is skipped.
#[cfg(feature = "sign-gpg")]
fn primary_fingerprints(listing: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let mut wanted = false;
    for line in listing.split(|&b| b == b'\n') {
        let mut fields = line.split(|&b| b == b':');
        match fields.next() {
            Some(b"sec") => wanted = true,
            Some(b"fpr") if wanted => {
                wanted = false;
                if let Some(fpr) = fields.nth(8)
                    && let Ok(text) = std::str::from_utf8(fpr)
                    && !text.is_empty()
                {
                    found.push(text.to_owned());
                }
            }
            Some(b"ssb") => wanted = false,
            _ => {}
        }
    }
    found
}

#[cfg(feature = "sign-gpg")]
impl Signer for GpgSigner {
    fn name(&self) -> &str {
        GPG_SIGN_TYPE
    }

    fn metadata_key(&self) -> &str {
        GPG_METADATA_KEY
    }

    fn sign<'a>(&'a self, data: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async move {
            let mut cmd = ostrya_rt::Command::new("gpg");
            if let Some(dir) = &self.homedir {
                cmd.arg("--homedir").arg(dir);
            }
            cmd.arg("--batch")
                .arg("--status-fd")
                .arg("2")
                .arg("--detach-sign")
                .arg("--local-user")
                .arg(&self.key);
            let output = cmd.output(data).await.map_err(|e| spawn_err("gpg", &e))?;
            if !output.status.success() || output.stdout.is_empty() {
                return Err(Error::Signature(format!(
                    "gpg --detach-sign failed: {}",
                    failure_text(&output)
                )));
            }
            Ok(output.stdout)
        })
    }
}

/// The GPG commit-verifying engine, holding the trusted certificates its
/// keyrings parse to.
#[derive(Debug, Clone, Default)]
pub struct GpgVerifier {
    /// The certificates the loaded keyrings hold, in load order. The parse
    /// happens as a keyring is loaded, so a keyring the parser rejects fails
    /// the load rather than a verification made over it.
    ///
    /// A key the sources hold several certificates for keeps every one of
    /// them here. The verdict reads all the certificates that answer for a
    /// signature's issuer, so a revocation any of them carries refuses the
    /// signature whatever order the sources loaded in.
    certs: Vec<SignedPublicKey>,
}

impl GpgVerifier {
    /// Build a verifier trusting every certificate in the given keyring
    /// blobs. Each blob is a binary or ASCII-armored OpenPGP keyring and may
    /// hold several certificates; armored input is decoded to the binary
    /// form, and all blobs merge into one trusted set.
    ///
    /// Each blob is held to four mebibytes and to 256 certificates, and a blob
    /// carrying a GnuPG keybox is refused. A refusal names the blob by its
    /// position in the sequence and states the cap it reached.
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

    /// Build a verifier from keyring files on disk (binary or armored). A
    /// missing file is skipped rather than an error, so an absent optional
    /// keyring does not fail the build. Only a regular file is read, and only
    /// up to four mebibytes; a path of another kind and a keyring over that
    /// ceiling are each refused by the path's own name.
    pub fn from_keyring_files<I, P>(paths: I) -> Result<GpgVerifier>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut verifier = GpgVerifier::default();
        verifier.add_keyring_files(paths)?;
        Ok(verifier)
    }

    /// Build a verifier from the keyrings trusted for `remote` in the
    /// repository at `repo_path`: `<remote>.trustedkeys.gpg` in the repository
    /// and under `/etc/ostree/remotes.d/`, plus the global trusted set
    /// (see [`from_system_trust`](GpgVerifier::from_system_trust)). Missing
    /// paths are skipped.
    pub fn for_remote(repo_path: &Path, remote: &str) -> Result<GpgVerifier> {
        let keyring = repo_path.join(format!("{remote}.trustedkeys.gpg"));
        let repo_keyring = read_keyring_path(&keyring)?;
        GpgVerifier::for_remote_keyrings(repo_keyring, remote, &[])
    }

    /// Build a verifier from a remote's whole trusted set, with the
    /// repository's own keyring supplied as bytes.
    ///
    /// `repo_keyring` is the repository's `<remote>.trustedkeys.gpg`, which a
    /// caller holding a descriptor rather than a path reads for itself. On top
    /// of it come the system per-remote keyring
    /// (`/etc/ostree/remotes.d/<remote>.trustedkeys.gpg`), the global trusted
    /// set (see [`from_system_trust`](GpgVerifier::from_system_trust)), and
    /// every entry of `keypath`, which is what a remote's `gpgkeypath` names.
    ///
    /// A `keypath` entry is a keyring file or a directory of `*.gpg` keyrings,
    /// and an entry that names neither fails the build, so a keyring path that
    /// has gone missing is reported rather than silently reducing the trusted
    /// set. The other sources are optional and a missing one is skipped.
    pub fn for_remote_keyrings(
        repo_keyring: Option<Vec<u8>>,
        remote: &str,
        keypath: &[String],
    ) -> Result<GpgVerifier> {
        let mut paths: Vec<PathBuf> = Vec::new();
        paths.push(Path::new(SYSTEM_REMOTES_D).join(format!("{remote}.trustedkeys.gpg")));
        paths.extend(keyring_files_in(&global_trusted_dir())?);
        for entry in keypath {
            let path = Path::new(entry);
            let meta = std::fs::metadata(path).map_err(|e| {
                Error::Signature(format!("gpgkeypath entry '{entry}' cannot be read: {e}"))
            })?;
            if meta.is_dir() {
                paths.extend(keyring_files_in(path)?);
            } else {
                paths.push(path.to_owned());
            }
        }
        let mut verifier = GpgVerifier::default();
        if let Some(bytes) = repo_keyring {
            verifier.add_keyring(&bytes, &format!("the keyring '{remote}.trustedkeys.gpg'"))?;
        }
        verifier.add_keyring_files(paths)?;
        Ok(verifier)
    }

    /// Build a verifier from the global trusted keyrings alone: every `*.gpg`
    /// keyring in the directory named by the `OSTREE_GPG_HOME` environment
    /// variable, or, when that variable is unset or empty, the system
    /// `/usr/share/ostree/trusted.gpg.d/` directory. No per-remote keyring
    /// participates. This is the trust applied to a commit named with no
    /// remote. A missing directory yields an empty trusted set.
    pub fn from_system_trust() -> Result<GpgVerifier> {
        GpgVerifier::from_keyring_files(keyring_files_in(&global_trusted_dir())?)
    }

    /// Add every keyring `paths` names to the trusted set, in the order given.
    /// A path naming no file is skipped.
    fn add_keyring_files<I, P>(&mut self, paths: I) -> Result<()>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        for path in paths {
            let path = path.as_ref();
            if let Some(bytes) = read_keyring_path(path)? {
                self.add_keyring(&bytes, &format!("the keyring '{}'", path.display()))?;
            }
        }
        Ok(())
    }

    /// Add one keyring to the trusted set: decode armor, hold the blob to the
    /// input caps, refuse a keybox, and parse the certificates it carries.
    /// `subject` names the source, so a refusal states which keyring reached
    /// which cap.
    fn add_keyring(&mut self, bytes: &[u8], subject: &str) -> Result<()> {
        let binary = keyring_stream(bytes, subject)?;
        self.certs.extend(parse_keyring(&binary, subject)?);
        Ok(())
    }
}

/// The binary packet stream one keyring blob carries: armor decoded, the blob
/// held to [`MAX_KEYRING`], and a GnuPG keybox refused. `subject` names the
/// source, so a refusal states which keyring reached which cap.
fn keyring_stream(bytes: &[u8], subject: &str) -> Result<Vec<u8>> {
    if bytes.len() as u64 > MAX_KEYRING {
        return Err(Error::Signature(format!(
            "{subject} is over the {MAX_KEYRING}-byte ceiling"
        )));
    }
    let binary = dearmor(bytes)?;
    if binary.len() >= KEYBOX_MAGIC_OFFSET + KEYBOX_MAGIC.len()
        && &binary[KEYBOX_MAGIC_OFFSET..KEYBOX_MAGIC_OFFSET + KEYBOX_MAGIC.len()] == KEYBOX_MAGIC
    {
        return Err(Error::Signature(format!(
            "{subject} is a GnuPG keybox, and a keyring is read as an OpenPGP \
             packet stream"
        )));
    }
    Ok(binary)
}

/// The packet stream of `binary` with every Trust packet removed.
///
/// A Trust packet (tag 12) holds a GnuPG-local trust value and carries no part
/// of a transferable public key. A legacy GnuPG keyring writes one after the
/// primary key packet, after each user id packet, and after each signature
/// packet. rPGP's certificate parser reads the packets of one certificate
/// through runs of tag tests, and a packet of any other tag ends a run, so a
/// Trust packet standing after the primary key leaves the certificate with no
/// user id and no subkey. With the Trust packets gone, a legacy keyring parses
/// to the certificates the `gpg --export` form of the same keys parses to.
///
/// The walk frames each packet with [`packet_spans`], and the bytes past the
/// framed prefix pass through as they stand. The result is at most as long as
/// the input, which [`keyring_stream`] has already held to [`MAX_KEYRING`].
fn without_trust_packets(binary: &[u8]) -> Vec<u8> {
    let (spans, framed) = packet_spans(binary);
    let mut kept: Vec<u8> = Vec::with_capacity(binary.len());
    for (tag, span) in spans {
        if tag != Tag::Trust {
            kept.extend_from_slice(&binary[span]);
        }
    }
    kept.extend_from_slice(&binary[framed..]);
    kept
}

/// The packets a binary OpenPGP stream carries, each as its tag and the byte
/// range it occupies, together with the length of the prefix that framed.
///
/// The walk frames each packet with rPGP's own header parser, which is the
/// parser the packet stream is read with, so a packet boundary here is a packet
/// boundary there. A header the parser refuses, a length form other than a
/// fixed one, and a length that runs past the end each stop the walk, and the
/// reported prefix length then falls short of the input.
fn packet_spans(binary: &[u8]) -> (Vec<(Tag, Range<usize>)>, usize) {
    let mut spans: Vec<(Tag, Range<usize>)> = Vec::new();
    let mut at = 0usize;
    while at < binary.len() {
        let rest = &binary[at..];
        let mut reader = rest;
        let Ok(header) = PacketHeader::try_from_reader(&mut reader) else {
            break;
        };
        let PacketLength::Fixed(body) = header.packet_length() else {
            break;
        };
        let total = (rest.len() - reader.len()).saturating_add(body as usize);
        if total == 0 || total > rest.len() {
            break;
        }
        spans.push((header.tag(), at..at + total));
        at += total;
    }
    (spans, at)
}

/// The certificates a binary keyring stream carries, each as the packets of one
/// transferable public key with the Trust packets dropped.
///
/// A Public-Key packet opens a certificate and every packet up to the next one
/// belongs to it. A packet standing before the first Public-Key packet belongs
/// to no certificate and is dropped. `None` where the packet stream does not
/// frame to its end, which is what a truncated keyring reaches, and which the
/// `ostree` tool refuses as well.
fn certificate_chunks(binary: &[u8]) -> Option<Vec<Vec<u8>>> {
    let (spans, framed) = packet_spans(binary);
    if framed != binary.len() {
        return None;
    }
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    for (tag, span) in spans {
        match tag {
            Tag::Trust => {}
            Tag::PublicKey => chunks.push(binary[span].to_vec()),
            _ => {
                if let Some(chunk) = chunks.last_mut() {
                    chunk.extend_from_slice(&binary[span]);
                }
            }
        }
    }
    Some(chunks)
}

/// Parse a binary OpenPGP keyring into the certificates it carries, holding
/// the result to [`MAX_KEYRING_CERTS`]. A keyring carrying no packet parses to
/// no certificate. Trust packets are dropped first (see
/// [`without_trust_packets`]), so a legacy GnuPG keyring and a `gpg --export`
/// stream of the same keys parse to the same certificates.
///
/// The parse runs inside [`contained`], since a keyring is untrusted input.
fn parse_keyring(binary: &[u8], subject: &str) -> Result<Vec<SignedPublicKey>> {
    let refusal = format!("{subject} is not readable as an OpenPGP keyring: the parser panicked");
    contained(&refusal, || {
        let refuse = |e: pgp::errors::Error| {
            Error::Signature(format!(
                "{subject} is not readable as an OpenPGP keyring: {e}"
            ))
        };
        let stream = without_trust_packets(binary);
        let certs = SignedPublicKey::from_bytes_many(Cursor::new(&stream)).map_err(refuse)?;
        let mut held: Vec<SignedPublicKey> = Vec::new();
        for cert in certs {
            if held.len() == MAX_KEYRING_CERTS {
                return Err(Error::Signature(format!(
                    "{subject} holds more than {MAX_KEYRING_CERTS} certificates"
                )));
            }
            held.push(cert.map_err(refuse)?);
        }
        Ok(held)
    })
}

/// Run `work`, which reads OpenPGP packets, with a panic inside it converted to
/// the refusal `refusal` states.
///
/// A keyring is untrusted input, so every read over one runs here and a caught
/// panic reads as input the parser rejects. Two limits hold: `catch_unwind`
/// catches nothing where the final binary is built with `panic = "abort"`, and
/// it says nothing about a parser that returns a wrong answer without
/// panicking.
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

    fn verify<'a>(&'a self, data: &'a [u8], signatures: &'a [Vec<u8>]) -> VerifyFuture<'a> {
        Box::pin(async move {
            if signatures.is_empty() {
                return Ok(VerifyOutcome::default());
            }
            // Public-key cryptography over untrusted input, so it runs on the
            // blocking pool over owned copies of its inputs.
            let certs = self.certs.clone();
            let payload = data.to_vec();
            let blobs = signatures.to_vec();
            ostrya_rt::unblock(move || verify::verify_signatures(&certs, &payload, &blobs)).await
        })
    }
}

/// One key in a remote's trusted keyring, as `remote gpg-list-keys` reports it.
///
/// The fields are what a certificate states about its primary key: the
/// fingerprint, the instant it was created, and its user ids in listing order.
/// Subkeys are not reported on their own; a subkey's parent carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpgKey {
    /// The primary key fingerprint, uppercase hex.
    pub fingerprint: String,
    /// When the key was created, in seconds since the Unix epoch.
    pub created: Option<u64>,
    /// The user ids bound to the key, in listing order.
    pub user_ids: Vec<String>,
}

impl Repo {
    /// Import the OpenPGP certificates `keys` holds into `remote`'s trusted
    /// keyring, `<remote>.trustedkeys.gpg`, and report how many the keyring did
    /// not already hold.
    ///
    /// `keys` is a binary or ASCII-armored certificate stream, which is what an
    /// exported public keyring is. With `key_ids` non-empty only the keys those
    /// selectors name are imported (a fingerprint, a key id, or a user id
    /// substring); a selector that names nothing in `keys` fails the import and
    /// the keyring is left as it was, as does a `keys` holding no certificate.
    ///
    /// The keyring is replaced atomically at the repository root. It keeps the
    /// packet stream it already held and carries the packets of each added
    /// certificate as `keys` wrote them, with the Trust packets dropped (see
    /// [`merge_keyring`]). It is written in the binary form, so an armored
    /// keyring keeps its packets and loses its armor.
    ///
    /// A certificate for a key the keyring already holds is left as the keyring
    /// holds it, and is counted as a key the keyring already held. So a
    /// revocation, a new user id, or a new subkey for a held key reaches the
    /// keyring through [`Repo::remove_remote_keyring`] and a fresh import, and
    /// not through a second call here. `docs/conformance/cli-surface.md`, "P3",
    /// records what the `ostree` tool does instead.
    pub async fn gpg_import_keys(
        &self,
        remote: &str,
        keys: &[u8],
        key_ids: &[String],
    ) -> Result<usize> {
        let name = remote_keyring_name(remote);
        let existing = self.read_root_file(&name).await?.unwrap_or_default();
        // Parsing untrusted certificate streams is CPU work over owned copies
        // of its inputs, so it runs on the blocking pool.
        let offered = keys.to_vec();
        let ids = key_ids.to_vec();
        let subject = format!("the keyring '{name}'");
        let (imported, keyring) =
            ostrya_rt::unblock(move || merge_keyring(&existing, &offered, &ids, &subject)).await?;
        let fsync = self.config().fsync()?;
        self.write_root_file(&name, keyring, fsync).await?;
        Ok(imported)
    }

    /// The keys `remote`'s trusted keyring holds. An absent keyring holds none.
    pub async fn gpg_list_keys(&self, remote: &str) -> Result<Vec<GpgKey>> {
        let name = remote_keyring_name(remote);
        let Some(keyring) = self.read_root_file(&name).await? else {
            return Ok(Vec::new());
        };
        let subject = format!("the keyring '{name}'");
        ostrya_rt::unblock(move || keyring_keys(&keyring, &subject)).await
    }
}

/// Merge the certificates `offered` holds into the keyring `existing` holds and
/// report how many certificates the keyring did not already hold.
///
/// The packet stream `existing` carries is kept as it stands and the packets of
/// each certificate the keyring does not hold are appended, so a keyring another
/// implementation wrote keeps its own packets and an added certificate stands as
/// the offered stream wrote it. The result is a binary packet stream: an armored
/// `existing` decodes to the packets it holds, the merge keeps those packets,
/// and the result carries no armor. The keyring carries no Trust packet of this
/// import's making. A certificate whose fingerprint the keyring already holds is
/// left as the keyring holds it, and it is counted as a key the keyring already
/// held.
///
/// Both streams are untrusted input, so each is held to [`MAX_KEYRING`] and to
/// [`MAX_KEYRING_CERTS`], a keybox is refused, and every packet read runs inside
/// [`contained`]. `subject` names the keyring the repository holds, so a refusal
/// over it states which file was read.
fn merge_keyring(
    existing: &[u8],
    offered: &[u8],
    key_ids: &[String],
    subject: &str,
) -> Result<(usize, Vec<u8>)> {
    let source = "the keyring to import";
    let mut keyring = keyring_stream(existing, subject)?;
    let stream = keyring_stream(offered, source)?;
    let refusal = format!("{source} cannot be merged into {subject}: the parser panicked");
    let (imported, appended) = contained(&refusal, || {
        let mut fingerprints: BTreeSet<String> = parse_keyring(&keyring, subject)?
            .iter()
            .map(fingerprint_hex)
            .collect();
        let offered = offered_certificates(&stream, source)?;
        if offered.is_empty() {
            return Err(Error::Signature(format!(
                "{source} holds no OpenPGP certificate"
            )));
        }
        let mut appended: Vec<u8> = Vec::new();
        let mut imported = 0;
        for index in select_keys(&offered, key_ids)? {
            let (cert, packets) = &offered[index];
            if fingerprints.insert(fingerprint_hex(cert)) {
                appended.extend_from_slice(packets);
                imported += 1;
            }
        }
        Ok((imported, appended))
    })?;
    keyring.extend_from_slice(&appended);
    Ok((imported, keyring))
}

/// The certificates an offered keyring stream carries, each with the packets it
/// is made of, held to [`MAX_KEYRING_CERTS`].
///
/// A stream the packet walk cannot frame to its end and a certificate the parser
/// rejects each fail the import by the name of the source, which is what the
/// `ostree` tool answers over a truncated keyring as well. The caller runs this
/// inside [`contained`].
fn offered_certificates(binary: &[u8], subject: &str) -> Result<Vec<(SignedPublicKey, Vec<u8>)>> {
    let Some(chunks) = certificate_chunks(binary) else {
        return Err(Error::Signature(format!(
            "{subject} is not readable as an OpenPGP keyring"
        )));
    };
    if chunks.len() > MAX_KEYRING_CERTS {
        return Err(Error::Signature(format!(
            "{subject} holds more than {MAX_KEYRING_CERTS} certificates"
        )));
    }
    let mut certs = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let cert = SignedPublicKey::from_bytes(Cursor::new(&chunk)).map_err(|e| {
            Error::Signature(format!(
                "{subject} is not readable as an OpenPGP keyring: {e}"
            ))
        })?;
        certs.push((cert, chunk));
    }
    Ok(certs)
}

/// The offered certificates `key_ids` names, by index, in selector order. An
/// empty `key_ids` names every offered certificate, and a selector that names
/// none is refused by name, which leaves the keyring as it was.
fn select_keys(offered: &[(SignedPublicKey, Vec<u8>)], key_ids: &[String]) -> Result<Vec<usize>> {
    if key_ids.is_empty() {
        return Ok((0..offered.len()).collect());
    }
    let mut selected = Vec::new();
    for id in key_ids {
        let matched = offered
            .iter()
            .enumerate()
            .filter(|(_, (cert, _))| selector_matches(cert, id))
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

/// Whether `selector` names `cert`.
///
/// A selector names a key, a user id, or nothing, per [`read_selector`]. A key
/// selector is read over the primary key and over every subkey; a user id
/// selector is a case-insensitive substring of one of the certificate's user
/// ids, folded over ASCII alone.
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

/// What a `KEY-ID` selector names.
enum Selector {
    /// A key, by the lowercase hex a key id or a fingerprint holds.
    Key(String),
    /// A substring of a user id, ASCII-lowercased.
    UserId(String),
    /// Nothing.
    Nothing,
}

/// What `selector` names, read as `gpg --export` reads a key name.
///
/// Measured against `gpg` 2.4.9 over `gpg --export -- <selector>`, where a
/// selector read as a key exports nothing when no key answers to it and a
/// selector read as a user id substring exports the key whose user id holds it:
///
/// - Hex digits alone name a key at five lengths: 8 digits a short key id, 16 a
///   key id, and 32, 40, or 64 a fingerprint. Any other length is a user id
///   substring -- `0123456789ab` exports the key whose user id holds those
///   twelve digits.
/// - A `0x` prefix names a key and never a user id: `0xhello` reports
///   `key "0xhello" not found: Invalid user ID` over a certificate whose user id
///   holds `0xhello`. The prefix is read in lower case alone, so `0X1234` is a
///   user id substring and exports the key whose user id holds `0X1234`.
/// - Interior spaces are admitted in one shape, the printed v4 fingerprint: ten
///   groups of four hex digits with one space between them. Every other spaced
///   shape is a user id substring -- forty hex digits in groups of two, and
///   thirty-two or sixty-four in groups of four, each export the key whose user
///   id holds them, and a `0x` prefix with a space reports `Invalid user ID`.
/// - Leading and trailing whitespace around a key selector is dropped, and
///   leading whitespace before a user id selector is dropped as well.
/// - A selector holding no character other than whitespace names nothing:
///   `gpg --export -- ''` reports `key "" not found: Invalid user ID`.
/// - The user id search folds ASCII case alone. Over the user id `Ärger`,
///   `ÄRGER` exports the key and `ärger` exports nothing.
fn read_selector(selector: &str) -> Selector {
    // `gpg` reads a space and a tab as the whitespace it drops, and no other
    // character, so a selector opening with one of those loses it here.
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

/// The lowercase hex `text` holds, where it is hex digits alone of a key id's or
/// a fingerprint's length.
fn key_hex(text: &str) -> Option<String> {
    let named = matches!(text.len(), 8 | 16 | 32 | 40 | 64);
    (named && text.chars().all(|c| c.is_ascii_hexdigit())).then(|| text.to_ascii_lowercase())
}

/// The lowercase hex a printed v4 fingerprint holds: ten groups of four hex
/// digits with one space between them.
fn spaced_fingerprint(text: &str) -> Option<String> {
    let groups: Vec<&str> = text.split(' ').collect();
    let shaped = groups.len() == 10
        && groups
            .iter()
            .all(|group| group.len() == 4 && group.chars().all(|c| c.is_ascii_hexdigit()));
    shaped.then(|| groups.concat().to_ascii_lowercase())
}

/// Whether one key answers to the hex a key selector holds.
fn key_matches<K: KeyDetails>(key: &K, hex: &str) -> bool {
    let id = key.legacy_key_id().to_string();
    match hex.len() {
        8 => id.ends_with(hex),
        16 => id == hex,
        _ => format!("{:x}", key.fingerprint()) == hex,
    }
}

/// The primary key fingerprint of a certificate, uppercase hex.
fn fingerprint_hex(cert: &SignedPublicKey) -> String {
    format!("{:X}", cert.fingerprint())
}

/// The keys a keyring holds, in the order its certificates stand in. The read
/// runs inside [`contained`], since a keyring is untrusted input.
fn keyring_keys(keyring: &[u8], subject: &str) -> Result<Vec<GpgKey>> {
    let binary = keyring_stream(keyring, subject)?;
    let refusal = format!("{subject} is not readable as an OpenPGP keyring: the parser panicked");
    contained(&refusal, || {
        let keys = parse_keyring(&binary, subject)?
            .iter()
            .map(|cert| {
                let created = cert.primary_key.created_at().as_secs();
                GpgKey {
                    fingerprint: fingerprint_hex(cert),
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

/// Decode ASCII-armored OpenPGP data (RFC 4880 radix-64) into the binary
/// packet stream, concatenating every armored block found. Binary input
/// passes through unchanged. The optional armor headers and the `=XXXX`
/// checksum line are skipped.
fn dearmor(bytes: &[u8]) -> Result<Vec<u8>> {
    let is_armored = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .is_some_and(|i| bytes[i..].starts_with(b"-----BEGIN PGP"));
    if !is_armored {
        return Ok(bytes.to_vec());
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
                // An armor header is `Key: Value`; a line without a colon is
                // already body (the blank separator was absent).
                if line.contains(':') {
                    continue;
                }
                in_headers = false;
            }
            // The `=XXXX` line is the radix-64 checksum, not body.
            if line.starts_with('=') {
                continue;
            }
            body.push_str(line.trim());
        }
        out.extend_from_slice(&base64::decode(&body)?);
    }
    Ok(out)
}

/// The directory of keyrings trusted for every remote: the value of the
/// `OSTREE_GPG_HOME` environment variable when set to a non-empty value,
/// otherwise the system `/usr/share/ostree/trusted.gpg.d` directory.
fn global_trusted_dir() -> PathBuf {
    match std::env::var_os(OSTREE_GPG_HOME_ENV) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(GLOBAL_TRUSTED_GPG_D),
    }
}

/// The `*.gpg` keyring files in `dir`, sorted by name. A missing directory
/// yields an empty list rather than an error.
fn keyring_files_in(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_file() && entry.path().extension().is_some_and(|ext| ext == "gpg")
        {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

/// Read the keyring at `path`, up to [`MAX_KEYRING`], or `None` where no file
/// is there. This is how every keyring source reaches the trusted set.
fn read_keyring_path(path: &Path) -> Result<Option<Vec<u8>>> {
    let subject = format!("the keyring '{}'", path.display());
    read_key_path(path, &subject, MAX_KEYRING)
}

/// Read an opened keyring, holding it to its kind and to [`MAX_KEYRING`] through
/// [`read_key_source`], the reader every key source is read under. `name` is
/// what a refusal reports, so an operator can find the entry that named it.
///
/// The ceiling a keyring is held to is its own: a keyring carries certificates
/// rather than base64 lines, and refusing one over the ceiling by name rather
/// than reading the part it admits is the rule `gpgkeypath` already states for
/// an entry that names nothing.
pub(crate) fn read_keyring_fd(fd: OwnedFd, name: &str) -> Result<Vec<u8>> {
    read_key_source(fd, &format!("the keyring '{name}'"), MAX_KEYRING)
}

/// A process-unique scratch directory path for one test fixture: the GnuPG home
/// directory its `gpg` runs work in, or a directory of keyring files. The
/// fixtures of this module and of [`verify`] both take their paths from it.
#[cfg(test)]
fn scratch_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "ostrya-gpg-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Parse a status-line epoch field, treating `0` as absent. The reference
/// reader the differential cases in [`verify`] compare against reads the
/// `gpgv` status stream through it.
#[cfg(test)]
fn parse_epoch(field: &str) -> Option<u64> {
    match field.parse::<u64>() {
        Ok(0) => None,
        Ok(secs) => Some(secs),
        Err(_) => None,
    }
}

/// Wrap a spawn failure, naming the missing program when that is the cause.
#[cfg(feature = "sign-gpg")]
fn spawn_err(program: &str, err: &std::io::Error) -> Error {
    if err.kind() == std::io::ErrorKind::NotFound {
        Error::Signature(format!("{program}: program not found in PATH"))
    } else {
        Error::Signature(format!("{program}: {err}"))
    }
}

/// The human-readable failure text of a finished gpg run: the non-status
/// stderr lines, or the exit status when gpg said nothing.
#[cfg(feature = "sign-gpg")]
fn failure_text(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = stderr
        .lines()
        .filter(|line| !line.starts_with(STATUS_PREFIX))
        .collect::<Vec<_>>()
        .join("; ");
    if text.trim().is_empty() {
        format!("exit status {}", output.status)
    } else {
        text
    }
}

/// The GPG public types move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    #[cfg(feature = "sign-gpg")]
    assert_send_sync::<GpgSigner>();
    assert_send_sync::<GpgVerifier>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dearmor_passes_binary_through() {
        let binary = [0x99, 0x01, 0x0d, 0x04];
        assert_eq!(dearmor(&binary).unwrap(), binary);
    }

    #[test]
    fn dearmor_decodes_an_armored_block() {
        let armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
Comment: a header\n\
\n\
aGVsbG8=\n\
=abcd\n\
-----END PGP PUBLIC KEY BLOCK-----\n";
        assert_eq!(dearmor(armored.as_bytes()).unwrap(), b"hello");
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
        assert_eq!(dearmor(armored.as_bytes()).unwrap(), b"hello world");
    }

    #[test]
    fn keyring_files_in_selects_gpg_and_sorts() {
        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["b.gpg", "a.gpg", "notes.txt", "keyring"] {
            std::fs::write(dir.join(name), b"").unwrap();
        }
        let names: Vec<String> = keyring_files_in(&dir)
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(names, ["a.gpg", "b.gpg"]);
    }

    #[test]
    fn keyring_files_in_missing_dir_is_empty() {
        assert!(keyring_files_in(&scratch_dir()).unwrap().is_empty());
    }

    /// Whether the `gpg` binary answers. The keyring cases below build their
    /// fixtures with it, so an absent binary skips them and never passes one.
    fn gpg_available() -> bool {
        std::process::Command::new("gpg")
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// A private GnuPG home holding freshly generated, passphrase-free ed25519
    /// signing keys, under the test scratch tree. Every `gpg` run names this
    /// directory with `--homedir`, so the invoking user's GnuPG home and any
    /// agent of theirs take no part. Dropping the fixture kills the agent
    /// GnuPG auto-started for the directory and removes the directory.
    struct KeyFixture {
        dir: PathBuf,
    }

    impl KeyFixture {
        /// A new home directory holding one key for `uid`.
        fn new(uid: &str) -> KeyFixture {
            use std::os::unix::fs::DirBuilderExt;
            let dir = scratch_dir();
            std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
            let fixture = KeyFixture { dir };
            fixture.add_key(uid);
            fixture
        }

        /// Generate one more key, for `uid`, in the same home directory.
        fn add_key(&self, uid: &str) {
            let status = self
                .gpg()
                .args(["--pinentry-mode", "loopback", "--passphrase", ""])
                .args(["--quick-gen-key", uid, "ed25519", "sign", "never"])
                .status()
                .unwrap();
            assert!(status.success(), "gpg --quick-gen-key failed");
        }

        /// Add a signing subkey to the home's first key.
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

        /// The fingerprint of the home's first key, uppercase hex.
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

        /// A `gpg` command bound to this home directory, batch mode.
        fn gpg(&self) -> std::process::Command {
            let mut cmd = std::process::Command::new("gpg");
            cmd.arg("--homedir").arg(&self.dir).arg("--batch");
            cmd
        }

        /// The exported public keyring, binary or ASCII-armored.
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

        /// The keybox `gpg` keeps this home directory's public keys in.
        fn keybox(&self) -> Vec<u8> {
            std::fs::read(self.dir.join("pubring.kbx")).unwrap()
        }

        /// Bind one more user id to the home's first key.
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

        /// The `--with-colons` key listing of this home, as `gpg` writes it.
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

        /// The primary-key fingerprints `gpg` reports over `keyring`, in
        /// listing order. This is the reader the `ostree` tool drives through
        /// gpgme, so a keyring it lists is a keyring the tool reads.
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

        /// The `gpg --export-secret-keys` stream of this home's keys, which
        /// carries no transferable public key.
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

        /// The `gpg --export` stream of the one key `selector` names.
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

        /// The legacy keyring `gpg --import` writes for this home's own keys.
        /// GnuPG puts a Trust packet after the primary key packet, after each
        /// user id packet, and after each signature packet of such a keyring,
        /// which is the form the `ostree` tool's own import leaves at the
        /// repository root.
        fn legacy_keyring(&self) -> Vec<u8> {
            use std::os::unix::fs::DirBuilderExt;
            let exported = self.dir.join("exported.gpg");
            std::fs::write(&exported, self.export(false)).unwrap();
            // `gpg` writes a keybox when it creates a keyring file itself, and
            // a legacy keyring when the file is already there, so the import
            // runs in a home of its own over an empty keyring file.
            let home = self.dir.join("legacy");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&home)
                .unwrap();
            let ring = home.join("ring.gpg");
            std::fs::write(&ring, b"").unwrap();
            let status = std::process::Command::new("gpg")
                .arg("--homedir")
                .arg(&home)
                .arg("--batch")
                .arg("--no-default-keyring")
                .arg("--keyring")
                .arg(&ring)
                .arg("--import")
                .arg(&exported)
                .status()
                .unwrap();
            assert!(status.success(), "gpg --import into a keyring failed");
            std::fs::read(&ring).unwrap()
        }
    }

    impl Drop for KeyFixture {
        fn drop(&mut self) {
            let _ = std::process::Command::new("gpgconf")
                .arg("--homedir")
                .arg(&self.dir)
                .args(["--kill", "gpg-agent"])
                .status();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A binary keyring holding one certificate loads to that certificate.
    #[test]
    fn loads_a_binary_keyring() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
            return;
        }
        let home = KeyFixture::new("Binary <binary@ostrya.example>");
        let verifier = GpgVerifier::from_keyring_bytes([home.export(false)]).unwrap();
        assert_eq!(verifier.certs.len(), 1);
    }

    /// An armored keyring loads to the same certificate as the binary form,
    /// and the armor decoder reaches the binary export byte for byte, so the
    /// parser reads the same packet stream out of either form.
    #[test]
    fn loads_an_armored_keyring() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
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
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
            return;
        }
        let home = KeyFixture::new("First <first@ostrya.example>");
        home.add_key("Second <second@ostrya.example>");
        let verifier = GpgVerifier::from_keyring_bytes([home.export(false)]).unwrap();
        assert_eq!(verifier.certs.len(), 2);
    }

    /// An empty keyring loads and holds no certificate. An optional keyring
    /// that is there and holds nothing is not a failure.
    #[test]
    fn loads_an_empty_keyring() {
        let verifier = GpgVerifier::from_keyring_bytes([b""]).unwrap();
        assert!(verifier.certs.is_empty());
    }

    /// A truncated keyring is refused by the name of the blob that carried it.
    #[test]
    fn refuses_a_truncated_keyring() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
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

    /// A GnuPG keybox is refused by name. rPGP reads an OpenPGP packet stream,
    /// and a keybox is a container of another kind, so reading it as a keyring
    /// would leave the trusted set empty with nothing said about it.
    #[test]
    fn refuses_a_keybox() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
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

    /// A keyring over the four-mebibyte ceiling is refused by name, and the
    /// refusal states the ceiling. The blob is bounded before it is parsed.
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

    /// A keyring holding more than 256 certificates is refused by name, and
    /// the refusal states the cap. The keyring is one certificate repeated,
    /// which is 257 transferable public keys in one packet stream.
    #[test]
    fn refuses_too_many_certificates() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
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
        // One certificate short of the cap loads, so the cap is what refused.
        let allowed = one.repeat(MAX_KEYRING_CERTS);
        let verifier = GpgVerifier::from_keyring_bytes([&allowed]).unwrap();
        assert_eq!(verifier.certs.len(), MAX_KEYRING_CERTS);
    }
    /// The user ids each certificate carries, one list per certificate, with
    /// both the certificates and the ids sorted, so two trusted sets compare as
    /// one value whatever order their keyrings held them in.
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

    /// A legacy keyring, which carries a Trust packet after the primary key
    /// packet and after each user id and signature packet, parses to what the
    /// `gpg --export` stream of the same keys parses to: the same certificate
    /// count, the same user ids, and the same subkeys.
    #[test]
    fn loads_a_trust_packet_keyring() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
            return;
        }
        let home = KeyFixture::new("Trust <trust@ostrya.example>");
        home.add_key("Second <second@ostrya.example>");
        let exported = home.export(false);
        let legacy = home.legacy_keyring();
        // The fixture is the shape under test: the two forms differ in bytes.
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

    /// A signing subkey reaches the trusted set out of a legacy keyring. The
    /// subkey packet stands after the primary key's Trust packet, so this is
    /// what a keyring holding Trust packets loses when they reach the parser.
    #[test]
    fn loads_a_subkey_from_a_trust_packet_keyring() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
            return;
        }
        let home = KeyFixture::new("Subkey <subkey@ostrya.example>");
        home.add_signing_subkey();
        let verifier = GpgVerifier::from_keyring_bytes([home.legacy_keyring()]).unwrap();
        assert_eq!(verifier.certs.len(), 1);
        assert_eq!(verifier.certs[0].public_subkeys.len(), 1);
    }

    /// The certificate cap counts the certificates a keyring parses to,
    /// whether or not the keyring carries Trust packets: 257 legacy
    /// certificates are refused by name and 256 load.
    #[test]
    fn refuses_too_many_certificates_with_trust_packets() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
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

    /// A stream carrying no Trust packet passes through the filter byte for
    /// byte, and a stream the header parser cannot frame passes through whole,
    /// so such a keyring reaches the certificate parser as it stands.
    #[test]
    fn without_trust_packets_leaves_other_streams_alone() {
        assert!(without_trust_packets(b"").is_empty());
        // No OpenPGP packet header opens with these bits.
        assert_eq!(without_trust_packets(b"\x00\x01\x02"), b"\x00\x01\x02");
        if !gpg_available() {
            eprintln!("skipping the exported-keyring half: gpg not available");
            return;
        }
        let home = KeyFixture::new("Untouched <untouched@ostrya.example>");
        let exported = home.export(false);
        assert_eq!(without_trust_packets(&exported), exported);
        // A truncated keyring keeps every byte it had.
        let cut = &exported[..exported.len() / 2];
        assert_eq!(without_trust_packets(cut), cut);
    }

    /// The subject a refusal over the repository's own keyring names.
    const SUBJECT: &str = "the keyring 'origin.trustedkeys.gpg'";

    /// An import into no keyring writes the offered stream as it stands and
    /// counts each certificate, `gpg` reads the result, and a repeated import
    /// counts none and leaves the bytes alone.
    #[test]
    fn an_import_writes_the_offered_certificates() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
            return;
        }
        let home = KeyFixture::new("First <first@ostrya.example>");
        home.add_key("Second <second@ostrya.example>");
        let offered = home.export(false);

        let (imported, keyring) = merge_keyring(b"", &offered, &[], SUBJECT).unwrap();
        assert_eq!(imported, 2);
        assert_eq!(keyring, offered);
        // The keyring the import writes is one `gpg` reads, which is the
        // reader the `ostree` tool drives through gpgme.
        assert_eq!(home.fingerprints_of(&keyring).len(), 2);

        let (again, repeated) = merge_keyring(&keyring, &offered, &[], SUBJECT).unwrap();
        assert_eq!(again, 0);
        assert_eq!(repeated, keyring);
    }

    /// An import onto a keyring GnuPG wrote keeps that keyring byte for byte
    /// and appends the packets of the added certificate. `gpg` reads the
    /// result, which holds both keys, so a keyring carrying Trust packets for
    /// one key and none for another is a keyring both implementations read.
    #[test]
    fn an_import_keeps_the_keyring_it_was_given() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
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

    /// An import onto an armored keyring keeps the packet stream that keyring
    /// held and writes it back in the binary form: the armor decodes to the
    /// packets the binary export of the same key holds, those packets open the
    /// result, and the added certificate's packets follow them. `gpg` reads the
    /// result and lists both keys.
    #[test]
    fn an_import_keeps_the_packet_stream_of_an_armored_keyring() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
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

    /// The Trust packets are the whole difference between the keyring GnuPG
    /// writes and the keyring this import writes for the same keys.
    ///
    /// A legacy keyring offered for import loses its Trust packets, so the
    /// keyring the import writes carries none whichever form the offered stream
    /// took.
    #[test]
    fn the_trust_packets_are_the_whole_difference() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
            return;
        }
        let home = KeyFixture::new("Same <same@ostrya.example>");
        home.add_signing_subkey();
        let exported = home.export(false);
        let legacy = home.legacy_keyring();
        assert!(legacy.len() > exported.len());
        assert_eq!(without_trust_packets(&legacy), exported);
        for offered in [&exported, &legacy] {
            let (imported, keyring) = merge_keyring(b"", offered, &[], SUBJECT).unwrap();
            assert_eq!(imported, 1);
            assert_eq!(keyring, exported);
        }
        // A selection off a legacy keyring writes the selected certificate
        // without its Trust packets as well.
        let selector = [home.fingerprint()];
        let (imported, keyring) = merge_keyring(b"", &legacy, &selector, SUBJECT).unwrap();
        assert_eq!(imported, 1);
        assert_eq!(keyring, exported);
    }

    /// Each selector form takes the key it names out of the offered stream: a
    /// fingerprint plain, `0x`-prefixed, and spaced, a key id long and short, a
    /// subkey fingerprint, and a user id substring in another case.
    #[test]
    fn a_selector_takes_the_key_it_names() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
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

        // Two selectors take two keys, and one selector matching both user ids
        // takes both.
        let both = [primary.clone(), "other".to_owned()];
        assert_eq!(merge_keyring(b"", &offered, &both, SUBJECT).unwrap().0, 2);
        let shared = ["ostrya.example".to_owned()];
        assert_eq!(merge_keyring(b"", &offered, &shared, SUBJECT).unwrap().0, 2);
    }

    /// A selector naming no offered key is refused by name, and the keyring is
    /// then left as it was. A hex selector names a key alone: it is no user id
    /// substring, which is how `gpg --export` reads one.
    #[test]
    fn a_selector_naming_nothing_is_refused() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
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
        // The person's own name is a user id substring and takes the key.
        let taken = ["DEADBEEF Person".to_owned()];
        assert_eq!(merge_keyring(b"", &offered, &taken, SUBJECT).unwrap().0, 1);
    }

    /// A selector `gpg --export` reads as a user id substring is no key
    /// selector here either, so a shape the key reader does not carry names
    /// nothing rather than a key of its own choosing.
    ///
    /// Each row was measured against `gpg --export -- <selector>` on
    /// `gpg` 2.4.9, and none of them exports the key the hex names.
    #[test]
    fn a_selector_the_key_reader_does_not_carry_names_nothing() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
            return;
        }
        // The user id holds a `0x`-prefixed word, so a `0x` selector that is no
        // key would take this key if it were read as a user id substring.
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
        // Ten groups the same fingerprint splits into at uneven widths.
        let uneven = format!(
            "{} {} {}",
            &primary[..3],
            &primary[3..8],
            group(4)[10..].to_owned()
        );
        // The `0x` prefix is read in lower case alone and names a key or
        // nothing; a key id carries no interior space; the one spaced shape is a
        // printed v4 fingerprint, ten groups of four; a tab is no space; and
        // `0x` admits no space.
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
            // The reference: the selector exports nothing through `gpg`.
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
        // The forms the reader does carry still take the key: a printed
        // fingerprint in its ten groups of four, and either hex case, with
        // leading and trailing spaces dropped.
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

    /// The user id search folds ASCII case alone, which is what `gpg` folds:
    /// over the user id `Ärger`, `ÄRGER` takes the key and `ärger` takes none.
    #[test]
    fn a_user_id_selector_folds_ascii_case_alone() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
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

    /// A stream carrying no certificate, one the packet walk cannot frame to
    /// its end, and a keybox are each refused, and the keyring is then left as
    /// it was. The `ostree` tool refuses all three as well.
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
        if !gpg_available() {
            eprintln!("skipping the keyring half: gpg not available");
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
        // holds none. The `ostree` tool takes the public part of such a stream;
        // `cli-surface.md`, "P3", records the divergence.
        let err = merge_keyring(b"", &home.export_secret(), &[], SUBJECT).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("no OpenPGP certificate")),
            "{err}"
        );
        // The certificate cap holds over an offered stream as well: 257 are
        // refused by name and 256 are taken.
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

    /// The listing reports what `gpg` reports over the same keyring: the
    /// fingerprint, the creation instant, and the user ids in listing order.
    /// A keyring holding no key lists none.
    #[test]
    fn the_listing_agrees_with_gpg() {
        if !gpg_available() {
            eprintln!("skipping: gpg not available");
            return;
        }
        let home = KeyFixture::new("Listed <listed@ostrya.example>");
        home.add_uid("Second <second@ostrya.example>");
        home.add_signing_subkey();
        home.add_key("Another <another@ostrya.example>");

        // The reference: the `pub`, `fpr`, and `uid` records of gpg's own
        // machine-readable listing, one record set per primary key.
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
            assert_eq!(keyring_keys(&keyring, SUBJECT).unwrap(), reference);
        }
        assert!(keyring_keys(b"", SUBJECT).unwrap().is_empty());
    }
}
