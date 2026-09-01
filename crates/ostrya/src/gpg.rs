//! GPG (OpenPGP) commit-signing engine (Phase 13d).
//!
//! Behind the `verify-gpg` feature: keyrings are parsed and signatures are
//! verified in the process with the `pgp` crate (rPGP). The `sign-gpg` feature
//! adds signing through `gpg --detach-sign` and turns on `verify-gpg` with it.
//! Each `gpg` run is a short-lived subprocess through [`ostrya_rt::Command`],
//! with results read from the machine-readable `--status-fd` line protocol.
//! The private key stays with GnuPG and its agent and never passes through the
//! library.
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
//! A remote's own trusted keyring is managed through subprocess plumbing:
//! [`Repo::gpg_import_keys`] adds certificates to `<remote>.trustedkeys.gpg`
//! and reports how many the keyring did not already hold, and
//! [`Repo::gpg_list_keys`] reads back the keys it holds as
//! [`GpgKey`] records. Both run `gpg` in a private scratch directory, so the
//! invoking user's GnuPG home takes no part.
//!
//! A signature is valid only where it verifies against a trusted key whose
//! bindings hold and which is neither expired nor revoked. An expired key, a
//! revoked key, a bad signature, and an absent key are each reported per
//! signature in [`SignatureInfo`](crate::sign::SignatureInfo). Trust is
//! membership in the verifier's keyrings; GnuPG's ownertrust model plays no
//! part.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ostrya_core::base64;
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::packet::PacketHeader;
use pgp::types::{PacketLength, Tag};

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
const STATUS_PREFIX: &str = "[GNUPG:] ";
/// The scratch-directory name of the keyring an import writes and a listing
/// reads.
const RING_FILE: &str = "ring.gpg";
/// The scratch-directory name of the keyring holding the keys offered to an
/// import, out of which a `KEY-ID` selection exports.
const OFFERED_FILE: &str = "offered.gpg";
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
        if bytes.len() as u64 > MAX_KEYRING {
            return Err(Error::Signature(format!(
                "{subject} is over the {MAX_KEYRING}-byte ceiling"
            )));
        }
        let binary = dearmor(bytes)?;
        if binary.len() >= KEYBOX_MAGIC_OFFSET + KEYBOX_MAGIC.len()
            && &binary[KEYBOX_MAGIC_OFFSET..KEYBOX_MAGIC_OFFSET + KEYBOX_MAGIC.len()]
                == KEYBOX_MAGIC
        {
            return Err(Error::Signature(format!(
                "{subject} is a GnuPG keybox, and a keyring is read as an OpenPGP \
                 packet stream"
            )));
        }
        self.certs.extend(parse_keyring(&binary, subject)?);
        Ok(())
    }
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
/// The walk frames each packet with rPGP's own header parser, which is the
/// parser the packet stream is read with, so a packet boundary here is a
/// packet boundary there. A header the parser refuses, a length form other
/// than a fixed one, and a length that runs past the end each stop the walk,
/// and the bytes from that point to the end pass through as they stand. The
/// result is at most as long as the input, which
/// [`GpgVerifier::add_keyring`] has already held to [`MAX_KEYRING`].
fn without_trust_packets(binary: &[u8]) -> Vec<u8> {
    let mut kept: Vec<u8> = Vec::with_capacity(binary.len());
    let mut rest = binary;
    while !rest.is_empty() {
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
        if header.tag() != Tag::Trust {
            kept.extend_from_slice(&rest[..total]);
        }
        rest = &rest[total..];
    }
    kept.extend_from_slice(rest);
    kept
}

/// Parse a binary OpenPGP keyring into the certificates it carries, holding
/// the result to [`MAX_KEYRING_CERTS`]. A keyring carrying no packet parses to
/// no certificate. Trust packets are dropped first (see
/// [`without_trust_packets`]), so a legacy GnuPG keyring and a `gpg --export`
/// stream of the same keys parse to the same certificates.
///
/// A keyring is untrusted input, so the parse runs inside
/// [`std::panic::catch_unwind`] and a caught panic reads as a keyring the
/// parser rejects. Two limits hold: `catch_unwind` catches nothing where the
/// final binary is built with `panic = "abort"`, and it says nothing about a
/// parser that returns a wrong answer without panicking.
fn parse_keyring(binary: &[u8], subject: &str) -> Result<Vec<SignedPublicKey>> {
    let parse = || -> Result<Vec<SignedPublicKey>> {
        let refuse = |e: pgp::errors::Error| {
            Error::Signature(format!(
                "{subject} is not readable as an OpenPGP keyring: {e}"
            ))
        };
        let stream = without_trust_packets(binary);
        let certs =
            SignedPublicKey::from_bytes_many(std::io::Cursor::new(&stream)).map_err(refuse)?;
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
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(parse)) {
        Ok(result) => result,
        Err(_) => Err(Error::Signature(format!(
            "{subject} is not readable as an OpenPGP keyring: the parser panicked"
        ))),
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
/// The fields are what `gpg`'s machine-readable key listing states about the
/// primary key: its fingerprint, the instant it was created, and its user ids in
/// listing order. Subkeys are not reported on their own; a subkey's parent
/// carries it.
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
    /// selectors name are imported, each selector resolved the way `gpg` resolves
    /// one (a fingerprint, key id, or user id substring); a selector that names
    /// nothing in `keys` fails the import and the keyring is left as it was.
    ///
    /// The work runs as `gpg` subprocesses in a private scratch directory, so
    /// neither the invoking user's GnuPG home nor any agent takes part, and the
    /// keyring is replaced atomically at the repository root.
    pub async fn gpg_import_keys(
        &self,
        remote: &str,
        keys: &[u8],
        key_ids: &[String],
    ) -> Result<usize> {
        let name = remote_keyring_name(remote);
        let existing = self.read_root_file(&name).await?.unwrap_or_default();
        let dir = scratch_dir();

        let result = self
            .import_into_scratch(&dir, existing, keys, key_ids)
            .await;
        let cleanup = dir.clone();
        let _ = ostrya_rt::unblock(move || std::fs::remove_dir_all(cleanup)).await;

        let (imported, keyring) = result?;
        let fsync = self.config().fsync()?;
        self.write_root_file(&name, keyring, fsync).await?;
        Ok(imported)
    }

    /// The keys `remote`'s trusted keyring holds. An absent keyring holds none.
    ///
    /// The keyring is read through a `gpg` key listing in a private scratch
    /// directory, so the invoking user's own keyring plays no part.
    pub async fn gpg_list_keys(&self, remote: &str) -> Result<Vec<GpgKey>> {
        let Some(keyring) = self.read_root_file(&remote_keyring_name(remote)).await? else {
            return Ok(Vec::new());
        };
        let dir = scratch_dir();
        let result = list_keys_in_scratch(&dir, keyring).await;
        let cleanup = dir.clone();
        let _ = ostrya_rt::unblock(move || std::fs::remove_dir_all(cleanup)).await;
        result
    }

    /// Stage the current keyring in `dir`, import into it, and return the number
    /// of keys added and the resulting keyring bytes.
    async fn import_into_scratch(
        &self,
        dir: &Path,
        existing: Vec<u8>,
        keys: &[u8],
        key_ids: &[String],
    ) -> Result<(usize, Vec<u8>)> {
        let setup_dir = dir.to_owned();
        let staged = existing;
        ostrya_rt::unblock(move || -> std::io::Result<()> {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&setup_dir)?;
            std::fs::write(setup_dir.join(RING_FILE), &staged)
        })
        .await?;

        let selected = if key_ids.is_empty() {
            keys.to_vec()
        } else {
            select_keys(dir, keys, key_ids).await?
        };
        let imported = import_keyring(dir, RING_FILE, &selected).await?;
        let read_dir = dir.to_owned();
        let keyring = ostrya_rt::unblock(move || std::fs::read(read_dir.join(RING_FILE))).await?;
        Ok((imported, keyring))
    }
}

/// Export the keys `key_ids` names out of `keys`, through a scratch keyring of
/// its own so the selection reads only what was offered. A selector that names
/// nothing is refused by name. Each selector stands after `--`, so gpg reads it
/// as a key name rather than as one of its own options.
async fn select_keys(dir: &Path, keys: &[u8], key_ids: &[String]) -> Result<Vec<u8>> {
    import_keyring(dir, OFFERED_FILE, keys).await?;
    let mut selected = Vec::new();
    for id in key_ids {
        let mut cmd = gpg_in(dir, OFFERED_FILE);
        cmd.arg("--export").arg("--").arg(id);
        let output = cmd.output(&[]).await.map_err(|e| spawn_err("gpg", &e))?;
        if !output.status.success() || output.stdout.is_empty() {
            return Err(Error::Signature(format!(
                "no key matching '{id}' among the keys to import"
            )));
        }
        selected.extend_from_slice(&output.stdout);
    }
    Ok(selected)
}

/// Import `keys` into the scratch keyring `ring` and report how many keys the
/// keyring did not already hold, read from the `IMPORT_RES` status line.
async fn import_keyring(dir: &Path, ring: &str, keys: &[u8]) -> Result<usize> {
    let mut cmd = gpg_in(dir, ring);
    cmd.arg("--status-fd").arg("1").arg("--import");
    let output = cmd.output(keys).await.map_err(|e| spawn_err("gpg", &e))?;
    if !output.status.success() {
        return Err(Error::Signature(format!(
            "gpg --import failed: {}",
            failure_text(&output)
        )));
    }
    Ok(parse_import_count(&output.stdout))
}

/// List the keys of a keyring staged in `dir`.
async fn list_keys_in_scratch(dir: &Path, keyring: Vec<u8>) -> Result<Vec<GpgKey>> {
    let setup_dir = dir.to_owned();
    ostrya_rt::unblock(move || -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&setup_dir)?;
        std::fs::write(setup_dir.join(RING_FILE), &keyring)
    })
    .await?;

    let mut cmd = gpg_in(dir, RING_FILE);
    cmd.arg("--with-colons")
        .arg("--fixed-list-mode")
        .arg("--list-keys");
    let output = cmd.output(&[]).await.map_err(|e| spawn_err("gpg", &e))?;
    if !output.status.success() {
        return Err(Error::Signature(format!(
            "gpg --list-keys failed: {}",
            failure_text(&output)
        )));
    }
    Ok(parse_key_listing(&output.stdout))
}

/// A `gpg` command bound to the scratch directory as its GnuPG home and to
/// `ring` as its one keyring, so no keyring of the invoking user is read or
/// written.
fn gpg_in(dir: &Path, ring: &str) -> ostrya_rt::Command {
    let mut cmd = ostrya_rt::Command::new("gpg");
    cmd.arg("--homedir")
        .arg(dir)
        .arg("--batch")
        .arg("--no-default-keyring")
        .arg("--keyring")
        .arg(dir.join(ring));
    cmd
}

/// The count of newly imported keys an import run reports: field 3 of
/// `IMPORT_RES`, which counts the keys the keyring did not already hold. A run
/// that imported nothing new reports `0` there.
fn parse_import_count(stdout: &[u8]) -> usize {
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(STATUS_PREFIX) else {
            continue;
        };
        let mut fields = rest.split(' ');
        if fields.next() != Some("IMPORT_RES") {
            continue;
        }
        // IMPORT_RES <count> <no-user-id> <imported> <imported-rsa> <unchanged> ...
        return fields
            .nth(2)
            .and_then(|field| field.parse::<usize>().ok())
            .unwrap_or(0);
    }
    0
}

/// Parse a `--with-colons` key listing into one record per primary key. A `pub`
/// record starts a key, the `fpr` record that follows it carries the
/// fingerprint, and each `uid` record adds a user id; the records of a subkey
/// (`sub` and what follows it) belong to the key they were listed under.
fn parse_key_listing(stdout: &[u8]) -> Vec<GpgKey> {
    let text = String::from_utf8_lossy(stdout);
    let mut keys: Vec<GpgKey> = Vec::new();
    let mut in_subkey = false;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields.first().copied() {
            Some("pub") => {
                in_subkey = false;
                keys.push(GpgKey {
                    fingerprint: String::new(),
                    created: fields.get(5).and_then(|f| parse_epoch(f)),
                    user_ids: Vec::new(),
                });
            }
            Some("sub") => in_subkey = true,
            Some("fpr") if !in_subkey => {
                if let Some(key) = keys.last_mut()
                    && key.fingerprint.is_empty()
                    && let Some(fpr) = fields.get(9)
                {
                    key.fingerprint = (*fpr).to_owned();
                }
            }
            Some("uid") => {
                if let Some(key) = keys.last_mut()
                    && let Some(uid) = fields.get(9)
                    && !uid.is_empty()
                {
                    key.user_ids.push(unescape_colon_field(uid));
                }
            }
            _ => {}
        }
    }
    keys
}

/// Undo the escaping a `--with-colons` field carries: `\x3a` for a colon, and
/// the same `\xNN` form for any other byte gpg escapes.
fn unescape_colon_field(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut rest = field;
    while let Some(index) = rest.find("\\x") {
        out.push_str(&rest[..index]);
        let hex = rest.get(index + 2..index + 4);
        match hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
            Some(byte) => {
                out.push(byte as char);
                rest = &rest[index + 4..];
            }
            None => {
                out.push_str("\\x");
                rest = &rest[index + 2..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Parse a status-line epoch field, treating `0` as absent.
fn parse_epoch(field: &str) -> Option<u64> {
    match field.parse::<u64>() {
        Ok(0) => None,
        Ok(secs) => Some(secs),
        Err(_) => None,
    }
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

/// A process-unique scratch directory path for one `gpg` run: the GnuPG home
/// directory an import or a listing works in.
fn scratch_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "ostrya-gpg-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Wrap a spawn failure, naming the missing program when that is the cause.
fn spawn_err(program: &str, err: &std::io::Error) -> Error {
    if err.kind() == std::io::ErrorKind::NotFound {
        Error::Signature(format!("{program}: program not found in PATH"))
    } else {
        Error::Signature(format!("{program}: {err}"))
    }
}

/// The human-readable failure text of a finished gpg run: the non-status
/// stderr lines, or the exit status when gpg said nothing.
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

    /// The two `IMPORT_RES` lines a first and a repeated import produce: field 3
    /// counts the keys the keyring did not already hold.
    #[test]
    fn parses_the_import_count() {
        let first = b"[GNUPG:] IMPORTED EA11F223F7A88090 T <t@e.invalid>\n\
[GNUPG:] IMPORT_OK 1 A98EFC84DC1176AFDF076367EA11F223F7A88090\n\
[GNUPG:] IMPORT_RES 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0\n";
        assert_eq!(parse_import_count(first), 1);
        let repeated = b"[GNUPG:] IMPORT_OK 0 A98EFC84DC1176AFDF076367EA11F223F7A88090\n\
[GNUPG:] IMPORT_RES 1 0 0 0 1 0 0 0 0 0 0 0 0 0 0\n";
        assert_eq!(parse_import_count(repeated), 0);
        let two = b"[GNUPG:] IMPORT_RES 2 0 2 0 0 0 0 0 0 0 0 0 0 0 0\n";
        assert_eq!(parse_import_count(two), 2);
        // A run whose status stream says nothing about the result counts none.
        assert_eq!(parse_import_count(b""), 0);
    }

    /// A `--with-colons` listing of one ed25519 key and one RSA key with an
    /// encryption subkey, as `gpg --list-keys` wrote it.
    #[test]
    fn parses_the_key_listing() {
        let listing = b"tru::1:1785958949:0:3:1:5\n\
pub:-:255:22:CA965442280A3BB5:1785958949:::-:::scSC:::::ed25519:::0:\n\
fpr:::::::::FA2B2317C9966572B5D729EDCA965442280A3BB5:\n\
uid:-::::1785958949::2002AD890A7DC86C5CE36C4EB351537E74CBC5E9::Ostrya Test <test@example.invalid>::::::::::0:\n\
uid:-::::1785958949::AA02AD890A7DC86C5CE36C4EB351537E74CBC5E8::Second Id <second@example.invalid>::::::::::0:\n\
pub:-:2048:1:56A674CB09BADB3E:1785958950:::-:::scSC::::::23::0:\n\
fpr:::::::::8EB5022E57DB2BB28470F20A56A674CB09BADB3E:\n\
uid:-::::1785958950::FA8A955FF9BB9C4540D030246F056A7DB9E282FA::No Email Person::::::::::0:\n\
sub:-:2048:1:9A5C1E4D2F3B7A81:1785958950::::::e::::::23:\n\
fpr:::::::::1111111111111111111111119A5C1E4D2F3B7A81:\n";
        let keys = parse_key_listing(listing);
        assert_eq!(keys.len(), 2);
        assert_eq!(
            keys[0].fingerprint,
            "FA2B2317C9966572B5D729EDCA965442280A3BB5"
        );
        assert_eq!(keys[0].created, Some(1_785_958_949));
        assert_eq!(
            keys[0].user_ids,
            [
                "Ostrya Test <test@example.invalid>",
                "Second Id <second@example.invalid>"
            ]
        );
        // The subkey's own fingerprint record does not become a third key, and
        // it does not replace its parent's.
        assert_eq!(
            keys[1].fingerprint,
            "8EB5022E57DB2BB28470F20A56A674CB09BADB3E"
        );
        assert_eq!(keys[1].user_ids, ["No Email Person"]);
    }

    #[test]
    fn unescapes_a_colon_field() {
        assert_eq!(unescape_colon_field("plain"), "plain");
        assert_eq!(unescape_colon_field("a\\x3ab"), "a:b");
        assert_eq!(unescape_colon_field("a\\x5cb"), "a\\b");
        // A `\x` that is not a byte escape stays as written.
        assert_eq!(unescape_colon_field("a\\xzz"), "a\\xzz");
    }

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

        /// The legacy keyring `gpg --import` writes for this home's own keys.
        /// GnuPG puts a Trust packet after the primary key packet, after each
        /// user id packet, and after each signature packet of such a keyring,
        /// which is the form [`Repo::gpg_import_keys`] leaves at the
        /// repository root.
        fn legacy_keyring(&self) -> Vec<u8> {
            use std::os::unix::fs::DirBuilderExt;
            let exported = self.dir.join("exported.gpg");
            std::fs::write(&exported, self.export(false)).unwrap();
            // `gpg` writes a keybox when it creates a keyring file itself, and
            // a legacy keyring when the file is already there, so the import
            // runs in a home of its own over an empty keyring file, as the
            // import path's scratch directory does.
            let home = self.dir.join("legacy");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&home)
                .unwrap();
            let ring = home.join(RING_FILE);
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
}
