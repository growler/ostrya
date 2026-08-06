//! GPG (OpenPGP) commit-signing engine (Phase 13d).
//!
//! Behind the `sign-gpg` feature, over the system GnuPG installation: signing
//! runs `gpg --detach-sign` and verification runs `gpgv`, each as a
//! short-lived subprocess through [`ostrya_rt::Command`], with results read
//! from the machine-readable `--status-fd` line protocol. No OpenPGP
//! implementation is linked into the library, and the private key never
//! passes through it.
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
//! [`GpgVerifier`] holds binary keyring blobs, loaded through
//! [`from_keyring_bytes`](GpgVerifier::from_keyring_bytes) and
//! [`from_keyring_files`](GpgVerifier::from_keyring_files) (armored input is
//! decoded to the binary form on load, since `gpgv` reads only binary
//! keyrings). [`from_system_trust`](GpgVerifier::from_system_trust) loads the
//! global trusted set -- every `*.gpg` keyring in the directory named by the
//! `OSTREE_GPG_HOME` environment variable, or `<datadir>/ostree/trusted.gpg.d/`
//! when it is unset. [`for_remote`](GpgVerifier::for_remote) adds the
//! per-remote keyring (`<remote>.trustedkeys.gpg` in the repo or under
//! `/etc/ostree/remotes.d/`) on top of that global set, and
//! [`for_remote_keyrings`](GpgVerifier::for_remote_keyrings) takes the
//! repository's keyring as bytes and adds the keyrings a remote's `gpgkeypath`
//! names, which is what a pull trusts. Every keyring file reaches the trusted
//! set through one reader: only a regular file is read, and only up to four
//! mebibytes, so a path naming a fifo and a keyring over that ceiling are each
//! refused by that path's own name. Verification writes
//! the merged keyring to a private scratch directory and runs `gpgv` once per
//! stored blob; `gpgv` performs public-key operations only and starts no
//! agent.
//!
//! A remote's own trusted keyring is managed through the same subprocess
//! plumbing: [`Repo::gpg_import_keys`] adds certificates to
//! `<remote>.trustedkeys.gpg` and reports how many the keyring did not already
//! hold, and [`Repo::gpg_list_keys`] reads back the keys it holds as
//! [`GpgKey`] records. Both run `gpg` in a private scratch directory, so the
//! invoking user's GnuPG home takes no part.
//!
//! A signature is valid only when `gpgv` reports `GOODSIG`. An expired key
//! (`EXPKEYSIG`), a revoked key (`REVKEYSIG`), a bad signature (`BADSIG`),
//! and an absent key (`ERRSIG`/`NO_PUBKEY`) are reported per signature in
//! [`SignatureInfo`]. Trust is membership in the verifier's keyrings; GnuPG's
//! ownertrust model plays no part.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ostrya_core::base64;

use crate::config::remote_keyring_name;
use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::sign::{
    SignFuture, SignatureInfo, Signer, Verifier, VerifyFuture, VerifyOutcome, read_key_path,
    read_key_source,
};

/// The GPG engine's short name.
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

/// The GPG commit-signing engine.
///
/// Holds the key selector `gpg --local-user` resolves -- a fingerprint, a key
/// id, or a user id -- and an optional GnuPG home directory. Signing runs
/// `gpg --detach-sign` with the payload on stdin and reads the binary
/// signature from stdout.
#[derive(Debug, Clone)]
pub struct GpgSigner {
    key: String,
    homedir: Option<PathBuf>,
}

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
}

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

/// The GPG commit-verifying engine, holding the trusted keyrings as binary
/// blobs.
#[derive(Debug, Clone, Default)]
pub struct GpgVerifier {
    keyrings: Vec<Vec<u8>>,
}

impl GpgVerifier {
    /// Build a verifier trusting every certificate in the given keyring
    /// blobs. Each blob is a binary or ASCII-armored OpenPGP keyring and may
    /// hold several certificates; armored input is decoded to the binary
    /// form, and all blobs merge into one trusted set.
    pub fn from_keyring_bytes<I, B>(keyrings: I) -> Result<GpgVerifier>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut blobs = Vec::new();
        for keyring in keyrings {
            blobs.push(dearmor(keyring.as_ref())?);
        }
        Ok(GpgVerifier { keyrings: blobs })
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
        let mut blobs: Vec<Vec<u8>> = Vec::new();
        for path in paths {
            if let Some(bytes) = read_keyring_path(path.as_ref())? {
                blobs.push(bytes);
            }
        }
        GpgVerifier::from_keyring_bytes(blobs)
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
        let mut verifier = GpgVerifier::from_keyring_files(paths)?;
        if let Some(bytes) = repo_keyring {
            verifier.keyrings.insert(0, dearmor(&bytes)?);
        }
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
}

impl Verifier for GpgVerifier {
    fn metadata_key(&self) -> &str {
        GPG_METADATA_KEY
    }

    fn verify<'a>(&'a self, data: &'a [u8], signatures: &'a [Vec<u8>]) -> VerifyFuture<'a> {
        Box::pin(async move {
            let mut outcome = VerifyOutcome::default();
            if signatures.is_empty() {
                return Ok(outcome);
            }

            // Materialize the merged keyring and the signature blobs in a
            // private scratch directory on the blocking pool.
            let ring: Vec<u8> = self.keyrings.concat();
            let blobs: Vec<Vec<u8>> = signatures.to_vec();
            let count = blobs.len();
            let dir = scratch_dir();
            let setup_dir = dir.clone();
            ostrya_rt::unblock(move || -> std::io::Result<()> {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new().mode(0o700).create(&setup_dir)?;
                std::fs::write(setup_dir.join("ring.gpg"), &ring)?;
                for (i, blob) in blobs.iter().enumerate() {
                    std::fs::write(setup_dir.join(format!("sig{i}")), blob)?;
                }
                Ok(())
            })
            .await?;

            let result = run_gpgv(&dir, count, data, &mut outcome).await;

            let cleanup_dir = dir.clone();
            let _ = ostrya_rt::unblock(move || std::fs::remove_dir_all(cleanup_dir)).await;

            result.map(|()| outcome)
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
/// nothing is refused by name.
async fn select_keys(dir: &Path, keys: &[u8], key_ids: &[String]) -> Result<Vec<u8>> {
    import_keyring(dir, OFFERED_FILE, keys).await?;
    let mut selected = Vec::new();
    for id in key_ids {
        let mut cmd = gpg_in(dir, OFFERED_FILE);
        cmd.arg("--export").arg(id);
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

/// Verify each staged signature blob with one `gpgv` run, accumulating the
/// per-signature outcomes.
async fn run_gpgv(
    dir: &Path,
    count: usize,
    payload: &[u8],
    outcome: &mut VerifyOutcome,
) -> Result<()> {
    for i in 0..count {
        let mut cmd = ostrya_rt::Command::new("gpgv");
        cmd.arg("--homedir")
            .arg(dir)
            .arg("--status-fd")
            .arg("1")
            .arg("--keyring")
            .arg(dir.join("ring.gpg"))
            .arg(dir.join(format!("sig{i}")))
            .arg("-");
        let output = cmd
            .output(payload)
            .await
            .map_err(|e| spawn_err("gpgv", &e))?;
        // A nonzero exit reports a signature that did not verify; the status
        // lines carry the verdict. Only an empty status stream -- an
        // unparsable blob with no signature packet -- has no record, and is
        // reported so the count matches the stored blobs.
        let infos = parse_status(&output.stdout);
        if infos.is_empty() {
            outcome.signatures.push(SignatureInfo::default());
        } else {
            for info in infos {
                outcome.valid |= info.valid;
                outcome.signatures.push(info);
            }
        }
    }
    Ok(())
}

/// Parse the machine-readable status stream of one `gpgv` (or `gpg --verify`)
/// run into per-signature records. Each `NEWSIG` starts a record; the verdict
/// keywords and `VALIDSIG` detail lines fill it.
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
                info.primary_fingerprint = fields.next().map(str::to_owned).or_else(|| fpr.clone());
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

/// Parse a status-line epoch field, treating `0` as absent.
fn parse_epoch(field: &str) -> Option<u64> {
    match field.parse::<u64>() {
        Ok(0) => None,
        Ok(secs) => Some(secs),
        Err(_) => None,
    }
}

/// Split a GnuPG user-id string into name and email: the trailing
/// `<address>` is the email and what precedes it is the name. A uid without
/// an address is all name.
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

/// A process-unique scratch directory path for one `gpg` or `gpgv` run: the
/// GnuPG home directory a verification, an import, or a listing works in.
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
    assert_send_sync::<GpgSigner>();
    assert_send_sync::<GpgVerifier>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_good_signature_group() {
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
    fn parses_a_missing_key_group() {
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
    fn parses_a_bad_signature_group() {
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
    fn parses_an_expired_key_group() {
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
    fn parses_a_revoked_key_group() {
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
    fn parses_two_signature_groups() {
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
    fn empty_status_yields_no_records() {
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
}
