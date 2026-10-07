//! Commit signing framework and the dummy test engine.
//!
//! The engines, the [`Signer`] and [`Verifier`] traits, [`SignKeys`], and the
//! key reader are items of the `ostrya-sign` crate, re-exported here with its
//! [`Error`] and [`Result`]. This module adds the repository side: the
//! `impl Repo` entry points, the system key store readers
//! ([`load_sign_keys`], [`load_sign_keys_from`]), and [`FromSystemKeys`].
//!
//! [`Signer`] and [`Verifier`] are the engine-agnostic surface: a signer names
//! its engine and its detached-metadata key and signs an opaque byte payload; a
//! verifier checks a set of signature blobs against a payload and reports a
//! [`VerifyOutcome`]. Both operate on opaque bytes, so the commit path here and
//! the summary path of the `summary` module share one surface.
//!
//! The signed payload for a commit is the canonical serialized commit GVariant
//! bytes -- the same normal-form bytes that hash to the commit checksum
//! (`format-reference.md`, "Signing details").
//!
//! Signatures live in the commit's detached metadata (`.commitmeta`), a bare
//! `a{sv}` dict. Each engine owns one key whose value is an `aay` (an array of
//! signature blobs); signing appends one `ay` element, creating the array when
//! absent and leaving other engines' arrays untouched. [`Repo::sign_commit`]
//! and [`Repo::verify_commit`] tie the engine to the detached-metadata I/O, and
//! [`Repo::delete_signatures`] removes stored blobs an engine no longer wants,
//! dropping the entry when its array empties and clearing the metadata when the
//! dict empties.
//!
//! The dummy engine ([`DummySigner`] / [`DummyVerifier`]) carries no crypto: a
//! signature is the raw bytes of its key identifier, and verification matches a
//! stored blob against a trusted key byte string. It exercises the framework
//! and cross-checks against the tool's `ostree.sign.dummy` engine.
//!
//! The ed25519 engine ([`Ed25519Signer`] / [`Ed25519Verifier`]) is the first
//! real engine: a 32-byte public key, a 64-byte signature, and a
//! 64-byte secret key (32-byte seed followed by the 32-byte public key), all per
//! `format-reference.md`. ed25519 is deterministic, so signing needs no RNG and
//! the same key over the same commit yields byte-identical detached metadata.
//! [`load_sign_keys`] loads the sign-api key store -- base64-one-key-per-line
//! `trusted.<type>` and `revoked.<type>` files and their `.d` directories under
//! a system search path -- parameterized by sign-type name so the spki engine
//! reuses it; a verifier trusts the loaded set minus the revoked set.

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use ostrya_core::{Checksum, ObjectType, Value, base64};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::repo::Repo;

pub use ostrya_sign::{
    DummySigner, DummyVerifier, Ed25519Signer, Ed25519Verifier, Error, MAX_KEY_FILE, Result,
    SignFuture, SignKeys, SignatureInfo, Signer, Verifier, VerifyFuture, VerifyOutcome,
    append_signature, key_text, read_key_file, read_key_source,
};

impl Repo {
    /// Sign the commit `checksum` with `signer` and append the signature to the
    /// commit's detached metadata.
    ///
    /// The signed payload is the commit object's canonical bytes. The signature
    /// is appended to the engine's `aay` array in the `.commitmeta` `a{sv}`
    /// dict, which is created if absent; other engines' arrays are untouched.
    ///
    /// The signature is made first, with no lock held. The call then takes
    /// the repository lock shared and the update lock, as
    /// [`Repo::begin_update`] does, and under both it loads the dict, adds the
    /// signature, and replaces the `.commitmeta` file atomically. So signers
    /// of one commit keep every signature, whether they run in several tasks
    /// of this process or in several processes, and whether they sign here or
    /// through [`Transaction::sign_commit`](crate::Transaction::sign_commit).
    /// The `ostree` tool can lose a signature in that case.
    ///
    /// Each of the two waits fails with [`Error::LockTimeout`](crate::Error::LockTimeout)
    /// after `lock-timeout-secs`, and the signature is then dropped. A caller
    /// that holds an [`UpdateGuard`](crate::UpdateGuard) of this repository
    /// waits for its own guard until the timeout, and with
    /// `lock-timeout-secs=-1` it waits forever.
    pub async fn sign_commit(&self, checksum: &Checksum, signer: &dyn Signer) -> crate::Result<()> {
        let data = self.load_object_bytes(ObjectType::Commit, checksum).await?;
        let signature = signer.sign(&data).await?;
        let fsync = self.config().fsync()?;
        let repo_mode = self.mode();
        let checksum = *checksum;
        let appends = vec![(signer.metadata_key().to_owned(), signature)];
        self.write_locked(move |repo| {
            let tmp_fd = crate::staging::open_tmp_dir(repo.repo_fd(), repo_mode)?;
            crate::commit::merge_detached_blocking(
                tmp_fd.as_fd(),
                repo.objects_fd(),
                &checksum,
                None,
                None,
                appends,
                fsync,
                repo_mode,
            )
        })
        .await
    }

    /// Verify the commit `checksum` against `verifiers`.
    ///
    /// Each verifier receives the signature blobs stored under its engine key in
    /// the commit's detached metadata (an empty set when the key or the metadata
    /// is absent) together with the commit's canonical bytes. The outcome is
    /// valid when any verifier reports a valid signature; every examined
    /// signature contributes a [`SignatureInfo`].
    pub async fn verify_commit(
        &self,
        checksum: &Checksum,
        verifiers: &[&dyn Verifier],
    ) -> crate::Result<VerifyOutcome> {
        let data = self.load_object_bytes(ObjectType::Commit, checksum).await?;
        let dict = self.read_commit_detached_metadata(checksum).await?;
        let mut outcome = VerifyOutcome::default();
        for verifier in verifiers {
            let signatures = match &dict {
                Some(dict) => signatures_for(dict, verifier.metadata_key()),
                None => Vec::new(),
            };
            let result = verifier.verify(&data, &signatures).await?;
            outcome.valid |= result.valid;
            outcome.signatures.extend(result.signatures);
        }
        Ok(outcome)
    }

    /// Delete signatures from a commit's detached metadata.
    ///
    /// Removes every blob stored under `metadata_key` for which
    /// `remove(payload, blob)` returns true, where `payload` is the commit's
    /// canonical bytes (the same payload [`sign_commit`](Self::sign_commit)
    /// signs) and `blob` is one stored signature. The predicate lets a caller
    /// match a signature to a key -- by re-verifying it for the sign-api
    /// engines, or by issuer fingerprint for GPG.
    ///
    /// The `.commitmeta` file is rewritten atomically: an emptied engine array
    /// drops its dict entry, and an emptied dict is written as the zero-length
    /// "no metadata" marker. Other engines' arrays are left in place. A commit
    /// with no detached metadata, or no entry for `metadata_key`, removes
    /// nothing and leaves the file untouched. Returns the number of signatures
    /// removed.
    ///
    /// Like [`sign_commit`](Self::sign_commit), this is a read-modify-write
    /// under the locks `sign_commit` takes, which the call takes after it
    /// loads the payload: `remove` runs on the dict the file holds at that
    /// moment, and a signer of the same commit, in this process or in another
    /// one, reaches the file before or after the removal, never inside it. The
    /// waits fail with [`Error::LockTimeout`](crate::Error::LockTimeout) as the
    /// waits of `sign_commit` do. `remove` runs on the blocking pool, so it
    /// must be `Send` and own what it matches against.
    pub async fn delete_signatures(
        &self,
        checksum: &Checksum,
        metadata_key: &str,
        mut remove: impl FnMut(&[u8], &[u8]) -> bool + Send + 'static,
    ) -> crate::Result<usize> {
        let payload = self.load_object_bytes(ObjectType::Commit, checksum).await?;
        let fsync = self.config().fsync()?;
        let repo_mode = self.mode();
        let checksum = *checksum;
        let metadata_key = metadata_key.to_owned();
        self.write_locked(move |repo| {
            let tmp_fd = crate::staging::open_tmp_dir(repo.repo_fd(), repo_mode)?;
            crate::commit::prune_detached_signatures_blocking(
                tmp_fd.as_fd(),
                repo.objects_fd(),
                &checksum,
                &metadata_key,
                &payload,
                &mut remove,
                fsync,
                repo_mode,
            )
        })
        .await
    }
}

/// Collect the signature blobs stored under `metadata_key` in the `a{sv}` dict
/// `dict`. Missing key, wrong shape, or non-byte-array elements yield an empty
/// set rather than an error, so a malformed foreign entry cannot fail a verify.
pub(crate) fn signatures_for(dict: &Value, metadata_key: &str) -> Vec<Vec<u8>> {
    let Some(value) = dict.dict_get(metadata_key) else {
        return Vec::new();
    };
    let array = match value.as_variant() {
        Some((_, inner)) => inner,
        None => value,
    };
    match array.as_array() {
        Some(blobs) => blobs
            .iter()
            .filter_map(|blob| blob.as_bytes().map(<[u8]>::to_vec))
            .collect(),
        None => Vec::new(),
    }
}

/// Remove from the `a{sv}` dict `dict` every signature blob stored under
/// `metadata_key` for which `remove(payload, blob)` returns true, dropping the
/// engine entry when its array empties. Returns the number of blobs removed.
/// Non-byte elements are kept, and other engines' entries are left untouched.
pub(crate) fn remove_signatures(
    dict: &mut Value,
    metadata_key: &str,
    payload: &[u8],
    remove: &mut dyn FnMut(&[u8], &[u8]) -> bool,
) -> crate::Result<usize> {
    let entries = match dict {
        Value::Array(entries) => entries,
        _ => {
            return Err(crate::Error::InvalidFormat(
                "detached metadata must be an a{sv} dict".into(),
            ));
        }
    };
    let mut removed = 0usize;
    let mut emptied = false;
    for entry in entries.iter_mut() {
        if let Value::Tuple(fields) = entry
            && let [key, value] = fields.as_mut_slice()
            && key.as_str() == Some(metadata_key)
        {
            let array = match value {
                Value::Variant(inner) => &mut inner.1,
                other => other,
            };
            let Value::Array(blobs) = array else {
                return Err(crate::Error::InvalidFormat(
                    "detached-metadata signature value is not an array".into(),
                ));
            };
            let before = blobs.len();
            blobs.retain(|blob| match blob.as_bytes() {
                Some(bytes) => !remove(payload, bytes),
                None => true,
            });
            removed = before - blobs.len();
            emptied = blobs.is_empty();
            break;
        }
    }
    if emptied {
        entries.retain(|entry| {
            entry
                .as_tuple()
                .and_then(<[Value]>::first)
                .and_then(Value::as_str)
                != Some(metadata_key)
        });
    }
    Ok(removed)
}

/// The system directories searched for sign-api keys, in order. The second is
/// `<datadir>/ostree`.
const SYSTEM_KEY_ROOTS: [&str; 2] = ["/etc/ostree", "/usr/share/ostree"];

/// Load the sign-api key store for `sign_type` from the system search path
/// (`/etc/ostree` and `/usr/share/ostree`).
pub fn load_sign_keys(sign_type: &str) -> crate::Result<SignKeys> {
    let roots: Vec<PathBuf> = SYSTEM_KEY_ROOTS.iter().map(PathBuf::from).collect();
    let refs: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
    load_sign_keys_from(&refs, sign_type)
}

/// A verifier built from the system sign-api key store.
///
/// The engines come from `ostrya-sign`, which holds no system search path, so
/// the constructor is an extension trait here. A caller brings the trait into
/// scope to call it.
pub trait FromSystemKeys: Sized {
    /// Build a verifier from the system sign-api key store: `trusted.<type>`
    /// and `revoked.<type>` and their `.d` directories under the system search
    /// path (see [`load_sign_keys`]), where `<type>` is the sign-type name of
    /// the engine.
    fn from_system_keys() -> crate::Result<Self>;
}

impl FromSystemKeys for Ed25519Verifier {
    /// Build a verifier from the system sign-api key store: `trusted.ed25519`
    /// and `revoked.ed25519` and their `.d` directories under the system search
    /// path (see [`load_sign_keys`]).
    fn from_system_keys() -> crate::Result<Ed25519Verifier> {
        Ok(Ed25519Verifier::from_sign_keys(load_sign_keys("ed25519")?)?)
    }
}

#[cfg(feature = "sign-spki")]
impl FromSystemKeys for crate::spki::SpkiVerifier {
    /// Build a verifier from the system sign-api key store: `trusted.spki` and
    /// `revoked.spki` and their `.d` directories under the system search path
    /// (see [`load_sign_keys`]).
    fn from_system_keys() -> crate::Result<crate::spki::SpkiVerifier> {
        Ok(crate::spki::SpkiVerifier::from_sign_keys(load_sign_keys(
            "spki",
        )?)?)
    }
}

/// Load the sign-api key store for `sign_type` from the given search roots.
///
/// Under each root, reads the `trusted.<type>` file and every file in the
/// `trusted.<type>.d/` directory, and likewise `revoked.<type>` and
/// `revoked.<type>.d/`. Each line is one base64 key; blank and whitespace-only
/// lines are skipped and any other line must decode. A missing file or
/// directory is not an error. Directory entries are read in sorted name order.
///
/// Every file is read under the rule `read_key_source` states: only a regular
/// file, and only up to `MAX_KEY_FILE`. A path of another kind and a file over
/// the ceiling are each refused by that file's own name.
pub fn load_sign_keys_from(roots: &[&Path], sign_type: &str) -> crate::Result<SignKeys> {
    let mut keys = SignKeys::default();
    for root in roots {
        collect_keys(root, &format!("trusted.{sign_type}"), &mut keys.trusted)?;
        collect_keys(root, &format!("revoked.{sign_type}"), &mut keys.revoked)?;
    }
    Ok(keys)
}

/// Read `<root>/<base>` and every file in `<root>/<base>.d/` into `out`.
fn collect_keys(root: &Path, base: &str, out: &mut Vec<Vec<u8>>) -> crate::Result<()> {
    read_key_lines(&root.join(base), out)?;
    let dir = root.join(format!("{base}.d"));
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    for file in files {
        read_key_lines(&file, out)?;
    }
    Ok(())
}

/// Read one base64-per-line key file of the store into `out`, under the rule
/// [`read_key_source`] states. A missing file is not an error.
fn read_key_lines(path: &Path, out: &mut Vec<Vec<u8>>) -> crate::Result<()> {
    let subject = format!("the key file '{}'", path.display());
    let Some(bytes) = read_key_path(path, &subject, MAX_KEY_FILE)? else {
        return Ok(());
    };
    for line in key_text(bytes, &subject)?.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push(base64::decode(line)?);
    }
    Ok(())
}

/// Read the key source at `path` whole, up to `ceiling`, or `None` where no file
/// is there. `subject` is what a refusal names the source by, so an operator can
/// find the entry that named it.
pub(crate) fn read_key_path(
    path: &Path,
    subject: &str,
    ceiling: u64,
) -> crate::Result<Option<Vec<u8>>> {
    // `NONBLOCK` so a fifo answers the open rather than waiting for a writer.
    // On a regular file the flag has no effect on the read below.
    let fd = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => {
            return Err(crate::Error::Signature(format!(
                "{subject} cannot be opened: {e}"
            )));
        }
    };
    Ok(Some(read_key_source(
        std::fs::File::from(fd),
        subject,
        ceiling,
    )?))
}
