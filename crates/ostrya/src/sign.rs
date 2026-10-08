//! Commit signatures, the signing engines, and the key store.
//!
//! The engines, the [`Signer`] and [`Verifier`] traits, and [`SignKeys`] come
//! from the `ostrya-sign` crate. A [`Signer`] signs a byte payload. A
//! [`Verifier`] verifies signature blobs against a byte payload. The same
//! engines sign commits and the summary ([`Repo::sign_summary`]).
//!
//! The entry points are:
//!
//! - the signatures of a commit: [`Repo::sign_commit`],
//!   [`Repo::verify_commit`], and [`Repo::delete_signatures`]
//! - the key store of the ed25519 and spki engines: [`load_sign_keys`] and
//!   [`load_sign_keys_from`]
//! - a verifier that trusts the system key store: [`FromSystemKeys`]
//!
//! The engines are:
//!
//! - ed25519: [`Ed25519Signer`] and [`Ed25519Verifier`]
//! - the dummy engine for tests: [`DummySigner`] and [`DummyVerifier`]
//! - spki: feature `sign-spki`
//! - GPG: features `verify-gpg` and `sign-gpg`

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use ostrya_core::{Checksum, ObjectType, Value, base64};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::repo::Repo;

pub use ostrya_sign::{
    DummySigner, DummyVerifier, Ed25519Signer, Ed25519Verifier, MAX_KEY_FILE, SignFuture, SignKeys,
    SignatureInfo, Signer, Verifier, VerifyFuture, VerifyOutcome, append_signature, key_text,
    read_key_file, read_key_source,
};
#[doc(hidden)]
pub use ostrya_sign::{Error, Result};

/// Methods that sign and verify commits.
impl Repo {
    /// Signs the commit `checksum` with `signer` and stores the signature.
    ///
    /// The signed payload is the serialized commit object. These bytes are the
    /// normal-form GVariant bytes that give the commit checksum.
    ///
    /// # Storage
    ///
    /// The signature goes into the detached metadata of the commit, the
    /// `.commitmeta` file. The file holds an `a{sv}` dict. Each engine owns one
    /// key of the dict, the [`metadata_key`](Signer::metadata_key) of the
    /// signer. The value of the key is an `aay`, with one `ay` element for each
    /// signature blob.
    ///
    /// The call appends the signature as one `ay` element. If the dict has no
    /// key for the engine, the call adds the key. If the file is absent, the
    /// call creates the file. The arrays of the other engines stay unchanged.
    /// The new file replaces the old file atomically.
    ///
    /// # Locks
    ///
    /// The call makes the signature first, with no lock held. Then it takes
    /// the repository lock as [`Shared`](crate::LockKind::Shared) and the
    /// update lock, as [`begin_update`](Repo::begin_update) does. Under both
    /// locks, it reads the dict, adds the signature, and writes the file.
    ///
    /// Concurrent signers of one commit keep every signature, because each
    /// signer reads and writes the file under both locks. This applies to
    /// tasks of this process, to other processes, and to
    /// [`Transaction::sign_commit`](crate::Transaction::sign_commit). The
    /// `ostree` command can lose a signature in this case.
    ///
    /// If the caller holds an [`UpdateGuard`](crate::UpdateGuard) of this
    /// repository, the call waits for that guard.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the commit object is not in the object
    ///   store.
    /// - [`Error::Signature`] if `signer` cannot make a signature.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`. Each of the two waits gets the full timeout. The
    ///   call then stores no signature.
    /// - [`Error::Core`] if `[core] fsync` or `[core] locking` is not a
    ///   boolean, or if `[core] lock-timeout-secs` is not an integer.
    /// - [`Error::Core`] if the `.commitmeta` file does not parse as an
    ///   `a{sv}` dict.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is less than
    ///   `-1`.
    /// - [`Error::InvalidFormat`] if the value of the key of the engine is not
    ///   an array.
    /// - [`Error::Io`] if the commit object or the `.commitmeta` file is larger
    ///   than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    /// - [`Error::Io`] with `EXDEV` if `tmp/` and `objects/` are on different
    ///   file systems.
    /// - [`Error::Io`] if another file system operation fails.
    ///
    /// [`Error::ObjectNotFound`]: crate::Error::ObjectNotFound
    /// [`Error::Signature`]: crate::Error::Signature
    /// [`Error::LockTimeout`]: crate::Error::LockTimeout
    /// [`Error::Core`]: crate::Error::Core
    /// [`Error::InvalidFormat`]: crate::Error::InvalidFormat
    /// [`Error::Io`]: crate::Error::Io
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

    /// Verifies the signatures of the commit `checksum` with `verifiers`.
    ///
    /// Each verifier gets the serialized commit object and the signature
    /// blobs under its key in the detached metadata of the commit. If the key
    /// or the detached metadata is absent, the verifier gets no blob. If the
    /// value of the key is not an array, the verifier gets no blob. The
    /// verifier does not get an element of the array that is not a byte
    /// string.
    ///
    /// If at least one verifier reports a valid signature, the outcome is
    /// valid. The outcome holds the [`SignatureInfo`] records of all
    /// verifiers, in the order of `verifiers`.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the commit object is not in the object
    ///   store.
    /// - [`Error::Core`] if the `.commitmeta` file does not parse as an
    ///   `a{sv}` dict.
    /// - [`Error::Signature`] if a verifier fails with the `Signature` variant
    ///   of [`ostrya_sign::Error`], or with a variant that the conversion to
    ///   [`Error`](crate::Error) does not name. Of the verifiers that this
    ///   crate exports, only `GpgVerifier` fails: if a blob is larger than
    ///   1 MiB, holds more than 64 signature packets, or makes the OpenPGP
    ///   parser panic.
    /// - [`Error::InvalidFormat`] or [`Error::Core`] if a verifier of another
    ///   crate fails with the variant of the same name of
    ///   [`ostrya_sign::Error`].
    /// - [`Error::Io`] if the commit object or the `.commitmeta` file is larger
    ///   than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), or if a file
    ///   system operation fails.
    ///
    /// [`Error::ObjectNotFound`]: crate::Error::ObjectNotFound
    /// [`Error::Core`]: crate::Error::Core
    /// [`Error::Signature`]: crate::Error::Signature
    /// [`Error::InvalidFormat`]: crate::Error::InvalidFormat
    /// [`Error::Io`]: crate::Error::Io
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

    /// Removes the signatures of a commit that `remove` selects.
    ///
    /// The call removes each blob under `metadata_key` in the detached
    /// metadata for which `remove(payload, blob)` returns `true`. `payload` is
    /// the serialized commit object, the payload that
    /// [`sign_commit`](Self::sign_commit) signs. `blob` is one stored
    /// signature. With the predicate, a caller can match a signature to a key.
    /// For example, the predicate can verify the blob again (ed25519 and
    /// spki), or read the issuer fingerprint (GPG). The call returns the
    /// number of signatures that it removed.
    ///
    /// # Rewrite rules
    ///
    /// - The new `.commitmeta` file replaces the old file atomically.
    /// - If the array of the engine becomes empty, the call removes the key
    ///   from the dict.
    /// - If the dict becomes empty, the call writes the zero-length file that
    ///   marks no metadata.
    /// - The arrays of the other engines stay unchanged. An element that is
    ///   not a byte string stays in the array.
    /// - If the commit has no detached metadata, or no blob matches, the call
    ///   removes nothing and does not write the file.
    ///
    /// # Locks
    ///
    /// The call loads the payload first. Then it takes the locks that
    /// [`sign_commit`](Self::sign_commit) takes, and reads, edits, and writes
    /// the dict under them. `remove` runs on the dict that the file holds at
    /// that time. A signer of the same commit, in this process or in
    /// another process, writes the file before or after the removal.
    ///
    /// `remove` runs on the blocking pool. For this reason it must be `Send`
    /// and own the data that it matches against.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the commit object is not in the object
    ///   store.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`. Each of the two waits gets the full timeout.
    /// - [`Error::Core`] if `[core] fsync` or `[core] locking` is not a
    ///   boolean, or if `[core] lock-timeout-secs` is not an integer.
    /// - [`Error::Core`] if the `.commitmeta` file does not parse as an
    ///   `a{sv}` dict.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is less than
    ///   `-1`.
    /// - [`Error::InvalidFormat`] if the value of `metadata_key` is not an
    ///   array.
    /// - [`Error::Io`] if the commit object or the `.commitmeta` file is larger
    ///   than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    /// - [`Error::Io`] with `EXDEV` if `tmp/` and `objects/` are on different
    ///   file systems.
    /// - [`Error::Io`] if another file system operation fails.
    ///
    /// [`Error::ObjectNotFound`]: crate::Error::ObjectNotFound
    /// [`Error::LockTimeout`]: crate::Error::LockTimeout
    /// [`Error::Core`]: crate::Error::Core
    /// [`Error::InvalidFormat`]: crate::Error::InvalidFormat
    /// [`Error::Io`]: crate::Error::Io
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

/// Returns the signature blobs under `metadata_key` in the `a{sv}` dict `dict`.
///
/// If the key is absent or its value is not an array, the result is empty.
/// The result skips each element that is not a byte string. A malformed entry
/// of another writer does not cause an error, so it cannot fail a
/// verification.
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

/// Removes each blob under `metadata_key` in the `a{sv}` dict `dict` for which
/// `remove(payload, blob)` returns `true`.
///
/// If the array of the engine becomes empty, the call removes the entry of the
/// engine. An element that is not a byte string stays. The entries of the
/// other engines stay unchanged. Returns the number of removed blobs.
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

/// The system directories of the key store, in search order.
///
/// The second directory is `<datadir>/ostree`.
const SYSTEM_KEY_ROOTS: [&str; 2] = ["/etc/ostree", "/usr/share/ostree"];

/// Loads the trusted and revoked keys of `sign_type` from the system key store.
///
/// The call gives the directories `/etc/ostree` and `/usr/share/ostree`, in
/// this order, to [`load_sign_keys_from`]. That function states the files that
/// the call reads. `sign_type` is the sign-type name of the engine: `ed25519`
/// or `spki`.
///
/// # Errors
///
/// The errors of [`load_sign_keys_from`]:
///
/// - [`Error::Signature`] if a key file cannot be opened or read, is not a
///   regular file, is larger than [`MAX_KEY_FILE`], or is not valid UTF-8.
/// - [`Error::Core`] if a line of a key file is not valid base64.
/// - [`Error::Io`] if a `.d` directory cannot be read.
///
/// [`Error::Signature`]: crate::Error::Signature
/// [`Error::Core`]: crate::Error::Core
/// [`Error::Io`]: crate::Error::Io
pub fn load_sign_keys(sign_type: &str) -> crate::Result<SignKeys> {
    let roots: Vec<PathBuf> = SYSTEM_KEY_ROOTS.iter().map(PathBuf::from).collect();
    let refs: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
    load_sign_keys_from(&refs, sign_type)
}

/// A verifier that loads its keys from the system key store.
///
/// The `ostrya-sign` crate has no system search path, so this crate adds the
/// constructor as a trait. A caller brings the trait into scope to call it.
pub trait FromSystemKeys: Sized {
    /// Creates a verifier from the keys of its engine in the system key store.
    ///
    /// The call reads `trusted.<type>`, `revoked.<type>`, and their `.d`
    /// directories with [`load_sign_keys`]. `<type>` is the sign-type name of
    /// the engine.
    ///
    /// # Errors
    ///
    /// - The errors of [`load_sign_keys`].
    /// - [`Error::Signature`] if the engine refuses a key.
    ///
    /// [`Error::Signature`]: crate::Error::Signature
    fn from_system_keys() -> crate::Result<Self>;
}

impl FromSystemKeys for Ed25519Verifier {
    /// Creates an ed25519 verifier from the system key store.
    ///
    /// The call reads `trusted.ed25519`, `revoked.ed25519`, and their `.d`
    /// directories with [`load_sign_keys`].
    ///
    /// # Errors
    ///
    /// - The errors of [`load_sign_keys`].
    /// - [`Error::Signature`] if a key is not 32 bytes long, or if a trusted key
    ///   that is not revoked is not a valid curve point. The rules are on
    ///   [`Ed25519Verifier::new`].
    ///
    /// [`Error::Signature`]: crate::Error::Signature
    fn from_system_keys() -> crate::Result<Ed25519Verifier> {
        Ok(Ed25519Verifier::from_sign_keys(load_sign_keys("ed25519")?)?)
    }
}

#[cfg(feature = "sign-spki")]
impl FromSystemKeys for crate::spki::SpkiVerifier {
    /// Creates an spki verifier from the system key store.
    ///
    /// The call reads `trusted.spki`, `revoked.spki`, and their `.d`
    /// directories with [`load_sign_keys`].
    ///
    /// # Errors
    ///
    /// - The errors of [`load_sign_keys`].
    /// - [`Error::Signature`] if a key does not parse. The rules are on
    ///   [`SpkiVerifier::new`](crate::spki::SpkiVerifier::new).
    ///
    /// [`Error::Signature`]: crate::Error::Signature
    fn from_system_keys() -> crate::Result<crate::spki::SpkiVerifier> {
        Ok(crate::spki::SpkiVerifier::from_sign_keys(load_sign_keys(
            "spki",
        )?)?)
    }
}

/// Loads the trusted and revoked keys of `sign_type` from the directories
/// `roots`.
///
/// # Files
///
/// The call reads each root in order and adds its keys to one [`SignKeys`]
/// set. Under each root, it reads these files, in this order:
///
/// 1. The file `trusted.<type>`, then each regular file in the directory
///    `trusted.<type>.d/`, in sorted name order.
/// 2. The file `revoked.<type>`, then each regular file in the directory
///    `revoked.<type>.d/`, in sorted name order.
///
/// `<type>` is `sign_type`. A missing file or directory is not an error. In a
/// `.d` directory, the call reads only regular files. It skips a symlink, also
/// a symlink to a regular file. The call follows a symlink at `trusted.<type>`
/// or `revoked.<type>`.
///
/// Each line of a file holds one base64 key. The call skips an empty line and
/// a line of white space only. Each other line must decode.
///
/// The call reads each file with [`read_key_source`]: only a regular file, and
/// only up to [`MAX_KEY_FILE`] bytes. The error for a file names that file.
///
/// # Errors
///
/// - [`Error::Signature`] with the message
///   `the key file '<path>' cannot be opened: <e>` if the open of a file fails
///   for a reason other than a missing file.
/// - [`Error::Signature`] if a file cannot be read, is not a regular file, is
///   larger than [`MAX_KEY_FILE`], or is not valid UTF-8.
///   [`read_key_source`] and [`key_text`] give the messages.
/// - [`Error::Core`] if a line is not valid base64.
/// - [`Error::Io`] if a `.d` directory cannot be read, or if it is not a
///   directory.
///
/// [`Error::Signature`]: crate::Error::Signature
/// [`Error::Core`]: crate::Error::Core
/// [`Error::Io`]: crate::Error::Io
pub fn load_sign_keys_from(roots: &[&Path], sign_type: &str) -> crate::Result<SignKeys> {
    let mut keys = SignKeys::default();
    for root in roots {
        collect_keys(root, &format!("trusted.{sign_type}"), &mut keys.trusted)?;
        collect_keys(root, &format!("revoked.{sign_type}"), &mut keys.revoked)?;
    }
    Ok(keys)
}

/// Reads the keys of `<root>/<base>` and of each regular file in
/// `<root>/<base>.d/` into `out`.
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

/// Reads the keys of one key file of the store into `out`.
///
/// The file holds one base64 key on each line. The read obeys the rules of
/// [`read_key_source`]. A missing file is not an error.
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

/// Returns the whole key source at `path`, up to `ceiling` bytes, or `None` if
/// no file is there.
///
/// Each error names the source by `subject`, so an operator can find the entry
/// that named the source.
pub(crate) fn read_key_path(
    path: &Path,
    subject: &str,
    ceiling: u64,
) -> crate::Result<Option<Vec<u8>>> {
    // With `NONBLOCK`, the open of a fifo returns at once. Without the flag,
    // the open waits for a writer. On a regular file, the flag has no effect
    // on the read that follows.
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
