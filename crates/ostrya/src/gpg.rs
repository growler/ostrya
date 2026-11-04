//! GPG (OpenPGP) signature verification, keyring management, and signing.
//!
//! The `verify-gpg` feature turns on this module. [`GpgVerifier`] and
//! [`GpgKey`] are items of the `ostrya-sign` crate, re-exported here. The
//! verifier parses keyrings and verifies signatures in the process, with
//! rPGP. This module adds the items that read ostree paths and the keyring
//! files of a repository: the trait [`FromOstreeKeyrings`], which builds a
//! verifier from the ostree keyring paths, [`Repo::gpg_import_keys`], and
//! [`Repo::gpg_list_keys`].
//!
//! The `sign-gpg` feature adds `GpgSigner`, which signs with
//! `gpg --detach-sign`. This feature also turns on `verify-gpg`. `GpgSigner` is
//! an item of the `ostrya-sign` crate, re-exported here.
//!
//! This crate runs the `gpg` command for these operations only:
//!
//! - The signing run of `GpgSigner`.
//! - The secret-key listing of `GpgSigner`.
//! - The export of `GpgSigner` under the `receive` and `sign-gpg` features.
//!   It gives the minimal public certificate of a server signing key, so the
//!   receive path can recognize a signature that this key made.
//!
//! The private key stays with GnuPG and its agent. It never goes through this
//! crate.

use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};

use ostrya_sign::{MAX_KEYRING, gpg_keyring_keys, gpg_merge_keyring, gpg_offered_keys};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::config::{remote_keyring_name, valid_remote_name};
use crate::error::{Error, Result};
use crate::remotes_dir;
use crate::repo::{RemotesDir, Repo};
use crate::sign::{read_key_path, read_key_source};
use crate::summary::{read_root_file_blocking, write_root_file_blocking};

#[cfg(feature = "sign-gpg")]
pub use ostrya_sign::GpgSigner;
pub use ostrya_sign::{GpgKey, GpgVerifier};

/// The system directory of the keyrings that every remote trusts.
const GLOBAL_TRUSTED_GPG_D: &str = "/usr/share/ostree/trusted.gpg.d";
/// The environment variable that overrides the global trusted-keyring
/// directory. The `ostree` command reads the same variable.
const OSTREE_GPG_HOME_ENV: &str = "OSTREE_GPG_HOME";

/// A GPG verifier that loads its keyrings from the ostree keyring paths.
///
/// The `ostrya-sign` crate has no ostree search path, so this crate adds the
/// constructors as a trait. A caller brings the trait into scope to call them.
///
/// The keyring of a remote is `<remote>.trustedkeys.gpg` in the repository.
/// [`for_remote_in`](FromOstreeKeyrings::for_remote_in) reads the keyrings of
/// a repository handle. When the repository holds no keyring of the remote,
/// it reads the keyring of the remote in the remotes directory of the handle.
/// The other constructors take a repository path or the bytes of a keyring,
/// and read no keyring of a remotes directory.
pub trait FromOstreeKeyrings: Sized {
    /// Creates a verifier from the keyrings that `remote` trusts.
    ///
    /// The trusted set is the union of these keyrings:
    ///
    /// - `<remote>.trustedkeys.gpg` in the repository at `repo_path`.
    /// - The global trusted set of
    ///   [`from_system_trust`](FromOstreeKeyrings::from_system_trust), only
    ///   when the keyring of the remote does not exist.
    ///
    /// The call reads no keyring of a remotes directory.
    /// [`for_remote_in`](FromOstreeKeyrings::for_remote_in) reads it.
    ///
    /// If a path does not exist, the load skips it. Each keyring must be a
    /// binary OpenPGP packet stream, so an armored keyring is refused.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if [`valid_remote_name`] refuses `remote`.
    ///   The call refuses the name before it reads a keyring.
    /// - The errors of
    ///   [`for_remote_keypath`](FromOstreeKeyrings::for_remote_keypath).
    fn for_remote(repo_path: &Path, remote: &str) -> Result<Self>;

    /// Creates a verifier from the keyrings that `remote` trusts, together
    /// with the `gpgkeypath` entries of the remote.
    ///
    /// The trusted set is the union of these keyrings, in load order:
    ///
    /// - `<remote>.trustedkeys.gpg` in the repository at `repo_path`.
    /// - The global trusted set of
    ///   [`from_system_trust`](FromOstreeKeyrings::from_system_trust), only
    ///   when the keyring of the remote does not exist.
    /// - Each entry of `keypath`, which holds the values of the `gpgkeypath`
    ///   key of the remote.
    ///
    /// The call reads no keyring of a remotes directory.
    /// [`for_remote_in`](FromOstreeKeyrings::for_remote_in) reads it.
    ///
    /// Where two keyrings hold one key, the first certificate in load order
    /// supplies the user id of a signature report.
    ///
    /// The rules of
    /// [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings) apply
    /// to each source. The keyring of the remote exists if the open of its
    /// path does not give "No such file or directory". So an empty file is a
    /// keyring with no key, and a symlink to no file is no keyring.
    ///
    /// The provided method reads the repository keyring and gives its bytes
    /// to [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings).
    /// [`for_remote`](FromOstreeKeyrings::for_remote) of [`GpgVerifier`] is
    /// this call with an empty `keypath`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if [`valid_remote_name`] refuses `remote`.
    ///   The call refuses the name before it reads a keyring.
    /// - [`Error::Signature`] if the repository keyring cannot be read, for
    ///   example because it is a directory. The call reads this keyring
    ///   before the other sources, so this error comes first.
    /// - The errors of
    ///   [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings).
    fn for_remote_keypath(repo_path: &Path, remote: &str, keypath: &[String]) -> Result<Self> {
        if !valid_remote_name(remote) {
            return Err(Error::InvalidInput(format!(
                "invalid remote name: {remote}"
            )));
        }
        let keyring = repo_path.join(format!("{remote}.trustedkeys.gpg"));
        let repo_keyring = read_keyring_path(&keyring)?;
        Self::for_remote_keyrings(repo_keyring, remote, keypath)
    }

    /// Creates a verifier from the keyrings that `remote` of the repository
    /// handle `repo` trusts, together with the `gpgkeypath` entries of the
    /// remote.
    ///
    /// The keyring of the remote is one of these two files:
    ///
    /// - `<remote>.trustedkeys.gpg` in the repository.
    /// - `<remote>.trustedkeys.gpg` in the remotes directory of the handle
    ///   ([`Repo::remotes_dir`]), only when the repository holds no keyring
    ///   of the remote. A handle with no remotes directory reads no such
    ///   file.
    ///
    /// The trusted set is the union of these keyrings, in load order:
    ///
    /// - The keyring of the remote.
    /// - The global trusted set of
    ///   [`from_system_trust`](FromOstreeKeyrings::from_system_trust), only
    ///   when neither file exists.
    /// - Each entry of `keypath`, which holds the values of the `gpgkeypath`
    ///   key of the remote.
    ///
    /// A file exists if its open does not give "No such file or directory".
    /// So an empty repository keyring hides the keyring of the remotes
    /// directory and stops the read of the global trusted directory. A
    /// symlink to no file is no keyring. The rules of
    /// [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings) apply
    /// to each source. The call blocks the calling thread while it reads the
    /// keyrings.
    ///
    /// The provided method reads the keyring of the remote and gives its
    /// bytes to [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings).
    /// The method of [`GpgVerifier`] names the keyring of the remotes
    /// directory in a refusal, as `the keyring '<path>' of the remotes
    /// directory`. `<path>` is the file name joined to the path of a
    /// [`Path`](RemotesDir::Path) value as given, or to the path of an
    /// [`InRepo`](RemotesDir::InRepo) value, relative to the repository. For
    /// a [`Fd`](RemotesDir::Fd) value, `<path>` is the file name alone.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if [`valid_remote_name`] refuses `remote`.
    ///   The call refuses the name before it reads a keyring.
    /// - [`Error::Signature`] if a keyring of the remote cannot be opened or
    ///   read for a reason other than its absence, for example because it is
    ///   a directory. The message names the keyring. The call reads the
    ///   keyrings of the remote before the other sources, so this error comes
    ///   first.
    /// - The errors of
    ///   [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings).
    fn for_remote_in(repo: &Repo, remote: &str, keypath: &[String]) -> Result<Self> {
        let keyring = read_remote_keyring(repo.repo_fd(), repo.remotes_dir(), remote)?;
        Self::for_remote_keyrings(keyring.map(|keyring| keyring.bytes), remote, keypath)
    }

    /// Creates a verifier from the whole trusted set of a remote.
    ///
    /// `repo_keyring` holds the bytes of the keyring of the remote, or `None`
    /// if the remote has no keyring. A caller that holds a descriptor and no
    /// path reads this file itself. A pull trusts the union of these keyrings,
    /// in load order:
    ///
    /// - `repo_keyring`.
    /// - The global trusted set of
    ///   [`from_system_trust`](FromOstreeKeyrings::from_system_trust), only
    ///   when `repo_keyring` is `None`. An empty keyring exists, so it stops
    ///   the read of the global trusted directory.
    /// - Each entry of `keypath`, which holds the values of the `gpgkeypath`
    ///   key of the remote.
    ///
    /// The call reads no `<remote>.trustedkeys.gpg` file, in the repository
    /// or in a remotes directory. A refusal of `repo_keyring` names it as
    /// `the keyring '<remote>.trustedkeys.gpg'`.
    ///
    /// `repo_keyring` and each global keyring file must be a binary OpenPGP
    /// packet stream. The load refuses each keyring that
    /// [`add_binary_keyring`](GpgVerifier::add_binary_keyring) refuses, and
    /// the refusal names the keyring. Armor, a GnuPG keybox, bytes that do not
    /// frame as a whole packet stream, and a keyring over a limit are
    /// examples. An empty keyring adds no key.
    ///
    /// A `keypath` entry is a keyring file or a directory of keyring files.
    /// The load reads each regular file of a directory, with any name, in name
    /// order. It does not read a subdirectory or a symlink of the directory.
    /// If an entry cannot be read, the build fails. So a missing keyring path
    /// gives an error, and the trusted set does not become smaller with no
    /// message. The load skips a `keypath` file that does not hold the bytes
    /// `-----BEGIN PGP` and that is a GnuPG keybox or is not a whole OpenPGP
    /// packet stream. Such a file adds no key and gives no message. Each other
    /// `keypath` file that the load cannot read whole as a keyring fails the
    /// build: a file that cannot be read, a file over a limit of a keyring,
    /// armor that does not decode to a keyring, and a packet stream that the
    /// parser refuses.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if [`valid_remote_name`] refuses `remote`.
    ///   The call refuses the name before it reads a keyring.
    /// - [`Error::Signature`] if the metadata of a `keypath` entry cannot be
    ///   read, or a directory that an entry names cannot be listed. The
    ///   message names `gpgkeypath` and the entry.
    /// - [`Error::Signature`] if the global trusted directory is read and
    ///   cannot be listed for a reason other than its absence. The message
    ///   names the directory.
    /// - The errors of
    ///   [`add_binary_keyring`](GpgVerifier::add_binary_keyring) for
    ///   `repo_keyring`.
    /// - The errors of
    ///   [`add_binary_keyring_files`](GpgVerifier::add_binary_keyring_files)
    ///   for each global keyring file.
    /// - The errors of
    ///   [`add_keyring_files_skipping`](GpgVerifier::add_keyring_files_skipping)
    ///   for each `keypath` file.
    fn for_remote_keyrings(
        repo_keyring: Option<Vec<u8>>,
        remote: &str,
        keypath: &[String],
    ) -> Result<Self>;

    /// Creates a verifier from the global trusted keyrings only.
    ///
    /// The global trusted set is the keyrings in the directory that the
    /// `OSTREE_GPG_HOME` environment variable names. If this variable is unset
    /// or empty, the directory is `/usr/share/ostree/trusted.gpg.d/`. The load
    /// takes each regular file whose name ends in `.gpg`, a hidden name and
    /// the name `.gpg` included. It skips a symlink, a subdirectory, and a
    /// name that ends in `.GPG`. The keyrings load in name order. No keyring
    /// of a remote takes part.
    ///
    /// Each file must be a binary OpenPGP packet stream. The load refuses
    /// each file that
    /// [`add_binary_keyring_files`](GpgVerifier::add_binary_keyring_files)
    /// refuses, and the refusal names the path. So an armored file, a GnuPG
    /// keybox, and a file that is not a keyring are refused. An empty file
    /// adds no key.
    ///
    /// This is the trust for a commit that names no remote. If the directory
    /// does not exist, the trusted set is empty.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if the directory cannot be listed for a reason
    ///   other than its absence. A path that names a regular file is an
    ///   example. The message names the directory.
    /// - The errors of
    ///   [`add_binary_keyring_files`](GpgVerifier::add_binary_keyring_files)
    ///   for each keyring file.
    fn from_system_trust() -> Result<Self>;
}

impl FromOstreeKeyrings for GpgVerifier {
    fn for_remote(repo_path: &Path, remote: &str) -> Result<GpgVerifier> {
        GpgVerifier::for_remote_keypath(repo_path, remote, &[])
    }

    fn for_remote_in(repo: &Repo, remote: &str, keypath: &[String]) -> Result<GpgVerifier> {
        let keyring = read_remote_keyring(repo.repo_fd(), repo.remotes_dir(), remote)?;
        remote_keyrings(keyring, remote, keypath, true)
    }

    fn for_remote_keyrings(
        repo_keyring: Option<Vec<u8>>,
        remote: &str,
        keypath: &[String],
    ) -> Result<GpgVerifier> {
        let keyring = repo_keyring.map(|bytes| RemoteKeyring::in_repo(bytes, remote));
        remote_keyrings(keyring, remote, keypath, true)
    }

    fn from_system_trust() -> Result<GpgVerifier> {
        let mut verifier = GpgVerifier::default();
        verifier.add_binary_keyring_files(keyring_files_in(&global_trusted_dir())?)?;
        Ok(verifier)
    }
}

/// The keyring of a remote that a read found: the repository keyring, or the
/// keyring of the remotes directory of a handle.
pub(crate) struct RemoteKeyring {
    /// The bytes of the keyring.
    pub(crate) bytes: Vec<u8>,
    /// The name of the keyring in a refusal.
    pub(crate) subject: String,
}

impl RemoteKeyring {
    /// Returns the repository keyring of `remote`, with the bytes `bytes`.
    fn in_repo(bytes: Vec<u8>, remote: &str) -> RemoteKeyring {
        RemoteKeyring {
            bytes,
            subject: format!("the keyring '{}'", remote_keyring_name(remote)),
        }
    }
}

/// Reads the keyring of `remote` for the repository at `repo_fd`, with the
/// remotes directory `dir`.
///
/// The keyring is `<remote>.trustedkeys.gpg` of the repository. Only when no
/// file is at that name, the keyring is the file of that name in `dir`. If
/// `dir` is `None`, or neither file exists, the result is `None`. A file
/// exists if its open does not give "No such file or directory", so a
/// symlink to no file is no keyring, and an absent directory or an absent
/// parent of it holds no keyring. The read follows a symlink. The `ostree`
/// command was observed to follow a symlink at the repository keyring too.
///
/// The read refuses a remote name that [`valid_remote_name`] refuses with
/// [`Error::InvalidInput`], before it opens a file. Each other refusal is
/// [`Error::Signature`], and it names the keyring: a file that cannot be
/// opened for a reason other than its absence, a file that is not a regular
/// file, a file that cannot be read, and a file over [`MAX_KEYRING`]. The
/// call blocks the calling thread.
pub(crate) fn read_remote_keyring(
    repo_fd: BorrowedFd<'_>,
    dir: Option<&RemotesDir>,
    remote: &str,
) -> Result<Option<RemoteKeyring>> {
    if !valid_remote_name(remote) {
        return Err(Error::InvalidInput(format!(
            "invalid remote name: {remote}"
        )));
    }
    let name = remote_keyring_name(remote);
    let repo_subject = format!("the keyring '{name}'");
    if let Some(bytes) = read_keyring_at(repo_fd, Path::new(&name), &repo_subject)? {
        return Ok(Some(RemoteKeyring {
            bytes,
            subject: repo_subject,
        }));
    }
    let Some(dir) = dir else {
        return Ok(None);
    };
    let (base, at, display) = remotes_dir::entry(repo_fd, dir, &name);
    let subject = format!(
        "the keyring '{}' of the remotes directory",
        display.display()
    );
    Ok(read_keyring_at(base, &at, &subject)?.map(|bytes| RemoteKeyring { bytes, subject }))
}

/// Creates a verifier from the keyrings of a remote, as
/// [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings) does.
///
/// `keyring` is the keyring of the remote that [`read_remote_keyring`] gives,
/// and a refusal of it names its subject. If `global` is `false`, the global
/// trusted set takes no part, and the trusted set is `keyring` and the
/// entries of `keypath` alone. If `global` is `true`, the global trusted set
/// takes part only when `keyring` is `None`.
///
/// The call refuses a name that [`valid_remote_name`] refuses with
/// [`Error::InvalidInput`], before it reads a keyring.
pub(crate) fn remote_keyrings(
    keyring: Option<RemoteKeyring>,
    remote: &str,
    keypath: &[String],
    global: bool,
) -> Result<GpgVerifier> {
    let global_dir = global.then(global_trusted_dir);
    remote_keyrings_in(keyring, remote, keypath, global_dir.as_deref())
}

/// Runs [`remote_keyrings`] with the global trusted directory `global_dir`,
/// or with no global trusted set if `global_dir` is `None`.
///
/// `keyring` takes only a binary packet stream, and so does each global
/// keyring file. The call lists `global_dir` only when `keyring` is `None`.
///
/// The call adds `keyring`, then lists `global_dir` and the `keypath`
/// entries, and reads their files.
fn remote_keyrings_in(
    keyring: Option<RemoteKeyring>,
    remote: &str,
    keypath: &[String],
    global_dir: Option<&Path>,
) -> Result<GpgVerifier> {
    if !valid_remote_name(remote) {
        return Err(Error::InvalidInput(format!(
            "invalid remote name: {remote}"
        )));
    }
    // The verifier is new, and an error drops it. So the result trusts all
    // the sources or the call fails.
    let mut verifier = GpgVerifier::default();
    let own_keyring = keyring.is_some();
    if let Some(keyring) = keyring {
        verifier.add_binary_keyring(&keyring.bytes, &keyring.subject)?;
    }
    let global = match global_dir {
        Some(dir) if !own_keyring => keyring_files_in(dir)?,
        _ => Vec::new(),
    };
    let keypath = keypath_files("gpgkeypath", keypath)?;
    verifier.add_binary_keyring_files(global)?;
    verifier.add_keyring_files_skipping(keypath)?;
    Ok(verifier)
}

/// Creates a verifier from the keyrings that `keypath` names, and from no
/// other source.
///
/// No keyring of a remote and no global trusted set take part. Each entry
/// is a keyring file or a directory of keyring files, as
/// [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings) reads a
/// `keypath` entry. If an entry cannot be read, the build fails. The load
/// skips and refuses the files that
/// [`add_keyring_files_skipping`](GpgVerifier::add_keyring_files_skipping)
/// skips and refuses. `key` is the configuration key of the entries, and a
/// refusal names it.
///
/// If the keyrings hold no certificate, the build fails with
/// [`Error::Signature`]. An empty file, a directory with no regular file, and
/// a directory of files that the load skips are examples. A verifier with
/// no trusted key refuses every commit.
pub(crate) fn from_keypath(key: &str, keypath: &[String]) -> Result<GpgVerifier> {
    let mut verifier = GpgVerifier::default();
    verifier.add_keyring_files_skipping(keypath_files(key, keypath)?)?;
    if verifier.is_empty() {
        return Err(Error::Signature(format!(
            "{key} names no key: the keyrings it names hold no certificate"
        )));
    }
    Ok(verifier)
}

/// Methods that manage the GPG keyring of a remote.
impl Repo {
    /// Imports OpenPGP certificates into the trusted keyring of `remote`.
    ///
    /// The keyring is `<remote>.trustedkeys.gpg` at the repository root.
    /// `keys` is a binary or ASCII-armored certificate stream, as an exported
    /// public keyring is. The call returns the number of certificates that the
    /// keyring did not already hold.
    ///
    /// The call reads and writes the repository keyring alone. When the
    /// remotes directory of the handle ([`Repo::remotes_dir`]) holds the
    /// keyring of `remote` and no file is at the path of the repository
    /// keyring, the call creates the repository keyring. That keyring hides
    /// the keyring of the directory. To trust the keys of the directory too,
    /// import that keyring as well. The call copies the keys, so a later
    /// change to the keyring of the directory has no effect.
    ///
    /// If `key_ids` is not empty, the call imports only the keys that these
    /// selectors name. A selector is a fingerprint, a key id, or a user id
    /// substring.
    ///
    /// # Import rules
    ///
    /// The call replaces the keyring atomically. The keyring keeps the packet
    /// stream that it already held. The packets of each added certificate
    /// follow, as `keys` wrote them, with no Trust packets. The keyring is
    /// written in the binary form, so an armored keyring keeps its packets and
    /// loses its armor. `gpg` and the `ostree` command both read a keyring of
    /// this form.
    ///
    /// If the keyring already holds a key, the call keeps the certificate of
    /// that key as it is, and counts the key as already held. So a new user id
    /// or a new subkey of a held key gets into the keyring only through
    /// [`Repo::remove_remote_keyring`] and a new import. The `ostree` command
    /// merges the offered user ids, signatures, and subkeys into the held
    /// certificate. Both report `Imported 0 GPG keys`.
    ///
    /// Two statements are exceptions. Each one replaces the held certificate:
    ///
    /// - A key revocation signature that verifies under the key that it
    ///   revokes, or under a designated revoker of that key. So a revoked key
    ///   stops speaking for the remote.
    /// - A key expiry that is later than the expiry of the held certificate.
    ///   An absent expiry is later than any instant. So a key whose owner
    ///   extended its life speaks again.
    ///
    /// The call looks for a designated revoker in all certificates of the
    /// offered stream and of the keyring. Each replacement writes the keyring
    /// again, with no Trust packets, and the count still treats the key as
    /// already held. A bare revocation certificate holds no public-key packet
    /// and no certificate, so the call refuses it. The re-export of the revoked
    /// key is the stream that brings a revocation in.
    ///
    /// The offered stream is untrusted input. It has
    /// [the limits of a keyring](GpgVerifier#limits-of-a-keyring). The offered
    /// stream and the keyring of the remote both go through the reader of a
    /// verification load. So if either stream does not frame to its end, the
    /// import fails, and the keyring does not change.
    ///
    /// # Locks
    ///
    /// The call takes the repository lock shared, as
    /// [`LockKind`](crate::LockKind) describes. It then takes the update lock,
    /// as [`Repo::begin_update`] does. It reads, merges, and writes the keyring
    /// under both locks, so two imports into one keyring keep the keys of
    /// both. The call parses the offered stream before it takes the locks.
    /// [`UpdateGuard`](crate::UpdateGuard) describes a caller that holds a
    /// guard of this repository.
    ///
    /// # Errors
    ///
    /// For each error, the keyring does not change. The one exception is a
    /// failed sync of the repository directory, which comes after the rename
    /// of the new keyring.
    ///
    /// - [`Error::InvalidInput`] if [`valid_remote_name`] refuses `remote`.
    ///   The call refuses the name before it parses `keys` and before it
    ///   takes a lock.
    /// - [`Error::Signature`] if `keys` or the keyring is over 4 MiB, holds
    ///   more than 256 certificates, or is a GnuPG keybox.
    /// - [`Error::InvalidFormat`] if the keyring is larger than 64 MiB, the
    ///   cap of its read.
    /// - [`Error::Signature`] if `keys` or the keyring does not parse as an
    ///   OpenPGP keyring.
    /// - [`Error::Signature`] if `keys` holds no certificate, or a selector in
    ///   `key_ids` names no key in `keys`.
    /// - [`Error::Signature`] if an armored stream is not valid UTF-8.
    /// - [`Error::Core`] if the armor of a stream holds text that is not valid
    ///   base64.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or
    ///   `[core] lock-timeout-secs` has a value that does not parse.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is less than
    ///   `-1`.
    /// - [`Error::LockTimeout`] if the wait for a lock passes
    ///   `[core] lock-timeout-secs`.
    /// - [`Error::Io`] if a symlink is at the path of the repository keyring,
    ///   also a symlink to no file. The call refuses each such symlink.
    /// - [`Error::Io`] if a lock file, the read of the keyring, the write of
    ///   the keyring, or the sync of the repository directory fails.
    pub async fn gpg_import_keys(
        &self,
        remote: &str,
        keys: &[u8],
        key_ids: &[String],
    ) -> Result<usize> {
        if !valid_remote_name(remote) {
            return Err(Error::InvalidInput(format!(
                "invalid remote name: {remote}"
            )));
        }
        let name = remote_keyring_name(remote);
        let fsync = self.config().fsync()?;
        let subject = format!("the keyring '{name}'");
        // Parsing untrusted certificate streams is CPU work over owned copies
        // of its inputs, so it runs on the blocking pool. The offered stream
        // is read before the locks, and only the read of the keyring, the
        // merge, and the write run under them. The read refuses a stream over
        // `MAX_KEYRING` before it reads a byte. So such a stream gets no copy,
        // and its read runs here.
        let offered = if keys.len() as u64 > MAX_KEYRING {
            gpg_offered_keys(keys, key_ids, &subject)
        } else {
            let offered = keys.to_vec();
            let ids = key_ids.to_vec();
            let read_subject = subject.clone();
            ostrya_rt::unblock(move || gpg_offered_keys(&offered, &ids, &read_subject)).await
        };
        self.write_locked(move |repo| {
            let existing = read_root_file_blocking(repo.repo_fd(), &name)?.unwrap_or_default();
            let (imported, keyring) = gpg_merge_keyring(&existing, offered, &subject)?;
            write_root_file_blocking(repo.repo_fd(), &name, &keyring, fsync)?;
            Ok(imported)
        })
        .await
    }

    /// Returns the keys in the trusted keyring of `remote`.
    ///
    /// The keyring is `<remote>.trustedkeys.gpg` at the repository root. Only
    /// when the repository holds no such file, the keyring is
    /// `<remote>.trustedkeys.gpg` in the remotes directory of the handle
    /// ([`Repo::remotes_dir`]). The `ostree` command reads the two files in
    /// this way. A handle with no remotes directory reads the repository
    /// keyring alone. The read follows a symlink, and a symlink to no file is
    /// no keyring.
    ///
    /// The keys come in the order of their certificates in the keyring. If
    /// neither keyring exists, the list is empty.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if [`valid_remote_name`] refuses `remote`.
    ///   The call refuses the name before it reads a keyring.
    /// - [`Error::Signature`] if a keyring cannot be opened or read for a
    ///   reason other than its absence, or is not a regular file. The message
    ///   names the keyring. A keyring of the remotes directory is named as
    ///   [`for_remote_in`](FromOstreeKeyrings::for_remote_in) names it.
    /// - [`Error::Signature`] if the keyring is over 4 MiB, is a GnuPG keybox,
    ///   holds more than 256 certificates, or does not parse as an OpenPGP
    ///   keyring.
    /// - [`Error::Signature`] if an armored keyring is not valid UTF-8.
    /// - [`Error::Core`] if the armor of the keyring holds text that is not
    ///   valid base64.
    pub async fn gpg_list_keys(&self, remote: &str) -> Result<Vec<GpgKey>> {
        if !valid_remote_name(remote) {
            return Err(Error::InvalidInput(format!(
                "invalid remote name: {remote}"
            )));
        }
        let repo = self.clone();
        let remote = remote.to_owned();
        // The read resolves the names through descriptors, and the parse is
        // CPU work, so both run in one job on the blocking pool.
        ostrya_rt::unblock(move || {
            let Some(keyring) = read_remote_keyring(repo.repo_fd(), repo.remotes_dir(), &remote)?
            else {
                return Ok(Vec::new());
            };
            Ok(gpg_keyring_keys(&keyring.bytes, &keyring.subject)?)
        })
        .await
    }
}

/// Returns the directory of the keyrings that every remote trusts.
///
/// If the `OSTREE_GPG_HOME` environment variable has a value that is not
/// empty, the result is this value. If not, the result is the system directory
/// `/usr/share/ostree/trusted.gpg.d`.
fn global_trusted_dir() -> PathBuf {
    match std::env::var_os(OSTREE_GPG_HOME_ENV) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(GLOBAL_TRUSTED_GPG_D),
    }
}

/// Returns the keyring files in `dir`, the global trusted directory, sorted by
/// name.
///
/// The list holds each regular file whose name ends in the bytes `.gpg`. So
/// it holds a hidden name such as `.a.gpg`, and the name `.gpg` itself. It
/// does not hold a name that ends in `.GPG`. The file type comes from the
/// directory entry, and the call does not follow a symlink. So the list holds
/// no subdirectory, no symlink, no fifo, and no socket.
///
/// On a file system that gives no file type in the directory entry, the call
/// reads the type with `lstat`. If the entry is removed after the listing,
/// that read finds no file, and the list does not hold the entry.
///
/// If the directory does not exist, the result is an empty list. If the
/// directory cannot be listed for another reason, the call fails with
/// [`Error::Signature`], and the message names the directory. A path that
/// names a file that is not a directory is an example.
fn keyring_files_in(dir: &Path) -> Result<Vec<PathBuf>> {
    let refuse = |e: std::io::Error| {
        Error::Signature(format!(
            "the global trusted directory '{}' cannot be listed: {e}",
            dir.display()
        ))
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(refuse(e)),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(refuse)?;
        if !entry.file_name().as_encoded_bytes().ends_with(b".gpg") {
            continue;
        }
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(refuse(e)),
        };
        if file_type.is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

/// Returns the keyring files that the entries of a keyring path name, in
/// entry order.
///
/// An entry that names a file gives that file. An entry that names a directory
/// gives the files of [`keypath_dir_files`]. If an entry cannot be read, the
/// refusal names `key`, the configuration key of the entry, and the text of
/// the entry.
fn keypath_files(key: &str, keypath: &[String]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in keypath {
        let path = Path::new(entry);
        let meta = std::fs::metadata(path).map_err(|e| keypath_refusal(key, entry, &e))?;
        if meta.is_dir() {
            paths.extend(keypath_dir_files(key, entry, path)?);
        } else {
            paths.push(path.to_owned());
        }
    }
    Ok(paths)
}

/// Returns the regular files in `dir`, the directory of the keyring path
/// entry `entry`, sorted by name.
///
/// The `ostree` command reads the files of a `gpgkeypath` directory in this
/// way. The list holds each regular file with any name, a hidden name
/// included. The file type comes from the directory entry, and the call does
/// not follow a symlink. So the list holds no subdirectory, no symlink, no
/// fifo, and no socket. The call does not read a subdirectory.
///
/// On a file system that gives no file type in the directory entry, the call
/// reads the type with `lstat`. If the entry is removed after the listing,
/// that read finds no file, and the list does not hold the entry.
///
/// If the directory cannot be listed, the refusal names `key`, the
/// configuration key of the entry, and the text of the entry.
fn keypath_dir_files(key: &str, entry: &str, dir: &Path) -> Result<Vec<PathBuf>> {
    let refuse = |e: std::io::Error| keypath_refusal(key, entry, &e);
    let mut files = Vec::new();
    for dirent in std::fs::read_dir(dir).map_err(refuse)? {
        let dirent = dirent.map_err(refuse)?;
        let file_type = match dirent.file_type() {
            Ok(file_type) => file_type,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(refuse(e)),
        };
        if file_type.is_file() {
            files.push(dirent.path());
        }
    }
    files.sort();
    Ok(files)
}

/// Returns the refusal of the keyring path entry `entry`, which cannot be
/// read. `key` is the configuration key of the entry.
fn keypath_refusal(key: &str, entry: &str, e: &std::io::Error) -> Error {
    Error::Signature(format!("{key} entry '{entry}' cannot be read: {e}"))
}

/// Reads the keyring at `path`, up to [`MAX_KEYRING`].
///
/// Returns `None` if no file is at `path`.
fn read_keyring_path(path: &Path) -> Result<Option<Vec<u8>>> {
    let subject = format!("the keyring '{}'", path.display());
    read_key_path(path, &subject, MAX_KEYRING)
}

/// Reads the keyring at `path`, resolved against `base`, through
/// [`read_key_source`], the reader of each key source.
///
/// Returns `None` if no file is at `path`. If a symlink is at `path`, the
/// read follows it. The reader accepts only a regular file, up to
/// [`MAX_KEYRING`]. A refusal names `subject`, so an operator can find the
/// keyring.
///
/// The call checks the type before it opens the file, so it opens no device
/// and no socket. It opens the file with `O_NONBLOCK`, and the reader checks
/// the type again, so a fifo that replaces the file after the check does not
/// block the read.
///
/// A keyring has its own limit, because it holds certificates and no base64
/// lines. The call refuses a keyring over the limit by name, and does not read
/// the part under the limit. `gpgkeypath` applies the same rule to an entry
/// that names nothing.
fn read_keyring_at(base: BorrowedFd<'_>, path: &Path, subject: &str) -> Result<Option<Vec<u8>>> {
    let refuse_open = |e: Errno| Error::Signature(format!("{subject} cannot be opened: {e}"));
    match rustix::fs::statat(base, path, AtFlags::empty()) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile => {}
        Ok(_) => return Err(Error::Signature(format!("{subject} is not a regular file"))),
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(refuse_open(e)),
    }
    // `NONBLOCK` makes a fifo answer the open at once. Without it, the open
    // waits for a writer. On a regular file, the flag has no effect on the
    // read that the reader makes.
    let fd = match rustix::fs::openat(
        base,
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(refuse_open(e)),
    };
    Ok(Some(read_key_source(
        std::fs::File::from(fd),
        subject,
        MAX_KEYRING,
    )?))
}

/// Returns a scratch directory path for one test fixture, unique in the
/// process.
///
/// The path is the GnuPG home of the `gpg` runs of the fixture, or a directory
/// of keyring files. The fixtures of this module get their paths from this
/// function.
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

/// Stops each GnuPG daemon of the home directory `dir`, and removes its
/// socket directory.
///
/// GnuPG makes the socket directory under the user runtime directory. It names
/// that directory from the path string of `dir`, so the call also works after
/// the removal of `dir`. The fixtures of this module call it before they
/// remove their home. The call ignores failures.
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

#[cfg(test)]
pub(crate) mod tests {
    use std::os::fd::{AsFd, OwnedFd};

    use super::*;

    /// The global trusted directory gives each regular file whose name ends
    /// in `.gpg`, a hidden name and the name `.gpg` included, sorted by name.
    /// The list holds no other name, no subdirectory, no symlink, and no fifo.
    #[cfg(unix)]
    #[test]
    fn keyring_files_in_selects_gpg_and_sorts() {
        use std::os::unix::fs::symlink;

        let dir = scratch_dir();
        std::fs::create_dir_all(dir.join("d.gpg")).unwrap();
        for name in [
            "b.gpg",
            "a.gpg",
            ".gpg",
            ".a.gpg",
            "a.GPG",
            "a.gpg.bak",
            "notes.txt",
            "keyring",
            "d.gpg/c.gpg",
        ] {
            std::fs::write(dir.join(name), b"").unwrap();
        }
        symlink(dir.join("b.gpg"), dir.join("link.gpg")).unwrap();
        match std::process::Command::new("mkfifo")
            .arg(dir.join("fifo.gpg"))
            .status()
        {
            Ok(status) if status.success() => {}
            other => eprintln!("skipping the fifo arm: mkfifo did not create a fifo: {other:?}"),
        }
        let files = keyring_files_in(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
        let names: Vec<String> = files
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [".a.gpg", ".gpg", "a.gpg", "b.gpg"]);
    }

    #[test]
    fn keyring_files_in_missing_dir_is_empty() {
        assert!(keyring_files_in(&scratch_dir()).unwrap().is_empty());
    }

    /// A global trusted directory that cannot be listed fails the read with
    /// [`Error::Signature`], and the message names the directory. A path that
    /// names a regular file and a directory with mode 000 are the cases.
    #[cfg(unix)]
    #[test]
    fn a_global_directory_that_cannot_be_listed_is_refused_by_its_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir();
        let file = dir.join("file");
        let locked = dir.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(&file, b"").unwrap();
        std::fs::write(locked.join("a.gpg"), b"").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let listed = std::fs::read_dir(&locked).is_ok();
        let from_file = keyring_files_in(&file);
        let from_locked = keyring_files_in(&locked);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let mut cases = vec![(file, from_file)];
        // A process that holds the override of file permissions, as root
        // does, lists the directory. The arm then has no refusal to observe.
        if listed {
            eprintln!("skipping the mode 000 arm: the directory lists with mode 000");
        } else {
            cases.push((locked, from_locked));
        }
        for (path, result) in cases {
            let expected = format!(
                "the global trusted directory '{}' cannot be listed: ",
                path.display()
            );
            assert!(
                matches!(&result, Err(Error::Signature(m)) if m.starts_with(&expected)),
                "{:?}",
                result.err()
            );
        }
    }

    /// The global trusted directory is a fallback. A repository keyring that
    /// exists, an empty one included, stops its listing, so a file there that
    /// the load refuses gives no error. With no repository keyring, the load
    /// reads the directory and refuses the file by its path.
    #[test]
    fn a_repository_keyring_stops_the_read_of_the_global_directory() {
        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let junk = dir.join("junk.gpg");
        std::fs::write(&junk, b"This directory holds the trusted keys.\n").unwrap();
        let remote = "ostrya-global-fallback-test";
        let empty = || Some(RemoteKeyring::in_repo(Vec::new(), remote));
        let with_keyring = remote_keyrings_in(empty(), remote, &[], Some(&dir));
        let without = remote_keyrings_in(None, remote, &[], Some(&dir));
        let no_global = remote_keyrings_in(None, remote, &[], None);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(with_keyring.unwrap().is_empty());
        assert!(no_global.unwrap().is_empty());
        let named = format!("the keyring '{}'", junk.display());
        assert!(
            matches!(&without, Err(Error::Signature(m)) if m.contains(&named)),
            "{:?}",
            without.err()
        );
    }

    /// A key in the global trusted directory takes part only when the
    /// repository holds no keyring of the remote. An armored file in the
    /// global directory and an armored repository keyring are refused by
    /// name.
    #[test]
    fn the_global_directory_trusts_its_keys_only_with_no_repository_keyring() {
        use ostrya_sign::Verifier as _;

        if !gpg_available() {
            assert!(
                std::env::var_os("OSTRYA_REQUIRE_GNUPG").is_none(),
                "OSTRYA_REQUIRE_GNUPG is set and `gpg` is not available"
            );
            eprintln!("skipping: gpg not available");
            return;
        }
        let repo_key = KeyFixture::new("Repository <repository@ostrya.example>");
        let global_key = KeyFixture::new("Global <global@ostrya.example>");
        let payload = b"global payload";
        let signature = global_key.sign(payload);
        let dir = scratch_dir();
        let global = dir.join("global");
        let armored = dir.join("armored");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::create_dir_all(&armored).unwrap();
        std::fs::write(global.join("k.gpg"), global_key.export(false)).unwrap();
        std::fs::write(armored.join("k.gpg"), global_key.export(true)).unwrap();
        let remote = "ostrya-global-trust-test";
        let load = |repo_keyring: Option<Vec<u8>>, dir: &Path| {
            let keyring = repo_keyring.map(|bytes| RemoteKeyring::in_repo(bytes, remote));
            remote_keyrings_in(keyring, remote, &[], Some(dir))
        };
        let verdict = |verifier: Result<GpgVerifier>| {
            verifier
                .unwrap()
                .verify(payload, std::slice::from_ref(&signature))
                .unwrap()
                .valid
        };
        let fallback = verdict(load(None, &global));
        let shadowed = verdict(load(Some(repo_key.export(false)), &global));
        let armored_global = load(None, &armored);
        let armored_repo = load(Some(repo_key.export(true)), &global);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(fallback);
        assert!(!shadowed);
        let named = format!("the keyring '{}'", armored.join("k.gpg").display());
        assert!(
            matches!(&armored_global, Err(Error::Signature(m)) if m.contains(&named)
                && m.contains("armor")),
            "{:?}",
            armored_global.err()
        );
        let named = format!("the keyring '{remote}.trustedkeys.gpg'");
        assert!(
            matches!(&armored_repo, Err(Error::Signature(m)) if m.contains(&named)
                && m.contains("armor")),
            "{:?}",
            armored_repo.err()
        );
    }

    /// Opens the directory at `path` for the keyring read of a test.
    fn open_dir(path: &Path) -> OwnedFd {
        OwnedFd::from(std::fs::File::open(path).unwrap())
    }

    /// Reads the keyring of `remote` in the directory `repo` with the remotes
    /// directory `dir`, as a pull reads it.
    fn read_in(
        repo: &Path,
        dir: Option<&RemotesDir>,
        remote: &str,
    ) -> Result<Option<RemoteKeyring>> {
        read_remote_keyring(open_dir(repo).as_fd(), dir, remote)
    }

    /// Reads the keyring of `remote` as [`read_in`] does, and builds a
    /// verifier with the global trusted directory `global`.
    fn load_in(repo: &Path, dir: &RemotesDir, remote: &str, global: &Path) -> Result<GpgVerifier> {
        let keyring = read_in(repo, Some(dir), remote)?;
        remote_keyrings_in(keyring, remote, &[], Some(global))
    }

    /// A keyring of the remote in the remotes directory that exists, an empty
    /// one included, stops the listing of the global trusted directory, so a
    /// file there that the load refuses gives no error. A keyring of another
    /// remote in the remotes directory does not stop it, so the load reads
    /// the global directory and refuses the file by its path.
    #[test]
    fn a_keyring_of_the_remotes_directory_stops_the_read_of_the_global_directory() {
        let dir = scratch_dir();
        let repo = dir.join("repo");
        let global = dir.join("global");
        let remotes = dir.join("remotes.d");
        for path in [&repo, &global, &remotes] {
            std::fs::create_dir_all(path).unwrap();
        }
        let junk = global.join("junk.gpg");
        std::fs::write(&junk, b"This directory holds the trusted keys.\n").unwrap();
        let remote = "ostrya-dir-fallback-test";
        let remotes_dir = RemotesDir::path(&remotes);
        std::fs::write(remotes.join("other.trustedkeys.gpg"), b"").unwrap();
        let without = load_in(&repo, &remotes_dir, remote, &global);
        std::fs::write(remotes.join(remote_keyring_name(remote)), b"").unwrap();
        let with_keyring = load_in(&repo, &remotes_dir, remote, &global);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(with_keyring.unwrap().is_empty());
        let named = format!("the keyring '{}'", junk.display());
        assert!(
            matches!(&without, Err(Error::Signature(m)) if m.contains(&named)),
            "{:?}",
            without.err()
        );
    }

    /// A key in the global trusted directory takes part only when no keyring
    /// of the remote exists in the remotes directory. The key of the keyring
    /// of the remotes directory takes part. An armored keyring of the remotes
    /// directory is refused by its path, with the words "of the remotes
    /// directory".
    #[test]
    fn the_global_directory_trusts_its_keys_only_with_no_keyring_of_the_remotes_directory() {
        use ostrya_sign::Verifier as _;

        if !gpg_available() {
            assert!(
                std::env::var_os("OSTRYA_REQUIRE_GNUPG").is_none(),
                "OSTRYA_REQUIRE_GNUPG is set and `gpg` is not available"
            );
            eprintln!("skipping: gpg not available");
            return;
        }
        let dir_key = KeyFixture::new("Directory <directory@ostrya.example>");
        let global_key = KeyFixture::new("Global <global@ostrya.example>");
        let payload = b"directory payload";
        let dir_signature = dir_key.sign(payload);
        let global_signature = global_key.sign(payload);
        let dir = scratch_dir();
        let repo = dir.join("repo");
        let global = dir.join("global");
        let remotes = dir.join("remotes.d");
        for path in [&repo, &global, &remotes] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::write(global.join("k.gpg"), global_key.export(false)).unwrap();
        let remote = "ostrya-dir-trust-test";
        let keyring = remotes.join(remote_keyring_name(remote));
        let remotes_dir = RemotesDir::path(&remotes);
        let load = || load_in(&repo, &remotes_dir, remote, &global);
        let verdicts = |verifier: Result<GpgVerifier>| {
            let verifier = verifier.unwrap();
            [&global_signature, &dir_signature].map(|signature| {
                verifier
                    .verify(payload, std::slice::from_ref(signature))
                    .unwrap()
                    .valid
            })
        };
        let fallback = verdicts(load());
        std::fs::write(&keyring, dir_key.export(false)).unwrap();
        let shadowed = verdicts(load());
        std::fs::write(&keyring, dir_key.export(true)).unwrap();
        let armored = load();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(fallback, [true, false]);
        assert_eq!(shadowed, [false, true]);
        let named = format!(
            "the keyring '{}' of the remotes directory",
            keyring.display()
        );
        assert!(
            matches!(&armored, Err(Error::Signature(m)) if m.contains(&named)
                && m.contains("armor")),
            "{:?}",
            armored.err()
        );
    }

    /// A repository keyring that exists hides the keyring of the remotes
    /// directory: the read does not open the file of the directory. A
    /// directory is at the path of the keyring of the remotes directory, so
    /// an open of that path gives a refusal. A repository keyring with bytes
    /// and an empty one give the repository keyring. A repository keyring
    /// that cannot be read is refused by its name, and the read does not go
    /// on to the remotes directory.
    #[test]
    fn the_repository_keyring_hides_the_keyring_of_the_remotes_directory() {
        let dir = scratch_dir();
        let repo = dir.join("repo");
        let remotes = dir.join("remotes.d");
        let remote = "ostrya-hide-test";
        let name = remote_keyring_name(remote);
        std::fs::create_dir_all(remotes.join(&name)).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        let remotes_dir = RemotesDir::path(&remotes);
        let read = || read_in(&repo, Some(&remotes_dir), remote);
        std::fs::write(repo.join(&name), b"repository bytes").unwrap();
        let with_bytes = read();
        std::fs::write(repo.join(&name), b"").unwrap();
        let empty = read();
        std::fs::remove_file(repo.join(&name)).unwrap();
        std::fs::create_dir(repo.join(&name)).unwrap();
        let unreadable = read();
        std::fs::remove_dir_all(&dir).unwrap();
        let subject = format!("the keyring '{name}'");
        for (result, bytes) in [(with_bytes, &b"repository bytes"[..]), (empty, &b""[..])] {
            let keyring = result.unwrap().unwrap();
            assert_eq!(keyring.bytes, bytes);
            assert_eq!(keyring.subject, subject);
        }
        let expected = format!("{subject} is not a regular file");
        assert!(
            matches!(&unreadable, Err(Error::Signature(m)) if *m == expected),
            "{:?}",
            unreadable.err().map(|e| e.to_string())
        );
    }

    /// A fifo and a character device 0:0 at the name of the repository
    /// keyring, and a symlink to each, are refused as files that are not
    /// regular files. The read checks the type before the open, so it does
    /// not open the device: an open of a device 0:0 gives an error, and the
    /// refusal would then be one of the open. A process needs no capability
    /// to create a character device 0:0.
    #[cfg(unix)]
    #[test]
    fn a_fifo_and_a_device_at_the_repository_keyring_are_refused_before_an_open() {
        let dir = scratch_dir();
        let repo = dir.join("repo");
        let remote = "ostrya-special-test";
        let name = remote_keyring_name(remote);
        std::fs::create_dir_all(&repo).unwrap();
        let fifo = dir.join("fifo");
        let device = dir.join("device");
        let special = [
            (&fifo, FileType::Fifo, 0),
            (
                &device,
                FileType::CharacterDevice,
                rustix::fs::makedev(0, 0),
            ),
        ];
        for (path, file_type, dev) in special {
            let mode = Mode::from_raw_mode(0o600);
            rustix::fs::mknodat(rustix::fs::CWD, path, file_type, mode, dev).unwrap();
        }
        let mut results = Vec::new();
        for target in [&fifo, &device] {
            std::fs::rename(target, repo.join(&name)).unwrap();
            results.push(read_in(&repo, None, remote));
            std::fs::rename(repo.join(&name), target).unwrap();
            std::os::unix::fs::symlink(target, repo.join(&name)).unwrap();
            results.push(read_in(&repo, None, remote));
            std::fs::remove_file(repo.join(&name)).unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();
        let expected = format!("the keyring '{name}' is not a regular file");
        for result in results {
            assert!(
                matches!(&result, Err(Error::Signature(m)) if *m == expected),
                "{:?}",
                result.err().map(|e| e.to_string())
            );
        }
    }

    /// The read takes the keyring of the remotes directory when no file is at
    /// the name of the repository keyring, and when a symlink to no file is
    /// there.
    #[cfg(unix)]
    #[test]
    fn the_keyring_of_the_remotes_directory_is_read_when_the_repository_keyring_is_absent() {
        let dir = scratch_dir();
        let repo = dir.join("repo");
        let remotes = dir.join("remotes.d");
        let remote = "ostrya-absent-test";
        let name = remote_keyring_name(remote);
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&remotes).unwrap();
        std::fs::write(remotes.join(&name), b"directory bytes").unwrap();
        let remotes_dir = RemotesDir::path(&remotes);
        let absent = read_in(&repo, Some(&remotes_dir), remote);
        std::os::unix::fs::symlink(dir.join("absent.gpg"), repo.join(&name)).unwrap();
        let dangling = read_in(&repo, Some(&remotes_dir), remote);
        std::fs::remove_dir_all(&dir).unwrap();
        let subject = format!(
            "the keyring '{}' of the remotes directory",
            remotes.join(&name).display()
        );
        for result in [absent, dangling] {
            let keyring = result.unwrap().unwrap();
            assert_eq!(keyring.bytes, b"directory bytes");
            assert_eq!(keyring.subject, subject);
        }
    }

    /// A keyring of the remotes directory that cannot be read is refused by
    /// its path, for each form of [`RemotesDir`]. A directory is at the path
    /// of the keyring. A [`Path`](RemotesDir::Path) value names the path as
    /// given, an [`InRepo`](RemotesDir::InRepo) value names it relative to
    /// the repository, and a [`Fd`](RemotesDir::Fd) value names the file
    /// alone. A remotes directory that is a regular file gives a refusal of
    /// the open.
    #[test]
    fn a_keyring_of_the_remotes_directory_that_cannot_be_read_is_refused_by_its_path() {
        let dir = scratch_dir();
        let repo = dir.join("repo");
        let remotes = repo.join("remotes.d");
        let remote = "ostrya-refusal-test";
        let name = remote_keyring_name(remote);
        std::fs::create_dir_all(remotes.join(&name)).unwrap();
        let file = dir.join("file");
        std::fs::write(&file, b"").unwrap();
        let forms = [
            (RemotesDir::path(&remotes), remotes.join(&name)),
            (
                RemotesDir::InRepo(PathBuf::from("remotes.d")),
                Path::new("remotes.d").join(&name),
            ),
            (RemotesDir::from(open_dir(&remotes)), PathBuf::from(&name)),
        ];
        let results: Vec<_> = forms
            .into_iter()
            .map(|(form, path)| (read_in(&repo, Some(&form), remote), path))
            .collect();
        let not_a_dir = read_in(&repo, Some(&RemotesDir::path(&file)), remote);
        std::fs::remove_dir_all(&dir).unwrap();
        for (result, path) in results {
            let expected = format!(
                "the keyring '{}' of the remotes directory is not a regular file",
                path.display()
            );
            assert!(
                matches!(&result, Err(Error::Signature(m)) if *m == expected),
                "{expected}: {:?}",
                result.err().map(|e| e.to_string())
            );
        }
        let expected = format!(
            "the keyring '{}' of the remotes directory cannot be opened: ",
            file.join(&name).display()
        );
        assert!(
            matches!(&not_a_dir, Err(Error::Signature(m)) if m.starts_with(&expected)),
            "{:?}",
            not_a_dir.err().map(|e| e.to_string())
        );
    }

    /// The read gives no keyring when neither file exists: with no remotes
    /// directory, with an absent remotes directory, and with an absent parent
    /// of it. The remotes directory of the first case holds a keyring of the
    /// remote, and the read does not take it.
    #[test]
    fn no_remotes_directory_and_an_absent_one_give_no_keyring() {
        let dir = scratch_dir();
        let repo = dir.join("repo");
        let remotes = dir.join("remotes.d");
        let remote = "ostrya-none-test";
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&remotes).unwrap();
        std::fs::write(remotes.join(remote_keyring_name(remote)), b"").unwrap();
        let none = read_in(&repo, None, remote);
        let absent = read_in(&repo, Some(&RemotesDir::path(dir.join("absent"))), remote);
        let parent = RemotesDir::path(dir.join("absent").join("remotes.d"));
        let absent_parent = read_in(&repo, Some(&parent), remote);
        std::fs::remove_dir_all(&dir).unwrap();
        for result in [none, absent, absent_parent] {
            assert!(matches!(result, Ok(None)), "{:?}", result.err());
        }
    }

    /// The files of a `gpgkeypath` directory are its regular files with any
    /// name, sorted by name. The list holds no subdirectory, no symlink, and
    /// no fifo, and the read does not go into a subdirectory.
    #[cfg(unix)]
    #[test]
    fn keypath_dir_files_takes_each_regular_file_and_sorts() {
        use std::os::unix::fs::symlink;

        let dir = scratch_dir();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        for name in [
            "z.asc",
            "a.keyring",
            "README",
            ".gpg",
            ".a.gpg",
            "sub/b.gpg",
        ] {
            std::fs::write(dir.join(name), b"").unwrap();
        }
        symlink(dir.join("README"), dir.join("link.gpg")).unwrap();
        symlink(dir.join("absent"), dir.join("dangling.gpg")).unwrap();
        symlink(dir.join("sub"), dir.join("linkdir")).unwrap();
        match std::process::Command::new("mkfifo")
            .arg(dir.join("fifo.gpg"))
            .status()
        {
            Ok(status) if status.success() => {}
            other => eprintln!("skipping the fifo arm: mkfifo did not create a fifo: {other:?}"),
        }
        let files = keypath_dir_files("gpgkeypath", "keys", &dir);
        std::fs::remove_dir_all(&dir).unwrap();
        let names: Vec<String> = files
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [".a.gpg", ".gpg", "README", "a.keyring", "z.asc"]);
    }

    /// A `gpgkeypath` directory that cannot be listed fails the read. The
    /// refusal names the configuration key and the entry.
    #[cfg(unix)]
    #[test]
    fn a_keypath_directory_that_cannot_be_listed_is_refused_by_the_entry() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir();
        let keys = dir.join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("a.gpg"), b"").unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o000)).unwrap();
        let entry = keys.to_string_lossy().into_owned();
        let listed = std::fs::read_dir(&keys).is_ok();
        let result = keypath_files("gpgkeypath", std::slice::from_ref(&entry));
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        // A process that holds the override of file permissions, as root
        // does, lists the directory. The case then has no refusal to observe.
        if listed {
            eprintln!("skipping: the directory lists with mode 000");
            return;
        }
        let expected = format!("gpgkeypath entry '{entry}' cannot be read: ");
        assert!(
            matches!(&result, Err(Error::Signature(m)) if m.starts_with(&expected)),
            "{:?}",
            result.err()
        );
    }

    /// An empty `gpgkeypath` entry names no file, so the read refuses it.
    /// The refusal names the configuration key and the empty entry.
    #[test]
    fn an_empty_keypath_entry_is_refused() {
        let result = keypath_files("gpgkeypath", &[String::new()]);
        assert!(
            matches!(
                &result,
                Err(Error::Signature(m)) if m.starts_with("gpgkeypath entry '' cannot be read: ")
            ),
            "{:?}",
            result.err()
        );
    }

    /// A keyring load refuses a remote name that [`valid_remote_name`]
    /// refuses, before it reads a keyring. A directory is at the path that
    /// the join of the name to the repository or to the remotes directory
    /// reaches, so a read of that path before the check gives
    /// [`Error::Signature`] with `is not a regular file`.
    #[test]
    fn a_remote_keyring_load_refuses_an_invalid_remote_name() {
        use crate::{CreateOptions, OpenOptions, RepoMode};

        let dir = scratch_dir();
        let root = dir.join("repo");
        let remotes = dir.join("remotes.d");
        std::fs::create_dir_all(&remotes).unwrap();
        std::fs::create_dir(dir.join("x.trustedkeys.gpg")).unwrap();
        let handle = ostrya_rt::block_on(async {
            Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            OpenOptions::new()
                .remotes_dir(RemotesDir::path(&remotes))
                .open(&root)
                .await
                .unwrap()
        });
        let repo = GpgVerifier::for_remote(&root, "../x");
        let keypath = GpgVerifier::for_remote_keypath(&root, "../x", &[]);
        let keyrings = GpgVerifier::for_remote_keyrings(None, "../x", &[]);
        let in_handle = GpgVerifier::for_remote_in(&handle, "../x", &[]);
        drop(handle);
        std::fs::remove_dir_all(&dir).unwrap();
        for result in [repo, keypath, keyrings, in_handle] {
            assert!(
                matches!(
                    &result,
                    Err(Error::InvalidInput(m)) if m == "invalid remote name: ../x"
                ),
                "{:?}",
                result.err()
            );
        }
    }

    /// A remote keyring load reads the repository keyring before the
    /// `gpgkeypath` entries. A directory is at the path of the repository
    /// keyring, and the entry does not exist, so the refusal names the
    /// repository keyring.
    #[test]
    fn a_keypath_load_refuses_the_repository_keyring_first() {
        let dir = scratch_dir();
        let keyring = dir.join("keypath-order.trustedkeys.gpg");
        std::fs::create_dir_all(&keyring).unwrap();
        let entry = dir.join("absent.gpg").to_string_lossy().into_owned();
        let result = GpgVerifier::for_remote_keypath(&dir, "keypath-order", &[entry]);
        std::fs::remove_dir_all(&dir).unwrap();
        let expected = format!("the keyring '{}' is not a regular file", keyring.display());
        assert!(
            matches!(&result, Err(Error::Signature(m)) if *m == expected),
            "{:?}",
            result.err()
        );
    }

    /// A remote keyring load trusts the keys of a `gpgkeypath` entry. The
    /// repository holds no keyring of the remote, so the same load with no
    /// entry does not trust the key.
    #[test]
    fn a_keypath_load_trusts_the_keypath_entries() {
        use ostrya_sign::Verifier as _;

        if !gpg_available() {
            assert!(
                std::env::var_os("OSTRYA_REQUIRE_GNUPG").is_none(),
                "OSTRYA_REQUIRE_GNUPG is set and `gpg` is not available"
            );
            eprintln!("skipping: gpg not available");
            return;
        }
        let key = KeyFixture::new("Keypath <keypath@ostrya.example>");
        let payload = b"keypath payload";
        let signature = key.sign(payload);
        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let keyring = dir.join("k.gpg");
        std::fs::write(&keyring, key.export(false)).unwrap();
        let entry = keyring.to_string_lossy().into_owned();
        let trusted = GpgVerifier::for_remote_keypath(&dir, "keypath-trust", &[entry])
            .unwrap()
            .verify(payload, std::slice::from_ref(&signature))
            .unwrap();
        let untrusted = GpgVerifier::for_remote_keypath(&dir, "keypath-trust", &[])
            .unwrap()
            .verify(payload, std::slice::from_ref(&signature))
            .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(trusted.valid, "{:?}", trusted.signatures);
        assert!(!untrusted.valid, "{:?}", untrusted.signatures);
    }

    /// An import refuses an offered stream over [`MAX_KEYRING`] by its size,
    /// and the keyring of the remote does not change. The case runs with no
    /// keyring and with an empty keyring.
    #[test]
    fn an_import_over_the_keyring_ceiling_is_refused() {
        use crate::{CreateOptions, RepoMode};

        let dir = scratch_dir();
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let keyring = root.join("origin.trustedkeys.gpg");
        let oversized = vec![0u8; MAX_KEYRING as usize + 1];
        let refusals = ostrya_rt::block_on(async {
            let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let absent = repo.gpg_import_keys("origin", &oversized, &[]).await;
            let absent_after = std::fs::exists(&keyring).unwrap();
            std::fs::write(&keyring, b"").unwrap();
            let empty = repo.gpg_import_keys("origin", &oversized, &[]).await;
            let empty_after = std::fs::read(&keyring).unwrap();
            (absent, absent_after, empty, empty_after)
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let (absent, absent_after, empty, empty_after) = refusals;
        let text = "signature: the keyring to import is over the 4194304-byte ceiling";
        assert_eq!(absent.unwrap_err().to_string(), text);
        assert!(!absent_after, "the refused import wrote a keyring");
        assert_eq!(empty.unwrap_err().to_string(), text);
        assert!(
            empty_after.is_empty(),
            "the refused import changed the keyring"
        );
    }

    /// An import refuses a remote name that [`valid_remote_name`] refuses,
    /// before it reads a keyring. A directory is at the path that the join of
    /// the name to the repository reaches, so a read of that path before the
    /// check gives a different error. The directory stays.
    #[test]
    fn an_import_refuses_an_invalid_remote_name() {
        use crate::{CreateOptions, RepoMode};

        let dir = scratch_dir();
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let decoy = dir.join("x.trustedkeys.gpg");
        std::fs::create_dir(&decoy).unwrap();
        let result = ostrya_rt::block_on(async {
            let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            repo.gpg_import_keys("../x", b"", &[]).await
        });
        let decoy_stays = decoy.is_dir();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            matches!(&result, Err(Error::InvalidInput(m)) if m == "invalid remote name: ../x"),
            "{:?}",
            result.err()
        );
        assert!(decoy_stays, "the refused import changed the decoy");
    }

    /// A key listing refuses a remote name that [`valid_remote_name`]
    /// refuses, before it reads a keyring. A directory is at the path that
    /// the join of the name to the repository reaches, so a read of that
    /// path before the check gives a different error.
    #[test]
    fn a_key_listing_refuses_an_invalid_remote_name() {
        use crate::{CreateOptions, RepoMode};

        let dir = scratch_dir();
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let decoy = dir.join("x.trustedkeys.gpg");
        std::fs::create_dir(&decoy).unwrap();
        let result = ostrya_rt::block_on(async {
            let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            repo.gpg_list_keys("../x").await
        });
        let decoy_stays = decoy.is_dir();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            matches!(&result, Err(Error::InvalidInput(m)) if m == "invalid remote name: ../x"),
            "{:?}",
            result.err()
        );
        assert!(decoy_stays, "the refused listing changed the decoy");
    }

    /// A key listing reads the keyring of the remotes directory when the
    /// repository holds no keyring of the remote, as the `ostree` command
    /// does. An empty repository keyring hides it. A handle with no remotes
    /// directory does not read it.
    #[test]
    fn a_key_listing_reads_the_keyring_of_the_remotes_directory() {
        use crate::{CreateOptions, OpenOptions, RepoMode};

        if !gpg_available() {
            assert!(
                std::env::var_os("OSTRYA_REQUIRE_GNUPG").is_none(),
                "OSTRYA_REQUIRE_GNUPG is set and `gpg` is not available"
            );
            eprintln!("skipping: gpg not available");
            return;
        }
        let key = KeyFixture::new("Listed <listed@ostrya.example>");
        let dir = scratch_dir();
        let root = dir.join("repo");
        let remotes = dir.join("remotes.d");
        std::fs::create_dir_all(&remotes).unwrap();
        std::fs::write(remotes.join("origin.trustedkeys.gpg"), key.export(false)).unwrap();
        let listings = ostrya_rt::block_on(async {
            Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let with_dir = OpenOptions::new()
                .remotes_dir(RemotesDir::path(&remotes))
                .open(&root)
                .await
                .unwrap();
            let without_dir = Repo::open(&root).await.unwrap();
            let fallback = with_dir.gpg_list_keys("origin").await.unwrap();
            let no_dir = without_dir.gpg_list_keys("origin").await.unwrap();
            std::fs::write(root.join("origin.trustedkeys.gpg"), b"").unwrap();
            let hidden = with_dir.gpg_list_keys("origin").await.unwrap();
            (fallback, no_dir, hidden)
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let (fallback, no_dir, hidden) = listings;
        let fingerprints: Vec<&str> = fallback.iter().map(|k| k.fingerprint.as_str()).collect();
        assert_eq!(fingerprints, [key.fingerprint()]);
        assert!(no_dir.is_empty(), "{no_dir:?}");
        assert!(hidden.is_empty(), "{hidden:?}");
    }

    /// A key listing refuses a keyring of the remotes directory that cannot
    /// be read by its path. A directory is at the path of the keyring.
    #[test]
    fn a_key_listing_refuses_a_keyring_of_the_remotes_directory_by_its_path() {
        use crate::{CreateOptions, OpenOptions, RepoMode};

        let dir = scratch_dir();
        let root = dir.join("repo");
        let keyring = dir.join("remotes.d").join("origin.trustedkeys.gpg");
        std::fs::create_dir_all(&keyring).unwrap();
        let result = ostrya_rt::block_on(async {
            Repo::create(&root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            OpenOptions::new()
                .remotes_dir(RemotesDir::path(dir.join("remotes.d")))
                .open(&root)
                .await
                .unwrap()
                .gpg_list_keys("origin")
                .await
        });
        std::fs::remove_dir_all(&dir).unwrap();
        let expected = format!(
            "the keyring '{}' of the remotes directory is not a regular file",
            keyring.display()
        );
        assert!(
            matches!(&result, Err(Error::Signature(m)) if *m == expected),
            "{:?}",
            result.err().map(|e| e.to_string())
        );
    }

    /// Returns `true` if the `gpg` binary runs.
    ///
    /// The trust group cases in `verify::trust` and the receive signer cases
    /// in `receive::signer` build their fixtures with `gpg`. Each of these
    /// cases skips if the binary is absent. If `OSTRYA_REQUIRE_GNUPG` is set,
    /// the absence of the binary fails the case.
    pub(crate) fn gpg_available() -> bool {
        std::process::Command::new("gpg")
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// A private GnuPG home with new ed25519 signing keys that have no
    /// passphrase, under the test scratch tree.
    ///
    /// Each `gpg` run names this directory with `--homedir`. So the GnuPG home
    /// and the agents of the user that runs the tests take no part. When the
    /// fixture drops, it stops the GnuPG daemons of the directory, removes
    /// their socket directory, and removes the directory.
    pub(crate) struct KeyFixture {
        pub(crate) dir: PathBuf,
    }

    impl KeyFixture {
        /// Creates a home directory with one key for `uid` that never expires.
        pub(crate) fn new(uid: &str) -> KeyFixture {
            let fixture = KeyFixture {
                dir: KeyFixture::make_dir(),
            };
            fixture.add_key(uid);
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
        pub(crate) fn add_key(&self, uid: &str) {
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

        /// Returns one detached signature over `payload` by the first key of
        /// the home.
        pub(crate) fn sign(&self, payload: &[u8]) -> Vec<u8> {
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

        /// Returns the fingerprint of the first key of the home, in uppercase
        /// hex.
        pub(crate) fn fingerprint(&self) -> String {
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
            cmd
        }

        /// Returns the exported public keyring, binary or ASCII-armored.
        pub(crate) fn export(&self, armored: bool) -> Vec<u8> {
            let mut cmd = self.gpg();
            cmd.arg("--export");
            if armored {
                cmd.arg("--armor");
            }
            let out = cmd.output().unwrap();
            assert!(out.status.success() && !out.stdout.is_empty());
            out.stdout
        }
    }

    impl Drop for KeyFixture {
        fn drop(&mut self) {
            remove_home_sockets(&self.dir);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}
