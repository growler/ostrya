//! GPG (OpenPGP) signature verification, keyring management, and signing.
//!
//! The `verify-gpg` feature turns on this module. [`GpgVerifier`],
//! [`GpgKey`], and [`MAX_KEYRING`] are items of the `ostrya-sign` crate,
//! re-exported here. The verifier parses keyrings and verifies signatures in
//! the process, with rPGP. This module adds the items that read ostree paths
//! and the keyring files of a repository: the trait [`FromOstreeKeyrings`],
//! [`Repo::gpg_import_keys`], and [`Repo::gpg_list_keys`]. The trait builds a
//! verifier from the keyrings of a repository handle, from the bytes of a
//! keyring, from the `gpgkeys.gpg` keyring of a repository, or from the
//! global trusted keyrings.
//!
//! The `sign-gpg` feature adds `GpgSigner`, which signs with
//! `gpg --detach-sign`. This feature also turns on `verify-gpg`. `GpgSigner` is
//! an item of the `ostrya-sign` crate, re-exported here.
//!
//! This crate runs the `gpg` command for these operations only:
//!
//! - The signing run of `GpgSigner`.
//! - The secret-key listing of `GpgSigner`.
//! - The export of `GpgSigner` under the `sign-gpg` feature, in
//!   `SigningKey::gpg`. It gives the minimal public certificate of a signing
//!   key, so `SigningKey::has_signed` can recognize a signature that this key
//!   made.
//!
//! The private key stays with GnuPG and its agent. It never goes through this
//! crate.

use std::ffi::OsStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use ostrya_sign::{gpg_keyring_keys, gpg_merge_keyring, gpg_offered_keys};
use rustix::fs::FileType;

use crate::config::{KeyPath, io_of, relative_with_parent, remote_keyring_name, valid_remote_name};
use crate::error::{Error, Result};
use crate::remotes_dir;
use crate::repo::{RemotesDir, Repo};
use crate::repo_fs::{FsError, Named, Publish, Reason, RepoDir, RootFile, list_fd, open_named};
use crate::sign::read_key_source;

#[cfg(feature = "sign-gpg")]
pub use ostrya_sign::GpgSigner;
pub use ostrya_sign::{GpgKey, GpgVerifier, MAX_KEYRING};

/// The system directory of the keyrings that every remote trusts.
const GLOBAL_TRUSTED_GPG_D: &str = "/usr/share/ostree/trusted.gpg.d";
/// The environment variable that overrides the global trusted-keyring
/// directory. The `ostree` command reads the same variable.
const OSTREE_GPG_HOME_ENV: &str = "OSTREE_GPG_HOME";
/// The name of the keyring of a repository that names no remote.
const REPO_KEYRING: &str = "gpgkeys.gpg";
/// The name of [`REPO_KEYRING`] in a refusal.
const REPO_KEYRING_SUBJECT: &str = "the keyring 'gpgkeys.gpg'";

/// A GPG verifier that loads the keyrings that ostree trusts.
///
/// The `ostrya-sign` crate has no ostree search path, so this crate adds the
/// constructors as a trait. A caller brings the trait into scope to call them.
///
/// The keyring of a remote is `<remote>.trustedkeys.gpg` in the repository.
/// When the repository holds no keyring of the remote, the keyring is the file
/// of that name in the remotes directory of the handle.
/// [`for_remote_in`](FromOstreeKeyrings::for_remote_in) reads the keyring of a
/// remote through a repository handle, so it reads the same keyring as a pull
/// of that remote.
/// [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings) takes the
/// bytes of that keyring from the caller.
/// [`for_repo_in`](FromOstreeKeyrings::for_repo_in) reads the `gpgkeys.gpg`
/// keyring of a repository, which names no remote.
/// [`from_system_trust`](FromOstreeKeyrings::from_system_trust) reads the
/// global trusted keyrings alone.
pub trait FromOstreeKeyrings: Sized {
    /// Creates a verifier from the keyrings that `remote` of the repository
    /// handle `repo` trusts, together with the `gpgkeypath` entries of the
    /// section of the remote in the config of `repo`.
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
    /// - Each `gpgkeypath` entry of the section of the remote
    ///   ([`Remote::gpgkeypath`](crate::config::Remote::gpgkeypath)). A remote
    ///   with no section has no entry. A relative entry in `config` is
    ///   relative to the repository root, and a relative entry in a `.conf`
    ///   file of the remotes directory is relative to that directory, by the
    ///   rules of [`Remote`](crate::config::Remote#paths). A refusal names an
    ///   entry of a `.conf` file as the path of the remotes directory joined
    ///   with the entry. For a [`Fd`](RemotesDir::Fd) value, the refusal
    ///   names the entry alone. An empty entry names no file, as an empty
    ///   entry in `config` does, and the refusal names the empty entry.
    ///
    /// A file exists if its open does not give "No such file or directory".
    /// So an empty repository keyring hides the keyring of the remotes
    /// directory and stops the read of the global trusted directory. A
    /// symlink to no file is no keyring. The read follows a symlink, opens
    /// the file with `O_NONBLOCK`, and then checks its type, so a FIFO does
    /// not block the read. The read of a device, also through a symlink,
    /// opens the device before the type check, and the open of a device with
    /// a driver can have side effects. The read refuses the device as a file
    /// that is not a regular file if the open succeeds or if the device has
    /// no driver. Each other error of the open, for example `EACCES` for a
    /// device on a `nodev` mount, gives the error "cannot be opened". The
    /// rules of
    /// [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings) apply
    /// to each source, also to a `gpgkeypath` entry. The call blocks the
    /// calling thread while it reads the keyrings.
    ///
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
    /// - [`Error::InvalidFormat`] if a `gpgkeypath` entry is a relative path
    ///   with a `..` component. The call refuses the entry before it reads a
    ///   keyring.
    /// - [`Error::Signature`] if a keyring of the remote cannot be opened or
    ///   read for a reason other than its absence, for example because it is
    ///   a directory. The message names the keyring. The call reads the
    ///   keyrings of the remote before the other sources, so this error comes
    ///   first.
    /// - The errors of
    ///   [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings),
    ///   except the refusal of a `keypath` path of the caller.
    fn for_remote_in(repo: &Repo, remote: &str) -> Result<Self>;

    /// Creates a verifier from the whole trusted set of a remote.
    ///
    /// `repo_keyring` holds the bytes of the keyring of the remote, or `None`
    /// if the remote has no keyring. A caller with no repository handle reads
    /// this file itself and gives its bytes. To give the keyring that a pull
    /// reads, the caller reads `<remote>.trustedkeys.gpg` in the repository.
    /// If the open of that file gives "No such file or directory", the caller
    /// reads the file of that name in the remotes directory. A symlink to no
    /// file is an absent file. If neither file exists, `repo_keyring` is
    /// `None`. A pull trusts the union of these keyrings, in load order:
    ///
    /// - `repo_keyring`.
    /// - The global trusted set of
    ///   [`from_system_trust`](FromOstreeKeyrings::from_system_trust), only
    ///   when `repo_keyring` is `None`. An empty keyring exists, so it stops
    ///   the read of the global trusted directory.
    /// - Each entry of `keypath`, which holds the paths of the caller in the
    ///   form of `gpgkeypath` entries. A relative path is relative to the
    ///   working directory.
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
    /// The load opens the entry as a file with `O_NONBLOCK`, and follows a
    /// symlink at each component of the path. An entry that is a directory
    /// is then opened as a directory and listed. The load reads each member
    /// that the listing gives as a regular file, with any name, in name
    /// order. It skips a symlink, a subdirectory, a FIFO, a socket, and a
    /// device of the directory, and opens no such member. It also skips a
    /// member that is absent or is not a regular file at its open. It holds
    /// one directory open at a time, and reads one file at a time. If an
    /// entry cannot be read, the build fails. So a missing keyring path gives
    /// an error, and the trusted set does not become smaller with no message.
    /// An entry that is a FIFO, a device, or a socket also fails the build.
    /// The load skips a `keypath` file that does not hold the bytes
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
    /// - [`Error::InvalidInput`] if a `keypath` path is a relative path with
    ///   a `..` component. The call refuses the path before it reads a
    ///   keyring.
    /// - [`Error::Signature`] if a `keypath` entry cannot be opened, or a
    ///   directory that an entry names cannot be opened or listed. The
    ///   message names `gpgkeypath` and the entry.
    /// - [`Error::Signature`] if a `keypath` entry or a member that the
    ///   listing gives as a regular file is not a regular file at its open,
    ///   cannot be read, or is over [`MAX_KEYRING`]. The message names the
    ///   file, as `the keyring '<path>'`. A member is skipped if it is not a
    ///   regular file at its open.
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
    ///   [`add_keyring_skipping`](GpgVerifier::add_keyring_skipping) for each
    ///   `keypath` file.
    fn for_remote_keyrings(
        repo_keyring: Option<Vec<u8>>,
        remote: &str,
        keypath: &[PathBuf],
    ) -> Result<Self>;

    /// Creates a verifier from the `gpgkeys.gpg` keyring of the repository
    /// of the handle `repo`.
    ///
    /// The keyring is the file `gpgkeys.gpg` at the repository root. If no
    /// file is at that name, the verifier trusts no key. A file exists if its
    /// open does not give "No such file or directory", so a symlink to no
    /// file is no keyring. The read follows a symlink at the name, also to a
    /// path outside the repository. It opens the file with `O_NONBLOCK`, and
    /// then checks its type, so a FIFO does not block the read. The keyring
    /// is a binary OpenPGP packet stream or armor, as
    /// [`add_keyring`](GpgVerifier::add_keyring) reads it. No keyring of a
    /// remote and no global trusted set take part. The call blocks the
    /// calling thread while it reads the keyring.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if the keyring cannot be opened for a reason
    ///   other than its absence, is not a regular file, cannot be read, or is
    ///   over [`MAX_KEYRING`]. The message names the keyring as `the keyring
    ///   'gpgkeys.gpg'`.
    /// - The errors of [`add_keyring`](GpgVerifier::add_keyring), with the
    ///   subject `the keyring 'gpgkeys.gpg'`.
    fn for_repo_in(repo: &Repo) -> Result<Self>;

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
    fn for_remote_in(repo: &Repo, remote: &str) -> Result<GpgVerifier> {
        if !valid_remote_name(remote) {
            return Err(Error::InvalidInput(format!(
                "invalid remote name: {remote}"
            )));
        }
        let keypath = match repo.config().remote(remote) {
            Some(section) => section.gpgkeypath_paths()?,
            None => Vec::new(),
        };
        let keyring = read_remote_keyring(repo.root_dir(), repo.remotes_dir(), remote)?;
        remote_keyrings(keyring, remote, Some(repo), &keypath, true)
    }

    fn for_remote_keyrings(
        repo_keyring: Option<Vec<u8>>,
        remote: &str,
        keypath: &[PathBuf],
    ) -> Result<GpgVerifier> {
        if !valid_remote_name(remote) {
            return Err(Error::InvalidInput(format!(
                "invalid remote name: {remote}"
            )));
        }
        if let Some(path) = keypath.iter().find(|path| relative_with_parent(path)) {
            return Err(Error::InvalidInput(format!(
                "the gpgkeypath entry {} is a relative path with a `..` component",
                path.display()
            )));
        }
        let keypath: Vec<KeyPath> = keypath.iter().map(KeyPath::caller).collect();
        let keyring = repo_keyring.map(|bytes| RemoteKeyring::in_repo(bytes, remote));
        remote_keyrings(keyring, remote, None, &keypath, true)
    }

    fn for_repo_in(repo: &Repo) -> Result<GpgVerifier> {
        let mut verifier = GpgVerifier::default();
        if let Some(bytes) = read_root_keyring(repo.root_dir(), REPO_KEYRING, REPO_KEYRING_SUBJECT)?
        {
            verifier.add_keyring(&bytes, REPO_KEYRING_SUBJECT)?;
        }
        Ok(verifier)
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

/// Reads the keyring of `remote` for the repository of the root handle
/// `root`, with the remotes directory `dir`.
///
/// The keyring is `<remote>.trustedkeys.gpg` of the repository. Only when no
/// file is at that name, the keyring is the file of that name in `dir`. If
/// `dir` is `None`, or neither file exists, the result is `None`. A file
/// exists if its open does not give "No such file or directory", so a
/// symlink to no file is no keyring, and an absent directory or an absent
/// parent of it holds no keyring. The read follows a symlink at the
/// repository keyring, and at each component of the path of the keyring of
/// `dir`. The `ostree` command was observed to follow a symlink at the
/// repository keyring too.
///
/// The read opens the file with `O_NONBLOCK`, and then checks its type, so a
/// FIFO does not block the read. The read of a device, also through a
/// symlink, opens the device before the type check, and the open of a device
/// with a driver can have side effects. The read refuses the device as a
/// file that is not a regular file if the open succeeds or if the device has
/// no driver. Each other error of the open, for example `EACCES` for a
/// device on a `nodev` mount, gives the error "cannot be opened".
///
/// The read refuses a remote name that [`valid_remote_name`] refuses with
/// [`Error::InvalidInput`], before it opens a file. Each other refusal is
/// [`Error::Signature`], and it names the keyring: a file that cannot be
/// opened for a reason other than its absence, a file that is not a regular
/// file, a file that cannot be read, and a file over [`MAX_KEYRING`]. The
/// call blocks the calling thread.
pub(crate) fn read_remote_keyring(
    root: &RepoDir,
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
    if let Some(bytes) = read_root_keyring(root, &name, &repo_subject)? {
        return Ok(Some(RemoteKeyring {
            bytes,
            subject: repo_subject,
        }));
    }
    let Some(dir) = dir else {
        return Ok(None);
    };
    let (base, at, display) = remotes_dir::entry(root.as_fd(), dir, Path::new(&name));
    let subject = format!(
        "the keyring '{}' of the remotes directory",
        display.display()
    );
    let opened = open_named(base, &at, Named::File).map(std::fs::File::from);
    Ok(read_keyring(opened, &subject)?.map(|bytes| RemoteKeyring { bytes, subject }))
}

/// Creates a verifier from the keyrings of a remote, as
/// [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings) does.
///
/// `keyring` is the keyring of the remote that [`read_remote_keyring`] gives,
/// and a refusal of it names its subject. If `global` is `false`, the global
/// trusted set takes no part, and the trusted set is `keyring` and the
/// entries of `keypath` alone. If `global` is `true`, the global trusted set
/// takes part only when `keyring` is `None`. A relative entry of `keypath`
/// resolves against the base that its source and `repo` give, as
/// [`KeyPath::locate`] states.
///
/// The call refuses a name that [`valid_remote_name`] refuses with
/// [`Error::InvalidInput`], before it reads a keyring.
pub(crate) fn remote_keyrings(
    keyring: Option<RemoteKeyring>,
    remote: &str,
    repo: Option<&Repo>,
    keypath: &[KeyPath],
    global: bool,
) -> Result<GpgVerifier> {
    let global_dir = global.then(global_trusted_dir);
    remote_keyrings_in(keyring, remote, repo, keypath, global_dir.as_deref())
}

/// Runs [`remote_keyrings`] with the global trusted directory `global_dir`,
/// or with no global trusted set if `global_dir` is `None`.
///
/// `keyring` takes only a binary packet stream, and so does each global
/// keyring file. The call lists `global_dir` only when `keyring` is `None`.
///
/// The call adds `keyring`, then the files of `global_dir`, then the
/// `keypath` entries.
fn remote_keyrings_in(
    keyring: Option<RemoteKeyring>,
    remote: &str,
    repo: Option<&Repo>,
    keypath: &[KeyPath],
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
    verifier.add_binary_keyring_files(global)?;
    add_keypath(&mut verifier, "gpgkeypath", repo, keypath)?;
    Ok(verifier)
}

/// Creates a verifier from the keyrings that `keypath` names, and from no
/// other source.
///
/// No keyring of a remote and no global trusted set take part. Each entry
/// is a keyring file or a directory of keyring files, as
/// [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings) reads a
/// `keypath` entry. A relative entry resolves against the base that its
/// source and `repo` give, as [`KeyPath::locate`] states. If an entry cannot
/// be read, the build fails. The load skips and refuses the files that
/// [`add_keyring_skipping`](GpgVerifier::add_keyring_skipping) skips and
/// refuses. `key` is the configuration key of the entries, and a refusal
/// names it.
///
/// If the keyrings hold no certificate, the build fails with
/// [`Error::Signature`]. An empty file, a directory with no regular file, and
/// a directory of files that the load skips are examples. A verifier with
/// no trusted key refuses every commit.
pub(crate) fn from_keypath(key: &str, repo: &Repo, keypath: &[KeyPath]) -> Result<GpgVerifier> {
    let mut verifier = GpgVerifier::default();
    add_keypath(&mut verifier, key, Some(repo), keypath)?;
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
    /// Each stream of `keys` is a binary or ASCII-armored certificate stream,
    /// as an exported public keyring is. The call decodes each stream by
    /// itself, and joins the streams in order into one offered stream. The
    /// call returns the number of certificates that the keyring did not
    /// already hold.
    ///
    /// The call reads and writes the repository keyring alone. When the
    /// remotes directory of the handle ([`Repo::remotes_dir`]) holds the
    /// keyring of `remote` and no file is at the path of the repository
    /// keyring, the call creates the repository keyring. That keyring hides
    /// the keyring of the directory. To trust the keys of the directory too,
    /// import that keyring as well. The call copies the keys, so a later
    /// change to the keyring of the directory has no effect.
    ///
    /// If `key_ids` is not empty, the call imports only the keys of the
    /// offered stream that these selectors name. A selector is a fingerprint,
    /// a key id, or a user id substring.
    ///
    /// # Import rules
    ///
    /// The call replaces the keyring atomically. The read of the keyring
    /// follows a symlink, and a symlink to no file is no keyring. The read
    /// opens the file with `O_NONBLOCK`, and then checks its type. The write
    /// puts a regular file at the path of the symlink, and does not change the
    /// target. The keyring keeps the packet stream that it already held. The
    /// packets of each added certificate follow, as `keys` wrote them, with no
    /// Trust packets. The keyring is written in the binary form, so an armored
    /// keyring keeps its packets and loses its armor. `gpg` and the `ostree`
    /// command both read a keyring of this form.
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
    /// The offered streams are untrusted input. The sum of their lengths is
    /// at most 4 MiB, and the joined stream holds at most 256 certificates.
    /// No stream may be a GnuPG keybox. The offered stream and the keyring of
    /// the remote both go through the reader of a verification load. So if
    /// either stream does not frame to its end, the import fails, and the
    /// keyring does not change.
    ///
    /// # Locks
    ///
    /// The call takes the repository lock shared, as
    /// [`LockKind`](crate::LockKind) describes. It then takes the update lock,
    /// as [`Repo::begin_update`] does. It reads, merges, and writes the keyring
    /// under both locks, so two imports into one keyring keep the keys of
    /// both. The call parses the offered streams before it takes the locks.
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
    /// - [`Error::Signature`] if the keyring cannot be opened or read for a
    ///   reason other than its absence, or is not a regular file. The message
    ///   names the keyring.
    /// - [`Error::Signature`] if the keyring is over 4 MiB, or the streams of
    ///   `keys` together are over 4 MiB. The call refuses the size of the
    ///   keyring before it reads the keyring.
    /// - [`Error::Signature`] if the offered stream or the keyring holds more
    ///   than 256 certificates, or if a stream of `keys` or the keyring is a
    ///   GnuPG keybox.
    /// - [`Error::Signature`] if the offered stream or the keyring does not
    ///   parse as an OpenPGP keyring.
    /// - [`Error::Signature`] if the offered stream holds no certificate, or a
    ///   selector in `key_ids` names no key in it.
    /// - [`Error::Signature`] if an armored stream is not valid UTF-8.
    /// - [`Error::Core`] if the armor of a stream holds text that is not valid
    ///   base64.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or
    ///   `[core] lock-timeout-secs` has a value that does not parse.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is less than
    ///   `-1`.
    /// - [`Error::LockTimeout`] if the wait for a lock passes
    ///   `[core] lock-timeout-secs`.
    /// - [`Error::InvalidFormat`] if a symlink or an entry that is not a
    ///   regular file is at `.lock` or at `.update.lock`. The lock open
    ///   follows no symlink. If the process cannot open a FIFO, a socket, or
    ///   a device there for write, the error is [`Error::Io`].
    /// - [`Error::InvalidFormat`] if `tmp` or `tmp/cache` is a symlink or is
    ///   not a directory. The write of the keyring makes its temp file in
    ///   `tmp/`.
    /// - [`Error::Io`] if a lock file, the write of the keyring, or the sync
    ///   of the repository directory fails.
    pub async fn gpg_import_keys(
        &self,
        remote: &str,
        keys: &[&[u8]],
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
        // of its inputs, so it runs on the blocking pool. The offered streams
        // are read before the locks, and only the read of the keyring, the
        // merge, and the write run under them. The read refuses streams over
        // `MAX_KEYRING` together before it reads a byte. So such streams get
        // no copy, and their read runs here.
        let len: u64 = keys.iter().map(|stream| stream.len() as u64).sum();
        let offered = if len > MAX_KEYRING {
            gpg_offered_keys(keys, key_ids, &subject)
        } else {
            let offered: Vec<Vec<u8>> = keys.iter().map(|stream| stream.to_vec()).collect();
            let ids = key_ids.to_vec();
            let read_subject = subject.clone();
            ostrya_rt::unblock(move || {
                let streams: Vec<&[u8]> = offered.iter().map(Vec::as_slice).collect();
                gpg_offered_keys(&streams, &ids, &read_subject)
            })
            .await
        };
        self.write_locked(move |repo| {
            let existing = read_root_keyring(repo.root_dir(), &name, &subject)?.unwrap_or_default();
            let (imported, keyring) = gpg_merge_keyring(&existing, offered, &subject)?;
            repo.root_dir().write_root_file(
                RootFile::Keyring(name),
                &keyring,
                Publish::Replace,
                fsync,
            )?;
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
            let Some(keyring) = read_remote_keyring(repo.root_dir(), repo.remotes_dir(), &remote)?
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

/// Adds the keyrings that the keyring path entries `keypath` name to
/// `verifier`, in entry order, one file at a time.
///
/// The call opens an entry as a file with `O_NONBLOCK`, and follows a
/// symlink at each component of the path. A regular file adds its keyring.
/// An entry that is a directory gives the members of
/// [`add_keypath_dir`]. Each other type fails the call. `key` is the
/// configuration key of the entries. A refusal of an entry that cannot be
/// opened names `key` and the path of the entry, as [`KeyPath::locate`]
/// gives it for a message.
///
/// The caller drops `verifier` after an error, so the trusted set gets all
/// the keyrings or none of them.
fn add_keypath(
    verifier: &mut GpgVerifier,
    key: &str,
    repo: Option<&Repo>,
    keypath: &[KeyPath],
) -> Result<()> {
    for entry in keypath {
        let (base, at, shown) = entry.locate(repo);
        let fd = match open_named(base, &at, Named::File) {
            Ok(fd) => fd,
            Err(FsError::Invalid {
                reason: Reason::NotRegular(FileType::Directory),
                ..
            }) => {
                add_keypath_dir(verifier, key, base, &at, &shown)?;
                continue;
            }
            Err(FsError::Invalid {
                reason: Reason::NotRegular(_),
                ..
            }) => {
                return Err(Error::Signature(format!(
                    "the keyring '{}' is not a regular file",
                    shown.display()
                )));
            }
            Err(err) => return Err(keypath_refusal(key, &shown, &io_of(err))),
        };
        add_keyring_fd(verifier, fd, &format!("the keyring '{}'", shown.display()))?;
    }
    Ok(())
}

/// Adds the keyrings of the directory at `at` relative to `base`, the
/// directory of the keyring path entry `shown`, to `verifier`.
///
/// The `ostree` command reads the files of a `gpgkeypath` directory in this
/// way. The call reads each member that the listing gives as a regular file,
/// with any name, a hidden name included, in name order. It skips a symlink,
/// a subdirectory, a FIFO, a socket, and a device, and opens no such member.
/// The call does not read a subdirectory. On a file system that gives no
/// file type in the directory entry, the listing reads the type with no
/// follow, and leaves out an entry that is gone at that read.
///
/// The call opens each member with `O_NONBLOCK`, and skips a member that is
/// absent or is not a regular file at its open. So a FIFO that comes in after
/// the listing does not block the read. A member that cannot be opened for
/// another reason fails the call, and the refusal names the member.
///
/// If the directory cannot be opened or listed, the refusal names `key`, the
/// configuration key of the entry, and `shown`.
fn add_keypath_dir(
    verifier: &mut GpgVerifier,
    key: &str,
    base: BorrowedFd<'_>,
    at: &Path,
    shown: &Path,
) -> Result<()> {
    let refuse = |err: FsError| keypath_refusal(key, shown, &io_of(err));
    let dir = open_named(base, at, Named::Dir).map_err(refuse)?;
    let mut members = list_fd(dir.as_fd()).map_err(refuse)?;
    members.retain(|member| member.file_type == FileType::RegularFile);
    members.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    for member in &members {
        let name = Path::new(OsStr::from_bytes(&member.name));
        let subject = format!("the keyring '{}'", shown.join(name).display());
        match open_named(dir.as_fd(), name, Named::File) {
            Ok(fd) => add_keyring_fd(verifier, fd, &subject)?,
            Err(
                FsError::Absent { .. }
                | FsError::Invalid {
                    reason: Reason::NotRegular(_),
                    ..
                },
            ) => {}
            Err(err) => {
                return Err(Error::Signature(format!(
                    "{subject} cannot be opened: {}",
                    io_of(err)
                )));
            }
        }
    }
    Ok(())
}

/// Reads the keyring file open at `fd` through [`read_key_source`], up to
/// [`MAX_KEYRING`], and adds it to `verifier` with
/// [`add_keyring_skipping`](GpgVerifier::add_keyring_skipping). A refusal
/// names `subject`.
fn add_keyring_fd(verifier: &mut GpgVerifier, fd: OwnedFd, subject: &str) -> Result<()> {
    let bytes = read_key_source(std::fs::File::from(fd), subject, MAX_KEYRING)?;
    verifier.add_keyring_skipping(&bytes, subject)?;
    Ok(())
}

/// Returns the refusal of the keyring path entry `entry`, which cannot be
/// read. `key` is the configuration key of the entry.
fn keypath_refusal(key: &str, entry: &Path, e: &std::io::Error) -> Error {
    Error::Signature(format!(
        "{key} entry '{}' cannot be read: {e}",
        entry.display()
    ))
}

/// Reads the keyring `name` at the root of the repository of the root handle
/// `root`, as [`read_keyring`] reads it. The open follows a symlink at
/// `name`.
fn read_root_keyring(root: &RepoDir, name: &str, subject: &str) -> Result<Option<Vec<u8>>> {
    let opened = root
        .open_root_file(RootFile::Keyring(name.to_owned()))
        .map(|opened| opened.file);
    read_keyring(opened, subject)
}

/// Reads the keyring file of the result `opened` through
/// [`read_key_source`], the reader of each key source.
///
/// Returns `None` if no file was at the path of the open. The open uses
/// `O_NONBLOCK`, so a FIFO does not block it, and the type check of the
/// open refuses each entry that is not a regular file. The reader accepts
/// only a regular file, up to [`MAX_KEYRING`]. A refusal names `subject`,
/// so an operator can find the keyring.
///
/// A keyring has its own limit, because it holds certificates and no base64
/// lines. The call refuses a keyring over the limit by name, and does not read
/// the part under the limit. `gpgkeypath` applies the same rule to an entry
/// that names nothing.
fn read_keyring(
    opened: std::result::Result<std::fs::File, FsError>,
    subject: &str,
) -> Result<Option<Vec<u8>>> {
    let reason = match opened {
        Ok(file) => return Ok(Some(read_key_source(file, subject, MAX_KEYRING)?)),
        Err(FsError::Absent { .. }) => return Ok(None),
        Err(FsError::Invalid {
            reason: Reason::NotRegular(_),
            ..
        }) => return Err(Error::Signature(format!("{subject} is not a regular file"))),
        Err(FsError::Io(e)) => e.to_string(),
        Err(FsError::Invalid { path, reason }) => format!("{path} {reason}"),
        Err(other) => Error::from(other).to_string(),
    };
    Err(Error::Signature(format!(
        "{subject} cannot be opened: {reason}"
    )))
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
    use std::os::fd::OwnedFd;

    use rustix::fs::{FileType, Mode};

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
        let with_keyring = remote_keyrings_in(empty(), remote, None, &[], Some(&dir));
        let without = remote_keyrings_in(None, remote, None, &[], Some(&dir));
        let no_global = remote_keyrings_in(None, remote, None, &[], None);
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
            remote_keyrings_in(keyring, remote, None, &[], Some(dir))
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
        read_remote_keyring(&RepoDir::from_root_fd(open_dir(repo)), dir, remote)
    }

    /// Reads the keyring of `remote` as [`read_in`] does, and builds a
    /// verifier with the global trusted directory `global`.
    fn load_in(repo: &Path, dir: &RemotesDir, remote: &str, global: &Path) -> Result<GpgVerifier> {
        let keyring = read_in(repo, Some(dir), remote)?;
        remote_keyrings_in(keyring, remote, None, &[], Some(global))
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
    /// regular files. The read opens the file with `O_NONBLOCK` and then
    /// checks its type, so the open of the fifo does not block. The open of a
    /// device 0:0 gives `ENXIO`, and a `statx` that follows the symlink then
    /// reads the type. A process needs no capability to create a character
    /// device 0:0.
    #[cfg(unix)]
    #[test]
    fn a_fifo_and_a_device_at_the_repository_keyring_are_refused_as_not_regular_files() {
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
        // A `nodev` mount refuses the open of a device with `EACCES`, so
        // there the device is refused as a file that cannot be opened.
        let denied = format!("the keyring '{name}' cannot be opened: Permission denied");
        for (index, result) in results.into_iter().enumerate() {
            let message = match &result {
                Err(Error::Signature(m)) => m.as_str(),
                Err(other) => panic!("{other}"),
                Ok(_) => panic!("the read succeeds"),
            };
            if message == expected {
                continue;
            }
            let nodev = rustix::fs::statvfs(std::env::temp_dir())
                .is_ok_and(|vfs| vfs.f_flag.contains(rustix::fs::StatVfsMountFlags::NODEV));
            assert!(
                index >= 2 && nodev && message.starts_with(&denied),
                "{message}"
            );
        }
    }

    /// The read follows a symlink at the repository keyring to a file outside
    /// the repository, and reads the bytes of the target.
    #[cfg(unix)]
    #[test]
    fn the_repository_keyring_is_read_through_a_symlink_outside_the_repository() {
        let dir = scratch_dir();
        let repo = dir.join("repo");
        let remote = "ostrya-link-test";
        let name = remote_keyring_name(remote);
        std::fs::create_dir_all(&repo).unwrap();
        let target = dir.join("outside.gpg");
        std::fs::write(&target, b"outside bytes").unwrap();
        std::os::unix::fs::symlink(&target, repo.join(&name)).unwrap();
        let read = read_in(&repo, None, remote);
        std::fs::remove_dir_all(&dir).unwrap();
        let keyring = read.unwrap().unwrap();
        assert_eq!(keyring.bytes, b"outside bytes");
        assert_eq!(keyring.subject, format!("the keyring '{name}'"));
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

    /// The bytes of a file that the skipping load refuses: armor that does
    /// not decode.
    const BAD_ARMOR: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!!\n\
                               -----END PGP PUBLIC KEY BLOCK-----\n";

    /// Adds the keyrings of the caller paths `entries` to a new verifier, as
    /// the load of `gpgkeypath` does.
    fn keypath_load(entries: &[&Path]) -> Result<GpgVerifier> {
        let keypath: Vec<KeyPath> = entries.iter().map(KeyPath::caller).collect();
        let mut verifier = GpgVerifier::default();
        add_keypath(&mut verifier, "gpgkeypath", None, &keypath)?;
        Ok(verifier)
    }

    /// The load of a `gpgkeypath` directory reads each member that the
    /// listing gives as a regular file, with any name, in name order. It
    /// skips a subdirectory, a symlink to a file or to a directory, a
    /// dangling symlink, and a FIFO, and opens none of them.
    ///
    /// The hidden member `.a.gpg` and the member `.gpg` hold keys, and the
    /// verifier trusts both keys. An inotify watch on the directory records
    /// the name of each member that the load opens. The set of these names
    /// is the set of the regular members, so the load opens no FIFO, no
    /// symlink, and no subdirectory. The open of a FIFO with `O_NONBLOCK`
    /// does not block, so only the watch shows such an open.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_keypath_directory_gives_its_regular_members_in_name_order() {
        use std::collections::BTreeSet;
        use std::mem::MaybeUninit;
        use std::os::unix::fs::symlink;

        use ostrya_sign::Verifier as _;
        use rustix::fs::inotify;

        let with_keys = gpg_available();
        if !with_keys {
            assert!(
                std::env::var_os("OSTRYA_REQUIRE_GNUPG").is_none(),
                "OSTRYA_REQUIRE_GNUPG is set and `gpg` is not available"
            );
            eprintln!("skipping the trust arm: gpg not available");
        }
        let fixtures = with_keys.then(|| {
            [
                KeyFixture::new("Hidden <hidden@ostrya.example>"),
                KeyFixture::new("Dot <dot@ostrya.example>"),
            ]
        });
        let payload = b"keypath directory payload";
        let dir = scratch_dir();
        let keys = dir.join("keys");
        std::fs::create_dir_all(keys.join("sub")).unwrap();
        for name in ["a.keyring", "README"] {
            std::fs::write(keys.join(name), b"").unwrap();
        }
        let (hidden, dot) = match &fixtures {
            Some([hidden, dot]) => (hidden.export(true), dot.export(false)),
            None => (Vec::new(), Vec::new()),
        };
        std::fs::write(keys.join(".a.gpg"), hidden).unwrap();
        std::fs::write(keys.join(".gpg"), dot).unwrap();
        // Each of these names reaches a file that the load refuses, so a
        // read of one of them fails the load.
        std::fs::write(keys.join("sub/b.gpg"), BAD_ARMOR).unwrap();
        std::fs::write(dir.join("bad.asc"), BAD_ARMOR).unwrap();
        symlink(dir.join("bad.asc"), keys.join("link.gpg")).unwrap();
        symlink(dir.join("absent"), keys.join("dangling.gpg")).unwrap();
        symlink(keys.join("sub"), keys.join("linkdir")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            keys.join("fifo.gpg"),
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let watch = inotify::init(inotify::CreateFlags::NONBLOCK).unwrap();
        inotify::add_watch(&watch, &keys, inotify::WatchFlags::OPEN).unwrap();
        let skipped = keypath_load(&[&keys]);
        let mut opened = BTreeSet::new();
        let mut buf = [MaybeUninit::uninit(); 4096];
        let mut events = inotify::Reader::new(&watch, &mut buf);
        loop {
            match events.next() {
                Ok(event) => {
                    if let Some(name) = event.file_name() {
                        opened.insert(name.to_string_lossy().into_owned());
                    }
                }
                Err(rustix::io::Errno::AGAIN) => break,
                Err(e) => panic!("{e}"),
            }
        }
        std::fs::write(keys.join("y.asc"), BAD_ARMOR).unwrap();
        std::fs::write(keys.join("x.asc"), BAD_ARMOR).unwrap();
        let first = keypath_load(&[&keys]);
        std::fs::remove_dir_all(&dir).unwrap();
        let verifier = skipped.unwrap();
        assert_eq!(
            opened,
            BTreeSet::from([".a.gpg", ".gpg", "README", "a.keyring"].map(String::from))
        );
        if let Some(fixtures) = &fixtures {
            for fixture in fixtures {
                let signature = fixture.sign(payload);
                let outcome = verifier.verify(payload, &[signature]).unwrap();
                assert!(outcome.valid, "{:?}", outcome.signatures);
            }
        } else {
            assert!(verifier.is_empty());
        }
        let named = format!("the keyring '{}'", keys.join("x.asc").display());
        assert!(
            matches!(&first, Err(Error::Signature(m)) if m.starts_with(&named)),
            "{:?}",
            first.err()
        );
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
        let listed = std::fs::read_dir(&keys).is_ok();
        let result = keypath_load(&[&keys]);
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        // A process that holds the override of file permissions, as root
        // does, lists the directory. The case then has no refusal to observe.
        if listed {
            eprintln!("skipping: the directory lists with mode 000");
            return;
        }
        let expected = format!("gpgkeypath entry '{}' cannot be read: ", keys.display());
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
        let result = keypath_load(&[Path::new("")]);
        assert!(
            matches!(
                &result,
                Err(Error::Signature(m)) if m.starts_with("gpgkeypath entry '' cannot be read: ")
            ),
            "{:?}",
            result.err()
        );
    }

    /// An empty `gpgkeypath` entry of a `.conf` file names no file, as the
    /// same entry of `config` does, so the load gives the same refusal. The
    /// case runs for each form of the remotes directory, for an empty value,
    /// an empty first entry, and an empty entry between two entries. The
    /// remotes directory holds a keyring of another remote that the load
    /// refuses, so a read of the remotes directory gives another refusal.
    #[test]
    fn an_empty_keypath_entry_of_a_remotes_file_is_refused_as_in_config() {
        use crate::config::tests::repos_with_remotes_file;

        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        for (i, keypath) in ["", ";k.gpg", "k.gpg;;k.gpg"].into_iter().enumerate() {
            let root = dir.join(format!("repo-{i}"));
            let section =
                |name: &str| format!("[remote \"{name}\"]\nurl=http://h/\ngpgkeypath={keypath}\n");
            let repos = repos_with_remotes_file(&root, &section("c"), &section("o"));
            let remotes = root.join("remotes.d");
            for name in ["c.trustedkeys.gpg", "o.trustedkeys.gpg", "k.gpg"] {
                std::fs::write(root.join(name), b"").unwrap();
            }
            std::fs::write(remotes.join("k.gpg"), b"").unwrap();
            std::fs::write(remotes.join("other.trustedkeys.gpg"), BAD_ARMOR).unwrap();
            for repo in &repos {
                let in_config = GpgVerifier::for_remote_in(repo, "c");
                let in_file = GpgVerifier::for_remote_in(repo, "o");
                let expected = "gpgkeypath entry '' cannot be read: No such file or directory";
                for result in [&in_config, &in_file] {
                    assert!(
                        matches!(result, Err(Error::Signature(m)) if m.starts_with(expected)),
                        "{keypath:?} {:?}: {:?}",
                        repo.remotes_dir(),
                        result.as_ref().err()
                    );
                }
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A `gpgkeypath` file entry follows a symlink, and opens an absolute
    /// path with a `..` component. An absent entry, an entry over the
    /// keyring ceiling, and a FIFO fail the load, and the FIFO does not
    /// block it.
    #[cfg(unix)]
    #[test]
    fn a_keypath_file_entry_follows_a_symlink_and_refuses_a_fifo() {
        use std::os::unix::fs::symlink;

        let dir = scratch_dir();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("k.gpg"), b"").unwrap();
        symlink(dir.join("k.gpg"), dir.join("link.gpg")).unwrap();
        std::fs::write(dir.join("big.gpg"), vec![0u8; MAX_KEYRING as usize + 1]).unwrap();
        let fifo = dir.join("fifo.gpg");
        let made = rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .is_ok();
        let through = dir.join("sub/../k.gpg");
        let fifo_load = std::thread::spawn({
            let fifo = fifo.clone();
            move || keypath_load(&[&fifo])
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !fifo_load.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(fifo_load.is_finished(), "the load of a FIFO does not block");
        let fifo_result = fifo_load.join().unwrap();
        let link = keypath_load(&[&dir.join("link.gpg"), &through]);
        let absent = keypath_load(&[&dir.join("absent.gpg")]);
        let big = keypath_load(&[&dir.join("big.gpg")]);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(link.unwrap().is_empty());
        let expected = format!(
            "gpgkeypath entry '{}' cannot be read: ",
            dir.join("absent.gpg").display()
        );
        assert!(
            matches!(&absent, Err(Error::Signature(m)) if m.starts_with(&expected)),
            "{:?}",
            absent.err()
        );
        assert!(
            matches!(&big, Err(Error::Signature(m)) if m.contains("ceiling")),
            "{:?}",
            big.err()
        );
        if made {
            let expected = format!("the keyring '{}' is not a regular file", fifo.display());
            assert!(
                matches!(&fifo_result, Err(Error::Signature(m)) if *m == expected),
                "{:?}",
                fifo_result.err()
            );
        }
    }

    /// A keyring load refuses a `gpgkeypath` path of the caller that is
    /// relative and has a `..` component, before it reads a keyring.
    #[test]
    fn a_caller_keypath_with_a_parent_component_is_refused() {
        let result = GpgVerifier::for_remote_keyrings(None, "o", &[PathBuf::from("../k.gpg")]);
        assert!(
            matches!(&result, Err(Error::InvalidInput(m)) if m.contains("`..`")),
            "{:?}",
            result.err()
        );
    }

    /// Creates a repository at `root` whose config holds the remote `remote`
    /// with the key `gpgkeypath=keypath`, and opens it.
    fn repo_with_keypath(root: &Path, remote: &str, keypath: &str) -> Repo {
        use crate::{CreateOptions, RepoMode};

        ostrya_rt::block_on(async {
            Repo::create(root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let config = root.join("config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str(&format!(
                "\n[remote \"{remote}\"]\nurl=http://localhost/\ngpgkeypath={keypath}\n"
            ));
            std::fs::write(&config, text).unwrap();
            Repo::open(root).await.unwrap()
        })
    }

    /// A relative `gpgkeypath` entry in `config` is relative to the
    /// repository root, and not to the working directory. A relative entry
    /// with a `..` component is refused.
    #[test]
    fn a_relative_keypath_in_config_is_relative_to_the_root() {
        let dir = scratch_dir();
        let root = dir.join("repo");
        std::fs::create_dir_all(root.join("keys")).unwrap();
        let repo = repo_with_keypath(&root, "rel", "keys/k.gpg");
        let absent = GpgVerifier::for_remote_in(&repo, "rel");
        std::fs::write(root.join("keys/k.gpg"), b"").unwrap();
        let present = GpgVerifier::for_remote_in(&repo, "rel");
        drop(repo);
        let parent = repo_with_keypath(&dir.join("other"), "up", "../repo/keys/k.gpg");
        let refused = GpgVerifier::for_remote_in(&parent, "up");
        drop(parent);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            matches!(&absent, Err(Error::Signature(m))
                if m.starts_with("gpgkeypath entry 'keys/k.gpg' cannot be read: ")),
            "{:?}",
            absent.err()
        );
        present.unwrap();
        assert!(
            matches!(&refused, Err(Error::InvalidFormat(m))
                if m.starts_with("[remote \"up\"] gpgkeypath ../repo/keys/k.gpg has a `..`")),
            "{:?}",
            refused.err()
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
        let keyrings = GpgVerifier::for_remote_keyrings(None, "../x", &[]);
        let in_handle = GpgVerifier::for_remote_in(&handle, "../x");
        drop(handle);
        std::fs::remove_dir_all(&dir).unwrap();
        for result in [keyrings, in_handle] {
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
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("absent.gpg").to_string_lossy().into_owned();
        let repo = repo_with_keypath(&root, "keypath-order", &entry);
        std::fs::create_dir(root.join("keypath-order.trustedkeys.gpg")).unwrap();
        let result = GpgVerifier::for_remote_in(&repo, "keypath-order");
        drop(repo);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            matches!(
                &result,
                Err(Error::Signature(m))
                    if m == "the keyring 'keypath-order.trustedkeys.gpg' is not a regular file"
            ),
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
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let keyring = dir.join("k.gpg");
        std::fs::write(&keyring, key.export(false)).unwrap();
        let entry = keyring.to_string_lossy().into_owned();
        let repo = repo_with_keypath(&root, "keypath-trust", &entry);
        let trusted = GpgVerifier::for_remote_in(&repo, "keypath-trust")
            .unwrap()
            .verify(payload, std::slice::from_ref(&signature))
            .unwrap();
        let untrusted = GpgVerifier::for_remote_in(&repo, "keypath-other")
            .unwrap()
            .verify(payload, std::slice::from_ref(&signature))
            .unwrap();
        drop(repo);
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
            let absent = repo.gpg_import_keys("origin", &[&oversized], &[]).await;
            let absent_after = std::fs::exists(&keyring).unwrap();
            std::fs::write(&keyring, b"").unwrap();
            let empty = repo.gpg_import_keys("origin", &[&oversized], &[]).await;
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
            repo.gpg_import_keys("../x", &[], &[]).await
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

    /// Creates a repository at `root` and opens it.
    fn new_repo(root: &Path) -> Repo {
        use crate::{CreateOptions, RepoMode};

        ostrya_rt::block_on(async {
            Repo::create(root, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap()
        })
    }

    /// The `gpgkeys.gpg` keyring of a repository gives the keys of a binary
    /// and of an armored keyring, also through a symlink to a file outside
    /// the repository. With no file at the name, and with a symlink to no
    /// file, the verifier trusts no key.
    #[test]
    fn the_repository_gpgkeys_keyring_loads() {
        use ostrya_sign::Verifier as _;

        if !gpg_available() {
            assert!(
                std::env::var_os("OSTRYA_REQUIRE_GNUPG").is_none(),
                "OSTRYA_REQUIRE_GNUPG is set and `gpg` is not available"
            );
            eprintln!("skipping: gpg not available");
            return;
        }
        let key = KeyFixture::new("Repo keyring <gpgkeys@ostrya.example>");
        let payload = b"gpgkeys payload";
        let signature = key.sign(payload);
        let dir = scratch_dir();
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let repo = new_repo(&root);
        let keyring = root.join("gpgkeys.gpg");
        let outside = dir.join("outside.gpg");
        let verify = |repo: &Repo| {
            GpgVerifier::for_repo_in(repo)
                .unwrap()
                .verify(payload, std::slice::from_ref(&signature))
                .unwrap()
                .valid
        };
        let absent = GpgVerifier::for_repo_in(&repo).unwrap().is_empty();
        std::os::unix::fs::symlink(&outside, &keyring).unwrap();
        let dangling = GpgVerifier::for_repo_in(&repo).unwrap().is_empty();
        std::fs::write(&outside, key.export(false)).unwrap();
        let linked = verify(&repo);
        std::fs::remove_file(&keyring).unwrap();
        std::fs::write(&keyring, key.export(false)).unwrap();
        let binary = verify(&repo);
        std::fs::write(&keyring, key.export(true)).unwrap();
        let armored = verify(&repo);
        drop(repo);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(absent);
        assert!(dangling);
        assert!(linked);
        assert!(binary);
        assert!(armored);
    }

    /// A directory and a FIFO at `gpgkeys.gpg` are refused by name as files
    /// that are not regular files, and the FIFO does not block the read. A
    /// keyring over [`MAX_KEYRING`] is refused by name.
    #[cfg(unix)]
    #[test]
    fn a_gpgkeys_keyring_that_is_not_a_regular_file_is_refused() {
        let dir = scratch_dir();
        let root = dir.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let repo = new_repo(&root);
        let keyring = root.join("gpgkeys.gpg");
        let mut results = Vec::new();
        std::fs::create_dir(&keyring).unwrap();
        results.push(GpgVerifier::for_repo_in(&repo).map(|_| ()));
        std::fs::remove_dir(&keyring).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &keyring,
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let worker = {
            let repo = repo.clone();
            std::thread::spawn(move || GpgVerifier::for_repo_in(&repo).map(|_| ()))
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !worker.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let finished = worker.is_finished();
        if finished {
            results.push(worker.join().unwrap());
        }
        std::fs::remove_file(&keyring).unwrap();
        std::fs::File::create(&keyring)
            .unwrap()
            .set_len(MAX_KEYRING + 1)
            .unwrap();
        let over = GpgVerifier::for_repo_in(&repo).map(|_| ());
        drop(repo);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(finished, "the read does not end in 10 seconds");
        for result in results {
            assert!(
                matches!(&result, Err(Error::Signature(m))
                    if m == "the keyring 'gpgkeys.gpg' is not a regular file"),
                "{result:?}"
            );
        }
        assert!(
            matches!(&over, Err(Error::Signature(m))
                if *m == format!("the keyring 'gpgkeys.gpg' is over the {MAX_KEYRING}-byte ceiling")),
            "{over:?}"
        );
    }

    /// Returns `true` if the `gpg` binary runs.
    ///
    /// The trust group cases in `verify::trust` and the signing key cases in
    /// `sign::signing_key` build their fixtures with `gpg`. Each of these
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
