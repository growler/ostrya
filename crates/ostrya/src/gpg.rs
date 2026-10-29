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
//! - `gpg --export` under the `receive` and `sign-gpg` features. It reads the
//!   public certificate of a server signing key, so the receive path can
//!   recognize a signature that this key made.
//!
//! The private key stays with GnuPG and its agent. It never goes through this
//! crate.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use ostrya_sign::{MAX_KEYRING, gpg_keyring_keys, gpg_merge_keyring, gpg_offered_keys};

use crate::config::remote_keyring_name;
use crate::error::{Error, Result};
use crate::repo::Repo;
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
/// The system directory of the configuration and the keyrings of each remote.
const SYSTEM_REMOTES_D: &str = "/etc/ostree/remotes.d";

/// A GPG verifier that loads its keyrings from the ostree keyring paths.
///
/// The `ostrya-sign` crate has no ostree search path, so this crate adds the
/// constructors as a trait. A caller brings the trait into scope to call them.
pub trait FromOstreeKeyrings: Sized {
    /// Creates a verifier from the keyrings that `remote` trusts.
    ///
    /// The trusted set is the union of these keyrings:
    ///
    /// - `<remote>.trustedkeys.gpg` in the repository at `repo_path`.
    /// - `<remote>.trustedkeys.gpg` in `/etc/ostree/remotes.d/`.
    /// - The global trusted set of
    ///   [`from_system_trust`](FromOstreeKeyrings::from_system_trust).
    ///
    /// If a path does not exist, the load skips it.
    ///
    /// # Errors
    ///
    /// - The errors of [`from_keyring_files`](GpgVerifier::from_keyring_files)
    ///   for each keyring file.
    /// - [`Error::Io`] if the global trusted directory cannot be listed for a
    ///   reason other than its absence.
    fn for_remote(repo_path: &Path, remote: &str) -> Result<Self>;

    /// Creates a verifier from the whole trusted set of a remote.
    ///
    /// `repo_keyring` holds the bytes of the `<remote>.trustedkeys.gpg` file
    /// of the repository. A caller that holds a descriptor and no path reads
    /// this file itself. A pull trusts the union of these keyrings:
    ///
    /// - `repo_keyring`.
    /// - The system keyring of the remote,
    ///   `/etc/ostree/remotes.d/<remote>.trustedkeys.gpg`.
    /// - The global trusted set of
    ///   [`from_system_trust`](FromOstreeKeyrings::from_system_trust).
    /// - Each entry of `keypath`, which holds the values of the `gpgkeypath`
    ///   key of the remote.
    ///
    /// A `keypath` entry is a keyring file or a directory of `*.gpg` keyrings.
    /// The keyrings of a directory load in name order. The load takes only the
    /// regular files of a directory, and skips a symlink. If an entry names
    /// neither, the build fails. So a missing keyring path gives an error, and
    /// the trusted set does not become smaller with no message. The other
    /// sources are optional, and the load skips a missing one.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if the metadata of a `keypath` entry cannot be
    ///   read. The message names `gpgkeypath` and the entry.
    /// - [`Error::Io`] if a directory that an entry names, or the global
    ///   trusted directory, cannot be listed.
    /// - The errors of [`from_keyring_bytes`](GpgVerifier::from_keyring_bytes)
    ///   for `repo_keyring`.
    /// - The errors of [`from_keyring_files`](GpgVerifier::from_keyring_files)
    ///   for each keyring file.
    fn for_remote_keyrings(
        repo_keyring: Option<Vec<u8>>,
        remote: &str,
        keypath: &[String],
    ) -> Result<Self>;

    /// Creates a verifier from the global trusted keyrings only.
    ///
    /// The global trusted set is each `*.gpg` keyring in the directory that the
    /// `OSTREE_GPG_HOME` environment variable names. If this variable is unset
    /// or empty, the directory is `/usr/share/ostree/trusted.gpg.d/`. The
    /// keyrings load in name order. The load takes only the regular files of
    /// the directory, and skips a symlink. No keyring of a remote takes part.
    ///
    /// This is the trust for a commit that names no remote. If the directory
    /// does not exist, the trusted set is empty.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the directory cannot be listed for a reason other
    ///   than its absence.
    /// - The errors of [`from_keyring_files`](GpgVerifier::from_keyring_files)
    ///   for each keyring file.
    fn from_system_trust() -> Result<Self>;
}

impl FromOstreeKeyrings for GpgVerifier {
    fn for_remote(repo_path: &Path, remote: &str) -> Result<GpgVerifier> {
        let keyring = repo_path.join(format!("{remote}.trustedkeys.gpg"));
        let repo_keyring = read_keyring_path(&keyring)?;
        GpgVerifier::for_remote_keyrings(repo_keyring, remote, &[])
    }

    fn for_remote_keyrings(
        repo_keyring: Option<Vec<u8>>,
        remote: &str,
        keypath: &[String],
    ) -> Result<GpgVerifier> {
        remote_keyrings(repo_keyring, remote, keypath, true)
    }

    fn from_system_trust() -> Result<GpgVerifier> {
        Ok(GpgVerifier::from_keyring_files(keyring_files_in(
            &global_trusted_dir(),
        )?)?)
    }
}

/// Creates a verifier from the keyrings of a remote, as
/// [`for_remote_keyrings`](FromOstreeKeyrings::for_remote_keyrings) does.
///
/// If `global` is `false`, the global trusted set takes no part, and the
/// trusted set is `repo_keyring`, the system keyring of the remote, and the
/// entries of `keypath` alone.
pub(crate) fn remote_keyrings(
    repo_keyring: Option<Vec<u8>>,
    remote: &str,
    keypath: &[String],
    global: bool,
) -> Result<GpgVerifier> {
    let mut paths: Vec<PathBuf> = Vec::new();
    paths.push(Path::new(SYSTEM_REMOTES_D).join(format!("{remote}.trustedkeys.gpg")));
    if global {
        paths.extend(keyring_files_in(&global_trusted_dir())?);
    }
    paths.extend(keypath_files("gpgkeypath", keypath)?);
    let mut verifier = GpgVerifier::default();
    if let Some(bytes) = repo_keyring {
        verifier.add_keyring(&bytes, &format!("the keyring '{remote}.trustedkeys.gpg'"))?;
    }
    verifier.add_keyring_files(paths)?;
    Ok(verifier)
}

/// Creates a verifier from the keyrings that `keypath` names, and from no
/// other source.
///
/// No keyring of a remote and no global trusted set take part. Each entry
/// is a keyring file or a directory of `*.gpg` keyrings. If an entry names
/// neither, the build fails. `key` is the configuration key of the entries,
/// and a refusal names it.
///
/// If the keyrings hold no certificate, the build fails with
/// [`Error::Signature`]. An empty file and a directory with no `*.gpg`
/// keyring are examples. A verifier with no trusted key refuses every
/// commit.
pub(crate) fn from_keypath(key: &str, keypath: &[String]) -> Result<GpgVerifier> {
    let mut verifier = GpgVerifier::default();
    verifier.add_keyring_files(keypath_files(key, keypath)?)?;
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
    /// - [`Error::Io`] if a lock file, the read of the keyring, the write of
    ///   the keyring, or the sync of the repository directory fails.
    pub async fn gpg_import_keys(
        &self,
        remote: &str,
        keys: &[u8],
        key_ids: &[String],
    ) -> Result<usize> {
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
    /// The keyring is `<remote>.trustedkeys.gpg` at the repository root. The
    /// keys come in the order of their certificates in the keyring. If the
    /// keyring does not exist, the list is empty.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if the keyring is over 4 MiB, is a GnuPG keybox,
    ///   holds more than 256 certificates, or does not parse as an OpenPGP
    ///   keyring.
    /// - [`Error::InvalidFormat`] if the keyring is larger than 64 MiB, the
    ///   cap of its read.
    /// - [`Error::Signature`] if an armored keyring is not valid UTF-8.
    /// - [`Error::Core`] if the armor of the keyring holds text that is not
    ///   valid base64.
    /// - [`Error::Io`] if the read of the keyring fails.
    pub async fn gpg_list_keys(&self, remote: &str) -> Result<Vec<GpgKey>> {
        let name = remote_keyring_name(remote);
        let Some(keyring) = self.read_root_file(&name).await? else {
            return Ok(Vec::new());
        };
        let subject = format!("the keyring '{name}'");
        Ok(ostrya_rt::unblock(move || gpg_keyring_keys(&keyring, &subject)).await?)
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

/// Returns the `*.gpg` keyring files in `dir`, sorted by name.
///
/// If the directory does not exist, the result is an empty list.
fn keyring_files_in(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "gpg") {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Returns the keyring files that the entries of a keyring path name, in
/// entry order.
///
/// An entry that names a file gives that file. An entry that names a directory
/// gives the `*.gpg` keyrings in it, sorted by name. If an entry cannot be
/// read, the refusal names `key`, the configuration key of the entry, and the
/// text of the entry.
fn keypath_files(key: &str, keypath: &[String]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in keypath {
        let path = Path::new(entry);
        let meta = std::fs::metadata(path)
            .map_err(|e| Error::Signature(format!("{key} entry '{entry}' cannot be read: {e}")))?;
        if meta.is_dir() {
            paths.extend(keyring_files_in(path)?);
        } else {
            paths.push(path.to_owned());
        }
    }
    Ok(paths)
}

/// Returns the public certificate of the key that `fingerprint` names, as
/// `gpg --export` writes it.
///
/// `gpg` uses the GnuPG home `homedir`, or its own default home if `homedir`
/// is `None`. The receive path trusts this certificate to recognize a
/// signature that its own server key made.
///
/// The export has the limit [`MAX_KEYRING`]. The read stops one byte after
/// the limit and refuses the export. So the output size of `gpg` cannot set
/// the size of an allocation. The call also refuses an export that fails or
/// writes nothing.
///
/// `gpg` writes its standard error to the standard error of this process. The
/// call does not capture it. A refused export names the exit status of `gpg`,
/// and does not hold the text that `gpg` wrote.
///
/// The fingerprint comes after `--`, so `gpg` reads it only as a key name.
#[cfg(all(feature = "receive", feature = "sign-gpg"))]
pub(crate) async fn export_public_key(
    homedir: Option<&Path>,
    fingerprint: &str,
) -> Result<Vec<u8>> {
    use futures_lite::AsyncReadExt;

    let mut cmd = ostrya_rt::Command::new("gpg");
    if let Some(dir) = homedir {
        cmd.arg("--homedir").arg(dir);
    }
    cmd.arg("--batch")
        .arg("--quiet")
        .arg("--export")
        .arg("--")
        .arg(fingerprint);
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::Signature("gpg: program not found in PATH".into())
        } else {
            Error::Signature(format!("gpg: {e}"))
        }
    })?;
    let mut exported = Vec::new();
    let read = match child.take_stdout() {
        Some(stdout) => stdout
            .take(MAX_KEYRING + 1)
            .read_to_end(&mut exported)
            .await
            .map(|_| ()),
        None => Ok(()),
    };
    let status = child.wait().await?;
    read?;
    if exported.len() as u64 > MAX_KEYRING {
        return Err(Error::Signature(format!(
            "gpg --export of '{fingerprint}' is over the {MAX_KEYRING}-byte ceiling"
        )));
    }
    if !status.success() || exported.is_empty() {
        return Err(Error::Signature(format!(
            "gpg --export of '{fingerprint}' gave no certificate: exit status {status}"
        )));
    }
    Ok(exported)
}

/// Reads the keyring at `path`, up to [`MAX_KEYRING`].
///
/// Returns `None` if no file is at `path`. Each keyring source gets into the
/// trusted set through this function.
fn read_keyring_path(path: &Path) -> Result<Option<Vec<u8>>> {
    let subject = format!("the keyring '{}'", path.display());
    read_key_path(path, &subject, MAX_KEYRING)
}

/// Reads an open keyring through [`read_key_source`], the reader of each key
/// source.
///
/// The reader accepts only a regular file, up to [`MAX_KEYRING`]. A refusal
/// reports `name`, so an operator can find the entry that named the keyring.
///
/// A keyring has its own limit, because it holds certificates and no base64
/// lines. The call refuses a keyring over the limit by name, and does not read
/// the part under the limit. `gpgkeypath` applies the same rule to an entry
/// that names nothing.
pub(crate) fn read_keyring_fd(fd: OwnedFd, name: &str) -> Result<Vec<u8>> {
    Ok(read_key_source(
        std::fs::File::from(fd),
        &format!("the keyring '{name}'"),
        MAX_KEYRING,
    )?)
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
    use super::*;

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
