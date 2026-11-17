//! The reader of the key groups, `[ex-ostrya key "NAME"]`, and the build of
//! their signing keys.

use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;

use ostrya_core::KeyFile;

use crate::config::relative_with_parent;
use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::sign::key_text;
use crate::verify::read_key_file_at;
use crate::verify::trust::{unknown_key, valid_group_name};

use super::SigningKey;

/// The name prefix of a key group, before the quoted name.
const KEY_PREFIX: &str = "ex-ostrya key \"";

/// One key group as the check of its keys reads it.
pub(crate) enum KeySpec {
    Ed25519 {
        file: String,
    },
    #[cfg(feature = "sign-spki")]
    Spki {
        file: String,
    },
    #[cfg(feature = "sign-gpg")]
    Gpg {
        key: String,
        homedir: Option<String>,
    },
}

impl SigningKey {
    /// Builds the signing keys of the key group `[ex-ostrya key "NAME"]` of
    /// the config of `repo`, where `NAME` is `name`.
    ///
    /// The call reads the group from [`Repo::config`]. It checks and builds
    /// that group alone. It reads no client group, no server group, no trust
    /// group, and no other key group, so a malformed group that `name` does
    /// not name does not stop the call. `ostrya serve` and `ostrya receive`
    /// read the same groups, so one group holds one key for each of them.
    ///
    /// The group takes `type`, which is `ed25519`, `spki`, or `gpg`. An
    /// `ed25519` or `spki` group takes `secret-key-file`. A `gpg` group takes
    /// `gpg-key`, and `gpg-homedir` as an option.
    ///
    /// An `ed25519` group and a `gpg` group give one key. The
    /// `secret-key-file` of an `ed25519` group holds one base64 key on one
    /// line. The `secret-key-file` of an `spki` group holds PEM
    /// `PRIVATE KEY` blocks, as `spki_secret_keys` of the `spki` module reads
    /// them. Each block gives one key, in the order of the file. The list
    /// that the call returns is never empty.
    ///
    /// A relative `secret-key-file` is relative to the root of `repo`. The
    /// call reads the file on the blocking pool. The value of `gpg-homedir`
    /// goes to GnuPG unchanged, so a relative value is relative to the
    /// current directory of the process. A `gpg` group runs `gpg` at most
    /// two times: the listing of the secret key and the export of its public
    /// certificate.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `name` is empty or holds a `"` or a
    ///   control character. The message is
    ///   `malformed key group name '<name>': the name is not empty, and holds
    ///   no '"' and no control character`.
    /// - [`Error::InvalidInput`] if the config has no such group. The message
    ///   is `the config has no [ex-ostrya key "<name>"] group`.
    /// - [`Error::InvalidFormat`] if the group holds a key that it does not
    ///   take, has no `type`, has an unknown `type` or the type `dummy`, has
    ///   no value or an empty value for a required key, or has a relative
    ///   `secret-key-file` with a `..` component. The message names the
    ///   group.
    /// - [`Error::Unsupported`] if the group is an `spki` group in a build
    ///   with no `sign-spki` feature, or a `gpg` group in a build with no
    ///   `sign-gpg` feature.
    /// - [`Error::Signature`] if:
    ///   - the secret key file does not exist, cannot be opened or read, is
    ///     not a regular file, or is larger than
    ///     [`MAX_KEY_FILE`](crate::sign::MAX_KEY_FILE)
    ///   - the secret key file holds no key, or holds more than one key (an
    ///     `ed25519` group)
    ///   - `spki_secret_keys` refuses the secret key file of an `spki` group
    ///   - an engine refuses a key
    ///   - the GPG selector names no secret key or more than one
    ///   - `gpg` cannot start, a read of its output or the wait for it fails,
    ///     or `gpg` fails.
    ///
    ///   The message starts with `[ex-ostrya key "<name>"]: `.
    /// - [`Error::Core`] if a value holds a malformed escape sequence, or if
    ///   the key line of an `ed25519` secret key file is not valid base64.
    ///   The message does not name the group.
    ///
    /// # Examples
    ///
    /// Sign a commit with the keys of the group `release`, and skip each key
    /// that signed the commit before:
    ///
    /// ```no_run
    /// use ostrya::sign::SigningKey;
    /// use ostrya::{Checksum, Repo};
    ///
    /// # async fn run(commit: Checksum) -> ostrya::Result<()> {
    /// let repo = Repo::open("/srv/repo".as_ref()).await?;
    /// for key in SigningKey::from_key_group(&repo, "release").await? {
    ///     if !repo.has_signed_commit(&commit, &key).await? {
    ///         repo.sign_commit(&commit, key.signer()).await?;
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    pub async fn from_key_group(repo: &Repo, name: &str) -> Result<Vec<SigningKey>> {
        if !valid_group_name(name) {
            return Err(Error::InvalidInput(format!(
                "malformed key group name '{name}': the name is not empty, and holds no '\"' \
                 and no control character"
            )));
        }
        let group = format!("{KEY_PREFIX}{name}\"");
        let keyfile = repo.config().keyfile();
        if !keyfile.has_group(&group) {
            return Err(Error::InvalidInput(format!(
                "the config has no [{group}] group"
            )));
        }
        let spec = parse_key(keyfile, &group)?;
        build_signers(repo, name, &spec).await
    }
}

/// Reads the key group `group`.
pub(crate) fn parse_key(keyfile: &KeyFile, group: &str) -> Result<KeySpec> {
    for key in keyfile.keys(group) {
        if !matches!(key, "type" | "secret-key-file" | "gpg-key" | "gpg-homedir") {
            return Err(unknown_key(group, key));
        }
    }
    let foreign = |kind: &str, keys: &[&str]| -> Result<()> {
        match keys
            .iter()
            .find(|key| keyfile.get_value(group, key).is_some())
        {
            Some(key) => Err(Error::InvalidFormat(format!(
                "[{group}] holds '{key}', which a key of type {kind} does not take"
            ))),
            None => Ok(()),
        }
    };
    let required = |key: &str| -> Result<String> {
        match keyfile.get_string(group, key)? {
            Some(value) if !value.is_empty() => Ok(value),
            _ => Err(Error::InvalidFormat(format!("[{group}] needs {key}"))),
        }
    };
    // A relative path of the secret key file is relative to the repository
    // root, and cannot leave it through a `..` component.
    let key_file = || -> Result<String> {
        let value = required("secret-key-file")?;
        if relative_with_parent(Path::new(&value)) {
            return Err(Error::InvalidFormat(format!(
                "[{group}] secret-key-file {value} has a `..` component, which a relative \
                 path in a config cannot have"
            )));
        }
        Ok(value)
    };
    let Some(kind) = keyfile.get_string(group, "type")? else {
        return Err(Error::InvalidFormat(format!(
            "[{group}] needs type: ed25519, spki, or gpg"
        )));
    };
    match kind.as_str() {
        "ed25519" => {
            foreign(&kind, &["gpg-key", "gpg-homedir"])?;
            Ok(KeySpec::Ed25519 { file: key_file()? })
        }
        "spki" => {
            foreign(&kind, &["gpg-key", "gpg-homedir"])?;
            spki_key(group, key_file()?)
        }
        "gpg" => {
            foreign(&kind, &["secret-key-file"])?;
            let key = required("gpg-key")?;
            gpg_key(group, key, keyfile.get_string(group, "gpg-homedir")?)
        }
        "dummy" => Err(Error::InvalidFormat(format!(
            "malformed [{group}] type 'dummy': the dummy engine is not a signing key, \
             its signature is its key"
        ))),
        other => Err(Error::InvalidFormat(format!(
            "malformed [{group}] type '{other}': the type is ed25519, spki, or gpg"
        ))),
    }
}

/// Returns the spec of an spki key group whose keys passed their checks.
#[cfg(feature = "sign-spki")]
fn spki_key(_group: &str, file: String) -> Result<KeySpec> {
    Ok(KeySpec::Spki { file })
}

/// Refuses an spki key group with [`Error::Unsupported`] in a build without
/// the spki engine.
///
/// The build cannot sign with the key, so the refusal stops the build of the
/// key group before a caller signs with the key.
#[cfg(not(feature = "sign-spki"))]
fn spki_key(group: &str, _file: String) -> Result<KeySpec> {
    Err(Error::Unsupported(format!(
        "[{group}] is an spki key, which this build cannot sign with; build with \
         the sign-spki feature"
    )))
}

/// Returns the spec of a GPG key group whose keys passed their checks.
#[cfg(feature = "sign-gpg")]
fn gpg_key(_group: &str, key: String, homedir: Option<String>) -> Result<KeySpec> {
    Ok(KeySpec::Gpg { key, homedir })
}

/// Refuses a GPG key group with [`Error::Unsupported`] in a build without
/// GPG signing.
///
/// The build cannot sign with the key, so the refusal stops the build of the
/// key group before a caller signs with the key.
#[cfg(not(feature = "sign-gpg"))]
fn gpg_key(group: &str, _key: String, _homedir: Option<String>) -> Result<KeySpec> {
    Err(Error::Unsupported(format!(
        "[{group}] is a GPG key, which this build cannot sign with; build with the \
         sign-gpg feature"
    )))
}

/// Builds the signers of the key group `name`.
///
/// An ed25519 or GPG key group gives one signer. An spki key group gives one
/// signer for each `PRIVATE KEY` block of its secret key file, in the order of
/// the file. A relative path of the secret key file is relative to the root of
/// `repo`.
pub(crate) async fn build_signers(
    repo: &Repo,
    name: &str,
    spec: &KeySpec,
) -> Result<Vec<SigningKey>> {
    let label = format!("[{KEY_PREFIX}{name}\"]");
    let in_group = |e: Error| match e {
        Error::Signature(message) => Error::Signature(format!("{label}: {message}")),
        other => other,
    };
    match spec {
        KeySpec::Ed25519 { file } => {
            let line = secret_key_line(repo, file).await.map_err(in_group)?;
            let signer =
                SigningKey::ed25519(&ostrya_core::base64::decode(&line)?).map_err(in_group)?;
            Ok(vec![signer])
        }
        #[cfg(feature = "sign-spki")]
        KeySpec::Spki { file } => secret_key_blocks(repo, file)
            .await
            .map_err(in_group)?
            .into_iter()
            .map(|signer| SigningKey::spki(signer).map_err(in_group))
            .collect(),
        #[cfg(feature = "sign-gpg")]
        KeySpec::Gpg { key, homedir } => {
            let mut signer = crate::gpg::GpgSigner::new(key.as_str());
            if let Some(dir) = homedir {
                signer = signer.with_homedir(dir);
            }
            Ok(vec![SigningKey::gpg(signer).await.map_err(in_group)?])
        }
    }
}

/// Returns the one secret key that the file at `path` holds, as its base64
/// line. A relative `path` is relative to the root of `repo`.
///
/// The read runs on the blocking pool.
async fn secret_key_line(repo: &Repo, path: &str) -> Result<String> {
    let repo = repo.clone();
    let path = path.to_owned();
    ostrya_rt::unblock(move || read_secret_key_line(repo.root_dir().as_fd(), &path)).await
}

/// Reads the one secret key line of the file at `path` relative to `root`,
/// the blocking half of `secret_key_line`.
///
/// The read obeys the rule of every key source: a regular file alone, of at
/// most [`MAX_KEY_FILE`](crate::sign::MAX_KEY_FILE) bytes. The function
/// skips blank lines. The file must hold exactly one other line.
fn read_secret_key_line(root: BorrowedFd<'_>, path: &str) -> Result<String> {
    let subject = format!("the secret key file '{path}'");
    let bytes = read_key_file_at(root, Path::new(path), &subject)?;
    let text = key_text(bytes, &subject)?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    match (lines.next(), lines.next()) {
        (Some(line), None) => Ok(line.to_owned()),
        (None, _) => Err(Error::Signature(format!("{subject} holds no key"))),
        (Some(_), Some(_)) => Err(Error::Signature(format!(
            "{subject} holds more than one key"
        ))),
    }
}

/// Returns the signers of the spki secret key file at `path`, one for each
/// `PRIVATE KEY` block, in the order of the file. A relative `path` is
/// relative to the root of `repo`.
///
/// The read runs on the blocking pool.
#[cfg(feature = "sign-spki")]
async fn secret_key_blocks(repo: &Repo, path: &str) -> Result<Vec<crate::spki::SpkiSigner>> {
    let repo = repo.clone();
    let path = path.to_owned();
    ostrya_rt::unblock(move || read_secret_key_blocks(repo.root_dir().as_fd(), &path)).await
}

/// Reads the signers of the spki secret key file at `path` relative to
/// `root`, the blocking half of `secret_key_blocks`.
///
/// The read obeys the rule of every key source: a regular file alone, of at
/// most [`MAX_KEY_FILE`](crate::sign::MAX_KEY_FILE) bytes.
/// `spki_secret_keys` reads the blocks and states the rules of the file.
#[cfg(feature = "sign-spki")]
fn read_secret_key_blocks(
    root: BorrowedFd<'_>,
    path: &str,
) -> Result<Vec<crate::spki::SpkiSigner>> {
    let subject = format!("the secret key file '{path}'");
    let bytes = read_key_file_at(root, Path::new(path), &subject)?;
    Ok(crate::spki::spki_secret_keys(bytes, &subject)?)
}
