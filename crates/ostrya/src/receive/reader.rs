//! The reader of the trust groups and the key groups, and the build of the
//! receive policy of each client group.
//!
//! The reader makes two passes. The first pass checks each trust group and
//! each key group, and refuses each key and each value outside the syntax.
//! This pass reads no file and runs no program.
//!
//! The second pass builds each key group and each trust group once, in file
//! order. It also builds a group that no client group names. The policies get
//! shared handles to these objects.

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;
use std::sync::Arc;

use ostrya_core::KeyFile;
use rustix::io::Errno;

use crate::access::{ClientAccess, Group, classify};
use crate::config::relative_with_parent;
use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::repo_fs::{FsError, Named, Reason, open_named};
use crate::sign::{MAX_KEY_FILE, key_text, read_key_source};
use crate::verify::trust::{check_trust, unknown_key};

use super::{ReceivePolicy, ReceiveVerify, ServerSigner, TrustedKeys};

/// The name prefix of a key group, before the quoted name.
const KEY_PREFIX: &str = "ex-ostrya key \"";

/// One key group as the first pass reads it.
enum KeySpec {
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

/// Reads the client groups of the config of `repo`, and returns them with the
/// receive policy of each group, in the order of the groups.
pub(crate) async fn read(repo: &Repo) -> Result<(ClientAccess, Vec<Arc<ReceivePolicy>>)> {
    let config = repo.config();
    let access = ClientAccess::from_config(config, repo.path())?;
    let keyfile = config.keyfile();

    // The first pass checks each key group, then each trust group. The
    // access reader refused each other group name with the extension prefix.
    let mut builds: Vec<(Group<'_>, &str)> = Vec::new();
    for group in keyfile.groups() {
        if let Some(found @ (Group::Trust(_) | Group::Key(_))) = classify(group)? {
            builds.push((found, group));
        }
    }
    let mut keys: HashMap<&str, KeySpec> = HashMap::new();
    for (build, group) in &builds {
        if let Group::Key(name) = build {
            keys.insert(name, parse_key(keyfile, group)?);
        }
    }
    for (build, group) in &builds {
        if let Group::Trust(_) = build {
            check_trust(keyfile, group)?;
        }
    }

    // The second pass builds each key group and each trust group once, in
    // file order.
    let mut signers: HashMap<&str, Vec<Arc<ServerSigner>>> = HashMap::new();
    let mut trusts: HashMap<&str, Arc<TrustedKeys>> = HashMap::new();
    for (build, _) in builds {
        match build {
            Group::Key(name) => {
                let built = build_signers(repo, name, &keys[name]).await?;
                signers.insert(name, built.into_iter().map(Arc::new).collect());
            }
            Group::Trust(name) => {
                let built = TrustedKeys::from_trust_group(repo, name).await?;
                trusts.insert(name, Arc::new(built));
            }
            _ => {}
        }
    }

    let named = |names: &[String]| -> Vec<Arc<ServerSigner>> {
        names
            .iter()
            .flat_map(|name| signers[name.as_str()].iter().map(Arc::clone))
            .collect()
    };
    let summary_signers = named(access.server().sign_summary.as_deref().unwrap_or_default());
    let update_summary = config.auto_update_summary()?;
    let policies = access
        .groups()
        .iter()
        .map(|group| {
            Arc::new(ReceivePolicy {
                rules: group.rules().clone(),
                verify: match group.verify_trust() {
                    Some(name) => ReceiveVerify::Keys(Arc::clone(&trusts[name])),
                    None => ReceiveVerify::Off,
                },
                allow_unsigned: group.allow_unsigned(),
                signers: named(group.sign()),
                allow_privileged: group.allow_privileged(),
                disable_verify_bindings: group.disable_verify_bindings(),
                summary_signers: summary_signers.clone(),
                update_summary,
                group: Some(group.name().to_owned()),
            })
        })
        .collect();
    Ok((access, policies))
}

/// Reads the key group `group`.
fn parse_key(keyfile: &KeyFile, group: &str) -> Result<KeySpec> {
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
/// The build cannot sign with the key, so the refusal stops the policy before
/// it accepts a session.
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
/// The build cannot sign with the key, so the refusal stops the policy before
/// it accepts a session.
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
async fn build_signers(repo: &Repo, name: &str, spec: &KeySpec) -> Result<Vec<ServerSigner>> {
    let label = format!("[{KEY_PREFIX}{name}\"]");
    let in_group = |e: Error| match e {
        Error::Signature(message) => Error::Signature(format!("{label}: {message}")),
        other => other,
    };
    match spec {
        KeySpec::Ed25519 { file } => {
            let line = secret_key_line(repo, file).await.map_err(in_group)?;
            let signer =
                ServerSigner::ed25519(&ostrya_core::base64::decode(&line)?).map_err(in_group)?;
            Ok(vec![signer])
        }
        #[cfg(feature = "sign-spki")]
        KeySpec::Spki { file } => secret_key_blocks(repo, file)
            .await
            .map_err(in_group)?
            .into_iter()
            .map(|signer| ServerSigner::spki(signer).map_err(in_group))
            .collect(),
        #[cfg(feature = "sign-gpg")]
        KeySpec::Gpg { key, homedir } => {
            let mut signer = crate::gpg::GpgSigner::new(key.as_str());
            if let Some(dir) = homedir {
                signer = signer.with_homedir(dir);
            }
            Ok(vec![ServerSigner::gpg(signer).await.map_err(in_group)?])
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
/// most [`MAX_KEY_FILE`] bytes. The function skips blank lines. The file must
/// hold exactly one other line.
fn read_secret_key_line(root: BorrowedFd<'_>, path: &str) -> Result<String> {
    let subject = format!("the secret key file '{path}'");
    let bytes = read_secret_key_file(root, path, &subject)?;
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
/// most [`MAX_KEY_FILE`] bytes. `spki_secret_keys` reads the blocks and states
/// the rules of the file.
#[cfg(feature = "sign-spki")]
fn read_secret_key_blocks(
    root: BorrowedFd<'_>,
    path: &str,
) -> Result<Vec<crate::spki::SpkiSigner>> {
    let subject = format!("the secret key file '{path}'");
    let bytes = read_secret_key_file(root, path, &subject)?;
    Ok(crate::spki::spki_secret_keys(bytes, &subject)?)
}

/// Reads the whole secret key file at `path` relative to `root`, up to
/// [`MAX_KEY_FILE`] bytes. `subject` names the file in a refusal.
///
/// The open follows a symlink at each component of the path, and uses
/// `O_NONBLOCK`. The type check after the open refuses each file that is not
/// a regular file, so a FIFO does not block the read.
fn read_secret_key_file(root: BorrowedFd<'_>, path: &str, subject: &str) -> Result<Vec<u8>> {
    let fd = match open_named(root, Path::new(path), Named::File) {
        Ok(fd) => fd,
        Err(FsError::Absent { .. }) => {
            return Err(Error::Signature(format!("{subject} does not exist")));
        }
        Err(FsError::Invalid {
            reason: Reason::NotRegular(_),
            ..
        }) => return Err(Error::Signature(format!("{subject} is not a regular file"))),
        Err(FsError::Invalid {
            reason: Reason::NotDirectory,
            ..
        }) => {
            return Err(Error::Signature(format!(
                "{subject} cannot be opened: {}",
                std::io::Error::from(Errno::NOTDIR)
            )));
        }
        Err(FsError::Io(e)) => {
            return Err(Error::Signature(format!("{subject} cannot be opened: {e}")));
        }
        Err(other) => return Err(other.into()),
    };
    Ok(read_key_source(
        std::fs::File::from(fd),
        subject,
        MAX_KEY_FILE,
    )?)
}
