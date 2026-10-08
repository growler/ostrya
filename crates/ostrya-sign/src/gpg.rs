//! The GPG signing engine, behind the `sign-gpg` feature.
//!
//! The doc of `GpgSigner` holds the key selection, the signing process, and
//! the signature format.

use std::path::{Path, PathBuf};

use crate::{Error, Result, SignFuture, Signer};

/// The short name of the GPG engine.
const GPG_SIGN_TYPE: &str = "gpg";
/// The key of the GPG engine in the detached-metadata dict.
///
/// The GPG verifier of `ostrya` holds a copy of this key, and the two must
/// agree.
const GPG_METADATA_KEY: &str = "ostree.gpgsigs";
/// The prefix of a machine-readable status line on the status fd.
const STATUS_PREFIX: &str = "[GNUPG:] ";

/// The GPG signing engine.
///
/// The signer holds a key selector and an optional GnuPG home directory. It
/// signs through the `gpg` command of GnuPG. This crate has no GPG verifier.
/// The `ostrya` crate verifies GPG signatures.
///
/// # Key selection
///
/// The key selector is a fingerprint, a key id, or a user id. `gpg
/// --local-user` resolves it in a GnuPG home directory. If the signer has no
/// home directory, `gpg` uses its default home directory.
/// [`with_homedir`](GpgSigner::with_homedir) sets a home directory, which the
/// signer gives to `gpg` as `--homedir`.
///
/// # Signing
///
/// [`sign`](Signer::sign) runs `gpg --detach-sign` as a short-lived process.
/// The process runs through the `ostrya-rt` crate, on the runtime that the
/// `smol` or `tokio` feature selects. The payload goes to standard input, and
/// the binary signature comes from standard output.
///
/// `gpg` does the private-key operation. It uses `gpg-agent` and any hardware
/// token behind it. The private key stays with GnuPG and its agent and never
/// goes through this crate.
///
/// # Signature format
///
/// - The engine name is `gpg`.
/// - The metadata key is `ostree.gpgsigs`. The key of each other engine of
///   this crate has the form `ostree.sign.<type>`.
/// - Each `ay` element of the array under the key is one detached OpenPGP
///   signature. It is the binary packet stream, with no ASCII armor.
///   [`append_signature`](crate::append_signature) gives the layout.
/// - One element can hold more than one signature packet.
/// - The signed payload is the same for each engine. [`Signer::sign`] states
///   it.
///
/// # Errors
///
/// [`sign`](Signer::sign) returns [`Error::Signature`] in these cases:
///
/// - `gpg` cannot start. If `gpg` is not in `PATH`, the message is
///   `gpg: program not found in PATH`. For another failure, the message is
///   `gpg: <io error>`.
/// - `gpg` exits with a failure status, or it writes no signature. The message
///   is `gpg --detach-sign failed: <text>`. The text is the lines of standard
///   error that do not start with `[GNUPG:] `, joined with `"; "`. If there
///   are no such lines, the text is the exit status of `gpg`, for example
///   `exit status: 1` on Unix.
#[derive(Debug, Clone)]
pub struct GpgSigner {
    key: String,
    homedir: Option<PathBuf>,
}

impl GpgSigner {
    /// Creates a signer for `key` in the default GnuPG home directory.
    pub fn new(key: impl Into<String>) -> GpgSigner {
        GpgSigner {
            key: key.into(),
            homedir: None,
        }
    }

    /// Sets `dir` as the GnuPG home directory in which `gpg` resolves the key.
    pub fn with_homedir(mut self, dir: impl Into<PathBuf>) -> GpgSigner {
        self.homedir = Some(dir.into());
        self
    }

    /// Returns the GnuPG home directory, or `None` for the default of `gpg`.
    pub fn homedir(&self) -> Option<&Path> {
        self.homedir.as_deref()
    }

    /// Returns the fingerprints of the secret keys that the key selector names.
    ///
    /// The method runs `gpg --list-secret-keys` with the selector. That
    /// command lists the keys. It does not use the private key material, and
    /// it starts no signing operation.
    ///
    /// The list holds the fingerprint of each primary key, in the order of the
    /// `gpg` listing. It holds no subkey fingerprints. If the list holds more
    /// than one fingerprint, the selector names more than one key. A caller
    /// that needs a single signing key refuses such a selector.
    ///
    /// If `gpg` exits with a failure status, the list is empty. `gpg` gives a
    /// failure status in these cases:
    ///
    /// - The home directory does not exist.
    /// - The home directory cannot be read.
    /// - The home directory holds no matching key.
    ///
    /// A caller can report one "no such key" refusal for the three cases.
    ///
    /// The selector comes after `--`, so `gpg` reads it only as a key name.
    /// Without the `--`, `gpg` reads a selector in the form of an option as
    /// one of its own options. For example, the selector `--homedir=<path>`
    /// moves the lookup to another home directory. `gpg` then creates a keybox
    /// and a trust database there.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if `gpg` cannot start. If `gpg` is not in
    ///   `PATH`, the message is `gpg: program not found in PATH`. For another
    ///   failure, the message is `gpg: <io error>`.
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
/// Each `sec` record starts one key. The `fpr` record after it holds the
/// fingerprint of that key in field ten. An `ssb` record starts a subkey. The
/// `fpr` record of a subkey names the subkey, and the function skips it.
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

/// Wraps a spawn failure. If the program is missing, the message names it.
fn spawn_err(program: &str, err: &std::io::Error) -> Error {
    if err.kind() == std::io::ErrorKind::NotFound {
        Error::Signature(format!("{program}: program not found in PATH"))
    } else {
        Error::Signature(format!("{program}: {err}"))
    }
}

/// The failure text of a finished `gpg` run.
///
/// The text is the stderr lines that are not status lines. If there are no
/// such lines, the text is the exit status.
fn failure_text(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = stderr
        .lines()
        .filter(|line| !line.starts_with(STATUS_PREFIX))
        .collect::<Vec<_>>()
        .join("; ");
    if text.trim().is_empty() {
        output.status.to_string()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn failure_text_without_stderr_text_is_exit_status() {
        use std::os::unix::process::ExitStatusExt;

        // Stderr holds only a status line, so the text is the exit status.
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: format!("{STATUS_PREFIX}FAILURE sign 1\n").into_bytes(),
        };
        assert_eq!(failure_text(&output), "exit status: 1");
    }
}
