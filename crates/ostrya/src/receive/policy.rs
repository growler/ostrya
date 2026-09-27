//! The receive policy and its configuration keys.

use std::path::Path;

use crate::config::RepoConfig;
use crate::error::{Error, Result};
use crate::pull::DetachedMetadataFilter;
use crate::repo::Repo;
use crate::sign::{MAX_KEY_FILE, key_text, read_key_path};

use super::ServerSigner;

/// What a receiving repository accepts, and what it does after it accepts a
/// session.
///
/// [`Default`] is the strictest policy: fast-forward updates only, no delete,
/// no privileged content, no remote ref, no signature required, no server key,
/// no summary regeneration, and no detached-metadata filter.
/// [`ReceivePolicy::from_config`] reads the policy a repository's
/// configuration states.
#[derive(Debug, Default)]
pub struct ReceivePolicy {
    /// Accept a ref update whose new commit does not descend from the current
    /// one, where the client asks for it.
    pub allow_non_fast_forward: bool,
    /// Accept a ref delete.
    pub allow_delete: bool,
    /// Accept privileged content in a `bare` repository: a setuid or setgid
    /// mode bit, and the `security.capability` and `security.selinux`
    /// extended attributes.
    pub allow_privileged: bool,
    /// Accept a ref update that names a remote ref, `REMOTE:NAME`.
    pub allow_remote_refs: bool,
    /// The signatures each commit that becomes the new value of a ref must
    /// carry.
    pub require_signature: ReceiveVerify,
    /// The keys the server signs each such commit with, in order.
    pub signers: Vec<ServerSigner>,
    /// Sign the regenerated summary with [`signers`](ReceivePolicy::signers).
    pub sign_summary: bool,
    /// Regenerate the summary after a session that writes a ref.
    pub update_summary: bool,
    /// The detached-metadata keys the repository does not store, `None` to
    /// store every key.
    pub detached_metadata_filter: Option<DetachedMetadataFilter>,
}

/// The signatures a received commit must carry.
///
/// The two axes are ANDed: with `gpg` true and `sign` not empty, a commit needs
/// a valid GPG signature and a valid sign-api signature. The engines of `sign`
/// are ORed: one valid signature from one of them is enough. `gpg` false with
/// an empty `sign` requires no signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiveVerify {
    /// Require a GPG signature from a key of `[ex-ostrya] receive-gpgkeypath`.
    pub gpg: bool,
    /// Require a signature from one of these sign-api engines, each named once,
    /// from a key of its `receive-verification-<engine>-key` or
    /// `receive-verification-<engine>-file`.
    pub sign: Vec<String>,
}

impl ReceivePolicy {
    /// The policy the configuration of `repo` states.
    ///
    /// The keys, all in the `[ex-ostrya]` group unless stated:
    ///
    /// - `receive-allow-non-fast-forward`, `receive-allow-delete`,
    ///   `receive-allow-privileged`, `receive-allow-remote-refs`, and
    ///   `receive-sign-summary`: booleans, default false.
    /// - `receive-verify`: `off` (the default), or a `;`-separated list of
    ///   `gpg`, `ed25519`, and `spki`. A name given twice counts once.
    /// - `receive-gpgkeypath`: the keyrings the GPG axis trusts, a
    ///   `;`-separated list of keyring files and directories of `*.gpg`
    ///   keyrings.
    /// - `receive-verification-<engine>-key` and
    ///   `receive-verification-<engine>-file`: the keys the sign-api axis
    ///   trusts for one engine, in the forms of the remote keys
    ///   `verification-<engine>-key` and `verification-<engine>-file`.
    /// - `receive-sign-type` and `receive-sign-key-file`: one sign-api key the
    ///   server signs with. The type is `ed25519` (the default when only the
    ///   file is set) or `spki`. The file holds one base64 secret key.
    /// - `receive-gpg-sign` and `receive-gpg-homedir`: the `;`-separated GPG
    ///   key selectors the server signs with, and the GnuPG home they are
    ///   resolved in. Each selector has to name exactly one secret key.
    /// - `detached-metadata-exclude`: the detached-metadata keys the
    ///   repository does not store.
    /// - `[core] auto-update-summary` and its alias `commit-update-summary`:
    ///   whether the summary is regenerated (see
    ///   [`RepoConfig::auto_update_summary`]).
    ///
    /// The sign-api signing key comes before the GPG keys in
    /// [`signers`](ReceivePolicy::signers).
    ///
    /// The trusted keys are read here once, so a key source the policy cannot
    /// use is refused here and not at the first session. The errors:
    ///
    /// - A malformed value is [`Error::InvalidFormat`].
    /// - A malformed boolean is the key-file error [`Error::Core`].
    /// - A key, a line of a key file, or a secret key that is not valid base64
    ///   is the base64 error [`Error::Core`], as it is for the keys of a
    ///   remote in a pull.
    /// - An engine this build does not have is [`Error::Unsupported`].
    /// - These are [`Error::Signature`]: a key source that cannot be read, a
    ///   key the engine refuses, an engine with no trusted key, a
    ///   `receive-gpgkeypath` that names no keyring, keyrings that hold no
    ///   certificate, and a GPG selector that names no secret key or more than
    ///   one.
    pub async fn from_config(repo: &Repo) -> Result<ReceivePolicy> {
        let config = repo.config();
        let require_signature = parse_receive_verify(config)?;
        crate::verify::receive_policy(repo, &require_signature).await?;

        let mut signers = Vec::new();
        if let Some(signer) = sign_api_signer(config).await? {
            signers.push(signer);
        }
        signers.extend(gpg_signers(config).await?);

        let exclude = config.detached_metadata_exclude()?;
        let detached_metadata_filter =
            (!exclude.is_empty()).then(|| DetachedMetadataFilter::excluding(exclude));

        Ok(ReceivePolicy {
            allow_non_fast_forward: config.ex_ostrya_bool("receive-allow-non-fast-forward")?,
            allow_delete: config.ex_ostrya_bool("receive-allow-delete")?,
            allow_privileged: config.ex_ostrya_bool("receive-allow-privileged")?,
            allow_remote_refs: config.ex_ostrya_bool("receive-allow-remote-refs")?,
            require_signature,
            signers,
            sign_summary: config.ex_ostrya_bool("receive-sign-summary")?,
            update_summary: config.auto_update_summary()?,
            detached_metadata_filter,
        })
    }
}

/// Read `[ex-ostrya] receive-verify`.
///
/// The value is absent or `off` for no check, or a list the key-file syntax
/// splits on `;`, whose trailing separator adds no element. Each element is
/// `gpg`, `ed25519`, or `spki`, taken as written. An empty value, an empty
/// element, `off` beside a name, and any other name are refused, `true` and
/// `false` among them, so a value that reads as a boolean elsewhere does not
/// turn a check on or off here. The dummy engine is refused by name: its
/// signature is its key.
fn parse_receive_verify(config: &RepoConfig) -> Result<ReceiveVerify> {
    const KEY: &str = "receive-verify";
    let Some(raw) = config.ex_ostrya_string(KEY)? else {
        return Ok(ReceiveVerify::default());
    };
    if raw == "off" {
        return Ok(ReceiveVerify::default());
    }
    let malformed = |why: &str| {
        Error::InvalidFormat(format!("malformed [ex-ostrya] {KEY} value '{raw}': {why}"))
    };
    let names = config.ex_ostrya_list(KEY)?;
    if names.is_empty() {
        return Err(malformed("the value names nothing; write off for no check"));
    }
    let mut verify = ReceiveVerify::default();
    for name in &names {
        match name.as_str() {
            "" => return Err(malformed("an element is empty")),
            "off" => return Err(malformed("off stands alone")),
            "gpg" => {
                if cfg!(not(feature = "verify-gpg")) {
                    return Err(Error::Unsupported(format!(
                        "[ex-ostrya] {KEY} names gpg, which this build has no engine \
                         for; build with the verify-gpg feature"
                    )));
                }
                verify.gpg = true;
            }
            "ed25519" | "spki" => {
                if name == "spki" && cfg!(not(feature = "sign-spki")) {
                    return Err(Error::Unsupported(format!(
                        "[ex-ostrya] {KEY} names spki, which this build has no engine \
                         for; build with the sign-spki feature"
                    )));
                }
                if !verify.sign.contains(name) {
                    verify.sign.push(name.clone());
                }
            }
            "dummy" => {
                return Err(malformed(
                    "the dummy engine is not a check: its signature is its key",
                ));
            }
            other => {
                return Err(malformed(&format!(
                    "'{other}' is not gpg, ed25519, or spki"
                )));
            }
        }
    }
    Ok(verify)
}

/// The sign-api signing key of `[ex-ostrya] receive-sign-type` and
/// `receive-sign-key-file`, `None` where neither is set.
async fn sign_api_signer(config: &RepoConfig) -> Result<Option<ServerSigner>> {
    let kind = config.ex_ostrya_string("receive-sign-type")?;
    let Some(path) = config.ex_ostrya_string("receive-sign-key-file")? else {
        return match kind {
            None => Ok(None),
            Some(kind) => Err(Error::InvalidFormat(format!(
                "[ex-ostrya] receive-sign-type is '{kind}', but receive-sign-key-file \
                 names no key file"
            ))),
        };
    };
    let kind = kind.unwrap_or_else(|| "ed25519".to_owned());
    match kind.as_str() {
        "ed25519" => {}
        #[cfg(feature = "sign-spki")]
        "spki" => {}
        #[cfg(not(feature = "sign-spki"))]
        "spki" => {
            return Err(Error::Unsupported(
                "[ex-ostrya] receive-sign-type is spki, which this build has no \
                 engine for; build with the sign-spki feature"
                    .into(),
            ));
        }
        "gpg" => {
            return Err(Error::InvalidFormat(
                "malformed [ex-ostrya] receive-sign-type value 'gpg': name GPG \
                 keys with receive-gpg-sign"
                    .into(),
            ));
        }
        other => {
            return Err(Error::InvalidFormat(format!(
                "malformed [ex-ostrya] receive-sign-type value '{other}': the type is \
                 ed25519 or spki"
            )));
        }
    }
    let line = ostrya_rt::unblock(move || read_secret_key_line(&path)).await?;
    let signer = match kind.as_str() {
        #[cfg(feature = "sign-spki")]
        "spki" => ServerSigner::spki(crate::spki::SpkiSigner::from_base64(&line)?)?,
        _ => ServerSigner::ed25519(&ostrya_core::base64::decode(&line)?)?,
    };
    Ok(Some(signer))
}

/// The one secret key the file at `path` holds, as its base64 line.
///
/// The file is read under the rule every key source is read under: a regular
/// file alone, up to [`MAX_KEY_FILE`]. Blank lines are skipped, and the file
/// has to hold exactly one other line.
fn read_secret_key_line(path: &str) -> Result<String> {
    let subject = format!("the receive signing key file '{path}'");
    let Some(bytes) = read_key_path(Path::new(path), &subject, MAX_KEY_FILE)? else {
        return Err(Error::Signature(format!("{subject} does not exist")));
    };
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

/// The GPG signing keys of `[ex-ostrya] receive-gpg-sign`, resolved in
/// `receive-gpg-homedir` where it is set.
#[cfg(feature = "sign-gpg")]
async fn gpg_signers(config: &RepoConfig) -> Result<Vec<ServerSigner>> {
    let homedir = config.ex_ostrya_string("receive-gpg-homedir")?;
    let mut signers = Vec::new();
    for selector in config.ex_ostrya_list("receive-gpg-sign")? {
        if selector.is_empty() {
            continue;
        }
        let mut signer = crate::gpg::GpgSigner::new(selector.as_str());
        if let Some(dir) = &homedir {
            signer = signer.with_homedir(dir);
        }
        let signer = ServerSigner::gpg(signer).await.map_err(|e| match e {
            Error::Signature(message) => Error::Signature(format!(
                "[ex-ostrya] receive-gpg-sign entry '{selector}': {message}"
            )),
            other => other,
        })?;
        signers.push(signer);
    }
    Ok(signers)
}

/// A build without GPG signing refuses a configuration that names a GPG key,
/// rather than accept a session it would not sign.
#[cfg(not(feature = "sign-gpg"))]
async fn gpg_signers(config: &RepoConfig) -> Result<Vec<ServerSigner>> {
    let selectors = config.ex_ostrya_list("receive-gpg-sign")?;
    if selectors.iter().any(|selector| !selector.is_empty()) {
        return Err(Error::Unsupported(
            "[ex-ostrya] receive-gpg-sign names a GPG key, which this build cannot \
             sign with; build with the sign-gpg feature"
                .into(),
        ));
    }
    Ok(Vec::new())
}
