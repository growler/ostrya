//! The reader of the receive groups: `[ex-ostrya receive]`,
//! `[ex-ostrya receive "PATTERN"]`, `[ex-ostrya trust "NAME"]`, and
//! `[ex-ostrya key "NAME"]`.
//!
//! The reader makes two passes. The first pass reads each group and refuses
//! each key and each value outside the syntax. It also resolves each reference
//! to a trust group, a key group, or a remote section. This pass reads no file
//! and runs no program.
//!
//! The second pass builds each key group and each trust group once, in file
//! order. It also builds a group that no rule names. Then it builds the pull
//! trust of each remote that a rule names. The rules get shared handles to
//! these objects.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use ostrya_core::KeyFile;
use rustix::fs::{Mode, OFlags};

use crate::config::{Remote, SignVerify, remote_group_name};
use crate::error::{Error, Result};
use crate::pull::DetachedMetadataFilter;
use crate::refs::is_component;
use crate::repo::Repo;
use crate::sign::{MAX_KEY_FILE, key_text, read_key_path, read_key_source};

use super::{ReceivePolicy, ReceiveRule, ReceiveVerify, RefPattern, ServerSigner, TrustedKeys};

/// The name of the default rule group.
const DEFAULT_GROUP: &str = "ex-ostrya receive";
/// The name prefix of a pattern rule group, before the quoted pattern.
const RULE_PREFIX: &str = "ex-ostrya receive \"";
/// The name prefix of a trust group, before the quoted name.
const TRUST_PREFIX: &str = "ex-ostrya trust \"";
/// The name prefix of a key group, before the quoted name.
const KEY_PREFIX: &str = "ex-ostrya key \"";
/// The name prefix of every receive group.
///
/// If a group name has this prefix and no shape of a receive group, the
/// reader refuses the group.
const RESERVED_PREFIX: &str = "ex-ostrya ";

/// The keys of a rule, valid in each receive group.
const RULE_KEYS: &[&str] = &[
    "accept",
    "verify",
    "allow-non-fast-forward",
    "allow-delete",
    "sign",
];
/// The keys of a rule that have no effect if the rule refuses its refs.
const ACCEPT_ONLY_KEYS: &[&str] = &["verify", "sign", "allow-non-fast-forward", "allow-delete"];
/// The keys that cover the whole session, valid in `[ex-ostrya receive]`
/// alone.
const SESSION_KEYS: &[&str] = &["allow-privileged", "sign-summary"];
/// The sign-api engines that a trust group can name.
const TRUST_ENGINES: &[&str] = &["ed25519", "spki"];

/// The source of the receive groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// The repository config. The groups other than the receive groups
    /// belong to the repository, so the reader skips them.
    Config,
    /// A policy file. It holds the receive groups and remote sections, and
    /// no other group. A remote section in a policy file reads no keyring
    /// inside the repository.
    File,
}

/// One receive group, by the shape of its name.
enum Group<'a> {
    /// `[ex-ostrya receive]`.
    Default,
    /// `[ex-ostrya receive "PATTERN"]`, with the pattern text.
    Rule(&'a str),
    /// `[ex-ostrya trust "NAME"]`, with the name.
    Trust(&'a str),
    /// `[ex-ostrya key "NAME"]`, with the name.
    Key(&'a str),
}

/// The source of the trusted keys of one rule, as the rule names it.
enum VerifySpec {
    Off,
    Trust(String),
    Remote(String),
}

/// One rule as the first pass reads it, before the second pass builds the key
/// sources.
struct RuleSpec {
    accept: bool,
    verify: VerifySpec,
    allow_non_fast_forward: bool,
    allow_delete: bool,
    sign: Vec<String>,
}

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

/// Returns the receive policy that the receive groups of `keyfile` state.
///
/// For both origins, `update_summary` and the detached-metadata filter come
/// from the repository config.
pub(crate) async fn read(repo: &Repo, keyfile: &KeyFile, origin: Origin) -> Result<ReceivePolicy> {
    // The first pass reads each group by its shape, in file order.
    let mut default = None;
    let mut rule_groups: Vec<(RefPattern, &str)> = Vec::new();
    let mut trust_groups: Vec<(&str, &str)> = Vec::new();
    let mut key_groups: Vec<(&str, &str)> = Vec::new();
    // Trust and key groups with their names, in file order, for the second
    // pass.
    let mut builds: Vec<(Group<'_>, &str)> = Vec::new();
    for group in keyfile.groups() {
        match classify(group)? {
            Some(Group::Default) => default = Some(group),
            Some(Group::Rule(pattern)) => rule_groups.push((RefPattern::parse(pattern)?, group)),
            Some(Group::Trust(name)) => {
                trust_groups.push((name, group));
                builds.push((Group::Trust(name), group));
            }
            Some(Group::Key(name)) => {
                key_groups.push((name, group));
                builds.push((Group::Key(name), group));
            }
            None if origin == Origin::File && remote_group_name(group).is_none() => {
                return Err(Error::InvalidFormat(format!(
                    "the receive policy file holds [{group}], which is not a receive, \
                     trust, key, or remote group"
                )));
            }
            None => {}
        }
    }

    let mut keys: HashMap<&str, KeySpec> = HashMap::new();
    for &(name, group) in &key_groups {
        keys.insert(name, parse_key(keyfile, group)?);
    }
    for &(_, group) in &trust_groups {
        check_trust(keyfile, group)?;
    }
    let names = Names {
        keyfile,
        trusts: trust_groups.iter().map(|(name, _)| *name).collect(),
        keys: key_groups.iter().map(|(name, _)| *name).collect(),
    };
    let default_spec = match default {
        Some(group) => parse_rule(&names, group, true)?,
        None => RuleSpec::default(),
    };
    let mut rule_specs = Vec::with_capacity(rule_groups.len());
    for (pattern, group) in rule_groups {
        rule_specs.push((pattern, parse_rule(&names, group, false)?));
    }
    let (allow_privileged, sign_summary) = match default {
        Some(group) => (
            keyfile
                .get_bool(group, "allow-privileged")?
                .unwrap_or(false),
            key_list(&names, group, "sign-summary")?,
        ),
        None => (false, Vec::new()),
    };

    // The second pass builds each key group and each trust group once, in
    // file order. Then it builds the trust of each remote that a rule names.
    let mut signers: HashMap<&str, Arc<ServerSigner>> = HashMap::new();
    let mut trusts: HashMap<&str, Arc<TrustedKeys>> = HashMap::new();
    for (build, group) in builds {
        match build {
            Group::Key(name) => {
                let signer = build_signer(name, &keys[name]).await?;
                signers.insert(name, Arc::new(signer));
            }
            Group::Trust(name) => {
                let keys = TrustedKeys::for_trust_group(repo, keyfile, name, group).await?;
                trusts.insert(name, Arc::new(keys));
            }
            Group::Default | Group::Rule(_) => {}
        }
    }
    let mut remotes: HashMap<&str, Arc<TrustedKeys>> = HashMap::new();
    for spec in std::iter::once(&default_spec).chain(rule_specs.iter().map(|(_, spec)| spec)) {
        if let VerifySpec::Remote(name) = &spec.verify
            && !remotes.contains_key(name.as_str())
        {
            let keys =
                TrustedKeys::for_remote_in(repo, keyfile, name, origin == Origin::Config).await?;
            remotes.insert(name.as_str(), Arc::new(keys));
        }
    }

    let rule = |spec: &RuleSpec| ReceiveRule {
        accept: spec.accept,
        verify: match &spec.verify {
            VerifySpec::Off => ReceiveVerify::Off,
            VerifySpec::Trust(name) => ReceiveVerify::Keys(Arc::clone(&trusts[name.as_str()])),
            VerifySpec::Remote(name) => ReceiveVerify::Keys(Arc::clone(&remotes[name.as_str()])),
        },
        allow_non_fast_forward: spec.allow_non_fast_forward,
        allow_delete: spec.allow_delete,
        signers: spec
            .sign
            .iter()
            .map(|name| Arc::clone(&signers[name.as_str()]))
            .collect(),
    };
    let default_rule = rule(&default_spec);
    let rules = rule_specs
        .iter()
        .map(|(pattern, spec)| (pattern.clone(), rule(spec)))
        .collect();
    let summary_signers = sign_summary
        .iter()
        .map(|name| Arc::clone(&signers[name.as_str()]))
        .collect();

    let config = repo.config();
    let exclude = config.detached_metadata_exclude()?;
    let detached_metadata_filter =
        (!exclude.is_empty()).then(|| DetachedMetadataFilter::excluding(exclude));
    Ok(ReceivePolicy {
        default_rule,
        rules,
        allow_privileged,
        summary_signers,
        update_summary: config.auto_update_summary()?,
        detached_metadata_filter,
    })
}

/// Reads the policy file at `path` and parses it as a key file.
///
/// The file must be a regular file of at most [`MAX_KEY_FILE`] bytes, in
/// UTF-8. The read and the parse run on the blocking pool.
///
/// The function returns [`Error::InvalidFormat`], with the path in the
/// message, if the file:
///
/// - cannot be opened or read,
/// - is not a regular file,
/// - is larger than [`MAX_KEY_FILE`] bytes,
/// - is not valid UTF-8.
///
/// If the text is not a valid key file, the function returns the key-file
/// error [`Error::Core`].
pub(crate) async fn read_policy_file(path: &Path) -> Result<KeyFile> {
    let path = path.to_owned();
    ostrya_rt::unblock(move || {
        let subject = format!("the receive policy file '{}'", path.display());
        let refused = |e: Error| match e {
            Error::Signature(message) => Error::InvalidFormat(message),
            other => other,
        };
        // With `NONBLOCK`, the open of a fifo returns at once. Without the
        // flag, the open waits for a writer. On a regular file, the flag has
        // no effect on the read.
        let fd = rustix::fs::open(
            &path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| Error::InvalidFormat(format!("{subject} cannot be opened: {e}")))?;
        let bytes = read_key_source(std::fs::File::from(fd), &subject, MAX_KEY_FILE)
            .map_err(|e| refused(e.into()))?;
        let text = key_text(bytes, &subject).map_err(|e| refused(e.into()))?;
        Ok(KeyFile::parse(&text)?)
    })
    .await
}

/// Returns the receive group that `group` names, or `None` for a group
/// outside the receive groups.
///
/// If the name starts with `ex-ostrya ` and has no shape of a receive group,
/// the function returns [`Error::InvalidFormat`].
fn classify(group: &str) -> Result<Option<Group<'_>>> {
    if group == DEFAULT_GROUP {
        return Ok(Some(Group::Default));
    }
    if let Some(rest) = group.strip_prefix(RULE_PREFIX) {
        return quoted(group, rest).map(|pattern| Some(Group::Rule(pattern)));
    }
    if let Some(rest) = group.strip_prefix(TRUST_PREFIX) {
        return quoted(group, rest).map(|name| Some(Group::Trust(name)));
    }
    if let Some(rest) = group.strip_prefix(KEY_PREFIX) {
        return quoted(group, rest).map(|name| Some(Group::Key(name)));
    }
    if group.starts_with(RESERVED_PREFIX) {
        return Err(Error::InvalidFormat(format!(
            "[{group}] is not a receive, trust, or key group"
        )));
    }
    Ok(None)
}

/// Returns the quoted part of a group name.
///
/// `rest` is the text after the opening `"`. If the part does not end the
/// name, is empty, or holds a `"` or a control character, the function
/// returns [`Error::InvalidFormat`].
fn quoted<'a>(group: &str, rest: &'a str) -> Result<&'a str> {
    match rest.strip_suffix('"') {
        Some(name)
            if !name.is_empty() && !name.contains('"') && !name.contains(char::is_control) =>
        {
            Ok(name)
        }
        _ => Err(Error::InvalidFormat(format!(
            "malformed group name [{group}]: the quoted name ends the group name, is \
             not empty, and holds no '\"' and no control character"
        ))),
    }
}

/// The groups that a rule can name, for the checks of its references.
struct Names<'a> {
    keyfile: &'a KeyFile,
    trusts: HashSet<&'a str>,
    keys: HashSet<&'a str>,
}

impl Default for RuleSpec {
    fn default() -> RuleSpec {
        RuleSpec {
            accept: true,
            verify: VerifySpec::Off,
            allow_non_fast_forward: false,
            allow_delete: false,
            sign: Vec::new(),
        }
    }
}

/// Reads the rule keys of the receive group `group`.
///
/// `session` is `true` for `[ex-ostrya receive]`, which also holds the
/// session keys.
fn parse_rule(names: &Names<'_>, group: &str, session: bool) -> Result<RuleSpec> {
    let keyfile = names.keyfile;
    for key in keyfile.keys(group) {
        if RULE_KEYS.contains(&key) || (session && SESSION_KEYS.contains(&key)) {
            continue;
        }
        if SESSION_KEYS.contains(&key) {
            return Err(Error::InvalidFormat(format!(
                "[{group}] holds '{key}', which covers the whole session and is valid \
                 in [{DEFAULT_GROUP}] alone"
            )));
        }
        return Err(unknown_key(group, key));
    }
    let accept = keyfile.get_bool(group, "accept")?.unwrap_or(true);
    if !accept {
        let dead: Vec<&str> = ACCEPT_ONLY_KEYS
            .iter()
            .copied()
            .filter(|key| keyfile.get_value(group, key).is_some())
            .collect();
        if !dead.is_empty() {
            return Err(Error::InvalidFormat(format!(
                "[{group}] sets accept=false, so {} has no effect; remove it",
                dead.join(", ")
            )));
        }
    }
    Ok(RuleSpec {
        accept,
        verify: parse_verify(names, group)?,
        allow_non_fast_forward: keyfile
            .get_bool(group, "allow-non-fast-forward")?
            .unwrap_or(false),
        allow_delete: keyfile.get_bool(group, "allow-delete")?.unwrap_or(false),
        sign: key_list(names, group, "sign")?,
    })
}

/// Reads the `verify` key of `group`.
///
/// The value is `off` (the default), `trust:NAME` for a trust group, or
/// `remote:NAME` for a remote section of the same file.
fn parse_verify(names: &Names<'_>, group: &str) -> Result<VerifySpec> {
    let Some(raw) = names.keyfile.get_string(group, "verify")? else {
        return Ok(VerifySpec::Off);
    };
    if raw == "off" {
        return Ok(VerifySpec::Off);
    }
    if let Some(name) = raw.strip_prefix("trust:").filter(|name| !name.is_empty()) {
        if !names.trusts.contains(&name) {
            return Err(Error::InvalidFormat(format!(
                "[{group}] verify={raw} names no [{TRUST_PREFIX}{name}\"] group"
            )));
        }
        return Ok(VerifySpec::Trust(name.to_owned()));
    }
    if let Some(name) = raw.strip_prefix("remote:").filter(|name| !name.is_empty()) {
        // The name is part of the path of the keyrings of the remote, so it
        // must be one path component.
        if !is_component(name) || name.contains(char::is_control) {
            return Err(Error::InvalidFormat(format!(
                "malformed [{group}] verify value '{raw}': the remote name is one path \
                 component, not '.' or '..', with no '/' and no control character"
            )));
        }
        if Remote::in_keyfile(names.keyfile, name).is_none() {
            return Err(Error::InvalidFormat(format!(
                "[{group}] verify={raw} names no [remote \"{name}\"] group"
            )));
        }
        return Ok(VerifySpec::Remote(name.to_owned()));
    }
    Err(Error::InvalidFormat(format!(
        "malformed [{group}] verify value '{raw}': the value is off, trust:NAME, or \
         remote:NAME"
    )))
}

/// Reads the list of key group names in the key `key` of `group`.
///
/// `key` is `sign` or `sign-summary`. Each entry must name a key group. An
/// entry that occurs twice counts once.
fn key_list(names: &Names<'_>, group: &str, key: &str) -> Result<Vec<String>> {
    let mut kept: Vec<String> = Vec::new();
    for name in names
        .keyfile
        .get_string_list(group, key)?
        .unwrap_or_default()
    {
        if !names.keys.contains(&name.as_str()) {
            return Err(Error::InvalidFormat(format!(
                "[{group}] {key} names the key group '{name}', and no \
                 [{KEY_PREFIX}{name}\"] group exists"
            )));
        }
        if !kept.contains(&name) {
            kept.push(name);
        }
    }
    Ok(kept)
}

/// Checks the trust group `group`.
///
/// Each key must be one that an axis reads. The group must turn on at least
/// one axis.
fn check_trust(keyfile: &KeyFile, group: &str) -> Result<()> {
    let mut engine_keys: Vec<(&str, &str)> = Vec::new();
    for key in keyfile.keys(group) {
        match key {
            "gpg-verify" | "gpgkeypath" | "sign-verify" => {}
            "gpg-verify-summary" | "sign-verify-summary" => {
                return Err(Error::InvalidFormat(format!(
                    "[{group}] holds '{key}', and a push carries no summary"
                )));
            }
            _ => match verification_engine(key) {
                Some(engine) if TRUST_ENGINES.contains(&engine) => {
                    engine_keys.push((key, engine));
                }
                Some(engine) => {
                    return Err(Error::InvalidFormat(format!(
                        "[{group}] holds '{key}', and '{engine}' is not ed25519 or spki"
                    )));
                }
                None => return Err(unknown_key(group, key)),
            },
        }
    }

    let gpg = keyfile.get_bool(group, "gpg-verify")?.unwrap_or(false);
    let sign = Remote::view(keyfile, group.to_owned()).sign_verify()?;
    let engines: Vec<&str> = match &sign {
        SignVerify::Off => Vec::new(),
        SignVerify::All => TRUST_ENGINES.to_vec(),
        SignVerify::Engines(names) => names.iter().map(String::as_str).collect(),
    };
    for engine in &engines {
        if !TRUST_ENGINES.contains(engine) {
            return Err(Error::InvalidFormat(format!(
                "[{group}] sign-verify names '{engine}', which is not ed25519 or spki"
            )));
        }
    }
    if !gpg && engines.is_empty() {
        return Err(Error::InvalidFormat(format!(
            "[{group}] turns on no signature check: set gpg-verify=true or sign-verify"
        )));
    }

    let keypath = keyfile.get_value(group, "gpgkeypath").is_some();
    if keypath && !gpg {
        return Err(Error::InvalidFormat(format!(
            "[{group}] sets gpgkeypath, and gpg-verify is not true, so no check reads it"
        )));
    }
    // `sign-verify=true` names every engine of the build, so it names spki
    // only in a build that has it.
    let names_spki = matches!(&sign, SignVerify::Engines(names) if names.iter().any(|n| n == "spki"))
        || engine_keys.iter().any(|(_, engine)| *engine == "spki");
    if cfg!(not(feature = "sign-spki")) && names_spki {
        return Err(Error::Unsupported(format!(
            "[{group}] names the spki engine, which this build has no engine for; \
             build with the sign-spki feature"
        )));
    }
    for (key, engine) in engine_keys {
        if !engines.contains(&engine) {
            return Err(Error::InvalidFormat(format!(
                "[{group}] holds '{key}', and sign-verify does not select {engine}, so \
                 no check reads it"
            )));
        }
    }
    if gpg {
        if cfg!(not(feature = "verify-gpg")) {
            return Err(Error::Unsupported(format!(
                "[{group}] asks for GPG verification, which this build has no engine \
                 for; build with the verify-gpg feature"
            )));
        }
        if Remote::view(keyfile, group.to_owned())
            .gpgkeypath()?
            .is_empty()
        {
            return Err(Error::InvalidFormat(format!(
                "[{group}] sets gpg-verify=true, and gpgkeypath names no keyring"
            )));
        }
    }
    Ok(())
}

/// Returns the engine that a `verification-ENGINE-key` or
/// `verification-ENGINE-file` key names, or `None` for another key.
fn verification_engine(key: &str) -> Option<&str> {
    let rest = key.strip_prefix("verification-")?;
    rest.strip_suffix("-key")
        .or_else(|| rest.strip_suffix("-file"))
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
    let Some(kind) = keyfile.get_string(group, "type")? else {
        return Err(Error::InvalidFormat(format!(
            "[{group}] needs type: ed25519, spki, or gpg"
        )));
    };
    match kind.as_str() {
        "ed25519" => {
            foreign(&kind, &["gpg-key", "gpg-homedir"])?;
            Ok(KeySpec::Ed25519 {
                file: required("secret-key-file")?,
            })
        }
        "spki" => {
            foreign(&kind, &["gpg-key", "gpg-homedir"])?;
            spki_key(group, required("secret-key-file")?)
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

/// Builds the signer of the key group `name`.
async fn build_signer(name: &str, spec: &KeySpec) -> Result<ServerSigner> {
    let label = format!("[{KEY_PREFIX}{name}\"]");
    let in_group = |e: Error| match e {
        Error::Signature(message) => Error::Signature(format!("{label}: {message}")),
        other => other,
    };
    match spec {
        KeySpec::Ed25519 { file } => {
            let line = secret_key_line(file).await.map_err(in_group)?;
            ServerSigner::ed25519(&ostrya_core::base64::decode(&line)?).map_err(in_group)
        }
        #[cfg(feature = "sign-spki")]
        KeySpec::Spki { file } => {
            let line = secret_key_line(file).await.map_err(in_group)?;
            ServerSigner::spki(crate::spki::SpkiSigner::from_base64(&line)?).map_err(in_group)
        }
        #[cfg(feature = "sign-gpg")]
        KeySpec::Gpg { key, homedir } => {
            let mut signer = crate::gpg::GpgSigner::new(key.as_str());
            if let Some(dir) = homedir {
                signer = signer.with_homedir(dir);
            }
            ServerSigner::gpg(signer).await.map_err(in_group)
        }
    }
}

/// Returns the one secret key that the file at `path` holds, as its base64
/// line.
///
/// The read runs on the blocking pool.
async fn secret_key_line(path: &str) -> Result<String> {
    let path = path.to_owned();
    ostrya_rt::unblock(move || read_secret_key_line(&path)).await
}

/// Reads the one secret key line of the file at `path`, the blocking half of
/// `secret_key_line`.
///
/// The read obeys the rule of every key source: a regular file alone, of at
/// most [`MAX_KEY_FILE`] bytes. The function skips blank lines. The file must
/// hold exactly one other line.
fn read_secret_key_line(path: &str) -> Result<String> {
    let subject = format!("the secret key file '{path}'");
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

/// Returns the error for a key that `group` does not take.
fn unknown_key(group: &str, key: &str) -> Error {
    Error::InvalidFormat(format!("[{group}] holds the unknown key '{key}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `classify` tells the four shapes apart, and the groups outside the
    /// receive groups pass through.
    #[test]
    fn the_group_shapes_are_told_apart() {
        assert!(matches!(
            classify("ex-ostrya receive").unwrap(),
            Some(Group::Default)
        ));
        assert!(matches!(
            classify("ex-ostrya receive \"a/*\"").unwrap(),
            Some(Group::Rule("a/*"))
        ));
        assert!(matches!(
            classify("ex-ostrya trust \"t\"").unwrap(),
            Some(Group::Trust("t"))
        ));
        assert!(matches!(
            classify("ex-ostrya key \"k 1\"").unwrap(),
            Some(Group::Key("k 1"))
        ));
        for group in ["ex-ostrya", "ex-ostryax", "core", "remote \"origin\""] {
            assert!(classify(group).unwrap().is_none(), "{group}");
        }
    }

    /// `classify` refuses each name that starts with `ex-ostrya ` and has no
    /// shape of a receive group.
    #[test]
    fn the_other_reserved_names_are_refused() {
        for group in [
            "ex-ostrya receive p",
            "ex-ostrya receive \"\"",
            "ex-ostrya receive \"a\"b\"",
            "ex-ostrya receive \"p\" ",
            "ex-ostrya receive  \"p\"",
            "ex-ostrya receive \"p",
            "ex-ostrya receivex",
            "ex-ostrya bogus",
            "ex-ostrya trust",
            "ex-ostrya trust \"\"",
            "ex-ostrya trust \"a\tb\"",
            "ex-ostrya key",
            "ex-ostrya key \"a\"\"",
            "ex-ostrya ",
        ] {
            let Err(err) = classify(group) else {
                panic!("{group:?} was accepted");
            };
            assert!(matches!(err, Error::InvalidFormat(_)), "{group:?}: {err}");
        }
    }

    /// `verification_engine` returns the engine that a verification key
    /// names.
    #[test]
    fn verification_keys_name_their_engine() {
        assert_eq!(
            verification_engine("verification-ed25519-key"),
            Some("ed25519")
        );
        assert_eq!(verification_engine("verification-spki-file"), Some("spki"));
        assert_eq!(verification_engine("verification-x-y"), None);
        assert_eq!(verification_engine("gpgkeypath"), None);
    }
}
