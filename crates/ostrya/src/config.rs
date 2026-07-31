//! Typed view of the repository `config` file.
//!
//! [`RepoConfig`] wraps the [`KeyFile`] parsed from `<repo>/config` and applies
//! the value-level conventions the `ostree` tool uses: the `[core]` group with
//! `repo_version` and `mode`, the documented `[core]` tunables with their
//! defaults, the `[archive]` group, and `[remote "<name>"]` sections.
//!
//! The `repo_version` and `mode` keys are validated when the config is loaded,
//! matching the tool, which refuses to open a repository whose version is not
//! `1`. The remaining tunables are read on demand through accessors that apply
//! the documented default when the key is absent and surface a malformed value
//! as an error, the same way the tool reports a value it cannot interpret.
//!
//! The parsed [`KeyFile`] is retained so a caller can read keys this view does
//! not model and so the document reserializes in the order it was written.

use ostrya_core::{KeyFile, RepoMode};

use crate::error::{Error, Result};

const CORE: &str = "core";
const ARCHIVE: &str = "archive";
const EX_INTEGRITY: &str = "ex-integrity";

/// A parsed repository configuration.
#[derive(Debug, Clone)]
pub struct RepoConfig {
    keyfile: KeyFile,
    mode: RepoMode,
    repo_version: i64,
    collection_id: Option<String>,
    remotes: Vec<String>,
}

/// The minimum free space a write must leave, as configured. A size, when set,
/// takes precedence over a percentage.
///
/// The byte value of a [`Size`](MinFreeSpace::Size) spec is applied by the
/// write path; this type carries the parsed magnitude and unit verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinFreeSpace {
    /// `min-free-space-percent`, `0`-`100`. The default is `3`.
    Percent(u32),
    /// `min-free-space-size`, a magnitude with a binary unit suffix.
    Size(SizeSpec),
}

/// A `min-free-space-size` value: a magnitude and one of the `MB`, `GB`, `TB`
/// unit suffixes the tool accepts (regex `^([0-9]+)(G|M|T)B$`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeSpec {
    /// The numeric magnitude.
    pub value: u64,
    /// The unit suffix.
    pub unit: SizeUnit,
}

/// The unit suffix on a `min-free-space-size` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeUnit {
    /// `MB`.
    Mega,
    /// `GB`.
    Giga,
    /// `TB`.
    Tera,
}

impl SizeUnit {
    /// The byte multiplier for this unit. The `MB`/`GB`/`TB` suffixes denote
    /// binary multiples (2^20, 2^30, 2^40).
    pub fn multiplier(self) -> u64 {
        match self {
            SizeUnit::Mega => 1 << 20,
            SizeUnit::Giga => 1 << 30,
            SizeUnit::Tera => 1 << 40,
        }
    }
}

impl SizeSpec {
    /// The value in bytes, saturating on overflow.
    pub fn bytes(self) -> u64 {
        self.value.saturating_mul(self.unit.multiplier())
    }
}

/// A tri-state repository setting, spelled `no`, `maybe`, or `yes`.
///
/// The `[ex-integrity]` keys use this form: `No` disables the feature, `Maybe`
/// enables it best-effort (ignoring a filesystem that cannot provide it), and
/// `Yes` requires it (failing where it cannot be provided).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tristate {
    /// The feature is disabled.
    No,
    /// Best effort: enable where supported, ignore where not.
    Maybe,
    /// Required: fail where the feature cannot be provided.
    Yes,
}

impl Tristate {
    /// Parse the `no`/`maybe`/`yes` spelling the tool writes.
    fn parse(raw: &str) -> Option<Tristate> {
        match raw {
            "no" => Some(Tristate::No),
            "maybe" => Some(Tristate::Maybe),
            "yes" => Some(Tristate::Yes),
            _ => None,
        }
    }
}

impl RepoConfig {
    /// Build a typed view over an already-parsed [`KeyFile`], validating the
    /// `[core]` `repo_version` and `mode` keys.
    pub fn from_keyfile(keyfile: KeyFile) -> Result<RepoConfig> {
        if !keyfile.has_group(CORE) {
            return Err(Error::InvalidFormat("config has no [core] group".into()));
        }

        let repo_version = keyfile
            .get_integer(CORE, "repo_version")?
            .ok_or_else(|| Error::InvalidFormat("config [core] has no repo_version".into()))?;
        if repo_version != 1 {
            return Err(Error::InvalidFormat(format!(
                "unsupported repository version {repo_version}"
            )));
        }

        let mode_str = keyfile
            .get_string(CORE, "mode")?
            .ok_or_else(|| Error::InvalidFormat("config [core] has no mode".into()))?;
        let mode = RepoMode::from_mode_str(&mode_str)
            .ok_or_else(|| Error::InvalidFormat(format!("unknown repository mode '{mode_str}'")))?;

        let collection_id = keyfile.get_string(CORE, "collection-id")?;

        // A repeated group header merges into one group during parsing, so
        // each remote name appears once already.
        let remotes: Vec<String> = keyfile
            .groups()
            .filter_map(remote_group_name)
            .map(str::to_owned)
            .collect();

        Ok(RepoConfig {
            keyfile,
            mode,
            repo_version,
            collection_id,
            remotes,
        })
    }

    /// Parse a config document from its text.
    pub fn parse(text: &str) -> Result<RepoConfig> {
        RepoConfig::from_keyfile(KeyFile::parse(text)?)
    }

    /// The repository storage mode.
    pub fn mode(&self) -> RepoMode {
        self.mode
    }

    /// The `[core] repo_version`. Always `1` for a config this type accepts.
    pub fn repo_version(&self) -> i64 {
        self.repo_version
    }

    /// The repository collection id, if `[core] collection-id` is set.
    pub fn collection_id(&self) -> Option<&str> {
        self.collection_id.as_deref()
    }

    /// The names of the configured remotes, in the order their sections appear.
    pub fn remotes(&self) -> impl Iterator<Item = &str> {
        self.remotes.iter().map(String::as_str)
    }

    /// A typed accessor for one remote, or `None` if no such section exists.
    pub fn remote(&self, name: &str) -> Option<Remote<'_>> {
        let group = remote_group(name);
        self.keyfile.has_group(&group).then_some(Remote {
            keyfile: &self.keyfile,
            group,
        })
    }

    /// Whether `fsync` durability is enabled. Default `true`.
    pub fn fsync(&self) -> Result<bool> {
        Ok(self.keyfile.get_bool(CORE, "fsync")?.unwrap_or(true))
    }

    /// Whether each object is fsynced individually. Default `false`.
    pub fn per_object_fsync(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(CORE, "per-object-fsync")?
            .unwrap_or(false))
    }

    /// Whether repository locking is enabled. Default `true`.
    pub fn locking(&self) -> Result<bool> {
        Ok(self.keyfile.get_bool(CORE, "locking")?.unwrap_or(true))
    }

    /// The lock-acquisition timeout in seconds. Default `300`.
    pub fn lock_timeout_secs(&self) -> Result<i64> {
        Ok(self
            .keyfile
            .get_integer(CORE, "lock-timeout-secs")?
            .unwrap_or(300))
    }

    /// The staging-directory expiry in seconds. Default `86400`.
    pub fn tmp_expiry_secs(&self) -> Result<i64> {
        Ok(self
            .keyfile
            .get_integer(CORE, "tmp-expiry-secs")?
            .unwrap_or(86400))
    }

    /// Whether the repository advertises tombstone commits in its summary.
    /// Default `false`. The summary emits `ostree.summary.tombstone-commits`
    /// with this value.
    pub fn tombstone_commits(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(CORE, "tombstone-commits")?
            .unwrap_or(false))
    }

    /// Whether the repository indexes its static deltas. Default `true`. The
    /// summary emits `ostree.summary.indexed-deltas` with this value.
    pub fn indexed_deltas(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(CORE, "indexed-deltas")?
            .unwrap_or(true))
    }

    /// Whether xattr storage is disabled. Default `false`.
    pub fn disable_xattrs(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(CORE, "disable-xattrs")?
            .unwrap_or(false))
    }

    /// The `[core] parent` repository path, if set.
    pub fn parent(&self) -> Result<Option<String>> {
        self.keyfile.get_string(CORE, "parent").map_err(Error::from)
    }

    /// The configured repo finders. Default `["config", "mount"]`.
    pub fn default_repo_finders(&self) -> Result<Vec<String>> {
        Ok(self
            .keyfile
            .get_string_list(CORE, "default-repo-finders")?
            .unwrap_or_else(|| vec!["config".to_owned(), "mount".to_owned()]))
    }

    /// The minimum free space a write must leave. A `min-free-space-size` value
    /// takes precedence; otherwise `min-free-space-percent` applies, defaulting
    /// to `3`.
    pub fn min_free_space(&self) -> Result<MinFreeSpace> {
        if let Some(raw) = self.keyfile.get_value(CORE, "min-free-space-size") {
            let spec = parse_size(raw).ok_or_else(|| {
                Error::InvalidFormat(format!("malformed min-free-space-size '{raw}'"))
            })?;
            return Ok(MinFreeSpace::Size(spec));
        }
        let percent = self
            .keyfile
            .get_integer(CORE, "min-free-space-percent")?
            .unwrap_or(3);
        if !(0..=100).contains(&percent) {
            return Err(Error::InvalidFormat(format!(
                "min-free-space-percent {percent} is out of the range 0-100"
            )));
        }
        Ok(MinFreeSpace::Percent(percent as u32))
    }

    /// The `[archive] zlib-level` compression level. Default `6`.
    pub fn zlib_level(&self) -> Result<i64> {
        Ok(self
            .keyfile
            .get_integer(ARCHIVE, "zlib-level")?
            .unwrap_or(6))
    }

    /// The `[ex-integrity] composefs` setting. Default `No`.
    ///
    /// This is read to compute the [`fsverity`](RepoConfig::fsverity) default.
    /// The composefs deployment behavior the key otherwise governs is out of
    /// scope for the write path.
    pub fn composefs(&self) -> Result<Tristate> {
        Ok(self
            .tristate(EX_INTEGRITY, "composefs")?
            .unwrap_or(Tristate::No))
    }

    /// The `[ex-integrity] fsverity` setting: whether loose objects are sealed
    /// with fs-verity as they are written.
    ///
    /// An explicit value is honored as written. When the key is absent it
    /// defaults to `No`, raised to `Maybe` when
    /// [`composefs`](RepoConfig::composefs) is `Yes` or `Maybe`; `composefs` is
    /// read only in that fallback.
    pub fn fsverity(&self) -> Result<Tristate> {
        if let Some(explicit) = self.tristate(EX_INTEGRITY, "fsverity")? {
            return Ok(explicit);
        }
        Ok(match self.composefs()? {
            Tristate::No => Tristate::No,
            Tristate::Maybe | Tristate::Yes => Tristate::Maybe,
        })
    }

    /// Read a tri-state key, returning `None` when it is absent and reporting a
    /// value that is not `no`/`maybe`/`yes` as a malformed config error.
    fn tristate(&self, group: &str, key: &str) -> Result<Option<Tristate>> {
        match self.keyfile.get_string(group, key)? {
            None => Ok(None),
            Some(raw) => Tristate::parse(&raw).map(Some).ok_or_else(|| {
                Error::InvalidFormat(format!("malformed [{group}] {key} value '{raw}'"))
            }),
        }
    }

    /// The parsed key file backing this view.
    pub fn keyfile(&self) -> &KeyFile {
        &self.keyfile
    }
}

/// A typed accessor for one `[remote "<name>"]` section.
#[derive(Debug, Clone)]
pub struct Remote<'a> {
    keyfile: &'a KeyFile,
    group: String,
}

impl Remote<'_> {
    /// The base URL for objects and refs.
    pub fn url(&self) -> Result<Option<String>> {
        self.string("url")
    }

    /// The URL for content objects, when it differs from `url`.
    pub fn contenturl(&self) -> Result<Option<String>> {
        self.string("contenturl")
    }

    /// The metalink URL, when the remote is described by a metalink.
    pub fn metalink(&self) -> Result<Option<String>> {
        self.string("metalink")
    }

    /// Whether commits pulled from this remote are GPG-verified. Default
    /// `true`.
    pub fn gpg_verify(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(&self.group, "gpg-verify")?
            .unwrap_or(true))
    }

    /// Whether the summary of this remote is GPG-verified. Default `false`.
    pub fn gpg_verify_summary(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(&self.group, "gpg-verify-summary")?
            .unwrap_or(false))
    }

    /// The path to a GPG keyring file or directory for this remote.
    pub fn gpgkeypath(&self) -> Result<Option<String>> {
        self.string("gpgkeypath")
    }

    /// The collection id bound to this remote, if set.
    pub fn collection_id(&self) -> Result<Option<String>> {
        self.string("collection-id")
    }

    /// The refs a pull of this remote takes when it is asked for none.
    pub fn branches(&self) -> Result<Option<Vec<String>>> {
        self.keyfile
            .get_string_list(&self.group, "branches")
            .map_err(Error::from)
    }

    /// The path to a PEM file of trust anchors for this remote's TLS, replacing
    /// the host trust store.
    pub fn tls_ca_path(&self) -> Result<Option<String>> {
        self.string("tls-ca-path")
    }

    /// The path to the PEM client certificate chain presented to this remote.
    pub fn tls_client_cert_path(&self) -> Result<Option<String>> {
        self.string("tls-client-cert-path")
    }

    /// The path to the PEM private key of
    /// [`tls_client_cert_path`](Remote::tls_client_cert_path).
    pub fn tls_client_key_path(&self) -> Result<Option<String>> {
        self.string("tls-client-key-path")
    }

    /// Whether this remote's TLS certificate is accepted unverified. Default
    /// `false`. The fetcher has no way to skip verification, so a pull refuses a
    /// remote that sets this rather than verifying against the configuration.
    pub fn tls_permissive(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(&self.group, "tls-permissive")?
            .unwrap_or(false))
    }

    /// The raw value of an arbitrary key in this remote's section.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.keyfile.get_value(&self.group, key)
    }

    fn string(&self, key: &str) -> Result<Option<String>> {
        self.keyfile
            .get_string(&self.group, key)
            .map_err(Error::from)
    }
}

/// The key-file group name for a remote: `remote "<name>"`.
fn remote_group(name: &str) -> String {
    format!("remote \"{name}\"")
}

/// The remote name in a `remote "<name>"` group header, or `None` for any other
/// group.
fn remote_group_name(group: &str) -> Option<&str> {
    group
        .strip_prefix("remote \"")
        .and_then(|rest| rest.strip_suffix('"'))
}

/// Parse a `min-free-space-size` value against `^([0-9]+)(G|M|T)B$`.
fn parse_size(raw: &str) -> Option<SizeSpec> {
    let digits = raw
        .strip_suffix("MB")
        .map(|d| (d, SizeUnit::Mega))
        .or_else(|| {
            raw.strip_suffix("GB")
                .map(|d| (d, SizeUnit::Giga))
                .or_else(|| raw.strip_suffix("TB").map(|d| (d, SizeUnit::Tera)))
        });
    let (digits, unit) = digits?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value = digits.parse::<u64>().ok()?;
    Some(SizeSpec { value, unit })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCHIVE_CONFIG: &str = "[core]\nrepo_version=1\nmode=archive-z2\n";

    #[test]
    fn parses_core_mode_and_version() {
        let cfg = RepoConfig::parse(ARCHIVE_CONFIG).unwrap();
        assert_eq!(cfg.mode(), RepoMode::Archive);
        assert_eq!(cfg.repo_version(), 1);
        assert_eq!(cfg.collection_id(), None);
        assert_eq!(cfg.remotes().count(), 0);
    }

    #[test]
    fn rejects_unsupported_repo_version() {
        let err = RepoConfig::parse("[core]\nrepo_version=2\nmode=bare\n").unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)));
        assert!(err.to_string().contains("version 2"));
    }

    #[test]
    fn rejects_missing_core_group_and_keys() {
        assert!(RepoConfig::parse("[other]\nx=1\n").is_err());
        assert!(RepoConfig::parse("[core]\nmode=bare\n").is_err());
        assert!(RepoConfig::parse("[core]\nrepo_version=1\n").is_err());
    }

    #[test]
    fn rejects_unknown_mode() {
        let err = RepoConfig::parse("[core]\nrepo_version=1\nmode=bogus\n").unwrap_err();
        assert!(err.to_string().contains("unknown repository mode 'bogus'"));
    }

    #[test]
    fn reads_collection_id() {
        let cfg = RepoConfig::parse("[core]\nrepo_version=1\nmode=bare\ncollection-id=org.ex.C\n")
            .unwrap();
        assert_eq!(cfg.collection_id(), Some("org.ex.C"));
    }

    #[test]
    fn tunables_default_when_absent() {
        let cfg = RepoConfig::parse(ARCHIVE_CONFIG).unwrap();
        assert!(cfg.fsync().unwrap());
        assert!(!cfg.per_object_fsync().unwrap());
        assert!(cfg.locking().unwrap());
        assert_eq!(cfg.lock_timeout_secs().unwrap(), 300);
        assert_eq!(cfg.tmp_expiry_secs().unwrap(), 86400);
        assert!(!cfg.disable_xattrs().unwrap());
        assert_eq!(cfg.parent().unwrap(), None);
        assert_eq!(
            cfg.default_repo_finders().unwrap(),
            vec!["config".to_owned(), "mount".to_owned()]
        );
        assert_eq!(cfg.zlib_level().unwrap(), 6);
        assert_eq!(cfg.min_free_space().unwrap(), MinFreeSpace::Percent(3));
    }

    #[test]
    fn tunables_read_configured_values() {
        let text = "[core]\nrepo_version=1\nmode=bare\nfsync=false\n\
                    per-object-fsync=1\nlock-timeout-secs=30\nmin-free-space-percent=5\n\
                    [archive]\nzlib-level=9\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert!(!cfg.fsync().unwrap());
        assert!(cfg.per_object_fsync().unwrap());
        assert_eq!(cfg.lock_timeout_secs().unwrap(), 30);
        assert_eq!(cfg.min_free_space().unwrap(), MinFreeSpace::Percent(5));
        assert_eq!(cfg.zlib_level().unwrap(), 9);
    }

    #[test]
    fn bad_boolean_value_is_an_error() {
        let cfg = RepoConfig::parse("[core]\nrepo_version=1\nmode=bare\nfsync=yes\n").unwrap();
        assert!(cfg.fsync().is_err());
    }

    #[test]
    fn min_free_space_size_wins_over_percent() {
        let text = "[core]\nrepo_version=1\nmode=bare\n\
                    min-free-space-percent=5\nmin-free-space-size=2GB\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert_eq!(
            cfg.min_free_space().unwrap(),
            MinFreeSpace::Size(SizeSpec {
                value: 2,
                unit: SizeUnit::Giga
            })
        );
    }

    #[test]
    fn rejects_out_of_range_min_free_space_percent() {
        for bad in ["-1", "101"] {
            let text = format!("[core]\nrepo_version=1\nmode=bare\nmin-free-space-percent={bad}\n");
            let cfg = RepoConfig::parse(&text).unwrap();
            assert!(cfg.min_free_space().is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn min_free_space_size_units_and_rejection() {
        for (raw, unit) in [
            ("500MB", SizeUnit::Mega),
            ("1GB", SizeUnit::Giga),
            ("3TB", SizeUnit::Tera),
        ] {
            assert_eq!(parse_size(raw).unwrap().unit, unit);
        }
        for bad in ["1G", "GB", "1KB", "1gb", "1GB ", "", "1.5GB"] {
            assert!(parse_size(bad).is_none(), "should reject {bad:?}");
        }
    }

    #[test]
    fn ex_integrity_defaults_off() {
        let cfg = RepoConfig::parse(ARCHIVE_CONFIG).unwrap();
        assert_eq!(cfg.composefs().unwrap(), Tristate::No);
        assert_eq!(cfg.fsverity().unwrap(), Tristate::No);
    }

    #[test]
    fn composefs_raises_fsverity_default_to_maybe() {
        for composefs in ["yes", "maybe"] {
            let text = format!(
                "[core]\nrepo_version=1\nmode=bare\n[ex-integrity]\ncomposefs={composefs}\n"
            );
            let cfg = RepoConfig::parse(&text).unwrap();
            assert_eq!(
                cfg.fsverity().unwrap(),
                Tristate::Maybe,
                "composefs={composefs}"
            );
        }
        // composefs=no leaves fsverity off.
        let text = "[core]\nrepo_version=1\nmode=bare\n[ex-integrity]\ncomposefs=no\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert_eq!(cfg.fsverity().unwrap(), Tristate::No);
    }

    #[test]
    fn explicit_fsverity_overrides_the_composefs_default() {
        // An explicit fsverity value wins over the composefs-derived default.
        let text = "[core]\nrepo_version=1\nmode=bare\n\
                    [ex-integrity]\ncomposefs=yes\nfsverity=no\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert_eq!(cfg.fsverity().unwrap(), Tristate::No);

        let text = "[core]\nrepo_version=1\nmode=bare\n[ex-integrity]\nfsverity=yes\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert_eq!(cfg.fsverity().unwrap(), Tristate::Yes);
    }

    #[test]
    fn malformed_tristate_is_an_error() {
        let text = "[core]\nrepo_version=1\nmode=bare\n[ex-integrity]\nfsverity=true\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert!(cfg.fsverity().is_err());
    }

    #[test]
    fn explicit_fsverity_ignores_a_malformed_composefs() {
        // An explicit fsverity value is honored without consulting composefs, so
        // a malformed composefs does not fail the fsverity read.
        let text = "[core]\nrepo_version=1\nmode=bare\n\
                    [ex-integrity]\ncomposefs=perhaps\nfsverity=no\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert_eq!(cfg.fsverity().unwrap(), Tristate::No);
    }

    #[test]
    fn parses_remote_sections() {
        let text = "[core]\nrepo_version=1\nmode=archive-z2\n\n\
                    [remote \"origin\"]\nurl=https://example.com/repo\nbranches=main;\n\
                    gpg-verify=false\n\n\
                    [remote \"withkey\"]\nurl=https://ex2.com/r\ncollection-id=org.ex.C\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert_eq!(cfg.remotes().collect::<Vec<_>>(), ["origin", "withkey"]);

        let origin = cfg.remote("origin").unwrap();
        assert_eq!(
            origin.url().unwrap().as_deref(),
            Some("https://example.com/repo")
        );
        assert!(!origin.gpg_verify().unwrap());
        assert!(!origin.gpg_verify_summary().unwrap());
        assert_eq!(origin.get("branches"), Some("main;"));
        assert_eq!(origin.branches().unwrap(), Some(vec!["main".to_owned()]));
        assert!(!origin.tls_permissive().unwrap());
        assert_eq!(origin.tls_ca_path().unwrap(), None);

        let withkey = cfg.remote("withkey").unwrap();
        assert!(withkey.gpg_verify().unwrap()); // default true
        assert_eq!(
            withkey.collection_id().unwrap().as_deref(),
            Some("org.ex.C")
        );

        assert!(cfg.remote("absent").is_none());
    }

    /// The TLS keys a pull fills its fetcher's options from, and the one it
    /// refuses rather than misrepresent.
    #[test]
    fn reads_remote_tls_keys() {
        let text = "[core]\nrepo_version=1\nmode=archive-z2\n\n\
                    [remote \"secure\"]\nurl=https://ex.com/r\ntls-ca-path=/etc/ca.pem\n\
                    tls-client-cert-path=/etc/client.pem\ntls-client-key-path=/etc/client.key\n\
                    tls-permissive=true\n";
        let cfg = RepoConfig::parse(text).unwrap();
        let remote = cfg.remote("secure").unwrap();
        assert_eq!(
            remote.tls_ca_path().unwrap().as_deref(),
            Some("/etc/ca.pem")
        );
        assert_eq!(
            remote.tls_client_cert_path().unwrap().as_deref(),
            Some("/etc/client.pem")
        );
        assert_eq!(
            remote.tls_client_key_path().unwrap().as_deref(),
            Some("/etc/client.key")
        );
        assert!(remote.tls_permissive().unwrap());
    }
}
