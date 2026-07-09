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

        let withkey = cfg.remote("withkey").unwrap();
        assert!(withkey.gpg_verify().unwrap()); // default true
        assert_eq!(
            withkey.collection_id().unwrap().as_deref(),
            Some("org.ex.C")
        );

        assert!(cfg.remote("absent").is_none());
    }
}
