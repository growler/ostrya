//! The typed view of the repository `config` file.
//!
//! - [`RepoConfig`] reads the keys of the repository groups.
//! - [`Remote`] reads the keys of one `[remote "<name>"]` section.
//! - [`Repo::write_config`] writes an edited config back to the repository.
//! - [`valid_remote_name`] checks a remote name.

use ostrya_core::{KeyFile, RepoMode};

use crate::error::{Error, Result};
use crate::repo::{Repo, check_config_size};
use crate::summary::{remove_root_file_blocking, write_root_file_blocking};

const CORE: &str = "core";
const ARCHIVE: &str = "archive";
const EX_INTEGRITY: &str = "ex-integrity";
const EX_OSTRYA: &str = "ex-ostrya";
/// The name of the `config` file at the repository root.
const CONFIG_FILE: &str = "config";

/// A parsed repository configuration.
///
/// The type holds the [`KeyFile`] parsed from `<repo>/config`. It reads the
/// values with the conventions of the `ostree` command.
///
/// # Groups
///
/// - `[core]`: `repo_version`, `mode`, and the other tunables, each with its
///   default.
/// - `[archive]`: [`zlib_level`](RepoConfig::zlib_level).
/// - `[ex-integrity]`: [`composefs`](RepoConfig::composefs) and
///   [`fsverity`](RepoConfig::fsverity).
/// - `[remote "<name>"]`: one section for each remote, read through
///   [`Remote`].
/// - `[ex-ostrya]`: the keys that are ostrya extensions,
///   [`gc_root_metadata_keys`](RepoConfig::gc_root_metadata_keys) and
///   [`detached_metadata_exclude`](RepoConfig::detached_metadata_exclude).
/// - The groups whose names start with `ex-ostrya` and a space, for example
///   `[ex-ostrya receive]`: the policy that a repository applies to the
///   commits that it receives. Under the `receive` feature,
///   `ReceivePolicy::from_config` reads these groups.
///
/// # Checks
///
/// [`from_keyfile`](RepoConfig::from_keyfile) checks `repo_version` and `mode`
/// when it loads the config. The `ostree` command also refuses to open a
/// repository whose version is not `1`.
///
/// Each other accessor reads its key when it is called. If the key is absent,
/// the accessor returns the default. If the value is malformed, the accessor
/// returns an error, as the `ostree` command reports a value that it cannot
/// read.
#[derive(Debug, Clone)]
pub struct RepoConfig {
    keyfile: KeyFile,
    mode: RepoMode,
    repo_version: i64,
    collection_id: Option<String>,
    remotes: Vec<String>,
}

/// The minimum free space that a write must leave.
///
/// If the config sets a size, the size applies and the percentage does not.
/// The write path applies the byte value of a [`Size`](MinFreeSpace::Size).
/// This type holds the parsed magnitude and unit as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinFreeSpace {
    /// `min-free-space-percent`, from `0` to `100`.
    ///
    /// The default is `3`.
    Percent(u32),
    /// `min-free-space-size`, a magnitude with a binary unit suffix.
    Size(SizeSpec),
}

/// A `min-free-space-size` value: a magnitude and a unit suffix.
///
/// The `ostree` command accepts the suffixes `MB`, `GB`, and `TB`, with the
/// regex `^([0-9]+)(G|M|T)B$`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeSpec {
    /// The numeric magnitude.
    pub value: u64,
    /// The unit suffix.
    pub unit: SizeUnit,
}

/// The unit suffix of a `min-free-space-size` value.
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
    /// Returns the byte multiplier of this unit.
    ///
    /// The suffixes `MB`, `GB`, and `TB` are binary multiples: 2^20, 2^30, and
    /// 2^40.
    pub fn multiplier(self) -> u64 {
        match self {
            SizeUnit::Mega => 1 << 20,
            SizeUnit::Giga => 1 << 30,
            SizeUnit::Tera => 1 << 40,
        }
    }
}

impl SizeSpec {
    /// Returns the value in bytes, or `u64::MAX` if the product overflows.
    pub fn bytes(self) -> u64 {
        self.value.saturating_mul(self.unit.multiplier())
    }
}

/// The value of a `sign-verify` key: the engines that verify signatures.
///
/// The value is a boolean in the key-file spelling (`true`, `false`, `1`,
/// `0`), or a list of engine names. A `,` or a `;` separates the names.
///
/// Each name is used as written. In `ed25519, ed25519`, the second name starts
/// with a space, so no engine has that name. The `ostree` command also refuses
/// this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignVerify {
    /// No sign-api verification: the key is absent, `false`, or names no
    /// engine.
    Off,
    /// Every engine of this build, selected by `true`.
    All,
    /// The engines that the value names, in the order of the value.
    Engines(Vec<String>),
}

/// A tri-state repository setting: `no`, `maybe`, or `yes`.
///
/// The `[ex-integrity]` keys use this form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tristate {
    /// The feature is off.
    No,
    /// Best effort: on where the file system supports the feature.
    ///
    /// Where the file system cannot provide the feature, the operation ignores
    /// it.
    Maybe,
    /// Required: the operation fails where the file system cannot provide it.
    Yes,
}

impl Tristate {
    /// Parses the `no`, `maybe`, or `yes` spelling that the `ostree` command
    /// writes.
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
    /// Creates a typed view of a parsed [`KeyFile`].
    ///
    /// The call checks the `[core]` keys `repo_version` and `mode`. It also
    /// reads `[core] collection-id` and the names of the remote sections.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the config has no `[core]` group, no
    ///   `repo_version` key, or no `mode` key.
    /// - [`Error::InvalidFormat`] if `repo_version` is not `1`, or if `mode`
    ///   names no repository mode.
    /// - [`Error::Core`] if `repo_version` is not an integer, or if `mode` or
    ///   `collection-id` holds a malformed escape sequence.
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

    /// Parses a config from its text.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if the text is not a valid key file.
    /// - The errors of [`from_keyfile`](RepoConfig::from_keyfile).
    pub fn parse(text: &str) -> Result<RepoConfig> {
        RepoConfig::from_keyfile(KeyFile::parse(text)?)
    }

    /// Returns the storage mode of the repository.
    pub fn mode(&self) -> RepoMode {
        self.mode
    }

    /// Returns the `[core] repo_version` value.
    ///
    /// The value is always `1` for a config that this type accepts.
    pub fn repo_version(&self) -> i64 {
        self.repo_version
    }

    /// Returns the `[core] collection-id` of the repository, if it is set.
    pub fn collection_id(&self) -> Option<&str> {
        self.collection_id.as_deref()
    }

    /// Returns the names of the remotes, in the order of their sections.
    pub fn remotes(&self) -> impl Iterator<Item = &str> {
        self.remotes.iter().map(String::as_str)
    }

    /// Returns the accessor of one remote, or `None` if the section does not
    /// exist.
    pub fn remote(&self, name: &str) -> Option<Remote<'_>> {
        Remote::in_keyfile(&self.keyfile, name)
    }

    /// Returns `true` if `[core] fsync` is on.
    ///
    /// The default is `true`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not a boolean.
    pub fn fsync(&self) -> Result<bool> {
        Ok(self.keyfile.get_bool(CORE, "fsync")?.unwrap_or(true))
    }

    /// Returns `true` if each content object file is synced when it is staged.
    ///
    /// The key is `[core] per-object-fsync`, and the default is `false`. A
    /// metadata object is not synced alone.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not a boolean.
    pub fn per_object_fsync(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(CORE, "per-object-fsync")?
            .unwrap_or(false))
    }

    /// Returns `true` if `[core] locking` turns on the repository lock.
    ///
    /// The default is `true`. [`LockKind`](crate::LockKind) describes the
    /// repository lock.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not a boolean.
    pub fn locking(&self) -> Result<bool> {
        Ok(self.keyfile.get_bool(CORE, "locking")?.unwrap_or(true))
    }

    /// Returns the `[core] lock-timeout-secs` limit of a lock wait, in seconds.
    ///
    /// The default is `300`. The value `-1` means no limit.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the value is less than `-1`.
    /// - [`Error::Core`] if the value is not an integer.
    pub fn lock_timeout_secs(&self) -> Result<i64> {
        let secs = self
            .keyfile
            .get_integer(CORE, "lock-timeout-secs")?
            .unwrap_or(300);
        if secs < -1 {
            return Err(Error::InvalidFormat(format!(
                "lock-timeout-secs {secs} is below -1"
            )));
        }
        Ok(secs)
    }

    /// Returns the `[core] tmp-expiry-secs` expiry of a stale entry in `tmp/`,
    /// in seconds.
    ///
    /// The default is `86400`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not an integer.
    pub fn tmp_expiry_secs(&self) -> Result<i64> {
        Ok(self
            .keyfile
            .get_integer(CORE, "tmp-expiry-secs")?
            .unwrap_or(86400))
    }

    /// Returns `true` if the summary announces tombstone commits.
    ///
    /// The key is `[core] tombstone-commits`, and the default is `false`. The
    /// summary writes this value as `ostree.summary.tombstone-commits`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not a boolean.
    pub fn tombstone_commits(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(CORE, "tombstone-commits")?
            .unwrap_or(false))
    }

    /// Returns `true` if the repository indexes its static deltas.
    ///
    /// The key is `[core] indexed-deltas`, and the default is `true`. The
    /// summary writes this value as `ostree.summary.indexed-deltas`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not a boolean.
    pub fn indexed_deltas(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(CORE, "indexed-deltas")?
            .unwrap_or(true))
    }

    /// Returns `true` if `[core] disable-xattrs` turns off xattr storage.
    ///
    /// The default is `false`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not a boolean.
    pub fn disable_xattrs(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(CORE, "disable-xattrs")?
            .unwrap_or(false))
    }

    /// Returns the `[core] parent` repository path, if it is set.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn parent(&self) -> Result<Option<String>> {
        self.keyfile.get_string(CORE, "parent").map_err(Error::from)
    }

    /// Returns the `[core] default-repo-finders` list.
    ///
    /// The default is `["config", "mount"]`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn default_repo_finders(&self) -> Result<Vec<String>> {
        Ok(self
            .keyfile
            .get_string_list(CORE, "default-repo-finders")?
            .unwrap_or_else(|| vec!["config".to_owned(), "mount".to_owned()]))
    }

    /// Returns the minimum free space that a write must leave.
    ///
    /// If `[core] min-free-space-size` is set, it applies. If it is not set,
    /// `[core] min-free-space-percent` applies, with the default `3`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `min-free-space-size` does not match
    ///   `^([0-9]+)(G|M|T)B$`, or if its magnitude does not fit in a `u64`.
    /// - [`Error::InvalidFormat`] if `min-free-space-percent` is outside the
    ///   range `0` to `100`.
    /// - [`Error::Core`] if `min-free-space-percent` is not an integer.
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

    /// Returns the `[archive] zlib-level` compression level.
    ///
    /// The default is `6`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not an integer.
    pub fn zlib_level(&self) -> Result<i64> {
        Ok(self
            .keyfile
            .get_integer(ARCHIVE, "zlib-level")?
            .unwrap_or(6))
    }

    /// Returns the `[ex-ostrya] gc-root-metadata-keys` list.
    ///
    /// The list names the metadata keys from which a prune reads more
    /// reachable commits. The key is an ostrya extension, and the list is empty
    /// by default.
    ///
    /// The `ostrya prune` command puts this list into
    /// [`PruneOptions::gc_root_metadata_keys`](crate::PruneOptions::gc_root_metadata_keys).
    /// The list adds roots and removes none. It has no counterpart for
    /// [`traverse_parent`](crate::PruneOptions::traverse_parent). As a result,
    /// a prune with this list keeps at least what a prune with the
    /// reachability of the `ostree` command keeps.
    ///
    /// The library does not read this key. [`Repo::prune`](crate::Repo::prune)
    /// uses only the options that its caller gives.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn gc_root_metadata_keys(&self) -> Result<Vec<String>> {
        self.string_list(EX_OSTRYA, "gc-root-metadata-keys")
    }

    /// Returns the `[ex-ostrya] detached-metadata-exclude` list.
    ///
    /// The list names the detached metadata keys that this repository does not
    /// store when it receives a commit. The repository also does not send these
    /// keys when it serves a commit. The key is an ostrya extension, and the
    /// list is empty by default.
    ///
    /// The `ostrya pull` and `ostrya pull-local` commands put this list into
    /// [`PullOptions::detached_metadata_filter`](crate::PullOptions::detached_metadata_filter)
    /// through
    /// [`DetachedMetadataFilter::excluding`](crate::DetachedMetadataFilter::excluding).
    /// Under the `receive` feature, `ReceivePolicy::from_config` reads it into
    /// the filter of the receive path.
    ///
    /// This list never comes from
    /// [`gc_root_metadata_keys`](RepoConfig::gc_root_metadata_keys), also when
    /// the two lists are equal. If a repository roots on a key and does not
    /// list it here, the repository continues to transfer the key.
    ///
    /// The list controls what a pull stores. It does not change what the
    /// repository already holds. If the list names each detached metadata key
    /// of a commit, a pull keeps the copy that the destination holds. A new
    /// pull after a change of this key does not remove a copy from an earlier
    /// pull.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn detached_metadata_exclude(&self) -> Result<Vec<String>> {
        self.string_list(EX_OSTRYA, "detached-metadata-exclude")
    }

    /// Returns `true` if a ref change regenerates the summary.
    ///
    /// The keys are `[core] auto-update-summary` and its deprecated alias
    /// `commit-update-summary`. The default is `false`.
    ///
    /// The call reads the two keys together. If either key is true, the
    /// regeneration is on. An observation of the `ostree` command shows the
    /// same rule: with one key true and the other false, in either order,
    /// `ostree commit` writes a summary.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if either key is not a boolean, also when the other key
    /// is true. The `ostree` command also refuses this value.
    pub fn auto_update_summary(&self) -> Result<bool> {
        let canonical = self.keyfile.get_bool(CORE, "auto-update-summary")?;
        let alias = self.keyfile.get_bool(CORE, "commit-update-summary")?;
        Ok(canonical.unwrap_or(false) || alias.unwrap_or(false))
    }

    /// Reads a `;`-separated list key. The list is empty if the key is absent.
    /// A value that the key-file syntax cannot split is an error.
    fn string_list(&self, group: &str, key: &str) -> Result<Vec<String>> {
        Ok(self
            .keyfile
            .get_string_list(group, key)?
            .unwrap_or_default())
    }

    /// Returns the `[ex-integrity] composefs` setting.
    ///
    /// The default is [`Tristate::No`]. The setting sets the default of
    /// [`fsverity`](RepoConfig::fsverity). The write path does not use the
    /// composefs deployment behavior that the key also controls.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the value is not `no`, `maybe`, or `yes`.
    /// - [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn composefs(&self) -> Result<Tristate> {
        Ok(self
            .tristate(EX_INTEGRITY, "composefs")?
            .unwrap_or(Tristate::No))
    }

    /// Returns the `[ex-integrity] fsverity` setting.
    ///
    /// The setting controls the fs-verity seal of the loose objects:
    ///
    /// - `maybe` or `yes`: each loose object that the object store holds as a
    ///   regular file gets a seal at staging, in every repository mode.
    /// - `yes`: if a seal fails, the write fails with [`Error::Unsupported`].
    /// - `maybe`: the write ignores a seal that fails.
    ///
    /// An explicit value applies as written. If the key is absent, the default
    /// is `No`. If the key is absent and [`composefs`](RepoConfig::composefs)
    /// is `Yes` or `Maybe`, the default is `Maybe`. The call reads `composefs`
    /// only when the key is absent.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the value is not `no`, `maybe`, or `yes`.
    /// - [`Error::Core`] if the value holds a malformed escape sequence.
    /// - If the key is absent, the errors of
    ///   [`composefs`](RepoConfig::composefs).
    pub fn fsverity(&self) -> Result<Tristate> {
        if let Some(explicit) = self.tristate(EX_INTEGRITY, "fsverity")? {
            return Ok(explicit);
        }
        Ok(match self.composefs()? {
            Tristate::No => Tristate::No,
            Tristate::Maybe | Tristate::Yes => Tristate::Maybe,
        })
    }

    /// Reads a tri-state key. Returns `None` if the key is absent. A value
    /// other than `no`, `maybe`, or `yes` is a malformed config error.
    fn tristate(&self, group: &str, key: &str) -> Result<Option<Tristate>> {
        match self.keyfile.get_string(group, key)? {
            None => Ok(None),
            Some(raw) => Tristate::parse(&raw).map(Some).ok_or_else(|| {
                Error::InvalidFormat(format!("malformed [{group}] {key} value '{raw}'"))
            }),
        }
    }

    /// Returns the parsed key file of this view.
    ///
    /// A caller can read the keys that this type does not model. The key file
    /// keeps the order of the source text when it writes the config again.
    pub fn keyfile(&self) -> &KeyFile {
        &self.keyfile
    }

    /// Returns the parsed key file of this view by value.
    pub(crate) fn into_keyfile(self) -> KeyFile {
        self.keyfile
    }
}

/// Methods that write the config and the keyring of a remote.
impl Repo {
    /// Replaces the repository `config` with the document in `keyfile`.
    ///
    /// The call writes the file as the write path writes each file at the
    /// repository root:
    ///
    /// 1. It writes a new temporary file at mode `0644`.
    /// 2. If `[core] fsync` is on, it syncs the file with `fdatasync`.
    /// 3. It renames the file over `config`.
    /// 4. If `[core] fsync` is on, it syncs the repository directory.
    ///
    /// A reader sees the old document or the new one.
    ///
    /// # Edits
    ///
    /// The call writes the document as given. If a caller removes `[core] mode`
    /// or `[core] repo_version`, [`Repo::open`] refuses the written file. To
    /// change a key, a caller reads the current document through
    /// [`RepoConfig::keyfile`], changes it with the setters and removers of
    /// [`KeyFile`], and writes it back.
    ///
    /// This handle keeps the configuration that it was opened with. To read
    /// the new values, open the repository again.
    ///
    /// # Locks
    ///
    /// The call takes the repository lock shared, as
    /// [`LockKind`](crate::LockKind) describes. Then it takes the update lock
    /// for its write step, as [`Repo::begin_update`] does. It writes under both
    /// locks.
    ///
    /// The locks cover the write alone. A document that a caller read from
    /// this handle before the call can miss the write of another writer. A
    /// read-modify-write that must see the current file reads and writes it
    /// through an [`UpdateGuard`](crate::UpdateGuard).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the document is larger than 1 MiB, the
    ///   size that an open accepts. The call then writes nothing.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`. Each of the two waits gets the full timeout.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` of this handle
    ///   is less than `-1`.
    /// - [`Error::Core`] if `[core] fsync` or `[core] locking` of this handle
    ///   is not a boolean, or if `[core] lock-timeout-secs` is not an integer.
    /// - [`Error::Io`] if a lock file, the write, the rename, or a sync fails
    ///   on the file system.
    pub async fn write_config(&self, keyfile: &KeyFile) -> Result<()> {
        let fsync = self.config().fsync()?;
        let bytes = keyfile.to_string().into_bytes();
        check_config_size(&bytes)?;
        self.write_locked(move |repo| {
            write_root_file_blocking(repo.repo_fd(), CONFIG_FILE, &bytes, fsync)
        })
        .await
    }

    /// Removes the trusted GPG keyring of a remote at the repository root.
    ///
    /// The file is `<remote>.trustedkeys.gpg`. If the keyring is absent, the
    /// call succeeds. The keyring belongs to the config section of the remote,
    /// so a deletion of the section also deletes this file.
    ///
    /// The call takes the same locks as [`write_config`](Repo::write_config)
    /// and waits for them in the same way.
    ///
    /// # Errors
    ///
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` of this handle
    ///   is less than `-1`.
    /// - [`Error::Core`] if `[core] locking` of this handle is not a boolean,
    ///   or if `[core] lock-timeout-secs` is not an integer.
    /// - [`Error::Io`] if a lock file or the removal fails on the file system.
    pub async fn remove_remote_keyring(&self, remote: &str) -> Result<()> {
        let name = remote_keyring_name(remote);
        self.write_locked(move |repo| remove_root_file_blocking(repo.repo_fd(), &name))
            .await
    }
}

/// Returns the name of the trusted keyring of a remote at the repository root.
pub(crate) fn remote_keyring_name(remote: &str) -> String {
    format!("{remote}.trustedkeys.gpg")
}

/// A typed accessor for one `[remote "<name>"]` section.
///
/// A trust group of a receive policy takes the key names of a remote section.
/// Under the `receive` feature, `ReceivePolicy::from_config` reads a trust
/// group through this type.
#[derive(Debug, Clone)]
pub struct Remote<'a> {
    keyfile: &'a KeyFile,
    group: String,
}

impl<'a> Remote<'a> {
    /// Returns the `[remote "<name>"]` section of `keyfile`, or `None` if the
    /// section does not exist.
    pub(crate) fn in_keyfile(keyfile: &'a KeyFile, name: &str) -> Option<Remote<'a>> {
        let group = remote_group(name);
        keyfile
            .has_group(&group)
            .then_some(Remote { keyfile, group })
    }

    /// Returns the accessors of a remote section over another group of
    /// `keyfile`. The group takes the key names and the value forms of a
    /// remote section.
    #[cfg(feature = "receive")]
    pub(crate) fn view(keyfile: &'a KeyFile, group: String) -> Remote<'a> {
        Remote { keyfile, group }
    }
}

impl Remote<'_> {
    /// Returns the `url` key: the base URL of the objects and the refs.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn url(&self) -> Result<Option<String>> {
        self.string("url")
    }

    /// Returns the `contenturl` key: the URL of the content objects.
    ///
    /// A remote sets this key if the URL differs from `url`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn contenturl(&self) -> Result<Option<String>> {
        self.string("contenturl")
    }

    /// Returns the `metalink` key: the URL of a metalink for this remote.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn metalink(&self) -> Result<Option<String>> {
        self.string("metalink")
    }

    /// Returns `true` if a pull verifies the GPG signatures of commits.
    ///
    /// The key is `gpg-verify`, and the default is `true`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not a boolean.
    pub fn gpg_verify(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(&self.group, "gpg-verify")?
            .unwrap_or(true))
    }

    /// Returns `true` if a pull verifies the GPG signature of the summary.
    ///
    /// The key is `gpg-verify-summary`, and the default is `false`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not a boolean.
    pub fn gpg_verify_summary(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(&self.group, "gpg-verify-summary")?
            .unwrap_or(false))
    }

    /// Returns the `gpgkeypath` entries: more trusted GPG keyrings.
    ///
    /// The remote also trusts the keyring `<remote>.trustedkeys.gpg` of the
    /// repository and the system trusted set. A `;` separates the entries, and
    /// the list skips an empty entry. Each entry is a keyring file or a
    /// directory of keyring files.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn gpgkeypath(&self) -> Result<Vec<String>> {
        Ok(self
            .string("gpgkeypath")?
            .map(|raw| {
                raw.split(';')
                    .filter(|entry| !entry.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Returns the sign-api engines that verify the commits of this remote.
    ///
    /// The key is `sign-verify`, and the default is [`SignVerify::Off`].
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn sign_verify(&self) -> Result<SignVerify> {
        Ok(parse_sign_verify(self.string("sign-verify")?.as_deref()))
    }

    /// Returns the sign-api engines that verify the summary of this remote.
    ///
    /// The key is `sign-verify-summary`, and the default is
    /// [`SignVerify::Off`]. The call reads this key alone. `sign-verify=false`
    /// does not turn off a summary verification that this key asks for.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn sign_verify_summary(&self) -> Result<SignVerify> {
        Ok(parse_sign_verify(
            self.string("sign-verify-summary")?.as_deref(),
        ))
    }

    /// Returns the inline trusted key of one sign-api engine.
    ///
    /// The key is `verification-<engine>-key`. It holds exactly one key.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn verification_key(&self, engine: &str) -> Result<Option<String>> {
        self.string(&format!("verification-{engine}-key"))
    }

    /// Returns the path of a file of trusted keys for one sign-api engine.
    ///
    /// The key is `verification-<engine>-file`. The file holds one key on each
    /// line.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn verification_file(&self, engine: &str) -> Result<Option<String>> {
        self.string(&format!("verification-{engine}-file"))
    }

    /// Returns the `collection-id` of this remote, if it is set.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn collection_id(&self) -> Result<Option<String>> {
        self.string("collection-id")
    }

    /// Returns the `branches` key: the refs of a pull that names no ref.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn branches(&self) -> Result<Option<Vec<String>>> {
        self.keyfile
            .get_string_list(&self.group, "branches")
            .map_err(Error::from)
    }

    /// Returns the `tls-ca-path` key: a PEM file of trust anchors for TLS.
    ///
    /// The anchors replace the trust store of the host. A pull and a push read
    /// a relative path from the current directory of the process. They do not
    /// expand `~`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn tls_ca_path(&self) -> Result<Option<String>> {
        self.string("tls-ca-path")
    }

    /// Returns the `tls-client-cert-path` key: the PEM client certificate
    /// chain.
    ///
    /// The client presents this chain to the remote. A relative path is read as
    /// [`tls_ca_path`](Remote::tls_ca_path) states.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn tls_client_cert_path(&self) -> Result<Option<String>> {
        self.string("tls-client-cert-path")
    }

    /// Returns the `tls-client-key-path` key: the PEM private key of the
    /// client.
    ///
    /// The key belongs to the chain of
    /// [`tls_client_cert_path`](Remote::tls_client_cert_path). A relative path
    /// is read as [`tls_ca_path`](Remote::tls_ca_path) states.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn tls_client_key_path(&self) -> Result<Option<String>> {
        self.string("tls-client-key-path")
    }

    /// Returns `true` if `tls-permissive` turns off the TLS chain verification.
    ///
    /// The default is `false`. A pull from a remote that sets the key accepts
    /// the certificate chain as presented and keeps the host name check.
    ///
    /// A push refuses an `https://` address of a remote that sets the key. A
    /// push to an `http://` address uses no TLS and ignores the key.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value is not a boolean.
    pub fn tls_permissive(&self) -> Result<bool> {
        Ok(self
            .keyfile
            .get_bool(&self.group, "tls-permissive")?
            .unwrap_or(false))
    }

    /// Returns the `push-url` key: the push address of this remote.
    ///
    /// If the key is absent and `url` is an `http://` or an `https://` URL, a
    /// push uses `url`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn push_url(&self) -> Result<Option<String>> {
        self.string("push-url")
    }

    /// Returns the `ssh-command` key: the ssh command line of this remote.
    ///
    /// A push to this remote and a pull over ssh from it run this command. The
    /// ssh transport splits it at ASCII white space, with no quoting rule.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn ssh_command(&self) -> Result<Option<String>> {
        self.string("ssh-command")
    }

    /// Returns the `receive-command` key: the remote command of a push.
    ///
    /// The remote side of a push to this remote runs this command. The remote
    /// shell parses it.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn receive_command(&self) -> Result<Option<String>> {
        self.string("receive-command")
    }

    /// Returns the `push-token-file` key: the token file of an HTTP push.
    ///
    /// The first line of the file is the token of an HTTP push to this remote.
    /// The push reads a relative path from the current directory of the
    /// process, as a pull reads the TLS keys. It does not expand `~`.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn push_token_file(&self) -> Result<Option<String>> {
        self.string("push-token-file")
    }

    /// Returns the `push-user` key: the Basic credential name of an HTTP push.
    ///
    /// The token of [`push_token_file`](Remote::push_token_file) is the
    /// password. If the key is absent, the push sends the token as a bearer
    /// token.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn push_user(&self) -> Result<Option<String>> {
        self.string("push-user")
    }

    /// Returns the `pull-url` key: the pull address of this remote.
    ///
    /// The value is an ssh address, or an `http://` or `https://` URL. If the
    /// key is set, a pull from this remote uses it and ignores `url`. The key
    /// is an ostrya extension, and the `ostree` command does not read it.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn pull_url(&self) -> Result<Option<String>> {
        self.string("pull-url")
    }

    /// Returns the `send-command` key: the remote command of a pull over ssh.
    ///
    /// The remote side of a pull over ssh from this remote runs this command.
    /// The remote shell parses it.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn send_command(&self) -> Result<Option<String>> {
        self.string("send-command")
    }

    /// Returns the `proxy` key: the `http://` proxy URL of an HTTP pull.
    ///
    /// An HTTP pull from this remote connects through this proxy. If the value
    /// is empty, the key counts as absent, and the pull reads the proxy
    /// environment variables. A pull that uses the key connects through the
    /// proxy for every origin and ignores `no_proxy`.
    ///
    /// The call keeps white space at the end of the value. An HTTP pull
    /// refuses a non-empty value with white space at its start or end. A push
    /// and a pull over ssh do not read the key.
    ///
    /// # Errors
    ///
    /// [`Error::Core`] if the value holds a malformed escape sequence.
    pub fn proxy(&self) -> Result<Option<String>> {
        self.string("proxy")
    }

    /// Returns the raw value of any key in this remote section.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.keyfile.get_value(&self.group, key)
    }

    fn string(&self, key: &str) -> Result<Option<String>> {
        self.keyfile
            .get_string(&self.group, key)
            .map_err(Error::from)
    }
}

/// Reads a `sign-verify` or `sign-verify-summary` value. The value is a
/// boolean in the key-file spelling, or a list of engine names that `,` or `;`
/// separates.
fn parse_sign_verify(raw: Option<&str>) -> SignVerify {
    let Some(raw) = raw else {
        return SignVerify::Off;
    };
    match raw {
        "true" | "1" => return SignVerify::All,
        "false" | "0" => return SignVerify::Off,
        _ => {}
    }
    let engines: Vec<String> = raw
        .split([',', ';'])
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    if engines.is_empty() {
        return SignVerify::Off;
    }
    SignVerify::Engines(engines)
}

/// Returns the key-file group name of a remote: `remote "<name>"`.
pub(crate) fn remote_group(name: &str) -> String {
    format!("remote \"{name}\"")
}

/// Returns `true` if the `ostree` command accepts `name` as a remote name.
///
/// A valid name obeys these rules:
///
/// - It has at least one character.
/// - Each character is alphanumeric, `-`, `_`, or `.`.
/// - The first character is alphanumeric or `_`.
///
/// For example, `_` is a valid name, and `-`, `.`, and `..` are not.
/// "Alphanumeric" is [`char::is_alphanumeric`], so a non-ASCII letter counts.
pub fn valid_remote_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_alphanumeric() || first == '_') {
        return false;
    }
    name.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Returns the remote name in a `remote "<name>"` group header, or `None` for
/// another group.
pub(crate) fn remote_group_name(group: &str) -> Option<&str> {
    group
        .strip_prefix("remote \"")
        .and_then(|rest| rest.strip_suffix('"'))
}

/// Parses a `min-free-space-size` value with the pattern `^([0-9]+)(G|M|T)B$`.
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
    fn valid_remote_name_takes_the_names_the_tool_takes() {
        for name in ["_", "1o", "a..b", "\u{e9}", "origin"] {
            assert!(valid_remote_name(name), "{name:?}");
        }
        for name in ["", "-", ".", "..", "a b", "a/b", "a+b"] {
            assert!(!valid_remote_name(name), "{name:?}");
        }
    }

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
    fn lock_timeout_secs_takes_minus_one_and_refuses_below() {
        let with = |v: &str| {
            RepoConfig::parse(&format!(
                "[core]\nrepo_version=1\nmode=bare\nlock-timeout-secs={v}\n"
            ))
            .unwrap()
        };
        assert_eq!(with("-1").lock_timeout_secs().unwrap(), -1);
        assert_eq!(with("0").lock_timeout_secs().unwrap(), 0);
        let err = with("-2").lock_timeout_secs().unwrap_err();
        assert!(err.to_string().contains("lock-timeout-secs -2 is below -1"));
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
        // The call does not read composefs when fsverity has an explicit
        // value, so a malformed composefs does not fail the fsverity read.
        let text = "[core]\nrepo_version=1\nmode=bare\n\
                    [ex-integrity]\ncomposefs=perhaps\nfsverity=no\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert_eq!(cfg.fsverity().unwrap(), Tristate::No);
    }

    #[test]
    fn ex_ostrya_lists_are_empty_when_absent() {
        let cfg = RepoConfig::parse(ARCHIVE_CONFIG).unwrap();
        assert!(cfg.gc_root_metadata_keys().unwrap().is_empty());
        assert!(cfg.detached_metadata_exclude().unwrap().is_empty());
    }

    #[test]
    fn ex_ostrya_lists_parse_their_values() {
        let text = "[core]\nrepo_version=1\nmode=bare\n[ex-ostrya]\n\
                    gc-root-metadata-keys=app.roots;app.caches\n\
                    detached-metadata-exclude=app.roots\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert_eq!(
            cfg.gc_root_metadata_keys().unwrap(),
            vec!["app.roots".to_owned(), "app.caches".to_owned()]
        );
        assert_eq!(
            cfg.detached_metadata_exclude().unwrap(),
            vec!["app.roots".to_owned()]
        );
    }

    #[test]
    fn an_ex_ostrya_list_takes_a_trailing_separator() {
        // The key-file list convention writes a trailing `;`, which adds no
        // empty element.
        let text = "[core]\nrepo_version=1\nmode=bare\n[ex-ostrya]\n\
                    gc-root-metadata-keys=app.roots;app.caches;\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert_eq!(
            cfg.gc_root_metadata_keys().unwrap(),
            vec!["app.roots".to_owned(), "app.caches".to_owned()]
        );
    }

    #[test]
    fn a_malformed_ex_ostrya_list_is_an_error() {
        // A value that ends in a lone backslash is not a list that the
        // key-file syntax can split.
        let text = "[core]\nrepo_version=1\nmode=bare\n[ex-ostrya]\n\
                    detached-metadata-exclude=app.roots\\\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert!(cfg.detached_metadata_exclude().is_err());
    }

    /// Summary regeneration is off by default, each key alone turns it on, and
    /// either key true wins over the other key false.
    #[test]
    fn auto_update_summary_reads_both_keys() {
        let read = |extra: &str| {
            RepoConfig::parse(&format!("[core]\nrepo_version=1\nmode=archive\n{extra}"))
                .unwrap()
                .auto_update_summary()
        };
        assert!(!read("").unwrap());
        assert!(read("auto-update-summary=true\n").unwrap());
        assert!(read("commit-update-summary=1\n").unwrap());
        assert!(!read("auto-update-summary=false\ncommit-update-summary=0\n").unwrap());
        assert!(read("auto-update-summary=true\ncommit-update-summary=false\n").unwrap());
        assert!(read("auto-update-summary=false\ncommit-update-summary=true\n").unwrap());
    }

    /// A malformed value in either key is an error, also when the other key is
    /// true.
    #[test]
    fn a_malformed_auto_update_summary_is_an_error() {
        for extra in [
            "auto-update-summary=yes\n",
            "commit-update-summary=yes\n",
            "auto-update-summary=true\ncommit-update-summary=yes\n",
            "auto-update-summary=yes\ncommit-update-summary=true\n",
        ] {
            let cfg = RepoConfig::parse(&format!("[core]\nrepo_version=1\nmode=archive\n{extra}"))
                .unwrap();
            assert!(
                matches!(
                    cfg.auto_update_summary(),
                    Err(Error::Core(ostrya_core::Error::KeyFile(_)))
                ),
                "{extra:?}"
            );
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

    /// The verification keys a pull reads its policy from: the two sign-api
    /// switches, the per-engine key sources, and the GPG keyring list.
    #[test]
    fn reads_remote_verification_keys() {
        let text = "[core]\nrepo_version=1\nmode=archive-z2\n\n\
                    [remote \"signed\"]\nurl=https://ex.com/r\nsign-verify=ed25519\n\
                    sign-verify-summary=true\nverification-ed25519-key=AAAA\n\
                    verification-ed25519-file=/etc/keys.ed25519\n\
                    gpgkeypath=/etc/one.gpg;/etc/keys.d\n";
        let cfg = RepoConfig::parse(text).unwrap();
        let remote = cfg.remote("signed").unwrap();
        assert_eq!(
            remote.sign_verify().unwrap(),
            SignVerify::Engines(vec!["ed25519".to_owned()])
        );
        assert_eq!(remote.sign_verify_summary().unwrap(), SignVerify::All);
        assert_eq!(
            remote.verification_key("ed25519").unwrap().as_deref(),
            Some("AAAA")
        );
        assert_eq!(
            remote.verification_file("ed25519").unwrap().as_deref(),
            Some("/etc/keys.ed25519")
        );
        assert_eq!(remote.verification_key("spki").unwrap(), None);
        assert_eq!(
            remote.gpgkeypath().unwrap(),
            vec!["/etc/one.gpg".to_owned(), "/etc/keys.d".to_owned()]
        );

        // The defaults: no sign-api verification and no extra keyring.
        let plain = cfg.remote("signed").unwrap();
        assert!(plain.gpg_verify().unwrap());
        let bare = RepoConfig::parse(
            "[core]\nrepo_version=1\nmode=bare\n\n[remote \"plain\"]\nurl=http://ex/r\n",
        )
        .unwrap();
        let bare = bare.remote("plain").unwrap();
        assert_eq!(bare.sign_verify().unwrap(), SignVerify::Off);
        assert_eq!(bare.sign_verify_summary().unwrap(), SignVerify::Off);
        assert!(bare.gpgkeypath().unwrap().is_empty());
    }

    /// `sign-verify` is a boolean or a list of engine names, split on `,` and
    /// `;`, each name taken as written.
    #[test]
    fn parses_the_sign_verify_spellings() {
        assert_eq!(parse_sign_verify(None), SignVerify::Off);
        assert_eq!(parse_sign_verify(Some("true")), SignVerify::All);
        assert_eq!(parse_sign_verify(Some("1")), SignVerify::All);
        assert_eq!(parse_sign_verify(Some("false")), SignVerify::Off);
        assert_eq!(parse_sign_verify(Some("0")), SignVerify::Off);
        assert_eq!(parse_sign_verify(Some("")), SignVerify::Off);
        assert_eq!(
            parse_sign_verify(Some("ed25519")),
            SignVerify::Engines(vec!["ed25519".to_owned()])
        );
        // Both separators, and an empty element dropped.
        assert_eq!(
            parse_sign_verify(Some("ed25519;spki,")),
            SignVerify::Engines(vec!["ed25519".to_owned(), "spki".to_owned()])
        );
        // A name is not trimmed. The `ostree` command also refuses this value.
        assert_eq!(
            parse_sign_verify(Some("ed25519, ed25519")),
            SignVerify::Engines(vec!["ed25519".to_owned(), " ed25519".to_owned()])
        );
    }

    /// The TLS keys from which a pull fills the options of its fetcher.
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

    /// The `proxy` key of a remote section, read as written.
    ///
    /// The value keeps its trailing spaces, and the read decodes its escapes.
    /// It is empty when the value is empty or spaces, and absent when the
    /// section does not set it.
    #[test]
    fn reads_remote_proxy_key() {
        let text = "[core]\nrepo_version=1\nmode=archive-z2\n\n\
                    [remote \"set\"]\nurl=http://ex.com/r\n\
                    proxy=http://user:pw@proxy.ex.com:3128\n\n\
                    [remote \"empty\"]\nurl=http://ex.com/r\nproxy=\n\n\
                    [remote \"blank\"]\nurl=http://ex.com/r\nproxy=  \n\n\
                    [remote \"trail\"]\nurl=http://ex.com/r\nproxy=http://p:1  \n\n\
                    [remote \"escape\"]\nurl=http://ex.com/r\nproxy=\\s\n\n\
                    [remote \"plain\"]\nurl=http://ex.com/r\n";
        let cfg = RepoConfig::parse(text).unwrap();
        assert_eq!(
            cfg.remote("set").unwrap().proxy().unwrap().as_deref(),
            Some("http://user:pw@proxy.ex.com:3128")
        );
        assert_eq!(
            cfg.remote("empty").unwrap().proxy().unwrap().as_deref(),
            Some("")
        );
        assert_eq!(
            cfg.remote("blank").unwrap().proxy().unwrap().as_deref(),
            Some("")
        );
        assert_eq!(
            cfg.remote("trail").unwrap().proxy().unwrap().as_deref(),
            Some("http://p:1  ")
        );
        assert_eq!(
            cfg.remote("escape").unwrap().proxy().unwrap().as_deref(),
            Some(" ")
        );
        assert_eq!(cfg.remote("plain").unwrap().proxy().unwrap(), None);
    }

    /// The push keys and the pull keys of ostrya in a remote section. Each key
    /// is read as written, and is absent when the section does not set it.
    #[test]
    fn reads_remote_push_keys() {
        let text = "[core]\nrepo_version=1\nmode=archive-z2\n\n\
                    [remote \"central\"]\nurl=https://ex.com/r\n\
                    push-url=ssh://pusher@ex.com/srv/repo\n\
                    ssh-command=ssh -o BatchMode=yes\n\
                    receive-command=/opt/bin/ostrya receive\n\
                    push-token-file=/etc/push token\n\
                    push-user=alice\n\
                    pull-url=puller@ex.com:srv/repo\n\
                    send-command=/opt/bin/ostrya send -v\n\n\
                    [remote \"plain\"]\nurl=https://ex.com/r\n";
        let cfg = RepoConfig::parse(text).unwrap();
        let remote = cfg.remote("central").unwrap();
        assert_eq!(
            remote.push_url().unwrap().as_deref(),
            Some("ssh://pusher@ex.com/srv/repo")
        );
        assert_eq!(
            remote.ssh_command().unwrap().as_deref(),
            Some("ssh -o BatchMode=yes")
        );
        assert_eq!(
            remote.receive_command().unwrap().as_deref(),
            Some("/opt/bin/ostrya receive")
        );
        assert_eq!(
            remote.push_token_file().unwrap().as_deref(),
            Some("/etc/push token")
        );
        assert_eq!(remote.push_user().unwrap().as_deref(), Some("alice"));
        assert_eq!(
            remote.pull_url().unwrap().as_deref(),
            Some("puller@ex.com:srv/repo")
        );
        assert_eq!(
            remote.send_command().unwrap().as_deref(),
            Some("/opt/bin/ostrya send -v")
        );

        let plain = cfg.remote("plain").unwrap();
        assert_eq!(plain.push_url().unwrap(), None);
        assert_eq!(plain.ssh_command().unwrap(), None);
        assert_eq!(plain.receive_command().unwrap(), None);
        assert_eq!(plain.push_token_file().unwrap(), None);
        assert_eq!(plain.push_user().unwrap(), None);
        assert_eq!(plain.pull_url().unwrap(), None);
        assert_eq!(plain.send_command().unwrap(), None);
    }
}
