//! The front end that selects [`Direct`] or [`Helper`] for the process.

use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::OnceLock;

use ostrya::{Checksum, Repo};

use crate::direct::Direct;
use crate::error::Result;
use crate::helper::Helper;
use crate::options::MountOptions;

/// A mounter with the calls of [`Direct`] and [`Helper`].
///
/// [`Mounter::from_env`] selects the front end for the process. Each call
/// goes to the front end that the value holds.
#[derive(Debug)]
#[non_exhaustive]
pub enum Mounter {
    /// The mounter that makes each mount in the process.
    Direct(Direct),
    /// The client of the mount daemon.
    Helper(Helper),
}

impl Mounter {
    /// Returns the mounter for the process.
    ///
    /// If [`Mounter::is_privileged`] is true, the mounter is [`Direct`].
    /// Otherwise it is [`Helper::new`], with the namespaces of the calling
    /// thread.
    ///
    /// # Errors
    ///
    /// The errors of [`Helper::new`].
    pub fn from_env() -> Result<Mounter> {
        if Mounter::is_privileged() {
            Ok(Mounter::Direct(Direct::new()))
        } else {
            Helper::new().map(Mounter::Helper)
        }
    }

    /// Returns `true` if the process is root in the initial user namespace.
    ///
    /// The real and the effective user id must be 0, and
    /// `/proc/self/uid_map` must map the full range of ids from 0 to 0, as
    /// the initial user namespace does. The process reads the two files once
    /// and keeps the answer. If a file does not read, the answer is `false`.
    pub fn is_privileged() -> bool {
        is_privileged()
    }

    /// Mounts the stored composefs image of `commit` at `target`.
    ///
    /// [`Direct::mount_stored`] and [`Helper::mount_stored`] give the rules
    /// and the errors.
    pub async fn mount_stored(
        &self,
        repo: &Repo,
        commit: &Checksum,
        target: &Path,
        opts: &MountOptions,
    ) -> Result<OwnedFd> {
        match self {
            Mounter::Direct(direct) => direct.mount_stored(repo, commit, target, opts).await,
            Mounter::Helper(helper) => helper.mount_stored(repo, commit, target, opts).await,
        }
    }

    /// Builds the composefs image of `commit` and mounts it at `target`.
    ///
    /// [`Direct::mount_built`] and [`Helper::mount_built`] give the rules
    /// and the errors.
    pub async fn mount_built(
        &self,
        repo: &Repo,
        commit: &Checksum,
        target: &Path,
        opts: &MountOptions,
    ) -> Result<OwnedFd> {
        match self {
            Mounter::Direct(direct) => direct.mount_built(repo, commit, target, opts).await,
            Mounter::Helper(helper) => helper.mount_built(repo, commit, target, opts).await,
        }
    }

    /// Unmounts the composefs mount at `target`.
    ///
    /// [`Direct::unmount`] and [`Helper::unmount`] give the rules and the
    /// errors.
    pub async fn unmount(&self, target: &Path) -> Result<()> {
        match self {
            Mounter::Direct(direct) => direct.unmount(target).await,
            Mounter::Helper(helper) => helper.unmount(target).await,
        }
    }
}

/// The facts about the ids of the process that the crate reads once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessIds {
    /// The process is root in the initial user namespace.
    privileged: bool,
    /// The real user id is the effective user id, and the real group id is
    /// the effective group id.
    ids_match: bool,
}

/// Returns the [`ProcessIds`] of the process. The answer is computed once,
/// from `/proc/self/status` and `/proc/self/uid_map`.
fn process_ids() -> ProcessIds {
    static IDS: OnceLock<ProcessIds> = OnceLock::new();
    *IDS.get_or_init(|| {
        let status = std::fs::read_to_string("/proc/self/status").ok();
        let uid = status.as_deref().and_then(|text| id_pair(text, "Uid:"));
        let gid = status.as_deref().and_then(|text| id_pair(text, "Gid:"));
        let map = std::fs::read_to_string("/proc/self/uid_map").ok();
        ProcessIds {
            privileged: uid == Some((0, 0)) && map.is_some_and(|text| uid_map_is_initial(&text)),
            ids_match: matches!((uid, gid), (Some((ru, eu)), Some((rg, eg))) if ru == eu && rg == eg),
        }
    })
}

/// Returns `true` if the process is root in the initial user namespace. The
/// answer is computed once.
pub(crate) fn is_privileged() -> bool {
    process_ids().privileged
}

/// Returns `true` if the real user id of the process is its effective user
/// id, and its real group id is its effective group id. A setuid or setgid
/// program gives `false`. If `/proc/self/status` does not read, the answer
/// is `false`. The answer is computed once.
pub(crate) fn ids_match() -> bool {
    process_ids().ids_match
}

/// Returns the real and the effective id of the line `prefix`, `Uid:` or
/// `Gid:`, of a `/proc/<pid>/status` text, or `None` if the line does not
/// parse.
fn id_pair(status: &str, prefix: &str) -> Option<(u32, u32)> {
    let line = status.lines().find_map(|l| l.strip_prefix(prefix))?;
    let mut ids = line.split_whitespace().map(str::parse::<u32>);
    let real = ids.next()?.ok()?;
    let effective = ids.next()?.ok()?;
    Some((real, effective))
}

/// Returns `true` if a `uid_map` text has a line that maps the full range
/// of ids from 0 to 0, as the map of the initial user namespace does.
fn uid_map_is_initial(text: &str) -> bool {
    text.lines().any(|line| {
        let fields: Vec<u64> = line
            .split_whitespace()
            .filter_map(|f| f.parse().ok())
            .collect();
        matches!(fields.as_slice(), [0, 0, len] if *len >= u64::from(u32::MAX))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_full_range_from_zero_is_the_initial_map() {
        assert!(uid_map_is_initial("         0          0 4294967295\n"));
        assert!(!uid_map_is_initial("         0       1000          1\n"));
        assert!(!uid_map_is_initial("         0     100000      65536\n"));
        assert!(!uid_map_is_initial(""));
    }

    #[test]
    fn id_pair_reads_the_real_and_the_effective_id() {
        let status = "Name:\tx\nUid:\t1000\t0\t0\t0\nGid:\t100\t100\t100\t100\n";
        assert_eq!(id_pair(status, "Uid:"), Some((1000, 0)));
        assert_eq!(id_pair(status, "Gid:"), Some((100, 100)));
        assert_eq!(id_pair("Uid:\t0\t0\t0\t0\n", "Uid:"), Some((0, 0)));
        assert_eq!(id_pair("Name:\tx\n", "Uid:"), None);
        assert_eq!(id_pair("Uid:\tx\t0\n", "Uid:"), None);
    }

    #[test]
    fn the_ids_of_the_test_process_match() {
        assert!(ids_match());
    }
}
