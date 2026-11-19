//! The facts about the ids of the process: root in the initial user
//! namespace, and real ids that are the effective ids.

use std::sync::OnceLock;

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

/// Returns `true` if the process is root in the initial user namespace.
///
/// The real and the effective user id must be 0, and `/proc/self/uid_map`
/// must map the full range of ids from 0 to 0, as the initial user namespace
/// does. The process reads `/proc/self/status` and `/proc/self/uid_map` once
/// and keeps the answer. If a file does not read, the answer is `false`.
///
/// A process for which the answer is `true` mounts with
/// [`Direct`](crate::Direct). Each other process asks the mount daemon with
/// [`Helper`](crate::Helper).
pub fn is_privileged() -> bool {
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
