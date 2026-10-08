//! The privilege tier of the host.
//!
//! [`detect`] returns the [`Host`], with the tier that the process provides.
//! [`Tier`] names the tiers.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::record::Tier;

/// The path of the system repository.
///
/// The `ostree` command has this path compiled in as its third `--repo`
/// source, after the current directory and `OSTREE_REPO`.
pub const SYSTEM_REPO: &str = "/sysroot/ostree/repo";

/// Returns the system repository, if the host has one.
///
/// The host has one if [`SYSTEM_REPO`] exists and is a directory.
/// [`exec::run`](crate::exec::run) reads this fact for each invocation, so the
/// function checks it one time for each process and keeps the result.
pub fn system_repo() -> Option<&'static Path> {
    static DETECTED: OnceLock<Option<PathBuf>> = OnceLock::new();
    DETECTED
        .get_or_init(|| {
            let path = Path::new(SYSTEM_REPO);
            path.is_dir().then(|| path.to_path_buf())
        })
        .as_deref()
}

/// The privileges that the host gives to the running process.
#[derive(Clone, Debug)]
pub struct Host {
    /// The tier that the running process provides, by the rules of [`detect`].
    pub tier: Tier,
    /// The effective uid of the process.
    pub euid: u32,
    /// The number of supplementary groups of the process.
    pub groups: usize,
    /// The flag that is `true` if the process runs in the initial user
    /// namespace.
    pub initial_namespace: bool,
    /// The flag that is `true` if the kernel reports SELinux in enforcing
    /// state.
    pub selinux_enforcing: bool,
    /// The flag that is `true` if `unshare -r true` succeeds.
    ///
    /// If it is `true`, a new run under `unshare -r` reaches T2.
    pub namespaces_available: bool,
    /// The system repository, if the host has one.
    ///
    /// The `ostree` command resolves it as its third `--repo` source.
    pub system_repo: Option<PathBuf>,
}

impl Host {
    /// Returns one line that names the tier and the facts that give it.
    pub fn describe(&self) -> String {
        format!(
            "tier {} (euid {}, {} group(s), {} namespace, SELinux {}, {})",
            self.tier,
            self.euid,
            self.groups,
            if self.initial_namespace {
                "initial"
            } else {
                "mapped"
            },
            if self.selinux_enforcing {
                "enforcing"
            } else {
                "not enforcing"
            },
            match &self.system_repo {
                Some(path) => format!("system repo {}", path.display()),
                None => "no system repo".to_owned(),
            },
        )
    }

    /// Returns the advice of a skip with the reason `tier`.
    ///
    /// `required` is the tier that the cell needs. The advice is:
    ///
    /// - T1: `the process belongs to one group only`.
    /// - T2: if [`namespaces_available`] is `true`,
    ///   `` re-run under `unshare -r` ``, else `the host grants no user namespace`.
    /// - T3: `re-run as root`.
    /// - T4: `needs root on an SELinux-enforcing kernel`.
    /// - T0: an empty string.
    ///
    /// [`namespaces_available`]: Host::namespaces_available
    pub fn advice(&self, required: Tier) -> String {
        match required {
            Tier::T2 if self.namespaces_available => "re-run under `unshare -r`".to_owned(),
            Tier::T2 => "the host grants no user namespace".to_owned(),
            Tier::T3 => "re-run as root".to_owned(),
            Tier::T4 => "needs root on an SELinux-enforcing kernel".to_owned(),
            Tier::T1 => "the process belongs to one group only".to_owned(),
            Tier::T0 => String::new(),
        }
    }
}

/// Returns the [`Host`], with the tier that the running process provides.
///
/// A cell needs a tier: the higher of the `tier` field of its record and the
/// tier of its corpus ([`required_tier`](crate::runner::required_tier)). If a
/// cell needs a higher tier than the host provides, the cell reports a skip
/// with the reason `tier`. The cell does not fail because of a limit of the
/// host.
///
/// # Tiers
///
/// - If the effective uid is 0 in the initial user namespace, the tier is T3.
///   If SELinux also enforces, the tier is T4.
/// - If the effective uid is 0 in another user namespace, the tier is T2.
/// - If the process has more than one supplementary group, the tier is T1.
/// - Else the tier is T0.
///
/// [`Tier`] states what each tier means.
///
/// # Detection
///
/// - The initial user namespace has the `/proc/self/uid_map` line
///   `0 0 4294967295`. If the file cannot be read, the process counts as in
///   the initial namespace.
/// - If `/sys/fs/selinux/enforce` holds `1`, SELinux enforces. If the file
///   cannot be read, SELinux counts as not enforcing.
/// - If `getgroups` fails, the group count is 1.
/// - The function runs `unshare -r true` once to set
///   [`Host::namespaces_available`].
pub fn detect() -> Host {
    let euid = rustix::process::geteuid().as_raw();
    let groups = rustix::process::getgroups()
        .map(|list| list.len())
        .unwrap_or(1);
    let initial_namespace = in_initial_namespace();
    let selinux_enforcing = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|text| text.trim() == "1")
        .unwrap_or(false);

    let tier = if euid == 0 && initial_namespace {
        if selinux_enforcing {
            Tier::T4
        } else {
            Tier::T3
        }
    } else if euid == 0 {
        Tier::T2
    } else if groups > 1 {
        Tier::T1
    } else {
        Tier::T0
    };

    Host {
        tier,
        euid,
        groups,
        initial_namespace,
        selinux_enforcing,
        namespaces_available: namespaces_available(),
        system_repo: system_repo().map(Path::to_path_buf),
    }
}

/// The initial user namespace maps the whole id space onto itself.
fn in_initial_namespace() -> bool {
    let Ok(text) = std::fs::read_to_string("/proc/self/uid_map") else {
        // If procfs is absent, a root euid counts as real root. The caller
        // distinguishes only this case.
        return true;
    };
    let fields: Vec<&str> = text.split_whitespace().collect();
    fields == ["0", "0", "4294967295"]
}

/// Returns `true` if the process can enter a user namespace with a mapped
/// root.
fn namespaces_available() -> bool {
    Command::new("unshare")
        .args(["-r", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
