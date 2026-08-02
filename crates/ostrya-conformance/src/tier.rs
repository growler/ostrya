//! Privilege-tier detection.
//!
//! `docs/conformance/README.md` defines the tiers. A tier is a property of the
//! (mode, corpus) pair a cell names; this module reports the tier the running
//! process provides, so a cell needing more reports as skipped rather than
//! failing for a reason the host caused.

use std::process::{Command, Stdio};

use crate::record::Tier;

/// What the host grants the running process.
#[derive(Clone, Debug)]
pub struct Host {
    pub tier: Tier,
    pub euid: u32,
    pub groups: usize,
    /// Whether the process runs in the initial user namespace.
    pub initial_namespace: bool,
    /// Whether the kernel reports SELinux in enforcing state.
    pub selinux_enforcing: bool,
    /// Whether `unshare -r true` succeeds, so T2 is reachable by re-running.
    pub namespaces_available: bool,
}

impl Host {
    /// One line naming the tier and the reason it is that tier.
    pub fn describe(&self) -> String {
        format!(
            "tier {} (euid {}, {} group(s), {} namespace, SELinux {})",
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
        )
    }

    /// The advice a `skip: tier` report carries.
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

/// Detect the host's tier.
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
    }
}

/// The initial user namespace maps the whole id space onto itself.
fn in_initial_namespace() -> bool {
    let Ok(text) = std::fs::read_to_string("/proc/self/uid_map") else {
        // No procfs: treat a root euid as real root, which is the only case
        // the caller distinguishes.
        return true;
    };
    let fields: Vec<&str> = text.split_whitespace().collect();
    fields == ["0", "0", "4294967295"]
}

/// Whether a user namespace with a mapped root can be entered.
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
