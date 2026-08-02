#![forbid(unsafe_code)]

//! The runner for the interoperability conformance matrix.
//!
//! `docs/conformance/README.md` defines the matrix: the custody axes, the
//! outcome vocabulary, the corpora, and the privilege tiers.
//! `docs/conformance/harness.md` defines this program: the record is the
//! program, a verdict states what the run observed, and a cell the run could
//! not observe reports as skipped with the reason. Conformance is reported
//! only when both implementations ran and their observations agreed.
//!
//! The crate links neither implementation. It drives the `ostrya` and
//! `ostree` binaries as subprocesses, so it observes the surface a user
//! observes.
//!
//! The library exists so the cargo test targets can call the same code the
//! binary calls; the binary runs standalone, because cells at tiers T2
//! through T4 run under `unshare -r` or as root on a machine that holds no
//! cargo installation and no source tree.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod check;
pub mod corpus;
pub mod deb822;
pub mod exec;
pub mod json;
pub mod observe;
pub mod oracle;
pub mod probe;
pub mod record;
pub mod report;
pub mod runner;
pub mod setup;
pub mod sha256;
pub mod syntax;
pub mod tier;

/// The record directory this crate was built beside.
pub fn default_matrix_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("OSTRYA_MATRIX_DIR") {
        return PathBuf::from(dir);
    }
    let beside = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/conformance");
    if beside.is_dir() {
        return beside;
    }
    PathBuf::from("docs/conformance")
}

/// `path` made absolute against the current directory.
///
/// Every invocation runs in a cell's scratch directory, so a relative
/// artifact path would resolve against the wrong root.
pub fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|dir| dir.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// The workspace root this crate was built in.
pub fn workspace_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The run identifier the default artifact directory carries:
/// `YYYYmmdd-HHMMSS`, in UTC.
pub fn run_id() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        time / 3_600,
        (time % 3_600) / 60,
        time % 60
    )
}

/// The proleptic Gregorian date `days` after 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The result of the workspace test gate.
pub struct Gate {
    pub results: Vec<runner::CellResult>,
    pub text: String,
    pub failed: bool,
}

/// Run every cell the host's tier admits at T0, with `port` as the port
/// handle and the reference resolved from `OSTREE_BIN` or `PATH`.
///
/// This is what `crates/ostrya-cli/tests/conformance.rs` calls, so the
/// workspace test run gates on the matrix with no workflow change.
pub fn t0_gate(port: &Path, artifact_dir: &Path) -> Result<Gate, String> {
    let artifact_dir = absolute(artifact_dir);
    let matrix = record::load(&default_matrix_dir())?;
    let port = exec::resolve("port", Some(port), "OSTRYA_BIN", "ostrya")
        .ok_or_else(|| format!("{} is not an executable file", port.display()))?;
    let reference = exec::resolve("reference", None, "OSTREE_BIN", "ostree");

    let options = runner::Options {
        port: port.clone(),
        reference: reference.clone(),
        artifact_dir: artifact_dir.clone(),
        keep: false,
        jobs: std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1),
        filters: runner::Filters {
            tier: Some(record::Tier::T0),
            ..runner::Filters::default()
        },
        require_tool: false,
        require_tier: None,
        strict_identity: false,
        host: tier::detect(),
    };
    let results = runner::run(&matrix, &options);
    let info = report::RunInfo {
        artifact_dir: artifact_dir.display().to_string(),
        port: port.path.display().to_string(),
        reference: reference.map(|tool| tool.path.display().to_string()),
        host: options.host.clone(),
    };
    let text = report::run_report(&results, &info, report::Format::Human);
    let failed = runner::gating_failure(&results, false);
    Ok(Gate {
        results,
        text,
        failed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_renders_as_its_date() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_000), (2022, 1, 8));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }
}
