#![forbid(unsafe_code)]

//! The runner of the conformance matrix of `ostrya` and the `ostree` command.
//!
//! Each record of a matrix directory expands into cells. A cell runs the
//! `ostrya` binary and the `ostree` command as subprocesses and compares what
//! they did. If a run cannot observe a cell, the cell reports a skip with the reason.
//!
//! # Entry points
//!
//! - [`record::load`] reads a matrix directory, and [`default_matrix_dir`] names the default.
//! - [`check::check`] checks the records and runs no binary.
//! - [`runner::run`] runs the cells, and [`report::run_report`] renders the results.
//! - [`observe::observe`] runs the `ostree` command alone and prints a record skeleton.
//! - [`t0_gate`] runs the T0 cells in a cargo test.
//!
//! # Modules
//!
//! - [`check`]: the static check of the record files.
//! - [`corpus`]: the source trees that the cells commit.
//! - [`deb822`]: the paragraph format of the record files.
//! - [`exec`]: the resolution and the run of the two implementations.
//! - [`json`]: the JSON document of `--format json`.
//! - [`observe`]: the observation of the `ostree` command alone.
//! - [`oracle`]: the comparison of the state that each implementation leaves after a run.
//! - [`probe`]: the cells that a `run:` line cannot state.
//! - [`record`]: the record vocabulary and the expansion of a record into cells.
//! - [`report`]: the output formats and the mode grids.
//! - [`runner`]: the run of the cells and their verdicts.
//! - [`setup`]: the start state of a cell and the placeholders that it binds.
//! - [`sha256`]: the SHA-256 digest of the `manifest` oracle.
//! - [`syntax`]: the grammar of a `run:` line and of an `expect-*` claim.
//! - [`tier`]: the privilege tier of the host.
//!
//! # Examples
//!
//! ```no_run
//! use ostrya_conformance::{check, default_matrix_dir, record};
//! let matrix = record::load(&default_matrix_dir())?;
//! assert!(check::check(&matrix).ok());
//! # Ok::<(), String>(())
//! ```

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

/// Returns the matrix directory that a run reads by default.
///
/// The directory is the first of these:
///
/// - The value of `OSTRYA_MATRIX_DIR`, if it is set.
/// - `docs/conformance` in the workspace that this crate was built in, if it
///   is a directory.
/// - `docs/conformance`, relative to the current directory.
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

/// Returns `path` as an absolute path, relative to the current directory.
///
/// Each invocation runs in the scratch directory of a cell, so a relative
/// artifact path resolves against the wrong directory there. If the current
/// directory cannot be read, the function returns `path` unchanged.
pub fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|dir| dir.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// Returns the root of the workspace that this crate was built in.
///
/// The path comes from the build, so it names a directory of the build host.
pub fn workspace_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Returns an identifier for a run, from the current UTC time.
///
/// The form is `YYYYmmdd-HHMMSS`. The binary writes the artifacts of a run to
/// `target/conformance/<run-id>` by default. If the clock is before 1970, the
/// identifier is `19700101-000000`.
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

/// Returns the proleptic Gregorian date `days` after 1970-01-01.
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

/// The result of [`t0_gate`].
pub struct Gate {
    /// The result of each cell of the matrix, in matrix order.
    ///
    /// A cell that does not need T0 has a skip with the reason `filtered`.
    pub results: Vec<runner::CellResult>,
    /// The report of the run, in the human format.
    pub text: String,
    /// The flag that is `true` if a failure gates the run.
    ///
    /// [`runner::gating_failure`] decides it, with no `--strict-identity`. A
    /// failure of a cell with the severity `identity` does not set it.
    pub failed: bool,
}

/// Runs the T0 cells of the default matrix against the `ostrya` binary at `port`.
///
/// A cargo test target of `ostrya-cli` calls this function, so `cargo test`
/// runs the T0 cells. The cells of a higher tier run with the
/// `ostrya-conformance` binary. At T2 to T4, it runs under `unshare -r` or as
/// root.
///
/// # Run
///
/// - The matrix is [`default_matrix_dir`].
/// - The `ostree` command is the file that `OSTREE_BIN` names, else the first
///   executable `ostree` in `PATH`. [`exec::resolve`] states the rule. If no
///   command resolves, each cell that needs it reports a skip with the reason
///   `reference-absent`.
/// - The cells run on as many threads as [`available_parallelism`] gives.
/// - The run writes the artifacts to `artifact_dir`, as an absolute path. It
///   removes the artifacts of a cell that passes.
///
/// # Errors
///
/// - An error from [`record::load`] if the matrix does not load.
/// - An error if `port` is not an executable file.
/// - An error with the text of [`exec::locale_codeset_defect`] if an `ostree`
///   command resolves and [`exec::LOCALE`] has no UTF-8 codeset on the host.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// let port = Path::new("target/debug/ostrya");
/// let gate = ostrya_conformance::t0_gate(port, Path::new("target/conformance/t0"))?;
/// assert!(!gate.failed, "{}", gate.text);
/// # Ok::<(), String>(())
/// ```
///
/// [`available_parallelism`]: std::thread::available_parallelism
pub fn t0_gate(port: &Path, artifact_dir: &Path) -> Result<Gate, String> {
    let artifact_dir = absolute(artifact_dir);
    let matrix = record::load(&default_matrix_dir())?;
    let port = exec::resolve("port", Some(port), "OSTRYA_BIN", "ostrya")
        .ok_or_else(|| format!("{} is not an executable file", port.display()))?;
    let reference = exec::resolve("reference", None, "OSTREE_BIN", "ostree");
    // Only the reference converts its messages through the locale, so a run
    // without one is unaffected.
    if reference.is_some()
        && let Some(defect) = exec::locale_codeset_defect()
    {
        return Err(defect);
    }

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
