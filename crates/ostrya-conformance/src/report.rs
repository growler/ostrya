//! The output formats of a check and of a run, and the mode grids.
//!
//! [`run_report`] and [`check_report`] render a result in a [`Format`].
//! [`grids`] renders a JSON document as one mode grid for each family.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::check;
use crate::json::Json;
use crate::record::{MODES, Matrix, Tier};
use crate::runner::{self, CellResult, OracleStatus, Verdict};
use crate::tier::Host;

/// The output format of a report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Text for a human reader.
    Human,
    /// TAP version 13.
    Tap,
    /// One JSON document.
    Json,
}

impl Format {
    /// Returns the format that `text` names, or `None` for an unknown name.
    ///
    /// The names are `human`, `tap`, and `json`.
    pub fn parse(text: &str) -> Option<Format> {
        match text {
            "human" => Some(Format::Human),
            "tap" => Some(Format::Tap),
            "json" => Some(Format::Json),
            _ => None,
        }
    }
}

/// The facts of a run for the report header.
pub struct RunInfo {
    /// The directory where the run wrote its artifacts.
    pub artifact_dir: String,
    /// The `ostrya` binary of the run.
    pub port: String,
    /// The `ostree` command of the run, if the run found one.
    pub reference: Option<String>,
    /// The privileges that the host gave the run.
    pub host: Host,
}

/// Returns the report of a completed run in `format`.
///
/// The human format holds:
///
/// - A header with the host, the `ostrya` binary, the `ostree` command (or
///   `absent`), and the artifact directory.
/// - One line for each cell, by family, with its verdict and its reason or
///   the first line of its detail.
/// - The full detail and the artifact directory of each failed cell.
/// - A summary with the count of each verdict and of each skip reason.
///
/// The cell lines omit each cell with a skip of the reason `filtered`, and the
/// summary counts it. For each tier that gates a cell, the summary also gives
/// the [`Host::advice`].
///
/// The TAP format has one test point for each cell. A skip is `ok`, with a
/// `# SKIP` directive and the reason. The JSON format holds the facts of the
/// run, one object for each cell, and the summary counts.
pub fn run_report(results: &[CellResult], info: &RunInfo, format: Format) -> String {
    match format {
        Format::Human => run_human(results, info),
        Format::Tap => run_tap(results),
        Format::Json => run_json(results, info).render(),
    }
}

fn run_human(results: &[CellResult], info: &RunInfo) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "host: {}", info.host.describe());
    let _ = writeln!(out, "port: {}", info.port);
    let _ = writeln!(
        out,
        "reference: {}",
        info.reference.as_deref().unwrap_or("absent")
    );
    let _ = writeln!(out, "artifacts: {}", info.artifact_dir);
    out.push('\n');

    let mut family = String::new();
    let width = results
        .iter()
        .map(|result| result.id.chars().count())
        .max()
        .unwrap_or(0)
        .max(20);
    // The summary counts a cell that the selection excluded. The list omits it.
    for result in results
        .iter()
        .filter(|result| result.reason.as_deref() != Some("filtered"))
    {
        if result.family != family {
            family.clone_from(&result.family);
            let _ = writeln!(out, "{family}");
        }
        let tail = match (result.verdict, &result.reason, &result.detail) {
            (Verdict::Fail, _, Some(detail)) => format!("  {}", first_line(detail)),
            (_, Some(reason), Some(detail)) => format!("  {reason}: {}", first_line(detail)),
            (_, Some(reason), None) => format!("  {reason}"),
            _ => String::new(),
        };
        let _ = writeln!(
            out,
            "  {:<width$}  {}{tail}",
            result.id,
            result.verdict.as_str(),
            width = width
        );
    }

    let failures: Vec<&CellResult> = results
        .iter()
        .filter(|result| result.verdict == Verdict::Fail)
        .collect();
    if !failures.is_empty() {
        out.push('\n');
        for result in &failures {
            let _ = writeln!(out, "FAIL {}", result.id);
            for line in result.detail.as_deref().unwrap_or("").lines() {
                let _ = writeln!(out, "  {line}");
            }
            if let Some(path) = &result.artifact {
                let _ = writeln!(out, "  artifacts: {}", path.display());
            }
        }
    }

    out.push('\n');
    out.push_str(&summary_text(results, &info.host));
    out
}

fn summary_text(results: &[CellResult], host: &Host) -> String {
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
    for result in results {
        match result.verdict {
            Verdict::Pass => passed += 1,
            Verdict::Fail => failed += 1,
            Verdict::Skip => {
                skipped += 1;
                *reasons
                    .entry(result.reason.as_deref().unwrap_or("unstated"))
                    .or_insert(0) += 1;
            }
        }
    }

    let gated = tier_gated(results);
    let mut out = format!(
        "{} cells: {passed} pass, {failed} fail, {skipped} skip\n",
        results.len()
    );
    for (reason, count) in reasons {
        if reason == "tier" {
            let breakdown: Vec<String> = gated
                .iter()
                .map(|(tier, count)| format!("{tier} {count}"))
                .collect();
            let _ = writeln!(out, "  skip tier: {count} ({})", breakdown.join(", "));
        } else {
            let _ = writeln!(out, "  skip {reason}: {count}");
        }
    }

    // The tier gate is the only skip reason that the operator can remove, so
    // the summary states what the removal needs.
    for (tier, count) in &gated {
        let _ = writeln!(
            out,
            "{count} cell(s) need {tier}, above this host's {}: {}",
            host.tier,
            host.advice(*tier)
        );
    }
    out
}

/// Returns the number of cells with a skip of the reason `tier`, for each
/// required tier.
///
/// If a `--require` flag promotes a tier skip, the cell is a failure. The
/// count of failures holds it, and this count does not.
fn tier_gated(results: &[CellResult]) -> Vec<(Tier, usize)> {
    let mut counts: BTreeMap<Tier, usize> = BTreeMap::new();
    for result in results.iter().filter(|result| {
        result.verdict == Verdict::Skip && result.reason.as_deref() == Some("tier")
    }) {
        *counts.entry(result.required_tier).or_insert(0) += 1;
    }
    counts.into_iter().collect()
}

fn run_tap(results: &[CellResult]) -> String {
    let mut out = String::from("TAP version 13\n");
    let _ = writeln!(out, "1..{}", results.len());
    for (index, result) in results.iter().enumerate() {
        let number = index + 1;
        match result.verdict {
            Verdict::Pass => {
                let _ = writeln!(out, "ok {number} - {}", result.id);
            }
            Verdict::Skip => {
                let _ = writeln!(
                    out,
                    "ok {number} - {} # SKIP {}",
                    result.id,
                    result.reason.as_deref().unwrap_or("unstated")
                );
            }
            Verdict::Fail => {
                let _ = writeln!(out, "not ok {number} - {}", result.id);
                let _ = writeln!(out, "  ---");
                for line in result.detail.as_deref().unwrap_or("").lines() {
                    let _ = writeln!(out, "  message: {line}");
                }
                if let Some(path) = &result.artifact {
                    let _ = writeln!(out, "  artifacts: {}", path.display());
                }
                let _ = writeln!(out, "  ...");
            }
        }
    }
    out
}

fn run_json(results: &[CellResult], info: &RunInfo) -> Json {
    let cells: Vec<Json> = results
        .iter()
        .map(|result| {
            Json::object(vec![
                ("id", Json::string(&result.id)),
                ("family", Json::string(&result.family)),
                ("row", Json::string(&result.row)),
                (
                    "mode",
                    result.mode.as_ref().map_or(Json::Null, Json::string),
                ),
                ("outcome", Json::string(&result.outcome)),
                ("severity", Json::string(&result.severity)),
                ("tier", Json::string(result.required_tier.to_string())),
                ("verdict", Json::string(result.verdict.as_str())),
                (
                    "reason",
                    result.reason.as_ref().map_or(Json::Null, Json::string),
                ),
                (
                    "detail",
                    result.detail.as_ref().map_or(Json::Null, Json::string),
                ),
                (
                    "oracles",
                    Json::Array(
                        result
                            .oracles
                            .iter()
                            .map(|(name, status)| {
                                Json::object(vec![
                                    ("name", Json::string(name)),
                                    ("status", Json::string(status.as_str())),
                                    (
                                        "reason",
                                        match status {
                                            OracleStatus::Unavailable(reason) => {
                                                Json::string(reason)
                                            }
                                            _ => Json::Null,
                                        },
                                    ),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "notes",
                    Json::Array(result.notes.iter().map(Json::string).collect()),
                ),
                (
                    "artifact",
                    result
                        .artifact
                        .as_ref()
                        .map_or(Json::Null, |path| Json::string(path.display().to_string())),
                ),
                ("elapsed-ms", Json::Int(result.elapsed_ms as i64)),
            ])
        })
        .collect();

    let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
    let mut passed = 0i64;
    let mut failed = 0i64;
    let mut skipped = 0i64;
    for result in results {
        match result.verdict {
            Verdict::Pass => passed += 1,
            Verdict::Fail => failed += 1,
            Verdict::Skip => {
                skipped += 1;
                *reasons
                    .entry(result.reason.as_deref().unwrap_or("unstated"))
                    .or_insert(0) += 1;
            }
        }
    }

    Json::object(vec![
        (
            "run",
            Json::object(vec![
                ("artifact-dir", Json::string(&info.artifact_dir)),
                ("port", Json::string(&info.port)),
                (
                    "reference",
                    info.reference.as_ref().map_or(Json::Null, Json::string),
                ),
                ("host-tier", Json::string(info.host.tier.to_string())),
            ]),
        ),
        ("cells", Json::Array(cells)),
        (
            "summary",
            Json::object(vec![
                ("total", Json::Int(results.len() as i64)),
                ("pass", Json::Int(passed)),
                ("fail", Json::Int(failed)),
                ("skip", Json::Int(skipped)),
                (
                    "skip-reasons",
                    Json::Object(
                        reasons
                            .into_iter()
                            .map(|(reason, count)| (reason.to_owned(), Json::Int(count as i64)))
                            .collect(),
                    ),
                ),
                (
                    "tier-gated",
                    Json::Object(
                        tier_gated(results)
                            .into_iter()
                            .map(|(tier, count)| (tier.to_string(), Json::Int(count as i64)))
                            .collect(),
                    ),
                ),
            ]),
        ),
    ])
}

/// Returns the report of [`check::check`] in `format`.
///
/// The human format holds one `error:` line for each error, and a summary line
/// with the counts of records, cells, and errors. The TAP format has one test
/// point. The JSON format holds one object for each cell, the summary counts,
/// and the errors.
pub fn check_report(matrix: &Matrix, report: &check::Report, format: Format) -> String {
    match format {
        Format::Human => {
            let mut out = String::new();
            for error in &report.errors {
                let _ = writeln!(out, "error: {error}");
            }
            let _ = writeln!(
                out,
                "{} records, {} cells, {} error(s)",
                report.records,
                report.cells,
                report.errors.len()
            );
            out
        }
        Format::Tap => {
            let mut out = String::from("TAP version 13\n1..1\n");
            if report.errors.is_empty() {
                let _ = writeln!(
                    out,
                    "ok 1 - static validation ({} records, {} cells)",
                    report.records, report.cells
                );
            } else {
                let _ = writeln!(out, "not ok 1 - static validation");
                let _ = writeln!(out, "  ---");
                for error in &report.errors {
                    let _ = writeln!(out, "  message: {error}");
                }
                let _ = writeln!(out, "  ...");
            }
            out
        }
        Format::Json => check_json(matrix, report).render(),
    }
}

fn check_json(matrix: &Matrix, report: &check::Report) -> Json {
    let cells: Vec<Json> = matrix
        .cells
        .iter()
        .map(|cell| {
            let record = matrix.record(cell);
            Json::object(vec![
                ("id", Json::string(&cell.id)),
                ("family", Json::string(&cell.family)),
                ("row", Json::string(&cell.row)),
                ("mode", cell.mode.as_ref().map_or(Json::Null, Json::string)),
                ("outcome", Json::string(record.outcome())),
                ("severity", Json::string(record.severity())),
                (
                    "tier",
                    Json::string(runner::required_tier(cell, record).to_string()),
                ),
                ("verdict", Json::Null),
                ("executable", Json::Bool(record.is_executable())),
            ])
        })
        .collect();

    Json::object(vec![
        ("cells", Json::Array(cells)),
        (
            "summary",
            Json::object(vec![
                ("records", Json::Int(report.records as i64)),
                ("total", Json::Int(report.cells as i64)),
                ("errors", Json::Int(report.errors.len() as i64)),
            ]),
        ),
        (
            "errors",
            Json::Array(report.errors.iter().map(Json::string).collect()),
        ),
    ])
}

/// Returns the mode grids of a JSON document, one grid for each family.
///
/// The document is the output of `check --format json` or
/// `run --format json`. The result is Markdown text:
///
/// - A family with no mode in its cells gets a list of its cells.
/// - Each other family gets a table with one table row for each `row` value
///   and one column for each mode of [`MODES`]. A cell that is absent shows
///   `--`.
///
/// A grid entry is the verdict of the cell, with its reason if it has one, and
/// the declared outcome. If the cell has no verdict, the entry is the declared
/// outcome.
///
/// # Errors
///
/// - An error if the document has no `cells` member.
/// - An error if `cells` is empty or is not an array.
pub fn grids(document: &Json) -> Result<String, String> {
    let cells = document
        .get("cells")
        .ok_or_else(|| "the document holds no `cells` array".to_owned())?
        .as_array();
    if cells.is_empty() {
        return Err("the document's `cells` array is empty".to_owned());
    }

    let mut families: Vec<String> = Vec::new();
    for cell in cells {
        let family = cell
            .get("family")
            .map(Json::as_str)
            .unwrap_or("")
            .to_owned();
        if !families.contains(&family) {
            families.push(family);
        }
    }

    let mut out = String::from("# Conformance matrix\n");
    for family in families {
        let members: Vec<&Json> = cells
            .iter()
            .filter(|cell| cell.get("family").map(Json::as_str) == Some(family.as_str()))
            .collect();
        let _ = write!(out, "\n## {family}\n\n");
        if members
            .iter()
            .all(|cell| matches!(cell.get("mode"), None | Some(Json::Null)))
        {
            for cell in members {
                let _ = writeln!(
                    out,
                    "- `{}` -- {}",
                    cell.get("id").map(Json::as_str).unwrap_or(""),
                    state(cell)
                );
            }
            continue;
        }

        let mut rows: Vec<String> = Vec::new();
        let mut states: BTreeMap<(String, String), String> = BTreeMap::new();
        for cell in members {
            let row = cell.get("row").map(Json::as_str).unwrap_or("").to_owned();
            let mode = cell.get("mode").map(Json::as_str).unwrap_or("").to_owned();
            if !rows.contains(&row) {
                rows.push(row.clone());
            }
            states.insert((row, mode), state(cell));
        }

        let _ = writeln!(out, "| | {} |", MODES.join(" | "));
        let _ = writeln!(out, "| --- |{}", " --- |".repeat(MODES.len()));
        for row in rows {
            let _ = write!(out, "| {row} |");
            for mode in MODES {
                let value = states
                    .get(&(row.clone(), mode.to_owned()))
                    .cloned()
                    .unwrap_or_else(|| "--".to_owned());
                let _ = write!(out, " {value} |");
            }
            out.push('\n');
        }
    }
    Ok(out)
}

/// Returns a grid entry: the verdict if the cell has one, else the declared
/// outcome.
fn state(cell: &Json) -> String {
    let outcome = cell.get("outcome").map(Json::as_str).unwrap_or("");
    match cell.get("verdict") {
        None | Some(Json::Null) => outcome.to_owned(),
        Some(verdict) => {
            let reason = cell.get("reason").map(Json::as_str).unwrap_or("");
            if reason.is_empty() {
                format!("{} ({outcome})", verdict.as_str())
            } else {
                format!("{} {reason} ({outcome})", verdict.as_str())
            }
        }
    }
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or("")
}
