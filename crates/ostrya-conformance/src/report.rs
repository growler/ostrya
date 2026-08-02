//! The output formats, and the `report` subcommand that renders a JSON
//! document as the per-family mode grids.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::check;
use crate::json::Json;
use crate::record::{MODES, Matrix, Tier};
use crate::runner::{self, CellResult, OracleStatus, Verdict};
use crate::tier::Host;

/// Which format to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Human,
    Tap,
    Json,
}

impl Format {
    pub fn parse(text: &str) -> Option<Format> {
        match text {
            "human" => Some(Format::Human),
            "tap" => Some(Format::Tap),
            "json" => Some(Format::Json),
            _ => None,
        }
    }
}

/// What the run itself recorded, for the report header.
pub struct RunInfo {
    pub artifact_dir: String,
    pub port: String,
    pub reference: Option<String>,
    pub host: Host,
}

/// Render a completed run.
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
    // A cell the selection excluded is counted in the summary and not listed.
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

    // The privilege gate is the one skip reason the operator can lift, so the
    // summary states what lifting it needs.
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

/// How many skipped cells each tier above the host's gates.
///
/// A cell whose tier skip a `--require` flag promoted is a failure, not a
/// skip, so it is counted with the failures and not here.
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

/// Render the result of `check`.
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

/// Render a `check --format json` or `run --format json` document as the
/// per-family mode grids.
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

/// A grid entry: the verdict when the document holds one, else the declared
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
