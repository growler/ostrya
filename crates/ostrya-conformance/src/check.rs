//! Static validation, running no binaries.
//!
//! `check` confirms the deb822 syntax, that every field name is recognized,
//! that the completeness rule in `docs/conformance/README.md` holds for each
//! family, that every placeholder in a `run:` line is bound by the record's
//! setups, that every named corpus, setup, oracle, and probe is registered,
//! and that every registered probe is named by some record.

use std::collections::{BTreeMap, BTreeSet};

use crate::corpus;
use crate::oracle;
use crate::probe;
use crate::record::{DESCRIPTIVE_FIELDS, EXECUTABLE_FIELDS, MODES, Matrix, OUTCOMES, Record, Tier};
use crate::setup;
use crate::syntax;

/// What `check` found.
pub struct Report {
    pub records: usize,
    pub cells: usize,
    pub errors: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate every record and every expanded cell.
pub fn check(matrix: &Matrix) -> Report {
    let mut errors = Vec::new();

    for record in &matrix.records {
        fields(record, &mut errors);
        vocabulary(record, &mut errors);
        outcome_fields(record, &mut errors);
        executable(record, &mut errors);
    }
    duplicates(matrix, &mut errors);
    completeness(matrix, &mut errors);
    unused_probes(matrix, &mut errors);

    Report {
        records: matrix.records.len(),
        cells: matrix.cells.len(),
        errors,
    }
}

fn fields(record: &Record, errors: &mut Vec<String>) {
    for field in &record.paragraph.fields {
        let known = DESCRIPTIVE_FIELDS.contains(&field.name.as_str())
            || EXECUTABLE_FIELDS.contains(&field.name.as_str());
        if !known {
            errors.push(format!(
                "{}:{}: field `{}` is not recognized",
                record.paragraph.file.display(),
                field.line,
                field.name
            ));
        }
    }
}

fn vocabulary(record: &Record, errors: &mut Vec<String>) {
    let origin = record.origin();

    if let Some(tier) = record.get("tier")
        && Tier::parse(tier).is_none()
    {
        errors.push(format!("{origin}: `tier: {tier}` names no tier"));
    }
    if let Some(outcome) = record.get("outcome")
        && !OUTCOMES.contains(&outcome)
    {
        errors.push(format!(
            "{origin}: `outcome: {outcome}` is not in the vocabulary"
        ));
    }
    if let Some(severity) = record.get("severity")
        && !["interop", "identity"].contains(&severity)
    {
        errors.push(format!(
            "{origin}: `severity: {severity}` is not `interop` or `identity`"
        ));
    }
    if let Some(identity) = record.get("identity")
        && !["full", "not-required", "n-a", "unobserved"].contains(&identity)
    {
        errors.push(format!(
            "{origin}: `identity: {identity}` is not in the vocabulary"
        ));
    }
    for field in ["created-by", "populated-by", "operated-by"] {
        if let Some(value) = record.get(field)
            && !["t", "p"].contains(&value)
        {
            errors.push(format!("{origin}: `{field}: {value}` is not `t` or `p`"));
        }
    }
    for mode in record
        .list("modes")
        .into_iter()
        .chain(record.list("src-mode"))
        .chain(record.list("dst-mode"))
    {
        if !MODES.contains(&mode) {
            errors.push(format!("{origin}: `{mode}` is not a repository mode"));
        }
    }
    for name in record.list("corpus") {
        if !corpus::is_registered(name) {
            errors.push(format!("{origin}: corpus `{name}` is not registered"));
        }
    }
    for name in record.list("oracle") {
        if !oracle::is_registered(name) {
            errors.push(format!("{origin}: oracle `{name}` is not registered"));
        }
    }
}

/// The outcome vocabulary in `docs/conformance/README.md` ties three outcomes
/// to a field that must accompany them: `unobserved` to `question`, `lossy`
/// to `loss`, and `unimplemented-cli` to `cli-gap`.
fn outcome_fields(record: &Record, errors: &mut Vec<String>) {
    let origin = record.origin();
    let required = match record.get("outcome") {
        Some("unobserved") => Some("question"),
        Some("lossy") => Some("loss"),
        Some("unimplemented-cli") => Some("cli-gap"),
        _ => None,
    };
    if let Some(field) = required
        && record.get(field).is_none()
    {
        errors.push(format!(
            "{origin}: `outcome: {}` needs a `{field}` field",
            record.outcome()
        ));
    }
}

fn executable(record: &Record, errors: &mut Vec<String>) {
    let origin = record.origin();

    if record.get("run").is_some() && record.get("probe").is_some() {
        errors.push(format!(
            "{origin}: a record states `run` or `probe`, not both"
        ));
    }
    if let Some(name) = record.get("probe")
        && !probe::is_registered(name)
    {
        errors.push(format!("{origin}: probe `{name}` is not registered"));
    }

    let mut bound: BTreeSet<String> = BTreeSet::new();
    bound.insert(setup::IMPLICIT.to_owned());
    for name in record.list("setup") {
        let Some(bindings) = setup::bindings_of(name) else {
            errors.push(format!("{origin}: setup `{name}` is not registered"));
            continue;
        };
        for placeholder in bindings {
            if !bound.insert((*placeholder).to_owned()) {
                errors.push(format!("{origin}: two setups bind `${placeholder}`"));
            }
        }
    }

    for field in ["run", "ref-run"] {
        let Some(line) = record.get(field) else {
            continue;
        };
        if line == "n-a" {
            continue;
        }
        match syntax::split(line) {
            Err(err) => errors.push(format!("{origin}: `{field}`: {err}")),
            Ok(arguments) if arguments.is_empty() => {
                errors.push(format!("{origin}: `{field}` names no command"));
            }
            Ok(_) => {}
        }
        match syntax::placeholders(line) {
            Err(err) => errors.push(format!("{origin}: `{field}`: {err}")),
            Ok(names) => {
                for name in names {
                    if !bound.contains(&name) {
                        errors.push(format!(
                            "{origin}: `{field}` names `${name}`, which no setup binds"
                        ));
                    }
                }
            }
        }
    }

    for field in ["expect-exit", "ref-expect-exit"] {
        if let Some(text) = record.get(field)
            && text.trim().parse::<i32>().is_err()
        {
            errors.push(format!("{origin}: `{field}: {text}` is not a number"));
        }
    }
    for field in [
        "expect-stdout",
        "expect-stderr",
        "ref-expect-stdout",
        "ref-expect-stderr",
    ] {
        if let Some(text) = record.get(field)
            && let Err(err) = syntax::parse_claim(text)
        {
            errors.push(format!("{origin}: `{field}`: {err}"));
        }
    }

    if let Some(text) = record.get("ref-may-abort") {
        if text.trim().parse::<i32>().is_err() {
            errors.push(format!(
                "{origin}: `ref-may-abort: {text}` is not a signal number"
            ));
        }
        if record.get("note").is_none() {
            errors.push(format!(
                "{origin}: `ref-may-abort` needs a `note:` recording the crash \
                 that was observed"
            ));
        }
    }

    if record.get("ref-run") == Some("n-a") {
        for field in [
            "ref-expect-exit",
            "ref-expect-stdout",
            "ref-expect-stderr",
            "ref-may-abort",
        ] {
            if record.get(field).is_some() {
                errors.push(format!(
                    "{origin}: `ref-run: n-a` leaves `{field}` with nothing to assert against"
                ));
            }
        }
    }
}

fn duplicates(matrix: &Matrix, errors: &mut Vec<String>) {
    let mut seen: BTreeMap<&str, &Record> = BTreeMap::new();
    for cell in &matrix.cells {
        let record = matrix.record(cell);
        if let Some(first) = seen.insert(&cell.id, record) {
            errors.push(format!(
                "{}: cell `{}` is also stated at {}",
                record.origin(),
                cell.id,
                first.origin()
            ));
        }
    }
}

/// Within one family, for each row key, the `modes` values cover all six modes
/// exactly once.
fn completeness(matrix: &Matrix, errors: &mut Vec<String>) {
    let mut counts: BTreeMap<(String, String), BTreeMap<String, usize>> = BTreeMap::new();
    for cell in &matrix.cells {
        if !["M0", "M1"].contains(&cell.family.as_str()) {
            continue;
        }
        let Some(mode) = &cell.mode else { continue };
        *counts
            .entry((cell.family.clone(), cell.row.clone()))
            .or_default()
            .entry(mode.clone())
            .or_insert(0) += 1;
    }

    for ((family, row), modes) in counts {
        for mode in MODES {
            match modes.get(mode).copied().unwrap_or(0) {
                1 => {}
                0 => errors.push(format!(
                    "{family} row `{row}` states no outcome for `{mode}`"
                )),
                count => errors.push(format!(
                    "{family} row `{row}` states `{mode}` {count} times"
                )),
            }
        }
    }
}

fn unused_probes(matrix: &Matrix, errors: &mut Vec<String>) {
    let named: BTreeSet<&str> = matrix
        .records
        .iter()
        .filter_map(|record| record.get("probe"))
        .collect();
    for (name, _) in probe::PROBES {
        if !named.contains(name) {
            errors.push(format!(
                "probe `{name}` is registered and no record names it"
            ));
        }
    }
}

/// Confirm every `evidence:` value that looks like a test path names a test
/// `cargo test -- --list` reports.
///
/// A value that is not a test path -- a fixture file, a document reference,
/// or a loose area reference (`crate::area`) rather than a specific test --
/// is reported as unchecked rather than as an error.
pub fn verify_evidence(
    matrix: &Matrix,
    workspace: &std::path::Path,
) -> Result<Vec<String>, String> {
    let output = std::process::Command::new("cargo")
        .current_dir(workspace)
        .args(["test", "--workspace", "--all-features", "--", "--list"])
        .output()
        .map_err(|err| format!("running cargo test --list: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo test --list exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let listing = String::from_utf8_lossy(&output.stdout).into_owned();
    let listed_functions = listed_functions(&listing);

    let mut problems = Vec::new();
    for record in &matrix.records {
        let Some(evidence) = record.get("evidence") else {
            continue;
        };
        if evidence == "-" {
            continue;
        }
        for token in split_citations(evidence) {
            let path = token.split_whitespace().next().unwrap_or(token);
            let Some(function) = test_function_name(path) else {
                continue;
            };
            if !listed_functions.contains(function) {
                problems.push(format!(
                    "{}: evidence `{path}` names no test cargo lists",
                    record.origin()
                ));
            }
        }
    }
    Ok(problems)
}

/// The bare function name of every test `cargo test -- --list` reports.
///
/// Each line is a full test name followed by `: test` or `: bench`; a unit
/// test's name carries its module path (`module::tests::function`) while an
/// integration test's does not (`function`). Reducing every listed name to
/// its own trailing segment gives one set comparable to a citation's trailing
/// segment, so a citation naming a real test's suffix as if it stood alone
/// (`commit_matches_the_tool` against the real
/// `bare_user_only_commit_matches_the_tool`) does not match: the real test's
/// own trailing segment is the whole name, not that suffix.
fn listed_functions(listing: &str) -> BTreeSet<&str> {
    listing
        .lines()
        .filter_map(|line| {
            line.strip_suffix(": test")
                .or_else(|| line.strip_suffix(": bench"))
        })
        .map(|name| name.rsplit("::").next().unwrap_or(name))
        .collect()
}

/// Split an `evidence:` value on the commas that separate citations, leaving
/// a comma inside a parenthetical remark alone.
fn split_citations(evidence: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (index, ch) in evidence.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(evidence[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(evidence[start..].trim());
    parts
}

/// The bare function name a test-path citation names, or `None` when `path`
/// is not a test path.
///
/// A test path has at least two `::` separators: `crate::file::function` for
/// an integration test, `crate::module::function` for a unit test. A single
/// `::` (`crate::area`, as in `ostrya::read_modes`) names an area, not one
/// test, and is not a path to verify. `cargo test -- --list` always ends a
/// test's name at the function, whether or not the crate's own module path
/// leads up to it, so matching the trailing segment covers both shapes.
fn test_function_name(path: &str) -> Option<&str> {
    let looks_like_a_test = path.matches("::").count() >= 2
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':');
    looks_like_a_test.then(|| path.rsplit("::").next().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deb822::{Field, Paragraph};
    use crate::record::Cell;
    use std::path::PathBuf;

    fn record(fields: &[(&str, &str)]) -> Record {
        Record {
            paragraph: Paragraph {
                file: PathBuf::from("t"),
                line: 1,
                fields: fields
                    .iter()
                    .map(|(name, value)| Field {
                        name: (*name).to_owned(),
                        value: (*value).to_owned(),
                        line: 1,
                    })
                    .collect(),
            },
        }
    }

    #[test]
    fn a_duplicate_cell_id_is_reported() {
        let matrix = Matrix {
            dir: PathBuf::from("t"),
            records: vec![record(&[("family", "M10")]), record(&[("family", "M10")])],
            cells: vec![
                Cell {
                    id: "m10/x".to_owned(),
                    family: "M10".to_owned(),
                    row: "x".to_owned(),
                    mode: None,
                    corpus: None,
                    op: None,
                    record: 0,
                },
                Cell {
                    id: "m10/x".to_owned(),
                    family: "M10".to_owned(),
                    row: "x".to_owned(),
                    mode: None,
                    corpus: None,
                    op: None,
                    record: 1,
                },
            ],
        };
        let mut errors = Vec::new();
        duplicates(&matrix, &mut errors);
        assert_eq!(
            errors,
            vec!["t:1: cell `m10/x` is also stated at t:1".to_owned()]
        );
    }

    #[test]
    fn completeness_flags_a_mode_missing_from_a_row() {
        let present = [
            "archive",
            "bare",
            "bare-user",
            "bare-user-only",
            "bare-user-shared",
        ];
        let matrix = Matrix {
            dir: PathBuf::from("t"),
            records: vec![record(&[("family", "M0")])],
            cells: present
                .iter()
                .map(|mode| Cell {
                    id: format!("m0/C0/{mode}"),
                    family: "M0".to_owned(),
                    row: "C0".to_owned(),
                    mode: Some((*mode).to_owned()),
                    corpus: Some("C0".to_owned()),
                    op: None,
                    record: 0,
                })
                .collect(),
        };
        let mut errors = Vec::new();
        completeness(&matrix, &mut errors);
        assert_eq!(
            errors,
            vec!["M0 row `C0` states no outcome for `bare-split-xattrs`".to_owned()]
        );
    }

    #[test]
    fn executable_flags_an_unbound_placeholder() {
        let record = record(&[("run", "ostrya init --repo=$NOPE")]);
        let mut errors = Vec::new();
        executable(&record, &mut errors);
        assert_eq!(
            errors,
            vec![format!(
                "{}: `run` names `$NOPE`, which no setup binds",
                record.origin()
            )]
        );
    }

    #[test]
    fn a_crash_tolerance_without_a_note_is_reported() {
        let record = record(&[("run", "ostrya refs"), ("ref-may-abort", "6")]);
        let mut errors = Vec::new();
        executable(&record, &mut errors);
        assert_eq!(
            errors,
            vec![format!(
                "{}: `ref-may-abort` needs a `note:` recording the crash that \
                 was observed",
                record.origin()
            )]
        );
    }

    #[test]
    fn a_crash_tolerance_naming_no_signal_is_reported() {
        let record = record(&[
            ("run", "ostrya refs"),
            ("ref-may-abort", "sigabrt"),
            ("note", "observed"),
        ]);
        let mut errors = Vec::new();
        executable(&record, &mut errors);
        assert_eq!(
            errors,
            vec![format!(
                "{}: `ref-may-abort: sigabrt` is not a signal number",
                record.origin()
            )]
        );
    }

    #[test]
    fn unused_probes_are_reported() {
        let records: Vec<Record> = probe::PROBES
            .into_iter()
            .skip(1)
            .map(|(name, _)| record(&[("probe", name)]))
            .collect();
        let matrix = Matrix {
            dir: PathBuf::from("t"),
            records,
            cells: Vec::new(),
        };
        let mut errors = Vec::new();
        unused_probes(&matrix, &mut errors);
        let (expected, _) = probe::PROBES[0];
        assert_eq!(
            errors,
            vec![format!(
                "probe `{expected}` is registered and no record names it"
            )]
        );
    }

    #[test]
    fn outcome_fields_requires_the_correlated_field() {
        let mut errors = Vec::new();
        outcome_fields(&record(&[("outcome", "lossy")]), &mut errors);
        assert_eq!(
            errors,
            vec!["t:1: `outcome: lossy` needs a `loss` field".to_owned()]
        );
    }

    #[test]
    fn outcome_fields_passes_when_the_correlated_field_is_present() {
        let mut errors = Vec::new();
        outcome_fields(
            &record(&[("outcome", "lossy"), ("loss", "xattr order")]),
            &mut errors,
        );
        assert!(errors.is_empty());
    }

    #[test]
    fn a_citation_matching_a_real_tests_suffix_is_still_flagged() {
        // `commit_matches_the_tool` never names a test on its own; the only
        // real test that shares those trailing characters is
        // `bare_user_only_commit_matches_the_tool`, a different, whole name.
        let functions = listed_functions("bare_user_only_commit_matches_the_tool: test\n");
        assert!(!functions.contains("commit_matches_the_tool"));
        assert!(functions.contains("bare_user_only_commit_matches_the_tool"));
    }

    #[test]
    fn listed_functions_strips_a_unit_tests_module_path() {
        let functions = listed_functions("bspatch::tests::offtin_sign_magnitude: test\n");
        assert!(functions.contains("offtin_sign_magnitude"));
        assert!(!functions.contains("bspatch::tests::offtin_sign_magnitude"));
    }

    #[test]
    fn test_function_name_takes_the_trailing_segment_of_a_test_path() {
        assert_eq!(
            test_function_name("ostrya::write::archive_objects_are_byte_identical_to_the_fixture"),
            Some("archive_objects_are_byte_identical_to_the_fixture")
        );
    }

    #[test]
    fn test_function_name_ignores_a_loose_area_reference() {
        assert_eq!(test_function_name("ostrya::read_modes"), None);
    }

    #[test]
    fn split_citations_keeps_a_comma_inside_a_parenthetical_together() {
        assert_eq!(
            split_citations(
                "ostrya::commit (cross-mode commit identity across archive, bare-user, and bare-user-shared)"
            ),
            vec![
                "ostrya::commit (cross-mode commit identity across archive, bare-user, and bare-user-shared)"
            ]
        );
    }

    #[test]
    fn split_citations_splits_top_level_commas() {
        assert_eq!(
            split_citations("ostrya::summary, ostrya::delta_generate, ostrya::sign (partial, on)"),
            vec![
                "ostrya::summary",
                "ostrya::delta_generate",
                "ostrya::sign (partial, on)"
            ]
        );
    }
}
