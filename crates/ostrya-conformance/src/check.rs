//! The static check of the record files, which runs no binary.
//!
//! [`check`] checks a matrix and returns a [`Report`]. [`verify_evidence`]
//! checks the `evidence:` values against the tests that cargo lists.

use std::collections::{BTreeMap, BTreeSet};

use crate::corpus;
use crate::oracle;
use crate::probe;
use crate::record::{DESCRIPTIVE_FIELDS, EXECUTABLE_FIELDS, MODES, Matrix, OUTCOMES, Record, Tier};
use crate::setup;
use crate::syntax;

/// The result of [`check`].
pub struct Report {
    /// The number of records in the matrix files.
    pub records: usize,
    /// The number of cells that the records expand into.
    pub cells: usize,
    /// One message for each rule violation.
    pub errors: Vec<String>,
}

impl Report {
    /// Returns `true` if the check found no rule violation.
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Checks every record and every expanded cell of a matrix.
///
/// The check runs no binary. It adds one message to [`Report::errors`] for
/// each rule violation. [`record::load`](crate::record::load) checks the
/// deb822 syntax before this function gets the matrix.
///
/// # Checks
///
/// The rules for the fields and their values:
///
/// - Each field name is in [`DESCRIPTIVE_FIELDS`] or [`EXECUTABLE_FIELDS`].
/// - `tier` names a [`Tier`]. `outcome` is in [`OUTCOMES`].
/// - `severity` is `interop` or `identity`.
/// - `identity` is `full`, `not-required`, `n-a`, or `unobserved`.
/// - `created-by`, `populated-by`, and `operated-by` are `t` or `p`.
/// - Each value of `modes`, `src-mode`, and `dst-mode` is in [`MODES`].
/// - Each corpus that a record names is in [`CORPORA`](corpus::CORPORA), and
///   each oracle is in [`ORACLES`](oracle::ORACLES).
/// - Each setup that a record names is in [`SETUPS`](setup::SETUPS), and the
///   probe is in [`PROBES`](probe::PROBES).
///
/// The rules for the outcome:
///
/// - `outcome: unobserved` needs a `question` field.
/// - `outcome: lossy` needs a `loss` field.
/// - `outcome: unimplemented-cli` needs a `cli-gap` field.
/// - A `cli-gap` field needs `outcome: unimplemented-cli`. When ostrya gets
///   the command that a cell names, the cell gets a different outcome, and a
///   `cli-gap` field that stays names a closed gap.
///
/// The `question` and `loss` fields have no converse rule. A `question` field
/// records what is still to observe, under any outcome.
///
/// The rules for the executable fields:
///
/// - A record does not state both `run` and `probe`.
/// - No two setups of one record bind the same placeholder.
/// - Each `run` and `ref-run` line is valid for [`split`](syntax::split) and
///   names a command. A line with the value `n-a` is not checked.
/// - A setup of the record binds each placeholder of a `run` or `ref-run`
///   line. The placeholder [`IMPLICIT`](setup::IMPLICIT) is always bound.
/// - `expect-exit` and `ref-expect-exit` are integers.
/// - `expect-stdout`, `expect-stderr`, `ref-expect-stdout`, and
///   `ref-expect-stderr` are valid for [`parse_claim`](syntax::parse_claim).
/// - `ref-may-abort` is a signal number, and the record has a `note` field
///   that records the observed crash.
/// - A record with `ref-run: n-a` has no `ref-expect-exit`,
///   `ref-expect-stdout`, `ref-expect-stderr`, or `ref-may-abort` field.
///
/// The rules for the whole matrix:
///
/// - No two cells have the same id.
/// - In the families `M0` and `M1`, the `modes` values of each row cover the
///   six [`MODES`] once each.
/// - A record names each probe of [`PROBES`](probe::PROBES).
/// - Each `spec:` value names a heading of a design document. See
///   [Spec anchors](#spec-anchors).
///
/// # Spec anchors
///
/// A `spec:` value is `<document>#<anchor>`. The document name resolves first
/// in the matrix directory, which holds `cli-surface.md` and `harness.md`.
/// Then it resolves in the parent directory, which holds `format-reference.md`,
/// `port-plan.md`, and `api-sketch.md`.
///
/// The anchor is the fragment that GitHub makes from the heading text, so a
/// resolved value links to the section in the rendered document.
///
/// If the parent directory has no `format-reference.md`, `check` does not
/// check the `spec:` values. This is the case when the record files are apart
/// from the design documents, for example in a privileged run from a copied
/// directory.
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
    spec_anchors(matrix, &mut errors);

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

/// Checks the field that each of three outcomes needs: `unobserved` needs
/// `question`, `lossy` needs `loss`, and `unimplemented-cli` needs `cli-gap`.
///
/// The `cli-gap` tie holds in both directions. When ostrya gets the command
/// that a cell names, the cell gets a different outcome. A `cli-gap:` that
/// stays on the record then names a closed gap. The other two fields have no
/// converse rule. `question:` records what is still to observe, under any
/// outcome.
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
    if record.get("cli-gap").is_some() && record.get("outcome") != Some("unimplemented-cli") {
        errors.push(format!(
            "{origin}: `cli-gap` belongs to `outcome: unimplemented-cli`, and \
             this record states `outcome: {}`",
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

/// Checks that the `modes` values of each row of `M0` and `M1` cover the six
/// modes once each.
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

/// Checks that each `spec:` value names a heading of its document.
///
/// The `# Spec anchors` section of [`check`] states the rules. A file that
/// cannot be read gives an empty set of headings.
fn spec_anchors(matrix: &Matrix, errors: &mut Vec<String>) {
    if !matrix.dir.join("../format-reference.md").is_file() {
        return;
    }
    let mut cache: BTreeMap<std::path::PathBuf, BTreeSet<String>> = BTreeMap::new();

    for record in &matrix.records {
        for field in &record.paragraph.fields {
            if field.name != "spec" {
                continue;
            }
            for value in field.value.split_whitespace() {
                let Some((document, anchor)) = value.split_once('#') else {
                    errors.push(format!(
                        "{}:{}: `spec: {value}` names no heading",
                        record.paragraph.file.display(),
                        field.line
                    ));
                    continue;
                };
                let candidates = [
                    matrix.dir.join(document),
                    matrix.dir.join("..").join(document),
                ];
                let Some(path) = candidates.iter().find(|path| path.is_file()) else {
                    errors.push(format!(
                        "{}:{}: `spec: {value}` names no document `{document}`",
                        record.paragraph.file.display(),
                        field.line
                    ));
                    continue;
                };
                let headings = cache.entry(path.clone()).or_insert_with(|| {
                    match std::fs::read_to_string(path) {
                        Ok(text) => heading_anchors(&text),
                        Err(_) => BTreeSet::new(),
                    }
                });
                if !headings.contains(anchor) {
                    errors.push(format!(
                        "{}:{}: `spec: {value}` names no heading of `{document}`",
                        record.paragraph.file.display(),
                        field.line
                    ));
                }
            }
        }
    }
}

/// Returns each anchor that the headings of a Markdown document give.
///
/// A heading in a fenced code block is text, so the function skips the
/// content of each fence. A repeated anchor gets the suffix `-1`, then `-2`,
/// and up.
fn heading_anchors(text: &str) -> BTreeSet<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut anchors = BTreeSet::new();
    let mut fenced = false;

    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let hashes = line.len() - line.trim_start_matches('#').len();
        if !(1..=6).contains(&hashes) {
            continue;
        }
        let Some(title) = line[hashes..].strip_prefix(' ') else {
            continue;
        };
        let base = anchor_of(title.trim());
        let seen = counts.entry(base.clone()).or_insert(0);
        anchors.insert(if *seen == 0 {
            base
        } else {
            format!("{base}-{seen}")
        });
        *seen += 1;
    }
    anchors
}

/// Returns the anchor that GitHub makes from the text of one heading.
///
/// The function changes the text to lower case and changes each space to a
/// hyphen. It drops each character that is not a letter, a digit, a hyphen,
/// or an underscore. A heading that ends in `-- words` gives four hyphens in
/// sequence: one for the space, two for the dashes, and one for the next space.
fn anchor_of(title: &str) -> String {
    title
        .to_lowercase()
        .chars()
        .filter_map(|ch| match ch {
            ' ' => Some('-'),
            '-' | '_' => Some(ch),
            _ if ch.is_alphanumeric() => Some(ch),
            _ => None,
        })
        .collect()
}

/// Checks each test path of the `evidence:` values against the tests that
/// cargo lists.
///
/// The function runs `cargo test --workspace --all-features -- --list` in
/// `workspace`, so it compiles the tests of the workspace. The `Ok` vector
/// holds one message for each test path that names no listed test.
///
/// # Test paths
///
/// - The value `-` of `evidence:` is not checked.
/// - Commas split a value into citations. A comma in parentheses does not
///   split. The first word of each citation is its path.
/// - A test path has two or more `::` separators and holds only ASCII
///   letters, digits, `_`, and `:`.
/// - A path with one `::` (`crate::area`) names an area of tests. This
///   function does not check it, and it gives no message.
/// - A fixture file or a document name is not a test path. This function
///   does not check it, and it gives no message.
/// - A test path matches a listed test if the last `::` segments are equal.
///
/// # Errors
///
/// - An error if `cargo` does not start.
/// - An error if `cargo test --list` exits with a failure status. The message
///   holds the status and the standard error of cargo.
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

/// Returns the bare function name of each test that `cargo test -- --list`
/// reports.
///
/// Each line is a full test name and then `: test` or `: bench`. The name of a
/// unit test has its module path (`module::tests::function`). The name of an
/// integration test is the function name alone (`function`). The function
/// keeps the last segment of each name, so the set compares with the last
/// segment of a citation.
///
/// A citation that names only the end of a real test name does not match.
/// For example, `commit_matches_the_tool` does not match the real
/// `bare_user_only_commit_matches_the_tool`. The last segment of that test is
/// its whole name.
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

/// Splits an `evidence:` value at the commas that separate citations.
///
/// A comma in a remark in parentheses does not split.
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

/// Returns the bare function name that a test-path citation names, or `None`
/// if `path` is not a test path.
///
/// A test path has two or more `::` separators. The form is
/// `crate::file::function` for an integration test and
/// `crate::module::function` for a unit test. A path with one `::`
/// (`crate::area`, as in `ostrya::read_modes`) names an area of tests, and
/// this function does not check it.
///
/// A match on the last segment covers both forms, because
/// `cargo test -- --list` always ends a test name at the function name. The
/// module path of the crate can be in front of it or not.
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
    fn a_cli_gap_left_behind_by_a_landed_command_is_reported() {
        let mut errors = Vec::new();
        outcome_fields(
            &record(&[("outcome", "full"), ("cli-gap", "config set")]),
            &mut errors,
        );
        assert_eq!(
            errors,
            vec![
                "t:1: `cli-gap` belongs to `outcome: unimplemented-cli`, and \
                 this record states `outcome: full`"
                    .to_owned()
            ]
        );
    }

    #[test]
    fn a_cli_gap_under_its_own_outcome_passes() {
        let mut errors = Vec::new();
        outcome_fields(
            &record(&[("outcome", "unimplemented-cli"), ("cli-gap", "config set")]),
            &mut errors,
        );
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn a_question_under_another_outcome_passes() {
        let mut errors = Vec::new();
        outcome_fields(
            &record(&[("outcome", "refused-both"), ("question", "record the text")]),
            &mut errors,
        );
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn an_anchor_lowercases_and_drops_punctuation() {
        assert_eq!(
            anchor_of("Commit modifier: canonical permissions, consume, and devino"),
            "commit-modifier-canonical-permissions-consume-and-devino"
        );
        assert_eq!(
            anchor_of("`config set` and `config unset`"),
            "config-set-and-config-unset"
        );
        assert_eq!(
            anchor_of("Port extension: bare-user-shared mode"),
            "port-extension-bare-user-shared-mode"
        );
    }

    #[test]
    fn a_dashed_heading_yields_four_hyphens() {
        assert_eq!(
            anchor_of("P2 -- options missing from commands that exist"),
            "p2----options-missing-from-commands-that-exist"
        );
    }

    #[test]
    fn heading_anchors_skips_a_fenced_block_and_numbers_a_repeat() {
        let anchors = heading_anchors(
            "# Title\n```\n# not a heading\n```\n## Refs\ntext\n## Refs\n### Trailing #\n",
        );
        assert!(anchors.contains("title"));
        assert!(!anchors.contains("not-a-heading"));
        assert!(anchors.contains("refs"));
        assert!(anchors.contains("refs-1"));
        assert!(anchors.contains("trailing-"));
    }

    /// Creates a scratch directory and its child `conformance`, and returns
    /// the child.
    ///
    /// The layout is that of the design documents and the record files. The
    /// parent holds `format-reference.md`, and the child holds one `doc.md`.
    fn scratch_docs(tag: u32) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "ostrya-conformance-spec-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("conformance");
        std::fs::create_dir_all(&dir).expect("the scratch directories are created");
        std::fs::write(root.join("format-reference.md"), "## Object store layout\n")
            .expect("the parent document is written");
        std::fs::write(dir.join("doc.md"), "## P2 -- options that exist\n")
            .expect("the sibling document is written");
        dir
    }

    #[test]
    fn a_spec_anchor_that_names_no_heading_is_reported() {
        let dir = scratch_docs(line!());
        let matrix = Matrix {
            dir: dir.clone(),
            records: vec![
                record(&[("spec", "doc.md#p2")]),
                record(&[("spec", "doc.md#p2----options-that-exist")]),
                record(&[("spec", "format-reference.md#object-store-layout")]),
                record(&[("spec", "absent.md#anything")]),
                record(&[("spec", "doc.md")]),
            ],
            cells: Vec::new(),
        };
        let mut errors = Vec::new();
        spec_anchors(&matrix, &mut errors);
        std::fs::remove_dir_all(dir.parent().expect("the scratch root")).ok();

        assert_eq!(
            errors,
            vec![
                "t:1: `spec: doc.md#p2` names no heading of `doc.md`".to_owned(),
                "t:1: `spec: absent.md#anything` names no document `absent.md`".to_owned(),
                "t:1: `spec: doc.md` names no heading".to_owned(),
            ]
        );
    }

    #[test]
    fn records_apart_from_the_design_documents_are_left_unchecked() {
        let dir = scratch_docs(line!());
        std::fs::remove_file(
            dir.parent()
                .expect("the scratch root")
                .join("format-reference.md"),
        )
        .expect("the parent document is removed");

        let matrix = Matrix {
            dir: dir.clone(),
            records: vec![record(&[("spec", "doc.md#p2")])],
            cells: Vec::new(),
        };
        let mut errors = Vec::new();
        spec_anchors(&matrix, &mut errors);
        std::fs::remove_dir_all(dir.parent().expect("the scratch root")).ok();

        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn every_spec_anchor_of_the_shipped_matrix_resolves() {
        let matrix = crate::record::load(&crate::default_matrix_dir())
            .expect("the shipped record files load");
        let mut errors = Vec::new();
        spec_anchors(&matrix, &mut errors);
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn a_citation_matching_a_real_tests_suffix_is_still_flagged() {
        // `commit_matches_the_tool` names no test. The one real test that ends
        // in these characters is `bare_user_only_commit_matches_the_tool`,
        // which is a different name.
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
