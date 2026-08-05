//! The execution model.
//!
//! For one cell, in order: compute the required tier, resolve the
//! implementations, create the scratch root, materialize the setups, bind the
//! placeholders, substitute them into the invocation, run each side, apply the
//! oracles, evaluate the assertions, and emit the verdict.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::corpus;
use crate::exec::{self, Outcome, Tool};
use crate::oracle::{self, Side, Value};
use crate::probe;
use crate::record::{Actor, Cell, Matrix, Record, Tier};
use crate::setup::{self, Context};
use crate::syntax;
use crate::tier::Host;

/// What a cell reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Skip,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Skip => "skip",
        }
    }
}

/// What one oracle decided.
#[derive(Clone, Debug)]
pub enum OracleStatus {
    /// Both sides produced the same artifact.
    Equal,
    /// The two artifacts differ.
    Different { port: String, reference: String },
    /// The reference has no equivalent invocation, so nothing was compared.
    Unpaired,
    /// The oracle could not read a side.
    Unavailable(String),
}

impl OracleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            OracleStatus::Equal => "equal",
            OracleStatus::Different { .. } => "different",
            OracleStatus::Unpaired => "unpaired",
            OracleStatus::Unavailable(_) => "unavailable",
        }
    }
}

/// One cell's result.
#[derive(Clone, Debug)]
pub struct CellResult {
    pub id: String,
    pub family: String,
    pub row: String,
    pub mode: Option<String>,
    pub outcome: String,
    pub severity: String,
    /// The tier the cell needs: the highest of the record's `tier` and the
    /// tier each named corpus declares.
    pub required_tier: Tier,
    pub verdict: Verdict,
    /// The skip reason, one of the seven the design names.
    pub reason: Option<String>,
    /// The failure message, or the detail behind a skip.
    pub detail: Option<String>,
    pub oracles: Vec<(String, OracleStatus)>,
    pub artifact: Option<PathBuf>,
    pub notes: Vec<String>,
    pub elapsed_ms: u64,
    /// Whether a `--require` flag turned this cell's skip into a failure.
    pub promoted: bool,
}

impl CellResult {
    fn skip(
        cell: &Cell,
        record: &Record,
        required: Tier,
        reason: &str,
        detail: String,
    ) -> CellResult {
        CellResult {
            id: cell.id.clone(),
            family: cell.family.clone(),
            row: cell.row.clone(),
            mode: cell.mode.clone(),
            outcome: record.outcome().to_owned(),
            severity: record.severity().to_owned(),
            required_tier: required,
            verdict: Verdict::Skip,
            reason: Some(reason.to_owned()),
            detail: Some(detail),
            oracles: Vec::new(),
            artifact: None,
            notes: Vec::new(),
            elapsed_ms: 0,
            promoted: false,
        }
    }
}

/// Which cells to run.
#[derive(Clone, Debug, Default)]
pub struct Filters {
    pub family: Option<String>,
    pub cell: Option<String>,
    pub corpus: Option<String>,
    pub mode: Option<String>,
    pub tier: Option<Tier>,
}

impl Filters {
    fn admits(&self, cell: &Cell, required: Tier) -> bool {
        if let Some(family) = &self.family
            && !cell.family.eq_ignore_ascii_case(family)
        {
            return false;
        }
        if let Some(wanted) = &self.cell
            && &cell.id != wanted
        {
            return false;
        }
        if let Some(wanted) = &self.corpus
            && cell.corpus.as_deref() != Some(wanted.as_str())
        {
            return false;
        }
        if let Some(wanted) = &self.mode
            && cell.mode.as_deref() != Some(wanted.as_str())
        {
            return false;
        }
        if let Some(wanted) = self.tier
            && required != wanted
        {
            return false;
        }
        true
    }
}

/// How to run.
pub struct Options {
    pub port: Tool,
    pub reference: Option<Tool>,
    pub artifact_dir: PathBuf,
    pub keep: bool,
    pub jobs: usize,
    pub filters: Filters,
    pub require_tool: bool,
    pub require_tier: Option<Tier>,
    pub strict_identity: bool,
    pub host: Host,
}

/// Run the selected cells.
pub fn run(matrix: &Matrix, options: &Options) -> Vec<CellResult> {
    let results: Mutex<Vec<(usize, CellResult)>> = Mutex::new(Vec::new());
    let next = AtomicUsize::new(0);
    let jobs = options.jobs.max(1);

    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(cell) = matrix.cells.get(index) else {
                        break;
                    };
                    let result = one(matrix, cell, options);
                    results
                        .lock()
                        .expect("no panic holds the lock")
                        .push((index, result));
                }
            });
        }
    });

    let mut ordered = results.into_inner().expect("no panic holds the lock");
    ordered.sort_by_key(|(index, _)| *index);
    ordered.into_iter().map(|(_, result)| result).collect()
}

fn one(matrix: &Matrix, cell: &Cell, options: &Options) -> CellResult {
    let record = matrix.record(cell);
    let required = required_tier(cell, record);

    if !options.filters.admits(cell, required) {
        return CellResult::skip(
            cell,
            record,
            required,
            "filtered",
            "not selected".to_owned(),
        );
    }

    // The privilege gate is decided first, so a cell this host cannot observe
    // at all says so, whatever state its record is in. The same cell run at
    // the tier it needs then reports what the record itself is missing, and
    // the difference between the two runs is what the privilege unlocked.
    if options.host.tier < required {
        let mut result = CellResult::skip(
            cell,
            record,
            required,
            "tier",
            format!(
                "needs {required}, the host provides {}; {}",
                options.host.tier,
                options.host.advice(required)
            ),
        );
        if options
            .require_tier
            .is_some_and(|wanted| required <= wanted)
        {
            promote(&mut result, "--require tier");
        }
        return result;
    }

    let is_probe = record.get("probe").is_some();
    if !record.is_executable() {
        return if record.cites_evidence() {
            CellResult::skip(
                cell,
                record,
                required,
                "proved-elsewhere",
                record.get("evidence").unwrap_or("-").to_owned(),
            )
        } else {
            CellResult::skip(
                cell,
                record,
                required,
                "declaration",
                format!("the record states `{}` and no invocation", record.outcome()),
            )
        };
    }

    let needs_reference = if is_probe {
        record.get("ref-run") != Some("n-a")
    } else {
        record.reference_run().is_some()
    } || matches!(record.actor("created-by"), Actor::Reference)
        || matches!(record.actor("populated-by"), Actor::Reference);

    if needs_reference && options.reference.is_none() {
        let mut result = CellResult::skip(
            cell,
            record,
            required,
            "reference-absent",
            "no ostree binary resolved".to_owned(),
        );
        if options.require_tool {
            promote(&mut result, "--require tool=ostree");
        }
        return result;
    }

    // The reference tool resolves the compiled-in `tier::SYSTEM_REPO` when an
    // invocation binds no repository, so on a host carrying one the cell's
    // premise fails and the run would act on live system state. A cell whose
    // premise fails for either implementation handle is a cell to skip whole,
    // so both invocations are read here. A declared cell runs in the side's
    // scratch root, which no setup makes a repository -- the setups bind
    // `$REPO` to a path under it -- so the current directory resolves nothing
    // there and the run line is the whole reading.
    //
    // A `probe:` cell carries no textual `run:` line, so the guard inside
    // `exec::run` is its gate, one invocation at a time. Of the two registered
    // probes, `repo-position-precedence` binds `--repo` or `OSTREE_REPO` in
    // all three of its invocations (`probe.rs:127`, `:134`, `:142`), and
    // `init-reuse-via-cwd-and-env` exercises the current-directory source
    // deliberately (`probe.rs:84`), which the guard's `cwd` term admits.
    let directory = options.artifact_dir.join(&cell.id);
    if !is_probe
        && let Some(detail) =
            system_repo_premise(record, &directory, options.host.system_repo.as_deref())
    {
        return CellResult::skip(cell, record, required, "system-repo", detail);
    }

    let started = std::time::Instant::now();
    let mut result = match execute(cell, record, options, required, &directory, is_probe) {
        Ok(result) => result,
        Err(message) => CellResult {
            id: cell.id.clone(),
            family: cell.family.clone(),
            row: cell.row.clone(),
            mode: cell.mode.clone(),
            outcome: record.outcome().to_owned(),
            severity: record.severity().to_owned(),
            required_tier: required,
            verdict: Verdict::Fail,
            reason: None,
            detail: Some(message),
            oracles: Vec::new(),
            artifact: Some(directory.clone()),
            notes: Vec::new(),
            elapsed_ms: 0,
            promoted: false,
        },
    };
    result.elapsed_ms = started.elapsed().as_millis() as u64;

    if result.verdict == Verdict::Pass && !options.keep {
        let _ = std::fs::remove_dir_all(&directory);
        result.artifact = None;
    }
    result
}

/// The detail a `system-repo` skip carries, and `None` when the cell's two
/// invocations both bind a repository or the host carries none.
///
/// The invocations are read as the record states them, before substitution: a
/// placeholder such as `--repo=$REPO` still reads as a binding. `directory` is
/// the cell's artifact directory, which holds the two scratch roots the
/// invocations run in; no setup makes a scratch root a repository, so the
/// current-directory source resolves nothing for a declared cell.
fn system_repo_premise(
    record: &Record,
    directory: &Path,
    system_repo: Option<&Path>,
) -> Option<String> {
    let system_repo = system_repo?;
    for line in [record.get("run"), record.reference_run()]
        .into_iter()
        .flatten()
    {
        // A line the splitter rejects is left to the executor, which reports
        // the syntax error itself.
        let Ok(args) = syntax::split(line) else {
            continue;
        };
        if exec::system_repo_refusal(directory, &args, &[], Some(system_repo)).is_some() {
            return Some(format!(
                "`{line}` binds no repository, and this host carries {}, which \
                 the reference tool resolves; the claim cannot be made here",
                system_repo.display()
            ));
        }
    }
    None
}

fn promote(result: &mut CellResult, flag: &str) {
    let reason = result.reason.clone().unwrap_or_default();
    let detail = result.detail.clone().unwrap_or_default();
    result.verdict = Verdict::Fail;
    result.promoted = true;
    result.detail = Some(format!("skip `{reason}` promoted by {flag}: {detail}"));
}

/// The highest of the record's tier and the tier each named corpus declares.
pub fn required_tier(cell: &Cell, record: &Record) -> Tier {
    let mut required = record.tier();
    if let Some(name) = &cell.corpus
        && let Some(tier) = corpus::tier(name)
    {
        required = required.max(tier);
    }
    required
}

struct Prepared<'a> {
    tool: &'a Tool,
    root: PathBuf,
    /// Where an oracle that needs scratch space of its own may write. It sits
    /// beside the side's subtree rather than inside it, so a checkout the
    /// `manifest` oracle makes is not itself part of what an oracle reads,
    /// and the two sides never share a path.
    work: PathBuf,
    bindings: BTreeMap<String, String>,
}

fn execute(
    cell: &Cell,
    record: &Record,
    options: &Options,
    required: Tier,
    directory: &Path,
    is_probe: bool,
) -> Result<CellResult, String> {
    let _ = std::fs::remove_dir_all(directory);
    std::fs::create_dir_all(directory).map_err(|err| format!("{}: {err}", directory.display()))?;

    let mode = cell
        .mode
        .clone()
        .unwrap_or_else(|| setup::DEFAULT_MODE.to_owned());
    let corpus_name = cell
        .corpus
        .clone()
        .unwrap_or_else(|| setup::DEFAULT_CORPUS.to_owned());
    let setups = record.list("setup");

    let reference_line = if is_probe {
        (record.get("ref-run") != Some("n-a")).then_some("")
    } else {
        record.reference_run()
    };

    let mut sides: Vec<Prepared<'_>> = Vec::new();
    let mut plan: Vec<(&Tool, &str)> = vec![(&options.port, "port")];
    let wants_reference = reference_line.is_some()
        || matches!(record.actor("created-by"), Actor::Reference)
        || matches!(record.actor("populated-by"), Actor::Reference);
    if wants_reference && let Some(reference) = &options.reference {
        plan.push((reference, "ref"));
    }

    for (tool, name) in plan {
        let root = directory.join(name);
        std::fs::create_dir_all(&root).map_err(|err| format!("{}: {err}", root.display()))?;
        let work = directory.join(format!("{name}.work"));
        std::fs::create_dir_all(&work).map_err(|err| format!("{}: {err}", work.display()))?;
        let context = Context {
            root: &root,
            own: tool,
            port: Some(&options.port),
            reference: options.reference.as_ref(),
            mode: &mode,
            src_mode: record.get("src-mode").unwrap_or(&mode),
            dst_mode: record.get("dst-mode").unwrap_or(&mode),
            corpus: &corpus_name,
            created_by: record.actor("created-by"),
            populated_by: record.actor("populated-by"),
        };
        let bindings = setup::apply(&setups, &context)
            .map_err(|err| format!("setting up the {name} side: {err}"))?;
        sides.push(Prepared {
            tool,
            root,
            work,
            bindings,
        });
    }

    if is_probe {
        return probe_cell(cell, record, required, directory, &sides);
    }
    declared_cell(cell, record, required, directory, &sides)
}

fn probe_cell(
    cell: &Cell,
    record: &Record,
    required: Tier,
    directory: &Path,
    sides: &[Prepared<'_>],
) -> Result<CellResult, String> {
    let name = record.get("probe").expect("the caller checked for a probe");
    let function =
        probe::lookup(name).ok_or_else(|| format!("probe `{name}` is not registered"))?;
    let env = probe::Env {
        sides: sides
            .iter()
            .map(|side| probe::SideEnv {
                tool: side.tool,
                root: &side.root,
                bindings: &side.bindings,
            })
            .collect(),
    };

    let (verdict, detail, notes) = match function(&env) {
        Ok(notes) => (Verdict::Pass, None, notes),
        Err(message) => (Verdict::Fail, Some(message), Vec::new()),
    };
    Ok(CellResult {
        id: cell.id.clone(),
        family: cell.family.clone(),
        row: cell.row.clone(),
        mode: cell.mode.clone(),
        outcome: record.outcome().to_owned(),
        severity: record.severity().to_owned(),
        required_tier: required,
        verdict,
        reason: None,
        detail,
        oracles: Vec::new(),
        artifact: Some(directory.to_path_buf()),
        notes,
        elapsed_ms: 0,
        promoted: false,
    })
}

fn declared_cell(
    cell: &Cell,
    record: &Record,
    required: Tier,
    directory: &Path,
    sides: &[Prepared<'_>],
) -> Result<CellResult, String> {
    let port_line = record
        .get("run")
        .expect("the caller checked for a run line");
    let reference_line = record.reference_run();
    let oracles = record.list("oracle");
    let keep_checksums = oracles.contains(&"checksum-agreement");

    let mut failures: Vec<String> = Vec::new();
    let mut outcomes: Vec<(usize, Outcome, Option<String>)> = Vec::new();

    for (index, side) in sides.iter().enumerate() {
        let is_port = side.tool.role == "port";
        let line = if is_port {
            Some(port_line)
        } else {
            reference_line
        };
        let Some(line) = line else { continue };

        let args = syntax::split(line)?
            .iter()
            .map(|argument| syntax::substitute(argument, &side.bindings))
            .collect::<Result<Vec<String>, String>>()?;
        let outcome = exec::run(side.tool, &side.root, &args, &[])?;

        let label = if is_port { "port" } else { "ref" };
        write_artifact(directory, &format!("{label}.stdout"), &outcome.stdout)?;
        write_artifact(directory, &format!("{label}.stderr"), &outcome.stderr)?;

        // A tolerated reference crash carries no claims to check: the process
        // never reached its own exit or messages.
        let tolerated = tolerated_abort(record, &outcome, is_port);
        if tolerated.is_none() {
            failures.extend(assertions(record, side, &outcome, is_port));
        }
        outcomes.push((index, outcome, tolerated));
    }

    let mut results: Vec<(String, OracleStatus)> = Vec::new();
    for name in &oracles {
        let mut values: Vec<(&'static str, Value)> = Vec::new();
        for (index, outcome, tolerated) in &outcomes {
            let side = &sides[*index];
            let label = if side.tool.role == "port" {
                "port"
            } else {
                "ref"
            };
            let value = match tolerated {
                Some(reason) => Value::Unavailable(reason.clone()),
                None => oracle::apply(
                    name,
                    &Side {
                        tool: side.tool,
                        root: &side.root,
                        repo: setup::primary_repo(&side.bindings),
                        bindings: &side.bindings,
                        outcome,
                        work: &side.work,
                        keep_checksums,
                    },
                ),
            };
            if let Value::Text(text) = &value {
                write_artifact(
                    directory,
                    &format!("oracle-{name}.{label}"),
                    text.as_bytes(),
                )?;
            }
            values.push((label, value));
        }

        let find = |wanted: &str| {
            values
                .iter()
                .find(|(label, _)| *label == wanted)
                .map(|(_, value)| value)
        };
        let status = match (find("port"), find("ref")) {
            (Some(Value::Unavailable(reason)), _) | (_, Some(Value::Unavailable(reason))) => {
                OracleStatus::Unavailable(reason.clone())
            }
            (Some(Value::Text(port)), Some(Value::Text(reference))) => {
                if port == reference {
                    OracleStatus::Equal
                } else {
                    OracleStatus::Different {
                        port: port.clone(),
                        reference: reference.clone(),
                    }
                }
            }
            (Some(Value::Text(_)), None) => OracleStatus::Unpaired,
            _ => OracleStatus::Unavailable("no side produced an artifact".to_owned()),
        };
        if let OracleStatus::Different { port, reference } = &status {
            failures.push(format!(
                "oracle `{name}` disagreed\n  port: {}\n  reference: {}",
                summarize(port),
                summarize(reference)
            ));
        }
        results.push(((*name).to_owned(), status));
    }

    // An oracle that could not read a side leaves the cell unobserved, so it
    // reports as skipped rather than as a pass on the assertions that did run.
    let unavailable: Vec<String> = results
        .iter()
        .filter_map(|(name, status)| match status {
            OracleStatus::Unavailable(reason) => Some(format!("`{name}`: {reason}")),
            _ => None,
        })
        .collect();

    let (verdict, reason, detail) = if !failures.is_empty() {
        (Verdict::Fail, None, Some(failures.join("\n")))
    } else if !unavailable.is_empty() {
        // A tolerated reference crash is its own category, so the summary names
        // the reference build's defect rather than a missing port command.
        let aborted = if outcomes.iter().any(|(_, _, tolerated)| tolerated.is_some()) {
            "reference-abort"
        } else {
            "unimplemented-cli"
        };
        (
            Verdict::Skip,
            Some(aborted.to_owned()),
            Some(unavailable.join("; ")),
        )
    } else {
        (Verdict::Pass, None, None)
    };

    Ok(CellResult {
        id: cell.id.clone(),
        family: cell.family.clone(),
        row: cell.row.clone(),
        mode: cell.mode.clone(),
        outcome: record.outcome().to_owned(),
        severity: record.severity().to_owned(),
        required_tier: required,
        verdict,
        reason,
        detail,
        oracles: results,
        artifact: Some(directory.to_path_buf()),
        notes: Vec::new(),
        elapsed_ms: 0,
        promoted: false,
    })
}

/// The reason a record tolerates the reference's abnormal termination, and
/// `None` where it does not.
///
/// A reference build that crashes on a cell's invocation states nothing about
/// the port, so `ref-may-abort:` names the one signal the record tolerates and
/// the cell reports as skipped. The record names a single signal, so a crash
/// other than the observed one still fails the cell, and the port's own
/// `expect-*` claims are asserted either way.
fn tolerated_abort(record: &Record, outcome: &Outcome, is_port: bool) -> Option<String> {
    if is_port {
        return None;
    }
    let tolerated: i32 = record.get("ref-may-abort")?.trim().parse().ok()?;
    let signal = outcome.signal?;
    (signal == tolerated).then(|| {
        format!("the reference aborted on signal {signal}, which `ref-may-abort` tolerates")
    })
}

/// The absolute claims one side must satisfy.
///
/// Every executed side asserts that it terminated normally, and a record that
/// omits its `expect-exit` claims exit status 0.
fn assertions(
    record: &Record,
    side: &Prepared<'_>,
    outcome: &Outcome,
    is_port: bool,
) -> Vec<String> {
    let (exit_field, stdout_field, stderr_field, who) = if is_port {
        ("expect-exit", "expect-stdout", "expect-stderr", "port")
    } else {
        (
            "ref-expect-exit",
            "ref-expect-stdout",
            "ref-expect-stderr",
            "reference",
        )
    };

    let mut failures = Vec::new();
    if !outcome.terminated_normally() {
        failures.push(format!(
            "the {who} did not terminate normally: {}",
            outcome.status_text()
        ));
        return failures;
    }

    let expected: i32 = match record.get(exit_field) {
        None => 0,
        Some(text) => match text.trim().parse() {
            Ok(value) => value,
            Err(err) => {
                failures.push(format!("`{exit_field}: {text}` is not a number: {err}"));
                return failures;
            }
        },
    };
    if outcome.status != Some(expected) {
        failures.push(format!(
            "the {who} exited {} where the record claims {expected}\n  stderr: {}",
            outcome.status_text(),
            summarize(&String::from_utf8_lossy(&outcome.stderr))
        ));
    }

    for (field, stream, bytes) in [
        (stdout_field, "stdout", &outcome.stdout),
        (stderr_field, "stderr", &outcome.stderr),
    ] {
        let Some(text) = record.get(field) else {
            continue;
        };
        let claim = match syntax::parse_claim(text) {
            Ok(claim) => claim,
            Err(err) => {
                failures.push(format!("`{field}`: {err}"));
                continue;
            }
        };
        let observed = oracle::normalize(bytes, &side.bindings, true);
        let raw = String::from_utf8_lossy(bytes);
        if !claim.holds(observed.trim_end()) && !claim.holds(&raw) {
            failures.push(format!(
                "the {who}'s {stream} does not satisfy `{}`\n  observed: {}",
                claim.render(),
                summarize(&observed)
            ));
        }
    }
    failures
}

fn write_artifact(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let path = directory.join(name);
    std::fs::write(&path, bytes).map_err(|err| format!("{}: {err}", path.display()))
}

/// A one-line rendering of a possibly long artifact, for a failure message.
fn summarize(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return "<empty>".to_owned();
    }
    let single: String = trimmed.replace('\n', " ⏎ ");
    if single.chars().count() <= 200 {
        return single;
    }
    let head: String = single.chars().take(200).collect();
    format!("{head}… ({} characters)", single.chars().count())
}

/// Whether the run holds a failure that gates it.
///
/// An `identity` failure is reported and leaves the exit status alone, unless
/// `--strict-identity` promotes it. A skip a `--require` flag promoted always
/// gates, since the flag states that the host must observe the cell.
pub fn gating_failure(results: &[CellResult], strict_identity: bool) -> bool {
    results.iter().any(|result| {
        result.verdict == Verdict::Fail
            && (result.promoted || strict_identity || result.severity != "identity")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deb822::{Field, Paragraph};
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

    fn failure(severity: &str, promoted: bool) -> CellResult {
        CellResult {
            id: "t".to_owned(),
            family: "M1".to_owned(),
            row: "t".to_owned(),
            mode: None,
            outcome: "full".to_owned(),
            severity: severity.to_owned(),
            required_tier: Tier::T0,
            verdict: Verdict::Fail,
            reason: None,
            detail: None,
            oracles: Vec::new(),
            artifact: None,
            notes: Vec::new(),
            elapsed_ms: 0,
            promoted,
        }
    }

    #[test]
    fn an_identity_failure_gates_only_under_strict_identity() {
        let unpromoted = failure("identity", false);
        assert!(!gating_failure(std::slice::from_ref(&unpromoted), false));
        assert!(gating_failure(&[unpromoted], true));
    }

    #[test]
    fn a_require_promoted_skip_gates_regardless_of_strict_identity() {
        let promoted = failure("identity", true);
        assert!(gating_failure(&[promoted], false));
    }

    #[test]
    fn a_repo_less_invocation_on_either_side_fails_the_system_repo_premise() {
        let present = Some(Path::new(crate::tier::SYSTEM_REPO));
        // The scratch root a declared cell runs in, which is never a
        // repository.
        let directory = Path::new("/ostrya-conformance-no-such-directory");

        let bound = record(&[("run", "--repo=$REPO refs")]);
        assert!(system_repo_premise(&bound, directory, present).is_none());
        // The host fact decides: the same record passes the premise where no
        // system repository exists.
        let unbound = record(&[("run", "prune")]);
        assert!(system_repo_premise(&unbound, directory, None).is_none());
        assert!(system_repo_premise(&unbound, directory, present).is_some());

        // `ref-run` states the reference's own invocation, and a repo-less one
        // there fails the premise for the whole cell.
        let reference_only = record(&[("run", "--repo=$REPO refs"), ("ref-run", "refs")]);
        assert!(system_repo_premise(&reference_only, directory, present).is_some());
    }

    #[test]
    fn required_tier_takes_the_higher_of_record_and_corpus() {
        let record = record(&[("tier", "T1")]);

        let low_corpus = Cell {
            id: "t".to_owned(),
            family: "M0".to_owned(),
            row: "t".to_owned(),
            mode: None,
            corpus: Some("C0".to_owned()),
            op: None,
            record: 0,
        };
        assert_eq!(required_tier(&low_corpus, &record), Tier::T1);

        let high_corpus = Cell {
            corpus: Some("C12".to_owned()),
            ..low_corpus
        };
        assert_eq!(required_tier(&high_corpus, &record), Tier::T3);
    }

    /// An outcome that ended on `signal`, or exited with `status`.
    fn ended(signal: Option<i32>, status: Option<i32>) -> Outcome {
        Outcome {
            argv: Vec::new(),
            cwd: PathBuf::from("t"),
            status,
            signal,
            stdout: Vec::new(),
            stderr: Vec::new(),
            elapsed_ms: 0,
        }
    }

    #[test]
    fn a_record_tolerates_the_reference_signal_it_names() {
        let record = record(&[("ref-may-abort", "6")]);
        assert!(tolerated_abort(&record, &ended(Some(6), None), false).is_some());
    }

    #[test]
    fn a_tolerance_covers_no_other_signal() {
        let record = record(&[("ref-may-abort", "6")]);
        assert!(tolerated_abort(&record, &ended(Some(11), None), false).is_none());
    }

    #[test]
    fn a_tolerance_never_covers_the_port() {
        let record = record(&[("ref-may-abort", "6")]);
        assert!(tolerated_abort(&record, &ended(Some(6), None), true).is_none());
    }

    #[test]
    fn a_reference_that_exits_is_not_a_tolerated_abort() {
        let record = record(&[("ref-may-abort", "6")]);
        assert!(tolerated_abort(&record, &ended(None, Some(1)), false).is_none());
    }

    #[test]
    fn a_record_without_the_field_tolerates_no_abort() {
        assert!(tolerated_abort(&record(&[]), &ended(Some(6), None), false).is_none());
    }
}
