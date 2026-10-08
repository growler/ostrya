//! The run of the cells of a matrix, and their verdicts.
//!
//! [`run`] runs the cells that [`Options`] selects and returns a [`CellResult`]
//! for each cell. [`gating_failure`] tells if the results fail the run.

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

/// The verdict of a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The cell ran and met its expectation.
    Pass,
    /// The cell did not meet its expectation.
    ///
    /// An error in the setup or the run of the cell also gives `Fail`. A skip
    /// that a `--require` switch promotes is also a `Fail`, and
    /// [`CellResult::promoted`] is `true`.
    Fail,
    /// The cell did not run, or an oracle cannot read a side.
    ///
    /// [`CellResult::reason`] gives the reason of the skip.
    Skip,
}

impl Verdict {
    /// Returns the name of the verdict in a report: `pass`, `fail`, or `skip`.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Skip => "skip",
        }
    }
}

/// The status that one oracle gives for a cell.
///
/// An oracle reads one text from the [`Side`] of each implementation, and the
/// status compares the two texts.
#[derive(Clone, Debug)]
pub enum OracleStatus {
    /// The oracle gave the same text for the two sides.
    Equal,
    /// The oracle gave a different text for each side.
    ///
    /// This status fails the cell.
    Different {
        /// The text of the `ostrya` side.
        port: String,
        /// The text of the `ostree` side.
        reference: String,
    },
    /// Only the `ostrya` side ran, so the oracle compared no texts.
    ///
    /// The record states `ref-run: n-a`, so no invocation of the `ostree`
    /// command ran. This status is not a failure. A cell can pass on the
    /// claims of the `ostrya` side alone.
    Unpaired,
    /// The oracle cannot read a side, for the reason that the string gives.
    ///
    /// If no claim and no oracle of the cell failed, the cell reports a skip.
    /// The reason is `reference-abort` if the `ostree` command aborted on a
    /// signal that the record tolerates, else `unimplemented-cli`.
    Unavailable(String),
}

impl OracleStatus {
    /// Returns the name of the status in a report.
    ///
    /// The names are `equal`, `different`, `unpaired`, and `unavailable`.
    pub fn as_str(&self) -> &'static str {
        match self {
            OracleStatus::Equal => "equal",
            OracleStatus::Different { .. } => "different",
            OracleStatus::Unpaired => "unpaired",
            OracleStatus::Unavailable(_) => "unavailable",
        }
    }
}

/// The result of one cell.
#[derive(Clone, Debug)]
pub struct CellResult {
    /// The cell id.
    pub id: String,
    /// The family of the cell.
    pub family: String,
    /// The row key of the cell in the report grid.
    pub row: String,
    /// The repository mode of the cell, if the cell names one.
    pub mode: Option<String>,
    /// The outcome that the record declares.
    pub outcome: String,
    /// The severity that the record declares.
    pub severity: String,
    /// The tier that the cell needs, from [`required_tier`].
    pub required_tier: Tier,
    /// The verdict of the cell.
    pub verdict: Verdict,
    /// The reason of a skip, or `None` if the cell did not skip.
    ///
    /// [`run`] checks the gates of a cell in the order of this list. The
    /// first gate that fails gives the reason.
    ///
    /// - `filtered`: [`Options::filters`] does not select the cell.
    /// - `tier`: the tier of the host is lower than the required tier of the
    ///   cell. [`Host::advice`] gives the detail.
    /// - `proved-elsewhere`: the record states no `run` or `probe` field, and
    ///   its `evidence` field names a test. The detail is that field.
    /// - `declaration`: the record states no `run` or `probe` field, and no
    ///   evidence.
    /// - `reference-absent`: the cell needs the `ostree` command, and no
    ///   `ostree` binary resolved. A cell needs it if the record does not
    ///   state `ref-run: n-a`, or if `created-by` or `populated-by` names it.
    /// - `system-repo`: the host has a system repository, and the `run` or
    ///   `ref-run` line of a declared cell binds no repository.
    ///
    /// Two more reasons come after the cell ran. They apply only if no claim
    /// and no oracle failed:
    ///
    /// - `reference-abort`: an oracle cannot read a side, and the `ostree`
    ///   command aborted on the signal that `ref-may-abort` names.
    /// - `unimplemented-cli`: an oracle cannot read a side for another
    ///   reason.
    ///
    /// A skip that a `--require` switch promotes keeps its reason.
    pub reason: Option<String>,
    /// The failure message, or the detail of a skip.
    pub detail: Option<String>,
    /// The name and the status of each oracle that the cell ran.
    pub oracles: Vec<(String, OracleStatus)>,
    /// The artifact directory of the cell, if [`run`] kept it.
    ///
    /// [`run`] removes the directory of a cell that passed, unless
    /// [`Options::keep`] is `true`. A cell that skips at a gate has no
    /// directory.
    pub artifact: Option<PathBuf>,
    /// The notes of the run beside the verdict.
    ///
    /// Only a probe that passes gives notes.
    pub notes: Vec<String>,
    /// The time that the cell took, in milliseconds.
    ///
    /// A cell that skips at a gate has the value 0.
    pub elapsed_ms: u64,
    /// The flag that is `true` if a `--require` switch made a skip a failure.
    ///
    /// [`Options::require_tool`] promotes a `reference-absent` skip, and
    /// [`Options::require_tier`] promotes a `tier` skip. A promoted cell has
    /// the verdict [`Verdict::Fail`], and its [`reason`](CellResult::reason)
    /// keeps the skip reason. Its [`detail`](CellResult::detail) names the
    /// switch.
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

/// The selection of the cells that a run executes.
///
/// A cell must match each filter that is set. [`run`] reports a cell that does
/// not match as a skip with the reason `filtered`.
#[derive(Clone, Debug, Default)]
pub struct Filters {
    /// The family of the selected cells, compared with no regard to ASCII case.
    pub family: Option<String>,
    /// The id of the one selected cell.
    pub cell: Option<String>,
    /// The corpus of the selected cells.
    pub corpus: Option<String>,
    /// The repository mode of the selected cells.
    pub mode: Option<String>,
    /// The required tier of the selected cells.
    ///
    /// A cell matches only if its [`required_tier`] is equal to this tier.
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

/// The options of a run.
pub struct Options {
    /// The `ostrya` binary to run.
    pub port: Tool,
    /// The `ostree` command, or `None` if no `ostree` binary resolved.
    pub reference: Option<Tool>,
    /// The directory for the artifacts of the run.
    ///
    /// Each cell gets the directory `<artifact_dir>/<cell id>`.
    pub artifact_dir: PathBuf,
    /// The switch that keeps the artifact directory of a cell that passed.
    pub keep: bool,
    /// The number of threads that run cells at the same time.
    ///
    /// The value 0 gives one thread.
    pub jobs: usize,
    /// The selection of the cells to run.
    pub filters: Filters,
    /// The switch that fails a cell that skips with the reason
    /// `reference-absent`.
    ///
    /// The command-line form is `--require tool=ostree`.
    pub require_tool: bool,
    /// The tier up to which a skip with the reason `tier` becomes a failure.
    ///
    /// If a cell skips because of the tier of the host, and its required tier
    /// is at or lower than this tier, the cell fails. The command-line form is
    /// `--require tier=<tier>`.
    pub require_tier: Option<Tier>,
    /// The switch that makes a failure with the severity `identity` gate the
    /// run.
    ///
    /// [`run`] does not read this field. The caller gives it to
    /// [`gating_failure`].
    pub strict_identity: bool,
    /// The properties of the host, from [`detect`](crate::tier::detect).
    pub host: Host,
}

/// Runs the cells of a matrix and returns one result for each cell.
///
/// The results are in the order of the cells in `matrix`. A cell that
/// [`Options::filters`] does not select gets a skip with the reason
/// `filtered`. [`Options::jobs`] threads run the cells at the same time.
///
/// # Order
///
/// For each cell, `run` does these steps in this order:
///
/// 1. Gets the required tier of the cell from [`required_tier`].
/// 2. Checks the gates: the filters, the tier of the host, an invocation in
///    the record, the `ostree` command, and the system repository. If a gate
///    fails, the cell skips with the reason that
///    [`CellResult::reason`] gives.
/// 3. Removes and creates the artifact directory of the cell.
/// 4. Creates a scratch root and a work directory for each side, and applies
///    the setups of the record with [`setup::apply`].
/// 5. For a probe cell, runs the probe and gives its verdict.
/// 6. For a declared cell, runs the sides one after the other. For each side,
///    it substitutes the bindings into the invocation, runs it, and writes
///    its stdout and stderr to the artifact directory.
/// 7. Checks the claims of a side right after that side runs. The `ostrya`
///    side has the `expect-*` claims, and the `ostree` side has the
///    `ref-expect-*` claims. If the `ostree` command aborted on the signal
///    that `ref-may-abort` names, this step skips the claims of the `ostree`
///    side.
/// 8. Applies each oracle of the record to each side and compares the two
///    texts.
/// 9. Gives the verdict. A failed claim or a different oracle text gives
///    `Fail`. An oracle that cannot read a side gives a skip. All other
///    cells pass.
/// 10. Removes the artifact directory of a cell that passed, unless
///     [`Options::keep`] is `true`.
///
/// If one of the steps 3 to 8 returns an error, the cell fails, and
/// [`CellResult::detail`] holds the error message.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use ostrya_conformance::{default_matrix_dir, exec, record, runner, tier};
/// let matrix = record::load(&default_matrix_dir())?;
/// let port = exec::resolve("port", None, "OSTRYA_BIN", "ostrya").ok_or("no ostrya")?;
/// let options = runner::Options {
///     port: port.clone(),
///     reference: exec::resolve("reference", None, "OSTREE_BIN", "ostree"),
///     artifact_dir: ostrya_conformance::absolute(Path::new("target/conformance/run")),
///     keep: false,
///     jobs: 4,
///     filters: runner::Filters { family: Some("M10".to_owned()), ..Default::default() },
///     require_tool: false,
///     require_tier: None,
///     strict_identity: false,
///     host: tier::detect(),
/// };
/// let results = runner::run(&matrix, &options);
/// assert!(!runner::gating_failure(&results, false));
/// # Ok::<(), String>(())
/// ```
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

    // The tier gate comes first, so a cell that this host cannot observe
    // reports the tier skip, whatever the state of its record. A run of the
    // same cell at the tier it needs then reports the defects of the record.
    // The difference between the two runs shows what the privilege unlocks.
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

    // If an invocation binds no repository, the `ostree` command opens the
    // compiled-in `tier::SYSTEM_REPO`. On a host with that repository, the
    // premise of the cell fails, and the run acts on live system state. If
    // the premise fails for one of the two implementations, the whole cell
    // skips, so this check reads the two invocations. A declared cell runs in
    // the scratch root of its side. The setups bind `$REPO` to a path under
    // that root, and no setup makes the root itself a repository. The
    // current directory thus resolves no repository, and the run line is the
    // only input to read.
    //
    // A `probe:` cell has no `run:` line, so the guard in `exec::run` checks
    // each invocation of the probe. Of the two registered probes,
    // `repo-position-precedence` binds `--repo` or `OSTREE_REPO` in each of
    // the three invocations of `repo_position_precedence`. The `init` of
    // `init_reuse_via_cwd_and_env` with the repository as the current
    // directory uses the current-directory source on purpose. The `cwd` term
    // of the guard admits it.
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

/// Returns the detail of a `system-repo` skip for a cell, or `None`.
///
/// The result is `None` if each invocation of the cell binds a repository, or
/// if the host has no system repository. The function reads the invocations
/// as the record states them, before substitution. A placeholder such as
/// `--repo=$REPO` thus reads as a binding.
///
/// `directory` is the artifact directory of the cell, which holds the two
/// scratch roots of the invocations. No setup makes a scratch root a
/// repository, so the current-directory source resolves no repository for a
/// declared cell.
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
        // If `syntax::split` refuses a line, this check ignores it. The run
        // of the cell reports the syntax error.
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

/// Returns the tier that a cell needs.
///
/// The tier is the higher of the `tier` field of the record and the tier of
/// the corpus of the cell, from [`corpus::tier`].
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
    /// The directory where an oracle can write scratch files. It is next to
    /// the scratch root of the side, so no oracle reads a checkout that the
    /// `manifest` oracle makes. The two sides never share a path.
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

        // A tolerated crash of the `ostree` command gives no claims to check,
        // because the process did not reach its own exit or messages.
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

    // If an oracle cannot read a side and no claim failed, the cell is
    // unobserved and reports a skip.
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
        // A tolerated crash of the `ostree` command has its own reason, so the
        // summary names the defect of the `ostree` build. The reason
        // `unimplemented-cli` names a command that `ostrya` does not have.
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

/// Returns the reason why the record tolerates the abnormal end of the
/// `ostree` command, or `None`.
///
/// If the `ostree` command crashes on the invocation of a cell, the crash
/// states nothing about `ostrya`. `ref-may-abort:` names the one signal that
/// the record tolerates, and the cell reports a skip. A crash on another
/// signal still fails the cell.
///
/// The function returns `None` for the `ostrya` side. This crate checks the
/// `expect-*` claims of the `ostrya` side in all cases.
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

/// Returns the failures of the claims that one side must satisfy.
///
/// Each side that ran must end normally. If the record has no exit claim for
/// the side (`expect-exit` or `ref-expect-exit`), the claim is exit status 0.
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

/// Returns a text on one line for a failure message, cut at 200 characters.
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

/// Returns `true` if the results hold a failure that gates the run.
///
/// A skip never gates the run. A failure with the severity `identity` gates
/// the run only if `strict_identity` is `true`. The command-line switch is
/// `--strict-identity`. [`run_report`](crate::report::run_report) shows each
/// failure, also a failure that does not gate the run.
///
/// A skip that a `--require` switch promoted always gates the run, because the
/// switch states that the host must observe the cell.
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
        // The host decides. If no system repository exists, the same record
        // passes the premise.
        let unbound = record(&[("run", "prune")]);
        assert!(system_repo_premise(&unbound, directory, None).is_none());
        assert!(system_repo_premise(&unbound, directory, present).is_some());

        // `ref-run` states the invocation of the `ostree` command. If it binds
        // no repository, the premise fails for the whole cell.
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
