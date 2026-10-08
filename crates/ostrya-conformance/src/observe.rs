//! The observation of the `ostree` command alone, for a record skeleton.
//!
//! [`observe`] runs one cell with the [`Options`] and returns the record text.

use std::path::PathBuf;

use crate::exec::{self, Tool};
use crate::oracle::{self, Side, Value};
use crate::record::Matrix;
use crate::setup::{self, Context};
use crate::syntax;

/// The options of an observation.
pub struct Options {
    /// The `ostree` command to observe.
    pub reference: Tool,
    /// The `ostrya` binary, for each setup step that the record assigns to `p`.
    ///
    /// If `created-by` is `p`, each `init` of the setups runs this binary. If
    /// `populated-by` is `p`, each `commit` of the setups runs it. If this
    /// field is `None`, such a step makes [`observe`] return an error. The
    /// observed invocation always runs the `ostree` command.
    pub port: Option<Tool>,
    /// The directory that holds the files of the observation.
    pub artifact_dir: PathBuf,
    /// The invocation to run, in place of the invocation of the record.
    ///
    /// If `None`, the invocation comes from
    /// [`Record::reference_run`](crate::record::Record::reference_run).
    pub run: Option<String>,
    /// The setups to build, in place of the setups of the record.
    ///
    /// If the vector is empty, the setups are the `setup` field of the record.
    pub setup: Vec<String>,
}

/// Runs the `ostree` command for one cell and returns a record skeleton.
///
/// An observation is the step from a declared record to an executable record.
/// Each cell with the outcome `unobserved` needs one observation. The skeleton
/// is the record body for that cell.
///
/// The function builds the setups and runs the invocation in
/// `<artifact_dir>/observe/<id>/ref`. It removes an earlier directory of the
/// cell first. It writes the two streams to `ref.stdout` and `ref.stderr` in
/// `<artifact_dir>/observe/<id>`. If the cell has no mode or no corpus, the
/// setups use [`DEFAULT_MODE`](setup::DEFAULT_MODE) and
/// [`DEFAULT_CORPUS`](setup::DEFAULT_CORPUS).
///
/// # Skeleton
///
/// - Two comment lines name the `ostree` command and the artifact directory.
/// - The fields `family`, `setup`, `run`, `tier`, and `severity` come from the
///   record and the options. The fields `subcommand`, `cell`, and `oracle`
///   appear if the record has them.
/// - `expect-exit` is the observed exit status. `expect-stdout` and
///   `expect-stderr` are `empty`, or an `equals` claim of the stream after
///   [`normalize`](oracle::normalize).
/// - If the exit status is 0, the outcome is `full`. Else it is `unobserved`,
///   with a comment that asks for the correct outcome and its reason.
/// - A comment block holds the value of each oracle of the record.
///
/// # Errors
///
/// - An error if the matrix has no cell `id`.
/// - An error if [`Options::setup`] is empty and the record has no `setup`
///   field.
/// - An error if [`Options::run`] is `None` and
///   [`Record::reference_run`](crate::record::Record::reference_run) returns
///   `None`.
/// - An error if the artifact directory cannot be created, or a stream file
///   cannot be written.
/// - An error from [`setup::apply`] for the setups.
/// - An error from [`split`](syntax::split) or
///   [`substitute`](syntax::substitute) for the invocation.
/// - An error from [`exec::run`], for example the refusal of
///   [`system_repo_refusal`](exec::system_repo_refusal) or a command that does
///   not start.
pub fn observe(matrix: &Matrix, id: &str, options: &Options) -> Result<String, String> {
    let cell = matrix
        .cells
        .iter()
        .find(|cell| cell.id == id)
        .ok_or_else(|| format!("no cell `{id}`"))?;
    let record = matrix.record(cell);

    let setups: Vec<String> = if options.setup.is_empty() {
        record
            .list("setup")
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    } else {
        options.setup.clone()
    };
    if setups.is_empty() {
        return Err(format!(
            "cell `{id}` states no `setup`; name one with --setup"
        ));
    }
    let line = options
        .run
        .clone()
        .or_else(|| record.reference_run().map(str::to_owned))
        .ok_or_else(|| {
            format!("cell `{id}` states no invocation to observe; give one with --run")
        })?;

    let directory = options.artifact_dir.join("observe").join(id);
    let _ = std::fs::remove_dir_all(&directory);
    let root = directory.join("ref");
    std::fs::create_dir_all(&root).map_err(|err| format!("{}: {err}", root.display()))?;

    let mode = cell
        .mode
        .clone()
        .unwrap_or_else(|| setup::DEFAULT_MODE.to_owned());
    let corpus = cell
        .corpus
        .clone()
        .unwrap_or_else(|| setup::DEFAULT_CORPUS.to_owned());
    let context = Context {
        root: &root,
        own: &options.reference,
        port: options.port.as_ref(),
        reference: Some(&options.reference),
        mode: &mode,
        src_mode: record.get("src-mode").unwrap_or(&mode),
        dst_mode: record.get("dst-mode").unwrap_or(&mode),
        corpus: &corpus,
        created_by: record.actor("created-by"),
        populated_by: record.actor("populated-by"),
    };
    let names: Vec<&str> = setups.iter().map(String::as_str).collect();
    let bindings = setup::apply(&names, &context)?;

    let args = syntax::split(&line)?
        .iter()
        .map(|argument| syntax::substitute(argument, &bindings))
        .collect::<Result<Vec<String>, String>>()?;
    let outcome = exec::run(&options.reference, &root, &args, &[])?;

    std::fs::write(directory.join("ref.stdout"), &outcome.stdout)
        .map_err(|err| format!("{}: {err}", directory.display()))?;
    std::fs::write(directory.join("ref.stderr"), &outcome.stderr)
        .map_err(|err| format!("{}: {err}", directory.display()))?;

    let oracles = record.list("oracle");
    let keep_checksums = oracles.contains(&"checksum-agreement");
    let side = Side {
        tool: &options.reference,
        root: &root,
        repo: setup::primary_repo(&bindings),
        bindings: &bindings,
        outcome: &outcome,
        work: &directory,
        keep_checksums,
    };

    let stdout = oracle::normalize(&outcome.stdout, &bindings, keep_checksums);
    let stderr = oracle::normalize(&outcome.stderr, &bindings, keep_checksums);

    let mut out = String::new();
    out.push_str(&format!(
        "# observed against {}\n",
        options.reference.path.display()
    ));
    out.push_str(&format!("# artifacts: {}\n", directory.display()));
    out.push_str(&format!("family: {}\n", record.family()));
    if let Some(subcommand) = record.get("subcommand") {
        out.push_str(&format!("subcommand: {subcommand}\n"));
    }
    if let Some(tail) = record.get("cell") {
        out.push_str(&format!("cell: {tail}\n"));
    }
    out.push_str(&format!("setup: {}\n", setups.join(" ")));
    out.push_str(&format!("run: {line}\n"));
    out.push_str(&format!("expect-exit: {}\n", outcome.status_text()));
    out.push_str(&format!("expect-stdout: {}\n", claim_for(&stdout)));
    out.push_str(&format!("expect-stderr: {}\n", claim_for(&stderr)));
    if !oracles.is_empty() {
        out.push_str(&format!("oracle: {}\n", oracles.join(" ")));
    }
    out.push_str(&format!("tier: {}\n", record.tier()));
    if outcome.status == Some(0) {
        out.push_str("outcome: full\n");
    } else {
        out.push_str(
            "# the invocation failed: state `refused-both`, `refused-clean`, `lossy`,\n\
             # `needs-priv`, or `impossible`, with the reason, in place of this line\n\
             outcome: unobserved\n",
        );
    }
    out.push_str(&format!("severity: {}\n", record.severity()));

    for name in &oracles {
        let value = oracle::apply(name, &side);
        out.push_str(&format!("# oracle {name}:\n"));
        let text = match value {
            Value::Text(text) => text,
            Value::Unavailable(reason) => format!("unavailable: {reason}\n"),
        };
        for line in text.lines() {
            out.push_str(&format!("#   {line}\n"));
        }
    }
    Ok(out)
}

/// Returns the claim for an observed stream: `empty`, or `equals` and the text.
///
/// The text loses its trailing white space first.
fn claim_for(text: &str) -> String {
    let trimmed = text.trim_end();
    if trimmed.is_empty() {
        return "empty".to_owned();
    }
    syntax::Claim::Equals(trimmed.to_owned()).render()
}
