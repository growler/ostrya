//! `observe`: run the reference alone and print a record skeleton.
//!
//! This is the path from a declaration to an executable record. The 160 cells
//! the matrix marks `unobserved` each need one observation pass, and the
//! output of this subcommand is the record body that pass produces.

use std::path::PathBuf;

use crate::exec::{self, Tool};
use crate::oracle::{self, Side, Value};
use crate::record::Matrix;
use crate::setup::{self, Context};
use crate::syntax;

/// What to observe.
pub struct Options {
    pub reference: Tool,
    pub port: Option<Tool>,
    pub artifact_dir: PathBuf,
    /// The invocation to try, when the record states none.
    pub run: Option<String>,
    /// The setups to build, when the record states none.
    pub setup: Vec<String>,
}

/// Run the reference against one cell's setup and return the record skeleton.
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

/// The claim a record would state for this observed stream.
fn claim_for(text: &str) -> String {
    let trimmed = text.trim_end();
    if trimmed.is_empty() {
        return "empty".to_owned();
    }
    syntax::Claim::Equals(trimmed.to_owned()).render()
}
