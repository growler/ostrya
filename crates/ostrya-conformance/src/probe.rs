//! The registered probes.
//!
//! A probe is the escape hatch for a cell a `run:` line would distort: a
//! command line holding a name the grammar cannot express, an interleaved
//! sequence of invocations, or a comparison that reads state between two
//! steps. Both probes here exist because the cell controls the working
//! directory and the environment of the invocation, which a `run:` line does
//! not state.
//!
//! `check` fails a probe no record names, so this registry cannot outgrow the
//! matrix.

use std::collections::BTreeMap;
use std::path::Path;

use crate::exec::{self, Outcome, Tool};

/// One side, as a probe sees it.
pub struct SideEnv<'a> {
    pub tool: &'a Tool,
    /// The side's subtree, and the working directory unless the probe changes
    /// it.
    pub root: &'a Path,
    pub bindings: &'a BTreeMap<String, String>,
}

/// What a probe receives.
pub struct Env<'a> {
    pub sides: Vec<SideEnv<'a>>,
}

/// A probe returns the observations it made, or the failure it found.
pub type Probe = fn(&Env<'_>) -> Result<Vec<String>, String>;

/// Every probe name.
pub const PROBES: [(&str, Probe); 2] = [
    ("init-reuse-via-cwd-and-env", init_reuse_via_cwd_and_env),
    ("repo-position-precedence", repo_position_precedence),
];

/// Whether `name` is a registered probe.
pub fn is_registered(name: &str) -> bool {
    PROBES.iter().any(|(known, _)| *known == name)
}

/// The probe `name` registers.
pub fn lookup(name: &str) -> Option<Probe> {
    PROBES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, probe)| *probe)
}

/// `init` shares the current-directory and `OSTREE_REPO` precedence every
/// other subcommand uses: an existing repository resolved either way is
/// reused, idempotently, with the config untouched.
///
/// The repository carries a `collection-id`, so the cell does not also
/// exercise the tool's fallback-only crash on a repository lacking one
/// (`cli-surface.md`, "Global conventions"), which the port does not
/// reproduce.
fn init_reuse_via_cwd_and_env(env: &Env<'_>) -> Result<Vec<String>, String> {
    let mut notes = Vec::new();
    for side in &env.sides {
        let repo = binding(side, "REPO")?;
        let elsewhere = side.root.join("not-a-repo");
        std::fs::create_dir_all(&elsewhere)
            .map_err(|err| format!("{}: {err}", elsewhere.display()))?;

        succeeded(
            side,
            side.root,
            &[
                format!("--repo={repo}"),
                "init".to_owned(),
                "--mode=bare".to_owned(),
                "--collection-id=org.example.M10".to_owned(),
            ],
            &[],
            "priming init",
        )?;
        let before = config_of(&repo)?;

        succeeded(
            side,
            Path::new(&repo),
            &["init".to_owned(), "--mode=bare".to_owned()],
            &[],
            "init with the repository as the current directory",
        )?;
        succeeded(
            side,
            &elsewhere,
            &["init".to_owned(), "--mode=bare".to_owned()],
            &[("OSTREE_REPO".to_owned(), repo.clone())],
            "init with OSTREE_REPO set",
        )?;

        let after = config_of(&repo)?;
        if before != after {
            return Err(format!(
                "{}: the reused repository's config changed",
                side.tool.role
            ));
        }
        notes.push(format!(
            "{}: both fallbacks reused the repository, config untouched",
            side.tool.role
        ));
    }
    Ok(notes)
}

/// `--repo` before the subcommand, after it, and `OSTREE_REPO` with neither
/// all resolve the same repository, and all three report the same thing.
fn repo_position_precedence(env: &Env<'_>) -> Result<Vec<String>, String> {
    let mut notes = Vec::new();
    for side in &env.sides {
        let repo = binding(side, "REPO")?;
        let elsewhere = side.root.join("not-a-repo");
        std::fs::create_dir_all(&elsewhere)
            .map_err(|err| format!("{}: {err}", elsewhere.display()))?;

        let leading = succeeded(
            side,
            &elsewhere,
            &[format!("--repo={repo}"), "prune".to_owned()],
            &[],
            "--repo before the subcommand",
        )?;
        let trailing = succeeded(
            side,
            &elsewhere,
            &["prune".to_owned(), "--repo".to_owned(), repo.clone()],
            &[],
            "--repo after the subcommand",
        )?;
        let environment = succeeded(
            side,
            &elsewhere,
            &["prune".to_owned()],
            &[("OSTREE_REPO".to_owned(), repo.clone())],
            "OSTREE_REPO with no --repo",
        )?;

        let texts: Vec<String> = [&leading, &trailing, &environment]
            .iter()
            .map(|outcome| String::from_utf8_lossy(&outcome.stdout).into_owned())
            .collect();
        if texts[0] != texts[1] || texts[0] != texts[2] {
            return Err(format!(
                "{}: the three positions disagreed:\nleading: {}\ntrailing: {}\nenvironment: {}",
                side.tool.role, texts[0], texts[1], texts[2]
            ));
        }
        notes.push(format!(
            "{}: all three positions reported {:?}",
            side.tool.role,
            texts[0].trim()
        ));
    }
    Ok(notes)
}

fn binding(side: &SideEnv<'_>, name: &str) -> Result<String, String> {
    side.bindings
        .get(name)
        .cloned()
        .ok_or_else(|| format!("the probe needs `${name}`, which no setup bound"))
}

fn config_of(repo: &str) -> Result<String, String> {
    std::fs::read_to_string(Path::new(repo).join("config"))
        .map_err(|err| format!("{repo}/config: {err}"))
}

fn succeeded(
    side: &SideEnv<'_>,
    cwd: &Path,
    args: &[String],
    env: &[(String, String)],
    what: &str,
) -> Result<Outcome, String> {
    let outcome = exec::run(side.tool, cwd, args, env)?;
    if outcome.status != Some(0) {
        return Err(format!(
            "{}: {what} exited {}: {}",
            side.tool.role,
            outcome.status_text(),
            String::from_utf8_lossy(&outcome.stderr).trim()
        ));
    }
    Ok(outcome)
}
