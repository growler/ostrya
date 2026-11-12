//! The registered probes: the cells that a `run:` line cannot state.
//!
//! [`PROBES`] names each [`Probe`], and [`lookup`] finds one by name.

use std::collections::BTreeMap;
use std::path::Path;

use crate::exec::{self, Outcome, Tool};

/// The side of one implementation, as a probe sees it.
pub struct SideEnv<'a> {
    /// The implementation that this side runs.
    pub tool: &'a Tool,
    /// The subtree of the side.
    ///
    /// It is the working directory if the probe sets no other directory.
    pub root: &'a Path,
    /// The placeholder bindings of the setups of the cell for this side.
    pub bindings: &'a BTreeMap<String, String>,
}

/// The input of a probe.
pub struct Env<'a> {
    /// One entry for each side: the `ostrya` side first, then the `ostree`
    /// side if it runs.
    pub sides: Vec<SideEnv<'a>>,
}

/// A function that runs the steps of one probe cell.
///
/// A probe returns the observations that it made, or the failure that it
/// found. A probe states a cell that a `run:` line cannot state without a
/// change of meaning:
///
/// - A command line with a name that the grammar cannot express.
/// - An interleaved sequence of invocations.
/// - A comparison that reads state between two steps.
pub type Probe = fn(&Env<'_>) -> Result<Vec<String>, String>;

/// The registered probes, each with its name.
///
/// Each probe controls the working directory and the environment of its
/// invocations. A `run:` line does not state them.
///
/// - `init-refusal-via-cwd-and-env` checks `init` with no `--repo` where the
///   current directory or `OSTREE_REPO` resolves an existing repository. The
///   port refuses the repository and exits non-zero with `repository
///   exists`. The `ostree` command exits 0. The `config` of the repository
///   does not change on either side.
/// - `repo-position-precedence` checks that `--repo` before the subcommand,
///   `--repo` after it, and `OSTREE_REPO` with no `--repo` resolve the same
///   repository. The three `prune` invocations must write the same standard
///   output.
///
/// The repository of `init-refusal-via-cwd-and-env` has a `collection-id`. If a
/// repository has no `collection-id`, the `ostree` command crashes when it
/// finds the repository through the current directory or `OSTREE_REPO`.
/// ostrya does not reproduce that crash, and the probe does not reach it.
///
/// [`check`](crate::check::check) gives an error for each probe that no record
/// names, so this list does not grow past the matrix.
pub const PROBES: [(&str, Probe); 2] = [
    ("init-refusal-via-cwd-and-env", init_refusal_via_cwd_and_env),
    ("repo-position-precedence", repo_position_precedence),
];

/// Returns `true` if `name` is a registered probe.
pub fn is_registered(name: &str) -> bool {
    PROBES.iter().any(|(known, _)| *known == name)
}

/// Returns the probe with the name `name`, or `None` if it is not registered.
pub fn lookup(name: &str) -> Option<Probe> {
    PROBES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, probe)| *probe)
}

/// Checks `init` on an existing repository that the current directory or
/// `OSTREE_REPO` resolves. The port exits non-zero with `repository exists`,
/// and the `ostree` command exits 0. The `config` of the repository does not
/// change on either side.
///
/// The repository has a `collection-id`, so the cell does not reach the crash
/// of the `ostree` command on a fallback to a repository with no
/// `collection-id`. ostrya does not reproduce that crash.
fn init_refusal_via_cwd_and_env(env: &Env<'_>) -> Result<Vec<String>, String> {
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

        let refuses = side.tool.role == "port";
        let init = |cwd: &Path, vars: &[(String, String)], what: &str| {
            let args = ["init".to_owned(), "--mode=bare".to_owned()];
            match refuses {
                true => refused(side, cwd, &args, vars, what, "repository exists"),
                false => succeeded(side, cwd, &args, vars, what).map(|_| ()),
            }
        };
        init(
            Path::new(&repo),
            &[],
            "init with the repository as the current directory",
        )?;
        init(
            &elsewhere,
            &[("OSTREE_REPO".to_owned(), repo.clone())],
            "init with OSTREE_REPO set",
        )?;

        let after = config_of(&repo)?;
        if before != after {
            return Err(format!(
                "{}: the config of the existing repository changed",
                side.tool.role
            ));
        }
        notes.push(format!(
            "{}: both fallbacks {}, config untouched",
            side.tool.role,
            if refuses {
                "refused the repository"
            } else {
                "exited 0"
            }
        ));
    }
    Ok(notes)
}

/// Checks that `--repo` before the subcommand, `--repo` after it, and
/// `OSTREE_REPO` with no `--repo` resolve the same repository and give the
/// same output.
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

/// Runs one invocation and checks that it exits non-zero and that its
/// standard error holds `text`.
fn refused(
    side: &SideEnv<'_>,
    cwd: &Path,
    args: &[String],
    env: &[(String, String)],
    what: &str,
    text: &str,
) -> Result<(), String> {
    let outcome = exec::run(side.tool, cwd, args, env)?;
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    if matches!(outcome.status, Some(0) | None) || !stderr.contains(text) {
        return Err(format!(
            "{}: {what} exited {} and did not refuse with `{text}`: {}",
            side.tool.role,
            outcome.status_text(),
            stderr.trim()
        ));
    }
    Ok(())
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
