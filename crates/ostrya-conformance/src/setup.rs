//! The setups a record names, and the placeholders they bind.
//!
//! A setup builds the state a cell starts from. `created-by` and
//! `populated-by` select which binary performs each step; a record naming
//! neither has each side build its own subtree with its own implementation,
//! which is what an M10 cell wants.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::corpus;
use crate::exec::{self, Tool};
use crate::record::Actor;

/// The branch every setup that commits writes to.
pub const BRANCH: &str = "conformance";

/// The commit timestamp every setup that commits states. Both implementations
/// read the `@SECONDS` form, so a setup commit is reproducible: the two sides
/// commit the same corpus and reach the same checksum, which is what lets a cell
/// name the `checksum-agreement` oracle.
pub const TIMESTAMP: &str = "@1700000000";

/// The corpus a setup commits when the record names none.
pub const DEFAULT_CORPUS: &str = "C0";

/// The mode a setup creates a repository in when the cell names none.
pub const DEFAULT_MODE: &str = "bare";

/// The file `two-repos` writes, and the content that tells the two apart.
pub const MARKER_FILE: &str = "which.txt";
/// The content that names the first repository.
pub const MARKER_ONE: &str = "distinguish-repo-1";
/// The content that names the second repository.
pub const MARKER_TWO: &str = "distinguish-repo-2";

/// Every setup name, with the placeholders it binds.
pub const SETUPS: [(&str, &[&str]); 7] = [
    ("empty-dir", &["REPO"]),
    ("repo", &["REPO"]),
    ("repo-with-commit", &["REPO", "BRANCH", "REV"]),
    ("two-repos", &["REPO", "REPO2", "BRANCH"]),
    ("src-dst", &["SRC", "DST"]),
    ("tree", &["TREE"]),
    ("out-dir", &["OUT"]),
];

/// The placeholder the runner binds for every cell, whatever its setups.
pub const IMPLICIT: &str = "SCRATCH";

/// Whether `name` is a registered setup.
pub fn is_registered(name: &str) -> bool {
    SETUPS.iter().any(|(known, _)| *known == name)
}

/// The placeholders `name` binds, or `None` when it is not registered.
pub fn bindings_of(name: &str) -> Option<&'static [&'static str]> {
    SETUPS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, bound)| *bound)
}

/// What one side's setup needs to know.
pub struct Context<'a> {
    /// The side's own subtree, and the value of `$SCRATCH`.
    pub root: &'a Path,
    /// The implementation whose subtree this is.
    pub own: &'a Tool,
    /// The port, where the run has one.
    pub port: Option<&'a Tool>,
    /// The reference implementation, where the run has one.
    pub reference: Option<&'a Tool>,
    /// The repository mode the setup creates.
    pub mode: &'a str,
    /// The source repository's mode, for a two-repository setup.
    pub src_mode: &'a str,
    /// The destination repository's mode, for a two-repository setup.
    pub dst_mode: &'a str,
    /// The corpus the setup populates from.
    pub corpus: &'a str,
    /// Which implementation creates the repository.
    pub created_by: Actor,
    /// Which implementation populates it.
    pub populated_by: Actor,
}

impl Context<'_> {
    fn actor(&self, which: Actor) -> Result<&Tool, String> {
        match which {
            Actor::Own => Ok(self.own),
            Actor::Port => self
                .port
                .ok_or_else(|| "the setup names `p` and no ostrya binary resolved".to_owned()),
            Actor::Reference => self
                .reference
                .ok_or_else(|| "the setup names `t` and no ostree binary resolved".to_owned()),
        }
    }
}

/// Run every named setup and return the bindings.
pub fn apply(names: &[&str], context: &Context<'_>) -> Result<BTreeMap<String, String>, String> {
    let mut bindings = BTreeMap::new();
    bindings.insert(IMPLICIT.to_owned(), path_text(context.root)?);
    let mut corpus_tree = CorpusTree::default();

    for name in names {
        match *name {
            "empty-dir" => {
                bind(&mut bindings, "REPO", &context.root.join("repo"))?;
            }
            "repo" => {
                let repo = context.root.join("repo");
                create(context, &repo, context.mode)?;
                bind(&mut bindings, "REPO", &repo)?;
            }
            "repo-with-commit" => {
                let repo = context.root.join("repo");
                create(context, &repo, context.mode)?;
                let tree = corpus_tree.get(context)?;
                let revision = commit(context, &repo, BRANCH, &tree)?;
                bind(&mut bindings, "REPO", &repo)?;
                insert(&mut bindings, "BRANCH", BRANCH.to_owned())?;
                insert(&mut bindings, "REV", revision)?;
            }
            "two-repos" => {
                for (index, (marker, slot)) in [(MARKER_ONE, "REPO"), (MARKER_TWO, "REPO2")]
                    .iter()
                    .enumerate()
                {
                    let repo = context.root.join(format!("repo{}", index + 1));
                    create(context, &repo, context.mode)?;
                    let tree = context.root.join(format!("marker{}", index + 1));
                    std::fs::create_dir_all(&tree)
                        .map_err(|err| format!("{}: {err}", tree.display()))?;
                    let file = tree.join(MARKER_FILE);
                    std::fs::write(&file, format!("{marker}\n"))
                        .map_err(|err| format!("{}: {err}", file.display()))?;
                    commit(context, &repo, BRANCH, &tree)?;
                    bind(&mut bindings, slot, &repo)?;
                }
                insert(&mut bindings, "BRANCH", BRANCH.to_owned())?;
            }
            "src-dst" => {
                let source = context.root.join("src");
                create(context, &source, context.src_mode)?;
                let tree = corpus_tree.get(context)?;
                commit(context, &source, BRANCH, &tree)?;
                let destination = context.root.join("dst");
                create(context, &destination, context.dst_mode)?;
                bind(&mut bindings, "SRC", &source)?;
                bind(&mut bindings, "DST", &destination)?;
            }
            "tree" => {
                let tree = corpus_tree.get(context)?;
                bind(&mut bindings, "TREE", &tree)?;
            }
            "out-dir" => {
                let out = context.root.join("out");
                std::fs::create_dir_all(&out).map_err(|err| format!("{}: {err}", out.display()))?;
                bind(&mut bindings, "OUT", &out)?;
            }
            other => return Err(format!("setup `{other}` is not registered")),
        }
    }
    Ok(bindings)
}

fn create(context: &Context<'_>, repo: &Path, mode: &str) -> Result<(), String> {
    let tool = context.actor(context.created_by)?;
    let args = vec![
        format!("--repo={}", path_text(repo)?),
        "init".to_owned(),
        format!("--mode={mode}"),
    ];
    expect_success(tool, context.root, &args)
}

fn commit(context: &Context<'_>, repo: &Path, branch: &str, tree: &Path) -> Result<String, String> {
    let tool = context.actor(context.populated_by)?;
    let args = vec![
        format!("--repo={}", path_text(repo)?),
        "commit".to_owned(),
        "-b".to_owned(),
        branch.to_owned(),
        format!("--timestamp={TIMESTAMP}"),
        path_text(tree)?,
    ];
    let outcome = expect_output(tool, context.root, &args)?;
    let text = String::from_utf8_lossy(&outcome.stdout);
    let revision = text.trim().lines().last().unwrap_or("").trim().to_owned();
    if revision.len() != 64 || !revision.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "setup commit printed no checksum: {:?}",
            text.trim()
        ));
    }
    Ok(revision)
}

fn expect_success(tool: &Tool, cwd: &Path, args: &[String]) -> Result<(), String> {
    expect_output(tool, cwd, args).map(|_| ())
}

fn expect_output(tool: &Tool, cwd: &Path, args: &[String]) -> Result<exec::Outcome, String> {
    let outcome = exec::run(tool, cwd, args, &[])?;
    if outcome.status != Some(0) {
        return Err(format!(
            "setup step `{}` exited {}: {}",
            outcome.command_text(),
            outcome.status_text(),
            String::from_utf8_lossy(&outcome.stderr).trim()
        ));
    }
    Ok(outcome)
}

fn bind(bindings: &mut BTreeMap<String, String>, name: &str, path: &Path) -> Result<(), String> {
    insert(bindings, name, path_text(path)?)
}

/// The corpus tree of one side, materialized on first use. Every setup that
/// needs the corpus names one path for it, so two setups in the same record
/// share the tree the first of them wrote. A second materialization over one
/// path fails: `C0` and `C3` end at a symlink and `C8` at a hard link, and
/// each reports `EEXIST` once the entry stands.
#[derive(Default)]
struct CorpusTree {
    path: Option<PathBuf>,
}

impl CorpusTree {
    fn get(&mut self, context: &Context<'_>) -> Result<PathBuf, String> {
        if let Some(path) = &self.path {
            return Ok(path.clone());
        }
        let path = corpus::tree_path(context.root, context.corpus);
        corpus::materialize(context.corpus, &path)?;
        self.path = Some(path.clone());
        Ok(path)
    }
}

fn insert(
    bindings: &mut BTreeMap<String, String>,
    name: &str,
    value: String,
) -> Result<(), String> {
    if bindings.insert(name.to_owned(), value).is_some() {
        return Err(format!("two setups bind `${name}`"));
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{} is not a UTF-8 path", path.display()))
}

/// The repository a cell's oracles read, given its bindings.
pub fn primary_repo(bindings: &BTreeMap<String, String>) -> Option<PathBuf> {
    bindings
        .get("REPO")
        .or_else(|| bindings.get("DST"))
        .map(PathBuf::from)
}
