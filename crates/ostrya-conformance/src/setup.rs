//! The setups a record names, and the placeholders they bind.
//!
//! A setup builds the state that a cell starts from. [`SETUPS`] names each
//! setup and its placeholders, and [`apply`] runs the setups of one side.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::corpus;
use crate::exec::{self, Tool};
use crate::record::Actor;

/// The branch of each setup commit.
pub const BRANCH: &str = "conformance";

/// The commit timestamp of each setup commit.
///
/// Both implementations read the `@SECONDS` form, so a setup commit is
/// reproducible. The two sides commit the same corpus and get the same
/// checksum. This lets a cell name the `checksum-agreement` oracle.
pub const TIMESTAMP: &str = "@1700000000";

/// The corpus of a setup if the cell names no corpus.
pub const DEFAULT_CORPUS: &str = "C0";

/// The mode of a repository that a setup creates if the cell names no mode.
pub const DEFAULT_MODE: &str = "bare";

/// The name of the file that `two-repos` commits to each repository.
pub const MARKER_FILE: &str = "which.txt";
/// The first line of [`MARKER_FILE`] in the first repository of `two-repos`.
pub const MARKER_ONE: &str = "distinguish-repo-1";
/// The first line of [`MARKER_FILE`] in the second repository of `two-repos`.
pub const MARKER_TWO: &str = "distinguish-repo-2";

/// The registered setups, each with the placeholders that it binds.
///
/// [`apply`] runs the setups in the order that the record names them. Each
/// path is in the subtree of the side ([`Context::root`]):
///
/// - `empty-dir` binds `$REPO` to `repo`, a path that does not exist.
/// - `repo` creates the repository `repo` in [`Context::mode`] and binds
///   `$REPO`.
/// - `repo-with-commit` creates `repo` and commits the corpus to [`BRANCH`].
///   It binds `$REPO`, `$BRANCH`, and `$REV`, the checksum of the commit.
/// - `two-repos` creates `repo1` and `repo2` in [`Context::mode`]. Each gets
///   one commit to [`BRANCH`] of a tree with [`MARKER_FILE`] in it. It binds
///   `$REPO`, `$REPO2`, and `$BRANCH`.
/// - `src-dst` creates `src` in [`Context::src_mode`] with one commit of the
///   corpus to [`BRANCH`]. It also creates the empty repository `dst` in
///   [`Context::dst_mode`]. It binds `$SRC` and `$DST`.
/// - `tree` builds the corpus at [`corpus::tree_path`] and binds `$TREE`.
/// - `out-dir` creates the empty directory `out` and binds `$OUT`.
pub const SETUPS: [(&str, &[&str]); 7] = [
    ("empty-dir", &["REPO"]),
    ("repo", &["REPO"]),
    ("repo-with-commit", &["REPO", "BRANCH", "REV"]),
    ("two-repos", &["REPO", "REPO2", "BRANCH"]),
    ("src-dst", &["SRC", "DST"]),
    ("tree", &["TREE"]),
    ("out-dir", &["OUT"]),
];

/// The placeholder that [`apply`] binds for each cell, also with no setup.
pub const IMPLICIT: &str = "SCRATCH";

/// Returns `true` if `name` is a registered setup.
pub fn is_registered(name: &str) -> bool {
    SETUPS.iter().any(|(known, _)| *known == name)
}

/// Returns the placeholders that `name` binds, or `None` if it is not
/// registered.
pub fn bindings_of(name: &str) -> Option<&'static [&'static str]> {
    SETUPS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, bound)| *bound)
}

/// The input of [`apply`] for the side of one implementation.
pub struct Context<'a> {
    /// The subtree of the side, and the value of `$SCRATCH`.
    pub root: &'a Path,
    /// The implementation of this subtree.
    pub own: &'a Tool,
    /// The `ostrya` binary, if the run has one.
    pub port: Option<&'a Tool>,
    /// The `ostree` command, if the run has one.
    pub reference: Option<&'a Tool>,
    /// The mode of each repository that a setup creates.
    pub mode: &'a str,
    /// The mode of the source repository of `src-dst`.
    pub src_mode: &'a str,
    /// The mode of the destination repository of `src-dst`.
    pub dst_mode: &'a str,
    /// The corpus that a setup commits or builds.
    pub corpus: &'a str,
    /// The implementation that creates each repository.
    pub created_by: Actor,
    /// The implementation that commits to each repository.
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

/// Runs the named setups for one side and returns the placeholder bindings.
///
/// [`SETUPS`] states what each setup builds. The bindings also hold
/// [`IMPLICIT`].
///
/// # Custody
///
/// [`Context::created_by`] selects the implementation that runs each `init`.
/// [`Context::populated_by`] selects the implementation that runs each
/// `commit`. The two values come from the `created-by` and `populated-by`
/// fields of the record.
///
/// If a record names neither field, each side builds its own subtree with its
/// own implementation ([`Actor::Own`]). An `M10` cell uses this default.
///
/// # Errors
///
/// - An error if a name is not a registered setup.
/// - An error if a custody field names an implementation that did not
///   resolve.
/// - An error if two setups bind one placeholder.
/// - An error from [`exec::run`] for an `init` or a `commit`.
/// - An error if an `init` or a `commit` does not exit with status 0.
/// - An error if the last line of the `commit` output is not a 64-digit
///   hexadecimal checksum.
/// - An error from [`corpus::materialize`] if the corpus does not build.
/// - An error if a directory or a file cannot be created, or if a path is not
///   UTF-8.
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

/// The corpus tree of one side. The first setup that needs it builds it.
///
/// All setups that need the corpus use one path, so two setups of one record
/// share the tree that the first one built. A second build at one path can
/// fail. For example, the symlink of `C0` and `C3`, the hard link of `C8`,
/// and the special files of `C11` and `C12` give `EEXIST`.
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

/// Returns the repository that the oracles of a cell read.
///
/// The repository is the value of `$REPO` in `bindings`, else the value of
/// `$DST`. If neither is bound, the function returns `None`.
pub fn primary_repo(bindings: &BTreeMap<String, String>) -> Option<PathBuf> {
    bindings
        .get("REPO")
        .or_else(|| bindings.get("DST"))
        .map(PathBuf::from)
}
