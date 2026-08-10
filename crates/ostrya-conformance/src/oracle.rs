//! The oracles a record names.
//!
//! An oracle reads one side's post-execution state and produces a comparable
//! artifact. The set is closed and matches the vocabulary in
//! `docs/conformance/README.md`. Each name states that the two
//! implementations produced an equal artifact; the runner compares the two
//! texts this module returns.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::exec::{self, Outcome, Tool};
use crate::sha256;

/// Every oracle name.
pub const ORACLES: [&str; 9] = [
    "exit-status",
    "stdout-text",
    "stderr-text",
    "config-bytes",
    "refs-bytes",
    "inventory",
    "manifest",
    "checksum-agreement",
    "fsck",
];

/// Whether `name` is a registered oracle.
pub fn is_registered(name: &str) -> bool {
    ORACLES.contains(&name)
}

/// What an oracle produced for one side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// The artifact, ready to compare.
    Text(String),
    /// The oracle could not read this side, with the reason. A missing CLI
    /// command reports here rather than failing the cell.
    Unavailable(String),
}

/// One side's post-execution state.
pub struct Side<'a> {
    /// The implementation this side ran.
    pub tool: &'a Tool,
    /// The side's subtree, the working directory of every extra invocation.
    pub root: &'a Path,
    /// The repository the oracles read, when the setups bound one.
    pub repo: Option<PathBuf>,
    /// The setup bindings the cell resolved.
    pub bindings: &'a BTreeMap<String, String>,
    /// What the cell's invocation produced.
    pub outcome: &'a Outcome,
    /// Where an oracle that needs scratch space of its own may write.
    pub work: &'a Path,
    /// Whether the cell compares checksums, which keeps them out of the
    /// normalizer.
    pub keep_checksums: bool,
}

impl Side<'_> {
    fn repo(&self) -> Result<&Path, Value> {
        self.repo
            .as_deref()
            .ok_or_else(|| Value::Unavailable("the cell's setups bound no repository".to_owned()))
    }
}

/// Apply one oracle.
pub fn apply(name: &str, side: &Side<'_>) -> Value {
    match name {
        "exit-status" => Value::Text(format!("{}\n", side.outcome.status_text())),
        "stdout-text" => Value::Text(normalize(
            &side.outcome.stdout,
            side.bindings,
            side.keep_checksums,
        )),
        "stderr-text" => Value::Text(normalize(
            &side.outcome.stderr,
            side.bindings,
            side.keep_checksums,
        )),
        "config-bytes" => config_bytes(side),
        "refs-bytes" => refs_bytes(side),
        "inventory" => inventory(side),
        "manifest" => manifest(side),
        "checksum-agreement" => checksum_agreement(side),
        "fsck" => fsck(side),
        other => Value::Unavailable(format!("oracle `{other}` is not registered")),
    }
}

fn config_bytes(side: &Side<'_>) -> Value {
    let repo = match side.repo() {
        Ok(repo) => repo,
        Err(value) => return value,
    };
    match std::fs::read_to_string(repo.join("config")) {
        Ok(text) => Value::Text(text),
        Err(err) => Value::Unavailable(format!("reading the repository config: {err}")),
    }
}

/// Every path under `refs/`, sorted, with the checksum each ref file holds.
///
/// The content goes through the same rewriting the text oracles apply: a bound
/// placeholder's value becomes its name, so the branch ref reads `$REV`, and
/// any other 64-character checksum is masked. Without that, two repositories
/// each side committed for itself never compare -- neither passes a timestamp,
/// so the two commit checksums differ by wall-clock time.
fn refs_bytes(side: &Side<'_>) -> Value {
    let repo = match side.repo() {
        Ok(repo) => repo,
        Err(value) => return value,
    };
    let root = repo.join("refs");
    let mut lines = Vec::new();
    for path in match walk(&root) {
        Ok(paths) => paths,
        Err(err) => return Value::Unavailable(err),
    } {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let content = substitute(content.trim(), side.bindings);
        lines.push(format!(
            "{relative} {}",
            if side.keep_checksums {
                content
            } else {
                mask_checksums(&content)
            }
        ));
    }
    lines.sort();
    Value::Text(joined(lines))
}

fn inventory(side: &Side<'_>) -> Value {
    let repo = match side.repo() {
        Ok(repo) => repo,
        Err(value) => return value,
    };
    let root = repo.join("objects");
    let mut lines = Vec::new();
    for path in match walk(&root) {
        Ok(paths) => paths,
        Err(err) => return Value::Unavailable(err),
    } {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let extension = path
            .extension()
            .map(|ext| ext.to_string_lossy().into_owned())
            .unwrap_or_default();
        let size = std::fs::symlink_metadata(&path)
            .map(|meta| meta.len())
            .unwrap_or(0);
        lines.push(format!("{relative} {extension} {size}"));
    }
    lines.sort();
    Value::Text(joined(lines))
}

/// Check the cell's commit out and reduce the tree to one line per path.
fn manifest(side: &Side<'_>) -> Value {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let repo = match side.repo() {
        Ok(repo) => repo,
        Err(value) => return value,
    };
    let Some(revision) = side
        .bindings
        .get("REV")
        .or_else(|| side.bindings.get("BRANCH"))
    else {
        return Value::Unavailable(
            "the cell's setups bound neither `$REV` nor `$BRANCH`, so there is \
             nothing to check out"
                .to_owned(),
        );
    };

    let destination = side.work.join("manifest-checkout");
    let _ = std::fs::remove_dir_all(&destination);
    let args = vec![
        format!("--repo={}", repo.display()),
        "checkout".to_owned(),
        revision.clone(),
        destination.display().to_string(),
    ];
    match exec::run(side.tool, side.root, &args, &[]) {
        Err(err) => return Value::Unavailable(err),
        Ok(outcome) if outcome.status != Some(0) => {
            return Value::Unavailable(format!(
                "`{}` exited {}: {}",
                outcome.command_text(),
                outcome.status_text(),
                String::from_utf8_lossy(&outcome.stderr).trim()
            ));
        }
        Ok(_) => {}
    }

    let mut lines = Vec::new();
    let mut paths = match walk_all(&destination) {
        Ok(paths) => paths,
        Err(err) => return Value::Unavailable(err),
    };
    paths.sort();
    for path in paths {
        let relative = path
            .strip_prefix(&destination)
            .unwrap_or(&path)
            .display()
            .to_string();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let kind = if meta.is_dir() {
            "dir"
        } else if meta.file_type().is_symlink() {
            "link"
        } else {
            "file"
        };
        let content = if meta.is_dir() {
            "-".to_owned()
        } else if meta.file_type().is_symlink() {
            std::fs::read_link(&path)
                .map(|target| target.display().to_string())
                .unwrap_or_else(|_| "?".to_owned())
        } else {
            sha256::digest_file(&path).unwrap_or_else(|_| "?".to_owned())
        };
        lines.push(format!(
            "{relative} {kind} {:04o} {} {} [{}] {content}",
            meta.permissions().mode() & 0o7777,
            meta.uid(),
            meta.gid(),
            xattrs(&path).join(" "),
        ));
    }
    Value::Text(joined(lines))
}

/// The commit checksum the operation produced.
///
/// A commit prints it as the last line of its standard output, so a commit
/// cell reads it there. Any other operation resolves it through `rev-parse`
/// against the revision the cell's setups bound.
fn checksum_agreement(side: &Side<'_>) -> Value {
    if let Some(checksum) = checksum_line(&side.outcome.stdout) {
        return Value::Text(checksum);
    }
    let repo = match side.repo() {
        Ok(repo) => repo,
        Err(value) => return value,
    };
    let Some(revision) = side
        .bindings
        .get("BRANCH")
        .or_else(|| side.bindings.get("REV"))
    else {
        return Value::Unavailable(
            "the invocation printed no checksum, and the cell's setups bound neither \
             `$BRANCH` nor `$REV` for `rev-parse` to resolve"
                .to_owned(),
        );
    };
    let args = vec![
        format!("--repo={}", repo.display()),
        "rev-parse".to_owned(),
        revision.clone(),
    ];
    match exec::run(side.tool, side.root, &args, &[]) {
        Err(err) => Value::Unavailable(err),
        Ok(outcome) if outcome.status != Some(0) => Value::Unavailable(format!(
            "`{}` exited {}: {}",
            outcome.command_text(),
            outcome.status_text(),
            String::from_utf8_lossy(&outcome.stderr).trim()
        )),
        Ok(outcome) => match checksum_line(&outcome.stdout) {
            Some(checksum) => Value::Text(checksum),
            None => Value::Unavailable(format!("`{}` printed no checksum", outcome.command_text())),
        },
    }
}

/// The last line of `stdout` when it is a bare 64-character hex checksum, with
/// a trailing newline so the artifact compares as one line.
fn checksum_line(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let line = text.lines().map(str::trim).next_back()?;
    (line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit())).then(|| format!("{line}\n"))
}

/// Each implementation's own `fsck` run against its own repository.
///
/// The compared artifact is the exit status alone. The two implementations
/// word their progress and summary lines differently, and the claim the cell
/// makes is that both find the repository sound, so the captured text goes to
/// the side's work directory for diagnosis rather than into the comparison.
fn fsck(side: &Side<'_>) -> Value {
    let repo = match side.repo() {
        Ok(repo) => repo,
        Err(value) => return value,
    };
    let args = vec![format!("--repo={}", repo.display()), "fsck".to_owned()];
    match exec::run(side.tool, side.root, &args, &[]) {
        Err(err) => Value::Unavailable(err),
        Ok(outcome) => {
            let _ = std::fs::write(side.work.join("fsck.stdout"), &outcome.stdout);
            let _ = std::fs::write(side.work.join("fsck.stderr"), &outcome.stderr);
            Value::Text(format!("exit {}\n", outcome.status_text()))
        }
    }
}

/// The sorted `name=value` list of one path's extended attributes.
fn xattrs(path: &Path) -> Vec<String> {
    let mut buffer = vec![0u8; 64 * 1024];
    let Ok(length) = rustix::fs::llistxattr(path, &mut buffer[..]) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for name in buffer[..length].split(|byte| *byte == 0) {
        if name.is_empty() {
            continue;
        }
        let Ok(name) = std::str::from_utf8(name) else {
            continue;
        };
        let mut value = vec![0u8; 64 * 1024];
        let text = match rustix::fs::lgetxattr(path, name, &mut value[..]) {
            Ok(length) => sha256::digest(&value[..length]),
            Err(_) => "?".to_owned(),
        };
        out.push(format!("{name}={text}"));
    }
    out.sort();
    out
}

/// Every regular file under `root`, empty when `root` does not exist.
fn walk(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|err| format!("{}: {err}", dir.display()))?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|err| format!("{}: {err}", path.display()))?;
            if meta.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}

/// Every path under `root`, directories included.
fn walk_all(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|err| format!("{}: {err}", dir.display()))?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|err| format!("{}: {err}", path.display()))?;
            if meta.is_dir() {
                stack.push(path.clone());
            }
            out.push(path);
        }
    }
    Ok(out)
}

fn joined(lines: Vec<String>) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// Normalize captured text before comparison.
///
/// A bound placeholder's path becomes the placeholder name, a 64-character
/// lowercase hex run becomes `<checksum>` unless the cell compares checksums,
/// and a progress line carrying a rate or an elapsed time is dropped.
pub fn normalize(
    bytes: &[u8],
    bindings: &BTreeMap<String, String>,
    keep_checksums: bool,
) -> String {
    let text = String::from_utf8_lossy(bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let text = substitute(&text, bindings);

    let mut out = String::new();
    for line in text.lines() {
        if is_progress(line) {
            continue;
        }
        let line = line.trim_end();
        out.push_str(&if keep_checksums {
            line.to_owned()
        } else {
            mask_checksums(line)
        });
        out.push('\n');
    }
    out
}

/// Replace every bound placeholder's value with its name, longest value first
/// so a value holding another one is rewritten whole.
fn substitute(text: &str, bindings: &BTreeMap<String, String>) -> String {
    let mut ordered: Vec<(&String, &String)> = bindings.iter().collect();
    ordered.sort_by_key(|(_, value)| std::cmp::Reverse(value.len()));
    let mut text = text.to_owned();
    for (name, value) in ordered {
        if !value.is_empty() {
            text = text.replace(value.as_str(), &format!("${name}"));
        }
    }
    text
}

fn is_progress(line: &str) -> bool {
    let lowered = line.to_ascii_lowercase();
    lowered.contains("elapsed")
        || ["b/s", "kb/s", "mb/s", "gb/s", "kib/s", "mib/s"]
            .iter()
            .any(|rate| lowered.contains(rate))
}

/// Replace every 64-character lowercase hex run with `<checksum>`.
fn mask_checksums(line: &str) -> String {
    let bytes = line.as_bytes();
    let hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
    let mut out = String::new();
    let mut at = 0usize;
    while at < bytes.len() {
        if hex(bytes[at]) && (at == 0 || !hex(bytes[at - 1])) {
            let mut end = at;
            while end < bytes.len() && hex(bytes[end]) {
                end += 1;
            }
            if end - at == 64 {
                out.push_str("<checksum>");
                at = end;
                continue;
            }
            out.push_str(&line[at..end]);
            at = end;
            continue;
        }
        out.push(bytes[at] as char);
        at += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bound_path_becomes_its_placeholder() {
        let mut bindings = BTreeMap::new();
        bindings.insert("REPO".to_owned(), "/scratch/port/repo".to_owned());
        let text = normalize(
            b"error: opening /scratch/port/repo failed\n",
            &bindings,
            false,
        );
        assert_eq!(text, "error: opening $REPO failed\n");
    }

    #[test]
    fn a_checksum_is_masked_unless_the_cell_compares_it() {
        let checksum = "a".repeat(64);
        let line = format!("{checksum}\n");
        assert_eq!(
            normalize(line.as_bytes(), &BTreeMap::new(), false),
            "<checksum>\n"
        );
        assert_eq!(normalize(line.as_bytes(), &BTreeMap::new(), true), line);
    }

    #[test]
    fn a_shorter_hex_run_survives() {
        assert_eq!(
            normalize(b"deadbeef\n", &BTreeMap::new(), false),
            "deadbeef\n"
        );
    }

    #[test]
    fn a_progress_line_is_dropped() {
        let text = normalize(
            b"Receiving objects 12.3 kB/s\ndone\n",
            &BTreeMap::new(),
            false,
        );
        assert_eq!(text, "done\n");
    }

    // --- `checksum-agreement` ------------------------------------------------
    //
    // No cell names this oracle before `commit --timestamp` makes a commit
    // reproducible (`docs/conformance/harness.md`, "Availability by
    // sub-phase"), so these three tests are the resolution path's only guard.
    // They stand in for the implementation with a script that answers the way
    // `rev-parse` does, which keeps the harness's own no-linkage rule.

    /// A directory of this test's own, empty at the start of each run.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-conformance-oracle-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        dir
    }

    /// A handle to a script that records the arguments it received in
    /// `<dir>/argv` and prints `checksum` the way `rev-parse` does.
    fn rev_parse_stub(dir: &Path, checksum: &str) -> Tool {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("stub");
        let argv = dir.join("argv");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\necho {checksum}\n",
                argv.display()
            ),
        )
        .expect("write the stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("mark the stub executable");
        Tool { role: "port", path }
    }

    /// An outcome carrying `stdout` and nothing else.
    fn outcome(stdout: &[u8]) -> Outcome {
        Outcome {
            argv: vec!["stub".to_owned()],
            cwd: PathBuf::from("/"),
            status: Some(0),
            signal: None,
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            elapsed_ms: 0,
        }
    }

    #[test]
    fn a_printed_checksum_is_the_agreement_artifact() {
        let checksum = "b".repeat(64);
        let printed = outcome(format!("{checksum}\n").as_bytes());
        let bindings = BTreeMap::new();
        // The handle names no file, so reaching the fallback would report the
        // oracle unavailable instead.
        let tool = Tool {
            role: "port",
            path: PathBuf::from("/nonexistent-by-design"),
        };
        let value = checksum_agreement(&Side {
            tool: &tool,
            root: Path::new("/"),
            repo: None,
            bindings: &bindings,
            outcome: &printed,
            work: Path::new("/"),
            keep_checksums: true,
        });
        assert_eq!(value, Value::Text(format!("{checksum}\n")));
    }

    #[test]
    fn an_operation_printing_no_checksum_resolves_through_rev_parse() {
        let dir = scratch("fallback");
        let checksum = "c".repeat(64);
        let tool = rev_parse_stub(&dir, &checksum);
        let repo = dir.join("repo");
        let quiet = outcome(b"Deleting refs\n");

        // `$BRANCH` is resolved where a setup bound one, and `$REV` otherwise.
        for (name, revision) in [("BRANCH", "conformance"), ("REV", &checksum)] {
            let mut bindings = BTreeMap::new();
            bindings.insert(name.to_owned(), revision.to_string());
            let value = checksum_agreement(&Side {
                tool: &tool,
                root: &dir,
                repo: Some(repo.clone()),
                bindings: &bindings,
                outcome: &quiet,
                work: &dir,
                keep_checksums: true,
            });
            assert_eq!(value, Value::Text(format!("{checksum}\n")));
            assert_eq!(
                std::fs::read_to_string(dir.join("argv"))
                    .expect("the stub recorded its arguments")
                    .trim(),
                format!("--repo={} rev-parse {revision}", repo.display()),
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cell_binding_no_revision_leaves_the_oracle_unavailable() {
        let dir = scratch("unbound");
        let tool = rev_parse_stub(&dir, &"d".repeat(64));
        let quiet = outcome(b"");
        let bindings = BTreeMap::new();
        let value = checksum_agreement(&Side {
            tool: &tool,
            root: &dir,
            repo: Some(dir.join("repo")),
            bindings: &bindings,
            outcome: &quiet,
            work: &dir,
            keep_checksums: true,
        });
        assert!(
            matches!(value, Value::Unavailable(_)),
            "an unbound revision produced {value:?}"
        );
        assert!(
            !dir.join("argv").exists(),
            "the oracle ran the tool with no revision to resolve"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
