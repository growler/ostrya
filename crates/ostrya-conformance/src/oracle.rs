//! The oracles a record names.
//!
//! [`ORACLES`] names each oracle, and [`apply`] runs one oracle on one
//! [`Side`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::exec::{self, Outcome, Tool};
use crate::sha256;

/// The names of all oracles.
///
/// An oracle reads the state of one [`Side`] after the invocation of a cell
/// and gives a text. The set is closed. A record that names an oracle states
/// that the texts of the two sides are equal.
/// [`runner::run`](crate::runner::run) compares the two texts.
///
/// # Oracles
///
/// - `exit-status`: the exit status of the invocation as one line. This is
///   the exit code, `signal N`, or `unknown`.
/// - `stdout-text` and `stderr-text`: the standard output or the standard
///   error of the invocation, after [`normalize`].
/// - `config-bytes`: the text of the `config` file of the repository, with
///   no change.
/// - `refs-bytes`: one line for each file under `refs/`, sorted. A line
///   holds the relative path and the content of the file, trimmed.
/// - `inventory`: one line for each file under `objects/`, sorted. A line
///   holds the relative path, the file name extension, and the size in bytes.
/// - `manifest`: one line for each path of a checkout of the commit of the
///   cell.
/// - `checksum-agreement`: the commit checksum that the operation made, as
///   one line.
/// - `fsck`: the exit status of `fsck` on the repository, as `exit N`.
///
/// The walks of `refs-bytes` and `inventory` do not enter a symbolic link to
/// a directory. If `refs/` or `objects/` does not exist, the text is empty.
///
/// # The `refs-bytes` oracle
///
/// The content of each ref file goes through the same substitution as
/// [`normalize`]. The value of a bound placeholder becomes its name, so the
/// branch ref reads `$REV`. Each other 64-character checksum becomes
/// `<checksum>`, unless [`Side::keep_checksums`] is `true`.
///
/// The mask is necessary because each side makes its own commits, and
/// neither side gives a timestamp. So the commit checksums of the two sides
/// differ by the wall-clock time.
///
/// # The `manifest` oracle
///
/// The oracle checks out `$REV`, or `$BRANCH` if no setup bound `$REV`. It
/// runs `checkout` of the implementation of the side into
/// `manifest-checkout` in [`Side::work`], and removes an earlier checkout
/// first. Each path of the checkout, directories included, gives one line,
/// sorted by path. A line holds these fields, separated by spaces:
///
/// - the relative path
/// - the kind: `dir`, `link`, or `file`
/// - the permission bits as four octal digits
/// - the uid and the gid
/// - the extended attributes in brackets, sorted, each one as `name=` and the
///   SHA-256 digest of the value
/// - `-` for a directory, the target for a link, or the SHA-256 digest of the
///   content for a file.
///
/// If a link target, a digest, or an attribute value cannot be read, the
/// field is `?`. The oracle reads at most 64 KiB of attribute names for each
/// path, and at most 64 KiB for each attribute value.
///
/// # The `checksum-agreement` oracle
///
/// If the last line of the standard output of the invocation is a
/// 64-character hex checksum, the oracle gives that line. A commit prints its
/// checksum there. If not, the oracle runs `rev-parse` of the implementation of the side on
/// `$BRANCH`, or on `$REV` if no setup bound `$BRANCH`. The oracle then gives
/// the checksum that `rev-parse` prints.
///
/// # The `fsck` oracle
///
/// Each implementation runs its own `fsck` on its own repository. The
/// compared text is the exit status alone. The two implementations write
/// different progress and summary lines, and the cell states only that both
/// find the repository sound. The oracle writes the output to `fsck.stdout`
/// and `fsck.stderr` in [`Side::work`] for diagnosis.
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

/// Returns `true` if `name` is in [`ORACLES`].
pub fn is_registered(name: &str) -> bool {
    ORACLES.contains(&name)
}

/// The result of one oracle for one side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// The text to compare.
    Text(String),
    /// The reason why the oracle cannot read this side.
    ///
    /// If one side is `Unavailable`, and no claim and no other oracle of the
    /// cell fails, [`runner::run`](crate::runner::run) reports a skip. This is
    /// the result when an oracle runs a command that the side does not have.
    Unavailable(String),
}

/// The state of one side of a cell after the invocation.
///
/// A side is one of the two implementations in one cell, with its own
/// scratch root.
pub struct Side<'a> {
    /// The implementation of this side.
    pub tool: &'a Tool,
    /// The scratch root of this side.
    ///
    /// Each command that an oracle runs has this working directory.
    pub root: &'a Path,
    /// The repository that the oracles read, if the setups bound one.
    pub repo: Option<PathBuf>,
    /// The setup bindings that the cell resolved.
    pub bindings: &'a BTreeMap<String, String>,
    /// The outcome of the invocation of the cell.
    pub outcome: &'a Outcome,
    /// A directory where an oracle can write scratch files of its own.
    pub work: &'a Path,
    /// The flag that is `true` if the cell compares checksums.
    ///
    /// If it is `true`, [`normalize`] and the `refs-bytes` oracle do not
    /// replace checksums with `<checksum>`.
    pub keep_checksums: bool,
}

impl Side<'_> {
    fn repo(&self) -> Result<&Path, Value> {
        self.repo
            .as_deref()
            .ok_or_else(|| Value::Unavailable("the cell's setups bound no repository".to_owned()))
    }
}

/// Runs the oracle `name` on one side and returns its value.
///
/// [`ORACLES`] states what each oracle gives. The value is
/// [`Value::Unavailable`] in these cases:
///
/// - `name` is not in [`ORACLES`].
/// - The oracle reads the repository, and the `repo` field of the side is
///   `None`.
/// - The oracle needs a placeholder that the setups did not bind.
/// - The `config` file cannot be read, or a directory that the oracle lists
///   cannot be read.
/// - [`exec::run`] refuses a command of the oracle, or the command
///   cannot start.
/// - `checkout` or `rev-parse` exits with a status other than 0.
/// - `rev-parse` prints no checksum.
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

/// Returns the `refs-bytes` text: each path under `refs/`, sorted, with the
/// content of the ref file.
///
/// The doc of `ORACLES` states the substitution and the checksum mask, and
/// the reason for the mask.
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

/// Checks out the commit of the cell and returns one line for each path.
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

/// Returns the commit checksum that the operation made.
///
/// A commit prints the checksum as the last line of its standard output, so
/// the oracle reads it there for a commit cell. For other operations, the
/// oracle runs `rev-parse` on the revision that the setups of the cell bound.
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

/// Returns the last line of `stdout` if it is a bare 64-character hex
/// checksum. The line ends with a newline, so the text compares as one line.
fn checksum_line(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let line = text.lines().map(str::trim).next_back()?;
    (line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit())).then(|| format!("{line}\n"))
}

/// Runs `fsck` of the implementation of the side on its own repository and
/// returns the exit status.
///
/// The two implementations write different progress and summary lines. The
/// cell states only that both find the repository sound. So the output goes
/// to the work directory of the side for diagnosis.
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

/// Returns the extended attributes of one path as a sorted `name=value` list.
/// The value is its SHA-256 digest, or `?` if it cannot be read.
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

/// Returns each path under `root` that is not a directory. The list is empty
/// if `root` does not exist.
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

/// Returns each path under `root`, directories included.
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

/// Returns captured output in the form that an oracle compares.
///
/// The function decodes `bytes` as UTF-8 with lossy replacement, then does
/// these steps in this order:
///
/// 1. It changes each `\r\n` and each `\r` to `\n`.
/// 2. It replaces the value of each placeholder in `bindings` with `$NAME`.
///    It replaces the longest value first, so a value that holds another
///    value changes as one unit. It ignores an empty value.
/// 3. It removes each progress line.
/// 4. It removes the white space at the end of each line.
/// 5. If `keep_checksums` is `false`, it replaces each run of exactly 64
///    lowercase hex characters with `<checksum>`. A shorter or a longer run
///    stays.
/// 6. It ends each line with `\n`.
///
/// # Progress lines
///
/// The check ignores case. A line is a progress line if it starts with
/// `fsck objects (`, or contains `elapsed`, or contains one of these rates:
/// `b/s`, `kb/s`, `mb/s`, `gb/s`, `kib/s`, `mib/s`. The `ostree` command
/// writes the `fsck objects (` progress line, and `ostrya` does not.
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

/// Replaces the value of each bound placeholder with its name. The longest
/// value goes first, so a value that holds another value changes as one unit.
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

/// Returns `true` if one line reports progress.
///
/// A rate or an elapsed time marks a progress line. `fsck` has its own
/// progress line, `fsck objects (`, which the `ostree` command writes and
/// `ostrya` does not.
fn is_progress(line: &str) -> bool {
    let lowered = line.to_ascii_lowercase();
    lowered.starts_with("fsck objects (")
        || lowered.contains("elapsed")
        || ["b/s", "kb/s", "mb/s", "gb/s", "kib/s", "mib/s"]
            .iter()
            .any(|rate| lowered.contains(rate))
}

/// Replaces each run of exactly 64 lowercase hex characters with
/// `<checksum>`.
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
    // These three tests check how the oracle finds the checksum. A script
    // that answers as `rev-parse` does stands in for the implementation, so
    // this crate links no implementation.

    /// Returns a directory for one test, empty at the start of each run.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-conformance-oracle-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        dir
    }

    /// Returns a handle to a script. The script records its arguments in
    /// `<dir>/argv` and prints `checksum` as `rev-parse` does.
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

    /// Returns an outcome with `stdout` and no other output.
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
        // The handle names no file. If the oracle runs `rev-parse`, the value
        // is `Unavailable` and the assertion fails.
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

        // The oracle resolves `$BRANCH` if a setup bound it, and `$REV` if
        // not.
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
