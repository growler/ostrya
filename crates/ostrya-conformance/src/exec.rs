//! The resolution of the two implementations, and the run of one invocation.
//!
//! This crate links neither implementation. Each observation comes from the
//! exit status of a process, its output, or the bytes that it left on disk.
//! [`resolve`] finds an implementation, and [`run`] runs one invocation.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::tier;

/// A resolved implementation: its role and the path of its executable.
#[derive(Clone, Debug)]
pub struct Tool {
    /// The role: `port` for the `ostrya` binary, or `reference` for the
    /// `ostree` command.
    pub role: &'static str,
    /// The executable that this role runs.
    ///
    /// [`resolve`] canonicalizes the path if it can.
    pub path: PathBuf,
}

/// Returns the implementation for `role`, or `None` if no executable is found.
///
/// The function takes the first candidate from these sources, in this order:
///
/// 1. `explicit`, if it is `Some`.
/// 2. The value of the environment variable `variable`, if it is set.
/// 3. The first executable file `name` in the directories of `PATH`.
///
/// An executable file is a regular file with at least one execute permission
/// bit. The function checks only the first candidate. If this candidate is not
/// an executable file, the function returns `None` and does not try the next
/// source.
///
/// If possible, the function canonicalizes the path, because each invocation
/// runs in the scratch directory of a cell.
pub fn resolve(
    role: &'static str,
    explicit: Option<&Path>,
    variable: &str,
    name: &str,
) -> Option<Tool> {
    let candidate = explicit
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os(variable).map(PathBuf::from))
        .or_else(|| search_path(name))?;
    if !executable(&candidate) {
        return None;
    }
    // Each invocation runs in the scratch directory of a cell, so the handle
    // must hold an absolute path.
    let path = std::fs::canonicalize(&candidate).unwrap_or(candidate);
    Some(Tool { role, path })
}

fn search_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| executable(candidate))
}

fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// The result of one invocation.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// The argument vector, with the path of the program first.
    pub argv: Vec<String>,
    /// The working directory of the process.
    pub cwd: PathBuf,
    /// The exit status, or `None` if a signal ended the process.
    pub status: Option<i32>,
    /// The signal that ended the process, or `None` if no signal ended it.
    pub signal: Option<i32>,
    /// The bytes that the process wrote to standard output.
    pub stdout: Vec<u8>,
    /// The bytes that the process wrote to standard error.
    pub stderr: Vec<u8>,
    /// The duration of the run, in milliseconds.
    pub elapsed_ms: u64,
}

impl Outcome {
    /// Returns `true` if no signal ended the process.
    pub fn terminated_normally(&self) -> bool {
        self.signal.is_none()
    }

    /// Returns the exit status as text for a report.
    ///
    /// The text is the exit code, or `signal N` if a signal ended the process.
    /// If neither is known, the text is `unknown`.
    pub fn status_text(&self) -> String {
        match (self.status, self.signal) {
            (Some(code), _) => code.to_string(),
            (None, Some(signal)) => format!("signal {signal}"),
            (None, None) => "unknown".to_owned(),
        }
    }

    /// Returns the command line as text for a report.
    ///
    /// One space separates two arguments.
    pub fn command_text(&self) -> String {
        self.argv.join(" ")
    }
}

/// Returns a refusal message if the invocation can reach the system repository.
///
/// `system_repo` is the system repository of the host, or `None` if the host
/// has none. If it is `None`, or if the invocation binds a repository, the
/// function returns `None`.
///
/// # System repository
///
/// The `ostree` command resolves a repository from these sources, in this
/// order:
///
/// 1. The current directory.
/// 2. The environment variable `OSTREE_REPO`.
/// 3. The compiled-in path [`SYSTEM_REPO`](tier::SYSTEM_REPO).
///
/// If an invocation binds no repository, it reaches the system repository on a
/// host that has one. A subcommand that writes then changes live state. This
/// function refuses that invocation.
///
/// # Binding rules
///
/// The function reads `args` and `env` as text. It reads `cwd` from disk.
///
/// - `args` binds a repository if an argument starts with `--repo=` and has a
///   value.
/// - `args` also binds a repository if an argument is `--repo` and another
///   argument comes after it.
/// - If `args` ends with a bare `--repo`, the reading is uncertain, and
///   `args` binds no repository.
/// - `env` binds a repository if it sets `OSTREE_REPO` to a value that is not
///   empty. [`run`] removes `OSTREE_REPO` from the inherited environment, so
///   `env` is the only source of this variable.
/// - `cwd` binds a repository if it opens as a repository. The current
///   directory is the first source, so an invocation that resolves there never
///   reaches the third source.
///
/// A directory opens as a repository if it has an `objects` directory and a
/// `config` file with a `[core]` section that has a `mode` key. This is the
/// rule of the `ostree` command for its first source. If `cwd` has less than
/// this, it does not open, and `cwd` binds no repository.
pub fn system_repo_refusal(
    cwd: &Path,
    args: &[String],
    env: &[(String, String)],
    system_repo: Option<&Path>,
) -> Option<String> {
    let system_repo = system_repo?;
    if binds_repo_argument(args) || binds_repo_variable(env) || opens_as_repository(cwd) {
        return None;
    }
    Some(format!(
        "this invocation binds no repository, and the host carries {}, which \
         the reference tool resolves as its third `--repo` source: the run \
         would act on the host's own system repository",
        system_repo.display()
    ))
}

/// Returns `true` if the argv binds a repository. If the argv ends with a bare
/// `--repo`, the function returns `false`, so the caller refuses it.
fn binds_repo_argument(args: &[String]) -> bool {
    let mut rest = args.iter();
    while let Some(argument) = rest.next() {
        if let Some(value) = argument.strip_prefix("--repo=") {
            if !value.is_empty() {
                return true;
            }
        } else if argument == "--repo" && rest.next().is_some() {
            return true;
        }
    }
    false
}

/// Returns `true` if `env` binds `OSTREE_REPO` to a value that is not empty.
fn binds_repo_variable(env: &[(String, String)]) -> bool {
    env.iter()
        .any(|(key, value)| key == "OSTREE_REPO" && !value.is_empty())
}

/// Returns `true` if `directory` opens as a repository by the rule of the
/// first source of the `ostree` command.
///
/// The directory must have an `objects` directory and a `config` file with a
/// `[core]` section that has a `mode` key. A directory with less than this
/// does not open, so the caller refuses a directory that only looks like a
/// repository.
fn opens_as_repository(directory: &Path) -> bool {
    if !directory.join("objects").is_dir() {
        return false;
    }
    let Ok(config) = std::fs::read_to_string(directory.join("config")) else {
        return false;
    };
    let mut in_core = false;
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_core = line.trim_end_matches(|c: char| c == ';' || c.is_whitespace()) == "[core]";
            continue;
        }
        if in_core
            && let Some((key, _)) = line.split_once('=')
            && key.trim() == "mode"
        {
            return true;
        }
    }
    false
}

/// The locale of each invocation.
///
/// The comparison of messages covers their encoding and their language. GLib
/// puts U+201C and U+201D around the value that an option-parser message
/// quotes. It converts these characters to the charset of the locale when it
/// writes the message to stderr.
///
/// Under `C`, the charset is ASCII, and ASCII cannot hold these characters.
/// The `ostree` command then prints `?` on a host with locale data, and the
/// characters on a host with no locale data. A UTF-8 locale makes the
/// conversion lossless. The `ostree` command then writes the same bytes on
/// each host, and these bytes match the `ostrya` binary, which writes UTF-8 in
/// all output.
pub const LOCALE: &str = "C.UTF-8";

/// Returns a message if [`LOCALE`] does not resolve to UTF-8 on the host.
///
/// The function runs `locale charmap` with `LC_ALL` set to [`LOCALE`]. This
/// command names the codeset of the locale, and GLib converts its messages to
/// this codeset. If the codeset is UTF-8, the function returns `None`. If
/// `locale` cannot run or exits with a failure, the function also returns
/// `None`.
///
/// A host with no such locale falls back to ASCII, and GLib prints `?` for
/// each character that ASCII cannot hold. Each cell that quotes a value then
/// shows a difference in the message text, and the cause is the missing
/// locale. The caller reports the message one time, before the cells run.
pub fn locale_codeset_defect() -> Option<String> {
    let output = Command::new("locale")
        .arg("charmap")
        .env("LC_ALL", LOCALE)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    let codeset = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (output.status.success() && codeset != "UTF-8").then(|| {
        format!(
            "`LC_ALL={LOCALE}` resolves to the {codeset} codeset on this host, \
             so the reference renders the characters it cannot hold as `?` and a \
             message quoting a value compares as a text difference"
        )
    })
}

/// Runs `tool` with `args` in `cwd` and returns the [`Outcome`].
///
/// The function sets the environment of the process in this order:
///
/// 1. It removes `OSTREE_REPO`. The repository fallbacks of a cell (the
///    current directory and `OSTREE_REPO`) then come from the cell alone.
/// 2. It removes `G_DEBUG`. A `fatal-criticals` or `fatal-warnings` value on
///    the host of the operator then cannot turn a GLib critical in the
///    `ostree` command into an abort.
/// 3. It sets `LC_ALL` to [`LOCALE`], so the messages of the two
///    implementations compare in one language and one encoding.
/// 4. It applies `env`, so a variable in `env` replaces the values of the
///    earlier steps.
///
/// Standard input is null. The function captures standard output and standard
/// error.
///
/// # Errors
///
/// - The message of [`system_repo_refusal`] if the invocation can reach the
///   system repository of the host. The function checks this before the
///   process starts, with the result of [`system_repo`](tier::system_repo).
/// - An error with the text `spawning PATH: ...` if the process cannot start,
///   or if the wait for its output fails.
pub fn run(
    tool: &Tool,
    cwd: &Path,
    args: &[String],
    env: &[(String, String)],
) -> Result<Outcome, String> {
    use std::os::unix::process::ExitStatusExt;

    if let Some(message) = system_repo_refusal(cwd, args, env, tier::system_repo()) {
        return Err(message);
    }

    let started = Instant::now();
    let output = Command::new(&tool.path)
        .current_dir(cwd)
        .args(args.iter().map(OsStr::new))
        .env_remove("OSTREE_REPO")
        .env_remove("G_DEBUG")
        .env("LC_ALL", LOCALE)
        .envs(env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("spawning {}: {err}", tool.path.display()))?;

    let mut argv = vec![tool.path.display().to_string()];
    argv.extend(args.iter().cloned());
    Ok(Outcome {
        argv,
        cwd: cwd.to_path_buf(),
        status: output.status.code(),
        signal: output.status.signal(),
        stdout: output.stdout,
        stderr: output.stderr,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a system repository for the tests. The tests inject this host
    /// fact, so they run on a host with or without a system repository.
    fn present() -> Option<&'static Path> {
        Some(Path::new(tier::SYSTEM_REPO))
    }

    /// Returns a working directory that does not open as a repository. With
    /// it, the result of a test depends on the argv and the environment alone.
    fn elsewhere() -> &'static Path {
        Path::new("/ostrya-conformance-no-such-directory")
    }

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    /// Returns a scratch directory for one test, empty at the start of each
    /// run.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-conformance-exec-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        dir
    }

    #[test]
    fn a_repo_less_argv_is_refused_where_the_host_carries_a_system_repo() {
        let message = system_repo_refusal(elsewhere(), &argv(&["prune"]), &[], present())
            .expect("the invocation binds no repository");
        assert!(message.contains(tier::SYSTEM_REPO), "{message}");
    }

    #[test]
    fn an_argv_binding_the_repository_is_allowed() {
        assert!(
            system_repo_refusal(
                elsewhere(),
                &argv(&["--repo=/scratch/repo", "prune"]),
                &[],
                present()
            )
            .is_none()
        );
        assert!(
            system_repo_refusal(
                elsewhere(),
                &argv(&["prune", "--repo", "/scratch/repo"]),
                &[],
                present()
            )
            .is_none()
        );
    }

    #[test]
    fn a_trailing_bare_repo_flag_is_refused_as_an_uncertain_reading() {
        assert!(
            system_repo_refusal(elsewhere(), &argv(&["prune", "--repo"]), &[], present()).is_some()
        );
        assert!(
            system_repo_refusal(elsewhere(), &argv(&["--repo=", "prune"]), &[], present())
                .is_some()
        );
    }

    #[test]
    fn an_environment_binding_the_repository_is_allowed() {
        let env = [("OSTREE_REPO".to_owned(), "/scratch/repo".to_owned())];
        assert!(system_repo_refusal(elsewhere(), &argv(&["prune"]), &env, present()).is_none());

        let empty = [("OSTREE_REPO".to_owned(), String::new())];
        assert!(system_repo_refusal(elsewhere(), &argv(&["prune"]), &empty, present()).is_some());
    }

    #[test]
    fn a_repo_less_argv_is_allowed_where_the_host_carries_no_system_repo() {
        assert!(system_repo_refusal(elsewhere(), &argv(&["prune"]), &[], None).is_none());
    }

    #[test]
    fn a_repo_less_argv_whose_cwd_is_a_repository_is_allowed() {
        let dir = scratch("cwd-repo");
        std::fs::create_dir_all(dir.join("objects")).expect("create objects");
        std::fs::write(
            dir.join("config"),
            "[core]\nrepo_version=1\nmode=bare-user\n",
        )
        .expect("write config");

        assert!(system_repo_refusal(&dir, &argv(&["prune"]), &[], present()).is_none());
        std::fs::remove_dir_all(&dir).expect("remove the scratch directory");
    }

    #[test]
    fn a_repo_less_argv_whose_cwd_does_not_open_is_refused() {
        let dir = scratch("cwd-not-a-repo");
        // The directory looks like a repository and does not open. It has an
        // `objects` directory, and its `config` has no `[core]` section with a
        // `mode` key.
        std::fs::create_dir_all(dir.join("objects")).expect("create objects");
        std::fs::write(dir.join("config"), "[remote \"origin\"]\nurl=http://x/\n")
            .expect("write config");

        assert!(system_repo_refusal(&dir, &argv(&["prune"]), &[], present()).is_some());

        // The same directory with no `objects` and a complete `config` also
        // does not open.
        std::fs::remove_dir_all(dir.join("objects")).expect("remove objects");
        std::fs::write(dir.join("config"), "[core]\nmode=bare\n").expect("rewrite config");
        assert!(system_repo_refusal(&dir, &argv(&["prune"]), &[], present()).is_some());

        std::fs::remove_dir_all(&dir).expect("remove the scratch directory");
    }
}
