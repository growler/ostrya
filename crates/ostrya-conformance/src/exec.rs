//! Resolving the two implementation handles and running them.
//!
//! The harness links neither implementation. Every observation comes from a
//! process's exit status, its output, or the bytes it left on disk.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::tier;

/// One implementation handle.
#[derive(Clone, Debug)]
pub struct Tool {
    /// `port` or `reference`.
    pub role: &'static str,
    pub path: PathBuf,
}

/// Resolve a handle: the explicit path, then the environment variable, then a
/// `PATH` lookup of `name`.
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
    // Every invocation runs in a cell's scratch directory, so the handle must
    // hold an absolute path.
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

/// What one invocation produced.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    /// The exit status, or `None` when a signal ended the process.
    pub status: Option<i32>,
    /// The signal that ended the process, when one did.
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed_ms: u64,
}

impl Outcome {
    /// Whether the process ended by its own exit call.
    pub fn terminated_normally(&self) -> bool {
        self.signal.is_none()
    }

    /// The exit status as a report prints it.
    pub fn status_text(&self) -> String {
        match (self.status, self.signal) {
            (Some(code), _) => code.to_string(),
            (None, Some(signal)) => format!("signal {signal}"),
            (None, None) => "unknown".to_owned(),
        }
    }

    /// The command line as a report prints it.
    pub fn command_text(&self) -> String {
        self.argv.join(" ")
    }
}

/// The refusal an invocation earns when it would let an implementation resolve
/// the host's system repository, and `None` when it would not.
///
/// The reference tool resolves a repository from the current directory, then
/// `OSTREE_REPO`, then the compiled-in `tier::SYSTEM_REPO`. An invocation that
/// binds no repository therefore reaches the host's own system repository on a
/// host that carries one, and a writing subcommand acts on live state. The
/// check refuses that invocation.
///
/// The argv and the environment are read textually. The argv binds a
/// repository when an argument begins with `--repo=` and carries a value, or
/// when an argument equals `--repo` and another argument follows it. An argv
/// ending in a bare `--repo` is an uncertain reading, and the check refuses
/// where the reading is uncertain. The environment binds a repository when
/// `env` carries `OSTREE_REPO` with a value; `run` removes that variable from
/// the inherited environment, so the slice is the whole truth. `cwd` is read
/// from disk, since it is the first source in the chain and an invocation that
/// resolves there never reaches the third.
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

/// Whether the argv binds a repository. An argv ending in a bare `--repo`
/// reads as no binding, so the caller refuses it.
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

/// Whether `env` binds `OSTREE_REPO` to a value.
fn binds_repo_variable(env: &[(String, String)]) -> bool {
    env.iter()
        .any(|(key, value)| key == "OSTREE_REPO" && !value.is_empty())
}

/// Whether `directory` opens as a repository, by the rule
/// `docs/conformance/cli-surface.md` records for the tool's first `--repo`
/// source: the directory holds an `objects` directory and a `config` file
/// whose text carries a `[core]` section with a `mode` key. Anything less does
/// not open, so a directory that is only repository-shaped still refuses.
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

/// The locale every invocation runs under.
///
/// The encoding is part of the comparison, not only the language. GLib holds its
/// option-parser messages with U+201C and U+201D around the offending value and
/// converts them to the locale's charset on the way to stderr. Under `C` the
/// charset is ASCII, which cannot hold those characters, so a reference on a host
/// carrying locale data prints `?` where one on a host carrying none prints the
/// characters themselves. Pinning a UTF-8 locale keeps that conversion lossless,
/// so the reference renders the same bytes on either host and the port, which
/// writes UTF-8 throughout, matches it.
pub const LOCALE: &str = "C.UTF-8";

/// The reason the host resolves [`LOCALE`] to something other than UTF-8, and
/// `None` where it resolves it to UTF-8.
///
/// A host missing the locale falls back to ASCII, where GLib prints `?` for the
/// characters it cannot hold. That would read as a difference in the message
/// text rather than as the missing locale it is, so the caller reports it once
/// ahead of the cells instead of leaving it to surface in every cell that quotes
/// a value.
///
/// `locale charmap` names the codeset the locale resolves to, which is what GLib
/// converts its messages into. A host where `locale` cannot be run states
/// nothing either way and is left alone.
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

/// Run `tool` with `args` in `cwd`.
///
/// `OSTREE_REPO` is removed unless `env` sets it, so the current-directory and
/// environment fallbacks a cell exercises are the cell's own doing. `G_DEBUG`
/// is removed, so a `fatal-criticals` or `fatal-warnings` setting on the
/// operator's host cannot turn a GLib critical in the reference into an abort.
/// `LC_ALL` is set to [`LOCALE`] so the two implementations' messages compare in
/// one language and one encoding.
///
/// The run is refused, before the process starts, when `system_repo_refusal`
/// reads the invocation as one that resolves the host's system repository.
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

    /// The host fact is injected, so these run on a host with or without a
    /// system repository.
    fn present() -> Option<&'static Path> {
        Some(Path::new(tier::SYSTEM_REPO))
    }

    /// A working directory that does not open as a repository, so the cases
    /// below turn on the argv and the environment alone.
    fn elsewhere() -> &'static Path {
        Path::new("/ostrya-conformance-no-such-directory")
    }

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    /// A directory of this test's own, empty at the start of each run.
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
        // Repository-shaped and no more: the `objects` directory is there, and
        // the `config` states no `[core]` section with a `mode` key.
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
