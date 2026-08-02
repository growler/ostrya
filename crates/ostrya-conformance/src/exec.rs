//! Resolving the two implementation handles and running them.
//!
//! The harness links neither implementation. Every observation comes from a
//! process's exit status, its output, or the bytes it left on disk.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

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

/// Run `tool` with `args` in `cwd`.
///
/// `OSTREE_REPO` is removed unless `env` sets it, so the current-directory and
/// environment fallbacks a cell exercises are the cell's own doing. `LC_ALL`
/// is set to `C` so the two implementations' messages compare in one language.
pub fn run(
    tool: &Tool,
    cwd: &Path,
    args: &[String],
    env: &[(String, String)],
) -> Result<Outcome, String> {
    use std::os::unix::process::ExitStatusExt;

    let started = Instant::now();
    let output = Command::new(&tool.path)
        .current_dir(cwd)
        .args(args.iter().map(OsStr::new))
        .env_remove("OSTREE_REPO")
        .env("LC_ALL", "C")
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
