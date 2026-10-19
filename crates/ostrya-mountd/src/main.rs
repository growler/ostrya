#![forbid(unsafe_code)]

//! `ostrya-mountd`, the mount daemon of ostrya.
//!
//! The daemon mounts a commit of an ostrya repository as a composefs tree
//! for a caller without `CAP_SYS_ADMIN` in the initial user namespace. It
//! serves the requests of the `Helper` client of `ostrya-mount` over a
//! `SOCK_SEQPACKET` Unix socket, one request for each connection, one
//! connection at a time.
//!
//! The process runs in one of three modes:
//!
//! - systemd socket activation with `Accept=no`: systemd passes the
//!   listening socket. The daemon accepts connections and exits after the
//!   idle timeout.
//! - systemd socket activation with `Accept=yes`: systemd passes one
//!   connection. The daemon serves it and exits.
//! - standalone, with `--listen`: the daemon creates the socket, accepts
//!   connections, and exits after the idle timeout or when the process of
//!   `--parent-pid` exits.
//!
//! The hidden option `--worker` runs one request as the worker process of
//! the daemon. The connection handler starts the worker with the channel on
//! its standard input.

use std::ffi::OsString;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use ostrya_mount::Mounter;
use ostrya_mount::server::{Server, worker_main};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{AtFlags, CWD, FileType, Mode, chmodat, statat, unlinkat};
use rustix::io::Errno;
use rustix::net::sockopt::{socket_acceptconn, socket_type};
use rustix::net::{
    AddressFamily, SocketAddrUnix, SocketFlags, SocketType, accept_with, bind, listen, socket_with,
};
use rustix::process::{Pid, PidfdFlags, pidfd_open};

#[cfg(test)]
mod man;

/// The program of the worker process: this binary.
const WORKER_PROGRAM: &str = "/proc/self/exe";

/// The option that runs the worker.
const WORKER_FLAG: &str = "--worker";

/// The exit status of a usage error.
const USAGE_ERROR: u8 = 2;

/// The default largest size of a built image, in bytes: 100 MiB.
const DEFAULT_MAX_IMAGE_SIZE: u64 = 100 * 1024 * 1024;

/// The command line of `ostrya-mountd`.
#[derive(Debug, Parser)]
#[command(
    name = "ostrya-mountd",
    version,
    about = "Mount composefs trees of ostrya repositories for unprivileged callers",
    long_about = "Mount composefs trees of ostrya repositories for unprivileged callers.\n\n\
        ostrya-mountd mounts a commit of an ostrya repository as a composefs tree \
        for a caller in its own user namespace. The caller is the `Helper` client of \
        the ostrya-mount library. It connects to the socket of the daemon and sends \
        the repository path, the commit, the target path, and descriptors of its \
        user namespace and its mount namespace. The daemon mounts the tree, moves \
        the mount onto the target in the mount namespace of the caller, and sends \
        back a descriptor of the root of the mount.\n\n\
        The daemon must run as root in the initial user namespace. Systemd starts \
        it through socket activation, or a parent process starts it with --listen."
)]
struct Cli {
    /// Create a socket at PATH and serve it (standalone mode).
    ///
    /// The daemon refuses PATH if a file that is not a socket is there. It
    /// removes an old socket at PATH, binds a new `SOCK_SEQPACKET` socket,
    /// gives it the mode 0666, and removes it when it exits. The option is
    /// refused when `LISTEN_PID` or `LISTEN_FDS` is set.
    #[arg(long, value_name = "PATH")]
    listen: Option<PathBuf>,
    /// Exit when the process PID exits (standalone mode).
    ///
    /// The daemon watches the process through a pidfd. It exits with status 1
    /// when the process exits. The option needs --listen.
    #[arg(
        long,
        value_name = "PID",
        requires = "listen",
        value_parser = clap::value_parser!(i32).range(1..)
    )]
    parent_pid: Option<i32>,
    /// Exit after SECS seconds with no connection.
    ///
    /// The time starts again after each connection. The option applies to the
    /// standalone mode and to socket activation with `Accept=no`.
    #[arg(
        long,
        value_name = "SECS",
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    idle_timeout: u64,
    /// Refuse to build an image larger than BYTES bytes.
    ///
    /// A request for a built image fails with the code `repository` if the
    /// image is larger. The daemon computes the size before it writes the
    /// image, so a refused image takes no memory. The limit does not apply
    /// to a stored image. The default is 100 MiB.
    #[arg(
        long,
        value_name = "BYTES",
        default_value_t = DEFAULT_MAX_IMAGE_SIZE,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    max_image_size: u64,
    /// Run one request as the worker process of the daemon.
    #[arg(long, hide = true, conflicts_with_all = ["listen", "parent_pid"])]
    worker: bool,
}

/// The source of the connections of the daemon.
#[derive(Debug, PartialEq, Eq)]
enum Source {
    /// The socket that systemd passes.
    Systemd,
    /// A socket that the daemon creates at `listen`.
    Standalone {
        /// The path of the socket.
        listen: PathBuf,
        /// The process whose exit stops the daemon.
        parent_pid: Option<i32>,
    },
}

/// The values of the socket activation variables of systemd.
#[derive(Debug, Default)]
struct ListenEnv {
    /// `LISTEN_PID`.
    pid: Option<OsString>,
    /// `LISTEN_FDS`.
    fds: Option<OsString>,
}

impl ListenEnv {
    /// Reads the two variables from the environment of the process.
    fn from_env() -> ListenEnv {
        ListenEnv {
            pid: std::env::var_os("LISTEN_PID"),
            fds: std::env::var_os("LISTEN_FDS"),
        }
    }
}

/// Selects the source of the connections from the options and the
/// socket activation variables of the process `own_pid`.
fn select_source(
    listen: Option<&Path>,
    parent_pid: Option<i32>,
    env: &ListenEnv,
    own_pid: u32,
) -> Result<Source, String> {
    if env.pid.is_some() || env.fds.is_some() {
        if listen.is_some() {
            return Err("--listen is refused when LISTEN_PID or LISTEN_FDS is set".to_owned());
        }
        if parent_pid.is_some() {
            return Err("--parent-pid needs --listen".to_owned());
        }
        let pid_ok = env
            .pid
            .as_deref()
            .and_then(|p| p.to_str())
            .and_then(|p| p.parse::<u32>().ok())
            == Some(own_pid);
        if !pid_ok {
            return Err("LISTEN_PID is not the process id of the daemon".to_owned());
        }
        if env.fds.as_deref() != Some("1".as_ref()) {
            return Err("LISTEN_FDS must be 1".to_owned());
        }
        return Ok(Source::Systemd);
    }
    match (listen, parent_pid) {
        (Some(listen), parent_pid) => Ok(Source::Standalone {
            listen: listen.to_owned(),
            parent_pid,
        }),
        (None, Some(_)) => Err("--parent-pid needs --listen".to_owned()),
        (None, None) => Err(
            "no socket: start the daemon through systemd socket activation, or give --listen"
                .to_owned(),
        ),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // The daemon starts the worker after its own check. A worker that runs
    // with no privilege fails at its first namespace step.
    if cli.worker {
        return worker();
    }
    if !Mounter::is_privileged() {
        eprintln!("ostrya-mountd: the daemon must run as root in the initial user namespace");
        return ExitCode::FAILURE;
    }
    let source = match select_source(
        cli.listen.as_deref(),
        cli.parent_pid,
        &ListenEnv::from_env(),
        std::process::id(),
    ) {
        Ok(source) => source,
        Err(text) => {
            eprintln!("ostrya-mountd: {text}");
            return ExitCode::from(USAGE_ERROR);
        }
    };
    let server = match Server::new(
        PathBuf::from(WORKER_PROGRAM),
        vec![WORKER_FLAG.into()],
        cli.max_image_size,
    ) {
        Ok(server) => server,
        Err(text) => {
            eprintln!("ostrya-mountd: {text}");
            return ExitCode::FAILURE;
        }
    };
    let idle = Duration::from_secs(cli.idle_timeout);
    let result = match source {
        Source::Systemd => systemd(&server, idle),
        Source::Standalone { listen, parent_pid } => standalone(&server, &listen, parent_pid, idle),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(text) => {
            eprintln!("ostrya-mountd: {text}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the worker on the channel on standard input.
fn worker() -> ExitCode {
    let channel = match std::io::stdin().as_fd().try_clone_to_owned() {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("ostrya-mountd worker: standard input: {e}");
            return ExitCode::FAILURE;
        }
    };
    match worker_main(channel) {
        Ok(()) => ExitCode::SUCCESS,
        Err(text) => {
            eprintln!("ostrya-mountd worker: {text}");
            ExitCode::FAILURE
        }
    }
}

/// Serves the socket that systemd passes: an accept loop for a listening
/// socket, or one connection.
fn systemd(server: &Server, idle: Duration) -> Result<(), String> {
    let fd = ostrya_sys::systemd_listen_fd()
        .map_err(|e| format!("take the socket of systemd: {e}"))?
        .ok_or("systemd passed no socket")?;
    match socket_type(&fd) {
        Ok(SocketType::SEQPACKET) => {}
        Ok(_) => return Err("the socket of systemd is not a SOCK_SEQPACKET socket".to_owned()),
        Err(e) => return Err(format!("the descriptor of systemd is not a socket: {e}")),
    }
    let listening = socket_acceptconn(&fd).map_err(|e| format!("SO_ACCEPTCONN: {e}"))?;
    if listening {
        accept_loop(server, &fd, None, idle).map(|_| ())
    } else {
        serve_one(server, fd)
    }
}

/// Creates the socket at `path` and serves it until the idle timeout or
/// the exit of the process `parent_pid`. Removes the socket at the end.
fn standalone(
    server: &Server,
    path: &Path,
    parent_pid: Option<i32>,
    idle: Duration,
) -> Result<(), String> {
    let parent = parent_pid
        .map(|pid| {
            let pid = Pid::from_raw(pid).ok_or("the parent process id is not valid")?;
            pidfd_open(pid, PidfdFlags::empty())
                .map_err(|e| format!("watch the parent process {pid}: {e}"))
        })
        .transpose()?;
    let listener = bind_listener(path)?;
    let result = accept_loop(server, &listener, parent.as_ref(), idle);
    let _ = unlinkat(CWD, path, AtFlags::empty());
    match result? {
        LoopEnd::Idle => Ok(()),
        LoopEnd::ParentExited => Err("the parent process exited".to_owned()),
    }
}

/// Creates a `SOCK_SEQPACKET` socket at `path` with the mode 0666 and a
/// backlog of 1. An old socket at `path` is removed first. Another file at
/// `path` is refused.
fn bind_listener(path: &Path) -> Result<OwnedFd, String> {
    match statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Socket => {
            unlinkat(CWD, path, AtFlags::empty())
                .map_err(|e| format!("remove the old socket {}: {e}", path.display()))?;
        }
        Ok(_) => return Err(format!("{} exists and is not a socket", path.display())),
        Err(Errno::NOENT) => {}
        Err(e) => return Err(format!("stat {}: {e}", path.display())),
    }
    let sock = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|e| format!("socket: {e}"))?;
    let addr = SocketAddrUnix::new(path).map_err(|e| format!("{}: {e}", path.display()))?;
    bind(&sock, &addr).map_err(|e| format!("bind {}: {e}", path.display()))?;
    chmodat(CWD, path, Mode::from_raw_mode(0o666), AtFlags::empty())
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    listen(&sock, 1).map_err(|e| format!("listen: {e}"))?;
    Ok(sock)
}

/// How an accept loop ends.
#[derive(Debug, PartialEq, Eq)]
enum LoopEnd {
    /// No connection came in the idle time.
    Idle,
    /// The parent process exited.
    ParentExited,
}

/// Accepts the connections of `listener` and serves each one in turn. The
/// loop ends when no connection comes for `idle`, or when `parent` becomes
/// readable, which a pidfd does when its process exits.
fn accept_loop(
    server: &Server,
    listener: &OwnedFd,
    parent: Option<&OwnedFd>,
    idle: Duration,
) -> Result<LoopEnd, String> {
    let timeout = Timespec {
        tv_sec: i64::try_from(idle.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: 0,
    };
    loop {
        let mut fds = vec![PollFd::new(listener, PollFlags::IN)];
        if let Some(parent) = parent {
            fds.push(PollFd::new(parent, PollFlags::IN));
        }
        let ready = match poll(&mut fds, Some(&timeout)) {
            Ok(n) => n,
            Err(Errno::INTR) => continue,
            Err(e) => return Err(format!("poll: {e}")),
        };
        if ready == 0 {
            return Ok(LoopEnd::Idle);
        }
        if fds.get(1).is_some_and(|p| !p.revents().is_empty()) {
            return Ok(LoopEnd::ParentExited);
        }
        if fds[0].revents().is_empty() {
            continue;
        }
        drop(fds);
        let conn = match accept_with(listener, SocketFlags::CLOEXEC) {
            Ok(conn) => conn,
            Err(Errno::INTR | Errno::AGAIN | Errno::CONNABORTED) => continue,
            Err(e) => return Err(format!("accept: {e}")),
        };
        // A failed request is logged, and the loop serves the next one.
        let _ = serve_one(server, conn);
    }
}

/// Serves the one request of the connection `conn` and logs the result.
fn serve_one(server: &Server, conn: OwnedFd) -> Result<(), String> {
    match ostrya_rt::block_on(server.serve(conn)) {
        Ok(()) => {
            eprintln!("ostrya-mountd: the request is served");
            Ok(())
        }
        Err(text) => {
            eprintln!("ostrya-mountd: the request failed: {text}");
            Err(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn env(pid: Option<&str>, fds: Option<&str>) -> ListenEnv {
        ListenEnv {
            pid: pid.map(OsString::from),
            fds: fds.map(OsString::from),
        }
    }

    #[test]
    fn the_command_line_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn systemd_variables_select_socket_activation() {
        let none = env(Some("42"), Some("1"));
        assert_eq!(select_source(None, None, &none, 42), Ok(Source::Systemd));
    }

    #[test]
    fn listen_selects_the_standalone_mode() {
        let source = select_source(Some(Path::new("/run/x.sock")), Some(7), &env(None, None), 1);
        assert_eq!(
            source,
            Ok(Source::Standalone {
                listen: PathBuf::from("/run/x.sock"),
                parent_pid: Some(7),
            })
        );
    }

    #[test]
    fn each_wrong_combination_is_refused() {
        let refuse = |listen: Option<&str>, parent: Option<i32>, e: ListenEnv, what: &str| {
            let err = select_source(listen.map(Path::new), parent, &e, 42).unwrap_err();
            assert!(err.contains(what), "{err}");
        };
        refuse(
            Some("/s"),
            None,
            env(Some("42"), Some("1")),
            "--listen is refused",
        );
        refuse(
            Some("/s"),
            None,
            env(None, Some("1")),
            "--listen is refused",
        );
        refuse(
            None,
            Some(3),
            env(Some("42"), Some("1")),
            "--parent-pid needs",
        );
        refuse(None, Some(3), env(None, None), "--parent-pid needs");
        refuse(None, None, env(Some("41"), Some("1")), "LISTEN_PID");
        refuse(None, None, env(None, Some("1")), "LISTEN_PID");
        refuse(
            None,
            None,
            env(Some("42"), Some("2")),
            "LISTEN_FDS must be 1",
        );
        refuse(None, None, env(Some("42"), None), "LISTEN_FDS must be 1");
        refuse(None, None, env(None, None), "no socket");
    }

    #[test]
    fn clap_refuses_the_conflicting_options() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["ostrya-mountd"], args].concat());
        assert!(parse(&["--parent-pid", "1"]).is_err());
        assert!(parse(&["--worker", "--listen", "/s"]).is_err());
        assert!(parse(&["--listen", "/s", "--idle-timeout", "0"]).is_err());
        assert!(parse(&["--listen", "/s", "--parent-pid", "0"]).is_err());
        let cli = parse(&["--listen", "/s", "--parent-pid", "9"]).unwrap();
        assert_eq!(cli.idle_timeout, 300);
        assert_eq!(cli.parent_pid, Some(9));
        assert_eq!(cli.max_image_size, 104_857_600);
        assert!(parse(&["--listen", "/s", "--max-image-size", "0"]).is_err());
        let cli = parse(&["--listen", "/s", "--max-image-size", "4096"]).unwrap();
        assert_eq!(cli.max_image_size, 4096);
        assert!(parse(&["--worker"]).unwrap().worker);
    }
}
