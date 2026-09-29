//! The transports a push session runs over.
//!
//! [`PushRemote`] is a parsed push address. [`PushSession::connect`] opens a
//! session to it with [`ConnectOptions`].
//!
//! # ssh
//!
//! The client runs the ssh client as a child process, and the remote side
//! runs the receive command. The frames of the session go over the standard
//! input and the standard output of the child. Its standard error is the
//! standard error of this process, so host key prompts, password prompts,
//! and the diagnostics of the server reach the user.
//!
//! The addresses are:
//!
//! - `ssh://[USER@]HOST[:PORT]/ABSOLUTE/PATH`.
//! - `ssh://[USER@]HOST[:PORT]/~/RELATIVE/PATH`. The client removes the `/~/`
//!   prefix and sends `RELATIVE/PATH`, which the remote side resolves in the
//!   home directory of the ssh session.
//! - `[USER@]HOST:PATH`, the scp form. `PATH` is relative to the remote home
//!   directory unless it starts with `/`. A leading `~/` is removed.
//!
//! After a `/~/` or a `~/` prefix, each leading `/` of the path is removed
//! too, so the path stays relative to the home directory.
//!
//! In the scp form, the first `:` ends the host, as git reads the form. So
//! `u:p@host:path` gives the host `u` and the path `p@host:path`, and the scp
//! form cannot give a user that holds `:`. An IPv6 host needs brackets:
//! `fe80::1:repo` gives the host `fe80`, and `[fe80::1]:repo` gives the host
//! `fe80::1`. ssh gets a bracketed host without the brackets.
//!
//! A user holds ASCII letters, digits, `.`, `-`, and `_` alone. A host holds
//! the same characters, or it is a bracketed IPv6 address of hex digits, `:`,
//! and `.`, with an optional `%ZONE` of ASCII letters and digits. So a
//! control character, whitespace, and a shell metacharacter in a user or a
//! host are refused. A user or a host that starts with `-` is refused, so no
//! part of an address reaches ssh as an option. An empty user, host, or
//! path, a port that is 0 or not a number, more than one `@`, a path of the
//! form `~` or `~USER`, and a scheme other than `ssh`, `http`, and `https`
//! are refused too. In the `ssh://` form, a `USER:PASSWORD@` user is
//! refused. The client does not decode percent escapes.
//!
//! On Windows, a scp-form address that names a local path is refused: one
//! whose host is one ASCII letter (`C:\repo`, `C:repo`), and one with a `\`
//! before the first `:` (`..\dir:x`, `\\?\C:\repo`). The `ssh://` form
//! carries a one-letter host.
//!
//! The command line is:
//!
//! ```text
//! SSH_COMMAND... [-p PORT] [USER@]HOST 'RECEIVE_COMMAND --repo=QUOTED_PATH'
//! ```
//!
//! The last argument is one string, which the remote shell parses. The path
//! is quoted with POSIX single quotes, so it gets no expansion.
//!
//! `SSH_COMMAND` comes from the first of these that is set:
//! [`ConnectOptions::ssh_command`], the `OSTRYA_SSH_COMMAND` environment
//! variable, and [`ConnectOptions::remote_ssh_command`]. With none, it is
//! `ssh`. The environment variable and `remote_ssh_command` are split at
//! ASCII whitespace, with no quoting rule. A command whose arguments hold
//! whitespace is set through `ssh_command`. `RECEIVE_COMMAND` is
//! [`ConnectOptions::receive_command`], or `ostrya receive`.
//!
//! # The end of an ssh session
//!
//! After a failed write, the session reads the message the server can have
//! sent before it closed, for at most five seconds. A server that closed its
//! input and keeps its output open with no message cannot hold the session.
//! When the time ends, the call returns the error of the write, or
//! [`Error::CommitOutcomeUnknown`] after `Commit`.
//!
//! [`commit`](PushSession::commit) and [`abort`](PushSession::abort) close the
//! standard input of the ssh client and then wait for it to exit, for at most
//! the same time. An open that fails waits in the same way. When the session
//! failed with an I/O error and the ssh client exited with a failure status,
//! the call returns [`Error::Transport`] with the status. A session that
//! committed returns its outcome, whatever the exit status. On every other
//! failure, the session drops the child without a wait: the child reads end
//! of file on its standard input and ends.
//!
//! # HTTP
//!
//! [`PushRemote::parse`] accepts an `http://` or `https://` address, and
//! [`PushSession::connect`] refuses it with [`Error::InvalidInput`]: the
//! crate has no HTTP transport yet.

mod ssh;

use std::fmt;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::session::{PushSession, SessionOptions};

pub(crate) use ssh::Transport;

/// The longest wait for a pending message after a failed write, and for the
/// exit of the ssh client, on a session that [`PushSession::connect`] opens.
const PENDING_READ_LIMIT: Duration = Duration::from_secs(5);

/// A push destination, parsed from an `ssh://` address, a `[USER@]HOST:PATH`
/// address, or an `http://` or `https://` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRemote {
    inner: RemoteAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RemoteAddr {
    Ssh(ssh::SshAddr),
    Http(String),
}

impl PushRemote {
    /// Parse `address`. An address that is not one of the forms of the
    /// module docs is [`Error::InvalidInput`].
    pub fn parse(address: &str) -> Result<PushRemote> {
        parse_remote(address, cfg!(windows))
    }
}

impl fmt::Display for PushRemote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            RemoteAddr::Ssh(addr) => addr.fmt(f),
            RemoteAddr::Http(url) => f.write_str(url),
        }
    }
}

/// Parse `address`, with the Windows rule for a one-letter host when
/// `windows` is true.
fn parse_remote(address: &str, windows: bool) -> Result<PushRemote> {
    let inner = if address.starts_with("http://") || address.starts_with("https://") {
        let rest = address.split_once("://").map_or("", |(_, rest)| rest);
        if rest.is_empty() {
            return Err(Error::InvalidInput(format!(
                "push address '{address}' names no host"
            )));
        }
        RemoteAddr::Http(address.to_owned())
    } else {
        RemoteAddr::Ssh(ssh::SshAddr::parse(address, windows)?)
    };
    Ok(PushRemote { inner })
}

/// How [`PushSession::connect`] reaches a remote.
///
/// The struct carries no `#[non_exhaustive]`: build it with
/// `..Default::default()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectOptions {
    /// The ssh command line, as a list of arguments. It wins over the
    /// `OSTRYA_SSH_COMMAND` environment variable and over
    /// [`remote_ssh_command`](ConnectOptions::remote_ssh_command). An empty
    /// list is refused.
    pub ssh_command: Option<Vec<String>>,
    /// The command the remote side runs, which the remote shell parses. The
    /// default is `ostrya receive`.
    pub receive_command: Option<String>,
    /// The ssh command line from the configuration of a remote, split at
    /// ASCII whitespace. It has the lowest precedence: the
    /// `OSTRYA_SSH_COMMAND` environment variable wins over it.
    pub remote_ssh_command: Option<String>,
}

impl PushSession {
    /// Open a session to `remote`: start the transport, send `Hello` with
    /// `refs`, and read `HelloReply`.
    ///
    /// An `http://` or `https://` remote is [`Error::InvalidInput`]. An ssh
    /// command or a receive command that is empty or holds only whitespace
    /// is [`Error::InvalidInput`], and so is an `OSTRYA_SSH_COMMAND` value
    /// that is not UTF-8. An ssh client that cannot be started is
    /// [`Error::Transport`], which names the program. The module docs state
    /// the time limits and the exit rules of an ssh session.
    ///
    /// Under the tokio backend, the call must run within a runtime that has
    /// the IO driver and the time driver enabled (`enable_io` and
    /// `enable_time` of the runtime builder, or `enable_all`). The child
    /// process and its pipes need the IO driver, and the time limits need
    /// the time driver. The session runs on the runtime that opened it.
    pub async fn connect(
        remote: &PushRemote,
        connect: ConnectOptions,
        refs: &[String],
        opts: SessionOptions,
    ) -> Result<PushSession> {
        let env = std::env::var_os("OSTRYA_SSH_COMMAND");
        connect_with(
            remote,
            &connect,
            env.as_deref(),
            refs,
            opts,
            PENDING_READ_LIMIT,
        )
        .await
    }
}

/// [`PushSession::connect`] with the value of the environment variable and
/// the time limit as parameters.
async fn connect_with(
    remote: &PushRemote,
    connect: &ConnectOptions,
    env: Option<&std::ffi::OsStr>,
    refs: &[String],
    opts: SessionOptions,
    limit: Duration,
) -> Result<PushSession> {
    let addr = match &remote.inner {
        RemoteAddr::Ssh(addr) => addr,
        RemoteAddr::Http(url) => {
            return Err(Error::InvalidInput(format!(
                "push address '{url}': the HTTP transport is not supported"
            )));
        }
    };
    let program = ssh::ssh_program(
        connect.ssh_command.as_deref(),
        env,
        connect.remote_ssh_command.as_deref(),
    )?;
    let receive = ssh::receive_command(connect.receive_command.as_deref())?;
    let argv = addr.command_line(program, receive);
    let (input, output, transport) = Transport::spawn(&argv, limit)?;
    match PushSession::open(input, output, refs, opts, Some(limit)).await {
        Ok(session) => Ok(session.with_transport(transport)),
        Err(e) => transport.finish(Err(e)).await,
    }
}

#[cfg(test)]
mod tests;
