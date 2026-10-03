//! The transports a push session runs over.
//!
//! [`PushRemote`] is a parsed push address. [`PushSession::connect`] opens a
//! session to it with [`ConnectOptions`]. [`PushSession::prepare`] runs the
//! first step of `connect` alone: it checks the options and makes the
//! transport ready, and [`PreparedSession::open`] opens the session later.
//! An ssh address takes the ssh fields
//! of the options, and an `http://` or `https://` address takes the HTTP
//! fields. A field that does not apply to the transport of the address is
//! [`Error::InvalidInput`], with one exception:
//! [`ConnectOptions::remote_ssh_command`] holds a key of the configuration of
//! a remote, and an HTTP address does not read it.
//!
//! A refusal names a field by the key of a remote that has its name, which is
//! also the option of the `ostrya` command without `--`: for example
//! `push-user needs push-token-file`. A refusal of a field of
//! [`ConnectOptions::http`] names that field.
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
//! the same time, also when the stream is broken and when `commit` refuses
//! its updates. An open that fails waits in the same way. When the session
//! failed with an I/O error and the ssh client exited with a failure status,
//! the call returns [`Error::Transport`] with the status. A session that
//! committed returns its outcome, whatever the exit status.
//!
//! The session drops the child without a wait in three cases: the session
//! is dropped without `commit` or `abort`, the future of `commit` or `abort`
//! is dropped before it completes, and the ssh client does not exit within
//! the limit. The standard input of the child is then closed, so the child
//! reads end of file on it.
//!
//! # HTTP
//!
//! The addresses are `http://HOST[:PORT][/PATH]` and
//! `https://HOST[:PORT][/PATH]`. [`PushRemote::parse`] refuses userinfo, a
//! query, a fragment, an empty host, and a port that is not a number from 0
//! to 65535. A refusal does not show the userinfo.
//!
//! Each step of a session is one request to the receive endpoint of the
//! server. The client adds `_ostrya/receive/v1/session`, then `/ID` and the
//! step, to the path of the address. `ostrya serve` serves the endpoint at
//! the root of the server, so an address with a path works only behind a
//! proxy that removes that path. `Hello`, `Have`, and `Commit` go as whole
//! request bodies. Each object stream is the streamed body of one `objects`
//! request.
//!
//! [`ConnectOptions::push_token_file`] names a file whose first line is the
//! token. With [`ConnectOptions::push_user`], the client sends the token as
//! the password of a Basic credential with that name. Without it, the
//! client sends a bearer token. The client reads at most 1 MiB of the file,
//! and refuses a first line that is empty, that holds a carriage return,
//! that is not UTF-8, or that is not token68. A refusal holds no part of the
//! token. The client checks no permission of the file. A relative path of a
//! file of the options is relative to the current directory of the process,
//! and `~` is not expanded. A file that cannot be read is [`Error::Io`], with
//! the key and the path in the message. A credential to an
//! `http://` address is refused before any request, unless
//! [`ConnectOptions::allow_cleartext_credentials`] is set.
//!
//! [`ConnectOptions::tls_ca_path`] names the CA certificates that verify the
//! server, in place of the trust store of the host.
//! [`ConnectOptions::tls_client_cert_path`] and
//! [`ConnectOptions::tls_client_key_path`] name a client certificate and its
//! key, and the two come together. A key that needs a passphrase is
//! refused. Each file is read once, at most 1 MiB, when the session opens.
//! [`ConnectOptions::http`] holds the other options of the HTTP client, for
//! example a proxy and the timeouts. A trust setting of it that verifies no
//! certificate chain is refused, and so are its mirrors and its Basic
//! credential. The client sets its own redirect limit and request limit: a
//! redirect is not followed, and a 3xx answer is [`Error::Transport`].
//!
//! One `send` call runs an object stream for each of the `parallel-uploads`
//! of the server, at most 31, and no more than the objects it sends. The
//! object streams of all the calls of one session stay within that number.
//!
//! The response to `Hello` may take 6 minutes after the request body was
//! sent, and the response to `Commit` 1 hour. The response to each other
//! request takes the progress timeout of [`ConnectOptions::http`].
//!
//! The client sends a request again only when the attempt failed before it
//! sent any byte of the request. A `Commit` that was sent and whose response
//! does not arrive is [`Error::CommitOutcomeUnknown`]: the server can have
//! written the refs. An answer with a status the endpoint does not give,
//! and a body that is not one frame, are [`Error::Transport`], which names
//! the URL and the status. A failure of the HTTP client is [`Error::Fetch`].
//!
//! [`abort`](PushSession::abort) ends the session with `DELETE`, also on a
//! broken session, and so does a [`commit`](PushSession::commit) that
//! refuses its updates. A session that is dropped without `commit` or
//! `abort` sends nothing, and the server ends it when its idle timeout
//! ends.

mod http;
mod ssh;

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::session::http::Endpoint;
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
        // The message of the fetcher leaves userinfo out.
        ostrya_fetch::check_base_url(address)
            .map_err(|e| Error::InvalidInput(format!("push address: {e}")))?;
        RemoteAddr::Http(address.to_owned())
    } else {
        RemoteAddr::Ssh(ssh::SshAddr::parse(address, windows)?)
    };
    Ok(PushRemote { inner })
}

/// How [`PushSession::connect`] reaches a remote.
///
/// The ssh fields apply to an ssh address, and the other fields to an
/// `http://` or `https://` address. A field set for the other transport is
/// refused, except `remote_ssh_command`, which an HTTP address does not read.
/// The module docs state the rules of each transport.
///
/// The struct carries no `#[non_exhaustive]`: build it with
/// `..Default::default()`.
#[derive(Debug, Clone, Default)]
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
    /// `OSTRYA_SSH_COMMAND` environment variable wins over it. An HTTP
    /// address does not read it.
    pub remote_ssh_command: Option<String>,
    /// A file whose first line is the token of an HTTP push.
    pub push_token_file: Option<PathBuf>,
    /// The name of a Basic credential. The token of
    /// [`push_token_file`](ConnectOptions::push_token_file) is its password.
    /// Without a name, the token is a bearer token.
    pub push_user: Option<String>,
    /// A file of PEM CA certificates that verify the server, in place of the
    /// trust store of the host.
    pub tls_ca_path: Option<PathBuf>,
    /// A PEM file of the client certificate, with the intermediates that
    /// follow it. It needs [`tls_client_key_path`](ConnectOptions::tls_client_key_path).
    pub tls_client_cert_path: Option<PathBuf>,
    /// A PEM file of the private key of the client certificate, which needs
    /// no passphrase.
    pub tls_client_key_path: Option<PathBuf>,
    /// Send the credential of
    /// [`push_token_file`](ConnectOptions::push_token_file) to an `http://`
    /// address. Set it for a server on a loopback address or behind a proxy
    /// that terminates TLS.
    pub allow_cleartext_credentials: bool,
    /// The other options of the HTTP client: for example the trust roots, a
    /// client identity, a proxy, extra headers, and the timeouts. The client
    /// replaces `max_outstanding` and `max_redirects` with its own values.
    pub http: ostrya_fetch::FetcherOptions,
}

impl PushSession {
    /// Open a session to `remote`: start the transport, send `Hello` with
    /// `refs`, and read `HelloReply`. This is [`prepare`](PushSession::prepare)
    /// and then [`PreparedSession::open`].
    ///
    /// An ssh command or a receive command that is empty or holds only
    /// whitespace is [`Error::InvalidInput`], and so is an
    /// `OSTRYA_SSH_COMMAND` value that is not UTF-8. An ssh client that
    /// cannot be started is [`Error::Transport`], which names the program.
    /// A field of `connect` that does not apply to the transport of
    /// `remote`, and each refusal of the HTTP options in the module docs, are
    /// [`Error::InvalidInput`]. The module docs state the time limits and the
    /// exit rules of an ssh session, and the rules of an HTTP session.
    ///
    /// Under the tokio backend, the call must run within a runtime that has
    /// the IO driver and the time driver enabled (`enable_io` and
    /// `enable_time` of the runtime builder, or `enable_all`). The child
    /// process and its pipes, and the connections of an HTTP session, need
    /// the IO driver, and the time limits need the time driver. The session
    /// runs on the runtime that opened it.
    pub async fn connect(
        remote: &PushRemote,
        connect: ConnectOptions,
        refs: &[String],
        opts: SessionOptions,
    ) -> Result<PushSession> {
        PushSession::prepare(remote, connect)
            .await?
            .open(refs, opts)
            .await
    }

    /// Check `connect` for `remote`, and make the transport ready to open.
    /// For an ssh address, the call reads the `OSTRYA_SSH_COMMAND`
    /// environment variable and builds the command line of the ssh client.
    /// For an HTTP address, it reads the token file and the TLS files that
    /// `connect` names, and builds the HTTP client.
    ///
    /// The call starts no ssh client and sends no request. It refuses each
    /// value that [`connect`](PushSession::connect) refuses before it starts
    /// the transport, so a caller can make these checks before its own
    /// local work, and open the session with [`PreparedSession::open`] after
    /// that work.
    ///
    /// Under the tokio backend, the call must run within a runtime that has
    /// the IO driver enabled, as [`connect`](PushSession::connect) states.
    pub async fn prepare(remote: &PushRemote, connect: ConnectOptions) -> Result<PreparedSession> {
        let env = std::env::var_os("OSTRYA_SSH_COMMAND");
        let inner = prepare_with(remote, &connect, env.as_deref()).await?;
        Ok(PreparedSession { inner })
    }
}

/// A session whose transport is checked and ready to open, which
/// [`PushSession::prepare`] gives.
///
/// For ssh it holds the command line of the ssh client, and for HTTP the HTTP
/// client with the credential of the session. No process runs and no request
/// was sent. The value is `Send + Sync`, and its `Debug` output shows the
/// transport and the HTTP address alone: no credential and no command line.
pub struct PreparedSession {
    inner: Prepared,
}

impl PreparedSession {
    /// Open the session: start the ssh client, or send the first HTTP
    /// request, then send `Hello` with `refs` and read `HelloReply`, as
    /// [`PushSession::connect`] does, with its time limits.
    pub async fn open(self, refs: &[String], opts: SessionOptions) -> Result<PushSession> {
        self.inner.open(refs, opts).await
    }
}

impl fmt::Debug for PreparedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("PreparedSession");
        match &self.inner {
            Prepared::Ssh(_) => out.field("transport", &"ssh"),
            Prepared::Http(endpoint) => out.field("transport", &"http").field("url", &endpoint.url),
        };
        out.finish_non_exhaustive()
    }
}

/// The transport of a session, checked and ready to open.
pub(crate) enum Prepared {
    /// The command line of the ssh client.
    Ssh(Vec<String>),
    /// The receive endpoint of an HTTP server.
    Http(Endpoint),
}

/// Check `connect` for `remote`, and make the transport ready to open, with
/// `env` as the value of the `OSTRYA_SSH_COMMAND` environment variable. For
/// ssh, build the command line. For HTTP, read the files that `connect` names
/// and build the HTTP client. It starts nothing and sends nothing.
async fn prepare_with(
    remote: &PushRemote,
    connect: &ConnectOptions,
    env: Option<&std::ffi::OsStr>,
) -> Result<Prepared> {
    match &remote.inner {
        RemoteAddr::Ssh(addr) => {
            refuse_http_fields(addr, connect)?;
            let program = ssh::ssh_program(
                connect.ssh_command.as_deref(),
                env,
                connect.remote_ssh_command.as_deref(),
            )?;
            let receive = ssh::receive_command(connect.receive_command.as_deref())?;
            Ok(Prepared::Ssh(addr.command_line(program, receive)))
        }
        // The HTTP preparation reads files and builds the fetcher, and its
        // future is boxed so the future of an ssh connect does not hold it.
        RemoteAddr::Http(url) => Ok(Prepared::Http(Box::pin(http::prepare(url, connect)).await?)),
    }
}

/// Refuse a field of `connect` that applies to an HTTP address alone.
fn refuse_http_fields(addr: &ssh::SshAddr, connect: &ConnectOptions) -> Result<()> {
    // Each name is the remote key and the CLI option of the field. The
    // options of the HTTP client have neither, so the field names them.
    let set = [
        ("push-token-file", connect.push_token_file.is_some()),
        ("push-user", connect.push_user.is_some()),
        ("tls-ca-path", connect.tls_ca_path.is_some()),
        (
            "tls-client-cert-path",
            connect.tls_client_cert_path.is_some(),
        ),
        ("tls-client-key-path", connect.tls_client_key_path.is_some()),
        (
            "allow-cleartext-credentials",
            connect.allow_cleartext_credentials,
        ),
        ("ConnectOptions::http", !http::is_default(&connect.http)),
    ];
    match set.iter().find(|(_, set)| *set) {
        Some((name, _)) => Err(Error::InvalidInput(format!(
            "{name} applies to an HTTP address, and '{addr}' is an ssh address"
        ))),
        None => Ok(()),
    }
}

impl Prepared {
    /// Open a session over the transport, with the time limits of
    /// [`PushSession::connect`].
    async fn open(self, refs: &[String], opts: SessionOptions) -> Result<PushSession> {
        self.open_with(refs, opts, PENDING_READ_LIMIT).await
    }

    /// [`open`](Prepared::open) with `limit` as the time limit of an ssh
    /// session.
    async fn open_with(
        self,
        refs: &[String],
        opts: SessionOptions,
        limit: Duration,
    ) -> Result<PushSession> {
        match self {
            Prepared::Ssh(argv) => spawn_and_open(&argv, refs, opts, limit).await,
            // Boxed, as the HTTP preparation is.
            Prepared::Http(endpoint) => {
                Box::pin(PushSession::open_http(endpoint, refs, opts)).await
            }
        }
    }
}

/// [`PushSession::connect`] with the value of the environment variable and
/// the time limit as parameters.
#[cfg(test)]
async fn connect_with(
    remote: &PushRemote,
    connect: &ConnectOptions,
    env: Option<&std::ffi::OsStr>,
    refs: &[String],
    opts: SessionOptions,
    limit: Duration,
) -> Result<PushSession> {
    prepare_with(remote, connect, env)
        .await?
        .open_with(refs, opts, limit)
        .await
}

/// Start `argv` and open a session over its standard input and standard
/// output, with `limit` as the time limit of the session.
async fn spawn_and_open(
    argv: &[String],
    refs: &[String],
    opts: SessionOptions,
    limit: Duration,
) -> Result<PushSession> {
    let (input, output, transport) = Transport::spawn(argv, limit)?;
    match PushSession::open(input, output, refs, opts, Some(limit)).await {
        Ok(session) => Ok(session.with_transport(transport)),
        Err(e) => transport.finish(Err(e)).await,
    }
}

#[cfg(test)]
mod tests;
