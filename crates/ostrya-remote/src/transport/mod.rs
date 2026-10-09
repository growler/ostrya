//! The push addresses, and the ssh and HTTP transports of the sessions.
//!
//! [`Endpoint`] holds an address and the options of its transport: an
//! [`SshAddress`] with [`SshOptions`], or the options of the HTTP client.
//! [`PushSession::connect`] opens a push session to an endpoint.
//! [`PushSession::prepare`] checks the endpoint and makes the transport ready,
//! and [`PreparedSession::open`] opens the session later.
//!
//! [`PushRemote`] is a parsed address of a pull over ssh.
//! [`PullSession::connect`] opens a pull session over ssh to it with
//! [`PullConnectOptions`].
//!
//! Over ssh, the client runs the ssh client as a child process, and the remote
//! side runs the receive command or the send command. The frames of the
//! session go over the standard input and the standard output of the child.
//! Over HTTP, each step of a push session is one request to the server.

mod http;
mod ssh;

use std::ffi::OsStr;
use std::fmt;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::session::http::Endpoint as HttpEndpoint;
use crate::session::{PullSession, PullSessionOptions, PushSession, SessionOptions};

pub(crate) use ssh::Transport;
pub use ssh::{SshAddress, SshOptions, without_userinfo};

/// The longest wait for a pending message after a failed write, and for the
/// exit of the ssh client. It applies to a session that
/// [`PushSession::connect`] or [`PullSession::connect`] opens.
const PENDING_READ_LIMIT: Duration = Duration::from_secs(5);

/// The address of a pull over ssh, parsed from an ssh address or an HTTP
/// address.
///
/// [`PullSession::connect`] takes the ssh forms alone.
///
/// # ssh addresses
///
/// An address that does not start with `http://` or `https://` is an ssh
/// address. Its forms and rules are the forms and rules of [`SshAddress`]. A
/// refusal does not show the userinfo.
///
/// # HTTP addresses
///
/// The forms are `http://HOST[:PORT][/PATH]` and `https://HOST[:PORT][/PATH]`.
/// [`parse`](PushRemote::parse) refuses an `@` at any position, so it refuses
/// userinfo. It also refuses a query, a fragment, an empty host, and a port
/// that is not a number from 0 to 65535. A refusal does not show the userinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRemote {
    inner: RemoteAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RemoteAddr {
    Ssh(SshAddress),
    Http(String),
}

impl PushRemote {
    /// Parses `address` as one of the forms of [`PushRemote`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `address` is not one of the
    ///   [ssh forms](PushRemote#ssh-addresses) or the
    ///   [HTTP forms](PushRemote#http-addresses), or if the parse refuses a
    ///   part of it.
    pub fn parse(address: &str) -> Result<PushRemote> {
        parse_remote(address, cfg!(windows))
    }

    /// Returns the address with no user, for a message.
    ///
    /// The `Display` of the result writes an ssh address in the `ssh://`
    /// form with no `USER@`. An HTTP address holds no user, so the result is
    /// equal to `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ostrya_remote::transport::PushRemote;
    /// # fn main() -> ostrya_remote::Result<()> {
    /// let remote = PushRemote::parse("builder@repo.example.com:srv/a@b")?;
    /// assert_eq!(
    ///     remote.without_user().to_string(),
    ///     "ssh://repo.example.com/~/srv/a@b"
    /// );
    /// # Ok(()) }
    /// ```
    #[doc(hidden)]
    pub fn without_user(&self) -> PushRemote {
        let inner = match &self.inner {
            RemoteAddr::Ssh(addr) => RemoteAddr::Ssh(addr.without_user()),
            RemoteAddr::Http(url) => RemoteAddr::Http(url.clone()),
        };
        PushRemote { inner }
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

/// Parses `address`, with the Windows rule for a one-letter host if `windows`
/// is `true`.
fn parse_remote(address: &str, windows: bool) -> Result<PushRemote> {
    let inner = if address.starts_with("http://") || address.starts_with("https://") {
        // The message of the fetcher holds no userinfo.
        ostrya_fetch::check_base_url(address)
            .map_err(|e| Error::InvalidInput(format!("address: {e}")))?;
        RemoteAddr::Http(address.to_owned())
    } else {
        RemoteAddr::Ssh(SshAddress::parse_with(address, windows)?)
    };
    Ok(PushRemote { inner })
}

/// A remote address with the options of its transport.
///
/// [`Endpoint::parse`] reads an address and gives the default options. A
/// caller can also build an endpoint from its parts, with options of its own.
#[derive(Debug, Clone)]
pub enum Endpoint {
    /// An ssh address and the options of the ssh client.
    Ssh {
        /// The ssh address.
        address: SshAddress,
        /// The options of the ssh client.
        options: SshOptions,
    },
    /// The options of the HTTP client. The `mirrors` field holds the address.
    Http(ostrya_fetch::FetcherOptions),
}

impl Endpoint {
    /// Parses `address` into an endpoint with the default options.
    ///
    /// An address that starts with `http://` or `https://` gives
    /// [`Endpoint::Http`] with
    /// [`FetcherOptions::new`](ostrya_fetch::FetcherOptions::new) of the
    /// address. Each other address gives [`Endpoint::Ssh`] with the default
    /// [`SshOptions`]. The call accepts and refuses the same addresses as
    /// [`PushRemote::parse`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `address` is not one of the
    ///   [ssh forms](SshAddress#forms) or the
    ///   [HTTP forms](PushRemote#http-addresses), or if the parse refuses a
    ///   part of it. No refusal shows the userinfo of the address.
    ///
    /// # Examples
    ///
    /// ```
    /// use ostrya_remote::transport::Endpoint;
    /// # fn main() -> ostrya_remote::Result<()> {
    /// let endpoint = Endpoint::parse("builder@repo.example.com:/srv/repo")?;
    /// let Endpoint::Ssh { address, options } = endpoint else {
    ///     panic!("an scp-form address gives an ssh endpoint");
    /// };
    /// assert_eq!(address.to_string(), "ssh://builder@repo.example.com/srv/repo");
    /// assert_eq!(options.remote_command, None);
    ///
    /// let Endpoint::Http(http) = Endpoint::parse("https://repo.example.com/")? else {
    ///     panic!("an https address gives an HTTP endpoint");
    /// };
    /// assert_eq!(http.mirrors, ["https://repo.example.com/"]);
    /// # Ok(()) }
    /// ```
    pub fn parse(address: &str) -> Result<Endpoint> {
        parse_endpoint(address, cfg!(windows))
    }
}

/// Parses `address` as [`Endpoint::parse`] does, with the Windows rules of an
/// ssh address if `windows` is `true`.
fn parse_endpoint(address: &str, windows: bool) -> Result<Endpoint> {
    if address.starts_with("http://") || address.starts_with("https://") {
        // The message of the fetcher holds no userinfo.
        ostrya_fetch::check_base_url(address)
            .map_err(|e| Error::InvalidInput(format!("address: {e}")))?;
        Ok(Endpoint::Http(ostrya_fetch::FetcherOptions::new(address)))
    } else {
        Ok(Endpoint::Ssh {
            address: SshAddress::parse_with(address, windows)?,
            options: SshOptions::default(),
        })
    }
}

/// The open of a session over ssh or HTTP.
impl PushSession {
    /// Opens a push session to `endpoint` over ssh or HTTP.
    ///
    /// The call starts the transport, sends `Hello` with `refs`, and reads
    /// `HelloReply`. It is [`prepare`](PushSession::prepare) and then
    /// [`PreparedSession::open`].
    ///
    /// # Errors
    ///
    /// - An `Error` message from the server, as the [`Error`] variant of its
    ///   code.
    /// - Each error of [`prepare`](PushSession::prepare).
    /// - [`Error::Fetch`] if an HTTP request fails.
    /// - [`Error::Transport`] if the ssh client cannot be started. The message
    ///   names the program.
    /// - [`Error::Transport`] if an HTTP answer has a status that the endpoint
    ///   does not give, or a body that is not one frame. The message names the
    ///   URL and the status.
    /// - [`Error::Transport`] if the HTTP answer to `Hello` has no session id.
    /// - [`Error::Transport`] if the session fails with [`Error::Io`] and the
    ///   ssh client exits with a failure status. The message holds the status.
    /// - [`Error::Protocol`] if the reply is not `HelloReply`, if its version
    ///   is not [`PROTOCOL_VERSION`](crate::proto::PROTOCOL_VERSION), or if its
    ///   refs are not the refs of `Hello` in order.
    /// - [`Error::LimitExceeded`] if the `Hello` frame is more than
    ///   [`MIN_FRAME_LIMIT`](crate::proto::MIN_FRAME_LIMIT) bytes.
    /// - [`Error::Protocol`] or [`Error::LimitExceeded`] if the codec refuses
    ///   a frame of the server over ssh, by the rules of
    ///   [`proto`](crate::proto#frames).
    /// - [`Error::Io`] if a read or a write of the session fails.
    ///
    /// # tokio runtime
    ///
    /// Under the tokio backend, the call must run within a runtime that has
    /// the IO driver and the time driver enabled. The runtime builder enables
    /// them with `enable_io` and `enable_time`, or with `enable_all`.
    ///
    /// The child process, its pipes, and the connections of an HTTP session
    /// need the IO driver. The time limits need the time driver. The session
    /// runs on the runtime that opened it.
    ///
    /// # ssh time limits
    ///
    /// After a failed write, the session reads the message that the server can
    /// have sent before it closed. The read takes at most five seconds. A
    /// server that closed its input and keeps its output open with no message
    /// cannot hold the session. When the time ends, the call returns the error
    /// of the write, or [`Error::CommitOutcomeUnknown`] after `Commit`.
    ///
    /// [`commit`](PushSession::commit) and [`abort`](PushSession::abort) close
    /// the standard input of the ssh client. They then wait at most five
    /// seconds for the ssh client to exit. They also wait if the stream is
    /// broken and if `commit` refuses its updates. An open that fails waits in
    /// the same way.
    ///
    /// If the session failed with an I/O error and the ssh client exited with a
    /// failure status, the call returns [`Error::Transport`] with the status.
    /// The status is also added to the message of
    /// [`Error::CommitOutcomeUnknown`]. A session that committed returns its
    /// outcome, whatever the exit status.
    ///
    /// The session drops the child with no wait in three cases:
    ///
    /// - the caller drops the session without `commit` or `abort`
    /// - the caller drops the future of `commit` or `abort` before it completes
    /// - the ssh client does not exit within the limit
    ///
    /// In each case, the standard input of the child closes, so the child
    /// reads end of file on it.
    ///
    /// # HTTP
    ///
    /// Each step of a session is one request to the receive endpoint of the
    /// server. The client adds `_ostrya/receive/v1/session` to the path of the
    /// address, and then `/ID` and the step. The response to `Hello` gives
    /// the `ID` in its `ostrya-session` header, as 64 lowercase hex digits.
    ///
    /// `ostrya serve` serves the endpoint at the root of the server. An
    /// address with a path works only behind a proxy that removes that path,
    /// or with a host that mounts the `ReceiveEndpoint` of `ostrya-server`
    /// under that path.
    ///
    /// `Hello`, `Have`, and `Commit` go as whole request bodies. Each object
    /// stream is the streamed body of one `objects` request. Each response
    /// body holds one frame: the reply of the step, or an `Error` message.
    ///
    /// After the client sent the request body, it waits for the response. The
    /// wait is at most 6 minutes for `Hello` and at most 1 hour for `Commit`.
    /// For each other request, the limit is the `progress_timeout` of the
    /// options of [`Endpoint::Http`]. The client sends a request again only if
    /// the attempt failed before it sent any byte of the request.
    ///
    /// The options of [`Endpoint::Http`] must name exactly one mirror, the
    /// push address. The client sets `max_outstanding` to 32 and
    /// `max_redirects` to 0, whatever values the options hold. The 32 requests
    /// are one for each of the at most 31 object streams of
    /// [`PushSession::send`], and one `Have` or `Commit` request. The client
    /// follows no redirect, and a 3xx answer is [`Error::Transport`].
    ///
    /// The fetcher carries the credential, the TLS settings, the proxy, and
    /// the headers of the options to each request. The client accepts each
    /// trust setting of the options, a setting that verifies no certificate
    /// chain among them. The trust policy belongs to the caller.
    ///
    /// # Examples
    ///
    /// The example deletes a ref on the server if the ref exists.
    ///
    /// ```no_run
    /// use ostrya_fetch::BearerToken;
    /// use ostrya_remote::proto::{Expected, RefUpdate};
    /// use ostrya_remote::session::{PushSession, SessionOptions};
    /// use ostrya_remote::transport::Endpoint;
    /// # async fn run(token: String) -> ostrya_remote::Result<()> {
    /// let mut endpoint = Endpoint::parse("https://repo.example.com/")?;
    /// if let Endpoint::Http(http) = &mut endpoint {
    ///     http.bearer_token = Some(BearerToken { token });
    /// }
    /// let refs = vec!["exampleos/testing".to_owned()];
    /// let session = PushSession::connect(endpoint, &refs, SessionOptions::default()).await?;
    /// let Some(tip) = session.server().tip(&refs[0]) else {
    ///     return session.abort().await;
    /// };
    /// let update = RefUpdate { name: refs[0].clone(), expected: Expected::Commit(tip), new: None };
    /// let outcome = session.commit(&[update], false).await?;
    /// assert_eq!(outcome.refs[0].new, None);
    /// # Ok(()) }
    /// ```
    pub async fn connect(
        endpoint: Endpoint,
        refs: &[String],
        opts: SessionOptions,
    ) -> Result<PushSession> {
        PushSession::prepare(endpoint).await?.open(refs, opts).await
    }

    /// Checks `endpoint` and makes the transport ready to open.
    ///
    /// For an ssh endpoint, the call reads the `OSTRYA_SSH_COMMAND`
    /// environment variable and builds the command line of the ssh client, by
    /// the rules of [`SshOptions`]. The remote command is `ostrya receive` if
    /// [`SshOptions::remote_command`] is not set. For an HTTP endpoint, it
    /// builds the HTTP client from the options, as
    /// [`connect`](PushSession::connect) states. The call takes the
    /// credential and the TLS material from the endpoint, and reads no file
    /// that the endpoint names. An `https://` endpoint with
    /// [`TrustRoots::System`](ostrya_fetch::TrustRoots::System) reads the
    /// trust store of the host.
    ///
    /// The call starts no ssh client and sends no request. It refuses each
    /// value that [`connect`](PushSession::connect) refuses before it starts
    /// the transport. A caller can make these checks before its own local
    /// work, and open the session with [`PreparedSession::open`] after that
    /// work.
    ///
    /// Under the tokio backend, the call must run within a runtime that has
    /// the IO driver enabled, as [`connect`](PushSession::connect) states.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if the ssh command or the receive command is
    ///   empty or holds only white space, or if the value of
    ///   `OSTRYA_SSH_COMMAND` is not UTF-8.
    /// - [`Error::InvalidInput`] if the options of an HTTP endpoint do not name
    ///   exactly one mirror, or if
    ///   [`check_base_url`](ostrya_fetch::check_base_url) refuses the mirror.
    ///   The message holds no userinfo.
    /// - [`Error::Fetch`] if the HTTP client cannot be built. Examples are a
    ///   credential to an `http://` address without
    ///   `allow_cleartext_credentials`, a bearer token beside an
    ///   `Authorization` header, and a client key that needs a passphrase that
    ///   the options do not hold.
    pub async fn prepare(endpoint: Endpoint) -> Result<PreparedSession> {
        let env = std::env::var_os("OSTRYA_SSH_COMMAND");
        let inner = prepare_with(endpoint, env.as_deref()).await?;
        Ok(PreparedSession { inner })
    }
}

/// A push session whose transport is checked and ready to open.
///
/// [`PushSession::prepare`] returns it. For ssh, it holds the command line of
/// the ssh client. For HTTP, it holds the HTTP client and the credential of the
/// session. No process runs and no request is sent before
/// [`open`](PreparedSession::open).
///
/// The value is `Send + Sync`. Its `Debug` output shows the transport and the
/// HTTP address alone, with no credential and no command line.
pub struct PreparedSession {
    inner: Prepared,
}

impl PreparedSession {
    /// Opens the session, sends `Hello` with `refs`, and reads `HelloReply`.
    ///
    /// The call starts the ssh client, or sends the first HTTP request, as
    /// [`PushSession::connect`] does. An ssh session has the ssh time limits of
    /// [`PushSession::connect`].
    ///
    /// # Errors
    ///
    /// - An `Error` message from the server, as the [`Error`] variant of its
    ///   code.
    /// - [`Error::Fetch`] if an HTTP request fails.
    /// - [`Error::Transport`] if the ssh client cannot be started. The message
    ///   names the program.
    /// - [`Error::Transport`] if an HTTP answer has a status that the endpoint
    ///   does not give, or a body that is not one frame. The message names the
    ///   URL and the status.
    /// - [`Error::Transport`] if the HTTP answer to `Hello` has no session id.
    /// - [`Error::Transport`] if the session fails with [`Error::Io`] and the
    ///   ssh client exits with a failure status. The message holds the status.
    /// - [`Error::Protocol`] if the reply is not `HelloReply`, if its version
    ///   is not [`PROTOCOL_VERSION`](crate::proto::PROTOCOL_VERSION), or if its
    ///   refs are not the refs of `Hello` in order.
    /// - [`Error::LimitExceeded`] if the `Hello` frame is more than
    ///   [`MIN_FRAME_LIMIT`](crate::proto::MIN_FRAME_LIMIT) bytes.
    /// - [`Error::Protocol`] or [`Error::LimitExceeded`] if the codec refuses
    ///   a frame of the server over ssh, by the rules of
    ///   [`proto`](crate::proto#frames).
    /// - [`Error::Io`] if a read or a write of the session fails.
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
    Http(HttpEndpoint),
}

/// Checks `endpoint` and makes the transport ready to open, with `env` as the
/// value of the `OSTRYA_SSH_COMMAND` environment variable. For ssh, it builds
/// the command line. For HTTP, it builds the HTTP client. It starts nothing and
/// sends nothing.
async fn prepare_with(endpoint: Endpoint, env: Option<&OsStr>) -> Result<Prepared> {
    match endpoint {
        Endpoint::Ssh { address, options } => {
            let program = options.program(env)?;
            let receive = ssh::receive_command(options.remote_command.as_deref())?;
            Ok(Prepared::Ssh(address.command_line(program, receive)))
        }
        // The HTTP preparation builds the fetcher. Its future is boxed, so
        // that the future of an ssh connect does not hold it.
        Endpoint::Http(http) => Ok(Prepared::Http(Box::pin(http::prepare(http)).await?)),
    }
}

impl Prepared {
    /// Opens a session over the transport, with the time limits of
    /// [`PushSession::connect`].
    async fn open(self, refs: &[String], opts: SessionOptions) -> Result<PushSession> {
        self.open_with(refs, opts, PENDING_READ_LIMIT).await
    }

    /// Opens a session as [`open`](Prepared::open) does, with `limit` as the
    /// time limit of an ssh session.
    async fn open_with(
        self,
        refs: &[String],
        opts: SessionOptions,
        limit: Duration,
    ) -> Result<PushSession> {
        match self {
            Prepared::Ssh(argv) => spawn_and_open(&argv, refs, opts, limit).await,
            // The future is boxed, as the future of the HTTP preparation is.
            Prepared::Http(endpoint) => {
                Box::pin(PushSession::open_http(endpoint, refs, opts)).await
            }
        }
    }
}

/// The transport options of a pull session.
///
/// The fields resolve as the fields of [`SshOptions`] do, by the rules of its
/// [ssh command line](SshOptions#ssh-command-line). The struct
/// carries no `#[non_exhaustive]`. A caller builds it with
/// `..Default::default()`.
#[derive(Debug, Clone, Default)]
pub struct PullConnectOptions {
    /// The ssh command line, as a list of arguments.
    ///
    /// It wins over the `OSTRYA_SSH_COMMAND` environment variable and over
    /// [`remote_ssh_command`](PullConnectOptions::remote_ssh_command). An
    /// empty list is refused, and so is a list whose first argument holds only
    /// white space.
    pub ssh_command: Option<Vec<String>>,
    /// The command that the remote side runs.
    ///
    /// The remote shell parses it. The default is `ostrya send`.
    pub send_command: Option<String>,
    /// The ssh command line from the configuration of a remote.
    ///
    /// The client splits it at ASCII white space. It has the lowest
    /// precedence: the `OSTRYA_SSH_COMMAND` environment variable wins over it.
    pub remote_ssh_command: Option<String>,
}

/// The open of a session over ssh.
impl PullSession {
    /// Opens a pull session to the ssh address `remote`.
    ///
    /// The call starts the ssh client, sends `PullHello`, and reads
    /// `PullHelloReply`. `remote` takes the [ssh forms](PushRemote#ssh-addresses)
    /// of [`PushRemote`]. The command line is:
    ///
    /// ```text
    /// SSH_COMMAND... [-p PORT] [USER@]HOST 'SEND_COMMAND --repo=QUOTED_PATH'
    /// ```
    ///
    /// `SSH_COMMAND` comes from [`PullConnectOptions::ssh_command`], the
    /// `OSTRYA_SSH_COMMAND` environment variable, and
    /// [`PullConnectOptions::remote_ssh_command`], in that order, as for a
    /// push. `SEND_COMMAND` is [`PullConnectOptions::send_command`], or
    /// `ostrya send`.
    ///
    /// The session has the ssh time limits of [`PushSession::connect`].
    /// [`finish`](PullSession::finish) waits for the ssh client as `commit` and
    /// `abort` of a push do. The session puts no time limit on a read of a
    /// reply.
    ///
    /// Under the tokio backend, the call must run within a runtime that has
    /// the IO driver and the time driver enabled, as [`PushSession::connect`]
    /// states. The session runs on the runtime that opened it.
    ///
    /// # Errors
    ///
    /// - An `Error` message from the server, as the [`Error`] variant of its
    ///   code.
    /// - [`Error::InvalidInput`] if `remote` is an HTTP address, because a pull
    ///   session runs over ssh.
    /// - [`Error::InvalidInput`] if the ssh command or the send command is
    ///   empty or holds only white space, or if the value of
    ///   `OSTRYA_SSH_COMMAND` is not UTF-8.
    /// - [`Error::Transport`] if the ssh client cannot be started. The message
    ///   names the program.
    /// - [`Error::Transport`] if the session fails with [`Error::Io`] and the
    ///   ssh client exits with a failure status. The message holds the status.
    /// - [`Error::VersionUnsupported`] if the reply has a pull version outside
    ///   1 to [`PULL_PROTOCOL_VERSION`](crate::proto::PULL_PROTOCOL_VERSION).
    ///   The session then closes its output and sends no `Get`.
    /// - [`Error::Protocol`] if the reply is not `PullHelloReply`.
    /// - [`Error::LimitExceeded`] if the `PullHello` frame is more than
    ///   [`MIN_FRAME_LIMIT`](crate::proto::MIN_FRAME_LIMIT) bytes.
    /// - [`Error::Protocol`] or [`Error::LimitExceeded`] if the codec refuses
    ///   a frame of the server, by the rules of
    ///   [`proto`](crate::proto#frames).
    /// - [`Error::Io`] if a read or a write of the session fails, or if the
    ///   session ends before the reply.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use futures_lite::AsyncReadExt;
    /// use ostrya_remote::session::{PullSession, PullSessionOptions};
    /// use ostrya_remote::transport::{PullConnectOptions, PushRemote};
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let remote = PushRemote::parse("builder@repo.example.com:/srv/repo")?;
    /// let opts = PullSessionOptions::default();
    /// let session = PullSession::connect(&remote, PullConnectOptions::default(), opts).await?;
    /// if let Some(mut body) = session.get("config", 1 << 20).await? {
    ///     let mut config = Vec::new();
    ///     body.read_to_end(&mut config).await?;
    /// }
    /// session.finish().await?;
    /// # Ok(()) }
    /// ```
    pub async fn connect(
        remote: &PushRemote,
        connect: PullConnectOptions,
        opts: PullSessionOptions,
    ) -> Result<PullSession> {
        let env = std::env::var_os("OSTRYA_SSH_COMMAND");
        let argv = pull_command_line(remote, &connect, env.as_deref())?;
        spawn_and_open_pull(&argv, opts, PENDING_READ_LIMIT).await
    }
}

/// Builds the command line of the ssh client of a pull from `remote`, with
/// `env` as the value of the `OSTRYA_SSH_COMMAND` environment variable.
fn pull_command_line(
    remote: &PushRemote,
    connect: &PullConnectOptions,
    env: Option<&OsStr>,
) -> Result<Vec<String>> {
    match &remote.inner {
        RemoteAddr::Ssh(addr) => {
            let program = ssh::ssh_program(
                connect.ssh_command.as_deref(),
                env,
                connect.remote_ssh_command.as_deref(),
            )?;
            let send = ssh::send_command(connect.send_command.as_deref())?;
            Ok(addr.command_line(program, send))
        }
        RemoteAddr::Http(url) => Err(Error::InvalidInput(format!(
            "'{url}' is an HTTP address, and a pull session runs over ssh"
        ))),
    }
}

/// Starts `argv` and opens a pull session over its standard input and
/// standard output, with `limit` as the time limit of the session.
async fn spawn_and_open_pull(
    argv: &[String],
    opts: PullSessionOptions,
    limit: Duration,
) -> Result<PullSession> {
    let (input, output, transport) = Transport::spawn(argv, limit)?;
    match PullSession::open(input, output, opts, Some(limit)).await {
        Ok(session) => Ok(session.with_transport(transport)),
        Err(e) => transport.finish(Err(e)).await,
    }
}

/// Opens a pull session as [`PullSession::connect`] does, with the value of
/// the environment variable and the time limit as parameters.
#[cfg(test)]
async fn connect_pull_with(
    remote: &PushRemote,
    connect: &PullConnectOptions,
    env: Option<&OsStr>,
    opts: PullSessionOptions,
    limit: Duration,
) -> Result<PullSession> {
    let argv = pull_command_line(remote, connect, env)?;
    spawn_and_open_pull(&argv, opts, limit).await
}

/// Opens a push session as [`PushSession::connect`] does, with the value of
/// the environment variable and the time limit as parameters.
#[cfg(test)]
async fn connect_with(
    endpoint: Endpoint,
    env: Option<&OsStr>,
    refs: &[String],
    opts: SessionOptions,
    limit: Duration,
) -> Result<PushSession> {
    prepare_with(endpoint, env)
        .await?
        .open_with(refs, opts, limit)
        .await
}

/// Starts `argv` and opens a push session over its standard input and
/// standard output, with `limit` as the time limit of the session.
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
