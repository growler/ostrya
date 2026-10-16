//! The endpoints, and the ssh and HTTP transports of the sessions.
//!
//! An [`Endpoint`] holds a remote address and the options of its transport.
//! These calls open a session:
//!
//! - [`PushSession::connect`], or [`PushSession::prepare`] and then
//!   [`PreparedSession::open`], for a push to an endpoint
//! - [`PullSession::connect`] for a pull from an endpoint
//! - [`StreamSession::connect`] for a stream session to an [`SshAddress`]
//!
//! Over ssh, the session runs the ssh client as a child process, and the remote
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
use crate::session::{
    PullSession, PushSession, SessionOptions, StreamSession, StreamSessionOptions,
};

pub(crate) use ssh::Transport;
pub use ssh::{SshAddress, SshOptions, without_userinfo};

/// The longest wait for a pending message after a failed write, and for the
/// exit of the ssh client. It applies to a session that
/// [`PushSession::connect`] or [`StreamSession::connect`] opens.
const PENDING_READ_LIMIT: Duration = Duration::from_secs(5);

/// A remote address with the options of its transport.
///
/// [`Endpoint::parse`] reads an address and gives the default options. A
/// caller can also build an endpoint from its parts, with options of its own.
///
/// The [`Debug`] output of [`Endpoint::Http`] is the output of
/// [`FetcherOptions`](ostrya_fetch::FetcherOptions), which shows no
/// credential, no header value, and no userinfo.
///
/// # HTTP addresses
///
/// The forms are `http://HOST[:PORT][/PATH]` and `https://HOST[:PORT][/PATH]`.
/// [`parse`](Endpoint::parse) refuses an `@` at any position, so it refuses
/// userinfo. It also refuses a query, a fragment, an empty host, and a port
/// that is not a number from 0 to 65535.
#[derive(Debug, Clone)]
pub enum Endpoint {
    /// An ssh address and the options of the ssh client.
    Ssh {
        /// The ssh address.
        address: SshAddress,
        /// The options of the ssh client.
        options: SshOptions,
    },
    /// The options of the HTTP client.
    ///
    /// [`mirrors`](ostrya_fetch::FetcherOptions::mirrors) holds the address:
    /// exactly one mirror for a push, one or more for a pull.
    Http(ostrya_fetch::FetcherOptions),
}

impl Endpoint {
    /// Parses `address` into an endpoint with the default options.
    ///
    /// An address that starts with `http://` or `https://` gives
    /// [`Endpoint::Http`] with
    /// [`FetcherOptions::new`](ostrya_fetch::FetcherOptions::new) of the
    /// address. Each other address gives [`Endpoint::Ssh`] with the default
    /// [`SshOptions`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `address` is not one of the
    ///   [ssh forms](SshAddress#forms) or the
    ///   [HTTP forms](Endpoint#http-addresses), or if the parse refuses a
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
    /// - Each error of [`prepare`](PushSession::prepare).
    /// - Each error of [`PreparedSession::open`].
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
    /// For each other request, the limit is the
    /// [`progress_timeout`](ostrya_fetch::FetcherOptions::progress_timeout) of
    /// the options of [`Endpoint::Http`]. The client sends a request again only
    /// if the attempt failed before it sent any byte of the request.
    ///
    /// The options of [`Endpoint::Http`] must name exactly one mirror, the
    /// push address. The client sets
    /// [`max_outstanding`](ostrya_fetch::FetcherOptions::max_outstanding) to 32
    /// and [`max_redirects`](ostrya_fetch::FetcherOptions::max_redirects) to 0,
    /// whatever values the options hold. The 32 requests are one for each of
    /// the at most 31 object streams of [`PushSession::send`], and one `Have`
    /// or `Commit` request. The client follows no redirect, and a 3xx answer
    /// is [`Error::Transport`].
    ///
    /// The fetcher carries the credential, the TLS settings, the proxy, and
    /// the headers of the options to each request. The client takes each trust
    /// setting of the options, also a bypass variant of
    /// [`TrustRoots`](ostrya_fetch::TrustRoots) that verifies no certificate
    /// chain. The caller owns the trust policy.
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
    /// environment variable and builds the command line of the ssh client by
    /// the rules of the [ssh command line](SshOptions#ssh-command-line).
    ///
    /// For an HTTP endpoint, the call builds the HTTP client from the options,
    /// as [`connect`](PushSession::connect) states. With
    /// [`TrustRoots::System`](ostrya_fetch::TrustRoots::System), an `https://`
    /// endpoint reads the trust store of the host, by the rule of
    /// [`Fetcher::new`](ostrya_fetch::Fetcher::new).
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
    ///   `OSTRYA_SSH_COMMAND` is not UTF-8. [`SshOptions`] states the full
    ///   rule under [Empty values](SshOptions#empty-values).
    /// - [`Error::InvalidInput`] if the options of an HTTP endpoint do not name
    ///   exactly one mirror, or if
    ///   [`check_base_url`](ostrya_fetch::check_base_url) refuses the mirror.
    ///   The message holds no userinfo.
    /// - [`Error::Fetch`] if [`Fetcher::new`](ostrya_fetch::Fetcher::new)
    ///   refuses the options. Examples:
    ///   - a credential to an `http://` address, with
    ///     [`allow_cleartext_credentials`](ostrya_fetch::FetcherOptions::allow_cleartext_credentials)
    ///     set to `false`
    ///   - a bearer token and an `Authorization` header together
    ///   - a client key that needs a passphrase that the options do not hold
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
    /// Opens the session, sends `Hello` with `refs` and the collection of
    /// `opts`, and reads `HelloReply`.
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
    ///   is not [`PROTOCOL_VERSION`](crate::proto::PROTOCOL_VERSION), if its
    ///   refs are not the refs of `Hello` in order, or if its `collection`
    ///   does not match [`SessionOptions::collection`].
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

/// The open of a session over ssh.
impl StreamSession {
    /// Opens a stream session to the ssh address `address`.
    ///
    /// The call starts the ssh client, sends `PullHello`, and reads
    /// `PullHelloReply`. The command line of the ssh client comes from
    /// `options` by the rules of the
    /// [ssh command line](SshOptions#ssh-command-line) of a pull. `session`
    /// gives the agent in `PullHello` and the request limit of the session.
    ///
    /// The session has the ssh time limits of [`PushSession::connect`].
    /// [`finish`](StreamSession::finish) waits for the ssh client as `commit`
    /// and `abort` of a push do. The session puts no time limit on a read of
    /// a reply.
    ///
    /// Under the tokio backend, the call must run within a runtime that has
    /// the IO driver and the time driver enabled, as [`PushSession::connect`]
    /// states. The session runs on the runtime that opened it.
    ///
    /// # Errors
    ///
    /// - An `Error` message from the server, as the [`Error`] variant of its
    ///   code.
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
    /// - [`Error::Protocol`] if the [`agent`](StreamSessionOptions::agent) of
    ///   `session` holds a NUL byte.
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
    /// use ostrya_remote::session::{StreamSession, StreamSessionOptions};
    /// use ostrya_remote::transport::{SshAddress, SshOptions};
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let address = SshAddress::parse("builder@repo.example.com:/srv/repo")?;
    /// let options = SshOptions::default();
    /// let session = StreamSession::connect(&address, &options, StreamSessionOptions::default()).await?;
    /// if let Some(mut body) = session.get("config", 1 << 20).await? {
    ///     let mut config = Vec::new();
    ///     body.read_to_end(&mut config).await?;
    /// }
    /// session.finish().await?;
    /// # Ok(()) }
    /// ```
    pub async fn connect(
        address: &SshAddress,
        options: &SshOptions,
        session: StreamSessionOptions,
    ) -> Result<StreamSession> {
        let env = std::env::var_os("OSTRYA_SSH_COMMAND");
        let argv = pull_command_line(address, options, env.as_deref())?;
        spawn_and_open_pull(&argv, session, PENDING_READ_LIMIT).await
    }
}

/// The open of the session of a pull over ssh or HTTP.
impl PullSession {
    /// Opens the session of a pull to `endpoint`.
    ///
    /// For an [`Endpoint::Ssh`], the call is [`StreamSession::connect`] with
    /// the address, the ssh options, and `opts`. The result is
    /// [`PullSession::Stream`].
    ///
    /// For an [`Endpoint::Http`], the call builds the fetcher with
    /// [`Fetcher::new`](ostrya_fetch::Fetcher::new), and the result is
    /// [`PullSession::Http`]. The call sends no HTTP request.
    ///
    /// Under the tokio backend, the call must run within a runtime that has
    /// the IO driver and the time driver enabled, as [`PushSession::connect`]
    /// states.
    ///
    /// # HTTP options
    ///
    /// The call gives the options of the endpoint to the fetcher with no
    /// change:
    ///
    /// - The options can name one or more mirrors.
    /// - The fetcher follows redirects up to
    ///   [`max_redirects`](ostrya_fetch::FetcherOptions::max_redirects).
    /// - [`max_outstanding`](ostrya_fetch::FetcherOptions::max_outstanding) is
    ///   the request limit of the pull.
    /// - A `User-Agent` entry of
    ///   [`headers`](ostrya_fetch::FetcherOptions::headers) sets the agent.
    /// - The call does not apply [`check_base_url`](ostrya_fetch::check_base_url)
    ///   to the mirrors.
    ///
    /// The options give the agent and the request limit, so `opts` must set no
    /// field.
    ///
    /// With [`TrustRoots::System`](ostrya_fetch::TrustRoots::System), the call
    /// reads the trust store of the host by the rule of
    /// [`Fetcher::new`](ostrya_fetch::Fetcher::new). An `https://` mirror
    /// causes the read. The options that [`Endpoint::parse`] gives an
    /// `http://` address also cause it, because their `max_redirects` is 10.
    ///
    /// # Errors
    ///
    /// - The errors of [`StreamSession::connect`] for an ssh endpoint.
    /// - [`Error::InvalidInput`] if `opts` sets
    ///   [`agent`](StreamSessionOptions::agent) or
    ///   [`max_outstanding`](StreamSessionOptions::max_outstanding) for an HTTP
    ///   endpoint.
    /// - [`Error::InvalidInput`] if the options of an HTTP endpoint name no
    ///   mirror.
    /// - [`Error::Fetch`] if [`Fetcher::new`](ostrya_fetch::Fetcher::new)
    ///   refuses the options of an HTTP endpoint.
    pub async fn connect(endpoint: Endpoint, opts: StreamSessionOptions) -> Result<PullSession> {
        match endpoint {
            Endpoint::Ssh { address, options } => StreamSession::connect(&address, &options, opts)
                .await
                .map(PullSession::Stream),
            // The future of the fetcher construction is boxed, so that the
            // future of an ssh connect does not hold it.
            Endpoint::Http(http) => Ok(PullSession::Http(
                Box::pin(http::prepare_pull(http, opts)).await?,
            )),
        }
    }
}

/// Builds the command line of the ssh client of a pull to `address`, with
/// `env` as the value of the `OSTRYA_SSH_COMMAND` environment variable.
fn pull_command_line(
    address: &SshAddress,
    options: &SshOptions,
    env: Option<&OsStr>,
) -> Result<Vec<String>> {
    let program = options.program(env)?;
    let send = ssh::send_command(options.remote_command.as_deref())?;
    Ok(address.command_line(program, send))
}

/// Starts `argv` and opens a stream session over its standard input and
/// standard output, with `limit` as the time limit of the session.
async fn spawn_and_open_pull(
    argv: &[String],
    opts: StreamSessionOptions,
    limit: Duration,
) -> Result<StreamSession> {
    let (input, output, transport) = Transport::spawn(argv, limit)?;
    match StreamSession::open(input, output, opts, Some(limit)).await {
        Ok(session) => Ok(session.with_transport(transport)),
        Err(e) => transport.finish(Err(e)).await,
    }
}

/// Opens a stream session as [`StreamSession::connect`] does, with the value of
/// the environment variable and the time limit as parameters.
#[cfg(test)]
async fn connect_pull_with(
    address: &SshAddress,
    options: &SshOptions,
    env: Option<&OsStr>,
    opts: StreamSessionOptions,
    limit: Duration,
) -> Result<StreamSession> {
    let argv = pull_command_line(address, options, env)?;
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
