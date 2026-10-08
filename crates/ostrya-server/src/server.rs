//! The listeners and the connections of a server.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_lite::future;
use futures_rustls::TlsAcceptor;
use futures_rustls::rustls::ServerConfig;
use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use ostrya::{ArchiveView, Checksum, Repo};
use ostrya_fetch::{FuturesIo, RtExecutor, RtTimer};
use ostrya_rt as rt;

use crate::auth::{FileAuth, Peer};
use crate::endpoint::{EndpointOptions, ReceiveEndpoint};
use crate::error::{Error, Result};
use crate::options::ServeOptions;
use crate::router;
use crate::shutdown::{Shutdown, Trigger};
use crate::stall::Stall;

/// The time a TLS handshake has to complete.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The time an HTTP/1.1 connection has to send the headers of a request.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The most streams one HTTP/2 connection carries at the same time.
const MAX_CONCURRENT_STREAMS: u32 = 32;

/// The wait after an accept fails, for example when the process is out of
/// descriptors, before the listener accepts again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// A server with its listeners bound, ready to [`run`](Server::run).
///
/// # HTTP behavior
///
/// - The server answers `GET` and `HEAD`. Outside the receive endpoint,
///   another method gets 405 with `Allow: GET, HEAD`.
/// - With a receive endpoint, a request under the raw path prefix
///   `/_ostrya/receive/v1/` goes to the endpoint if its method is not `GET`
///   or `HEAD`. A `GET` or a `HEAD` under the prefix goes to the archive
///   view and gets 404.
/// - A `GET` and a `HEAD` of the archive view ignore `Authorization`.
/// - The server percent-decodes the request path and ignores the query. If
///   the path has a bad escape, a NUL, or bytes that are not UTF-8, the
///   response is 404.
/// - A path that the view does not find gets 404 with an empty body. A path
///   that the view refuses gets the same response, so a client cannot tell
///   a private path from an absent one.
/// - If the view returns an error, the response is 500 with an empty body.
/// - A response with a known length carries `Content-Length`. A `.filez`
///   built on request carries no `Content-Length`.
/// - The server reads a response body in frames of at most 64 KiB. It never
///   collects the body whole.
/// - A `HEAD` takes the answer of [`ArchiveView::head`], which reads no byte
///   of the file. For a `.filez` built on request, it reads no xattr and
///   does no deflate work.
/// - Plain HTTP serves HTTP/1.1. Over TLS, ALPN selects HTTP/2 or HTTP/1.1.
///   An HTTP/2 connection carries at most 32 streams at the same time.
/// - A TLS handshake has 30 seconds to complete. An HTTP/1.1 connection has
///   30 seconds to send the headers of each request.
/// - With a receive endpoint, the HTTP/2 windows are the windows of
///   [`ReceiveEndpoint::h2_windows`]. A read-only server keeps the windows
///   of hyper.
/// - If a response body waits longer than [`ServeOptions::body_timeout`]
///   for the client, the server ends its connection. If an HTTP/2 peer does
///   not answer a ping within that time, the server ends the connection.
/// - A body that streams gives at most 256 KiB in one run of polls. Then it
///   yields to the executor.
/// - With a client CA, the server verifies a client certificate against the
///   CA. The server also serves a client that presents no certificate.
pub struct Server {
    listeners: Vec<rt::TcpListener>,
    addrs: Vec<SocketAddr>,
    view: Arc<ArchiveView>,
    receive: Option<Arc<ReceiveEndpoint<FileAuth>>>,
    tls: Option<Arc<ServerConfig>>,
    body_timeout: Duration,
}

/// Returns the receive endpoint of `opts` over `repo`, or `None` if `opts`
/// has no receive policy. With a policy, the function checks the
/// authentication methods first, with [`FileAuth::new`]. Then it checks the
/// other options, with [`ReceiveEndpoint::new`]. With no policy, it checks
/// nothing.
fn receive(repo: &Repo, opts: &ServeOptions) -> Result<Option<Arc<ReceiveEndpoint<FileAuth>>>> {
    let Some(policy) = &opts.receive else {
        return Ok(None);
    };
    let auth = FileAuth::new(opts, policy.clone())?;
    let options = EndpointOptions {
        parallel_uploads: opts.parallel_uploads,
        session_idle_timeout: opts.session_idle_timeout,
        max_sessions: opts.max_sessions,
        on_report: opts.on_report.clone(),
    };
    let endpoint = ReceiveEndpoint::new(repo.clone(), auth, options)?;
    Ok(Some(Arc::new(endpoint)))
}

/// Binds the listeners of `opts` and returns a server over `repo`.
///
/// The function checks the options and builds the TLS configuration of
/// `opts`. Then it binds each listen address of `opts`, in order. The server
/// serves the archive view of `repo`. With [`ServeOptions::receive`], it also
/// serves the receive endpoint over `repo`.
///
/// # Errors
///
/// The checks run in this order:
///
/// - [`Error::Options`] if `listen` is empty, or if `body_timeout` is zero.
/// - [`Error::Credentials`] if `receive` is set and a line of `credentials`
///   is malformed.
/// - [`Error::Options`] if `receive` is set and the endpoint has no
///   [authentication method](ServeOptions#authentication).
/// - [`Error::Options`] if `receive` is set, `tls` is `None`, and both
///   `allow_anonymous_push` and `allow_cleartext_credentials` are `false`.
/// - [`Error::Options`] if `receive` is set and `parallel_uploads` is
///   outside `1..=31`, or `session_idle_timeout` or `max_sessions` is zero.
/// - [`Error::Tls`] if the TLS files give no server configuration.
/// - [`Error::Bind`] if a listen address cannot be bound, or if its local
///   address cannot be read.
pub async fn bind(repo: Repo, opts: ServeOptions) -> Result<Server> {
    if opts.listen.is_empty() {
        return Err(Error::Options("no listen address".into()));
    }
    if opts.body_timeout.is_zero() {
        return Err(Error::Options("a body timeout of zero".into()));
    }
    let receive = receive(&repo, &opts)?;
    let tls = match &opts.tls {
        Some(tls) => Some(
            ostrya_fetch::server_config(
                &tls.cert_chain_pem,
                &tls.key_pem,
                tls.key_passphrase.as_deref(),
                tls.client_ca_pem.as_deref(),
            )
            .await
            .map_err(|e| match e {
                ostrya_fetch::Error::Fetch(message) => Error::Tls(message),
                other => Error::Tls(other.to_string()),
            })?,
        ),
        None => None,
    };
    let mut listeners = Vec::with_capacity(opts.listen.len());
    let mut addrs = Vec::with_capacity(opts.listen.len());
    for addr in opts.listen {
        let bound = |source| Error::Bind { addr, source };
        let listener = rt::TcpListener::bind(addr).await.map_err(bound)?;
        addrs.push(listener.local_addr().map_err(bound)?);
        listeners.push(listener);
    }
    Ok(Server {
        listeners,
        addrs,
        view: Arc::new(ArchiveView::new(repo)),
        receive,
        tls,
        body_timeout: opts.body_timeout,
    })
}

/// Binds the listeners of `opts` and runs the server until the future drops.
///
/// The function calls [`bind`], then [`Server::run`].
///
/// # Errors
///
/// The errors of [`bind`](bind#errors). The future of [`Server::run`] never
/// completes, so it gives no error.
pub async fn serve(repo: Repo, opts: ServeOptions) -> Result<()> {
    bind(repo, opts).await?.run().await
}

impl Server {
    /// Returns the address of each listener, in the order of the options.
    ///
    /// If the options give port 0, the address holds the port that the
    /// kernel chose.
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Serves connections until the future drops.
    ///
    /// Each listener accepts in a task of its own. The idle sweep of the
    /// sessions runs in a task of its own. If an accept fails, the listener
    /// accepts again after 100 ms.
    ///
    /// When the future drops, the server closes the listeners and ends each
    /// connection that it accepted. It also stops the receive endpoint,
    /// which aborts each session that does not commit. The
    /// [session rules](ReceiveEndpoint#sessions) of the endpoint state the
    /// other effects.
    ///
    /// # Errors
    ///
    /// The future never completes, so it returns no error.
    pub async fn run(self) -> Result<()> {
        let shutdown = Arc::new(Shutdown::default());
        let _trigger = Trigger(shutdown.clone());
        if let Some(endpoint) = &self.receive {
            let endpoint = endpoint.clone();
            let stop = shutdown.wait();
            drop(rt::spawn(async move {
                future::or(endpoint.sweep(), stop).await;
                endpoint.shutdown();
            }));
        }
        let serving = Arc::new(Serving {
            view: self.view,
            receive: self.receive,
            tls: self.tls,
            body_timeout: self.body_timeout,
        });
        for listener in self.listeners {
            let accept = accept_loop(listener, serving.clone(), shutdown.clone());
            drop(rt::spawn(future::or(accept, shutdown.wait())));
        }
        std::future::pending().await
    }
}

/// The state that each connection of a server shares.
struct Serving {
    view: Arc<ArchiveView>,
    receive: Option<Arc<ReceiveEndpoint<FileAuth>>>,
    tls: Option<Arc<ServerConfig>>,
    body_timeout: Duration,
}

/// Accepts connections on `listener` and serves each one in a task of its
/// own, until `shutdown` fires.
async fn accept_loop(listener: rt::TcpListener, serving: Arc<Serving>, shutdown: Arc<Shutdown>) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let connection = connection(stream, serving.clone());
                let stop = shutdown.wait();
                drop(rt::spawn(future::or(connection, stop)));
            }
            Err(_) => rt::Timer::after(ACCEPT_BACKOFF).await,
        }
    }
}

/// Serves one connection until it ends, or until one of its response bodies
/// waits longer than the body timeout for the client.
async fn connection(stream: rt::TcpStream, serving: Arc<Serving>) {
    let stall = Stall::new(serving.body_timeout);
    future::or(
        serve_connection(stream, serving, stall.clone()),
        async move { stall.expired().await },
    )
    .await
}

/// Serves one connection. An error ends this connection and no other. With
/// a receive endpoint, each request carries the [`Peer`] of the connection
/// in its extensions.
async fn serve_connection(stream: rt::TcpStream, serving: Arc<Serving>, stall: Arc<Stall>) {
    let shared = serving.clone();
    let service = move |peer: Peer| {
        service_fn(move |mut req: Request<Incoming>| {
            let serving = shared.clone();
            let stall = stall.clone();
            if serving.receive.is_some() {
                req.extensions_mut().insert(peer);
            }
            async move {
                let receive = serving.receive.as_deref();
                let response = router::handle(&serving.view, receive, &stall, req).await;
                Ok::<_, Infallible>(response)
            }
        })
    };
    let Some(config) = serving.tls.clone() else {
        let peer = Peer {
            tls: false,
            cert: None,
        };
        let served = http1::Builder::new()
            .timer(RtTimer)
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .serve_connection(FuturesIo::new(stream), service(peer));
        let _ = served.await;
        return;
    };
    let handshake = future::or(
        async { Some(TlsAcceptor::from(config).accept(stream).await) },
        async {
            rt::Timer::after(HANDSHAKE_TIMEOUT).await;
            None
        },
    );
    let Some(Ok(stream)) = handshake.await else {
        return;
    };
    let connection = stream.get_ref().1;
    let h2 = connection.alpn_protocol() == Some(b"h2".as_slice());
    let peer = Peer {
        tls: true,
        cert: connection
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|der| Checksum::sha256(der.as_ref())),
    };
    let service = service(peer);
    let io = FuturesIo::new(stream);
    if h2 {
        let mut builder = http2::Builder::new(RtExecutor);
        builder
            .timer(RtTimer)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .keep_alive_interval(Some(serving.body_timeout / 2))
            .keep_alive_timeout(serving.body_timeout);
        // With a receive endpoint, the windows bound the bytes of the request
        // bodies of one connection that the server did not read. A
        // read-only server keeps the windows of hyper.
        if let Some((stream, connection)) = serving.receive.as_ref().map(|e| e.h2_windows()) {
            builder
                .initial_stream_window_size(stream)
                .initial_connection_window_size(connection);
        }
        let served = builder.serve_connection(io, service);
        let _ = served.await;
    } else {
        let served = http1::Builder::new()
            .timer(RtTimer)
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .serve_connection(io, service);
        let _ = served.await;
    }
}
