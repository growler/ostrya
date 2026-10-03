//! The listeners and the connections of a server.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_lite::future;
use futures_rustls::TlsAcceptor;
use futures_rustls::rustls::ServerConfig;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use ostrya::{ArchiveView, Checksum, Repo};
use ostrya_fetch::{FuturesIo, RtExecutor, RtTimer};
use ostrya_rt as rt;

use crate::auth::{Auth, Peer, parse_credentials};
use crate::error::{Error, Result};
use crate::options::ServeOptions;
use crate::receive::Receive;
use crate::router;
use crate::session::SessionTable;
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

/// The values of `parallel_uploads` a server takes.
const PARALLEL_UPLOADS: std::ops::RangeInclusive<u32> = 1..=31;

/// The HTTP/2 receive window of one stream of a server with a receive
/// endpoint. The window of the connection is this value times
/// `parallel_uploads`.
const UPLOAD_WINDOW: u32 = 2 * 1024 * 1024;

/// The HTTP/2 receive windows of a server, the stream window and the
/// connection window, or `None` for the windows of hyper. With a receive
/// endpoint of `parallel_uploads`, each stream takes [`UPLOAD_WINDOW`], and
/// the connection takes that for each of the object streams of a session,
/// so the request bodies of one connection hold at most that many bytes
/// that the server did not read.
fn h2_windows(parallel_uploads: Option<u32>) -> Option<(u32, u32)> {
    parallel_uploads.map(|n| (UPLOAD_WINDOW, UPLOAD_WINDOW * n))
}

/// A server with its listeners bound, ready to [`run`](Server::run).
pub struct Server {
    listeners: Vec<rt::TcpListener>,
    addrs: Vec<SocketAddr>,
    view: Arc<ArchiveView>,
    receive: Option<Arc<Receive>>,
    tls: Option<Arc<ServerConfig>>,
    body_timeout: Duration,
}

/// Check the options of the receive endpoint of `opts`, and build it over
/// `repo` when `opts` has a receive policy. An endpoint with no
/// authentication method is refused, and so is an endpoint with no TLS
/// whose one method is the credential file and that takes no credential
/// over plain HTTP, because no request can pass it.
fn receive(repo: &Repo, opts: &ServeOptions) -> Result<Option<Arc<Receive>>> {
    let Some(policy) = &opts.receive else {
        return Ok(None);
    };
    let credentials = match &opts.credentials {
        Some(bytes) => parse_credentials(bytes)?,
        None => Vec::new(),
    };
    let auth = Auth {
        anonymous: opts.allow_anonymous_push,
        client_ca: opts
            .tls
            .as_ref()
            .is_some_and(|tls| tls.client_ca_pem.is_some()),
        cleartext: opts.allow_cleartext_credentials,
        credentials,
    };
    if !auth.has_method() {
        return Err(Error::Options(
            "a receive endpoint with no authentication method".into(),
        ));
    }
    // With no TLS there is no client CA, so the credential lines are the one
    // method, and the endpoint refuses each of them over plain HTTP.
    if opts.tls.is_none() && !auth.anonymous && !auth.cleartext {
        return Err(Error::Options(
            "a receive endpoint over plain HTTP with the credential file as its one method \
             and no allow_cleartext_credentials"
                .into(),
        ));
    }
    if !PARALLEL_UPLOADS.contains(&opts.parallel_uploads) {
        return Err(Error::Options(format!(
            "parallel_uploads {} is outside {}..={}",
            opts.parallel_uploads,
            PARALLEL_UPLOADS.start(),
            PARALLEL_UPLOADS.end()
        )));
    }
    if opts.session_idle_timeout.is_zero() {
        return Err(Error::Options("a session idle timeout of zero".into()));
    }
    if opts.max_sessions == 0 {
        return Err(Error::Options("a session limit of zero".into()));
    }
    Ok(Some(Arc::new(Receive {
        repo: repo.clone(),
        policy: policy.clone(),
        auth,
        parallel_uploads: opts.parallel_uploads,
        on_report: opts.on_report.clone(),
        table: SessionTable::new(opts.max_sessions, opts.session_idle_timeout),
    })))
}

/// Check the options, build the TLS configuration of `opts`, then bind each
/// listen address of `opts`, in order. The server serves the archive view of
/// `repo`, and with [`ServeOptions::receive`] the receive endpoint over
/// `repo`.
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

/// [`bind`], then [`Server::run`].
pub async fn serve(repo: Repo, opts: ServeOptions) -> Result<()> {
    bind(repo, opts).await?.run().await
}

impl Server {
    /// The address each listener is bound to, in the order of the options.
    /// A port 0 of the options is the port the kernel chose.
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Accept and serve connections until the future is dropped. Dropping it
    /// closes the listeners, ends every connection it accepted, and aborts
    /// every session of the receive endpoint that does not commit. A commit
    /// that runs goes on to its end, and a session that opens after that
    /// gets 503. Each listener accepts in a task of its own, and the idle
    /// sweep of the sessions runs in a task of its own. An accept that fails
    /// is tried again after a short wait, so the future does not complete.
    pub async fn run(self) -> Result<()> {
        let shutdown = Arc::new(Shutdown::default());
        let _trigger = Trigger(shutdown.clone());
        if let Some(receive) = &self.receive {
            let table = receive.table.clone();
            let stop = shutdown.wait();
            drop(rt::spawn(async move {
                future::or(table.sweep(), stop).await;
                table.close_all();
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

/// What each connection of a server shares.
struct Serving {
    view: Arc<ArchiveView>,
    receive: Option<Arc<Receive>>,
    tls: Option<Arc<ServerConfig>>,
    body_timeout: Duration,
}

/// Accept connections on `listener` and serve each in a task of its own,
/// until `shutdown` fires.
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

/// Serve one connection until it ends, or until one of its response bodies
/// waits longer than the body timeout for the client.
async fn connection(stream: rt::TcpStream, serving: Arc<Serving>) {
    let stall = Stall::new(serving.body_timeout);
    future::or(
        serve_connection(stream, serving, stall.clone()),
        async move { stall.expired().await },
    )
    .await
}

/// Serve one connection. An error ends the connection alone.
async fn serve_connection(stream: rt::TcpStream, serving: Arc<Serving>, stall: Arc<Stall>) {
    let shared = serving.clone();
    let service = move |peer: Peer| {
        service_fn(move |req| {
            let serving = shared.clone();
            let stall = stall.clone();
            async move {
                let receive = serving.receive.as_deref();
                let response = router::handle(&serving.view, receive, &peer, &stall, req).await;
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
        if let Some((stream, connection)) =
            h2_windows(serving.receive.as_ref().map(|r| r.parallel_uploads))
        {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A server with a receive endpoint widens the HTTP/2 windows for the
    /// object streams of a session, and a read-only server keeps the windows
    /// of hyper. The widest connection window is below the HTTP/2 maximum.
    #[test]
    fn the_h2_windows_follow_parallel_uploads() {
        assert_eq!(h2_windows(None), None);
        assert_eq!(h2_windows(Some(4)), Some((2 << 20, 8 << 20)));
        let (_, widest) = h2_windows(Some(*PARALLEL_UPLOADS.end())).unwrap();
        assert_eq!(widest, 62 << 20);
        assert!(widest < 1 << 31);
    }
}
