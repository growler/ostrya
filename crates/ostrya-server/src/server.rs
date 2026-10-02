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
use ostrya::{ArchiveView, Repo};
use ostrya_fetch::{FuturesIo, RtExecutor, RtTimer};
use ostrya_rt as rt;

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
pub struct Server {
    listeners: Vec<rt::TcpListener>,
    addrs: Vec<SocketAddr>,
    view: Arc<ArchiveView>,
    tls: Option<Arc<ServerConfig>>,
    body_timeout: Duration,
}

/// Build the TLS configuration of `opts`, then bind each listen address of
/// `opts`, in order. The server serves the archive view of `repo`.
pub async fn bind(repo: Repo, opts: ServeOptions) -> Result<Server> {
    if opts.listen.is_empty() {
        return Err(Error::Options("no listen address".into()));
    }
    if opts.body_timeout.is_zero() {
        return Err(Error::Options("a body timeout of zero".into()));
    }
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
    /// closes the listeners and ends every connection it accepted. Each
    /// listener accepts in a task of its own. An accept that fails is tried
    /// again after a short wait, so the future does not complete.
    pub async fn run(self) -> Result<()> {
        let shutdown = Arc::new(Shutdown::default());
        let _trigger = Trigger(shutdown.clone());
        let serving = Arc::new(Serving {
            view: self.view,
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
    let view = serving.view.clone();
    let service = service_fn(move |req| {
        let view = view.clone();
        let stall = stall.clone();
        async move { Ok::<_, Infallible>(router::handle(&view, &stall, req).await) }
    });
    let Some(config) = serving.tls.clone() else {
        let served = http1::Builder::new()
            .timer(RtTimer)
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .serve_connection(FuturesIo::new(stream), service);
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
    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
    let io = FuturesIo::new(stream);
    if h2 {
        let served = http2::Builder::new(RtExecutor)
            .timer(RtTimer)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .keep_alive_interval(Some(serving.body_timeout / 2))
            .keep_alive_timeout(serving.body_timeout)
            .serve_connection(io, service);
        let _ = served.await;
    } else {
        let served = http1::Builder::new()
            .timer(RtTimer)
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .serve_connection(io, service);
        let _ = served.await;
    }
}
