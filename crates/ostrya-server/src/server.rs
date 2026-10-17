//! The listeners and the connections of a server.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_lite::future;
use futures_rustls::TlsAcceptor;
use futures_rustls::rustls::ServerConfig;
use futures_rustls::rustls::server::danger::ClientCertVerifier;
use hyper::Request;
use hyper::body::Incoming;
use hyper::header::HeaderName;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use ostrya::access::{AuthItem, ClientAccess, ReadAccess};
use ostrya::{ArchiveView, Repo};
use ostrya_fetch::{FuturesIo, RtExecutor, RtTimer};
use ostrya_rt as rt;

use crate::auth::{GroupAuth, Peer};
use crate::cert::{ClientCert, ForwardedCerts};
use crate::endpoint::{EndpointOptions, ReceiveEndpoint};
use crate::error::{Error, Result};
use crate::event::StaleSummaries;
use crate::forwarded::Forwarding;
use crate::options::ServeOptions;
use crate::proxy_protocol::{self, Rewind};
use crate::refs::Listings;
use crate::router::{self, Clients};
use crate::shutdown::{Shutdown, Trigger};
use crate::stall::Stall;

/// The time a TLS handshake has to complete.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The time a connection has to send its PROXY protocol header.
const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// The time an HTTP/1.1 connection has to send the headers of a request.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The most streams one HTTP/2 connection carries at the same time.
const MAX_CONCURRENT_STREAMS: u32 = 32;

/// The largest header list of one request that an HTTP/2 connection takes:
/// 32 KiB.
///
/// The size of the list is the sum, for each header field, of the name, the
/// value, and 32 bytes. The pseudo-header `:path` counts, so the request
/// target counts. The client of a ref listing sends a target of at most
/// 16 KiB, which comes after the base path of the mirror. The limit leaves
/// 16 KiB for the base path and the other fields. A larger list gets 431.
const MAX_HEADER_LIST_SIZE: u32 = 32 * 1024;

/// The wait after an accept fails, for example when the process is out of
/// descriptors, before the listener accepts again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// A server with its listeners bound, ready to [`run`](Server::run).
///
/// # HTTP behavior
///
/// - The server answers `GET` and `HEAD`, except on the ref listing. Outside
///   the receive endpoint and the ref listing, another method gets 405 with
///   `Allow: GET, HEAD`.
/// - With a receive endpoint, a request under the raw path prefix
///   `/_ostrya/receive/v1/` goes to the endpoint if its method is not `GET`
///   or `HEAD`. A `GET` or a `HEAD` under the prefix goes to the archive
///   view and gets 404.
/// - With receive policies, the server identifies the client of each
///   request by the steps of [Authentication](ServeOptions#authentication),
///   after the check of the method. A `GET` and a `HEAD` of the archive
///   view, and a `GET` of the ref listing, get the status of a refusal, 401
///   or 403, with an empty body and `Content-Length: 0`. A 401 carries the
///   two `WWW-Authenticate` headers. Claims that do not parse refuse each
///   read with 403, as [Claims](ServeOptions#claims) states.
/// - The server serves the archive view and the ref listing with the
///   [`ReadAccess`] of the item, as
///   [`ArchiveView`](ArchiveView#read-access) and
///   [`Repo::build_ref_listing`] state. A path that the client cannot read
///   gets the 404 of an absent path.
/// - `summary` and `summary.sig` give the files of the summary of the item
///   of the client, which [`Repo::regenerate_summaries`] writes. An item
///   with no summary gets 404. When the `.access` file of the item holds
///   another digest than the access digest of the item, or does not exist
///   while the file exists, the request gets 404, and the server reports one
///   [`ServerEvent::StaleSummary`](crate::ServerEvent::StaleSummary) for
///   each item in the life of the server. The server computes the digests
///   at start, and reads the files for each request, so a new write of the
///   summaries takes effect while the server runs. A 200 and a 404 of these
///   two paths carry `Cache-Control: private`, because the body depends on
///   the client. A 401 and a 403 do not.
/// - With no receive policies, the server identifies no client. Each read
///   gets the rights of the `anonymous` item under the two implicit groups of
///   a config with no client group, with the collection id of the
///   repository. Each local ref and each mirror ref are served, and
///   `refs/remotes/` is not. `summary` and `summary.sig` are the files at
///   the repository root, with the `.access` file of the `anonymous` item of
///   these implicit groups.
/// - The HTTP layer removes a `#` fragment before the routing, so the server
///   does not see a fragment.
/// - The server percent-decodes the request path. Outside the ref listing,
///   it ignores the query. If the path has a bad escape, a NUL, or bytes
///   that are not UTF-8, the response is 404. The server decodes the path
///   after it identifies the client.
/// - The server answers the raw path `/_ostrya/refs/v1`, with and without a
///   receive endpoint, with the bytes of [`Repo::build_ref_listing`]. The
///   path must match exactly, and the server reads its query. Each pair of
///   the query is `pattern=VALUE`, an entry of the local refs, or
///   `collection=VALUE`, an entry of the collection refs by `ID/NAME`. The
///   raw key is `pattern` or `collection`, and the value is percent-decoded,
///   with `+` that stays `+`. The value is one entry of a
///   [`ostrya::RefSelector`]: a ref pattern with an optional leading `!`.
///   An entry has at most [`ostrya::MAX_REF_ENTRY_PARTS`] parts and
///   [`ostrya::MAX_REF_ENTRY_LEN`] bytes. No `pattern` pair is an empty
///   list, which selects all local refs. With one or more `collection`
///   pairs, the listing holds the selected collection refs in
///   `ostree.summary.collection-map`. With none, it holds no collection ref.
///   The checks come in this order:
///   1. A method other than `GET`, `HEAD` included, gets 405 with
///      `Allow: GET`.
///   2. The server identifies the client. A refusal gets its status.
///   3. A bad pair, a pair with another key, an entry over the limits of one
///      entry, an entry that [`ostrya::RefSelector::parse`] refuses, and a
///      query of more than 256 pairs of the two keys together
///      ([`ostrya::MAX_REF_PATTERNS`]), get 400. An entry given two times
///      for one key counts two times, and the server keeps it one time.
///   4. If 4 listings are in flight over all connections, the request gets
///      503 with `Retry-After: 1`. A listing is in flight from the start of
///      its build until its response body drops.
///
///   Then the server builds the listing with the read rights of the client.
///   Each error of the build gets 500. For each directory under
///   `refs/mirrors/` whose name fails the collection-id rule, the server
///   reports one [`ServerEvent::InvalidCollectionDir`](crate::ServerEvent::InvalidCollectionDir)
///   to [`ServeOptions::on_event`] in the life of the server, and the
///   listing leaves out the directory.
///   A 400, a 405, a 500, and a 503 have an empty body. A 200 carries
///   `Content-Length`, and the server sends the body in frames of at most
///   64 KiB under the body timeout.
/// - A path that the view does not find gets 404 with an empty body. A path
///   that the view refuses gets the same response, so a client cannot tell
///   a private path from an absent one.
/// - If the view returns an error, the response is 500 with an empty body.
/// - A response with a known length carries `Content-Length`. A `.filez`
///   built on request carries no `Content-Length`.
/// - The server reads a file of the archive view in frames of at most
///   64 KiB, and never collects the file whole. The server builds a ref
///   listing whole in memory, at most [`ostrya::MAX_REF_LISTING`] bytes, and
///   sends it in frames of at most 64 KiB.
/// - A `HEAD` takes the answer of [`ArchiveView::head`], which reads no byte
///   of the file. For a `.filez` built on request, it reads no xattr and
///   does no deflate work.
/// - Plain HTTP serves HTTP/1.1. Over TLS, ALPN selects HTTP/2 or HTTP/1.1.
///   An HTTP/2 connection carries at most 32 streams at the same time. It
///   takes a header list of at most 32 KiB for one request, counted as the
///   name, the value, and 32 bytes of each header field. A larger list gets
///   431.
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
///   CA. A client that presents no certificate also completes the handshake,
///   and the other auth items identify it.
/// - With [`ServeOptions::proxy_protocol`], each listener reads a PROXY
///   protocol header, version 1 or 2, at the start of each connection,
///   before the TLS handshake. A connection with no valid header, or with no
///   header within 30 seconds, closes with no response. The bytes after the
///   header go to the TLS handshake or to the HTTP layer.
/// - The server reads the client address, the scheme, and a forwarded
///   certificate from the headers of a trusted proxy, for each request.
///   [Client address](ServeOptions#client-address) and
///   [Forwarded certificate](ServeOptions#forwarded-certificate) state the
///   rules.
pub struct Server {
    listeners: Vec<rt::TcpListener>,
    addrs: Vec<SocketAddr>,
    view: Arc<ArchiveView>,
    repo: Repo,
    clients: Arc<Clients>,
    /// The ref listings of the server.
    listings: Arc<Listings>,
    /// The stale summaries that the server reported.
    stale: StaleSummaries,
    tls: Option<Arc<ServerConfig>>,
    body_timeout: Duration,
    proxy_protocol: bool,
}

/// Returns the receive endpoint of `opts` over `repo`, or `None` if `opts`
/// has no receive policies. With policies, the function checks the options
/// of the endpoint with [`ReceiveEndpoint::new`]. With no policies, it checks
/// nothing. `verifier` is the verifier of the client CA, which checks a
/// forwarded certificate.
fn receive(
    repo: &Repo,
    opts: &ServeOptions,
    verifier: Option<&Arc<dyn ClientCertVerifier>>,
) -> Result<Option<Arc<ReceiveEndpoint<GroupAuth>>>> {
    let Some(policies) = &opts.receive else {
        return Ok(None);
    };
    let forwarding = opts
        .trusted_proxy_header
        .map(|header| Forwarding::new(opts.trusted_proxies.clone(), header));
    let certs = match (&opts.trusted_proxy_client_cert, verifier) {
        (Some(name), Some(verifier)) => {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| Error::Options(format!("a bad header name '{name}'")))?;
            Some(ForwardedCerts::new(name, verifier.clone()))
        }
        _ => None,
    };
    let auth = GroupAuth::new(policies.clone(), opts.allow_cleartext_credentials)
        .with_proxies(forwarding, certs)
        .with_events(opts.on_event.clone());
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
/// - [`Error::Options`] if `trusted_proxy_client_cert` is not a header name
///   ([`ostrya::access::is_header_name`]).
/// - [`Error::Options`] if `trusted_proxy_client_cert` is set and
///   `client_ca_pem` is `None`, or `trusted_proxies` is empty.
/// - [`Error::Options`] if `trusted_proxies` is not empty and
///   `trusted_proxy_header` is `None`, or the reverse.
/// - [`Error::Options`] if `client_ca_pem` is set, and `tls` and
///   `trusted_proxy_client_cert` are `None`.
/// - [`Error::Options`] if a client group of `receive` carries a `tls:*`,
///   `tls:NAME`, or `tls-sha256:HEX` item and `client_ca_pem` is `None`. The
///   message names the group and the item.
/// - [`Error::Tls`] if `client_ca_pem` gives no verifier: it does not decode
///   as PEM, holds no certificate, or holds a certificate that rustls
///   refuses as a trust anchor.
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
    check_proxies(&opts)?;
    let tls_error = |e| match e {
        ostrya_fetch::Error::Fetch(message) => Error::Tls(message),
        other => Error::Tls(other.to_string()),
    };
    let verifier = match &opts.client_ca_pem {
        Some(pem) => Some(ostrya_fetch::client_cert_verifier(pem).map_err(tls_error)?),
        None => None,
    };
    let clients = match receive(&repo, &opts, verifier.as_ref())? {
        Some(endpoint) => Clients::Groups(endpoint),
        None => Clients::Anonymous(anonymous_reads(&repo)),
    };
    let tls = match &opts.tls {
        Some(tls) => Some(
            ostrya_fetch::server_config(
                &tls.cert_chain_pem,
                &tls.key_pem,
                tls.key_passphrase.as_deref(),
                verifier,
            )
            .await
            .map_err(tls_error)?,
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
        view: Arc::new(ArchiveView::new(repo.clone())),
        repo,
        clients: Arc::new(clients),
        listings: Arc::new(Listings::new(opts.on_event.clone())),
        stale: StaleSummaries::new(opts.on_event),
        tls,
        body_timeout: opts.body_timeout,
        proxy_protocol: opts.proxy_protocol,
    })
}

/// Returns the read rights of each request of a server with no receive
/// policies: the rights of the `anonymous` item under the two implicit
/// groups of a config with no client group. The config has the collection id
/// of `repo`, so `refs/mirrors/ID/NAME` of that id is in the local
/// namespace.
fn anonymous_reads(repo: &Repo) -> ReadAccess {
    let access = ClientAccess::implicit(repo.config().collection_id());
    ReadAccess::new(Arc::new(access), AuthItem::Anonymous, None)
}

/// Checks the fields of `opts` that go together: the client CA, the TLS
/// files, the trusted proxies, and their headers. The doc of [`bind`] lists
/// the refusals.
fn check_proxies(opts: &ServeOptions) -> Result<()> {
    if let Some(name) = &opts.trusted_proxy_client_cert {
        if !ostrya::access::is_header_name(name) {
            return Err(Error::Options(format!(
                "the forwarded certificate header '{name}' is not a header name"
            )));
        }
        if opts.client_ca_pem.is_none() {
            return Err(Error::Options(
                "a forwarded certificate header with no client CA".into(),
            ));
        }
        if opts.trusted_proxies.is_empty() {
            return Err(Error::Options(
                "a forwarded certificate header with no trusted proxy".into(),
            ));
        }
    }
    match (opts.trusted_proxies.is_empty(), opts.trusted_proxy_header) {
        (false, None) => {
            return Err(Error::Options(
                "trusted proxies with no header of the client address".into(),
            ));
        }
        (true, Some(header)) => {
            return Err(Error::Options(format!(
                "the client address header {header} with no trusted proxy"
            )));
        }
        _ => {}
    }
    if opts.client_ca_pem.is_some()
        && opts.tls.is_none()
        && opts.trusted_proxy_client_cert.is_none()
    {
        return Err(Error::Options(
            "a client CA with no TLS and no forwarded certificate header".into(),
        ));
    }
    if opts.client_ca_pem.is_none()
        && let Some(policies) = &opts.receive
    {
        for group in policies.access().groups() {
            if let Some(item) = group.auth().iter().find(|item| item.is_tls()) {
                return Err(Error::Options(format!(
                    "[ex-ostrya client \"{}\"] carries the item {item}, and the server has \
                     no client CA",
                    group.name()
                )));
            }
        }
    }
    Ok(())
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
        if let Some(endpoint) = self.clients.endpoint() {
            let endpoint = endpoint.clone();
            let stop = shutdown.wait();
            drop(rt::spawn(async move {
                future::or(endpoint.sweep(), stop).await;
                endpoint.shutdown();
            }));
        }
        let serving = Arc::new(Serving {
            view: self.view,
            repo: self.repo,
            listings: self.listings,
            stale: self.stale,
            clients: self.clients,
            tls: self.tls,
            body_timeout: self.body_timeout,
            proxy_protocol: self.proxy_protocol,
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
    repo: Repo,
    /// The ref listings of the server, over all connections.
    listings: Arc<Listings>,
    /// The stale summaries that the server reported, over all connections.
    stale: StaleSummaries,
    clients: Arc<Clients>,
    tls: Option<Arc<ServerConfig>>,
    body_timeout: Duration,
    /// `true` if each connection starts with a PROXY protocol header.
    proxy_protocol: bool,
}

/// Accepts connections on `listener` and serves each one in a task of its
/// own, until `shutdown` fires.
async fn accept_loop(listener: rt::TcpListener, serving: Arc<Serving>, shutdown: Arc<Shutdown>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let connection = connection(stream, peer, serving.clone());
                let stop = shutdown.wait();
                drop(rt::spawn(future::or(connection, stop)));
            }
            Err(_) => rt::Timer::after(ACCEPT_BACKOFF).await,
        }
    }
}

/// Serves one connection until it ends, or until one of its response bodies
/// waits longer than the body timeout for the client.
async fn connection(stream: rt::TcpStream, addr: SocketAddr, serving: Arc<Serving>) {
    let stall = Stall::new(serving.body_timeout);
    future::or(
        serve_connection(stream, addr, serving, stall.clone()),
        async move { stall.expired().await },
    )
    .await
}

/// Serves one connection from the peer address `addr`. An error ends this
/// connection and no other. With the PROXY protocol, the function first reads
/// the header, and its source address replaces `addr`. A connection with no
/// valid header ends with no byte written. With client groups, each request
/// carries the [`Peer`] of the connection in its extensions. The server then
/// reads the client certificate of a TLS connection one time, for each
/// request of the connection.
async fn serve_connection(
    stream: rt::TcpStream,
    addr: SocketAddr,
    serving: Arc<Serving>,
    stall: Arc<Stall>,
) {
    let (addr, stream): (IpAddr, _) = if serving.proxy_protocol {
        match proxy_protocol::read_header(stream, PROXY_HEADER_TIMEOUT).await {
            Some((source, stream)) => (source.unwrap_or(addr.ip()), stream),
            None => return,
        }
    } else {
        (addr.ip(), Rewind::new(stream))
    };
    let shared = serving.clone();
    let service = move |peer: Peer| {
        service_fn(move |mut req: Request<Incoming>| {
            let serving = shared.clone();
            let stall = stall.clone();
            if serving.clients.endpoint().is_some() {
                req.extensions_mut().insert(peer.clone());
            }
            async move {
                let response = router::handle(
                    &serving.view,
                    &serving.repo,
                    &serving.listings,
                    &serving.stale,
                    &serving.clients,
                    &stall,
                    req,
                )
                .await;
                Ok::<_, Infallible>(response)
            }
        })
    };
    let Some(config) = serving.tls.clone() else {
        let peer = Peer {
            tls: false,
            addr,
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
    let cert = match serving.clients.endpoint() {
        Some(_) => connection
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|der| Arc::new(ClientCert::from_der(der.as_ref()))),
        None => None,
    };
    let peer = Peer {
        tls: true,
        addr,
        cert,
    };
    let service = service(peer);
    let io = FuturesIo::new(stream);
    if h2 {
        let mut builder = http2::Builder::new(RtExecutor);
        builder
            .timer(RtTimer)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .keep_alive_interval(Some(serving.body_timeout / 2))
            .keep_alive_timeout(serving.body_timeout);
        // With a receive endpoint, the windows bound the bytes of the request
        // bodies of one connection that the server did not read. A
        // read-only server keeps the windows of hyper.
        if let Some((stream, connection)) = serving.clients.endpoint().map(|e| e.h2_windows()) {
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
    use ostrya::access::{ForwardedHeader, IpNet};

    use super::*;
    use crate::options::ServerTls;
    use crate::session::tests::TmpRepo;

    const CA_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/ca.pem");

    /// The options with the trusted proxies of 10.0.0.0/8, the header
    /// `X-Forwarded-For`, a forwarded certificate header, and a client CA,
    /// with no TLS.
    fn proxied() -> ServeOptions {
        ServeOptions {
            client_ca_pem: Some(CA_PEM.to_vec()),
            trusted_proxies: vec![IpNet::parse("10.0.0.0/8").unwrap()],
            trusted_proxy_header: Some(ForwardedHeader::XForwardedFor),
            trusted_proxy_client_cert: Some("X-Client-Cert".into()),
            ..ServeOptions::default()
        }
    }

    fn refused(opts: &ServeOptions) -> String {
        match check_proxies(opts) {
            Err(Error::Options(message)) => message,
            other => panic!("{opts:?}: {other:?}"),
        }
    }

    /// A client CA with a forwarded certificate header needs no TLS.
    #[test]
    fn a_client_ca_with_a_forwarded_certificate_header_needs_no_tls() {
        check_proxies(&proxied()).unwrap();
        let tmp = TmpRepo::new("bind-tls-item");
        let opts = ServeOptions {
            receive: Some(
                tmp.policies("[ex-ostrya client \"c\"]\nauth=tls:ostrya test\nallow=w:**\n"),
            ),
            ..proxied()
        };
        check_proxies(&opts).unwrap();
    }

    /// Each field that needs another field is refused without it.
    #[test]
    fn each_field_needs_its_partner() {
        type Change = fn(&mut ServeOptions);
        let cases: [(Change, &str); 7] = [
            (
                |o| o.trusted_proxy_client_cert = Some("X Client".into()),
                "the forwarded certificate header 'X Client' is not a header name",
            ),
            (
                |o| o.trusted_proxy_client_cert = Some(String::new()),
                "the forwarded certificate header '' is not a header name",
            ),
            (
                |o| o.client_ca_pem = None,
                "a forwarded certificate header with no client CA",
            ),
            (
                |o| o.trusted_proxies.clear(),
                "a forwarded certificate header with no trusted proxy",
            ),
            (
                |o| o.trusted_proxy_header = None,
                "trusted proxies with no header of the client address",
            ),
            (
                |o| {
                    o.trusted_proxy_client_cert = None;
                    o.trusted_proxies.clear();
                },
                "the client address header x-forwarded-for with no trusted proxy",
            ),
            (
                |o| o.trusted_proxy_client_cert = None,
                "a client CA with no TLS and no forwarded certificate header",
            ),
        ];
        for (change, message) in cases {
            let mut opts = proxied();
            change(&mut opts);
            assert_eq!(refused(&opts), message);
        }
        let mut opts = proxied();
        opts.trusted_proxy_client_cert = None;
        opts.tls = Some(ServerTls {
            cert_chain_pem: Vec::new(),
            key_pem: Vec::new(),
            key_passphrase: None,
        });
        check_proxies(&opts).unwrap();
        check_proxies(&ServeOptions::default()).unwrap();
    }

    /// A `tls:` item needs a client CA.
    #[test]
    fn a_tls_item_needs_a_client_ca() {
        let tmp = TmpRepo::new("bind-no-ca");
        let opts = ServeOptions {
            receive: Some(tmp.policies("[ex-ostrya client \"c\"]\nauth=tls:*\nallow=w:**\n")),
            ..ServeOptions::default()
        };
        assert_eq!(
            refused(&opts),
            "[ex-ostrya client \"c\"] carries the item tls:*, and the server has no client CA"
        );
    }

    /// A client CA that gives no verifier is a TLS error of `bind`, before
    /// it binds a listener.
    #[test]
    fn a_bad_client_ca_is_a_tls_error() {
        let tmp = TmpRepo::new("bind-bad-ca");
        let opts = ServeOptions {
            client_ca_pem: Some(b"no certificate".to_vec()),
            listen: vec!["127.0.0.1:0".parse().unwrap()],
            ..proxied()
        };
        let err = rt::block_on(bind(tmp.repo.clone(), opts)).err().unwrap();
        assert!(matches!(err, Error::Tls(_)), "{err}");
    }
}
