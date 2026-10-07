//! Fetcher integration tests (Phase 16a).
//!
//! Every test serves requests from an in-process server built on hyper's server
//! half, over cleartext HTTP/1.1 and over TLS where ALPN selects HTTP/1.1 or
//! HTTP/2. The upload tests at the end send request bodies to the same
//! servers, which record the length and the SHA-256 digest of each body. The
//! fixture certificates under `tests/fixtures/tls/` provide a certificate
//! authority the client trusts, a server certificate for `127.0.0.1`, and a
//! client certificate for the mutual-TLS test.

#[path = "common/proxy.rs"]
mod proxy;

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::future::or;
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use hyper::body::{Body as _, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{HeaderMap, HeaderName};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use ostrya::fetch::Error;
use ostrya::{
    BasicAuth, BearerToken, Checksum, ClientIdentity, FetchRequest, Fetched, Fetcher,
    FetcherOptions, LowSpeed, Priority, Protocol, Proxy, TlsOptions, TrustRoots, UploadBody,
    UploadMethod, UploadRequest, UploadWriter, Uploaded, VerifyingReader,
};
use ostrya_rt::{TcpListener, TcpStream, Timer, block_on, spawn};
use proxy::{TestProxy, Tunnel};
use rustix::net;
use sha2::{Digest, Sha256};

const CA_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/ca.pem");
const SERVER_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.pem");
const SERVER_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.key.pem");
const CLIENT_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/client.pem");
const CLIENT_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/client.key.pem");
const CLIENT_KEY_ENC_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/client.key.enc.pem");
/// The passphrase `tests/fixtures/tls/generate.sh` encrypted that key with.
const CLIENT_KEY_PASSPHRASE: &str = "ostrya test passphrase";
const OTHERNAME_CERT_PEM: &[u8] =
    include_bytes!("../../../tests/fixtures/tls/server-othername.pem");
const OTHERNAME_KEY_PEM: &[u8] =
    include_bytes!("../../../tests/fixtures/tls/server-othername.key.pem");
const UNTRUSTED_CERT_PEM: &[u8] =
    include_bytes!("../../../tests/fixtures/tls/server-untrusted.pem");
const UNTRUSTED_KEY_PEM: &[u8] =
    include_bytes!("../../../tests/fixtures/tls/server-untrusted.key.pem");
const EXPIRED_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server-expired.pem");
const EXPIRED_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server-expired.key.pem");

// --- server plumbing -------------------------------------------------------

/// A `futures-io` stream presented to hyper, the server-side counterpart of the
/// adapter the fetcher uses.
struct TestIo<S> {
    inner: S,
    scratch: Vec<u8>,
}

impl<S: AsyncRead + Unpin> hyper::rt::Read for TestIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let want = buf.remaining().min(16 * 1024);
        if want == 0 {
            return Poll::Ready(Ok(()));
        }
        let me = self.get_mut();
        if me.scratch.len() < want {
            me.scratch.resize(want, 0);
        }
        let n = ready!(Pin::new(&mut me.inner).poll_read(cx, &mut me.scratch[..want]))?;
        buf.put_slice(&me.scratch[..n]);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> hyper::rt::Write for TestIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
}

#[derive(Clone, Copy)]
struct TestExecutor;

impl<F> hyper::rt::Executor<F> for TestExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        drop(spawn(future));
    }
}

/// A response body of pre-baked chunks.
struct TestBody {
    chunks: VecDeque<Bytes>,
    /// The exact length, when the response should declare `Content-Length`.
    exact: Option<u64>,
    /// Whether the body stays open once its chunks are gone, so it never ends.
    endless: bool,
}

impl TestBody {
    /// A body of `bytes`, delivered in one chunk with a declared length.
    fn measured(bytes: &[u8]) -> TestBody {
        TestBody {
            chunks: VecDeque::from([Bytes::copy_from_slice(bytes)]),
            exact: Some(bytes.len() as u64),
            endless: false,
        }
    }

    /// A body delivered in `count` chunks with no declared length, which makes
    /// the server answer with chunked transfer encoding.
    fn chunked(bytes: &[u8], count: usize) -> TestBody {
        let size = bytes.len().div_ceil(count.max(1));
        TestBody {
            chunks: bytes.chunks(size).map(Bytes::copy_from_slice).collect(),
            exact: None,
            endless: false,
        }
    }

    fn empty() -> TestBody {
        TestBody {
            chunks: VecDeque::new(),
            exact: Some(0),
            endless: false,
        }
    }

    /// A body that delivers nothing and never ends.
    fn endless() -> TestBody {
        TestBody {
            chunks: VecDeque::new(),
            exact: None,
            endless: true,
        }
    }
}

impl hyper::body::Body for TestBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let me = self.get_mut();
        match me.chunks.pop_front() {
            Some(chunk) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            None if me.endless => Poll::Pending,
            None => Poll::Ready(None),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.exact {
            Some(n) => SizeHint::with_exact(n),
            None => SizeHint::default(),
        }
    }
}

/// What the client asked for, as the server saw it.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    /// The request target's path alone.
    path: String,
    /// The whole request target, the query string included.
    target: String,
    headers: HeaderMap,
    /// The request body as the server read it: its length, its SHA-256
    /// digest, and whether it reached its end. A handler that reads the body
    /// itself leaves all three at the values of an unread body.
    body_len: u64,
    body_sha256: [u8; 32],
    body_complete: bool,
}

impl Seen {
    /// The head of `request`, with the values of an unread body.
    fn head(request: &Request<Incoming>) -> Seen {
        Seen {
            method: request.method().to_string(),
            path: request.uri().path().to_string(),
            target: request.uri().to_string(),
            headers: request.headers().clone(),
            body_len: 0,
            body_sha256: Sha256::digest(b"").into(),
            body_complete: false,
        }
    }

    /// Read `body` to its end and record it, adding each frame to `received`
    /// as it arrives. The body is hashed as it arrives and never held whole.
    async fn read_body(&mut self, mut body: Incoming, received: &AtomicU64) {
        let mut digest = Sha256::new();
        loop {
            match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        digest.update(&data);
                        self.body_len += data.len() as u64;
                        received.fetch_add(data.len() as u64, Ordering::SeqCst);
                    }
                }
                Some(Err(_)) => break,
                None => {
                    self.body_complete = true;
                    break;
                }
            }
        }
        self.body_sha256 = digest.finalize().into();
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(HeaderName::from_bytes(name.as_bytes()).unwrap())?
            .to_str()
            .ok()
    }
}

/// How a server terminates connections.
enum Transport {
    /// Cleartext HTTP/1.1.
    Cleartext,
    /// TLS, offering these ALPN protocols and asking of its clients what
    /// `client_auth` states.
    Tls {
        alpn: Vec<&'static str>,
        client_auth: ClientAuth,
    },
}

/// What a TLS server asks of its clients.
#[derive(Clone, Copy)]
enum ClientAuth {
    /// No certificate is asked for.
    None,
    /// A certificate signed by the fixture authority is demanded, and a client
    /// that presents none is refused.
    Required,
    /// A certificate signed by the fixture authority is asked for, and a client
    /// that presents none is served. The server records what each connection
    /// presented.
    Optional,
}

/// Which server leaf a TLS test server presents. Each one beyond the fixture
/// leaf fails exactly one of the checks the full verification makes, so a test
/// states which check a bypass dropped.
#[derive(Clone, Copy)]
enum Leaf {
    /// Signed by the fixture authority, valid, and covering both `localhost`
    /// and `127.0.0.1`.
    Fixture,
    /// Signed by the fixture authority and valid, covering neither name.
    OtherName,
    /// Covering both names and valid, signed by an authority nothing trusts.
    Untrusted,
    /// Signed by the fixture authority and covering both names, out of
    /// validity since 2020.
    Expired,
    /// The `server-untrusted` certificate with the `server` private key, which
    /// belongs to a different certificate: every server certificate check the
    /// bypass drops passes for it under `DangerousAcceptAnyChain`, and the
    /// handshake signature the bypass still checks is made with the wrong key.
    MismatchedKey,
}

impl Leaf {
    /// The certificate and the private key, both PEM-encoded.
    fn pem(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Leaf::Fixture => (SERVER_CERT_PEM, SERVER_KEY_PEM),
            Leaf::OtherName => (OTHERNAME_CERT_PEM, OTHERNAME_KEY_PEM),
            Leaf::Untrusted => (UNTRUSTED_CERT_PEM, UNTRUSTED_KEY_PEM),
            Leaf::Expired => (EXPIRED_CERT_PEM, EXPIRED_KEY_PEM),
            Leaf::MismatchedKey => (UNTRUSTED_CERT_PEM, SERVER_KEY_PEM),
        }
    }
}

/// The handler a test installs: it sees the request and the 1-based count of
/// requests this server has answered. The server reads the request body to its
/// end before it calls the handler.
type Handler = Arc<dyn Fn(&Seen, usize) -> Response<TestBody> + Send + Sync>;

/// A handler that reads the request body itself. An error ends the exchange
/// without a response: an HTTP/1.1 connection closes, and an HTTP/2 stream is
/// reset.
type StreamHandler = Arc<
    dyn Fn(
            Request<Incoming>,
        ) -> Pin<Box<dyn Future<Output = io::Result<Response<TestBody>>> + Send>>
        + Send
        + Sync,
>;

/// How a server answers a request.
#[derive(Clone)]
enum Answering {
    /// Read the body, record it, and answer with the handler.
    Collected(Handler),
    /// Record the head and hand the request to the handler.
    Streamed(StreamHandler),
}

/// An in-process HTTP server.
///
/// The accept loop runs in a detached task for the life of the test process;
/// the tests are short and each server answers a handful of requests.
struct TestServer {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    connections: Arc<AtomicUsize>,
    /// The request body bytes the server has read, counted as each frame
    /// arrives.
    received: Arc<AtomicU64>,
    /// Whether each accepted TLS connection presented a client certificate, in
    /// the order the connections arrived.
    client_certificates: Arc<Mutex<Vec<bool>>>,
}

impl TestServer {
    async fn start(transport: Transport, handler: Handler) -> TestServer {
        TestServer::start_on(
            "127.0.0.1:0".parse().unwrap(),
            Leaf::Fixture,
            transport,
            handler,
        )
        .await
    }

    /// A server on an ephemeral port presenting `leaf`.
    async fn start_with_leaf(leaf: Leaf, transport: Transport, handler: Handler) -> TestServer {
        TestServer::start_on("127.0.0.1:0".parse().unwrap(), leaf, transport, handler).await
    }

    async fn start_on(
        bind: SocketAddr,
        leaf: Leaf,
        transport: Transport,
        handler: Handler,
    ) -> TestServer {
        TestServer::start_answering(bind, leaf, transport, Answering::Collected(handler)).await
    }

    /// A server on an ephemeral port whose handler reads each request body
    /// itself.
    async fn start_streamed(transport: Transport, handler: StreamHandler) -> TestServer {
        TestServer::start_answering(
            "127.0.0.1:0".parse().unwrap(),
            Leaf::Fixture,
            transport,
            Answering::Streamed(handler),
        )
        .await
    }

    async fn start_answering(
        bind: SocketAddr,
        leaf: Leaf,
        transport: Transport,
        handler: Answering,
    ) -> TestServer {
        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let client_certificates: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::new(AtomicU64::new(0));
        let acceptor = match &transport {
            Transport::Cleartext => None,
            Transport::Tls { alpn, client_auth } => Some(futures_rustls::TlsAcceptor::from(
                Arc::new(server_config(alpn, *client_auth, leaf)),
            )),
        };
        let task_seen = seen.clone();
        let task_connections = connections.clone();
        let task_certificates = client_certificates.clone();
        let task_received = received.clone();
        drop(spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                task_connections.fetch_add(1, Ordering::SeqCst);
                let handler = handler.clone();
                let seen = task_seen.clone();
                let certificates = task_certificates.clone();
                let received = task_received.clone();
                let acceptor = acceptor.clone();
                drop(spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            let Ok(tls) = acceptor.accept(stream).await else {
                                return;
                            };
                            // The handshake is complete, so the client's
                            // certificate has arrived if it sent one.
                            let presented = tls.get_ref().1.peer_certificates().is_some();
                            certificates.lock().unwrap().push(presented);
                            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                            serve(tls, h2, handler, seen, received).await;
                        }
                        None => serve(stream, false, handler, seen, received).await,
                    }
                }));
            }
        }));
        TestServer {
            addr,
            seen,
            connections,
            received,
            client_certificates,
        }
    }

    /// The base URL clients should use.
    fn url(&self, tls: bool) -> String {
        let scheme = if tls { "https" } else { "http" };
        // The fixture server certificate covers `localhost` and `127.0.0.1`.
        format!("{scheme}://localhost:{}", self.addr.port())
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn requests(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn received(&self) -> u64 {
        self.received.load(Ordering::SeqCst)
    }

    /// Whether each accepted TLS connection presented a client certificate.
    fn client_certificates(&self) -> Vec<bool> {
        self.client_certificates.lock().unwrap().clone()
    }
}

/// Serve one connection.
async fn serve<S>(
    io: S,
    h2: bool,
    handler: Answering,
    seen: Arc<Mutex<Vec<Seen>>>,
    received: Arc<AtomicU64>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let io = TestIo {
        inner: io,
        scratch: Vec::new(),
    };
    let service = service_fn(move |request: Request<Incoming>| {
        let handler = handler.clone();
        let seen = seen.clone();
        let received = received.clone();
        async move {
            let mut record = Seen::head(&request);
            let handler = match handler {
                Answering::Collected(handler) => handler,
                Answering::Streamed(handler) => {
                    seen.lock().unwrap().push(record);
                    return handler(request).await;
                }
            };
            record.read_body(request.into_body(), &received).await;
            let count = {
                let mut log = seen.lock().unwrap();
                log.push(record.clone());
                log.len()
            };
            Ok::<_, io::Error>(handler(&record, count))
        }
    });
    if h2 {
        let _ = hyper::server::conn::http2::Builder::new(TestExecutor)
            .serve_connection(io, service)
            .await;
    } else {
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await;
    }
}

/// The fixture server's rustls configuration.
fn server_config(alpn: &[&str], client_auth: ClientAuth, leaf: Leaf) -> rustls::ServerConfig {
    let provider = Arc::new(rustls_graviola::default_provider());
    let (cert_pem, key_pem) = leaf.pem();
    let certs: Vec<_> = rustls_pemfile::certs(&mut io::BufReader::new(cert_pem))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut io::BufReader::new(key_pem))
        .unwrap()
        .unwrap();
    // The certificate and the key are paired here rather than through
    // `with_single_cert`, which refuses a key that does not belong to the
    // certificate. `Leaf::MismatchedKey` is exactly that pair.
    let signing_key = provider.key_provider.load_private_key(key).unwrap();
    let resolver: Arc<dyn rustls::server::ResolvesServerCert> = Arc::new(
        rustls::sign::SingleCertAndKey::from(rustls::sign::CertifiedKey::new(certs, signing_key)),
    );
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();
    let verifier = |optional: bool| {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut io::BufReader::new(CA_PEM)) {
            roots.add(cert.unwrap()).unwrap();
        }
        let builder =
            rustls::server::WebPkiClientVerifier::builder_with_provider(roots.into(), provider);
        let builder = if optional {
            builder.allow_unauthenticated()
        } else {
            builder
        };
        builder.build().unwrap()
    };
    let mut config = match client_auth {
        ClientAuth::None => builder.with_no_client_auth().with_cert_resolver(resolver),
        ClientAuth::Required => builder
            .with_client_cert_verifier(verifier(false))
            .with_cert_resolver(resolver),
        ClientAuth::Optional => builder
            .with_client_cert_verifier(verifier(true))
            .with_cert_resolver(resolver),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    config
}

// --- client helpers --------------------------------------------------------

/// A handler that answers every request with `body` and a 200.
fn always(body: &'static [u8]) -> Handler {
    Arc::new(move |_seen, _count| {
        Response::builder()
            .status(StatusCode::OK)
            .body(TestBody::measured(body))
            .unwrap()
    })
}

/// A handler that answers every request with `status` and no body.
fn always_status(status: u16) -> Handler {
    Arc::new(move |_seen, _count| {
        Response::builder()
            .status(status)
            .body(TestBody::empty())
            .unwrap()
    })
}

/// A response that redirects to `location` with `status` and an empty body.
fn redirect(status: u16, location: &str) -> Response<TestBody> {
    Response::builder()
        .status(status)
        .header("location", location)
        .body(TestBody::empty())
        .unwrap()
}

/// A handler that redirects the first request to `location` and answers every
/// one after it with `body` and a 200.
fn redirect_once(location: String, body: &'static [u8]) -> Handler {
    Arc::new(move |_seen, count| {
        if count == 1 {
            redirect(302, &location)
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .body(TestBody::measured(body))
                .unwrap()
        }
    })
}

/// Fetch `path` and return the error the fetch failed with.
async fn fetch_error(fetcher: &Fetcher, path: &str) -> Error {
    match fetcher.fetch(FetchRequest::path(path)).await {
        Ok(_) => panic!("the fetch of {path} was expected to fail"),
        Err(err) => err,
    }
}

/// A peer that accepts a connection, reads what the client sent, answers with
/// `answer`, and then holds the connection open without another byte. An empty
/// answer stands in for a mirror that never replies at all.
async fn stalling_server(answer: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    drop(spawn(async move {
        // The accepted connections are kept so the peer stays silent instead of
        // closing, which is what makes the client wait.
        let mut held = Vec::new();
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            if !answer.is_empty() {
                stream.write_all(answer).await.unwrap();
                stream.flush().await.unwrap();
            }
            held.push(stream);
        }
    }));
    addr
}

/// A peer that answers every request with a head declaring `body`, and then
/// sends `body` a `step`-byte piece at a time, one piece every `interval`, on a
/// connection of its own. With `head` false it answers nothing and holds the
/// connection open. The counter reports how many requests the peer read.
async fn trickling_server(
    head: bool,
    body: &'static [u8],
    step: usize,
    interval: Duration,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    drop(spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            counter.fetch_add(1, Ordering::SeqCst);
            if !head {
                held.push(stream);
                continue;
            }
            drop(spawn(async move {
                let answer = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                if stream.write_all(answer.as_bytes()).await.is_err() {
                    return;
                }
                for piece in body.chunks(step) {
                    // A client that gave up closes the connection, which ends
                    // the trickle.
                    if stream.write_all(piece).await.is_err() || stream.flush().await.is_err() {
                        return;
                    }
                    Timer::after(interval).await;
                }
            }));
        }
    }));
    (addr, requests)
}

/// The body the trickling tests send.
static TRICKLED: [u8; 4096] = [b'x'; 4096];

/// A low-speed rule of `limit` bytes per second, which the rate may stay below
/// for `millis` milliseconds.
fn low_speed(limit: u32, millis: u64) -> Option<LowSpeed> {
    Some(LowSpeed {
        limit,
        time: Duration::from_millis(millis),
    })
}

/// A peer that accepts a connection, reads what the client sent, answers with
/// `answer`, and closes the connection. With a head that declares more bytes
/// than `answer` carries, the body is cut short mid-stream.
async fn truncating_server(answer: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    drop(spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            stream.write_all(answer).await.unwrap();
            stream.flush().await.unwrap();
            stream.close().await.unwrap();
        }
    }));
    addr
}

/// A peer that answers every `CONNECT` with a 200 carrying bytes behind it, and
/// then holds the connection open. Nothing follows a `CONNECT` response before
/// the client has spoken, so those bytes are what the tunnel refuses.
async fn talkative_connect_proxy() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    drop(spawn(async move {
        // The accepted connections are kept, so the client reads the answer and
        // not a close.
        let mut held = Vec::new();
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            let answer = b"HTTP/1.1 200 Connection established\r\n\r\nsurprise";
            stream.write_all(answer).await.unwrap();
            stream.flush().await.unwrap();
            held.push(stream);
        }
    }));
    addr
}

/// A peer that answers every request with a redirect declaring a body it does
/// not finish sending, and then holds the connection open without another byte.
/// Every hop leaves a body short of its declared length, which is what an
/// attempt drains. The counter reports how many requests the peer read.
async fn short_redirecting_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    drop(spawn(async move {
        // The accepted connections are kept so the peer stays silent instead of
        // closing, which is what leaves the declared body unfinished.
        let mut held = Vec::new();
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            let hop = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let answer = format!(
                "HTTP/1.1 302 Found\r\nLocation: /hop{hop}\r\nContent-Length: 64\r\n\r\nshort"
            );
            stream.write_all(answer.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            held.push(stream);
        }
    }));
    (addr, requests)
}

/// Options for a client that trusts the fixture authority.
fn tls_options(identity: Option<ClientIdentity>) -> TlsOptions {
    TlsOptions {
        roots: TrustRoots::Pem(CA_PEM.to_vec()),
        client_identity: identity,
    }
}

/// Fetch `path` at `priority`, reading the body out so the permit is released.
/// Owned arguments, so the whole thing can be spawned.
async fn queued(fetcher: Fetcher, path: &'static str, priority: Priority) {
    let fetched = fetcher
        .fetch(FetchRequest {
            priority,
            ..FetchRequest::path(path)
        })
        .await
        .unwrap();
    let Fetched::Body(mut body) = fetched else {
        panic!("unexpected 304 for {path}");
    };
    let mut out = Vec::new();
    body.read_to_end(&mut out).await.unwrap();
}

/// Fetch `path` and return the body's bytes with the protocol that carried it.
async fn fetch_bytes(fetcher: &Fetcher, path: &str) -> (Vec<u8>, Protocol) {
    match fetcher.fetch(FetchRequest::path(path)).await.unwrap() {
        Fetched::Body(mut body) => {
            let protocol = body.protocol();
            let mut out = Vec::new();
            body.read_to_end(&mut out).await.unwrap();
            (out, protocol)
        }
        Fetched::NotModified => panic!("unexpected 304 for {path}"),
    }
}

/// Fetch the absolute URL `url` and return the body's bytes with the protocol
/// that carried it.
async fn fetch_url_bytes(fetcher: &Fetcher, url: &str) -> (Vec<u8>, Protocol) {
    match fetcher.fetch(FetchRequest::url(url)).await.unwrap() {
        Fetched::Body(mut body) => {
            let protocol = body.protocol();
            let mut out = Vec::new();
            body.read_to_end(&mut out).await.unwrap();
            (out, protocol)
        }
        Fetched::NotModified => panic!("unexpected 304 for {url}"),
    }
}

/// Read a fetched body to the end, which releases the admission permit.
async fn read_body(fetched: Fetched) -> Vec<u8> {
    let Fetched::Body(mut body) = fetched else {
        panic!("unexpected 304");
    };
    let mut out = Vec::new();
    body.read_to_end(&mut out).await.unwrap();
    out
}

/// Options for a fetcher with no mirror, which serves the URLs its requests
/// name. The fixture anchors stand in for the host trust store, which an empty
/// mirror list otherwise demands.
fn mirrorless_options() -> FetcherOptions {
    FetcherOptions {
        tls: tls_options(None),
        proxy: Proxy::None,
        ..FetcherOptions::default()
    }
}

/// Options for a fetcher whose mirror is `url` and which reaches every origin
/// directly.
///
/// A test that is not about the proxy states this, so the proxy variables the
/// host running the suite holds decide nothing: the default form reads them,
/// and a fetcher built under one would travel to a proxy no test started.
fn direct_options(url: impl Into<String>) -> FetcherOptions {
    FetcherOptions {
        proxy: Proxy::None,
        ..FetcherOptions::new(url)
    }
}

/// Credentials a test sends.
fn basic_auth(user: &str, password: &str) -> BasicAuth {
    BasicAuth {
        user: user.to_owned(),
        password: password.to_owned(),
    }
}

// --- tests -----------------------------------------------------------------

#[test]
fn fetches_a_body_over_cleartext_http1() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"object bytes")).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        let (bytes, protocol) = fetch_bytes(&fetcher, "objects/ab/cd.filez").await;
        assert_eq!(bytes, b"object bytes");
        assert_eq!(protocol, Protocol::Http11);
        assert_eq!(server.seen()[0].path, "/objects/ab/cd.filez");
        assert_eq!(
            server.seen()[0].header("user-agent"),
            Some(concat!("ostrya/", env!("CARGO_PKG_VERSION")))
        );
    });
}

/// A mirror URL may name its host as an IPv6 literal. The brackets are the
/// URL's, not the address's: the connect target is the address alone, while the
/// `Host` header carries the bracketed form.
#[test]
fn fetches_from_an_ipv6_literal_mirror() {
    block_on(async {
        // A client of another test that dials `localhost` tries `::1` first,
        // so the port number is held on 127.0.0.1 as well.
        let reserved = reserved_port();
        let port = reserved.port;
        let server = TestServer::start_on(
            format!("[::1]:{port}").parse().unwrap(),
            Leaf::Fixture,
            Transport::Cleartext,
            always(b"object bytes"),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(format!("http://[::1]:{port}/repo")))
            .await
            .unwrap();

        let (bytes, _) = fetch_bytes(&fetcher, "objects/ab/cd.filez").await;
        assert_eq!(bytes, b"object bytes");
        assert_eq!(server.seen()[0].path, "/repo/objects/ab/cd.filez");
        assert_eq!(
            server.seen()[0].header("host"),
            Some(format!("[::1]:{port}").as_str())
        );
    });
}

/// An HTTP/1.1 request must carry the origin-form target and a `Host` header.
/// The absolute form belongs to proxy requests, and a plain static-file server
/// -- what an ostree repository is usually served by -- answers 404 to it.
#[test]
fn http1_requests_use_origin_form_with_a_host_header() {
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn(async move {
            let (mut stream, _peer) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).await.unwrap() == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            stream.flush().await.unwrap();
            String::from_utf8(head).unwrap()
        });

        let base = format!("http://127.0.0.1:{}/repo", addr.port());
        let fetcher = Fetcher::new(direct_options(base)).await.unwrap();
        let (bytes, _) = fetch_bytes(&fetcher, "objects/ab/cd.filez").await;
        assert_eq!(bytes, b"ok");

        let head = server.await;
        let request_line = head.lines().next().unwrap();
        assert_eq!(request_line, "GET /repo/objects/ab/cd.filez HTTP/1.1");
        assert!(
            head.to_lowercase()
                .contains(&format!("host: 127.0.0.1:{}", addr.port())),
            "{head}"
        );
    });
}

#[test]
fn alpn_selects_http2_over_tls() {
    block_on(async {
        let server = TestServer::start(
            Transport::Tls {
                alpn: vec!["h2", "http/1.1"],
                client_auth: ClientAuth::None,
            },
            always(b"over h2"),
        )
        .await;
        let mut options = direct_options(server.url(true));
        options.tls = tls_options(None);
        let fetcher = Fetcher::new(options).await.unwrap();

        let (bytes, protocol) = fetch_bytes(&fetcher, "summary").await;
        assert_eq!(bytes, b"over h2");
        assert_eq!(protocol, Protocol::Http2);
    });
}

#[test]
fn disabling_http2_negotiates_http1_over_tls() {
    block_on(async {
        // The server offers HTTP/2, so the version comes from the client's offer.
        let server = TestServer::start(
            Transport::Tls {
                alpn: vec!["h2", "http/1.1"],
                client_auth: ClientAuth::None,
            },
            always(b"over h1"),
        )
        .await;
        let mut options = direct_options(server.url(true));
        options.tls = tls_options(None);
        options.http2 = false;
        let fetcher = Fetcher::new(options).await.unwrap();

        let (bytes, protocol) = fetch_bytes(&fetcher, "summary").await;
        assert_eq!(bytes, b"over h1");
        assert_eq!(protocol, Protocol::Http11);
    });
}

#[test]
fn a_conditional_fetch_resolves_to_not_modified() {
    block_on(async {
        let handler: Handler = Arc::new(|seen, _count| {
            if seen.header("if-none-match") == Some("\"v1\"") {
                return Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .body(TestBody::empty())
                    .unwrap();
            }
            Response::builder()
                .status(StatusCode::OK)
                .header("etag", "\"v1\"")
                .header("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")
                .body(TestBody::measured(b"summary bytes"))
                .unwrap()
        });
        let server = TestServer::start(Transport::Cleartext, handler).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        let validators = match fetcher.fetch(FetchRequest::path("summary")).await.unwrap() {
            Fetched::Body(mut body) => {
                let validators = body.validators().clone();
                let mut out = Vec::new();
                body.read_to_end(&mut out).await.unwrap();
                assert_eq!(out, b"summary bytes");
                validators
            }
            Fetched::NotModified => panic!("first fetch was conditional"),
        };
        assert_eq!(validators.etag.as_deref(), Some("\"v1\""));
        assert_eq!(
            validators.last_modified.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );

        let mut request = FetchRequest::path("summary");
        request.validators = Some(&validators);
        assert!(matches!(
            fetcher.fetch(request).await.unwrap(),
            Fetched::NotModified
        ));
        // The conditional request replayed both validators.
        let second = &server.seen()[1];
        assert_eq!(second.header("if-none-match"), Some("\"v1\""));
        assert_eq!(
            second.header("if-modified-since"),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );
    });
}

#[test]
fn a_missing_object_reports_its_status_without_retrying() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always_status(404)).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        let err = fetcher
            .fetch(FetchRequest::path("objects/ab/cd.filez"))
            .await
            .unwrap_err();
        match err {
            Error::HttpStatus { status, ref url } => {
                assert_eq!(status, 404);
                assert!(url.ends_with("/objects/ab/cd.filez"), "{url}");
            }
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(server.requests(), 1);
    });
}

#[test]
fn a_server_error_is_retried_and_then_succeeds() {
    block_on(async {
        // The first two attempts fail with a retryable status.
        let handler: Handler = Arc::new(|_seen, count| {
            if count <= 2 {
                return Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(TestBody::empty())
                    .unwrap();
            }
            Response::builder()
                .status(StatusCode::OK)
                .body(TestBody::measured(b"eventually"))
                .unwrap()
        });
        let server = TestServer::start(Transport::Cleartext, handler).await;
        let mut options = direct_options(server.url(false));
        options.max_retries = 3;
        let fetcher = Fetcher::new(options).await.unwrap();

        let (bytes, _) = fetch_bytes(&fetcher, "config").await;
        assert_eq!(bytes, b"eventually");
        assert_eq!(server.requests(), 3);
    });
}

#[test]
fn retries_stop_at_the_configured_count() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always_status(503)).await;
        let mut options = direct_options(server.url(false));
        options.max_retries = 1;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::path("config"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::HttpStatus { status: 503, .. }),
            "{err}"
        );
        // One round plus one retry.
        assert_eq!(server.requests(), 2);
    });
}

/// A mirror that answered definitively answers the same in every round, so a
/// repeated round asks only the mirrors that failed retryably. Running out of
/// rounds reports the same thing running out of mirrors does: the earliest
/// definitive answer, which here is the first mirror's, from the first round.
#[test]
fn a_mirror_that_answered_definitively_is_not_asked_again() {
    block_on(async {
        let absent = TestServer::start(Transport::Cleartext, always_status(404)).await;
        let flapping = TestServer::start(Transport::Cleartext, always_status(503)).await;
        let gone = TestServer::start(Transport::Cleartext, always_status(410)).await;
        let mut options = direct_options(absent.url(false));
        options
            .mirrors
            .extend([flapping.url(false), gone.url(false)]);
        options.max_retries = 2;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::path("objects/ab/cd.dirtree"))
            .await
            .unwrap_err();
        // The first mirror in the list is the first that had something to say.
        assert!(
            matches!(err, Error::HttpStatus { status: 404, .. }),
            "{err}"
        );
        // Three rounds for the mirror whose answer another attempt may change,
        // one apiece for the two that answered definitively.
        assert_eq!(flapping.requests(), 3);
        assert_eq!(absent.requests(), 1);
        assert_eq!(gone.requests(), 1);
    });
}

/// The earliest definitive answer is what a fetch reports, from whichever round
/// it came, so an answer given in an earlier round outlives the round it came
/// from.
#[test]
fn a_definitive_answer_from_an_earlier_round_is_reported() {
    block_on(async {
        let absent = TestServer::start(Transport::Cleartext, always_status(404)).await;
        // Retryable in the first round, definitive in the second.
        let handler: Handler = Arc::new(|_seen, count| {
            let status = if count == 1 { 503 } else { 410 };
            Response::builder()
                .status(StatusCode::from_u16(status).unwrap())
                .body(TestBody::empty())
                .unwrap()
        });
        let turning = TestServer::start(Transport::Cleartext, handler).await;
        let mut options = direct_options(absent.url(false));
        options.mirrors.push(turning.url(false));
        options.max_retries = 3;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::path("summary"))
            .await
            .unwrap_err();
        // The 404 came first, in the round before the 410 that ended the fetch.
        assert!(
            matches!(err, Error::HttpStatus { status: 404, .. }),
            "{err}"
        );
        // The second round asked only the mirror that was still retryable, and
        // its definitive answer left nothing to repeat.
        assert_eq!(absent.requests(), 1);
        assert_eq!(turning.requests(), 2);
    });
}

/// A definitive answer is reported even when a retryable failure came first, so
/// a caller that reads 404 as absence reads it through a flaky link.
#[test]
fn a_definitive_answer_after_a_retryable_failure_is_reported() {
    block_on(async {
        // Retryable in the first round, absent in the second.
        let handler: Handler = Arc::new(|_seen, count| {
            let status = if count == 1 { 503 } else { 404 };
            Response::builder()
                .status(StatusCode::from_u16(status).unwrap())
                .body(TestBody::empty())
                .unwrap()
        });
        let turning = TestServer::start(Transport::Cleartext, handler).await;
        let mut options = direct_options(turning.url(false));
        options.max_retries = 3;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::path("summary"))
            .await
            .unwrap_err();
        // The 503 of the first round does not hide the answer of the second.
        assert!(
            matches!(err, Error::HttpStatus { status: 404, .. }),
            "{err}"
        );
        // The 404 settled the one mirror, so the remaining rounds were not run.
        assert_eq!(turning.requests(), 2);
    });
}

#[test]
fn mirrors_are_tried_in_order_until_one_answers() {
    block_on(async {
        let broken = TestServer::start(Transport::Cleartext, always_status(500)).await;
        let absent = TestServer::start(Transport::Cleartext, always_status(404)).await;
        let good = TestServer::start(Transport::Cleartext, always(b"from the third")).await;
        let mut options = direct_options(broken.url(false));
        options.mirrors.extend([absent.url(false), good.url(false)]);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let (bytes, _) = fetch_bytes(&fetcher, "objects/ab/cd.dirtree").await;
        assert_eq!(bytes, b"from the third");
        // Each earlier mirror was asked once, in order.
        assert_eq!(broken.requests(), 1);
        assert_eq!(absent.requests(), 1);
        assert_eq!(good.requests(), 1);
    });
}

/// A path a target cannot carry is the same path for every mirror, so it is
/// rejected before the fetch is admitted: no mirror is connected to, and the
/// failure is reported once.
#[test]
fn an_invalid_path_connects_to_no_mirror() {
    block_on(async {
        let first = TestServer::start(Transport::Cleartext, always(b"unreachable")).await;
        let second = TestServer::start(Transport::Cleartext, always(b"unreachable")).await;
        let mut options = direct_options(first.url(false));
        options.mirrors.push(second.url(false));
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::path("summary?sig=1"))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no query and no fragment"),
            "{err}"
        );
        assert_eq!(first.connections(), 0);
        assert_eq!(second.connections(), 0);

        // The fetcher still serves the next request, so the rejection left no
        // permit or connection behind.
        let (bytes, _) = fetch_bytes(&fetcher, "summary").await;
        assert_eq!(bytes, b"unreachable");
    });
}

// --- url targets, request headers, and request credentials ----------------

/// A URL target names the whole request target, so its query string reaches
/// the handler as it was written, escapes included.
#[test]
fn a_url_target_sends_its_query_string_verbatim() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"signed bytes")).await;
        let fetcher = Fetcher::new(mirrorless_options()).await.unwrap();

        let url = format!("{}/repo/summary?sig=a%2Fb&x=1", server.url(false));
        let (bytes, _) = fetch_url_bytes(&fetcher, &url).await;
        assert_eq!(bytes, b"signed bytes");
        assert_eq!(server.seen()[0].target, "/repo/summary?sig=a%2Fb&x=1");
        assert_eq!(server.seen()[0].path, "/repo/summary");
    });
}

/// Neither userinfo nor a fragment is ever sent, so a URL target carrying one
/// asks for something other than what the caller named. Both are refused
/// before the fetch is admitted: no connection is opened, and the fetcher
/// serves the next request.
#[test]
fn a_url_target_with_userinfo_or_a_fragment_connects_to_nothing() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"unreachable")).await;
        let fetcher = Fetcher::new(mirrorless_options()).await.unwrap();
        let port = server.addr.port();

        for (url, expected) in [
            (
                format!("http://user:pass@localhost:{port}/summary"),
                "userinfo",
            ),
            (format!("http://localhost:{port}/summary#frag"), "fragment"),
        ] {
            let err = fetcher.fetch(FetchRequest::url(&url)).await.unwrap_err();
            assert!(err.to_string().contains(expected), "{url}: {err}");
        }
        assert_eq!(server.requests(), 0);
        assert_eq!(server.connections(), 0);

        let url = format!("http://localhost:{port}/summary");
        let (bytes, _) = fetch_url_bytes(&fetcher, &url).await;
        assert_eq!(bytes, b"unreachable");
    });
}

/// A fetcher with no mirror serves the URLs its requests name, and pools their
/// connections by origin: two URL fetches of one origin travel over one
/// HTTP/2 connection.
#[test]
fn a_mirrorless_fetcher_pools_one_connection_per_origin() {
    block_on(async {
        let server = TestServer::start(
            Transport::Tls {
                alpn: vec!["h2"],
                client_auth: ClientAuth::None,
            },
            always(b"over h2"),
        )
        .await;
        let fetcher = Fetcher::new(mirrorless_options()).await.unwrap();

        let base = server.url(true);
        for name in ["a", "b"] {
            let url = format!("{base}/{name}");
            let (bytes, protocol) = fetch_url_bytes(&fetcher, &url).await;
            assert_eq!(bytes, b"over h2");
            assert_eq!(protocol, Protocol::Http2);
        }
        assert_eq!(server.requests(), 2);
        assert_eq!(server.connections(), 1);
    });
}

/// A request's headers are merged over the fetcher's: one of the same name
/// replaces the fetcher's and is seen once, and one of another name is sent
/// beside the fetcher's own.
#[test]
fn a_request_header_replaces_the_fetchers_header_of_the_same_name() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"bytes")).await;
        let mut options = direct_options(server.url(false));
        options.headers = vec![
            ("x-trace".to_owned(), "fetcher".to_owned()),
            ("x-fetcher-only".to_owned(), "yes".to_owned()),
        ];
        let fetcher = Fetcher::new(options).await.unwrap();

        // The name is written in another case, which a header name compares
        // the same as.
        let headers = vec![
            ("X-Trace".to_owned(), "request".to_owned()),
            ("x-request-only".to_owned(), "yes".to_owned()),
        ];
        let fetched = fetcher
            .fetch(FetchRequest {
                headers: &headers,
                ..FetchRequest::path("summary")
            })
            .await
            .unwrap();
        assert_eq!(read_body(fetched).await, b"bytes");

        let seen = &server.seen()[0];
        assert_eq!(seen.header("x-trace"), Some("request"));
        assert_eq!(seen.headers.get_all("x-trace").iter().count(), 1);
        assert_eq!(seen.header("x-fetcher-only"), Some("yes"));
        assert_eq!(seen.header("x-request-only"), Some("yes"));
    });
}

/// The connection layer frames a request and holds the connection carrying it,
/// so a request header of one of those names is refused before the fetch is
/// admitted: no request reaches the server, and the connection pool is left as
/// it was, so the next fetch over the same fetcher is served.
#[test]
fn a_request_framing_header_reaches_no_server() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"bytes")).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        let headers = vec![("content-length".to_owned(), "10".to_owned())];
        let err = fetcher
            .fetch(FetchRequest {
                headers: &headers,
                ..FetchRequest::path("summary")
            })
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("content-length"), "{message}");
        assert!(message.contains("connection layer"), "{message}");
        assert_eq!(server.requests(), 0);
        assert_eq!(server.connections(), 0);

        let (bytes, _) = fetch_bytes(&fetcher, "summary").await;
        assert_eq!(bytes, b"bytes");
        assert_eq!(server.requests(), 1);
    });
}

/// A fetcher header of a connection-layer name fails the constructor, which is
/// where the fetcher's own headers are read.
#[test]
fn a_fetcher_framing_header_fails_the_constructor() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"unreachable")).await;
        let mut options = direct_options(server.url(false));
        options.headers = vec![("transfer-encoding".to_owned(), "chunked".to_owned())];
        let err = Fetcher::new(options).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("transfer-encoding"), "{message}");
        assert!(message.contains("connection layer"), "{message}");
        assert_eq!(server.connections(), 0);
    });
}

/// A fetch delivers the bytes the remote stores, so every request states that
/// it accepts no content coding, and it states it once.
#[test]
fn every_request_asks_for_no_content_coding() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"object bytes")).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        let (bytes, _) = fetch_bytes(&fetcher, "objects/ab/cd.filez").await;
        assert_eq!(bytes, b"object bytes");
        let seen = &server.seen()[0];
        assert_eq!(seen.header("accept-encoding"), Some("identity"));
        assert_eq!(seen.headers.get_all("accept-encoding").iter().count(), 1);
    });
}

/// A coded body holds bytes other than the ones the remote stores, so a
/// response declaring a coding is refused and the coding is named. The refusal
/// drains the short body the response declared, so the next fetch is served over
/// the same connection.
#[test]
fn a_coded_response_is_refused_and_keeps_its_connection() {
    block_on(async {
        let handler: Handler = Arc::new(|_seen, count| {
            let mut response = Response::builder().status(StatusCode::OK);
            if count == 1 {
                response = response.header("content-encoding", "gzip");
            }
            response.body(TestBody::measured(b"squeezed")).unwrap()
        });
        let server = TestServer::start(Transport::Cleartext, handler).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        let err = fetcher
            .fetch(FetchRequest::path("objects/ab/cd.filez"))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::ContentEncoded { encoding, .. } if encoding == "gzip"),
            "{err}"
        );
        let message = err.to_string();
        assert!(message.contains("gzip"), "{message}");
        assert!(
            message.contains(&format!("{}/objects/ab/cd.filez", server.url(false))),
            "{message}"
        );

        let (bytes, _) = fetch_bytes(&fetcher, "objects/ab/cd.filez").await;
        assert_eq!(bytes, b"squeezed");
        assert_eq!(server.requests(), 2);
        assert_eq!(server.connections(), 1);
    });
}

/// `identity` names no coding, so a response declaring it carries the bytes the
/// remote stores and is served whole.
#[test]
fn a_response_declaring_identity_is_served() {
    block_on(async {
        let handler: Handler = Arc::new(|_seen, _count| {
            Response::builder()
                .status(StatusCode::OK)
                .header("content-encoding", "identity")
                .body(TestBody::measured(b"object bytes"))
                .unwrap()
        });
        let server = TestServer::start(Transport::Cleartext, handler).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        let (bytes, _) = fetch_bytes(&fetcher, "objects/ab/cd.filez").await;
        assert_eq!(bytes, b"object bytes");
    });
}

/// A caller that asks for a content coding of its own replaces what the fetcher
/// asks for, at either layer, and the server sees the caller's value once. The
/// coding the caller asked for is refused all the same, so a caller that wants
/// a coded body decodes it outside the fetcher.
#[test]
fn a_caller_supplied_accept_encoding_replaces_the_fetchers() {
    block_on(async {
        // A server that honors the request: it codes the response where the
        // request asked for gzip, and leaves it alone otherwise.
        let handler: Handler = Arc::new(|seen, _count| {
            let mut response = Response::builder().status(StatusCode::OK);
            if seen.header("accept-encoding") == Some("gzip") {
                response = response.header("content-encoding", "gzip");
            }
            response.body(TestBody::measured(b"bytes")).unwrap()
        });
        let server = TestServer::start(Transport::Cleartext, handler).await;

        // A request header, with the name written in another case.
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let headers = vec![("Accept-Encoding".to_owned(), "gzip".to_owned())];
        let err = fetcher
            .fetch(FetchRequest {
                headers: &headers,
                ..FetchRequest::path("summary")
            })
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::ContentEncoded { encoding, .. } if encoding == "gzip"),
            "{err}"
        );
        let seen = &server.seen()[0];
        assert_eq!(seen.header("accept-encoding"), Some("gzip"));
        assert_eq!(seen.headers.get_all("accept-encoding").iter().count(), 1);

        // A fetcher header, and the `User-Agent` the fetcher sets beside it.
        // The coded answer to the first is refused, and the second asks for no
        // coding, so it is served.
        for (name, value, coded) in [
            ("accept-encoding", "gzip", true),
            ("user-agent", "caller/1", false),
        ] {
            let mut options = direct_options(server.url(false));
            options.headers = vec![(name.to_owned(), value.to_owned())];
            let fetcher = Fetcher::new(options).await.unwrap();
            let before = server.requests();
            let outcome = fetcher.fetch(FetchRequest::path("summary")).await;
            if coded {
                let err = outcome.unwrap_err();
                assert!(
                    matches!(&err, Error::ContentEncoded { encoding, .. } if encoding == "gzip"),
                    "{name}: {err}"
                );
            } else {
                assert_eq!(read_body(outcome.unwrap()).await, b"bytes", "{name}");
            }
            let seen = &server.seen()[before];
            assert_eq!(seen.header(name), Some(value), "{name}");
            assert_eq!(seen.headers.get_all(name).iter().count(), 1, "{name}");
        }
    });
}

/// A transfer coding other than `chunked` leaves the body coded, so a response
/// declaring one is refused and the coding is named. `chunked` frames a message
/// and the connection undoes the framing, so a response carrying it alone
/// delivers the body as the remote wrote it. The peer is raw, since the
/// transfer coding of a response is the connection layer's to write.
#[test]
fn a_transfer_coded_response_is_refused() {
    block_on(async {
        // Each row states the whole answer the peer writes, then the coding the
        // refusal names, or nothing where the response is served.
        for (answer, refused) in [
            // A final coding other than `chunked`, under a body that runs to
            // the close.
            (
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nsqueezed"[..],
                Some("gzip"),
            ),
            // Chunked framing over a coded body: the connection undoes the
            // framing and the coding stays.
            (
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n8\r\nsqueezed\r\n0\r\n\r\n"[..],
                Some("gzip, chunked"),
            ),
            // Chunked framing alone.
            (
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nsqueezed\r\n0\r\n\r\n"[..],
                None,
            ),
        ] {
            let addr = truncating_server(answer).await;
            let base = format!("http://127.0.0.1:{}", addr.port());
            let fetcher = Fetcher::new(direct_options(base)).await.unwrap();
            let outcome = fetcher
                .fetch(FetchRequest::path("objects/ab/cd.filez"))
                .await;
            match refused {
                Some(coding) => {
                    let err = outcome.unwrap_err();
                    assert!(
                        matches!(&err, Error::ContentEncoded { encoding, .. } if encoding == coding),
                        "{coding}: {err}"
                    );
                    assert!(err.to_string().contains(coding), "{err}");
                }
                None => assert_eq!(read_body(outcome.unwrap()).await, b"squeezed"),
            }
        }
    });
}

/// A host is one origin whichever case it is written in, so two URL targets
/// that differ only in the case of the host travel over one connection.
#[test]
fn a_host_written_in_two_cases_shares_one_connection() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"bytes")).await;
        let fetcher = Fetcher::new(mirrorless_options()).await.unwrap();
        let port = server.addr.port();

        for host in ["localhost", "LOCALHOST"] {
            let url = format!("http://{host}:{port}/summary");
            let (bytes, _) = fetch_url_bytes(&fetcher, &url).await;
            assert_eq!(bytes, b"bytes");
        }
        assert_eq!(server.requests(), 2);
        assert_eq!(server.connections(), 1);
    });
}

/// A request's credentials replace the fetcher's, whether the fetcher holds
/// them as credentials or as an `Authorization` header. Both layers reach an
/// https destination, which is where a credential may go.
#[test]
fn a_request_basic_auth_overrides_the_fetchers_authorization() {
    block_on(async {
        let server = TestServer::start(
            Transport::Tls {
                alpn: vec!["http/1.1"],
                client_auth: ClientAuth::None,
            },
            always(b"bytes"),
        )
        .await;
        let auth = basic_auth("u", "p");

        let mut options = direct_options(server.url(true));
        options.tls = tls_options(None);
        options.basic_auth = Some(basic_auth("fetcher", "secret"));
        let fetcher = Fetcher::new(options).await.unwrap();
        let fetched = fetcher
            .fetch(FetchRequest {
                basic_auth: Some(&auth),
                ..FetchRequest::path("one")
            })
            .await
            .unwrap();
        assert_eq!(read_body(fetched).await, b"bytes");

        let mut options = direct_options(server.url(true));
        options.tls = tls_options(None);
        options.headers = vec![("authorization".to_owned(), "Basic ZmV0Y2hlcg==".to_owned())];
        let header_fetcher = Fetcher::new(options).await.unwrap();
        let fetched = header_fetcher
            .fetch(FetchRequest {
                basic_auth: Some(&auth),
                ..FetchRequest::path("two")
            })
            .await
            .unwrap();
        assert_eq!(read_body(fetched).await, b"bytes");

        // base64("u:p"), sent once by each fetcher.
        assert_eq!(server.requests(), 2);
        for seen in server.seen() {
            assert_eq!(seen.header("authorization"), Some("Basic dTpw"));
            assert_eq!(seen.headers.get_all("authorization").iter().count(), 1);
        }
    });
}

/// A credential is withheld from no destination, so a cleartext destination
/// refuses the fetch and is named. A request that means it says so, and the
/// credential goes over cleartext.
#[test]
fn a_request_credential_to_a_cleartext_origin_is_refused() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"bytes")).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let auth = basic_auth("u", "p");

        let err = fetcher
            .fetch(FetchRequest {
                basic_auth: Some(&auth),
                ..FetchRequest::path("summary")
            })
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("carries credentials"), "{message}");
        assert!(
            message.contains(&format!("http://localhost:{}", server.addr.port())),
            "{message}"
        );
        assert_eq!(server.requests(), 0);
        assert_eq!(server.connections(), 0);

        let fetched = fetcher
            .fetch(FetchRequest {
                basic_auth: Some(&auth),
                allow_cleartext_credentials: true,
                ..FetchRequest::path("summary")
            })
            .await
            .unwrap();
        assert_eq!(read_body(fetched).await, b"bytes");
        assert_eq!(server.seen()[0].header("authorization"), Some("Basic dTpw"));
    });
}

/// Credentials beside an `Authorization` header give two answers to one
/// question. The fetcher refuses them at construction, and a request refuses
/// them before it is admitted.
#[test]
fn basic_auth_beside_an_authorization_header_is_refused() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"unreachable")).await;
        let auth = basic_auth("u", "p");

        // An https mirror, so the refusal is the ambiguity and not the
        // cleartext one. The mirror is never contacted.
        let mut options = FetcherOptions {
            tls: tls_options(None),
            ..direct_options("https://secure.example/repo")
        };
        options.headers = vec![("authorization".to_owned(), "Basic aaa".to_owned())];
        options.basic_auth = Some(auth.clone());
        let err = Fetcher::new(options).await.unwrap_err();
        assert!(err.to_string().contains("pass one of them"), "{err}");

        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let headers = vec![("authorization".to_owned(), "Basic aaa".to_owned())];
        let err = fetcher
            .fetch(FetchRequest {
                headers: &headers,
                basic_auth: Some(&auth),
                allow_cleartext_credentials: true,
                ..FetchRequest::path("summary")
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("pass one of them"), "{err}");
        assert_eq!(server.requests(), 0);
    });
}

/// A path target is served under the mirrors, so a fetcher with none has
/// nowhere to send it and says so before the fetch is admitted.
#[test]
fn a_path_target_without_a_mirror_reaches_no_server() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"unreachable")).await;
        let fetcher = Fetcher::new(mirrorless_options()).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::path("summary"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Fetch(_)), "{err}");
        assert!(err.to_string().contains("no mirror is configured"), "{err}");
        assert_eq!(server.requests(), 0);
        assert_eq!(server.connections(), 0);
    });
}

/// The pool is keyed by origin, so a URL target and a path target for one
/// origin travel over one connection.
#[test]
fn a_url_target_shares_the_pooled_connection_with_a_path_target() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"bytes")).await;
        let base = server.url(false);
        let fetcher = Fetcher::new(direct_options(base.clone())).await.unwrap();

        let (bytes, _) = fetch_bytes(&fetcher, "summary").await;
        assert_eq!(bytes, b"bytes");
        let url = format!("{base}/objects/ab/cd.filez");
        let (bytes, _) = fetch_url_bytes(&fetcher, &url).await;
        assert_eq!(bytes, b"bytes");

        assert_eq!(server.requests(), 2);
        assert_eq!(server.connections(), 1);
    });
}

#[test]
fn a_declared_length_over_the_cap_fails_before_streaming() {
    block_on(async {
        let body = vec![b'x'; 4096];
        let handler: Handler = Arc::new(move |_seen, _count| {
            Response::builder()
                .status(StatusCode::OK)
                .body(TestBody::measured(&vec![b'x'; 4096]))
                .unwrap()
        });
        let server = TestServer::start(Transport::Cleartext, handler).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        let mut request = FetchRequest::path("summary");
        request.max_size = Some(1024);
        let err = fetcher.fetch(request).await.unwrap_err();
        assert!(matches!(err, Error::FetchTooLarge { limit: 1024 }), "{err}");
        assert_eq!(body.len(), 4096);
    });
}

#[test]
fn a_fetch_error_converts_into_the_library_error() {
    block_on(async {
        for (status, kind) in [
            (404, io::ErrorKind::NotFound),
            (401, io::ErrorKind::PermissionDenied),
            (403, io::ErrorKind::PermissionDenied),
        ] {
            let server = TestServer::start(Transport::Cleartext, always_status(status)).await;
            let fetcher = Fetcher::new(FetcherOptions {
                max_retries: 0,
                ..direct_options(server.url(false))
            })
            .await
            .unwrap();

            let err = fetch_error(&fetcher, "summary").await;
            let rendered = err.to_string();
            let err = ostrya::Error::from(err);
            assert!(
                matches!(err, ostrya::Error::HttpStatus { status: s, .. } if s == status),
                "{err}"
            );
            assert_eq!(err.to_string(), rendered);
            let io = io::Error::from(err);
            assert_eq!(io.kind(), kind, "{rendered}");
            assert_eq!(io.to_string(), rendered);
        }

        let handler: Handler = Arc::new(|_seen, _count| {
            Response::builder()
                .status(StatusCode::OK)
                .body(TestBody::measured(&vec![b'x'; 4096]))
                .unwrap()
        });
        let server = TestServer::start(Transport::Cleartext, handler).await;
        let fetcher = Fetcher::new(FetcherOptions {
            max_retries: 0,
            ..direct_options(server.url(false))
        })
        .await
        .unwrap();
        let mut request = FetchRequest::path("summary");
        request.max_size = Some(1024);
        let err = fetcher.fetch(request).await.unwrap_err();
        let rendered = err.to_string();
        let err = ostrya::Error::from(err);
        assert!(
            matches!(err, ostrya::Error::FetchTooLarge { limit: 1024 }),
            "{err}"
        );
        assert_eq!(err.to_string(), rendered);
        let io = io::Error::from(err);
        assert_eq!(io.kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(io.to_string(), rendered);
    });
}

#[test]
fn a_body_that_outgrows_the_cap_fails_the_read() {
    block_on(async {
        // No declared length, so the cap can only be enforced while streaming.
        let handler: Handler = Arc::new(|_seen, _count| {
            Response::builder()
                .status(StatusCode::OK)
                .body(TestBody::chunked(&vec![b'y'; 4096], 8))
                .unwrap()
        });
        let server = TestServer::start(Transport::Cleartext, handler).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        let mut request = FetchRequest::path("summary");
        request.max_size = Some(1024);
        let Fetched::Body(mut body) = fetcher.fetch(request).await.unwrap() else {
            panic!("unexpected 304");
        };
        assert_eq!(body.content_length(), None);
        let mut out = Vec::new();
        let err = body.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::FileTooLarge);
        assert!(err.to_string().contains("1024-byte cap"), "{err}");

        // A consumer that reads on sees the failure again, past the end of the
        // response: more reads here than the eight-frame body has frames, so a
        // read that reported the end of stream instead would be caught.
        let mut buf = [0u8; 512];
        for _ in 0..16 {
            let repeat = body.read(&mut buf).await.unwrap_err();
            assert_eq!(repeat.kind(), io::ErrorKind::FileTooLarge);
            assert_eq!(repeat.to_string(), err.to_string());
        }
        assert!(body.read_to_end(&mut out).await.is_err());
    });
}

/// Credentials go only to `https` mirrors, so the server this reaches is a TLS
/// one.
#[test]
fn credentials_and_extra_headers_reach_the_server() {
    block_on(async {
        let server = TestServer::start(
            Transport::Tls {
                alpn: vec!["http/1.1"],
                client_auth: ClientAuth::None,
            },
            always(b"authorized"),
        )
        .await;
        let mut options = direct_options(server.url(true));
        options.tls = tls_options(None);
        options.basic_auth = Some(BasicAuth {
            user: "alice".into(),
            password: "s3cret".into(),
        });
        options.headers = vec![("x-ostrya-test".into(), "yes".into())];
        let fetcher = Fetcher::new(options).await.unwrap();

        let (bytes, _) = fetch_bytes(&fetcher, "config").await;
        assert_eq!(bytes, b"authorized");
        let seen = &server.seen()[0];
        // base64("alice:s3cret")
        assert_eq!(seen.header("authorization"), Some("Basic YWxpY2U6czNjcmV0"));
        assert_eq!(seen.header("x-ostrya-test"), Some("yes"));
    });
}

/// A credential reaches every mirror, so a cleartext mirror alongside one fails
/// the constructor rather than putting the credential on the wire in the clear.
#[test]
fn credentials_with_a_cleartext_mirror_fail_the_constructor() {
    block_on(async {
        let cleartext = TestServer::start(Transport::Cleartext, always(b"unreachable")).await;
        let secure = TestServer::start(
            Transport::Tls {
                alpn: vec!["http/1.1"],
                client_auth: ClientAuth::None,
            },
            always(b"unreachable"),
        )
        .await;

        let mut options = direct_options(secure.url(true));
        options.mirrors.push(cleartext.url(false));
        options.tls = tls_options(None);
        options.basic_auth = Some(BasicAuth {
            user: "alice".into(),
            password: "s3cret".into(),
        });
        let err = Fetcher::new(options).await.unwrap_err();
        assert!(
            err.to_string().contains(&cleartext.url(false)),
            "the cleartext mirror is named: {err}"
        );

        // Nothing was fetched, so neither server was reached.
        assert_eq!(cleartext.connections(), 0);
        assert_eq!(secure.connections(), 0);
    });
}

#[test]
fn a_client_certificate_is_presented_when_the_server_demands_one() {
    block_on(async {
        let server = TestServer::start(
            Transport::Tls {
                alpn: vec!["h2", "http/1.1"],
                client_auth: ClientAuth::Required,
            },
            always(b"mutual"),
        )
        .await;

        let mut with_cert = direct_options(server.url(true));
        with_cert.tls = tls_options(Some(ClientIdentity {
            cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
            key_pem: CLIENT_KEY_PEM.to_vec(),
            key_passphrase: None,
        }));
        let fetcher = Fetcher::new(with_cert).await.unwrap();
        let (bytes, _) = fetch_bytes(&fetcher, "config").await;
        assert_eq!(bytes, b"mutual");

        // Without the certificate the handshake fails, and a failed handshake
        // is retryable, so the attempt is repeated before it is reported.
        let mut without_cert = direct_options(server.url(true));
        without_cert.tls = tls_options(None);
        without_cert.max_retries = 0;
        let fetcher = Fetcher::new(without_cert).await.unwrap();
        let err = fetcher
            .fetch(FetchRequest::path("config"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Fetch(_)), "{err}");
    });
}

/// The same client certificate under an encrypted PKCS#8 key completes client
/// authentication: the fetcher decrypts the key with the passphrase and
/// presents the certificate the server demands.
#[test]
fn an_encrypted_client_key_is_presented_when_the_server_demands_one() {
    block_on(async {
        let server = TestServer::start(
            Transport::Tls {
                alpn: vec!["h2", "http/1.1"],
                client_auth: ClientAuth::Required,
            },
            always(b"mutual"),
        )
        .await;

        let mut options = direct_options(server.url(true));
        options.tls = tls_options(Some(ClientIdentity {
            cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
            key_pem: CLIENT_KEY_ENC_PEM.to_vec(),
            key_passphrase: Some(CLIENT_KEY_PASSPHRASE.to_string()),
        }));
        let fetcher = Fetcher::new(options).await.unwrap();
        let (bytes, _) = fetch_bytes(&fetcher, "config").await;
        assert_eq!(bytes, b"mutual");
        assert_eq!(server.client_certificates(), [true]);
    });
}

/// Fetch one path over TLS from a server presenting `leaf`, verifying it under
/// `roots`. Retries are off, so a refused handshake reports at once rather
/// than spending every round and every backoff first.
async fn tls_fetch(leaf: Leaf, roots: TrustRoots) -> Result<Vec<u8>, Error> {
    let server = TestServer::start_with_leaf(
        leaf,
        Transport::Tls {
            alpn: vec!["h2", "http/1.1"],
            client_auth: ClientAuth::None,
        },
        always(b"served"),
    )
    .await;
    let mut options = direct_options(server.url(true));
    options.tls = TlsOptions {
        roots,
        client_identity: None,
    };
    options.max_retries = 0;
    let fetcher = Fetcher::new(options).await?;
    match fetcher.fetch(FetchRequest::path("config")).await? {
        Fetched::Body(mut body) => {
            let mut out = Vec::new();
            body.read_to_end(&mut out).await.unwrap();
            Ok(out)
        }
        Fetched::NotModified => panic!("unexpected 304"),
    }
}

/// A leaf covering neither name the tests reach fails the host name check
/// alone: the fixture authority signed it and it is in validity. Only the
/// bypass that drops the name check serves it.
#[test]
fn a_name_mismatch_is_served_only_where_the_name_check_is_dropped() {
    block_on(async {
        let bytes = tls_fetch(Leaf::OtherName, TrustRoots::DangerousAcceptAny)
            .await
            .unwrap();
        assert_eq!(bytes, b"served");

        for roots in [
            TrustRoots::Pem(CA_PEM.to_vec()),
            TrustRoots::DangerousAcceptAnyChain,
        ] {
            let err = tls_fetch(Leaf::OtherName, roots.clone()).await.unwrap_err();
            assert!(
                err.to_string()
                    .contains(r#"certificate not valid for name "localhost""#),
                "{roots:?}: {err}"
            );
        }
    });
}

/// A leaf carrying the right name that no trusted authority signed fails the
/// chain check alone. Both bypasses serve it, and the anchors refuse it.
#[test]
fn an_untrusted_chain_is_served_by_either_bypass() {
    block_on(async {
        for roots in [
            TrustRoots::DangerousAcceptAnyChain,
            TrustRoots::DangerousAcceptAny,
        ] {
            let bytes = tls_fetch(Leaf::Untrusted, roots.clone()).await.unwrap();
            assert_eq!(bytes, b"served", "{roots:?}");
        }

        let err = tls_fetch(Leaf::Untrusted, TrustRoots::Pem(CA_PEM.to_vec()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("UnknownIssuer"), "{err}");
    });
}

/// A leaf carrying the right name that the fixture authority signed, whose
/// validity ended in 2020, fails the expiry check alone. Both bypasses serve
/// it, and the anchors refuse it.
#[test]
fn an_expired_leaf_is_served_by_either_bypass() {
    block_on(async {
        for roots in [
            TrustRoots::DangerousAcceptAnyChain,
            TrustRoots::DangerousAcceptAny,
        ] {
            let bytes = tls_fetch(Leaf::Expired, roots.clone()).await.unwrap();
            assert_eq!(bytes, b"served", "{roots:?}");
        }

        let err = tls_fetch(Leaf::Expired, TrustRoots::Pem(CA_PEM.to_vec()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("certificate expired"), "{err}");
    });
}

/// The one check a bypass keeps is the handshake signature. A server that
/// presents the `server-untrusted` certificate and signs with the `server`
/// private key passes every check either bypass drops -- the name check finds
/// the right name in that certificate -- and fails that one, so both bypasses
/// refuse it. The harness pairs the certificate and the key directly, since
/// `with_single_cert` refuses a pair that does not match.
#[test]
fn a_signature_made_with_another_key_is_refused_by_either_bypass() {
    block_on(async {
        for roots in [
            TrustRoots::DangerousAcceptAnyChain,
            TrustRoots::DangerousAcceptAny,
        ] {
            let err = tls_fetch(Leaf::MismatchedKey, roots.clone())
                .await
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("invalid peer certificate: BadSignature"),
                "{roots:?}: {err}"
            );
        }
    });
}

/// A redirect to another origin carries every header but the credentials: the
/// server the route named receives them, and the server the hop reaches
/// receives none of the three. A header that is not a credential reaches both.
#[test]
fn a_redirect_to_another_origin_leaves_the_credentials_behind() {
    block_on(async {
        let hop = TestServer::start(Transport::Cleartext, always(b"hopped")).await;
        let named = TestServer::start(
            Transport::Cleartext,
            redirect_once(format!("{}/hopped", hop.url(false)), b"unreachable"),
        )
        .await;

        let fetcher = Fetcher::new(direct_options(named.url(false)))
            .await
            .unwrap();
        let headers = vec![
            ("authorization".to_owned(), "Basic aaa".to_owned()),
            ("proxy-authorization".to_owned(), "Basic bbb".to_owned()),
            ("cookie".to_owned(), "session=1".to_owned()),
            ("x-trace".to_owned(), "abc".to_owned()),
        ];
        let fetched = fetcher
            .fetch(FetchRequest {
                headers: &headers,
                allow_cleartext_credentials: true,
                ..FetchRequest::path("config")
            })
            .await
            .unwrap();
        assert_eq!(read_body(fetched).await, b"hopped");

        let first = &named.seen()[0];
        assert_eq!(first.header("authorization"), Some("Basic aaa"));
        assert_eq!(first.header("proxy-authorization"), Some("Basic bbb"));
        assert_eq!(first.header("cookie"), Some("session=1"));
        assert_eq!(first.header("x-trace"), Some("abc"));

        let second = &hop.seen()[0];
        assert_eq!(second.path, "/hopped");
        assert_eq!(second.header("authorization"), None);
        assert_eq!(second.header("proxy-authorization"), None);
        assert_eq!(second.header("cookie"), None);
        assert_eq!(second.header("x-trace"), Some("abc"));
        // The fetcher's own headers reach the hop as well.
        assert_eq!(second.header("accept-encoding"), Some("identity"));
        assert!(second.header("user-agent").is_some());
    });
}

/// A hop at the origin the route named is the origin the credentials were
/// meant for, so they go with it.
#[test]
fn a_same_origin_redirect_keeps_the_credentials() {
    block_on(async {
        let server = TestServer::start(
            Transport::Cleartext,
            redirect_once("/elsewhere".to_owned(), b"arrived"),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let headers = vec![("cookie".to_owned(), "session=1".to_owned())];
        let fetched = fetcher
            .fetch(FetchRequest {
                headers: &headers,
                basic_auth: Some(&basic_auth("u", "p")),
                allow_cleartext_credentials: true,
                ..FetchRequest::path("config")
            })
            .await
            .unwrap();
        assert_eq!(read_body(fetched).await, b"arrived");

        let seen = server.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].path, "/elsewhere");
        for request in &seen {
            // base64("u:p")
            assert_eq!(request.header("authorization"), Some("Basic dTpw"));
            assert_eq!(request.header("cookie"), Some("session=1"));
        }
    });
}

/// A `Location` is resolved against the URL of the response that carried it, so
/// a rooted one names a path at that origin and a bare one names a sibling of
/// the path the response was answered at.
#[test]
fn a_relative_location_resolves_against_the_response() {
    block_on(async {
        let server = TestServer::start(
            Transport::Cleartext,
            Arc::new(|_seen: &Seen, count: usize| match count {
                1 => redirect(302, "/deep/path?q=1"),
                2 => redirect(302, "sibling"),
                _ => Response::builder()
                    .status(StatusCode::OK)
                    .body(TestBody::measured(b"arrived"))
                    .unwrap(),
            }),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(format!("{}/base", server.url(false))))
            .await
            .unwrap();
        let (bytes, _) = fetch_bytes(&fetcher, "config").await;
        assert_eq!(bytes, b"arrived");

        let seen = server.seen();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0].target, "/base/config");
        assert_eq!(seen[1].target, "/deep/path?q=1");
        assert_eq!(seen[2].target, "/deep/sibling");
    });
}

/// A scheme-relative `Location` names another authority and takes the scheme of
/// the response that carried it.
#[test]
fn a_scheme_relative_location_keeps_the_scheme() {
    block_on(async {
        let hop = TestServer::start(Transport::Cleartext, always(b"hopped")).await;
        let named = TestServer::start(
            Transport::Cleartext,
            redirect_once(
                format!("//localhost:{}/hopped", hop.addr.port()),
                b"unreachable",
            ),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(named.url(false)))
            .await
            .unwrap();
        let (bytes, _) = fetch_bytes(&fetcher, "config").await;
        assert_eq!(bytes, b"hopped");
        assert_eq!(hop.seen()[0].path, "/hopped");
    });
}

/// A fragment names a part of a representation and reaches no request, so a
/// redirect drops the one its `Location` carries.
#[test]
fn a_fragment_in_a_location_reaches_no_server() {
    block_on(async {
        let server = TestServer::start(
            Transport::Cleartext,
            redirect_once("/other/path#frag".to_owned(), b"arrived"),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let (bytes, _) = fetch_bytes(&fetcher, "config").await;
        assert_eq!(bytes, b"arrived");

        let seen = server.seen();
        assert_eq!(seen[1].target, "/other/path");
        for request in &seen {
            assert!(!request.target.contains('#'), "{}", request.target);
        }
    });
}

/// A request the caller made over tls is not followed onto cleartext: the hop
/// is refused, both URLs are named, and the cleartext server is never asked.
#[test]
fn a_redirect_from_tls_to_cleartext_is_refused() {
    block_on(async {
        let cleartext = TestServer::start(Transport::Cleartext, always(b"unreachable")).await;
        let secure = TestServer::start(
            Transport::Tls {
                alpn: vec!["http/1.1"],
                client_auth: ClientAuth::None,
            },
            redirect_once(format!("{}/hopped", cleartext.url(false)), b"unreachable"),
        )
        .await;

        let mut options = direct_options(secure.url(true));
        options.tls = tls_options(None);
        let fetcher = Fetcher::new(options).await.unwrap();
        let err = fetch_error(&fetcher, "config").await;
        let message = err.to_string();
        assert!(matches!(err, Error::Fetch(_)), "{message}");
        assert!(
            message.contains(&format!("{}/config", secure.url(true))),
            "{message}"
        );
        assert!(
            message.contains(&format!("{}/hopped", cleartext.url(false))),
            "{message}"
        );
        assert!(message.contains("cleartext"), "{message}");
        assert_eq!(cleartext.requests(), 0);
        assert_eq!(cleartext.connections(), 0);
    });
}

/// A chain longer than the limit fails the attempt, and the failure names the
/// hop the limit stopped it at.
#[test]
fn a_chain_longer_than_the_limit_is_refused() {
    block_on(async {
        let server = TestServer::start(
            Transport::Cleartext,
            Arc::new(|_seen: &Seen, count: usize| redirect(302, &format!("/hop{count}"))),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let err = fetch_error(&fetcher, "config").await;
        let Error::RedirectLimit { url, hops } = &err else {
            panic!("{err}");
        };
        assert_eq!(*hops, 10);
        assert_eq!(url, &format!("{}/hop10", server.url(false)));
        // Eleven requests: the first, and one for each of the ten hops.
        assert_eq!(server.requests(), 11);
    });
}

/// A limit of zero follows nothing, which leaves a redirect a definitive answer
/// of its own.
#[test]
fn a_limit_of_zero_follows_nothing() {
    block_on(async {
        let server = TestServer::start(
            Transport::Cleartext,
            redirect_once("/elsewhere".to_owned(), b"unreachable"),
        )
        .await;
        let mut options = direct_options(server.url(false));
        options.max_redirects = 0;
        let fetcher = Fetcher::new(options).await.unwrap();
        let err = fetch_error(&fetcher, "config").await;
        let Error::HttpStatus { status, url } = &err else {
            panic!("{err}");
        };
        assert_eq!(*status, 302);
        assert_eq!(url, &format!("{}/config", server.url(false)));
        assert_eq!(server.requests(), 1);
    });
}

/// A redirect with nothing to follow is reported as the status it answered.
#[test]
fn a_redirect_without_a_location_reports_its_status() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always_status(302)).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let err = fetch_error(&fetcher, "config").await;
        let Error::HttpStatus { status, .. } = &err else {
            panic!("{err}");
        };
        assert_eq!(*status, 302);
        assert_eq!(server.requests(), 1);
    });
}

/// The cap is the caller's bound on the object, so it is compared against the
/// response that answers and against no redirect on the way there: an
/// intermediate response declaring more than the cap leaves the fetch standing.
#[test]
fn the_size_cap_measures_the_final_response_alone() {
    block_on(async {
        let server = TestServer::start(
            Transport::Cleartext,
            Arc::new(|_seen: &Seen, count: usize| {
                if count == 1 {
                    // A redirect whose own body declares far more than the cap.
                    Response::builder()
                        .status(302)
                        .header("location", "/small")
                        .body(TestBody::measured(&[b'x'; 4096]))
                        .unwrap()
                } else {
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(TestBody::measured(b"tiny"))
                        .unwrap()
                }
            }),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let fetched = fetcher
            .fetch(FetchRequest {
                max_size: Some(16),
                ..FetchRequest::path("config")
            })
            .await
            .unwrap();
        assert_eq!(read_body(fetched).await, b"tiny");

        // The response that answers is measured: a final body over the cap
        // fails the fetch.
        let err = fetcher
            .fetch(FetchRequest {
                max_size: Some(2),
                ..FetchRequest::path("config")
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::FetchTooLarge { limit: 2 }), "{err}");
    });
}

/// A configured client certificate identifies the fetcher to the origin its
/// route named and to no other, so a hop at another origin presents none.
///
/// Both servers ask for a certificate and serve a client that presents none, so
/// each records what its connection presented and the chain runs to its end.
/// TLS 1.3 sends the client certificate after the server has finished, and the
/// server's accept resolves once the client's whole flight has arrived, so a
/// certificate the client sent is on the connection by then.
#[test]
fn a_client_certificate_reaches_the_named_origin_alone() {
    block_on(async {
        let hop = TestServer::start(
            Transport::Tls {
                alpn: vec!["http/1.1"],
                client_auth: ClientAuth::Optional,
            },
            always(b"hopped"),
        )
        .await;
        let named = TestServer::start(
            Transport::Tls {
                alpn: vec!["http/1.1"],
                client_auth: ClientAuth::Optional,
            },
            redirect_once(format!("{}/hopped", hop.url(true)), b"unreachable"),
        )
        .await;

        let mut options = direct_options(named.url(true));
        options.tls = tls_options(Some(ClientIdentity {
            cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
            key_pem: CLIENT_KEY_PEM.to_vec(),
            key_passphrase: None,
        }));
        let fetcher = Fetcher::new(options).await.unwrap();
        let (bytes, _) = fetch_bytes(&fetcher, "config").await;
        assert_eq!(bytes, b"hopped");

        // The origin the route named received the certificate, and the hop
        // received none.
        assert_eq!(named.client_certificates(), [true]);
        assert_eq!(hop.client_certificates(), [false]);
        // One request each: the redirect, and the response that answered.
        assert_eq!(named.requests(), 1);
        assert_eq!(hop.requests(), 1);
    });
}

/// An intermediate body is discarded the way an unsuccessful one is, so a chain
/// of short redirects on one origin travels over the connection the first hop
/// opened.
#[test]
fn a_redirect_chain_on_one_origin_travels_over_one_connection() {
    block_on(async {
        let server = TestServer::start(
            Transport::Cleartext,
            Arc::new(|_seen: &Seen, count: usize| {
                if count <= 3 {
                    redirect(302, &format!("/hop{count}"))
                } else {
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(TestBody::measured(b"arrived"))
                        .unwrap()
                }
            }),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let (bytes, protocol) = fetch_bytes(&fetcher, "config").await;
        assert_eq!(bytes, b"arrived");
        assert_eq!(protocol, Protocol::Http11);
        assert_eq!(server.requests(), 4);
        assert_eq!(server.connections(), 1);
    });
}

/// Every drain one attempt makes shares one progress window, however many hops
/// the attempt follows: a peer that answers each hop with a short declared body
/// and then sends fewer bytes than it declared spends that window once.
#[test]
fn one_progress_window_covers_every_drain_of_an_attempt() {
    block_on(async {
        let (addr, requests) = short_redirecting_server().await;
        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(200);
        let fetcher = Fetcher::new(options).await.unwrap();

        let started = Instant::now();
        let err = fetch_error(&fetcher, "config").await;
        let elapsed = started.elapsed();
        assert!(
            matches!(err, Error::RedirectLimit { hops: 10, .. }),
            "{err}"
        );
        // Eleven requests: the first, and one for each of the ten hops.
        assert_eq!(requests.load(Ordering::SeqCst), 11);
        // One window is 200ms, and eleven of them are 2.2s.
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    });
}

/// A `Location` with no value resolves to the URL of the response that carried
/// it, so it names no URL a request can be sent to and the status the response
/// answered is the answer the attempt reports.
#[test]
fn an_empty_location_names_no_url() {
    block_on(async {
        let server = TestServer::start(
            Transport::Cleartext,
            Arc::new(|_seen: &Seen, _count: usize| redirect(302, "")),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let err = fetch_error(&fetcher, "config").await;
        let Error::HttpStatus { status, url } = &err else {
            panic!("{err}");
        };
        assert_eq!(*status, 302);
        assert_eq!(url, &format!("{}/config", server.url(false)));
        assert_eq!(server.requests(), 1);
    });
}

/// The limit stops an attempt at a URL it would otherwise follow, so a redirect
/// with nothing to follow reports the status it answered whatever the hop count,
/// and one that does name a URL reports the limit.
#[test]
fn at_the_limit_a_redirect_reports_what_it_carried() {
    block_on(async {
        let nothing_to_follow = TestServer::start(
            Transport::Cleartext,
            Arc::new(|_seen: &Seen, count: usize| {
                if count <= 2 {
                    redirect(302, &format!("/hop{count}"))
                } else {
                    Response::builder()
                        .status(302)
                        .body(TestBody::empty())
                        .unwrap()
                }
            }),
        )
        .await;
        let mut options = direct_options(nothing_to_follow.url(false));
        options.max_redirects = 2;
        let fetcher = Fetcher::new(options).await.unwrap();
        let err = fetch_error(&fetcher, "config").await;
        let Error::HttpStatus { status, url } = &err else {
            panic!("{err}");
        };
        assert_eq!(*status, 302);
        assert_eq!(url, &format!("{}/hop2", nothing_to_follow.url(false)));
        assert_eq!(nothing_to_follow.requests(), 3);

        let another_hop = TestServer::start(
            Transport::Cleartext,
            Arc::new(|_seen: &Seen, count: usize| redirect(302, &format!("/hop{count}"))),
        )
        .await;
        let mut options = direct_options(another_hop.url(false));
        options.max_redirects = 2;
        let fetcher = Fetcher::new(options).await.unwrap();
        let err = fetch_error(&fetcher, "config").await;
        let Error::RedirectLimit { url, hops } = &err else {
            panic!("{err}");
        };
        assert_eq!(*hops, 2);
        assert_eq!(url, &format!("{}/hop2", another_hop.url(false)));
        assert_eq!(another_hop.requests(), 3);
    });
}

#[test]
fn http1_connections_are_reused_between_fetches() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"pooled")).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        for _ in 0..3 {
            let (bytes, protocol) = fetch_bytes(&fetcher, "config").await;
            assert_eq!(bytes, b"pooled");
            assert_eq!(protocol, Protocol::Http11);
        }
        assert_eq!(server.requests(), 3);
        assert_eq!(server.connections(), 1);
    });
}

#[test]
fn http2_multiplexes_concurrent_fetches_over_one_connection() {
    block_on(async {
        let server = TestServer::start(
            Transport::Tls {
                alpn: vec!["h2"],
                client_auth: ClientAuth::None,
            },
            always(b"multiplexed"),
        )
        .await;
        let mut options = direct_options(server.url(true));
        options.tls = tls_options(None);
        let fetcher = Fetcher::new(options).await.unwrap();

        // Warm the pool so the concurrent fetches share one connection.
        let (bytes, protocol) = fetch_bytes(&fetcher, "config").await;
        assert_eq!(bytes, b"multiplexed");
        assert_eq!(protocol, Protocol::Http2);

        let tasks: Vec<_> = (0..4)
            .map(|i| {
                let fetcher = fetcher.clone();
                spawn(async move {
                    let path = format!("objects/{i:02}/x.filez");
                    let (bytes, protocol) = fetch_bytes(&fetcher, &path).await;
                    assert_eq!(bytes, b"multiplexed");
                    assert_eq!(protocol, Protocol::Http2);
                })
            })
            .collect();
        for task in tasks {
            task.await;
        }
        assert_eq!(server.requests(), 5);
        assert_eq!(server.connections(), 1);
    });
}

#[test]
fn a_fetched_body_verifies_against_its_expected_digest() {
    block_on(async {
        let payload = b"content object payload";
        let server = TestServer::start(Transport::Cleartext, always(payload)).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        let Fetched::Body(body) = fetcher
            .fetch(FetchRequest::path("objects/ab/cd.filez"))
            .await
            .unwrap()
        else {
            panic!("unexpected 304");
        };
        let mut reader = VerifyingReader::new(Checksum::sha256(payload), Sha256::new(), body);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, payload);

        // The same stream against a different digest fails at the end.
        let Fetched::Body(body) = fetcher
            .fetch(FetchRequest::path("objects/ab/cd.filez"))
            .await
            .unwrap()
        else {
            panic!("unexpected 304");
        };
        let mut reader =
            VerifyingReader::new(Checksum::sha256(b"a different object"), Sha256::new(), body);
        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("checksum mismatch"), "{err}");
    });
}

/// A body dropped before the end must not be returned to the connection pool,
/// because the rest of the response is still in flight.
#[test]
fn an_abandoned_body_is_not_pooled() {
    block_on(async {
        let handler: Handler = Arc::new(|_seen, _count| {
            Response::builder()
                .status(StatusCode::OK)
                .body(TestBody::chunked(&vec![b'z'; 64 * 1024], 16))
                .unwrap()
        });
        let server = TestServer::start(Transport::Cleartext, handler).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::path("big")).await.unwrap()
        else {
            panic!("unexpected 304");
        };
        let mut head = [0u8; 16];
        body.read_exact(&mut head).await.unwrap();
        // The counter is bytes off the connection, so one whole 4 KiB frame is
        // counted against the 16 bytes the caller took out of it.
        assert_eq!(body.received(), 64 * 1024 / 16);
        drop(body);

        // The next fetch opens a fresh connection.
        let (bytes, _) = fetch_bytes(&fetcher, "big").await;
        assert_eq!(bytes.len(), 64 * 1024);
        assert_eq!(server.connections(), 2);
    });
}

/// A 404 is the ordinary answer for an object a remote does not hold, so an
/// attempt that ends on one drains the short body it declares and keeps the
/// connection. Otherwise a scan would pay a connection setup per absent object.
#[test]
fn an_unsuccessful_status_with_a_short_body_keeps_its_connection() {
    block_on(async {
        let handler: Handler = Arc::new(|_seen, _count| {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(TestBody::measured(b"<html>not found</html>"))
                .unwrap()
        });
        let server = TestServer::start(Transport::Cleartext, handler).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        for _ in 0..4 {
            let err = fetcher
                .fetch(FetchRequest::path("objects/ab/cd.filez"))
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::HttpStatus { status: 404, .. }),
                "{err}"
            );
        }
        assert_eq!(server.requests(), 4);
        assert_eq!(server.connections(), 1);
    });
}

/// A declared body over the request's cap is the same shape of failure and gets
/// the same treatment, as long as what it declares is small enough to drain.
#[test]
fn an_over_cap_response_with_a_short_body_keeps_its_connection() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"more than asked for")).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        for _ in 0..4 {
            let err = fetcher
                .fetch(FetchRequest {
                    max_size: Some(4),
                    ..FetchRequest::path("summary")
                })
                .await
                .unwrap_err();
            assert!(matches!(err, Error::FetchTooLarge { limit: 4 }), "{err}");
        }
        assert_eq!(server.requests(), 4);
        assert_eq!(server.connections(), 1);
    });
}

/// A body with no declared length is not drained: the rest of the response is
/// still in flight and its size is unknown, so the connection is closed instead.
#[test]
fn an_unsuccessful_status_with_an_undeclared_body_closes_its_connection() {
    block_on(async {
        let handler: Handler = Arc::new(|_seen, _count| {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(TestBody::chunked(&vec![b'z'; 4096], 8))
                .unwrap()
        });
        let server = TestServer::start(Transport::Cleartext, handler).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();

        for _ in 0..3 {
            assert!(
                fetcher
                    .fetch(FetchRequest::path("objects/ab/cd.filez"))
                    .await
                    .is_err()
            );
        }
        assert_eq!(server.connections(), 3);
    });
}

/// The fetcher's admission gate serves the queue highest priority first, which
/// the state machine of a pull relies on: the metadata its scan is blocked on
/// overtakes queued bulk content.
#[test]
fn a_queued_high_priority_fetch_is_served_before_a_low_priority_one() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"served")).await;
        let mut options = direct_options(server.url(false));
        options.max_outstanding = 1;
        let fetcher = Fetcher::new(options).await.unwrap();

        // The one permit is held by a body that has not been read to the end.
        let Fetched::Body(held) = fetcher.fetch(FetchRequest::path("held")).await.unwrap() else {
            panic!("unexpected 304");
        };

        // Queue the low-priority fetch first, so priority and not arrival order
        // is what decides which the freed permit goes to.
        let low = spawn(queued(fetcher.clone(), "objects/low.filez", Priority::Low));
        Timer::after(Duration::from_millis(50)).await;
        let high = spawn(queued(
            fetcher.clone(),
            "objects/high.dirtree",
            Priority::High,
        ));
        Timer::after(Duration::from_millis(50)).await;
        // Neither has reached the server: the permit is still held.
        assert_eq!(server.requests(), 1);

        drop(held);
        high.await;
        low.await;

        let paths: Vec<String> = server.seen().iter().map(|s| s.path.clone()).collect();
        assert_eq!(
            paths,
            ["/held", "/objects/high.dirtree", "/objects/low.filez"]
        );
    });
}

/// The connect deadline covers the TLS handshake, so a peer that accepts the
/// connection and then says nothing fails the attempt.
#[test]
fn a_stalled_handshake_times_out() {
    block_on(async {
        let addr = stalling_server(b"").await;
        let mut options = direct_options(format!("https://localhost:{}", addr.port()));
        options.tls = tls_options(None);
        options.connect_timeout = Duration::from_millis(150);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::path("summary"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    });
}

/// A peer that takes the request and answers nothing fails the attempt once the
/// progress window is gone.
#[test]
fn a_stalled_response_times_out() {
    block_on(async {
        let addr = stalling_server(b"").await;
        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(150);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::path("summary"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no response after"), "{err}");
    });
}

/// The per-attempt deadlines bound one mirror, and a fetch multiplies them by
/// the mirror count and the retry count. The whole-fetch deadline bounds that
/// product, and the attempt it cancels takes the admission permit with it.
#[test]
fn a_fetch_gives_up_when_its_own_deadline_passes() {
    block_on(async {
        let addr = stalling_server(b"").await;
        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(100);
        // Rounds enough that the per-attempt deadline and the backoff alone
        // would keep this fetch going for minutes.
        options.max_retries = 200;
        options.fetch_timeout = Some(Duration::from_millis(300));
        // One permit, so a second fetch is admitted only if the first gave its
        // permit back.
        options.max_outstanding = 1;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::path("summary"))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("fetch of summary timed out after"),
            "{err}"
        );

        let second = or(
            async { Some(fetcher.fetch(FetchRequest::path("summary")).await) },
            async {
                Timer::after(Duration::from_secs(5)).await;
                None
            },
        )
        .await;
        let err = second.expect("the permit outlived the fetch").unwrap_err();
        assert!(
            err.to_string().contains("fetch of summary timed out after"),
            "{err}"
        );
    });
}

/// Without a whole-fetch deadline the mirror-and-retry loop runs to its own end,
/// and a response that arrives is unaffected.
#[test]
fn a_fetch_without_a_deadline_still_completes() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"object bytes")).await;
        let mut options = direct_options(server.url(false));
        options.fetch_timeout = None;
        let fetcher = Fetcher::new(options).await.unwrap();

        let (bytes, _) = fetch_bytes(&fetcher, "objects/ab/cd.filez").await;
        assert_eq!(bytes, b"object bytes");
    });
}

/// A body that stops mid-stream fails the read that finds no bytes, and keeps
/// failing it, rather than waiting for the rest forever.
#[test]
fn a_stalled_body_fails_the_read() {
    block_on(async {
        // A head promising 64 bytes, eight of them, and then silence.
        let addr = stalling_server(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\nfirst   ").await;
        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(150);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::path("big")).await.unwrap()
        else {
            panic!("unexpected 304");
        };
        assert_eq!(body.content_length(), Some(64));
        let mut head = [0u8; 8];
        body.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"first   ");

        let mut rest = [0u8; 8];
        for _ in 0..2 {
            let err = body.read(&mut rest).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert!(err.to_string().contains("delivered nothing"), "{err}");
        }
    });
}

/// A peer that stays silent past the window and then resumes has already failed
/// the body: the read that reported the timeout latched it, so the bytes that
/// follow never reach the consumer and the body never reaches a clean end of
/// stream.
#[test]
fn a_body_that_resumes_after_the_window_stays_failed() {
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let served = spawn(async move {
            let (mut stream, _peer) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            // A head promising 16 bytes, eight of them, silence for longer than
            // the window, and then the rest.
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nfirst   ")
                .await
                .unwrap();
            stream.flush().await.unwrap();
            Timer::after(Duration::from_millis(400)).await;
            stream.write_all(b"second  ").await.unwrap();
            stream.flush().await.unwrap();
        });

        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(150);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::path("big")).await.unwrap()
        else {
            panic!("unexpected 304");
        };
        let mut head = [0u8; 8];
        body.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"first   ");

        let mut rest = [0u8; 8];
        let err = body.read(&mut rest).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("delivered nothing"), "{err}");

        // The rest of the object is on the wire now, and the body still reports
        // the failure rather than handing out what arrived or ending cleanly.
        served.await;
        for _ in 0..2 {
            let repeat = body.read(&mut rest).await.unwrap_err();
            assert_eq!(repeat.kind(), err.kind());
            assert_eq!(repeat.to_string(), err.to_string());
        }
        let mut out = Vec::new();
        assert!(body.read_to_end(&mut out).await.is_err());
        assert!(out.is_empty(), "{out:?}");
    });
}

/// A peer that closes the connection short of the length it declared fails the
/// read, and keeps failing it. hyper reports the body as ended after it reports
/// the error, so an unlatched failure would let the next read hand a consumer a
/// clean end of stream for a truncated object.
#[test]
fn a_truncated_body_fails_the_read() {
    block_on(async {
        // A head promising 64 bytes, eight of them, and then a close.
        let addr =
            truncating_server(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\nfirst   ").await;
        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::path("big")).await.unwrap()
        else {
            panic!("unexpected 304");
        };
        assert_eq!(body.content_length(), Some(64));

        // What arrived is short of the declared length, and the read that finds
        // the failure reports it rather than the end of the object.
        let mut out = Vec::new();
        let err = body.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(out.len() < 64, "{} bytes", out.len());

        // A consumer that reads on sees the same failure, not a clean end of
        // stream.
        let mut buf = [0u8; 8];
        for _ in 0..8 {
            let repeat = body.read(&mut buf).await.unwrap_err();
            assert_eq!(repeat.kind(), err.kind());
            assert_eq!(repeat.to_string(), err.to_string());
        }
        assert!(body.read_to_end(&mut out).await.is_err());
    });
}

/// The window starts at the read that finds nothing, so a body no read has yet
/// found empty is not on the clock at all: a consumer that starts later than the
/// window still reads.
#[test]
fn an_unread_body_is_not_on_the_progress_clock() {
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        drop(spawn(async move {
            let (mut stream, _peer) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n")
                .await
                .unwrap();
            stream.flush().await.unwrap();
            // The payload follows later than the window the client is given.
            Timer::after(Duration::from_millis(400)).await;
            stream.write_all(b"late one").await.unwrap();
            stream.flush().await.unwrap();
        }));

        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(300);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::path("late")).await.unwrap()
        else {
            panic!("unexpected 304");
        };
        // Nobody reads for longer than the window, and then the read succeeds.
        Timer::after(Duration::from_millis(350)).await;
        let mut out = Vec::new();
        body.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"late one");
    });
}

/// Once a read has found nothing the window runs whether or not a read is
/// outstanding: what it measures is silence since a read wanted bytes, not the
/// time a read spends waiting. A read abandoned while the peer is silent leaves
/// the window running, so the next read finds it gone.
#[test]
fn an_abandoned_read_leaves_the_progress_window_running() {
    block_on(async {
        // A head promising 16 bytes, eight of them, and then silence.
        let addr = stalling_server(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nfirst   ").await;
        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(200);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::path("big")).await.unwrap()
        else {
            panic!("unexpected 304");
        };
        let mut head = [0u8; 8];
        body.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"first   ");

        // A read that finds nothing starts the window, and is then abandoned
        // well inside it.
        let mut rest = [0u8; 8];
        let abandoned = or(async { Some(body.read(&mut rest).await) }, async {
            Timer::after(Duration::from_millis(50)).await;
            None
        })
        .await;
        assert!(abandoned.is_none(), "the silent peer delivered nothing");

        // Nobody is reading while the rest of the window passes. The next read
        // finds it spent and fails at once: raced against a timer shorter than
        // the window, so a read that started a fresh window instead would still
        // be waiting when the race ends.
        Timer::after(Duration::from_millis(400)).await;
        let settled = or(async { Some(body.read(&mut rest).await) }, async {
            Timer::after(Duration::from_millis(100)).await;
            None
        })
        .await;
        let err = settled
            .expect("the window was spent, so the read failed without waiting")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("delivered nothing"), "{err}");
    });
}

/// A cleartext origin behind a proxy is reached over a connection to the proxy,
/// and the request carries the absolute-form target with the origin's own
/// `Host` header. What the origin answers is what the fetch delivers.
#[test]
fn a_cleartext_fetch_travels_through_the_proxy() {
    block_on(async {
        let origin = TestServer::start(Transport::Cleartext, always(b"object bytes")).await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        let fetcher = Fetcher::new(FetcherOptions {
            tls: tls_options(None),
            proxy: Proxy::Url(proxy.url()),
            ..direct_options(origin.url(false))
        })
        .await
        .unwrap();

        let (bytes, protocol) = fetch_bytes(&fetcher, "objects/ab/cd.filez").await;
        assert_eq!(bytes, b"object bytes");
        // A proxy connection is cleartext, so it speaks HTTP/1.1.
        assert_eq!(protocol, Protocol::Http11);

        let authority = format!("localhost:{}", origin.addr.port());
        let seen = proxy.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "GET");
        assert_eq!(
            seen[0].target,
            format!("http://{authority}/objects/ab/cd.filez")
        );
        assert_eq!(seen[0].header("host"), Some(authority.as_str()));
        // The origin was asked for the object, in the origin form a server
        // answers.
        assert_eq!(origin.seen()[0].path, "/objects/ab/cd.filez");
        assert_eq!(origin.seen()[0].target, "/objects/ab/cd.filez");

        // One proxy connection carries requests for any cleartext origin: a
        // fetch of another origin's URL travels over the connection the first
        // fetch returned to the pool.
        let other = TestServer::start(Transport::Cleartext, always(b"other bytes")).await;
        let url = format!("{}/summary", other.url(false));
        let (bytes, _) = fetch_url_bytes(&fetcher, &url).await;
        assert_eq!(bytes, b"other bytes");
        assert_eq!(proxy.requests(), 2);
        assert_eq!(proxy.seen()[1].target, url);
        assert_eq!(proxy.connections(), 1);
        assert_eq!(other.seen()[0].path, "/summary");
    });
}

/// A TLS origin behind a proxy is reached over a `CONNECT` tunnel, and the
/// handshake that follows is the one a direct connection makes: ALPN selects
/// HTTP/2 end to end, and the proxy carries the bytes without reading them.
#[test]
fn a_tls_fetch_tunnels_through_the_proxy() {
    block_on(async {
        let origin = TestServer::start(
            Transport::Tls {
                alpn: vec!["h2", "http/1.1"],
                client_auth: ClientAuth::None,
            },
            always(b"over h2"),
        )
        .await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        let fetcher = Fetcher::new(FetcherOptions {
            tls: tls_options(None),
            proxy: Proxy::Url(proxy.url()),
            ..direct_options(origin.url(true))
        })
        .await
        .unwrap();

        let (bytes, protocol) = fetch_bytes(&fetcher, "summary").await;
        assert_eq!(bytes, b"over h2");
        assert_eq!(protocol, Protocol::Http2);

        // The proxy saw the tunnel and nothing of the request inside it. The
        // target is named with its port, and the `Host` header holds the same.
        let authority = format!("localhost:{}", origin.addr.port());
        let seen = proxy.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "CONNECT");
        assert_eq!(seen[0].target, authority);
        assert_eq!(seen[0].header("host"), Some(authority.as_str()));
        assert_eq!(origin.seen()[0].path, "/summary");
    });
}

/// `no_proxy` exempts an origin from the proxy: an exact host, the same host
/// written with the leading `.`, an entry qualified by the port the origin
/// names, and `*`. An exempt fetch reaches the origin directly, and the proxy
/// records nothing.
#[test]
fn no_proxy_exempts_the_origin_from_the_proxy() {
    block_on(async {
        let origin = TestServer::start(Transport::Cleartext, always(b"direct")).await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        let port = origin.addr.port();
        let fetcher = |no_proxy: String| {
            let variables = vec![
                ("http_proxy".to_owned(), proxy.url()),
                ("no_proxy".to_owned(), no_proxy),
            ];
            Fetcher::new(FetcherOptions {
                tls: tls_options(None),
                proxy: Proxy::Variables(variables),
                ..direct_options(origin.url(false))
            })
        };

        for no_proxy in [
            "localhost".to_owned(),
            ".localhost".to_owned(),
            format!("localhost:{port}"),
            "*".to_owned(),
            format!("other.example,localhost:{port}"),
        ] {
            let fetcher = fetcher(no_proxy.clone()).await.unwrap();
            let (bytes, _) = fetch_bytes(&fetcher, "summary").await;
            assert_eq!(bytes, b"direct", "{no_proxy}");
            assert_eq!(proxy.requests(), 0, "{no_proxy}");
        }

        // An entry that exempts something else leaves the origin behind the
        // proxy: an unrelated host, and the same host at another port.
        for (asked, no_proxy) in [
            (1, "other.example".to_owned()),
            // The listener holds a port of its own, so the wrap names one it
            // does not.
            (2, format!("localhost:{}", port.wrapping_add(1))),
        ] {
            let fetcher = fetcher(no_proxy.clone()).await.unwrap();
            let (bytes, _) = fetch_bytes(&fetcher, "summary").await;
            assert_eq!(bytes, b"direct", "{no_proxy}");
            assert_eq!(proxy.requests(), asked, "{no_proxy}");
        }
    });
}

/// An entry exempts every host under the domain it names.
///
/// The origin here is a name that resolves to nothing, so what the exemption
/// decides is which endpoint the connect names: a request that is not exempt
/// reaches the proxy, which records it and then answers 502, having nothing to
/// forward it to, while an exempt one is a connect the fetch makes itself and
/// the proxy sees no more of it.
#[test]
fn no_proxy_exempts_a_host_under_a_listed_domain() {
    block_on(async {
        let proxy = TestProxy::start(Tunnel::Open).await;
        // Port 9 of a `.invalid` name, which the DNS answers for nothing.
        let mirror = "http://deep.host.example.invalid:9/repo";
        let fetcher = |no_proxy: &str| {
            let variables = vec![
                ("http_proxy".to_owned(), proxy.url()),
                ("no_proxy".to_owned(), no_proxy.to_owned()),
            ];
            Fetcher::new(FetcherOptions {
                tls: tls_options(None),
                proxy: Proxy::Variables(variables),
                max_retries: 0,
                // The assertions read what reached the proxy, and both arms
                // discard what the fetch resolved to, so the window is the one
                // that keeps a name nothing answers for off the test clock.
                fetch_timeout: Some(Duration::from_secs(1)),
                ..direct_options(mirror)
            })
        };

        let not_exempt = fetcher("other.example").await.unwrap();
        let _ = not_exempt.fetch(FetchRequest::path("summary")).await;
        let seen = proxy.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].target,
            "http://deep.host.example.invalid:9/repo/summary"
        );

        for entry in ["host.example.invalid", ".host.example.invalid"] {
            let exempt = fetcher(entry).await.unwrap();
            let _ = exempt.fetch(FetchRequest::path("summary")).await;
            assert_eq!(proxy.requests(), 1, "{entry}");
        }
    });
}

/// [`Proxy::None`] reaches every origin directly. The variables that would name
/// the proxy are stated in the other form, so what the two fetchers part over
/// is which of them reads them at all.
#[test]
fn proxy_none_reaches_the_origin_directly() {
    block_on(async {
        let origin = TestServer::start(Transport::Cleartext, always(b"answered")).await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        let variables = vec![("http_proxy".to_owned(), proxy.url())];

        let through = Fetcher::new(FetcherOptions {
            tls: tls_options(None),
            proxy: Proxy::Variables(variables),
            ..direct_options(origin.url(false))
        })
        .await
        .unwrap();
        let (bytes, _) = fetch_bytes(&through, "summary").await;
        assert_eq!(bytes, b"answered");
        assert_eq!(proxy.requests(), 1);

        let direct = Fetcher::new(FetcherOptions {
            tls: tls_options(None),
            proxy: Proxy::None,
            ..direct_options(origin.url(false))
        })
        .await
        .unwrap();
        let (bytes, _) = fetch_bytes(&direct, "summary").await;
        assert_eq!(bytes, b"answered");
        assert_eq!(proxy.requests(), 1);
        assert_eq!(origin.requests(), 2);
    });
}

/// The userinfo of a proxy URL is the proxy's credential: it reaches the proxy
/// as `Proxy-Authorization`, and it is no part of the merged header list, which
/// carries the caller's own credential beside it.
///
/// A proxied cleartext request is one request, so what the proxy recorded is
/// the header list the fetcher built, and the two credentials arrive there
/// under their own names. On the tunnel path nothing between the fetcher and
/// the origin reads the bytes at all, so what the origin recorded is the
/// fetcher's own doing, and the credential it holds is the caller's alone.
#[test]
fn the_proxy_credential_reaches_the_proxy_and_no_origin() {
    block_on(async {
        // base64("alice:s3cret")
        let expected = Some("Basic YWxpY2U6czNjcmV0");

        let origin = TestServer::start(Transport::Cleartext, always(b"through")).await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        let fetcher = Fetcher::new(FetcherOptions {
            tls: tls_options(None),
            proxy: Proxy::Url(proxy.url_with("alice:s3cret")),
            ..direct_options(origin.url(false))
        })
        .await
        .unwrap();
        let caller = basic_auth("bob", "origin");
        let fetched = fetcher
            .fetch(FetchRequest {
                basic_auth: Some(&caller),
                allow_cleartext_credentials: true,
                ..FetchRequest::path("summary")
            })
            .await
            .unwrap();
        assert_eq!(read_body(fetched).await, b"through");
        let seen = proxy.seen();
        assert_eq!(seen[0].header("proxy-authorization"), expected);
        // base64("bob:origin")
        assert_eq!(
            seen[0].header("authorization"),
            Some("Basic Ym9iOm9yaWdpbg==")
        );

        let tls_origin = TestServer::start(
            Transport::Tls {
                alpn: vec!["h2", "http/1.1"],
                client_auth: ClientAuth::None,
            },
            always(b"tunneled"),
        )
        .await;
        let tls_proxy = TestProxy::start(Tunnel::Open).await;
        let fetcher = Fetcher::new(FetcherOptions {
            tls: tls_options(None),
            basic_auth: Some(basic_auth("bob", "origin")),
            proxy: Proxy::Url(tls_proxy.url_with("alice:s3cret")),
            ..direct_options(tls_origin.url(true))
        })
        .await
        .unwrap();
        let (bytes, _) = fetch_bytes(&fetcher, "summary").await;
        assert_eq!(bytes, b"tunneled");
        let seen = tls_proxy.seen();
        assert_eq!(seen[0].method, "CONNECT");
        assert_eq!(seen[0].header("proxy-authorization"), expected);
        assert_eq!(tls_origin.seen()[0].header("proxy-authorization"), None);
        // The credential the origin is asked for is the caller's, which the
        // tunnel carried past a proxy that read none of it.
        assert_eq!(
            tls_origin.seen()[0].header("authorization"),
            Some("Basic Ym9iOm9yaWdpbg==")
        );
    });
}

/// A proxy that refuses the tunnel names the proxy and the status in the
/// failure. A 407 refuses the credential the fetcher holds, which no retry
/// changes, so the proxy is asked once; every other status is retryable and the
/// round that repeats asks again.
#[test]
fn a_refused_connect_is_definitive_at_407_and_retried_at_502() {
    block_on(async {
        let refusing = |status: u16, max_retries: u32| async move {
            let proxy = TestProxy::start(Tunnel::Refuse(status)).await;
            let fetcher = Fetcher::new(FetcherOptions {
                tls: tls_options(None),
                proxy: Proxy::Url(proxy.url()),
                max_retries,
                // Nothing listens on port 1 of the loopback, so a fetch that
                // reached past the proxy would fail on the connect instead.
                ..direct_options("https://localhost:1/repo")
            })
            .await
            .unwrap();
            let err = fetch_error(&fetcher, "summary").await;
            (proxy, err)
        };

        let (proxy, err) = refusing(407, 3).await;
        let message = err.to_string();
        assert!(message.contains("407"), "{message}");
        assert!(message.contains(&proxy.url()), "{message}");
        assert!(message.contains("localhost:1"), "{message}");
        assert_eq!(proxy.requests(), 1);
        assert!(
            proxy.seen().iter().all(|seen| seen.method == "CONNECT"),
            "{:?}",
            proxy.seen()
        );

        let (proxy, err) = refusing(502, 1).await;
        let message = err.to_string();
        assert!(message.contains("502"), "{message}");
        assert!(message.contains(&proxy.url()), "{message}");
        // One round, then the round the retry repeats.
        assert_eq!(proxy.requests(), 2);
    });
}

/// A proxy URL the fetcher cannot connect through fails the constructor, and
/// the value is named. The environment forms are read the same way, so a
/// variable holding one fails it too.
#[test]
fn a_proxy_the_fetcher_cannot_reach_is_refused_at_construction() {
    block_on(async {
        for url in ["socks5://127.0.0.1:1080", "https://127.0.0.1:3128"] {
            let err = Fetcher::new(FetcherOptions {
                proxy: Proxy::Url(url.to_owned()),
                ..direct_options("http://origin.example/repo")
            })
            .await
            .unwrap_err();
            assert!(matches!(err, Error::Unsupported(_)), "{url}: {err}");
            let message = err.to_string();
            assert!(message.contains(url), "{url}: {message}");

            let variables = vec![("all_proxy".to_owned(), url.to_owned())];
            let err = Fetcher::new(FetcherOptions {
                proxy: Proxy::Variables(variables),
                ..direct_options("http://origin.example/repo")
            })
            .await
            .unwrap_err();
            assert!(matches!(err, Error::Unsupported(_)), "{url}: {err}");
        }
    });
}

/// A redirect under a proxy is served the way a route naming the hop's origin
/// would be: the hop that follows carries the absolute form to the same proxy,
/// and one proxy connection carries both.
#[test]
fn a_redirect_under_the_proxy_travels_over_one_proxy_connection() {
    block_on(async {
        let second = TestServer::start(Transport::Cleartext, always(b"second hop")).await;
        let first = TestServer::start(
            Transport::Cleartext,
            redirect_once(format!("{}/moved", second.url(false)), b"first hop"),
        )
        .await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        let fetcher = Fetcher::new(FetcherOptions {
            tls: tls_options(None),
            proxy: Proxy::Url(proxy.url()),
            ..direct_options(first.url(false))
        })
        .await
        .unwrap();

        let (bytes, _) = fetch_bytes(&fetcher, "summary").await;
        assert_eq!(bytes, b"second hop");
        let seen = proxy.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].target, format!("{}/summary", first.url(false)));
        assert_eq!(seen[1].target, format!("{}/moved", second.url(false)));
        // Both hops are cleartext origins behind one proxy, and the redirect
        // carried an empty body, so its connection was back in the pool for the
        // hop that followed it.
        assert_eq!(proxy.connections(), 1);
        assert_eq!(second.seen()[0].target, "/moved");
    });
}

/// The proxy decision is made per hop, so a proxied origin that redirects onto
/// an exempt one is followed to that origin itself: the hop opens its own
/// connection and carries the origin form a server answers.
#[test]
fn a_redirect_onto_an_exempt_origin_is_followed_directly() {
    block_on(async {
        let exempt = TestServer::start(Transport::Cleartext, always(b"direct hop")).await;
        let proxied = TestServer::start(
            Transport::Cleartext,
            redirect_once(format!("{}/moved", exempt.url(false)), b"first hop"),
        )
        .await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        // The two origins are one host at two ports, which a port-qualified
        // entry tells apart.
        let variables = vec![
            ("http_proxy".to_owned(), proxy.url()),
            (
                "no_proxy".to_owned(),
                format!("localhost:{}", exempt.addr.port()),
            ),
        ];
        let fetcher = Fetcher::new(FetcherOptions {
            tls: tls_options(None),
            proxy: Proxy::Variables(variables),
            ..direct_options(proxied.url(false))
        })
        .await
        .unwrap();

        let (bytes, _) = fetch_bytes(&fetcher, "summary").await;
        assert_eq!(bytes, b"direct hop");
        let seen = proxy.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].target, format!("{}/summary", proxied.url(false)));
        assert_eq!(exempt.seen()[0].target, "/moved");
        assert_eq!(exempt.connections(), 1);
    });
}

/// A direct connection and a proxied connection to one endpoint are two
/// connections, and each carries its own request form. The endpoint is the
/// proxy's own here, exempted by `no_proxy` so a URL target naming it is
/// reached directly: the proxy reads the absolute form of the proxied request
/// and the origin form of the direct one.
#[test]
fn a_proxied_connection_is_not_handed_to_a_direct_request() {
    block_on(async {
        let origin = TestServer::start(Transport::Cleartext, always(b"proxied")).await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        let variables = vec![
            ("http_proxy".to_owned(), proxy.url()),
            (
                "no_proxy".to_owned(),
                format!("127.0.0.1:{}", proxy.addr.port()),
            ),
        ];
        let fetcher = Fetcher::new(FetcherOptions {
            tls: tls_options(None),
            proxy: Proxy::Variables(variables),
            max_retries: 0,
            ..direct_options(origin.url(false))
        })
        .await
        .unwrap();

        let (bytes, _) = fetch_bytes(&fetcher, "summary").await;
        assert_eq!(bytes, b"proxied");
        assert_eq!(proxy.connections(), 1);

        // The same endpoint asked for a path of its own: the proxy has no
        // absolute-form target to forward and answers 502, which is the answer
        // a server gives the form it was not expecting.
        let url = format!("{}/direct", proxy.url());
        let err = fetcher
            .fetch(FetchRequest::url(&url))
            .await
            .expect_err("the proxy forwards nothing for an origin-form target");
        assert!(err.to_string().contains("502"), "{err}");
        let seen = proxy.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].target, format!("{}/summary", origin.url(false)));
        assert_eq!(seen[1].target, "/direct");
        assert_eq!(proxy.connections(), 2);
    });
}

/// A byte behind a `CONNECT` response fails the connect: nothing follows that
/// response before the client has spoken, so the TLS handshake would read the
/// stream from after those bytes.
#[test]
fn a_connect_answered_with_trailing_bytes_fails_the_connect() {
    block_on(async {
        let addr = talkative_connect_proxy().await;
        let proxy = format!("http://127.0.0.1:{}", addr.port());
        let fetcher = Fetcher::new(FetcherOptions {
            tls: tls_options(None),
            proxy: Proxy::Url(proxy.clone()),
            max_retries: 0,
            // Nothing listens on port 1 of the loopback, so a tunnel the
            // fetcher took up would fail on the handshake instead.
            ..direct_options("https://localhost:1/repo")
        })
        .await
        .unwrap();

        let err = fetch_error(&fetcher, "summary").await;
        let message = err.to_string();
        assert!(message.contains(&proxy), "{message}");
        assert!(message.contains("after the connect"), "{message}");
        assert!(message.contains("localhost:1"), "{message}");
    });
}

/// A connect window that ends on a proxied hop names the proxy: the connection
/// the window covers is the one to the proxy, and the origin behind it is
/// contacted by nothing until that connection is open.
#[test]
fn a_connect_timeout_on_a_proxied_hop_names_the_proxy() {
    block_on(async {
        // A peer that accepts the connection, reads the `CONNECT`, and answers
        // nothing.
        let addr = stalling_server(b"").await;
        let proxy = format!("http://127.0.0.1:{}", addr.port());
        let fetcher = Fetcher::new(FetcherOptions {
            tls: tls_options(None),
            proxy: Proxy::Url(proxy.clone()),
            connect_timeout: Duration::from_millis(300),
            max_retries: 0,
            ..direct_options("https://localhost:1/repo")
        })
        .await
        .unwrap();

        let message = fetch_error(&fetcher, "summary").await.to_string();
        assert!(message.contains(&proxy), "{message}");
        assert!(message.contains("timed out"), "{message}");
        assert!(!message.contains("localhost:1"), "{message}");
    });
}

/// A body that keeps delivering, but below the low-speed rate, fails the read
/// once the rate has stayed below the limit for the rule's time: long before
/// the progress window, which the trickle never lets run out, and long before
/// the body could end.
#[test]
fn a_body_below_the_low_speed_rate_fails_the_read() {
    block_on(async {
        // 10 bytes every 50ms is 200 bytes per second, against a rule of 1000
        // for one second.
        let (addr, requests) =
            trickling_server(true, &TRICKLED, 10, Duration::from_millis(50)).await;
        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.low_speed = low_speed(1000, 1000);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::path("slow")).await.unwrap()
        else {
            panic!("unexpected 304");
        };
        let started = Instant::now();
        let mut out = Vec::new();
        let err = body.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            err.to_string()
                .contains("averaged below 1000 bytes per second"),
            "{err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        assert!(out.len() < TRICKLED.len());
        // The failure latches, as every failure of a body does.
        let err = body.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    });
}

/// A body that stays above the rate over several samples completes.
#[test]
fn a_body_above_the_low_speed_rate_completes() {
    block_on(async {
        // 100 bytes every 50ms is about 2000 bytes per second, against a rule
        // of 1000 for one second, for about two samples.
        let (addr, _) = trickling_server(true, &TRICKLED, 100, Duration::from_millis(50)).await;
        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.low_speed = low_speed(1000, 1000);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let started = Instant::now();
        let (bytes, _) = fetch_bytes(&fetcher, "steady").await;
        assert_eq!(bytes, TRICKLED);
        assert!(started.elapsed() >= Duration::from_millis(1500));
    });
}

/// A body that arrives in bursts completes while the rate over the samples so
/// far stays above the limit, though a whole second passes with no byte. Held
/// to the limit one second at a time, the body would fail.
#[test]
fn a_bursty_body_above_the_low_speed_rate_completes() {
    block_on(async {
        // 2600 bytes, and the other 1496 bytes 2.5 seconds later: the second
        // second carries nothing, and the rate over two seconds is 1300 bytes
        // per second, against a rule of 1000 for one second.
        let (addr, requests) =
            trickling_server(true, &TRICKLED, 2600, Duration::from_millis(2500)).await;
        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.low_speed = low_speed(1000, 1000);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let started = Instant::now();
        let (bytes, _) = fetch_bytes(&fetcher, "bursty").await;
        assert_eq!(bytes, TRICKLED);
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    });
}

/// A head that never arrives fails the attempt once the rule's time, rounded up
/// to a whole second, has passed, well before the progress window, and the
/// failure is retryable.
#[test]
fn a_head_that_never_arrives_fails_after_the_low_speed_time() {
    block_on(async {
        let (addr, requests) = trickling_server(false, &TRICKLED, 1, Duration::ZERO).await;
        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        options.low_speed = low_speed(1000, 200);
        options.progress_timeout = Duration::from_secs(30);
        options.max_retries = 1;
        let fetcher = Fetcher::new(options).await.unwrap();

        let started = Instant::now();
        let err = fetch_error(&fetcher, "summary").await;
        assert!(
            err.to_string()
                .contains("transfer below 1000 bytes per second"),
            "{err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    });
}

/// The low-speed rate of a body is measured from its first read, so a body its
/// consumer leaves unread for longer than one sample is not failed for it.
#[test]
fn the_low_speed_rate_is_measured_from_the_first_read() {
    block_on(async {
        let (addr, _) = trickling_server(true, &TRICKLED, TRICKLED.len(), Duration::ZERO).await;
        let mut options = direct_options(format!("http://127.0.0.1:{}", addr.port()));
        // A limit above the whole body: a sample taken while the body is read
        // fails it, so the body completes only if the reads end before the
        // first sample is due, one second after the first read.
        options.low_speed = low_speed(1_000_000, 1000);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let fetched = fetcher.fetch(FetchRequest::path("parked")).await.unwrap();
        Timer::after(Duration::from_millis(1500)).await;
        assert_eq!(read_body(fetched).await, TRICKLED);
    });
}

/// A low-speed rule holding a zero measures nothing, and is refused.
#[test]
fn a_low_speed_rule_with_a_zero_is_refused() {
    block_on(async {
        for rule in [low_speed(0, 100), low_speed(1000, 0)] {
            let mut options = direct_options("http://127.0.0.1:1");
            options.low_speed = rule;
            let err = Fetcher::new(options).await.unwrap_err();
            assert!(matches!(err, Error::Fetch(_)), "{err}");
        }
    });
}

// --- uploads ---------------------------------------------------------------

/// The longest an upload test runs before it fails rather than hangs.
const UPLOAD_TEST_LIMIT: Duration = Duration::from_secs(60);

/// The piece sizes a streamed upload writes in, in turn: none of them is a
/// frame or a buffer size, so a piece crosses frame boundaries at every offset.
const PIECES: [usize; 6] = [1, 7, 4096, 65_535, 100_003, 13];

/// Run `future`, failing the test if it runs past [`UPLOAD_TEST_LIMIT`].
async fn bounded<F: Future>(future: F) -> F::Output {
    or(future, async {
        Timer::after(UPLOAD_TEST_LIMIT).await;
        panic!("the upload test did not finish within {UPLOAD_TEST_LIMIT:?}")
    })
    .await
}

/// Wait until `done` holds, failing the test after five seconds.
async fn eventually(what: &str, done: impl Fn() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < Duration::from_secs(5), "{what}");
        Timer::after(Duration::from_millis(10)).await;
    }
}

/// `len` bytes of a pattern in which a lost, a repeated, or a moved piece
/// changes the digest.
fn upload_data(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i % 251) as u8 ^ (i >> 12) as u8)
        .collect()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Check that the server read `data` whole as the body of `seen`.
fn assert_body(seen: &Seen, data: &[u8]) {
    assert!(seen.body_complete, "the body of {} ended short", seen.path);
    assert_eq!(seen.body_len, data.len() as u64);
    assert_eq!(seen.body_sha256, sha256(data));
}

/// Write `data` into `writer` in the sizes of [`PIECES`], then close it.
async fn write_in_pieces(mut writer: UploadWriter, data: &[u8]) -> io::Result<()> {
    let mut at = 0;
    for piece in PIECES.iter().cycle() {
        if at == data.len() {
            break;
        }
        let end = (at + piece).min(data.len());
        writer.write_all(&data[at..end]).await?;
        at = end;
    }
    writer.close().await
}

/// Run `request`, whose body is the channel of `writer`, while `data` is
/// written into it, and give the result of each.
async fn upload_streamed(
    fetcher: &Fetcher,
    request: UploadRequest<'_>,
    writer: UploadWriter,
    data: &[u8],
) -> (Result<Uploaded, Error>, io::Result<()>) {
    futures_lite::future::zip(fetcher.upload(request), write_in_pieces(writer, data)).await
}

/// Upload `data` as a streamed `POST` to `path`, and give the status, the
/// protocol, and the response body.
async fn post_streamed(fetcher: &Fetcher, path: &str, data: &[u8]) -> (u16, Protocol, Vec<u8>) {
    let (body, writer) = UploadBody::channel();
    let (uploaded, written) =
        upload_streamed(fetcher, UploadRequest::path(path, body), writer, data).await;
    written.unwrap();
    let uploaded = uploaded.unwrap();
    let (status, protocol) = (uploaded.status(), uploaded.protocol());
    (status, protocol, read_uploaded(uploaded).await)
}

/// Read the response body of an upload to its end.
async fn read_uploaded(uploaded: Uploaded) -> Vec<u8> {
    let mut body = uploaded.into_body();
    let mut out = Vec::new();
    body.read_to_end(&mut out).await.unwrap();
    out
}

/// The error an upload failed with.
async fn upload_error(fetcher: &Fetcher, request: UploadRequest<'_>) -> Error {
    match fetcher.upload(request).await {
        Ok(uploaded) => panic!("the upload was expected to fail, got {}", uploaded.status()),
        Err(err) => err,
    }
}

/// Options for a fetcher at `url` that trusts the fixture authority and
/// reaches every origin directly.
fn upload_options(url: impl Into<String>) -> FetcherOptions {
    FetcherOptions {
        tls: tls_options(None),
        ..direct_options(url)
    }
}

/// A TLS transport offering `alpn` alone.
fn tls_transport(alpn: &'static str) -> Transport {
    Transport::Tls {
        alpn: vec![alpn],
        client_auth: ClientAuth::None,
    }
}

/// A loopback port held by a socket that is bound and does not listen.
///
/// While the value lives, a connect to the port is refused and no IPv4 or
/// dual-stack bind to port 0 gets the port number. A server that sets
/// `SO_REUSEADDR`, as both runtime backends do, can still bind the port
/// explicitly.
struct ReservedPort {
    port: u16,
    _socket: OwnedFd,
}

fn reserved_port() -> ReservedPort {
    let socket = net::socket_with(
        net::AddressFamily::INET,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    net::sockopt::set_socket_reuseaddr(&socket, true).unwrap();
    net::bind(&socket, &SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    let bound = SocketAddrV4::try_from(net::getsockname(&socket).unwrap()).unwrap();
    ReservedPort {
        port: bound.port(),
        _socket: socket,
    }
}

/// Read `body` until at least `bytes` have arrived or it ends, and give the
/// count that arrived.
async fn read_at_least(body: &mut Incoming, bytes: u64) -> u64 {
    let mut read = 0;
    while read < bytes {
        match std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    read += data.len() as u64;
                }
            }
            Some(Err(_)) | None => break,
        }
    }
    read
}

/// A handler that reads `bytes` of the request body and then ends the exchange
/// with no answer: an HTTP/1.1 connection closes, and an HTTP/2 stream is
/// reset.
fn cut_after(bytes: u64) -> StreamHandler {
    Arc::new(move |request| {
        Box::pin(async move {
            let mut body = request.into_body();
            read_at_least(&mut body, bytes).await;
            Err(io::Error::other("the server cut the body short"))
        })
    })
}

/// A handler that reads the whole request body and then gives no answer:
/// with `close`, it ends the exchange, and without, it never answers.
fn no_answer_after_the_body(close: bool) -> StreamHandler {
    Arc::new(move |request| {
        Box::pin(async move {
            let mut body = request.into_body();
            read_at_least(&mut body, u64::MAX).await;
            if !close {
                futures_lite::future::pending::<()>().await;
            }
            Err(io::Error::other("the server gave no answer"))
        })
    })
}

/// A peer that accepts connections and never reads from them, so a client
/// writing to one fills the socket buffers and then stalls.
async fn silent_reader() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    drop(spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _peer)) = listener.accept().await {
            held.push(stream);
        }
    }));
    addr
}

/// A front that closes the first connection it accepts before a byte crosses
/// it, and carries every later one to `target`.
async fn dropping_front(target: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    drop(spawn(async move {
        let mut first = true;
        while let Ok((client, _peer)) = listener.accept().await {
            if std::mem::take(&mut first) {
                drop(client);
                continue;
            }
            drop(spawn(async move {
                let Ok(server) = TcpStream::connect("127.0.0.1", target.port()).await else {
                    return;
                };
                let (mut client_reader, mut client_writer) = futures_lite::io::split(client);
                let (mut server_reader, mut server_writer) = futures_lite::io::split(server);
                or(
                    async {
                        let _ =
                            futures_lite::io::copy(&mut client_reader, &mut server_writer).await;
                    },
                    async {
                        let _ =
                            futures_lite::io::copy(&mut server_reader, &mut client_writer).await;
                    },
                )
                .await;
            }));
        }
    }));
    addr
}

/// A streamed `POST` reaches the server whole -- its method, its path, its
/// length, and its digest -- over cleartext HTTP/1.1, where it travels
/// chunked, over HTTP/1.1 on TLS, and over HTTP/2, where the body is larger
/// than the flow-control window. The fetcher sets no `Content-Type` and no
/// `Expect`.
#[test]
fn a_streamed_post_arrives_intact_over_http1_tls_and_http2() {
    block_on(bounded(async {
        let data = upload_data(4 * 1024 * 1024 + 4097);
        for (transport, tls, protocol) in [
            (Transport::Cleartext, false, Protocol::Http11),
            (tls_transport("http/1.1"), true, Protocol::Http11),
            (tls_transport("h2"), true, Protocol::Http2),
        ] {
            let server = TestServer::start(transport, always(b"accepted")).await;
            let fetcher = Fetcher::new(upload_options(server.url(tls))).await.unwrap();

            let (status, carried, answer) =
                post_streamed(&fetcher, "_ostrya/receive/v1/session", &data).await;
            assert_eq!(status, 200);
            assert_eq!(carried, protocol);
            assert_eq!(answer, b"accepted");

            let seen = server.seen();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].method, "POST");
            assert_eq!(seen[0].path, "/_ostrya/receive/v1/session");
            assert_body(&seen[0], &data);
            assert_eq!(seen[0].header("content-length"), None);
            if protocol == Protocol::Http11 {
                assert_eq!(seen[0].header("transfer-encoding"), Some("chunked"));
            }
            assert_eq!(seen[0].header("content-type"), None);
            assert_eq!(seen[0].header("expect"), None);
        }
    }));
}

/// The body streams: the server reads part of it while the writer still holds
/// it open.
#[test]
fn a_streamed_body_reaches_the_server_before_the_writer_closes_it() {
    block_on(bounded(async {
        let server = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let head = upload_data(512 * 1024);
        let tail = upload_data(1000);
        let (body, mut writer) = UploadBody::channel();
        let written = async {
            writer.write_all(&head).await?;
            writer.flush().await?;
            eventually("the server reads the body before its end", || {
                server.received() >= 256 * 1024
            })
            .await;
            writer.write_all(&tail).await?;
            writer.close().await
        };
        let (uploaded, written) = futures_lite::future::zip(
            fetcher.upload(UploadRequest::path("objects", body)),
            written,
        )
        .await;
        written.unwrap();
        assert_eq!(uploaded.unwrap().status(), 200);
        assert_body(&server.seen()[0], &[head, tail].concat());
    }));
}

/// A body given whole declares its length, over HTTP/1.1 and over HTTP/2, and
/// an empty `POST` declares a length of zero.
#[test]
fn a_whole_body_declares_its_length() {
    block_on(bounded(async {
        let data = upload_data(100_000);
        for alpn in ["http/1.1", "h2"] {
            let server = TestServer::start(tls_transport(alpn), always(b"accepted")).await;
            let fetcher = Fetcher::new(upload_options(server.url(true)))
                .await
                .unwrap();
            let uploaded = fetcher
                .upload(UploadRequest::path(
                    "objects",
                    UploadBody::bytes(data.clone()),
                ))
                .await
                .unwrap();
            assert_eq!(uploaded.status(), 200);
            assert_eq!(read_uploaded(uploaded).await, b"accepted");
            let uploaded = fetcher
                .upload(UploadRequest::path("empty", Vec::new().into()))
                .await
                .unwrap();
            assert_eq!(uploaded.status(), 200);

            let seen = server.seen();
            assert_eq!(seen[0].header("content-length"), Some("100000"));
            assert_eq!(seen[0].header("transfer-encoding"), None);
            assert_body(&seen[0], &data);
            assert_eq!(seen[1].method, "POST");
            assert_eq!(seen[1].header("content-length"), Some("0"));
            assert_body(&seen[1], b"");
        }
    }));
}

/// A streamed `POST` to a cleartext origin travels to the proxy in absolute
/// form, and the proxy carries the body on whole.
#[test]
fn a_streamed_post_travels_through_the_proxy() {
    block_on(bounded(async {
        let origin = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        let fetcher = Fetcher::new(FetcherOptions {
            proxy: Proxy::Url(proxy.url()),
            ..upload_options(origin.url(false))
        })
        .await
        .unwrap();
        let data = upload_data(1024 * 1024 + 3);

        let (status, protocol, answer) = post_streamed(&fetcher, "objects", &data).await;
        assert_eq!((status, protocol), (200, Protocol::Http11));
        assert_eq!(answer, b"accepted");
        let seen = proxy.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(
            seen[0].target,
            format!("http://localhost:{}/objects", origin.addr.port())
        );
        assert_eq!(origin.seen()[0].method, "POST");
        assert_body(&origin.seen()[0], &data);
    }));
}

/// A streamed `POST` to a TLS origin travels over a `CONNECT` tunnel, with
/// HTTP/1.1 or HTTP/2 inside it as ALPN selects.
#[test]
fn a_streamed_post_tunnels_through_the_proxy_over_http1_and_http2() {
    block_on(bounded(async {
        let data = upload_data(1024 * 1024 + 5);
        for (alpn, protocol) in [("http/1.1", Protocol::Http11), ("h2", Protocol::Http2)] {
            let origin = TestServer::start(tls_transport(alpn), always(b"accepted")).await;
            let proxy = TestProxy::start(Tunnel::Open).await;
            let fetcher = Fetcher::new(FetcherOptions {
                proxy: Proxy::Url(proxy.url()),
                ..upload_options(origin.url(true))
            })
            .await
            .unwrap();

            let (status, carried, _) = post_streamed(&fetcher, "objects", &data).await;
            assert_eq!((status, carried), (200, protocol));
            let seen = proxy.seen();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].method, "CONNECT");
            assert_eq!(origin.seen()[0].method, "POST");
            assert_body(&origin.seen()[0], &data);
        }
    }));
}

/// A bearer token and Basic credentials each reach the server as the
/// `Authorization` of the upload.
#[test]
fn a_bearer_token_and_basic_credentials_reach_the_server() {
    block_on(bounded(async {
        let server = TestServer::start(tls_transport("h2"), always(b"accepted")).await;
        let fetcher = Fetcher::new(upload_options(server.url(true)))
            .await
            .unwrap();
        let token = BearerToken {
            token: "abc.DEF-123~+/==".into(),
        };
        let uploaded = fetcher
            .upload(UploadRequest {
                bearer_token: Some(&token),
                ..UploadRequest::path("session", b"hello".to_vec().into())
            })
            .await
            .unwrap();
        assert_eq!(uploaded.status(), 200);
        let auth = basic_auth("u", "p");
        fetcher
            .upload(UploadRequest {
                basic_auth: Some(&auth),
                ..UploadRequest::path("session", b"hello".to_vec().into())
            })
            .await
            .unwrap();

        let seen = server.seen();
        assert_eq!(
            seen[0].header("authorization"),
            Some("Bearer abc.DEF-123~+/==")
        );
        // base64("u:p")
        assert_eq!(seen[1].header("authorization"), Some("Basic dTpw"));
    }));
}

/// Two credentials for one header, and a token outside the token68 syntax,
/// are refused before admission: no connection is opened, and the writer of
/// a streamed body gets a broken pipe.
#[test]
fn an_ambiguous_or_malformed_credential_reaches_no_server() {
    block_on(bounded(async {
        let server = TestServer::start(tls_transport("h2"), always(b"accepted")).await;
        let fetcher = Fetcher::new(upload_options(server.url(true)))
            .await
            .unwrap();
        let token = BearerToken {
            token: "t0k3n".into(),
        };
        let malformed = BearerToken {
            token: "not a token".into(),
        };
        let auth = basic_auth("u", "p");
        let header = vec![("authorization".to_owned(), "Bearer other".to_owned())];

        let cases: [(UploadRequest<'_>, &str); 4] = [
            (
                UploadRequest {
                    basic_auth: Some(&auth),
                    bearer_token: Some(&token),
                    ..UploadRequest::path("session", Vec::new().into())
                },
                "pass one of them",
            ),
            (
                UploadRequest {
                    bearer_token: Some(&token),
                    headers: &header,
                    ..UploadRequest::path("session", Vec::new().into())
                },
                "pass one of them",
            ),
            (
                UploadRequest {
                    basic_auth: Some(&auth),
                    headers: &header,
                    ..UploadRequest::path("session", Vec::new().into())
                },
                "pass one of them",
            ),
            (
                UploadRequest {
                    bearer_token: Some(&malformed),
                    ..UploadRequest::path("session", Vec::new().into())
                },
                "token68",
            ),
        ];
        for (request, expected) in cases {
            let err = upload_error(&fetcher, request).await;
            assert!(matches!(err, Error::Fetch(_)), "{err}");
            let message = err.to_string();
            assert!(message.contains(expected), "{message}");
            assert!(!message.contains("not a token"), "{message}");
        }

        let (body, mut writer) = UploadBody::channel();
        let err = upload_error(
            &fetcher,
            UploadRequest {
                bearer_token: Some(&malformed),
                ..UploadRequest::path("session", body)
            },
        )
        .await;
        assert!(err.to_string().contains("token68"), "{err}");
        let err = writer.write_all(b"late").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(server.connections(), 0);
    }));
}

/// A credential bound for a cleartext origin is refused unless the request
/// allows it.
#[test]
fn an_upload_credential_to_a_cleartext_origin_is_refused_unless_allowed() {
    block_on(bounded(async {
        let server = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let token = BearerToken {
            token: "t0k3n".into(),
        };
        let err = upload_error(
            &fetcher,
            UploadRequest {
                bearer_token: Some(&token),
                ..UploadRequest::path("session", b"hello".to_vec().into())
            },
        )
        .await;
        assert!(err.to_string().contains("cleartext"), "{err}");
        assert_eq!(server.connections(), 0);

        fetcher
            .upload(UploadRequest {
                bearer_token: Some(&token),
                allow_cleartext_credentials: true,
                ..UploadRequest::path("session", b"hello".to_vec().into())
            })
            .await
            .unwrap();
        assert_eq!(
            server.seen()[0].header("authorization"),
            Some("Bearer t0k3n")
        );
    }));
}

/// A 307 followed onto another origin sends the body again and leaves the
/// credential with the origin the route named.
#[test]
fn a_followed_upload_redirect_leaves_the_credentials_at_the_named_origin() {
    block_on(bounded(async {
        let hop = TestServer::start(Transport::Cleartext, always(b"landed")).await;
        let location = format!("{}/landed", hop.url(false));
        let named = TestServer::start(
            Transport::Cleartext,
            Arc::new(move |_seen, _count| redirect(307, &location)),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(named.url(false)))
            .await
            .unwrap();
        let token = BearerToken {
            token: "t0k3n".into(),
        };
        let data = upload_data(70_000);

        let uploaded = fetcher
            .upload(UploadRequest {
                bearer_token: Some(&token),
                allow_cleartext_credentials: true,
                ..UploadRequest::path("session", data.clone().into())
            })
            .await
            .unwrap();
        assert_eq!(uploaded.status(), 200);
        assert_eq!(uploaded.url(), format!("{}/landed", hop.url(false)));
        assert_eq!(read_uploaded(uploaded).await, b"landed");

        let first = &named.seen()[0];
        assert_eq!(first.header("authorization"), Some("Bearer t0k3n"));
        assert_body(first, &data);
        let second = &hop.seen()[0];
        assert_eq!(second.method, "POST");
        assert_eq!(second.header("authorization"), None);
        assert_body(second, &data);
    }));
}

/// A refused connection sends nothing, so the upload is tried again, and the
/// streamed body arrives whole on the one request that reaches the server.
#[test]
fn a_refused_connection_is_retried_with_the_body_intact() {
    block_on(bounded(async {
        let reserved = reserved_port();
        let port = reserved.port;
        let late = spawn(async move {
            Timer::after(Duration::from_millis(100)).await;
            TestServer::start_on(
                format!("127.0.0.1:{port}").parse().unwrap(),
                Leaf::Fixture,
                Transport::Cleartext,
                always(b"accepted"),
            )
            .await
        });
        let fetcher = Fetcher::new(FetcherOptions {
            max_retries: 2,
            ..direct_options(format!("http://127.0.0.1:{port}"))
        })
        .await
        .unwrap();
        let data = upload_data(300_001);

        let (status, _, answer) = post_streamed(&fetcher, "objects", &data).await;
        assert_eq!(status, 200);
        assert_eq!(answer, b"accepted");
        let server = late.await;
        assert_eq!(server.requests(), 1);
        assert_body(&server.seen()[0], &data);
    }));
}

/// An upload refused by the first mirror before it was sent goes on to the
/// next one.
#[test]
fn an_unsent_upload_moves_on_to_the_next_mirror() {
    block_on(bounded(async {
        let reserved = reserved_port();
        let port = reserved.port;
        let live = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
        let fetcher = Fetcher::new(FetcherOptions {
            mirrors: vec![format!("http://127.0.0.1:{port}"), live.url(false)],
            max_retries: 0,
            ..direct_options("unused")
        })
        .await
        .unwrap();
        let data = upload_data(200_000);

        let (body, writer) = UploadBody::channel();
        let (uploaded, written) = upload_streamed(
            &fetcher,
            UploadRequest::path("objects", body),
            writer,
            &data,
        )
        .await;
        written.unwrap();
        let uploaded = uploaded.unwrap();
        assert!(
            uploaded.url().starts_with(&live.url(false)),
            "{}",
            uploaded.url()
        );
        assert_eq!(live.requests(), 1);
        assert_body(&live.seen()[0], &data);
    }));
}

/// A connection closed before the TLS handshake sends nothing, so the upload
/// is tried again over a new one.
#[test]
fn a_tls_handshake_dropped_on_the_first_connection_is_retried() {
    block_on(bounded(async {
        let server = TestServer::start(tls_transport("h2"), always(b"accepted")).await;
        let front = dropping_front(server.addr).await;
        let fetcher = Fetcher::new(FetcherOptions {
            max_retries: 1,
            ..upload_options(format!("https://localhost:{}", front.port()))
        })
        .await
        .unwrap();
        let data = upload_data(200_000);

        let (status, protocol, _) = post_streamed(&fetcher, "objects", &data).await;
        assert_eq!((status, protocol), (200, Protocol::Http2));
        assert_eq!(server.connections(), 1);
        assert_eq!(server.requests(), 1);
        assert_body(&server.seen()[0], &data);
    }));
}

/// A tunnel the proxy refuses with 503 is tried again, and the upload goes
/// through on the next round. A 407 refuses the credential, so it is final.
#[test]
fn a_refused_tunnel_is_retried_at_503_and_final_at_407() {
    block_on(bounded(async {
        let origin = TestServer::start(tls_transport("h2"), always(b"accepted")).await;
        let proxy = TestProxy::start(Tunnel::RefuseFirst(503)).await;
        let fetcher = Fetcher::new(FetcherOptions {
            proxy: Proxy::Url(proxy.url()),
            max_retries: 1,
            ..upload_options(origin.url(true))
        })
        .await
        .unwrap();
        let data = upload_data(100_000);
        let (status, _, _) = post_streamed(&fetcher, "objects", &data).await;
        assert_eq!(status, 200);
        assert_eq!(proxy.requests(), 2);
        assert_eq!(origin.requests(), 1);
        assert_body(&origin.seen()[0], &data);

        let proxy = TestProxy::start(Tunnel::Refuse(407)).await;
        let fetcher = Fetcher::new(FetcherOptions {
            proxy: Proxy::Url(proxy.url()),
            max_retries: 3,
            ..upload_options("https://localhost:1/repo")
        })
        .await
        .unwrap();
        let err = upload_error(&fetcher, UploadRequest::path("objects", Vec::new().into())).await;
        assert!(matches!(err, Error::Fetch(_)), "{err}");
        assert!(err.to_string().contains("407"), "{err}");
        assert_eq!(proxy.requests(), 1);
    }));
}

/// Rounds that run out before the request is sent report the error a fetch
/// reports. The writer waits through the rounds with no stall window, since
/// nothing has taken the body, and then gets a broken pipe.
#[test]
fn retries_that_run_out_before_sending_report_a_fetch_error() {
    block_on(bounded(async {
        let reserved = reserved_port();
        let port = reserved.port;
        let fetcher = Fetcher::new(FetcherOptions {
            progress_timeout: Duration::from_millis(100),
            max_retries: 1,
            ..direct_options(format!("http://127.0.0.1:{port}"))
        })
        .await
        .unwrap();
        let data = upload_data(300_000);
        let (body, writer) = UploadBody::channel();
        let (uploaded, written) = upload_streamed(
            &fetcher,
            UploadRequest::path("objects", body),
            writer,
            &data,
        )
        .await;
        let err = uploaded.unwrap_err();
        assert!(matches!(err, Error::Fetch(_)), "{err}");
        assert!(err.is_unsent());
        assert!(err.to_string().contains("connect to"), "{err}");
        assert_eq!(written.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }));
}

/// A writer whose slot is full while the upload waits out the backoff between
/// rounds has no stall window: the window starts when the request is handed
/// over, so the body arrives whole once a round reaches the server.
#[test]
fn a_writer_waiting_through_the_retry_rounds_does_not_time_out() {
    block_on(bounded(async {
        let reserved = reserved_port();
        let port = reserved.port;
        let late = spawn(async move {
            Timer::after(Duration::from_millis(600)).await;
            TestServer::start_on(
                format!("127.0.0.1:{port}").parse().unwrap(),
                Leaf::Fixture,
                Transport::Cleartext,
                always(b"accepted"),
            )
            .await
        });
        let fetcher = Fetcher::new(FetcherOptions {
            progress_timeout: Duration::from_millis(200),
            max_retries: 4,
            ..direct_options(format!("http://127.0.0.1:{port}"))
        })
        .await
        .unwrap();
        let data = upload_data(300_000);

        let (status, _, answer) = post_streamed(&fetcher, "objects", &data).await;
        assert_eq!(status, 200);
        assert_eq!(answer, b"accepted");
        let server = late.await;
        assert_eq!(server.requests(), 1);
        assert_body(&server.seen()[0], &data);
    }));
}

/// A writer whose slot is full while the upload waits at the gate has no
/// stall window either.
#[test]
fn a_writer_waiting_at_the_gate_does_not_time_out() {
    block_on(bounded(async {
        let server = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
        let fetcher = Fetcher::new(FetcherOptions {
            progress_timeout: Duration::from_millis(200),
            max_outstanding: 1,
            ..direct_options(server.url(false))
        })
        .await
        .unwrap();
        let Fetched::Body(held) = fetcher.fetch(FetchRequest::path("config")).await.unwrap() else {
            panic!("a 200 carries a body");
        };
        let data = upload_data(300_000);
        let (body, writer) = UploadBody::channel();
        let released = async {
            Timer::after(Duration::from_millis(600)).await;
            drop(held);
        };
        let ((uploaded, written), ()) = futures_lite::future::zip(
            upload_streamed(
                &fetcher,
                UploadRequest::path("objects", body),
                writer,
                &data,
            ),
            released,
        )
        .await;
        written.unwrap();
        assert_eq!(uploaded.unwrap().status(), 200);
        assert_eq!(server.requests(), 2);
        assert_body(&server.seen()[1], &data);
    }));
}

/// A writer dropped before the upload hands its request over leaves a body
/// that fails, so the request is never sent: the upload fails as unsent, and
/// the server sees no request of it.
#[test]
fn a_writer_dropped_before_the_hand_over_sends_nothing() {
    block_on(bounded(async {
        let server = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
        let fetcher = Fetcher::new(FetcherOptions {
            max_outstanding: 1,
            ..direct_options(server.url(false))
        })
        .await
        .unwrap();
        let Fetched::Body(held) = fetcher.fetch(FetchRequest::path("config")).await.unwrap() else {
            panic!("a 200 carries a body");
        };
        let (body, mut writer) = UploadBody::channel();
        writer.write_all(&upload_data(1000)).await.unwrap();
        drop(writer);
        let released = async {
            Timer::after(Duration::from_millis(100)).await;
            drop(held);
        };
        let (uploaded, ()) = futures_lite::future::zip(
            fetcher.upload(UploadRequest::path("objects", body)),
            released,
        )
        .await;
        let err = uploaded.unwrap_err();
        assert!(matches!(err, Error::Fetch(_)), "{err}");
        assert!(err.is_unsent());
        assert!(err.to_string().contains("dropped"), "{err}");
        assert_eq!(server.requests(), 1);
        assert_eq!(server.seen()[0].method, "GET");
    }));
}

/// The fetch timeout bounds an upload that is never handed over: a peer that
/// takes the connection and never completes the TLS handshake fails the
/// upload as unsent, and the writer then gets a broken pipe.
#[test]
fn the_fetch_timeout_bounds_an_upload_before_the_hand_over() {
    block_on(bounded(async {
        let addr = silent_reader().await;
        let fetcher = Fetcher::new(FetcherOptions {
            fetch_timeout: Some(Duration::from_millis(300)),
            ..upload_options(format!("https://localhost:{}", addr.port()))
        })
        .await
        .unwrap();
        let (body, mut writer) = UploadBody::channel();
        let started = Instant::now();
        let err = upload_error(&fetcher, UploadRequest::path("objects", body)).await;
        assert!(matches!(err, Error::Fetch(_)), "{err}");
        assert!(err.is_unsent());
        assert!(err.to_string().contains("not sent within"), "{err}");
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert!(started.elapsed() < Duration::from_secs(10));
        let err = writer.write_all(b"late").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }));
}

/// A body the server cuts short was sent in part, so the upload fails as
/// interrupted, and neither another round nor another mirror is asked.
#[test]
fn a_body_cut_short_by_the_server_is_not_sent_again() {
    block_on(bounded(async {
        let cutting = TestServer::start_streamed(Transport::Cleartext, cut_after(100 * 1024)).await;
        let live = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
        let fetcher = Fetcher::new(FetcherOptions {
            mirrors: vec![cutting.url(false), live.url(false)],
            max_retries: 3,
            ..direct_options("unused")
        })
        .await
        .unwrap();
        let data = upload_data(2 * 1024 * 1024);

        let (body, writer) = UploadBody::channel();
        let (uploaded, _) = upload_streamed(
            &fetcher,
            UploadRequest::path("objects", body),
            writer,
            &data,
        )
        .await;
        let err = uploaded.unwrap_err();
        assert!(
            matches!(&err, Error::UploadInterrupted { url, .. } if url.starts_with(&cutting.url(false))),
            "{err}"
        );
        assert_eq!(cutting.connections(), 1);
        assert_eq!(cutting.requests(), 1);
        assert_eq!(live.connections(), 0);
    }));
}

/// Every status that follows the whole body is the caller's answer, the
/// retryable ones of a fetch included: one request, and no other mirror.
#[test]
fn every_status_after_the_full_body_is_the_callers_answer() {
    block_on(bounded(async {
        let data = upload_data(200_000);
        for status in [500, 503, 408, 429, 422, 401] {
            let server = TestServer::start(Transport::Cleartext, always_status(status)).await;
            let live = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
            let fetcher = Fetcher::new(FetcherOptions {
                mirrors: vec![server.url(false), live.url(false)],
                max_retries: 3,
                ..direct_options("unused")
            })
            .await
            .unwrap();
            let (answered, _, _) = post_streamed(&fetcher, "objects", &data).await;
            assert_eq!(answered, status);
            assert_eq!(server.requests(), 1, "{status}");
            assert_body(&server.seen()[0], &data);
            assert_eq!(live.requests(), 0, "{status}");
        }
    }));
}

/// A server that takes the whole body and closes without an answer leaves the
/// outcome unknown: the upload is interrupted, and nothing is asked again.
#[test]
fn a_full_body_with_no_answer_is_interrupted() {
    block_on(bounded(async {
        let server =
            TestServer::start_streamed(Transport::Cleartext, no_answer_after_the_body(true)).await;
        let live = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
        let fetcher = Fetcher::new(FetcherOptions {
            mirrors: vec![server.url(false), live.url(false)],
            max_retries: 3,
            ..direct_options("unused")
        })
        .await
        .unwrap();
        let err = upload_error(
            &fetcher,
            UploadRequest::path("commit", upload_data(10_000).into()),
        )
        .await;
        assert!(matches!(err, Error::UploadInterrupted { .. }), "{err}");
        assert!(!err.is_unsent());
        assert_eq!(server.requests(), 1);
        assert_eq!(live.requests(), 0);
    }));
}

/// The wait for the head starts when the body ends and lasts the response
/// timeout, past which the upload is interrupted. The fetch timeout ends at
/// the hand-over, so a shorter one does not cut the wait.
#[test]
fn a_head_that_stalls_past_the_response_timeout_is_interrupted() {
    block_on(bounded(async {
        let server =
            TestServer::start_streamed(Transport::Cleartext, no_answer_after_the_body(false)).await;
        let fetcher = Fetcher::new(FetcherOptions {
            fetch_timeout: Some(Duration::from_millis(150)),
            max_retries: 3,
            ..direct_options(server.url(false))
        })
        .await
        .unwrap();
        let started = Instant::now();
        let err = upload_error(
            &fetcher,
            UploadRequest {
                response_timeout: Some(Duration::from_millis(400)),
                ..UploadRequest::path("commit", upload_data(64 * 1024).into())
            },
        )
        .await;
        assert!(matches!(err, Error::UploadInterrupted { .. }), "{err}");
        assert!(err.to_string().contains("no response within"), "{err}");
        assert!(started.elapsed() >= Duration::from_millis(400));
        assert_eq!(server.requests(), 1);
    }));
}

/// An HTTP/2 stream the server resets after part of the body ends the upload
/// as interrupted, with no other request.
#[test]
fn an_http2_stream_reset_after_part_of_the_body_is_interrupted() {
    block_on(bounded(async {
        let server = TestServer::start_streamed(tls_transport("h2"), cut_after(100 * 1024)).await;
        let live = TestServer::start(tls_transport("h2"), always(b"accepted")).await;
        let fetcher = Fetcher::new(FetcherOptions {
            mirrors: vec![server.url(true), live.url(true)],
            max_retries: 3,
            ..upload_options("unused")
        })
        .await
        .unwrap();
        let data = upload_data(2 * 1024 * 1024);

        let (body, writer) = UploadBody::channel();
        let (uploaded, _) = upload_streamed(
            &fetcher,
            UploadRequest::path("objects", body),
            writer,
            &data,
        )
        .await;
        let err = uploaded.unwrap_err();
        assert!(matches!(err, Error::UploadInterrupted { .. }), "{err}");
        assert_eq!(server.requests(), 1);
        assert_eq!(live.connections(), 0);
    }));
}

/// A 307 or a 308 is followed for a body given whole, with the method kept and
/// the bytes sent again. A streamed body is not followed, and neither is a
/// 302: each is delivered as its status.
#[test]
fn an_upload_follows_307_and_308_for_a_whole_body_alone() {
    block_on(bounded(async {
        let data = upload_data(70_000);
        let redirecting = |status: u16| -> Handler {
            Arc::new(move |_seen, count| {
                if count == 1 {
                    redirect(status, "/moved")
                } else {
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(TestBody::measured(b"landed"))
                        .unwrap()
                }
            })
        };
        for status in [307, 308] {
            let server = TestServer::start(Transport::Cleartext, redirecting(status)).await;
            let fetcher = Fetcher::new(direct_options(server.url(false)))
                .await
                .unwrap();
            let uploaded = fetcher
                .upload(UploadRequest::path("objects", data.clone().into()))
                .await
                .unwrap();
            assert_eq!(uploaded.status(), 200);
            assert_eq!(uploaded.url(), format!("{}/moved", server.url(false)));
            assert_eq!(read_uploaded(uploaded).await, b"landed");
            let seen = server.seen();
            assert_eq!(seen.len(), 2);
            assert_eq!(seen[1].method, "POST");
            assert_eq!(seen[1].path, "/moved");
            assert_body(&seen[1], &data);

            let server = TestServer::start(Transport::Cleartext, redirecting(status)).await;
            let fetcher = Fetcher::new(direct_options(server.url(false)))
                .await
                .unwrap();
            let (answered, _, _) = post_streamed(&fetcher, "objects", &data).await;
            assert_eq!(answered, status);
            assert_eq!(server.requests(), 1);
        }

        let server = TestServer::start(Transport::Cleartext, redirecting(302)).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let uploaded = fetcher
            .upload(UploadRequest::path("objects", data.clone().into()))
            .await
            .unwrap();
        assert_eq!(uploaded.status(), 302);
        assert_eq!(server.requests(), 1);
    }));
}

/// A declared response length over the cap fails the upload after its one
/// request, whatever the status.
#[test]
fn a_declared_response_over_the_cap_fails_after_one_request() {
    block_on(bounded(async {
        static LARGE: [u8; 4096] = [b'r'; 4096];
        for status in [200, 422] {
            let server = TestServer::start(
                Transport::Cleartext,
                Arc::new(move |_seen, _count| {
                    Response::builder()
                        .status(status)
                        .body(TestBody::measured(&LARGE))
                        .unwrap()
                }),
            )
            .await;
            let live = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
            let fetcher = Fetcher::new(FetcherOptions {
                mirrors: vec![server.url(false), live.url(false)],
                ..direct_options("unused")
            })
            .await
            .unwrap();
            let err = upload_error(
                &fetcher,
                UploadRequest {
                    max_response: 1024,
                    ..UploadRequest::path("objects", b"hello".to_vec().into())
                },
            )
            .await;
            // The request was sent, so the upload is interrupted, and the
            // message names the cap.
            assert!(
                matches!(&err, Error::UploadInterrupted { message, .. } if message.contains("1024-byte cap")),
                "{err}"
            );
            assert!(!err.is_unsent());
            assert_eq!(server.requests(), 1);
            assert_eq!(live.requests(), 0);
        }
    }));
}

/// A response body that outgrows the cap while it streams fails the read, and
/// every read after it.
#[test]
fn a_chunked_response_past_the_cap_fails_the_read_and_stays_failed() {
    block_on(bounded(async {
        static LARGE: [u8; 8192] = [b'r'; 8192];
        let server = TestServer::start(
            Transport::Cleartext,
            Arc::new(|_seen, _count| {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(TestBody::chunked(&LARGE, 8))
                    .unwrap()
            }),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let uploaded = fetcher
            .upload(UploadRequest {
                max_response: 1000,
                ..UploadRequest::path("objects", b"hello".to_vec().into())
            })
            .await
            .unwrap();
        let mut body = uploaded.into_body();
        let mut out = Vec::new();
        let err = body.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::FileTooLarge);
        let mut more = [0u8; 16];
        let err = body.read(&mut more).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::FileTooLarge);
    }));
}

/// A response that declares a coding is refused. The request was sent, so the
/// upload is interrupted, and the message names the coding.
#[test]
fn a_coded_response_to_an_upload_is_refused() {
    block_on(bounded(async {
        let server = TestServer::start(
            Transport::Cleartext,
            Arc::new(|_seen, _count| {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-encoding", "gzip")
                    .body(TestBody::measured(b"squeezed"))
                    .unwrap()
            }),
        )
        .await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let err = upload_error(
            &fetcher,
            UploadRequest::path("objects", b"hello".to_vec().into()),
        )
        .await;
        assert!(
            matches!(&err, Error::UploadInterrupted { message, .. } if message.contains("coding gzip")),
            "{err}"
        );
        assert!(!err.is_unsent());
        assert_eq!(server.requests(), 1);
    }));
}

/// A writer dropped before close fails the body: the upload is interrupted,
/// and the server reads a body that never reaches its end.
#[test]
fn a_writer_dropped_before_close_interrupts_the_upload() {
    block_on(bounded(async {
        let server = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let data = upload_data(200_000);
        let (body, mut writer) = UploadBody::channel();
        let written = async move {
            writer.write_all(&data).await.unwrap();
            writer.flush().await.unwrap();
            drop(writer);
        };
        let (uploaded, ()) = futures_lite::future::zip(
            fetcher.upload(UploadRequest::path("objects", body)),
            written,
        )
        .await;
        let err = uploaded.unwrap_err();
        assert!(matches!(err, Error::UploadInterrupted { .. }), "{err}");
        assert!(err.to_string().contains("dropped"), "{err}");
        eventually("the server records the request", || server.requests() == 1).await;
        let seen = &server.seen()[0];
        assert!(!seen.body_complete);
        assert!(seen.body_len <= 200_000);
    }));
}

/// Against a server that never reads, the frame in the slot waits past the
/// stall window: the write fails with a timeout, and the upload is
/// interrupted.
#[test]
fn a_writer_stalls_against_a_server_that_never_reads() {
    block_on(bounded(async {
        let addr = silent_reader().await;
        let fetcher = Fetcher::new(FetcherOptions {
            progress_timeout: Duration::from_millis(300),
            max_retries: 0,
            ..direct_options(format!("http://127.0.0.1:{}", addr.port()))
        })
        .await
        .unwrap();
        let (body, mut writer) = UploadBody::channel();
        // The body is made as it is written, and the socket buffers fill long
        // before the bound.
        let written = async move {
            let piece = vec![0u8; 64 * 1024];
            let mut total = 0u64;
            loop {
                if let Err(err) = writer.write_all(&piece).await {
                    return err;
                }
                total += piece.len() as u64;
                assert!(total < 1 << 30, "the writer never stalled");
            }
        };
        let (uploaded, err) = futures_lite::future::zip(
            fetcher.upload(UploadRequest::path("objects", body)),
            written,
        )
        .await;
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let err = uploaded.unwrap_err();
        assert!(matches!(err, Error::UploadInterrupted { .. }), "{err}");
        assert!(err.to_string().contains("not taken"), "{err}");
    }));
}

/// Once the upload is done with the body, a write fails with a broken pipe.
#[test]
fn a_write_after_the_upload_ended_is_a_broken_pipe() {
    block_on(bounded(async {
        let server = TestServer::start_streamed(Transport::Cleartext, cut_after(64 * 1024)).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let (body, mut writer) = UploadBody::channel();
        // One frame waits in the slot and one in the writer, so the server
        // has its 64 KiB without another write.
        writer.write_all(&upload_data(128 * 1024)).await.unwrap();
        let err = upload_error(&fetcher, UploadRequest::path("objects", body)).await;
        assert!(matches!(err, Error::UploadInterrupted { .. }), "{err}");
        let piece = vec![0u8; 64 * 1024];
        let err = loop {
            if let Err(err) = writer.write_all(&piece).await {
                break err;
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }));
}

/// A `DELETE` reaches the server with no body and no framing headers, and a
/// `DELETE` that carries a body is refused before admission.
#[test]
fn a_delete_reaches_the_server_with_no_body() {
    block_on(bounded(async {
        let server = TestServer::start(Transport::Cleartext, always_status(204)).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let uploaded = fetcher
            .upload(UploadRequest {
                method: UploadMethod::Delete,
                ..UploadRequest::path("_ostrya/receive/v1/session/abc", Vec::new().into())
            })
            .await
            .unwrap();
        assert_eq!(uploaded.status(), 204);
        let seen = &server.seen()[0];
        assert_eq!(seen.method, "DELETE");
        assert_eq!(seen.path, "/_ostrya/receive/v1/session/abc");
        assert_eq!(seen.header("content-length"), None);
        assert_eq!(seen.header("transfer-encoding"), None);
        assert_body(seen, b"");

        for body in [b"x".to_vec().into(), UploadBody::channel().0] {
            let err = upload_error(
                &fetcher,
                UploadRequest {
                    method: UploadMethod::Delete,
                    ..UploadRequest::path("session", body)
                },
            )
            .await;
            assert!(err.to_string().contains("carries a body"), "{err}");
        }
        assert_eq!(server.requests(), 1);
    }));
}

/// An upload takes an HTTP/1.1 connection that went idle a short time ago,
/// and its connection goes back to the pool once its response body ends, so
/// a fetch and two sequential uploads travel over one connection. HTTP/2
/// connections are shared.
#[test]
fn sequential_uploads_reuse_one_http1_connection_and_share_http2() {
    block_on(bounded(async {
        let server = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        fetch_bytes(&fetcher, "config").await;
        assert_eq!(server.connections(), 1);
        for _ in 0..2 {
            let uploaded = fetcher
                .upload(UploadRequest::path("objects", b"hello".to_vec().into()))
                .await
                .unwrap();
            assert_eq!(read_uploaded(uploaded).await, b"accepted");
        }
        let (body, writer) = UploadBody::channel();
        let (uploaded, written) = upload_streamed(
            &fetcher,
            UploadRequest::path("objects", body),
            writer,
            &upload_data(300_000),
        )
        .await;
        written.unwrap();
        read_uploaded(uploaded.unwrap()).await;
        assert_eq!(server.requests(), 4);
        assert_eq!(server.connections(), 1);
        // Two fetches in flight at once: the pool holds one connection, so
        // the second opens another.
        let first = fetcher.fetch(FetchRequest::path("config")).await.unwrap();
        let second = fetcher.fetch(FetchRequest::path("config")).await.unwrap();
        assert_eq!(server.connections(), 2);
        drop((first, second));

        let server = TestServer::start(tls_transport("h2"), always(b"accepted")).await;
        let fetcher = Fetcher::new(upload_options(server.url(true)))
            .await
            .unwrap();
        fetch_bytes(&fetcher, "config").await;
        for _ in 0..2 {
            let uploaded = fetcher
                .upload(UploadRequest::path("objects", b"hello".to_vec().into()))
                .await
                .unwrap();
            read_uploaded(uploaded).await;
        }
        assert_eq!(server.requests(), 3);
        assert_eq!(server.connections(), 1);
    }));
}

/// A response head that arrives before the end of the request body is an
/// early answer. The connection of that upload does not go back to the pool,
/// also when the writer then ends the body cleanly and the response is read
/// to its end, so the next upload opens a new connection.
#[test]
fn an_early_answer_keeps_the_http1_connection_out_of_the_pool() {
    block_on(bounded(async {
        let early: StreamHandler = Arc::new(|request: Request<Incoming>| {
            Box::pin(async move {
                let mut body = request.into_body();
                read_at_least(&mut body, 1024).await;
                // The rest of the body is read after the answer.
                drop(spawn(async move {
                    read_at_least(&mut body, u64::MAX).await;
                }));
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(TestBody::measured(b"early"))
                    .unwrap())
            })
        });
        let server = TestServer::start_streamed(Transport::Cleartext, early).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        let (body, mut writer) = UploadBody::channel();
        let first_part = async {
            writer.write_all(&[7u8; 1024]).await.unwrap();
            writer.flush().await.unwrap();
        };
        let (uploaded, ()) = futures_lite::future::zip(
            fetcher.upload(UploadRequest::path("objects", body)),
            first_part,
        )
        .await;
        let uploaded = uploaded.unwrap();
        // The head has arrived. The body now ends cleanly, and the response
        // is read to its end.
        writer.write_all(&[7u8; 1024]).await.unwrap();
        writer.close().await.unwrap();
        assert_eq!(read_uploaded(uploaded).await, b"early");
        assert_eq!(server.connections(), 1);
        let (body, mut writer) = UploadBody::channel();
        let (uploaded, ()) = futures_lite::future::zip(
            fetcher.upload(UploadRequest::path("objects", body)),
            async {
                writer.write_all(&[7u8; 2048]).await.unwrap();
                writer.close().await.unwrap();
            },
        )
        .await;
        read_uploaded(uploaded.unwrap()).await;
        assert_eq!(server.connections(), 2);
    }));
}

/// An HTTP/1.1 connection that has been idle for two seconds or more stays
/// in the pool for a fetch, and an upload opens a new connection.
#[test]
fn an_upload_does_not_take_a_connection_idle_for_two_seconds() {
    block_on(bounded(async {
        let server = TestServer::start(Transport::Cleartext, always(b"accepted")).await;
        let fetcher = Fetcher::new(direct_options(server.url(false)))
            .await
            .unwrap();
        fetch_bytes(&fetcher, "config").await;
        Timer::after(Duration::from_millis(2100)).await;
        let uploaded = fetcher
            .upload(UploadRequest::path("objects", b"hello".to_vec().into()))
            .await
            .unwrap();
        read_uploaded(uploaded).await;
        assert_eq!(server.connections(), 2);
        // The fetch takes the connection that the upload did not.
        fetch_bytes(&fetcher, "config").await;
        assert_eq!(server.connections(), 2);
    }));
}

/// A pooled connection that the server closed while it was idle does not
/// carry an upload: the upload goes over a new connection with no round
/// spent, so it succeeds with no retry allowed.
#[test]
fn an_upload_does_not_use_an_idle_connection_the_server_closed() {
    block_on(bounded(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        drop(spawn(async move {
            // Each connection carries one exchange, and the server then
            // closes it with no `Connection: close`.
            while let Ok((mut stream, _peer)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
                let _ = stream.close().await;
            }
        }));
        let fetcher = Fetcher::new(FetcherOptions {
            max_retries: 0,
            ..direct_options(format!("http://127.0.0.1:{}", addr.port()))
        })
        .await
        .unwrap();
        fetch_bytes(&fetcher, "config").await;
        Timer::after(Duration::from_millis(100)).await;
        let uploaded = fetcher
            .upload(UploadRequest::path("objects", b"hello".to_vec().into()))
            .await
            .unwrap();
        assert_eq!(read_uploaded(uploaded).await, b"ok");
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }));
}

/// The response body of an upload holds its admission permit until it ends,
/// and its bytes reach the counters of the fetcher.
#[test]
fn an_upload_response_holds_its_permit_and_is_counted() {
    block_on(bounded(async {
        let server = TestServer::start(Transport::Cleartext, always(b"twelve bytes")).await;
        let counter = Arc::new(AtomicU64::new(0));
        let fetcher = Fetcher::with_counters(
            FetcherOptions {
                max_outstanding: 1,
                ..direct_options(server.url(false))
            },
            vec![counter.clone()],
        )
        .await
        .unwrap();
        let uploaded = fetcher
            .upload(UploadRequest::path("objects", b"hello".to_vec().into()))
            .await
            .unwrap();
        let queued = or(
            async {
                fetch_bytes(&fetcher, "config").await;
                true
            },
            async {
                Timer::after(Duration::from_millis(200)).await;
                false
            },
        )
        .await;
        assert!(
            !queued,
            "a fetch was admitted beside the unread upload body"
        );
        assert_eq!(read_uploaded(uploaded).await, b"twelve bytes");
        assert_eq!(counter.load(Ordering::SeqCst), 12);
        fetch_bytes(&fetcher, "config").await;
    }));
}

/// The upload future travels between threads with its writer.
#[test]
fn the_upload_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    block_on(async {
        let fetcher = Fetcher::new(direct_options("http://127.0.0.1:1"))
            .await
            .unwrap();
        let (body, writer) = UploadBody::channel();
        let future = fetcher.upload(UploadRequest::path("objects", body));
        assert_send(&future);
        assert_send(&writer);
    });
}

/// A body given whole travels in frames, and the window for the response head
/// starts when hyper takes the last of them. A server that stops reading for
/// longer than the response timeout, and then reads the rest at once, answers
/// within the window.
#[test]
fn a_whole_body_streams_in_frames_before_the_response_window() {
    block_on(bounded(async {
        let data = upload_data(32 * 1024 * 1024);
        let read = Arc::new(AtomicU64::new(0));
        let pausing = {
            let read = read.clone();
            Arc::new(move |request: Request<Incoming>| {
                let read = read.clone();
                Box::pin(async move {
                    let mut body = request.into_body();
                    let first = read_at_least(&mut body, 64 * 1024).await;
                    Timer::after(Duration::from_secs(1)).await;
                    let rest = read_at_least(&mut body, u64::MAX).await;
                    read.store(first + rest, Ordering::SeqCst);
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(TestBody::measured(b"accepted"))
                        .unwrap())
                }) as Pin<Box<dyn Future<Output = _> + Send>>
            }) as StreamHandler
        };
        for (transport, tls) in [(Transport::Cleartext, false), (tls_transport("h2"), true)] {
            let server = TestServer::start_streamed(transport, pausing.clone()).await;
            let fetcher = Fetcher::new(FetcherOptions {
                progress_timeout: Duration::from_secs(5),
                ..upload_options(server.url(tls))
            })
            .await
            .unwrap();
            let uploaded = fetcher
                .upload(UploadRequest {
                    response_timeout: Some(Duration::from_millis(300)),
                    ..UploadRequest::path("objects", data.clone().into())
                })
                .await
                .unwrap();
            assert_eq!(uploaded.status(), 200);
            assert_eq!(read.load(Ordering::SeqCst), data.len() as u64);
            assert_eq!(
                server.seen()[0].header("content-length"),
                Some(data.len().to_string().as_str())
            );
        }
    }));
}

/// An HTTP/2 server that lets one stream open at a time on each connection.
/// A request for `/held` gets a response head and a body that never ends,
/// which keeps its stream open. Every other request has its body read and
/// recorded, and gets a 200. Once `cut` is set, the first connection closes.
struct OneStreamServer {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    connections: Arc<AtomicUsize>,
    cut: Arc<std::sync::atomic::AtomicBool>,
}

impl OneStreamServer {
    async fn start() -> OneStreamServer {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = OneStreamServer {
            addr,
            seen: Arc::new(Mutex::new(Vec::new())),
            connections: Arc::new(AtomicUsize::new(0)),
            cut: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let acceptor = futures_rustls::TlsAcceptor::from(Arc::new(server_config(
            &["h2"],
            ClientAuth::None,
            Leaf::Fixture,
        )));
        let (seen, connections, cut) = (
            server.seen.clone(),
            server.connections.clone(),
            server.cut.clone(),
        );
        drop(spawn(async move {
            while let Ok((stream, _peer)) = listener.accept().await {
                let first = connections.fetch_add(1, Ordering::SeqCst) == 0;
                let (acceptor, seen, cut) = (acceptor.clone(), seen.clone(), cut.clone());
                drop(spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request: Request<Incoming>| {
                        let seen = seen.clone();
                        async move {
                            let mut record = Seen::head(&request);
                            if record.path == "/held" {
                                seen.lock().unwrap().push(record);
                                return Ok::<_, Infallible>(Response::new(TestBody::endless()));
                            }
                            record
                                .read_body(request.into_body(), &AtomicU64::new(0))
                                .await;
                            seen.lock().unwrap().push(record);
                            Ok(Response::new(TestBody::measured(b"accepted")))
                        }
                    });
                    let served = hyper::server::conn::http2::Builder::new(TestExecutor)
                        .max_concurrent_streams(1)
                        .serve_connection(
                            TestIo {
                                inner: tls,
                                scratch: Vec::new(),
                            },
                            service,
                        );
                    or(
                        async {
                            let _ = served.await;
                        },
                        async {
                            while !(first && cut.load(Ordering::SeqCst)) {
                                Timer::after(Duration::from_millis(10)).await;
                            }
                        },
                    )
                    .await;
                }));
            }
        }));
        server
    }

    fn url(&self) -> String {
        format!("https://localhost:{}", self.addr.port())
    }
}

/// A body given whole on an HTTP/2 stream that never opens, because the
/// server has no stream to spare, is bounded by the stall window: its first
/// frame is not taken, and the upload is interrupted.
#[test]
fn a_whole_body_on_a_stream_that_never_opens_is_bounded() {
    block_on(bounded(async {
        let server = OneStreamServer::start().await;
        let fetcher = Fetcher::new(FetcherOptions {
            progress_timeout: Duration::from_millis(300),
            ..upload_options(server.url())
        })
        .await
        .unwrap();
        let held = fetcher.fetch(FetchRequest::path("held")).await.unwrap();
        let started = Instant::now();
        let err = or(
            upload_error(
                &fetcher,
                UploadRequest::path("objects", upload_data(100_000).into()),
            ),
            async {
                Timer::after(Duration::from_secs(5)).await;
                panic!("the upload waited on a stream that never opened")
            },
        )
        .await;
        assert!(matches!(err, Error::UploadInterrupted { .. }), "{err}");
        assert!(err.to_string().contains("not taken"), "{err}");
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
        assert_eq!(server.seen.lock().unwrap().len(), 1);
        drop(held);
    }));
}

/// A request that hyper gives back unsent spends a round and is sent on the
/// next one. The upload waits in the queue of an HTTP/2 connection behind a
/// stream that cannot open, and the connection closes: hyper returns the
/// queued request, and the next round sends it over a new connection.
#[test]
fn a_request_given_back_unsent_is_sent_on_the_next_round() {
    block_on(bounded(async {
        let server = OneStreamServer::start().await;
        let fetcher = Fetcher::new(FetcherOptions {
            max_retries: 1,
            ..upload_options(server.url())
        })
        .await
        .unwrap();
        let held = fetcher.fetch(FetchRequest::path("held")).await.unwrap();
        // A second fetch waits for a stream to open, so the connection takes
        // no further request from its queue.
        let blocked = spawn({
            let fetcher = fetcher.clone();
            async move {
                let _ = fetcher.fetch(FetchRequest::path("config")).await;
            }
        });
        Timer::after(Duration::from_millis(100)).await;
        let data = upload_data(100_000);
        let cut = async {
            Timer::after(Duration::from_millis(300)).await;
            server.cut.store(true, Ordering::SeqCst);
        };
        let (uploaded, ()) = futures_lite::future::zip(
            fetcher.upload(UploadRequest::path("objects", data.clone().into())),
            cut,
        )
        .await;
        let uploaded = uploaded.unwrap();
        assert_eq!(uploaded.status(), 200);
        assert!(server.connections.load(Ordering::SeqCst) >= 2);
        let seen = server.seen.lock().unwrap().clone();
        let posts = seen
            .iter()
            .filter(|seen| seen.method == "POST")
            .collect::<Vec<_>>();
        assert_eq!(posts.len(), 1);
        assert_body(posts[0], &data);
        drop(held);
        blocked.await;
    }));
}

/// A server that answers before it has read the streamed body, and keeps
/// reading, does not get the rest of it: once the response has ended, the
/// body fails, and the writer gets a broken pipe.
#[test]
fn an_early_answer_ends_the_streamed_body() {
    block_on(bounded(async {
        const LIMIT: u64 = 64 * 1024 * 1024;
        for (transport, tls) in [(Transport::Cleartext, false), (tls_transport("h2"), true)] {
            let read = Arc::new(AtomicU64::new(0));
            let early = {
                let read = read.clone();
                Arc::new(move |request: Request<Incoming>| {
                    let read = read.clone();
                    Box::pin(async move {
                        let mut body = request.into_body();
                        drop(spawn(async move {
                            while let Some(Ok(frame)) =
                                std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
                            {
                                if let Ok(data) = frame.into_data() {
                                    read.fetch_add(data.len() as u64, Ordering::SeqCst);
                                }
                            }
                        }));
                        Ok(Response::builder()
                            .status(StatusCode::PAYLOAD_TOO_LARGE)
                            .body(TestBody::measured(b"too large"))
                            .unwrap())
                    }) as Pin<Box<dyn Future<Output = _> + Send>>
                }) as StreamHandler
            };
            let server = TestServer::start_streamed(transport, early).await;
            let fetcher = Fetcher::new(upload_options(server.url(tls))).await.unwrap();
            let (body, mut writer) = UploadBody::channel();
            let answered = async {
                let uploaded = fetcher
                    .upload(UploadRequest::path("objects", body))
                    .await
                    .unwrap();
                assert_eq!(uploaded.status(), 413);
                read_uploaded(uploaded).await
            };
            let written = async move {
                let piece = vec![0u8; 64 * 1024];
                let mut total = 0u64;
                while total < LIMIT {
                    writer.write_all(&piece).await?;
                    total += piece.len() as u64;
                }
                Ok::<_, io::Error>(total)
            };
            let (answer, written) = futures_lite::future::zip(answered, written).await;
            assert_eq!(answer, b"too large");
            let err = written.expect_err("the body was still taken after the answer");
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
            assert!(read.load(Ordering::SeqCst) < LIMIT);
        }
    }));
}

/// A `POST` whose streamed body is at its end when the request is handed over
/// declares a length of zero, over HTTP/1.1 and over HTTP/2.
#[test]
fn an_empty_streamed_post_declares_a_length_of_zero() {
    block_on(bounded(async {
        for (transport, tls) in [(Transport::Cleartext, false), (tls_transport("h2"), true)] {
            let server = TestServer::start(transport, always(b"accepted")).await;
            let fetcher = Fetcher::new(upload_options(server.url(tls))).await.unwrap();
            let (body, writer) = UploadBody::channel();
            let (uploaded, written) =
                upload_streamed(&fetcher, UploadRequest::path("objects", body), writer, b"").await;
            written.unwrap();
            assert_eq!(uploaded.unwrap().status(), 200);
            let seen = &server.seen()[0];
            assert_eq!(seen.header("content-length"), Some("0"));
            assert_eq!(seen.header("transfer-encoding"), None);
            assert_body(seen, b"");
        }
    }));
}
