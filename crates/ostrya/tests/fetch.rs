//! Fetcher integration tests (Phase 16a).
//!
//! Every test serves requests from an in-process server built on hyper's server
//! half, over cleartext HTTP/1.1 and over TLS where ALPN selects HTTP/1.1 or
//! HTTP/2. The fixture certificates under `tests/fixtures/tls/` provide a
//! certificate authority the client trusts, a server certificate for
//! `127.0.0.1`, and a client certificate for the mutual-TLS test.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::future::or;
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use hyper::body::{Bytes, Frame, SizeHint};
use hyper::header::{HeaderMap, HeaderName};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use ostrya::{
    BasicAuth, Checksum, ClientIdentity, Error, FetchRequest, Fetched, Fetcher, FetcherOptions,
    Priority, Protocol, TlsOptions, TrustRoots, VerifyingReader,
};
use ostrya_rt::{TcpListener, Timer, block_on, spawn};
use sha2::{Digest, Sha256};

const CA_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/ca.pem");
const SERVER_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.pem");
const SERVER_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.key.pem");
const CLIENT_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/client.pem");
const CLIENT_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/client.key.pem");

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
}

impl TestBody {
    /// A body of `bytes`, delivered in one chunk with a declared length.
    fn measured(bytes: &[u8]) -> TestBody {
        TestBody {
            chunks: VecDeque::from([Bytes::copy_from_slice(bytes)]),
            exact: Some(bytes.len() as u64),
        }
    }

    /// A body delivered in `count` chunks with no declared length, which makes
    /// the server answer with chunked transfer encoding.
    fn chunked(bytes: &[u8], count: usize) -> TestBody {
        let size = bytes.len().div_ceil(count.max(1));
        TestBody {
            chunks: bytes.chunks(size).map(Bytes::copy_from_slice).collect(),
            exact: None,
        }
    }

    fn empty() -> TestBody {
        TestBody {
            chunks: VecDeque::new(),
            exact: Some(0),
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
        Poll::Ready(
            self.get_mut()
                .chunks
                .pop_front()
                .map(|c| Ok(Frame::data(c))),
        )
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
    path: String,
    headers: HeaderMap,
}

impl Seen {
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
    /// TLS, offering these ALPN protocols, optionally demanding a client
    /// certificate signed by the fixture authority.
    Tls {
        alpn: Vec<&'static str>,
        client_auth: bool,
    },
}

/// The handler a test installs: it sees the request and the 1-based count of
/// requests this server has answered.
type Handler = Arc<dyn Fn(&Seen, usize) -> Response<TestBody> + Send + Sync>;

/// An in-process HTTP server.
///
/// The accept loop runs in a detached task for the life of the test process;
/// the tests are short and each server answers a handful of requests.
struct TestServer {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    connections: Arc<AtomicUsize>,
}

impl TestServer {
    async fn start(transport: Transport, handler: Handler) -> TestServer {
        TestServer::start_on("127.0.0.1:0".parse().unwrap(), transport, handler).await
    }

    async fn start_on(bind: SocketAddr, transport: Transport, handler: Handler) -> TestServer {
        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let acceptor = match &transport {
            Transport::Cleartext => None,
            Transport::Tls { alpn, client_auth } => Some(futures_rustls::TlsAcceptor::from(
                Arc::new(server_config(alpn, *client_auth)),
            )),
        };
        let task_seen = seen.clone();
        let task_connections = connections.clone();
        drop(spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                task_connections.fetch_add(1, Ordering::SeqCst);
                let handler = handler.clone();
                let seen = task_seen.clone();
                let acceptor = acceptor.clone();
                drop(spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            let Ok(tls) = acceptor.accept(stream).await else {
                                return;
                            };
                            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                            serve(tls, h2, handler, seen).await;
                        }
                        None => serve(stream, false, handler, seen).await,
                    }
                }));
            }
        }));
        TestServer {
            addr,
            seen,
            connections,
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
}

/// Serve one connection.
async fn serve<S>(io: S, h2: bool, handler: Handler, seen: Arc<Mutex<Vec<Seen>>>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let io = TestIo {
        inner: io,
        scratch: Vec::new(),
    };
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let handler = handler.clone();
        let seen = seen.clone();
        async move {
            let record = Seen {
                path: request.uri().path().to_string(),
                headers: request.headers().clone(),
            };
            let count = {
                let mut log = seen.lock().unwrap();
                log.push(record.clone());
                log.len()
            };
            Ok::<_, Infallible>(handler(&record, count))
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
fn server_config(alpn: &[&str], client_auth: bool) -> rustls::ServerConfig {
    let provider = Arc::new(rustls_graviola::default_provider());
    let certs: Vec<_> = rustls_pemfile::certs(&mut io::BufReader::new(SERVER_CERT_PEM))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut io::BufReader::new(SERVER_KEY_PEM))
        .unwrap()
        .unwrap();
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();
    let mut config = if client_auth {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut io::BufReader::new(CA_PEM)) {
            roots.add(cert.unwrap()).unwrap();
        }
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(roots.into(), provider)
                .build()
                .unwrap();
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .unwrap()
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap()
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
            ..FetchRequest::new(path)
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
    match fetcher.fetch(FetchRequest::new(path)).await.unwrap() {
        Fetched::Body(mut body) => {
            let protocol = body.protocol();
            let mut out = Vec::new();
            body.read_to_end(&mut out).await.unwrap();
            (out, protocol)
        }
        Fetched::NotModified => panic!("unexpected 304 for {path}"),
    }
}

// --- tests -----------------------------------------------------------------

#[test]
fn fetches_a_body_over_cleartext_http1() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"object bytes")).await;
        let fetcher = Fetcher::new(FetcherOptions::new(server.url(false)))
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
        let server = TestServer::start_on(
            "[::1]:0".parse().unwrap(),
            Transport::Cleartext,
            always(b"object bytes"),
        )
        .await;
        let port = server.addr.port();
        let fetcher = Fetcher::new(FetcherOptions::new(format!("http://[::1]:{port}/repo")))
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
        let fetcher = Fetcher::new(FetcherOptions::new(base)).await.unwrap();
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
                client_auth: false,
            },
            always(b"over h2"),
        )
        .await;
        let mut options = FetcherOptions::new(server.url(true));
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
                client_auth: false,
            },
            always(b"over h1"),
        )
        .await;
        let mut options = FetcherOptions::new(server.url(true));
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
        let fetcher = Fetcher::new(FetcherOptions::new(server.url(false)))
            .await
            .unwrap();

        let validators = match fetcher.fetch(FetchRequest::new("summary")).await.unwrap() {
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

        let mut request = FetchRequest::new("summary");
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
        let fetcher = Fetcher::new(FetcherOptions::new(server.url(false)))
            .await
            .unwrap();

        let err = fetcher
            .fetch(FetchRequest::new("objects/ab/cd.filez"))
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
        let mut options = FetcherOptions::new(server.url(false));
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
        let mut options = FetcherOptions::new(server.url(false));
        options.max_retries = 1;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::new("config"))
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
        let mut options = FetcherOptions::new(absent.url(false));
        options
            .mirrors
            .extend([flapping.url(false), gone.url(false)]);
        options.max_retries = 2;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::new("objects/ab/cd.dirtree"))
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
        let mut options = FetcherOptions::new(absent.url(false));
        options.mirrors.push(turning.url(false));
        options.max_retries = 3;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::new("summary"))
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
        let mut options = FetcherOptions::new(turning.url(false));
        options.max_retries = 3;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::new("summary"))
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
        let mut options = FetcherOptions::new(broken.url(false));
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
        let mut options = FetcherOptions::new(first.url(false));
        options.mirrors.push(second.url(false));
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::new("summary?sig=1"))
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
        let fetcher = Fetcher::new(FetcherOptions::new(server.url(false)))
            .await
            .unwrap();

        let mut request = FetchRequest::new("summary");
        request.max_size = Some(1024);
        let err = fetcher.fetch(request).await.unwrap_err();
        assert!(matches!(err, Error::FetchTooLarge { limit: 1024 }), "{err}");
        assert_eq!(body.len(), 4096);
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
        let fetcher = Fetcher::new(FetcherOptions::new(server.url(false)))
            .await
            .unwrap();

        let mut request = FetchRequest::new("summary");
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
                client_auth: false,
            },
            always(b"authorized"),
        )
        .await;
        let mut options = FetcherOptions::new(server.url(true));
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
                client_auth: false,
            },
            always(b"unreachable"),
        )
        .await;

        let mut options = FetcherOptions::new(secure.url(true));
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
                client_auth: true,
            },
            always(b"mutual"),
        )
        .await;

        let mut with_cert = FetcherOptions::new(server.url(true));
        with_cert.tls = tls_options(Some(ClientIdentity {
            cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
            key_pem: CLIENT_KEY_PEM.to_vec(),
        }));
        let fetcher = Fetcher::new(with_cert).await.unwrap();
        let (bytes, _) = fetch_bytes(&fetcher, "config").await;
        assert_eq!(bytes, b"mutual");

        // Without the certificate the handshake fails, and a failed handshake
        // is retryable, so the attempt is repeated before it is reported.
        let mut without_cert = FetcherOptions::new(server.url(true));
        without_cert.tls = tls_options(None);
        without_cert.max_retries = 0;
        let fetcher = Fetcher::new(without_cert).await.unwrap();
        let err = fetcher
            .fetch(FetchRequest::new("config"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Fetch(_)), "{err}");
    });
}

#[test]
fn http1_connections_are_reused_between_fetches() {
    block_on(async {
        let server = TestServer::start(Transport::Cleartext, always(b"pooled")).await;
        let fetcher = Fetcher::new(FetcherOptions::new(server.url(false)))
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
                client_auth: false,
            },
            always(b"multiplexed"),
        )
        .await;
        let mut options = FetcherOptions::new(server.url(true));
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
        let fetcher = Fetcher::new(FetcherOptions::new(server.url(false)))
            .await
            .unwrap();

        let Fetched::Body(body) = fetcher
            .fetch(FetchRequest::new("objects/ab/cd.filez"))
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
            .fetch(FetchRequest::new("objects/ab/cd.filez"))
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
        let fetcher = Fetcher::new(FetcherOptions::new(server.url(false)))
            .await
            .unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::new("big")).await.unwrap() else {
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
        let fetcher = Fetcher::new(FetcherOptions::new(server.url(false)))
            .await
            .unwrap();

        for _ in 0..4 {
            let err = fetcher
                .fetch(FetchRequest::new("objects/ab/cd.filez"))
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
        let fetcher = Fetcher::new(FetcherOptions::new(server.url(false)))
            .await
            .unwrap();

        for _ in 0..4 {
            let err = fetcher
                .fetch(FetchRequest {
                    max_size: Some(4),
                    ..FetchRequest::new("summary")
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
        let fetcher = Fetcher::new(FetcherOptions::new(server.url(false)))
            .await
            .unwrap();

        for _ in 0..3 {
            assert!(
                fetcher
                    .fetch(FetchRequest::new("objects/ab/cd.filez"))
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
        let mut options = FetcherOptions::new(server.url(false));
        options.max_outstanding = 1;
        let fetcher = Fetcher::new(options).await.unwrap();

        // The one permit is held by a body that has not been read to the end.
        let Fetched::Body(held) = fetcher.fetch(FetchRequest::new("held")).await.unwrap() else {
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
        let mut options = FetcherOptions::new(format!("https://localhost:{}", addr.port()));
        options.tls = tls_options(None);
        options.connect_timeout = Duration::from_millis(150);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::new("summary"))
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
        let mut options = FetcherOptions::new(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(150);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let err = fetcher
            .fetch(FetchRequest::new("summary"))
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
        let mut options = FetcherOptions::new(format!("http://127.0.0.1:{}", addr.port()));
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
            .fetch(FetchRequest::new("summary"))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("fetch of summary timed out after"),
            "{err}"
        );

        let second = or(
            async { Some(fetcher.fetch(FetchRequest::new("summary")).await) },
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
        let mut options = FetcherOptions::new(server.url(false));
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
        let mut options = FetcherOptions::new(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(150);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::new("big")).await.unwrap() else {
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

        let mut options = FetcherOptions::new(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(150);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::new("big")).await.unwrap() else {
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
        let mut options = FetcherOptions::new(format!("http://127.0.0.1:{}", addr.port()));
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::new("big")).await.unwrap() else {
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

        let mut options = FetcherOptions::new(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(300);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::new("late")).await.unwrap()
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
        let mut options = FetcherOptions::new(format!("http://127.0.0.1:{}", addr.port()));
        options.progress_timeout = Duration::from_millis(200);
        options.max_retries = 0;
        let fetcher = Fetcher::new(options).await.unwrap();

        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::new("big")).await.unwrap() else {
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
