//! An in-process HTTP/1.1 proxy for the tests that reach an origin through
//! one.
//!
//! The proxy forwards an absolute-form request to the origin it names and
//! answers a `CONNECT` with a tunnel, and it records every request it reads.

#![allow(dead_code)]

use std::convert::Infallible;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::future::or;
use futures_lite::io::AsyncWriteExt;
use hyper::body::{Body as _, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{HeaderMap, HeaderName};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use ostrya_rt::{TcpListener, TcpStream, spawn};

/// A `futures-io` stream presented to hyper, on both sides of the proxy.
struct ProxyIo<S> {
    inner: S,
    scratch: Vec<u8>,
}

impl<S: AsyncRead + Unpin> hyper::rt::Read for ProxyIo<S> {
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

impl<S: AsyncWrite + Unpin> hyper::rt::Write for ProxyIo<S> {
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

/// A response body of one chunk with a declared length.
struct ProxyBody {
    data: Option<Bytes>,
    len: u64,
}

impl ProxyBody {
    /// A body of `bytes`, delivered in one chunk.
    fn measured(bytes: &[u8]) -> ProxyBody {
        ProxyBody {
            data: Some(Bytes::copy_from_slice(bytes)),
            len: bytes.len() as u64,
        }
    }

    fn empty() -> ProxyBody {
        ProxyBody { data: None, len: 0 }
    }
}

impl hyper::body::Body for ProxyBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.get_mut().data.take().map(|data| Ok(Frame::data(data))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.len)
    }
}

/// What the proxy saw of one request.
#[derive(Clone, Debug)]
pub struct ProxySeen {
    pub method: String,
    /// The request target as the proxy read it: the absolute form of a
    /// forwarded request, and `host:port` for a `CONNECT`.
    pub target: String,
    pub headers: HeaderMap,
}

impl ProxySeen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(HeaderName::from_bytes(name.as_bytes()).unwrap())?
            .to_str()
            .ok()
    }
}

/// How the proxy answers a `CONNECT`.
#[derive(Clone, Copy)]
pub enum Tunnel {
    /// Open a connection to the target and carry the bytes both ways.
    Open,
    /// Answer with this status and tunnel nothing.
    Refuse(u16),
    /// Answer the first `CONNECT` with this status, and open every later one.
    RefuseFirst(u16),
}

/// An in-process HTTP/1.1 proxy.
///
/// A forwarded request is sent on to the origin the absolute-form target names,
/// and a `CONNECT` is answered by splicing a connection to the target. Every
/// request line and every header is recorded, so a test states what reached the
/// proxy and what reached the origin.
///
/// The headers of a forwarded request are sent on as the client wrote them, the
/// hop-by-hop ones excepted: `Proxy-Authorization` names the proxy and travels
/// no further, which is what a proxy does with it.
pub struct TestProxy {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<ProxySeen>>>,
    connections: Arc<AtomicUsize>,
}

impl TestProxy {
    pub async fn start(tunnel: Tunnel) -> TestProxy {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<ProxySeen>>> = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let task_seen = seen.clone();
        let task_connections = connections.clone();
        drop(spawn(async move {
            while let Ok((stream, _peer)) = listener.accept().await {
                task_connections.fetch_add(1, Ordering::SeqCst);
                let seen = task_seen.clone();
                drop(spawn(async move {
                    let io = ProxyIo {
                        inner: stream,
                        scratch: Vec::new(),
                    };
                    let service = service_fn(move |request| {
                        let seen = seen.clone();
                        proxied(request, tunnel, seen)
                    });
                    // The upgrades are what carries a `CONNECT`: the tunneled
                    // socket comes back through one.
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await;
                }));
            }
        }));
        TestProxy {
            addr,
            seen,
            connections,
        }
    }

    /// The URL a fetcher names this proxy by.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }

    /// The URL with `userinfo` in it, which the proxy is sent as a credential.
    pub fn url_with(&self, userinfo: &str) -> String {
        format!("http://{userinfo}@127.0.0.1:{}", self.addr.port())
    }

    pub fn seen(&self) -> Vec<ProxySeen> {
        self.seen.lock().unwrap().clone()
    }

    pub fn requests(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

/// Serve one request the proxy received.
async fn proxied(
    mut request: Request<hyper::body::Incoming>,
    tunnel: Tunnel,
    seen: Arc<Mutex<Vec<ProxySeen>>>,
) -> Result<Response<ProxyBody>, Infallible> {
    seen.lock().unwrap().push(ProxySeen {
        method: request.method().to_string(),
        target: request.uri().to_string(),
        headers: request.headers().clone(),
    });
    if request.method() == hyper::Method::CONNECT {
        let connects = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|seen| seen.method == "CONNECT")
            .count();
        let tunnel = match tunnel {
            Tunnel::RefuseFirst(status) if connects == 1 => Tunnel::Refuse(status),
            Tunnel::RefuseFirst(_) => Tunnel::Open,
            other => other,
        };
        let status = match tunnel {
            Tunnel::Refuse(status) => status,
            Tunnel::RefuseFirst(_) => unreachable!("resolved above"),
            Tunnel::Open => {
                let target = request.uri().authority().unwrap().clone();
                let upgrade = hyper::upgrade::on(&mut request);
                // The splice runs once the 200 below has reached the client,
                // which is when the upgrade is delivered.
                drop(spawn(splice(upgrade, target)));
                200
            }
        };
        return Ok(Response::builder()
            .status(status)
            .body(ProxyBody::empty())
            .unwrap());
    }
    Ok(forwarded(request).await)
}

/// Carry the bytes of one tunnel both ways.
async fn splice(upgrade: hyper::upgrade::OnUpgrade, target: hyper::http::uri::Authority) {
    let port = target.port_u16().unwrap_or(80);
    let host = target.host().trim_start_matches('[').trim_end_matches(']');
    let Ok(target) = TcpStream::connect(host, port).await else {
        return;
    };
    let Ok(upgraded) = upgrade.await else {
        return;
    };
    let Ok(parts) = upgraded.downcast::<ProxyIo<TcpStream>>() else {
        return;
    };
    let (client_reader, mut client_writer) = futures_lite::io::split(parts.io.inner);
    let (target_reader, mut target_writer) = futures_lite::io::split(target);
    // Whatever arrived behind the request head belongs to the tunnel.
    if !parts.read_buf.is_empty() && target_writer.write_all(&parts.read_buf).await.is_err() {
        return;
    }
    let mut client_reader = client_reader;
    let mut target_reader = target_reader;
    // The first direction to end ends the tunnel, and dropping the other half
    // closes what is left of it.
    or(
        async {
            let _ = futures_lite::io::copy(&mut client_reader, &mut target_writer).await;
        },
        async {
            let _ = futures_lite::io::copy(&mut target_reader, &mut client_writer).await;
        },
    )
    .await;
}

/// Send one absolute-form request on to the origin it names and answer with
/// what came back. The request body streams on to the origin as it arrives.
async fn forwarded(request: Request<Incoming>) -> Response<ProxyBody> {
    let refused = || {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(ProxyBody::empty())
            .unwrap()
    };
    let Some(authority) = request.uri().authority().cloned() else {
        return refused();
    };
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let Ok(stream) = TcpStream::connect(host, authority.port_u16().unwrap_or(80)).await else {
        return refused();
    };
    let io = ProxyIo {
        inner: stream,
        scratch: Vec::new(),
    };
    let Ok((mut sender, connection)) = hyper::client::conn::http1::handshake(io).await else {
        return refused();
    };
    drop(spawn(async move {
        let _ = connection.await;
    }));
    let target = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str())
        .to_owned();
    let (parts, body) = request.into_parts();
    let mut upstream = Request::builder()
        .method(parts.method)
        .uri(&target)
        .body(body)
        .unwrap();
    for (name, value) in &parts.headers {
        // A hop-by-hop header names this proxy and travels no further, and the
        // framing headers belong to the connection the body travels over.
        if name == hyper::header::PROXY_AUTHORIZATION
            || name == "proxy-connection"
            || name == hyper::header::CONTENT_LENGTH
            || name == hyper::header::TRANSFER_ENCODING
        {
            continue;
        }
        upstream.headers_mut().append(name.clone(), value.clone());
    }
    let Ok(response) = sender.send_request(upstream).await else {
        return refused();
    };
    let status = response.status();
    let headers = response.headers().clone();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(Ok(frame)) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
    {
        if let Ok(data) = frame.into_data() {
            bytes.extend_from_slice(&data);
        }
    }
    let mut answer = Response::builder()
        .status(status)
        .body(ProxyBody::measured(&bytes))
        .unwrap();
    for (name, value) in &headers {
        // The framing headers belong to the connection this answer travels
        // over, and the body is re-measured here. Every other header is what
        // the origin said, a `Location` a redirect names among them.
        if name == hyper::header::CONTENT_LENGTH || name == hyper::header::TRANSFER_ENCODING {
            continue;
        }
        answer.headers_mut().append(name.clone(), value.clone());
    }
    answer
}
