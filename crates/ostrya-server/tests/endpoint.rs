//! The receive endpoint mounted in the router of a host: a push of a tree
//! over HTTPS and HTTP/2 to a path prefix that the host removes, with the
//! authentication of the host and the HTTP/2 windows of the endpoint, and
//! the stop of the endpoint. The client is `push_tree`. The assertions at
//! the end pin the auto traits of the public types.

use std::cell::Cell;
use std::convert::Infallible;
use std::fs::File;
use std::future::Future;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_lite::future;
use futures_rustls::TlsAcceptor;
use futures_rustls::rustls::ServerConfig;
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::header::AUTHORIZATION;
use hyper::http::request::Parts;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response};
use ostrya::push::proto::Hello;
use ostrya::push::{ConnectOptions, PushRemote, TreePushOptions, push_tree};
use ostrya::{CreateOptions, ReceivePolicy, Repo, RepoMode};
use ostrya_fetch::{FetcherOptions, FuturesIo, Proxy, RtExecutor, RtTimer};
use ostrya_rt::{self as rt, Timer, block_on};
use ostrya_server::{
    EndpointOptions, ReceiveAuth, ReceiveBody, ReceiveEndpoint, Refusal, RequestKind, SessionSetup,
};

const CA_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/ca.pem");
const SERVER_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.pem");
const SERVER_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.key.pem");

/// The path prefix the host mounts the endpoint under.
const MOUNT: &str = "/api/v1/push";

/// The bearer token the host takes.
const TOKEN: &str = "host-token";

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        let path = std::env::temp_dir().join(format!(
            "ostrya-server-endpoint-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TmpDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The authentication of the host: a request needs `Authorization: Bearer`
/// with [`TOKEN`]. It records the target refs of each session it opens.
struct TokenAuth {
    opened: Arc<Mutex<Vec<Vec<String>>>>,
}

impl ReceiveAuth for TokenAuth {
    type Principal = String;

    fn owner(principal: &String) -> &str {
        principal
    }

    async fn authenticate(&self, parts: &Parts, _kind: RequestKind) -> Result<String, Refusal> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        match token {
            Some(TOKEN) => Ok("pusher".to_owned()),
            _ => Err(Refusal::unauthorized("the host takes its own token alone")),
        }
    }

    async fn open(&self, _principal: &String, hello: &Hello) -> Result<SessionSetup, Refusal> {
        self.opened.lock().unwrap().push(hello.refs.clone());
        Ok(SessionSetup {
            policy: Arc::new(ReceivePolicy::default()),
        })
    }
}

/// What the host saw.
#[derive(Default)]
struct Seen {
    connections: AtomicUsize,
    /// The connections whose TLS handshake selected `h2`.
    h2_connections: AtomicUsize,
    /// The raw path of each request, before the host removes its prefix.
    requests: Mutex<Vec<String>>,
}

/// Accept connections on `listener` and serve each in a task of its own.
async fn host(
    listener: rt::TcpListener,
    config: Arc<ServerConfig>,
    endpoint: Arc<ReceiveEndpoint<TokenAuth>>,
    seen: Arc<Seen>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let connection = connection(stream, config.clone(), endpoint.clone(), seen.clone());
        drop(rt::spawn(connection));
    }
}

/// Serve one TLS connection over HTTP/2 with the windows of the endpoint
/// and at most 32 streams at the same time.
async fn connection(
    stream: rt::TcpStream,
    config: Arc<ServerConfig>,
    endpoint: Arc<ReceiveEndpoint<TokenAuth>>,
    seen: Arc<Seen>,
) {
    let Ok(tls) = TlsAcceptor::from(config).accept(stream).await else {
        return;
    };
    seen.connections.fetch_add(1, Ordering::SeqCst);
    if tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) {
        seen.h2_connections.fetch_add(1, Ordering::SeqCst);
    }
    let (stream_window, connection_window) = endpoint.h2_windows();
    let service = service_fn(move |req: Request<Incoming>| {
        let endpoint = endpoint.clone();
        let seen = seen.clone();
        async move { Ok::<_, Infallible>(mounted(&endpoint, &seen, req).await) }
    });
    let mut builder = http2::Builder::new(RtExecutor);
    builder
        .timer(RtTimer)
        .max_concurrent_streams(32)
        .initial_stream_window_size(stream_window)
        .initial_connection_window_size(connection_window);
    let _ = builder.serve_connection(FuturesIo::new(tls), service).await;
}

/// The route of the host: it records the request, removes [`MOUNT`] from
/// the path, and calls the endpoint. A path outside the mount goes to the
/// endpoint as it is, and gets 404.
async fn mounted(
    endpoint: &ReceiveEndpoint<TokenAuth>,
    seen: &Seen,
    mut req: Request<Incoming>,
) -> Response<ReceiveBody> {
    let path = req.uri().path().to_owned();
    seen.requests.lock().unwrap().push(path.clone());
    if let Some(rest) = path.strip_prefix(MOUNT).filter(|r| r.starts_with('/')) {
        *req.uri_mut() = rest.parse().expect("a path is a URI");
    }
    endpoint.handle(req).await
}

/// A tree of small files and one file of 3 MiB of pseudo-random bytes, so
/// one object stream carries more than the 2 MiB window of a stream. The
/// big file is written in chunks.
fn tree(base: &Path) -> PathBuf {
    let root = base.join("tree");
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/hostname"), b"host\n").unwrap();
    std::fs::write(root.join("README"), b"a tree of the endpoint test\n").unwrap();
    let mut big = File::create(root.join("big.bin")).unwrap();
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    let mut chunk = vec![0u8; 64 * 1024];
    for _ in 0..48 {
        for byte in chunk.iter_mut() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (state >> 56) as u8;
        }
        big.write_all(&chunk).unwrap();
    }
    root
}

/// A tree of one small file, for the pushes that the endpoint refuses at
/// the `session` request.
fn small_tree(base: &Path) -> PathBuf {
    let root = base.join("small");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("README"),
        b"a small tree of the endpoint test
",
    )
    .unwrap();
    root
}

/// Wait until `done` holds, for at most 10 seconds.
async fn eventually(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        Timer::after(Duration::from_millis(10)).await;
    }
}

/// A push of a tree with `push_tree` to `https://HOST/api/v1/push` goes
/// through the host route over HTTP/2, with the windows of the endpoint,
/// and sets the ref. A wrong token is `unauthorized`. After `shutdown` the
/// sweep ends, and a push gets `limit-exceeded`.
#[test]
fn a_push_through_a_mounted_endpoint_commits_over_http2() {
    let tmp = TmpDir::new("push");
    let root = tree(tmp.path());
    let small = small_tree(tmp.path());
    let receiver = block_on(Repo::create(
        &tmp.path().join("receiver"),
        CreateOptions::new(RepoMode::Archive),
    ))
    .unwrap();
    let ca = tmp.path().join("ca.pem");
    std::fs::write(&ca, CA_PEM).unwrap();
    let token = tmp.path().join("token");
    std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
    let wrong = tmp.path().join("wrong-token");
    std::fs::write(&wrong, b"other-token\n").unwrap();

    let reports = Arc::new(AtomicUsize::new(0));
    let counter = reports.clone();
    let options = EndpointOptions {
        on_report: Some(Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        })),
        ..EndpointOptions::default()
    };
    let opened = Arc::new(Mutex::new(Vec::new()));
    let auth = TokenAuth {
        opened: opened.clone(),
    };
    let endpoint = Arc::new(ReceiveEndpoint::new(receiver.clone(), auth, options).unwrap());
    let seen = Arc::new(Seen::default());

    let connect = |token: &Path| ConnectOptions {
        tls_ca_path: Some(ca.clone()),
        push_token_file: Some(token.to_owned()),
        http: FetcherOptions {
            proxy: Proxy::None,
            ..FetcherOptions::default()
        },
        ..ConnectOptions::default()
    };
    let push_options = || TreePushOptions {
        refs: vec!["main".into()],
        timestamp: Some(1_700_000_000),
        ..TreePushOptions::default()
    };

    block_on(async {
        let config = ostrya_fetch::server_config(SERVER_CERT_PEM, SERVER_KEY_PEM, None, None)
            .await
            .unwrap();
        let listener = rt::TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let sweep = rt::spawn({
            let endpoint = endpoint.clone();
            async move { endpoint.sweep().await }
        });
        let remote = PushRemote::parse(&format!("https://127.0.0.1:{port}{MOUNT}")).unwrap();
        let serving = host(listener, config, endpoint.clone(), seen.clone());
        future::or(
            async {
                serving.await;
                unreachable!("the host serves until the test ends");
            },
            async {
                let outcome = push_tree(&remote, &root, connect(&token), push_options())
                    .await
                    .unwrap();
                let commit = outcome.commit.expect("a tree push builds a commit");
                assert_eq!(outcome.refs.len(), 1);
                assert_eq!(outcome.refs[0].new, Some(commit));
                assert_eq!(
                    receiver.resolve_rev("main", false).await.unwrap(),
                    Some(commit)
                );
                eventually("the report", || reports.load(Ordering::SeqCst) == 1).await;

                {
                    let requests = seen.requests.lock().unwrap();
                    assert!(requests.len() >= 4, "{requests:?}");
                    let prefix = format!("{MOUNT}/_ostrya/receive/v1/");
                    for path in requests.iter() {
                        assert!(path.starts_with(&prefix), "{path}");
                    }
                }
                let connections = seen.connections.load(Ordering::SeqCst);
                assert!(connections >= 1);
                assert_eq!(seen.h2_connections.load(Ordering::SeqCst), connections);
                assert_eq!(*opened.lock().unwrap(), vec![vec!["main".to_owned()]]);

                let refused = push_tree(&remote, &small, connect(&wrong), push_options()).await;
                assert!(
                    matches!(refused, Err(ostrya::push::Error::Unauthorized(_))),
                    "{refused:?}"
                );

                endpoint.shutdown();
                let ended = future::or(
                    async {
                        sweep.await;
                        true
                    },
                    async {
                        Timer::after(Duration::from_secs(10)).await;
                        false
                    },
                )
                .await;
                assert!(ended, "the sweep ends after shutdown");
                let stopped = push_tree(&remote, &small, connect(&token), push_options()).await;
                assert!(
                    matches!(stopped, Err(ostrya::push::Error::LimitExceeded(_))),
                    "{stopped:?}"
                );
            },
        )
        .await;
    });
    assert_eq!(reports.load(Ordering::SeqCst), 1);
}

/// A request body with the shape of the body of a router: `Send` and
/// `Unpin`, and not `Sync`.
struct NotSync {
    _not_sync: PhantomData<Cell<()>>,
}

impl Body for NotSync {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        Poll::Ready(None)
    }
}

/// The endpoint is `Send + Sync` for every authentication, and the futures
/// of `handle` and `sweep` are `Send`, also with a request body that is not
/// `Sync`. The response body is `Send + Unpin + 'static`. `NotSync` is
/// `Send` and `Unpin`, and not `Sync`: the last check is ambiguous, and does
/// not compile, for a type that is `Sync`. Each generic function is checked
/// for every `A`.
const _: fn() = || {
    fn send_sync<T: Send + Sync>() {}
    fn endpoint_is_send_sync<A: ReceiveAuth>() {
        send_sync::<ReceiveEndpoint<A>>();
    }
    fn handle_is_send<A: ReceiveAuth>(
        endpoint: &ReceiveEndpoint<A>,
        req: Request<NotSync>,
    ) -> impl Future<Output = Response<ReceiveBody>> + Send {
        endpoint.handle(req)
    }
    fn sweep_is_send<A: ReceiveAuth>(
        endpoint: &ReceiveEndpoint<A>,
    ) -> impl Future<Output = ()> + Send {
        endpoint.sweep()
    }
    fn response_body<T: Body<Data = Bytes, Error = io::Error> + Send + Unpin + 'static>() {}
    let _ = endpoint_is_send_sync::<TokenAuth>;
    let _ = handle_is_send::<TokenAuth>;
    let _ = sweep_is_send::<TokenAuth>;
    response_body::<ReceiveBody>();

    fn send_unpin<T: Send + Unpin>() {}
    send_unpin::<NotSync>();
    trait NotSyncCheck<A> {
        fn check() {}
    }
    impl<T: ?Sized> NotSyncCheck<()> for T {}
    struct IsSync;
    impl<T: ?Sized + Sync> NotSyncCheck<IsSync> for T {}
    <NotSync as NotSyncCheck<_>>::check();
};
