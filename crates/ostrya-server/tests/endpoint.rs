//! Tests of the receive endpoint mounted in the router of a host.
//!
//! The client is `push_tree`. It pushes a tree over HTTPS and HTTP/2 to a
//! path prefix, and the host removes the prefix. The tests cover these parts
//! of the mount:
//!
//! - the authentication of the host and the HTTP/2 windows of the endpoint
//! - the stop of the endpoint with `shutdown`
//! - the hooks of the host: an entry of the host in the detached metadata, a
//!   per-name lock in the carried value, an error of `after_update`, and a
//!   ref that moves during `before_update`
//!
//! A compile-time check pins the auto traits of the public types.

use std::any::Any;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::fs::File;
use std::future::Future;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
use hyper::{Request, Response, StatusCode};
use ostrya::push::proto::Hello;
use ostrya::push::{
    self, ConnectOptions, ParentPolicy, PushRemote, RefUpdate, TreePushOptions, push_tree,
};
use ostrya::{
    Checksum, CreateOptions, HookFuture, HookRefusal, HostEntry, ReceiveHooks, ReceivePolicy,
    ReceiveReport, Repo, RepoMode, Type, UpdatePlan, Value,
};
use ostrya_fetch::{FetcherOptions, FuturesIo, Proxy, RtExecutor, RtTimer};
use ostrya_rt::{self as rt, Timer, block_on};
use ostrya_server::{
    EndpointOptions, ReceiveAuth, ReceiveBody, ReceiveEndpoint, Refusal, RequestKind, SessionSetup,
};

const CA_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/ca.pem");
const SERVER_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.pem");
const SERVER_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.key.pem");

/// The path prefix that the host mounts the endpoint under.
const MOUNT: &str = "/api/v1/push";

/// The bearer token that the host takes.
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
            hooks: None,
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
    /// The raw path and the response status of each request, in the order
    /// of the responses.
    statuses: Mutex<Vec<(String, StatusCode)>>,
}

impl Seen {
    /// Returns the status of each `commit` request, in the order of the
    /// responses.
    fn commit_statuses(&self) -> Vec<StatusCode> {
        let statuses = self.statuses.lock().unwrap();
        statuses
            .iter()
            .filter(|(path, _)| path.ends_with("/commit"))
            .map(|(_, status)| *status)
            .collect()
    }
}

/// Accepts connections on `listener` and serves each in a task of its own.
async fn host<A: ReceiveAuth>(
    listener: rt::TcpListener,
    config: Arc<ServerConfig>,
    endpoint: Arc<ReceiveEndpoint<A>>,
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

/// Serves one TLS connection over HTTP/2 with the windows of the endpoint
/// and at most 32 streams at the same time.
async fn connection<A: ReceiveAuth>(
    stream: rt::TcpStream,
    config: Arc<ServerConfig>,
    endpoint: Arc<ReceiveEndpoint<A>>,
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
/// the path, calls the endpoint, and records the status of the response. A
/// path outside the mount goes to the endpoint as it is, and gets 404.
async fn mounted<A: ReceiveAuth>(
    endpoint: &ReceiveEndpoint<A>,
    seen: &Seen,
    mut req: Request<Incoming>,
) -> Response<ReceiveBody> {
    let path = req.uri().path().to_owned();
    seen.requests.lock().unwrap().push(path.clone());
    if let Some(rest) = path.strip_prefix(MOUNT).filter(|r| r.starts_with('/')) {
        *req.uri_mut() = rest.parse().expect("a path is a URI");
    }
    let response = endpoint.handle(req).await;
    seen.statuses
        .lock()
        .unwrap()
        .push((path, response.status()));
    response
}

/// A tree of small files and one file of 3 MiB of pseudo-random bytes. One
/// object stream then carries more than the 2 MiB window of a stream. The
/// function writes the big file in 48 chunks of 64 KiB.
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
/// the `session` request, and for the pushes of the hooks test.
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

/// Waits until `done` returns `true`, for at most 10 seconds.
///
/// After 10 seconds, it panics with the message `what`.
async fn eventually(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        Timer::after(Duration::from_millis(10)).await;
    }
}

/// A push of a tree with `push_tree` to `https://HOST/api/v1/push` goes
/// through the host route over HTTP/2 with the windows of the endpoint. The
/// push sets the ref. A push with a wrong token gets `unauthorized`. After
/// `shutdown`, the sweep ends, and a push gets `limit-exceeded`.
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

/// The locks of the host, one for each ref name.
#[derive(Default)]
struct NameLocks {
    held: Mutex<BTreeSet<String>>,
}

impl NameLocks {
    /// Takes the locks of all `names`, or of none if one of them is held.
    fn try_lock(self: &Arc<Self>, mut names: Vec<String>) -> Option<NameGuard> {
        names.sort();
        names.dedup();
        let mut held = self.held.lock().unwrap();
        if names.iter().any(|name| held.contains(name)) {
            return None;
        }
        held.extend(names.iter().cloned());
        Some(NameGuard {
            locks: self.clone(),
            names,
        })
    }

    /// Returns the names that are held, in sorted order.
    fn held(&self) -> Vec<String> {
        self.held.lock().unwrap().iter().cloned().collect()
    }
}

/// The locks of some names. The drop of the guard releases them.
struct NameGuard {
    locks: Arc<NameLocks>,
    names: Vec<String>,
}

impl Drop for NameGuard {
    fn drop(&mut self) {
        let mut held = self.locks.held.lock().unwrap();
        for name in &self.names {
            held.remove(name);
        }
    }
}

/// The state that the hooks of all sessions share with the test.
#[derive(Default)]
struct HostState {
    /// If `true`, `after_update` returns an error.
    fail_after: AtomicBool,
    /// A ref that the next `before_update` sets, to move a ref after the
    /// checks of the session and before the update lock.
    move_ref: Mutex<Option<(String, Checksum)>>,
    before_calls: AtomicUsize,
    after_calls: AtomicUsize,
    /// The held names that each `after_update` saw before it dropped the
    /// carried value.
    held_in_after: Mutex<Vec<Vec<String>>>,
}

/// The text of the error of `after_update`.
const AFTER_FAILED: &str = "the host failed after the update";

/// The hooks of the host for one session of `uploader`. `before_update`
/// first sets the ref of [`HostState::move_ref`], if one is given. Then it
/// locks the names of the refs. It gives a `centrex.uploader` entry with
/// `keep_existing` set to `true` for each new commit. `after_update` releases
/// the locks.
struct HostHooks {
    uploader: String,
    repo: Repo,
    locks: Arc<NameLocks>,
    state: Arc<HostState>,
}

impl ReceiveHooks for HostHooks {
    fn before_update<'a>(
        &'a self,
        updates: &'a [RefUpdate],
    ) -> HookFuture<'a, Result<UpdatePlan, HookRefusal>> {
        Box::pin(async move {
            self.state.before_calls.fetch_add(1, Ordering::SeqCst);
            let moved = self.state.move_ref.lock().unwrap().take();
            if let Some((name, commit)) = moved {
                self.repo
                    .set_ref_immediate(&name, Some(&commit))
                    .await
                    .map_err(|e| HookRefusal::internal(e.to_string()))?;
            }
            let names = updates.iter().map(|u| u.name.clone()).collect();
            let Some(guard) = self.locks.try_lock(names) else {
                return Err(HookRefusal::internal("a ref of the push is locked"));
            };
            let commits: BTreeSet<Checksum> = updates.iter().filter_map(|u| u.new).collect();
            let entry = HostEntry {
                key: "centrex.uploader".into(),
                value: Value::variant(Type::Str, Value::Str(self.uploader.clone())),
                keep_existing: true,
            };
            Ok(UpdatePlan {
                metadata: commits
                    .into_iter()
                    .map(|commit| (commit, vec![entry.clone()]))
                    .collect(),
                carried: Box::new(guard),
            })
        })
    }

    fn after_update<'a>(
        &'a self,
        _report: &'a ReceiveReport,
        carried: Box<dyn Any + Send>,
    ) -> HookFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.state.after_calls.fetch_add(1, Ordering::SeqCst);
            let guard = carried
                .downcast::<NameGuard>()
                .map_err(|_| "the carried value is not a NameGuard".to_owned())?;
            self.state
                .held_in_after
                .lock()
                .unwrap()
                .push(self.locks.held());
            drop(guard);
            if self.state.fail_after.load(Ordering::SeqCst) {
                return Err(AFTER_FAILED.into());
            }
            Ok(())
        })
    }
}

/// The authentication of a host with hooks: a bearer token of `alice` or of
/// `bob`. Each session gets the default policy and the hooks of its
/// principal.
struct HookAuth {
    repo: Repo,
    locks: Arc<NameLocks>,
    state: Arc<HostState>,
}

impl ReceiveAuth for HookAuth {
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
            Some("alice-token") => Ok("alice".to_owned()),
            Some("bob-token") => Ok("bob".to_owned()),
            _ => Err(Refusal::unauthorized(
                "the host takes the tokens of its users alone",
            )),
        }
    }

    async fn open(&self, principal: &String, _hello: &Hello) -> Result<SessionSetup, Refusal> {
        let hooks = HostHooks {
            uploader: principal.clone(),
            repo: self.repo.clone(),
            locks: self.locks.clone(),
            state: self.state.clone(),
        };
        Ok(SessionSetup {
            policy: Arc::new(ReceivePolicy::default()),
            hooks: Some(Arc::new(hooks)),
        })
    }
}

/// Returns the string under `centrex.uploader` in the detached metadata of
/// `commit`.
async fn uploader(repo: &Repo, commit: &Checksum) -> Option<String> {
    let dict = repo.read_commit_detached_metadata(commit).await.unwrap()?;
    dict.dict_get("centrex.uploader")
        .and_then(Value::as_variant)
        .and_then(|(_, value)| value.as_str().map(str::to_owned))
}

/// The hooks that `ReceiveAuth::open` gives run in the commit of a push
/// through a mounted endpoint. Every push sends the same tree with no
/// parent, no bindings, and one timestamp, so all the pushes give the same
/// commit.
///
/// The entry of the first uploader stays at the second push. An error of
/// `after_update` gets 500 with the ref written and no report. A ref that
/// `before_update` moves gets 409 with `ref-mismatch`. The locks of the host
/// are held in `after_update`, and free after each push.
#[test]
fn the_hooks_of_the_host_run_in_a_push_through_a_mounted_endpoint() {
    let tmp = TmpDir::new("hooks");
    let small = small_tree(tmp.path());
    let receiver = block_on(Repo::create(
        &tmp.path().join("receiver"),
        CreateOptions::new(RepoMode::Archive),
    ))
    .unwrap();
    let ca = tmp.path().join("ca.pem");
    std::fs::write(&ca, CA_PEM).unwrap();
    let alice = tmp.path().join("alice-token");
    std::fs::write(&alice, b"alice-token\n").unwrap();
    let bob = tmp.path().join("bob-token");
    std::fs::write(&bob, b"bob-token\n").unwrap();

    let reports = Arc::new(AtomicUsize::new(0));
    let counter = reports.clone();
    let options = EndpointOptions {
        on_report: Some(Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        })),
        ..EndpointOptions::default()
    };
    let locks = Arc::new(NameLocks::default());
    let state = Arc::new(HostState::default());
    let auth = HookAuth {
        repo: receiver.clone(),
        locks: locks.clone(),
        state: state.clone(),
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
    let push_options = |name: &str| TreePushOptions {
        refs: vec![name.into()],
        parent: ParentPolicy::None,
        timestamp: Some(1_700_000_000),
        no_bindings: true,
        ..TreePushOptions::default()
    };
    let before_calls = || state.before_calls.load(Ordering::SeqCst);
    let after_calls = || state.after_calls.load(Ordering::SeqCst);

    block_on(async {
        let config = ostrya_fetch::server_config(SERVER_CERT_PEM, SERVER_KEY_PEM, None, None)
            .await
            .unwrap();
        let listener = rt::TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let remote = PushRemote::parse(&format!("https://127.0.0.1:{port}{MOUNT}")).unwrap();
        let serving = host(listener, config, endpoint.clone(), seen.clone());
        future::or(
            async {
                serving.await;
                unreachable!("the host serves until the test ends");
            },
            async {
                let resolve = |name: &'static str| receiver.resolve_rev(name, false);

                // The first push writes the entry of its uploader.
                let outcome = push_tree(&remote, &small, connect(&alice), push_options("rel/a"))
                    .await
                    .unwrap();
                let commit = outcome.commit.expect("a tree push builds a commit");
                assert_eq!(resolve("rel/a").await.unwrap(), Some(commit));
                assert_eq!(uploader(&receiver, &commit).await.as_deref(), Some("alice"));
                assert_eq!((before_calls(), after_calls()), (1, 1));
                assert_eq!(
                    *state.held_in_after.lock().unwrap(),
                    vec![vec!["rel/a".to_owned()]]
                );
                assert_eq!(seen.commit_statuses(), [StatusCode::OK]);
                assert!(locks.held().is_empty());
                eventually("the first report", || reports.load(Ordering::SeqCst) == 1).await;

                // The second push of the commit keeps the first entry.
                let outcome = push_tree(&remote, &small, connect(&bob), push_options("rel/b"))
                    .await
                    .unwrap();
                assert_eq!(outcome.commit, Some(commit));
                assert_eq!(resolve("rel/b").await.unwrap(), Some(commit));
                assert_eq!(uploader(&receiver, &commit).await.as_deref(), Some("alice"));
                assert_eq!((before_calls(), after_calls()), (2, 2));
                assert_eq!(seen.commit_statuses(), [StatusCode::OK; 2]);
                assert!(locks.held().is_empty());
                eventually("the second report", || reports.load(Ordering::SeqCst) == 2).await;

                // An error of `after_update` comes after the write of the ref.
                state.fail_after.store(true, Ordering::SeqCst);
                let failed = push_tree(&remote, &small, connect(&bob), push_options("rel/c")).await;
                match &failed {
                    Err(push::Error::Internal(message)) => {
                        assert!(message.contains(AFTER_FAILED), "{message}");
                    }
                    other => panic!("{other:?}"),
                }
                assert_eq!(
                    seen.commit_statuses().last(),
                    Some(&StatusCode::INTERNAL_SERVER_ERROR)
                );
                assert_eq!(resolve("rel/c").await.unwrap(), Some(commit));
                assert_eq!((before_calls(), after_calls()), (3, 3));
                assert!(locks.held().is_empty());
                assert_eq!(reports.load(Ordering::SeqCst), 2);

                // A ref that moves after the checks of the session and before
                // the update lock fails the check under the lock.
                state.fail_after.store(false, Ordering::SeqCst);
                *state.move_ref.lock().unwrap() = Some(("rel/d".into(), commit));
                let moved =
                    push_tree(&remote, &small, connect(&alice), push_options("rel/d")).await;
                match &moved {
                    Err(push::Error::RefMismatch { name, current, .. }) => {
                        assert_eq!(name, "rel/d");
                        assert_eq!(*current, Some(commit));
                    }
                    other => panic!("{other:?}"),
                }
                assert_eq!(seen.commit_statuses().last(), Some(&StatusCode::CONFLICT));
                assert_eq!(resolve("rel/d").await.unwrap(), Some(commit));
                assert_eq!((before_calls(), after_calls()), (4, 3));
                assert!(locks.held().is_empty());
                assert_eq!(reports.load(Ordering::SeqCst), 2);
                assert_eq!(state.held_in_after.lock().unwrap().len(), 3);
            },
        )
        .await;
    });
    assert_eq!(reports.load(Ordering::SeqCst), 2);
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

/// The endpoint is `Send + Sync` for every authentication. The futures of
/// `handle` and `sweep` are `Send`, also with a request body that is not
/// `Sync`. The response body is `Send + Unpin + 'static`.
///
/// `NotSync` is `Send` and `Unpin`, and not `Sync`. For a type that is
/// `Sync`, the last check is ambiguous and does not compile. The compiler
/// checks each generic function for every `A`.
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
