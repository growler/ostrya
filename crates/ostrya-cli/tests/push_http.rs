//! The HTTP transport of a push against `ostrya_server` in this process:
//! each authentication method over HTTPS, a credential over plain HTTP, the
//! tree push and its repeat, the push of a repository, the object streams
//! of a session through a proxy that counts them, a commit whose response is
//! lost or refused, a source that fails, and an object whose bytes do not
//! hash to its name. The module `cli` runs `ostrya push` and `ostrya
//! push-tree` against `ostrya serve`, and checks the receiving repository
//! with the `ostree` tool.

#![cfg(all(feature = "serve", feature = "push"))]

use std::future::Future;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use ostrya::fetch::Proxy;
use ostrya::push::tree::{ScanOptions, TreeModel};
use ostrya::push::{
    BoxFuture, Compression, ConnectOptions, Encoding, Error, ObjectData, ObjectSource, PushOutcome,
    PushRemote, PushSession, SessionOptions, TreePushOptions, push_tree,
};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree,
    ObjectName, ObjectType, ReceivePolicy, Repo, RepoMode, RepoPushOptions, Value,
};
use ostrya_rt::block_on;
use ostrya_server::{ServeOptions, ServerTls};

const ALICE: &str = "alice-token";
const BOB: &str = "bob-token";

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ostrya-push-http-{}-{tag}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TmpDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/tls")
        .join(name)
}

fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).unwrap()
}

// ---------------------------------------------------------------------------
// Trees and repositories.
// ---------------------------------------------------------------------------

/// A tree under `base/name` of `files` files of `size` bytes each, in two
/// directories. The bytes come from a fixed generator, so no two files are
/// equal and no file compresses.
fn tree(base: &Path, name: &str, files: usize, size: usize) -> PathBuf {
    let root = base.join(name);
    std::fs::create_dir_all(root.join("a")).unwrap();
    std::fs::create_dir_all(root.join("b")).unwrap();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for i in 0..files {
        let mut bytes = Vec::with_capacity(size);
        while bytes.len() < size {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.extend_from_slice(&state.to_le_bytes());
        }
        bytes.truncate(size);
        let dir = if i % 2 == 0 { "a" } else { "b" };
        std::fs::write(root.join(dir).join(format!("file-{i}")), bytes).unwrap();
    }
    root
}

/// A new `archive` repository at `base/name`.
fn repo(base: &Path, name: &str) -> Repo {
    block_on(Repo::create(
        &base.join(name),
        CreateOptions::new(RepoMode::Archive),
    ))
    .unwrap()
}

async fn tip(repo: &Repo, name: &str) -> Option<Checksum> {
    repo.resolve_rev(name, true).await.unwrap()
}

/// The staging directories left under `tmp/` of `repo`.
fn staging_entries(repo: &Repo) -> Vec<String> {
    std::fs::read_dir(repo.path().join("tmp"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("staging-"))
        .collect()
}

/// Wait until `done` holds, and fail the test after 30 seconds.
async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "{what} did not happen");
        ostrya_rt::Timer::after(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Futures.
// ---------------------------------------------------------------------------

/// Run `a` and `b` together, and give the output of the first that ends.
async fn race<T>(a: impl Future<Output = T>, b: impl Future<Output = T>) -> T {
    let mut a = pin!(a);
    let mut b = pin!(b);
    std::future::poll_fn(|cx| match a.as_mut().poll(cx) {
        Poll::Ready(v) => Poll::Ready(v),
        Poll::Pending => b.as_mut().poll(cx),
    })
    .await
}

/// Run `a` and `b` together, and give both outputs.
async fn both<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let mut a = pin!(a);
    let mut b = pin!(b);
    let (mut from_a, mut from_b) = (None, None);
    std::future::poll_fn(|cx| {
        if from_a.is_none()
            && let Poll::Ready(v) = a.as_mut().poll(cx)
        {
            from_a = Some(v);
        }
        if from_b.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            from_b = Some(v);
        }
        match (from_a.take(), from_b.take()) {
            (Some(x), Some(y)) => Poll::Ready((x, y)),
            (x, y) => {
                from_a = x;
                from_b = y;
                Poll::Pending
            }
        }
    })
    .await
}

// ---------------------------------------------------------------------------
// The server and the client.
// ---------------------------------------------------------------------------

/// The options of a plain HTTP server on a port the kernel chooses, with the
/// default receive policy and anonymous push.
fn serve_options() -> ServeOptions {
    let mut opts = ServeOptions::default();
    opts.listen = vec!["127.0.0.1:0".parse().unwrap()];
    opts.receive = Some(Arc::new(ReceivePolicy::default()));
    opts.allow_anonymous_push = true;
    opts
}

/// The server TLS files of the fixtures, with the fixture CA as the client
/// CA.
fn server_tls() -> ServerTls {
    ServerTls {
        cert_chain_pem: read_fixture("server.pem"),
        key_pem: read_fixture("server.key.pem"),
        key_passphrase: None,
        client_ca_pem: Some(read_fixture("ca.pem")),
    }
}

/// A credential file with the lines of `alice` and `bob`.
fn credentials() -> Vec<u8> {
    let digest = |token: &str| Checksum::sha256(token.as_bytes()).to_hex();
    format!("alice:{}\nbob:{}\n", digest(ALICE), digest(BOB)).into_bytes()
}

/// Run `test` with the address of a server over `repo`, then drop the
/// server.
fn with_server<F, Fut>(repo: Repo, opts: ServeOptions, test: F)
where
    F: FnOnce(SocketAddr) -> Fut,
    Fut: Future<Output = ()>,
{
    block_on(async {
        let server = ostrya_server::bind(repo, opts).await.unwrap();
        let addr = server.local_addrs()[0];
        race(
            async {
                server.run().await.unwrap();
                unreachable!("the server runs until it is dropped");
            },
            test(addr),
        )
        .await
    });
}

/// Connect options that reach the server directly, whatever proxy the
/// environment names.
fn direct() -> ConnectOptions {
    let mut connect = ConnectOptions::default();
    connect.http.proxy = Proxy::None;
    connect
}

fn remote(url: &str) -> PushRemote {
    PushRemote::parse(url).unwrap()
}

fn tree_options(refs: &[&str], timestamp: u64) -> TreePushOptions {
    TreePushOptions {
        refs: refs.iter().map(|s| s.to_string()).collect(),
        timestamp: Some(timestamp),
        ..Default::default()
    }
}

async fn push(
    url: &str,
    root: &Path,
    connect: ConnectOptions,
    refs: &[&str],
) -> ostrya::push::Result<PushOutcome> {
    push_tree(
        &remote(url),
        root,
        connect,
        tree_options(refs, 1_700_000_000),
    )
    .await
}

/// The commit of `outcome`, which set the ref `name` of `server`.
async fn assert_pushed(server: &Repo, name: &str, outcome: &PushOutcome) {
    let commit = outcome.commit.unwrap();
    assert_eq!(outcome.refs.len(), 1);
    assert_eq!(outcome.refs[0].name, name);
    assert_eq!(outcome.refs[0].new, Some(commit));
    assert_eq!(tip(server, name).await, Some(commit));
}

// ---------------------------------------------------------------------------
// A proxy that counts the requests in flight.
// ---------------------------------------------------------------------------

const OTHER: u8 = 0;
const OBJECTS: u8 = 1;
const COMMIT: u8 = 2;

/// What the proxy does to the response to a `commit` request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CommitResponse {
    /// It forwards the response.
    Forward,
    /// It closes the connection to the client at the start of the response.
    Drop,
    /// It adds `Content-Encoding: gzip` to the head of the response, which
    /// the client refuses after it sent the request.
    Gzip,
}

/// What the proxy saw.
#[derive(Default)]
struct Seen {
    connections: AtomicUsize,
    requests: AtomicUsize,
    /// The `objects` requests whose response has not started.
    objects_in_flight: AtomicUsize,
    /// The most `objects` requests in flight at one time.
    max_objects: AtomicUsize,
    objects: AtomicUsize,
    commits: AtomicUsize,
    /// The body of each response to an `objects` request.
    objects_responses: Mutex<Vec<Vec<u8>>>,
}

/// A plain TCP proxy to a server that reads the HTTP/1.1 messages on each
/// connection, so it counts each request also when the client sends several
/// requests over one connection.
struct CountingProxy {
    url: String,
    seen: Arc<Seen>,
}

impl CountingProxy {
    fn start(target: SocketAddr, commit: CommitResponse) -> CountingProxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let seen = Arc::new(Seen::default());
        let shared = Arc::clone(&seen);
        std::thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else { return };
                let Ok(server) = TcpStream::connect(target) else {
                    return;
                };
                shared.connections.fetch_add(1, Ordering::SeqCst);
                let seen = Arc::clone(&shared);
                std::thread::spawn(move || relay(client, server, seen, commit));
            }
        });
        CountingProxy { url, seen }
    }

    fn max_objects(&self) -> usize {
        self.seen.max_objects.load(Ordering::SeqCst)
    }
}

/// Read the head of one HTTP/1.1 message: the lines up to the empty line.
/// `None` at the end of the stream.
fn read_head(input: &mut BufReader<TcpStream>) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    loop {
        let start = head.len();
        match input.read_until(b'\n', &mut head) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        if &head[start..] == b"\r\n" {
            return Some(head);
        }
    }
}

/// The value of the header `name` in `head`, in lower case.
fn header(head: &[u8], name: &str) -> Option<String> {
    String::from_utf8_lossy(head)
        .lines()
        .skip(1)
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_ascii_lowercase())
        })
}

/// Copy the body that `head` frames from `input` to `output`, and give its
/// bytes when `keep` is set: a `Content-Length` body, a chunked body, or no
/// body. `None` when the copy failed.
fn copy_body(
    head: &[u8],
    no_body: bool,
    input: &mut BufReader<TcpStream>,
    output: &mut TcpStream,
    keep: bool,
) -> Option<Vec<u8>> {
    let mut kept = Vec::new();
    let mut copy = |n: usize, input: &mut BufReader<TcpStream>, output: &mut TcpStream| {
        let mut bytes = vec![0u8; n];
        input.read_exact(&mut bytes).ok()?;
        output.write_all(&bytes).ok()?;
        if keep {
            kept.extend_from_slice(&bytes);
        }
        Some(())
    };
    if no_body {
        return Some(kept);
    }
    if header(head, "transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        loop {
            let mut line = Vec::new();
            input.read_until(b'\n', &mut line).ok()?;
            output.write_all(&line).ok()?;
            let text = String::from_utf8_lossy(&line);
            let size = usize::from_str_radix(text.trim().split(';').next()?, 16).ok()?;
            if size == 0 {
                // The trailers, up to the empty line.
                loop {
                    let mut line = Vec::new();
                    input.read_until(b'\n', &mut line).ok()?;
                    output.write_all(&line).ok()?;
                    if line == b"\r\n" {
                        return Some(kept);
                    }
                }
            }
            copy(size, input, output)?;
            let mut crlf = [0u8; 2];
            input.read_exact(&mut crlf).ok()?;
            output.write_all(&crlf).ok()?;
        }
    }
    let length = header(head, "content-length").map_or(0, |v| v.parse().unwrap());
    copy(length, input, output)?;
    Some(kept)
}

/// Relay one connection, and count each request on it.
fn relay(client: TcpStream, server: TcpStream, seen: Arc<Seen>, commit: CommitResponse) {
    let (kinds, requests) = std::sync::mpsc::channel::<u8>();
    let (from_client, mut to_server) = (client.try_clone().unwrap(), server.try_clone().unwrap());
    let request_seen = Arc::clone(&seen);
    let upstream = std::thread::spawn(move || {
        let mut input = BufReader::with_capacity(64 * 1024, from_client);
        while let Some(head) = read_head(&mut input) {
            let line = String::from_utf8_lossy(&head)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned();
            let path = line.split(' ').nth(1).unwrap_or("");
            let kind = if path.ends_with("/objects") {
                OBJECTS
            } else if path.ends_with("/commit") {
                COMMIT
            } else {
                OTHER
            };
            request_seen.requests.fetch_add(1, Ordering::SeqCst);
            match kind {
                OBJECTS => {
                    request_seen.objects.fetch_add(1, Ordering::SeqCst);
                    let now = request_seen
                        .objects_in_flight
                        .fetch_add(1, Ordering::SeqCst)
                        + 1;
                    request_seen.max_objects.fetch_max(now, Ordering::SeqCst);
                }
                COMMIT => {
                    request_seen.commits.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
            if kinds.send(kind).is_err() || to_server.write_all(&head).is_err() {
                break;
            }
            if copy_body(&head, false, &mut input, &mut to_server, false).is_none() {
                break;
            }
        }
        let _ = to_server.shutdown(Shutdown::Write);
    });
    let mut to_client = client;
    let mut input = BufReader::with_capacity(64 * 1024, server);
    while let Some(mut head) = read_head(&mut input) {
        let Ok(kind) = requests.recv() else { break };
        match kind {
            OBJECTS => {
                seen.objects_in_flight.fetch_sub(1, Ordering::SeqCst);
            }
            COMMIT if commit == CommitResponse::Drop => {
                let _ = to_client.shutdown(Shutdown::Both);
                let _ = input.get_ref().shutdown(Shutdown::Both);
                break;
            }
            COMMIT if commit == CommitResponse::Gzip => {
                let end = head.len() - 2;
                head.splice(end..end, b"content-encoding: gzip\r\n".iter().copied());
            }
            _ => {}
        }
        if to_client.write_all(&head).is_err() {
            break;
        }
        let status = String::from_utf8_lossy(&head)
            .split(' ')
            .nth(1)
            .unwrap_or("")
            .to_owned();
        let no_body = matches!(status.as_str(), "204" | "304");
        match copy_body(&head, no_body, &mut input, &mut to_client, kind == OBJECTS) {
            Some(body) if kind == OBJECTS => seen.objects_responses.lock().unwrap().push(body),
            Some(_) => {}
            None => break,
        }
    }
    let _ = to_client.shutdown(Shutdown::Write);
    let _ = upstream.join();
}

// ---------------------------------------------------------------------------
// Sources that change one object of a tree.
// ---------------------------------------------------------------------------

/// What [`Altered`] does to its one object.
enum Change {
    /// The open of the object fails.
    Fail,
    /// The object gets the data of another object.
    Swap(ObjectName),
}

/// The objects of a tree model, with one object changed.
struct Altered<'a> {
    model: &'a TreeModel,
    target: ObjectName,
    change: Change,
}

impl ObjectSource for Altered<'_> {
    fn objects<'a>(
        &'a self,
        commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya::push::Result<Vec<ObjectName>>> {
        self.model.objects(commit)
    }

    fn open<'a>(
        &'a self,
        name: &'a ObjectName,
        encoding: Encoding,
    ) -> BoxFuture<'a, ostrya::push::Result<ObjectData>> {
        if *name != self.target {
            return self.model.open(name, encoding);
        }
        match &self.change {
            Change::Fail => Box::pin(async {
                Err(Error::Source(Box::new(std::io::Error::other(
                    "the source failed on purpose",
                ))))
            }),
            Change::Swap(other) => self.model.open(other, encoding),
        }
    }

    fn detached_metadata<'a>(
        &'a self,
        commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya::push::Result<Option<Value>>> {
        self.model.detached_metadata(commit)
    }
}

/// Scan `root` into a tree model.
async fn scan(root: &Path) -> TreeModel {
    TreeModel::scan(root, ScanOptions::default()).await.unwrap()
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// Over HTTPS, a push with a bearer token, with Basic, and with a client
/// certificate sets its ref, and a push with no credential is
/// `unauthorized`. A server that allows anonymous push takes a push with no
/// credential.
#[test]
fn each_method_pushes_over_https_and_no_credential_is_refused() {
    let tmp = TmpDir::new("methods");
    let root = tree(tmp.path(), "tree", 4, 1000);
    let server = repo(tmp.path(), "server");
    let alice = tmp.file("alice", format!("{ALICE}\n").as_bytes());
    let bob = tmp.file("bob", format!("{BOB}\n").as_bytes());
    let mut opts = serve_options();
    opts.allow_anonymous_push = false;
    opts.credentials = Some(credentials());
    opts.tls = Some(server_tls());
    let (first_server, first_root) = (server.clone(), root.clone());
    with_server(server.clone(), opts, |addr| async move {
        let (server, root) = (first_server, first_root);
        let url = format!("https://127.0.0.1:{}/", addr.port());
        let tls = || ConnectOptions {
            tls_ca_path: Some(fixture("ca.pem")),
            ..direct()
        };
        let by_bearer = ConnectOptions {
            push_token_file: Some(alice),
            ..tls()
        };
        let by_basic = ConnectOptions {
            push_token_file: Some(bob),
            push_user: Some("bob".into()),
            ..tls()
        };
        let by_cert = ConnectOptions {
            tls_client_cert_path: Some(fixture("client.pem")),
            tls_client_key_path: Some(fixture("client.key.pem")),
            ..tls()
        };
        for (name, connect) in [
            ("bearer", by_bearer),
            ("basic", by_basic),
            ("cert", by_cert),
        ] {
            let outcome = push(&url, &root, connect, &[name]).await.unwrap();
            assert_pushed(&server, name, &outcome).await;
        }
        match push(&url, &root, tls(), &["nobody"]).await {
            Err(Error::Unauthorized(_)) => {}
            other => panic!("expected unauthorized, got {other:?}"),
        }
        assert_eq!(tip(&server, "nobody").await, None);
    });

    let mut opts = serve_options();
    opts.tls = Some(server_tls());
    with_server(server.clone(), opts, |addr| async move {
        let url = format!("https://127.0.0.1:{}/", addr.port());
        let connect = ConnectOptions {
            tls_ca_path: Some(fixture("ca.pem")),
            ..direct()
        };
        let outcome = push(&url, &root, connect, &["anonymous"]).await.unwrap();
        assert_pushed(&server, "anonymous", &outcome).await;
    });
}

/// A token to an `http://` address is refused before any request when the
/// cleartext switch is not set. With it, the push succeeds against a server
/// that takes cleartext credentials.
#[test]
fn a_cleartext_credential_needs_the_switch() {
    let tmp = TmpDir::new("cleartext");
    let root = tree(tmp.path(), "tree", 2, 100);
    let server = repo(tmp.path(), "server");
    let alice = tmp.file("alice", format!("{ALICE}\n").as_bytes());
    let mut opts = serve_options();
    opts.allow_anonymous_push = false;
    opts.credentials = Some(credentials());
    opts.allow_cleartext_credentials = true;
    with_server(server.clone(), opts, |addr| async move {
        let proxy = CountingProxy::start(addr, CommitResponse::Forward);
        let connect = ConnectOptions {
            push_token_file: Some(alice.clone()),
            ..direct()
        };
        match push(&proxy.url, &root, connect, &["main"]).await {
            Err(Error::InvalidInput(m)) => assert!(m.contains("cleartext"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(proxy.seen.connections.load(Ordering::SeqCst), 0);
        let connect = ConnectOptions {
            push_token_file: Some(alice),
            allow_cleartext_credentials: true,
            ..direct()
        };
        let outcome = push(&proxy.url, &root, connect, &["main"]).await.unwrap();
        assert_pushed(&server, "main", &outcome).await;
    });
}

/// A tree push over HTTP sets the ref. A repeat push of the same tree with
/// a new timestamp sends the new commit alone.
#[test]
fn a_tree_push_and_its_repeat_over_http() {
    let tmp = TmpDir::new("tree");
    let root = tree(tmp.path(), "tree", 6, 5000);
    let server = repo(tmp.path(), "server");
    with_server(server.clone(), serve_options(), |addr| async move {
        let url = format!("http://{addr}/");
        let first = push(&url, &root, direct(), &["main"]).await.unwrap();
        assert_pushed(&server, "main", &first).await;
        // The server holds nothing, so each object of the tree and the
        // commit go.
        assert_eq!(
            first.stats.objects_sent, first.stats.objects_total,
            "{:?}",
            first.stats
        );
        assert!(first.stats.objects_sent > 6, "{:?}", first.stats);
        assert!(first.stats.bytes_sent > 30_000, "{:?}", first.stats);

        let opts = tree_options(&["main"], 1_700_000_001);
        let second = push_tree(&remote(&url), &root, direct(), opts)
            .await
            .unwrap();
        assert_pushed(&server, "main", &second).await;
        assert_eq!(second.refs[0].old, first.commit);
        assert_eq!(second.stats.objects_sent, 1, "{:?}", second.stats);
        assert_eq!(second.stats.objects_needed, 1, "{:?}", second.stats);
    });
}

/// `Repo::push` to an HTTP address sends the commit of a local branch.
#[test]
fn a_repository_push_over_http() {
    let tmp = TmpDir::new("repo");
    let src = tree(tmp.path(), "tree", 3, 2000);
    let local = repo(tmp.path(), "local");
    let commit = block_on(async {
        let txn = local.transaction().await.unwrap();
        let dfd = std::fs::File::open(&src).unwrap();
        let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, Some(&mut modifier))
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let options = CommitOptions {
            timestamp: Some(1_700_000_000),
            ..CommitOptions::default()
        };
        let commit = txn.write_commit(options, &root).await.unwrap();
        txn.set_ref("main", Some(&commit));
        txn.commit().await.unwrap();
        commit
    });
    let server = repo(tmp.path(), "server");
    with_server(server.clone(), serve_options(), |addr| async move {
        let opts = RepoPushOptions {
            refspecs: vec!["main".into()],
            connect: direct(),
            ..Default::default()
        };
        let outcome = local.push(&format!("http://{addr}/"), opts).await.unwrap();
        assert_eq!(outcome.refs[0].new, Some(commit));
        assert_eq!(tip(&server, "main").await, Some(commit));
    });
}

/// The `objects` requests of a session stay within `parallel-uploads`, and
/// with more than one allowed, several run at the same time. Two `send`
/// calls of one session at the same time share the limit.
#[test]
fn the_object_streams_stay_within_parallel_uploads() {
    let tmp = TmpDir::new("parallel");
    let root = tree(tmp.path(), "tree", 96, 48 * 1024);
    for parallel in [1, 3] {
        let server = repo(tmp.path(), &format!("server-{parallel}"));
        let mut opts = serve_options();
        opts.parallel_uploads = parallel;
        let root = root.clone();
        with_server(server.clone(), opts, |addr| async move {
            let proxy = CountingProxy::start(addr, CommitResponse::Forward);
            let name = format!("p{parallel}");
            let outcome = push(&proxy.url, &root, direct(), &[&name]).await.unwrap();
            assert_pushed(&server, &name, &outcome).await;
            let max = proxy.max_objects();
            assert!(max <= parallel as usize, "{max} streams, limit {parallel}");
            if parallel > 1 {
                assert!(max > 1, "the {parallel} streams did not overlap");
            } else {
                // One request at a time: the requests of the session share
                // the connections that went back to the pool.
                let requests = proxy.seen.requests.load(Ordering::SeqCst);
                let connections = proxy.seen.connections.load(Ordering::SeqCst);
                assert!(requests >= 4, "{requests} requests");
                assert!(connections < requests, "{connections} connections");
            }

            // Two calls at the same time, each with half of the objects.
            let proxy = CountingProxy::start(addr, CommitResponse::Forward);
            let model = scan(&root).await;
            let names = model.object_names();
            let (a, b) = names.split_at(names.len() / 2);
            let session = PushSession::connect(
                &remote(&proxy.url),
                direct(),
                &["concurrent".to_owned()],
                SessionOptions::default(),
            )
            .await
            .unwrap();
            let (first, second) = both(
                session.send(&model, a, &[], Compression::None),
                session.send(&model, b, &[], Compression::None),
            )
            .await;
            first.unwrap();
            second.unwrap();
            let max = proxy.max_objects();
            assert!(max <= parallel as usize, "{max} streams, limit {parallel}");
            assert!(proxy.seen.objects.load(Ordering::SeqCst) >= 2);
            session.abort().await.unwrap();
        });
    }
}

/// The commit that a push of `root` to the ref `main` of a server with no
/// refs builds: a push to a new repository under `base`. A push to any
/// other server with no refs builds the same commit.
fn expected_commit(base: &Path, root: &Path) -> Checksum {
    let server = repo(base, "expected");
    let mut commit = None;
    with_server(server, serve_options(), |addr| {
        let commit = &mut commit;
        async move {
            let url = format!("http://{addr}/");
            *commit = push(&url, root, direct(), &["main"]).await.unwrap().commit;
        }
    });
    commit.unwrap()
}

/// A commit whose response the proxy drops gives `CommitOutcomeUnknown`
/// with the ref names, and the client sends the commit once. The server
/// applied the commit.
#[test]
fn a_lost_commit_response_leaves_the_outcome_unknown() {
    let tmp = TmpDir::new("lost");
    let root = tree(tmp.path(), "tree", 2, 100);
    let expected = expected_commit(tmp.path(), &root);
    let server = repo(tmp.path(), "server");
    with_server(server.clone(), serve_options(), |addr| async move {
        let proxy = CountingProxy::start(addr, CommitResponse::Drop);
        match push(&proxy.url, &root, direct(), &["main"]).await {
            Err(Error::CommitOutcomeUnknown { refs, .. }) => assert_eq!(refs, ["main"]),
            other => panic!("expected an unknown outcome, got {other:?}"),
        }
        assert_eq!(proxy.seen.commits.load(Ordering::SeqCst), 1);
        assert_eq!(tip(&server, "main").await, Some(expected));
    });
}

/// A commit whose response the client refuses after it sent the request,
/// here for a coding the response declares, gives `CommitOutcomeUnknown`
/// and not a definite failure: the server applied the commit.
#[test]
fn a_refused_commit_response_leaves_the_outcome_unknown() {
    let tmp = TmpDir::new("coded");
    let root = tree(tmp.path(), "tree", 2, 100);
    let expected = expected_commit(tmp.path(), &root);
    let server = repo(tmp.path(), "server");
    with_server(server.clone(), serve_options(), |addr| async move {
        let proxy = CountingProxy::start(addr, CommitResponse::Gzip);
        match push(&proxy.url, &root, direct(), &["main"]).await {
            Err(Error::CommitOutcomeUnknown { refs, message }) => {
                assert_eq!(refs, ["main"]);
                assert!(message.contains("gzip"), "{message}");
            }
            other => panic!("expected an unknown outcome, got {other:?}"),
        }
        assert_eq!(proxy.seen.commits.load(Ordering::SeqCst), 1);
        assert_eq!(tip(&server, "main").await, Some(expected));
    });
}

/// A source that fails in one object stream fails the call with
/// `Error::Source`. The server aborts the session, so its staging
/// directory goes, and no ref changes. `abort` then succeeds.
#[test]
fn a_failed_source_aborts_the_session() {
    let tmp = TmpDir::new("source");
    let root = tree(tmp.path(), "tree", 40, 16 * 1024);
    let server = repo(tmp.path(), "server");
    let mut opts = serve_options();
    opts.parallel_uploads = 3;
    with_server(server.clone(), opts, |addr| async move {
        let model = scan(&root).await;
        let names = model.object_names();
        let source = Altered {
            model: &model,
            target: names[names.len() / 2],
            change: Change::Fail,
        };
        let session = PushSession::connect(
            &remote(&format!("http://{addr}/")),
            direct(),
            &["main".to_owned()],
            SessionOptions::default(),
        )
        .await
        .unwrap();
        match session.send(&source, &names, &[], Compression::None).await {
            Err(Error::Source(e)) => assert!(e.to_string().contains("on purpose"), "{e}"),
            other => panic!("expected a source error, got {other:?}"),
        }
        // The session is broken: abort still ends it on the server.
        match session.abort().await {
            Err(Error::InvalidInput(m)) => assert!(m.contains("broken"), "{m}"),
            other => panic!("expected a broken session, got {other:?}"),
        }
        eventually("the removal of the staging directory", || {
            staging_entries(&server).is_empty()
        })
        .await;
        assert_eq!(tip(&server, "main").await, None);
    });
}

/// An object whose bytes do not hash to its name gives `checksum-mismatch`
/// from the server, also when other streams of the call ran at the same time
/// and failed because the server aborted the session: the call returns the
/// error that the server gave for its own cause.
#[test]
fn a_checksum_mismatch_over_http() {
    let tmp = TmpDir::new("mismatch");
    let root = tree(tmp.path(), "tree", 40, 16 * 1024);
    let server = repo(tmp.path(), "server");
    let mut opts = serve_options();
    opts.parallel_uploads = 3;
    with_server(server.clone(), opts, |addr| async move {
        let proxy = CountingProxy::start(addr, CommitResponse::Forward);
        let model = scan(&root).await;
        let names = model.object_names();
        let files: Vec<ObjectName> = names
            .iter()
            .filter(|n| n.ty == ObjectType::File)
            .copied()
            .collect();
        let source = Altered {
            model: &model,
            target: files[files.len() / 2],
            change: Change::Swap(files[0]),
        };
        let session = PushSession::connect(
            &remote(&proxy.url),
            direct(),
            &["main".to_owned()],
            SessionOptions::default(),
        )
        .await
        .unwrap();
        match session.send(&source, &names, &[], Compression::None).await {
            Err(Error::ChecksumMismatch(_)) => {}
            other => panic!("expected checksum-mismatch, got {other:?}"),
        }
        let _ = session.abort().await;
        assert_eq!(tip(&server, "main").await, None);
        // The streams of the call ran at the same time. One stream got the
        // error of the object, and another stream got the error of the
        // session that the server aborted for it.
        assert!(proxy.max_objects() > 1, "the streams did not overlap");
        let responses = proxy.seen.objects_responses.lock().unwrap();
        let holds =
            |body: &[u8], text: &str| body.windows(text.len()).any(|w| w == text.as_bytes());
        let cascade = responses
            .iter()
            .filter(|b| holds(b, "the session was aborted"))
            .count();
        let cause = responses
            .iter()
            .filter(|b| holds(b, "checksum-mismatch") && !holds(b, "the session was aborted"))
            .count();
        assert_eq!(cause, 1, "{} responses", responses.len());
        assert!(cascade >= 1, "no stream failed with the aborted session");
    });
}

/// `ostrya push` and `ostrya push-tree` against `ostrya serve`, and the
/// checks of the `ostree` tool on the receiving repository.
mod cli {
    use super::*;
    use std::process::{Child, Command, Output, Stdio};

    const REQUIRE_OSTREE: &str = "OSTRYA_REQUIRE_OSTREE";

    /// The variables that name a proxy to the HTTP client of the port or of
    /// the tool.
    const PROXY_VARIABLES: [&str; 8] = [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ];

    fn ostrya_bin() -> &'static str {
        env!("CARGO_BIN_EXE_ostrya")
    }

    /// A command of `program` with no proxy variable in its environment and
    /// no standard input.
    fn command(program: &str) -> Command {
        let mut command = Command::new(program);
        command.stdin(Stdio::null());
        for name in PROXY_VARIABLES {
            command.env_remove(name);
        }
        command
    }

    /// A run of the built `ostrya` with `args`, with no proxy, no ssh
    /// command, and no repository from the environment.
    fn ostrya(args: &[&str]) -> Output {
        command(ostrya_bin())
            .args(args)
            .env_remove("OSTREE_REPO")
            .env("OSTRYA_SSH_COMMAND", "false")
            .output()
            .unwrap()
    }

    fn stdout(out: &Output) -> String {
        String::from_utf8(out.stdout.clone()).unwrap()
    }

    fn stderr(out: &Output) -> String {
        String::from_utf8(out.stderr.clone()).unwrap()
    }

    /// Run `program` with `args`, with no proxy, and return its standard
    /// output, failing the test when it fails.
    fn ok(program: &str, args: &[&str]) -> String {
        let out = if program == "ostrya" {
            ostrya(args)
        } else {
            command(program).args(args).output().unwrap()
        };
        assert!(
            out.status.success(),
            "{program} {args:?} failed: {}{}",
            stdout(&out),
            stderr(&out)
        );
        stdout(&out)
    }

    /// Assert that `out` is a failure at exit 1 with no standard output, and
    /// that its error line holds `needle`.
    fn assert_refused(out: &Output, needle: &str) {
        let err = stderr(out);
        assert_eq!(out.status.code(), Some(1), "{err}");
        assert!(out.stdout.is_empty(), "{}", stdout(out));
        assert!(err.starts_with("error: "), "{err}");
        assert!(err.contains(needle), "{err:?} lacks {needle:?}");
    }

    /// A listener that accepts nothing, to show that a refused push made no
    /// connection.
    struct Silent {
        listener: TcpListener,
    }

    impl Silent {
        fn new() -> Silent {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            Silent { listener }
        }

        fn url(&self, scheme: &str) -> String {
            format!("{scheme}://{}/", self.listener.local_addr().unwrap())
        }

        fn assert_untouched(&self) {
            match self.listener.accept() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("the push made a connection: {other:?}"),
            }
        }
    }

    /// A running `ostrya serve`, killed when it drops.
    struct Serving {
        child: Child,
        url: String,
    }

    impl Serving {
        /// Start the server over `repo` with `args`, on a port the kernel
        /// chooses, and read the URL it writes.
        fn start(repo: &Path, args: &[&str]) -> Serving {
            let mut child = Command::new(ostrya_bin())
                .arg(format!("--repo={}", repo.display()))
                .args(["serve", "--listen=127.0.0.1:0"])
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert!(line.ends_with("/\n"), "serve wrote {line:?}");
            Serving {
                child,
                url: line.trim_end().to_owned(),
            }
        }
    }

    impl Drop for Serving {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// The paths of one test: the base, a credential file of `alice` and
    /// `bob`, a token file of each, and a token file that no line names.
    struct Setup {
        tmp: TmpDir,
        credentials: PathBuf,
        alice: PathBuf,
        bob: PathBuf,
        wrong: PathBuf,
    }

    impl Setup {
        fn new(tag: &str) -> Setup {
            let tmp = TmpDir::new(tag);
            let credentials = tmp.file("credentials", &super::credentials());
            let alice = tmp.file("alice", format!("{ALICE}\n").as_bytes());
            let bob = tmp.file("bob", format!("{BOB}\n").as_bytes());
            let wrong = tmp.file("wrong", b"wrong-token\n");
            Setup {
                tmp,
                credentials,
                alice,
                bob,
                wrong,
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.tmp.path().join(name)
        }

        /// A new repository `name` of `mode`, created by the port.
        fn init(&self, name: &str, mode: &str) -> PathBuf {
            let path = self.path(name);
            ok(
                "ostrya",
                &[
                    &format!("--repo={}", path.display()),
                    "init",
                    &format!("--mode={mode}"),
                ],
            );
            path
        }

        /// A client repository with a commit of the tree under `src` on
        /// `main`, and the commit. The commit binds no ref, so the server
        /// takes it under any name.
        fn client(&self, src: &Path) -> (PathBuf, String) {
            let client = self.init("client", "archive");
            let commit = ok(
                "ostrya",
                &[
                    &format!("--repo={}", client.display()),
                    "commit",
                    "-b",
                    "main",
                    "-s",
                    "subject",
                    "--no-xattrs",
                    "--no-bindings",
                    src.to_str().unwrap(),
                ],
            );
            (client, commit.trim().to_owned())
        }

        /// `--push-credentials` of the credential file.
        fn credentials_arg(&self) -> String {
            format!("--push-credentials={}", self.credentials.display())
        }
    }

    /// Add `sections` to the config of `repo`.
    fn add_config(repo: &Path, sections: &str) {
        let path = repo.join("config");
        let mut config = std::fs::read_to_string(&path).unwrap();
        config.push('\n');
        config.push_str(sections);
        std::fs::write(&path, config).unwrap();
    }

    /// The commit of the ref `name` of `repo`.
    fn rev_parse(repo: &Path, name: &str) -> String {
        ok(
            "ostrya",
            &[&format!("--repo={}", repo.display()), "rev-parse", name],
        )
        .trim()
        .to_owned()
    }

    /// `ostrya push` from `repo` with `args`.
    fn push_from(repo: &Path, args: &[&str]) -> Output {
        let repo = format!("--repo={}", repo.display());
        ostrya(&[&[repo.as_str(), "push"], args].concat())
    }

    /// The `--tls-` options of the fixture CA, and of the fixture client
    /// certificate when `cert` is set.
    fn tls_args(cert: bool) -> Vec<String> {
        let mut args = vec![format!("--tls-ca-path={}", fixture("ca.pem").display())];
        if cert {
            args.push(format!(
                "--tls-client-cert-path={}",
                fixture("client.pem").display()
            ));
            args.push(format!(
                "--tls-client-key-path={}",
                fixture("client.key.pem").display()
            ));
        }
        args
    }

    /// The `serve` options of HTTPS with the fixture server certificate.
    fn server_tls_args() -> Vec<String> {
        vec![
            format!("--tls-cert={}", fixture("server.pem").display()),
            format!("--tls-key={}", fixture("server.key.pem").display()),
        ]
    }

    fn strs(args: &[String]) -> Vec<&str> {
        args.iter().map(String::as_str).collect()
    }

    /// `ostrya push` to an HTTPS remote of the config takes the address from
    /// `url`, or from `push-url` when the section has one, and the token
    /// file, the user, and the CA from the keys of the section. The ssh keys
    /// of a section with an HTTP address are not read. Each option wins over
    /// the key of its name, and each key resolves on its own.
    #[test]
    fn push_takes_the_http_keys_of_the_remote_and_the_options_win() {
        let setup = Setup::new("cli-keys");
        let src = tree(setup.tmp.path(), "tree", 3, 1000);
        let (client, commit) = setup.client(&src);
        let server = setup.init("server", "archive");
        let creds = setup.credentials_arg();
        let mut args = server_tls_args();
        args.push(creds);
        let serving = Serving::start(&server, &strs(&args));
        let ca = fixture("ca.pem");
        let absent = setup.path("absent-ca");
        add_config(
            &client,
            &format!(
                "[remote \"origin\"]\nurl={url}\ntls-ca-path={ca}\npush-token-file={alice}\n\
                 ssh-command=false\nreceive-command=/nonexistent\n\n\
                 [remote \"by-push-url\"]\nurl=https://example.invalid/repo\n\
                 push-url={url}\ntls-ca-path={ca}\npush-token-file={bob}\npush-user=bob\n\n\
                 [remote \"override\"]\nurl={url}\ntls-ca-path={absent}\n\
                 push-token-file={wrong}\npush-user=bob\n",
                url = serving.url,
                ca = ca.display(),
                alice = setup.alice.display(),
                bob = setup.bob.display(),
                wrong = setup.wrong.display(),
                absent = absent.display(),
            ),
        );

        // A bearer token from the keys of `origin`.
        let out = push_from(&client, &["origin", "main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {commit}\n"));
        // Basic from the keys of `by-push-url`, at its `push-url`.
        let out = push_from(&client, &["by-push-url", "main:basic"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("basic (new) {commit}\n"));

        // The CA key of `override` names no file.
        assert_refused(&push_from(&client, &["override", "main:o"]), "absent-ca");
        // The option wins over the CA key, and the token key, which no line
        // names, is sent.
        let ca_arg = format!("--tls-ca-path={}", ca.display());
        assert_refused(
            &push_from(&client, &[&ca_arg, "override", "main:o"]),
            "error: unauthorized: ",
        );
        // The token option wins over its key, and the user key stays.
        let bob = format!("--push-token-file={}", setup.bob.display());
        let out = push_from(&client, &[&ca_arg, &bob, "override", "main:o"]);
        assert!(out.status.success(), "{}", stderr(&out));
        // The user option wins over its key.
        let alice = format!("--push-token-file={}", setup.alice.display());
        let out = push_from(
            &client,
            &[&ca_arg, &alice, "--push-user=alice", "override", "main:o2"],
        );
        assert!(out.status.success(), "{}", stderr(&out));
        // A user that does not own the token is refused.
        assert_refused(
            &push_from(
                &client,
                &[&ca_arg, &alice, "--push-user=bob", "override", "main:o3"],
            ),
            "error: unauthorized: ",
        );

        for name in ["main", "basic", "o", "o2"] {
            assert_eq!(rev_parse(&server, name), commit, "{name}");
        }
        let refs = ok("ostrya", &[&format!("--repo={}", server.display()), "refs"]);
        assert!(!refs.lines().any(|l| l == "o3"), "{refs}");
    }

    /// `ostrya push-tree` over HTTPS with a client certificate that the
    /// client CA of the server signed sets the ref. With no credential, the
    /// server refuses the push as `unauthorized`, and the command exits 1.
    #[test]
    fn push_tree_over_https_with_a_client_certificate() {
        let setup = Setup::new("cli-cert");
        let src = tree(setup.tmp.path(), "tree", 4, 3000);
        let server = setup.init("server", "archive");
        let mut args = server_tls_args();
        args.push(format!("--client-ca={}", fixture("ca.pem").display()));
        let serving = Serving::start(&server, &strs(&args));
        let src_arg = src.to_str().unwrap();
        let push_tree = |extra: &[String], branch: &str| {
            let mut all = vec![
                "push-tree",
                serving.url.as_str(),
                src_arg,
                "-b",
                branch,
                "--timestamp=@1700000000",
            ];
            all.extend(strs(extra));
            ostrya(&all)
        };
        let out = push_tree(&tls_args(true), "main");
        assert!(out.status.success(), "{}", stderr(&out));
        let commit = stdout(&out);
        assert_eq!(commit.len(), 65, "{commit:?}");
        assert_eq!(rev_parse(&server, "main"), commit.trim());

        assert_refused(
            &push_tree(&tls_args(false), "other"),
            "error: unauthorized: ",
        );
        let refs = ok("ostrya", &[&format!("--repo={}", server.display()), "refs"]);
        assert_eq!(refs, "main\n");
    }

    /// A token to an `http://` address is refused before any connection
    /// without `--allow-cleartext-credentials`. With it, the push succeeds
    /// against a server that takes credentials over plain HTTP.
    #[test]
    fn a_cleartext_token_needs_the_switch() {
        let setup = Setup::new("cli-cleartext");
        let src = tree(setup.tmp.path(), "tree", 2, 100);
        let silent = Silent::new();
        let token = format!("--push-token-file={}", setup.alice.display());
        let src_arg = src.to_str().unwrap();
        let out = ostrya(&[
            "push-tree",
            &silent.url("http"),
            src_arg,
            "-b",
            "main",
            &token,
        ]);
        assert_refused(&out, "cleartext");
        silent.assert_untouched();

        let server = setup.init("server", "archive");
        let serving = Serving::start(
            &server,
            &[&setup.credentials_arg(), "--allow-cleartext-credentials"],
        );
        assert!(serving.url.starts_with("http://"), "{}", serving.url);
        let out = ostrya(&[
            "push-tree",
            &serving.url,
            src_arg,
            "-b",
            "main",
            &token,
            "--allow-cleartext-credentials",
        ]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(rev_parse(&server, "main"), stdout(&out).trim());
    }

    /// `tls-permissive=true` on a remote with an HTTP push address is refused
    /// before any connection. An option of the other transport is refused
    /// too, for an HTTP address and for an ssh address.
    #[test]
    fn tls_permissive_and_an_option_of_the_other_transport_are_refused() {
        let setup = Setup::new("cli-refusals");
        let src = tree(setup.tmp.path(), "tree", 2, 100);
        let (client, _) = setup.client(&src);
        let silent = Silent::new();
        let https = silent.url("https");
        add_config(
            &client,
            &format!(
                "[remote \"permissive\"]\nurl={https}\ntls-permissive=true\n\n\
                 [remote \"permissive-ssh\"]\npush-url=ssh://localhost/srv/repo\n\
                 tls-permissive=true\npush-token-file=/nonexistent\n"
            ),
        );
        assert_refused(
            &push_from(&client, &["permissive", "main"]),
            "remote 'permissive' sets tls-permissive=true",
        );
        assert_refused(
            &push_from(&client, &["--ssh-command=ssh", &https, "main"]),
            &format!(
                "error: invalid input: ssh-command applies to an ssh address, and '{https}' is an HTTP"
            ),
        );
        assert_refused(
            &push_from(&client, &["--receive-command=receiver", &https, "main"]),
            "error: invalid input: receive-command applies to an ssh address",
        );
        silent.assert_untouched();
        // The HTTP keys of a remote with an ssh address are not read, so the
        // push reaches the ssh client, which `OSTRYA_SSH_COMMAND` sets to
        // `false`.
        let out = push_from(&client, &["permissive-ssh", "main"]);
        assert_refused(&out, "transport: 'false'");
        assert!(!stderr(&out).contains("tls-permissive"), "{}", stderr(&out));
        assert!(
            !stderr(&out).contains("push-token-file"),
            "{}",
            stderr(&out)
        );
        let token = format!("--push-token-file={}", setup.alice.display());
        for option in [
            token.as_str(),
            "--push-user=alice",
            "--allow-cleartext-credentials",
        ] {
            let out = push_from(&client, &[option, "permissive-ssh", "main"]);
            let name = option.trim_start_matches("--");
            let name = name.split('=').next().unwrap();
            assert_refused(
                &out,
                &format!("error: invalid input: {name} applies to an HTTP address, and 'ssh://"),
            );
        }
        let ca = format!("--tls-ca-path={}", fixture("ca.pem").display());
        let out = ostrya(&[
            "push-tree",
            "ssh://localhost/srv/repo",
            src.to_str().unwrap(),
            "-b",
            "main",
            &ca,
        ]);
        assert_refused(
            &out,
            "error: invalid input: tls-ca-path applies to an HTTP address",
        );
    }

    /// `tls-permissive=true` on a remote whose push address is `http://` is
    /// ignored: the push uses no TLS, and it succeeds.
    #[test]
    fn tls_permissive_is_ignored_for_an_http_address() {
        let setup = Setup::new("cli-permissive-http");
        let src = tree(setup.tmp.path(), "tree", 2, 100);
        let (client, commit) = setup.client(&src);
        let server = setup.init("server", "archive");
        let serving = Serving::start(&server, &["--allow-anonymous-push"]);
        assert!(serving.url.starts_with("http://"), "{}", serving.url);
        add_config(
            &client,
            &format!(
                "[remote \"permissive-http\"]\nurl={}\ntls-permissive=true\n",
                serving.url
            ),
        );
        let out = push_from(&client, &["permissive-http", "main"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {commit}\n"));
        assert_eq!(rev_parse(&server, "main"), commit);
    }

    /// The push checks the remote and makes the transport ready before its
    /// own local work. `ostrya push` refuses a bad HTTP option before it
    /// reads a refspec, and `ostrya push-tree` refuses an option of the
    /// other transport before it checks a signing key and before it reads
    /// the body file.
    #[test]
    fn the_transport_checks_come_before_the_local_work() {
        let setup = Setup::new("cli-order");
        let src = tree(setup.tmp.path(), "tree", 2, 100);
        let (client, _) = setup.client(&src);
        let silent = Silent::new();
        let https = silent.url("https");
        // The refspec names no ref, and the push-user has no token file.
        let out = push_from(&client, &["--push-user=bob", &https, "nosuchref"]);
        assert_refused(
            &out,
            "error: invalid input: push-user needs push-token-file",
        );
        // A token file that does not exist, beside the same refspec.
        let absent = setup.path("absent-token");
        let token = format!("--push-token-file={}", absent.display());
        let out = push_from(&client, &[&token, &https, "nosuchref"]);
        assert_refused(
            &out,
            &format!("error: push-token-file '{}': ", absent.display()),
        );
        // A depth below -1 is a check of the local work too.
        let out = push_from(&client, &["--push-user=bob", "--depth=-2", &https, "main"]);
        assert_refused(
            &out,
            "error: invalid input: push-user needs push-token-file",
        );
        silent.assert_untouched();

        let ca = format!("--tls-ca-path={}", fixture("ca.pem").display());
        let body = format!("--body-file={}", setup.path("absent-body").display());
        let out = ostrya(&[
            "push-tree",
            "ssh://localhost/srv/repo",
            src.to_str().unwrap(),
            "-b",
            "main",
            &ca,
            "--sign=short",
            &body,
        ]);
        assert_refused(
            &out,
            "error: invalid input: tls-ca-path applies to an HTTP address",
        );
        // Without the option of the other transport, the signing key is
        // checked first, and then the body file.
        let out = ostrya(&[
            "push-tree",
            "ssh://localhost/srv/repo",
            src.to_str().unwrap(),
            "-b",
            "main",
            "--sign=short",
            &body,
        ]);
        assert_refused(&out, "Invalid ed25519 secret key");
        let out = ostrya(&[
            "push-tree",
            "ssh://localhost/srv/repo",
            src.to_str().unwrap(),
            "-b",
            "main",
            &body,
        ]);
        assert_refused(&out, "absent-body");
        // A refused HTTP option stands ahead of the body file too.
        let out = ostrya(&[
            "push-tree",
            &https,
            src.to_str().unwrap(),
            "-b",
            "main",
            "--push-user=bob",
            &body,
        ]);
        assert_refused(
            &out,
            "error: invalid input: push-user needs push-token-file",
        );
        silent.assert_untouched();
    }

    /// Whether the `ostree` tool and `openssl`, which makes the certificates
    /// of the check, are installed. With [`REQUIRE_OSTREE`] set the absence
    /// of either fails the test; without it the test skips and says so.
    fn tools_available() -> bool {
        let runs = |program: &str, arg: &str| {
            command(program)
                .arg(arg)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        for (program, arg) in [("ostree", "--version"), ("openssl", "version")] {
            let found = runs(program, arg);
            assert!(
                found || std::env::var_os(REQUIRE_OSTREE).is_none(),
                "{REQUIRE_OSTREE} is set and `{program}` is not installed"
            );
            if !found {
                eprintln!("skipped: `{program}` is not installed");
                return false;
            }
        }
        true
    }

    /// A CA and a server certificate for `127.0.0.1` that it signed, for the
    /// HTTPS pull of the tool. The TLS fixtures name one subject for the CA
    /// and the server certificate, which an OpenSSL client reads as a
    /// self-signed leaf, so the tool needs a pair of its own.
    struct Pki {
        ca: PathBuf,
        cert: PathBuf,
        key: PathBuf,
    }

    /// Generate a [`Pki`] under `dir` with `openssl`. Each certificate takes
    /// a config file of its own, and `OPENSSL_CONF` names no file, so no
    /// distinguished-name section of a host config replaces the subject.
    fn make_pki(dir: &Path) -> Pki {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("ca.cnf"),
            "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\n\
             basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("leaf.cnf"),
            "[req]\ndistinguished_name = dn\n[dn]\n[v3]\nbasicConstraints = critical,CA:FALSE\n\
             keyUsage = critical,digitalSignature\nextendedKeyUsage = serverAuth\n\
             subjectAltName = IP:127.0.0.1\n",
        )
        .unwrap();
        let at = |name: &str| dir.join(name).to_str().unwrap().to_owned();
        let openssl = |args: &[&str]| {
            let out = command("openssl")
                .args(args)
                .env("OPENSSL_CONF", "/dev/null")
                .output()
                .expect("run openssl");
            assert!(
                out.status.success(),
                "openssl {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        let p256 = [
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
        ];
        openssl(&[&p256[..], &["-out", &at("ca.key")]].concat());
        openssl(&[
            "req",
            "-x509",
            "-new",
            "-sha256",
            "-key",
            &at("ca.key"),
            "-subj",
            "/CN=ostrya push test ca",
            "-days",
            "2",
            "-config",
            &at("ca.cnf"),
            "-out",
            &at("ca.pem"),
        ]);
        openssl(&[&p256[..], &["-out", &at("server.key")]].concat());
        openssl(&[
            "req",
            "-new",
            "-sha256",
            "-key",
            &at("server.key"),
            "-subj",
            "/CN=127.0.0.1",
            "-config",
            &at("leaf.cnf"),
            "-out",
            &at("server.csr"),
        ]);
        openssl(&[
            "x509",
            "-req",
            "-sha256",
            "-in",
            &at("server.csr"),
            "-CA",
            &at("ca.pem"),
            "-CAkey",
            &at("ca.key"),
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            &at("leaf.cnf"),
            "-extensions",
            "v3",
            "-out",
            &at("server.pem"),
        ]);
        Pki {
            ca: dir.join("ca.pem"),
            cert: dir.join("server.pem"),
            key: dir.join("server.key"),
        }
    }

    /// After `ostrya push` over HTTPS to `ostrya serve`, the receiving
    /// `bare-user` repository passes `ostree fsck`, and `ostree pull` from
    /// the archive view of the same server, over HTTPS, gives the pushed
    /// commit in a new archive repository, which passes `ostree fsck` too.
    #[test]
    fn the_tool_checks_and_pulls_a_push_over_https() {
        if !tools_available() {
            return;
        }
        let setup = Setup::new("cli-tool");
        let src = tree(setup.tmp.path(), "tree", 6, 70_000);
        std::os::unix::fs::symlink("a/file-0", src.join("link")).unwrap();
        let (client, commit) = setup.client(&src);
        let server = setup.init("server", "bare-user");
        let pki = make_pki(&setup.path("pki"));
        let serving = Serving::start(
            &server,
            &[
                &format!("--tls-cert={}", pki.cert.display()),
                &format!("--tls-key={}", pki.key.display()),
                &setup.credentials_arg(),
            ],
        );
        assert!(serving.url.starts_with("https://"), "{}", serving.url);
        let out = push_from(
            &client,
            &[
                &format!("--tls-ca-path={}", pki.ca.display()),
                &format!("--push-token-file={}", setup.alice.display()),
                &serving.url,
                "main",
            ],
        );
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("main (new) {commit}\n"));
        let server_arg = format!("--repo={}", server.display());
        ok("ostree", &[&server_arg, "fsck"]);

        let pulled = setup.path("pulled");
        let pulled_arg = format!("--repo={}", pulled.display());
        ok("ostree", &[&pulled_arg, "init", "--mode=archive"]);
        ok(
            "ostree",
            &[
                &pulled_arg,
                "remote",
                "add",
                "--no-gpg-verify",
                &format!("--set=tls-ca-path={}", pki.ca.display()),
                "origin",
                &serving.url,
            ],
        );
        ok("ostree", &[&pulled_arg, "pull", "origin", "main"]);
        ok("ostree", &[&pulled_arg, "fsck"]);
        let tip = ok("ostree", &[&pulled_arg, "rev-parse", "origin:main"]);
        assert_eq!(tip.trim(), commit);
    }
}
