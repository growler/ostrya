//! Tests of the receive endpoint over HTTP/1.1 and HTTP/2. The client is the
//! upload request of the fetcher. The tests cover these subjects:
//!
//! - a push through the steps of one session
//! - the routes, and the status of each error
//! - the session limit, the idle timeout, and the silent body
//! - `DELETE`, and the commit that holds its session
//! - the refusals of the steps in flight
//! - the authentication of each request

use std::future::Future;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_lite::{AsyncReadExt, AsyncWriteExt, future};
use ostrya::fetch::{
    BasicAuth, BearerToken, ClientIdentity, Fetcher, FetcherOptions, Protocol, Proxy, TlsOptions,
    TrustRoots, UploadBody, UploadMethod, UploadRequest,
};
use ostrya::push::proto::{
    CommitRequest, ErrorMessage, FrameWriter, Hello, Kind, Message, ObjectHeader,
};
use ostrya::push::{Encoding, ErrorCode, Expected, RefUpdate};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree,
    ObjectName, ObjectType, PruneOptions, ReceivePolicy, ReceiveReport, Repo, RepoMode, loose_path,
};
use ostrya_rt::{Timer, block_on};
use ostrya_server::{ServeOptions, ServerTls};

const SESSION: &str = "_ostrya/receive/v1/session";

const CA_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/ca.pem");
const SERVER_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.pem");
const SERVER_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.key.pem");
const CLIENT_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/client.pem");
const CLIENT_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/client.key.pem");
/// A certificate that a second authority signed. Its subject is not the
/// issuer of `client.pem`, so as a client CA it did not sign that client.
const UNTRUSTED_CERT_PEM: &[u8] =
    include_bytes!("../../../tests/fixtures/tls/server-untrusted.pem");

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ostrya-server-receive-{}-{tag}-{}",
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
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Repositories and objects.
// ---------------------------------------------------------------------------

/// One object that a client sends.
#[derive(Clone)]
struct Obj {
    name: ObjectName,
    encoding: Encoding,
    bytes: Vec<u8>,
}

/// An `archive` source repository with two commits that have no parent. Each
/// commit is over a tree of its own. The source also holds the objects of
/// each commit as a client sends them:
///
/// - a content object as its stored `.filez`, in the `deflate` encoding
/// - a metadata object as its raw bytes
struct Source {
    commits: [Checksum; 2],
    objects: [Vec<Obj>; 2],
}

async fn source(base: &Path) -> Source {
    let root = base.join("source");
    let repo = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let mut commits = Vec::new();
    for (i, text) in ["one\n", "two\n"].into_iter().enumerate() {
        let src = base.join(format!("tree-{i}"));
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("file"), text).unwrap();
        std::fs::write(src.join("sub/nested"), b"nested\n").unwrap();
        let txn = repo.transaction().await.unwrap();
        let mut mtree = MutableTree::new();
        let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
        let dfd = std::fs::File::open(&src).unwrap();
        txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, Some(&mut modifier))
            .await
            .unwrap();
        let tree = txn.write_mtree(&mut mtree).await.unwrap();
        let options = CommitOptions {
            timestamp: Some(1_700_000_000 + i as u64),
            ..CommitOptions::default()
        };
        let commit = txn.write_commit(options, &tree).await.unwrap();
        txn.commit().await.unwrap();
        commits.push(commit);
    }
    let mut objects = Vec::new();
    for commit in &commits {
        let mut names: Vec<ObjectName> = repo
            .traverse_commit(commit, 0)
            .await
            .unwrap()
            .into_iter()
            .collect();
        names.sort_by_key(|n| (n.ty as u8, n.checksum));
        let objs = names
            .into_iter()
            .map(|name| {
                let path = loose_path(&name.checksum, name.ty, RepoMode::Archive);
                Obj {
                    name,
                    encoding: if name.ty == ObjectType::File {
                        Encoding::Deflate
                    } else {
                        Encoding::Raw
                    },
                    bytes: std::fs::read(root.join("objects").join(path)).unwrap(),
                }
            })
            .collect();
        objects.push(objs);
    }
    Source {
        commits: [commits[0], commits[1]],
        objects: [objects.remove(0), objects.remove(0)],
    }
}

/// The first object of `ty` in `objects`.
fn of_type(objects: &[Obj], ty: ObjectType) -> Obj {
    objects.iter().find(|o| o.name.ty == ty).unwrap().clone()
}

/// A new receiving repository of `mode` with `core` appended to its config.
fn receiver(base: &Path, mode: RepoMode, core: &str) -> Repo {
    let root = base.join("receiver");
    block_on(Repo::create(&root, CreateOptions::new(mode))).unwrap();
    let config = root.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(core);
    std::fs::write(&config, text).unwrap();
    block_on(Repo::open(&root)).unwrap()
}

/// The staging entries left under `tmp/`.
fn staging_entries(root: &Path) -> Vec<String> {
    std::fs::read_dir(root.join("tmp"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("staging-"))
        .collect()
}

/// Waits until `done` holds, and fails the test after 30 seconds.
fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "{what} did not happen");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Checks that the session ended with no commit. Its staging directory goes,
/// and the server releases the repository lock, so a prune takes the lock at
/// once.
fn assert_released(repo: &Repo) {
    eventually("the removal of the staging directory", || {
        staging_entries(repo.path()).is_empty()
    });
    let options = PruneOptions {
        no_prune: true,
        ..PruneOptions::default()
    };
    eventually("the release of the repository lock", || {
        block_on(repo.prune(&options)).is_ok()
    });
}

// ---------------------------------------------------------------------------
// Frames.
// ---------------------------------------------------------------------------

async fn encode(messages: &[Message]) -> Vec<u8> {
    let mut writer = FrameWriter::new(Vec::new());
    for message in messages {
        writer.write_message(message).await.unwrap();
    }
    writer.into_inner()
}

/// An object stream of `objects`, closed with `ObjectsEnd`.
async fn stream(objects: &[Obj]) -> Vec<u8> {
    let mut writer = FrameWriter::new(Vec::new());
    for obj in objects {
        write_object(&mut writer, obj).await;
    }
    writer.write_message(&Message::ObjectsEnd).await.unwrap();
    writer.into_inner()
}

async fn write_object(writer: &mut FrameWriter<Vec<u8>>, obj: &Obj) {
    writer
        .write_message(&Message::ObjectHeader(ObjectHeader {
            name: obj.name,
            encoding: obj.encoding,
        }))
        .await
        .unwrap();
    writer.write_object_data(&obj.bytes).await.unwrap();
    writer.end_object().await.unwrap();
}

/// The header of an object and the first byte of its data: a body that
/// waits inside an object.
async fn object_start() -> Vec<u8> {
    let mut writer = FrameWriter::new(Vec::new());
    writer
        .write_message(&Message::ObjectHeader(ObjectHeader {
            name: ObjectName::new(Checksum::sha256(b"waits"), ObjectType::DirTree),
            encoding: Encoding::Raw,
        }))
        .await
        .unwrap();
    writer.write_object_data(&[0]).await.unwrap();
    writer.into_inner()
}

/// A body that waits inside an object after the whole object `first`. The
/// session has `first` after the server reads it.
async fn waiting_body(first: &Obj) -> Vec<u8> {
    let mut writer = FrameWriter::new(Vec::new());
    write_object(&mut writer, first).await;
    let mut body = writer.into_inner();
    body.extend_from_slice(&object_start().await);
    body
}

fn hello() -> Message {
    Message::Hello(Hello {
        version: 1,
        agent: None,
        refs: vec!["main".into()],
        one_way: false,
    })
}

fn update(expected: Expected, new: Checksum) -> Message {
    Message::Commit(CommitRequest {
        updates: vec![RefUpdate {
            name: "main".into(),
            expected,
            new: Some(new),
        }],
        force: false,
    })
}

// ---------------------------------------------------------------------------
// The client.
// ---------------------------------------------------------------------------

/// One response of the endpoint.
#[derive(Debug)]
struct Reply {
    status: u16,
    headers: hyper::HeaderMap,
    protocol: Protocol,
    body: Vec<u8>,
}

impl Reply {
    /// The one message of the body, which holds one frame.
    fn message(&self) -> Message {
        assert!(self.body.len() > 4, "{self:?}");
        let (len, rest) = self.body.split_at(4);
        let len = u32::from_be_bytes(len.try_into().unwrap());
        assert_eq!(rest.len(), len as usize, "one frame");
        let kind = Kind::from_u8(rest[0]).unwrap();
        Message::decode(kind, &rest[1..]).unwrap()
    }

    /// The `Error` of the body, after a check of the status.
    fn error(&self, status: u16, code: ErrorCode) -> ErrorMessage {
        assert_eq!(self.status, status, "{self:?}");
        match self.message() {
            Message::Error(e) if e.code == code => e,
            other => panic!("expected {code:?}, got {other:?}"),
        }
    }

    /// The reply of a step that succeeded.
    fn ok(&self) -> Message {
        assert_eq!(self.status, 200, "{:?}", self.message());
        assert!(self.headers.get("content-type").is_none());
        self.message()
    }
}

struct Client {
    fetcher: Fetcher,
    bearer: Option<BearerToken>,
    basic: Option<BasicAuth>,
}

impl Client {
    async fn new(addr: SocketAddr) -> Client {
        let mut options = FetcherOptions::new(format!("http://{addr}/"));
        options.proxy = Proxy::None;
        options.max_retries = 0;
        Client {
            fetcher: Fetcher::new(options).await.unwrap(),
            bearer: None,
            basic: None,
        }
    }

    /// A client over TLS that offers HTTP/2 alone.
    async fn http2(addr: SocketAddr) -> Client {
        Client::tls(addr, true, None).await
    }

    /// A client over TLS that offers HTTP/2 alone, or HTTP/1.1 alone, and
    /// presents the certificate and the key `identity`.
    async fn tls(addr: SocketAddr, http2: bool, identity: Option<(&[u8], &[u8])>) -> Client {
        let mut options = FetcherOptions::new(format!("https://127.0.0.1:{}/", addr.port()));
        options.proxy = Proxy::None;
        options.max_retries = 0;
        options.http2 = http2;
        options.tls = TlsOptions {
            roots: TrustRoots::Pem(CA_PEM.to_vec()),
            client_identity: identity.map(|(cert, key)| ClientIdentity {
                cert_chain_pem: cert.to_vec(),
                key_pem: key.to_vec(),
                key_passphrase: None,
            }),
        };
        Client {
            fetcher: Fetcher::new(options).await.unwrap(),
            bearer: None,
            basic: None,
        }
    }

    async fn send(&self, path: &str, method: UploadMethod, body: UploadBody) -> Reply {
        let mut request = UploadRequest::path(path, body);
        request.method = method;
        request.bearer_token = self.bearer.as_ref();
        request.basic_auth = self.basic.as_ref();
        request.allow_cleartext_credentials = true;
        let uploaded = self.fetcher.upload(request).await.unwrap();
        let status = uploaded.status();
        let headers = uploaded.headers().clone();
        let protocol = uploaded.protocol();
        let mut body = Vec::new();
        uploaded.into_body().read_to_end(&mut body).await.unwrap();
        Reply {
            status,
            headers,
            protocol,
            body,
        }
    }

    async fn post(&self, path: &str, body: Vec<u8>) -> Reply {
        self.send(path, UploadMethod::Post, UploadBody::bytes(body))
            .await
    }

    /// Opens a session and returns its id.
    async fn open(&self) -> String {
        let reply = self.post(SESSION, encode(&[hello()]).await).await;
        assert!(matches!(reply.ok(), Message::HelloReply(_)));
        reply.headers["ostrya-session"].to_str().unwrap().to_owned()
    }

    async fn step(&self, id: &str, step: &str, body: Vec<u8>) -> Reply {
        self.post(&format!("{SESSION}/{id}/{step}"), body).await
    }

    async fn have(&self, id: &str, names: Vec<ObjectName>) -> Reply {
        self.step(id, "have", encode(&[Message::Have(names)]).await)
            .await
    }

    async fn delete(&self, id: &str) -> Reply {
        let path = format!("{SESSION}/{id}");
        self.send(&path, UploadMethod::Delete, UploadBody::bytes(Vec::new()))
            .await
    }

    /// Waits until the session `id` has `name`. At the return, the server read
    /// the object, so the request that carries the object is in flight.
    async fn until_read(&self, id: &str, name: ObjectName) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let Message::HaveReply(have) = self.have(id, vec![name]).await.ok() else {
                panic!("no HaveReply");
            };
            if !have.is_missing(0) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the server did not read the object"
            );
            Timer::after(Duration::from_millis(10)).await;
        }
    }

    /// An `objects` request whose body `write` streams. The request and the
    /// writer run together. When the response arrives, the function drops the
    /// writer.
    async fn objects_streamed<F, Fut>(&self, id: &str, write: F) -> Reply
    where
        F: FnOnce(ostrya::fetch::UploadWriter) -> Fut,
        Fut: Future<Output = ()>,
    {
        let (body, writer) = UploadBody::channel();
        let path = format!("{SESSION}/{id}/objects");
        let mut upload = Box::pin(self.send(&path, UploadMethod::Post, body));
        future::or(&mut upload, async {
            write(writer).await;
            std::future::pending::<Reply>().await
        })
        .await
    }
}

/// Runs `test` with a client of a server over `repo`, then drops the server.
fn with_server<F, Fut>(repo: Repo, opts: ServeOptions, test: F)
where
    F: FnOnce(Client, SocketAddr) -> Fut,
    Fut: Future<Output = ()>,
{
    block_on(async {
        let server = ostrya_server::bind(repo, opts).await.unwrap();
        let addr = server.local_addrs()[0];
        future::or(
            async {
                server.run().await.unwrap();
                unreachable!("the server runs until it is dropped");
            },
            async { test(Client::new(addr).await, addr).await },
        )
        .await
    });
}

fn options() -> ServeOptions {
    let mut opts = ServeOptions::default();
    opts.listen = vec!["127.0.0.1:0".parse().unwrap()];
    opts.receive = Some(Arc::new(ReceivePolicy::default()));
    opts.allow_anonymous_push = true;
    opts
}

/// Writes `bytes` to `writer` and flushes it. A failure gives `false` and no
/// panic, because the server can answer before the body ends.
async fn send_piece(writer: &mut ostrya::fetch::UploadWriter, bytes: &[u8]) -> bool {
    writer.write_all(bytes).await.is_ok() && writer.flush().await.is_ok()
}

/// Sends `request` raw on a new connection, and reads the response until the
/// server closes the connection.
async fn raw(addr: SocketAddr, request: &str) -> String {
    let mut stream = ostrya_rt::TcpStream::connect("127.0.0.1", addr.port())
        .await
        .unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

fn without_date(response: &str) -> String {
    response
        .split("\r\n")
        .filter(|line| !line.starts_with("date: "))
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let head = response.split("\r\n\r\n").next().unwrap();
    head.split("\r\n")
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// A push through `session`, `have`, two concurrent `objects` requests, and
/// `commit` sets the ref. The report goes to `on_report` with no warning.
/// Then the session is gone.
#[test]
fn a_push_through_the_endpoint_commits() {
    let tmp = TmpDir::new("push");
    let src = block_on(source(tmp.path()));
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let reports = Arc::new(Mutex::new(Vec::<ReceiveReport>::new()));
    let sink = reports.clone();
    let mut opts = options();
    opts.parallel_uploads = 2;
    opts.on_report = Some(Arc::new(move |r| sink.lock().unwrap().push(r)));
    let commit = src.commits[0];
    let objects = src.objects[0].clone();
    with_server(repo.clone(), opts, |client, _| async move {
        let reply = client.post(SESSION, encode(&[hello()]).await).await;
        let Message::HelloReply(hello_reply) = reply.ok() else {
            panic!("no HelloReply");
        };
        assert_eq!(hello_reply.parallel_uploads, 2);
        let id = reply.headers["ostrya-session"].to_str().unwrap().to_owned();
        assert_eq!(id.len(), 64);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_ne!(client.open().await, id, "each session gets its own id");

        let names: Vec<ObjectName> = objects.iter().map(|o| o.name).collect();
        let Message::HaveReply(have) = client.have(&id, names.clone()).await.ok() else {
            panic!("no HaveReply");
        };
        assert!((0..names.len()).all(|i| have.is_missing(i)));

        let (first, second) = objects.split_at(objects.len() / 2);
        let (a, b) = future::zip(
            client.step(&id, "objects", stream(first).await),
            client.step(&id, "objects", stream(second).await),
        )
        .await;
        let mut stored = 0;
        for reply in [a, b] {
            let Message::ObjectsReply(r) = reply.ok() else {
                panic!("no ObjectsReply");
            };
            stored += r.objects;
        }
        assert_eq!(stored as usize, objects.len());

        let reply = client
            .step(
                &id,
                "commit",
                encode(&[update(Expected::Absent, commit)]).await,
            )
            .await;
        let Message::CommitReply(refs) = reply.ok() else {
            panic!("no CommitReply");
        };
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].new, Some(commit));
        assert_eq!(client.have(&id, names).await.status, 404);
    });
    assert_eq!(
        block_on(repo.resolve_rev("main", false)).unwrap(),
        Some(commit)
    );
    eventually("the report", || !reports.lock().unwrap().is_empty());
    let reports = reports.lock().unwrap();
    assert_eq!(reports.len(), 1);
    assert!(reports[0].warnings.is_empty(), "{:?}", reports[0].warnings);
}

/// An unknown session id gets an empty 404 on each route. A path under the
/// prefix that names no route gets the same bytes. A known path with a wrong
/// method gets 405 with `Allow`. A `GET` gets the 404 of the archive view.
///
/// A read-only server has no endpoint.
#[test]
fn routes_unknown_ids_and_methods() {
    let tmp = TmpDir::new("routes");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let id = "0".repeat(64);
    with_server(repo.clone(), options(), |client, addr| async move {
        let ask = |method: &str, path: &str| {
            format!(
                "{method} /{path} HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\n\
                 connection: close\r\n\r\n"
            )
        };
        let have = raw(addr, &ask("POST", &format!("{SESSION}/{id}/have"))).await;
        assert!(have.starts_with("HTTP/1.1 404 "), "{have}");
        assert_eq!(header(&have, "content-length"), Some("0"));
        for path in [
            format!("{SESSION}/{id}/objects"),
            format!("{SESSION}/{id}/commit"),
            format!("{SESSION}/{id}/other"),
            format!("{SESSION}/{}", "A".repeat(64)),
            "_ostrya/receive/v1/nothing".to_string(),
        ] {
            let other = raw(addr, &ask("POST", &path)).await;
            assert_eq!(without_date(&other), without_date(&have), "{path}");
        }
        let delete = raw(addr, &ask("DELETE", &format!("{SESSION}/{id}"))).await;
        assert_eq!(without_date(&delete), without_date(&have));

        let put = raw(addr, &ask("PUT", SESSION)).await;
        assert!(put.starts_with("HTTP/1.1 405 "), "{put}");
        assert_eq!(header(&put, "allow"), Some("POST"));
        let post = raw(addr, &ask("POST", &format!("{SESSION}/{id}"))).await;
        assert!(post.starts_with("HTTP/1.1 405 "), "{post}");
        assert_eq!(header(&post, "allow"), Some("DELETE"));
        for method in ["GET", "HEAD"] {
            let read = raw(addr, &ask(method, SESSION)).await;
            assert!(read.starts_with("HTTP/1.1 404 "), "{read}");
        }

        let reply = client.post(SESSION, Vec::new()).await;
        assert!(
            reply
                .error(422, ErrorCode::Protocol)
                .message
                .contains("no message"),
            "{reply:?}"
        );
        let mut two = encode(&[hello()]).await;
        two.push(0);
        let reply = client.post(SESSION, two).await;
        reply.error(422, ErrorCode::Protocol);
    });
    let mut opts = options();
    opts.receive = None;
    with_server(repo, opts, |_, addr| async move {
        let request = format!(
            "POST /{SESSION} HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
        let post = raw(addr, &request).await;
        assert!(post.starts_with("HTTP/1.1 405 "), "{post}");
        assert_eq!(header(&post, "allow"), Some("GET, HEAD"));
    });
}

/// With a limit of one session, a second `session` request gets 503 with
/// `limit-exceeded`. A `DELETE` of the first session gets 204 with no body
/// and no `Content-Length`. Then a new session opens.
#[test]
fn a_session_past_the_limit_gets_503() {
    let tmp = TmpDir::new("limit");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = options();
    opts.max_sessions = 1;
    with_server(repo, opts, |client, addr| async move {
        let id = client.open().await;
        let reply = client.post(SESSION, encode(&[hello()]).await).await;
        assert!(reply.headers.get("retry-after").is_none());
        reply.error(503, ErrorCode::LimitExceeded);
        let request =
            format!("DELETE /{SESSION}/{id} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n");
        let deleted = raw(addr, &request).await;
        assert!(deleted.starts_with("HTTP/1.1 204 "), "{deleted}");
        assert_eq!(header(&deleted, "content-length"), None, "{deleted}");
        assert!(deleted.ends_with("\r\n\r\n"), "{deleted}");
        assert_eq!(client.delete(&id).await.status, 404);
        client.open().await;
    });
}

/// The endpoint checks a `Hello` before the session takes a slot. A bad
/// `Hello` gets its 422 also when the sessions are at the limit.
#[test]
fn a_bad_hello_is_422_also_when_the_sessions_are_at_the_limit() {
    let tmp = TmpDir::new("limit-bad-hello");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = options();
    opts.max_sessions = 1;
    with_server(repo, opts, |client, _| async move {
        client.open().await;
        let bad = Message::Hello(Hello {
            version: 1,
            agent: None,
            refs: vec!["a//b".into()],
            one_way: false,
        });
        let reply = client.post(SESSION, encode(&[bad]).await).await;
        reply.error(422, ErrorCode::InvalidRef);
        let reply = client.post(SESSION, encode(&[hello()]).await).await;
        reply.error(503, ErrorCode::LimitExceeded);
    });
}

/// Over HTTP/2, a `DELETE` gets 204 with no `Content-Length`. A `DELETE` of
/// an unknown session gets the empty 404.
#[test]
fn a_delete_over_http2_has_no_length() {
    let tmp = TmpDir::new("h2-delete");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = options();
    opts.tls = Some(ServerTls {
        cert_chain_pem: SERVER_CERT_PEM.to_vec(),
        key_pem: SERVER_KEY_PEM.to_vec(),
        key_passphrase: None,
        client_ca_pem: None,
    });
    with_server(repo, opts, |_, addr| async move {
        let client = Client::http2(addr).await;
        let id = client.open().await;
        let deleted = client.delete(&id).await;
        assert_eq!(deleted.protocol, Protocol::Http2);
        assert_eq!(deleted.status, 204);
        assert!(
            deleted.headers.get("content-length").is_none(),
            "{deleted:?}"
        );
        assert!(deleted.body.is_empty());
        let gone = client.delete(&id).await;
        assert_eq!(gone.status, 404);
        assert!(gone.body.is_empty());
    });
}

/// The status of each error code:
///
/// - `ref-mismatch` and `non-fast-forward` get 409.
/// - `protocol`, `missing-objects`, and `mode-refused` get 422.
/// - A server-side failure gets 500 with `internal`.
///
/// A failed step ends the session.
#[test]
fn errors_map_to_their_status() {
    let tmp = TmpDir::new("status");
    let src = block_on(source(tmp.path()));
    let repo = receiver(tmp.path(), RepoMode::Archive, "lock-timeout-secs=0\n");
    let [c1, c2] = src.commits;
    let [o1, o2] = src.objects;
    let held = repo.clone();
    with_server(repo.clone(), options(), |client, _| async move {
        // An expected commit on an absent ref.
        let id = client.open().await;
        client.step(&id, "objects", stream(&o1).await).await.ok();
        let reply = client
            .step(
                &id,
                "commit",
                encode(&[update(Expected::Commit(c2), c1)]).await,
            )
            .await;
        reply.error(409, ErrorCode::RefMismatch);
        assert_eq!(client.have(&id, Vec::new()).await.status, 404);

        // `main` goes to c1, and then to c2, which does not descend from c1.
        let id = client.open().await;
        client.step(&id, "objects", stream(&o1).await).await.ok();
        let reply = client
            .step(&id, "commit", encode(&[update(Expected::Absent, c1)]).await)
            .await;
        reply.ok();
        let id = client.open().await;
        client.step(&id, "objects", stream(&o2).await).await.ok();
        let reply = client
            .step(
                &id,
                "commit",
                encode(&[update(Expected::Commit(c1), c2)]).await,
            )
            .await;
        reply.error(409, ErrorCode::NonFastForward);

        // A body that is no frame.
        let id = client.open().await;
        client
            .step(&id, "have", vec![0, 0, 0])
            .await
            .error(422, ErrorCode::Protocol);
        assert_eq!(client.have(&id, Vec::new()).await.status, 404);

        // A commit whose objects never came.
        let id = client.open().await;
        let reply = client
            .step(
                &id,
                "commit",
                encode(&[update(Expected::Commit(c1), c2)]).await,
            )
            .await;
        reply.error(422, ErrorCode::MissingObjects);

        // Another holder of the update lock. The lock timeout is 0, so the
        // commit does not wait for the lock.
        let id = client.open().await;
        client.step(&id, "objects", stream(&o2).await).await.ok();
        let guard = held.begin_update().await.unwrap();
        let reply = client
            .step(
                &id,
                "commit",
                encode(&[update(Expected::Commit(c1), c2)]).await,
            )
            .await;
        reply.error(500, ErrorCode::Internal);
        guard.finish().await.unwrap();
    });
    assert_eq!(block_on(repo.resolve_rev("main", false)).unwrap(), Some(c1));

    // A `bare` repository takes no push from a user other than root.
    if !is_root() {
        let tmp = TmpDir::new("status-bare");
        let repo = receiver(tmp.path(), RepoMode::Bare, "");
        with_server(repo, options(), |client, _| async move {
            let reply = client.post(SESSION, encode(&[hello()]).await).await;
            reply.error(422, ErrorCode::ModeRefused);
        });
    }
}

/// Returns `true` if the process runs as root. The function reads the user
/// id from `/proc/self/status`.
fn is_root() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        == Some("0")
}

/// With one upload in flight and `parallel_uploads` 1, a second `objects`
/// request gets `limit-exceeded`. This refusal ends the session, so the first
/// request fails with `protocol`.
#[test]
fn objects_past_parallel_uploads_is_limit_exceeded() {
    let tmp = TmpDir::new("parallel");
    let src = block_on(source(tmp.path()));
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = options();
    opts.parallel_uploads = 1;
    let first = of_type(&src.objects[0], ObjectType::DirMeta);
    with_server(repo.clone(), opts, |client, _| async move {
        let id = client.open().await;
        let body = waiting_body(&first).await;
        let (waiting, second) = future::zip(
            client.objects_streamed(&id, |mut w| async move {
                send_piece(&mut w, &body).await;
                Timer::after(Duration::from_secs(30)).await;
            }),
            async {
                client.until_read(&id, first.name).await;
                client.step(&id, "objects", stream(&[]).await).await
            },
        )
        .await;
        second.error(422, ErrorCode::LimitExceeded);
        let e = waiting.error(422, ErrorCode::Protocol);
        assert!(e.message.contains("the session was aborted"), "{e:?}");
        assert_eq!(client.have(&id, Vec::new()).await.status, 404);
    });
    assert_released(&repo);
}

/// A `commit` while an `objects` request is in flight gets `protocol`, and
/// the session ends.
#[test]
fn a_commit_during_objects_is_protocol() {
    let tmp = TmpDir::new("commit-during");
    let src = block_on(source(tmp.path()));
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let commit = src.commits[0];
    let first = of_type(&src.objects[0], ObjectType::DirMeta);
    with_server(repo.clone(), options(), |client, _| async move {
        let id = client.open().await;
        let body = waiting_body(&first).await;
        let (waiting, committed) = future::zip(
            client.objects_streamed(&id, |mut w| async move {
                send_piece(&mut w, &body).await;
                Timer::after(Duration::from_secs(30)).await;
            }),
            async {
                client.until_read(&id, first.name).await;
                let body = encode(&[update(Expected::Absent, commit)]).await;
                client.step(&id, "commit", body).await
            },
        )
        .await;
        committed.error(422, ErrorCode::Protocol);
        waiting.error(422, ErrorCode::Protocol);
        assert_eq!(client.have(&id, Vec::new()).await.status, 404);
    });
    assert_released(&repo);
}

/// An object that does not hash to its name fails its request with
/// `checksum-mismatch`. The other `objects` request of the session fails too.
#[test]
fn an_error_in_one_stream_fails_the_other() {
    let tmp = TmpDir::new("one-fails");
    let src = block_on(source(tmp.path()));
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let first = of_type(&src.objects[0], ObjectType::DirMeta);
    with_server(repo.clone(), options(), |client, _| async move {
        let id = client.open().await;
        let body = waiting_body(&first).await;
        let corrupt = Obj {
            name: ObjectName::new(Checksum::sha256(b"not these bytes"), ObjectType::DirMeta),
            encoding: Encoding::Raw,
            bytes: b"bytes".to_vec(),
        };
        let (waiting, failed) = future::zip(
            client.objects_streamed(&id, |mut w| async move {
                send_piece(&mut w, &body).await;
                Timer::after(Duration::from_secs(30)).await;
            }),
            async {
                client.until_read(&id, first.name).await;
                client.step(&id, "objects", stream(&[corrupt]).await).await
            },
        )
        .await;
        failed.error(422, ErrorCode::ChecksumMismatch);
        waiting.error(422, ErrorCode::Protocol);
        assert_eq!(client.have(&id, Vec::new()).await.status, 404);
    });
    assert_released(&repo);
}

/// A `DELETE` during an upload ends the session. The upload gets `protocol`,
/// and the next request gets 404. The staging directory goes, and the server
/// releases the repository lock.
#[test]
fn a_delete_during_an_upload_aborts_the_session() {
    let tmp = TmpDir::new("delete");
    let src = block_on(source(tmp.path()));
    let repo = receiver(tmp.path(), RepoMode::Archive, "lock-timeout-secs=0\n");
    let first = of_type(&src.objects[0], ObjectType::DirMeta);
    with_server(repo.clone(), options(), |client, _| async move {
        let id = client.open().await;
        let body = waiting_body(&first).await;
        let (waiting, deleted) = future::zip(
            client.objects_streamed(&id, |mut w| async move {
                send_piece(&mut w, &body).await;
                Timer::after(Duration::from_secs(30)).await;
            }),
            async {
                client.until_read(&id, first.name).await;
                client.delete(&id).await
            },
        )
        .await;
        assert_eq!(deleted.status, 204);
        assert!(deleted.body.is_empty());
        let e = waiting.error(422, ErrorCode::Protocol);
        assert!(e.message.contains("deleted"), "{e:?}");
        assert_eq!(client.have(&id, Vec::new()).await.status, 404);
    });
    assert_released(&repo);
}

/// While the session commits, a second `commit` and a `DELETE` get
/// `protocol`. The session keeps its slot, so with a limit of one session, a
/// new session gets 503. The commit continues to its end and then frees the
/// slot.
#[test]
fn a_session_that_commits_keeps_its_commit_and_its_slot() {
    let tmp = TmpDir::new("committing");
    let src = block_on(source(tmp.path()));
    let repo = receiver(tmp.path(), RepoMode::Archive, "lock-timeout-secs=60\n");
    let commit = src.commits[0];
    let objects = src.objects[0].clone();
    let held = repo.clone();
    let mut opts = options();
    opts.max_sessions = 1;
    with_server(repo.clone(), opts, |client, _| async move {
        let id = client.open().await;
        client
            .step(&id, "objects", stream(&objects).await)
            .await
            .ok();
        // The commit waits for the update lock that the test holds. Of two
        // commits, the one that comes second finds that the session commits.
        let guard = held.begin_update().await.unwrap();
        let body = encode(&[update(Expected::Absent, commit)]).await;
        let mut first = Box::pin(client.step(&id, "commit", body.clone()));
        let mut second = Box::pin(client.step(&id, "commit", body));
        let (which, refused) = future::or(async { (0, first.as_mut().await) }, async {
            (1, second.as_mut().await)
        })
        .await;
        let waiting = if which == 0 { second } else { first };
        let e = refused.error(422, ErrorCode::Protocol);
        assert!(e.message.contains("the session is committing"), "{e:?}");
        let reply = client.post(SESSION, encode(&[hello()]).await).await;
        reply.error(503, ErrorCode::LimitExceeded);
        let e = client.delete(&id).await.error(422, ErrorCode::Protocol);
        assert!(e.message.contains("the session is committing"), "{e:?}");
        guard.finish().await.unwrap();
        assert!(matches!(waiting.await.ok(), Message::CommitReply(_)));
        assert_eq!(client.have(&id, Vec::new()).await.status, 404);
        client.open().await;
    });
    assert_eq!(
        block_on(repo.resolve_rev("main", false)).unwrap(),
        Some(commit)
    );
}

/// The endpoint aborts a session with no request for the idle timeout. The
/// endpoint does not abort a session whose upload delivers bytes slowly,
/// over several idle timeouts.
#[test]
fn an_idle_session_is_aborted_and_a_slow_upload_is_not() {
    let tmp = TmpDir::new("idle");
    let src = block_on(source(tmp.path()));
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let idle = Duration::from_millis(500);
    let mut opts = options();
    opts.session_idle_timeout = idle;
    let objects = src.objects[0].clone();
    with_server(repo.clone(), opts, |client, _| async move {
        let idle_id = client.open().await;
        let busy_id = client.open().await;
        let body = stream(&objects).await;
        let reply = client
            .objects_streamed(&busy_id, |mut w| async move {
                let piece = body.len().div_ceil(20);
                for chunk in body.chunks(piece) {
                    assert!(send_piece(&mut w, chunk).await);
                    Timer::after(idle / 5).await;
                }
                w.close().await.unwrap();
            })
            .await;
        let Message::ObjectsReply(r) = reply.ok() else {
            panic!("no ObjectsReply");
        };
        assert_eq!(r.objects as usize, objects.len());
        assert_eq!(client.have(&idle_id, Vec::new()).await.status, 404);
        let Message::HaveReply(_) = client.have(&busy_id, Vec::new()).await.ok() else {
            panic!("no HaveReply");
        };
    });
}

/// A request body that delivers no byte for the idle timeout fails its
/// request and aborts the session.
#[test]
fn a_silent_body_aborts_the_session() {
    let tmp = TmpDir::new("silent");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = options();
    opts.session_idle_timeout = Duration::from_millis(500);
    with_server(repo.clone(), opts, |client, _| async move {
        let id = client.open().await;
        let start = object_start().await;
        let started = Instant::now();
        let reply = client
            .objects_streamed(&id, |mut w| async move {
                send_piece(&mut w, &start).await;
                Timer::after(Duration::from_secs(30)).await;
            })
            .await;
        assert!(started.elapsed() < Duration::from_secs(20));
        let e = reply.error(422, ErrorCode::Protocol);
        assert!(e.message.contains("delivered no byte"), "{e:?}");
        assert_eq!(client.have(&id, Vec::new()).await.status, 404);
    });
    assert_released(&repo);
}

/// A connection that closes in the middle of an `objects` body ends the
/// session long before the idle timeout. The other request of the session
/// gets the cause of a request that ended before its response. Then a
/// request of the session gets 404.
#[test]
fn a_cut_request_ends_the_session() {
    let tmp = TmpDir::new("cut");
    let src = block_on(source(tmp.path()));
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let first = of_type(&src.objects[0], ObjectType::DirMeta);
    let file = of_type(&src.objects[0], ObjectType::File);
    with_server(repo.clone(), options(), |client, addr| async move {
        let id = client.open().await;
        let body = waiting_body(&first).await;
        let (waiting, ()) = future::zip(
            client.objects_streamed(&id, |mut w| async move {
                send_piece(&mut w, &body).await;
                Timer::after(Duration::from_secs(30)).await;
            }),
            async {
                client.until_read(&id, first.name).await;
                let mut stream = ostrya_rt::TcpStream::connect("127.0.0.1", addr.port())
                    .await
                    .unwrap();
                let head = format!(
                    "POST /{SESSION}/{id}/objects HTTP/1.1\r\nhost: x\r\n\
                     content-length: 1048576\r\n\r\n"
                );
                let mut writer = FrameWriter::new(Vec::new());
                write_object(&mut writer, &file).await;
                let mut cut = writer.into_inner();
                // The first byte of the length of the next frame.
                cut.push(0);
                stream.write_all(head.as_bytes()).await.unwrap();
                stream.write_all(&cut).await.unwrap();
                stream.flush().await.unwrap();
                client.until_read(&id, file.name).await;
                drop(stream);
            },
        )
        .await;
        let e = waiting.error(422, ErrorCode::Protocol);
        assert!(
            e.message
                .contains("a request of the session ended before its response"),
            "{e:?}"
        );
        assert_eq!(client.have(&id, Vec::new()).await.status, 404);
    });
    assert_released(&repo);
}

/// The bytes before and after the value of a detached metadata dict with the
/// one entry `k`. The value is an `ay` of `len` zero bytes. `len` must be
/// 64 KiB or more.
fn one_entry_dict(len: usize) -> ([u8; 8], Vec<u8>) {
    let prefix = *b"k\0\0\0\0\0\0\0";
    let mut suffix = vec![0, b'a', b'y'];
    suffix.extend_from_slice(&2u32.to_le_bytes());
    suffix.extend_from_slice(&u32::try_from(len + 15).unwrap().to_le_bytes());
    (prefix, suffix)
}

/// In one session, two `objects` requests that each carry a detached metadata
/// object of 65 MiB are more than the session cap. The second request gets
/// `limit-exceeded`.
#[test]
fn detached_metadata_past_the_session_cap_is_limit_exceeded() {
    let tmp = TmpDir::new("metacap");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let len = 65 << 20;
    with_server(repo.clone(), options(), |client, _| async move {
        let id = client.open().await;
        let header = |seed: &[u8]| {
            Message::ObjectHeader(ObjectHeader {
                name: ObjectName::new(Checksum::sha256(seed), ObjectType::CommitMeta),
                encoding: Encoding::Raw,
            })
        };
        let first = client
            .objects_streamed(&id, |w| async move {
                let mut writer = FrameWriter::new(w);
                let (prefix, suffix) = one_entry_dict(len);
                let zeros = vec![0u8; 64 * 1024];
                writer.write_message(&header(b"first")).await.unwrap();
                writer.write_object_data(&prefix).await.unwrap();
                for _ in 0..len / zeros.len() {
                    writer.write_object_data(&zeros).await.unwrap();
                }
                writer.write_object_data(&suffix).await.unwrap();
                writer.end_object().await.unwrap();
                writer.write_message(&Message::ObjectsEnd).await.unwrap();
                writer.into_inner().close().await.unwrap();
            })
            .await;
        let Message::ObjectsReply(r) = first.ok() else {
            panic!("no ObjectsReply");
        };
        assert_eq!(r.objects, 1);
        // The second dict does not need a valid form, because the cap refuses
        // it before its end. The response then ends the writer.
        let second = client
            .objects_streamed(&id, |w| async move {
                let mut writer = FrameWriter::new(w);
                let zeros = vec![0u8; 64 * 1024];
                let _: ostrya::push::Result<()> = async {
                    writer.write_message(&header(b"second")).await?;
                    for _ in 0..2 * len / zeros.len() {
                        writer.write_object_data(&zeros).await?;
                    }
                    Ok(())
                }
                .await;
            })
            .await;
        let e = second.error(422, ErrorCode::LimitExceeded);
        assert!(e.message.contains("detached metadata"), "{e:?}");
        assert_eq!(client.have(&id, Vec::new()).await.status, 404);
    });
    assert_released(&repo);
}

/// `bind` refuses a receive endpoint with no authentication method, a
/// `parallel_uploads` outside `1..=31`, a zero idle timeout, and a zero
/// session limit.
#[test]
fn bad_receive_options_are_refused() {
    let tmp = TmpDir::new("options");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let cases: [fn(&mut ServeOptions); 5] = [
        |o| o.allow_anonymous_push = false,
        |o| o.parallel_uploads = 0,
        |o| o.parallel_uploads = 32,
        |o| o.session_idle_timeout = Duration::ZERO,
        |o| o.max_sessions = 0,
    ];
    for change in cases {
        let mut opts = options();
        change(&mut opts);
        let err = block_on(ostrya_server::bind(repo.clone(), opts))
            .err()
            .unwrap();
        assert!(matches!(err, ostrya_server::Error::Options(_)), "{err}");
    }
    let mut opts = options();
    opts.parallel_uploads = 31;
    block_on(ostrya_server::bind(repo, opts)).unwrap();
}

// ---------------------------------------------------------------------------
// Authentication.
// ---------------------------------------------------------------------------

const ALICE: &str = "alice-token";
const BOB: &str = "bob-token";

/// A credential file with a comment, an empty line, and the lines of
/// `alice` and `bob`.
fn credentials() -> Vec<u8> {
    let digest = |token: &str| Checksum::sha256(token.as_bytes()).to_hex();
    format!(
        "# the push credentials\n\nalice:{}\nbob:{}\n",
        digest(ALICE),
        digest(BOB)
    )
    .into_bytes()
}

/// The server TLS files. If `client_ca` is `true`, the fixture CA is also the
/// client CA.
fn server_tls(client_ca: bool) -> ServerTls {
    ServerTls {
        cert_chain_pem: SERVER_CERT_PEM.to_vec(),
        key_pem: SERVER_KEY_PEM.to_vec(),
        key_passphrase: None,
        client_ca_pem: client_ca.then(|| CA_PEM.to_vec()),
    }
}

/// The options of a server whose one method is the credential file.
fn credential_options() -> ServeOptions {
    let mut opts = options();
    opts.allow_anonymous_push = false;
    opts.credentials = Some(credentials());
    opts
}

fn bearer(token: &str) -> Option<BearerToken> {
    Some(BearerToken {
        token: token.into(),
    })
}

fn basic(user: &str, token: &str) -> Option<BasicAuth> {
    Some(BasicAuth {
        user: user.into(),
        password: token.into(),
    })
}

/// The `WWW-Authenticate` values of `reply`.
fn challenges(reply: &Reply) -> Vec<&str> {
    reply
        .headers
        .get_all("www-authenticate")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect()
}

/// Checks that `reply` is 401 with an `unauthorized` frame and the two
/// challenges.
fn assert_401(reply: &Reply) {
    reply.error(401, ErrorCode::Unauthorized);
    assert_eq!(
        challenges(reply),
        [r#"Bearer realm="ostrya""#, r#"Basic realm="ostrya""#]
    );
}

/// The status, the headers other than `date`, and the body of `reply`.
fn without_date_reply(reply: &Reply) -> (u16, String, Vec<u8>) {
    let mut headers = reply.headers.clone();
    headers.remove("date");
    (reply.status, format!("{headers:?}"), reply.body.clone())
}

/// A name for a `have` that the session does not hold.
fn absent() -> ObjectName {
    ObjectName::new(Checksum::sha256(b"absent"), ObjectType::DirTree)
}

/// Over TLS, the endpoint accepts `Hello` with a bearer token, with Basic,
/// and with a client certificate. The session then takes the next step of
/// its owner. A `Hello` with no credential gets 401 with `unauthorized`. A
/// credential that matches no line gets the same 401, also beside a valid
/// client certificate.
#[test]
fn each_method_opens_a_session_and_a_bad_credential_is_401() {
    let tmp = TmpDir::new("methods");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = credential_options();
    opts.tls = Some(server_tls(true));
    with_server(repo, opts, |_, addr| async move {
        let identity = Some((CLIENT_CERT_PEM, CLIENT_KEY_PEM));
        let mut by_bearer = Client::tls(addr, false, None).await;
        by_bearer.bearer = bearer(ALICE);
        let mut by_basic = Client::tls(addr, true, None).await;
        by_basic.basic = basic("bob", BOB);
        let by_cert = Client::tls(addr, false, identity).await;
        for client in [&by_bearer, &by_basic, &by_cert] {
            let id = client.open().await;
            assert!(matches!(
                client.have(&id, vec![absent()]).await.ok(),
                Message::HaveReply(_)
            ));
            assert_eq!(client.delete(&id).await.status, 204);
        }

        let nobody = Client::tls(addr, false, None).await;
        assert_401(&nobody.post(SESSION, encode(&[hello()]).await).await);
        let mut wrong = Client::tls(addr, false, identity).await;
        for (token, user) in [(bearer("other"), None), (None, basic("alice", BOB))] {
            wrong.bearer = token;
            wrong.basic = user;
            assert_401(&wrong.post(SESSION, encode(&[hello()]).await).await);
        }
    });
}

/// With a client CA as the one method, a client with no certificate gets
/// 403 with `unauthorized` and no challenge. A client with a certificate
/// opens a session.
#[test]
fn a_client_ca_alone_refuses_a_client_with_no_certificate() {
    let tmp = TmpDir::new("client-ca");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = options();
    opts.allow_anonymous_push = false;
    opts.tls = Some(server_tls(true));
    with_server(repo, opts, |_, addr| async move {
        let nobody = Client::tls(addr, false, None).await;
        let reply = nobody.post(SESSION, encode(&[hello()]).await).await;
        reply.error(403, ErrorCode::Unauthorized);
        assert!(challenges(&reply).is_empty(), "{reply:?}");
        let identity = Some((CLIENT_CERT_PEM, CLIENT_KEY_PEM));
        Client::tls(addr, true, identity).await.open().await;
    });
}

/// Over plain HTTP, a bearer or Basic credential gets 403 with
/// `unauthorized`, also on a server that allows anonymous push. On that
/// server, a request with no credential pushes anonymously. With
/// `allow_cleartext_credentials`, the endpoint accepts both credentials.
#[test]
fn a_credential_over_plain_http_is_403_unless_allowed() {
    let tmp = TmpDir::new("cleartext");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = credential_options();
    opts.allow_anonymous_push = true;
    with_server(repo.clone(), opts.clone(), |client, addr| async move {
        client.open().await;
        for (token, user) in [(bearer(ALICE), None), (None, basic("alice", ALICE))] {
            let mut client = Client::new(addr).await;
            client.bearer = token;
            client.basic = user;
            let reply = client.post(SESSION, encode(&[hello()]).await).await;
            let refusal = reply.error(403, ErrorCode::Unauthorized);
            assert!(refusal.message.contains("plain HTTP"), "{refusal:?}");
        }
    });
    opts.allow_cleartext_credentials = true;
    with_server(repo, opts, |_, addr| async move {
        for (token, user) in [(bearer(ALICE), None), (None, basic("alice", ALICE))] {
            let mut client = Client::new(addr).await;
            client.bearer = token;
            client.basic = user;
            client.open().await;
        }
    });
}

/// A request of a session with another credential, or with none, gets the
/// bytes of an unknown id. The session stays. A Basic credential with the
/// name of the line of a bearer token is the same owner as that token.
#[test]
fn another_credential_gets_the_404_of_an_unknown_id() {
    let tmp = TmpDir::new("owner");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = credential_options();
    opts.allow_anonymous_push = true;
    opts.allow_cleartext_credentials = true;
    with_server(repo, opts, |anonymous, addr| async move {
        let mut alice = Client::new(addr).await;
        alice.bearer = bearer(ALICE);
        let mut bob = Client::new(addr).await;
        bob.bearer = bearer(BOB);
        let mut alice_basic = Client::new(addr).await;
        alice_basic.basic = basic("alice", ALICE);
        let id = alice.open().await;
        let unknown = "0".repeat(64);
        let reference = without_date_reply(&bob.have(&unknown, vec![absent()]).await);
        assert_eq!(reference.0, 404);
        assert!(reference.2.is_empty());
        for other in [&bob, &anonymous] {
            for step in ["have", "objects", "commit"] {
                let reply = other.step(&id, step, Vec::new()).await;
                assert_eq!(without_date_reply(&reply), reference, "{step}");
            }
            assert_eq!(other.delete(&id).await.status, 404);
        }
        assert!(matches!(
            alice_basic.have(&id, vec![absent()]).await.ok(),
            Message::HaveReply(_)
        ));
        assert_eq!(alice.delete(&id).await.status, 204);
    });
}

/// More than one `Authorization` header gets 401, also over plain HTTP.
#[test]
fn more_than_one_authorization_header_is_401() {
    let tmp = TmpDir::new("two-headers");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = credential_options();
    opts.allow_anonymous_push = true;
    with_server(repo, opts, |_, addr| async move {
        let token = format!("authorization: Bearer {ALICE}\r\n");
        let request = format!(
            "POST /{SESSION} HTTP/1.1\r\nhost: x\r\n{token}{token}\
             content-length: 0\r\nconnection: close\r\n\r\n"
        );
        let response = raw(addr, &request).await;
        assert!(response.starts_with("HTTP/1.1 401 "), "{response}");
        assert!(
            response.contains("www-authenticate: Bearer realm=\"ostrya\"\r\n"),
            "{response}"
        );
        assert!(response.contains("more than one Authorization header"));
    });
}

/// A `GET` and a `HEAD` of the archive view ignore `Authorization`. A read
/// with Basic over plain HTTP succeeds on a server whose receive endpoint
/// takes no credential over plain HTTP.
#[test]
fn a_read_ignores_authorization() {
    let tmp = TmpDir::new("read");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = credential_options();
    opts.allow_anonymous_push = true;
    with_server(repo, opts, |_, addr| async move {
        let basic = ostrya::base64::encode(format!("alice:{ALICE}").as_bytes());
        for method in ["GET", "HEAD"] {
            for auth in [
                format!("authorization: Basic {basic}\r\n"),
                format!("authorization: Basic {basic}\r\nauthorization: Bearer x\r\n"),
            ] {
                let request = format!(
                    "{method} /config HTTP/1.1\r\nhost: x\r\n{auth}connection: close\r\n\r\n"
                );
                let response = raw(addr, &request).await;
                assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
            }
        }
    });
}

/// `bind` refuses a malformed credential line with `Error::Credentials`,
/// which names the line and holds no byte of it. A file with no credential
/// line gives no authentication method.
#[test]
fn a_malformed_credential_line_is_refused_at_bind() {
    let tmp = TmpDir::new("malformed");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = credential_options();
    let mut file = credentials();
    file.extend_from_slice(b"carol secret\n");
    opts.credentials = Some(file);
    let err = block_on(ostrya_server::bind(repo.clone(), opts))
        .err()
        .unwrap();
    assert!(
        matches!(err, ostrya_server::Error::Credentials { line: 5, .. }),
        "{err}"
    );
    let text = err.to_string();
    assert!(text.contains("line 5"), "{text}");
    assert!(
        !text.contains("carol") && !text.contains("secret"),
        "{text}"
    );

    let mut opts = credential_options();
    opts.credentials = Some(b"# no credential\n".to_vec());
    let err = block_on(ostrya_server::bind(repo.clone(), opts.clone()))
        .err()
        .unwrap();
    assert!(matches!(err, ostrya_server::Error::Options(_)), "{err}");
    opts.allow_anonymous_push = true;
    block_on(ostrya_server::bind(repo, opts)).unwrap();
}

/// Over plain HTTP, `bind` refuses a receive endpoint whose one method is
/// the credential file, because the endpoint refuses each credential over
/// plain HTTP. `allow_cleartext_credentials`, anonymous push, and TLS each
/// let it bind.
#[test]
fn a_credential_file_alone_over_plain_http_is_refused_at_bind() {
    let tmp = TmpDir::new("plain-file");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let err = block_on(ostrya_server::bind(repo.clone(), credential_options()))
        .err()
        .unwrap();
    assert!(matches!(err, ostrya_server::Error::Options(_)), "{err}");
    assert!(err.to_string().contains("plain HTTP"), "{err}");
    let cases: [fn(&mut ServeOptions); 3] = [
        |o| o.allow_cleartext_credentials = true,
        |o| o.allow_anonymous_push = true,
        |o| o.tls = Some(server_tls(false)),
    ];
    for change in cases {
        let mut opts = credential_options();
        change(&mut opts);
        block_on(ostrya_server::bind(repo.clone(), opts)).unwrap();
    }
}

/// With a client CA that did not sign the client certificate, the TLS
/// handshake of a client that presents that certificate fails. The request
/// gets no response. The handshake of a client with no certificate
/// succeeds, and its request gets 403.
#[test]
fn a_client_certificate_the_client_ca_did_not_sign_fails_the_handshake() {
    let tmp = TmpDir::new("other-ca");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = options();
    opts.allow_anonymous_push = false;
    opts.tls = Some(ServerTls {
        client_ca_pem: Some(UNTRUSTED_CERT_PEM.to_vec()),
        ..server_tls(false)
    });
    with_server(repo, opts, |_, addr| async move {
        for http2 in [false, true] {
            let identity = Some((CLIENT_CERT_PEM, CLIENT_KEY_PEM));
            let client = Client::tls(addr, http2, identity).await;
            let mut request =
                UploadRequest::path(SESSION, UploadBody::bytes(encode(&[hello()]).await));
            request.method = UploadMethod::Post;
            assert!(client.fetcher.upload(request).await.is_err(), "{http2}");
            let nobody = Client::tls(addr, http2, None).await;
            let reply = nobody.post(SESSION, encode(&[hello()]).await).await;
            reply.error(403, ErrorCode::Unauthorized);
        }
    });
}

/// The endpoint authorizes each stream of one HTTP/2 connection again. A
/// request to the session of a bearer token gets these responses:
///
/// - with no `Authorization` header: 401
/// - with the token of another line: the 404 of an unknown id
/// - with Basic of the same line: the reply of its step
///
/// One client opens a session with its client certificate and a session
/// with a token, on one connection. A request of each owner to the session of
/// the other owner gets the 404 of an unknown id.
#[test]
fn each_stream_of_one_http2_connection_is_authorized_again() {
    let tmp = TmpDir::new("h2-owners");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let mut opts = credential_options();
    opts.tls = Some(server_tls(true));
    with_server(repo, opts, |_, addr| async move {
        let mut client = Client::http2(addr).await;
        client.bearer = bearer(ALICE);
        let id = client.open().await;
        client.bearer = None;
        let reply = client.have(&id, vec![absent()]).await;
        assert_eq!(reply.protocol, Protocol::Http2);
        assert_401(&reply);
        client.bearer = bearer(BOB);
        let reply = client.have(&id, vec![absent()]).await;
        assert_eq!((reply.status, reply.body.is_empty()), (404, true));
        client.bearer = None;
        client.basic = basic("alice", ALICE);
        assert!(matches!(
            client.have(&id, vec![absent()]).await.ok(),
            Message::HaveReply(_)
        ));
        assert_eq!(client.delete(&id).await.status, 204);

        let identity = Some((CLIENT_CERT_PEM, CLIENT_KEY_PEM));
        let mut client = Client::tls(addr, true, identity).await;
        let by_cert = client.open().await;
        client.bearer = bearer(ALICE);
        let by_token = client.open().await;
        for (owner, other) in [(&by_token, &by_cert), (&by_cert, &by_token)] {
            let reply = client.have(other, vec![absent()]).await;
            assert_eq!(reply.protocol, Protocol::Http2);
            assert_eq!((reply.status, reply.body.is_empty()), (404, true));
            assert!(matches!(
                client.have(owner, vec![absent()]).await.ok(),
                Message::HaveReply(_)
            ));
            client.bearer = None;
        }
    });
}

/// A refusal before the body waits at most 5 seconds for the body, also with
/// the default idle timeout of 300 seconds. Then the refusal goes out with
/// `Connection: close`. If the idle timeout is less than 5 seconds, the
/// refusal waits for the idle timeout.
#[test]
fn a_refusal_with_a_silent_body_answers_within_5_seconds() {
    let tmp = TmpDir::new("drain");
    let repo = receiver(tmp.path(), RepoMode::Archive, "");
    let head = |path: &str| {
        format!(
            "POST /{path} HTTP/1.1\r\nhost: x\r\ncontent-length: 1000\r\n\r\n\
             ten bytes."
        )
    };
    let mut opts = credential_options();
    opts.allow_cleartext_credentials = true;
    assert_eq!(opts.session_idle_timeout, Duration::from_secs(300));
    with_server(repo.clone(), opts, |_, addr| async move {
        let started = Instant::now();
        let response = raw(addr, &head(SESSION)).await;
        let elapsed = started.elapsed();
        assert!(response.starts_with("HTTP/1.1 401 "), "{response}");
        assert_eq!(header(&response, "connection"), Some("close"), "{response}");
        assert!(elapsed >= Duration::from_millis(4900), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
    });
    let mut opts = options();
    opts.session_idle_timeout = Duration::from_millis(500);
    with_server(repo, opts, |_, addr| async move {
        let started = Instant::now();
        let unknown = format!("{SESSION}/{}/have", "0".repeat(64));
        let response = raw(addr, &head(&unknown)).await;
        let elapsed = started.elapsed();
        assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
        assert_eq!(header(&response, "connection"), Some("close"), "{response}");
        assert!(elapsed >= Duration::from_millis(400), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(4), "{elapsed:?}");
    });
}
