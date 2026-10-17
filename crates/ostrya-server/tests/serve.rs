//! Tests of the server over a `bare-user` repository:
//!
//! - the archive view over HTTP/1.1, and over TLS with HTTP/2 and HTTP/1.1
//! - the 404 of a refused path and of an absent path
//! - `HEAD`
//! - client certificates
//! - the stop on drop
//! - the ref listing and its query, and `PullSession::fetch_refs` over HTTP
//! - over an archive repository, a pull of the chain of static deltas that
//!   the ref listing advertises

use std::future::Future;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use futures_lite::{AsyncReadExt, AsyncWriteExt, future};
use ostrya::access::{AuthItem, ClientAccess, ReadAccess};
use ostrya::fetch::{
    ClientIdentity, FetchRequest, Fetched, Fetcher, FetcherOptions, Protocol, Proxy, TlsOptions,
    TrustRoots,
};
use ostrya::remote::PullSession;
use ostrya::verify::PullTrust;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DeltaOptions,
    MutableTree, ObjectType, PullOptions, PullProgress, ReceivePolicies, RefSelector, Repo,
    RepoMode, Summary, Type, Value, loose_path,
};
use ostrya_rt::block_on;
use ostrya_server::{ServeOptions, ServerTls};

const CA_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/ca.pem");
const SERVER_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.pem");
const SERVER_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.key.pem");
const CLIENT_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/client.pem");
const CLIENT_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/client.key.pem");
const UNTRUSTED_CERT_PEM: &[u8] =
    include_bytes!("../../../tests/fixtures/tls/server-untrusted.pem");
const UNTRUSTED_KEY_PEM: &[u8] =
    include_bytes!("../../../tests/fixtures/tls/server-untrusted.key.pem");

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ostrya-server-{}-{tag}-{}",
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

/// A `bare-user` repository with a commit of one file and one symlink on
/// `main`, and the checksum of the file object.
async fn repo(base: &Path) -> (PathBuf, Repo, Checksum, Checksum) {
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello"), b"hello ostree\n").unwrap();
    symlink("hello", src.join("link")).unwrap();
    let path = base.join("repo");
    let repo = Repo::create(&path, CreateOptions::new(RepoMode::BareUser))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = std::fs::File::open(&src).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                timestamp: Some(1_700_000_000),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("main", Some(&commit));
    txn.commit().await.unwrap();
    let file = repo
        .traverse_commit(&commit, 0)
        .await
        .unwrap()
        .into_iter()
        .find(|name| name.ty == ObjectType::File)
        .unwrap()
        .checksum;
    (path, repo, commit, file)
}

/// The read rights of an anonymous client under the client groups of the
/// config that `repo` read.
fn anyone(repo: &Repo) -> ReadAccess {
    let access = ClientAccess::from_config(repo.config(), repo.path()).unwrap();
    ReadAccess::new(Arc::new(access), AuthItem::Anonymous, None)
}

fn object_path(ty: ObjectType, checksum: &Checksum) -> String {
    format!("objects/{}", loose_path(checksum, ty, RepoMode::Archive))
}

/// Runs `test` with the addresses of a server over `repo`, then drops the
/// server.
fn with_server<F, Fut>(repo: Repo, opts: ServeOptions, test: F)
where
    F: FnOnce(Vec<SocketAddr>) -> Fut,
    Fut: Future<Output = ()>,
{
    block_on(async {
        let server = ostrya_server::bind(repo, opts).await.unwrap();
        let addrs = server.local_addrs().to_vec();
        future::or(
            async {
                server.run().await.unwrap();
                unreachable!("the server runs until it is dropped");
            },
            test(addrs),
        )
        .await
    });
}

fn local() -> ServeOptions {
    let mut opts = ServeOptions::default();
    opts.listen = vec!["127.0.0.1:0".parse().unwrap()];
    opts
}

fn tls(client_ca: bool) -> ServeOptions {
    let mut opts = local();
    opts.tls = Some(ServerTls {
        cert_chain_pem: SERVER_CERT_PEM.to_vec(),
        key_pem: SERVER_KEY_PEM.to_vec(),
        key_passphrase: None,
    });
    opts.client_ca_pem = client_ca.then(|| CA_PEM.to_vec());
    opts
}

async fn fetcher(url: String, http2: bool, identity: Option<(&[u8], &[u8])>) -> Fetcher {
    let mut options = FetcherOptions::new(url);
    options.proxy = Proxy::None;
    options.http2 = http2;
    options.max_retries = 0;
    options.tls = TlsOptions {
        roots: TrustRoots::Pem(CA_PEM.to_vec()),
        client_identity: identity.map(|(cert, key)| ClientIdentity {
            cert_chain_pem: cert.to_vec(),
            key_pem: key.to_vec(),
            key_passphrase: None,
        }),
    };
    Fetcher::new(options).await.unwrap()
}

/// The body, the `Content-Length`, and the protocol of a fetch.
async fn fetch(
    fetcher: &Fetcher,
    path: &str,
) -> ostrya::fetch::Result<(Vec<u8>, Option<u64>, Protocol)> {
    let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::path(path)).await? else {
        panic!("not modified");
    };
    let len = body.content_length();
    let protocol = body.protocol();
    let mut out = Vec::new();
    body.read_to_end(&mut out).await.unwrap();
    Ok((out, len, protocol))
}

fn status(result: ostrya::fetch::Result<(Vec<u8>, Option<u64>, Protocol)>) -> u16 {
    match result {
        Err(ostrya::fetch::Error::HttpStatus { status, .. }) => status,
        other => panic!("not an HTTP status: {other:?}"),
    }
}

/// Sends `request` on a new connection and reads the response until the
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

/// The response with its `date` line taken out.
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

/// Sends `request` on a new connection, reads the response until the server
/// closes the connection, and returns its head and its body.
async fn exchange(addr: SocketAddr, request: &str) -> (String, Vec<u8>) {
    let mut stream = ostrya_rt::TcpStream::connect("127.0.0.1", addr.port())
        .await
        .unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    let end = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let body = out.split_off(end);
    (String::from_utf8(out).unwrap(), body)
}

/// A request of `method` for `target` that closes its connection.
fn ask(method: &str, target: &str) -> String {
    format!("{method} {target} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
}

/// Over plain HTTP, the server serves the built `config`, a stored object
/// with its length, and a `.filez` built on request with no length. A path
/// that the view refuses or does not find gets 404.
#[test]
fn the_archive_view_is_served_over_http() {
    let tmp = TmpDir::new("http");
    let (path, repo, commit, file) = block_on(repo(tmp.path()));
    with_server(repo, local(), |addrs| async move {
        let fetcher = fetcher(format!("http://{}/", addrs[0]), false, None).await;
        let (config, len, protocol) = fetch(&fetcher, "config").await.unwrap();
        assert_eq!(config, b"[core]\nrepo_version=1\nmode=archive-z2\n");
        assert_eq!(len, Some(config.len() as u64));
        assert_eq!(protocol, Protocol::Http11);

        let commit_path = object_path(ObjectType::Commit, &commit);
        let stored = std::fs::read(path.join(&commit_path)).unwrap();
        let (bytes, len, _) = fetch(&fetcher, &commit_path).await.unwrap();
        assert_eq!((bytes, len), (stored.clone(), Some(stored.len() as u64)));
        let (filez, len, _) = fetch(&fetcher, &object_path(ObjectType::File, &file))
            .await
            .unwrap();
        assert_eq!(len, None);
        assert!(filez.len() > 8);

        for absent in [
            ".lock",
            "tmp/x",
            "a/../config",
            "objects/00/absent.commit",
            "deltas/x",
            "nothing",
        ] {
            assert_eq!(status(fetch(&fetcher, absent).await), 404, "{absent}");
        }

        // A change of the repository config shows in the next answer.
        let mut text = std::fs::read_to_string(path.join("config")).unwrap();
        text.push_str("indexed-deltas=true\n");
        std::fs::write(path.join("config"), text).unwrap();
        assert!(
            fetch(&fetcher, "config")
                .await
                .unwrap()
                .0
                .ends_with(b"mode=archive-z2\nindexed-deltas=true\n")
        );
    });
}

/// A refused path and an absent path get the same response. A `HEAD` of a
/// stored file sends the length and no body. A `HEAD` of a built `.filez`
/// sends no length and no body. A method other than `GET` and `HEAD` gets
/// 405.
#[test]
fn raw_responses_hide_refused_paths() {
    let tmp = TmpDir::new("raw");
    let (path, repo, commit, file) = block_on(repo(tmp.path()));
    with_server(repo, local(), |addrs| async move {
        let addr = addrs[0];
        let ask = |method: &str, target: &str| {
            format!("{method} {target} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
        };
        let refused = raw(addr, &ask("GET", "/.lock")).await;
        let absent = raw(addr, &ask("GET", "/objects/00/nothing.commit")).await;
        assert!(refused.starts_with("HTTP/1.1 404 "), "{refused}");
        assert_eq!(without_date(&refused), without_date(&absent));
        assert_eq!(header(&refused, "content-length"), Some("0"));

        let commit_path = format!("/{}", object_path(ObjectType::Commit, &commit));
        let size = std::fs::metadata(path.join(&commit_path[1..]))
            .unwrap()
            .len();
        let head = raw(addr, &ask("HEAD", &commit_path)).await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(
            header(&head, "content-length"),
            Some(size.to_string().as_str())
        );
        assert!(head.ends_with("\r\n\r\n"), "a HEAD response has no body");

        let filez_path = format!("/{}", object_path(ObjectType::File, &file));
        let head = raw(addr, &ask("HEAD", &filez_path)).await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(header(&head, "content-length"), None);
        assert!(head.ends_with("\r\n\r\n"), "a HEAD response has no body");
        let get = raw(addr, &ask("GET", &filez_path)).await;
        assert_eq!(header(&get, "content-length"), None);
        assert_eq!(header(&get, "transfer-encoding"), Some("chunked"));

        let post = raw(addr, &ask("POST", "/config")).await;
        assert!(post.starts_with("HTTP/1.1 405 "), "{post}");
        assert_eq!(header(&post, "allow"), Some("GET, HEAD"));
    });
}

/// Over TLS, ALPN selects HTTP/2 or HTTP/1.1, as the client offers.
#[test]
fn tls_serves_http2_and_http1() {
    let tmp = TmpDir::new("tls");
    let (_, repo, _, file) = block_on(repo(tmp.path()));
    with_server(repo, tls(false), |addrs| async move {
        let url = format!("https://127.0.0.1:{}/", addrs[0].port());
        for (http2, protocol) in [(true, Protocol::Http2), (false, Protocol::Http11)] {
            let fetcher = fetcher(url.clone(), http2, None).await;
            let (config, _, got) = fetch(&fetcher, "config").await.unwrap();
            assert_eq!(got, protocol);
            assert!(config.starts_with(b"[core]\n"));
            let (_, len, _) = fetch(&fetcher, &object_path(ObjectType::File, &file))
                .await
                .unwrap();
            assert_eq!(len, None);
            assert_eq!(status(fetch(&fetcher, "state/x").await), 404);
        }
    });
}

/// With a client CA, the server serves a client with a certificate that the
/// CA signed, and a client with no certificate. A fetch of a client with a
/// certificate of another CA fails.
#[test]
fn a_client_certificate_is_optional_and_verified() {
    let tmp = TmpDir::new("client-ca");
    let (_, repo, _, _) = block_on(repo(tmp.path()));
    with_server(repo, tls(true), |addrs| async move {
        let url = format!("https://127.0.0.1:{}/", addrs[0].port());
        for identity in [None, Some((CLIENT_CERT_PEM, CLIENT_KEY_PEM))] {
            let fetcher = fetcher(url.clone(), true, identity).await;
            fetch(&fetcher, "config").await.unwrap();
        }
        let fetcher = fetcher(
            url.clone(),
            true,
            Some((UNTRUSTED_CERT_PEM, UNTRUSTED_KEY_PEM)),
        )
        .await;
        assert!(fetch(&fetcher, "config").await.is_err());
    });
}

/// A drop of the future of `run` closes the listener and ends the
/// connections that the listener accepted.
#[test]
fn dropping_the_server_stops_it() {
    let tmp = TmpDir::new("drop");
    let (_, repo, _, _) = block_on(repo(tmp.path()));
    block_on(async {
        let server = ostrya_server::bind(repo, local()).await.unwrap();
        let addr = server.local_addrs()[0];
        let run = server.run();
        let mut stream = future::or(
            async {
                run.await.unwrap();
                unreachable!("the server runs until it is dropped");
            },
            async {
                let mut stream = ostrya_rt::TcpStream::connect("127.0.0.1", addr.port())
                    .await
                    .unwrap();
                stream
                    .write_all(b"GET /config HTTP/1.1\r\nhost: x\r\n\r\n")
                    .await
                    .unwrap();
                let mut head = [0u8; 15];
                stream.read_exact(&mut head).await.unwrap();
                assert_eq!(&head, b"HTTP/1.1 200 OK");
                stream
            },
        )
        .await;
        // The keep-alive connection ends, so a read reaches its end.
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert!(
            ostrya_rt::TcpStream::connect("127.0.0.1", addr.port())
                .await
                .is_err()
        );
    });
}

/// `bind` refuses an empty listen list, a client CA with no TLS, and TLS
/// files that give no configuration. It refuses them before it binds a
/// listener.
#[test]
fn bad_options_are_refused() {
    let tmp = TmpDir::new("options");
    let (_, repo, _, _) = block_on(repo(tmp.path()));
    block_on(async {
        let mut opts = local();
        opts.listen.clear();
        let err = ostrya_server::bind(repo.clone(), opts).await.err().unwrap();
        assert!(matches!(err, ostrya_server::Error::Options(_)), "{err}");
        let mut opts = local();
        opts.client_ca_pem = Some(CA_PEM.to_vec());
        match ostrya_server::bind(repo.clone(), opts).await.err().unwrap() {
            ostrya_server::Error::Options(message) => {
                assert_eq!(
                    message,
                    "a client CA with no TLS and no forwarded certificate header"
                )
            }
            other => panic!("{other}"),
        }
        let mut opts = tls(false);
        opts.tls.as_mut().unwrap().key_pem = CLIENT_KEY_PEM.to_vec();
        let err = ostrya_server::bind(repo, opts).await.err().unwrap();
        assert!(matches!(err, ostrya_server::Error::Tls(_)), "{err}");
    });
}

/// Reads one HTTP/1.1 response with a `Content-Length` from `stream`, and
/// returns its status line and its body. The stream stays open.
async fn read_response(stream: &mut ostrya_rt::TcpStream) -> (String, Vec<u8>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let len: usize = header(&head, "content-length").unwrap().parse().unwrap();
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.unwrap();
    (head.lines().next().unwrap().to_owned(), body)
}

/// Runs `fut`. If `fut` takes longer than `limit`, the test fails.
async fn within<T>(limit: std::time::Duration, what: &str, fut: impl Future<Output = T>) -> T {
    future::or(fut, async {
        ostrya_rt::Timer::after(limit).await;
        panic!("{what} took longer than {limit:?}");
    })
    .await
}

/// Three thousand `GET`s of a small stored file go one after the other on
/// one keep-alive connection. Each one gets the whole body at once.
#[test]
fn keep_alive_gets_of_a_stored_file_complete() {
    let tmp = TmpDir::new("keep-alive");
    let (path, repo, commit, _) = block_on(repo(tmp.path()));
    with_server(repo, local(), |addrs| async move {
        let commit_path = object_path(ObjectType::Commit, &commit);
        let stored = std::fs::read(path.join(&commit_path)).unwrap();
        let request = format!("GET /{commit_path} HTTP/1.1\r\nhost: x\r\n\r\n");
        let mut stream = ostrya_rt::TcpStream::connect("127.0.0.1", addrs[0].port())
            .await
            .unwrap();
        for i in 0..3000 {
            stream.write_all(request.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            let (status, body) = within(
                std::time::Duration::from_secs(5),
                &format!("request {i}"),
                read_response(&mut stream),
            )
            .await;
            assert_eq!(status, "HTTP/1.1 200 OK");
            assert_eq!(body, stored);
        }
    });
}

/// A `bare-user` repository at `zlib-level=1`, and the checksums of its two
/// file objects. One file has `size` bytes that do not compress, and the
/// other file is small.
async fn repo_with_big_file(base: &Path, size: usize) -> (Repo, Checksum, Checksum) {
    let src = base.join("big-src");
    std::fs::create_dir_all(&src).unwrap();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let bytes: Vec<u8> = (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();
    std::fs::write(src.join("big"), bytes).unwrap();
    std::fs::write(src.join("small"), b"small\n").unwrap();
    let path = base.join("big-repo");
    let repo = Repo::create(&path, CreateOptions::new(RepoMode::BareUser))
        .await
        .unwrap();
    let mut text = std::fs::read_to_string(path.join("config")).unwrap();
    text.push_str("[archive]\nzlib-level=1\n");
    std::fs::write(path.join("config"), text).unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = std::fs::File::open(&src).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(CommitOptions::default(), &root)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    let mut big = None;
    let mut small = None;
    for name in repo.traverse_commit(&commit, 0).await.unwrap() {
        if name.ty != ObjectType::File {
            continue;
        }
        let file = repo.load_file(&name.checksum).await.unwrap();
        match file.kind {
            ostrya::FileKind::Regular { size: 6 } => small = Some(name.checksum),
            _ => big = Some(name.checksum),
        }
    }
    (repo, big.unwrap(), small.unwrap())
}

/// Clients ask for a large `.filez` built on request and read none of it.
/// They hold every compressor of the view until the body timeout ends their
/// connections. Then the server serves a request after them.
#[test]
fn a_stalled_body_releases_its_compressor() {
    let tmp = TmpDir::new("stall");
    let (repo, big, small) = block_on(repo_with_big_file(tmp.path(), 8 << 20));
    let mut opts = local();
    opts.body_timeout = std::time::Duration::from_secs(1);
    with_server(repo, opts, |addrs| async move {
        let port = addrs[0].port();
        let request = |checksum: &Checksum| {
            format!(
                "GET /{} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n",
                object_path(ObjectType::File, checksum)
            )
        };
        let mut stalled = Vec::new();
        for _ in 0..ostrya::archive::MAX_COMPRESSORS {
            let mut stream = ostrya_rt::TcpStream::connect("127.0.0.1", port)
                .await
                .unwrap();
            stream.write_all(request(&big).as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            stalled.push(stream);
        }
        let mut stream = ostrya_rt::TcpStream::connect("127.0.0.1", port)
            .await
            .unwrap();
        stream.write_all(request(&small).as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut out = Vec::new();
        within(
            std::time::Duration::from_secs(60),
            "the request after the stalled ones",
            stream.read_to_end(&mut out),
        )
        .await
        .unwrap();
        let out = String::from_utf8_lossy(&out);
        assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
        assert!(out.ends_with("0\r\n\r\n"), "the chunked body ends");
        drop(stalled);
    });
}

/// Sets the refs `a/b/c`, `a/b/d`, and `a/bc` of `repo` to `commit`.
async fn add_refs(repo: &Repo, commit: &Checksum) {
    let txn = repo.transaction().await.unwrap();
    for name in ["a/b/c", "a/b/d", "a/bc"] {
        txn.set_ref(name, Some(commit));
    }
    txn.commit().await.unwrap();
}

/// Parses `entries` as a selector.
fn selector(entries: &[&str]) -> RefSelector {
    RefSelector::parse(entries.iter().copied()).unwrap()
}

/// A `GET` of the ref listing gives the bytes of `build_ref_listing` for the
/// entries of its query, with their length. The entries are ref patterns
/// with an optional `!`. No query takes all refs, and an entry given two
/// times gives the bytes of one time. The server does not see a `#`
/// fragment. The requests go one after the other, more of them than the
/// listings that the server holds at the same time, so each listing frees
/// its place when its body ends.
#[test]
fn the_ref_listing_is_served() {
    let tmp = TmpDir::new("listing");
    let (_, repo, commit, _) = block_on(repo(tmp.path()));
    block_on(add_refs(&repo, &commit));
    with_server(repo.clone(), local(), |addrs| async move {
        let addr = addrs[0];
        let get = |query: &str| {
            let request = ask("GET", &format!("/_ostrya/refs/v1{query}"));
            async move { exchange(addr, &request).await }
        };

        let (head, body) = get("?pattern=a%2Fb%2F%2A%2A&pattern=main").await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(
            body,
            repo.build_ref_listing(&selector(&["a/b/**", "main"]), None, &anyone(&repo))
                .await
                .unwrap()
                .bytes
        );
        assert_eq!(
            header(&head, "content-length"),
            Some(body.len().to_string().as_str())
        );
        assert_eq!(header(&head, "content-type"), None);
        let names: Vec<String> = Summary::parse(&body)
            .unwrap()
            .refs
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(names, ["a/b/c", "a/b/d", "main"]);

        let all = repo
            .build_ref_listing(&selector(&[]), None, &anyone(&repo))
            .await
            .unwrap()
            .bytes;
        for query in ["", "?", "#pattern=main"] {
            let (head, body) = get(query).await;
            assert!(head.starts_with("HTTP/1.1 200 "), "{query}: {head}");
            assert_eq!(body, all, "{query}");
        }
        let main = repo
            .build_ref_listing(&selector(&["main"]), None, &anyone(&repo))
            .await
            .unwrap()
            .bytes;
        for query in [
            "?pattern=main&pattern=main",
            "?pattern=main",
            "?pattern=main#x",
        ] {
            let (head, body) = get(query).await;
            assert!(head.starts_with("HTTP/1.1 200 "), "{query}: {head}");
            assert_eq!(body, main, "{query}");
        }

        // A wildcard, a negative entry, a mixed list, and an overlap give
        // the listing of their selector. `a%2F%2A` is `a/*`, `%21` is `!`.
        let cases: [(&str, &[&str], &[&str]); 5] = [
            ("?pattern=a%2F%2A", &["a/*"], &["a/bc"]),
            (
                "?pattern=a%2F%2A%2A",
                &["a/**"],
                &["a/b/c", "a/b/d", "a/bc"],
            ),
            ("?pattern=%21a%2F%2A%2A", &["!a/**"], &["main"]),
            (
                "?pattern=a%2F%2A%2A&pattern=%21a%2Fb%2F%2A",
                &["a/**", "!a/b/*"],
                &["a/bc"],
            ),
            (
                "?pattern=a%2F%2A&pattern=a%2F%2A%2A&pattern=a%2F%2A",
                &["a/*", "a/**"],
                &["a/b/c", "a/b/d", "a/bc"],
            ),
        ];
        for (query, entries, names) in cases {
            let (head, body) = get(query).await;
            assert!(head.starts_with("HTTP/1.1 200 "), "{query}: {head}");
            assert_eq!(
                body,
                repo.build_ref_listing(&selector(entries), None, &anyone(&repo))
                    .await
                    .unwrap()
                    .bytes,
                "{query}"
            );
            assert_eq!(listed_names(&body), names, "{query}");
        }
    });
}

/// A listed ref that names an absent commit fails the build. Each such
/// request gets 500 with an empty body and frees its place, so a listing
/// after more of them than the server holds at the same time gets 200.
#[test]
fn a_failed_listing_gets_500() {
    let tmp = TmpDir::new("listing-500");
    let (path, repo, _, _) = block_on(repo(tmp.path()));
    std::fs::write(
        path.join("refs/heads/absent"),
        format!("{}\n", "ab".repeat(32)),
    )
    .unwrap();
    with_server(repo.clone(), local(), |addrs| async move {
        let target = "/_ostrya/refs/v1?pattern=absent";
        for _ in 0..6 {
            let (head, body) = exchange(addrs[0], &ask("GET", target)).await;
            assert!(head.starts_with("HTTP/1.1 500 "), "{head}");
            assert_eq!(header(&head, "content-length"), Some("0"));
            assert!(body.is_empty());
        }
        let (head, body) = exchange(addrs[0], &ask("GET", "/_ostrya/refs/v1?pattern=main")).await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(
            body,
            repo.build_ref_listing(&selector(&["main"]), None, &anyone(&repo))
                .await
                .unwrap()
                .bytes
        );
    });
}

/// A bad pair of the query and an entry that is not a ref pattern get 400
/// with an empty body, and so does an entry of more than 256 parts or 4096
/// bytes. An entry at a limit gets 200, and so does `a/*` written as
/// `a%2F%2A`.
#[test]
fn the_ref_listing_refuses_bad_queries() {
    let tmp = TmpDir::new("listing-bad");
    let (_, repo, _, _) = block_on(repo(tmp.path()));
    with_server(repo, local(), |addrs| async move {
        for query in [
            "?x=1",
            "?pattern",
            "?prefix=main",
            "?prefix=a&pattern=b",
            "?pattern=main&prefix=a",
            "?pattern=",
            "?pattern=a&&pattern=b",
            "?pattern=a%zz",
            "?pattern=a%00",
            "?pattern=%ff",
            "?pattern=a%2F%2Fb",
            "?pattern=..",
            "?pattern=a/",
            "?pattern=a%20b",
            "?pattern=-a",
            "?pattern=a*",
            "?pattern=a%2A",
            "?pattern=%2A%2Ax",
            "?pattern=%21%21a",
            "?pattern=%21",
            "?pattern=a%21",
            "?pattern=%2F",
            "?pattern=main&pattern=a%2F%2Fb",
        ] {
            let target = format!("/_ostrya/refs/v1{query}");
            let (head, body) = exchange(addrs[0], &ask("GET", &target)).await;
            assert!(head.starts_with("HTTP/1.1 400 "), "{query}: {head}");
            assert_eq!(header(&head, "content-length"), Some("0"), "{query}");
            assert!(body.is_empty(), "{query}");
        }

        let parts = |n: usize| vec!["a"; n].join("%2F");
        let long = |n: usize| "a".repeat(n);
        for (query, status) in [
            (format!("?pattern={}", parts(256)), "200"),
            (format!("?pattern={}", parts(257)), "400"),
            (format!("?pattern={}", long(4096)), "200"),
            (format!("?pattern={}", long(4097)), "400"),
            (format!("?pattern=%21{}", long(4096)), "400"),
            ("?pattern=a%2F%2A".to_owned(), "200"),
            ("?pattern=a%2F%2A%2A&pattern=%21a%2Fx".to_owned(), "200"),
        ] {
            let target = format!("/_ostrya/refs/v1{query}");
            let (head, _) = exchange(addrs[0], &ask("GET", &target)).await;
            let prefix = format!("HTTP/1.1 {status} ");
            assert!(
                head.starts_with(&prefix),
                "{}: {head}",
                &query[..query.len().min(40)]
            );
        }
    });
}

/// A `HEAD` and a `POST` of the ref listing get 405 with `Allow: GET`.
#[test]
fn the_ref_listing_takes_get_alone() {
    let tmp = TmpDir::new("listing-method");
    let (_, repo, _, _) = block_on(repo(tmp.path()));
    with_server(repo, local(), |addrs| async move {
        for method in ["HEAD", "POST"] {
            let (head, _) = exchange(addrs[0], &ask(method, "/_ostrya/refs/v1")).await;
            assert!(head.starts_with("HTTP/1.1 405 "), "{method}: {head}");
            assert_eq!(header(&head, "allow"), Some("GET"), "{method}");
        }
    });
}

/// The archive view still serves the files under `refs/heads`, and still
/// ignores the query. A path near the path of the listing gets 404.
#[test]
fn the_view_still_serves_refs_heads() {
    let tmp = TmpDir::new("listing-view");
    let (path, repo, _, _) = block_on(repo(tmp.path()));
    with_server(repo, local(), |addrs| async move {
        let addr = addrs[0];
        let stored = std::fs::read(path.join("refs/heads/main")).unwrap();
        let (head, body) = exchange(addr, &ask("GET", "/refs/heads/main")).await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(body, stored);
        for target in ["/_ostrya/refs/v1/", "/_ostrya/refs", "/_ostrya/refs/v1%2F"] {
            let (head, _) = exchange(addr, &ask("GET", target)).await;
            assert!(head.starts_with("HTTP/1.1 404 "), "{target}: {head}");
        }
        let (head, body) = exchange(addr, &ask("GET", "/config?pattern=x")).await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert!(body.starts_with(b"[core]\n"));
    });
}

/// Ref names that hold bytes that the query of the listing escapes. The
/// ref-name rule refuses each other name with such a byte.
const ESCAPED_REFS: [&str; 1] = ["odd/é"];

/// Returns the names of the refs of a listing, in the order of the listing.
fn listed_names(listing: &[u8]) -> Vec<String> {
    Summary::parse(listing)
        .unwrap()
        .refs
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

/// `PullSession::fetch_refs` over HTTP/1.1 and over HTTP/2 gives the bytes of
/// `build_ref_listing`. The client removes exact duplicate entries, and a ref name
/// with bytes that the query escapes comes back unchanged.
#[test]
fn fetch_refs_over_http_gives_the_built_listing() {
    let tmp = TmpDir::new("fetch-refs");
    let (_, repo, commit, _) = block_on(repo(tmp.path()));
    block_on(async {
        add_refs(&repo, &commit).await;
        let txn = repo.transaction().await.unwrap();
        for name in ESCAPED_REFS {
            txn.set_ref(name, Some(&commit));
        }
        txn.commit().await.unwrap();
    });
    for (opts, scheme, http2) in [(local(), "http", false), (tls(false), "https", true)] {
        let repo = repo.clone();
        with_server(repo.clone(), opts, |addrs| async move {
            let url = format!("{scheme}://127.0.0.1:{}/", addrs[0].port());
            let session = PullSession::Http(fetcher(url, http2, None).await);
            // The client sends the positive entries first, then the negative
            // entries, and drops an exact duplicate. The listing is the
            // listing of the same selector in the repository.
            let cases: [&[&str]; 11] = [
                &["a/b/c", "main"],
                &[],
                &["main", "a/b/c", "main"],
                &ESCAPED_REFS,
                &["a/*"],
                &["a/**"],
                &["**"],
                &["!a/**"],
                &["a/**", "!a/b/*"],
                &["!a/b/*", "a/**", "!a/b/*", "a/*"],
                &["a/*", "a/**", "!main", "!a/bc", "a/*"],
            ];
            for entries in cases {
                let got = session
                    .fetch_refs(&selector(entries), None)
                    .await
                    .unwrap()
                    .unwrap();
                let want = repo
                    .build_ref_listing(&selector(entries), None, &anyone(&repo))
                    .await
                    .unwrap()
                    .bytes;
                assert_eq!(got, want, "{scheme}: {entries:?}");
            }
            let got = session
                .fetch_refs(&selector(&["a/**", "!a/b/*"]), None)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(listed_names(&got), ["a/bc"], "{scheme}");
            let got = session
                .fetch_refs(&selector(&ESCAPED_REFS), None)
                .await
                .unwrap()
                .unwrap();
            let mut names = ESCAPED_REFS.map(str::to_owned).to_vec();
            names.sort();
            assert_eq!(listed_names(&got), names, "{scheme}");
            for name in ESCAPED_REFS {
                let got = session
                    .fetch_refs(&selector(&[name]), None)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(listed_names(&got), [name], "{scheme}: {name}");
            }
        });
    }
}

/// Returns a ref name whose percent-encoded form has `len` bytes, for a `len`
/// of at least one. The name is parts of 100 bytes, each with a `/` after
/// it, which the query writes as `%2F`, and a last part of the remaining
/// length.
fn prefix_of_encoded_len(len: usize) -> String {
    let mut name = String::new();
    let mut left = len;
    while left > 103 {
        name.push_str(&"a".repeat(100));
        name.push('/');
        left -= 103;
    }
    name.push_str(&"a".repeat(left));
    name
}

/// A request target of exactly 16 KiB, the client limit, gets the listing over
/// HTTP/1.1 and over HTTP/2. The target is `_ostrya/refs/v1?` and five
/// pairs `pattern=` and an encoded name, so each name is under the limit of
/// 4096 bytes of one entry. The first part of each name differs.
#[test]
fn fetch_refs_takes_a_target_at_the_client_limit() {
    let tmp = TmpDir::new("fetch-refs-target");
    let (_, repo, _, _) = block_on(repo(tmp.path()));
    let fixed = "_ostrya/refs/v1?".len() + 5 * "pattern=".len() + 4;
    let mut lens = vec![3900; 4];
    lens.push(16 * 1024 - fixed - lens.iter().sum::<usize>());
    let prefixes: Vec<String> = lens
        .iter()
        .zip(b'a'..)
        .map(|(len, first)| {
            let mut name = prefix_of_encoded_len(*len);
            name.replace_range(..1, &char::from(first).to_string());
            name
        })
        .collect();
    let encoded: usize = prefixes
        .iter()
        .map(|p| p.len() + 2 * p.matches('/').count())
        .sum();
    assert_eq!(fixed + encoded, 16 * 1024);
    for (opts, scheme, http2) in [(local(), "http", false), (tls(false), "https", true)] {
        let repo = repo.clone();
        let prefixes = prefixes.clone();
        with_server(repo.clone(), opts, |addrs| async move {
            let url = format!("{scheme}://127.0.0.1:{}/", addrs[0].port());
            let session = PullSession::Http(fetcher(url, http2, None).await);
            let entries: Vec<&str> = prefixes.iter().map(String::as_str).collect();
            let got = session.fetch_refs(&selector(&entries), None).await;
            let want = repo
                .build_ref_listing(&selector(&entries), None, &anyone(&repo))
                .await
                .unwrap()
                .bytes;
            assert_eq!(got.unwrap(), Some(want), "{scheme}");
        });
    }
}

/// A list of 200 positive and negative entries passes the client and the
/// server over HTTP/1.1 and over HTTP/2, and gives the listing of the same
/// selector in the repository. A list of 257 entries is refused by the
/// client with `InvalidInput`, and the same session then reads a listing.
#[test]
fn fetch_refs_takes_a_mixed_list_up_to_the_limit() {
    let tmp = TmpDir::new("fetch-refs-mixed");
    let (_, repo, commit, _) = block_on(repo(tmp.path()));
    block_on(add_refs(&repo, &commit));
    let mixed = |count: usize| -> Vec<String> {
        let mut entries: Vec<String> = (0..count)
            .map(|n| {
                if n % 2 == 0 {
                    format!("p{n}/**")
                } else {
                    format!("!n{n}/*")
                }
            })
            .collect();
        entries[0] = "a/**".to_owned();
        entries[1] = "!a/b/*".to_owned();
        entries
    };
    for (opts, scheme, http2) in [(local(), "http", false), (tls(false), "https", true)] {
        let repo = repo.clone();
        with_server(repo.clone(), opts, |addrs| async move {
            let url = format!("{scheme}://127.0.0.1:{}/", addrs[0].port());
            let session = PullSession::Http(fetcher(url, http2, None).await);
            let entries = mixed(200);
            let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
            let got = session.fetch_refs(&selector(&entries), None).await;
            let want = repo
                .build_ref_listing(&selector(&entries), None, &anyone(&repo))
                .await
                .unwrap()
                .bytes;
            assert_eq!(got.unwrap(), Some(want), "{scheme}");
            let entries = mixed(257);
            let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
            let err = session
                .fetch_refs(&selector(&entries), None)
                .await
                .unwrap_err();
            assert!(
                matches!(err, ostrya::remote::Error::InvalidInput(_)),
                "{err:?}"
            );
            let got = session
                .fetch_refs(&selector(&["main"]), None)
                .await
                .unwrap();
            assert!(got.is_some(), "{scheme}");
        });
    }
}

/// A pattern with a part longer than 255 bytes gets the listing of an absent
/// name over HTTP/1.1 and over HTTP/2.
#[test]
fn fetch_refs_of_a_too_long_part_gets_an_empty_listing() {
    let tmp = TmpDir::new("fetch-refs-long-part");
    let (_, repo, _, _) = block_on(repo(tmp.path()));
    let long = "l".repeat(256);
    for (opts, scheme, http2) in [(local(), "http", false), (tls(false), "https", true)] {
        let repo = repo.clone();
        let long = long.clone();
        with_server(repo.clone(), opts, |addrs| async move {
            let url = format!("{scheme}://127.0.0.1:{}/", addrs[0].port());
            let session = PullSession::Http(fetcher(url, http2, None).await);
            let got = session.fetch_refs(&selector(&[long.as_str()]), None).await;
            let want = repo
                .build_ref_listing(&selector(&["absent"]), None, &anyone(&repo))
                .await
                .unwrap()
                .bytes;
            assert_eq!(got.unwrap(), Some(want), "{scheme}");
        });
    }
}

/// Commits a tree of two files on `test/main` of `repo`, with `parent` as the
/// parent. The file `marker` holds `name`, and the file `shared` is the same
/// in each commit.
async fn commit_marker(repo: &Repo, base: &Path, name: &str, parent: Option<Checksum>) -> Checksum {
    let src = base.join(name);
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("marker"), name).unwrap();
    std::fs::write(src.join("shared"), b"shared\n").unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = std::fs::File::open(&src).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                parent,
                timestamp: Some(1_700_000_000),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("test/main", Some(&commit));
    txn.commit().await.unwrap();
    commit
}

/// Returns a small `a{sv}` dict for the detached metadata of a commit.
fn detached_dict() -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("test.detached".to_owned()),
        Value::Variant(Box::new((
            Type::parse("s").unwrap(),
            Value::Str("present".to_owned()),
        ))),
    ])])
}

/// An archive repository with the commits A, B, C, and D on `test/main`, the
/// deltas from A to B, from B to C, and from C to D, and the delta indexes.
/// C has detached metadata. The part size limit of the deltas is one byte, so
/// the three deltas have more part files than superblocks. A `bare-user`
/// client under `base` for each name in `clients` holds A.
///
/// Returns the server, the clients, the commits A to D, and the number of
/// part files of the three deltas.
async fn indexed_chain(base: &Path, clients: &[&str]) -> (Repo, Vec<Repo>, Vec<Checksum>, usize) {
    let server = Repo::create(&base.join("server"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let mut commits = vec![commit_marker(&server, base, "A", None).await];
    let mut repos = Vec::new();
    for name in clients {
        let client = Repo::create(&base.join(name), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let main = PullOptions {
            refs: vec!["test/main".to_owned()],
            ..PullOptions::default()
        };
        client.pull_local(&server, main).await.unwrap();
        repos.push(client);
    }
    for name in ["B", "C", "D"] {
        let parent = commits.last().copied();
        commits.push(commit_marker(&server, base, name, parent).await);
    }
    server
        .write_commit_detached_metadata(&commits[2], Some(&detached_dict()))
        .await
        .unwrap();
    let opts = DeltaOptions {
        max_chunk_size: 1,
        timestamp: Some(1_700_000_000),
        ..DeltaOptions::default()
    };
    let mut parts = 0;
    for step in commits.windows(2) {
        let dir = server
            .generate_static_delta(Some(&step[0]), &step[1], &opts)
            .await
            .unwrap();
        let count = std::fs::read_dir(server.path().join(dir))
            .unwrap()
            .filter(|entry| {
                let name = entry.as_ref().unwrap().file_name();
                name.to_string_lossy().parse::<u32>().is_ok()
            })
            .count();
        assert!(count >= 1, "{}-{}", step[0], step[1]);
        parts += count;
    }
    assert!(parts > 3, "{parts}");
    server.reindex_static_deltas().await.unwrap();
    (server, repos, commits, parts)
}

/// A client that holds A pulls D with the three deltas of the ref listing,
/// over HTTP/1.1 and over HTTP/2. The pull fetches the three superblocks and
/// the detached metadata of C, and no content object. It applies each part
/// file of the deltas, and the client keeps the detached metadata of C.
#[test]
fn a_chain_from_the_ref_listing_is_pulled_over_http() {
    let tmp = TmpDir::new("delta-chain");
    let (server, clients, commits, parts) =
        block_on(indexed_chain(tmp.path(), &["client-http", "client-https"]));
    let passes = [(local(), "http", false), (tls(false), "https", true)];
    for ((opts, scheme, http2), client) in passes.into_iter().zip(clients) {
        let commits = &commits;
        with_server(server.clone(), opts, |addrs| async move {
            let url = format!("{scheme}://127.0.0.1:{}/", addrs[0].port());
            let session = PullSession::Http(fetcher(url, http2, None).await);
            let listing = session
                .fetch_refs(&selector(&["test/main"]), None)
                .await
                .unwrap()
                .unwrap();
            let deltas = Summary::parse(&listing).unwrap().static_deltas().unwrap();
            assert_eq!(deltas.len(), 3, "{scheme}");
            let progress = PullProgress::new();
            let opts = PullOptions {
                refs: vec!["test/main".to_owned()],
                static_deltas: Some(deltas),
                progress: Some(progress.clone()),
                ..PullOptions::default()
            };
            let stats = client
                .pull_with_session(session, PullTrust::unverified(), opts)
                .await
                .unwrap();
            assert_eq!(stats.metadata_fetched, 4, "{scheme}");
            assert_eq!(stats.content_fetched, 0, "{scheme}");
            assert_eq!(stats.delta_parts as usize, parts, "{scheme}");
            let snapshot = progress.snapshot();
            assert_eq!(snapshot.delta_parts_total, stats.delta_parts, "{scheme}");
            let head = client.resolve_rev("test/main", false).await.unwrap();
            assert_eq!(head, Some(commits[3]), "{scheme}");
            let meta = client.read_commit_detached_metadata(&commits[2]).await;
            assert_eq!(meta.unwrap(), Some(detached_dict()), "{scheme}");
        });
    }
}

/// Writes the client groups `groups` at the end of the config of the
/// repository at `path`, and returns the repository opened again and its
/// receive policies.
fn with_groups(path: &Path, groups: &str) -> (Repo, Arc<ReceivePolicies>) {
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(groups);
    std::fs::write(&config, text).unwrap();
    block_on(async {
        let repo = Repo::open(path).await.unwrap();
        let policies = Arc::new(ReceivePolicies::from_config(&repo).await.unwrap());
        (repo, policies)
    })
}

/// The options of [`local`] with the receive policies `policies`.
fn with_policies(policies: Arc<ReceivePolicies>) -> ServeOptions {
    let mut opts = local();
    opts.receive = Some(policies);
    opts
}

/// Copies the ref file `refs/heads/main` of the repository at `path` to each
/// path of `refs`, so each one names the commit of `main`.
fn copy_main(path: &Path, refs: &[&str]) {
    let main = path.join("refs/heads/main");
    for to in refs {
        let to = path.join(to);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(&main, to).unwrap();
    }
}

/// With client groups, a read needs an identified item. With a token group
/// alone, a `GET` and a `HEAD` of `config` and a `GET` of the ref listing get
/// 401 with the two challenges and an empty body. A `HEAD` of the listing
/// gets 405 first. With the token, the reads get 200.
#[test]
fn a_read_needs_an_identified_client() {
    let tmp = TmpDir::new("read-identified");
    let (path, _, _, _) = block_on(repo(tmp.path()));
    let digest = Checksum::sha256(b"a-token").to_hex();
    let (repo, policies) = with_groups(
        &path,
        &format!("[ex-ostrya client \"t\"]\nauth=token-sha256:{digest}\nallow=r:**\n"),
    );
    let mut opts = with_policies(policies);
    opts.allow_cleartext_credentials = true;
    with_server(repo, opts, |addrs| async move {
        let addr = addrs[0];
        for (method, target) in [
            ("GET", "/config"),
            ("HEAD", "/config"),
            ("GET", "/_ostrya/refs/v1"),
            ("GET", "/refs/heads/main"),
        ] {
            let response = raw(addr, &ask(method, target)).await;
            assert!(
                response.starts_with("HTTP/1.1 401 "),
                "{target}: {response}"
            );
            assert_eq!(header(&response, "content-length"), Some("0"));
            for challenge in [r#"Bearer realm="ostrya""#, r#"Basic realm="ostrya""#] {
                let line = format!("www-authenticate: {challenge}\r\n");
                assert!(response.contains(&line), "{response}");
            }
            assert!(response.ends_with("\r\n\r\n"), "{response}");
            let request = format!(
                "{method} {target} HTTP/1.1\r\nhost: x\r\nauthorization: Bearer a-token\r\n\
                 connection: close\r\n\r\n"
            );
            let response = raw(addr, &request).await;
            assert!(
                response.starts_with("HTTP/1.1 200 "),
                "{target}: {response}"
            );
        }
        let response = raw(addr, &ask("HEAD", "/_ostrya/refs/v1")).await;
        assert!(response.starts_with("HTTP/1.1 405 "), "{response}");
    });
}

/// A ref is served when the group of the item has `r` on its name, an alias
/// when the item reads its name and its target, and a mirror ref by the
/// group of its collection. Each denial gets the response of an absent
/// path. `refs/remotes/` is never served. Objects and `config` are served.
#[test]
fn the_refs_follow_the_read_rights() {
    let tmp = TmpDir::new("read-rights");
    let (path, _, commit, _) = block_on(repo(tmp.path()));
    copy_main(
        &path,
        &[
            "refs/heads/pub/a",
            "refs/heads/secret",
            "refs/remotes/o/pub/a",
            "refs/mirrors/a.b/x",
            "refs/mirrors/a.b/y",
        ],
    );
    let heads = path.join("refs/heads");
    symlink("a", heads.join("pub/to-a")).unwrap();
    symlink("../main", heads.join("pub/to-main")).unwrap();
    symlink("../../remotes/o/pub/a", heads.join("pub/to-remote")).unwrap();
    let (repo, policies) = with_groups(
        &path,
        "[ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:pub/**\n\
         [ex-ostrya client \"mirrors\"]\nauth=anonymous\ncollection=a.b\nallow=r:x\n",
    );
    with_server(repo, with_policies(policies), |addrs| async move {
        let addr = addrs[0];
        let stored = std::fs::read(path.join("refs/heads/main")).unwrap();
        for target in [
            "/refs/heads/pub/a",
            "/refs/heads/pub/to-a",
            "/refs/mirrors/a.b/x",
        ] {
            let (head, body) = exchange(addr, &ask("GET", target)).await;
            assert!(head.starts_with("HTTP/1.1 200 "), "{target}: {head}");
            assert_eq!(body, stored, "{target}");
        }
        let absent = without_date(&raw(addr, &ask("GET", "/refs/heads/absent")).await);
        assert!(absent.starts_with("HTTP/1.1 404 "), "{absent}");
        for target in [
            "/refs/heads/main",
            "/refs/heads/secret",
            "/refs/heads/pub/to-main",
            "/refs/heads/pub/to-remote",
            "/refs/remotes/o/pub/a",
            "/refs/mirrors/a.b/y",
            "/refs/mirrors/c.d/x",
        ] {
            let response = raw(addr, &ask("GET", target)).await;
            assert_eq!(without_date(&response), absent, "{target}");
        }
        for target in [
            "/config".to_owned(),
            format!("/{}", object_path(ObjectType::Commit, &commit)),
        ] {
            let response = raw(addr, &ask("GET", &target)).await;
            assert!(
                response.starts_with("HTTP/1.1 200 "),
                "{target}: {response}"
            );
        }
    });
}

/// Returns a request of `method` for `target` with the bearer token
/// `token`, which closes its connection.
fn ask_with_token(method: &str, target: &str, token: &str) -> String {
    format!(
        "{method} {target} HTTP/1.1\r\nhost: x\r\nauthorization: Bearer {token}\r\n\
         connection: close\r\n\r\n"
    )
}

/// `summary` and `summary.sig` give the files of the summary of the item of
/// the client: the files at the root for `anonymous`, and the files under
/// `extensions/ostrya/summary/` for a token item. An item with no summary
/// gets 404. A 200 and a 404 carry `Cache-Control: private`, and a 401 does
/// not.
#[test]
fn the_summary_of_each_item_is_served() {
    let tmp = TmpDir::new("read-summary");
    let (path, _, _, _) = block_on(repo(tmp.path()));
    copy_main(&path, &["refs/heads/pub/a"]);
    let digest = |token: &str| Checksum::sha256(token.as_bytes()).to_hex();
    let (repo, policies) = with_groups(
        &path,
        &format!(
            "[ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:pub/**\nsummary=true\n\
             [ex-ostrya client \"ci\"]\nauth=token-sha256:{}\nallow=r:**\nsummary=true\n\
             [ex-ostrya client \"ops\"]\nauth=token-sha256:{}\nallow=r:**\n",
            digest("ci-token"),
            digest("ops-token")
        ),
    );
    let signer = ostrya::DummySigner::new(b"sig".to_vec());
    block_on(repo.regenerate_summaries(&ostrya::SummaryOptions::default(), &[&signer])).unwrap();
    let stem = Checksum::sha256(format!("token-sha256:{}", digest("ci-token")).as_bytes());
    let stored = |rel: &str| std::fs::read(path.join(rel)).unwrap();
    let ci_summary = stored(&format!("extensions/ostrya/summary/{stem}"));
    let ci_sig = stored(&format!("extensions/ostrya/summary/{stem}.sig"));
    let (root_summary, root_sig) = (stored("summary"), stored("summary.sig"));
    assert_eq!(listed_names(&root_summary), ["pub/a"]);
    assert_eq!(listed_names(&ci_summary), ["main", "pub/a"]);
    let mut opts = with_policies(policies);
    opts.allow_cleartext_credentials = true;
    with_server(repo, opts, |addrs| async move {
        let addr = addrs[0];
        for (token, target, want) in [
            (None, "/summary", &root_summary),
            (None, "/summary.sig", &root_sig),
            (Some("ci-token"), "/summary", &ci_summary),
            (Some("ci-token"), "/summary.sig", &ci_sig),
        ] {
            for method in ["GET", "HEAD"] {
                let request = match token {
                    Some(token) => ask_with_token(method, target, token),
                    None => ask(method, target),
                };
                let (head, body) = exchange(addr, &request).await;
                assert!(
                    head.starts_with("HTTP/1.1 200 "),
                    "{method} {target}: {head}"
                );
                assert!(head.contains("cache-control: private\r\n"), "{head}");
                let len = want.len().to_string();
                assert_eq!(header(&head, "content-length"), Some(len.as_str()));
                if method == "GET" {
                    assert_eq!(&body, want, "{target}");
                }
            }
        }
        for method in ["GET", "HEAD"] {
            for target in ["/summary", "/summary.sig"] {
                let (head, _) = exchange(addr, &ask_with_token(method, target, "ops-token")).await;
                assert!(
                    head.starts_with("HTTP/1.1 404 "),
                    "{method} {target}: {head}"
                );
                assert!(head.contains("cache-control: private\r\n"), "{head}");
            }
            let response = raw(addr, &ask_with_token(method, "/summary", "bad-token")).await;
            assert!(!response.starts_with("HTTP/1.1 200 "), "{response}");
            assert!(!response.starts_with("HTTP/1.1 404 "), "{response}");
            assert_eq!(header(&response, "cache-control"), None, "{response}");
        }
        let (head, _) = exchange(addr, &ask("GET", "/config")).await;
        assert_eq!(header(&head, "cache-control"), None, "{head}");
        let direct = format!("/extensions/ostrya/summary/{stem}");
        let (head, _) = exchange(addr, &ask_with_token("GET", &direct, "ci-token")).await;
        assert!(head.starts_with("HTTP/1.1 404 "), "{head}");
    });
}

/// A change to `allow` makes the summary stale: the server answers 404 and
/// reports one error event for each item, until the summaries are written
/// again. The server reads the files for each request, so the new write
/// takes effect while the server runs.
#[test]
fn a_stale_summary_gets_404_until_it_is_written_again() {
    stale_until_written("read-summary-stale", "allow=r:pub/**\n", "allow=r:**\n");
}

/// A change to `deny` makes the summary stale, as a change to `allow` does.
#[test]
fn a_deny_change_gets_404_until_the_summary_is_written_again() {
    stale_until_written(
        "read-summary-stale-deny",
        "allow=r:**\ndeny=main\n",
        "allow=r:**\n",
    );
}

/// Writes the summary of `anonymous` under the rules `before`, which read
/// `pub/a` alone, and serves the repository under the rules `after`, which
/// read `main` and `pub/a`. The summary gets 404 and one error event until
/// the summaries are written again.
fn stale_until_written(name: &str, before: &str, after: &str) {
    let tmp = TmpDir::new(name);
    let (path, _, _, _) = block_on(repo(tmp.path()));
    copy_main(&path, &["refs/heads/pub/a"]);
    let group = |rules: &str| {
        format!("[ex-ostrya client \"public\"]\nauth=anonymous\n{rules}summary=true\n")
    };
    let (repo, _) = with_groups(&path, &group(before));
    block_on(repo.regenerate_summary(&ostrya::SummaryOptions::default())).unwrap();
    let written = std::fs::read(path.join("summary")).unwrap();
    assert_eq!(listed_names(&written), ["pub/a"]);
    let config = path.join("config");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, text.replace(&group(before), &group(after))).unwrap();
    let (repo, policies) = with_groups(&path, "");
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = events.clone();
    let mut opts = with_policies(policies);
    opts.on_event = Some(Arc::new(move |event: &ostrya_server::ServerEvent| {
        sink.lock().unwrap().push(event.clone());
    }));
    let writer = repo.clone();
    with_server(repo, opts, |addrs| async move {
        for (method, target) in [
            ("GET", "/summary"),
            ("HEAD", "/summary"),
            ("GET", "/summary.sig"),
        ] {
            let (head, _) = exchange(addrs[0], &ask(method, target)).await;
            assert!(
                head.starts_with("HTTP/1.1 404 "),
                "{method} {target}: {head}"
            );
            assert!(head.contains("cache-control: private\r\n"), "{head}");
        }
        writer
            .regenerate_summary(&ostrya::SummaryOptions::default())
            .await
            .unwrap();
        let (head, body) = exchange(addrs[0], &ask("GET", "/summary")).await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(listed_names(&body), ["main", "pub/a"]);
    });
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(
        matches!(&events[0], ostrya_server::ServerEvent::StaleSummary { item, .. }
            if item == "anonymous"),
        "{events:?}"
    );
    assert!(!events[0].is_warning());
}

/// A 403 of `summary` and `summary.sig` carries no `Cache-Control`. A
/// credential over plain HTTP gets 403 without
/// `allow-cleartext-credentials`.
#[test]
fn a_403_of_the_summary_carries_no_cache_control() {
    let tmp = TmpDir::new("read-summary-403");
    let (path, _, _, _) = block_on(repo(tmp.path()));
    let token = Checksum::sha256(b"ci-token").to_hex();
    let (repo, policies) = with_groups(
        &path,
        &format!(
            "[ex-ostrya client \"ci\"]\nauth=token-sha256:{token}\nallow=r:**\nsummary=true\n"
        ),
    );
    block_on(repo.regenerate_summary(&ostrya::SummaryOptions::default())).unwrap();
    with_server(repo, with_policies(policies), |addrs| async move {
        for method in ["GET", "HEAD"] {
            for target in ["/summary", "/summary.sig"] {
                let response = raw(addrs[0], &ask_with_token(method, target, "ci-token")).await;
                assert!(
                    response.starts_with("HTTP/1.1 403 "),
                    "{method} {target}: {response}"
                );
                assert_eq!(header(&response, "cache-control"), None, "{response}");
            }
        }
    });
}

/// The ref listing holds the refs that the item reads. Its body is the
/// listing that `build_ref_listing` builds with the same rights.
#[test]
fn the_ref_listing_holds_the_readable_refs() {
    let tmp = TmpDir::new("read-listing");
    let (path, _, _, _) = block_on(repo(tmp.path()));
    copy_main(&path, &["refs/heads/pub/a", "refs/heads/secret"]);
    symlink("../main", path.join("refs/heads/pub/to-main")).unwrap();
    symlink("a", path.join("refs/heads/pub/to-a")).unwrap();
    let (repo, policies) = with_groups(
        &path,
        "[ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:pub/**\n",
    );
    let want = block_on(repo.build_ref_listing(&selector(&[]), None, &anyone(&repo)))
        .unwrap()
        .bytes;
    assert_eq!(listed_names(&want), ["pub/a", "pub/to-a"]);
    with_server(repo, with_policies(policies), |addrs| async move {
        let (head, body) = exchange(addrs[0], &ask("GET", "/_ostrya/refs/v1")).await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(body, want);
    });
}

/// With no receive policies, the server identifies no client. Each read is
/// the `anonymous` item under the two implicit groups, also when the
/// repository config has client groups and the request has a credential:
/// each local ref and each mirror ref, the summary, and no remote ref.
#[test]
fn a_server_with_no_receive_policies_serves_as_the_implicit_groups() {
    let tmp = TmpDir::new("read-implicit");
    let (path, repo, _, _) = block_on(repo(tmp.path()));
    block_on(repo.regenerate_summary(&ostrya::SummaryOptions::default())).unwrap();
    copy_main(&path, &["refs/mirrors/a.b/x", "refs/remotes/o/x"]);
    let (repo, _) = with_groups(&path, "[ex-ostrya client \"c\"]\nauth=ssh:u\n");
    with_server(repo, local(), |addrs| async move {
        let addr = addrs[0];
        for target in ["/refs/heads/main", "/refs/mirrors/a.b/x", "/summary"] {
            for auth in ["", "authorization: Bearer x\r\n"] {
                let request =
                    format!("GET {target} HTTP/1.1\r\nhost: x\r\n{auth}connection: close\r\n\r\n");
                let response = raw(addr, &request).await;
                assert!(
                    response.starts_with("HTTP/1.1 200 "),
                    "{target}: {response}"
                );
            }
        }
        let response = raw(addr, &ask("GET", "/refs/remotes/o/x")).await;
        assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
    });
}

/// With no receive policies, the collection id of the repository maps its
/// mirror refs to the local refs as the config holds it. The id `a\b` is
/// written with an escape in the config and fails the collection-id rule,
/// so only that mapping serves `refs/mirrors/a\b/x`. Another id that fails
/// the rule is not served.
#[test]
fn a_server_with_no_receive_policies_takes_the_own_collection_id_as_read() {
    let tmp = TmpDir::new("read-own-id");
    let (path, _, _, _) = block_on(repo(tmp.path()));
    let config = path.join("config");
    let text = std::fs::read_to_string(&config).unwrap();
    let text = text.replacen("[core]\n", "[core]\ncollection-id=a\\\\b\n", 1);
    std::fs::write(&config, text).unwrap();
    copy_main(&path, &["refs/mirrors/a\\b/x", "refs/mirrors/c\\d/x"]);
    let repo = block_on(Repo::open(&path)).unwrap();
    assert_eq!(repo.config().collection_id(), Some("a\\b"));
    with_server(repo, local(), |addrs| async move {
        let addr = addrs[0];
        let response = raw(addr, &ask("GET", "/refs/mirrors/a%5Cb/x")).await;
        assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
        let response = raw(addr, &ask("GET", "/refs/mirrors/c%5Cd/x")).await;
        assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
    });
}

/// A list of selector entries.
type Entries<'a> = &'a [&'a str];

/// Copies `refs/heads/main` of the repository at `path` to the mirror refs
/// `org.a/x`, `org.a/y/z`, and `org.b/main`, and returns the repository
/// opened again.
fn with_mirrors(path: &Path) -> Repo {
    copy_main(
        path,
        &[
            "refs/mirrors/org.a/x",
            "refs/mirrors/org.a/y/z",
            "refs/mirrors/org.b/main",
        ],
    );
    block_on(Repo::open(path)).unwrap()
}

/// Returns the collection ids of the collection map of `listing`, each with
/// the names of its refs, in stored order.
fn collection_names(listing: &[u8]) -> Vec<(String, Vec<String>)> {
    Summary::parse(listing)
        .unwrap()
        .collection_map()
        .unwrap()
        .into_iter()
        .map(|(id, refs)| (id, refs.into_iter().map(|entry| entry.name).collect()))
        .collect()
}

/// `PullSession::fetch_refs` with a selector of the collection refs, over
/// HTTP/1.1 and over HTTP/2, gives the bytes of `build_ref_listing` for the
/// two selectors. A selector with no entry goes as `collection=**` and gives
/// each collection ref. With no selector of the collection refs, the bytes
/// are those of the listing of the local refs alone.
#[test]
fn fetch_refs_with_collections_over_http_gives_the_built_listing() {
    let tmp = TmpDir::new("fetch-refs-collections");
    let (path, _, _, _) = block_on(repo(tmp.path()));
    let repo = with_mirrors(&path);
    for (opts, scheme, http2) in [(local(), "http", false), (tls(false), "https", true)] {
        let repo = repo.clone();
        with_server(repo.clone(), opts, |addrs| async move {
            let url = format!("{scheme}://127.0.0.1:{}/", addrs[0].port());
            let session = PullSession::Http(fetcher(url, http2, None).await);
            let cases: [(&[&str], Option<&[&str]>); 6] = [
                (&[], Some(&[])),
                (&["main"], Some(&["org.a/**"])),
                (&["!**"], Some(&["*/main", "!org.b/**", "*/main"])),
                (&[], Some(&["!org.a/**"])),
                (&[], Some(&["org.a"])),
                (&["main"], None),
            ];
            for (refs, collections) in cases {
                let collections = collections.map(selector);
                let got = session
                    .fetch_refs(&selector(refs), collections.as_ref())
                    .await
                    .unwrap()
                    .unwrap();
                let want = repo
                    .build_ref_listing(&selector(refs), collections.as_ref(), &anyone(&repo))
                    .await
                    .unwrap()
                    .bytes;
                assert_eq!(got, want, "{scheme}: {refs:?} {collections:?}");
            }
            let got = session
                .fetch_refs(&selector(&[]), Some(&selector(&[])))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                collection_names(&got),
                [
                    ("org.a".to_owned(), vec!["x".to_owned(), "y/z".to_owned()]),
                    ("org.b".to_owned(), vec!["main".to_owned()]),
                ],
                "{scheme}"
            );
            let plain = session
                .fetch_refs(&selector(&[]), None)
                .await
                .unwrap()
                .unwrap();
            assert!(collection_names(&plain).is_empty());
            assert_eq!(listed_names(&plain), listed_names(&got));
        });
    }
}

/// The query of the ref listing takes `collection` pairs beside `pattern`
/// pairs. A query with no `collection` pair has the bytes of the listing of
/// the local refs alone. A bad `collection` entry, a pair with another key,
/// and more than 256 pairs of the two keys together get 400.
#[test]
fn the_ref_listing_reads_collection_pairs() {
    let tmp = TmpDir::new("listing-collection-pairs");
    let (path, _, _, _) = block_on(repo(tmp.path()));
    let repo = with_mirrors(&path);
    with_server(repo.clone(), local(), |addrs| async move {
        let addr = addrs[0];
        let get = |query: String| {
            let request = ask("GET", &format!("/_ostrya/refs/v1{query}"));
            async move { exchange(addr, &request).await }
        };
        let build = |refs: &[&str], collections: Option<&[&str]>| {
            let repo = repo.clone();
            let refs = selector(refs);
            let collections = collections.map(selector);
            async move {
                repo.build_ref_listing(&refs, collections.as_ref(), &anyone(&repo))
                    .await
                    .unwrap()
                    .bytes
            }
        };
        let cases: [(&str, Entries, Option<Entries>); 5] = [
            ("?collection=org.a%2F%2A%2A", &[], Some(&["org.a/**"])),
            (
                "?collection=%2A%2Fmain&pattern=main&collection=%2A%2Fmain",
                &["main"],
                Some(&["*/main"]),
            ),
            ("?collection=%2A%2A", &[], Some(&[])),
            ("?pattern=main", &["main"], None),
            ("", &[], None),
        ];
        for (query, refs, collections) in cases {
            let (head, body) = get(query.to_owned()).await;
            assert!(head.starts_with("HTTP/1.1 200 "), "{query}: {head}");
            assert_eq!(body, build(refs, collections).await, "{query}");
        }
        let mixed = |count: usize| {
            (0..count)
                .map(|n| {
                    if n % 2 == 0 {
                        format!("pattern=r{n}")
                    } else {
                        format!("collection=org.a%2Fc{n}")
                    }
                })
                .collect::<Vec<_>>()
                .join("&")
        };
        let (head, _) = get(format!("?{}", mixed(256))).await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        for query in [
            format!("?{}", mixed(257)),
            "?collection=a%2F%2Fb".to_owned(),
            "?collection=%21%21a".to_owned(),
            "?collection=".to_owned(),
            "?collections=org.a%2Fx".to_owned(),
            format!("?collection={}", "a".repeat(4097)),
        ] {
            let (head, body) = get(query.clone()).await;
            assert!(head.starts_with("HTTP/1.1 400 "), "{query}: {head}");
            assert!(body.is_empty());
        }
    });
}

/// Each collection of a listing takes the group of the token item in the
/// namespace of the collection: the group of the exact id, else the group
/// of `collection=*`. The body is the listing that `build_ref_listing`
/// builds with the rights of the item.
#[test]
fn the_collection_refs_follow_the_group_of_the_item() {
    let tmp = TmpDir::new("listing-collection-rights");
    let (path, _, _, _) = block_on(repo(tmp.path()));
    with_mirrors(&path);
    let a = Checksum::sha256(b"token-a").to_hex();
    let b = Checksum::sha256(b"token-b").to_hex();
    let (repo, policies) = with_groups(
        &path,
        &format!(
            "[ex-ostrya client \"a-local\"]\nauth=token-sha256:{a}\nallow=r:main\n\
             [ex-ostrya client \"a-exact\"]\nauth=token-sha256:{a}\ncollection=org.a\n\
             allow=r:y/**\n\
             [ex-ostrya client \"a-any\"]\nauth=token-sha256:{a}\ncollection=*\nallow=r:**\n\
             [ex-ostrya client \"b-local\"]\nauth=token-sha256:{b}\nallow=r:**\n"
        ),
    );
    let access = |digest: &str| {
        let access = ClientAccess::from_config(repo.config(), repo.path()).unwrap();
        let item = AuthItem::parse(&format!("token-sha256:{digest}")).unwrap();
        ReadAccess::new(Arc::new(access), item, None)
    };
    let all = selector(&[]);
    let want_a = block_on(repo.build_ref_listing(&all, Some(&all), &access(&a)))
        .unwrap()
        .bytes;
    let want_b = block_on(repo.build_ref_listing(&all, Some(&all), &access(&b)))
        .unwrap()
        .bytes;
    assert_eq!(
        collection_names(&want_a),
        [
            ("org.a".to_owned(), vec!["y/z".to_owned()]),
            ("org.b".to_owned(), vec!["main".to_owned()]),
        ]
    );
    assert!(collection_names(&want_b).is_empty());
    let mut opts = with_policies(policies);
    opts.allow_cleartext_credentials = true;
    with_server(repo, opts, |addrs| async move {
        for (token, want) in [("token-a", want_a), ("token-b", want_b)] {
            let request = format!(
                "GET /_ostrya/refs/v1?collection=%2A%2A HTTP/1.1\r\nhost: x\r\n\
                 authorization: Bearer {token}\r\nconnection: close\r\n\r\n"
            );
            let (head, body) = exchange(addrs[0], &request).await;
            assert!(head.starts_with("HTTP/1.1 200 "), "{token}: {head}");
            assert_eq!(body, want, "{token}");
        }
    });
}

/// A directory under `refs/mirrors/` whose name is not a collection id gives
/// one `InvalidCollectionDir` event over two listings that read it, with and
/// without receive policies. A listing with no `collection` pair reads no
/// such directory. Each listing gets 200 and leaves out the directory.
#[test]
fn an_invalid_collection_dir_gives_one_event_per_server() {
    let tmp = TmpDir::new("listing-invalid-dir");
    let (path, _, _, _) = block_on(repo(tmp.path()));
    with_mirrors(&path);
    let bad = path.join("refs/mirrors/bad");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("x"), "no checksum\n").unwrap();
    let (repo, policies) = with_groups(
        &path,
        "[ex-ostrya client \"all\"]\nauth=anonymous\nallow=r:**\n\
         [ex-ostrya client \"mirrors\"]\nauth=anonymous\ncollection=*\nallow=r:**\n",
    );
    for opts in [local(), with_policies(policies)] {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = events.clone();
        let mut opts = opts;
        opts.on_event = Some(Arc::new(move |event: &ostrya_server::ServerEvent| {
            sink.lock().unwrap().push(event.clone());
        }));
        with_server(repo.clone(), opts, |addrs| async move {
            for target in [
                "/_ostrya/refs/v1",
                "/_ostrya/refs/v1?collection=%2A%2A",
                "/_ostrya/refs/v1?pattern=main&collection=org.a%2F%2A%2A",
            ] {
                let (head, body) = exchange(addrs[0], &ask("GET", target)).await;
                assert!(head.starts_with("HTTP/1.1 200 "), "{target}: {head}");
                let ids: Vec<String> = collection_names(&body)
                    .into_iter()
                    .map(|(id, _)| id)
                    .collect();
                assert!(!ids.contains(&"bad".to_owned()), "{target}");
            }
        });
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1, "{events:?}");
        assert!(
            matches!(&events[0], ostrya_server::ServerEvent::InvalidCollectionDir { name, .. }
                if name == "bad"),
            "{events:?}"
        );
        assert!(events[0].is_warning());
    }
}
