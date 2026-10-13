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
use std::sync::atomic::{AtomicU32, Ordering};

use futures_lite::{AsyncReadExt, AsyncWriteExt, future};
use ostrya::fetch::{
    ClientIdentity, FetchRequest, Fetched, Fetcher, FetcherOptions, Protocol, Proxy, TlsOptions,
    TrustRoots,
};
use ostrya::remote::PullSession;
use ostrya::verify::PullTrust;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DeltaOptions,
    MutableTree, ObjectType, PullOptions, PullProgress, Repo, RepoMode, Summary, Type, Value,
    loose_path,
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
        client_ca_pem: client_ca.then(|| CA_PEM.to_vec()),
    });
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

/// `bind` refuses an empty listen list and TLS files that give no
/// configuration. It refuses them before it binds a listener.
#[test]
fn bad_options_are_refused() {
    let tmp = TmpDir::new("options");
    let (_, repo, _, _) = block_on(repo(tmp.path()));
    block_on(async {
        let mut opts = local();
        opts.listen.clear();
        let err = ostrya_server::bind(repo.clone(), opts).await.err().unwrap();
        assert!(matches!(err, ostrya_server::Error::Options(_)), "{err}");
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

/// A `GET` of the ref listing gives the bytes of `build_ref_listing` for the
/// prefixes of its query, with their length. No query takes all refs, and a
/// prefix given two times gives the bytes of one time. The server does not
/// see a `#` fragment. The requests go one
/// after the other, more of them than the listings that the server holds at
/// the same time, so each listing frees its place when its body ends.
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

        let (head, body) = get("?prefix=a%2Fb&prefix=main").await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(
            body,
            repo.build_ref_listing(&["a/b", "main"]).await.unwrap()
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

        let all = repo.build_ref_listing(&[]).await.unwrap();
        for query in ["", "?", "#prefix=main"] {
            let (head, body) = get(query).await;
            assert!(head.starts_with("HTTP/1.1 200 "), "{query}: {head}");
            assert_eq!(body, all, "{query}");
        }
        let main = repo.build_ref_listing(&["main"]).await.unwrap();
        for query in ["?prefix=main&prefix=main", "?prefix=main", "?prefix=main#x"] {
            let (head, body) = get(query).await;
            assert!(head.starts_with("HTTP/1.1 200 "), "{query}: {head}");
            assert_eq!(body, main, "{query}");
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
        let target = "/_ostrya/refs/v1?prefix=absent";
        for _ in 0..6 {
            let (head, body) = exchange(addrs[0], &ask("GET", target)).await;
            assert!(head.starts_with("HTTP/1.1 500 "), "{head}");
            assert_eq!(header(&head, "content-length"), Some("0"));
            assert!(body.is_empty());
        }
        let (head, body) = exchange(addrs[0], &ask("GET", "/_ostrya/refs/v1?prefix=main")).await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(body, repo.build_ref_listing(&["main"]).await.unwrap());
    });
}

/// A bad pair of the query and a prefix that is not a ref name get 400 with
/// an empty body.
#[test]
fn the_ref_listing_refuses_bad_queries() {
    let tmp = TmpDir::new("listing-bad");
    let (_, repo, _, _) = block_on(repo(tmp.path()));
    with_server(repo, local(), |addrs| async move {
        for query in [
            "?x=1",
            "?prefix",
            "?prefix=",
            "?prefix=a&&prefix=b",
            "?prefix=a%zz",
            "?prefix=a%00",
            "?prefix=%ff",
            "?prefix=a%2F%2Fb",
            "?prefix=..",
            "?prefix=a/",
            "?prefix=a%20b",
            "?prefix=-a",
            "?prefix=a*",
        ] {
            let target = format!("/_ostrya/refs/v1{query}");
            let (head, body) = exchange(addrs[0], &ask("GET", &target)).await;
            assert!(head.starts_with("HTTP/1.1 400 "), "{query}: {head}");
            assert_eq!(header(&head, "content-length"), Some("0"), "{query}");
            assert!(body.is_empty(), "{query}");
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
        let (head, body) = exchange(addr, &ask("GET", "/config?prefix=x")).await;
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
/// `build_ref_listing`. The client removes duplicate and covered prefixes,
/// and a ref name with bytes that the query escapes comes back unchanged.
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
            let cases: [(&[&str], &[&str]); 4] = [
                (&["a/b", "main"], &["a/b", "main"]),
                (&[], &[]),
                (&["main", "a/b/c", "a", "main", "a/b"], &["main", "a"]),
                (&ESCAPED_REFS, &ESCAPED_REFS),
            ];
            for (prefixes, built) in cases {
                let got = session.fetch_refs(prefixes).await.unwrap().unwrap();
                let want = repo.build_ref_listing(built).await.unwrap();
                assert_eq!(got, want, "{scheme}: {prefixes:?}");
            }
            let got = session.fetch_refs(&ESCAPED_REFS).await.unwrap().unwrap();
            let mut names = ESCAPED_REFS.map(str::to_owned).to_vec();
            names.sort();
            assert_eq!(listed_names(&got), names, "{scheme}");
            for name in ESCAPED_REFS {
                let got = session.fetch_refs(&[name]).await.unwrap().unwrap();
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
/// HTTP/1.1 and over HTTP/2. The target is `_ostrya/refs/v1?prefix=` and the
/// encoded prefix.
#[test]
fn fetch_refs_takes_a_target_at_the_client_limit() {
    let tmp = TmpDir::new("fetch-refs-target");
    let (_, repo, _, _) = block_on(repo(tmp.path()));
    let fixed = "_ostrya/refs/v1?prefix=".len();
    let prefix = prefix_of_encoded_len(16 * 1024 - fixed);
    let encoded = prefix.len() + 2 * prefix.matches('/').count();
    assert_eq!(fixed + encoded, 16 * 1024);
    for (opts, scheme, http2) in [(local(), "http", false), (tls(false), "https", true)] {
        let repo = repo.clone();
        let prefix = prefix.clone();
        with_server(repo.clone(), opts, |addrs| async move {
            let url = format!("{scheme}://127.0.0.1:{}/", addrs[0].port());
            let session = PullSession::Http(fetcher(url, http2, None).await);
            let got = session.fetch_refs(&[prefix.as_str()]).await;
            let want = repo.build_ref_listing(&[prefix.as_str()]).await.unwrap();
            assert_eq!(got.unwrap(), Some(want), "{scheme}");
        });
    }
}

/// A prefix with a part longer than 255 bytes gets the listing of an absent
/// prefix over HTTP/1.1 and over HTTP/2.
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
            let got = session.fetch_refs(&[long.as_str()]).await;
            let want = repo.build_ref_listing(&["absent"]).await.unwrap();
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
            let listing = session.fetch_refs(&["test"]).await.unwrap().unwrap();
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
