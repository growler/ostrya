//! Tests of the server over a `bare-user` repository:
//!
//! - the archive view over HTTP/1.1, and over TLS with HTTP/2 and HTTP/1.1
//! - the 404 of a refused path and of an absent path
//! - `HEAD`
//! - client certificates
//! - the stop on drop

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
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree,
    ObjectType, Repo, RepoMode, loose_path,
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
