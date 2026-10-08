//! An in-process static file server over a repository directory, for the
//! tests of a pull from a remote. The module also builds the source and
//! destination repositories of these tests.
//!
//! The server records these values:
//!
//! - each request path that it receives
//! - the status of the answer to each request
//! - the largest number of requests in flight at the same time
//! - the number of connections that it accepts
//!
//! The pull tests declare this module with a `path` attribute, so the other
//! tests do not build the server.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use futures_io::{AsyncRead, AsyncWrite};
use hyper::body::{Bytes, Frame, SizeHint};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree, Repo,
    RepoMode, SummaryOptions, Type, Value,
};
use ostrya_rt::{TcpListener, spawn};

pub const CA_PEM: &[u8] = include_bytes!("../../../../tests/fixtures/tls/ca.pem");
pub const SERVER_CERT_PEM: &[u8] = include_bytes!("../../../../tests/fixtures/tls/server.pem");
pub const SERVER_KEY_PEM: &[u8] = include_bytes!("../../../../tests/fixtures/tls/server.key.pem");
pub const OTHERNAME_CERT_PEM: &[u8] =
    include_bytes!("../../../../tests/fixtures/tls/server-othername.pem");
pub const OTHERNAME_KEY_PEM: &[u8] =
    include_bytes!("../../../../tests/fixtures/tls/server-othername.key.pem");
pub const UNTRUSTED_CERT_PEM: &[u8] =
    include_bytes!("../../../../tests/fixtures/tls/server-untrusted.pem");
pub const UNTRUSTED_KEY_PEM: &[u8] =
    include_bytes!("../../../../tests/fixtures/tls/server-untrusted.key.pem");

/// A fixed timestamp that makes the commits of a source repository reproducible.
pub const FIXED_TS: u64 = 1_700_000_000;

/// The `summary.sig` bytes that a remote publishes in the mirror tests.
///
/// A pull copies the file and does not read it, so any bytes are sufficient.
pub const SUMMARY_SIG: &[u8] = b"summary signature bytes";

// --- HTTP server -----------------------------------------------------------

/// A `futures-io` stream that hyper reads and writes.
pub struct TestIo<S> {
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
pub struct TestExecutor;

impl<F> hyper::rt::Executor<F> for TestExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        drop(spawn(future));
    }
}

/// A response body of prepared chunks.
///
/// If the declared length is more than the length of the chunks, hyper cuts
/// the connection in the middle of the response.
pub struct FileBody {
    chunks: Vec<Bytes>,
    declared: u64,
}

impl hyper::body::Body for FileBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let me = self.get_mut();
        if me.chunks.is_empty() {
            return Poll::Ready(None);
        }
        Poll::Ready(Some(Ok(Frame::data(me.chunks.remove(0)))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.declared)
    }
}

/// The rules that override the files of the served repository directory.
#[derive(Default)]
pub struct Policy {
    /// The request paths that get a 404 answer, whatever the directory holds.
    hidden: HashSet<String>,
    /// The request paths, each with the bytes that replace its body.
    tampered: HashMap<String, Vec<u8>>,
    /// The request paths that get a body shorter than its declared length, so
    /// hyper cuts the connection in the middle of the response.
    truncated: HashSet<String>,
    /// The request paths that get the same cut body, each with the number of
    /// cut answers left.
    ///
    /// If the count is 0, the server sends the full body.
    truncate_first: HashMap<String, usize>,
}

/// The server leaf certificate that a TLS [`RepoServer`] presents.
#[derive(Clone, Copy)]
pub enum Leaf {
    /// A valid leaf that the fixture authority signed, for `localhost` and
    /// `127.0.0.1`.
    Fixture,
    /// A valid leaf that the fixture authority signed, for neither
    /// `localhost` nor `127.0.0.1`.
    OtherName,
    /// A valid leaf for `localhost` and `127.0.0.1`, signed by an authority
    /// that no client trusts.
    Untrusted,
}

impl Leaf {
    /// Returns the certificate and the private key of the leaf, in PEM
    /// encoding.
    fn pem(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Leaf::Fixture => (SERVER_CERT_PEM, SERVER_KEY_PEM),
            Leaf::OtherName => (OTHERNAME_CERT_PEM, OTHERNAME_KEY_PEM),
            Leaf::Untrusted => (UNTRUSTED_CERT_PEM, UNTRUSTED_KEY_PEM),
        }
    }
}

/// An in-process static file server over a repository directory.
pub struct RepoServer {
    addr: SocketAddr,
    tls: bool,
    seen: Arc<Mutex<Vec<String>>>,
    /// Each request path with the status of its answer, in the order of the
    /// answers.
    answered: Arc<Mutex<Vec<(String, u16)>>>,
    policy: Arc<Mutex<Policy>>,
    /// The largest number of requests in flight at the same time.
    peak: Arc<AtomicUsize>,
    /// The number of connections that the server accepted.
    connections: Arc<AtomicUsize>,
}

impl RepoServer {
    pub async fn start(root: &Path, tls: bool) -> RepoServer {
        RepoServer::start_with_leaf(root, tls, Leaf::Fixture).await
    }

    /// Starts a server that presents `leaf`.
    ///
    /// The leaf sets which server certificate checks a TLS client can
    /// complete.
    pub async fn start_with_leaf(root: &Path, tls: bool, leaf: Leaf) -> RepoServer {
        let root = root.to_path_buf();
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let answered: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
        let policy: Arc<Mutex<Policy>> = Arc::new(Mutex::new(Policy::default()));
        let peak = Arc::new(AtomicUsize::new(0));
        let inflight = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let acceptor = tls.then(|| {
            futures_rustls::TlsAcceptor::from(Arc::new(server_config(&["h2", "http/1.1"], leaf)))
        });

        let task = (
            root,
            seen.clone(),
            answered.clone(),
            policy.clone(),
            peak.clone(),
            inflight,
            connections.clone(),
        );
        drop(spawn(async move {
            let (root, seen, answered, policy, peak, inflight, connections) = task;
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                connections.fetch_add(1, Ordering::SeqCst);
                let state = (
                    root.clone(),
                    seen.clone(),
                    answered.clone(),
                    policy.clone(),
                    peak.clone(),
                    inflight.clone(),
                );
                let acceptor = acceptor.clone();
                drop(spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            let Ok(tls) = acceptor.accept(stream).await else {
                                return;
                            };
                            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                            serve(tls, h2, state).await;
                        }
                        None => serve(stream, false, state).await,
                    }
                }));
            }
        }));
        RepoServer {
            addr,
            tls,
            seen,
            answered,
            policy,
            peak,
            connections,
        }
    }

    pub fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        // The fixture server certificate covers `localhost` and `127.0.0.1`.
        format!("{scheme}://localhost:{}", self.addr.port())
    }

    /// Returns the request paths that the server received, in order, without
    /// the leading slash.
    pub fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    /// Returns the request paths that the server received, as a set.
    pub fn seen_set(&self) -> HashSet<String> {
        self.seen().into_iter().collect()
    }

    pub fn peak_inflight(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn hide(&self, path: &str) {
        self.policy.lock().unwrap().hidden.insert(path.to_owned());
    }

    pub fn tamper(&self, path: &str, bytes: Vec<u8>) {
        self.policy
            .lock()
            .unwrap()
            .tampered
            .insert(path.to_owned(), bytes);
    }

    pub fn truncate(&self, path: &str) {
        self.policy
            .lock()
            .unwrap()
            .truncated
            .insert(path.to_owned());
    }

    /// Cuts the next `times` responses for `path`, then serves the full body.
    pub fn truncate_times(&self, path: &str, times: usize) {
        self.policy
            .lock()
            .unwrap()
            .truncate_first
            .insert(path.to_owned(), times);
    }

    /// Returns the number of requests that the server received for `path`.
    pub fn requests_for(&self, path: &str) -> usize {
        self.seen().iter().filter(|seen| *seen == path).count()
    }

    /// Returns the statuses of the answers to the requests for `path`, in
    /// order.
    pub fn statuses_for(&self, path: &str) -> Vec<u16> {
        self.answered
            .lock()
            .unwrap()
            .iter()
            .filter(|(answered, _)| answered == path)
            .map(|(_, status)| *status)
            .collect()
    }

    pub fn forget(&self) {
        self.seen.lock().unwrap().clear();
        self.answered.lock().unwrap().clear();
    }
}

pub type ServeState = (
    PathBuf,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Vec<(String, u16)>>>,
    Arc<Mutex<Policy>>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
);

/// Serves one connection from the repository directory.
pub async fn serve<S>(io: S, h2: bool, state: ServeState)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let io = TestIo {
        inner: io,
        scratch: Vec::new(),
    };
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let (root, seen, answered, policy, peak, inflight) = state.clone();
        async move {
            let path = request.uri().path().trim_start_matches('/').to_owned();
            seen.lock().unwrap().push(path.clone());
            let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            // A small delay makes the overlap of concurrent requests longer,
            // so the counter sees the peak that the pull reaches.
            ostrya_rt::Timer::after(std::time::Duration::from_millis(5)).await;
            let response = answer(&root, &path, &policy);
            answered
                .lock()
                .unwrap()
                .push((path, response.status().as_u16()));
            inflight.fetch_sub(1, Ordering::SeqCst);
            Ok::<_, Infallible>(response)
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

/// Returns the response for one request path.
pub fn answer(root: &Path, path: &str, policy: &Mutex<Policy>) -> Response<FileBody> {
    let (hidden, replacement, truncated) = {
        let mut policy = policy.lock().unwrap();
        let cut_once = match policy.truncate_first.get_mut(path) {
            Some(left) if *left > 0 => {
                *left -= 1;
                true
            }
            _ => false,
        };
        (
            policy.hidden.contains(path),
            policy.tampered.get(path).cloned(),
            cut_once || policy.truncated.contains(path),
        )
    };
    if hidden {
        return not_found();
    }
    let bytes = match replacement {
        Some(bytes) => bytes,
        None => match std::fs::read(root.join(path)) {
            Ok(bytes) => bytes,
            Err(_) => return not_found(),
        },
    };
    if truncated {
        // The declared length is more than the body holds, so hyper cuts the
        // connection when the body ends early.
        return Response::builder()
            .status(StatusCode::OK)
            .body(FileBody {
                chunks: vec![Bytes::copy_from_slice(&bytes[..bytes.len() / 2])],
                declared: bytes.len() as u64,
            })
            .unwrap();
    }
    Response::builder()
        .status(StatusCode::OK)
        .body(FileBody {
            declared: bytes.len() as u64,
            chunks: vec![Bytes::from(bytes)],
        })
        .unwrap()
}

pub fn not_found() -> Response<FileBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(FileBody {
            chunks: Vec::new(),
            declared: 0,
        })
        .unwrap()
}

/// Returns the rustls configuration of the fixture server.
pub fn server_config(alpn: &[&str], leaf: Leaf) -> rustls::ServerConfig {
    let provider = Arc::new(rustls_graviola::default_provider());
    let (cert_pem, key_pem) = leaf.pem();
    let certs: Vec<_> = rustls_pemfile::certs(&mut io::BufReader::new(cert_pem))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut io::BufReader::new(key_pem))
        .unwrap()
        .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    config
}

// --- repository helpers ----------------------------------------------------

/// Runs the `ostree` command, asserts that it succeeds, and returns its
/// standard output.
pub fn ostree(args: &[&str]) -> Vec<u8> {
    let out = Command::new("ostree")
        .args(args)
        .output()
        .expect("run ostree");
    assert!(
        out.status.success(),
        "ostree {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Builds a small source tree under `dir`.
///
/// The tree holds two regular files with different modes, a symlink, and a
/// nested subdirectory.
pub fn build_tree(dir: &Path, marker: &[u8]) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(dir.join("subdir")).unwrap();
    std::fs::write(dir.join("hello.txt"), marker).unwrap();
    std::fs::write(dir.join("exec.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    std::fs::write(dir.join("subdir/nested.txt"), b"nested\n").unwrap();
    symlink("hello.txt", dir.join("link")).unwrap();
    std::fs::set_permissions(
        dir.join("hello.txt"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::set_permissions(dir.join("exec.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Returns `len` bytes of a fixed sequence that a compressor cannot make
/// smaller.
///
/// A content object goes on the wire in deflated form. If the body compresses
/// well, the payload on the wire is a small fraction of the size that its
/// header declares. The buffers of the receive path can then hold the full
/// payload, whatever the size of the object.
///
/// An xorshift sequence deflates to stored blocks, so the body is as long as
/// the payload.
pub fn incompressible(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Returns the size of the largest `.filez` object in the archive repository at
/// `repo`.
///
/// This size is the longest body that a pull from the repository reads from a
/// connection.
pub fn largest_filez(repo: &Path) -> u64 {
    let mut largest = 0;
    for shard in std::fs::read_dir(repo.join("objects")).unwrap() {
        for entry in std::fs::read_dir(shard.unwrap().path()).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().is_some_and(|ext| ext == "filez") {
                largest = largest.max(entry.metadata().unwrap().len());
            }
        }
    }
    largest
}

/// Returns the `ostree.ref-binding` metadata dict that binds a commit to
/// `branch`.
pub fn ref_binding(branch: &str) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("ostree.ref-binding".to_owned()),
        Value::Variant(Box::new((
            Type::parse("as").unwrap(),
            Value::Array(vec![Value::Str(branch.to_owned())]),
        ))),
    ])])
}

/// Returns a small `a{sv}` dict for the detached metadata of a commit.
pub fn detached_dict() -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("test.detached".to_owned()),
        Value::Variant(Box::new((
            Type::parse("s").unwrap(),
            Value::Str("present".to_owned()),
        ))),
    ])])
}

/// Commits the subtree `sub` of `base` into `repo` under `branch`.
///
/// The commit gets the timestamp `timestamp` and the ref binding of `branch`.
/// The import uses the modifier flags `SKIP_XATTRS` and
/// `CANONICAL_PERMISSIONS`. The function sets `branch` to the commit.
pub async fn commit_tree(
    repo: &Repo,
    base: &Path,
    sub: &str,
    branch: &str,
    parent: Option<Checksum>,
    timestamp: u64,
) -> Checksum {
    commit_tree_with(
        repo,
        base,
        sub,
        branch,
        parent,
        timestamp,
        CommitModifierFlags::SKIP_XATTRS | CommitModifierFlags::CANONICAL_PERMISSIONS,
    )
    .await
}

/// Commits the subtree `sub` as [`commit_tree`] does, with the modifier flags
/// `flags`.
#[allow(clippy::too_many_arguments)]
pub async fn commit_tree_with(
    repo: &Repo,
    base: &Path,
    sub: &str,
    branch: &str,
    parent: Option<Checksum>,
    timestamp: u64,
    flags: CommitModifierFlags,
) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(flags);
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new(sub), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                parent,
                subject: Some(format!("{branch} {sub}")),
                timestamp: Some(timestamp),
                metadata: Some(ref_binding(branch)),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref(branch, Some(&commit));
    txn.commit().await.unwrap();
    commit
}

/// Builds a remote archive repository under `dir/remote`, with a summary.
///
/// The ref `test/main` names a commit of the small tree that `build_tree`
/// writes.
pub async fn build_remote(dir: &Path) -> (Repo, Checksum) {
    let src = dir.join("src");
    build_tree(&src, b"hello\n");
    let repo = Repo::create(&dir.join("remote"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let commit = commit_tree(&repo, dir, "src", "test/main", None, FIXED_TS).await;
    repo.regenerate_summary(&SummaryOptions {
        last_modified: Some(FIXED_TS),
        ..SummaryOptions::default()
    })
    .await
    .unwrap();
    (repo, commit)
}

/// Builds a remote archive repository under `dir/remote` with one commit and
/// two refs.
///
/// The refs `test/main` and `test/other` both name the commit. The
/// `ostree.ref-binding` of the commit lists only `test/main`. The summary lists
/// both refs.
pub async fn build_remote_two_refs(dir: &Path) -> (Repo, Checksum) {
    let src = dir.join("src");
    build_tree(&src, b"hello\n");
    let repo = Repo::create(&dir.join("remote"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let commit = commit_tree(&repo, dir, "src", "test/main", None, FIXED_TS).await;
    let txn = repo.transaction().await.unwrap();
    txn.set_ref("test/other", Some(&commit));
    txn.commit().await.unwrap();
    repo.regenerate_summary(&SummaryOptions {
        last_modified: Some(FIXED_TS),
        ..SummaryOptions::default()
    })
    .await
    .unwrap();
    (repo, commit)
}

/// Creates a destination repository under `dir/dest` with the remote `origin`
/// at `url`.
///
/// The section of `origin` sets `gpg-verify=false`, because the default is on
/// and the test remotes publish unsigned commits. The function writes the extra
/// `[remote]` keys of `extra` after this key. A verification test sets its own
/// policy in `extra`, and the last value of a repeated key applies.
pub async fn build_dest(dir: &Path, mode: RepoMode, url: &str, extra: &str) -> Repo {
    let path = dir.join("dest");
    let repo = Repo::create(&path, CreateOptions::new(mode)).await.unwrap();
    drop(repo);
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!(
        "\n[remote \"origin\"]\nurl={url}\ngpg-verify=false\n{extra}"
    ));
    std::fs::write(&config, text).unwrap();
    Repo::open(&path).await.unwrap()
}

/// Rewrites the `origin` section of the destination at `dir/dest` and opens
/// the repository again.
///
/// A test sets a second policy with this function on a repository that holds
/// the result of an earlier pull.
pub async fn reconfigure_dest(dir: &Path, url: &str, extra: &str) -> Repo {
    let path = dir.join("dest");
    let config = path.join("config");
    let text = std::fs::read_to_string(&config).unwrap();
    let core = text.split("\n[remote").next().unwrap().to_owned();
    std::fs::write(
        &config,
        format!("{core}\n[remote \"origin\"]\nurl={url}\ngpg-verify=false\n{extra}"),
    )
    .unwrap();
    Repo::open(&path).await.unwrap()
}

/// Returns the loose object path of a content object, as an archive remote
/// serves it.
pub fn filez_path(checksum: &str) -> String {
    format!("objects/{}/{}.filez", &checksum[..2], &checksum[2..])
}

/// Returns the loose object path of a metadata object.
pub fn meta_path(checksum: &Checksum, ext: &str) -> String {
    let hex = checksum.to_hex();
    format!("objects/{}/{}.{ext}", &hex[..2], &hex[2..])
}

/// Asserts that the repository holds no local ref under `refs/heads`.
///
/// The tests call it after a failed pull. The second assertion filters the same local
/// refs by the prefix `refs/remotes`, so it adds no check. The function does
/// not check the remote refs or the objects.
pub async fn assert_nothing_published(repo: &Repo) {
    assert!(repo.list_refs(None).await.unwrap().is_empty());
    assert!(
        repo.list_refs(Some("refs/remotes"))
            .await
            .unwrap()
            .is_empty()
    );
}

/// Returns the checksum of each content object of the tree that `build_tree`
/// writes, in sorted order.
///
/// The checksums are the names of the objects in the source repository.
pub async fn content_checksums(repo: &Repo, commit: &Checksum) -> Vec<Checksum> {
    let reachable = repo.traverse_commit(commit, -1).await.unwrap();
    let mut out: Vec<Checksum> = reachable
        .iter()
        .filter(|name| name.ty == ostrya::ObjectType::File)
        .map(|name| name.checksum)
        .collect();
    out.sort();
    out
}
