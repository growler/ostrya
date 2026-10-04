//! An in-process static file server over a repository directory, and the
//! builders of the source and destination repositories, for the tests of
//! the pull from a remote.
//!
//! The server records the request paths it saw, how many requests were in
//! flight at once, and how many connections it accepted.
//!
//! The tests of the pull declare this module with a `path` attribute, so the
//! other tests do not build the server.

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

/// A fixed timestamp, so a source repository's commits are reproducible.
pub const FIXED_TS: u64 = 1_700_000_000;

/// The `summary.sig` bytes a remote publishes in the mirror tests. A pull copies
/// the file without reading it, so any bytes serve.
pub const SUMMARY_SIG: &[u8] = b"summary signature bytes";

// --- server plumbing -------------------------------------------------------

/// A `futures-io` stream presented to hyper.
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

/// A response body of pre-baked chunks, which may declare more than it carries
/// so the connection is cut mid-response.
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

/// What the served repository directory answers with, beyond its own files.
#[derive(Default)]
pub struct Policy {
    /// Request paths answered 404 whatever the directory holds.
    hidden: HashSet<String>,
    /// Request paths whose body is replaced by these bytes.
    tampered: HashMap<String, Vec<u8>>,
    /// Request paths answered with a body shorter than the length it declares,
    /// which cuts the connection mid-response.
    truncated: HashSet<String>,
    /// Request paths cut the same way for as many requests as the count left,
    /// and served whole after that.
    truncate_first: HashMap<String, usize>,
}

/// Which server leaf a TLS [`RepoServer`] presents.
#[derive(Clone, Copy)]
pub enum Leaf {
    /// Signed by the fixture authority, valid, covering `localhost` and
    /// `127.0.0.1`.
    Fixture,
    /// Signed by the fixture authority and valid, covering neither name.
    OtherName,
    /// Covering both names and valid, signed by an authority nothing trusts.
    Untrusted,
}

impl Leaf {
    /// The certificate and the private key, both PEM-encoded.
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
    policy: Arc<Mutex<Policy>>,
    /// The most requests the server had in flight at once.
    peak: Arc<AtomicUsize>,
    /// How many connections the server accepted.
    connections: Arc<AtomicUsize>,
}

impl RepoServer {
    pub async fn start(root: &Path, tls: bool) -> RepoServer {
        RepoServer::start_with_leaf(root, tls, Leaf::Fixture).await
    }

    /// A server presenting `leaf`, which decides which of the server
    /// certificate checks a TLS client can complete.
    pub async fn start_with_leaf(root: &Path, tls: bool, leaf: Leaf) -> RepoServer {
        let root = root.to_path_buf();
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
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
            policy.clone(),
            peak.clone(),
            inflight,
            connections.clone(),
        );
        drop(spawn(async move {
            let (root, seen, policy, peak, inflight, connections) = task;
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                connections.fetch_add(1, Ordering::SeqCst);
                let state = (
                    root.clone(),
                    seen.clone(),
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

    /// The request paths the server saw, in order, without the leading slash.
    pub fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    /// The request paths the server saw, as a set.
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

    /// Cut the next `times` responses for `path`, and serve it whole after.
    pub fn truncate_times(&self, path: &str, times: usize) {
        self.policy
            .lock()
            .unwrap()
            .truncate_first
            .insert(path.to_owned(), times);
    }

    /// How many requests the server saw for `path`.
    pub fn requests_for(&self, path: &str) -> usize {
        self.seen().iter().filter(|seen| *seen == path).count()
    }

    pub fn forget(&self) {
        self.seen.lock().unwrap().clear();
    }
}

pub type ServeState = (
    PathBuf,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Policy>>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
);

/// Serve one connection out of the repository directory.
pub async fn serve<S>(io: S, h2: bool, state: ServeState)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let io = TestIo {
        inner: io,
        scratch: Vec::new(),
    };
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let (root, seen, policy, peak, inflight) = state.clone();
        async move {
            let path = request.uri().path().trim_start_matches('/').to_owned();
            seen.lock().unwrap().push(path.clone());
            let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            // A small delay widens the window in which concurrent requests
            // overlap, so the peak the pull reaches is what the counter sees.
            ostrya_rt::Timer::after(std::time::Duration::from_millis(5)).await;
            let response = answer(&root, &path, &policy);
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

/// The response for one request path.
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
        // Declaring more than the body carries makes hyper cut the connection
        // once the body ends short.
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

/// The fixture server's rustls configuration.
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

/// Run the `ostree` tool and assert it succeeded.
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

/// Build a small source tree under `dir`: two regular files of differing modes,
/// a symlink, and a nested subdirectory.
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

/// `len` bytes of a fixed sequence a compressor cannot shrink.
///
/// A content object reaches the wire deflated, so a compressible body would leave
/// the payload a fraction of the size its header declares and the receive path's
/// buffers would hold it whole whatever the object's own size is. An xorshift
/// sequence deflates to stored blocks, so the body is as long as the payload.
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

/// The largest `.filez` object the archive repository at `repo` stores, which is
/// the longest body a pull from it takes off a connection.
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

/// The `ostree.ref-binding` metadata dict binding a commit to `branch`.
pub fn ref_binding(branch: &str) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("ostree.ref-binding".to_owned()),
        Value::Variant(Box::new((
            Type::parse("as").unwrap(),
            Value::Array(vec![Value::Str(branch.to_owned())]),
        ))),
    ])])
}

/// A small `a{sv}` dict a commit's detached metadata can carry.
pub fn detached_dict() -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("test.detached".to_owned()),
        Value::Variant(Box::new((
            Type::parse("s").unwrap(),
            Value::Str("present".to_owned()),
        ))),
    ])])
}

/// Commit subtree `sub` of `base` into `repo` under `branch`, with a fixed
/// timestamp and the branch's ref binding.
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

/// Commit subtree `sub` as [`commit_tree`] does, under the given modifier flags.
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

/// A remote archive repository under `dir/remote`, holding `test/main` over the
/// small tree, with a summary.
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

/// A remote archive repository under `dir/remote` holding one commit named by
/// both `test/main` and `test/other`, whose `ostree.ref-binding` lists
/// `test/main` alone, with a summary listing both refs.
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

/// A destination repository under `dir/dest` whose config names `origin` at
/// `url`, with the extra `[remote]` keys `extra` supplies.
///
/// The section turns `gpg-verify` off, since the default is on and these
/// remotes publish unsigned commits; `extra` is written after it, so a
/// verification test states its own policy there and the repeated key takes the
/// last value.
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

/// Rewrite the `origin` section of the destination at `dir/dest` and reopen it,
/// which is how a test states a second policy over a repository that already
/// holds what an earlier pull landed.
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

/// The loose object path of a content object as an archive remote serves it.
pub fn filez_path(checksum: &str) -> String {
    format!("objects/{}/{}.filez", &checksum[..2], &checksum[2..])
}

/// The loose object path of a metadata object.
pub fn meta_path(checksum: &Checksum, ext: &str) -> String {
    let hex = checksum.to_hex();
    format!("objects/{}/{}.{ext}", &hex[..2], &hex[2..])
}

/// Assert that the repository holds no ref and no object beyond what it started
/// with, which is what a failed pull leaves behind.
pub async fn assert_nothing_published(repo: &Repo) {
    assert!(repo.list_refs(None).await.unwrap().is_empty());
    assert!(
        repo.list_refs(Some("refs/remotes"))
            .await
            .unwrap()
            .is_empty()
    );
}

/// Every content object of the tree `build_tree` writes, by checksum, as the
/// source repository named them.
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
