//! HTTP pull from a remote repository (Phase 16c).
//!
//! Every test serves a repository directory from an in-process static file
//! server, over cleartext HTTP/1.1 and, where the transport matters, over TLS
//! with ALPN selecting HTTP/2. The source repositories are built with the port
//! itself; the interop tests that need the `ostree` tool are skipped when it is
//! absent.
//!
//! The server records the request paths it saw, which is what the request-set
//! assertions read, how many requests were in flight at once, which is what the
//! concurrency assertion reads, and how many connections it accepted, which is
//! what the connection-reuse assertion reads.

mod common;

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

use common::{TmpDir, ostree_available};
use futures_io::{AsyncRead, AsyncWrite};
use hyper::body::{Bytes, Frame, SizeHint};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CommitState, CreateOptions,
    DeltaOptions, Error, FsckOptions, MutableTree, PullFlags, PullOptions, Repo, RepoMode,
    SummaryOptions, TimestampCheck, TreeEntry, Type, Value,
};
use ostrya_rt::{TcpListener, block_on, spawn};

const CA_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/ca.pem");
const SERVER_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.pem");
const SERVER_KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.key.pem");

/// A fixed timestamp, so a source repository's commits are reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// The `summary.sig` bytes a remote publishes in the mirror tests. A pull copies
/// the file without reading it, so any bytes serve.
const SUMMARY_SIG: &[u8] = b"summary signature bytes";

// --- server plumbing -------------------------------------------------------

/// A `futures-io` stream presented to hyper.
struct TestIo<S> {
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
struct TestExecutor;

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
struct FileBody {
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
struct Policy {
    /// Request paths answered 404 whatever the directory holds.
    hidden: HashSet<String>,
    /// Request paths whose body is replaced by these bytes.
    tampered: HashMap<String, Vec<u8>>,
    /// Request paths answered with a body shorter than the length it declares,
    /// which cuts the connection mid-response.
    truncated: HashSet<String>,
}

/// An in-process static file server over a repository directory.
struct RepoServer {
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
    async fn start(root: &Path, tls: bool) -> RepoServer {
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
            futures_rustls::TlsAcceptor::from(Arc::new(server_config(&["h2", "http/1.1"])))
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

    fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        // The fixture server certificate covers `localhost` and `127.0.0.1`.
        format!("{scheme}://localhost:{}", self.addr.port())
    }

    /// The request paths the server saw, in order, without the leading slash.
    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    /// The request paths the server saw, as a set.
    fn seen_set(&self) -> HashSet<String> {
        self.seen().into_iter().collect()
    }

    fn peak_inflight(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn hide(&self, path: &str) {
        self.policy.lock().unwrap().hidden.insert(path.to_owned());
    }

    fn tamper(&self, path: &str, bytes: Vec<u8>) {
        self.policy
            .lock()
            .unwrap()
            .tampered
            .insert(path.to_owned(), bytes);
    }

    fn truncate(&self, path: &str) {
        self.policy
            .lock()
            .unwrap()
            .truncated
            .insert(path.to_owned());
    }

    fn forget(&self) {
        self.seen.lock().unwrap().clear();
    }
}

type ServeState = (
    PathBuf,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Policy>>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
);

/// Serve one connection out of the repository directory.
async fn serve<S>(io: S, h2: bool, state: ServeState)
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
fn answer(root: &Path, path: &str, policy: &Mutex<Policy>) -> Response<FileBody> {
    let (hidden, replacement, truncated) = {
        let policy = policy.lock().unwrap();
        (
            policy.hidden.contains(path),
            policy.tampered.get(path).cloned(),
            policy.truncated.contains(path),
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

fn not_found() -> Response<FileBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(FileBody {
            chunks: Vec::new(),
            declared: 0,
        })
        .unwrap()
}

/// The fixture server's rustls configuration.
fn server_config(alpn: &[&str]) -> rustls::ServerConfig {
    let provider = Arc::new(rustls_graviola::default_provider());
    let certs: Vec<_> = rustls_pemfile::certs(&mut io::BufReader::new(SERVER_CERT_PEM))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut io::BufReader::new(SERVER_KEY_PEM))
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
fn ostree(args: &[&str]) -> Vec<u8> {
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
fn build_tree(dir: &Path, marker: &[u8]) {
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
fn incompressible(len: usize) -> Vec<u8> {
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
fn largest_filez(repo: &Path) -> u64 {
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
fn ref_binding(branch: &str) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("ostree.ref-binding".to_owned()),
        Value::Variant(Box::new((
            Type::parse("as").unwrap(),
            Value::Array(vec![Value::Str(branch.to_owned())]),
        ))),
    ])])
}

/// A small `a{sv}` dict a commit's detached metadata can carry.
fn detached_dict() -> Value {
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
async fn commit_tree(
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
async fn commit_tree_with(
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
async fn build_remote(dir: &Path) -> (Repo, Checksum) {
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
async fn build_remote_two_refs(dir: &Path) -> (Repo, Checksum) {
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
async fn build_dest(dir: &Path, mode: RepoMode, url: &str, extra: &str) -> Repo {
    let path = dir.join("dest");
    let repo = Repo::create(&path, CreateOptions::new(mode)).await.unwrap();
    drop(repo);
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!("\n[remote \"origin\"]\nurl={url}\n{extra}"));
    std::fs::write(&config, text).unwrap();
    Repo::open(&path).await.unwrap()
}

/// The loose object path of a content object as an archive remote serves it.
fn filez_path(checksum: &str) -> String {
    format!("objects/{}/{}.filez", &checksum[..2], &checksum[2..])
}

/// The loose object path of a metadata object.
fn meta_path(checksum: &Checksum, ext: &str) -> String {
    let hex = checksum.to_hex();
    format!("objects/{}/{}.{ext}", &hex[..2], &hex[2..])
}

/// Assert that the repository holds no ref and no object beyond what it started
/// with, which is what a failed pull leaves behind.
async fn assert_nothing_published(repo: &Repo) {
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
async fn content_checksums(repo: &Repo, commit: &Checksum) -> Vec<Checksum> {
    let reachable = repo.traverse_commit(commit, -1).await.unwrap();
    let mut out: Vec<Checksum> = reachable
        .iter()
        .filter(|name| name.ty == ostrya::ObjectType::File)
        .map(|name| name.checksum)
        .collect();
    out.sort();
    out
}

// --- tests -----------------------------------------------------------------

/// The base case: one ref, its commit, and its whole tree arrive, the ref lands
/// under `refs/remotes/`, and a second pull of the unchanged ref fetches no
/// object at all.
#[test]
fn pulls_a_ref_and_its_tree_then_fetches_nothing_the_second_time() {
    block_on(async {
        let dir = TmpDir::new("pull-http-basic");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let stats = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        assert_eq!(
            dest.commit_state(&commit).await.unwrap(),
            CommitState::Normal
        );
        assert_eq!(stats.content_imported, 4);
        assert!(stats.metadata_imported >= 4);

        // The order the tool's own pull asks in: the signature, the summary,
        // the config, then the commit's detached metadata before the commit.
        let seen = server.seen();
        assert_eq!(&seen[..3], ["summary.sig", "summary", "config"]);
        assert!(seen.contains(&meta_path(&commit, "commitmeta")));
        assert!(seen.contains(&meta_path(&commit, "commit")));
        for content in content_checksums(&remote, &commit).await {
            assert!(
                seen.contains(&filez_path(&content.to_hex())),
                "{content} was not fetched"
            );
        }

        // A repeat pull re-reads what may have changed and stops at the commit
        // it already holds: no object is fetched.
        server.forget();
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        let repeat = server.seen();
        assert_eq!(
            repeat,
            [
                "summary.sig".to_owned(),
                "summary".to_owned(),
                "config".to_owned(),
                meta_path(&commit, "commitmeta"),
            ]
        );
    });
}

/// The same pull over TLS, where ALPN selects HTTP/2 and every object travels
/// over one multiplexed connection.
#[test]
fn pulls_over_tls_with_http2() {
    block_on(async {
        let dir = TmpDir::new("pull-http-h2");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), true).await;
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, CA_PEM).unwrap();
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("tls-ca-path={}\n", ca.display()),
        )
        .await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// An archive remote into each destination mode. Every destination lands the
/// same commit and passes its own fsck, which for the bare family means the
/// re-ingested objects hash to the names they arrived under.
#[test]
fn pulls_an_archive_remote_into_every_destination_mode() {
    block_on(async {
        for mode in [
            RepoMode::Archive,
            RepoMode::BareUser,
            RepoMode::BareUserOnly,
            RepoMode::Bare,
        ] {
            // A bare destination writes each object's own uid and gid, which
            // for a canonically committed remote is root.
            if mode == RepoMode::Bare && !rustix::process::geteuid().is_root() {
                eprintln!("skipping the bare destination: not running as root");
                continue;
            }
            let dir = TmpDir::new(&format!("pull-http-mode-{}", mode.as_mode_str()));
            let (_remote, commit) = build_remote(dir.path()).await;
            let server = RepoServer::start(&dir.path().join("remote"), false).await;
            let dest = build_dest(dir.path(), mode, &server.url(), "").await;

            dest.pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

            assert_eq!(
                dest.resolve_rev("origin:test/main", true).await.unwrap(),
                Some(commit),
                "{mode:?}"
            );
            let report = dest.fsck(&FsckOptions::default()).await.unwrap();
            assert!(report.is_ok(), "{mode:?}: {:?}", report.errors);

            // The symlink object and the two regular files of differing modes
            // all crossed, so the tree reads back whole.
            let (tree, _) = dest.read_commit(&commit.to_hex()).await.unwrap();
            let mut names: Vec<String> = tree
                .read_dir()
                .await
                .unwrap()
                .into_iter()
                .map(|entry| match entry {
                    TreeEntry::File { name, .. } | TreeEntry::Dir { name, .. } => name,
                })
                .collect();
            names.sort();
            assert_eq!(
                names,
                ["exec.sh", "hello.txt", "link", "subdir"],
                "{mode:?}"
            );
        }
    });
}

/// The tool reads what an HTTP pull wrote: it resolves the ref, passes its own
/// fsck, and reads the tree back.
#[test]
fn the_tool_reads_what_an_http_pull_wrote() {
    if !ostree_available() {
        eprintln!("skipping: the ostree tool is not installed");
        return;
    }
    block_on(async {
        let dir = TmpDir::new("pull-http-interop");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let path = dir.path().join("dest");
        let repo_arg = format!("--repo={}", path.display());
        let resolved = ostree(&[&repo_arg, "rev-parse", "origin:test/main"]);
        assert_eq!(String::from_utf8_lossy(&resolved).trim(), commit.to_hex());
        ostree(&[&repo_arg, "fsck"]);
        let listing = ostree(&[&repo_arg, "ls", "-R", &commit.to_hex()]);
        let listing = String::from_utf8_lossy(&listing);
        assert!(listing.contains("/hello.txt"), "{listing}");
        assert!(listing.contains("/subdir/nested.txt"), "{listing}");
    });
}

/// A pull reads a payload of several reads from a remote the `ostree` tool built.
///
/// The object is 256 KiB of incompressible content, so the streaming loop runs
/// several iterations, the decoder's input buffer refills several times, and the
/// end-of-stream check meets the framing the tool wrote. The tool judges what
/// landed: it recomputes each object's checksum and reads the payload back.
#[test]
fn pulls_a_multi_read_payload_from_a_tool_built_remote() {
    if !ostree_available() {
        eprintln!("skipping: the ostree tool is not installed");
        return;
    }
    block_on(async {
        let dir = TmpDir::new("pull-http-tool-remote");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let payload = incompressible(256 * 1024);
        std::fs::write(src.join("big.bin"), &payload).unwrap();

        let remote = dir.path().join("remote");
        let remote_arg = format!("--repo={}", remote.display());
        ostree(&[&remote_arg, "init", "--mode=archive"]);
        let commit = String::from_utf8(ostree(&[
            &remote_arg,
            "commit",
            "-b",
            "test/main",
            "--timestamp=2020-01-01 00:00:00 +0000",
            &format!("--tree=dir={}", src.display()),
        ]))
        .unwrap()
        .trim()
        .to_owned();
        ostree(&[&remote_arg, "summary", "-u"]);
        // The premise of the test: one body is longer than one read of the
        // receive path's 128 KiB payload buffer.
        let largest = largest_filez(&remote);
        assert!(largest > 128 * 1024, "largest object is {largest} byte(s)");

        let server = RepoServer::start(&remote, false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(Checksum::from_hex(&commit).unwrap())
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());

        let dest_arg = format!("--repo={}", dir.path().join("dest").display());
        ostree(&[&dest_arg, "fsck"]);
        let read_back = ostree(&[&dest_arg, "cat", &commit, "/big.bin"]);
        assert_eq!(read_back.len(), payload.len());
        assert!(
            read_back == payload,
            "the payload the tool read back differs"
        );
    });
}

/// A remote serving no summary answers 404 for it, and each requested ref
/// resolves through `refs/heads/<ref>` instead.
#[test]
fn a_remote_with_no_summary_resolves_through_refs_heads() {
    block_on(async {
        let dir = TmpDir::new("pull-http-no-summary");
        let (_remote, commit) = build_remote(dir.path()).await;
        std::fs::remove_file(dir.path().join("remote/summary")).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        assert!(server.seen().contains(&"refs/heads/test/main".to_owned()));
    });
}

/// A ref name reaches the wire percent-encoded, so a name carrying `%` asks the
/// server for that name and not for what it would decode the escape into.
#[test]
fn a_ref_name_reaches_the_wire_percent_encoded() {
    block_on(async {
        let dir = TmpDir::new("pull-http-ref-encoded");
        build_remote(dir.path()).await;
        std::fs::remove_file(dir.path().join("remote/summary")).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // Unencoded, `test%2fmain` asks a server that decodes its request target
        // for `refs/heads/test/main` -- the ref that exists, under a name that
        // was not requested.
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test%2fmain".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RefNotFound(_)), "{err}");
        let seen = server.seen();
        assert!(
            seen.contains(&"refs/heads/test%252fmain".to_owned()),
            "the name reached the wire unencoded: {seen:?}"
        );
    });
}

/// A ref neither the summary nor `refs/heads` yields fails before anything is
/// fetched.
#[test]
fn an_absent_ref_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-absent-ref");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/other".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RefNotFound(_)), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// An empty ref list takes the remote's configured `branches`, and fails when
/// the remote configures none.
#[test]
fn an_empty_ref_list_takes_the_configured_branches() {
    block_on(async {
        let dir = TmpDir::new("pull-http-branches");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            "branches=test/main;\n",
        )
        .await;

        dest.pull("origin", PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

#[test]
fn an_empty_ref_list_with_no_branches_fails() {
    block_on(async {
        let dir = TmpDir::new("pull-http-no-branches");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull("origin", PullOptions::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no configured branches"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// A mirror pull of every ref takes them from the summary, writes them under
/// `refs/heads`, and copies the summary and its signature verbatim. The
/// signature bytes are arbitrary here: the pull copies them without reading
/// them, and verifying them is a later phase.
#[test]
fn a_mirror_pull_writes_local_refs_and_copies_the_summary() {
    block_on(async {
        let dir = TmpDir::new("pull-http-mirror");
        let (_remote, commit) = build_remote(dir.path()).await;
        std::fs::write(dir.path().join("remote/summary.sig"), SUMMARY_SIG).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                flags: PullFlags::MIRROR,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The ref is local, not under refs/remotes.
        assert_eq!(
            dest.resolve_rev("test/main", true).await.unwrap(),
            Some(commit)
        );
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());

        let published = std::fs::read(dir.path().join("remote/summary")).unwrap();
        let copied = std::fs::read(dir.path().join("dest/summary")).unwrap();
        assert_eq!(copied, published);
        // A client pulling from this repository with `gpg-verify-summary=true`
        // needs the signature that covers those bytes.
        let signature = std::fs::read(dir.path().join("dest/summary.sig")).unwrap();
        assert_eq!(signature, SUMMARY_SIG);
    });
}

/// A remote holding no `summary.sig` leaves the destination's own file as it
/// stands, which is what the tool was observed to do.
#[test]
fn a_mirror_pull_from_an_unsigned_summary_keeps_the_signature_here() {
    block_on(async {
        let dir = TmpDir::new("pull-http-mirror-unsigned");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        std::fs::write(dir.path().join("dest/summary.sig"), b"an earlier pull").unwrap();

        dest.pull(
            "origin",
            PullOptions {
                flags: PullFlags::MIRROR,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let published = std::fs::read(dir.path().join("remote/summary")).unwrap();
        let copied = std::fs::read(dir.path().join("dest/summary")).unwrap();
        assert_eq!(copied, published);
        let signature = std::fs::read(dir.path().join("dest/summary.sig")).unwrap();
        assert_eq!(signature, b"an earlier pull");
    });
}

/// A mirror pull takes its ref names from the summary, so a malformed name
/// there is refused where a requested one is: before the first object request,
/// rather than when the transaction resolves the refspec at publication.
#[test]
fn a_mirror_pull_rejects_a_malformed_summary_ref_name_before_fetching() {
    block_on(async {
        const NAME: &[u8] = b"test/main";
        // Same length, so the summary's frame offsets stay valid; the name gains
        // a traversal component, which the ref store refuses.
        const TRAVERSAL: &[u8] = b"test/../m";

        let dir = TmpDir::new("pull-http-mirror-bad-ref");
        build_remote(dir.path()).await;
        let published = std::fs::read(dir.path().join("remote/summary")).unwrap();
        let at = published
            .windows(NAME.len())
            .position(|window| window == NAME)
            .expect("the summary names the ref");
        let mut tampered = published.clone();
        tampered[at..at + NAME.len()].copy_from_slice(TRAVERSAL);

        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        server.tamper("summary", tampered);
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    flags: PullFlags::MIRROR,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        assert!(
            err.to_string().contains("invalid refspec component"),
            "{err}"
        );
        assert_nothing_published(&dest).await;
        let seen = server.seen();
        assert!(
            !seen.iter().any(|path| path.starts_with("objects/")),
            "an object was fetched before the ref names were checked: {seen:?}"
        );
    });
}

/// A mirror pull of named refs holds part of what the remote publishes, so it
/// writes neither the summary nor its signature.
#[test]
fn a_mirror_pull_of_named_refs_writes_no_summary() {
    block_on(async {
        let dir = TmpDir::new("pull-http-mirror-named");
        build_remote(dir.path()).await;
        std::fs::write(dir.path().join("remote/summary.sig"), SUMMARY_SIG).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                flags: PullFlags::MIRROR,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(!dir.path().join("dest/summary").exists());
        assert!(!dir.path().join("dest/summary.sig").exists());
    });
}

/// A mirror pull of every ref needs the summary to know what every ref is.
#[test]
fn a_mirror_pull_of_every_ref_needs_a_summary() {
    block_on(async {
        let dir = TmpDir::new("pull-http-mirror-no-summary");
        build_remote(dir.path()).await;
        std::fs::remove_file(dir.path().join("remote/summary")).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    flags: PullFlags::MIRROR,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("mirror mode"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// `depth` follows the commit chain, and a parent the remote does not hold ends
/// that chain without failing the pull.
#[test]
fn depth_follows_parents_and_an_absent_parent_ends_the_chain() {
    block_on(async {
        let dir = TmpDir::new("pull-http-depth");
        let src = dir.path().join("src");
        build_tree(&src, b"first\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let first = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        std::fs::write(src.join("hello.txt"), b"second\n").unwrap();
        let second = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(first),
            FIXED_TS + 1,
        )
        .await;
        std::fs::write(src.join("hello.txt"), b"third\n").unwrap();
        let third = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(second),
            FIXED_TS + 2,
        )
        .await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();

        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // Two parents deep reaches all three commits.
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                depth: 2,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        for commit in [first, second, third] {
            assert!(
                dest.has_object(ostrya::ObjectType::Commit, &commit)
                    .await
                    .unwrap(),
                "{commit} was not pulled"
            );
            assert_eq!(
                dest.commit_state(&commit).await.unwrap(),
                CommitState::Normal
            );
        }
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());

        // A remote that has pruned the root ends the chain there rather than
        // failing: the same shape as a local source with truncated history.
        let dir2 = TmpDir::new("pull-http-depth-truncated");
        let dest2 = build_dest(dir2.path(), RepoMode::Archive, &server.url(), "").await;
        server.hide(&meta_path(&first, "commit"));
        dest2
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    depth: -1,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert!(
            dest2
                .has_object(ostrya::ObjectType::Commit, &second)
                .await
                .unwrap()
        );
        assert!(
            !dest2
                .has_object(ostrya::ObjectType::Commit, &first)
                .await
                .unwrap()
        );
        assert_eq!(
            dest2.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(third)
        );
    });
}

/// A pull at a greater depth extends the history a shallower pull left: the tip
/// this repository already holds complete is walked past, and its parent arrives.
#[test]
fn a_deep_pull_extends_a_shallow_history() {
    block_on(async {
        let dir = TmpDir::new("pull-http-deepen");
        let src = dir.path().join("src");
        build_tree(&src, b"first\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let first = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        std::fs::write(src.join("hello.txt"), b"second\n").unwrap();
        let second = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(first),
            FIXED_TS + 1,
        )
        .await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();

        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // The tip alone, which leaves the parent absent.
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                depth: 0,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.commit_state(&second).await.unwrap(),
            CommitState::Normal
        );
        assert!(
            !dest
                .has_object(ostrya::ObjectType::Commit, &first)
                .await
                .unwrap()
        );

        // The whole history, which has to walk past the tip already here.
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                depth: -1,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(
            dest.has_object(ostrya::ObjectType::Commit, &first)
                .await
                .unwrap(),
            "the deep pull did not fetch the parent commit"
        );
        assert_eq!(
            dest.commit_state(&first).await.unwrap(),
            CommitState::Normal
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// A parent the remote answers 404 for ends the chain, and its detached metadata
/// is dropped rather than written: the `.commitmeta` is fetched ahead of the
/// commit and written once the commit object is here.
#[test]
fn a_chain_ending_parent_leaves_no_detached_metadata() {
    block_on(async {
        let dir = TmpDir::new("pull-http-detached-chain-end");
        let src = dir.path().join("src");
        build_tree(&src, b"first\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let first = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        std::fs::write(src.join("hello.txt"), b"second\n").unwrap();
        let second = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(first),
            FIXED_TS + 1,
        )
        .await;
        // Both commits carry detached metadata, so the pull has bytes in hand
        // for the parent whose commit object it cannot fetch.
        for commit in [first, second] {
            remote
                .write_commit_detached_metadata(&commit, Some(&detached_dict()))
                .await
                .unwrap();
        }
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();

        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        server.hide(&meta_path(&first, "commit"));
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                depth: -1,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The parent's detached metadata was fetched and dropped; the tip's was
        // written with the commit it belongs to.
        assert!(
            server.seen_set().contains(&meta_path(&first, "commitmeta")),
            "the parent's detached metadata was not requested"
        );
        let orphan = dir
            .path()
            .join("dest")
            .join(meta_path(&first, "commitmeta"));
        assert!(!orphan.exists(), "{} was written", orphan.display());
        assert!(
            dest.read_commit_detached_metadata(&second)
                .await
                .unwrap()
                .is_some()
        );
    });
}

/// A remote that is not archive is refused on its config mode, before any
/// object is requested.
#[test]
fn a_non_archive_remote_is_refused_on_its_config_mode() {
    block_on(async {
        let dir = TmpDir::new("pull-http-bare-remote");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::BareUser),
        )
        .await
        .unwrap();
        commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        assert!(err.to_string().contains("bare-user"), "{err}");
        // Nothing beyond the three root files was asked for.
        assert_eq!(server.seen(), ["summary.sig", "summary", "config"]);
        assert_nothing_published(&dest).await;
    });
}

/// A corrupt object on the remote is caught where it is stored: the write path
/// names what it stores, so the pull fails and publishes nothing.
#[test]
fn a_corrupt_object_fails_the_pull_with_a_checksum_mismatch() {
    block_on(async {
        let dir = TmpDir::new("pull-http-corrupt");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // Replace one content object's stored bytes with another's, which is a
        // well-formed object under the wrong name.
        let contents = content_checksums(&remote, &commit).await;
        let victim = filez_path(&contents[0].to_hex());
        let donor = filez_path(&contents[1].to_hex());
        let bytes = std::fs::read(dir.path().join("remote").join(&donor)).unwrap();
        server.tamper(&victim, bytes);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ChecksumMismatch { .. }), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// A payload that decompresses past the size its own header declares is refused
/// there, which bounds what is written before the checksum comparison at the end
/// of the payload is reached. The declared size is not part of the object's
/// identity, so nothing else in the pull looks at it.
#[test]
fn a_payload_outgrowing_its_declared_size_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-declared-size");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // The stored form is a four-byte header length, four zero bytes, then the
        // header, whose first field is the payload's uncompressed size. Declaring
        // one byte leaves the object's bytes otherwise as they were.
        let mut victim = None;
        for checksum in content_checksums(&remote, &commit).await {
            let path = filez_path(&checksum.to_hex());
            let stored = std::fs::read(dir.path().join("remote").join(&path)).unwrap();
            let declared = u64::from_be_bytes(stored[8..16].try_into().unwrap());
            if declared > 1 {
                victim = Some((path, stored));
                break;
            }
        }
        let (path, mut stored) = victim.expect("the fixture tree holds a payload-bearing file");
        stored[8..16].copy_from_slice(&1u64.to_be_bytes());
        server.tamper(&path, stored);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        assert!(err.to_string().contains("outgrew the 1 byte"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// A payload that decompresses to nothing however long it runs -- empty non-final
/// DEFLATE blocks, five bytes each -- is refused against the bound its declared
/// size sets for the compressed side. The decompressed bound never trips against
/// such a stream, and the progress deadline measures silence, which a stream that
/// keeps delivering never falls into.
#[test]
fn a_compressed_payload_passing_its_bound_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-compressed-bound");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // The header is left as it was, so the object declares the size it always
        // did; what replaces the payload behind it decompresses to nothing.
        let mut victim = None;
        for checksum in content_checksums(&remote, &commit).await {
            let path = filez_path(&checksum.to_hex());
            let stored = std::fs::read(dir.path().join("remote").join(&path)).unwrap();
            let declared = u64::from_be_bytes(stored[8..16].try_into().unwrap());
            if declared > 1 {
                victim = Some((path, stored, declared));
                break;
            }
        }
        let (path, stored, declared) =
            victim.expect("the fixture tree holds a payload-bearing file");
        let header_len = u32::from_be_bytes(stored[..4].try_into().unwrap()) as usize;
        let bound = declared + declared / 1024 + 64 * 1024;
        let mut tampered = stored[..8 + header_len].to_vec();
        for _ in 0..(bound / 5 + 2) {
            tampered.extend_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xff]);
        }
        server.tamper(&path, tampered);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        assert!(
            err.to_string()
                .contains(&format!("passed the {bound} byte")),
            "{err}"
        );
        assert_nothing_published(&dest).await;
    });
}

/// A commit object substituted on the remote -- another commit's bytes, on the
/// same ref, under the wrong name -- fails where the commit object is stored,
/// which is before its tree is asked for.
#[test]
fn a_substituted_commit_object_fails_before_its_tree_is_fetched() {
    block_on(async {
        let dir = TmpDir::new("pull-http-commit-substituted");
        let src = dir.path().join("src");
        build_tree(&src, b"first\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let first = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        std::fs::write(src.join("hello.txt"), b"second\n").unwrap();
        let second = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(first),
            FIXED_TS + 1,
        )
        .await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();

        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        // The tip serves its parent's bytes: a commit that parses, carries the
        // same ref binding, and is not the commit that was asked for.
        let donor =
            std::fs::read(dir.path().join("remote").join(meta_path(&first, "commit"))).unwrap();
        server.tamper(&meta_path(&second, "commit"), donor);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ChecksumMismatch { .. }), "{err}");
        assert_nothing_published(&dest).await;
        let seen = server.seen();
        assert!(
            !seen.iter().any(|path| path.ends_with(".filez")),
            "the tree was fetched before the commit was checked: {seen:?}"
        );
    });
}

/// An object the remote does not hold fails the pull, publishing nothing and
/// leaving the commit's marker behind.
#[test]
fn a_missing_object_fails_the_pull_and_leaves_the_marker() {
    block_on(async {
        let dir = TmpDir::new("pull-http-missing");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let contents = content_checksums(&remote, &commit).await;
        server.hide(&filez_path(&contents[0].to_hex()));

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }), "{err}");
        assert_nothing_published(&dest).await;
        let marker = dir
            .path()
            .join("dest/state")
            .join(format!("{}.commitpartial", commit.to_hex()));
        assert!(marker.exists(), "the marker was not left behind");
    });
}

/// A commit-only pull fetches the commit object alone, leaves a zero-length
/// marker, and reports the commit partial.
#[test]
fn a_commit_only_pull_leaves_the_commit_partial() {
    block_on(async {
        let dir = TmpDir::new("pull-http-commit-only");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let stats = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    flags: PullFlags::COMMIT_ONLY,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(stats.metadata_imported, 1);
        assert_eq!(stats.content_imported, 0);
        assert_eq!(
            dest.commit_state(&commit).await.unwrap(),
            CommitState::Partial
        );
        let marker = dir
            .path()
            .join("dest/state")
            .join(format!("{}.commitpartial", commit.to_hex()));
        assert_eq!(std::fs::metadata(&marker).unwrap().len(), 0);

        // Completing the pull clears it.
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.commit_state(&commit).await.unwrap(),
            CommitState::Normal
        );
        assert!(!marker.exists());
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// The timestamp check refuses a fetched tip strictly older than what it is
/// checked against, and accepts an equal one.
#[test]
fn the_timestamp_check_refuses_only_a_strictly_older_tip() {
    block_on(async {
        let dir = TmpDir::new("pull-http-timestamp");
        let src = dir.path().join("src");
        build_tree(&src, b"older\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let older = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // The destination already holds a newer commit under the same ref.
        std::fs::write(src.join("hello.txt"), b"newer\n").unwrap();
        let newer = commit_tree(
            &dest,
            dir.path(),
            "src",
            "origin:test/main",
            None,
            FIXED_TS + 100,
        )
        .await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    timestamp_check: TimestampCheck::CurrentRef,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains(&older.to_hex()), "{message}");
        assert!(message.contains(&newer.to_hex()), "{message}");
        assert!(message.contains(&FIXED_TS.to_string()), "{message}");
        assert!(message.contains(&(FIXED_TS + 100).to_string()), "{message}");
        // The ref still names what it did.
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(newer)
        );

        // An equal timestamp passes: the check is strict.
        let equal = commit_tree(&dest, dir.path(), "src", "origin:test/main", None, FIXED_TS).await;
        assert_ne!(equal, older);
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                timestamp_check: TimestampCheck::CurrentRef,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(older)
        );
    });
}

/// `TimestampCheck::Rev` compares against a named commit rather than the ref's
/// current tip.
#[test]
fn the_timestamp_check_can_name_the_commit_to_compare_against() {
    block_on(async {
        let dir = TmpDir::new("pull-http-timestamp-rev");
        let src = dir.path().join("src");
        build_tree(&src, b"older\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // A commit in the destination under an unrelated ref, newer than the
        // remote's tip.
        std::fs::write(src.join("hello.txt"), b"newer\n").unwrap();
        let reference = commit_tree(
            &dest,
            dir.path(),
            "src",
            "local/reference",
            None,
            FIXED_TS + 100,
        )
        .await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    timestamp_check: TimestampCheck::Rev(reference),
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains(&reference.to_hex()), "{err}");
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
    });
}

/// Two requested refs naming one commit are each checked against its ref
/// binding. The commit is fetched once, so the second ref has no step of its own,
/// and the flag remains the only way out.
#[test]
fn a_second_ref_at_one_commit_is_checked_against_the_binding() {
    block_on(async {
        let dir = TmpDir::new("pull-http-two-refs-binding");
        let (_remote, commit) = build_remote_two_refs(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned(), "test/other".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("test/other"), "{message}");
        assert!(message.contains(&commit.to_hex()), "{message}");
        assert_nothing_published(&dest).await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned(), "test/other".to_owned()],
                flags: PullFlags::DISABLE_VERIFY_BINDINGS,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/other", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// The timestamp check runs for each of two requested refs naming one commit, so
/// a second ref whose current tip here is newer refuses the pull.
#[test]
fn a_second_ref_at_one_commit_is_checked_against_its_timestamp() {
    block_on(async {
        let dir = TmpDir::new("pull-http-two-refs-timestamp");
        let (_remote, older) = build_remote_two_refs(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // Only the second ref names a newer commit here, so only its check
        // refuses the fetched tip.
        std::fs::write(dir.path().join("src/hello.txt"), b"newer\n").unwrap();
        let newer = commit_tree(
            &dest,
            dir.path(),
            "src",
            "origin:test/other",
            None,
            FIXED_TS + 100,
        )
        .await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned(), "test/other".to_owned()],
                    flags: PullFlags::DISABLE_VERIFY_BINDINGS,
                    timestamp_check: TimestampCheck::CurrentRef,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains(&older.to_hex()), "{message}");
        assert!(message.contains(&newer.to_hex()), "{message}");
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
        assert_eq!(
            dest.resolve_rev("origin:test/other", true).await.unwrap(),
            Some(newer)
        );
    });
}

/// A localcache repository supplies an object the remote answers 404 for, and
/// without it the same pull fails.
#[test]
fn a_localcache_repository_supplies_an_object_the_remote_lost() {
    block_on(async {
        let dir = TmpDir::new("pull-http-localcache");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;

        // A cache holding the whole commit, built by pulling it before the
        // remote loses the object.
        let cache = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        cache
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        std::fs::rename(dir.path().join("dest"), dir.path().join("cache")).unwrap();
        let cache = Repo::open(&dir.path().join("cache")).await.unwrap();

        let contents = content_checksums(&remote, &commit).await;
        server.hide(&filez_path(&contents[0].to_hex()));

        // Without the cache the object is gone and the pull fails.
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }), "{err}");

        // With it, the pull completes and the object is never requested.
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        server.forget();
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                localcache_repos: vec![cache],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        assert!(!server.seen().contains(&filez_path(&contents[0].to_hex())));
    });
}

/// One slot pins the request order to the plan's drain order: the commit, then
/// the scan, then the content.
#[test]
fn a_single_slot_pins_the_request_order() {
    block_on(async {
        let dir = TmpDir::new("pull-http-serial");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                max_outstanding_fetches: Some(1),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(server.peak_inflight(), 1);
        let seen = server.seen();
        let objects: Vec<&String> = seen
            .iter()
            .filter(|path| path.starts_with("objects/"))
            .collect();
        // The commit's detached metadata and the commit itself come first, then
        // the metadata the scan is blocked on, and the content last.
        assert_eq!(*objects[0], meta_path(&commit, "commitmeta"));
        assert_eq!(*objects[1], meta_path(&commit, "commit"));
        let first_content = objects
            .iter()
            .position(|path| path.ends_with(".filez"))
            .expect("content was fetched");
        let last_meta = objects
            .iter()
            .rposition(|path| path.ends_with(".dirtree") || path.ends_with(".dirmeta"))
            .expect("metadata was fetched");
        assert!(
            last_meta < first_content,
            "content was fetched before the scan finished: {objects:?}"
        );
        let _ = remote;
    });
}

/// A pull reuses one connection per slot: each step reads its response to the
/// end, which returns the connection to the pool for the next step. One slot
/// makes every request share one connection, so a step that left its response
/// unfinished would cost a connection setup and show up here.
#[test]
fn one_slot_pulls_every_object_over_one_connection() {
    block_on(async {
        let dir = TmpDir::new("pull-http-one-connection");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                max_outstanding_fetches: Some(1),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The fixture tree carries regular files and a symlink, so both content
        // paths are covered.
        let contents = content_checksums(&remote, &commit).await;
        assert!(contents.len() > 1);
        assert_eq!(server.connections(), 1, "requests: {:?}", server.seen());
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// A content object declaring a header past the header cap is refused, so the
/// receive path allocates no buffer for it.
#[test]
fn an_oversized_content_header_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-big-header");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // One byte past the 1 MiB header cap, with the rest of the object left as
        // it was: the length is refused before its bytes are read.
        let checksum = content_checksums(&remote, &commit)
            .await
            .pop()
            .expect("the fixture tree holds a content object");
        let path = filez_path(&checksum.to_hex());
        let mut bytes = std::fs::read(dir.path().join("remote").join(&path)).unwrap();
        bytes[..4].copy_from_slice(&(1024u32 * 1024 + 1).to_be_bytes());
        server.tamper(&path, bytes);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        assert!(err.to_string().contains("size cap"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// A content object followed by bytes its payload does not account for is
/// refused, since the stream a correct object ends is the connection's own.
#[test]
fn trailing_bytes_after_a_payload_fail_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-trailing");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // A regular file, so the bytes land after a deflated payload rather than
        // after a symlink's header.
        let (tree, _) = remote.read_commit(&commit.to_hex()).await.unwrap();
        let mut content = None;
        for entry in tree.read_dir().await.unwrap() {
            if let TreeEntry::File { name, checksum } = entry
                && name == "hello.txt"
            {
                content = Some(checksum);
            }
        }
        let path = filez_path(&content.expect("hello.txt").to_hex());
        let mut bytes = std::fs::read(dir.path().join("remote").join(&path)).unwrap();
        bytes.extend_from_slice(b"trailing");
        server.tamper(&path, bytes);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bytes follow"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// The default limit fetches concurrently: the request set is the same and the
/// server sees more than one request in flight at once.
#[test]
fn the_default_limit_fetches_concurrently() {
    block_on(async {
        let dir = TmpDir::new("pull-http-concurrent");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert!(
            server.peak_inflight() > 1,
            "the pull never had two fetches in flight"
        );
        let seen = server.seen_set();
        for content in content_checksums(&remote, &commit).await {
            assert!(seen.contains(&filez_path(&content.to_hex())));
        }
        assert!(seen.contains(&meta_path(&commit, "commit")));
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// A connection cut mid-object fails the pull rather than storing a truncated
/// object, and publishes nothing.
#[test]
fn a_connection_cut_mid_pull_fails_and_publishes_nothing() {
    block_on(async {
        let dir = TmpDir::new("pull-http-cut");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let contents = content_checksums(&remote, &commit).await;
        server.truncate(&filez_path(&contents[0].to_hex()));

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    // One slot keeps the failure on the object the test cut.
                    max_outstanding_fetches: Some(1),
                    n_network_retries: Some(0),
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        // The pull fails on the object whose delivery was cut, and nothing of
        // what it did receive is published under a name it does not hash to.
        assert!(err.to_string().contains(".filez"), "{err}");
        assert_nothing_published(&dest).await;
        assert!(
            !dest
                .has_object(ostrya::ObjectType::File, &contents[0])
                .await
                .unwrap()
        );
    });
}

/// A remote setting `tls-permissive` is refused rather than verified anyway,
/// which would misreport the configuration.
#[test]
fn a_tls_permissive_remote_is_refused() {
    block_on(async {
        let dir = TmpDir::new("pull-http-permissive");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            "tls-permissive=true\n",
        )
        .await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        assert!(err.to_string().contains("tls-permissive"), "{err}");
    });
}

/// `remote_fetch_summary` reports the remote's summary and its signature, an
/// absent one as `None`.
#[test]
fn remote_fetch_summary_reports_both_files() {
    block_on(async {
        let dir = TmpDir::new("pull-http-fetch-summary");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let (summary, signature) = dest.remote_fetch_summary("origin").await.unwrap();
        assert_eq!(
            summary.as_deref(),
            Some(
                std::fs::read(dir.path().join("remote/summary"))
                    .unwrap()
                    .as_slice()
            )
        );
        assert_eq!(signature, None);

        // A signature the remote publishes comes back with it.
        std::fs::write(dir.path().join("remote/summary.sig"), b"signature bytes").unwrap();
        let (_, signature) = dest.remote_fetch_summary("origin").await.unwrap();
        assert_eq!(signature.as_deref(), Some(b"signature bytes".as_slice()));
    });
}

/// A pull needs a URL: a remote the config does not describe fails unless the
/// caller supplies one.
#[test]
fn an_unconfigured_remote_needs_a_url() {
    block_on(async {
        let dir = TmpDir::new("pull-http-no-remote");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "elsewhere",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no remote 'elsewhere'"), "{err}");

        // With a URL the same pull runs, and the refs land under the remote
        // name it was asked for.
        dest.pull(
            "elsewhere",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                url: Some(server.url()),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("elsewhere:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// A symlink object and an xattr-bearing object both cross: the symlink's
/// identity is its header alone, and the xattrs are part of the header the
/// destination stores.
#[test]
fn symlink_and_xattr_bearing_objects_cross() {
    block_on(async {
        let dir = TmpDir::new("pull-http-xattrs");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        // A user xattr the commit records, so the object's header carries it.
        if rustix::fs::setxattr(
            src.join("hello.txt"),
            "user.marked",
            b"yes",
            rustix::fs::XattrFlags::empty(),
        )
        .is_err()
        {
            eprintln!("skipping: the filesystem does not support user xattrs");
            return;
        }
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let commit = commit_tree_with(
            &remote,
            dir.path(),
            "src",
            "test/main",
            None,
            FIXED_TS,
            // Neither SKIP_XATTRS nor CANONICAL_PERMISSIONS: both drop the
            // xattr set, and a bare-user destination stores whatever header an
            // object arrives with.
            CommitModifierFlags::empty(),
        )
        .await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());

        let (tree, _) = dest.read_commit(&commit.to_hex()).await.unwrap();
        let mut marked = None;
        let mut link = None;
        for entry in tree.read_dir().await.unwrap() {
            if let TreeEntry::File { name, checksum } = entry {
                match name.as_str() {
                    "hello.txt" => marked = Some(checksum),
                    "link" => link = Some(checksum),
                    _ => {}
                }
            }
        }
        let marked = dest.load_file(&marked.expect("hello.txt")).await.unwrap();
        let xattrs: Vec<(String, String)> = marked
            .xattrs
            .iter()
            .map(|(name, value)| {
                (
                    String::from_utf8_lossy(name)
                        .trim_end_matches('\0')
                        .to_owned(),
                    String::from_utf8_lossy(value).into_owned(),
                )
            })
            .collect();
        assert_eq!(xattrs, [("user.marked".to_owned(), "yes".to_owned())]);
        let link = dest.load_file(&link.expect("link")).await.unwrap();
        assert!(link.is_symlink());
    });
}

/// A bare-user-only destination stores neither ownership nor xattrs, so an
/// object whose header is not the canonical form cannot be held under its own
/// name and the pull is refused.
#[test]
fn a_bare_user_only_destination_refuses_a_non_canonical_object() {
    block_on(async {
        let dir = TmpDir::new("pull-http-non-canonical");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        // Committed under the process's own ownership, which for a bare-user-only
        // destination is not the header it stores.
        commit_tree_with(
            &remote,
            dir.path(),
            "src",
            "test/main",
            None,
            FIXED_TS,
            CommitModifierFlags::SKIP_XATTRS,
        )
        .await;
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: running as root commits the canonical ownership");
            return;
        }
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUserOnly, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err}");
        assert!(err.to_string().contains("bare-user-only"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// `BAREUSERONLY_FILES` rejects a regular-file mode with bits outside `0775`,
/// over the header the object arrives with.
#[test]
fn bareuseronly_files_rejects_a_mode_outside_0775() {
    block_on(async {
        use std::os::unix::fs::PermissionsExt;

        let dir = TmpDir::new("pull-http-mode-bits");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        std::fs::set_permissions(src.join("exec.sh"), std::fs::Permissions::from_mode(0o4755))
            .unwrap();
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        commit_tree_with(
            &remote,
            dir.path(),
            "src",
            "test/main",
            None,
            FIXED_TS,
            CommitModifierFlags::SKIP_XATTRS,
        )
        .await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    flags: PullFlags::BAREUSERONLY_FILES,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid mode"), "{err}");
        assert_nothing_published(&dest).await;

        // Without the flag an archive destination stores it.
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// The request path of one part of the single delta a served repository holds,
/// found by walking `deltas/<fanout>/<leaf>/` rather than rebuilding the name.
fn served_part_path(root: &Path, index: usize) -> String {
    let deltas = root.join("deltas");
    let fanout = std::fs::read_dir(&deltas)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let leaf = std::fs::read_dir(&fanout).unwrap().next().unwrap().unwrap();
    let dir = leaf.path().strip_prefix(root).unwrap().to_owned();
    format!("{}/{index}", dir.display())
}

/// A remote answering a part request with more than the part is gets no further
/// than the size the superblock declares for that part: the fetcher refuses the
/// oversized body and the pull publishes nothing.
#[test]
fn a_part_larger_than_the_superblock_declares_is_refused() {
    block_on(async {
        let dir = TmpDir::new("pull-http-delta-part-size");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let remote_path = dir.path().join("remote");
        let remote = Repo::create(&remote_path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let tip = commit_tree_with(
            &remote,
            dir.path(),
            "src",
            "test/main",
            None,
            FIXED_TS,
            CommitModifierFlags::SKIP_XATTRS,
        )
        .await;
        remote
            .generate_static_delta(
                None,
                &tip,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();

        // The part the superblock declares, served four times over.
        let part = served_part_path(&remote_path, 0);
        let declared = std::fs::metadata(remote_path.join(&part)).unwrap().len();
        let server = RepoServer::start(&remote_path, false).await;
        server.tamper(&part, vec![0u8; declared as usize * 4]);

        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::FetchTooLarge { limit } if limit == declared),
            "{err}"
        );
        assert_nothing_published(&dest).await;
        assert!(
            server.seen().contains(&part),
            "the part was requested: {:?}",
            server.seen()
        );
    });
}

/// `BAREUSERONLY_FILES` reaches an object a static delta delivers: the mode a
/// part's table names is checked before the object is written, so a remote
/// publishing a delta cannot hand over what a loose fetch of the same object
/// would be refused.
#[test]
fn bareuseronly_files_rejects_a_delta_delivered_mode_outside_0775() {
    block_on(async {
        use std::os::unix::fs::PermissionsExt;

        let dir = TmpDir::new("pull-http-delta-mode-bits");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        std::fs::set_permissions(src.join("exec.sh"), std::fs::Permissions::from_mode(0o4755))
            .unwrap();
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let tip = commit_tree_with(
            &remote,
            dir.path(),
            "src",
            "test/main",
            None,
            FIXED_TS,
            CommitModifierFlags::SKIP_XATTRS,
        )
        .await;
        // A from-scratch delta of the commit, which a fresh destination is what
        // the remote publishes for. The remote serves no summary, so the delta is
        // asked for by name.
        remote
            .generate_static_delta(
                None,
                &tip,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;

        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    flags: PullFlags::BAREUSERONLY_FILES,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid mode"), "{err}");
        assert_nothing_published(&dest).await;
        assert!(
            server
                .seen()
                .iter()
                .any(|path| path.ends_with("/superblock")),
            "the pull took the delta: {:?}",
            server.seen()
        );

        // Without the flag the same delta delivers the object, so the refusal is
        // the flag's and not the delta path failing to apply.
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        server.forget();
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(
            server
                .seen()
                .iter()
                .any(|path| path.ends_with("/superblock")),
            "the second pull took the delta as well: {:?}",
            server.seen()
        );
        assert_eq!(
            dest.commit_state(&tip).await.unwrap(),
            CommitState::Normal,
            "the delta delivered the whole commit"
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// A delta into each destination mode. The destination is one commit behind, so
/// the delta patches against objects it already stores: the applier reads a
/// source object in the destination's own storage form -- a deflated `.filez`
/// for an archive destination -- and writes what the part produces back in that
/// same form. Every mode lands the target commit whole and passes its own fsck.
#[test]
fn a_delta_delivers_a_commit_into_every_destination_mode() {
    block_on(async {
        for mode in [
            RepoMode::Archive,
            RepoMode::BareUser,
            RepoMode::BareUserOnly,
        ] {
            let dir = TmpDir::new(&format!("pull-http-delta-dest-{}", mode.as_mode_str()));
            let src = dir.path().join("src");
            build_tree(&src, b"hello\n");
            // A file spanning several chunks, so the edit below leaves most of
            // it to be copied out of the object the destination already holds.
            let mut bulk = incompressible(256 * 1024);
            std::fs::write(src.join("bulk.bin"), &bulk).unwrap();

            let remote_path = dir.path().join("remote");
            let remote = Repo::create(&remote_path, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let first = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;

            // The destination takes the first commit loose: the remote holds no
            // delta yet, so its superblock request is a 404.
            let server = RepoServer::start(&remote_path, false).await;
            let dest = build_dest(dir.path(), mode, &server.url(), "").await;
            dest.pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(
                dest.resolve_rev("origin:test/main", true).await.unwrap(),
                Some(first),
                "{mode:?}"
            );

            // The remote moves on by one commit -- one file edited, one added --
            // and publishes the delta that produces it from the commit the
            // destination holds.
            bulk[128 * 1024..128 * 1024 + 4].copy_from_slice(b"edit");
            std::fs::write(src.join("bulk.bin"), &bulk).unwrap();
            std::fs::write(src.join("added.txt"), b"added\n").unwrap();
            let second = commit_tree(
                &remote,
                dir.path(),
                "src",
                "test/main",
                Some(first),
                FIXED_TS + 1,
            )
            .await;
            remote
                .generate_static_delta(
                    Some(&first),
                    &second,
                    &DeltaOptions {
                        timestamp: Some(FIXED_TS),
                        ..DeltaOptions::default()
                    },
                )
                .await
                .unwrap();

            server.forget();
            dest.pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

            // The delta carried the content: the superblock was requested and no
            // content object was.
            let seen = server.seen();
            assert!(
                seen.iter().any(|path| path.ends_with("/superblock")),
                "{mode:?}: the pull took the delta: {seen:?}"
            );
            assert!(
                !seen.iter().any(|path| path.ends_with(".filez")),
                "{mode:?}: a content object was fetched loose: {seen:?}"
            );

            assert_eq!(
                dest.resolve_rev("origin:test/main", true).await.unwrap(),
                Some(second),
                "{mode:?}"
            );
            assert_eq!(
                dest.commit_state(&second).await.unwrap(),
                CommitState::Normal,
                "{mode:?}"
            );
            let report = dest.fsck(&FsckOptions::default()).await.unwrap();
            assert!(report.is_ok(), "{mode:?}: {:?}", report.errors);

            // The tree reads back with both the edited and the added file.
            let (tree, _) = dest.read_commit(&second.to_hex()).await.unwrap();
            let mut names: Vec<String> = tree
                .read_dir()
                .await
                .unwrap()
                .into_iter()
                .map(|entry| match entry {
                    TreeEntry::File { name, .. } | TreeEntry::Dir { name, .. } => name,
                })
                .collect();
            names.sort();
            assert_eq!(
                names,
                [
                    "added.txt",
                    "bulk.bin",
                    "exec.sh",
                    "hello.txt",
                    "link",
                    "subdir"
                ],
                "{mode:?}"
            );
        }
    });
}
