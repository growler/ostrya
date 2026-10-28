//! Tests of `Repo::push_over_stream` against `Repo::receive` over two
//! in-process pipes. The tests cover the negotiation, the depth of the chains,
//! the refusals of the client, and the lock of the local repository.

#![cfg(all(feature = "push", feature = "receive"))]

mod common;

use std::io;
use std::os::fd::AsFd;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use common::receive::{
    PIPE_CAP, PipeReader, PipeWriter, SECRET_B64, SERVER_SECRET_B64, ed25519_signature,
    ed25519_signatures, is_root, new_repo, pipe, policy_allowing, secret, server_signer, trust,
};
use common::{Counting, TmpDir, dependency_error, mark_partial, store_with_field2};
use futures_io::AsyncWrite;
use futures_lite::future::zip;
use ostrya::access::CollectionScope;
use ostrya::remote::{self, Compression, PushOutcome, PushProgress};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, DictBuilder, Ed25519Signer,
    Error, MutableTree, ObjectType, PruneOptions, ReceivePolicy, ReceiveReport, ReceiveVerify,
    Repo, RepoMode, RepoPushOptions, Value,
};
use ostrya_rt::block_on;

// ---------------------------------------------------------------------------
// Repositories and commits.
// ---------------------------------------------------------------------------

/// A client repository and a server repository, each in a directory of its
/// own. The constructors append `server_core` to the config of the server.
struct Pair {
    _client_dir: TmpDir,
    _server_dir: TmpDir,
    client: Repo,
    server: Repo,
}

impl Pair {
    fn new(tag: &str, client_mode: RepoMode, server_mode: RepoMode, server_core: &str) -> Pair {
        Pair::with_client_core(tag, client_mode, "", server_mode, server_core)
    }

    fn with_client_core(
        tag: &str,
        client_mode: RepoMode,
        client_core: &str,
        server_mode: RepoMode,
        server_core: &str,
    ) -> Pair {
        let client_dir = TmpDir::new(&format!("push-repo-{tag}-client"));
        let server_dir = TmpDir::new(&format!("push-repo-{tag}-server"));
        let client = new_repo(&client_dir, client_mode, client_core);
        let server = new_repo(&server_dir, server_mode, server_core);
        Pair {
            _client_dir: client_dir,
            _server_dir: server_dir,
            client,
            server,
        }
    }
}

/// Commits a tree onto `branch` of `repo`, with `parent` and `metadata`. The
/// tree holds a file `file` with `content`, a symlink `link` to it, and a
/// directory `sub` whose file is the same in every commit.
fn commit(
    repo: &Repo,
    branch: &str,
    parent: Option<Checksum>,
    content: &str,
    metadata: Option<Value>,
) -> Checksum {
    commit_related(repo, branch, parent, content, metadata, &[])
}

/// Commits a tree as [`commit`] does, with the dependencies `related` in
/// field 2.
fn commit_related(
    repo: &Repo,
    branch: &str,
    parent: Option<Checksum>,
    content: &str,
    metadata: Option<Value>,
    related: &[(&str, Checksum)],
) -> Checksum {
    let tree = repo
        .path()
        .parent()
        .unwrap()
        .join(format!("tree-{branch}-{content}"));
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("file"), content).unwrap();
    std::fs::write(tree.join("sub/nested"), "the same in each commit\n").unwrap();
    let _ = std::fs::remove_file(tree.join("link"));
    std::os::unix::fs::symlink("file", tree.join("link")).unwrap();
    block_on(async {
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(&tree).unwrap();
        let mut modifier = CommitModifier::new(
            CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
        );
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, Some(&mut modifier))
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let checksum = txn
            .write_commit(
                CommitOptions {
                    parent,
                    subject: Some(content.to_owned()),
                    timestamp: Some(1_700_000_000),
                    metadata,
                    related: related
                        .iter()
                        .map(|(name, dependency)| ((*name).to_owned(), *dependency))
                        .collect(),
                    ..CommitOptions::default()
                },
                &root,
            )
            .await
            .unwrap();
        txn.set_ref(branch, Some(&checksum));
        txn.commit().await.unwrap();
        checksum
    })
}

/// A branch of four commits on `branch`, oldest first.
fn chain(repo: &Repo, branch: &str) -> [Checksum; 4] {
    let c1 = commit(repo, branch, None, "c1", None);
    let c2 = commit(repo, branch, Some(c1), "c2", None);
    let c3 = commit(repo, branch, Some(c2), "c3", None);
    let c4 = commit(repo, branch, Some(c3), "c4", None);
    [c1, c2, c3, c4]
}

fn has_commit(repo: &Repo, checksum: &Checksum) -> bool {
    block_on(repo.has_object(ObjectType::Commit, checksum)).unwrap()
}

fn tip(repo: &Repo, name: &str) -> Option<Checksum> {
    block_on(repo.resolve_rev(name, true)).unwrap()
}

fn refspecs(specs: &[&str]) -> Vec<String> {
    specs.iter().map(|s| (*s).to_owned()).collect()
}

fn opts(specs: &[&str]) -> RepoPushOptions {
    RepoPushOptions {
        refspecs: refspecs(specs),
        ..RepoPushOptions::default()
    }
}

// ---------------------------------------------------------------------------
// The pushes.
// ---------------------------------------------------------------------------

type Pushed = (ostrya::Result<ReceiveReport>, ostrya::Result<PushOutcome>);

/// One push from the client into the server under the default policy.
fn push(pair: &Pair, opts: RepoPushOptions) -> Pushed {
    push_through(pair, opts, |_| {})
}

/// One push whose client output runs through a [`Hook`] that calls `hook`
/// with the kind of each frame before the frame reaches the server.
fn push_through<F>(pair: &Pair, opts: RepoPushOptions, hook: F) -> Pushed
where
    F: FnMut(u8) + Send + 'static,
{
    push_under(pair, opts, &policy_allowing(&["w:**"]), hook)
}

/// [`push_through`] with the server under `policy`.
fn push_under<F>(pair: &Pair, opts: RepoPushOptions, policy: &ReceivePolicy, hook: F) -> Pushed
where
    F: FnMut(u8) + Send + 'static,
{
    let (client_out, server_in) = pipe(PIPE_CAP);
    let (server_out, client_in) = pipe(PIPE_CAP);
    block_on(zip(
        pair.server.receive(server_in, server_out, policy),
        pair.client
            .push_over_stream(client_in, Hook::new(client_out, Box::new(hook)), opts),
    ))
}

/// The error of a push that the client refuses before it writes a byte, and
/// the number of bytes it wrote.
fn refused(repo: &Repo, opts: RepoPushOptions) -> (Error, u64) {
    let written = Arc::new(AtomicU64::new(0));
    let output = Counting {
        inner: futures_lite::io::sink(),
        written: Arc::clone(&written),
    };
    let result = block_on(repo.push_over_stream(futures_lite::io::empty(), output, opts));
    let error = result.expect_err("the push is refused");
    (error, written.load(Ordering::Relaxed))
}

/// The kind byte of a `Have` frame.
const HAVE_FRAME: u8 = 3;

/// The kind byte of a `Commit` frame.
const COMMIT_FRAME: u8 = 8;

/// The kind byte of an `Abort` frame.
const ABORT_FRAME: u8 = 11;

/// The kind byte of an `ObjectHeader` frame, after which object chunks come.
const OBJECT_HEADER_FRAME: u8 = 5;

/// Where the parse of the client stream is.
enum Parse {
    Frames,
    /// Inside an object, with this many bytes of the current chunk left.
    Chunks(usize),
}

/// A writer between the client and the server. It parses the frames and the
/// object chunks of the client stream. It calls its hook with the kind of
/// each frame before it passes the frame on, and it passes every byte on
/// unchanged.
struct Hook {
    inner: PipeWriter,
    hook: Box<dyn FnMut(u8) + Send>,
    parse: Parse,
    /// Bytes that are not parsed yet.
    partial: Vec<u8>,
    /// Parsed bytes to pass on.
    forward: Vec<u8>,
}

impl Hook {
    fn new(inner: PipeWriter, hook: Box<dyn FnMut(u8) + Send>) -> Hook {
        Hook {
            inner,
            hook,
            parse: Parse::Frames,
            partial: Vec::new(),
            forward: Vec::new(),
        }
    }

    fn parse(&mut self) {
        loop {
            match self.parse {
                Parse::Frames => {
                    if self.partial.len() < 5 {
                        return;
                    }
                    let len = u32::from_be_bytes(self.partial[..4].try_into().unwrap()) as usize;
                    if self.partial.len() < 4 + len {
                        return;
                    }
                    let kind = self.partial[4];
                    (self.hook)(kind);
                    self.forward.extend(self.partial.drain(..4 + len));
                    if kind == OBJECT_HEADER_FRAME {
                        self.parse = Parse::Chunks(0);
                    }
                }
                Parse::Chunks(0) => {
                    if self.partial.len() < 4 {
                        return;
                    }
                    let len = u32::from_be_bytes(self.partial[..4].try_into().unwrap());
                    self.forward.extend(self.partial.drain(..4));
                    self.parse = match len {
                        0 | remote::proto::ABANDON => Parse::Frames,
                        len => Parse::Chunks(len as usize),
                    };
                }
                Parse::Chunks(left) => {
                    let n = left.min(self.partial.len());
                    if n == 0 {
                        return;
                    }
                    self.forward.extend(self.partial.drain(..n));
                    self.parse = Parse::Chunks(left - n);
                }
            }
        }
    }

    fn poll_forward(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.forward.is_empty() {
            let n = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, &self.forward))?;
            self.forward.drain(..n);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Hook {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        std::task::ready!(me.poll_forward(cx))?;
        me.partial.extend_from_slice(buf);
        me.parse();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        std::task::ready!(me.poll_forward(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        std::task::ready!(me.poll_forward(cx))?;
        Pin::new(&mut me.inner).poll_close(cx)
    }
}

/// Runs `work` to its end on a thread of its own, with an executor of its
/// own, while the push waits in a hook.
fn on_own_thread<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|s| s.spawn(work).join().unwrap())
}

/// A hook that records the kind of each frame into the list it gives.
fn frame_kinds() -> (
    Arc<std::sync::Mutex<Vec<u8>>>,
    impl FnMut(u8) + Send + 'static,
) {
    let kinds = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = Arc::clone(&kinds);
    (kinds, move |kind| record.lock().unwrap().push(kind))
}

fn assert_aborted(report: &ostrya::Result<ReceiveReport>) {
    match report {
        Err(Error::Remote(remote::Error::Aborted)) => {}
        other => panic!("expected Aborted on the server, got {other:?}"),
    }
}

fn assert_invalid_input(error: &Error, needle: &str) {
    match error {
        Error::Remote(remote::Error::InvalidInput(msg)) => {
            assert!(msg.contains(needle), "{msg:?} lacks {needle:?}")
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

#[test]
fn a_second_push_of_the_same_commit_sends_no_object() {
    let pair = Pair::new("repeat", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    let outcome = outcome.unwrap();
    assert!(outcome.stats.objects_sent > 0);
    assert_eq!(tip(&pair.server, "main"), Some(c1));

    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    let outcome = outcome.unwrap();
    assert_eq!(outcome.stats.objects_needed, 0);
    assert_eq!(outcome.stats.objects_sent, 0);
    assert_eq!(outcome.refs.len(), 1);
    assert_eq!(outcome.refs[0].old, Some(c1));
    assert_eq!(outcome.refs[0].new, Some(c1));
    assert_eq!(tip(&pair.server, "main"), Some(c1));
}

#[test]
fn a_branch_ahead_of_the_server_tip_is_a_fast_forward() {
    let pair = Pair::new("ahead", RepoMode::Archive, RepoMode::BareUser, "");
    let [c1, c2, c3, c4] = chain(&pair.client, "main");
    let (report, outcome) = push(&pair, opts(&[&format!("{c1}:main")]));
    report.unwrap();
    outcome.unwrap();
    assert_eq!(tip(&pair.server, "main"), Some(c1));

    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    let outcome = outcome.unwrap();
    assert_eq!(outcome.refs[0].old, Some(c1));
    assert_eq!(outcome.refs[0].new, Some(c4));
    assert_eq!(tip(&pair.server, "main"), Some(c4));
    assert!(has_commit(&pair.server, &c2));
    assert!(has_commit(&pair.server, &c3));
}

#[test]
fn a_push_onto_a_moved_ref_fails_with_ref_mismatch() {
    let pair = Pair::new("moved", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let side = commit(&pair.client, "side", None, "side", None);
    let (report, outcome) = push(&pair, opts(&["main", "side"]));
    report.unwrap();
    outcome.unwrap();
    let c2 = commit(&pair.client, "main", Some(c1), "c2", None);

    // Another writer moves the ref of the server after `HelloReply` and
    // before `Commit` reaches the server.
    let server = pair.server.clone();
    let (report, outcome) = push_through(&pair, opts(&["main"]), move |kind| {
        if kind == COMMIT_FRAME {
            let server = server.clone();
            on_own_thread(move || block_on(server.set_ref_immediate("main", Some(&side)))).unwrap();
        }
    });
    assert!(report.is_err());
    match outcome {
        Err(Error::Remote(remote::Error::RefMismatch { name, current, .. })) => {
            assert_eq!(name, "main");
            assert_eq!(current, Some(side));
        }
        other => panic!("expected RefMismatch, got {other:?}"),
    }
    assert_eq!(tip(&pair.server, "main"), Some(side));
    assert_ne!(tip(&pair.server, "main"), Some(c2));
}

#[test]
fn depth_zero_sends_the_source_commit_alone() {
    let pair = Pair::new("depth-zero", RepoMode::Archive, RepoMode::Archive, "");
    let [c1, c2, c3, c4] = chain(&pair.client, "main");
    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            depth: Some(0),
            ..opts(&["main:zero"])
        },
    );
    report.unwrap();
    outcome.unwrap();
    assert_eq!(tip(&pair.server, "zero"), Some(c4));
    assert!(has_commit(&pair.server, &c4));
    for lacked in [c3, c2, c1] {
        assert!(!has_commit(&pair.server, &lacked), "{lacked}");
    }
}

#[test]
fn depth_minus_one_sends_the_whole_chain() {
    let pair = Pair::new("depth-all", RepoMode::Archive, RepoMode::Archive, "");
    let commits = chain(&pair.client, "main");
    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            depth: Some(-1),
            ..opts(&["main"])
        },
    );
    report.unwrap();
    outcome.unwrap();
    assert_eq!(tip(&pair.server, "main"), Some(commits[3]));
    for held in commits {
        assert!(has_commit(&pair.server, &held), "{held}");
    }
}

#[test]
fn a_depth_below_minus_one_is_refused_before_any_byte() {
    let dir = TmpDir::new("push-repo-depth-refused");
    let repo = new_repo(&dir, RepoMode::Archive, "");
    commit(&repo, "main", None, "c1", None);
    let (error, written) = refused(
        &repo,
        RepoPushOptions {
            depth: Some(-2),
            ..opts(&["main"])
        },
    );
    assert_invalid_input(&error, "depth -2");
    assert_eq!(written, 0);
}

#[test]
fn a_partial_source_commit_is_refused_before_any_byte() {
    let dir = TmpDir::new("push-repo-partial");
    let repo = new_repo(&dir, RepoMode::Archive, "");
    let c1 = commit(&repo, "main", None, "c1", None);
    std::fs::write(repo.path().join(format!("state/{c1}.commitpartial")), b"").unwrap();
    let (error, written) = refused(&repo, opts(&["main"]));
    assert_invalid_input(&error, "partial");
    assert_eq!(written, 0);
}

#[test]
fn a_ref_binding_that_does_not_hold_the_destination_is_refused_before_any_byte() {
    let dir = TmpDir::new("push-repo-ref-binding");
    let repo = new_repo(&dir, RepoMode::Archive, "");
    let mut metadata = DictBuilder::new();
    metadata.insert_strv("ostree.ref-binding", &["a".to_owned()]);
    commit(&repo, "a", None, "bound", Some(metadata.build()));
    let (error, written) = refused(&repo, opts(&["a:b"]));
    match &error {
        Error::Remote(remote::Error::BindingMismatch(msg)) => {
            assert!(msg.contains("[\"a\"]") && msg.contains("'b'"), "{msg}");
        }
        other => panic!("expected BindingMismatch, got {other:?}"),
    }
    assert_eq!(written, 0);
}

#[test]
fn an_empty_ref_binding_list_passes() {
    let pair = Pair::new("empty-binding", RepoMode::Archive, RepoMode::Archive, "");
    let mut metadata = DictBuilder::new();
    metadata.insert_strv("ostree.ref-binding", &[]);
    let c1 = commit(&pair.client, "a", None, "unbound", Some(metadata.build()));
    let (report, outcome) = push(&pair, opts(&["a:b"]));
    report.unwrap();
    outcome.unwrap();
    assert_eq!(tip(&pair.server, "b"), Some(c1));
}

/// Returns the metadata of a commit bound to the collection `id` and to the
/// refs `refs`. An empty `refs` gives no ref binding.
fn bound(id: Option<&str>, refs: &[&str]) -> Option<Value> {
    let mut metadata = DictBuilder::new();
    if !refs.is_empty() {
        let refs: Vec<String> = refs.iter().map(|r| (*r).to_owned()).collect();
        metadata.insert_strv("ostree.ref-binding", &refs);
    }
    if let Some(id) = id {
        metadata.insert_str("ostree.collection-binding", id);
    }
    Some(metadata.build())
}

/// The policy of a client group with `collection=*` and the allow items
/// `allow`.
fn collections(allow: &[&str]) -> ReceivePolicy {
    ReceivePolicy {
        scope: CollectionScope::AllOther,
        ..policy_allowing(allow)
    }
}

fn ref_file(repo: &Repo, relpath: &str) -> Option<String> {
    std::fs::read_to_string(repo.path().join(relpath)).ok()
}

fn assert_binding_mismatch<T: std::fmt::Debug>(result: &ostrya::Result<T>, needle: &str) {
    match result {
        Err(Error::Remote(remote::Error::BindingMismatch(msg))) => {
            assert!(msg.contains(needle), "{msg:?} lacks {needle:?}")
        }
        other => panic!("expected BindingMismatch, got {other:?}"),
    }
}

/// A commit bound to a collection that is not the collection id of the
/// server goes to `refs/mirrors/ID/` of the server. The server has no
/// collection id here.
#[test]
fn a_commit_bound_to_another_collection_goes_to_the_mirror_refs() {
    let pair = Pair::new("mirror", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(
        &pair.client,
        "main",
        None,
        "c1",
        bound(Some("org.example.Os"), &[]),
    );
    let (report, outcome) = push_under(&pair, opts(&["main"]), &collections(&["w:**"]), |_| {});
    let report = report.unwrap();
    assert_eq!(report.collection.as_deref(), Some("org.example.Os"));
    outcome.unwrap();
    assert_eq!(
        ref_file(&pair.server, "refs/mirrors/org.example.Os/main"),
        Some(format!("{c1}\n"))
    );
    assert_eq!(tip(&pair.server, "main"), None);
}

/// A commit bound to the collection id of the server goes to the local refs.
/// A commit with no binding goes there with it.
#[test]
fn a_commit_bound_to_the_server_collection_goes_to_the_local_refs() {
    let pair = Pair::new(
        "own",
        RepoMode::Archive,
        RepoMode::Archive,
        "collection-id=org.example.Os\n",
    );
    let c1 = commit(
        &pair.client,
        "main",
        None,
        "c1",
        bound(Some("org.example.Os"), &[]),
    );
    let c2 = commit(&pair.client, "other", None, "c2", None);
    let (report, outcome) = push(&pair, opts(&["main", "other"]));
    assert_eq!(report.unwrap().collection, None);
    let outcome = outcome.unwrap();
    assert_eq!(outcome.refs.len(), 2);
    assert_eq!(tip(&pair.server, "main"), Some(c1));
    assert_eq!(tip(&pair.server, "other"), Some(c2));
    assert!(
        !pair
            .server
            .path()
            .join("refs/mirrors/org.example.Os")
            .exists()
    );
}

/// Two different bindings, a `collection` that differs from the binding, a
/// `collection` that fails the collection-id rule or is longer than 255
/// bytes, and a binding that fails the collection-id rule are refused before
/// the push writes a byte.
#[test]
fn disagreeing_collections_are_refused_before_any_byte() {
    let dir = TmpDir::new("push-repo-mixed-bindings");
    let repo = new_repo(&dir, RepoMode::Archive, "");
    commit(&repo, "os-a", None, "a", bound(Some("org.example.A"), &[]));
    commit(&repo, "os-b", None, "b", bound(Some("org.example.B"), &[]));
    let (error, written) = refused(&repo, opts(&["os-a", "os-b"]));
    assert_binding_mismatch::<()>(&Err(error), "'org.example.A'");
    assert_eq!(written, 0);
    let (error, written) = refused(
        &repo,
        RepoPushOptions {
            collection: Some("org.example.B".into()),
            ..opts(&["os-a"])
        },
    );
    assert_binding_mismatch::<()>(&Err(error), "not 'org.example.B'");
    assert_eq!(written, 0);
    let (error, written) = refused(
        &repo,
        RepoPushOptions {
            collection: Some("no-dot".into()),
            ..opts(&["os-a"])
        },
    );
    assert_invalid_input(&error, "invalid collection id 'no-dot'");
    assert_eq!(written, 0);
    let (error, written) = refused(
        &repo,
        RepoPushOptions {
            collection: Some(format!("org.{}", "a".repeat(252))),
            ..opts(&["os-a"])
        },
    );
    assert_invalid_input(&error, "256 bytes");
    assert_eq!(written, 0);
    commit(&repo, "os-bad", None, "bad", bound(Some("no-dot"), &[]));
    let (error, written) = refused(&repo, opts(&["os-bad"]));
    assert_invalid_input(&error, "'no-dot'");
    assert_eq!(written, 0);
}

/// A commit with no binding goes to the local refs alone. If `Hello` names a
/// collection that is not the collection id of the server, the push sends
/// `Abort` after `HelloReply` and sends no `Have`. This holds for a
/// requested collection and for the binding of another source commit.
#[test]
fn an_unbound_commit_is_refused_in_a_collection_before_any_upload() {
    let pair = Pair::new(
        "unbound-collection",
        RepoMode::Archive,
        RepoMode::Archive,
        "collection-id=org.example.Server\n",
    );
    let c1 = commit(&pair.client, "main", None, "c1", None);
    commit(
        &pair.client,
        "os",
        None,
        "os",
        bound(Some("org.example.Os"), &[]),
    );
    for opts in [
        RepoPushOptions {
            collection: Some("org.example.Os".into()),
            ..opts(&["main"])
        },
        opts(&["main", "os"]),
    ] {
        let progress = PushProgress::new();
        let (kinds, hook) = frame_kinds();
        let (report, outcome) = push_under(
            &pair,
            RepoPushOptions {
                progress: Some(progress.clone()),
                ..opts
            },
            &collections(&["w:**"]),
            hook,
        );
        assert_aborted(&report);
        assert_binding_mismatch(&outcome, "has no collection binding");
        let kinds = kinds.lock().unwrap().clone();
        assert!(!kinds.contains(&HAVE_FRAME), "{kinds:?}");
        assert_eq!(kinds.last(), Some(&ABORT_FRAME), "{kinds:?}");
        assert_eq!(progress.snapshot().objects_total, 0, "no Have was sent");
        assert!(!has_commit(&pair.server, &c1));
    }
    assert!(
        !pair
            .server
            .path()
            .join("refs/mirrors")
            .join("org.example.Os")
            .exists()
    );
}

/// A tag is a ref update that expects no ref at the source commit. A tag
/// that exists is `ref-mismatch`, also with `force`. The push sends `Abort`
/// after `HelloReply`, and sends no `Have` and no object.
#[test]
fn a_tag_is_created_once_at_the_source_commit() {
    let pair = Pair::new("tag", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(
        &pair.client,
        "main",
        None,
        "c1",
        bound(None, &["main", "v1"]),
    );
    let tags = || RepoPushOptions {
        tags: vec!["v1".into()],
        ..opts(&["main"])
    };
    let policy = policy_allowing(&["w:main", "t:v1"]);
    let (report, outcome) = push_under(&pair, tags(), &policy, |_| {});
    report.unwrap();
    let outcome = outcome.unwrap();
    let names: Vec<_> = outcome
        .refs
        .iter()
        .map(|r| (r.name.as_str(), r.old, r.new))
        .collect();
    assert_eq!(
        names,
        vec![("main", None, Some(c1)), ("v1", None, Some(c1))]
    );
    assert_eq!(tip(&pair.server, "v1"), Some(c1));

    let c2 = commit(
        &pair.client,
        "main",
        Some(c1),
        "c2",
        bound(None, &["main", "v1"]),
    );
    for force in [false, true] {
        let progress = PushProgress::new();
        let (kinds, hook) = frame_kinds();
        let (report, outcome) = push_under(
            &pair,
            RepoPushOptions {
                force,
                progress: Some(progress.clone()),
                ..tags()
            },
            &policy,
            hook,
        );
        assert_aborted(&report);
        match outcome {
            Err(Error::Remote(remote::Error::RefMismatch { name, current, .. })) => {
                assert_eq!(name, "v1");
                assert_eq!(current, Some(c1));
            }
            other => panic!("expected RefMismatch, got {other:?}"),
        }
        let kinds = kinds.lock().unwrap().clone();
        assert!(!kinds.contains(&HAVE_FRAME), "{kinds:?}");
        assert_eq!(kinds.last(), Some(&ABORT_FRAME), "{kinds:?}");
        let snapshot = progress.snapshot();
        assert_eq!(snapshot.objects_total, 0, "no Have was sent");
        assert_eq!(snapshot.payload_bytes, 0, "no object was sent");
        assert!(!has_commit(&pair.server, &c2));
        assert_eq!(tip(&pair.server, "main"), Some(c1));
    }
}

/// A tag needs one source commit whose ref binding holds the tag. A tag name
/// that a push cannot create is refused. Each refusal comes before the push
/// writes a byte.
#[test]
fn a_tag_the_push_cannot_create_is_refused_before_any_byte() {
    let dir = TmpDir::new("push-repo-bad-tag");
    let repo = new_repo(&dir, RepoMode::Archive, "");
    let c1 = commit(&repo, "main", None, "c1", bound(None, &["main", "v1"]));
    commit(&repo, "other", None, "c2", bound(None, &["other", "v1"]));
    commit(&repo, "plain", None, "c3", None);
    let with = |specs: &[&str], tags: &[&str]| RepoPushOptions {
        tags: tags.iter().map(|t| (*t).to_owned()).collect(),
        ..opts(specs)
    };

    let (error, written) = refused(&repo, with(&["main"], &["v2"]));
    assert_binding_mismatch::<()>(&Err(error), "the tag 'v2'");
    assert_eq!(written, 0);
    let (error, written) = refused(&repo, with(&["plain"], &["v1"]));
    assert_binding_mismatch::<()>(&Err(error), "the tag 'v1'");
    assert_eq!(written, 0);
    let (error, written) = refused(&repo, with(&["main", "other"], &["v1"]));
    assert_invalid_input(&error, "one source commit");
    assert_eq!(written, 0);
    let (error, written) = refused(&repo, with(&[":gone"], &["v1"]));
    assert_invalid_input(&error, "not a delete");
    assert_eq!(written, 0);
    let (error, written) = refused(&repo, with(&["main"], &["v1", "v1"]));
    assert_invalid_input(&error, "named twice");
    assert_eq!(written, 0);
    let (error, written) = refused(&repo, with(&["main"], &["main"]));
    assert_invalid_input(&error, "destination");
    assert_eq!(written, 0);
    let hex = c1.to_string();
    for name in ["origin:v1", "a b", hex.as_str()] {
        let (error, written) = refused(&repo, with(&["main"], &[name]));
        match error {
            Error::InvalidRefspec(got) => assert_eq!(got, name),
            other => panic!("{name}: expected InvalidRefspec, got {other:?}"),
        }
        assert_eq!(written, 0);
    }
}

#[test]
fn a_dirtree_the_local_repository_lacks_ends_the_push_before_any_upload() {
    let pair = Pair::new("damaged", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let (root, _) = block_on(pair.client.load_commit(&c1)).unwrap();
    let path = ostrya::loose_path(&root.root_dirtree, ObjectType::DirTree, RepoMode::Archive);
    std::fs::remove_file(pair.client.path().join("objects").join(path)).unwrap();
    let progress = PushProgress::new();
    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            progress: Some(progress.clone()),
            ..opts(&["main"])
        },
    );
    assert_aborted(&report);
    match outcome {
        Err(Error::ObjectNotFound { checksum, ty }) => {
            assert_eq!(checksum, root.root_dirtree);
            assert_eq!(ty, ObjectType::DirTree);
        }
        other => panic!("expected ObjectNotFound, got {other:?}"),
    }
    assert_eq!(progress.snapshot().payload_bytes, 0);
    assert!(!has_commit(&pair.server, &c1));
    assert_eq!(tip(&pair.server, "main"), None);
}

#[test]
fn a_root_dirmeta_the_local_repository_lacks_ends_the_push_before_any_upload() {
    let pair = Pair::new("no-dirmeta", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let (root, _) = block_on(pair.client.load_commit(&c1)).unwrap();
    let path = ostrya::loose_path(&root.root_dirmeta, ObjectType::DirMeta, RepoMode::Archive);
    std::fs::remove_file(pair.client.path().join("objects").join(path)).unwrap();
    let progress = PushProgress::new();
    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            progress: Some(progress.clone()),
            ..opts(&["main"])
        },
    );
    assert_aborted(&report);
    match outcome {
        Err(Error::ObjectNotFound { checksum, ty }) => {
            assert_eq!(checksum, root.root_dirmeta);
            assert_eq!(ty, ObjectType::DirMeta);
        }
        other => panic!("expected ObjectNotFound, got {other:?}"),
    }
    assert_eq!(progress.snapshot().payload_bytes, 0);
    assert!(!has_commit(&pair.server, &c1));
    assert_eq!(tip(&pair.server, "main"), None);
}

#[test]
fn deleting_a_present_ref_is_delete_denied_by_default() {
    let pair = Pair::new("delete", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();

    let progress = PushProgress::new();
    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            progress: Some(progress.clone()),
            ..opts(&[":main"])
        },
    );
    assert!(report.is_err());
    match outcome {
        Err(Error::Remote(remote::Error::DeleteDenied(_))) => {}
        other => panic!("expected DeleteDenied, got {other:?}"),
    }
    // A push of deletes alone offers no object.
    assert_eq!(progress.snapshot().objects_total, 0);
    assert_eq!(tip(&pair.server, "main"), Some(c1));
}

/// With `keep-detached-related=false` in the config of the server, the
/// session drops `ostrya.related` from the incoming dict and stores each other
/// property. The client sends the key: the server reads its own switch.
#[test]
fn the_switch_of_the_server_drops_the_related_key() {
    let pair = Pair::new(
        "keep-related",
        RepoMode::Archive,
        RepoMode::Archive,
        "\n[ex-ostrya]\nkeep-detached-related=false\n",
    );
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let c2 = commit(&pair.client, "main", Some(c1), "c2", None);
    let mut builder = DictBuilder::new();
    builder.insert_str("xa.keep", "kept");
    let detached = builder.build();
    block_on(async {
        pair.client
            .write_commit_detached_metadata(&c2, Some(&detached))
            .await
            .unwrap();
        pair.client
            .add_detached_related(&c2, "layer/base", &c1)
            .await
            .unwrap();
    });
    let held = block_on(pair.client.read_commit_detached_metadata(&c2))
        .unwrap()
        .unwrap();
    assert!(held.dict_get("ostrya.related").is_some());

    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();

    assert_eq!(
        block_on(pair.server.read_commit_detached_metadata(&c2)).unwrap(),
        Some(detached)
    );
}

#[test]
fn deflate_objects_of_an_archive_source_equal_the_stored_filez() {
    // The server deflates a `raw` object at level 1, and the client stored
    // its objects at level 6. The `.filez` bytes of the server equal those
    // of the client only if the push sends the stored bytes.
    let pair = Pair::new(
        "filez",
        RepoMode::Archive,
        RepoMode::Archive,
        "\n[archive]\nzlib-level=1\n",
    );
    let tree = pair.client.path().parent().unwrap().join("tree-main-c1");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("text"), text(200 * 1024)).unwrap();
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            compression: Compression::Deflate { level: 6 },
            ..opts(&["main"])
        },
    );
    report.unwrap();
    outcome.unwrap();
    let names = block_on(pair.client.traverse_commit(&c1, 0)).unwrap();
    let mut files = 0;
    for name in names.iter().filter(|n| n.ty == ObjectType::File) {
        let path = ostrya::loose_path(&name.checksum, ObjectType::File, RepoMode::Archive);
        let sent = std::fs::read(pair.client.path().join("objects").join(&path)).unwrap();
        let stored = std::fs::read(pair.server.path().join("objects").join(&path)).unwrap();
        assert_eq!(sent, stored, "{}", name.checksum);
        files += 1;
    }
    assert_eq!(files, 4);
}

/// Returns about `len` bytes of text with words in an order that does not
/// repeat soon. Deflate levels 1 and 6 give different bytes for this text.
fn text(len: usize) -> String {
    const WORDS: [&str; 16] = [
        "tree", "commit", "object", "branch", "remote", "delta", "summary", "mode", "file", "link",
        "meta", "push", "pull", "ref", "root", "chain",
    ];
    let mut state: u32 = 0x1234_5678;
    let mut out = String::with_capacity(len + 16);
    while out.len() < len {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        out.push_str(WORDS[(state >> 16) as usize % WORDS.len()]);
        out.push(if state.is_multiple_of(7) { '\n' } else { ' ' });
    }
    out
}

#[test]
fn a_local_prune_waits_for_an_open_push() {
    let pair = Pair::with_client_core(
        "prune",
        RepoMode::Archive,
        "lock-timeout-secs=1\n",
        RepoMode::Archive,
        "",
    );
    commit(&pair.client, "main", None, "c1", None);
    let prune = PruneOptions {
        refs_only: true,
        ..PruneOptions::default()
    };

    let client = pair.client.clone();
    let during = Arc::new(std::sync::Mutex::new(None));
    let seen = Arc::clone(&during);
    let prune_during = prune.clone();
    let (report, outcome) = push_through(&pair, opts(&["main"]), move |kind| {
        if kind == COMMIT_FRAME {
            let client = client.clone();
            let prune = prune_during.clone();
            let result = on_own_thread(move || block_on(client.prune(&prune)));
            *seen.lock().unwrap() = Some(result);
        }
    });
    report.unwrap();
    outcome.unwrap();
    match during.lock().unwrap().take() {
        Some(Err(Error::LockTimeout { secs: 1 })) => {}
        other => panic!("expected LockTimeout, got {other:?}"),
    }
    block_on(pair.client.prune(&prune)).unwrap();
}

#[test]
fn a_history_commit_the_server_holds_offers_no_tree() {
    let pair = Pair::new("commits-first", RepoMode::Archive, RepoMode::Archive, "");
    let [c1, c2, c3, c4] = chain(&pair.client, "main");
    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            depth: Some(-1),
            ..opts(&[&format!("{c3}:main")])
        },
    );
    report.unwrap();
    outcome.unwrap();
    for held in [c1, c2, c3] {
        assert!(has_commit(&pair.server, &held), "{held}");
    }

    let progress = PushProgress::new();
    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            depth: Some(-1),
            progress: Some(progress.clone()),
            ..opts(&["main"])
        },
    );
    report.unwrap();
    let outcome = outcome.unwrap();
    assert_eq!(tip(&pair.server, "main"), Some(c4));
    // The offer holds the four commits and the tree of the new value alone.
    let tree = block_on(pair.client.traverse_commit(&c4, 0)).unwrap().len() as u64 - 1;
    assert_eq!(outcome.stats.objects_total, 4 + tree);
    // The session counts into the handle of the options.
    assert_eq!(
        progress.snapshot().objects_total,
        outcome.stats.objects_total
    );
}

#[test]
fn with_no_depth_the_chain_is_cut_at_the_server_tip() {
    let pair = Pair::new("cut", RepoMode::Archive, RepoMode::Archive, "");
    let [c1, c2, c3, c4] = chain(&pair.client, "main");
    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            depth: Some(0),
            ..opts(&[&format!("{c2}:main")])
        },
    );
    report.unwrap();
    outcome.unwrap();
    assert!(!has_commit(&pair.server, &c1));

    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();
    assert_eq!(tip(&pair.server, "main"), Some(c4));
    assert!(has_commit(&pair.server, &c3));
    assert!(!has_commit(&pair.server, &c1));
}

#[test]
fn with_no_depth_an_absent_destination_gets_the_source_commit_alone() {
    let pair = Pair::new("cut-absent", RepoMode::Archive, RepoMode::Archive, "");
    let [c1, c2, c3, c4] = chain(&pair.client, "main");
    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();
    assert_eq!(tip(&pair.server, "main"), Some(c4));
    for lacked in [c3, c2, c1] {
        assert!(!has_commit(&pair.server, &lacked), "{lacked}");
    }
}

#[test]
fn a_server_tip_the_local_repository_marks_partial_is_a_fast_forward() {
    let pair = Pair::new("partial-tip", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();
    // The local repository marks the server tip partial, as after a pull of
    // its commit alone, and builds on it.
    mark_partial(&pair.client, &c1);
    let c2 = commit(&pair.client, "main", Some(c1), "c2", None);
    let c3 = commit(&pair.client, "main", Some(c2), "c3", None);

    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    let outcome = outcome.unwrap();
    assert_eq!(outcome.refs[0].old, Some(c1));
    assert_eq!(outcome.refs[0].new, Some(c3));
    assert_eq!(tip(&pair.server, "main"), Some(c3));
    assert!(has_commit(&pair.server, &c2));
}

#[test]
fn a_partial_commit_before_the_server_tip_leaves_the_source_commit_alone() {
    let pair = Pair::new("partial-between", RepoMode::Archive, RepoMode::Archive, "");
    let [c1, c2, c3, c4] = chain(&pair.client, "main");
    let (report, outcome) = push(&pair, opts(&[&format!("{c1}:main")]));
    report.unwrap();
    outcome.unwrap();
    mark_partial(&pair.client, &c2);

    let progress = PushProgress::new();
    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            progress: Some(progress.clone()),
            ..opts(&["main"])
        },
    );
    assert!(report.is_err());
    match outcome {
        Err(Error::Remote(remote::Error::NonFastForward(_))) => {}
        other => panic!("expected NonFastForward, got {other:?}"),
    }
    // The offer holds the source commit and its tree alone.
    let tree = block_on(pair.client.traverse_commit(&c4, 0)).unwrap().len() as u64 - 1;
    assert_eq!(progress.snapshot().objects_total, 1 + tree);
    assert_eq!(tip(&pair.server, "main"), Some(c1));
    for lacked in [c3, c2] {
        assert!(!has_commit(&pair.server, &lacked), "{lacked}");
    }
}

#[test]
fn with_a_depth_a_partial_history_commit_ends_the_chain_before_it() {
    let pair = Pair::new("partial-depth", RepoMode::Archive, RepoMode::Archive, "");
    let [c1, c2, c3, c4] = chain(&pair.client, "main");
    let (report, outcome) = push(&pair, opts(&[&format!("{c1}:main")]));
    report.unwrap();
    outcome.unwrap();
    mark_partial(&pair.client, &c2);

    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            depth: Some(-1),
            ..opts(&["main"])
        },
    );
    assert!(report.is_err());
    match outcome {
        Err(Error::Remote(remote::Error::NonFastForward(_))) => {}
        other => panic!("expected NonFastForward, got {other:?}"),
    }
    assert_eq!(tip(&pair.server, "main"), Some(c1));
    for lacked in [c4, c3, c2] {
        assert!(!has_commit(&pair.server, &lacked), "{lacked}");
    }
}

#[test]
fn detached_metadata_of_a_new_value_the_server_holds_is_sent() {
    let pair = Pair::new("held-meta", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();
    let mut detached = DictBuilder::new();
    detached.insert_str("xa.later", "written after the first push");
    block_on(
        pair.client
            .write_commit_detached_metadata(&c1, Some(&detached.build())),
    )
    .unwrap();

    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    assert_eq!(outcome.unwrap().stats.objects_sent, 0);
    let stored = block_on(pair.server.read_commit_detached_metadata(&c1))
        .unwrap()
        .expect("the server stores the detached metadata");
    assert!(stored.dict_get("xa.later").is_some());
}

#[test]
fn an_object_that_a_held_source_commit_lacks_on_the_server_is_sent() {
    let pair = Pair::new("held-partial", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();
    // The server loses one file object of the commit, and marks the commit
    // partial.
    let names = block_on(pair.server.traverse_commit(&c1, 0)).unwrap();
    let lost = names
        .iter()
        .find(|n| n.ty == ObjectType::File)
        .expect("the tree holds a file object");
    let path = ostrya::loose_path(&lost.checksum, ObjectType::File, RepoMode::Archive);
    std::fs::remove_file(pair.server.path().join("objects").join(path)).unwrap();
    mark_partial(&pair.server, &c1);

    let (report, outcome) = push(&pair, opts(&["main:other"]));
    report.unwrap();
    assert_eq!(outcome.unwrap().stats.objects_sent, 1);
    assert_eq!(tip(&pair.server, "other"), Some(c1));
    assert!(block_on(pair.server.has_object(ObjectType::File, &lost.checksum)).unwrap());
}

#[test]
fn a_forced_push_expects_any_state_of_the_ref() {
    let pair = Pair::new("force", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let side = commit(&pair.client, "side", None, "side", None);
    let (report, outcome) = push(&pair, opts(&["main", "side"]));
    report.unwrap();
    outcome.unwrap();
    let c2 = commit(&pair.client, "main", Some(c1), "c2", None);

    // Another writer moves the ref of the server to an unrelated commit
    // after `HelloReply`. The update is then not a fast-forward from the
    // state that `HelloReply` reported.
    let policy = policy_allowing(&["wd:**"]);
    let server = pair.server.clone();
    let (report, outcome) = push_under(
        &pair,
        RepoPushOptions {
            force: true,
            ..opts(&["main"])
        },
        &policy,
        move |kind| {
            if kind == COMMIT_FRAME {
                let server = server.clone();
                on_own_thread(move || block_on(server.set_ref_immediate("main", Some(&side))))
                    .unwrap();
            }
        },
    );
    report.unwrap();
    let outcome = outcome.unwrap();
    assert_eq!(outcome.refs[0].old, Some(side));
    assert_eq!(outcome.refs[0].new, Some(c2));
    assert_eq!(tip(&pair.server, "main"), Some(c2));
}

/// A revision reads a `DST` of 64 lowercase hex characters as a commit
/// checksum. The client refuses this `DST` as an invalid refspec before it
/// writes a byte.
#[test]
fn a_destination_of_64_lowercase_hex_characters_is_refused_before_any_byte() {
    let dir = TmpDir::new("push-repo-hex-dst");
    let repo = new_repo(&dir, RepoMode::Archive, "");
    commit(&repo, "main", None, "c1", None);
    let hex = "a".repeat(64);
    let (error, written) = refused(&repo, opts(&[&format!("main:{hex}")]));
    match &error {
        Error::InvalidRefspec(name) => assert_eq!(name, &hex),
        other => panic!("expected InvalidRefspec, got {other:?}"),
    }
    assert_eq!(written, 0);
}

/// A delete (`:DST`) of a `DST` of 64 lowercase hex characters passes the
/// client, and a server policy with `d` on the ref removes the ref.
#[test]
fn a_delete_of_a_destination_of_64_lowercase_hex_characters_removes_the_ref() {
    let pair = Pair::new("hex-delete", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();
    let hex = "a".repeat(64);
    block_on(pair.server.set_ref_immediate(&hex, Some(&c1))).unwrap();
    let path = pair.server.path().join("refs/heads").join(&hex);
    assert!(path.exists());

    let policy = policy_allowing(&["rwd:**"]);
    let (report, outcome) = push_under(&pair, opts(&[&format!(":{hex}")]), &policy, |_| {});
    report.unwrap();
    let outcome = outcome.unwrap();
    assert_eq!(outcome.refs[0].name, hex);
    assert_eq!(outcome.refs[0].old, Some(c1));
    assert_eq!(outcome.refs[0].new, None);
    assert!(!path.exists());
    assert_eq!(tip(&pair.server, "main"), Some(c1));
}

/// The content bytes that a push reads end at the byte total of its source.
/// This holds in each client mode that ostrya writes, and with each
/// encoding. A symlink counts no byte.
#[test]
fn the_content_bytes_end_at_the_byte_total() {
    let deflate = Compression::Deflate { level: 6 };
    for (tag, mode, compression) in [
        ("total-archive-raw", RepoMode::Archive, Compression::None),
        ("total-archive-deflate", RepoMode::Archive, deflate),
        ("total-bare-user-raw", RepoMode::BareUser, Compression::None),
        ("total-bare-user-deflate", RepoMode::BareUser, deflate),
        (
            "total-bare-user-only",
            RepoMode::BareUserOnly,
            Compression::None,
        ),
        ("total-bare-user-shared", RepoMode::BareUserShared, deflate),
        ("total-bare", RepoMode::Bare, deflate),
    ] {
        // A `bare` commit writes the owner 0:0 of its files.
        if mode == RepoMode::Bare && !is_root() {
            eprintln!("skipping {tag}: the commit needs root");
            continue;
        }
        let pair = Pair::new(tag, mode, RepoMode::Archive, "");
        commit(&pair.client, "main", None, "c1", None);
        let progress = PushProgress::new();
        let (report, outcome) = push(
            &pair,
            RepoPushOptions {
                progress: Some(progress.clone()),
                compression,
                ..opts(&["main"])
            },
        );
        report.unwrap();
        outcome.unwrap();
        let snapshot = progress.snapshot();
        assert_eq!(snapshot.content_bytes, snapshot.bytes_total, "{tag}");
        if (mode, compression) == (RepoMode::Archive, deflate) {
            // The stored `.filez` files go as they are.
            assert!(snapshot.bytes_total > 26, "{tag}: {snapshot:?}");
        } else {
            // The payloads of `file` and `sub/nested`, and 0 for `link`.
            assert_eq!(snapshot.bytes_total, 2 + 24, "{tag}");
        }
    }
}

/// A push over ssh, over HTTP, or over a pair of streams refuses the fields
/// of a push to a bucket repository, before it takes a lock or writes a
/// byte.
#[test]
fn a_session_push_refuses_the_bucket_fields() {
    let dir = TmpDir::new("push-repo-bucket-fields");
    let client = new_repo(&dir, RepoMode::Archive, "");
    for (name, opts) in [
        (
            "break_lock",
            RepoPushOptions {
                break_lock: true,
                ..RepoPushOptions::default()
            },
        ),
        (
            "part_size",
            RepoPushOptions {
                part_size: Some(5 << 20),
                ..RepoPushOptions::default()
            },
        ),
    ] {
        let opts = RepoPushOptions {
            refspecs: vec!["main".into()],
            ..opts
        };
        let endpoint = remote::Endpoint::Http(ostrya::FetcherOptions::new("https://ex.com/repo"));
        let expected = format!("{name} applies to a push to an s3:// address");
        for result in [
            block_on(client.push(endpoint, opts.clone())),
            block_on(client.push_over_stream(
                futures_lite::io::empty(),
                futures_lite::io::sink(),
                opts,
            )),
        ] {
            match result {
                Err(Error::Remote(remote::Error::InvalidInput(message))) => {
                    assert_eq!(message, expected)
                }
                other => panic!("{name}: {other:?}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dependencies.
// ---------------------------------------------------------------------------

/// Commits a dependency on `dep/uki` of `repo`, and a tip on `main` whose
/// field 2 names it as `boot/uki`. Returns the tip and the dependency.
fn dependency_chain(repo: &Repo) -> (Checksum, Checksum) {
    let dep = commit(repo, "dep/uki", None, "uki", None);
    let main = commit_related(repo, "main", None, "main", None, &[("boot/uki", dep)]);
    (main, dep)
}

/// Asserts that `server` holds `commit` with no marker and each object of
/// its tree.
fn assert_complete(client: &Repo, server: &Repo, commit: &Checksum) {
    assert_eq!(
        block_on(server.commit_state(commit)).unwrap(),
        ostrya::CommitState::Normal,
        "{commit}"
    );
    for name in block_on(client.traverse_commit(commit, 0)).unwrap() {
        assert!(
            block_on(server.has_object(name.ty, &name.checksum)).unwrap(),
            "{commit}: {name:?}"
        );
    }
}

/// Removes the loose commit object of `commit` from the archive repository
/// `repo`.
fn remove_commit_object(repo: &Repo, commit: &Checksum) {
    let path = ostrya::loose_path(commit, ObjectType::Commit, RepoMode::Archive);
    std::fs::remove_file(repo.path().join("objects").join(path)).unwrap();
}

/// Points the ref `name` of `repo` at `commit`.
fn move_ref(repo: &Repo, name: &str, commit: &Checksum) {
    block_on(async {
        let txn = repo.transaction().await.unwrap();
        txn.set_ref(name, Some(commit));
        txn.commit().await.unwrap();
    });
}

/// A detached metadata dict with one property.
fn detached_dict() -> Value {
    let mut builder = DictBuilder::new();
    builder.insert_str("xa.note", "dependency");
    builder.build()
}

/// A push sends the dependency that field 2 of the source commit names,
/// complete and with its `.commitmeta`, and the server writes no ref for it.
/// A second push sends no object.
#[test]
fn a_push_sends_the_dependency_of_the_commit() {
    let pair = Pair::new("dependency", RepoMode::Archive, RepoMode::Archive, "");
    let (main, dep) = dependency_chain(&pair.client);
    block_on(
        pair.client
            .write_commit_detached_metadata(&dep, Some(&detached_dict())),
    )
    .unwrap();

    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();

    assert_complete(&pair.client, &pair.server, &main);
    assert_complete(&pair.client, &pair.server, &dep);
    assert_eq!(
        block_on(pair.server.read_commit_detached_metadata(&dep)).unwrap(),
        Some(detached_dict())
    );
    assert_eq!(
        block_on(pair.server.list_refs(None)).unwrap(),
        [("main".to_owned(), main)]
    );

    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    assert_eq!(outcome.unwrap().stats.objects_sent, 0);
}

/// A push with a depth sends the dependencies of each parent that it sends.
/// At depth 0 it sends no parent, so it sends the dependency of the source
/// commit alone.
#[test]
fn a_push_with_depth_sends_the_dependencies_of_the_parents() {
    for depth in [0, 1, -1] {
        let pair = Pair::new(
            &format!("dependency-parent-{depth}"),
            RepoMode::Archive,
            RepoMode::Archive,
            "",
        );
        let d1 = commit(&pair.client, "dep/d1", None, "d1", None);
        let d2 = commit(&pair.client, "dep/d2", None, "d2", None);
        let parent = commit_related(&pair.client, "main", None, "p", None, &[("boot/d1", d1)]);
        let main = commit_related(
            &pair.client,
            "main",
            Some(parent),
            "t",
            None,
            &[("boot/d2", d2)],
        );

        let (report, outcome) = push(
            &pair,
            RepoPushOptions {
                depth: Some(depth),
                ..opts(&["main"])
            },
        );
        report.unwrap();
        outcome.unwrap();

        assert_complete(&pair.client, &pair.server, &main);
        assert_complete(&pair.client, &pair.server, &d2);
        for commit in [parent, d1] {
            assert_eq!(
                has_commit(&pair.server, &commit),
                depth != 0,
                "depth {depth}: {commit}"
            );
        }
        if depth != 0 {
            assert_complete(&pair.client, &pair.server, &d1);
        }
        assert_eq!(tip(&pair.server, "main"), Some(main));
    }
}

/// A push sends a dependency at depth 0, also under a push of the whole
/// history and with no depth. The parent of the dependency stays in the
/// local repository.
#[test]
fn a_dependency_is_sent_at_depth_zero() {
    for depth in [Some(-1), None] {
        let pair = Pair::new(
            &format!("dependency-depth-{depth:?}"),
            RepoMode::Archive,
            RepoMode::Archive,
            "",
        );
        let old = commit(&pair.client, "dep/uki", None, "old", None);
        let dep = commit(&pair.client, "dep/uki", Some(old), "uki", None);
        let main = commit_related(
            &pair.client,
            "main",
            None,
            "main",
            None,
            &[("boot/uki", dep)],
        );

        let (report, outcome) = push(
            &pair,
            RepoPushOptions {
                depth,
                ..opts(&["main"])
            },
        );
        report.unwrap();
        outcome.unwrap();

        assert_complete(&pair.client, &pair.server, &main);
        assert_complete(&pair.client, &pair.server, &dep);
        assert!(!has_commit(&pair.server, &old), "{depth:?}");
    }
}

/// A dependency that two sent commits name is sent one time. The server
/// refuses a second dict for one commit, so the push passes only if it sends
/// the `.commitmeta` of the dependency one time.
#[test]
fn a_dependency_that_two_commits_name_is_sent_once() {
    let pair = Pair::new("dependency-once", RepoMode::Archive, RepoMode::Archive, "");
    let dep = commit(&pair.client, "dep/uki", None, "uki", None);
    block_on(
        pair.client
            .write_commit_detached_metadata(&dep, Some(&detached_dict())),
    )
    .unwrap();
    let parent = commit_related(&pair.client, "main", None, "p", None, &[("boot/uki", dep)]);
    commit_related(
        &pair.client,
        "main",
        Some(parent),
        "t",
        None,
        &[("boot/uki", dep)],
    );

    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            depth: Some(1),
            ..opts(&["main"])
        },
    );
    report.unwrap();
    outcome.unwrap();

    assert_complete(&pair.client, &pair.server, &dep);
    assert_eq!(
        block_on(pair.server.read_commit_detached_metadata(&dep)).unwrap(),
        Some(detached_dict())
    );
}

/// The source commit names its own parent as a dependency. At depth 0 the
/// dependency brings the parent in, and at depth 1 the walk does. In both,
/// the push sends the parent and its `.commitmeta` one time, with no parent
/// of its own.
#[test]
fn a_parent_that_is_a_dependency_is_sent_once() {
    for depth in [0, 1] {
        let pair = Pair::new(
            &format!("dependency-parent-once-{depth}"),
            RepoMode::Archive,
            RepoMode::Archive,
            "",
        );
        let grand = commit(&pair.client, "main", None, "g", None);
        let parent = commit(&pair.client, "main", Some(grand), "p", None);
        block_on(
            pair.client
                .write_commit_detached_metadata(&parent, Some(&detached_dict())),
        )
        .unwrap();
        commit_related(
            &pair.client,
            "main",
            Some(parent),
            "t",
            None,
            &[("boot/p", parent)],
        );

        let (report, outcome) = push(
            &pair,
            RepoPushOptions {
                depth: Some(depth),
                ..opts(&["main"])
            },
        );
        report.unwrap();
        outcome.unwrap();

        assert_complete(&pair.client, &pair.server, &parent);
        assert!(!has_commit(&pair.server, &grand), "depth {depth}");
        assert_eq!(
            block_on(pair.server.read_commit_detached_metadata(&parent)).unwrap(),
            Some(detached_dict()),
            "depth {depth}"
        );
    }
}

/// The push walks no tree of a dependency that the server holds: the local
/// repository lacks the root dirtree of the dependency, and the push passes.
#[test]
fn a_dependency_the_server_holds_gets_no_tree_walk() {
    let pair = Pair::new("dependency-held", RepoMode::Archive, RepoMode::Archive, "");
    let (main, dep) = dependency_chain(&pair.client);
    let (report, outcome) = push(&pair, opts(&["dep/uki"]));
    report.unwrap();
    outcome.unwrap();
    let (root, _) = block_on(pair.client.load_commit(&dep)).unwrap();
    let path = ostrya::loose_path(&root.root_dirtree, ObjectType::DirTree, RepoMode::Archive);
    std::fs::remove_file(pair.client.path().join("objects").join(path)).unwrap();

    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();

    assert_eq!(tip(&pair.server, "main"), Some(main));
    assert_complete(&pair.server, &pair.server, &dep);
}

/// A dependency that the local repository does not hold, or marks partial,
/// is refused before the push writes a byte.
#[test]
fn an_absent_or_partial_dependency_is_refused_before_any_byte() {
    let dir = TmpDir::new("push-repo-dependency-absent");
    let repo = new_repo(&dir, RepoMode::Archive, "");
    let (main, dep) = dependency_chain(&repo);

    mark_partial(&repo, &dep);
    let (error, written) = refused(&repo, opts(&["main"]));
    assert_eq!(
        dependency_error(error),
        (
            Some(main),
            format!("dependency boot/uki names commit {dep}, which is partial")
        )
    );
    assert_eq!(written, 0);

    remove_commit_object(&repo, &dep);
    let (error, written) = refused(&repo, opts(&["main"]));
    match error {
        Error::ObjectNotFound { checksum, ty } => {
            assert_eq!((checksum, ty), (dep, ObjectType::Commit));
        }
        other => panic!("expected ObjectNotFound, got {other:?}"),
    }
    assert_eq!(written, 0);
}

/// A field 2 entry with an empty name or with a checksum that is not 32
/// bytes is refused before the push writes a byte, also in a history commit
/// that a push with no depth does not send.
#[test]
fn a_defective_dependency_entry_is_refused_before_any_byte() {
    let dir = TmpDir::new("push-repo-dependency-defective");
    let repo = new_repo(&dir, RepoMode::Archive, "");
    let (main, dep) = dependency_chain(&repo);
    let short: &[u8] = &dep.as_bytes()[..31];
    for (entry, reason) in [
        (
            ("boot/uki", short),
            "entry 0 (boot/uki) has a checksum of 31 bytes, not 32",
        ),
        (("", dep.as_bytes()), "entry 0 has an empty name"),
    ] {
        let defective = block_on(store_with_field2(&repo, &main, &[entry]));
        move_ref(&repo, "main", &defective);
        let (error, written) = refused(&repo, opts(&["main"]));
        assert_eq!(
            dependency_error(error),
            (Some(defective), reason.to_owned())
        );
        assert_eq!(written, 0);

        // The defective commit is the parent of the source commit.
        let child = commit(&repo, "main", Some(defective), "child", None);
        let (error, written) = refused(&repo, opts(&["main"]));
        assert_eq!(
            dependency_error(error),
            (Some(defective), reason.to_owned())
        );
        assert_eq!(written, 0);
        assert_eq!(tip(&repo, "main"), Some(child));
    }
}

/// A dependency that names dependencies of its own is refused before the
/// push writes a byte, also if the push takes that commit as a source
/// commit. The error names the commit that names the nested dependency.
#[test]
fn a_nested_dependency_is_refused_before_any_byte() {
    let dir = TmpDir::new("push-repo-dependency-nested");
    let repo = new_repo(&dir, RepoMode::Archive, "");
    let (main, dep) = dependency_chain(&repo);
    let other = commit(&repo, "other", None, "other", None);
    // `other` names a commit with a dependency, and `main` names a commit
    // whose dependency is that commit.
    let nested = block_on(store_with_field2(
        &repo,
        &other,
        &[("lib/c", dep.as_bytes())],
    ));
    let head = block_on(store_with_field2(
        &repo,
        &main,
        &[("lib/b", nested.as_bytes())],
    ));
    move_ref(&repo, "other", &nested);
    move_ref(&repo, "main", &head);

    let reason =
        format!("dependency lib/b names commit {nested}, which has dependencies of its own");
    for specs in [&["main"][..], &["main", "other"], &["other", "main"]] {
        let (error, written) = refused(&repo, opts(specs));
        assert_eq!(
            dependency_error(error),
            (Some(head), reason.clone()),
            "{specs:?}"
        );
        assert_eq!(written, 0, "{specs:?}");
    }
}

/// A parent that the local repository does not hold ends its chain. If the
/// source commit names the parent as a dependency, the push is refused
/// before it writes a byte.
#[test]
fn an_absent_parent_that_is_a_dependency_is_refused_before_any_byte() {
    let dir = TmpDir::new("push-repo-dependency-absent-parent");
    let repo = new_repo(&dir, RepoMode::Archive, "");
    let parent = commit(&repo, "main", None, "p", None);
    let plain = commit(&repo, "main", Some(parent), "t", None);
    let source = block_on(store_with_field2(
        &repo,
        &plain,
        &[("boot/p", parent.as_bytes())],
    ));
    move_ref(&repo, "main", &source);
    remove_commit_object(&repo, &parent);

    for depth in [Some(1), None] {
        let (error, written) = refused(
            &repo,
            RepoPushOptions {
                depth,
                ..opts(&["main"])
            },
        );
        match error {
            Error::ObjectNotFound { checksum, ty } => {
                assert_eq!((checksum, ty), (parent, ObjectType::Commit), "{depth:?}");
            }
            other => panic!("{depth:?}: expected ObjectNotFound, got {other:?}"),
        }
        assert_eq!(written, 0, "{depth:?}");
    }
}

/// With a depth, the push resolves the dependencies of each history commit
/// before it writes a byte. A nested, a partial, and an absent dependency
/// that the parent of the source commit alone names are each refused.
#[test]
fn with_a_depth_a_dependency_of_a_history_commit_is_refused_before_any_byte() {
    let dir = TmpDir::new("push-repo-dependency-history");
    let repo = new_repo(&dir, RepoMode::Archive, "");
    let depth_one = || RepoPushOptions {
        depth: Some(1),
        ..opts(&["main"])
    };

    // The parent names a commit that names a dependency of its own.
    let dep = commit(&repo, "dep/uki", None, "uki", None);
    let other = commit(&repo, "other", None, "other", None);
    let nested = block_on(store_with_field2(
        &repo,
        &other,
        &[("lib/c", dep.as_bytes())],
    ));
    let plain = commit(&repo, "main", None, "p", None);
    let parent = block_on(store_with_field2(
        &repo,
        &plain,
        &[("lib/b", nested.as_bytes())],
    ));
    commit(&repo, "main", Some(parent), "t", None);
    let (error, written) = refused(&repo, depth_one());
    assert_eq!(
        dependency_error(error),
        (
            Some(parent),
            format!("dependency lib/b names commit {nested}, which has dependencies of its own")
        )
    );
    assert_eq!(written, 0);

    // The parent names a partial dependency, then an absent one.
    let parent = commit_related(&repo, "main", None, "p", None, &[("boot/uki", dep)]);
    commit(&repo, "main", Some(parent), "t", None);
    mark_partial(&repo, &dep);
    let (error, written) = refused(&repo, depth_one());
    assert_eq!(
        dependency_error(error),
        (
            Some(parent),
            format!("dependency boot/uki names commit {dep}, which is partial")
        )
    );
    assert_eq!(written, 0);

    remove_commit_object(&repo, &dep);
    let (error, written) = refused(&repo, depth_one());
    match error {
        Error::ObjectNotFound { checksum, ty } => {
            assert_eq!((checksum, ty), (dep, ObjectType::Commit));
        }
        other => panic!("expected ObjectNotFound, got {other:?}"),
    }
    assert_eq!(written, 0);
}

/// A push does not send a build source: the commit that `ostrya.related`
/// names. The key travels with the detached metadata of the commit.
#[test]
fn a_push_does_not_send_a_build_source() {
    let pair = Pair::new("build-source", RepoMode::Archive, RepoMode::Archive, "");
    let (main, _dep) = dependency_chain(&pair.client);
    let source = commit(&pair.client, "other/base", None, "base", None);
    block_on(
        pair.client
            .add_detached_related(&main, "layer/base", &source),
    )
    .unwrap();

    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();

    assert_eq!(
        block_on(pair.server.read_commit_related(&main))
            .unwrap()
            .build_sources,
        [("layer/base".to_owned(), source)]
    );
    assert!(!has_commit(&pair.server, &source));
}

/// With no depth, the push resolves the dependencies of the history after
/// the cut at the server tip. A refused dependency of such a commit ends the
/// session with `Abort` before the first upload. A dependency of the server
/// tip, which the push does not send, is not resolved.
#[test]
fn with_no_depth_a_dependency_of_the_offered_history_is_resolved_after_the_cut() {
    let pair = Pair::new("dependency-cut", RepoMode::Archive, RepoMode::Archive, "");
    let held = commit(&pair.client, "dep/held", None, "held", None);
    let c1 = commit_related(
        &pair.client,
        "main",
        None,
        "c1",
        None,
        &[("boot/held", held)],
    );
    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();
    assert!(has_commit(&pair.server, &held));
    // The client loses the dependency of the server tip.
    remove_commit_object(&pair.client, &held);

    let dep = commit(&pair.client, "dep/uki", None, "uki", None);
    let c2 = commit_related(
        &pair.client,
        "main",
        Some(c1),
        "c2",
        None,
        &[("boot/uki", dep)],
    );
    let c3 = commit(&pair.client, "main", Some(c2), "c3", None);
    remove_commit_object(&pair.client, &dep);
    let progress = PushProgress::new();
    let (kinds, hook) = frame_kinds();
    let (report, outcome) = push_through(
        &pair,
        RepoPushOptions {
            progress: Some(progress.clone()),
            ..opts(&["main"])
        },
        hook,
    );
    assert_aborted(&report);
    match outcome {
        Err(Error::ObjectNotFound { checksum, ty }) => {
            assert_eq!((checksum, ty), (dep, ObjectType::Commit));
        }
        other => panic!("expected ObjectNotFound, got {other:?}"),
    }
    let kinds = kinds.lock().unwrap().clone();
    assert!(!kinds.contains(&HAVE_FRAME), "{kinds:?}");
    assert_eq!(progress.snapshot().payload_bytes, 0);
    assert!(!has_commit(&pair.server, &c2));
    assert!(!has_commit(&pair.server, &c3));
    assert_eq!(tip(&pair.server, "main"), Some(c1));

    // With the commit that names the absent dependency out of the push, the
    // push passes.
    move_ref(&pair.client, "main", &c1);
    let c4 = commit(&pair.client, "main", Some(c1), "c4", None);
    let (report, outcome) = push(&pair, opts(&["main"]));
    report.unwrap();
    outcome.unwrap();
    assert_eq!(tip(&pair.server, "main"), Some(c4));
}

// ---------------------------------------------------------------------------
// The checks of the server on the dependencies.
// ---------------------------------------------------------------------------

/// Signs `commit` of `repo` with the key [`SECRET_B64`].
fn client_sign(repo: &Repo, commit: &Checksum) {
    let signer = Ed25519Signer::from_secret_key(&secret(SECRET_B64)).unwrap();
    block_on(repo.sign_commit(commit, &signer)).unwrap();
}

/// A server policy that needs a signature of the key [`SECRET_B64`].
fn verify_policy() -> ReceivePolicy {
    ReceivePolicy {
        verify: ReceiveVerify::Keys(trust(SECRET_B64)),
        ..policy_allowing(&["w:**"])
    }
}

/// A server policy that signs each new commit with the key
/// [`SERVER_SECRET_B64`].
fn sign_policy() -> ReceivePolicy {
    ReceivePolicy {
        signers: vec![server_signer(SERVER_SECRET_B64)],
        ..policy_allowing(&["w:**"])
    }
}

/// Asserts that the server refused a push with `code`.
fn assert_refused(pushed: Pushed, code: remote::ErrorCode) {
    let (report, outcome) = pushed;
    match report {
        Err(Error::Remote(e)) => assert_eq!(e.code(), Some(code), "{e}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(outcome.is_err(), "{outcome:?}");
}

/// Under a server policy with `verify`, a dependency with no signature is
/// refused, and the server keeps no ref and no dependency. After the client
/// signs the dependency, the push passes.
#[test]
fn an_unsigned_dependency_is_refused_under_verify() {
    let pair = Pair::new(
        "dependency-verify",
        RepoMode::Archive,
        RepoMode::Archive,
        "",
    );
    let (main, dep) = dependency_chain(&pair.client);
    client_sign(&pair.client, &main);

    let pushed = push_under(&pair, opts(&["main"]), &verify_policy(), |_| {});
    assert_refused(pushed, remote::ErrorCode::SignatureRequired);
    assert_eq!(tip(&pair.server, "main"), None);
    assert!(!has_commit(&pair.server, &dep));
    assert!(!has_commit(&pair.server, &main));

    client_sign(&pair.client, &dep);
    let (report, outcome) = push_under(&pair, opts(&["main"]), &verify_policy(), |_| {});
    report.unwrap();
    outcome.unwrap();
    assert_eq!(tip(&pair.server, "main"), Some(main));
    assert_complete(&pair.client, &pair.server, &dep);
}

/// With depth 1, a dependency of the parent is checked under the rule of the
/// source commit.
#[test]
fn with_a_depth_a_dependency_of_the_parent_is_checked_under_the_rule_of_the_source() {
    let pair = Pair::new(
        "dependency-verify-parent",
        RepoMode::Archive,
        RepoMode::Archive,
        "",
    );
    let dep = commit(&pair.client, "dep/d", None, "d", None);
    let parent = commit_related(&pair.client, "main", None, "p", None, &[("boot/d", dep)]);
    let main = commit(&pair.client, "main", Some(parent), "t", None);
    client_sign(&pair.client, &main);
    let options = || RepoPushOptions {
        depth: Some(1),
        ..opts(&["main"])
    };

    let pushed = push_under(&pair, options(), &verify_policy(), |_| {});
    assert_refused(pushed, remote::ErrorCode::SignatureRequired);
    assert!(!has_commit(&pair.server, &dep));

    client_sign(&pair.client, &dep);
    let (report, outcome) = push_under(&pair, options(), &verify_policy(), |_| {});
    report.unwrap();
    outcome.unwrap();
    assert_eq!(tip(&pair.server, "main"), Some(main));
    assert!(has_commit(&pair.server, &parent));
    assert_complete(&pair.client, &pair.server, &dep);
}

/// Under a server policy with `sign`, a staged dependency carries the server
/// signature once. A later push of a commit that names the held dependency
/// adds no signature.
#[test]
fn a_staged_dependency_carries_the_server_signature_once() {
    let pair = Pair::new("dependency-sign", RepoMode::Archive, RepoMode::Archive, "");
    let (main, dep) = dependency_chain(&pair.client);
    let (report, outcome) = push_under(&pair, opts(&["main"]), &sign_policy(), |_| {});
    report.unwrap();
    outcome.unwrap();
    let bytes = block_on(pair.server.load_object_bytes(ObjectType::Commit, &dep)).unwrap();
    let expected = [ed25519_signature(SERVER_SECRET_B64, &bytes)];
    assert_eq!(ed25519_signatures(&pair.server, &dep), expected);

    let next = commit_related(
        &pair.client,
        "main",
        Some(main),
        "next",
        None,
        &[("boot/uki", dep)],
    );
    let (report, outcome) = push_under(&pair, opts(&["main"]), &sign_policy(), |_| {});
    report.unwrap();
    outcome.unwrap();
    assert_eq!(tip(&pair.server, "main"), Some(next));
    assert_eq!(ed25519_signatures(&pair.server, &dep), expected);
}

/// A dependency that the server already holds gets no server signature.
#[test]
fn a_dependency_the_server_holds_gets_no_server_signature() {
    let pair = Pair::new(
        "dependency-held-sign",
        RepoMode::Archive,
        RepoMode::Archive,
        "",
    );
    let (main, dep) = dependency_chain(&pair.client);
    let (report, outcome) = push(&pair, opts(&["dep/uki"]));
    report.unwrap();
    outcome.unwrap();

    let (report, outcome) = push_under(&pair, opts(&["main"]), &sign_policy(), |_| {});
    report.unwrap();
    outcome.unwrap();
    assert_eq!(tip(&pair.server, "main"), Some(main));
    assert!(ed25519_signatures(&pair.server, &dep).is_empty());
    assert_eq!(ed25519_signatures(&pair.server, &main).len(), 1);
}

/// A dependency that the server holds and marks partial refuses the push
/// with `missing-objects`. The server moves no ref.
#[test]
fn a_dependency_the_server_holds_partial_refuses_the_push() {
    let pair = Pair::new(
        "dependency-held-partial",
        RepoMode::Archive,
        RepoMode::Archive,
        "",
    );
    let (main, dep) = dependency_chain(&pair.client);
    let (report, outcome) = push(&pair, opts(&["dep/uki"]));
    report.unwrap();
    outcome.unwrap();
    mark_partial(&pair.server, &dep);

    assert_refused(
        push(&pair, opts(&["main"])),
        remote::ErrorCode::MissingObjects,
    );
    assert_eq!(tip(&pair.server, "main"), None);
    assert!(!has_commit(&pair.server, &main));
}

// ---------------------------------------------------------------------------
// Compile-time checks.
// ---------------------------------------------------------------------------

/// The options are `Send` and `Sync`, so they can move across tasks and
/// threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RepoPushOptions>();
};

/// The futures of a push can run on a multi-threaded executor.
#[allow(dead_code)]
fn push_futures_are_send(
    repo: &Repo,
    endpoint: remote::Endpoint,
    input: PipeReader,
    output: PipeWriter,
) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&repo.push(endpoint, RepoPushOptions::default()));
    assert_send(&repo.push_over_stream(input, output, RepoPushOptions::default()));
}
