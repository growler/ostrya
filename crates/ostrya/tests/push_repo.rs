//! `Repo::push_over_stream` against `Repo::receive` over two in-process
//! pipes. The tests cover the negotiation, the depth of the chains, the
//! refusals of the client, and the lock of the local repository.

#![cfg(all(feature = "push", feature = "receive"))]

mod common;

use std::io;
use std::os::fd::AsFd;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use common::TmpDir;
use common::receive::{PIPE_CAP, PipeReader, PipeWriter, new_repo, pipe};
use futures_io::AsyncWrite;
use futures_lite::future::zip;
use ostrya::push::{self, Compression, PushOutcome, PushProgress};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, DetachedMetadataFilter,
    DictBuilder, Error, MutableTree, ObjectType, PruneOptions, ReceivePolicy, ReceiveReport,
    ReceiveRule, Repo, RepoMode, RepoPushOptions, Value,
};
use ostrya_rt::block_on;

// ---------------------------------------------------------------------------
// Repositories and commits.
// ---------------------------------------------------------------------------

/// A client repository and a server repository, each in a directory of its
/// own. `server_core` is appended to the config of the server.
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

/// Commit a tree onto `branch` of `repo`, with `parent` and `metadata`. The
/// tree holds a file `file` with `content`, a symlink `link` to it, and a
/// directory `sub` whose file is the same in every commit.
fn commit(
    repo: &Repo,
    branch: &str,
    parent: Option<Checksum>,
    content: &str,
    metadata: Option<Value>,
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
    push_under(pair, opts, &ReceivePolicy::default(), hook)
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

/// A writer that counts the bytes it takes.
struct Counting<W> {
    inner: W,
    written: Arc<AtomicU64>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Counting<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let n = std::task::ready!(Pin::new(&mut me.inner).poll_write(cx, buf))?;
        me.written.fetch_add(n as u64, Ordering::Relaxed);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
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
                        0 | push::proto::ABANDON => Parse::Frames,
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

/// Run `work` to its end on a thread of its own, with an executor of its
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
        Err(Error::Push(push::Error::Aborted)) => {}
        other => panic!("expected Aborted on the server, got {other:?}"),
    }
}

/// Mark `commit` partial in `repo`.
fn mark_partial(repo: &Repo, commit: &Checksum) {
    std::fs::write(
        repo.path().join(format!("state/{commit}.commitpartial")),
        b"",
    )
    .unwrap();
}

fn assert_invalid_input(error: &Error, needle: &str) {
    match error {
        Error::Push(push::Error::InvalidInput(msg)) => {
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
        Err(Error::Push(push::Error::RefMismatch { name, current, .. })) => {
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
        Error::Push(push::Error::BindingMismatch(msg)) => {
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

#[test]
fn a_collection_binding_mismatch_is_refused_before_any_upload() {
    let pair = Pair::new(
        "collection",
        RepoMode::Archive,
        RepoMode::Archive,
        "collection-id=org.example.Server\n",
    );
    let mut metadata = DictBuilder::new();
    metadata.insert_str("ostree.collection-binding", "org.example.Other");
    let c1 = commit(&pair.client, "main", None, "c1", Some(metadata.build()));
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
        Err(Error::Push(push::Error::BindingMismatch(msg))) => {
            assert!(msg.contains("org.example.Other"), "{msg}");
        }
        other => panic!("expected BindingMismatch, got {other:?}"),
    }
    // The client refuses after `Hello`, with no `Have`: the check of the
    // server runs only after the upload.
    let kinds = kinds.lock().unwrap().clone();
    assert!(!kinds.contains(&HAVE_FRAME), "{kinds:?}");
    assert_eq!(kinds.last(), Some(&ABORT_FRAME), "{kinds:?}");
    let snapshot = progress.snapshot();
    assert_eq!(snapshot.objects_total, 0, "no Have was sent");
    assert_eq!(snapshot.objects_sent, 0);
    assert_eq!(snapshot.payload_bytes, 0);
    assert!(!has_commit(&pair.server, &c1));
    assert_eq!(tip(&pair.server, "main"), None);
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
        Err(Error::Push(push::Error::DeleteDenied(_))) => {}
        other => panic!("expected DeleteDenied, got {other:?}"),
    }
    // A push of deletes alone offers no object.
    assert_eq!(progress.snapshot().objects_total, 0);
    assert_eq!(tip(&pair.server, "main"), Some(c1));
}

#[test]
fn the_filter_drops_the_excluded_keys_from_the_detached_metadata() {
    let pair = Pair::new("filter", RepoMode::Archive, RepoMode::Archive, "");
    let c1 = commit(&pair.client, "main", None, "c1", None);
    let mut detached = DictBuilder::new();
    detached
        .insert_str("xa.keep", "kept")
        .insert_str("xa.drop", "dropped");
    block_on(
        pair.client
            .write_commit_detached_metadata(&c1, Some(&detached.build())),
    )
    .unwrap();
    let (report, outcome) = push(
        &pair,
        RepoPushOptions {
            detached_metadata_filter: DetachedMetadataFilter::excluding(["xa.drop"]),
            ..opts(&["main"])
        },
    );
    report.unwrap();
    outcome.unwrap();
    let stored = block_on(pair.server.read_commit_detached_metadata(&c1))
        .unwrap()
        .expect("the server stores the detached metadata");
    assert!(stored.dict_get("xa.keep").is_some());
    assert!(stored.dict_get("xa.drop").is_none());
}

#[test]
fn deflate_objects_of_an_archive_source_equal_the_stored_filez() {
    // The server deflates a `raw` object at level 1, and the client stored
    // its objects at level 6. So the `.filez` bytes of the server equal
    // those of the client only when the push sends the stored bytes.
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

/// About `len` bytes of text of words in an order that does not repeat
/// soon, so that deflate levels 1 and 6 give different bytes.
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
        Err(Error::Push(push::Error::NonFastForward(_))) => {}
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
        Err(Error::Push(push::Error::NonFastForward(_))) => {}
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
    // after `HelloReply`. So the update is no fast-forward from the state
    // that `HelloReply` reported.
    let policy = ReceivePolicy {
        default_rule: ReceiveRule {
            allow_non_fast_forward: true,
            ..ReceiveRule::default()
        },
        ..ReceivePolicy::default()
    };
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

// ---------------------------------------------------------------------------
// Compile-time checks.
// ---------------------------------------------------------------------------

/// The options move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RepoPushOptions>();
};

/// The futures of a push can run on a multi-threaded executor.
#[allow(dead_code)]
fn push_futures_are_send(repo: &Repo, input: PipeReader, output: PipeWriter) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&repo.push("origin", RepoPushOptions::default()));
    assert_send(&repo.push_over_stream(input, output, RepoPushOptions::default()));
}
