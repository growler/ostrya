//! Tests of the tree push of `ostrya::remote`. The file has three parts:
//!
//! - The tree walk of `ostrya::remote::tree` against the ingest of
//!   `write_dfd_to_mtree`. The two give the same root checksums over the same
//!   tree. The tests skip extended attributes, run with and without canonical
//!   permissions, and skip a directory.
//! - The tree model as the object source of a push to `Repo::receive` over
//!   two in-process pipes, with a commit that the test builds.
//! - The tree push of `push_tree_over_stream` to `Repo::receive`, which makes
//!   a server commit. The tests compare the commit of the server with the
//!   commit of `Transaction::write_commit`. They check the refs that the
//!   server sets, the objects that the push sends, the refusals before any
//!   upload, and the progress phases.

#![cfg(all(feature = "push", feature = "receive"))]

mod common;

use std::collections::HashSet;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use common::receive::{PipeReader, collections_policy, connect, new_repo, policy_allowing};
use common::{ROOT_DIRMETA, ROOT_DIRTREE, TmpDir};
use futures_io::AsyncRead;
use futures_lite::future::zip;
use ostrya::remote::tree::{EntryAction, EntryFilter, EntryKind, ScanOptions, TreeModel};
use ostrya::remote::{
    BoxFuture, Compression, Encoding, Error, Expected, ObjectData, ObjectSource, PushOutcome,
    PushPhase, PushProgress, PushSession, RefUpdate, SessionOptions, TreePushOptions,
    push_tree_over_stream,
};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DictBuilder,
    FilterResult, FsckOptions, MutableTree, ObjectName, ObjectType, ReceivePolicy, ReceiveReport,
    Repo, RepoMode, Type, Value,
};
use ostrya_core::commit_metadata;
use ostrya_rt::block_on;

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The fixture source tree, owner-agnostic, under `base/src`.
fn build_fixture_source(base: &Path) -> PathBuf {
    let src = base.join("src");
    std::fs::create_dir_all(src.join("subdir")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    std::fs::write(src.join("empty.txt"), b"").unwrap();
    std::fs::write(src.join("subdir/nested.txt"), b"nested\n").unwrap();
    std::os::unix::fs::symlink("hello.txt", src.join("link")).unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    set_mode(&src.join("empty.txt"), 0o644);
    set_mode(&src.join("subdir/nested.txt"), 0o644);
    set_mode(&src.join("subdir"), 0o755);
    set_mode(&src, 0o755);
    src
}

/// Builds a source tree under `base/src` and returns its path. The tree holds:
///
/// - nested and empty directories, and a setgid directory
/// - files at several modes, an empty file, and a file over three hash chunks
/// - duplicate content and a hard link
/// - a symlink to a directory
/// - names whose listing order differs from their byte order
fn build_rich_source(base: &Path) -> PathBuf {
    let src = base.join("src");
    std::fs::create_dir_all(src.join("nested/deeper/deepest")).unwrap();
    std::fs::create_dir_all(src.join("nested/empty")).unwrap();
    std::fs::create_dir_all(src.join("setgid")).unwrap();
    std::fs::create_dir_all(src.join("Zdir")).unwrap();
    let big: Vec<u8> = (0..200 * 1024 + 1).map(|i| (i % 251) as u8).collect();
    std::fs::write(src.join("big"), &big).unwrap();
    std::fs::write(src.join("empty"), b"").unwrap();
    std::fs::write(src.join("private"), b"private\n").unwrap();
    std::fs::write(src.join("tool"), b"#!/bin/sh\n").unwrap();
    std::fs::write(src.join("dup-a"), b"same\n").unwrap();
    std::fs::write(src.join("nested/dup-b"), b"same\n").unwrap();
    std::fs::write(src.join("nested/deeper/deepest/leaf"), b"leaf\n").unwrap();
    std::fs::write(src.join("setgid/inside"), b"inside\n").unwrap();
    std::fs::write(src.join("Zdir/_x"), b"x\n").unwrap();
    for name in ["B", "a", "_", "0", "a.b", "aa", "A"] {
        std::fs::write(src.join(name), name.as_bytes()).unwrap();
    }
    std::fs::hard_link(src.join("private"), src.join("hard")).unwrap();
    std::os::unix::fs::symlink("nested", src.join("dirlink")).unwrap();
    std::os::unix::fs::symlink("../big", src.join("nested/up")).unwrap();
    set_mode(&src.join("private"), 0o600);
    set_mode(&src.join("tool"), 0o755);
    set_mode(&src.join("nested/deeper"), 0o700);
    set_mode(&src.join("setgid"), 0o2755);
    set_mode(&src, 0o755);
    src
}

/// Returns a filter that gives each entry the canonical permissions.
///
/// The filter sets the owner to 0:0. For each entry that is not a symlink, it
/// masks the permission bits with 0755.
fn canonical() -> EntryFilter {
    Box::new(|_path, meta| {
        meta.uid = 0;
        meta.gid = 0;
        if meta.kind != EntryKind::Symlink {
            meta.mode = (meta.mode & 0o170000) | (meta.mode & 0o755);
        }
        EntryAction::Keep
    })
}

/// The root dirtree and dirmeta checksums of `write_dfd_to_mtree` over
/// `base/src` into a new archive repository, with `flags` and a filter that
/// skips the path `skip`.
async fn ingest(
    base: &Path,
    repo: &str,
    flags: CommitModifierFlags,
    skip: Option<&'static str>,
) -> (Checksum, Checksum) {
    let repo = Repo::create(&base.join(repo), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let dfd = std::fs::File::open(base).unwrap();
    let mut modifier = CommitModifier::new(flags);
    if let Some(skip) = skip {
        modifier.filter = Some(Box::new(move |path, _meta| {
            if path == Path::new(skip) {
                FilterResult::Skip
            } else {
                FilterResult::Allow
            }
        }));
    }
    let mut mtree = MutableTree::new();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new("src"),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let sums = (*root.dirtree_checksum(), *root.dirmeta_checksum());
    txn.commit().await.unwrap();
    sums
}

/// The root checksums of the tree walk, with each object named once.
async fn scan(src: &Path, entry_filter: Option<EntryFilter>) -> (Checksum, Checksum) {
    let options = ScanOptions {
        entry_filter,
        hash_jobs: None,
    };
    let model = TreeModel::scan(src, options).await.unwrap();
    let names = model.object_names();
    let unique: std::collections::HashSet<_> = names.iter().collect();
    assert_eq!(unique.len(), names.len(), "an object is named twice");
    (model.root_dirtree(), model.root_dirmeta())
}

/// Checks that the walk and the ingest give the same root checksums over the
/// tree that `build` makes. The walk with no filter runs against
/// `SKIP_XATTRS`. The walk with the canonical filter runs against
/// `SKIP_XATTRS | CANONICAL_PERMISSIONS`. Returns the canonical checksums.
fn agree_over(tag: &str, build: fn(&Path) -> PathBuf) -> (Checksum, Checksum) {
    let tmp = TmpDir::new(tag);
    let base = tmp.path();
    let src = build(base);
    block_on(async {
        let plain = ingest(base, "repo-plain", CommitModifierFlags::SKIP_XATTRS, None).await;
        assert_eq!(scan(&src, None).await, plain, "{tag}: no filter");

        let flags = CommitModifierFlags::SKIP_XATTRS | CommitModifierFlags::CANONICAL_PERMISSIONS;
        let canon = ingest(base, "repo-canon", flags, None).await;
        assert_eq!(
            scan(&src, Some(canonical())).await,
            canon,
            "{tag}: canonical"
        );
        canon
    })
}

#[test]
fn the_walk_gives_the_checksums_of_the_ingest_over_the_fixture_tree() {
    let (dirtree, dirmeta) = agree_over("push-tree-fixture", build_fixture_source);
    assert_eq!(dirtree.to_hex(), ROOT_DIRTREE);
    assert_eq!(dirmeta.to_hex(), ROOT_DIRMETA);
}

#[test]
fn the_walk_gives_the_checksums_of_the_ingest_over_a_rich_tree() {
    agree_over("push-tree-rich", build_rich_source);
}

#[test]
fn a_skipped_directory_leaves_out_its_subtree_as_the_ingest_does() {
    let tmp = TmpDir::new("push-tree-skip");
    let base = tmp.path();
    let src = build_rich_source(base);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let filter: EntryFilter = Box::new(move |path, _meta| {
        record.lock().unwrap().push(path.as_str().to_owned());
        if path.as_str() == "nested" {
            EntryAction::Skip
        } else {
            EntryAction::Keep
        }
    });
    block_on(async {
        let want = ingest(
            base,
            "repo-skip",
            CommitModifierFlags::SKIP_XATTRS,
            Some("/nested"),
        )
        .await;
        assert_eq!(scan(&src, Some(filter)).await, want);
    });
    let seen = seen.lock().unwrap();
    assert!(seen.iter().any(|p| p == "nested"), "{seen:?}");
    assert!(seen.iter().any(|p| p == "setgid/inside"), "{seen:?}");
    assert!(
        !seen.iter().any(|p| p.starts_with("nested/")),
        "the filter saw an entry of the skipped subtree: {seen:?}"
    );
}

// ---------------------------------------------------------------------------
// The tree model as the source of a push.
// ---------------------------------------------------------------------------

/// The ref that each push sets.
const REF: &str = "tree/main";

/// A tree model and a commit over its tree, with a detached metadata dict. The
/// source gives the objects of the tree from the model, and the commit and
/// its detached metadata from its own fields.
struct Committed {
    model: TreeModel,
    commit: Checksum,
    bytes: Vec<u8>,
    detached: Value,
}

impl ObjectSource for Committed {
    fn objects<'a>(
        &'a self,
        _commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya::remote::Result<Vec<ObjectName>>> {
        let mut names = self.model.object_names();
        names.push(ObjectName::new(self.commit, ObjectType::Commit));
        Box::pin(async move { Ok(names) })
    }

    fn open<'a>(
        &'a self,
        name: &'a ObjectName,
        encoding: Encoding,
    ) -> BoxFuture<'a, ostrya::remote::Result<ObjectData>> {
        if name.ty == ObjectType::Commit {
            let reader = Box::new(futures_lite::io::Cursor::new(self.bytes.clone()));
            return Box::pin(async move {
                Ok(ObjectData::Encoded {
                    encoding: Encoding::Raw,
                    reader,
                })
            });
        }
        self.model.open(name, encoding)
    }

    fn detached_metadata<'a>(
        &'a self,
        _commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya::remote::Result<Option<Value>>> {
        Box::pin(async move { Ok(Some(self.detached.clone())) })
    }
}

/// Scans `src` with the canonical filter and builds a commit over its roots,
/// with a detached metadata dict.
fn scan_and_commit(src: &Path) -> Committed {
    let options = ScanOptions {
        entry_filter: Some(canonical()),
        hash_jobs: None,
    };
    let model = block_on(TreeModel::scan(src, options)).unwrap();
    let bytes = ostrya_core::Commit {
        metadata: Value::Array(Vec::new()),
        parent: None,
        related: Vec::new(),
        subject: "tree push".into(),
        body: String::new(),
        timestamp: 1_700_000_000,
        root_dirtree: model.root_dirtree(),
        root_dirmeta: model.root_dirmeta(),
    }
    .serialize()
    .unwrap();
    let mut dict = DictBuilder::new();
    dict.insert_str("xa.pushed-by", "push_tree");
    Committed {
        model,
        commit: Checksum::sha256(&bytes),
        bytes,
        detached: dict.build(),
    }
}

/// Pushes the commit of `source` into `repo`. The push sets `REF` and expects
/// it to be absent.
fn push(
    repo: &Repo,
    source: &Committed,
    compression: Compression,
) -> (
    ostrya::Result<ReceiveReport>,
    ostrya::remote::Result<PushOutcome>,
) {
    let (client, server_in, server_out) = connect();
    let output = client.writer.into_inner();
    let input = client.reader.into_inner();
    let policy = policy_allowing(&["w:**"]);
    let refs = vec![REF.to_string()];
    let commit = source.commit;
    let client = async {
        let session =
            PushSession::over_stream(input, output, &refs, SessionOptions::default()).await?;
        let names = source.objects(&commit).await?;
        let missing = session.missing(&names).await?;
        session
            .send(source, &missing, &[commit], compression)
            .await?;
        let update = RefUpdate {
            name: REF.into(),
            expected: Expected::Absent,
            new: Some(commit),
        };
        session.commit(&[update], false).await
    };
    block_on(zip(repo.receive(server_in, server_out, &policy), client))
}

fn ref_file(repo: &Repo) -> Option<String> {
    std::fs::read_to_string(repo.path().join("refs/heads").join(REF)).ok()
}

const MODES: [RepoMode; 2] = [RepoMode::Archive, RepoMode::BareUser];
const COMPRESSIONS: [Compression; 2] = [Compression::None, Compression::Deflate { level: 6 }];

#[test]
fn a_push_of_the_tree_model_commits_and_sets_its_ref() {
    for mode in MODES {
        for compression in COMPRESSIONS {
            let what = format!("{mode:?}, {compression:?}");
            let tmp = TmpDir::new("push-tree-push");
            let src = build_fixture_source(tmp.path());
            let repo = new_repo(&tmp, mode, "");
            let source = scan_and_commit(&src);
            let commit = source.commit;
            let (report, client) = push(&repo, &source, compression);
            let report = report.unwrap_or_else(|e| panic!("{what}: {e}"));
            let outcome = client.unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(outcome.refs, report.refs, "{what}");
            assert_eq!(outcome.refs[0].new, Some(commit), "{what}");
            assert_eq!(ref_file(&repo), Some(format!("{commit}\n")), "{what}");

            // The server holds each object the source named, and no other.
            let reopened = block_on(Repo::open(repo.path())).unwrap();
            let stored = block_on(reopened.traverse_commit(&commit, 0)).unwrap();
            let named: HashSet<_> = block_on(source.objects(&commit))
                .unwrap()
                .into_iter()
                .collect();
            assert_eq!(stored.into_iter().collect::<HashSet<_>>(), named, "{what}");
            assert_eq!(outcome.stats.objects_sent, named.len() as u64, "{what}");
            let meta = repo.path().join("objects").join(ostrya::loose_path(
                &commit,
                ObjectType::CommitMeta,
                mode,
            ));
            assert!(meta.exists(), "{what}: the detached metadata is stored");
            let fsck = block_on(reopened.fsck(&FsckOptions::default())).unwrap();
            assert!(fsck.is_ok(), "{what}: {fsck:?}");
        }
    }
}

/// Scans the fixture tree, runs `change` on its file `hello.txt`, and pushes.
/// Checks that the ref is still absent. Returns the server error and the
/// client error.
fn push_after_change(
    tag: &str,
    mode: RepoMode,
    compression: Compression,
    change: impl FnOnce(&Path),
) -> (ostrya::Error, Error) {
    let what = format!("{tag}, {mode:?}, {compression:?}");
    let tmp = TmpDir::new(tag);
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, mode, "");
    let source = scan_and_commit(&src);
    change(&src.join("hello.txt"));
    let (report, client) = push(&repo, &source, compression);
    assert_eq!(ref_file(&repo), None, "{what}: a ref changed");
    let server = match report {
        Err(e) => e,
        Ok(report) => panic!("{what}: the session succeeded: {report:?}"),
    };
    match client {
        Err(e) => (server, e),
        Ok(outcome) => panic!("{what}: the push succeeded: {outcome:?}"),
    }
}

#[test]
fn a_file_changed_at_the_same_length_fails_with_checksum_mismatch() {
    for mode in MODES {
        for compression in COMPRESSIONS {
            let (server, e) =
                push_after_change("push-tree-same-length", mode, compression, |file| {
                    // The write truncates the file in place, so the inode stays.
                    std::fs::write(file, b"HELLO OSTREE\n").unwrap();
                });
            assert!(
                matches!(
                    server,
                    ostrya::Error::Remote(ostrya::remote::Error::ChecksumMismatch(_))
                ),
                "{mode:?}, {compression:?}: server {server:?}"
            );
            assert!(
                matches!(e, Error::ChecksumMismatch(_)),
                "{mode:?}, {compression:?}: {e:?}"
            );
        }
    }
}

#[test]
fn a_file_that_grew_fails_with_protocol_in_deflate_and_checksum_mismatch_in_raw() {
    let grow = |file: &Path| std::fs::write(file, b"hello ostree\nand more\n").unwrap();
    for mode in MODES {
        let (server, e) = push_after_change(
            "push-tree-grew",
            mode,
            Compression::Deflate { level: 6 },
            grow,
        );
        assert!(
            matches!(
                server,
                ostrya::Error::Remote(ostrya::remote::Error::Protocol(_))
            ),
            "{mode:?}, deflate: server {server:?}"
        );
        assert!(matches!(e, Error::Protocol(_)), "{mode:?}, deflate: {e:?}");
        let (server, e) = push_after_change("push-tree-grew", mode, Compression::None, grow);
        assert!(
            matches!(
                server,
                ostrya::Error::Remote(ostrya::remote::Error::ChecksumMismatch(_))
            ),
            "{mode:?}, raw: server {server:?}"
        );
        assert!(
            matches!(e, Error::ChecksumMismatch(_)),
            "{mode:?}, raw: {e:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The tree push.
// ---------------------------------------------------------------------------

const SUBJECT: &str = "tree push";
const BODY: &str = "the body";
const TIMESTAMP: u64 = 1_700_000_000;

fn string(s: &str) -> Value {
    Value::variant(Type::Str, Value::Str(s.to_owned()))
}

/// The metadata entries of the caller in the tests that pass some.
fn caller_entries() -> Vec<(String, Value)> {
    vec![
        ("version".to_owned(), string("1.0")),
        ("xa.note".to_owned(), string("note")),
    ]
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// The options of a tree push onto `branch` with the canonical filter, the
/// subject, the body, and the timestamp of these tests.
fn tree_options(branch: &str) -> TreePushOptions {
    TreePushOptions {
        onto: branch.into(),
        subject: Some(SUBJECT.into()),
        body: Some(BODY.into()),
        timestamp: Some(TIMESTAMP),
        entry_filter: Some(canonical()),
        ..Default::default()
    }
}

/// A hook that runs once.
type Hook = Box<dyn FnOnce() + Send>;

/// The input stream of the client, which runs a hook at its first read. The
/// first read of the push comes after the scan and `Hello`.
struct FirstRead {
    inner: PipeReader,
    hook: Option<Hook>,
}

impl AsyncRead for FirstRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(hook) = self.hook.take() {
            hook();
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// The policy of the tree pushes: a server commit on each ref, and a tag on
/// each ref.
fn server_commit_policy() -> ReceivePolicy {
    policy_allowing(&["c:**", "t:**"])
}

/// One tree push of `src` into `repo` under `policy` over two in-process
/// pipes, with `hook` at the first read of the client.
fn tree_push_under(
    repo: &Repo,
    policy: &ReceivePolicy,
    src: &Path,
    opts: TreePushOptions,
    hook: Option<Hook>,
) -> (
    ostrya::Result<ReceiveReport>,
    ostrya::remote::Result<PushOutcome>,
) {
    let (client, server_in, server_out) = connect();
    let output = client.writer.into_inner();
    let input = FirstRead {
        inner: client.reader.into_inner(),
        hook,
    };
    block_on(zip(
        repo.receive(server_in, server_out, policy),
        push_tree_over_stream(input, output, src, opts),
    ))
}

/// [`tree_push_under`] with [`server_commit_policy`].
fn tree_push(
    repo: &Repo,
    src: &Path,
    opts: TreePushOptions,
    hook: Option<Hook>,
) -> (
    ostrya::Result<ReceiveReport>,
    ostrya::remote::Result<PushOutcome>,
) {
    tree_push_under(repo, &server_commit_policy(), src, opts, hook)
}

/// Runs a tree push under `policy` that must succeed. Checks the outcome
/// against the report of the server. Returns the commit and the outcome.
fn pushed_under(
    repo: &Repo,
    policy: &ReceivePolicy,
    src: &Path,
    opts: TreePushOptions,
    what: &str,
) -> (Checksum, PushOutcome) {
    let (report, client) = tree_push_under(repo, policy, src, opts, None);
    let report = report.unwrap_or_else(|e| panic!("{what}: {e}"));
    let outcome = client.unwrap_or_else(|e| panic!("{what}: {e}"));
    assert_eq!(outcome.refs, report.refs, "{what}");
    let commit = outcome.commit.expect("the server names its commit");
    for r in &outcome.refs {
        assert_eq!(r.new, Some(commit), "{what}");
    }
    (commit, outcome)
}

/// [`pushed_under`] with [`server_commit_policy`].
fn pushed(repo: &Repo, src: &Path, opts: TreePushOptions, what: &str) -> (Checksum, PushOutcome) {
    pushed_under(repo, &server_commit_policy(), src, opts, what)
}

fn named_ref(repo: &Repo, name: &str) -> Option<String> {
    std::fs::read_to_string(repo.path().join("refs/heads").join(name)).ok()
}

/// Writes a commit with `Transaction::write_commit` and returns its checksum.
/// The commit holds `base/src`, ingested with canonical permissions and no
/// extended attributes into the new archive repository `base/<repo>`. The
/// commit has `parent`, `metadata`, and the subject, the body, and the
/// timestamp of these tests.
async fn local_commit(
    base: &Path,
    repo: &str,
    parent: Option<Checksum>,
    metadata: Value,
) -> Checksum {
    let repo = Repo::create(&base.join(repo), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let dfd = std::fs::File::open(base).unwrap();
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::SKIP_XATTRS | CommitModifierFlags::CANONICAL_PERMISSIONS,
    );
    let mut mtree = MutableTree::new();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new("src"),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let opts = CommitOptions {
        parent,
        subject: Some(SUBJECT.into()),
        body: Some(BODY.into()),
        timestamp: Some(TIMESTAMP),
        metadata: Some(metadata),
        related: Vec::new(),
    };
    let commit = txn.write_commit(opts, &root).await.unwrap();
    txn.commit().await.unwrap();
    commit
}

/// The commit of the server is the commit of `write_commit` with the tip of
/// the branch as its parent, the entries of the caller, and then the
/// bindings of the namespace: the branch, the tags, and the bound names, and
/// the collection.
#[test]
fn the_commit_of_a_tree_push_is_the_commit_that_write_commit_writes() {
    let tmp = TmpDir::new("push-tree-checksum");
    let base = tmp.path();
    let src = build_rich_source(base);
    let local = |repo: &str, parent: Option<Checksum>, metadata: Value| {
        block_on(local_commit(base, repo, parent, metadata))
    };

    // One branch with entries of the caller, on a server with no collection
    // id.
    let plain = new_repo(&tmp, RepoMode::Archive, "");
    let (first, _) = pushed(
        &plain,
        &src,
        TreePushOptions {
            metadata: caller_entries(),
            ..tree_options(REF)
        },
        "one branch",
    );
    let want = local(
        "local-one",
        None,
        commit_metadata(caller_entries(), Some(&[REF]), None),
    );
    assert_eq!(first, want, "one branch");
    assert_eq!(named_ref(&plain, REF), Some(format!("{first}\n")));

    // The current tip of the branch is the parent.
    let (second, outcome) = pushed(
        &plain,
        &src,
        TreePushOptions {
            metadata: caller_entries(),
            ..tree_options(REF)
        },
        "current tip",
    );
    assert_eq!(outcome.refs[0].old, Some(first));
    let want = local(
        "local-tip",
        Some(first),
        commit_metadata(caller_entries(), Some(&[REF]), None),
    );
    assert_eq!(second, want, "current tip");

    // Tags and bound names join the ref binding, a bound name twice. Each tag
    // takes the commit, and a bound name gets no ref.
    let (tagged, _) = pushed(
        &plain,
        &src,
        TreePushOptions {
            tags: strings(&["tree/t2", "tree/t1"]),
            bind_refs: strings(&["tree/bound", "tree/bound"]),
            ..tree_options("tree/other")
        },
        "tags",
    );
    let bound = [
        "tree/other",
        "tree/t2",
        "tree/t1",
        "tree/bound",
        "tree/bound",
    ];
    let want = local(
        "local-tags",
        None,
        commit_metadata(Vec::new(), Some(&bound), None),
    );
    assert_eq!(tagged, want, "tags");
    for name in ["tree/t1", "tree/t2"] {
        assert_eq!(
            named_ref(&plain, name),
            Some(format!("{tagged}\n")),
            "{name}"
        );
    }
    assert_eq!(named_ref(&plain, "tree/bound"), None);

    // `orphan` on a branch that exists needs `d`, and makes a root commit.
    let (report, client) = tree_push(
        &plain,
        &src,
        TreePushOptions {
            orphan: true,
            ..tree_options(REF)
        },
        None,
    );
    assert!(
        matches!(client, Err(Error::NonFastForward(_))),
        "{client:?}"
    );
    assert!(report.is_err(), "{report:?}");
    assert_eq!(named_ref(&plain, REF), Some(format!("{second}\n")));
    let (orphan, _) = pushed_under(
        &plain,
        &policy_allowing(&["cd:**"]),
        &src,
        TreePushOptions {
            orphan: true,
            ..tree_options(REF)
        },
        "orphan",
    );
    let want = local(
        "local-orphan",
        None,
        commit_metadata(Vec::new(), Some(&[REF]), None),
    );
    assert_eq!(orphan, want, "orphan");

    // A server with a collection id binds the commit to it.
    let tmp_c = TmpDir::new("push-tree-checksum-collection");
    let collection = new_repo(&tmp_c, RepoMode::Archive, "collection-id=org.example.C\n");
    let (own, _) = pushed(
        &collection,
        &src,
        TreePushOptions {
            metadata: caller_entries(),
            ..tree_options(REF)
        },
        "own collection",
    );
    let want = local(
        "local-own",
        None,
        commit_metadata(caller_entries(), Some(&[REF]), Some("org.example.C")),
    );
    assert_eq!(own, want, "own collection");

    // The namespace of another collection binds the commit to it, and the
    // server writes its refs under `refs/mirrors/`.
    let (mirrored, _) = pushed_under(
        &collection,
        &collections_policy(&["c:**"]),
        &src,
        TreePushOptions {
            collection: Some("org.example.Other".into()),
            ..tree_options(REF)
        },
        "other collection",
    );
    let want = local(
        "local-other",
        None,
        commit_metadata(Vec::new(), Some(&[REF]), Some("org.example.Other")),
    );
    assert_eq!(mirrored, want, "other collection");
    let mirror = collection
        .path()
        .join("refs/mirrors/org.example.Other")
        .join(REF);
    assert_eq!(
        std::fs::read_to_string(mirror).ok(),
        Some(format!("{mirrored}\n"))
    );
    assert_eq!(named_ref(&collection, REF), Some(format!("{own}\n")));
}

/// The push sends each object of the tree and no commit object. The server
/// moves the branch and creates the tag. With no signing key, the server
/// stores no detached metadata.
#[test]
fn a_tree_push_sends_the_tree_and_the_server_sets_its_refs() {
    for mode in MODES {
        for compression in COMPRESSIONS {
            let what = format!("{mode:?}, {compression:?}");
            let tmp = TmpDir::new("push-tree-tree-push");
            let src = build_rich_source(tmp.path());
            let repo = new_repo(&tmp, mode, "");
            let (commit, outcome) = pushed(
                &repo,
                &src,
                TreePushOptions {
                    compression,
                    tags: strings(&["tree/tag"]),
                    ..tree_options("tree/one")
                },
                &what,
            );
            let names: Vec<&str> = outcome.refs.iter().map(|r| r.name.as_str()).collect();
            assert_eq!(names, ["tree/one", "tree/tag"], "{what}");
            for name in ["tree/one", "tree/tag"] {
                assert_eq!(
                    named_ref(&repo, name),
                    Some(format!("{commit}\n")),
                    "{what}"
                );
            }
            let reopened = block_on(Repo::open(repo.path())).unwrap();
            let stored = block_on(reopened.traverse_commit(&commit, 0)).unwrap();
            let stats = outcome.stats;
            // The stored objects hold the commit, which the push did not send.
            assert_eq!(stats.objects_total + 1, stored.len() as u64, "{what}");
            assert_eq!(stats.objects_needed, stats.objects_total, "{what}");
            assert_eq!(stats.objects_sent, stats.objects_total, "{what}");
            let meta = repo.path().join("objects").join(ostrya::loose_path(
                &commit,
                ObjectType::CommitMeta,
                mode,
            ));
            assert!(!meta.exists(), "{what}: detached metadata is stored");
            let fsck = block_on(reopened.fsck(&FsckOptions::default())).unwrap();
            assert!(fsck.is_ok(), "{what}: {fsck:?}");
        }
    }
}

#[test]
fn a_second_tree_push_sends_no_object() {
    let tmp = TmpDir::new("push-tree-second");
    let src = build_rich_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (first, _) = pushed(&repo, &src, tree_options(REF), "first");
    let (second, outcome) = pushed(&repo, &src, tree_options(REF), "second");
    assert_ne!(second, first);
    assert_eq!(outcome.refs[0].old, Some(first));
    assert_eq!(outcome.stats.objects_needed, 0, "{:?}", outcome.stats);
    assert_eq!(outcome.stats.objects_sent, 0, "{:?}", outcome.stats);
    let (commit, _) = block_on(repo.load_commit(&second)).unwrap();
    assert_eq!(commit.parent, Some(first));
    assert_eq!(named_ref(&repo, REF), Some(format!("{second}\n")));
}

/// The server commit of a tree push has an empty field 2, also onto a tip
/// whose field 2 names a dependency.
#[test]
fn the_server_commit_of_a_tree_push_names_no_dependency() {
    let tmp = TmpDir::new("push-tree-no-dependency");
    let src = build_rich_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (first, _) = pushed(&repo, &src, tree_options(REF), "first");
    let named = block_on(async {
        let named =
            common::store_with_field2(&repo, &first, &[("boot/first", first.as_bytes())]).await;
        let txn = repo.transaction().await.unwrap();
        txn.set_ref(REF, Some(&named));
        txn.commit().await.unwrap();
        named
    });
    assert_eq!(
        block_on(repo.read_commit_related(&named))
            .unwrap()
            .dependencies,
        [("boot/first".to_owned(), first)]
    );

    let (second, _) = pushed(&repo, &src, tree_options(REF), "second");

    let (commit, _) = block_on(repo.load_commit(&second)).unwrap();
    assert_eq!(commit.parent, Some(named));
    assert!(commit.related.is_empty(), "{:?}", commit.related);
}

/// With no timestamp, the server takes its clock.
#[test]
fn a_tree_push_with_no_timestamp_takes_the_clock_of_the_server() {
    let tmp = TmpDir::new("push-tree-clock");
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let before = now();
    let (commit, _) = pushed(
        &repo,
        &src,
        TreePushOptions {
            timestamp: None,
            ..tree_options(REF)
        },
        "clock",
    );
    let after = now();
    let (commit, _) = block_on(repo.load_commit(&commit)).unwrap();
    assert!(
        (before..=after).contains(&commit.timestamp),
        "{} is not in {before}..={after}",
        commit.timestamp
    );
}

/// The push refuses a tag of 64 lowercase hex characters before the scan,
/// because a revision reads it as a commit checksum. The server writes no
/// ref and no object.
#[test]
fn a_tag_of_64_lowercase_hex_characters_is_refused() {
    let tmp = TmpDir::new("push-tree-hex-ref");
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = object_files(&repo);
    let hex = "a".repeat(64);
    let (report, client) = tree_push(
        &repo,
        &src,
        TreePushOptions {
            tags: strings(&[&hex]),
            ..tree_options("main")
        },
        None,
    );
    match client {
        Err(Error::InvalidInput(m)) => assert!(m.contains(&hex), "{m}"),
        other => panic!("{other:?}"),
    }
    assert!(report.is_err(), "server {report:?}");
    assert_eq!(object_files(&repo), before, "the store changed");
    assert_eq!(named_ref(&repo, &hex), None);
    assert_eq!(named_ref(&repo, "main"), None);
}

#[test]
fn a_file_changed_at_the_same_length_after_the_scan_fails_the_tree_push() {
    for mode in MODES {
        for compression in COMPRESSIONS {
            let what = format!("{mode:?}, {compression:?}");
            let tmp = TmpDir::new("push-tree-tree-same-length");
            let src = build_fixture_source(tmp.path());
            let repo = new_repo(&tmp, mode, "");
            let file = src.join("hello.txt");
            // The write truncates the file in place, so the inode stays.
            let change: Hook = Box::new(move || std::fs::write(file, b"HELLO OSTREE\n").unwrap());
            let (report, client) = tree_push(
                &repo,
                &src,
                TreePushOptions {
                    compression,
                    ..tree_options(REF)
                },
                Some(change),
            );
            assert_eq!(ref_file(&repo), None, "{what}: a ref changed");
            assert!(
                matches!(
                    report,
                    Err(ostrya::Error::Remote(
                        ostrya::remote::Error::ChecksumMismatch(_)
                    ))
                ),
                "{what}: server {report:?}"
            );
            assert!(
                matches!(client, Err(Error::ChecksumMismatch(_))),
                "{what}: {client:?}"
            );
        }
    }
}

/// The object files of the store of `repo`.
fn object_files(repo: &Repo) -> HashSet<PathBuf> {
    fn walk(dir: &Path, out: &mut HashSet<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                walk(&path, out);
            } else {
                out.insert(path);
            }
        }
    }
    let mut out = HashSet::new();
    walk(&repo.path().join("objects"), &mut out);
    out
}

/// Runs a tree push that the client refuses after `HelloReply`, and checks
/// that the push offered no object and the server stored none. Returns the
/// error of the client.
fn refused_before_any_upload(repo: &Repo, src: &Path, opts: TreePushOptions, what: &str) -> Error {
    let before = object_files(repo);
    let progress = PushProgress::new();
    let (report, client) = tree_push(
        repo,
        src,
        TreePushOptions {
            progress: Some(progress.clone()),
            ..opts
        },
        None,
    );
    assert!(
        matches!(
            report,
            Err(ostrya::Error::Remote(ostrya::remote::Error::Aborted))
        ),
        "{what}: server {report:?}"
    );
    let snapshot = progress.snapshot();
    assert_eq!(snapshot.objects_total, 0, "{what}: {snapshot:?}");
    assert_eq!(snapshot.objects_sent, 0, "{what}: {snapshot:?}");
    assert_eq!(object_files(repo), before, "{what}: the store changed");
    client.expect_err(what)
}

#[test]
fn an_existing_tag_is_refused_before_any_upload() {
    let tmp = TmpDir::new("push-tree-existing-tag");
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (tip, _) = pushed(&repo, &src, tree_options("tree/a"), "first");
    // A new file gives the tree objects that the server does not hold.
    std::fs::write(src.join("new.txt"), b"new\n").unwrap();
    let opts = TreePushOptions {
        tags: strings(&["tree/a"]),
        ..tree_options("tree/b")
    };
    match refused_before_any_upload(&repo, &src, opts, "tag") {
        Error::RefMismatch { name, current, .. } => {
            assert_eq!(name, "tree/a");
            assert_eq!(current, Some(tip));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(named_ref(&repo, "tree/a"), Some(format!("{tip}\n")));
    assert_eq!(named_ref(&repo, "tree/b"), None);
}

/// A server commit whose `Commit` frame is over the `max-frame` of the
/// server is refused before any upload.
#[test]
fn a_server_commit_over_the_frame_limit_is_refused_before_any_upload() {
    let tmp = TmpDir::new("push-tree-frame");
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let big = Value::variant(
        Type::parse("ay").unwrap(),
        Value::Bytes(vec![7; ostrya::remote::proto::MAX_FRAME as usize]),
    );
    let opts = TreePushOptions {
        metadata: vec![("xa.big".into(), big)],
        ..tree_options(REF)
    };
    match refused_before_any_upload(&repo, &src, opts, "frame") {
        Error::LimitExceeded(m) => assert!(m.contains("over the limit"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(named_ref(&repo, REF), None);
}

/// Returns a variant that holds `levels` nested arrays around one `i`.
fn nested_arrays(levels: usize) -> Value {
    let ty = Type::parse(&format!("{}i", "a".repeat(levels))).unwrap();
    let value = (0..levels).fold(Value::I32(1), |inner, _| Value::Array(vec![inner]));
    Value::variant(ty, value)
}

/// A metadata value that a `v` holds and a commit does not hold is refused
/// before any upload. A value two levels less deep is committed.
#[test]
fn a_metadata_value_too_deep_for_a_commit_is_refused_before_any_upload() {
    let tmp = TmpDir::new("push-tree-deep");
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let opts = TreePushOptions {
        metadata: vec![("xa.deep".into(), nested_arrays(126))],
        ..tree_options(REF)
    };
    match refused_before_any_upload(&repo, &src, opts, "deep") {
        Error::InvalidInput(m) => assert!(m.contains("'xa.deep'"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(named_ref(&repo, REF), None);

    let opts = TreePushOptions {
        metadata: vec![("xa.deep".into(), nested_arrays(125))],
        ..tree_options(REF)
    };
    pushed(&repo, &src, opts, "125 levels");
}

/// A server commit whose longest `CommitReply` is over the frame limit of
/// the server is refused before any upload, also when its `Commit` frame
/// fits.
#[test]
fn a_server_commit_whose_reply_is_over_the_frame_limit_is_refused_before_any_upload() {
    let tmp = TmpDir::new("push-tree-reply");
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    // A tag of 6 bytes costs 11 bytes in `Commit`, 45 in `HelloReply` with
    // a commit, and 46 in `CommitReply`. With 23,000 tags, `HelloReply` fits
    // in 1 MiB and `CommitReply` does not.
    let tags: Vec<String> = (0..23_000).map(|i| format!("t{i:05}")).collect();
    let opts = TreePushOptions {
        tags,
        ..tree_options(REF)
    };
    match refused_before_any_upload(&repo, &src, opts, "reply") {
        Error::LimitExceeded(m) => assert!(m.contains("reply"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(named_ref(&repo, REF), None);
}

/// A client group with no `c` on the branch gets `ref-denied`, and the
/// branch does not change.
#[test]
fn a_tree_push_needs_c_on_the_branch() {
    let tmp = TmpDir::new("push-tree-denied");
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (report, client) = tree_push_under(
        &repo,
        &policy_allowing(&["w:**"]),
        &src,
        tree_options(REF),
        None,
    );
    assert!(matches!(client, Err(Error::RefDenied(_))), "{client:?}");
    assert!(report.is_err(), "{report:?}");
    assert_eq!(named_ref(&repo, REF), None);
}

/// At the end of a tree push, the count of content bytes equals the byte
/// total of its model, with raw and with deflated objects.
#[test]
fn the_content_bytes_of_a_tree_push_end_at_the_byte_total() {
    for (tag, compression) in [
        ("raw", Compression::None),
        ("deflate", Compression::Deflate { level: 6 }),
    ] {
        let tmp = TmpDir::new(&format!("push-tree-total-{tag}"));
        let src = build_rich_source(tmp.path());
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let progress = PushProgress::new();
        let opts = TreePushOptions {
            progress: Some(progress.clone()),
            compression,
            ..tree_options(REF)
        };
        pushed(&repo, &src, opts, tag);
        let snapshot = progress.snapshot();
        assert_eq!(snapshot.content_bytes, snapshot.bytes_total, "{tag}");
        assert!(snapshot.bytes_total > 200 * 1024, "{tag}: {snapshot:?}");
    }
}

#[test]
fn the_progress_handle_shows_the_scan_and_then_the_session() {
    let tmp = TmpDir::new("push-tree-progress");
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let progress = PushProgress::new();
    let first = TreePushOptions {
        progress: Some(progress.clone()),
        ..tree_options(REF)
    };
    pushed(&repo, &src, first, "first");
    assert_eq!(progress.snapshot().phase, PushPhase::Committing);

    // The handle holds the last phase of the first push. The second push
    // sets the phases of its scan again.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = (seen.clone(), progress.clone());
    let mut keep = canonical();
    let filter: EntryFilter = Box::new(move |path, meta| {
        record.0.lock().unwrap().push(record.1.snapshot().phase);
        keep(path, meta)
    });
    let at_read = Arc::new(Mutex::new(None));
    let hook: Hook = {
        let (at_read, progress) = (at_read.clone(), progress.clone());
        Box::new(move || *at_read.lock().unwrap() = Some(progress.snapshot().phase))
    };
    let second = TreePushOptions {
        progress: Some(progress.clone()),
        entry_filter: Some(filter),
        ..tree_options(REF)
    };
    let (report, client) = tree_push(&repo, &src, second, Some(hook));
    report.unwrap();
    client.unwrap();
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|p| *p == PushPhase::Scanning), "{seen:?}");
    assert_eq!(*at_read.lock().unwrap(), Some(PushPhase::Connecting));
    assert_eq!(progress.snapshot().phase, PushPhase::Committing);
}
