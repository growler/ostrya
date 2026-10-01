//! The tree walk of `ostrya::push::tree` against the ingest of
//! `write_dfd_to_mtree`: the root checksums of the two agree over the same
//! tree, with extended attributes skipped, with and without canonical
//! permissions, and with a skipped directory. The tree model as the object
//! source of a push to `Repo::receive` over two in-process pipes. The tree
//! push of `push_tree_over_stream` to `Repo::receive`: its commit against
//! `Transaction::write_commit`, the refs it sets, the objects it sends, the
//! refusal of mixed ref states, its signatures, and its progress phases.

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

use common::receive::{PipeReader, connect, new_repo};
use common::{ROOT_DIRMETA, ROOT_DIRTREE, TmpDir};
use futures_io::AsyncRead;
use futures_lite::future::zip;
use ostrya::push::tree::{EntryAction, EntryFilter, EntryKind, ScanOptions, TreeModel};
use ostrya::push::{
    Compression, Error, Expected, ObjectSource, ParentPolicy, PushOutcome, PushPhase, PushProgress,
    PushSession, RefUpdate, SessionOptions, TreePushOptions, push_tree_over_stream,
};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DictBuilder,
    DummySigner, Ed25519Signer, Ed25519Verifier, FilterResult, FsckOptions, MutableTree,
    ObjectType, ReceivePolicy, ReceiveReport, Repo, RepoMode, Signer, Type, Value,
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

/// A tree with nested and empty directories, a setgid directory, files at
/// several modes, an empty file, a file over three hash chunks, duplicate
/// content, a hard link, a symlink to a directory, and names whose listing
/// order differs from their byte order, under `base/src`.
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

/// A filter that gives each entry the canonical permissions: owner 0:0, and
/// the permission bits masked with 0755 for a regular file and a directory.
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

/// The walk and the ingest agree over the tree `build` makes, with no filter
/// against `SKIP_XATTRS`, and with the canonical filter against
/// `SKIP_XATTRS | CANONICAL_PERMISSIONS`. Gives the canonical checksums.
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

/// The ref each push sets.
const REF: &str = "tree/main";

/// Scan `src` with the canonical filter, and give the model a commit over its
/// roots with a detached dict. Gives the model and the commit checksum.
fn scan_and_commit(src: &Path) -> (TreeModel, Checksum) {
    let options = ScanOptions {
        entry_filter: Some(canonical()),
        hash_jobs: None,
    };
    let mut model = block_on(TreeModel::scan(src, options)).unwrap();
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
    let commit = Checksum::sha256(&bytes);
    let mut dict = DictBuilder::new();
    dict.insert_str("xa.pushed-by", "push_tree");
    model.set_commit(commit, bytes, Some(dict.build()));
    (model, commit)
}

/// One push of `commit` from `model` into `repo`, which sets `REF` from
/// absent.
fn push(
    repo: &Repo,
    model: &TreeModel,
    commit: Checksum,
    compression: Compression,
) -> (
    ostrya::Result<ReceiveReport>,
    ostrya::push::Result<PushOutcome>,
) {
    let (client, server_in, server_out) = connect();
    let output = client.writer.into_inner();
    let input = client.reader.into_inner();
    let policy = ReceivePolicy::default();
    let refs = vec![REF.to_string()];
    let client = async {
        let session =
            PushSession::over_stream(input, output, &refs, SessionOptions::default()).await?;
        let names = model.objects(&commit).await?;
        let missing = session.missing(&names).await?;
        session
            .send(model, &missing, &[commit], compression)
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
            let (model, commit) = scan_and_commit(&src);
            let (report, client) = push(&repo, &model, commit, compression);
            let report = report.unwrap_or_else(|e| panic!("{what}: {e}"));
            let outcome = client.unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(outcome.refs, report.refs, "{what}");
            assert_eq!(outcome.refs[0].new, Some(commit), "{what}");
            assert_eq!(ref_file(&repo), Some(format!("{commit}\n")), "{what}");

            // The server holds each object the model named, and no other.
            let reopened = block_on(Repo::open(repo.path())).unwrap();
            let stored = block_on(reopened.traverse_commit(&commit, 0)).unwrap();
            let named: HashSet<_> = block_on(model.objects(&commit))
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

/// Scan the fixture tree, run `change` on its file `hello.txt`, and push.
/// Gives the server error and the client error, after it checks that the
/// ref stayed absent.
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
    let (model, commit) = scan_and_commit(&src);
    change(&src.join("hello.txt"));
    let (report, client) = push(&repo, &model, commit, compression);
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
                    ostrya::Error::Push(ostrya::push::Error::ChecksumMismatch(_))
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
                ostrya::Error::Push(ostrya::push::Error::Protocol(_))
            ),
            "{mode:?}, deflate: server {server:?}"
        );
        assert!(matches!(e, Error::Protocol(_)), "{mode:?}, deflate: {e:?}");
        let (server, e) = push_after_change("push-tree-grew", mode, Compression::None, grow);
        assert!(
            matches!(
                server,
                ostrya::Error::Push(ostrya::push::Error::ChecksumMismatch(_))
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

/// The base64 of a 64-byte ed25519 secret key (seed, then public key).
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";

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

/// The options of a tree push of `refs` with the canonical filter, the
/// subject, the body, and the timestamp of these tests.
fn tree_options(refs: &[&str]) -> TreePushOptions {
    TreePushOptions {
        refs: refs.iter().map(|r| r.to_string()).collect(),
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
/// push reads first after the scan and `Hello`.
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

/// One tree push of `src` into `repo` over two in-process pipes, with `hook`
/// at the first read of the client.
fn tree_push(
    repo: &Repo,
    src: &Path,
    opts: TreePushOptions,
    hook: Option<Hook>,
) -> (
    ostrya::Result<ReceiveReport>,
    ostrya::push::Result<PushOutcome>,
) {
    let (client, server_in, server_out) = connect();
    let output = client.writer.into_inner();
    let input = FirstRead {
        inner: client.reader.into_inner(),
        hook,
    };
    let policy = ReceivePolicy::default();
    block_on(zip(
        repo.receive(server_in, server_out, &policy),
        push_tree_over_stream(input, output, src, opts),
    ))
}

/// A tree push that succeeds. Gives the commit, after it checks the outcome
/// against the report of the server.
fn pushed(repo: &Repo, src: &Path, opts: TreePushOptions, what: &str) -> (Checksum, PushOutcome) {
    let (report, client) = tree_push(repo, src, opts, None);
    let report = report.unwrap_or_else(|e| panic!("{what}: {e}"));
    let outcome = client.unwrap_or_else(|e| panic!("{what}: {e}"));
    assert_eq!(outcome.refs, report.refs, "{what}");
    let commit = outcome.commit.expect("a tree push builds a commit");
    for r in &outcome.refs {
        assert_eq!(r.new, Some(commit), "{what}");
    }
    (commit, outcome)
}

fn named_ref(repo: &Repo, name: &str) -> Option<String> {
    std::fs::read_to_string(repo.path().join("refs/heads").join(name)).ok()
}

/// The commit `Transaction::write_commit` writes over `base/src`, ingested
/// with canonical permissions and no extended attributes into the new
/// archive repository `base/<repo>`, with `parent`, `metadata`, and the
/// subject, the body, and the timestamp of these tests.
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
    };
    let commit = txn.write_commit(opts, &root).await.unwrap();
    txn.commit().await.unwrap();
    commit
}

#[test]
fn the_commit_of_a_tree_push_is_the_commit_that_write_commit_writes() {
    let tmp = TmpDir::new("push-tree-checksum");
    let base = tmp.path();
    let src = build_rich_source(base);
    let local = |repo: &str, parent: Option<Checksum>, metadata: Value| {
        block_on(local_commit(base, repo, parent, metadata))
    };

    // One ref with entries of the caller, on a server with no collection id.
    let plain = new_repo(&tmp, RepoMode::Archive, "");
    let (first, _) = pushed(
        &plain,
        &src,
        TreePushOptions {
            metadata: caller_entries(),
            ..tree_options(&[REF])
        },
        "one ref",
    );
    let want = local(
        "local-one",
        None,
        commit_metadata(caller_entries(), Some(&[REF]), None),
    );
    assert_eq!(first, want, "one ref");
    assert_eq!(named_ref(&plain, REF), Some(format!("{first}\n")));

    // The current tip of the first ref is the parent.
    let (second, _) = pushed(
        &plain,
        &src,
        TreePushOptions {
            metadata: caller_entries(),
            ..tree_options(&[REF])
        },
        "current tip",
    );
    let want = local(
        "local-tip",
        Some(first),
        commit_metadata(caller_entries(), Some(&[REF]), None),
    );
    assert_eq!(second, want, "current tip");

    // A given parent, for a ref that the server does not hold.
    let (given, _) = pushed(
        &plain,
        &src,
        TreePushOptions {
            parent: ParentPolicy::Commit(first),
            ..tree_options(&["tree/other"])
        },
        "given parent",
    );
    let want = local(
        "local-given",
        Some(first),
        commit_metadata(Vec::new(), Some(&["tree/other"]), None),
    );
    assert_eq!(given, want, "given parent");

    // Two refs, out of order, on a server with a collection id.
    let tmp_c = TmpDir::new("push-tree-checksum-collection");
    let collection = new_repo(&tmp_c, RepoMode::Archive, "collection-id=org.example.C\n");
    let refs = ["tree/b", "tree/a"];
    let (bound, _) = pushed(
        &collection,
        &src,
        TreePushOptions {
            metadata: caller_entries(),
            ..tree_options(&refs)
        },
        "two refs",
    );
    let want = local(
        "local-two",
        None,
        commit_metadata(caller_entries(), Some(&refs), Some("org.example.C")),
    );
    assert_eq!(bound, want, "two refs");

    // No bindings, on the same server.
    let (unbound, _) = pushed(
        &collection,
        &src,
        TreePushOptions {
            metadata: caller_entries(),
            no_bindings: true,
            ..tree_options(&["tree/unbound"])
        },
        "no bindings",
    );
    let want = local(
        "local-unbound",
        None,
        commit_metadata(caller_entries(), None, None),
    );
    assert_eq!(unbound, want, "no bindings");
}

#[test]
fn a_tree_push_commits_and_sets_its_refs() {
    for mode in MODES {
        for compression in COMPRESSIONS {
            let what = format!("{mode:?}, {compression:?}");
            let tmp = TmpDir::new("push-tree-tree-push");
            let src = build_rich_source(tmp.path());
            let repo = new_repo(&tmp, mode, "");
            let refs = ["tree/one", "tree/two"];
            let (commit, outcome) = pushed(
                &repo,
                &src,
                TreePushOptions {
                    compression,
                    ..tree_options(&refs)
                },
                &what,
            );
            for name in refs {
                assert_eq!(
                    named_ref(&repo, name),
                    Some(format!("{commit}\n")),
                    "{what}"
                );
            }
            let reopened = block_on(Repo::open(repo.path())).unwrap();
            let stored = block_on(reopened.traverse_commit(&commit, 0)).unwrap();
            let stats = outcome.stats;
            assert_eq!(stats.objects_total, stored.len() as u64, "{what}");
            assert_eq!(stats.objects_needed, stats.objects_total, "{what}");
            assert_eq!(stats.objects_sent, stats.objects_total, "{what}");
            let fsck = block_on(reopened.fsck(&FsckOptions::default())).unwrap();
            assert!(fsck.is_ok(), "{what}: {fsck:?}");
        }
    }
}

#[test]
fn a_second_tree_push_sends_only_the_commit() {
    let tmp = TmpDir::new("push-tree-second");
    let src = build_rich_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (first, _) = pushed(&repo, &src, tree_options(&[REF]), "first");
    let (second, outcome) = pushed(&repo, &src, tree_options(&[REF]), "second");
    assert_ne!(second, first);
    assert_eq!(outcome.refs[0].old, Some(first));
    assert_eq!(outcome.stats.objects_needed, 1, "{:?}", outcome.stats);
    assert_eq!(outcome.stats.objects_sent, 1, "{:?}", outcome.stats);
    let (commit, _) = block_on(repo.load_commit(&second)).unwrap();
    assert_eq!(commit.parent, Some(first));
    assert_eq!(named_ref(&repo, REF), Some(format!("{second}\n")));
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
                    ..tree_options(&[REF])
                },
                Some(change),
            );
            assert_eq!(ref_file(&repo), None, "{what}: a ref changed");
            assert!(
                matches!(
                    report,
                    Err(ostrya::Error::Push(ostrya::push::Error::ChecksumMismatch(
                        _
                    )))
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

#[test]
fn target_refs_in_mixed_states_are_refused_before_any_upload() {
    let tmp = TmpDir::new("push-tree-mixed");
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (tip, _) = pushed(&repo, &src, tree_options(&["tree/a"]), "first");
    // A new file gives the tree objects that the server does not hold.
    std::fs::write(src.join("new.txt"), b"new\n").unwrap();
    let before = object_files(&repo);
    for refs in [["tree/a", "tree/b"], ["tree/b", "tree/a"]] {
        let what = format!("{refs:?}");
        let progress = PushProgress::new();
        let (report, client) = tree_push(
            &repo,
            &src,
            TreePushOptions {
                progress: Some(progress.clone()),
                ..tree_options(&refs)
            },
            None,
        );
        match client {
            Err(Error::InvalidInput(m)) => {
                assert!(m.contains("mixed states"), "{what}: {m}");
                assert!(m.contains(&format!("'tree/a' is at {tip}")), "{what}: {m}");
                assert!(m.contains("'tree/b' is absent"), "{what}: {m}");
            }
            other => panic!("{what}: {other:?}"),
        }
        assert!(
            matches!(
                report,
                Err(ostrya::Error::Push(ostrya::push::Error::Aborted))
            ),
            "{what}: server {report:?}"
        );
        let snapshot = progress.snapshot();
        assert_eq!(snapshot.objects_total, 0, "{what}: {snapshot:?}");
        assert_eq!(snapshot.objects_sent, 0, "{what}: {snapshot:?}");
        assert_eq!(object_files(&repo), before, "{what}: the store changed");
        assert_eq!(
            named_ref(&repo, "tree/a"),
            Some(format!("{tip}\n")),
            "{what}"
        );
        assert_eq!(named_ref(&repo, "tree/b"), None, "{what}");
    }
}

#[test]
fn the_signatures_follow_the_detached_entries_of_the_caller_in_signer_order() {
    let tmp = TmpDir::new("push-tree-signed");
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let secret = ostrya::base64::decode(SECRET_B64).unwrap();
    let signers: Vec<Box<dyn Signer>> = vec![
        Box::new(DummySigner::new(b"dummy-key".to_vec())),
        Box::new(Ed25519Signer::from_secret_key(&secret).unwrap()),
    ];
    let (commit, _) = pushed(
        &repo,
        &src,
        TreePushOptions {
            detached_metadata: vec![
                ("xa.one".to_owned(), string("1")),
                ("xa.two".to_owned(), string("2")),
            ],
            signers,
            ..tree_options(&[REF])
        },
        "signed",
    );
    let dict = block_on(repo.read_commit_detached_metadata(&commit))
        .unwrap()
        .expect("the commit has detached metadata");
    let keys: Vec<&str> = dict
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_tuple().unwrap()[0].as_str().unwrap())
        .collect();
    assert_eq!(
        keys,
        [
            "xa.one",
            "xa.two",
            "ostree.sign.dummy",
            "ostree.sign.ed25519"
        ]
    );
    let verifier = Ed25519Verifier::new([&secret[32..]], Vec::<Vec<u8>>::new()).unwrap();
    let outcome = block_on(repo.verify_commit(&commit, &[&verifier])).unwrap();
    assert!(outcome.valid, "{outcome:?}");
}

#[test]
fn the_progress_handle_shows_the_scan_and_then_the_session() {
    let tmp = TmpDir::new("push-tree-progress");
    let src = build_fixture_source(tmp.path());
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let progress = PushProgress::new();
    let first = TreePushOptions {
        progress: Some(progress.clone()),
        ..tree_options(&[REF])
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
        ..tree_options(&[REF])
    };
    let (report, client) = tree_push(&repo, &src, second, Some(hook));
    report.unwrap();
    client.unwrap();
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|p| *p == PushPhase::Scanning), "{seen:?}");
    assert_eq!(*at_read.lock().unwrap(), Some(PushPhase::Negotiating));
    assert_eq!(progress.snapshot().phase, PushPhase::Committing);
}
