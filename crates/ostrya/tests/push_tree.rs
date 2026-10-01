//! The tree walk of `ostrya::push::tree` against the ingest of
//! `write_dfd_to_mtree`: the root checksums of the two agree over the same
//! tree, with extended attributes skipped, with and without canonical
//! permissions, and with a skipped directory. The tree model as the object
//! source of a push to `Repo::receive` over two in-process pipes.

#![cfg(all(feature = "push", feature = "receive"))]

mod common;

use std::collections::HashSet;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::receive::{connect, new_repo};
use common::{ROOT_DIRMETA, ROOT_DIRTREE, TmpDir};
use futures_lite::future::zip;
use ostrya::push::tree::{EntryAction, EntryFilter, EntryKind, ScanOptions, TreeModel};
use ostrya::push::{
    Compression, Error, Expected, ObjectSource, PushOutcome, PushSession, RefUpdate, SessionOptions,
};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CreateOptions, DictBuilder, FilterResult,
    FsckOptions, MutableTree, ObjectType, ReceivePolicy, ReceiveReport, Repo, RepoMode, Value,
};
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
