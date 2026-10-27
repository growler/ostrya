#![forbid(unsafe_code)]

//! Tests of the tree push to a bucket repository, `BucketRepo::push_tree`.
//!
//! Most tests run against the S3 stand-in of `common::s3`. The commit of a
//! tree push is checked against the commit of `Transaction::write_commit`
//! over the same tree, and against the commit that the receive side of a
//! session tree push makes. A test on SeaweedFS or rclone skips when its
//! program is absent. `OSTRYA_REQUIRE_SEAWEEDFS` and `OSTRYA_REQUIRE_S3` turn
//! each skip into a failure. No test reads the AWS environment.

#![cfg(all(feature = "push", feature = "s3"))]

mod common;

use std::collections::BTreeSet;
use std::os::fd::AsFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::TmpDir;
use common::modes::object_path;
use common::s3::{Rclone, Seaweed, StandIn, endpoint, rclone_available, seaweed_available};
use ostrya::bucket::{BucketPushOutcome, BucketRepo, BucketWriteOptions};
use ostrya::remote::s3::S3Endpoint;
use ostrya::remote::tree::{EntryAction, EntryFilter, EntryKind};
use ostrya::remote::{
    Compression, Endpoint, PullSession, PushPhase, PushProgress, PushProgressSnapshot,
    StreamSessionOptions, TreePushOptions,
};
use ostrya::verify::PullTrust;
use ostrya::{
    Checksum, Commit, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DirTree,
    Error, MutableTree, ObjectType, PullOptions, Repo, RepoMode, RepoPushOptions, Type, Value,
};
use ostrya_core::{ContentHasher, FileHeader, Xattrs, commit_metadata};
use ostrya_rt::block_on;

/// The address of the repository in each test.
const ADDRESS: &str = "s3://bkt/repo";

/// The key of the writer lock in the bucket.
const LOCK: &str = "repo/extensions/ostrya/lock";

/// The key of the probe of the lock in the bucket.
const PROBE: &str = "repo/extensions/ostrya/lock-probe";

/// The key of the config in the bucket.
const CONFIG: &str = "repo/config";

/// The branch of the tests.
const BRANCH: &str = "exampleos/main";

/// The collection ids of the tests.
const A: &str = "org.example.A";
const B: &str = "org.example.B";

const SUBJECT: &str = "tree push";
const BODY: &str = "the body of the tree push";
const TIMESTAMP: u64 = 1_700_000_000;

/// The body of a lock of a writer that ended with no release.
const DEAD_LOCK: &str = "[lock]\nid=9999999999999999999999999999999999999999999999999999999999999999\n\
                         host=deadhost\npid=99\noperation=push\nstarted=1700000000\n";

/// The content of the file `hello` of [`build_src`].
const HELLO: &[u8] = b"hello ostree\n";

/// Builds a tree with fixed modes in `base/src` and returns its path.
///
/// The tree has a regular file, an executable, an empty file, a file larger
/// than one 64 KiB chunk, a symlink, and a subdirectory with a file.
fn build_src(base: &Path) -> PathBuf {
    let src = base.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("hello"), HELLO).unwrap();
    std::fs::write(src.join("exec"), b"#!/bin/sh\n").unwrap();
    std::fs::write(src.join("empty"), b"").unwrap();
    let big: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(src.join("big"), big).unwrap();
    std::fs::write(src.join("sub/nested"), b"nested\n").unwrap();
    symlink("hello", src.join("link")).unwrap();
    for (path, mode) in [
        ("hello", 0o644),
        ("exec", 0o755),
        ("empty", 0o644),
        ("big", 0o644),
        ("sub/nested", 0o644),
        ("sub", 0o755),
        ("", 0o755),
    ] {
        std::fs::set_permissions(src.join(path), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    src
}

/// Returns the checksum of a regular file with the canonical owner, the mode
/// `0o100644`, and `content`.
fn file_checksum(content: &[u8]) -> Checksum {
    let header = FileHeader {
        uid: 0,
        gid: 0,
        mode: 0o100644,
        symlink_target: String::new(),
        xattrs: Xattrs::empty(),
    };
    let mut hasher = ContentHasher::new(&header).unwrap();
    hasher.update(content);
    hasher.finish()
}

/// Returns a filter that gives each entry the canonical permissions.
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

fn string(s: &str) -> Value {
    Value::variant(Type::Str, Value::Str(s.to_owned()))
}

/// The metadata entries of the caller.
fn caller_entries() -> Vec<(String, Value)> {
    vec![
        ("version".to_owned(), string("1.0")),
        ("xa.note".to_owned(), string("note")),
    ]
}

/// The options of a tree push onto `branch` with the canonical filter, the
/// subject, the body, the timestamp, and the metadata of these tests.
fn tree_options(branch: &str) -> TreePushOptions {
    TreePushOptions {
        onto: branch.into(),
        subject: Some(SUBJECT.into()),
        body: Some(BODY.into()),
        timestamp: Some(TIMESTAMP),
        metadata: caller_entries(),
        entry_filter: Some(canonical()),
        ..Default::default()
    }
}

/// Returns the write options with `break_lock`.
fn write(break_lock: bool) -> BucketWriteOptions {
    let mut write = BucketWriteOptions::default();
    write.break_lock = break_lock;
    write
}

/// Writes the `config` of a new bucket repository at [`ADDRESS`] on the
/// server at `url`, with the collection id `id` and the zlib level `level`.
async fn init(url: &str, id: Option<&str>, level: Option<u8>) {
    let repo = BucketRepo::open(&endpoint(url, ADDRESS)).await.unwrap();
    assert_eq!(repo.init(id, level, false).await.unwrap(), None);
}

/// Pushes the tree `src` with `opts` to [`ADDRESS`] on the server at `url`.
async fn push_tree(
    url: &str,
    src: &Path,
    opts: TreePushOptions,
    write: BucketWriteOptions,
) -> ostrya::Result<BucketPushOutcome> {
    BucketRepo::open(&endpoint(url, ADDRESS))
        .await?
        .push_tree(src, opts, write)
        .await
}

/// Writes a commit with `Transaction::write_commit` over `src` into a new
/// archive repository `base/<name>`, with the zlib level `level`, sets
/// [`BRANCH`] to it, and returns the repository and the commit.
///
/// The ingest takes the canonical permissions and no extended attributes,
/// as the filter of [`tree_options`]. The commit has `parent`, `metadata`,
/// and the subject, the body, and the timestamp of these tests.
async fn local_commit(
    base: &Path,
    name: &str,
    src: &Path,
    parent: Option<Checksum>,
    metadata: Value,
    level: Option<u8>,
) -> (Repo, Checksum) {
    let path = base.join(name);
    drop(
        Repo::create(&path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap(),
    );
    if let Some(level) = level {
        let config = path.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(&format!("\n[archive]\nzlib-level={level}\n"));
        std::fs::write(&config, text).unwrap();
    }
    let repo = Repo::open(&path).await.unwrap();
    let txn = repo.transaction().await.unwrap();
    let dfd = std::fs::File::open(src).unwrap();
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::SKIP_XATTRS | CommitModifierFlags::CANONICAL_PERMISSIONS,
    );
    let mut mtree = MutableTree::new();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, Some(&mut modifier))
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
    txn.set_ref(BRANCH, Some(&commit));
    txn.commit().await.unwrap();
    (repo, commit)
}

/// Returns the commit metadata of [`caller_entries`] with the bindings of
/// `refs` and `collection`.
fn bound(refs: &[&str], collection: Option<&str>) -> Value {
    commit_metadata(caller_entries(), Some(refs), collection)
}

/// Returns the key of the object of `ty` and `checksum` in the bucket.
fn key(ty: ObjectType, checksum: &Checksum) -> String {
    format!("repo/{}", object_path(ty, checksum))
}

/// Returns the target of each `PUT` that `server` got, without the bucket.
fn puts(server: &StandIn) -> Vec<String> {
    server
        .state()
        .requests
        .iter()
        .filter(|(method, _)| method == "PUT")
        .map(|(_, target)| target.trim_start_matches("/bkt/").to_owned())
        .collect()
}

/// Returns the target of each `PUT` of `server` to an object key.
fn object_puts(server: &StandIn) -> Vec<String> {
    puts(server)
        .into_iter()
        .filter(|target| target.starts_with("repo/objects/"))
        .collect()
}

/// Returns the commit that the ref file at `key` names, or `None`.
fn ref_of(server: &StandIn, key: &str) -> Option<Checksum> {
    let state = server.state();
    let stored = state.objects.get(key)?;
    Some(Checksum::from_hex(std::str::from_utf8(&stored.bytes).unwrap().trim_end()).unwrap())
}

/// Returns the keys of `server` that start with `prefix`.
fn keys(server: &StandIn, prefix: &str) -> Vec<String> {
    server
        .state()
        .objects
        .keys()
        .filter(|key| key.starts_with(prefix))
        .cloned()
        .collect()
}

/// Returns the commit object that `server` holds for `commit`.
fn stored_commit(server: &StandIn, commit: &Checksum) -> Commit {
    Commit::parse(&server.state().objects[&key(ObjectType::Commit, commit)].bytes).unwrap()
}

/// Asserts that each commit object of `server` has its whole tree in the
/// bucket.
fn assert_trees_whole(server: &StandIn) {
    let state = server.state();
    let has = |ty, checksum: &Checksum| state.objects.contains_key(&key(ty, checksum));
    for (stored_key, stored) in &state.objects {
        if !stored_key.ends_with(".commit") {
            continue;
        }
        let commit = Commit::parse(&stored.bytes).unwrap();
        assert!(
            has(ObjectType::DirMeta, &commit.root_dirmeta),
            "{stored_key}"
        );
        let mut stack = vec![commit.root_dirtree];
        while let Some(tree) = stack.pop() {
            let tree_key = key(ObjectType::DirTree, &tree);
            let bytes = &state
                .objects
                .get(&tree_key)
                .unwrap_or_else(|| panic!("{stored_key}: no {tree_key}"))
                .bytes;
            let dirtree = DirTree::parse(bytes).unwrap();
            for (name, file) in &dirtree.files {
                assert!(has(ObjectType::File, file), "{stored_key}: {name}");
            }
            for (name, subtree, submeta) in dirtree.dirs {
                assert!(has(ObjectType::DirMeta, &submeta), "{stored_key}: {name}");
                stack.push(subtree);
            }
        }
    }
}

/// Returns the objects of `commit` and the commit, by name.
async fn objects_of(repo: &Repo, commit: &Checksum) -> BTreeSet<String> {
    repo.traverse_commit(commit, 0)
        .await
        .unwrap()
        .into_iter()
        .map(|name| object_path(name.ty, &name.checksum))
        .collect()
}

/// Pulls `refs` of the bucket repository of `s3` into a new archive
/// repository at `path`.
async fn pull_back(s3: S3Endpoint, path: &Path, refs: &[&str]) -> Repo {
    drop(
        Repo::create(path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap(),
    );
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    // The host of the tests can have little free space.
    text.push_str("min-free-space-percent=0\n");
    std::fs::write(&config, text).unwrap();
    let repo = Repo::open(path).await.unwrap();
    let session = PullSession::connect(Endpoint::S3(s3), StreamSessionOptions::default())
        .await
        .unwrap();
    let opts = PullOptions {
        refs: refs.iter().map(|r| (*r).to_owned()).collect(),
        ..PullOptions::default()
    };
    repo.pull_with_session(session, PullTrust::unverified(), opts)
        .await
        .unwrap();
    repo
}

/// Returns a change of the stand-in that puts [`DEAD_LOCK`] in place of the
/// lock.
fn replace_lock() -> common::s3::Change {
    Box::new(|objects| {
        let stored = objects.get_mut(LOCK).unwrap();
        stored.bytes = DEAD_LOCK.as_bytes().to_vec();
        stored.etag = "\"replaced\"".into();
    })
}

/// Returns a progress handle that writes `content` to `path` when the push
/// enters the phase `Uploading`, after the scan.
fn change_at_upload(path: PathBuf, content: Vec<u8>) -> PushProgress {
    PushProgress::with_hook(Arc::new(move |snapshot: &PushProgressSnapshot| {
        if snapshot.phase == PushPhase::Uploading {
            std::fs::write(&path, &content).unwrap();
        }
    }))
}

/// Returns the message of `result` if it is a refusal of the request.
fn refused<T: std::fmt::Debug>(result: ostrya::Result<T>) -> String {
    match result {
        Err(Error::Remote(ostrya::remote::Error::InvalidInput(message))) => message,
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

/// Returns the message of `result` if it is a malformed bucket repository.
fn malformed<T: std::fmt::Debug>(result: ostrya::Result<T>) -> String {
    match result {
        Err(Error::InvalidFormat(message)) => message,
        other => panic!("expected InvalidFormat, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The commit and the objects.
// ---------------------------------------------------------------------------

/// The commit of a tree push is the commit of `write_commit` over the same
/// tree, and a pull of the branch gives each object of the tree.
#[test]
fn a_tree_push_writes_the_commit_of_write_commit_and_pulls_back() {
    let scratch = TmpDir::new("push-tree-s3-commit");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None, None).await;
        let (local, want) = local_commit(
            scratch.path(),
            "local",
            &src,
            None,
            bound(&[BRANCH], None),
            None,
        )
        .await;
        let outcome = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap();
        assert_eq!(outcome.broken_lock, None);
        let pushed = outcome.outcome;
        assert_eq!(pushed.commit, Some(want));
        assert_eq!(pushed.refs.len(), 1);
        assert_eq!(
            (
                pushed.refs[0].name.as_str(),
                pushed.refs[0].old,
                pushed.refs[0].new
            ),
            (BRANCH, None, Some(want))
        );
        let stats = pushed.stats;
        assert_eq!(stats.objects_needed, stats.objects_sent);
        assert_eq!(stats.objects_total, stats.objects_needed);
        assert!(stats.bytes_sent > 0);
        assert_eq!(
            ref_of(&server, &format!("repo/refs/heads/{BRANCH}")),
            Some(want)
        );
        assert!(!server.state().objects.contains_key(LOCK));
        assert!(keys(&server, "repo/summary").is_empty());
        assert_trees_whole(&server);
        // The bucket holds the objects of the local commit, each in archive
        // form.
        let stored: BTreeSet<String> = keys(&server, "repo/objects/")
            .into_iter()
            .map(|key| key["repo/".len()..].to_owned())
            .collect();
        assert_eq!(stored, objects_of(&local, &want).await);
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let pulled = pull_back(s3, &scratch.path().join("pulled"), &[BRANCH]).await;
        assert_eq!(pulled.resolve_rev(BRANCH, false).await.unwrap(), Some(want));
        assert_eq!(
            objects_of(&pulled, &want).await,
            objects_of(&local, &want).await
        );
    });
}

/// The commit of a tree push to a bucket is the commit that the receive side
/// of a session tree push makes from the same inputs, in each namespace: for
/// a new branch, for a second push whose parent is the tip, and for `orphan`
/// over the branch.
#[cfg(feature = "receive")]
#[test]
fn the_commit_is_the_commit_of_a_session_tree_push() {
    use common::receive::{collections_policy, connect, new_repo, policy_allowing};

    let scratch = TmpDir::new("push-tree-s3-session");
    let src = build_src(scratch.path());
    let cases: [(Option<&str>, Option<&str>, &str); 5] = [
        (None, None, ""),
        (Some(A), None, "collection-id=org.example.A\n"),
        (Some(A), Some(A), "collection-id=org.example.A\n"),
        (Some(A), Some(B), "collection-id=org.example.A\n"),
        (None, Some(B), ""),
    ];
    // A new branch, a second push onto the tip, and `orphan` over the branch.
    let pushes = [
        (false, TIMESTAMP),
        (false, TIMESTAMP),
        (true, TIMESTAMP + 1),
    ];
    for (index, (bucket_id, collection, core)) in cases.into_iter().enumerate() {
        let options = |orphan: bool, timestamp: u64| TreePushOptions {
            collection: collection.map(str::to_owned),
            bind_refs: vec!["alias".into()],
            orphan,
            timestamp: Some(timestamp),
            ..tree_options(BRANCH)
        };
        let tmp = TmpDir::new(&format!("push-tree-s3-session-{index}"));
        let receiver = new_repo(&tmp, RepoMode::Archive, core);
        let mirror = collection.is_some_and(|id| Some(id) != bucket_id);
        let policy = if mirror {
            collections_policy(&["cd:**"])
        } else {
            policy_allowing(&["cd:**"])
        };
        let dir = match collection {
            Some(id) if mirror => format!("refs/mirrors/{id}"),
            _ => "refs/heads".to_owned(),
        };
        let server = StandIn::start();
        block_on(init(&server.endpoint(), bucket_id, None));
        let mut tip = None;
        for (step, (orphan, timestamp)) in pushes.into_iter().enumerate() {
            let what = format!("{bucket_id:?} {collection:?} push {step}");
            let (client, server_in, server_out) = connect();
            let (report, session) = block_on(futures_lite::future::zip(
                receiver.receive(server_in, server_out, &policy),
                ostrya::remote::push_tree_over_stream(
                    client.reader.into_inner(),
                    client.writer.into_inner(),
                    &src,
                    options(orphan, timestamp),
                ),
            ));
            report.unwrap_or_else(|e| panic!("{what}: {e}"));
            let want = session
                .unwrap_or_else(|e| panic!("{what}: {e}"))
                .commit
                .unwrap();
            let outcome = block_on(push_tree(
                &server.endpoint(),
                &src,
                options(orphan, timestamp),
                write(false),
            ))
            .unwrap_or_else(|e| panic!("{what}: {e}"))
            .outcome;
            assert_eq!(outcome.commit, Some(want), "{what}");
            assert_eq!(outcome.refs[0].old, tip, "{what}");
            assert_eq!(
                ref_of(&server, &format!("repo/{dir}/{BRANCH}")),
                Some(want),
                "{what}"
            );
            let commit = stored_commit(&server, &want);
            assert_eq!(commit.parent, if orphan { None } else { tip }, "{what}");
            assert_eq!(
                commit.collection_binding(),
                collection.or(bucket_id),
                "{what}"
            );
            assert_eq!(commit.ref_bindings(), ["alias", BRANCH], "{what}");
            tip = Some(want);
        }
    }
}

/// A second push takes the tip as its parent and uploads the changed objects
/// alone. A push of the same tree again uploads the commit alone.
#[test]
fn a_second_tree_push_takes_the_tip_as_parent_and_uploads_the_delta() {
    let scratch = TmpDir::new("push-tree-s3-second");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None, None).await;
        let first = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap()
            .outcome
            .commit
            .unwrap();
        std::fs::write(src.join("sub/nested"), b"changed\n").unwrap();
        let (_, want) = local_commit(
            scratch.path(),
            "local-second",
            &src,
            Some(first),
            bound(&[BRANCH], None),
            None,
        )
        .await;
        server.state().requests.clear();
        let outcome = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap()
            .outcome;
        assert_eq!(outcome.commit, Some(want));
        assert_eq!(outcome.refs[0].old, Some(first));
        assert_eq!(stored_commit(&server, &want).parent, Some(first));
        // The changed file, the dirtree of `sub`, the root dirtree, and the
        // commit.
        let uploaded = object_puts(&server);
        assert_eq!(uploaded.len(), 4, "{uploaded:?}");
        assert!(uploaded.contains(&key(ObjectType::File, &file_checksum(b"changed\n"))));
        assert_eq!(uploaded.last(), Some(&key(ObjectType::Commit, &want)));
        assert_eq!(outcome.stats.objects_sent, 4);
        assert_trees_whole(&server);

        server.state().requests.clear();
        let again = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap()
            .outcome;
        let third = again.commit.unwrap();
        assert_eq!(object_puts(&server), [key(ObjectType::Commit, &third)]);
        assert_eq!(stored_commit(&server, &third).parent, Some(want));
        assert_eq!(
            ref_of(&server, &format!("repo/refs/heads/{BRANCH}")),
            Some(third)
        );
    });
}

/// `orphan` on a branch that exists makes a commit with no parent, and the
/// ref takes it.
#[test]
fn orphan_replaces_the_tip_of_an_existing_branch() {
    let scratch = TmpDir::new("push-tree-s3-orphan");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None, None).await;
        let first = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap()
            .outcome
            .commit
            .unwrap();
        let opts = TreePushOptions {
            orphan: true,
            timestamp: Some(TIMESTAMP + 1),
            ..tree_options(BRANCH)
        };
        let outcome = push_tree(&server.endpoint(), &src, opts, write(false))
            .await
            .unwrap()
            .outcome;
        let orphan = outcome.commit.unwrap();
        assert_ne!(orphan, first);
        assert_eq!(outcome.refs[0].old, Some(first));
        assert_eq!(stored_commit(&server, &orphan).parent, None);
        assert_eq!(
            ref_of(&server, &format!("repo/refs/heads/{BRANCH}")),
            Some(orphan)
        );
    });
}

// ---------------------------------------------------------------------------
// Namespaces and refusals.
// ---------------------------------------------------------------------------

/// The collection id of the bucket writes `refs/heads/`, another id writes
/// `refs/mirrors/ID/`, and a key under `refs/mirrors/` of the own id refuses
/// the push.
#[test]
fn the_namespace_follows_the_collection_and_the_bucket_id() {
    let scratch = TmpDir::new("push-tree-s3-namespace");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), Some(A), None).await;
        for (collection, dir) in [
            (None, "refs/heads"),
            (Some(A), "refs/heads"),
            (Some(B), "refs/mirrors/org.example.B"),
        ] {
            let opts = TreePushOptions {
                collection: collection.map(str::to_owned),
                ..tree_options("ns")
            };
            let commit = push_tree(&server.endpoint(), &src, opts, write(false))
                .await
                .unwrap()
                .outcome
                .commit
                .unwrap();
            assert_eq!(
                ref_of(&server, &format!("repo/{dir}/ns")),
                Some(commit),
                "{collection:?}"
            );
            assert_eq!(
                stored_commit(&server, &commit).collection_binding(),
                Some(collection.unwrap_or(A))
            );
        }
        server
            .state()
            .store("repo/refs/mirrors/org.example.A/x", b"junk");
        let message =
            malformed(push_tree(&server.endpoint(), &src, tree_options("ns"), write(false)).await);
        assert!(message.contains("own collection id"), "{message}");
    });
}

/// The branch `ostree-metadata` is refused in `refs/heads/` of a bucket with
/// a collection id, and taken in a mirror namespace and in a bucket with no
/// id.
#[test]
fn the_anchor_ref_is_refused_in_the_local_refs_of_a_bucket_with_an_id() {
    let scratch = TmpDir::new("push-tree-s3-anchor");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), Some(A), None).await;
        let result = push_tree(
            &server.endpoint(),
            &src,
            tree_options("ostree-metadata"),
            write(false),
        )
        .await;
        match result {
            Err(Error::Remote(ostrya::remote::Error::RefDenied(message))) => {
                assert!(message.contains("ostree-metadata"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        assert!(keys(&server, "repo/objects/").is_empty());
        assert!(keys(&server, "repo/refs/").is_empty());
        assert!(!server.state().objects.contains_key(LOCK));
        let opts = TreePushOptions {
            collection: Some(B.into()),
            ..tree_options("ostree-metadata")
        };
        push_tree(&server.endpoint(), &src, opts, write(false))
            .await
            .unwrap();

        let plain = StandIn::start();
        init(&plain.endpoint(), None, None).await;
        push_tree(
            &plain.endpoint(),
            &src,
            tree_options("ostree-metadata"),
            write(false),
        )
        .await
        .unwrap();
    });
}

#[test]
fn a_tree_push_to_a_bucket_with_no_config_is_refused() {
    let scratch = TmpDir::new("push-tree-s3-no-config");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        let message =
            refused(push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false)).await);
        assert_eq!(
            message,
            format!("the bucket repository {ADDRESS} has no config; init it first")
        );
        assert_eq!(puts(&server), [PROBE, PROBE, LOCK]);
        assert_eq!(keys(&server, "repo/"), [PROBE]);
    });
}

/// A branch that is a directory of a ref of the namespace, or under a ref of
/// it, is refused before an upload.
#[test]
fn a_branch_that_clashes_with_a_ref_directory_is_refused() {
    let scratch = TmpDir::new("push-tree-s3-prefix");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None, None).await;
        push_tree(&server.endpoint(), &src, tree_options("a/b"), write(false))
            .await
            .unwrap();
        let before = keys(&server, "repo/");
        for branch in ["a", "a/b/c"] {
            let message = refused(
                push_tree(&server.endpoint(), &src, tree_options(branch), write(false)).await,
            );
            assert!(message.contains("is a directory of the ref"), "{message}");
        }
        assert_eq!(keys(&server, "repo/"), before);
    });
}

/// A ref of the namespace whose commit the bucket does not hold refuses the
/// push before an upload, also when the ref is the parent.
#[test]
fn a_ref_whose_commit_is_absent_refuses_the_push() {
    let scratch = TmpDir::new("push-tree-s3-absent");
    let src = build_src(scratch.path());
    block_on(async {
        let absent = format!("{}\n", "ab".repeat(32));
        for name in ["other", BRANCH] {
            let server = StandIn::start();
            init(&server.endpoint(), None, None).await;
            server
                .state()
                .store(&format!("repo/refs/heads/{name}"), absent.as_bytes());
            let message = malformed(
                push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false)).await,
            );
            assert!(
                message.contains("which the bucket does not hold"),
                "{message}"
            );
            assert!(keys(&server, "repo/objects/").is_empty(), "{name}");
            assert!(!server.state().objects.contains_key(LOCK));
        }
    });
}

/// Tags, bad options, and a walk error refuse the push before any request.
#[test]
fn a_refusal_of_the_options_or_the_walk_sends_no_request() {
    let scratch = TmpDir::new("push-tree-s3-refusals");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None, None).await;
        server.state().requests.clear();
        let message = refused(
            push_tree(
                &server.endpoint(),
                &src,
                TreePushOptions {
                    tags: vec!["v1".into()],
                    ..tree_options(BRANCH)
                },
                write(false),
            )
            .await,
        );
        assert!(message.contains("creates no tag"), "{message}");
        for opts in [
            tree_options("bad^name"),
            TreePushOptions {
                compression: Compression::Deflate { level: 10 },
                ..tree_options(BRANCH)
            },
            TreePushOptions {
                collection: Some("nodot".into()),
                ..tree_options(BRANCH)
            },
            TreePushOptions {
                metadata: vec![("ostree.ref-binding".into(), string("x"))],
                ..tree_options(BRANCH)
            },
        ] {
            refused(push_tree(&server.endpoint(), &src, opts, write(false)).await);
        }
        match push_tree(
            &server.endpoint(),
            &scratch.path().join("absent"),
            tree_options(BRANCH),
            write(false),
        )
        .await
        {
            Err(Error::Remote(ostrya::remote::Error::Walk { .. })) => {}
            other => panic!("{other:?}"),
        }
        assert!(server.state().requests.is_empty());
    });
}

// ---------------------------------------------------------------------------
// Failure states.
// ---------------------------------------------------------------------------

/// A file that changes after the hash pass fails the push. Its object does
/// not go up, and no commit object and no ref are written.
#[test]
fn a_file_changed_after_the_scan_uploads_no_object_of_it_and_no_commit() {
    let scratch = TmpDir::new("push-tree-s3-changed");
    let src = build_src(scratch.path());
    block_on(async {
        for (what, content) in [
            ("same length", b"HELLO ostree\n".to_vec()),
            ("longer", b"hello ostree, and more\n".to_vec()),
            ("shorter", b"hello\n".to_vec()),
        ] {
            std::fs::write(src.join("hello"), HELLO).unwrap();
            let server = StandIn::start();
            init(&server.endpoint(), None, None).await;
            let opts = TreePushOptions {
                progress: Some(change_at_upload(src.join("hello"), content)),
                ..tree_options(BRANCH)
            };
            match push_tree(&server.endpoint(), &src, opts, write(false)).await {
                Err(Error::Remote(ostrya::remote::Error::ChecksumMismatch(message))) => {
                    assert!(message.contains("changed after the hash pass"), "{message}");
                    assert!(message.contains("hello"), "{message}");
                }
                other => panic!("{what}: {other:?}"),
            }
            let hello = key(ObjectType::File, &file_checksum(HELLO));
            assert!(!object_puts(&server).contains(&hello), "{what}");
            assert!(
                keys(&server, "repo/objects/")
                    .iter()
                    .all(|k| !k.ends_with(".commit"))
            );
            assert!(keys(&server, "repo/refs/").is_empty(), "{what}");
            assert!(!server.state().objects.contains_key(LOCK), "{what}");
            assert_trees_whole(&server);
        }
    });
}

/// A failed upload leaves no commit and no ref, and a run again uploads the
/// rest and writes the ref.
#[test]
fn a_failed_upload_leaves_no_ref_and_a_run_again_completes() {
    let scratch = TmpDir::new("push-tree-s3-run-again");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None, None).await;
        let (local, want) = local_commit(
            scratch.path(),
            "local",
            &src,
            None,
            bound(&[BRANCH], None),
            None,
        )
        .await;
        let big = key(ObjectType::File, &{
            // The largest file of the tree.
            let mut files = common::modes::file_objects(&local, &want).await;
            files.sort_by_key(|file| {
                std::fs::metadata(local.path().join(object_path(ObjectType::File, file)))
                    .unwrap()
                    .len()
            });
            *files.last().unwrap()
        });
        server.state().refuse = Some(("PUT", big.clone()));
        let err = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("AccessDenied"), "{err}");
        assert!(keys(&server, "repo/refs/").is_empty());
        assert!(!server.state().objects.contains_key(LOCK));
        assert_trees_whole(&server);
        // The objects of the commit that the bucket lacks after the failed
        // run, the commit included.
        let held: BTreeSet<String> = keys(&server, "repo/objects/").into_iter().collect();
        let rest: BTreeSet<String> = objects_of(&local, &want)
            .await
            .into_iter()
            .map(|path| format!("repo/{path}"))
            .filter(|key| !held.contains(key))
            .collect();
        assert!(rest.contains(&big));
        server.state().refuse = None;
        server.state().requests.clear();
        let outcome = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap()
            .outcome;
        let commit = outcome.commit.unwrap();
        assert_eq!(commit, want);
        let uploaded = object_puts(&server);
        assert_eq!(uploaded.last(), Some(&key(ObjectType::Commit, &commit)));
        // Each object of the rest goes up once, and no other object.
        assert_eq!(uploaded.len(), rest.len(), "{uploaded:?}");
        assert_eq!(
            uploaded.into_iter().collect::<BTreeSet<_>>(),
            rest,
            "the second run uploads the rest alone"
        );
        assert_eq!(
            ref_of(&server, &format!("repo/refs/heads/{BRANCH}")),
            Some(commit)
        );
        assert_trees_whole(&server);
    });
}

#[test]
fn a_lock_of_another_writer_refuses_the_push_and_break_lock_removes_it() {
    let scratch = TmpDir::new("push-tree-s3-locked");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None, None).await;
        server.state().store(LOCK, DEAD_LOCK.as_bytes());
        let err = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BucketLocked { .. }), "{err}");
        assert!(keys(&server, "repo/objects/").is_empty());
        let outcome = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(true))
            .await
            .unwrap();
        let holder = outcome.broken_lock.expect("the holder of the broken lock");
        assert_eq!(holder.host.as_deref(), Some("deadhost"));
        assert!(!server.state().objects.contains_key(LOCK));
        assert!(ref_of(&server, &format!("repo/refs/heads/{BRANCH}")).is_some());
    });
}

/// A lock that another writer takes before the ref write stops the push with
/// no ref, and the push removes no lock.
#[test]
fn a_lock_broken_before_the_ref_stops_the_push() {
    let scratch = TmpDir::new("push-tree-s3-lost");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None, None).await;
        let (_, want) = local_commit(
            scratch.path(),
            "local",
            &src,
            None,
            bound(&[BRANCH], None),
            None,
        )
        .await;
        server.state().before_key = Some(("PUT", key(ObjectType::Commit, &want), replace_lock()));
        let err = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BucketLockLost { .. }), "{err}");
        assert!(keys(&server, "repo/refs/").is_empty());
        assert_eq!(server.state().objects[LOCK].bytes, DEAD_LOCK.as_bytes());
        assert_trees_whole(&server);
    });
}

#[test]
fn a_tree_push_to_a_server_that_ignores_if_none_match_writes_only_the_probe() {
    let scratch = TmpDir::new("push-tree-s3-no-exclusion");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None, None).await;
        server.state().honor_if_none_match = false;
        let err = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BucketNoExclusion { .. }), "{err}");
        assert_eq!(keys(&server, "repo/"), [CONFIG, PROBE]);
    });
}

/// A tree push writes no summary and keeps the one that the bucket holds.
#[test]
fn a_tree_push_writes_no_summary() {
    let scratch = TmpDir::new("push-tree-s3-summary");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None, None).await;
        server.state().store("repo/summary", b"old summary");
        push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap();
        assert!(!puts(&server).iter().any(|put| put.contains("summary")));
        assert_eq!(server.state().objects["repo/summary"].bytes, b"old summary");
    });
}

// ---------------------------------------------------------------------------
// The zlib level.
// ---------------------------------------------------------------------------

/// Returns the bytes of each `.filez` of `commit` in the archive repository
/// `repo`, by checksum.
async fn stored_filez(repo: &Repo, commit: &Checksum) -> Vec<(Checksum, Vec<u8>)> {
    common::modes::file_objects(repo, commit)
        .await
        .into_iter()
        .map(|file| {
            let path = repo.path().join(object_path(ObjectType::File, &file));
            (file, std::fs::read(path).unwrap())
        })
        .collect()
}

/// A tree push builds each `.filez` at the `[archive] zlib-level` of the
/// bucket, or at the level of `compression`. The bytes are those of an
/// `archive` repository at that level.
#[test]
fn the_filez_bytes_follow_the_level_of_the_bucket_or_of_the_push() {
    let scratch = TmpDir::new("push-tree-s3-level");
    let src = build_src(scratch.path());
    block_on(async {
        let mut by_level = Vec::new();
        for level in [1u8, 9] {
            let (repo, commit) = local_commit(
                scratch.path(),
                &format!("local-{level}"),
                &src,
                None,
                bound(&[BRANCH], None),
                Some(level),
            )
            .await;
            by_level.push((level, stored_filez(&repo, &commit).await));
        }
        // The big file deflates to other bytes at the two levels, so each
        // check below tells the levels apart.
        let differ = by_level[0]
            .1
            .iter()
            .zip(&by_level[1].1)
            .any(|(one, nine)| one.1 != nine.1);
        assert!(differ);
        for (bucket_level, compression, want) in [
            (Some(1), Compression::None, 0),
            (Some(9), Compression::None, 1),
            (Some(1), Compression::Deflate { level: 9 }, 1),
            (None, Compression::Deflate { level: 1 }, 0),
        ] {
            let what = format!("{bucket_level:?} {compression:?}");
            let server = StandIn::start();
            init(&server.endpoint(), None, bucket_level).await;
            let opts = TreePushOptions {
                compression,
                ..tree_options(BRANCH)
            };
            push_tree(&server.endpoint(), &src, opts, write(false))
                .await
                .unwrap();
            let state = server.state();
            for (file, bytes) in &by_level[want].1 {
                assert_eq!(
                    &state.objects[&key(ObjectType::File, file)].bytes,
                    bytes,
                    "{what}"
                );
            }
        }
    });
}

/// The push of commits from a repository that is not `archive` builds each
/// `.filez` at the level of the bucket, and not at the level of the local
/// repository.
#[test]
fn a_commit_push_builds_the_filez_at_the_level_of_the_bucket() {
    let scratch = TmpDir::new("push-tree-s3-commit-level");
    let src = build_src(scratch.path());
    block_on(async {
        let (archive, commit) = local_commit(
            scratch.path(),
            "local-9",
            &src,
            None,
            bound(&[BRANCH], None),
            Some(9),
        )
        .await;
        let want = stored_filez(&archive, &commit).await;
        // A bare-user repository with the default level 6 and the same
        // commit.
        let bare = Repo::create(
            &scratch.path().join("bare-user"),
            CreateOptions::new(RepoMode::BareUser),
        )
        .await
        .unwrap();
        bare.pull_local(
            &archive,
            PullOptions {
                refs: vec![BRANCH.to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        let server = StandIn::start();
        init(&server.endpoint(), None, Some(9)).await;
        bare.push_to_bucket(
            endpoint(&server.endpoint(), ADDRESS),
            RepoPushOptions {
                refspecs: vec![BRANCH.to_owned()],
                ..RepoPushOptions::default()
            },
        )
        .await
        .unwrap();
        let state = server.state();
        for (file, bytes) in &want {
            assert_eq!(&state.objects[&key(ObjectType::File, file)].bytes, bytes);
        }
    });
}

#[test]
fn init_writes_the_level_and_refuses_one_outside_1_to_9() {
    block_on(async {
        let server = StandIn::start();
        let repo = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        for level in [0, 10, 255] {
            match repo.init(None, Some(level), false).await {
                Err(Error::InvalidInput(message)) => {
                    assert!(message.contains("outside 1 to 9"), "{message}")
                }
                other => panic!("{level}: {other:?}"),
            }
        }
        assert!(server.state().requests.is_empty());
        repo.init(Some(A), Some(3), false).await.unwrap();
        assert_eq!(
            server.state().objects[CONFIG].bytes,
            format!(
                "[core]\nrepo_version=1\nmode=archive-z2\ncollection-id={A}\n\n[archive]\n\
                 zlib-level=3\n"
            )
            .as_bytes()
        );
    });
}

/// A bucket `config` whose `zlib-level` is no integer refuses the push
/// before an upload.
#[test]
fn a_zlib_level_that_is_no_integer_refuses_the_push() {
    let scratch = TmpDir::new("push-tree-s3-bad-level");
    let src = build_src(scratch.path());
    block_on(async {
        let server = StandIn::start();
        server.state().store(
            CONFIG,
            b"[core]\nrepo_version=1\nmode=archive-z2\n\n[archive]\nzlib-level=high\n",
        );
        let message = malformed(
            push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false)).await,
        );
        assert!(message.contains("zlib-level"), "{message}");
        assert!(keys(&server, "repo/objects/").is_empty());
    });
}

// ---------------------------------------------------------------------------
// SeaweedFS and rclone.
// ---------------------------------------------------------------------------

/// Returns `len` bytes of a fixed xorshift sequence, which DEFLATE does not
/// shrink.
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}

/// A tree push with a multipart upload, and a pull of the branch.
#[test]
fn a_multipart_tree_push_and_a_pull_on_seaweedfs() {
    if !seaweed_available("a_multipart_tree_push_and_a_pull_on_seaweedfs") {
        return;
    }
    let scratch = TmpDir::new("push-tree-s3-seaweed");
    let src = build_src(scratch.path());
    std::fs::write(src.join("large"), incompressible(12 << 20)).unwrap();
    std::fs::set_permissions(src.join("large"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let server = Seaweed::start(scratch.path(), "bkt");
    block_on(async {
        init(&server.endpoint(), None, None).await;
        let (local, want) = local_commit(
            scratch.path(),
            "local",
            &src,
            None,
            bound(&[BRANCH], None),
            None,
        )
        .await;
        let mut parts = write(false);
        parts.part_size = Some(5 << 20);
        let outcome = push_tree(&server.endpoint(), &src, tree_options(BRANCH), parts)
            .await
            .unwrap();
        assert_eq!(outcome.outcome.commit, Some(want));
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let bucket = BucketRepo::open(&s3).await.unwrap();
        let large = ostrya::ObjectName::new(
            file_checksum(&std::fs::read(src.join("large")).unwrap()),
            ObjectType::File,
        );
        assert!(bucket.list_objects().await.unwrap().objects[&large] > 10 << 20);
        let pulled = pull_back(s3, &scratch.path().join("pulled"), &[BRANCH]).await;
        assert_eq!(pulled.resolve_rev(BRANCH, false).await.unwrap(), Some(want));
        assert_eq!(
            objects_of(&pulled, &want).await,
            objects_of(&local, &want).await
        );
    });
}

/// A large file that changes after the hash pass fails its multipart upload
/// before the last part. The upload is aborted, and the key holds no object.
#[test]
fn a_changed_file_aborts_its_multipart_upload_on_seaweedfs() {
    if !seaweed_available("a_changed_file_aborts_its_multipart_upload_on_seaweedfs") {
        return;
    }
    let scratch = TmpDir::new("push-tree-s3-seaweed-changed");
    let src = scratch.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    let original = incompressible(12 << 20);
    std::fs::write(src.join("large"), &original).unwrap();
    std::fs::set_permissions(src.join("large"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut changed = original.clone();
    *changed.last_mut().unwrap() ^= 0xff;
    let server = Seaweed::start(scratch.path(), "bkt");
    block_on(async {
        init(&server.endpoint(), None, None).await;
        let mut parts = write(false);
        parts.part_size = Some(5 << 20);
        let opts = TreePushOptions {
            progress: Some(change_at_upload(src.join("large"), changed)),
            ..tree_options(BRANCH)
        };
        let err = push_tree(&server.endpoint(), &src, opts, parts)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Remote(ostrya::remote::Error::ChecksumMismatch(_))
            ),
            "{err}"
        );
        let bucket = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        let large = ostrya::ObjectName::new(file_checksum(&original), ObjectType::File);
        let listing = bucket.list_objects().await.unwrap();
        assert!(!listing.objects.contains_key(&large));
        assert!(
            listing
                .objects
                .keys()
                .all(|name| name.ty != ObjectType::Commit)
        );
        assert!(
            bucket
                .bucket()
                .list("refs/")
                .await
                .unwrap()
                .objects
                .is_empty()
        );
        assert!(bucket.bucket().list_uploads().await.unwrap().is_empty());
        assert_eq!(bucket.lock_holder().await.unwrap(), None);
    });
}

/// rclone does not honor `If-None-Match`, so a tree push to it is refused
/// and writes nothing.
#[test]
fn a_tree_push_on_rclone_is_refused() {
    if !rclone_available("a_tree_push_on_rclone_is_refused") {
        return;
    }
    let scratch = TmpDir::new("push-tree-s3-rclone");
    let src = build_src(scratch.path());
    let root = scratch.path().join("root");
    let bucket = root.join("bkt").join("repo");
    std::fs::create_dir_all(&bucket).unwrap();
    std::fs::write(
        bucket.join("config"),
        "[core]\nrepo_version=1\nmode=archive-z2\n",
    )
    .unwrap();
    let server = Rclone::start(scratch.path(), &root);
    block_on(async {
        let err = push_tree(&server.endpoint(), &src, tree_options(BRANCH), write(false))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BucketNoExclusion { .. }), "{err}");
    });
    for path in ["objects", "refs", "extensions/ostrya/lock"] {
        assert!(!bucket.join(path).exists(), "{path}");
    }
}

/// The future of a tree push to a bucket repository can run on a
/// multi-threaded executor.
#[allow(dead_code)]
fn the_tree_push_future_is_send(bucket: &BucketRepo, root: &Path) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&bucket.push_tree(
        root,
        TreePushOptions::default(),
        BucketWriteOptions::default(),
    ));
}
