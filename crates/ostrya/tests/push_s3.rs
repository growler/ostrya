#![forbid(unsafe_code)]

//! Tests of the init of a bucket repository and of the push to a bucket
//! repository.
//!
//! Most tests run against the S3 stand-in of `common::s3`, which holds its
//! objects in memory and honors `If-None-Match` and `If-Match`. Other tests
//! run against `weed mini` of SeaweedFS, which honors the headers, and
//! against `rclone serve s3`, which does not, so a writer is refused there.
//! A test on a real server skips when its program is absent.
//! `OSTRYA_REQUIRE_SEAWEEDFS` and `OSTRYA_REQUIRE_S3` turn each skip into a
//! failure. No test reads the AWS environment.
//!
//! The tests of the `ostree` command pull a pushed bucket over HTTP with no
//! signature: from the stand-in, and from the S3 port of SeaweedFS with the
//! identity `anonymous`. They run `ostree fsck` on a dump of the bucket,
//! because SeaweedFS keeps no tree of files on disk. A test skips when
//! `ostree` is absent, and `OSTRYA_REQUIRE_OSTREE` turns the skip into a
//! failure.

#![cfg(all(feature = "push", feature = "s3"))]

mod common;

use std::collections::BTreeSet;
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::TmpDir;
use common::modes::{build_tree, object_path, repo_of};
use common::s3::{Rclone, Seaweed, StandIn, endpoint, rclone_available, seaweed_available};
use ostrya::bucket::{BucketPushOutcome, BucketRepo};
use ostrya::remote::s3::S3Endpoint;
use ostrya::remote::{Compression, Endpoint, PullSession, StreamSessionOptions};
use ostrya::verify::PullTrust;
use ostrya::{
    Checksum, Commit, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions,
    DetachedMetadataFilter, DictBuilder, DirTree, Ed25519Signer, Error, MutableTree, ObjectType,
    PullOptions, PushOntoOptions, Repo, RepoMode, RepoPushOptions, Value,
};
use ostrya_rt::block_on;

/// The address of the repository in each test.
const ADDRESS: &str = "s3://bkt/repo";

/// The key of the writer lock in the bucket.
const LOCK: &str = "repo/extensions/ostrya/lock";

/// The key of the config in the bucket.
const CONFIG: &str = "repo/config";

/// A fixed ed25519 key that signs the commits.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";

/// The collection ids of the tests.
const A: &str = "org.example.A";
const B: &str = "org.example.B";
const C: &str = "org.example.C";

/// The body of a lock of a writer that ended with no release.
const DEAD_LOCK: &str = "[lock]\nid=9999999999999999999999999999999999999999999999999999999999999999\n\
                         host=deadhost\npid=99\noperation=push\nstarted=1700000000\n";

/// Writes the `config` of a new bucket repository at [`ADDRESS`] on the
/// server at `url`, with the collection id `id`.
async fn init(url: &str, id: Option<&str>) {
    let repo = BucketRepo::open(&endpoint(url, ADDRESS)).await.unwrap();
    assert_eq!(repo.init(id, None, false).await.unwrap(), None);
}

/// Returns the options of a push of `refspecs`.
fn opts(refspecs: &[&str]) -> RepoPushOptions {
    RepoPushOptions {
        refspecs: refspecs.iter().map(|spec| (*spec).to_owned()).collect(),
        ..RepoPushOptions::default()
    }
}

/// Pushes `opts` from `repo` to [`ADDRESS`] on the server at `url`.
async fn push(repo: &Repo, url: &str, opts: RepoPushOptions) -> ostrya::Result<BucketPushOutcome> {
    repo.push_to_bucket(endpoint(url, ADDRESS), opts).await
}

/// Pushes `opts` from `repo` to [`ADDRESS`] on the server at `url`, with at
/// most `max_outstanding` requests in flight.
async fn push_bounded(
    repo: &Repo,
    url: &str,
    opts: RepoPushOptions,
    max_outstanding: usize,
) -> ostrya::Result<BucketPushOutcome> {
    let mut s3 = endpoint(url, ADDRESS);
    s3.http.max_outstanding = max_outstanding;
    repo.push_to_bucket(s3, opts).await
}

/// Creates an `archive` repository at `path` for the commits of a test.
async fn archive(path: &Path) -> Repo {
    Repo::create(path, CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap()
}

/// Commits a tree with `content` onto `parent`, with the commit metadata
/// `metadata`, and points the ref `branch` at the commit.
async fn commit(
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
        .join(format!("tree-{}", content.replace('/', "-")));
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("file"), content).unwrap();
    std::fs::write(tree.join("sub/nested"), "the same in each commit\n").unwrap();
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
}

/// Returns the metadata of a commit bound to the collection `id`.
fn bound(id: &str) -> Option<Value> {
    let mut metadata = DictBuilder::new();
    metadata.insert_str("ostree.collection-binding", id);
    Some(metadata.build())
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

/// Creates an `archive` repository at `path` with no free space check.
async fn dest(path: &Path) -> Repo {
    drop(archive(path).await);
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    // The host of the tests can have little free space.
    text.push_str("min-free-space-percent=0\n");
    std::fs::write(&config, text).unwrap();
    Repo::open(path).await.unwrap()
}

/// Pulls `refs` of the bucket repository of `s3` into a new repository at
/// `path`, with `trust`.
async fn pull_back(s3: S3Endpoint, path: &Path, refs: &[&str], trust: PullTrust) -> Repo {
    let repo = dest(path).await;
    let session = PullSession::connect(Endpoint::S3(s3), StreamSessionOptions::default())
        .await
        .unwrap();
    let opts = PullOptions {
        refs: refs.iter().map(|r| (*r).to_owned()).collect(),
        ..PullOptions::default()
    };
    repo.pull_with_session(session, trust, opts).await.unwrap();
    repo
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

/// Returns the signer of [`SECRET_B64`].
fn signer() -> Arc<Ed25519Signer> {
    Arc::new(Ed25519Signer::from_base64(SECRET_B64).unwrap())
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

/// Returns the message of `result` if it is a binding mismatch.
fn mismatch<T: std::fmt::Debug>(result: ostrya::Result<T>) -> String {
    match result {
        Err(Error::Remote(ostrya::remote::Error::BindingMismatch(message))) => message,
        other => panic!("expected BindingMismatch, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Init.
// ---------------------------------------------------------------------------

#[test]
fn init_writes_the_config_with_no_collection_id() {
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let state = server.state();
        assert_eq!(
            state.objects[CONFIG].bytes,
            b"[core]\nrepo_version=1\nmode=archive-z2\n"
        );
        assert!(!state.objects.contains_key(LOCK));
        assert_eq!(state.objects.len(), 1);
    });
}

#[test]
fn init_writes_the_config_with_a_collection_id() {
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), Some(A)).await;
        assert_eq!(
            server.state().objects[CONFIG].bytes,
            format!("[core]\nrepo_version=1\nmode=archive-z2\ncollection-id={A}\n").as_bytes()
        );
    });
}

#[test]
fn a_second_init_is_refused_and_keeps_the_config() {
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), Some(A)).await;
        let repo = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        for id in [None, Some(B)] {
            match repo.init(id, None, false).await {
                Err(Error::InvalidInput(message)) => {
                    assert!(message.contains("holds a config already"), "{message}");
                    assert!(message.contains(ADDRESS), "{message}");
                }
                other => panic!("{other:?}"),
            }
        }
        let state = server.state();
        assert!(
            std::str::from_utf8(&state.objects[CONFIG].bytes)
                .unwrap()
                .contains(A)
        );
        assert!(!state.objects.contains_key(LOCK));
    });
}

#[test]
fn init_refuses_an_invalid_collection_id_before_a_request() {
    block_on(async {
        let server = StandIn::start();
        let repo = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        let long = format!("org.{}", "a".repeat(252));
        for id in ["", "nodot", long.as_str()] {
            assert!(
                matches!(
                    repo.init(Some(id), None, false).await,
                    Err(Error::InvalidInput(_))
                ),
                "{id}"
            );
        }
        assert!(server.state().requests.is_empty());
    });
}

#[test]
fn init_breaks_the_lock_of_a_killed_writer() {
    block_on(async {
        let server = StandIn::start();
        server.state().store(LOCK, DEAD_LOCK.as_bytes());
        let repo = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        assert!(matches!(
            repo.init(None, None, false).await,
            Err(Error::BucketLocked { .. })
        ));
        let broken = repo.init(None, None, true).await.unwrap().unwrap();
        assert_eq!(broken.host.as_deref(), Some("deadhost"));
        assert!(server.state().objects.contains_key(CONFIG));
    });
}

#[test]
fn init_on_seaweedfs() {
    if !seaweed_available("init_on_seaweedfs") {
        return;
    }
    let scratch = TmpDir::new("init-seaweed");
    let server = Seaweed::start(scratch.path(), "bkt");
    block_on(async {
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let repo = BucketRepo::open(&s3).await.unwrap();
        assert_eq!(repo.init(Some(A), None, false).await.unwrap(), None);
        assert!(matches!(
            repo.init(None, None, false).await,
            Err(Error::InvalidInput(_))
        ));
        let config = repo.bucket().get("config", 4096).await.unwrap().unwrap();
        assert_eq!(
            config.bytes,
            format!("[core]\nrepo_version=1\nmode=archive-z2\ncollection-id={A}\n").as_bytes()
        );
        assert_eq!(repo.lock_holder().await.unwrap(), None);
    });
}

#[test]
fn init_on_rclone_is_refused() {
    if !rclone_available("init_on_rclone_is_refused") {
        return;
    }
    let scratch = TmpDir::new("init-rclone");
    let root = scratch.path().join("root");
    std::fs::create_dir_all(root.join("bkt").join("repo")).unwrap();
    let server = Rclone::start(scratch.path(), &root);
    block_on(async {
        let repo = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        let err = repo.init(None, None, false).await.unwrap_err();
        assert!(matches!(err, Error::BucketNoExclusion { .. }), "{err}");
    });
    assert!(!root.join("bkt/repo/config").exists());
    assert!(!root.join("bkt/repo/extensions/ostrya/lock").exists());
}

// ---------------------------------------------------------------------------
// Push.
// ---------------------------------------------------------------------------

#[test]
fn a_push_of_each_mode_pulls_back_with_the_same_objects() {
    let scratch = TmpDir::new("push-s3-modes");
    let src = build_tree(scratch.path());
    block_on(async {
        for mode in common::modes::WRITABLE {
            let server = StandIn::start();
            init(&server.endpoint(), None).await;
            let (_, repo, tip) = repo_of(scratch.path(), mode, &src).await;
            let outcome = push(&repo, &server.endpoint(), opts(&["main"]))
                .await
                .unwrap();
            assert_eq!(outcome.broken_lock, None, "{mode:?}");
            let refs = &outcome.outcome.refs;
            assert_eq!(refs.len(), 1);
            assert_eq!(
                (refs[0].name.as_str(), refs[0].old, refs[0].new),
                ("main", None, Some(tip))
            );
            let stats = outcome.outcome.stats;
            assert_eq!(stats.objects_needed, stats.objects_sent, "{mode:?}");
            assert!(stats.objects_total >= stats.objects_needed, "{mode:?}");
            assert!(stats.bytes_sent > 0, "{mode:?}");
            assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(tip));
            assert!(!server.state().objects.contains_key(LOCK));
            assert_trees_whole(&server);

            let path = scratch
                .path()
                .join(format!("pulled-{}", mode.as_mode_str()));
            let s3 = endpoint(&server.endpoint(), ADDRESS);
            let pulled = pull_back(s3, &path, &["main"], PullTrust::unverified()).await;
            assert_eq!(pulled.resolve_rev("main", false).await.unwrap(), Some(tip));
            let local = objects_of(&repo, &tip).await;
            assert_eq!(objects_of(&pulled, &tip).await, local, "{mode:?}");
            let stored: BTreeSet<String> = keys(&server, "repo/objects/")
                .into_iter()
                .map(|key| key["repo/".len()..].to_owned())
                .collect();
            assert_eq!(stored, local, "{mode:?}");
        }
    });
}

#[test]
fn a_push_of_an_archive_repository_keeps_the_stored_filez_bytes() {
    let scratch = TmpDir::new("push-s3-filez");
    let src = build_tree(scratch.path());
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let (path, repo, tip) = repo_of(scratch.path(), RepoMode::Archive, &src).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        let files = common::modes::file_objects(&repo, &tip).await;
        assert!(!files.is_empty());
        let state = server.state();
        for file in files {
            let local = std::fs::read(path.join(object_path(ObjectType::File, &file))).unwrap();
            assert_eq!(state.objects[&key(ObjectType::File, &file)].bytes, local);
        }
    });
}

/// The stored `.filez` of an `archive` repository goes up as it is, at the
/// level of the repository, also when the `config` of the bucket names
/// another level. A push from a `bare-user` repository builds each `.filez`
/// at the level of the bucket, which gives other bytes.
#[test]
fn a_push_of_an_archive_repository_keeps_its_level_over_the_level_of_the_bucket() {
    let scratch = TmpDir::new("push-s3-filez-level");
    let src = build_tree(scratch.path());
    let text: Vec<u8> = (0..20_000u32)
        .flat_map(|i| format!("line {} of a text file\n", i % 977).into_bytes())
        .collect();
    std::fs::write(src.join("text"), text).unwrap();
    block_on(async {
        let path = scratch.path().join("archive-level-1");
        drop(
            Repo::create(&path, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap(),
        );
        let config = path.join("config");
        let mut config_text = std::fs::read_to_string(&config).unwrap();
        config_text.push_str("\n[archive]\nzlib-level=1\n");
        std::fs::write(&config, config_text).unwrap();
        let repo = Repo::open(&path).await.unwrap();
        let tip = common::modes::commit(&repo, &src).await;
        let (_, built_repo, built_tip) = repo_of(scratch.path(), RepoMode::BareUser, &src).await;
        assert_eq!(built_tip, tip);

        let stored = StandIn::start();
        let built = StandIn::start();
        for server in [&stored, &built] {
            let bucket = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
                .await
                .unwrap();
            assert_eq!(bucket.init(None, Some(9), false).await.unwrap(), None);
        }
        push(&repo, &stored.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        push(&built_repo, &built.endpoint(), opts(&["main"]))
            .await
            .unwrap();

        let files = common::modes::file_objects(&repo, &tip).await;
        assert!(!files.is_empty());
        let (stored, built) = (stored.state(), built.state());
        let mut rebuilt = 0;
        for file in files {
            let local = std::fs::read(path.join(object_path(ObjectType::File, &file))).unwrap();
            let file_key = key(ObjectType::File, &file);
            assert_eq!(stored.objects[&file_key].bytes, local, "{file}");
            if built.objects[&file_key].bytes != local {
                rebuilt += 1;
            }
        }
        // The level of the bucket gives other bytes for a file that DEFLATE
        // shrinks.
        assert!(rebuilt > 0);
    });
}

#[test]
fn a_push_to_a_bucket_with_no_config_is_refused() {
    let scratch = TmpDir::new("push-s3-no-config");
    block_on(async {
        let server = StandIn::start();
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", None).await;
        let message = refused(push(&repo, &server.endpoint(), opts(&["main"])).await);
        assert_eq!(
            message,
            format!("the bucket repository {ADDRESS} has no config; init it first")
        );
        assert_eq!(
            puts(&server),
            ["repo/extensions/ostrya/lock", "repo/extensions/ostrya/lock"]
        );
        assert!(server.state().objects.is_empty());
    });
}

#[test]
fn a_push_and_a_pull_on_seaweedfs() {
    if !seaweed_available("a_push_and_a_pull_on_seaweedfs") {
        return;
    }
    let scratch = TmpDir::new("push-s3-seaweed");
    let src = build_tree(scratch.path());
    let server = Seaweed::start(scratch.path(), "bkt");
    block_on(async {
        init(&server.endpoint(), None).await;
        let (_, repo, tip) = repo_of(scratch.path(), RepoMode::BareUserOnly, &src).await;
        let outcome = push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        assert_eq!(outcome.outcome.refs[0].new, Some(tip));
        // A second push changes no ref and uploads no object.
        let again = push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        assert_eq!(again.outcome.stats.objects_sent, 0);
        assert_eq!(again.outcome.refs[0].old, Some(tip));
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let pulled = pull_back(
            s3,
            &scratch.path().join("pulled"),
            &["main"],
            PullTrust::unverified(),
        )
        .await;
        assert_eq!(pulled.resolve_rev("main", false).await.unwrap(), Some(tip));
        assert_eq!(
            objects_of(&pulled, &tip).await,
            objects_of(&repo, &tip).await
        );
    });
}

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

#[test]
fn a_multipart_push_on_seaweedfs() {
    if !seaweed_available("a_multipart_push_on_seaweedfs") {
        return;
    }
    let scratch = TmpDir::new("push-s3-multipart");
    let src = scratch.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("large"), incompressible(12 << 20)).unwrap();
    let server = Seaweed::start(scratch.path(), "bkt");
    block_on(async {
        init(&server.endpoint(), None).await;
        let (path, repo, tip) = repo_of(scratch.path(), RepoMode::Archive, &src).await;
        let files = common::modes::file_objects(&repo, &tip).await;
        let large = std::fs::metadata(path.join(object_path(ObjectType::File, &files[0])))
            .unwrap()
            .len();
        assert!(large > 10 << 20, "three parts of 5 MiB: {large}");
        let push_opts = RepoPushOptions {
            part_size: Some(5 << 20),
            ..opts(&["main"])
        };
        push(&repo, &server.endpoint(), push_opts).await.unwrap();
        let bucket = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        let listing = bucket.list_objects().await.unwrap();
        let name = ostrya::ObjectName::new(files[0], ObjectType::File);
        assert_eq!(listing.objects[&name], large);
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let pulled = pull_back(
            s3,
            &scratch.path().join("pulled"),
            &["main"],
            PullTrust::unverified(),
        )
        .await;
        assert_eq!(pulled.resolve_rev("main", false).await.unwrap(), Some(tip));
        assert!(
            pulled
                .has_object(ObjectType::File, &files[0])
                .await
                .unwrap()
        );
    });
}

#[test]
fn a_multipart_push_of_a_built_filez_on_seaweedfs() {
    if !seaweed_available("a_multipart_push_of_a_built_filez_on_seaweedfs") {
        return;
    }
    let scratch = TmpDir::new("push-s3-multipart-built");
    let src = scratch.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("large"), incompressible(12 << 20)).unwrap();
    let server = Seaweed::start(scratch.path(), "bkt");
    block_on(async {
        init(&server.endpoint(), None).await;
        // The push builds the `.filez` of a `bare-user` repository, so the
        // view gives no length.
        let (_, repo, tip) = repo_of(scratch.path(), RepoMode::BareUser, &src).await;
        let files = common::modes::file_objects(&repo, &tip).await;
        let push_opts = RepoPushOptions {
            part_size: Some(5 << 20),
            ..opts(&["main"])
        };
        push(&repo, &server.endpoint(), push_opts).await.unwrap();
        let bucket = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        let listing = bucket.list_objects().await.unwrap();
        let name = ostrya::ObjectName::new(files[0], ObjectType::File);
        assert!(listing.objects[&name] > 10 << 20, "three parts of 5 MiB");
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let path = scratch.path().join("pulled");
        let pulled = pull_back(s3, &path, &["main"], PullTrust::unverified()).await;
        assert_eq!(pulled.resolve_rev("main", false).await.unwrap(), Some(tip));
        // The pull checks the checksum of each object it stores.
        assert_eq!(
            objects_of(&pulled, &tip).await,
            objects_of(&repo, &tip).await
        );
    });
}

#[test]
fn a_second_push_with_no_change_uploads_no_object_and_writes_no_ref() {
    let scratch = TmpDir::new("push-s3-again");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        repo.sign_commit(&tip, signer().as_ref()).await.unwrap();
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        assert!(
            server
                .state()
                .objects
                .contains_key(&key(ObjectType::CommitMeta, &tip))
        );
        server.state().requests.clear();
        let outcome = push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        assert_eq!(
            puts(&server),
            ["repo/extensions/ostrya/lock", "repo/extensions/ostrya/lock"]
        );
        assert_eq!(outcome.outcome.stats.objects_needed, 0);
        assert_eq!(outcome.outcome.refs[0].old, Some(tip));
    });
}

#[test]
fn a_push_of_a_commit_that_the_bucket_holds_reads_no_tree() {
    let scratch = TmpDir::new("push-s3-held-commit");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        // With no root dirtree in the local repository, a walk of the tree
        // of the commit fails.
        let stored =
            std::fs::read(repo.path().join(object_path(ObjectType::Commit, &tip))).unwrap();
        let root = Commit::parse(&stored).unwrap().root_dirtree;
        std::fs::remove_file(repo.path().join(object_path(ObjectType::DirTree, &root))).unwrap();
        server.state().requests.clear();
        let outcome = push(&repo, &server.endpoint(), opts(&["main:other"]))
            .await
            .unwrap();
        assert_eq!(outcome.outcome.stats.objects_needed, 0);
        assert_eq!(
            puts(&server),
            [
                "repo/extensions/ostrya/lock",
                "repo/extensions/ostrya/lock",
                "repo/refs/heads/other"
            ]
        );
        assert_eq!(ref_of(&server, "repo/refs/heads/other"), Some(tip));
    });
}

#[test]
fn a_push_after_a_new_signature_uploads_the_commitmeta_alone() {
    let scratch = TmpDir::new("push-s3-resign");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        let meta = key(ObjectType::CommitMeta, &tip);
        assert!(!server.state().objects.contains_key(&meta));
        repo.sign_commit(&tip, signer().as_ref()).await.unwrap();
        server.state().requests.clear();
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        let meta_target = meta["repo/".len()..].to_owned();
        assert_eq!(
            puts(&server),
            [
                "repo/extensions/ostrya/lock".to_owned(),
                "repo/extensions/ostrya/lock".to_owned(),
                format!("repo/{meta_target}")
            ]
        );
        let local =
            std::fs::read(repo.path().join(object_path(ObjectType::CommitMeta, &tip))).unwrap();
        assert_eq!(server.state().objects[&meta].bytes, local);
    });
}

/// Writes the detached metadata `keys` with string values to `commit`.
async fn detached(repo: &Repo, commit: &Checksum, keys: &[&str]) {
    let mut dict = DictBuilder::new();
    for key in keys {
        dict.insert_str(key, "value");
    }
    repo.write_commit_detached_metadata(commit, Some(&dict.build()))
        .await
        .unwrap();
}

#[test]
fn the_commitmeta_goes_without_the_excluded_keys() {
    let scratch = TmpDir::new("push-s3-filter");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        detached(&repo, &tip, &["keep", "secret"]).await;
        let filtered = || RepoPushOptions {
            detached_metadata_filter: DetachedMetadataFilter::excluding(["secret"]),
            ..opts(&["main"])
        };
        push(&repo, &server.endpoint(), filtered()).await.unwrap();
        let meta = key(ObjectType::CommitMeta, &tip);
        let stored = server.state().objects[&meta].bytes.clone();
        let ty = ostrya::Type::parse("a{sv}").unwrap();
        let dict = ostrya::from_bytes(&ty, &stored).unwrap();
        assert!(dict.dict_get("keep").is_some());
        assert!(dict.dict_get("secret").is_none());
        // The bucket holds the filtered bytes, so a second push skips them.
        server.state().requests.clear();
        push(&repo, &server.endpoint(), filtered()).await.unwrap();
        assert!(!puts(&server).iter().any(|t| t.ends_with(".commitmeta")));
    });
}

#[test]
fn a_commitmeta_that_the_filter_empties_is_not_uploaded() {
    let scratch = TmpDir::new("push-s3-empty-filter");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        detached(&repo, &tip, &["secret"]).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        let meta = key(ObjectType::CommitMeta, &tip);
        let first = server.state().objects[&meta].clone();
        server.state().requests.clear();
        let filtered = RepoPushOptions {
            detached_metadata_filter: DetachedMetadataFilter::excluding(["secret"]),
            ..opts(&["main"])
        };
        push(&repo, &server.endpoint(), filtered).await.unwrap();
        assert!(!puts(&server).iter().any(|t| t.ends_with(".commitmeta")));
        assert_eq!(server.state().objects[&meta], first);
    });
}

#[test]
fn an_interrupted_push_leaves_whole_trees_and_a_run_again_completes() {
    let scratch = TmpDir::new("push-s3-interrupted");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        let files = common::modes::file_objects(&repo, &tip).await;
        // A refused upload of a file object.
        server.state().refuse = Some(("PUT", key(ObjectType::File, &files[0])));
        let err = push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("AccessDenied"), "{err}");
        assert!(keys(&server, "repo/refs/").is_empty());
        assert!(
            !server
                .state()
                .objects
                .contains_key(&key(ObjectType::Commit, &tip))
        );
        assert!(!server.state().objects.contains_key(LOCK));
        assert_trees_whole(&server);
        // A refused upload of the commit object.
        server.state().refuse = Some(("PUT", key(ObjectType::Commit, &tip)));
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap_err();
        assert!(keys(&server, "repo/refs/").is_empty());
        assert!(
            server
                .state()
                .objects
                .contains_key(&key(ObjectType::File, &files[0]))
        );
        assert!(!server.state().objects.contains_key(LOCK));
        assert_trees_whole(&server);
        // A run again uploads the rest.
        server.state().refuse = None;
        server.state().requests.clear();
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        assert_eq!(
            puts(&server),
            [
                "repo/extensions/ostrya/lock".to_owned(),
                "repo/extensions/ostrya/lock".to_owned(),
                key(ObjectType::Commit, &tip),
                "repo/refs/heads/main".to_owned()
            ]
        );
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(tip));
        assert_trees_whole(&server);
    });
}

/// Returns the target of each `PUT` of `server` to an object key.
fn object_puts(server: &StandIn) -> Vec<String> {
    puts(server)
        .into_iter()
        .filter(|target| target.starts_with("repo/objects/"))
        .collect()
}

#[test]
fn no_upload_starts_after_the_first_failed_upload() {
    let scratch = TmpDir::new("push-s3-no-new-upload");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        detached(&repo, &tip, &["keep"]).await;
        server.state().refuse = Some(("PUT", "repo/objects/".to_owned()));
        let err = push_bounded(&repo, &server.endpoint(), opts(&["main"]), 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("AccessDenied"), "{err}");
        // One upload at a time: the first one fails, and no other starts.
        assert_eq!(object_puts(&server).len(), 1, "{:?}", object_puts(&server));
        assert!(keys(&server, "repo/refs/").is_empty());
        assert!(!server.state().objects.contains_key(LOCK));
    });
}

#[test]
fn the_uploads_in_flight_end_before_a_failed_push_returns() {
    let scratch = TmpDir::new("push-s3-in-flight");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        let files = common::modes::file_objects(&repo, &tip).await;
        assert_eq!(files.len(), 2);
        let refused = key(ObjectType::File, &files[0]);
        let slow = key(ObjectType::File, &files[1]);
        {
            let mut state = server.state();
            state.refuse = Some(("PUT", refused.clone()));
            state.delay = Some(("PUT", slow.clone(), Duration::from_secs(1)));
        }
        // Each upload of the tree starts at once, so the slow upload is in
        // flight when the refused one fails.
        let err = push_bounded(&repo, &server.endpoint(), opts(&["main"]), 64)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("AccessDenied"), "{err}");
        let state = server.state();
        assert!(state.objects.contains_key(&slow), "the push did not wait");
        assert!(!state.objects.contains_key(&refused));
        assert!(!state.objects.contains_key(&key(ObjectType::Commit, &tip)));
        assert!(!state.objects.contains_key(LOCK));
    });
}

#[test]
fn a_failure_at_the_refs_leaves_some_refs_and_a_run_again_writes_the_rest() {
    let scratch = TmpDir::new("push-s3-ref-failure");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        server.state().refuse = Some(("PUT", "repo/refs/heads/b".to_owned()));
        push(&repo, &server.endpoint(), opts(&["main:a", "main:b"]))
            .await
            .unwrap_err();
        assert_eq!(ref_of(&server, "repo/refs/heads/a"), Some(tip));
        assert_eq!(ref_of(&server, "repo/refs/heads/b"), None);
        assert!(!server.state().objects.contains_key(LOCK));
        server.state().refuse = None;
        server.state().requests.clear();
        let outcome = push(&repo, &server.endpoint(), opts(&["main:a", "main:b"]))
            .await
            .unwrap();
        assert_eq!(
            puts(&server),
            [
                "repo/extensions/ostrya/lock",
                "repo/extensions/ostrya/lock",
                "repo/refs/heads/b"
            ]
        );
        let olds: Vec<Option<Checksum>> = outcome.outcome.refs.iter().map(|r| r.old).collect();
        assert_eq!(olds, [Some(tip), None]);
        assert_eq!(ref_of(&server, "repo/refs/heads/b"), Some(tip));
    });
}

#[test]
fn a_lock_broken_before_the_refs_stops_the_push() {
    let scratch = TmpDir::new("push-s3-lost-refs");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        server.state().before_key = Some(("PUT", key(ObjectType::Commit, &tip), replace_lock()));
        let err = push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BucketLockLost { .. }), "{err}");
        assert!(keys(&server, "repo/refs/").is_empty());
        assert_eq!(server.state().objects[LOCK].bytes, DEAD_LOCK.as_bytes());
        assert_trees_whole(&server);
    });
}

/// A lock that another writer takes during the ref writes fails the
/// release, and the push removes no lock.
#[test]
fn a_lock_broken_during_the_ref_writes_fails_the_release() {
    let scratch = TmpDir::new("push-s3-lost-release");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        server.state().before_key = Some(("PUT", "repo/refs/heads/b".to_owned(), replace_lock()));
        let err = push(&repo, &server.endpoint(), opts(&["main:a", "main:b"]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BucketLockLost { .. }), "{err}");
        assert_eq!(ref_of(&server, "repo/refs/heads/b"), Some(tip));
        assert_eq!(server.state().objects[LOCK].bytes, DEAD_LOCK.as_bytes());
    });
}

#[test]
fn a_failed_release_leaves_the_lock_and_break_lock_removes_it() {
    let scratch = TmpDir::new("push-s3-release");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        server.state().refuse = Some(("DELETE", LOCK.to_owned()));
        let err = push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("AccessDenied"), "{err}");
        // The refs are written.
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(tip));
        server.state().refuse = None;
        let held = match push(&repo, &server.endpoint(), opts(&["main"])).await {
            Err(Error::BucketLocked { holder, .. }) => *holder.expect("the holder"),
            other => panic!("{other:?}"),
        };
        assert_eq!(held.pid, Some(std::process::id()));
        let broken = RepoPushOptions {
            break_lock: true,
            ..opts(&["main"])
        };
        let outcome = push(&repo, &server.endpoint(), broken).await.unwrap();
        assert_eq!(outcome.broken_lock, Some(held));
        assert!(!server.state().objects.contains_key(LOCK));
    });
}

#[test]
fn a_push_to_a_server_that_ignores_if_none_match_changes_nothing() {
    let scratch = TmpDir::new("push-s3-no-exclusion");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        server.state().honor_if_none_match = false;
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", None).await;
        let err = push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BucketNoExclusion { .. }), "{err}");
        let all = keys(&server, "repo/");
        assert_eq!(all, [CONFIG]);
    });
}

#[test]
fn a_push_on_rclone_is_refused() {
    if !rclone_available("a_push_on_rclone_is_refused") {
        return;
    }
    let scratch = TmpDir::new("push-s3-rclone");
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
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", None).await;
        let err = push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BucketNoExclusion { .. }), "{err}");
    });
    for path in ["objects", "refs", "summary", "extensions/ostrya/lock"] {
        assert!(!bucket.join(path).exists(), "{path}");
    }
}

#[test]
fn a_wrong_secret_gives_signature_does_not_match() {
    if !seaweed_available("a_wrong_secret_gives_signature_does_not_match") {
        return;
    }
    let scratch = TmpDir::new("push-s3-wrong-secret");
    let server = Seaweed::start(scratch.path(), "bkt");
    block_on(async {
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", None).await;
        let mut s3 = endpoint(&server.endpoint(), ADDRESS);
        s3.credentials = ostrya::remote::s3::Credentials::new(
            common::s3::ACCESS_KEY.into(),
            "wrong-secret-key".into(),
            None,
        )
        .unwrap();
        let err = repo.push_to_bucket(s3, opts(&["main"])).await.unwrap_err();
        match &err {
            Error::Remote(ostrya::remote::Error::S3 { code, .. }) => {
                assert_eq!(code.as_deref(), Some("SignatureDoesNotMatch"), "{err}")
            }
            other => panic!("{other:?}"),
        }
    });
}

/// A push writes no summary. A summary and a signature that the bucket holds
/// stay as they are, and a pull of a named ref reads the ref file.
#[test]
fn a_push_writes_no_summary_and_keeps_an_existing_one() {
    let scratch = TmpDir::new("push-s3-keeps-summary");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        assert!(!server.state().objects.contains_key("repo/summary"));
        assert!(!server.state().objects.contains_key("repo/summary.sig"));
        {
            let mut state = server.state();
            state.store("repo/summary", b"old summary");
            state.store("repo/summary.sig", b"old signature");
        }
        let before = server.state().objects.clone();
        let next = commit(&repo, "main", Some(tip), "two", None).await;
        server.state().requests.clear();
        push(&repo, &server.endpoint(), opts(&["main", "main:other"]))
            .await
            .unwrap();
        assert!(!puts(&server).iter().any(|t| t.contains("summary")));
        for key in ["repo/summary", "repo/summary.sig"] {
            assert_eq!(server.state().objects[key], before[key], "{key}");
        }
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(next));
        // With no summary, the pull reads the ref files.
        server.state().objects.remove("repo/summary");
        server.state().objects.remove("repo/summary.sig");
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let path = scratch.path().join("pulled");
        let pulled = pull_back(s3, &path, &["main", "other"], PullTrust::unverified()).await;
        assert_eq!(pulled.resolve_rev("main", false).await.unwrap(), Some(next));
        assert_eq!(
            pulled.resolve_rev("other", false).await.unwrap(),
            Some(next)
        );
    });
}

#[test]
fn a_push_that_is_not_a_fast_forward_is_refused_unless_forced() {
    let scratch = TmpDir::new("push-s3-ff");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let first = commit(&repo, "main", None, "one", None).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        let second = commit(&repo, "main", Some(first), "two", None).await;
        let outcome = push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        assert_eq!(
            (outcome.outcome.refs[0].old, outcome.outcome.refs[0].new),
            (Some(first), Some(second))
        );
        let other = commit(&repo, "other", None, "unrelated", None).await;
        match push(&repo, &server.endpoint(), opts(&["other:main"])).await {
            Err(Error::Remote(ostrya::remote::Error::NonFastForward(message))) => {
                assert!(message.contains("ref 'refs/heads/main'"), "{message}");
                assert!(message.contains(&second.to_string()), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(second));
        let forced = RepoPushOptions {
            force: true,
            ..opts(&["other:main"])
        };
        push(&repo, &server.endpoint(), forced).await.unwrap();
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(other));
    });
}

#[test]
fn the_options_of_another_transport_are_refused_before_a_request() {
    let scratch = TmpDir::new("push-s3-options");
    block_on(async {
        let server = StandIn::start();
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", None).await;
        for o in [
            RepoPushOptions {
                tags: vec!["v1".into()],
                ..opts(&["main"])
            },
            RepoPushOptions {
                compression: Compression::Deflate { level: 6 },
                ..opts(&["main"])
            },
            opts(&["main", ":old"]),
        ] {
            refused(push(&repo, &server.endpoint(), o).await);
        }
        assert!(server.state().requests.is_empty());
    });
}

#[test]
fn a_ref_that_is_a_directory_prefix_of_another_is_refused() {
    let scratch = TmpDir::new("push-s3-prefix");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", None).await;
        commit(&repo, "bound", None, "bound", bound(B)).await;
        push(&repo, &server.endpoint(), opts(&["main:a"]))
            .await
            .unwrap();
        let message = refused(push(&repo, &server.endpoint(), opts(&["main:a/b"])).await);
        assert!(message.contains("is a directory of the ref"), "{message}");
        refused(push(&repo, &server.endpoint(), opts(&["main:x", "main:x/y"])).await);
        // A mirror directory is a directory of its own.
        push(&repo, &server.endpoint(), opts(&["bound:a/b"]))
            .await
            .unwrap();
        assert!(
            server
                .state()
                .objects
                .contains_key(&format!("repo/refs/mirrors/{B}/a/b"))
        );
        refused(push(&repo, &server.endpoint(), opts(&["bound:a"])).await);
    });
}

#[test]
fn push_onto_refuses_an_s3_endpoint() {
    let scratch = TmpDir::new("push-s3-onto");
    block_on(async {
        let server = StandIn::start();
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", None).await;
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let o = PushOntoOptions {
            rev: "main".into(),
            onto: "main".into(),
            ..PushOntoOptions::default()
        };
        let message = refused(repo.push_onto(Endpoint::S3(s3), o).await);
        assert!(message.contains("is an s3:// address"), "{message}");
        assert!(server.state().requests.is_empty());
    });
}

/// `Repo::push` with an `Endpoint::S3` goes to the push to a bucket
/// repository.
#[test]
fn repo_push_with_an_s3_endpoint_writes_the_bucket() {
    let scratch = TmpDir::new("push-s3-repo-push");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let outcome = repo.push(Endpoint::S3(s3), opts(&["main"])).await.unwrap();
        assert_eq!(outcome.refs[0].new, Some(tip));
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(tip));
    });
}

// ---------------------------------------------------------------------------
// Collections.
// ---------------------------------------------------------------------------

#[test]
fn a_push_into_the_primary_collection_writes_refs_heads() {
    let scratch = TmpDir::new("push-s3-primary");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), Some(A)).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", bound(A)).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        let named = RepoPushOptions {
            collection: Some(A.into()),
            ..opts(&["main:other"])
        };
        push(&repo, &server.endpoint(), named).await.unwrap();
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(tip));
        assert_eq!(ref_of(&server, "repo/refs/heads/other"), Some(tip));
        assert!(keys(&server, "repo/refs/mirrors/").is_empty());
    });
}

#[test]
fn an_unbound_commit_goes_to_refs_heads_of_a_bucket_with_an_id() {
    let scratch = TmpDir::new("push-s3-unbound");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), Some(A)).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(tip));
    });
}

#[test]
fn a_push_into_a_mirror_namespace_writes_refs_mirrors() {
    let scratch = TmpDir::new("push-s3-mirror");
    block_on(async {
        for bucket_id in [Some(A), None] {
            let server = StandIn::start();
            init(&server.endpoint(), bucket_id).await;
            let repo = archive(&scratch.path().join(format!("src-{bucket_id:?}"))).await;
            let tip = commit(&repo, "main", None, "one", bound(B)).await;
            push(&repo, &server.endpoint(), opts(&["main"]))
                .await
                .unwrap();
            assert_eq!(
                ref_of(&server, &format!("repo/refs/mirrors/{B}/main")),
                Some(tip)
            );
            assert!(keys(&server, "repo/refs/heads/").is_empty());
            assert_trees_whole(&server);
            let stored: BTreeSet<String> = keys(&server, "repo/objects/")
                .into_iter()
                .map(|key| key["repo/".len()..].to_owned())
                .collect();
            assert_eq!(stored, objects_of(&repo, &tip).await);
        }
    });
}

#[test]
fn a_mirror_ref_is_fast_forward_checked_in_its_own_namespace() {
    let scratch = TmpDir::new("push-s3-mirror-ff");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let local = commit(&repo, "main", None, "local", None).await;
        let mirrored = commit(&repo, "mirrored", None, "mirrored", bound(B)).await;
        push(&repo, &server.endpoint(), opts(&["main", "mirrored:main"]))
            .await
            .unwrap_err();
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        push(&repo, &server.endpoint(), opts(&["mirrored:main"]))
            .await
            .unwrap();
        // Each namespace has its own tip of `main`.
        let next = commit(&repo, "mirrored", Some(mirrored), "next", bound(B)).await;
        let outcome = push(&repo, &server.endpoint(), opts(&["mirrored:main"]))
            .await
            .unwrap();
        assert_eq!(outcome.outcome.refs[0].old, Some(mirrored));
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(local));
        assert_eq!(
            ref_of(&server, &format!("repo/refs/mirrors/{B}/main")),
            Some(next)
        );
        let unrelated = commit(&repo, "unrelated", None, "unrelated", bound(B)).await;
        match push(&repo, &server.endpoint(), opts(&["unrelated:main"])).await {
            Err(Error::Remote(ostrya::remote::Error::NonFastForward(message))) => {
                assert!(
                    message.contains(&format!("ref 'refs/mirrors/{B}/main'")),
                    "{message}"
                );
            }
            other => panic!("{other:?}"),
        }
        let forced = RepoPushOptions {
            force: true,
            ..opts(&["unrelated:main"])
        };
        push(&repo, &server.endpoint(), forced).await.unwrap();
        assert_eq!(
            ref_of(&server, &format!("repo/refs/mirrors/{B}/main")),
            Some(unrelated)
        );
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(local));
    });
}

#[test]
fn a_bound_commit_into_another_namespace_is_refused() {
    let scratch = TmpDir::new("push-s3-other-namespace");
    block_on(async {
        let server = StandIn::start();
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", bound(B)).await;
        let o = RepoPushOptions {
            collection: Some(C.into()),
            ..opts(&["main"])
        };
        let message = mismatch(push(&repo, &server.endpoint(), o).await);
        assert!(message.contains(B) && message.contains(C), "{message}");
        assert!(server.state().requests.is_empty());
    });
}

#[test]
fn an_unbound_commit_into_a_mirror_namespace_is_refused() {
    let scratch = TmpDir::new("push-s3-unbound-mirror");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), Some(A)).await;
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", None).await;
        let o = RepoPushOptions {
            collection: Some(B.into()),
            ..opts(&["main"])
        };
        let message = mismatch(push(&repo, &server.endpoint(), o).await);
        assert!(message.contains("has no collection binding"), "{message}");
        assert!(keys(&server, "repo/objects/").is_empty());
        assert!(!server.state().objects.contains_key(LOCK));
    });
}

#[test]
fn two_sources_with_different_bindings_are_refused() {
    let scratch = TmpDir::new("push-s3-two-bindings");
    block_on(async {
        let server = StandIn::start();
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "bound-b", None, "b", bound(B)).await;
        commit(&repo, "bound-c", None, "c", bound(C)).await;
        mismatch(push(&repo, &server.endpoint(), opts(&["bound-b", "bound-c"])).await);
        assert!(server.state().requests.is_empty());
    });
}

#[test]
fn a_commit_bound_to_another_id_than_the_bucket_is_refused_in_refs_heads() {
    let scratch = TmpDir::new("push-s3-other-id");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), Some(A)).await;
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", bound("org.example.A2")).await;
        let o = RepoPushOptions {
            collection: Some(A.into()),
            ..opts(&["main"])
        };
        mismatch(push(&repo, &server.endpoint(), o).await);
        assert!(keys(&server, "repo/refs/").is_empty());
    });
}

/// Pushes `main` of a new repository to a bucket whose config and objects
/// are `seed`, and returns the result.
fn push_onto_seed(
    tag: &str,
    config: &str,
    seed: &[(&str, &[u8])],
) -> (StandIn, ostrya::Result<BucketPushOutcome>) {
    let scratch = TmpDir::new(tag);
    let server = StandIn::start();
    server.state().store(CONFIG, config.as_bytes());
    for (key, bytes) in seed {
        server.state().store(key, bytes);
    }
    let result = block_on(async {
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", None).await;
        push(&repo, &server.endpoint(), opts(&["main"])).await
    });
    (server, result)
}

const PLAIN: &str = "[core]\nrepo_version=1\nmode=archive-z2\n";

/// Asserts that a push refused by the state of the bucket changed nothing.
fn assert_unchanged(server: &StandIn) {
    assert!(keys(server, "repo/objects/").is_empty());
    assert!(!server.state().objects.contains_key("repo/summary"));
    assert!(!server.state().objects.contains_key(LOCK));
}

#[test]
fn a_key_under_refs_heads_that_is_no_ref_name_refuses_the_push() {
    let ref_body = format!("{}\n", "ab".repeat(32));
    let (server, result) = push_onto_seed(
        "push-s3-bad-head",
        PLAIN,
        &[("repo/refs/heads/-x", ref_body.as_bytes())],
    );
    let message = malformed(result);
    assert!(message.contains("refs/heads/-x"), "{message}");
    assert_unchanged(&server);
}

/// Returns the keys under `refs/` that `server` got a `GET` of, and the
/// prefixes under `refs/` that it listed, without the prefix of the
/// repository.
fn ref_reads(server: &StandIn) -> (Vec<String>, BTreeSet<String>) {
    let state = server.state();
    let mut gets = Vec::new();
    let mut lists = BTreeSet::new();
    for (method, target) in &state.requests {
        if method != "GET" {
            continue;
        }
        match target.split_once('?') {
            Some((_, query)) => {
                let prefix = query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("prefix="))
                    .unwrap_or_default()
                    .replace("%2F", "/");
                if let Some(prefix) = prefix.strip_prefix("repo/refs/") {
                    lists.insert(format!("refs/{prefix}"));
                }
            }
            None => {
                if let Some(key) = target.strip_prefix("/bkt/repo/refs/") {
                    gets.push(format!("refs/{key}"));
                }
            }
        }
    }
    gets.sort();
    (gets, lists)
}

/// A push lists and reads the ref directory of its namespace alone, and
/// lists `refs/mirrors/` of the collection id of the bucket. A key or a ref
/// file of another namespace that breaks a rule does not refuse the push.
#[test]
fn a_push_reads_no_ref_file_of_another_namespace() {
    let scratch = TmpDir::new("push-s3-own-namespace");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), Some(A)).await;
        let absent = format!("{}\n", "cd".repeat(32));
        {
            let mut state = server.state();
            state.store("repo/refs/remotes/origin/main", b"x");
            state.store("repo/refs/mirrors/nodot/x", absent.as_bytes());
            state.store(&format!("repo/refs/mirrors/{C}/main"), absent.as_bytes());
            state.store(&format!("repo/refs/mirrors/{C}/bad"), b"bad");
        }
        let repo = archive(&scratch.path().join("src")).await;
        let main = commit(&repo, "main", None, "one", None).await;
        let mirrored = commit(&repo, "bound-b", None, "b", bound(B)).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        push(&repo, &server.endpoint(), opts(&["bound-b:main"]))
            .await
            .unwrap();
        let next = commit(&repo, "main", Some(main), "two", None).await;
        let next_mirrored = commit(&repo, "bound-b", Some(mirrored), "b2", bound(B)).await;

        server.state().requests.clear();
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        let (gets, lists) = ref_reads(&server);
        assert_eq!(gets, ["refs/heads/main"]);
        assert_eq!(
            lists,
            BTreeSet::from(["refs/heads/".to_owned(), format!("refs/mirrors/{A}/")])
        );
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(next));

        server.state().requests.clear();
        push(&repo, &server.endpoint(), opts(&["bound-b:main"]))
            .await
            .unwrap();
        let (gets, lists) = ref_reads(&server);
        assert_eq!(gets, [format!("refs/mirrors/{B}/main")]);
        assert_eq!(
            lists,
            BTreeSet::from([format!("refs/mirrors/{A}/"), format!("refs/mirrors/{B}/")])
        );
        assert_eq!(
            ref_of(&server, &format!("repo/refs/mirrors/{B}/main")),
            Some(next_mirrored)
        );
        // The keys of the other namespaces stay as they are.
        assert_eq!(
            server.state().objects["repo/refs/remotes/origin/main"].bytes,
            b"x"
        );
        assert_eq!(
            server.state().objects[&format!("repo/refs/mirrors/{C}/bad")].bytes,
            b"bad"
        );
    });
}

/// A ref key under `refs/mirrors/` of the collection id of the bucket
/// refuses a push into each namespace.
#[test]
fn the_mirror_refs_of_the_own_collection_id_refuse_the_push() {
    let ref_body = format!("{}\n", "ab".repeat(32));
    let (server, result) = push_onto_seed(
        "push-s3-own-mirror",
        &format!("{PLAIN}collection-id={A}\n"),
        &[(&format!("repo/refs/mirrors/{A}/x"), ref_body.as_bytes())],
    );
    let message = malformed(result);
    assert!(message.contains("its own collection id"), "{message}");
    assert!(
        message.contains(&format!("refs/mirrors/{A}/x")),
        "{message}"
    );
    assert_unchanged(&server);
    let (gets, _) = ref_reads(&server);
    assert!(gets.is_empty(), "{gets:?}");

    let scratch = TmpDir::new("push-s3-own-mirror-into-mirror");
    let result = block_on(async {
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "bound-b", None, "b", bound(B)).await;
        push(&repo, &server.endpoint(), opts(&["bound-b:main"])).await
    });
    let message = malformed(result);
    assert!(message.contains("its own collection id"), "{message}");
    assert_unchanged(&server);
}

#[test]
fn a_malformed_ref_file_refuses_the_push() {
    let hex = "ab".repeat(32);
    for body in [
        hex.clone(),
        format!("{}\n", hex.to_uppercase()),
        format!("{}\n", &hex[..63]),
        format!("{hex}\nmore"),
    ] {
        let (server, result) = push_onto_seed(
            "push-s3-bad-ref",
            PLAIN,
            &[("repo/refs/heads/other", body.as_bytes())],
        );
        let message = malformed(result);
        assert!(message.contains("refs/heads/other"), "{body:?}: {message}");
        assert_unchanged(&server);
    }
}

#[test]
fn a_ref_of_the_bucket_whose_commit_is_absent_refuses_the_push() {
    let absent = "cd".repeat(32);
    let (server, result) = push_onto_seed(
        "push-s3-absent-commit",
        PLAIN,
        &[("repo/refs/heads/other", format!("{absent}\n").as_bytes())],
    );
    let message = malformed(result);
    assert!(message.contains(&absent), "{message}");
    assert_unchanged(&server);
}

#[test]
fn a_bucket_config_with_a_bare_mode_refuses_the_push() {
    for config in [
        "[core]\nrepo_version=1\nmode=bare\n".to_owned(),
        format!("{PLAIN}collection-id=nodot\n"),
        "not a key file".to_owned(),
    ] {
        let (server, result) = push_onto_seed("push-s3-bad-config", &config, &[]);
        let message = malformed(result);
        assert!(message.contains("its config"), "{message}");
        assert_unchanged(&server);
    }
}

#[test]
fn a_bucket_config_with_a_value_that_is_no_boolean_refuses_the_push() {
    for key in ["tombstone-commits", "indexed-deltas"] {
        let (server, result) =
            push_onto_seed("push-s3-no-boolean", &format!("{PLAIN}{key}=maybe\n"), &[]);
        let message = malformed(result);
        assert!(message.contains("its config"), "{message}");
        assert!(message.contains(key), "{message}");
        assert_unchanged(&server);
        assert!(keys(&server, "repo/refs/").is_empty());
    }
}

// ---------------------------------------------------------------------------
// The `ostree` command.
// ---------------------------------------------------------------------------

/// The public key of [`SECRET_B64`].
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

/// A public key of no signer of the tests.
const OTHER_PUBLIC_B64: &str = "5WYA48XDLt1Tw6UD6mF5sMzJRCXqpaUjPPrO2C37pto=";

/// Returns `true` if the `ostree` command runs. Else the function writes the
/// reason of the skip of `test` to standard error. With
/// `OSTRYA_REQUIRE_OSTREE` set, an absent command fails the test.
fn tool_available(test: &str) -> bool {
    let found = common::ostree_available();
    if !found {
        eprintln!("skipping {test}: ostree is not installed");
    }
    found
}

/// Runs the `ostree` command with `args`, and returns its output with no
/// check of the exit status.
fn tool(args: &[&str]) -> std::process::Output {
    std::process::Command::new("ostree")
        .args(args)
        .output()
        .unwrap()
}

/// Runs the `ostree` command with `args`, asserts that it succeeds, and
/// returns its standard output.
fn tool_ok(args: &[&str]) -> String {
    let out = tool(args);
    assert!(
        out.status.success(),
        "ostree {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Creates a repository of the `ostree` command at `path` with `mode`, with
/// the remote `w` at `url` and the remote keys `keys`, and returns its
/// `--repo` option. The remote verifies no GPG signature.
fn tool_client(path: &Path, mode: &str, url: &str, keys: &[&str]) -> String {
    let repo = format!("--repo={}", path.display());
    tool_ok(&[&repo, "init", &format!("--mode={mode}")]);
    // The host of the tests can have little free space.
    tool_ok(&[&repo, "config", "set", "core.min-free-space-percent", "0"]);
    let sets: Vec<String> = keys.iter().map(|key| format!("--set={key}")).collect();
    let mut add = vec![repo.as_str(), "remote", "add", "--no-gpg-verify"];
    add.extend(sets.iter().map(String::as_str));
    add.extend(["w", url]);
    tool_ok(&add);
    repo
}

/// Returns the commit that the ref `w:main` of the client `repo` names, or
/// `None`.
fn tool_tip(repo: &str) -> Option<Checksum> {
    let out = tool(&[repo, "rev-parse", "w:main"]);
    out.status
        .success()
        .then(|| Checksum::from_hex(String::from_utf8(out.stdout).unwrap().trim()).unwrap())
}

/// Returns the options of a summary update with the signer of
/// [`SECRET_B64`].
fn signed_summary() -> ostrya::bucket::BucketSummaryOptions {
    let mut opts = ostrya::bucket::BucketSummaryOptions::default();
    opts.summary_signers = vec![signer()];
    opts
}

/// Returns the key of the delta index of `to`, relative to the prefix of the
/// repository.
fn delta_index(to: &Checksum) -> String {
    let b64 = to.to_base64_modified();
    format!("delta-indexes/{}/{}.index", &b64[..2], &b64[2..])
}

/// Returns the key of the superblock of the delta from scratch to `to`,
/// relative to the prefix of the repository.
fn scratch_superblock(to: &Checksum) -> String {
    let b64 = to.to_base64_modified();
    format!("deltas/{}/{}/superblock", &b64[..2], &b64[2..])
}

/// Returns the keys that `server` got a request for, relative to the
/// prefix of the repository. Asserts that each request is a `GET` with no
/// `Authorization` header.
fn unsigned_reads(server: &StandIn) -> Vec<String> {
    let state = server.state();
    state
        .requests
        .iter()
        .zip(&state.authorizations)
        .map(|((method, target), authorization)| {
            assert_eq!(method, "GET", "{target}");
            assert_eq!(*authorization, None, "{target}");
            target.strip_prefix("/bkt/repo/").unwrap().to_owned()
        })
        .collect()
}

/// Inits the bucket repository of `server`, pushes a commit of `content` on
/// `main` from a new repository in `scratch`, and returns the commit. With
/// `summary` set, a summary update follows the push. The requests of the
/// setup are then cleared.
async fn pushed(scratch: &Path, server: &StandIn, content: &str, summary: bool) -> Checksum {
    init(&server.endpoint(), None).await;
    let repo = archive(&scratch.join(format!("src-{content}"))).await;
    let tip = commit(&repo, "main", None, content, None).await;
    push(&repo, &server.endpoint(), opts(&["main"]))
        .await
        .unwrap();
    if summary {
        let bucket = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        let opts = ostrya::bucket::BucketSummaryOptions::default();
        bucket.update_summary(&opts).await.unwrap();
    }
    let mut state = server.state();
    state.requests.clear();
    state.authorizations.clear();
    tip
}

/// The `ostree` command reads a 403 for `summary.sig`, `summary`, the delta
/// index, the superblock of a delta, and a `.commitmeta` as an absent key,
/// and the pull goes on. A 403 for `config` after a summary fails the pull.
/// So a pull over the anonymous policy of a bucket needs no
/// `s3:ListBucket`.
#[test]
fn the_ostree_command_reads_a_403_as_an_absent_key_and_fails_on_config_alone() {
    if !tool_available("the_ostree_command_reads_a_403_as_an_absent_key_and_fails_on_config_alone")
    {
        return;
    }
    let scratch = TmpDir::new("push-s3-tool-403");
    let with_summary = StandIn::start();
    let no_summary = StandIn::start();
    let (tip_with, tip_without) = block_on(async {
        (
            pushed(scratch.path(), &with_summary, "with", true).await,
            pushed(scratch.path(), &no_summary, "without", false).await,
        )
    });
    // The case, whether the bucket holds a summary, and the refused key, or
    // `None` for a 403 for each absent key.
    let cases = [
        ("summary.sig", true, Some("summary.sig")),
        ("config", true, Some("config")),
        ("index", true, Some("index")),
        ("commitmeta", true, Some("commitmeta")),
        ("superblock", false, Some("superblock")),
        ("absent keys with a summary", true, None),
        ("absent keys with no summary", false, None),
    ];
    for (n, (case, summary, refused)) in cases.into_iter().enumerate() {
        let (server, tip) = if summary {
            (&with_summary, tip_with)
        } else {
            (&no_summary, tip_without)
        };
        let commitmeta = object_path(ObjectType::CommitMeta, &tip);
        // The first requests of the pull.
        let first = if summary {
            ["summary.sig", "summary", "config"]
                .map(str::to_owned)
                .to_vec()
        } else {
            ["summary.sig", "summary", "refs/heads/main"]
                .map(str::to_owned)
                .to_vec()
        };
        let delta = if summary {
            delta_index(&tip)
        } else {
            scratch_superblock(&tip)
        };
        let first: Vec<String> = first
            .into_iter()
            .chain([
                delta,
                commitmeta.clone(),
                object_path(ObjectType::Commit, &tip),
            ])
            .collect();
        {
            let mut state = server.state();
            state.requests.clear();
            state.authorizations.clear();
            state.refuse = None;
            state.forbid_absent = refused.is_none();
            if let Some(key) = refused {
                let key = match key {
                    "index" => delta_index(&tip),
                    "superblock" => scratch_superblock(&tip),
                    "commitmeta" => commitmeta,
                    key => key.to_owned(),
                };
                state.refuse = Some(("GET", format!("repo/{key}")));
            }
        }
        let client = tool_client(
            &scratch.path().join(format!("client-{n}")),
            "bare-user",
            &server.url("repo"),
            &[],
        );
        let out = tool(&[&client, "pull", "w", "main"]);
        let reads = unsigned_reads(server);
        if case == "config" {
            assert_eq!(out.status.code(), Some(1), "{case}");
            assert_eq!(reads, first[..3], "{case}");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains(&format!("{}/config", server.url("repo"))),
                "{stderr}"
            );
            assert_eq!(tool_tip(&client), None, "{case}");
            continue;
        }
        assert!(
            out.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(reads[..first.len()], first, "{case}");
        assert_eq!(tool_tip(&client), Some(tip), "{case}");
    }
}

/// The lock of a writer is in the bucket. The `ostree` command pulls with
/// no signature on a request, and reads no key under `extensions/`.
#[test]
fn the_ostree_command_pulls_from_the_stand_in_with_no_signature_and_reads_no_extensions_key() {
    if !tool_available(
        "the_ostree_command_pulls_from_the_stand_in_with_no_signature_and_reads_no_extensions_key",
    ) {
        return;
    }
    let scratch = TmpDir::new("push-s3-tool-extensions");
    let server = StandIn::start();
    let tip = block_on(pushed(scratch.path(), &server, "one", true));
    server.state().store(LOCK, DEAD_LOCK.as_bytes());
    let client = tool_client(
        &scratch.path().join("client"),
        "archive",
        &server.url("repo"),
        &[],
    );
    tool_ok(&[&client, "pull", "w", "main"]);
    assert_eq!(tool_tip(&client), Some(tip));
    let reads = unsigned_reads(&server);
    assert!(
        reads.iter().all(|key| !key.starts_with("extensions/")),
        "{reads:?}"
    );
}

/// The `ostree` command verifies the ed25519 signature of a summary that
/// the port writes, and refuses the summary under another key.
#[test]
fn the_ostree_command_verifies_an_ed25519_summary_that_the_port_signs() {
    let test = "the_ostree_command_verifies_an_ed25519_summary_that_the_port_signs";
    if !tool_available(test) {
        return;
    }
    if !common::ostree_supports_ed25519() {
        eprintln!("skipping {test}: ostree has no ed25519 engine");
        return;
    }
    let scratch = TmpDir::new("push-s3-tool-signed");
    let server = StandIn::start();
    let tip = block_on(async {
        let tip = pushed(scratch.path(), &server, "one", false).await;
        let bucket = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        bucket.update_summary(&signed_summary()).await.unwrap();
        tip
    });
    for (n, key, verifies) in [(0, PUBLIC_B64, true), (1, OTHER_PUBLIC_B64, false)] {
        let client = tool_client(
            &scratch.path().join(format!("client-{n}")),
            "bare-user",
            &server.url("repo"),
            &[
                "sign-verify-summary=true",
                &format!("verification-ed25519-key={key}"),
            ],
        );
        let out = tool(&[&client, "pull", "w", "main"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.success(), verifies, "{key}: {stderr}");
        assert_eq!(
            stderr.contains("ed25519: Signature couldn't be verified"),
            !verifies,
            "{key}: {stderr}"
        );
        assert_eq!(tool_tip(&client), verifies.then_some(tip), "{key}");
    }
}

/// A push from an `archive` repository and from a `bare-user-only`
/// repository to two prefixes. The push from the `archive` repository has
/// an object of three parts, which goes up as a multipart upload. The
/// `ostree` command checks a dump of each prefix, and pulls each one with no
/// signature over the S3 port, with no summary. After a summary update with
/// an ed25519 signer, it pulls the second prefix with the summary verified.
#[test]
fn the_ostree_command_checks_and_pulls_a_push_on_seaweedfs() {
    let test = "the_ostree_command_checks_and_pulls_a_push_on_seaweedfs";
    if !seaweed_available(test) || !tool_available(test) {
        return;
    }
    let scratch = TmpDir::new("push-s3-weed-tool");
    let large_src = build_tree(&scratch.path().join("large"));
    std::fs::write(large_src.join("large"), incompressible(12 << 20)).unwrap();
    let src = build_tree(scratch.path());
    let sources = [
        ("repo", RepoMode::Archive, large_src),
        ("repo2", RepoMode::BareUserOnly, src),
    ];
    let repos = block_on(async {
        let mut repos = Vec::new();
        for (prefix, mode, src) in &sources {
            let (path, _, tip) = repo_of(scratch.path(), *mode, src).await;
            repos.push((*prefix, path, tip));
        }
        repos
    });
    // The start of the server runs its own `block_on`, so it comes between
    // the two of the test.
    let server = Seaweed::start_anonymous(scratch.path(), "bkt");
    block_on(async {
        for (prefix, path, _) in &repos {
            let s3 = endpoint(&server.endpoint(), &format!("s3://bkt/{prefix}"));
            let bucket = BucketRepo::open(&s3).await.unwrap();
            assert_eq!(bucket.init(None, None, false).await.unwrap(), None);
            let repo = Repo::open(path).await.unwrap();
            let push_opts = RepoPushOptions {
                part_size: Some(5 << 20),
                ..opts(&["main"])
            };
            repo.push_to_bucket(s3, push_opts).await.unwrap();
            let listing = bucket.bucket().list("objects/").await.unwrap();
            let large: Vec<&str> = listing
                .objects
                .iter()
                .filter(|listed| listed.size > 10 << 20)
                .map(|listed| listed.key.as_str())
                .collect();
            if *prefix == "repo" {
                // The `ETag` of a multipart upload ends in the count of its
                // parts.
                let stream = bucket.bucket().get_stream(large[0]).await.unwrap();
                let etag = stream.unwrap().etag().map(str::to_owned);
                assert!(
                    etag.as_ref().is_some_and(|etag| etag.ends_with("-3\"")),
                    "{etag:?}"
                );
            } else {
                assert_eq!(large, Vec::<&str>::new());
            }
            common::dump_bucket(
                bucket.bucket(),
                &scratch.path().join(format!("dump-{prefix}")),
            )
            .await;
        }
    });
    for (prefix, _, tip) in &repos {
        common::tool_fsck(&scratch.path().join(format!("dump-{prefix}")));
        let path = scratch.path().join(format!("client-{prefix}"));
        let client = tool_client(&path, "archive", &server.url("bkt", prefix), &[]);
        tool_ok(&[&client, "pull", "w", "main"]);
        assert_eq!(tool_tip(&client), Some(*tip), "{prefix}");
    }
    common::tool_fsck(&scratch.path().join("client-repo2"));
    if !common::ostree_supports_ed25519() {
        eprintln!("skipping the signed summary of {test}: ostree has no ed25519 engine");
        return;
    }
    block_on(async {
        let bucket = BucketRepo::open(&endpoint(&server.endpoint(), "s3://bkt/repo2"))
            .await
            .unwrap();
        bucket.update_summary(&signed_summary()).await.unwrap();
    });
    let client = tool_client(
        &scratch.path().join("client-signed"),
        "bare-user",
        &server.url("bkt", "repo2"),
        &[
            "sign-verify-summary=true",
            &format!("verification-ed25519-key={PUBLIC_B64}"),
        ],
    );
    tool_ok(&[&client, "pull", "w", "main"]);
    assert_eq!(tool_tip(&client), Some(repos[1].2));
}

/// A delta whose key holds `+` goes into the bucket next to a push, and a
/// summary update lists it. The `ostree` command pulls it with
/// `--require-static-deltas` into a `bare-user` repository, and the port
/// pulls it over `s3://` with
/// [`require_static_deltas`](PullOptions::require_static_deltas).
#[test]
fn a_delta_whose_key_holds_a_plus_pulls_with_the_ostree_command_and_the_port_on_seaweedfs() {
    let test =
        "a_delta_whose_key_holds_a_plus_pulls_with_the_ostree_command_and_the_port_on_seaweedfs";
    if !seaweed_available(test) || !tool_available(test) {
        return;
    }
    let scratch = TmpDir::new("push-s3-weed-delta");
    let server = Seaweed::start_anonymous(scratch.path(), "bkt");
    let url = server.url("bkt", "repo");
    let local = scratch.path().join("src");
    let (first, port) = block_on(async {
        init(&server.endpoint(), None).await;
        let repo = archive(&local).await;
        let first = commit(&repo, "main", None, "first", None).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        let port = scratch.path().join("port");
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let pulled = pull_back(s3, &port, &["main"], PullTrust::unverified()).await;
        assert_eq!(
            pulled.resolve_rev("main", false).await.unwrap(),
            Some(first)
        );
        (first, port)
    });
    let client_path = scratch.path().join("client");
    let client = tool_client(&client_path, "bare-user", &url, &[]);
    tool_ok(&[&client, "pull", "w", "main"]);
    let (second, delta) = block_on(async {
        let repo = Repo::open(&local).await.unwrap();
        // The key of a delta holds the modified base64 of its two commits,
        // so about three keys in four hold a `+`, and each key holds one if
        // the part of `first` holds one.
        let mut n = 0;
        let (second, delta) = loop {
            let second = commit(&repo, "main", Some(first), &format!("second {n}"), None).await;
            let delta = repo
                .generate_static_delta(Some(&first), &second, &ostrya::DeltaOptions::default())
                .await
                .unwrap();
            let delta = delta.to_str().unwrap().to_owned();
            if delta.contains('+') {
                break (second, delta);
            }
            n += 1;
        };
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        let bucket = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        for entry in std::fs::read_dir(local.join(&delta)).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            let bytes = std::fs::read(entry.path()).unwrap();
            bucket
                .bucket()
                .put(&format!("{delta}/{name}"), bytes)
                .await
                .unwrap();
        }
        let opts = ostrya::bucket::BucketSummaryOptions::default();
        assert_eq!(bucket.update_summary(&opts).await.unwrap().deltas, 1);
        (second, delta)
    });
    tool_ok(&[&client, "pull", "--require-static-deltas", "w", "main"]);
    assert_eq!(tool_tip(&client), Some(second), "{delta}");
    common::tool_fsck(&client_path);
    block_on(async {
        let repo = Repo::open(&port).await.unwrap();
        let session = PullSession::connect(
            Endpoint::S3(endpoint(&server.endpoint(), ADDRESS)),
            StreamSessionOptions::default(),
        )
        .await
        .unwrap();
        let opts = PullOptions {
            refs: vec!["main".to_owned()],
            require_static_deltas: true,
            ..PullOptions::default()
        };
        repo.pull_with_session(session, PullTrust::unverified(), opts)
            .await
            .unwrap();
        assert_eq!(repo.resolve_rev("main", false).await.unwrap(), Some(second));
    });
}

/// The future of a push to a bucket repository can run on a multi-threaded
/// executor.
#[allow(dead_code)]
fn the_push_future_is_send(repo: &Repo, s3: S3Endpoint) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&repo.push_to_bucket(s3, RepoPushOptions::default()));
}
