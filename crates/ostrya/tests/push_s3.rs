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
use ostrya::sign::Ed25519Verifier;
use ostrya::summary::Summary;
use ostrya::verify::{PullTrust, TrustedKeys};
use ostrya::{
    Checksum, Commit, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions,
    DetachedMetadataFilter, DictBuilder, DirTree, Ed25519Signer, Error, MutableTree, ObjectType,
    PullOptions, PushOntoOptions, Repo, RepoMode, RepoPushOptions, SignFuture, Signer,
    SummaryOptions, Value,
};
use ostrya_rt::block_on;

/// The address of the repository in each test.
const ADDRESS: &str = "s3://bkt/repo";

/// The key of the writer lock in the bucket.
const LOCK: &str = "repo/extensions/ostrya/lock";

/// The key of the config in the bucket.
const CONFIG: &str = "repo/config";

/// A fixed ed25519 key pair that signs the summary.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

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
    assert_eq!(repo.init(id, false).await.unwrap(), None);
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

/// Returns the trusted keys of [`PUBLIC_B64`].
fn trusted() -> TrustedKeys {
    let public = ostrya::base64::decode(PUBLIC_B64).unwrap();
    let verifier = Ed25519Verifier::new([public], Vec::<Vec<u8>>::new()).unwrap();
    TrustedKeys::new(vec![Arc::new(verifier)]).unwrap()
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
            match repo.init(id, false).await {
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
                    repo.init(Some(id), false).await,
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
            repo.init(None, false).await,
            Err(Error::BucketLocked { .. })
        ));
        let broken = repo.init(None, true).await.unwrap().unwrap();
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
        assert_eq!(repo.init(Some(A), false).await.unwrap(), None);
        assert!(matches!(
            repo.init(None, false).await,
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
        let err = repo.init(None, false).await.unwrap_err();
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
            [
                "repo/extensions/ostrya/lock",
                "repo/extensions/ostrya/lock",
                "repo/summary"
            ]
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
                "repo/refs/heads/other",
                "repo/summary"
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
                format!("repo/{meta_target}"),
                "repo/summary".to_owned()
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
                "repo/refs/heads/main".to_owned(),
                "repo/summary".to_owned()
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
        assert!(!server.state().objects.contains_key("repo/summary"));
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
                "repo/refs/heads/b",
                "repo/summary"
            ]
        );
        let olds: Vec<Option<Checksum>> = outcome.outcome.refs.iter().map(|r| r.old).collect();
        assert_eq!(olds, [Some(tip), None]);
        let summary = Summary::parse(&server.state().objects["repo/summary"].bytes).unwrap();
        assert_eq!(summary.lookup("a"), Some(tip));
        assert_eq!(summary.lookup("b"), Some(tip));
    });
}

#[test]
fn a_failure_at_the_summary_is_repaired_by_a_run_again() {
    let scratch = TmpDir::new("push-s3-summary-failure");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        let signed = || RepoPushOptions {
            summary_signers: vec![signer()],
            ..opts(&["main"])
        };
        server.state().refuse = Some(("PUT", "repo/summary".to_owned()));
        push(&repo, &server.endpoint(), signed()).await.unwrap_err();
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(tip));
        assert!(!server.state().objects.contains_key("repo/summary"));
        server.state().refuse = Some(("PUT", "repo/summary.sig".to_owned()));
        push(&repo, &server.endpoint(), signed()).await.unwrap_err();
        assert!(server.state().objects.contains_key("repo/summary"));
        assert!(!server.state().objects.contains_key("repo/summary.sig"));
        server.state().refuse = None;
        push(&repo, &server.endpoint(), signed()).await.unwrap();
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let trust = PullTrust::unverified().with_summary(trusted());
        let pulled = pull_back(s3, &scratch.path().join("pulled"), &["main"], trust).await;
        assert_eq!(pulled.resolve_rev("main", false).await.unwrap(), Some(tip));
    });
}

/// A summary signer that always fails.
struct FailingSigner;

impl Signer for FailingSigner {
    fn name(&self) -> &str {
        "failing"
    }

    fn metadata_key(&self) -> &str {
        "ostree.sign.failing"
    }

    fn sign<'a>(&'a self, _data: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async {
            Err(ostrya::sign::Error::Signature(
                "the test signer fails".to_owned(),
            ))
        })
    }
}

#[test]
fn a_failed_summary_signer_changes_no_ref() {
    let scratch = TmpDir::new("push-s3-failed-signer");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let first = commit(&repo, "main", None, "one", None).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        let summary = server.state().objects["repo/summary"].clone();
        commit(&repo, "main", Some(first), "two", None).await;
        let signed = RepoPushOptions {
            summary_signers: vec![signer(), Arc::new(FailingSigner)],
            ..opts(&["main"])
        };
        match push(&repo, &server.endpoint(), signed).await {
            Err(Error::Signature(message)) => {
                assert!(message.contains("with the failing key"), "{message}");
                assert!(message.contains("the test signer fails"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(first));
        assert_eq!(server.state().objects["repo/summary"], summary);
        assert!(!server.state().objects.contains_key("repo/summary.sig"));
        assert!(!server.state().objects.contains_key(LOCK));
    });
}

#[test]
fn a_commit_object_of_the_bucket_with_other_bytes_changes_no_ref() {
    let scratch = TmpDir::new("push-s3-corrupt-commit");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        // A ref of the bucket names a commit whose object holds other
        // bytes. The local repository does not hold that commit, so the
        // summary reads it from the bucket.
        let other = Checksum::from_bytes([0xcd; 32]);
        let other_ref = format!("{}\n", other.to_hex());
        {
            let mut state = server.state();
            state.store(&key(ObjectType::Commit, &other), b"other bytes");
            state.store("repo/refs/heads/other", other_ref.as_bytes());
        }
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        let message = malformed(push(&repo, &server.endpoint(), opts(&["main"])).await);
        assert!(message.contains("has the checksum"), "{message}");
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), None);
        assert_eq!(ref_of(&server, "repo/refs/heads/other"), Some(other));
        assert!(!server.state().objects.contains_key("repo/summary"));
        assert!(!server.state().objects.contains_key(LOCK));
        // The objects of the push went up.
        assert!(
            server
                .state()
                .objects
                .contains_key(&key(ObjectType::Commit, &tip))
        );
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
        assert!(!server.state().objects.contains_key("repo/summary"));
        assert_eq!(server.state().objects[LOCK].bytes, DEAD_LOCK.as_bytes());
        assert_trees_whole(&server);
    });
}

#[test]
fn a_lock_broken_before_the_summary_stops_the_push() {
    let scratch = TmpDir::new("push-s3-lost-summary");
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
        assert!(!server.state().objects.contains_key("repo/summary"));
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
        // The refs and the summary are written.
        assert_eq!(ref_of(&server, "repo/refs/heads/main"), Some(tip));
        assert!(server.state().objects.contains_key("repo/summary"));
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

#[test]
fn a_signed_bucket_repository_refuses_a_push_with_no_signer() {
    let scratch = TmpDir::new("push-s3-signed");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        server.state().store("repo/summary.sig", b"signed");
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", None).await;
        server.state().requests.clear();
        let message = refused(push(&repo, &server.endpoint(), opts(&["main"])).await);
        assert!(message.contains("has a signed summary"), "{message}");
        assert_eq!(
            puts(&server),
            ["repo/extensions/ostrya/lock", "repo/extensions/ostrya/lock"]
        );
        assert!(!server.state().objects.contains_key(LOCK));
    });
}

#[test]
fn a_push_with_a_signer_writes_summary_and_summary_sig() {
    let scratch = TmpDir::new("push-s3-signer");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let tip = commit(&repo, "main", None, "one", None).await;
        let signed = RepoPushOptions {
            summary_signers: vec![signer()],
            ..opts(&["main"])
        };
        push(&repo, &server.endpoint(), signed).await.unwrap();
        assert!(server.state().objects.contains_key("repo/summary.sig"));
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let trust = PullTrust::unverified().with_summary(trusted());
        let pulled = pull_back(s3, &scratch.path().join("pulled"), &["main"], trust).await;
        assert_eq!(pulled.resolve_rev("main", false).await.unwrap(), Some(tip));
        // A changed summary fails the check of its signature.
        let mut summary = server.state().objects["repo/summary"].bytes.clone();
        let middle = summary.len() / 2;
        summary[middle] ^= 1;
        server.state().store("repo/summary", &summary);
        let other = dest(&scratch.path().join("tampered")).await;
        let session = PullSession::connect(
            Endpoint::S3(endpoint(&server.endpoint(), ADDRESS)),
            StreamSessionOptions::default(),
        )
        .await
        .unwrap();
        let pulled = other
            .pull_with_session(
                session,
                PullTrust::unverified().with_summary(trusted()),
                PullOptions {
                    refs: vec!["main".into()],
                    ..PullOptions::default()
                },
            )
            .await;
        assert!(matches!(pulled, Err(Error::Signature(_))), "{pulled:?}");
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
fn a_key_under_refs_remotes_refuses_the_push() {
    let (server, result) = push_onto_seed(
        "push-s3-remotes",
        PLAIN,
        &[("repo/refs/remotes/origin/main", b"x")],
    );
    let message = malformed(result);
    assert!(message.contains("refs/remotes/origin/main"), "{message}");
    assert_unchanged(&server);
}

#[test]
fn a_mirror_directory_with_an_invalid_collection_id_refuses_the_push() {
    let ref_body = format!("{}\n", "ab".repeat(32));
    let (server, result) = push_onto_seed(
        "push-s3-bad-mirror",
        PLAIN,
        &[("repo/refs/mirrors/nodot/x", ref_body.as_bytes())],
    );
    let message = malformed(result);
    assert!(message.contains("refs/mirrors/nodot/x"), "{message}");
    assert_unchanged(&server);
}

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
// Summary.
// ---------------------------------------------------------------------------

/// Returns the `ostree.summary.last-modified` value of `summary`.
fn last_modified(summary: &Summary) -> u64 {
    match summary.metadata_value("ostree.summary.last-modified") {
        Some(Value::U64(value)) => u64::from_be(*value),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_summary_of_a_push_has_the_bytes_of_a_local_summary() {
    let scratch = TmpDir::new("push-s3-summary-bytes");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let repo = archive(&scratch.path().join("src")).await;
        let first = commit(&repo, "main", None, "one", None).await;
        commit(&repo, "main", Some(first), "two", None).await;
        commit(&repo, "bound-b", None, "b", bound(B)).await;
        commit(&repo, "bound-c", None, "c", bound(C)).await;
        for spec in [
            "main",
            "main:x/y",
            "bound-b:main",
            "bound-c:main",
            "bound-c:other",
        ] {
            push(&repo, &server.endpoint(), opts(&[spec]))
                .await
                .unwrap();
        }
        let bucket_summary = server.state().objects["repo/summary"].bytes.clone();
        let parsed = Summary::parse(&bucket_summary).unwrap();
        assert_eq!(parsed.collection_map().unwrap().len(), 2);

        // The same files in a local repository give the same root summary.
        let path = scratch.path().join("local");
        drop(archive(&path).await);
        let objects = server.state().objects.clone();
        for (key, stored) in &objects {
            let relative = &key["repo/".len()..];
            if relative.starts_with("extensions/") || relative.starts_with("summary") {
                continue;
            }
            let file = path.join(relative);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, &stored.bytes).unwrap();
        }
        let local = Repo::open(&path).await.unwrap();
        let summary_opts = SummaryOptions {
            last_modified: Some(last_modified(&parsed)),
            ..SummaryOptions::default()
        };
        local.regenerate_summary(&summary_opts).await.unwrap();
        assert_eq!(local.read_summary().await.unwrap().unwrap(), bucket_summary);
    });
}

#[test]
fn the_summary_has_the_collection_id_and_the_map() {
    let scratch = TmpDir::new("push-s3-summary-collections");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), Some(A)).await;
        let repo = archive(&scratch.path().join("src")).await;
        let main = commit(&repo, "main", None, "one", bound(A)).await;
        let mirrored = commit(&repo, "bound-b", None, "b", bound(B)).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        push(&repo, &server.endpoint(), opts(&["bound-b:stable"]))
            .await
            .unwrap();
        let summary = Summary::parse(&server.state().objects["repo/summary"].bytes).unwrap();
        assert_eq!(
            summary.metadata_value("ostree.summary.collection-id"),
            Some(&Value::Str(A.into()))
        );
        let names: Vec<(&str, Checksum)> = summary
            .refs
            .iter()
            .map(|entry| (entry.name.as_str(), entry.commit))
            .collect();
        assert_eq!(names, [("main", main)]);
        let map = summary.collection_map().unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].0, B);
        assert_eq!(map[0].1.len(), 1);
        assert_eq!(
            (map[0].1[0].name.as_str(), map[0].1[0].commit),
            ("stable", mirrored)
        );
    });
}

#[test]
fn the_summary_lists_the_deltas_of_the_bucket() {
    let scratch = TmpDir::new("push-s3-summary-deltas");
    block_on(async {
        let server = StandIn::start();
        init(&server.endpoint(), None).await;
        let mut bytes = [7u8; 32];
        bytes[0] = 0xfb;
        bytes[1] = 0xff;
        let to = Checksum::from_bytes(bytes);
        let b64 = to.to_base64_modified();
        assert!(b64.contains('+'), "{b64}");
        let superblock = b"a superblock".to_vec();
        let other = Checksum::from_bytes([3u8; 32]).to_base64_modified();
        {
            let mut state = server.state();
            state.store(
                &format!("repo/deltas/{}/{}/superblock", &b64[..2], &b64[2..]),
                &superblock,
            );
            // A delta directory with no superblock is not in the map.
            state.store(
                &format!("repo/deltas/{}/{}/0", &other[..2], &other[2..]),
                b"part",
            );
        }
        let repo = archive(&scratch.path().join("src")).await;
        commit(&repo, "main", None, "one", None).await;
        push(&repo, &server.endpoint(), opts(&["main"]))
            .await
            .unwrap();
        let summary = Summary::parse(&server.state().objects["repo/summary"].bytes).unwrap();
        let deltas = summary.static_deltas().unwrap();
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].from, None);
        assert_eq!(deltas[0].to, to);
        assert_eq!(deltas[0].superblock, Checksum::sha256(&superblock));
    });
}

/// The future of a push to a bucket repository can run on a multi-threaded
/// executor.
#[allow(dead_code)]
fn the_push_future_is_send(repo: &Repo, s3: S3Endpoint) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&repo.push_to_bucket(s3, RepoPushOptions::default()));
}
