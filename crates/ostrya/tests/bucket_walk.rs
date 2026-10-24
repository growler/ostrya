#![forbid(unsafe_code)]

//! Tests of the reachability walk over a bucket repository.
//!
//! Each test builds an `archive` repository with ostrya and copies each of
//! its objects into the S3 stand-in of `common::s3`. The walk over the
//! bucket must give the set that the walk over the local repository gives.
//! A refused `GET`, and a 404 without the code `NoSuchKey`, must fail the
//! walk over the bucket.

#![cfg(feature = "s3")]

mod common;

use std::collections::HashSet;
use std::os::fd::AsFd;
use std::path::Path;
use std::time::Duration;

use common::TmpDir;
use common::modes::object_path;
use common::s3::{StandIn, endpoint};
use ostrya::bucket::BucketRepo;
use ostrya::remote;
use ostrya::remote::s3::Bucket;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Error,
    MutableTree, ObjectName, ObjectType, Repo, RepoMode,
};
use ostrya_rt::block_on;

/// The address of the repository in each test.
const ADDRESS: &str = "s3://bkt/repo";

/// A local repository and the copy of its objects in a bucket.
struct Fixture {
    _tmp: TmpDir,
    local: Repo,
    server: StandIn,
    bucket: BucketRepo,
    /// The commits of the branch `main`, oldest first.
    chain: [Checksum; 3],
    /// A commit of the branch `side`, whose parent is `chain[1]`.
    side: Checksum,
}

impl Fixture {
    /// Builds the repository and copies each of its objects into a new
    /// stand-in.
    async fn new() -> Fixture {
        let tmp = TmpDir::new("bucket-walk");
        let local = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let mut parent = None;
        let mut chain = Vec::new();
        for step in 1..=3 {
            let c = commit(&local, tmp.path(), &format!("main{step}"), parent).await;
            parent = Some(c);
            chain.push(c);
        }
        let side = commit(&local, tmp.path(), "side", Some(chain[1])).await;
        let server = StandIn::start();
        for (name, bytes) in common::file_inventory(local.path(), "objects") {
            server.state().store(&format!("repo/{name}"), &bytes);
        }
        let bucket = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        Fixture {
            _tmp: tmp,
            local,
            server,
            bucket,
            chain: [chain[0], chain[1], chain[2]],
            side,
        }
    }

    /// Walks both stores from `roots` to `depth` and checks that the sets
    /// are equal. Returns the set.
    async fn both(&self, roots: &[Checksum], depth: i32) -> HashSet<ObjectName> {
        let local = self
            .local
            .traverse_reachable(roots.iter().copied(), depth)
            .await
            .unwrap();
        let bucket = self
            .bucket
            .traverse_reachable(roots.iter().copied(), depth)
            .await
            .unwrap();
        assert_eq!(bucket, local, "roots {roots:?}, depth {depth}");
        local
    }

    /// Removes the object of `ty` and `checksum` from both stores.
    fn remove(&self, ty: ObjectType, checksum: &Checksum) {
        let path = object_path(ty, checksum);
        std::fs::remove_file(self.local.path().join(&path)).unwrap();
        assert!(
            self.server
                .state()
                .objects
                .remove(&format!("repo/{path}"))
                .is_some()
        );
    }

    /// Writes `bytes` in place of the object of `ty` and `checksum` in both
    /// stores.
    fn replace(&self, ty: ObjectType, checksum: &Checksum, bytes: &[u8]) {
        let path = object_path(ty, checksum);
        std::fs::write(self.local.path().join(&path), bytes).unwrap();
        self.server.state().store(&format!("repo/{path}"), bytes);
    }

    /// Returns the dirtree `sub`, which each commit shares.
    async fn shared_subtree(&self) -> Checksum {
        let root = self.root_dirtree(&self.chain[2]).await;
        self.subtree(&root, "sub").await
    }

    /// Returns the root dirtree of the commit `checksum`.
    async fn root_dirtree(&self, checksum: &Checksum) -> Checksum {
        let (commit, _) = self.local.load_commit(checksum).await.unwrap();
        commit.root_dirtree
    }

    /// Returns the dirtree of the directory `name` in the dirtree `tree`.
    async fn subtree(&self, tree: &Checksum, name: &str) -> Checksum {
        let tree = self.local.load_dirtree(tree).await.unwrap();
        tree.dirs
            .iter()
            .find(|(dir, _, _)| dir == name)
            .map(|(_, tree, _)| *tree)
            .unwrap()
    }

    /// Makes each `GET` of the dirtree `checksum` in the bucket get 404 with
    /// `body`.
    fn not_found(&self, checksum: &Checksum, body: &[u8]) {
        let path = object_path(ObjectType::DirTree, checksum);
        self.server.state().not_found = Some((format!("repo/{path}"), body.to_vec()));
    }
}

/// Commits a tree with the file `file`, which holds `name`, and the
/// directory `sub`, which is the same in each commit. Sets the ref of the
/// name without its digits to the commit.
async fn commit(repo: &Repo, base: &Path, name: &str, parent: Option<Checksum>) -> Checksum {
    let tree = base.join(format!("tree-{name}"));
    std::fs::create_dir_all(tree.join("sub/deep")).unwrap();
    std::fs::write(tree.join("file"), name).unwrap();
    std::fs::write(tree.join("sub/deep/nested"), "the same in each commit\n").unwrap();
    commit_tree(repo, &tree, name, parent).await
}

/// Commits the directory `tree` with the subject `name`. Sets the ref of
/// the name without its digits to the commit.
async fn commit_tree(repo: &Repo, tree: &Path, name: &str, parent: Option<Checksum>) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let dfd = std::fs::File::open(tree).unwrap();
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
                subject: Some(name.to_owned()),
                timestamp: Some(1_700_000_000),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref(name.trim_end_matches(char::is_numeric), Some(&checksum));
    txn.commit().await.unwrap();
    checksum
}

/// Returns the name of the commit `checksum`.
fn commit_name(checksum: Checksum) -> ObjectName {
    ObjectName::new(checksum, ObjectType::Commit)
}

#[test]
fn the_bucket_walk_gives_the_local_set_at_each_depth() {
    block_on(async {
        let f = Fixture::new().await;
        let [first, second, head] = f.chain;
        for depth in [-1, 0, 1, 2] {
            f.both(&[head], depth).await;
            f.both(&[head, f.side], depth).await;
        }
        let whole = f.both(&[head], -1).await;
        assert!(whole.contains(&commit_name(first)));
        let alone = f.both(&[head], 0).await;
        assert!(!alone.contains(&commit_name(second)));
        let two = f.both(&[head, f.side], 1).await;
        assert!(two.contains(&commit_name(second)) && !two.contains(&commit_name(first)));
    });
}

#[test]
fn an_absent_commit_or_dirtree_hides_its_children_in_both_walks() {
    block_on(async {
        let f = Fixture::new().await;
        let sub = f.shared_subtree().await;
        let deep = f.subtree(&sub, "deep").await;
        let first_root = f.root_dirtree(&f.chain[0]).await;
        f.remove(ObjectType::Commit, &f.chain[0]);
        f.remove(ObjectType::DirTree, &sub);
        let set = f.both(&[f.chain[2], f.side], -1).await;
        assert!(set.contains(&commit_name(f.chain[0])));
        assert!(set.contains(&ObjectName::new(sub, ObjectType::DirTree)));
        assert!(!set.contains(&ObjectName::new(deep, ObjectType::DirTree)));
        assert!(!set.contains(&ObjectName::new(first_root, ObjectType::DirTree)));
    });
}

#[test]
fn an_absent_root_causes_no_error() {
    block_on(async {
        let f = Fixture::new().await;
        let absent = Checksum::sha256(b"no such commit");
        let set = f.both(&[absent, f.chain[2]], -1).await;
        assert!(set.contains(&commit_name(absent)));
    });
}

#[test]
fn a_dirtree_that_does_not_parse_fails_both_walks_alike() {
    block_on(async {
        let f = Fixture::new().await;
        let sub = f.shared_subtree().await;
        f.replace(ObjectType::DirTree, &sub, b"\xff");
        let local = f.local.traverse_reachable([f.chain[2]], -1).await;
        let bucket = f.bucket.traverse_reachable([f.chain[2]], -1).await;
        assert!(matches!(local, Err(Error::Core(_))), "{local:?}");
        assert!(matches!(bucket, Err(Error::Core(_))), "{bucket:?}");
    });
}

#[test]
fn the_bucket_walk_reads_commits_and_dirtrees_alone() {
    block_on(async {
        let f = Fixture::new().await;
        f.server.state().requests.clear();
        let set = f.both(&[f.chain[2], f.side], -1).await;
        let mut wanted: Vec<(String, String)> = set
            .iter()
            .filter(|name| matches!(name.ty, ObjectType::Commit | ObjectType::DirTree))
            .map(|name| {
                let path = object_path(name.ty, &name.checksum);
                ("GET".to_owned(), format!("/bkt/repo/{path}"))
            })
            .collect();
        let mut requests = f.server.state().requests.clone();
        wanted.sort();
        requests.sort();
        assert!(!wanted.is_empty());
        assert_eq!(requests, wanted);
    });
}

#[test]
fn the_bucket_walk_reads_at_most_max_outstanding_dirtrees_at_a_time() {
    block_on(async {
        let f = Fixture::new().await;
        // The root of the tree holds 16 directories, each with a file of its
        // own, so the walk can read 16 dirtrees at a time.
        let tree = f._tmp.path().join("tree-wide");
        for n in 0..16 {
            let dir = tree.join(format!("d{n:02}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("file"), format!("file {n}\n")).unwrap();
        }
        let wide = commit_tree(&f.local, &tree, "wide", Some(f.chain[2])).await;
        for (name, bytes) in common::file_inventory(f.local.path(), "objects") {
            f.server.state().store(&format!("repo/{name}"), &bytes);
        }
        let local = f.local.traverse_reachable([wide], 0).await.unwrap();
        for limit in [1, 4] {
            let client = Bucket::new(&endpoint(&f.server.endpoint(), ADDRESS))
                .await
                .unwrap();
            let bucket = BucketRepo::new(client, limit);
            {
                let mut state = f.server.state();
                // Each read of the walk is a `GET` of a key under `objects/`.
                state.delay = Some(("GET", "repo/objects/".to_owned(), Duration::from_millis(25)));
                state.max_delayed = 0;
            }
            let set = bucket.traverse_reachable([wide], 0).await.unwrap();
            let max = f.server.state().max_delayed;
            if limit == 1 {
                assert_eq!(max, 1);
            } else {
                assert!(max > 1 && max <= limit, "limit {limit}: {max}");
            }
            assert_eq!(set, local, "limit {limit}");
        }
    });
}

#[test]
fn a_404_without_no_such_key_fails_the_bucket_walk() {
    block_on(async {
        let f = Fixture::new().await;
        let sub = f.shared_subtree().await;
        for body in [&b""[..], b"<html><body>Not Found</body></html>"] {
            f.not_found(&sub, body);
            let local = f.local.traverse_reachable([f.chain[2]], -1).await;
            assert!(local.is_ok(), "{local:?}");
            let err = f
                .bucket
                .traverse_reachable([f.chain[2]], -1)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    &err,
                    Error::Remote(remote::Error::S3 {
                        status: 404,
                        code: None,
                        ..
                    })
                ),
                "{err}"
            );
        }
    });
}

#[test]
fn a_refused_get_fails_the_bucket_walk() {
    block_on(async {
        let f = Fixture::new().await;
        f.server.state().refuse = Some(("GET", "repo/objects/".into()));
        let err = f
            .bucket
            .traverse_reachable([f.chain[2]], -1)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::Remote(remote::Error::S3 {
                    status: 403,
                    code: Some(code),
                    ..
                }) if code == "AccessDenied"
            ),
            "{err}"
        );
    });
}
