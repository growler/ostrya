#![forbid(unsafe_code)]

//! Tests of `[ex-ostrya] generate-composefs` for the local writers and the
//! fsck.
//!
//! The tests check these facts:
//!
//! - With the key `true`, the commit of a transaction stores the image of
//!   each commit that `write_commit` writes and that carries the digest key.
//!   A commit with no key gets no image. With the key `false`, no commit gets
//!   an image.
//! - A malformed key, or a key that is not the digest of the tree, fails the
//!   commit of the transaction, and nothing is published.
//! - A commit that `write_metadata` writes gets no image.
//! - `commit_add_composefs_metadata` stores the image of the new commit.
//! - `apply_static_delta_offline` stores the image of the target commit. A
//!   target that the repository holds partial gets no image.
//! - A commit that the repository holds complete before the transaction gets
//!   no image when a transaction writes it again.
//! - `is_commit_staged` is `true` for a new commit, and `false` for a commit
//!   that the repository holds before the transaction.
//! - `commit_add_composefs_metadata` stores no image of a new commit that the
//!   repository holds before the transaction.
//! - A value of the key that is not a boolean, and the value `true` in an
//!   `archive` repository, fail the open of a transaction and the fsck.
//! - With the key `true`, the fsck notes each complete commit with the key
//!   and no image. It notes no partial commit, no commit that the run marks
//!   partial, no commit with a malformed key, and nothing with the key
//!   `false`.
//! - In a repository that seals its objects, each object and the image are
//!   sealed after the commit. The test skips if the file system has no
//!   fs-verity.
//! - A local pull of a chain of commits that share most of their files
//!   stores a valid image of each commit.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use ostrya::{
    Checksum, CommitOptions, CommitState, ComposefsImageState, DeltaOptions, Error, FsckOptions,
    MutableTree, ObjectType, PullFlags, PullOptions, Repo, RepoMode, RepoTree, Transaction, Value,
};
use ostrya_rt::block_on;

use common::composefs::{
    DIGEST_KEY, build_owned_source, commit_owned, commit_tree, dict, key_dict, new_repo,
    verity_supported,
};
use common::{TmpDir, file_inventory, is_sealed, mark_partial, regular_objects, store_with_field2};

/// The config text that turns the generation on, with no fs-verity seal.
const GENERATE: &str = "[ex-integrity]\nfsverity=no\n[ex-ostrya]\ngenerate-composefs=true\n";

/// Replaces the value of `[ex-ostrya] generate-composefs` in the config of
/// the repository at `root` with `value`, and opens the repository again.
async fn set_generate(root: &Path, value: &str) -> Repo {
    let cfg = root.join("config");
    let text = std::fs::read_to_string(&cfg).unwrap();
    let mut out: String = text
        .lines()
        .filter(|l| !l.starts_with("generate-composefs=") && *l != "[ex-ostrya]")
        .map(|l| format!("{l}\n"))
        .collect();
    out.push_str(&format!("[ex-ostrya]\ngenerate-composefs={value}\n"));
    std::fs::write(&cfg, out).unwrap();
    Repo::open(root).await.unwrap()
}

/// Walks `base/src` into `txn` and returns the root of the tree.
async fn stage_tree(txn: &Transaction, base: &Path) -> RepoTree {
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
        .await
        .unwrap();
    txn.write_mtree(&mut mtree).await.unwrap()
}

/// Walks `base/sub` into a new transaction of `repo`, and commits the tree on
/// `main` at `timestamp` with `parent` and the composefs digest key of the
/// tree. Returns the commit.
async fn commit_keyed(
    repo: &Repo,
    base: &Path,
    sub: &str,
    timestamp: u64,
    parent: Option<Checksum>,
) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new(sub), &mut mtree, None)
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let digest = txn.composefs_digest(&root).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                parent,
                timestamp: Some(timestamp),
                metadata: Some(key_dict(&digest)),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("main", Some(&commit));
    txn.commit().await.unwrap();
    commit
}

/// Writes a commit of `base/src` with `metadata` at `timestamp` in a new
/// transaction, queues the ref `main`, and returns the commit and the result
/// of the commit of the transaction.
async fn commit_with(
    repo: &Repo,
    base: &Path,
    timestamp: u64,
    metadata: Value,
) -> (Checksum, ostrya::Result<ostrya::TransactionStats>) {
    let txn = repo.transaction().await.unwrap();
    let root = stage_tree(&txn, base).await;
    let commit = txn
        .write_commit(
            CommitOptions {
                timestamp: Some(timestamp),
                metadata: Some(metadata),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("main", Some(&commit));
    (commit, txn.commit().await)
}

/// With the key `true`, the commit of a transaction stores the image of a
/// commit with the digest key, and no image of a commit with no key. With the
/// key `false`, no commit gets an image.
#[test]
fn a_commit_with_the_key_gets_its_image() {
    let scratch = TmpDir::new("cfs-gen-commit");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    block_on(async {
        let repo = new_repo(&scratch.path().join("on"), RepoMode::BareUser, GENERATE).await;
        let (keyed, _) = commit_tree(&repo, &base, 1, false, Some("main")).await;
        assert_eq!(
            repo.check_composefs_image(&keyed).await.unwrap(),
            ComposefsImageState::Valid
        );
        let plain = commit_owned(&repo, &base).await;
        assert!(!repo.has_composefs_image(&plain).await.unwrap());
        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert!(report.is_ok(), "{report:?}");
        assert!(report.missing_images.is_empty());

        let off = new_repo(
            &scratch.path().join("off"),
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=no\n",
        )
        .await;
        let (keyed, _) = commit_tree(&off, &base, 1, false, None).await;
        assert!(!off.has_composefs_image(&keyed).await.unwrap());
    });
}

/// A malformed key, or a key that is not the digest of the tree, fails the
/// commit of the transaction. The transaction publishes no object, no image,
/// and no ref.
#[test]
fn a_bad_key_fails_the_commit_and_publishes_nothing() {
    let scratch = TmpDir::new("cfs-gen-bad");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let root = scratch.path().join("repo");
    block_on(async {
        let repo = new_repo(&root, RepoMode::BareUser, GENERATE).await;

        let malformed = dict(DIGEST_KEY, "s", Value::Str("digest".into()));
        let (commit, result) = commit_with(&repo, &base, 1, malformed).await;
        let err = result.unwrap_err();
        assert!(
            matches!(&err, Error::InvalidFormat(m) if m.contains(&commit.to_hex())),
            "{err}"
        );

        let (commit, result) = commit_with(&repo, &base, 2, key_dict(&[7; 32])).await;
        match result.unwrap_err() {
            Error::ComposefsDigestMismatch {
                commit: named,
                expected,
                ..
            } => {
                assert_eq!(named, commit);
                assert_eq!(expected, [7; 32]);
            }
            other => panic!("{other}"),
        }

        assert!(file_inventory(&root, "objects").is_empty());
        assert!(!root.join("extensions/ostrya/composefs").exists());
        assert!(repo.list_refs(None).await.unwrap().is_empty());
    });
}

/// A commit that `write_metadata` writes gets no image, also with the key.
#[test]
fn a_commit_of_write_metadata_gets_no_image() {
    let scratch = TmpDir::new("cfs-gen-raw");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    block_on(async {
        let repo = new_repo(&scratch.path().join("repo"), RepoMode::BareUser, GENERATE).await;
        let txn = repo.transaction().await.unwrap();
        let root = stage_tree(&txn, &base).await;
        let digest = txn.composefs_digest(&root).await.unwrap();
        let bytes = ostrya_core::Commit {
            metadata: key_dict(&digest),
            parent: None,
            related: Vec::new(),
            subject: String::new(),
            body: String::new(),
            timestamp: 1,
            root_dirtree: *root.dirtree_checksum(),
            root_dirmeta: *root.dirmeta_checksum(),
        }
        .serialize()
        .unwrap();
        let commit = txn
            .write_metadata(ObjectType::Commit, None, &bytes)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        assert!(repo.has_object(ObjectType::Commit, &commit).await.unwrap());
        assert!(!repo.has_composefs_image(&commit).await.unwrap());
    });
}

/// With the key `true`, `commit_add_composefs_metadata` stores the image of
/// the new commit. With the key `false`, it writes the same commit and stores
/// no image.
#[test]
fn a_commit_with_added_metadata_gets_its_image() {
    let scratch = TmpDir::new("cfs-gen-add");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let base = &base;
    block_on(async {
        let add = |repo: Repo| async move {
            let plain = commit_owned(&repo, base).await;
            let txn = repo.transaction().await.unwrap();
            let keyed = repo
                .commit_add_composefs_metadata(&txn, &plain)
                .await
                .unwrap();
            txn.commit().await.unwrap();
            assert!(!repo.has_composefs_image(&plain).await.unwrap());
            (repo, keyed)
        };
        let (repo, keyed) =
            add(new_repo(&scratch.path().join("on"), RepoMode::BareUser, GENERATE).await).await;
        assert_eq!(
            repo.check_composefs_image(&keyed).await.unwrap(),
            ComposefsImageState::Valid
        );

        let off = new_repo(
            &scratch.path().join("off"),
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=no\n",
        )
        .await;
        let (off, unstored) = add(off).await;
        assert_eq!(unstored, keyed);
        assert!(!off.has_composefs_image(&unstored).await.unwrap());
    });
}

/// With the key `true`, `apply_static_delta_offline` stores the image of the
/// target commit.
#[test]
fn an_offline_delta_apply_stores_the_image() {
    let scratch = TmpDir::new("cfs-gen-delta");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    block_on(async {
        let src_root = scratch.path().join("src");
        let src = new_repo(&src_root, RepoMode::Archive, "").await;
        let (commit, _) = commit_tree(&src, &base, 1, false, None).await;
        let relative = src
            .generate_static_delta(None, &commit, &DeltaOptions::default())
            .await
            .unwrap();

        let dst = new_repo(&scratch.path().join("dst"), RepoMode::BareUser, GENERATE).await;
        let applied = dst
            .apply_static_delta_offline(&src_root.join(relative))
            .await
            .unwrap();
        assert_eq!(applied, commit);
        assert_eq!(
            dst.check_composefs_image(&commit).await.unwrap(),
            ComposefsImageState::Valid
        );
    });
}

/// With the key `true`, `apply_static_delta_offline` to a target that a
/// commit-only pull left partial stores no image, and does not fail.
#[test]
fn an_offline_delta_apply_to_a_held_partial_commit_stores_no_image() {
    let scratch = TmpDir::new("cfs-gen-delta-partial");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    block_on(async {
        let src_root = scratch.path().join("src");
        let src = new_repo(&src_root, RepoMode::Archive, "").await;
        let (commit, _) = commit_tree(&src, &base, 1, false, Some("main")).await;
        let relative = src
            .generate_static_delta(None, &commit, &DeltaOptions::default())
            .await
            .unwrap();

        let dst = new_repo(&scratch.path().join("dst"), RepoMode::BareUser, GENERATE).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                flags: PullFlags::COMMIT_ONLY,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dst.commit_state(&commit).await.unwrap(),
            CommitState::Partial
        );
        assert!(!dst.has_composefs_image(&commit).await.unwrap());

        let applied = dst
            .apply_static_delta_offline(&src_root.join(relative))
            .await
            .unwrap();
        assert_eq!(applied, commit);
        assert!(!dst.has_composefs_image(&commit).await.unwrap());
    });
}

/// A commit that the repository holds complete before the transaction gets no
/// image when a transaction writes it again.
#[test]
fn a_commit_held_complete_gets_no_image() {
    let scratch = TmpDir::new("cfs-gen-held");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let root = scratch.path().join("repo");
    block_on(async {
        let repo = new_repo(&root, RepoMode::BareUser, "[ex-integrity]\nfsverity=no\n").await;
        let (commit, _) = commit_tree(&repo, &base, 1, false, None).await;
        drop(repo);
        let repo = set_generate(&root, "true").await;
        let (again, _) = commit_tree(&repo, &base, 1, false, None).await;
        assert_eq!(again, commit);
        assert!(!repo.has_composefs_image(&commit).await.unwrap());
    });
}

/// `is_commit_staged` is `true` for a new commit that `write_commit` writes,
/// and `false` when a second transaction writes the same commit again.
#[test]
fn a_held_commit_is_not_staged_again() {
    let scratch = TmpDir::new("cfs-gen-staged");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let base = &base;
    block_on(async {
        let repo = new_repo(
            &scratch.path().join("repo"),
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=no\n",
        )
        .await;
        let write = |txn: Transaction| async move {
            let root = stage_tree(&txn, base).await;
            let opts = CommitOptions {
                timestamp: Some(1),
                ..CommitOptions::default()
            };
            let commit = txn.write_commit(opts, &root).await.unwrap();
            let staged = txn.is_commit_staged(&commit);
            txn.commit().await.unwrap();
            (commit, staged)
        };
        let (commit, staged) = write(repo.transaction().await.unwrap()).await;
        assert!(staged);
        let (again, staged) = write(repo.transaction().await.unwrap()).await;
        assert_eq!(again, commit);
        assert!(!staged);
    });
}

/// With the key `true`, `commit_add_composefs_metadata` stores no image when
/// the repository holds the new commit before the transaction.
#[test]
fn a_held_commit_with_added_metadata_gets_no_image() {
    let scratch = TmpDir::new("cfs-gen-add-held");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let root = scratch.path().join("repo");
    block_on(async {
        let add = |repo: Repo, plain: Checksum| async move {
            let txn = repo.transaction().await.unwrap();
            let keyed = repo
                .commit_add_composefs_metadata(&txn, &plain)
                .await
                .unwrap();
            txn.commit().await.unwrap();
            keyed
        };
        let repo = new_repo(&root, RepoMode::BareUser, "[ex-integrity]\nfsverity=no\n").await;
        let plain = commit_owned(&repo, &base).await;
        let keyed = add(repo, plain).await;
        let repo = set_generate(&root, "true").await;
        let again = add(repo.clone(), plain).await;
        assert_eq!(again, keyed);
        assert!(!repo.has_composefs_image(&keyed).await.unwrap());
    });
}

/// A value of the key that is not a boolean, and the value `true` in an
/// `archive` repository, fail the open of a transaction and the fsck. The
/// value `false` in an `archive` repository is accepted.
#[test]
fn a_bad_value_of_the_key_fails_the_transaction_and_the_fsck() {
    let scratch = TmpDir::new("cfs-gen-value");
    block_on(async {
        let repo = new_repo(
            &scratch.path().join("bad"),
            RepoMode::BareUser,
            "[ex-ostrya]\ngenerate-composefs=maybe\n",
        )
        .await;
        let err = repo.transaction().await.err().unwrap();
        assert!(matches!(err, Error::Core(_)), "{err}");
        let err = repo.fsck(&FsckOptions::default()).await.unwrap_err();
        assert!(matches!(err, Error::Core(_)), "{err}");

        let root = scratch.path().join("archive");
        let repo = new_repo(
            &root,
            RepoMode::Archive,
            "[ex-ostrya]\ngenerate-composefs=true\n",
        )
        .await;
        let err = repo.transaction().await.err().unwrap();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        let err = repo.fsck(&FsckOptions::default()).await.unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        let repo = set_generate(&root, "false").await;
        repo.transaction().await.unwrap().abort().await.unwrap();
    });
}

/// With the key `true`, the fsck notes a complete commit with the key and no
/// image. It notes no commit with no key, no commit with a malformed key, and
/// no partial commit. With the key `false`, it notes nothing. A note does not
/// fail the run.
#[test]
fn the_fsck_notes_a_commit_with_no_image() {
    let scratch = TmpDir::new("cfs-gen-fsck");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let root = scratch.path().join("repo");
    block_on(async {
        let repo = new_repo(&root, RepoMode::BareUser, "[ex-integrity]\nfsverity=no\n").await;
        let (held, _) = commit_tree(&repo, &base, 1, false, None).await;
        commit_owned(&repo, &base).await;
        let malformed = dict(DIGEST_KEY, "s", Value::Str("digest".into()));
        let (_, result) = commit_with(&repo, &base, 2, malformed).await;
        result.unwrap();

        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert!(report.missing_images.is_empty());
        drop(repo);

        let repo = set_generate(&root, "true").await;
        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert!(report.is_ok(), "{report:?}");
        assert_eq!(report.missing_images, vec![held]);

        mark_partial(&repo, &held);
        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert!(report.missing_images.is_empty(), "{report:?}");
        std::fs::remove_file(root.join(format!("state/{held}.commitpartial"))).unwrap();

        repo.add_composefs_image(&held).await.unwrap();
        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert!(report.is_ok(), "{report:?}");
        assert!(report.missing_images.is_empty());
    });
}

/// With the key `true`, the fsck notes no commit that the same run marks
/// partial because a dependency in field 2 is absent.
#[test]
fn the_fsck_notes_no_commit_that_it_marks_partial() {
    let scratch = TmpDir::new("cfs-gen-fsck-dep");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let root = scratch.path().join("repo");
    block_on(async {
        let repo = new_repo(&root, RepoMode::BareUser, "[ex-integrity]\nfsverity=no\n").await;
        let (keyed, _) = commit_tree(&repo, &base, 1, false, None).await;
        let absent = Checksum::from_bytes([0x5a; 32]);
        let named = store_with_field2(&repo, &keyed, &[("boot/uki", absent.as_bytes())]).await;
        drop(repo);
        let repo = set_generate(&root, "true").await;
        assert!(!repo.has_composefs_image(&named).await.unwrap());

        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert_eq!(report.marked_partial, vec![named], "{report:?}");
        assert!(!report.missing_images.contains(&named), "{report:?}");
        assert_eq!(report.missing_images, vec![keyed], "{report:?}");
    });
}

/// In a repository with `fsverity=yes`, each regular object and the image are
/// sealed after a commit under the key. Skips if the file system has no
/// fs-verity.
#[test]
fn a_sealing_repository_seals_each_object_the_build_reads() {
    let scratch = TmpDir::new("cfs-gen-sealed");
    if !verity_supported(scratch.path()) {
        eprintln!("skipping: the file system has no fs-verity");
        return;
    }
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let root = scratch.path().join("repo");
    block_on(async {
        let repo = new_repo(
            &root,
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=yes\n[ex-ostrya]\ngenerate-composefs=true\n",
        )
        .await;
        assert!(repo.seals_objects().await.unwrap());
        let (commit, _) = commit_tree(&repo, &base, 1, false, None).await;
        assert_eq!(
            repo.check_composefs_image(&commit).await.unwrap(),
            ComposefsImageState::Valid
        );
        for object in regular_objects(&root) {
            assert!(is_sealed(&object), "{} has no seal", object.display());
        }
        assert!(is_sealed(&repo.composefs_image_path(&commit)));
    });
}

/// A local pull of a chain of three commits stores a valid image of each
/// commit. The commits share most of their files, and two paths of each tree
/// name one object.
#[test]
fn a_local_pull_of_a_commit_chain_stores_each_image() {
    let scratch = TmpDir::new("cfs-gen-chain");
    let base = scratch.path().join("tree");
    let big: Vec<u8> = (0..9000).map(|i| i as u8).collect();
    for (n, sub) in ["v1", "v2", "v3"].iter().enumerate() {
        let dir = base.join(sub);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("big.bin"), &big).unwrap();
        std::fs::write(dir.join("shared.txt"), b"shared\n").unwrap();
        std::fs::write(dir.join("sub/copy.txt"), b"shared\n").unwrap();
        std::fs::write(dir.join("empty"), b"").unwrap();
        std::fs::write(dir.join("version"), format!("version {n}\n")).unwrap();
    }
    block_on(async {
        let src = new_repo(&scratch.path().join("src"), RepoMode::Archive, "").await;
        let c1 = commit_keyed(&src, &base, "v1", 1, None).await;
        let c2 = commit_keyed(&src, &base, "v2", 2, Some(c1)).await;
        let c3 = commit_keyed(&src, &base, "v3", 3, Some(c2)).await;

        let dst = new_repo(&scratch.path().join("dst"), RepoMode::BareUser, GENERATE).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                depth: 2,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        for commit in [c1, c2, c3] {
            assert_eq!(
                dst.check_composefs_image(&commit).await.unwrap(),
                ComposefsImageState::Valid
            );
        }
    });
}
