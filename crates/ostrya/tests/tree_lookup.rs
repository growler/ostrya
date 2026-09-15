//! `RepoTree::lookup` path-component tests.
//!
//! A commit-tree path names entries. A `..` component is an entry name that no
//! directory holds, so the lookup reports it absent. This file builds a commit
//! holding `a/b` and a top-level `c` and states the outcome for each `..`
//! position, together with the plain path that still resolves.
//!
//! The shapes are split by which component the walk stops at: a `..` the walk
//! reaches, and a `..` that stands behind a component naming nothing or naming
//! a file. Both report the path absent, and the second group holds the same
//! answer the split before this one gave.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use common::TmpDir;
use ostrya::{
    CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree, Repo, RepoMode,
    TreeEntry,
};
use ostrya_rt::block_on;

/// Commit a tree holding `a/b` and `c`, and return its root tree handle.
async fn commit_ab_c(repo: &Repo, base: &Path) -> ostrya::RepoTree {
    let src = base.join("src");
    std::fs::create_dir_all(src.join("a")).unwrap();
    std::fs::write(src.join("a/b"), b"b\n").unwrap();
    std::fs::write(src.join("c"), b"c\n").unwrap();

    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new("src"),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(CommitOptions::default(), &root)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    let (tree, _) = repo.read_commit(&commit.to_hex()).await.unwrap();
    tree
}

#[test]
fn lookup_reports_a_parent_component_absent() {
    let tmp = TmpDir::new("tree-lookup-parent");
    let base = tmp.path();
    block_on(async {
        let root_dir = base.join("repo");
        Repo::create(&root_dir, CreateOptions::new(RepoMode::BareUserOnly))
            .await
            .unwrap();
        let repo = Repo::open(&root_dir).await.unwrap();
        let root = commit_ab_c(&repo, base).await;

        // Each path here reaches the `..` with the components before it
        // resolved, so the `..` is the component the lookup stops at. In
        // order: a `..` after a directory that resolves; a `..` as the first
        // component; a `..` as the last one; a path that is nothing but a
        // `..`; a `..` the walk reaches twice over; a `.` ahead of the `..`,
        // which the split drops; and a root with a trailing separator around
        // the `..`.
        for path in ["a/../c", "../c", "a/..", "..", "a/../..", "./..", "//../"] {
            assert!(
                root.lookup(Path::new(path)).await.unwrap().is_none(),
                "{path} resolved",
            );
        }

        // A `..` behind a component that names nothing. The walk stops at the
        // absent component, reports the path absent, and does not fail.
        let absent = root.lookup(Path::new("nope/../c")).await;
        assert!(absent.unwrap().is_none());

        // A `..` behind a file in a non-final position. The file is not a
        // directory, so the walk stops one component ahead of the `..` and
        // reports the path absent. `c/..` is the same shape with the file in
        // the commit root.
        for path in ["a/b/../c", "a/b/../../c", "c/.."] {
            assert!(
                root.lookup(Path::new(path)).await.unwrap().is_none(),
                "{path} resolved",
            );
        }

        // The plain path still resolves.
        assert!(matches!(
            root.lookup(Path::new("a/b")).await.unwrap(),
            Some(TreeEntry::File { name, .. }) if name == "b"
        ));
        assert!(matches!(
            root.lookup(Path::new("c")).await.unwrap(),
            Some(TreeEntry::File { name, .. }) if name == "c"
        ));
        assert!(matches!(
            root.lookup(Path::new("a")).await.unwrap(),
            Some(TreeEntry::Dir { name, .. }) if name == "a"
        ));
        // A leading `/` and a `.` component are still dropped.
        assert!(matches!(
            root.lookup(Path::new("/./a/./b")).await.unwrap(),
            Some(TreeEntry::File { name, .. }) if name == "b"
        ));
    });
}
