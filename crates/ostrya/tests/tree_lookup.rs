//! Tests of the path components of `RepoTree::lookup`.
//!
//! A path in a commit tree names entries. A `..` component is an entry name
//! that no directory holds, so the lookup reports the path absent. These tests
//! build a commit with `a/b` and a top-level `c`. They state the result for
//! each position of `..`, and for the plain paths that resolve.
//!
//! The paths fall in two groups, by the component where the walk stops:
//!
//! - a `..` that the walk reaches
//! - a `..` after a component that names nothing or names a file
//!
//! In both groups, the lookup reports the path absent.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use common::TmpDir;
use ostrya::{
    CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree, Repo, RepoMode,
    TreeEntry,
};
use ostrya_rt::block_on;

/// Commits a tree with `a/b` and `c`, and returns the handle of its root tree.
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

        // In each path, the components before the `..` resolve, so the
        // lookup stops at the `..`. The paths are, in order:
        // - a `..` after a directory that resolves
        // - a `..` as the first component
        // - a `..` as the last component
        // - a path that is only `..`
        // - two `..` components after a directory
        // - a `.` before the `..` (the split drops the `.`)
        // - a root and a trailing separator around the `..`
        for path in ["a/../c", "../c", "a/..", "..", "a/../..", "./..", "//../"] {
            assert!(
                root.lookup(Path::new(path)).await.unwrap().is_none(),
                "{path} resolved",
            );
        }

        // A `..` after a component that names nothing. The walk stops at the
        // absent component and reports the path absent. It returns no error.
        let absent = root.lookup(Path::new("nope/../c")).await;
        assert!(absent.unwrap().is_none());

        // A `..` after a file that is not the last component. The file is not
        // a directory, so the walk stops one component before the `..` and
        // reports the path absent. `c/..` has the same shape, with the file in
        // the commit root.
        for path in ["a/b/../c", "a/b/../../c", "c/.."] {
            assert!(
                root.lookup(Path::new(path)).await.unwrap().is_none(),
                "{path} resolved",
            );
        }

        // The plain paths resolve.
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
        // The lookup drops a leading `/` and a `.` component.
        assert!(matches!(
            root.lookup(Path::new("/./a/./b")).await.unwrap(),
            Some(TreeEntry::File { name, .. }) if name == "b"
        ));
    });
}
