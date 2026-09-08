//! Prune under metadata GC roots and the optional parent edge.
//!
//! Both options are port extensions with no counterpart in the `ostree` tool, so
//! these repositories are built and pruned with the port alone. The tool-checked
//! prune behavior lives in `maintenance.rs`.

mod common;

use std::path::Path;

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Error,
    MutableTree, ObjectType, PruneOptions, Repo, RepoMode, Type, Value,
};
use ostrya_rt::block_on;

/// A fixed timestamp, so the commits are reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// The property name these tests configure as a GC root.
const GC_ROOTS: &str = "test.gc-roots";

/// Write a one-file tree at `dir`, its content naming it.
fn write_tree(base: &Path, name: &str) {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), format!("{name}\n")).unwrap();
}

/// An `a{sv}` holding one property whose value is an `aay` of commit checksums.
fn checksum_list(key: &str, commits: &[Checksum]) -> Value {
    let elements = commits
        .iter()
        .map(|c| Value::Bytes(c.as_bytes().to_vec()))
        .collect();
    dict(key, Type::parse("aay").unwrap(), Value::Array(elements))
}

/// An `a{sv}` holding one property of the caller's type and value.
fn dict(key: &str, ty: Type, value: Value) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str(key.to_owned()),
        Value::Variant(Box::new((ty, value))),
    ])])
}

/// Commit the tree `base/<name>` into `repo`, with the given parent, metadata,
/// and, where `branch` names one, a ref pointing at the result.
async fn commit(
    repo: &Repo,
    base: &Path,
    name: &str,
    parent: Option<Checksum>,
    metadata: Option<Value>,
    branch: Option<&str>,
) -> Checksum {
    use std::os::fd::AsFd;
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new(name),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                parent,
                subject: Some(name.to_owned()),
                timestamp: Some(FIXED_TS),
                metadata,
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    if let Some(branch) = branch {
        txn.set_ref(branch, Some(&commit));
    }
    txn.commit().await.unwrap();
    commit
}

/// A repository under `base/repo` with the trees `base/<name>` written.
async fn repo_with_trees(base: &Path, names: &[&str]) -> Repo {
    for name in names {
        write_tree(base, name);
    }
    Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap()
}

/// The options these tests prune with: refs alone, no parent edge, and the one
/// property configured.
fn gc_root_options() -> PruneOptions {
    PruneOptions::gc_roots([GC_ROOTS])
}

/// Whether the repository still holds `commit` as an object.
async fn holds(repo: &Repo, commit: &Checksum) -> bool {
    repo.has_object(ObjectType::Commit, commit).await.unwrap()
}

#[test]
fn a_property_in_commit_metadata_keeps_its_target() {
    let tmp = TmpDir::new("gc-roots-commit-meta");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["kept", "head"]).await;
        // `kept` is named by no ref. The ref head names it through the property.
        let kept = commit(&repo, tmp.path(), "kept", None, None, None).await;
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(checksum_list(GC_ROOTS, &[kept])),
            Some("main"),
        )
        .await;

        repo.prune(&gc_root_options()).await.unwrap();
        assert!(holds(&repo, &head).await, "the ref's own commit survives");
        assert!(
            holds(&repo, &kept).await,
            "the commit the property names survives"
        );
        assert!(
            repo.has_object(ObjectType::DirTree, &commit_root(&repo, &kept).await)
                .await
                .unwrap(),
            "the objects that commit reaches survive with it"
        );
    });
}

#[test]
fn a_commit_no_property_names_is_pruned() {
    let tmp = TmpDir::new("gc-roots-control");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["orphan", "head"]).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, None, None).await;
        let head = commit(&repo, tmp.path(), "head", None, None, Some("main")).await;

        // The same options, with nothing naming the orphan: it goes.
        repo.prune(&gc_root_options()).await.unwrap();
        assert!(holds(&repo, &head).await, "the ref's own commit survives");
        assert!(
            !holds(&repo, &orphan).await,
            "a commit no ref and no property names is pruned"
        );
    });
}

#[test]
fn a_property_in_detached_metadata_keeps_its_target() {
    let tmp = TmpDir::new("gc-roots-detached");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["kept", "head"]).await;
        let kept = commit(&repo, tmp.path(), "kept", None, None, None).await;
        let head = commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        repo.write_commit_detached_metadata(&head, Some(&checksum_list(GC_ROOTS, &[kept])))
            .await
            .unwrap();

        repo.prune(&gc_root_options()).await.unwrap();
        assert!(
            holds(&repo, &kept).await,
            "the commit the detached property names survives"
        );
    });
}

#[test]
fn property_edges_are_followed_recursively() {
    let tmp = TmpDir::new("gc-roots-recursive");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["deep", "middle", "head"]).await;
        let deep = commit(&repo, tmp.path(), "deep", None, None, None).await;
        // The middle commit names the deep one through its detached metadata, so
        // the recursion crosses both metadata sources.
        let middle = commit(&repo, tmp.path(), "middle", None, None, None).await;
        repo.write_commit_detached_metadata(&middle, Some(&checksum_list(GC_ROOTS, &[deep])))
            .await
            .unwrap();
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(checksum_list(GC_ROOTS, &[middle])),
            Some("main"),
        )
        .await;

        repo.prune(&gc_root_options()).await.unwrap();
        for (label, commit) in [("head", head), ("middle", middle), ("deep", deep)] {
            assert!(holds(&repo, &commit).await, "{label} survives the prune");
        }
    });
}

#[test]
fn a_kept_commit_keeps_its_detached_metadata() {
    let tmp = TmpDir::new("gc-roots-keeps-commitmeta");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["kept", "head"]).await;
        let kept = commit(&repo, tmp.path(), "kept", None, None, None).await;
        repo.write_commit_detached_metadata(
            &kept,
            Some(&dict(
                "test.note",
                Type::parse("s").unwrap(),
                Value::Str("keep me".into()),
            )),
        )
        .await
        .unwrap();
        commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(checksum_list(GC_ROOTS, &[kept])),
            Some("main"),
        )
        .await;

        repo.prune(&gc_root_options()).await.unwrap();
        assert!(
            repo.read_commit_detached_metadata(&kept)
                .await
                .unwrap()
                .is_some(),
            "the detached metadata of a property-kept commit survives with it"
        );
    });
}

#[test]
fn the_parent_edge_is_not_followed_when_it_is_off() {
    let tmp = TmpDir::new("gc-roots-parent-off");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["first", "second"]).await;
        let first = commit(&repo, tmp.path(), "first", None, None, None).await;
        let second = commit(&repo, tmp.path(), "second", Some(first), None, Some("main")).await;

        let opts = PruneOptions {
            refs_only: true,
            traverse_parent: false,
            ..PruneOptions::new()
        };
        repo.prune(&opts).await.unwrap();
        assert!(holds(&repo, &second).await, "the ref's commit survives");
        assert!(
            !holds(&repo, &first).await,
            "the parent is not reachable with the parent edge off"
        );
    });
}

#[test]
fn the_parent_edge_is_followed_by_default() {
    let tmp = TmpDir::new("gc-roots-parent-on");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["first", "second"]).await;
        let first = commit(&repo, tmp.path(), "first", None, None, None).await;
        let second = commit(&repo, tmp.path(), "second", Some(first), None, Some("main")).await;

        let opts = PruneOptions {
            refs_only: true,
            ..PruneOptions::new()
        };
        repo.prune(&opts).await.unwrap();
        assert!(holds(&repo, &second).await, "the ref's commit survives");
        assert!(holds(&repo, &first).await, "its parent survives with it");
    });
}

#[test]
fn a_property_edge_seeds_the_full_depth() {
    let tmp = TmpDir::new("gc-roots-depth");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["base", "tip", "head"]).await;
        // A two-commit chain the ref does not name, reached by one property edge
        // at its tip. Depth counts parent hops, and the edge seeds the walk's
        // own depth, so the chain is kept whole.
        let base = commit(&repo, tmp.path(), "base", None, None, None).await;
        let tip = commit(&repo, tmp.path(), "tip", Some(base), None, None).await;
        commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(checksum_list(GC_ROOTS, &[tip])),
            Some("main"),
        )
        .await;

        let opts = PruneOptions {
            traverse_parent: true,
            ..gc_root_options()
        };
        repo.prune(&opts).await.unwrap();
        assert!(
            holds(&repo, &tip).await,
            "the commit the property names survives"
        );
        assert!(
            holds(&repo, &base).await,
            "and its parent, since the edge seeds the walk's depth"
        );
    });
}

#[test]
fn a_property_of_the_wrong_type_fails_the_prune() {
    let tmp = TmpDir::new("gc-roots-bad-type");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head"]).await;
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(dict(
                GC_ROOTS,
                Type::parse("as").unwrap(),
                Value::Array(vec![Value::Str("not a checksum".into())]),
            )),
            Some("main"),
        )
        .await;

        let err = repo.prune(&gc_root_options()).await.unwrap_err();
        match err {
            Error::InvalidGcRoot {
                commit,
                property,
                reason,
            } => {
                assert_eq!(commit, head);
                assert_eq!(property, GC_ROOTS);
                assert!(
                    reason.contains("`as`"),
                    "the reason names the type: {reason}"
                );
            }
            other => panic!("expected InvalidGcRoot, got {other:?}"),
        }
        assert!(holds(&repo, &head).await, "a refused prune deletes nothing");
    });
}

#[test]
fn an_element_of_the_wrong_length_fails_the_prune() {
    let tmp = TmpDir::new("gc-roots-bad-element");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head"]).await;
        commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(dict(
                GC_ROOTS,
                Type::parse("aay").unwrap(),
                Value::Array(vec![Value::Bytes(vec![0u8; 20])]),
            )),
            Some("main"),
        )
        .await;

        let err = repo.prune(&gc_root_options()).await.unwrap_err();
        match err {
            Error::InvalidGcRoot { reason, .. } => assert!(
                reason.contains("20 bytes"),
                "the reason names the length: {reason}"
            ),
            other => panic!("expected InvalidGcRoot, got {other:?}"),
        }
    });
}

#[test]
fn a_property_naming_an_absent_commit_is_tolerated() {
    let tmp = TmpDir::new("gc-roots-absent");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head"]).await;
        let absent = Checksum::from_bytes([0x5a; 32]);
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(checksum_list(GC_ROOTS, &[absent])),
            Some("main"),
        )
        .await;

        // A dangling property edge is a dangling reference like any other: the
        // walk keeps its name and descends into nothing.
        repo.prune(&gc_root_options()).await.unwrap();
        assert!(holds(&repo, &head).await, "the ref's commit survives");
        assert!(
            !holds(&repo, &absent).await,
            "nothing is created for the absent target"
        );
    });
}

#[test]
fn a_refused_prune_keeps_the_commit_it_was_told_to_delete() {
    let tmp = TmpDir::new("gc-roots-refused-delete");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "spare"]).await;
        // The ref's commit holds a property the walk cannot read, so the prune
        // is refused. The spare commit is unreferenced, so it is deletable.
        commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(dict(
                GC_ROOTS,
                Type::parse("as").unwrap(),
                Value::Array(vec![Value::Str("not a checksum".into())]),
            )),
            Some("main"),
        )
        .await;
        let spare = commit(&repo, tmp.path(), "spare", None, None, None).await;

        let opts = PruneOptions {
            delete_commit: Some(spare),
            ..gc_root_options()
        };
        let err = repo.prune(&opts).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidGcRoot { .. }),
            "expected InvalidGcRoot, got {err:?}"
        );
        assert!(
            holds(&repo, &spare).await,
            "a refused prune keeps the commit it was told to delete"
        );
    });
}

#[test]
fn a_deleted_commit_takes_the_objects_only_it_reached() {
    let tmp = TmpDir::new("gc-roots-delete-orphans");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["first", "second"]).await;
        let first = commit(&repo, tmp.path(), "first", None, None, None).await;
        commit(&repo, tmp.path(), "second", Some(first), None, Some("main")).await;
        let orphaned = commit_root(&repo, &first).await;

        let opts = PruneOptions {
            delete_commit: Some(first),
            ..PruneOptions::new()
        };
        repo.prune(&opts).await.unwrap();

        assert!(!holds(&repo, &first).await, "the named commit is removed");
        assert!(
            !repo
                .has_object(ObjectType::DirTree, &orphaned)
                .await
                .unwrap(),
            "the tree only it reached is swept with it"
        );
    });
}

#[test]
fn a_dry_run_keeps_the_commit_it_was_told_to_delete() {
    let tmp = TmpDir::new("gc-roots-dry-run-delete");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["first", "second"]).await;
        let first = commit(&repo, tmp.path(), "first", None, None, None).await;
        commit(&repo, tmp.path(), "second", Some(first), None, Some("main")).await;
        let orphaned = commit_root(&repo, &first).await;

        let opts = PruneOptions {
            delete_commit: Some(first),
            no_prune: true,
            ..PruneOptions::new()
        };
        let stats = repo.prune(&opts).await.unwrap();

        assert!(
            stats.pruned_objects > 0,
            "the dry run reports the sweep the deletion would cause"
        );
        assert!(
            holds(&repo, &first).await,
            "the commit named for deletion stays"
        );
        assert!(
            repo.has_object(ObjectType::DirTree, &orphaned)
                .await
                .unwrap(),
            "and so does the tree only it reached"
        );
    });
}

/// The root dirtree checksum of a stored commit.
async fn commit_root(repo: &Repo, commit: &Checksum) -> Checksum {
    repo.load_commit(commit).await.unwrap().0.root_dirtree
}
