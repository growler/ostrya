//! Integration tests of a prune with metadata GC roots and with the optional
//! parent edge.
//!
//! Both options are ostrya extensions, and the `ostree` command has no
//! counterpart. The tests build and prune these repositories with ostrya alone.
//! The prune tests that compare with the `ostree` command are in
//! `maintenance.rs`.

mod common;

use std::path::Path;

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DictBuilder,
    Error, MutableTree, ObjectType, PruneOptions, Repo, RepoMode, Type, Value,
};
use ostrya_rt::block_on;

/// A fixed timestamp, so the commits are reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// The metadata key that these tests configure as a GC root.
const GC_ROOTS: &str = "test.gc-roots";

/// Writes a tree with one file at `base/<name>`. The content of the file names
/// the tree.
fn write_tree(base: &Path, name: &str) {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), format!("{name}\n")).unwrap();
}

/// Returns an `a{sv}` with one key, whose value is an `aay` of commit
/// checksums.
fn checksum_list(key: &str, commits: &[Checksum]) -> Value {
    let elements = commits
        .iter()
        .map(|c| Value::Bytes(c.as_bytes().to_vec()))
        .collect();
    dict(key, Type::parse("aay").unwrap(), Value::Array(elements))
}

/// Returns an `a{sv}` with one key, with the type and the value that the caller
/// gives.
fn dict(key: &str, ty: Type, value: Value) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str(key.to_owned()),
        Value::Variant(Box::new((ty, value))),
    ])])
}

/// Returns an `aay` value of commit checksums, with its type.
fn checksums(commits: &[Checksum]) -> (Type, Value) {
    let elements = commits
        .iter()
        .map(|c| Value::Bytes(c.as_bytes().to_vec()))
        .collect();
    (Type::parse("aay").unwrap(), Value::Array(elements))
}

/// Returns an `(say)` pair of a canonical ref and checksum bytes.
fn pair(canonical_ref: &str, checksum: &[u8]) -> Value {
    Value::Tuple(vec![
        Value::Str(canonical_ref.to_owned()),
        Value::Bytes(checksum.to_vec()),
    ])
}

/// Returns an `a(say)` value of `(canonical ref, checksum)` pairs, with its
/// type.
fn pairs(pairs: &[(&str, &[u8])]) -> (Type, Value) {
    let elements = pairs.iter().map(|(r, c)| pair(r, c)).collect();
    (Type::parse("a(say)").unwrap(), Value::Array(elements))
}

/// Returns an `a{s(say)}` value of `name -> (canonical ref, checksum)`
/// entries, with its type.
fn named_pairs(entries: &[(&str, &str, &[u8])]) -> (Type, Value) {
    let elements = entries
        .iter()
        .map(|(name, r, c)| Value::Tuple(vec![Value::Str((*name).to_owned()), pair(r, c)]))
        .collect();
    (Type::parse("a{s(say)}").unwrap(), Value::Array(elements))
}

/// Returns an `a{sv}` with one entry for each `(key, (type, value))`, in the
/// order of `entries`. A key can occur more than one time.
fn entries(entries: Vec<(&str, (Type, Value))>) -> Value {
    let mut builder = DictBuilder::new();
    for (key, (ty, value)) in entries {
        builder.insert(key, ty, value);
    }
    builder.build()
}

/// Commits the tree `base/<name>` into `repo` with the given parent and
/// metadata. If `branch` names a ref, the function also sets that ref to the
/// result.
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

/// Writes the trees `base/<name>` and creates a repository under `base/repo`.
async fn repo_with_trees(base: &Path, names: &[&str]) -> Repo {
    for name in names {
        write_tree(base, name);
    }
    Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap()
}

/// Returns the prune options of these tests: refs only, no parent edge, and the
/// one configured metadata key.
fn gc_root_options() -> PruneOptions {
    PruneOptions::gc_roots([GC_ROOTS])
}

/// Returns `true` if the repository still holds `commit` as an object.
async fn holds(repo: &Repo, commit: &Checksum) -> bool {
    repo.has_object(ObjectType::Commit, commit).await.unwrap()
}

/// Runs a prune with `opts` that must fail with [`Error::InvalidGcRoot`] for
/// `expected_commit`, and returns the metadata key and the reason.
///
/// The function also checks that the prune deleted no object.
async fn refused_with(
    repo: &Repo,
    opts: &PruneOptions,
    expected_commit: &Checksum,
) -> (String, String) {
    let before = repo.list_objects().await.unwrap();
    let err = repo.prune(opts).await.unwrap_err();
    assert_eq!(
        repo.list_objects().await.unwrap(),
        before,
        "a refused prune deletes nothing"
    );
    match err {
        Error::InvalidGcRoot {
            commit,
            metadata_key,
            reason,
        } => {
            assert_eq!(commit, *expected_commit, "the error names the commit");
            (metadata_key, reason)
        }
        other => panic!("expected InvalidGcRoot, got {other:?}"),
    }
}

/// Runs a prune with [`gc_root_options`] that must fail with
/// [`Error::InvalidGcRoot`] for `expected_commit` and the key [`GC_ROOTS`],
/// and returns the reason.
///
/// The function also checks that the prune deleted no object.
async fn refused(repo: &Repo, expected_commit: &Checksum) -> String {
    let (metadata_key, reason) = refused_with(repo, &gc_root_options(), expected_commit).await;
    assert_eq!(metadata_key, GC_ROOTS);
    reason
}

/// Writes the commit of the tree `base/orphan`, which no ref and no metadata
/// key names. A prune that succeeds deletes it.
async fn orphan(repo: &Repo, base: &Path) -> Checksum {
    commit(repo, base, "orphan", None, None, None).await
}

#[test]
fn a_metadata_key_in_commit_metadata_keeps_its_target() {
    let tmp = TmpDir::new("gc-roots-commit-meta");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["kept", "head"]).await;
        // No ref names `kept`. The ref head names it through the metadata key.
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
            "the commit the metadata key names survives"
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
fn a_commit_no_metadata_key_names_is_pruned() {
    let tmp = TmpDir::new("gc-roots-control");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["orphan", "head"]).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, None, None).await;
        let head = commit(&repo, tmp.path(), "head", None, None, Some("main")).await;

        // The options are the same. Nothing names the orphan, so the prune
        // removes it.
        repo.prune(&gc_root_options()).await.unwrap();
        assert!(holds(&repo, &head).await, "the ref's own commit survives");
        assert!(
            !holds(&repo, &orphan).await,
            "a commit no ref and no metadata key names is pruned"
        );
    });
}

#[test]
fn a_metadata_key_in_detached_metadata_keeps_its_target() {
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
            "the commit the detached metadata key names survives"
        );
    });
}

#[test]
fn metadata_key_edges_are_followed_recursively() {
    let tmp = TmpDir::new("gc-roots-recursive");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["deep", "middle", "head"]).await;
        let deep = commit(&repo, tmp.path(), "deep", None, None, None).await;
        // The middle commit names the deep commit through its detached metadata,
        // so the recursion crosses both metadata sources.
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
            "the detached metadata of a metadata-key-kept commit survives with it"
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
fn a_metadata_key_edge_seeds_the_full_depth() {
    let tmp = TmpDir::new("gc-roots-depth");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["base", "tip", "head"]).await;
        // A chain of two commits that the ref does not name. One metadata-key
        // edge at its tip reaches it. The depth counts parent hops, and the edge
        // seeds the depth of the walk, so the prune keeps the full chain.
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
            "the commit the metadata key names survives"
        );
        assert!(
            holds(&repo, &base).await,
            "and its parent, since the edge seeds the walk's depth"
        );
    });
}

#[test]
fn a_metadata_key_of_the_wrong_type_fails_the_prune() {
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
                metadata_key,
                reason,
            } => {
                assert_eq!(commit, head);
                assert_eq!(metadata_key, GC_ROOTS);
                assert_eq!(reason, "type is `as`, not `aay`, `a(say)`, or `a{s(say)}`");
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
            Error::InvalidGcRoot { reason, .. } => {
                assert_eq!(reason, "element 0 is 20 bytes, not 32")
            }
            other => panic!("expected InvalidGcRoot, got {other:?}"),
        }
    });
}

#[test]
fn a_metadata_key_naming_an_absent_commit_is_tolerated() {
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

        // A dangling metadata-key edge is a dangling reference like all others.
        // The walk keeps its name and descends into nothing.
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
        // The commit of the ref holds a metadata key that the walk cannot read,
        // so the prune is refused. No ref names the spare commit, so a prune can
        // delete it.
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

/// Returns the checksum of the root dirtree of a stored commit.
async fn commit_root(repo: &Repo, commit: &Checksum) -> Checksum {
    repo.load_commit(commit).await.unwrap().0.root_dirtree
}

#[test]
fn one_key_twice_in_commit_metadata_keeps_the_anchors_of_both_entries() {
    let tmp = TmpDir::new("gc-roots-key-twice");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["first", "second", "head"]).await;
        let first = commit(&repo, tmp.path(), "first", None, None, None).await;
        let second = commit(&repo, tmp.path(), "second", None, None, None).await;
        let metadata = entries(vec![
            (GC_ROOTS, checksums(&[first])),
            (GC_ROOTS, pairs(&[("refs/second", second.as_bytes())])),
        ]);
        commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(metadata),
            Some("main"),
        )
        .await;

        repo.prune(&gc_root_options()).await.unwrap();
        assert!(
            holds(&repo, &first).await,
            "the anchor of the first entry survives"
        );
        assert!(
            holds(&repo, &second).await,
            "the anchor of the second entry survives"
        );
    });
}

#[test]
fn a_defective_second_entry_of_one_key_fails_the_prune() {
    let tmp = TmpDir::new("gc-roots-key-twice-defect");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["kept", "head", "orphan"]).await;
        let kept = commit(&repo, tmp.path(), "kept", None, None, None).await;
        let orphan = orphan(&repo, tmp.path()).await;
        let metadata = entries(vec![
            (GC_ROOTS, checksums(&[kept])),
            (
                GC_ROOTS,
                (
                    Type::parse("aay").unwrap(),
                    Value::Array(vec![Value::Bytes(vec![0; 20])]),
                ),
            ),
        ]);
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(metadata),
            Some("main"),
        )
        .await;

        assert_eq!(refused(&repo, &head).await, "element 0 is 20 bytes, not 32");
        assert!(holds(&repo, &orphan).await, "the orphan stays");
    });
}

#[test]
fn one_key_in_commit_and_detached_metadata_keeps_both_anchors() {
    let tmp = TmpDir::new("gc-roots-both-sources");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["attached", "detached", "head"]).await;
        let attached = commit(&repo, tmp.path(), "attached", None, None, None).await;
        let detached = commit(&repo, tmp.path(), "detached", None, None, None).await;
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(checksum_list(GC_ROOTS, &[attached])),
            Some("main"),
        )
        .await;
        let detached_metadata = entries(vec![(
            GC_ROOTS,
            pairs(&[("refs/detached", detached.as_bytes())]),
        )]);
        repo.write_commit_detached_metadata(&head, Some(&detached_metadata))
            .await
            .unwrap();

        repo.prune(&gc_root_options()).await.unwrap();
        assert!(
            holds(&repo, &attached).await,
            "the anchor of the commit metadata survives"
        );
        assert!(
            holds(&repo, &detached).await,
            "the anchor of the detached metadata survives"
        );
    });
}

#[test]
fn a_defective_detached_value_fails_the_prune_next_to_a_valid_one() {
    let tmp = TmpDir::new("gc-roots-detached-defect");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["kept", "head", "orphan"]).await;
        let kept = commit(&repo, tmp.path(), "kept", None, None, None).await;
        let orphan = orphan(&repo, tmp.path()).await;
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(checksum_list(GC_ROOTS, &[kept])),
            Some("main"),
        )
        .await;
        repo.write_commit_detached_metadata(
            &head,
            Some(&dict(
                GC_ROOTS,
                Type::parse("s").unwrap(),
                Value::Str("not anchors".into()),
            )),
        )
        .await
        .unwrap();

        assert_eq!(
            refused(&repo, &head).await,
            "type is `s`, not `aay`, `a(say)`, or `a{s(say)}`"
        );
        assert!(holds(&repo, &orphan).await, "the orphan stays");
    });
}

#[test]
fn a_pair_array_in_commit_metadata_keeps_its_anchor() {
    let tmp = TmpDir::new("gc-roots-pairs");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["kept", "head", "orphan"]).await;
        let kept = commit(&repo, tmp.path(), "kept", None, None, None).await;
        let orphan = orphan(&repo, tmp.path()).await;
        let metadata = entries(vec![(GC_ROOTS, pairs(&[("refs/kept", kept.as_bytes())]))]);
        commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(metadata),
            Some("main"),
        )
        .await;

        repo.prune(&gc_root_options()).await.unwrap();
        assert!(holds(&repo, &kept).await, "the anchor of the pair survives");
        assert!(!holds(&repo, &orphan).await, "the orphan is pruned");
    });
}

#[test]
fn a_named_pair_dict_in_detached_metadata_keeps_its_anchor() {
    let tmp = TmpDir::new("gc-roots-named-pairs");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["kept", "head"]).await;
        let kept = commit(&repo, tmp.path(), "kept", None, None, None).await;
        let head = commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        let detached_metadata = entries(vec![(
            GC_ROOTS,
            named_pairs(&[("app", "refs/kept", kept.as_bytes())]),
        )]);
        repo.write_commit_detached_metadata(&head, Some(&detached_metadata))
            .await
            .unwrap();

        repo.prune(&gc_root_options()).await.unwrap();
        assert!(
            holds(&repo, &kept).await,
            "the anchor of the entry survives"
        );
    });
}

#[test]
fn a_named_pair_dict_with_one_name_twice_keeps_both_anchors() {
    let tmp = TmpDir::new("gc-roots-name-twice");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["first", "second", "head"]).await;
        let first = commit(&repo, tmp.path(), "first", None, None, None).await;
        let second = commit(&repo, tmp.path(), "second", None, None, None).await;
        let metadata = entries(vec![(
            GC_ROOTS,
            named_pairs(&[
                ("app", "refs/first", first.as_bytes()),
                ("app", "refs/second", second.as_bytes()),
            ]),
        )]);
        commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(metadata),
            Some("main"),
        )
        .await;

        repo.prune(&gc_root_options()).await.unwrap();
        assert!(
            holds(&repo, &first).await,
            "the anchor of the first entry survives"
        );
        assert!(
            holds(&repo, &second).await,
            "the anchor of the second entry survives"
        );
    });
}

#[test]
fn the_strings_of_a_value_are_not_checked() {
    let tmp = TmpDir::new("gc-roots-strings");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["first", "second", "third", "head"]).await;
        let first = commit(&repo, tmp.path(), "first", None, None, None).await;
        let second = commit(&repo, tmp.path(), "second", None, None, None).await;
        let third = commit(&repo, tmp.path(), "third", None, None, None).await;
        // No ref has the name `refs/absent`, and `..` fails the ref-name rule.
        let metadata = entries(vec![
            (GC_ROOTS, pairs(&[("", first.as_bytes())])),
            (
                GC_ROOTS,
                named_pairs(&[
                    ("", "", second.as_bytes()),
                    ("app", "refs/absent/..", third.as_bytes()),
                ]),
            ),
            (GC_ROOTS, checksums(&[])),
            (GC_ROOTS, pairs(&[])),
            (GC_ROOTS, named_pairs(&[])),
        ]);
        commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(metadata),
            Some("main"),
        )
        .await;

        repo.prune(&gc_root_options()).await.unwrap();
        for (label, anchor) in [("first", first), ("second", second), ("third", third)] {
            assert!(holds(&repo, &anchor).await, "{label} survives the prune");
        }
    });
}

#[test]
fn an_anchor_reached_through_a_pair_is_expanded() {
    let tmp = TmpDir::new("gc-roots-pairs-recursive");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["deep", "middle", "head"]).await;
        let deep = commit(&repo, tmp.path(), "deep", None, None, None).await;
        let middle = commit(
            &repo,
            tmp.path(),
            "middle",
            None,
            Some(entries(vec![(
                GC_ROOTS,
                named_pairs(&[("app", "refs/deep", deep.as_bytes())]),
            )])),
            None,
        )
        .await;
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(entries(vec![(
                GC_ROOTS,
                pairs(&[("refs/middle", middle.as_bytes())]),
            )])),
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
fn an_array_of_string_pairs_fails_the_prune() {
    let tmp = TmpDir::new("gc-roots-bad-pair-type");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        let orphan = orphan(&repo, tmp.path()).await;
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(dict(
                GC_ROOTS,
                Type::parse("a(ss)").unwrap(),
                Value::Array(vec![Value::Tuple(vec![
                    Value::Str("refs/a".into()),
                    Value::Str("not a checksum".into()),
                ])]),
            )),
            Some("main"),
        )
        .await;

        assert_eq!(
            refused(&repo, &head).await,
            "type is `a(ss)`, not `aay`, `a(say)`, or `a{s(say)}`"
        );
        assert!(holds(&repo, &orphan).await, "the orphan stays");
    });
}

#[test]
fn a_short_checksum_in_a_pair_fails_the_prune() {
    let tmp = TmpDir::new("gc-roots-short-pair");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["kept", "head", "orphan"]).await;
        let kept = commit(&repo, tmp.path(), "kept", None, None, None).await;
        let orphan = orphan(&repo, tmp.path()).await;
        let metadata = entries(vec![(
            GC_ROOTS,
            pairs(&[("refs/kept", kept.as_bytes()), ("refs/short", &[0; 20])]),
        )]);
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(metadata),
            Some("main"),
        )
        .await;

        assert_eq!(refused(&repo, &head).await, "element 1 is 20 bytes, not 32");
        assert!(holds(&repo, &orphan).await, "the orphan stays");
    });
}

#[test]
fn a_short_checksum_in_a_named_pair_fails_the_prune() {
    let tmp = TmpDir::new("gc-roots-short-named-pair");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["kept", "head", "orphan"]).await;
        let kept = commit(&repo, tmp.path(), "kept", None, None, None).await;
        let orphan = orphan(&repo, tmp.path()).await;
        let metadata = entries(vec![(
            GC_ROOTS,
            named_pairs(&[
                ("app", "refs/kept", kept.as_bytes()),
                ("app", "refs/short", &[0; 20]),
            ]),
        )]);
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(metadata),
            Some("main"),
        )
        .await;

        assert_eq!(refused(&repo, &head).await, "element 1 is 20 bytes, not 32");
        assert!(holds(&repo, &orphan).await, "the orphan stays");
    });
}

#[test]
fn the_first_defect_in_walk_order_is_reported() {
    let tmp = TmpDir::new("gc-roots-defect-order");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        let orphan = orphan(&repo, tmp.path()).await;
        // The commit metadata holds the key `test.other` with a defective
        // entry, and then the key `GC_ROOTS` with two defective entries. The
        // detached metadata holds `GC_ROOTS` with a defective entry too.
        let metadata = entries(vec![
            ("test.other", (Type::parse("u").unwrap(), Value::U32(0))),
            (
                GC_ROOTS,
                (
                    Type::parse("aay").unwrap(),
                    Value::Array(vec![Value::Bytes(vec![0; 20])]),
                ),
            ),
            (GC_ROOTS, (Type::parse("u").unwrap(), Value::U32(0))),
        ]);
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(metadata),
            Some("main"),
        )
        .await;
        repo.write_commit_detached_metadata(
            &head,
            Some(&dict(
                GC_ROOTS,
                Type::parse("s").unwrap(),
                Value::Str("not anchors".into()),
            )),
        )
        .await
        .unwrap();

        // With `GC_ROOTS` alone, the reason is that of its first entry in the
        // commit metadata. The detached entry gives the reason of type `s`, so
        // the commit metadata comes before the detached metadata. The second
        // entry gives the reason of type `u`, so the dict order holds.
        assert_eq!(refused(&repo, &head).await, "element 0 is 20 bytes, not 32");

        // The list names `GC_ROOTS` first, and the dict holds `test.other`
        // first. The error names `GC_ROOTS`, so the order of the list comes
        // before the order of the dict.
        let opts = PruneOptions::gc_roots([GC_ROOTS, "test.other"]);
        let (metadata_key, reason) = refused_with(&repo, &opts, &head).await;
        assert_eq!(metadata_key, GC_ROOTS);
        assert_eq!(reason, "element 0 is 20 bytes, not 32");

        // A second head holds `test.other` with a defective entry in the
        // commit metadata alone, and `GC_ROOTS` with a defective entry in the
        // detached metadata alone. The ref moves to it, so the walk does not
        // reach the first head.
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(dict("test.other", Type::parse("u").unwrap(), Value::U32(0))),
            Some("main"),
        )
        .await;
        repo.write_commit_detached_metadata(
            &head,
            Some(&dict(
                GC_ROOTS,
                Type::parse("s").unwrap(),
                Value::Str("not anchors".into()),
            )),
        )
        .await
        .unwrap();

        // The list names `GC_ROOTS` first. The error names `GC_ROOTS` and the
        // reason of its detached entry, so the order of the list comes before
        // the order of the commit metadata and the detached metadata.
        let (metadata_key, reason) = refused_with(&repo, &opts, &head).await;
        assert_eq!(metadata_key, GC_ROOTS);
        assert_eq!(reason, "type is `s`, not `aay`, `a(say)`, or `a{s(say)}`");
        assert!(holds(&repo, &orphan).await, "the orphan stays");
    });
}
