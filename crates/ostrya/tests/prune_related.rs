//! The local prune on the related commits of a commit.
//!
//! `Repo::prune` keeps the commits that field 2 (the dependencies) and the
//! detached key `ostrya.related` (the build sources) of each reached commit
//! name. It walks each such commit as a root of its own at the global bound
//! of the run, and reads the two fields of each related commit too. A
//! defective value gives a warning in `PruneStats::warnings` and roots
//! nothing, and the run continues. The `ostree` command has no counterpart,
//! so the tests use ostrya alone.

mod common;

use std::path::Path;

use common::{TmpDir, dependency_warning, store_with_field2};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DictBuilder,
    Error, MutableTree, ObjectType, PruneOptions, RelatedField, RelatedWarning, Repo, RepoMode,
    RepoTree, Transaction, Type, Value, WeakRefFilter,
};
use ostrya_rt::block_on;

/// A fixed timestamp, so the commits are reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// The detached metadata key of the build sources.
const RELATED_KEY: &str = "ostrya.related";

/// Writes a tree with one file at `base/<name>`. The content of the file names
/// the tree.
fn write_tree(base: &Path, name: &str) {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), format!("{name}\n")).unwrap();
}

/// Writes the trees `base/<name>` and creates an archive repository under
/// `base/repo`.
async fn repo_with_trees(base: &Path, names: &[&str]) -> Repo {
    for name in names {
        write_tree(base, name);
    }
    Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap()
}

/// Stages the tree `base/<name>` in `txn` and returns its root.
async fn stage_tree(txn: &Transaction, base: &Path, name: &str) -> RepoTree {
    use std::os::fd::AsFd;
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
    txn.write_mtree(&mut mtree).await.unwrap()
}

/// Commits the tree `base/<name>` into `repo` with the parent `parent` and the
/// dependencies `related`. If `branch` names a ref, the transaction also sets
/// that ref to the new commit.
async fn commit(
    repo: &Repo,
    base: &Path,
    name: &str,
    parent: Option<Checksum>,
    related: &[(&str, Checksum)],
    branch: Option<&str>,
) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let root = stage_tree(&txn, base, name).await;
    let opts = CommitOptions {
        parent,
        subject: Some(name.to_owned()),
        timestamp: Some(FIXED_TS),
        related: related
            .iter()
            .map(|(entry, checksum)| ((*entry).to_owned(), *checksum))
            .collect(),
        ..CommitOptions::default()
    };
    let commit = txn.write_commit(opts, &root).await.unwrap();
    if let Some(branch) = branch {
        txn.set_ref(branch, Some(&commit));
    }
    txn.commit().await.unwrap();
    commit
}

/// Returns an `a(say)` variant of the build sources `entries`.
fn sources(entries: &[(&str, &[u8])]) -> (Type, Value) {
    let elements = entries
        .iter()
        .map(|(name, bytes)| {
            Value::Tuple(vec![
                Value::Str((*name).to_owned()),
                Value::Bytes(bytes.to_vec()),
            ])
        })
        .collect();
    (Type::parse("a(say)").unwrap(), Value::Array(elements))
}

/// Returns an `a{sv}` with one entry for each `(key, (type, value))`, in the
/// order of `entries`.
fn dict(entries: Vec<(&str, (Type, Value))>) -> Value {
    let mut builder = DictBuilder::new();
    for (key, (ty, value)) in entries {
        builder.insert(key, ty, value);
    }
    builder.build()
}

/// Returns the loose path of the `.commitmeta` of `commit` in `repo`.
fn detached_path(repo: &Repo, commit: &Checksum) -> std::path::PathBuf {
    repo.path().join("objects").join(ostrya::loose_path(
        commit,
        ObjectType::CommitMeta,
        repo.mode(),
    ))
}

/// Writes the bytes `bytes` as the `.commitmeta` of `commit` with no check,
/// as a write out of band does.
fn write_raw_bytes(repo: &Repo, commit: &Checksum, bytes: &[u8]) {
    let path = detached_path(repo, commit);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Writes `meta` as the `.commitmeta` of `commit` with no check. Both write
/// paths of the library refuse a defective `ostrya.related` value.
fn write_raw_detached(repo: &Repo, commit: &Checksum, meta: &Value) {
    let bytes = ostrya_core::to_bytes(&Type::parse("a{sv}").unwrap(), meta).unwrap();
    write_raw_bytes(repo, commit, &bytes);
}

/// Returns `true` if the repository still holds the commit object `commit`.
async fn holds(repo: &Repo, commit: &Checksum) -> bool {
    repo.has_object(ObjectType::Commit, commit).await.unwrap()
}

/// Returns the checksum of the root dirtree of a stored commit.
async fn commit_root(repo: &Repo, commit: &Checksum) -> Checksum {
    repo.load_commit(commit).await.unwrap().0.root_dirtree
}

/// Returns `true` if the repository still holds the dirtree `root`.
///
/// `root` is the root dirtree of a commit. The caller records it while the
/// commit still stands.
async fn holds_tree(repo: &Repo, root: &Checksum) -> bool {
    repo.has_object(ObjectType::DirTree, root).await.unwrap()
}

/// Returns the options of a prune that roots the walk on the refs alone.
fn refs_only() -> PruneOptions {
    PruneOptions {
        refs_only: true,
        ..PruneOptions::new()
    }
}

/// Returns a warning of the build sources of `commit`.
fn build_source_warning(commit: Checksum, reason: &str) -> RelatedWarning {
    RelatedWarning {
        commit,
        field: RelatedField::BuildSources,
        reason: reason.to_owned(),
    }
}

#[test]
fn a_dependency_and_a_build_source_of_a_kept_commit_survive() {
    let tmp = TmpDir::new("prune-related-keep");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["dep", "src", "head", "plain"]).await;
        let dep = commit(&repo, tmp.path(), "dep", None, &[], None).await;
        let src = commit(&repo, tmp.path(), "src", None, &[], None).await;
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            None,
            &[("boot/dep", dep)],
            Some("main"),
        )
        .await;
        repo.add_detached_related(&head, "layer/src", &src)
            .await
            .unwrap();
        // Each related commit has detached metadata of its own.
        let note = dict(vec![(
            "test.note",
            (Type::parse("s").unwrap(), Value::Str("kept".into())),
        )]);
        for commit in [dep, src] {
            repo.write_commit_detached_metadata(&commit, Some(&note))
                .await
                .unwrap();
        }
        let dep_root = commit_root(&repo, &dep).await;
        let src_root = commit_root(&repo, &src).await;

        let stats = repo.prune(&refs_only()).await.unwrap();
        assert!(stats.warnings.is_empty(), "got {:?}", stats.warnings);
        for (label, commit, root) in [("dep", dep, dep_root), ("src", src, src_root)] {
            assert!(holds(&repo, &commit).await, "{label} survives");
            assert!(
                holds_tree(&repo, &root).await,
                "the tree of {label} survives"
            );
            assert_eq!(
                repo.read_commit_detached_metadata(&commit).await.unwrap(),
                Some(note.clone()),
                "the detached metadata of {label} survives"
            );
        }

        // A ref to a commit with no related entry keeps neither commit.
        let head_root = commit_root(&repo, &head).await;
        let plain = commit(&repo, tmp.path(), "plain", None, &[], Some("main")).await;
        let stats = repo.prune(&refs_only()).await.unwrap();
        assert!(stats.warnings.is_empty());
        assert!(holds(&repo, &plain).await);
        for (label, commit, root) in [
            ("head", head, head_root),
            ("dep", dep, dep_root),
            ("src", src, src_root),
        ] {
            assert!(!holds(&repo, &commit).await, "{label} is pruned");
            assert!(
                !holds_tree(&repo, &root).await,
                "the tree of {label} is pruned"
            );
            assert!(!detached_path(&repo, &commit).exists());
        }
    });
}

#[test]
fn a_related_entry_that_names_an_absent_commit_roots_nothing() {
    let tmp = TmpDir::new("prune-related-absent");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        let plain = commit(&repo, tmp.path(), "head", None, &[], None).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, &[], None).await;
        let absent = [0x44; 32];
        let head = store_with_field2(&repo, &plain, &[("boot/gone", &absent)]).await;
        repo.set_ref_immediate("main", Some(&head)).await.unwrap();
        repo.add_detached_related(
            &head,
            "layer/gone",
            &Checksum::from_ay(&[0x45; 32]).unwrap(),
        )
        .await
        .unwrap();

        let stats = repo.prune(&refs_only()).await.unwrap();
        assert!(stats.warnings.is_empty(), "got {:?}", stats.warnings);
        assert!(holds(&repo, &head).await);
        assert!(!holds(&repo, &orphan).await, "the orphan is pruned");
    });
}

#[test]
fn a_weak_ref_named_by_a_build_source_of_a_strong_commit_survives() {
    let tmp = TmpDir::new("prune-related-weak");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["src", "other", "head"]).await;
        let src = commit(&repo, tmp.path(), "src", None, &[], Some("cache/src")).await;
        let other = commit(&repo, tmp.path(), "other", None, &[], Some("cache/other")).await;
        let head = commit(&repo, tmp.path(), "head", None, &[], Some("main")).await;
        repo.add_detached_related(&head, "layer/src", &src)
            .await
            .unwrap();

        let opts = PruneOptions {
            weak_ref_filter: WeakRefFilter::new(|name, _| !name.starts_with("cache/")),
            ..refs_only()
        };
        let stats = repo.prune(&opts).await.unwrap();
        assert_eq!(stats.deleted_refs, ["cache/other"]);
        assert!(holds(&repo, &src).await, "the build source survives");
        assert_eq!(
            repo.resolve_rev("cache/src", true).await.unwrap(),
            Some(src),
            "the weak ref of the build source survives"
        );
        assert!(
            !holds(&repo, &other).await,
            "the commit of the other weak ref is pruned"
        );
    });
}

#[test]
fn a_build_source_of_a_build_source_survives() {
    let tmp = TmpDir::new("prune-related-recursive");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["base", "mid", "head", "orphan"]).await;
        let base = commit(&repo, tmp.path(), "base", None, &[], None).await;
        let mid = commit(&repo, tmp.path(), "mid", None, &[], None).await;
        let head = commit(&repo, tmp.path(), "head", None, &[], Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, &[], None).await;
        repo.add_detached_related(&head, "layer/mid", &mid)
            .await
            .unwrap();
        repo.add_detached_related(&mid, "layer/base", &base)
            .await
            .unwrap();

        repo.prune(&refs_only()).await.unwrap();
        assert!(holds(&repo, &mid).await, "the build source survives");
        assert!(holds(&repo, &base).await, "its build source survives");
        assert!(!holds(&repo, &orphan).await, "the orphan is pruned");
    });
}

#[test]
fn a_cycle_of_build_sources_ends_the_walk() {
    let tmp = TmpDir::new("prune-related-cycle");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["a", "b", "orphan"]).await;
        let a = commit(&repo, tmp.path(), "a", None, &[], Some("main")).await;
        let b = commit(&repo, tmp.path(), "b", None, &[], None).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, &[], None).await;
        repo.add_detached_related(&a, "layer/b", &b).await.unwrap();
        repo.add_detached_related(&b, "layer/a", &a).await.unwrap();
        repo.add_detached_related(&a, "layer/a", &a).await.unwrap();

        let stats = repo.prune(&refs_only()).await.unwrap();
        assert!(stats.warnings.is_empty());
        assert!(holds(&repo, &a).await);
        assert!(holds(&repo, &b).await, "the cycle keeps b");
        assert!(!holds(&repo, &orphan).await, "the orphan is pruned");
    });
}

#[test]
fn a_nested_dependency_roots_its_dependencies_with_no_warning() {
    let tmp = TmpDir::new("prune-related-nested");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["c", "b", "head", "orphan"]).await;
        let c = commit(&repo, tmp.path(), "c", None, &[], None).await;
        let plain_b = commit(&repo, tmp.path(), "b", None, &[], None).await;
        let plain_head = commit(&repo, tmp.path(), "head", None, &[], None).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, &[], None).await;
        // The commit write refuses a nested dependency, so the commits are
        // stored as metadata objects.
        let b = store_with_field2(&repo, &plain_b, &[("x/c", c.as_bytes())]).await;
        let head = store_with_field2(&repo, &plain_head, &[("x/b", b.as_bytes())]).await;
        repo.set_ref_immediate("main", Some(&head)).await.unwrap();

        let stats = repo.prune(&refs_only()).await.unwrap();
        assert!(stats.warnings.is_empty(), "got {:?}", stats.warnings);
        assert!(holds(&repo, &b).await, "the dependency survives");
        assert!(
            holds(&repo, &c).await,
            "the dependency of the dependency survives"
        );
        assert!(!holds(&repo, &plain_b).await);
        assert!(!holds(&repo, &orphan).await, "the orphan is pruned");
    });
}

#[test]
fn unsorted_and_repeated_dependency_names_root_each_entry() {
    let tmp = TmpDir::new("prune-related-unsorted");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["x", "y", "z", "head"]).await;
        let x = commit(&repo, tmp.path(), "x", None, &[], None).await;
        let y = commit(&repo, tmp.path(), "y", None, &[], None).await;
        let z = commit(&repo, tmp.path(), "z", None, &[], None).await;
        let plain = commit(&repo, tmp.path(), "head", None, &[], None).await;
        let head = store_with_field2(
            &repo,
            &plain,
            &[
                ("b/n", x.as_bytes()),
                ("a/n", y.as_bytes()),
                ("b/n", z.as_bytes()),
            ],
        )
        .await;
        repo.set_ref_immediate("main", Some(&head)).await.unwrap();

        let stats = repo.prune(&refs_only()).await.unwrap();
        assert!(stats.warnings.is_empty(), "got {:?}", stats.warnings);
        for kept in [x, y, z] {
            assert!(holds(&repo, &kept).await, "{kept} survives");
        }
    });
}

#[test]
fn a_defective_build_source_value_gives_a_warning() {
    let tmp = TmpDir::new("prune-related-bad-sources");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["src", "head", "orphan"]).await;
        let src = commit(&repo, tmp.path(), "src", None, &[], None).await;
        let head = commit(&repo, tmp.path(), "head", None, &[], Some("main")).await;
        let strings = (
            Type::parse("as").unwrap(),
            Value::Array(vec![Value::Str(src.to_hex())]),
        );
        let cases = vec![
            (strings, vec!["type is `as`, not `a(say)`"], false),
            (
                sources(&[("source/ok", src.as_bytes()), ("source/x", &[0x55; 31])]),
                vec!["entry 1 (source/x) has a checksum of 31 bytes, not 32"],
                true,
            ),
            (
                sources(&[
                    ("", &[0x55; 32]),
                    ("source/ok", src.as_bytes()),
                    ("", &[0x56; 3]),
                ]),
                vec!["entry 0 has an empty name", "entry 2 has an empty name"],
                true,
            ),
        ];
        for (value, reasons, keeps_src) in cases {
            let orphan = commit(&repo, tmp.path(), "orphan", None, &[], None).await;
            write_raw_detached(&repo, &head, &dict(vec![(RELATED_KEY, value)]));
            let stats = repo.prune(&refs_only()).await.unwrap();
            let expected: Vec<RelatedWarning> = reasons
                .iter()
                .map(|reason| build_source_warning(head, reason))
                .collect();
            assert_eq!(stats.warnings, expected);
            assert_eq!(
                stats.warnings[0].to_string(),
                format!(
                    "related commits in ostrya.related of commit {head}: {}",
                    reasons[0]
                )
            );
            assert_eq!(holds(&repo, &src).await, keeps_src, "the valid entry roots");
            assert!(!holds(&repo, &orphan).await, "the run completes its sweep");
            if !keeps_src {
                // The next case needs the commit again.
                commit(&repo, tmp.path(), "src", None, &[], None).await;
            }
        }
    });
}

#[test]
fn a_defective_dependency_entry_gives_a_warning() {
    let tmp = TmpDir::new("prune-related-bad-field2");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["dep", "other", "src", "head", "orphan"]).await;
        let dep = commit(&repo, tmp.path(), "dep", None, &[], None).await;
        let other = commit(&repo, tmp.path(), "other", None, &[], None).await;
        let src = commit(&repo, tmp.path(), "src", None, &[], None).await;
        let plain = commit(&repo, tmp.path(), "head", None, &[], None).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, &[], None).await;
        let head = store_with_field2(
            &repo,
            &plain,
            &[
                ("a/ok", dep.as_bytes()),
                ("", other.as_bytes()),
                ("b/short", &dep.as_bytes()[..31]),
            ],
        )
        .await;
        repo.set_ref_immediate("main", Some(&head)).await.unwrap();
        // The build sources of the same commit are defective too. The
        // warnings of field 2 come first.
        write_raw_detached(
            &repo,
            &head,
            &dict(vec![(
                RELATED_KEY,
                sources(&[("layer/src", src.as_bytes()), ("layer/x", &[0x55; 2])]),
            )]),
        );

        let stats = repo.prune(&refs_only()).await.unwrap();
        assert_eq!(
            stats.warnings,
            vec![
                dependency_warning(head, "entry 1 has an empty name"),
                dependency_warning(head, "entry 2 (b/short) has a checksum of 31 bytes, not 32"),
                build_source_warning(head, "entry 1 (layer/x) has a checksum of 2 bytes, not 32"),
            ]
        );
        assert_eq!(
            stats.warnings[0].to_string(),
            format!("related commits in field 2 of commit {head}: entry 1 has an empty name")
        );
        assert!(holds(&repo, &dep).await, "the valid dependency survives");
        assert!(holds(&repo, &src).await, "the valid build source survives");
        assert!(
            !holds(&repo, &other).await,
            "the defective entry roots nothing"
        );
        assert!(!holds(&repo, &orphan).await, "the orphan is pruned");
    });
}

#[test]
fn the_warnings_are_sorted_by_commit() {
    let tmp = TmpDir::new("prune-related-sorted");
    block_on(async {
        // Sixteen commits, each with its own ref. The walk reads them in the
        // order of the roots, which follows the ref listing or the object
        // listing. The chance that this order is the sorted order is 1 in
        // 16!, so a run without the sort fails.
        let names: Vec<String> = (0..16).map(|i| format!("t{i:02}")).collect();
        let trees: Vec<&str> = names.iter().map(String::as_str).collect();
        let repo = repo_with_trees(tmp.path(), &trees).await;
        let mut heads = Vec::new();
        for name in &trees {
            let branch = format!("b/{name}");
            let head = commit(&repo, tmp.path(), name, None, &[], Some(&branch)).await;
            write_raw_detached(
                &repo,
                &head,
                &dict(vec![(RELATED_KEY, sources(&[("", &[0x55; 32])]))]),
            );
            heads.push(head);
        }
        heads.sort();
        for opts in [refs_only(), PruneOptions::new()] {
            let stats = repo.prune(&opts).await.unwrap();
            let commits: Vec<Checksum> = stats.warnings.iter().map(|w| w.commit).collect();
            assert_eq!(commits, heads);
        }
    });
}

#[test]
fn the_parent_edge_off_still_follows_related_edges() {
    let tmp = TmpDir::new("prune-related-no-parent");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["dp", "dep", "sp", "src", "hp", "head"]).await;
        let dp = commit(&repo, tmp.path(), "dp", None, &[], None).await;
        let dep = commit(&repo, tmp.path(), "dep", Some(dp), &[], None).await;
        let sp = commit(&repo, tmp.path(), "sp", None, &[], None).await;
        let src = commit(&repo, tmp.path(), "src", Some(sp), &[], None).await;
        let hp = commit(&repo, tmp.path(), "hp", None, &[], None).await;
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            Some(hp),
            &[("boot/dep", dep)],
            Some("main"),
        )
        .await;
        repo.add_detached_related(&head, "layer/src", &src)
            .await
            .unwrap();

        let opts = PruneOptions {
            traverse_parent: false,
            ..refs_only()
        };
        repo.prune(&opts).await.unwrap();
        assert!(holds(&repo, &head).await);
        assert!(holds(&repo, &dep).await, "the dependency survives");
        assert!(holds(&repo, &src).await, "the build source survives");
        for (label, parent) in [("head", hp), ("dep", dp), ("src", sp)] {
            assert!(
                !holds(&repo, &parent).await,
                "the parent of {label} is pruned"
            );
        }
    });
}

#[test]
fn a_related_commit_takes_the_global_bound() {
    let tmp = TmpDir::new("prune-related-depth");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["sp", "src", "head"]).await;
        let sp = commit(&repo, tmp.path(), "sp", None, &[], None).await;
        let src = commit(&repo, tmp.path(), "src", Some(sp), &[], None).await;
        let head = commit(&repo, tmp.path(), "head", None, &[], Some("main")).await;
        repo.add_detached_related(&head, "layer/src", &src)
            .await
            .unwrap();

        // The global depth applies to the build source, as to a ref.
        repo.prune(&refs_only()).await.unwrap();
        assert!(holds(&repo, &sp).await, "the full depth keeps the parent");
        let opts = PruneOptions {
            depth: 0,
            ..refs_only()
        };
        repo.prune(&opts).await.unwrap();
        assert!(holds(&repo, &src).await, "the build source survives");
        assert!(!holds(&repo, &sp).await, "depth 0 keeps no parent");
    });
}

#[test]
fn a_related_commit_deep_in_history_takes_the_global_bound() {
    let tmp = TmpDir::new("prune-related-deep");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["sp", "src", "h0", "h1", "h2"]).await;
        let sp = commit(&repo, tmp.path(), "sp", None, &[], None).await;
        let src = commit(&repo, tmp.path(), "src", Some(sp), &[], None).await;
        let h0 = commit(&repo, tmp.path(), "h0", None, &[], None).await;
        let h1 = commit(&repo, tmp.path(), "h1", Some(h0), &[], None).await;
        commit(&repo, tmp.path(), "h2", Some(h1), &[], Some("main")).await;
        repo.add_detached_related(&h1, "layer/src", &src)
            .await
            .unwrap();

        // The walk reaches h1 with no parent left. The build source of h1
        // gets the global depth, so it keeps its parent.
        let opts = PruneOptions {
            depth: 1,
            ..refs_only()
        };
        repo.prune(&opts).await.unwrap();
        assert!(
            holds(&repo, &h1).await,
            "depth 1 keeps the parent of the head"
        );
        assert!(!holds(&repo, &h0).await, "depth 1 keeps no second parent");
        assert!(holds(&repo, &src).await, "the build source survives");
        assert!(holds(&repo, &sp).await, "the build source keeps its parent");
    });
}

#[test]
fn a_commit_expanded_twice_gives_its_warnings_once() {
    let tmp = TmpDir::new("prune-related-twice");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["h1", "h2"]).await;
        let h1 = commit(&repo, tmp.path(), "h1", None, &[], None).await;
        let h2 = commit(&repo, tmp.path(), "h2", Some(h1), &[], Some("main")).await;
        repo.add_detached_related(&h2, "layer/h1", &h1)
            .await
            .unwrap();
        write_raw_detached(
            &repo,
            &h1,
            &dict(vec![(RELATED_KEY, sources(&[("", &[0x55; 32])]))]),
        );

        // The walk reaches h1 over the parent edge with depth 1, and again as
        // a build source with depth 2. It reads the fields of h1 one time.
        let opts = PruneOptions {
            depth: 2,
            ..refs_only()
        };
        let stats = repo.prune(&opts).await.unwrap();
        assert_eq!(
            stats.warnings,
            vec![build_source_warning(h1, "entry 0 has an empty name")]
        );
    });
}

#[test]
fn an_absent_or_empty_commitmeta_gives_no_warning() {
    let tmp = TmpDir::new("prune-related-no-commitmeta");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["plain", "marked", "bad"]).await;
        let plain = commit(&repo, tmp.path(), "plain", None, &[], Some("plain")).await;
        let marked = commit(&repo, tmp.path(), "marked", None, &[], Some("marked")).await;
        let bad = commit(&repo, tmp.path(), "bad", None, &[], Some("bad")).await;
        // The zero-length file marks no detached metadata.
        write_raw_bytes(&repo, &marked, &[]);
        write_raw_detached(
            &repo,
            &bad,
            &dict(vec![(RELATED_KEY, sources(&[("", &[0x55; 32])]))]),
        );
        for opts in [refs_only(), PruneOptions::new()] {
            let stats = repo.prune(&opts).await.unwrap();
            assert_eq!(
                stats.warnings,
                vec![build_source_warning(bad, "entry 0 has an empty name")]
            );
            assert!(holds(&repo, &plain).await);
            assert!(holds(&repo, &marked).await);
            assert!(
                detached_path(&repo, &marked).exists(),
                "a kept commit keeps its marker"
            );
        }
    });
}

#[test]
fn a_dry_run_reports_the_warnings() {
    let tmp = TmpDir::new("prune-related-dry-run");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        let head = commit(&repo, tmp.path(), "head", None, &[], Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, &[], None).await;
        write_raw_detached(
            &repo,
            &head,
            &dict(vec![(RELATED_KEY, sources(&[("", &[0x55; 32])]))]),
        );
        let before = repo.list_objects().await.unwrap();
        let opts = PruneOptions {
            no_prune: true,
            ..refs_only()
        };
        let stats = repo.prune(&opts).await.unwrap();
        assert_eq!(
            stats.warnings,
            vec![build_source_warning(head, "entry 0 has an empty name")]
        );
        assert!(stats.pruned_objects > 0);
        assert_eq!(
            repo.list_objects().await.unwrap(),
            before,
            "a dry run deletes nothing"
        );
        assert_eq!(
            repo.prune(&refs_only()).await.unwrap().warnings,
            stats.warnings
        );
        assert!(!holds(&repo, &orphan).await);
    });
}

#[test]
fn a_commit_that_a_related_field_names_can_be_deleted() {
    let tmp = TmpDir::new("prune-related-delete");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["src", "base", "head"]).await;
        let base = commit(&repo, tmp.path(), "base", None, &[], None).await;
        let src = commit(&repo, tmp.path(), "src", None, &[], None).await;
        let head = commit(&repo, tmp.path(), "head", None, &[], Some("main")).await;
        repo.add_detached_related(&head, "layer/src", &src)
            .await
            .unwrap();
        repo.add_detached_related(&src, "layer/base", &base)
            .await
            .unwrap();

        let opts = PruneOptions {
            delete_commit: Some(src),
            ..refs_only()
        };
        let stats = repo.prune(&opts).await.unwrap();
        assert!(stats.warnings.is_empty());
        assert!(!holds(&repo, &src).await, "the named commit is removed");
        assert!(!holds(&repo, &base).await, "what only it named is swept");
        assert!(holds(&repo, &head).await);
        // The entry stays and names an absent commit, which roots nothing.
        assert_eq!(
            repo.read_commit_related(&head).await.unwrap().build_sources,
            vec![("layer/src".to_owned(), src)]
        );
        assert!(repo.prune(&refs_only()).await.unwrap().warnings.is_empty());
    });
}

#[test]
fn a_prune_of_each_commit_gives_the_same_warnings() {
    let tmp = TmpDir::new("prune-related-default");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "loose"]).await;
        let head = commit(&repo, tmp.path(), "head", None, &[], Some("main")).await;
        // No ref names the commit. A default prune roots it all the same.
        let loose = commit(&repo, tmp.path(), "loose", None, &[], None).await;
        for commit in [head, loose] {
            write_raw_detached(
                &repo,
                &commit,
                &dict(vec![(RELATED_KEY, sources(&[("x", &[0x55; 4])]))]),
            );
        }
        let mut expected = vec![
            build_source_warning(head, "entry 0 (x) has a checksum of 4 bytes, not 32"),
            build_source_warning(loose, "entry 0 (x) has a checksum of 4 bytes, not 32"),
        ];
        expected.sort_by_key(|w| w.commit);
        let stats = repo.prune(&PruneOptions::new()).await.unwrap();
        assert_eq!(stats.warnings, expected);
        assert!(holds(&repo, &loose).await);
    });
}

#[test]
fn a_commitmeta_that_does_not_parse_fails_the_prune() {
    let tmp = TmpDir::new("prune-related-bad-commitmeta");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        let head = commit(&repo, tmp.path(), "head", None, &[], Some("main")).await;
        commit(&repo, tmp.path(), "orphan", None, &[], None).await;
        // An `a{sv}` whose one entry claims an offset past the end.
        write_raw_bytes(&repo, &head, &[b'k', 0, 0, b's', 0xff]);
        let before = repo.list_objects().await.unwrap();
        let err = repo.prune(&refs_only()).await.unwrap_err();
        assert!(matches!(err, Error::Core(_)), "got {err:?}");
        assert_eq!(
            repo.list_objects().await.unwrap(),
            before,
            "the failed prune deletes nothing"
        );
    });
}

/// Appends `text` to the config of the repository under `base/repo` and
/// returns a new handle, which reads the changed config.
async fn reconfigure(base: &Path, text: &str) -> Repo {
    let path = base.join("repo");
    let config = path.join("config");
    let mut current = std::fs::read_to_string(&config).unwrap();
    current.push_str(text);
    std::fs::write(&config, current).unwrap();
    Repo::open(&path).await.unwrap()
}

#[test]
fn a_config_key_that_names_metadata_keys_changes_no_write_and_no_prune() {
    // The metadata key that the commits of this test give commit checksums
    // and strings.
    const ANCHORS: &str = "test.anchors";
    // The config of each variant. The `[ex-ostrya]` group holds no key that
    // names metadata keys, so the port reads none of these values.
    let variants = [
        ("absent", ""),
        (
            "valid",
            "\n[ex-ostrya]\ngc-root-metadata-keys=test.anchors;ostrya.related\n",
        ),
        (
            "malformed",
            "\n[ex-ostrya]\ngc-root-metadata-keys=app.roots\\\n",
        ),
    ];
    let mut outcomes = Vec::new();
    for (label, text) in variants {
        let tmp = TmpDir::new(&format!("prune-related-config-{label}"));
        let outcome = block_on(async {
            repo_with_trees(tmp.path(), &["orphan", "head", "cfs"]).await;
            let repo = reconfigure(tmp.path(), text).await;
            let orphan = commit(&repo, tmp.path(), "orphan", None, &[], None).await;
            let string = dict(vec![(
                ANCHORS,
                (Type::parse("s").unwrap(), Value::Str("main".into())),
            )]);

            // The commit metadata of the head names the orphan in an `aay`.
            let txn = repo.transaction().await.unwrap();
            let root = stage_tree(&txn, tmp.path(), "head").await;
            let checksums = dict(vec![(
                ANCHORS,
                (
                    Type::parse("aay").unwrap(),
                    Value::Array(vec![Value::Bytes(orphan.as_bytes().to_vec())]),
                ),
            )]);
            let opts = CommitOptions {
                subject: Some("head".into()),
                timestamp: Some(FIXED_TS),
                metadata: Some(checksums),
                ..CommitOptions::default()
            };
            let head = txn.write_commit(opts, &root).await.unwrap();
            txn.set_ref("main", Some(&head));
            txn.commit().await.unwrap();

            // Each write path takes a string value of the key.
            repo.write_commit_detached_metadata(&head, Some(&string))
                .await
                .unwrap();
            let txn = repo.transaction().await.unwrap();
            txn.set_commit_detached_metadata(&head, string.clone());
            txn.commit().await.unwrap();
            let txn = repo.transaction().await.unwrap();
            let root = stage_tree(&txn, tmp.path(), "cfs").await;
            let opts = CommitOptions {
                subject: Some("cfs".into()),
                timestamp: Some(FIXED_TS),
                metadata: Some(string.clone()),
                ..CommitOptions::default()
            };
            let plain = txn.write_commit(opts, &root).await.unwrap();
            txn.commit().await.unwrap();
            let txn = repo.transaction().await.unwrap();
            let cfs = repo
                .commit_add_composefs_metadata(&txn, &plain)
                .await
                .unwrap();
            txn.set_ref("cfs", Some(&cfs));
            txn.commit().await.unwrap();

            // A defective build-source value on a reached commit.
            let strings = (
                Type::parse("as").unwrap(),
                Value::Array(vec![Value::Str(orphan.to_hex())]),
            );
            write_raw_detached(&repo, &cfs, &dict(vec![(RELATED_KEY, strings)]));

            let stats = repo.prune(&refs_only()).await.unwrap();
            assert!(
                !holds(&repo, &orphan).await,
                "{label}: the orphan is pruned"
            );
            assert_eq!(
                stats.warnings,
                [build_source_warning(cfs, "type is `as`, not `a(say)`")],
                "{label}"
            );
            (stats.pruned_objects, stats.warnings)
        });
        outcomes.push(outcome);
    }
    assert_eq!(outcomes[0], outcomes[1], "the valid value changes nothing");
    assert_eq!(
        outcomes[0], outcomes[2],
        "the malformed value changes nothing"
    );
}
