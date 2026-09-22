//! Prune with a weak-ref classifier.
//!
//! `PruneOptions::weak_ref_filter` splits the refs under `refs/heads` into
//! strong refs, which root the walk, and weak refs, which root nothing. A weak
//! ref survives where the walk reaches its commit over some other edge, and the
//! run unlinks it otherwise. The classifier is a port extension with no
//! counterpart in the `ostree` tool, so these repositories are built and pruned
//! with the port alone.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Error,
    MutableTree, ObjectType, PruneOptions, Repo, RepoMode, Type, Value, WeakRefFilter,
};
use ostrya_rt::block_on;

/// A fixed timestamp, so the commits are reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// The metadata key these tests configure as a GC root.
const GC_ROOTS: &str = "test.gc-roots";

/// Write a one-file tree at `dir`, its content naming it.
fn write_tree(base: &Path, name: &str) {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), format!("{name}\n")).unwrap();
}

/// An `a{sv}` holding one key whose value is an `aay` of commit checksums.
fn checksum_list(key: &str, commits: &[Checksum]) -> Value {
    let elements = commits
        .iter()
        .map(|c| Value::Bytes(c.as_bytes().to_vec()))
        .collect();
    dict(key, Type::parse("aay").unwrap(), Value::Array(elements))
}

/// An `a{sv}` holding one key of the caller's type and value.
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

/// Whether the repository still holds `commit` as an object.
async fn holds(repo: &Repo, commit: &Checksum) -> bool {
    repo.has_object(ObjectType::Commit, commit).await.unwrap()
}

/// The root dirtree checksum of a stored commit.
async fn commit_root(repo: &Repo, commit: &Checksum) -> Checksum {
    repo.load_commit(commit).await.unwrap().0.root_dirtree
}

/// Whether the repository still holds the root dirtree of `commit`, read from
/// the checksum the caller recorded while the commit stood.
async fn holds_tree(repo: &Repo, root: &Checksum) -> bool {
    repo.has_object(ObjectType::DirTree, root).await.unwrap()
}

/// The options these tests prune with: refs alone, the parent edge, the one
/// metadata key configured, and the caller's classifier.
fn weak_options(filter: WeakRefFilter) -> PruneOptions {
    PruneOptions {
        refs_only: true,
        gc_root_metadata_keys: vec![GC_ROOTS.to_owned()],
        weak_ref_filter: filter,
        ..PruneOptions::new()
    }
}

/// A classifier that answers weak for every ref whose name starts with `pool/`.
fn pool_is_weak() -> WeakRefFilter {
    WeakRefFilter::new(|name: &str, _: &Checksum| !name.starts_with("pool/"))
}

/// The commit a ref names, or `None` where the store carries no such ref.
async fn tip(repo: &Repo, name: &str) -> Option<Checksum> {
    repo.resolve_ref_tip(name).await.unwrap()
}

#[test]
fn an_unreached_weak_ref_is_deleted_and_its_objects_swept() {
    let tmp = TmpDir::new("weak-refs-unreached");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        let head = commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, None, Some("pool/a")).await;
        let orphan_root = commit_root(&repo, &orphan).await;
        let head_root = commit_root(&repo, &head).await;

        let stats = repo.prune(&weak_options(pool_is_weak())).await.unwrap();

        assert_eq!(
            stats.deleted_refs,
            vec!["pool/a".to_owned()],
            "the run names the weak ref it deleted"
        );
        assert_eq!(tip(&repo, "pool/a").await, None, "the weak ref is gone");
        assert!(!holds(&repo, &orphan).await, "its commit is swept");
        assert!(
            !holds_tree(&repo, &orphan_root).await,
            "and so is the tree only it reached"
        );
        assert!(holds(&repo, &head).await, "the strong ref's commit stands");
        assert!(
            holds_tree(&repo, &head_root).await,
            "and so does the tree it reaches"
        );
        assert_eq!(
            tip(&repo, "main").await,
            Some(head),
            "the strong ref still names it"
        );
    });
}

#[test]
fn a_weak_ref_reached_over_a_metadata_edge_survives() {
    let tmp = TmpDir::new("weak-refs-metadata-edge");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["kept", "head"]).await;
        let kept = commit(&repo, tmp.path(), "kept", None, None, Some("pool/a")).await;
        let kept_root = commit_root(&repo, &kept).await;
        commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(checksum_list(GC_ROOTS, &[kept])),
            Some("main"),
        )
        .await;

        let stats = repo.prune(&weak_options(pool_is_weak())).await.unwrap();

        assert!(
            stats.deleted_refs.is_empty(),
            "the run deleted no ref: {:?}",
            stats.deleted_refs
        );
        assert_eq!(
            tip(&repo, "pool/a").await,
            Some(kept),
            "the weak ref still names its commit"
        );
        assert!(holds(&repo, &kept).await, "the commit survives");
        assert!(
            holds_tree(&repo, &kept_root).await,
            "and so does the tree it reaches"
        );
    });
}

#[test]
fn a_reached_weak_ref_reseeds_the_walk_at_its_own_bound() {
    let tmp = TmpDir::new("weak-refs-rule-b");
    block_on(async {
        let repo = repo_with_trees(
            tmp.path(),
            &["c1", "c2", "c3", "c4", "c5", "d1", "d2", "d3"],
        )
        .await;
        let c1 = commit(&repo, tmp.path(), "c1", None, None, None).await;
        let c2 = commit(&repo, tmp.path(), "c2", Some(c1), None, None).await;
        let c3 = commit(&repo, tmp.path(), "c3", Some(c2), None, None).await;
        let c4 = commit(&repo, tmp.path(), "c4", Some(c3), None, Some("pool/a")).await;
        let c5 = commit(&repo, tmp.path(), "c5", Some(c4), None, Some("main")).await;
        // The control chain: a strong ref at the global depth of 1, so the walk
        // keeps d3 and d2 and drops d1. It proves the depth bound is in force,
        // so the assertions on the weak ref's ancestry cannot pass vacuously.
        let d1 = commit(&repo, tmp.path(), "d1", None, None, None).await;
        let d2 = commit(&repo, tmp.path(), "d2", Some(d1), None, None).await;
        let d3 = commit(&repo, tmp.path(), "d3", Some(d2), None, Some("other")).await;

        let roots: Vec<Checksum> = vec![c1, c2, c3, c4, c5, d1, d2, d3];
        let mut trees = Vec::new();
        for c in &roots {
            trees.push(commit_root(&repo, c).await);
        }

        let opts = PruneOptions {
            depth: 1,
            retain_branch_depth: vec![("pool/a".to_owned(), -1)],
            ..weak_options(pool_is_weak())
        };
        let stats = repo.prune(&opts).await.unwrap();

        assert!(
            stats.deleted_refs.is_empty(),
            "the run deleted no ref: {:?}",
            stats.deleted_refs
        );
        assert_eq!(
            tip(&repo, "pool/a").await,
            Some(c4),
            "the weak ref still names its commit"
        );
        // `main` reaches c4 with its depth spent, so everything below c4 is
        // there because the weak ref re-seeded the walk at its own bound.
        for (name, checksum, root) in [
            ("c5", c5, trees[4]),
            ("c4", c4, trees[3]),
            ("c3", c3, trees[2]),
            ("c2", c2, trees[1]),
            ("c1", c1, trees[0]),
        ] {
            assert!(holds(&repo, &checksum).await, "{name} survives");
            assert!(holds_tree(&repo, &root).await, "{name}'s tree survives");
        }
        assert!(holds(&repo, &d3).await, "the control head survives");
        assert!(holds(&repo, &d2).await, "its one kept parent survives");
        assert!(
            !holds(&repo, &d1).await,
            "the control's second parent is beyond the depth of 1 and is swept"
        );
    });
}

#[test]
fn the_ancestry_rule_b_reaches_roots_a_second_weak_ref() {
    let tmp = TmpDir::new("weak-refs-fixpoint");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["c1", "c2", "c3", "x", "y"]).await;
        let x = commit(&repo, tmp.path(), "x", None, None, Some("pool/b")).await;
        let x_root = commit_root(&repo, &x).await;
        // c1 carries the key naming x, and the walk reads it only where the
        // weak ref pool/a re-seeds c2 at the bound its own name carries.
        let c1 = commit(
            &repo,
            tmp.path(),
            "c1",
            None,
            Some(checksum_list(GC_ROOTS, &[x])),
            None,
        )
        .await;
        let c2 = commit(&repo, tmp.path(), "c2", Some(c1), None, Some("pool/a")).await;
        let c3 = commit(&repo, tmp.path(), "c3", Some(c2), None, Some("main")).await;
        let y = commit(&repo, tmp.path(), "y", None, None, Some("pool/c")).await;
        let y_root = commit_root(&repo, &y).await;

        let opts = PruneOptions {
            depth: 1,
            retain_branch_depth: vec![("pool/a".to_owned(), -1)],
            ..weak_options(pool_is_weak())
        };
        let stats = repo.prune(&opts).await.unwrap();

        assert_eq!(
            stats.deleted_refs,
            vec!["pool/c".to_owned()],
            "the one weak ref nothing reaches is the one the run deleted"
        );
        assert_eq!(
            tip(&repo, "pool/b").await,
            Some(x),
            "the second weak ref still names its commit"
        );
        assert!(holds(&repo, &x).await, "that commit survives");
        assert!(holds_tree(&repo, &x_root).await, "and so does its tree");
        assert!(
            holds(&repo, &c1).await,
            "the ancestry Rule B reached survives"
        );
        assert!(
            holds(&repo, &c2).await,
            "the weak ref's own commit survives"
        );
        assert!(holds(&repo, &c3).await, "the strong ref's commit survives");
        assert_eq!(tip(&repo, "pool/c").await, None, "pool/c is gone");
        assert!(!holds(&repo, &y).await, "and so is the commit it named");
        assert!(!holds_tree(&repo, &y_root).await, "and its tree");
    });
}

#[test]
fn a_dry_run_deletes_no_ref_and_still_reports_the_list() {
    let tmp = TmpDir::new("weak-refs-no-prune");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, None, Some("pool/a")).await;
        let orphan_root = commit_root(&repo, &orphan).await;

        let opts = PruneOptions {
            no_prune: true,
            ..weak_options(pool_is_weak())
        };
        let stats = repo.prune(&opts).await.unwrap();

        assert_eq!(
            stats.deleted_refs,
            vec!["pool/a".to_owned()],
            "the dry run names the ref the run would delete"
        );
        assert_eq!(
            tip(&repo, "pool/a").await,
            Some(orphan),
            "the ref still names its commit"
        );
        assert!(holds(&repo, &orphan).await, "the commit stands");
        assert!(
            holds_tree(&repo, &orphan_root).await,
            "and so does its tree"
        );
    });
}

#[test]
fn a_classifier_without_refs_only_is_refused() {
    let tmp = TmpDir::new("weak-refs-refusal");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, None, Some("pool/a")).await;

        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let opts = PruneOptions {
            refs_only: false,
            ..weak_options(WeakRefFilter::new(move |_: &str, _: &Checksum| {
                counter.fetch_add(1, Ordering::SeqCst);
                false
            }))
        };
        let err = repo
            .prune(&opts)
            .await
            .expect_err("a classifier without refs_only is refused");
        assert!(
            matches!(err, Error::InvalidFormat(_)),
            "the refusal is an invalid-format error: {err:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the classifier was never called"
        );
        assert_eq!(
            tip(&repo, "pool/a").await,
            Some(orphan),
            "the weak ref still stands"
        );
        assert!(holds(&repo, &orphan).await, "and its commit survives");
    });
}

/// The refusal stands ahead of the repository lock, so a repository another
/// holder keeps gives the same refusal a free one gives.
#[test]
fn the_classifier_refusal_precedes_the_lock() {
    let tmp = TmpDir::new("weak-refs-refusal-lock");
    block_on(async {
        let repo_path = tmp.path().join("repo");
        Repo::create(&repo_path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let config = repo_path.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("lock-timeout-secs=1\n");
        std::fs::write(&config, text).unwrap();

        let repo = Repo::open(&repo_path).await.unwrap();
        let txn = repo.transaction().await.unwrap();

        let opts = PruneOptions {
            refs_only: false,
            ..weak_options(pool_is_weak())
        };
        let err = repo
            .prune(&opts)
            .await
            .expect_err("a classifier without refs_only is refused");
        assert!(
            matches!(err, Error::InvalidFormat(_)),
            "the refusal stands ahead of the lock, so it is no timeout: {err:?}"
        );

        // The transaction stands for the whole of the assertion above.
        drop(txn);
    });
}

#[test]
fn the_deleted_ref_list_is_sorted() {
    let tmp = TmpDir::new("weak-refs-sorted");
    // The directories and the leaf names are chosen so that a listing in
    // directory order is very unlikely to be sorted.
    let weak = [
        "zeta/one",
        "zeta/two",
        "alpha/one",
        "alpha/two",
        "mid/aaa",
        "mid/zzz",
        "pool/9",
        "pool/0",
    ];
    block_on(async {
        let mut names = vec!["head"];
        let owned: Vec<String> = weak.iter().map(|n| n.replace('/', "-")).collect();
        names.extend(owned.iter().map(String::as_str));
        let repo = repo_with_trees(tmp.path(), &names).await;

        commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        for (branch, tree) in weak.iter().zip(owned.iter()) {
            commit(&repo, tmp.path(), tree, None, None, Some(branch)).await;
        }

        let filter = WeakRefFilter::new(|name: &str, _: &Checksum| name == "main");
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let mut expected: Vec<String> = weak.iter().map(|n| (*n).to_owned()).collect();
        expected.sort();
        assert_eq!(
            expected,
            vec![
                "alpha/one".to_owned(),
                "alpha/two".to_owned(),
                "mid/aaa".to_owned(),
                "mid/zzz".to_owned(),
                "pool/0".to_owned(),
                "pool/9".to_owned(),
                "zeta/one".to_owned(),
                "zeta/two".to_owned(),
            ],
            "the expected list is the eight weak names in byte order"
        );
        assert_eq!(stats.deleted_refs, expected, "the run reports them sorted");
        assert!(
            stats.deleted_refs.windows(2).all(|w| w[0] < w[1]),
            "the list is strictly increasing: {:?}",
            stats.deleted_refs
        );
    });
}

/// A classifier that repoints a ref from inside its own call leaves that ref
/// where it now stands: the run reads the ref again next to the unlink and
/// skips it where the checksum moved.
#[test]
fn a_ref_that_moved_under_the_classifier_is_not_unlinked() {
    let tmp = TmpDir::new("weak-refs-moved");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        let head = commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        commit(&repo, tmp.path(), "orphan", None, None, Some("pool/a")).await;

        let repo_path = tmp.path().join("repo");
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        // The repoint goes through blocking `std::fs` against the path the
        // closure captured. A `Repo` method here would re-enter the runtime.
        // The new target is a commit the run keeps, so the repository the test
        // leaves is consistent.
        let filter = WeakRefFilter::new(move |name: &str, _: &Checksum| {
            if name == "pool/a" {
                counter.fetch_add(1, Ordering::SeqCst);
                std::fs::write(
                    repo_path.join("refs/heads/pool/a"),
                    format!("{}\n", head.to_hex()),
                )
                .unwrap();
                return false;
            }
            true
        });
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the classifier ran once for that name"
        );
        assert!(
            stats.deleted_refs.is_empty(),
            "the run deleted no ref: {:?}",
            stats.deleted_refs
        );
        assert_eq!(
            tip(&repo, "pool/a").await,
            Some(head),
            "the ref stands at the commit the classifier gave it"
        );
        assert!(holds(&repo, &head).await, "that commit survives");
    });
}

/// A local ref name holding a `:` maps to a different file through the refspec
/// rule, so the classifier never sees it and the run never deletes it.
#[test]
fn a_local_ref_name_holding_a_colon_is_never_classified() {
    let tmp = TmpDir::new("weak-refs-colon");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "colon"]).await;
        commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        let odd = commit(&repo, tmp.path(), "colon", None, None, None).await;

        // `set_ref_immediate` reads the `:` as a remote separator, so the file
        // is written with blocking `std::fs`.
        let path = tmp.path().join("repo/refs/heads/foo:bar");
        std::fs::write(&path, format!("{}\n", odd.to_hex())).unwrap();

        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let filter = WeakRefFilter::new(move |name: &str, _: &Checksum| {
            record.lock().unwrap().push(name.to_owned());
            false
        });
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let names = seen.lock().unwrap().clone();
        assert!(
            !names.iter().any(|n| n == "foo:bar"),
            "the classifier never saw the colon name: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "main"),
            "it did see the ordinary name: {names:?}"
        );
        assert!(
            !stats.deleted_refs.iter().any(|n| n == "foo:bar"),
            "the run did not report it deleted: {:?}",
            stats.deleted_refs
        );
        assert!(path.exists(), "the ref file stands");
        assert!(holds(&repo, &odd).await, "and the commit it names survives");
    });
}

/// A weak alias and the weak ref it names both enter the classification with
/// the checksum behind the link, and the run removes both files whatever order
/// it visits them in.
///
/// The two pairs are created in opposite orders, so a listing that follows the
/// order of creation gives one pair alias first and the other target first.
#[test]
fn a_weak_alias_over_a_weak_ref_leaves_no_ref_file() {
    let tmp = TmpDir::new("weak-refs-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "first", "second"]).await;
        commit(&repo, tmp.path(), "head", None, None, Some("main")).await;

        // The target is written first, so a listing in creation order reaches
        // the aliased ref ahead of the alias that names it.
        let first = commit(&repo, tmp.path(), "first", None, None, Some("pool/b")).await;
        repo.set_ref_alias_immediate("pool/a", "pool/b")
            .await
            .unwrap();

        // The alias is written first, so the same listing reaches the alias
        // ahead of the ref it names.
        repo.set_ref_alias_immediate("pool/x", "pool/y")
            .await
            .unwrap();
        let second = commit(&repo, tmp.path(), "second", None, None, Some("pool/y")).await;

        let stats = repo.prune(&weak_options(pool_is_weak())).await.unwrap();

        assert_eq!(
            stats.deleted_refs,
            vec![
                "pool/a".to_owned(),
                "pool/b".to_owned(),
                "pool/x".to_owned(),
                "pool/y".to_owned(),
            ],
            "the run names every weak ref it removed, the aliases among them"
        );
        for name in ["pool/a", "pool/b", "pool/x", "pool/y"] {
            let path = tmp.path().join("repo/refs/heads").join(name);
            assert!(
                std::fs::symlink_metadata(&path).is_err(),
                "{name} left a file behind at {}",
                path.display()
            );
        }
        let left: Vec<String> = std::fs::read_dir(tmp.path().join("repo/refs/heads/pool"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(left.is_empty(), "the weak directory still holds {left:?}");
        assert!(!holds(&repo, &first).await, "the first commit is swept");
        assert!(!holds(&repo, &second).await, "and so is the second");
    });
}

/// Rule B narrows as well as widens: a weak ref whose own bound reaches less
/// far than the arrival's replaces that arrival's bound, so the ancestry beyond
/// the weak ref's bound is swept.
#[test]
fn a_reached_weak_ref_narrows_the_arrival_bound() {
    let tmp = TmpDir::new("weak-refs-rule-b-narrow");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["c1", "c2", "c3"]).await;
        let c1 = commit(&repo, tmp.path(), "c1", None, None, None).await;
        let c2 = commit(&repo, tmp.path(), "c2", Some(c1), None, Some("pool/a")).await;
        let c3 = commit(&repo, tmp.path(), "c3", Some(c2), None, Some("main")).await;

        // `main` reaches c2 with the whole ancestry left, and the weak ref's
        // own name carries a bound of the head alone. A depth of -2 is one of
        // the negative values that keep the named commit alone.
        let opts = PruneOptions {
            depth: -1,
            retain_branch_depth: vec![("pool/a".to_owned(), -2)],
            ..weak_options(pool_is_weak())
        };
        let stats = repo.prune(&opts).await.unwrap();

        assert!(
            stats.deleted_refs.is_empty(),
            "the run deleted no ref: {:?}",
            stats.deleted_refs
        );
        assert_eq!(
            tip(&repo, "pool/a").await,
            Some(c2),
            "the weak ref still names its commit"
        );
        assert!(holds(&repo, &c3).await, "the strong ref's commit survives");
        assert!(
            holds(&repo, &c2).await,
            "the weak ref's own commit survives"
        );
        assert!(
            !holds(&repo, &c1).await,
            "the parent beyond the weak ref's own bound is swept"
        );
    });
}
