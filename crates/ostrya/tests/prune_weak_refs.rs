//! Prune with a weak-ref classifier.
//!
//! `PruneOptions::weak_ref_filter` splits the refs under `refs/heads` and the
//! refs under `refs/remotes` into strong refs, which root the walk, and weak
//! refs, which root nothing. A weak ref survives where the walk reaches its
//! commit over some other edge, and the run unlinks it otherwise. A ref under
//! `refs/mirrors` is strong and never reaches the classifier. The classifier is
//! a port extension with no counterpart in the `ostree` tool, so these
//! repositories are built and pruned with the port alone.

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::TmpDir;
use ostrya::{
    Checksum, CollectionRef, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions,
    Error, MutableTree, ObjectType, PruneOptions, Repo, RepoMode, Type, Value, WeakRefFilter,
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

/// A classifier that answers weak for every name holding `pool`, which reaches
/// a local name and a remote refspec alike.
fn any_pool_is_weak() -> WeakRefFilter {
    WeakRefFilter::new(|name: &str, _: &Checksum| !name.contains("pool"))
}

/// A classifier that records the name of every ref it classifies, and takes its
/// verdict from `strong`.
///
/// The record is the proof that a ref reached the classifier, or that it never
/// did.
fn recording_filter<F>(strong: F) -> (WeakRefFilter, Arc<Mutex<Vec<String>>>)
where
    F: Fn(&str) -> bool + Send + Sync + 'static,
{
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let filter = WeakRefFilter::new(move |name: &str, _: &Checksum| {
        record.lock().unwrap().push(name.to_owned());
        strong(name)
    });
    (filter, seen)
}

/// The names a recording classifier was called with.
fn recorded(seen: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    seen.lock().unwrap().clone()
}

/// A recording classifier that answers weak for every name holding `pool`,
/// which reaches a local name, a remote refspec, and a mirror path alike.
fn recording_pool_is_weak() -> (WeakRefFilter, Arc<Mutex<Vec<String>>>) {
    recording_filter(|name: &str| !name.contains("pool"))
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

        let (filter, seen) = recording_filter(|_: &str| false);
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let names = recorded(&seen);
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

/// A ref under `refs/remotes` reaches the classifier under its
/// `<remote>:<name>` refspec, and the run deletes it through the same name.
#[test]
fn a_weak_remote_ref_is_classified_and_deleted() {
    let tmp = TmpDir::new("weak-refs-remote");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "keep", "drop"]).await;
        let keep = commit(
            &repo,
            tmp.path(),
            "keep",
            None,
            None,
            Some("origin:pool/keep"),
        )
        .await;
        let keep_root = commit_root(&repo, &keep).await;
        let dropped = commit(
            &repo,
            tmp.path(),
            "drop",
            None,
            None,
            Some("origin:pool/drop"),
        )
        .await;
        let dropped_root = commit_root(&repo, &dropped).await;
        commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(checksum_list(GC_ROOTS, &[keep])),
            Some("main"),
        )
        .await;

        let (filter, seen) = recording_pool_is_weak();
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let names = recorded(&seen);
        assert!(
            names.iter().any(|n| n == "origin:pool/drop"),
            "the classifier saw the remote refspec: {names:?}"
        );
        assert_eq!(
            stats.deleted_refs,
            vec!["origin:pool/drop".to_owned()],
            "the run names the remote ref it deleted by its refspec"
        );
        assert_eq!(
            tip(&repo, "origin:pool/drop").await,
            None,
            "the weak remote ref is gone"
        );
        assert!(
            !tmp.path()
                .join("repo/refs/remotes/origin/pool/drop")
                .exists(),
            "and so is its file"
        );
        assert!(!holds(&repo, &dropped).await, "its commit is swept");
        assert!(
            !holds_tree(&repo, &dropped_root).await,
            "and so is the tree only it reached"
        );
        assert_eq!(
            tip(&repo, "origin:pool/keep").await,
            Some(keep),
            "the reached remote ref still names its commit"
        );
        assert!(holds(&repo, &keep).await, "that commit survives");
        assert!(
            holds_tree(&repo, &keep_root).await,
            "and so does the tree it reaches"
        );
    });
}

/// A ref under `refs/mirrors` never reaches the classifier, and it roots the
/// walk: its commit survives with the objects under it.
#[test]
fn a_mirror_ref_is_never_classified_and_never_deleted() {
    let tmp = TmpDir::new("weak-refs-mirror");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "a", "m"]).await;
        commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "a", None, None, Some("pool/a")).await;
        let mirrored = commit(&repo, tmp.path(), "m", None, None, None).await;
        let mirrored_root = commit_root(&repo, &mirrored).await;
        let cref = CollectionRef::new("org.example.Coll", "pool/m");
        repo.set_collection_ref_immediate(&cref, Some(&mirrored))
            .await
            .unwrap();

        let (filter, seen) = recording_pool_is_weak();
        // The record is read ahead of the run's own result, so the name the
        // classifier saw is what this reports.
        let result = repo.prune(&weak_options(filter)).await;

        let names = recorded(&seen);
        assert!(
            names.iter().any(|n| n == "main"),
            "the classifier saw the strong local ref: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "pool/a"),
            "and the weak local ref: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("org.example.Coll")),
            "the classifier never saw the mirror ref: {names:?}"
        );
        let stats = result.unwrap();
        assert_eq!(
            stats.deleted_refs,
            vec!["pool/a".to_owned()],
            "the run deleted the weak local ref alone"
        );
        assert!(!holds(&repo, &orphan).await, "and swept its commit");
        let mirror_path = tmp.path().join("repo/refs/mirrors/org.example.Coll/pool/m");
        assert!(mirror_path.exists(), "the mirror ref file stands");
        assert_eq!(
            repo.list_mirror_refs().await.unwrap(),
            vec![("org.example.Coll".to_owned(), "pool/m".to_owned(), mirrored)],
            "and it still lists"
        );
        assert!(
            holds(&repo, &mirrored).await,
            "the mirror ref roots its commit"
        );
        assert!(
            holds_tree(&repo, &mirrored_root).await,
            "and the tree under it"
        );
    });
}

/// A strong alias over a weak ref roots the commit the two share, so the walk
/// reaches the weak ref and both files stand.
#[test]
fn a_strong_alias_over_a_weak_ref_keeps_both_refs() {
    let tmp = TmpDir::new("weak-refs-strong-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "target"]).await;
        commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        let x = commit(&repo, tmp.path(), "target", None, None, Some("pool/target")).await;
        let x_root = commit_root(&repo, &x).await;
        repo.set_ref_alias_immediate("keepalive", "pool/target")
            .await
            .unwrap();

        let stats = repo.prune(&weak_options(pool_is_weak())).await.unwrap();

        assert!(
            stats.deleted_refs.is_empty(),
            "the run deleted no ref: {:?}",
            stats.deleted_refs
        );
        assert_eq!(
            tip(&repo, "pool/target").await,
            Some(x),
            "the weak ref still names its commit"
        );
        assert_eq!(
            tip(&repo, "keepalive").await,
            Some(x),
            "and so does the alias"
        );
        let alias = tmp.path().join("repo/refs/heads/keepalive");
        assert!(
            std::fs::symlink_metadata(&alias).unwrap().is_symlink(),
            "the alias is still a symlink"
        );
        assert!(holds(&repo, &x).await, "the shared commit survives");
        assert!(
            holds_tree(&repo, &x_root).await,
            "and so does the tree it reaches"
        );
    });
}

/// A weak alias over a strong ref is classified weak and survives, because the
/// ref it names roots the commit behind the link.
#[test]
fn a_weak_alias_over_a_strong_ref_survives() {
    let tmp = TmpDir::new("weak-refs-weak-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head"]).await;
        let x = commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        repo.set_ref_alias_immediate("pool/alias", "main")
            .await
            .unwrap();

        let (filter, seen) = recording_pool_is_weak();
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let names = recorded(&seen);
        assert!(
            names.iter().any(|n| n == "pool/alias"),
            "the alias was classified, and weak: {names:?}"
        );
        assert!(
            stats.deleted_refs.is_empty(),
            "the run deleted no ref: {:?}",
            stats.deleted_refs
        );
        assert_eq!(
            tip(&repo, "pool/alias").await,
            Some(x),
            "the alias still names the commit behind it"
        );
        let alias = tmp.path().join("repo/refs/heads/pool/alias");
        assert!(
            std::fs::symlink_metadata(&alias).unwrap().is_symlink(),
            "and is still a symlink"
        );
        assert!(holds(&repo, &x).await, "the commit survives");
    });
}

/// An alias whose target ref is absent is skipped by the reader, so it never
/// reaches the classifier and the run leaves it where it stands.
#[test]
fn a_dangling_alias_is_never_classified_and_never_deleted() {
    let tmp = TmpDir::new("weak-refs-dangling-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, None, Some("pool/a")).await;
        // `pool/missing` is never written, so the link dangles.
        repo.set_ref_alias_immediate("pool/dangle", "pool/missing")
            .await
            .unwrap();

        let (filter, seen) = recording_pool_is_weak();
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let names = recorded(&seen);
        assert!(
            names.iter().any(|n| n == "pool/a"),
            "the weak ref was classified: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n == "pool/dangle"),
            "the dangling alias was not: {names:?}"
        );
        assert_eq!(
            stats.deleted_refs,
            vec!["pool/a".to_owned()],
            "the run deleted the weak ref alone"
        );
        assert!(!holds(&repo, &orphan).await, "and swept its commit");
        let dangle = tmp.path().join("repo/refs/heads/pool/dangle");
        assert!(
            std::fs::symlink_metadata(&dangle).unwrap().is_symlink(),
            "the dangling alias stands"
        );
    });
}

/// Two ref files under `refs/remotes` can list under one name, and the refspec
/// rule addresses one of the two. The run classifies the one the name
/// addresses, and leaves the other strong and untouched.
///
/// `refs/remotes/a:b/pool/x` and `refs/remotes/a/b:pool/x` both list as
/// `a:b:pool/x`, and that name maps to the second. The same holds one level up:
/// a file directly under `refs/remotes` lists under a name that maps below
/// `refs/heads`.
#[test]
fn a_colon_bearing_remote_directory_is_never_classified() {
    let tmp = TmpDir::new("weak-refs-colon-remote");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "shadowed", "addressed", "stray"]).await;
        commit(&repo, tmp.path(), "head", None, None, Some("main")).await;

        // No refspec addresses this file, so it is written with blocking
        // `std::fs`.
        let shadowed = commit(&repo, tmp.path(), "shadowed", None, None, None).await;
        let shadowed_root = commit_root(&repo, &shadowed).await;
        let shadowed_path = tmp.path().join("repo/refs/remotes/a:b/pool/x");
        let shadowed_body = format!("{}\n", shadowed.to_hex());
        std::fs::create_dir_all(shadowed_path.parent().unwrap()).unwrap();
        std::fs::write(&shadowed_path, &shadowed_body).unwrap();

        // The refspec `a:b:pool/x` addresses `refs/remotes/a/b:pool/x`.
        let addressed = commit(&repo, tmp.path(), "addressed", None, None, None).await;
        let addressed_root = commit_root(&repo, &addressed).await;
        repo.set_ref_immediate("a:b:pool/x", Some(&addressed))
            .await
            .unwrap();
        let addressed_path = tmp.path().join("repo/refs/remotes/a/b:pool/x");
        assert!(
            addressed_path.exists(),
            "the refspec wrote the file it maps to"
        );

        // A file directly under `refs/remotes` lists under a name that maps
        // below `refs/heads`, where a ref of that name stands.
        let stray = commit(&repo, tmp.path(), "stray", None, None, None).await;
        let stray_path = tmp.path().join("repo/refs/remotes/poolstray");
        std::fs::write(&stray_path, format!("{}\n", stray.to_hex())).unwrap();
        repo.set_ref_immediate("poolstray", Some(&stray))
            .await
            .unwrap();

        let (filter, seen) = recording_pool_is_weak();
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let names = recorded(&seen);
        assert_eq!(
            names.iter().filter(|n| *n == "a:b:pool/x").count(),
            1,
            "the name reached the classifier once, for the file it addresses: {names:?}"
        );
        assert_eq!(
            stats.deleted_refs,
            vec!["a:b:pool/x".to_owned()],
            "the run deleted the addressed ref alone"
        );
        assert!(!addressed_path.exists(), "the addressed file is gone");
        assert!(!holds(&repo, &addressed).await, "and its commit is swept");
        assert!(
            !holds_tree(&repo, &addressed_root).await,
            "with the tree only it reached"
        );
        assert_eq!(
            std::fs::read_to_string(&shadowed_path).unwrap(),
            shadowed_body,
            "the shadowed file stands with the content it was written with"
        );
        assert!(
            holds(&repo, &shadowed).await,
            "so it rooted the walk and its commit survives"
        );
        assert!(
            holds_tree(&repo, &shadowed_root).await,
            "and so does the tree it reaches"
        );
        assert!(stray_path.exists(), "the stray remote file stands");
        assert!(
            tmp.path().join("repo/refs/heads/poolstray").exists(),
            "and so does the local ref of that name"
        );
        assert!(
            !stats.deleted_refs.iter().any(|n| n == "poolstray"),
            "the run deleted neither: {:?}",
            stats.deleted_refs
        );
        assert!(
            holds(&repo, &stray).await,
            "the stray remote file rooted the commit the two name"
        );
    });
}

/// A classifier runs caller code, and an actor outside the process can clear a
/// ref directory at any point between the listing and the unlink. A doomed ref
/// whose file and whose parent directory are both gone by the time the pass
/// reaches it is reported deleted, and the run goes on to sweep.
#[test]
fn a_ref_directory_gone_before_the_unlink_does_not_fail_the_run() {
    let tmp = TmpDir::new("weak-refs-vanished-parent");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "doomed"]).await;
        let head = commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        let doomed = commit(&repo, tmp.path(), "doomed", None, None, Some("pool/doomed")).await;
        let doomed_root = commit_root(&repo, &doomed).await;

        // The classifier clears the directory holding the doomed ref, so the
        // unlink meets an absent file and the directory that held it is gone
        // as well.
        let dir = tmp.path().join("repo/refs/heads/pool");
        let filter = WeakRefFilter::new(move |name: &str, _: &Checksum| {
            if name == "pool/doomed" {
                std::fs::remove_file(dir.join("doomed")).unwrap();
                std::fs::remove_dir(&dir).unwrap();
            }
            !name.starts_with("pool/")
        });

        let stats = repo
            .prune(&weak_options(filter))
            .await
            .expect("the run tolerates a ref directory that is already gone");

        assert_eq!(
            stats.deleted_refs,
            vec!["pool/doomed".to_owned()],
            "the run names the ref it removed"
        );
        assert!(
            !tmp.path().join("repo/refs/heads/pool").exists(),
            "the directory stays gone"
        );
        assert!(!holds(&repo, &doomed).await, "the run swept the commit");
        assert!(
            !holds_tree(&repo, &doomed_root).await,
            "and the tree only it reached"
        );
        assert!(holds(&repo, &head).await, "the strong ref's commit stands");
    });
}

/// A weak remote ref re-seeds the walk under the bound its own name carries,
/// and its name is its `<remote>:<name>` refspec. A
/// [`PruneOptions::retain_branch_depth`] entry keyed on that refspec holds the
/// ancestry below the commit the walk arrived at.
#[test]
fn a_reached_weak_remote_ref_reseeds_the_walk_at_its_refspec_bound() {
    let tmp = TmpDir::new("weak-refs-remote-rule-b");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["g1", "g2", "g3", "head", "d1", "d2"]).await;
        let g1 = commit(&repo, tmp.path(), "g1", None, None, None).await;
        let g2 = commit(&repo, tmp.path(), "g2", Some(g1), None, None).await;
        let g3 = commit(
            &repo,
            tmp.path(),
            "g3",
            Some(g2),
            None,
            Some("origin:pool/chain"),
        )
        .await;
        // `main` reaches g3 over a metadata edge, which carries the global
        // bound of 0, so g2 and g1 stand only under the weak ref's own bound.
        commit(
            &repo,
            tmp.path(),
            "head",
            None,
            Some(checksum_list(GC_ROOTS, &[g3])),
            Some("main"),
        )
        .await;
        // The control chain: a strong ref at the global depth of 0, so the walk
        // keeps d2 and drops d1. It proves the depth bound is in force, so the
        // assertions on the weak ref's ancestry cannot pass vacuously.
        let d1 = commit(&repo, tmp.path(), "d1", None, None, None).await;
        let d2 = commit(&repo, tmp.path(), "d2", Some(d1), None, Some("other")).await;

        let mut trees = Vec::new();
        for c in [g1, g2, g3] {
            trees.push(commit_root(&repo, &c).await);
        }

        let opts = PruneOptions {
            depth: 0,
            retain_branch_depth: vec![("origin:pool/chain".to_owned(), -1)],
            ..weak_options(any_pool_is_weak())
        };
        let stats = repo.prune(&opts).await.unwrap();

        assert!(
            stats.deleted_refs.is_empty(),
            "the run deleted no ref: {:?}",
            stats.deleted_refs
        );
        assert_eq!(
            tip(&repo, "origin:pool/chain").await,
            Some(g3),
            "the weak remote ref still names its commit"
        );
        for (name, checksum, root) in [
            ("g3", g3, trees[2]),
            ("g2", g2, trees[1]),
            ("g1", g1, trees[0]),
        ] {
            assert!(holds(&repo, &checksum).await, "{name} survives");
            assert!(holds_tree(&repo, &root).await, "{name}'s tree survives");
        }
        assert!(holds(&repo, &d2).await, "the control head survives");
        assert!(
            !holds(&repo, &d1).await,
            "the control's parent is beyond the depth of 0 and is swept"
        );
    });
}

/// An alias links a ref of one space to a ref of another. Each alias is
/// classified under the name of the file it is stored in, whichever space its
/// target lives in. An alias whose commit the walk never reaches is unlinked,
/// and the link itself is what goes.
#[test]
fn a_cross_space_alias_is_classified_under_its_own_name() {
    let tmp = TmpDir::new("weak-refs-cross-space-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "target"]).await;
        let head = commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        let target = commit(
            &repo,
            tmp.path(),
            "target",
            None,
            None,
            Some("origin:pool/target"),
        )
        .await;
        let target_root = commit_root(&repo, &target).await;
        // A local alias naming a remote ref, and a remote alias naming the
        // strong local ref.
        repo.set_ref_alias_immediate("pool/into-remote", "origin:pool/target")
            .await
            .unwrap();
        repo.set_ref_alias_immediate("origin:pool/into-heads", "main")
            .await
            .unwrap();

        let (filter, seen) = recording_pool_is_weak();
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let names = recorded(&seen);
        for name in [
            "pool/into-remote",
            "origin:pool/into-heads",
            "origin:pool/target",
        ] {
            assert!(
                names.iter().any(|n| n == name),
                "{name} reached the classifier: {names:?}"
            );
        }
        assert_eq!(
            stats.deleted_refs,
            vec![
                "origin:pool/target".to_owned(),
                "pool/into-remote".to_owned()
            ],
            "the run removed the alias into the remote space and the ref it named"
        );
        for path in [
            "repo/refs/heads/pool/into-remote",
            "repo/refs/remotes/origin/pool/target",
        ] {
            assert!(
                std::fs::symlink_metadata(tmp.path().join(path)).is_err(),
                "{path} left a file behind"
            );
        }
        assert!(!holds(&repo, &target).await, "the shared commit is swept");
        assert!(
            !holds_tree(&repo, &target_root).await,
            "and so is the tree only it reached"
        );
        // The remote alias is weak too, and the ref it names roots the commit
        // behind the link, so it survives as a link.
        assert_eq!(
            tip(&repo, "origin:pool/into-heads").await,
            Some(head),
            "the remote alias still names the commit behind it"
        );
        let alias = tmp.path().join("repo/refs/remotes/origin/pool/into-heads");
        assert!(
            std::fs::symlink_metadata(&alias).unwrap().is_symlink(),
            "and is still a symlink"
        );
        assert!(holds(&repo, &head).await, "that commit survives");
    });
}

/// A weak alias under `refs/remotes` over a weak remote ref leaves no ref file:
/// the run removes the link and the file the link names, and sweeps the commit
/// the two shared.
#[test]
fn a_weak_remote_alias_over_a_weak_remote_ref_leaves_no_ref_file() {
    let tmp = TmpDir::new("weak-refs-remote-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "target"]).await;
        commit(&repo, tmp.path(), "head", None, None, Some("main")).await;
        let target = commit(
            &repo,
            tmp.path(),
            "target",
            None,
            None,
            Some("origin:pool/target"),
        )
        .await;
        let target_root = commit_root(&repo, &target).await;
        repo.set_ref_alias_immediate("origin:pool/alias", "origin:pool/target")
            .await
            .unwrap();

        let stats = repo.prune(&weak_options(any_pool_is_weak())).await.unwrap();

        assert_eq!(
            stats.deleted_refs,
            vec![
                "origin:pool/alias".to_owned(),
                "origin:pool/target".to_owned(),
            ],
            "the run names the remote alias and the remote ref it named"
        );
        for name in ["alias", "target"] {
            let path = tmp.path().join("repo/refs/remotes/origin/pool").join(name);
            assert!(
                std::fs::symlink_metadata(&path).is_err(),
                "{name} left a file behind at {}",
                path.display()
            );
        }
        assert_eq!(
            tip(&repo, "origin:pool/alias").await,
            None,
            "the alias resolves to nothing"
        );
        assert!(!holds(&repo, &target).await, "the commit is swept");
        assert!(
            !holds_tree(&repo, &target_root).await,
            "and so is the tree only it reached"
        );
    });
}
