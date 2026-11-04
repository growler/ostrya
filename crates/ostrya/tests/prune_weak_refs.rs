//! Prune with a weak-ref classifier.
//!
//! `PruneOptions::weak_ref_filter` sorts the refs under `refs/heads`,
//! `refs/remotes`, and `refs/mirrors` into strong refs and weak refs. A strong
//! ref roots the walk. A weak ref roots nothing.
//!
//! If the walk reaches the commit of a weak ref over another edge, the weak ref
//! survives. If not, the run unlinks the weak ref. A ref under `refs/mirrors`
//! reaches the classifier as a collection ref if its path splits into a valid
//! collection id and a valid ref name. Each other mirror ref is strong.
//!
//! Rule B: if the walk reaches the commit of a weak ref, the walk restarts at
//! that commit under the own bound of the weak ref.
//!
//! The classifier is an ostrya extension that the `ostree` command does not
//! have. The tests build and prune each repository with ostrya alone.

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::TmpDir;
use ostrya::{
    Checksum, CollectionRef, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions,
    Error, MutableTree, ObjectType, PruneOptions, RefLocation, Repo, RepoMode, WeakRefFilter,
};
use ostrya_rt::block_on;

/// A fixed timestamp, so the commits are reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// Writes a tree of one file at `base/<name>`. The file content is the name.
fn write_tree(base: &Path, name: &str) {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), format!("{name}\n")).unwrap();
}

/// Commits the tree `base/<name>` into `repo` with the given parent. If
/// `branch` names a ref, the transaction also sets that ref to the new commit.
async fn commit(
    repo: &Repo,
    base: &Path,
    name: &str,
    parent: Option<Checksum>,
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

/// Writes the trees `base/<name>` and creates an archive repository at
/// `base/repo`.
async fn repo_with_trees(base: &Path, names: &[&str]) -> Repo {
    for name in names {
        write_tree(base, name);
    }
    Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap()
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

/// Returns the prune options of these tests: refs only, the parent edge, and
/// the classifier of the caller.
fn weak_options(filter: WeakRefFilter) -> PruneOptions {
    PruneOptions {
        refs_only: true,
        weak_ref_filter: filter,
        ..PruneOptions::new()
    }
}

/// Returns the label of a ref location:
///
/// - the name of a local ref;
/// - the `<remote>:<name>` refspec of a remote ref;
/// - `<collection id>::<name>` for a collection ref.
fn label(location: RefLocation<'_>) -> String {
    match location {
        RefLocation::Local(name) => name.to_owned(),
        RefLocation::Remote { remote, name } => format!("{remote}:{name}"),
        RefLocation::Collection {
            collection_id,
            name,
        } => format!("{collection_id}::{name}"),
        other => format!("{other:?}"),
    }
}

/// Returns a classifier that answers weak for each ref whose label starts with
/// `pool/`. Only a local ref has such a label.
fn pool_is_weak() -> WeakRefFilter {
    WeakRefFilter::new(|location: RefLocation<'_>, _: &Checksum| {
        !label(location).starts_with("pool/")
    })
}

/// Returns a classifier that answers weak for each label that contains `pool`.
/// The rule applies to local, remote, and collection refs.
fn any_pool_is_weak() -> WeakRefFilter {
    WeakRefFilter::new(|location: RefLocation<'_>, _: &Checksum| !label(location).contains("pool"))
}

/// Returns a classifier that records the label of each ref location it gets,
/// and the record.
///
/// `strong` gives the verdict for each label. The record proves which refs
/// reached the classifier and which refs did not.
fn recording_filter<F>(strong: F) -> (WeakRefFilter, Arc<Mutex<Vec<String>>>)
where
    F: Fn(&str) -> bool + Send + Sync + 'static,
{
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let filter = WeakRefFilter::new(move |location: RefLocation<'_>, _: &Checksum| {
        let name = label(location);
        let verdict = strong(&name);
        record.lock().unwrap().push(name);
        verdict
    });
    (filter, seen)
}

/// Returns the labels that a recording classifier got.
fn recorded(seen: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    seen.lock().unwrap().clone()
}

/// Returns a recording classifier that answers weak for each label that
/// contains `pool`. The rule applies to local, remote, and collection refs.
fn recording_pool_is_weak() -> (WeakRefFilter, Arc<Mutex<Vec<String>>>) {
    recording_filter(|name: &str| !name.contains("pool"))
}

/// Returns the commit that a ref names, or `None` if the repository has no
/// such ref.
async fn tip(repo: &Repo, name: &str) -> Option<Checksum> {
    repo.resolve_ref_tip(name).await.unwrap()
}

#[test]
fn an_unreached_weak_ref_is_deleted_and_its_objects_swept() {
    let tmp = TmpDir::new("weak-refs-unreached");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        let head = commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, Some("pool/a")).await;
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
fn a_reached_weak_ref_reseeds_the_walk_at_its_own_bound() {
    let tmp = TmpDir::new("weak-refs-rule-b");
    block_on(async {
        let repo = repo_with_trees(
            tmp.path(),
            &["c1", "c2", "c3", "c4", "c5", "d1", "d2", "d3"],
        )
        .await;
        let c1 = commit(&repo, tmp.path(), "c1", None, None).await;
        let c2 = commit(&repo, tmp.path(), "c2", Some(c1), None).await;
        let c3 = commit(&repo, tmp.path(), "c3", Some(c2), None).await;
        let c4 = commit(&repo, tmp.path(), "c4", Some(c3), Some("pool/a")).await;
        let c5 = commit(&repo, tmp.path(), "c5", Some(c4), Some("main")).await;
        // The control chain has a strong ref at the global depth of 1. The walk
        // keeps d3 and d2 and drops d1. This chain proves that the depth bound
        // applies, so the assertions on the weak ref's ancestry cannot pass
        // vacuously.
        let d1 = commit(&repo, tmp.path(), "d1", None, None).await;
        let d2 = commit(&repo, tmp.path(), "d2", Some(d1), None).await;
        let d3 = commit(&repo, tmp.path(), "d3", Some(d2), Some("other")).await;

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
        // `main` reaches c4 with no depth left, so each commit below c4
        // survives because the weak ref re-seeds the walk at its own bound.
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
        let x = commit(&repo, tmp.path(), "x", None, Some("pool/b")).await;
        let x_root = commit_root(&repo, &x).await;
        // c1 names x as a build source. The walk reads this entry only if the
        // weak ref pool/a re-seeds c2 at the bound of its own name.
        let c1 = commit(&repo, tmp.path(), "c1", None, None).await;
        repo.add_detached_related(&c1, "source/x", &x)
            .await
            .unwrap();
        let c2 = commit(&repo, tmp.path(), "c2", Some(c1), Some("pool/a")).await;
        let c3 = commit(&repo, tmp.path(), "c3", Some(c2), Some("main")).await;
        let y = commit(&repo, tmp.path(), "y", None, Some("pool/c")).await;
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
        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, Some("pool/a")).await;
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
        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, Some("pool/a")).await;

        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let opts = PruneOptions {
            refs_only: false,
            ..weak_options(WeakRefFilter::new(
                move |_: RefLocation<'_>, _: &Checksum| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    false
                },
            ))
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

/// The refusal comes before the repository lock. A repository that another
/// holder locks gives the same refusal as a free repository.
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

        // The transaction stays open until the assertion is complete.
        drop(txn);
    });
}

#[test]
fn the_deleted_ref_list_is_sorted() {
    let tmp = TmpDir::new("weak-refs-sorted");
    // The test picks the directory names and the leaf names so that a listing
    // in directory order is almost never in sorted order.
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

        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        for (branch, tree) in weak.iter().zip(owned.iter()) {
            commit(&repo, tmp.path(), tree, None, Some(branch)).await;
        }

        let filter = WeakRefFilter::new(|location: RefLocation<'_>, _: &Checksum| {
            location == RefLocation::Local("main")
        });
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

/// If a classifier moves a ref during its own call, the ref stays at its new
/// commit. The run reads the ref again immediately before the unlink. If the
/// checksum changed, the run skips the ref.
#[test]
fn a_ref_that_moved_under_the_classifier_is_not_unlinked() {
    let tmp = TmpDir::new("weak-refs-moved");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        let head = commit(&repo, tmp.path(), "head", None, Some("main")).await;
        commit(&repo, tmp.path(), "orphan", None, Some("pool/a")).await;

        let repo_path = tmp.path().join("repo");
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        // The closure moves the ref with blocking `std::fs` calls on the path
        // that it captured. A `Repo` method in the closure re-enters the
        // runtime. The new target is a commit that the run keeps, so the
        // repository stays consistent after the test.
        let filter = WeakRefFilter::new(move |location: RefLocation<'_>, _: &Checksum| {
            if location == RefLocation::Local("pool/a") {
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

/// The refspec rule maps a local ref name that contains `:` to a different
/// file, so the classifier never sees the name. The run never deletes the ref.
#[test]
fn a_local_ref_name_holding_a_colon_is_never_classified() {
    let tmp = TmpDir::new("weak-refs-colon");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "colon"]).await;
        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let odd = commit(&repo, tmp.path(), "colon", None, None).await;

        // `set_ref_immediate` reads the `:` as a remote separator, so the test
        // writes the file with blocking `std::fs`.
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

/// A weak alias and the weak ref that it names both get the checksum behind the
/// link in the classification. The run removes both files in any visit order.
///
/// The test creates the two pairs in opposite orders. A listing in the order of
/// creation gives the alias first for one pair and the target first for the
/// other pair.
#[test]
fn a_weak_alias_over_a_weak_ref_leaves_no_ref_file() {
    let tmp = TmpDir::new("weak-refs-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "first", "second"]).await;
        commit(&repo, tmp.path(), "head", None, Some("main")).await;

        // The test writes the target first, so a listing in creation order
        // reaches the target before the alias that names it.
        let first = commit(&repo, tmp.path(), "first", None, Some("pool/b")).await;
        repo.set_ref_alias_immediate("pool/a", "pool/b")
            .await
            .unwrap();

        // The test writes the alias first, so the same listing reaches the
        // alias before the ref that it names.
        repo.set_ref_alias_immediate("pool/x", "pool/y")
            .await
            .unwrap();
        let second = commit(&repo, tmp.path(), "second", None, Some("pool/y")).await;

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

/// Rule B can make a bound smaller as well as larger. If the own bound of a
/// weak ref is shorter than the bound of the arrival, the own bound replaces
/// it. The run then sweeps the ancestry beyond the own bound of the weak ref.
#[test]
fn a_reached_weak_ref_narrows_the_arrival_bound() {
    let tmp = TmpDir::new("weak-refs-rule-b-narrow");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["c1", "c2", "c3"]).await;
        let c1 = commit(&repo, tmp.path(), "c1", None, None).await;
        let c2 = commit(&repo, tmp.path(), "c2", Some(c1), Some("pool/a")).await;
        let c3 = commit(&repo, tmp.path(), "c3", Some(c2), Some("main")).await;

        // `main` reaches c2 with the whole ancestry left. The weak ref's own
        // name carries a bound that keeps the head alone. A depth of -2 is one
        // of the negative values that keep only the named commit.
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

/// A ref under `refs/remotes` reaches the classifier as its `<remote>:<name>`
/// refspec. The run deletes the ref through the same name.
#[test]
fn a_weak_remote_ref_is_classified_and_deleted() {
    let tmp = TmpDir::new("weak-refs-remote");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "keep", "drop"]).await;
        let keep = commit(&repo, tmp.path(), "keep", None, Some("origin:pool/keep")).await;
        let keep_root = commit_root(&repo, &keep).await;
        let dropped = commit(&repo, tmp.path(), "drop", None, Some("origin:pool/drop")).await;
        let dropped_root = commit_root(&repo, &dropped).await;
        let head = commit(&repo, tmp.path(), "head", None, Some("main")).await;
        repo.add_detached_related(&head, "source/keep", &keep)
            .await
            .unwrap();

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

/// Returns a classifier that answers weak for each collection ref of
/// `collection_id`. Each other ref is strong.
fn collection_is_weak(collection_id: &'static str) -> WeakRefFilter {
    WeakRefFilter::new(move |location: RefLocation<'_>, _: &Checksum| {
        !matches!(
            location,
            RefLocation::Collection { collection_id: id, .. } if id == collection_id
        )
    })
}

/// Sets the collection ref `collection_id`, `name` to `commit` and returns it.
async fn set_collection_ref(
    repo: &Repo,
    collection_id: &str,
    name: &str,
    commit: &Checksum,
) -> CollectionRef {
    let cref = CollectionRef::new(collection_id, name);
    repo.set_collection_ref_immediate(&cref, Some(commit))
        .await
        .unwrap();
    cref
}

/// Returns the commit that a collection ref names, or `None` if the
/// repository has no such ref.
async fn collection_tip(repo: &Repo, cref: &CollectionRef) -> Option<Checksum> {
    repo.resolve_collection_ref(cref, true).await.unwrap()
}

/// A weak collection ref whose commit no strong root reaches is deleted, and
/// its commit is swept. The run names the ref in `deleted_collection_refs`
/// alone. The emptied directory of the collection id stays.
#[test]
fn an_unreached_weak_collection_ref_is_deleted_and_its_objects_swept() {
    let tmp = TmpDir::new("weak-refs-collection-unreached");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "cached"]).await;
        let head = commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let cached = commit(&repo, tmp.path(), "cached", None, None).await;
        let cached_root = commit_root(&repo, &cached).await;
        let cref = set_collection_ref(&repo, "org.example.Cache", "pool/c", &cached).await;

        let stats = repo
            .prune(&weak_options(collection_is_weak("org.example.Cache")))
            .await
            .unwrap();

        assert_eq!(
            stats.deleted_collection_refs,
            vec![cref.clone()],
            "the run names the collection ref it deleted"
        );
        assert!(
            stats.deleted_refs.is_empty(),
            "and names no ref in deleted_refs: {:?}",
            stats.deleted_refs
        );
        assert_eq!(collection_tip(&repo, &cref).await, None, "the ref is gone");
        let dir = tmp.path().join("repo/refs/mirrors/org.example.Cache");
        assert!(!dir.join("pool/c").exists(), "and so is its file");
        assert!(dir.is_dir(), "the directory of the collection id stays");
        assert!(!holds(&repo, &cached).await, "its commit is swept");
        assert!(
            !holds_tree(&repo, &cached_root).await,
            "and so is the tree only it reached"
        );
        assert!(holds(&repo, &head).await, "the strong ref's commit stands");
    });
}

/// A weak collection ref whose commit a strong branch reaches through a
/// `parent` edge survives with its commit.
///
/// A second weak ref of the same collection names a commit that nothing
/// reaches, and the run deletes it. So the run classified the refs of the
/// collection weak, and the `parent` edge alone keeps the first ref.
#[test]
fn a_weak_collection_ref_reached_through_a_parent_survives() {
    let tmp = TmpDir::new("weak-refs-collection-parent");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["base", "head", "orphan"]).await;
        let base = commit(&repo, tmp.path(), "base", None, None).await;
        let head = commit(&repo, tmp.path(), "head", Some(base), Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, None).await;
        let cref = set_collection_ref(&repo, "org.example.Cache", "base", &base).await;
        let unreached = set_collection_ref(&repo, "org.example.Cache", "orphan", &orphan).await;

        let (filter, seen) =
            recording_filter(|name: &str| !name.starts_with("org.example.Cache::"));
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let names = recorded(&seen);
        assert!(
            names.iter().any(|n| n == "org.example.Cache::base"),
            "the classifier saw the kept ref: {names:?}"
        );
        assert_eq!(
            stats.deleted_collection_refs,
            vec![unreached.clone()],
            "the run deleted the unreached weak ref alone"
        );
        assert_eq!(collection_tip(&repo, &unreached).await, None);
        assert!(!holds(&repo, &orphan).await, "its commit is swept");
        assert_eq!(
            collection_tip(&repo, &cref).await,
            Some(base),
            "the weak collection ref still names its commit"
        );
        assert!(holds(&repo, &base).await, "the parent commit survives");
        assert!(holds(&repo, &head).await, "and so does the branch head");
    });
}

/// With no classifier, each collection ref is strong. The ref roots the walk,
/// so its commit and the objects under the commit survive.
#[test]
fn with_no_filter_each_collection_ref_is_strong() {
    let tmp = TmpDir::new("weak-refs-collection-no-filter");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "m", "loose"]).await;
        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let mirrored = commit(&repo, tmp.path(), "m", None, None).await;
        let mirrored_root = commit_root(&repo, &mirrored).await;
        let cref = set_collection_ref(&repo, "org.example.Coll", "pool/m", &mirrored).await;
        let loose = commit(&repo, tmp.path(), "loose", None, None).await;

        let opts = PruneOptions {
            refs_only: true,
            ..PruneOptions::new()
        };
        let stats = repo.prune(&opts).await.unwrap();

        assert!(stats.deleted_refs.is_empty(), "{:?}", stats.deleted_refs);
        assert!(
            stats.deleted_collection_refs.is_empty(),
            "{:?}",
            stats.deleted_collection_refs
        );
        assert!(
            !holds(&repo, &loose).await,
            "the run swept the loose commit"
        );
        assert_eq!(
            collection_tip(&repo, &cref).await,
            Some(mirrored),
            "the collection ref stands"
        );
        assert!(
            holds(&repo, &mirrored).await,
            "the collection ref roots its commit"
        );
        assert!(
            holds_tree(&repo, &mirrored_root).await,
            "and the tree under it"
        );
    });
}

/// A classifier that marks the refs of one collection weak leaves the refs of
/// another collection strong, also under the same ref name.
#[test]
fn a_filter_on_one_collection_leaves_another_collection_strong() {
    let tmp = TmpDir::new("weak-refs-collection-other");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "cache", "keep"]).await;
        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let cached = commit(&repo, tmp.path(), "cache", None, None).await;
        let kept = commit(&repo, tmp.path(), "keep", None, None).await;
        let weak = set_collection_ref(&repo, "org.example.Cache", "app/main", &cached).await;
        let strong = set_collection_ref(&repo, "org.example.Keep", "app/main", &kept).await;

        let (filter, seen) =
            recording_filter(|name: &str| !name.starts_with("org.example.Cache::"));
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let names = recorded(&seen);
        for name in ["org.example.Cache::app/main", "org.example.Keep::app/main"] {
            assert!(
                names.iter().any(|n| n == name),
                "the classifier saw {name}: {names:?}"
            );
        }
        assert_eq!(stats.deleted_collection_refs, vec![weak.clone()]);
        assert_eq!(collection_tip(&repo, &weak).await, None);
        assert!(
            !holds(&repo, &cached).await,
            "the weak ref's commit is swept"
        );
        assert_eq!(
            collection_tip(&repo, &strong).await,
            Some(kept),
            "the ref of the other collection stands"
        );
        assert!(holds(&repo, &kept).await, "and roots its commit");
    });
}

/// A file under `refs/mirrors` whose path does not split into a valid
/// collection id and a valid ref name never reaches the classifier. The run
/// does not change it, and its commit stands. A valid mirror ref in the same
/// run is classified and deleted.
///
/// `a` has one element, `1org.x` has an element that starts with a digit,
/// `-bad` is not a valid ref name component, and `stray` has no ref name.
#[test]
fn a_mirror_ref_outside_the_name_rule_is_never_classified() {
    let tmp = TmpDir::new("weak-refs-collection-invalid");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "valid", "invalid"]).await;
        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let valid = commit(&repo, tmp.path(), "valid", None, None).await;
        let cref = set_collection_ref(&repo, "org.example.Cache", "pool/ok", &valid).await;
        let invalid = commit(&repo, tmp.path(), "invalid", None, None).await;
        let invalid_root = commit_root(&repo, &invalid).await;

        // No write path of the library accepts these paths, so the test writes
        // the files with blocking `std::fs`.
        let body = format!("{}\n", invalid.to_hex());
        let mirrors = tmp.path().join("repo/refs/mirrors");
        let paths = [
            mirrors.join("a/pool/x"),
            mirrors.join("1org.x/pool/y"),
            mirrors.join("org.example.Cache/-bad"),
            mirrors.join("stray"),
        ];
        for path in &paths {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, &body).unwrap();
        }

        let (filter, seen) = recording_filter(|name: &str| name == "main");
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let mut names = recorded(&seen);
        names.sort();
        assert_eq!(
            names,
            vec!["main".to_owned(), "org.example.Cache::pool/ok".to_owned()],
            "only the valid refs reached the classifier"
        );
        assert_eq!(stats.deleted_collection_refs, vec![cref.clone()]);
        assert!(stats.deleted_refs.is_empty(), "{:?}", stats.deleted_refs);
        assert_eq!(collection_tip(&repo, &cref).await, None);
        assert!(
            !holds(&repo, &valid).await,
            "the valid ref's commit is swept"
        );
        for path in &paths {
            assert_eq!(
                std::fs::read_to_string(path).unwrap(),
                body,
                "{} stands with the content it was written with",
                path.display()
            );
        }
        assert!(
            holds(&repo, &invalid).await,
            "the invalid refs rooted their commit"
        );
        assert!(
            holds_tree(&repo, &invalid_root).await,
            "and the tree under it"
        );
    });
}

/// A dry run lists the weak collection refs that a run deletes and deletes
/// nothing.
#[test]
fn a_dry_run_lists_weak_collection_refs_and_deletes_nothing() {
    let tmp = TmpDir::new("weak-refs-collection-no-prune");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "cached"]).await;
        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let cached = commit(&repo, tmp.path(), "cached", None, None).await;
        let cref = set_collection_ref(&repo, "org.example.Cache", "pool/c", &cached).await;

        let opts = PruneOptions {
            no_prune: true,
            ..weak_options(collection_is_weak("org.example.Cache"))
        };
        let stats = repo.prune(&opts).await.unwrap();

        assert_eq!(
            stats.deleted_collection_refs,
            vec![cref.clone()],
            "the dry run names the ref the run would delete"
        );
        assert!(stats.deleted_refs.is_empty(), "{:?}", stats.deleted_refs);
        assert_eq!(
            collection_tip(&repo, &cref).await,
            Some(cached),
            "the ref still names its commit"
        );
        assert!(holds(&repo, &cached).await, "the commit stands");
    });
}

/// The deleted collection refs are sorted by collection id and then by ref
/// name. `org.ex` sorts before `org.ex.sub`, though the path `org.ex.sub/a`
/// sorts before the path `org.ex/x` in byte order.
#[test]
fn the_deleted_collection_ref_list_is_sorted_by_id_then_name() {
    let tmp = TmpDir::new("weak-refs-collection-sorted");
    let refs = [
        ("org.zeta.C", "b"),
        ("org.zeta.C", "a/z"),
        ("org.ex.sub", "a"),
        ("org.ex", "x"),
        ("org.alpha.C", "pool/9"),
        ("org.alpha.C", "pool/0"),
    ];
    block_on(async {
        let mut names = vec!["head".to_owned()];
        names.extend((0..refs.len()).map(|i| format!("t{i}")));
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let repo = repo_with_trees(tmp.path(), &names).await;
        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        for (i, (collection_id, name)) in refs.iter().enumerate() {
            let target = commit(&repo, tmp.path(), &format!("t{i}"), None, None).await;
            set_collection_ref(&repo, collection_id, name, &target).await;
        }

        let filter = WeakRefFilter::new(|location: RefLocation<'_>, _: &Checksum| {
            !matches!(location, RefLocation::Collection { .. })
        });
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let expected: Vec<CollectionRef> = [
            ("org.alpha.C", "pool/0"),
            ("org.alpha.C", "pool/9"),
            ("org.ex", "x"),
            ("org.ex.sub", "a"),
            ("org.zeta.C", "a/z"),
            ("org.zeta.C", "b"),
        ]
        .iter()
        .map(|(collection_id, name)| CollectionRef::new(*collection_id, *name))
        .collect();
        assert_eq!(stats.deleted_collection_refs, expected);
    });
}

/// A mirror ref of the `[core] collection-id` of the repository reaches the
/// classifier as a collection ref. After the run deletes it, the local ref of
/// the same name stays, and a read of the collection ref gives the commit of
/// the local ref.
#[test]
fn an_own_id_mirror_ref_is_classified_as_a_collection_ref() {
    let tmp = TmpDir::new("weak-refs-collection-own-id");
    block_on(async {
        for name in ["local", "mirror"] {
            write_tree(tmp.path(), name);
        }
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive).collection_id("org.example.Own"),
        )
        .await
        .unwrap();
        let local = commit(&repo, tmp.path(), "local", None, Some("app")).await;
        let mirrored = commit(&repo, tmp.path(), "mirror", None, None).await;
        let cref = set_collection_ref(&repo, "org.example.Own", "app", &mirrored).await;
        assert_eq!(
            collection_tip(&repo, &cref).await,
            Some(mirrored),
            "the mirror ref wins before the run"
        );

        let (filter, seen) = recording_filter(|name: &str| !name.contains("::"));
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let mut names = recorded(&seen);
        names.sort();
        assert_eq!(
            names,
            vec!["app".to_owned(), "org.example.Own::app".to_owned()],
            "the classifier saw the local ref and the collection ref"
        );
        assert_eq!(stats.deleted_collection_refs, vec![cref.clone()]);
        assert!(stats.deleted_refs.is_empty(), "{:?}", stats.deleted_refs);
        assert!(
            !tmp.path()
                .join("repo/refs/mirrors/org.example.Own/app")
                .exists(),
            "the mirror ref file is gone"
        );
        assert_eq!(tip(&repo, "app").await, Some(local), "the local ref stays");
        assert_eq!(
            collection_tip(&repo, &cref).await,
            Some(local),
            "a read of the collection ref gives the local ref"
        );
        assert!(!holds(&repo, &mirrored).await, "the mirror commit is swept");
    });
}

/// A strong alias over a weak ref roots the commit that the two refs share, so
/// the walk reaches the weak ref. Both files stay.
#[test]
fn a_strong_alias_over_a_weak_ref_keeps_both_refs() {
    let tmp = TmpDir::new("weak-refs-strong-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "target"]).await;
        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let x = commit(&repo, tmp.path(), "target", None, Some("pool/target")).await;
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

/// The classifier answers weak for an alias over a strong ref. The alias
/// survives because the ref that it names roots the commit behind the link.
#[test]
fn a_weak_alias_over_a_strong_ref_survives() {
    let tmp = TmpDir::new("weak-refs-weak-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head"]).await;
        let x = commit(&repo, tmp.path(), "head", None, Some("main")).await;
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

/// The ref reader skips an alias whose target ref is absent, so the alias never
/// reaches the classifier. The run leaves the alias in place.
#[test]
fn a_dangling_alias_is_never_classified_and_never_deleted() {
    let tmp = TmpDir::new("weak-refs-dangling-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "orphan"]).await;
        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let orphan = commit(&repo, tmp.path(), "orphan", None, Some("pool/a")).await;
        // The test never writes `pool/missing`, so the link dangles.
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

/// A ref file under `refs/remotes` that an out-of-band write placed under a
/// name outside the ref-name rule is never classified. The run does not change
/// it, and its commit stands. A ref with a valid remote name is classified one
/// time.
///
/// `refs/remotes/a:b/pool/x` and `refs/remotes/a/b:pool/x` both list as
/// `a:b:pool/x`, a name that holds a `:` in its name part. The rule refuses
/// that name, so neither file is addressable. The refspec `a:pool/x` is valid
/// and maps to `refs/remotes/a/pool/x`. A file directly under `refs/remotes`
/// lists under a name that maps below `refs/heads`.
#[test]
fn a_remote_ref_outside_the_name_rule_is_never_classified() {
    let tmp = TmpDir::new("weak-refs-colon-remote");
    block_on(async {
        let repo = repo_with_trees(
            tmp.path(),
            &["head", "shadowed", "second", "addressed", "stray"],
        )
        .await;
        commit(&repo, tmp.path(), "head", None, Some("main")).await;

        // No write path of the library accepts these names, so the test writes
        // the files with blocking `std::fs`.
        let shadowed = commit(&repo, tmp.path(), "shadowed", None, None).await;
        let shadowed_root = commit_root(&repo, &shadowed).await;
        let shadowed_path = tmp.path().join("repo/refs/remotes/a:b/pool/x");
        let shadowed_body = format!("{}\n", shadowed.to_hex());
        std::fs::create_dir_all(shadowed_path.parent().unwrap()).unwrap();
        std::fs::write(&shadowed_path, &shadowed_body).unwrap();

        let second = commit(&repo, tmp.path(), "second", None, None).await;
        let second_root = commit_root(&repo, &second).await;
        let second_path = tmp.path().join("repo/refs/remotes/a/b:pool/x");
        let second_body = format!("{}\n", second.to_hex());
        std::fs::create_dir_all(second_path.parent().unwrap()).unwrap();
        std::fs::write(&second_path, &second_body).unwrap();

        // The refspec `a:pool/x` is valid and addresses its own file.
        let addressed = commit(&repo, tmp.path(), "addressed", None, None).await;
        let addressed_root = commit_root(&repo, &addressed).await;
        repo.set_ref_immediate("a:pool/x", Some(&addressed))
            .await
            .unwrap();
        let addressed_path = tmp.path().join("repo/refs/remotes/a/pool/x");
        assert!(
            addressed_path.exists(),
            "the refspec wrote the file it maps to"
        );

        // A file directly under `refs/remotes` lists under a name that maps
        // below `refs/heads`. A ref of that name also stands there.
        let stray = commit(&repo, tmp.path(), "stray", None, None).await;
        let stray_path = tmp.path().join("repo/refs/remotes/poolstray");
        std::fs::write(&stray_path, format!("{}\n", stray.to_hex())).unwrap();
        repo.set_ref_immediate("poolstray", Some(&stray))
            .await
            .unwrap();

        let (filter, seen) = recording_pool_is_weak();
        let stats = repo.prune(&weak_options(filter)).await.unwrap();

        let names = recorded(&seen);
        assert!(
            !names.iter().any(|n| n == "a:b:pool/x"),
            "no file that lists as a name outside the rule reached the classifier: {names:?}"
        );
        assert_eq!(
            names.iter().filter(|n| *n == "a:pool/x").count(),
            1,
            "the valid name reached the classifier once: {names:?}"
        );
        assert_eq!(
            stats.deleted_refs,
            vec!["a:pool/x".to_owned()],
            "the run deleted the addressed ref alone"
        );
        assert!(!addressed_path.exists(), "the addressed file is gone");
        assert!(!holds(&repo, &addressed).await, "and its commit is swept");
        assert!(
            !holds_tree(&repo, &addressed_root).await,
            "with the tree only it reached"
        );
        for (path, body, commit_id, root) in [
            (&shadowed_path, &shadowed_body, &shadowed, &shadowed_root),
            (&second_path, &second_body, &second, &second_root),
        ] {
            assert_eq!(
                &std::fs::read_to_string(path).unwrap(),
                body,
                "the file stands with the content it was written with"
            );
            assert!(
                holds(&repo, commit_id).await,
                "so it rooted the walk and its commit survives"
            );
            assert!(
                holds_tree(&repo, root).await,
                "and so does the tree it reaches"
            );
        }
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

/// A classifier runs caller code. An actor outside the process can clear a ref
/// directory at any time between the listing and the unlink. The file of a
/// doomed ref and its parent directory can both be gone when the pass reaches
/// the ref. In that case, the run reports the ref as deleted and continues to
/// the sweep.
#[test]
fn a_ref_directory_gone_before_the_unlink_does_not_fail_the_run() {
    let tmp = TmpDir::new("weak-refs-vanished-parent");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "doomed"]).await;
        let head = commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let doomed = commit(&repo, tmp.path(), "doomed", None, Some("pool/doomed")).await;
        let doomed_root = commit_root(&repo, &doomed).await;

        // The classifier clears the directory that holds the doomed ref. The
        // unlink then finds no file, and the directory that held the file is
        // also gone.
        let dir = tmp.path().join("repo/refs/heads/pool");
        let filter = WeakRefFilter::new(move |location: RefLocation<'_>, _: &Checksum| {
            let name = label(location);
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

/// A weak remote ref re-seeds the walk under the bound of its own name. That
/// name is its `<remote>:<name>` refspec. A `PruneOptions::retain_branch_depth`
/// entry with that refspec as key keeps the ancestry below the commit that the
/// walk arrived at.
#[test]
fn a_reached_weak_remote_ref_reseeds_the_walk_at_its_refspec_bound() {
    let tmp = TmpDir::new("weak-refs-remote-rule-b");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["g1", "g2", "g3", "head", "d1", "d2"]).await;
        let g1 = commit(&repo, tmp.path(), "g1", None, None).await;
        let g2 = commit(&repo, tmp.path(), "g2", Some(g1), None).await;
        let g3 = commit(&repo, tmp.path(), "g3", Some(g2), Some("origin:pool/chain")).await;
        // `main` reaches g3 over a build-source edge with the global bound of
        // 0. g2 and g1 survive only under the weak ref's own bound.
        let head = commit(&repo, tmp.path(), "head", None, Some("main")).await;
        repo.add_detached_related(&head, "source/chain", &g3)
            .await
            .unwrap();
        // The control chain has a strong ref at the global depth of 0. The walk
        // keeps d2 and drops d1. This chain proves that the depth bound
        // applies, so the assertions on the weak ref's ancestry cannot pass
        // vacuously.
        let d1 = commit(&repo, tmp.path(), "d1", None, None).await;
        let d2 = commit(&repo, tmp.path(), "d2", Some(d1), Some("other")).await;

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

/// An alias links a ref of one space to a ref of another space. The classifier
/// gets each alias under the name of the file that holds the alias. The space
/// of the target does not change this name. If the walk never reaches the
/// commit of an alias, the run removes the symlink of the alias.
#[test]
fn a_cross_space_alias_is_classified_under_its_own_name() {
    let tmp = TmpDir::new("weak-refs-cross-space-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "target"]).await;
        let head = commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let target = commit(
            &repo,
            tmp.path(),
            "target",
            None,
            Some("origin:pool/target"),
        )
        .await;
        let target_root = commit_root(&repo, &target).await;
        // A local alias that names a remote ref, and a remote alias that names
        // the strong local ref.
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
        // The remote alias is also weak. The ref that it names roots the
        // commit behind the link, so the alias survives as a link.
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

/// A weak alias under `refs/remotes` over a weak remote ref leaves no ref file.
/// The run removes the link and the file that the link names. The run then
/// sweeps the commit that the two refs shared.
#[test]
fn a_weak_remote_alias_over_a_weak_remote_ref_leaves_no_ref_file() {
    let tmp = TmpDir::new("weak-refs-remote-alias");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head", "target"]).await;
        commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let target = commit(
            &repo,
            tmp.path(),
            "target",
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
