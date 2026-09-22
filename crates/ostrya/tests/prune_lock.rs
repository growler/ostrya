//! The repository lock a prune holds.
//!
//! [`Repo::prune`] takes the repository lock exclusive for its whole run, so it
//! excludes every other writer, this process's own transactions included. These
//! tests drive that from the library side: a prune contended by a live
//! transaction, a transaction contended by a live exclusive hold, the same
//! prune once that transaction commits, a prune in a repository whose
//! `[core] locking` is false, and the one refusal that stands ahead of the
//! lock.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::TmpDir;
use ostrya::{
    CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Error, LockKind,
    MutableTree, ObjectType, PruneOptions, Repo, RepoMode,
};
use ostrya_rt::block_on;

/// A fixed timestamp, so the commits are reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// A repository under `<tmp>/repo`, with the config lines `extra` appended.
///
/// The config is read once at open, so every key a test states is written
/// before the handle exists.
fn new_repo(tag: &str, extra: &str) -> (TmpDir, PathBuf) {
    let dir = TmpDir::new(tag);
    let repo_path = dir.path().join("repo");
    block_on(Repo::create(
        &repo_path,
        CreateOptions::new(RepoMode::Archive),
    ))
    .expect("create repo");
    if !extra.is_empty() {
        let config = repo_path.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(extra);
        std::fs::write(&config, text).unwrap();
    }
    (dir, repo_path)
}

/// Write a one-file tree at `<base>/<name>`.
fn write_tree(base: &Path, name: &str) {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), format!("{name}\n")).unwrap();
}

/// Commit the tree `<base>/<name>` onto `branch` of `repo`.
async fn commit_tree(repo: &Repo, base: &Path, name: &str, branch: &str) {
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
                subject: Some(name.to_owned()),
                timestamp: Some(FIXED_TS),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref(branch, Some(&commit));
    txn.commit().await.unwrap();
}

#[test]
fn prune_times_out_while_a_transaction_is_open() {
    let (_dir, repo_path) = new_repo("prune-lock-contended", "lock-timeout-secs=1\n");

    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let txn = repo.transaction().await.unwrap();

        let start = Instant::now();
        let err = repo
            .prune(&PruneOptions::new())
            .await
            .expect_err("a prune contended by a live transaction fails");
        let elapsed = start.elapsed();

        assert!(
            matches!(err, Error::LockTimeout { secs: 1 }),
            "the contended prune reports the configured timeout: {err:?}"
        );
        assert!(
            elapsed >= Duration::from_secs(1),
            "the prune waited out the timeout, took {elapsed:?}"
        );

        // The transaction stands for the whole of the assertion above.
        drop(txn);
    });
}

/// A transaction opened while an exclusive hold stands waits for that hold, so
/// the exclusion runs in both directions inside one process.
///
/// This is the direction a prune depends on: the run takes the lock before it
/// lists the store, and a writer that opened afterwards must not reach the
/// objects the sweep is about to remove. The hold here is taken directly, so
/// the rule is pinned at the public API with no timing between two tasks.
#[test]
fn a_transaction_waits_for_an_exclusive_hold() {
    let (_dir, repo_path) = new_repo("prune-lock-txn-blocked", "lock-timeout-secs=1\n");

    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let held = repo
            .transaction_with_lock(LockKind::Exclusive)
            .await
            .expect("take the exclusive hold");

        let start = Instant::now();
        let Err(err) = repo.transaction().await else {
            panic!("a transaction opened under an exclusive hold succeeded");
        };
        let elapsed = start.elapsed();
        assert!(
            matches!(err, Error::LockTimeout { secs: 1 }),
            "the contended transaction reports the configured timeout: {err:?}"
        );
        assert!(
            elapsed >= Duration::from_secs(1),
            "the transaction waited out the timeout, took {elapsed:?}"
        );

        // The hold goes away and the next transaction opens at once.
        held.abort().await.unwrap();
        let txn = repo
            .transaction()
            .await
            .expect("a transaction opens once the exclusive hold releases");
        txn.abort().await.unwrap();
    });
}

#[test]
fn prune_succeeds_once_the_transaction_commits() {
    let (dir, repo_path) = new_repo("prune-lock-released", "lock-timeout-secs=1\n");

    block_on(async {
        write_tree(dir.path(), "tree");
        let repo = Repo::open(&repo_path).await.unwrap();
        commit_tree(&repo, dir.path(), "tree", "kept").await;

        let stats = repo
            .prune(&PruneOptions::new())
            .await
            .expect("the prune runs once no transaction stands");
        assert_eq!(stats.pruned_objects, 0, "a default prune removes nothing");

        // The commit the branch names is still in the store, so the run above
        // reached the sweep and kept what a ref roots.
        let head = repo.resolve_rev("kept", false).await.unwrap().unwrap();
        assert!(
            repo.has_object(ObjectType::Commit, &head).await.unwrap(),
            "the referenced commit survives the prune"
        );
        assert!(stats.total_objects > 0, "the run counted the store");
    });
}

#[test]
fn prune_with_locking_disabled_runs_while_a_transaction_is_open() {
    let (dir, repo_path) = new_repo(
        "prune-lock-disabled",
        "locking=false\nlock-timeout-secs=1\n",
    );

    block_on(async {
        write_tree(dir.path(), "tree");
        let repo = Repo::open(&repo_path).await.unwrap();
        commit_tree(&repo, dir.path(), "tree", "kept").await;

        // With `locking` true this call is the contended one that times out.
        let txn = repo.transaction().await.unwrap();
        let stats = repo
            .prune(&PruneOptions::new())
            .await
            .expect("a prune with locking disabled runs beside a transaction");
        assert_eq!(stats.pruned_objects, 0, "a default prune removes nothing");
        assert!(stats.total_objects > 0, "the run counted the store");

        drop(txn);
    });
}

#[test]
fn prune_static_deltas_only_refusal_precedes_the_lock() {
    let (_dir, repo_path) = new_repo("prune-lock-refusal", "lock-timeout-secs=1\n");

    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let txn = repo.transaction().await.unwrap();

        let opts = PruneOptions {
            static_deltas_only: true,
            delete_commit: None,
            ..PruneOptions::new()
        };
        let err = repo
            .prune(&opts)
            .await
            .expect_err("static_deltas_only without delete_commit is refused");
        assert!(
            matches!(err, Error::InvalidFormat(_)),
            "the refusal stands ahead of the lock, so it is no timeout: {err:?}"
        );

        drop(txn);
    });
}
