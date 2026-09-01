//! Transaction and locking integration tests (Phase 6).
//!
//! These exercise the transaction lifecycle against real repositories: staging
//! directory allocation and teardown, reaping of stale staging directories,
//! concurrent transactions in one process, drop-based auto-abort, and
//! cross-process lock contention (the last driven by re-executing this test
//! binary as a lock holder).

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use common::TmpDir;
use ostrya::{
    Checksum, CreateOptions, DirMeta, Error, LockKind, ObjectType, Repo, RepoMode, Xattrs,
    loose_path,
};
use ostrya_rt::block_on;

/// The staging directory names present under `<repo>/tmp`.
fn staging_dirs(repo: &Path) -> Vec<String> {
    let tmp = repo.join("tmp");
    let mut dirs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&tmp) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir && name.starts_with("staging-") && !name.ends_with("-lock") {
                dirs.push(name);
            }
        }
    }
    dirs
}

fn new_repo(tag: &str) -> (TmpDir, PathBuf) {
    let dir = TmpDir::new(tag);
    let repo_path = dir.path().join("repo");
    block_on(Repo::create(&repo_path, CreateOptions::new(RepoMode::Bare))).expect("create repo");
    (dir, repo_path)
}

#[test]
fn transaction_allocates_and_removes_a_staging_dir() {
    let (_dir, repo_path) = new_repo("txn-life");
    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let txn = repo.transaction().await.unwrap();

        let dirs = staging_dirs(&repo_path);
        assert_eq!(dirs.len(), 1, "one staging dir during the transaction");
        let lock = repo_path.join("tmp").join(format!("{}-lock", dirs[0]));
        assert!(
            lock.exists(),
            "staging lock sibling exists during the transaction"
        );

        txn.commit().await.unwrap();

        assert!(
            staging_dirs(&repo_path).is_empty(),
            "staging dir removed after commit"
        );
        assert!(!lock.exists(), "staging lock removed after commit");
    });
}

#[test]
fn aborting_a_transaction_removes_its_staging_dir() {
    let (_dir, repo_path) = new_repo("txn-abort");
    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        assert_eq!(staging_dirs(&repo_path).len(), 1);
        txn.abort().await.unwrap();
        assert!(
            staging_dirs(&repo_path).is_empty(),
            "abort reaps the staging dir"
        );
    });
}

#[test]
fn dropping_a_transaction_reaps_its_staging_dir() {
    let (_dir, repo_path) = new_repo("txn-drop");
    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        {
            let _txn = repo.transaction().await.unwrap();
            assert_eq!(
                staging_dirs(&repo_path).len(),
                1,
                "staging dir present while held"
            );
        } // dropped without commit or abort
        assert!(
            staging_dirs(&repo_path).is_empty(),
            "dropping the transaction reaps the staging dir"
        );
    });
}

#[test]
fn concurrent_shared_transactions_get_distinct_staging_dirs() {
    let (_dir, repo_path) = new_repo("txn-concurrent");
    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let t1 = repo.transaction().await.unwrap();
        let t2 = repo.transaction().await.unwrap();

        let mut dirs = staging_dirs(&repo_path);
        dirs.sort();
        assert_eq!(dirs.len(), 2, "two live transactions, two staging dirs");
        assert_ne!(dirs[0], dirs[1], "each transaction has its own staging dir");

        t1.commit().await.unwrap();
        assert_eq!(
            staging_dirs(&repo_path).len(),
            1,
            "one staging dir after the first commit"
        );
        t2.commit().await.unwrap();
        assert!(
            staging_dirs(&repo_path).is_empty(),
            "no staging dir after both commit"
        );
    });
}

#[test]
fn concurrent_transactions_keep_their_staging_dirs() {
    let (_dir, repo_path) = new_repo("txn-stress");

    // tmp-expiry-secs=0 makes the reaper treat a lockless staging directory as
    // immediately expired, the setting under which a concurrently starting
    // transaction was able to reap a live transaction's directory.
    let config = repo_path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("tmp-expiry-secs=0\n");
    std::fs::write(&config, text).unwrap();

    const WORKERS: usize = 8;
    const ROUNDS: usize = 20;

    let repo = block_on(Repo::open(&repo_path)).unwrap();

    for round in 0..ROUNDS {
        // `start` releases all workers into `transaction()` together so their
        // staging creation overlaps. `created` gates the count until every
        // transaction is live; `release` holds them live until the count is
        // taken.
        let start = Arc::new(Barrier::new(WORKERS));
        let created = Arc::new(Barrier::new(WORKERS + 1));
        let release = Arc::new(Barrier::new(WORKERS + 1));

        let mut handles = Vec::with_capacity(WORKERS);
        for _ in 0..WORKERS {
            let repo = repo.clone();
            let start = Arc::clone(&start);
            let created = Arc::clone(&created);
            let release = Arc::clone(&release);
            handles.push(thread::spawn(move || {
                block_on(async {
                    start.wait();
                    let txn = repo.transaction().await.unwrap();
                    created.wait();
                    release.wait();
                    txn.commit().await.unwrap();
                });
            }));
        }

        created.wait();
        let dirs = staging_dirs(&repo_path);
        release.wait();
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            dirs.len(),
            WORKERS,
            "round {round}: each live transaction keeps its own staging dir, got {dirs:?}"
        );
    }
}

#[test]
fn a_transaction_reaps_a_stale_staging_dir() {
    let (_dir, repo_path) = new_repo("txn-reap");
    let tmp = repo_path.join("tmp");

    // Fabricate a leftover staging directory with an unheld sibling lock, as a
    // crashed transaction would leave behind. It is non-empty, so reaping it
    // exercises the recursive removal.
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let stale = format!("staging-{}-STALE0", boot.trim());
    let stale_dir = tmp.join(&stale);
    std::fs::create_dir_all(stale_dir.join("aa")).unwrap();
    std::fs::write(stale_dir.join("aa").join("leftover"), b"x").unwrap();
    let stale_lock = tmp.join(format!("{stale}-lock"));
    std::fs::write(&stale_lock, b"").unwrap();

    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        assert!(
            !stale_dir.exists(),
            "the stale staging dir is reaped at transaction start"
        );
        assert!(!stale_lock.exists(), "the stale staging lock is reaped too");
        txn.commit().await.unwrap();
    });
}

#[test]
fn cross_process_lock_contention() {
    let (_dir, repo_path) = new_repo("txn-xproc");

    // Shorten the lock timeout so the contended acquire fails within a second.
    let config = repo_path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("lock-timeout-secs=1\n");
    std::fs::write(&config, text).unwrap();

    // Re-execute this test binary as an exclusive-lock holder.
    let held_marker = repo_path.join(".held");
    let _ = std::fs::remove_file(&held_marker);
    let mut holder = Command::new(std::env::current_exe().unwrap())
        .args([
            "lock_holder_subprocess",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("OSTRYA_HOLD_REPO", &repo_path)
        .env("OSTRYA_HOLD_MS", "3000")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lock holder");

    // Wait for the holder to acquire the exclusive lock.
    let mut ready = false;
    for _ in 0..200 {
        if held_marker.exists() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "the holder never acquired the lock");

    // While the holder has the exclusive lock, our shared acquire must time out.
    let contended = block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        repo.transaction().await
    });
    assert!(contended.is_err(), "acquiring while contended should fail");
    assert!(
        matches!(contended.err(), Some(Error::LockTimeout { .. })),
        "the contended acquire should report a lock timeout"
    );

    // Once the holder releases, acquisition succeeds.
    holder.wait().expect("holder exits");
    let after = block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let txn = repo.transaction().await?;
        txn.commit().await
    });
    assert!(
        after.is_ok(),
        "acquire after release should succeed: {after:?}"
    );
}

/// The lock-holder half of [`cross_process_lock_contention`], run only when this
/// test binary is re-executed with the environment set. It takes the exclusive
/// repository lock, signals readiness, holds it briefly, then releases.
#[test]
#[ignore = "helper process for cross_process_lock_contention"]
fn lock_holder_subprocess() {
    let Ok(repo_path) = std::env::var("OSTRYA_HOLD_REPO") else {
        return;
    };
    let hold_ms: u64 = std::env::var("OSTRYA_HOLD_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000);

    block_on(async {
        let repo = Repo::open(Path::new(&repo_path)).await.expect("open repo");
        let txn = repo
            .transaction_with_lock(LockKind::Exclusive)
            .await
            .expect("acquire exclusive lock");
        std::fs::write(Path::new(&repo_path).join(".held"), b"1").expect("write readiness marker");
        ostrya_rt::Timer::after(Duration::from_millis(hold_ms)).await;
        txn.commit().await.expect("release lock");
    });
}

/// `Transaction::write_dirmeta` and `loose_path` reach a consumer through the
/// `ostrya` crate alone, and the pair locates the object a dirmeta write leaves
/// in `objects/`.
///
/// The two modes name one directory by two checksums: `bare` records the
/// ownership, the mode, and the xattrs `meta` states, and `bare-user-only`
/// records the canonical form of the same directory. The object's identity
/// covers the form the mode records, which is what this method holds for a
/// caller assembling a tree.
#[test]
fn write_dirmeta_and_loose_path_are_public() {
    let dir = TmpDir::new("public-dirmeta");

    // A directory whose every canonicalized field carries something to lose:
    // a non-zero owner, an xattr, and permission bits outside the 0o755 a
    // `bare-user-only` repository keeps.
    let meta = DirMeta {
        uid: 1000,
        gid: 1000,
        mode: 0o042_771,
        xattrs: Xattrs::new([(b"user.mark\0".to_vec(), b"value".to_vec())]).unwrap(),
    };
    let canonical = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040_751,
        xattrs: Xattrs::empty(),
    };

    let stored = |mode: RepoMode, meta: &DirMeta| -> Checksum {
        let repo_path = dir.path().join(format!("repo-{}", mode.as_mode_str()));
        let meta = meta.clone();
        block_on(async move {
            Repo::create(&repo_path, CreateOptions::new(mode))
                .await
                .unwrap();
            let repo = Repo::open(&repo_path).await.unwrap();
            let txn = repo.transaction().await.unwrap();
            let checksum = txn.write_dirmeta(&meta).await.unwrap();
            txn.commit().await.unwrap();

            let path =
                repo_path
                    .join("objects")
                    .join(loose_path(&checksum, ObjectType::DirMeta, mode));
            assert!(path.exists(), "{} names the written object", path.display());
            assert_eq!(
                std::fs::read(&path).unwrap(),
                meta.serialize().unwrap(),
                "the object holds the bytes the mode records"
            );
            checksum
        })
    };

    let bare = stored(RepoMode::Bare, &meta);
    let bare_user_only = stored(RepoMode::BareUserOnly, &canonical);
    assert_ne!(
        bare, bare_user_only,
        "the two modes record the directory under different identities"
    );

    // The `bare-user-only` write of the stated form reaches the identity of the
    // canonical form, which is the checksum the mode records.
    let repo_path = dir.path().join("repo-canonical");
    let recorded = block_on(async {
        Repo::create(&repo_path, CreateOptions::new(RepoMode::BareUserOnly))
            .await
            .unwrap();
        let repo = Repo::open(&repo_path).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let checksum = txn.write_dirmeta(&meta).await.unwrap();
        txn.commit().await.unwrap();
        checksum
    });
    assert_eq!(recorded, bare_user_only);
}
