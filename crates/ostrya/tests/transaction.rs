//! Integration tests of transactions and of the repository lock.
//!
//! The tests run transactions on real repositories. They cover:
//!
//! - the creation and the removal of the staging directory
//! - the reap of stale staging directories and of aged `tmp/` entries
//! - concurrent transactions in one process
//! - the automatic abort of a transaction that is dropped
//! - lock contention between two processes (this test binary runs again as
//!   the lock holder)
//! - the public `Transaction::write_dirmeta` and `loose_path`

mod common;

use std::os::unix::net::UnixListener;
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

/// Returns the names of the staging directories under `<repo>/tmp`.
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

    // With `tmp-expiry-secs=0`, the reaper treats a staging directory without
    // a lock as expired at once. If the staging creation has a race, this
    // setting lets a transaction that starts at the same time reap the staging
    // directory of a live transaction.
    let config = repo_path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("tmp-expiry-secs=0\n");
    std::fs::write(&config, text).unwrap();

    const WORKERS: usize = 8;
    const ROUNDS: usize = 20;

    let repo = block_on(Repo::open(&repo_path)).unwrap();

    for round in 0..ROUNDS {
        // `start` releases all workers into `transaction()` at the same time,
        // so the creation of their staging directories overlaps. `created`
        // holds the count until every transaction is live. `release` keeps the
        // transactions live until the count is done.
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
    let (dir, repo_path) = new_repo("txn-reap");
    let tmp = repo_path.join("tmp");

    // Make a leftover staging directory with a sibling lock that no process
    // holds. A transaction that crashes leaves this pair. The directory is not
    // empty, so its reap tests the recursive removal.
    let stale = format!("staging-{}-STALE0", boot_id());
    let stale_dir = tmp.join(&stale);
    std::fs::create_dir_all(stale_dir.join("aa")).unwrap();
    std::fs::write(stale_dir.join("aa").join("leftover"), b"x").unwrap();
    let stale_lock = tmp.join(format!("{stale}-lock"));
    std::fs::write(&stale_lock, b"").unwrap();
    // The removal unlinks a symlink in the tree as a link. Its target stays.
    let outside = dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"k").unwrap();
    let outside_file = dir.path().join("outside-file");
    std::fs::write(&outside_file, b"f").unwrap();
    std::os::unix::fs::symlink(&outside, stale_dir.join("aa").join("to-dir")).unwrap();
    std::os::unix::fs::symlink(&outside_file, stale_dir.join("to-file")).unwrap();

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
    assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"k");
    assert_eq!(std::fs::read(&outside_file).unwrap(), b"f");
}

/// Returns the boot id of the host.
fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .to_owned()
}

/// Makes a FIFO at `path`.
fn mkfifo(path: &Path) {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
}

/// Runs `f` in a new thread and gives its result. A panic of `f` passes on.
/// If `f` does not return in 10 seconds, the function opens the FIFO `fifo`
/// for write with no wait, which releases an open that waits for a writer,
/// and panics.
fn without_block<T: Send + 'static>(fifo: &Path, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(value) => {
            worker.join().unwrap();
            value
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => match worker.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => unreachable!("the worker sends a value before it ends"),
        },
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let _ = rustix::fs::open(
                fifo,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            );
            panic!("an open of the FIFO {} blocked", fifo.display());
        }
    }
}

/// The kinds of entry that a test puts at a lock file name.
const NOT_REGULAR: [&str; 4] = ["symlink", "fifo", "socket", "directory"];

/// Makes an entry of the kind `kind` at `at`. A symlink points to the regular
/// file `target`.
///
/// A socket binds at the short path `socket` next to `target`, because the
/// path of a socket address has a limit of 107 bytes, and then moves to `at`.
/// The function gives the listener of a socket, and the caller keeps it while
/// the case runs.
fn make_entry(kind: &str, at: &Path, target: &Path) -> Option<UnixListener> {
    match kind {
        "symlink" => std::os::unix::fs::symlink(target, at).unwrap(),
        "fifo" => mkfifo(at),
        "socket" => {
            let bound = target.with_file_name("socket");
            let listener = UnixListener::bind(&bound).unwrap();
            std::fs::rename(&bound, at).unwrap();
            return Some(listener);
        }
        "directory" => std::fs::create_dir(at).unwrap(),
        other => unreachable!("no entry kind {other}"),
    }
    None
}

#[test]
fn a_repository_lock_that_is_not_a_regular_file_fails_the_begin() {
    for kind in NOT_REGULAR {
        let (dir, repo_path) = new_repo("txn-lock-not-regular");
        let target = dir.path().join("outside");
        std::fs::write(&target, b"outside bytes").unwrap();
        let lock = repo_path.join(".lock");
        let _listener = make_entry(kind, &lock, &target);

        let path = repo_path.clone();
        let err = without_block(&lock, move || {
            block_on(async {
                let repo = Repo::open(&path).await.unwrap();
                repo.transaction().await.map(drop).unwrap_err()
            })
        });
        let expected = if kind == "symlink" {
            ".lock passes through a symlink; ostrya refuses a symlink in the repository"
        } else {
            ".lock is not a regular file"
        };
        assert!(
            matches!(&err, Error::InvalidFormat(m) if m == expected),
            ".lock as a {kind}: {err:?}"
        );
        assert!(
            staging_dirs(&repo_path).is_empty(),
            ".lock as a {kind}: the begin made no staging dir"
        );
        let left: Vec<String> = listing(&repo_path.join("tmp"))
            .into_iter()
            .filter(|n| n.starts_with("staging-"))
            .collect();
        assert!(left.is_empty(), ".lock as a {kind}: {left:?}");
        assert_eq!(std::fs::read(&target).unwrap(), b"outside bytes");

        // With `locking=false` the begin does not open `.lock`.
        let config = repo_path.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("locking=false\n");
        std::fs::write(&config, text).unwrap();
        let path = repo_path.clone();
        without_block(&lock, move || {
            block_on(async {
                let repo = Repo::open(&path).await.unwrap();
                repo.transaction().await.unwrap().commit().await.unwrap();
            })
        });
    }
}

#[test]
fn a_stale_staging_dir_whose_lock_is_not_a_regular_file_stays() {
    for kind in NOT_REGULAR {
        let (dir, repo_path) = new_repo("txn-reap-not-regular");
        let tmp = repo_path.join("tmp");
        let target = dir.path().join("outside");
        std::fs::write(&target, b"outside bytes").unwrap();
        let stale = format!("staging-{}-STALE1", boot_id());
        let stale_dir = tmp.join(&stale);
        std::fs::create_dir(&stale_dir).unwrap();
        std::fs::write(stale_dir.join("leftover"), b"x").unwrap();
        stamp(&stale_dir, OLD);
        let stale_lock = tmp.join(format!("{stale}-lock"));
        let _listener = make_entry(kind, &stale_lock, &target);

        let path = repo_path.clone();
        without_block(&stale_lock, move || {
            block_on(async {
                let repo = Repo::open(&path).await.unwrap();
                repo.transaction().await.unwrap().commit().await.unwrap();
            })
        });
        assert!(
            stale_dir.join("leftover").exists(),
            "a {kind} lock keeps the stale staging dir"
        );
        assert!(
            std::fs::symlink_metadata(&stale_lock).is_ok(),
            "the {kind} lock stays"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"outside bytes");
    }
}

/// Sets the mtime of `path` to `epoch` seconds. On a symlink, it sets the mtime
/// of the link itself (`touch -h`).
fn stamp(path: &Path, epoch: i64) {
    let status = Command::new("touch")
        .arg("-h")
        .arg("-d")
        .arg(format!("@{epoch}"))
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "touch could not stamp {}", path.display());
}

/// Returns the sorted names of the top-level entries of `dir`.
fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The time 2020-01-01T00:00:00Z. Its age is much more than the default
/// `tmp-expiry-secs`.
const OLD: i64 = 1_577_836_800;

#[test]
fn a_transaction_reaps_aged_tmp_entries() {
    let (dir, repo_path) = new_repo("txn-reap-aged");
    let tmp = repo_path.join("tmp");
    let outside = dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"k").unwrap();
    stamp(&outside, OLD);

    // Entries older than the expiry window. The reap removes each of them.
    std::fs::write(tmp.join("oldfile"), b"o").unwrap();
    stamp(&tmp.join("oldfile"), OLD);
    std::fs::write(tmp.join(".tmp-old"), b"o").unwrap();
    stamp(&tmp.join(".tmp-old"), OLD);
    // The temporary entries of a ref write and of a detached-metadata write.
    for name in [".ostrya-ref-1-1-aBc123", ".ostrya-tmp-1-aBc123"] {
        std::fs::write(tmp.join(name), b"o").unwrap();
        stamp(&tmp.join(name), OLD);
    }
    std::fs::write(tmp.join("staging-not-a-dir"), b"o").unwrap();
    stamp(&tmp.join("staging-not-a-dir"), OLD);
    let fifo = Command::new("mkfifo")
        .arg(tmp.join("oldfifo"))
        .status()
        .unwrap();
    assert!(fifo.success(), "mkfifo failed");
    stamp(&tmp.join("oldfifo"), OLD);
    // The reap checks a directory by its own mtime alone. A new child in an
    // old directory does not keep the directory.
    std::fs::create_dir_all(tmp.join("olddir/sub")).unwrap();
    std::fs::write(tmp.join("olddir/sub/fresh"), b"n").unwrap();
    stamp(&tmp.join("olddir"), OLD);
    // The reap removes a symlink as a link. The target of the link stays.
    std::os::unix::fs::symlink(&outside, tmp.join("oldlink")).unwrap();
    stamp(&tmp.join("oldlink"), OLD);

    // Entries that the reap keeps.
    std::fs::write(tmp.join("newfile"), b"n").unwrap();
    std::fs::write(tmp.join(".ostrya-ref-2-2-aBc123"), b"n").unwrap();
    std::fs::write(tmp.join(".ostrya-tmp-2-aBc123"), b"n").unwrap();
    std::fs::create_dir(tmp.join("newdir")).unwrap();
    std::fs::write(tmp.join("newdir/oldkid"), b"o").unwrap();
    stamp(&tmp.join("newdir/oldkid"), OLD);
    std::fs::write(tmp.join("cache/oldentry"), b"o").unwrap();
    stamp(&tmp.join("cache/oldentry"), OLD);
    stamp(&tmp.join("cache"), OLD);
    // The age check does not apply to a staging lock file.
    std::fs::write(tmp.join("staging-orphan-lock"), b"").unwrap();
    stamp(&tmp.join("staging-orphan-lock"), OLD);

    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        // The assertion ignores the staging directory and the lock of the
        // live transaction.
        let own: Vec<String> = staging_dirs(&repo_path)
            .into_iter()
            .flat_map(|n| [format!("{n}-lock"), n])
            .collect();
        let mut left = listing(&tmp);
        left.retain(|n| !own.contains(n));
        assert_eq!(
            left,
            [
                ".ostrya-ref-2-2-aBc123",
                ".ostrya-tmp-2-aBc123",
                "cache",
                "newdir",
                "newfile",
                "staging-orphan-lock"
            ],
            "the reap at transaction start removes the aged entries only"
        );
        txn.commit().await.unwrap();
    });
    assert!(
        tmp.join("cache/oldentry").exists(),
        "tmp/cache is not touched"
    );
    assert!(
        tmp.join("newdir/oldkid").exists(),
        "a fresh directory is kept whole"
    );
    assert!(outside.join("keep").exists(), "the symlink target stays");
}

#[test]
fn an_aged_temp_symlink_goes_as_a_link_and_a_name_that_is_not_utf8_stays() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let (dir, repo_path) = new_repo("txn-reap-names");
    let tmp = repo_path.join("tmp");
    let outside = dir.path().join("outside");
    std::fs::write(&outside, b"outside bytes").unwrap();
    let link = tmp.join(".ostrya-tmp-1-aBc123");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    stamp(&link, OLD);
    let raw = tmp.join(OsStr::from_bytes(b"\xffold"));
    std::fs::write(&raw, b"o").unwrap();
    stamp(&raw, OLD);

    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        repo.transaction().await.unwrap().commit().await.unwrap();
    });
    assert!(
        std::fs::symlink_metadata(&link).is_err(),
        "the aged temp symlink goes"
    );
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside bytes");
    assert!(raw.exists(), "a name that is not UTF-8 stays");
}

#[test]
fn the_tmp_age_test_is_strict_on_whole_seconds() {
    let (_dir, repo_path) = new_repo("txn-reap-age");
    let config = repo_path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("tmp-expiry-secs=5\n");
    std::fs::write(&config, text).unwrap();
    let tmp = repo_path.join("tmp");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    for age in [3, 8] {
        let path = tmp.join(format!("age{age}"));
        std::fs::write(&path, b"a").unwrap();
        stamp(&path, now - age);
    }

    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        assert!(
            tmp.join("age3").exists(),
            "an entry inside the window stays"
        );
        assert!(!tmp.join("age8").exists(), "an entry past the window goes");
        txn.commit().await.unwrap();
    });
}

#[test]
fn an_aged_lock_of_a_live_transaction_is_kept() {
    let (_dir, repo_path) = new_repo("txn-reap-live-lock");
    let tmp = repo_path.join("tmp");

    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let live = repo.transaction().await.unwrap();
        let name = staging_dirs(&repo_path).pop().unwrap();
        let lock = tmp.join(format!("{name}-lock"));
        stamp(&tmp.join(&name), OLD);
        stamp(&lock, OLD);

        let second = repo.transaction().await.unwrap();
        assert!(
            lock.exists(),
            "the lock of a live transaction is kept at any age"
        );
        assert!(tmp.join(&name).exists(), "the live staging dir is kept");
        second.commit().await.unwrap();
        live.commit().await.unwrap();
    });
}

#[test]
fn cross_process_lock_contention() {
    let (_dir, repo_path) = new_repo("txn-xproc");

    // Set a lock timeout of one second, so the contended acquire fails after
    // one second.
    let config = repo_path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("lock-timeout-secs=1\n");
    std::fs::write(&config, text).unwrap();

    // Run this test binary again as the holder of the exclusive lock.
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

    // While the holder has the exclusive lock, the shared acquire of this
    // process must time out.
    let contended = block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        repo.transaction().await
    });
    assert!(contended.is_err(), "acquiring while contended should fail");
    assert!(
        matches!(contended.err(), Some(Error::LockTimeout { .. })),
        "the contended acquire should report a lock timeout"
    );

    // After the holder releases the lock, the acquire succeeds.
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

/// Holds the repository lock for [`cross_process_lock_contention`].
///
/// The test runs only when this test binary runs again with `OSTRYA_HOLD_REPO`
/// set. It takes the exclusive repository lock and writes the readiness marker
/// `.held`. Then it holds the lock for `OSTRYA_HOLD_MS` milliseconds (3000 by
/// default) and releases it.
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

/// Checks that `Transaction::write_dirmeta` and `loose_path` are public.
///
/// A consumer reaches the pair through the `ostrya` crate alone. The pair
/// locates the object that a dirmeta write leaves in `objects/`.
///
/// The two modes name one directory by two checksums. `bare` records the
/// ownership, the mode, and the xattrs that `meta` states. `bare-user-only`
/// records the canonical form of the same directory. The identity of the
/// object covers the form that the mode records, and the method returns this
/// identity to a caller that assembles a tree.
#[test]
fn write_dirmeta_and_loose_path_are_public() {
    let dir = TmpDir::new("public-dirmeta");

    // In this directory, each field that the canonical form changes holds a
    // value that the canonical form drops:
    // - an owner that is not zero
    // - an xattr
    // - permission bits outside the 0o755 that a `bare-user-only` repository
    //   keeps
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

    // A `bare-user-only` write of the stated form gets the identity of the
    // canonical form. This identity is the checksum that the mode records.
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
