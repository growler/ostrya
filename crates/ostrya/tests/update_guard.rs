//! `Repo::begin_update` and `UpdateGuard`: the lock file, the exclusion across
//! processes and inside one process, the lock order against the repository
//! lock, the reads and writes of the guard, and the release rules of `finish`
//! and of a guard that drops.

mod common;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{
    GUARD_RELEASING_MARKER, TmpDir, foreign_holder, guard_holder, guard_holder_main,
    lock_holder_main,
};
use futures_lite::future::poll_once;
use ostrya::{
    Checksum, CollectionRef, CreateOptions, Error, LockKind, ObjectType, PruneOptions, Repo,
    RepoMode, UpdateGuard,
};
use ostrya_rt::block_on;

/// The update lock file, relative to the repository root.
const UPDATE_LOCK_FILE: &str = ".update.lock";

/// The environment variable that names the marker file of the umask child.
const UMASK_ENV: &str = "OSTRYA_TEST_UPDATE_GUARD_UMASK_CHILD";

#[test]
#[ignore = "helper process for the update guard tests"]
fn lock_holder_subprocess() {
    lock_holder_main();
}

#[test]
#[ignore = "helper process for the update guard tests"]
fn guard_holder_subprocess() {
    guard_holder_main();
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Create a repository in `mode` at `<tmp>/repo`, with the `[core]` lines
/// `core` appended, and return its path.
fn create(tmp: &TmpDir, mode: RepoMode, core: &str) -> PathBuf {
    let path = tmp.path().join("repo");
    block_on(Repo::create(&path, CreateOptions::new(mode))).unwrap();
    append_config(&path, core);
    path
}

/// Append `lines` to the config of the repository at `path`.
fn append_config(path: &Path, lines: &str) {
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(lines);
    std::fs::write(&config, text).unwrap();
}

/// Replace `lock-timeout-secs` in the config of the repository at `path`.
fn set_timeout(path: &Path, secs: i64) {
    let config = path.join("config");
    let text = std::fs::read_to_string(&config).unwrap();
    let mut kept: String = text
        .lines()
        .filter(|l| !l.starts_with("lock-timeout-secs="))
        .map(|l| format!("{l}\n"))
        .collect();
    kept.push_str(&format!("lock-timeout-secs={secs}\n"));
    std::fs::write(&config, kept).unwrap();
}

fn open(path: &Path) -> Repo {
    block_on(Repo::open(path)).unwrap()
}

fn checksum(byte: u8) -> Checksum {
    Checksum::from_bytes([byte; 32])
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// The mode a file created with request `0660` takes under the mask this
/// process runs with.
fn masked_lock_mode(dir: &Path) -> u32 {
    use std::os::unix::fs::OpenOptionsExt;
    let probe = dir.join("probe-file");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o660)
        .open(&probe)
        .unwrap();
    let mode = mode_of(&probe);
    std::fs::remove_file(&probe).unwrap();
    mode
}

fn assert_timeout<T: std::fmt::Debug>(result: ostrya::Result<T>) {
    let err = result.unwrap_err();
    assert!(matches!(err, Error::LockTimeout { secs: 0 }), "{err:?}");
}

/// Assert that both locks of a guard are free: a handle with
/// `lock-timeout-secs=0` takes the repository lock exclusive, and then the
/// update lock, at the first attempt.
async fn assert_locks_free(path: &Path) {
    let repo = Repo::open(path).await.unwrap();
    assert_eq!(repo.config().lock_timeout_secs().unwrap(), 0);
    let txn = repo
        .transaction_with_lock(LockKind::Exclusive)
        .await
        .expect("the repository lock is free");
    txn.abort().await.unwrap();
    let guard = repo.begin_update().await.expect("the update lock is free");
    guard.finish().await.unwrap();
}

/// The record locks that `/proc/locks` records for the process `pid` on the
/// inode `ino`, as their access words (`READ` or `WRITE`).
fn record_locks(pid: u32, ino: u64) -> Vec<String> {
    let pid = pid.to_string();
    let ino = ino.to_string();
    std::fs::read_to_string("/proc/locks")
        .unwrap()
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() > 5
                && fields[1] == "POSIX"
                && fields[4] == pid
                && fields[5].rsplit(':').next() == Some(ino.as_str()))
            .then(|| fields[3].to_owned())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The lock file.
// ---------------------------------------------------------------------------

/// The first `begin_update` creates `<repo>/.update.lock` with mode 0660
/// reduced by the umask, and the file stays after the guard and the handle go.
#[test]
fn the_lock_file_is_created_on_first_use_and_stays() {
    let tmp = TmpDir::new("guard-file");
    let path = create(&tmp, RepoMode::BareUser, "");
    let file = path.join(UPDATE_LOCK_FILE);
    let repo = open(&path);
    assert!(!file.exists(), "the open creates no lock file");

    let guard = block_on(repo.begin_update()).unwrap();
    assert!(std::fs::symlink_metadata(&file).unwrap().is_file());
    assert_eq!(mode_of(&file), masked_lock_mode(tmp.path()));
    block_on(guard.finish()).unwrap();
    drop(repo);
    assert!(file.exists(), "the lock file stays");
}

#[test]
fn an_existing_lock_file_keeps_its_mode() {
    let tmp = TmpDir::new("guard-file-existing");
    let path = create(&tmp, RepoMode::BareUserShared, "");
    let file = path.join(UPDATE_LOCK_FILE);
    std::fs::write(&file, b"").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let repo = open(&path);
    block_on(async { repo.begin_update().await.unwrap().finish().await.unwrap() });
    assert_eq!(mode_of(&file), 0o600);
}

/// In a `bare-user-shared` repository the lock file is 0660 under a umask of
/// 0077. The umask is a property of the process, so the check runs in a
/// child: this test binary re-executed for this test alone.
#[test]
fn a_shared_repository_forces_the_lock_file_mode() {
    if let Some(marker) = std::env::var_os(UMASK_ENV) {
        let marker = PathBuf::from(marker);
        rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
        let dir = marker.with_file_name("child");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(masked_lock_mode(&dir), 0o600, "umask 0077 applies");
        let path = dir.join("repo");
        block_on(async {
            let repo = Repo::create(&path, CreateOptions::new(RepoMode::BareUserShared))
                .await
                .unwrap();
            repo.begin_update().await.unwrap().finish().await.unwrap();
        });
        assert_eq!(mode_of(&path.join(UPDATE_LOCK_FILE)), 0o660);
        std::fs::write(marker, b"ran").unwrap();
        return;
    }
    let tmp = TmpDir::new("guard-file-shared");
    let marker = tmp.path().join("ran");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "a_shared_repository_forces_the_lock_file_mode",
            "--exact",
            "--nocapture",
        ])
        .env(UMASK_ENV, &marker)
        .status()
        .expect("re-execute this test binary");
    assert!(status.success(), "the child failed: {status}");
    // A name the filter does not match runs nothing and still exits 0, so
    // the marker is what proves the check ran.
    assert!(marker.exists(), "the child ran no check");
}

// ---------------------------------------------------------------------------
// Exclusion.
// ---------------------------------------------------------------------------

/// A guard that another process holds excludes this process: with
/// `lock-timeout-secs=0` a `begin_update` fails, and with `-1` it gets the
/// guard only after the holder released it.
#[test]
fn two_processes_serialize() {
    let tmp = TmpDir::new("guard-processes");
    let path = create(&tmp, RepoMode::BareUser, "");
    set_timeout(&path, 0);
    let no_wait = open(&path);
    set_timeout(&path, -1);
    let no_limit = open(&path);

    let holder = guard_holder(&path);
    assert_timeout(block_on(no_wait.begin_update()));

    // The releasing marker proves the order, so the release needs no delay.
    let release = std::thread::spawn(move || holder.release());
    let guard = block_on(no_limit.begin_update()).unwrap();
    assert!(
        path.join(GUARD_RELEASING_MARKER).exists(),
        "the guard came only after the release"
    );
    block_on(guard.finish()).unwrap();
    release.join().unwrap();
}

/// Two tasks of one process serialize and get the guard in the order of the
/// first poll of their calls. A call with `lock-timeout-secs=0` fails at once.
#[test]
fn two_tasks_serialize_in_first_poll_order() {
    let tmp = TmpDir::new("guard-tasks");
    let path = create(&tmp, RepoMode::BareUser, "");
    set_timeout(&path, 0);
    let no_wait = open(&path);
    set_timeout(&path, 30);
    let repo = open(&path);
    block_on(async {
        // The first call on a handle opens the lock file on the blocking pool
        // before it joins the queue, so the handles are used once first.
        repo.begin_update().await.unwrap().finish().await.unwrap();
        no_wait
            .begin_update()
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();

        let holder = repo.begin_update().await.unwrap();
        let mut x = Box::pin(repo.begin_update());
        let mut y = Box::pin(repo.begin_update());
        assert!(poll_once(&mut x).await.is_none(), "the first call waits");
        assert!(poll_once(&mut y).await.is_none(), "the second call waits");
        assert_timeout(no_wait.begin_update().await);
        holder.finish().await.unwrap();

        // Poll the second call first. It waits until the first releases.
        assert!(poll_once(&mut y).await.is_none(), "the second call waits");
        let first = x.await.unwrap();
        assert!(poll_once(&mut y).await.is_none(), "the second call waits");
        first.finish().await.unwrap();
        y.await.unwrap().finish().await.unwrap();
    });
}

/// A transaction takes the repository lock shared, so it opens and stages
/// objects while a guard is held.
#[test]
fn a_transaction_stages_while_a_guard_is_held() {
    let tmp = TmpDir::new("guard-transaction");
    let path = create(&tmp, RepoMode::BareUser, "lock-timeout-secs=0\n");
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let dirmeta = ostrya::DirMeta {
            uid: 0,
            gid: 0,
            mode: 0o40755,
            xattrs: Default::default(),
        }
        .serialize()
        .unwrap();
        txn.write_metadata(ObjectType::DirMeta, None, &dirmeta)
            .await
            .unwrap();
        txn.abort().await.unwrap();
        guard.finish().await.unwrap();
    });
}

/// A prune waits for a held guard: with `lock-timeout-secs=0` it fails while
/// the guard is held, and it runs once the guard is finished.
#[test]
fn a_prune_waits_for_a_held_guard() {
    let tmp = TmpDir::new("guard-prune");
    let path = create(&tmp, RepoMode::BareUser, "lock-timeout-secs=0\n");
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        assert_timeout(repo.prune(&PruneOptions::new()).await);
        guard.finish().await.unwrap();
        repo.prune(&PruneOptions::new()).await.unwrap();
    });
}

/// `begin_update` waits for a holder of the repository lock exclusive in this
/// process.
#[test]
fn begin_update_waits_for_an_exclusive_transaction() {
    let tmp = TmpDir::new("guard-exclusive");
    let path = create(&tmp, RepoMode::BareUser, "");
    set_timeout(&path, 0);
    let no_wait = open(&path);
    set_timeout(&path, 30);
    let repo = open(&path);
    block_on(async {
        let txn = repo
            .transaction_with_lock(LockKind::Exclusive)
            .await
            .unwrap();
        let mut waiting = Box::pin(repo.begin_update());
        assert!(poll_once(&mut waiting).await.is_none(), "the call waits");
        assert_timeout(no_wait.begin_update().await);
        txn.abort().await.unwrap();
        waiting.await.unwrap().finish().await.unwrap();
    });
}

/// `begin_update` waits for another process that holds `.lock` with an
/// exclusive record lock, as a prune of another process does.
#[test]
fn begin_update_waits_for_a_foreign_exclusive_lock() {
    let tmp = TmpDir::new("guard-foreign-lock");
    let path = create(&tmp, RepoMode::BareUser, "");
    set_timeout(&path, 0);
    let no_wait = open(&path);
    set_timeout(&path, 30);
    let repo = open(&path);

    let holder = foreign_holder(&path, ".lock");
    assert_timeout(block_on(no_wait.begin_update()));
    let started = Instant::now();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(holder);
    });
    let guard = block_on(repo.begin_update()).unwrap();
    assert!(started.elapsed() >= Duration::from_millis(300));
    block_on(guard.finish()).unwrap();
    release.join().unwrap();
}

/// With `[core] locking=false` the guard takes the update lock and no
/// repository lock: another process gets no guard, and the kernel records
/// the exclusive record lock of the holder on `.update.lock` and none on
/// `.lock`.
#[test]
fn locking_false_still_takes_the_update_lock() {
    let tmp = TmpDir::new("guard-locking-false");
    let path = create(
        &tmp,
        RepoMode::BareUser,
        "locking=false\nlock-timeout-secs=0\n",
    );
    // `.lock` exists, so an inode is there to hold no lock.
    std::fs::write(path.join(".lock"), b"").unwrap();
    let repo = open(&path);

    let holder = guard_holder(&path);
    assert_timeout(block_on(repo.begin_update()));
    let pid = holder.pid();
    let update_ino = std::fs::metadata(path.join(UPDATE_LOCK_FILE))
        .unwrap()
        .ino();
    let repo_ino = std::fs::metadata(path.join(".lock")).unwrap().ino();
    assert_eq!(record_locks(pid, update_ino), ["WRITE"]);
    assert!(record_locks(pid, repo_ino).is_empty(), "no lock on .lock");
    holder.release();
}

// ---------------------------------------------------------------------------
// Reads and writes.
// ---------------------------------------------------------------------------

/// Each write of the guard is visible to another handle while the guard is
/// held, and `read_config` returns the file `write_config` wrote while the
/// handle keeps the config it was opened with.
#[test]
fn the_writes_of_the_guard_are_visible_under_the_guard() {
    let tmp = TmpDir::new("guard-writes");
    let path = create(&tmp, RepoMode::BareUser, "");
    let repo = open(&path);
    let other = open(&path);
    let cref = CollectionRef::new("org.example.C", "app/main");
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        guard
            .set_ref("host/main", Some(&checksum(1)))
            .await
            .unwrap();
        guard
            .set_ref("origin:host/main", Some(&checksum(2)))
            .await
            .unwrap();
        guard
            .set_collection_ref(&cref, Some(&checksum(3)))
            .await
            .unwrap();
        guard.set_ref_alias("current", "host/main").await.unwrap();

        assert_eq!(
            other.resolve_ref_tip("host/main").await.unwrap(),
            Some(checksum(1))
        );
        assert_eq!(
            other.resolve_ref_tip("origin:host/main").await.unwrap(),
            Some(checksum(2))
        );
        assert_eq!(
            other.resolve_ref_tip("current").await.unwrap(),
            Some(checksum(1))
        );
        let mirrors = other.list_mirror_refs().await.unwrap();
        assert_eq!(
            mirrors,
            [(
                "org.example.C".to_owned(),
                "app/main".to_owned(),
                checksum(3)
            )]
        );
        let aliases = other.list_ref_aliases().await.unwrap();
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].refspec, "current");

        assert_eq!(guard.read_ref("current").await.unwrap(), Some(checksum(1)));
        assert_eq!(
            guard.read_collection_ref(&cref).await.unwrap(),
            Some(checksum(3))
        );
        assert_eq!(guard.read_ref("absent").await.unwrap(), None);

        let mut keyfile = guard.read_config().await.unwrap().keyfile().clone();
        keyfile
            .set_value("ex-test", "written", "under-the-guard")
            .unwrap();
        guard.write_config(&keyfile).await.unwrap();
        let read = guard.read_config().await.unwrap();
        assert_eq!(
            read.keyfile().get_value("ex-test", "written"),
            Some("under-the-guard")
        );
        assert_eq!(
            repo.config().keyfile().get_value("ex-test", "written"),
            None
        );

        guard.set_ref("host/main", None).await.unwrap();
        assert_eq!(other.resolve_ref_tip("host/main").await.unwrap(), None);
        guard.finish().await.unwrap();
    });
    let reopened = open(&path);
    assert_eq!(
        reopened.config().keyfile().get_value("ex-test", "written"),
        Some("under-the-guard")
    );
}

// ---------------------------------------------------------------------------
// Release.
// ---------------------------------------------------------------------------

/// `finish` returns the error of a directory sync, here of a recorded
/// directory that a regular file replaced, and it releases both locks.
#[test]
fn finish_returns_a_sync_error_and_releases_the_locks() {
    let tmp = TmpDir::new("guard-finish-error");
    let path = create(&tmp, RepoMode::BareUser, "lock-timeout-secs=0\n");
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        guard
            .set_ref("deep/main", Some(&checksum(1)))
            .await
            .unwrap();
        let dir = path.join("refs/heads/deep");
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, b"").unwrap();

        let err = guard.finish().await.unwrap_err();
        match &err {
            Error::Io(e) => assert_eq!(
                e.raw_os_error(),
                Some(rustix::io::Errno::NOTDIR.raw_os_error())
            ),
            other => panic!("expected ENOTDIR, got {other:?}"),
        }
        assert_locks_free(&path).await;
    });
}

/// A guard that drops without `finish` releases both locks.
#[test]
fn a_dropped_guard_releases_both_locks() {
    let tmp = TmpDir::new("guard-dropped");
    let path = create(&tmp, RepoMode::BareUser, "lock-timeout-secs=0\n");
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        guard.set_ref("main", Some(&checksum(1))).await.unwrap();
        drop(guard);
        assert_locks_free(&path).await;
    });
}

/// A `finish` future polled once and then dropped releases both locks, after
/// its syncs. The other handle waits for the locks, since the syncs can still
/// run on the blocking pool.
#[test]
fn a_dropped_finish_releases_both_locks() {
    let tmp = TmpDir::new("guard-finish-dropped");
    let path = create(&tmp, RepoMode::BareUser, "lock-timeout-secs=10\n");
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        guard.set_ref("a/main", Some(&checksum(1))).await.unwrap();
        let mut finish = Box::pin(guard.finish());
        let _ = poll_once(&mut finish).await;
        drop(finish);

        let other = Repo::open(&path).await.unwrap();
        let txn = other
            .transaction_with_lock(LockKind::Exclusive)
            .await
            .unwrap();
        txn.abort().await.unwrap();
        other.begin_update().await.unwrap().finish().await.unwrap();
    });
}

#[test]
fn the_guard_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<UpdateGuard>();
}
