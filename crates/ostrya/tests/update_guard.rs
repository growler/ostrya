//! Tests of `Repo::begin_update` and `UpdateGuard`. They cover the lock file,
//! the exclusion across processes and inside one process, and the lock order
//! against the repository lock. They also cover the reads and writes of the
//! guard, and the release rules of `finish` and of a guard that drops.

mod common;

use std::future::Future;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::Poll;
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
use rustix::process::{Flock, FlockType, Pid};

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

/// Creates a repository in `mode` at `<tmp>/repo`, appends the `[core]` lines
/// `core` to its config, and returns its path.
fn create(tmp: &TmpDir, mode: RepoMode, core: &str) -> PathBuf {
    let path = tmp.path().join("repo");
    block_on(Repo::create(&path, CreateOptions::new(mode))).unwrap();
    append_config(&path, core);
    path
}

/// Appends `lines` to the config of the repository at `path`.
fn append_config(path: &Path, lines: &str) {
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(lines);
    std::fs::write(&config, text).unwrap();
}

/// Sets `lock-timeout-secs` to `secs` in the config of the repository at
/// `path`.
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

/// Returns the mode of a file that this process creates in `dir` with the
/// requested mode `0660`, under the umask of this process.
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

/// Asserts that both locks of a guard are free. A handle with
/// `lock-timeout-secs=0` takes the repository lock exclusive and then the
/// update lock, each at the first attempt.
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

/// Returns the first record lock that another process holds on the file at
/// `path`, or `None` if no other process holds one.
///
/// The probe checks for a lock that conflicts with a write lock over the
/// whole file. It reports a read lock or a write lock of another process. It
/// does not report the classic record locks of this process.
///
/// The kernel answers from one consistent state. `/proc/locks` gives no
/// consistent state, because a reader reads it in several calls.
///
/// This process must hold no record lock on the file at the call. The close
/// of the probe descriptor drops each record lock of this process on the
/// file.
fn foreign_record_lock(path: &Path) -> Option<Flock> {
    let file = std::fs::File::open(path).unwrap();
    rustix::process::fcntl_getlk(&file, &Flock::from(FlockType::WriteLock)).unwrap()
}

// ---------------------------------------------------------------------------
// The lock file.
// ---------------------------------------------------------------------------

/// The first `begin_update` creates `<repo>/.update.lock` with mode 0660
/// reduced by the umask. The file stays after the guard and the handle drop.
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

/// In a `bare-user-shared` repository, the lock file gets mode 0660 under a
/// umask of 0077. The umask is a property of the process, so the check runs
/// in a child process. The child is this test binary, which runs this test
/// alone.
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
    // If the filter matches no test name, the child runs nothing and exits
    // 0. Only the marker proves that the check ran.
    assert!(marker.exists(), "the child ran no check");
}

// ---------------------------------------------------------------------------
// Exclusion.
// ---------------------------------------------------------------------------

/// A guard that another process holds excludes this process. With
/// `lock-timeout-secs=0`, a `begin_update` fails. With `-1`, it gets the
/// guard only after the holder releases it.
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
        // before it joins the queue, so the test uses each handle once first.
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

        // Poll the second call first. It waits until the first call releases
        // the guard.
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

/// A prune waits for a held guard. With `lock-timeout-secs=0`, the prune
/// fails while the guard is held. It runs after the guard finishes.
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

/// `begin_update` waits while a transaction of this process holds the
/// repository lock exclusive.
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

/// With `[core] locking=false`, the guard takes the update lock and no
/// repository lock. While another process holds the guard, this process gets
/// no guard. The kernel records the exclusive record lock of the holder on
/// `.update.lock` and no lock on `.lock`.
#[test]
fn locking_false_still_takes_the_update_lock() {
    let tmp = TmpDir::new("guard-locking-false");
    let path = create(
        &tmp,
        RepoMode::BareUser,
        "locking=false\nlock-timeout-secs=0\n",
    );
    // The test creates `.lock`, so the probe of `.lock` has an inode to check.
    std::fs::write(path.join(".lock"), b"").unwrap();
    let repo = open(&path);

    let holder = guard_holder(&path);
    assert_timeout(block_on(repo.begin_update()));
    // The `begin_update` attempt failed, and `locking=false` takes no
    // repository lock. As a result, this process holds no record lock on
    // either file, as `foreign_record_lock` requires. A write lock of the
    // holder over the whole file excludes any other lock of the holder on it.
    let whole_file_write_lock = Flock {
        pid: Pid::from_raw(holder.pid().try_into().unwrap()),
        ..Flock::from(FlockType::WriteLock)
    };
    assert_eq!(
        foreign_record_lock(&path.join(UPDATE_LOCK_FILE)),
        Some(whole_file_write_lock)
    );
    assert_eq!(
        foreign_record_lock(&path.join(".lock")),
        None,
        "no lock on .lock"
    );
    holder.release();
}

// ---------------------------------------------------------------------------
// Reads and writes.
// ---------------------------------------------------------------------------

/// Each write of the guard is visible to another handle while the guard is
/// held. `read_config` returns the file that `write_config` wrote. The handle
/// keeps the config that it read at open.
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

/// A guard of one handle reads the config that the guard of another handle
/// wrote. The first handle keeps the config that it read at open.
#[test]
fn a_guard_reads_the_config_another_handle_wrote() {
    let tmp = TmpDir::new("guard-config-other-handle");
    let path = create(&tmp, RepoMode::BareUser, "lock-timeout-secs=0\n");
    let a = open(&path);
    let b = open(&path);
    block_on(async {
        let guard = b.begin_update().await.unwrap();
        let mut keyfile = guard.read_config().await.unwrap().keyfile().clone();
        keyfile.set_value("ex-test", "written", "by-b").unwrap();
        guard.write_config(&keyfile).await.unwrap();
        guard.finish().await.unwrap();

        let guard = a.begin_update().await.unwrap();
        assert_eq!(
            guard
                .read_config()
                .await
                .unwrap()
                .keyfile()
                .get_value("ex-test", "written"),
            Some("by-b")
        );
        assert_eq!(a.config().keyfile().get_value("ex-test", "written"), None);
        guard.finish().await.unwrap();
    });
}

// ---------------------------------------------------------------------------
// Remotes.
// ---------------------------------------------------------------------------

/// Returns the name of the key-file group of the remote `name`.
fn group(name: &str) -> String {
    format!("remote \"{name}\"")
}

/// Returns the bytes and the inode of the config of the repository at `path`.
fn config_file(path: &Path) -> (Vec<u8>, u64) {
    let config = path.join("config");
    let ino = std::fs::metadata(&config).unwrap().ino();
    (std::fs::read(&config).unwrap(), ino)
}

/// Returns the keys of the remote `name` and their values, in file order, as
/// the config of the repository at `path` holds them on disk.
fn remote_keys(path: &Path, name: &str) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(path.join("config")).unwrap();
    let keyfile = ostrya_core::KeyFile::parse(&text).unwrap();
    let group = group(name);
    keyfile
        .keys(&group)
        .map(|k| {
            let value = keyfile.get_string(&group, k).unwrap().unwrap();
            (k.to_owned(), value)
        })
        .collect()
}

/// Adds the remote `name` with `keys` through a guard of its own.
fn add_remote(path: &Path, name: &str, keys: &[(&str, &str)]) {
    let repo = open(path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        guard.add_remote(name, keys).await.unwrap();
        guard.finish().await.unwrap();
    });
}

fn assert_invalid_input<T: std::fmt::Debug>(result: ostrya::Result<T>) {
    match result {
        Err(Error::InvalidInput(_)) => {}
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

fn assert_remote_not_found<T: std::fmt::Debug>(result: ostrya::Result<T>, name: &str) {
    match result {
        Err(Error::RemoteNotFound(n)) => assert_eq!(n, name),
        other => panic!("expected RemoteNotFound, got {other:?}"),
    }
}

/// A remote that a guard adds is in the config that a new open reads. Its
/// keys are in the given order. The guard escapes each value as the key file
/// escapes it, so a parse returns the given value.
#[test]
fn add_remote_writes_a_group_a_new_open_reads() {
    let tmp = TmpDir::new("guard-remote-add");
    let path = create(&tmp, RepoMode::BareUser, "");
    add_remote(
        &path,
        "origin",
        &[("url", "https://example.invalid/repo"), ("note", " a\nb")],
    );
    let repo = open(&path);
    assert_eq!(repo.config().remotes().collect::<Vec<_>>(), ["origin"]);
    assert_eq!(
        repo.config().remote("origin").unwrap().url().unwrap(),
        Some("https://example.invalid/repo".to_owned())
    );
    assert_eq!(
        remote_keys(&path, "origin"),
        [
            ("url".to_owned(), "https://example.invalid/repo".to_owned()),
            ("note".to_owned(), " a\nb".to_owned()),
        ]
    );
}

/// An add over a remote that exists fails with `RemoteExists` and leaves the
/// config file as it was, down to its inode.
#[test]
fn add_remote_over_an_existing_remote_writes_nothing() {
    let tmp = TmpDir::new("guard-remote-exists");
    let path = create(&tmp, RepoMode::BareUser, "");
    add_remote(&path, "origin", &[("url", "https://example.invalid/one")]);
    let before = config_file(&path);
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        match guard
            .add_remote("origin", &[("url", "https://example.invalid/two")])
            .await
        {
            Err(Error::RemoteExists(name)) => assert_eq!(name, "origin"),
            other => panic!("expected RemoteExists, got {other:?}"),
        }
        guard.finish().await.unwrap();
    });
    assert_eq!(config_file(&path), before);
}

/// An add refuses an empty key list and a name that the `ostree` command
/// refuses. An add and a set refuse a key name that the config cannot hold.
/// The calls write nothing.
#[test]
fn the_remote_calls_refuse_bad_names_and_keys() {
    let tmp = TmpDir::new("guard-remote-invalid");
    let path = create(&tmp, RepoMode::BareUser, "");
    add_remote(&path, "origin", &[("url", "https://example.invalid/repo")]);
    let before = config_file(&path);
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        for name in ["", "-", ".", "..", "a b", "a/b", "a+b"] {
            assert_invalid_input(guard.add_remote(name, &[("url", "u")]).await);
        }
        assert_invalid_input(guard.add_remote("fresh", &[]).await);
        for key in ["a=b", " k", "#k", ""] {
            assert_invalid_input(guard.add_remote("fresh", &[("url", "u"), (key, "v")]).await);
            assert_invalid_input(guard.set_remote_key("origin", key, "v").await);
        }
        guard.finish().await.unwrap();
    });
    assert_eq!(config_file(&path), before);
}

/// A set writes one key and leaves the other keys of the group as they were.
/// An unset removes one key. An unset of an absent key returns `false` and
/// leaves the config file as it was, down to its inode.
#[test]
fn set_and_unset_remote_key_edit_one_key() {
    let tmp = TmpDir::new("guard-remote-set");
    let path = create(&tmp, RepoMode::BareUser, "");
    add_remote(
        &path,
        "origin",
        &[
            ("url", "https://example.invalid/repo"),
            ("gpg-verify", "false"),
        ],
    );
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        guard
            .set_remote_key("origin", "url", "https://example.invalid/moved")
            .await
            .unwrap();
        guard
            .set_remote_key("origin", "branches", "main;")
            .await
            .unwrap();
        assert_eq!(
            remote_keys(&path, "origin"),
            [
                ("url".to_owned(), "https://example.invalid/moved".to_owned()),
                ("gpg-verify".to_owned(), "false".to_owned()),
                ("branches".to_owned(), "main;".to_owned()),
            ]
        );

        assert!(guard.unset_remote_key("origin", "url").await.unwrap());
        assert_eq!(
            remote_keys(&path, "origin"),
            [
                ("gpg-verify".to_owned(), "false".to_owned()),
                ("branches".to_owned(), "main;".to_owned()),
            ]
        );

        let before = config_file(&path);
        assert!(!guard.unset_remote_key("origin", "url").await.unwrap());
        assert_eq!(config_file(&path), before);
        guard.finish().await.unwrap();
    });
}

/// If the config has no remote of the name, a set and an unset fail with
/// `RemoteNotFound` and write nothing.
#[test]
fn set_and_unset_on_an_absent_remote_fail() {
    let tmp = TmpDir::new("guard-remote-set-absent");
    let path = create(&tmp, RepoMode::BareUser, "");
    let before = config_file(&path);
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        assert_remote_not_found(guard.set_remote_key("absent", "url", "u").await, "absent");
        assert_remote_not_found(guard.unset_remote_key("absent", "url").await, "absent");
        guard.finish().await.unwrap();
    });
    assert_eq!(config_file(&path), before);
}

/// A delete removes the group and the trusted keyring of the remote. A delete
/// of a remote that has no keyring also succeeds.
#[test]
fn delete_remote_removes_the_group_and_the_keyring() {
    let tmp = TmpDir::new("guard-remote-delete");
    let path = create(&tmp, RepoMode::BareUser, "");
    add_remote(&path, "keyed", &[("url", "https://example.invalid/keyed")]);
    add_remote(&path, "bare", &[("url", "https://example.invalid/bare")]);
    let keyring = path.join("keyed.trustedkeys.gpg");
    std::fs::write(&keyring, b"keys").unwrap();
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        guard.delete_remote("keyed").await.unwrap();
        assert!(!keyring.exists());
        guard.delete_remote("bare").await.unwrap();
        guard.finish().await.unwrap();
    });
    let reopened = open(&path);
    assert_eq!(reopened.config().remotes().count(), 0);
    assert!(!reopened.config().keyfile().has_group(&group("keyed")));
}

/// If the config has no remote of the name, a delete fails with
/// `RemoteNotFound` and removes no keyring. A delete of a name that the
/// `ostree` command refuses fails with `InvalidInput`.
#[test]
fn delete_remote_refuses_an_absent_remote_and_a_bad_name() {
    let tmp = TmpDir::new("guard-remote-delete-absent");
    let path = create(&tmp, RepoMode::BareUser, "");
    let stale = path.join("gone.trustedkeys.gpg");
    std::fs::write(&stale, b"keys").unwrap();
    let before = config_file(&path);
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        assert_remote_not_found(guard.delete_remote("gone").await, "gone");
        for name in ["", "..", "a/b", "../gone"] {
            assert_invalid_input(guard.delete_remote(name).await);
        }
        guard.finish().await.unwrap();
    });
    assert!(stale.exists());
    assert_eq!(config_file(&path), before);
}

/// Each guard reads the config on disk. If a handle opens before another
/// handle adds a remote, a guard of the first handle keeps that remote when it
/// adds its own.
#[test]
fn a_guard_adds_to_the_config_another_handle_wrote() {
    let tmp = TmpDir::new("guard-remote-two-handles");
    let path = create(&tmp, RepoMode::BareUser, "");
    let first = open(&path);
    add_remote(&path, "one", &[("url", "https://example.invalid/one")]);
    block_on(async {
        let guard = first.begin_update().await.unwrap();
        guard
            .add_remote("two", &[("url", "https://example.invalid/two")])
            .await
            .unwrap();
        guard.finish().await.unwrap();
    });
    let reopened = open(&path);
    assert_eq!(
        reopened.config().remotes().collect::<Vec<_>>(),
        ["one", "two"]
    );
}

/// Polls each future of `futures` in turn until all of them are ready, so
/// their blocking work runs at the same time.
async fn join_all(mut futures: Vec<Pin<Box<dyn Future<Output = ()> + '_>>>) {
    let mut done = vec![false; futures.len()];
    futures_lite::future::poll_fn(|cx| {
        let mut pending = false;
        for (future, done) in futures.iter_mut().zip(done.iter_mut()) {
            if !*done {
                match future.as_mut().poll(cx) {
                    Poll::Ready(()) => *done = true,
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
}

/// If the test polls eight adds on one guard together, each add keeps the
/// remotes that the other adds wrote.
#[test]
fn concurrent_adds_on_one_guard_lose_no_remote() {
    let tmp = TmpDir::new("guard-remote-concurrent-add");
    let path = create(&tmp, RepoMode::BareUser, "");
    let names: Vec<String> = (0..8).map(|i| format!("r{i}")).collect();
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        let adds = names
            .iter()
            .map(|name| {
                let guard = &guard;
                Box::pin(async move {
                    guard
                        .add_remote(name, &[("url", "https://example.invalid/repo")])
                        .await
                        .unwrap();
                }) as Pin<Box<dyn Future<Output = ()> + '_>>
            })
            .collect();
        join_all(adds).await;
        guard.finish().await.unwrap();
    });
    let reopened = open(&path);
    let mut remotes: Vec<&str> = reopened.config().remotes().collect();
    remotes.sort_unstable();
    assert_eq!(remotes, names);
}

/// If the test polls an add, a set, an unset, and a delete on one guard
/// together, each call keeps the edits of the other calls.
#[test]
fn concurrent_remote_calls_on_one_guard_keep_each_edit() {
    let tmp = TmpDir::new("guard-remote-concurrent-mix");
    let path = create(&tmp, RepoMode::BareUser, "");
    for name in ["set", "unset", "gone"] {
        add_remote(
            &path,
            name,
            &[("url", "https://example.invalid/repo"), ("note", "n")],
        );
    }
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        let edits = &guard;
        join_all(vec![
            Box::pin(async move {
                edits
                    .add_remote("added", &[("url", "https://example.invalid/added")])
                    .await
                    .unwrap();
            }),
            Box::pin(async move {
                edits.set_remote_key("set", "note", "m").await.unwrap();
            }),
            Box::pin(async move {
                assert!(edits.unset_remote_key("unset", "note").await.unwrap());
            }),
            Box::pin(async move {
                edits.delete_remote("gone").await.unwrap();
            }),
        ])
        .await;
        guard.finish().await.unwrap();
    });
    let url = ("url".to_owned(), "https://example.invalid/repo".to_owned());
    assert_eq!(
        remote_keys(&path, "set"),
        [url.clone(), ("note".to_owned(), "m".to_owned())]
    );
    assert_eq!(remote_keys(&path, "unset"), [url]);
    let reopened = open(&path);
    let mut remotes: Vec<&str> = reopened.config().remotes().collect();
    remotes.sort_unstable();
    assert_eq!(remotes, ["added", "set", "unset"]);
}

/// A delete removes the keyring before it writes the config. If the keyring
/// path is a directory, the delete fails. The config file stays as it was,
/// down to its inode.
#[test]
fn delete_remote_fails_on_the_keyring_before_it_writes_the_config() {
    let tmp = TmpDir::new("guard-remote-delete-order");
    let path = create(&tmp, RepoMode::BareUser, "");
    add_remote(&path, "origin", &[("url", "https://example.invalid/repo")]);
    std::fs::create_dir(path.join("origin.trustedkeys.gpg")).unwrap();
    let before = config_file(&path);
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        assert!(guard.delete_remote("origin").await.is_err());
        guard.finish().await.unwrap();
    });
    assert_eq!(config_file(&path), before);
    assert!(path.join("origin.trustedkeys.gpg").is_dir());
}

/// An add leaves a trusted keyring of the name as it was.
#[test]
fn add_remote_leaves_an_existing_keyring() {
    let tmp = TmpDir::new("guard-remote-add-keyring");
    let path = create(&tmp, RepoMode::BareUser, "");
    let keyring = path.join("origin.trustedkeys.gpg");
    std::fs::write(&keyring, b"keys").unwrap();
    add_remote(&path, "origin", &[("url", "https://example.invalid/repo")]);
    assert_eq!(std::fs::read(&keyring).unwrap(), b"keys");
}

/// A guard adds and then deletes a remote whose keyring name is too long for
/// a file name.
#[test]
fn a_remote_with_a_long_name_is_added_and_deleted() {
    let tmp = TmpDir::new("guard-remote-long-name");
    let path = create(&tmp, RepoMode::BareUser, "");
    let name = "a".repeat(250);
    add_remote(&path, &name, &[("url", "https://example.invalid/repo")]);
    let repo = open(&path);
    assert_eq!(repo.config().remotes().collect::<Vec<_>>(), [name.as_str()]);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        guard.delete_remote(&name).await.unwrap();
        guard.finish().await.unwrap();
    });
    assert!(!open(&path).config().keyfile().has_group(&group(&name)));
}

/// A set of the value that a key holds writes nothing. This is also true if
/// the file spells the value with an escape that a set does not write.
#[test]
fn set_remote_key_to_the_held_value_writes_nothing() {
    let tmp = TmpDir::new("guard-remote-set-same");
    let path = create(&tmp, RepoMode::BareUser, "");
    add_remote(&path, "origin", &[("url", "https://example.invalid/repo")]);
    append_config(&path, "branches=a\\;b\n");
    let before = config_file(&path);
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        guard
            .set_remote_key("origin", "url", "https://example.invalid/repo")
            .await
            .unwrap();
        guard
            .set_remote_key("origin", "branches", "a;b")
            .await
            .unwrap();
        guard.finish().await.unwrap();
    });
    assert_eq!(config_file(&path), before);
}

/// If the config parses a remote group name that a set refuses, the set fails
/// with the error of the key file. The set writes nothing.
#[test]
fn set_remote_key_passes_on_an_error_of_the_group() {
    let tmp = TmpDir::new("guard-remote-set-bad-group");
    let path = create(&tmp, RepoMode::BareUser, "");
    append_config(&path, "\n[remote \"a\rb\"]\nurl=x\n");
    let before = config_file(&path);
    let repo = open(&path);
    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        match guard.set_remote_key("a\rb", "url", "y").await {
            Err(Error::Core(_)) => {}
            other => panic!("expected Core, got {other:?}"),
        }
        guard.finish().await.unwrap();
    });
    assert_eq!(config_file(&path), before);
}

// ---------------------------------------------------------------------------
// Release.
// ---------------------------------------------------------------------------

/// `finish` returns the error of a directory sync and releases both locks.
/// In this test, the sync fails because a regular file replaced a recorded
/// directory.
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

/// If a `finish` future is polled once and then dropped, it releases both
/// locks after its syncs. The other handle waits for the locks, because the
/// syncs can still run on the blocking pool.
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
