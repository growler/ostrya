//! Integration tests of prune, fsck, traversal, and diff.
//!
//! The tests compare the reachability, prune, and diff results of ostrya with
//! the results of the `ostree` command:
//!
//! - ostrya and the `ostree` command prune identical repositories. They must
//!   keep the same objects and free the same number of bytes.
//! - The diff of ostrya must give the same result as `ostree diff`.
//! - A repository that ostrya prunes or leaves must pass `ostree fsck`.
//!
//! The fsck tests corrupt and delete objects. They check that ostrya finds
//! exactly the injected fault.

mod common;

use std::collections::HashSet;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{TmpDir, ostree_available};
use ostrya::{
    Checksum, CreateOptions, DiffChange, DiffEntry, FsckOptions, LockKind, ObjectName, ObjectType,
    Repo, RepoMode,
};
use ostrya_rt::block_on;

// ---------------------------------------------------------------------------
// Helpers that build repositories with the `ostree` command.
// ---------------------------------------------------------------------------

/// Runs the `ostree` command, asserts that it succeeds, and returns the trimmed
/// standard output.
fn ostree(args: &[&str]) -> String {
    let output = Command::new("ostree")
        .args(args)
        .output()
        .expect("run ostree");
    assert!(
        output.status.success(),
        "ostree {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// Runs the `ostree` command and returns its standard output and standard error
/// together, whatever the exit status.
fn ostree_output(args: &[&str]) -> String {
    let output = Command::new("ostree")
        .args(args)
        .output()
        .expect("run ostree");
    let mut s = String::from_utf8_lossy(&output.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&output.stderr));
    s
}

/// Writes a tree of one file at `dir`, with canonical permissions (0644 on the
/// file, 0755 on the directory).
fn write_tree(dir: &Path, name: &str, content: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(name), content).unwrap();
    std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Commits `src` to the branch `branch` of the repository at `repo` with the
/// `ostree` command, and returns the new commit checksum.
///
/// The commit sets the owner to 0:0 and records no xattrs.
fn tool_commit(repo: &Path, branch: &str, src: &Path) -> Checksum {
    let repo_arg = format!("--repo={}", repo.display());
    let hex = ostree(&[
        &repo_arg,
        "commit",
        "-b",
        branch,
        "-s",
        "c",
        "--owner-uid=0",
        "--owner-gid=0",
        "--no-xattrs",
        "--timestamp=@1700000000",
        src.to_str().unwrap(),
    ]);
    Checksum::from_hex(&hex).unwrap()
}

/// Creates an archive repository at `repo` with the `ostree` command.
fn tool_init(repo: &Path) {
    ostree(&[
        &format!("--repo={}", repo.display()),
        "init",
        "--mode=archive-z2",
    ]);
}

/// Copies a directory tree recursively and keeps its attributes.
fn copy_tree(from: &Path, to: &Path) {
    let status = Command::new("cp")
        .args(["-a"])
        .arg(from)
        .arg(to)
        .status()
        .expect("run cp");
    assert!(status.success(), "cp -a {from:?} {to:?} failed");
}

/// Returns the set of loose objects on disk, as paths relative to `objects/`.
fn disk_object_paths(repo: &Path) -> HashSet<String> {
    let mut out = HashSet::new();
    let objects = repo.join("objects");
    for fanout in std::fs::read_dir(&objects).unwrap() {
        let fanout = fanout.unwrap().path();
        if !fanout.is_dir() {
            continue;
        }
        let prefix = fanout.file_name().unwrap().to_string_lossy().into_owned();
        for entry in std::fs::read_dir(&fanout).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            out.insert(format!("{prefix}/{name}"));
        }
    }
    out
}

/// Builds the branch `m` of three commits (c1 <- c2 <- c3) in a new repository
/// with the `ostree` command, and returns the three commit checksums.
///
/// Each commit changes the same top-level file, so the history holds distinct
/// objects.
fn build_three_commit_repo(base: &Path, repo: &Path) -> [Checksum; 3] {
    tool_init(repo);
    let mut commits = Vec::new();
    for (i, content) in ["one\n", "two\n", "three\n"].iter().enumerate() {
        let src = base.join(format!("tree{i}"));
        write_tree(&src.join("sub"), "nested.txt", b"nested\n");
        write_tree(&src, "a.txt", content.as_bytes());
        commits.push(tool_commit(repo, "m", &src));
    }
    [commits[0], commits[1], commits[2]]
}

// ---------------------------------------------------------------------------
// Object listing and traversal.
// ---------------------------------------------------------------------------

#[test]
fn list_objects_matches_the_disk() {
    if !ostree_available() {
        eprintln!("skipping list_objects_matches_the_disk: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("maint-list");
    let repo = tmp.path().join("repo");
    build_three_commit_repo(tmp.path(), &repo);

    block_on(async {
        let handle = Repo::open(&repo).await.unwrap();
        let listed = handle.list_objects().await.unwrap();
        let listed_paths: HashSet<String> = listed
            .iter()
            .map(|o| o.loose_path(RepoMode::Archive))
            .collect();
        assert_eq!(
            listed_paths,
            disk_object_paths(&repo),
            "list_objects matches the loose objects on disk"
        );
    });
}

#[test]
fn traverse_commit_honors_depth() {
    if !ostree_available() {
        eprintln!("skipping traverse_commit_honors_depth: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("maint-traverse");
    let repo = tmp.path().join("repo");
    let [c1, c2, c3] = build_three_commit_repo(tmp.path(), &repo);

    block_on(async {
        let handle = Repo::open(&repo).await.unwrap();

        // Depth -1 (no limit) reaches every commit in the ancestry.
        let full = handle.traverse_commit(&c3, -1).await.unwrap();
        for c in [c1, c2, c3] {
            assert!(
                full.contains(&ObjectName::new(c, ObjectType::Commit)),
                "depth -1 reaches commit {c}"
            );
        }

        // Depth 0 reaches the head commit alone.
        let head_only = handle.traverse_commit(&c3, 0).await.unwrap();
        assert!(head_only.contains(&ObjectName::new(c3, ObjectType::Commit)));
        assert!(!head_only.contains(&ObjectName::new(c2, ObjectType::Commit)));
        assert!(!head_only.contains(&ObjectName::new(c1, ObjectType::Commit)));

        // Depth 1 reaches the head and its direct parent alone.
        let one = handle.traverse_commit(&c3, 1).await.unwrap();
        assert!(one.contains(&ObjectName::new(c3, ObjectType::Commit)));
        assert!(one.contains(&ObjectName::new(c2, ObjectType::Commit)));
        assert!(!one.contains(&ObjectName::new(c1, ObjectType::Commit)));

        // A traversal of an absent commit returns an error.
        let bogus = Checksum::from_hex(&"ab".repeat(32)).unwrap();
        assert!(handle.traverse_commit(&bogus, -1).await.is_err());
    });
}

#[test]
fn traverse_reachable_depth_is_order_independent() {
    let tmp = TmpDir::new("maint-traverse-order");
    block_on(async {
        let base = tmp.path();
        // Linear history c0 <- c1 <- c2 <- c3. The library builds it, so the
        // test does not need the `ostree` command.
        write_tree(&base.join("t0"), "a.txt", b"zero\n");
        write_tree(&base.join("t1"), "a.txt", b"one\n");
        write_tree(&base.join("t2"), "a.txt", b"two\n");
        write_tree(&base.join("t3"), "a.txt", b"three\n");
        let repo_dir = base.join("repo");
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let c0 = library_commit(&repo, base, "t0", None).await;
        let c1 = library_commit(&repo, base, "t1", Some(c0)).await;
        let c2 = library_commit(&repo, base, "t2", Some(c1)).await;
        let c3 = library_commit(&repo, base, "t3", Some(c2)).await;

        // The roots are c3 and c2 at depth 1, and c2 is the parent of c3. c1
        // is the parent of c2, so it is within depth 1 of the root c2. It must
        // be reachable for both orders of the two roots.
        let forward = repo.traverse_reachable([c3, c2], 1).await.unwrap();
        let reverse = repo.traverse_reachable([c2, c3], 1).await.unwrap();
        assert_eq!(
            forward, reverse,
            "the reachable set must not depend on root order"
        );
        assert!(
            forward.contains(&ObjectName::new(c1, ObjectType::Commit)),
            "c1 is within depth 1 of the c2 root, so it is reachable"
        );
        // c0 is two parents back from every root, so depth 1 does not reach it.
        assert!(
            !forward.contains(&ObjectName::new(c0, ObjectType::Commit)),
            "c0 is beyond depth 1 from every root"
        );
    });
}

// ---------------------------------------------------------------------------
// Prune.
// ---------------------------------------------------------------------------

/// Parses the deletion line of the prune output of the `ostree` command into
/// `(objects, bytes)`.
///
/// The deletion line is "Deleted N objects, S bytes freed" or "Would delete: N
/// objects, freeing S bytes". The function reads that line alone, so it ignores
/// the "Total objects:" line.
fn parse_prune_counts(output: &str) -> (usize, u64) {
    let line = output
        .lines()
        .find(|l| l.contains("Deleted") || l.contains("Would delete"))
        .expect("a deletion line in prune output");
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let objects = tokens
        .iter()
        .position(|t| t.starts_with("object"))
        .map(|i| tokens[i - 1].parse().unwrap())
        .expect("object count in prune output");
    let bytes = tokens
        .iter()
        .position(|t| t.starts_with("byte"))
        .map(|i| tokens[i - 1].parse().unwrap())
        .expect("byte count in prune output");
    (objects, bytes)
}

#[test]
fn prune_matches_the_tool_refs_only_depth_zero() {
    if !ostree_available() {
        eprintln!("skipping prune_matches_the_tool_refs_only_depth_zero: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("maint-prune");
    let tool_repo = tmp.path().join("tool");
    build_three_commit_repo(tmp.path(), &tool_repo);
    // An identical copy that ostrya prunes.
    let port_repo = tmp.path().join("port");
    copy_tree(&tool_repo, &port_repo);

    // The `ostree` command prunes its copy. The test keeps the counts that it
    // reports.
    let out = ostree_output(&[
        &format!("--repo={}", tool_repo.display()),
        "prune",
        "--refs-only",
        "--depth=0",
    ]);
    let (tool_objects, tool_bytes) = parse_prune_counts(&out);
    assert!(tool_objects > 0, "the tool prunes history at depth 0");

    let stats = block_on(async {
        let handle = Repo::open(&port_repo).await.unwrap();
        let opts = ostrya::PruneOptions {
            refs_only: true,
            depth: 0,
            ..ostrya::PruneOptions::new()
        };
        handle.prune(&opts).await.unwrap()
    });

    assert_eq!(
        stats.pruned_objects, tool_objects,
        "port and tool prune the same number of objects"
    );
    assert_eq!(
        stats.freed_bytes, tool_bytes,
        "port and tool free the same number of bytes"
    );
    assert_eq!(
        disk_object_paths(&port_repo),
        disk_object_paths(&tool_repo),
        "the surviving object sets are identical"
    );

    // The pruned repository still passes `ostree fsck`.
    let fsck = ostree_output(&[&format!("--repo={}", port_repo.display()), "fsck"]);
    assert!(
        fsck.contains("no errors found"),
        "tool fsck accepts the port-pruned repo: {fsck}"
    );
}

#[test]
fn prune_default_keeps_everything() {
    if !ostree_available() {
        eprintln!("skipping prune_default_keeps_everything: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("maint-prune-default");
    let repo = tmp.path().join("repo");
    build_three_commit_repo(tmp.path(), &repo);
    let before = disk_object_paths(&repo);

    let stats = block_on(async {
        let handle = Repo::open(&repo).await.unwrap();
        handle.prune(&ostrya::PruneOptions::new()).await.unwrap()
    });
    assert_eq!(stats.pruned_objects, 0, "default prune removes nothing");
    assert_eq!(stats.total_objects, before.len());
    assert_eq!(disk_object_paths(&repo), before, "no objects removed");
}

#[test]
fn prune_no_prune_is_a_dry_run() {
    if !ostree_available() {
        eprintln!("skipping prune_no_prune_is_a_dry_run: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("maint-prune-dry");
    let repo = tmp.path().join("repo");
    build_three_commit_repo(tmp.path(), &repo);
    let before = disk_object_paths(&repo);

    let stats = block_on(async {
        let handle = Repo::open(&repo).await.unwrap();
        let opts = ostrya::PruneOptions {
            refs_only: true,
            depth: 0,
            no_prune: true,
            ..ostrya::PruneOptions::new()
        };
        handle.prune(&opts).await.unwrap()
    });
    assert!(
        stats.pruned_objects > 0,
        "the dry run reports would-be deletions"
    );
    assert_eq!(
        disk_object_paths(&repo),
        before,
        "no_prune deletes nothing on disk"
    );
}

#[test]
fn prune_delete_commit_removes_it_and_orphans() {
    if !ostree_available() {
        eprintln!("skipping prune_delete_commit_removes_it_and_orphans: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("maint-delete-commit");
    let repo = tmp.path().join("repo");
    let [c1, _c2, _c3] = build_three_commit_repo(tmp.path(), &repo);

    block_on(async {
        let handle = Repo::open(&repo).await.unwrap();
        // c1 is an ancestor of the ref head. No ref names c1, so prune can
        // delete it.
        let opts = ostrya::PruneOptions {
            delete_commit: Some(c1),
            ..ostrya::PruneOptions::new()
        };
        handle.prune(&opts).await.unwrap();
        // The commit object is gone.
        assert!(
            !handle.has_object(ObjectType::Commit, &c1).await.unwrap(),
            "the deleted commit object is removed"
        );
    });

    // `ostree fsck` accepts the result.
    let fsck = ostree_output(&[&format!("--repo={}", repo.display()), "fsck"]);
    assert!(
        fsck.contains("no errors found"),
        "tool fsck accepts the repo after delete-commit: {fsck}"
    );
}

#[test]
fn prune_refuses_to_delete_a_referenced_commit() {
    if !ostree_available() {
        eprintln!("skipping prune_refuses_to_delete_a_referenced_commit: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("maint-delete-ref");
    let repo = tmp.path().join("repo");
    let [_c1, _c2, c3] = build_three_commit_repo(tmp.path(), &repo);

    block_on(async {
        let handle = Repo::open(&repo).await.unwrap();
        let opts = ostrya::PruneOptions {
            delete_commit: Some(c3), // the ref head
            ..ostrya::PruneOptions::new()
        };
        assert!(
            handle.prune(&opts).await.is_err(),
            "deleting a ref's target is refused"
        );
    });
}

// ---------------------------------------------------------------------------
// The repository lock between processes.
// ---------------------------------------------------------------------------

/// The environment variable that names the repository of the foreign-lock
/// helper.
const FOREIGN_LOCK_REPO: &str = "OSTRYA_FOREIGN_LOCK_REPO";

/// The `lock-timeout-secs` value of each lock test, in seconds. It limits the
/// time that a contended acquisition waits before it fails.
const LOCK_TIMEOUT_SECS: u64 = 1;

/// The maximum time of a readiness wait. After this time, the wait reports a
/// holder that never arrived.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// The interval of one readiness poll.
const READY_POLL: Duration = Duration::from_millis(20);

/// A spawned child that the guard kills and reaps when it drops.
///
/// A panic skips a reap at the end of a test. The child then keeps its hold on
/// the repository while the test removes the test directory. The guard ends the
/// child on every path out of the test.
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Appends `lock-timeout-secs` to the repository config.
///
/// The repository reads its config once at open, so this function runs before
/// the handle exists.
fn set_lock_timeout(repo: &Path, secs: u64) {
    let config = repo.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!("lock-timeout-secs={secs}\n"));
    std::fs::write(&config, text).unwrap();
}

/// Waits up to [`READY_TIMEOUT`] for `marker` to appear.
fn wait_for_marker(marker: &Path) -> bool {
    wait_until(|| marker.exists())
}

/// Waits up to [`READY_TIMEOUT`] for a staging directory to appear under
/// `<repo>/tmp`.
///
/// The `ostree` command creates one after it takes the repository, so the entry
/// shows that the `ostree` command holds its lock. Observed with ostree 2026.1:
/// a probe of `<repo>/.lock` reports the lock as held at every point where the
/// entry exists.
fn wait_for_tool_staging(repo: &Path) -> bool {
    wait_until(|| {
        let Ok(entries) = std::fs::read_dir(repo.join("tmp")) else {
            return false;
        };
        entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(TOOL_STAGING_PREFIX)
        })
    })
}

/// The prefix of the staging directory that the `ostree` command creates under
/// `tmp/`.
const TOOL_STAGING_PREFIX: &str = "staging-";

/// Polls `ready` until it returns `true` or [`READY_TIMEOUT`] elapses.
fn wait_until(mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if ready() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(READY_POLL);
    }
}

/// The prune of the `ostree` command waits on the repository lock that ostrya
/// holds, so the two exclude each other on one repository.
///
/// This process takes the lock exclusive through ostrya, and the `ostree`
/// command runs as a child. A record lock resolves this arrangement. The
/// elapsed wall clock time of the `ostree` run shows that it waited on the
/// lock, and did not fail for another reason.
///
/// The wording of the diagnostic of the `ostree` command is outside the scope
/// of this project. The other assertions cover the exit status and the object
/// inventory alone.
#[test]
fn the_tool_prune_waits_on_a_lock_the_port_holds() {
    if !ostree_available() {
        eprintln!("skipping the_tool_prune_waits_on_a_lock_the_port_holds: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("maint-lock-tool");
    let repo = tmp.path().join("repo");
    build_three_commit_repo(tmp.path(), &repo);
    set_lock_timeout(&repo, LOCK_TIMEOUT_SECS);

    let before = disk_object_paths(&repo);

    block_on(async {
        let handle = Repo::open(&repo).await.unwrap();
        let txn = handle
            .transaction_with_lock(LockKind::Exclusive)
            .await
            .unwrap();

        let started = Instant::now();
        let out = Command::new("ostree")
            .args([
                &format!("--repo={}", repo.display()),
                "prune",
                "--refs-only",
                "--depth=0",
            ])
            .output()
            .expect("run ostree");
        let waited = started.elapsed();
        assert!(
            !out.status.success(),
            "the tool's prune fails while the port holds the lock"
        );
        assert!(
            waited >= Duration::from_secs(LOCK_TIMEOUT_SECS),
            "the tool ran for {waited:?}, short of the configured timeout, so it \
             did not wait on the lock"
        );

        txn.abort().await.unwrap();
    });

    assert_eq!(
        disk_object_paths(&repo),
        before,
        "the refused tool prune removed no object"
    );
}

/// The prune of ostrya waits on the repository that the `ostree` command holds.
/// This is the other side of the exclusion between the two.
///
/// The `ostree` command commits a tar tree that it reads from its standard
/// input. It takes the repository lock and creates its staging directory before
/// it reads the first byte. While its standard input stays open and silent, the
/// child holds the repository for as long as the test needs.
#[test]
fn prune_waits_while_the_tool_holds_the_repository() {
    if !ostree_available() {
        eprintln!("skipping prune_waits_while_the_tool_holds_the_repository: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("maint-lock-port");
    let repo = tmp.path().join("repo");
    build_three_commit_repo(tmp.path(), &repo);
    set_lock_timeout(&repo, LOCK_TIMEOUT_SECS);

    let before = disk_object_paths(&repo);

    let holder = ChildGuard(
        Command::new("ostree")
            .args([
                &format!("--repo={}", repo.display()),
                "commit",
                "-b",
                "held",
                "-s",
                "held",
                "--tree=tar=-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the tool"),
    );
    assert!(
        wait_for_tool_staging(&repo),
        "the tool never took the repository"
    );

    let (err, waited) = block_on(async {
        let handle = Repo::open(&repo).await.unwrap();
        let started = Instant::now();
        let err = handle
            .prune(&ostrya::PruneOptions::new())
            .await
            .expect_err("a prune fails while the tool holds the repository");
        (err, started.elapsed())
    });
    assert!(
        matches!(err, ostrya::Error::LockTimeout { secs: 1 }),
        "the contended prune reports the configured timeout: {err:?}"
    );
    assert!(
        waited >= Duration::from_secs(LOCK_TIMEOUT_SECS),
        "the prune returned after {waited:?}, short of the configured timeout"
    );

    drop(holder);
    assert_eq!(
        disk_object_paths(&repo),
        before,
        "the refused prune removed no object"
    );
}

/// The prune of ostrya waits on a repository lock that another process holds.
/// After `lock-timeout-secs`, it fails with [`ostrya::Error::LockTimeout`].
///
/// The holder is this test binary, run again as a child. It takes an `fcntl`
/// exclusive record lock on `<repo>/.lock`, the lock space that the library and
/// the `ostree` command share. The helper keeps the lock until its standard
/// input closes, so the hold covers every assertion of this test. The guard
/// ends the hold.
#[test]
fn prune_waits_on_a_foreign_lock_holder() {
    let tmp = TmpDir::new("maint-lock-foreign");
    let repo = tmp.path().join("repo");
    block_on(Repo::create(
        &repo,
        ostrya::CreateOptions::new(RepoMode::Archive),
    ))
    .unwrap();
    set_lock_timeout(&repo, LOCK_TIMEOUT_SECS);

    let marker = repo.join(FOREIGN_LOCK_MARKER);
    let holder = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "foreign_lock_holder_subprocess",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env(FOREIGN_LOCK_REPO, &repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the foreign lock holder"),
    );
    assert!(wait_for_marker(&marker), "the holder never took the lock");

    let (err, waited) = block_on(async {
        let handle = Repo::open(&repo).await.unwrap();
        let started = Instant::now();
        let err = handle
            .prune(&ostrya::PruneOptions::new())
            .await
            .expect_err("a prune under a foreign lock fails");
        (err, started.elapsed())
    });
    assert!(
        matches!(err, ostrya::Error::LockTimeout { secs: 1 }),
        "the contended prune reports the configured timeout: {err:?}"
    );
    assert!(
        waited >= Duration::from_secs(LOCK_TIMEOUT_SECS),
        "the prune returned after {waited:?}, short of the configured timeout"
    );

    drop(holder);
}

/// The file that the foreign-lock helper writes after it takes the lock.
const FOREIGN_LOCK_MARKER: &str = ".foreign-held";

/// The lock-holder half of [`prune_waits_on_a_foreign_lock_holder`].
///
/// If [`FOREIGN_LOCK_REPO`] is not set, the test returns at once. The parent
/// test sets it when it runs this test binary again as a child. The helper
/// takes an `fcntl` exclusive record lock on `<repo>/.lock` and writes
/// [`FOREIGN_LOCK_MARKER`]. It keeps the lock until its standard input closes.
#[test]
#[ignore = "helper process for prune_waits_on_a_foreign_lock_holder"]
fn foreign_lock_holder_subprocess() {
    use rustix::fs::{FlockOperation, Mode, OFlags};
    use std::io::Read;

    let Ok(repo) = std::env::var(FOREIGN_LOCK_REPO) else {
        return;
    };

    let repo = Path::new(&repo);
    let fd = rustix::fs::open(
        repo.join(".lock"),
        OFlags::RDWR | OFlags::CREATE,
        Mode::from_raw_mode(0o660),
    )
    .expect("open the lock file");
    rustix::fs::fcntl_lock(&fd, FlockOperation::LockExclusive).expect("take the record lock");
    std::fs::write(repo.join(FOREIGN_LOCK_MARKER), b"1").expect("write the readiness marker");

    // The parent holds the write half of this pipe while it needs the lock.
    // The read returns when the parent ends the child or exits.
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}

// ---------------------------------------------------------------------------
// fsck.
// ---------------------------------------------------------------------------

/// Creates an archive repository with the library, commits a small source tree
/// to `main`, and returns the repository and the commit.
///
/// The tree holds `hello.txt`, `sub/nested.txt`, and the symlink `link`.
async fn build_library_repo(base: &Path) -> (Repo, Checksum) {
    use ostrya::{CommitModifier, CommitModifierFlags, CommitOptions, MutableTree};
    use std::os::fd::AsFd;

    let src = base.join("src");
    write_tree(&src.join("sub"), "nested.txt", b"nested\n");
    write_tree(&src, "hello.txt", b"hello ostree\n");
    std::os::unix::fs::symlink("hello.txt", src.join("link")).unwrap();

    let repo_dir = base.join("repo");
    let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    );
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new("src"),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("c".to_owned()),
                timestamp: Some(1_700_000_000),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("main", Some(&commit));
    txn.commit().await.unwrap();
    (repo, commit)
}

/// Commits the tree at `base/rel` with the parent `parent` to the branch `main`
/// of `repo`, and returns the new commit.
///
/// The commit uses canonical permissions and records no xattrs.
async fn library_commit(repo: &Repo, base: &Path, rel: &str, parent: Option<Checksum>) -> Checksum {
    use ostrya::{CommitModifier, CommitModifierFlags, CommitOptions, MutableTree};
    use std::os::fd::AsFd;

    let txn = repo.transaction().await.unwrap();
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    );
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new(rel), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                parent,
                subject: Some("c".to_owned()),
                timestamp: Some(1_700_000_000),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("main", Some(&commit));
    txn.commit().await.unwrap();
    commit
}

#[test]
fn fsck_passes_on_a_healthy_repo() {
    let tmp = TmpDir::new("maint-fsck-ok");
    block_on(async {
        let (repo, commit) = build_library_repo(tmp.path()).await;
        let report = repo.fsck(&FsckOptions::new()).await.unwrap();
        assert!(report.is_ok(), "healthy fsck: {:?}", report.errors);
        assert_eq!(report.commits_checked, 1);
        // fsck checks every reachable object.
        let reachable = repo.traverse_commit(&commit, -1).await.unwrap();
        assert_eq!(report.objects_checked, reachable.len());

        // Detached commit metadata is outside the count. It raises the count of
        // loose objects and leaves `objects_checked` unchanged. The total that
        // `ostree fsck` prints also excludes detached commit metadata.
        let detached = tmp
            .path()
            .join("repo/objects")
            .join(ObjectName::new(commit, ObjectType::CommitMeta).loose_path(RepoMode::Archive));
        std::fs::write(&detached, [0x61, 0x7b, 0x73, 0x76, 0x7d, 0x00]).unwrap();
        let again = repo.fsck(&FsckOptions::new()).await.unwrap();
        assert!(again.is_ok(), "healthy fsck: {:?}", again.errors);
        assert_eq!(again.objects_checked, reachable.len());
    });
}

#[test]
fn fsck_refuses_a_ref_symlink_naming_a_directory() {
    // fsck and prune start from the refs. The ref walk reads a symlink as an
    // alias and does not descend into it. If a link names a directory, the
    // read fails with EISDIR. The `ostree` command gives the same refusal,
    // `Listing refs: Is a directory`. Without this rule, a self-link recurses
    // without end.
    let tmp = TmpDir::new("maint-fsck-dirlink");
    block_on(async {
        let (repo, _commit) = build_library_repo(tmp.path()).await;
        let heads = tmp.path().join("repo/refs/heads");
        std::os::unix::fs::symlink(".", heads.join("selfdir")).unwrap();
        let err = repo.fsck(&FsckOptions::new()).await.unwrap_err();
        assert!(
            err.to_string().contains("Is a directory"),
            "fsck is refused, got {err}"
        );
        let err = repo.prune(&ostrya::PruneOptions::new()).await.unwrap_err();
        assert!(
            err.to_string().contains("Is a directory"),
            "prune is refused, got {err}"
        );
    });
}

#[test]
fn fsck_detects_content_corruption() {
    let tmp = TmpDir::new("maint-fsck-content");
    block_on(async {
        let (repo, _commit) = build_library_repo(tmp.path()).await;
        // Corrupt a content object in place.
        let repo_dir = tmp.path().join("repo");
        let filez = find_object(&repo_dir, "filez").expect("a .filez object");
        std::fs::write(&filez, b"corrupted payload bytes").unwrap();

        let report = repo.fsck(&FsckOptions::new()).await.unwrap();
        assert!(!report.is_ok(), "corruption is detected");
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.object.ty == ObjectType::File),
            "a content-object fault is reported: {:?}",
            report.errors
        );
    });
}

#[test]
fn fsck_detects_metadata_corruption() {
    let tmp = TmpDir::new("maint-fsck-meta");
    block_on(async {
        let (repo, _commit) = build_library_repo(tmp.path()).await;
        let repo_dir = tmp.path().join("repo");
        let dirtree = find_object(&repo_dir, "dirtree").expect("a .dirtree object");
        // Append a byte so the checksum no longer matches the name.
        let mut bytes = std::fs::read(&dirtree).unwrap();
        bytes.push(0);
        std::fs::write(&dirtree, &bytes).unwrap();

        let report = repo.fsck(&FsckOptions::new()).await.unwrap();
        assert!(
            report.errors.iter().any(|e| matches!(
                e.kind,
                ostrya::FsckErrorKind::ChecksumMismatch { .. }
            ) && e.object.ty == ObjectType::DirTree),
            "a dirtree checksum mismatch is reported: {:?}",
            report.errors
        );
    });
}

#[test]
fn fsck_detects_missing_object_and_marks_partial() {
    let tmp = TmpDir::new("maint-fsck-missing");
    block_on(async {
        let (repo, commit) = build_library_repo(tmp.path()).await;
        let repo_dir = tmp.path().join("repo");
        let filez = find_object(&repo_dir, "filez").expect("a .filez object");
        std::fs::remove_file(&filez).unwrap();

        let report = repo.fsck(&FsckOptions::new()).await.unwrap();
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e.kind, ostrya::FsckErrorKind::Missing)),
            "a missing object is reported: {:?}",
            report.errors
        );
        // fsck marks the commit partial.
        assert_eq!(
            repo.commit_state(&commit).await.unwrap(),
            ostrya::CommitState::Partial,
            "the commit is marked partial after a missing object"
        );
        // The marker holds the single state byte that the `ostree` command
        // writes.
        let marker = repo_dir.join(format!("state/{}.commitpartial", commit.to_hex()));
        assert_eq!(std::fs::read(&marker).unwrap(), vec![0x66]);
    });
}

#[test]
fn fsck_mark_partial_can_be_disabled() {
    let tmp = TmpDir::new("maint-fsck-nomark");
    block_on(async {
        let (repo, commit) = build_library_repo(tmp.path()).await;
        let repo_dir = tmp.path().join("repo");
        std::fs::remove_file(find_object(&repo_dir, "filez").unwrap()).unwrap();

        let report = repo
            .fsck(&FsckOptions {
                mark_partial: false,
                ..FsckOptions::new()
            })
            .await
            .unwrap();
        assert!(!report.is_ok());
        assert_eq!(
            repo.commit_state(&commit).await.unwrap(),
            ostrya::CommitState::Normal,
            "no marker is written when mark_partial is off"
        );
    });
}

#[test]
fn fsck_marks_every_commit_sharing_a_missing_subtree() {
    let tmp = TmpDir::new("maint-fsck-shared");
    block_on(async {
        let base = tmp.path();
        // Two commits that differ at the top level and share an identical
        // `sub/` subtree. Both reference the same `sub/` dirtree and the same
        // nested content object.
        write_tree(&base.join("one/sub"), "nested.txt", b"nested\n");
        write_tree(&base.join("one"), "a.txt", b"one\n");
        write_tree(&base.join("two/sub"), "nested.txt", b"nested\n");
        write_tree(&base.join("two"), "a.txt", b"two\n");

        let repo_dir = base.join("repo");
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let c1 = library_commit(&repo, base, "one", None).await;
        let c2 = library_commit(&repo, base, "two", Some(c1)).await;

        // The one content object that both commits reach is the shared
        // nested.txt. The test deletes it, so both commits are incomplete.
        let r1 = repo.traverse_commit(&c1, 0).await.unwrap();
        let r2 = repo.traverse_commit(&c2, 0).await.unwrap();
        let shared = r1
            .intersection(&r2)
            .find(|o| o.ty == ObjectType::File)
            .copied()
            .expect("a file object shared by both commits");
        std::fs::remove_file(
            repo_dir
                .join("objects")
                .join(shared.loose_path(RepoMode::Archive)),
        )
        .unwrap();

        let report = repo.fsck(&FsckOptions::new()).await.unwrap();
        assert!(!report.is_ok(), "the missing shared object is detected");
        // Both commits reference the missing object, so both are partial.
        assert_eq!(
            repo.commit_state(&c1).await.unwrap(),
            ostrya::CommitState::Partial,
            "the first commit is marked partial"
        );
        assert_eq!(
            repo.commit_state(&c2).await.unwrap(),
            ostrya::CommitState::Partial,
            "the second commit is marked partial"
        );
    });
}

#[test]
fn fsck_marks_commits_sharing_a_missing_file_via_distinct_dirs() {
    let tmp = TmpDir::new("maint-fsck-shared-file");
    block_on(async {
        let base = tmp.path();
        // Two commits whose `dir/` differs, so the dirtrees that hold it
        // differ. Both commits hold an identical `dir/shared.txt`, so two
        // distinct dirtrees reach the same content object. No dirtree is common
        // to the two commits. fsck must report the missing object once and mark
        // both commits partial.
        write_tree(&base.join("one/dir"), "shared.txt", b"data\n");
        write_tree(&base.join("one/dir"), "other.txt", b"a\n");
        write_tree(&base.join("two/dir"), "shared.txt", b"data\n");
        write_tree(&base.join("two/dir"), "other.txt", b"b\n");

        let repo_dir = base.join("repo");
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let c1 = library_commit(&repo, base, "one", None).await;
        let c2 = library_commit(&repo, base, "two", Some(c1)).await;

        let r1 = repo.traverse_commit(&c1, 0).await.unwrap();
        let r2 = repo.traverse_commit(&c2, 0).await.unwrap();
        let shared = r1
            .intersection(&r2)
            .find(|o| o.ty == ObjectType::File)
            .copied()
            .expect("a file object shared by both commits");
        std::fs::remove_file(
            repo_dir
                .join("objects")
                .join(shared.loose_path(RepoMode::Archive)),
        )
        .unwrap();

        let report = repo.fsck(&FsckOptions::new()).await.unwrap();
        // fsck reports the shared missing file exactly once.
        assert_eq!(
            report
                .errors
                .iter()
                .filter(|e| matches!(e.kind, ostrya::FsckErrorKind::Missing))
                .count(),
            1,
            "the missing file is reported once: {:?}",
            report.errors
        );
        assert_eq!(
            repo.commit_state(&c1).await.unwrap(),
            ostrya::CommitState::Partial,
            "the first commit is marked partial"
        );
        assert_eq!(
            repo.commit_state(&c2).await.unwrap(),
            ostrya::CommitState::Partial,
            "the second commit is marked partial"
        );
    });
}

/// Builds the branch `main` of two commits in a new repository of `mode`, and
/// returns the repository and the two commits.
///
/// The first commit is the parent of the second.
async fn build_two_commit_repo(base: &Path, mode: RepoMode) -> (Repo, Checksum, Checksum) {
    write_tree(&base.join("one"), "a.txt", b"one\n");
    write_tree(&base.join("two"), "a.txt", b"two\n");
    let repo = Repo::create(&base.join("repo"), CreateOptions::new(mode))
        .await
        .unwrap();
    let c1 = library_commit(&repo, base, "one", None).await;
    let c2 = library_commit(&repo, base, "two", Some(c1)).await;
    (repo, c1, c2)
}

/// Commits the tree at `base/rel` with `metadata` as the metadata dict of the
/// commit, and returns the new commit.
///
/// The function sets no ref to the commit.
async fn commit_with_metadata(
    repo: &Repo,
    base: &Path,
    rel: &str,
    metadata: ostrya::Value,
) -> Checksum {
    use ostrya::{CommitModifier, CommitModifierFlags, CommitOptions, MutableTree};
    use std::os::fd::AsFd;

    let txn = repo.transaction().await.unwrap();
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    );
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new(rel), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("c".to_owned()),
                timestamp: Some(1_700_000_000),
                metadata: Some(metadata),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.commit().await.unwrap();
    commit
}

/// Returns a metadata dict with an `ostree.ref-binding` entry.
///
/// If `collection` is `Some`, the dict also holds an
/// `ostree.collection-binding` entry.
fn binding_metadata(refs: &[&str], collection: Option<&str>) -> ostrya::Value {
    let names: Vec<String> = refs.iter().map(|r| (*r).to_owned()).collect();
    let mut builder = ostrya::DictBuilder::new();
    builder.insert_strv("ostree.ref-binding", &names);
    if let Some(collection) = collection {
        builder.insert_str("ostree.collection-binding", collection);
    }
    builder.build()
}

#[test]
fn fsck_skips_a_commit_already_marked_partial() {
    let tmp = TmpDir::new("maint-fsck-skip-partial");
    block_on(async {
        let base = tmp.path();
        let (repo, _c1, c2) = build_two_commit_repo(base, RepoMode::Archive).await;

        let both = repo.fsck(&FsckOptions::new()).await.unwrap();
        assert_eq!(both.commits_checked, 2);
        assert_eq!(both.commits_partial, 0);
        assert!(both.is_ok());

        // The test marks the tip partial by hand. An interrupted pull leaves
        // the same marker.
        let marker = base.join(format!("repo/state/{}.commitpartial", c2.to_hex()));
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, [0x66]).unwrap();

        let skipped = repo.fsck(&FsckOptions::new()).await.unwrap();
        assert_eq!(skipped.commits_checked, 1, "the partial commit is skipped");
        assert_eq!(skipped.commits_partial, 1);
        assert!(
            skipped.objects_checked < both.objects_checked,
            "the skipped commit's objects leave the denominator: {} against {}",
            skipped.objects_checked,
            both.objects_checked
        );
        assert!(!skipped.is_ok(), "a skipped commit is not a clean run");
    });
}

#[test]
fn fsck_delete_unlinks_and_marks() {
    let tmp = TmpDir::new("maint-fsck-delete");
    block_on(async {
        let base = tmp.path();
        let (repo, c1, c2) = build_two_commit_repo(base, RepoMode::Archive).await;
        let repo_dir = base.join("repo");

        // The test corrupts the content object of each commit. The run then
        // has two faults to carry, and each commit reaches one.
        let mut corrupted = Vec::new();
        for name in [c1, c2] {
            let reachable = repo.traverse_commit(&name, 0).await.unwrap();
            let object = reachable
                .iter()
                .find(|o| o.ty == ObjectType::File)
                .copied()
                .expect("a content object");
            let path = repo_dir
                .join("objects")
                .join(object.loose_path(RepoMode::Archive));
            std::fs::write(&path, b"not the object these bytes are named for").unwrap();
            corrupted.push(object);
        }

        // The walk runs to its end with each set of options, so a default run
        // reports both faults. It unlinks nothing and marks nothing. A checksum
        // mismatch alone leaves the commit complete.
        let plain = repo.fsck(&FsckOptions::new()).await.unwrap();
        assert_eq!(
            plain.errors.len(),
            2,
            "the walk carries past the first fault: {:?}",
            plain.errors
        );
        assert!(plain.deleted.is_empty() && plain.marked_partial.is_empty());

        let report = repo
            .fsck(&FsckOptions {
                delete: true,
                ..FsckOptions::new()
            })
            .await
            .unwrap();
        assert_eq!(
            report.errors.len(),
            2,
            "`delete` continues past the first fault: {:?}",
            report.errors
        );
        for object in &corrupted {
            assert!(report.deleted.contains(object), "{object} was unlinked");
            assert!(
                !repo_dir
                    .join("objects")
                    .join(object.loose_path(RepoMode::Archive))
                    .exists(),
                "{object} is gone from the store"
            );
        }
        assert_eq!(report.marked_partial, {
            let mut expected = vec![c1, c2];
            expected.sort();
            expected
        });
        for commit in [c1, c2] {
            assert_eq!(
                repo.commit_state(&commit).await.unwrap(),
                ostrya::CommitState::Partial
            );
        }
    });
}

#[test]
fn fsck_add_tombstones_replaces_the_commit() {
    // `bare` records the owner of the source inode, which an unprivileged run
    // cannot write. The three modes here are the modes that the suite commits
    // in.
    for mode in [
        RepoMode::BareUser,
        RepoMode::BareUserOnly,
        RepoMode::Archive,
    ] {
        let tmp = TmpDir::new("maint-fsck-tombstone");
        block_on(async {
            let base = tmp.path();
            let (repo, c1, c2) = build_two_commit_repo(base, mode).await;
            let repo_dir = base.join("repo");

            // The test removes the parent commit object. The option acts on
            // this condition.
            let parent = repo_dir
                .join("objects")
                .join(ObjectName::new(c1, ObjectType::Commit).loose_path(mode));
            std::fs::remove_file(&parent).unwrap();

            let report = repo
                .fsck(&FsckOptions {
                    add_tombstones: true,
                    ..FsckOptions::new()
                })
                .await
                .unwrap();
            assert_eq!(report.tombstoned, vec![c2], "the child is tombstoned");

            let commit_path = repo_dir
                .join("objects")
                .join(ObjectName::new(c2, ObjectType::Commit).loose_path(mode));
            assert!(!commit_path.exists(), "the child commit object is gone");

            let tombstone = repo_dir
                .join("objects")
                .join(ObjectName::new(c2, ObjectType::TombstoneCommit).loose_path(mode));
            let bytes = std::fs::read(&tombstone).unwrap();
            assert_eq!(bytes.len(), 78, "the marker is 78 bytes in {mode:?}");
            let mut expected = b"commit\0\0".to_vec();
            expected.extend_from_slice(c2.to_hex().as_bytes());
            assert!(
                bytes.starts_with(&expected),
                "the marker names the commit in {mode:?}"
            );
            let meta = std::fs::metadata(&tombstone).unwrap();
            assert_eq!(
                std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777,
                0o644,
                "the marker's permission bits in {mode:?}"
            );
        });
    }
}

/// The tombstone step writes to the repository. If the walk found a corrupt
/// object, the step runs under `all` or `delete` alone. An absent object leaves
/// the walk sound for this purpose, so the step runs.
#[test]
fn fsck_add_tombstones_needs_a_walk_that_found_no_corruption() {
    // Each arm acts on the repository, so each arm gets a repository of its
    // own. `name` names the arm, `corrupt` selects the fault to plant, and
    // `opts` holds the switches under test.
    let arm = |name: &str, corrupt: bool, opts: FsckOptions| {
        let tmp = TmpDir::new(name);
        block_on(async {
            let base = tmp.path();
            let (repo, c1, c2) = build_two_commit_repo(base, RepoMode::Archive).await;
            let objects = base.join("repo").join("objects");
            std::fs::remove_file(
                objects.join(ObjectName::new(c1, ObjectType::Commit).loose_path(RepoMode::Archive)),
            )
            .unwrap();

            let reachable = repo.traverse_commit(&c2, 0).await.unwrap();
            let object = reachable
                .iter()
                .find(|o| o.ty == ObjectType::File)
                .copied()
                .expect("a content object");
            let path = objects.join(object.loose_path(RepoMode::Archive));
            if corrupt {
                std::fs::write(&path, b"not the object these bytes are named for").unwrap();
            } else {
                std::fs::remove_file(&path).unwrap();
            }

            let report = repo.fsck(&opts).await.unwrap();
            assert_eq!(report.errors.len(), 1, "the walk reports the one fault");
            let commit =
                objects.join(ObjectName::new(c2, ObjectType::Commit).loose_path(RepoMode::Archive));
            let tombstone = objects.join(
                ObjectName::new(c2, ObjectType::TombstoneCommit).loose_path(RepoMode::Archive),
            );
            (report.tombstoned, commit.exists(), tombstone.exists())
        })
    };
    let tombstones = |opts: FsckOptions| FsckOptions {
        add_tombstones: true,
        ..opts
    };

    // A corrupt object and neither switch: the step does not run, and the
    // child commit object stays.
    let (tombstoned, commit, tombstone) =
        arm("maint-fsck-tomb-held", true, tombstones(FsckOptions::new()));
    assert!(tombstoned.is_empty(), "no commit is tombstoned");
    assert!(commit, "the child commit object stands");
    assert!(!tombstone, "no tombstone is written");

    // The same repository under `all`, and under `delete`: the step runs.
    for (name, opts) in [
        (
            "maint-fsck-tomb-all",
            FsckOptions {
                all: true,
                ..FsckOptions::new()
            },
        ),
        (
            "maint-fsck-tomb-delete",
            FsckOptions {
                delete: true,
                ..FsckOptions::new()
            },
        ),
    ] {
        let (tombstoned, commit, tombstone) = arm(name, true, tombstones(opts));
        assert_eq!(tombstoned.len(), 1, "{name}: the child is tombstoned");
        assert!(!commit, "{name}: the child commit object is gone");
        assert!(tombstone, "{name}: the tombstone is written");
    }

    // An absent object is a fault that the walk carries on its own, so the
    // step runs with no switch.
    let (tombstoned, commit, tombstone) = arm(
        "maint-fsck-tomb-absent",
        false,
        tombstones(FsckOptions::new()),
    );
    assert_eq!(tombstoned.len(), 1, "the child is tombstoned");
    assert!(!commit, "the child commit object is gone");
    assert!(tombstone, "the tombstone is written");
}

#[test]
fn fsck_binding_checks_report_each_kind() {
    use ostrya::{FsckBindingErrorKind, FsckFailure};

    let tmp = TmpDir::new("maint-fsck-bindings");
    block_on(async {
        let base = tmp.path();
        write_tree(&base.join("one"), "a.txt", b"one\n");
        write_tree(&base.join("two"), "a.txt", b"two\n");

        let bindings = |back: bool| {
            let mut opts = FsckOptions::new();
            opts.verify_bindings = !back;
            opts.verify_back_refs = back;
            opts
        };
        let kind = |failure: Option<FsckFailure>| match failure {
            Some(FsckFailure::Binding(error)) => error.kind,
            other => panic!("a binding finding, got {other:?}"),
        };

        // RefNotBound: a second ref at a commit bound to one name alone.
        let repo = Repo::create(
            &base.join("not-bound"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let commit =
            commit_with_metadata(&repo, base, "one", binding_metadata(&["alpha"], None)).await;
        repo.set_ref_immediate("alpha", Some(&commit))
            .await
            .unwrap();
        repo.set_ref_immediate("beta", Some(&commit)).await.unwrap();
        let report = repo.fsck(&bindings(false)).await.unwrap();
        match kind(report.failure) {
            FsckBindingErrorKind::RefNotBound { ref_name, bindings } => {
                assert_eq!(ref_name, "beta");
                assert_eq!(bindings, vec!["alpha".to_owned()]);
            }
            other => panic!("RefNotBound, got {other:?}"),
        }

        // CollectionMismatch: a mirror ref under an id that the commit does
        // not carry.
        let repo = Repo::create(
            &base.join("collection"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let commit = commit_with_metadata(
            &repo,
            base,
            "one",
            binding_metadata(&["main"], Some("org.test.Coll")),
        )
        .await;
        let cref = ostrya::CollectionRef::new("org.test.Other", "main");
        repo.set_collection_ref_immediate(&cref, Some(&commit))
            .await
            .unwrap();
        let report = repo.fsck(&bindings(false)).await.unwrap();
        match kind(report.failure) {
            FsckBindingErrorKind::CollectionMismatch { bound, found_under } => {
                assert_eq!(bound, "org.test.Coll");
                assert_eq!(found_under, "org.test.Other");
            }
            other => panic!("CollectionMismatch, got {other:?}"),
        }

        // BackRefMissing: a bound name that no ref carries.
        let repo = Repo::create(&base.join("no-ref"), CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_with_metadata(
            &repo,
            base,
            "one",
            binding_metadata(&["alpha", "delta"], None),
        )
        .await;
        repo.set_ref_immediate("alpha", Some(&commit))
            .await
            .unwrap();
        let report = repo.fsck(&bindings(true)).await.unwrap();
        match kind(report.failure) {
            FsckBindingErrorKind::BackRefMissing { ref_name } => assert_eq!(ref_name, "delta"),
            other => panic!("BackRefMissing, got {other:?}"),
        }

        // BackRefMismatch: the ref exists and names another commit.
        let repo = Repo::create(&base.join("moved"), CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let first =
            commit_with_metadata(&repo, base, "one", binding_metadata(&["alpha"], None)).await;
        let second =
            commit_with_metadata(&repo, base, "two", binding_metadata(&["alpha"], None)).await;
        repo.set_ref_immediate("alpha", Some(&second))
            .await
            .unwrap();
        let report = repo.fsck(&bindings(true)).await.unwrap();
        match kind(report.failure) {
            FsckBindingErrorKind::BackRefMismatch { ref_name } => assert_eq!(ref_name, "alpha"),
            other => panic!("BackRefMismatch, got {other:?}"),
        }
        assert_ne!(first, second);

        // BackCollectionRefMissing: the collection ref that the binding names
        // is not in the store.
        let repo = Repo::create(
            &base.join("no-collection-ref"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let commit = commit_with_metadata(
            &repo,
            base,
            "one",
            binding_metadata(&["main"], Some("org.test.Coll")),
        )
        .await;
        repo.set_ref_immediate("main", Some(&commit)).await.unwrap();
        let report = repo.fsck(&bindings(true)).await.unwrap();
        match kind(report.failure) {
            FsckBindingErrorKind::BackCollectionRefMissing {
                collection_id,
                ref_name,
            } => {
                assert_eq!(collection_id, "org.test.Coll");
                assert_eq!(ref_name, "main");
            }
            other => panic!("BackCollectionRefMissing, got {other:?}"),
        }

        // BackCollectionRefMismatch: the collection ref exists and names
        // another commit.
        let repo = Repo::create(
            &base.join("moved-collection-ref"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        // The first commit binds nothing, so the check reaches the second
        // commit alone. Its plain ref resolves, and its collection ref names
        // the first commit.
        let first = commit_with_metadata(&repo, base, "one", binding_metadata(&[], None)).await;
        let second = commit_with_metadata(
            &repo,
            base,
            "two",
            binding_metadata(&["main"], Some("org.test.Coll")),
        )
        .await;
        repo.set_ref_immediate("main", Some(&second)).await.unwrap();
        let cref = ostrya::CollectionRef::new("org.test.Coll", "main");
        repo.set_collection_ref_immediate(&cref, Some(&first))
            .await
            .unwrap();
        let report = repo.fsck(&bindings(true)).await.unwrap();
        match kind(report.failure) {
            FsckBindingErrorKind::BackCollectionRefMismatch {
                collection_id,
                ref_name,
            } => {
                assert_eq!(collection_id, "org.test.Coll");
                assert_eq!(ref_name, "main");
            }
            other => panic!("BackCollectionRefMismatch, got {other:?}"),
        }
    });
}

#[test]
fn fsck_options_and_report_are_send_sync() {
    // `FsckOptions` holds a boxed `FnMut`, so it is `Send` and not `Sync`,
    // the same as `CheckoutOptions`. The report is both.
    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send::<FsckOptions>();
    assert_send_sync::<ostrya::FsckReport>();
    assert_send_sync::<ostrya::FsckError>();
    assert_send_sync::<ostrya::FsckBindingError>();
    assert_send_sync::<ostrya::FsckFailure>();
}

/// Finds one loose object with the extension `ext` under the repository `repo`.
fn find_object(repo: &Path, ext: &str) -> Option<std::path::PathBuf> {
    for fanout in std::fs::read_dir(repo.join("objects")).unwrap() {
        let fanout = fanout.unwrap().path();
        if !fanout.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&fanout).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().and_then(|e| e.to_str()) == Some(ext) {
                return Some(p);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// diff.
// ---------------------------------------------------------------------------

/// Parses the output of `ostree diff` into a set of `(code, path)` pairs.
fn parse_tool_diff(output: &str) -> HashSet<(char, String)> {
    output
        .lines()
        .filter_map(|line| {
            let code = line.chars().next()?;
            let path = line[1..].trim_start().to_owned();
            if matches!(code, 'A' | 'D' | 'M') && !path.is_empty() {
                Some((code, path))
            } else {
                None
            }
        })
        .collect()
}

/// Returns the diff of ostrya as a set of `(code, path)` pairs.
fn port_diff_set(entries: &[DiffEntry]) -> HashSet<(char, String)> {
    entries
        .iter()
        .map(|e| {
            let code = match e.change {
                DiffChange::Added => 'A',
                DiffChange::Removed => 'D',
                DiffChange::Modified => 'M',
            };
            (code, e.path.clone())
        })
        .collect()
}

#[test]
fn diff_matches_the_tool() {
    if !ostree_available() {
        eprintln!("skipping diff_matches_the_tool: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("maint-diff");
    let base = tmp.path();
    let repo = base.join("repo");
    tool_init(&repo);

    // First tree: a file to modify, a directory to remove, a directory whose
    // metadata changes, and a name that changes type.
    let t1 = base.join("t1");
    write_tree(&t1, "keep.txt", b"one\n");
    write_tree(&t1.join("gone"), "x.txt", b"g\n");
    write_tree(&t1.join("meta"), "f.txt", b"m\n");
    write_tree(&t1, "thing", b"file-form\n");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(t1.join("meta"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Second tree: keep.txt modified, gone/ removed, added/ new, meta/ with a
    // changed mode, and thing now a directory.
    let t2 = base.join("t2");
    write_tree(&t2, "keep.txt", b"two\n");
    write_tree(&t2.join("meta"), "f.txt", b"m\n");
    write_tree(&t2.join("added"), "y.txt", b"new\n");
    write_tree(&t2.join("thing"), "inner.txt", b"dir-form\n");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(t2.join("meta"), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    let a = tool_commit(&repo, "b", &t1);
    let b = tool_commit(&repo, "b", &t2);

    let tool_out = ostree(&[
        &format!("--repo={}", repo.display()),
        "diff",
        &a.to_hex(),
        &b.to_hex(),
    ]);
    let tool_set = parse_tool_diff(&tool_out);

    let port_set = block_on(async {
        let handle = Repo::open(&repo).await.unwrap();
        let entries = handle.diff_commits(&a, &b).await.unwrap();
        port_diff_set(&entries)
    });

    assert_eq!(
        port_set, tool_set,
        "the port's diff matches the tool's:\n tool={tool_set:?}\n port={port_set:?}"
    );
}

/// The diff reports its entries in the walk order, which is the order that
/// `ostree diff` prints.
///
/// - The report has three groups in this order: modified, removed, added.
/// - In one group, the entries come in the order that the walk found them.
/// - At each pair of directories of one name, the entries of the first side
///   come first, in the order of that side. This order is the files in
///   stored order, then the subdirectories in stored order.
/// - The descent into a pair of directories stands where the walk finds it.
/// - The entries of the second side follow, in the order of that side.
#[test]
fn diff_print_order_is_the_walk_order() {
    let tmp = TmpDir::new("maint-diff-order");
    let base = tmp.path();
    let repo_path = base.join("repo");

    let one = base.join("t1");
    write_tree(&one.join("M1/s"), "x", b"x\n");
    write_tree(&one.join("M1"), "y", b"y\n");
    write_tree(&one.join("M2"), "w", b"w\n");
    write_tree(&one.join("D1"), "keep", b"k\n");
    write_tree(&one, "aa", b"a\n");
    write_tree(&one, "gone", b"g\n");
    write_tree(&one.join("gonedir"), "inner", b"i\n");

    let two = base.join("t2");
    write_tree(&two.join("M1/s"), "x", b"x2\n");
    write_tree(&two.join("M1"), "y", b"y2\n");
    write_tree(&two.join("M2"), "w", b"w2\n");
    write_tree(&two.join("D1"), "keep", b"k\n");
    write_tree(&two.join("D1"), "new1", b"n\n");
    write_tree(&two, "aa", b"a2\n");
    write_tree(&two, "zz_added", b"z\n");
    write_tree(&two.join("N/b1/deep"), "g", b"g\n");
    write_tree(&two.join("N/b1"), "f", b"f\n");
    write_tree(&two.join("N"), "a", b"a\n");

    let ordered = block_on(async {
        let repo = Repo::create(&repo_path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let a = library_commit(&repo, base, "t1", None).await;
        let b = library_commit(&repo, base, "t2", Some(a)).await;
        let entries = repo.diff_commits(&a, &b).await.unwrap();
        entries
            .iter()
            .map(|entry| {
                let code = match entry.change {
                    DiffChange::Added => 'A',
                    DiffChange::Removed => 'D',
                    DiffChange::Modified => 'M',
                };
                format!("{code} {}", entry.path)
            })
            .collect::<Vec<_>>()
    });

    assert_eq!(
        ordered,
        vec![
            "M /aa",
            "M /M1/y",
            "M /M1/s/x",
            "M /M2/w",
            "D /gone",
            "D /gonedir",
            "A /D1/new1",
            "A /zz_added",
            "A /N",
            "A /N/a",
            "A /N/b1",
            "A /N/b1/f",
            "A /N/b1/deep",
            "A /N/b1/deep/g",
        ],
        "the walk order"
    );
}

#[test]
fn diff_of_identical_commits_is_empty() {
    if !ostree_available() {
        eprintln!("skipping diff_of_identical_commits_is_empty: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("maint-diff-empty");
    let base = tmp.path();
    let repo = base.join("repo");
    tool_init(&repo);
    let t = base.join("t");
    write_tree(&t, "a.txt", b"same\n");
    let c = tool_commit(&repo, "b", &t);

    block_on(async {
        let handle = Repo::open(&repo).await.unwrap();
        let entries = handle.diff_commits(&c, &c).await.unwrap();
        assert!(entries.is_empty(), "a commit differs from itself nowhere");
    });
}
