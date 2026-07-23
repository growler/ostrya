//! Prune, fsck, traversal, and diff integration tests (Phase 12).
//!
//! The reachability, prune, and diff results are cross-checked against the
//! `ostree` tool: the port and the tool prune identical repositories and must
//! agree on which objects survive and how many bytes are freed; the port's diff
//! must reproduce `ostree diff`; and a repository the port prunes or leaves must
//! pass `ostree fsck`. The fsck tests corrupt and delete objects and confirm the
//! port detects exactly the injected fault.

mod common;

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use common::{TmpDir, ostree_available};
use ostrya::{
    Checksum, CreateOptions, DiffChange, DiffEntry, FsckOptions, ObjectName, ObjectType, Repo,
    RepoMode,
};
use ostrya_rt::block_on;

// ---------------------------------------------------------------------------
// Tool-driven repository construction helpers.
// ---------------------------------------------------------------------------

/// Run the `ostree` tool, asserting success and returning trimmed stdout.
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

/// Run the `ostree` tool and return combined stdout+stderr, whatever the exit.
fn ostree_output(args: &[&str]) -> String {
    let output = Command::new("ostree")
        .args(args)
        .output()
        .expect("run ostree");
    let mut s = String::from_utf8_lossy(&output.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&output.stderr));
    s
}

/// Write a single-file tree at `dir` with canonical permissions.
fn write_tree(dir: &Path, name: &str, content: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(name), content).unwrap();
    std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Commit `src` onto branch `branch` of the tool repository at `repo`, forcing
/// owner 0:0 and no xattrs, and return the new commit checksum.
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

/// Initialize an archive repository with the tool.
fn tool_init(repo: &Path) {
    ostree(&[
        &format!("--repo={}", repo.display()),
        "init",
        "--mode=archive-z2",
    ]);
}

/// Recursively copy a directory tree, preserving attributes.
fn copy_tree(from: &Path, to: &Path) {
    let status = Command::new("cp")
        .args(["-a"])
        .arg(from)
        .arg(to)
        .status()
        .expect("run cp");
    assert!(status.success(), "cp -a {from:?} {to:?} failed");
}

/// The set of loose objects present on disk, by relative `objects/` path.
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

/// A three-commit branch (`m`: c1 <- c2 <- c3) in a fresh tool repository, with
/// each commit changing the same top-level file so history holds distinct
/// objects. Returns the three commit checksums.
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

        // Unbounded depth reaches every commit in the ancestry.
        let full = handle.traverse_commit(&c3, -1).await.unwrap();
        for c in [c1, c2, c3] {
            assert!(
                full.contains(&ObjectName::new(c, ObjectType::Commit)),
                "depth -1 reaches commit {c}"
            );
        }

        // Depth 0 reaches only the head commit.
        let head_only = handle.traverse_commit(&c3, 0).await.unwrap();
        assert!(head_only.contains(&ObjectName::new(c3, ObjectType::Commit)));
        assert!(!head_only.contains(&ObjectName::new(c2, ObjectType::Commit)));
        assert!(!head_only.contains(&ObjectName::new(c1, ObjectType::Commit)));

        // Depth 1 reaches the head and its immediate parent only.
        let one = handle.traverse_commit(&c3, 1).await.unwrap();
        assert!(one.contains(&ObjectName::new(c3, ObjectType::Commit)));
        assert!(one.contains(&ObjectName::new(c2, ObjectType::Commit)));
        assert!(!one.contains(&ObjectName::new(c1, ObjectType::Commit)));

        // A traversal of an absent commit is an error.
        let bogus = Checksum::from_hex(&"ab".repeat(32)).unwrap();
        assert!(handle.traverse_commit(&bogus, -1).await.is_err());
    });
}

#[test]
fn traverse_reachable_depth_is_order_independent() {
    let tmp = TmpDir::new("maint-traverse-order");
    block_on(async {
        let base = tmp.path();
        // Linear history c0 <- c1 <- c2 <- c3, built with the library so the
        // test does not need the tool.
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

        // Roots c3 and c2 (c2 is c3's parent) at depth 1. c1 is c2's parent, so
        // it is within depth 1 of the c2 root and must be reachable no matter
        // which order the two roots are supplied in.
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

/// Parse "Deleted N objects, S bytes freed" or "Would delete: N objects,
/// freeing S bytes" from tool prune output into `(objects, bytes)`. Only the
/// deletion line is examined, so the "Total objects:" line is ignored.
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
    // An identical copy the port prunes.
    let port_repo = tmp.path().join("port");
    copy_tree(&tool_repo, &port_repo);

    // The tool prunes its copy; capture the reported counts.
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

    // The pruned repository still passes the tool's own fsck.
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
        // c1 is an ancestor, not the ref head, so it can be deleted.
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

    // The tool accepts the result.
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
// fsck.
// ---------------------------------------------------------------------------

/// Commit the fixture-like source into a fresh library-built archive repo and
/// return the (repo, commit).
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

/// Commit the tree at `base/rel` onto `parent` on branch `main` of `repo`,
/// forcing canonical permissions and no xattrs, and return the new commit.
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
        // Every reachable object is examined.
        let reachable = repo.traverse_commit(&commit, -1).await.unwrap();
        assert_eq!(report.objects_checked, reachable.len());
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
        // The commit is marked partial.
        assert_eq!(
            repo.commit_state(&commit).await.unwrap(),
            ostrya::CommitState::Partial,
            "the commit is marked partial after a missing object"
        );
        // The marker holds the tool's single state byte.
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
        // Two commits differing at the top level but sharing an identical
        // `sub/` subtree, so both reference the same `sub/` dirtree and the
        // same nested content object.
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

        // The one content object reachable from both commits is the shared
        // nested.txt; delete it so both commits are incomplete.
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
        // Two commits whose `dir/` differs (so the containing dirtrees differ)
        // but that share an identical `dir/shared.txt`, so the same content
        // object is reached through two distinct dirtrees. The missing outcome
        // must reach the second commit through the content memo, not the
        // dirtree memo.
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
        // The shared missing file is reported exactly once.
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

/// Find one loose object with the given extension under a repository.
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

/// Parse `ostree diff` output into a set of `(code, path)` pairs.
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

/// The port's diff as `(code, path)` pairs.
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

    // First tree: a modifiable file, a directory to be removed, a directory
    // whose metadata will change, and a name that will change type.
    let t1 = base.join("t1");
    write_tree(&t1, "keep.txt", b"one\n");
    write_tree(&t1.join("gone"), "x.txt", b"g\n");
    write_tree(&t1.join("meta"), "f.txt", b"m\n");
    write_tree(&t1, "thing", b"file-form\n");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(t1.join("meta"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Second tree: keep.txt modified, gone/ removed, added/ new, meta/ mode
    // changed, thing now a directory.
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
