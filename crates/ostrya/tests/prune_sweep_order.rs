//! The order in which a prune removes what it dooms, and the leftovers of an
//! interrupted run that the next run removes.
//!
//! A run that stops part way through its deletions must leave no commit object
//! whose tree it already started to remove. The next run also removes each
//! static delta whose target commit is absent and each `.commitpartial` marker
//! whose commit is absent.

mod common;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DeltaOptions,
    MutableTree, ObjectName, ObjectType, PruneOptions, Repo, RepoMode,
};
use ostrya_rt::block_on;

/// The number of unreferenced commits the sweep-order test dooms.
const DOOMED_COMMITS: usize = 20;
/// The number of fanout directories the sweep-order test makes read-only. More
/// than one makes the first failure fall early in the sweep.
const BLOCKED_FANOUTS: usize = 5;

/// Commit a one-file tree whose content names `name`, with a ref `branch` where
/// one is given.
async fn commit(
    repo: &Repo,
    base: &Path,
    name: &str,
    parent: Option<Checksum>,
    branch: Option<&str>,
) -> Checksum {
    use std::os::fd::AsFd;
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), format!("{name}\n")).unwrap();
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
                timestamp: Some(1_700_000_000),
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

/// Sets each directory back to mode 0755 when dropped, so the scratch
/// directory can be removed after a failed assertion too.
struct RestoreWritable(Vec<PathBuf>);

impl Drop for RestoreWritable {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        for dir in &self.0 {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
        }
    }
}

/// The two-hex fanout directory name of an object.
fn fanout(name: &ObjectName) -> String {
    name.checksum.to_hex()[..2].to_owned()
}

#[test]
fn an_interrupted_sweep_leaves_no_commit_whose_tree_it_removed() {
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().is_root() {
        eprintln!("skipping: root ignores the directory permissions this test relies on");
        return;
    }
    let tmp = TmpDir::new("prune-sweep-order");
    let base = tmp.path();
    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        commit(&repo, base, "kept", None, Some("main")).await;
        let kept = repo.list_objects().await.unwrap();
        for i in 0..DOOMED_COMMITS {
            commit(&repo, base, &format!("doomed-{i}"), None, None).await;
        }
        let doomed: HashSet<ObjectName> = repo
            .list_objects()
            .await
            .unwrap()
            .difference(&kept)
            .copied()
            .collect();
        let doomed_commits: Vec<Checksum> = doomed
            .iter()
            .filter(|o| o.ty == ObjectType::Commit)
            .map(|o| o.checksum)
            .collect();
        assert_eq!(doomed_commits.len(), DOOMED_COMMITS);

        // Pick file objects of the doomed commits in fanout directories that
        // hold no doomed commit and no doomed detached metadata, so the
        // blocked unlinks touch the content of a commit and never a commit.
        let commit_fanouts: HashSet<String> = doomed
            .iter()
            .filter(|o| matches!(o.ty, ObjectType::Commit | ObjectType::CommitMeta))
            .map(fanout)
            .collect();
        let mut blocked: Vec<String> = doomed
            .iter()
            .filter(|o| o.ty == ObjectType::File)
            .map(fanout)
            .filter(|f| !commit_fanouts.contains(f))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        blocked.sort();
        blocked.truncate(BLOCKED_FANOUTS);
        assert!(!blocked.is_empty(), "no fanout directory holds files alone");

        let dirs: Vec<PathBuf> = blocked
            .iter()
            .map(|f| base.join("repo/objects").join(f))
            .collect();
        let _restore = RestoreWritable(dirs.clone());
        for dir in &dirs {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        }

        let result = repo
            .prune(&PruneOptions {
                refs_only: true,
                ..PruneOptions::default()
            })
            .await;
        assert!(
            result.is_err(),
            "the unlink in a read-only directory fails the run: {result:?}"
        );

        let left: Vec<String> = {
            let mut left = Vec::new();
            for c in &doomed_commits {
                if repo.has_object(ObjectType::Commit, c).await.unwrap() {
                    left.push(c.to_hex());
                }
            }
            left
        };
        assert!(
            left.is_empty(),
            "the run removed content while {} of {} doomed commits stayed: {left:?}",
            left.len(),
            DOOMED_COMMITS
        );
    });
}

/// The path of a commit's `.commitpartial` marker.
fn marker(base: &Path, commit: &Checksum) -> PathBuf {
    base.join("repo/state")
        .join(format!("{}.commitpartial", commit.to_hex()))
}

/// An `archive` repository with a ref `main` at `c2` over `c1`, a delta
/// `c1-c2` whose target is present, and a delta `c2-x` whose target `x` the
/// test then removes by hand, the way an interrupted run leaves it. `x` also
/// has a `.commitpartial` marker, and so does `c2`. Returns the repository,
/// `c1`, `c2`, and `x`.
async fn leftovers(base: &Path) -> (Repo, Checksum, Checksum, Checksum) {
    let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let c1 = commit(&repo, base, "one", None, None).await;
    let c2 = commit(&repo, base, "two", Some(c1), Some("main")).await;
    let x = commit(&repo, base, "gone", Some(c2), None).await;
    repo.generate_static_delta(Some(&c1), &c2, &DeltaOptions::default())
        .await
        .unwrap();
    repo.generate_static_delta(Some(&c2), &x, &DeltaOptions::default())
        .await
        .unwrap();
    assert_eq!(repo.list_static_deltas().await.unwrap().len(), 2);

    let x_path = base
        .join("repo/objects")
        .join(ObjectName::new(x, ObjectType::Commit).loose_path(RepoMode::Archive));
    std::fs::remove_file(x_path).unwrap();
    std::fs::create_dir_all(base.join("repo/state")).unwrap();
    std::fs::write(marker(base, &x), b"").unwrap();
    std::fs::write(marker(base, &c2), b"").unwrap();
    (repo, c1, c2, x)
}

#[test]
fn a_prune_removes_the_delta_and_the_marker_of_an_absent_commit() {
    let tmp = TmpDir::new("prune-absent-leftovers");
    let base = tmp.path();
    block_on(async {
        let (repo, c1, c2, x) = leftovers(base).await;

        repo.prune(&PruneOptions::default()).await.unwrap();
        assert_eq!(
            repo.list_static_deltas().await.unwrap(),
            vec![format!("{}-{}", c1.to_hex(), c2.to_hex())],
            "the delta whose target is absent goes, and the delta whose target \
             is present stays"
        );
        assert!(
            !marker(base, &x).exists(),
            "the marker of an absent commit goes"
        );
        assert!(
            marker(base, &c2).exists(),
            "the marker of a present commit stays"
        );
    });
}

#[test]
fn a_dry_run_leaves_the_delta_and_the_marker_of_an_absent_commit() {
    let tmp = TmpDir::new("prune-absent-leftovers-dry");
    let base = tmp.path();
    block_on(async {
        let (repo, _, c2, x) = leftovers(base).await;

        repo.prune(&PruneOptions {
            no_prune: true,
            ..PruneOptions::default()
        })
        .await
        .unwrap();
        assert_eq!(repo.list_static_deltas().await.unwrap().len(), 2);
        assert!(marker(base, &x).exists());
        assert!(marker(base, &c2).exists());
    });
}

#[test]
fn a_prune_skips_a_delta_name_that_does_not_decode() {
    let tmp = TmpDir::new("prune-undecodable-delta");
    let base = tmp.path();
    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let c1 = commit(&repo, base, "one", None, Some("main")).await;
        let x = commit(&repo, base, "doomed", Some(c1), None).await;
        repo.generate_static_delta(Some(&c1), &x, &DeltaOptions::default())
            .await
            .unwrap();
        let bad = base.join("repo/deltas/zz/!!bad!!");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("superblock"), b"").unwrap();

        repo.prune(&PruneOptions::default())
            .await
            .expect("a plain prune skips the name that does not decode");
        assert!(bad.join("superblock").exists(), "the entry stays");

        repo.prune(&PruneOptions {
            refs_only: true,
            ..PruneOptions::default()
        })
        .await
        .expect("a prune that removes a commit skips the name too");
        assert!(!repo.has_object(ObjectType::Commit, &x).await.unwrap());
        // The fanout of the removed delta stays in place, empty.
        let deltas_left: Vec<_> = base
            .join("repo/deltas")
            .read_dir()
            .unwrap()
            .flatten()
            .filter(|fanout| fanout.file_name() != "zz")
            .flat_map(|fanout| fanout.path().read_dir().unwrap().flatten())
            .map(|leaf| leaf.path())
            .collect();
        assert!(
            deltas_left.is_empty(),
            "the delta of the removed commit goes: {deltas_left:?}"
        );
        assert!(bad.join("superblock").exists(), "the entry stays");
    });
}

#[test]
fn the_sweep_removes_the_markers_after_the_commits_and_their_content() {
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().is_root() {
        eprintln!("skipping: root ignores the directory permissions this test relies on");
        return;
    }
    let tmp = TmpDir::new("prune-marker-order");
    let base = tmp.path();
    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        commit(&repo, base, "kept", None, Some("main")).await;
        let kept = repo.list_objects().await.unwrap();
        for i in 0..3 {
            commit(&repo, base, &format!("doomed-{i}"), None, None).await;
        }
        let doomed: HashSet<ObjectName> = repo
            .list_objects()
            .await
            .unwrap()
            .difference(&kept)
            .copied()
            .collect();
        let state = base.join("repo/state");
        std::fs::create_dir_all(&state).unwrap();
        for o in doomed.iter().filter(|o| o.ty == ObjectType::Commit) {
            std::fs::write(marker(base, &o.checksum), b"").unwrap();
        }

        // A read-only `state/` fails the first marker unlink. Every commit and
        // every content object is gone by then.
        {
            let _restore = RestoreWritable(vec![state.clone()]);
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o555)).unwrap();
            let result = repo
                .prune(&PruneOptions {
                    refs_only: true,
                    ..PruneOptions::default()
                })
                .await;
            assert!(
                result.is_err(),
                "the marker unlink fails the run: {result:?}"
            );
        }
        let left: HashSet<ObjectName> = repo
            .list_objects()
            .await
            .unwrap()
            .intersection(&doomed)
            .copied()
            .collect();
        assert!(
            left.is_empty(),
            "the run stopped at a marker while doomed objects stayed: {left:?}"
        );
        for o in doomed.iter().filter(|o| o.ty == ObjectType::Commit) {
            assert!(marker(base, &o.checksum).exists());
        }

        // The next run removes the markers the failed run left.
        repo.prune(&PruneOptions::default()).await.unwrap();
        for o in doomed.iter().filter(|o| o.ty == ObjectType::Commit) {
            assert!(!marker(base, &o.checksum).exists());
        }
    });
}

#[test]
fn a_delete_commit_run_removes_the_marker_of_the_named_commit() {
    let tmp = TmpDir::new("prune-delete-commit-marker");
    let base = tmp.path();
    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        commit(&repo, base, "kept", None, Some("main")).await;
        let x = commit(&repo, base, "named", None, None).await;
        std::fs::create_dir_all(base.join("repo/state")).unwrap();
        std::fs::write(marker(base, &x), b"").unwrap();

        repo.prune(&PruneOptions {
            delete_commit: Some(x),
            ..PruneOptions::default()
        })
        .await
        .unwrap();
        assert!(!repo.has_object(ObjectType::Commit, &x).await.unwrap());
        assert!(
            !marker(base, &x).exists(),
            "the marker of the named commit goes"
        );
    });
}
