//! The prune options that bound a walk: the per-branch depths, the timestamp
//! cut, the commit-only sweep, the static-delta sweep, and the tombstone
//! markers.
//!
//! Each test builds its repository with the port and states the objects the run
//! left and the statistics it reported. The `ostree` tool's own behavior for
//! these options is compared in `crates/ostrya-cli/tests/cli.rs`; these tests
//! pin the library rules those comparisons rest on.

mod common;

use std::path::Path;

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DeltaOptions,
    Error, MutableTree, ObjectName, ObjectType, PruneOptions, PruneStats, Repo, RepoMode,
    static_delta_relative_dir,
};
use ostrya_rt::block_on;

/// The timestamp of the first commit every fixture writes. Later commits step
/// one day at a time from it, so a cut between two of them is spellable.
const DAY: u64 = 86_400;
/// The base timestamp, so every commit is reproducible.
const BASE_TS: u64 = 1_700_000_000;

/// Write a one-file tree at `base/<name>`, its content naming it.
fn write_tree(base: &Path, name: &str) {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), format!("{name}\n")).unwrap();
}

/// Commit the tree `base/<name>` into `repo` at `timestamp`, with the given
/// parent and, where `branch` names one, a ref pointing at the result.
async fn commit(
    repo: &Repo,
    base: &Path,
    name: &str,
    timestamp: u64,
    parent: Option<Checksum>,
    branch: Option<&str>,
) -> Checksum {
    use std::os::fd::AsFd;
    write_tree(base, name);
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
                timestamp: Some(timestamp),
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

/// A fresh `bare` repository under `base/repo`.
async fn repo_at(base: &Path) -> Repo {
    Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Bare))
        .await
        .unwrap()
}

/// A branch of three commits, one day apart, named `<branch>1` to `<branch>3`.
/// Returns them oldest first.
async fn chain(repo: &Repo, base: &Path, branch: &str) -> [Checksum; 3] {
    let mut parent = None;
    let mut out = Vec::new();
    for step in 1..=3u64 {
        let name = format!("{branch}{step}");
        let head = if step == 3 { Some(branch) } else { None };
        let c = commit(repo, base, &name, BASE_TS + DAY * step, parent, head).await;
        parent = Some(c);
        out.push(c);
    }
    [out[0], out[1], out[2]]
}

/// A branch of five commits, one day apart, named `<branch>1` to `<branch>5`,
/// with a second ref `mid` pointing at the third. The two branches share their
/// history, so a bound one of them carries reaches the other's walk. Returns
/// the five commits oldest first.
async fn shared_chain(repo: &Repo, base: &Path, branch: &str, mid: &str) -> [Checksum; 5] {
    let mut parent = None;
    let mut out = Vec::new();
    for step in 1..=5u64 {
        let name = format!("{branch}{step}");
        let head = if step == 5 { Some(branch) } else { None };
        let c = commit(repo, base, &name, BASE_TS + DAY * step, parent, head).await;
        parent = Some(c);
        out.push(c);
    }
    let txn = repo.transaction().await.unwrap();
    txn.set_ref(mid, Some(&out[2]));
    txn.commit().await.unwrap();
    [out[0], out[1], out[2], out[3], out[4]]
}

/// Whether the repository still holds `commit` as an object.
async fn holds(repo: &Repo, commit: &Checksum) -> bool {
    repo.has_object(ObjectType::Commit, commit).await.unwrap()
}

/// Prune with the options the caller shaped from the refs-only default.
async fn prune(repo: &Repo, shape: impl FnOnce(&mut PruneOptions)) -> PruneStats {
    let mut opts = PruneOptions {
        refs_only: true,
        ..PruneOptions::default()
    };
    shape(&mut opts);
    repo.prune(&opts).await.unwrap()
}

#[test]
fn keep_younger_than_roots_on_refs_alone() {
    let tmp = TmpDir::new("prune-kyt-refs-alone");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;
        // An orphan younger than the cut, named by no ref.
        let orphan = commit(&repo, tmp.path(), "orphan", BASE_TS + DAY * 10, None, None).await;

        prune(&repo, |o| {
            o.refs_only = false;
            o.keep_younger_than = Some(BASE_TS);
        })
        .await;
        assert!(
            !holds(&repo, &orphan).await,
            "a timestamp cut roots the walk on the refs alone, so an unreferenced \
             commit goes whatever its own timestamp"
        );
        assert!(holds(&repo, &main[2]).await, "the ref's head stays");
    });
}

#[test]
fn keep_younger_than_keeps_every_ref_head() {
    let tmp = TmpDir::new("prune-kyt-heads");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;

        // A cut past every commit in the repository.
        prune(&repo, |o| o.keep_younger_than = Some(BASE_TS + DAY * 100)).await;
        assert!(
            holds(&repo, &main[2]).await,
            "a ref's target is kept whatever its timestamp"
        );
        assert!(!holds(&repo, &main[1]).await, "its parents go");
        assert!(!holds(&repo, &main[0]).await);
    });
}

#[test]
fn keep_younger_than_replaces_depth() {
    let tmp = TmpDir::new("prune-kyt-depth");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;

        // Depth 0 alone keeps the head alone. With a cut older than every
        // commit the depth is read nowhere and the whole chain stays.
        let stats = prune(&repo, |o| {
            o.depth = 0;
            o.keep_younger_than = Some(BASE_TS);
        })
        .await;
        assert_eq!(stats.pruned_objects, 0, "nothing is unreachable");
        assert!(holds(&repo, &main[0]).await);
        assert!(holds(&repo, &main[1]).await);
    });
}

#[test]
fn only_branch_retains_the_branches_it_does_not_name() {
    let tmp = TmpDir::new("prune-only-branch");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;
        let other = chain(&repo, tmp.path(), "other").await;

        prune(&repo, |o| {
            o.depth = 0;
            o.only_branch = vec!["main".to_owned()];
        })
        .await;
        assert!(
            !holds(&repo, &main[0]).await,
            "the named branch takes the depth"
        );
        assert!(!holds(&repo, &main[1]).await);
        assert!(holds(&repo, &main[2]).await);
        assert!(
            holds(&repo, &other[0]).await,
            "a branch the option does not name keeps its whole ancestry"
        );
        assert!(holds(&repo, &other[1]).await);
    });
}

#[test]
fn only_branch_implies_refs_only() {
    let tmp = TmpDir::new("prune-only-branch-refs-only");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        chain(&repo, tmp.path(), "main").await;
        let orphan = commit(&repo, tmp.path(), "orphan", BASE_TS, None, None).await;

        prune(&repo, |o| {
            o.refs_only = false;
            o.only_branch = vec!["main".to_owned()];
        })
        .await;
        assert!(
            !holds(&repo, &orphan).await,
            "a branch selection roots the walk on the refs alone"
        );
    });
}

#[test]
fn only_branch_naming_no_ref_is_refused() {
    let tmp = TmpDir::new("prune-only-branch-unknown");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;

        let mut opts = PruneOptions {
            refs_only: true,
            depth: 0,
            only_branch: vec!["nosuch".to_owned()],
            ..PruneOptions::default()
        };
        let err = repo.prune(&opts).await.unwrap_err();
        assert!(matches!(err, Error::RefNotFound(_)), "got {err:?}");
        assert!(
            holds(&repo, &main[0]).await,
            "the refusal stands ahead of every removal"
        );

        // A value that resolves and names no ref assigns the depth to no
        // branch, so every branch is retained in full.
        opts.only_branch = vec![main[2].to_hex()];
        let stats = repo.prune(&opts).await.unwrap();
        assert_eq!(stats.pruned_objects, 0);
        assert!(holds(&repo, &main[0]).await);
    });
}

#[test]
fn retain_branch_depth_replaces_the_global_depth() {
    let tmp = TmpDir::new("prune-rbd-replaces");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;
        let other = chain(&repo, tmp.path(), "other").await;

        prune(&repo, |o| {
            o.depth = 0;
            o.retain_branch_depth = vec![("main".to_owned(), -1)];
        })
        .await;
        assert!(holds(&repo, &main[0]).await, "the entry keeps main whole");
        assert!(holds(&repo, &main[1]).await);
        assert!(
            !holds(&repo, &other[0]).await,
            "a branch no entry names takes the global depth"
        );
    });
}

#[test]
fn retain_branch_depth_zero_leaves_the_global_depth() {
    let tmp = TmpDir::new("prune-rbd-zero");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;

        prune(&repo, |o| {
            o.depth = 1;
            o.retain_branch_depth = vec![("main".to_owned(), 0)];
        })
        .await;
        assert!(
            holds(&repo, &main[1]).await,
            "depth 0 in an entry leaves the branch at the global depth 1"
        );
        assert!(!holds(&repo, &main[0]).await);
    });
}

#[test]
fn retain_branch_depth_suppresses_only_branch_retention() {
    let tmp = TmpDir::new("prune-rbd-only-branch");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        chain(&repo, tmp.path(), "main").await;
        let other = chain(&repo, tmp.path(), "other").await;

        prune(&repo, |o| {
            o.depth = 0;
            o.only_branch = vec!["main".to_owned()];
            o.retain_branch_depth = vec![("other".to_owned(), 0)];
        })
        .await;
        assert!(
            !holds(&repo, &other[0]).await,
            "an entry of depth 0 names the branch, so the full retention \
             `only_branch` gives an unnamed branch does not reach it"
        );
        assert!(holds(&repo, &other[2]).await);
    });
}

#[test]
fn retain_branch_depth_takes_the_last_entry_for_a_branch() {
    let tmp = TmpDir::new("prune-rbd-last");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;

        prune(&repo, |o| {
            o.depth = 0;
            o.retain_branch_depth = vec![("main".to_owned(), 1), ("main".to_owned(), -1)];
        })
        .await;
        assert!(holds(&repo, &main[0]).await, "the last entry decides");
    });
}

#[test]
fn retain_branch_depth_roots_on_refs_alone() {
    let tmp = TmpDir::new("prune-rbd-refs-alone");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;
        // An orphan named by no ref.
        let orphan = commit(&repo, tmp.path(), "orphan", BASE_TS + DAY * 10, None, None).await;

        prune(&repo, |o| {
            o.refs_only = false;
            o.retain_branch_depth = vec![("main".to_owned(), -1)];
        })
        .await;
        assert!(
            !holds(&repo, &orphan).await,
            "a per-branch depth roots the walk on the refs alone, so an \
             unreferenced commit goes"
        );
        assert!(holds(&repo, &main[0]).await, "the entry keeps main whole");
    });
}

#[test]
fn a_ref_target_takes_its_own_bound_over_an_inherited_one() {
    let tmp = TmpDir::new("prune-reset-rbd");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let c = shared_chain(&repo, tmp.path(), "main", "mid").await;

        // `main` keeps its whole ancestry and reaches `mid`'s target on the
        // way. The bound `mid` carries stands there, so one parent of it is
        // kept and the rest of the history goes.
        prune(&repo, |o| {
            o.retain_branch_depth = vec![("mid".to_owned(), 1)]
        })
        .await;
        assert!(holds(&repo, &c[4]).await);
        assert!(holds(&repo, &c[3]).await);
        assert!(holds(&repo, &c[2]).await, "mid's own target stays");
        assert!(holds(&repo, &c[1]).await, "mid's one parent stays");
        assert!(
            !holds(&repo, &c[0]).await,
            "the bound at mid replaces the unbounded one main's walk carried"
        );
    });
}

#[test]
fn a_ref_target_bound_replaces_and_does_not_narrow() {
    let tmp = TmpDir::new("prune-reset-widens");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let c = shared_chain(&repo, tmp.path(), "main", "mid").await;

        // The walk arrives at `mid`'s target with one parent hop left of the
        // global depth 3. `mid` takes the global depth itself, so the arrival
        // continues under depth 3 and the whole chain is kept.
        prune(&repo, |o| {
            o.depth = 3;
            o.retain_branch_depth = vec![("mid".to_owned(), 0)];
        })
        .await;
        for commit in &c {
            assert!(
                holds(&repo, commit).await,
                "a ref target's bound replaces the inherited one, so the \
                 shorter of the two does not decide"
            );
        }
    });
}

#[test]
fn only_branch_bounds_the_history_running_through_the_branch_it_names() {
    let tmp = TmpDir::new("prune-reset-only-branch");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let c = shared_chain(&repo, tmp.path(), "main", "mid").await;

        // `main` is retained in full and `mid` is cut to its head. The cut
        // holds where `main`'s walk reaches `mid`'s target.
        prune(&repo, |o| {
            o.depth = 0;
            o.only_branch = vec!["mid".to_owned()];
        })
        .await;
        assert!(holds(&repo, &c[4]).await);
        assert!(holds(&repo, &c[3]).await);
        assert!(holds(&repo, &c[2]).await);
        assert!(!holds(&repo, &c[1]).await);
        assert!(!holds(&repo, &c[0]).await);
    });
}

#[test]
fn a_time_bound_at_a_ref_target_replaces_an_inherited_depth() {
    let tmp = TmpDir::new("prune-reset-since");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let c = shared_chain(&repo, tmp.path(), "main", "mid").await;

        // `main` keeps its whole ancestry; `mid` takes the timestamp cut. The
        // cut holds from `mid`'s target back.
        prune(&repo, |o| {
            o.keep_younger_than = Some(BASE_TS + DAY * 3);
            o.retain_branch_depth = vec![("main".to_owned(), -1)];
        })
        .await;
        assert!(holds(&repo, &c[2]).await, "mid's own target stays");
        assert!(!holds(&repo, &c[1]).await, "its parents are below the cut");
        assert!(!holds(&repo, &c[0]).await);
    });
}

#[test]
fn two_refs_at_one_commit_keep_what_either_bound_reaches() {
    let tmp = TmpDir::new("prune-reset-two-refs");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let c = shared_chain(&repo, tmp.path(), "main", "alpha").await;
        let txn = repo.transaction().await.unwrap();
        txn.set_ref("beta", Some(&c[2]));
        txn.commit().await.unwrap();

        // `alpha` and `beta` name one commit. `alpha` is cut to its head and
        // `beta`, which no value names, is retained in full. The commit is
        // walked under each of the two bounds and keeps what either reaches.
        prune(&repo, |o| {
            o.depth = 0;
            o.only_branch = vec!["alpha".to_owned()];
        })
        .await;
        for commit in &c {
            assert!(holds(&repo, commit).await);
        }
    });
}

#[test]
fn depth_minus_two_keeps_the_head_alone() {
    let tmp = TmpDir::new("prune-depth-minus-two");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;

        prune(&repo, |o| o.depth = -2).await;
        assert!(holds(&repo, &main[2]).await);
        assert!(
            !holds(&repo, &main[1]).await,
            "-1 is the one negative depth that keeps the whole ancestry"
        );
        assert!(!holds(&repo, &main[0]).await);
    });
}

#[test]
fn commit_only_deletes_commits_and_leaves_their_trees() {
    let tmp = TmpDir::new("prune-commit-only");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;
        let before = repo.list_objects().await.unwrap();
        let trees: Vec<_> = before
            .iter()
            .filter(|o| o.ty != ObjectType::Commit)
            .copied()
            .collect();

        let stats = prune(&repo, |o| {
            o.depth = 0;
            o.commit_only = true;
        })
        .await;
        assert_eq!(
            stats.total_objects, 3,
            "the total counts commit objects alone"
        );
        assert_eq!(stats.pruned_objects, 2);
        assert!(!holds(&repo, &main[0]).await);
        assert!(!holds(&repo, &main[1]).await);
        let after = repo.list_objects().await.unwrap();
        for name in trees {
            assert!(
                after.contains(&name),
                "the objects a deleted commit reached stay where they stand"
            );
        }
    });
}

#[test]
fn commitmeta_is_outside_both_counts() {
    let tmp = TmpDir::new("prune-commitmeta-counts");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;
        for c in &main {
            repo.write_commit_detached_metadata(c, None).await.unwrap();
        }
        let before = repo.list_objects().await.unwrap();
        let counted = |set: &std::collections::HashSet<ObjectName>| {
            set.iter()
                .filter(|o| o.ty != ObjectType::CommitMeta)
                .count()
        };

        let stats = prune(&repo, |o| o.depth = 0).await;
        assert_eq!(
            stats.total_objects,
            counted(&before),
            "detached commit metadata is outside the total"
        );
        let after = repo.list_objects().await.unwrap();
        assert!(
            !after.contains(&ObjectName::new(main[0], ObjectType::CommitMeta)),
            "a pruned commit's detached metadata is removed with it"
        );
        assert!(
            after.contains(&ObjectName::new(main[2], ObjectType::CommitMeta)),
            "a kept commit keeps its detached metadata"
        );
        assert_eq!(
            stats.pruned_objects,
            counted(&before) - counted(&after),
            "the bytes a removed `.commitmeta` freed are outside the deletion count"
        );
    });
}

#[test]
fn static_delta_is_swept_with_its_target_commit() {
    let tmp = TmpDir::new("prune-delta-target");
    block_on(async {
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let main = chain(&repo, tmp.path(), "main").await;
        repo.generate_static_delta(Some(&main[0]), &main[1], &DeltaOptions::default())
            .await
            .unwrap();
        repo.generate_static_delta(Some(&main[1]), &main[2], &DeltaOptions::default())
            .await
            .unwrap();
        assert_eq!(repo.list_static_deltas().await.unwrap().len(), 2);

        prune(&repo, |o| o.depth = 0).await;
        let deltas = repo.list_static_deltas().await.unwrap();
        assert_eq!(
            deltas,
            vec![format!("{}-{}", main[1].to_hex(), main[2].to_hex())],
            "the delta whose target the run deleted goes, and the delta whose \
             source it deleted stays"
        );
    });
}

#[test]
fn static_deltas_only_requires_delete_commit() {
    let tmp = TmpDir::new("prune-deltas-only-refusal");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;

        let opts = PruneOptions {
            refs_only: true,
            depth: 0,
            static_deltas_only: true,
            ..PruneOptions::default()
        };
        let err = repo.prune(&opts).await.unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "got {err:?}");
        assert!(holds(&repo, &main[0]).await, "the refusal removes nothing");
    });
}

#[test]
fn static_deltas_only_deletes_the_delta_and_nothing_else() {
    let tmp = TmpDir::new("prune-deltas-only");
    block_on(async {
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let main = chain(&repo, tmp.path(), "main").await;
        repo.generate_static_delta(Some(&main[0]), &main[1], &DeltaOptions::default())
            .await
            .unwrap();
        repo.generate_static_delta(Some(&main[1]), &main[2], &DeltaOptions::default())
            .await
            .unwrap();
        let before = repo.list_objects().await.unwrap();

        // The commit the option names is the branch head, which a plain
        // `delete_commit` refuses; this run keys the deltas on it and touches
        // no loose object.
        let stats = repo
            .prune(&PruneOptions {
                delete_commit: Some(main[2]),
                static_deltas_only: true,
                ..PruneOptions::default()
            })
            .await
            .unwrap();
        assert_eq!(stats.pruned_objects, 0);
        assert_eq!(stats.total_objects, before.len());
        assert_eq!(repo.list_objects().await.unwrap(), before);
        assert_eq!(
            repo.list_static_deltas().await.unwrap(),
            vec![format!("{}-{}", main[0].to_hex(), main[1].to_hex())],
            "the delta the named commit targets goes and the other stays"
        );
    });
}

#[test]
fn static_deltas_only_removes_a_nested_delta_directory() {
    let tmp = TmpDir::new("prune-deltas-nested");
    block_on(async {
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let main = chain(&repo, tmp.path(), "main").await;
        repo.generate_static_delta(Some(&main[1]), &main[2], &DeltaOptions::default())
            .await
            .unwrap();
        let dir = tmp
            .path()
            .join("repo")
            .join(static_delta_relative_dir(Some(&main[1]), &main[2]));
        std::fs::create_dir_all(dir.join("n1/n2")).unwrap();
        std::fs::write(dir.join("n1/n2/f"), b"nested\n").unwrap();

        repo.prune(&PruneOptions {
            delete_commit: Some(main[2]),
            static_deltas_only: true,
            ..PruneOptions::default()
        })
        .await
        .unwrap();
        assert!(
            std::fs::symlink_metadata(&dir).is_err(),
            "the delta directory goes whole, its subdirectories included"
        );
        assert!(dir.parent().unwrap().is_dir(), "the fanout stays");
    });
}

#[test]
fn static_delta_sweep_leaves_a_symlink_at_the_delta_path() {
    let tmp = TmpDir::new("prune-deltas-symlink");
    block_on(async {
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let main = chain(&repo, tmp.path(), "main").await;
        let victim = tmp.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("file"), b"keep\n").unwrap();
        let link = tmp
            .path()
            .join("repo")
            .join(static_delta_relative_dir(Some(&main[1]), &main[2]));
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        repo.prune(&PruneOptions {
            delete_commit: Some(main[2]),
            static_deltas_only: true,
            ..PruneOptions::default()
        })
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(victim.join("file")).unwrap(),
            b"keep\n",
            "the sweep follows no symlink at the delta path"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "an entry at the delta path that is not a directory stays"
        );
    });
}

#[test]
fn a_tombstone_is_written_for_every_commit_a_delete_commit_run_removes() {
    let tmp = TmpDir::new("prune-tombstone-delete-commit");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;

        repo.prune(&PruneOptions {
            refs_only: true,
            depth: 0,
            delete_commit: Some(main[0]),
            ..PruneOptions::default()
        })
        .await
        .unwrap();
        for c in [&main[0], &main[1]] {
            assert!(
                repo.has_object(ObjectType::TombstoneCommit, c)
                    .await
                    .unwrap(),
                "`delete_commit` turns tombstone writing on for the whole run"
            );
        }
        assert!(
            !repo
                .has_object(ObjectType::TombstoneCommit, &main[2])
                .await
                .unwrap(),
            "a commit the run kept gets none"
        );
    });
}

#[test]
fn a_tombstone_is_written_when_the_config_key_is_set() {
    let tmp = TmpDir::new("prune-tombstone-config");
    block_on(async {
        let repo = repo_at(tmp.path()).await;
        let main = chain(&repo, tmp.path(), "main").await;
        let mut keyfile = repo.config().keyfile().clone();
        keyfile
            .set_string("core", "tombstone-commits", "true")
            .unwrap();
        repo.write_config(&keyfile).await.unwrap();
        // The handle keeps the configuration it was opened with, so the key is
        // read by a fresh one.
        let repo = Repo::open(&tmp.path().join("repo")).await.unwrap();

        // The two commits below the head, and the dirtree and the file object
        // each of them alone reached.
        let stats = prune(&repo, |o| o.depth = 0).await;
        assert_eq!(stats.pruned_objects, 6);
        for c in [&main[0], &main[1]] {
            assert!(
                repo.has_object(ObjectType::TombstoneCommit, c)
                    .await
                    .unwrap()
            );
        }
        // A second run reads the markers and counts neither them nor itself
        // into the deletion.
        let again = prune(&repo, |o| o.depth = 0).await;
        assert_eq!(again.pruned_objects, 0);
        assert_eq!(
            again.total_objects,
            repo.list_objects().await.unwrap().len() - 2,
            "tombstone markers are outside the total"
        );
    });
}

#[test]
fn prune_options_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PruneOptions>();
    assert_send_sync::<PruneStats>();
}
