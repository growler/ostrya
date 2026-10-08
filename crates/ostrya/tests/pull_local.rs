//! Local pull between two repositories.
//!
//! ostrya builds the source repositories, so these tests cover the flags and
//! the traversal without the `ostree` command. The interop tests that need the
//! `ostree` command build a source with it, or give it what ostrya pulled. If
//! the `ostree` command is absent, these tests skip.

mod common;

use std::collections::HashSet;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{TmpDir, file_inventory, ostree_available, wait_for_commit_under_guard, within};
use futures_lite::future::poll_once;
use ostrya::{
    Checksum, CollectionRef, CommitModifier, CommitModifierFlags, CommitOptions, CommitState,
    CreateOptions, DeltaOptions, DetachedMetadataFilter, DetachedMetadataFilterFn, Ed25519Signer,
    Error, FilterResult, FsckOptions, MutableTree, ObjectName, ObjectType, PullFlags, PullOptions,
    PullStats, PullVerify, Repo, RepoMode, SummaryOptions, Type, Value,
};
use ostrya_rt::{block_on, spawn};

/// A fixed timestamp that makes the commits of a source repository reproducible.
const FIXED_TS: u64 = 1_700_000_000;

// --- helpers -------------------------------------------------------------

/// Runs the `ostree` command and asserts that it succeeds.
fn ostree(args: &[&str]) -> Vec<u8> {
    let out = Command::new("ostree")
        .args(args)
        .output()
        .expect("run ostree");
    assert!(
        out.status.success(),
        "ostree {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Builds a small source tree under `dir`: two regular files with different
/// modes, a symlink, and a nested subdirectory.
fn build_tree(dir: &Path, marker: &[u8]) {
    std::fs::create_dir_all(dir.join("subdir")).unwrap();
    std::fs::write(dir.join("hello.txt"), marker).unwrap();
    std::fs::write(dir.join("exec.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    std::fs::write(dir.join("subdir/nested.txt"), b"nested\n").unwrap();
    symlink("hello.txt", dir.join("link")).unwrap();
    std::fs::set_permissions(
        dir.join("hello.txt"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::set_permissions(dir.join("exec.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Returns the `ostree.ref-binding` metadata dict that binds a commit to
/// `branch`.
fn ref_binding(branch: &str) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("ostree.ref-binding".to_owned()),
        Value::Variant(Box::new((
            Type::parse("as").unwrap(),
            Value::Array(vec![Value::Str(branch.to_owned())]),
        ))),
    ])])
}

/// Commits subtree `sub` of `base` into `repo` under `branch`, with a fixed
/// timestamp and the ref binding of the branch.
async fn commit_tree(
    repo: &Repo,
    base: &Path,
    sub: &str,
    branch: &str,
    parent: Option<Checksum>,
) -> Checksum {
    commit_tree_with(
        repo,
        base,
        sub,
        branch,
        parent,
        CommitModifierFlags::SKIP_XATTRS,
        None,
    )
    .await
}

/// Commits subtree `sub` as [`commit_tree`] does, under the given modifier
/// flags. If `owner` is set, the commit declares that uid and gid and ignores
/// the uid and gid of the source files.
async fn commit_tree_with(
    repo: &Repo,
    base: &Path,
    sub: &str,
    branch: &str,
    parent: Option<Checksum>,
    flags: CommitModifierFlags,
    owner: Option<(u32, u32)>,
) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(flags);
    if let Some((uid, gid)) = owner {
        modifier.owner_uid = Some(uid);
        modifier.owner_gid = Some(gid);
    }
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new(sub), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                parent,
                subject: Some(format!("{branch} {sub}")),
                timestamp: Some(FIXED_TS),
                metadata: Some(ref_binding(branch)),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref(branch, Some(&commit));
    txn.commit().await.unwrap();
    commit
}

/// Creates a repository of the given mode under `base/<name>`.
async fn make_repo(base: &Path, name: &str, mode: RepoMode) -> (PathBuf, Repo) {
    let path = base.join(name);
    let repo = Repo::create(&path, CreateOptions::new(mode)).await.unwrap();
    (path, repo)
}

/// Creates a repository of the given mode in a setgid `2775` directory owned by
/// group `gid`. The setgid bit gives `gid` to the repository root and to each
/// directory under it, so each object written there gets `gid`.
async fn make_repo_in_group(base: &Path, name: &str, mode: RepoMode, gid: u32) -> (PathBuf, Repo) {
    let parent = base.join(format!("{name}-group"));
    std::fs::create_dir(&parent).unwrap();
    std::os::unix::fs::chown(&parent, None, Some(gid)).unwrap();
    // Set the group first, because a change of the owner of a file can clear
    // its setgid bit.
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o2775)).unwrap();
    let path = parent.join(name);
    let repo = Repo::create(&path, CreateOptions::new(mode)).await.unwrap();
    (path, repo)
}

/// Creates a source repository with two commits on `main`. The second commit is
/// a child of the first. Returns the path, the handle, and the two checksums.
async fn source_repo(base: &Path, mode: RepoMode) -> (PathBuf, Repo, Checksum, Checksum) {
    build_tree(&base.join("v1"), b"hello one\n");
    build_tree(&base.join("v2"), b"hello two\n");
    let (path, repo) = make_repo(base, "src", mode).await;
    let c1 = commit_tree(&repo, base, "v1", "main", None).await;
    let c2 = commit_tree(&repo, base, "v2", "main", Some(c1)).await;
    (path, repo, c1, c2)
}

/// Creates a source repository as [`source_repo`] does, with canonical
/// permissions. Each object then carries the header that a bare-user-only
/// destination stores, so that destination can import it under its own name.
async fn canonical_source_repo(base: &Path, mode: RepoMode) -> (PathBuf, Repo, Checksum, Checksum) {
    build_tree(&base.join("v1"), b"hello one\n");
    build_tree(&base.join("v2"), b"hello two\n");
    let (path, repo) = make_repo(base, "src", mode).await;
    let flags = CommitModifierFlags::SKIP_XATTRS | CommitModifierFlags::CANONICAL_PERMISSIONS;
    let c1 = commit_tree_with(&repo, base, "v1", "main", None, flags, None).await;
    let c2 = commit_tree_with(&repo, base, "v2", "main", Some(c1), flags, None).await;
    (path, repo, c1, c2)
}

/// Creates a source repository as [`source_repo`] does, with a declared
/// non-root owner. Each object then carries a uid and gid that a bare-user-only
/// destination discards. The commit declares the owner and ignores the ids of
/// the process, so the objects are the same for each user that runs the test.
async fn owned_source_repo(base: &Path, mode: RepoMode) -> (PathBuf, Repo, Checksum, Checksum) {
    build_tree(&base.join("v1"), b"hello one\n");
    build_tree(&base.join("v2"), b"hello two\n");
    let (path, repo) = make_repo(base, "src", mode).await;
    let flags = CommitModifierFlags::SKIP_XATTRS;
    let owner = Some((1000, 1000));
    let c1 = commit_tree_with(&repo, base, "v1", "main", None, flags, owner).await;
    let c2 = commit_tree_with(&repo, base, "v2", "main", Some(c1), flags, owner).await;
    (path, repo, c1, c2)
}

/// Returns the path of the `.commitmeta` file of a commit in a repository
/// directory.
fn commitmeta_path(repo_dir: &Path, commit: &Checksum) -> PathBuf {
    let hex = commit.to_hex();
    repo_dir
        .join("objects")
        .join(&hex[..2])
        .join(format!("{}.commitmeta", &hex[2..]))
}

/// Returns the `(device, inode)` of a loose object in a repository, or `None`
/// if the object is absent.
fn object_ino(repo_dir: &Path, name: &str) -> Option<(u64, u64)> {
    let path = repo_dir.join("objects").join(&name[..2]).join(&name[2..]);
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Returns the permission bits of a loose object in a repository, or `None` if
/// the object is absent.
fn object_mode(repo_dir: &Path, name: &str) -> Option<u32> {
    let path = repo_dir.join("objects").join(&name[..2]).join(&name[2..]);
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| m.mode() & 0o7777)
}

/// Pulls `main` from `src` into `dst` under `flags`.
async fn pull_main(dst: &Repo, src: &Repo, flags: PullFlags) {
    dst.pull_local(
        src,
        PullOptions {
            refs: vec!["main".to_owned()],
            flags,
            ..PullOptions::default()
        },
    )
    .await
    .unwrap();
}

/// Returns the sorted names of the loose objects in a repository. Each name is
/// flattened from `<2>/<62>.<ext>` to `<64>.<ext>`.
fn object_names(repo_dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let objects = repo_dir.join("objects");
    let Ok(fanouts) = std::fs::read_dir(&objects) else {
        return out;
    };
    for fanout in fanouts.flatten() {
        let prefix = fanout.file_name().to_string_lossy().into_owned();
        if prefix.len() != 2 {
            continue;
        }
        for entry in std::fs::read_dir(fanout.path()).unwrap().flatten() {
            out.push(format!("{prefix}{}", entry.file_name().to_string_lossy()));
        }
    }
    out.sort();
    out
}

/// Returns the content object of `commit` with the lowest checksum that is a
/// regular file with a payload. The checksum order makes the pick independent
/// of the iteration order of the traversal set.
async fn first_regular_content(repo: &Repo, commit: &Checksum) -> ostrya::ObjectName {
    let mut names: Vec<ostrya::ObjectName> = repo
        .traverse_commit(commit, 0)
        .await
        .unwrap()
        .into_iter()
        .filter(|name| name.ty == ostrya::ObjectType::File)
        .collect();
    names.sort_by_key(|name| name.checksum.to_hex());
    for name in names {
        let file = repo.load_file(&name.checksum).await.unwrap();
        if let ostrya::FileKind::Regular { size } = file.kind
            && size > 0
        {
            return name;
        }
    }
    panic!("the commit holds no regular content object with a payload");
}

/// Returns the symlink content object of `commit` with the lowest checksum. The
/// checksum order makes the pick independent of the iteration order of the
/// traversal set.
async fn symlink_content(repo: &Repo, commit: &Checksum) -> ostrya::ObjectName {
    let mut names: Vec<ostrya::ObjectName> = repo
        .traverse_commit(commit, 0)
        .await
        .unwrap()
        .into_iter()
        .filter(|name| name.ty == ostrya::ObjectType::File)
        .collect();
    names.sort_by_key(|name| name.checksum.to_hex());
    for name in names {
        if repo.load_file(&name.checksum).await.unwrap().is_symlink() {
            return name;
        }
    }
    panic!("the commit holds no symlink content object");
}

/// Returns the dirtree object of the subdirectory of `commit`. It is the one
/// dirtree that the commit reaches and that is not the root. `build_tree` makes
/// exactly one such dirtree.
async fn subdir_dirtree(repo: &Repo, commit: &Checksum) -> ostrya::ObjectName {
    let bytes = repo
        .load_object_bytes(ostrya::ObjectType::Commit, commit)
        .await
        .unwrap();
    let root = ostrya::Commit::parse(&bytes).unwrap().root_dirtree;
    repo.traverse_commit(commit, 0)
        .await
        .unwrap()
        .into_iter()
        .find(|name| name.ty == ostrya::ObjectType::DirTree && name.checksum != root)
        .expect("the commit holds a subdirectory dirtree")
}

/// Returns the absolute path of a loose object in a repository.
fn object_path(repo_dir: &Path, name: &ostrya::ObjectName, mode: RepoMode) -> PathBuf {
    repo_dir.join("objects").join(name.loose_path(mode))
}

/// Returns `true` if a loose object carries the named xattr.
fn has_xattr(path: &Path, name: &str) -> bool {
    let mut buf = [0u8; 256];
    rustix::fs::getxattr(path, name, &mut buf).is_ok()
}

/// Returns `true` if a loose object carries the `user.ostreemeta` xattr.
fn has_ostreemeta(path: &Path) -> bool {
    has_xattr(path, "user.ostreemeta")
}

/// Returns a group of the process other than `own`, or `None` if the process is
/// in one group only. A test uses it to give a source object an ownership that
/// no write into the destination repository produces.
fn other_group(own: u32) -> Option<u32> {
    let out = Command::new("id").arg("-G").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|g| g.parse::<u32>().ok())
        .find(|g| *g != own)
}

/// The environment variable that turns the multi-group skip into a failure. If
/// a harness sets it, the harness declares that a second group is available. A
/// run without a second group is then a broken harness, and the test fails.
const REQUIRE_MULTIGROUP: &str = "OSTRYA_REQUIRE_MULTIGROUP";

/// Returns a group of the process other than `own`, for a test that cannot run
/// without one. These tests are the only coverage of the ownership gate.
/// Without this check, a single-group harness reports the gate as tested when
/// no test exercised it. An example is a container that runs as root with only
/// the group `root`. If [`REQUIRE_MULTIGROUP`] is set, a missing group fails
/// the test. If it is not set, the test skips and prints a message.
fn required_other_group(own: u32) -> Option<u32> {
    if let Some(gid) = other_group(own) {
        return Some(gid);
    }
    assert!(
        std::env::var_os(REQUIRE_MULTIGROUP).is_none(),
        "{REQUIRE_MULTIGROUP} is set and the process belongs to a single group, \
         so the ownership gate cannot be exercised"
    );
    eprintln!("skipped: the process belongs to a single group");
    None
}

/// Returns the path of a loose object from the flattened `<64>.<ext>` name that
/// [`object_names`] returns.
fn flat_object_path(repo_dir: &Path, flat: &str) -> PathBuf {
    repo_dir.join("objects").join(&flat[..2]).join(&flat[2..])
}

/// Creates a repository of the given mode with `[ex-integrity] fsverity` set to
/// `fsverity`. The function reopens the repository so that it parses the
/// setting.
async fn verity_repo(base: &Path, name: &str, mode: RepoMode, fsverity: &str) -> (PathBuf, Repo) {
    let (path, repo) = make_repo(base, name, mode).await;
    drop(repo);
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!("[ex-integrity]\nfsverity={fsverity}\n"));
    std::fs::write(&config, text).unwrap();
    let repo = Repo::open(&path).await.unwrap();
    (path, repo)
}

/// Returns `true` if a loose object is sealed with fs-verity. A sealed regular
/// file refuses an open for writing. Each examined object is writable by its
/// owner, so the permissions do not cause a refused open.
fn is_sealed(path: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(path).is_err()
}

/// Returns `true` if the file system of `base` can seal a file with fs-verity.
/// The probe commits into a `maybe` repository, which succeeds in both cases.
async fn fs_supports_verity(base: &Path) -> bool {
    build_tree(&base.join("verity-probe"), b"probe\n");
    let (path, repo) = verity_repo(base, "verity-probe-repo", RepoMode::BareUser, "maybe").await;
    commit_tree(&repo, base, "verity-probe", "probe", None).await;
    object_names(&path)
        .iter()
        .any(|flat| is_sealed(&flat_object_path(&path, flat)))
}

/// Creates a repository of the given mode with `min-free-space-percent=100`,
/// which reserves the whole file system. A transaction there starts with a
/// write budget of zero, so each object that allocates blocks makes it fail.
/// The function reopens the repository so that it parses the setting.
async fn zero_budget_repo(base: &Path, name: &str, mode: RepoMode) -> (PathBuf, Repo) {
    let (path, repo) = make_repo(base, name, mode).await;
    drop(repo);
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("min-free-space-percent=100\n");
    std::fs::write(&config, text).unwrap();
    let repo = Repo::open(&path).await.unwrap();
    (path, repo)
}

/// Returns `true` if the `.commitpartial` marker of a commit is present.
fn has_partial_marker(repo_dir: &Path, commit: &Checksum) -> bool {
    repo_dir
        .join("state")
        .join(format!("{}.commitpartial", commit.to_hex()))
        .exists()
}

// --- the basic pull ------------------------------------------------------

#[test]
fn pulls_a_ref_its_commit_and_its_tree() {
    let tmp = TmpDir::new("pull-basic");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        let stats = dst
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(dst.resolve_rev("main", false).await.unwrap(), Some(c2));
        assert!(
            dst.has_object(ostrya::ObjectType::Commit, &c2)
                .await
                .unwrap()
        );
        // At depth 0, the pull does not import the parent commit.
        assert!(
            !dst.has_object(ostrya::ObjectType::Commit, &c1)
                .await
                .unwrap()
        );
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(!has_partial_marker(&dst_dir, &c2));
        assert!(stats.metadata_imported > 0 && stats.content_imported > 0);

        // The destination holds each object that the pulled commit reaches, and
        // no other object.
        let reached = src.traverse_commit(&c2, 0).await.unwrap();
        for name in &reached {
            assert!(
                dst.has_object(name.ty, &name.checksum).await.unwrap(),
                "{name} missing from the destination"
            );
        }
        assert_eq!(object_names(&dst_dir).len(), reached.len());
        assert!(object_names(&src_dir).len() > reached.len());

        // A second pull imports nothing.
        let again = dst
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(again.metadata_imported, 0);
        assert_eq!(again.content_imported, 0);
    });
}

#[test]
fn an_empty_ref_list_pulls_every_ref() {
    let tmp = TmpDir::new("pull-all-refs");
    block_on(async {
        let base = tmp.path();
        build_tree(&base.join("v1"), b"hello\n");
        let (_src_dir, src) = make_repo(base, "src", RepoMode::Archive).await;
        let a = commit_tree(&src, base, "v1", "a", None).await;
        let b = commit_tree(&src, base, "v1", "team/b", None).await;
        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        dst.pull_local(&src, PullOptions::default()).await.unwrap();

        assert_eq!(dst.resolve_rev("a", false).await.unwrap(), Some(a));
        assert_eq!(dst.resolve_rev("team/b", false).await.unwrap(), Some(b));
    });
}

#[test]
fn a_remote_name_writes_the_ref_under_refs_remotes() {
    let tmp = TmpDir::new("pull-remote");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                remote: Some("origin".to_owned()),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert!(dst_dir.join("refs/remotes/origin/main").exists());
        assert!(!dst_dir.join("refs/heads/main").exists());
        assert_eq!(
            dst.resolve_rev("origin:main", false).await.unwrap(),
            Some(c2)
        );
    });
}

#[test]
fn a_local_pull_ignores_the_mirror_flag() {
    let tmp = TmpDir::new("pull-mirror");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        // The flag applies to `Repo::pull` only. A local pull writes its refs
        // under the prefix that `remote` names, with or without the flag.
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                remote: Some("origin".to_owned()),
                flags: PullFlags::MIRROR,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert!(dst_dir.join("refs/remotes/origin/main").exists());
        assert!(!dst_dir.join("refs/heads/main").exists());
        assert_eq!(
            dst.resolve_rev("origin:main", false).await.unwrap(),
            Some(c2)
        );
    });
}

#[test]
fn depth_follows_parent_commits() {
    let tmp = TmpDir::new("pull-depth");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                depth: -1,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        for commit in [c1, c2] {
            assert!(
                dst.has_object(ostrya::ObjectType::Commit, &commit)
                    .await
                    .unwrap()
            );
            assert_eq!(
                dst.commit_state(&commit).await.unwrap(),
                CommitState::Normal
            );
        }
    });
}

#[test]
fn depth_does_not_depend_on_ref_order() {
    let tmp = TmpDir::new("pull-depth-order");
    block_on(async {
        let base = tmp.path();
        // A chain c1 <- c2 <- c3 <- c4, with `old` at c3 and `main` at c4. At
        // depth 1, `main` reaches c3 and `old` reaches c2.
        for (sub, marker) in [
            ("v1", "one\n"),
            ("v2", "two\n"),
            ("v3", "three\n"),
            ("v4", "four\n"),
        ] {
            build_tree(&base.join(sub), marker.as_bytes());
        }
        let (_src_dir, src) = make_repo(base, "src", RepoMode::Archive).await;
        let c1 = commit_tree(&src, base, "v1", "main", None).await;
        let c2 = commit_tree(&src, base, "v2", "main", Some(c1)).await;
        let c3 = commit_tree(&src, base, "v3", "old", Some(c2)).await;
        let c4 = commit_tree(&src, base, "v4", "main", Some(c3)).await;

        for (name, refs) in [
            ("forward", vec!["main".to_owned(), "old".to_owned()]),
            ("reverse", vec!["old".to_owned(), "main".to_owned()]),
        ] {
            let (_dst_dir, dst) = make_repo(base, name, RepoMode::Archive).await;
            dst.pull_local(
                &src,
                PullOptions {
                    refs,
                    depth: 1,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

            for commit in [c4, c3, c2] {
                assert!(
                    dst.has_object(ostrya::ObjectType::Commit, &commit)
                        .await
                        .unwrap(),
                    "{name}: commit {commit} missing"
                );
            }
            assert!(
                !dst.has_object(ostrya::ObjectType::Commit, &c1)
                    .await
                    .unwrap(),
                "{name}: commit {c1} is past the requested depth"
            );
        }
    });
}

#[test]
fn a_deep_pull_imports_every_commits_tree() {
    let tmp = TmpDir::new("pull-deep-tree");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                depth: -1,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The two commits have different root trees and share the tree of the
        // subdirectory. A walk that descends into each dirtree once must still
        // list the full trees of both commits.
        let reached = src.traverse_commit(&c2, -1).await.unwrap();
        for name in &reached {
            assert!(
                dst.has_object(name.ty, &name.checksum).await.unwrap(),
                "{name} missing from the destination"
            );
        }
        assert_eq!(object_names(&dst_dir).len(), reached.len());
    });
}

#[test]
fn a_parent_the_source_lacks_ends_the_chain() {
    let tmp = TmpDir::new("pull-truncated");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        // Delete the parent commit object. The source then has a truncated
        // history, and the deep pull must accept it.
        std::fs::remove_file(
            src_dir
                .join("objects")
                .join(&c1.to_hex()[..2])
                .join(format!("{}.commit", &c1.to_hex()[2..])),
        )
        .unwrap();

        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                depth: -1,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert!(
            dst.has_object(ostrya::ObjectType::Commit, &c2)
                .await
                .unwrap()
        );
        assert!(
            !dst.has_object(ostrya::ObjectType::Commit, &c1)
                .await
                .unwrap()
        );
    });
}

#[test]
fn a_missing_ref_fails_before_anything_is_imported() {
    let tmp = TmpDir::new("pull-missing-ref");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, _c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        let err = dst
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["nosuch".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RefNotFound(ref name) if name == "nosuch"));
        assert!(object_names(&dst_dir).is_empty());
    });
}

// --- how an object is imported -------------------------------------------

#[test]
fn a_same_mode_import_hardlinks_the_loose_object() {
    let tmp = TmpDir::new("pull-hardlink");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let reached = src.traverse_commit(&c2, 0).await.unwrap();
        assert!(!reached.is_empty());
        for name in &reached {
            let object = name.loose_path(RepoMode::Archive).replace('/', "");
            assert_eq!(
                object_ino(&src_dir, &object),
                object_ino(&dst_dir, &object),
                "{name} should share the source inode"
            );
        }
    });
}

#[test]
fn force_copy_clones_the_object_instead_of_linking() {
    let tmp = TmpDir::new("pull-force-copy");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::BareUser).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                flags: PullFlags::FORCE_COPY,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let reached = src.traverse_commit(&c2, 0).await.unwrap();
        for name in &reached {
            let object = name.loose_path(RepoMode::BareUser).replace('/', "");
            let src_ino = object_ino(&src_dir, &object).unwrap();
            let dst_ino = object_ino(&dst_dir, &object).unwrap();
            assert_ne!(src_ino, dst_ino, "{name} should be a fresh inode");
            let src_path = src_dir
                .join("objects")
                .join(&object[..2])
                .join(&object[2..]);
            let dst_path = dst_dir
                .join("objects")
                .join(&object[..2])
                .join(&object[2..]);
            let src_meta = std::fs::symlink_metadata(&src_path).unwrap();
            let dst_meta = std::fs::symlink_metadata(&dst_path).unwrap();
            // Both repositories are bare-user, so the destination gives the
            // copy the mode that the source gave the object at its write.
            assert_eq!(
                src_meta.permissions().mode(),
                dst_meta.permissions().mode(),
                "{name} should carry the bare-user mode"
            );
            if src_meta.is_file() {
                assert_eq!(
                    std::fs::read(&src_path).unwrap(),
                    std::fs::read(&dst_path).unwrap()
                );
            }
        }

        // Each copy reads back as the object of its name. A bare-user object
        // keeps its logical metadata in an xattr, so the clone must carry it.
        let report = dst.fsck(&ostrya::FsckOptions::new()).await.unwrap();
        assert!(report.is_ok(), "fsck reported {:?}", report.errors);
    });
}

#[test]
fn a_refused_link_imports_a_content_object_through_its_header() {
    let tmp = TmpDir::new("pull-refused-link");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::BareUser).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;

        // A bare-user object keeps its logical metadata in `user.ostreemeta`,
        // so the mode bits and xattrs of its inode tell nothing about the
        // object. Change them in the source so that they differ from the
        // logical metadata. The copy in the destination then shows which of the
        // two the import uses for its inode.
        let content = first_regular_content(&src, &c2).await;
        let src_path = object_path(&src_dir, &content, RepoMode::BareUser);
        std::fs::set_permissions(&src_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        rustix::fs::setxattr(
            &src_path,
            "user.stray",
            b"1",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                flags: PullFlags::FORCE_COPY,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The import used the header of the object, so the copy carries what a
        // commit into this repository writes. That is the bare-user mode
        // derived from the logical mode, plus `user.ostreemeta`, and nothing of
        // the source inode.
        let dst_path = object_path(&dst_dir, &content, RepoMode::BareUser);
        let logical = src.load_file(&content.checksum).await.unwrap().mode;
        assert_eq!(
            std::fs::symlink_metadata(&dst_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            (logical & 0o775) | 0o400
        );
        assert!(has_ostreemeta(&dst_path));
        assert!(!has_xattr(&dst_path, "user.stray"));
        assert_eq!(
            std::fs::read(&src_path).unwrap(),
            std::fs::read(&dst_path).unwrap()
        );

        let report = dst.fsck(&ostrya::FsckOptions::new()).await.unwrap();
        assert!(report.is_ok(), "fsck reported {:?}", report.errors);
    });
}

#[test]
fn a_cloned_metadata_object_takes_the_destination_policy() {
    let tmp = TmpDir::new("pull-clone-metadata");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Bare).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Bare).await;

        // The baseline: the inode that a write into the destination gives a
        // metadata object. A commit in the destination supplies it.
        build_tree(&base.join("baseline"), b"baseline\n");
        let baseline = commit_tree(&dst, base, "baseline", "baseline", None).await;
        let want = std::fs::symlink_metadata(object_path(
            &dst_dir,
            &ostrya::ObjectName::new(baseline, ostrya::ObjectType::Commit),
            RepoMode::Bare,
        ))
        .unwrap();

        // A metadata object carries no header, so no part of the source inode
        // is authoritative. Make the source inode differ from what a write
        // produces:
        // - the mode 0600, where a write gives 0644
        // - a stray xattr
        // - a second group of the process, if it has one. A bare destination is
        //   the mode that does a chown.
        let name = ostrya::ObjectName::new(c2, ostrya::ObjectType::Commit);
        let src_path = object_path(&src_dir, &name, RepoMode::Bare);
        std::fs::set_permissions(&src_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        rustix::fs::setxattr(
            &src_path,
            "user.stray",
            b"1",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        if let Some(gid) = other_group(want.gid()) {
            std::os::unix::fs::chown(&src_path, None, Some(gid)).unwrap();
        }

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                flags: PullFlags::FORCE_COPY,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The clone carries the inode policy of the destination.
        let dst_path = object_path(&dst_dir, &name, RepoMode::Bare);
        let got = std::fs::symlink_metadata(&dst_path).unwrap();
        assert_eq!(
            got.permissions().mode() & 0o7777,
            want.permissions().mode() & 0o7777
        );
        assert_eq!((got.uid(), got.gid()), (want.uid(), want.gid()));
        assert!(!has_xattr(&dst_path, "user.stray"));
        assert_eq!(
            std::fs::read(&src_path).unwrap(),
            std::fs::read(&dst_path).unwrap()
        );

        let report = dst.fsck(&ostrya::FsckOptions::new()).await.unwrap();
        assert!(report.is_ok(), "fsck reported {:?}", report.errors);
    });
}

#[test]
fn differing_ownership_refuses_the_link_and_writes_the_destinations_own() {
    let tmp = TmpDir::new("pull-owner-gate");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::BareUserShared).await;
        let own = std::fs::symlink_metadata(&src_dir).unwrap().gid();
        let Some(gid) = required_other_group(own) else {
            return;
        };
        let (dst_dir, dst) = make_repo_in_group(base, "dst", RepoMode::BareUserShared, gid).await;

        // The baseline: the owner of an object that a write into the
        // destination makes. Its group is the group of the setgid directory,
        // and the group of the process differs from it.
        build_tree(&base.join("baseline"), b"baseline\n");
        let baseline = commit_tree(&dst, base, "baseline", "baseline", None).await;
        let want = std::fs::symlink_metadata(object_path(
            &dst_dir,
            &ostrya::ObjectName::new(baseline, ostrya::ObjectType::Commit),
            RepoMode::BareUserShared,
        ))
        .unwrap();
        assert_eq!(want.gid(), gid);
        assert_ne!(want.gid(), own);

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // A shared source inode brings the group of the source into the
        // destination. The group of the destination is the group that can
        // repair it, so the pull writes each object as a new inode.
        let reached = src.traverse_commit(&c2, 0).await.unwrap();
        assert!(!reached.is_empty());
        for name in &reached {
            let object = name.loose_path(RepoMode::BareUserShared).replace('/', "");
            assert_ne!(
                object_ino(&src_dir, &object),
                object_ino(&dst_dir, &object),
                "{name} should be a fresh inode"
            );
            let got =
                std::fs::symlink_metadata(object_path(&dst_dir, name, RepoMode::BareUserShared))
                    .unwrap();
            assert_eq!(
                (got.uid(), got.gid()),
                (want.uid(), want.gid()),
                "{name} should carry the destination's ownership"
            );
        }

        // The `ostree` command does not check this repository, because it
        // refuses to open a bare-user-shared repository.
        let report = dst.fsck(&ostrya::FsckOptions::new()).await.unwrap();
        assert!(report.is_ok(), "fsck reported {:?}", report.errors);
    });
}

#[test]
fn a_bare_content_object_links_whatever_the_repositories_ownership() {
    let tmp = TmpDir::new("pull-bare-owner-gate");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Bare).await;
        let own = std::fs::symlink_metadata(&src_dir).unwrap().gid();
        let Some(gid) = required_other_group(own) else {
            return;
        };
        let (dst_dir, dst) = make_repo_in_group(base, "dst", RepoMode::Bare, gid).await;

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let reached = src.traverse_commit(&c2, 0).await.unwrap();
        assert!(!reached.is_empty());
        let mut content = 0;
        let mut metadata = 0;
        for name in &reached {
            let object = name.loose_path(RepoMode::Bare).replace('/', "");
            let got =
                std::fs::symlink_metadata(object_path(&dst_dir, name, RepoMode::Bare)).unwrap();
            if name.ty == ostrya::ObjectType::File {
                // The uid and gid of a bare content object come from the header
                // that its checksum covers. A write here produces the same inode
                // as the source inode, so the link stands.
                content += 1;
                assert_eq!(
                    object_ino(&src_dir, &object),
                    object_ino(&dst_dir, &object),
                    "{name} should share the source inode"
                );
                assert_eq!(got.gid(), own, "{name} should carry the header's group");
            } else {
                // A metadata object carries no header, so its owner is the
                // writer, and the pull refuses the link.
                metadata += 1;
                assert_ne!(
                    object_ino(&src_dir, &object),
                    object_ino(&dst_dir, &object),
                    "{name} should be a fresh inode"
                );
                assert_eq!(
                    got.gid(),
                    gid,
                    "{name} should carry the destination's group"
                );
            }
        }
        assert!(content > 0 && metadata > 0);

        // The inode of a bare object is its metadata. fsck computes each
        // checksum again, and this proves that the linked inodes equal the
        // inodes that a write here produces.
        let report = dst.fsck(&ostrya::FsckOptions::new()).await.unwrap();
        assert!(report.is_ok(), "fsck reported {:?}", report.errors);
        if ostree_available() {
            ostree(&[&format!("--repo={}", dst_dir.display()), "fsck"]);
        }
    });
}

#[test]
fn crossing_repository_modes_reingests_the_content() {
    let tmp = TmpDir::new("pull-cross-mode");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The commit identity does not depend on the mode, so the same
        // checksums arrive. The destination stores the content objects in its
        // own form.
        for name in src.traverse_commit(&c2, 0).await.unwrap() {
            assert!(dst.has_object(name.ty, &name.checksum).await.unwrap());
        }
        let report = dst.fsck(&ostrya::FsckOptions::new()).await.unwrap();
        assert!(report.is_ok(), "fsck reported {:?}", report.errors);
    });
}

#[test]
fn a_bare_family_cross_mode_pull_clones_the_content() {
    let tmp = TmpDir::new("pull-bare-family");
    block_on(async {
        let base = tmp.path();
        // A bare-user-only destination imports an object only under the name
        // that its own stored form hashes to, so the source commit uses
        // canonical permissions.
        let (src_dir, src, _c1, c2) = canonical_source_repo(base, RepoMode::BareUser).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUserOnly).await;

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The modes of the bare family store the same payload bytes for a
        // regular file. They differ only on the inode, so the pull clones the
        // object. The bytes arrive unchanged on a new inode with the policy of
        // the destination. For bare-user-only, that policy is the canonical
        // mode and no xattr.
        let content = first_regular_content(&src, &c2).await;
        let src_path = object_path(&src_dir, &content, RepoMode::BareUser);
        let dst_path = object_path(&dst_dir, &content, RepoMode::BareUserOnly);
        let flat = content.loose_path(RepoMode::BareUser).replace('/', "");
        assert_ne!(
            object_ino(&src_dir, &flat),
            object_ino(&dst_dir, &flat),
            "{content} should be a fresh inode"
        );
        assert_eq!(
            std::fs::read(&src_path).unwrap(),
            std::fs::read(&dst_path).unwrap()
        );
        assert!(has_ostreemeta(&src_path));
        assert!(!has_ostreemeta(&dst_path));
        let logical = src.load_file(&content.checksum).await.unwrap().mode;
        assert_eq!(
            std::fs::symlink_metadata(&dst_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            logical & 0o755
        );

        // The object reads back as the header of its name. That header is what
        // the writer of the destination stores for the object.
        let landed = dst.load_file(&content.checksum).await.unwrap();
        assert_eq!((landed.uid, landed.gid), (0, 0));
        assert_eq!(landed.mode, (logical & 0o755) | 0o100000);
        assert!(landed.xattrs.is_empty());

        for name in src.traverse_commit(&c2, 0).await.unwrap() {
            assert!(dst.has_object(name.ty, &name.checksum).await.unwrap());
        }
        let report = dst.fsck(&ostrya::FsckOptions::new()).await.unwrap();
        assert!(report.is_ok(), "fsck reported {:?}", report.errors);
    });
}

#[test]
fn a_bare_user_only_destination_refuses_a_header_it_cannot_store() {
    let tmp = TmpDir::new("pull-buo-header");
    block_on(async {
        let base = tmp.path();
        // The source commit declares a non-root owner, so each object carries
        // a uid and gid that this mode discards. If the commit takes the ids of
        // the process and the test runs as root, the objects carry 0:0. This
        // mode stores 0:0, so the refusal under test does not occur.
        let (_src_dir, src, _c1, _c2) = owned_source_repo(base, RepoMode::BareUser).await;
        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUserOnly).await;

        let err = dst
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err}");
        assert!(
            err.to_string()
                .contains("cannot be imported under its own name"),
            "{err}"
        );
        assert_eq!(dst.resolve_rev("main", true).await.unwrap(), None);
    });
}

#[test]
fn a_symlink_object_is_shared_between_bare_user_and_bare_user_shared() {
    let tmp = TmpDir::new("pull-symlink-share");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::BareUser).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUserShared).await;

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The two modes store a symlink object in the same form, so the pull
        // hardlinks it. The form is a 0644 regular file that holds the target
        // plus a NUL, with the logical metadata in `user.ostreemeta`. The two
        // modes give a regular file different inode modes, so the pull clones it.
        let link = symlink_content(&src, &c2).await;
        let link_flat = link.loose_path(RepoMode::BareUser).replace('/', "");
        assert_eq!(
            object_ino(&src_dir, &link_flat),
            object_ino(&dst_dir, &link_flat),
            "{link} should share the source inode"
        );

        let content = first_regular_content(&src, &c2).await;
        let content_flat = content.loose_path(RepoMode::BareUser).replace('/', "");
        assert_ne!(
            object_ino(&src_dir, &content_flat),
            object_ino(&dst_dir, &content_flat),
            "{content} should be a fresh inode"
        );
        assert_eq!(
            std::fs::symlink_metadata(object_path(&dst_dir, &content, RepoMode::BareUserShared))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );

        let report = dst.fsck(&ostrya::FsckOptions::new()).await.unwrap();
        assert!(report.is_ok(), "fsck reported {:?}", report.errors);
    });
}

#[test]
fn a_verity_destination_seals_every_imported_object() {
    let tmp = TmpDir::new("pull-verity");
    block_on(async {
        let base = tmp.path();
        if !fs_supports_verity(base).await {
            eprintln!("skipping: filesystem does not support fs-verity");
            return;
        }
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::BareUser).await;
        let (dst_dir, dst) = verity_repo(base, "dst", RepoMode::BareUser, "yes").await;

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // bare-user stores each object as a regular file, and this destination
        // seals each regular-file object that it writes. A hardlink cannot
        // carry that seal. fs-verity is a property of an inode, so a seal on a
        // shared inode also seals the copy of the source. As a result, each
        // object arrives sealed on a new inode, and the source stays unchanged.
        let names = object_names(&dst_dir);
        assert!(!names.is_empty(), "the pull imported nothing");
        for flat in &names {
            assert!(
                is_sealed(&flat_object_path(&dst_dir, flat)),
                "imported object not sealed: {flat}"
            );
            assert_ne!(
                object_ino(&src_dir, flat),
                object_ino(&dst_dir, flat),
                "{flat} should be a fresh inode"
            );
            assert!(
                !is_sealed(&flat_object_path(&src_dir, flat)),
                "the pull sealed the source's copy: {flat}"
            );
        }
        for name in src.traverse_commit(&c2, 0).await.unwrap() {
            assert!(dst.has_object(name.ty, &name.checksum).await.unwrap());
        }
        let report = dst.fsck(&ostrya::FsckOptions::new()).await.unwrap();
        assert!(report.is_ok(), "fsck reported {:?}", report.errors);
    });
}

#[test]
fn a_bare_split_xattrs_destination_is_refused() {
    let tmp = TmpDir::new("pull-split-xattrs-dst");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, _c2) = source_repo(base, RepoMode::BareUser).await;
        // A branch whose tree is one regular file. The only content object that
        // a full pull of it imports is then an object of the clone path. `main`
        // also holds a symlink, which a bare-user source and this destination
        // store in different forms. In a full pull of `main`, the re-ingest
        // path for that symlink can give the refusal, so `main` does not
        // isolate the clone path.
        std::fs::create_dir(base.join("flat")).unwrap();
        std::fs::write(base.join("flat/only.txt"), b"only\n").unwrap();
        commit_tree(&src, base, "flat", "flat", None).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareSplitXattrs).await;

        // Both import paths reach the destination, and each checks the mode of
        // the destination before it touches the source. The link path serves
        // each metadata object and each same-mode content object. The clone
        // path serves a content object whose payload the two modes share, as
        // bare-user and bare-split-xattrs do. Neither path writes the
        // `.file-xattrs` and `.file-xattrs-link` sidecars that this mode needs,
        // so the destination refuses the import. The rest of the write surface
        // refuses the mode in the same way. A commit-only pull isolates the link
        // path, and a full pull of `flat` reaches the clone path.
        for (ref_name, flags) in [("main", PullFlags::COMMIT_ONLY), ("flat", PullFlags::NONE)] {
            let err = dst
                .pull_local(
                    &src,
                    PullOptions {
                        refs: vec![ref_name.to_owned()],
                        flags,
                        ..PullOptions::default()
                    },
                )
                .await
                .unwrap_err();

            assert!(
                matches!(err, Error::Unsupported(_)),
                "bare-split-xattrs is read-only, got {err:?}"
            );
            assert!(object_names(&dst_dir).is_empty());
            assert!(dst.resolve_rev(ref_name, true).await.unwrap().is_none());
        }
    });
}

#[test]
fn a_read_only_file_imports_on_every_path() {
    let tmp = TmpDir::new("pull-readonly");
    block_on(async {
        let base = tmp.path();
        // The tree holds a file with no owner-write bit. Such a file is common
        // in a system tree. In bare-user, the logical metadata is in a
        // `user.ostreemeta` xattr, and the kernel checks the write permission of
        // the inode for that xattr. As a result, each path that applies the
        // inode policy of the destination must set the xattr before the mode
        // removes that bit.
        let tree = base.join("ro");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("ro.txt"), b"read only\n").unwrap();
        std::fs::set_permissions(tree.join("ro.txt"), std::fs::Permissions::from_mode(0o444))
            .unwrap();

        let (src_dir, src) = make_repo(base, "src", RepoMode::BareUser).await;
        let commit = commit_tree(&src, base, "ro", "main", None).await;
        let (_archive_dir, archive) = make_repo(base, "src-archive", RepoMode::Archive).await;
        let archived = commit_tree(&archive, base, "ro", "main", None).await;
        assert_eq!(commit, archived, "the commit identity is mode-independent");

        let content = first_regular_content(&src, &commit).await;
        let object = content.loose_path(RepoMode::BareUser).replace('/', "");

        // The link path shares the read-only inode of the source.
        let (link_dir, link_dst) = make_repo(base, "link", RepoMode::BareUser).await;
        pull_main(&link_dst, &src, PullFlags::NONE).await;
        assert_eq!(
            object_ino(&src_dir, &object),
            object_ino(&link_dir, &object),
            "the link path shares the inode"
        );

        // The clone path applies the inode policy of the destination.
        let (copy_dir, copy_dst) = make_repo(base, "copy", RepoMode::BareUser).await;
        pull_main(&copy_dst, &src, PullFlags::FORCE_COPY).await;
        assert_ne!(
            object_ino(&src_dir, &object),
            object_ino(&copy_dir, &object),
            "force_copy writes a fresh inode"
        );

        // A pull from an archive source writes the object through the ingest
        // path.
        let (ingest_dir, ingest_dst) = make_repo(base, "ingest", RepoMode::BareUser).await;
        pull_main(&ingest_dst, &archive, PullFlags::NONE).await;

        for (dir, dst) in [
            (&link_dir, &link_dst),
            (&copy_dir, &copy_dst),
            (&ingest_dir, &ingest_dst),
        ] {
            assert_eq!(
                object_mode(dir, &object),
                Some(0o444),
                "stored mode in {}",
                dir.display()
            );
            let file = dst.load_file(&content.checksum).await.unwrap();
            assert_eq!(
                file.mode & 0o7777,
                0o444,
                "logical mode in {}",
                dir.display()
            );
        }
    });
}

// --- free space ----------------------------------------------------------

#[test]
fn a_shared_import_debits_no_free_space() {
    let tmp = TmpDir::new("pull-budget-shared");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::BareUser).await;
        // The config reserves the whole file system, so the pull has no room
        // for one new block. A same-mode pull hardlinks each object, and a
        // hardlink allocates no block.
        let (dst_dir, dst) = zero_budget_repo(base, "dst", RepoMode::BareUser).await;

        let stats = dst
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

        let reached = src.traverse_commit(&c2, 0).await.unwrap();
        assert!(!reached.is_empty());
        for name in &reached {
            let object = name.loose_path(RepoMode::BareUser).replace('/', "");
            assert_eq!(
                object_ino(&src_dir, &object),
                object_ino(&dst_dir, &object),
                "{name} should share the source inode"
            );
        }
        // The stats count the storage that the imported objects use. The shared
        // inodes hold that storage, whatever the budget is.
        assert!(stats.content_bytes_written > 0);
        // The pull never writes the payload of a hardlinked object, so the
        // figure that the `ostree` command reports as the content written is
        // zero.
        assert_eq!(stats.content_bytes_unpacked, 0);
        assert!(!has_partial_marker(&dst_dir, &c2));
    });
}

#[test]
fn a_reingested_import_debits_the_free_space_budget() {
    let tmp = TmpDir::new("pull-budget-reingest");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::BareUser).await;
        // Archive stores the payload of a regular file in a framed, deflated
        // form that the bare family does not share. The pull writes each content
        // object as a new file and charges it against the budget, which the
        // reserve keeps at zero.
        let (dst_dir, dst) = zero_budget_repo(base, "dst", RepoMode::Archive).await;

        let err = dst
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, Error::InsufficientFreeSpace { shortfall } if shortfall > 0),
            "expected a free-space error, got {err:?}"
        );
        assert!(object_names(&dst_dir).is_empty());
        assert!(dst.resolve_rev("main", true).await.unwrap().is_none());
        assert!(!has_partial_marker(&dst_dir, &c2));
    });
}

// --- commit state --------------------------------------------------------

#[test]
fn commit_metadata_only_leaves_the_commit_partial() {
    let tmp = TmpDir::new("pull-commit-only");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        let stats = dst
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    flags: PullFlags::COMMIT_ONLY,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(stats.metadata_imported, 1);
        assert_eq!(stats.content_imported, 0);
        assert_eq!(
            object_names(&dst_dir),
            vec![format!("{}.commit", c2.to_hex())]
        );
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Partial);
        // The marker that the `ostree` command writes for a pull is
        // zero-length. The marker of fsck holds a state byte.
        let marker = dst_dir
            .join("state")
            .join(format!("{}.commitpartial", c2.to_hex()));
        assert_eq!(std::fs::metadata(&marker).unwrap().len(), 0);

        // A complete pull imports the remaining objects and removes the marker.
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(!has_partial_marker(&dst_dir, &c2));
    });
}

#[test]
fn a_failed_pull_publishes_nothing_and_clears_the_marker() {
    let tmp = TmpDir::new("pull-failed");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        // Delete one content object that the tip commit reaches.
        let content = src
            .traverse_commit(&c2, 0)
            .await
            .unwrap()
            .into_iter()
            .find(|name| name.ty == ostrya::ObjectType::File)
            .unwrap();
        let object = content.loose_path(RepoMode::Archive);
        std::fs::remove_file(src_dir.join("objects").join(&object)).unwrap();

        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        let err = dst
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }));

        assert!(object_names(&dst_dir).is_empty());
        assert!(dst.resolve_rev("main", true).await.unwrap().is_none());
        // The pull did not publish the commit, so its marker goes away with the
        // objects that the transaction discarded.
        assert!(!has_partial_marker(&dst_dir, &c2));
    });
}

#[test]
fn a_pull_leaves_an_fsck_marker_as_it_found_it() {
    let tmp = TmpDir::new("pull-fsck-marker");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        let opts = || PullOptions {
            refs: vec!["main".to_owned()],
            ..PullOptions::default()
        };
        dst.pull_local(&src, opts()).await.unwrap();

        // Remove one content object from the destination, so fsck marks the
        // commit partial with its own state byte.
        let content = dst
            .traverse_commit(&c2, 0)
            .await
            .unwrap()
            .into_iter()
            .find(|name| name.ty == ostrya::ObjectType::File)
            .unwrap();
        let object = content.loose_path(RepoMode::Archive);
        std::fs::remove_file(dst_dir.join("objects").join(&object)).unwrap();
        let report = dst.fsck(&ostrya::FsckOptions::new()).await.unwrap();
        assert!(!report.is_ok());
        let marker = dst_dir
            .join("state")
            .join(format!("{}.commitpartial", c2.to_hex()));
        assert_eq!(std::fs::read(&marker).unwrap(), b"f");

        // Remove the same object from the source. The repair pull then marks
        // the commit, which it finds partial already, and fails on the missing
        // object.
        std::fs::remove_file(src_dir.join("objects").join(&object)).unwrap();
        let err = dst.pull_local(&src, opts()).await.unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }));

        // The state byte of fsck stays, because the pull does not rewrite a
        // marker that it finds.
        assert_eq!(std::fs::read(&marker).unwrap(), b"f");
    });
}

// --- trust and checks ----------------------------------------------------

#[test]
fn untrusted_rejects_a_corrupt_source_object() {
    let tmp = TmpDir::new("pull-untrusted");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::BareUser).await;
        // Use a regular file with a payload. A changed payload byte keeps the
        // object decodable and changes only its checksum. bare-user stores a
        // symlink object as its target plus a NUL, and a changed byte in such
        // an object makes the decode fail.
        let content = first_regular_content(&src, &c2).await;
        let path = src_dir
            .join("objects")
            .join(content.loose_path(RepoMode::BareUser));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        // Trusted: the pull links the object and does not read it, so the
        // corruption goes to the destination. The `ostree` command does the
        // same.
        let (_trusted_dir, trusted) = make_repo(base, "trusted", RepoMode::BareUser).await;
        trusted
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert!(
            trusted
                .has_object(content.ty, &content.checksum)
                .await
                .unwrap()
        );

        // Untrusted: the pull reads each object first, so it fails.
        let (untrusted_dir, untrusted) = make_repo(base, "untrusted", RepoMode::BareUser).await;
        let err = untrusted
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    flags: PullFlags::UNTRUSTED,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::ChecksumMismatch { expected, .. } if expected == content.checksum),
            "unexpected error: {err}"
        );
        assert!(object_names(&untrusted_dir).is_empty());
    });
}

#[test]
fn a_cross_mode_clone_is_trusted_and_untrusted_verifies_it() {
    let tmp = TmpDir::new("pull-clone-trust");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::BareUser).await;
        let content = first_regular_content(&src, &c2).await;
        let path = object_path(&src_dir, &content, RepoMode::BareUser);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        // A bare-family clone moves the payload and does not hash it, so a
        // trusted pull carries the corruption across modes. The same-mode link
        // does the same. A re-ingest catches the corruption.
        let (trusted_dir, trusted) = make_repo(base, "trusted", RepoMode::BareUserShared).await;
        trusted
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(object_path(
                &trusted_dir,
                &content,
                RepoMode::BareUserShared
            ))
            .unwrap(),
            bytes
        );

        // `UNTRUSTED` reads the object once, before the clone, and rejects it.
        let (untrusted_dir, untrusted) =
            make_repo(base, "untrusted", RepoMode::BareUserShared).await;
        let err = untrusted
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    flags: PullFlags::UNTRUSTED,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::ChecksumMismatch { expected, .. } if expected == content.checksum),
            "unexpected error: {err}"
        );
        assert!(object_names(&untrusted_dir).is_empty());
    });
}

#[test]
fn a_reingest_rejects_a_corrupt_payload_with_or_without_untrusted() {
    let tmp = TmpDir::new("pull-reingest-trust");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::BareUser).await;
        let content = first_regular_content(&src, &c2).await;
        let path = object_path(&src_dir, &content, RepoMode::BareUser);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        // Archive stores the payload of a regular file in a framed, deflated
        // form that the bare family does not share. As a result, the object
        // crosses on the re-ingest path. That path hashes the object as it streams and
        // compares the result with the name. It rejects the corruption with or
        // without `UNTRUSTED`. For this reason, the flag can skip its own read
        // of an object that goes to this path.
        for flags in [PullFlags::NONE, PullFlags::UNTRUSTED] {
            let (dst_dir, dst) =
                make_repo(base, &format!("dst-{}", flags.bits()), RepoMode::Archive).await;
            let err = dst
                .pull_local(
                    &src,
                    PullOptions {
                        refs: vec!["main".to_owned()],
                        flags,
                        ..PullOptions::default()
                    },
                )
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::ChecksumMismatch { expected, .. } if expected == content.checksum),
                "flags {flags:?}: unexpected error: {err}"
            );
            assert!(object_names(&dst_dir).is_empty());
        }
    });
}

#[test]
fn untrusted_rejects_a_corrupt_metadata_object() {
    let tmp = TmpDir::new("pull-untrusted-meta");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        // Change the subject of the commit in place. The object still parses,
        // so the pull gets to the checksum verification and does not fail on
        // the decode.
        let path = src_dir.join("objects").join(
            ostrya::ObjectName::new(c2, ostrya::ObjectType::Commit).loose_path(RepoMode::Archive),
        );
        let mut bytes = std::fs::read(&path).unwrap();
        let subject = b"main v2";
        let at = bytes
            .windows(subject.len())
            .position(|w| w == subject)
            .expect("the commit carries its subject verbatim");
        bytes[at] = b'M';
        std::fs::write(&path, &bytes).unwrap();

        let (_untrusted_dir, untrusted) = make_repo(base, "untrusted", RepoMode::Archive).await;
        let err = untrusted
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    flags: PullFlags::UNTRUSTED,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::ChecksumMismatch { expected, .. } if expected == c2),
            "unexpected error: {err}"
        );

        // Trusted: the pull links the metadata object and does not read it, so
        // the corruption goes to the destination. The `ostree` command does the
        // same.
        let (_trusted_dir, trusted) = make_repo(base, "trusted", RepoMode::Archive).await;
        trusted
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert!(
            trusted
                .has_object(ostrya::ObjectType::Commit, &c2)
                .await
                .unwrap()
        );
    });
}

#[test]
fn a_ref_binding_that_omits_the_pulled_ref_is_rejected() {
    let tmp = TmpDir::new("pull-binding");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        // Add a second ref for the same commit. The binding of the commit does
        // not list that ref.
        src.set_ref_immediate("other", Some(&c2)).await.unwrap();

        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        let err = dst
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["other".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err}");
        assert!(err.to_string().contains("other"));

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["other".to_owned()],
                flags: PullFlags::DISABLE_VERIFY_BINDINGS,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(dst.resolve_rev("other", false).await.unwrap(), Some(c2));
    });
}

#[test]
fn a_commit_with_no_binding_key_is_accepted() {
    let tmp = TmpDir::new("pull-no-binding");
    block_on(async {
        let base = tmp.path();
        build_tree(&base.join("v1"), b"hello\n");
        let (_src_dir, src) = make_repo(base, "src", RepoMode::Archive).await;
        let commit = {
            let txn = src.transaction().await.unwrap();
            let mut mtree = MutableTree::new();
            let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
            let dfd = std::fs::File::open(base).unwrap();
            txn.write_dfd_to_mtree(
                dfd.as_fd(),
                Path::new("v1"),
                &mut mtree,
                Some(&mut modifier),
            )
            .await
            .unwrap();
            let root = txn.write_mtree(&mut mtree).await.unwrap();
            let commit = txn
                .write_commit(
                    CommitOptions {
                        timestamp: Some(FIXED_TS),
                        ..CommitOptions::default()
                    },
                    &root,
                )
                .await
                .unwrap();
            txn.set_ref("free", Some(&commit));
            txn.commit().await.unwrap();
            commit
        };

        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["free".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(dst.resolve_rev("free", false).await.unwrap(), Some(commit));
    });
}

#[test]
fn bareuseronly_files_rejects_a_world_writable_mode() {
    let tmp = TmpDir::new("pull-bareuseronly");
    block_on(async {
        let base = tmp.path();
        let tree = base.join("v1");
        build_tree(&tree, b"hello\n");
        std::fs::set_permissions(
            tree.join("hello.txt"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let (_src_dir, src) = make_repo(base, "src", RepoMode::Archive).await;
        commit_tree(&src, base, "v1", "main", None).await;

        // The flag applies the check to any destination.
        let (_flagged_dir, flagged) = make_repo(base, "flagged", RepoMode::Archive).await;
        let err = flagged
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    flags: PullFlags::BAREUSERONLY_FILES,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err}");
        assert!(err.to_string().contains("invalid mode"));

        // A bare-user-only destination refuses the same object without the flag,
        // under its own rule. That mode cannot store the mode bits of this file.
        let (_buo_dir, buo) = make_repo(base, "buo", RepoMode::BareUserOnly).await;
        let err = buo
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err}");

        // Without the flag, an archive destination accepts the object.
        let (_plain_dir, plain) = make_repo(base, "plain", RepoMode::Archive).await;
        plain
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
    });
}

// --- detached metadata and local caches ----------------------------------

#[test]
fn detached_metadata_travels_with_the_commit() {
    let tmp = TmpDir::new("pull-detached");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let meta = Value::Array(vec![Value::Tuple(vec![
            Value::Str("demo".to_owned()),
            Value::Variant(Box::new((
                Type::parse("s").unwrap(),
                Value::Str("value".to_owned()),
            ))),
        ])]);
        src.write_commit_detached_metadata(&c2, Some(&meta))
            .await
            .unwrap();

        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            dst.read_commit_detached_metadata(&c2).await.unwrap(),
            Some(meta)
        );
    });
}

/// Returns an `a{sv}` with two properties: a stand-in for a signature, and a
/// property that the repository keeps local.
fn two_property_metadata() -> Value {
    let entry = |key: &str, value: &str| {
        Value::Tuple(vec![
            Value::Str(key.to_owned()),
            Value::Variant(Box::new((
                Type::parse("s").unwrap(),
                Value::Str(value.to_owned()),
            ))),
        ])
    };
    Value::Array(vec![
        entry("ostree.gpgsigs", "a signature"),
        entry("build.gc-roots", "repository-local"),
    ])
}

/// Returns the value of one property of the stored detached metadata of a
/// commit.
async fn detached_property(repo: &Repo, commit: &Checksum, key: &str) -> Option<Value> {
    repo.read_commit_detached_metadata(commit)
        .await
        .unwrap()
        .and_then(|dict| dict.dict_get(key).cloned())
}

#[test]
fn a_filter_drops_the_properties_it_skips_and_keeps_the_rest() {
    let tmp = TmpDir::new("pull-detached-filter");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        src.write_commit_detached_metadata(&c2, Some(&two_property_metadata()))
            .await
            .unwrap();

        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                detached_metadata_filter: DetachedMetadataFilter::new(|_, key, _| {
                    if key == "build.gc-roots" {
                        FilterResult::Skip
                    } else {
                        FilterResult::Allow
                    }
                }),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            detached_property(&dst, &c2, "ostree.gpgsigs").await,
            Some(Value::Variant(Box::new((
                Type::parse("s").unwrap(),
                Value::Str("a signature".to_owned()),
            )))),
            "an allowed property is stored"
        );
        assert_eq!(
            detached_property(&dst, &c2, "build.gc-roots").await,
            None,
            "a skipped property is not"
        );
        // The source stays unchanged. The filter changes only what the
        // destination stores.
        assert_eq!(
            src.read_commit_detached_metadata(&c2).await.unwrap(),
            Some(two_property_metadata())
        );
    });
}

#[test]
fn a_filter_that_allows_everything_stores_the_source_bytes() {
    let tmp = TmpDir::new("pull-detached-filter-allow");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        src.write_commit_detached_metadata(&c2, Some(&two_property_metadata()))
            .await
            .unwrap();

        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                detached_metadata_filter: DetachedMetadataFilter::new(|_, _, _| {
                    FilterResult::Allow
                }),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read(commitmeta_path(&dst_dir, &c2)).unwrap(),
            std::fs::read(commitmeta_path(&src_dir, &c2)).unwrap(),
            "the stored bytes are the source's, byte for byte"
        );
    });
}

#[test]
fn a_filter_that_skips_everything_stores_nothing() {
    let tmp = TmpDir::new("pull-detached-filter-skip");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        src.write_commit_detached_metadata(&c2, Some(&two_property_metadata()))
            .await
            .unwrap();

        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                detached_metadata_filter: DetachedMetadataFilter::new(|_, _, _| FilterResult::Skip),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert!(
            !commitmeta_path(&dst_dir, &c2).exists(),
            "no detached metadata is written"
        );
        assert_eq!(
            dst.read_commit_detached_metadata(&c2).await.unwrap(),
            None,
            "which reads back as no metadata at all"
        );
    });
}

/// A guard holds the update lock, so the pull fails at the step that writes
/// detached metadata and refs. The pull keeps the marker of the commit that it
/// published, and writes no `.commitmeta` and no ref. The next pull completes
/// the commit and its detached metadata.
#[test]
fn a_pull_that_times_out_at_the_ref_step_keeps_its_markers() {
    let tmp = TmpDir::new("pull-ref-step-timeout");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        src.write_commit_detached_metadata(&c2, Some(&two_property_metadata()))
            .await
            .unwrap();
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        drop(dst);
        let config = dst_dir.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("lock-timeout-secs=0\n");
        std::fs::write(&config, text).unwrap();
        let dst = Repo::open(&dst_dir).await.unwrap();

        let guard = dst.begin_update().await.unwrap();
        let opts = || PullOptions {
            refs: vec!["main".to_owned()],
            ..PullOptions::default()
        };
        let err = dst.pull_local(&src, opts()).await.unwrap_err();
        assert!(matches!(err, Error::LockTimeout { secs: 0 }), "{err:?}");
        assert!(
            dst.has_object(ostrya::ObjectType::Commit, &c2)
                .await
                .unwrap()
        );
        assert!(has_partial_marker(&dst_dir, &c2), "the marker stays");
        assert!(
            !commitmeta_path(&dst_dir, &c2).exists(),
            "no detached metadata"
        );
        assert_eq!(dst.resolve_ref_tip("main").await.unwrap(), None);
        guard.finish().await.unwrap();

        dst.pull_local(&src, opts()).await.unwrap();
        assert!(!has_partial_marker(&dst_dir, &c2));
        assert_eq!(
            std::fs::read(commitmeta_path(&dst_dir, &c2)).unwrap(),
            std::fs::read(commitmeta_path(&src_dir, &c2)).unwrap()
        );
        assert_eq!(dst.resolve_ref_tip("main").await.unwrap(), Some(c2));
    });
}

/// One handle of a repository holds a guard, and a pull runs into a second
/// handle. The pull publishes its objects and waits at the step that writes
/// detached metadata and refs. With `lock-timeout-secs=-1`, it completes that
/// step after the guard finishes.
#[test]
fn a_pull_under_a_guard_publishes_its_objects_and_waits_at_the_ref_step() {
    let tmp = TmpDir::new("pull-under-guard");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        src.write_commit_detached_metadata(&c2, Some(&two_property_metadata()))
            .await
            .unwrap();
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        drop(dst);
        let config = dst_dir.join("config");
        let text = std::fs::read_to_string(&config).unwrap();
        std::fs::write(
            &config,
            text.replacen("[core]\n", "[core]\nlock-timeout-secs=-1\n", 1),
        )
        .unwrap();
        let a = Repo::open(&dst_dir).await.unwrap();
        let b = Repo::open(&dst_dir).await.unwrap();

        let guard = a.begin_update().await.unwrap();
        let mut task = spawn(async move {
            let opts = PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            };
            b.pull_local(&src, opts).await
        });
        wait_for_commit_under_guard(&a, &c2, &mut task).await;
        assert_eq!(a.resolve_ref_tip("main").await.unwrap(), None);
        assert!(has_partial_marker(&dst_dir, &c2), "the marker stays");
        assert!(
            !commitmeta_path(&dst_dir, &c2).exists(),
            "no detached metadata"
        );
        assert!(poll_once(&mut task).await.is_none(), "the pull waits");
        guard.finish().await.unwrap();

        within("the pull", task).await.unwrap();
        assert_eq!(a.resolve_ref_tip("main").await.unwrap(), Some(c2));
        assert!(!has_partial_marker(&dst_dir, &c2));
        assert_eq!(
            std::fs::read(commitmeta_path(&dst_dir, &c2)).unwrap(),
            std::fs::read(commitmeta_path(&src_dir, &c2)).unwrap()
        );
    });
}

/// `DetachedMetadataFilter::excluding` is the constructor that the `ostrya`
/// CLI uses for `[ex-ostrya] detached-metadata-exclude`. The filter drops the
/// properties that the list names and keeps each other property.
#[test]
fn an_exclude_list_drops_the_named_properties_and_keeps_the_rest() {
    let tmp = TmpDir::new("pull-detached-exclude");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        src.write_commit_detached_metadata(&c2, Some(&two_property_metadata()))
            .await
            .unwrap();

        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                detached_metadata_filter: DetachedMetadataFilter::excluding(["build.gc-roots"]),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            detached_property(&dst, &c2, "build.gc-roots").await,
            None,
            "a property the list names is not stored"
        );
        assert_eq!(
            detached_property(&dst, &c2, "ostree.gpgsigs").await,
            Some(Value::Variant(Box::new((
                Type::parse("s").unwrap(),
                Value::Str("a signature".to_owned()),
            )))),
            "a property it does not name is stored"
        );
    });
}

/// The CLI treats an empty exclude list as an absent key and uses the default
/// filter. A filter built directly from an empty list also keeps each
/// property.
#[test]
fn an_empty_exclude_list_keeps_every_property() {
    let tmp = TmpDir::new("pull-detached-exclude-empty");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        src.write_commit_detached_metadata(&c2, Some(&two_property_metadata()))
            .await
            .unwrap();

        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                detached_metadata_filter: DetachedMetadataFilter::excluding(Vec::<String>::new()),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read(commitmeta_path(&dst_dir, &c2)).unwrap(),
            std::fs::read(commitmeta_path(&src_dir, &c2)).unwrap(),
            "the stored bytes are the source's, byte for byte"
        );
    });
}

/// A filter that allows no property keeps the `.commitmeta` of the
/// destination. A source that holds no `.commitmeta` has the same result.
#[test]
fn a_filter_that_skips_everything_keeps_the_destinations_own_metadata() {
    let tmp = TmpDir::new("pull-detached-filter-skip-keep");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        src.write_commit_detached_metadata(&c2, Some(&two_property_metadata()))
            .await
            .unwrap();

        // The destination holds the commit and detached metadata of its own.
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        let local = dict_of("local.signature", "the destination's own");
        dst.write_commit_detached_metadata(&c2, Some(&local))
            .await
            .unwrap();
        let before = std::fs::read(commitmeta_path(&dst_dir, &c2)).unwrap();

        // `from_fn` takes a callback that the caller holds.
        let skip: DetachedMetadataFilterFn =
            std::sync::Arc::new(|_: &Checksum, _: &str, _: &Value| FilterResult::Skip);
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                detached_metadata_filter: DetachedMetadataFilter::from_fn(skip),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read(commitmeta_path(&dst_dir, &c2)).unwrap(),
            before,
            "the destination's own detached metadata stands"
        );
    });
}

/// Returns an `a{sv}` with one string property.
fn dict_of(key: &str, value: &str) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str(key.to_owned()),
        Value::Variant(Box::new((
            Type::parse("s").unwrap(),
            Value::Str(value.to_owned()),
        ))),
    ])])
}

#[test]
fn the_filter_sees_the_commit_it_is_filtering_for() {
    let tmp = TmpDir::new("pull-detached-filter-commit");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        for commit in [&c1, &c2] {
            src.write_commit_detached_metadata(commit, Some(&two_property_metadata()))
                .await
                .unwrap();
        }

        // The filter drops the private property of the tip only. The parent
        // keeps its private property.
        let tip = c2;
        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                depth: -1,
                detached_metadata_filter: DetachedMetadataFilter::new(move |commit, key, _| {
                    if *commit == tip && key == "build.gc-roots" {
                        FilterResult::Skip
                    } else {
                        FilterResult::Allow
                    }
                }),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(detached_property(&dst, &c2, "build.gc-roots").await, None);
        assert!(
            detached_property(&dst, &c1, "build.gc-roots")
                .await
                .is_some(),
            "the parent commit is filtered on its own terms"
        );
    });
}

#[test]
fn a_localcache_repo_supplies_an_object_the_source_lacks() {
    let tmp = TmpDir::new("pull-localcache");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;

        // The cache holds all objects, and the source lacks one content
        // object.
        let (_cache_dir, cache) = make_repo(base, "cache", RepoMode::Archive).await;
        cache
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    flags: PullFlags::FORCE_COPY,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        let content = src
            .traverse_commit(&c2, 0)
            .await
            .unwrap()
            .into_iter()
            .find(|name| name.ty == ostrya::ObjectType::File)
            .unwrap();
        std::fs::remove_file(
            src_dir
                .join("objects")
                .join(content.loose_path(RepoMode::Archive)),
        )
        .unwrap();

        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                localcache_repos: vec![cache.clone()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(dst.has_object(content.ty, &content.checksum).await.unwrap());
    });
}

#[test]
fn a_localcache_supplied_dirtree_is_descended_into() {
    let tmp = TmpDir::new("pull-cache-dirtree");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;

        // The cache holds all objects, and the source lacks the dirtree of the
        // subdirectory. Only the cache can then name the objects under it.
        let (_cache_dir, cache) = make_repo(base, "cache", RepoMode::Archive).await;
        cache
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    flags: PullFlags::FORCE_COPY,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        let dirtree = subdir_dirtree(&src, &c2).await;
        std::fs::remove_file(object_path(&src_dir, &dirtree, RepoMode::Archive)).unwrap();

        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                localcache_repos: vec![cache.clone()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The full tree arrives, with the content under the dirtree from the
        // cache, and the published commit is complete.
        let reached = cache.traverse_commit(&c2, 0).await.unwrap();
        for name in &reached {
            assert!(
                dst.has_object(name.ty, &name.checksum).await.unwrap(),
                "{name} missing from the destination"
            );
        }
        assert_eq!(object_names(&dst_dir).len(), reached.len());
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(!has_partial_marker(&dst_dir, &c2));
        assert_eq!(dst.resolve_rev("main", false).await.unwrap(), Some(c2));

        // Without a cache, no repository names the objects under the missing
        // dirtree. The pull cannot reach them, so it fails and publishes no
        // commit with a hole.
        let (bare_dir, bare) = make_repo(base, "dst2", RepoMode::Archive).await;
        let err = bare
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }));
        assert!(bare.resolve_rev("main", true).await.unwrap().is_none());
        assert!(!has_partial_marker(&bare_dir, &c2));
    });
}

// --- interop with the ostree command ------------------------------------

#[test]
fn pulls_from_a_tool_built_repository_and_the_tool_reads_the_result() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("pull-interop");
    block_on(async {
        let base = tmp.path();
        let tree = base.join("v1");
        build_tree(&tree, b"hello interop\n");
        let src_dir = base.join("src");
        let src_arg = format!("--repo={}", src_dir.display());
        ostree(&[&src_arg, "init", "--mode=archive"]);
        let tip = String::from_utf8(ostree(&[
            &src_arg,
            "commit",
            "-b",
            "main",
            "--timestamp=2020-01-01 00:00:00 +0000",
            &format!("--tree=dir={}", tree.display()),
        ]))
        .unwrap()
        .trim()
        .to_owned();

        for (name, mode) in [
            ("dst-archive", RepoMode::Archive),
            ("dst-bare-user", RepoMode::BareUser),
        ] {
            let src = Repo::open(&src_dir).await.unwrap();
            let (dst_dir, dst) = make_repo(base, name, mode).await;
            dst.pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

            let dst_arg = format!("--repo={}", dst_dir.display());
            // The `ostree` command resolves the ref, reads the tree, and
            // verifies each object that ostrya imported.
            let resolved = String::from_utf8(ostree(&[&dst_arg, "rev-parse", "main"])).unwrap();
            assert_eq!(resolved.trim(), tip, "{name}");
            ostree(&[&dst_arg, "fsck"]);
            let listing = String::from_utf8(ostree(&[&dst_arg, "ls", "-R", "main"])).unwrap();
            assert!(listing.contains("/hello.txt"), "{name}: {listing}");
            let content = ostree(&[&dst_arg, "cat", "main", "/hello.txt"]);
            assert_eq!(content, b"hello interop\n", "{name}");
        }
    });
}

#[test]
fn the_tool_validates_a_bare_family_cross_mode_clone() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("pull-interop-clone");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Bare).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;

        // bare and bare-user store the same payload for a regular file and
        // differ on the inode, so each regular file crosses on the clone path.
        // The `ostree` command checks the result of the inode policy of the
        // destination. Its fsck computes the checksum of each object again from
        // the stored form. For bare-user, that form is the payload plus the
        // `user.ostreemeta` that the clone wrote.
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let dst_arg = format!("--repo={}", dst_dir.display());
        let resolved = String::from_utf8(ostree(&[&dst_arg, "rev-parse", "main"])).unwrap();
        assert_eq!(resolved.trim(), c2.to_hex());
        ostree(&[&dst_arg, "fsck"]);
        assert_eq!(
            ostree(&[&dst_arg, "cat", "main", "/hello.txt"]),
            b"hello two\n"
        );
        let listing = String::from_utf8(ostree(&[&dst_arg, "ls", "-R", "main"])).unwrap();
        assert!(listing.contains("/link -> hello.txt"), "{listing}");
    });
}

#[test]
fn the_tool_pulls_from_a_repository_the_port_wrote() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("pull-interop-reverse");
    block_on(async {
        let base = tmp.path();
        let (src_dir, _src, _c1, c2) = source_repo(base, RepoMode::Archive).await;

        let dst_dir = base.join("tool-dst");
        let dst_arg = format!("--repo={}", dst_dir.display());
        ostree(&[&dst_arg, "init", "--mode=bare-user"]);
        ostree(&[&dst_arg, "pull-local", &src_dir.to_string_lossy(), "main"]);
        let resolved = String::from_utf8(ostree(&[&dst_arg, "rev-parse", "main"])).unwrap();
        assert_eq!(resolved.trim(), c2.to_hex());
        ostree(&[&dst_arg, "fsck"]);
    });
}

// --- signature verification ----------------------------------------------

/// The fixed ed25519 keypair that signs the signed sources.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";
/// A second public key, which stands for a key that the destination does not
/// trust.
const OTHER_PUBLIC_B64: &str = "8+dqdDZWIesQQO95CRCSoSm2543BNK7FgOVwPyuUquU=";

/// Creates a destination repository under `base/dst` with the remote `origin`
/// in its config. The `[remote]` section gets the keys of `extra`. A local
/// pull reads no URL, so the section states only the verification policy.
async fn dest_with_remote(base: &Path, extra: &str) -> Repo {
    let (path, repo) = make_repo(base, "dst", RepoMode::Archive).await;
    drop(repo);
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!(
        "\n[remote \"origin\"]\nurl=file:///dev/null\n{extra}"
    ));
    std::fs::write(&config, text).unwrap();
    Repo::open(&path).await.unwrap()
}

/// Pulls `main` from `src` into `dst` with the options of `opts`.
async fn pull_main_with(dst: &Repo, src: &Repo, opts: PullOptions) -> Result<(), Error> {
    dst.pull_local(
        src,
        PullOptions {
            refs: vec!["main".to_owned()],
            ..opts
        },
    )
    .await
    .map(|_| ())
}

/// A local pull verifies nothing by default. This is also true if the remote
/// for its refs sets `gpg-verify` and `sign-verify`. `ostree pull-local` does
/// the same: only its own flags turn on a verification, and the remote config
/// does not.
#[test]
fn a_local_pull_checks_nothing_by_default() {
    let tmp = TmpDir::new("pull-local-verify-default");
    let base = tmp.path();
    block_on(async {
        let (_src_path, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let dst = dest_with_remote(base, "gpg-verify=true\nsign-verify=true\n").await;

        pull_main_with(
            &dst,
            &src,
            PullOptions {
                remote: Some("origin".to_owned()),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dst.resolve_rev("origin:main", true).await.unwrap(),
            Some(c2)
        );
    });
}

/// If a local pull must verify, it reads the keys from the remote that it
/// names. The signed commits of the source pass under the key that signed
/// them. Under another key, the pull fails and imports nothing.
#[test]
fn a_local_pull_checks_the_commits_when_asked() {
    let tmp = TmpDir::new("pull-local-verify-asked");
    let base = tmp.path();
    block_on(async {
        let (_src_path, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        src.sign_commit(&c1, &signer).await.unwrap();
        src.sign_commit(&c2, &signer).await.unwrap();

        let dst = dest_with_remote(base, &format!("verification-ed25519-key={PUBLIC_B64}\n")).await;
        let asked = PullOptions {
            remote: Some("origin".to_owned()),
            verify: PullVerify {
                sign: Some(true),
                ..PullVerify::default()
            },
            depth: -1,
            ..PullOptions::default()
        };
        pull_main_with(&dst, &src, asked.clone()).await.unwrap();
        assert_eq!(
            dst.resolve_rev("origin:main", true).await.unwrap(),
            Some(c2)
        );
        drop(dst);

        std::fs::remove_dir_all(base.join("dst")).unwrap();
        let dst = dest_with_remote(
            base,
            &format!("verification-ed25519-key={OTHER_PUBLIC_B64}\n"),
        )
        .await;
        let err = pull_main_with(&dst, &src, asked).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("is from a trusted key")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());
        assert!(
            !dst.has_object(ostrya::ObjectType::Commit, &c2)
                .await
                .unwrap()
        );
    });
}

/// The filter runs after the signature verification, on the metadata of the
/// source. As a result, a filter that drops the signature cannot stop the
/// verification. The stored commit then carries no signature.
#[test]
fn the_filter_runs_after_the_signature_check() {
    let tmp = TmpDir::new("pull-local-filter-after-verify");
    let base = tmp.path();
    block_on(async {
        let (_src_path, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        src.sign_commit(&c1, &signer).await.unwrap();
        src.sign_commit(&c2, &signer).await.unwrap();

        let dst = dest_with_remote(base, &format!("verification-ed25519-key={PUBLIC_B64}\n")).await;
        let opts = PullOptions {
            remote: Some("origin".to_owned()),
            verify: PullVerify {
                sign: Some(true),
                ..PullVerify::default()
            },
            depth: -1,
            detached_metadata_filter: DetachedMetadataFilter::new(|_, _, _| FilterResult::Skip),
            ..PullOptions::default()
        };
        pull_main_with(&dst, &src, opts).await.unwrap();

        assert_eq!(
            dst.resolve_rev("origin:main", true).await.unwrap(),
            Some(c2),
            "the pull verified the signature and published the ref"
        );
        assert_eq!(
            dst.read_commit_detached_metadata(&c2).await.unwrap(),
            None,
            "and stored none of the metadata the filter skipped"
        );
    });
}

/// The summary verification reads the `summary` and `summary.sig` of the
/// source repository. If the source publishes no signature, the error names
/// the missing file.
#[test]
fn a_local_pull_checks_the_source_summary_when_asked() {
    let tmp = TmpDir::new("pull-local-verify-summary");
    let base = tmp.path();
    block_on(async {
        let (_src_path, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        src.regenerate_summary(&ostrya::SummaryOptions {
            last_modified: Some(FIXED_TS),
            ..ostrya::SummaryOptions::default()
        })
        .await
        .unwrap();

        let dst = dest_with_remote(base, &format!("verification-ed25519-key={PUBLIC_B64}\n")).await;
        let asked = PullOptions {
            remote: Some("origin".to_owned()),
            verify: PullVerify {
                sign_summary: Some(true),
                ..PullVerify::default()
            },
            ..PullOptions::default()
        };
        let err = pull_main_with(&dst, &src, asked.clone()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("no summary.sig")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());

        src.sign_summary(&Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
        pull_main_with(&dst, &src, asked).await.unwrap();
        assert_eq!(
            dst.resolve_rev("origin:main", true).await.unwrap(),
            Some(c2)
        );
    });
}

/// A local pull verifies the detached metadata that it keeps in place. If the
/// source holds no `.commitmeta`, the pull keeps the `.commitmeta` of the
/// destination and verifies that stored signature. If the source holds the
/// zero-length "no metadata" marker, the marker replaces the signature, so the
/// pull fails.
#[test]
fn a_local_pull_checks_the_metadata_it_leaves_in_place() {
    let tmp = TmpDir::new("pull-local-verify-stored-meta");
    let base = tmp.path();
    block_on(async {
        let (src_path, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        src.sign_commit(&c1, &signer).await.unwrap();
        src.sign_commit(&c2, &signer).await.unwrap();

        let dst = dest_with_remote(base, &format!("verification-ed25519-key={PUBLIC_B64}\n")).await;
        let asked = PullOptions {
            remote: Some("origin".to_owned()),
            verify: PullVerify {
                sign: Some(true),
                ..PullVerify::default()
            },
            depth: -1,
            ..PullOptions::default()
        };
        pull_main_with(&dst, &src, asked.clone()).await.unwrap();
        assert!(
            dst.read_commit_detached_metadata(&c2)
                .await
                .unwrap()
                .is_some()
        );

        // Delete the two signature files from the source. The copies in the
        // destination stay, so the second pull passes with them.
        for commit in [c1, c2] {
            let hex = commit.to_hex();
            let path = src_path
                .join("objects")
                .join(&hex[..2])
                .join(format!("{}.commitmeta", &hex[2..]));
            std::fs::remove_file(&path).unwrap();
        }
        pull_main_with(&dst, &src, asked.clone()).await.unwrap();
        assert!(
            dst.read_commit_detached_metadata(&c2)
                .await
                .unwrap()
                .is_some()
        );

        // The source now holds the zero-length marker. A copy of it replaces
        // the signature of the destination, so the pull fails.
        src.write_commit_detached_metadata(&c2, None).await.unwrap();
        let err = pull_main_with(&dst, &src, asked).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("carries no signature")),
            "{err}"
        );
    });
}

/// The keys of each verification come from the config of a remote. If a pull
/// sets a verification and names no remote, it fails before it reads the
/// source. The `ostree` command refuses the same combination.
#[test]
fn a_check_without_a_remote_name_is_refused() {
    let tmp = TmpDir::new("pull-local-verify-no-remote");
    let base = tmp.path();
    block_on(async {
        let (_src_path, src, _c1, _c2) = source_repo(base, RepoMode::Archive).await;
        let (_dst_path, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        let err = pull_main_with(
            &dst,
            &src,
            PullOptions {
                verify: PullVerify {
                    sign: Some(true),
                    ..PullVerify::default()
                },
                ..PullOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("name a remote")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());
    });
}

/// The durability options change the sync calls of a pull and no byte that it
/// writes. Each combination of the two options gives the same objects, the
/// same refs, and the same statistics. This is true for linked objects
/// (`archive` to `archive`) and for re-ingested objects (`archive` to
/// `bare-user`). The CLI tests read the sync calls under `strace`.
#[test]
fn pull_local_durability_options_change_no_byte() {
    let tmp = TmpDir::new("pull-durability");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, _c2) = source_repo(base, RepoMode::Archive).await;
        for mode in [RepoMode::Archive, RepoMode::BareUser] {
            let mut answer = None;
            for (disable_fsync, per_object_fsync) in
                [(false, false), (true, false), (false, true), (true, true)]
            {
                let name = format!("dst-{mode:?}-{disable_fsync}-{per_object_fsync}");
                let (dst_dir, dst) = make_repo(base, &name, mode).await;
                let stats = dst
                    .pull_local(
                        &src,
                        PullOptions {
                            refs: vec!["main".to_owned()],
                            disable_fsync,
                            per_object_fsync,
                            ..PullOptions::default()
                        },
                    )
                    .await
                    .unwrap();
                // The elapsed time is the only figure that a second run
                // changes.
                let seen = (
                    file_inventory(&dst_dir, "objects"),
                    dst.list_refs(None).await.unwrap(),
                    ostrya::PullStats {
                        elapsed: std::time::Duration::ZERO,
                        ..stats
                    },
                );
                match &answer {
                    None => answer = Some(seen),
                    Some(first) => assert_eq!(
                        &seen, first,
                        "{mode:?} disable_fsync={disable_fsync} \
                         per_object_fsync={per_object_fsync} changed what the pull wrote",
                    ),
                }
            }
        }
    });
}

/// A local pull takes no subpath. It refuses the option before it reads the
/// source, and imports nothing.
#[test]
fn a_local_pull_refuses_subpaths() {
    let tmp = TmpDir::new("pull-subpath-refused");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, _c2) = source_repo(base, RepoMode::Archive).await;
        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        let err = dst
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    subpaths: vec!["/".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        assert!(dst.list_refs(None).await.unwrap().is_empty());
        assert!(dst.list_objects().await.unwrap().is_empty());
    });
}

/// A local pull refuses a depth less than -1 before it reads the source, and
/// imports nothing.
#[test]
fn a_local_pull_refuses_a_depth_below_minus_one() {
    let tmp = TmpDir::new("pull-depth-refused");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, _c2) = source_repo(base, RepoMode::Archive).await;
        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        for depth in [-2, -3, i32::MIN] {
            let err = dst
                .pull_local(
                    &src,
                    PullOptions {
                        refs: vec!["main".to_owned()],
                        depth,
                        ..PullOptions::default()
                    },
                )
                .await
                .unwrap_err();
            match &err {
                Error::InvalidInput(msg) => {
                    assert!(msg.contains(&format!("depth {depth} is below -1")), "{msg}")
                }
                other => panic!("{depth}: {other:?}"),
            }
        }
        assert!(dst.list_refs(None).await.unwrap().is_empty());
        assert!(dst.list_objects().await.unwrap().is_empty());
    });
}

// --- static deltas -------------------------------------------------------

/// Generates a delta in `repo` with a fixed timestamp under `opts`, and
/// returns its directory.
async fn delta_with(
    repo: &Repo,
    from: Option<&Checksum>,
    to: &Checksum,
    opts: DeltaOptions,
) -> PathBuf {
    let dir = repo
        .generate_static_delta(
            from,
            to,
            &DeltaOptions {
                timestamp: Some(FIXED_TS),
                ..opts
            },
        )
        .await
        .unwrap();
    repo.path().join(dir)
}

/// Regenerates the summary of `repo` with a fixed timestamp.
async fn summarize(repo: &Repo) {
    repo.regenerate_summary(&SummaryOptions {
        last_modified: Some(FIXED_TS),
        ..SummaryOptions::default()
    })
    .await
    .unwrap();
}

/// Creates an archive source as [`source_repo`] does, with the from-scratch
/// delta to the second commit, its index, and a summary. Returns the values of
/// [`source_repo`] and the directory of the delta.
async fn delta_source(base: &Path) -> (PathBuf, Repo, Checksum, Checksum, PathBuf) {
    let (path, repo, c1, c2) = source_repo(base, RepoMode::Archive).await;
    let dir = delta_with(&repo, None, &c2, DeltaOptions::default()).await;
    repo.reindex_static_deltas().await.unwrap();
    summarize(&repo).await;
    (path, repo, c1, c2, dir)
}

/// Returns the options of a pull of `main` that requires static deltas.
fn required(flags: PullFlags) -> PullOptions {
    PullOptions {
        refs: vec!["main".to_owned()],
        flags,
        require_static_deltas: true,
        ..PullOptions::default()
    }
}

/// Creates a destination under `base/<name>` that holds `commit` of `src`
/// complete, with no ref.
async fn dst_holding(base: &Path, name: &str, src: &Repo, commit: &Checksum) -> (PathBuf, Repo) {
    let (path, dst) = make_repo(base, name, RepoMode::BareUser).await;
    dst.pull_local(
        src,
        PullOptions {
            refs: vec![commit.to_hex()],
            flags: PullFlags::DISABLE_VERIFY_BINDINGS,
            ..PullOptions::default()
        },
    )
    .await
    .unwrap();
    let txn = dst.transaction().await.unwrap();
    txn.set_ref(&commit.to_hex(), None);
    txn.commit().await.unwrap();
    assert!(dst.list_refs(None).await.unwrap().is_empty());
    (path, dst)
}

/// Returns the sum of the sizes of the files under `dir`.
fn tree_size(dir: &Path) -> u64 {
    let mut total = 0;
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let meta = entry.metadata().unwrap();
        total += if meta.is_dir() {
            tree_size(&entry.path())
        } else {
            meta.len()
        };
    }
    total
}

/// Asserts that a failed pull left `dst` with no ref, no object, and no marker
/// for `commit`.
async fn assert_nothing_left(dst_dir: &Path, dst: &Repo, commit: &Checksum) {
    assert!(dst.list_refs(None).await.unwrap().is_empty());
    assert!(dst.list_objects().await.unwrap().is_empty());
    assert!(!has_partial_marker(dst_dir, commit));
}

/// By default, a local pull reads no delta. A source with a corrupt and
/// unreadable delta tree gives the same pull as with deltas disabled.
#[test]
fn a_local_pull_reads_no_delta_by_default() {
    let tmp = TmpDir::new("pull-delta-default");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2, dir) = delta_source(base).await;
        std::fs::write(dir.join("superblock"), b"not a superblock").unwrap();
        let deltas = src_dir.join("deltas");
        std::fs::set_permissions(&deltas, std::fs::Permissions::from_mode(0o000)).unwrap();
        for (name, disable_static_deltas) in [("plain", false), ("disabled", true)] {
            let (_dst_dir, dst) = make_repo(base, name, RepoMode::BareUser).await;
            let stats = dst
                .pull_local(
                    &src,
                    PullOptions {
                        refs: vec!["main".to_owned()],
                        disable_static_deltas,
                        ..PullOptions::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(stats.delta_parts, 0, "{name}");
            assert_eq!(stats.metadata_fetched, 0, "{name}");
            assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        }
        std::fs::set_permissions(&deltas, std::fs::Permissions::from_mode(0o755)).unwrap();
    });
}

/// A pull that requires static deltas applies the from-scratch delta of the
/// source. It stores the same objects as a plain import, the commit is
/// complete, and the counts are those of a fetch.
#[test]
fn a_required_delta_applies_from_scratch() {
    let tmp = TmpDir::new("pull-delta-scratch");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2, dir) = delta_source(base).await;
        let (_plain_dir, plain) = make_repo(base, "plain", RepoMode::BareUser).await;
        pull_main(&plain, &src, PullFlags::empty()).await;

        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let stats = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap();
        assert_eq!(
            dst.list_objects().await.unwrap(),
            plain.list_objects().await.unwrap()
        );
        assert_eq!(dst.resolve_rev("main", false).await.unwrap(), Some(c2));
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(!has_partial_marker(&dst_dir, &c2));
        assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        let index_dir = src_dir.join("delta-indexes");
        assert_eq!(
            PullStats {
                elapsed: std::time::Duration::ZERO,
                ..stats
            },
            PullStats {
                metadata_imported: stats.metadata_imported,
                content_imported: stats.content_imported,
                content_bytes_written: stats.content_bytes_written,
                metadata_fetched: 2,
                content_fetched: 0,
                delta_parts: 1,
                bytes_transferred: tree_size(&dir) + tree_size(&index_dir),
                ..PullStats::default()
            }
        );
    });
}

/// A destination that holds the source commit of a from-to delta takes that
/// delta. This is true with or without a remote name, and for each ref that
/// it holds.
#[test]
fn a_required_from_to_delta_applies() {
    let tmp = TmpDir::new("pull-delta-from-to");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let dir = delta_with(&src, Some(&c1), &c2, DeltaOptions::default()).await;
        summarize(&src).await;
        for remote in [None, Some("origin")] {
            let name = format!("dst-{}", remote.unwrap_or("local"));
            let (_dst_dir, dst) = dst_holding(base, &name, &src, &c1).await;
            let stats = dst
                .pull_local(
                    &src,
                    PullOptions {
                        remote: remote.map(str::to_owned),
                        ..required(PullFlags::empty())
                    },
                )
                .await
                .unwrap();
            assert_eq!(stats.delta_parts, 1, "{remote:?}");
            // The summary lists the delta and the source publishes no index.
            // The read of the index finds nothing, and the count still
            // includes it.
            assert_eq!(stats.metadata_fetched, 2, "{remote:?}");
            assert_eq!(stats.bytes_transferred, tree_size(&dir), "{remote:?}");
            assert_eq!(stats.content_bytes_unpacked, 0, "{remote:?}");
            assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
            assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        }
    });
}

/// If no advertised delta makes the commit from what the destination holds, a
/// pull that requires static deltas fails and writes nothing.
#[test]
fn a_required_delta_that_is_not_published_is_refused() {
    let tmp = TmpDir::new("pull-delta-none-found");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        delta_with(&src, Some(&c1), &c2, DeltaOptions::default()).await;
        summarize(&src).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let err = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("pull: Static deltas required, but none found for main to {c2}")
        );
        assert_nothing_left(&dst_dir, &dst, &c2).await;
    });
}

/// A pull that requires static deltas fails on a source with no summary. The
/// source holds a delta and its index, and the pull still fails.
#[test]
fn a_required_delta_needs_a_summary() {
    let tmp = TmpDir::new("pull-delta-no-summary");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        delta_with(&src, None, &c2, DeltaOptions::default()).await;
        src.reindex_static_deltas().await.unwrap();
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let err = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "pull: Fetch configured to require static deltas, but no summary deltas or \
             delta index found"
        );
        assert_nothing_left(&dst_dir, &dst, &c2).await;
    });
}

/// A pull that requires static deltas reads only an archive source.
#[test]
fn a_required_delta_refuses_a_source_outside_archive_mode() {
    let tmp = TmpDir::new("pull-delta-bare-source");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::BareUser).await;
        delta_with(&src, None, &c2, DeltaOptions::default()).await;
        summarize(&src).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let err = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        assert!(err.to_string().contains("bare-user"), "{err}");
        assert_nothing_left(&dst_dir, &dst, &c2).await;
    });
}

/// If a superblock does not match the digest in the summary, the pull fails.
/// If a part file does not match its checksum, the pull also fails. Neither
/// pull publishes anything.
#[test]
fn a_tampered_delta_fails_and_publishes_nothing() {
    let tmp = TmpDir::new("pull-delta-tampered");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2, dir) = delta_source(base).await;

        let superblock = dir.join("superblock");
        let original = std::fs::read(&superblock).unwrap();
        let mut changed = original.clone();
        *changed.last_mut().unwrap() ^= 0xff;
        std::fs::write(&superblock, &changed).unwrap();
        let (dst_dir, dst) = make_repo(base, "sb", RepoMode::BareUser).await;
        let err = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ChecksumMismatch { .. }), "{err}");
        assert_nothing_left(&dst_dir, &dst, &c2).await;
        std::fs::write(&superblock, &original).unwrap();

        let part = dir.join("0");
        let mut bytes = std::fs::read(&part).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        std::fs::write(&part, &bytes).unwrap();
        let (dst_dir, dst) = make_repo(base, "part", RepoMode::BareUser).await;
        let err = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        assert_nothing_left(&dst_dir, &dst, &c2).await;
    });
}

/// A pull into a destination that holds the commit does not fail. No delta
/// makes the commit from what the destination holds, and the pull still
/// passes.
#[test]
fn a_required_delta_pull_of_a_held_commit_is_not_refused() {
    let tmp = TmpDir::new("pull-delta-held");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        delta_with(&src, Some(&c1), &c2, DeltaOptions::default()).await;
        summarize(&src).await;
        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        pull_main(&dst, &src, PullFlags::empty()).await;
        let stats = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap();
        assert_eq!(stats.delta_parts, 0);
        assert_eq!(stats.metadata_fetched, 0);
    });
}

/// A commit-only pull that requires static deltas looks for no delta and does
/// not fail. It counts the commit object as fetched.
#[test]
fn a_required_delta_commit_only_pull_takes_the_commit_loose() {
    let tmp = TmpDir::new("pull-delta-commit-only");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        summarize(&src).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let stats = dst
            .pull_local(&src, required(PullFlags::COMMIT_ONLY))
            .await
            .unwrap();
        let hex = c2.to_hex();
        let commit_file = src_dir
            .join("objects")
            .join(&hex[..2])
            .join(format!("{}.commit", &hex[2..]));
        assert_eq!(stats.metadata_fetched, 1);
        assert_eq!(
            stats.bytes_transferred,
            std::fs::metadata(commit_file).unwrap().len()
        );
        assert!(has_partial_marker(&dst_dir, &c2));
    });
}

/// A pull that requires static deltas applies the delta into an `archive`
/// destination, and the destination passes its fsck.
#[test]
fn a_required_delta_applies_into_archive() {
    let tmp = TmpDir::new("pull-delta-archive");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2, _dir) = delta_source(base).await;
        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        let stats = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap();
        assert_eq!(stats.delta_parts, 1);
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// `BAREUSERONLY_FILES` applies to an object from a local delta. The pull
/// refuses the object and publishes nothing.
#[test]
fn bareuseronly_files_rejects_a_local_delta_object_outside_0775() {
    let tmp = TmpDir::new("pull-delta-mode-bits");
    block_on(async {
        let base = tmp.path();
        build_tree(&base.join("v1"), b"hello\n");
        std::fs::set_permissions(
            base.join("v1/exec.sh"),
            std::fs::Permissions::from_mode(0o4755),
        )
        .unwrap();
        let (_src_dir, src) = make_repo(base, "src", RepoMode::Archive).await;
        let c1 = commit_tree_with(
            &src,
            base,
            "v1",
            "main",
            None,
            CommitModifierFlags::SKIP_XATTRS,
            None,
        )
        .await;
        delta_with(&src, None, &c1, DeltaOptions::default()).await;
        summarize(&src).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let err = dst
            .pull_local(&src, required(PullFlags::BAREUSERONLY_FILES))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid mode"), "{err}");
        assert_nothing_left(&dst_dir, &dst, &c1).await;
    });
}

/// Each of these two deltas delivers the full commit:
/// - a delta of several parts, one of which carries a 256 KiB file
/// - a delta with its parts inline in the superblock
///
/// Only a part that the pull reads as a file counts.
#[test]
fn multi_part_and_inline_deltas_apply() {
    let tmp = TmpDir::new("pull-delta-parts");
    block_on(async {
        let base = tmp.path();
        build_tree(&base.join("v1"), b"hello\n");
        let mut big = Vec::with_capacity(256 * 1024);
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        while big.len() < 256 * 1024 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            big.extend_from_slice(&state.to_le_bytes());
        }
        std::fs::write(base.join("v1/big"), &big).unwrap();
        let (_src_dir, src) = make_repo(base, "src", RepoMode::Archive).await;
        let c1 = commit_tree(&src, base, "v1", "main", None).await;
        summarize(&src).await;
        for (name, inline) in [("parts", false), ("inline", true)] {
            delta_with(
                &src,
                None,
                &c1,
                DeltaOptions {
                    max_chunk_size: 1,
                    inline,
                    ..DeltaOptions::default()
                },
            )
            .await;
            summarize(&src).await;
            let (_dst_dir, dst) = make_repo(base, name, RepoMode::BareUser).await;
            let stats = dst
                .pull_local(&src, required(PullFlags::empty()))
                .await
                .unwrap();
            if inline {
                assert_eq!(stats.delta_parts, 0, "{name}");
            } else {
                assert!(stats.delta_parts > 1, "{name}: {stats:?}");
            }
            assert_eq!(dst.commit_state(&c1).await.unwrap(), CommitState::Normal);
            assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
            assert_eq!(
                dst.list_objects().await.unwrap(),
                src.traverse_commit(&c1, 0).await.unwrap()
            );
        }
    });
}

/// If the destination holds the commit object partial, the pull looks for a
/// delta. If the source advertises no delta, a pull that requires static
/// deltas fails and keeps the commit partial. If the source advertises the
/// from-scratch delta, the ref names that commit. The pull then does not use
/// the delta, fetches the objects loose, and does not fail.
#[test]
fn a_required_delta_pull_of_a_partial_commit_looks_for_a_delta() {
    let tmp = TmpDir::new("pull-delta-partial");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        summarize(&src).await;
        let (dst_dir, dst) = make_repo(base, "none", RepoMode::BareUser).await;
        pull_main(&dst, &src, PullFlags::COMMIT_ONLY).await;
        let held = dst.list_objects().await.unwrap();
        let err = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("pull: Static deltas required, but none found for main to {c2}")
        );
        assert_eq!(dst.list_objects().await.unwrap(), held);
        assert!(has_partial_marker(&dst_dir, &c2));

        delta_with(&src, None, &c2, DeltaOptions::default()).await;
        src.reindex_static_deltas().await.unwrap();
        summarize(&src).await;
        let (dst_dir, dst) = make_repo(base, "scratch", RepoMode::BareUser).await;
        pull_main(&dst, &src, PullFlags::COMMIT_ONLY).await;
        let stats = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap();
        assert_eq!(stats.delta_parts, 0);
        assert!(stats.content_fetched > 0, "{stats:?}");
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(!has_partial_marker(&dst_dir, &c2));
    });
}

/// A pull that requires static deltas refuses a source with no summary before
/// it reads the mode of the source. It refuses a source outside archive mode
/// before it resolves a ref. The `ostree` command refuses in the same order.
#[test]
fn a_required_delta_pull_refuses_in_the_tool_order() {
    let tmp = TmpDir::new("pull-delta-refusal-order");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, _c2) = source_repo(base, RepoMode::BareUser).await;
        let (_dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let absent = PullOptions {
            refs: vec!["absent".to_owned()],
            ..required(PullFlags::empty())
        };
        let err = dst.pull_local(&src, absent.clone()).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "pull: Fetch configured to require static deltas, but no summary deltas or \
             delta index found"
        );
        summarize(&src).await;
        let err = dst.pull_local(&src, absent).await.unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
    });
}

/// The pull refuses a FIFO at the summary path of the source. The read does
/// not wait for a writer.
#[test]
fn a_required_delta_pull_refuses_a_summary_that_is_not_a_regular_file() {
    let tmp = TmpDir::new("pull-delta-summary-fifo");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let status = Command::new("mkfifo")
            .arg(src_dir.join("summary"))
            .status()
            .unwrap();
        assert!(status.success());
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let err = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
        assert_nothing_left(&dst_dir, &dst, &c2).await;
    });
}

/// The pull refuses a part file that is longer than the size in the
/// superblock, and publishes nothing.
#[test]
fn a_part_file_past_its_declared_size_is_refused() {
    let tmp = TmpDir::new("pull-delta-grown-part");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2, dir) = delta_source(base).await;
        let mut part = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("0"))
            .unwrap();
        std::io::Write::write_all(&mut part, &[0u8; 4096]).unwrap();
        drop(part);
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let err = dst
            .pull_local(&src, required(PullFlags::empty()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("declared for it"), "{err}");
        assert_nothing_left(&dst_dir, &dst, &c2).await;
    });
}

// --- writing no ref ------------------------------------------------------

/// Asserts that `commit` is complete in `dst`: its state is normal, it has no
/// `.commitpartial` marker, and each object that it reaches in `src` is
/// present.
async fn assert_complete(src: &Repo, dst: &Repo, dst_dir: &Path, commit: &Checksum) {
    assert_eq!(dst.commit_state(commit).await.unwrap(), CommitState::Normal);
    assert!(!has_partial_marker(dst_dir, commit));
    for name in &src.traverse_commit(commit, 0).await.unwrap() {
        assert!(
            dst.has_object(name.ty, &name.checksum).await.unwrap(),
            "{name} missing from the destination"
        );
    }
}

/// A pull that writes no ref keeps the ref of the destination unchanged. It
/// stores the pulled commit complete, with its detached metadata.
#[test]
fn a_pull_with_no_ref_writes_keeps_the_ref_and_completes_the_commit() {
    let tmp = TmpDir::new("pull-no-ref-writes");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        src.write_commit_detached_metadata(&c2, Some(&two_property_metadata()))
            .await
            .unwrap();
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        let txn = dst.transaction().await.unwrap();
        txn.set_ref("main", Some(&c1));
        txn.commit().await.unwrap();
        let refs = file_inventory(&dst_dir, "refs");

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                no_ref_writes: true,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(file_inventory(&dst_dir, "refs"), refs);
        assert_eq!(dst.resolve_rev("main", false).await.unwrap(), Some(c1));
        assert_complete(&src, &dst, &dst_dir, &c2).await;
        assert_eq!(
            dst.read_commit_detached_metadata(&c2).await.unwrap(),
            Some(two_property_metadata())
        );
    });
}

/// A pull that writes no ref also writes no ref under the remote prefix.
#[test]
fn a_pull_with_no_ref_writes_writes_no_remote_ref() {
    let tmp = TmpDir::new("pull-no-ref-writes-remote");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        let refs = file_inventory(&dst_dir, "refs");

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                remote: Some("origin".to_owned()),
                no_ref_writes: true,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(file_inventory(&dst_dir, "refs"), refs);
        assert!(!dst_dir.join("refs/remotes/origin").exists());
        assert_eq!(dst.resolve_rev("origin:main", true).await.unwrap(), None);
        assert_complete(&src, &dst, &dst_dir, &c2).await;
    });
}

/// A pull that writes no ref still obeys `depth` and completes each commit of
/// the chain.
#[test]
fn a_pull_with_no_ref_writes_completes_every_parent_under_depth() {
    let tmp = TmpDir::new("pull-no-ref-writes-depth");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let refs = file_inventory(&dst_dir, "refs");

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                depth: -1,
                no_ref_writes: true,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(file_inventory(&dst_dir, "refs"), refs);
        assert_eq!(dst.resolve_rev("main", true).await.unwrap(), None);
        for commit in [&c1, &c2] {
            assert_complete(&src, &dst, &dst_dir, commit).await;
        }
    });
}

// --- collection refs -----------------------------------------------------

/// The collection id that the collection-ref tests read.
const COLLECTION: &str = "org.example.Os";

/// Returns the options of a pull that writes no ref. The pull reads `refs` as
/// collection refs of [`COLLECTION`], under the remote name `origin`.
fn collection_pull(refs: &[&str]) -> PullOptions {
    PullOptions {
        refs: refs.iter().map(|name| (*name).to_owned()).collect(),
        remote: Some("origin".to_owned()),
        collection_id: Some(COLLECTION.to_owned()),
        no_ref_writes: true,
        ..PullOptions::default()
    }
}

/// Points the collection ref `name` of `collection` in `repo` at `commit`.
async fn set_collection_ref(repo: &Repo, collection: &str, name: &str, commit: &Checksum) {
    let txn = repo.transaction().await.unwrap();
    txn.set_collection_ref(&CollectionRef::new(collection, name), Some(commit));
    txn.commit().await.unwrap();
}

/// Creates an archive source under `base/thin` with a copy of some objects of
/// the archive `src` at `src_dir`. The copy holds only the objects that `c2`
/// reaches and `c1` does not reach. The collection ref `main` of
/// [`COLLECTION`] points at `c2`. Returns the path, a handle opened after the
/// copy, and the objects that the two commits share.
async fn thin_source(
    base: &Path,
    src_dir: &Path,
    src: &Repo,
    c1: &Checksum,
    c2: &Checksum,
) -> (PathBuf, Repo, HashSet<ObjectName>) {
    let old = src.traverse_commit(c1, 0).await.unwrap();
    let new = src.traverse_commit(c2, 0).await.unwrap();
    let (path, thin) = make_repo(base, "thin", RepoMode::Archive).await;
    for name in new.difference(&old) {
        let to = object_path(&path, name, RepoMode::Archive);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(object_path(src_dir, name, RepoMode::Archive), &to).unwrap();
    }
    set_collection_ref(&thin, COLLECTION, "main", c2).await;
    drop(thin);
    let thin = Repo::open(&path).await.unwrap();
    let shared = old.intersection(&new).copied().collect();
    (path, thin, shared)
}

/// Copies the files under `from` to `to`, and creates the directories.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// The source holds only the objects that the new commit adds. A pull of a
/// collection ref from it takes the shared objects from the destination. It
/// reads no object that the destination holds, and the commit is complete.
#[test]
fn a_collection_pull_takes_the_shared_objects_from_the_destination() {
    let tmp = TmpDir::new("pull-collection-thin");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (_thin_dir, thin, shared) = thin_source(base, &src_dir, &src, &c1, &c2).await;
        assert!(shared.contains(&subdir_dirtree(&src, &c2).await));
        assert!(shared.iter().any(|name| name.ty == ObjectType::File));
        for name in &shared {
            assert!(!thin.has_object(name.ty, &name.checksum).await.unwrap());
        }
        let held = thin.list_objects().await.unwrap();
        let (dst_dir, dst) = dst_holding(base, "dst", &src, &c1).await;
        let refs = file_inventory(&dst_dir, "refs");

        let stats = dst
            .pull_local(&thin, collection_pull(&["main"]))
            .await
            .unwrap();

        assert_eq!(file_inventory(&dst_dir, "refs"), refs);
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(!has_partial_marker(&dst_dir, &c2));
        let mut expected = src.traverse_commit(&c1, 0).await.unwrap();
        expected.extend(src.traverse_commit(&c2, 0).await.unwrap());
        assert_eq!(dst.list_objects().await.unwrap(), expected);
        let content = held.iter().filter(|n| n.ty == ObjectType::File).count();
        assert_eq!(stats.content_imported as usize, content);
        assert_eq!(stats.metadata_imported as usize, held.len() - content);
        assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// The same pull into an empty destination fails, because no repository holds
/// the shared objects. The pull publishes nothing.
#[test]
fn a_collection_pull_from_a_thin_source_into_an_empty_destination_fails() {
    let tmp = TmpDir::new("pull-collection-thin-empty");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (_thin_dir, thin, _shared) = thin_source(base, &src_dir, &src, &c1, &c2).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;

        let err = dst
            .pull_local(&thin, collection_pull(&["main"]))
            .await
            .unwrap_err();

        assert!(matches!(err, Error::ObjectNotFound { .. }), "{err:?}");
        assert_nothing_left(&dst_dir, &dst, &c2).await;
    });
}

/// A collection pull reads only the collection ref. It does not read the ref
/// of the same name under `refs/heads`.
#[test]
fn a_collection_pull_reads_the_ref_under_refs_mirrors() {
    let tmp = TmpDir::new("pull-collection-mirrors");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        assert_eq!(src.resolve_rev("main", false).await.unwrap(), Some(c2));
        set_collection_ref(&src, COLLECTION, "main", &c1).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        dst.pull_local(&src, collection_pull(&["main"]))
            .await
            .unwrap();

        assert_complete(&src, &dst, &dst_dir, &c1).await;
        assert!(!dst.has_object(ObjectType::Commit, &c2).await.unwrap());
    });
}

/// If the source has no collection ref for a name, the pull fails with the
/// path of the collection ref. This is also true in these cases:
/// - the source holds the name under `refs/heads`
/// - the source holds the name under another collection
/// - the name is a checksum, which the pull reads as a ref name
#[test]
fn an_absent_collection_ref_is_not_found() {
    let tmp = TmpDir::new("pull-collection-absent");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        set_collection_ref(&src, "org.example.Other", "main", &c2).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        let hex = c2.to_hex();

        for name in ["main", hex.as_str()] {
            let err = dst
                .pull_local(&src, collection_pull(&[name]))
                .await
                .unwrap_err();
            match err {
                Error::RefNotFound(path) => {
                    assert_eq!(path, format!("refs/mirrors/{COLLECTION}/{name}"))
                }
                other => panic!("{name}: {other:?}"),
            }
            assert_nothing_left(&dst_dir, &dst, &c2).await;
        }
    });
}

/// A collection pull that requires static deltas takes the delta from the
/// commit of the ref under the remote name. The pull keeps that ref unchanged.
#[test]
fn a_collection_pull_takes_a_required_delta() {
    let tmp = TmpDir::new("pull-collection-delta");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let delta = delta_with(&src, Some(&c1), &c2, DeltaOptions::default()).await;
        let (thin_dir, thin, _shared) = thin_source(base, &src_dir, &src, &c1, &c2).await;
        copy_tree(
            &delta,
            &thin_dir.join(delta.strip_prefix(&src_dir).unwrap()),
        );
        thin.reindex_static_deltas().await.unwrap();
        summarize(&thin).await;
        let (_dst_dir, dst) = dst_holding(base, "dst", &src, &c1).await;
        let txn = dst.transaction().await.unwrap();
        txn.set_ref("origin:main", Some(&c1));
        txn.commit().await.unwrap();

        let stats = dst
            .pull_local(
                &thin,
                PullOptions {
                    remote: Some("origin".to_owned()),
                    collection_id: Some(COLLECTION.to_owned()),
                    no_ref_writes: true,
                    ..required(PullFlags::empty())
                },
            )
            .await
            .unwrap();

        assert_eq!(stats.delta_parts, 1);
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert_eq!(
            dst.resolve_rev("origin:main", false).await.unwrap(),
            Some(c1)
        );
        assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// The ref-binding check reads the name of the collection ref. The pull
/// refuses a commit bound to `main` under `other`. With the check off, the
/// pull takes the commit.
#[test]
fn a_collection_pull_checks_the_ref_binding_against_the_name() {
    let tmp = TmpDir::new("pull-collection-binding");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        set_collection_ref(&src, COLLECTION, "other", &c2).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        let err = dst
            .pull_local(&src, collection_pull(&["other"]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err}");
        assert!(err.to_string().contains("other"), "{err}");
        assert_nothing_left(&dst_dir, &dst, &c2).await;

        dst.pull_local(
            &src,
            PullOptions {
                flags: PullFlags::DISABLE_VERIFY_BINDINGS,
                ..collection_pull(&["other"])
            },
        )
        .await
        .unwrap();
        assert_complete(&src, &dst, &dst_dir, &c2).await;
    });
}

/// A collection pull that writes refs fails before it reads the source. A
/// collection pull that names no ref also fails before it reads the source.
/// Neither pull changes the destination. The source holds no collection ref.
/// If the check comes after the read of the collection ref, the error is
/// [`Error::RefNotFound`]. If the pull reads an empty list, it pulls the refs
/// under `refs/heads`.
#[test]
fn a_collection_pull_is_refused_without_no_ref_writes_or_a_ref() {
    let tmp = TmpDir::new("pull-collection-refused");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, _c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let inventory = |dir: &Path| {
            let mut out = file_inventory(dir, "objects");
            out.extend(file_inventory(dir, "refs"));
            out.extend(file_inventory(dir, "state"));
            out
        };
        let before = inventory(&dst_dir);

        for (case, opts, expected) in [
            (
                "ref writes",
                PullOptions {
                    no_ref_writes: false,
                    ..collection_pull(&["main"])
                },
                "a local pull with a collection id needs no_ref_writes",
            ),
            (
                "no ref",
                collection_pull(&[]),
                "a local pull with a collection id needs at least one ref name",
            ),
        ] {
            match dst.pull_local(&src, opts).await {
                Err(Error::Unsupported(msg)) => assert_eq!(msg, expected, "{case}"),
                other => panic!("{case}: {other:?}"),
            }
            assert_eq!(inventory(&dst_dir), before, "{case}");
        }
    });
}

/// A collection ref path to a directory, or through a file, holds no ref. The
/// pull fails with the path of the collection ref, as for an absent ref.
#[test]
fn a_collection_ref_path_through_a_directory_or_a_file_is_not_found() {
    let tmp = TmpDir::new("pull-collection-not-a-ref");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        set_collection_ref(&src, COLLECTION, "main/sub", &c2).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;

        for name in ["main", "main/sub/x"] {
            let err = dst
                .pull_local(&src, collection_pull(&[name]))
                .await
                .unwrap_err();
            match err {
                Error::RefNotFound(path) => {
                    assert_eq!(path, format!("refs/mirrors/{COLLECTION}/{name}"))
                }
                other => panic!("{name}: {other:?}"),
            }
            assert_nothing_left(&dst_dir, &dst, &c2).await;
        }
    });
}

/// With a collection id, an abbreviated checksum and an ancestry suffix are
/// part of the ref name. The source holds `main` under `refs/heads` and as a
/// collection ref. If the pull reads either name as a revision, it finds a
/// commit.
#[test]
fn a_collection_ref_name_takes_no_revision_syntax() {
    let tmp = TmpDir::new("pull-collection-revision");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        set_collection_ref(&src, COLLECTION, "main", &c2).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::Archive).await;
        let hex = c2.to_hex();

        for name in [&hex[..10], "main^"] {
            let err = dst
                .pull_local(&src, collection_pull(&[name]))
                .await
                .unwrap_err();
            match err {
                Error::RefNotFound(path) => {
                    assert_eq!(path, format!("refs/mirrors/{COLLECTION}/{name}"))
                }
                other => panic!("{name}: {other:?}"),
            }
            assert_nothing_left(&dst_dir, &dst, &c2).await;
        }
    });
}

/// The pull refuses an invalid collection id, and a name that holds `:`,
/// before it reads the source. The error holds the pair. The pull requires
/// static deltas and the source holds no summary. If the check comes after the
/// first read of the source, the error is that of the absent summary, as for
/// the valid pair.
#[test]
fn an_invalid_collection_id_or_name_is_refused_before_the_source_is_read() {
    let tmp = TmpDir::new("pull-collection-invalid");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src) = make_repo(base, "src", RepoMode::Archive).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareUser).await;
        let inventory = |dir: &Path| {
            let mut out = file_inventory(dir, "objects");
            out.extend(file_inventory(dir, "refs"));
            out.extend(file_inventory(dir, "state"));
            out
        };
        let before = inventory(&dst_dir);
        let opts = |id: &str, name: &str| PullOptions {
            refs: vec![name.to_owned()],
            collection_id: Some(id.to_owned()),
            no_ref_writes: true,
            require_static_deltas: true,
            ..PullOptions::default()
        };

        let err = dst.pull_local(&src, opts(COLLECTION, "main")).await;
        assert!(matches!(err, Err(Error::Pull(_))), "{err:?}");

        for (id, name) in [
            ("", "main"),
            ("..", "main"),
            ("a/b", "main"),
            (COLLECTION, "a:b"),
            (COLLECTION, "x:"),
            (COLLECTION, ":y"),
        ] {
            match dst.pull_local(&src, opts(id, name)).await {
                Err(Error::InvalidRefspec(pair)) => {
                    assert_eq!(pair, format!("{id}:{name}"), "{id:?} {name:?}")
                }
                other => panic!("{id:?} {name:?}: {other:?}"),
            }
            assert_eq!(inventory(&dst_dir), before, "{id:?} {name:?}");
        }
    });
}

// --- what the destination holds ------------------------------------------

/// Returns `true` if the tests run as root. Root can read a file of mode
/// `0000`.
fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Gives a loose object of `repo_dir` mode `0000`, so a read of it fails with
/// `EACCES` for a user other than root.
fn make_unreadable(repo_dir: &Path, name: &ObjectName, mode: RepoMode) {
    std::fs::set_permissions(
        object_path(repo_dir, name, mode),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
}

/// Creates a destination of `mode` under `base/<name>` that holds `commit` of
/// `src` complete, with no ref. The pull copies each object, so the
/// destination shares no inode with the source. A mode change in the source
/// then does not reach the destination.
async fn dst_copy_holding(
    base: &Path,
    name: &str,
    mode: RepoMode,
    src: &Repo,
    commit: &Checksum,
) -> (PathBuf, Repo) {
    let (path, dst) = make_repo(base, name, mode).await;
    dst.pull_local(
        src,
        PullOptions {
            refs: vec![commit.to_hex()],
            flags: PullFlags::DISABLE_VERIFY_BINDINGS | PullFlags::FORCE_COPY,
            no_ref_writes: true,
            ..PullOptions::default()
        },
    )
    .await
    .unwrap();
    assert!(dst.list_refs(None).await.unwrap().is_empty());
    (path, dst)
}

/// Asserts that a dirtree of the destination is a separate inode from the same
/// dirtree in the source.
fn assert_own_inode(src_dir: &Path, dst_dir: &Path, dirtree: &ObjectName, dst_mode: RepoMode) {
    let ino = |path: PathBuf| {
        let meta = std::fs::symlink_metadata(path).unwrap();
        (meta.dev(), meta.ino())
    };
    assert_ne!(
        ino(object_path(src_dir, dirtree, RepoMode::Archive)),
        ino(object_path(dst_dir, dirtree, dst_mode)),
        "{dirtree} is one inode in the source and the destination"
    );
}

/// Returns the content object of `nested.txt`, the one file of the
/// subdirectory that `build_tree` makes.
async fn nested_content(repo: &Repo, commit: &Checksum) -> ObjectName {
    let subdir = subdir_dirtree(repo, commit).await;
    let dirtree = repo.load_dirtree(&subdir.checksum).await.unwrap();
    let (_, file) = dirtree
        .files
        .into_iter()
        .find(|(name, _)| name == "nested.txt")
        .expect("the subdirectory holds nested.txt");
    ObjectName::new(file, ObjectType::File)
}

/// A pull of a commit that the destination holds complete reads no object of
/// its tree. The test makes these objects unreadable:
/// - each dirtree, dirmeta, and content object of the commit in the source
/// - each dirtree of the commit in the destination
///
/// A walk of the tree then fails where it reads its root, and the pull
/// imports only the detached metadata. If the destination holds the commit
/// partial, the same pull walks the tree and fails on the first unreadable
/// dirtree.
#[test]
fn a_commit_the_destination_holds_complete_reads_no_object_of_its_tree() {
    if is_root() {
        eprintln!("skipping: root reads a file of mode 0000");
        return;
    }
    let tmp = TmpDir::new("pull-held-commit");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = dst_copy_holding(base, "dst", RepoMode::BareUser, &src, &c2).await;
        let (partial_dir, partial) = make_repo(base, "partial", RepoMode::BareUser).await;
        partial
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    flags: PullFlags::COMMIT_ONLY | PullFlags::FORCE_COPY,
                    no_ref_writes: true,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            partial.commit_state(&c2).await.unwrap(),
            CommitState::Partial
        );
        src.write_commit_detached_metadata(&c2, Some(&two_property_metadata()))
            .await
            .unwrap();
        let tree = src.traverse_commit(&c2, 0).await.unwrap();
        let mut held: Vec<(PathBuf, std::fs::Permissions)> = Vec::new();
        for name in tree.iter().filter(|name| name.ty == ObjectType::DirTree) {
            assert_own_inode(&src_dir, &dst_dir, name, RepoMode::BareUser);
            let path = object_path(&dst_dir, name, RepoMode::BareUser);
            held.push((
                path.clone(),
                std::fs::metadata(&path).unwrap().permissions(),
            ));
            make_unreadable(&dst_dir, name, RepoMode::BareUser);
        }
        assert!(held.len() > 1, "the commit holds a root and a subdirectory");
        for name in &tree {
            if name.ty != ObjectType::Commit {
                make_unreadable(&src_dir, name, RepoMode::Archive);
            }
        }
        let opts = || PullOptions {
            refs: vec!["main".to_owned()],
            no_ref_writes: true,
            ..PullOptions::default()
        };

        let stats = dst.pull_local(&src, opts()).await.unwrap();

        assert_eq!(stats.content_imported, 0);
        assert_eq!(
            dst.read_commit_detached_metadata(&c2).await.unwrap(),
            Some(two_property_metadata())
        );
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(!has_partial_marker(&dst_dir, &c2));
        assert!(dst.list_refs(None).await.unwrap().is_empty());
        for (path, permissions) in held {
            std::fs::set_permissions(path, permissions).unwrap();
        }
        assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());

        let err = partial.pull_local(&src, opts()).await.unwrap_err();
        match err {
            Error::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
            other => panic!("{other:?}"),
        }
        assert!(has_partial_marker(&partial_dir, &c2));
    });
}

/// The pull reads a dirtree from the destination if the destination holds it.
/// Each dirtree that the two commits share is unreadable in the source. A pull
/// of the second commit into a destination with the first commit completes it.
#[test]
fn a_dirtree_the_destination_holds_is_read_from_the_destination() {
    if is_root() {
        eprintln!("skipping: root reads a file of mode 0000");
        return;
    }
    for mode in [RepoMode::Archive, RepoMode::BareUser] {
        let tmp = TmpDir::new("pull-held-dirtree");
        block_on(async {
            let base = tmp.path();
            let (src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
            let (dst_dir, dst) = dst_copy_holding(base, "dst", mode, &src, &c1).await;
            let old = src.traverse_commit(&c1, 0).await.unwrap();
            let new = src.traverse_commit(&c2, 0).await.unwrap();
            let shared: Vec<ObjectName> = old
                .intersection(&new)
                .filter(|name| name.ty == ObjectType::DirTree)
                .copied()
                .collect();
            assert!(shared.contains(&subdir_dirtree(&src, &c2).await));
            for name in &shared {
                assert_own_inode(&src_dir, &dst_dir, name, mode);
                make_unreadable(&src_dir, name, RepoMode::Archive);
            }

            dst.pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

            assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
            assert!(!has_partial_marker(&dst_dir, &c2));
            for name in &new {
                assert!(
                    dst.has_object(name.ty, &name.checksum).await.unwrap(),
                    "{mode:?}: {name} missing from the destination"
                );
            }
            assert_eq!(dst.resolve_rev("main", false).await.unwrap(), Some(c2));
            assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        });
    }
}

/// The walk descends into a dirtree that the destination holds. The pull
/// imports a content object under it from the source if the destination
/// lacks the object. The dirtree in the source is unreadable.
#[test]
fn a_hole_below_a_dirtree_the_destination_holds_is_filled_from_the_source() {
    if is_root() {
        eprintln!("skipping: root reads a file of mode 0000");
        return;
    }
    let tmp = TmpDir::new("pull-held-dirtree-hole");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = dst_copy_holding(base, "dst", RepoMode::BareUser, &src, &c1).await;
        let nested = nested_content(&src, &c2).await;
        std::fs::remove_file(object_path(&dst_dir, &nested, RepoMode::BareUser)).unwrap();
        let new = src.traverse_commit(&c2, 0).await.unwrap();
        let subdir = subdir_dirtree(&src, &c2).await;
        assert_own_inode(&src_dir, &dst_dir, &subdir, RepoMode::BareUser);
        make_unreadable(&src_dir, &subdir, RepoMode::Archive);

        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert!(dst.has_object(nested.ty, &nested.checksum).await.unwrap());
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(!has_partial_marker(&dst_dir, &c2));
        for name in &new {
            assert!(
                dst.has_object(name.ty, &name.checksum).await.unwrap(),
                "{name} missing from the destination"
            );
        }
        assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// The walk also descends into a dirtree that the destination holds and no
/// source holds. If neither the destination nor a source holds a content
/// object under it, the pull fails with [`Error::ObjectNotFound`]. The pull
/// does not change the destination.
/// After the source gets the object, the same pull imports it.
#[test]
fn a_hole_below_a_dirtree_no_source_holds_fails_the_pull() {
    let tmp = TmpDir::new("pull-held-dirtree-thin");
    block_on(async {
        let base = tmp.path();
        let (src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (thin_dir, thin, shared) = thin_source(base, &src_dir, &src, &c1, &c2).await;
        let subdir = subdir_dirtree(&src, &c2).await;
        let nested = nested_content(&src, &c2).await;
        assert!(shared.contains(&subdir));
        assert!(shared.contains(&nested));
        let (dst_dir, dst) = dst_copy_holding(base, "dst", RepoMode::BareUser, &src, &c1).await;
        std::fs::remove_file(object_path(&dst_dir, &nested, RepoMode::BareUser)).unwrap();
        let before = object_names(&dst_dir);

        let err = dst
            .pull_local(&thin, collection_pull(&["main"]))
            .await
            .unwrap_err();

        match err {
            Error::ObjectNotFound { checksum, ty } => {
                assert_eq!(ObjectName::new(checksum, ty), nested)
            }
            other => panic!("{other:?}"),
        }
        assert!(!dst.has_object(ObjectType::Commit, &c2).await.unwrap());
        assert!(!has_partial_marker(&dst_dir, &c2));
        assert_eq!(object_names(&dst_dir), before);

        let to = object_path(&thin_dir, &nested, RepoMode::Archive);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(object_path(&src_dir, &nested, RepoMode::Archive), &to).unwrap();

        dst.pull_local(&thin, collection_pull(&["main"]))
            .await
            .unwrap();

        assert!(dst.has_object(nested.ty, &nested.checksum).await.unwrap());
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(!has_partial_marker(&dst_dir, &c2));
        assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// The destination holds a dirtree as a dangling symlink. The pull reads the
/// dirtree from the destination and fails with [`Error::ObjectNotFound`] for
/// it. The source holds the dirtree, and the pull still fails. The pull
/// publishes no commit object, no marker, and no ref.
#[test]
fn a_dangling_symlink_at_a_dirtree_the_destination_holds_fails_the_pull() {
    let tmp = TmpDir::new("pull-held-dirtree-symlink");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = dst_copy_holding(base, "dst", RepoMode::BareUser, &src, &c1).await;
        let subdir = subdir_dirtree(&src, &c2).await;
        assert!(src.traverse_commit(&c1, 0).await.unwrap().contains(&subdir));
        let path = object_path(&dst_dir, &subdir, RepoMode::BareUser);
        std::fs::remove_file(&path).unwrap();
        symlink(dst_dir.join("absent"), &path).unwrap();

        let err = dst
            .pull_local(
                &src,
                PullOptions {
                    refs: vec!["main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();

        match err {
            Error::ObjectNotFound { checksum, ty } => {
                assert_eq!(ObjectName::new(checksum, ty), subdir)
            }
            other => panic!("{other:?}"),
        }
        assert!(!dst.has_object(ObjectType::Commit, &c2).await.unwrap());
        assert!(!has_partial_marker(&dst_dir, &c2));
        assert!(dst.list_refs(None).await.unwrap().is_empty());
    });
}

/// A pull of a commit that the destination holds complete does not walk its
/// tree, so a content object that the destination lost stays absent. fsck
/// marks the commit partial, and the next pull walks the tree and imports the
/// object.
#[test]
fn a_hole_in_a_commit_held_complete_is_filled_after_fsck_marks_it() {
    let tmp = TmpDir::new("pull-held-commit-hole");
    block_on(async {
        let base = tmp.path();
        let (_src_dir, src, _c1, c2) = source_repo(base, RepoMode::Archive).await;
        let (dst_dir, dst) = dst_copy_holding(base, "dst", RepoMode::BareUser, &src, &c2).await;
        let nested = nested_content(&src, &c2).await;
        std::fs::remove_file(object_path(&dst_dir, &nested, RepoMode::BareUser)).unwrap();
        let opts = || PullOptions {
            refs: vec!["main".to_owned()],
            no_ref_writes: true,
            ..PullOptions::default()
        };

        let stats = dst.pull_local(&src, opts()).await.unwrap();

        assert_eq!(stats.content_imported, 0);
        assert!(!dst.has_object(nested.ty, &nested.checksum).await.unwrap());
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);

        assert!(!dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Partial);

        let stats = dst.pull_local(&src, opts()).await.unwrap();

        assert_eq!(stats.content_imported, 1);
        assert!(dst.has_object(nested.ty, &nested.checksum).await.unwrap());
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(!has_partial_marker(&dst_dir, &c2));
        assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}
