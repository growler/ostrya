//! Local pull between two repositories.
//!
//! The source repositories are built with the port itself, so the flag and
//! traversal behavior is covered without the `ostree` tool; the interop tests
//! that need the tool build a source with it, or hand it what the port pulled,
//! and are skipped when it is absent.

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

/// A fixed timestamp, so a source repository's commits are reproducible.
const FIXED_TS: u64 = 1_700_000_000;

// --- helpers -------------------------------------------------------------

/// Run the `ostree` tool and assert it succeeded.
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

/// Build a small source tree under `dir`: two regular files of differing modes,
/// a symlink, and a nested subdirectory.
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

/// The `ostree.ref-binding` metadata dict binding a commit to `branch`.
fn ref_binding(branch: &str) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("ostree.ref-binding".to_owned()),
        Value::Variant(Box::new((
            Type::parse("as").unwrap(),
            Value::Array(vec![Value::Str(branch.to_owned())]),
        ))),
    ])])
}

/// Commit subtree `sub` of `base` into `repo` under `branch`, with a fixed
/// timestamp and the branch's ref binding.
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

/// Commit subtree `sub` as [`commit_tree`] does, under the given modifier flags
/// and, where `owner` names one, a declared uid and gid in place of the ones the
/// source carries.
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

/// Create a repository of the given mode under `base/<name>`.
async fn make_repo(base: &Path, name: &str, mode: RepoMode) -> (PathBuf, Repo) {
    let path = base.join(name);
    let repo = Repo::create(&path, CreateOptions::new(mode)).await.unwrap();
    (path, repo)
}

/// Create a repository of the given mode inside a setgid `2775` directory owned
/// by group `gid`. The setgid bit carries `gid` to the repository root and, from
/// there, to every directory below it, so every object written there takes
/// `gid`.
async fn make_repo_in_group(base: &Path, name: &str, mode: RepoMode, gid: u32) -> (PathBuf, Repo) {
    let parent = base.join(format!("{name}-group"));
    std::fs::create_dir(&parent).unwrap();
    std::os::unix::fs::chown(&parent, None, Some(gid)).unwrap();
    // The group is set first: changing a file's owner may clear its setgid bit.
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o2775)).unwrap();
    let path = parent.join(name);
    let repo = Repo::create(&path, CreateOptions::new(mode)).await.unwrap();
    (path, repo)
}

/// A source repository holding two commits on `main`, the second a child of the
/// first. Returns its path, handle, and the two commit checksums.
async fn source_repo(base: &Path, mode: RepoMode) -> (PathBuf, Repo, Checksum, Checksum) {
    build_tree(&base.join("v1"), b"hello one\n");
    build_tree(&base.join("v2"), b"hello two\n");
    let (path, repo) = make_repo(base, "src", mode).await;
    let c1 = commit_tree(&repo, base, "v1", "main", None).await;
    let c2 = commit_tree(&repo, base, "v2", "main", Some(c1)).await;
    (path, repo, c1, c2)
}

/// A source repository as [`source_repo`], committed with canonical permissions
/// so every object it holds carries the header a bare-user-only destination
/// stores and can therefore be imported under its own name.
async fn canonical_source_repo(base: &Path, mode: RepoMode) -> (PathBuf, Repo, Checksum, Checksum) {
    build_tree(&base.join("v1"), b"hello one\n");
    build_tree(&base.join("v2"), b"hello two\n");
    let (path, repo) = make_repo(base, "src", mode).await;
    let flags = CommitModifierFlags::SKIP_XATTRS | CommitModifierFlags::CANONICAL_PERMISSIONS;
    let c1 = commit_tree_with(&repo, base, "v1", "main", None, flags, None).await;
    let c2 = commit_tree_with(&repo, base, "v2", "main", Some(c1), flags, None).await;
    (path, repo, c1, c2)
}

/// A source repository as [`source_repo`], committed with a declared non-root
/// owner so every object it holds carries a uid and gid a bare-user-only
/// destination discards. The ownership is declared rather than inherited from the
/// committing process, so the objects are the same whoever runs the test.
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

/// The path of a commit's `.commitmeta` file inside a repository directory.
fn commitmeta_path(repo_dir: &Path, commit: &Checksum) -> PathBuf {
    let hex = commit.to_hex();
    repo_dir
        .join("objects")
        .join(&hex[..2])
        .join(format!("{}.commitmeta", &hex[2..]))
}

/// The `(device, inode)` of a loose object in a repository, or `None` when the
/// object is absent.
fn object_ino(repo_dir: &Path, name: &str) -> Option<(u64, u64)> {
    let path = repo_dir.join("objects").join(&name[..2]).join(&name[2..]);
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// The permission bits of a loose object in a repository, or `None` when the
/// object is absent.
fn object_mode(repo_dir: &Path, name: &str) -> Option<u32> {
    let path = repo_dir.join("objects").join(&name[..2]).join(&name[2..]);
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| m.mode() & 0o7777)
}

/// Pull `main` from `src` into `dst` under `flags`.
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

/// Every loose object name (`<2>/<62>.<ext>` flattened to `<64>.<ext>`) in a
/// repository, sorted.
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

/// The lowest-numbered content object of `commit` that is a regular file with a
/// payload. Chosen by checksum order so the pick does not depend on the
/// traversal set's iteration order.
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

/// The symlink content object of `commit`, chosen by checksum order so the pick
/// does not depend on the traversal set's iteration order.
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

/// The subdirectory's dirtree object of `commit`: the one dirtree the commit
/// reaches that is not its root, which `build_tree` gives it exactly one of.
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

/// The absolute path of a loose object in a repository.
fn object_path(repo_dir: &Path, name: &ostrya::ObjectName, mode: RepoMode) -> PathBuf {
    repo_dir.join("objects").join(name.loose_path(mode))
}

/// Whether a loose object carries the named xattr.
fn has_xattr(path: &Path, name: &str) -> bool {
    let mut buf = [0u8; 256];
    rustix::fs::getxattr(path, name, &mut buf).is_ok()
}

/// Whether a loose object carries the `user.ostreemeta` xattr.
fn has_ostreemeta(path: &Path) -> bool {
    has_xattr(path, "user.ostreemeta")
}

/// A group the process belongs to other than `own`, or `None` when it belongs to
/// only one. Used to give a source object an ownership no write into the
/// destination repository would produce.
fn other_group(own: u32) -> Option<u32> {
    let out = Command::new("id").arg("-G").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|g| g.parse::<u32>().ok())
        .find(|g| *g != own)
}

/// The environment variable that turns the multi-group skip into a failure. A
/// harness setting it declares that the arrangement is available, so a run where
/// it is not is a broken harness rather than a test to pass over.
const REQUIRE_MULTIGROUP: &str = "OSTRYA_REQUIRE_MULTIGROUP";

/// A group the process belongs to other than `own`, for a test that cannot run
/// without one. These tests are the whole of the ownership gate's coverage, so a
/// single-group harness -- a container running as root with only `root` -- would
/// otherwise report the gate as tested when nothing exercised it. With
/// [`REQUIRE_MULTIGROUP`] set the absence fails; without it the test skips and
/// says so.
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

/// The path of a loose object named by the flattened `<64>.<ext>` name
/// [`object_names`] returns.
fn flat_object_path(repo_dir: &Path, flat: &str) -> PathBuf {
    repo_dir.join("objects").join(&flat[..2]).join(&flat[2..])
}

/// Create a repository of the given mode with `[ex-integrity] fsverity` set to
/// `fsverity`, reopened so the setting is parsed.
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

/// Whether a loose object is sealed with fs-verity, which a sealed regular file
/// reports by refusing to be opened for writing. Every object examined is
/// owner-writable, so a refused write-open is verity rather than permissions.
fn is_sealed(path: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(path).is_err()
}

/// Whether the filesystem holding `base` can seal a file with fs-verity, probed by
/// committing into a `maybe` repository, which succeeds either way.
async fn fs_supports_verity(base: &Path) -> bool {
    build_tree(&base.join("verity-probe"), b"probe\n");
    let (path, repo) = verity_repo(base, "verity-probe-repo", RepoMode::BareUser, "maybe").await;
    commit_tree(&repo, base, "verity-probe", "probe", None).await;
    object_names(&path)
        .iter()
        .any(|flat| is_sealed(&flat_object_path(&path, flat)))
}

/// Create a repository of the given mode reserving the whole filesystem through
/// `min-free-space-percent=100`, so a transaction there starts with a zero write
/// budget and any object that allocates blocks fails it. Reopened so the setting
/// is parsed.
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

/// Whether a commit's `.commitpartial` marker is present.
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
        // depth 0: the parent commit is not pulled.
        assert!(
            !dst.has_object(ostrya::ObjectType::Commit, &c1)
                .await
                .unwrap()
        );
        assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
        assert!(!has_partial_marker(&dst_dir, &c2));
        assert!(stats.metadata_imported > 0 && stats.content_imported > 0);

        // Every object the pulled commit reaches is present, and nothing else.
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

        // The flag belongs to `Repo::pull`. A local pull writes its refs under
        // the prefix `remote` names whether or not the flag is set.
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
        // A chain c1 <- c2 <- c3 <- c4 with `old` at c3 and `main` at c4, so at
        // depth 1 `main` reaches c3 and `old` reaches c2.
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

        // The two commits differ in their root tree and share the
        // subdirectory's, so a walk that descends into each dirtree once still
        // has to enumerate both commits' trees whole.
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
        // Drop the parent commit object, leaving the source with a truncated
        // history the deep pull must tolerate.
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
            // Both repositories are bare-user, so the mode the copy is given
            // afresh is the mode the source object was written with.
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

        // The copies read back as the objects they are named for: a bare-user
        // object's logical metadata lives in an xattr the clone had to carry.
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

        // A bare-user object's logical metadata lives in `user.ostreemeta`, so
        // its inode's own bits and xattrs say nothing about the object. Drift
        // them apart in the source, and the destination's copy shows which of
        // the two the import derives the inode from.
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

        // The import went through the object's header, so the copy carries what
        // a commit into this repository writes: the bare-user mode derived from
        // the logical mode, `user.ostreemeta`, and nothing of the source inode.
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

        // The baseline: what a metadata object written into the destination
        // carries, read off a commit made there.
        build_tree(&base.join("baseline"), b"baseline\n");
        let baseline = commit_tree(&dst, base, "baseline", "baseline", None).await;
        let want = std::fs::symlink_metadata(object_path(
            &dst_dir,
            &ostrya::ObjectName::new(baseline, ostrya::ObjectType::Commit),
            RepoMode::Bare,
        ))
        .unwrap();

        // A metadata object carries no header, so nothing of the source inode is
        // authoritative. Drift the source's away from what a write produces: 0600
        // instead of 0644, a stray xattr, and a second group of the process where
        // it has one, which a bare destination is the mode that would chown to.
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

        // The clone carries the destination's own inode policy, not the source's.
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

        // The baseline: what an object written into the destination is owned by.
        // Its group is the setgid directory's, not the process's.
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

        // Sharing the source inode would carry the source's group into a
        // repository whose group is the one that may repair it, so every object
        // is written afresh instead.
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

        // The tool is not the judge here: bare-user-shared is a mode it refuses to
        // open at all.
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
                // A bare content object's uid and gid come from the header its
                // checksum covers, so the source inode is the inode a write here
                // would have produced and the link stands.
                content += 1;
                assert_eq!(
                    object_ino(&src_dir, &object),
                    object_ino(&dst_dir, &object),
                    "{name} should share the source inode"
                );
                assert_eq!(got.gid(), own, "{name} should carry the header's group");
            } else {
                // A metadata object carries no header, so its ownership is the
                // writer's and the link is refused.
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

        // A bare object's inode is its metadata, so fsck recomputing each
        // checksum is what proves the linked inodes are the ones a write here
        // would have produced.
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

        // The commit identity is mode-independent, so the same checksums land;
        // the content objects are stored in the destination's own form.
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
        // A bare-user-only destination imports an object only under the name its
        // own stored form hashes to, so the source is committed canonically.
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

        // The bare family shares a regular file's payload bytes and differs
        // only on the inode, so the object is cloned: the bytes arrive
        // unchanged on a fresh inode carrying the destination's policy, which
        // for bare-user-only is the canonical mode and no xattr at all.
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

        // The object reads back as the header it is named for, which is what the
        // destination's own writer would have stored for it.
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
        // Committed under a declared non-root owner, so every object carries a
        // uid and gid this mode discards. A commit inheriting the running
        // process's ids would carry 0:0 under a root test run, which is what
        // this mode stores, and the refusal under test would not arise.
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

        // The two modes store a symlink object identically -- a 0644 regular
        // file of the target plus a NUL, with the logical metadata in
        // user.ostreemeta -- so it is hardlinked. A regular file, whose inode
        // mode the two modes disagree on, is cloned instead.
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

        // bare-user stores every object as a regular file, and this destination
        // seals every regular-file object it writes. A hardlink cannot carry that:
        // fs-verity is a per-inode property, so sealing a shared inode would seal
        // the source's copy. Every object therefore arrives on a fresh inode,
        // sealed, and the source is left as it was.
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
        // A branch whose tree is one regular file, so the only content object a
        // full pull of it imports is one the clone path serves. `main` holds a
        // symlink too, which a bare-user source and this destination store
        // differently, and that would be refused by the re-ingest instead.
        std::fs::create_dir(base.join("flat")).unwrap();
        std::fs::write(base.join("flat/only.txt"), b"only\n").unwrap();
        commit_tree(&src, base, "flat", "flat", None).await;
        let (dst_dir, dst) = make_repo(base, "dst", RepoMode::BareSplitXattrs).await;

        // Both import paths reach the destination, and each tests its mode before
        // it touches the source. The link path serves every metadata object and
        // every same-mode content object; the clone path serves a content object
        // whose payload the two modes share, which bare-user and
        // bare-split-xattrs do. Neither writes the `.file-xattrs` and
        // `.file-xattrs-link` sidecars this mode needs, so the destination refuses
        // the import the way the rest of the write surface refuses the mode. A
        // commit-only pull isolates the link path; a full pull of `flat` reaches
        // the clone path.
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
        // A tree whose file has no owner-write bit, which is ordinary in a system
        // tree. In bare-user the logical metadata lives in a `user.ostreemeta`
        // xattr the kernel checks against the inode's write permission, so every
        // path that applies the destination's inode policy has to set the xattr
        // before the mode drops that bit.
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

        // The link path shares the source's read-only inode.
        let (link_dir, link_dst) = make_repo(base, "link", RepoMode::BareUser).await;
        pull_main(&link_dst, &src, PullFlags::NONE).await;
        assert_eq!(
            object_ino(&src_dir, &object),
            object_ino(&link_dir, &object),
            "the link path shares the inode"
        );

        // The clone path applies the destination's own inode policy.
        let (copy_dir, copy_dst) = make_repo(base, "copy", RepoMode::BareUser).await;
        pull_main(&copy_dst, &src, PullFlags::FORCE_COPY).await;
        assert_ne!(
            object_ino(&src_dir, &object),
            object_ino(&copy_dir, &object),
            "force_copy writes a fresh inode"
        );

        // Crossing the archive boundary writes the object through the ingest path.
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
        // The whole filesystem is reserved, so the pull has no room for a single
        // freshly allocated block. Every object of a same-mode pull is
        // hardlinked, which allocates none.
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
        // The stats count the storage the imported objects occupy, which the
        // shared inodes hold whatever the budget said.
        assert!(stats.content_bytes_written > 0);
        // A hardlinked object's payload is never written, so the figure the
        // tool reports as the content written is zero.
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
        // Archive stores a regular file's payload in a framed, deflated form the
        // bare family does not share, so each content object is written afresh
        // and charged against the budget the reserve leaves at zero.
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
        // The marker the tool writes for a pull is zero-length, unlike fsck's.
        let marker = dst_dir
            .join("state")
            .join(format!("{}.commitpartial", c2.to_hex()));
        assert_eq!(std::fs::metadata(&marker).unwrap().len(), 0);

        // Completing the pull imports the rest and clears the marker.
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
        // Delete one content object the tip commit reaches.
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
        // The commit was never published, so the marker the pull wrote for it
        // goes with the objects the transaction discarded.
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

        // One content object removed from the destination, so fsck marks the
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

        // The same object removed from the source, so the repair pull marks the
        // commit it already found partial and then fails on the missing object.
        std::fs::remove_file(src_dir.join("objects").join(&object)).unwrap();
        let err = dst.pull_local(&src, opts()).await.unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }));

        // fsck's state byte survives: the pull does not rewrite a marker it finds.
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
        // A regular file with a payload: flipping a payload byte leaves the
        // object decodable and changes only what it hashes to. A symlink
        // object, stored in bare-user as its target plus a NUL, would instead
        // fail to decode.
        let content = first_regular_content(&src, &c2).await;
        let path = src_dir
            .join("objects")
            .join(content.loose_path(RepoMode::BareUser));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        // Trusted: the object is linked without being read, so the corruption
        // travels, matching the tool.
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

        // Untrusted: every object is read first, so the pull fails.
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

        // A bare-family clone moves the payload without hashing it, so a
        // trusted pull carries the corruption across modes exactly as the
        // same-mode link does; a re-ingest would have caught it.
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

        // UNTRUSTED reads the object once, ahead of the clone, and rejects it.
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

        // Archive stores a regular file's payload in a framed, deflated form the
        // bare family shares nothing with, so the object crosses on the re-ingest
        // path, which hashes it as it streams and compares the result against its
        // name. The corruption is rejected there with or without UNTRUSTED, which
        // is what lets the flag skip its own read of an object bound for this path.
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
        // Edit the commit's subject in place: the object still parses, so the
        // pull reaches the checksum check rather than failing on the decode.
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

        // Trusted, the metadata object is linked without being read, matching
        // the tool: the corruption travels.
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
        // A second name for the same commit, which its binding does not list.
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
        // under its own rule: that mode cannot store this mode's bits.
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

        // Without the flag, an archive destination takes it.
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

/// An `a{sv}` of two properties: one a signature stands in for, one the
/// repository keeps to itself.
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

/// The value of one property of a stored commit's detached metadata.
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
        // The source keeps what it had: the filter shapes what is stored here.
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

/// A pull whose commit fails at the step that writes detached metadata and
/// refs, because a guard holds the update lock, keeps the marker of the
/// commit it published and writes no `.commitmeta` and no ref. The next pull
/// completes the commit, its detached metadata included.
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

/// A pull into one handle of a repository whose other handle holds a guard
/// publishes its objects and waits at the step that writes detached metadata
/// and refs. With `lock-timeout-secs=-1` it completes that step once the guard
/// is finished.
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

/// `DetachedMetadataFilter::excluding` is the constructor the `ostrya` CLI
/// builds from `[ex-ostrya] detached-metadata-exclude`. It drops the properties
/// the list names and keeps every other one.
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

/// An empty exclude list is the absent-key case the CLI turns into the default
/// filter. Built directly it keeps every property all the same.
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

/// A filter allowing no property leaves the destination's own `.commitmeta`
/// where it stands, which is what a source holding none does.
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

        // A callback the caller holds, which is what `from_fn` takes.
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

/// An `a{sv}` of one string property.
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

        // Only the tip's private property is dropped; the parent keeps its own.
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

        // A cache holding everything, and a source missing one content object.
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

        // A cache holding everything, and a source missing the subdirectory's
        // dirtree, so what lies under it can only be named through the cache.
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

        // The whole tree arrives, the content under the cache-supplied dirtree
        // included, and the published commit is complete.
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

        // With no cache to name them, the objects under the missing dirtree
        // cannot be reached and the pull fails rather than publishing the hole.
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

// --- interop with the tool ----------------------------------------------

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
            // The tool resolves the ref, reads the tree, and validates every
            // object the port imported.
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

        // bare and bare-user share a regular file's payload and disagree on the
        // inode, so every regular file crosses on the clone path. The tool is
        // the judge of what the destination's inode policy produced: fsck
        // recomputes each object's checksum from the stored form, which for
        // bare-user means the payload plus the user.ostreemeta the clone wrote.
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

/// The fixed ed25519 keypair the signed sources sign with.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";
/// A second public key, standing for one the destination does not trust.
const OTHER_PUBLIC_B64: &str = "8+dqdDZWIesQQO95CRCSoSm2543BNK7FgOVwPyuUquU=";

/// A destination repository under `base/dst` whose config names the remote
/// `origin`, with the `[remote]` keys `extra` supplies. A local pull reads no
/// URL, so the section states the verification policy alone.
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

/// Pull `main` from `src` into `dst` with the options `opts` supplies.
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

/// A local pull checks nothing unless it is asked to, even where the remote it
/// writes its refs under asks for GPG verification. This is what the tool's
/// `pull-local` does: the checks are its own flags, not the remote's config.
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

/// A local pull asked to check reads the keys from the remote it names: the
/// source's signed commits pass under the key that signed them, and the same
/// pull under another key is refused with nothing imported.
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

/// The filter runs after the signature check, over the metadata the source
/// holds, so a filter that drops the signature does not defeat the verification
/// the pull was asked for. The commit that is stored then carries none.
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

/// The summary check reads the source repository's own `summary` and
/// `summary.sig`, and a source publishing no signature is refused by name.
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

/// A local pull checks the detached metadata it leaves in place. A source
/// holding no `.commitmeta` leaves this repository's own alone, so the stored
/// signature is what the check reads; a source holding the zero-length "no
/// metadata" marker replaces it, so that pull is refused.
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

        // The source drops both signatures, file and all. The destination's own
        // copies stay in place, so the second pull passes on them.
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

        // The source now holds the zero-length marker, which the pull would copy
        // over the destination's signature, so it is refused instead.
        src.write_commit_detached_metadata(&c2, None).await.unwrap();
        let err = pull_main_with(&dst, &src, asked).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("carries no signature")),
            "{err}"
        );
    });
}

/// The keys of every check come from a remote's configuration, so a pull that
/// asks for one and names no remote is refused before the source is read. The
/// tool refuses the same combination.
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

/// The durability options change the sync calls of a pull and no byte it
/// writes: a pull under each combination of the two stores the same objects,
/// the same refs, and reports the same statistics, whether the objects are
/// linked (`archive` to `archive`) or re-ingested (`archive` to `bare-user`).
/// The sync calls themselves are read under `strace` by the CLI tests.
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
                // The elapsed time is the one figure a rerun changes.
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

/// A local pull takes no subpath: it refuses the option before it reads the
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

/// A depth below -1 is refused before the source is read, and nothing is
/// imported.
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

/// Generate a delta in `repo` with a fixed timestamp under `opts`, and return
/// its directory.
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

/// Regenerate the summary of `repo` with a fixed timestamp.
async fn summarize(repo: &Repo) {
    repo.regenerate_summary(&SummaryOptions {
        last_modified: Some(FIXED_TS),
        ..SummaryOptions::default()
    })
    .await
    .unwrap();
}

/// An archive source as [`source_repo`] holding the from-scratch delta to the
/// second commit, its index, and a summary. Returns what [`source_repo`]
/// returns and the delta's directory.
async fn delta_source(base: &Path) -> (PathBuf, Repo, Checksum, Checksum, PathBuf) {
    let (path, repo, c1, c2) = source_repo(base, RepoMode::Archive).await;
    let dir = delta_with(&repo, None, &c2, DeltaOptions::default()).await;
    repo.reindex_static_deltas().await.unwrap();
    summarize(&repo).await;
    (path, repo, c1, c2, dir)
}

/// The options of a pull of `main` that requires static deltas.
fn required(flags: PullFlags) -> PullOptions {
    PullOptions {
        refs: vec!["main".to_owned()],
        flags,
        require_static_deltas: true,
        ..PullOptions::default()
    }
}

/// A destination under `base/<name>` holding `commit` of `src` complete, with
/// no ref.
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

/// The size of each file under `dir`, added up.
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

/// Assert that a failed pull left `dst` with no ref, no object, and no marker
/// for `commit`.
async fn assert_nothing_left(dst_dir: &Path, dst: &Repo, commit: &Checksum) {
    assert!(dst.list_refs(None).await.unwrap().is_empty());
    assert!(dst.list_objects().await.unwrap().is_empty());
    assert!(!has_partial_marker(dst_dir, commit));
}

/// By default a local pull reads no delta: a source whose delta tree is corrupt
/// and unreadable pulls as it does with deltas disabled.
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

/// A pull that requires static deltas applies the source's from-scratch delta:
/// it lands the objects a plain import lands, the commit is complete, and the
/// counts are those of a fetch.
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

/// A destination holding the source of a from-to delta takes that delta, with
/// or without a remote name, whatever ref it holds.
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
            // The summary lists the delta and no index is published, so the
            // index read finds nothing and still counts.
            assert_eq!(stats.metadata_fetched, 2, "{remote:?}");
            assert_eq!(stats.bytes_transferred, tree_size(&dir), "{remote:?}");
            assert_eq!(stats.content_bytes_unpacked, 0, "{remote:?}");
            assert_eq!(dst.commit_state(&c2).await.unwrap(), CommitState::Normal);
            assert!(dst.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        }
    });
}

/// A pull that requires static deltas is refused where no advertised delta
/// produces the commit from what the destination holds, and writes nothing.
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

/// A pull that requires static deltas from a source with no summary is
/// refused, although the source holds a delta and its index.
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

/// A pull that requires static deltas reads an archive source alone.
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

/// A superblock off the digest the summary advertises fails the pull, and a
/// part file off its checksum fails it too. Neither publishes anything.
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

/// A destination that already holds the commit is not refused, although no
/// delta produces the commit from what it holds.
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

/// A commit-only pull that requires static deltas looks for none and is not
/// refused; it counts the commit object as fetched.
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

/// Into an `archive` destination a pull that requires static deltas applies
/// the delta, and the destination passes its fsck.
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

/// `BAREUSERONLY_FILES` reaches an object a local delta delivers, and the
/// refusal publishes nothing.
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

/// A delta of several parts, one of them carrying a 256 KiB file, and a delta
/// whose parts ride inline in the superblock each land the commit whole. Only
/// a part read as a file counts.
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

/// A destination that holds the commit object partial is looked for a delta
/// for. Where the source advertises none, a pull that requires static deltas
/// is refused and leaves the commit partial. Where the source advertises the
/// from-scratch delta, the ref names that commit, so the pull leaves the delta
/// alone, fetches the objects loose, and is not refused.
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
/// it reads the source's mode, and a source outside archive mode before it
/// resolves a ref, which is the order the tool refuses in.
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

/// A FIFO at the source's summary is refused, and the read does not wait on
/// a writer.
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

/// A part file longer than the superblock declares is refused, and the pull
/// publishes nothing.
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

/// Assert that `commit` is complete in `dst`: its state is normal, it keeps no
/// `.commitpartial` marker, and every object it reaches in `src` is present.
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

/// A pull that writes no ref leaves the ref the destination holds as it
/// stands, and stores the pulled commit complete with its detached metadata.
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

/// A pull that writes no ref writes none under the remote prefix either.
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

/// A pull that writes no ref still follows `depth` and completes every
/// commit of the chain.
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

/// The collection id the collection-ref tests read.
const COLLECTION: &str = "org.example.Os";

/// The options of a pull of `refs` as collection refs of [`COLLECTION`], under
/// the remote name `origin`, that writes no ref.
fn collection_pull(refs: &[&str]) -> PullOptions {
    PullOptions {
        refs: refs.iter().map(|name| (*name).to_owned()).collect(),
        remote: Some("origin".to_owned()),
        collection_id: Some(COLLECTION.to_owned()),
        no_ref_writes: true,
        ..PullOptions::default()
    }
}

/// Point the collection ref `name` of `collection` in `repo` at `commit`.
async fn set_collection_ref(repo: &Repo, collection: &str, name: &str, commit: &Checksum) {
    let txn = repo.transaction().await.unwrap();
    txn.set_collection_ref(&CollectionRef::new(collection, name), Some(commit));
    txn.commit().await.unwrap();
}

/// An archive source under `base/thin` that holds only the objects `c2`
/// reaches in `src` and `c1` does not, copied from the archive `src` at
/// `src_dir`, with `c2` under the collection ref `main` of [`COLLECTION`].
/// Returns its path, a handle opened after the copy, and the objects the two
/// commits share.
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

/// Copy the files under `from` to `to`, creating the directories.
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

/// A pull of a collection ref from a source that holds only the objects the
/// new commit adds takes the shared objects from the destination: it reads
/// no object the destination holds and leaves the commit complete.
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

/// The same pull into an empty destination fails, since no repository holds
/// the shared objects, and publishes nothing.
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

/// A collection pull reads the collection ref alone: the ref of the same name
/// under `refs/heads` is not read.
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

/// A name the source holds no collection ref for fails with the path of the
/// collection ref, also where the source holds the name under `refs/heads` or
/// under another collection, and a checksum is read as a ref name.
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
/// commit the ref under the remote name holds, and leaves that ref as it is.
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

/// The ref-binding check reads the name of the collection ref: a commit bound
/// to `main` is refused under `other`, and is taken with the check off.
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

/// A collection pull that would write refs, and one that names no ref, are
/// refused before the source is read, and change nothing in the destination.
/// The source holds no collection ref, so a refusal after the read of the
/// collection ref would fail with [`Error::RefNotFound`], and an empty list
/// would pull the refs under `refs/heads`.
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

/// A collection ref path that names a directory, or that passes through a
/// file, holds no ref: the pull fails with the path of the collection ref, as
/// for an absent one.
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
/// collection ref, so a revision read of either name would find a commit.
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

/// An invalid collection id, and a name that holds `:`, are refused with the
/// pair as the payload before the source is read. The pull requires static
/// deltas and the source holds no summary, so a check after the first read
/// of the source would fail with the error of the absent summary, as the
/// valid pair does.
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

/// Whether the tests run as root, which reads a file of mode `0000`.
fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Give a loose object of `repo_dir` mode `0000`, so a read of it fails with
/// `EACCES` for a user other than root.
fn make_unreadable(repo_dir: &Path, name: &ObjectName, mode: RepoMode) {
    std::fs::set_permissions(
        object_path(repo_dir, name, mode),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
}

/// A destination of `mode` under `base/<name>` holding `commit` of `src`
/// complete, with no ref. Each object is copied, so the destination shares
/// no inode with the source and a mode change in the source does not reach
/// it.
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

/// Assert that a dirtree of the destination is a separate inode from the
/// same dirtree in the source.
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

/// The content object of `nested.txt`, the one file of the subdirectory
/// `build_tree` makes.
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

/// A pull of a commit the destination holds complete reads no object of its
/// tree: each dirtree, dirmeta, and content object of the commit is
/// unreadable in the source, each dirtree of the commit is unreadable in the
/// destination too, so a walk of the tree fails wherever it reads its root,
/// and the pull imports the detached metadata alone. A commit the destination
/// holds partial is walked, and the same pull fails on the first unreadable
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

/// A dirtree the destination holds is read from the destination: each
/// dirtree the two commits share is unreadable in the source, and a pull of
/// the second commit into a destination that holds the first completes it.
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

/// The walk descends into a dirtree the destination holds: a content object
/// below it that the destination lacks is imported from the source, which
/// holds the dirtree unreadable.
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

/// A dirtree the destination holds and no source holds is descended into
/// too. A content object below it that neither the destination nor a source
/// holds fails the pull with [`Error::ObjectNotFound`], and the pull leaves
/// the destination as it found it. Once the source holds the object, the
/// same pull imports it.
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

/// A dirtree the destination holds as a dangling symlink is read from the
/// destination, and the read fails the pull with [`Error::ObjectNotFound`]
/// for that dirtree, although the source holds it. The pull publishes no
/// commit object, no marker, and no ref.
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

/// A pull of a commit the destination holds complete does not walk its tree,
/// so it leaves a content object the destination lost absent. fsck marks the
/// commit partial, and the next pull walks the tree and imports the object.
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
