//! Local pull between two repositories (Phase 16b).
//!
//! The source repositories are built with the port itself, so the flag and
//! traversal behavior is covered without the `ostree` tool; the interop tests
//! that need the tool build a source with it, or hand it what the port pulled,
//! and are skipped when it is absent.

mod common;

use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{TmpDir, ostree_available};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CommitState, CreateOptions,
    Error, MutableTree, PullFlags, PullOptions, Repo, RepoMode, Type, Value,
};
use ostrya_rt::block_on;

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
    )
    .await
}

/// Commit subtree `sub` as [`commit_tree`] does, under the given modifier flags.
async fn commit_tree_with(
    repo: &Repo,
    base: &Path,
    sub: &str,
    branch: &str,
    parent: Option<Checksum>,
    flags: CommitModifierFlags,
) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(flags);
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
/// by group `gid`, which is the arrangement `format-reference.md` prescribes for a
/// group-shared repository. Every object written there takes `gid`.
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
    let c1 = commit_tree_with(&repo, base, "v1", "main", None, flags).await;
    let c2 = commit_tree_with(&repo, base, "v2", "main", Some(c1), flags).await;
    (path, repo, c1, c2)
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
        // Committed without canonical permissions, so every object carries the
        // committing process's uid and gid, which this mode discards.
        let (_src_dir, src, _c1, _c2) = source_repo(base, RepoMode::BareUser).await;
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
        assert!(has_partial_marker(&dst_dir, &c2));
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
fn a_failed_pull_publishes_nothing_and_leaves_the_marker() {
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
        assert!(has_partial_marker(&dst_dir, &c2));
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
        assert!(has_partial_marker(&bare_dir, &c2));
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
