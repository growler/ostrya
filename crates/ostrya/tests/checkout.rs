//! Checkout-path integration tests (Phase 8).
//!
//! These check the port's [`Repo::checkout_at`] against the `ostree` tool's
//! checkout (mode, ownership, content, symlink targets, and hardlinking) for
//! `bare` + faithful, `bare-user` + unprivileged, and `archive` + faithful; a
//! commit -> checkout -> re-ingest round-trip that must reproduce the commit
//! checksum; the reflink/force-copy path; Docker-style whiteouts; the overwrite
//! modes; subpath resolution; and the include/prune filter. Tool cross-checks
//! are skipped when the `ostree` tool is unavailable.

mod common;

use std::collections::BTreeMap;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{TmpDir, ostree_available};
use ostrya::{
    CheckoutMode, CheckoutOptions, Checksum, CommitModifier, CommitModifierFlags, CommitOptions,
    CreateOptions, DevInoCache, DirMeta, FileMeta, FilterResult, MutableTree, ObjectType, Repo,
    RepoMode, TreeEntry,
};
use ostrya_core::{Xattrs, loose_path};
use ostrya_rt::block_on;

/// The regular-file and directory file-type bits.
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

/// A fixed timestamp so a commit -> checkout -> re-commit round-trip is
/// deterministic.
const FIXED_TS: u64 = 1_700_000_000;

// --- helpers -------------------------------------------------------------

fn run_ostree(args: &[&str]) {
    let output = Command::new("ostree")
        .args(args)
        .output()
        .expect("run ostree");
    assert!(
        output.status.success(),
        "ostree {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The invoking process's uid/gid, recovered from a freshly created file so the
/// tests need no `getuid` binding. Ownership committed and restored as this
/// owner stays within the caller's privilege.
fn self_owner(base: &Path) -> (u32, u32) {
    let probe = base.join(".probe");
    std::fs::write(&probe, b"").unwrap();
    let meta = std::fs::metadata(&probe).unwrap();
    let owner = (meta.uid(), meta.gid());
    std::fs::remove_file(&probe).unwrap();
    owner
}

/// Build a source tree with assorted file types and modes under `dir`.
fn build_source(dir: &Path) {
    std::fs::create_dir_all(dir.join("subdir")).unwrap();
    std::fs::write(dir.join("hello.txt"), b"hello ostree\n").unwrap();
    std::fs::write(dir.join("exec.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    std::fs::write(dir.join("secret"), b"private\n").unwrap();
    std::fs::write(dir.join("empty.txt"), b"").unwrap();
    std::fs::write(dir.join("subdir/nested.txt"), b"nested\n").unwrap();
    symlink("hello.txt", dir.join("link")).unwrap();
    set_mode(&dir.join("hello.txt"), 0o644);
    set_mode(&dir.join("exec.sh"), 0o755);
    set_mode(&dir.join("secret"), 0o600);
    set_mode(&dir.join("empty.txt"), 0o644);
    set_mode(&dir.join("subdir/nested.txt"), 0o644);
    set_mode(&dir.join("subdir"), 0o750);
    set_mode(dir, 0o755);
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// One entry's comparable metadata: type, mode, ownership, and content or
/// target. Link count and xattrs are excluded (the tool differs from the port
/// on the uncompressed-cache link count, and the test crate carries no xattr
/// syscall binding; xattr application is checked by the round-trip test).
#[derive(Debug, PartialEq, Eq)]
enum EntryMeta {
    File {
        mode: u32,
        uid: u32,
        gid: u32,
        content: Vec<u8>,
    },
    Dir {
        mode: u32,
        uid: u32,
        gid: u32,
    },
    Symlink {
        target: PathBuf,
    },
}

/// Collect the metadata of every entry beneath `root`, keyed by relative path.
fn collect_tree(root: &Path) -> BTreeMap<String, EntryMeta> {
    let mut map = BTreeMap::new();
    collect_into(root, root, &mut map);
    map
}

fn collect_into(root: &Path, dir: &Path, map: &mut BTreeMap<String, EntryMeta>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        let ft = meta.file_type();
        if ft.is_symlink() {
            map.insert(
                rel,
                EntryMeta::Symlink {
                    target: std::fs::read_link(&path).unwrap(),
                },
            );
        } else if ft.is_dir() {
            map.insert(
                rel,
                EntryMeta::Dir {
                    mode: meta.mode() & 0o7777,
                    uid: meta.uid(),
                    gid: meta.gid(),
                },
            );
            collect_into(root, &path, map);
        } else {
            map.insert(
                rel,
                EntryMeta::File {
                    mode: meta.mode() & 0o7777,
                    uid: meta.uid(),
                    gid: meta.gid(),
                    content: std::fs::read(&path).unwrap(),
                },
            );
        }
    }
}

/// The `(dev, ino)` of a file, via `symlink_metadata` (no-follow).
fn dev_ino(path: &Path) -> (u64, u64) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.dev(), meta.ino())
}

/// The `(dev, ino)` of a loose content object.
fn object_dev_ino(repo_root: &Path, checksum: &Checksum, mode: RepoMode) -> (u64, u64) {
    let path = repo_root
        .join("objects")
        .join(loose_path(checksum, ObjectType::File, mode));
    dev_ino(&path)
}

/// Resolve a file entry's content checksum within a commit tree.
async fn file_checksum(repo: &Repo, rev: &str, name: &str) -> Checksum {
    let (tree, _) = repo.read_commit(rev).await.unwrap();
    match tree.lookup(Path::new(name)).await.unwrap() {
        Some(TreeEntry::File { checksum, .. }) => checksum,
        other => panic!("expected a file entry for {name}, got {other:?}"),
    }
}

/// Cross-check the port's checkout of a tool-committed tree against the tool's
/// own checkout, for a given repository mode and checkout mode.
fn cross_check(repo_mode: &str, port_mode: CheckoutMode, user_flag: bool) {
    if !ostree_available() {
        eprintln!("skipping checkout cross-check for {repo_mode}: the ostree tool is unavailable");
        return;
    }
    let tmp = TmpDir::new(&format!("co-cross-{repo_mode}"));
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);
    let repo_dir = base.join("repo");
    let repo_arg = format!("--repo={}", repo_dir.display());

    run_ostree(&[&repo_arg, "init", &format!("--mode={repo_mode}")]);
    run_ostree(&[
        &repo_arg,
        "commit",
        "-b",
        "main",
        "-s",
        "cross",
        "--no-xattrs",
        src.to_str().unwrap(),
    ]);

    // The tool's reference checkout.
    let co_tool = base.join("co-tool");
    let mut tool_args = vec![repo_arg.as_str(), "checkout"];
    if user_flag {
        tool_args.push("-U");
    }
    tool_args.push("main");
    tool_args.push(co_tool.to_str().unwrap());
    run_ostree(&tool_args);

    // The port's checkout.
    let co_port = base.join("co-port");
    let (storage_mode, hello) = block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let commit = repo.resolve_rev("main", false).await.unwrap().unwrap();
        let mut opts = CheckoutOptions::new(port_mode);
        let base_fd = std::fs::File::open(base).unwrap();
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("co-port"), &commit)
            .await
            .unwrap();
        let hello = file_checksum(&repo, &commit.to_hex(), "hello.txt").await;
        (repo.mode(), hello)
    });

    // The two trees agree on type, mode, ownership, content, and targets.
    assert_eq!(
        collect_tree(&co_tool),
        collect_tree(&co_port),
        "port checkout of a {repo_mode} repo diverges from the tool"
    );

    // The destination roots agree too (the root receives the tree root's
    // dirmeta).
    let tool_root = std::fs::metadata(&co_tool).unwrap();
    let port_root = std::fs::metadata(&co_port).unwrap();
    assert_eq!(tool_root.mode() & 0o7777, port_root.mode() & 0o7777);

    // The hardlinking outcome the mode dictates: the destination file shares the
    // object inode exactly when a hardlink checkout is expected.
    let dest = dev_ino(&co_port.join("hello.txt"));
    let object = object_dev_ino(&repo_dir, &hello, storage_mode);
    let expect_hardlink = matches!(
        (storage_mode, port_mode),
        (RepoMode::Bare, CheckoutMode::None)
            | (RepoMode::BareUser, CheckoutMode::User)
            | (RepoMode::BareUserOnly, _)
    );
    if expect_hardlink {
        assert_eq!(
            dest, object,
            "{repo_mode} + {port_mode:?} must hardlink the object into place"
        );
    } else {
        assert_ne!(
            dest, object,
            "{repo_mode} + {port_mode:?} must copy, not hardlink"
        );
    }
}

// --- tool cross-checks ---------------------------------------------------

#[test]
fn bare_none_matches_tool() {
    cross_check("bare", CheckoutMode::None, false);
}

#[test]
fn bare_user_user_matches_tool() {
    cross_check("bare-user", CheckoutMode::User, true);
}

#[test]
fn archive_none_matches_tool() {
    cross_check("archive-z2", CheckoutMode::None, false);
}

// bare-user-only carries no ownership and its objects hold the canonical mode
// on the inode, so both a faithful and an unprivileged checkout hardlink the
// object and produce the same tree the tool does.
#[test]
fn bare_user_only_none_matches_tool() {
    cross_check("bare-user-only", CheckoutMode::None, false);
}

#[test]
fn bare_user_only_user_matches_tool() {
    cross_check("bare-user-only", CheckoutMode::User, true);
}

/// bare-user-only forces user semantics, so a faithful (None) and an
/// unprivileged (User) checkout produce identical trees, and each hardlinks the
/// object into place. This holds without the tool, so it runs unconditionally.
#[test]
fn bare_user_only_faithful_equals_unprivileged() {
    let tmp = TmpDir::new("co-buo-equiv");
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);
    let repo_dir = base.join("repo");

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::BareUserOnly))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let hello = file_checksum(&repo, &commit.to_hex(), "hello.txt").await;
        let base_fd = std::fs::File::open(base).unwrap();

        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("co_none"), &commit)
            .await
            .unwrap();
        let mut opts = CheckoutOptions::new(CheckoutMode::User);
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("co_user"), &commit)
            .await
            .unwrap();

        assert_eq!(
            collect_tree(&base.join("co_none")),
            collect_tree(&base.join("co_user")),
            "bare-user-only faithful and unprivileged checkouts are identical"
        );

        let object = object_dev_ino(&repo_dir, &hello, RepoMode::BareUserOnly);
        assert_eq!(
            dev_ino(&base.join("co_none").join("hello.txt")),
            object,
            "a faithful bare-user-only checkout hardlinks the object"
        );
        assert_eq!(
            dev_ino(&base.join("co_user").join("hello.txt")),
            object,
            "an unprivileged bare-user-only checkout hardlinks the object"
        );
    });
}

/// force_copy suppresses the hardlink bare-user-only would otherwise use: the
/// destination is a fresh inode with byte-identical content and the canonical
/// mode (& 0o777) applied by the copy path.
#[test]
fn bare_user_only_force_copy_makes_an_independent_copy() {
    let tmp = TmpDir::new("co-buo-copy");
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);
    let repo_dir = base.join("repo");

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::BareUserOnly))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let hello = file_checksum(&repo, &commit.to_hex(), "hello.txt").await;
        let base_fd = std::fs::File::open(base).unwrap();

        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.force_copy = true;
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("co"), &commit)
            .await
            .unwrap();

        let dest = base.join("co").join("hello.txt");
        assert_ne!(
            dev_ino(&dest),
            object_dev_ino(&repo_dir, &hello, RepoMode::BareUserOnly),
            "force_copy must not hardlink the object"
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello ostree\n");
        assert_eq!(
            std::fs::metadata(&dest).unwrap().mode() & 0o777,
            0o644,
            "the copy path applies the canonical mode (& 0o777)"
        );
    });
}

// --- round-trip stability -----------------------------------------------

#[test]
fn commit_checkout_roundtrip_is_stable() {
    let tmp = TmpDir::new("co-roundtrip");
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);
    let repo_dir = base.join("repo");

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();

        // Commit the source tree preserving its ownership and modes.
        let commit1 = {
            let txn = repo.transaction().await.unwrap();
            let mut mtree = MutableTree::new();
            let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
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
            let commit = txn.write_commit(roundtrip_options(), &root).await.unwrap();
            txn.commit().await.unwrap();
            commit
        };

        // Check it out faithfully.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        let base_fd = std::fs::File::open(base).unwrap();
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("co"), &commit1)
            .await
            .unwrap();

        // Re-ingest the checkout: the same tree yields the same commit.
        let commit2 = {
            let txn = repo.transaction().await.unwrap();
            let mut mtree = MutableTree::new();
            let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
            let dfd = std::fs::File::open(base).unwrap();
            txn.write_dfd_to_mtree(
                dfd.as_fd(),
                Path::new("co"),
                &mut mtree,
                Some(&mut modifier),
            )
            .await
            .unwrap();
            let root = txn.write_mtree(&mut mtree).await.unwrap();
            let commit = txn.write_commit(roundtrip_options(), &root).await.unwrap();
            txn.commit().await.unwrap();
            commit
        };

        assert_eq!(
            commit1, commit2,
            "a commit -> checkout -> re-commit round-trip is stable"
        );
    });
}

fn roundtrip_options() -> CommitOptions {
    CommitOptions {
        subject: Some("roundtrip".to_owned()),
        timestamp: Some(FIXED_TS),
        ..CommitOptions::default()
    }
}

/// bare-user-shared is a development-only mode the ostree tool does not provide,
/// so it has no tool cross-check. A commit -> checkout -> re-commit round-trip
/// that reproduces the commit checksum exercises the copy path (bare-user-shared
/// never hardlinks) and the `user.ostreemeta`-derived metadata: the re-commit
/// matches only if the checkout reproduced each entry's logical mode, ownership,
/// and content.
#[test]
fn bare_user_shared_roundtrip_is_stable() {
    let tmp = TmpDir::new("co-bus-roundtrip");
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);
    let repo_dir = base.join("repo");

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::BareUserShared))
            .await
            .unwrap();
        let commit1 = commit_tree_stable(&repo, base, "src").await;

        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        let base_fd = std::fs::File::open(base).unwrap();
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("co"), &commit1)
            .await
            .unwrap();

        let commit2 = commit_tree_stable(&repo, base, "co").await;
        assert_eq!(
            commit1, commit2,
            "a bare-user-shared commit -> checkout -> re-commit round-trip is stable"
        );
    });
}

/// Commit subtree `sub` of `base` with a fixed timestamp, so re-committing the
/// same tree reproduces the commit checksum.
async fn commit_tree_stable(repo: &Repo, base: &Path, sub: &str) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new(sub), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn.write_commit(roundtrip_options(), &root).await.unwrap();
    txn.commit().await.unwrap();
    commit
}

// --- xattr application via a copy-path round-trip ------------------------

#[test]
fn checkout_applies_logical_xattrs() {
    // A bare-user repo copies (not hardlinks) under a faithful checkout, so this
    // exercises the copy path's xattr application: a file committed with a
    // `user.demo` xattr, checked out, and re-ingested, must reproduce its
    // content checksum -- which is only possible if the xattr was applied to the
    // destination inode and read back.
    let tmp = TmpDir::new("co-xattr");
    let base = tmp.path();
    let repo_dir = base.join("repo");
    let (uid, gid) = self_owner(base);

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();

        let file_csum;
        let commit = {
            let txn = repo.transaction().await.unwrap();
            let meta = FileMeta {
                uid,
                gid,
                mode: S_IFREG | 0o644,
                xattrs: Xattrs::new([(b"user.demo\0".to_vec(), b"value".to_vec())]).unwrap(),
            };
            file_csum = txn
                .write_regfile_inline(None, &meta, b"payload\n")
                .await
                .unwrap();
            let dirmeta = DirMeta {
                uid,
                gid,
                mode: S_IFDIR | 0o755,
                xattrs: Xattrs::empty(),
            };
            let dm = txn
                .write_metadata(ObjectType::DirMeta, None, &dirmeta.serialize().unwrap())
                .await
                .unwrap();
            let mut mtree = MutableTree::new();
            mtree.set_metadata_checksum(dm);
            mtree.replace_file("hello.txt", file_csum).unwrap();
            let root = txn.write_mtree(&mut mtree).await.unwrap();
            let commit = txn
                .write_commit(CommitOptions::default(), &root)
                .await
                .unwrap();
            txn.commit().await.unwrap();
            commit
        };

        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        let base_fd = std::fs::File::open(base).unwrap();
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("co"), &commit)
            .await
            .unwrap();

        // Re-ingest the checked-out file: its content object identity, which
        // covers the xattr set, must match the original.
        let txn = repo.transaction().await.unwrap();
        let mut mtree = MutableTree::new();
        let dfd = std::fs::File::open(base).unwrap();
        txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("co"), &mut mtree, None)
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let reingested = match root.lookup(Path::new("hello.txt")).await.unwrap() {
            Some(TreeEntry::File { checksum, .. }) => checksum,
            other => panic!("expected hello.txt file, got {other:?}"),
        };
        txn.abort().await.unwrap();
        assert_eq!(
            reingested, file_csum,
            "checkout applied and preserved the logical xattr set"
        );
    });
}

#[test]
fn checkout_applies_xattrs_to_read_only_entries() {
    // A file and a directory whose logical modes carry no owner-write bit, each
    // with a `user.*` xattr. The kernel checks a `user.*` xattr against the
    // inode's write permission, so the xattrs are applied before the mode. The
    // repository is archive, which stores the logical metadata in the object
    // header and so holds entries of any mode.
    let tmp = TmpDir::new("co-readonly");
    let base = tmp.path();
    let repo_dir = base.join("repo");
    let (uid, gid) = self_owner(base);

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = {
            let txn = repo.transaction().await.unwrap();
            let meta = FileMeta {
                uid,
                gid,
                mode: S_IFREG | 0o444,
                xattrs: Xattrs::new([(b"user.demo\0".to_vec(), b"value".to_vec())]).unwrap(),
            };
            let file = txn
                .write_regfile_inline(None, &meta, b"read only\n")
                .await
                .unwrap();
            let dirmeta = DirMeta {
                uid,
                gid,
                mode: S_IFDIR | 0o555,
                xattrs: Xattrs::new([(b"user.dir\0".to_vec(), b"d".to_vec())]).unwrap(),
            };
            let dm = txn
                .write_metadata(ObjectType::DirMeta, None, &dirmeta.serialize().unwrap())
                .await
                .unwrap();
            let mut mtree = MutableTree::new();
            mtree.set_metadata_checksum(dm);
            mtree.replace_file("ro.txt", file).unwrap();
            let root = txn.write_mtree(&mut mtree).await.unwrap();
            let commit = txn
                .write_commit(CommitOptions::default(), &root)
                .await
                .unwrap();
            txn.commit().await.unwrap();
            commit
        };

        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        let base_fd = std::fs::File::open(base).unwrap();
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("co"), &commit)
            .await
            .unwrap();

        let dir = base.join("co");
        let file = dir.join("ro.txt");
        assert_eq!(mode_of(&dir), 0o555, "directory mode");
        assert_eq!(mode_of(&file), 0o444, "file mode");
        assert_eq!(xattr_of(&dir, "user.dir"), b"d", "directory xattr");
        assert_eq!(xattr_of(&file, "user.demo"), b"value", "file xattr");

        // The checked-out directory is read-only, which its own cleanup needs
        // reversed.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    });
}

/// The permission bits of a checked-out path.
fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

/// The value of a checked-out path's named xattr.
fn xattr_of(path: &Path, name: &str) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = rustix::fs::getxattr(path, name, &mut buf)
        .unwrap_or_else(|e| panic!("getxattr({name}) on {}: {e}", path.display()));
    buf[..n].to_vec()
}

// --- reflink / force-copy ------------------------------------------------

#[test]
fn force_copy_makes_an_independent_copy() {
    // A bare repo hardlinks under a faithful checkout; force_copy suppresses the
    // hardlink, so the destination is a fresh inode with byte-identical content.
    // The copy path attempts a FICLONE reflink and falls back cleanly to a byte
    // copy where the filesystem refuses it; either way the result is correct.
    let tmp = TmpDir::new("co-forcecopy");
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);
    let repo_dir = base.join("repo");

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = {
            let txn = repo.transaction().await.unwrap();
            let mut mtree = MutableTree::new();
            let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
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
                .write_commit(CommitOptions::default(), &root)
                .await
                .unwrap();
            txn.commit().await.unwrap();
            commit
        };

        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.force_copy = true;
        let base_fd = std::fs::File::open(base).unwrap();
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("co"), &commit)
            .await
            .unwrap();

        let hello = file_checksum(&repo, &commit.to_hex(), "hello.txt").await;
        let dest = base.join("co/hello.txt");
        assert_ne!(
            dev_ino(&dest),
            object_dev_ino(&repo_dir, &hello, RepoMode::Bare),
            "force_copy must not hardlink the object"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"hello ostree\n",
            "the copy is byte-identical to the committed content"
        );
    });
}

// --- whiteouts -----------------------------------------------------------

#[test]
fn whiteouts_processed_and_literal() {
    let tmp = TmpDir::new("co-whiteout");
    let base = tmp.path();
    let repo_dir = base.join("repo");

    // A base layer, and a whiteout layer over it.
    let base_src = base.join("base");
    std::fs::create_dir_all(base_src.join("subdir")).unwrap();
    std::fs::write(base_src.join("keep.txt"), b"old\n").unwrap();
    std::fs::write(base_src.join("gone.txt"), b"remove me\n").unwrap();
    std::fs::write(base_src.join("subdir/preexisting.txt"), b"stale\n").unwrap();

    let layer_src = base.join("layer");
    std::fs::create_dir_all(layer_src.join("subdir")).unwrap();
    std::fs::write(layer_src.join("keep.txt"), b"new\n").unwrap();
    std::fs::write(layer_src.join(".wh.gone.txt"), b"").unwrap();
    std::fs::write(layer_src.join("subdir/child.txt"), b"child\n").unwrap();
    std::fs::write(layer_src.join("subdir/.wh..wh..opq"), b"").unwrap();

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let base_commit = commit_tree(&repo, base, "base").await;
        let layer_commit = commit_tree(&repo, base, "layer").await;
        let base_fd = std::fs::File::open(base).unwrap();

        // Check out the base, then the layer over it with whiteouts processed.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        repo.checkout_at(
            &mut opts,
            base_fd.as_fd(),
            Path::new("merged"),
            &base_commit,
        )
        .await
        .unwrap();
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionFiles;
        opts.process_whiteouts = true;
        repo.checkout_at(
            &mut opts,
            base_fd.as_fd(),
            Path::new("merged"),
            &layer_commit,
        )
        .await
        .unwrap();

        let merged = base.join("merged");
        assert_eq!(std::fs::read(merged.join("keep.txt")).unwrap(), b"new\n");
        assert!(
            !merged.join("gone.txt").exists(),
            "whiteout removed gone.txt"
        );
        assert!(
            !merged.join(".wh.gone.txt").exists(),
            "the whiteout marker is not materialized"
        );
        assert!(
            !merged.join("subdir/preexisting.txt").exists(),
            "the opaque marker cleared the pre-existing subdir content"
        );
        assert_eq!(
            std::fs::read(merged.join("subdir/child.txt")).unwrap(),
            b"child\n"
        );
        assert!(
            !merged.join("subdir/.wh..wh..opq").exists(),
            "the opaque marker is not materialized"
        );

        // Without whiteout processing, the markers check out as ordinary files.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        repo.checkout_at(
            &mut opts,
            base_fd.as_fd(),
            Path::new("literal"),
            &layer_commit,
        )
        .await
        .unwrap();
        let literal = base.join("literal");
        assert!(
            literal.join(".wh.gone.txt").exists(),
            "with whiteouts off, .wh.gone.txt is an ordinary file"
        );
        assert!(literal.join("subdir/.wh..wh..opq").exists());
    });
}

// --- overwrite modes -----------------------------------------------------

#[test]
fn overwrite_modes() {
    let tmp = TmpDir::new("co-overwrite");
    let base = tmp.path();
    let repo_dir = base.join("repo");

    let a = base.join("a");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::write(a.join("hello.txt"), b"A\n").unwrap();
    std::fs::write(a.join("same.txt"), b"same\n").unwrap();
    std::fs::write(a.join("aonly.txt"), b"A\n").unwrap();

    let b = base.join("b");
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(b.join("hello.txt"), b"B\n").unwrap();
    std::fs::write(b.join("same.txt"), b"same\n").unwrap();
    std::fs::write(b.join("bonly.txt"), b"B\n").unwrap();

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit_a = commit_tree(&repo, base, "a").await;
        let commit_b = commit_tree(&repo, base, "b").await;
        let base_fd = std::fs::File::open(base).unwrap();

        // UnionFiles: overwrite existing files, keep others, add new.
        checkout_none(&repo, base_fd.as_fd(), "union", &commit_a).await;
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionFiles;
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("union"), &commit_b)
            .await
            .unwrap();
        let union = base.join("union");
        assert_eq!(std::fs::read(union.join("hello.txt")).unwrap(), b"B\n");
        assert_eq!(std::fs::read(union.join("same.txt")).unwrap(), b"same\n");
        assert_eq!(std::fs::read(union.join("aonly.txt")).unwrap(), b"A\n");
        assert_eq!(std::fs::read(union.join("bonly.txt")).unwrap(), b"B\n");

        // AddFiles: keep existing, only add new.
        checkout_none(&repo, base_fd.as_fd(), "add", &commit_a).await;
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::AddFiles;
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("add"), &commit_b)
            .await
            .unwrap();
        let add = base.join("add");
        assert_eq!(
            std::fs::read(add.join("hello.txt")).unwrap(),
            b"A\n",
            "add-files keeps the existing file"
        );
        assert_eq!(std::fs::read(add.join("bonly.txt")).unwrap(), b"B\n");

        // UnionIdentical: a differing file is a conflict.
        checkout_none(&repo, base_fd.as_fd(), "ident", &commit_a).await;
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionIdentical;
        let err = repo
            .checkout_at(&mut opts, base_fd.as_fd(), Path::new("ident"), &commit_b)
            .await;
        assert!(
            matches!(err, Err(ostrya::Error::Checkout(_))),
            "union-identical over a differing file is a conflict, got {err:?}"
        );

        // UnionIdentical over an identical tree succeeds (the objects are the
        // same inodes the base checkout hardlinked).
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionIdentical;
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("ident"), &commit_a)
            .await
            .expect("union-identical over an identical tree is a no-op");
    });
}

/// union-identical establishes identity by the object inode, so it is
/// meaningful only for a hardlink checkout. A copy-mode repository (archive) or
/// a forced copy cannot hardlink, so the checkout is rejected before the
/// destination is created, matching the tool's refusal to run
/// `--union-identical` without `--require-hardlinks`.
#[test]
fn union_identical_requires_hardlink_mode() {
    let tmp = TmpDir::new("co-ui-guard");
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);

    block_on(async {
        // archive checks out by copy under both modes, so union-identical is
        // rejected up front.
        let archive_dir = base.join("archive");
        let repo = Repo::create(&archive_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let base_fd = std::fs::File::open(base).unwrap();
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionIdentical;
        let err = repo
            .checkout_at(&mut opts, base_fd.as_fd(), Path::new("co_archive"), &commit)
            .await;
        assert!(
            matches!(err, Err(ostrya::Error::Checkout(_))),
            "union-identical on a copy-mode repo is rejected, got {err:?}"
        );
        assert!(
            !base.join("co_archive").exists(),
            "the destination is not created when union-identical is rejected"
        );

        // force_copy suppresses the hardlink a bare + faithful checkout would
        // otherwise use, so union-identical is rejected there too.
        let bare_dir = base.join("bare");
        let repo = Repo::create(&bare_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionIdentical;
        opts.force_copy = true;
        let err = repo
            .checkout_at(
                &mut opts,
                base_fd.as_fd(),
                Path::new("co_forcecopy"),
                &commit,
            )
            .await;
        assert!(
            matches!(err, Err(ostrya::Error::Checkout(_))),
            "union-identical under force_copy is rejected, got {err:?}"
        );
        assert!(!base.join("co_forcecopy").exists());
    });
}

// --- type conflict -------------------------------------------------------

/// A destination name held by a file when the commit carries a directory of
/// that name is a conflict in every mode: the checkout errors rather than
/// replacing the entry, and the file is left in place. (The `ostree` tool errors
/// here too, with `opendir(<name>): Not a directory`.)
#[test]
fn file_where_commit_has_directory_is_a_conflict() {
    let tmp = TmpDir::new("co-typeconflict");
    let base = tmp.path();
    let repo_dir = base.join("repo");

    // A tree whose `clash` is a regular file, plus a file to survive the merge.
    let cf = base.join("cf");
    std::fs::create_dir_all(&cf).unwrap();
    std::fs::write(cf.join("clash"), b"i am a file\n").unwrap();
    std::fs::write(cf.join("keep"), b"keep\n").unwrap();

    // A tree whose `clash` is a directory.
    let cd = base.join("cd");
    std::fs::create_dir_all(cd.join("clash")).unwrap();
    std::fs::write(cd.join("clash").join("bar"), b"nested\n").unwrap();

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit_file = commit_tree(&repo, base, "cf").await;
        let commit_dir = commit_tree(&repo, base, "cd").await;
        let base_fd = std::fs::File::open(base).unwrap();

        // The union modes reach the conflict at a nested child: the top-level
        // destination is reused, then `clash` collides.
        for mode in [
            ostrya::OverwriteMode::UnionFiles,
            ostrya::OverwriteMode::AddFiles,
            ostrya::OverwriteMode::UnionIdentical,
        ] {
            let dest_name = format!("u_{mode:?}");
            checkout_none(&repo, base_fd.as_fd(), &dest_name, &commit_file).await;
            let mut opts = CheckoutOptions::new(CheckoutMode::None);
            opts.overwrite = mode;
            let err = repo
                .checkout_at(
                    &mut opts,
                    base_fd.as_fd(),
                    Path::new(&dest_name),
                    &commit_dir,
                )
                .await;
            assert!(
                matches!(err, Err(ostrya::Error::Checkout(_))),
                "{mode:?}: a file where the commit has a directory is a conflict, got {err:?}"
            );
            let clash = base.join(&dest_name).join("clash");
            assert!(
                clash.is_file(),
                "{mode:?}: the existing file is left in place"
            );
            assert_eq!(std::fs::read(&clash).unwrap(), b"i am a file\n");
        }

        // Default (None) reaches the same guard at the destination root: a plain
        // file where the checkout would otherwise create the root directory.
        std::fs::write(base.join("none_clash"), b"i am a file\n").unwrap();
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        let err = repo
            .checkout_at(
                &mut opts,
                base_fd.as_fd(),
                Path::new("none_clash"),
                &commit_dir,
            )
            .await;
        assert!(
            matches!(err, Err(ostrya::Error::Checkout(_))),
            "None: a file at the destination root is a conflict, got {err:?}"
        );
        assert!(base.join("none_clash").is_file());
    });
}

/// A destination directory when the commit carries a file of that name is a
/// conflict under union-files and union-identical (the directory is left in
/// place), while add-files keeps the directory and writes nothing for that name.
/// (Matches `ostree` 2026.1: union-files errors with `renameat(...): Is a
/// directory`, union-identical errors, add-files keeps the directory.)
#[test]
fn directory_where_commit_has_file_follows_the_tool() {
    let tmp = TmpDir::new("co-dirfile");
    let base = tmp.path();
    let repo_dir = base.join("repo");

    // A tree whose `clash` is a directory with a child.
    let cd = base.join("cd");
    std::fs::create_dir_all(cd.join("clash")).unwrap();
    std::fs::write(cd.join("clash").join("bar"), b"nested\n").unwrap();
    std::fs::write(cd.join("keep"), b"keep\n").unwrap();

    // A tree whose `clash` is a regular file.
    let cf = base.join("cf");
    std::fs::create_dir_all(&cf).unwrap();
    std::fs::write(cf.join("clash"), b"i am a file\n").unwrap();

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit_dir = commit_tree(&repo, base, "cd").await;
        let commit_file = commit_tree(&repo, base, "cf").await;
        let base_fd = std::fs::File::open(base).unwrap();

        // union-files and union-identical: a conflict; the directory stays.
        for mode in [
            ostrya::OverwriteMode::UnionFiles,
            ostrya::OverwriteMode::UnionIdentical,
        ] {
            let dest_name = format!("d_{mode:?}");
            checkout_none(&repo, base_fd.as_fd(), &dest_name, &commit_dir).await;
            let mut opts = CheckoutOptions::new(CheckoutMode::None);
            opts.overwrite = mode;
            let err = repo
                .checkout_at(
                    &mut opts,
                    base_fd.as_fd(),
                    Path::new(&dest_name),
                    &commit_file,
                )
                .await;
            assert!(
                matches!(err, Err(ostrya::Error::Checkout(_))),
                "{mode:?}: a directory where the commit has a file is a conflict, got {err:?}"
            );
            let clash = base.join(&dest_name).join("clash");
            assert!(
                clash.is_dir(),
                "{mode:?}: the existing directory is left in place"
            );
            assert_eq!(std::fs::read(clash.join("bar")).unwrap(), b"nested\n");
        }

        // add-files: the directory is kept and nothing is written for that name.
        checkout_none(&repo, base_fd.as_fd(), "d_add", &commit_dir).await;
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::AddFiles;
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("d_add"), &commit_file)
            .await
            .expect("add-files keeps the existing directory");
        let clash = base.join("d_add").join("clash");
        assert!(clash.is_dir(), "add-files keeps the existing directory");
        assert_eq!(std::fs::read(clash.join("bar")).unwrap(), b"nested\n");
    });
}

// --- subpath -------------------------------------------------------------

#[test]
fn subpath_directory_and_file() {
    let tmp = TmpDir::new("co-subpath");
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);
    let repo_dir = base.join("repo");

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let base_fd = std::fs::File::open(base).unwrap();

        // A subpath to a directory: the subtree becomes the destination root,
        // and the root takes the subdir's dirmeta (mode 0750).
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.subpath = Some(PathBuf::from("subdir"));
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("sub"), &commit)
            .await
            .unwrap();
        let sub = base.join("sub");
        assert_eq!(
            std::fs::metadata(&sub).unwrap().mode() & 0o7777,
            0o750,
            "the destination root takes the subtree root's dirmeta"
        );
        assert_eq!(std::fs::read(sub.join("nested.txt")).unwrap(), b"nested\n");

        // A subpath to a single file: the destination directory holds the one
        // object under its name.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.subpath = Some(PathBuf::from("hello.txt"));
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("onefile"), &commit)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(base.join("onefile/hello.txt")).unwrap(),
            b"hello ostree\n"
        );

        // A missing subpath is an error.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.subpath = Some(PathBuf::from("nope"));
        let err = repo
            .checkout_at(&mut opts, base_fd.as_fd(), Path::new("missing"), &commit)
            .await;
        assert!(matches!(err, Err(ostrya::Error::Checkout(_))));
    });
}

// --- filter --------------------------------------------------------------

#[test]
fn filter_prunes_a_subtree() {
    let tmp = TmpDir::new("co-filter");
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);
    let repo_dir = base.join("repo");

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let base_fd = std::fs::File::open(base).unwrap();

        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.filter = Some(Box::new(|path: &Path, _meta: &FileMeta| {
            if path == Path::new("/subdir") || path == Path::new("/secret") {
                FilterResult::Skip
            } else {
                FilterResult::Allow
            }
        }));
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("filtered"), &commit)
            .await
            .unwrap();

        let filtered = base.join("filtered");
        assert!(filtered.join("hello.txt").exists());
        assert!(!filtered.join("subdir").exists(), "the subtree was pruned");
        assert!(!filtered.join("secret").exists(), "the file was skipped");
    });
}

// --- devino cache --------------------------------------------------------

#[test]
fn checkout_populates_devino_cache() {
    let tmp = TmpDir::new("co-devino");
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);
    let repo_dir = base.join("repo");

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let base_fd = std::fs::File::open(base).unwrap();

        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.devino_cache = Some(DevInoCache::new());
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("co"), &commit)
            .await
            .unwrap();

        let cache = opts.devino_cache.unwrap();
        assert!(!cache.is_empty(), "checkout recorded regular-file inodes");
        // The recorded inode for hello.txt maps back to its checksum.
        let hello = file_checksum(&repo, &commit.to_hex(), "hello.txt").await;
        let (dev, ino) = dev_ino(&base.join("co/hello.txt"));
        assert_eq!(cache.get(dev, ino), Some(hello));
    });
}

// --- partial commit ------------------------------------------------------

#[test]
fn checkout_rejects_a_partial_commit() {
    let tmp = TmpDir::new("co-partial");
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);
    let repo_dir = base.join("repo");

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let base_fd = std::fs::File::open(base).unwrap();

        // A `.commitpartial` marker makes the commit report as partial. Checkout
        // rejects it up front instead of failing on the first missing object.
        std::fs::create_dir_all(repo_dir.join("state")).unwrap();
        std::fs::write(
            repo_dir.join(format!("state/{}.commitpartial", commit.to_hex())),
            b"",
        )
        .unwrap();

        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        let err = repo
            .checkout_at(&mut opts, base_fd.as_fd(), Path::new("co"), &commit)
            .await;
        assert!(
            matches!(&err, Err(ostrya::Error::Checkout(msg)) if msg.contains("partial")),
            "expected a partial-commit checkout error, got {err:?}"
        );
        assert!(
            !base.join("co").exists(),
            "the destination is not created for a partial commit"
        );
    });
}

// --- shared commit helper ------------------------------------------------

/// Commit the subtree `sub` of `base` into `repo`, returning the commit
/// checksum. Ownership and modes are preserved; xattrs are skipped.
async fn commit_tree(repo: &Repo, base: &Path, sub: &str) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new(sub), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(CommitOptions::default(), &root)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    commit
}

/// Faithfully check `commit` out to `dest` under `base_fd`.
async fn checkout_none(
    repo: &Repo,
    base_fd: std::os::fd::BorrowedFd<'_>,
    dest: &str,
    commit: &Checksum,
) {
    let mut opts = CheckoutOptions::new(CheckoutMode::None);
    repo.checkout_at(&mut opts, base_fd, Path::new(dest), commit)
        .await
        .unwrap();
}

/// The public checkout types move across threads.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<CheckoutOptions>();
};
