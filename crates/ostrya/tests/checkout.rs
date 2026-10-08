//! Integration tests for checkout.
//!
//! These tests compare [`Repo::checkout_at`] of ostrya with the checkout of the
//! `ostree` command. They compare the mode, the ownership, the content, the
//! symlink targets, and the hardlinks for these pairs:
//!
//! - `bare` with a faithful checkout
//! - `bare-user` with an unprivileged checkout
//! - `archive` with a faithful checkout
//!
//! Other tests cover:
//!
//! - a commit -> checkout -> re-ingest round-trip that must give the same
//!   commit checksum
//! - the reflink and force-copy path
//! - Docker-style whiteouts
//! - the overwrite modes
//! - subpath resolution
//! - the include and prune filter
//!
//! If the `ostree` command is not available, the comparison tests skip.

mod common;

use std::collections::BTreeMap;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

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

/// A fixed timestamp that makes a commit -> checkout -> re-commit round-trip
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

/// Returns the uid and gid of the process, read from a new file, so the tests
/// need no `getuid` binding. If a commit records this owner and a checkout
/// restores it, no step needs more privilege than the caller has.
fn self_owner(base: &Path) -> (u32, u32) {
    let probe = base.join(".probe");
    std::fs::write(&probe, b"").unwrap();
    let meta = std::fs::metadata(&probe).unwrap();
    let owner = (meta.uid(), meta.gid());
    std::fs::remove_file(&probe).unwrap();
    owner
}

/// Builds a source tree with different file types and modes under `dir`.
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

/// The metadata of one entry that the tests compare: the type, the mode, the
/// ownership, and the content or the target.
///
/// The comparison excludes the link count and the xattrs. The `ostree` command
/// and ostrya give different link counts for the uncompressed cache.
/// `collect_tree` reads no xattr. The round-trip test and the tests that call
/// `xattr_of` check the xattrs.
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

/// Collects the metadata of each entry under `root`, keyed by relative path.
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

/// Returns the `(dev, ino)` of a file, from `symlink_metadata` (no-follow).
fn dev_ino(path: &Path) -> (u64, u64) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.dev(), meta.ino())
}

/// Returns the `(dev, ino)` of a loose content object.
fn object_dev_ino(repo_root: &Path, checksum: &Checksum, mode: RepoMode) -> (u64, u64) {
    let path = repo_root
        .join("objects")
        .join(loose_path(checksum, ObjectType::File, mode));
    dev_ino(&path)
}

/// Returns the content checksum of a file entry in a commit tree.
async fn file_checksum(repo: &Repo, rev: &str, name: &str) -> Checksum {
    let (tree, _) = repo.read_commit(rev).await.unwrap();
    match tree.lookup(Path::new(name)).await.unwrap() {
        Some(TreeEntry::File { checksum, .. }) => checksum,
        other => panic!("expected a file entry for {name}, got {other:?}"),
    }
}

/// Compares the checkout of ostrya with the checkout of the `ostree` command.
/// The `ostree` command commits the tree. The comparison uses one repository
/// mode and one checkout mode.
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

    // The reference checkout of the `ostree` command.
    let co_tool = base.join("co-tool");
    let mut tool_args = vec![repo_arg.as_str(), "checkout"];
    if user_flag {
        tool_args.push("-U");
    }
    tool_args.push("main");
    tool_args.push(co_tool.to_str().unwrap());
    run_ostree(&tool_args);

    // The checkout of ostrya.
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

    // The two trees have the same types, modes, ownership, content, and
    // targets.
    assert_eq!(
        collect_tree(&co_tool),
        collect_tree(&co_port),
        "port checkout of a {repo_mode} repo diverges from the tool"
    );

    // The two destination roots also agree. The root gets the dirmeta of the
    // tree root.
    let tool_root = std::fs::metadata(&co_tool).unwrap();
    let port_root = std::fs::metadata(&co_port).unwrap();
    assert_eq!(tool_root.mode() & 0o7777, port_root.mode() & 0o7777);

    // The modes decide the hardlink result. The destination file shares the
    // inode of the object if and only if the modes give a hardlink checkout.
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

// --- comparisons with the `ostree` command --------------------------------

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

// Because bare-user-only stores no ownership and keeps the canonical mode on
// the object inode, a faithful and an unprivileged checkout both hardlink the
// object. Both give the same tree as the `ostree` command.
#[test]
fn bare_user_only_none_matches_tool() {
    cross_check("bare-user-only", CheckoutMode::None, false);
}

#[test]
fn bare_user_only_user_matches_tool() {
    cross_check("bare-user-only", CheckoutMode::User, true);
}

/// bare-user-only forces user semantics. A faithful (None) and an unprivileged
/// (User) checkout give identical trees, and each hardlinks the object into
/// place. This test does not need the `ostree` command, so it always runs.
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

/// `force_copy` stops the hardlink that bare-user-only uses without it. The
/// destination is a new inode with byte-identical content. The copy path
/// applies the canonical mode (& 0o777).
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

        // Commit the source tree with its ownership and modes.
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

        // Re-ingest the checkout. The same tree gives the same commit.
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

/// bare-user-shared is a development-only mode that the `ostree` command does
/// not have, so there is no comparison with the `ostree` command. A commit ->
/// checkout -> re-commit round-trip that gives the same commit checksum covers:
///
/// - the copy path, because bare-user-shared never hardlinks
/// - the metadata from `user.ostreemeta`
///
/// The re-commit matches only if the checkout restored the logical mode, the
/// ownership, and the content of each entry.
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

/// Commits subtree `sub` of `base` with a fixed timestamp, so a second commit
/// of the same tree gives the same commit checksum.
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
    // Under a faithful checkout, a bare-user repository copies each file and
    // makes no hardlink. This test covers the xattr application of the copy
    // path.
    //
    // A file with a `user.demo` xattr goes through commit, checkout, and
    // re-ingest. The re-ingest must give the same content checksum. This is
    // possible only if the checkout applied the xattr to the destination inode
    // and the re-ingest read it back.
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

        // Re-ingest the checked-out file. Its content object identity covers
        // the xattr set and must match the original.
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
    // A file and a directory, each with a `user.*` xattr. Their logical modes
    // have no owner-write bit. The kernel checks a `user.*` xattr against the
    // write permission of the inode, so the checkout applies the xattrs before
    // the mode.
    //
    // The repository is archive. Archive stores the logical metadata in the
    // object header, so it holds entries of any mode.
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

        // The checked-out directory is read-only. Its cleanup needs write
        // permission, so the test resets the mode.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    });
}

/// A faithful checkout that writes a regular file keeps the logical
/// `security.capability` value of the file. The test covers two owners:
///
/// - an owner that is the writer
/// - a foreign owner, with a set-user-ID mode and a `user.*` xattr
///
/// Because the kernel removes `security.capability` when the owner of a regular
/// file changes, the checkout sets the xattrs after the owner. An archive
/// repository always writes the file. A bare repository writes it under
/// `force_copy`. The xattr and the change of owner need root.
#[test]
fn a_faithful_checkout_keeps_a_file_capability_as_root() {
    if !rustix::process::geteuid().is_root() {
        eprintln!("skipping faithful file-capability checkout: not running as root");
        return;
    }
    // A VFS_CAP_REVISION_2 value: the revision with the effective bit, then the
    // permitted and inheritable low words, then the high words. The permitted
    // set holds cap_net_raw (bit 13).
    let cap: Vec<u8> = [0x0200_0001u32, 1 << 13, 0, 0, 0]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    let tmp = TmpDir::new("co-cap");
    let base = tmp.path();
    let (uid, gid) = self_owner(base);
    let cap_xattr = (b"security.capability\0".to_vec(), cap.clone());
    // Each file: the name, the logical metadata, and `true` if it has
    // `user.demo`.
    let files = [
        (
            "cap.bin",
            FileMeta {
                uid,
                gid,
                mode: S_IFREG | 0o755,
                xattrs: Xattrs::new([cap_xattr.clone()]).unwrap(),
            },
            false,
        ),
        (
            "suid-cap.bin",
            FileMeta {
                uid: 1234,
                gid: 5678,
                mode: S_IFREG | 0o4755,
                xattrs: Xattrs::new([cap_xattr, (b"user.demo\0".to_vec(), b"value".to_vec())])
                    .unwrap(),
            },
            true,
        ),
    ];

    for repo_mode in [RepoMode::Archive, RepoMode::Bare] {
        let repo_dir = base.join(format!("repo-{repo_mode:?}"));
        let destination = format!("co-{repo_mode:?}");
        block_on(async {
            let repo = Repo::create(&repo_dir, CreateOptions::new(repo_mode))
                .await
                .unwrap();
            let commit = {
                let txn = repo.transaction().await.unwrap();
                let mut mtree = MutableTree::new();
                for (name, meta, _) in &files {
                    let file = txn
                        .write_regfile_inline(None, meta, b"capable\n")
                        .await
                        .unwrap();
                    mtree.replace_file(name, file).unwrap();
                }
                let dirmeta = DirMeta {
                    uid,
                    gid,
                    mode: S_IFDIR | 0o755,
                    xattrs: Xattrs::default(),
                };
                let dm = txn
                    .write_metadata(ObjectType::DirMeta, None, &dirmeta.serialize().unwrap())
                    .await
                    .unwrap();
                mtree.set_metadata_checksum(dm);
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
            repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new(&destination), &commit)
                .await
                .unwrap();

            let out = base.join(&destination);
            for (name, meta, demo) in &files {
                let path = out.join(name);
                let what = format!("{repo_mode:?} {name}");
                let mut buf = [0u8; 256];
                let stored = rustix::fs::getxattr(&path, "security.capability", &mut buf)
                    .ok()
                    .map(|n| buf[..n].to_vec());
                assert_eq!(
                    stored.as_deref(),
                    Some(&cap[..]),
                    "{what}: security.capability"
                );
                assert_eq!(mode_of(&path), meta.mode & 0o7777, "{what}: mode");
                let stat = std::fs::symlink_metadata(&path).unwrap();
                assert_eq!(
                    (stat.uid(), stat.gid()),
                    (meta.uid, meta.gid),
                    "{what}: owner"
                );
                if *demo {
                    assert_eq!(xattr_of(&path, "user.demo"), b"value", "{what}: user.demo");
                }
            }
        });
    }
}

/// A [`User`](CheckoutMode::User) checkout writes a regular file at
/// `mode & 0o1777`: the setuid and setgid bits go, and the sticky bit stays. A
/// directory keeps all three bits. The `ostree` command applies the same rule
/// to the files that it writes. `force_copy` makes the checkout write each file
/// with no hardlink.
#[test]
fn a_user_mode_checkout_keeps_the_sticky_bit_of_a_written_file() {
    let tmp = TmpDir::new("co-user-bits");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();

    let files = [0o1644u32, 0o1755, 0o2755, 0o4755, 0o6755, 0o7755];
    // A source directory that the walk must enter keeps its owner execute bit,
    // so the directory cases are the searchable forms of the same bits.
    let dirs = [0o1755u32, 0o2755, 0o4755, 0o6755, 0o7755, 0o1777];
    for mode in files {
        let file = src.join(format!("f{mode:04o}"));
        std::fs::write(&file, b"x\n").unwrap();
        set_mode(&file, mode);
    }
    for mode in dirs {
        let dir = src.join(format!("d{mode:04o}"));
        std::fs::create_dir(&dir).unwrap();
        set_mode(&dir, mode);
    }

    // The mode that the rule keeps for each file mode: the sticky bit and the
    // permission bits stay, and the setuid and setgid bits go.
    let expected = |mode: u32| mode & 0o1777;

    for repo_mode in [RepoMode::Archive, RepoMode::Bare, RepoMode::BareUser] {
        let repo_dir = base.join(format!("repo-{repo_mode:?}"));
        let destination = format!("co-{repo_mode:?}");
        block_on(async {
            let repo = Repo::create(&repo_dir, CreateOptions::new(repo_mode))
                .await
                .unwrap();
            let commit = commit_tree(&repo, base, "src").await;

            let mut opts = CheckoutOptions::new(CheckoutMode::User);
            opts.force_copy = true;
            let base_fd = std::fs::File::open(base).unwrap();
            repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new(&destination), &commit)
                .await
                .unwrap();

            let out = base.join(&destination);
            for mode in files {
                assert_eq!(
                    mode_of(&out.join(format!("f{mode:04o}"))),
                    expected(mode),
                    "{repo_mode:?}: regular file {mode:04o}",
                );
            }
            for mode in dirs {
                assert_eq!(
                    mode_of(&out.join(format!("d{mode:04o}"))),
                    mode,
                    "{repo_mode:?}: directory {mode:04o}",
                );
            }
        });
    }
}

/// Returns the permission bits of a checked-out path.
fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

/// Returns the value of the named xattr of a checked-out path.
fn xattr_of(path: &Path, name: &str) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = rustix::fs::getxattr(path, name, &mut buf)
        .unwrap_or_else(|e| panic!("getxattr({name}) on {}: {e}", path.display()));
    buf[..n].to_vec()
}

// --- reflink / force-copy ------------------------------------------------

#[test]
fn force_copy_makes_an_independent_copy() {
    // A bare repository hardlinks under a faithful checkout. `force_copy` stops
    // the hardlink, so the destination is a new inode with byte-identical
    // content. The copy path tries a FICLONE reflink, and does a byte copy if
    // the file system refuses the reflink. Both results are correct.
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

/// Creates `name` under `dir`, `depth` nested directories under it, and one
/// file at the bottom. A moving directory descriptor builds the nesting, so the
/// function never forms a path longer than one component.
fn build_deep_dir(dir: &Path, name: &str, depth: usize) {
    use rustix::fs::{Mode, OFlags};
    std::fs::create_dir_all(dir.join(name)).unwrap();
    let mut fd: std::os::fd::OwnedFd = std::fs::File::open(dir.join(name)).unwrap().into();
    for _ in 0..depth {
        rustix::fs::mkdirat(fd.as_fd(), "d", Mode::from_raw_mode(0o755)).unwrap();
        fd = rustix::fs::openat(
            fd.as_fd(),
            "d",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
    }
    rustix::fs::openat(
        fd.as_fd(),
        "leaf",
        OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )
    .unwrap();
}

/// A removal reaches a destination subtree of any depth. The per-name removal
/// and the opaque clear use the same walk. The walk holds one directory
/// descriptor and keeps its levels on the heap. As a result, neither the
/// descriptor limit of the process nor the thread stack limits its depth.
#[test]
fn whiteouts_remove_a_deep_destination_subtree() {
    /// A depth at which a walk that recurses on the native stack ends the
    /// process.
    const DEPTH: usize = 4000;

    let tmp = TmpDir::new("co-wh-deep");
    let base = tmp.path();
    let repo_dir = base.join("repo");

    let named = base.join("named");
    std::fs::create_dir_all(&named).unwrap();
    std::fs::write(named.join(".wh.deep"), b"").unwrap();
    std::fs::write(named.join("keep"), b"k\n").unwrap();

    let opaque = base.join("opaque");
    std::fs::create_dir_all(&opaque).unwrap();
    std::fs::write(opaque.join(".wh..wh..opq"), b"").unwrap();
    std::fs::write(opaque.join("keep"), b"k\n").unwrap();

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let named_commit = commit_tree(&repo, base, "named").await;
        let opaque_commit = commit_tree(&repo, base, "opaque").await;
        let base_fd = std::fs::File::open(base).unwrap();

        for (case, commit) in [
            ("named-dest", &named_commit),
            ("opaque-dest", &opaque_commit),
        ] {
            let dest = base.join(case);
            build_deep_dir(&dest, "deep", DEPTH);
            std::fs::write(dest.join("pre"), b"pre\n").unwrap();

            let mut opts = CheckoutOptions::new(CheckoutMode::User);
            opts.overwrite = ostrya::OverwriteMode::UnionFiles;
            opts.process_whiteouts = true;
            repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new(case), commit)
                .await
                .unwrap();

            assert!(
                !dest.join("deep").exists(),
                "{case}: the deep subtree was removed",
            );
            assert_eq!(std::fs::read(dest.join("keep")).unwrap(), b"k\n");
            assert_eq!(
                dest.join("pre").exists(),
                case == "named-dest",
                "{case}: the opaque clear takes the whole directory",
            );
        }
    });
}

/// The whiteout markers act on a regular-file entry only. A symlink or a
/// directory with a marker name is materialized verbatim and removes nothing.
///
/// The clear of the opaque marker depends only on the name in the file-entry
/// list, so a symlink with that name also clears the directory. The checkout
/// then materializes the symlink.
#[test]
fn whiteout_markers_act_on_regular_files_only() {
    let tmp = TmpDir::new("co-wh-types");
    let base = tmp.path();
    let repo_dir = base.join("repo");

    // A layer whose markers are a symlink and a directory.
    let types = base.join("types");
    std::fs::create_dir_all(types.join(".wh.dirmarker")).unwrap();
    std::fs::write(types.join(".wh.dirmarker/child"), b"c\n").unwrap();
    symlink("t", types.join(".wh.slink")).unwrap();
    symlink("t", types.join(".ostree-wh.alink")).unwrap();
    std::fs::create_dir_all(types.join(".ostree-wh.adir")).unwrap();
    std::fs::write(types.join(".ostree-wh.adir/c"), b"c\n").unwrap();
    std::fs::write(types.join("keep"), b"k\n").unwrap();

    // A layer whose opaque marker is a symlink. It needs a tree of its own.
    let opq = base.join("opq");
    std::fs::create_dir_all(&opq).unwrap();
    symlink("nowhere", opq.join(".wh..wh..opq")).unwrap();
    std::fs::write(opq.join("keep"), b"k\n").unwrap();

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let types_commit = commit_tree(&repo, base, "types").await;
        let opq_commit = commit_tree(&repo, base, "opq").await;
        let base_fd = std::fs::File::open(base).unwrap();

        // The destination holds an entry at the target name of each marker.
        let dest = base.join("dest");
        std::fs::create_dir_all(dest.join("dirmarker")).unwrap();
        std::fs::write(dest.join("dirmarker/pre"), b"pre\n").unwrap();
        std::fs::write(dest.join("slink"), b"slink\n").unwrap();
        std::fs::write(dest.join("alink"), b"alink\n").unwrap();
        std::fs::write(dest.join("adir"), b"adir\n").unwrap();

        let mut opts = CheckoutOptions::new(CheckoutMode::User);
        opts.overwrite = ostrya::OverwriteMode::UnionFiles;
        opts.process_whiteouts = true;
        opts.process_passthrough_whiteouts = true;
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("dest"), &types_commit)
            .await
            .unwrap();

        for target in ["dirmarker", "slink", "alink", "adir"] {
            assert!(
                dest.join(target).exists(),
                "a non-regular marker removed {target}",
            );
        }
        assert!(
            std::fs::symlink_metadata(dest.join(".wh.slink"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "a symlink named .wh.<name> is materialized",
        );
        assert!(
            std::fs::symlink_metadata(dest.join(".ostree-wh.alink"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "a symlink named .ostree-wh.<name> is materialized",
        );
        assert!(dest.join(".wh.dirmarker/child").exists());
        assert!(dest.join(".ostree-wh.adir/c").exists());

        // The opaque marker as a symlink: the checkout clears the directory and
        // then materializes the symlink.
        let opq_dest = base.join("opq-dest");
        std::fs::create_dir_all(&opq_dest).unwrap();
        std::fs::write(opq_dest.join("pre"), b"pre\n").unwrap();
        let mut opts = CheckoutOptions::new(CheckoutMode::User);
        opts.overwrite = ostrya::OverwriteMode::UnionFiles;
        opts.process_whiteouts = true;
        repo.checkout_at(
            &mut opts,
            base_fd.as_fd(),
            Path::new("opq-dest"),
            &opq_commit,
        )
        .await
        .unwrap();
        assert!(!opq_dest.join("pre").exists(), "the clear ran");
        assert!(
            std::fs::symlink_metadata(opq_dest.join(".wh..wh..opq"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "a symlink named .wh..wh..opq is materialized after the clear",
        );
    });
}

/// Outside [`CheckoutMode::User`], the whiteout device gets the extended
/// attributes of the marker. The `user.` namespace is not permitted on a device
/// node, so a marker with such an attribute ends the checkout. The checkout
/// applies the attributes before the mode, so the device stays at the mode
/// that `mknod` gave it. The `ostree` command gives the same result for the
/// same commit.
#[test]
fn passthrough_whiteout_xattrs_reach_the_device() {
    let tmp = TmpDir::new("co-wh-xattr");
    let base = tmp.path();
    let repo_dir = base.join("repo");

    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let marker = src.join(".ostree-wh.xdev");
    std::fs::write(&marker, b"x\n").unwrap();
    set_mode(&marker, 0o4755);
    std::fs::write(src.join("keep"), b"k\n").unwrap();
    set_mode(&src.join("keep"), 0o644);
    let xattr_ok = rustix::fs::setxattr(
        &marker,
        "user.mark",
        b"hello",
        rustix::fs::XattrFlags::empty(),
    )
    .is_ok();
    if !xattr_ok {
        eprintln!("skipped: this filesystem takes no `user.` extended attribute");
        return;
    }

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        // The attributes must reach the commit, so this commit keeps them.
        let commit = {
            let txn = repo.transaction().await.unwrap();
            let mut mtree = MutableTree::new();
            let dfd = std::fs::File::open(base).unwrap();
            txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
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
        let base_fd = std::fs::File::open(base).unwrap();

        // Under `User`, the checkout does not apply the attributes. The
        // checkout completes, and the device has the bits of the marker minus
        // the umask.
        let mut opts = CheckoutOptions::new(CheckoutMode::User);
        opts.process_passthrough_whiteouts = true;
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("user"), &commit)
            .await
            .unwrap();
        let user = base.join("user").join("xdev");
        let meta = std::fs::symlink_metadata(&user).unwrap();
        assert_eq!(meta.mode() & 0o170000, 0o020000, "xdev is a device");
        assert_eq!(
            meta.mode() & 0o7777 & !0o4755,
            0,
            "xdev carries no bit the marker does not record",
        );
        assert_eq!(
            meta.mode() & 0o4000,
            0o4000,
            "the umask masks no setuid bit, so `mknod` keeps it",
        );

        // Outside `User`, the checkout applies the attribute and the kernel
        // refuses it. The device stays at the recorded mode.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.process_passthrough_whiteouts = true;
        let err = repo
            .checkout_at(&mut opts, base_fd.as_fd(), Path::new("faithful"), &commit)
            .await;
        let err = err.expect_err("a `user.` attribute on a device node is refused");
        let text = err.to_string();
        assert!(
            text.contains("xdev") && text.contains("user.mark"),
            "the refusal names the entry and the attribute: {text}",
        );
        let faithful = base.join("faithful").join("xdev");
        let meta = std::fs::symlink_metadata(&faithful).unwrap();
        assert_eq!(meta.mode() & 0o170000, 0o020000, "xdev is a device");
        let refused_mode = meta.mode() & 0o7777;
        assert_eq!(
            refused_mode & !0o4755,
            0,
            "xdev carries no bit the marker does not record",
        );

        // The `ostree` command gets the same status and leaves the same device.
        if !ostree_available() {
            return;
        }
        let tool_dest = base.join("tool");
        let output = Command::new("ostree")
            .arg(format!("--repo={}", repo_dir.display()))
            .arg("checkout")
            .arg("--process-passthrough-whiteouts")
            .arg(commit.to_hex())
            .arg(&tool_dest)
            .output()
            .expect("run ostree");
        assert_eq!(
            output.status.code(),
            Some(1),
            "the tool took the attribute: {}",
            String::from_utf8_lossy(&output.stderr),
        );
        let meta = std::fs::symlink_metadata(tool_dest.join("xdev")).unwrap();
        assert_eq!(meta.mode() & 0o170000, 0o020000, "the tool wrote a device");
        assert_eq!(
            meta.mode() & 0o7777,
            refused_mode,
            "the two leave the device at one mode",
        );
    });
}

/// A marker that names no entry is refused. The switch of the marker and the
/// type of the entry control each refusal.
#[test]
fn whiteout_empty_names_are_refused() {
    let tmp = TmpDir::new("co-wh-empty");
    let base = tmp.path();
    let repo_dir = base.join("repo");

    // One tree for each marker, so a run under one switch alone shows the
    // refusal of that switch and the materialization of the other marker.
    let wh = base.join("wh");
    std::fs::create_dir_all(&wh).unwrap();
    std::fs::write(wh.join(".wh."), b"a\n").unwrap();
    let pt = base.join("pt");
    std::fs::create_dir_all(&pt).unwrap();
    std::fs::write(pt.join(".ostree-wh."), b"a\n").unwrap();

    let links = base.join("links");
    std::fs::create_dir_all(&links).unwrap();
    symlink("t", links.join(".wh.")).unwrap();
    symlink("t", links.join(".ostree-wh.")).unwrap();

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let wh_commit = commit_tree(&repo, base, "wh").await;
        let pt_commit = commit_tree(&repo, base, "pt").await;
        let links_commit = commit_tree(&repo, base, "links").await;
        let base_fd = std::fs::File::open(base).unwrap();

        let mut case = 0;
        for (whiteouts, passthrough) in [(false, false), (true, false), (false, true), (true, true)]
        {
            case += 1;
            for (marker, commit, refused) in [
                (".wh.", &wh_commit, whiteouts),
                (".ostree-wh.", &pt_commit, passthrough),
            ] {
                let name = format!("{}-{case}", marker.trim_matches('.'));
                let mut opts = CheckoutOptions::new(CheckoutMode::User);
                opts.process_whiteouts = whiteouts;
                opts.process_passthrough_whiteouts = passthrough;
                let result = repo
                    .checkout_at(&mut opts, base_fd.as_fd(), Path::new(&name), commit)
                    .await;
                assert_eq!(
                    result.is_err(),
                    refused,
                    "case {case}: {marker} answers to its own switch alone",
                );
                if !refused {
                    assert!(base.join(&name).join(marker).exists());
                }
            }

            // A symlink with a marker name is materialized under each switch.
            let name = format!("links-{case}");
            let mut opts = CheckoutOptions::new(CheckoutMode::User);
            opts.process_whiteouts = whiteouts;
            opts.process_passthrough_whiteouts = passthrough;
            repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new(&name), &links_commit)
                .await
                .unwrap();
            let dest = base.join(&name);
            for marker in [".wh.", ".ostree-wh."] {
                assert!(
                    std::fs::symlink_metadata(dest.join(marker))
                        .unwrap()
                        .file_type()
                        .is_symlink(),
                    "case {case}: the symlink {marker} is materialized",
                );
            }
        }
    });
}

/// A passthrough marker becomes a character device 0:0 at the target name of
/// the marker, with the permission bits of the marker. The checkout does not
/// materialize the marker under its own name.
#[test]
fn passthrough_whiteouts_write_char_devices() {
    let tmp = TmpDir::new("co-wh-passthrough");
    let base = tmp.path();
    let repo_dir = base.join("repo");

    let src = base.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join(".ostree-wh.m644"), b"x\n").unwrap();
    set_mode(&src.join(".ostree-wh.m644"), 0o644);
    std::fs::write(src.join(".ostree-wh.m755"), b"x\n").unwrap();
    set_mode(&src.join(".ostree-wh.m755"), 0o755);
    std::fs::write(src.join(".ostree-wh.m600"), b"x\n").unwrap();
    set_mode(&src.join(".ostree-wh.m600"), 0o600);
    std::fs::write(src.join("sub/.ostree-wh.nested"), b"x\n").unwrap();
    set_mode(&src.join("sub/.ostree-wh.nested"), 0o644);
    std::fs::write(src.join("keep"), b"k\n").unwrap();
    set_mode(&src.join("keep"), 0o644);

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let base_fd = std::fs::File::open(base).unwrap();

        // The permission bits go to `mknod`, and the process umask reduces
        // them there. `CheckoutMode::None` applies the recorded mode after it
        // creates the device, so the test checks the exact mode under it. Under
        // `CheckoutMode::User`, the device has the bits that the marker records
        // minus the bits that the umask removes.
        for (case, mode) in [
            ("user", CheckoutMode::User),
            ("faithful", CheckoutMode::None),
        ] {
            let mut opts = CheckoutOptions::new(mode);
            opts.process_passthrough_whiteouts = true;
            repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new(case), &commit)
                .await
                .unwrap();

            let dest = base.join(case);
            for (name, recorded) in [
                ("m644", 0o644),
                ("m755", 0o755),
                ("m600", 0o600),
                ("sub/nested", 0o644),
            ] {
                let meta = std::fs::symlink_metadata(dest.join(name)).unwrap();
                assert_eq!(
                    meta.mode() & 0o170000,
                    0o020000,
                    "{case}: {name} is a character device",
                );
                assert_eq!(meta.rdev(), 0, "{case}: {name} carries device number 0:0");
                let bits = meta.mode() & 0o7777;
                if mode == CheckoutMode::None {
                    assert_eq!(bits, recorded, "{case}: {name} keeps the marker's mode");
                } else {
                    assert_eq!(
                        bits & !recorded,
                        0,
                        "{case}: {name} carries no bit the marker does not record",
                    );
                }
            }
            assert!(!dest.join(".ostree-wh.m644").exists());
            assert!(!dest.join("sub/.ostree-wh.nested").exists());
            assert_eq!(std::fs::read(dest.join("keep")).unwrap(), b"k\n");
        }

        // If the switch is off, the marker is an ordinary file.
        let mut opts = CheckoutOptions::new(CheckoutMode::User);
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("literal"), &commit)
            .await
            .unwrap();
        let literal = base.join("literal");
        assert_eq!(
            std::fs::read(literal.join(".ostree-wh.m644")).unwrap(),
            b"x\n",
        );
        assert!(!literal.join("m644").exists());

        // The result at the destination for each overwrite mode. `UnionFiles`
        // replaces an existing entry and refuses a directory. `AddFiles` and
        // `UnionIdentical` keep an existing entry of any type and do no
        // comparison.
        for (overwrite, replaced, dir_refused) in [
            (ostrya::OverwriteMode::UnionFiles, true, true),
            (ostrya::OverwriteMode::AddFiles, false, false),
            (ostrya::OverwriteMode::UnionIdentical, false, false),
        ] {
            let name = format!("over-{overwrite:?}");
            let over = base.join(&name);
            std::fs::create_dir_all(over.join("m755")).unwrap();
            std::fs::write(over.join("m644"), b"OLDFILE\n").unwrap();
            symlink("nowhere", over.join("m600")).unwrap();
            let mut opts = CheckoutOptions::new(CheckoutMode::User);
            opts.overwrite = overwrite;
            opts.require_hardlinks = overwrite == ostrya::OverwriteMode::UnionIdentical;
            opts.process_passthrough_whiteouts = true;
            let result = repo
                .checkout_at(&mut opts, base_fd.as_fd(), Path::new(&name), &commit)
                .await;
            assert_eq!(
                result.is_err(),
                dir_refused,
                "{name}: a destination directory is refused under UnionFiles alone",
            );
            let is_device = |path: PathBuf| {
                std::fs::symlink_metadata(path).unwrap().mode() & 0o170000 == 0o020000
            };
            assert_eq!(
                is_device(over.join("m644")),
                replaced,
                "{name}: the regular file at the target",
            );
            if !dir_refused {
                assert_eq!(
                    is_device(over.join("m600")),
                    replaced,
                    "{name}: the symlink at the target",
                );
            }
        }
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

        // UnionFiles: replaces existing files, keeps the others, and adds new
        // files.
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

        // AddFiles: keeps existing files and adds only new files.
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
        opts.require_hardlinks = true;
        let err = repo
            .checkout_at(&mut opts, base_fd.as_fd(), Path::new("ident"), &commit_b)
            .await;
        assert!(
            matches!(err, Err(ostrya::Error::Checkout(_))),
            "union-identical over a differing file is a conflict, got {err:?}"
        );

        // UnionIdentical over an identical tree succeeds. The objects are the
        // same inodes that the base checkout hardlinked.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionIdentical;
        opts.require_hardlinks = true;
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("ident"), &commit_a)
            .await
            .expect("union-identical over an identical tree is a no-op");
    });
}

/// union-identical decides identity by the object inode, so the `ostree`
/// command accepts the option only with `--require-hardlinks`. ostrya checks
/// this rule on the options alone, before any I/O.
///
/// The per-entry `require_hardlinks` refusal decides which repository mode and
/// checkout mode can hardlink. If a tree has no entry that needs a copy, a
/// checkout in a mode that copies writes the whole tree. The `ostree` command
/// gives the same result.
#[test]
fn union_identical_requires_require_hardlinks() {
    let tmp = TmpDir::new("co-ui-guard");
    let base = tmp.path();
    let src = base.join("src");
    build_source(&src);
    let dirs = base.join("dirs");
    std::fs::create_dir_all(dirs.join("inner")).unwrap();

    block_on(async {
        let archive_dir = base.join("archive");
        let repo = Repo::create(&archive_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let dir_commit = commit_tree(&repo, base, "dirs").await;
        let base_fd = std::fs::File::open(base).unwrap();

        // Without `require_hardlinks`, the option is refused before any I/O.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionIdentical;
        let err = repo
            .checkout_at(&mut opts, base_fd.as_fd(), Path::new("co_alone"), &commit)
            .await;
        assert!(
            matches!(err, Err(ostrya::Error::Checkout(_))),
            "union-identical without require_hardlinks is refused, got {err:?}"
        );
        assert!(
            !base.join("co_alone").exists(),
            "the destination is not created when union-identical is refused"
        );

        // With it, a tree with a regular file is refused at that entry, because
        // `archive` gives a copy of it.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionIdentical;
        opts.require_hardlinks = true;
        let err = repo
            .checkout_at(&mut opts, base_fd.as_fd(), Path::new("co_entry"), &commit)
            .await;
        assert!(
            matches!(err, Err(ostrya::Error::RequireHardlinks(_))),
            "an `archive` regular file is refused at the entry, got {err:?}"
        );

        // A tree of directories alone reaches no such entry, so the same
        // options write it in full.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionIdentical;
        opts.require_hardlinks = true;
        repo.checkout_at(
            &mut opts,
            base_fd.as_fd(),
            Path::new("co_dirs"),
            &dir_commit,
        )
        .await
        .expect("a directory-only tree needs no copy");
        assert!(base.join("co_dirs").join("inner").is_dir());

        // `require_hardlinks` and `force_copy` are mutually exclusive.
        let bare_dir = base.join("bare");
        let repo = Repo::create(&bare_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.require_hardlinks = true;
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
            "require_hardlinks with force_copy is refused, got {err:?}"
        );
        assert!(!base.join("co_forcecopy").exists());
    });
}

/// The per-entry `require_hardlinks` refusal, on the shapes that the table of
/// the `ostree` command separates:
///
/// - A directory and a zero-length regular file are written in each mode.
/// - A regular file of non-zero length is refused in each pair of repository
///   mode and checkout mode that gives a copy.
/// - A symlink has a table of its own: `archive` refuses it in both checkout
///   modes, and `bare` refuses it under a user checkout.
///
/// A refusal in the middle of a walk keeps the entries that the walk already
/// wrote.
#[test]
fn require_hardlinks_refuses_at_the_entry() {
    let tmp = TmpDir::new("co-require-entry");
    let base = tmp.path();
    std::fs::create_dir_all(base.join("t_dir").join("d")).unwrap();
    std::fs::create_dir_all(base.join("t_empty")).unwrap();
    std::fs::write(base.join("t_empty").join("e"), b"").unwrap();
    std::fs::create_dir_all(base.join("t_one")).unwrap();
    std::fs::write(base.join("t_one").join("o"), b"x").unwrap();
    std::fs::create_dir_all(base.join("t_sym")).unwrap();
    symlink("target", base.join("t_sym").join("l")).unwrap();
    std::fs::create_dir_all(base.join("t_order").join("a")).unwrap();
    std::fs::write(base.join("t_order").join("a").join("empty"), b"").unwrap();
    symlink("x", base.join("t_order").join("a").join("link")).unwrap();

    block_on(async {
        let base_fd = std::fs::File::open(base).unwrap();
        for (mode_name, mode) in [
            ("archive", RepoMode::Archive),
            ("bare", RepoMode::Bare),
            ("bare-user", RepoMode::BareUser),
            ("bare-user-only", RepoMode::BareUserOnly),
        ] {
            let repo = Repo::create(
                &base.join(format!("repo-{mode_name}")),
                CreateOptions::new(mode),
            )
            .await
            .unwrap();
            // Each shape gets one commit in each repository mode. The two
            // checkout modes read the same four commits.
            let shapes: [(&str, Checksum); 4] = [
                ("t_dir", commit_tree(&repo, base, "t_dir").await),
                ("t_empty", commit_tree(&repo, base, "t_empty").await),
                ("t_one", commit_tree(&repo, base, "t_one").await),
                ("t_sym", commit_tree(&repo, base, "t_sym").await),
            ];
            for checkout_mode in [CheckoutMode::None, CheckoutMode::User] {
                let user = checkout_mode == CheckoutMode::User;
                let refuses_regular = !matches!(
                    (mode, user),
                    (RepoMode::Bare, false)
                        | (RepoMode::BareUser, true)
                        | (RepoMode::BareUserOnly, _)
                );
                let refuses_symlink = matches!(
                    (mode, user),
                    (RepoMode::Archive, _) | (RepoMode::Bare, true)
                );
                for ((tree, commit), refuses) in
                    shapes
                        .iter()
                        .zip([false, false, refuses_regular, refuses_symlink])
                {
                    let dest = format!("out-{mode_name}-{}-{tree}", u8::from(user));
                    let mut opts = CheckoutOptions::new(checkout_mode);
                    opts.require_hardlinks = true;
                    let result = repo
                        .checkout_at(&mut opts, base_fd.as_fd(), Path::new(&dest), commit)
                        .await;
                    if refuses {
                        assert!(
                            matches!(result, Err(ostrya::Error::RequireHardlinks(_))),
                            "{mode_name}/user={user}/{tree}: got {result:?}",
                        );
                    } else {
                        result.unwrap_or_else(|e| {
                            panic!("{mode_name}/user={user}/{tree} is written: {e}")
                        });
                    }
                }

                // With the switch off, nothing is refused: the same shapes are
                // written in the same cells with `require_hardlinks` clear.
                for (tree, commit) in &shapes {
                    let dest = format!("free-{mode_name}-{}-{tree}", u8::from(user));
                    let mut opts = CheckoutOptions::new(checkout_mode);
                    let result = repo
                        .checkout_at(&mut opts, base_fd.as_fd(), Path::new(&dest), commit)
                        .await;
                    result.unwrap_or_else(|e| {
                        panic!("{mode_name}/user={user}/{tree} without the switch: {e}")
                    });
                }
            }
        }

        // The refusal occurs where the entry is materialized, so the entries
        // that the walk already wrote stay. `bare` under a user checkout writes
        // the zero-length file and refuses the symlink next to it.
        let repo = Repo::open(&base.join("repo-bare")).await.unwrap();
        let commit = commit_tree(&repo, base, "t_order").await;
        let mut opts = CheckoutOptions::new(CheckoutMode::User);
        opts.require_hardlinks = true;
        let result = repo
            .checkout_at(&mut opts, base_fd.as_fd(), Path::new("partial"), &commit)
            .await;
        assert!(
            matches!(result, Err(ostrya::Error::RequireHardlinks(_))),
            "the symlink is refused, got {result:?}",
        );
        assert!(base.join("partial").join("a").join("empty").is_file());
        assert!(!base.join("partial").join("a").join("link").exists());
    });
}

// --- union-identical: what the option calls identical ---------------------

/// Builds a source tree with one regular file `f` of `content` at `perm`.
fn build_one_file(dir: &Path, content: &[u8], perm: u32) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("f"), content).unwrap();
    set_mode(&dir.join("f"), perm);
    set_mode(dir, 0o755);
}

/// Returns the permission bits of the one loose content object in a fixture
/// repository.
fn only_loose_object_perm(repo_dir: &Path) -> u32 {
    let mut found = Vec::new();
    for shard in std::fs::read_dir(repo_dir.join("objects")).unwrap() {
        let shard = shard.unwrap().path();
        if !shard.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&shard).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) == Some("file") {
                found.push(path);
            }
        }
    }
    assert_eq!(found.len(), 1, "the fixture holds one content object");
    std::fs::symlink_metadata(&found[0])
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

/// Checks out `commit` over `dest` under [`OverwriteMode::UnionIdentical`].
async fn union_identical_checkout(
    repo: &Repo,
    mode: CheckoutMode,
    base_fd: std::os::fd::BorrowedFd<'_>,
    dest: &str,
    commit: &Checksum,
) -> Result<(), ostrya::Error> {
    let mut opts = CheckoutOptions::new(mode);
    opts.overwrite = ostrya::OverwriteMode::UnionIdentical;
    opts.require_hardlinks = true;
    repo.checkout_at(&mut opts, base_fd, Path::new(dest), commit)
        .await
}

/// The checkout keeps a destination file that is equal to the file that it
/// writes. The test makes the file by hand, so the file has its own inode. The
/// file-object checksum of the file equals the checksum of the object. The
/// permission bits of the file equal those of the loose object inode.
#[test]
fn union_identical_keeps_a_byte_identical_copy() {
    let tmp = TmpDir::new("co-ui-identical");
    let base = tmp.path();
    build_one_file(&base.join("src"), b"payload\n", 0o644);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let base_fd = std::fs::File::open(base).unwrap();

        let dest = base.join("dest");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("f"), b"payload\n").unwrap();
        set_mode(&dest.join("f"), 0o644);
        let before = std::fs::symlink_metadata(dest.join("f")).unwrap().ino();

        union_identical_checkout(&repo, CheckoutMode::None, base_fd.as_fd(), "dest", &commit)
            .await
            .expect("a byte-identical destination file is kept");
        assert_eq!(
            std::fs::symlink_metadata(dest.join("f")).unwrap().ino(),
            before,
            "the kept file is left in place rather than relinked",
        );
    });
}

/// The comparison includes the permission bits: the same content at a
/// different mode is not equal to the file that the checkout writes.
#[test]
fn union_identical_refuses_a_differing_mode() {
    let tmp = TmpDir::new("co-ui-mode");
    let base = tmp.path();
    build_one_file(&base.join("src"), b"payload\n", 0o644);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let base_fd = std::fs::File::open(base).unwrap();

        let dest = base.join("dest");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("f"), b"payload\n").unwrap();
        set_mode(&dest.join("f"), 0o755);

        let err =
            union_identical_checkout(&repo, CheckoutMode::None, base_fd.as_fd(), "dest", &commit)
                .await;
        assert!(
            matches!(err, Err(ostrya::Error::Checkout(_))),
            "a differing mode is a conflict, got {err:?}",
        );
        assert_eq!(
            std::fs::symlink_metadata(dest.join("f"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755,
            "the colliding entry is left as it was",
        );
    });
}

/// The comparison includes the extended-attribute set: one attribute that the
/// object does not have makes the entry differ.
#[test]
fn union_identical_refuses_an_extra_xattr() {
    let tmp = TmpDir::new("co-ui-xattr");
    let base = tmp.path();
    build_one_file(&base.join("src"), b"payload\n", 0o644);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let base_fd = std::fs::File::open(base).unwrap();

        let dest = base.join("dest");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("f"), b"payload\n").unwrap();
        set_mode(&dest.join("f"), 0o644);
        let set = rustix::fs::setxattr(
            dest.join("f"),
            "user.k",
            b"v",
            rustix::fs::XattrFlags::empty(),
        );
        if set.is_err() {
            // The file system under the temporary directory has no user
            // extended attributes, so this case has nothing to check here.
            eprintln!("skipped: the temporary filesystem takes no user xattr");
            return;
        }

        let err =
            union_identical_checkout(&repo, CheckoutMode::None, base_fd.as_fd(), "dest", &commit)
                .await;
        assert!(
            matches!(err, Err(ostrya::Error::Checkout(_))),
            "an extra extended attribute is a conflict, got {err:?}",
        );
    });
}

/// The comparison excludes the modification time: a destination with a past
/// timestamp is still equal to the file that the checkout writes.
#[test]
fn union_identical_ignores_the_modification_time() {
    let tmp = TmpDir::new("co-ui-mtime");
    let base = tmp.path();
    build_one_file(&base.join("src"), b"payload\n", 0o644);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let base_fd = std::fs::File::open(base).unwrap();

        let dest = base.join("dest");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("f"), b"payload\n").unwrap();
        set_mode(&dest.join("f"), 0o644);
        // 2001-01-01T00:00:00Z.
        let stamp = rustix::fs::Timespec {
            tv_sec: 978_307_200,
            tv_nsec: 0,
        };
        rustix::fs::utimensat(
            rustix::fs::CWD,
            dest.join("f"),
            &rustix::fs::Timestamps {
                last_access: stamp,
                last_modification: stamp,
            },
            rustix::fs::AtFlags::empty(),
        )
        .unwrap();

        union_identical_checkout(&repo, CheckoutMode::None, base_fd.as_fd(), "dest", &commit)
            .await
            .expect("the modification time is outside the comparison");
    });
}

/// A symlink is compared by its target alone.
#[test]
fn union_identical_compares_a_symlink_by_target() {
    let tmp = TmpDir::new("co-ui-symlink");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    symlink("hello.txt", src.join("l")).unwrap();
    set_mode(&src, 0o755);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        let base_fd = std::fs::File::open(base).unwrap();

        let same = base.join("same");
        std::fs::create_dir(&same).unwrap();
        symlink("hello.txt", same.join("l")).unwrap();
        union_identical_checkout(&repo, CheckoutMode::None, base_fd.as_fd(), "same", &commit)
            .await
            .expect("a symlink carrying the committed target is kept");

        let other = base.join("other");
        std::fs::create_dir(&other).unwrap();
        symlink("elsewhere", other.join("l")).unwrap();
        let err =
            union_identical_checkout(&repo, CheckoutMode::None, base_fd.as_fd(), "other", &commit)
                .await;
        assert!(
            matches!(err, Err(ostrya::Error::Checkout(_))),
            "a differing target is a conflict, got {err:?}",
        );
        assert_eq!(
            std::fs::read_link(other.join("l")).unwrap(),
            Path::new("elsewhere"),
            "the colliding link is left as it was",
        );
    });
}

/// The second condition of the identity rule: the checkout compares the
/// permission bits of the destination with those of the loose object inode.
/// The logical mode of the object is not part of this comparison.
///
/// The `bare-user` inode rule `(logical_perm & 0o775) | 0o400` drops some bits.
/// If the logical mode of a `bare-user` object has such a bit, no destination
/// is identical to the object. In `bare`, the same object is identical to a
/// destination at its own mode.
#[test]
fn union_identical_refuses_a_mode_the_loose_inode_cannot_carry() {
    let tmp = TmpDir::new("co-ui-inode-mode");
    let base = tmp.path();
    build_one_file(&base.join("src"), b"payload\n", 0o777);

    block_on(async {
        let base_fd = std::fs::File::open(base).unwrap();

        // `bare-user` stores the object inode at 0775 for a logical 0777, so no
        // destination mode satisfies both conditions.
        let repo = Repo::create(
            &base.join("repo-bare-user"),
            CreateOptions::new(RepoMode::BareUser),
        )
        .await
        .unwrap();
        let commit = commit_tree(&repo, base, "src").await;
        assert_eq!(
            only_loose_object_perm(&base.join("repo-bare-user")),
            0o775,
            "the `bare-user` inode rule drops the group- and other-write bits",
        );

        let dest = base.join("dest-bare-user");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("f"), b"payload\n").unwrap();
        set_mode(&dest.join("f"), 0o777);
        let err = union_identical_checkout(
            &repo,
            CheckoutMode::User,
            base_fd.as_fd(),
            "dest-bare-user",
            &commit,
        )
        .await;
        assert!(
            matches!(err, Err(ostrya::Error::Checkout(_))),
            "a destination at the object's logical mode is refused where the \
             loose inode cannot carry it, got {err:?}",
        );

        // `bare` puts the full logical mode on the inode, so the same
        // destination is identical there.
        let bare = Repo::create(&base.join("repo-bare"), CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&bare, base, "src").await;
        let dest = base.join("dest-bare");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("f"), b"payload\n").unwrap();
        set_mode(&dest.join("f"), 0o777);
        union_identical_checkout(
            &bare,
            CheckoutMode::None,
            base_fd.as_fd(),
            "dest-bare",
            &commit,
        )
        .await
        .expect("`bare` carries the full logical mode on the inode");
    });
}

// --- type conflict -------------------------------------------------------

/// A file at a destination name where the commit has a directory is a conflict
/// in each mode. The checkout returns an error, and the file stays in place.
/// The `ostree` command also fails here, with
/// `opendir(<name>): Not a directory`.
#[test]
fn file_where_commit_has_directory_is_a_conflict() {
    let tmp = TmpDir::new("co-typeconflict");
    let base = tmp.path();
    let repo_dir = base.join("repo");

    // A tree whose `clash` is a regular file, and a file that stays after the
    // merge.
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

        // The union modes reach the conflict at a nested child: the checkout
        // uses the top-level destination again, and then `clash` collides.
        for mode in [
            ostrya::OverwriteMode::UnionFiles,
            ostrya::OverwriteMode::AddFiles,
            ostrya::OverwriteMode::UnionIdentical,
        ] {
            let dest_name = format!("u_{mode:?}");
            checkout_none(&repo, base_fd.as_fd(), &dest_name, &commit_file).await;
            let mut opts = CheckoutOptions::new(CheckoutMode::None);
            opts.overwrite = mode;
            opts.require_hardlinks = mode == ostrya::OverwriteMode::UnionIdentical;
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

        // The default mode (None) reaches the same guard at the destination
        // root: a plain file is where the checkout must create the root
        // directory.
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

/// A directory at a destination name where the commit has a file is a conflict
/// under union-files and union-identical, and the directory stays in place.
/// Under add-files, the checkout keeps the directory and writes nothing for
/// that name. This agrees with `ostree` 2026.1: union-files fails with
/// `renameat(...): Is a directory`, union-identical fails, and add-files keeps
/// the directory.
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

        // union-files and union-identical: a conflict. The directory stays.
        for mode in [
            ostrya::OverwriteMode::UnionFiles,
            ostrya::OverwriteMode::UnionIdentical,
        ] {
            let dest_name = format!("d_{mode:?}");
            checkout_none(&repo, base_fd.as_fd(), &dest_name, &commit_dir).await;
            let mut opts = CheckoutOptions::new(CheckoutMode::None);
            opts.overwrite = mode;
            opts.require_hardlinks = mode == ostrya::OverwriteMode::UnionIdentical;
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
        // and the root gets the dirmeta of the subdir (mode 0750).
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
        assert!(matches!(err, Err(ostrya::Error::SubpathNotFound(_))));

        // A subpath through an entry that is not a directory gives the other
        // refusal. `--allow-noent` acts on the split between the two refusals.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.subpath = Some(PathBuf::from("hello.txt/deeper"));
        let err = repo
            .checkout_at(&mut opts, base_fd.as_fd(), Path::new("through"), &commit)
            .await;
        assert!(matches!(err, Err(ostrya::Error::SubpathNotADirectory(_))));

        // A `..` followed by a name that the directory before the `..` holds as
        // a file. No directory holds an entry named `..`, so the walk stops at
        // the `..` and the value gets the absent-subpath refusal.
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.subpath = Some(PathBuf::from("subdir/../nested.txt/x"));
        let err = repo
            .checkout_at(&mut opts, base_fd.as_fd(), Path::new("parent"), &commit)
            .await;
        assert!(
            matches!(err, Err(ostrya::Error::SubpathNotFound(_))),
            "a `..` carries the absent-subpath refusal, got {err:?}"
        );
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

/// Returns a filter that records each `(path, mode)` that it gets and returns
/// the verdict of `skip` for the path.
fn recording_filter(
    calls: &Arc<Mutex<Vec<(String, u32)>>>,
    skip: fn(&str) -> bool,
) -> ostrya::CheckoutFilterFn {
    let calls = Arc::clone(calls);
    Box::new(move |path: &Path, meta: &FileMeta| {
        let path = path.to_string_lossy().into_owned();
        let skipped = skip(&path);
        calls.lock().unwrap().push((path, meta.mode));
        if skipped {
            FilterResult::Skip
        } else {
            FilterResult::Allow
        }
    })
}

/// The filter gets the checkout root as `/`, with the mode of the root
/// dirmeta. The filter gets each entry under the root at its own path.
#[test]
fn checkout_filter_sees_the_destination_root() {
    let tmp = TmpDir::new("co-filter-root");
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

        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.filter = Some(recording_filter(&calls, |_| false));
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("co"), &commit)
            .await
            .unwrap();

        let calls = calls.lock().unwrap();
        let roots: Vec<&(String, u32)> = calls.iter().filter(|(path, _)| path == "/").collect();
        assert_eq!(roots.len(), 1, "the root is offered once, got {calls:?}");
        assert_eq!(roots[0].1 & S_IFDIR, S_IFDIR, "the root carries its type");
        assert_eq!(roots[0].1 & 0o7777, 0o755, "the root carries its own mode");

        let mode_of = |name: &str| {
            calls
                .iter()
                .find(|(path, _)| path == name)
                .unwrap_or_else(|| panic!("{name} was never offered, got {calls:?}"))
                .1
        };
        assert_eq!(mode_of("/subdir") & S_IFDIR, S_IFDIR);
        assert_eq!(mode_of("/hello.txt") & S_IFREG, S_IFREG);
        assert!(calls.iter().any(|(path, _)| path == "/link"));
        assert!(calls.iter().any(|(path, _)| path == "/subdir/nested.txt"));
    });
}

/// A `Skip` on the root writes nothing and creates no destination. Under a
/// union mode, it leaves an existing destination unchanged.
#[test]
fn checkout_filter_skipping_the_root_creates_no_destination() {
    let tmp = TmpDir::new("co-filter-root-skip");
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

        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.filter = Some(recording_filter(&calls, |path| path == "/"));
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("absent"), &commit)
            .await
            .unwrap();
        assert!(
            !base.join("absent").exists(),
            "a pruned root creates no destination"
        );
        assert_eq!(
            calls.lock().unwrap().len(),
            1,
            "the walk stops at the pruned root"
        );

        let existing = base.join("existing");
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::write(existing.join("pre.txt"), b"pre\n").unwrap();
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionFiles;
        opts.filter = Some(recording_filter(&calls, |path| path == "/"));
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("existing"), &commit)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_dir(&existing).unwrap().count(),
            1,
            "a pruned root adds nothing to an existing destination"
        );
        assert_eq!(std::fs::read(existing.join("pre.txt")).unwrap(), b"pre\n");
    });
}

/// The filter decides a file entry before the whiteout decision, so a `Skip` on
/// the path of a marker removes nothing and writes no device. The clear of the
/// opaque marker is a pre-pass of the directory walk, and the filter does not
/// apply to it.
#[test]
fn checkout_filter_runs_ahead_of_the_whiteout_decision() {
    let tmp = TmpDir::new("co-filter-whiteout");
    let base = tmp.path();
    let layer = base.join("layer");
    std::fs::create_dir_all(layer.join("sub")).unwrap();
    std::fs::write(layer.join("keep.txt"), b"new\n").unwrap();
    std::fs::write(layer.join(".wh.gone.txt"), b"").unwrap();
    std::fs::write(layer.join(".ostree-wh.dev"), b"").unwrap();
    std::fs::write(layer.join("sub/.wh..wh..opq"), b"").unwrap();
    std::fs::write(layer.join("sub/child.txt"), b"child\n").unwrap();
    let repo_dir = base.join("repo");

    /// Builds the destination that each arm runs over.
    fn prestate(dest: &Path) {
        std::fs::create_dir_all(dest.join("sub")).unwrap();
        std::fs::write(dest.join("gone.txt"), b"old\n").unwrap();
        std::fs::write(dest.join("dev"), b"olddev\n").unwrap();
        std::fs::write(dest.join("sub/stale.txt"), b"stale\n").unwrap();
    }

    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Bare))
            .await
            .unwrap();
        let commit = commit_tree(&repo, base, "layer").await;
        let base_fd = std::fs::File::open(base).unwrap();

        // The control arm, with no filter: the markers act.
        let plain = base.join("plain");
        prestate(&plain);
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionFiles;
        opts.process_whiteouts = true;
        opts.process_passthrough_whiteouts = true;
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("plain"), &commit)
            .await
            .unwrap();
        assert!(!plain.join("gone.txt").exists(), "the marker removed it");
        assert!(
            !plain.join("sub/stale.txt").exists(),
            "the opaque marker cleared it"
        );
        let dev = std::fs::symlink_metadata(plain.join("dev")).unwrap();
        assert_eq!(
            dev.mode() & 0o170000,
            0o020000,
            "the passthrough marker wrote a character device"
        );

        // The filtered arm: the filter prunes the path of each marker.
        let filtered = base.join("filtered");
        prestate(&filtered);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.overwrite = ostrya::OverwriteMode::UnionFiles;
        opts.process_whiteouts = true;
        opts.process_passthrough_whiteouts = true;
        opts.filter = Some(recording_filter(&calls, |path| {
            matches!(
                path,
                "/.wh.gone.txt" | "/.ostree-wh.dev" | "/sub/.wh..wh..opq"
            )
        }));
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("filtered"), &commit)
            .await
            .unwrap();

        assert_eq!(
            std::fs::read(filtered.join("gone.txt")).unwrap(),
            b"old\n",
            "a pruned marker removes nothing"
        );
        assert_eq!(
            std::fs::read(filtered.join("dev")).unwrap(),
            b"olddev\n",
            "a pruned passthrough marker writes no device"
        );
        assert!(
            !filtered.join("sub/stale.txt").exists(),
            "the opaque clear is not filtered"
        );
        assert_eq!(
            std::fs::read(filtered.join("sub/child.txt")).unwrap(),
            b"child\n"
        );
        let calls = calls.lock().unwrap();
        assert!(
            calls.iter().any(|(path, _)| path == "/.wh.gone.txt"),
            "the marker's own path is offered, got {calls:?}"
        );
    });
}

/// The checkout writes the single object that a file subpath names with no
/// filter call.
#[test]
fn checkout_filter_does_not_reach_a_file_subpath_target() {
    let tmp = TmpDir::new("co-filter-file-subpath");
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

        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut opts = CheckoutOptions::new(CheckoutMode::None);
        opts.subpath = Some(PathBuf::from("/hello.txt"));
        opts.filter = Some(recording_filter(&calls, |_| true));
        repo.checkout_at(&mut opts, base_fd.as_fd(), Path::new("one"), &commit)
            .await
            .unwrap();

        assert!(
            calls.lock().unwrap().is_empty(),
            "the filter is not called for a file subpath target"
        );
        assert_eq!(
            std::fs::read(base.join("one/hello.txt")).unwrap(),
            b"hello ostree\n"
        );
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

        // A `.commitpartial` marker makes the commit report as partial. The
        // checkout refuses the commit at the start, before it reaches a missing
        // object.
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

/// Commits the subtree `sub` of `base` into `repo` and returns the commit
/// checksum. The commit keeps the ownership and the modes, and skips the
/// xattrs.
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

/// Checks out `commit` to `dest` under `base_fd` with a faithful checkout.
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

/// A compile-time check that the public checkout types move across threads.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<CheckoutOptions>();
};
