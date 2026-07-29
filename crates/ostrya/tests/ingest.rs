//! Filesystem-ingest integration tests (Phase 7c).
//!
//! These build source trees on disk and ingest them through
//! `write_dfd_to_mtree` under a `CommitModifier`: reproducing the fixture
//! tree's checksums, matching the tool's canonical-permissions output for modes
//! and for xattrs, the filter's subtree pruning, an xattr callback landing in the
//! object id, a devino-cache hit skipping ingestion, source consumption, and a
//! `user.*` xattr round-trip.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use common::{ROOT_DIRMETA, ROOT_DIRTREE, TmpDir, fixture_repo, ostree_available};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CreateOptions, DevInoCache, FileKind, FileMeta,
    FilterResult, MutableTree, Repo, RepoMode, TreeEntry,
};
use ostrya_core::Xattrs;
use ostrya_rt::block_on;

fn csum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

/// Compile-time pin: the ingest walk future is `Send`, callbacks included.
fn assert_send<T: Send>(value: T) -> T {
    value
}

/// Set a path's permission bits.
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Build the fixture source tree (hello/empty/nested/link, owner-agnostic) under
/// `base/src` and return the source directory.
fn build_fixture_source(base: &Path) -> std::path::PathBuf {
    let src = base.join("src");
    std::fs::create_dir_all(src.join("subdir")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    std::fs::write(src.join("empty.txt"), b"").unwrap();
    std::fs::write(src.join("subdir/nested.txt"), b"nested\n").unwrap();
    std::os::unix::fs::symlink("hello.txt", src.join("link")).unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    set_mode(&src.join("empty.txt"), 0o644);
    set_mode(&src.join("subdir/nested.txt"), 0o644);
    set_mode(&src.join("subdir"), 0o755);
    set_mode(&src, 0o755);
    src
}

/// The uid/gid this process owns, taken from a directory it created.
fn own_ids(path: &Path) -> (u32, u32) {
    let stat = rustix::fs::stat(path).unwrap();
    (stat.st_uid, stat.st_gid)
}

#[test]
fn ingest_reproduces_the_fixture_tree() {
    // Canonicalizing owner to 0:0 with modes already canonical (0644 files,
    // 0755 dirs) reproduces the tool's owner-0:0 fixture exactly.
    let tmp = TmpDir::new("ingest-fixture");
    let base = tmp.path();
    build_fixture_source(base);
    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier = CommitModifier::new(
            CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
        );
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        assert_eq!(rt.dirtree_checksum(), &csum(ROOT_DIRTREE), "root dirtree");
        assert_eq!(rt.dirmeta_checksum(), &csum(ROOT_DIRMETA), "root dirmeta");

        let stats = txn.commit().await.unwrap();
        // Four content objects, two dirtrees, one shared dirmeta.
        assert_eq!(stats.content_written, 4);
        assert_eq!(stats.metadata_written, 3);
    });
}

#[test]
fn canonical_permissions_match_the_canon_fixture() {
    // The same assorted-mode tree the canon fixture was built from, ingested
    // with CANONICAL_PERMISSIONS, has the root-tree identity the tool produced
    // with --canonical-permissions.
    let tmp = TmpDir::new("ingest-canon");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(src.join("dir0775")).unwrap();
    std::fs::write(src.join("f0664"), b"a").unwrap();
    std::fs::write(src.join("f0755"), b"b").unwrap();
    std::fs::write(src.join("f4755"), b"c").unwrap();
    std::os::unix::fs::symlink("f0664", src.join("link")).unwrap();
    set_mode(&src.join("f0664"), 0o664);
    set_mode(&src.join("f0755"), 0o755);
    set_mode(&src.join("f4755"), 0o4755);
    set_mode(&src.join("dir0775"), 0o775);
    set_mode(&src, 0o775);

    block_on(async {
        let fixture = Repo::open(&fixture_repo("canon")).await.unwrap();
        let (want, _) = fixture.read_commit("test/main").await.unwrap();
        let want_dirtree = *want.dirtree_checksum();
        let want_dirmeta = *want.dirmeta_checksum();

        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier = CommitModifier::new(
            CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
        );
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        assert_eq!(
            rt.dirtree_checksum(),
            &want_dirtree,
            "canonical root dirtree matches the tool"
        );
        assert_eq!(rt.dirmeta_checksum(), &want_dirmeta);
        txn.abort().await.unwrap();
    });
}

#[test]
fn canonical_permissions_apply_the_recovered_mode_rule() {
    // 0664 -> 0644, 0755 -> 0755, 04755 -> 0755; owner forced to 0:0. Read the
    // ingested modes back through the port, tool-free.
    let tmp = TmpDir::new("ingest-canon-rule");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f0664"), b"a").unwrap();
    std::fs::write(src.join("f0755"), b"b").unwrap();
    std::fs::write(src.join("f4755"), b"c").unwrap();
    set_mode(&src.join("f0664"), 0o664);
    set_mode(&src.join("f0755"), 0o755);
    set_mode(&src.join("f4755"), 0o4755);
    set_mode(&src, 0o755);
    let root = base.join("repo");

    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier = CommitModifier::new(
            CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
        );
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *rt.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        for (name, expect_mode) in [
            ("f0664", 0o100644),
            ("f0755", 0o100755),
            ("f4755", 0o100755),
        ] {
            let checksum = tree
                .files
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, c)| *c)
                .unwrap_or_else(|| panic!("missing {name}"));
            let file = repo.load_file(&checksum).await.unwrap();
            assert_eq!(file.mode, expect_mode, "{name} canonical mode");
            assert_eq!((file.uid, file.gid), (0, 0), "{name} owner forced to 0:0");
        }
    });
}

#[test]
fn canonical_permissions_records_no_xattrs() {
    // Canonical ingest records no xattrs, so an entry carrying one takes the
    // identity of the same entry without it -- for a file and for a directory's
    // metadata alike. Pinned to the tool by
    // `canonical_permissions_match_the_tool_over_xattrs`.
    let tmp = TmpDir::new("ingest-canon-xattr");
    let base = tmp.path();
    // Two copies of one tree, identical but for the xattrs one of them carries.
    for variant in ["with", "without"] {
        let src = base.join(variant).join("src");
        std::fs::create_dir_all(src.join("subdir")).unwrap();
        std::fs::write(src.join("hello.txt"), b"labeled\n").unwrap();
        set_mode(&src.join("hello.txt"), 0o644);
        set_mode(&src.join("subdir"), 0o755);
        set_mode(&src, 0o755);
    }
    let labeled = base.join("with").join("src");
    for path in [labeled.join("hello.txt"), labeled.join("subdir")] {
        rustix::fs::setxattr(
            &path,
            "user.demo",
            b"value",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
    }

    block_on(async {
        let root = base.join("repo");
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let mut ingested = Vec::new();
        for variant in ["with", "without"] {
            let txn = repo.transaction().await.unwrap();
            // No SKIP_XATTRS: the walk captures the on-disk set, and canonical
            // ingest is what drops it.
            let mut modifier = CommitModifier::new(CommitModifierFlags::CANONICAL_PERMISSIONS);
            let mut mtree = MutableTree::new();
            let dfd = std::fs::File::open(base.join(variant)).unwrap();
            txn.write_dfd_to_mtree(
                dfd.as_fd(),
                Path::new("src"),
                &mut mtree,
                Some(&mut modifier),
            )
            .await
            .unwrap();
            let rt = txn.write_mtree(&mut mtree).await.unwrap();
            ingested.push((*rt.dirtree_checksum(), *rt.dirmeta_checksum()));
            txn.commit().await.unwrap();
        }
        assert_eq!(
            ingested[0], ingested[1],
            "the xattr-bearing tree has the identity of the tree without xattrs"
        );

        // The recorded file header carries no xattr either.
        let tree = repo.load_dirtree(&ingested[0].0).await.unwrap();
        let hello = tree.files.iter().find(|(n, _)| n == "hello.txt").unwrap().1;
        let file = repo.load_file(&hello).await.unwrap();
        assert!(file.xattrs.is_empty(), "file xattrs: {:?}", file.xattrs);
        let sub = tree.dirs.iter().find(|(n, _, _)| n == "subdir").unwrap();
        let dirmeta = repo.load_dirmeta(&sub.2).await.unwrap();
        assert!(dirmeta.xattrs.is_empty(), "dirmeta xattrs: {:?}", dirmeta);
    });
}

#[test]
fn canonical_permissions_match_the_tool_over_xattrs() {
    if !ostree_available() {
        eprintln!(
            "skipping canonical_permissions_match_the_tool_over_xattrs: the ostree tool is \
             unavailable"
        );
        return;
    }
    // The tool's `--canonical-permissions` records no xattrs, so the port's
    // canonical ingest of an xattr-bearing tree has to produce the tool's own
    // object names for it.
    let tmp = TmpDir::new("ingest-canon-tool");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(src.join("subdir")).unwrap();
    std::fs::write(src.join("hello.txt"), b"labeled\n").unwrap();
    std::fs::write(src.join("subdir/nested.txt"), b"nested\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o664);
    set_mode(&src.join("subdir/nested.txt"), 0o644);
    set_mode(&src.join("subdir"), 0o775);
    set_mode(&src, 0o755);
    for path in [src.join("hello.txt"), src.join("subdir")] {
        rustix::fs::setxattr(
            &path,
            "user.demo",
            b"value",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
    }

    block_on(async {
        let repo = Repo::create(&base.join("port"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(CommitModifierFlags::CANONICAL_PERMISSIONS);
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
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let (dirtree, dirmeta) = (*rt.dirtree_checksum(), *rt.dirmeta_checksum());
        txn.abort().await.unwrap();

        let tool_root = base.join("tool");
        let repo_arg = format!("--repo={}", tool_root.display());
        run_ostree(&[&repo_arg, "init", "--mode=bare-user"]);
        run_ostree(&[
            &repo_arg,
            "commit",
            "--branch=t",
            "--subject=x",
            "--canonical-permissions",
            "--timestamp=@1700000000",
            src.to_str().unwrap(),
        ]);
        let tool = Repo::open(&tool_root).await.unwrap();
        let (want, _) = tool.read_commit("t").await.unwrap();
        assert_eq!(&dirtree, want.dirtree_checksum(), "root dirtree");
        assert_eq!(&dirmeta, want.dirmeta_checksum(), "root dirmeta");
    });
}

fn run_ostree(args: &[&str]) {
    let status = std::process::Command::new("ostree")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run ostree");
    assert!(status.success(), "ostree {args:?} failed");
}

#[test]
fn filter_prunes_a_subtree() {
    // A filter that skips /subdir excludes it and its contents entirely.
    let tmp = TmpDir::new("ingest-filter");
    let base = tmp.path();
    build_fixture_source(base);
    let root = base.join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
        modifier.filter = Some(Box::new(|path, _meta| {
            if path == Path::new("/subdir") {
                FilterResult::Skip
            } else {
                FilterResult::Allow
            }
        }));
        let mut mtree = MutableTree::new();
        assert_send(txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        ))
        .await
        .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *rt.dirtree_checksum();
        let stats = txn.commit().await.unwrap();

        assert_eq!(stats.filtered, 1, "one directory skipped");
        assert_eq!(
            stats.content_written, 3,
            "hello, empty, and link; nested is pruned"
        );

        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        assert!(tree.dirs.is_empty(), "the skipped subdir is absent");
        let names: Vec<&str> = tree.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["empty.txt", "hello.txt", "link"]);
    });
}

#[test]
fn xattr_callback_lands_in_the_object_id() {
    // A callback that sets user.extra on hello.txt makes the ingested object id
    // equal to the same content written with that xattr in its header.
    let tmp = TmpDir::new("ingest-xattr-cb");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    let (uid, gid) = own_ids(&src);
    let root = base.join("repo");

    let xattr = || Xattrs::new([(b"user.extra\0".to_vec(), b"v".to_vec())]).unwrap();

    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();

        // The identity the same payload gets with the xattr set directly.
        let expected = {
            let txn = repo.transaction().await.unwrap();
            let mut meta = FileMeta::regular(uid, gid, 0o644);
            meta.xattrs = xattr();
            let c = txn
                .write_regfile_inline(None, &meta, b"hello ostree\n")
                .await
                .unwrap();
            txn.abort().await.unwrap();
            c
        };

        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
        modifier.xattr_callback = Some(Box::new(move |path, meta| {
            if path == Path::new("/hello.txt") {
                xattr()
            } else {
                meta.xattrs.clone()
            }
        }));
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *rt.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let hello = tree
            .files
            .iter()
            .find(|(n, _)| n == "hello.txt")
            .map(|(_, c)| *c)
            .unwrap();
        assert_eq!(
            hello, expected,
            "the callback's xattr entered the object id"
        );
    });
}

#[test]
fn devino_cache_hit_skips_rehashing() {
    // With DEVINO_CANONICAL and a cache entry for the file's (dev, ino), the
    // file takes the cached checksum and no object is staged. Without the flag,
    // the file is hashed normally.
    let tmp = TmpDir::new("ingest-devino");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    let stat = rustix::fs::stat(src.join("hello.txt")).unwrap();
    let sentinel = Checksum::sha256(b"a checksum that is not the real content");

    block_on(async {
        // Hit: the cache is consulted and the object is not staged.
        let root = base.join("repo-hit");
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut cache = DevInoCache::new();
        cache.insert(stat.st_dev, stat.st_ino, sentinel);
        let mut modifier = CommitModifier::new(
            CommitModifierFlags::DEVINO_CANONICAL | CommitModifierFlags::SKIP_XATTRS,
        );
        modifier.devino_cache = Some(cache);
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *rt.dirtree_checksum();
        let stats = txn.commit().await.unwrap();
        assert_eq!(stats.devino_cache_hits, 1);
        assert_eq!(stats.content_written, 0, "no object staged on a hit");

        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let hello = tree.files.iter().find(|(n, _)| n == "hello.txt").unwrap().1;
        assert_eq!(hello, sentinel, "the cached checksum is used verbatim");

        // No flag: the same cache is ignored and the file is hashed.
        let root = base.join("repo-miss");
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut cache = DevInoCache::new();
        cache.insert(stat.st_dev, stat.st_ino, sentinel);
        let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
        modifier.devino_cache = Some(cache);
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *rt.dirtree_checksum();
        let stats = txn.commit().await.unwrap();
        assert_eq!(stats.devino_cache_hits, 0, "the cache is not consulted");
        assert_eq!(stats.content_written, 1, "the file is hashed");

        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let hello = tree.files.iter().find(|(n, _)| n == "hello.txt").unwrap().1;
        assert_ne!(hello, sentinel, "the real content is hashed");
    });
}

#[test]
fn consume_empties_the_source() {
    // A consuming walk removes every source file and the walk-root directory,
    // leaving its parent, while the objects are still staged.
    let tmp = TmpDir::new("ingest-consume");
    let base = tmp.path();
    let src = build_fixture_source(base);
    let root = base.join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier =
            CommitModifier::new(CommitModifierFlags::CONSUME | CommitModifierFlags::SKIP_XATTRS);
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        txn.write_mtree(&mut mtree).await.unwrap();
        let stats = txn.commit().await.unwrap();

        assert!(!src.exists(), "the walk root is removed");
        assert!(base.exists(), "the parent of the walk root remains");
        assert_eq!(stats.content_written, 4, "objects are still staged");
    });
}

#[test]
fn user_xattr_round_trips_through_ingest() {
    // A file bearing a user.* xattr ingests into bare-user and reads back with
    // the xattr intact.
    let tmp = TmpDir::new("ingest-xattr-roundtrip");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let file = src.join("hello.txt");
    std::fs::write(&file, b"labeled\n").unwrap();
    set_mode(&file, 0o644);
    rustix::fs::setxattr(
        &file,
        "user.demo",
        b"value",
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
    let root = base.join("repo");

    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut mtree = MutableTree::new();
        // No SKIP_XATTRS: on-disk xattrs are captured.
        txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
            .await
            .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *rt.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let hello = tree.files.iter().find(|(n, _)| n == "hello.txt").unwrap().1;
        let file = repo.load_file(&hello).await.unwrap();
        assert!(matches!(file.kind, FileKind::Regular { .. }));
        let has_demo = file
            .xattrs
            .iter()
            .any(|(name, value)| name == b"user.demo\0" && value == b"value");
        assert!(
            has_demo,
            "the user.demo xattr survived ingest: {:?}",
            file.xattrs
        );
    });
}

#[test]
fn reads_the_tool_written_user_xattr_from_the_fixture() {
    // The xattr fixture is a bare-user commit the tool made with a user.demo
    // xattr on hello.txt, folded into the file's user.ostreemeta and carried
    // across git in the fixture tarball. Reading it back proves the port decodes
    // a tool-written xattr set: the ingest round-trip test above uses the port on
    // both ends, while this reads the bytes the tool itself wrote.
    block_on(async {
        let repo = Repo::open(&fixture_repo("xattr")).await.unwrap();
        let (root, _) = repo.read_commit("test/main").await.unwrap();
        let Some(TreeEntry::File { checksum, .. }) =
            root.lookup(Path::new("hello.txt")).await.unwrap()
        else {
            panic!("hello.txt is not a file");
        };
        let file = repo.load_file(&checksum).await.unwrap();
        assert_eq!((file.uid, file.gid), (0, 0), "owner forced to 0:0");
        let has_demo = file
            .xattrs
            .iter()
            .any(|(name, value)| name == b"user.demo\0" && value == b"value");
        assert!(
            has_demo,
            "the tool-written user.demo survived storage: {:?}",
            file.xattrs
        );
    });
}

#[test]
fn symlink_xattrs_round_trip_through_the_object_store() {
    // A symlink object carrying a user.* xattr round-trips through the modes
    // that store xattrs in-band: archive keeps them in the framed header,
    // bare-user in user.ostreemeta. write_symlink takes the xattr set directly,
    // so this exercises storage and read-back without setting an xattr on a
    // source symlink, which the VFS forbids for user.* and gates behind
    // CAP_SYS_ADMIN otherwise. The bare mode's on-inode storage of the same
    // xattr needs that privilege and is covered on a privileged host.
    let tmp = TmpDir::new("symlink-xattr-roundtrip");
    let base = tmp.path();
    let xattrs = Xattrs::new([(b"user.demo\0".to_vec(), b"value".to_vec())]).unwrap();

    for (tag, mode) in [
        ("archive", RepoMode::Archive),
        ("bare-user", RepoMode::BareUser),
    ] {
        block_on(async {
            let repo = Repo::create(&base.join(tag), CreateOptions::new(mode))
                .await
                .unwrap();
            let txn = repo.transaction().await.unwrap();
            let meta = FileMeta {
                uid: 0,
                gid: 0,
                mode: 0,
                xattrs: xattrs.clone(),
            };
            let checksum = txn.write_symlink("target/path", &meta, None).await.unwrap();
            txn.commit().await.unwrap();

            let repo = Repo::open(&base.join(tag)).await.unwrap();
            let file = repo.load_file(&checksum).await.unwrap();
            let FileKind::Symlink { target } = file.kind else {
                panic!("{tag}: expected a symlink");
            };
            assert_eq!(target, "target/path", "{tag} target");
            let has_demo = file
                .xattrs
                .iter()
                .any(|(n, v)| n == b"user.demo\0" && v == b"value");
            assert!(
                has_demo,
                "{tag}: the symlink xattr round-trips: {:?}",
                file.xattrs
            );
        });
    }
}

#[test]
fn ingest_reads_symlink_xattrs_no_follow() {
    // A symlink pointing at an xattr-bearing regular file ingests with the
    // link's own (empty) xattr set: the target's user.demo must not leak into
    // the symlink object. Committed without SKIP_XATTRS so the walk reads
    // on-disk xattrs.
    let tmp = TmpDir::new("ingest-symlink-nofollow");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("target.txt"), b"payload\n").unwrap();
    set_mode(&src.join("target.txt"), 0o644);
    rustix::fs::setxattr(
        src.join("target.txt"),
        "user.demo",
        b"value",
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
    std::os::unix::fs::symlink("target.txt", src.join("link")).unwrap();
    set_mode(&src, 0o755);
    let root = base.join("repo");

    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
            .await
            .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *rt.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();

        // The target keeps its xattr.
        let target = tree
            .files
            .iter()
            .find(|(n, _)| n == "target.txt")
            .unwrap()
            .1;
        let target_file = repo.load_file(&target).await.unwrap();
        assert!(
            target_file
                .xattrs
                .iter()
                .any(|(n, v)| n == b"user.demo\0" && v == b"value"),
            "the regular file keeps its xattr"
        );

        // The symlink does not inherit it: no-follow read of an empty own set.
        let link = tree.files.iter().find(|(n, _)| n == "link").unwrap().1;
        let link_file = repo.load_file(&link).await.unwrap();
        let FileKind::Symlink { target } = link_file.kind else {
            panic!("expected a symlink");
        };
        assert_eq!(target, "target.txt");
        assert_eq!(
            link_file.xattrs.iter().count(),
            0,
            "the symlink's xattr set is empty, no leak from the target: {:?}",
            link_file.xattrs
        );
    });
}

#[test]
fn label_callback_sets_selinux_in_the_object_id() {
    // A label callback's SELinux label enters the content object's xattr set,
    // so its object id matches the same content written with that label.
    let tmp = TmpDir::new("ingest-label");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    let (uid, gid) = own_ids(&src);
    let root = base.join("repo");
    let label = b"unconfined_u:object_r:user_home_t:s0\0";

    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();

        // The identity the same payload gets with the label set directly.
        let expected = {
            let txn = repo.transaction().await.unwrap();
            let mut meta = FileMeta::regular(uid, gid, 0o644);
            meta.xattrs = Xattrs::new([(b"security.selinux\0".to_vec(), label.to_vec())]).unwrap();
            let c = txn
                .write_regfile_inline(None, &meta, b"hello ostree\n")
                .await
                .unwrap();
            txn.abort().await.unwrap();
            c
        };

        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
        modifier.label_callback = Some(Box::new(move |_path, _meta| Some(label.to_vec())));
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *rt.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let hello = tree.files.iter().find(|(n, _)| n == "hello.txt").unwrap().1;
        assert_eq!(hello, expected, "the label entered the object id");
    });
}

#[test]
fn error_on_unlabeled_fails_when_the_hook_returns_no_label() {
    // With ERROR_ON_UNLABELED and a label callback that labels nothing, ingest
    // fails rather than committing an unlabeled path.
    let tmp = TmpDir::new("ingest-unlabeled");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    let root = base.join("repo");

    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier = CommitModifier::new(
            CommitModifierFlags::ERROR_ON_UNLABELED | CommitModifierFlags::SKIP_XATTRS,
        );
        modifier.label_callback = Some(Box::new(|_path, _meta| None));
        let mut mtree = MutableTree::new();
        let err = txn
            .write_dfd_to_mtree(
                dfd.as_fd(),
                Path::new("src"),
                &mut mtree,
                Some(&mut modifier),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, ostrya::Error::InvalidFormat(_)),
            "an unlabeled path is an error, got {err:?}"
        );
        txn.abort().await.unwrap();
    });
}

#[test]
fn consume_with_a_pruning_filter_leaves_the_pruned_source() {
    // CONSUME deletes each ingested source, but a filter that prunes a file
    // inside a subdirectory leaves that file -- and its now-non-empty parent --
    // on disk without failing the walk, and the committed tree omits it.
    let tmp = TmpDir::new("ingest-consume-prune");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(src.join("subdir")).unwrap();
    std::fs::write(src.join("subdir/keep.txt"), b"keep\n").unwrap();
    std::fs::write(src.join("subdir/skip.txt"), b"skip\n").unwrap();
    set_mode(&src.join("subdir/keep.txt"), 0o644);
    set_mode(&src.join("subdir/skip.txt"), 0o644);
    set_mode(&src.join("subdir"), 0o755);
    set_mode(&src, 0o755);
    let root = base.join("repo");

    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier =
            CommitModifier::new(CommitModifierFlags::CONSUME | CommitModifierFlags::SKIP_XATTRS);
        modifier.filter = Some(Box::new(|path, _meta| {
            if path == Path::new("/subdir/skip.txt") {
                FilterResult::Skip
            } else {
                FilterResult::Allow
            }
        }));
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *rt.dirtree_checksum();
        txn.commit().await.unwrap();

        assert!(src.join("subdir/skip.txt").exists(), "pruned file remains");
        assert!(src.join("subdir").exists(), "its parent remains");
        assert!(!src.join("subdir/keep.txt").exists(), "kept file consumed");

        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let subdir = tree.dirs.iter().find(|(n, ..)| n == "subdir").unwrap().1;
        let subtree = repo.load_dirtree(&subdir).await.unwrap();
        let names: Vec<&str> = subtree.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["keep.txt"], "the pruned file is not committed");
    });
}

#[test]
fn modifier_callbacks_run_once_per_directory() {
    // The xattr callback fires exactly once per path, directories included.
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    let tmp = TmpDir::new("ingest-callback-once");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(src.join("subdir")).unwrap();
    std::fs::write(src.join("top.txt"), b"top\n").unwrap();
    std::fs::write(src.join("subdir/nested.txt"), b"nested\n").unwrap();
    set_mode(&src.join("top.txt"), 0o644);
    set_mode(&src.join("subdir/nested.txt"), 0o644);
    set_mode(&src.join("subdir"), 0o755);
    set_mode(&src, 0o755);

    let calls: Arc<Mutex<HashMap<PathBuf, usize>>> = Arc::new(Mutex::new(HashMap::new()));

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let seen = Arc::clone(&calls);
        let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
        modifier.xattr_callback = Some(Box::new(move |path, meta| {
            *seen.lock().unwrap().entry(path.to_path_buf()).or_insert(0) += 1;
            meta.xattrs.clone()
        }));
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        txn.abort().await.unwrap();
    });

    let calls = calls.lock().unwrap();
    for dir in ["/", "/subdir"] {
        assert_eq!(
            calls.get(Path::new(dir)).copied(),
            Some(1),
            "directory {dir} adjusted once, recorded {:?}",
            calls.get(Path::new(dir))
        );
    }
}

#[test]
fn devino_hit_bypasses_the_label_hook() {
    // A devino-cache hit takes the cached checksum without running the label
    // hook, so ERROR_ON_UNLABELED with a hook that leaves the cached file
    // unlabeled does not fail the ingest.
    let tmp = TmpDir::new("ingest-devino-label");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    set_mode(&src, 0o755);
    let stat = rustix::fs::stat(src.join("hello.txt")).unwrap();
    let sentinel = Checksum::sha256(b"a cached checksum, not the real content");
    let root = base.join("repo");

    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut cache = DevInoCache::new();
        cache.insert(stat.st_dev, stat.st_ino, sentinel);
        // The hook labels everything except the cached file; if it ran for the
        // cached file it would return None and abort under ERROR_ON_UNLABELED.
        let mut modifier = CommitModifier::new(
            CommitModifierFlags::DEVINO_CANONICAL
                | CommitModifierFlags::ERROR_ON_UNLABELED
                | CommitModifierFlags::SKIP_XATTRS,
        );
        modifier.devino_cache = Some(cache);
        modifier.label_callback = Some(Box::new(|path, _meta| {
            if path == Path::new("/hello.txt") {
                None
            } else {
                Some(b"system_u:object_r:default_t:s0\0".to_vec())
            }
        }));
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *rt.dirtree_checksum();
        let stats = txn.commit().await.unwrap();
        assert_eq!(stats.devino_cache_hits, 1);

        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let hello = tree.files.iter().find(|(n, _)| n == "hello.txt").unwrap().1;
        assert_eq!(hello, sentinel, "the cached checksum is used");
    });
}

#[test]
fn devino_hit_skips_the_xattr_callback() {
    // A devino-cache hit runs no user callbacks: a counting xattr callback is
    // never invoked for the cached file.
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let tmp = TmpDir::new("ingest-devino-xattr");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    set_mode(&src, 0o755);
    let stat = rustix::fs::stat(src.join("hello.txt")).unwrap();
    let sentinel = Checksum::sha256(b"a cached checksum, not the real content");
    let root = base.join("repo");

    let hits = Arc::new(AtomicUsize::new(0));

    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut cache = DevInoCache::new();
        cache.insert(stat.st_dev, stat.st_ino, sentinel);
        let counter = Arc::clone(&hits);
        let mut modifier = CommitModifier::new(
            CommitModifierFlags::DEVINO_CANONICAL | CommitModifierFlags::SKIP_XATTRS,
        );
        modifier.devino_cache = Some(cache);
        modifier.xattr_callback = Some(Box::new(move |path, meta| {
            if path == Path::new("/hello.txt") {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            meta.xattrs.clone()
        }));
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        txn.abort().await.unwrap();
    });

    assert_eq!(
        hits.load(Ordering::Relaxed),
        0,
        "the xattr callback is not invoked for a cached file"
    );
}
