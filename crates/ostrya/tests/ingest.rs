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
use futures_lite::AsyncReadExt;
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
fn canonical_permissions_reduce_the_mode_callback_result() {
    // The canonical reduction stands last of the mode modifiers, so a mode
    // callback states the mode the reduction then masks. The file type stays
    // the one the walk found, so a callback naming a type of its own leaves
    // the entry the kind it is. Both the plain walk and the devino-cache path
    // run the callback through the same step, so both are asserted here.
    let tmp = TmpDir::new("ingest-canon-order");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    set_mode(&src.join("sub"), 0o700);
    set_mode(&src, 0o755);
    let stat = rustix::fs::stat(src.join("hello.txt")).unwrap();

    // What the CLI's `--statoverride` mode callback does for `=511 /hello.txt`,
    // `=2048 /sub`, and a value renaming the file's type.
    let assign = |value: u32| {
        move |path: &Path, meta: &FileMeta| -> u32 {
            match path.to_str().unwrap() {
                "/hello.txt" | "/sub" => (meta.mode & 0o170000) | value,
                _ => meta.mode,
            }
        }
    };

    block_on(async {
        let root = base.join("repo");
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();

        let walk = async |value: u32, cache: Option<DevInoCache>| {
            let txn = repo.transaction().await.unwrap();
            let dfd = std::fs::File::open(base).unwrap();
            let mut modifier = CommitModifier::new(
                CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
            );
            modifier.mode_callback = Some(Box::new(assign(value)));
            modifier.devino_cache = cache;
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
            let dirtree = *rt.dirtree_checksum();
            txn.commit().await.unwrap();
            let tree = repo.load_dirtree(&dirtree).await.unwrap();
            let hello = tree.files.iter().find(|(n, _)| n == "hello.txt").unwrap().1;
            let sub = tree.dirs.iter().find(|(n, _, _)| n == "sub").unwrap().2;
            (
                repo.load_file(&hello).await.unwrap().mode,
                repo.load_dirmeta(&sub).await.unwrap().mode,
            )
        };

        // 0o777 assigned, then reduced: 0o755. 0o4000 assigned, then reduced:
        // nothing survives the mask. Running the reduction first would give
        // 0o777 and 0o4000.
        assert_eq!(walk(0o777, None).await, (0o100755, 0o40755));
        assert_eq!(walk(0o4000, None).await, (0o100000, 0o40000));
        // A value naming a directory's type over a regular file leaves a
        // regular file, and the permission bits it carries are masked.
        assert_eq!(walk(0o40755, None).await, (0o100755, 0o40755));

        // The same over the devino-cache path: the stored object supplies the
        // metadata, and the callback and the reduction shape it in that order.
        let stored = {
            let (mode, _) = walk(0o777, None).await;
            assert_eq!(mode, 0o100755);
            let txn = repo.transaction().await.unwrap();
            let meta = FileMeta::regular(0, 0, 0o644);
            let c = txn
                .write_regfile_inline(None, &meta, b"hello ostree\n")
                .await
                .unwrap();
            txn.commit().await.unwrap();
            c
        };
        let mut cache = DevInoCache::new();
        cache.insert(stat.st_dev, stat.st_ino, stored);
        assert_eq!(walk(0o777, Some(cache)).await, (0o100755, 0o40755));
    });
}

#[test]
fn devino_cache_hit_skips_rehashing() {
    // With DEVINO_CANONICAL and a cache entry for the file's (dev, ino), the
    // file takes the cached checksum and no object is staged. Without the flag,
    // the cache is still consulted: the stored object supplies the metadata the
    // modifier shapes, and the object is reused where the shaped metadata
    // matches it and rewritten from the stored content where it does not.
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

        // A repository holding the real object, for the two walks below.
        let root = base.join("repo-plain");
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let real = {
            let txn = repo.transaction().await.unwrap();
            let dfd = std::fs::File::open(base).unwrap();
            let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
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
            let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
            tree.files.iter().find(|(n, _)| n == "hello.txt").unwrap().1
        };

        // The source file is rewritten in place, keeping its inode, so the
        // stored object's payload and the source file's payload now differ.
        // Either half below that read the source would produce an object
        // holding `rewritten` rather than the stored bytes.
        std::fs::write(
            src.join("hello.txt"),
            b"a payload the store does not hold\n",
        )
        .unwrap();
        set_mode(&src.join("hello.txt"), 0o644);
        let after = rustix::fs::stat(src.join("hello.txt")).unwrap();
        assert_eq!(
            (after.st_dev, after.st_ino),
            (stat.st_dev, stat.st_ino),
            "the rewrite kept the inode the cache is keyed on"
        );

        // No flag, and the shaped metadata equals the stored metadata: the
        // object is reused and the hit is counted.
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut cache = DevInoCache::new();
        cache.insert(stat.st_dev, stat.st_ino, real);
        let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
        modifier.devino_cache = Some(cache.clone());
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
        assert_eq!(stats.devino_cache_hits, 1, "the cache is consulted");
        assert_eq!(stats.content_written, 0, "no object is rewritten");
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let hello = tree.files.iter().find(|(n, _)| n == "hello.txt").unwrap().1;
        assert_eq!(hello, real, "the stored object is reused");

        // No flag, and the modifier changes the metadata: the object is
        // rewritten from the stored content under the shaped metadata.
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
        modifier.owner_uid = Some(4242);
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
        assert_eq!(stats.devino_cache_hits, 0, "the hit did not stand");
        assert_eq!(stats.content_written, 1, "the object is rewritten");
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let hello = tree.files.iter().find(|(n, _)| n == "hello.txt").unwrap().1;
        assert_ne!(hello, real, "the shaped metadata gives a new identity");
        let object = repo.load_file(&hello).await.unwrap();
        assert_eq!(object.uid, 4242);
        let mut payload = Vec::new();
        object
            .reader()
            .await
            .unwrap()
            .read_to_end(&mut payload)
            .await
            .unwrap();
        assert_eq!(
            payload, b"hello ostree\n",
            "the rewritten object carries the stored payload, not the source file's"
        );
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
fn consume_spares_a_walk_root_spelled_dot() {
    // A consuming walk spares the walk root when the path is exactly `.`, and
    // removes it under every other spelling, `./` among them. The test is on
    // the text the path carries, which is the rule
    // `docs/format-reference.md`, "CLI output formats", `commit` records for
    // `--consume`. Both spellings here name the directory the walk-root
    // descriptor is open on, and the kernel refuses to unlink a path whose
    // last component is `.`, so each leaves the directory in place and empties
    // it.
    for spelling in [".", "./"] {
        let tmp = TmpDir::new("ingest-consume-dot");
        let base = tmp.path();
        let src = build_fixture_source(base);
        let root = base.join("repo");
        block_on(async {
            let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
                .await
                .unwrap();
            let txn = repo.transaction().await.unwrap();
            let dfd = std::fs::File::open(&src).unwrap();
            let mut modifier = CommitModifier::new(
                CommitModifierFlags::CONSUME | CommitModifierFlags::SKIP_XATTRS,
            );
            let mut mtree = MutableTree::new();
            txn.write_dfd_to_mtree(
                dfd.as_fd(),
                Path::new(spelling),
                &mut mtree,
                Some(&mut modifier),
            )
            .await
            .unwrap();
            txn.write_mtree(&mut mtree).await.unwrap();
            txn.commit().await.unwrap();

            assert!(
                src.is_dir(),
                "the walk root spelled {spelling} stands after the walk"
            );
            assert_eq!(
                std::fs::read_dir(&src).unwrap().count(),
                0,
                "the walk root spelled {spelling} is emptied"
            );
        });
    }
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
fn consume_with_a_pruning_filter_still_empties_the_source() {
    // CONSUME empties each ingested source whatever the filter kept out of the
    // commit: a pruned file and its parent are removed with the rest, and the
    // committed tree omits the pruned file. Leaving them would strand the
    // source half-deleted and fail the removal of the directory above.
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

        assert!(
            !src.join("subdir").exists(),
            "the pruned file and its parent are consumed with the rest"
        );

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

/// Marks the re-executed child of
/// [`deep_source_tree_ingests_under_a_low_descriptor_limit`], and names the
/// file the child writes to record that the ingest ran.
const DEEP_INGEST_CHILD: &str = "OSTRYA_DEEP_INGEST_CHILD";
/// The soft descriptor limit the child runs under. It stands well above what
/// the repository, the runtime, and the blocking pool open for themselves.
const DEEP_INGEST_NOFILE: usize = 256;
/// The depth of the source tree the child ingests. It stands well above
/// [`DEEP_INGEST_NOFILE`], so a walk holding one descriptor per level runs out.
const DEEP_INGEST_DEPTH: usize = 1024;
/// The thread stack the child runs with. One level of the walk costs one
/// future, and the tree is deep, so the child is given room for the whole
/// descent and the descriptor limit is what the walk meets.
const DEEP_INGEST_STACK: usize = 512 * 1024 * 1024;

#[test]
fn deep_source_tree_ingests_under_a_low_descriptor_limit() {
    // The walk holds at most two directory descriptors, whatever the depth of
    // the source, so a tree deeper than the process descriptor limit ingests.
    //
    // The limit is a property of the process and the tests of this binary run
    // in parallel threads, so the lowered limit goes to a child: this test
    // binary re-executed for this test alone, through `sh` with `ulimit -n`.
    if let Some(marker) = std::env::var_os(DEEP_INGEST_CHILD) {
        ingest_a_deep_tree();
        std::fs::write(marker, b"ingested").expect("record that the deep ingest ran");
        return;
    }
    let tmp = TmpDir::new("ingest-deep-marker");
    let marker = tmp.path().join("ingested");
    let exe = std::env::current_exe().expect("the path of the running test binary");
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"ulimit -n "$1" || exit 111; shift; exec "$@""#)
        .arg("sh")
        .arg(DEEP_INGEST_NOFILE.to_string())
        .arg(&exe)
        .arg("--exact")
        .arg("deep_source_tree_ingests_under_a_low_descriptor_limit")
        .arg("--nocapture")
        .env(DEEP_INGEST_CHILD, &marker)
        .env("RUST_MIN_STACK", DEEP_INGEST_STACK.to_string())
        .status()
        .expect("re-run the test binary under a lowered descriptor limit");
    assert!(
        status.success(),
        "the deep ingest failed under a soft limit of {DEEP_INGEST_NOFILE} descriptors: {status}"
    );
    // A name the child's filter does not match runs nothing and still exits 0,
    // so the marker is what proves the ingest ran.
    assert!(
        marker.exists(),
        "the child ran no deep ingest: the test name the filter names is stale"
    );
}

/// The soft `RLIMIT_NOFILE` of the running process, read from `/proc`.
fn soft_nofile_limit() -> usize {
    let limits = std::fs::read_to_string("/proc/self/limits").expect("read /proc/self/limits");
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .expect("the open-file limit line");
    line.split_whitespace()
        .nth(3)
        .and_then(|soft| soft.parse().ok())
        .expect("the soft open-file limit")
}

/// Ingest a source tree [`DEEP_INGEST_DEPTH`] directories deep, consuming it.
/// Runs in the child process, under the lowered descriptor limit.
fn ingest_a_deep_tree() {
    assert_eq!(
        soft_nofile_limit(),
        DEEP_INGEST_NOFILE,
        "the child runs under the lowered descriptor limit"
    );
    let tmp = TmpDir::new("ingest-deep");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir(&src).unwrap();
    set_mode(&src, 0o755);
    // The tree is built through a descending descriptor, so no path of its own
    // grows past the kernel's limit. CONSUME then empties it as the walk
    // ascends, which is also what removes it: a path-based removal of a tree
    // this deep runs out of descriptors itself.
    let mut dir: std::os::fd::OwnedFd = std::fs::File::open(&src).unwrap().into();
    for _ in 0..DEEP_INGEST_DEPTH {
        rustix::fs::mkdirat(dir.as_fd(), "d", rustix::fs::Mode::from_raw_mode(0o755)).unwrap();
        dir = rustix::fs::openat(
            dir.as_fd(),
            "d",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
    }
    drop(dir);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
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
        txn.abort().await.unwrap();
    });

    assert!(!src.exists(), "the consuming walk emptied the deep source");
}
